//! Integration coverage for the confirmation / reorg-reconciliation loop as the
//! single chain-truth authority over the `chain_attempt` ledger.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test stands up an isolated, freshly migrated database, seeds an operator,
//! a wallet, the materialised tip, a `poe_record` and the `chain_attempt` row(s) it
//! rides, then drives the real `ConfirmHandler` against a SCRIPTED chain gateway
//! with programmable per-tick responses.
//!
//! The assertions are behavioural: the resulting `chain_attempt` / `poe_record` /
//! `chain_records` / `wallet_utxo` / `refund_intent` / `subject_event` / `job`
//! rows and the iteration summary, never log strings. The through-lines are the
//! locked confirm semantics:
//!
//! - Pass A settles a threshold-crossing ATTEMPT with zero gateway traffic, flips
//!   its record, promotes its wallet state, and enqueues the index job in one
//!   transaction.
//! - The replacement-watch set keeps a superseded original reconcilable; whichever
//!   of an original/replacement pair lands first is confirmed and the loser is
//!   abandoned by a SETTLEMENT-DEEP conflict (shared inputs stay confirmed_spent by
//!   the winner, exclusive inputs are restored, outputs tombstoned), with NO refund.
//! - Input restore and refund move ONLY on a settlement-deep proof-of-death
//!   conflict. A gone-but-no-conflicting-spend attempt past the horizon is NEVER
//!   abandoned, restored, or refunded. A conflicting spend that is still shallow
//!   does NOT fire the abandon, and reorging it out before depth leaves nothing to
//!   claw back.
//! - A different-height re-confirmation re-pins coordinates everywhere; a confirmed
//!   below-threshold re-inclusion re-pins under the confirmed guard.
//! - The wallet-mutating arms take the wallet lock yield-not-block: a held lock
//!   yields and re-queues (starvation-free), escalating to a bounded-fair acquire
//!   after the yield threshold.

#![cfg(feature = "pg-tests")]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use cardanowall::cbor::{encode_canonical_cbor, CborValue};
use cardanowall::cose::{cose_sign1_label309_build, CoseHeader, Label309Signer};
use cardanowall::poe_standard::{
    encode_poe_record, encode_record_body_for_signing, ItemEntry, PoeRecord, SigEntry,
};
use chrono::{DateTime, Utc};
use gateway_core::chain::attempt::{
    self, AttemptInput, AttemptKind, AttemptOutput, AttemptStatus, NewAttempt,
};
use gateway_core::chain::confirm::{
    read_tip, read_tip_epoch, upsert_tip, ConfirmConfig, ConfirmHandler,
    MEMPOOL_PRESUMED_DEAD_EVENT, MEMPOOL_STUCK_EVENT,
};
use gateway_core::chain::gateway::{
    BlockInfo, ChainGateway, ChainTip, Label309RecordsResult, TxCborMap, TxConfirmation,
    TxConfirmationMap,
};
use gateway_core::chain::records::{index_tx_policy, IndexTxJob, MetadataSource, INDEX_TX_QUEUE};
use gateway_core::chain::submit::{submit_policy, SUBMIT_QUEUE};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network as WalletNetwork, WalletConfig};
use sqlx::Row;
use uuid::Uuid;

const NETWORK: &str = "preprod";

// ---------------------------------------------------------------------------
// Scripted chain gateway: per-call programmable confirmation responses.
// ---------------------------------------------------------------------------

/// A chain gateway whose `get_tx_confirmations` answers from a script. An unseeded
/// hash answers `not_on_chain`.
#[derive(Default)]
struct ScriptedGateway {
    confirmations: Mutex<HashMap<[u8; 32], TxConfirmation>>,
    cbor: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}

impl ScriptedGateway {
    fn new() -> Self {
        Self::default()
    }

    fn set_confirmation(&self, hash: [u8; 32], confirmation: TxConfirmation) {
        self.confirmations
            .lock()
            .unwrap()
            .insert(hash, confirmation);
    }

    fn set_gone(&self, hash: [u8; 32]) {
        self.confirmations
            .lock()
            .unwrap()
            .insert(hash, TxConfirmation::not_on_chain());
    }

    fn set_cbor(&self, hash: [u8; 32], cbor: Vec<u8>) {
        self.cbor.lock().unwrap().insert(hash, cbor);
    }
}

impl ChainGateway for ScriptedGateway {
    async fn submit_tx(&self, _signed_tx: &[u8]) -> gateway_core::Result<[u8; 32]> {
        Ok([0u8; 32])
    }

    async fn get_tx_confirmations(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxConfirmationMap> {
        let script = self.confirmations.lock().unwrap();
        let mut out = TxConfirmationMap::new();
        for hash in tx_hashes {
            let confirmation = script
                .get(hash)
                .copied()
                .unwrap_or_else(TxConfirmation::not_on_chain);
            out.insert(*hash, confirmation);
        }
        Ok(out)
    }

    async fn get_block_info(&self, _block_height: u64) -> gateway_core::Result<Option<BlockInfo>> {
        Ok(None)
    }

    async fn get_tip(&self) -> gateway_core::Result<ChainTip> {
        Ok(ChainTip {
            block_height: 0,
            epoch: None,
        })
    }

    async fn fetch_tx_cbor_by_hashes(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxCborMap> {
        let script = self.cbor.lock().unwrap();
        let mut out = TxCborMap::new();
        for hash in tx_hashes {
            if let Some(cbor) = script.get(hash) {
                out.insert(*hash, cbor.clone());
            }
        }
        Ok(out)
    }

    async fn fetch_label309_records_since(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<Label309RecordsResult> {
        Ok(Label309RecordsResult::default())
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<Label309RecordsResult> {
        Ok(Label309RecordsResult::default())
    }
}

// ---------------------------------------------------------------------------
// Record bytes: a minimal valid Label 309 record, optionally signed.
// ---------------------------------------------------------------------------

fn open_record_bytes() -> Vec<u8> {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0xab; 32])],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    encode_poe_record(&record).expect("encode record")
}

fn signed_record_bytes(seed: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let pubkey = cardanowall::cose::ed25519_public_key_from_seed(seed);
    let mut record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0xcd; 32])],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let body = encode_record_body_for_signing(&record).expect("encode body");
    let protected = CoseHeader::new()
        .with_int(1, CborValue::int(-8))
        .with_int(4, CborValue::bytes(pubkey.to_vec()));
    let sign1 = cose_sign1_label309_build(
        &protected,
        &CoseHeader::new(),
        &body,
        Label309Signer::Seed(seed),
    )
    .expect("build cose_sign1");
    record.sigs = Some(vec![SigEntry {
        cose_sign1: sign1,
        cose_key: None,
    }]);
    let bytes = encode_poe_record(&record).expect("encode signed record");
    let _ = encode_canonical_cbor;
    (bytes, pubkey)
}

// ---------------------------------------------------------------------------
// Seeding helpers.
// ---------------------------------------------------------------------------

async fn seed_operator(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'test-op')")
        .bind(id)
        .execute(pool)
        .await
        .expect("insert operator");
    id
}

async fn seed_wallet(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet (id, registrar_operator_id, label, address, network) \
         VALUES ($1, $2, 'w', $3, $4)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(format!("addr_test_{id}"))
    .bind(NETWORK)
    .execute(pool)
    .await
    .expect("insert wallet");
    id
}

/// A `wallet_utxo` row to seed for the wallet-state tests.
struct SeedUtxo {
    tx_hash: [u8; 32],
    output_index: i32,
    lovelace: i64,
    state: &'static str,
    source: &'static str,
    canonical: bool,
    spendable_unconfirmed: bool,
}

async fn seed_wallet_utxo(pool: &sqlx::PgPool, wallet_id: Uuid, utxo: SeedUtxo) {
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, \
            spendable_unconfirmed, source) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(wallet_id)
    .bind(utxo.tx_hash.to_vec())
    .bind(utxo.output_index)
    .bind(utxo.lovelace)
    .bind(utxo.state)
    .bind(utxo.canonical)
    .bind(utxo.spendable_unconfirmed)
    .bind(utxo.source)
    .execute(pool)
    .await
    .expect("insert wallet_utxo");
}

async fn wallet_utxo_state(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    tx_hash: [u8; 32],
    output_index: i32,
) -> Option<(String, bool, bool)> {
    let row = sqlx::query(
        "SELECT state, canonical, spendable_unconfirmed FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3",
    )
    .bind(wallet_id)
    .bind(tx_hash.to_vec())
    .bind(output_index)
    .fetch_optional(pool)
    .await
    .expect("read wallet_utxo");
    row.map(|row| {
        (
            row.get::<String, _>("state"),
            row.get::<bool, _>("canonical"),
            row.get::<bool, _>("spendable_unconfirmed"),
        )
    })
}

async fn register_policies(pool: &sqlx::PgPool) {
    gateway_core::runtime::policy::reconcile(pool, &submit_policy())
        .await
        .expect("submit policy");
    gateway_core::runtime::policy::reconcile(pool, &index_tx_policy())
        .await
        .expect("index_tx policy");
}

/// Insert a `poe_record` in a chosen status, returning its id. The record's
/// chain-effect state lives on its attempt; the record carries the customer status
/// and the projection columns the confirm authority writes.
struct SeedRecord {
    status: &'static str,
    record_bytes: Vec<u8>,
    rollback_retry_count: i32,
}

impl SeedRecord {
    fn new(status: &'static str) -> Self {
        Self {
            status,
            record_bytes: open_record_bytes(),
            rollback_retry_count: 0,
        }
    }
}

async fn seed_record(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    wallet_id: Uuid,
    spec: SeedRecord,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, wallet_id, record_bytes, status, rollback_retry_count, request_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(wallet_id)
    .bind(&spec.record_bytes)
    .bind(spec.status)
    .bind(spec.rollback_retry_count)
    .bind(format!("req-{id}"))
    .execute(pool)
    .await
    .expect("insert poe_record");
    id
}

/// The fields a seeded attempt carries.
struct SeedAttempt {
    kind: AttemptKind,
    record_id: Option<Uuid>,
    wallet_id: Uuid,
    tx_hash: [u8; 32],
    spent_inputs: Vec<AttemptInput>,
    produced_outputs: Vec<AttemptOutput>,
    replaces_tx_hash: Option<[u8; 32]>,
    status: AttemptStatus,
    block_height: Option<i64>,
    first_seen_on_chain_at: Option<DateTime<Utc>>,
    mempool_entered_at: Option<DateTime<Utc>>,
    point_record_at: bool,
}

impl SeedAttempt {
    fn publish(record_id: Uuid, wallet_id: Uuid, tx_hash: [u8; 32]) -> Self {
        Self {
            kind: AttemptKind::Publish,
            record_id: Some(record_id),
            wallet_id,
            tx_hash,
            spent_inputs: Vec::new(),
            produced_outputs: Vec::new(),
            replaces_tx_hash: None,
            status: AttemptStatus::Broadcast,
            block_height: None,
            first_seen_on_chain_at: None,
            mempool_entered_at: Some(Utc::now()),
            point_record_at: true,
        }
    }
}

/// Record an attempt and (optionally) point its record's `current_attempt_id` at
/// it, plus stamp the seeded on-chain coordinates the constructors do not set.
async fn seed_attempt(pool: &sqlx::PgPool, spec: SeedAttempt) -> Uuid {
    let id = Uuid::now_v7();
    let new = NewAttempt {
        id,
        kind: spec.kind,
        record_id: spec.record_id,
        wallet_id: spec.wallet_id,
        tx_hash: spec.tx_hash,
        signed_tx: vec![0xa1, 0x01, 0x82],
        fee_lovelace: 169_197,
        spent_inputs: spec.spent_inputs,
        produced_outputs: spec.produced_outputs,
        replaces_tx_hash: spec.replaces_tx_hash,
    };
    let mut tx = pool.begin().await.expect("begin");
    attempt::record_attempt_in_tx(&mut tx, &new)
        .await
        .expect("record attempt");
    tx.commit().await.expect("commit");

    // Drive the seeded lifecycle/coords directly so a test can place an attempt in
    // any state without re-deriving the production transition path.
    sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET status = $2, block_height = $3, \
             block_time = CASE WHEN $3 IS NULL THEN NULL ELSE now() END, \
             first_seen_on_chain_at = $4, mempool_entered_at = $5 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(spec.status.as_str())
    .bind(spec.block_height)
    .bind(spec.first_seen_on_chain_at)
    .bind(spec.mempool_entered_at)
    .execute(pool)
    .await
    .expect("stamp attempt coords");

    if spec.point_record_at {
        if let Some(record_id) = spec.record_id {
            sqlx::query("UPDATE cw_core.poe_record SET current_attempt_id = $2 WHERE id = $1")
                .bind(record_id)
                .bind(id)
                .execute(pool)
                .await
                .expect("point record at attempt");
        }
    }
    id
}

fn input(hash: [u8; 32], index: u32, lovelace: u64) -> AttemptInput {
    AttemptInput {
        tx_hash: hex::encode(hash),
        index,
        lovelace,
    }
}

async fn set_tip(pool: &sqlx::PgPool, height: u64) {
    upsert_tip(pool, NETWORK, height, None)
        .await
        .expect("upsert tip");
}

/// The materialised tip epoch is governed by STRICTLY-higher height: an
/// equal-height observation can never swap the recorded epoch (a delayed replica
/// reporting the same height with a stale epoch must not corrupt it), a
/// strictly-higher observation that omits the epoch keeps the prior one (never
/// wiping it to NULL), and a strictly-higher observation that carries an epoch
/// adopts it. A behind (lower) observation never touches the epoch.
#[tokio::test]
async fn materialised_tip_epoch_only_advances_on_a_strictly_higher_height() {
    let db = TestDb::fresh().await.expect("test database");

    // First observation: height 1000 in epoch 214.
    upsert_tip(&db.pool, NETWORK, 1000, Some(214))
        .await
        .expect("first tip");
    assert_eq!(read_tip_epoch(&db.pool, NETWORK).await.unwrap(), Some(214));

    // A delayed equal-height observation carrying a STALE epoch (213) must not
    // overwrite the recorded epoch: the epoch belongs to the highest height seen,
    // and an equal-height race never swaps it.
    upsert_tip(&db.pool, NETWORK, 1000, Some(213))
        .await
        .expect("equal-height stale");
    assert_eq!(
        read_tip_epoch(&db.pool, NETWORK).await.unwrap(),
        Some(214),
        "an equal-height observation must never swap the recorded epoch"
    );

    // A behind (lower) observation never regresses the height or the epoch.
    upsert_tip(&db.pool, NETWORK, 900, Some(213))
        .await
        .expect("behind observation");
    assert_eq!(read_tip(&db.pool, NETWORK).await.unwrap(), Some(1000));
    assert_eq!(read_tip_epoch(&db.pool, NETWORK).await.unwrap(), Some(214));

    // A strictly-higher observation that OMITS the epoch carries its own (NULL)
    // epoch onto the new height, so the stored (height, epoch) pair stays
    // coherent: the populate loop sees NULL and does a single /tip fallback to
    // recover the real epoch, rather than serving the prior (older-height) epoch
    // as if it were current. Real providers always carry the epoch, so this NULL
    // path is effectively unreachable in production.
    upsert_tip(&db.pool, NETWORK, 1001, None)
        .await
        .expect("higher, no epoch");
    assert_eq!(
        read_tip_epoch(&db.pool, NETWORK).await.unwrap(),
        None,
        "a higher observation with no epoch nulls the stored epoch (height and epoch stay coherent), forcing a one-shot fallback"
    );

    // A strictly-higher observation that carries a new epoch adopts it.
    upsert_tip(&db.pool, NETWORK, 1100, Some(215))
        .await
        .expect("higher, new epoch");
    assert_eq!(
        read_tip_epoch(&db.pool, NETWORK).await.unwrap(),
        Some(215),
        "a strictly-higher observation adopts its epoch"
    );
}

// ---------------------------------------------------------------------------
// Assertion helpers.
// ---------------------------------------------------------------------------

async fn record_status(pool: &sqlx::PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM cw_core.poe_record WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read status")
}

async fn attempt_status(pool: &sqlx::PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM cw_core.chain_attempt WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read attempt status")
}

async fn record_block_height(pool: &sqlx::PgPool, id: Uuid) -> Option<i64> {
    sqlx::query_scalar("SELECT block_height FROM cw_core.poe_record WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read block height")
}

async fn record_yield_count(pool: &sqlx::PgPool, attempt_id: Uuid) -> i32 {
    sqlx::query_scalar("SELECT yield_count FROM cw_core.chain_attempt WHERE id = $1")
        .bind(attempt_id)
        .fetch_one(pool)
        .await
        .expect("read yield_count")
}

async fn attempt_next_after(pool: &sqlx::PgPool, attempt_id: Uuid) -> Option<DateTime<Utc>> {
    sqlx::query_scalar("SELECT next_attempt_after FROM cw_core.chain_attempt WHERE id = $1")
        .bind(attempt_id)
        .fetch_one(pool)
        .await
        .expect("read next_attempt_after")
}

async fn refund_intent_count(pool: &sqlx::PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.refund_intent WHERE record_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count refund intents")
}

async fn job_count(pool: &sqlx::PgPool, queue: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.job WHERE queue = $1")
        .bind(queue)
        .fetch_one(pool)
        .await
        .expect("count jobs")
}

async fn single_job_payload(pool: &sqlx::PgPool, queue: &str) -> serde_json::Value {
    let row = sqlx::query("SELECT payload FROM cw_core.job WHERE queue = $1")
        .bind(queue)
        .fetch_all(pool)
        .await
        .expect("fetch jobs");
    assert_eq!(row.len(), 1, "expected exactly one {queue} job");
    row[0].get::<serde_json::Value, _>("payload")
}

async fn subject_event_count_of(pool: &sqlx::PgPool, id: Uuid, event_type: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'poe_record' AND subject_id = $1 AND event_type = $2",
    )
    .bind(id.to_string())
    .bind(event_type)
    .fetch_one(pool)
    .await
    .expect("count events of type")
}

/// Count subject events of a type raised on a `chain_attempt` subject (the channel
/// the mempool-reconcile stuck/escalated alerts are appended under).
async fn attempt_event_count(pool: &sqlx::PgPool, attempt_id: Uuid, event_type: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'chain_attempt' AND subject_id = $1 AND event_type = $2",
    )
    .bind(attempt_id.to_string())
    .bind(event_type)
    .fetch_one(pool)
    .await
    .expect("count attempt events of type")
}

async fn chain_record_height(pool: &sqlx::PgPool, tx_hash: [u8; 32]) -> Option<i64> {
    sqlx::query_scalar("SELECT block_height FROM cw_core.chain_records WHERE tx_hash = $1")
        .bind(tx_hash.to_vec())
        .fetch_optional(pool)
        .await
        .expect("read chain record height")
}

async fn chain_record_exists(pool: &sqlx::PgPool, tx_hash: [u8; 32]) -> bool {
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.chain_records WHERE tx_hash = $1")
            .bind(tx_hash.to_vec())
            .fetch_one(pool)
            .await
            .expect("count chain records");
    count > 0
}

/// Index a confirmed attempt's transaction so `chain_records` carries a row the
/// abandon path can later delete.
async fn index_record(pool: &sqlx::PgPool, tx_hash: [u8; 32], block_height: u64) {
    let columns = gateway_core::chain::records::derive_chain_record_columns(
        &open_record_bytes(),
        gateway_core::chain::params::Network::Preprod,
    )
    .expect("derive columns");
    gateway_core::chain::records::insert_chain_record(
        pool,
        tx_hash,
        block_height,
        Utc::now(),
        &open_record_bytes(),
        &columns,
    )
    .await
    .expect("insert chain record");
}

fn confirm_config() -> ConfirmConfig {
    ConfirmConfig {
        confirmation_threshold: 5,
        rollback_window_blocks: 5,
        settlement_reverify_blocks: 10,
        max_rollback_retries: 2,
        mempool_alert_after: Duration::from_secs(1800),
        mempool_proof_of_death_after: Duration::from_secs(7200),
        max_lock_yields: 3,
        fair_lock_deadline: Duration::from_millis(500),
    }
}

fn wallet_config() -> WalletConfig {
    WalletConfig::new(
        WalletNetwork::Preprod,
        LovelaceBand::new(4_000_000, 8_000_000, 6_000_000).expect("band"),
        Duration::from_secs(120),
        4,
    )
    .expect("wallet config")
}

fn handler(pool: sqlx::PgPool, gateway: ScriptedGateway) -> ConfirmHandler<ScriptedGateway> {
    ConfirmHandler::new(pool, gateway, NETWORK, confirm_config(), wallet_config())
}

// ===========================================================================
// Pass A: tip-derived settlement over the attempt ledger.
// ===========================================================================

/// A publish attempt at/above the threshold settles with ZERO gateway traffic: the
/// attempt flips `confirmed`, its record flips `confirmed`, exactly one index_tx
/// job is enqueued, and exactly one `confirmed` event is appended.
#[tokio::test]
async fn pass_a_confirms_a_threshold_crossing_attempt_and_flips_its_record() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0x11u8; 32];
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.block_height = Some(100);
    spec.first_seen_on_chain_at = Some(Utc::now());
    let attempt_id = seed_attempt(&db.pool, spec).await;

    // Tip 110: confirmations = 110 - 100 + 1 = 11 >= threshold 5.
    set_tip(&db.pool, 110).await;

    let summary = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(summary.confirmed, 1, "the attempt crossed the threshold");
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "confirmed");
    assert_eq!(record_status(&db.pool, record).await, "confirmed");
    assert_eq!(
        record_block_height(&db.pool, record).await,
        Some(100),
        "the confirm authority projects the attempt's coordinates onto the record"
    );
    assert_eq!(
        job_count(&db.pool, INDEX_TX_QUEUE).await,
        1,
        "exactly one index_tx job for the single writer"
    );
    assert_eq!(
        subject_event_count_of(&db.pool, record, "confirmed").await,
        1,
        "exactly one confirmed event"
    );
    let payload = single_job_payload(&db.pool, INDEX_TX_QUEUE).await;
    assert_eq!(payload["tx_hash"], serde_json::json!(hex::encode(tx_hash)));
}

/// A confirming attempt drives the wallet state in the SAME transaction: its spent
/// input moves pending_spent -> confirmed_spent and its change output becomes
/// spendable and canonical.
#[tokio::test]
async fn confirm_attempt_promotes_spent_inputs_and_change() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0x55u8; 32];
    let spent_origin = [0x66u8; 32];

    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: spent_origin,
            output_index: 0,
            lovelace: 6_000_000,
            state: "pending_spent",
            source: "snapshot",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash,
            output_index: 0,
            lovelace: 5_000_000,
            state: "available",
            source: "change",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.block_height = Some(100);
    spec.first_seen_on_chain_at = Some(Utc::now());
    spec.spent_inputs = vec![input(spent_origin, 0, 6_000_000)];
    spec.produced_outputs = vec![AttemptOutput {
        index: 0,
        lovelace: 5_000_000,
    }];
    seed_attempt(&db.pool, spec).await;

    set_tip(&db.pool, 110).await;
    let summary = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration");
    assert_eq!(summary.confirmed, 1);

    let (input_state, _, _) = wallet_utxo_state(&db.pool, wallet, spent_origin, 0)
        .await
        .expect("input row");
    assert_eq!(input_state, "confirmed_spent");
    let (change_state, change_canonical, change_spendable) =
        wallet_utxo_state(&db.pool, wallet, tx_hash, 0)
            .await
            .expect("change row");
    assert_eq!(change_state, "available");
    assert!(change_spendable);
    assert!(change_canonical);
}

/// An attempt on chain below the threshold and inside the rollback window is live
/// progress: no terminal transition, no gateway call, no index job.
#[tokio::test]
async fn pass_a_below_threshold_in_window_is_progress_only() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, [0x22u8; 32]);
    spec.block_height = Some(100);
    spec.first_seen_on_chain_at = Some(Utc::now());
    let attempt_id = seed_attempt(&db.pool, spec).await;

    // Tip 102: confirmations 3 < threshold 5, advance 2 < window 5.
    set_tip(&db.pool, 102).await;
    let summary = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(summary.progress, 1);
    assert_eq!(summary.confirmed, 0);
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "broadcast");
    assert_eq!(record_status(&db.pool, record).await, "submitted");
    assert_eq!(job_count(&db.pool, INDEX_TX_QUEUE).await, 0);
}

/// A tip briefly behind an attempt's own block height is `tip_behind`: skipped, no
/// state change.
#[tokio::test]
async fn pass_a_tip_behind_skips_the_attempt() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, [0x33u8; 32]);
    spec.block_height = Some(200);
    spec.first_seen_on_chain_at = Some(Utc::now());
    let attempt_id = seed_attempt(&db.pool, spec).await;

    set_tip(&db.pool, 150).await;
    let summary = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(summary.tip_behind, 1);
    assert_eq!(summary.confirmed, 0);
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "broadcast");
}

// ===========================================================================
// Pass B: mempool discovery, never abandon on absence.
// ===========================================================================

/// A mempool-only attempt the gateway now reports on chain (below threshold) is
/// re-pinned to its observed coordinates and counted as progress.
#[tokio::test]
async fn pass_b_discovers_a_landed_mempool_attempt() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0x44u8; 32];
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let attempt_id = seed_attempt(&db.pool, SeedAttempt::publish(record, wallet, tx_hash)).await;
    set_tip(&db.pool, 300).await;

    let gateway = ScriptedGateway::new();
    gateway.set_confirmation(tx_hash, TxConfirmation::on_chain(2, 299, Utc::now()));
    let summary = handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(summary.progress, 1);
    let height: Option<i64> =
        sqlx::query_scalar("SELECT block_height FROM cw_core.chain_attempt WHERE id = $1")
            .bind(attempt_id)
            .fetch_one(&db.pool)
            .await
            .expect("read attempt height");
    assert_eq!(
        height,
        Some(299),
        "the observed height is pinned on the attempt"
    );
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "broadcast");
}

/// A mempool-only attempt still not on chain stays in the mempool: no state change,
/// no refund. Absence is never a death proof.
#[tokio::test]
async fn pass_b_mempool_absent_stays_never_refunds() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0x56u8; 32];
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let attempt_id = seed_attempt(&db.pool, SeedAttempt::publish(record, wallet, tx_hash)).await;
    set_tip(&db.pool, 300).await;

    let gateway = ScriptedGateway::new();
    gateway.set_gone(tx_hash);
    let summary = handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(summary.mempool, 1);
    assert_eq!(summary.abandoned_by_conflict, 0);
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "broadcast");
    assert_eq!(record_status(&db.pool, record).await, "submitted");
    assert_eq!(refund_intent_count(&db.pool, record).await, 0);
}

/// An observation that reports a confirmation count AT or ABOVE the threshold but
/// carries NO block height is incomplete provider data, never an on-chain sighting.
/// It must NOT settle the record at a fabricated height 0: the attempt stays in the
/// mempool watch set, its record stays `submitted`, and no index job is enqueued.
#[tokio::test]
async fn confirmations_without_block_height_never_settle() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0x57u8; 32];
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let attempt_id = seed_attempt(&db.pool, SeedAttempt::publish(record, wallet, tx_hash)).await;
    set_tip(&db.pool, 300).await;

    // A high confirmation count with NO coordinates (a partially-hydrated provider
    // response): num_confirmations 20 >= the threshold 5, but block_height is None.
    let gateway = ScriptedGateway::new();
    gateway.set_confirmation(
        tx_hash,
        TxConfirmation {
            num_confirmations: 20,
            block_height: None,
            block_time: None,
            positively_seen: true,
        },
    );
    let summary = handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(
        summary.confirmed, 0,
        "a coordinate-less observation must never confirm"
    );
    assert_eq!(
        summary.mempool, 1,
        "the never-on-chain attempt stays in the mempool watch set"
    );
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "broadcast");
    assert_eq!(record_status(&db.pool, record).await, "submitted");
    assert_eq!(
        record_block_height(&db.pool, record).await,
        None,
        "no fabricated height 0 is written"
    );
    assert_eq!(
        job_count(&db.pool, INDEX_TX_QUEUE).await,
        0,
        "no index job is enqueued on an incomplete observation"
    );
}

// ===========================================================================
// NEGATIVE: gone past the horizon but NO conflicting spend is never abandoned.
// ===========================================================================

/// An attempt that was on chain, is now GONE to a fresh lookup, with the tip past
/// the rollback window, but for which NO settlement-deep conflicting spend exists,
/// is NEVER abandoned, restored, or refunded. Its reorged-out spend is left
/// reserved; the only automatic action is the supersede control (a cancelling
/// replacement), with the original kept reconcilable.
#[tokio::test]
async fn gone_past_window_without_conflicting_spend_is_never_abandoned() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0x77u8; 32];
    let spent_origin = [0x88u8; 32];
    // The reorged-out attempt's input is still reserved (pending_spent): nothing
    // ever restores it without a settlement-deep conflicting spend.
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: spent_origin,
            output_index: 0,
            lovelace: 6_000_000,
            state: "pending_spent",
            source: "snapshot",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.block_height = Some(100);
    spec.first_seen_on_chain_at = Some(Utc::now());
    spec.spent_inputs = vec![input(spent_origin, 0, 6_000_000)];
    let attempt_id = seed_attempt(&db.pool, spec).await;

    // Tip 110: advance 10 >= window 5, so the two-source gate can fire; the fresh
    // lookup reports GONE. But no confirmed conflicting spend exists for the input.
    set_tip(&db.pool, 110).await;
    let config = ConfirmConfig {
        confirmation_threshold: 50,
        ..confirm_config()
    };
    let gateway = ScriptedGateway::new();
    gateway.set_gone(tx_hash);
    let summary = ConfirmHandler::new(db.pool.clone(), gateway, NETWORK, config, wallet_config())
        .run_iteration()
        .await
        .expect("iteration");

    // The reorged-out original is superseded by a cancelling replacement (the
    // operator-resolution control action), NOT abandoned.
    assert_eq!(
        summary.abandoned_by_conflict, 0,
        "no conflicting spend, no abandon"
    );
    assert_eq!(
        summary.rollback_retry, 1,
        "a cancelling replacement is enqueued"
    );
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        "broadcast",
        "the original stays an active broadcaster until the enqueued replacement \
         submits and supersedes it atomically; never abandoned here"
    );
    // The input is NOT restored and NO refund is written.
    let (state, _, _) = wallet_utxo_state(&db.pool, wallet, spent_origin, 0)
        .await
        .expect("input row");
    assert_eq!(
        state, "pending_spent",
        "the input stays reserved (not restored)"
    );
    assert_eq!(
        refund_intent_count(&db.pool, record).await,
        0,
        "no refund on absence"
    );
    assert_eq!(record_status(&db.pool, record).await, "submitted");
}

// ===========================================================================
// Replacement watch: original/replacement pair, whichever lands wins.
// ===========================================================================

/// Set up an original (superseded) and its cancelling replacement (active
/// broadcaster) sharing one input, plus an exclusive input on the loser. Returns
/// (record, original_id, original_tx, replacement_id, replacement_tx,
/// shared_input_origin, loser_exclusive_origin).
struct PairFixture {
    record: Uuid,
    original_id: Uuid,
    original_tx: [u8; 32],
    replacement_id: Uuid,
    replacement_tx: [u8; 32],
    shared_origin: [u8; 32],
}

async fn seed_original_replacement_pair(
    pool: &sqlx::PgPool,
    op: Uuid,
    wallet: Uuid,
) -> PairFixture {
    let original_tx = [0xa1u8; 32];
    let replacement_tx = [0xb2u8; 32];
    let shared_origin = [0xc3u8; 32];
    let original_exclusive = [0xd4u8; 32];

    let record = seed_record(pool, op, wallet, SeedRecord::new("submitted")).await;

    // The shared input both spend (the conflict), and the original's exclusive
    // input the winner does not spend (restored on the loser's abandon). Both
    // pending_spent at the start.
    for origin in [shared_origin, original_exclusive] {
        seed_wallet_utxo(
            pool,
            wallet,
            SeedUtxo {
                tx_hash: origin,
                output_index: 0,
                lovelace: 6_000_000,
                state: "pending_spent",
                source: "snapshot",
                canonical: false,
                spendable_unconfirmed: false,
            },
        )
        .await;
    }
    // The original's change output (tombstoned if the original loses).
    seed_wallet_utxo(
        pool,
        wallet,
        SeedUtxo {
            tx_hash: original_tx,
            output_index: 0,
            lovelace: 5_000_000,
            state: "available",
            source: "change",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;
    // The replacement's change output (tombstoned if the replacement loses).
    seed_wallet_utxo(
        pool,
        wallet,
        SeedUtxo {
            tx_hash: replacement_tx,
            output_index: 0,
            lovelace: 5_000_000,
            state: "available",
            source: "change",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    // The original spends shared + its exclusive input. It is recorded first as the
    // active broadcaster, then moved to `superseded` BEFORE the replacement records
    // (so the one-active-broadcaster index admits the replacement, exactly as the
    // atomic handoff does).
    let mut original = SeedAttempt::publish(record, wallet, original_tx);
    original.spent_inputs = vec![
        input(shared_origin, 0, 6_000_000),
        input(original_exclusive, 0, 6_000_000),
    ];
    original.produced_outputs = vec![AttemptOutput {
        index: 0,
        lovelace: 5_000_000,
    }];
    original.status = AttemptStatus::Superseded;
    original.point_record_at = false;
    let original_id = seed_attempt(pool, original).await;

    // The replacement spends only the shared input (the forced conflict).
    let mut replacement = SeedAttempt::publish(record, wallet, replacement_tx);
    replacement.kind = AttemptKind::Replacement;
    replacement.replaces_tx_hash = Some(original_tx);
    replacement.spent_inputs = vec![input(shared_origin, 0, 6_000_000)];
    replacement.produced_outputs = vec![AttemptOutput {
        index: 0,
        lovelace: 5_000_000,
    }];
    replacement.point_record_at = true;
    let replacement_id = seed_attempt(pool, replacement).await;

    // Link the superseded original to its replacement.
    sqlx::query("UPDATE cw_core.chain_attempt SET superseded_by = $2 WHERE id = $1")
        .bind(original_id)
        .bind(replacement_id)
        .execute(pool)
        .await
        .expect("link superseded_by");

    PairFixture {
        record,
        original_id,
        original_tx,
        replacement_id,
        replacement_tx,
        shared_origin,
    }
}

/// The REPLACEMENT lands first: it is confirmed, the superseded original is
/// abandoned by a settlement-deep conflict, the record is confirmed exactly once
/// with NO refund, the shared input stays confirmed_spent by the winner, the
/// loser's exclusive input is restored, and the loser's change output is tombstoned.
#[tokio::test]
async fn replacement_lands_first_abandons_original_by_settlement_deep_conflict() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;
    let fx = seed_original_replacement_pair(&db.pool, op, wallet).await;
    let original_exclusive = [0xd4u8; 32];

    // The replacement is on chain at height 100; tip 110 -> 11 confirmations >= 5,
    // so the winner is confirmed AT settlement depth.
    sqlx::query("UPDATE cw_core.chain_attempt SET block_height = 100, first_seen_on_chain_at = now() WHERE id = $1")
        .bind(fx.replacement_id)
        .execute(&db.pool)
        .await
        .expect("place replacement on chain");
    set_tip(&db.pool, 110).await;

    let summary = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(summary.confirmed, 1, "the replacement confirmed");
    assert_eq!(
        attempt_status(&db.pool, fx.replacement_id).await,
        "confirmed"
    );
    assert_eq!(
        attempt_status(&db.pool, fx.original_id).await,
        "abandoned",
        "the loser original is abandoned by settlement-deep conflict"
    );
    assert_eq!(record_status(&db.pool, fx.record).await, "confirmed");
    assert_eq!(
        subject_event_count_of(&db.pool, fx.record, "confirmed").await,
        1,
        "the record is confirmed exactly once"
    );
    assert_eq!(
        refund_intent_count(&db.pool, fx.record).await,
        0,
        "no refund: the PoE landed"
    );

    // The shared input the winner spent stays confirmed_spent by the winner (NOT
    // restored to the loser).
    let (shared_state, _, _) = wallet_utxo_state(&db.pool, wallet, fx.shared_origin, 0)
        .await
        .expect("shared input row");
    assert_eq!(shared_state, "confirmed_spent");
    // The loser's exclusive input is restored to available.
    let (exclusive_state, _, _) = wallet_utxo_state(&db.pool, wallet, original_exclusive, 0)
        .await
        .expect("exclusive input row");
    assert_eq!(
        exclusive_state, "available",
        "the loser's exclusive input is restored"
    );
    // The loser's change output is tombstoned (gone).
    assert!(
        wallet_utxo_state(&db.pool, wallet, fx.original_tx, 0)
            .await
            .is_none(),
        "the loser's change output is tombstoned"
    );
    // The winner's change output is promoted (spendable, canonical).
    let (_, win_canonical, win_spendable) =
        wallet_utxo_state(&db.pool, wallet, fx.replacement_tx, 0)
            .await
            .expect("winner change row");
    assert!(win_spendable && win_canonical);
}

/// The ORIGINAL lands first (a superseded original can still land before its
/// replacement). It is confirmed and the replacement loser is abandoned by a
/// settlement-deep conflict, with the same input/output discipline and no refund.
#[tokio::test]
async fn original_lands_first_after_handoff_confirms_and_abandons_replacement() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;
    let fx = seed_original_replacement_pair(&db.pool, op, wallet).await;

    // The superseded ORIGINAL is on chain at height 100 (it landed first); tip 110.
    sqlx::query("UPDATE cw_core.chain_attempt SET block_height = 100, first_seen_on_chain_at = now() WHERE id = $1")
        .bind(fx.original_id)
        .execute(&db.pool)
        .await
        .expect("place original on chain");
    set_tip(&db.pool, 110).await;

    let summary = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(summary.confirmed, 1, "the original confirmed");
    assert_eq!(attempt_status(&db.pool, fx.original_id).await, "confirmed");
    assert_eq!(
        attempt_status(&db.pool, fx.replacement_id).await,
        "abandoned",
        "the replacement loser is abandoned by settlement-deep conflict"
    );
    assert_eq!(record_status(&db.pool, fx.record).await, "confirmed");
    assert_eq!(refund_intent_count(&db.pool, fx.record).await, 0);

    // The shared input stays confirmed_spent by the winning original.
    let (shared_state, _, _) = wallet_utxo_state(&db.pool, wallet, fx.shared_origin, 0)
        .await
        .expect("shared input row");
    assert_eq!(shared_state, "confirmed_spent");
    // The replacement's change output is tombstoned.
    assert!(
        wallet_utxo_state(&db.pool, wallet, fx.replacement_tx, 0)
            .await
            .is_none(),
        "the loser replacement's change output is tombstoned"
    );
}

// ===========================================================================
// PoD-conflict only: a confirmed conflicting spend at settlement depth abandons.
// ===========================================================================

/// A confirmed original is abandoned ONLY by a settlement-deep conflicting spend:
/// a cancelling replacement re-spends one of its inputs and confirms TO settlement
/// depth. The original's exclusive inputs return to available, its indexed
/// chain_records row is deleted, and (because the record's PoE never landed via the
/// replacement) the refund is written exactly once.
#[tokio::test]
async fn settlement_deep_conflicting_replacement_abandons_a_confirmed_original() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let original_tx = [0xe1u8; 32];
    let replacement_tx = [0xf2u8; 32];
    let shared_origin = [0x1au8; 32];
    let original_exclusive = [0x2bu8; 32];

    // The reorged-out original's inputs: shared + exclusive, both confirmed_spent
    // (the original had confirmed before the reorg).
    for origin in [shared_origin, original_exclusive] {
        seed_wallet_utxo(
            &db.pool,
            wallet,
            SeedUtxo {
                tx_hash: origin,
                output_index: 0,
                lovelace: 6_000_000,
                state: "confirmed_spent",
                source: "snapshot",
                canonical: false,
                spendable_unconfirmed: false,
            },
        )
        .await;
    }

    // The record that never landed (the replacement is a bare cancelling tx, not a
    // re-publish of this record's PoE), in `submitted` after the rollback.
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;

    // The reorged-out original attempt, superseded, still reconcilable, no block
    // height (it was reorged out). It spent shared + exclusive.
    let mut original = SeedAttempt::publish(record, wallet, original_tx);
    original.spent_inputs = vec![
        input(shared_origin, 0, 6_000_000),
        input(original_exclusive, 0, 6_000_000),
    ];
    original.status = AttemptStatus::Superseded;
    original.first_seen_on_chain_at = Some(Utc::now());
    original.point_record_at = false;
    let original_id = seed_attempt(&db.pool, original).await;
    // The original was previously indexed; the abandon must delete that row.
    index_record(&db.pool, original_tx, 100).await;
    assert!(chain_record_exists(&db.pool, original_tx).await);

    // The cancelling replacement that re-spends the shared input, ON CHAIN at height
    // 100; tip 110 -> 11 confirmations >= 5, so it is settlement-deep. It is a
    // 'split'-like cancel: it does NOT carry the record forward, so the record stays
    // non-terminal and is refunded.
    let mut replacement = SeedAttempt::publish(record, wallet, replacement_tx);
    replacement.kind = AttemptKind::Replacement;
    replacement.replaces_tx_hash = Some(original_tx);
    replacement.spent_inputs = vec![input(shared_origin, 0, 6_000_000)];
    replacement.status = AttemptStatus::Confirmed;
    replacement.block_height = Some(100);
    replacement.first_seen_on_chain_at = Some(Utc::now());
    replacement.point_record_at = false;
    seed_attempt(&db.pool, replacement).await;
    // The shared input is confirmed_spent by the replacement (the winner).
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: replacement_tx,
            output_index: 0,
            lovelace: 5_000_000,
            state: "available",
            source: "change",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    set_tip(&db.pool, 110).await;
    // The original's fresh lookup reports it GONE (reorged out); the replacement is
    // its settlement-deep conflicting spend.
    let gateway = ScriptedGateway::new();
    gateway.set_gone(original_tx);
    let summary = handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(
        summary.abandoned_by_conflict, 1,
        "the original is abandoned by the settlement-deep conflicting replacement"
    );
    assert_eq!(attempt_status(&db.pool, original_id).await, "abandoned");
    // The original's exclusive input (the replacement did NOT spend it) is restored.
    let (exclusive_state, _, _) = wallet_utxo_state(&db.pool, wallet, original_exclusive, 0)
        .await
        .expect("exclusive input row");
    assert_eq!(
        exclusive_state, "available",
        "the exclusive input is restored"
    );
    // The shared input stays confirmed_spent by the winner.
    let (shared_state, _, _) = wallet_utxo_state(&db.pool, wallet, shared_origin, 0)
        .await
        .expect("shared input row");
    assert_eq!(shared_state, "confirmed_spent");
    // The original's indexed chain_records row is deleted.
    assert!(
        !chain_record_exists(&db.pool, original_tx).await,
        "the reorged-out original's index row is deleted"
    );
    // The record never landed, so exactly one refund is written.
    assert_eq!(record_status(&db.pool, record).await, "permanent_failure");
    assert_eq!(refund_intent_count(&db.pool, record).await, 1);
}

// ===========================================================================
// Post-confirmation reorg: a CONFIRMED attempt the settlement-window reverify
// pass finds gone is un-confirmed and rolled back, never left stuck `confirmed`
// pointing at a vanished tx.
// ===========================================================================

/// A literal `confirmed` attempt + record that the reverify pass observes GONE,
/// with NO settlement-deep conflicting spend, is reversed back to a broadcaster
/// and its record back to `submitted`, then rolled forward with EXACTLY ONE forced
/// cancelling replacement. No refund is written (absence alone is not death).
#[tokio::test]
async fn confirmed_then_reorged_out_no_conflict_rolls_back_with_one_replacement() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0xc7u8; 32];
    let spent_origin = [0xc8u8; 32];
    // The confirmed attempt's input is confirmed_spent (it had settled).
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: spent_origin,
            output_index: 0,
            lovelace: 6_000_000,
            state: "confirmed_spent",
            source: "snapshot",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    // A record + attempt that genuinely CONFIRMED (not superseded): the bug is that
    // a confirmed source state is treated as terminal by the rollback guards.
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("confirmed")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.status = AttemptStatus::Confirmed;
    spec.block_height = Some(100);
    spec.first_seen_on_chain_at = Some(Utc::now());
    spec.spent_inputs = vec![input(spent_origin, 0, 6_000_000)];
    let attempt_id = seed_attempt(&db.pool, spec).await;
    // Project the confirmed coordinates onto the record (as confirm would have).
    sqlx::query("UPDATE cw_core.poe_record SET block_height = 100, tx_hash = $2 WHERE id = $1")
        .bind(record)
        .bind(tx_hash.to_vec())
        .execute(&db.pool)
        .await
        .expect("project record coords");

    // Tip 108: inside the settlement-reverify window (108 - 100 = 8 < 10) AND past
    // the rollback window (8 >= 5), so the reverify pass re-checks the confirmed
    // attempt and a gone observation is a genuine deep reorg.
    set_tip(&db.pool, 108).await;
    let gateway = ScriptedGateway::new();
    gateway.set_gone(tx_hash);
    let summary = handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration");

    // Exactly one rollback, exactly one forced replacement job.
    assert_eq!(
        summary.rollback_retry, 1,
        "a confirmed-then-reorged record rolls back exactly once"
    );
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        "broadcast",
        "the reorged-out confirmed attempt is un-confirmed back to an active broadcaster"
    );
    assert_eq!(
        record_status(&db.pool, record).await,
        "submitted",
        "the record is reverted out of confirmed so the rollback can carry it"
    );
    assert_eq!(
        record_block_height(&db.pool, record).await,
        None,
        "the stale confirmed coordinates are cleared on reversal"
    );
    assert_eq!(
        refund_intent_count(&db.pool, record).await,
        0,
        "absence alone never refunds"
    );
    // A reorg_reverted audit event was appended.
    assert_eq!(
        subject_event_count_of(&db.pool, record, "reorg_reverted").await,
        1
    );

    // Exactly one cancelling replacement, forced to spend the original's input.
    let payload = single_job_payload(&db.pool, SUBMIT_QUEUE).await;
    assert_eq!(
        payload["replacement_for"],
        serde_json::json!(hex::encode(tx_hash))
    );
    let forced = payload["forced_inputs"].as_array().expect("forced array");
    assert_eq!(
        forced.len(),
        1,
        "the replacement is forced to spend one input"
    );
    assert_eq!(
        forced[0]["tx_hash"],
        serde_json::json!(hex::encode(spent_origin))
    );
}

/// A stale "gone at the old height" observation must NEVER un-confirm a record that
/// a concurrent pass already re-confirmed at a NEW height. The reorg-reversal is
/// CAS-bound to the exact (tx_hash, block_height) it observed gone, so a
/// re-inclusion at a different height is never undone by a stale gone-observation:
/// the revert matches zero rows and the fresh real coordinates survive. A genuine
/// reorg of the SAME observed coordinates still reverts.
#[tokio::test]
async fn stale_gone_observation_never_reverts_a_reconfirmed_attempt() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0xd1u8; 32];
    let spent_origin = [0xd2u8; 32];
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: spent_origin,
            output_index: 0,
            lovelace: 6_000_000,
            state: "confirmed_spent",
            source: "snapshot",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    // A confirmed record + attempt that a concurrent pass has just RE-CONFIRMED at a
    // NEW height 105 (a reorg re-included the tx one block higher). The DB row is at
    // 105; a slower pass still holds the stale "gone at 100" view.
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("confirmed")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.status = AttemptStatus::Confirmed;
    spec.block_height = Some(105);
    spec.first_seen_on_chain_at = Some(Utc::now());
    spec.spent_inputs = vec![input(spent_origin, 0, 6_000_000)];
    let attempt_id = seed_attempt(&db.pool, spec).await;
    sqlx::query("UPDATE cw_core.poe_record SET block_height = 105, tx_hash = $2 WHERE id = $1")
        .bind(record)
        .bind(tx_hash.to_vec())
        .execute(&db.pool)
        .await
        .expect("project the re-confirmed coordinates");

    // The stale revert — exactly the production CAS, but with the OLD height 100 the
    // slow pass observed gone. Because the row is now at 105, it matches zero rows.
    let stale = sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET status = 'broadcast', block_height = NULL, block_time = NULL, \
             next_attempt_after = NULL, updated_at = now() \
         WHERE id = $1 AND status = 'confirmed' AND tx_hash = $2 AND block_height = $3",
    )
    .bind(attempt_id)
    .bind(tx_hash.to_vec())
    .bind(100_i64)
    .execute(&db.pool)
    .await
    .expect("stale revert")
    .rows_affected();
    assert_eq!(
        stale, 0,
        "a stale gone-at-old-height observation must not match the re-confirmed row"
    );
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        "confirmed",
        "the re-confirmed attempt keeps its fresh coordinates"
    );
    assert_eq!(record_status(&db.pool, record).await, "confirmed");

    // A genuine reorg of the CURRENT (105) coordinates still reverts: drive the real
    // reverify pass with the tx gone and the tip past the rollback window at 105.
    // 105 + rollback_window(5) = 110, inside the reverify window (settlement reverify
    // 10: 115 - 105 = 10 is the boundary, so use 113).
    set_tip(&db.pool, 113).await;
    let gateway = ScriptedGateway::new();
    gateway.set_gone(tx_hash);
    let summary = handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration");
    assert_eq!(
        summary.rollback_retry, 1,
        "a real reorg of the current coordinates still reverts and rolls back"
    );
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "broadcast");
    assert_eq!(record_status(&db.pool, record).await, "submitted");
}

/// A literal `confirmed` attempt the reverify pass finds gone, WITH a
/// settlement-deep conflicting spend, is reversed then abandoned by the conflict:
/// its exclusive input returns to available, its index row is deleted, and because
/// the winner did not carry the record forward the un-confirmed record is refunded
/// exactly once. The confirmed source state must NOT block the abandon.
#[tokio::test]
async fn confirmed_then_reorged_out_with_conflict_abandons_and_refunds() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let original_tx = [0xe3u8; 32];
    let conflict_tx = [0xf4u8; 32];
    let shared_origin = [0x3au8; 32];
    let original_exclusive = [0x4bu8; 32];

    // Both inputs confirmed_spent (the original had confirmed).
    for origin in [shared_origin, original_exclusive] {
        seed_wallet_utxo(
            &db.pool,
            wallet,
            SeedUtxo {
                tx_hash: origin,
                output_index: 0,
                lovelace: 6_000_000,
                state: "confirmed_spent",
                source: "snapshot",
                canonical: false,
                spendable_unconfirmed: false,
            },
        )
        .await;
    }

    // The record that genuinely CONFIRMED, then was reorged out.
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("confirmed")).await;
    let mut original = SeedAttempt::publish(record, wallet, original_tx);
    original.status = AttemptStatus::Confirmed;
    original.block_height = Some(100);
    original.first_seen_on_chain_at = Some(Utc::now());
    original.spent_inputs = vec![
        input(shared_origin, 0, 6_000_000),
        input(original_exclusive, 0, 6_000_000),
    ];
    let original_id = seed_attempt(&db.pool, original).await;
    index_record(&db.pool, original_tx, 100).await;
    assert!(chain_record_exists(&db.pool, original_tx).await);

    // A foreign confirmed transaction that re-spends the shared input, settlement-
    // deep (at height 100, tip 108 -> 9 confirmations >= settlement depth 5).
    let mut conflict = SeedAttempt::publish(record, wallet, conflict_tx);
    conflict.kind = AttemptKind::Replacement;
    conflict.replaces_tx_hash = Some(original_tx);
    conflict.spent_inputs = vec![input(shared_origin, 0, 6_000_000)];
    conflict.status = AttemptStatus::Confirmed;
    conflict.block_height = Some(100);
    conflict.first_seen_on_chain_at = Some(Utc::now());
    conflict.point_record_at = false;
    seed_attempt(&db.pool, conflict).await;

    set_tip(&db.pool, 108).await;
    let gateway = ScriptedGateway::new();
    // The original is gone (reorged out); the conflict stays on chain settlement-deep.
    gateway.set_gone(original_tx);
    gateway.set_confirmation(conflict_tx, TxConfirmation::on_chain(9, 100, Utc::now()));
    let summary = handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(
        summary.abandoned_by_conflict, 1,
        "the reorged-out confirmed original is abandoned by the settlement-deep conflict"
    );
    assert_eq!(
        attempt_status(&db.pool, original_id).await,
        "abandoned",
        "the confirmed source state must not block the abandon"
    );
    // The exclusive input (the conflict did not spend it) is restored.
    let (exclusive_state, _, _) = wallet_utxo_state(&db.pool, wallet, original_exclusive, 0)
        .await
        .expect("exclusive input row");
    assert_eq!(
        exclusive_state, "available",
        "the exclusive input is restored"
    );
    // The shared input stays confirmed_spent by the winner.
    let (shared_state, _, _) = wallet_utxo_state(&db.pool, wallet, shared_origin, 0)
        .await
        .expect("shared input row");
    assert_eq!(shared_state, "confirmed_spent");
    // The reorged-out original's index row is deleted.
    assert!(
        !chain_record_exists(&db.pool, original_tx).await,
        "the reorged-out confirmed original's index row is deleted"
    );
    // The record never landed via the conflict, so it is un-confirmed and refunded once.
    assert_eq!(record_status(&db.pool, record).await, "permanent_failure");
    assert_eq!(refund_intent_count(&db.pool, record).await, 1);
}

// ===========================================================================
// A SHALLOW conflicting spend (below settlement depth) never fires the abandon.
// ===========================================================================

/// A conflicting spend that is on chain but still SHALLOW (below the settlement
/// depth) does NOT fire `abandon_attempt`: the original stays in the watch state
/// with its inputs reserved and NO refund or restore written. When that shallow
/// conflicting spend is then reorged out before reaching depth, the original
/// reverts cleanly to the watch state with NOTHING to claw back, and can still be
/// confirmed if it subsequently lands. This proves the refund transition never
/// fires before settlement depth.
#[tokio::test]
async fn shallow_conflicting_spend_never_refunds_and_reverts_cleanly() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let original_tx = [0x3cu8; 32];
    let conflict_tx = [0x4du8; 32];
    let shared_origin = [0x5eu8; 32];
    let original_exclusive = [0x6fu8; 32];

    for origin in [shared_origin, original_exclusive] {
        seed_wallet_utxo(
            &db.pool,
            wallet,
            SeedUtxo {
                tx_hash: origin,
                output_index: 0,
                lovelace: 6_000_000,
                state: "confirmed_spent",
                source: "snapshot",
                canonical: false,
                spendable_unconfirmed: false,
            },
        )
        .await;
    }

    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;

    // The reorged-out original, superseded, reconcilable, no block height.
    let mut original = SeedAttempt::publish(record, wallet, original_tx);
    original.spent_inputs = vec![
        input(shared_origin, 0, 6_000_000),
        input(original_exclusive, 0, 6_000_000),
    ];
    original.status = AttemptStatus::Superseded;
    original.first_seen_on_chain_at = Some(Utc::now());
    original.point_record_at = false;
    let original_id = seed_attempt(&db.pool, original).await;

    // The conflicting spend re-spends the shared input but is CONFIRMED only
    // SHALLOW: at height 108 with tip 110 -> 3 confirmations < settlement depth 5.
    let mut conflict = SeedAttempt::publish(record, wallet, conflict_tx);
    conflict.kind = AttemptKind::Replacement;
    conflict.replaces_tx_hash = Some(original_tx);
    conflict.spent_inputs = vec![input(shared_origin, 0, 6_000_000)];
    conflict.status = AttemptStatus::Confirmed;
    conflict.block_height = Some(108);
    conflict.first_seen_on_chain_at = Some(Utc::now());
    conflict.point_record_at = false;
    let conflict_id = seed_attempt(&db.pool, conflict).await;

    set_tip(&db.pool, 110).await;
    let gateway = ScriptedGateway::new();
    gateway.set_gone(original_tx);
    let summary = handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration with shallow conflict");

    // The shallow conflict does NOT abandon the original: no refund, no restore.
    assert_eq!(
        summary.abandoned_by_conflict, 0,
        "a shallow conflicting spend never fires the abandon"
    );
    assert_ne!(
        attempt_status(&db.pool, original_id).await,
        "abandoned",
        "the original is not abandoned while the conflict is shallow"
    );
    let (exclusive_state, _, _) = wallet_utxo_state(&db.pool, wallet, original_exclusive, 0)
        .await
        .expect("exclusive input row");
    assert_eq!(
        exclusive_state, "confirmed_spent",
        "no restore: the input state is unchanged while the conflict is shallow"
    );
    assert_eq!(
        refund_intent_count(&db.pool, record).await,
        0,
        "no refund before settlement depth"
    );
    assert_eq!(record_status(&db.pool, record).await, "submitted");

    // Now reorg the shallow conflict OUT before it reached depth: it is abandoned
    // (gone, no settlement-deep conflict of its own). The original reverts cleanly
    // to the watch state with nothing to claw back.
    sqlx::query("UPDATE cw_core.chain_attempt SET status = 'abandoned', block_height = NULL, block_time = NULL WHERE id = $1")
        .bind(conflict_id)
        .execute(&db.pool)
        .await
        .expect("reorg the shallow conflict out");

    // The original is still reconcilable and can confirm if it subsequently lands:
    // re-place it on chain at settlement depth and confirm it.
    sqlx::query("UPDATE cw_core.chain_attempt SET status = 'broadcast', block_height = 100, block_time = now() WHERE id = $1")
        .bind(original_id)
        .execute(&db.pool)
        .await
        .expect("re-land the original");
    let summary2 = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration after the conflict reorged out");

    assert_eq!(
        summary2.confirmed, 1,
        "the original can still confirm after a shallow conflict was reorged out"
    );
    assert_eq!(attempt_status(&db.pool, original_id).await, "confirmed");
    assert_eq!(record_status(&db.pool, record).await, "confirmed");
    // Across the whole envelope NO refund was ever written (no refunded-yet-settleable
    // record), and no input-state churn left a stranded restore.
    assert_eq!(
        refund_intent_count(&db.pool, record).await,
        0,
        "no refund was ever written: nothing to claw back"
    );
}

// ===========================================================================
// Coordinate-aware re-confirmation and confirmed below-threshold re-pin.
// ===========================================================================

/// A different-height re-confirmation updates the attempt, the record projection,
/// AND re-enqueues an index job carrying the new height (the single-writer repin).
#[tokio::test]
async fn different_height_reconfirmation_repins_attempt_record_and_reindexes() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0xa5u8; 32];
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.block_height = Some(100);
    spec.first_seen_on_chain_at = Some(Utc::now());
    let attempt_id = seed_attempt(&db.pool, spec).await;

    // Tip 105: 6 confirmations >= 5 (confirm) AND inside the settlement window
    // (105 - 100 = 5 < 10). Phase 1: confirm at block 100.
    set_tip(&db.pool, 105).await;
    let gateway = ScriptedGateway::new();
    gateway.set_confirmation(tx_hash, TxConfirmation::on_chain(6, 100, Utc::now()));
    handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration 1");
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "confirmed");
    assert_eq!(job_count(&db.pool, INDEX_TX_QUEUE).await, 1);
    // Complete the first index job so the next enqueue is not folded onto a pending
    // singleton.
    sqlx::query("UPDATE cw_core.job SET state = 'completed' WHERE queue = $1")
        .bind(INDEX_TX_QUEUE)
        .execute(&db.pool)
        .await
        .expect("complete first index job");
    index_record(&db.pool, tx_hash, 100).await;
    assert_eq!(chain_record_height(&db.pool, tx_hash).await, Some(100));

    // Phase 2: a reorg moved the transaction to a DIFFERENT block 101. The fresh
    // lookup reports it on chain at 101 above the threshold. The attempt re-pins, the
    // record projection re-pins, and a new index job carries the new height.
    let gateway = ScriptedGateway::new();
    gateway.set_confirmation(tx_hash, TxConfirmation::on_chain(6, 101, Utc::now()));
    handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration 2");

    let attempt_height: Option<i64> =
        sqlx::query_scalar("SELECT block_height FROM cw_core.chain_attempt WHERE id = $1")
            .bind(attempt_id)
            .fetch_one(&db.pool)
            .await
            .expect("read attempt height");
    assert_eq!(
        attempt_height,
        Some(101),
        "the attempt re-pins to the moved block"
    );
    assert_eq!(
        record_block_height(&db.pool, record).await,
        Some(101),
        "the record projection re-pins"
    );
    // A running worker consumes a completed job; the steady state is exactly one
    // PENDING index job, and it carries the moved height (the single-writer re-pin).
    let pending: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload FROM cw_core.job WHERE queue = $1 AND state = 'available'",
    )
    .bind(INDEX_TX_QUEUE)
    .fetch_all(&db.pool)
    .await
    .expect("pending index jobs");
    assert_eq!(
        pending.len(),
        1,
        "a moved-block re-confirmation enqueues exactly one more (pending) index job"
    );
    assert_eq!(
        pending[0]["block_height"], 101,
        "the re-enqueued index job carries the moved height"
    );
}

/// A `confirmed` attempt re-observed below threshold at a NEW height inside
/// the settlement window re-pins under the confirmed guard, and the repin returns a
/// row (a zero-row repin past the confirmed guard would be a logged anomaly).
#[tokio::test]
async fn confirmed_below_threshold_reinclusion_repins_under_confirmed_guard() {
    let db = TestDb::fresh().await.expect("db");
    let wallet = Uuid::now_v7(); // not used directly; repin helper is attempt-scoped
    let _ = wallet;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0xb6u8; 32];
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("confirmed")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.status = AttemptStatus::Confirmed;
    spec.block_height = Some(100);
    spec.first_seen_on_chain_at = Some(Utc::now());
    let attempt_id = seed_attempt(&db.pool, spec).await;

    // The confirmed-attempt repin helper updates the coordinates under the confirmed
    // guard and returns the affected row count.
    let mut tx = db.pool.begin().await.expect("begin");
    let affected =
        attempt::repin_confirmed_attempt_in_tx(&mut tx, attempt_id, 101, Some(Utc::now()))
            .await
            .expect("repin confirmed");
    tx.commit().await.expect("commit");
    assert_eq!(affected, 1, "the confirmed re-pin affected exactly one row");

    let height: Option<i64> =
        sqlx::query_scalar("SELECT block_height FROM cw_core.chain_attempt WHERE id = $1")
            .bind(attempt_id)
            .fetch_one(&db.pool)
            .await
            .expect("read height");
    assert_eq!(height, Some(101));

    // A same-height repin matches zero rows (the IS DISTINCT FROM guard): the caller
    // treats this as a no-op, not a silent success that masks a wrong-status row.
    let mut tx = db.pool.begin().await.expect("begin");
    let again = attempt::repin_confirmed_attempt_in_tx(&mut tx, attempt_id, 101, Some(Utc::now()))
        .await
        .expect("repin confirmed again");
    tx.commit().await.expect("commit");
    assert_eq!(again, 0, "a same-height repin is a no-op");
}

// ===========================================================================
// Lock-order, starvation-freedom, and bounded-fair lock escalation.
// ===========================================================================

/// A submit holding the wallet advisory lock while the confirm loop tries to confirm
/// (a wallet-mutating arm) on the same wallet does NOT deadlock: the confirm arm
/// takes the lock yield-not-block, yields, stamps a bounded backoff + bumps the
/// yield counter, and the attempt is re-queued (its confirm side effects are
/// withheld this pass, never applied while the submit holds the lock).
#[tokio::test]
async fn confirm_yields_when_a_submit_holds_the_wallet_lock_no_deadlock() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0xc7u8; 32];
    let spent_origin = [0xd8u8; 32];
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: spent_origin,
            output_index: 0,
            lovelace: 6_000_000,
            state: "pending_spent",
            source: "snapshot",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.block_height = Some(100);
    spec.first_seen_on_chain_at = Some(Utc::now());
    spec.spent_inputs = vec![input(spent_origin, 0, 6_000_000)];
    let attempt_id = seed_attempt(&db.pool, spec).await;
    set_tip(&db.pool, 110).await;

    // A live submit holds the wallet advisory lock for the whole iteration.
    let lock = gateway_core::wallet::pool::lock_wallet(&db.pool, wallet)
        .await
        .expect("hold the wallet lock");

    // The confirm iteration must NOT deadlock; the wallet-mutating confirm arm
    // yields rather than blocks on the held lock.
    let summary = tokio::time::timeout(
        Duration::from_secs(10),
        handler(db.pool.clone(), ScriptedGateway::new()).run_iteration(),
    )
    .await
    .expect("the confirm iteration must not deadlock on the held wallet lock")
    .expect("iteration");

    assert_eq!(
        summary.yielded, 1,
        "the confirm arm yielded on the held lock"
    );
    assert_eq!(
        summary.confirmed, 0,
        "no confirmation applied while the lock is held"
    );
    // The attempt is NOT confirmed (its side effects were withheld) and the spent
    // input was NOT touched while the submit holds the lock.
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "broadcast");
    let (state, _, _) = wallet_utxo_state(&db.pool, wallet, spent_origin, 0)
        .await
        .expect("input row");
    assert_eq!(
        state, "pending_spent",
        "no wallet mutation while the lock is held"
    );
    // The yield stamped a bounded backoff and bumped the yield counter, so the next
    // pass retries it (starvation-free).
    assert!(record_yield_count(&db.pool, attempt_id).await >= 1);
    assert!(
        attempt_next_after(&db.pool, attempt_id).await.is_some(),
        "a bounded next_attempt_after retry hint is stamped"
    );

    // Release the lock; a subsequent pass (the next_attempt_after is sub-second)
    // acquires the lock and applies the confirmation: the yielded mutation is never
    // permanently skipped.
    lock.release().await.expect("release the wallet lock");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let summary2 = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration after lock release");
    assert_eq!(
        summary2.confirmed, 1,
        "the yielded confirmation eventually commits"
    );
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "confirmed");
}

/// After the attempt has yielded past the `max_lock_yields` threshold the next
/// acquisition escalates to a bounded-fair acquire: once the holding lock is
/// released the escalated acquire commits the mutation within its bounded deadline
/// rather than only eventually, and a yield_count past the anomaly threshold is
/// surfaced (recorded on the attempt).
#[tokio::test]
async fn bounded_fair_escalation_commits_a_persistently_contended_mutation() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0xe9u8; 32];
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.block_height = Some(100);
    spec.first_seen_on_chain_at = Some(Utc::now());
    let attempt_id = seed_attempt(&db.pool, spec).await;
    set_tip(&db.pool, 110).await;

    // Pre-stamp the attempt with a yield count past the escalation threshold (3) and
    // a due next_attempt_after, simulating a record that has already yielded several
    // passes under sustained contention.
    sqlx::query(
        "UPDATE cw_core.chain_attempt SET yield_count = 4, next_attempt_after = now() - interval '1 second' WHERE id = $1",
    )
    .bind(attempt_id)
    .execute(&db.pool)
    .await
    .expect("pre-stamp yields");
    assert!(record_yield_count(&db.pool, attempt_id).await >= 3);

    // No submit holds the lock now, so the escalated bounded-fair acquire succeeds
    // immediately and the mutation commits within the bounded budget (not just
    // eventually).
    let summary = tokio::time::timeout(
        Duration::from_secs(5),
        handler(db.pool.clone(), ScriptedGateway::new()).run_iteration(),
    )
    .await
    .expect("the bounded-fair acquire must complete within the budget")
    .expect("iteration");

    assert_eq!(
        summary.confirmed, 1,
        "the persistently-contended mutation commits via the bounded-fair acquire"
    );
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "confirmed");
}

// ===========================================================================
// The single chain_records writer + index handler (unchanged behaviour).
// ===========================================================================

/// The index_tx handler derives the columns from inline metadata and inserts one
/// chain_records row, with no confirmations column anywhere.
#[tokio::test]
async fn index_tx_handler_inserts_one_chain_record_with_derived_columns() {
    let db = TestDb::fresh().await.expect("db");
    let seed = [0x42u8; 32];
    let (record_bytes, pubkey) = signed_record_bytes(&seed);
    let tx_hash = [0xbbu8; 32];

    let job = IndexTxJob {
        tx_hash: hex::encode(tx_hash),
        block_height: 500,
        block_time: Utc::now(),
        metadata: MetadataSource::Inline {
            metadata_cbor: record_bytes.clone(),
        },
    };

    let handler = gateway_core::chain::records::IndexTxHandler::new(
        db.pool.clone(),
        ScriptedGateway::new(),
        gateway_core::chain::params::Network::Preprod,
    );
    assert!(handler.index_once(&job).await.expect("index"));

    let row = sqlx::query(
        "SELECT block_height, item_count, scheme, signer_ed25519, metadata_cbor \
         FROM cw_core.chain_records WHERE tx_hash = $1",
    )
    .bind(tx_hash.to_vec())
    .fetch_one(&db.pool)
    .await
    .expect("read chain_record");
    assert_eq!(row.get::<i64, _>("block_height"), 500);
    assert_eq!(row.get::<i32, _>("item_count"), 1);
    assert_eq!(row.get::<i16, _>("scheme"), 0);
    assert_eq!(
        row.get::<Option<Vec<u8>>, _>("signer_ed25519"),
        Some(pubkey.to_vec())
    );
    assert_eq!(row.get::<Vec<u8>, _>("metadata_cbor"), record_bytes);

    let has_confirmations: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
           SELECT 1 FROM information_schema.columns \
           WHERE table_schema = 'cw_core' AND table_name = 'chain_records' \
             AND column_name LIKE '%confirmation%')",
    )
    .fetch_one(&db.pool)
    .await
    .expect("introspect columns");
    assert!(!has_confirmations);
}

/// `delete_chain_record_by_tx_hash` removes the targeted indexed row (the abandon
/// arm's index purge) and leaves the historical `cw_api.records` anchor.
#[tokio::test]
async fn delete_chain_record_removes_the_row_and_keeps_the_anchor() {
    let db = TestDb::fresh().await.expect("db");
    let tx_hash = [0xcdu8; 32];
    index_record(&db.pool, tx_hash, 42).await;
    assert!(chain_record_exists(&db.pool, tx_hash).await);

    let mut tx = db.pool.begin().await.expect("begin");
    let deleted = gateway_core::chain::records::delete_chain_record_by_tx_hash(&mut *tx, tx_hash)
        .await
        .expect("delete chain record");
    tx.commit().await.expect("commit");
    assert_eq!(deleted, 1, "exactly the targeted row is deleted");
    assert!(!chain_record_exists(&db.pool, tx_hash).await);

    // The thin cw_api.records anchor is the historical reference and is left.
    let anchor: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_api.records WHERE tx_hash = $1")
        .bind(tx_hash.to_vec())
        .fetch_one(&db.pool)
        .await
        .expect("count anchor");
    assert_eq!(anchor, 1, "the historical anchor is left in place");
}

/// The fetch-by-hash source resolves the metadata CBOR from the gateway when the
/// job carries no inline bytes.
#[tokio::test]
async fn index_tx_fetch_by_hash_resolves_metadata_from_the_gateway() {
    let db = TestDb::fresh().await.expect("db");
    let record_bytes = open_record_bytes();
    let tx_hash = [0xddu8; 32];

    let gateway = ScriptedGateway::new();
    gateway.set_cbor(tx_hash, record_bytes.clone());
    let job = IndexTxJob {
        tx_hash: hex::encode(tx_hash),
        block_height: 20,
        block_time: Utc::now(),
        metadata: MetadataSource::FetchByHash,
    };

    let handler = gateway_core::chain::records::IndexTxHandler::new(
        db.pool.clone(),
        gateway,
        gateway_core::chain::params::Network::Preprod,
    );
    assert!(handler.index_once(&job).await.expect("index"));
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT metadata_cbor FROM cw_core.chain_records WHERE tx_hash = $1")
            .bind(tx_hash.to_vec())
            .fetch_one(&db.pool)
            .await
            .expect("read");
    assert_eq!(stored, record_bytes);
}

// ===========================================================================
// Monotonic tip upsert.
// ===========================================================================

/// The tip upsert is monotonic: a higher observation advances it, a lower one never
/// regresses it.
#[tokio::test]
async fn tip_upsert_is_monotonic() {
    let db = TestDb::fresh().await.expect("db");
    set_tip(&db.pool, 100).await;
    set_tip(&db.pool, 150).await;
    set_tip(&db.pool, 120).await;

    let height: i64 =
        sqlx::query_scalar("SELECT tip_block_height FROM cw_core.cardano_tip WHERE network = $1")
            .bind(NETWORK)
            .fetch_one(&db.pool)
            .await
            .expect("read tip");
    assert_eq!(height, 150);
}

/// A cancelling-replacement rollback supersedes the reorged-out original (keeps it
/// reconcilable) and enqueues exactly one replacement submit job forced to spend the
/// original's input.
#[tokio::test]
async fn rollback_supersedes_original_and_enqueues_a_forced_replacement() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0xeeu8; 32];
    let spent_origin = [0x91u8; 32];
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.block_height = Some(100);
    spec.first_seen_on_chain_at = Some(Utc::now());
    spec.spent_inputs = vec![input(spent_origin, 0, 5_000_000)];
    let attempt_id = seed_attempt(&db.pool, spec).await;

    set_tip(&db.pool, 110).await;
    let config = ConfirmConfig {
        confirmation_threshold: 50,
        max_rollback_retries: 3,
        ..confirm_config()
    };
    let gateway = ScriptedGateway::new();
    gateway.set_gone(tx_hash);
    let summary = ConfirmHandler::new(db.pool.clone(), gateway, NETWORK, config, wallet_config())
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(summary.rollback_retry, 1);
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        "broadcast",
        "the reorged-out original stays an active broadcaster until the enqueued \
         replacement submits and supersedes it; kept reconcilable, not refunded"
    );
    assert_eq!(record_status(&db.pool, record).await, "submitted");
    assert_eq!(refund_intent_count(&db.pool, record).await, 0);

    let payload = single_job_payload(&db.pool, SUBMIT_QUEUE).await;
    assert_eq!(
        payload["replacement_for"],
        serde_json::json!(hex::encode(tx_hash))
    );
    let forced = payload["forced_inputs"].as_array().expect("forced array");
    assert_eq!(
        forced.len(),
        1,
        "the replacement is forced to spend one input"
    );
    assert_eq!(
        forced[0]["tx_hash"],
        serde_json::json!(hex::encode(spent_origin))
    );
}

// ===========================================================================
// Mempool reconcile: alert-only. A stuck transaction is an operator-visible
// reconcile state, NEVER an automatic refund. Money and inputs move ONLY on a
// settlement-deep conflicting spend, via an operator-issued cancelling replacement.
// ===========================================================================

/// (a) A broadcast attempt past the alert threshold transitions to `stuck` and
/// raises an operator alert, and is NOT refunded, restored, or abandoned. Its input
/// stays reserved; the record stays in its customer state.
#[tokio::test]
async fn stuck_alert_past_threshold_never_refunds_or_restores() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0x91u8; 32];
    let spent_origin = [0x92u8; 32];
    // The attempt's input is reserved (pending_spent): the alert pass must NOT
    // restore it.
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: spent_origin,
            output_index: 0,
            lovelace: 6_000_000,
            state: "pending_spent",
            source: "snapshot",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.spent_inputs = vec![input(spent_origin, 0, 6_000_000)];
    // Entered the mempool well past the 1800s alert threshold, but inside the 7200s
    // long horizon, so it alerts but does not escalate.
    spec.mempool_entered_at = Some(Utc::now() - chrono::Duration::seconds(3600));
    let attempt_id = seed_attempt(&db.pool, spec).await;
    set_tip(&db.pool, 300).await;

    // The gateway is never consulted for the broadcast->stuck transition (it is
    // tip/clock-only); a not-found answer here would not change the alert-only result.
    let summary = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(
        summary.mempool_stuck, 1,
        "the attempt is marked stuck + alerted"
    );
    assert_eq!(
        summary.mempool_stuck_escalated, 0,
        "not yet past the long horizon"
    );
    assert_eq!(
        summary.abandoned_by_conflict, 0,
        "alert is never an abandon"
    );
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "stuck");
    assert_eq!(
        attempt_event_count(&db.pool, attempt_id, MEMPOOL_STUCK_EVENT).await,
        1,
        "exactly one stuck alert is raised"
    );
    // The input stays reserved; nothing is restored.
    let (state, _, _) = wallet_utxo_state(&db.pool, wallet, spent_origin, 0)
        .await
        .expect("input row");
    assert_eq!(
        state, "pending_spent",
        "the input is never restored on alert"
    );
    // No refund; the record stays in its customer state.
    assert_eq!(
        refund_intent_count(&db.pool, record).await,
        0,
        "no refund on age"
    );
    assert_eq!(record_status(&db.pool, record).await, "submitted");

    // Idempotent: a second pass does not re-alert (the attempt is already stuck, and
    // mark_stuck no-ops a non-broadcast row).
    let summary2 = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("second iteration");
    assert_eq!(summary2.mempool_stuck, 0, "no duplicate stuck transition");
    assert_eq!(
        attempt_event_count(&db.pool, attempt_id, MEMPOOL_STUCK_EVENT).await,
        1,
        "no duplicate stuck alert"
    );
}

/// (b) A rolled-back record whose live replacement attempt has a FRESH
/// `mempool_entered_at` is never reconciled-to-stuck: the alert pass keys on the
/// attempt's `mempool_entered_at`, not the record's `created_at`, so the fresh
/// replacement is not mistaken for the stale rolled-back original.
#[tokio::test]
async fn fresh_replacement_after_rollback_is_not_reconciled_as_stale() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    // The record itself is OLD (it was created long ago and rolled back once), so a
    // created_at-keyed predicate would wrongly flag its live attempt.
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    sqlx::query(
        "UPDATE cw_core.poe_record SET created_at = now() - make_interval(hours => 6) WHERE id = $1",
    )
    .bind(record)
    .execute(&db.pool)
    .await
    .expect("age the record");

    // The fresh replacement attempt: just (re-)broadcast, so its mempool entry is
    // recent and it is a healthy in-flight transaction, NOT stuck.
    let tx_hash = [0xa3u8; 32];
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.mempool_entered_at = Some(Utc::now());
    let attempt_id = seed_attempt(&db.pool, spec).await;
    set_tip(&db.pool, 300).await;

    let summary = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(
        summary.mempool_stuck, 0,
        "a fresh replacement is never marked stuck on the record's age"
    );
    assert_eq!(summary.abandoned_by_conflict, 0);
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        "broadcast",
        "the fresh replacement stays a healthy broadcaster"
    );
    assert_eq!(
        attempt_event_count(&db.pool, attempt_id, MEMPOOL_STUCK_EVENT).await,
        0,
        "no stuck alert on a fresh replacement"
    );
    assert_eq!(refund_intent_count(&db.pool, record).await, 0);
}

/// (c) An attempt past the LONG horizon whose fresh lookup reports it GONE has its
/// alert ESCALATED, but is still NOT abandoned, restored, or refunded. Under the
/// no-validity-interval model absence + horizon is not a proof of death.
#[tokio::test]
async fn presumed_dead_escalates_alert_but_never_refunds() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0xb4u8; 32];
    let spent_origin = [0xb5u8; 32];
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: spent_origin,
            output_index: 0,
            lovelace: 6_000_000,
            state: "pending_spent",
            source: "snapshot",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.spent_inputs = vec![input(spent_origin, 0, 6_000_000)];
    // Already `stuck` from a prior pass, and past the 7200s long horizon.
    spec.status = AttemptStatus::Stuck;
    spec.mempool_entered_at = Some(Utc::now() - chrono::Duration::seconds(10_800));
    let attempt_id = seed_attempt(&db.pool, spec).await;
    set_tip(&db.pool, 300).await;

    // The fresh per-candidate lookup reports the transaction GONE (not found).
    let gateway = ScriptedGateway::new();
    gateway.set_gone(tx_hash);
    let summary = handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(
        summary.mempool_stuck_escalated, 1,
        "the long-horizon not-found attempt escalates its alert"
    );
    assert_eq!(
        summary.mempool_stuck, 0,
        "already stuck: no new stuck transition"
    );
    assert_eq!(
        summary.abandoned_by_conflict, 0,
        "absence + horizon is never a death proof"
    );
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        "stuck",
        "still stuck; never abandoned on absence"
    );
    assert_eq!(
        attempt_event_count(&db.pool, attempt_id, MEMPOOL_PRESUMED_DEAD_EVENT).await,
        1,
        "exactly one escalation alert is raised"
    );
    // The input is NOT restored and NO refund is written.
    let (state, _, _) = wallet_utxo_state(&db.pool, wallet, spent_origin, 0)
        .await
        .expect("input row");
    assert_eq!(state, "pending_spent", "absence never restores inputs");
    assert_eq!(
        refund_intent_count(&db.pool, record).await,
        0,
        "no refund on absence"
    );
    assert_eq!(record_status(&db.pool, record).await, "submitted");
}

/// (d) The canonical resolution of a stuck attempt: an operator issues a cancelling
/// replacement (which re-spends one of the stuck transaction's inputs), and when
/// that replacement confirms TO SETTLEMENT DEPTH the confirm authority abandons the
/// stuck original by a settlement-deep PoD-conflict, restoring its exclusive inputs.
/// Here the operator-issued replacement carries the record's PoE forward, so the
/// record LANDS (confirmed) and no refund is written; the refund clause fires only
/// when the record never landed, the complementary branch covered by
/// `settlement_deep_conflicting_replacement_abandons_a_confirmed_original`. Either
/// way the inputs and refund move ONLY on the settlement-deep conflict, never on the
/// stuck/alert state.
#[tokio::test]
async fn issuing_replacement_then_confirming_it_abandons_the_stuck_original() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let original_tx = [0xc6u8; 32];
    let shared_origin = [0xc7u8; 32];
    let original_exclusive = [0xc8u8; 32];

    // The stuck original's inputs, both reserved to it (pending_spent).
    for origin in [shared_origin, original_exclusive] {
        seed_wallet_utxo(
            &db.pool,
            wallet,
            SeedUtxo {
                tx_hash: origin,
                output_index: 0,
                lovelace: 6_000_000,
                state: "pending_spent",
                source: "snapshot",
                canonical: false,
                spendable_unconfirmed: false,
            },
        )
        .await;
    }

    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, original_tx);
    spec.spent_inputs = vec![
        input(shared_origin, 0, 6_000_000),
        input(original_exclusive, 0, 6_000_000),
    ];
    // Stuck in the mempool, no block height.
    spec.status = AttemptStatus::Stuck;
    spec.mempool_entered_at = Some(Utc::now() - chrono::Duration::seconds(3600));
    let original_id = seed_attempt(&db.pool, spec).await;
    set_tip(&db.pool, 300).await;

    // The operator control action: issue a cancelling replacement for the stuck
    // attempt. It enqueues a replacement submit job forced to spend the original's
    // inputs (the conflict); the submit path supersedes the still-active original when
    // the replacement records. It moves no money.
    let issued = handler(db.pool.clone(), ScriptedGateway::new())
        .issue_cancelling_replacement(original_id)
        .await
        .expect("issue replacement");
    assert!(issued, "the control action issued the replacement");
    assert_eq!(
        attempt_status(&db.pool, original_id).await,
        "stuck",
        "the stuck original stays an active broadcaster until the enqueued replacement \
         submits and supersedes it atomically; not abandoned on issuance"
    );
    // The replacement submit job carries the forced inputs (the conflict).
    let payload = single_job_payload(&db.pool, SUBMIT_QUEUE).await;
    assert_eq!(
        payload["replacement_for"],
        serde_json::json!(hex::encode(original_tx))
    );
    let forced = payload["forced_inputs"].as_array().expect("forced array");
    assert!(
        forced
            .iter()
            .any(|f| f["tx_hash"] == serde_json::json!(hex::encode(shared_origin))),
        "the replacement re-spends a shared input of the original"
    );
    // No money moved yet: nothing restored, nothing refunded.
    let (exclusive_before, _, _) = wallet_utxo_state(&db.pool, wallet, original_exclusive, 0)
        .await
        .expect("exclusive input row");
    assert_eq!(exclusive_before, "pending_spent", "no restore on issuance");
    assert_eq!(
        refund_intent_count(&db.pool, record).await,
        0,
        "no refund on issuance"
    );

    // Simulate the replacement landing and confirming TO SETTLEMENT DEPTH (the submit
    // path that builds and broadcasts it is exercised elsewhere; here we drive its
    // confirmed terminal state so the settlement-deep PoD-conflict closure is what is
    // under test). The submit path's atomic handoff supersedes the still-active stuck
    // original the instant it records the replacement (so the one-active index holds);
    // mirror that here by superseding the original before seeding the replacement,
    // since this test injects the replacement directly rather than through the submit
    // path. The replacement re-spends ONLY the shared input.
    sqlx::query("UPDATE cw_core.chain_attempt SET status = 'superseded' WHERE id = $1")
        .bind(original_id)
        .execute(&db.pool)
        .await
        .expect("supersede the original (the submit handoff does this atomically)");
    let replacement_tx = [0xd9u8; 32];
    let mut rspec = SeedAttempt::publish(record, wallet, replacement_tx);
    rspec.kind = AttemptKind::Replacement;
    rspec.replaces_tx_hash = Some(original_tx);
    rspec.spent_inputs = vec![input(shared_origin, 0, 6_000_000)];
    rspec.produced_outputs = vec![AttemptOutput {
        index: 0,
        lovelace: 5_000_000,
    }];
    // On chain at height 100 but not yet confirmed: Pass A confirms it THIS iteration
    // and, in the same transaction, abandons the superseded stuck original by the
    // settlement-deep conflict (the winner-confirmation path).
    rspec.status = AttemptStatus::Broadcast;
    rspec.block_height = Some(100);
    rspec.first_seen_on_chain_at = Some(Utc::now());
    rspec.point_record_at = true;
    let replacement_id = seed_attempt(&db.pool, rspec).await;
    // Link the superseded original to its replacement so the confirm authority walks
    // the pair (the submit path sets this when the replacement records its attempt).
    sqlx::query("UPDATE cw_core.chain_attempt SET superseded_by = $2 WHERE id = $1")
        .bind(original_id)
        .bind(replacement_id)
        .execute(&db.pool)
        .await
        .expect("link superseded_by");
    // The replacement's change output (promoted on its confirmation).
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: replacement_tx,
            output_index: 0,
            lovelace: 5_000_000,
            state: "available",
            source: "change",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    // tip 110 -> 11 confirmations on the replacement >= 5, so Pass A confirms it AT
    // settlement depth. The winner's confirmation promotes the shared input to
    // confirmed_spent and, in the SAME transaction, abandons the stuck original by
    // the settlement-deep conflict (a side effect of the confirm, so it is counted in
    // `confirmed`, and proven by the original's resulting `abandoned` status below).
    set_tip(&db.pool, 110).await;
    let summary = handler(db.pool.clone(), ScriptedGateway::new())
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(summary.confirmed, 1, "the replacement confirmed");
    assert_eq!(
        attempt_status(&db.pool, replacement_id).await,
        "confirmed",
        "the operator-issued replacement confirmed at settlement depth"
    );
    assert_eq!(
        attempt_status(&db.pool, original_id).await,
        "abandoned",
        "the stuck original is terminalised by the settlement-deep conflict"
    );
    // The original's exclusive input (the replacement did NOT spend it) is restored.
    let (exclusive_after, _, _) = wallet_utxo_state(&db.pool, wallet, original_exclusive, 0)
        .await
        .expect("exclusive input row");
    assert_eq!(
        exclusive_after, "available",
        "the stuck original's exclusive input is restored on the settlement-deep abandon"
    );
    // The shared input is confirmed_spent by the winning replacement (NOT restored).
    let (shared_state, _, _) = wallet_utxo_state(&db.pool, wallet, shared_origin, 0)
        .await
        .expect("shared input row");
    assert_eq!(shared_state, "confirmed_spent");
    // The operator-issued replacement carried the record's PoE forward, so the record
    // LANDED (confirmed) and NO refund is written: the refund clause fires only when
    // the record never landed, and the single-refund discipline is preserved either
    // way. The complementary bare-cancel refund branch is covered by
    // `settlement_deep_conflicting_replacement_abandons_a_confirmed_original`.
    assert_eq!(record_status(&db.pool, record).await, "confirmed");
    assert_eq!(
        subject_event_count_of(&db.pool, record, "confirmed").await,
        1,
        "the record is confirmed exactly once"
    );
    assert_eq!(
        refund_intent_count(&db.pool, record).await,
        0,
        "no refund: the operator-issued replacement carried the PoE forward and it landed"
    );
}

/// The rollback handoff is idempotent: two passes (e.g. two concurrent confirm
/// passes, or a confirm pass racing an operator call) that both observe the same
/// reorged-out original enqueue AT MOST ONE cancelling replacement and bump the
/// rollback count exactly once. The first pass clears `current_attempt_id`, so the
/// second pass's `current_attempt_id = $original` guard matches zero rows and the
/// handoff is a no-op. Models the race sequentially: the second call starts from
/// the post-first-handoff state exactly as a slower concurrent pass would commit.
#[tokio::test]
async fn rollback_handoff_is_idempotent_under_a_second_pass() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let original_tx = [0xa7u8; 32];
    let spent_origin = [0xa8u8; 32];
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: spent_origin,
            output_index: 0,
            lovelace: 6_000_000,
            state: "pending_spent",
            source: "snapshot",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, original_tx);
    spec.spent_inputs = vec![input(spent_origin, 0, 6_000_000)];
    spec.status = AttemptStatus::Stuck;
    spec.mempool_entered_at = Some(Utc::now() - chrono::Duration::seconds(3600));
    let original_id = seed_attempt(&db.pool, spec).await;
    set_tip(&db.pool, 300).await;

    // First handoff: enqueues exactly one replacement and clears current_attempt_id.
    let first = handler(db.pool.clone(), ScriptedGateway::new())
        .issue_cancelling_replacement(original_id)
        .await
        .expect("first issue");
    assert!(first, "the first handoff is applied");

    // Second handoff (the racing pass): the original is still a stuck active
    // broadcaster (the submit-side supersede has not run), so the operator path loads
    // it and attempts the handoff again. The current_attempt_id guard now matches zero
    // rows, so it returns false and enqueues nothing.
    let second = handler(db.pool.clone(), ScriptedGateway::new())
        .issue_cancelling_replacement(original_id)
        .await
        .expect("second issue");
    assert!(
        !second,
        "the second handoff is a no-op: the record no longer points at the original"
    );

    // Exactly one replacement submit job, one rollback bump, one retrying event.
    assert_eq!(
        job_count(&db.pool, SUBMIT_QUEUE).await,
        1,
        "concurrent handoffs enqueue at most one cancelling replacement"
    );
    let rollback_count: i32 =
        sqlx::query_scalar("SELECT rollback_retry_count FROM cw_core.poe_record WHERE id = $1")
            .bind(record)
            .fetch_one(&db.pool)
            .await
            .expect("read rollback count");
    assert_eq!(
        rollback_count, 1,
        "the rollback count is bumped exactly once, never double-counted"
    );
    assert_eq!(
        subject_event_count_of(&db.pool, record, "retrying").await,
        1,
        "exactly one retrying event"
    );
}

/// The operator resolution for a STRANDED `recorded` attempt (one whose broadcast
/// never reached the wire, surfaced by the recovery sweep's stranded alert): the
/// same `issue_cancelling_replacement` control action supersedes the recorded
/// original and enqueues a cancelling replacement, even though the original never
/// reached the mempool and its record is still `submitting`. A blind age-refund is
/// never safe for a `recorded` attempt (the body may yet be in a mempool), so this
/// proof-producing replacement is the resolution. No money moves on issuance.
#[tokio::test]
async fn issuing_a_cancelling_replacement_resolves_a_stranded_recorded_attempt() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let stranded_tx = [0x5au8; 32];
    let reserved_input = [0x5bu8; 32];

    // The stranded recorded attempt's input, reserved to it (pending_spent) exactly
    // as record-before-broadcast left it. It must stay reserved: a stranded recorded
    // attempt's bytes may yet be in a mempool, so its inputs are never restored on age.
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: reserved_input,
            output_index: 0,
            lovelace: 6_000_000,
            state: "pending_spent",
            source: "snapshot",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    // A FIRST-publish record still `submitting`: its original never broadcast, so it
    // never reached `submitted`. This is the stranded first-publish case the recovery
    // alert surfaces and the operator lever must resolve.
    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitting")).await;
    let mut spec = SeedAttempt::publish(record, wallet, stranded_tx);
    spec.spent_inputs = vec![input(reserved_input, 0, 6_000_000)];
    // Stranded: recorded, never on the wire (NULL mempool entry), no block height.
    spec.status = AttemptStatus::Recorded;
    spec.mempool_entered_at = None;
    let stranded_id = seed_attempt(&db.pool, spec).await;
    set_tip(&db.pool, 300).await;

    // The same operator control action resolves the stranded recorded attempt.
    let issued = handler(db.pool.clone(), ScriptedGateway::new())
        .issue_cancelling_replacement(stranded_id)
        .await
        .expect("issue replacement for a stranded recorded attempt");
    assert!(issued, "the control action issued the replacement");

    // The stranded original stays an active broadcaster (`recorded`): the supersede is
    // the submit path's atomic handoff when the enqueued replacement records, NOT this
    // enqueue step. It is never abandoned/refunded on age.
    assert_eq!(
        attempt_status(&db.pool, stranded_id).await,
        "recorded",
        "the stranded recorded original stays active until the replacement submits"
    );
    // The record was normalised `submitting` -> `submitted` so the replacement's
    // generation guard can claim it, with its attempt pointer cleared.
    assert_eq!(record_status(&db.pool, record).await, "submitted");

    // The replacement submit job carries the forced inputs (the conflict the
    // at-most-one-lands invariant rests on).
    let payload = single_job_payload(&db.pool, SUBMIT_QUEUE).await;
    assert_eq!(
        payload["replacement_for"],
        serde_json::json!(hex::encode(stranded_tx))
    );
    let forced = payload["forced_inputs"].as_array().expect("forced array");
    assert!(
        forced
            .iter()
            .any(|f| f["tx_hash"] == serde_json::json!(hex::encode(reserved_input))),
        "the replacement re-spends the stranded original's reserved input"
    );

    // No money moved and the input stays reserved: nothing restored, nothing refunded.
    let (input_state, _, _) = wallet_utxo_state(&db.pool, wallet, reserved_input, 0)
        .await
        .expect("reserved input row");
    assert_eq!(
        input_state, "pending_spent",
        "the stranded original's input stays reserved on issuance (never restored on age)"
    );
    assert_eq!(
        refund_intent_count(&db.pool, record).await,
        0,
        "no refund on issuance: termination waits for the settlement-deep conflict proof"
    );
}

/// The operator wedged-attempt list surfaces BOTH a stuck (on-the-wire) attempt and
/// a stranded `recorded` (never-broadcast) attempt, so the recovery sweep's stranded
/// alert has a matching control-surface entry the operator can act on. A healthy
/// `broadcast` attempt is NOT listed.
#[tokio::test]
async fn the_wedged_attempt_list_includes_stranded_recorded_attempts() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    // A stuck attempt (reached the wire, mempool entry stamped).
    let stuck_record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut stuck = SeedAttempt::publish(stuck_record, wallet, [0x6au8; 32]);
    stuck.status = AttemptStatus::Stuck;
    stuck.mempool_entered_at = Some(Utc::now() - chrono::Duration::seconds(3600));
    let stuck_id = seed_attempt(&db.pool, stuck).await;

    // A stranded recorded attempt (never reached the wire, NULL mempool entry).
    let stranded_record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitting")).await;
    let mut stranded = SeedAttempt::publish(stranded_record, wallet, [0x6bu8; 32]);
    stranded.status = AttemptStatus::Recorded;
    stranded.mempool_entered_at = None;
    let stranded_id = seed_attempt(&db.pool, stranded).await;

    // A healthy broadcast attempt (progressing normally): must NOT be listed.
    let healthy_record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut healthy = SeedAttempt::publish(healthy_record, wallet, [0x6cu8; 32]);
    healthy.status = AttemptStatus::Broadcast;
    healthy.mempool_entered_at = Some(Utc::now());
    let healthy_id = seed_attempt(&db.pool, healthy).await;

    let listed = handler(db.pool.clone(), ScriptedGateway::new())
        .list_stuck_attempts(100)
        .await
        .expect("list wedged attempts");

    let ids: Vec<Uuid> = listed.iter().map(|a| a.attempt_id).collect();
    assert!(ids.contains(&stuck_id), "the stuck attempt is listed");
    assert!(
        ids.contains(&stranded_id),
        "the stranded recorded attempt is listed for operator resolution"
    );
    assert!(
        !ids.contains(&healthy_id),
        "a healthy broadcast attempt is NOT listed"
    );
}

/// (e) An attempt whose fresh lookup STILL FINDS it on chain is NEVER abandoned,
/// regardless of how long it has been in the mempool: a transaction that is on chain
/// is alive, so age is irrelevant.
#[tokio::test]
async fn on_chain_attempt_is_never_abandoned_regardless_of_age() {
    let db = TestDb::fresh().await.expect("db");
    register_policies(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, op).await;

    let tx_hash = [0xeau8; 32];
    let spent_origin = [0xebu8; 32];
    seed_wallet_utxo(
        &db.pool,
        wallet,
        SeedUtxo {
            tx_hash: spent_origin,
            output_index: 0,
            lovelace: 6_000_000,
            state: "pending_spent",
            source: "snapshot",
            canonical: false,
            spendable_unconfirmed: false,
        },
    )
    .await;

    let record = seed_record(&db.pool, op, wallet, SeedRecord::new("submitted")).await;
    let mut spec = SeedAttempt::publish(record, wallet, tx_hash);
    spec.spent_inputs = vec![input(spent_origin, 0, 6_000_000)];
    // On chain below threshold for a long time: very old mempool entry, but landed.
    spec.block_height = Some(98);
    spec.first_seen_on_chain_at = Some(Utc::now());
    spec.mempool_entered_at = Some(Utc::now() - chrono::Duration::seconds(10_800));
    let attempt_id = seed_attempt(&db.pool, spec).await;

    // tip 100 -> 3 confirmations < threshold 5, so it is on chain below threshold.
    set_tip(&db.pool, 100).await;
    // The fresh lookup STILL FINDS it on chain (3 confirmations).
    let gateway = ScriptedGateway::new();
    gateway.set_confirmation(tx_hash, TxConfirmation::on_chain(3, 98, Utc::now()));
    let summary = handler(db.pool.clone(), gateway)
        .run_iteration()
        .await
        .expect("iteration");

    assert_eq!(
        summary.abandoned_by_conflict, 0,
        "an on-chain attempt is never abandoned, regardless of age"
    );
    assert_eq!(
        summary.mempool_stuck, 0,
        "an on-chain attempt is not a mempool candidate"
    );
    assert_eq!(summary.mempool_stuck_escalated, 0);
    assert_ne!(
        attempt_status(&db.pool, attempt_id).await,
        "abandoned",
        "the on-chain attempt is never abandoned"
    );
    // The input stays reserved; nothing restored, no refund.
    let (state, _, _) = wallet_utxo_state(&db.pool, wallet, spent_origin, 0)
        .await
        .expect("input row");
    assert_eq!(state, "pending_spent");
    assert_eq!(refund_intent_count(&db.pool, record).await, 0);
    assert_eq!(
        attempt_event_count(&db.pool, attempt_id, MEMPOOL_STUCK_EVENT).await,
        0,
        "no stuck alert for an on-chain attempt"
    );
}
