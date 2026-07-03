//! Integration coverage for the submission pipeline.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test stands up an isolated, freshly migrated database via the harness,
//! seeds an operator, an active wallet whose address matches a real (unlocked)
//! signing key, the wallet's canonical UTxOs, the cached protocol parameters, and
//! a `poe_record`, then drives the real `SubmitHandler` against a test chain
//! gateway with mockable failure injection.
//!
//! The assertions are behavioural: the resulting `poe_record`/`wallet_utxo`/
//! `refund_intent`/`subject_event`/`job` rows, not log strings. The through-lines
//! are the locked submit semantics: a landed submit flips the record to
//! `submitted` and applies the spend locally; a provider cooldown releases the
//! lease and defers WITHOUT consuming an attempt; a terminal arm writes exactly
//! one refund intent no matter how many times it converges; an over-budget record
//! fails immediately; and a locked wallet retries.

#![cfg(feature = "pg-tests")]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use age::secrecy::SecretString;
use gateway_core::chain::confirm::{record_permanent_failure, RefundReason};
use gateway_core::chain::gateway::{
    BlockInfo, ChainGateway, ChainTip, FailoverGateway, ProviderCooldown, ProviderKind, TxCborMap,
    TxConfirmation, TxConfirmationMap,
};
use gateway_core::chain::params::Network as ChainNetwork;
use gateway_core::chain::submit::{
    ForcedInput, SplitResumeJob, SubmitError, SubmitHandler, SubmitJob, SubmitOutcome,
    INDEXER_ABSENCE_HORIZON, SUBMIT_MAX_ATTEMPTS, SUBMIT_QUEUE,
};
use gateway_core::runtime::claim::{self};
use gateway_core::runtime::enqueue::{enqueue, EnqueueOptions};
use gateway_core::runtime::{JobContext, JobHandler, JobOutcome, JobState};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use gateway_core::wallet::keyring::{derive_enterprise_address, unlock, UnlockedKeyring};
use pallas_crypto::key::ed25519::{PublicKey, SecretKey};
use pallas_primitives::conway::Tx as ConwayTx;
use pallas_primitives::Fragment;
use sqlx::Row;
use uuid::Uuid;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Test chain gateway: a concrete `ChainGateway` whose submit can be switched
// between accept / provider-cooldown / generic-exhaustion. It echoes the body
// hash of the submitted CBOR, which equals the builder's tx id (signing leaves
// the body untouched), so the submit path's id cross-check always matches on the
// accept path. The confirm-side reads are unused here and return empty.
// ---------------------------------------------------------------------------

/// How the test gateway answers a submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmitMode {
    /// Accept and echo the submitted transaction's body hash.
    Accept,
    /// Report an all-provider rate-limit storm until a fixed instant (the typed
    /// error the failover wrapper raises when both providers 429).
    Cooldown,
    /// Report a generic transport failure (an exhausted gateway).
    Exhausted,
    /// Report a DETERMINISTIC node rejection: the node returned a 400/422 carrying
    /// a ledger validation error body, which the submit path classifies as a typed
    /// `NodeReject`. The classifier abandons the recorded attempt with its inputs
    /// restored only when the confirmation lookup also proves the attempt's own
    /// transaction absent from chain (the gateway's `ConfirmationsMode`) and, on
    /// a resume re-broadcast, the attempt has outlived the indexer-lag horizon.
    NodeReject,
    /// Report a TRANSIENT HTTP failure (a 5xx the failover wrapper retries, or a
    /// provider-side 401/403/404 misconfig). The classifier leaves the recorded
    /// attempt in-flight, never abandons — a provider failure must not permanently
    /// fail a well-formed transaction.
    TransientHttp,
    /// Report a provider-side HTTP 404 (a routing/auth misconfig). Under the GC-2
    /// classification this is TRANSIENT, not a ledger reject, so it must never
    /// abandon+refund a well-formed transaction.
    ProviderMisconfig404,
}

/// How the test gateway answers the confirmation lookup the deterministic-reject
/// classifier gates its abandon-with-restore on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmationsMode {
    /// Every hash is reported AFFIRMATIVELY not on chain (the default): a
    /// rejected body is proven absent, so the classifier may abandon and refund.
    NotOnChain,
    /// Every hash is reported ON CHAIN with real coordinates, modelling an
    /// attempt whose earlier "failed" broadcast actually reached a relay and
    /// confirmed — the self-landed case a re-broadcast reject must never refund.
    OnChain,
    /// Every hash is reported with a POSITIVE but incomplete signal (a status
    /// count whose detail row lagged — no coordinates): exactly the shape a
    /// just-confirmed transaction produces while the provider is mid-hydration.
    /// The classifier must treat it like a failed lookup, never as absence.
    Inconclusive,
    /// The lookup itself fails (provider down / rate-limited): the other
    /// inconclusive case, from which the classifier must never abandon or refund.
    LookupFails,
}

struct TestGateway {
    mode: SubmitMode,
    /// How confirmation lookups answer, so a test can stage the self-landed and
    /// inconclusive-lookup reject paths.
    confirmations: ConfirmationsMode,
    /// The instant the storm cooldown lifts, carried in the typed storm error.
    cooldown_until: chrono::DateTime<chrono::Utc>,
    /// How many submits were attempted, so a test can assert the gateway was hit.
    submits: AtomicU32,
    /// The exact bytes of the last accepted submit, so a test can assert a retry
    /// re-broadcast the SAME recorded transaction rather than building a fresh one.
    last_submitted: std::sync::Mutex<Option<Vec<u8>>>,
}

impl TestGateway {
    fn new(mode: SubmitMode) -> Self {
        Self::with_confirmations(mode, ConfirmationsMode::NotOnChain)
    }

    fn with_confirmations(mode: SubmitMode, confirmations: ConfirmationsMode) -> Self {
        Self {
            mode,
            confirmations,
            cooldown_until: chrono::Utc::now() + chrono::Duration::seconds(300),
            submits: AtomicU32::new(0),
            last_submitted: std::sync::Mutex::new(None),
        }
    }
}

impl ChainGateway for TestGateway {
    async fn submit_tx(&self, signed_tx: &[u8]) -> gateway_core::Result<[u8; 32]> {
        self.submits.fetch_add(1, Ordering::SeqCst);
        *self.last_submitted.lock().unwrap() = Some(signed_tx.to_vec());
        match self.mode {
            SubmitMode::Accept => Ok(body_hash_of(signed_tx)),
            SubmitMode::Cooldown => Err(gateway_core::Error::ChainRateLimitStorm {
                cooldown_until: self.cooldown_until,
            }),
            SubmitMode::Exhausted => Err(gateway_core::Error::ChainProvider(
                "every gateway failed".to_string(),
            )),
            // A proven ledger reject: a 400/422 the submit path classified from the
            // node's validation error body. Deterministic, never accepted by any
            // node, so the recorded attempt is abandoned with its inputs restored.
            SubmitMode::NodeReject => Err(gateway_core::chain::gateway::chain_error(
                gateway_core::chain::gateway::ChainErrorClass::NodeReject { status: 400 },
                "node rejected the transaction body",
            )),
            // A provider 5xx the failover wrapper retries: transient, ambiguous.
            SubmitMode::TransientHttp => Err(gateway_core::chain::gateway::chain_error(
                gateway_core::chain::gateway::ChainErrorClass::Http { status: 503 },
                "provider temporarily unavailable",
            )),
            // A provider-side 404 (routing/auth misconfig): transient under GC-2,
            // NEVER a ledger reject — must not abandon+refund a well-formed tx.
            SubmitMode::ProviderMisconfig404 => Err(gateway_core::chain::gateway::chain_error(
                gateway_core::chain::gateway::ChainErrorClass::Http { status: 404 },
                "provider returned 404 (routing misconfig)",
            )),
        }
    }

    async fn get_tx_confirmations(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxConfirmationMap> {
        match self.confirmations {
            ConfirmationsMode::NotOnChain => Ok(tx_hashes
                .iter()
                .map(|h| (*h, TxConfirmation::not_on_chain()))
                .collect()),
            ConfirmationsMode::OnChain => Ok(tx_hashes
                .iter()
                .map(|h| (*h, TxConfirmation::on_chain(2, 100, chrono::Utc::now())))
                .collect()),
            ConfirmationsMode::Inconclusive => Ok(tx_hashes
                .iter()
                .map(|h| (*h, TxConfirmation::inconclusive()))
                .collect()),
            ConfirmationsMode::LookupFails => Err(gateway_core::Error::ChainProvider(
                "confirmation lookup unavailable".to_string(),
            )),
        }
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
        _tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxCborMap> {
        Ok(TxCborMap::new())
    }

    async fn fetch_label309_records_since(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<gateway_core::chain::gateway::Label309RecordsResult> {
        Ok(gateway_core::chain::gateway::Label309RecordsResult::default())
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<gateway_core::chain::gateway::Label309RecordsResult> {
        Ok(gateway_core::chain::gateway::Label309RecordsResult::default())
    }
}

/// A shared, clonable handle over a `TestGateway` so a test can keep an observable
/// reference (submit count, last-submitted bytes) while the handler owns a clone of
/// the same underlying gateway. A local newtype is required because the orphan rule
/// forbids implementing the gateway trait directly on `Arc`.
#[derive(Clone)]
struct SharedGateway(std::sync::Arc<TestGateway>);

impl SharedGateway {
    fn new(mode: SubmitMode) -> Self {
        Self(std::sync::Arc::new(TestGateway::new(mode)))
    }
    fn submits(&self) -> u32 {
        self.0.submits.load(Ordering::SeqCst)
    }
    fn last_submitted(&self) -> Option<Vec<u8>> {
        self.0.last_submitted.lock().unwrap().clone()
    }
}

impl ChainGateway for SharedGateway {
    async fn submit_tx(&self, signed_tx: &[u8]) -> gateway_core::Result<[u8; 32]> {
        self.0.submit_tx(signed_tx).await
    }
    async fn get_tx_confirmations(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxConfirmationMap> {
        self.0.get_tx_confirmations(tx_hashes).await
    }
    async fn get_block_info(&self, block_height: u64) -> gateway_core::Result<Option<BlockInfo>> {
        self.0.get_block_info(block_height).await
    }
    async fn get_tip(&self) -> gateway_core::Result<ChainTip> {
        self.0.get_tip().await
    }
    async fn fetch_tx_cbor_by_hashes(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxCborMap> {
        self.0.fetch_tx_cbor_by_hashes(tx_hashes).await
    }
    async fn fetch_label309_records_since(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> gateway_core::Result<gateway_core::chain::gateway::Label309RecordsResult> {
        self.0
            .fetch_label309_records_since(
                after_block_height,
                exclude_tx_hashes,
                tip_block_height,
                max_records,
            )
            .await
    }
    async fn fetch_label309_records_since_alternate(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> gateway_core::Result<gateway_core::chain::gateway::Label309RecordsResult> {
        self.0
            .fetch_label309_records_since_alternate(
                after_block_height,
                exclude_tx_hashes,
                tip_block_height,
                max_records,
            )
            .await
    }
}

/// The Blake2b-256 hash of a transaction's body (its id), recomputed from the
/// signed CBOR so the test gateway echoes the same id the builder produced.
fn body_hash_of(tx_bytes: &[u8]) -> [u8; 32] {
    let tx = ConwayTx::decode_fragment(tx_bytes).expect("decode submitted tx");
    *pallas_crypto::hash::Hasher::<256>::hash(tx.transaction_body.raw_cbor())
}

/// A gateway that simulates a sustained provider rate-limit storm: its first
/// `storm_calls` submits return a provider cooldown (a 429, with the cooldown
/// instant already lapsed so the deferred job is immediately re-due), and every
/// submit after that is accepted. Models a 429 storm that finally clears, so the
/// submit pipeline can be driven to eventual success across deferrals.
struct StormThenAcceptGateway {
    /// How many of the first submits answer with a cooldown before accepting.
    storm_calls: u32,
    /// Submits seen so far.
    submits: AtomicU32,
}

impl StormThenAcceptGateway {
    fn new(storm_calls: u32) -> Self {
        Self {
            storm_calls,
            submits: AtomicU32::new(0),
        }
    }
}

impl ChainGateway for StormThenAcceptGateway {
    async fn submit_tx(&self, signed_tx: &[u8]) -> gateway_core::Result<[u8; 32]> {
        let seen = self.submits.fetch_add(1, Ordering::SeqCst);
        if seen < self.storm_calls {
            // The cooldown instant is in the (recent) past so the deferred job is
            // re-due at once: the test can drive the next attempt with no sleep,
            // while the submit path still classifies it as an OutboundCooldown.
            let until = chrono::Utc::now() - chrono::Duration::seconds(1);
            return Err(gateway_core::Error::ChainRateLimitStorm {
                cooldown_until: until,
            });
        }
        Ok(body_hash_of(signed_tx))
    }

    async fn get_tx_confirmations(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxConfirmationMap> {
        Ok(tx_hashes
            .iter()
            .map(|h| (*h, TxConfirmation::not_on_chain()))
            .collect())
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
        _tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxCborMap> {
        Ok(TxCborMap::new())
    }

    async fn fetch_label309_records_since(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<gateway_core::chain::gateway::Label309RecordsResult> {
        Ok(gateway_core::chain::gateway::Label309RecordsResult::default())
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<gateway_core::chain::gateway::Label309RecordsResult> {
        Ok(gateway_core::chain::gateway::Label309RecordsResult::default())
    }
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

const TEST_SCRYPT_LOG_N: u8 = 4;
const PREPROD_EPOCH: i32 = 100;

fn band() -> LovelaceBand {
    LovelaceBand {
        min: 4_000_000,
        max: 8_000_000,
        mid: 6_000_000,
    }
}

fn config() -> WalletConfig {
    WalletConfig {
        network: Network::Preprod,
        band: band(),
        lease: std::time::Duration::from_secs(120),
        min_canonical_count: 4,
    }
}

/// A deterministic wallet: a fixed-seed ed25519 key, its derived preprod
/// enterprise address, and an unlocked keyring holding the signer for it.
struct Wallet {
    address: String,
    keyring: Arc<UnlockedKeyring>,
}

/// Build a wallet from a 32-byte seed: derive its address and unlock a keyring
/// envelope holding its signing key, so the submit path can sign with it.
fn wallet_from_seed(seed: [u8; 32]) -> Wallet {
    let secret = SecretKey::from(seed);
    let public: PublicKey = secret.public_key();
    let mut vk = [0u8; 32];
    vk.copy_from_slice(public.as_ref());
    let address = derive_enterprise_address(&vk, Network::Preprod).expect("derive address");

    let hrp = bech32::Hrp::parse("ed25519_sk").expect("hrp");
    let bech32_skey = bech32::encode::<bech32::Bech32>(hrp, &seed).expect("encode skey");
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "cardano-ed25519", "label": "primary", "address": address,
              "secret": bech32_skey }
        ]
    })
    .to_string();

    let mut recipient = age::scrypt::Recipient::new(SecretString::from("test-passphrase"));
    recipient.set_work_factor(TEST_SCRYPT_LOG_N);
    let envelope = age::encrypt(&recipient, json.as_bytes()).expect("encrypt envelope");
    let keyring = unlock(
        &envelope,
        Zeroizing::new("test-passphrase".to_string()),
        Network::Preprod,
    )
    .expect("unlock keyring");

    Wallet {
        address,
        keyring: Arc::new(keyring),
    }
}

/// Insert an operator and an active wallet at `address`, returning their ids.
async fn seed_operator_and_wallet(
    pool: &sqlx::PgPool,
    address: &str,
    status: &str,
) -> (Uuid, Uuid) {
    let operator_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(operator_id)
        .bind("op")
        .execute(pool)
        .await
        .expect("insert operator");

    let wallet_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet \
           (id, registrar_operator_id, label, address, network, status) \
         VALUES ($1, $2, 'primary', $3, 'preprod', $4)",
    )
    .bind(wallet_id)
    .bind(operator_id)
    .bind(address)
    .bind(status)
    .execute(pool)
    .await
    .expect("insert wallet");
    (operator_id, wallet_id)
}

/// Insert one canonical, available UTxO for a wallet at `output_index`,
/// distinguished by `byte`, returning its `(tx_hash, index)` reference.
async fn seed_canonical_utxo(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    byte: u8,
    output_index: i32,
    lovelace: i64,
) -> ([u8; 32], i32) {
    let tx_hash = [byte; 32];
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, $3, $4, 'available', true, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(tx_hash.as_slice())
    .bind(output_index)
    .bind(lovelace)
    .execute(pool)
    .await
    .expect("insert utxo");
    (tx_hash, output_index)
}

/// Seed the cached preprod protocol parameters the build reads.
async fn seed_protocol_params(pool: &sqlx::PgPool, max_tx_size: i64) {
    sqlx::query(
        "INSERT INTO cw_core.cardano_protocol_params \
           (network, epoch, min_fee_a, min_fee_b, coins_per_utxo_byte, max_tx_size, raw) \
         VALUES ('preprod', $1, 44, 155381, 4310, $2, '{}'::jsonb)",
    )
    .bind(PREPROD_EPOCH)
    .bind(max_tx_size)
    .execute(pool)
    .await
    .expect("insert params");
}

/// Insert a `poe_record` ready for submit, returning its id. `pinned_wallet` ties
/// the record to a wallet (the pinned path); `None` leaves the pool to pick.
async fn seed_record(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    record_bytes: &[u8],
    pinned_wallet: Option<Uuid>,
) -> Uuid {
    let record_id = Uuid::now_v7();
    // account_id is left NULL: it is a tracing reference the submit path only
    // carries forward, never an input to a build or a fee, so an operator-direct
    // record (no tenant) exercises the same submit path.
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, record_bytes, status, wallet_id, request_id) \
         VALUES ($1, $2, $3, 'submitting', $4, $5)",
    )
    .bind(record_id)
    .bind(operator_id)
    .bind(record_bytes)
    .bind(pinned_wallet)
    .bind("req-1")
    .execute(pool)
    .await
    .expect("insert record");
    record_id
}

/// Register the submit queue policy so the confirm-nudge enqueue resolves a
/// policy (and any later enqueue against the queue does too).
async fn register_queue_policies(pool: &sqlx::PgPool) {
    for policy in [
        gateway_core::chain::submit::submit_policy(),
        gateway_core::chain::confirm::confirm_policy(),
    ] {
        gateway_core::runtime::policy::reconcile(pool, &policy)
            .await
            .expect("reconcile policy");
    }
}

/// A handler over the test gateway in a given submit mode.
fn handler(pool: &sqlx::PgPool, wallet: &Wallet, mode: SubmitMode) -> SubmitHandler<TestGateway> {
    handler_with_confirmations(pool, wallet, mode, ConfirmationsMode::NotOnChain)
}

/// A handler over the test gateway with an explicit confirmation-lookup answer,
/// for staging the self-landed and inconclusive-lookup deterministic-reject paths.
fn handler_with_confirmations(
    pool: &sqlx::PgPool,
    wallet: &Wallet,
    mode: SubmitMode,
    confirmations: ConfirmationsMode,
) -> SubmitHandler<TestGateway> {
    SubmitHandler::new(
        pool.clone(),
        TestGateway::with_confirmations(mode, confirmations),
        config(),
        wallet.keyring.clone(),
    )
}

/// A handler over a SHARED test gateway, returning the gateway handle too so a test
/// can observe its submit count and last-submitted bytes (the handler owns a clone
/// of the same underlying gateway).
fn handler_observable(
    pool: &sqlx::PgPool,
    wallet: &Wallet,
    mode: SubmitMode,
) -> (SubmitHandler<SharedGateway>, SharedGateway) {
    let gateway = SharedGateway::new(mode);
    let handler = SubmitHandler::new(
        pool.clone(),
        gateway.clone(),
        config(),
        wallet.keyring.clone(),
    );
    (handler, gateway)
}

/// Read a `poe_record`'s `(status, has_tx_hash, actual_fee_lovelace, wallet_id)`.
async fn read_record(
    pool: &sqlx::PgPool,
    record_id: Uuid,
) -> (String, bool, Option<i64>, Option<Uuid>) {
    let row = sqlx::query(
        "SELECT status, (tx_hash IS NOT NULL) AS has_tx, actual_fee_lovelace, wallet_id \
         FROM cw_core.poe_record WHERE id = $1",
    )
    .bind(record_id)
    .fetch_one(pool)
    .await
    .expect("read record");
    (
        row.get::<String, _>("status"),
        row.get::<bool, _>("has_tx"),
        row.get::<Option<i64>, _>("actual_fee_lovelace"),
        row.get::<Option<Uuid>, _>("wallet_id"),
    )
}

/// Read a single UTxO's state, or `None` if no such row.
async fn utxo_state(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    tx_hash: [u8; 32],
    index: i32,
) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT state FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3",
    )
    .bind(wallet_id)
    .bind(tx_hash.as_slice())
    .bind(index)
    .fetch_optional(pool)
    .await
    .expect("read utxo state")
}

/// Count `subject_event` rows for a record of a given event type.
async fn count_events(pool: &sqlx::PgPool, record_id: Uuid, event_type: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'poe_record' AND subject_id = $1 AND event_type = $2",
    )
    .bind(record_id.to_string())
    .bind(event_type)
    .fetch_one(pool)
    .await
    .expect("count events")
}

/// Count `refund_intent` rows for a record.
async fn count_refunds(pool: &sqlx::PgPool, record_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM cw_core.refund_intent WHERE record_id = $1")
        .bind(record_id)
        .fetch_one(pool)
        .await
        .expect("count refunds")
}

/// Read a record's persisted `spent_inputs` JSON (the wallet inputs the submit
/// recorded for a later rollback / confirmation).
async fn read_spent_inputs(pool: &sqlx::PgPool, record_id: Uuid) -> Option<serde_json::Value> {
    sqlx::query_scalar::<_, Option<serde_json::Value>>(
        "SELECT spent_inputs FROM cw_core.poe_record WHERE id = $1",
    )
    .bind(record_id)
    .fetch_one(pool)
    .await
    .expect("read spent_inputs")
}

/// Read a record's `refund_intent.reason`, if any.
async fn refund_reason(pool: &sqlx::PgPool, record_id: Uuid) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT reason FROM cw_core.refund_intent WHERE record_id = $1")
        .bind(record_id)
        .fetch_optional(pool)
        .await
        .expect("read refund reason")
}

/// Seed a `broadcast` original publish attempt for a record, the record riding it,
/// spending `spent` (the input a later cancelling replacement re-spends). Returns
/// the attempt id and its tx hash. Mirrors a record that submitted, landed in a
/// mempool, then was rolled back: the original is the live attempt a replacement
/// supersedes.
async fn seed_original_attempt(
    pool: &sqlx::PgPool,
    record_id: Uuid,
    wallet_id: Uuid,
    marker: u8,
    spent: &[([u8; 32], u32, u64)],
) -> (Uuid, [u8; 32]) {
    let attempt_id = Uuid::now_v7();
    let tx_hash = [marker; 32];
    let spent_json: Vec<serde_json::Value> = spent
        .iter()
        .map(
            |(h, i, l)| serde_json::json!({ "tx_hash": hex::encode(h), "index": i, "lovelace": l }),
        )
        .collect();
    sqlx::query(
        "INSERT INTO cw_core.chain_attempt \
           (id, kind, record_id, wallet_id, tx_hash, signed_tx, fee_lovelace, \
            spent_inputs, produced_outputs, status, mempool_entered_at) \
         VALUES ($1, 'publish', $2, $3, $4, $5, 169197, $6, '[]'::jsonb, 'broadcast', now())",
    )
    .bind(attempt_id)
    .bind(record_id)
    .bind(wallet_id)
    .bind(tx_hash.as_slice())
    .bind(vec![marker, 0x00])
    .bind(serde_json::Value::Array(spent_json))
    .execute(pool)
    .await
    .expect("insert original attempt");
    sqlx::query("UPDATE cw_core.poe_record SET current_attempt_id = $2 WHERE id = $1")
        .bind(record_id)
        .bind(attempt_id)
        .execute(pool)
        .await
        .expect("point record at original attempt");
    (attempt_id, tx_hash)
}

/// Read an attempt's status by id, or `None` if no such row.
async fn attempt_status(pool: &sqlx::PgPool, attempt_id: Uuid) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT status FROM cw_core.chain_attempt WHERE id = $1")
        .bind(attempt_id)
        .fetch_optional(pool)
        .await
        .expect("read attempt status")
}

/// Count `chain_attempt` rows for a record (any status), so a test can assert a
/// redelivery never minted a second attempt.
async fn count_record_attempts(pool: &sqlx::PgPool, record_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM cw_core.chain_attempt WHERE record_id = $1")
        .bind(record_id)
        .fetch_one(pool)
        .await
        .expect("count chain attempts")
}

/// Read the status of the attempt a record currently rides (via its
/// `current_attempt_id`), or `None` when the record rides no attempt.
async fn current_attempt_status(pool: &sqlx::PgPool, record_id: Uuid) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT a.status FROM cw_core.chain_attempt a \
         JOIN cw_core.poe_record r ON r.current_attempt_id = a.id \
         WHERE r.id = $1",
    )
    .bind(record_id)
    .fetch_optional(pool)
    .await
    .expect("read current attempt status")
}

/// Read a record's `current_attempt_id`, if any.
async fn current_attempt_id(pool: &sqlx::PgPool, record_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT current_attempt_id FROM cw_core.poe_record WHERE id = $1",
    )
    .bind(record_id)
    .fetch_one(pool)
    .await
    .expect("read current_attempt_id")
}

/// Backdate an attempt's `created_at` past the indexer-lag horizon, so the
/// age-gated absence corroboration reads the attempt as old enough that a
/// self-landed transaction would have been indexed by now.
async fn backdate_attempt_past_absence_horizon(pool: &sqlx::PgPool, attempt_id: Uuid) {
    sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET created_at = created_at - make_interval(secs => $2) \
         WHERE id = $1",
    )
    .bind(attempt_id)
    .bind(INDEXER_ABSENCE_HORIZON.as_secs_f64() + 60.0)
    .execute(pool)
    .await
    .expect("backdate attempt");
}

// ---------------------------------------------------------------------------
// Success path.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn submit_success_flips_to_submitted_and_applies_the_spend() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([1u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x11, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(&db.pool, operator_id, b"hello-poe-record", None).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");

    // The submit landed: a tx hash, one spent input, a real fee.
    let SubmitOutcome::Submitted {
        spent_inputs,
        fee_lovelace,
        ..
    } = outcome
    else {
        panic!("expected a submitted outcome, got {outcome:?}");
    };
    assert_eq!(spent_inputs.len(), 1, "a first submit spends one input");
    assert!(
        fee_lovelace.unwrap() > 0,
        "the recorded fee is the real fee"
    );

    // The record is submitted, bound to the wallet, with a tx hash and fee.
    let (status, has_tx, fee, bound_wallet) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitted");
    assert!(has_tx, "a submitted record carries its tx hash");
    assert_eq!(fee, Some(fee_lovelace.unwrap() as i64));
    assert_eq!(bound_wallet, Some(wallet_id), "the wallet is bound");

    // The spent input is pending_spent locally.
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "the spent input is pending_spent after a landed submit"
    );

    // The submit persisted the spent inputs on the record (so a later rollback /
    // confirmation has the spend set to act on without a chain read). The shape is
    // the {tx_hash, index, lovelace} array both readers decode.
    let persisted = read_spent_inputs(&db.pool, record_id)
        .await
        .expect("a landed submit persists its spent inputs");
    let rows = persisted.as_array().expect("spent_inputs is a JSON array");
    assert_eq!(rows.len(), 1, "a first submit records one spent input");
    assert_eq!(
        rows[0]["tx_hash"],
        serde_json::json!(hex::encode(utxo_hash)),
        "the persisted input references the leased UTxO by hex tx hash"
    );
    assert_eq!(rows[0]["index"], serde_json::json!(utxo_index));

    // A submitted status event was appended.
    assert_eq!(
        count_events(&db.pool, record_id, "submitted").await,
        1,
        "exactly one submitted event is appended"
    );

    // The confirm loop was nudged: a cardano_confirm job exists.
    let confirm_jobs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.job WHERE queue = $1 AND state = 'available'",
    )
    .bind(gateway_core::chain::confirm::CONFIRM_QUEUE)
    .fetch_one(&db.pool)
    .await
    .expect("count confirm jobs");
    assert_eq!(confirm_jobs, 1, "the confirm loop is nudged exactly once");
}

// ---------------------------------------------------------------------------
// Scope-bound signing: a submit signs a wallet only when its principal is
// entitled to spend it.
// ---------------------------------------------------------------------------

/// Insert a second operator (a tenant that does NOT register the wallet) so a
/// submit can run under a non-registrar principal.
async fn seed_second_operator(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'other-op')")
        .bind(id)
        .execute(pool)
        .await
        .expect("insert second operator");
    id
}

/// A submit whose record belongs to an operator NOT entitled to the resolved
/// wallet never signs: the wallet is pinned, the principal is a stranger with no
/// grant, so `authorize_spend` yields nothing and the pinned wallet falls through
/// to a (here empty) pool pick. The record stays unsubmitted with no spend
/// applied and no UTxO leased.
#[tokio::test]
async fn submit_refuses_a_wallet_the_principal_cannot_spend() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([7u8; 32]);
    let (_registrar, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x71, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;

    // The record belongs to a DIFFERENT operator and is pinned to the registrar's
    // wallet. That operator is not the registrar and holds no grant.
    let stranger = seed_second_operator(&db.pool).await;
    let record_id = seed_record(&db.pool, stranger, b"hello-poe-record", Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-scope".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");

    // No entitled wallet resolved (the pinned wallet is not spendable by this
    // principal, and there is no other wallet to pick), so the attempt fails as
    // wallet-lock contention (retryable) rather than signing.
    assert!(
        matches!(
            outcome,
            SubmitOutcome::Failed {
                error: SubmitError::WalletLockContention
            }
        ),
        "a non-entitled principal must not sign; got {outcome:?}"
    );

    // The record is untouched and the UTxO never leased.
    let (status, has_tx, _, _) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitting", "the record stays unsubmitted");
    assert!(
        !has_tx,
        "no transaction was signed for a non-entitled spend"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("available".to_string()),
        "the UTxO is never leased when the principal cannot spend the wallet"
    );
}

/// A live SERVICE grant makes a stranger's submit succeed: with the wallet
/// service-granted, an operator that is not the registrar is entitled, so the
/// submit signs and lands exactly like the registrar's own.
#[tokio::test]
async fn submit_succeeds_for_a_stranger_under_a_service_grant() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([8u8; 32]);
    let (registrar, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    seed_canonical_utxo(&db.pool, wallet_id, 0x81, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;

    // A service grant entitles every operator to the wallet.
    gateway_core::wallet::grant::issue_grant(
        &db.pool,
        registrar,
        wallet_id,
        gateway_core::wallet::grant::GrantScope::Service,
    )
    .await
    .expect("issue service grant")
    .expect("registrar grants on its own wallet");

    // A stranger's record, pinned to the service-granted wallet, signs and lands.
    let stranger = seed_second_operator(&db.pool).await;
    let record_id = seed_record(&db.pool, stranger, b"hello-poe-record", Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-svc".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(outcome, SubmitOutcome::Submitted { .. }),
        "a service grant lets a stranger's submit land; got {outcome:?}"
    );
    let (status, has_tx, _, bound) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitted");
    assert!(has_tx);
    assert_eq!(bound, Some(wallet_id));
}

/// The PINNED-path gate: a record pinned to a wallet the principal IS entitled to
/// signs from exactly that wallet. This pins that the pinned path runs through
/// `authorize_spend` (the registrar is entitled) rather than blindly trusting the
/// pin.
#[tokio::test]
async fn submit_honours_a_pinned_wallet_the_principal_may_spend() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([9u8; 32]);
    let (registrar, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    seed_canonical_utxo(&db.pool, wallet_id, 0x91, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    // The registrar's own record, pinned to its own wallet.
    let record_id = seed_record(&db.pool, registrar, b"hello-poe-record", Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-pin".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(outcome, SubmitOutcome::Submitted { .. }),
        "an entitled pinned wallet signs and lands; got {outcome:?}"
    );
    let (_, _, _, bound) = read_record(&db.pool, record_id).await;
    assert_eq!(
        bound,
        Some(wallet_id),
        "the submit used exactly the pinned, entitled wallet"
    );
}

// ---------------------------------------------------------------------------
// Cooldown defer: the attempt is recorded before broadcast, so a cooldown leaves
// the recorded attempt in-flight (inputs reserved) and defers without consuming an
// attempt; a retry re-broadcasts the recorded bytes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cooldown_leaves_the_recorded_attempt_in_flight_and_defers_without_consuming_an_attempt() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([2u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x22, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(&db.pool, operator_id, b"cooldown-record", Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Cooldown);
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // submit_once classifies the cooldown.
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(
            outcome,
            SubmitOutcome::Failed {
                error: SubmitError::OutboundCooldown { .. }
            }
        ),
        "a provider cooldown is classified as OutboundCooldown, got {outcome:?}"
    );

    // The attempt was recorded BEFORE the (cooled-down) broadcast, so its input is
    // reserved (pending_spent) to the recorded attempt, NOT released: a retry
    // re-broadcasts the recorded bytes against the same input rather than minting a
    // fresh transaction. This is the record-before-broadcast durability.
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "a cooldown leaves the input reserved to the recorded attempt"
    );

    // Exactly one attempt was recorded for the record, in `recorded` (it never
    // reached the wire), and the record points at it. The record stays `submitting`
    // (no broadcast => no submitted flip) and no refund was written.
    assert_eq!(
        count_record_attempts(&db.pool, record_id).await,
        1,
        "a cooldown records exactly one attempt"
    );
    assert_eq!(
        current_attempt_status(&db.pool, record_id).await,
        Some("recorded".to_string()),
        "a cooled-down attempt is recorded but never broadcast"
    );
    let (status, has_tx, _fee, _w) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitting", "a cooldown does not flip the record");
    assert!(!has_tx, "a cooldown leaves no tx hash on the record");
    assert_eq!(count_refunds(&db.pool, record_id).await, 0);

    // Drive the full handler: a cooldown is a Defer (NOT a Fail), so the job's
    // attempt budget is never consumed.
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let job_outcome = handler.handle(ctx).await;
    assert!(
        matches!(job_outcome, JobOutcome::Defer { .. }),
        "a cooldown defers rather than fails, so no attempt is burned, got {job_outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// Byte budget: immediate terminal failure with one refund.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn over_budget_record_fails_immediately_with_one_refund() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([3u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x33, 0, band().mid as i64).await;
    // A tiny max tx size so any record exceeds the byte budget.
    seed_protocol_params(&db.pool, 64).await;
    let record_id = seed_record(&db.pool, operator_id, &[0xAB; 200], Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // submit_once classifies the over-budget record.
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(
            outcome,
            SubmitOutcome::Failed {
                error: SubmitError::ByteBudgetExceeded { .. }
            }
        ),
        "an over-budget record is classified ByteBudgetExceeded, got {outcome:?}"
    );

    // The leased UTxO is released (not stranded) by the byte-budget arm.
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("available".to_string()),
        "the byte-budget arm releases the lease"
    );

    // Driving the handler terminates immediately: the record is permanent_failure
    // with exactly one refund intent and the two terminal events.
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: 1,
        // Byte-budget is terminal even when it is NOT the final attempt.
        is_final_attempt: false,
        defer_count: 0,
    };
    let job_outcome = handler.handle(ctx).await;
    assert!(
        matches!(job_outcome, JobOutcome::Complete),
        "a terminated job completes (the failure is durable), got {job_outcome:?}"
    );

    let (status, _has_tx, _fee, _w) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "permanent_failure");
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        1,
        "an over-budget record writes exactly one refund intent"
    );
    assert_eq!(
        count_events(&db.pool, record_id, "poe.refund-intent").await,
        1
    );
    assert_eq!(
        count_events(&db.pool, record_id, "permanent_failure").await,
        1
    );
}

// ---------------------------------------------------------------------------
// Gateway exhaustion: retries before the final attempt, terminates on it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gateway_exhaustion_leaves_the_recorded_attempt_in_flight_and_never_refunds() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([4u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x44, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(&db.pool, operator_id, b"exhausted-record", Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Exhausted);
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // Gateway exhaustion is a BROADCAST failure, and the attempt is recorded BEFORE
    // the broadcast. A failed broadcast is ambiguous (the body may have reached a
    // node), so under the no-TTL model the recorded attempt is NEVER refunded on this
    // signal: a non-final attempt retries the re-broadcast, the record stays
    // submitting, the recorded attempt and its reserved input persist, and no refund
    // is ever written.
    let ctx_retry = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let retry = handler.handle(ctx_retry).await;
    assert!(
        matches!(retry, JobOutcome::Fail { .. }),
        "a non-final ambiguous broadcast failure retries via Fail, got {retry:?}"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitting", "a retry leaves the record submitting");
    assert_eq!(
        current_attempt_status(&db.pool, record_id).await,
        Some("recorded".to_string()),
        "the recorded attempt stays recorded across the failed broadcast"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "the recorded attempt's input stays reserved, never released or refunded"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "an ambiguous broadcast failure refunds nothing"
    );

    // The FINAL attempt does NOT refund either: the recorded attempt persists for the
    // confirm authority and the operator-reconcile path. Only a settlement-deep
    // conflicting spend can ever abandon it. The job simply completes.
    let ctx_final = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: 5,
        is_final_attempt: true,
        defer_count: 0,
    };
    let terminal = handler.handle(ctx_final).await;
    assert!(
        matches!(terminal, JobOutcome::Complete),
        "the final attempt completes (no refund), leaving the recorded attempt for confirm"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(
        status, "submitting",
        "the record stays submitting: a recorded attempt is never submit-refunded"
    );
    assert_eq!(
        count_record_attempts(&db.pool, record_id).await,
        1,
        "no second attempt was minted across the retries"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "the recorded attempt is never refunded by the submit path"
    );
}

// ---------------------------------------------------------------------------
// Single-refund-by-construction: a terminal arm that converges twice writes one
// refund intent. (Drives the shared refund hook directly, the single writer all
// submit terminal arms and the confirm give-up paths route through.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_terminal_arm_writes_exactly_one_refund_even_when_it_converges_twice() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([5u8; 32]);
    let (operator_id, _wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let record_id = seed_record(&db.pool, operator_id, b"converge-record", None).await;

    // Move the record to submitted so the flip guard accepts the first terminate.
    sqlx::query("UPDATE cw_core.poe_record SET status = 'submitted' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("set submitted");

    let detail = serde_json::json!({ "detail": "build failed at final attempt" });

    // First terminal arm owns the refund: it flips the record and writes one
    // refund intent and the two events.
    let first = record_permanent_failure(&db.pool, record_id, RefundReason::TxBuildFailed, &detail)
        .await
        .expect("first terminate");
    assert!(first, "the first terminal arm owns the flip");

    // A second converging arm (e.g. a rollback give-up racing the submit arm)
    // finds the record already terminal: it flips nothing and writes no second
    // refund or events.
    let second = record_permanent_failure(
        &db.pool,
        record_id,
        RefundReason::RollbackRetriesExhausted,
        &detail,
    )
    .await
    .expect("second terminate");
    assert!(
        !second,
        "a converging arm does not re-own a terminated record"
    );

    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        1,
        "single-refund-by-construction: exactly one intent across converging arms"
    );
    assert_eq!(
        count_events(&db.pool, record_id, "poe.refund-intent").await,
        1,
        "only the owning arm emits the refund-intent event"
    );
    assert_eq!(
        count_events(&db.pool, record_id, "permanent_failure").await,
        1,
        "only the owning arm emits the permanent_failure event"
    );
}

// ---------------------------------------------------------------------------
// Wallet lock contention: a held per-wallet lock makes the submit retryable.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_locked_wallet_yields_a_retryable_contention() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([6u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    seed_canonical_utxo(&db.pool, wallet_id, 0x66, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(&db.pool, operator_id, b"contended-record", Some(wallet_id)).await;

    // Hold the wallet's advisory lock so the submit cannot take it.
    let held = gateway_core::wallet::pool::lock_wallet(&db.pool, wallet_id)
        .await
        .expect("hold the wallet lock");

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(
            outcome,
            SubmitOutcome::Failed {
                error: SubmitError::WalletLockContention
            }
        ),
        "a locked wallet yields lock contention, got {outcome:?}"
    );

    // On a NON-final attempt the handler maps contention to a retry (Fail), not a
    // refund: another worker holds the wallet, so a requeue lets a later attempt
    // proceed once the lock frees. (The final-attempt terminal refund that prevents a
    // charged publish from stranding is covered by
    // `a_final_wallet_contention_refunds_a_charged_first_submit_instead_of_stranding_it`.)
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let job_outcome = handler.handle(ctx).await;
    assert!(
        matches!(job_outcome, JobOutcome::Fail { .. }),
        "a non-final contention retries (never refunds), got {job_outcome:?}"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(
        status, "submitting",
        "a non-final contention never flips the record"
    );
    assert_eq!(count_refunds(&db.pool, record_id).await, 0);

    held.release().await.expect("release the wallet lock");
}

// ---------------------------------------------------------------------------
// Pool path: an unpinned record picks a wallet from the pool and binds it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unpinned_record_picks_a_pool_wallet_and_binds_it() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([7u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    seed_canonical_utxo(&db.pool, wallet_id, 0x77, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    // No pinned wallet: the pool picks one.
    let record_id = seed_record(&db.pool, operator_id, b"pool-record", None).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(outcome, SubmitOutcome::Submitted { .. }),
        "an unpinned record submits via a pool pick, got {outcome:?}"
    );

    let (status, _has_tx, _fee, bound_wallet) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitted");
    assert_eq!(
        bound_wallet,
        Some(wallet_id),
        "the pool-picked wallet is bound to the record"
    );
}

// ---------------------------------------------------------------------------
// Replacement path: a cancelling replacement re-leases a rolled-back input and
// spends it alongside a fresh canonical input.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_cancelling_replacement_spends_a_rolled_back_input() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([8u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    // A fresh canonical input for the replacement to draw on.
    let (fresh_hash, fresh_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x88, 0, band().mid as i64).await;
    // A rolled-back input: a pending_spent row the replacement must re-lease and
    // spend so the old metadata-only transaction can never land.
    let rolled_back_hash = [0x99u8; 32];
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, 0, $3, 'pending_spent', false, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(rolled_back_hash.as_slice())
    .bind(band().mid as i64)
    .execute(&db.pool)
    .await
    .expect("insert rolled-back input");

    seed_protocol_params(&db.pool, 16384).await;
    // A rollback resubmit's record is `submitted` with cleared coordinates.
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"replacement-record",
        Some(wallet_id),
    )
    .await;
    sqlx::query("UPDATE cw_core.poe_record SET status = 'submitted' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("set submitted for replacement");

    // Seed the live ORIGINAL attempt the replacement supersedes: a broadcast publish
    // attempt for this record whose tx is the rolled-back one (0x99) and which spent
    // the rolled-back input. The replacement re-spends that input, so the gateway
    // intersection check passes and the atomic supersede-and-record handoff fires.
    let (original_id, original_tx) = seed_original_attempt(
        &db.pool,
        record_id,
        wallet_id,
        0x99,
        &[(rolled_back_hash, 0, band().mid)],
    )
    .await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: Some(hex::encode(original_tx)),
        forced_inputs: vec![ForcedInput {
            tx_hash: hex::encode(rolled_back_hash),
            index: 0,
            lovelace: band().mid,
        }],
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");

    let SubmitOutcome::Submitted { spent_inputs, .. } = outcome else {
        panic!("expected a submitted replacement, got {outcome:?}");
    };
    assert_eq!(
        spent_inputs.len(),
        2,
        "a cancelling replacement spends the fresh input plus the rolled-back one"
    );

    // Both inputs are now pending_spent: the fresh canonical one and the
    // re-leased rolled-back one.
    assert_eq!(
        utxo_state(&db.pool, wallet_id, fresh_hash, fresh_index).await,
        Some("pending_spent".to_string()),
        "the fresh canonical input is spent"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, rolled_back_hash, 0).await,
        Some("pending_spent".to_string()),
        "the re-leased rolled-back input is spent by the replacement"
    );

    // The atomic supersede-and-record handoff superseded the original and linked it
    // to the replacement, and the record now rides the replacement attempt: at no
    // instant were two active broadcasters sharing the rolled-back input.
    assert_eq!(
        attempt_status(&db.pool, original_id).await,
        Some("superseded".to_string()),
        "the original is superseded by the replacement handoff"
    );
    let now_riding = current_attempt_id(&db.pool, record_id)
        .await
        .expect("the record rides an attempt after the replacement");
    assert_ne!(
        now_riding, original_id,
        "the record now rides the replacement, not the superseded original"
    );
    // Exactly two attempts survive for the record: the superseded original and its
    // recorded/broadcast replacement, both reconcilable.
    assert_eq!(count_record_attempts(&db.pool, record_id).await, 2);
}

/// Regression: a cancelling replacement records and supersedes the original even
/// when the record's `current_attempt_id` was ALREADY CLEARED by the confirm-loop's
/// enqueue handoff (the post-handoff state: record `submitted`, pointer NULL,
/// original still an ACTIVE broadcaster). The confirm-loop handoff intentionally does
/// NOT supersede the original itself; the submit path owns the atomic supersede +
/// record. A prior version pre-superseded the original in the handoff, so the
/// submit-side supersede (guarded to an active broadcaster) no-oped and the
/// replacement was silently never recorded — the cancelling transaction never built.
/// This pins that the submit path records the replacement against a still-active
/// original with a cleared record pointer.
#[tokio::test]
async fn a_cancelling_replacement_records_when_the_record_pointer_was_already_cleared_regression() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([9u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (fresh_hash, fresh_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x77, 0, band().mid as i64).await;
    let rolled_back_hash = [0xaau8; 32];
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, 0, $3, 'pending_spent', false, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(rolled_back_hash.as_slice())
    .bind(band().mid as i64)
    .execute(&db.pool)
    .await
    .expect("insert rolled-back input");

    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"cleared-pointer-record",
        Some(wallet_id),
    )
    .await;
    sqlx::query("UPDATE cw_core.poe_record SET status = 'submitted' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("set submitted for replacement");

    // The active original the replacement supersedes.
    let (original_id, original_tx) = seed_original_attempt(
        &db.pool,
        record_id,
        wallet_id,
        0xab,
        &[(rolled_back_hash, 0, band().mid)],
    )
    .await;
    // Reproduce the post-confirm-handoff state precisely: the record pointer is
    // CLEARED while the original remains an active `broadcast` attempt. (The fixed
    // confirm handoff does exactly this; a pre-superseded original would instead make
    // the submit-side supersede no-op.)
    sqlx::query("UPDATE cw_core.poe_record SET current_attempt_id = NULL WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("clear the record pointer (the confirm handoff's state)");
    assert_eq!(
        attempt_status(&db.pool, original_id).await,
        Some("broadcast".to_string()),
        "the original is still an active broadcaster going into the replacement submit"
    );

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: Some(hex::encode(original_tx)),
        forced_inputs: vec![ForcedInput {
            tx_hash: hex::encode(rolled_back_hash),
            index: 0,
            lovelace: band().mid,
        }],
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");

    // The replacement RECORDED and broadcast (not a silent lost-generation no-op).
    let SubmitOutcome::Submitted { spent_inputs, .. } = outcome else {
        panic!("the replacement must record and broadcast, got {outcome:?}");
    };
    assert_eq!(
        spent_inputs.len(),
        2,
        "fresh input plus the rolled-back one"
    );
    let _ = (fresh_hash, fresh_index);

    // The submit path superseded the original atomically with recording the
    // replacement, and the record now rides the replacement.
    assert_eq!(
        attempt_status(&db.pool, original_id).await,
        Some("superseded".to_string()),
        "the submit path superseded the still-active original"
    );
    let now_riding = current_attempt_id(&db.pool, record_id)
        .await
        .expect("the record rides the replacement after the submit");
    assert_ne!(now_riding, original_id, "the record rides the replacement");
    assert_eq!(count_record_attempts(&db.pool, record_id).await, 2);
}

// ---------------------------------------------------------------------------
// Replacement integrity: a replacement with no usable forced inputs is a TERMINAL
// refund, never a silent non-cancelling normal submit.
// ---------------------------------------------------------------------------

/// A job marked `replacement_for` but carrying an EMPTY forced-input set cannot
/// cancel the rolled-back transaction. It must be a terminal replacement failure
/// (a refund), never fall through to a normal submit that double-publishes the
/// record while the old metadata-only transaction can still land.
#[tokio::test]
async fn a_replacement_with_no_forced_inputs_is_terminal_not_a_silent_submit() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([12u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0xC1, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"orphan-replacement",
        Some(wallet_id),
    )
    .await;
    sqlx::query("UPDATE cw_core.poe_record SET status = 'submitted' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("set submitted for replacement");

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    // replacement_for is set but forced_inputs is empty: the spend set was lost.
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: Some(hex::encode([0xEEu8; 32])),
        forced_inputs: Vec::new(),
    };

    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(
            outcome,
            SubmitOutcome::Failed {
                error: SubmitError::ReplacementInputsMissing { .. }
            }
        ),
        "a replacement with no forced inputs is terminal, got {outcome:?}"
    );

    // It never submitted (the terminal arm bails before the build), and the
    // canonical UTxO was released (not spent).
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("available".to_string()),
        "the canonical lease is released by the terminal arm"
    );

    // Driving the handler terminates immediately (even before the final attempt):
    // permanent_failure with exactly one refund whose reason is the new code.
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let job_outcome = handler.handle(ctx).await;
    assert!(
        matches!(job_outcome, JobOutcome::Complete),
        "a terminated replacement completes (the failure is durable), got {job_outcome:?}"
    );
    let (status, _has_tx, _fee, _w) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "permanent_failure");
    assert_eq!(count_refunds(&db.pool, record_id).await, 1);
    assert_eq!(
        refund_reason(&db.pool, record_id).await.as_deref(),
        Some("replacement_inputs_missing"),
        "the refund reason is the dedicated replacement-inputs-missing code"
    );
}

/// A `replacement_for` job whose forced inputs are MALFORMED (a tx hash that is
/// not valid hex) is likewise terminal: a retry can never repair corrupt input
/// data, so the record is refunded rather than retried or silently submitted.
#[tokio::test]
async fn a_replacement_with_malformed_forced_inputs_is_terminal() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([13u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0xC2, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"malformed-replacement",
        Some(wallet_id),
    )
    .await;
    sqlx::query("UPDATE cw_core.poe_record SET status = 'submitted' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("set submitted for replacement");

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: Some(hex::encode([0xEEu8; 32])),
        forced_inputs: vec![ForcedInput {
            // Not valid hex: the spend reference is corrupt.
            tx_hash: "not-a-hex-hash".to_string(),
            index: 0,
            lovelace: band().mid,
        }],
    };

    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(
            outcome,
            SubmitOutcome::Failed {
                error: SubmitError::ReplacementInputsMissing { .. }
            }
        ),
        "a replacement with malformed forced inputs is terminal, got {outcome:?}"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("available".to_string()),
        "the canonical lease is released by the terminal arm"
    );
}

// ---------------------------------------------------------------------------
// Byte budget: an oversize FINAL transaction (not just the raw record) is the
// same terminal refundable failure, with the actual and maximum sizes.
// ---------------------------------------------------------------------------

/// A record whose raw bytes FIT the protocol maximum but whose assembled (signed,
/// change-bearing) transaction does NOT must still be a terminal byte-budget
/// refund carrying the actual and maximum sizes, never a retryable build failure.
/// This exercises the builder's `TxTooLarge` survival through submit mapping (the
/// raw-record precheck cannot catch it).
#[tokio::test]
async fn an_oversize_final_transaction_is_terminal_with_actual_and_max() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([14u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0xD0, 0, band().mid as i64).await;

    // A 200-byte record with a max tx size of 220: the raw-record precheck passes
    // (200 <= 220), but the assembled transaction (record + body + witness +
    // change) exceeds 220, so the builder returns TxTooLarge.
    let record_bytes = [0xAB; 200];
    seed_protocol_params(&db.pool, 220).await;
    let record_id = seed_record(&db.pool, operator_id, &record_bytes, Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    let SubmitOutcome::Failed {
        error: SubmitError::ByteBudgetExceeded { size, max },
    } = outcome
    else {
        panic!("an oversize final transaction must be ByteBudgetExceeded, got {outcome:?}");
    };
    assert_eq!(max, 220, "the carried max is the protocol maximum");
    assert!(
        size > max,
        "the carried actual size exceeds the maximum (got size {size}, max {max})"
    );
    // The build failed before the submit, and the lease was released.
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("available".to_string()),
        "the byte-budget arm releases the lease"
    );

    // It is terminal even before the final attempt, with exactly one refund.
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let job_outcome = handler.handle(ctx).await;
    assert!(
        matches!(job_outcome, JobOutcome::Complete),
        "an oversize tx terminates (the failure is durable), got {job_outcome:?}"
    );
    let (status, _has_tx, _fee, _w) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "permanent_failure");
    assert_eq!(count_refunds(&db.pool, record_id).await, 1);
    assert_eq!(
        refund_reason(&db.pool, record_id).await.as_deref(),
        Some("byte_budget_exceeded"),
        "an oversize final transaction refunds under the byte-budget reason"
    );
}

// ---------------------------------------------------------------------------
// Cooldown-defer storm: a sustained 429 storm across many submit attempts must
// never burn the attempt budget. The publish eventually succeeds and the job's
// `attempts` column proves not one of the deferrals consumed an attempt.
// ---------------------------------------------------------------------------

/// Apply one job outcome via the same fenced writes the runtime worker uses, so
/// the test exercises the production claim/defer/complete accounting (in
/// particular that a Defer refunds the attempt the claim charged).
async fn apply_outcome(
    pool: &sqlx::PgPool,
    job_id: Uuid,
    token: gateway_core::runtime::ClaimToken,
    backoff: gateway_core::runtime::Backoff,
    attempt: i32,
    outcome: JobOutcome,
) {
    match outcome {
        JobOutcome::Complete => claim::complete(pool, job_id, token)
            .await
            .expect("complete"),
        JobOutcome::Defer { until } => claim::defer(pool, job_id, token, until)
            .await
            .expect("defer"),
        JobOutcome::Fail { error } => claim::fail(pool, job_id, token, backoff, attempt, &error)
            .await
            .expect("fail"),
    }
}

#[tokio::test]
async fn a_cooldown_storm_across_many_attempts_never_burns_an_attempt_and_eventually_succeeds() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([10u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0xA0, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(&db.pool, operator_id, b"storm-record", Some(wallet_id)).await;

    // The gateway 429s for the first SEVEN submits, then accepts. Seven is well
    // past the five-attempt budget: if any deferral burned an attempt the publish
    // would permanently-fail before the storm cleared.
    const STORM_ROUNDS: u32 = 7;
    let handler = SubmitHandler::new(
        db.pool.clone(),
        StormThenAcceptGateway::new(STORM_ROUNDS),
        config(),
        wallet.keyring.clone(),
    );

    // Enqueue a real submit job so the claim/defer accounting runs against a true
    // job row, the way the runtime drives it.
    let job = SubmitJob {
        request_id: "req-1".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let job_id = enqueue(
        &db.pool,
        SUBMIT_QUEUE,
        &serde_json::to_value(&job).unwrap(),
        EnqueueOptions::default(),
    )
    .await
    .expect("enqueue submit job");

    // Drive the claim -> handle -> apply-outcome cycle repeatedly. Each storm round
    // defers (which refunds its attempt); the round after the storm clears
    // completes. The defer sets run_at to the lapsed cooldown instant, so each
    // re-claim is immediately due with no sleep.
    let mut rounds = 0u32;
    let mut deferrals = 0u32;
    loop {
        rounds += 1;
        assert!(
            rounds <= STORM_ROUNDS + 3,
            "the storm must clear and complete"
        );

        let claimed = claim::claim_batch(&db.pool, "storm-worker", &[SUBMIT_QUEUE.to_string()], 1)
            .await
            .expect("claim batch");
        let (claimed_job, token) = claimed
            .into_iter()
            .next()
            .expect("the submit job is due and claimable each round");
        // Every claim charges exactly one attempt; a healthy publish under a storm
        // must never let the running attempt exceed the budget.
        assert!(
            claimed_job.attempts <= claimed_job.max_attempts,
            "a claim during a storm must never exceed the attempt budget (attempt {} of {})",
            claimed_job.attempts,
            claimed_job.max_attempts
        );

        let ctx = JobContext {
            job_id: claimed_job.id,
            queue: SUBMIT_QUEUE.to_string(),
            payload: claimed_job.payload.clone(),
            attempt: claimed_job.attempts,
            is_final_attempt: claimed_job.attempts >= claimed_job.max_attempts,
            defer_count: claimed_job.defer_count,
        };
        let outcome = handler.handle(ctx).await;
        let was_defer = matches!(outcome, JobOutcome::Defer { .. });
        let was_complete = matches!(outcome, JobOutcome::Complete);
        apply_outcome(
            &db.pool,
            claimed_job.id,
            token,
            claimed_job.backoff,
            claimed_job.attempts,
            outcome,
        )
        .await;

        if was_defer {
            deferrals += 1;
            continue;
        }
        assert!(
            was_complete,
            "the post-storm round must complete the publish, not fail it"
        );
        break;
    }

    // The storm produced one deferral per 429 round.
    assert_eq!(
        deferrals, STORM_ROUNDS,
        "every 429 round deferred exactly once"
    );

    // The publish succeeded.
    let (status, has_tx, _fee, _w) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitted", "the publish eventually lands");
    assert!(has_tx);
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "the landed submit spends its input"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "a publish that succeeds after a storm is never refunded"
    );

    // The attempt-burn proof: the job completed and, across SEVEN deferrals plus
    // one accept, the final attempts count is exactly 1. Each Defer refunded the
    // attempt the claim charged, so the budget never advanced past the single
    // attempt the successful round consumed.
    let finished = claim::get_job(&db.pool, job_id.0)
        .await
        .expect("read job")
        .expect("the job row exists");
    assert_eq!(finished.state, JobState::Completed, "the job completed");
    assert_eq!(
        finished.attempts, 1,
        "after {STORM_ROUNDS} deferrals and one accept the attempts column is 1: \
         no deferral ever burned an attempt"
    );
}

// ---------------------------------------------------------------------------
// Single-refund-by-construction under a real race: drive the rollback-cap
// terminal arm (the confirm side) and the submit-terminal arm concurrently on
// ONE record. Exactly one refund intent and one set of terminal events survive,
// no matter which arm wins the flip.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rollback_cap_and_submit_terminal_racing_one_record_yield_one_refund() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([11u8; 32]);
    let (operator_id, _wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let record_id = seed_record(&db.pool, operator_id, b"race-record", None).await;
    // Move to a non-terminal on-chain state so both arms find a flippable record.
    sqlx::query("UPDATE cw_core.poe_record SET status = 'submitted' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("set submitted");

    // Two terminal arms hit the same record at the same time: the confirm-side
    // rollback cap and the submit-side build failure at the final attempt. Both
    // route through the shared single-refund hook, whose flip-guard makes
    // single-refund a by-construction property regardless of interleaving.
    let pool_a = db.pool.clone();
    let pool_b = db.pool.clone();
    let detail_a = serde_json::json!({ "reason": "rollback_retries_exhausted" });
    let detail_b = serde_json::json!({ "detail": "build failed at final attempt" });

    let arm_rollback = tokio::spawn(async move {
        record_permanent_failure(
            &pool_a,
            record_id,
            RefundReason::RollbackRetriesExhausted,
            &detail_a,
        )
        .await
    });
    let arm_submit = tokio::spawn(async move {
        record_permanent_failure(&pool_b, record_id, RefundReason::TxBuildFailed, &detail_b).await
    });

    let owned_rollback = arm_rollback
        .await
        .expect("rollback arm joins")
        .expect("rollback arm ok");
    let owned_submit = arm_submit
        .await
        .expect("submit arm joins")
        .expect("submit arm ok");

    // Exactly one arm owns the flip: the flip-guard serialises them so one returns
    // true (it performed the flip and wrote the refund) and the other false.
    assert!(
        owned_rollback ^ owned_submit,
        "exactly one arm owns the terminal flip (rollback={owned_rollback}, submit={owned_submit})"
    );

    // The by-construction invariant: ONE refund intent, ONE permanent_failure
    // event, ONE refund-intent event, no matter which arm won the race.
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "permanent_failure");
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        1,
        "a concurrent rollback-cap / submit-terminal race writes exactly one refund intent"
    );
    assert_eq!(
        count_events(&db.pool, record_id, "poe.refund-intent").await,
        1,
        "only the owning arm emits the refund-intent event"
    );
    assert_eq!(
        count_events(&db.pool, record_id, "permanent_failure").await,
        1,
        "only the owning arm emits the permanent_failure event"
    );
}

// ---------------------------------------------------------------------------
// In-flight settlement survives grant revocation: a cancelling replacement of an
// already-submitted transaction settles strictly by the ORIGINAL wallet, even
// when that wallet's grant was revoked and the wallet was set draining after the
// original submit. A first-spend resolve would re-run the entitlement check and
// fall through to a different (or no) wallet, stranding the replacement because
// its forced inputs belong to the original wallet. The settlement path must not.
// ---------------------------------------------------------------------------

/// Set a wallet's lifecycle status (e.g. `draining`) directly.
async fn set_wallet_status(pool: &sqlx::PgPool, wallet_id: Uuid, status: &str) {
    sqlx::query("UPDATE cw_core.operator_wallet SET status = $2 WHERE id = $1")
        .bind(wallet_id)
        .bind(status)
        .execute(pool)
        .await
        .expect("set wallet status");
}

/// Seed a `pending_spent` rolled-back input on a wallet (the input the original,
/// now-reorged transaction spent), returning its 32-byte hash.
async fn seed_rolled_back_input(pool: &sqlx::PgPool, wallet_id: Uuid, byte: u8) -> [u8; 32] {
    let tx_hash = [byte; 32];
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, 0, $3, 'pending_spent', false, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(tx_hash.as_slice())
    .bind(band().mid as i64)
    .execute(pool)
    .await
    .expect("insert rolled-back input");
    tx_hash
}

#[tokio::test]
async fn a_replacement_settles_its_original_wallet_after_grant_revocation_and_draining() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([21u8; 32]);
    // An operator registers the wallet, then service-grants it so a stranger's
    // first submit could land. The seed inserts the wallet row directly; the
    // matching grant is issued through the real API below.
    let (registrar, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let grant = gateway_core::wallet::grant::issue_grant(
        &db.pool,
        registrar,
        wallet_id,
        gateway_core::wallet::grant::GrantScope::Service,
    )
    .await
    .expect("issue service grant")
    .expect("registrar grants on its own wallet");
    let grant_id = match grant {
        gateway_core::wallet::grant::IssueOutcome::Issued { grant_id } => grant_id,
        gateway_core::wallet::grant::IssueOutcome::AlreadyGranted { grant_id } => grant_id,
    };

    // A fresh canonical input for the replacement, plus the rolled-back input the
    // original (reorged) transaction spent. The replacement is forced to spend the
    // latter, which only exists on THIS wallet.
    let (fresh_hash, fresh_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0xE1, 0, band().mid as i64).await;
    let rolled_back_hash = seed_rolled_back_input(&db.pool, wallet_id, 0xE2).await;
    seed_protocol_params(&db.pool, 16384).await;

    // A stranger's record, pinned to the wallet, already submitted (a rollback
    // resubmit's record is `submitted` with cleared coordinates).
    let stranger = seed_second_operator(&db.pool).await;
    let record_id = seed_record(&db.pool, stranger, b"inflight-record", Some(wallet_id)).await;
    sqlx::query("UPDATE cw_core.poe_record SET status = 'submitted' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("set submitted");

    // After the original submit: the grant is revoked AND the wallet is set
    // draining. A NEW spend by the stranger would now be refused (not the
    // registrar, no live grant) and the draining wallet takes no new picks.
    gateway_core::wallet::grant::revoke_grant(&db.pool, registrar, wallet_id, grant_id)
        .await
        .expect("revoke")
        .expect("registrar revokes its own grant");
    set_wallet_status(&db.pool, wallet_id, "draining").await;

    // Sanity: a NEW (non-replacement) submit for this stranger/record (one that does
    // not yet ride an attempt) would now resolve to no wallet at all (revoked grant +
    // draining wallet, no fallthrough target), which is exactly the state that would
    // strand a replacement if the replacement reused the new-spend resolution.
    let new_spend_handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let new_spend_job = SubmitJob {
        request_id: "req-new".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let new_spend_outcome = new_spend_handler
        .submit_once(&new_spend_job, 1)
        .await
        .expect("submit once (new spend)");
    assert!(
        matches!(
            new_spend_outcome,
            SubmitOutcome::Failed {
                error: SubmitError::WalletLockContention
            }
        ),
        "a NEW spend after revoke+drain resolves to no wallet; got {new_spend_outcome:?}"
    );

    // The live original attempt the cancelling replacement supersedes: it spent the
    // rolled-back input the replacement re-spends. Seeded after the new-spend sanity
    // check so that check exercises pure wallet resolution (the record rides no
    // attempt yet).
    let (_original_id, original_tx) = seed_original_attempt(
        &db.pool,
        record_id,
        wallet_id,
        0xEE,
        &[(rolled_back_hash, 0, band().mid)],
    )
    .await;

    // The cancelling replacement, by contrast, settles on the ORIGINAL wallet:
    // it resolves by the pinned wallet id with no entitlement re-check and no
    // fallthrough, so a revoked grant and a draining wallet do not strand it.
    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-repl".to_string(),
        record_id,
        replacement_for: Some(hex::encode(original_tx)),
        forced_inputs: vec![ForcedInput {
            tx_hash: hex::encode(rolled_back_hash),
            index: 0,
            lovelace: band().mid,
        }],
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    let SubmitOutcome::Submitted { spent_inputs, .. } = outcome else {
        panic!("the replacement must settle on the original wallet, got {outcome:?}");
    };
    assert_eq!(
        spent_inputs.len(),
        2,
        "the replacement spends the fresh canonical input plus the rolled-back one"
    );

    // It used exactly the original wallet (never switched), and both inputs are
    // now pending_spent: the fix keys settlement on the wallet id, not a fresh
    // entitlement check.
    let (status, has_tx, _fee, bound) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitted", "the replacement lands");
    assert!(has_tx, "the replacement carries its tx hash");
    assert_eq!(
        bound,
        Some(wallet_id),
        "the replacement did NOT switch wallets; it settled the original wallet"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, fresh_hash, fresh_index).await,
        Some("pending_spent".to_string()),
        "the fresh canonical input is spent by the replacement"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, rolled_back_hash, 0).await,
        Some("pending_spent".to_string()),
        "the rolled-back input is re-leased and spent so the old tx can never land"
    );
}

// ---------------------------------------------------------------------------
// Record-before-broadcast crash-window idempotency (regression for the
// at-least-once double-broadcast a paid publish could otherwise mint). A job
// redelivered after the broadcast committed but before the `submitted` flip must
// NOT mint a second transaction: it re-broadcasts the EXACT recorded bytes and
// repairs the projection. The active-broadcaster unique index and the recorded
// signed_tx are what close the double-broadcast.
// ---------------------------------------------------------------------------

/// Drive a clean first submit so an attempt is recorded and broadcast, then RESET
/// the record's projection to the crash-window state (status `submitting`, but
/// still riding the live `broadcast` attempt) and re-run `submit_once`. The
/// redelivery must re-broadcast the recorded transaction (same tx_hash, no fresh
/// build), keep exactly ONE attempt, and converge the projection to `submitted`
/// with exactly one `submitted` event.
#[tokio::test]
async fn redelivered_first_submit_rebroadcasts_the_recorded_tx_and_repairs_the_projection_regression(
) {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([41u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x41, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"crash-window-record",
        Some(wallet_id),
    )
    .await;

    let (handler, gateway) = handler_observable(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-crash".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // First submit: an attempt is recorded and broadcast, the record flips to
    // submitted. Capture the broadcast bytes the recorded attempt holds.
    let first = handler.submit_once(&job, 1).await.expect("first submit");
    let SubmitOutcome::Submitted { tx_hash, .. } = first else {
        panic!("expected a submitted first attempt, got {first:?}");
    };
    let attempt_one = current_attempt_id(&db.pool, record_id)
        .await
        .expect("the record rides the recorded attempt");
    let recorded_signed: Vec<u8> =
        sqlx::query_scalar("SELECT signed_tx FROM cw_core.chain_attempt WHERE id = $1")
            .bind(attempt_one)
            .fetch_one(&db.pool)
            .await
            .expect("read recorded signed_tx");
    let submits_after_first = gateway.submits();

    // Simulate the crash window: the broadcast committed and the attempt is on the
    // wire (`broadcast`), but the record never flipped (a crash between marking the
    // attempt broadcast and the `submitted` flip). Reset the projection to
    // `submitting` while keeping current_attempt_id.
    sqlx::query(
        "UPDATE cw_core.poe_record \
         SET status = 'submitting', tx_hash = NULL, actual_fee_lovelace = NULL, spent_inputs = NULL \
         WHERE id = $1",
    )
    .bind(record_id)
    .execute(&db.pool)
    .await
    .expect("reset projection to crash-window state");
    // Drop the `submitted` event the first submit appended so we can prove the
    // repaired flip appends exactly one.
    sqlx::query(
        "DELETE FROM cw_core.subject_event \
         WHERE subject_kind = 'poe_record' AND subject_id = $1 AND event_type = 'submitted'",
    )
    .bind(record_id.to_string())
    .execute(&db.pool)
    .await
    .expect("clear the first submitted event");

    // The redelivery runs the SAME job again.
    let resumed = handler
        .submit_once(&job, 2)
        .await
        .expect("redelivered submit");
    assert!(
        matches!(resumed, SubmitOutcome::AlreadyResolved),
        "a redelivery of a broadcast attempt resolves without minting a new tx, got {resumed:?}"
    );

    // (a) Exactly ONE attempt exists for the record: no second transaction minted.
    assert_eq!(
        count_record_attempts(&db.pool, record_id).await,
        1,
        "the redelivery minted no second attempt"
    );
    assert_eq!(
        current_attempt_id(&db.pool, record_id).await,
        Some(attempt_one),
        "the record still rides the original recorded attempt"
    );

    // (b) The gateway saw a RE-broadcast of the same recorded bytes (a fresh build
    //     would produce different bytes; here they are byte-identical to what was
    //     recorded), and the submit count incremented by exactly one.
    assert_eq!(
        gateway.submits(),
        submits_after_first + 1,
        "the redelivery broadcast exactly once more"
    );
    assert_eq!(
        gateway.last_submitted(),
        Some(recorded_signed),
        "the redelivery re-broadcast the EXACT recorded bytes, not a fresh build"
    );

    // (c) The projection repaired to `submitted` carrying the attempt's tx hash, with
    //     exactly ONE `submitted` event.
    let (status, has_tx, _fee, _w) = read_record(&db.pool, record_id).await;
    assert_eq!(
        status, "submitted",
        "the crash-window projection repaired to submitted"
    );
    assert!(has_tx, "the repaired projection carries the tx hash");
    assert_eq!(
        count_events(&db.pool, record_id, "submitted").await,
        1,
        "the repair appends exactly one submitted event, never a duplicate"
    );
    // The input stayed reserved across the whole window (recorded before broadcast).
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string())
    );
    // The on-chain tx the record carries matches the recorded attempt's.
    let stored_tx: Vec<u8> =
        sqlx::query_scalar("SELECT tx_hash FROM cw_core.poe_record WHERE id = $1")
            .bind(record_id)
            .fetch_one(&db.pool)
            .await
            .expect("read record tx_hash");
    assert_eq!(stored_tx, tx_hash.to_vec());
}

// ---------------------------------------------------------------------------
// Replacement-input-intersection: a cancelling replacement that re-spends NONE of
// the superseded original's inputs is rejected at record time
// (ReplacementDoesNotConflict), never recorded, never broadcast. A conflicting
// replacement records and broadcasts normally.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_replacement_that_does_not_conflict_is_rejected_at_record_time_and_never_broadcast() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([42u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    // A fresh canonical input the replacement draws on.
    seed_canonical_utxo(&db.pool, wallet_id, 0x4A, 0, band().mid as i64).await;
    // A NON-overlapping input the replacement is forced to spend: it does NOT
    // intersect the original's recorded input, so the replacement does not conflict.
    let non_overlapping = [0x4Bu8; 32];
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, 0, $3, 'pending_spent', false, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(non_overlapping.as_slice())
    .bind(band().mid as i64)
    .execute(&db.pool)
    .await
    .expect("insert non-overlapping input");
    seed_protocol_params(&db.pool, 16384).await;

    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"non-conflict-replacement",
        Some(wallet_id),
    )
    .await;
    sqlx::query("UPDATE cw_core.poe_record SET status = 'submitted' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("set submitted");

    // The original attempt spent a DIFFERENT input (0x90) than the replacement's
    // forced input (0x4B), so the intersection is empty.
    let original_input = [0x90u8; 32];
    let (original_id, original_tx) = seed_original_attempt(
        &db.pool,
        record_id,
        wallet_id,
        0x99,
        &[(original_input, 0, band().mid)],
    )
    .await;

    let (handler, gateway) = handler_observable(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-noconflict".to_string(),
        record_id,
        replacement_for: Some(hex::encode(original_tx)),
        forced_inputs: vec![ForcedInput {
            tx_hash: hex::encode(non_overlapping),
            index: 0,
            lovelace: band().mid,
        }],
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(
            outcome,
            SubmitOutcome::Failed {
                error: SubmitError::ReplacementDoesNotConflict { .. }
            }
        ),
        "a non-conflicting replacement is rejected at record time, got {outcome:?}"
    );

    // The gateway was NEVER called: the abort happens before any broadcast.
    assert_eq!(
        gateway.submits(),
        0,
        "a non-conflicting replacement is never broadcast"
    );
    // No replacement attempt was recorded: only the original survives.
    assert_eq!(
        count_record_attempts(&db.pool, record_id).await,
        1,
        "the non-conflicting replacement left no chain_attempt row"
    );
    // The original is NOT superseded (the handoff aborted) and the record still
    // rides it.
    assert_eq!(
        attempt_status(&db.pool, original_id).await,
        Some("broadcast".to_string()),
        "the original is untouched by the aborted replacement"
    );
    assert_eq!(
        current_attempt_id(&db.pool, record_id).await,
        Some(original_id),
        "the record still rides the original; the supersede was rolled back"
    );
}

#[tokio::test]
async fn a_conflicting_replacement_records_and_broadcasts() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([43u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    seed_canonical_utxo(&db.pool, wallet_id, 0x5A, 0, band().mid as i64).await;
    // The shared input the original spent and the replacement re-spends.
    let shared = [0x5Bu8; 32];
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, 0, $3, 'pending_spent', false, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(shared.as_slice())
    .bind(band().mid as i64)
    .execute(&db.pool)
    .await
    .expect("insert shared input");
    seed_protocol_params(&db.pool, 16384).await;

    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"conflict-replacement",
        Some(wallet_id),
    )
    .await;
    sqlx::query("UPDATE cw_core.poe_record SET status = 'submitted' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("set submitted");

    let (original_id, original_tx) = seed_original_attempt(
        &db.pool,
        record_id,
        wallet_id,
        0x9A,
        &[(shared, 0, band().mid)],
    )
    .await;

    let (handler, gateway) = handler_observable(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-conflict".to_string(),
        record_id,
        replacement_for: Some(hex::encode(original_tx)),
        forced_inputs: vec![ForcedInput {
            tx_hash: hex::encode(shared),
            index: 0,
            lovelace: band().mid,
        }],
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(outcome, SubmitOutcome::Submitted { .. }),
        "a conflicting replacement records and broadcasts, got {outcome:?}"
    );
    assert_eq!(
        gateway.submits(),
        1,
        "a conflicting replacement is broadcast exactly once"
    );
    assert_eq!(
        attempt_status(&db.pool, original_id).await,
        Some("superseded".to_string()),
        "the original is superseded by the conflicting replacement"
    );
    assert_eq!(count_record_attempts(&db.pool, record_id).await, 2);
}

// ---------------------------------------------------------------------------
// Deterministic node-reject classifier. Its abandon-with-restore is the ONLY
// abandon not gated on a settlement-deep conflicting spend, so its boundary is
// safety-critical: a typed deterministic 4xx abandons-with-restore only when a
// fresh lookup also proves the attempt's own transaction absent from chain; a
// transient (5xx) failure NEVER abandons and leaves the input reserved.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_deterministic_node_reject_abandons_the_recorded_attempt_and_restores_its_input() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([44u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x4C, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(&db.pool, operator_id, b"reject-record", Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::NodeReject);
    let job = SubmitJob {
        request_id: "req-reject".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // Drive the full handler once (the realistic delivery): it records the attempt
    // before broadcast, the node deterministically rejects the body on the
    // attempt's genuine FIRST broadcast — the one entry where self-landing is
    // impossible, so the affirmative absence needs no age corroboration — and the
    // attempt is abandoned with its input restored AND the record terminalised
    // with one refund in the same delivery. The handler completes (no node can
    // accept the body, so retrying is futile).
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let job_outcome = handler.handle(ctx).await;
    assert!(
        matches!(job_outcome, JobOutcome::Complete),
        "a deterministic reject terminates the job, got {job_outcome:?}"
    );

    // The recorded attempt is ABANDONED (the body can never land) and its input is
    // RESTORED to available (the one abandon-with-restore not gated on a confirmed
    // conflicting spend, safe because the tx was never accepted by any node).
    assert_eq!(
        count_record_attempts(&db.pool, record_id).await,
        1,
        "exactly one attempt exists, now abandoned"
    );
    let abandoned_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM cw_core.chain_attempt WHERE record_id = $1")
            .bind(record_id)
            .fetch_optional(&db.pool)
            .await
            .expect("read attempt status");
    assert_eq!(abandoned_status, Some("abandoned".to_string()));
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("available".to_string()),
        "the deterministic reject restores the never-landed input to available"
    );

    // The record is refunded exactly once with the node-rejected reason. The abandon
    // and the refund committed in ONE transaction (the deterministic tx_hash stays in
    // the ledger, so an abandoned-but-unrefunded record could never be recovered by a
    // redelivery): exactly one refund-intent event accompanies the single refund.
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(
        status, "permanent_failure",
        "the record is refunded after a deterministic reject"
    );
    assert_eq!(count_refunds(&db.pool, record_id).await, 1);
    assert_eq!(
        refund_reason(&db.pool, record_id).await,
        Some("node_rejected".to_string())
    );
    assert_eq!(
        count_events(&db.pool, record_id, "poe.refund-intent").await,
        1,
        "exactly one refund-intent event accompanies the atomic abandon-and-refund"
    );
}

#[tokio::test]
async fn a_transient_broadcast_failure_never_abandons_and_keeps_the_input_reserved() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([45u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x4D, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(&db.pool, operator_id, b"transient-record", Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::TransientHttp);
    let job = SubmitJob {
        request_id: "req-transient".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "a transient broadcast failure leaves the recorded attempt in-flight, got {outcome:?}"
    );

    // The attempt is NOT abandoned: it stays `recorded` (the body may have reached a
    // node, so only a settlement-deep conflicting spend can kill it), the record
    // still rides it, and the input stays RESERVED (never restored, never refunded).
    assert_eq!(
        current_attempt_status(&db.pool, record_id).await,
        Some("recorded".to_string()),
        "a transient failure leaves the attempt recorded, never abandoned"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "a transient failure keeps the input reserved, never restored"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "a transient failure never refunds"
    );
    // The record stays submitting (no broadcast => no flip).
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitting");
}

/// GC-2: a provider-side HTTP 404 (a routing/auth misconfig) on submit must NOT be
/// treated as a ledger reject. It is transient, so the recorded attempt stays
/// in-flight (the secondary or a retry can still land it), its input stays
/// reserved, and the record is NEVER permanently-failed + auto-refunded. A
/// misconfigured provider must never refund a well-formed, never-broadcast tx.
#[tokio::test]
async fn a_provider_misconfig_404_on_submit_never_abandons_or_refunds() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([46u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x4E, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(&db.pool, operator_id, b"misconfig-record", Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::ProviderMisconfig404);
    let job = SubmitJob {
        request_id: "req-misconfig".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = handler.submit_once(&job, 1).await.expect("submit once");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "a provider 404 leaves the recorded attempt in-flight (failover-eligible), got {outcome:?}"
    );

    // The attempt is NOT abandoned, the input stays reserved, and nothing is refunded.
    assert_eq!(
        current_attempt_status(&db.pool, record_id).await,
        Some("recorded".to_string()),
        "a provider misconfig 404 never abandons the attempt"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "a provider misconfig 404 keeps the input reserved, never restored"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "a provider misconfig 404 never refunds a well-formed, never-broadcast tx"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(
        status, "submitting",
        "the record stays submitting after a provider misconfig, never permanently failed"
    );
}

// ---------------------------------------------------------------------------
// Self-landed re-broadcast. A first broadcast that fails transiently to OUR view
// can still reach a relay and confirm; the 30s retry then re-broadcasts the same
// recorded bytes and the node deterministically rejects them, because their
// inputs are already spent — by themselves. The classifier must not read that
// reject as "never landed": abandon+refund would refund a CONFIRMED publish and
// hand its on-chain-spent input back to the pool as available. The gate is a
// fresh own-tx lookup with a THREE-way verdict: on chain => repair the
// projection and hand the attempt to the confirm authority; a
// positive-but-incomplete observation (a status count whose detail row lagged —
// the exact shape a just-confirmed tx produces mid-hydration) or a failed
// lookup => leave everything in flight; only an AFFIRMATIVELY absent
// transaction abandons and refunds — and on a RESUME even that absence must be
// corroborated by the attempt outliving the indexer-lag horizon, because the
// provider's indexer can lag the very node that rejected the re-broadcast.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_self_landed_tx_rejected_on_rebroadcast_is_never_refunded_regression() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([70u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x70, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"self-landed-record",
        Some(wallet_id),
    )
    .await;
    let job = SubmitJob {
        request_id: "req-self-landed".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // First delivery: the broadcast fails transiently to our view (but, per the
    // scenario, the bytes reached a relay anyway). The attempt stays recorded,
    // in flight, its input reserved.
    let first = handler(&db.pool, &wallet, SubmitMode::TransientHttp);
    let outcome = first.submit_once(&job, 1).await.expect("first submit");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "the ambiguous first broadcast leaves the attempt recorded, got {outcome:?}"
    );
    let attempt_id = current_attempt_id(&db.pool, record_id)
        .await
        .expect("the record rides the recorded attempt");

    // Retry delivery ~1 block later: the transaction has CONFIRMED, so the node
    // deterministically rejects the re-broadcast (its inputs are spent by its own
    // landed body) while the fresh own-tx lookup reports it on chain.
    let retry = handler_with_confirmations(
        &db.pool,
        &wallet,
        SubmitMode::NodeReject,
        ConfirmationsMode::OnChain,
    );
    let outcome = retry.submit_once(&job, 2).await.expect("retry submit");
    assert!(
        matches!(outcome, SubmitOutcome::AlreadyResolved),
        "a self-landed reject resolves to the confirm authority, got {outcome:?}"
    );

    // NO refund and NO terminalisation: the publish landed.
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "a self-landed transaction is never refunded on its re-broadcast reject"
    );
    let (status, has_tx, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(
        status, "submitted",
        "the record projection is repaired to submitted, never terminalised"
    );
    assert!(has_tx, "the repaired projection carries the landed tx hash");
    // The attempt advanced to broadcast — the confirm loaders own it from here —
    // and the record still rides it.
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        Some("broadcast".to_string()),
        "the self-landed attempt is handed to the confirm authority, never abandoned"
    );
    assert_eq!(
        current_attempt_id(&db.pool, record_id).await,
        Some(attempt_id),
        "the record still rides its landed attempt"
    );
    // The input stays reserved: it is spent ON CHAIN by this attempt's own
    // transaction, so restoring it would corrupt the wallet accounting.
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "the on-chain-spent input is never returned to available"
    );
}

#[tokio::test]
async fn an_inconclusive_own_tx_lookup_on_a_node_reject_never_refunds_regression() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([71u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x71, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"inconclusive-record",
        Some(wallet_id),
    )
    .await;
    let job = SubmitJob {
        request_id: "req-inconclusive".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // First delivery: an ambiguous broadcast failure leaves the attempt recorded.
    let first = handler(&db.pool, &wallet, SubmitMode::TransientHttp);
    let outcome = first.submit_once(&job, 1).await.expect("first submit");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "the ambiguous first broadcast leaves the attempt recorded, got {outcome:?}"
    );

    // Retry delivery: the node deterministically rejects the re-broadcast, but the
    // own-tx lookup FAILS — absence is unproven, so the classifier must leave the
    // attempt in flight rather than refund on an inconclusive observation.
    let retry = handler_with_confirmations(
        &db.pool,
        &wallet,
        SubmitMode::NodeReject,
        ConfirmationsMode::LookupFails,
    );
    let outcome = retry.submit_once(&job, 2).await.expect("retry submit");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "an inconclusive lookup leaves the recorded attempt in flight, got {outcome:?}"
    );

    // Nothing moved: no abandon, no refund, no restore, no terminalisation. The
    // next retry re-evaluates with a fresh lookup.
    assert_eq!(
        current_attempt_status(&db.pool, record_id).await,
        Some("recorded".to_string()),
        "an inconclusive lookup never abandons the attempt"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "an inconclusive lookup keeps the input reserved"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "a refund never rides an inconclusive observation"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitting");
}

/// The provider-lag shape of the same hole: the lookup SUCCEEDS but answers a
/// positive-but-incomplete observation — the status endpoint counted our own
/// just-confirmed transaction while the detail endpoint lagged (no coordinates).
/// That is exactly what a self-landed transaction looks like mid-hydration, so
/// reading it as absence would refund a confirmed publish. The classifier must
/// treat it like a failed lookup: everything stays in flight, nothing is
/// refunded, and a later retry re-evaluates.
#[tokio::test]
async fn a_positive_but_incomplete_observation_on_a_node_reject_never_refunds_regression() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([72u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x72, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(&db.pool, operator_id, b"lag-window-record", Some(wallet_id)).await;
    let job = SubmitJob {
        request_id: "req-lag-window".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // First delivery: an ambiguous broadcast failure leaves the attempt recorded.
    let first = handler(&db.pool, &wallet, SubmitMode::TransientHttp);
    let outcome = first.submit_once(&job, 1).await.expect("first submit");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "the ambiguous first broadcast leaves the attempt recorded, got {outcome:?}"
    );

    // Retry delivery: the node deterministically rejects the re-broadcast, and the
    // own-tx lookup answers positive-but-incomplete (counted, no coordinates).
    let retry = handler_with_confirmations(
        &db.pool,
        &wallet,
        SubmitMode::NodeReject,
        ConfirmationsMode::Inconclusive,
    );
    let outcome = retry.submit_once(&job, 2).await.expect("retry submit");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "a positive-but-incomplete observation leaves the attempt in flight, got {outcome:?}"
    );

    // Nothing moved: no abandon, no refund, no restore, no terminalisation.
    assert_eq!(
        current_attempt_status(&db.pool, record_id).await,
        Some("recorded".to_string()),
        "a lag-window observation never abandons the attempt"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "a lag-window observation keeps the input reserved"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "a refund never rides a positive-but-incomplete observation"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitting");
}

/// The indexer-lag shape of the ABSENCE signal itself: on a RESUME re-broadcast
/// even an affirmative "no record" answer is not yet trustworthy while the
/// attempt is young. The submit and the confirmation lookup ride the same
/// provider, whose indexer (db-sync) can lag the very node that rejected the
/// re-broadcast — a self-landed transaction reads as affirmatively absent until
/// the indexer catches up. A young absence must defer exactly like an
/// inconclusive observation, never refund.
#[tokio::test]
async fn a_resume_reject_with_a_young_affirmative_absence_defers_the_refund_regression() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([73u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x73, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"young-absence-record",
        Some(wallet_id),
    )
    .await;
    let job = SubmitJob {
        request_id: "req-young-absence".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // First delivery: an ambiguous broadcast failure leaves the attempt recorded.
    let first = handler(&db.pool, &wallet, SubmitMode::TransientHttp);
    let outcome = first.submit_once(&job, 1).await.expect("first submit");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "the ambiguous first broadcast leaves the attempt recorded, got {outcome:?}"
    );

    // Retry delivery seconds later: deterministic reject + AFFIRMATIVE absence,
    // but the attempt is far younger than the indexer-lag horizon, so the
    // absence is uncorroborated and the classifier must defer.
    let retry = handler(&db.pool, &wallet, SubmitMode::NodeReject);
    let outcome = retry.submit_once(&job, 2).await.expect("retry submit");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "a young affirmative absence defers instead of refunding, got {outcome:?}"
    );

    assert_eq!(
        current_attempt_status(&db.pool, record_id).await,
        Some("recorded".to_string()),
        "a young absence never abandons the attempt"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "a young absence keeps the input reserved"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "a refund never rides an uncorroborated absence"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitting");
}

/// Past the horizon the same affirmative absence IS trustworthy — a self-landed
/// transaction would have been indexed by now — so the resume abandons and
/// refunds: the terminal guarantee for a truly-dead attempt survives the age
/// gate (the recovery sweep keeps re-driving the resume until this fires).
#[tokio::test]
async fn a_resume_reject_with_absence_past_the_indexer_horizon_abandons_and_refunds() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([74u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x74, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"aged-absence-record",
        Some(wallet_id),
    )
    .await;
    let job = SubmitJob {
        request_id: "req-aged-absence".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // First delivery: an ambiguous broadcast failure leaves the attempt recorded.
    let first = handler(&db.pool, &wallet, SubmitMode::TransientHttp);
    let outcome = first.submit_once(&job, 1).await.expect("first submit");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "the ambiguous first broadcast leaves the attempt recorded, got {outcome:?}"
    );
    let attempt_id = current_attempt_id(&db.pool, record_id)
        .await
        .expect("the record rides the recorded attempt");

    // The attempt has now outlived the indexer-lag horizon and a fresh lookup
    // STILL affirms absence: the absence is corroborated, the attempt is truly
    // dead, and the resume may finally abandon and refund.
    backdate_attempt_past_absence_horizon(&db.pool, attempt_id).await;
    let retry = handler(&db.pool, &wallet, SubmitMode::NodeReject);
    let outcome = retry.submit_once(&job, 2).await.expect("retry submit");
    assert!(
        matches!(
            outcome,
            SubmitOutcome::Failed {
                error: SubmitError::NodeRejected { .. }
            }
        ),
        "a corroborated absence terminalises the attempt, got {outcome:?}"
    );

    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        Some("abandoned".to_string()),
        "the corroborated-absent attempt is abandoned"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("available".to_string()),
        "the proven-dead attempt's input is restored to the pool"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(
        status, "permanent_failure",
        "the record is terminalised once absence is corroborated"
    );
    assert_eq!(count_refunds(&db.pool, record_id).await, 1);
    assert_eq!(
        refund_reason(&db.pool, record_id).await,
        Some("node_rejected".to_string())
    );
}

/// The intra-call failover shape of the same hole: on the attempt's genuine
/// FIRST broadcast, the failover's PRIMARY arm fails transiently (an ambiguous
/// wire contact — the bytes may have reached the primary's node) and the
/// SECONDARY answers a deterministic reject. That reject may be the transaction
/// conflicting with its own copy the primary delivered, so it must NOT ride the
/// first-broadcast immediate refund: the failover downgrades it to the
/// transient ambiguous-broadcast class and everything stays in flight for the
/// corroborated resume path.
#[tokio::test]
async fn a_first_broadcast_reject_after_a_failed_over_transient_primary_never_refunds_regression() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([75u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x75, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"failover-reject-record",
        Some(wallet_id),
    )
    .await;

    // A real failover pair: the primary's submit fails with a transient 5xx (the
    // ambiguous contact), the secondary deterministically rejects the body.
    let failover_gateway = FailoverGateway::new(
        TestGateway::new(SubmitMode::TransientHttp),
        TestGateway::new(SubmitMode::NodeReject),
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        ProviderCooldown::new(db.pool.clone()),
        ChainNetwork::Preprod,
    );
    let handler = SubmitHandler::new(
        db.pool.clone(),
        failover_gateway,
        config(),
        wallet.keyring.clone(),
    );
    let job = SubmitJob {
        request_id: "req-failover-reject".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    let outcome = handler.submit_once(&job, 1).await.expect("first submit");
    assert!(
        matches!(outcome, SubmitOutcome::RecordedInFlight),
        "a reject after a failed-over ambiguous primary contact leaves the attempt in \
         flight, got {outcome:?}"
    );

    // NO refund, NO abandon, NO restore: the bytes may be on the wire via the
    // primary, so only the corroborated resume path may ever terminalise this.
    assert_eq!(
        current_attempt_status(&db.pool, record_id).await,
        Some("recorded".to_string()),
        "the attempt stays recorded, never abandoned on the downgraded reject"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "the input stays reserved: the primary may have delivered the spend"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "a first-broadcast reject behind an ambiguous failover contact never refunds"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitting");
}

// ---------------------------------------------------------------------------
// A cancelling replacement that gets a deterministic node reject must NOT refund:
// the superseded ORIGINAL it cancels is still a live, reconcilable broadcaster that
// can confirm. The replacement re-spends the original's input by construction, so an
// "already spent / ledger-invalid" reject is the EXPECTED signal when the original
// is in a mempool or has re-landed. Refunding there would refund the customer while
// the original can still anchor the PoE on chain (double-spend of money + free
// publish). Instead the replacement is abandoned, its EXCLUSIVE inputs restored, and
// the record handed back to the live original for the confirm authority to own.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_rejected_replacement_does_not_refund_and_hands_the_record_back_to_the_live_original() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([57u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    // The replacement's fresh canonical input (exclusive to it) ...
    let (canonical_hash, canonical_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x57, 0, band().mid as i64).await;
    // ... and the shared input the live original spent, which the replacement is
    // forced to re-spend so it conflicts with the original.
    let shared = [0x58u8; 32];
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, 0, $3, 'pending_spent', false, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(shared.as_slice())
    .bind(band().mid as i64)
    .execute(&db.pool)
    .await
    .expect("insert shared input");
    seed_protocol_params(&db.pool, 16384).await;

    // A record that already submitted, landed in a mempool, then was rolled back: the
    // original is the live broadcaster the replacement supersedes. The record is
    // `submitted` riding the original.
    let record_id = seed_record(
        &db.pool,
        operator_id,
        b"reject-replacement",
        Some(wallet_id),
    )
    .await;
    sqlx::query("UPDATE cw_core.poe_record SET status = 'submitted' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("set submitted");
    let (original_id, original_tx) = seed_original_attempt(
        &db.pool,
        record_id,
        wallet_id,
        0x9C,
        &[(shared, 0, band().mid)],
    )
    .await;

    // The replacement is recorded and broadcast, but the node deterministically
    // rejects its body. Drive the full handler.
    let handler = handler(&db.pool, &wallet, SubmitMode::NodeReject);
    let job = SubmitJob {
        request_id: "req-reject-replacement".to_string(),
        record_id,
        replacement_for: Some(hex::encode(original_tx)),
        forced_inputs: vec![ForcedInput {
            tx_hash: hex::encode(shared),
            index: 0,
            lovelace: band().mid,
        }],
    };
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let outcome = handler.handle(ctx).await;
    assert!(
        matches!(outcome, JobOutcome::Complete),
        "a rejected replacement completes the job, got {outcome:?}"
    );

    // The RECORD IS NOT REFUNDED and stays non-terminal: the original can still land.
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(
        status, "submitted",
        "the record stays non-terminal so the live original can still confirm it"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "a rejected replacement NEVER refunds while its original is alive"
    );

    // The replacement attempt is abandoned; the original is restored to the active
    // broadcaster set and the record points back at it.
    let replacement_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM cw_core.chain_attempt \
         WHERE record_id = $1 AND kind = 'replacement'",
    )
    .bind(record_id)
    .fetch_one(&db.pool)
    .await
    .expect("read replacement id");
    assert_eq!(
        attempt_status(&db.pool, replacement_id).await,
        Some("abandoned".to_string()),
        "the rejected replacement is abandoned"
    );
    assert_eq!(
        attempt_status(&db.pool, original_id).await,
        Some("broadcast".to_string()),
        "the live original is restored to the active-broadcaster set"
    );
    assert_eq!(
        current_attempt_id(&db.pool, record_id).await,
        Some(original_id),
        "the record is handed back to the live original"
    );

    // The shared input stays the original's reservation; only the replacement's
    // exclusive (fresh canonical) input returns to the pool.
    assert_eq!(
        utxo_state(&db.pool, wallet_id, shared, 0).await,
        Some("pending_spent".to_string()),
        "the shared input stays reserved by the still-live original, never freed"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, canonical_hash, canonical_index).await,
        Some("available".to_string()),
        "the replacement's exclusive input returns to the pool"
    );
}

// ---------------------------------------------------------------------------
// A charged publish must always reach a terminal state (landed or refunded), never
// silent limbo. The final wallet-contention retry, which fires BEFORE any attempt is
// recorded, must not leave a first submit stranded in `submitting` with no recorded
// attempt and no refund.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_final_wallet_contention_refunds_a_charged_first_submit_instead_of_stranding_it() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([59u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    seed_protocol_params(&db.pool, 16384).await;
    // No canonical UTxO is seeded, so the claim finds none and the submit raises
    // WalletLockContention before any attempt is recorded — the exact pre-record
    // contention that would otherwise strand a charged publish forever.
    let record_id = seed_record(&db.pool, operator_id, b"contention-strand", Some(wallet_id)).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-contention".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    // A non-final attempt is a plain retry (no refund, record stays submitting).
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let mid = handler.handle(ctx).await;
    assert!(
        matches!(mid, JobOutcome::Fail { .. }),
        "a non-final contention retries, got {mid:?}"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(
        status, "submitting",
        "a non-final contention leaves the record submitting"
    );
    assert_eq!(count_refunds(&db.pool, record_id).await, 0);

    // The FINAL attempt terminalises the stranded charged publish with one refund.
    let ctx_final = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(&job).unwrap(),
        attempt: SUBMIT_MAX_ATTEMPTS,
        is_final_attempt: true,
        defer_count: 0,
    };
    let last = handler.handle(ctx_final).await;
    assert!(
        matches!(last, JobOutcome::Complete),
        "the final contention terminalises the job, got {last:?}"
    );
    let (status, ..) = read_record(&db.pool, record_id).await;
    assert_eq!(
        status, "permanent_failure",
        "the final contention refunds the charged publish instead of stranding it"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        1,
        "exactly one refund is written for the stranded charged publish"
    );
}

// ---------------------------------------------------------------------------
// Split-resume re-broadcast. A stranded `kind='split'` attempt (recorded before
// broadcast, never reached the wire, no record) is recovered by the submit handler
// re-broadcasting its durable bytes: an accept marks it broadcast for the confirm
// authority; a deterministic reject abandons it and restores its source — but only
// once a fresh lookup proves the split's own transaction absent from chain —
// closing the strand that would otherwise leave the source pending_spent forever.
// ---------------------------------------------------------------------------

/// Seed a recorded `kind='split'` attempt whose source is `pending_spent`, with REAL
/// signed bytes whose body hash equals the attempt's `tx_hash`, so a re-broadcast
/// through the Accept gateway (which echoes the body hash) cross-checks. It produces
/// the bytes by running a real first submit (which records and broadcasts a genuine
/// signed transaction), then re-shapes that attempt into a stranded split: status
/// back to `recorded`, `mempool_entered_at` cleared, `kind='split'`, `record_id`
/// NULL, and the record detached. The result is exactly the record-before-broadcast
/// state a split that never reached the wire leaves behind. Returns the attempt id
/// and the spent source's tx hash.
async fn seed_recorded_split(
    pool: &sqlx::PgPool,
    wallet: &Wallet,
    operator_id: Uuid,
    wallet_id: Uuid,
    canonical_byte: u8,
) -> (Uuid, [u8; 32]) {
    let (source, source_index) =
        seed_canonical_utxo(pool, wallet_id, canonical_byte, 0, band().mid as i64).await;
    let _ = source_index;
    seed_protocol_params(pool, 16384).await;
    let record_id = seed_record(pool, operator_id, b"split-seed-record", Some(wallet_id)).await;

    // Run a real submit so a genuine signed transaction is recorded against the
    // source, then read its durable bytes/hash and reshape the attempt into a split.
    let handler = handler(pool, wallet, SubmitMode::Accept);
    let job = SubmitJob {
        request_id: "req-split-seed".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = handler.submit_once(&job, 1).await.expect("seed submit");
    assert!(
        matches!(outcome, SubmitOutcome::Submitted { .. }),
        "the seed submit lands a real signed transaction, got {outcome:?}"
    );
    let attempt_id = current_attempt_id(pool, record_id)
        .await
        .expect("the seed record rides an attempt");

    // Detach the record and reshape the attempt into a stranded split: the subject
    // CHECK requires a split carry no record, so clear the record pointer first.
    sqlx::query("UPDATE cw_core.poe_record SET current_attempt_id = NULL WHERE id = $1")
        .bind(record_id)
        .execute(pool)
        .await
        .expect("detach record");
    sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET kind = 'split', record_id = NULL, status = 'recorded', \
             mempool_entered_at = NULL \
         WHERE id = $1",
    )
    .bind(attempt_id)
    .execute(pool)
    .await
    .expect("reshape attempt into a stranded split");
    (attempt_id, source)
}

#[tokio::test]
async fn a_split_resume_re_broadcasts_and_marks_the_split_broadcast_on_accept() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([60u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (attempt_id, source) =
        seed_recorded_split(&db.pool, &wallet, operator_id, wallet_id, 0x60).await;

    let (handler, gateway) = handler_observable(&db.pool, &wallet, SubmitMode::Accept);
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(SplitResumeJob {
            split_attempt_id: attempt_id,
        })
        .unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let outcome = handler.handle(ctx).await;
    assert!(matches!(outcome, JobOutcome::Complete), "got {outcome:?}");
    assert_eq!(
        gateway.submits(),
        1,
        "the recorded split bytes are re-broadcast once"
    );
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        Some("broadcast".to_string()),
        "a matching echo advances the split to broadcast for the confirm authority"
    );
    // The source stays reserved (a confirm later promotes the spend); the resume
    // never restores it.
    assert_eq!(
        utxo_state(&db.pool, wallet_id, source, 0).await,
        Some("pending_spent".to_string())
    );
}

#[tokio::test]
async fn a_split_resume_deterministic_reject_abandons_the_split_and_restores_its_source() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([61u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (attempt_id, source) =
        seed_recorded_split(&db.pool, &wallet, operator_id, wallet_id, 0x61).await;
    // The abandon requires the absence to be corroborated by age: a split resume
    // is always a re-broadcast, so a young "no record" could still be indexer
    // lag. Age the attempt past the horizon so the affirmative absence is
    // trustworthy and the abandon may fire.
    backdate_attempt_past_absence_horizon(&db.pool, attempt_id).await;

    let handler = handler(&db.pool, &wallet, SubmitMode::NodeReject);
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(SplitResumeJob {
            split_attempt_id: attempt_id,
        })
        .unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let outcome = handler.handle(ctx).await;
    assert!(matches!(outcome, JobOutcome::Complete), "got {outcome:?}");

    // The node rejected the body, the lookup proved the split's own transaction
    // absent, AND the attempt outlived the indexer-lag horizon, so the split is
    // abandoned and its source returns to the pool: the strand that would leave
    // the source pending_spent forever is closed.
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        Some("abandoned".to_string()),
        "a deterministic reject of a corroborated-absent split abandons it"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, source, 0).await,
        Some("available".to_string()),
        "the rejected split's source is restored to the pool"
    );
}

/// The split analogue of the young-absence deferral: a split resume is always a
/// re-broadcast, so an affirmative "no record" on a young split can still be
/// indexer lag on a self-landed transaction. The resume must leave the split
/// recorded (source reserved) for the next sweep rather than restore a source
/// the split may have spent on chain.
#[tokio::test]
async fn a_split_resume_reject_with_a_young_absence_leaves_the_split_recorded_regression() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([65u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (attempt_id, source) =
        seed_recorded_split(&db.pool, &wallet, operator_id, wallet_id, 0x65).await;

    // Deterministic reject + affirmative absence on a seconds-old split: the
    // absence is uncorroborated, so nothing may move.
    let handler = handler(&db.pool, &wallet, SubmitMode::NodeReject);
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(SplitResumeJob {
            split_attempt_id: attempt_id,
        })
        .unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let outcome = handler.handle(ctx).await;
    assert!(matches!(outcome, JobOutcome::Complete), "got {outcome:?}");

    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        Some("recorded".to_string()),
        "a young absence leaves the split recorded for the next sweep"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, source, 0).await,
        Some("pending_spent".to_string()),
        "a young absence keeps the source reserved"
    );
}

#[tokio::test]
async fn a_self_landed_split_rejected_on_rebroadcast_keeps_its_source_reserved_regression() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([62u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (attempt_id, source) =
        seed_recorded_split(&db.pool, &wallet, operator_id, wallet_id, 0x62).await;

    // The split's earlier "failed" broadcast actually landed and confirmed: the
    // re-broadcast is deterministically rejected (its source is spent by its own
    // body) while the fresh own-tx lookup reports the split on chain.
    let handler = handler_with_confirmations(
        &db.pool,
        &wallet,
        SubmitMode::NodeReject,
        ConfirmationsMode::OnChain,
    );
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(SplitResumeJob {
            split_attempt_id: attempt_id,
        })
        .unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let outcome = handler.handle(ctx).await;
    assert!(matches!(outcome, JobOutcome::Complete), "got {outcome:?}");

    // The self-landed split is handed to the confirm authority, never abandoned,
    // and its source stays reserved: it is spent ON CHAIN by the split's own
    // transaction, so restoring it would hand a spent UTxO back to the pool.
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        Some("broadcast".to_string()),
        "a self-landed split advances to broadcast for the confirm authority"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, source, 0).await,
        Some("pending_spent".to_string()),
        "the on-chain-spent source is never returned to available"
    );
}

#[tokio::test]
async fn an_inconclusive_lookup_on_a_split_reject_leaves_the_split_recorded_regression() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([63u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (attempt_id, source) =
        seed_recorded_split(&db.pool, &wallet, operator_id, wallet_id, 0x63).await;

    // The node deterministically rejects the re-broadcast, but the own-tx lookup
    // FAILS: absence is unproven, so the resume must leave the split recorded for
    // the next sweep rather than restore its source on an inconclusive observation.
    let handler = handler_with_confirmations(
        &db.pool,
        &wallet,
        SubmitMode::NodeReject,
        ConfirmationsMode::LookupFails,
    );
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(SplitResumeJob {
            split_attempt_id: attempt_id,
        })
        .unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let outcome = handler.handle(ctx).await;
    assert!(matches!(outcome, JobOutcome::Complete), "got {outcome:?}");

    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        Some("recorded".to_string()),
        "an inconclusive lookup leaves the split recorded for the next sweep"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, source, 0).await,
        Some("pending_spent".to_string()),
        "an inconclusive lookup keeps the source reserved"
    );
}

#[tokio::test]
async fn a_positive_but_incomplete_observation_on_a_split_reject_leaves_it_recorded_regression() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([64u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    let (attempt_id, source) =
        seed_recorded_split(&db.pool, &wallet, operator_id, wallet_id, 0x64).await;

    // The node deterministically rejects the re-broadcast, and the own-tx lookup
    // answers positive-but-incomplete (the provider counted the split's own
    // just-landed transaction but its detail row lagged). Absence is unproven, so
    // the resume must leave the split recorded rather than restore a source the
    // split may have spent on chain.
    let handler = handler_with_confirmations(
        &db.pool,
        &wallet,
        SubmitMode::NodeReject,
        ConfirmationsMode::Inconclusive,
    );
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: SUBMIT_QUEUE.to_string(),
        payload: serde_json::to_value(SplitResumeJob {
            split_attempt_id: attempt_id,
        })
        .unwrap(),
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    let outcome = handler.handle(ctx).await;
    assert!(matches!(outcome, JobOutcome::Complete), "got {outcome:?}");

    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        Some("recorded".to_string()),
        "a lag-window observation leaves the split recorded for the next sweep"
    );
    assert_eq!(
        utxo_state(&db.pool, wallet_id, source, 0).await,
        Some("pending_spent".to_string()),
        "a lag-window observation keeps the source reserved"
    );
}

// ---------------------------------------------------------------------------
// Lock order. The record-before-broadcast transaction holds the wallet advisory
// lock and writes attempt -> record -> wallet. A concurrent submit on the SAME
// wallet must serialize on the advisory lock (one records, the other yields a
// retryable contention) and never deadlock or double-spend the same UTxO.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_concurrent_submits_on_one_wallet_serialize_on_the_wallet_lock() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    let wallet = wallet_from_seed([46u8; 32]);
    let (operator_id, wallet_id) =
        seed_operator_and_wallet(&db.pool, &wallet.address, "active").await;
    // A single canonical input: two concurrent submits for two records contend for
    // the wallet, and only one can spend the lone UTxO at a time.
    let (utxo_hash, utxo_index) =
        seed_canonical_utxo(&db.pool, wallet_id, 0x4E, 0, band().mid as i64).await;
    seed_protocol_params(&db.pool, 16384).await;
    let record_a = seed_record(&db.pool, operator_id, b"lock-order-a", Some(wallet_id)).await;
    let record_b = seed_record(&db.pool, operator_id, b"lock-order-b", Some(wallet_id)).await;

    // Two handlers over independent gateways so each tracks its own submit. They
    // share the same wallet and pool, so the per-wallet advisory lock serializes
    // them.
    let handler_a = handler(&db.pool, &wallet, SubmitMode::Accept);
    let handler_b = handler(&db.pool, &wallet, SubmitMode::Accept);
    let job_a = SubmitJob {
        request_id: "req-a".to_string(),
        record_id: record_a,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let job_b = SubmitJob {
        request_id: "req-b".to_string(),
        record_id: record_b,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };

    let (out_a, out_b) = tokio::join!(
        handler_a.submit_once(&job_a, 1),
        handler_b.submit_once(&job_b, 1)
    );
    let out_a = out_a.expect("submit a");
    let out_b = out_b.expect("submit b");

    // The two never deadlock (both returned). Exactly one landed; the other found
    // the wallet locked or the lone UTxO already leased, a retryable contention.
    let landed = [&out_a, &out_b]
        .iter()
        .filter(|o| matches!(o, SubmitOutcome::Submitted { .. }))
        .count();
    let contended = [&out_a, &out_b]
        .iter()
        .filter(|o| {
            matches!(
                o,
                SubmitOutcome::Failed {
                    error: SubmitError::WalletLockContention
                }
            )
        })
        .count();
    assert_eq!(
        landed, 1,
        "exactly one of the contending submits lands (a={out_a:?}, b={out_b:?})"
    );
    assert_eq!(
        contended, 1,
        "the other yields a retryable contention, never deadlocks (a={out_a:?}, b={out_b:?})"
    );

    // The lone UTxO was spent exactly once (pending_spent), never double-spent.
    assert_eq!(
        utxo_state(&db.pool, wallet_id, utxo_hash, utxo_index).await,
        Some("pending_spent".to_string()),
        "the single UTxO is spent by exactly one submit, never double-spent"
    );
    // Exactly one record recorded an attempt (the loser minted none).
    let total_attempts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.chain_attempt WHERE wallet_id = $1")
            .bind(wallet_id)
            .fetch_one(&db.pool)
            .await
            .expect("count attempts");
    assert_eq!(
        total_attempts, 1,
        "exactly one attempt was recorded across the race"
    );
}
