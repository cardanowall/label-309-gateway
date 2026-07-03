//! Live preprod re-validation of the chain-core cutover blocker: one paid publish
//! yields EXACTLY ONE on-chain transaction, even under at-least-once job redelivery
//! and the post-broadcast crash window.
//!
//! This drives the REAL submit handler against the REAL Cardano preprod chain via
//! Koios, then re-drives the SAME record's submit (the at-least-once redelivery the
//! sweeper performs) and reproduces the crash window (a crash after broadcast but
//! before the `submitted` flip commits). The record-before-broadcast attempt ledger
//! must make every re-drive re-broadcast the EXACT recorded transaction rather than
//! build, sign and broadcast a second one. It closes with an INDEPENDENT Koios proof
//! that exactly one transaction spending the selected input exists on chain.
//!
//! It is doubly gated and skips (passing trivially) unless BOTH are set, exactly
//! like `chain_live_e2e.rs`, so the default `cargo test` and the `pg-tests` suite
//! never touch the network or move funds:
//!
//! - `GATEWAY_LIVE_TESTS=1` enables the live network path.
//! - `GATEWAY_OPERATOR_KEYRING_PATH` / `GATEWAY_OPERATOR_KEYRING_PASSPHRASE_PATH`
//!   point at the age-encrypted operator keyring and its passphrase file.
//!
//! It uses its OWN database (`GATEWAY_TEST_DATABASE_URL` must point at a dedicated
//! DB, e.g. `cardanowall_gateway_blocker_e2e`). It creates and migrates that DB in
//! place via `reset_and_migrate` and LEAVES it for inspection (it does not drop it),
//! unlike `TestDb::fresh`.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;
use std::time::Duration;

use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};
use gateway_core::chain::attempt::{self, AttemptStatus};
use gateway_core::chain::confirm::{upsert_tip, ConfirmConfig, ConfirmHandler};
use gateway_core::chain::gateway::{ChainGateway, KoiosGateway};
use gateway_core::chain::params::{
    KoiosParamsSource, Network as ParamsNetwork, ParamsPopulateHandler,
};
use gateway_core::chain::records::{IndexTxHandler, IndexTxJob, INDEX_TX_QUEUE};
use gateway_core::chain::submit::{submit_policy, SubmitHandler, SubmitJob, SubmitOutcome};
use gateway_core::runtime::policy::reconcile;
use gateway_core::testsupport::reset_and_migrate;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use gateway_core::wallet::keyring::{unlock, UnlockedKeyring};
use gateway_core::wallet::utxo::{ingest_snapshot, KoiosUtxoSource, UtxoSource};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The expected funded preprod wallet address (the keyring must resolve to it).
const FUNDED_ADDRESS: &str = "addr_test1vpa8ukd77k05gc3etxeyzylxxmyhzg0hvne9qplxvsyl44q6pl7v4";

/// The dedicated DB this validation owns (created + migrated in place, left for
/// inspection). The base test URL is taken from `GATEWAY_TEST_DATABASE_URL`.
const OWN_DB_URL: &str =
    "postgres://cardanowall:cardanowall_dev@localhost:5432/cardanowall_gateway_blocker_e2e";

const LIVE_CONFIRMATION_THRESHOLD: u64 = 2;
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(900);
const CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(20);

fn live_band() -> LovelaceBand {
    LovelaceBand {
        min: 4_000_000,
        max: 8_000_000,
        mid: 6_000_000,
    }
}

fn live_config() -> WalletConfig {
    WalletConfig {
        network: Network::Preprod,
        band: live_band(),
        lease: Duration::from_secs(120),
        min_canonical_count: 1,
    }
}

fn live_keyring() -> Option<(Vec<u8>, Zeroizing<String>)> {
    if std::env::var("GATEWAY_LIVE_TESTS").as_deref() != Ok("1") {
        eprintln!("skipping live preprod blocker e2e: set GATEWAY_LIVE_TESTS=1 to enable");
        return None;
    }
    let keyring_path = std::env::var("GATEWAY_OPERATOR_KEYRING_PATH").ok()?;
    let passphrase_path = std::env::var("GATEWAY_OPERATOR_KEYRING_PASSPHRASE_PATH").ok()?;
    let ciphertext = std::fs::read(&keyring_path).expect("read operator keyring");
    let passphrase = Zeroizing::new(
        std::fs::read_to_string(&passphrase_path)
            .expect("read keyring passphrase")
            .trim_end()
            .to_string(),
    );
    Some((ciphertext, passphrase))
}

/// A minimal valid Label 309 record carrying one open content item, with a unique
/// hash per run so each live submit publishes a distinct record (distinct metadata).
fn minimal_record_bytes(nonce: [u8; 32]) -> Vec<u8> {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), nonce.to_vec())],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    encode_poe_record(&record).expect("encode minimal record")
}

/// Seed the operator and the keyring's preprod wallet (its real address) bound to
/// it, mirroring the live e2e seed.
async fn seed_operator_and_keyring_wallet(pool: &sqlx::PgPool, address: &str) -> (Uuid, Uuid) {
    let operator_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'blocker-op')")
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert operator");
    let wallet_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet (id, registrar_operator_id, label, address, network, status) \
         VALUES ($1, $2, 'live', $3, 'preprod', 'active')",
    )
    .bind(wallet_id)
    .bind(operator_id)
    .bind(address)
    .execute(pool)
    .await
    .expect("insert wallet");
    (operator_id, wallet_id)
}

/// Seed an account under the operator with a generous USD balance and one PENDING
/// publish quote, so the publish path can consume exactly one quote and the single
/// `poe_publish` debit can be proven. Returns (account_id, quote_id).
async fn seed_account_and_quote(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    record_bytes_len: i32,
) -> (Uuid, Uuid) {
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("insert account");
    sqlx::query("INSERT INTO cw_core.account_detail (account_id, operator_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert account_detail");

    // Register a vendor top-up credit kind and credit a generous balance so the
    // publish debit is affordable.
    sqlx::query(
        "INSERT INTO cw_core.ledger_kind_registry (kind, allows_overdraft, registered_by) \
         VALUES ('vendor_topup', false, 'vendor') ON CONFLICT (kind) DO NOTHING",
    )
    .execute(pool)
    .await
    .expect("register credit kind");
    sqlx::query(
        "INSERT INTO cw_core.balance_ledger (account_id, kind, amount_micros, ref, allows_overdraft) \
         VALUES ($1, 'vendor_topup', 100000000, 'seed-credit', false)",
    )
    .bind(account_id)
    .execute(pool)
    .await
    .expect("seed credit");

    let quote_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.publish_quote \
           (id, account_id, expires_at, record_bytes, file_bytes_total, network_lovelace, \
            network_usd_micros, storage_usd_micros, margin_pct, margin_source, \
            service_usd_micros, total_usd_micros, fx_snapshot, status) \
         VALUES ($1, $2, now() + interval '60 minutes', $3, 0, 200000, \
            50000, 0, 0.2500, 'fixed', 12500, 62500, '{}'::jsonb, 'pending')",
    )
    .bind(quote_id)
    .bind(account_id)
    .bind(record_bytes_len)
    .execute(pool)
    .await
    .expect("insert pending quote");
    (account_id, quote_id)
}

/// Count the `poe_publish` ledger debits for a record (the idempotency target).
async fn count_publish_debits(pool: &sqlx::PgPool, record_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger \
         WHERE kind = 'poe_publish' AND ref = $1",
    )
    .bind(record_id.to_string())
    .fetch_one(pool)
    .await
    .expect("count publish debits")
}

/// Count chain_attempt rows for a record (any extra means a second broadcaster).
async fn count_record_attempts(pool: &sqlx::PgPool, record_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.chain_attempt WHERE record_id = $1")
        .bind(record_id)
        .fetch_one(pool)
        .await
        .expect("count attempts")
}

async fn current_attempt_id(pool: &sqlx::PgPool, record_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT current_attempt_id FROM cw_core.poe_record WHERE id = $1")
        .bind(record_id)
        .fetch_one(pool)
        .await
        .expect("read current_attempt_id")
}

async fn record_status(pool: &sqlx::PgPool, record_id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM cw_core.poe_record WHERE id = $1")
        .bind(record_id)
        .fetch_one(pool)
        .await
        .expect("read status")
}

async fn count_events(pool: &sqlx::PgPool, record_id: Uuid, event_type: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'poe_record' AND subject_id = $1 AND event_type = $2",
    )
    .bind(record_id.to_string())
    .bind(event_type)
    .fetch_one(pool)
    .await
    .expect("count events")
}

#[tokio::test]
async fn live_preprod_one_publish_one_tx_under_redelivery_and_crash_window() {
    let Some((ciphertext, passphrase)) = live_keyring() else {
        return;
    };

    // === Decrypt the operator keyring and resolve the preprod wallet. ===
    let keyring: UnlockedKeyring =
        unlock(&ciphertext, passphrase, Network::Preprod).expect("unlock operator keyring");
    let wallets = keyring.wallets();
    let wallet = wallets
        .first()
        .expect("the operator keyring holds at least one preprod wallet");
    let address = wallet.address.clone();
    eprintln!("live preprod wallet address: {address}");
    assert_eq!(
        address, FUNDED_ADDRESS,
        "the keyring must resolve to the funded preprod address"
    );
    let keyring = Arc::new(keyring);

    // === Set up: OWN DB + migrations (created + migrated in place, never dropped). ===
    std::env::set_var(gateway_core::testsupport::TEST_DATABASE_URL_ENV, OWN_DB_URL);
    let pool = reset_and_migrate(OWN_DB_URL)
        .await
        .expect("create + migrate own DB");
    for policy in [
        submit_policy(),
        gateway_core::chain::confirm::confirm_policy(),
        gateway_core::chain::records::index_tx_policy(),
    ] {
        reconcile(&pool, &policy).await.expect("reconcile policy");
    }
    let (operator_id, wallet_id) = seed_operator_and_keyring_wallet(&pool, &address).await;

    // === Populate LIVE protocol parameters from preprod Koios. ===
    let params_handler = ParamsPopulateHandler::new(
        pool.clone(),
        KoiosParamsSource::new(Default::default()).expect("build params source"),
        vec![ParamsNetwork::Preprod],
    );
    for (network, result) in &params_handler.run_once().await {
        result
            .as_ref()
            .unwrap_or_else(|e| panic!("populate live params for {network:?}: {e}"));
    }

    // === Ingest the wallet's LIVE UTxOs into durable wallet state. ===
    let utxo_source = KoiosUtxoSource::new(ParamsNetwork::Preprod.koios_base_url(), None)
        .expect("build utxo source");
    let observed = utxo_source
        .address_utxos(&address)
        .await
        .expect("fetch live utxos");
    assert!(
        !observed.is_empty(),
        "the funded wallet {address} has no UTxOs; STOP NEEDS-FUNDING"
    );
    let config = live_config();
    ingest_snapshot(&pool, wallet_id, &observed, &config)
        .await
        .expect("ingest live utxos");
    let canonical: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND state = 'available' AND canonical = true",
    )
    .bind(wallet_id)
    .fetch_one(&pool)
    .await
    .expect("count canonical");
    assert!(canonical >= 1, "no canonical UTxO; STOP NEEDS-FUNDING");
    eprintln!("ingested {canonical} canonical UTxOs");

    // === Build the record + seed account/quote, then publish exactly like the API. ===
    let nonce = *uuid::Uuid::now_v7().as_bytes();
    let mut nonce32 = [0u8; 32];
    nonce32[..16].copy_from_slice(&nonce);
    let record_bytes = minimal_record_bytes(nonce32);
    let record_id = Uuid::now_v7();
    let (account_id, quote_id) =
        seed_account_and_quote(&pool, operator_id, record_bytes.len() as i32).await;

    // Insert the record bound to the account (text id) and wallet, status submitting,
    // then consume the quote exactly once (the publish debit, ref = record id).
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, account_id, record_bytes, status, wallet_id, request_id) \
         VALUES ($1, $2, $3, $4, 'submitting', $5, $6)",
    )
    .bind(record_id)
    .bind(operator_id)
    .bind(account_id)
    .bind(&record_bytes)
    .bind(wallet_id)
    .bind("blocker-req-1")
    .execute(&pool)
    .await
    .expect("insert poe_record");

    let consume = gateway_core::ledger::quote::consume_quote(
        &pool,
        quote_id,
        account_id,
        record_id,
        record_bytes.len() as u32,
        None,
    )
    .await
    .expect("consume quote");
    assert!(
        matches!(
            consume,
            gateway_core::ledger::quote::ConsumeOutcome::Consumed { .. }
        ),
        "the publish consumes the quote exactly once, got {consume:?}"
    );
    assert_eq!(
        count_publish_debits(&pool, record_id).await,
        1,
        "exactly one poe_publish debit after the publish"
    );

    // === STEP 2: NORMAL live submit against live Koios. ===
    let submit_gateway =
        KoiosGateway::new(ParamsNetwork::Preprod, Default::default()).expect("submit gateway");
    let submit_handler = SubmitHandler::new(pool.clone(), submit_gateway, config, keyring.clone());
    let job = SubmitJob {
        request_id: "blocker-req-1".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = submit_handler
        .submit_once(&job, 1)
        .await
        .expect("live submit");
    let SubmitOutcome::Submitted {
        tx_hash: tx1,
        spent_inputs,
        ..
    } = outcome
    else {
        panic!("the live submit did not land: {outcome:?}");
    };
    eprintln!("TX1 = {}", hex::encode(tx1));

    // The selected input I1 (the canonical UTxO the submit fenced and spent).
    assert_eq!(
        spent_inputs.len(),
        1,
        "a first submit spends one canonical input"
    );
    let input_i1 = spent_inputs[0];
    eprintln!(
        "I1 = {}#{}",
        hex::encode(input_i1.tx_hash),
        input_i1.output_index
    );

    // Record-before-broadcast ordering: the attempt was RECORDED (chain_attempt row
    // + poe_record.current_attempt_id) and carries the recorded signed bytes, fenced
    // inputs and the computed tx hash. The broadcaster sends only recorded bytes, so
    // the recorded tx hash equals TX1.
    let attempt_one = current_attempt_id(&pool, record_id)
        .await
        .expect("the record rides the recorded attempt");
    let recorded = attempt::load_attempt(&pool, attempt_one)
        .await
        .expect("load attempt")
        .expect("attempt exists");
    assert_eq!(
        recorded.tx_hash, tx1,
        "the recorded attempt's tx hash equals TX1 (record-before-broadcast)"
    );
    assert!(
        !recorded.signed_tx.is_empty(),
        "the attempt persists the signed bytes that went on the wire"
    );
    assert_eq!(
        recorded.spent_inputs.len(),
        1,
        "the recorded attempt fenced exactly the one canonical input"
    );
    let recorded_input = recorded.spent_inputs[0].utxo_ref().expect("utxo ref");
    assert_eq!(recorded_input, input_i1, "the recorded fenced input is I1");
    let recorded_signed = recorded.signed_tx.clone();
    assert_eq!(
        count_record_attempts(&pool, record_id).await,
        1,
        "exactly one chain_attempt after the normal submit"
    );
    assert_eq!(record_status(&pool, record_id).await, "submitted");
    assert_eq!(count_events(&pool, record_id, "submitted").await, 1);
    eprintln!("RECORD-BEFORE-BROADCAST OK: one attempt, tx_hash==TX1, input==I1");

    // === STEP 3: REDELIVERY (the core blocker scenario). ===
    // Re-drive the SAME record's submit. The record still rides the broadcast attempt
    // (status submitted). The resume path must re-broadcast the EXACT recorded bytes
    // (no fresh build/sign), claim NO new canonical UTxO, and be idempotent.
    let canonical_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND state = 'available' AND canonical = true",
    )
    .bind(wallet_id)
    .fetch_one(&pool)
    .await
    .expect("count canonical before redelivery");

    let redelivered = submit_handler
        .submit_once(&job, 2)
        .await
        .expect("redelivered submit");
    eprintln!("redelivery outcome: {redelivered:?}");
    assert!(
        matches!(redelivered, SubmitOutcome::AlreadyResolved),
        "a redelivery of a broadcast attempt resolves idempotently, got {redelivered:?}"
    );

    // No second attempt, still riding the original; identical recorded bytes; no new
    // canonical UTxO claimed; no duplicate submitted event; one publish debit.
    assert_eq!(
        count_record_attempts(&pool, record_id).await,
        1,
        "REDELIVERY: no second chain_attempt minted"
    );
    assert_eq!(
        current_attempt_id(&pool, record_id).await,
        Some(attempt_one),
        "REDELIVERY: the record still rides the original attempt"
    );
    let resumed_signed = attempt::load_attempt(&pool, attempt_one)
        .await
        .expect("load")
        .expect("exists")
        .signed_tx;
    assert_eq!(
        resumed_signed, recorded_signed,
        "REDELIVERY: the recorded bytes are byte-identical (no fresh build)"
    );
    let canonical_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND state = 'available' AND canonical = true",
    )
    .bind(wallet_id)
    .fetch_one(&pool)
    .await
    .expect("count canonical after redelivery");
    assert_eq!(
        canonical_before, canonical_after,
        "REDELIVERY: no fresh canonical UTxO was claimed (input stays I1)"
    );
    assert_eq!(
        count_events(&pool, record_id, "submitted").await,
        1,
        "REDELIVERY: mark_broadcast_and_flip is idempotent (no duplicate submitted event)"
    );
    assert_eq!(
        count_publish_debits(&pool, record_id).await,
        1,
        "REDELIVERY: still exactly one poe_publish debit"
    );
    eprintln!("REDELIVERY OK: re-broadcast identical TX1, no TX2, idempotent");

    // === STEP 4: CRASH WINDOW (crash after broadcast, before the submitted flip). ===
    // Reproduce the window: the broadcast committed and the attempt is on the wire
    // (broadcast), but the record never flipped (a crash between marking the attempt
    // broadcast and the submitted flip). Reset the projection to submitting while
    // keeping current_attempt_id and the live attempt, and drop the submitted event.
    let attempt_status_before = attempt::load_attempt(&pool, attempt_one)
        .await
        .expect("load")
        .expect("exists")
        .status;
    assert_eq!(
        attempt_status_before,
        AttemptStatus::Broadcast,
        "the live attempt is on the wire before the crash-window reset"
    );
    sqlx::query(
        "UPDATE cw_core.poe_record \
         SET status = 'submitting', tx_hash = NULL, actual_fee_lovelace = NULL, spent_inputs = NULL \
         WHERE id = $1",
    )
    .bind(record_id)
    .execute(&pool)
    .await
    .expect("reset projection to crash-window state");
    sqlx::query(
        "DELETE FROM cw_core.subject_event \
         WHERE subject_kind = 'poe_record' AND subject_id = $1 AND event_type = 'submitted'",
    )
    .bind(record_id.to_string())
    .execute(&pool)
    .await
    .expect("clear the submitted event");
    assert_eq!(
        record_status(&pool, record_id).await,
        "submitting",
        "crash-window state set"
    );

    // The idempotent-retry preamble (the redelivery) must re-broadcast TX1 (not a new
    // tx) and repair the submitting -> submitted flip.
    let repaired = submit_handler
        .submit_once(&job, 3)
        .await
        .expect("crash-window redelivery");
    eprintln!("crash-window outcome: {repaired:?}");
    assert!(
        matches!(repaired, SubmitOutcome::AlreadyResolved),
        "the crash-window resume resolves idempotently, got {repaired:?}"
    );
    assert_eq!(
        count_record_attempts(&pool, record_id).await,
        1,
        "CRASH-WINDOW: still exactly one chain_attempt (no TX2)"
    );
    assert_eq!(
        current_attempt_id(&pool, record_id).await,
        Some(attempt_one),
        "CRASH-WINDOW: still rides the original attempt"
    );
    let repaired_signed = attempt::load_attempt(&pool, attempt_one)
        .await
        .expect("load")
        .expect("exists")
        .signed_tx;
    assert_eq!(
        repaired_signed, recorded_signed,
        "CRASH-WINDOW: re-broadcast the EXACT recorded bytes"
    );
    assert_eq!(
        record_status(&pool, record_id).await,
        "submitted",
        "CRASH-WINDOW: projection repaired to submitted"
    );
    assert_eq!(
        count_events(&pool, record_id, "submitted").await,
        1,
        "CRASH-WINDOW: exactly one submitted event after repair (never duplicate)"
    );
    assert_eq!(
        count_publish_debits(&pool, record_id).await,
        1,
        "CRASH-WINDOW: still exactly one poe_publish debit"
    );
    eprintln!("CRASH-WINDOW OK: re-broadcast TX1, repaired flip, still one tx");

    // === STEP 5: ON-CHAIN PROOF — wait for TX1 to confirm, then verify via Koios. ===
    let confirm_gateway =
        KoiosGateway::new(ParamsNetwork::Preprod, Default::default()).expect("confirm gateway");
    let confirm_config = ConfirmConfig {
        confirmation_threshold: LIVE_CONFIRMATION_THRESHOLD,
        ..ConfirmConfig::default()
    };
    let confirm_handler = ConfirmHandler::new(
        pool.clone(),
        confirm_gateway,
        Network::Preprod.as_str(),
        confirm_config,
        live_config(),
    );

    let deadline = std::time::Instant::now() + CONFIRM_TIMEOUT;
    let mut confirmed = false;
    while std::time::Instant::now() < deadline {
        let tip_gateway =
            KoiosGateway::new(ParamsNetwork::Preprod, Default::default()).expect("tip gateway");
        let tip = tip_gateway.get_tip().await.expect("live tip");
        upsert_tip(
            &pool,
            Network::Preprod.as_str(),
            tip.block_height,
            tip.epoch,
        )
        .await
        .expect("upsert tip");
        let summary = confirm_handler
            .run_iteration()
            .await
            .expect("confirm iteration");
        let status = record_status(&pool, record_id).await;
        eprintln!(
            "confirm iteration: tip={} status={status} confirmed={} mempool={}",
            tip.block_height, summary.confirmed, summary.mempool
        );
        if status == "confirmed" {
            confirmed = true;
            break;
        }
        assert_ne!(
            status, "permanent_failure",
            "the record reached a terminal failure instead of confirming"
        );
        tokio::time::sleep(CONFIRM_POLL_INTERVAL).await;
    }
    assert!(
        confirmed,
        "the record did not confirm within {CONFIRM_TIMEOUT:?}"
    );

    let block_height: i64 =
        sqlx::query_scalar("SELECT block_height FROM cw_core.poe_record WHERE id = $1")
            .bind(record_id)
            .fetch_one(&pool)
            .await
            .expect("read block height");
    let confirmed_tx: Vec<u8> =
        sqlx::query_scalar("SELECT tx_hash FROM cw_core.poe_record WHERE id = $1")
            .bind(record_id)
            .fetch_one(&pool)
            .await
            .expect("read confirmed tx_hash");
    assert_eq!(
        confirmed_tx,
        tx1.to_vec(),
        "the record confirmed via TX1, not some other tx"
    );
    eprintln!(
        "CONFIRMED via TX1={} at block_height={block_height}",
        hex::encode(tx1)
    );

    // Run the single chain_records index writer the confirm flip enqueued.
    let index_payload: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM cw_core.job WHERE queue = $1")
            .bind(INDEX_TX_QUEUE)
            .fetch_one(&pool)
            .await
            .expect("the confirm flip enqueued exactly one index job");
    let index_job: IndexTxJob =
        serde_json::from_value(index_payload).expect("decode index job payload");
    assert_eq!(index_job.tx_hash, hex::encode(tx1));
    let index_handler = IndexTxHandler::new(
        pool.clone(),
        KoiosGateway::new(ParamsNetwork::Preprod, Default::default()).unwrap(),
        ParamsNetwork::Preprod,
    );
    let inserted = index_handler
        .index_once(&index_job)
        .await
        .expect("index the confirmed transaction");
    assert!(
        inserted,
        "the index job inserts exactly one chain_records row"
    );
    let chain_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.chain_records WHERE tx_hash = $1")
            .bind(tx1.as_slice())
            .fetch_one(&pool)
            .await
            .expect("count chain_records");
    assert_eq!(
        chain_rows, 1,
        "the chain_records row is for TX1 (exactly one)"
    );

    // Final single-debit assertion across the whole flow.
    assert_eq!(
        count_publish_debits(&pool, record_id).await,
        1,
        "exactly one poe_publish debit across submit + redelivery + crash-window + confirm"
    );

    // === INDEPENDENT Koios proof: exactly ONE tx spends I1, and it is TX1. ===
    // Query Koios for the spending transaction of I1 directly: utxo_info reports
    // whether the output is spent. (Koios utxo_info reports `is_spent` but NOT the
    // spending tx; the row's own tx_hash/tx_index are I1's ORIGIN coordinates. The
    // spender is proven below by inspecting transaction inputs.)
    let i1_hash_hex = hex::encode(input_i1.tx_hash);
    let utxo_ref = format!("{}#{}", i1_hash_hex, input_i1.output_index);
    let koios = reqwest::Client::new();
    let utxo_info: serde_json::Value = koios
        .post("https://preprod.koios.rest/api/v1/utxo_info")
        .json(&serde_json::json!({ "_utxo_refs": [utxo_ref], "_extended": true }))
        .send()
        .await
        .expect("koios utxo_info")
        .json()
        .await
        .expect("utxo_info json");
    eprintln!("koios utxo_info for I1 {utxo_ref}: {utxo_info}");
    let i1_rows = utxo_info.as_array().expect("utxo_info array");
    assert_eq!(
        i1_rows.len(),
        1,
        "Koios reports one record for I1 {utxo_ref}"
    );
    assert_eq!(
        i1_rows[0]
            .get("is_spent")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "I1 is spent on chain"
    );

    // Helper: fetch tx_info (with inputs + metadata) for a batch of tx hashes.
    async fn tx_info_batch(koios: &reqwest::Client, hashes: &[String]) -> Vec<serde_json::Value> {
        koios
            .post("https://preprod.koios.rest/api/v1/tx_info")
            .json(&serde_json::json!({
                "_tx_hashes": hashes, "_inputs": true, "_metadata": true,
            }))
            .send()
            .await
            .expect("koios tx_info")
            .json::<Vec<serde_json::Value>>()
            .await
            .expect("tx_info json")
    }

    // Does I1 appear as an input of the given tx?
    fn tx_spends_input(tx: &serde_json::Value, i1_hash_hex: &str, i1_index: u32) -> bool {
        tx.get("inputs")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|inputs| {
                inputs.iter().any(|inp| {
                    inp.get("tx_hash").and_then(serde_json::Value::as_str) == Some(i1_hash_hex)
                        && inp.get("tx_index").and_then(serde_json::Value::as_u64)
                            == Some(u64::from(i1_index))
                })
            })
    }

    // (a) TX1 itself: on chain at the expected block, spends EXACTLY I1, carries
    //     the Label 309 metadata payload.
    let tx1_info = tx_info_batch(&koios, &[hex::encode(tx1)]).await;
    assert_eq!(tx1_info.len(), 1, "Koios reports exactly one tx for TX1");
    let onchain_block = tx1_info[0]
        .get("block_height")
        .and_then(serde_json::Value::as_i64)
        .expect("block_height");
    assert_eq!(
        onchain_block, block_height,
        "TX1's Koios block height matches the confirmed coordinates"
    );
    let tx1_inputs = tx1_info[0]["inputs"].as_array().expect("TX1 inputs");
    assert_eq!(tx1_inputs.len(), 1, "TX1 spends exactly one input");
    assert!(
        tx_spends_input(&tx1_info[0], &i1_hash_hex, input_i1.output_index),
        "TX1's single input is I1"
    );
    assert!(
        tx1_info[0]["metadata"].get("309").is_some(),
        "TX1 carries the Label 309 metadata payload"
    );
    eprintln!("KOIOS PROOF: TX1 on chain at block={onchain_block}, spends I1, carries label 309");

    // (b) THE decisive independent check, with NO dependence on our DB: scan the
    //     funded wallet's ENTIRE recent transaction history and inspect every input.
    //     Exactly ONE transaction in the whole history spends I1, and it is TX1. If a
    //     second tx had been minted for this record, a second spender of I1 (a
    //     double-spend attempt the node would reject) or a second tx carrying this
    //     record's metadata would appear here; it does not.
    let addr_txs: Vec<serde_json::Value> = koios
        .post("https://preprod.koios.rest/api/v1/address_txs")
        .json(&serde_json::json!({
            "_addresses": [address], "_after_block_height": 4_700_000u64,
        }))
        .send()
        .await
        .expect("koios address_txs")
        .json()
        .await
        .expect("address_txs json");
    let wallet_tx_hashes: Vec<String> = addr_txs
        .iter()
        .filter_map(|t| t.get("tx_hash").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect();
    eprintln!(
        "scanning {} wallet txs since block 4700000 for spenders of I1",
        wallet_tx_hashes.len()
    );
    let mut i1_spenders: Vec<String> = Vec::new();
    for chunk in wallet_tx_hashes.chunks(25) {
        for tx in tx_info_batch(&koios, chunk).await {
            if tx_spends_input(&tx, &i1_hash_hex, input_i1.output_index) {
                if let Some(h) = tx.get("tx_hash").and_then(serde_json::Value::as_str) {
                    i1_spenders.push(h.to_string());
                }
            }
        }
    }
    i1_spenders.sort();
    i1_spenders.dedup();
    eprintln!("KOIOS PROOF: distinct txs spending I1 in wallet history: {i1_spenders:?}");
    assert_eq!(
        i1_spenders,
        vec![hex::encode(tx1)],
        "exactly ONE transaction spends I1, and it is TX1 (no second tx minted)"
    );

    eprintln!(
        "PASSED: one paid publish -> exactly ONE on-chain tx (TX1={}) spending I1, \
         under redelivery + crash window. One poe_publish debit. One chain_records row.",
        hex::encode(tx1)
    );
}
