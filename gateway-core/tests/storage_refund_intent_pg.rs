//! Integration coverage for the storage-refund seam: the durable single-emit
//! `storage_refund_intent` writer and the asymmetry that a published-then-failed
//! record refunds network+service only, never storage.
//!
//! The engine never moves money on a refund. `record_storage_refund_intent` writes
//! one durable intent row (PK = the upload id) plus one outbox event a downstream
//! billing consumer applies as a `storage_refund` credit. These suites pin:
//!
//!   - SINGLE-EMIT by construction: two calls on one upload write exactly one intent
//!     and emit exactly one billing event; the second call is an idempotent no-op.
//!   - the billing event rides the operator-facing funding-source subject (not a
//!     customer's balance stream) and carries the attempt id the downstream credit
//!     nets on.
//!   - the ASYMMETRY: a publish that permanently fails writes a Cardano refund intent
//!     but no `storage_refund_intent`, so a published-then-failed upload keeps its
//!     storage charge (the bytes are permanently stored). This verifies the publish
//!     refund is network+service-only by construction.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use gateway_core::chain::confirm::{
    record_permanent_failure, RefundReason, REFUND_INTENT_EVENT_TYPE,
};
use gateway_core::ledger::journal::{
    insert_ledger_entry, load_balance_micros, register_kind, LedgerEntry,
};
use gateway_core::storage::{
    record_storage_refund_intent, StorageRefundOutcome, StorageRefundReason,
    FUNDING_SOURCE_SUBJECT_KIND, STORAGE_REFUND_INTENT_EVENT_TYPE,
};
use gateway_core::testsupport::TestDb;
use uuid::Uuid;

/// The canonical backend the storage suites exercise (the Turbo rail).
const BACKEND: &str = "turbo";

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// Seed an operator + account and return both ids.
async fn seed_account(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
    let operator_id = Uuid::now_v7();
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'test')")
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert operator");
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("insert account anchor");
    sqlx::query(
        "INSERT INTO cw_core.account_detail (account_id, operator_id, status) \
         VALUES ($1, $2, 'active')",
    )
    .bind(account_id)
    .bind(operator_id)
    .execute(pool)
    .await
    .expect("insert account detail");
    (operator_id, account_id)
}

/// Register a funding source owned by `owner` and return its id.
async fn register_source(pool: &sqlx::PgPool, owner: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'primary', $3, $4, 'key-00')",
    )
    .bind(id)
    .bind(owner)
    .bind(BACKEND)
    .bind(format!("ar-address-{id}"))
    .execute(pool)
    .await
    .expect("seed funding source");
    id
}

/// Seed a committed attempt + its receipt row, returning the receipt
/// (`storage_upload`) id and the attempt id. The receipt links back to the attempt
/// and the funding source, the two correlation keys the refund event carries.
async fn seed_committed_upload(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    operator_id: Uuid,
    funding_source_id: Uuid,
    seed: u8,
) -> (Uuid, Uuid) {
    let attempt_id = Uuid::now_v7();
    let sha = vec![seed; 32];
    sqlx::query(
        "INSERT INTO cw_core.storage_upload_attempt \
           (id, account_id, operator_id, funding_source_id, backend, sha256, bytes, \
            chargeable_bytes, charged_usd_micros, settled_charge_usd_micros, estimated_winc, \
            data_item_id, state) \
         VALUES ($1, $2, $3, $4, $5, $6, 1024, 1024, 5000, 5000, 7, $7, 'committed')",
    )
    .bind(attempt_id)
    .bind(account_id)
    .bind(operator_id)
    .bind(funding_source_id)
    .bind(BACKEND)
    .bind(&sha)
    .bind(format!("data-item-{seed:02x}"))
    .execute(pool)
    .await
    .expect("seed attempt");

    let upload_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_upload \
           (id, account_id, sha256, bytes, uri, data_item_id, backend, \
            attempt_id, funding_source_id, charged_operator_id, chargeable_bytes, charged_usd_micros) \
         VALUES ($1, $2, $3, 1024, $4, $5, $6, $7, $8, $9, 1024, 5000)",
    )
    .bind(upload_id)
    .bind(account_id)
    .bind(&sha)
    .bind(format!("ar://data-item-{seed:02x}"))
    .bind(format!("data-item-{seed:02x}"))
    .bind(BACKEND)
    .bind(attempt_id)
    .bind(funding_source_id)
    .bind(operator_id)
    .execute(pool)
    .await
    .expect("seed receipt");

    (upload_id, attempt_id)
}

// ---------------------------------------------------------------------------
// Assertion helpers.
// ---------------------------------------------------------------------------

async fn intent_count(pool: &sqlx::PgPool, upload_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_refund_intent WHERE storage_upload_id = $1",
    )
    .bind(upload_id)
    .fetch_one(pool)
    .await
    .expect("count intents")
}

async fn intent_reason(pool: &sqlx::PgPool, upload_id: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT reason FROM cw_core.storage_refund_intent WHERE storage_upload_id = $1",
    )
    .bind(upload_id)
    .fetch_optional(pool)
    .await
    .expect("read reason")
}

/// Count the refund-intent events on the funding source's operator-facing subject.
async fn refund_event_count(pool: &sqlx::PgPool, funding_source_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = $1 AND subject_id = $2 AND event_type = $3",
    )
    .bind(FUNDING_SOURCE_SUBJECT_KIND)
    .bind(funding_source_id.to_string())
    .bind(STORAGE_REFUND_INTENT_EVENT_TYPE)
    .fetch_one(pool)
    .await
    .expect("count events")
}

/// Read the single refund-intent event payload on the funding source's subject.
async fn refund_event_payload(pool: &sqlx::PgPool, funding_source_id: Uuid) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT payload FROM cw_core.subject_event \
         WHERE subject_kind = $1 AND subject_id = $2 AND event_type = $3",
    )
    .bind(FUNDING_SOURCE_SUBJECT_KIND)
    .bind(funding_source_id.to_string())
    .bind(STORAGE_REFUND_INTENT_EVENT_TYPE)
    .fetch_one(pool)
    .await
    .expect("read payload")
}

async fn cardano_refund_intent_count(pool: &sqlx::PgPool, record_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.refund_intent WHERE record_id = $1")
        .bind(record_id)
        .fetch_one(pool)
        .await
        .expect("count cardano intents")
}

async fn total_storage_refund_intents(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_refund_intent")
        .fetch_one(pool)
        .await
        .expect("count all storage intents")
}

/// Seed a `submitting` PoE record owned by `account_id`, returning its id. The
/// account ownership is what links the auto-refund credit back to the right balance.
async fn seed_record_for_account(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
) -> (Uuid, Uuid) {
    let wallet_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet (id, registrar_operator_id, label, address, network) \
         VALUES ($1, $2, 'w', $3, 'preprod')",
    )
    .bind(wallet_id)
    .bind(operator_id)
    .bind(format!("addr_test_{wallet_id}"))
    .execute(pool)
    .await
    .expect("insert wallet");

    let record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, wallet_id, account_id, record_bytes, status, request_id) \
         VALUES ($1, $2, $3, $4, $5, 'submitting', $6)",
    )
    .bind(record_id)
    .bind(operator_id)
    .bind(wallet_id)
    .bind(account_id)
    .bind(vec![0xa1u8; 16])
    .bind(format!("req-{record_id}"))
    .execute(pool)
    .await
    .expect("insert poe_record");
    (record_id, wallet_id)
}

/// Fund an account with a vendor `topup` credit so a publish debit does not overdraw.
async fn fund_account(pool: &sqlx::PgPool, account_id: Uuid, micros: i64) {
    register_kind(pool, "topup", false, "vendor")
        .await
        .expect("register topup");
    insert_ledger_entry(
        pool,
        &LedgerEntry {
            account_id,
            kind: "topup".to_string(),
            amount_micros: micros,
            r#ref: Some(format!("fund-{account_id}")),
            quote_id: None,
            metadata: serde_json::json!({}),
            request_id: None,
        },
    )
    .await
    .expect("fund account");
}

/// Write the network+service publish debit the publish route would have written for
/// `record_id` (`kind = poe_publish`, `ref = record id`, signed negative).
async fn seed_publish_debit(pool: &sqlx::PgPool, account_id: Uuid, record_id: Uuid, micros: i64) {
    insert_ledger_entry(
        pool,
        &LedgerEntry {
            account_id,
            kind: "poe_publish".to_string(),
            amount_micros: -micros,
            r#ref: Some(record_id.to_string()),
            quote_id: None,
            metadata: serde_json::json!({}),
            request_id: None,
        },
    )
    .await
    .expect("seed publish debit");
}

/// Write a separate storage debit (`kind = storage_upload`) keyed on an upload, the
/// charge the publish-failure refund must NEVER reverse (the bytes are on Arweave).
async fn seed_storage_debit(pool: &sqlx::PgPool, account_id: Uuid, micros: i64) {
    insert_ledger_entry(
        pool,
        &LedgerEntry {
            account_id,
            kind: "storage_upload".to_string(),
            amount_micros: -micros,
            r#ref: Some(format!("upload-{account_id}")),
            quote_id: None,
            metadata: serde_json::json!({}),
            request_id: None,
        },
    )
    .await
    .expect("seed storage debit");
}

/// Sum the auto-refund credit (`kind = refund_rollback`) the engine wrote for a
/// record, in micro-USD (positive).
async fn publish_refund_credit_micros(pool: &sqlx::PgPool, record_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_micros), 0)::bigint FROM cw_core.balance_ledger \
         WHERE kind = 'refund_rollback' AND ref = $1",
    )
    .bind(record_id.to_string())
    .fetch_one(pool)
    .await
    .expect("sum refund credit")
}

/// Read the single `poe.refund-intent` event payload on the record's subject.
async fn cardano_refund_event_payload(pool: &sqlx::PgPool, record_id: Uuid) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT payload FROM cw_core.subject_event \
         WHERE subject_kind = 'poe_record' AND subject_id = $1 AND event_type = $2",
    )
    .bind(record_id.to_string())
    .bind(REFUND_INTENT_EVENT_TYPE)
    .fetch_one(pool)
    .await
    .expect("read refund-intent payload")
}

// ---------------------------------------------------------------------------
// Single-emit + the billing event.
// ---------------------------------------------------------------------------

/// An uncommitted-or-overcharge upload writes exactly one intent + one event, and a
/// second converging call is an idempotent no-op that never re-emits.
#[tokio::test]
async fn an_upload_refund_is_single_emit() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    let (upload_id, attempt_id) =
        seed_committed_upload(&db.pool, account_id, operator_id, source, 0x01).await;

    let first = record_storage_refund_intent(
        &db.pool,
        upload_id,
        StorageRefundReason::OverchargeReplay,
        &serde_json::json!({ "note": "duplicate charge" }),
    )
    .await
    .expect("first refund");
    assert_eq!(
        first,
        StorageRefundOutcome::Recorded,
        "the first call owns it"
    );

    // A second call (a converging path, a crash replay) writes nothing more.
    let second = record_storage_refund_intent(
        &db.pool,
        upload_id,
        StorageRefundReason::OverchargeReplay,
        &serde_json::json!({ "note": "duplicate charge" }),
    )
    .await
    .expect("second refund");
    assert_eq!(
        second,
        StorageRefundOutcome::AlreadyRecorded,
        "the second call is an idempotent no-op"
    );

    assert_eq!(
        intent_count(&db.pool, upload_id).await,
        1,
        "exactly one intent row exists"
    );
    assert_eq!(
        intent_reason(&db.pool, upload_id).await.as_deref(),
        Some("overcharge_replay")
    );
    assert_eq!(
        refund_event_count(&db.pool, source).await,
        1,
        "exactly one billing event was emitted, not two"
    );

    // The event rides the funding-source subject and carries the attempt id the
    // downstream storage_refund credit nets on.
    let payload = refund_event_payload(&db.pool, source).await;
    assert_eq!(payload["attempt_id"], serde_json::json!(attempt_id));
    assert_eq!(payload["funding_source_id"], serde_json::json!(source));
    assert_eq!(payload["reason"], serde_json::json!("overcharge_replay"));
}

/// Single-emit holds across two DISTINCT reasons converging on one upload: the first
/// reason wins the PK and the second call neither overwrites the reason nor emits a
/// second event.
#[tokio::test]
async fn the_first_reason_wins_the_single_intent() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    let (upload_id, _attempt_id) =
        seed_committed_upload(&db.pool, account_id, operator_id, source, 0x02).await;

    let first = record_storage_refund_intent(
        &db.pool,
        upload_id,
        StorageRefundReason::UploadUncommitted,
        &serde_json::json!({}),
    )
    .await
    .expect("first refund");
    assert_eq!(first, StorageRefundOutcome::Recorded);

    let second = record_storage_refund_intent(
        &db.pool,
        upload_id,
        StorageRefundReason::OverchargeReplay,
        &serde_json::json!({}),
    )
    .await
    .expect("second refund");
    assert_eq!(second, StorageRefundOutcome::AlreadyRecorded);

    assert_eq!(intent_count(&db.pool, upload_id).await, 1);
    assert_eq!(
        intent_reason(&db.pool, upload_id).await.as_deref(),
        Some("upload_uncommitted"),
        "the first reason is preserved; the second is a no-op"
    );
    assert_eq!(refund_event_count(&db.pool, source).await, 1);
}

// ---------------------------------------------------------------------------
// The asymmetry: a published-then-failed record refunds storage NEVER.
// ---------------------------------------------------------------------------

/// A publish that permanently fails writes a Cardano refund intent (network+service)
/// but no storage refund intent: the upload's bytes are permanently stored and the
/// storage charge is preserved. This verifies the publish refund is
/// network+service-only by construction.
#[tokio::test]
async fn a_published_then_failed_record_emits_no_storage_refund() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, _account_id) = seed_account(&db.pool).await;
    let wallet_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet (id, registrar_operator_id, label, address, network) \
         VALUES ($1, $2, 'w', $3, 'preprod')",
    )
    .bind(wallet_id)
    .bind(operator_id)
    .bind(format!("addr_test_{wallet_id}"))
    .execute(&db.pool)
    .await
    .expect("insert wallet");

    let record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, wallet_id, record_bytes, status, request_id) \
         VALUES ($1, $2, $3, $4, 'submitting', $5)",
    )
    .bind(record_id)
    .bind(operator_id)
    .bind(wallet_id)
    .bind(vec![0xa1u8; 16])
    .bind(format!("req-{record_id}"))
    .execute(&db.pool)
    .await
    .expect("insert poe_record");

    // The Cardano publish-failure refund path.
    let owned = record_permanent_failure(
        &db.pool,
        record_id,
        RefundReason::RollbackRetriesExhausted,
        &serde_json::json!({}),
    )
    .await
    .expect("permanent failure");
    assert!(owned, "this call owns the publish refund");

    // The publish refund happened (network+service)...
    assert_eq!(
        cardano_refund_intent_count(&db.pool, record_id).await,
        1,
        "the network+service publish refund intent exists"
    );
    // ...but no storage refund was emitted: the storage charge is preserved because
    // the bytes are permanently stored.
    assert_eq!(
        total_storage_refund_intents(&db.pool).await,
        0,
        "a published-then-failed record never refunds storage"
    );
}

// ---------------------------------------------------------------------------
// The auto-refund: a permanent failure credits the network+service publish debit
// back to the account itself, idempotently, storage excluded.
// ---------------------------------------------------------------------------

/// A permanent publish failure auto-credits the exact network+service publish debit
/// back to `cw_core.balance`, carries the amount on the `poe.refund-intent` event,
/// is idempotent across a re-run, and never reverses the separate storage charge.
#[tokio::test]
async fn a_permanent_failure_auto_credits_the_publish_debit_storage_excluded() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let (record_id, _wallet_id) = seed_record_for_account(&db.pool, operator_id, account_id).await;

    // Fund the account, then write the publish debit (network+service) and a SEPARATE
    // storage debit (the upload charge that is sunk once the bytes are on Arweave).
    let publish_micros: i64 = 7_000_000;
    let storage_micros: i64 = 3_000_000;
    fund_account(&db.pool, account_id, 20_000_000).await;
    seed_publish_debit(&db.pool, account_id, record_id, publish_micros).await;
    seed_storage_debit(&db.pool, account_id, storage_micros).await;

    let balance_before = load_balance_micros(&db.pool, account_id)
        .await
        .expect("balance before");
    assert_eq!(
        balance_before,
        20_000_000 - publish_micros - storage_micros,
        "the account paid both the publish and the storage charge"
    );

    // Drive the record to permanent failure.
    let owned = record_permanent_failure(
        &db.pool,
        record_id,
        RefundReason::RollbackRetriesExhausted,
        &serde_json::json!({ "reason": "rollback_retries_exhausted" }),
    )
    .await
    .expect("permanent failure");
    assert!(owned, "this call owns the refund");

    // (a) The balance was credited by exactly the publish debit (network+service);
    // the storage charge is untouched.
    assert_eq!(
        publish_refund_credit_micros(&db.pool, record_id).await,
        publish_micros,
        "the auto-refund credit equals the network+service publish debit"
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id)
            .await
            .expect("balance after"),
        balance_before + publish_micros,
        "the balance recovered exactly the publish charge, storage still spent"
    );

    // (c) The refund-intent event carries the auto-credited amount so the operator
    // can display it without summing the ledger.
    let payload = cardano_refund_event_payload(&db.pool, record_id).await;
    assert_eq!(
        payload["refund_usd_micros"],
        serde_json::json!(publish_micros),
        "the refund-intent event carries the credited amount"
    );

    // (d) No storage refund: the bytes are permanently on Arweave.
    assert_eq!(
        total_storage_refund_intents(&db.pool).await,
        0,
        "the publish-failure refund never reverses a storage charge"
    );
}

/// Re-running the permanent-failure path nets exactly ONE refund credit: the first
/// run owns the flip and writes the credit; a converging or replayed run finds the
/// record already terminal (or collides on the (kind, ref) idempotency index) and
/// adds nothing.
#[tokio::test]
async fn the_auto_refund_credit_is_idempotent() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let (record_id, _wallet_id) = seed_record_for_account(&db.pool, operator_id, account_id).await;

    let publish_micros: i64 = 4_500_000;
    fund_account(&db.pool, account_id, 10_000_000).await;
    seed_publish_debit(&db.pool, account_id, record_id, publish_micros).await;

    // First run owns the refund.
    let first = record_permanent_failure(
        &db.pool,
        record_id,
        RefundReason::RollbackRetriesExhausted,
        &serde_json::json!({}),
    )
    .await
    .expect("first permanent failure");
    assert!(first, "the first run owns the flip and the credit");

    let balance_after_first = load_balance_micros(&db.pool, account_id)
        .await
        .expect("balance after first");

    // A second converging run (the record is already terminal) writes nothing more.
    let second = record_permanent_failure(
        &db.pool,
        record_id,
        RefundReason::NodeRejected,
        &serde_json::json!({}),
    )
    .await
    .expect("second permanent failure");
    assert!(
        !second,
        "a converging run does not re-own a terminated record"
    );

    // Exactly one credit, exactly one credit's worth of balance recovery.
    assert_eq!(
        publish_refund_credit_micros(&db.pool, record_id).await,
        publish_micros,
        "two runs net exactly one refund credit"
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id)
            .await
            .expect("balance after second"),
        balance_after_first,
        "the second run moved no money"
    );
    let credit_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger \
         WHERE kind = 'refund_rollback' AND ref = $1",
    )
    .bind(record_id.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("count credit rows");
    assert_eq!(credit_rows, 1, "exactly one refund_rollback row exists");
}

/// A record with NO publish debit (an operator-direct / free-window / deduped
/// publish that was never billed) is credited nothing: the refund intent and the
/// terminal flip still happen, but the auto-refund skips cleanly and the event
/// reports a zero amount.
#[tokio::test]
async fn a_record_with_no_publish_debit_credits_nothing() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let (record_id, _wallet_id) = seed_record_for_account(&db.pool, operator_id, account_id).await;

    let owned = record_permanent_failure(
        &db.pool,
        record_id,
        RefundReason::TxBuildFailed,
        &serde_json::json!({ "reason": "tx_build_failed" }),
    )
    .await
    .expect("permanent failure");
    assert!(owned, "the flip and the intent still happen");

    assert_eq!(
        cardano_refund_intent_count(&db.pool, record_id).await,
        1,
        "the durable refund intent is still written"
    );
    assert_eq!(
        publish_refund_credit_micros(&db.pool, record_id).await,
        0,
        "no publish debit means no auto-refund credit"
    );
    let payload = cardano_refund_event_payload(&db.pool, record_id).await;
    assert_eq!(
        payload["refund_usd_micros"],
        serde_json::json!(0),
        "the event reports a zero refund when nothing was billed"
    );
}
