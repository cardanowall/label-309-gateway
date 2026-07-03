//! Integration coverage for the orphaned-upload refund sweep.
//!
//! A sealed multi-file publish charges each ciphertext upload at upload time,
//! before the record is anchored. If a later upload fails and the composer aborts,
//! a retry re-wraps the content under a fresh key, so the ciphertext bytes (and the
//! sha256, and the dedup key) differ and the gateway charges a second upload. The
//! first charged upload is then referenced by no published record, with no reason
//! in the storage-refund vocabulary that would reverse it.
//!
//! `refund_orphaned_uploads` is the self-correcting backstop: past a grace window,
//! it credits the user's USD `storage_upload` charge back and emits the
//! operator-facing refund intent for a charged account upload that no record
//! references — both in one transaction per upload. These suites pin its
//! behaviours against real ledger/balance rows:
//!
//!   - a charged upload no record references, past the TTL, is refunded EXACTLY ONCE
//!     (balance credited by the charged amount, intent emitted, a second sweep a
//!     no-op);
//!   - a charged upload a published record DOES reference (in any status) is NEVER
//!     refunded — the bytes back a real record;
//!   - a charged upload still inside the grace window is NOT refunded (its publish
//!     may yet arrive);
//!   - an already-refunded upload is NOT double-refunded;
//!   - a legacy half-settlement (credit landed, intent missing) gets its intent
//!     backfilled exactly once, with no second credit;
//!   - settlement is all-or-nothing per upload: a contended row writes NOTHING
//!     (no credit, no intent, no event) until it can be settled whole.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use gateway_core::ledger::journal::{
    insert_ledger_entry, load_balance_micros, register_kind, LedgerEntry,
};
use gateway_core::storage::{
    refund_orphaned_uploads, StorageRefundReason, FUNDING_SOURCE_SUBJECT_KIND,
    STORAGE_REFUND_INTENT_EVENT_TYPE,
};
use gateway_core::testsupport::TestDb;
use uuid::Uuid;

/// The canonical backend the storage suites exercise (the Turbo rail).
const BACKEND: &str = "turbo";

/// The grace window the suites pass to the sweep. A representative value the
/// tests drive the sweep with directly; the production default is longer (a week,
/// to outlast a vendor's stuck-draft retry), but the behaviour under test — refund
/// past the window, spare inside it — is independent of the exact figure, so the
/// suites pin it at a day to keep the relative ages easy to read.
const GRACE_SECS: i64 = 24 * 60 * 60;

/// A batch larger than any suite's candidate set, so one pass drains it.
const BATCH: i64 = 1_000;

/// The charge each seeded upload carries, in micro-USD.
const CHARGE_MICROS: i64 = 5_000;

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

/// Fund an account with a vendor `topup` credit so it carries a known balance.
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

/// The data-item id a seeded upload resolves at: a 43-char base64url string, the
/// exact shape the storage backends mint (id = base64url(sha256(signature))). The
/// seed varies the first character so distinct uploads get distinct ids while the
/// length stays valid.
fn data_item_id(seed: u8) -> String {
    // 43 base64url characters: a leading seed-derived char then a fixed filler.
    let lead = (b'A' + (seed % 26)) as char;
    format!("{lead}bcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
}

/// The URI a seeded upload resolves at: `ar://<43-char-id>`, a real, well-formed
/// `ar://` URI of the exact shape the storage backends produce and the orphan
/// sweep's shape guard requires. A published record embeds this string verbatim as
/// a canonical-CBOR text string.
fn upload_uri(seed: u8) -> String {
    format!("ar://{}", data_item_id(seed))
}

/// Seed a committed attempt + its receipt row + the user's `storage_upload` debit,
/// returning the receipt (`storage_upload`) id and the attempt id. `age_secs` is
/// stamped on the receipt's `created_at` so a test can place the upload before or
/// inside the grace window. The debit is keyed on the attempt id, exactly as the
/// commit path writes it, so the refund credit on the same key nets it.
async fn seed_charged_upload(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    operator_id: Uuid,
    funding_source_id: Uuid,
    seed: u8,
    age_secs: i64,
) -> (Uuid, Uuid) {
    let attempt_id = Uuid::now_v7();
    let sha = vec![seed; 32];
    sqlx::query(
        "INSERT INTO cw_core.storage_upload_attempt \
           (id, account_id, operator_id, funding_source_id, backend, sha256, bytes, \
            chargeable_bytes, charged_usd_micros, settled_charge_usd_micros, estimated_winc, \
            data_item_id, state) \
         VALUES ($1, $2, $3, $4, $5, $6, 1024, 1024, $7, $7, 7, $8, 'committed')",
    )
    .bind(attempt_id)
    .bind(account_id)
    .bind(operator_id)
    .bind(funding_source_id)
    .bind(BACKEND)
    .bind(&sha)
    .bind(CHARGE_MICROS)
    .bind(data_item_id(seed))
    .execute(pool)
    .await
    .expect("seed attempt");

    let upload_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_upload \
           (id, account_id, sha256, bytes, uri, data_item_id, backend, \
            attempt_id, funding_source_id, charged_operator_id, chargeable_bytes, \
            charged_usd_micros, created_at) \
         VALUES ($1, $2, $3, 1024, $4, $5, $6, $7, $8, $9, 1024, $10, \
                 now() - make_interval(secs => $11::double precision))",
    )
    .bind(upload_id)
    .bind(account_id)
    .bind(&sha)
    .bind(upload_uri(seed))
    .bind(data_item_id(seed))
    .bind(BACKEND)
    .bind(attempt_id)
    .bind(funding_source_id)
    .bind(operator_id)
    .bind(CHARGE_MICROS)
    .bind(age_secs as f64)
    .execute(pool)
    .await
    .expect("seed receipt");

    // The user's USD storage debit the commit path wrote, keyed on the attempt id.
    insert_ledger_entry(
        pool,
        &LedgerEntry {
            account_id,
            kind: "storage_upload".to_string(),
            amount_micros: -CHARGE_MICROS,
            r#ref: Some(attempt_id.to_string()),
            quote_id: None,
            metadata: serde_json::json!({ "chargeable_bytes": 1024 }),
            request_id: None,
        },
    )
    .await
    .expect("seed storage debit");

    (upload_id, attempt_id)
}

/// Build the canonical-CBOR bytes of a real Label 309 record that references `uri`,
/// using the SAME encoder the publish path validates against. This is what proves
/// the orphan sweep's binding test against actual canonical CBOR rather than a
/// synthetic byte append: the record is a genuine `encode_poe_record` output, and
/// the function asserts the encoded bytes do in fact contain the `ar://` URI as a
/// UTF-8 substring — the exact relationship the sweep's `position(...)` test relies
/// on. A producer that ever encoded the URI in a form this substring match could
/// not find would fail here, before any sweep ran.
fn encoded_record_referencing(uri: &str) -> Vec<u8> {
    use cardanowall::poe_standard::{encode_poe_record, validate_poe_record};
    use cardanowall::poe_standard::{ItemEntry, PoeRecord, ValidatorOptions};

    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0x01; 32])],
            uris: Some(vec![uri.to_string()]),
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    let bytes = encode_poe_record(&record).expect("encode real record");

    // The record must be a structurally valid Label 309 record (the publish path
    // would reject anything else), and its canonical bytes must contain the URI as a
    // UTF-8 substring — the mechanism the sweep's binding test depends on.
    assert!(
        matches!(
            validate_poe_record(&bytes, &ValidatorOptions::default()),
            cardanowall::poe_standard::ValidateResult::Ok { .. }
        ),
        "the seeded record must validate as a real Label 309 record"
    );
    assert!(
        bytes.windows(uri.len()).any(|w| w == uri.as_bytes()),
        "the genuinely-encoded record bytes must contain the ar:// URI verbatim; \
         if this fails the canonical CBOR does not embed the URI as the sweep assumes"
    );
    bytes
}

/// Seed a `poe_record` whose `record_bytes` are the REAL canonical-CBOR encoding of
/// a record referencing `uri`, the content-addressed binding a published record
/// carries back to its upload. `status` lets a test prove the binding holds in any
/// record state.
async fn seed_record_referencing(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
    uri: &str,
    status: &str,
) {
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

    let record_bytes = encoded_record_referencing(uri);

    let record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, wallet_id, account_id, record_bytes, status, request_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(record_id)
    .bind(operator_id)
    .bind(wallet_id)
    .bind(account_id)
    .bind(record_bytes)
    .bind(status)
    .bind(format!("req-{record_id}"))
    .execute(pool)
    .await
    .expect("insert poe_record");
}

// ---------------------------------------------------------------------------
// Assertion helpers.
// ---------------------------------------------------------------------------

/// Sum the orphan refund credit (`kind = storage_refund`) keyed on an attempt id.
async fn refund_credit_micros(pool: &sqlx::PgPool, attempt_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_micros), 0)::bigint FROM cw_core.balance_ledger \
         WHERE kind = 'storage_refund' AND ref = $1",
    )
    .bind(attempt_id.to_string())
    .fetch_one(pool)
    .await
    .expect("sum refund credit")
}

/// Count `storage_refund` ledger rows for an attempt (the refund-once row count).
async fn refund_row_count(pool: &sqlx::PgPool, attempt_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger \
         WHERE kind = 'storage_refund' AND ref = $1",
    )
    .bind(attempt_id.to_string())
    .fetch_one(pool)
    .await
    .expect("count refund rows")
}

/// Count refund-intent rows for an upload (the durable single-emit row count).
async fn intent_count(pool: &sqlx::PgPool, upload_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_refund_intent WHERE storage_upload_id = $1",
    )
    .bind(upload_id)
    .fetch_one(pool)
    .await
    .expect("count intents")
}

/// Read the reason recorded on the single refund intent for an upload.
async fn intent_reason(pool: &sqlx::PgPool, upload_id: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT reason FROM cw_core.storage_refund_intent WHERE storage_upload_id = $1",
    )
    .bind(upload_id)
    .fetch_optional(pool)
    .await
    .expect("read reason")
}

/// Count refund-intent events on a funding source's operator-facing subject.
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

// ---------------------------------------------------------------------------
// (1) A charged orphan past the TTL is refunded exactly once.
// ---------------------------------------------------------------------------

/// A charged upload no record references, past the grace window, is refunded once:
/// the balance recovers exactly the charge, a single `storage_refund` row and a
/// single intent + event land, and a second sweep moves nothing.
#[tokio::test]
async fn an_aged_orphan_is_refunded_exactly_once() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    fund_account(&db.pool, account_id, 1_000_000).await;
    // Two days old: comfortably past the one-day grace window.
    let (upload_id, attempt_id) = seed_charged_upload(
        &db.pool,
        account_id,
        operator_id,
        source,
        0x01,
        2 * GRACE_SECS,
    )
    .await;

    let balance_before = load_balance_micros(&db.pool, account_id)
        .await
        .expect("balance before");
    assert_eq!(
        balance_before,
        1_000_000 - CHARGE_MICROS,
        "the account paid the storage charge"
    );

    let sweep = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("first sweep");
    assert_eq!(sweep.uploads_refunded, 1, "exactly one orphan refunded");
    assert_eq!(
        sweep.refunded_usd_micros, CHARGE_MICROS,
        "the sweep reports the credited amount"
    );

    // The balance recovered exactly the charge.
    assert_eq!(
        load_balance_micros(&db.pool, account_id)
            .await
            .expect("balance after"),
        balance_before + CHARGE_MICROS,
        "the orphaned charge was credited back in full"
    );
    assert_eq!(
        refund_credit_micros(&db.pool, attempt_id).await,
        CHARGE_MICROS,
        "the storage_refund credit equals the charge"
    );

    // The durable single-emit intent + its operator-facing event landed with the
    // orphaned reason.
    assert_eq!(intent_count(&db.pool, upload_id).await, 1);
    assert_eq!(
        intent_reason(&db.pool, upload_id).await.as_deref(),
        Some(StorageRefundReason::UploadOrphaned.as_str())
    );
    assert_eq!(refund_event_count(&db.pool, source).await, 1);

    // A second sweep is a pure no-op: the upload is already refunded, so it is no
    // longer a candidate, and even were it claimed the idempotency keys would absorb
    // the refund.
    let again = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("second sweep");
    assert_eq!(
        again.uploads_refunded, 0,
        "the second sweep refunds nothing"
    );
    assert_eq!(again.refunded_usd_micros, 0);
    assert_eq!(
        refund_row_count(&db.pool, attempt_id).await,
        1,
        "exactly one storage_refund row exists across both sweeps"
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id)
            .await
            .expect("balance after second"),
        balance_before + CHARGE_MICROS,
        "the second sweep moved no money"
    );
}

// ---------------------------------------------------------------------------
// (2) A charged upload a published record references is never refunded.
// ---------------------------------------------------------------------------

/// An aged charged upload whose URI a published record embeds is NOT an orphan:
/// the bytes back a real record (in any status), so the charge stands.
#[tokio::test]
async fn an_upload_a_record_references_is_not_refunded() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    fund_account(&db.pool, account_id, 1_000_000).await;
    let (upload_id, attempt_id) = seed_charged_upload(
        &db.pool,
        account_id,
        operator_id,
        source,
        0x02,
        2 * GRACE_SECS,
    )
    .await;

    // A confirmed record embeds this upload's URI: the binding holds, so the upload
    // is referenced and must not be refunded.
    seed_record_referencing(
        &db.pool,
        operator_id,
        account_id,
        &upload_uri(0x02),
        "confirmed",
    )
    .await;

    let balance_before = load_balance_micros(&db.pool, account_id)
        .await
        .expect("balance before");

    let sweep = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("sweep");
    assert_eq!(
        sweep.uploads_refunded, 0,
        "a referenced upload is never refunded"
    );
    assert_eq!(refund_row_count(&db.pool, attempt_id).await, 0);
    assert_eq!(intent_count(&db.pool, upload_id).await, 0);
    assert_eq!(
        load_balance_micros(&db.pool, account_id)
            .await
            .expect("balance after"),
        balance_before,
        "the charge stands; the balance is unchanged"
    );
}

/// The binding holds even for a record that LATER failed: a published-then-failed
/// record's bytes are permanently stored, so an upload it referenced keeps its
/// charge and is never swept as an orphan.
#[tokio::test]
async fn an_upload_a_failed_record_referenced_is_not_refunded() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    fund_account(&db.pool, account_id, 1_000_000).await;
    let (_upload_id, attempt_id) = seed_charged_upload(
        &db.pool,
        account_id,
        operator_id,
        source,
        0x03,
        2 * GRACE_SECS,
    )
    .await;

    seed_record_referencing(
        &db.pool,
        operator_id,
        account_id,
        &upload_uri(0x03),
        "permanent_failure",
    )
    .await;

    let sweep = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("sweep");
    assert_eq!(
        sweep.uploads_refunded, 0,
        "a published-then-failed record's upload keeps its charge"
    );
    assert_eq!(refund_row_count(&db.pool, attempt_id).await, 0);
}

/// The reference test is robust to URI SCHEME case. Label 309 case-folds only a
/// URI's scheme (RFC 3986 §3.1), so a valid record may reference the upload as
/// `AR://<id>` while the gateway minted the lowercase `ar://<id>`. The sweep keys
/// the reference test on the exact-case data-item id, not the full scheme-prefixed
/// URI, so it still detects the reference and does NOT refund the live upload.
/// (Reachable for third-party records on this multi-tenant index.)
#[tokio::test]
async fn an_upload_referenced_with_an_uppercase_scheme_is_not_refunded() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    fund_account(&db.pool, account_id, 1_000_000).await;
    let (_upload_id, attempt_id) = seed_charged_upload(
        &db.pool,
        account_id,
        operator_id,
        source,
        0x07,
        2 * GRACE_SECS,
    )
    .await;

    // The record references the SAME data-item id but with an UPPERCASE scheme, a
    // form Label 309 validates as a valid ar:// URI. The gateway stored 'ar://<id>';
    // the record carries 'AR://<id>'.
    let uppercase_uri = format!("AR://{}", data_item_id(0x07));
    assert_ne!(
        uppercase_uri,
        upload_uri(0x07),
        "the uppercase-scheme URI must differ from the stored lowercase one"
    );
    seed_record_referencing(
        &db.pool,
        operator_id,
        account_id,
        &uppercase_uri,
        "confirmed",
    )
    .await;

    let sweep = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("sweep");
    assert_eq!(
        sweep.uploads_refunded, 0,
        "a record referencing the upload with an uppercase scheme is still detected; \
         the live upload is not refunded"
    );
    assert_eq!(refund_row_count(&db.pool, attempt_id).await, 0);
}

// ---------------------------------------------------------------------------
// (3) A charged upload still inside the grace window is not refunded.
// ---------------------------------------------------------------------------

/// An unreferenced charged upload inside the grace window is NOT refunded: its
/// publish may still arrive, so the elapsed-time judgement is deferred.
#[tokio::test]
async fn an_upload_inside_the_grace_window_is_not_refunded() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    fund_account(&db.pool, account_id, 1_000_000).await;
    // One hour old: well inside the grace window the suite drives the sweep with.
    let (upload_id, attempt_id) =
        seed_charged_upload(&db.pool, account_id, operator_id, source, 0x04, 60 * 60).await;

    let balance_before = load_balance_micros(&db.pool, account_id)
        .await
        .expect("balance before");

    let sweep = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("sweep");
    assert_eq!(
        sweep.uploads_refunded, 0,
        "an upload inside the grace window is not yet an orphan"
    );
    assert_eq!(refund_row_count(&db.pool, attempt_id).await, 0);
    assert_eq!(intent_count(&db.pool, upload_id).await, 0);
    assert_eq!(
        load_balance_micros(&db.pool, account_id)
            .await
            .expect("balance after"),
        balance_before,
        "the in-window charge is left in place"
    );

    // Once the same upload ages past the window, the next sweep refunds it: the
    // window is the only thing that held it back.
    sqlx::query(
        "UPDATE cw_core.storage_upload \
         SET created_at = now() - make_interval(secs => $1::double precision) WHERE id = $2",
    )
    .bind((2 * GRACE_SECS) as f64)
    .bind(upload_id)
    .execute(&db.pool)
    .await
    .expect("age the upload");

    let aged = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("sweep after aging");
    assert_eq!(
        aged.uploads_refunded, 1,
        "once past the window the same upload is refunded"
    );
    assert_eq!(
        refund_credit_micros(&db.pool, attempt_id).await,
        CHARGE_MICROS
    );
}

// ---------------------------------------------------------------------------
// (4) An already-refunded upload is not double-refunded.
// ---------------------------------------------------------------------------

/// An upload that already carries a `storage_refund` credit on its attempt is not
/// refunded again, even with no intent row present: the cross-refund-kind `ref`
/// index makes the credit single-emit, and the candidate query already excludes a
/// refunded attempt. This pins the idempotency against a partial prior refund (the
/// credit landed, the intent did not), which a crash between the two could leave.
#[tokio::test]
async fn an_already_refunded_upload_is_not_double_refunded() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    fund_account(&db.pool, account_id, 1_000_000).await;
    let (_upload_id, attempt_id) = seed_charged_upload(
        &db.pool,
        account_id,
        operator_id,
        source,
        0x05,
        2 * GRACE_SECS,
    )
    .await;

    // Pre-existing refund credit on the attempt id (a prior sweep's, or a downstream
    // consumer's), with no intent row: the credit alone must block a second refund.
    insert_ledger_entry(
        &db.pool,
        &LedgerEntry {
            account_id,
            kind: "storage_refund".to_string(),
            amount_micros: CHARGE_MICROS,
            r#ref: Some(attempt_id.to_string()),
            quote_id: None,
            metadata: serde_json::json!({ "note": "prior refund" }),
            request_id: None,
        },
    )
    .await
    .expect("seed prior refund credit");

    let balance_before = load_balance_micros(&db.pool, account_id)
        .await
        .expect("balance before");

    let sweep = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("sweep");
    assert_eq!(
        sweep.uploads_refunded, 0,
        "an already-refunded upload is not refunded again"
    );
    assert_eq!(
        sweep.intents_backfilled, 0,
        "a foreign refund credit (no sweep stamp in its metadata) is never given \
         an invented intent by the repair scan"
    );
    assert_eq!(
        refund_row_count(&db.pool, attempt_id).await,
        1,
        "exactly the one prior storage_refund row exists; the sweep added none"
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id)
            .await
            .expect("balance after"),
        balance_before,
        "no second credit moved the balance"
    );
}

// ---------------------------------------------------------------------------
// (5) The URI shape guard: a short/malformed URI is never a refund candidate.
// ---------------------------------------------------------------------------

/// A charged, aged, unreferenced upload whose URI is too short / not `ar://`-shaped
/// is NOT refunded: the shape guard keeps a malformed URI out of the candidate set,
/// so it can never drive a coincidental substring match. After the URI is repaired
/// to a real `ar://<id>`, the next sweep refunds it — proving the guard, not some
/// other predicate, was what held it back.
#[tokio::test]
async fn a_malformed_uri_is_not_a_refund_candidate() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    fund_account(&db.pool, account_id, 1_000_000).await;
    // Aged well past the window, charged, and referenced by no record.
    let (upload_id, attempt_id) = seed_charged_upload(
        &db.pool,
        account_id,
        operator_id,
        source,
        0x06,
        2 * GRACE_SECS,
    )
    .await;

    // Corrupt the receipt's URI to a short, non-ar:// string. Everything else about
    // the row still qualifies it as an orphan; only the shape guard excludes it.
    sqlx::query("UPDATE cw_core.storage_upload SET uri = 'x' WHERE id = $1")
        .bind(upload_id)
        .execute(&db.pool)
        .await
        .expect("corrupt uri");

    let sweep = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("sweep");
    assert_eq!(
        sweep.uploads_refunded, 0,
        "a malformed URI is excluded by the shape guard"
    );
    assert_eq!(refund_row_count(&db.pool, attempt_id).await, 0);

    // Repair the URI to a real ar://<id> and the same row is now refunded: the shape
    // guard was the only thing keeping it out of the candidate set.
    sqlx::query("UPDATE cw_core.storage_upload SET uri = $1 WHERE id = $2")
        .bind(upload_uri(0x06))
        .bind(upload_id)
        .execute(&db.pool)
        .await
        .expect("repair uri");

    let repaired = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("sweep after repair");
    assert_eq!(
        repaired.uploads_refunded, 1,
        "with a well-formed ar:// URI the same upload is an orphan and is refunded"
    );
    assert_eq!(
        refund_credit_micros(&db.pool, attempt_id).await,
        CHARGE_MICROS
    );
}

// ---------------------------------------------------------------------------
// (6) A legacy half-settlement (credit landed, intent missing) is healed.
// ---------------------------------------------------------------------------

/// Before settlement became a single transaction, a crash between the USD credit
/// and the intent could leave an upload refunded with the operator's
/// `storage.refund-intent` signal dropped forever: the credit alone excludes the
/// upload from the candidate set, so no later sweep would revisit it. The sweep
/// now heals exactly that state — it emits the missing intent + billing event
/// once, credits nothing again, and a further run moves nothing.
#[tokio::test]
async fn a_legacy_half_settlement_gets_its_intent_backfilled() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    fund_account(&db.pool, account_id, 1_000_000).await;
    let (upload_id, attempt_id) = seed_charged_upload(
        &db.pool,
        account_id,
        operator_id,
        source,
        0x07,
        2 * GRACE_SECS,
    )
    .await;

    // The exact ledger credit the settlement writes — same kind, ref, and
    // metadata stamp — but with NO intent row: the durable state a crash between
    // the two writes of the old non-atomic sweep left behind.
    insert_ledger_entry(
        &db.pool,
        &LedgerEntry {
            account_id,
            kind: "storage_refund".to_string(),
            amount_micros: CHARGE_MICROS,
            r#ref: Some(attempt_id.to_string()),
            quote_id: None,
            metadata: serde_json::json!({
                "reason": "upload_orphaned",
                "storage_upload_id": upload_id,
                "reversed_kind": "storage_upload",
            }),
            request_id: None,
        },
    )
    .await
    .expect("seed the half-settlement credit");

    let balance_before = load_balance_micros(&db.pool, account_id)
        .await
        .expect("balance before");

    let sweep = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("healing sweep");
    assert_eq!(
        sweep.uploads_refunded, 0,
        "the credit already landed; the sweep must not refund again"
    );
    assert_eq!(
        sweep.intents_backfilled, 1,
        "the missing operator-facing intent is emitted"
    );
    assert_eq!(intent_count(&db.pool, upload_id).await, 1);
    assert_eq!(
        intent_reason(&db.pool, upload_id).await.as_deref(),
        Some(StorageRefundReason::UploadOrphaned.as_str())
    );
    assert_eq!(
        refund_event_count(&db.pool, source).await,
        1,
        "the billing event rides the backfilled intent"
    );
    assert_eq!(
        refund_row_count(&db.pool, attempt_id).await,
        1,
        "no second credit row"
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id)
            .await
            .expect("balance after"),
        balance_before,
        "healing the intent moves no money"
    );

    // Healed once, emitted once: a further run finds nothing to repair.
    let again = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("second sweep");
    assert_eq!(again.intents_backfilled, 0);
    assert_eq!(again.uploads_refunded, 0);
    assert_eq!(
        refund_event_count(&db.pool, source).await,
        1,
        "the billing event is never re-emitted"
    );

    // The drained run recorded its completion durably: later sweeps skip the
    // unindexed legacy scan outright instead of re-walking the refund credits
    // forever. (Settlement is atomic now, so no NEW half-settlement can arise
    // and the permanent skip is safe.)
    let completed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM cw_core.repair_completion WHERE repair = $1)",
    )
    .bind("orphan_refund_intent_backfill")
    .fetch_one(&db.pool)
    .await
    .expect("read the repair-completion marker");
    assert!(
        completed,
        "the backfill records its completion once the legacy set is drained"
    );
}

// ---------------------------------------------------------------------------
// (7) Settlement is all-or-nothing per upload: a contended row writes NOTHING.
// ---------------------------------------------------------------------------

/// The credit and the intent land in one transaction opened by a `FOR UPDATE
/// SKIP LOCKED` claim of the upload row. While another session holds that row —
/// as a concurrent replica's in-flight settlement would — the sweep settles
/// nothing for it: no credit, no intent, no event, no half-state. Released, the
/// next sweep settles it completely.
#[tokio::test]
async fn a_contended_candidate_is_skipped_whole_never_half_settled() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let source = register_source(&db.pool, operator_id).await;
    fund_account(&db.pool, account_id, 1_000_000).await;
    let (upload_id, attempt_id) = seed_charged_upload(
        &db.pool,
        account_id,
        operator_id,
        source,
        0x08,
        2 * GRACE_SECS,
    )
    .await;

    // A second session locks the upload row for the duration of the sweep.
    let mut holder = db.pool.begin().await.expect("open the holding txn");
    sqlx::query("SELECT 1 FROM cw_core.storage_upload WHERE id = $1 FOR UPDATE")
        .bind(upload_id)
        .execute(&mut *holder)
        .await
        .expect("hold the row lock");

    let contended = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("contended sweep");
    assert_eq!(
        contended.uploads_refunded, 0,
        "a locked candidate is skipped, not blocked on"
    );
    assert_eq!(
        refund_row_count(&db.pool, attempt_id).await,
        0,
        "no credit landed for the contended upload"
    );
    assert_eq!(
        intent_count(&db.pool, upload_id).await,
        0,
        "no intent landed for the contended upload"
    );
    assert_eq!(
        refund_event_count(&db.pool, source).await,
        0,
        "no billing event landed for the contended upload"
    );

    holder.rollback().await.expect("release the row lock");

    let settled = refund_orphaned_uploads(&db.pool, GRACE_SECS, BATCH)
        .await
        .expect("uncontended sweep");
    assert_eq!(
        settled.uploads_refunded, 1,
        "released, the same upload settles completely"
    );
    assert_eq!(
        refund_credit_micros(&db.pool, attempt_id).await,
        CHARGE_MICROS
    );
    assert_eq!(intent_count(&db.pool, upload_id).await, 1);
    assert_eq!(refund_event_count(&db.pool, source).await, 1);
}
