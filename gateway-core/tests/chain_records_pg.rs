//! Integration coverage for the chain-records / PoE-record schema.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! These assert the schema behaviour the submit and confirm paths rely on: the
//! migration applies cleanly, the `poe_record.status` CHECK rejects
//! an out-of-range status, the `refund_intent` primary key enforces single-refund
//! by construction, the `chain_records` primary key rejects a duplicate
//! transaction (the one-row-per-tx invariant the single writer leans on), the
//! `chain_records.scheme` CHECK pins the legal scheme set, and the `cardano_tip`
//! upsert is monotonic.

#![cfg(feature = "pg-tests")]

use gateway_core::testsupport::TestDb;
use sqlx::Row;
use uuid::Uuid;

/// Seed an operator and return its id, so foreign-key-bearing rows can be
/// inserted directly in SQL.
async fn seed_operator(pool: &sqlx::PgPool) -> Uuid {
    let operator_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(operator_id)
        .bind("test-operator")
        .execute(pool)
        .await
        .expect("insert operator");
    operator_id
}

/// Insert a draft poe_record under an operator and return its id.
async fn seed_record(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record (id, operator_id, record_bytes) VALUES ($1, $2, $3)",
    )
    .bind(record_id)
    .bind(operator_id)
    .bind(vec![0xa1_u8, 0x01, 0x82])
    .execute(pool)
    .await
    .expect("insert poe_record");
    record_id
}

/// The migration applies cleanly: a query against each new
/// table succeeds on a freshly migrated database, and each starts empty.
#[tokio::test]
async fn migration_creates_the_chain_record_tables() {
    let db = TestDb::fresh().await.expect("test database");

    for table in [
        "poe_record",
        "chain_records",
        "cardano_tip",
        "chain_provider_cooldown",
        "refund_intent",
    ] {
        let sql = format!("SELECT count(*) FROM cw_core.{table}");
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&db.pool)
            .await
            .unwrap_or_else(|e| panic!("querying cw_core.{table} should succeed: {e}"));
        assert_eq!(count, 0, "a fresh {table} starts empty");
    }
}

/// The poe_record default status is `draft`, and the CHECK rejects a status
/// outside the legal set.
#[tokio::test]
async fn poe_record_status_check_enforces_the_legal_set() {
    let db = TestDb::fresh().await.expect("test database");
    let operator_id = seed_operator(&db.pool).await;
    let record_id = seed_record(&db.pool, operator_id).await;

    // The seeded row defaults to 'draft'.
    let status: String = sqlx::query_scalar("SELECT status FROM cw_core.poe_record WHERE id = $1")
        .bind(record_id)
        .fetch_one(&db.pool)
        .await
        .expect("read status");
    assert_eq!(status, "draft", "a new poe_record defaults to draft");

    // Every legal transition target is accepted.
    for status in ["submitting", "submitted", "confirmed", "permanent_failure"] {
        sqlx::query("UPDATE cw_core.poe_record SET status = $2 WHERE id = $1")
            .bind(record_id)
            .bind(status)
            .execute(&db.pool)
            .await
            .unwrap_or_else(|e| panic!("status {status} must be accepted: {e}"));
    }

    // An out-of-range status is rejected by the CHECK constraint.
    let err = sqlx::query("UPDATE cw_core.poe_record SET status = $2 WHERE id = $1")
        .bind(record_id)
        .bind("teleported")
        .execute(&db.pool)
        .await
        .expect_err("an illegal status must be rejected by the CHECK");
    assert!(
        is_check_violation(&err),
        "expected a CHECK violation, got {err:?}"
    );
}

/// The refund_intent primary key makes single-refund a by-construction property:
/// a second intent for the same record collides, and `ON CONFLICT DO NOTHING`
/// folds it into a no-op so the first refund is preserved.
#[tokio::test]
async fn refund_intent_primary_key_enforces_single_refund() {
    let db = TestDb::fresh().await.expect("test database");
    let operator_id = seed_operator(&db.pool).await;
    let record_id = seed_record(&db.pool, operator_id).await;

    // The first refund intent lands (a submit-side build failure at the final
    // attempt).
    let inserted = sqlx::query(
        "INSERT INTO cw_core.refund_intent (record_id, reason, detail) \
         VALUES ($1, 'tx_build_failed', '{\"attempt\": 5}'::jsonb) \
         ON CONFLICT (record_id) DO NOTHING",
    )
    .bind(record_id)
    .execute(&db.pool)
    .await
    .expect("first refund intent")
    .rows_affected();
    assert_eq!(inserted, 1, "the first refund intent is inserted");

    // A second terminal arm (a different reason) hitting the same record is a
    // no-op: single-refund holds even when submit and confirm both terminate it.
    let second = sqlx::query(
        "INSERT INTO cw_core.refund_intent (record_id, reason, detail) \
         VALUES ($1, 'rollback_retries_exhausted', '{}'::jsonb) \
         ON CONFLICT (record_id) DO NOTHING",
    )
    .bind(record_id)
    .execute(&db.pool)
    .await
    .expect("second refund attempt")
    .rows_affected();
    assert_eq!(second, 0, "a second refund intent is folded into a no-op");

    // The preserved intent is the first one's reason, not the second's.
    let reason: String =
        sqlx::query_scalar("SELECT reason FROM cw_core.refund_intent WHERE record_id = $1")
            .bind(record_id)
            .fetch_one(&db.pool)
            .await
            .expect("read reason");
    assert_eq!(
        reason, "tx_build_failed",
        "the first refund intent wins; the conflict never overwrites it"
    );

    // A bare INSERT without the conflict clause raises a unique violation, the
    // mechanism the no-op relies on.
    let dup = sqlx::query(
        "INSERT INTO cw_core.refund_intent (record_id, reason) VALUES ($1, 'rollback_retries_exhausted')",
    )
    .bind(record_id)
    .execute(&db.pool)
    .await
    .expect_err("a duplicate refund intent must violate the primary key");
    assert!(
        is_unique_violation(&dup),
        "expected a unique violation, got {dup:?}"
    );
}

/// The chain_records primary key rejects a second row for the same transaction,
/// the one-row-per-tx invariant the single writer's `ON CONFLICT (tx_hash) DO
/// NOTHING` leans on, and the scheme CHECK pins the legal scheme set.
#[tokio::test]
async fn chain_records_primary_key_and_scheme_check_hold() {
    let db = TestDb::fresh().await.expect("test database");
    let tx_hash = vec![0x11_u8; 32];

    // chain_records.tx_hash FK-references the cw_api.records anchor, so the anchor
    // for every transaction this test inserts must exist first. The single writer
    // creates the anchor in the same statement; here we seed it directly so the
    // raw-SQL constraint inserts below reach the PK/CHECK they exercise rather
    // than tripping the foreign key.
    for hash in [vec![0x11_u8; 32], vec![0x22_u8; 32]] {
        sqlx::query("INSERT INTO cw_api.records (tx_hash) VALUES ($1)")
            .bind(hash)
            .execute(&db.pool)
            .await
            .expect("seed record anchor");
    }

    let insert = |scheme: i16, hash: Vec<u8>| {
        let pool = db.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO cw_core.chain_records \
                   (tx_hash, block_height, block_time, metadata_cbor, item_count, scheme) \
                 VALUES ($1, 100, now(), $2, 1, $3)",
            )
            .bind(hash)
            .bind(vec![0xa1_u8])
            .bind(scheme)
            .execute(&pool)
            .await
        }
    };

    // First insert lands.
    insert(0, tx_hash.clone())
        .await
        .expect("first chain_records row");

    // A second row for the same tx_hash collides on the primary key.
    let dup = insert(1, tx_hash.clone())
        .await
        .expect_err("a duplicate tx_hash must violate the primary key");
    assert!(
        is_unique_violation(&dup),
        "expected a unique violation, got {dup:?}"
    );

    // The same INSERT under ON CONFLICT DO NOTHING is the single writer's
    // idempotent no-op.
    let folded = sqlx::query(
        "INSERT INTO cw_core.chain_records \
           (tx_hash, block_height, block_time, metadata_cbor, item_count, scheme) \
         VALUES ($1, 100, now(), $2, 1, 1) ON CONFLICT (tx_hash) DO NOTHING",
    )
    .bind(tx_hash)
    .bind(vec![0xa1_u8])
    .execute(&db.pool)
    .await
    .expect("conflict-do-nothing insert")
    .rows_affected();
    assert_eq!(folded, 0, "a re-observed transaction is a no-op");

    // An out-of-range scheme is rejected by the CHECK.
    let bad_scheme = insert(7, vec![0x22_u8; 32])
        .await
        .expect_err("scheme 7 must be rejected by the CHECK");
    assert!(
        is_check_violation(&bad_scheme),
        "expected a CHECK violation, got {bad_scheme:?}"
    );
}

/// The cardano_tip upsert is monotonic via GREATEST: a higher tip advances the
/// row, a lower observation never regresses it.
#[tokio::test]
async fn cardano_tip_upsert_is_monotonic() {
    let db = TestDb::fresh().await.expect("test database");

    let upsert = |height: i64| {
        let pool = db.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO cw_core.cardano_tip (network, tip_block_height) \
                 VALUES ('preprod', $1) \
                 ON CONFLICT (network) DO UPDATE SET \
                   tip_block_height = GREATEST(cw_core.cardano_tip.tip_block_height, EXCLUDED.tip_block_height), \
                   tip_observed_at = now()",
            )
            .bind(height)
            .execute(&pool)
            .await
            .expect("tip upsert");
        }
    };

    upsert(100).await;
    upsert(150).await;
    let after_advance: i64 = sqlx::query_scalar(
        "SELECT tip_block_height FROM cw_core.cardano_tip WHERE network = 'preprod'",
    )
    .fetch_one(&db.pool)
    .await
    .expect("read tip");
    assert_eq!(after_advance, 150, "a higher observation advances the tip");

    // A behind-the-times observation must not regress the tip.
    upsert(120).await;
    let after_regress_attempt: i64 = sqlx::query_scalar(
        "SELECT tip_block_height FROM cw_core.cardano_tip WHERE network = 'preprod'",
    )
    .fetch_one(&db.pool)
    .await
    .expect("read tip");
    assert_eq!(
        after_regress_attempt, 150,
        "a lower observation never regresses the tip (GREATEST)"
    );
}

/// A minimal valid open Label 309 record's metadata CBOR, so the single writer's
/// column derivation accepts it rather than rejecting malformed bytes.
fn open_record_bytes() -> Vec<u8> {
    use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};
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

/// Read the stored block height for a transaction, or `None` when no row exists.
async fn stored_block_height(pool: &sqlx::PgPool, tx_hash: [u8; 32]) -> Option<i64> {
    sqlx::query_scalar("SELECT block_height FROM cw_core.chain_records WHERE tx_hash = $1")
        .bind(tx_hash.to_vec())
        .fetch_optional(pool)
        .await
        .expect("read block height")
}

/// A re-fired index job for a transaction re-included at a NEW height UPDATEs the
/// stored coordinates instead of no-oping: the index never serves a stale height
/// for a re-included transaction. A re-observation at the SAME height is a true
/// no-op (the `IS DISTINCT FROM` filter affects no row), so a benign redelivery
/// neither rewrites nor reports a write.
#[tokio::test]
async fn job_path_repins_block_height_on_a_new_height_reinclusion() {
    let db = TestDb::fresh().await.expect("test database");
    let tx_hash = [0x31_u8; 32];
    let bytes = open_record_bytes();
    let columns = gateway_core::chain::records::derive_chain_record_columns(
        &bytes,
        gateway_core::chain::params::Network::Preprod,
    )
    .expect("derive columns");

    // First observation at height 100 inserts the row.
    let inserted = gateway_core::chain::records::insert_chain_record(
        &db.pool,
        tx_hash,
        100,
        chrono::Utc::now(),
        &bytes,
        &columns,
    )
    .await
    .expect("first insert");
    assert!(inserted, "the first observation inserts a new row");
    assert_eq!(
        stored_block_height(&db.pool, tx_hash).await,
        Some(100),
        "the row carries the first observed height"
    );

    // A re-fired job for the same transaction re-included at height 175 re-pins
    // the coordinates rather than no-oping.
    let repinned = gateway_core::chain::records::insert_chain_record(
        &db.pool,
        tx_hash,
        175,
        chrono::Utc::now(),
        &bytes,
        &columns,
    )
    .await
    .expect("re-pin insert");
    assert!(repinned, "a new-height re-inclusion reports a write");
    assert_eq!(
        stored_block_height(&db.pool, tx_hash).await,
        Some(175),
        "the stored height advances to the re-included height, not the stale one"
    );

    // A redelivery at the SAME (now-current) height is a true no-op: it affects
    // no row and reports no write.
    let same_height = gateway_core::chain::records::insert_chain_record(
        &db.pool,
        tx_hash,
        175,
        chrono::Utc::now(),
        &bytes,
        &columns,
    )
    .await
    .expect("same-height re-observation");
    assert!(
        !same_height,
        "a same-height re-observation is a no-op (no row affected)"
    );
    assert_eq!(
        stored_block_height(&db.pool, tx_hash).await,
        Some(175),
        "the stored height is unchanged by a same-height re-observation"
    );

    // Exactly one row exists for the transaction throughout: the conflict
    // converged it, never forked a second row.
    let row_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.chain_records WHERE tx_hash = $1")
            .bind(tx_hash.to_vec())
            .fetch_one(&db.pool)
            .await
            .expect("count rows");
    assert_eq!(row_count, 1, "the transaction has exactly one indexed row");
}

/// The scan-path writer re-pins the coordinates on a new-height re-observation
/// that does not cross the reorg rewind boundary, while still backfilling a
/// missing `tx_cbor` and never clobbering bytes already stored.
#[tokio::test]
async fn scan_path_repins_block_height_and_backfills_cbor() {
    let db = TestDb::fresh().await.expect("test database");
    let tx_hash = [0x32_u8; 32];
    let bytes = open_record_bytes();
    let columns = gateway_core::chain::records::derive_chain_record_columns(
        &bytes,
        gateway_core::chain::params::Network::Preprod,
    )
    .expect("derive columns");

    // The in-tx writer runs two statements (the rich row and its signer-set
    // fan-out) on one connection, so acquire a single connection and reuse it for
    // every observation, exactly as the scan's write transaction does.
    let mut conn = db.pool.acquire().await.expect("acquire connection");

    // First scan observation at height 200 with no full transaction CBOR yet.
    gateway_core::chain::records::insert_chain_record_in_tx(
        &mut conn,
        tx_hash,
        200,
        chrono::Utc::now(),
        &bytes,
        None,
        &columns,
    )
    .await
    .expect("first scan insert");

    // A re-scan re-discovers the transaction at height 264 (a re-inclusion below
    // the rewind boundary) and now carries the full CBOR: both the height re-pin
    // and the CBOR backfill apply in one statement.
    let tx_cbor = vec![0x84_u8, 0xa0];
    gateway_core::chain::records::insert_chain_record_in_tx(
        &mut conn,
        tx_hash,
        264,
        chrono::Utc::now(),
        &bytes,
        Some(&tx_cbor),
        &columns,
    )
    .await
    .expect("re-pin scan insert");

    let row =
        sqlx::query("SELECT block_height, tx_cbor FROM cw_core.chain_records WHERE tx_hash = $1")
            .bind(tx_hash.to_vec())
            .fetch_one(&db.pool)
            .await
            .expect("read row");
    assert_eq!(
        row.get::<i64, _>("block_height"),
        264,
        "the scan re-pins the stored height to the re-included height"
    );
    assert_eq!(
        row.get::<Option<Vec<u8>>, _>("tx_cbor"),
        Some(tx_cbor.clone()),
        "the scan backfills the previously-missing tx_cbor"
    );

    // A later observation at the same height carrying DIFFERENT bytes must not
    // clobber the stored CBOR (the COALESCE keeps the first non-null bytes).
    gateway_core::chain::records::insert_chain_record_in_tx(
        &mut conn,
        tx_hash,
        264,
        chrono::Utc::now(),
        &bytes,
        Some(&[0xff_u8, 0xee]),
        &columns,
    )
    .await
    .expect("same-height re-observation");
    let preserved: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT tx_cbor FROM cw_core.chain_records WHERE tx_hash = $1")
            .bind(tx_hash.to_vec())
            .fetch_one(&db.pool)
            .await
            .expect("read tx_cbor");
    assert_eq!(
        preserved,
        Some(tx_cbor),
        "a same-height re-observation never clobbers bytes already stored"
    );
}

/// `delete_chain_record_by_tx_hash` removes the rich index row for a known-dead
/// transaction while leaving the thin `cw_api.records` anchor as the historical
/// reference (the anchor is insert-once and outlives the rich row).
#[tokio::test]
async fn delete_chain_record_removes_the_rich_row_but_keeps_the_anchor() {
    let db = TestDb::fresh().await.expect("test database");
    let tx_hash = [0x33_u8; 32];
    let bytes = open_record_bytes();
    let columns = gateway_core::chain::records::derive_chain_record_columns(
        &bytes,
        gateway_core::chain::params::Network::Preprod,
    )
    .expect("derive columns");

    gateway_core::chain::records::insert_chain_record(
        &db.pool,
        tx_hash,
        300,
        chrono::Utc::now(),
        &bytes,
        &columns,
    )
    .await
    .expect("insert chain record");

    // Both the rich row and its anchor exist after the insert.
    assert!(
        stored_block_height(&db.pool, tx_hash).await.is_some(),
        "the rich row exists before the delete"
    );
    let anchor_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_api.records WHERE tx_hash = $1")
            .bind(tx_hash.to_vec())
            .fetch_one(&db.pool)
            .await
            .expect("count anchor");
    assert_eq!(anchor_before, 1, "the anchor exists before the delete");

    // Deleting by hash removes exactly the one rich row.
    let mut tx = db.pool.begin().await.expect("begin");
    let deleted = gateway_core::chain::records::delete_chain_record_by_tx_hash(&mut *tx, tx_hash)
        .await
        .expect("delete rich row");
    tx.commit().await.expect("commit");
    assert_eq!(deleted, 1, "exactly one rich row is deleted");

    assert!(
        stored_block_height(&db.pool, tx_hash).await.is_none(),
        "the rich row is gone after the delete"
    );

    // The historical anchor survives the delete.
    let anchor_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_api.records WHERE tx_hash = $1")
            .bind(tx_hash.to_vec())
            .fetch_one(&db.pool)
            .await
            .expect("count anchor");
    assert_eq!(
        anchor_after, 1,
        "the historical cw_api.records anchor outlives the rich row"
    );

    // Deleting an already-absent transaction is a clean zero-row no-op.
    let mut tx = db.pool.begin().await.expect("begin");
    let deleted_again =
        gateway_core::chain::records::delete_chain_record_by_tx_hash(&mut *tx, tx_hash)
            .await
            .expect("re-delete");
    tx.commit().await.expect("commit");
    assert_eq!(
        deleted_again, 0,
        "deleting an absent transaction removes nothing"
    );
}

/// Whether a sqlx error is a Postgres CHECK-constraint violation (SQLSTATE
/// 23514).
fn is_check_violation(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23514")
    )
}

/// Whether a sqlx error is a Postgres unique-violation (SQLSTATE 23505).
fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")
    )
}

/// Keep the `Row` import meaningful even as the asserts evolve: a trivial guard
/// that a selected row exposes its columns by name.
#[tokio::test]
async fn poe_record_row_exposes_named_columns() {
    let db = TestDb::fresh().await.expect("test database");
    let operator_id = seed_operator(&db.pool).await;
    let record_id = seed_record(&db.pool, operator_id).await;
    let row = sqlx::query(
        "SELECT id, status, rollback_retry_count FROM cw_core.poe_record WHERE id = $1",
    )
    .bind(record_id)
    .fetch_one(&db.pool)
    .await
    .expect("read row");
    assert_eq!(row.get::<Uuid, _>("id"), record_id);
    assert_eq!(row.get::<String, _>("status"), "draft");
    assert_eq!(row.get::<i32, _>("rollback_retry_count"), 0);
}
