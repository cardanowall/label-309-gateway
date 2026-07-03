//! The startup orphan-staging janitor against a real Postgres.
//!
//! A durable staged file is live exactly while a `reserved` `storage_upload_attempt`
//! row names it. The janitor reconciles the durable directory against that live set
//! and reclaims every engine-owned `.stage` file no live reservation points at,
//! while leaving a live file and any non-engine file untouched. These tests pin
//! that contract end to end: they promote real files, seed real attempt rows, run
//! the janitor handler, and assert which files survive.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::path::Path;

use gateway_core::storage::{
    durable_staged_path, promote_to_durable, stage_stream, sweep_orphan_durable_files,
    StagingJanitor, StagingJanitorSummary,
};
use gateway_core::testsupport::TestDb;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// Seed one operator and return its id.
async fn seed_operator(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'janitor-test')")
        .bind(id)
        .execute(pool)
        .await
        .expect("insert operator");
    id
}

/// Seed one account anchor + detail under an operator and return the account id.
async fn seed_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let account_id = Uuid::now_v7();
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
    account_id
}

/// Register one funding source and return its id.
async fn seed_funding_source(pool: &sqlx::PgPool, owner_operator_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'primary', 'turbo', $3, 'kr:1')",
    )
    .bind(id)
    .bind(owner_operator_id)
    .bind(format!("addr-{}", id.simple()))
    .execute(pool)
    .await
    .expect("insert funding source");
    id
}

/// Insert one `reserved` attempt naming `staged_path`, with a distinct sha256 per
/// call so the at-most-one-live-attempt unique never fires.
async fn seed_reserved_attempt(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    operator_id: Uuid,
    funding_source_id: Uuid,
    staged_path: &str,
) -> Uuid {
    let id = Uuid::now_v7();
    // A distinct 32-byte sha256 derived from the attempt id keeps the
    // (account, backend, sha256) live unique satisfied across many seeds.
    let mut sha = [0u8; 32];
    sha[..16].copy_from_slice(id.as_bytes());
    let signature = vec![0u8; 512];
    sqlx::query(
        "INSERT INTO cw_core.storage_upload_attempt \
           (id, account_id, operator_id, funding_source_id, backend, sha256, bytes, \
            chargeable_bytes, charged_usd_micros, estimated_winc, data_item_id, \
            data_item_signature, data_item_anchor, data_item_tag_bytes, staged_path) \
         VALUES ($1, $2, $3, $4, 'turbo', $5, 1000, 1000, 5000, 7, 'di:1', \
                 $6, NULL, NULL, $7)",
    )
    .bind(id)
    .bind(account_id)
    .bind(operator_id)
    .bind(funding_source_id)
    .bind(sha.as_slice())
    .bind(signature.as_slice())
    .bind(staged_path)
    .execute(pool)
    .await
    .expect("insert reserved attempt");
    id
}

/// Promote a small payload to the durable dir under a synthetic attempt id and
/// return its durable path. Used to materialise real on-disk files the janitor
/// reconciles.
async fn promote_payload(
    scratch: &Path,
    durable: &Path,
    attempt_id: Uuid,
    payload: &[u8],
) -> String {
    let staged = stage_stream(
        scratch,
        4096,
        futures_util::stream::iter(vec![Ok::<Vec<u8>, std::convert::Infallible>(
            payload.to_vec(),
        )]),
    )
    .await
    .expect("staging succeeds");
    let path = promote_to_durable(staged, durable, attempt_id)
        .await
        .expect("promotion succeeds");
    assert_eq!(path, durable_staged_path(durable, attempt_id));
    path.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// Janitor behaviour.
// ---------------------------------------------------------------------------

/// A durable file a live `reserved` attempt points at is kept; an engine-owned
/// `.stage` file no live attempt points at is reclaimed.
#[tokio::test]
async fn the_janitor_reclaims_orphans_and_keeps_live_files() {
    let db = TestDb::fresh().await.expect("fresh db");
    let scratch = tempfile::tempdir().expect("scratch");
    let durable = tempfile::tempdir().expect("durable");

    let operator = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, operator).await;
    let source = seed_funding_source(&db.pool, operator).await;

    // A live file: a real durable file and a reserved attempt that names it.
    let live_attempt = Uuid::now_v7();
    let live_path = promote_payload(scratch.path(), durable.path(), live_attempt, b"live").await;
    seed_reserved_attempt(&db.pool, account, operator, source, &live_path).await;

    // An orphan file: promoted, but no attempt row names it (a crash between
    // writing the file and committing the attempt row).
    let orphan_attempt = Uuid::now_v7();
    let orphan_path =
        promote_payload(scratch.path(), durable.path(), orphan_attempt, b"orphan").await;

    assert!(Path::new(&live_path).exists());
    assert!(Path::new(&orphan_path).exists());

    let summary = StagingJanitor::new(db.pool.clone(), durable.path().to_path_buf())
        .run_once()
        .await
        .expect("janitor pass");

    assert_eq!(
        summary,
        StagingJanitorSummary {
            files_seen: 2,
            files_reclaimed: 1,
        }
    );
    assert!(
        Path::new(&live_path).exists(),
        "the live file a reserved attempt points at is kept"
    );
    assert!(
        !Path::new(&orphan_path).exists(),
        "the orphan with no live attempt is reclaimed"
    );
}

/// A file whose attempt has SETTLED (left `reserved`) is an orphan: settlement
/// nulls `staged_path`, so the live set no longer names the file even though the
/// row survives. The janitor reclaims it.
#[tokio::test]
async fn a_settled_attempts_lingering_file_is_reclaimed() {
    let db = TestDb::fresh().await.expect("fresh db");
    let scratch = tempfile::tempdir().expect("scratch");
    let durable = tempfile::tempdir().expect("durable");

    let operator = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, operator).await;
    let source = seed_funding_source(&db.pool, operator).await;

    let attempt_id = Uuid::now_v7();
    let path = promote_payload(scratch.path(), durable.path(), attempt_id, b"settled").await;
    let row_id = seed_reserved_attempt(&db.pool, account, operator, source, &path).await;

    // Settle the attempt the way the commit/release CAS does: leave 'reserved',
    // null staged_path, and stamp the realized charge (a committed attempt must
    // carry a non-null `settled_charge_usd_micros` per the state CHECK). The file is
    // now an orphan the janitor must reclaim (the deletion that should have run was
    // lost to a crash).
    sqlx::query(
        "UPDATE cw_core.storage_upload_attempt \
         SET state = 'committed', staged_path = NULL, \
             settled_charge_usd_micros = charged_usd_micros, settled_at = now() \
         WHERE id = $1",
    )
    .bind(row_id)
    .execute(&db.pool)
    .await
    .expect("settle the attempt");

    let summary = sweep_orphan_durable_files(&db.pool, durable.path())
        .await
        .expect("sweep");
    assert_eq!(summary.files_reclaimed, 1);
    assert!(
        !Path::new(&path).exists(),
        "the settled attempt's lingering file is reclaimed"
    );
}

/// The janitor only ever touches engine-owned `.stage` files; an unrelated file
/// an operator placed in the durable directory is left alone.
#[tokio::test]
async fn the_janitor_never_touches_non_engine_files() {
    let db = TestDb::fresh().await.expect("fresh db");
    let durable = tempfile::tempdir().expect("durable");

    // No attempts at all, so every .stage file would be an orphan. Place a
    // non-.stage file alongside one orphan .stage file.
    let scratch = tempfile::tempdir().expect("scratch");
    let orphan_attempt = Uuid::now_v7();
    let orphan_path =
        promote_payload(scratch.path(), durable.path(), orphan_attempt, b"orphan").await;

    let foreign = durable.path().join("operator-notes.txt");
    tokio::fs::write(&foreign, b"do not touch")
        .await
        .expect("write foreign file");

    let summary = sweep_orphan_durable_files(&db.pool, durable.path())
        .await
        .expect("sweep");

    assert_eq!(
        summary,
        StagingJanitorSummary {
            files_seen: 1,
            files_reclaimed: 1,
        },
        "only the one .stage file is a candidate; the foreign file is not even counted"
    );
    assert!(!Path::new(&orphan_path).exists(), "the orphan is reclaimed");
    assert!(foreign.exists(), "the non-engine file is left untouched");
}

/// A pass over a durable directory that does not exist yet, or one with nothing
/// orphaned, is a clean no-op (the startup pass on a never-used deployment).
#[tokio::test]
async fn a_pass_with_nothing_to_reclaim_is_a_no_op() {
    let db = TestDb::fresh().await.expect("fresh db");

    // A directory that was never created (no upload has been promoted yet).
    let missing = tempfile::tempdir().expect("base");
    let never_created = missing.path().join("durable-not-yet-made");
    let summary = sweep_orphan_durable_files(&db.pool, &never_created)
        .await
        .expect("sweep of a missing dir is fine");
    assert_eq!(summary, StagingJanitorSummary::default());

    // An empty, existing directory.
    let empty = tempfile::tempdir().expect("empty durable");
    let summary = StagingJanitor::new(db.pool.clone(), empty.path().to_path_buf())
        .run_once()
        .await
        .expect("janitor pass over an empty dir");
    assert_eq!(summary, StagingJanitorSummary::default());
}
