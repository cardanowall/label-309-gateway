//! Smoke test for the integration harness.
//!
//! Proves the harness stands up the dedicated test database and applies the
//! engine's migration corpus: the migration-tracking table lands in `cw_core`
//! (not `public`), every engine table exists in `cw_core`, and the job-insert
//! NOTIFY trigger is installed. Gated behind `pg-tests` so the default test run
//! never requires a database.

#![cfg(feature = "pg-tests")]

use gateway_core::testsupport::TestDb;

#[tokio::test]
async fn harness_brings_up_db_and_applies_migrations() {
    let db = TestDb::fresh()
        .await
        .expect("harness should stand up the test database");

    // The migration-tracking table lives in the engine's schema, never in
    // public: at least one migration recorded as applied.
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core._sqlx_migrations")
        .fetch_one(&db.pool)
        .await
        .expect("cw_core._sqlx_migrations should exist and be queryable");
    assert!(
        applied >= 1,
        "expected at least one applied migration, found {applied}"
    );

    // The engine creates no objects in public: the tracking table must NOT
    // exist there.
    let in_public: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = '_sqlx_migrations')",
    )
    .fetch_one(&db.pool)
    .await
    .expect("information_schema query should succeed");
    assert!(
        !in_public,
        "migration-tracking table must not be created in public"
    );

    // Every engine table the design declares exists in cw_core.
    for table in [
        "job",
        "job_history",
        "queue_policy",
        "cron_tick",
        "subject_event",
        "delivery_outbox",
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
             WHERE table_schema = 'cw_core' AND table_name = $1)",
        )
        .bind(table)
        .fetch_one(&db.pool)
        .await
        .expect("table-existence query should succeed");
        assert!(exists, "cw_core.{table} should exist after migration");
    }

    // The job-insert NOTIFY trigger is installed on cw_core.job.
    let trigger_present: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.triggers \
         WHERE event_object_schema = 'cw_core' \
         AND event_object_table = 'job' \
         AND trigger_name = 'job_available_notify')",
    )
    .fetch_one(&db.pool)
    .await
    .expect("trigger-existence query should succeed");
    assert!(
        trigger_present,
        "job_available_notify trigger should be installed on cw_core.job"
    );

    // The singleton partial-unique index is global (the live table is flat),
    // which is the property that makes singleton dedupe correct.
    let singleton_index: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_indexes \
         WHERE schemaname = 'cw_core' AND indexname = 'job_singleton_inflight_idx')",
    )
    .fetch_one(&db.pool)
    .await
    .expect("index-existence query should succeed");
    assert!(
        singleton_index,
        "job_singleton_inflight_idx should exist on cw_core.job"
    );
}
