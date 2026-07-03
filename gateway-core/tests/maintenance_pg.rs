//! Integration tests for partition maintenance, terminal-job archival, and
//! cron-tick pruning.
//!
//! Gated behind `pg-tests`. Each test stands up an isolated, freshly migrated
//! database via the harness, then drives the maintenance framework against it.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;

use chrono::{Datelike, Duration, TimeZone, Utc};
use uuid::Uuid;

use gateway_core::maintenance::partitions::{
    drop_old, engine_tables, ensure_ahead, maintain, PartitionWindow, PartitionedTable,
};
use gateway_core::maintenance::{
    archive_terminal_jobs, maintenance_policy, prune_cron_ticks, prune_webhook_firehose,
    MaintenanceCadence, MaintenanceHandler, MAINTENANCE_DAILY_QUEUE,
};
use gateway_core::runtime::scheduler::CronSchedule;
use gateway_core::runtime::Runtime;
use gateway_core::testsupport::TestDb;
use gateway_core::webhook::registration::{soft_delete_endpoint, EndpointChange, EndpointScope};

/// Live leaf partitions of a parent table, by bare child name.
async fn leaf_partitions(pool: &sqlx::PgPool, parent: &str) -> Vec<String> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT relid::regclass::text \
         FROM pg_partition_tree($1::regclass) \
         WHERE isleaf \
         ORDER BY 1",
    )
    .bind(parent)
    .fetch_all(pool)
    .await
    .expect("introspect partition tree");
    rows.into_iter()
        .map(|(n,)| n.rsplit('.').next().unwrap_or(&n).to_string())
        .collect()
}

/// The bare partition name the framework would build for `offset` months from
/// the current month, matching the framework's own naming.
fn month_partition_name(bare: &str, offset: i32) -> String {
    let now = Utc::now();
    let abs = now.year() as i64 * 12 + (now.month() as i64 - 1) + offset as i64;
    let year = abs.div_euclid(12);
    let month = abs.rem_euclid(12) + 1;
    format!("{bare}_{year:04}_{month:02}")
}

/// `ensure_ahead` creates exactly the missing future partitions and re-running
/// it is a no-op (idempotent). `pg_partition_tree` confirms each new partition
/// is actually attached to the parent.
#[tokio::test]
async fn ensure_ahead_creates_future_partitions_idempotently() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let table = PartitionedTable::new("cw_core.subject_event", "created_at");
    let window = PartitionWindow {
        create_ahead_months: 3,
        retain_months: 2,
    };

    let created = ensure_ahead(&pool, &table, window).await.expect("ensure 1");
    assert!(
        !created.is_empty(),
        "the migration only seeds two months, so 3-ahead must create at least one"
    );

    // Every requested month (current..=+3) now exists and is a real leaf of the
    // parent.
    let leaves = leaf_partitions(&pool, "cw_core.subject_event").await;
    for offset in 0..=3 {
        let want = month_partition_name("subject_event", offset);
        assert!(
            leaves.contains(&want),
            "expected partition {want} to exist; have {leaves:?}"
        );
    }

    // Re-running creates nothing: idempotent.
    let again = ensure_ahead(&pool, &table, window).await.expect("ensure 2");
    assert!(
        again.is_empty(),
        "second ensure_ahead must be a no-op, created {again:?}"
    );
}

/// `drop_old` removes partitions wholly before the retention window and leaves
/// recent ones alone; a second pass drops nothing more.
#[tokio::test]
async fn drop_old_removes_only_partitions_past_the_hot_window() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let table = PartitionedTable::new("cw_core.subject_event", "created_at");

    // Manually attach a partition for a month far in the past (10 months back).
    let now = Utc::now();
    let abs = now.year() as i64 * 12 + (now.month() as i64 - 1) - 10;
    let year = abs.div_euclid(12);
    let month0 = abs.rem_euclid(12); // 0-based
    let start = Utc
        .with_ymd_and_hms(year as i32, month0 as u32 + 1, 1, 0, 0, 0)
        .single()
        .unwrap();
    let (ny, nm) = if month0 + 1 == 12 {
        (year + 1, 1)
    } else {
        (year, month0 + 2)
    };
    let end = Utc
        .with_ymd_and_hms(ny as i32, nm as u32, 1, 0, 0, 0)
        .single()
        .unwrap();
    let old_name = format!("subject_event_{year:04}_{:02}", month0 + 1);
    let create = format!(
        "CREATE TABLE cw_core.\"{old_name}\" PARTITION OF cw_core.subject_event \
         FOR VALUES FROM ('{}') TO ('{}')",
        start.to_rfc3339(),
        end.to_rfc3339()
    );
    sqlx::query(sqlx::AssertSqlSafe(create))
        .execute(&pool)
        .await
        .expect("attach old partition");

    let before = leaf_partitions(&pool, "cw_core.subject_event").await;
    assert!(
        before.contains(&old_name),
        "old partition should be attached"
    );

    let window = PartitionWindow {
        create_ahead_months: 2,
        retain_months: 2,
    };
    let dropped = drop_old(&pool, &table, window).await.expect("drop 1");
    assert!(
        dropped.contains(&old_name),
        "the 10-months-old partition must be dropped; dropped {dropped:?}"
    );

    let after = leaf_partitions(&pool, "cw_core.subject_event").await;
    assert!(!after.contains(&old_name), "old partition must be gone");
    // The migration-seeded current/next month partitions survive.
    assert!(
        after.iter().any(|p| p.starts_with("subject_event_")),
        "recent partitions must remain"
    );

    // Idempotent: a second drop removes nothing.
    let again = drop_old(&pool, &table, window).await.expect("drop 2");
    assert!(
        again.is_empty(),
        "second drop_old must be a no-op: {again:?}"
    );
}

/// A full `maintain` pass over the registered engine tables creates ahead and
/// drops old in one shot, under the advisory lock, and re-runs as a pure no-op.
#[tokio::test]
async fn maintain_pass_provisions_and_prunes_then_is_idempotent() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    // Attach an artificially-old partition to job_history so the pass has
    // something to drop.
    let now = Utc::now();
    let abs = now.year() as i64 * 12 + (now.month() as i64 - 1) - 9;
    let year = abs.div_euclid(12);
    let month0 = abs.rem_euclid(12);
    let start = Utc
        .with_ymd_and_hms(year as i32, month0 as u32 + 1, 1, 0, 0, 0)
        .single()
        .unwrap();
    let (ny, nm) = if month0 + 1 == 12 {
        (year + 1, 1)
    } else {
        (year, month0 + 2)
    };
    let end = Utc
        .with_ymd_and_hms(ny as i32, nm as u32, 1, 0, 0, 0)
        .single()
        .unwrap();
    let old_name = format!("job_history_{year:04}_{:02}", month0 + 1);
    let create = format!(
        "CREATE TABLE cw_core.\"{old_name}\" PARTITION OF cw_core.job_history \
         FOR VALUES FROM ('{}') TO ('{}')",
        start.to_rfc3339(),
        end.to_rfc3339()
    );
    sqlx::query(sqlx::AssertSqlSafe(create))
        .execute(&pool)
        .await
        .expect("attach old job_history partition");

    let window = PartitionWindow {
        create_ahead_months: 3,
        retain_months: 2,
    };
    let reports = maintain(&pool, &engine_tables(), window)
        .await
        .expect("first maintain pass");
    assert_eq!(reports.len(), 2, "both engine tables reported");

    let job_history_report = reports
        .iter()
        .find(|(t, _)| t == "cw_core.job_history")
        .map(|(_, r)| r)
        .expect("job_history report");
    assert!(
        job_history_report.dropped.contains(&old_name),
        "maintain must drop the old job_history partition: {:?}",
        job_history_report.dropped
    );
    assert!(
        !job_history_report.created.is_empty(),
        "maintain must create future job_history partitions"
    );

    // Each registered table now has its full create-ahead set attached.
    for (parent, bare) in [
        ("cw_core.job_history", "job_history"),
        ("cw_core.subject_event", "subject_event"),
    ] {
        let leaves = leaf_partitions(&pool, parent).await;
        for offset in 0..=3 {
            let want = month_partition_name(bare, offset);
            assert!(
                leaves.contains(&want),
                "{parent} must have provisioned {want}; have {leaves:?}"
            );
        }
        assert!(!leaves.contains(&old_name));
    }

    // A second pass changes nothing.
    let second = maintain(&pool, &engine_tables(), window)
        .await
        .expect("second maintain pass");
    for (table, report) in &second {
        assert!(
            report.created.is_empty() && report.dropped.is_empty(),
            "maintain re-run must be a no-op for {table}: {report:?}"
        );
    }
}

/// The job-history mover relocates aged terminal rows out of the live table into
/// the partitioned history table and keeps non-terminal / too-recent rows put.
/// History stays queryable; the move never duplicates or loses a row.
#[tokio::test]
async fn archive_terminal_jobs_moves_aged_terminal_rows_only() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    // Two aged terminal jobs (eligible), one fresh terminal job (too recent),
    // one running job (never eligible).
    insert_job(&pool, "completed", Some(Utc::now() - Duration::minutes(30))).await;
    insert_job(&pool, "failed", Some(Utc::now() - Duration::minutes(30))).await;
    let fresh_id = insert_job(&pool, "completed", Some(Utc::now())).await;
    let running_id = insert_job(&pool, "running", None).await;

    let moved = archive_terminal_jobs(&pool, 10, 100)
        .await
        .expect("archive pass");
    assert_eq!(moved, 2, "exactly the two aged terminal rows move");

    // Live table now holds only the fresh terminal row and the running row.
    let live_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM cw_core.job ORDER BY id")
        .fetch_all(&pool)
        .await
        .expect("read live jobs");
    let mut expect_live = vec![fresh_id, running_id];
    expect_live.sort();
    let mut got_live = live_ids.clone();
    got_live.sort();
    assert_eq!(
        got_live, expect_live,
        "only too-recent/non-terminal rows remain live"
    );

    // History holds exactly the two moved rows and is queryable.
    let history_count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.job_history")
        .fetch_one(&pool)
        .await
        .expect("count history");
    assert_eq!(history_count, 2);

    // No row was lost: live + history accounts for all four inserts.
    let live_count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.job")
        .fetch_one(&pool)
        .await
        .expect("count live");
    assert_eq!(live_count + history_count, 4);

    // Re-running with nothing newly eligible moves zero (idempotent against the
    // already-archived rows; they no longer exist in the live table).
    let again = archive_terminal_jobs(&pool, 10, 100)
        .await
        .expect("second archive pass");
    assert_eq!(again, 0, "nothing left to archive");
}

/// Cron-tick pruning deletes only rows older than the retention window.
#[tokio::test]
async fn prune_cron_ticks_deletes_only_old_rows() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    // One old tick (40 days), one recent tick (1 day).
    insert_cron_tick(&pool, "billing", "old", Utc::now() - Duration::days(40)).await;
    insert_cron_tick(&pool, "billing", "recent", Utc::now() - Duration::days(1)).await;

    let pruned = prune_cron_ticks(&pool, 30).await.expect("prune");
    assert_eq!(
        pruned, 1,
        "only the 40-day-old tick is past the 30-day window"
    );

    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT tick_id FROM cw_core.cron_tick ORDER BY tick_id")
            .fetch_all(&pool)
            .await
            .expect("read remaining ticks");
    assert_eq!(remaining, vec!["recent".to_string()]);

    // Idempotent: re-running prunes nothing more.
    let again = prune_cron_ticks(&pool, 30).await.expect("second prune");
    assert_eq!(again, 0);
}

/// The daily maintenance job, driven end to end THROUGH the runtime, provisions
/// future partitions and drops an aged one.
///
/// This is the operational proof for invariant 10: not that the helper functions
/// work (the tests above cover that), but that registering the maintenance
/// handler and schedule on a real `Runtime` causes the scheduler to enqueue a
/// maintenance job, a worker loop to claim and run it, and the partition
/// lifecycle to actually advance as a side effect of that job completing.
#[tokio::test]
async fn daily_maintenance_runs_through_the_job_system_and_advances_partitions() {
    let db = TestDb::fresh().await.expect("test database");
    // A full runtime needs more connections than the default pool: a NOTIFY
    // listener, the worker loop, the sweeper, the scheduler, and the handler's
    // own queries.
    let pool = db.pool_with(12).await.expect("sized pool");

    // Attach an artificially-old job_history partition so the daily pass has
    // something to drop. It is well outside the 12-month retention window.
    let now = Utc::now();
    let abs = now.year() as i64 * 12 + (now.month() as i64 - 1) - 18;
    let year = abs.div_euclid(12);
    let month0 = abs.rem_euclid(12);
    let start = Utc
        .with_ymd_and_hms(year as i32, month0 as u32 + 1, 1, 0, 0, 0)
        .single()
        .unwrap();
    let (ny, nm) = if month0 + 1 == 12 {
        (year + 1, 1)
    } else {
        (year, month0 + 2)
    };
    let end = Utc
        .with_ymd_and_hms(ny as i32, nm as u32, 1, 0, 0, 0)
        .single()
        .unwrap();
    let old_name = format!("job_history_{year:04}_{:02}", month0 + 1);
    let create = format!(
        "CREATE TABLE cw_core.\"{old_name}\" PARTITION OF cw_core.job_history \
         FOR VALUES FROM ('{}') TO ('{}')",
        start.to_rfc3339(),
        end.to_rfc3339()
    );
    sqlx::query(sqlx::AssertSqlSafe(create))
        .execute(&pool)
        .await
        .expect("attach old job_history partition");

    // A future partition the migration does not seed; the pass must create it.
    let future_name = month_partition_name("job_history", 3);
    assert!(
        !leaf_partitions(&pool, "cw_core.job_history")
            .await
            .contains(&future_name),
        "the 3-months-ahead partition must not exist before the pass runs"
    );

    // Build a runtime that registers the daily maintenance handler and a
    // per-second schedule so the scheduler enqueues a job almost immediately.
    let rt = Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("maintenance-test")
            .queue_policy(maintenance_policy(MaintenanceCadence::Daily))
            .handler(
                MAINTENANCE_DAILY_QUEUE,
                MaintenanceHandler::new(pool.clone(), MaintenanceCadence::Daily),
            )
            // Fire every second so the test does not wait for 03:17 UTC. The
            // production schedule is daily; the cadence is the only difference.
            .schedule(CronSchedule::new(
                "* * * * * *",
                MAINTENANCE_DAILY_QUEUE,
                serde_json::Value::Null,
            ))
            .poll_interval(std::time::Duration::from_millis(50))
            .build()
            .await
            .expect("build maintenance runtime"),
    );

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // Wait until BOTH proofs hold together: the partition lifecycle has advanced
    // (old partition gone AND the future one provisioned) AND at least one
    // maintenance job has reached `completed` through the job system. Requiring
    // both in the same poll iteration avoids a race where the partition DML (which
    // commits inside the handler) is visible a beat before the worker's separate
    // completion flip lands: the handler returns, then the worker marks the job
    // completed, so observing the side effect first and reading the job row
    // immediately afterwards could see the flip still in flight. Polling for both
    // is what distinguishes "the helper works" from "the job wiring works" without
    // a timing assumption about which commit lands first.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let leaves = leaf_partitions(&pool, "cw_core.job_history").await;
        let advanced = !leaves.contains(&old_name) && leaves.contains(&future_name);
        let completed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM cw_core.job WHERE queue = $1 AND state = 'completed'",
        )
        .bind(MAINTENANCE_DAILY_QUEUE)
        .fetch_one(&pool)
        .await
        .expect("count completed maintenance jobs");
        if advanced && completed >= 1 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            rt.shutdown();
            let _ = run.await;
            panic!(
                "maintenance job did not advance partitions AND complete through the runtime in \
                 time; leaves: {leaves:?}, completed: {completed}"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    rt.shutdown();
    tokio::time::timeout(std::time::Duration::from_secs(10), run)
        .await
        .expect("runtime stops promptly after shutdown")
        .expect("join runtime task")
        .expect("runtime run returns Ok");
}

/// The hourly maintenance job, driven through the runtime, archives aged terminal
/// jobs out of the live table.
#[tokio::test]
async fn hourly_maintenance_archives_terminal_jobs_through_the_job_system() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool_with(12).await.expect("sized pool");

    // Two terminal jobs old enough to be archived (the handler's grace period is
    // 15 minutes), and one fresh terminal job that must stay live.
    let aged_a = insert_job(&pool, "completed", Some(Utc::now() - Duration::minutes(30))).await;
    let aged_b = insert_job(&pool, "failed", Some(Utc::now() - Duration::minutes(30))).await;
    let fresh = insert_job(&pool, "completed", Some(Utc::now())).await;

    let rt = Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("maintenance-test-hourly")
            .queue_policy(maintenance_policy(MaintenanceCadence::Hourly))
            .handler(
                MaintenanceCadence::Hourly.queue(),
                MaintenanceHandler::new(pool.clone(), MaintenanceCadence::Hourly),
            )
            .schedule(CronSchedule::new(
                "* * * * * *",
                MaintenanceCadence::Hourly.queue(),
                serde_json::Value::Null,
            ))
            .poll_interval(std::time::Duration::from_millis(50))
            .build()
            .await
            .expect("build hourly maintenance runtime"),
    );

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // Wait until the two aged rows have migrated out of the live table into
    // history, as a side effect of an hourly maintenance job.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let history: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.job_history")
            .fetch_one(&pool)
            .await
            .expect("count history");
        if history >= 2 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            rt.shutdown();
            let _ = run.await;
            panic!("hourly maintenance did not archive aged terminal jobs in time");
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // The two aged rows are gone from the live table; the fresh one remains.
    let live_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM cw_core.job ORDER BY id")
        .fetch_all(&pool)
        .await
        .expect("read live jobs");
    assert!(
        !live_ids.contains(&aged_a) && !live_ids.contains(&aged_b),
        "aged terminal jobs must have left the live table"
    );
    assert!(
        live_ids.contains(&fresh),
        "the fresh terminal job stays live within the grace period"
    );

    rt.shutdown();
    tokio::time::timeout(std::time::Duration::from_secs(10), run)
        .await
        .expect("runtime stops promptly after shutdown")
        .expect("join runtime task")
        .expect("runtime run returns Ok");
}

/// The webhook firehose sweep deletes terminal deliveries past the retention
/// window and keeps everything that must survive: pending deliveries (still
/// mid-retry), terminal deliveries still inside the window (redrivable
/// dead-letters), and outbox rows that are either unfanned or still referenced.
#[tokio::test]
async fn prune_webhook_firehose_deletes_only_aged_terminal_rows_and_dereferenced_outbox() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let operator_id = seed_operator(&pool, "op").await;
    let endpoint_id = seed_operator_endpoint(&pool, operator_id, "active").await;

    let day = Duration::days(1);
    let old = Utc::now() - Duration::days(40);
    let recent = Utc::now() - day;

    // Outbox A: fully fanned out and old; both its deliveries are aged terminal,
    // so after the delivery sweep it is dereferenced and itself sweepable.
    let outbox_a = insert_outbox(&pool, "a", true, old).await;
    insert_delivery(&pool, endpoint_id, outbox_a, "delivered", old).await;
    insert_delivery(&pool, endpoint_id, outbox_a, "failed", old).await;

    // Outbox B: fanned out and old, but one delivery is still pending — the
    // delivery is kept, so B stays referenced and must NOT be swept.
    let outbox_b = insert_outbox(&pool, "b", true, old).await;
    let kept_pending = insert_delivery(&pool, endpoint_id, outbox_b, "pending", old).await;

    // Outbox C: fanned out and old, its delivery is terminal but RECENT (inside
    // the window) — the delivery is kept (redrivable), so C stays referenced.
    let outbox_c = insert_outbox(&pool, "c", true, old).await;
    let kept_recent = insert_delivery(&pool, endpoint_id, outbox_c, "failed", recent).await;

    // Outbox D: old but NOT yet fanned out (fanned_out_at IS NULL) — kept until
    // the fan-out reader explodes it, even though it has no children.
    let outbox_d = insert_outbox(&pool, "d", false, old).await;

    // A standalone aged terminal delivery whose outbox is recent: the delivery
    // ages out, the recent outbox stays.
    let outbox_e = insert_outbox(&pool, "e", true, recent).await;
    let aged_on_recent_outbox =
        insert_delivery(&pool, endpoint_id, outbox_e, "delivered", old).await;

    let sweep = prune_webhook_firehose(&pool, 30, 1_000)
        .await
        .expect("first sweep");
    // Three aged terminal deliveries deleted: the two on A and the one on E.
    assert_eq!(sweep.deliveries_deleted, 3);
    // Only outbox A is fanned-out, aged, and now dereferenced.
    assert_eq!(sweep.outbox_deleted, 1);

    // Surviving deliveries: the pending one and the recent-terminal one.
    let live_deliveries: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM cw_core.webhook_delivery ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("read deliveries");
    let mut expect = vec![kept_pending, kept_recent];
    expect.sort();
    let mut got = live_deliveries.clone();
    got.sort();
    assert_eq!(
        got, expect,
        "only pending + within-window terminal rows survive"
    );
    assert!(
        !live_deliveries.contains(&aged_on_recent_outbox),
        "an aged terminal delivery is swept even when its outbox is recent"
    );

    // Surviving outbox rows: B (live child), C (within-window child), D (unfanned),
    // E (recent). A is gone.
    let live_outbox: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM cw_core.delivery_outbox ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("read outbox");
    assert!(
        !live_outbox.contains(&outbox_a),
        "A is fanned-out, aged, dereferenced -> swept"
    );
    for kept in [outbox_b, outbox_c, outbox_d, outbox_e] {
        assert!(live_outbox.contains(&kept), "outbox {kept} must be kept");
    }

    // Idempotent: a second sweep with nothing newly eligible removes nothing.
    let again = prune_webhook_firehose(&pool, 30, 1_000)
        .await
        .expect("second sweep");
    assert_eq!(again.deliveries_deleted, 0);
    assert_eq!(again.outbox_deleted, 0);
}

/// A large terminal backlog is drained in bounded passes within a single sweep:
/// no statement deletes more than the batch bound at once, and the whole
/// eligible set is gone when the sweep returns. Cascading the deliveries then
/// dereferences every fanned-out outbox row so it is swept in the same run.
#[tokio::test]
async fn prune_webhook_firehose_drains_a_large_backlog_in_bounded_passes() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let operator_id = seed_operator(&pool, "op").await;
    let endpoint_id = seed_operator_endpoint(&pool, operator_id, "active").await;

    // 25 aged outbox rows, each with one aged terminal delivery: 25 deliveries and
    // 25 dereferenceable outbox rows once the deliveries are gone.
    let old = Utc::now() - Duration::days(45);
    let total = 25usize;
    for i in 0..total {
        let ob = insert_outbox(&pool, &format!("bulk-{i}"), true, old).await;
        insert_delivery(&pool, endpoint_id, ob, "delivered", old).await;
    }

    // A batch smaller than the backlog forces multiple bounded passes; the loop
    // inside the sweep must drain the whole set rather than stop after one batch.
    let batch = 10;
    let sweep = prune_webhook_firehose(&pool, 30, batch)
        .await
        .expect("bulk sweep");
    assert_eq!(
        sweep.deliveries_deleted, total as u64,
        "all aged deliveries drained"
    );
    assert_eq!(
        sweep.outbox_deleted, total as u64,
        "all dereferenced outbox rows drained"
    );

    let remaining_deliveries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.webhook_delivery")
            .fetch_one(&pool)
            .await
            .expect("count deliveries");
    let remaining_outbox: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.delivery_outbox")
        .fetch_one(&pool)
        .await
        .expect("count outbox");
    assert_eq!(remaining_deliveries, 0, "backlog fully drained");
    assert_eq!(remaining_outbox, 0, "backlog fully drained");
}

/// The stranded-pending stage of the firehose sweep: `pending` deliveries of
/// disabled/paused endpoints aged past the retention window are reclaimed,
/// together with the outbox rows only they were pinning. A live endpoint's
/// pending delivery is never pruned at any age, and a dead endpoint's pending
/// delivery inside the window is preserved so a re-enable resumes it.
#[tokio::test]
async fn prune_webhook_firehose_reclaims_stranded_pending_of_dead_endpoints() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let operator_id = seed_operator(&pool, "op").await;
    let disabled = seed_operator_endpoint(&pool, operator_id, "disabled").await;
    let paused = seed_operator_endpoint(&pool, operator_id, "paused").await;
    let active = seed_operator_endpoint(&pool, operator_id, "active").await;

    let old = Utc::now() - Duration::days(40);
    let recent = Utc::now() - Duration::days(1);

    // Aged pending deliveries on the disabled and paused endpoints: the claim
    // only serves active endpoints, so without the stranded stage these rows
    // (and the outbox rows they reference) would be frozen forever.
    let ob_disabled = insert_outbox(&pool, "str-dis", true, old).await;
    let stranded_disabled = insert_delivery(&pool, disabled, ob_disabled, "pending", old).await;
    let ob_paused = insert_outbox(&pool, "str-pau", true, old).await;
    let stranded_paused = insert_delivery(&pool, paused, ob_paused, "pending", old).await;

    // An equally aged pending delivery on the ACTIVE endpoint: still genuinely
    // deliverable, so it must never be pruned.
    let ob_active = insert_outbox(&pool, "str-act", true, old).await;
    let live_pending = insert_delivery(&pool, active, ob_active, "pending", old).await;

    // A within-window pending delivery on the disabled endpoint: preserved so a
    // re-enable (PATCH to active) resumes it exactly where it stopped.
    let ob_recent = insert_outbox(&pool, "str-rec", true, old).await;
    let recent_pending = insert_delivery(&pool, disabled, ob_recent, "pending", recent).await;

    let sweep = prune_webhook_firehose(&pool, 30, 1_000)
        .await
        .expect("first sweep");
    assert_eq!(
        sweep.stranded_deliveries_deleted, 2,
        "exactly the two aged pending rows on dead endpoints are reclaimed"
    );
    assert_eq!(
        sweep.deliveries_deleted, 0,
        "no terminal rows were eligible"
    );
    assert_eq!(
        sweep.outbox_deleted, 2,
        "the outbox rows only the stranded deliveries pinned are reclaimed in the same run"
    );

    let live_deliveries: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM cw_core.webhook_delivery ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("read deliveries");
    let mut expect = vec![live_pending, recent_pending];
    expect.sort();
    let mut got = live_deliveries.clone();
    got.sort();
    assert_eq!(
        got, expect,
        "the live endpoint's pending row and the within-window pending row survive"
    );
    assert!(!live_deliveries.contains(&stranded_disabled));
    assert!(!live_deliveries.contains(&stranded_paused));

    let live_outbox: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM cw_core.delivery_outbox ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("read outbox");
    assert!(!live_outbox.contains(&ob_disabled));
    assert!(!live_outbox.contains(&ob_paused));
    for kept in [ob_active, ob_recent] {
        assert!(
            live_outbox.contains(&kept),
            "outbox {kept} is still referenced by a surviving delivery"
        );
    }

    // Idempotent: nothing newly eligible on a second pass.
    let again = prune_webhook_firehose(&pool, 30, 1_000)
        .await
        .expect("second sweep");
    assert_eq!(again.stranded_deliveries_deleted, 0);
    assert_eq!(again.deliveries_deleted, 0);
    assert_eq!(again.outbox_deleted, 0);
}

/// Soft-deleting an endpoint fails its pending deliveries in the same
/// transaction — deletion has no undo, so `pending` under a deleted endpoint is
/// unresolvable — and the retention sweep then reclaims the aged ones through
/// the ordinary terminal-state stage, freeing the outbox rows they pinned.
#[tokio::test]
async fn soft_delete_fails_pending_deliveries_so_the_sweep_reclaims_them() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let operator_id = seed_operator(&pool, "op").await;
    let endpoint = seed_operator_endpoint(&pool, operator_id, "active").await;

    let old = Utc::now() - Duration::days(40);
    let recent = Utc::now() - Duration::days(1);

    let ob_old = insert_outbox(&pool, "sdel-old", true, old).await;
    let aged = insert_delivery(&pool, endpoint, ob_old, "pending", old).await;
    let ob_new = insert_outbox(&pool, "sdel-new", true, recent).await;
    let fresh = insert_delivery(&pool, endpoint, ob_new, "pending", recent).await;

    let change = soft_delete_endpoint(&pool, EndpointScope::Operator(operator_id), endpoint)
        .await
        .expect("soft delete");
    assert_eq!(change, EndpointChange::Changed);

    // Both pending rows flipped to the terminal dead-letter state, with the
    // reason recorded and any POST lease cleared.
    let rows: Vec<(Uuid, String, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, state, last_error, claim_token FROM cw_core.webhook_delivery ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("read deliveries");
    assert_eq!(rows.len(), 2);
    for (id, state, last_error, claim_token) in &rows {
        assert_eq!(state, "failed", "delivery {id} must be failed");
        assert_eq!(last_error.as_deref(), Some("endpoint deleted"));
        assert!(claim_token.is_none(), "the POST lease is released");
    }

    // The sweep reclaims the aged row via the terminal stage (no stranded
    // pending rows remain to need the dead-endpoint stage) and frees its outbox
    // row; the fresh row is kept until it ages out of the window.
    let sweep = prune_webhook_firehose(&pool, 30, 1_000)
        .await
        .expect("sweep");
    assert_eq!(sweep.deliveries_deleted, 1);
    assert_eq!(sweep.stranded_deliveries_deleted, 0);
    assert_eq!(sweep.outbox_deleted, 1);

    let remaining: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM cw_core.webhook_delivery")
        .fetch_all(&pool)
        .await
        .expect("read remaining deliveries");
    assert_eq!(remaining, vec![fresh]);
    assert!(!remaining.contains(&aged));
    let outbox: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM cw_core.delivery_outbox")
        .fetch_all(&pool)
        .await
        .expect("read remaining outbox");
    assert_eq!(outbox, vec![ob_new]);
}

/// Drop every monthly partition of a parent, leaving only the DEFAULT
/// partition attached — the state of a deployment whose provisioned months
/// have all lapsed.
async fn drop_monthly_partitions(pool: &sqlx::PgPool, parent: &str) {
    for leaf in leaf_partitions(pool, parent).await {
        if leaf.ends_with("_default") {
            continue;
        }
        let sql = format!("DROP TABLE cw_core.\"{leaf}\"");
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(pool)
            .await
            .expect("drop monthly partition");
    }
}

/// With no monthly partition attached, an insert on the publish hot path still
/// lands — in the DEFAULT partition — and the next ensure pass drains it into
/// a freshly created monthly partition so retention applies to it again.
#[tokio::test]
async fn default_partition_catches_inserts_and_ensure_drains_them() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    let table = PartitionedTable::new("cw_core.subject_event", "created_at");

    drop_monthly_partitions(&pool, "cw_core.subject_event").await;

    // The insert-never-fails backstop: with zero monthly partitions the row is
    // routed to DEFAULT instead of erroring.
    sqlx::query(
        "INSERT INTO cw_core.subject_event \
           (subject_kind, subject_id, subject_seq, event_type, payload) \
         VALUES ('poe_record', 'subj', 1, 'test.event', '{}'::jsonb)",
    )
    .execute(&pool)
    .await
    .expect("an insert with no monthly partition must land in DEFAULT, not fail");
    let stranded: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.subject_event_default")
        .fetch_one(&pool)
        .await
        .expect("count DEFAULT rows");
    assert_eq!(stranded, 1, "the row landed in the DEFAULT partition");

    // The ensure pass provisions the window AND drains the stranded row into
    // the current-month partition it creates.
    let created = ensure_ahead(&pool, &table, PartitionWindow::default())
        .await
        .expect("ensure pass");
    assert!(
        created.contains(&month_partition_name("subject_event", 0)),
        "the current month must be re-created; created {created:?}"
    );

    let stranded: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.subject_event_default")
        .fetch_one(&pool)
        .await
        .expect("count DEFAULT rows after drain");
    assert_eq!(stranded, 0, "the DEFAULT partition is drained");
    let location: String =
        sqlx::query_scalar("SELECT tableoid::regclass::text FROM cw_core.subject_event")
            .fetch_one(&pool)
            .await
            .expect("locate the moved row");
    assert_eq!(
        location,
        format!("cw_core.{}", month_partition_name("subject_event", 0)),
        "the stranded row now lives in the real monthly partition"
    );

    // A later insert routes straight into the monthly partition; DEFAULT stays
    // empty and a re-run of the ensure pass is a no-op.
    sqlx::query(
        "INSERT INTO cw_core.subject_event \
           (subject_kind, subject_id, subject_seq, event_type, payload) \
         VALUES ('poe_record', 'subj', 2, 'test.event', '{}'::jsonb)",
    )
    .execute(&pool)
    .await
    .expect("insert after provisioning");
    let stranded: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.subject_event_default")
        .fetch_one(&pool)
        .await
        .expect("count DEFAULT rows after provisioning");
    assert_eq!(stranded, 0);
    let again = ensure_ahead(&pool, &table, PartitionWindow::default())
        .await
        .expect("ensure re-run");
    assert!(again.is_empty(), "re-run must be a no-op: {again:?}");
}

/// Building a runtime provisions the partition working set synchronously,
/// before any loop starts: a build against a database whose monthly partitions
/// have all lapsed re-creates the current month plus the lookahead for both
/// engine tables, so the first hot-path insert already has a real home.
#[tokio::test]
async fn runtime_build_provisions_partitions_before_serving() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    drop_monthly_partitions(&pool, "cw_core.subject_event").await;
    drop_monthly_partitions(&pool, "cw_core.job_history").await;

    // No policies, handlers, or schedules: provisioning is a property of the
    // build itself, not of any registered work.
    let _runtime = Runtime::builder(pool.clone())
        .worker_id("provision-test")
        .build()
        .await
        .expect("build must provision the partition working set");

    for (parent, bare) in [
        ("cw_core.job_history", "job_history"),
        ("cw_core.subject_event", "subject_event"),
    ] {
        let leaves = leaf_partitions(&pool, parent).await;
        for offset in 0..=3 {
            let want = month_partition_name(bare, offset);
            assert!(
                leaves.contains(&want),
                "{parent} must have {want} after build; have {leaves:?}"
            );
        }
    }

    // The publish hot path's append lands in the real monthly partition, not
    // the DEFAULT backstop.
    sqlx::query(
        "INSERT INTO cw_core.subject_event \
           (subject_kind, subject_id, subject_seq, event_type, payload) \
         VALUES ('poe_record', 'subj', 1, 'test.event', '{}'::jsonb)",
    )
    .execute(&pool)
    .await
    .expect("insert after build");
    let location: String =
        sqlx::query_scalar("SELECT tableoid::regclass::text FROM cw_core.subject_event")
            .fetch_one(&pool)
            .await
            .expect("locate the row");
    assert_eq!(
        location,
        format!("cw_core.{}", month_partition_name("subject_event", 0))
    );
}

/// Seed an operator and return its id. The endpoint owner the firehose seed
/// needs; the sweep itself never reads operator fields.
async fn seed_operator(pool: &sqlx::PgPool, label: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(id)
        .bind(label)
        .execute(pool)
        .await
        .expect("seed operator");
    id
}

/// Seed an operator-scoped webhook endpoint with the given status and return
/// its id. The sweep never reads the secret, so the secret material is a dummy.
async fn seed_operator_endpoint(pool: &sqlx::PgPool, operator_id: Uuid, status: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.webhook_endpoint \
           (id, scope_kind, operator_id, url, secret_enc, secret_fp, wrap_key_id, enabled_events, \
            status) \
         VALUES ($1, 'operator', $2, 'https://example.test/hook', $3, $4, 'whk_test', '{}', $5)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(vec![0u8; 16])
    .bind(vec![0u8; 32])
    .bind(status)
    .execute(pool)
    .await
    .expect("seed operator endpoint");
    id
}

/// Insert a `delivery_outbox` row with an explicit `created_at` and fan-out
/// state, returning its id. `fanned_out` stamps `fanned_out_at` so the row is a
/// fan-out-complete spine row; `false` leaves it awaiting fan-out.
async fn insert_outbox(
    pool: &sqlx::PgPool,
    tag: &str,
    fanned_out: bool,
    created_at: chrono::DateTime<Utc>,
) -> Uuid {
    let id = Uuid::now_v7();
    let fanned_out_at = fanned_out.then_some(created_at);
    sqlx::query(
        "INSERT INTO cw_core.delivery_outbox \
           (id, subject_kind, subject_id, subject_seq, event_type, payload, dedupe_key, \
            created_at, fanned_out_at) \
         VALUES ($1, 'poe_record', $2, 1, 'cardano.tx.confirmed', '{}'::jsonb, $3, $4, $5)",
    )
    .bind(id)
    .bind(tag)
    .bind(format!("outbox:{tag}:{}", id.simple()))
    .bind(created_at)
    .bind(fanned_out_at)
    .execute(pool)
    .await
    .expect("insert delivery_outbox");
    id
}

/// Insert a `webhook_delivery` row fanned out from `outbox_id` with an explicit
/// state and `created_at`, returning its id.
async fn insert_delivery(
    pool: &sqlx::PgPool,
    endpoint_id: Uuid,
    outbox_id: Uuid,
    state: &str,
    created_at: chrono::DateTime<Utc>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.webhook_delivery \
           (id, endpoint_id, subject_kind, subject_id, subject_seq, event_type, body, \
            dedupe_key, outbox_id, state, created_at) \
         VALUES ($1, $2, 'poe_record', 'subj', 1, 'cardano.tx.confirmed', '{}'::jsonb, $3, $4, \
                 $5, $6)",
    )
    .bind(id)
    .bind(endpoint_id)
    .bind(format!("dedupe:{}", id.simple()))
    .bind(outbox_id)
    .bind(state)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert webhook_delivery");
    id
}

/// Insert a job row directly, returning its id. `finished_at` is set for
/// terminal states.
async fn insert_job(
    pool: &sqlx::PgPool,
    state: &str,
    finished_at: Option<chrono::DateTime<Utc>>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.job \
         (id, queue, payload, state, max_attempts, backoff, finished_at) \
         VALUES ($1, 'q', '{}'::jsonb, $2, 5, '{\"kind\":\"fixed\",\"base_secs\":1}'::jsonb, $3)",
    )
    .bind(id)
    .bind(state)
    .bind(finished_at)
    .execute(pool)
    .await
    .expect("insert job");
    id
}

/// Insert a cron_tick row directly with an explicit enqueued_at.
async fn insert_cron_tick(
    pool: &sqlx::PgPool,
    queue: &str,
    tick_id: &str,
    at: chrono::DateTime<Utc>,
) {
    sqlx::query("INSERT INTO cw_core.cron_tick (queue, tick_id, enqueued_at) VALUES ($1, $2, $3)")
        .bind(queue)
        .bind(tick_id)
        .bind(at)
        .execute(pool)
        .await
        .expect("insert cron_tick");
}
