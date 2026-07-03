//! End-to-end runtime smoke test.
//!
//! Stands up a single [`Runtime`] driving three queues at once and runs jobs
//! through their full lifecycles, then archives the terminal rows into history:
//!
//!   - a **cron-driven singleton_loop** queue: an in-process cron schedule
//!     enqueues onto it every second; its handler serializes across replicas via
//!     a session advisory lock and completes;
//!   - a **standard, fixed-backoff** queue: ordinary worker-pool concurrency,
//!     handler completes;
//!   - a **defer-simulating** queue: the handler defers its first attempt and
//!     completes the next, exercising the attempt-neutral cooldown path.
//!
//! After the jobs reach terminal states, the maintenance archiver moves them out
//! of the live table into the range-partitioned `job_history`, and the test
//! asserts the move is exact (count conserved, history queryable). Every
//! assertion is on observable end-state: lifecycle states, the defer counter and
//! attempt budget, a handler-written counter, and the live/history row split.
//!
//! Gated behind `pg-tests`.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;

use gateway_core::maintenance::archive_terminal_jobs;
use gateway_core::runtime::claim;
use gateway_core::runtime::enqueue::{enqueue, EnqueueOptions};
use gateway_core::runtime::locks::AdvisoryLock;
use gateway_core::runtime::policy::QueuePolicy;
use gateway_core::runtime::scheduler::CronSchedule;
use gateway_core::runtime::{Backoff, JobContext, JobHandler, JobOutcome, JobState, Runtime};
use gateway_core::testsupport::TestDb;

/// Handler for the standard fixed-backoff queue: count and complete.
struct CompleteHandler {
    pool: PgPool,
    counter_key: String,
}

impl JobHandler for CompleteHandler {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        bump(&self.pool, &self.counter_key).await;
        JobOutcome::Complete
    }
}

/// Handler for the cron-driven singleton_loop queue: take the singleton advisory
/// lock (proving the non-overlap primitive is usable from a handler), count, and
/// complete.
struct CronSingletonHandler {
    pool: PgPool,
    counter_key: String,
    lock_name: String,
}

impl JobHandler for CronSingletonHandler {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        // The singleton_loop policy already pins one in-flight job per replica;
        // the advisory lock is the cross-replica non-overlap guard. Acquiring it
        // here exercises that path end to end.
        let guard = AdvisoryLock::acquire(&self.pool, &self.lock_name)
            .await
            .expect("singleton handler acquires its advisory lock");
        bump(&self.pool, &self.counter_key).await;
        guard.release().await.expect("release advisory lock");
        JobOutcome::Complete
    }
}

/// Handler for the defer-simulating queue: defer the first attempt (a cooldown),
/// complete the second. Asserts attempt-neutrality of defer via the context it
/// is handed.
struct DeferOnceHandler {
    pool: PgPool,
    counter_key: String,
}

impl JobHandler for DeferOnceHandler {
    async fn handle(&self, ctx: JobContext) -> JobOutcome {
        if ctx.defer_count == 0 {
            // First pass: simulate a cooldown. Defer to "now" so it is
            // immediately due again. The claim that ran this attempt charged an
            // attempt; defer refunds it, so this does not erode the retry budget.
            JobOutcome::Defer { until: Utc::now() }
        } else {
            // Second pass (after exactly one defer): do the work and complete.
            bump(&self.pool, &self.counter_key).await;
            JobOutcome::Complete
        }
    }
}

async fn bump(pool: &PgPool, key: &str) {
    sqlx::query(
        "INSERT INTO cw_core.test_counter (key, value) VALUES ($1, 1) \
         ON CONFLICT (key) DO UPDATE SET value = cw_core.test_counter.value + 1",
    )
    .bind(key)
    .execute(pool)
    .await
    .expect("increment counter");
}

async fn counter(pool: &PgPool, key: &str) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(value, 0) FROM cw_core.test_counter WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .expect("read counter")
        .unwrap_or(0)
}

async fn count_in_state(pool: &PgPool, queue: &str, state: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.job WHERE queue = $1 AND state = $2")
        .bind(queue)
        .bind(state)
        .fetch_one(pool)
        .await
        .expect("count")
}

/// Poll until `pred` returns true or panic after `timeout`.
async fn wait_for<F, Fut>(timeout: Duration, mut pred: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if pred().await {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("condition not met within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn three_queue_runtime_runs_full_lifecycles_then_archives_history() {
    let db = TestDb::fresh().await.expect("test database");
    // The runtime keeps a NOTIFY listener plus sweeper, scheduler, and per-handler
    // advisory locks in flight, so it needs more than the default connection cap.
    let pool = db.pool_with(16).await.expect("sized pool");

    // Scratch counter table the handlers write to, in the engine schema.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cw_core.test_counter ( \
            key text PRIMARY KEY, value bigint NOT NULL DEFAULT 0 )",
    )
    .execute(&pool)
    .await
    .expect("create scratch counter table");

    let standard_q = "smoke-standard";
    let cron_q = "smoke-cron-singleton";
    let defer_q = "smoke-defer";

    let standard_key = "k-standard";
    let cron_key = "k-cron";
    let defer_key = "k-defer";

    const STANDARD_JOBS: usize = 4;

    let rt = Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("smoke")
            // Standard, fixed backoff.
            .queue_policy(QueuePolicy::standard(
                standard_q,
                3,
                Backoff::Fixed { base_secs: 1 },
                30,
                4,
            ))
            // Cron-driven singleton_loop: at most one in-flight at a time.
            .queue_policy(QueuePolicy::singleton_loop(
                cron_q,
                3,
                Backoff::Fixed { base_secs: 1 },
                30,
            ))
            // Defer simulation runs on a standard queue.
            .queue_policy(QueuePolicy::standard(
                defer_q,
                5,
                Backoff::Fixed { base_secs: 1 },
                30,
                2,
            ))
            .handler(
                standard_q,
                CompleteHandler {
                    pool: pool.clone(),
                    counter_key: standard_key.to_string(),
                },
            )
            .handler(
                cron_q,
                CronSingletonHandler {
                    pool: pool.clone(),
                    counter_key: cron_key.to_string(),
                    lock_name: format!("{cron_q}:singleton-guard"),
                },
            )
            .handler(
                defer_q,
                DeferOnceHandler {
                    pool: pool.clone(),
                    counter_key: defer_key.to_string(),
                },
            )
            // Every-second cron onto the singleton queue.
            .schedule(CronSchedule::new(
                "* * * * * *",
                cron_q,
                json!({ "src": "cron" }),
            ))
            .poll_interval(Duration::from_millis(25))
            .build()
            .await
            .expect("build runtime"),
    );

    // Building the runtime reconciled (seeded) the queue policy rows, which
    // `enqueue` reads for its `max_attempts`/`backoff` defaults. Enqueue the
    // standard and defer work now; the cron queue is fed by the in-process
    // scheduler once the runtime is running.
    for i in 0..STANDARD_JOBS {
        enqueue(
            &pool,
            standard_q,
            &json!({ "n": i }),
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue standard job");
    }
    let defer_id = enqueue(&pool, defer_q, &json!({}), EnqueueOptions::default())
        .await
        .expect("enqueue defer job");

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // All four standard jobs complete.
    {
        let pool = pool.clone();
        wait_for(Duration::from_secs(20), || {
            let pool = pool.clone();
            async move { count_in_state(&pool, standard_q, "completed").await == STANDARD_JOBS as i64 }
        })
        .await;
    }

    // The defer job completes after exactly one defer (attempt-neutral) and one
    // successful run.
    {
        let pool = pool.clone();
        wait_for(Duration::from_secs(20), || {
            let pool = pool.clone();
            async move { count_in_state(&pool, defer_q, "completed").await == 1 }
        })
        .await;
    }

    // At least one cron-driven singleton job completed.
    {
        let pool = pool.clone();
        wait_for(Duration::from_secs(20), || {
            let pool = pool.clone();
            async move { count_in_state(&pool, cron_q, "completed").await >= 1 }
        })
        .await;
    }

    rt.shutdown();
    let _ = run.await;

    // --- Assertions on the lifecycles -------------------------------------

    // Standard queue: every job ran its handler exactly once.
    assert_eq!(
        counter(&pool, standard_key).await,
        STANDARD_JOBS as i64,
        "every standard job completed exactly once"
    );

    // Defer job: completed, ran its work once, and the defer was attempt-neutral.
    let defer_job = claim::get_job(&pool, defer_id.0)
        .await
        .unwrap()
        .expect("defer job row");
    assert_eq!(defer_job.state, JobState::Completed);
    assert_eq!(
        defer_job.defer_count, 1,
        "defer telemetry recorded exactly one deferral"
    );
    // The job was claimed twice (deferred pass + completing pass); the defer
    // refunded the first claim's increment, so the net consumed attempts is 1.
    assert_eq!(
        defer_job.attempts, 1,
        "one defer refunded its claim's attempt: net 1 attempt consumed, not 2"
    );
    assert_eq!(
        counter(&pool, defer_key).await,
        1,
        "the defer handler did its work exactly once (on the post-defer pass)"
    );

    // Cron singleton queue: produced at least one completed job, and never more
    // than one was running at a time is structurally guaranteed by the
    // singleton_loop policy; we assert the work happened.
    let cron_completed = count_in_state(&pool, cron_q, "completed").await;
    assert!(cron_completed >= 1, "cron schedule drove at least one job");
    assert!(
        counter(&pool, cron_key).await >= 1,
        "the cron singleton handler ran"
    );

    // --- History move: terminal rows archived out of the live job table ---

    let live_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.job WHERE state IN ('completed','failed','cancelled')",
    )
    .fetch_one(&pool)
    .await
    .expect("count terminal live rows");
    assert!(live_before >= 1, "there are terminal rows to archive");

    // Archive everything terminal regardless of age (min_age_minutes = 0).
    let moved = archive_terminal_jobs(&pool, 0, 1000)
        .await
        .expect("archive terminal jobs");
    assert_eq!(
        moved, live_before as u64,
        "every terminal live row moved to history"
    );

    // The live table now holds no terminal rows...
    let live_terminal_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.job WHERE state IN ('completed','failed','cancelled')",
    )
    .fetch_one(&pool)
    .await
    .expect("count terminal live rows after");
    assert_eq!(live_terminal_after, 0, "no terminal rows remain live");

    // ...and history holds exactly the moved rows, queryable.
    let history_count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.job_history")
        .fetch_one(&pool)
        .await
        .expect("count history");
    assert_eq!(
        history_count, live_before,
        "history holds exactly the archived rows, none lost or duplicated"
    );

    // A specific archived row (the defer job) is queryable in history with its
    // terminal state and defer telemetry preserved.
    let (hist_state, hist_defers): (String, i32) =
        sqlx::query_as("SELECT state, defer_count FROM cw_core.job_history WHERE id = $1")
            .bind(defer_id.0)
            .fetch_one(&pool)
            .await
            .expect("the defer job is in history");
    assert_eq!(hist_state, "completed");
    assert_eq!(
        hist_defers, 1,
        "defer telemetry survives the move into history"
    );

    // A second archive pass moves nothing: idempotent against the now-empty set.
    let again = archive_terminal_jobs(&pool, 0, 1000)
        .await
        .expect("second archive pass");
    assert_eq!(again, 0, "nothing left to archive");
}
