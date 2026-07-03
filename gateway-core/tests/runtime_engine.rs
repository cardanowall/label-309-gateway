//! Integration tests for the job runtime against a real Postgres.
//!
//! Gated behind the `pg-tests` feature so the default `cargo test` never needs a
//! database. Every test asserts observable end-state: row columns, lifecycle
//! states, a handler-written counter, or returned values. None assert on log
//! lines or strings.
//!
//! All tests in this binary share one freshly-migrated database (stood up once
//! via the harness) and isolate from each other by using a unique queue name per
//! test, so they can run concurrently without colliding on rows or singleton
//! keys.

#![cfg(feature = "pg-tests")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use gateway_core::runtime::claim::{self};
use gateway_core::runtime::enqueue::{enqueue, enqueue_dedupe, EnqueueOptions};
use gateway_core::runtime::policy::{QueuePolicy, QueuePolicyKind};
use gateway_core::runtime::sweeper::sweep_once;
use gateway_core::runtime::{Backoff, JobContext, JobHandler, JobOutcome, JobState, Runtime};
use gateway_core::testsupport::reset_and_migrate;
use serde_json::json;
use sqlx::{PgPool, Row};
use tokio::sync::OnceCell;

// ---------------------------------------------------------------------------
// Shared database setup.
// ---------------------------------------------------------------------------

/// Guards a single reset+migrate of this binary's dedicated database.
///
/// Each `#[tokio::test]` runs on its own Tokio runtime, and a sqlx pool's
/// background reaper is bound to the runtime that created it: a pool shared
/// across test runtimes goes stale (`PoolTimedOut`) once the first runtime ends.
/// So the database is reset and migrated exactly once, and every test opens its
/// own pool in its own runtime against that already-migrated database. Tests
/// stay isolated by using a unique queue name and counter key each.
static MIGRATED: OnceCell<()> = OnceCell::const_new();

/// Resolve the engine test URL but point it at this binary's own database name,
/// so parallel test binaries each own an isolated database.
fn engine_database_url() -> String {
    let base = gateway_core::testsupport::TestDb::database_url();
    // Swap the final path segment for a binary-specific name.
    let (prefix, rest) = base.rsplit_once('/').expect("url has a database segment");
    let (_db, query) = match rest.split_once('?') {
        Some((db, q)) => (db, Some(q)),
        None => (rest, None),
    };
    match query {
        Some(q) => format!("{prefix}/cardanowall_gateway_test_engine?{q}"),
        None => format!("{prefix}/cardanowall_gateway_test_engine"),
    }
}

/// Reset and migrate the database once, then return a small fresh pool bound to
/// the current test's runtime. Most tests only need a couple of connections.
async fn pool() -> PgPool {
    pool_sized(5).await
}

/// Like [`pool`] but with an explicit connection cap, for tests that spin up a
/// full [`Runtime`] (a persistent NOTIFY listener plus the sweeper and worker
/// churn each need their own connections).
async fn pool_sized(max_connections: u32) -> PgPool {
    let url = engine_database_url();
    MIGRATED
        .get_or_init(|| {
            let url = url.clone();
            async move {
                let setup = reset_and_migrate(&url)
                    .await
                    .expect("stand up and migrate the engine test database");
                // A scratch counter table handlers write to, in the engine
                // schema so the test never touches public.
                sqlx::query(
                    "CREATE TABLE IF NOT EXISTS cw_core.test_counter ( \
                        key text PRIMARY KEY, \
                        value bigint NOT NULL DEFAULT 0 \
                     )",
                )
                .execute(&setup)
                .await
                .expect("create scratch counter table");
                // Drop the setup pool so its connections are not held for the
                // life of the suite; each test opens its own.
                setup.close().await;
            }
        })
        .await;

    sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&url)
        .await
        .expect("connect a per-test pool to the migrated database")
}

/// Insert (or reconcile) a queue policy directly so the free functions under
/// test have the policy row they read.
async fn seed_policy(pool: &PgPool, queue: &str, max_attempts: i32, backoff: Backoff, lease: i32) {
    seed_policy_kind(
        pool,
        queue,
        QueuePolicyKind::Standard,
        max_attempts,
        backoff,
        lease,
    )
    .await;
}

async fn seed_policy_kind(
    pool: &PgPool,
    queue: &str,
    kind: QueuePolicyKind,
    max_attempts: i32,
    backoff: Backoff,
    lease: i32,
) {
    let kind = match kind {
        QueuePolicyKind::Standard => "standard",
        QueuePolicyKind::SingletonLoop => "singleton_loop",
    };
    sqlx::query(
        "INSERT INTO cw_core.queue_policy \
            (queue, policy, max_attempts, backoff, lease_secs, concurrency) \
         VALUES ($1, $2, $3, $4, $5, 8) \
         ON CONFLICT (queue) DO UPDATE SET \
            policy = EXCLUDED.policy, max_attempts = EXCLUDED.max_attempts, \
            backoff = EXCLUDED.backoff, lease_secs = EXCLUDED.lease_secs",
    )
    .bind(queue)
    .bind(kind)
    .bind(max_attempts)
    .bind(sqlx::types::Json(backoff))
    .bind(lease)
    .execute(pool)
    .await
    .expect("seed queue policy");
}

/// A unique queue name per test so concurrent tests never share rows.
fn unique_queue(tag: &str) -> String {
    format!("{tag}-{}", uuid::Uuid::now_v7().simple())
}

async fn job_state(pool: &PgPool, id: uuid::Uuid) -> JobState {
    claim::get_job(pool, id)
        .await
        .expect("load job")
        .expect("job exists")
        .state
}

// ---------------------------------------------------------------------------
// Handlers used by the tests.
// ---------------------------------------------------------------------------

/// Increments a shared counter for every successful attempt, then completes.
/// Used to assert exactly-once / no-double-run.
struct CountingHandler {
    pool: PgPool,
    counter_key: String,
    /// In-process tally too, so a test can assert without a DB round trip.
    seen: Arc<AtomicU64>,
}

impl JobHandler for CountingHandler {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        self.seen.fetch_add(1, Ordering::SeqCst);
        sqlx::query(
            "INSERT INTO cw_core.test_counter (key, value) VALUES ($1, 1) \
             ON CONFLICT (key) DO UPDATE SET value = cw_core.test_counter.value + 1",
        )
        .bind(&self.counter_key)
        .execute(&self.pool)
        .await
        .expect("increment counter");
        JobOutcome::Complete
    }
}

/// Sleeps long enough that the first claimant's lease lapses, then completes.
/// Lets the test reclaim the job out from under it and prove the original
/// worker's completion no-ops.
struct SlowHandler {
    pool: PgPool,
    counter_key: String,
    delay: Duration,
}

impl JobHandler for SlowHandler {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        tokio::time::sleep(self.delay).await;
        sqlx::query(
            "INSERT INTO cw_core.test_counter (key, value) VALUES ($1, 1) \
             ON CONFLICT (key) DO UPDATE SET value = cw_core.test_counter.value + 1",
        )
        .bind(&self.counter_key)
        .execute(&self.pool)
        .await
        .expect("increment counter");
        JobOutcome::Complete
    }
}

async fn counter_value(pool: &PgPool, key: &str) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(value, 0) FROM cw_core.test_counter WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .expect("read counter")
        .unwrap_or(0)
}

/// Panics on any job whose payload carries `{"panic": true}`; every other job is
/// completed after incrementing the shared counter. This lets one runtime
/// dispatch a panicking job alongside ordinary work, so a test can prove the
/// panic is contained: the lease is released, an outcome is recorded, and the
/// worker keeps processing other jobs rather than the loop dying.
struct PanicHandler {
    pool: PgPool,
    counter_key: String,
}

impl JobHandler for PanicHandler {
    async fn handle(&self, ctx: JobContext) -> JobOutcome {
        if ctx.payload.get("panic").and_then(|v| v.as_bool()) == Some(true) {
            // Yield once so the panic crosses an await point: the handler future
            // is suspended and resumed before it unwinds, which is the exact
            // shape the catch boundary has to survive (a panic that is not at the
            // very first poll).
            tokio::task::yield_now().await;
            panic!("handler boom: {}", ctx.job_id);
        }
        sqlx::query(
            "INSERT INTO cw_core.test_counter (key, value) VALUES ($1, 1) \
             ON CONFLICT (key) DO UPDATE SET value = cw_core.test_counter.value + 1",
        )
        .bind(&self.counter_key)
        .execute(&self.pool)
        .await
        .expect("increment counter");
        JobOutcome::Complete
    }
}

/// Panics SYNCHRONOUSLY when `handle` is called — before it ever returns a
/// future to await. `handle` is a plain (non-`async`) method here, so the panic
/// fires while the runtime is *constructing* the handler future, not while
/// polling it. This is the exact shape that escapes a `catch_unwind` placed
/// around the already-built future (`catch_unwind(handler.handle(ctx))`): the
/// future would have to exist before it can be wrapped, and it never does. The
/// containment boundary must therefore wrap construction too.
struct ConstructionPanicHandler;

impl JobHandler for ConstructionPanicHandler {
    fn handle(&self, ctx: JobContext) -> impl std::future::Future<Output = JobOutcome> + Send {
        // The panic happens here, in the body of `handle`, before the returned
        // future is created — so it is raised the moment the worker evaluates
        // `handler.handle(ctx)`, not on first poll of the result.
        panic!("construction-time boom: {}", ctx.job_id);
        // Unreachable: present only to give `handle` a future-typed return so the
        // signature matches the trait. The panic above always diverges first.
        #[allow(unreachable_code)]
        std::future::ready(JobOutcome::Complete)
    }
}

// ---------------------------------------------------------------------------
// Enqueue: in-transaction atomicity.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enqueue_in_tx_commits_with_caller_tx() {
    let pool = pool().await;
    let queue = unique_queue("enq-commit");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    let mut tx = pool.begin().await.expect("begin tx");
    let id = enqueue(
        &mut *tx,
        &queue,
        &json!({"hello": "world"}),
        EnqueueOptions::default(),
    )
    .await
    .expect("enqueue in tx");
    // Not visible outside the open transaction yet.
    assert!(
        claim::get_job(&pool, id.0).await.unwrap().is_none(),
        "uncommitted enqueue must not be visible on the pool"
    );
    tx.commit().await.expect("commit");

    let job = claim::get_job(&pool, id.0)
        .await
        .unwrap()
        .expect("committed job is visible");
    assert_eq!(job.state, JobState::Available);
    assert_eq!(job.queue, queue);
    assert_eq!(
        job.max_attempts, 3,
        "max_attempts defaulted from the policy"
    );
}

#[tokio::test]
async fn enqueue_in_tx_rolls_back_with_caller_tx() {
    let pool = pool().await;
    let queue = unique_queue("enq-rollback");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    let mut tx = pool.begin().await.expect("begin tx");
    let id = enqueue(&mut *tx, &queue, &json!({}), EnqueueOptions::default())
        .await
        .expect("enqueue in tx");
    tx.rollback().await.expect("rollback");

    assert!(
        claim::get_job(&pool, id.0).await.unwrap().is_none(),
        "rolled-back enqueue must leave no row"
    );
}

#[tokio::test]
async fn enqueue_unknown_queue_errors() {
    let pool = pool().await;
    // No policy seeded for this queue.
    let queue = unique_queue("enq-noqueue");
    let err = enqueue(&pool, &queue, &json!({}), EnqueueOptions::default())
        .await
        .expect_err("enqueue onto an unregistered queue must error");
    assert!(
        matches!(&err, gateway_core::Error::UnknownQueue(q) if q == &queue),
        "expected UnknownQueue, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Claim -> complete.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claim_then_complete() {
    let pool = pool().await;
    let queue = unique_queue("claim-complete");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    let id = enqueue(&pool, &queue, &json!({}), EnqueueOptions::default())
        .await
        .unwrap();

    let claimed = claim::claim_batch(&pool, "w1", std::slice::from_ref(&queue), 10)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1, "exactly the one due job is claimed");
    let (job, token) = &claimed[0];
    assert_eq!(job.id, id.0);
    assert_eq!(job.state, JobState::Running);
    assert_eq!(job.attempts, 1, "claim charged one attempt");
    assert!(job.started_at.is_some(), "claim stamps started_at");

    claim::complete(&pool, job.id, *token).await.unwrap();
    let done = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(done.state, JobState::Completed);
    assert!(done.finished_at.is_some());
}

#[tokio::test]
async fn claim_skips_future_run_at() {
    let pool = pool().await;
    let queue = unique_queue("claim-future");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    let future = Utc::now() + chrono::Duration::seconds(3600);
    enqueue(
        &pool,
        &queue,
        &json!({}),
        EnqueueOptions {
            run_at: Some(future),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let claimed = claim::claim_batch(&pool, "w1", std::slice::from_ref(&queue), 10)
        .await
        .unwrap();
    assert!(
        claimed.is_empty(),
        "a job whose run_at is in the future is not due"
    );
}

// ---------------------------------------------------------------------------
// Retry with backoff, then exhaustion -> failed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handler_error_retries_with_backoff_then_fails() {
    let pool = pool().await;
    let queue = unique_queue("retry-exhaust");
    let max_attempts = 3;
    seed_policy(
        &pool,
        &queue,
        max_attempts,
        Backoff::Exponential { base_secs: 10 },
        30,
    )
    .await;

    let id = enqueue(&pool, &queue, &json!({}), EnqueueOptions::default())
        .await
        .unwrap();
    let err = gateway_core::runtime::JobError::new("handler_error", "boom");

    // Attempt 1: claim -> fail. attempts becomes 1, < max, so it retries with a
    // backoff in the future.
    let (job, token) = pop_claim(&pool, &queue, "w1").await;
    assert_eq!(job.attempts, 1);
    let before = Utc::now();
    claim::fail(&pool, job.id, token, job.backoff, job.attempts, &err)
        .await
        .unwrap();
    let after1 = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(after1.state, JobState::Available, "still retriable");
    // Exponential base 10, attempt 1 -> ~10s in the future.
    let delay1 = (after1.run_at - before).num_seconds();
    assert!(
        (8..=12).contains(&delay1),
        "attempt-1 backoff ~10s, got {delay1}s"
    );
    assert!(after1.last_error.is_some(), "failure recorded");
    assert!(after1.claim_token.is_none(), "claim cleared on retry");

    // Move run_at to the past so it is due again, then attempt 2.
    make_due(&pool, id.0).await;
    let (job, token) = pop_claim(&pool, &queue, "w1").await;
    assert_eq!(job.attempts, 2);
    let before = Utc::now();
    claim::fail(&pool, job.id, token, job.backoff, job.attempts, &err)
        .await
        .unwrap();
    let after2 = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(after2.state, JobState::Available);
    // Exponential base 10, attempt 2 -> ~20s.
    let delay2 = (after2.run_at - before).num_seconds();
    assert!(
        (16..=24).contains(&delay2),
        "attempt-2 backoff ~20s, got {delay2}s"
    );

    // Attempt 3 reaches max_attempts: failing now is terminal.
    make_due(&pool, id.0).await;
    let (job, token) = pop_claim(&pool, &queue, "w1").await;
    assert_eq!(job.attempts, 3);
    assert_eq!(job.attempts, job.max_attempts);
    claim::fail(&pool, job.id, token, job.backoff, job.attempts, &err)
        .await
        .unwrap();
    let final_job = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(final_job.state, JobState::Failed, "exhausted -> failed");
    assert!(final_job.finished_at.is_some());
    let recorded = final_job.last_error.expect("last_error recorded");
    assert_eq!(recorded["kind"], "handler_error");
}

#[tokio::test]
async fn large_attempt_backoff_saturates_instead_of_overflowing() {
    let pool = pool().await;
    let queue = unique_queue("backoff-saturate");
    // Exponential base >= 2 is the shape whose doubling can overflow a 64-bit
    // schedule once the attempt count is large; a high attempt budget lets the
    // single job reach the saturation boundary.
    let max_attempts = 70;
    seed_policy(
        &pool,
        &queue,
        max_attempts,
        Backoff::Exponential { base_secs: 2 },
        30,
    )
    .await;

    let id = enqueue(&pool, &queue, &json!({}), EnqueueOptions::default())
        .await
        .unwrap();

    // Drive the consumed-attempt count to 64 directly, then claim so the next
    // fail() runs at attempt 65 (shift 64): base * 2^64 exceeds the 64-bit range
    // and would overflow an unsaturated multiply, raising a database error and
    // stranding the job in 'running'.
    sqlx::query("UPDATE cw_core.job SET attempts = 64 WHERE id = $1")
        .bind(id.0)
        .execute(&pool)
        .await
        .expect("preset attempts to the overflow boundary");

    let (job, token) = pop_claim(&pool, &queue, "w1").await;
    assert_eq!(job.attempts, 65, "claim charged the 65th attempt");
    let err = gateway_core::runtime::JobError::new("handler_error", "boom");
    let before = Utc::now();

    // Must succeed (no overflow error) and re-avail the job rather than strand it.
    claim::fail(&pool, job.id, token, job.backoff, job.attempts, &err)
        .await
        .expect("a large-attempt backoff must not overflow the schedule");

    let after = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(
        after.state,
        JobState::Available,
        "retriable: the saturated retry re-avails the job, never strands it running"
    );
    assert!(after.claim_token.is_none(), "claim cleared on retry");

    // The delay lands at the bounded retry horizon (i32::MAX seconds, ~68 years),
    // not an overflow: the scheduled run_at is a finite, representable future
    // instant and the write committed. The exact ceiling is the runtime's
    // MAX_RETRY_DELAY_SECS; assert the scheduled delay sits at that cap.
    let cap = i32::MAX as i64;
    let scheduled = (after.run_at - before).num_seconds();
    let drift = (scheduled - cap).abs();
    assert!(
        drift <= 5,
        "run_at reflects the bounded retry horizon of {cap}s, got {scheduled}s"
    );
}

// ---------------------------------------------------------------------------
// Attempt-budget bound under lease expiry (regression: a sweeper re-avail of a
// final attempt must not let the next claim run attempt max_attempts + 1).
// ---------------------------------------------------------------------------

/// A final attempt whose worker dies before its fenced `fail()` lands is
/// re-availed by the sweeper with `attempts` unchanged (the sweeper never routes
/// through `fail`, so it never consults the attempt budget). The next `claim_batch`
/// must NOT re-claim and re-increment that exhausted row to `attempts =
/// max_attempts + 1` (which would let a permanently-failing job loop without bound
/// across crashes/lease expiries). Instead the exhausted available row is reaped to
/// terminal `failed`, the same end-state a handler failure on the last attempt
/// reaches. No deadline is set, so `max_attempts` is the sole retry bound, exactly
/// the money-path job shape.
#[tokio::test]
async fn exhausted_job_reavailed_by_sweeper_is_reaped_not_reclaimed() {
    let pool = pool().await;
    let queue = unique_queue("attempt-budget");
    // max_attempts=3, a comfortable 30s lease. The sweep is driven deterministically
    // by backdating the heartbeat below rather than by a real-time sleep, so this
    // test neither races nor depends on the global (all-queue) sweep's reclaim count.
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    // No deadline: the attempt budget is the only terminator, the path the defect
    // subverts.
    let id = enqueue(&pool, &queue, &json!({}), EnqueueOptions::default())
        .await
        .unwrap();

    // Drive the consumed-attempt count to one below max, then claim so this claim
    // charges the FINAL (3rd) attempt and dispatches it.
    sqlx::query("UPDATE cw_core.job SET attempts = 2 WHERE id = $1")
        .bind(id.0)
        .execute(&pool)
        .await
        .expect("preset attempts to one below max");

    let (job, _token) = pop_claim(&pool, &queue, "dying-worker").await;
    assert_eq!(job.attempts, 3, "claim charged the final attempt");
    assert_eq!(job.attempts, job.max_attempts);

    // The worker dies before its fenced fail() lands: it never heartbeats. Backdate
    // the heartbeat past the lease so a sweep reclaims it deterministically, with
    // attempts left at 3 (the sweeper never consults the attempt budget).
    sqlx::query(
        "UPDATE cw_core.job SET heartbeat_at = now() - interval '120 seconds' WHERE id = $1",
    )
    .bind(id.0)
    .execute(&pool)
    .await
    .expect("backdate the heartbeat past the lease");
    sweep_once(&pool).await.unwrap();
    let reavailed = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(
        reavailed.state,
        JobState::Available,
        "the lapsed-lease final attempt is re-availed by the sweeper"
    );
    assert_eq!(
        reavailed.attempts, 3,
        "the sweeper re-avails with attempts unchanged"
    );

    // The next claim must NOT pick this exhausted row and run attempt #4. It is
    // reaped to terminal `failed` instead, and the claim returns no runnable job.
    let claimed = claim::claim_batch(&pool, "fresh-worker", std::slice::from_ref(&queue), 5)
        .await
        .expect("claim");
    assert!(
        claimed.is_empty(),
        "an attempt-exhausted job is never claimed-and-run again"
    );

    let terminal = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(
        terminal.state,
        JobState::Failed,
        "the exhausted job is terminal, not re-claimed at attempts = max_attempts + 1"
    );
    assert_eq!(
        terminal.attempts, 3,
        "attempts never exceeds the budget: no spurious attempt #4 ran"
    );
    assert!(terminal.finished_at.is_some(), "the reaped job is finished");
    let recorded = terminal.last_error.expect("a reaped job records why");
    assert_eq!(recorded["kind"], "attempts_exhausted");
}

/// An attempt-exhausted `available` row with a `run_at` in the FUTURE is reaped
/// to terminal `failed`, not left to wedge the queue. Such a row is otherwise a
/// permanent deadlock for a singleton-loop queue: it is counted in-flight by the
/// singleton index (so the cron re-seed is blocked), never claimed (the budget
/// is spent), never retried, and never swept (the sweeper only touches
/// `running`). Dropping the `run_at <= now()` gate from the reaper terminalises
/// it regardless of when its future run_at falls, freeing the re-seed.
#[tokio::test]
async fn exhausted_available_with_future_run_at_is_reaped_not_left_to_wedge() {
    let pool = pool().await;
    let queue = unique_queue("exhausted-future-runat");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    let id = enqueue(&pool, &queue, &json!({}), EnqueueOptions::default())
        .await
        .unwrap();

    // Put the row in exactly the wedged shape: available, budget spent, and a
    // run_at well in the future (e.g. a backoff scheduled before the attempt
    // count reached the ceiling). Without the fix this row is unreachable by
    // claim, sweep, and the run_at-gated reaper alike.
    sqlx::query(
        "UPDATE cw_core.job SET \
            state = 'available', attempts = max_attempts, \
            run_at = now() + interval '1 hour' \
         WHERE id = $1",
    )
    .bind(id.0)
    .execute(&pool)
    .await
    .expect("force the exhausted-future-run_at shape");

    // A claim pass (which reaps first) must terminalise it even though it is not
    // yet due, and return no runnable job.
    let claimed = claim::claim_batch(&pool, "fresh-worker", std::slice::from_ref(&queue), 5)
        .await
        .expect("claim");
    assert!(
        claimed.is_empty(),
        "an exhausted row with a future run_at is never claimed"
    );

    let terminal = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(
        terminal.state,
        JobState::Failed,
        "the exhausted future-run_at row is terminalised, not left available to wedge the queue"
    );
    assert!(terminal.finished_at.is_some(), "the reaped job is finished");
    let recorded = terminal.last_error.expect("a reaped job records why");
    assert_eq!(recorded["kind"], "attempts_exhausted");
}

/// The reaper must NOT terminalise a legitimately-retrying row even when it is
/// `available` and not yet due. A row with attempts still below max is outside
/// the reaper's `attempts >= max_attempts` predicate, so dropping the run_at
/// gate does not over-reach onto rows that have retries left.
#[tokio::test]
async fn reaper_leaves_a_not_yet_exhausted_future_run_at_row_alone() {
    let pool = pool().await;
    let queue = unique_queue("retrying-future-runat");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    let id = enqueue(&pool, &queue, &json!({}), EnqueueOptions::default())
        .await
        .unwrap();

    // A genuine mid-backoff retry: one attempt below the ceiling, available, and
    // scheduled for the future. The reaper must skip it.
    sqlx::query(
        "UPDATE cw_core.job SET \
            state = 'available', attempts = max_attempts - 1, \
            run_at = now() + interval '1 hour' \
         WHERE id = $1",
    )
    .bind(id.0)
    .execute(&pool)
    .await
    .expect("force the retrying-future-run_at shape");

    // Reaping happens inside claim_batch; the not-due row is also not claimed
    // (run_at is in the future), but it must remain `available`, not be failed.
    let claimed = claim::claim_batch(&pool, "fresh-worker", std::slice::from_ref(&queue), 5)
        .await
        .expect("claim");
    assert!(
        claimed.is_empty(),
        "a not-yet-due retrying row is not claimed this pass"
    );

    let still = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(
        still.state,
        JobState::Available,
        "a row with retries left is never reaped, regardless of its run_at"
    );
    assert!(
        still.finished_at.is_none(),
        "a non-terminalised row carries no finished_at"
    );
}

// ---------------------------------------------------------------------------
// Defer: attempt-neutral, deadline-bounded.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn defer_is_attempt_neutral_then_deadline_fails() {
    let pool = pool().await;
    let queue = unique_queue("defer-deadline");
    seed_policy(&pool, &queue, 5, Backoff::Fixed { base_secs: 1 }, 30).await;

    // A deadline far enough out that the defers below stay within it, but close
    // enough that the final past-deadline defer trips it.
    let deadline = Utc::now() + chrono::Duration::seconds(60);
    let id = enqueue(
        &pool,
        &queue,
        &json!({}),
        EnqueueOptions {
            deadline: Some(deadline),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Defer 3 times. Each defer refunds the attempt the claim charged, so after
    // N claim+defer cycles the consumed-attempt count is back to 0 and
    // defer_count is N.
    let defers = 3;
    for n in 1..=defers {
        let (job, token) = pop_claim(&pool, &queue, "w1").await;
        assert_eq!(
            job.attempts, 1,
            "each claim charges one attempt before defer"
        );
        let until = Utc::now() - chrono::Duration::seconds(1); // immediately due again
        claim::defer(&pool, job.id, token, until).await.unwrap();

        let after = claim::get_job(&pool, id.0).await.unwrap().unwrap();
        assert_eq!(after.state, JobState::Available, "defer re-avails the job");
        assert_eq!(
            after.attempts, 0,
            "defer #{n} refunded the attempt: net 0 consumed"
        );
        assert_eq!(after.defer_count, n, "defer_count is telemetry, increments");
    }

    // Now defer past the deadline: the deadline is the primary lifetime bound,
    // so this fails the job instead of rescheduling it.
    let (job, token) = pop_claim(&pool, &queue, "w1").await;
    let past_deadline = deadline + chrono::Duration::seconds(120);
    claim::defer(&pool, job.id, token, past_deadline)
        .await
        .unwrap();
    let failed = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(
        failed.state,
        JobState::Failed,
        "a defer beyond the deadline fails the job"
    );
    let err = failed.last_error.expect("deadline error recorded");
    assert_eq!(err["kind"], "deadline_exceeded");
}

#[tokio::test]
async fn claim_fails_job_already_past_deadline() {
    let pool = pool().await;
    let queue = unique_queue("claim-deadline");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    // Deadline already in the past at enqueue time.
    let id = enqueue(
        &pool,
        &queue,
        &json!({}),
        EnqueueOptions {
            deadline: Some(Utc::now() - chrono::Duration::seconds(1)),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let claimed = claim::claim_batch(&pool, "w1", std::slice::from_ref(&queue), 10)
        .await
        .unwrap();
    assert!(
        claimed.is_empty(),
        "a job past its deadline is failed at claim, never dispatched"
    );
    let job = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(job.state, JobState::Failed);
    assert_eq!(
        job.last_error.unwrap()["kind"],
        "deadline_exceeded",
        "claim-time deadline breach records the reserved error"
    );
}

// ---------------------------------------------------------------------------
// Concurrency: two claimers over 100 jobs, never double-run.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_claimers_never_double_run() {
    // Two full runtimes share this pool: each keeps a NOTIFY listener plus
    // sweeper and worker churn, so it needs more than the default cap.
    let pool = pool_sized(16).await;
    let queue = unique_queue("concurrent-100");
    let counter_key = format!("counter-{queue}");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    const JOBS: usize = 100;
    for i in 0..JOBS {
        enqueue(&pool, &queue, &json!({ "n": i }), EnqueueOptions::default())
            .await
            .unwrap();
    }

    let seen = Arc::new(AtomicU64::new(0));
    let rt_a = Arc::new(
        build_counting_runtime(&pool, &queue, "worker-a", &counter_key, seen.clone()).await,
    );
    let rt_b = Arc::new(
        build_counting_runtime(&pool, &queue, "worker-b", &counter_key, seen.clone()).await,
    );

    let a = {
        let rt = rt_a.clone();
        tokio::spawn(async move { rt.run().await })
    };
    let b = {
        let rt = rt_b.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // Wait until every job is completed, with a generous bound.
    wait_until(
        &pool,
        &queue,
        JobState::Completed,
        JOBS,
        Duration::from_secs(30),
    )
    .await;

    rt_a.shutdown();
    rt_b.shutdown();
    let _ = a.await;
    let _ = b.await;

    let completed = count_in_state(&pool, &queue, JobState::Completed).await;
    assert_eq!(completed, JOBS as i64, "every job completed exactly once");
    let total = counter_value(&pool, &counter_key).await;
    assert_eq!(
        total, JOBS as i64,
        "handler ran exactly once per job across both workers (no double-run)"
    );
}

// ---------------------------------------------------------------------------
// Stale-worker fencing: reclaim + exactly-once.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stale_worker_is_fenced_after_reclaim() {
    let pool = pool().await;
    let queue = unique_queue("fencing");
    let counter_key = format!("counter-{queue}");
    // Short lease so the sweeper reclaims the slow worker's job quickly.
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 1).await;

    let id = enqueue(&pool, &queue, &json!({}), EnqueueOptions::default())
        .await
        .unwrap();

    // Worker 1 claims the job and (simulated) hangs: we hold its token and never
    // heartbeat, so the lease lapses.
    let (job1, token1) = pop_claim(&pool, &queue, "stale-worker").await;
    assert_eq!(job1.id, id.0);

    // Let the lease (1s) expire, then sweep: the job is re-availed, attempts
    // unchanged (the claim already counted it).
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let report = sweep_once(&pool).await.unwrap();
    assert_eq!(report.reclaimed, 1, "expired-lease job was reclaimed");
    let reclaimed = claim::get_job(&pool, id.0).await.unwrap().unwrap();
    assert_eq!(reclaimed.state, JobState::Available, "reclaim re-avails");
    assert_eq!(
        reclaimed.attempts, 1,
        "reclaim leaves attempts unchanged (claim already counted)"
    );
    assert!(reclaimed.claim_token.is_none(), "reclaim clears the token");

    // Worker 2 claims the reclaimed job and completes it, writing the counter.
    let (job2, token2) = pop_claim(&pool, &queue, "fresh-worker").await;
    assert_ne!(
        token2.0, token1.0,
        "a fresh claim mints a new fencing token"
    );
    sqlx::query(
        "INSERT INTO cw_core.test_counter (key, value) VALUES ($1, 1) \
         ON CONFLICT (key) DO UPDATE SET value = cw_core.test_counter.value + 1",
    )
    .bind(&counter_key)
    .execute(&pool)
    .await
    .unwrap();
    claim::complete(&pool, job2.id, token2).await.unwrap();
    assert_eq!(job_state(&pool, id.0).await, JobState::Completed);

    // Now worker 1 (the stale one) tries to complete with its old token. The
    // fence (claim_token + state='running') no longer matches, so the write
    // no-ops and surfaces as lost ownership.
    let stale = claim::complete(&pool, id.0, token1).await;
    assert!(
        matches!(stale, Err(gateway_core::Error::LostOwnership(j)) if j == id.0),
        "stale worker's completion is fenced out, got {stale:?}"
    );

    // The job stayed completed and the side effect happened exactly once.
    assert_eq!(job_state(&pool, id.0).await, JobState::Completed);
    assert_eq!(
        counter_value(&pool, &counter_key).await,
        1,
        "side effect applied exactly once despite the overlap"
    );
}

// ---------------------------------------------------------------------------
// Dedupe contract.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dedupe_suppresses_active_duplicate_then_allows_after_completion() {
    let pool = pool().await;
    let queue = unique_queue("dedupe");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    let opts = || EnqueueOptions {
        singleton_key: Some("only-one".to_string()),
        ..Default::default()
    };

    // First enqueue inserts.
    let first = enqueue_dedupe(&pool, &queue, &json!({}), opts())
        .await
        .unwrap();
    let first_id = first.expect("first dedupe enqueue inserts a row");

    // Second enqueue while the first is still in-flight is suppressed: None, not
    // an error.
    let second = enqueue_dedupe(&pool, &queue, &json!({}), opts())
        .await
        .unwrap();
    assert!(
        second.is_none(),
        "an in-flight singleton suppresses the duplicate"
    );

    // Drive the first to a terminal state.
    let (job, token) = pop_claim(&pool, &queue, "w1").await;
    assert_eq!(job.id, first_id.0);
    claim::complete(&pool, job.id, token).await.unwrap();

    // With the first completed (terminal rows are excluded from the partial
    // unique index), a new singleton enqueue is allowed again.
    let third = enqueue_dedupe(&pool, &queue, &json!({}), opts())
        .await
        .unwrap();
    let third_id = third.expect("after completion the singleton key is free again");
    assert_ne!(third_id.0, first_id.0, "a genuinely new row was inserted");
}

#[tokio::test]
async fn plain_enqueue_treats_singleton_conflict_as_error() {
    let pool = pool().await;
    let queue = unique_queue("dedupe-strict");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    let opts = || EnqueueOptions {
        singleton_key: Some("strict".to_string()),
        ..Default::default()
    };

    enqueue(&pool, &queue, &json!({}), opts())
        .await
        .expect("first plain enqueue inserts");
    let err = enqueue(&pool, &queue, &json!({}), opts())
        .await
        .expect_err("plain enqueue of an in-flight singleton must error");
    // The collision surfaces as a database (unique-violation) error, not a
    // silent None.
    assert!(
        matches!(err, gateway_core::Error::Database(_)),
        "expected a database unique-violation error, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Singleton-loop policy: one in-flight at a time through the runtime.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn singleton_loop_runs_one_at_a_time() {
    let pool = pool_sized(8).await;
    let queue = unique_queue("singleton-loop");
    let counter_key = format!("counter-{queue}");
    seed_policy_kind(
        &pool,
        &queue,
        QueuePolicyKind::SingletonLoop,
        3,
        Backoff::Fixed { base_secs: 1 },
        30,
    )
    .await;

    const JOBS: usize = 5;
    for _ in 0..JOBS {
        enqueue(&pool, &queue, &json!({}), EnqueueOptions::default())
            .await
            .unwrap();
    }

    let handler = SlowHandler {
        pool: pool.clone(),
        counter_key: counter_key.clone(),
        delay: Duration::from_millis(50),
    };
    let rt = Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("singleton")
            .queue_policy(QueuePolicy {
                queue: queue.clone(),
                policy: QueuePolicyKind::SingletonLoop,
                max_attempts: 3,
                backoff: Backoff::Fixed { base_secs: 1 },
                lease_secs: 30,
                concurrency: 8,
            })
            .poll_interval(Duration::from_millis(25))
            .handler(queue.clone(), handler)
            .build()
            .await
            .unwrap(),
    );

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };
    wait_until(
        &pool,
        &queue,
        JobState::Completed,
        JOBS,
        Duration::from_secs(20),
    )
    .await;
    rt.shutdown();
    let _ = run.await;

    assert_eq!(
        count_in_state(&pool, &queue, JobState::Completed).await,
        JOBS as i64
    );
    assert_eq!(counter_value(&pool, &counter_key).await, JOBS as i64);
}

// ---------------------------------------------------------------------------
// Graceful shutdown: in-flight job finishes, then the loop returns.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn graceful_shutdown_finishes_inflight_job() {
    let pool = pool_sized(8).await;
    let queue = unique_queue("graceful");
    let counter_key = format!("counter-{queue}");
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    let id = enqueue(&pool, &queue, &json!({}), EnqueueOptions::default())
        .await
        .unwrap();

    let handler = SlowHandler {
        pool: pool.clone(),
        counter_key: counter_key.clone(),
        delay: Duration::from_millis(300),
    };
    let rt = Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("graceful")
            .queue_policy(QueuePolicy {
                queue: queue.clone(),
                policy: QueuePolicyKind::Standard,
                max_attempts: 3,
                backoff: Backoff::Fixed { base_secs: 1 },
                lease_secs: 30,
                concurrency: 1,
            })
            .poll_interval(Duration::from_millis(25))
            .handler(queue.clone(), handler)
            .build()
            .await
            .unwrap(),
    );

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // Give the worker time to claim and enter the (slow) handler, then ask it to
    // stop. The in-flight job must still complete.
    tokio::time::sleep(Duration::from_millis(100)).await;
    rt.shutdown();
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("run loop returns promptly after shutdown")
        .expect("join")
        .expect("run ok");

    assert_eq!(
        job_state(&pool, id.0).await,
        JobState::Completed,
        "the in-flight job finished despite the shutdown request"
    );
    assert_eq!(counter_value(&pool, &counter_key).await, 1);
}

// ---------------------------------------------------------------------------
// Panic containment: a handler that panics must not strand its job `running`
// (which would silently kill a recurring single-job subsystem) and must not
// take down the worker loop. The panic is caught, the lease released, a failure
// recorded, and the worker keeps processing other jobs.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn panicking_handler_releases_lease_records_failure_and_keeps_processing() {
    let pool = pool_sized(8).await;
    let queue = unique_queue("panic-contain");
    let counter_key = format!("counter-{queue}");
    // A generous lease: if the panic stranded the job `running`, the row would
    // sit there well past the test's wait window rather than the sweeper masking
    // the bug by reclaiming it. A short lease would let a reclaim hide a stranded
    // row, so the lease is deliberately long and the recovery we assert is the
    // engine's own fenced fail write, not a sweep.
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 120).await;

    // One job that panics, and one ordinary job. Both are claimable at once
    // (concurrency 8), so the ordinary job proves the worker survived the panic.
    // The panic job gets a one-attempt budget so a single panic terminalises it
    // to `failed` — a stable, race-free end state for the assertions below (a
    // retriable job would cycle available->running->available on its backoff and
    // could be observed mid-reclaim).
    let panic_id = enqueue(
        &pool,
        &queue,
        &json!({ "panic": true }),
        EnqueueOptions {
            max_attempts: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let ok_id = enqueue(
        &pool,
        &queue,
        &json!({ "panic": false }),
        EnqueueOptions::default(),
    )
    .await
    .unwrap();

    let handler = PanicHandler {
        pool: pool.clone(),
        counter_key: counter_key.clone(),
    };
    let rt = Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("panic-worker")
            .queue_policy(QueuePolicy {
                queue: queue.clone(),
                policy: QueuePolicyKind::Standard,
                max_attempts: 3,
                backoff: Backoff::Fixed { base_secs: 1 },
                lease_secs: 120,
                concurrency: 8,
            })
            .poll_interval(Duration::from_millis(25))
            // A heartbeat well inside the lease; a stranded heartbeat task would
            // keep refreshing the row and the lease would never look expired.
            .heartbeat_interval(Duration::from_millis(50))
            .handler(queue.clone(), handler)
            .build()
            .await
            .unwrap(),
    );

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // The ordinary job must complete: the worker keeps processing despite the
    // sibling panic.
    wait_until(
        &pool,
        &queue,
        JobState::Completed,
        1,
        Duration::from_secs(20),
    )
    .await;

    // Poll until the panicked attempt has run and recorded its failure. With a
    // 120s lease the only thing that can move the row off `running` this fast is
    // the engine's own fenced fail write firing after the caught panic — not a
    // sweep. A stranded heartbeat task (the original bug) would have kept the row
    // `running` with a live claim token, and this poll would time out.
    let panicked =
        wait_for_recorded_error(&pool, panic_id.0, "handler_panic", Duration::from_secs(10)).await;
    assert_eq!(
        panicked.state,
        JobState::Failed,
        "the one-attempt panicked job terminalises to 'failed', never stranded 'running'"
    );
    assert!(
        panicked.finished_at.is_some(),
        "a terminalised panicked job is finished, proving the fenced fail write ran after the \
         caught panic — the original bug skipped this write entirely and left the row 'running'"
    );

    // The ordinary job completed exactly once.
    assert_eq!(job_state(&pool, ok_id.0).await, JobState::Completed);
    assert_eq!(
        counter_value(&pool, &counter_key).await,
        1,
        "the ordinary job's side effect ran exactly once despite the sibling panic"
    );

    rt.shutdown();
    let _ = run.await;
}

/// A handler that panics SYNCHRONOUSLY at construction time — before its future
/// is ever built, let alone polled — must recover identically to an await-time
/// panic: lease released, a `handler_panic` failure recorded, and the worker
/// keeps processing other jobs. A containment boundary placed only around the
/// already-built future would miss this panic entirely (the future never exists
/// to be wrapped), leaving the row stranded `running` until the sweeper's lease
/// timeout — the silent-dead-subsystem failure the boundary exists to prevent.
#[tokio::test]
async fn construction_time_panic_recovers_like_an_await_time_panic() {
    let pool = pool_sized(8).await;
    let queue = unique_queue("panic-construct");
    // Long lease: a construction panic that escaped the boundary would leave the
    // row `running` well past this test's window, so the recovery we observe is
    // the engine's own fenced fail write, not a sweep masking the bug.
    seed_policy(&pool, &queue, 3, Backoff::Fixed { base_secs: 1 }, 120).await;

    // The construction-panicking job (one-attempt, so a single panic terminalises
    // it to a stable `failed` state) plus an ordinary job to prove the worker
    // loop survived. They run on separate queues with separate handlers so the
    // construction panic is isolated to its own dispatch.
    let panic_id = enqueue(
        &pool,
        &queue,
        &json!({}),
        EnqueueOptions {
            max_attempts: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let ok_queue = unique_queue("panic-construct-ok");
    let ok_counter = format!("counter-{ok_queue}");
    seed_policy(&pool, &ok_queue, 3, Backoff::Fixed { base_secs: 1 }, 120).await;
    let ok_id = enqueue(
        &pool,
        &ok_queue,
        &json!({ "panic": false }),
        EnqueueOptions::default(),
    )
    .await
    .unwrap();

    let rt = Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("construct-panic-worker")
            .queue_policy(QueuePolicy {
                queue: queue.clone(),
                policy: QueuePolicyKind::Standard,
                max_attempts: 3,
                backoff: Backoff::Fixed { base_secs: 1 },
                lease_secs: 120,
                concurrency: 8,
            })
            .queue_policy(QueuePolicy {
                queue: ok_queue.clone(),
                policy: QueuePolicyKind::Standard,
                max_attempts: 3,
                backoff: Backoff::Fixed { base_secs: 1 },
                lease_secs: 120,
                concurrency: 8,
            })
            .poll_interval(Duration::from_millis(25))
            .heartbeat_interval(Duration::from_millis(50))
            .handler(queue.clone(), ConstructionPanicHandler)
            .handler(
                ok_queue.clone(),
                PanicHandler {
                    pool: pool.clone(),
                    counter_key: ok_counter.clone(),
                },
            )
            .build()
            .await
            .unwrap(),
    );

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // The ordinary job on the sibling queue completes: the worker survived the
    // construction-time panic on the other queue's dispatch.
    wait_until(
        &pool,
        &ok_queue,
        JobState::Completed,
        1,
        Duration::from_secs(20),
    )
    .await;
    assert_eq!(job_state(&pool, ok_id.0).await, JobState::Completed);
    assert_eq!(counter_value(&pool, &ok_counter).await, 1);

    // The construction-panicked job recorded a `handler_panic` failure — the SAME
    // recovery path an await-time panic takes — and terminalised, never stranded.
    let panicked =
        wait_for_recorded_error(&pool, panic_id.0, "handler_panic", Duration::from_secs(10)).await;
    assert_eq!(
        panicked.state,
        JobState::Failed,
        "a construction-time panic must terminalise the job, never strand it 'running'"
    );
    assert!(
        panicked.finished_at.is_some(),
        "the fenced fail write ran after the caught construction-time panic"
    );

    rt.shutdown();
    let _ = run.await;
}

/// A recurring single-job subsystem (a `singleton_loop` queue, the shape every
/// cron-driven loop uses) must survive a panicked tick: after the panic is
/// caught and the job re-availed, the *next* claim runs the work to completion.
/// If a panicked tick stranded the job `running`, the singleton's partial unique
/// index would block every future cron enqueue and the subsystem would be dead
/// forever with no alarm — this is the exact failure mode the fix prevents.
#[tokio::test]
async fn panicked_tick_does_not_wedge_a_recurring_singleton_subsystem() {
    let pool = pool_sized(8).await;
    let queue = unique_queue("panic-recur");
    let counter_key = format!("counter-{queue}");
    // A long backoff (30s) so the re-availed panicked job stays `available` long
    // enough to observe deterministically before any re-claim; the recovery flip
    // below resets run_at to now() to override it. A 120s lease so a strand would
    // not be masked by a sweep.
    seed_policy_kind(
        &pool,
        &queue,
        QueuePolicyKind::SingletonLoop,
        5,
        Backoff::Fixed { base_secs: 30 },
        120,
    )
    .await;

    // One singleton job that panics on its first attempt, then (because the
    // PanicHandler keys off the payload) would keep panicking — so to prove
    // recovery we flip the payload to non-panic after the first failure lands.
    let id = enqueue_dedupe(
        &pool,
        &queue,
        &json!({ "panic": true }),
        EnqueueOptions {
            singleton_key: Some("cron".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .expect("seed the singleton job");

    let handler = PanicHandler {
        pool: pool.clone(),
        counter_key: counter_key.clone(),
    };
    let rt = Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("recur-worker")
            .queue_policy(QueuePolicy {
                queue: queue.clone(),
                policy: QueuePolicyKind::SingletonLoop,
                max_attempts: 5,
                backoff: Backoff::Fixed { base_secs: 30 },
                lease_secs: 120,
                concurrency: 8,
            })
            .poll_interval(Duration::from_millis(25))
            .heartbeat_interval(Duration::from_millis(50))
            .handler(queue.clone(), handler)
            .build()
            .await
            .unwrap(),
    );

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // Wait until the first (panicking) attempt has actually run and recorded its
    // failure: the row must carry the `handler_panic` error and must NOT be stuck
    // `running`. Polling on the recorded error (not merely "non-running") avoids
    // catching the freshly-enqueued, never-yet-claimed `available` row.
    let after_panic =
        wait_for_recorded_error(&pool, id.0, "handler_panic", Duration::from_secs(10)).await;
    assert_eq!(
        after_panic.state,
        JobState::Available,
        "the panicked singleton tick re-avails the row for the next tick, never wedges it 'running'"
    );
    assert!(
        after_panic.claim_token.is_none(),
        "the re-availed row has its claim token cleared: the lease was released after the panic"
    );
    assert!(
        after_panic.heartbeat_at.is_none(),
        "the re-availed row has its heartbeat cleared, proving the heartbeat task was stopped and \
         did not leak detached (a leaked heartbeat is what wedged the row in the original bug)"
    );

    // Now make the job stop panicking and become due immediately, simulating a
    // transient panic that clears on the next tick. The same worker, still alive,
    // must claim and complete it: a recurring subsystem recovers on its own. The
    // worker keeps re-claiming and re-panicking the singleton on its backoff, so
    // the flip retries until it lands on an `available` row.
    flip_payload_when_available(
        &pool,
        id.0,
        &json!({ "panic": false }),
        Duration::from_secs(10),
    )
    .await;

    wait_until(
        &pool,
        &queue,
        JobState::Completed,
        1,
        Duration::from_secs(20),
    )
    .await;
    assert_eq!(
        job_state(&pool, id.0).await,
        JobState::Completed,
        "the subsystem recovered: the next tick ran the work to completion"
    );
    assert_eq!(
        counter_value(&pool, &counter_key).await,
        1,
        "the recovered tick produced its side effect exactly once"
    );

    rt.shutdown();
    let _ = run.await;
}

// ---------------------------------------------------------------------------
// Supervision: a failing non-worker loop surfaces even while worker loops poll
// forever, and the failure signals shutdown so every loop drains.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_surfaces_a_failing_loop_and_signals_shutdown() {
    use gateway_core::runtime::scheduler::CronSchedule;

    let pool = pool_sized(8).await;
    let worker_queue = unique_queue("supervise-worker");
    let sched_queue = unique_queue("supervise-sched");
    seed_policy(&pool, &worker_queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;
    seed_policy(&pool, &sched_queue, 3, Backoff::Fixed { base_secs: 1 }, 30).await;

    // A worker loop with no due work polls forever and never returns on its own,
    // which is exactly the steady state that the old sequential `for task.await`
    // blocked on. The sweeper loop also never returns on its own. The scheduler
    // validates every cron expression at startup, so registering an invalid one
    // makes the scheduler loop fail immediately with a typed `Error::Cron`. The
    // supervisor must observe that failure even though it was spawned after the
    // never-returning worker and sweeper loops.
    let counting_handler = CountingHandler {
        pool: pool.clone(),
        counter_key: format!("counter-{worker_queue}"),
        seen: Arc::new(AtomicU64::new(0)),
    };
    let rt = Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("supervise")
            .queue_policy(QueuePolicy {
                queue: worker_queue.clone(),
                policy: QueuePolicyKind::Standard,
                max_attempts: 3,
                backoff: Backoff::Fixed { base_secs: 1 },
                lease_secs: 30,
                concurrency: 1,
            })
            .poll_interval(Duration::from_millis(25))
            .handler(worker_queue.clone(), counting_handler)
            .schedule(CronSchedule::new(
                "not a valid cron expression",
                sched_queue.clone(),
                json!({}),
            ))
            .build()
            .await
            .unwrap(),
    );

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // The failure must surface promptly. If the supervisor awaited the worker
    // loop first (the old sequential bug), the never-returning worker loop would
    // hide the scheduler failure indefinitely and this would hit the timeout.
    let result = tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("run() must return promptly from the failing loop, not block on the worker")
        .expect("join run task");

    let err = result.expect_err("run() returns the first loop failure");
    assert!(
        matches!(err, gateway_core::Error::Cron(_)),
        "the surfaced error is the scheduler's typed cron failure, got {err:?}"
    );

    // run() returning at all proves shutdown was signalled and every loop was
    // drained: the worker and sweeper loops poll forever, so the only way the
    // JoinSet empties (and run() returns) is the supervisor flipping shutdown on
    // the scheduler failure and both loops observing it and returning. A second
    // call to shutdown is harmless, confirming the channel is still usable.
    rt.shutdown();
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Build a standard-policy runtime whose handler counts each successful attempt.
async fn build_counting_runtime(
    pool: &PgPool,
    queue: &str,
    worker: &str,
    counter_key: &str,
    seen: Arc<AtomicU64>,
) -> Runtime {
    let handler = CountingHandler {
        pool: pool.clone(),
        counter_key: counter_key.to_string(),
        seen,
    };
    Runtime::builder(pool.clone())
        .worker_id(worker)
        .queue_policy(QueuePolicy {
            queue: queue.to_string(),
            policy: QueuePolicyKind::Standard,
            max_attempts: 3,
            backoff: Backoff::Fixed { base_secs: 1 },
            lease_secs: 30,
            concurrency: 8,
        })
        .poll_interval(Duration::from_millis(50))
        .handler(queue.to_string(), handler)
        .build()
        .await
        .expect("build runtime")
}

/// Claim exactly one job from the queue, asserting one was available.
async fn pop_claim(
    pool: &PgPool,
    queue: &str,
    worker: &str,
) -> (
    gateway_core::runtime::Job,
    gateway_core::runtime::ClaimToken,
) {
    let mut claimed = claim::claim_batch(pool, worker, std::slice::from_ref(&queue.to_string()), 1)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1, "expected exactly one claimable job");
    claimed.pop().unwrap()
}

/// Force a job to be due now (reset run_at into the past).
async fn make_due(pool: &PgPool, id: uuid::Uuid) {
    sqlx::query("UPDATE cw_core.job SET run_at = now() - interval '1 second' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("make due");
}

async fn count_in_state(pool: &PgPool, queue: &str, state: JobState) -> i64 {
    let state_str = match state {
        JobState::Available => "available",
        JobState::Running => "running",
        JobState::Completed => "completed",
        JobState::Failed => "failed",
        JobState::Cancelled => "cancelled",
    };
    sqlx::query("SELECT count(*) AS c FROM cw_core.job WHERE queue = $1 AND state = $2")
        .bind(queue)
        .bind(state_str)
        .fetch_one(pool)
        .await
        .expect("count")
        .get::<i64, _>("c")
}

/// Poll a single job by id until its recorded `last_error.kind` matches `kind`,
/// then return the row. Panics on timeout. Polling on the recorded error (rather
/// than merely "not running") proves the handler attempt actually ran and its
/// outcome landed, and never matches the freshly-enqueued, never-yet-claimed
/// `available` row.
async fn wait_for_recorded_error(
    pool: &PgPool,
    id: uuid::Uuid,
    kind: &str,
    timeout: Duration,
) -> gateway_core::runtime::Job {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let job = claim::get_job(pool, id)
            .await
            .expect("load job")
            .expect("job exists");
        if job
            .last_error
            .as_ref()
            .and_then(|e| e.get("kind"))
            .and_then(|k| k.as_str())
            == Some(kind)
        {
            return job;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for job {id} to record last_error kind {kind:?}; \
                 state={:?}",
                job.state
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Set a job's payload and make it immediately due, retrying until the row is
/// `available` to update. A worker that keeps re-claiming and re-panicking the
/// job on its backoff would otherwise lose this update to a concurrent reclaim;
/// the fenced `WHERE state = 'available'` plus the retry loop makes the flip land
/// on an idle window deterministically.
async fn flip_payload_when_available(
    pool: &PgPool,
    id: uuid::Uuid,
    payload: &serde_json::Value,
    timeout: Duration,
) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let affected = sqlx::query(
            "UPDATE cw_core.job SET payload = $2, run_at = now() \
             WHERE id = $1 AND state = 'available'",
        )
        .bind(id)
        .bind(sqlx::types::Json(payload))
        .execute(pool)
        .await
        .expect("flip payload")
        .rows_affected();
        if affected == 1 {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for job {id} to be 'available' to flip its payload");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Poll until `target` jobs in the queue reach `state`, or panic on timeout.
async fn wait_until(pool: &PgPool, queue: &str, state: JobState, target: usize, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let n = count_in_state(pool, queue, state).await;
        if n >= target as i64 {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for {target} jobs in {state:?}; reached {n}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
