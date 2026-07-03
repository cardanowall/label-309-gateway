//! Integration coverage for the scheduler, queue-policy reconciliation, and the
//! detached-connection advisory locks. Gated behind `pg-tests` so the default
//! test run never needs a database.
//!
//! These tests drive the real Postgres substrate the engine runs on: they prove
//! the cron-tick gate dedupes enqueues across replicas with no leader, that a
//! drifted policy row is corrected to the code-declared config, and that a
//! session advisory lock is held on a connection the pool cannot recycle out
//! from under it.
//!
//! The harness's `TestDb::fresh()` drops and recreates a single named database,
//! so calling it once per test would make concurrently-running tests race on
//! `CREATE DATABASE`. Instead the database is reset exactly once per binary and
//! shared; every test scopes its rows to a unique queue/lock name so concurrent
//! tests never observe each other's state.

#![cfg(feature = "pg-tests")]

use std::time::Duration;

use gateway_core::runtime::locks::{lock_key, AdvisoryLock};
use gateway_core::runtime::policy::{self, QueuePolicy, QueuePolicyKind, Reconciliation};
use gateway_core::runtime::scheduler::{self, tick_id, CronSchedule};
use gateway_core::runtime::Backoff;
use gateway_core::testsupport::{database_url_with_name, reset_and_migrate, TestDb};
use sqlx::PgPool;
use tokio::sync::OnceCell;

/// Guards a single reset+migrate of the shared test database for this binary.
///
/// Resetting per test would race `CREATE DATABASE` across concurrently-running
/// tests; resetting once and sharing a single `PgPool` does not work either,
/// because each `#[tokio::test]` runs on its own runtime and a pool bound to the
/// first test's runtime dies when that runtime shuts down. So the database is
/// reset exactly once, and each test opens its *own* short-lived pool against
/// the already-migrated database. Tests isolate their rows by queue/lock name.
static RESET: OnceCell<()> = OnceCell::const_new();

/// Ensure the shared database is reset+migrated once, then return a fresh pool
/// owned by the calling test's runtime.
async fn pool() -> PgPool {
    // A binary-private database: reset_and_migrate drops the target with FORCE,
    // so sharing a name with another concurrently-running test binary would
    // evict its backends mid-run.
    let url = database_url_with_name("cardanowall_gateway_test_scheduler");
    RESET
        .get_or_init(|| async {
            // The returned pool is discarded; we only need the reset+migrate to
            // have happened. Each test connects its own pool below.
            reset_and_migrate(&url)
                .await
                .expect("reset the test database");
        })
        .await;
    PgPool::connect(&url)
        .await
        .expect("connect to the migrated test database")
}

/// Seed a policy row so `enqueue` (which resolves defaults from `queue_policy`)
/// can insert jobs for the queue under test.
async fn seed_policy(pool: &PgPool, queue: &str) {
    let declared = QueuePolicy::standard(queue, 5, Backoff::Fixed { base_secs: 10 }, 30, 4);
    policy::reconcile(pool, &declared)
        .await
        .expect("seeding the queue policy should succeed");
}

/// Count rows for a single queue in a table the scheduler writes.
async fn count_for_queue(pool: &PgPool, table: &'static str, queue: &str) -> i64 {
    let sql = match table {
        "cron_tick" => "SELECT count(*) FROM cw_core.cron_tick WHERE queue = $1",
        "job" => "SELECT count(*) FROM cw_core.job WHERE queue = $1",
        other => panic!("unsupported table {other}"),
    };
    sqlx::query_scalar(sql)
        .bind(queue)
        .fetch_one(pool)
        .await
        .expect("scoped count query should succeed")
}

// ---------------------------------------------------------------------------
// Scheduler: cron-tick gate dedupes enqueues with no leader.
// ---------------------------------------------------------------------------

/// Concurrent gating of the *same* occurrence by many callers (standing in for
/// many replicas) must produce exactly one winning enqueue: one `cron_tick` row
/// and one `job` row for that tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cron_tick_gate_admits_exactly_one_winner_per_occurrence() {
    let pool = pool().await;
    let queue = "scheduler_dedup";
    seed_policy(&pool, queue).await;

    let schedule = CronSchedule::new("* * * * *", queue, serde_json::json!({"tick": true}));
    let occurrence = chrono::Utc::now();

    // Eight tasks race to gate the identical occurrence. Only the cron_tick
    // insert serializes them; exactly one should win and enqueue.
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let schedule = schedule.clone();
        tasks.push(tokio::spawn(async move {
            scheduler::try_enqueue_tick(&pool, &schedule, occurrence)
                .await
                .expect("gating an occurrence should not error")
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.expect("task should not panic") {
            winners += 1;
        }
    }

    assert_eq!(winners, 1, "exactly one racer should win the occurrence");
    assert_eq!(
        count_for_queue(&pool, "cron_tick", queue).await,
        1,
        "the occurrence should have produced exactly one cron_tick row"
    );
    assert_eq!(
        count_for_queue(&pool, "job", queue).await,
        1,
        "the single winner should have enqueued exactly one job"
    );

    // The cron_tick id is the deterministic RFC3339 instant of the occurrence,
    // so every replica computes the same gate key.
    let stored_tick: String =
        sqlx::query_scalar("SELECT tick_id FROM cw_core.cron_tick WHERE queue = $1")
            .bind(queue)
            .fetch_one(&pool)
            .await
            .expect("the cron_tick row should be readable");
    assert_eq!(stored_tick, tick_id(occurrence));
}

/// Two independent scheduler instances running the same fast (every-second)
/// schedule over a window must keep exactly ONE live job on the queue, however
/// many ticks fire. With no worker consuming the queue the first tick's job
/// stays `available`, so every later tick must dedupe against it: a tick is a
/// liveness guarantee, not a work producer. This is the regression guard for
/// the unbounded cron-job pile-up that multiplied a self-deferring loop's
/// provider traffic by the number of accumulated jobs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_schedulers_keep_exactly_one_live_cron_job() {
    let pool = pool().await;
    let queue = "scheduler_every_second";
    seed_policy(&pool, queue).await;

    // Six-field expression with a seconds field: fire every second.
    let schedule = CronSchedule::new("* * * * * *", queue, serde_json::json!({"src": "cron"}));

    let (tx, rx) = tokio::sync::watch::channel(false);

    // Two "replicas" sharing the same schedule and database.
    let a = tokio::spawn(scheduler::run_scheduler(
        pool.clone(),
        vec![schedule.clone()],
        rx.clone(),
    ));
    let b = tokio::spawn(scheduler::run_scheduler(
        pool.clone(),
        vec![schedule.clone()],
        rx.clone(),
    ));

    // Let several ticks elapse, then signal shutdown and join.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    tx.send(true).expect("shutdown signal should send");
    a.await
        .expect("scheduler A task should not panic")
        .expect("scheduler A should exit cleanly");
    b.await
        .expect("scheduler B task should not panic")
        .expect("scheduler B should exit cleanly");

    let ticks = count_for_queue(&pool, "cron_tick", queue).await;
    let jobs = count_for_queue(&pool, "job", queue).await;

    // The core invariant: the first tick seeds one job and every later tick
    // (from either replica) dedupes against it while it is still alive, so the
    // queue never accumulates a second cron job.
    assert_eq!(
        jobs, 1,
        "ticks must dedupe against the still-live cron job, found {jobs} jobs for {ticks} ticks"
    );
    // Over ~3.5s of every-second ticks there must be several occurrences; the
    // bounded catch-up also fires the most-recent missed tick on startup, so at
    // least a couple are guaranteed even on a slow runner.
    assert!(
        ticks >= 2,
        "expected multiple ticks over the window, found {ticks}"
    );
    // The seeded job carries the cron singleton key the dedupe rests on.
    let key: Option<String> =
        sqlx::query_scalar("SELECT singleton_key FROM cw_core.job WHERE queue = $1")
            .bind(queue)
            .fetch_one(&pool)
            .await
            .expect("the cron job row should be readable");
    assert_eq!(
        key.as_deref(),
        Some(scheduler::CRON_SINGLETON_KEY),
        "a cron-seeded job must carry the cron singleton key"
    );
}

/// Startup catch-up enqueues at most the single most-recent missed occurrence,
/// never the whole gap. A schedule that has not run for a long time fires once
/// on start, not once per interval since the epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn catch_up_enqueues_at_most_one_missed_tick() {
    let pool = pool().await;
    let queue = "scheduler_catchup";
    seed_policy(&pool, queue).await;

    // Every-minute schedule: the catch-up considers the most-recent minute
    // boundary at or before now. Run briefly and shut down before the next
    // minute boundary so only the catch-up tick can have fired.
    let schedule = CronSchedule::new("* * * * *", queue, serde_json::json!({"src": "catchup"}));
    let (tx, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(scheduler::run_scheduler(pool.clone(), vec![schedule], rx));

    // A short window: long enough for catch-up to run, far shorter than the
    // minute cadence so no steady-state tick is due.
    tokio::time::sleep(Duration::from_millis(500)).await;
    tx.send(true).expect("shutdown should signal");
    task.await
        .expect("scheduler task should not panic")
        .expect("scheduler should exit cleanly");

    let ticks = count_for_queue(&pool, "cron_tick", queue).await;
    assert_eq!(
        ticks, 1,
        "catch-up must enqueue exactly one missed tick, not replay the gap"
    );
    assert_eq!(
        count_for_queue(&pool, "job", queue).await,
        1,
        "the single catch-up tick must enqueue exactly one job"
    );
}

/// A transient database failure during a tick must not kill the schedule: the
/// loop logs, retries on its short retry cadence, and fires once the database
/// recovers. Before the fix, the first failed `try_enqueue_tick` ended the
/// schedule's task for the rest of the process lifetime — a silently dead cron.
///
/// Runs on its own private database (not this binary's shared one) because it
/// breaks and restores the `cron_tick` table to simulate the outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transient_tick_failure_is_retried_not_fatal() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    let queue = "scheduler_retry";
    seed_policy(&pool, queue).await;

    // Break the tick gate so every enqueue attempt errors like a dropped
    // connection would.
    sqlx::query("ALTER TABLE cw_core.cron_tick RENAME TO cron_tick_broken")
        .execute(&pool)
        .await
        .expect("hide cron_tick");

    let schedule = CronSchedule::new("* * * * * *", queue, serde_json::json!({"src": "retry"}));
    let (tx, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(scheduler::run_scheduler(pool.clone(), vec![schedule], rx));

    // Let at least one attempt fail (the catch-up fires immediately). The
    // scheduler must still be running: the pre-fix behavior ended it here.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        !task.is_finished(),
        "a failing tick must not end the scheduler"
    );

    // Heal the database and observe the schedule recover: a tick lands and its
    // job is enqueued, without any restart of the scheduler.
    sqlx::query("ALTER TABLE cw_core.cron_tick_broken RENAME TO cron_tick")
        .execute(&pool)
        .await
        .expect("restore cron_tick");

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let ticks = count_for_queue(&pool, "cron_tick", queue).await;
        let jobs = count_for_queue(&pool, "job", queue).await;
        if ticks >= 1 && jobs >= 1 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = tx.send(true);
            let _ = task.await;
            panic!(
                "the schedule did not recover after the transient failure cleared \
                 (ticks: {ticks}, jobs: {jobs})"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tx.send(true).expect("shutdown signal should send");
    task.await
        .expect("scheduler task should not panic")
        .expect("the scheduler exits cleanly after riding out the failure");
}

// ---------------------------------------------------------------------------
// Queue-policy reconciliation.
// ---------------------------------------------------------------------------

/// A row that drifted from the code-declared config (here, manually corrupted to
/// simulate an older deploy's values) is corrected to match the code, reported
/// as `Updated`, and the persisted row equals the declared policy afterward.
#[tokio::test]
async fn reconcile_corrects_a_drifted_policy_row() {
    let pool = pool().await;
    let queue = "drift_queue";

    let declared = QueuePolicy::standard(queue, 7, Backoff::Exponential { base_secs: 4 }, 45, 3);

    // First reconcile inserts.
    assert_eq!(
        policy::reconcile(&pool, &declared).await.expect("insert"),
        Reconciliation::Inserted
    );
    // Idempotent second pass leaves it unchanged.
    assert_eq!(
        policy::reconcile(&pool, &declared).await.expect("noop"),
        Reconciliation::Unchanged
    );

    // Corrupt the stored row to a stale configuration directly in the DB,
    // simulating drift from a previous deploy.
    sqlx::query(
        "UPDATE cw_core.queue_policy \
         SET policy = 'singleton_loop', max_attempts = 1, \
             backoff = '{\"kind\":\"fixed\",\"base_secs\":99}'::jsonb, \
             lease_secs = 999, concurrency = 99 \
         WHERE queue = $1",
    )
    .bind(queue)
    .execute(&pool)
    .await
    .expect("manual corruption should apply");

    // Reconciling against the code config detects the drift and updates.
    assert_eq!(
        policy::reconcile(&pool, &declared)
            .await
            .expect("reconcile should succeed"),
        Reconciliation::Updated,
        "a drifted row must be reported as updated"
    );

    // The persisted row now equals the declared policy: code is the source of
    // truth.
    let stored = policy::load(&pool, queue)
        .await
        .expect("load should succeed")
        .expect("the row should exist");
    assert_eq!(stored, declared, "the row must match the declared config");
    assert_eq!(stored.policy, QueuePolicyKind::Standard);
    assert_eq!(stored.max_attempts, 7);
    assert_eq!(stored.lease_secs, 45);
    assert_eq!(stored.concurrency, 3);
    assert_eq!(stored.backoff, Backoff::Exponential { base_secs: 4 });

    // And a final reconcile is again a no-op.
    assert_eq!(
        policy::reconcile(&pool, &declared).await.expect("noop"),
        Reconciliation::Unchanged
    );
}

// ---------------------------------------------------------------------------
// Detached-connection session advisory locks.
// ---------------------------------------------------------------------------

/// Two guards for DISTINCT names never contend: each name derives its own
/// 64-bit key, so holding one lock leaves the other immediately acquirable.
/// (With the historical 32-bit `hashtext` derivation, distinct names could
/// collide onto one key and serialize spuriously.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn distinct_names_lock_independently() {
    let pool = pool().await;

    let held = AdvisoryLock::acquire(&pool, "wallet:lock-independence-a")
        .await
        .expect("first acquire should succeed");
    let other = AdvisoryLock::try_acquire(&pool, "wallet:lock-independence-b")
        .await
        .expect("try_acquire should not error")
        .expect("a different name must not contend with the held lock");

    assert_ne!(held.key(), other.key(), "distinct names share a key");
    other.release().await.expect("release b");
    held.release().await.expect("release a");
}

/// While one guard holds the lock, a non-blocking second acquire fails fast
/// (returns `None`); after the holder releases, a fresh acquire succeeds. This
/// is the non-overlapping primitive a singleton_loop queue relies on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn try_acquire_fails_fast_while_held_and_succeeds_after_release() {
    let pool = pool().await;
    let name = "singleton-guard";

    let held = AdvisoryLock::acquire(&pool, name)
        .await
        .expect("first acquire should succeed");
    assert_eq!(held.key(), lock_key(name));

    // A second session cannot take the lock: it fails fast rather than blocking.
    let contender = AdvisoryLock::try_acquire(&pool, name)
        .await
        .expect("try_acquire should not error");
    assert!(
        contender.is_none(),
        "a second acquirer must not get the lock while it is held"
    );

    // Releasing frees it for the next acquirer.
    held.release().await.expect("release should succeed");

    let reacquired = AdvisoryLock::try_acquire(&pool, name)
        .await
        .expect("try_acquire should not error")
        .expect("the lock should be free after release");
    reacquired.release().await.expect("release should succeed");
}

/// A blocking `acquire` against a held lock does not return until the holder
/// releases. We start a blocking acquire on a second task, prove it has not
/// completed while the lock is held, then release and observe it complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acquire_blocks_until_holder_releases() {
    let pool = pool().await;
    let name = "blocking-guard";

    let held = AdvisoryLock::acquire(&pool, name)
        .await
        .expect("first acquire should succeed");

    // A second task blocks inside acquire while the lock is held.
    let pool2 = pool.clone();
    let waiter = tokio::spawn(async move {
        AdvisoryLock::acquire(&pool2, "blocking-guard")
            .await
            .expect("blocked acquire should eventually succeed")
    });

    // Give the waiter time to reach the blocking pg_advisory_lock call; it must
    // not have completed because the lock is still held.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !waiter.is_finished(),
        "a blocking acquire must not complete while the lock is held"
    );

    // Releasing lets the blocked waiter proceed.
    held.release().await.expect("release should succeed");
    let acquired = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("the blocked acquire should complete promptly after release")
        .expect("waiter task should not panic");
    acquired.release().await.expect("release should succeed");
}

/// The lock lives on a connection detached from the pool, so checking
/// connections in and out of the pool (which recycles them) does not disturb the
/// held lock: a contender still fails to acquire after a full pool checkout
/// cycle. This is the property a pooled/transaction-scoped lock would violate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lock_survives_unrelated_pool_checkout_cycle() {
    let pool = pool().await;
    let name = "dedicated-conn-discipline";

    let held = AdvisoryLock::acquire(&pool, name)
        .await
        .expect("acquire should succeed");

    // Churn the pool: acquire and drop several connections, running work on each
    // so the pool exercises checkout/return/recycle. If the lock had been taken
    // on a pooled connection, one of these recycled checkouts could carry (and
    // then drop) it.
    for _ in 0..6 {
        let mut conn = pool.acquire().await.expect("pool checkout should work");
        let one: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&mut *conn)
            .await
            .expect("query on a pooled connection should work");
        assert_eq!(one, 1);
        drop(conn);
    }

    // The lock is still held: a contender on a fresh detached connection cannot
    // take it.
    let contender = AdvisoryLock::try_acquire(&pool, name)
        .await
        .expect("try_acquire should not error");
    assert!(
        contender.is_none(),
        "the lock must survive an unrelated pool checkout cycle"
    );

    held.release().await.expect("release should succeed");
}

/// Dropping a guard without calling `release` still frees the lock: ending the
/// detached session releases it server-side. A subsequent acquire succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_guard_releases_the_lock() {
    let pool = pool().await;
    let name = "drop-releases";

    {
        let _held = AdvisoryLock::acquire(&pool, name)
            .await
            .expect("acquire should succeed");
        let contender = AdvisoryLock::try_acquire(&pool, name)
            .await
            .expect("try_acquire should not error");
        assert!(contender.is_none(), "lock should be held inside the scope");
    } // _held dropped here without release()

    // The Drop impl spawns the connection close; give it a moment to end the
    // session so the server releases the lock, then poll until free. Polling
    // (rather than a fixed sleep) keeps the test robust under load.
    let mut acquired = None;
    for _ in 0..50 {
        if let Some(guard) = AdvisoryLock::try_acquire(&pool, name)
            .await
            .expect("try_acquire should not error")
        {
            acquired = Some(guard);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let guard = acquired.expect("the lock should be released after the guard dropped");
    guard.release().await.expect("release should succeed");
}
