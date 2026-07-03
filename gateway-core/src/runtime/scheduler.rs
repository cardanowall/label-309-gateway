//! The in-process cron scheduler.
//!
//! Every replica runs the scheduler. For each registered [`CronSchedule`] it
//! computes upcoming occurrences in UTC with croner and, at each occurrence,
//! attempts to gate the enqueue through `cw_core.cron_tick`:
//!
//! ```sql
//! INSERT INTO cw_core.cron_tick (queue, tick_id) VALUES ($queue, $tick)
//! ON CONFLICT DO NOTHING;
//! ```
//!
//! `tick_id` is the deterministic scheduled instant (RFC3339 UTC of the
//! occurrence), so every replica computes the same id and exactly one replica
//! wins the insert and performs the enqueue. There is no leader election. A
//! schedule whose work must never overlap pairs this with a session advisory
//! lock taken inside the handler (see [`super::locks`]).
//!
//! # A tick is a liveness guarantee, not a work producer
//!
//! The winning enqueue is deduped against the queue's own in-flight cron job
//! (the [`CRON_SINGLETON_KEY`] singleton key): if the job a previous tick
//! seeded is still alive — running, retry-scheduled, or parked in a handler
//! deferral — the tick is a no-op. This matters because several handlers
//! self-pace by deferring their own job (the forward scan parks itself for its
//! idle cadence and never completes); without the dedupe every tick would add
//! one more immortal job to the queue, and the population — each member
//! re-claimed the moment its deferral elapses — would grow without bound,
//! multiplying the loop's provider traffic by the number of accumulated jobs.
//! A tick therefore only ever (re)seeds a queue whose previous cron job
//! reached a terminal state.
//!
//! # Catch-up and retry are the same operation
//!
//! Every pass of a schedule's loop fires the *single most-recent occurrence at
//! or before now*, never the whole gap since the last run. On a fresh start
//! that is the bounded catch-up: a process that was down for hours fires the
//! schedule once on restart rather than replaying every interval it slept
//! through. In steady state the loop wakes exactly on the occurrence it slept
//! toward, so the same computation fires the on-time tick. And after a failed
//! attempt (a dropped connection, a Postgres failover, a lock error) the loop
//! retries shortly with the same computation, so a failure that outlasts a
//! whole period is superseded by the newer occurrence instead of replayed. The
//! `cron_tick` gate makes all of this idempotent across replicas and retries:
//! only one attempt per occurrence ever enqueues.
//!
//! A tick failure is therefore never fatal to the schedule — the loop logs and
//! retries, mirroring the sweeper's posture. The only fatal scheduler errors
//! are configuration (an unparseable cron expression fails the start) and a
//! panicked schedule task (surfaced to the runtime supervisor immediately).

use chrono::{DateTime, SubsecRound as _, Utc};
use croner::Cron;
use serde_json::Value;

use super::enqueue::{self, EnqueueOptions};
use crate::{Error, Result};

/// The singleton key every cron-driven enqueue carries.
///
/// One constant for all schedules: the partial unique index on
/// `(queue, singleton_key)` over non-terminal jobs then guarantees at most one
/// live cron-seeded job per queue, however many ticks fire while a handler
/// keeps its job alive by deferring. Ad-hoc (event-driven) enqueues onto the
/// same queues either carry their own keys or none, so they never collide with
/// this namespace.
pub const CRON_SINGLETON_KEY: &str = "cron";

/// A registered recurring enqueue.
#[derive(Debug, Clone)]
pub struct CronSchedule {
    /// Standard 5-field (or 6-field with seconds) cron expression, in UTC.
    pub cron: String,
    /// Queue the occurrence enqueues onto.
    pub queue: String,
    /// Payload enqueued at each occurrence.
    pub payload: Value,
}

impl CronSchedule {
    /// Build a schedule. The cron expression is validated when the scheduler
    /// starts; an invalid expression surfaces as [`crate::Error::Cron`].
    pub fn new(cron: impl Into<String>, queue: impl Into<String>, payload: Value) -> Self {
        Self {
            cron: cron.into(),
            queue: queue.into(),
            payload,
        }
    }

    /// Parse the cron expression, allowing an optional leading seconds field so
    /// both 5-field (`* * * * *`) and 6-field (`* * * * * *`) expressions are
    /// accepted, evaluated in UTC.
    fn parse(&self) -> Result<Cron> {
        croner::parser::CronParser::builder()
            .seconds(croner::parser::Seconds::Optional)
            .build()
            .parse(&self.cron)
            .map_err(|e| Error::Cron(format!("{}: {e}", self.cron)))
    }
}

/// The deterministic id for a single cron occurrence: the RFC3339 UTC instant
/// of the scheduled tick. Shared by all replicas so the `cron_tick` insert
/// dedupes the enqueue.
///
/// The occurrence is truncated to whole seconds before formatting so the id is
/// stable regardless of any sub-second component in the value croner returns:
/// cron resolution is one second, and every replica must format the same tick
/// to the same string for the dedup to hold.
pub fn tick_id(occurrence: DateTime<Utc>) -> String {
    occurrence
        .trunc_subsecs(0)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Gate one occurrence through `cron_tick` and, on a winning insert, enqueue
/// (deduped against the queue's live cron job).
///
/// Returns `true` if this caller won the tick (the `cron_tick` row did not yet
/// exist), `false` if another replica had already claimed the occurrence. The
/// `cron_tick` insert is what serializes replicas; the enqueue only runs for
/// the single winner — and even then it is a no-op when the job a previous
/// tick seeded is still alive (see the module docs: a tick is a liveness
/// guarantee, not a work producer). A self-pacing handler that parks its job
/// with a long deferral must wake on its own schedule, not once per tick.
pub async fn try_enqueue_tick(
    pool: &sqlx::PgPool,
    schedule: &CronSchedule,
    occurrence: DateTime<Utc>,
) -> Result<bool> {
    let tick = tick_id(occurrence);
    let inserted = sqlx::query(
        "INSERT INTO cw_core.cron_tick (queue, tick_id) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&schedule.queue)
    .bind(&tick)
    .execute(pool)
    .await?
    .rows_affected();

    if inserted == 0 {
        // Another replica already gated this exact occurrence.
        return Ok(false);
    }

    enqueue::enqueue_dedupe(
        pool,
        &schedule.queue,
        &schedule.payload,
        EnqueueOptions {
            singleton_key: Some(CRON_SINGLETON_KEY.to_string()),
            ..EnqueueOptions::default()
        },
    )
    .await?;
    Ok(true)
}

/// How long a schedule waits after a failed tick attempt before retrying.
///
/// The retry re-derives the most recent due occurrence and re-gates it through
/// `cron_tick`, so it is idempotent however often it runs; a short interval
/// bounds how long a schedule stays behind after a database blip without
/// hammering a struggling server. Matches the sweeper's reclaim cadence.
const TICK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Run the scheduler for the registered schedules until `shutdown` flips to
/// `true`.
///
/// Each schedule runs in its own task driving the fire-most-recent-occurrence
/// loop (see the module docs: catch-up, the steady-state tick, and the failure
/// retry are one operation). The tasks are supervised together so a panic in
/// any one of them fails the scheduler immediately.
pub async fn run_scheduler(
    pool: sqlx::PgPool,
    schedules: Vec<CronSchedule>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    // Validate every expression up front so a bad schedule fails the whole
    // start rather than silently never firing. Configuration is the only error
    // a schedule can surface: once running, tick failures are retried inside
    // the loop, never propagated.
    let parsed: Vec<(CronSchedule, Cron)> = schedules
        .into_iter()
        .map(|s| {
            let cron = s.parse()?;
            Ok((s, cron))
        })
        .collect::<Result<_>>()?;

    let mut tasks = tokio::task::JoinSet::new();
    for (schedule, cron) in parsed {
        let pool = pool.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(run_one(pool, schedule, cron, shutdown));
    }

    supervise(tasks).await
}

/// Await the schedule tasks, surfacing the first panic the moment it happens.
///
/// `join_next` yields tasks in completion order, so a panicked schedule is
/// observed immediately even while its siblings — steady-state loops that only
/// return at shutdown — are still running. Awaiting the handles in spawn order
/// instead would park the supervisor behind the first never-returning sibling
/// and hide every later failure for the life of the process. On the first
/// panic the set is dropped, aborting the surviving schedule tasks; the
/// runtime supervisor treats the returned error as fatal and winds the whole
/// process down, which is the intended fail-fast.
async fn supervise(mut tasks: tokio::task::JoinSet<()>) -> Result<()> {
    while let Some(joined) = tasks.join_next().await {
        if let Err(join) = joined {
            return Err(Error::Cron(format!("scheduler task panicked: {join}")));
        }
    }
    Ok(())
}

/// Drive a single schedule until shutdown or until it runs out of occurrences.
///
/// Each pass fires the most recent occurrence at or before now, then sleeps
/// until the next occurrence strictly in the future. Waking from that sleep
/// lands exactly on the occurrence slept toward, so the steady-state tick and
/// the startup catch-up are the same computation, and the `cron_tick` gate
/// dedupes both across replicas.
///
/// A failed attempt is logged and retried after [`TICK_RETRY_INTERVAL`] rather
/// than ending the task: a transient database failure must never kill a
/// schedule for the rest of the process lifetime (the failure mode of
/// propagating the error is a silently dead cron). The retry re-derives the
/// most recent due occurrence, so a failure that outlasts a whole period is
/// superseded by the newer occurrence — the same at-most-one-catch-up policy a
/// restart applies.
async fn run_one(
    pool: sqlx::PgPool,
    schedule: CronSchedule,
    cron: Cron,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }

        // Fire the most recent due occurrence, if the schedule has ever had
        // one. find_previous_occurrence(now, inclusive=true) is the latest
        // scheduled instant at or before now; the cron_tick gate makes a no-op
        // of an occurrence any replica (including this one) already fired.
        let now = Utc::now();
        if let Ok(due) = cron.find_previous_occurrence(&now, true) {
            if let Err(err) = try_enqueue_tick(&pool, &schedule, due).await {
                tracing::warn!(
                    queue = %schedule.queue,
                    occurrence = %tick_id(due),
                    error = %err,
                    "cron tick enqueue failed; retrying shortly"
                );
                tokio::select! {
                    _ = tokio::time::sleep(TICK_RETRY_INTERVAL) => {}
                    res = shutdown.changed() => {
                        // The sender dropped or signalled; stop retrying.
                        if res.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                }
                continue;
            }
        }

        // Sleep until the next occurrence strictly after now. Recomputing from
        // the current time each iteration (rather than advancing a cursor)
        // keeps the schedule self-correcting if a tick's work overran.
        let next = match cron.find_next_occurrence(&Utc::now(), false) {
            Ok(next) => next,
            // No further occurrence (e.g. a one-shot year that has passed):
            // nothing more to do for this schedule.
            Err(_) => return,
        };

        let sleep_for = (next - Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);

        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {}
            res = shutdown.changed() => {
                // The sender dropped or signalled; stop accepting new work.
                if res.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A panicked schedule task fails the supervisor promptly even while a
    /// sibling task never returns. This is the property the sequential
    /// spawn-order await violated: the first task here stands in for a
    /// steady-state schedule that only exits at shutdown, and the panic behind
    /// it must still be observed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervise_surfaces_a_panic_behind_a_never_returning_sibling() {
        let mut tasks = tokio::task::JoinSet::new();
        // Spawned FIRST, so a spawn-order await would block on it forever.
        tasks.spawn(std::future::pending::<()>());
        tasks.spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            panic!("schedule task died");
        });

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), supervise(tasks))
            .await
            .expect("the panic must be observed promptly, not queued behind the pending sibling");
        let err = result.expect_err("a panicked schedule task is a fatal scheduler error");
        assert!(
            matches!(err, Error::Cron(ref msg) if msg.contains("panicked")),
            "unexpected error: {err}"
        );
    }

    /// When every schedule task returns cleanly the supervisor returns Ok — the
    /// clean-shutdown path.
    #[tokio::test]
    async fn supervise_returns_ok_when_all_tasks_finish_cleanly() {
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async {});
        tasks.spawn(async {});
        supervise(tasks)
            .await
            .expect("clean task exits are a clean scheduler exit");
    }
}
