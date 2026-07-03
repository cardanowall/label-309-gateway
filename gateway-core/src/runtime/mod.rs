//! The job runtime.
//!
//! Jobs live in the flat `cw_core.job` table and move through the states
//! `available -> running -> {completed | failed | cancelled}`, with `running`
//! able to return to `available` via retry, sweeper reclaim, or a handler
//! deferral.
//!
//! # Ownership and fencing
//!
//! A claim stamps a fresh [`ClaimToken`] onto the row. Every subsequent write
//! the worker makes (heartbeat, complete, fail, defer) guards on that token and
//! on `state = 'running'`. If the sweeper reclaimed the job because the lease
//! expired, the original worker's token no longer matches, so its writes update
//! zero rows. The worker treats a zero-row update as lost ownership
//! ([`crate::Error::LostOwnership`]) and stops producing side effects. This is the
//! mechanism that makes at-least-once delivery safe even when a slow worker and
//! a fresh claimant briefly overlap.
//!
//! # Lifetime bounds
//!
//! `max_attempts` bounds retries; the per-job `deadline` is the primary
//! wall-clock lifetime bound and is enforced both when a job is claimed and
//! when a handler defers it. A deadline breach fails the job with
//! [`JobError::deadline_exceeded`].

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

pub mod claim;
pub mod enqueue;
pub mod locks;
pub mod policy;
pub mod scheduler;
pub mod sweeper;
pub mod worker;

use crate::{Error, Result};

/// A job's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum JobState {
    /// Ready to be claimed once `run_at` has passed.
    Available,
    /// Claimed by a worker and in flight.
    Running,
    /// The handler finished successfully.
    Completed,
    /// The job exhausted its attempts or breached its deadline.
    Failed,
    /// The job was cancelled before completion.
    Cancelled,
}

/// Retry backoff strategy for a queue/job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Backoff {
    /// A constant delay between attempts. Payment queues use this so retry
    /// timing is predictable regardless of attempt count.
    Fixed {
        /// The delay applied before every retry.
        base_secs: u32,
    },
    /// A doubling delay: `base_secs * 2^(attempt-1)`.
    Exponential {
        /// The first retry's delay; each subsequent retry doubles it.
        base_secs: u32,
    },
}

impl Backoff {
    /// Compute the delay before the retry following `attempt` (1-based number of
    /// attempts already consumed).
    ///
    /// Fixed backoff returns the same delay regardless of attempt count.
    /// Exponential backoff doubles per attempt: `base_secs * 2^(attempt-1)`.
    /// The doubling is saturated and then clamped to the largest representable
    /// delay, so however large the attempt count grows the result is always a
    /// finite, in-range duration rather than an overflow or a panic.
    pub fn delay(&self, attempt: u32) -> chrono::Duration {
        let secs = match *self {
            Backoff::Fixed { base_secs } => i64::from(base_secs),
            Backoff::Exponential { base_secs } => {
                let shift = attempt.saturating_sub(1).min(62);
                i64::from(base_secs).saturating_mul(1i64 << shift)
            }
        };
        // chrono::Duration is backed by milliseconds, so its second range tops
        // out below i64::MAX seconds; clamp to that bound so a saturated product
        // produces the longest representable delay instead of panicking.
        chrono::Duration::try_seconds(secs).unwrap_or(chrono::Duration::MAX)
    }
}

/// An opaque per-claim fencing token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimToken(pub Uuid);

/// A persisted job row, as returned by claim and inspection queries.
#[derive(Debug, Clone)]
pub struct Job {
    /// UUIDv7 primary key (time-ordered).
    pub id: Uuid,
    /// The queue the job belongs to.
    pub queue: String,
    /// Opaque caller payload.
    pub payload: Value,
    /// Current lifecycle state.
    pub state: JobState,
    /// Earliest time the job may be claimed.
    pub run_at: DateTime<Utc>,
    /// Attempts consumed so far (incremented by each claim).
    pub attempts: i32,
    /// Maximum attempts before the job is failed.
    pub max_attempts: i32,
    /// Retry backoff strategy.
    pub backoff: Backoff,
    /// Singleton dedupe key, if any.
    pub singleton_key: Option<String>,
    /// The token of the current claim, if claimed.
    pub claim_token: Option<Uuid>,
    /// Identifier of the worker that holds the current claim.
    pub claimed_by: Option<String>,
    /// Last heartbeat from the claiming worker.
    pub heartbeat_at: Option<DateTime<Utc>>,
    /// Number of times the handler voluntarily deferred this job (telemetry).
    pub defer_count: i32,
    /// Hard wall-clock lifetime bound, if any.
    pub deadline: Option<DateTime<Utc>>,
    /// Structured last failure/defer reason.
    pub last_error: Option<Value>,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// When the job first entered `running`.
    pub started_at: Option<DateTime<Utc>>,
    /// When the job reached a terminal state.
    pub finished_at: Option<DateTime<Utc>>,
}

/// A structured error reason recorded against a job.
///
/// The `kind` is a stable machine-readable discriminator; reserved kinds the
/// engine itself produces include `deadline_exceeded` (deadline breach) and
/// `handler_error` (a handler returned [`JobOutcome::Fail`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobError {
    /// Machine-readable error discriminator.
    pub kind: String,
    /// Human-readable detail.
    pub message: String,
}

impl JobError {
    /// Construct a job error from a kind and message.
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
        }
    }

    /// The reserved error a deadline breach records.
    pub fn deadline_exceeded() -> Self {
        Self::new("deadline_exceeded", "job deadline passed before completion")
    }
}

/// The context a handler is invoked with for one attempt at one job.
///
/// `is_final_attempt` and `defer_count` let handlers branch on the last attempt
/// (for example, an upload/submit/refund handler choosing whether to give up or
/// keep deferring).
#[derive(Debug, Clone)]
pub struct JobContext {
    /// The job's id.
    pub job_id: Uuid,
    /// The queue the job belongs to.
    pub queue: String,
    /// The job's payload.
    pub payload: Value,
    /// 1-based attempt number for this invocation.
    pub attempt: i32,
    /// True when this is the last attempt `max_attempts` allows.
    pub is_final_attempt: bool,
    /// How many times this job has been deferred so far.
    pub defer_count: i32,
}

/// What a handler asks the runtime to do with a job after an attempt.
#[derive(Debug, Clone)]
pub enum JobOutcome {
    /// The job succeeded; move it to `completed`.
    Complete,
    /// Re-schedule the job for `until` without consuming an attempt. Deferral
    /// is first-class: it refunds the attempt the claim charged and bumps
    /// `defer_count`. Still bounded by the job's deadline.
    Defer {
        /// When the job should next become available.
        until: DateTime<Utc>,
    },
    /// The attempt failed. The runtime retries (if attempts remain) or fails
    /// the job, recording `error`.
    Fail {
        /// The structured failure reason.
        error: JobError,
    },
}

/// A handler that processes jobs for one or more queues.
///
/// Handlers must be idempotent: the runtime guarantees at-least-once delivery,
/// so a job may be processed more than once if a worker's lease lapses mid-flight.
pub trait JobHandler: Send + Sync + 'static {
    /// Process a single attempt at a single job.
    fn handle(&self, ctx: JobContext) -> impl std::future::Future<Output = JobOutcome> + Send;
}

/// Type-erased handler registry keyed by queue name.
type HandlerMap = std::collections::HashMap<String, std::sync::Arc<dyn worker::ErasedHandler>>;

/// How often the sweeper runs a reclaim pass. The lease is the real bound on
/// staleness; the sweep cadence just decides how promptly an expired lease is
/// noticed, so a short fixed interval is fine.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Default fallback poll cadence for a worker loop when no NOTIFY arrives.
const DEFAULT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Default heartbeat refresh cadence for an in-flight job. Must be well under
/// the shortest queue lease so a live worker never looks expired to the sweeper.
const DEFAULT_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Builder for a [`Runtime`].
///
/// Registers queue policies, handlers, and cron schedules, then `build`s a
/// runtime bound to a pool.
pub struct RuntimeBuilder {
    pool: sqlx::PgPool,
    worker_id: String,
    policies: Vec<policy::QueuePolicy>,
    handlers: HandlerMap,
    schedules: Vec<scheduler::CronSchedule>,
    poll_interval: std::time::Duration,
    heartbeat_interval: std::time::Duration,
}

impl RuntimeBuilder {
    /// Start a new builder against a connection pool.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            pool,
            worker_id: String::new(),
            policies: Vec::new(),
            handlers: HandlerMap::new(),
            schedules: Vec::new(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
        }
    }

    /// Set the identifier this runtime stamps onto claims (`claimed_by`).
    pub fn worker_id(mut self, worker_id: impl Into<String>) -> Self {
        self.worker_id = worker_id.into();
        self
    }

    /// Register the queue-policy configuration this runtime declares. At
    /// startup the runtime reconciles these against the `queue_policy` rows.
    pub fn queue_policy(mut self, policy: policy::QueuePolicy) -> Self {
        self.policies.push(policy);
        self
    }

    /// Register a handler for a queue.
    pub fn handler<H: JobHandler>(mut self, queue: impl Into<String>, handler: H) -> Self {
        self.handlers
            .insert(queue.into(), std::sync::Arc::new(handler));
        self
    }

    /// Register a cron schedule that enqueues onto a queue.
    pub fn schedule(mut self, schedule: scheduler::CronSchedule) -> Self {
        self.schedules.push(schedule);
        self
    }

    /// Override the fallback poll interval for the worker loops (the cadence the
    /// claim loop uses when no NOTIFY wakes it). Primarily a test knob.
    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Override how often an in-flight job's heartbeat is refreshed. Must stay
    /// comfortably under the shortest queue lease. Primarily a test knob.
    pub fn heartbeat_interval(mut self, interval: std::time::Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Reconcile queue policies and provision the engine's partitioned tables,
    /// then produce a runtime handle ready to be started.
    ///
    /// Each declared policy is upserted into `cw_core.queue_policy` via
    /// [`policy::reconcile`]: a missing row is inserted, a drifted row is updated
    /// to match the code-declared config (and logged), and a matching row is left
    /// untouched. The persisted rows are the live source of truth the claim,
    /// retry, and sweep paths read, so reconciliation must complete before any
    /// work is claimed.
    ///
    /// The engine's range-partitioned tables (`job_history`, `subject_event`)
    /// are provisioned here for the same reason: `subject_event` is appended on
    /// the publish hot path, and its monthly partitions are otherwise created
    /// only by the daily maintenance job. A fresh deployment — or one restarted
    /// after the months provisioned at its last run have lapsed — must not
    /// depend on that job having ever fired, so the current month plus the
    /// lookahead are guaranteed synchronously, before any loop or route can
    /// insert.
    pub async fn build(self) -> Result<Runtime> {
        for declared in &self.policies {
            policy::reconcile(&self.pool, declared).await?;
        }

        crate::maintenance::partitions::provision(
            &self.pool,
            &crate::maintenance::partitions::engine_tables(),
            crate::maintenance::partitions::PartitionWindow::default(),
        )
        .await?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        Ok(Runtime {
            pool: self.pool,
            worker_id: self.worker_id,
            policies: std::sync::Arc::new(self.policies),
            handlers: std::sync::Arc::new(self.handlers),
            schedules: self.schedules,
            poll_interval: self.poll_interval,
            heartbeat_interval: self.heartbeat_interval,
            shutdown_tx,
            shutdown_rx,
        })
    }
}

/// A running engine instance.
///
/// Owns the claim/worker loops, the sweeper, and the in-process scheduler. The
/// enqueue and event-append APIs are free functions that take a caller-supplied
/// executor so callers can enqueue inside their own transaction.
pub struct Runtime {
    pool: sqlx::PgPool,
    worker_id: String,
    policies: std::sync::Arc<Vec<policy::QueuePolicy>>,
    handlers: std::sync::Arc<HandlerMap>,
    schedules: Vec<scheduler::CronSchedule>,
    poll_interval: std::time::Duration,
    heartbeat_interval: std::time::Duration,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

impl Runtime {
    /// Begin configuring a runtime.
    pub fn builder(pool: sqlx::PgPool) -> RuntimeBuilder {
        RuntimeBuilder::new(pool)
    }

    /// The pool this runtime is bound to.
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }

    /// This runtime's worker identifier.
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// Start the worker loops, sweeper, and scheduler. Runs until `shutdown` is
    /// signalled, at which point each loop stops claiming new work, finishes its
    /// in-flight job, and returns.
    ///
    /// One worker loop is spawned per registered queue. A queue's
    /// `concurrency` decides how many jobs that loop claims and processes per
    /// tick; a `singleton_loop` queue is pinned to a single in-flight job
    /// regardless of its declared concurrency so at most one job runs at a time.
    ///
    /// # Supervision
    ///
    /// Every loop is supervised together: the first one to return an error (or
    /// to panic) is observed as soon as it happens, regardless of which loop it
    /// is. A worker loop runs forever in steady state, so a scheduler or sweeper
    /// that fails must not be hidden behind a never-returning worker. The moment
    /// any loop fails, shutdown is signalled so the rest stop claiming new work,
    /// then every remaining loop is drained to completion before `run` returns
    /// the first failure. A clean shutdown (every loop returns `Ok`) returns
    /// `Ok`. The first failure is the one returned even if draining surfaces
    /// later ones.
    pub async fn run(&self) -> Result<()> {
        let mut tasks: tokio::task::JoinSet<Result<()>> = tokio::task::JoinSet::new();

        // One worker loop per queue that has a registered handler. Claiming is
        // scoped to a single queue per loop so a queue's concurrency and lease
        // are honored independently of other queues.
        for declared in self.policies.iter() {
            if !self.handlers.contains_key(&declared.queue) {
                // A policy without a handler is a config-only queue (for
                // example one driven purely by another replica); nothing to run
                // here.
                continue;
            }

            // singleton_loop pins the loop to one in-flight job; standard fans
            // out up to the declared concurrency.
            let batch_size = match declared.policy {
                policy::QueuePolicyKind::SingletonLoop => 1,
                policy::QueuePolicyKind::Standard => i64::from(declared.concurrency.max(1)),
            };

            let config = worker::WorkerConfig {
                queues: vec![declared.queue.clone()],
                batch_size,
                poll_interval: self.poll_interval,
                heartbeat_interval: self.heartbeat_interval,
            };

            let pool = self.pool.clone();
            let worker_id = self.worker_id.clone();
            let handlers = self.handlers.clone();
            let shutdown = self.shutdown_rx.clone();
            let handler_for = move |queue: &str| handlers.get(queue).cloned();

            tasks.spawn(async move {
                worker::run_worker(pool, worker_id, config, handler_for, shutdown).await
            });
        }

        // The sweeper reclaims jobs whose lease lapsed across every queue.
        {
            let pool = self.pool.clone();
            let shutdown = self.shutdown_rx.clone();
            tasks.spawn(async move { sweeper::run_sweeper(pool, SWEEP_INTERVAL, shutdown).await });
        }

        // The in-process scheduler runs on every replica; cron_tick dedupes the
        // enqueue so exactly one replica's occurrence wins.
        if !self.schedules.is_empty() {
            let pool = self.pool.clone();
            let schedules = self.schedules.clone();
            let shutdown = self.shutdown_rx.clone();
            tasks.spawn(async move { scheduler::run_scheduler(pool, schedules, shutdown).await });
        }

        // Supervise every loop together. `join_next` yields the first loop to
        // finish in any order, so a failing scheduler or sweeper is observed
        // immediately rather than queued behind a worker loop that never
        // returns. The first failure (or panic) signals shutdown so the rest
        // wind down; we then keep draining so no loop is abandoned mid-flight,
        // and return the first failure once every loop has stopped.
        let mut first_err: Option<Error> = None;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    if first_err.is_none() {
                        tracing::error!(error = %err, "runtime loop failed; signalling shutdown");
                        self.shutdown();
                        first_err = Some(err);
                    }
                }
                Err(join_err) => {
                    tracing::error!(error = %join_err, "runtime loop task panicked or was cancelled");
                    if first_err.is_none() {
                        self.shutdown();
                        first_err = Some(Error::Config(format!(
                            "runtime loop task panicked or was cancelled: {join_err}"
                        )));
                    }
                }
            }
        }

        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Request a graceful shutdown of the running loops. Each loop stops
    /// claiming new work and finishes its in-flight job before returning.
    pub fn shutdown(&self) {
        // Ignore send errors: a closed channel means every loop already exited.
        let _ = self.shutdown_tx.send(true);
    }

    /// Resolve when a shutdown has been signalled.
    ///
    /// A co-supervised task (the HTTP data plane) awaits this to wind down in
    /// lockstep with the background plane: when the signal handler calls
    /// [`shutdown`](Self::shutdown), this future resolves and the task stops. It
    /// returns immediately if shutdown was already signalled.
    pub async fn wait_for_shutdown(&self) {
        let mut rx = self.shutdown_rx.clone();
        // Already signalled: return at once.
        if *rx.borrow() {
            return;
        }
        // Otherwise wait for the next change to `true`. A send error (sender
        // dropped) also means we should stop.
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return;
            }
        }
    }

    /// Fetch a job by id (primarily for tests and inspection).
    pub async fn get_job(&self, id: Uuid) -> Result<Option<Job>> {
        claim::get_job(&self.pool, id).await
    }
}
