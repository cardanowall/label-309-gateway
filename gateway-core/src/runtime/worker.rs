//! The worker loop: claim, dispatch to a handler, apply the outcome.
//!
//! The loop blends a NOTIFY wake-hint with an interval poll: it `LISTEN`s on
//! [`crate::JOB_AVAILABLE_CHANNEL`] to wake promptly when a job is enqueued, but
//! always falls back to a periodic poll so a missed notification only ever
//! delays work, never drops it.
//!
//! For each claimed job it builds a [`super::JobContext`], invokes the
//! registered [`super::JobHandler`], and translates the returned
//! [`super::JobOutcome`] into the matching fenced write
//! ([`super::claim::complete`] / [`super::claim::fail`] /
//! [`super::claim::defer`]). A fenced write that returns
//! [`crate::Error::LostOwnership`] is logged and the result discarded: a fresh
//! claimant now owns the job.

use std::sync::Arc;

use futures_util::FutureExt;

use super::{claim, Backoff, ClaimToken, Job, JobContext, JobError, JobHandler, JobOutcome};
use crate::{Error, Result};

/// Tuning for a worker loop.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Queues this worker pulls from.
    pub queues: Vec<String>,
    /// How many jobs to claim per tick.
    pub batch_size: i64,
    /// Fallback poll interval when no NOTIFY arrives.
    pub poll_interval: std::time::Duration,
    /// How often to refresh the heartbeat on an in-flight job.
    pub heartbeat_interval: std::time::Duration,
}

/// Drives claim/dispatch/outcome for one worker over the given queues until
/// `shutdown` resolves.
///
/// `handler_for` resolves a queue name to its registered handler; a job for a
/// queue with no handler is failed with a structured error rather than left
/// claimed.
///
/// On shutdown the loop stops claiming new work, lets every in-flight job finish
/// (and apply its outcome), then returns. A worker never abandons a job it
/// already claimed: that would strand the row until the sweeper reclaimed it.
pub async fn run_worker<F>(
    pool: sqlx::PgPool,
    worker_id: String,
    config: WorkerConfig,
    handler_for: F,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()>
where
    F: Fn(&str) -> Option<Arc<dyn ErasedHandler>> + Send + Sync + 'static,
{
    let handler_for = Arc::new(handler_for);

    // LISTEN is best-effort: a listener that fails to connect or drops mid-run
    // only costs us the wake-hint, so the loop degrades to pure interval polling
    // rather than failing. The interval tick is the correctness fallback.
    let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
        Ok(mut l) => match l.listen(crate::JOB_AVAILABLE_CHANNEL).await {
            Ok(()) => Some(l),
            Err(err) => {
                tracing::warn!(error = %err, "job-available LISTEN failed; falling back to polling");
                None
            }
        },
        Err(err) => {
            tracing::warn!(error = %err, "could not open NOTIFY listener; falling back to polling");
            None
        }
    };

    let mut ticker = tokio::time::interval(config.poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        // Drain as many due jobs as are available this wake, in batches, until a
        // claim returns nothing. Each batch is processed concurrently up to
        // batch_size. We re-check shutdown between batches so a shutdown request
        // stops new claims promptly while letting the current batch finish.
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }

            let claimed =
                claim::claim_batch(&pool, &worker_id, &config.queues, config.batch_size.max(1))
                    .await?;

            if claimed.is_empty() {
                break;
            }

            process_batch(&pool, &config, &handler_for, claimed).await;

            // If we got a full batch there may be more ready; loop again.
            // A short batch means the queue is drained for now.
        }

        // Sleep until the next tick or a wake-hint, whichever comes first. A
        // shutdown signal also wakes us so we return promptly.
        wait_for_work(&mut ticker, listener.as_mut(), &mut shutdown).await;
    }
}

/// Process one claimed batch concurrently, applying each job's outcome.
async fn process_batch<F>(
    pool: &sqlx::PgPool,
    config: &WorkerConfig,
    handler_for: &Arc<F>,
    claimed: Vec<(Job, ClaimToken)>,
) where
    F: Fn(&str) -> Option<Arc<dyn ErasedHandler>> + Send + Sync + 'static,
{
    let mut set = tokio::task::JoinSet::new();
    for (job, token) in claimed {
        let pool = pool.clone();
        let handler = handler_for(&job.queue);
        let heartbeat_interval = config.heartbeat_interval;
        set.spawn(async move {
            process_one(pool, job, token, handler, heartbeat_interval).await;
        });
    }
    // Drain the set so the batch is fully resolved before we claim the next one.
    // `process_one` catches a panicking handler internally and turns it into a
    // recorded job outcome, so a per-job task does not normally panic. We still
    // inspect each join result: a `JoinError` here would mean the task was
    // cancelled or panicked in the runtime's own dispatch code (not the
    // handler), which must be surfaced rather than silently swallowed — a
    // discarded join result is how a recurring subsystem can die unobserved.
    while let Some(joined) = set.join_next().await {
        if let Err(join_err) = joined {
            tracing::error!(
                error = %join_err,
                "job dispatch task did not complete cleanly (cancelled or panicked outside the handler)"
            );
        }
    }
}

/// Run one job to its outcome with a heartbeat ticking underneath it.
async fn process_one(
    pool: sqlx::PgPool,
    job: Job,
    token: ClaimToken,
    handler: Option<Arc<dyn ErasedHandler>>,
    heartbeat_interval: std::time::Duration,
) {
    let job_id = job.id;
    // Carried into the retry write so the backoff delay is computed once, in the
    // saturating Rust implementation, against this claim's attempt count.
    let backoff = job.backoff;
    let attempt = job.attempts;

    let Some(handler) = handler else {
        // A claimed job whose queue has no handler is failed with a structured
        // error rather than left running until the lease lapses.
        let err = JobError::new(
            "no_handler",
            format!("no handler registered for queue {:?}", job.queue),
        );
        apply_outcome(
            &pool,
            job_id,
            token,
            backoff,
            attempt,
            JobOutcome::Fail { error: err },
        )
        .await;
        return;
    };

    // The queue names the subsystem in any panic log below; bind it before the
    // job is consumed into the context.
    let queue = job.queue.clone();

    let ctx = JobContext {
        job_id,
        queue: queue.clone(),
        payload: job.payload.clone(),
        attempt: job.attempts,
        is_final_attempt: job.attempts >= job.max_attempts,
        defer_count: job.defer_count,
    };

    // Spawn the heartbeat task. It refreshes heartbeat_at on the interval; the
    // moment a fenced heartbeat reports lost ownership (the sweeper reclaimed
    // this job), it stops. The handler keeps running but its outcome will no-op
    // against the row a fresh claimant now owns, which the apply step detects.
    let hb_pool = pool.clone();
    let heartbeat = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(heartbeat_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // First tick fires immediately; skip it so we do not double-write the
        // heartbeat the claim already stamped.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match claim::heartbeat(&hb_pool, job_id, token).await {
                Ok(()) => {}
                Err(Error::LostOwnership(_)) => {
                    tracing::debug!(job = %job_id, "heartbeat lost ownership; stopping heartbeat");
                    return;
                }
                Err(err) => {
                    tracing::warn!(job = %job_id, error = %err, "heartbeat write failed");
                }
            }
        }
    });

    // Run the handler with the panic boundary around BOTH constructing and
    // awaiting its future. A handler panic — whether it fires synchronously while
    // the future is being built (a panic in the async fn body before its first
    // await, or in guard/argument setup) or later at an await point — is then a
    // contained, observable, recoverable event rather than an unwind that escapes
    // this task. Catching it keeps the heartbeat teardown below reachable, so a
    // panicked job releases its lease and gets a recorded outcome instead of being
    // stranded `running` forever (which would silently kill a recurring single-job
    // subsystem — scan, FX refresh, webhook fan-out, storage reconcile,
    // confirmation tracker — recoverable only by the slow sweeper, and only after
    // its lease timeout). The construction MUST live inside the `async move` block
    // so a construction-time panic is caught too: wrapping only `handler.handle(ctx)`
    // would build the future before `catch_unwind` ever sees it, leaking that panic.
    //
    // `AssertUnwindSafe` over the shared `Arc<dyn ErasedHandler>` is justified by
    // what the handlers actually are. Every registered handler is a stateless
    // dispatcher: it borrows `&self` (a pool handle, immutable config, immutable
    // dependencies) and carries the per-attempt state in the owned `ctx`, so a
    // panic cannot leave half-written handler state for the next job that reuses
    // the same `Arc`. The two handlers that do hold interior-mutable state
    // (process-local optimisation/dedup caches behind a `std::sync::Mutex`) take
    // that lock only for a trivial, infallible critical section — read, compare,
    // write a scalar/insert an id — and drop the guard before any `.await` or
    // fallible work, so the lock can never be held at the instant a panic unwinds
    // and can never be poisoned by one. Nothing observes handler-local state after
    // a panic anyway: the future and its captures are dropped, and the only
    // post-panic action is the fenced fail write below, which reads solely from
    // the job row.
    let handled = std::panic::AssertUnwindSafe(async move { handler.handle(ctx).await })
        .catch_unwind()
        .await;

    // Stop the heartbeat before applying the terminal/retry write so the two
    // never race on the same row. This runs on both the normal and the panicked
    // path: a panic is caught above rather than unwinding past this point, so the
    // lease is always released and the heartbeat task never leaks detached.
    heartbeat.abort();
    let _ = heartbeat.await;

    let outcome = match handled {
        Ok(outcome) => outcome,
        Err(panic) => {
            let detail = panic_message(panic.as_ref());
            // Name the queue (the subsystem) and the job so a dead recurring
            // subsystem is visible at error level, not just silently degraded.
            tracing::error!(
                job = %job_id,
                queue = %queue,
                attempt,
                panic = %detail,
                "job handler panicked; releasing the lease and recording a failure so the job can retry or terminalise"
            );
            // A panicked attempt fails like any other: the fenced fail write
            // retries the job (if attempts remain) or terminalises it, so the
            // subsystem recovers on the next claim/tick rather than wedging.
            JobOutcome::Fail {
                error: JobError::new("handler_panic", format!("handler panicked: {detail}")),
            }
        }
    };

    apply_outcome(&pool, job_id, token, backoff, attempt, outcome).await;
}

/// Best-effort human-readable message from a caught panic payload.
///
/// `catch_unwind` hands back a `Box<dyn Any>`; the two payload shapes the
/// standard panic machinery produces are `&'static str` (a `panic!("literal")`)
/// and `String` (a `panic!("{}", formatted)`). Anything else is summarised
/// generically so we never panic again trying to describe the first panic.
fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Apply a handler outcome via the matching fenced write.
///
/// A fenced write returning [`Error::LostOwnership`] means the job was reclaimed
/// out from under this worker; the write no-ops and we log rather than error so
/// the fresh claimant's processing stands.
async fn apply_outcome(
    pool: &sqlx::PgPool,
    job_id: uuid::Uuid,
    token: ClaimToken,
    backoff: Backoff,
    attempt: i32,
    outcome: JobOutcome,
) {
    let result = match outcome {
        JobOutcome::Complete => claim::complete(pool, job_id, token).await,
        JobOutcome::Fail { error } => {
            claim::fail(pool, job_id, token, backoff, attempt, &error).await
        }
        JobOutcome::Defer { until } => claim::defer(pool, job_id, token, until).await,
    };

    match result {
        Ok(()) => {}
        Err(Error::LostOwnership(_)) => {
            tracing::info!(
                job = %job_id,
                "job was reclaimed before its outcome could be applied; discarding outcome"
            );
        }
        Err(err) => {
            tracing::error!(job = %job_id, error = %err, "failed to apply job outcome");
        }
    }
}

/// Block until there is plausibly work to do: the poll tick fired, a NOTIFY
/// wake-hint arrived, or shutdown was signalled.
async fn wait_for_work(
    ticker: &mut tokio::time::Interval,
    listener: Option<&mut sqlx::postgres::PgListener>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) {
    match listener {
        Some(listener) => {
            tokio::select! {
                _ = ticker.tick() => {}
                notification = listener.recv() => {
                    if let Err(err) = notification {
                        // A dropped listener just removes the wake-hint; the
                        // interval keeps the loop correct.
                        tracing::warn!(error = %err, "NOTIFY listener errored; continuing on poll interval");
                    }
                }
                _ = shutdown.changed() => {}
            }
        }
        None => {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown.changed() => {}
            }
        }
    }
}

/// Object-safe erasure over [`JobHandler`] so handlers for different queues can
/// be stored in one registry and resolved by name.
pub trait ErasedHandler: Send + Sync + 'static {
    /// Process one attempt, returning the outcome as a boxed future.
    fn handle<'a>(
        &'a self,
        ctx: super::JobContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = super::JobOutcome> + Send + 'a>>;
}

impl<H: JobHandler> ErasedHandler for H {
    fn handle<'a>(
        &'a self,
        ctx: super::JobContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = super::JobOutcome> + Send + 'a>> {
        Box::pin(JobHandler::handle(self, ctx))
    }
}
