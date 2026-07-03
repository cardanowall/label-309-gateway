//! Claiming jobs and the fenced lifecycle writes.
//!
//! A claim atomically moves up to `limit` available, due jobs to `running`,
//! stamping a fresh [`ClaimToken`], the worker id, a heartbeat, and (the first
//! time) `started_at`, while incrementing `attempts`. The select uses
//! `FOR UPDATE SKIP LOCKED` so concurrent workers never block each other and
//! never claim the same row.
//!
//! Every post-claim write (heartbeat, complete, fail, defer) is *fenced*: it
//! guards on `id = $id AND claim_token = $token AND state = 'running'`. If the
//! row was reclaimed by the sweeper (new token) the guard fails, zero rows are
//! updated, and the worker learns it lost ownership.

use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::{Backoff, ClaimToken, Job, JobError, JobState};
use crate::{Error, Result};

/// The columns every job-returning query selects, in a fixed order, so the row
/// decoder below can read them positionally and stay in sync across queries.
const JOB_COLUMNS: &str = "id, queue, payload, state, run_at, attempts, max_attempts, backoff, \
     singleton_key, claim_token, claimed_by, heartbeat_at, defer_count, deadline, last_error, \
     created_at, started_at, finished_at";

/// Upper bound, in seconds, on a single retry's backoff delay (about 68 years).
///
/// A retry horizon beyond this is meaningless, and clamping here keeps the
/// scheduled `run_at` (`now()` plus the delay) inside the representable timestamp
/// range no matter how large an exponential backoff's attempt count grows. Every
/// real queue policy uses delays measured in seconds to minutes, far below this.
const MAX_RETRY_DELAY_SECS: i64 = i32::MAX as i64;

/// Decode a [`Job`] from a row selecting [`JOB_COLUMNS`].
fn job_from_row(row: &sqlx::postgres::PgRow) -> Result<Job> {
    let backoff: sqlx::types::Json<Backoff> = row.try_get("backoff")?;
    let last_error: Option<sqlx::types::Json<serde_json::Value>> = row.try_get("last_error")?;
    Ok(Job {
        id: row.try_get("id")?,
        queue: row.try_get("queue")?,
        payload: row.try_get("payload")?,
        state: row.try_get("state")?,
        run_at: row.try_get("run_at")?,
        attempts: row.try_get("attempts")?,
        max_attempts: row.try_get("max_attempts")?,
        backoff: backoff.0,
        singleton_key: row.try_get("singleton_key")?,
        claim_token: row.try_get("claim_token")?,
        claimed_by: row.try_get("claimed_by")?,
        heartbeat_at: row.try_get("heartbeat_at")?,
        defer_count: row.try_get("defer_count")?,
        deadline: row.try_get("deadline")?,
        last_error: last_error.map(|j| j.0),
        created_at: row.try_get("created_at")?,
        started_at: row.try_get("started_at")?,
        finished_at: row.try_get("finished_at")?,
    })
}

/// Claim up to `limit` due jobs across the given queues for `worker_id`.
///
/// Implements:
/// ```sql
/// UPDATE cw_core.job SET
///   state='running', claim_token=$token, claimed_by=$worker,
///   heartbeat_at=now(), started_at=coalesce(started_at, now()),
///   attempts=attempts+1
/// WHERE id IN (
///   SELECT id FROM cw_core.job
///   WHERE state='available' AND run_at<=now() AND queue = ANY($queues)
///     AND attempts < max_attempts
///   ORDER BY run_at, id
///   FOR UPDATE SKIP LOCKED
///   LIMIT $limit
/// )
/// RETURNING *;
/// ```
///
/// The `attempts < max_attempts` guard makes the attempt budget the hard
/// retry bound it is meant to be: a job whose attempt count is already at the
/// ceiling is never re-claimed and re-incremented. That budget can be reached
/// without ever passing through [`fail`] — the sweeper re-avails a lapsed-lease
/// `running` job with `attempts` unchanged — so without this predicate a final
/// attempt that crashed before its fenced [`fail`] landed would be re-claimed at
/// `attempts = max_attempts + 1`, and a repeating crash/lease-expiry could run a
/// permanently-failing job without bound. An exhausted available row is instead
/// reaped to terminal `failed` by `reap_exhausted` in the same call, so it
/// never lingers non-terminal once its budget is spent.
///
/// A claimed job whose `deadline` has already passed is failed at claim time,
/// with a `deadline_exceeded` error, rather than handed to a handler. The claim
/// statement allocates one fresh token; the returned rows are post-deadline
/// triage so the caller only ever sees runnable jobs.
pub async fn claim_batch(
    pool: &sqlx::PgPool,
    worker_id: &str,
    queues: &[String],
    limit: i64,
) -> Result<Vec<(Job, ClaimToken)>> {
    // Reap any already-exhausted available rows in these queues to terminal
    // `failed` before claiming, so a budget-spent job leaves the available pool
    // instead of sitting there forever (the claim SELECT below would skip it, but
    // it must reach a terminal state, not linger). This is the lease-expiry twin
    // of the in-`fail` terminal branch: both terminate on `attempts >= max_attempts`.
    reap_exhausted(pool, queues).await?;

    let token = Uuid::now_v7();

    let sql = format!(
        "UPDATE cw_core.job SET \
            state = 'running', claim_token = $1, claimed_by = $2, \
            heartbeat_at = now(), started_at = COALESCE(started_at, now()), \
            attempts = attempts + 1 \
         WHERE id IN ( \
            SELECT id FROM cw_core.job \
            WHERE state = 'available' AND run_at <= now() AND queue = ANY($3) \
              AND attempts < max_attempts \
            ORDER BY run_at, id \
            FOR UPDATE SKIP LOCKED \
            LIMIT $4 \
         ) \
         RETURNING {JOB_COLUMNS}"
    );

    // The statement is built from a fixed column list and constant SQL; only
    // the $N bind parameters carry data, so wrapping the assembled string as
    // SQL-safe is an audited, injection-free use.
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(token)
        .bind(worker_id)
        .bind(queues)
        .bind(limit)
        .fetch_all(pool)
        .await?;

    let now = Utc::now();
    let mut claimed = Vec::with_capacity(rows.len());
    for row in &rows {
        let job = job_from_row(row)?;
        let claim_token = ClaimToken(token);

        // The deadline is the primary lifetime bound: a job that is already past
        // its deadline at claim time is failed rather than dispatched. The claim
        // already counted the attempt; the fenced fail-with-deadline write
        // moves it straight to terminal.
        if job.deadline.is_some_and(|d| d <= now) {
            fail_deadline(pool, job.id, claim_token).await?;
            continue;
        }

        claimed.push((job, claim_token));
    }

    Ok(claimed)
}

/// Terminalise any `available` jobs in `queues` that have already spent their
/// attempt budget, moving them to `failed` with an `attempts_exhausted` error.
///
/// The attempt budget can be reached outside the [`fail`] path: the sweeper
/// re-avails a lapsed-lease `running` job with `attempts` left unchanged, so a
/// final attempt whose worker died before its fenced [`fail`] landed comes back
/// `available` at `attempts == max_attempts`. The claim SELECT skips such a row
/// (its `attempts < max_attempts` guard), but a skipped row would otherwise sit
/// `available` forever. This reaps it to the same terminal state a handler
/// failure on the last attempt produces, so an exhausted job always converges on
/// `failed` whether the budget was spent by a handler failure or by lease expiry.
///
/// Crucially this does NOT gate on `run_at <= now()`. An exhausted row whose
/// `run_at` sits in the future is just as wedged: it can never be claimed (the
/// budget is spent), never retried, and — for a singleton-loop queue — its
/// `available` state keeps the partial-unique in-flight index occupied, so the
/// cron re-seed of that singleton is blocked until the row is terminalised. A
/// `run_at` filter would leave that row non-terminal until its future instant
/// arrived, permanently wedging the queue's re-seed in the meantime. The
/// `attempts >= max_attempts` predicate alone is the safe selector: a
/// legitimately-retrying row always has `attempts < max_attempts` (the claim
/// charges the attempt; a budget is only "spent" once the count reaches the
/// ceiling), so this can never terminalise a row that still has retries left,
/// regardless of when its backoff `run_at` falls.
async fn reap_exhausted(pool: &sqlx::PgPool, queues: &[String]) -> Result<()> {
    let error = JobError::new(
        "attempts_exhausted",
        "the job exhausted its attempt budget without completing",
    );
    sqlx::query(
        "UPDATE cw_core.job SET \
            state = 'failed', finished_at = now(), \
            claim_token = NULL, claimed_by = NULL, heartbeat_at = NULL, \
            last_error = COALESCE(last_error, $2) \
         WHERE state = 'available' AND queue = ANY($1) \
           AND attempts >= max_attempts",
    )
    .bind(queues)
    .bind(sqlx::types::Json(&error))
    .execute(pool)
    .await?;
    Ok(())
}

/// Refresh the heartbeat on a job this worker holds.
///
/// Fenced: returns `Ok(())` on success, [`crate::Error::LostOwnership`] if the
/// row no longer matches `(id, token, running)`.
pub async fn heartbeat(pool: &sqlx::PgPool, job_id: Uuid, token: ClaimToken) -> Result<()> {
    let affected = sqlx::query(
        "UPDATE cw_core.job SET heartbeat_at = now() \
         WHERE id = $1 AND claim_token = $2 AND state = 'running'",
    )
    .bind(job_id)
    .bind(token.0)
    .execute(pool)
    .await?
    .rows_affected();

    fenced(affected, job_id)
}

/// Mark a held job completed (terminal).
///
/// Fenced on `(id, token, running)`. Sets `state='completed'`,
/// `finished_at=now()`.
pub async fn complete(pool: &sqlx::PgPool, job_id: Uuid, token: ClaimToken) -> Result<()> {
    let affected = sqlx::query(
        "UPDATE cw_core.job SET state = 'completed', finished_at = now() \
         WHERE id = $1 AND claim_token = $2 AND state = 'running'",
    )
    .bind(job_id)
    .bind(token.0)
    .execute(pool)
    .await?
    .rows_affected();

    fenced(affected, job_id)
}

/// Apply a handler failure: retry if attempts remain, otherwise fail terminally.
///
/// Fenced on `(id, token, running)`. If `attempts >= max_attempts`, sets
/// `state='failed'`, `finished_at=now()`, `last_error=$error`. Otherwise sets
/// `state='available'`, `run_at=now()+backoff`, clears the claim token, and
/// records `last_error`.
///
/// The retry-vs-terminal branch is decided in SQL from the row's own `attempts`
/// and `max_attempts`, so the decision is made atomically against the row the
/// fence matched, never against a possibly stale in-memory copy. The fence
/// guarantees the row is still `running` under this claim token, so `backoff`
/// and `attempt` (carried from the claimed [`Job`]) describe exactly this row.
///
/// The retry delay is computed once via the saturating [`Backoff::delay`] and
/// bound as a whole-seconds interval. Keeping the doubling in one overflow-safe
/// implementation means a large attempt count caps at the longest representable
/// delay instead of overflowing the schedule, and the delay is bounded to a sane
/// retry horizon so the scheduled `run_at` always stays a representable instant.
pub async fn fail(
    pool: &sqlx::PgPool,
    job_id: Uuid,
    token: ClaimToken,
    backoff: Backoff,
    attempt: i32,
    error: &JobError,
) -> Result<()> {
    // `attempt` is the count already consumed (the claim incremented it), which
    // is the 1-based number the just-failed try ran as, so the delay grows per
    // retry. The doubling is saturated inside Backoff::delay; clamp the result to
    // a finite retry horizon so `now() + interval` can never run the schedule
    // past the timestamp range. Every shipped policy is far below this ceiling,
    // so the clamp is inert for real backoffs and only tames a degenerate one.
    let delay = backoff.delay(u32::try_from(attempt.max(0)).unwrap_or(u32::MAX));
    let delay_secs = delay.num_seconds().clamp(0, MAX_RETRY_DELAY_SECS);

    let affected = sqlx::query(
        "UPDATE cw_core.job SET \
            state = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'available' END, \
            run_at = CASE \
                WHEN attempts >= max_attempts THEN run_at \
                ELSE now() + make_interval(secs => $4) \
            END, \
            finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE finished_at END, \
            claim_token = CASE WHEN attempts >= max_attempts THEN claim_token ELSE NULL END, \
            claimed_by = CASE WHEN attempts >= max_attempts THEN claimed_by ELSE NULL END, \
            heartbeat_at = CASE WHEN attempts >= max_attempts THEN heartbeat_at ELSE NULL END, \
            last_error = $3 \
         WHERE id = $1 AND claim_token = $2 AND state = 'running'",
    )
    .bind(job_id)
    .bind(token.0)
    .bind(sqlx::types::Json(error))
    .bind(delay_secs as f64)
    .execute(pool)
    .await?
    .rows_affected();

    fenced(affected, job_id)
}

/// Defer a held job to `until` without consuming an attempt.
///
/// Fenced on `(id, token, running)`. Sets `state='available'`, `run_at=$until`,
/// clears the claim token, increments `defer_count`, and refunds the attempt
/// the claim charged (`attempts = attempts - 1`) so a deferral is attempt-neutral.
/// If `until` is past the job's deadline (or the deadline has already passed),
/// the job is failed with [`JobError::deadline_exceeded`] instead.
///
/// The deadline branch is decided in SQL against the row's own `deadline`, so a
/// deferral past the deadline always terminates the job atomically rather than
/// quietly rescheduling beyond its lifetime bound.
pub async fn defer(
    pool: &sqlx::PgPool,
    job_id: Uuid,
    token: ClaimToken,
    until: DateTime<Utc>,
) -> Result<()> {
    let affected = sqlx::query(
        "UPDATE cw_core.job SET \
            state = CASE \
                WHEN deadline IS NOT NULL AND (deadline <= now() OR deadline < $3) THEN 'failed' \
                ELSE 'available' END, \
            run_at = CASE \
                WHEN deadline IS NOT NULL AND (deadline <= now() OR deadline < $3) THEN run_at \
                ELSE $3 END, \
            finished_at = CASE \
                WHEN deadline IS NOT NULL AND (deadline <= now() OR deadline < $3) THEN now() \
                ELSE finished_at END, \
            last_error = CASE \
                WHEN deadline IS NOT NULL AND (deadline <= now() OR deadline < $3) THEN $4 \
                ELSE last_error END, \
            claim_token = CASE \
                WHEN deadline IS NOT NULL AND (deadline <= now() OR deadline < $3) \
                    THEN claim_token ELSE NULL END, \
            claimed_by = CASE \
                WHEN deadline IS NOT NULL AND (deadline <= now() OR deadline < $3) \
                    THEN claimed_by ELSE NULL END, \
            heartbeat_at = CASE \
                WHEN deadline IS NOT NULL AND (deadline <= now() OR deadline < $3) \
                    THEN heartbeat_at ELSE NULL END, \
            defer_count = defer_count + 1, \
            attempts = attempts - 1 \
         WHERE id = $1 AND claim_token = $2 AND state = 'running'",
    )
    .bind(job_id)
    .bind(token.0)
    .bind(until)
    .bind(sqlx::types::Json(JobError::deadline_exceeded()))
    .execute(pool)
    .await?
    .rows_affected();

    fenced(affected, job_id)
}

/// Fail a held job for breaching its deadline at claim time.
///
/// Fenced on `(id, token, running)` so a concurrently reclaimed job is not
/// clobbered. Records the reserved `deadline_exceeded` error.
async fn fail_deadline(pool: &sqlx::PgPool, job_id: Uuid, token: ClaimToken) -> Result<()> {
    let affected = sqlx::query(
        "UPDATE cw_core.job SET state = 'failed', finished_at = now(), last_error = $3 \
         WHERE id = $1 AND claim_token = $2 AND state = 'running'",
    )
    .bind(job_id)
    .bind(token.0)
    .bind(sqlx::types::Json(JobError::deadline_exceeded()))
    .execute(pool)
    .await?
    .rows_affected();

    // A zero-row update here means the job was reclaimed between the claim and
    // this triage write; the new owner will re-triage its own deadline. Treat
    // it as a benign lost-ownership rather than an error.
    if affected == 0 {
        tracing::debug!(job = %job_id, "deadline-failed job was reclaimed before triage");
    }
    Ok(())
}

/// Cancel a job that is not yet terminal.
///
/// Unlike the other writes this is not claim-fenced: cancellation is an
/// out-of-band administrative action. Sets `state='cancelled'`,
/// `finished_at=now()` when the job is `available` or `running`.
pub async fn cancel(pool: &sqlx::PgPool, job_id: Uuid) -> Result<()> {
    let affected = sqlx::query(
        "UPDATE cw_core.job SET state = 'cancelled', finished_at = now() \
         WHERE id = $1 AND state IN ('available', 'running')",
    )
    .bind(job_id)
    .execute(pool)
    .await?
    .rows_affected();

    if affected == 0 {
        // Either the job does not exist or it is already terminal. Distinguish
        // the two so a caller cancelling a missing job gets a clear error while
        // cancelling an already-terminal job is a no-op success (cancellation is
        // idempotent against a row that already reached a terminal state).
        let exists: Option<JobState> =
            sqlx::query_scalar("SELECT state FROM cw_core.job WHERE id = $1")
                .bind(job_id)
                .fetch_optional(pool)
                .await?;
        if exists.is_none() {
            return Err(Error::JobNotFound(job_id));
        }
    }
    Ok(())
}

/// Load a single job row by id.
pub async fn get_job(pool: &sqlx::PgPool, id: Uuid) -> Result<Option<Job>> {
    let sql = format!("SELECT {JOB_COLUMNS} FROM cw_core.job WHERE id = $1");
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.map(|r| job_from_row(&r)).transpose()
}

/// Translate a fenced write's affected-row count into the lost-ownership signal.
///
/// One row updated means the write landed on the row this worker still owns.
/// Zero rows means the fence (`claim_token` + `state = 'running'`) did not match:
/// the job was reclaimed, completed, or cancelled out from under this worker, so
/// the write is a no-op and the worker must stop producing side effects.
fn fenced(affected: u64, job_id: Uuid) -> Result<()> {
    if affected == 0 {
        Err(Error::LostOwnership(job_id))
    } else {
        Ok(())
    }
}
