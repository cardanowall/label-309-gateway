//! Enqueueing jobs.
//!
//! Both entry points are generic over [`sqlx::PgExecutor`], so a caller can
//! enqueue against the pool for a standalone insert or against
//! `&mut Transaction` to make the enqueue atomic with their own writes (enqueue
//! a job only if the surrounding business transaction commits).
//!
//! Each enqueue resolves its `max_attempts` and `backoff` defaults from the
//! queue's policy row in the same statement (`COALESCE` against a `queue_policy`
//! subquery), so the insert is a single round-trip even on a borrowed
//! transaction executor that can only run one query. A queue with no registered
//! policy yields no policy row, which surfaces as [`crate::Error::UnknownQueue`]
//! rather than a silent partial insert.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use super::Backoff;
use crate::{Error, Result};

/// A newtype over a job's UUIDv7 primary key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobId(pub Uuid);

/// Optional enqueue parameters. Defaults pull `max_attempts` and `backoff` from
/// the queue policy when left unset.
#[derive(Debug, Clone, Default)]
pub struct EnqueueOptions {
    /// Delay first availability until this instant. Defaults to `now()`.
    pub run_at: Option<DateTime<Utc>>,
    /// Override the queue policy's attempt budget for this job.
    pub max_attempts: Option<i32>,
    /// Override the queue policy's backoff for this job.
    pub backoff: Option<Backoff>,
    /// Singleton dedupe key. With [`enqueue_dedupe`] a conflicting in-flight
    /// job suppresses the enqueue; with [`enqueue`] it is an error.
    pub singleton_key: Option<String>,
    /// Hard wall-clock lifetime bound for the job.
    pub deadline: Option<DateTime<Utc>>,
}

/// Outcome of the shared insert CTE: how many policy rows matched the queue and
/// the id of the inserted job (NULL when an `ON CONFLICT DO NOTHING` suppressed
/// the insert).
#[derive(sqlx::FromRow)]
struct InsertOutcome {
    policy_count: i64,
    new_id: Option<Uuid>,
}

/// The shared CTE both entry points run. `conflict_clause` is either empty (the
/// plain `enqueue`, where a singleton collision raises a unique-violation that
/// propagates as a database error) or the `ON CONFLICT ... DO NOTHING` form (the
/// dedupe variant, where a collision is a successful no-op).
///
/// `policy_count` distinguishes a missing queue policy (0) from a suppressed
/// insert (1 policy, NULL id), so the dedupe variant never confuses
/// "unknown queue" with "duplicate".
fn insert_sql(conflict_clause: &str) -> String {
    format!(
        "WITH pol AS ( \
            SELECT max_attempts, backoff FROM cw_core.queue_policy WHERE queue = $2 \
         ), \
         ins AS ( \
            INSERT INTO cw_core.job \
                (id, queue, payload, state, run_at, max_attempts, backoff, singleton_key, deadline) \
            SELECT $1, $2, $3, 'available', COALESCE($4, now()), \
                COALESCE($5, pol.max_attempts), \
                COALESCE($6::jsonb, pol.backoff), \
                $7, $8 \
            FROM pol \
            {conflict_clause} \
            RETURNING id \
         ) \
         SELECT (SELECT count(*) FROM pol) AS policy_count, (SELECT id FROM ins) AS new_id"
    )
}

/// Enqueue a job, returning its id.
///
/// A new UUIDv7 is allocated for the row. If `opts.singleton_key` collides with
/// an in-flight job for the queue the insert violates the partial unique index
/// and this returns an error; callers that want the conflict to be silent use
/// [`enqueue_dedupe`].
pub async fn enqueue<'e, E, P>(
    executor: E,
    queue: &str,
    payload: &P,
    opts: EnqueueOptions,
) -> Result<JobId>
where
    E: sqlx::PgExecutor<'e>,
    P: Serialize + Sync,
{
    let id = Uuid::now_v7();
    let payload = serde_json::to_value(payload)?;
    let backoff = opts.backoff.map(serde_json::to_value).transpose()?;

    // No ON CONFLICT clause: a singleton collision aborts the statement with a
    // unique-violation that propagates as Error::Database, the documented
    // contract for the non-dedupe path. The statement structure is constant
    // (only $N bind params carry data), so AssertSqlSafe is an audited use.
    let outcome: InsertOutcome = sqlx::query_as(sqlx::AssertSqlSafe(insert_sql("")))
        .bind(id)
        .bind(queue)
        .bind(payload)
        .bind(opts.run_at)
        .bind(opts.max_attempts)
        .bind(backoff)
        .bind(opts.singleton_key)
        .bind(opts.deadline)
        .fetch_one(executor)
        .await?;

    if outcome.policy_count == 0 {
        return Err(Error::UnknownQueue(queue.to_string()));
    }
    match outcome.new_id {
        Some(id) => Ok(JobId(id)),
        // With no conflict clause the only way to get a policy row but no insert
        // is impossible in practice; treat it as a not-found-style invariant
        // breach rather than silently returning a fabricated id.
        None => Err(Error::Config(format!(
            "enqueue produced no row for queue {queue:?} despite a registered policy"
        ))),
    }
}

/// The singleton key an event-driven wake enqueue carries.
///
/// A wake is "run this queue's handler as soon as possible": producers fire one
/// when they commit work for a queue (an outbox row for the fan-out drain, a
/// fresh delivery row for the delivery worker) so the handler runs at NOTIFY
/// latency instead of waiting for its fallback cron tick. One shared key keeps
/// the in-flight wake population at one per queue, and it is distinct from the
/// scheduler's cron key so a parked cron-seeded job never absorbs a wake.
pub const WAKE_SINGLETON_KEY: &str = "wake";

/// Ensure `queue`'s handler runs as soon as possible.
///
/// Enqueues a [`WAKE_SINGLETON_KEY`]-keyed job due now; when an in-flight wake
/// job already exists the insert dedupes, and an `available` wake parked at a
/// FUTURE instant (a self-pacing handler deferred it to its next retry horizon)
/// is pulled forward to now — fresh work must not wait behind a defer computed
/// before that work existed. A wake that is currently `running` is left alone:
/// a running handler drains everything due before it returns.
///
/// Takes a bare connection so a producer can fire the wake on its open
/// transaction's connection (`&mut *txn`), making the wake and the work visible
/// together at commit (the transactional-outbox pattern; the job table's NOTIFY
/// trigger then wakes the worker immediately). A concrete connection — not a
/// generic `Acquire` — because the producers are themselves generic async
/// writers, and nesting a generic `Acquire` call inside them trips the
/// compiler's higher-ranked lifetime resolution.
pub async fn enqueue_wake(conn: &mut sqlx::PgConnection, queue: &str) -> Result<()> {
    let inserted = enqueue_dedupe(
        &mut *conn,
        queue,
        &serde_json::Value::Null,
        EnqueueOptions {
            singleton_key: Some(WAKE_SINGLETON_KEY.to_string()),
            ..EnqueueOptions::default()
        },
    )
    .await?;
    if inserted.is_none() {
        // A wake already exists. Pull an available-but-future one forward so
        // this producer's work is picked up now rather than at the earlier
        // wake's deferred instant.
        sqlx::query(
            "UPDATE cw_core.job SET run_at = now() \
             WHERE queue = $1 AND singleton_key = $2 \
               AND state = 'available' AND run_at > now()",
        )
        .bind(queue)
        .bind(WAKE_SINGLETON_KEY)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Enqueue a job unless a singleton conflict suppresses it.
///
/// Returns `Some(JobId)` when the row was inserted and `None` when an in-flight
/// job already holds `(queue, singleton_key)`. The `None` case is NOT an error:
/// it preserves the dedupe contract where a duplicate enqueue is a successful
/// no-op. Implemented with `INSERT ... ON CONFLICT DO NOTHING` against the
/// singleton partial unique index.
pub async fn enqueue_dedupe<'e, E, P>(
    executor: E,
    queue: &str,
    payload: &P,
    opts: EnqueueOptions,
) -> Result<Option<JobId>>
where
    E: sqlx::PgExecutor<'e>,
    P: Serialize + Sync,
{
    let id = Uuid::now_v7();
    let payload = serde_json::to_value(payload)?;
    let backoff = opts.backoff.map(serde_json::to_value).transpose()?;

    // The conflict target names the partial unique index by repeating its
    // predicate so Postgres infers the same index the live-table uniqueness is
    // enforced on. A collision leaves `ins` empty (new_id NULL) without aborting
    // the statement, which the caller reads as a successful dedupe no-op.
    let conflict_clause = "ON CONFLICT (queue, singleton_key) \
         WHERE singleton_key IS NOT NULL AND state IN ('available', 'running') \
         DO NOTHING";

    let outcome: InsertOutcome = sqlx::query_as(sqlx::AssertSqlSafe(insert_sql(conflict_clause)))
        .bind(id)
        .bind(queue)
        .bind(payload)
        .bind(opts.run_at)
        .bind(opts.max_attempts)
        .bind(backoff)
        .bind(opts.singleton_key)
        .bind(opts.deadline)
        .fetch_one(executor)
        .await?;

    if outcome.policy_count == 0 {
        return Err(Error::UnknownQueue(queue.to_string()));
    }
    // policy_count == 1 with a NULL id is the suppressed-duplicate case: the
    // contract returns None, not an error.
    Ok(outcome.new_id.map(JobId))
}
