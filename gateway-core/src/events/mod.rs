//! Durable per-subject events and the outbound delivery outbox.
//!
//! # Per-subject sequencing
//!
//! Each event carries a `subject_seq` that is gap-free and strictly increasing
//! per `(subject_kind, subject_id)`. The sequence is allocated *inside the
//! writer's transaction*: the writer first takes `pg_advisory_xact_lock` on the
//! subject (so concurrent writers to the same subject serialize), then bumps the
//! subject's durable counter row in `cw_core.subject_seq` and takes the value it
//! returns. Because the lock is held to commit, sequence order matches commit
//! order for that subject and there is no global counter that could hand out
//! numbers out of commit order. Different subjects never contend.
//!
//! The counter is a separate row keyed on the subject precisely because the
//! event log it numbers is retention-pruned: `subject_event` is range-partitioned
//! by `created_at` and old partitions are dropped, so the highest sequence a
//! subject ever reached can outlive the rows that carried it. Allocating from
//! `max(subject_event)` would let a long-silent subject restart at 1 after its
//! partitions are dropped, regressing the sequence and colliding on the
//! never-pruned outbox `dedupe_key`. The durable counter row carries the
//! high-water forward independently of which event partitions still exist.
//!
//! [`append_subject_event`] takes the caller's executor so the event can be
//! appended inside the same transaction as the state change it describes. The
//! whole append is one statement: a CTE acquires the per-subject lock, derives
//! the next sequence, and inserts the event row and its outbox row together.
//! Driving it from a single statement means the call consumes the caller's
//! executor exactly once, which is what lets a bare `&PgPool` or a
//! `&mut Transaction` both satisfy the bound.
//!
//! # Outbox
//!
//! Appending an event also writes a `cw_core.delivery_outbox` row. The outbox is
//! the durable record that an event must be delivered; it is the fan-out spine
//! the webhook fan-out reader drains as a set (see [`crate::webhook::fanout`]).
//! Per-subscription delivery state and per-subject delivery ordering live on the
//! `webhook_delivery` rows the fan-out reader materializes, not on the outbox
//! row, so this module only produces outbox rows and never consumes them.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::Result;

/// A persisted subject event.
#[derive(Debug, Clone)]
pub struct SubjectEvent {
    /// The subject's kind discriminator.
    pub subject_kind: String,
    /// The subject's id within its kind.
    pub subject_id: String,
    /// Gap-free, commit-ordered sequence within the subject (>= 1).
    pub subject_seq: i64,
    /// The event type.
    pub event_type: String,
    /// Opaque event payload.
    pub payload: Value,
    /// When the event was appended.
    pub created_at: DateTime<Utc>,
}

/// Append an event for a subject within the caller's transaction, returning the
/// stored event (including its allocated `subject_seq`).
///
/// Allocates the next per-subject sequence under `pg_advisory_xact_lock`, then
/// inserts the `subject_event` row and the matching `delivery_outbox` row, all
/// in one transaction that joins the caller's other writes.
///
/// The sequence comes from the durable `cw_core.subject_seq` counter rather than
/// `max(subject_event)`, so it cannot regress when retention pruning drops the
/// partitions that held a subject's earlier events. The lock and the counter
/// bump share one transaction, which is also why the executor here is an
/// [`sqlx::Acquire`] rather than a bare pool: `pg_advisory_xact_lock` is
/// transaction-scoped and can only serialize writers that hold it to commit. The
/// lock is taken first as its own statement; the counter `INSERT ... ON CONFLICT
/// DO UPDATE ... RETURNING` then runs as a second statement whose READ COMMITTED
/// snapshot is taken after the lock is granted, so a concurrent writer that held
/// the lock has already committed its bump and this writer reads the advanced
/// value. The result is gap-free and unique per subject.
///
/// The outbox `dedupe_key` is derived as `kind:id:seq`, which is unique per
/// logical event, so an at-least-once retry of the caller's transaction can
/// never enqueue the same delivery twice.
///
/// Passing a `&mut Transaction` runs the append inside the caller's transaction
/// via a savepoint, so the event and outbox row commit or roll back with the
/// caller's other writes. Passing a `&PgPool` runs the append in its own
/// transaction.
pub async fn append_subject_event<'a, A, P>(
    executor: A,
    subject_kind: &str,
    subject_id: &str,
    event_type: &str,
    payload: &P,
) -> Result<SubjectEvent>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
    P: Serialize + Sync,
{
    let payload = serde_json::to_value(payload)?;
    let outbox_id = Uuid::now_v7();

    let mut txn = executor.begin().await?;

    // Statement 1: take the per-subject advisory lock. Transaction-scoped, so it
    // is held until this transaction (or the caller's outer transaction, when
    // this is a savepoint) commits. Concurrent appends to the same subject block
    // here; different subjects hash to different keys and never contend. The key
    // is hashtext(kind || ':' || id), the SQL-side idiom the session-create
    // serializer and the FX cold-start seed share.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1 || ':' || $2)::bigint)")
        .bind(subject_kind)
        .bind(subject_id)
        .execute(&mut *txn)
        .await?;

    // Statement 2: bump the durable per-subject counter and insert the event +
    // outbox row. Running as a separate statement is what gives the counter
    // upsert a fresh post-lock snapshot, so it observes a just-committed
    // competitor. The counter row carries the high-water across retention pruning
    // of subject_event, so the allocated value never regresses when old
    // partitions are dropped. The first append for a subject inserts next_seq=2
    // and the event takes seq 1; each later append bumps next_seq by one and
    // takes the prior value.
    let row: (i64, DateTime<Utc>) = sqlx::query_as(
        r#"
        WITH seq AS (
            INSERT INTO cw_core.subject_seq (subject_kind, subject_id, next_seq)
            VALUES ($1, $2, 2)
            ON CONFLICT (subject_kind, subject_id) DO UPDATE
                SET next_seq = cw_core.subject_seq.next_seq + 1
            RETURNING next_seq - 1 AS next_seq
        ),
        ins_event AS (
            INSERT INTO cw_core.subject_event
                (subject_kind, subject_id, subject_seq, event_type, payload)
            SELECT $1, $2, seq.next_seq, $3, $4
            FROM seq
            RETURNING subject_seq, created_at
        ),
        ins_outbox AS (
            INSERT INTO cw_core.delivery_outbox
                (id, subject_kind, subject_id, subject_seq, event_type, payload, dedupe_key)
            SELECT $5, $1, $2, ie.subject_seq, $3, $4,
                   $1 || ':' || $2 || ':' || ie.subject_seq::text
            FROM ins_event ie
            RETURNING subject_seq
        )
        SELECT subject_seq, created_at FROM ins_event
        "#,
    )
    .bind(subject_kind)
    .bind(subject_id)
    .bind(event_type)
    .bind(&payload)
    .bind(outbox_id)
    .fetch_one(&mut *txn)
    .await?;

    // Statement 3: wake the webhook fan-out drain in the same transaction as the
    // outbox row it must consume. The wake job and the outbox row become visible
    // together at commit, and the job table's NOTIFY trigger fires the worker
    // immediately — the outbox's delivery latency is NOTIFY latency, with the
    // fan-out cron only as the lost-wake fallback. Deduped to one in-flight
    // wake, so an event burst costs one job row.
    crate::webhook::wake_fanout(&mut txn).await?;

    txn.commit().await?;

    Ok(SubjectEvent {
        subject_kind: subject_kind.to_string(),
        subject_id: subject_id.to_string(),
        subject_seq: row.0,
        event_type: event_type.to_string(),
        payload,
        created_at: row.1,
    })
}
