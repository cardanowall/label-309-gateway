//! The set-drain fan-out reader over `delivery_outbox`.
//!
//! The reader claims outbox rows whose `fanned_out_at IS NULL` as a *set*. Order
//! within a pass does not affect completeness: every un-fanned row is visited on
//! some pass and stamped exactly once. The claim takes a `FOR UPDATE SKIP LOCKED`
//! row lock inside the caller's transaction, so concurrent passes get disjoint
//! batches and never double-process a row; the lock is held until the caller
//! commits, which is also when [`stamp_fanned_out`] takes effect. There is no
//! cursor and no high-water: the presence of `fanned_out_at IS NULL` is the
//! entire fan-out state.
//!
//! # Crash safety
//!
//! A fan-out pass over one row runs the per-subscription delivery inserts and the
//! `fanned_out_at` stamp in a single transaction. If the worker dies before the
//! commit, the row lock is released and the row (still un-fanned) is re-claimed on
//! the next pass; nothing is stamped, so no event is silently dropped. Once the
//! stamp commits, the row leaves the un-fanned set and is never re-fanned. The
//! delivery inserts dedupe on their `dedupe_key`, so a partial fan-out that
//! crashed mid-insert self-heals to the complete set with no duplicates.

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::Result;

/// An outbox row claimed for fan-out.
///
/// Carries the logical event identity the fan-out stage explodes into one
/// `webhook_delivery` row per matching subscription. The `id` is the
/// `delivery_outbox` primary key the caller stamps via [`stamp_fanned_out`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimedOutboxRow {
    /// The `delivery_outbox` primary key.
    pub id: Uuid,
    /// The subject's kind discriminator.
    pub subject_kind: String,
    /// The subject's id within its kind.
    pub subject_id: String,
    /// The event sequence within the subject (gap-free, commit-ordered).
    pub subject_seq: i64,
    /// The internal event type, projected to a public wire name at send time.
    pub event_type: String,
    /// The event payload, reused to build the wire envelope.
    pub payload: Value,
    /// When the event was appended (oldest-first fairness ordering).
    pub created_at: DateTime<Utc>,
}

/// Claim up to `limit` un-fanned outbox rows for fan-out within the caller's
/// transaction.
///
/// Selects rows with `fanned_out_at IS NULL`, oldest first for fairness, taking a
/// `FOR UPDATE SKIP LOCKED` lock so a concurrent claim gets a disjoint set and no
/// row is processed twice. The lock is held until the caller commits or rolls
/// back. A claimed row is *not* yet stamped: the caller explodes it into delivery
/// rows and calls [`stamp_fanned_out`] in the same transaction, so a crash before
/// commit leaves the row un-fanned and re-claimable.
///
/// The drain order is irrelevant to completeness (every un-fanned row is visited
/// on some pass), so `ORDER BY created_at` is fairness only, not a correctness
/// requirement.
pub async fn claim_unfanned(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    limit: i64,
) -> Result<Vec<ClaimedOutboxRow>> {
    let rows = sqlx::query_as::<_, ClaimedOutboxRow>(
        r#"
        SELECT id, subject_kind, subject_id, subject_seq, event_type, payload, created_at
        FROM cw_core.delivery_outbox
        WHERE fanned_out_at IS NULL
        ORDER BY created_at
        LIMIT $1
        FOR UPDATE SKIP LOCKED
        "#,
    )
    .bind(limit)
    .fetch_all(&mut **tx)
    .await?;

    Ok(rows)
}

/// Stamp an outbox row as fanned out within the caller's transaction.
///
/// Run in the same transaction as the per-subscription delivery inserts for the
/// row, so the explode and the stamp commit atomically. Once committed, the row
/// leaves the un-fanned set and [`claim_unfanned`] never returns it again.
pub async fn stamp_fanned_out(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    outbox_id: Uuid,
) -> Result<()> {
    sqlx::query(
        "UPDATE cw_core.delivery_outbox SET fanned_out_at = now() \
         WHERE id = $1 AND fanned_out_at IS NULL",
    )
    .bind(outbox_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
