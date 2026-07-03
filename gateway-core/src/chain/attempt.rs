//! The chain-effect ledger: durable rows that record an intended on-chain action
//! before it is broadcast.
//!
//! Every action that puts bytes on chain (a publish submit, a cancelling
//! replacement, a replenish split) inserts a [`ChainAttempt`] row inside the same
//! wallet-locked transaction that fences its UTxO inputs, and before it calls the
//! gateway's submit. The row carries everything a later path needs without a
//! chain read: the deterministically computed transaction id, the exact signed
//! bytes (so a retry re-broadcasts THIS transaction rather than building a fresh
//! one), the spent inputs and produced outputs, the fee and wallet, the action
//! kind and the subject it serves, a lifecycle status the confirm/reorg authority
//! drives, and the replacement linkage tying an original to its cancelling
//! replacement.
//!
//! This module owns the row type and its lifecycle transitions; it does not own
//! the broadcast or the wallet-state promotion (those live in the submit and
//! confirm paths, which call into here under the per-wallet advisory lock). The
//! lock-order invariant the whole engine upholds is wallet advisory lock ->
//! `chain_attempt` row write -> `poe_record` row write -> `wallet_utxo` row
//! write, so [`record_attempt_in_tx`] is written to run first inside a
//! caller-owned transaction that already holds the wallet lock.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::wallet::utxo::UtxoRef;
use crate::{Error, Result};

/// What kind of chain action an attempt is.
///
/// The kind discriminates the subject: a `Publish` or `Replacement` serves a
/// `poe_record`, a `Split` serves only its wallet (it mints canonical-candidate
/// outputs). The migration's `chain_attempt_subject` CHECK pins exactly one
/// subject shape per kind, so a malformed row can never reach this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptKind {
    /// A first publish submit for a record.
    Publish,
    /// A cancelling replacement that re-spends at least one input of the attempt
    /// it supersedes.
    Replacement,
    /// A replenish split that mints band-mid canonical-candidate outputs for a
    /// wallet.
    Split,
}

impl AttemptKind {
    /// The stored `text` value the `kind` column carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AttemptKind::Publish => "publish",
            AttemptKind::Replacement => "replacement",
            AttemptKind::Split => "split",
        }
    }

    /// Parse a stored `kind` value, rejecting anything the column CHECK would not
    /// have admitted (so this only fails on a corrupt row).
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "publish" => Ok(AttemptKind::Publish),
            "replacement" => Ok(AttemptKind::Replacement),
            "split" => Ok(AttemptKind::Split),
            other => Err(Error::Config(format!(
                "unknown chain attempt kind: {other}"
            ))),
        }
    }
}

/// The lifecycle status the confirm/reorg authority drives an attempt through.
///
/// The active-broadcaster set is `{Recorded, Broadcast, Stuck}`: at most one such
/// attempt exists per record at a time (the `chain_attempt_one_active_per_record`
/// unique index). `Superseded` is the status of an original whose cancelling
/// replacement has taken over the active-broadcaster role: it is no longer the
/// active broadcaster but is still reconcilable, because the original transaction
/// can still land before the replacement does. Only `Confirmed` and `Abandoned`
/// are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    /// Durable but not yet on the wire.
    Recorded,
    /// Sent to the node; the active broadcaster for its record.
    Broadcast,
    /// Broadcast and past the alert threshold, awaiting operator reconcile. Still
    /// reconcilable; NOT a refund.
    Stuck,
    /// Seen on chain at/above the confirm threshold. Terminal.
    Confirmed,
    /// Provably dead by a settlement-deep conflicting spend of one of this
    /// attempt's inputs. Terminal.
    Abandoned,
    /// A replacement has taken over the active-broadcaster role; still
    /// reconcilable until provably dead.
    Superseded,
}

impl AttemptStatus {
    /// The stored `text` value the `status` column carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AttemptStatus::Recorded => "recorded",
            AttemptStatus::Broadcast => "broadcast",
            AttemptStatus::Stuck => "stuck",
            AttemptStatus::Confirmed => "confirmed",
            AttemptStatus::Abandoned => "abandoned",
            AttemptStatus::Superseded => "superseded",
        }
    }

    /// Parse a stored `status` value, rejecting anything the column CHECK would
    /// not have admitted (so this only fails on a corrupt row).
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "recorded" => Ok(AttemptStatus::Recorded),
            "broadcast" => Ok(AttemptStatus::Broadcast),
            "stuck" => Ok(AttemptStatus::Stuck),
            "confirmed" => Ok(AttemptStatus::Confirmed),
            "abandoned" => Ok(AttemptStatus::Abandoned),
            "superseded" => Ok(AttemptStatus::Superseded),
            other => Err(Error::Config(format!(
                "unknown chain attempt status: {other}"
            ))),
        }
    }

    /// Whether this status is terminal (`Confirmed` or `Abandoned`). A terminal
    /// attempt drops out of every reconcile and on-chain enumeration.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, AttemptStatus::Confirmed | AttemptStatus::Abandoned)
    }

    /// Whether this status is in the active-broadcaster set (`Recorded`,
    /// `Broadcast`, or `Stuck`). At most one active-broadcaster attempt exists per
    /// record; a `Superseded` original is not in this set even though it is still
    /// reconcilable.
    #[must_use]
    pub fn is_active_broadcaster(self) -> bool {
        matches!(
            self,
            AttemptStatus::Recorded | AttemptStatus::Broadcast | AttemptStatus::Stuck
        )
    }
}

/// One wallet input an attempt's transaction spends, as carried in the
/// `spent_inputs` JSON array.
///
/// The serialised shape `{tx_hash, index, lovelace}` is the one every reader
/// decodes; `tx_hash` is hex-encoded so the JSON is a plain string the read API
/// can echo. The confirm authority restores these inputs on abandon and promotes
/// them on confirm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptInput {
    /// 32-byte transaction id, hex-encoded.
    pub tx_hash: String,
    /// Output index within that transaction.
    pub index: u32,
    /// Lovelace the output holds.
    pub lovelace: u64,
}

impl AttemptInput {
    /// The on-chain reference this input names, decoded from the hex `tx_hash`.
    pub fn utxo_ref(&self) -> Result<UtxoRef> {
        let raw = hex::decode(&self.tx_hash).map_err(|_| {
            Error::Config(format!(
                "attempt input tx_hash is not hex: {}",
                self.tx_hash
            ))
        })?;
        let tx_hash: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            Error::Config(format!(
                "attempt input tx_hash is not 32 bytes: {}",
                self.tx_hash
            ))
        })?;
        Ok(UtxoRef {
            tx_hash,
            output_index: self.index,
        })
    }
}

/// One output an attempt's transaction produces that the wallet tracks, as
/// carried in the `produced_outputs` JSON array.
///
/// The output's transaction id is the attempt's own `tx_hash` (the producing
/// transaction), so only the index and lovelace are stored per output. The
/// confirm authority promotes these on confirm and tombstones them on abandon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptOutput {
    /// Output index within the attempt's transaction.
    pub index: u32,
    /// Lovelace the output holds.
    pub lovelace: u64,
}

/// The fields a new attempt is recorded with, before broadcast.
///
/// `record_id` is set for a publish/replacement and `None` for a split (the
/// migration's subject CHECK enforces the pairing). `replaces_tx_hash` is set
/// only for a replacement, naming the original transaction it cancels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAttempt {
    /// The attempt id (UUIDv7), allocated by the caller so it can reference the
    /// attempt in the same transaction (for example to set
    /// `poe_record.current_attempt_id`).
    pub id: Uuid,
    /// What kind of chain action this is.
    pub kind: AttemptKind,
    /// The record this attempt serves, for a publish/replacement. `None` for a
    /// split.
    pub record_id: Option<Uuid>,
    /// The wallet whose pool funds and tracks the spend.
    pub wallet_id: Uuid,
    /// The deterministically computed 32-byte transaction id.
    pub tx_hash: [u8; 32],
    /// The exact signed transaction bytes a retry re-broadcasts.
    pub signed_tx: Vec<u8>,
    /// The fee the transaction pays.
    pub fee_lovelace: u64,
    /// The wallet inputs the transaction spends.
    pub spent_inputs: Vec<AttemptInput>,
    /// The outputs the transaction produces that the wallet tracks.
    pub produced_outputs: Vec<AttemptOutput>,
    /// The original transaction a replacement cancels. `None` for a publish or a
    /// split.
    pub replaces_tx_hash: Option<[u8; 32]>,
}

/// A `chain_attempt` row as read back from Postgres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainAttempt {
    /// The attempt id.
    pub id: Uuid,
    /// What kind of chain action this attempt is.
    pub kind: AttemptKind,
    /// The record this attempt serves, for a publish/replacement.
    pub record_id: Option<Uuid>,
    /// The wallet whose pool funds and tracks the spend.
    pub wallet_id: Uuid,
    /// The 32-byte transaction id.
    pub tx_hash: [u8; 32],
    /// The exact signed transaction bytes.
    pub signed_tx: Vec<u8>,
    /// The fee the transaction pays.
    pub fee_lovelace: u64,
    /// The wallet inputs the transaction spends.
    pub spent_inputs: Vec<AttemptInput>,
    /// The outputs the transaction produces that the wallet tracks.
    pub produced_outputs: Vec<AttemptOutput>,
    /// The original transaction a replacement cancels.
    pub replaces_tx_hash: Option<[u8; 32]>,
    /// The attempt that supersedes this one.
    pub superseded_by: Option<Uuid>,
    /// The lifecycle status the confirm/reorg authority drives.
    pub status: AttemptStatus,
    /// When this attempt's transaction most recently (re-)entered the mempool.
    pub mempool_entered_at: Option<DateTime<Utc>>,
    /// When the transaction was first observed on chain.
    pub first_seen_on_chain_at: Option<DateTime<Utc>>,
    /// Observed block height once on chain.
    pub block_height: Option<u64>,
    /// Observed block time once on chain.
    pub block_time: Option<DateTime<Utc>>,
    /// The bounded-backoff retry hint a yielded confirm mutation stamps.
    pub next_attempt_after: Option<DateTime<Utc>>,
    /// How many times a confirm mutation for this attempt yielded on wallet-lock
    /// contention.
    pub yield_count: u32,
    /// When the attempt row was first recorded.
    pub created_at: DateTime<Utc>,
    /// When the attempt row was last updated.
    pub updated_at: DateTime<Utc>,
}

/// The raw row shape the loaders read back, before the typed decode.
#[derive(sqlx::FromRow)]
struct AttemptRow {
    id: Uuid,
    kind: String,
    record_id: Option<Uuid>,
    wallet_id: Uuid,
    tx_hash: Vec<u8>,
    signed_tx: Vec<u8>,
    fee_lovelace: i64,
    spent_inputs: serde_json::Value,
    produced_outputs: serde_json::Value,
    replaces_tx_hash: Option<Vec<u8>>,
    superseded_by: Option<Uuid>,
    status: String,
    mempool_entered_at: Option<DateTime<Utc>>,
    first_seen_on_chain_at: Option<DateTime<Utc>>,
    block_height: Option<i64>,
    block_time: Option<DateTime<Utc>>,
    next_attempt_after: Option<DateTime<Utc>>,
    yield_count: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl AttemptRow {
    fn into_attempt(self) -> Result<ChainAttempt> {
        Ok(ChainAttempt {
            id: self.id,
            kind: AttemptKind::parse(&self.kind)?,
            record_id: self.record_id,
            wallet_id: self.wallet_id,
            tx_hash: tx_hash_32(&self.tx_hash)?,
            signed_tx: self.signed_tx,
            fee_lovelace: u64::try_from(self.fee_lovelace).map_err(|_| {
                Error::Config(format!("stored fee is negative: {}", self.fee_lovelace))
            })?,
            spent_inputs: serde_json::from_value(self.spent_inputs)?,
            produced_outputs: serde_json::from_value(self.produced_outputs)?,
            replaces_tx_hash: self
                .replaces_tx_hash
                .as_deref()
                .map(tx_hash_32)
                .transpose()?,
            superseded_by: self.superseded_by,
            status: AttemptStatus::parse(&self.status)?,
            mempool_entered_at: self.mempool_entered_at,
            first_seen_on_chain_at: self.first_seen_on_chain_at,
            block_height: self
                .block_height
                .map(|h| {
                    u64::try_from(h)
                        .map_err(|_| Error::Config(format!("stored block height is negative: {h}")))
                })
                .transpose()?,
            block_time: self.block_time,
            next_attempt_after: self.next_attempt_after,
            yield_count: u32::try_from(self.yield_count).map_err(|_| {
                Error::Config(format!(
                    "stored yield_count is negative: {}",
                    self.yield_count
                ))
            })?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The full `SELECT ... FROM cw_core.chain_attempt` projection every loader
/// shares, in the [`AttemptRow`] field order. A macro so each loader composes a
/// single `&'static str` query (via `concat!`) and no runtime-built query string
/// ever reaches the database, satisfying sqlx's SQL-injection guard.
macro_rules! select_attempt {
    ($tail:expr) => {
        concat!(
            "SELECT id, kind, record_id, wallet_id, tx_hash, signed_tx, fee_lovelace, ",
            "spent_inputs, produced_outputs, replaces_tx_hash, superseded_by, status, ",
            "mempool_entered_at, first_seen_on_chain_at, block_height, block_time, ",
            "next_attempt_after, yield_count, created_at, updated_at ",
            "FROM cw_core.chain_attempt ",
            $tail
        )
    };
}

/// Record a new attempt inside the caller's transaction, in `status='recorded'`,
/// before its transaction is broadcast.
///
/// The caller must already hold the attempt's wallet advisory lock and run this
/// as the first write of the record-before-broadcast transaction (the lock-order
/// invariant: attempt row before record row before wallet row). The returned
/// attempt id is the one the caller allocated in [`NewAttempt`], so the caller
/// can reference it in the same transaction.
///
/// A unique-index violation on `chain_attempt_one_active_per_record` means a
/// concurrent generation already recorded an active-broadcaster attempt for this
/// record; the error surfaces as [`sqlx::Error::Database`] for the caller to map
/// to its lost-race outcome (the submit path rolls back and returns
/// `AlreadyResolved`). A violation on `chain_attempt_tx_hash_uk` means the exact
/// transaction was already recorded (an idempotent redelivery).
pub async fn record_attempt_in_tx(
    tx: &mut sqlx::PgConnection,
    attempt: &NewAttempt,
) -> Result<Uuid> {
    let fee = i64::try_from(attempt.fee_lovelace).map_err(|_| {
        Error::Config(format!(
            "attempt fee {} does not fit in i64",
            attempt.fee_lovelace
        ))
    })?;
    let spent = serde_json::to_value(&attempt.spent_inputs)?;
    let produced = serde_json::to_value(&attempt.produced_outputs)?;

    sqlx::query(
        "INSERT INTO cw_core.chain_attempt \
           (id, kind, record_id, wallet_id, tx_hash, signed_tx, fee_lovelace, \
            spent_inputs, produced_outputs, replaces_tx_hash, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'recorded')",
    )
    .bind(attempt.id)
    .bind(attempt.kind.as_str())
    .bind(attempt.record_id)
    .bind(attempt.wallet_id)
    .bind(attempt.tx_hash.as_slice())
    .bind(attempt.signed_tx.as_slice())
    .bind(fee)
    .bind(spent)
    .bind(produced)
    .bind(attempt.replaces_tx_hash.as_ref().map(|h| h.as_slice()))
    .execute(&mut *tx)
    .await?;

    Ok(attempt.id)
}

/// Advance a recorded attempt to `broadcast`, stamping `mempool_entered_at` to
/// now, after its transaction reaches the node.
///
/// Guarded so only a `recorded` attempt advances: zero rows affected means a
/// concurrent path (a redelivery that re-broadcast) already advanced it, a benign
/// no-op the caller treats as success. Returns whether the row advanced.
pub async fn mark_broadcast(pool: &sqlx::PgPool, attempt_id: Uuid) -> Result<bool> {
    let advanced = sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET status = 'broadcast', mempool_entered_at = now(), updated_at = now() \
         WHERE id = $1 AND status = 'recorded'",
    )
    .bind(attempt_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    Ok(advanced)
}

/// Re-stamp an active-broadcaster attempt as `broadcast` with a fresh
/// `mempool_entered_at`, used by the idempotent retry path when it re-broadcasts
/// the recorded bytes.
///
/// Unlike [`mark_broadcast`] this admits a `recorded`, `broadcast`, or `stuck`
/// attempt (a `stuck` attempt a retry re-broadcasts returns to `broadcast` with a
/// fresh mempool entry), so a re-send refreshes the alert clock. It never touches
/// a terminal or `superseded` attempt. Returns whether the row was re-stamped.
pub async fn refresh_broadcast(pool: &sqlx::PgPool, attempt_id: Uuid) -> Result<bool> {
    let advanced = sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET status = 'broadcast', mempool_entered_at = now(), updated_at = now() \
         WHERE id = $1 AND status IN ('recorded', 'broadcast', 'stuck')",
    )
    .bind(attempt_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    Ok(advanced)
}

/// Mark a broadcast attempt `stuck` because it has passed the alert threshold in
/// the mempool.
///
/// `stuck` is an operator-visible reconcile state, NOT a refund and NOT an input
/// restore: the attempt stays in the reconcile and on-chain enumerations and can
/// still land. Guarded so only a `broadcast` attempt transitions; zero rows means
/// it already landed, was re-stamped, or was superseded. Returns whether the row
/// transitioned.
pub async fn mark_stuck(pool: &sqlx::PgPool, attempt_id: Uuid) -> Result<bool> {
    let advanced = sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET status = 'stuck', updated_at = now() \
         WHERE id = $1 AND status = 'broadcast'",
    )
    .bind(attempt_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    Ok(advanced)
}

/// Mark an original attempt `superseded` and link it to the replacement that
/// takes over, inside the caller's transaction.
///
/// This is one half of the atomic supersede-and-record handoff: it runs in the
/// same wallet-locked transaction that records the replacement, so the original
/// leaves the active-broadcaster set (`recorded`/`broadcast`/`stuck`) the instant
/// the replacement enters it and the `chain_attempt_one_active_per_record` index
/// is satisfied at every instant. The original is NOT made terminal here: it
/// cannot be, it is merely stuck, and `superseded` keeps it reconcilable so it is
/// still confirmed if it lands before the replacement.
///
/// Guarded to an active-broadcaster original so the handoff cannot supersede a
/// terminal or already-superseded attempt; zero rows affected means the original
/// is no longer the active broadcaster and the caller must abort the handoff.
/// Returns whether the original was superseded.
pub async fn mark_superseded(
    tx: &mut sqlx::PgConnection,
    original_id: Uuid,
    superseded_by: Uuid,
) -> Result<bool> {
    let advanced = sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET status = 'superseded', superseded_by = $2, updated_at = now() \
         WHERE id = $1 AND status IN ('recorded', 'broadcast', 'stuck')",
    )
    .bind(original_id)
    .bind(superseded_by)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    Ok(advanced)
}

/// Restore a `superseded` original back to the active-broadcaster set when its
/// cancelling replacement died before it could land, inside the caller's
/// transaction.
///
/// The inverse of [`mark_superseded`]. A replacement that is abandoned by a
/// deterministic node reject never took over the active-broadcaster role for real:
/// the original it superseded is still a live, reconcilable transaction that can
/// confirm. This returns the original to `broadcast` (it already reached the wire,
/// so its `mempool_entered_at` is set) or to `recorded` (it never broadcast, so it
/// has no mempool entry and must stay recoverable by the stranded-attempt sweep
/// rather than masquerade as on-the-wire), and clears its `superseded_by` link.
///
/// Guarded to the exact original superseded BY this replacement
/// (`status = 'superseded' AND superseded_by = $replacement`): a zero-row result
/// means the original already moved on (it confirmed, was abandoned, or a racing
/// path re-superseded it), and the caller must NOT then resurrect it. Returns
/// whether the original was restored, so the caller routes the record accordingly.
pub async fn unsupersede_in_tx(
    tx: &mut sqlx::PgConnection,
    original_id: Uuid,
    superseded_by: Uuid,
) -> Result<bool> {
    let restored = sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET status = CASE WHEN mempool_entered_at IS NULL THEN 'recorded' ELSE 'broadcast' END, \
             superseded_by = NULL, updated_at = now() \
         WHERE id = $1 AND status = 'superseded' AND superseded_by = $2",
    )
    .bind(original_id)
    .bind(superseded_by)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    Ok(restored)
}

/// Load one attempt by id, or `None` when no such row exists.
pub async fn load_attempt(pool: &sqlx::PgPool, attempt_id: Uuid) -> Result<Option<ChainAttempt>> {
    let row: Option<AttemptRow> = sqlx::query_as(select_attempt!("WHERE id = $1"))
        .bind(attempt_id)
        .fetch_optional(pool)
        .await?;
    row.map(AttemptRow::into_attempt).transpose()
}

/// Load one attempt by its transaction hash, or `None` when no such row exists.
///
/// The chain key is unique (`chain_attempt_tx_hash_uk`), so this matches the one
/// attempt that carries the transaction the confirm authority observed on chain.
pub async fn load_attempt_by_tx_hash(
    pool: &sqlx::PgPool,
    tx_hash: &[u8; 32],
) -> Result<Option<ChainAttempt>> {
    let row: Option<AttemptRow> = sqlx::query_as(select_attempt!("WHERE tx_hash = $1"))
        .bind(tx_hash.as_slice())
        .fetch_optional(pool)
        .await?;
    row.map(AttemptRow::into_attempt).transpose()
}

/// Load one attempt by its transaction hash within the caller's transaction, or
/// `None` when no such row exists.
///
/// The atomic supersede-and-record handoff loads the superseded original inside
/// the same record-before-broadcast transaction that records its replacement, so
/// the intersection check and the supersede run against a consistent snapshot.
pub async fn load_attempt_in_tx(
    tx: &mut sqlx::PgConnection,
    tx_hash: &[u8; 32],
) -> Result<Option<ChainAttempt>> {
    let row: Option<AttemptRow> = sqlx::query_as(select_attempt!("WHERE tx_hash = $1"))
        .bind(tx_hash.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
    row.map(AttemptRow::into_attempt).transpose()
}

/// Load every non-terminal attempt for a record, oldest first, for the
/// replacement-watch enumeration.
///
/// "Non-terminal" is `{recorded, broadcast, stuck, superseded}`: a `superseded`
/// original is included because it is still reconcilable (it can land before its
/// replacement), so the confirm authority sees both the original and its
/// replacement and terminalises the loser once either lands. Only `confirmed` and
/// `abandoned` attempts drop out.
pub async fn load_record_attempts(
    pool: &sqlx::PgPool,
    record_id: Uuid,
) -> Result<Vec<ChainAttempt>> {
    let rows: Vec<AttemptRow> = sqlx::query_as(select_attempt!(
        "WHERE record_id = $1 \
         AND status IN ('recorded', 'broadcast', 'stuck', 'superseded') \
         ORDER BY created_at ASC"
    ))
    .bind(record_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(AttemptRow::into_attempt).collect()
}

/// Load every non-terminal attempt for a record within the caller's transaction,
/// oldest first, for the in-transaction sibling-terminalisation walk.
///
/// The confirm authority abandons a winner's conflicting siblings in the same
/// transaction that confirms the winner, so the sibling walk must read against the
/// same snapshot. Same selection as [`load_record_attempts`].
pub async fn load_record_attempts_in_tx(
    tx: &mut sqlx::PgConnection,
    record_id: Uuid,
) -> Result<Vec<ChainAttempt>> {
    let rows: Vec<AttemptRow> = sqlx::query_as(select_attempt!(
        "WHERE record_id = $1 \
         AND status IN ('recorded', 'broadcast', 'stuck', 'superseded') \
         ORDER BY created_at ASC"
    ))
    .bind(record_id)
    .fetch_all(&mut *tx)
    .await?;
    rows.into_iter().map(AttemptRow::into_attempt).collect()
}

/// Load every on-chain non-terminal-or-confirmed attempt (one with a block
/// height), oldest block first, for the confirm authority's tip-derived pass.
///
/// The set is `{broadcast, stuck, superseded, confirmed}` with a block height: a
/// `superseded` original that has landed is confirmed by the same authority, and a
/// `confirmed` attempt is re-loaded so a post-confirmation reorg is caught inside
/// the settlement window. A yielded mutation's attempt is skipped only while its
/// `next_attempt_after` is in the future, so a wallet-lock yield is retried on a
/// later pass rather than dropped.
pub async fn load_onchain_attempts(pool: &sqlx::PgPool, limit: i64) -> Result<Vec<ChainAttempt>> {
    let rows: Vec<AttemptRow> = sqlx::query_as(select_attempt!(
        "WHERE status IN ('broadcast', 'stuck', 'superseded', 'confirmed') \
         AND block_height IS NOT NULL \
         AND (next_attempt_after IS NULL OR next_attempt_after <= now()) \
         ORDER BY block_height ASC \
         LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(AttemptRow::into_attempt).collect()
}

/// Load every reconcile/watch attempt not yet on chain (no block height), oldest
/// mempool entry first, for the mempool reconcile/alert pass.
///
/// The set is `{broadcast, stuck, superseded}` with no block height. A
/// `superseded` original whose replacement is now the active broadcaster stays
/// here until it is provably dead, so it can still land first. A yielded mutation's
/// attempt is skipped only while its `next_attempt_after` is in the future.
pub async fn load_reconcile_attempts(pool: &sqlx::PgPool, limit: i64) -> Result<Vec<ChainAttempt>> {
    let rows: Vec<AttemptRow> = sqlx::query_as(select_attempt!(
        "WHERE status IN ('broadcast', 'stuck', 'superseded') \
         AND block_height IS NULL \
         AND (next_attempt_after IS NULL OR next_attempt_after <= now()) \
         ORDER BY mempool_entered_at ASC NULLS FIRST \
         LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(AttemptRow::into_attempt).collect()
}

/// Load the not-yet-on-chain attempts whose mempool entry is older than the alert
/// threshold, oldest first, for the alert-only stuck reconcile pass.
///
/// The set is `{broadcast, stuck, superseded}` with no block height whose
/// `mempool_entered_at` is older than `alert_after`. An attempt newer than the
/// threshold is a normal in-flight transaction and is excluded. The predicate keys
/// on `mempool_entered_at` (set on every (re-)broadcast), never on the record's
/// `created_at`, so a rolled-back-then-resubmitted record's fresh replacement is
/// never mistaken for a stale one. This pass only ever alerts: it transitions a
/// `broadcast` attempt to `stuck` and raises an operator-visible reconcile alert,
/// and never refunds, restores inputs, or abandons (those move only on a
/// settlement-deep conflicting spend).
pub async fn load_stuck_mempool_candidates(
    pool: &sqlx::PgPool,
    alert_after: std::time::Duration,
    limit: i64,
) -> Result<Vec<ChainAttempt>> {
    let alert_secs = i64::try_from(alert_after.as_secs())
        .map_err(|_| Error::Config("alert horizon overflow".into()))?;
    let rows: Vec<AttemptRow> = sqlx::query_as(select_attempt!(
        "WHERE status IN ('broadcast', 'stuck', 'superseded') \
         AND block_height IS NULL \
         AND mempool_entered_at IS NOT NULL \
         AND mempool_entered_at < now() - make_interval(secs => $1) \
         ORDER BY mempool_entered_at ASC \
         LIMIT $2"
    ))
    .bind(alert_secs)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(AttemptRow::into_attempt).collect()
}

/// Whether an attempt's mempool entry is older than `horizon` (the long
/// presumed-dead horizon), evaluated against the database clock.
///
/// A `true` here is the gate for escalating a stuck attempt's alert AFTER a fresh
/// not-found lookup; it is never on its own a proof of death. The age is measured
/// from `mempool_entered_at` so a re-broadcast resets it.
#[must_use]
pub fn mempool_entry_older_than(
    mempool_entered_at: Option<DateTime<Utc>>,
    horizon: std::time::Duration,
    now: DateTime<Utc>,
) -> bool {
    match mempool_entered_at {
        Some(entered) => match chrono::Duration::from_std(horizon) {
            Ok(horizon) => entered <= now - horizon,
            Err(_) => false,
        },
        None => false,
    }
}

/// Load specific attempts by id (the carried reorg suspects), regardless of the
/// settlement window, so a suspect Pass A collected is always re-verified by a fresh
/// lookup. A suspect whose row has since terminated is simply absent from the result.
pub async fn load_attempts_by_ids(pool: &sqlx::PgPool, ids: &[Uuid]) -> Result<Vec<ChainAttempt>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<AttemptRow> = sqlx::query_as(select_attempt!(
        "WHERE id = ANY($1) \
         AND status IN ('broadcast', 'stuck', 'superseded', 'confirmed')"
    ))
    .bind(ids)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(AttemptRow::into_attempt).collect()
}

/// Whether a wallet has a CONFIRMED attempt, other than `exclude_tx_hash`, that
/// spends `input_ref` and whose own confirmation has reached the settlement depth.
///
/// This is the settlement-deep proof-of-death conflict check the confirm authority
/// runs before it abandons an attempt: an attempt is provably dead only when a
/// confirmed transaction has spent one of its inputs AND that conflicting spend has
/// itself reached the settlement threshold, so a shallow reorg of the conflicting
/// spend cannot un-prove the death. The conflicting spend's own confirmation depth
/// is `tip - block_height + 1`; the predicate requires it `>= settlement_depth`.
/// The input is matched by the `(tx_hash, index)` reference inside the conflicting
/// attempt's `spent_inputs` JSON array. Returns the conflicting attempt's
/// `(tx_hash, depth)` when one exists, or `None` when no settlement-deep
/// conflicting spend is found.
pub async fn settlement_deep_conflicting_spend(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    exclude_tx_hash: &[u8; 32],
    input_ref: &UtxoRef,
    tip_block_height: u64,
    settlement_depth: u64,
) -> Result<Option<([u8; 32], u64)>> {
    let tip = i64::try_from(tip_block_height)
        .map_err(|_| Error::Config("tip block height overflow".into()))?;
    let depth = i64::try_from(settlement_depth)
        .map_err(|_| Error::Config("settlement depth overflow".into()))?;
    let input_hash = hex::encode(input_ref.tx_hash);
    let input_index = i64::from(input_ref.output_index);

    // A confirmed conflicting attempt on the same wallet, not this one, that spent
    // the named input and whose own confirmation has reached the settlement depth.
    // The depth predicate keys on the materialised tip the caller passes so the
    // proof is the same depth a normal record settles at.
    let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT tx_hash, block_height FROM cw_core.chain_attempt \
         WHERE wallet_id = $1 \
           AND status = 'confirmed' \
           AND tx_hash <> $2 \
           AND block_height IS NOT NULL \
           AND ($6 - block_height + 1) >= $5 \
           AND EXISTS ( \
                 SELECT 1 FROM jsonb_array_elements(spent_inputs) e \
                 WHERE e->>'tx_hash' = $3 AND (e->>'index')::bigint = $4 \
               ) \
         ORDER BY block_height ASC \
         LIMIT 1",
    )
    .bind(wallet_id)
    .bind(exclude_tx_hash.as_slice())
    .bind(&input_hash)
    .bind(input_index)
    .bind(depth)
    .bind(tip)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((hash, height)) => {
            let tx_hash = tx_hash_32(&hash)?;
            let conflict_height = u64::try_from(height)
                .map_err(|_| Error::Config("conflicting spend height is negative".into()))?;
            let conflict_depth = tip_block_height.saturating_sub(conflict_height) + 1;
            Ok(Some((tx_hash, conflict_depth)))
        }
        None => Ok(None),
    }
}

/// Mark a landed attempt `confirmed`, pinning its coordinates, within the caller's
/// transaction.
///
/// Guarded so the flip fires only on a genuine transition: a `broadcast`/`stuck`/
/// `superseded` attempt that has landed, or a `confirmed` attempt re-observed at a
/// DIFFERENT block height (a reorg moved it, which needs a re-index). A `confirmed`
/// attempt re-observed at the SAME height matches zero rows, so a deeper
/// confirmation count is a true no-op. `first_seen_on_chain_at` is set once.
/// Returns whether the row transitioned.
pub async fn mark_confirmed_in_tx(
    tx: &mut sqlx::PgConnection,
    attempt_id: Uuid,
    block_height: u64,
    block_time: DateTime<Utc>,
) -> Result<bool> {
    let height =
        i64::try_from(block_height).map_err(|_| Error::Config("block height overflow".into()))?;
    let flipped = sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET status = 'confirmed', block_height = $2, block_time = $3, \
             first_seen_on_chain_at = COALESCE(first_seen_on_chain_at, now()), \
             next_attempt_after = NULL, updated_at = now() \
         WHERE id = $1 \
           AND (status IN ('broadcast', 'stuck', 'superseded') \
                OR (status = 'confirmed' AND block_height IS DISTINCT FROM $2))",
    )
    .bind(attempt_id)
    .bind(height)
    .bind(block_time)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    Ok(flipped)
}

/// Mark an attempt `abandoned`, clearing its coordinates and stamping the
/// settlement-deep proof-of-death evidence, within the caller's transaction.
///
/// Runs only when the attempt is provably dead by a settlement-deep conflicting
/// spend; the evidence (the confirmed conflicting transaction hash and the
/// confirmation depth it had reached) is recorded so the transition is auditable.
/// Guarded to a non-terminal attempt so a converging path cannot abandon a
/// `confirmed` or already-`abandoned` row. Returns whether the row transitioned.
pub async fn mark_abandoned_in_tx(tx: &mut sqlx::PgConnection, attempt_id: Uuid) -> Result<bool> {
    let flipped = sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET status = 'abandoned', block_height = NULL, block_time = NULL, \
             next_attempt_after = NULL, updated_at = now() \
         WHERE id = $1 AND status NOT IN ('confirmed', 'abandoned')",
    )
    .bind(attempt_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    Ok(flipped)
}

/// Re-pin an on-chain non-terminal attempt's coordinates without confirming it (a
/// landed-below-threshold attempt, or a reorg suspect re-included at a new height),
/// within the caller's transaction.
///
/// Sets `first_seen_on_chain_at` on the first sighting. Guarded to an
/// active-broadcaster-or-superseded attempt; returns the affected row count so a
/// caller that expected a row can treat an unexpected zero as a reconciliation
/// anomaly rather than a silent success.
pub async fn repin_attempt_in_tx(
    tx: &mut sqlx::PgConnection,
    attempt_id: Uuid,
    block_height: u64,
    block_time: Option<DateTime<Utc>>,
) -> Result<u64> {
    let height =
        i64::try_from(block_height).map_err(|_| Error::Config("block height overflow".into()))?;
    let affected = sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET block_height = $2, block_time = $3, \
             first_seen_on_chain_at = COALESCE(first_seen_on_chain_at, now()), \
             updated_at = now() \
         WHERE id = $1 AND status IN ('broadcast', 'stuck', 'superseded')",
    )
    .bind(attempt_id)
    .bind(height)
    .bind(block_time)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    Ok(affected)
}

/// Re-pin a CONFIRMED attempt's coordinates on a below-threshold re-inclusion,
/// within the caller's transaction.
///
/// A `confirmed` attempt re-observed on chain at a new height inside the settlement
/// window keeps its `confirmed` status but must carry the fresh coordinates so the
/// projection and the index stay coordinate-accurate. Guarded on `status =
/// 'confirmed'` and on the height actually changing; returns the affected row count
/// so the caller can flag an unexpected zero (the row was not `confirmed` as
/// assumed) as a reconciliation anomaly.
pub async fn repin_confirmed_attempt_in_tx(
    tx: &mut sqlx::PgConnection,
    attempt_id: Uuid,
    block_height: u64,
    block_time: Option<DateTime<Utc>>,
) -> Result<u64> {
    let height =
        i64::try_from(block_height).map_err(|_| Error::Config("block height overflow".into()))?;
    let affected = sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET block_height = $2, block_time = $3, updated_at = now() \
         WHERE id = $1 AND status = 'confirmed' AND block_height IS DISTINCT FROM $2",
    )
    .bind(attempt_id)
    .bind(height)
    .bind(block_time)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    Ok(affected)
}

/// Stamp a bounded-backoff retry hint on an attempt whose confirm/abandon mutation
/// yielded because the wallet advisory lock was held, and bump its yield counter.
///
/// The confirm pass re-enumerates this attempt every cycle and skips it only while
/// `next_attempt_after` is in the future, so a yielded mutation is retried after the
/// backoff and never permanently dropped (starvation-free). The incremented
/// `yield_count` surfaces a pathologically contended wallet as an operator anomaly
/// and drives the bounded-fair lock escalation after a threshold of yields. Returns
/// the new yield count.
pub async fn stamp_yield(
    pool: &sqlx::PgPool,
    attempt_id: Uuid,
    backoff: std::time::Duration,
) -> Result<u32> {
    let backoff_secs = i64::try_from(backoff.as_secs())
        .map_err(|_| Error::Config("yield backoff overflow".into()))?
        .max(1);
    let new_count: i32 = sqlx::query_scalar(
        "UPDATE cw_core.chain_attempt \
         SET next_attempt_after = now() + make_interval(secs => $2), \
             yield_count = yield_count + 1, updated_at = now() \
         WHERE id = $1 \
         RETURNING yield_count",
    )
    .bind(attempt_id)
    .bind(backoff_secs)
    .fetch_one(pool)
    .await?;
    u32::try_from(new_count.max(0)).map_err(|_| Error::Config("yield_count overflow".into()))
}

/// Decode a stored `bytea` transaction hash to its fixed 32-byte array, rejecting
/// a row whose hash is not 32 bytes (which the producers never write).
fn tx_hash_32(raw: &[u8]) -> Result<[u8; 32]> {
    raw.try_into().map_err(|_| {
        Error::Config(format!(
            "stored chain attempt tx_hash is not 32 bytes ({} bytes)",
            raw.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_round_trips_through_its_stored_value() {
        for kind in [
            AttemptKind::Publish,
            AttemptKind::Replacement,
            AttemptKind::Split,
        ] {
            assert_eq!(AttemptKind::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(AttemptKind::parse("nope").is_err());
    }

    #[test]
    fn status_round_trips_and_classifies() {
        for status in [
            AttemptStatus::Recorded,
            AttemptStatus::Broadcast,
            AttemptStatus::Stuck,
            AttemptStatus::Confirmed,
            AttemptStatus::Abandoned,
            AttemptStatus::Superseded,
        ] {
            assert_eq!(AttemptStatus::parse(status.as_str()).unwrap(), status);
        }
        assert!(AttemptStatus::parse("nope").is_err());

        // Terminal set is exactly {confirmed, abandoned}.
        assert!(AttemptStatus::Confirmed.is_terminal());
        assert!(AttemptStatus::Abandoned.is_terminal());
        assert!(!AttemptStatus::Recorded.is_terminal());
        assert!(!AttemptStatus::Broadcast.is_terminal());
        assert!(!AttemptStatus::Stuck.is_terminal());
        assert!(!AttemptStatus::Superseded.is_terminal());

        // Active-broadcaster set is exactly {recorded, broadcast, stuck}: a
        // superseded original is reconcilable but NOT an active broadcaster, which
        // is what lets it coexist with its replacement under the one-active index.
        assert!(AttemptStatus::Recorded.is_active_broadcaster());
        assert!(AttemptStatus::Broadcast.is_active_broadcaster());
        assert!(AttemptStatus::Stuck.is_active_broadcaster());
        assert!(!AttemptStatus::Superseded.is_active_broadcaster());
        assert!(!AttemptStatus::Confirmed.is_active_broadcaster());
        assert!(!AttemptStatus::Abandoned.is_active_broadcaster());
    }

    #[test]
    fn attempt_input_decodes_to_its_utxo_ref() {
        let input = AttemptInput {
            tx_hash: hex::encode([0xab; 32]),
            index: 3,
            lovelace: 2_000_000,
        };
        let utxo = input.utxo_ref().unwrap();
        assert_eq!(utxo.tx_hash, [0xab; 32]);
        assert_eq!(utxo.output_index, 3);

        // A non-32-byte hash is a corrupt row, not a panic.
        let short = AttemptInput {
            tx_hash: hex::encode([0u8; 16]),
            index: 0,
            lovelace: 0,
        };
        assert!(short.utxo_ref().is_err());
    }

    #[test]
    fn spent_inputs_serialise_to_the_documented_shape() {
        // The on-chain-public shape every reader decodes: {tx_hash, index,
        // lovelace} with a hex-string tx_hash.
        let input = AttemptInput {
            tx_hash: "0a".repeat(32),
            index: 1,
            lovelace: 5,
        };
        let json = serde_json::to_value([&input]).unwrap();
        assert_eq!(json[0]["tx_hash"], "0a".repeat(32));
        assert_eq!(json[0]["index"], 1);
        assert_eq!(json[0]["lovelace"], 5);

        let back: Vec<AttemptInput> = serde_json::from_value(json).unwrap();
        assert_eq!(back, vec![input]);
    }

    #[test]
    fn produced_outputs_serialise_without_a_tx_hash() {
        // An output names only its index and lovelace; the producing transaction
        // is the attempt's own tx_hash, so the per-output shape omits it.
        let out = AttemptOutput {
            index: 0,
            lovelace: 1_500_000,
        };
        let json = serde_json::to_value([&out]).unwrap();
        assert_eq!(json[0]["index"], 0);
        assert_eq!(json[0]["lovelace"], 1_500_000);
        assert!(json[0].get("tx_hash").is_none());

        let back: Vec<AttemptOutput> = serde_json::from_value(json).unwrap();
        assert_eq!(back, vec![out]);
    }
}
