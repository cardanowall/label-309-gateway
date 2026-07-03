//! The confirmation and reorg-reconciliation loop.
//!
//! A singleton loop ([`CONFIRM_QUEUE`]) drives every live record toward a
//! terminal state. It never writes `chain_records` itself: on a threshold-flip it
//! enqueues an [`crate::chain::records::INDEX_TX_QUEUE`] job in the same
//! transaction that flips the record to `confirmed`, so the single writer owns
//! the index and the flip-plus-enqueue is atomic (the in-transaction enqueue is
//! what closes the stranded-row gap, where a crash between the state change and
//! the enqueue would leave a confirmed record that never got indexed).
//!
//! # Passes
//!
//! Each iteration runs, in order:
//!
//! - **Pass A (tip-derived, zero HTTP).** For every `submitted` record with a
//!   block height, derive `num_confirmations = max(0, tip - block_height + 1)`
//!   from the materialised [`crate::chain::records`] tip. At or above the
//!   threshold the record flips to `confirmed` and an index job is enqueued in
//!   the same transaction. Below the threshold but still inside the rollback
//!   window it is live progress; past the rollback window it becomes a reorg
//!   suspect for Pass C.
//! - **Pass A-reverify (settlement window).** `confirmed` records still within
//!   the settlement window ride the same batched gateway call as Pass B/C with
//!   their prior block height, so a post-confirmation reorg is caught.
//! - **Pass B (mempool discovery).** `submitted` records with no block height yet
//!   are looked up in one batched [`crate::chain::gateway::ChainGateway::get_tx_confirmations`]
//!   call. A record still absent past the mempool alert horizon is marked stuck and
//!   surfaced for operator reconciliation; it is never refunded on age or absence
//!   alone, because a transaction with no validity interval can still land later.
//! - **Pass C (reorg re-verification).** A reorg is confirmed only under a
//!   TWO-SOURCE gate: the materialised tip has advanced past the rollback window
//!   (the arithmetic source) AND a fresh gateway lookup reports the transaction
//!   gone from chain (the observation source). Only when both agree does the
//!   rollback decision tree run.
//!
//! # Rollback
//!
//! A confirmed reorg resubmits a cancelling replacement that spends an input of
//! the rolled-back transaction, so at most one of the two can ever land; the state
//! clear and the resubmit enqueue happen in one transaction. A record is refunded
//! and marked `permanent_failure` only on proof of death: a conflicting spend of
//! one of its inputs that has itself reached settlement depth, so the original can
//! never re-land and settle an already-refunded record. Elapsed time or a bare
//! "absent from this block" is never sufficient.
//!
//! # Rate-limit storm
//!
//! When every gateway attempt in an iteration returned 429 the handler returns
//! [`JobOutcome::Defer`] for the rate-limit backoff window, which does NOT consume
//! the single attempt the queue allows: a sustained storm parks the loop instead
//! of failing it.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::chain::attempt::{self, AttemptInput};
use crate::ledger::journal::{insert_ledger_entry, LedgerEntry};
use crate::runtime::{Backoff, JobContext, JobHandler, JobOutcome};
use crate::wallet::utxo::UtxoRef;
use crate::Result;

/// The ledger kind the publish route debited the account's balance under: the
/// network+service charge keyed on the record id (storage is debited separately
/// at upload). The permanent-failure auto-refund reads the debit back under this
/// kind and credits the same magnitude.
const PUBLISH_DEBIT_KIND: &str = "poe_publish";

/// The ledger kind the permanent-failure auto-refund credits the network+service
/// charge back under, keyed on the record id. Reusing the failure cause is fine:
/// both a submit-permanent-failure and a reorg-cap exhaustion credit the same
/// reversal of the same debit, and the precise cause is recorded on the
/// `refund_intent.reason` row that rides the same transaction.
const PUBLISH_REFUND_KIND: &str = "refund_rollback";

/// The queue the confirmation loop runs on.
pub const CONFIRM_QUEUE: &str = "cardano_confirm";

/// Steady-state loop cadence, matched to Cardano's block time so the loop sees
/// roughly one new block per iteration.
pub const CONFIRM_REENQUEUE_SECS: u32 = 20;

/// The maximum number of live records reconciled per iteration.
pub const CONFIRM_BATCH_LIMIT: i64 = 500;

/// The number of confirmations a record must accrue to be settled. (A deployment
/// may override this; the loader reads it from config.)
pub const DEFAULT_CONFIRMATION_THRESHOLD: u64 = 15;

/// How far past a record's block height the tip must advance before a missing
/// transaction is treated as a reorg candidate (the arithmetic half of the
/// two-source gate).
pub const DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 = 15;

/// The post-confirmation window, in blocks, a `confirmed` record is re-verified
/// over so a reorg shortly after settlement is still caught (~2x the threshold).
pub const DEFAULT_SETTLEMENT_REVERIFY_BLOCKS: u64 = 30;

/// The maximum number of times a reorg may roll a record back and resubmit a
/// cancelling replacement before the loop stops issuing replacements.
pub const DEFAULT_MAX_ROLLBACK_RETRIES: u32 = 5;

/// How long an attempt may sit in the mempool past its `mempool_entered_at` before
/// it is marked `stuck` and surfaced as an operator-reconcile alert. This gates
/// only alerting; under the no-validity-interval model a stuck attempt is never
/// refunded or restored on age, only on a settlement-deep conflicting spend.
pub const DEFAULT_MEMPOOL_ALERT_AFTER: Duration = Duration::from_secs(1800);

/// How long an attempt may sit in the mempool before, on a fresh "not found"
/// lookup, its alert is escalated to "long-stuck, presumed dead". This too gates
/// only alerting: a not-found transaction can still be rebroadcast and land while
/// its inputs are unspent, so absence is never a proof of death.
pub const DEFAULT_MEMPOOL_PROOF_OF_DEATH_AFTER: Duration = Duration::from_secs(7200);

/// The number of times a confirm/abandon wallet mutation may yield on wallet-lock
/// contention before it escalates from a non-blocking try-acquire to a
/// bounded-deadline fair acquire, so a persistently-contended record's mutation is
/// applied in bounded time rather than only eventually. A `yield_count` past this
/// threshold is also surfaced as an operator-reconcile anomaly.
pub const DEFAULT_MAX_LOCK_YIELDS: u32 = 5;

/// The bounded deadline the escalated fair acquire waits for the wallet lock, once
/// a mutation has yielded past [`DEFAULT_MAX_LOCK_YIELDS`].
pub const DEFAULT_FAIR_LOCK_DEADLINE: Duration = Duration::from_secs(5);

/// The backoff a yielded confirm/abandon mutation stamps as `next_attempt_after`,
/// so the next pass retries it after the wait rather than busy-spinning.
pub const LOCK_YIELD_BACKOFF: Duration = Duration::from_secs(2);

/// The base of the rollback-retry backoff: the nth retry is delayed
/// `20 * 2^n` seconds, capped at [`ROLLBACK_RETRY_BACKOFF_CAP_SECS`].
pub const ROLLBACK_RETRY_BACKOFF_BASE_SECS: u32 = 20;

/// The ceiling on the rollback-retry backoff.
pub const ROLLBACK_RETRY_BACKOFF_CAP_SECS: u32 = 300;

/// The exponential rollback-retry backoff for the `n`th retry (0-based),
/// `20 * 2^n` seconds capped at [`ROLLBACK_RETRY_BACKOFF_CAP_SECS`]. Saturates so
/// a large retry count can never overflow.
#[must_use]
pub fn rollback_retry_backoff_secs(retry_count: u32) -> u32 {
    let shift = retry_count.min(31);
    ROLLBACK_RETRY_BACKOFF_BASE_SECS
        .saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
        .min(ROLLBACK_RETRY_BACKOFF_CAP_SECS)
}

/// The confirmation loop's tuning, read from config so a deployment can override
/// the thresholds without a code change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmConfig {
    /// Confirmations required to settle a record.
    pub confirmation_threshold: u64,
    /// Blocks past a record's height before a missing transaction is a reorg
    /// candidate.
    pub rollback_window_blocks: u64,
    /// Blocks past settlement a `confirmed` record is re-verified over.
    pub settlement_reverify_blocks: u64,
    /// The rollback-retry budget: how many cancelling replacements a record may be
    /// rolled forward with before the loop stops issuing them.
    pub max_rollback_retries: u32,
    /// How long an attempt may sit in the mempool before it is marked `stuck` and
    /// alerted (gates alerting only, never a refund).
    pub mempool_alert_after: Duration,
    /// How long an attempt may sit in the mempool before a fresh not-found lookup
    /// escalates its alert (gates alerting only, never a refund).
    pub mempool_proof_of_death_after: Duration,
    /// How many wallet-lock yields a confirm/abandon mutation may take before it
    /// escalates to a bounded-fair acquire.
    pub max_lock_yields: u32,
    /// The bounded deadline the escalated fair acquire waits for the wallet lock.
    pub fair_lock_deadline: Duration,
}

impl ConfirmConfig {
    /// The settlement depth a conflicting spend must reach to count as proof of
    /// death: the same confirmation threshold a normal record settles at, so a
    /// conflicting spend that is itself reorged out before this depth cannot
    /// un-prove the death of the attempt it conflicts with.
    #[must_use]
    pub fn settlement_depth(&self) -> u64 {
        self.confirmation_threshold
    }
}

impl Default for ConfirmConfig {
    fn default() -> Self {
        Self {
            confirmation_threshold: DEFAULT_CONFIRMATION_THRESHOLD,
            rollback_window_blocks: DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            settlement_reverify_blocks: DEFAULT_SETTLEMENT_REVERIFY_BLOCKS,
            max_rollback_retries: DEFAULT_MAX_ROLLBACK_RETRIES,
            mempool_alert_after: DEFAULT_MEMPOOL_ALERT_AFTER,
            mempool_proof_of_death_after: DEFAULT_MEMPOOL_PROOF_OF_DEATH_AFTER,
            max_lock_yields: DEFAULT_MAX_LOCK_YIELDS,
            fair_lock_deadline: DEFAULT_FAIR_LOCK_DEADLINE,
        }
    }
}

/// The policy for the confirm queue: a singleton loop (one in-flight iteration
/// across the deployment), a single attempt (the handler defers on a storm rather
/// than failing, so it never needs the runtime's retry), a fixed re-enqueue
/// cadence matched to block time, and a long lease covering a full batched pass.
#[must_use]
pub fn confirm_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        CONFIRM_QUEUE,
        1,
        Backoff::Fixed {
            base_secs: CONFIRM_REENQUEUE_SECS,
        },
        600,
    )
}

/// A schedule that fires the confirmation loop every 20 seconds. The
/// singleton-loop policy keeps a single iteration in flight; the cron tick is the
/// steady wake-up between handler-driven re-enqueues.
#[must_use]
pub fn confirm_schedule() -> crate::runtime::scheduler::CronSchedule {
    // croner supports seconds-resolution; every 20 seconds is "*/20 * * * * *".
    crate::runtime::scheduler::CronSchedule::new(
        "*/20 * * * * *",
        CONFIRM_QUEUE,
        serde_json::Value::Null,
    )
}

/// The materialised-tip upsert: monotonic per network via GREATEST.
///
/// The indexer is the single owner of the `/tip` HTTP read and writes this row;
/// the confirm loop reads it for Pass A and the protocol-parameter populate loop
/// reads its epoch. GREATEST guarantees a behind-the-times observation can never
/// regress a higher tip already known.
///
/// The epoch is adopted only when the observation carried a STRICTLY higher tip
/// height (and that height itself carried an epoch). The strict comparison is
/// deliberate: an equal-height observation must never swap the recorded epoch,
/// since two replicas (or a delayed retry) can report the same height with
/// epoch readings from different instants, and the later-arriving one could be
/// the stale one. So the epoch always belongs to the highest height ever
/// observed, and an equal-height race can never corrupt it. A strictly-higher
/// observation carries its OWN epoch onto the new height (no COALESCE with the
/// prior): the stored `(height, epoch)` pair is always coherent, describing one
/// tip. If that observation omitted the epoch the stored epoch becomes NULL,
/// which makes the populate loop do a single `/tip` fallback to recover the real
/// epoch rather than serve the prior (older-height) epoch as if it were current.
/// Every real provider returns the epoch with the tip (Koios `epoch_no`,
/// Blockfrost `epoch`), so that fallback is effectively unreachable; the NULL
/// path exists only so a height can never advance while the stored epoch silently
/// belongs to an older height.
/// Returns the materialised (monotonic) tip height AFTER the upsert: GREATEST of
/// the new observation and any height already recorded. A behind-the-times
/// observation (a stale fallback `/tip`, a provider whose tip regressed) therefore
/// yields the higher stored height, never the regressed value — so a caller that
/// compares the scan cursor against this height can never be fooled into looking
/// caught-up (and stalling, or jumping past records) by a momentary tip
/// regression.
pub async fn upsert_tip(
    pool: &sqlx::PgPool,
    network: &str,
    tip_block_height: u64,
    tip_epoch: Option<u64>,
) -> Result<u64> {
    let height = i64::try_from(tip_block_height)
        .map_err(|_| crate::Error::Config("tip block height overflow".into()))?;
    let epoch = tip_epoch
        .map(|e| i32::try_from(e).map_err(|_| crate::Error::Config("tip epoch overflow".into())))
        .transpose()?;
    let materialised: i64 = sqlx::query_scalar(
        "INSERT INTO cw_core.cardano_tip (network, tip_block_height, tip_epoch, tip_observed_at) \
         VALUES ($1, $2, $3, now()) \
         ON CONFLICT (network) DO UPDATE SET \
           tip_block_height = GREATEST(cw_core.cardano_tip.tip_block_height, EXCLUDED.tip_block_height), \
           tip_epoch = CASE \
             WHEN EXCLUDED.tip_block_height > cw_core.cardano_tip.tip_block_height \
               THEN EXCLUDED.tip_epoch \
             ELSE cw_core.cardano_tip.tip_epoch \
           END, \
           tip_observed_at = EXCLUDED.tip_observed_at \
         RETURNING tip_block_height",
    )
    .bind(network)
    .bind(height)
    .bind(epoch)
    .fetch_one(pool)
    .await?;
    u64::try_from(materialised)
        .map_err(|_| crate::Error::Config("materialised tip height is negative".into()))
}

/// Read the materialised tip height for a network, or `None` when the indexer has
/// not yet recorded one.
pub async fn read_tip(pool: &sqlx::PgPool, network: &str) -> Result<Option<u64>> {
    let height: Option<i64> =
        sqlx::query_scalar("SELECT tip_block_height FROM cw_core.cardano_tip WHERE network = $1")
            .bind(network)
            .fetch_optional(pool)
            .await?;
    match height {
        Some(h) => Ok(Some(u64::try_from(h).map_err(|_| {
            crate::Error::Config("stored tip height is negative".into())
        })?)),
        None => Ok(None),
    }
}

/// Read the materialised tip epoch for a network: `None` when no tip row exists
/// yet (cold start) and `None` when a row exists but carries no epoch (a provider
/// that omitted it, or a row written before the epoch was materialised). The
/// protocol-parameter populate loop reads this to learn the current epoch without
/// its own `/tip` call, and falls back to a single provider tip read on `None`.
pub async fn read_tip_epoch(pool: &sqlx::PgPool, network: &str) -> Result<Option<u64>> {
    let epoch: Option<i32> =
        sqlx::query_scalar("SELECT tip_epoch FROM cw_core.cardano_tip WHERE network = $1")
            .bind(network)
            .fetch_optional(pool)
            .await?
            .flatten();
    match epoch {
        Some(e) => Ok(Some(u64::try_from(e).map_err(|_| {
            crate::Error::Config("stored tip epoch is negative".into())
        })?)),
        None => Ok(None),
    }
}

/// A terminal-failure reason, stored on the refund intent and the
/// permanent-failure event. The full taxonomy spans the submit terminal arms and
/// the confirm-side give-up paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundReason {
    /// The transaction could not be built after the attempt budget (submit).
    TxBuildFailed,
    /// The record exceeded the protocol byte budget (submit, immediate).
    ByteBudgetExceeded,
    /// A reorg rolled the record back more times than the retry budget allows.
    RollbackRetriesExhausted,
    /// A cancelling replacement could not be built because its forced-input set
    /// was empty or malformed (submit, immediate). Without forced inputs the
    /// replacement cannot guarantee it cancels the rolled-back transaction, so the
    /// record is refunded rather than resubmitted as a non-cancelling (and thus
    /// double-publishing) submit.
    ReplacementInputsMissing,
    /// A cancelling replacement's recorded inputs did not intersect the superseded
    /// original's, so it would not have cancelled the transaction it replaced
    /// (submit, immediate). Rejected at record time before any broadcast.
    ReplacementDoesNotConflict,
    /// The node rejected the transaction body deterministically (a ledger-invalid
    /// or already-spent submit). The recorded attempt was abandoned with its inputs
    /// restored, and the record refunded (submit, immediate).
    NodeRejected,
}

impl RefundReason {
    /// The stable string stored in `refund_intent.reason`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RefundReason::TxBuildFailed => "tx_build_failed",
            RefundReason::ByteBudgetExceeded => "byte_budget_exceeded",
            RefundReason::RollbackRetriesExhausted => "rollback_retries_exhausted",
            RefundReason::ReplacementInputsMissing => "replacement_inputs_missing",
            RefundReason::ReplacementDoesNotConflict => "replacement_does_not_conflict",
            RefundReason::NodeRejected => "node_rejected",
        }
    }
}

/// The outbox event type emitted alongside a refund intent. The host's billing
/// hook consumes it; the engine never moves money.
pub const REFUND_INTENT_EVENT_TYPE: &str = "poe.refund-intent";

/// The subject kind the mempool-reconcile alerts are appended under, keyed by the
/// stuck attempt's id so an operator can list and act on the exact attempt.
pub const CHAIN_ATTEMPT_SUBJECT_KIND: &str = "chain_attempt";

/// The operator-facing alert raised when a broadcast attempt has sat in the
/// mempool past the alert threshold. It is a queryable reconcile state, NOT a
/// refund: the attempt's inputs stay reserved and it can still land. The operator
/// resolution is to issue a cancelling replacement (see
/// [`ConfirmHandler::issue_cancelling_replacement`]); only the settlement-deep
/// confirmation of that replacement moves money or restores inputs.
pub const MEMPOOL_STUCK_EVENT: &str = "chain.attempt.stuck";

/// The operator-facing alert escalation raised when a stuck attempt is past the
/// long horizon AND a fresh gateway lookup reports it not found. Under the
/// no-validity-interval model a not-found transaction can still be rebroadcast and
/// land while its inputs are unspent, so this is still alert-only: it never
/// abandons, restores inputs, or refunds.
pub const MEMPOOL_PRESUMED_DEAD_EVENT: &str = "chain.attempt.presumed-dead";

/// Flip a record to `permanent_failure`, insert its single refund intent, and
/// emit the refund-intent outbox event, all in one transaction.
///
/// The insert is `ON CONFLICT (record_id) DO NOTHING`, so single-refund is a
/// by-construction property: no matter how many terminal arms (submit build/
/// gateway/byte-budget, the rollback cap, the mempool give-up) converge on a
/// record, at most one intent and one billing event ever exist. The flip is
/// guarded on the record still being in a non-terminal state so a path that lost
/// a race does not re-emit. Returns `true` when this call performed the flip
/// (it owned the refund), `false` when another path had already terminated it.
pub async fn record_permanent_failure(
    pool: &sqlx::PgPool,
    record_id: Uuid,
    reason: RefundReason,
    detail: &serde_json::Value,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let flipped = record_permanent_failure_in_tx(&mut tx, record_id, reason, detail).await?;
    if flipped {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(flipped)
}

/// Flip a record to `permanent_failure`, insert its single refund intent,
/// auto-credit the network+service publish debit back to the account's balance,
/// and emit the refund-intent + permanent_failure events within a caller-owned
/// transaction.
///
/// Same single-refund-by-construction discipline as [`record_permanent_failure`],
/// but the writes ride the caller's transaction so a terminal flip commits
/// atomically with whatever else the caller is doing. The submit path's
/// deterministic-node-reject arm uses this to abandon the recorded attempt, restore
/// its inputs, AND refund the record in ONE transaction, so a crash can never leave
/// a record abandoned-but-unrefunded (which a redelivery could not recover, since
/// the abandoned attempt's deterministic tx_hash would collide on rebuild).
///
/// # The auto-refund
///
/// The engine credits the publish debit back to `cw_core.balance` itself rather
/// than leaving the operator to compute and apply it: a service that permanently
/// failed must not bill the account. The credit is the exact negated magnitude of
/// the record's `poe_publish` debit (network+service), keyed on the record id, in
/// THIS transaction. It is storage-EXCLUDED on purpose: storage is charged
/// separately at upload against the funding source, and once the ciphertext is
/// durably on Arweave the bytes exist forever, so a publish failure never reverses
/// the storage charge — it reverses only the on-chain publish the account paid for
/// and never received. The auto-refund mirrors the storage `storage_hold_release`
/// pattern exactly (a positive `LedgerEntry` keyed on the failing unit's id, in the
/// same transaction as the state change) so the two failure-refund paths read as
/// one pattern.
///
/// A record with NO publish debit (an operator-direct, free-window, or deduped
/// publish that was never debited) is credited nothing: the lookup finds no row and
/// the refund is skipped cleanly.
///
/// Returns `true` when this call performed the flip (it owned the refund), `false`
/// when the record was already terminal (a converging arm writes nothing twice).
pub async fn record_permanent_failure_in_tx(
    tx: &mut sqlx::PgConnection,
    record_id: Uuid,
    reason: RefundReason,
    detail: &serde_json::Value,
) -> Result<bool> {
    // Flip the record to permanent_failure, guarded on it still being in a
    // non-terminal state. A path that lost the race to another terminal arm
    // (a rollback cap, a concurrent submit failure) updates zero rows and returns
    // false WITHOUT writing the refund intent or the events a second time, so a
    // converging arm never double-emits.
    let flipped = sqlx::query(
        "UPDATE cw_core.poe_record \
         SET status = 'permanent_failure' \
         WHERE id = $1 AND status IN ('submitting', 'submitted', 'confirmed')",
    )
    .bind(record_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;

    if !flipped {
        return Ok(false);
    }

    // The refund intent is the durable single-refund hook: PK on record_id makes
    // a second insert (a crash-replay, or a different terminal arm) a no-op, so
    // at most one refund intent ever exists for a record regardless of how many
    // terminal paths converge.
    sqlx::query(
        "INSERT INTO cw_core.refund_intent (record_id, reason, detail) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (record_id) DO NOTHING",
    )
    .bind(record_id)
    .bind(reason.as_str())
    .bind(detail)
    .execute(&mut *tx)
    .await?;

    // Credit the network+service publish debit back to the account, in this same
    // transaction. Idempotent on (kind, ref): a re-run of the permanent-failure
    // path, or two terminal arms (a reorg cap and a submit failure) converging on
    // one record, nets exactly ONE refund credit. The returned amount is woven into
    // the refund-intent event so an operator can display "refunded X" directly.
    let refunded_micros = refund_publish_debit_in_tx(&mut *tx, record_id).await?;

    // Two events ride the same transaction: the refund-intent the host's billing
    // hook consumes, then the permanent_failure status the SSE consumer sees. Both
    // append inside this transaction so they commit or roll back with the flip. The
    // refund-intent carries the auto-credited amount so a consumer need not
    // reconstruct it from the ledger; the permanent_failure event keeps the caller's
    // raw detail (its projection reads `reason` for the submit-failed wire name).
    let subject_id = record_id.to_string();
    let refund_event_detail = with_refund_amount(detail, refunded_micros);
    crate::events::append_subject_event(
        &mut *tx,
        "poe_record",
        &subject_id,
        REFUND_INTENT_EVENT_TYPE,
        &refund_event_detail,
    )
    .await?;
    crate::events::append_subject_event(
        &mut *tx,
        "poe_record",
        &subject_id,
        "permanent_failure",
        detail,
    )
    .await?;

    Ok(true)
}

/// Credit the record's network+service publish debit back to the owning account's
/// balance, idempotently, within the caller's transaction. Returns the magnitude
/// credited (`0` when the record had no publish debit to reverse).
///
/// The debit and the account both come from the record's `poe_publish` ledger
/// entries: the credit is the exact negated sum of those rows, applied to the same
/// account they debited, so the reversal cancels the charge precisely and can never
/// credit an account the record never debited. Storage is never read here, so the
/// refund is network+service-only by construction — there is no storage row to
/// exclude because storage was charged on a different kind against a funding source.
///
/// A retried permanent-failure path (or a second converging terminal arm) re-runs
/// this and collides on the `(kind, ref)` unique index (and the cross-kind refund
/// unique index), so [`insert_ledger_entry`] is an idempotent no-op the second time
/// and the net effect is exactly one credit.
async fn refund_publish_debit_in_tx(tx: &mut sqlx::PgConnection, record_id: Uuid) -> Result<i64> {
    // Read the publish debit and the account it was charged to off the ledger
    // itself, so the credit matches the debit's account and magnitude exactly. An
    // operator-direct / free-window / deduped publish has no such row.
    let debit: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT account_id, SUM(amount_micros)::bigint \
         FROM cw_core.balance_ledger \
         WHERE kind = $1 AND ref = $2 \
         GROUP BY account_id",
    )
    .bind(PUBLISH_DEBIT_KIND)
    .bind(record_id.to_string())
    .fetch_optional(&mut *tx)
    .await?;

    let Some((account_id, debit_micros)) = debit else {
        // No publish debit for this record: nothing to refund. (Free-window, deduped,
        // or operator-direct publish that was never billed.)
        return Ok(0);
    };

    // The debit is signed-negative; the credit is its positive reversal. A
    // non-negative debit (a malformed or already-zeroed row) leaves nothing to
    // refund.
    let refund_micros = debit_micros.saturating_neg();
    if refund_micros <= 0 {
        return Ok(0);
    }

    let credit = LedgerEntry {
        account_id,
        kind: PUBLISH_REFUND_KIND.to_string(),
        amount_micros: refund_micros,
        r#ref: Some(record_id.to_string()),
        quote_id: None,
        metadata: serde_json::json!({}),
        request_id: None,
    };
    // insert_ledger_entry is idempotent on (kind, ref): a converging or replayed
    // call collides and is a no-op, so the record is credited exactly once.
    insert_ledger_entry(&mut *tx, &credit).await?;
    Ok(refund_micros)
}

/// Merge the auto-credited refund magnitude into a copy of the caller's refund
/// detail, so the `poe.refund-intent` event carries `refund_usd_micros` alongside
/// the caller's existing fields. A non-object detail is replaced by an object
/// carrying the original detail under `detail` plus the amount.
fn with_refund_amount(detail: &serde_json::Value, refund_usd_micros: i64) -> serde_json::Value {
    match detail {
        serde_json::Value::Object(map) => {
            let mut merged = map.clone();
            merged.insert(
                "refund_usd_micros".to_string(),
                serde_json::Value::from(refund_usd_micros),
            );
            serde_json::Value::Object(merged)
        }
        other => serde_json::json!({
            "detail": other,
            "refund_usd_micros": refund_usd_micros,
        }),
    }
}

/// The outcome of reconciling one attempt in an iteration, aggregated into the
/// per-iteration summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// Crossed the threshold; the attempt is `confirmed` and (for a publish/
    /// replacement) its record is flipped and an index job enqueued.
    Confirmed,
    /// On chain below threshold and inside the window; live progress (coordinates
    /// re-pinned, no terminal transition).
    Progress,
    /// On chain at zero confirmations because the tip is briefly behind; skipped.
    TipBehind,
    /// Past the rollback window but still on chain to a fresh lookup; re-pinned, not
    /// rolled back.
    ReorgSuspectCleared,
    /// A reorged-out attempt with budget remaining; superseded by a cancelling
    /// replacement (the original stays reconcilable until provably dead).
    RollbackRetry,
    /// A reorged-out attempt with the rollback budget exhausted; left in the
    /// operator-reconcile state (no automatic refund under the no-validity-interval
    /// model).
    RollbackBudgetExhausted,
    /// A reorg candidate not yet past the safety window; left unchanged.
    RollbackPendingWindow,
    /// A loser abandoned by a settlement-deep conflicting spend: exclusive inputs
    /// restored, outputs tombstoned, refund written only on a never-confirmed
    /// record.
    AbandonedByConflict,
    /// Still in the mempool (no block height yet); left in place for the
    /// operator-reconcile pass. Never abandoned on age or absence.
    Mempool,
    /// A wallet-mutating arm yielded on wallet-lock contention; re-queued with a
    /// bounded backoff and retried on a later pass.
    Yielded,
}

/// The aggregate result of one confirmation iteration, for the summary log and
/// the handler's outcome.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IterationSummary {
    /// Attempts that crossed the threshold this iteration.
    pub confirmed: u64,
    /// Live-progress re-pins.
    pub progress: u64,
    /// Attempts skipped because the tip was briefly behind.
    pub tip_behind: u64,
    /// Reorg suspects that cleared on a fresh lookup.
    pub reorg_suspect_cleared: u64,
    /// Reorged-out attempts superseded by a cancelling replacement.
    pub rollback_retry: u64,
    /// Reorged-out attempts left in the reconcile state at the rollback budget.
    pub rollback_budget_exhausted: u64,
    /// Reorg candidates still inside the safety window.
    pub rollback_pending_window: u64,
    /// Losers abandoned by a settlement-deep conflicting spend.
    pub abandoned_by_conflict: u64,
    /// Attempts still in the mempool (no block height yet).
    pub mempool: u64,
    /// Mempool attempts transitioned to `stuck` and alerted this iteration (past
    /// the alert threshold). Alert only: never refunded, restored, or abandoned.
    pub mempool_stuck: u64,
    /// Stuck attempts whose alert was escalated this iteration (past the long
    /// horizon with a fresh not-found lookup). Still alert only.
    pub mempool_stuck_escalated: u64,
    /// Wallet-mutating arms that yielded on wallet-lock contention and were
    /// re-queued.
    pub yielded: u64,
    /// When every provider in the failover pair was rate-limited this iteration,
    /// the instant the cooldown lifts; `None` otherwise. The handler defers until
    /// this instant rather than failing the iteration.
    pub rate_limited_until: Option<DateTime<Utc>>,
}

/// The confirmation-loop job handler.
///
/// Register it on the runtime against [`CONFIRM_QUEUE`] with [`confirm_policy`]
/// and [`confirm_schedule`]. It owns its pool, the chain gateway it queries in
/// Passes B/C and A-reverify, the network it reconciles, the tuning config, and
/// the wallet config a `confirmed` flip promotes the record's spends against.
pub struct ConfirmHandler<G: crate::chain::gateway::ChainGateway> {
    pool: sqlx::PgPool,
    gateway: G,
    network: String,
    config: ConfirmConfig,
    wallet_config: crate::wallet::config::WalletConfig,
}

impl<G: crate::chain::gateway::ChainGateway> ConfirmHandler<G> {
    /// Build a confirmation handler.
    ///
    /// `wallet_config` supplies the lovelace band a confirmed record's change is
    /// re-evaluated against and is the source of the wallet network: the
    /// `confirmed` flip advances the record's spent inputs to `confirmed_spent`
    /// and promotes its change in the same transaction.
    pub fn new(
        pool: sqlx::PgPool,
        gateway: G,
        network: impl Into<String>,
        config: ConfirmConfig,
        wallet_config: crate::wallet::config::WalletConfig,
    ) -> Self {
        Self {
            pool,
            gateway,
            network: network.into(),
            config,
            wallet_config,
        }
    }

    /// Run one full confirmation iteration (Pass A, A-reverify, B, C) and return
    /// the aggregate summary. Used by the handler and by integration tests that
    /// drive the loop directly.
    ///
    /// The control flow is the locked decomposition: read the materialised tip,
    /// run the zero-HTTP Pass A to flip threshold-crossers and collect reorg
    /// suspects, run the single batched gateway pass (Pass B mempool discovery,
    /// Pass C reorg re-verification, and the settlement-window A-reverify), then run
    /// the alert-only mempool reconcile pass and fold its summary in.
    pub async fn run_iteration(&self) -> Result<IterationSummary> {
        let tip = read_tip(&self.pool, &self.network).await?.ok_or_else(|| {
            crate::Error::Config(format!("no materialised tip for {}", self.network))
        })?;

        let (mut summary, suspects) = self.pass_a(tip).await?;
        let gateway_pass = self.pass_bc(&suspects).await?;
        fold_summary(&mut summary, &gateway_pass.summary);
        summary.rate_limited_until = gateway_pass.rate_limited_until;

        // The alert-only mempool reconcile pass: a stuck transaction becomes an
        // operator-visible reconcile state, never an automatic refund. It moves no
        // money and no inputs; input restore and refund happen only on a
        // settlement-deep conflicting spend (the confirmation of an operator-issued
        // cancelling replacement), reconciled by the confirm/abandon passes above.
        let stuck = self.reconcile_stuck_mempool_attempts().await?;
        summary.mempool_stuck += stuck.stuck;
        summary.mempool_stuck_escalated += stuck.escalated;

        Ok(summary)
    }

    /// Pass A: tip-derived reconciliation over the on-chain attempt ledger with
    /// zero gateway traffic.
    ///
    /// Loads every on-chain attempt (one with a block height), derives
    /// confirmations from `tip`, and classifies each per the locked branches: a
    /// threshold-crosser is confirmed (and its linked siblings abandoned by
    /// settlement-deep conflict), a below-threshold attempt past the rollback window
    /// is a reorg suspect for the batched pass, and a tip briefly behind is skipped.
    /// Returns the partial summary and the suspects to carry into the gateway pass.
    async fn pass_a(&self, tip: u64) -> Result<(IterationSummary, Vec<ReorgSuspect>)> {
        let attempts = attempt::load_onchain_attempts(&self.pool, CONFIRM_BATCH_LIMIT).await?;
        let attempts = self.hydrate_attempts(attempts).await?;

        let mut summary = IterationSummary::default();
        let mut suspects = Vec::new();

        for live in &attempts {
            let Some(block_height) = live.block_height else {
                continue;
            };
            // Derive confirmations from the materialised tip alone: zero gateway
            // traffic. A tip briefly behind the attempt's height yields zero.
            let num_confirmations = tip.saturating_sub(block_height) + 1;
            let tip_advance = tip.saturating_sub(block_height);

            if tip < block_height {
                // The tip is behind the attempt's own height (clock skew, or a
                // concurrent write advanced it past the last tip read). The next
                // iteration's tip read catches up; nothing changes now.
                summary.tip_behind += 1;
            } else if num_confirmations >= self.config.confirmation_threshold {
                // Crossed the threshold: confirm the attempt, promote its wallet
                // state, flip its record, and abandon any settlement-deep-conflicting
                // siblings, all in one transaction under the wallet lock.
                let outcome = self
                    .confirm_attempt(live, block_height, live.block_time, tip)
                    .await?;
                tally(&mut summary, outcome);
            } else if tip_advance >= self.config.rollback_window_blocks {
                // On chain below threshold, yet the tip has advanced past the
                // rollback window: the arithmetic half of the two-source gate is met.
                // Carry it into the batched pass for a fresh gateway lookup before any
                // rollback can be decided.
                suspects.push(ReorgSuspect {
                    attempt_id: live.attempt_id,
                    tx_hash: live.tx_hash,
                    prior_block_height: block_height,
                });
            } else {
                // On chain, below threshold, inside the window: ordinary live
                // progress. No write; progress is implicit in the derived count.
                summary.progress += 1;
            }
        }

        Ok((summary, suspects))
    }

    /// Pass B + C + A-reverify: one batched gateway call reconciles mempool
    /// discovery, reorg suspects, and the settlement-window re-verification over the
    /// attempt ledger.
    ///
    /// Loads the mempool-only attempts (no block height) and the settlement-window
    /// confirmed attempts, joins the carried suspects, issues one
    /// [`crate::chain::gateway::ChainGateway::get_tx_confirmations`] call, and
    /// reconciles each attempt against its fresh observation. A rate-limit storm
    /// (every attempt 429) short-circuits to a rate-limited result the handler turns
    /// into a defer.
    async fn pass_bc(&self, suspects: &[ReorgSuspect]) -> Result<GatewayPassResult> {
        let mut summary = IterationSummary::default();

        // The live attempts to query in the single batched call.
        let attempts = self.gateway_pass_attempts(suspects).await?;
        if attempts.is_empty() {
            // Nothing to observe: no gateway call at all this iteration.
            return Ok(GatewayPassResult {
                summary,
                rate_limited_until: None,
            });
        }
        let tip = read_tip(&self.pool, &self.network).await?.ok_or_else(|| {
            crate::Error::Config(format!("no materialised tip for {}", self.network))
        })?;

        let observations = match self.batched_observe(&attempts).await {
            Ok(observations) => observations,
            // A rate-limit storm (every provider returned 429) parks the loop: the
            // handler defers until the cooldown lifts, which does NOT burn the single
            // attempt the queue allows. No state changes this iteration.
            Err(err) => match rate_limit_storm_until(&err) {
                Some(until) => {
                    return Ok(GatewayPassResult {
                        summary,
                        rate_limited_until: Some(until),
                    });
                }
                None => return Err(err),
            },
        };

        for live in &attempts {
            let observed = observations
                .get(&live.tx_hash)
                .copied()
                .unwrap_or_else(crate::chain::gateway::TxConfirmation::not_on_chain);
            let outcome = self.reconcile_attempt(live, observed, tip).await?;
            tally(&mut summary, outcome);
        }
        Ok(GatewayPassResult {
            summary,
            rate_limited_until: None,
        })
    }

    /// Load the attempts the batched gateway call should observe: the mempool-only
    /// attempts (no block height), the settlement-window confirmed attempts
    /// (A-reverify), and the carried reorg suspects.
    ///
    /// An attempt may qualify under more than one source (a suspect is also an
    /// on-chain row), so the set is keyed by attempt id to issue each hash once in
    /// the single batched call.
    async fn gateway_pass_attempts(&self, suspects: &[ReorgSuspect]) -> Result<Vec<LiveAttempt>> {
        use std::collections::HashMap;

        let mut by_id: HashMap<Uuid, LiveAttempt> = HashMap::new();

        // Pass B: mempool-only attempts with no block height. One batched lookup
        // discovers which have landed.
        for live in self.load_mempool_attempts().await? {
            by_id.insert(live.attempt_id, live);
        }

        // A-reverify + Pass C share the on-chain set: every confirmed attempt still
        // inside the settlement window rides the same batched call so a
        // post-confirmation reorg is caught, and any suspect Pass A collected is
        // re-verified against a fresh lookup. Both come from the on-chain attempt
        // enumeration; the suspect ids mark which entries reconcile as a suspect.
        let suspect_ids: Vec<Uuid> = suspects.iter().map(|s| s.attempt_id).collect();
        for live in self.load_onchain_attempts_for_reverify().await? {
            by_id.entry(live.attempt_id).or_insert(live);
        }

        // Every suspect Pass A collected is re-verified by a fresh lookup, regardless
        // of the settlement window: a below-threshold attempt past the rollback window
        // must be re-checked even if it has slipped out of the reverify window.
        let suspect_attempts = attempt::load_attempts_by_ids(&self.pool, &suspect_ids).await?;
        for live in self.hydrate_attempts(suspect_attempts).await? {
            by_id
                .entry(live.attempt_id)
                .and_modify(|existing| existing.is_reorg_suspect = true)
                .or_insert(LiveAttempt {
                    is_reorg_suspect: true,
                    ..live
                });
        }

        let mut attempts: Vec<LiveAttempt> = by_id.into_values().collect();
        // Deterministic order so the batched call and the reconcile loop visit
        // attempts in a stable sequence.
        attempts.sort_by_key(|a| a.attempt_id);
        Ok(attempts)
    }

    /// Load mempool-only attempts (no block height) for the batched discovery pass:
    /// the reconcile/watch set, which never abandons on age or absence here.
    async fn load_mempool_attempts(&self) -> Result<Vec<LiveAttempt>> {
        let attempts = attempt::load_reconcile_attempts(&self.pool, CONFIRM_BATCH_LIMIT).await?;
        self.hydrate_attempts(attempts).await
    }

    /// Load the on-chain attempts (those with a block height) the settlement-window
    /// re-verification and the suspect re-check both query, keyed for the batched
    /// gateway call.
    async fn load_onchain_attempts_for_reverify(&self) -> Result<Vec<LiveAttempt>> {
        // Only attempts still inside the settlement-reverify window need a fresh
        // lookup; a deeply-settled attempt is past any reorg and is never re-queried.
        let attempts = attempt::load_onchain_attempts(&self.pool, CONFIRM_BATCH_LIMIT).await?;
        let tip = read_tip(&self.pool, &self.network).await?.unwrap_or(0);
        let window = self.config.settlement_reverify_blocks;
        let inside: Vec<attempt::ChainAttempt> = attempts
            .into_iter()
            .filter(|a| match a.block_height {
                Some(h) => tip.saturating_sub(h) < window,
                None => false,
            })
            .collect();
        self.hydrate_attempts(inside).await
    }

    /// Resolve each attempt's record bytes (for the publish/replacement index
    /// enqueue), turning the row API's [`attempt::ChainAttempt`] into the confirm
    /// loop's [`LiveAttempt`].
    async fn hydrate_attempts(
        &self,
        attempts: Vec<attempt::ChainAttempt>,
    ) -> Result<Vec<LiveAttempt>> {
        let mut out = Vec::with_capacity(attempts.len());
        for a in attempts {
            out.push(self.hydrate_attempt(a).await?);
        }
        Ok(out)
    }

    /// Resolve one attempt into a [`LiveAttempt`], loading its record bytes when it
    /// serves a record (a split serves only its wallet and carries none).
    async fn hydrate_attempt(&self, a: attempt::ChainAttempt) -> Result<LiveAttempt> {
        let record_bytes = match a.record_id {
            Some(record_id) => {
                sqlx::query_scalar("SELECT record_bytes FROM cw_core.poe_record WHERE id = $1")
                    .bind(record_id)
                    .fetch_optional(&self.pool)
                    .await?
            }
            None => None,
        };
        Ok(LiveAttempt {
            attempt_id: a.id,
            kind: a.kind,
            record_id: a.record_id,
            wallet_id: a.wallet_id,
            tx_hash: a.tx_hash,
            block_height: a.block_height,
            block_time: a.block_time,
            first_seen_on_chain_at: a.first_seen_on_chain_at,
            status: a.status,
            spent_inputs: a.spent_inputs,
            record_bytes,
            is_reorg_suspect: false,
        })
    }

    /// Issue the single batched confirmation lookup for a pass's attempts.
    async fn batched_observe(
        &self,
        attempts: &[LiveAttempt],
    ) -> Result<crate::chain::gateway::TxConfirmationMap> {
        let hashes: Vec<[u8; 32]> = attempts.iter().map(|a| a.tx_hash).collect();
        self.gateway.get_tx_confirmations(&hashes).await
    }

    /// Reconcile one attempt against a fresh gateway observation, running the
    /// reorg decision tree when the attempt was on chain and is now gone.
    ///
    /// The TWO-SOURCE gate is enforced here: a rollback runs only when the attempt
    /// was previously on chain (`first_seen_on_chain_at` set) AND the fresh
    /// observation reports it gone AND the tip is past the safety window. An attempt
    /// never abandoned on age or absence: a gone-but-no-conflicting-spend attempt is
    /// left in the reconcile state for the operator pass.
    async fn reconcile_attempt(
        &self,
        live: &LiveAttempt,
        observed: crate::chain::gateway::TxConfirmation,
        tip: u64,
    ) -> Result<ReconcileOutcome> {
        let was_on_chain = live.first_seen_on_chain_at.is_some();
        let gone = observed.num_confirmations == 0 && observed.block_height.is_none();

        if gone {
            // Gone from a fresh lookup. If it was never on chain it is still in the
            // mempool to our view (never abandoned on absence here). If it WAS on
            // chain this is the second source of the reorg gate.
            if !was_on_chain {
                return Ok(ReconcileOutcome::Mempool);
            }
            return self.decide_rollback(live, tip).await;
        }

        // On chain to the fresh lookup requires REAL, COMPLETE coordinates: both a
        // block height AND a block time. An observation that reports a confirmation
        // count but is missing either coordinate is incomplete provider data
        // (cross-endpoint replica lag, a truncated response, a rollback race mid-poll),
        // never an on-chain sighting. Confirming or re-pinning on it would settle the
        // record at a fabricated coordinate (a height 0, or a synthesized now() block
        // time), so an incomplete observation is treated as not-yet-observed: a
        // not-yet-on-chain attempt stays in the mempool watch set, and an
        // already-confirmed attempt is left untouched for the next lookup.
        let (Some(block_height), Some(block_time)) = (observed.block_height, observed.block_time)
        else {
            if was_on_chain {
                return Ok(ReconcileOutcome::Progress);
            }
            return Ok(ReconcileOutcome::Mempool);
        };
        // Use the observed coordinates (a reorg can re-include the transaction at a
        // new height).
        if observed.num_confirmations >= self.config.confirmation_threshold {
            self.confirm_attempt(live, block_height, Some(block_time), tip)
                .await
        } else if live.is_reorg_suspect {
            // A suspect the fresh lookup still sees on chain: the two-source gate
            // disagreed (lag, not a reorg), so re-pin rather than roll back.
            self.repin_attempt(live, block_height, Some(block_time))
                .await?;
            Ok(ReconcileOutcome::ReorgSuspectCleared)
        } else {
            // A mempool attempt that just landed (or an A-reverify attempt still
            // present) below threshold: re-pin the freshly observed coordinates so
            // Pass A can settle it next iteration, and count it as live progress.
            self.repin_attempt(live, block_height, Some(block_time))
                .await?;
            Ok(ReconcileOutcome::Progress)
        }
    }

    /// The reorg decision for an attempt the two-source gate has confirmed gone:
    /// not past the safety window yet -> pending; past it with budget remaining ->
    /// supersede with a cancelling replacement (the original stays reconcilable);
    /// past it with the budget exhausted -> leave it in the reconcile state (no
    /// automatic refund under the no-validity-interval model).
    async fn decide_rollback(&self, live: &LiveAttempt, tip: u64) -> Result<ReconcileOutcome> {
        // A confirmed attempt the settlement-window reverify pass found gone MAY be a
        // post-confirmation reorg: the tx that had settled is no longer on chain.
        // `settlement_depth == confirmation_threshold` and the reverify window
        // deliberately re-checks confirmed records, so `Confirmed` is NOT terminal
        // inside that window. But a brief absence a few blocks deep is a transient
        // gateway/reorg hiccup that may re-include, NOT a genuine deep reorg, so the
        // confirmation is reversed ONLY under the same two proofs that drive any
        // rollback: a settlement-deep conflicting spend (a true double-spend reorg), or
        // the tip past the rollback window (the arithmetic half of the two-source
        // gate). Without one of those, the confirmed attempt is left untouched and the
        // next pass re-observes it (it typically re-includes). When a proof holds, the
        // confirmation is reversed FIRST — un-confirm the attempt back to an active
        // broadcaster (coordinates cleared) and revert its record to `submitted` — so
        // the same rollback machinery that drives a reorged-out broadcaster carries it
        // forward. Without this reversal the abandon guard (`status NOT IN
        // ('confirmed',...)`) and the supersede gate (`is_active_broadcaster`) both
        // hard-exclude `confirmed`, so a confirmed-then-reorged record would reach zero
        // rollback action and stay `confirmed` pointing at a vanished tx.
        if live.status == attempt::AttemptStatus::Confirmed {
            let past_window = match live.block_height {
                Some(height) => tip.saturating_sub(height) >= self.config.rollback_window_blocks,
                None => true,
            };
            let conflict = self.has_settlement_deep_conflict(live, tip).await?;
            if !past_window && !conflict {
                // A transient absence inside the rollback window with no death proof:
                // leave it confirmed. The two-source gate has not been met.
                return Ok(ReconcileOutcome::RollbackPendingWindow);
            }
            if !self.revert_confirmed_reorged_out(live).await? {
                // A racing pass already reverted (or re-confirmed) it; nothing to do
                // this pass. The next pass re-observes the reverted broadcaster.
                return Ok(ReconcileOutcome::RollbackPendingWindow);
            }
        }

        // The single money-moving proof: a confirmed transaction has spent one of
        // this attempt's inputs AND that conflicting spend has itself reached the
        // settlement depth. Only then is the attempt provably dead and its inputs
        // restored / its record refunded. This is gated on the CONFLICTING spend's
        // own settlement depth, not on this attempt's window, so it is checked first:
        // a reorged-out original (whose own coordinates are cleared) is still
        // abandoned the instant a settlement-deep conflicting spend exists. A
        // gone-but-no-settlement-deep-conflict attempt is NEVER abandoned, restored,
        // or refunded: a shallow conflicting spend can be reorged out and the
        // original re-land, and an absent transaction can be rebroadcast and land
        // while its inputs are unspent.
        if let Some(outcome) = self
            .try_abandon_on_settlement_deep_conflict(live, tip)
            .await?
        {
            return Ok(outcome);
        }

        // No settlement-deep conflict. Absence alone is not a death proof, so the
        // only automatic action is the supersede control (a cancelling replacement),
        // and only once the tip is past the safety window so a transient absence (a
        // gateway hiccup, a brief reorg that may re-include) is not mistaken for a
        // reorg.
        let past_window = match live.block_height {
            Some(height) => tip.saturating_sub(height) >= self.config.rollback_window_blocks,
            None => true,
        };
        if !past_window {
            // Inside the safety window: a transient absence is not yet a rollback.
            return Ok(ReconcileOutcome::RollbackPendingWindow);
        }

        // The rollback retry budget is read from the record's prior rollbacks.
        let Some(record_id) = live.record_id else {
            // A split has no record to roll a replacement forward for; a reorged-out
            // split is reconciled only by a settlement-deep conflict (handled above).
            return Ok(ReconcileOutcome::RollbackBudgetExhausted);
        };
        let retry_count = self.record_rollback_retry_count(record_id).await?;
        if retry_count + 1 > self.config.max_rollback_retries {
            // Budget exhausted: the reorged-out attempt stays in the reconcile state.
            // Under the no-validity-interval model there is no automatic refund here;
            // input restore and refund move only on a settlement-deep conflicting
            // spend (handled above), which a confirmed cancelling replacement supplies.
            Ok(ReconcileOutcome::RollbackBudgetExhausted)
        } else {
            self.rollback_retry(live, record_id, retry_count).await
        }
    }

    /// Whether a settlement-deep conflicting spend of one of this attempt's inputs
    /// exists, without mutating anything.
    ///
    /// A read-only probe sharing the same query as the abandon path, used to decide
    /// whether a reorged-out `confirmed` attempt has a genuine death proof (so its
    /// confirmation may be reversed) versus a transient absence (leave it confirmed).
    async fn has_settlement_deep_conflict(&self, live: &LiveAttempt, tip: u64) -> Result<bool> {
        let depth = self.config.settlement_depth();
        for input in live.spent_inputs.iter() {
            let input_ref = input.utxo_ref()?;
            if attempt::settlement_deep_conflicting_spend(
                &self.pool,
                live.wallet_id,
                &live.tx_hash,
                &input_ref,
                tip,
                depth,
            )
            .await?
            .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Abandon a reorged-out attempt if (and only if) a settlement-deep conflicting
    /// spend of one of its inputs exists, in ONE transaction under the wallet lock.
    ///
    /// This is the foreign-conflict death path: a different confirmed transaction
    /// (a cancelling replacement that already confirmed, or a foreign transaction in
    /// the new chain) has spent one of this attempt's inputs and that spend has
    /// itself reached the settlement depth, so this attempt can never land. When
    /// found, the attempt is abandoned with its exclusive inputs restored, its
    /// outputs tombstoned, its indexed record deleted, and a refund written only on
    /// a never-confirmed record. Returns `Some(outcome)` when a conflict abandoned
    /// the attempt (or the arm yielded on wallet-lock contention), or `None` when no
    /// settlement-deep conflict exists (so the caller falls through to the supersede
    /// control action — never an automatic refund).
    async fn try_abandon_on_settlement_deep_conflict(
        &self,
        live: &LiveAttempt,
        tip: u64,
    ) -> Result<Option<ReconcileOutcome>> {
        let depth = self.config.settlement_depth();
        let inputs: Vec<UtxoRef> = live
            .spent_inputs
            .iter()
            .map(AttemptInput::utxo_ref)
            .collect::<Result<_>>()?;

        // Find a settlement-deep conflicting spend and the exact winner input it
        // spent, so the abandon restores the loser's EXCLUSIVE inputs only.
        let mut conflict: Option<([u8; 32], u64, Vec<UtxoRef>)> = None;
        for input in &inputs {
            if let Some((winner_tx, winner_depth)) = attempt::settlement_deep_conflicting_spend(
                &self.pool,
                live.wallet_id,
                &live.tx_hash,
                input,
                tip,
                depth,
            )
            .await?
            {
                // Load the winner's full spent-input set so a shared input the winner
                // also spent is not restored to the loser.
                let winner_inputs =
                    match attempt::load_attempt_by_tx_hash(&self.pool, &winner_tx).await? {
                        Some(w) => w
                            .spent_inputs
                            .iter()
                            .map(AttemptInput::utxo_ref)
                            .collect::<Result<Vec<_>>>()?,
                        None => vec![*input],
                    };
                conflict = Some((winner_tx, winner_depth, winner_inputs));
                break;
            }
        }

        let Some((winner_tx, winner_depth, winner_inputs)) = conflict else {
            return Ok(None);
        };

        // Abandon under the wallet lock (it mutates wallet_utxo), yielding rather
        // than blocking on a live submit.
        let Some(lock) = self.acquire_wallet_for_mutation(live).await? else {
            return Ok(Some(ReconcileOutcome::Yielded));
        };

        let attempt = match attempt::load_attempt(&self.pool, live.attempt_id).await? {
            Some(a) => a,
            None => {
                let _ = lock.release().await;
                return Ok(Some(ReconcileOutcome::AbandonedByConflict));
            }
        };

        let mut tx = self.pool.begin().await?;
        // A reorged-out attempt whose record never landed is refunded; a record that
        // is already confirmed (the winner carried it) is confirmed-success and is
        // never refunded. The flag is "record is confirmed-success" so the refund
        // fires only on a non-terminal record.
        let record_confirmed_success = match attempt.record_id {
            Some(record_id) => self.record_is_confirmed(record_id).await?,
            None => false,
        };
        self.abandon_attempt_in_tx(
            &mut tx,
            &attempt,
            &inputs,
            &winner_inputs,
            &winner_tx,
            winner_depth,
            live.block_height.unwrap_or(0),
            record_confirmed_success,
        )
        .await?;
        tx.commit().await?;
        let _ = lock.release().await;
        Ok(Some(ReconcileOutcome::AbandonedByConflict))
    }

    /// Whether a record is already in the `confirmed` terminal-success state.
    async fn record_is_confirmed(&self, record_id: Uuid) -> Result<bool> {
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM cw_core.poe_record WHERE id = $1")
                .bind(record_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(status.as_deref() == Some("confirmed"))
    }

    /// Reverse a post-confirmation reorg: un-confirm a `confirmed` attempt the
    /// settlement-window reverify pass found gone, in ONE transaction under the
    /// wallet advisory lock.
    ///
    /// The attempt is moved back to `broadcast` with its on-chain coordinates cleared
    /// (it is no longer on a block, but it DID reach the wire, so `broadcast` not
    /// `recorded`, and `first_seen_on_chain_at` is preserved so the two-source reorg
    /// gate still treats it as having-been-on-chain). Its wallet inputs stay
    /// `confirmed_spent` and are deliberately NOT demoted: `confirmed_spent` is a
    /// reserved (non-selectable) state, so the inputs remain held by the now-active
    /// broadcaster exactly as a never-confirmed reorged-out original's `pending_spent`
    /// inputs are, and both downstream consumers already accept `confirmed_spent` —
    /// the abandon's input restore and a replacement's input re-lease both flip from
    /// `pending_spent` OR `confirmed_spent`. Leaving them put avoids reintroducing a
    /// spendable window. The record is reverted from `confirmed` to `submitted` with
    /// its projected coordinates cleared so Pass A does not re-settle it on the stale
    /// height; the `confirmed` index row is left in place (the original can still
    /// re-land) and is deleted only on the proof-gated abandon. A `reorg_reverted`
    /// event records the transition.
    ///
    /// Guarded to a `confirmed` attempt still pointed-to by its record AND still at the
    /// EXACT coordinates the reversal observed gone (a CAS on `status`, `tx_hash`, and
    /// `block_height`). This is the critical safety fence for a stale observation: a
    /// concurrent pass may have already re-confirmed the same transaction re-included
    /// at a NEW height before this (older) gone-observation fires. Binding the revert
    /// to the height it actually saw gone makes a re-confirmation at a different height
    /// match zero rows, so a fresh real coordinate is never un-done by a stale reorg
    /// observation. A racing pass that already reverted or re-confirmed it likewise
    /// matches zero rows and the caller takes the no-op path. Returns whether the
    /// reversal was applied.
    async fn revert_confirmed_reorged_out(&self, live: &LiveAttempt) -> Result<bool> {
        // The exact height the reversal observed confirmed-then-gone. A confirmed
        // attempt always carries one (it is loaded only with a block height); a missing
        // one is a corrupt row the reversal must not act on.
        let Some(observed_height) = live.block_height else {
            return Ok(false);
        };
        let observed_height = i64::try_from(observed_height)
            .map_err(|_| crate::Error::Config("block height overflow".into()))?;

        let Some(lock) = self.acquire_wallet_for_mutation(live).await? else {
            // Yielded on wallet-lock contention: a later pass retries the reversal.
            return Ok(false);
        };

        let mut tx = self.pool.begin().await?;

        // Un-confirm the attempt: back to an active broadcaster with cleared
        // coordinates. Guarded to `confirmed` at the EXACT observed tx_hash and height
        // so a re-confirmation at a different height (a re-inclusion a concurrent pass
        // already pinned) is never reverted by this stale gone-observation.
        let reverted = sqlx::query(
            "UPDATE cw_core.chain_attempt \
             SET status = 'broadcast', block_height = NULL, block_time = NULL, \
                 next_attempt_after = NULL, updated_at = now() \
             WHERE id = $1 AND status = 'confirmed' AND tx_hash = $2 AND block_height = $3",
        )
        .bind(live.attempt_id)
        .bind(live.tx_hash.as_slice())
        .bind(observed_height)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if !reverted {
            tx.rollback().await?;
            let _ = lock.release().await;
            return Ok(false);
        }

        // Revert the record from `confirmed` to `submitted` with cleared projected
        // coordinates, guarded so it still points at this attempt (so a record that
        // changed hands is not touched). The cleared coordinates keep Pass A from
        // re-settling on the stale height; the index row is left for the proof-gated
        // abandon to delete (the original can still re-land before any replacement).
        if let Some(record_id) = live.record_id {
            sqlx::query(
                "UPDATE cw_core.poe_record \
                 SET status = 'submitted', block_height = NULL, block_time = NULL \
                 WHERE id = $1 AND status = 'confirmed' AND current_attempt_id = $2",
            )
            .bind(record_id)
            .bind(live.attempt_id)
            .execute(&mut *tx)
            .await?;

            let detail = serde_json::json!({
                "reason": "reorg_reverted",
                "tx_hash": hex::encode(live.tx_hash),
                "prior_block_height": live.block_height,
            });
            crate::events::append_subject_event(
                &mut *tx,
                "poe_record",
                &record_id.to_string(),
                "reorg_reverted",
                &detail,
            )
            .await?;
        }

        tx.commit().await?;
        let _ = lock.release().await;
        Ok(true)
    }

    /// Confirm an attempt at/above the settlement threshold, in ONE transaction
    /// under the wallet advisory lock (lock order: wallet lock -> chain_attempt ->
    /// poe_record -> wallet_utxo).
    ///
    /// Marks the attempt `confirmed`, promotes its spent inputs to `confirmed_spent`
    /// and its produced outputs to spendable/canonical, and (for a publish or
    /// replacement) flips its record to `confirmed`, copies the projection onto the
    /// record, appends the `confirmed` event, and enqueues the single-writer index
    /// job. When the confirmed attempt has linked siblings (an original/replacement
    /// pair), each sibling that shares an input with the winner is abandoned by a
    /// settlement-deep conflict in the SAME transaction: its exclusive inputs are
    /// restored, its outputs tombstoned, and NO refund is written (the record is
    /// confirmed-success). Because the winner is only confirmed at/above the
    /// settlement threshold, the conflicting spend that terminalises a loser is
    /// itself settlement-deep, so the abandon cannot be un-proven by a shallow reorg.
    async fn confirm_attempt(
        &self,
        live: &LiveAttempt,
        block_height: u64,
        block_time: Option<DateTime<Utc>>,
        tip: u64,
    ) -> Result<ReconcileOutcome> {
        let block_time = block_time.unwrap_or_else(Utc::now);

        // A deeper re-confirmation of an already-confirmed attempt at the SAME height
        // is a pure no-op that touches no wallet rows (the settlement-window
        // re-verification re-observes a confirmed attempt every iteration). Short out
        // BEFORE acquiring the wallet lock, so a steady-state re-observation never
        // takes the lock and never yields/escalates against a live submit on the same
        // wallet (the lock-order rule: a confirm arm that touches no wallet rows needs
        // no wallet lock and is never yielded).
        if live.status == attempt::AttemptStatus::Confirmed
            && live.block_height == Some(block_height)
        {
            return Ok(ReconcileOutcome::Confirmed);
        }

        // Acquire the wallet advisory lock yield-not-block: confirm mutates
        // wallet_utxo, so it must serialize with a live submit on the same wallet and
        // must never block on the lock submit holds. On contention it yields and the
        // attempt is re-queued for the next pass with a bounded backoff.
        let Some(lock) = self.acquire_wallet_for_mutation(live).await? else {
            return Ok(ReconcileOutcome::Yielded);
        };

        let mut tx = self.pool.begin().await?;

        let flipped =
            attempt::mark_confirmed_in_tx(&mut tx, live.attempt_id, block_height, block_time)
                .await?;
        if !flipped {
            // Already confirmed at this same height (a deeper confirmation count over
            // an already-settled attempt): a true no-op. Nothing to commit.
            tx.rollback().await?;
            let _ = lock.release().await;
            return Ok(ReconcileOutcome::Confirmed);
        }

        // For a publish/replacement attempt, flip the record and enqueue its index
        // job; a split has no record.
        if let Some(record_id) = live.record_id {
            let record_flipped = self
                .flip_record_confirmed(&mut tx, live, record_id, block_height, block_time)
                .await?;
            if record_flipped {
                self.enqueue_index_job(&mut tx, live, block_height, block_time)
                    .await?;
            }
        }

        // Promote the winner's wallet state: its spent inputs become confirmed_spent
        // and its produced change/minted outputs become spendable and canonical.
        let input_refs: Vec<UtxoRef> = live
            .spent_inputs
            .iter()
            .map(AttemptInput::utxo_ref)
            .collect::<Result<_>>()?;
        if !input_refs.is_empty() {
            let confirmed = [crate::wallet::utxo::ConfirmedSpend {
                spend_tx_hash: live.tx_hash,
                inputs: input_refs.clone(),
            }];
            crate::wallet::utxo::apply_confirmed_in_tx(
                &mut tx,
                live.wallet_id,
                &confirmed,
                &self.wallet_config,
            )
            .await?;
        }

        // Terminalise any linked siblings (the original/replacement pair) the winner
        // conflicts with, in this same transaction. The winner is settlement-deep
        // (confirmed at/above the threshold), so the conflict is settlement-deep at
        // the instant the loser is abandoned.
        if let Some(record_id) = live.record_id {
            self.abandon_conflicting_siblings(
                &mut tx,
                live,
                record_id,
                &input_refs,
                block_height,
                tip,
            )
            .await?;
        }

        tx.commit().await?;
        let _ = lock.release().await;
        Ok(ReconcileOutcome::Confirmed)
    }

    /// Flip a publish/replacement attempt's record to `confirmed`, copying the
    /// attempt's coordinates/tx_hash/fee/spent_inputs projection onto the record and
    /// appending the `confirmed` event, within the caller's transaction.
    ///
    /// Guarded so it fires only on a genuine transition: `submitted` -> `confirmed`,
    /// or a `confirmed` record at a DIFFERENT height (a reorg moved the transaction,
    /// which needs a re-index). A same-height re-confirmation matches zero rows (a
    /// true no-op), and a terminal record is never resurrected. Returns whether the
    /// record transitioned (the index enqueue hangs off this being true).
    async fn flip_record_confirmed(
        &self,
        tx: &mut sqlx::PgConnection,
        live: &LiveAttempt,
        record_id: Uuid,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<bool> {
        let height = i64::try_from(block_height)
            .map_err(|_| crate::Error::Config("block height overflow".into()))?;
        let attempt = attempt::load_attempt_in_tx(tx, &live.tx_hash).await?;
        let (fee, spent_json) =
            match &attempt {
                Some(a) => (
                    Some(i64::try_from(a.fee_lovelace).map_err(|_| {
                        crate::Error::Config("attempt fee does not fit in i64".into())
                    })?),
                    serde_json::to_value(&a.spent_inputs)?,
                ),
                None => (None, serde_json::to_value(&live.spent_inputs)?),
            };

        let flipped = sqlx::query(
            "UPDATE cw_core.poe_record \
             SET status = 'confirmed', tx_hash = $2, block_height = $3, block_time = $4, \
                 actual_fee_lovelace = COALESCE($5, actual_fee_lovelace), \
                 spent_inputs = $6, \
                 first_seen_on_chain_at = COALESCE(first_seen_on_chain_at, now()) \
             WHERE id = $1 \
               AND (status = 'submitted' \
                    OR (status = 'confirmed' AND block_height IS DISTINCT FROM $3))",
        )
        .bind(record_id)
        .bind(live.tx_hash.as_slice())
        .bind(height)
        .bind(block_time)
        .bind(fee)
        .bind(spent_json)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;

        if flipped {
            let detail = serde_json::json!({
                "block_height": block_height,
                "tx_hash": hex::encode(live.tx_hash),
            });
            crate::events::append_subject_event(
                &mut *tx,
                "poe_record",
                &record_id.to_string(),
                "confirmed",
                &detail,
            )
            .await?;
        }
        Ok(flipped)
    }

    /// Enqueue the single-writer index job for a confirmed attempt's transaction,
    /// carrying the record bytes inline, within the caller's transaction.
    async fn enqueue_index_job(
        &self,
        tx: &mut sqlx::PgConnection,
        live: &LiveAttempt,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<()> {
        let Some(record_bytes) = &live.record_bytes else {
            return Ok(());
        };
        let job = crate::chain::records::IndexTxJob {
            tx_hash: hex::encode(live.tx_hash),
            block_height,
            block_time,
            metadata: crate::chain::records::MetadataSource::Inline {
                metadata_cbor: record_bytes.clone(),
            },
        };
        crate::chain::records::enqueue_index_tx(&mut *tx, &job).await?;
        Ok(())
    }

    /// Abandon every linked sibling of a freshly-confirmed winner that shares an
    /// input with it, by settlement-deep conflict, within the caller's transaction.
    ///
    /// Walks the record's non-terminal attempts (the replacement watch set), and for
    /// each one OTHER than the winner whose `spent_inputs` intersect the winner's:
    /// mark it `abandoned` with the conflict evidence, restore its EXCLUSIVE inputs
    /// (every input the winner did NOT spend; the shared input stays confirmed_spent
    /// by the winner), tombstone its produced outputs, and delete its indexed
    /// chain_records row if any. NO refund is written: the record is confirmed (the
    /// PoE landed). Because the winner is confirmed at/above the settlement
    /// threshold, the conflict is settlement-deep at the instant each loser is
    /// abandoned.
    async fn abandon_conflicting_siblings(
        &self,
        tx: &mut sqlx::PgConnection,
        winner: &LiveAttempt,
        record_id: Uuid,
        winner_inputs: &[UtxoRef],
        winner_block_height: u64,
        _tip: u64,
    ) -> Result<()> {
        let siblings = attempt::load_record_attempts_in_tx(tx, record_id).await?;
        let depth = self.config.settlement_depth();
        for sibling in &siblings {
            if sibling.tx_hash == winner.tx_hash {
                continue;
            }
            let sibling_inputs: Vec<UtxoRef> = sibling
                .spent_inputs
                .iter()
                .map(AttemptInput::utxo_ref)
                .collect::<Result<_>>()?;
            let shares_input = sibling_inputs.iter().any(|s| winner_inputs.contains(s));
            if !shares_input {
                // No shared input: the winner does not conflict with this sibling, so
                // it is not proven dead by the winner. Leave it in the watch set.
                continue;
            }
            // The winner is settlement-deep, so the conflict that kills this sibling
            // is settlement-deep. Record the evidence (winner tx + its depth).
            let winner_depth = depth;
            self.abandon_attempt_in_tx(
                tx,
                sibling,
                &sibling_inputs,
                winner_inputs,
                &winner.tx_hash,
                winner_depth,
                winner_block_height,
                /* record_is_confirmed_success */ true,
            )
            .await?;
        }
        Ok(())
    }

    /// The shared abandon arm: mark an attempt `abandoned` by settlement-deep
    /// conflict, restore its exclusive inputs, tombstone its outputs, delete its
    /// indexed chain_records row, and (only on a never-confirmed record) write the
    /// single refund, within the caller's transaction.
    ///
    /// `winner_inputs` are the inputs the confirmed conflicting transaction spent;
    /// any input of the abandoned attempt that the winner also spent stays
    /// `confirmed_spent` by the winner and is NOT restored. When
    /// `record_is_confirmed_success` is true (the winner carried the record forward),
    /// no refund is written; otherwise, if the record is still non-terminal, it is
    /// flipped to `permanent_failure` with its single refund in this same
    /// transaction.
    #[allow(clippy::too_many_arguments)]
    async fn abandon_attempt_in_tx(
        &self,
        tx: &mut sqlx::PgConnection,
        attempt: &attempt::ChainAttempt,
        attempt_inputs: &[UtxoRef],
        winner_inputs: &[UtxoRef],
        winner_tx_hash: &[u8; 32],
        winner_depth: u64,
        winner_block_height: u64,
        record_is_confirmed_success: bool,
    ) -> Result<()> {
        let flipped = attempt::mark_abandoned_in_tx(tx, attempt.id).await?;
        if !flipped {
            // Already terminal: a converging path abandoned or confirmed it. Skip.
            return Ok(());
        }

        // The settlement-deep proof-of-death evidence: the confirmed conflicting
        // transaction hash and the depth it had reached when the abandon fired (which
        // is at/above the settlement threshold for this arm to run).
        let evidence = serde_json::json!({
            "reason": "pod_conflict",
            "conflicting_tx_hash": hex::encode(winner_tx_hash),
            "conflicting_depth": winner_depth,
            "conflicting_block_height": winner_block_height,
        });
        crate::events::append_subject_event(
            &mut *tx,
            "chain_attempt",
            &attempt.id.to_string(),
            "attempt_abandoned",
            &evidence,
        )
        .await?;

        // Restore the abandoned attempt's EXCLUSIVE inputs (every input the winner
        // did not spend); a shared input stays confirmed_spent by the winner.
        let exclusive: Vec<UtxoRef> = attempt_inputs
            .iter()
            .filter(|r| !winner_inputs.contains(r))
            .copied()
            .collect();
        crate::wallet::utxo::restore_inputs_in_tx(&mut *tx, attempt.wallet_id, &exclusive).await?;

        // Tombstone the abandoned attempt's (reorged-out) produced outputs and delete
        // its indexed chain_records row so the index does not serve a dead tx.
        crate::wallet::utxo::tombstone_outputs_in_tx(&mut *tx, attempt.wallet_id, attempt.tx_hash)
            .await?;
        crate::chain::records::delete_chain_record_by_tx_hash(&mut *tx, attempt.tx_hash).await?;

        // Clear the record's pointer to the dead attempt so a future generation guard
        // can claim it, and refund only on a never-confirmed record.
        if let Some(record_id) = attempt.record_id {
            sqlx::query(
                "UPDATE cw_core.poe_record SET current_attempt_id = NULL \
                 WHERE id = $1 AND current_attempt_id = $2",
            )
            .bind(record_id)
            .bind(attempt.id)
            .execute(&mut *tx)
            .await?;

            if !record_is_confirmed_success {
                // The winner that supplied the conflict did NOT carry this record
                // forward (an operator-issued cancelling replacement whose PoE never
                // landed): refund the never-confirmed record in this same transaction.
                // The single-refund PK(record_id) keeps it at most once. A record that
                // is already confirmed-success never reaches here.
                let detail = serde_json::json!({
                    "reason": RefundReason::RollbackRetriesExhausted.as_str(),
                    "conflicting_tx_hash": hex::encode(winner_tx_hash),
                });
                record_permanent_failure_in_tx(
                    tx,
                    record_id,
                    RefundReason::RollbackRetriesExhausted,
                    &detail,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Re-pin an on-chain non-terminal attempt's coordinates without confirming it,
    /// and (for a confirmed attempt re-included below threshold) re-pin the confirmed
    /// row under the confirmed guard with a row-count check.
    ///
    /// A landed-below-threshold attempt or a reorg suspect re-included at a new height
    /// re-pins via the non-terminal arm. A `confirmed` attempt re-observed at a new
    /// height inside the settlement window re-pins via the confirmed arm; an
    /// unexpected zero row there is a reconciliation anomaly the caller surfaces.
    async fn repin_attempt(
        &self,
        live: &LiveAttempt,
        block_height: u64,
        block_time: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        if live.status == attempt::AttemptStatus::Confirmed {
            let affected = attempt::repin_confirmed_attempt_in_tx(
                &mut tx,
                live.attempt_id,
                block_height,
                block_time,
            )
            .await?;
            if affected == 0 {
                // The attempt was not `confirmed` as assumed (or already at this
                // height): not a silent success. Re-pin the record/index coordinates
                // is unnecessary; commit the (empty) transaction and surface nothing
                // further. A zero here past the confirmed guard is logged as an anomaly.
                tracing::warn!(
                    attempt_id = %live.attempt_id,
                    block_height,
                    "confirmed-attempt re-pin affected zero rows"
                );
            } else {
                self.repin_record_and_index(&mut tx, live, block_height, block_time)
                    .await?;
            }
        } else {
            attempt::repin_attempt_in_tx(&mut tx, live.attempt_id, block_height, block_time)
                .await?;
            self.repin_record_and_index(&mut tx, live, block_height, block_time)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Re-pin a record's projected coordinates (and re-enqueue the index job at the
    /// new height for a confirmed re-inclusion) within the caller's transaction.
    async fn repin_record_and_index(
        &self,
        tx: &mut sqlx::PgConnection,
        live: &LiveAttempt,
        block_height: u64,
        block_time: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let Some(record_id) = live.record_id else {
            return Ok(());
        };
        let height = i64::try_from(block_height)
            .map_err(|_| crate::Error::Config("block height overflow".into()))?;
        sqlx::query(
            "UPDATE cw_core.poe_record \
             SET block_height = $2, block_time = $3, \
                 first_seen_on_chain_at = COALESCE(first_seen_on_chain_at, now()) \
             WHERE id = $1 AND status IN ('submitted', 'confirmed')",
        )
        .bind(record_id)
        .bind(height)
        .bind(block_time)
        .execute(&mut *tx)
        .await?;

        // A confirmed re-inclusion at a new height must re-pin the index too, so the
        // single writer's chain_records coordinates follow the canonical chain.
        if live.status == attempt::AttemptStatus::Confirmed {
            self.enqueue_index_job(tx, live, block_height, block_time.unwrap_or_else(Utc::now))
                .await?;
        }
        Ok(())
    }

    /// Acquire the attempt's wallet advisory lock for a wallet-mutating arm, yielding
    /// (re-queuing) rather than blocking when a live submit holds it, and escalating
    /// to a bounded-fair acquire after the attempt has yielded too many times.
    ///
    /// Returns `Ok(Some(lock))` when the lock is held (the caller may mutate
    /// wallet_utxo), or `Ok(None)` when the arm yielded: in the yield case the
    /// attempt is stamped with a bounded backoff and its yield counter bumped so the
    /// next pass retries it (starvation-free), and a yield_count past the anomaly
    /// threshold is surfaced as an operator-reconcile anomaly. The escalation still
    /// takes the wallet advisory lock before any row lock, so the lock-order
    /// invariant holds.
    async fn acquire_wallet_for_mutation(
        &self,
        live: &LiveAttempt,
    ) -> Result<Option<crate::runtime::locks::AdvisoryLock>> {
        // Fast path: a non-blocking try-acquire. The common case is uncontended.
        if let Some(lock) = crate::wallet::pool::try_lock_wallet(&self.pool, live.wallet_id).await?
        {
            return Ok(Some(lock));
        }

        // Contended. How many times has this attempt's mutation already yielded?
        let yields = attempt::load_attempt(&self.pool, live.attempt_id)
            .await?
            .map_or(0, |a| a.yield_count);

        if yields >= self.config.max_lock_yields {
            // Escalate to a bounded-fair acquire so a persistently-contended record's
            // mutation is applied in bounded time rather than only eventually. Still
            // acquires the advisory lock before any wallet_utxo row lock.
            if let Some(lock) = crate::wallet::pool::try_lock_wallet_with_deadline(
                &self.pool,
                live.wallet_id,
                self.config.fair_lock_deadline,
            )
            .await?
            {
                return Ok(Some(lock));
            }
        }

        // Still could not acquire: yield. Stamp a bounded backoff and bump the yield
        // counter; the next pass retries this attempt after the backoff.
        let new_count =
            attempt::stamp_yield(&self.pool, live.attempt_id, LOCK_YIELD_BACKOFF).await?;
        if new_count >= self.config.max_lock_yields {
            tracing::warn!(
                attempt_id = %live.attempt_id,
                wallet_id = %live.wallet_id,
                yield_count = new_count,
                "confirm wallet mutation has yielded past the anomaly threshold (wallet is pathologically contended)"
            );
        }
        Ok(None)
    }

    /// Read a record's current rollback-retry count.
    async fn record_rollback_retry_count(&self, record_id: Uuid) -> Result<u32> {
        let count: i32 =
            sqlx::query_scalar("SELECT rollback_retry_count FROM cw_core.poe_record WHERE id = $1")
                .bind(record_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(u32::try_from(count.max(0)).unwrap_or(0))
    }

    /// Roll a reorged-out original forward with a cancelling replacement: clear the
    /// record's `current_attempt_id`, bump the record's rollback-retry count, and
    /// enqueue the cancelling-replacement submit job (forced to spend the original's
    /// inputs) in ONE transaction so a crash can never leave a rolled-back record with
    /// no pending replacement. It does NOT supersede the original here: the submit path
    /// supersedes the still-active original atomically with recording the replacement
    /// (see [`Self::supersede_and_enqueue_replacement_in_tx`]).
    ///
    /// The original is left an active broadcaster and reconcilable (it can still land
    /// before the replacement); it is terminalised only when the replacement
    /// re-confirms on the canonical chain to settlement depth (a settlement-deep
    /// conflict), by the confirm/abandon symmetry. There is no refund here.
    async fn rollback_retry(
        &self,
        live: &LiveAttempt,
        record_id: Uuid,
        prior_retry_count: u32,
    ) -> Result<ReconcileOutcome> {
        let attempt = match attempt::load_attempt(&self.pool, live.attempt_id).await? {
            Some(a) => a,
            None => return Ok(ReconcileOutcome::RollbackPendingWindow),
        };

        let mut tx = self.pool.begin().await?;
        let superseded = self
            .supersede_and_enqueue_replacement_in_tx(
                &mut tx,
                &attempt,
                record_id,
                prior_retry_count,
            )
            .await?;
        if !superseded {
            tx.rollback().await?;
            return Ok(ReconcileOutcome::RollbackPendingWindow);
        }
        tx.commit().await?;
        Ok(ReconcileOutcome::RollbackRetry)
    }

    /// The shared enqueue-replacement handoff that rolls a record forward with a
    /// cancelling replacement, within the caller's transaction.
    ///
    /// Moves the record to `submitted` with a cleared `current_attempt_id` and a
    /// bumped rollback count, appends the `retrying` event, and enqueues the
    /// cancelling-replacement submit job forced to spend the original's inputs (the
    /// conflict the at-most-one-lands invariant rests on) in the SAME transaction.
    ///
    /// It does NOT supersede the original here. The supersede is the submit path's
    /// ATOMIC supersede-and-record handoff: when the enqueued replacement submits, it
    /// marks the still-active original `superseded` and sets the `superseded_by` link
    /// in the same record-before-broadcast transaction that records the replacement
    /// and claims the record's generation, so the original leaves the
    /// active-broadcaster set the instant the replacement enters it (the one-active
    /// index is satisfied at every instant). Pre-superseding the original here would
    /// leave it `superseded` before the replacement submits, and the submit-side
    /// supersede (guarded to an active broadcaster) would then no-op, so the
    /// replacement could never record and the cancelling transaction would never be
    /// built. The original stays reconcilable until the replacement confirms to
    /// settlement depth; there is NO refund and NO input restore here.
    ///
    /// Returns `true` when the handoff was applied, `false` when the original is no
    /// longer an active broadcaster or the record is no longer live (a racing path
    /// already moved it), in which case the caller rolls back without acting.
    async fn supersede_and_enqueue_replacement_in_tx(
        &self,
        tx: &mut sqlx::PgConnection,
        original: &attempt::ChainAttempt,
        record_id: Uuid,
        prior_retry_count: u32,
    ) -> Result<bool> {
        // Verify the original is still an active broadcaster, but do NOT supersede it
        // here: the actual supersede is the submit path's atomic supersede-and-record
        // handoff, which marks the original `superseded` (guarded to an active
        // broadcaster) in the SAME transaction that records the cancelling replacement.
        // Pre-superseding here would make that submit-side supersede no-op, so the
        // replacement could never record (a lost generation) and the cancelling
        // transaction would never be built.
        if !original.status.is_active_broadcaster() {
            // The original is no longer an active broadcaster (already superseded,
            // confirmed, or abandoned by a racing path): abandon the handoff.
            return Ok(false);
        }

        // Move the record to `submitted` with a cleared attempt pointer and a bumped
        // rollback count, guarded on the record still being live AND still pointing at
        // THIS original. The cleared pointer forces the replacement submit down the
        // build path (the resume preamble is skipped when no current attempt rides the
        // record) AND satisfies the replacement's generation guard, which claims a
        // `submitted` record with no current attempt; the submit-side supersede then
        // re-checks and supersedes the still-active original atomically with recording
        // the replacement. `submitting` is admitted (and normalised to `submitted`)
        // for a stranded FIRST-publish original the recovery alert surfaced: its record
        // never reached `submitted` because the original never broadcast, but the
        // original is still a live in-flight attempt whose inputs are reserved, so a
        // cancelling replacement is the correct operator resolution.
        //
        // The `current_attempt_id = $2` predicate makes the handoff idempotent under
        // concurrency: two confirm passes (or a confirm pass racing an operator call)
        // for the same reorged-out original both target this row, but only the FIRST
        // observes it still pointing at the original — that pass clears the pointer and
        // wins; the second matches zero rows, returns false, and the caller rolls back
        // without bumping the count, appending a duplicate event, or enqueuing a second
        // replacement. This mirrors the submit-side clear-pointer generation guard.
        let row: Option<RollbackRow> = sqlx::query_as(
            "UPDATE cw_core.poe_record \
             SET rollback_retry_count = rollback_retry_count + 1, \
                 current_attempt_id = NULL, \
                 status = 'submitted' \
             WHERE id = $1 AND current_attempt_id = $2 \
               AND status IN ('submitting', 'submitted', 'confirmed') \
             RETURNING rollback_retry_count, request_id",
        )
        .bind(record_id)
        .bind(original.id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            return Ok(false);
        };

        let new_count =
            u32::try_from(row.rollback_retry_count.max(0)).unwrap_or(prior_retry_count + 1);
        let detail = serde_json::json!({
            "reason": "rollback_retry",
            "rollback_retry_count": new_count,
            "prior_block_height": original.block_height,
        });
        crate::events::append_subject_event(
            &mut *tx,
            "poe_record",
            &record_id.to_string(),
            "retrying",
            &detail,
        )
        .await?;

        // Enqueue the cancelling replacement, forced to spend the original's inputs,
        // in the SAME transaction as the supersede + state-clear. Use the deduplicating
        // enqueue with a singleton key per (record, rollback generation): even if the
        // current_attempt_id guard above were bypassed, two handoffs for the same
        // generation can never put two replacement submit jobs in flight. The key
        // includes the bumped count so a LATER legitimate rollback (a fresh generation
        // after the first replacement resolves) is not suppressed by a completed job.
        let forced_inputs = forced_inputs_from_attempt(&original.spent_inputs);
        let job = crate::chain::submit::SubmitJob {
            request_id: row.request_id.unwrap_or_default(),
            record_id,
            replacement_for: Some(hex::encode(original.tx_hash)),
            forced_inputs,
        };
        let backoff_secs = rollback_retry_backoff_secs(prior_retry_count);
        crate::runtime::enqueue::enqueue_dedupe(
            &mut *tx,
            crate::chain::submit::SUBMIT_QUEUE,
            &job,
            crate::runtime::enqueue::EnqueueOptions {
                run_at: Some(Utc::now() + chrono::Duration::seconds(i64::from(backoff_secs))),
                singleton_key: Some(format!("rollback:{record_id}:{new_count}")),
                ..Default::default()
            },
        )
        .await?;

        Ok(true)
    }

    /// The alert-only mempool reconcile pass: surface stuck transactions as an
    /// operator-visible reconcile state. It NEVER moves money and NEVER moves
    /// inputs.
    ///
    /// Over the not-yet-on-chain attempts past the alert threshold (keyed on the
    /// attempt's `mempool_entered_at`, never the record's `created_at`):
    ///
    /// - a `broadcast` attempt transitions to `stuck` and raises an operator alert;
    /// - an attempt past the long horizon whose fresh gateway lookup reports it not
    ///   found has its alert escalated (a louder "presumed dead" reconcile state).
    ///
    /// Neither transition refunds, restores inputs, or abandons: under the
    /// no-validity-interval model a not-found transaction can still be rebroadcast
    /// and land while its inputs are unspent, so absence + horizon is not a proof of
    /// death. The only money-moving proof is a settlement-deep conflicting spend
    /// (the confirmation of an operator-issued cancelling replacement, reconciled by
    /// the confirm/abandon passes), so a stuck attempt's inputs stay reserved until
    /// that conflict or an explicit operator resolution. An attempt newer than the
    /// alert threshold is a normal in-flight transaction and is untouched.
    async fn reconcile_stuck_mempool_attempts(&self) -> Result<StuckReconcileSummary> {
        let mut summary = StuckReconcileSummary::default();

        let candidates = attempt::load_stuck_mempool_candidates(
            &self.pool,
            self.config.mempool_alert_after,
            CONFIRM_BATCH_LIMIT,
        )
        .await?;
        if candidates.is_empty() {
            return Ok(summary);
        }

        // The escalation lookup is batched over only the candidates past the long
        // horizon, so a stuck-but-not-yet-presumed-dead attempt costs no gateway
        // traffic. A candidate found on chain is not absent and is left for the
        // on-chain confirm passes; only a not-found candidate past the horizon
        // escalates.
        let now = Utc::now();
        let escalation_targets: Vec<&attempt::ChainAttempt> = candidates
            .iter()
            .filter(|a| {
                attempt::mempool_entry_older_than(
                    a.mempool_entered_at,
                    self.config.mempool_proof_of_death_after,
                    now,
                )
            })
            .collect();
        let absent = self.observe_absent(&escalation_targets).await?;

        for candidate in &candidates {
            // Transition broadcast -> stuck and alert. A candidate already `stuck` or
            // `superseded` re-runs this idempotently: mark_stuck no-ops a non-broadcast
            // row, and the alert is keyed by attempt id so an operator sees one
            // reconcile state per attempt.
            if candidate.status == attempt::AttemptStatus::Broadcast {
                let transitioned = attempt::mark_stuck(&self.pool, candidate.id).await?;
                if transitioned {
                    self.alert_stuck(candidate).await?;
                    summary.stuck += 1;
                }
            }

            // Escalate the alert for a candidate past the long horizon whose fresh
            // lookup reports it not found. Still alert-only: no abandon, no restore,
            // no refund.
            if absent.contains(&candidate.id) {
                self.alert_presumed_dead(candidate).await?;
                summary.escalated += 1;
            }
        }

        Ok(summary)
    }

    /// Look up which of the given attempts a fresh gateway observation reports not
    /// found on chain, in one batched call.
    ///
    /// "Not found" is the same `gone` signal the reconcile pass uses: zero
    /// confirmations and no block height. The result is purely an alerting signal:
    /// under the no-validity-interval model a not-found transaction can still be
    /// rebroadcast and land, so the caller only ever escalates an alert on it. A
    /// gateway failure yields an empty set (no over-alerting); the next pass retries.
    async fn observe_absent(
        &self,
        attempts: &[&attempt::ChainAttempt],
    ) -> Result<std::collections::HashSet<Uuid>> {
        let mut absent = std::collections::HashSet::new();
        if attempts.is_empty() {
            return Ok(absent);
        }
        let hashes: Vec<[u8; 32]> = attempts.iter().map(|a| a.tx_hash).collect();
        let observations = match self.gateway.get_tx_confirmations(&hashes).await {
            Ok(observations) => observations,
            // A rate-limit storm or a transient gateway failure must not be read as
            // "absent" (which would over-alert): on any lookup failure no candidate is
            // escalated this pass, and the next pass retries.
            Err(_) => return Ok(absent),
        };
        for attempt in attempts {
            let observed = observations
                .get(&attempt.tx_hash)
                .copied()
                .unwrap_or_else(crate::chain::gateway::TxConfirmation::not_on_chain);
            let gone = observed.num_confirmations == 0 && observed.block_height.is_none();
            if gone {
                absent.insert(attempt.id);
            }
        }
        Ok(absent)
    }

    /// Raise the operator-facing stuck alert for an attempt, on the attempt's
    /// subject so an operator can list and act on the exact attempt.
    async fn alert_stuck(&self, attempt: &attempt::ChainAttempt) -> Result<()> {
        crate::events::append_subject_event(
            &self.pool,
            CHAIN_ATTEMPT_SUBJECT_KIND,
            &attempt.id.to_string(),
            MEMPOOL_STUCK_EVENT,
            &serde_json::json!({
                "attempt_id": attempt.id,
                "record_id": attempt.record_id,
                "wallet_id": attempt.wallet_id,
                "tx_hash": hex::encode(attempt.tx_hash),
                "mempool_entered_at": attempt.mempool_entered_at,
            }),
        )
        .await?;
        Ok(())
    }

    /// Escalate the operator-facing alert for a stuck attempt past the long horizon
    /// whose fresh lookup reports it not found. Still alert-only.
    async fn alert_presumed_dead(&self, attempt: &attempt::ChainAttempt) -> Result<()> {
        crate::events::append_subject_event(
            &self.pool,
            CHAIN_ATTEMPT_SUBJECT_KIND,
            &attempt.id.to_string(),
            MEMPOOL_PRESUMED_DEAD_EVENT,
            &serde_json::json!({
                "attempt_id": attempt.id,
                "record_id": attempt.record_id,
                "wallet_id": attempt.wallet_id,
                "tx_hash": hex::encode(attempt.tx_hash),
                "mempool_entered_at": attempt.mempool_entered_at,
            }),
        )
        .await?;
        Ok(())
    }

    /// List the attempts an operator should see in the wedged-attempt reconcile
    /// control surface: not-yet-on-chain attempts an operator can resolve with a
    /// cancelling replacement, oldest first.
    ///
    /// Two states qualify, both not on chain (`block_height IS NULL`):
    ///
    ///   - `stuck` — an attempt that reached the wire and passed the mempool alert
    ///     threshold (the confirm loop's mempool reconcile).
    ///   - `recorded` with no mempool entry — a stranded attempt that never reached
    ///     the wire, surfaced by the recovery sweep's stranded alert. Its
    ///     `mempool_entered_at` is NULL, so it sorts first.
    ///
    /// This is the read side of the control-plane list. The matching write side is
    /// [`issue_cancelling_replacement`](Self::issue_cancelling_replacement), the
    /// operator resolution that drives the replacement record-before-broadcast path.
    pub async fn list_stuck_attempts(&self, limit: i64) -> Result<Vec<StuckAttempt>> {
        let rows: Vec<StuckAttemptRow> = sqlx::query_as(
            "SELECT id, record_id, wallet_id, tx_hash, mempool_entered_at, yield_count \
             FROM cw_core.chain_attempt \
             WHERE block_height IS NULL \
               AND (status = 'stuck' \
                    OR (status = 'recorded' AND mempool_entered_at IS NULL)) \
             ORDER BY mempool_entered_at ASC NULLS FIRST, created_at ASC \
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(StuckAttemptRow::into_stuck).collect()
    }

    /// The operator control action that resolves a wedged attempt: issue a cancelling
    /// replacement that re-spends one of the wedged transaction's inputs.
    ///
    /// This is the ONLY way to terminalise a wedged attempt without waiting for it to
    /// land: enqueuing the replacement rolls the record forward; the submit path then
    /// supersedes the original atomically with recording the replacement, forced to
    /// spend the original's inputs (so it conflicts, the gateway-enforced intersection
    /// check guarantees it). When that replacement confirms to settlement depth, the
    /// confirm authority abandons the original by the settlement-deep conflict,
    /// restoring its exclusive inputs and writing the refund only if the record never
    /// landed. This action itself moves NO money and restores NO inputs; it only rolls
    /// the record forward with a replacement.
    ///
    /// It resolves the two operator-actionable wedged states:
    ///
    ///   - `stuck` — an attempt that reached the wire (mempool) and passed the alert
    ///     threshold without landing (the confirm loop's mempool reconcile).
    ///   - `recorded` — a stranded attempt that never reached the wire (a broadcast
    ///     that failed before any node observed it), surfaced by the recovery sweep's
    ///     stranded alert. Its bytes are durable and its inputs reserved, so the same
    ///     cancelling replacement re-spends them and produces the settlement-deep
    ///     conflict proof a refund is gated on. A blind age-refund is never safe for a
    ///     `recorded` attempt because the body may yet be in a mempool; the cancelling
    ///     replacement is the proof-producing resolution instead.
    ///
    /// A healthy `broadcast` attempt is left alone (it is progressing normally).
    ///
    /// The enqueue is one transaction under the wallet lock, taken yield-not-block so
    /// the action serialises with a live submit on the same wallet and never
    /// deadlocks. Returns `Ok(true)` when the handoff was issued, `Ok(false)` when the
    /// attempt is no longer a wedged active broadcaster (a racing path already resolved
    /// it) or the action yielded on wallet-lock contention.
    pub async fn issue_cancelling_replacement(&self, attempt_id: Uuid) -> Result<bool> {
        let original = match attempt::load_attempt(&self.pool, attempt_id).await? {
            Some(a) => a,
            None => return Ok(false),
        };
        if !matches!(
            original.status,
            attempt::AttemptStatus::Stuck | attempt::AttemptStatus::Recorded
        ) {
            // Only a wedged attempt (stuck on the wire, or stranded recorded) is
            // resolved by this control action; anything else (already superseded/
            // confirmed/abandoned, or a still-healthy broadcast) is a no-op.
            return Ok(false);
        }
        let Some(record_id) = original.record_id else {
            // A split has no record to roll a replacement forward for; a stuck split
            // is resolved by a settlement-deep conflict only.
            return Ok(false);
        };

        // Take the wallet advisory lock yield-not-block: the handoff supersedes the
        // original and enqueues the replacement under the lock, in the invariant lock
        // order, so it never deadlocks with a live submit on the same wallet.
        let Some(lock) =
            crate::wallet::pool::try_lock_wallet(&self.pool, original.wallet_id).await?
        else {
            return Ok(false);
        };

        let prior_retry_count = self.record_rollback_retry_count(record_id).await?;
        let mut tx = self.pool.begin().await?;
        let applied = self
            .supersede_and_enqueue_replacement_in_tx(
                &mut tx,
                &original,
                record_id,
                prior_retry_count,
            )
            .await?;
        if applied {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        let _ = lock.release().await;
        Ok(applied)
    }
}

/// The columns a rollback supersede returns: the bumped retry count and the
/// originating request id (carried onto the cancelling-replacement submit job).
#[derive(sqlx::FromRow)]
struct RollbackRow {
    rollback_retry_count: i32,
    request_id: Option<String>,
}

/// The counts the alert-only mempool reconcile pass produces in one iteration.
///
/// Both transitions are alert-only: neither moves money nor inputs. `stuck` is the
/// number of broadcast attempts newly transitioned to `stuck` and alerted;
/// `escalated` is the number whose alert was escalated because they are past the
/// long horizon and a fresh lookup reports them not found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StuckReconcileSummary {
    /// Broadcast attempts newly marked `stuck` and alerted this pass.
    stuck: u64,
    /// Stuck attempts whose alert was escalated to "presumed dead" this pass.
    escalated: u64,
}

/// One stuck attempt the operator-facing control surface lists.
///
/// The list exposes exactly what an operator needs to decide whether to issue a
/// cancelling replacement: the attempt and record/wallet it belongs to, its
/// transaction hash, when it entered the mempool, and how many times its
/// confirm/abandon mutation has yielded on wallet-lock contention (a high count
/// flags a pathologically contended wallet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StuckAttempt {
    /// The stuck attempt's id (the argument to
    /// [`ConfirmHandler::issue_cancelling_replacement`]).
    pub attempt_id: Uuid,
    /// The record this attempt serves, for a publish/replacement; `None` for a
    /// split.
    pub record_id: Option<Uuid>,
    /// The wallet whose inputs the stuck transaction reserves.
    pub wallet_id: Uuid,
    /// The 32-byte transaction hash, hex-encoded.
    pub tx_hash: String,
    /// When the transaction entered the mempool (the alert-timing basis).
    pub mempool_entered_at: Option<DateTime<Utc>>,
    /// How many times this attempt's confirm/abandon mutation yielded on wallet-lock
    /// contention.
    pub yield_count: i32,
}

/// The raw row the stuck-attempt list reads before the typed decode.
#[derive(sqlx::FromRow)]
struct StuckAttemptRow {
    id: Uuid,
    record_id: Option<Uuid>,
    wallet_id: Uuid,
    tx_hash: Vec<u8>,
    mempool_entered_at: Option<DateTime<Utc>>,
    yield_count: i32,
}

impl StuckAttemptRow {
    fn into_stuck(self) -> Result<StuckAttempt> {
        Ok(StuckAttempt {
            attempt_id: self.id,
            record_id: self.record_id,
            wallet_id: self.wallet_id,
            tx_hash: hex::encode(&self.tx_hash),
            mempool_entered_at: self.mempool_entered_at,
            yield_count: self.yield_count,
        })
    }
}

/// Build the cancelling replacement's forced-input set from the superseded
/// original attempt's recorded spent inputs, so the replacement is forced to
/// re-spend at least one of them (the conflict the at-most-one-lands invariant
/// rests on). An empty original input set yields an empty forced set; the submit
/// handler treats that as a degenerate replacement and surfaces the failure through
/// its own terminal path rather than silently double-publishing.
fn forced_inputs_from_attempt(
    inputs: &[crate::chain::attempt::AttemptInput],
) -> Vec<crate::chain::submit::ForcedInput> {
    inputs
        .iter()
        .map(|i| crate::chain::submit::ForcedInput {
            tx_hash: i.tx_hash.clone(),
            index: i.index,
            lovelace: i.lovelace,
        })
        .collect()
}

impl<G: crate::chain::gateway::ChainGateway + 'static> JobHandler for ConfirmHandler<G> {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        // Run one iteration. An all-provider 429 storm defers until the cooldown
        // lifts (preserving the single attempt); otherwise the iteration completes
        // and the cron tick re-fires the loop on its cadence.
        match self.run_iteration().await {
            Ok(summary) => match summary.rate_limited_until {
                Some(until) => JobOutcome::Defer { until },
                None => JobOutcome::Complete,
            },
            Err(e) => JobOutcome::Fail {
                error: crate::runtime::JobError::new("confirm_iteration_failed", e.to_string()),
            },
        }
    }
}

/// A reorg suspect carried from Pass A into the batched Pass B/C gateway call.
///
/// Selected when an attempt is on chain below the confirmation threshold AND the
/// materialised tip has advanced past the rollback window (the arithmetic half of
/// the two-source gate). The fresh gateway lookup is the second source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReorgSuspect {
    /// The suspect attempt's id.
    pub attempt_id: Uuid,
    /// The 32-byte transaction hash to re-query.
    pub tx_hash: [u8; 32],
    /// The block height the attempt was last seen at (the prior height the
    /// rollback decision compares the fresh observation against).
    pub prior_block_height: u64,
}

/// A live attempt the confirm loop reconciles, loaded for a pass and hydrated with
/// its record bytes (for the index enqueue) when it serves a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAttempt {
    /// The attempt's id.
    pub attempt_id: Uuid,
    /// What kind of chain action this attempt is.
    pub kind: crate::chain::attempt::AttemptKind,
    /// The record this attempt serves (a publish/replacement); `None` for a split.
    pub record_id: Option<Uuid>,
    /// The wallet whose pool funds and tracks the spend.
    pub wallet_id: Uuid,
    /// The 32-byte transaction hash.
    pub tx_hash: [u8; 32],
    /// The block height the transaction landed in, if observed.
    pub block_height: Option<u64>,
    /// The block time the transaction landed in, if observed.
    pub block_time: Option<DateTime<Utc>>,
    /// When the transaction was first seen on chain, if ever (the prior-sighting
    /// half of the two-source reorg gate).
    pub first_seen_on_chain_at: Option<DateTime<Utc>>,
    /// The attempt's lifecycle status (decides the re-pin arm: a `confirmed` attempt
    /// re-pins under the confirmed guard).
    pub status: crate::chain::attempt::AttemptStatus,
    /// The wallet inputs the transaction spends; promoted on confirm, used to detect
    /// a settlement-deep conflict on abandon.
    pub spent_inputs: Vec<AttemptInput>,
    /// The record's canonical bytes, carried inline into the index_tx job on a
    /// threshold-flip; `None` for a split (no record) or when the record was already
    /// terminalised.
    pub record_bytes: Option<Vec<u8>>,
    /// Whether this attempt was carried into the batched pass as a reorg suspect. A
    /// suspect the fresh lookup still sees on chain reconciles as
    /// `ReorgSuspectCleared` rather than plain `Progress`.
    pub is_reorg_suspect: bool,
}

/// The result of the batched Pass B/C gateway call: the partial summary it
/// produced and, when every provider was rate-limited, the instant the cooldown
/// lifts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GatewayPassResult {
    /// The outcomes the pass aggregated.
    pub summary: IterationSummary,
    /// When every provider in the failover pair returned 429 this pass, the
    /// instant the cooldown lifts; `None` otherwise.
    pub rate_limited_until: Option<DateTime<Utc>>,
}

/// The instant a rate-limit storm parks the confirm loop until, or `None` when
/// the error is not a storm.
///
/// A [`crate::Error::ChainRateLimitStorm`] (every provider in the failover pair
/// rate-limiting us) carries the instant the soonest provider cooldown lifts. The
/// confirm loop parks until exactly that instant with a defer, which never burns
/// the single attempt the queue allows. Any other error (a database failure, a
/// single-provider blip the failover already handled) is `None`: a real failure
/// that must surface, never be silently parked.
#[must_use]
fn rate_limit_storm_until(error: &crate::Error) -> Option<DateTime<Utc>> {
    match error {
        crate::Error::ChainRateLimitStorm { cooldown_until } => Some(*cooldown_until),
        _ => None,
    }
}

/// Add a single reconcile outcome to a running summary.
fn tally(summary: &mut IterationSummary, outcome: ReconcileOutcome) {
    match outcome {
        ReconcileOutcome::Confirmed => summary.confirmed += 1,
        ReconcileOutcome::Progress => summary.progress += 1,
        ReconcileOutcome::TipBehind => summary.tip_behind += 1,
        ReconcileOutcome::ReorgSuspectCleared => summary.reorg_suspect_cleared += 1,
        ReconcileOutcome::RollbackRetry => summary.rollback_retry += 1,
        ReconcileOutcome::RollbackBudgetExhausted => summary.rollback_budget_exhausted += 1,
        ReconcileOutcome::RollbackPendingWindow => summary.rollback_pending_window += 1,
        ReconcileOutcome::AbandonedByConflict => summary.abandoned_by_conflict += 1,
        ReconcileOutcome::Mempool => summary.mempool += 1,
        ReconcileOutcome::Yielded => summary.yielded += 1,
    }
}

/// Fold one summary's counts into another (Pass A's into the iteration total).
fn fold_summary(into: &mut IterationSummary, other: &IterationSummary) {
    into.confirmed += other.confirmed;
    into.progress += other.progress;
    into.tip_behind += other.tip_behind;
    into.reorg_suspect_cleared += other.reorg_suspect_cleared;
    into.rollback_retry += other.rollback_retry;
    into.rollback_budget_exhausted += other.rollback_budget_exhausted;
    into.rollback_pending_window += other.rollback_pending_window;
    into.abandoned_by_conflict += other.abandoned_by_conflict;
    into.mempool += other.mempool;
    into.mempool_stuck += other.mempool_stuck;
    into.mempool_stuck_escalated += other.mempool_stuck_escalated;
    into.yielded += other.yielded;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_backoff_grows_then_caps() {
        assert_eq!(rollback_retry_backoff_secs(0), 20);
        assert_eq!(rollback_retry_backoff_secs(1), 40);
        assert_eq!(rollback_retry_backoff_secs(2), 80);
        assert_eq!(rollback_retry_backoff_secs(3), 160);
        // 20 * 2^4 = 320 -> capped at 300.
        assert_eq!(rollback_retry_backoff_secs(4), 300);
        // A large count saturates at the cap, never overflowing.
        assert_eq!(rollback_retry_backoff_secs(100), 300);
    }

    #[test]
    fn confirm_policy_is_a_single_attempt_singleton_loop() {
        let policy = confirm_policy();
        assert_eq!(policy.queue, CONFIRM_QUEUE);
        assert_eq!(
            policy.policy,
            crate::runtime::policy::QueuePolicyKind::SingletonLoop
        );
        // One attempt: a 429 storm defers (which does not consume an attempt)
        // rather than failing the loop.
        assert_eq!(policy.max_attempts, 1);
        assert_eq!(policy.lease_secs, 600);
    }

    #[test]
    fn refund_reason_strings_are_stable() {
        assert_eq!(RefundReason::TxBuildFailed.as_str(), "tx_build_failed");
        assert_eq!(
            RefundReason::ByteBudgetExceeded.as_str(),
            "byte_budget_exceeded"
        );
        assert_eq!(
            RefundReason::RollbackRetriesExhausted.as_str(),
            "rollback_retries_exhausted"
        );
        assert_eq!(
            RefundReason::ReplacementInputsMissing.as_str(),
            "replacement_inputs_missing"
        );
        assert_eq!(
            RefundReason::ReplacementDoesNotConflict.as_str(),
            "replacement_does_not_conflict"
        );
        assert_eq!(RefundReason::NodeRejected.as_str(), "node_rejected");
    }

    #[test]
    fn default_config_uses_the_documented_thresholds() {
        let c = ConfirmConfig::default();
        assert_eq!(c.confirmation_threshold, 15);
        assert_eq!(c.settlement_reverify_blocks, 30);
        assert_eq!(c.max_rollback_retries, 5);
        assert_eq!(c.mempool_alert_after, Duration::from_secs(1800));
        assert_eq!(c.mempool_proof_of_death_after, Duration::from_secs(7200));
        assert_eq!(c.max_lock_yields, 5);
        // The settlement depth a conflicting spend must reach to count as proof of
        // death is the same threshold a normal record settles at.
        assert_eq!(c.settlement_depth(), c.confirmation_threshold);
    }
}
