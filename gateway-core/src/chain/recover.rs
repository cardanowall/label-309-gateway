//! The crash-recovery sweep over stranded chain-attempt records.
//!
//! The submission pipeline records a `chain_attempt` row (`status='recorded'`)
//! BEFORE it broadcasts, so a crashed or never-delivered broadcast can be
//! re-broadcast from durable bytes rather than lost. The confirm authority drives
//! every attempt that REACHED the wire (a `broadcast`/`stuck` attempt, with
//! `mempool_entered_at` stamped) toward a terminal state. But an attempt whose
//! broadcast failed BEFORE the projection learned it reached a node — a provider
//! 429 storm, a transport error, a malformed provider response, a crash between
//! record-before-broadcast and the broadcast — stays `recorded` with
//! `mempool_entered_at IS NULL`, and the submit job that owned it completes after
//! its retry budget without ever landing the transaction. Nothing keys off a
//! `recorded`+NULL-mempool attempt: the confirm loop's mempool reconcile keys off
//! `mempool_entered_at` (NULL here), and the only [`crate::chain::submit::SUBMIT_QUEUE`]
//! enqueue at publish time is gone once that job completes. Such a record is
//! stranded: the account was debited, no transaction is on chain, and no path
//! recovers it.
//!
//! This sweep owns every such stranded attempt and drives it toward a terminal
//! state, so a record never sits SILENTLY in `submitting` forever.
//!
//! # Why the sweep never refunds on age
//!
//! A Proof-of-Existence transaction carries NO validity interval, so it can land
//! at any later block. The submit path classifies a transport failure, a malformed
//! provider response, or a 5xx/429 as AMBIGUOUS: the body may already have reached
//! a node and be sitting in a mempool, so it is never abandoned on age or absence
//! (only a deterministic node reject or a settlement-deep conflicting spend proves
//! death). A `recorded`+NULL-mempool attempt is exactly such an ambiguous case:
//! age does not prove the body never reached a node. So the sweep MUST NOT abandon
//! the attempt, restore its inputs, or refund the record on age — doing so would
//! double-spend the restored inputs and double-pay the account if the transaction
//! later lands. The attempt's inputs stay reserved (`pending_spent`) until a real
//! proof of death exists, exactly as for any other in-flight attempt.
//!
//! # The two horizons
//!
//! - **grace** — how long an attempt must have been `recorded` (and never reached
//!   the wire) before the sweep re-enqueues a submit for it. Set ABOVE the submit
//!   job's own retry window (its five attempts at the fixed backoff), so the sweep
//!   only acts once the job that owned the attempt has finished and genuinely
//!   abandoned it. A still-in-flight submit is never raced. The re-enqueue is the
//!   safe recovery action: the submit path re-broadcasts the EXACT recorded bytes
//!   idempotently (the node dedupes by tx id), so a recoverable transaction lands
//!   (then the confirm authority owns it) or hits a deterministic node reject (then
//!   the submit path's existing abandon+refund arm fires on real proof). The
//!   re-enqueue keeps applying every pass, including past the alert horizon, so a
//!   recoverable transaction always gets another chance to land.
//! - **alert** — the horizon past which a still-stranded attempt raises a ONE-SHOT
//!   operator alert ([`CHAIN_RECOVER_STRANDED_EVENT`]) so a genuinely wedged record
//!   is never SILENTLY stuck. The alert is the operator's signal to resolve the
//!   record with a cancelling replacement
//!   ([`crate::chain::confirm::ConfirmHandler::issue_cancelling_replacement`]),
//!   which re-spends the stranded attempt's inputs and, on its settlement-deep
//!   confirmation, terminalises the original through the existing proof-gated
//!   abandon+refund. The alert NEVER moves money or inputs itself.
//!
//! # The terminal guarantee
//!
//! A stranded record always reaches a terminal state through a REAL proof, never an
//! age timer: it lands (confirm), the re-broadcast hits a deterministic reject
//! (refund on proof), or an operator (cued by the alert) issues a cancelling
//! replacement whose settlement-deep confirmation abandons the original and refunds
//! the record only if it never landed. "Never infinite limbo" is delivered as
//! "never SILENT limbo": a wedged record is always either recovering or
//! operator-alerted, and every refund is gated on proof.
//!
//! The sweep is a bounded, indexed query with no per-tick external calls: it only
//! enqueues submit jobs and appends operator alerts. The re-broadcast itself
//! happens on the submit queue, not here.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use uuid::Uuid;

use crate::chain::attempt::{AttemptInput, AttemptKind};
use crate::chain::confirm::CHAIN_ATTEMPT_SUBJECT_KIND;
use crate::chain::submit::{forced_inputs_from_attempt, SplitResumeJob, SubmitJob, SUBMIT_QUEUE};
use crate::runtime::enqueue::{enqueue_dedupe, EnqueueOptions};
use crate::runtime::{Backoff, JobContext, JobHandler, JobOutcome};
use crate::Result;

/// The queue the chain-attempt recovery sweep runs on.
pub const CHAIN_RECOVER_QUEUE: &str = "cardano_recover";

/// The default sweep cadence: every minute. The grace and alert horizons (not the
/// cadence) bound how long a stranded attempt waits before the sweep acts on it; a
/// deployment overrides the cadence via the chain configuration.
pub const DEFAULT_CHAIN_RECOVER_SCHEDULE: &str = "0 * * * * *";

/// How long an attempt must have been `recorded` (never on the wire) before the
/// sweep re-enqueues a submit. Set ABOVE the submit job's own retry window so the
/// sweep never races a still-in-flight submit: the job runs five attempts at the
/// fixed 30s backoff (~2.5 minutes of broadcast retries), so three minutes leaves
/// margin for the last attempt to finish before the sweep adopts the attempt.
pub const DEFAULT_RECOVER_GRACE: Duration = Duration::from_secs(180);

/// The horizon past which a still-stranded `recorded` attempt raises a one-shot
/// operator alert. Well beyond the grace and the mempool proof-of-death (two
/// hours), so a transaction that could still land via a recovered re-broadcast is
/// given ample time first; only an attempt that has resisted recovery for this long
/// is surfaced for operator resolution. The alert does NOT refund or restore
/// anything — it cues the operator to issue a cancelling replacement, which
/// terminalises through the existing settlement-deep-conflict proof.
pub const DEFAULT_RECOVER_ALERT_AFTER: Duration = Duration::from_secs(6 * 60 * 60);

/// The maximum number of stranded attempts processed per sweep pass.
pub const RECOVER_BATCH_LIMIT: i64 = 500;

/// The operator-facing reconcile alert raised on the attempt subject when a
/// `recorded` attempt has been stranded (never on the wire) past the alert horizon.
/// It is a queryable reconcile state, NOT a refund: the attempt's inputs stay
/// reserved and the transaction can still land. The operator resolution is to issue
/// a cancelling replacement
/// ([`crate::chain::confirm::ConfirmHandler::issue_cancelling_replacement`]); only
/// the settlement-deep confirmation of that replacement moves money or restores
/// inputs. Mirrors the confirm loop's mempool presumed-dead alert for an attempt
/// that DID reach the wire.
pub const CHAIN_RECOVER_STRANDED_EVENT: &str = "chain.attempt.stranded";

/// The sweep's tuning, read from config so a deployment can override the horizons
/// without a code change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainRecoverConfig {
    /// How long an attempt must have been `recorded` (never on the wire) before the
    /// sweep re-enqueues a submit for it. Set above the submit job's retry window.
    pub grace: Duration,
    /// The horizon past which a still-stranded `recorded` attempt raises a one-shot
    /// operator alert.
    pub alert_after: Duration,
}

impl Default for ChainRecoverConfig {
    fn default() -> Self {
        Self {
            grace: DEFAULT_RECOVER_GRACE,
            alert_after: DEFAULT_RECOVER_ALERT_AFTER,
        }
    }
}

/// The aggregate result of one sweep pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChainRecoverSummary {
    /// Stranded attempts for which a submit was re-enqueued this pass.
    pub re_enqueued: usize,
    /// Re-enqueues suppressed because a submit job was already in flight for the
    /// record (the dedupe no-op).
    pub already_in_flight: usize,
    /// Stranded attempts that raised a one-shot operator alert this pass (past the
    /// alert horizon, not previously alerted in this process).
    pub alerted: usize,
}

/// One stranded attempt the sweep must process, read past the grace.
#[derive(sqlx::FromRow)]
struct StrandedAttempt {
    id: Uuid,
    /// The record a publish/replacement serves; `None` for a split (which serves
    /// only its wallet and has no record).
    record_id: Option<Uuid>,
    kind: String,
    wallet_id: Uuid,
    tx_hash: Vec<u8>,
    replaces_tx_hash: Option<Vec<u8>>,
    spent_inputs: serde_json::Value,
    request_id: Option<String>,
    /// True when the record is live but no longer points at this attempt (an ORPHAN):
    /// a rollback handoff cleared the record's pointer to enqueue a cancelling
    /// replacement, but that replacement never recorded (it exhausted wallet
    /// contention), so the original sits `recorded`+NULL-mempool unpointed. The sweep
    /// re-points the record at it before re-broadcasting, so it cannot strand.
    orphaned: bool,
    /// True when the attempt is past the alert horizon.
    past_alert: bool,
}

/// Read the stranded attempts past the grace: a `recorded` attempt that never
/// reached the wire (`mempool_entered_at IS NULL`) and is past the grace.
///
/// All three attempt kinds can strand the same way (recorded before broadcast, the
/// broadcast never reaching the wire), and all three are recovered the same way: an
/// idempotent re-broadcast of the durable signed bytes. So the sweep covers them
/// all, with a per-kind liveness predicate:
///
///   - a publish/replacement the record still rides (`r.current_attempt_id = a.id`)
///     and the record still live (`submitting`/`submitted`), so a record already
///     terminalised by another path is not raced;
///   - an ORPHANED publish/replacement: a `recorded`+NULL-mempool attempt whose live
///     record no longer points at any attempt (`r.current_attempt_id IS NULL`) and
///     which has no genuine competing live sibling. This is the state a rollback
///     handoff leaves when it cleared the record's pointer to enqueue a cancelling
///     replacement that then never recorded (it exhausted wallet contention): the
///     attempt sits unpointed, never on the wire, and no other path owns it. The sweep
///     re-points the record at it (guarded on the pointer still being NULL) before
///     re-broadcasting, so the charged record cannot strand. A "competing live sibling"
///     is an active broadcaster (`recorded`/`broadcast`/`stuck`) or a `superseded`
///     sibling from a DIFFERENT chain — but NOT the very original THIS attempt
///     superseded (a `superseded` sibling with `superseded_by = a.id`), which is this
///     replacement's own cancelled predecessor, not a competitor. Without that
///     carve-out an orphaned recorded REPLACEMENT, which always sits behind its own
///     superseded original, would be wrongly blocked and strand its charged record;
///   - a split has no record (the LEFT JOIN yields a NULL record), so it is included
///     purely on its own `recorded`+NULL-mempool+past-grace state. Re-broadcasting
///     its recorded bytes is always safe (the node dedupes by tx id), and on a
///     deterministic reject the submit path abandons it and restores its source,
///     closing the strand that would otherwise leave the source `pending_spent`
///     forever.
///
/// The `past_alert` flag is computed in the database against the same clock the
/// grace cut uses, so the two horizons are consistent within a row.
async fn stranded_attempts(
    pool: &sqlx::PgPool,
    grace: Duration,
    alert_after: Duration,
    limit: i64,
) -> Result<Vec<StrandedAttempt>> {
    let grace_secs = grace.as_secs_f64();
    let alert_secs = alert_after.as_secs_f64();
    let rows = sqlx::query_as::<_, StrandedAttempt>(
        "SELECT a.id, a.record_id, a.kind, a.wallet_id, a.tx_hash, a.replaces_tx_hash, \
                a.spent_inputs, r.request_id, \
                (a.kind IN ('publish', 'replacement') \
                 AND r.current_attempt_id IS NULL) AS orphaned, \
                (a.created_at < now() - make_interval(secs => $2)) AS past_alert \
         FROM cw_core.chain_attempt a \
         LEFT JOIN cw_core.poe_record r ON r.id = a.record_id \
         WHERE a.status = 'recorded' \
           AND a.mempool_entered_at IS NULL \
           AND a.created_at < now() - make_interval(secs => $1) \
           AND ( \
                 (a.kind IN ('publish', 'replacement') \
                  AND r.status IN ('submitting', 'submitted') \
                  AND ( \
                        r.current_attempt_id = a.id \
                     OR ( \
                          r.current_attempt_id IS NULL \
                          AND NOT EXISTS ( \
                                SELECT 1 FROM cw_core.chain_attempt sib \
                                WHERE sib.record_id = a.record_id \
                                  AND sib.id <> a.id \
                                  AND ( \
                                        sib.status IN ('recorded', 'broadcast', 'stuck') \
                                     OR (sib.status = 'superseded' \
                                         AND sib.superseded_by IS DISTINCT FROM a.id) \
                                      ) \
                              ) \
                        ) \
                      )) \
              OR (a.kind = 'split') \
               ) \
         ORDER BY a.created_at \
         LIMIT $3",
    )
    .bind(grace_secs)
    .bind(alert_secs)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The chain-attempt recovery sweep handler.
///
/// Register it on the runtime against [`CHAIN_RECOVER_QUEUE`] with
/// [`chain_recover_policy`] and [`chain_recover_schedule`]. It owns its pool and the
/// two horizons; it takes no gateway (the re-broadcast happens on the submit queue)
/// and no keyring (it moves no money and no chain bytes). Every action is idempotent
/// on the record id, so the runtime's at-least-once delivery is harmless.
///
/// The one-shot stranded-alert is deduped in memory on the handler. The sweep is a
/// singleton loop (one in-flight pass across the deployment), so the set never
/// races; a process restart re-alerts a still-stranded attempt once (which only
/// delays, never suppresses, the alert), and an attempt that resolves (lands,
/// terminalises, or is superseded by an operator replacement) leaves the stranded
/// scan and is dropped from the set. This keeps the alert bookkeeping off the
/// durable schema, matching the storage recovery sweep's stuck-alert counter.
pub struct ChainRecoverHandler {
    pool: sqlx::PgPool,
    config: ChainRecoverConfig,
    /// Attempt ids already alerted this process, so the stranded alert fires once
    /// per attempt rather than every pass.
    alerted: Mutex<HashSet<Uuid>>,
}

impl ChainRecoverHandler {
    /// Build a recovery sweep handler over a pool and the horizon config.
    #[must_use]
    pub fn new(pool: sqlx::PgPool, config: ChainRecoverConfig) -> Self {
        Self {
            pool,
            config,
            alerted: Mutex::new(HashSet::new()),
        }
    }

    /// Run one sweep pass over every stranded attempt past the grace and return its
    /// summary. Used by the handler and by integration tests that drive the sweep
    /// directly. A single attempt's error does not abort the pass: it is logged and
    /// the sweep moves on, so one bad attempt never starves the rest.
    pub async fn run_once(&self) -> Result<ChainRecoverSummary> {
        let stranded = stranded_attempts(
            &self.pool,
            self.config.grace,
            self.config.alert_after,
            RECOVER_BATCH_LIMIT,
        )
        .await?;
        let mut summary = ChainRecoverSummary::default();
        let mut seen: Vec<Uuid> = Vec::with_capacity(stranded.len());
        for attempt in &stranded {
            seen.push(attempt.id);
            match self.converge(attempt, &mut summary).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(
                        attempt_id = %attempt.id,
                        record_id = ?attempt.record_id,
                        kind = %attempt.kind,
                        error = %e,
                        "chain recovery sweep skipped a stranded attempt after an error"
                    );
                }
            }
        }
        // Drop the alerted markers for attempts no longer in the stranded set (they
        // landed, terminalised, or were superseded), so the set does not grow without
        // bound and a recurrence after a genuine resolution re-alerts.
        self.retain_alerted(&seen);
        Ok(summary)
    }

    /// Converge a single stranded attempt: re-adopt an orphaned original onto its
    /// record, always re-enqueue a submit (the safe recovery action), and additionally
    /// raise a one-shot operator alert once it is past the alert horizon.
    async fn converge(
        &self,
        attempt: &StrandedAttempt,
        summary: &mut ChainRecoverSummary,
    ) -> Result<()> {
        // An orphaned original (its record's pointer was cleared by a rollback handoff
        // whose replacement never recorded) is re-adopted FIRST: re-point the record at
        // it so the submit path's resume preamble (which keys on
        // `current_attempt_id = a.id`) re-broadcasts it. Guarded on the pointer still
        // being NULL and the record live, so a replacement that recorded in the
        // meantime (claiming the pointer) wins and the re-adopt no-ops.
        if attempt.orphaned {
            self.readopt_orphan(attempt).await?;
        }
        // The re-enqueue applies every pass, including past the alert horizon, so a
        // recoverable transaction always gets another chance to land while the alert
        // cues the operator in parallel.
        self.re_enqueue_submit(attempt, summary).await?;
        if attempt.past_alert {
            self.alert_stranded(attempt, summary).await?;
        }
        Ok(())
    }

    /// Re-point a live record at its orphaned original so the submit path's resume
    /// preamble re-broadcasts it.
    ///
    /// Guarded on `current_attempt_id IS NULL` and the record still live, and on the
    /// attempt still being a `recorded` non-superseded original: if a cancelling
    /// replacement recorded in the meantime it has already claimed the pointer and
    /// superseded this original, so the guarded update affects zero rows and the
    /// re-adopt is a safe no-op (the replacement owns the record). Setting the pointer
    /// back makes the orphan the record's current attempt again, which the re-enqueued
    /// submit then resumes; the one-active-per-record unique index still holds because a
    /// `recorded` original is the single active broadcaster once it is re-adopted.
    async fn readopt_orphan(&self, attempt: &StrandedAttempt) -> Result<()> {
        let Some(record_id) = attempt.record_id else {
            return Ok(());
        };
        sqlx::query(
            "UPDATE cw_core.poe_record \
             SET current_attempt_id = $2 \
             WHERE id = $1 \
               AND current_attempt_id IS NULL \
               AND status IN ('submitting', 'submitted') \
               AND EXISTS ( \
                     SELECT 1 FROM cw_core.chain_attempt a \
                     WHERE a.id = $2 AND a.status = 'recorded' \
                   )",
        )
        .bind(record_id)
        .bind(attempt.id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Re-enqueue a re-broadcast for a stranded attempt, deduped so two sweep passes
    /// (or a sweep racing the steady cron) enqueue at most one job. The job is
    /// reconstructed to match the attempt's kind so the submit path resumes THIS
    /// recorded attempt and re-broadcasts the exact recorded bytes idempotently —
    /// never minting a second transaction:
    ///
    ///   - a publish/replacement re-enqueues a record-keyed [`SubmitJob`] whose resume
    ///     preamble adopts the attempt the record rides (a replacement carries its
    ///     `replacement_for` + forced inputs; a publish carries neither);
    ///   - a split has no record, so it re-enqueues an attempt-keyed
    ///     [`SplitResumeJob`] the submit handler resumes by attempt id.
    ///
    /// Both ride [`SUBMIT_QUEUE`], so they share the already-registered submit handler
    /// (which holds the gateway and the wallet lock the re-broadcast needs); the sweep
    /// itself never broadcasts.
    async fn re_enqueue_submit(
        &self,
        attempt: &StrandedAttempt,
        summary: &mut ChainRecoverSummary,
    ) -> Result<()> {
        let kind = AttemptKind::parse(&attempt.kind)?;
        // A per-subject singleton key, scoped to the recovery sweep, so two recovery
        // re-enqueues for one subject collapse to one job. It is distinct from the
        // confirm-loop's rollback enqueue (which carries no singleton key), so the
        // recovery dedupe never suppresses a legitimate cancelling replacement. A
        // split keys on its attempt id (it has no record); a record kind keys on the
        // record id.
        let enqueued = match kind {
            AttemptKind::Split => {
                let job = SplitResumeJob {
                    split_attempt_id: attempt.id,
                };
                let opts = EnqueueOptions {
                    singleton_key: Some(format!("chain_recover_split:{}", attempt.id)),
                    ..EnqueueOptions::default()
                };
                enqueue_dedupe(&self.pool, SUBMIT_QUEUE, &job, opts).await?
            }
            AttemptKind::Publish | AttemptKind::Replacement => {
                let job = self.record_submit_job_for(kind, attempt)?;
                let record_id = job.record_id;
                let opts = EnqueueOptions {
                    singleton_key: Some(format!("chain_recover:{record_id}")),
                    ..EnqueueOptions::default()
                };
                enqueue_dedupe(&self.pool, SUBMIT_QUEUE, &job, opts).await?
            }
        };
        match enqueued {
            Some(_) => summary.re_enqueued += 1,
            None => summary.already_in_flight += 1,
        }
        Ok(())
    }

    /// Reconstruct the record-keyed submit job a stranded publish/replacement
    /// attempt's resume needs, matching the kind so the resume preamble adopts THIS
    /// attempt. A split is never passed here (it has no record); the caller routes a
    /// split to a [`SplitResumeJob`].
    fn record_submit_job_for(
        &self,
        kind: AttemptKind,
        attempt: &StrandedAttempt,
    ) -> Result<SubmitJob> {
        let request_id = attempt.request_id.clone().unwrap_or_default();
        let record_id = attempt.record_id.ok_or_else(|| {
            crate::Error::Config(
                "a publish/replacement stranded attempt must carry a record".into(),
            )
        })?;
        let job = match kind {
            // A first-publish stranded attempt: a plain submit, whose resume preamble
            // resumes any current attempt the record rides (this one).
            AttemptKind::Publish => SubmitJob {
                request_id,
                record_id,
                replacement_for: None,
                forced_inputs: Vec::new(),
            },
            // A cancelling-replacement stranded attempt: the resume preamble only
            // resumes its own recorded replacement when the job is marked as a
            // replacement, so reconstruct that marking. `replaces_tx_hash` names the
            // original it cancels, and its own recorded inputs are the forced inputs a
            // rebuild (if the resume ever fell through) would re-spend.
            AttemptKind::Replacement => {
                let replaces = attempt.replaces_tx_hash.as_deref().map(hex::encode);
                let spent: Vec<AttemptInput> =
                    serde_json::from_value(attempt.spent_inputs.clone())?;
                SubmitJob {
                    request_id,
                    record_id,
                    replacement_for: replaces,
                    forced_inputs: forced_inputs_from_attempt(&spent),
                }
            }
            AttemptKind::Split => {
                return Err(crate::Error::Config(
                    "a split has no record-keyed submit job".into(),
                ));
            }
        };
        Ok(job)
    }

    /// Raise the one-shot operator alert for a stranded attempt past the alert
    /// horizon, deduped in memory so it fires once per attempt per process. The alert
    /// moves NO money and NO inputs: it surfaces the wedged record so an operator can
    /// resolve it with a cancelling replacement (the only path that produces the
    /// settlement-deep-conflict proof a refund is gated on).
    async fn alert_stranded(
        &self,
        attempt: &StrandedAttempt,
        summary: &mut ChainRecoverSummary,
    ) -> Result<()> {
        // Fire once per attempt per process. A first-seen attempt is inserted and
        // alerted; a re-seen attempt is suppressed. The singleton-loop policy keeps
        // one pass in flight, so the set is never raced.
        let first_time = self
            .alerted
            .lock()
            .expect("alerted lock")
            .insert(attempt.id);
        if !first_time {
            return Ok(());
        }
        crate::events::append_subject_event(
            &self.pool,
            CHAIN_ATTEMPT_SUBJECT_KIND,
            &attempt.id.to_string(),
            CHAIN_RECOVER_STRANDED_EVENT,
            &serde_json::json!({
                "attempt_id": attempt.id,
                "kind": attempt.kind,
                // A split carries no record; the field is null for it.
                "record_id": attempt.record_id,
                "wallet_id": attempt.wallet_id,
                "tx_hash": hex::encode(&attempt.tx_hash),
            }),
        )
        .await?;
        summary.alerted += 1;
        Ok(())
    }

    /// Drop the alerted markers for attempts no longer in the stranded set, so the
    /// set does not accumulate entries for resolved attempts and a genuine recurrence
    /// re-alerts.
    fn retain_alerted(&self, still_stranded: &[Uuid]) {
        let live: HashSet<Uuid> = still_stranded.iter().copied().collect();
        self.alerted
            .lock()
            .expect("alerted lock")
            .retain(|id| live.contains(id));
    }
}

/// The policy for the recovery-sweep queue: a singleton loop so at most one sweep
/// pass runs across the deployment at a time (which keeps the in-memory alert set
/// race-free), a small attempt budget and a short fixed backoff to ride out a
/// transient database blip (the pass is idempotent on the record id, so a retry is
/// cheap), and a lease ample for a bounded indexed scan plus a handful of enqueues.
#[must_use]
pub fn chain_recover_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        CHAIN_RECOVER_QUEUE,
        3,
        Backoff::Fixed { base_secs: 30 },
        120,
    )
}

/// The schedule that fires the recovery sweep on the configured cadence.
///
/// The `cron` expression comes from config, defaulting to
/// [`DEFAULT_CHAIN_RECOVER_SCHEDULE`]. The scheduler's `cron_tick` gate ensures
/// exactly one replica enqueues each occurrence.
#[must_use]
pub fn chain_recover_schedule(cron: impl Into<String>) -> crate::runtime::scheduler::CronSchedule {
    crate::runtime::scheduler::CronSchedule::new(
        cron.into(),
        CHAIN_RECOVER_QUEUE,
        serde_json::Value::Null,
    )
}

impl JobHandler for ChainRecoverHandler {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        match self.run_once().await {
            Ok(summary) => {
                tracing::info!(
                    re_enqueued = summary.re_enqueued,
                    already_in_flight = summary.already_in_flight,
                    alerted = summary.alerted,
                    "chain attempt-recovery sweep pass complete"
                );
                JobOutcome::Complete
            }
            Err(e) => {
                tracing::warn!(error = %e, "chain attempt-recovery sweep pass failed");
                JobOutcome::Fail {
                    error: crate::runtime::JobError::new("chain_recover_failed", e.to_string()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_is_a_single_in_flight_singleton_loop() {
        let policy = chain_recover_policy();
        assert_eq!(policy.queue, CHAIN_RECOVER_QUEUE);
        assert_eq!(policy.concurrency, 1);
    }

    #[test]
    fn the_grace_sits_above_the_submit_retry_window() {
        // The submit job runs SUBMIT_MAX_ATTEMPTS attempts at the fixed backoff, so
        // the grace must exceed that window or the sweep would race a live submit.
        let submit_window = crate::chain::submit::SUBMIT_BACKOFF_SECS
            * (crate::chain::submit::SUBMIT_MAX_ATTEMPTS as u32);
        assert!(
            DEFAULT_RECOVER_GRACE.as_secs() > u64::from(submit_window),
            "the recovery grace ({}s) must exceed the submit retry window ({}s)",
            DEFAULT_RECOVER_GRACE.as_secs(),
            submit_window,
        );
    }

    #[test]
    fn the_alert_horizon_sits_well_beyond_the_grace_and_proof_of_death() {
        // The stranded alert fires only for an attempt that resisted recovery for far
        // longer than the grace and the mempool proof-of-death, so a recoverable
        // re-broadcast is given ample time first.
        assert!(DEFAULT_RECOVER_ALERT_AFTER > DEFAULT_RECOVER_GRACE);
        assert!(
            DEFAULT_RECOVER_ALERT_AFTER
                > crate::chain::confirm::DEFAULT_MEMPOOL_PROOF_OF_DEATH_AFTER
        );
    }
}
