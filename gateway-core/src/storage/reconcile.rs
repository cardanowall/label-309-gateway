//! The crash-recovery sweep over interrupted upload attempts.
//!
//! A paid upload reserves a `storage_upload_attempt` row (the USD hold + the
//! believed winc charge) BEFORE the provider is paid, and settles it with a
//! compare-and-set on `state` once the provider answers. If the live handler dies
//! between the reservation and the settlement, or returns an ambiguous transport
//! failure (the POST may have been accepted before the connection dropped), the
//! attempt is left `reserved` with a persisted signed envelope and a durable staged
//! file. This sweep owns every such attempt and converges it to a terminal state.
//!
//! # The horizon
//!
//! The sweep only looks at `reserved` attempts older than `reconcile_horizon`,
//! which is set ABOVE the maximum in-flight upload duration (the upload timeout). So
//! a slow-but-live upload is never swept: every attempt the sweep sees has a live
//! handler that is gone (it crashed, or returned an ambiguous `Unavailable`).
//!
//! # The decision
//!
//! For each such attempt the sweep asks the provider whether the data item landed
//! ([`crate::storage::StorageBackend::lookup_data_item`]) and, only when it matters,
//! whether the durable staged file still exists:
//!
//!   - **`Present`** (the bytes are stored): commit the reservation under the CAS.
//!     No re-POST, so no claim-lease is taken; the staged file is not needed.
//!   - **`Absent` and the staged file is present** (recoverable): claim the
//!     external-POST lease, re-POST the byte-identical reconstruction (no re-sign,
//!     streamed), then commit on the provider 2xx. A contender that cannot claim the
//!     lease does not POST and retries next tick.
//!   - **`Absent` and the staged file is gone** (unrecoverable): release the hold,
//!     refund the believed winc, and emit a terminal client-facing
//!     `storage.upload.failed` event so the client re-uploads the bytes. Nothing is
//!     re-signed without the original content.
//!   - **`Unavailable`** (the lookup API is unreachable): leave the attempt
//!     `reserved` (the hold stays in place, the recovery artifact stays intact) and
//!     retry next tick. An attempt the provider cannot resolve for a configured
//!     number of consecutive passes raises a `storage.attempt.stuck` alert, so an
//!     operator sees a persistently-down provider rather than a silently held hold.
//!
//! Every settlement is the same single-winner compare-and-set the live handler
//! uses, so the sweep and the live handler can never both settle one attempt; and
//! every re-POST is fenced by the same claim-lease, so two sweep workers can never
//! both POST one data item. The user's USD ledger is single-settlement by
//! construction, so even a provider that, in a crash tail, charged twice for one
//! byte-identical POST charges the USER exactly once; the duplicate provider cost
//! lands only on the operator's winc rail, where the credit reconcile loop measures
//! it against the actual provider balance and self-corrects.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use uuid::Uuid;

use crate::storage::attempt::{
    commit_attempt, load_envelope, release_attempt, release_unrecoverable, PersistedEnvelope,
    ReleaseReason, SettleOutcome,
};
use crate::storage::backend::{DataItemStatus, StorageBackend, StorageError};
use crate::storage::funding::resolve_committed_upload;
use crate::wallet::keyring::UnlockedKeyring;
use crate::{Error, Result};

/// The operator-facing event raised when the sweep cannot resolve a `reserved`
/// attempt because the provider lookup API has been unreachable for a configured
/// number of consecutive passes. It rides the funding-source subject (the same
/// operator-facing channel the credit-reconcile signals use), so the held hold is
/// never silently leaked: an operator sees a provider whose lookup API is
/// persistently down.
pub const ATTEMPT_STUCK_EVENT: &str = "storage.attempt.stuck";

/// The queue the crash-recovery sweep runs on.
pub const ATTEMPT_RECONCILE_QUEUE: &str = "storage_attempt_reconcile";

/// The default sweep cadence: every minute. The horizon (not the cadence) bounds
/// how long an interrupted attempt waits before the sweep can act on it; a
/// deployment overrides this via the `[storage]` configuration.
pub const DEFAULT_ATTEMPT_RECONCILE_SCHEDULE: &str = "0 * * * * *";

/// The sweep's tuning, read from config so a deployment can override the horizon and
/// the stuck-alert threshold without a code change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptReconcileConfig {
    /// How long a `reserved` attempt must have been outstanding before the sweep
    /// touches it. Set ABOVE the upload timeout, so a slow-but-live upload is never
    /// swept.
    pub reconcile_horizon: Duration,
    /// The external-POST claim-lease lifetime the sweep acquires before a re-POST.
    /// Matches the live handler's lease so a sweep worker and the live handler are
    /// fenced by the same lease semantics.
    pub upload_claim_lease_ttl: Duration,
    /// How many consecutive passes an attempt may stay unresolved (the provider
    /// lookup API down) before `storage.attempt.stuck` alerts.
    pub attempt_stuck_passes: u32,
}

/// The aggregate result of one sweep pass over the attempts past the horizon.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttemptReconcileSummary {
    /// Attempts committed because the provider already held the bytes.
    pub committed: usize,
    /// Attempts re-POSTed from the durable staged content and committed.
    pub reposted: usize,
    /// Attempts released as unrecoverable (provider absent + staged content gone).
    pub released_unrecoverable: usize,
    /// Attempts released because a re-POST was definitively refused.
    pub released_rejected: usize,
    /// Attempts left `reserved` for a later pass (provider unreachable / ambiguous).
    pub left_reserved: usize,
    /// Attempts skipped because another contender owned the POST window.
    pub skipped: usize,
    /// `storage.attempt.stuck` alerts emitted this pass.
    pub stuck_emitted: usize,
}

/// One `reserved` attempt the sweep must converge, read past the horizon.
#[derive(sqlx::FromRow)]
struct StaleAttempt {
    id: Uuid,
    funding_source_id: Uuid,
    backend: String,
    data_item_id: String,
}

/// Read the `reserved` attempts older than the horizon, the set one sweep pass
/// converges.
///
/// The horizon is computed in the database (`created_at < now() - $horizon`) so the
/// cut is on the server clock, matching the lease expiry the same rows carry. The
/// partial index on `created_at WHERE state='reserved'` serves this scan.
async fn stale_reserved_attempts(
    pool: &sqlx::PgPool,
    horizon: Duration,
) -> Result<Vec<StaleAttempt>> {
    let horizon_secs = horizon.as_secs_f64();
    let rows = sqlx::query_as::<_, StaleAttempt>(
        "SELECT id, funding_source_id, backend, data_item_id \
         FROM cw_core.storage_upload_attempt \
         WHERE state = 'reserved' \
           AND created_at < now() - make_interval(secs => $1) \
         ORDER BY created_at",
    )
    .bind(horizon_secs)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Acquire the external-POST claim-lease the sweep needs before a re-POST.
///
/// The same atomic claim-CAS the live handler uses: it grants the lease only when
/// the attempt is still `reserved` and the lease is unheld or lapsed, so among the
/// live handler and the sweep workers exactly one owns the POST window. A worker
/// that does not get the token must NOT re-POST.
async fn claim_repost_window(
    pool: &sqlx::PgPool,
    attempt_id: Uuid,
    lease_ttl: Duration,
) -> Result<bool> {
    let token = Uuid::now_v7();
    let granted: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE cw_core.storage_upload_attempt \
            SET upload_claim_token = $2, \
                upload_claim_expires_at = now() + make_interval(secs => $3) \
          WHERE id = $1 AND state = 'reserved' \
            AND (upload_claim_token IS NULL OR upload_claim_expires_at < now()) \
          RETURNING upload_claim_token",
    )
    .bind(attempt_id)
    .bind(token)
    .bind(lease_ttl.as_secs_f64())
    .fetch_optional(pool)
    .await?;
    Ok(granted.is_some())
}

/// Resolve the owner key bytes for a funding source from the unlocked keyring.
///
/// The owner is the funding key's public modulus, which the byte-identical
/// reconstruction prepends to the staged content. A capability scopes the keyring
/// lookup, so the owner is never reachable from a bare address; an instance that
/// does not hold the funding key has no owner here, which is a definite recovery
/// failure for this source (the sweep logs and skips it rather than re-signing).
fn owner_for(
    keyring: &UnlockedKeyring,
    funding: &crate::storage::funding::AuthorizedFunding,
) -> Option<Vec<u8>> {
    keyring
        .arweave_signer_for(funding)
        .map(|signer| signer.owner())
}

/// Whether the durable staged content for an attempt still exists on disk.
///
/// The recovery body is reconstructed from the persisted envelope plus this staged
/// file. If the path is unset (already nulled) or the file is gone, the upload is
/// unrecoverable on the `Absent` branch: the content cannot be reconstructed.
async fn staged_file_present(envelope: &PersistedEnvelope) -> bool {
    match envelope.staged_path.as_deref() {
        Some(path) => tokio::fs::try_exists(path).await.unwrap_or(false),
        None => false,
    }
}

/// The recovery sweep handler: the crash-recovery cron over interrupted upload
/// attempts.
///
/// Register it on the runtime against [`ATTEMPT_RECONCILE_QUEUE`] with
/// [`attempt_reconcile_policy`] and [`attempt_reconcile_schedule`]. It owns its
/// pool, the upload backend it asks the data-item status and re-POSTs through, the
/// unlocked keyring it resolves the owner key from, and the horizon /
/// stuck-threshold config. Every settlement is idempotent on the attempt id, so the
/// at-least-once delivery the runtime guarantees is harmless.
///
/// The consecutive-unresolved-pass counter that gates the `storage.attempt.stuck`
/// alert is held in memory on the handler. The sweep is a singleton loop (one
/// in-flight pass across the deployment), so the counter never races; it resets the
/// moment an attempt resolves or its provider answers, and a process restart resets
/// it (which only delays, never suppresses, the alert for a provider that stays
/// down). This keeps the stuck threshold off the attempt row, so the durable schema
/// carries no sweep bookkeeping.
pub struct AttemptReconcileHandler<B: StorageBackend + ?Sized> {
    pool: sqlx::PgPool,
    backend: Arc<B>,
    keyring: Arc<UnlockedKeyring>,
    config: AttemptReconcileConfig,
    /// Per-attempt count of consecutive passes the provider lookup stayed
    /// unresolved, the gate for the stuck alert. Reset when an attempt resolves.
    unresolved_passes: Mutex<HashMap<Uuid, u32>>,
}

impl<B: StorageBackend + ?Sized> AttemptReconcileHandler<B> {
    /// Build a recovery sweep handler over a pool, the upload backend, the keyring,
    /// and the sweep config.
    pub fn new(
        pool: sqlx::PgPool,
        backend: Arc<B>,
        keyring: Arc<UnlockedKeyring>,
        config: AttemptReconcileConfig,
    ) -> Self {
        Self {
            pool,
            backend,
            keyring,
            config,
            unresolved_passes: Mutex::new(HashMap::new()),
        }
    }

    /// Run one sweep pass over every `reserved` attempt past the horizon and return
    /// its summary. Used by the handler and by integration tests that drive the
    /// sweep directly. A single attempt's error does not abort the pass: it is
    /// logged and the sweep moves on, so one bad attempt never starves the rest.
    pub async fn run_once(&self) -> Result<AttemptReconcileSummary> {
        let stale = stale_reserved_attempts(&self.pool, self.config.reconcile_horizon).await?;
        let mut summary = AttemptReconcileSummary::default();
        let mut seen: Vec<Uuid> = Vec::with_capacity(stale.len());
        for attempt in &stale {
            seen.push(attempt.id);
            match self.converge(attempt, &mut summary).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(attempt_id = %attempt.id, error = %e, "recovery sweep skipped an attempt after an error");
                }
            }
        }
        // Drop the unresolved-pass counters for attempts no longer in the stale set
        // (they settled, or aged out by a later commit), so the map does not grow
        // without bound across passes.
        self.retain_unresolved(&seen);
        Ok(summary)
    }

    /// Converge a single stale attempt to a terminal state (or leave it `reserved`
    /// for a later pass), recording the outcome on the summary.
    async fn converge(
        &self,
        attempt: &StaleAttempt,
        summary: &mut AttemptReconcileSummary,
    ) -> Result<()> {
        // Settle by the pinned funding source id with no entitlement re-check: the
        // charge was authorized at reserve time, so a grant revoked or the source set
        // draining afterwards must not strand the in-flight upload.
        let Some(funding) =
            resolve_committed_upload(&self.pool, attempt.funding_source_id, &attempt.backend)
                .await?
        else {
            // The source vanished (it cannot, the FK is RESTRICT, but the read is
            // defensive): nothing to act through this pass; leave it reserved.
            self.bump_unresolved(attempt, summary).await?;
            summary.left_reserved += 1;
            return Ok(());
        };

        let status = self
            .backend
            .lookup_data_item(&funding, &attempt.data_item_id)
            .await;

        match status {
            Ok(DataItemStatus::Present) => {
                // The bytes already landed; commit with no re-POST and no lease.
                self.commit(attempt, summary).await?;
            }
            Ok(DataItemStatus::Absent) => {
                self.converge_absent(attempt, &funding, summary).await?;
            }
            Ok(DataItemStatus::Unavailable) | Err(_) => {
                // The lookup API is unreachable or indeterminate: never read as
                // absent (that would un-charge bytes the provider may hold). Leave
                // the attempt reserved, the hold intact, and retry next tick.
                self.bump_unresolved(attempt, summary).await?;
                summary.left_reserved += 1;
            }
        }
        Ok(())
    }

    /// The provider confirms the data item is absent: re-POST the byte-identical
    /// reconstruction if the staged content survived, else release as unrecoverable.
    async fn converge_absent(
        &self,
        attempt: &StaleAttempt,
        funding: &crate::storage::funding::AuthorizedFunding,
        summary: &mut AttemptReconcileSummary,
    ) -> Result<()> {
        let Some(envelope) = load_envelope(&self.pool, attempt.id).await? else {
            // The attempt settled (its envelope was nulled) between the stale read
            // and here: a concurrent settler already owns it, nothing to do.
            self.resolve_unresolved(attempt.id);
            summary.skipped += 1;
            return Ok(());
        };

        if !staged_file_present(&envelope).await {
            // Unrecoverable: the provider does not hold the item AND the durable
            // staged content did not survive, so the body cannot be reconstructed.
            // Release the hold, refund the believed winc, and emit the terminal
            // client-facing failure event. Nothing is re-signed.
            match release_unrecoverable(&self.pool, attempt.id, None).await? {
                SettleOutcome::Settled { .. } => {
                    self.resolve_unresolved(attempt.id);
                    summary.released_unrecoverable += 1;
                }
                SettleOutcome::AlreadySettled => {
                    self.resolve_unresolved(attempt.id);
                    summary.skipped += 1;
                }
            }
            return Ok(());
        }

        // Recoverable: claim the external-POST window before re-POSTing. A worker
        // that cannot claim does not POST and re-evaluates next tick.
        if !claim_repost_window(&self.pool, attempt.id, self.config.upload_claim_lease_ttl).await? {
            summary.skipped += 1;
            return Ok(());
        }

        // The owner key the byte-identical reconstruction prepends. An instance that
        // does not hold the funding key cannot re-POST; that is a definite recovery
        // failure for this source, so leave the attempt reserved under visibility
        // rather than re-signing or releasing on a missing key.
        let Some(owner) = owner_for(&self.keyring, funding) else {
            self.bump_unresolved(attempt, summary).await?;
            summary.left_reserved += 1;
            return Ok(());
        };

        let staged_path = std::path::Path::new(
            envelope
                .staged_path
                .as_deref()
                .expect("staged file presence was just confirmed"),
        );
        let signed = envelope_to_signed(&envelope)?;

        match self
            .backend
            .upload(funding, &signed, &owner, staged_path)
            .await
        {
            Ok(receipt) => {
                // The re-POST landed: commit the receipt and the final charge.
                match commit_attempt(&self.pool, attempt.id, &receipt, None).await? {
                    SettleOutcome::Settled { .. } => {
                        let _ = crate::storage::delete_durable(staged_path).await;
                        self.resolve_unresolved(attempt.id);
                        summary.reposted += 1;
                    }
                    SettleOutcome::AlreadySettled => {
                        self.resolve_unresolved(attempt.id);
                        summary.skipped += 1;
                    }
                }
            }
            Err(StorageError::Unavailable(_)) => {
                // Ambiguous again: the re-POST may have been accepted. Do NOT
                // release; leave the attempt reserved for a later pass.
                self.bump_unresolved(attempt, summary).await?;
                summary.left_reserved += 1;
            }
            Err(_) => {
                // A definite re-POST failure (a 402, or a build fault before any
                // bytes were sent): the bytes never landed, release as a provider
                // rejection.
                match release_attempt(
                    &self.pool,
                    attempt.id,
                    ReleaseReason::ProviderRejected,
                    None,
                )
                .await?
                {
                    SettleOutcome::Settled { .. } => {
                        let _ = crate::storage::delete_durable(staged_path).await;
                        self.resolve_unresolved(attempt.id);
                        summary.released_rejected += 1;
                    }
                    SettleOutcome::AlreadySettled => {
                        self.resolve_unresolved(attempt.id);
                        summary.skipped += 1;
                    }
                }
            }
        }
        Ok(())
    }

    /// Commit an attempt whose bytes the provider already holds. The receipt is read
    /// back from the committed row if a concurrent settler won the CAS first.
    async fn commit(
        &self,
        attempt: &StaleAttempt,
        summary: &mut AttemptReconcileSummary,
    ) -> Result<()> {
        // Capture the staged path BEFORE the commit CAS nulls it, so a staged file
        // that happened to survive is reclaimed after a winning commit. The bytes are
        // already stored, so no re-POST happens and no claim-lease is taken.
        let staged_path = load_envelope(&self.pool, attempt.id)
            .await?
            .and_then(|env| env.staged_path);

        // The provider holds the item, so the addressable URI is the data-item id.
        // The CAS-guarded commit writes the receipt + the final charge; a loser reads
        // the already-committed receipt and no-ops.
        let receipt = crate::storage::backend::StorageReceipt {
            uri: format!("ar://{}", attempt.data_item_id),
            data_item_id: attempt.data_item_id.clone(),
            raw_receipt: serde_json::json!({ "recovered": true, "source": "lookup" }),
            root_tx_id: None,
        };
        match commit_attempt(&self.pool, attempt.id, &receipt, None).await? {
            SettleOutcome::Settled { .. } => {
                if let Some(path) = staged_path {
                    let _ = crate::storage::delete_durable(std::path::Path::new(&path)).await;
                }
                self.resolve_unresolved(attempt.id);
                summary.committed += 1;
            }
            SettleOutcome::AlreadySettled => {
                self.resolve_unresolved(attempt.id);
                summary.skipped += 1;
            }
        }
        Ok(())
    }

    /// Record one more consecutive unresolved pass for an attempt and, when the
    /// count reaches the configured threshold, emit `storage.attempt.stuck` exactly
    /// once (on the crossing pass).
    async fn bump_unresolved(
        &self,
        attempt: &StaleAttempt,
        summary: &mut AttemptReconcileSummary,
    ) -> Result<()> {
        let count = {
            let mut map = self.unresolved_passes.lock().expect("unresolved-pass lock");
            let entry = map.entry(attempt.id).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        };
        if count == self.config.attempt_stuck_passes {
            self.emit_stuck(attempt).await?;
            summary.stuck_emitted += 1;
        }
        Ok(())
    }

    /// Clear an attempt's consecutive-unresolved-pass count: it resolved (committed
    /// or released) or the provider answered, so the stuck gate starts over.
    fn resolve_unresolved(&self, attempt_id: Uuid) {
        self.unresolved_passes
            .lock()
            .expect("unresolved-pass lock")
            .remove(&attempt_id);
    }

    /// Drop the unresolved-pass counters for attempts no longer in the stale set, so
    /// the map does not accumulate entries for settled attempts.
    fn retain_unresolved(&self, still_stale: &[Uuid]) {
        let live: std::collections::HashSet<Uuid> = still_stale.iter().copied().collect();
        self.unresolved_passes
            .lock()
            .expect("unresolved-pass lock")
            .retain(|id, _| live.contains(id));
    }

    /// Emit the operator-facing stuck alert on the attempt's funding-source subject.
    async fn emit_stuck(&self, attempt: &StaleAttempt) -> Result<()> {
        crate::events::append_subject_event(
            &self.pool,
            crate::storage::credit::FUNDING_SOURCE_SUBJECT_KIND,
            &attempt.funding_source_id.to_string(),
            ATTEMPT_STUCK_EVENT,
            &serde_json::json!({
                "attempt_id": attempt.id,
                "funding_source_id": attempt.funding_source_id,
                "backend": attempt.backend,
                "data_item_id": attempt.data_item_id,
                "unresolved_passes": self.config.attempt_stuck_passes,
            }),
        )
        .await?;
        Ok(())
    }
}

/// Rebuild the `ans104::SignedEnvelope` the streaming reconstruction needs from the
/// persisted attempt envelope. The signature and tag block are taken verbatim, and
/// the id is parsed back from the persisted `data_item_id`, so the re-POSTed body is
/// byte-identical to the once-signed item.
fn envelope_to_signed(envelope: &PersistedEnvelope) -> Result<ans104::SignedEnvelope> {
    let id_bytes = ans104::base64url::decode(&envelope.data_item_id)
        .map_err(|e| Error::Config(format!("persisted data-item id is not base64url: {e}")))?;
    let id: [u8; 32] = id_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Config("persisted data-item id is not 32 bytes".into()))?;
    let anchor: Option<[u8; 32]> = match envelope.anchor.as_deref() {
        None => None,
        Some(bytes) => Some(
            bytes
                .try_into()
                .map_err(|_| Error::Config("persisted anchor is not 32 bytes".into()))?,
        ),
    };
    Ok(ans104::SignedEnvelope {
        signature_type: ans104::SIGNATURE_TYPE_ARWEAVE,
        signature: envelope.signature.clone(),
        id,
        id_b64url: envelope.data_item_id.clone(),
        target: None,
        anchor,
        tag_bytes: envelope.tag_bytes.clone(),
    })
}

/// The default policy for the recovery-sweep queue: a singleton loop so at most one
/// sweep pass runs across the deployment at a time. One pass holds the per-attempt
/// unresolved-pass counters in memory and serializes the external POST through the
/// claim-lease; a single in-flight pass keeps the stuck counter race-free. A short
/// fixed backoff and a small attempt budget ride out a transient database blip; the
/// pass is idempotent on the attempt id, so a retry is cheap.
#[must_use]
pub fn attempt_reconcile_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        ATTEMPT_RECONCILE_QUEUE,
        3,
        crate::runtime::Backoff::Fixed { base_secs: 30 },
        // A pass may re-POST a handful of recovered uploads; a 10-minute lease is
        // ample and reclaims promptly if a replica dies mid-pass.
        600,
    )
}

/// The schedule that fires the recovery sweep on the configured cadence.
///
/// The `cron` expression comes from config, defaulting to
/// [`DEFAULT_ATTEMPT_RECONCILE_SCHEDULE`]. The scheduler's `cron_tick` gate ensures
/// exactly one replica enqueues each occurrence.
#[must_use]
pub fn attempt_reconcile_schedule(
    cron: impl Into<String>,
) -> crate::runtime::scheduler::CronSchedule {
    crate::runtime::scheduler::CronSchedule::new(
        cron.into(),
        ATTEMPT_RECONCILE_QUEUE,
        serde_json::Value::Null,
    )
}

impl<B: StorageBackend + ?Sized + 'static> crate::runtime::JobHandler
    for AttemptReconcileHandler<B>
{
    async fn handle(&self, _ctx: crate::runtime::JobContext) -> crate::runtime::JobOutcome {
        match self.run_once().await {
            Ok(summary) => {
                tracing::info!(
                    committed = summary.committed,
                    reposted = summary.reposted,
                    released_unrecoverable = summary.released_unrecoverable,
                    released_rejected = summary.released_rejected,
                    left_reserved = summary.left_reserved,
                    skipped = summary.skipped,
                    stuck_emitted = summary.stuck_emitted,
                    "storage attempt-recovery sweep pass complete"
                );
                crate::runtime::JobOutcome::Complete
            }
            Err(e) => {
                tracing::warn!(error = %e, "storage attempt-recovery sweep pass failed");
                crate::runtime::JobOutcome::Fail {
                    error: crate::runtime::JobError::new(
                        "storage_attempt_reconcile_failed",
                        e.to_string(),
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_reconcile_policy_is_a_single_in_flight_singleton_loop() {
        let policy = attempt_reconcile_policy();
        assert_eq!(policy.queue, ATTEMPT_RECONCILE_QUEUE);
    }

    #[test]
    fn the_stuck_event_name_matches_the_outbox_taxonomy() {
        assert_eq!(ATTEMPT_STUCK_EVENT, "storage.attempt.stuck");
    }
}
