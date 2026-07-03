//! The two runtime handlers that drive webhook delivery.
//!
//! - The **fan-out drain** ([`FanoutHandler`]) is a singleton loop. Each pass
//!   claims un-fanned `delivery_outbox` rows as a set and, one transaction per
//!   row, explodes the row into per-subscription `webhook_delivery` rows and
//!   stamps it fanned-out. There is no cursor to advance: the mid-stream cutoff is
//!   "which subscriptions exist when this row is exploded".
//! - The **delivery worker** ([`DeliveryHandler`]) is standard-concurrency. Each
//!   pass claims due delivery rows with the frontier query (lowest pending seq per
//!   `(endpoint, subject)`, a terminal predecessor not blocking), unwraps the
//!   endpoint secret(s), signs (dual-signing inside a rotation window), and POSTs
//!   through the hardened egress. A `2xx` resets the endpoint's failure budget; a
//!   non-2xx re-schedules the row with the capped+jittered application backoff or,
//!   on exhaustion, dead-letters it (unblocking the next seq) and may auto-disable
//!   the endpoint. The worker paces itself with [`JobOutcome::Defer`] to the
//!   soonest pending due instant rather than busy-looping.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::runtime::{JobContext, JobError, JobHandler, JobOutcome};
use crate::wallet::keyring::UnlockedKeyring;
use crate::webhook::delivery::{self, ClaimedDelivery, DeliveryPolicy, FailureOutcome};
use crate::webhook::egress::{self, DeliveryError, EgressConfig};
use crate::webhook::fanout::claim_unfanned;
use crate::webhook::signer::sign_delivery;
use crate::{Error, Result};

/// The queue the fan-out drain runs on.
pub const FANOUT_QUEUE: &str = "webhook_fanout";

/// The queue the delivery worker runs on.
pub const DELIVERY_QUEUE: &str = "webhook_delivery";

/// How many outbox rows one fan-out pass claims before yielding the loop.
const FANOUT_BATCH: i64 = 64;

/// How many delivery rows one delivery pass claims per tick. Standard concurrency
/// fans several loops out across the queue, each claiming its own disjoint batch.
const DELIVERY_BATCH: i64 = 32;

/// The singleton-loop policy for the fan-out drain: at most one drain in flight, a
/// short fixed infrastructure-retry backoff (a transient DB error re-runs the
/// pass), and a lease comfortably above a pass duration.
#[must_use]
pub fn fanout_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        FANOUT_QUEUE,
        5,
        crate::runtime::Backoff::Fixed { base_secs: 5 },
        120,
    )
}

/// The standard-concurrency policy for the delivery worker. The `max_attempts` and
/// `backoff` here govern only the worker job's INFRASTRUCTURE retries (a transient
/// DB error re-running the handler); the per-delivery retry envelope is the
/// `webhook_delivery.next_attempt_at` the handler computes itself.
#[must_use]
pub fn delivery_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::standard(
        DELIVERY_QUEUE,
        5,
        crate::runtime::Backoff::Fixed { base_secs: 5 },
        120,
        4,
    )
}

/// A fallback schedule that wakes the fan-out drain periodically.
///
/// The PRIMARY wake is event-driven: appending a subject event enqueues a
/// fan-out wake inside the same transaction as the outbox row (see
/// [`wake_fanout`]), so fan-out normally runs at NOTIFY latency. This cron only
/// bounds the worst case when that wake is lost (a crash between an outbox
/// commit and the worker observing it). Correctness never depends on the
/// cadence (the drain is a set-scan).
#[must_use]
pub fn fanout_schedule() -> crate::runtime::scheduler::CronSchedule {
    crate::runtime::scheduler::CronSchedule::new("* * * * *", FANOUT_QUEUE, serde_json::Value::Null)
}

/// A fallback schedule that wakes the delivery worker periodically.
///
/// The PRIMARY wake is event-driven: a fan-out pass that materialised delivery
/// rows enqueues a delivery wake in the same transaction, so a fresh delivery
/// normally POSTs at NOTIFY latency. The handler drains everything due and
/// defers to the soonest pending instant; this cron only bounds the worst case
/// on a lost wake or a missed defer.
#[must_use]
pub fn delivery_schedule() -> crate::runtime::scheduler::CronSchedule {
    crate::runtime::scheduler::CronSchedule::new(
        "* * * * *",
        DELIVERY_QUEUE,
        serde_json::Value::Null,
    )
}

/// Wake the fan-out drain as soon as possible.
///
/// Producers call this on the connection of the SAME transaction that inserts a
/// `delivery_outbox` row (`&mut *txn`), so the wake job and the outbox row
/// become visible together and the job table's NOTIFY trigger fires the worker
/// at commit — collapsing outbox-to-fanout latency from the cron interval to
/// NOTIFY latency. Deduped to one in-flight wake via the shared wake singleton
/// key.
pub async fn wake_fanout(conn: &mut sqlx::PgConnection) -> Result<()> {
    crate::runtime::enqueue::enqueue_wake(conn, FANOUT_QUEUE).await
}

/// Wake the delivery worker as soon as possible. The fan-out drain calls this
/// on the transaction connection that materialises a batch's `webhook_delivery`
/// rows.
pub async fn wake_delivery(conn: &mut sqlx::PgConnection) -> Result<()> {
    crate::runtime::enqueue::enqueue_wake(conn, DELIVERY_QUEUE).await
}

/// The fan-out drain handler.
///
/// Holds only the pool: fan-out is a pure database operation (resolve owner, match
/// subscriptions, insert delivery rows, stamp). Register it against [`FANOUT_QUEUE`]
/// with [`fanout_policy`] and [`fanout_schedule`].
pub struct FanoutHandler {
    pool: sqlx::PgPool,
}

impl FanoutHandler {
    /// Build a fan-out handler over a pool.
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Drain the un-fanned outbox once: repeatedly claim a batch and explode each
    /// claimed row in the same transaction that holds its claim lock, stamping it
    /// fanned-out. Returns how many outbox rows were processed.
    ///
    /// One transaction spans the claim, the per-subscription inserts, and the
    /// `fanned_out_at` stamp for the whole batch. The claim takes a
    /// `FOR UPDATE SKIP LOCKED` lock that is held until this transaction commits, so
    /// the row is exploded and stamped under the same lock and the same snapshot —
    /// which is exactly what makes the mid-stream cutoff "the subscriptions live
    /// when this row is exploded". A crash before the commit rolls back both the
    /// inserts and the stamp, leaving the row un-fanned and re-claimable; the
    /// per-delivery `ON CONFLICT DO NOTHING` makes the replay idempotent.
    ///
    /// The loop terminates because every claimed row is stamped in the same
    /// transaction it is claimed in: once committed it leaves the un-fanned set, so
    /// the next claim returns a strictly smaller set and eventually empties.
    pub async fn run_once(&self) -> Result<u64> {
        let mut processed = 0u64;
        loop {
            let mut tx = self.pool.begin().await?;
            let claimed = claim_unfanned(&mut tx, FANOUT_BATCH).await?;
            if claimed.is_empty() {
                // Nothing left to fan out; end the empty transaction and stop.
                tx.rollback().await?;
                break;
            }

            for row in &claimed {
                delivery::explode_outbox_row(&self.pool, &mut tx, row).await?;
                processed += 1;
            }

            // Wake the delivery worker in the same transaction that materialises
            // the batch's delivery rows, so a fresh delivery POSTs at NOTIFY
            // latency instead of waiting for the delivery cron. A batch whose
            // rows all matched zero subscriptions wakes a no-op pass, which is
            // cheaper than detecting that case here.
            wake_delivery(&mut tx).await?;

            // Commit the whole batch's inserts and stamps together, releasing the
            // claim locks. A claimed-but-uncommitted batch (a crash here) rolls back
            // to un-fanned and is re-claimed on the next pass.
            tx.commit().await?;
        }
        Ok(processed)
    }
}

impl JobHandler for FanoutHandler {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        match self.run_once().await {
            Ok(processed) => {
                if processed > 0 {
                    tracing::debug!(processed, "webhook fan-out drained");
                }
                JobOutcome::Complete
            }
            Err(e) => {
                tracing::warn!(error = %e, "webhook fan-out pass failed");
                JobOutcome::Fail {
                    error: JobError::new("webhook_fanout_failed", e.to_string()),
                }
            }
        }
    }
}

/// The delivery worker handler.
///
/// Holds the pool, the unlocked keyring (to unwrap an endpoint secret just before
/// signing, never persisting the plaintext), the egress config (the self-host/test
/// toggles), and the delivery policy (the backoff + auto-disable budget). Register
/// it against [`DELIVERY_QUEUE`] with [`delivery_policy`] and [`delivery_schedule`].
pub struct DeliveryHandler {
    pool: sqlx::PgPool,
    keyring: Arc<UnlockedKeyring>,
    egress: EgressConfig,
    policy: DeliveryPolicy,
}

impl DeliveryHandler {
    /// Build a delivery handler.
    #[must_use]
    pub fn new(
        pool: sqlx::PgPool,
        keyring: Arc<UnlockedKeyring>,
        egress: EgressConfig,
        policy: DeliveryPolicy,
    ) -> Self {
        Self {
            pool,
            keyring,
            egress,
            policy,
        }
    }

    /// Drain the due delivery rows once and return the soonest instant a pending
    /// row becomes due again (so the worker can defer to it rather than waiting for
    /// the next cron tick), or `None` when nothing is pending.
    ///
    /// Each pass claims a batch with the frontier query, delivers each row, and
    /// records its outcome. The claim holds the row lock only for the claim
    /// transaction; the delivery itself (a blocking network POST) runs outside any
    /// transaction, and the outcome is recorded in its own short transaction.
    pub async fn run_once(&self) -> Result<Option<DateTime<Utc>>> {
        loop {
            let claimed = {
                let mut tx = self.pool.begin().await?;
                // The claim grants each returned row an exclusive POST claim-lease in
                // the same statement that locks the frontier, so the lease — not a
                // connection-held lock across the network POST — is the exclusion. A
                // concurrent worker's frontier sees the lease held and skips the row.
                let leases =
                    delivery::claim_due(&mut tx, DELIVERY_BATCH, self.policy.claim_lease).await?;
                // The claim transaction commits immediately, releasing only the
                // short-lived row locks; the lease lives on the row itself, so the
                // POST runs outside any transaction with no lock-ordering hazard.
                tx.commit().await?;
                leases
            };

            if claimed.is_empty() {
                break;
            }

            for lease in claimed {
                self.deliver_one(lease).await?;
            }
        }

        self.soonest_pending_due().await
    }

    /// Deliver one leased row: load it, sign, POST, and record the outcome under the
    /// lease token so a lost-race worker performs no second state write.
    async fn deliver_one(&self, lease: delivery::ClaimedLease) -> Result<()> {
        let Some(claimed) = delivery::load_for_delivery(&self.pool, lease.id).await? else {
            // The row vanished between the claim and the load (a soft-delete cascade).
            return Ok(());
        };

        let secrets = self.unwrap_secrets(&claimed)?;
        if secrets.is_empty() {
            // The wrap key the secret was sealed under is not held by this instance,
            // so it cannot be signed here. This is a LOCAL custody gap, not a delivery
            // failure: the endpoint and its receiver are fine. Release the lease and
            // re-arm the row for a later retry WITHOUT consuming the attempt budget or
            // feeding the auto-disable accumulator, so a key-holding replica claims it
            // — never burn attempts or auto-disable a live endpoint because this
            // replica happens to lack the key.
            delivery::release_for_custody_retry(
                &self.pool,
                lease.id,
                lease.claim_token,
                &self.policy,
            )
            .await?;
            return Ok(());
        }

        let body = serde_json::to_vec(&claimed.body)?;
        let timestamp = Utc::now().timestamp();
        let headers = sign_delivery(&claimed.dedupe_key, timestamp, &body, &secrets);

        // The egress is blocking (it drives the SDK's blocking pinned transport), so
        // run it on a blocking task to keep the async worker loop free.
        let url = claimed.url.clone();
        let header_pairs = headers.to_pairs();
        let body_owned = body.clone();
        let egress_config = self.egress;
        let result = tokio::task::spawn_blocking(move || {
            egress::deliver(&url, &body_owned, &header_pairs, egress_config)
        })
        .await
        .map_err(|e| Error::Config(format!("webhook delivery task join error: {e}")))?;

        self.record_outcome(&lease, result).await
    }

    /// Record the outcome of one delivery attempt under its lease token.
    async fn record_outcome(
        &self,
        lease: &delivery::ClaimedLease,
        result: std::result::Result<egress::DeliveryResponse, DeliveryError>,
    ) -> Result<()> {
        match result {
            Ok(response) if response.is_success() => {
                delivery::record_success(&self.pool, lease.id, lease.claim_token, response.status)
                    .await?;
            }
            Ok(response) => {
                // A non-2xx is a transient failure: the receiver is reachable but
                // not acknowledging. Retry with backoff or dead-letter on exhaustion.
                self.record_failure(lease, Some(response.status), "non-2xx delivery status")
                    .await?;
            }
            Err(DeliveryError::Refused(e)) => {
                // The URL was validated at registration; a refusal here means its
                // resolution changed (DNS now points at a blocked range) or the
                // scheme is no longer allowed. Treat as a transient failure with no
                // HTTP status so it retries and eventually dead-letters/auto-disables.
                self.record_failure(lease, None, &format!("egress refused: {e}"))
                    .await?;
            }
            Err(DeliveryError::Transport(detail)) => {
                self.record_failure(lease, None, &format!("transport error: {detail}"))
                    .await?;
            }
        }
        Ok(())
    }

    /// Record a failed attempt under its lease and log a dead-letter on exhaustion.
    async fn record_failure(
        &self,
        lease: &delivery::ClaimedLease,
        status: Option<u16>,
        error: &str,
    ) -> Result<()> {
        match delivery::record_failure(
            &self.pool,
            lease.id,
            lease.claim_token,
            status,
            error,
            &self.policy,
        )
        .await?
        {
            FailureOutcome::Retry { .. } => {}
            FailureOutcome::Exhausted => {
                tracing::info!(
                    delivery_id = %lease.id,
                    "webhook delivery exhausted attempts and is now a dead-letter"
                );
            }
        }
        Ok(())
    }

    /// Unwrap the active (and rotation-successor, when present) endpoint secret(s)
    /// into plaintext signing keys, resolving the wrap key by the row's
    /// `wrap_key_id`.
    ///
    /// Returns an empty vec when this instance does not hold the wrap key (the
    /// caller treats that as "retry elsewhere"). Each plaintext stays in the
    /// zeroizing buffer `SecretWrap::open` decrypted it into for its whole
    /// lifetime — the signer only borrows the bytes — so the secret is wiped when
    /// the delivery drops it and never lingers in an ordinary heap allocation.
    fn unwrap_secrets(&self, claimed: &ClaimedDelivery) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        let Some(wrap_key) = self.keyring.webhook_wrap_key(&claimed.wrap_key_id) else {
            return Ok(Vec::new());
        };
        let wrap = wrap_key.secret_wrap();

        let mut secrets = Vec::with_capacity(2);
        // The primary always signs.
        secrets.push(wrap.open(&claimed.secret_enc)?);
        // The rotation successor signs too while a window is open, so a receiver
        // that has deployed either secret validates the delivery.
        if let Some(next_enc) = &claimed.secret_next_enc {
            secrets.push(wrap.open(next_enc)?);
        }
        Ok(secrets)
    }

    /// The soonest `next_attempt_at` among pending deliveries whose endpoint is
    /// active, or `None` when nothing is pending. Drives the self-pacing defer.
    async fn soonest_pending_due(&self) -> Result<Option<DateTime<Utc>>> {
        let soonest: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT min(d.next_attempt_at) \
             FROM cw_core.webhook_delivery d \
             JOIN cw_core.webhook_endpoint e ON e.id = d.endpoint_id \
             WHERE d.state = 'pending' AND e.status = 'active' AND e.deleted_at IS NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(soonest)
    }
}

impl JobHandler for DeliveryHandler {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        match self.run_once().await {
            Ok(Some(next_due)) => {
                // Pending work remains: defer to the soonest due instant so the
                // worker wakes exactly when the next delivery is ready, without
                // consuming a job attempt. A due-in-the-past instant (a row already
                // due this pass that another loop is handling) clamps to a short
                // delay so the defer always moves forward.
                let until = next_due.max(Utc::now() + chrono::Duration::seconds(1));
                JobOutcome::Defer { until }
            }
            // Nothing pending: complete this job; the next NOTIFY/cron tick re-arms
            // the worker when a fresh delivery is fanned out.
            Ok(None) => JobOutcome::Complete,
            Err(e) => {
                tracing::warn!(error = %e, "webhook delivery pass failed");
                JobOutcome::Fail {
                    error: JobError::new("webhook_delivery_failed", e.to_string()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanout_policy_is_a_singleton_loop() {
        let policy = fanout_policy();
        assert_eq!(policy.queue, FANOUT_QUEUE);
        assert_eq!(
            policy.policy,
            crate::runtime::policy::QueuePolicyKind::SingletonLoop
        );
    }

    #[test]
    fn delivery_policy_is_standard_concurrency() {
        let policy = delivery_policy();
        assert_eq!(policy.queue, DELIVERY_QUEUE);
        assert_eq!(
            policy.policy,
            crate::runtime::policy::QueuePolicyKind::Standard
        );
        assert!(policy.concurrency >= 1);
    }

    #[test]
    fn schedules_target_their_queues() {
        assert_eq!(fanout_schedule().queue, FANOUT_QUEUE);
        assert_eq!(delivery_schedule().queue, DELIVERY_QUEUE);
    }
}
