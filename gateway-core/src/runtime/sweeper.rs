//! The reclaim sweeper.
//!
//! A running job whose heartbeat is older than its queue's lease is assumed
//! abandoned (the worker died, hung, or partitioned). The sweeper re-avails it:
//! `state='available'`, `claim_token=NULL`, `run_at=now()`. `attempts` is left
//! UNCHANGED because the claim that started the attempt already counted it; the
//! reclaimed job simply gets its remaining attempts. This is the source of the
//! engine's at-least-once semantics, which is why handlers must be idempotent.

use crate::Result;

/// Outcome of one sweep pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    /// Number of expired-lease jobs re-availed this pass.
    pub reclaimed: u64,
}

/// Run a single reclaim pass across all queues.
///
/// Each queue's lease comes from its `queue_policy.lease_secs`; a running job is
/// reclaimed when `heartbeat_at < now() - lease`. Implemented as one
/// set-returning UPDATE joined against the policy table so per-queue leases are
/// honored in a single statement.
///
/// The claim token is cleared so the original worker's next fenced write no-ops
/// (it has lost ownership). `attempts` is deliberately not touched: reclaiming a
/// lapsed lease is not a new attempt, it is the same attempt being retried by a
/// fresh claimant, so the attempt budget is not double-charged. A job with no
/// heartbeat yet (claimed but the first heartbeat never landed) is also
/// reclaimable once `started_at` is older than the lease, so a worker that dies
/// immediately after claiming cannot strand the row.
pub async fn sweep_once(pool: &sqlx::PgPool) -> Result<SweepReport> {
    let reclaimed = sqlx::query(
        "UPDATE cw_core.job j SET \
            state = 'available', \
            run_at = now(), \
            claim_token = NULL, \
            claimed_by = NULL, \
            heartbeat_at = NULL \
         FROM cw_core.queue_policy qp \
         WHERE j.queue = qp.queue \
           AND j.state = 'running' \
           AND COALESCE(j.heartbeat_at, j.started_at) \
               < now() - make_interval(secs => qp.lease_secs)",
    )
    .execute(pool)
    .await?
    .rows_affected();

    Ok(SweepReport { reclaimed })
}

/// Run the sweeper on an interval until `shutdown` resolves.
///
/// The interval only bounds how promptly a lapsed lease is noticed; correctness
/// rests on the lease itself, so a coarse cadence is fine. Shutdown is honored
/// between passes and while waiting on the tick.
pub async fn run_sweeper(
    pool: sqlx::PgPool,
    interval: std::time::Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        tokio::select! {
            _ = ticker.tick() => {
                match sweep_once(&pool).await {
                    Ok(report) if report.reclaimed > 0 => {
                        tracing::info!(reclaimed = report.reclaimed, "sweeper reclaimed expired-lease jobs");
                    }
                    Ok(_) => {}
                    Err(err) => {
                        // A transient sweep failure must not kill the loop: the
                        // next tick retries. Log and continue.
                        tracing::warn!(error = %err, "sweep pass failed; retrying next tick");
                    }
                }
            }
            res = shutdown.changed() => {
                // Sender dropped or signalled: stop sweeping.
                if res.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}
