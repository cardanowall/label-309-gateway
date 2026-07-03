//! Binary-side handler adapters.
//!
//! Two pieces of wiring live here rather than in the engine library because they
//! only make sense once a concrete provider is chosen at deploy time:
//!
//! - [`GatewaySubmitter`] adapts a [`ChainGateway`] into the narrower
//!   [`Submitter`] seam the wallet replenisher builds against, so the replenish
//!   split transaction is submitted through the very same provider the publish
//!   path submits through (one network endpoint, one credential, one failover
//!   policy), instead of needing a second submission client.
//! - [`LeaseReaperHandler`] turns the engine's expired-lease reclaim function
//!   into a scheduled job so stale submit leases are returned to the available
//!   pool on a cadence rather than only when a caller happens to invoke the
//!   reaper.

use std::sync::Arc;

use gateway_core::chain::gateway::ChainGateway;
use gateway_core::runtime::{JobContext, JobError, JobHandler, JobOutcome};
use gateway_core::wallet::submitter::{SubmitOutcome, Submitter};
use gateway_core::wallet::utxo::reap_expired_leases;

/// Adapts a [`ChainGateway`] into a [`Submitter`].
///
/// The wallet replenisher submits its split transaction through a [`Submitter`];
/// the publish path submits through a [`ChainGateway`]. Both go to the same
/// provider, so rather than maintain two submission clients this wraps the
/// gateway and forwards [`Submitter::submit`] to [`ChainGateway::submit_tx`].
///
/// The two seams differ only in how they report a transport failure. The gateway
/// returns a flat error; the [`Submitter`] contract distinguishes a definitive
/// rejection (the input was *not* consumed, the lease may be released) from an
/// ambiguous outcome (the input *may* have been consumed, the holder must
/// re-query before releasing). A bare transport error cannot prove the
/// transaction never reached the mempool, so it is mapped to the conservative
/// [`SubmitOutcome::Ambiguous`]: never release a lease on a maybe.
pub struct GatewaySubmitter<G> {
    gateway: Arc<G>,
}

impl<G> GatewaySubmitter<G> {
    /// Wrap a shared gateway as a submitter.
    #[must_use]
    pub fn new(gateway: Arc<G>) -> Self {
        Self { gateway }
    }
}

impl<G: ChainGateway> Submitter for GatewaySubmitter<G> {
    async fn submit(
        &self,
        signed_tx: &[u8],
        tx_hash: [u8; 32],
    ) -> gateway_core::Result<SubmitOutcome> {
        match self.gateway.submit_tx(signed_tx).await {
            Ok(accepted) => {
                // The builder-computed id is the authority for the local apply
                // step; the node's echoed id only cross-checks it. A mismatch is
                // ambiguous, not a clean acceptance, so the holder re-queries.
                if accepted == tx_hash {
                    Ok(SubmitOutcome::Accepted { tx_hash })
                } else {
                    Ok(SubmitOutcome::Ambiguous {
                        detail: "provider echoed a different transaction id than the builder \
                                 computed; the on-chain outcome is unknown"
                            .to_string(),
                    })
                }
            }
            // A transport/provider error cannot prove the input was not consumed,
            // so the lease holder must re-query rather than release blindly.
            Err(err) => Ok(SubmitOutcome::Ambiguous {
                detail: format!("submit through chain gateway failed: {err}"),
            }),
        }
    }
}

/// The scheduled job that reclaims expired submit leases.
///
/// One pass returns every UTxO whose submit lease lapsed to the available pool so
/// a builder that died mid-submit does not strand its canonical UTxO. The pass is
/// idempotent (a lease that is no longer expired is left alone), so the runtime's
/// at-least-once delivery is harmless.
pub struct LeaseReaperHandler {
    pool: sqlx::PgPool,
}

impl LeaseReaperHandler {
    /// Build a reaper handler against a pool.
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

impl JobHandler for LeaseReaperHandler {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        match reap_expired_leases(&self.pool).await {
            Ok(reaped) => {
                if reaped > 0 {
                    tracing::info!(reaped, "reclaimed expired submit leases");
                }
                JobOutcome::Complete
            }
            Err(e) => {
                tracing::warn!(error = %e, "lease reaper pass failed");
                JobOutcome::Fail {
                    error: JobError::new("lease_reaper_failed", e.to_string()),
                }
            }
        }
    }
}

/// The queue the lease reaper runs on, re-exported from the engine so the
/// schedule and policy registration name a single constant.
pub use gateway_core::wallet::utxo::LEASE_REAPER_QUEUE;

/// A schedule that fires the lease reaper every 30 seconds. The lease lifetime is
/// the real bound on how long a stale UTxO is held; a sub-minute cadence just
/// decides how promptly an expired lease is noticed.
#[must_use]
pub fn lease_reaper_schedule() -> gateway_core::runtime::scheduler::CronSchedule {
    gateway_core::runtime::scheduler::CronSchedule::new(
        "*/30 * * * * *",
        LEASE_REAPER_QUEUE,
        serde_json::Value::Null,
    )
}

#[cfg(test)]
mod tests {
    use gateway_core::chain::gateway::{
        chain_error, BlockInfo, ChainErrorClass, ChainTip, Label309RecordsResult, TxCborMap,
        TxConfirmationMap,
    };

    use super::*;

    /// A gateway whose submit always fails with the given error; the read
    /// methods are never reached by [`GatewaySubmitter`].
    struct RejectingGateway {
        error_class: ChainErrorClass,
    }

    impl ChainGateway for RejectingGateway {
        async fn submit_tx(&self, _signed_tx: &[u8]) -> gateway_core::Result<[u8; 32]> {
            Err(chain_error(self.error_class, "node rejected the body"))
        }
        async fn get_tx_confirmations(
            &self,
            _h: &[[u8; 32]],
        ) -> gateway_core::Result<TxConfirmationMap> {
            Ok(TxConfirmationMap::new())
        }
        async fn get_block_info(&self, _b: u64) -> gateway_core::Result<Option<BlockInfo>> {
            Ok(None)
        }
        async fn get_tip(&self) -> gateway_core::Result<ChainTip> {
            Ok(ChainTip {
                block_height: 0,
                epoch: None,
            })
        }
        async fn fetch_tx_cbor_by_hashes(
            &self,
            _h: &[[u8; 32]],
        ) -> gateway_core::Result<TxCborMap> {
            Ok(TxCborMap::new())
        }
        async fn fetch_label309_records_since(
            &self,
            _a: u64,
            _x: &[[u8; 32]],
            _t: u64,
            _m: u32,
        ) -> gateway_core::Result<Label309RecordsResult> {
            Ok(Label309RecordsResult::default())
        }
        async fn fetch_label309_records_since_alternate(
            &self,
            _a: u64,
            _x: &[[u8; 32]],
            _t: u64,
            _m: u32,
        ) -> gateway_core::Result<Label309RecordsResult> {
            Ok(Label309RecordsResult::default())
        }
    }

    /// The replenisher's split FIRST broadcast releases its source only on
    /// [`SubmitOutcome::Rejected`]. This adapter must never produce it from a
    /// gateway error — even a deterministic ledger reject maps to `Ambiguous` —
    /// because the adapter cannot know whether the failover pair had an earlier
    /// ambiguous wire contact with the same bytes. The recorded split then stays
    /// in flight and the recovery sweep's resume path terminalises it under the
    /// absence-corroboration gate, never on the reject alone.
    #[tokio::test]
    async fn a_gateway_submit_error_maps_to_ambiguous_never_rejected() {
        for error_class in [
            ChainErrorClass::NodeReject { status: 400 },
            ChainErrorClass::NodeRejectAfterAmbiguousBroadcast { status: 400 },
            ChainErrorClass::Http { status: 503 },
            ChainErrorClass::Transport,
        ] {
            let submitter = GatewaySubmitter::new(Arc::new(RejectingGateway { error_class }));
            let outcome = submitter
                .submit(&[0x84, 0xa0], [0x11; 32])
                .await
                .expect("the adapter reports an outcome, not an error");
            assert!(
                matches!(outcome, SubmitOutcome::Ambiguous { .. }),
                "a gateway submit error ({error_class:?}) must map to Ambiguous, got {outcome:?}"
            );
        }
    }
}
