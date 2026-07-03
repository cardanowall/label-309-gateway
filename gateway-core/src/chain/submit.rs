//! The submission pipeline.
//!
//! One job per record moves it from `submitting` to `submitted` (or to a
//! terminal `permanent_failure` with a refund). The whole claim -> build -> sign
//! -> submit window runs under a per-wallet session advisory lock so two
//! in-flight transactions on one wallet can never select the same UTxO.
//!
//! # Flow
//!
//! 1. Resolve the wallet. A first submit picks the record's entitled pinned
//!    wallet or a pool pick; a cancelling replacement (a rollback resubmit)
//!    settles strictly by the wallet the original submit pinned, since its forced
//!    inputs belong to that wallet and that spend was already authorized.
//! 2. Take the per-wallet advisory lock on a dedicated connection.
//! 3. Claim a canonical UTxO. For a cancelling replacement (a rollback resubmit)
//!    the rolled-back inputs are also claimed and passed to the builder as forced
//!    spends, so the replacement consumes an input of the transaction it
//!    replaces and the old metadata-only transaction can never land afterwards.
//! 4. Build via the deterministic builder with the cached protocol parameters.
//!    A record that exceeds the byte budget is an immediate `permanent_failure`
//!    plus refund (it can never succeed on retry).
//! 5. Sign and submit through the failover gateway.
//! 6. On success: apply the submit locally (mark the spent inputs `pending_spent`
//!    and record the change), flip the record to `submitted`, record the
//!    wallet's submission counter, trace the quote variance, and nudge the
//!    confirm loop.
//!
//! # Cooldown vs. terminal
//!
//! An outbound-cooldown signal (the failover gateway is parked behind a provider
//! 429) releases the UTxO lease and returns [`JobOutcome::Defer`], which does NOT
//! consume a retry attempt. The terminal arms (a pre-broadcast build failure at
//! the final attempt, an over-budget record at any attempt, a malformed or
//! non-conflicting replacement, or a deterministic node reject whose own
//! transaction a fresh lookup proves absent from chain — on a resume
//! re-broadcast additionally corroborated by the attempt outliving the
//! indexer-lag horizon) flip the record to
//! `permanent_failure` and write the single refund intent. A transient or
//! ambiguous broadcast failure is NOT terminal: once the attempt is recorded the
//! spend is durable, so the broadcast is retried and then left in-flight for the
//! confirm authority, which abandons it only on a settlement-deep conflicting
//! spend. The transaction carries no validity interval, so it can land at any
//! later block and is never refunded merely for failing to broadcast.

use std::sync::Arc;

use pallas_primitives::conway::Tx as ConwayTx;
use pallas_primitives::Fragment;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::chain::attempt::{self, AttemptInput, AttemptKind, AttemptOutput, NewAttempt};
use crate::chain::confirm::{record_permanent_failure, RefundReason, CONFIRM_QUEUE};
use crate::chain::gateway::{is_deterministic_node_reject, TxPresence};
use crate::runtime::enqueue::{enqueue_dedupe, EnqueueOptions};
use crate::runtime::{Backoff, JobContext, JobHandler, JobOutcome};
use crate::wallet::grant::{authorize_spend, AuthorizedWallet, SpendPrincipal};
use crate::wallet::keyring::UnlockedKeyring;
use crate::wallet::pool::{pick_wallet, record_submission, try_lock_wallet};
use crate::wallet::utxo::{self, ChangeOutput, SpentInput, UtxoLease, UtxoRef};
use crate::{Error, Result};

/// The queue the submission pipeline runs on.
pub const SUBMIT_QUEUE: &str = "cardano_submit";

/// The submit attempt budget. Attempts 1..=5; on the final attempt a build
/// failure refunds rather than retries, while a recorded-but-unbroadcast attempt
/// is left in-flight for the confirm authority rather than refunded.
pub const SUBMIT_MAX_ATTEMPTS: i32 = 5;

/// The fixed delay between submit retries.
pub const SUBMIT_BACKOFF_SECS: u32 = 30;

/// How old a recorded attempt must be before a deterministic-reject
/// RE-broadcast may trust an AFFIRMATIVE provider absence enough to abandon and
/// refund.
///
/// On a resume, absence has a second innocent explanation the reject cannot
/// rule out: the earlier "failed" broadcast reached a relay and the transaction
/// confirmed, but the provider's INDEXER (db-sync sitting behind the very node
/// that rejected the re-broadcast) has not indexed that block yet, so a status
/// lookup still answers "no record" — the same answer a truly-dead transaction
/// gives. A self-landed transaction cannot have entered a block before its
/// attempt row existed (record-before-broadcast), so once the row has outlived
/// this horizon and a fresh lookup STILL affirms absence, the absence is
/// corroborated: a landed transaction would have been indexed by now.
///
/// Thirty minutes dominates realistic indexer lag (seconds normally, minutes
/// under load) with a wide margin. It is deliberately its own constant rather
/// than riding the mempool alert / proof-of-death horizons: those tune operator
/// ALERTING and may be re-tuned freely, while this bounds an irreversible
/// refund. Liveness does not depend on the in-job retries finishing inside the
/// horizon: the chain-recovery sweep keeps re-enqueuing a stranded recorded
/// attempt every pass, so the abandon-and-refund fires on the first
/// re-broadcast past the horizon. The residual assumption is an indexer no more
/// than ~30 minutes stale; an operator running a resyncing (hours-stale)
/// indexer must drain it from rotation — the forward scan's non-advancing
/// frontier surfaces such an instance quickly.
pub const INDEXER_ABSENCE_HORIZON: std::time::Duration = std::time::Duration::from_secs(1800);

/// Whether an attempt has outlived [`INDEXER_ABSENCE_HORIZON`].
///
/// `created_at` is the record-before-broadcast insert instant, which strictly
/// precedes the first possible wire contact of the bytes, so it is a safe lower
/// bound on the earliest block the transaction could have entered. A clock
/// anomaly that makes the age negative reads as NOT elapsed — the fail-safe
/// direction (defer, never refund).
fn absence_horizon_elapsed(created_at: chrono::DateTime<chrono::Utc>) -> bool {
    (chrono::Utc::now() - created_at)
        .to_std()
        .is_ok_and(|age| age >= INDEXER_ABSENCE_HORIZON)
}

/// The policy for the submit queue: standard worker-pool concurrency (many
/// records submit in parallel across wallets), the five-attempt budget, and a
/// fixed backoff so retry timing is predictable. The per-wallet advisory lock,
/// not the queue, is what serialises two submits on the same wallet.
#[must_use]
pub fn submit_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::standard(
        SUBMIT_QUEUE,
        SUBMIT_MAX_ATTEMPTS,
        Backoff::Fixed {
            base_secs: SUBMIT_BACKOFF_SECS,
        },
        // The lease covers build -> sign -> submit, which is a handful of HTTP
        // calls; two minutes is ample and reclaims promptly on a dead replica.
        120,
        // Advisory worker-pool fan-out; the wallet lock bounds real parallelism
        // per wallet.
        8,
    )
}

/// The payload of a [`SUBMIT_QUEUE`] job.
///
/// `replacement_for` and `forced_inputs` are set only when the confirm loop
/// enqueued this as a cancelling replacement for a rolled-back transaction; for a
/// first submit they are absent and the builder selects inputs freely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitJob {
    /// The originating request id, propagated onto refund/events for tracing.
    pub request_id: String,
    /// The record to submit.
    pub record_id: Uuid,
    /// The transaction this submit replaces (a rollback resubmit), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_for: Option<String>,
    /// Inputs the replacement MUST spend so the rolled-back transaction can never
    /// land. Empty for a first submit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forced_inputs: Vec<ForcedInput>,
}

/// The payload of a split-recovery re-broadcast, enqueued by the recovery sweep for
/// a stranded `kind='split'` attempt that recorded before broadcast but never
/// reached the wire.
///
/// A split serves only its wallet (it has no record), so it cannot ride the
/// record-keyed [`SubmitJob`]. It rides [`SUBMIT_QUEUE`] alongside record submits so
/// it shares the already-registered submit handler (which holds the gateway and the
/// wallet lock the re-broadcast needs), but it is keyed by the split's attempt id
/// and the submit handler dispatches it to a split-resume path. The `split_attempt_id`
/// field is the discriminant: a [`SubmitJob`] never carries it, so the handler
/// distinguishes the two payload shapes on the one queue. `deny_unknown_fields`
/// makes the discrimination total: a [`SubmitJob`] payload (which carries
/// `request_id`/`record_id`) fails this parse outright rather than being mistaken for
/// a split resume that drops the real submit, so a split payload is the ONLY thing
/// that parses here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitResumeJob {
    /// The `kind='split'` attempt to re-broadcast from its durable recorded bytes.
    pub split_attempt_id: Uuid,
}

/// A reference to an input a cancelling replacement must spend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedInput {
    /// 32-byte transaction id, hex-encoded.
    pub tx_hash: String,
    /// Output index within that transaction.
    pub index: u32,
    /// Lovelace the output holds (so the builder can fee-balance without a chain
    /// read).
    pub lovelace: u64,
}

/// The reason a submit attempt could not complete, classified so the handler can
/// branch between defer (no attempt consumed), retry (attempt consumed), and a
/// terminal refund.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// A provider is in cooldown (a recent 429). Release the lease and defer; do
    /// NOT consume an attempt.
    OutboundCooldown {
        /// When the cooldown lifts; the defer targets this instant.
        until: chrono::DateTime<chrono::Utc>,
    },
    /// The transaction could not be built or signed (a pre-broadcast failure, so
    /// nothing is durably recorded). Retried until the final attempt, then terminal
    /// with [`RefundReason::TxBuildFailed`]. A broadcast failure is NOT this variant:
    /// once an attempt is recorded the spend is durable and a transient/ambiguous
    /// broadcast failure becomes [`SubmitOutcome::RecordedInFlight`] (never a refund).
    TxBuildFailed {
        /// Diagnostic detail.
        detail: String,
    },
    /// The record exceeds the protocol byte budget. Immediately terminal with
    /// [`RefundReason::ByteBudgetExceeded`]; never retried.
    ByteBudgetExceeded {
        /// The record's serialised size.
        size: u64,
        /// The protocol maximum it exceeded.
        max: u64,
    },
    /// A cancelling replacement job carried no usable forced inputs (the set was
    /// empty or malformed), so it cannot guarantee it cancels the rolled-back
    /// transaction. Immediately terminal with
    /// [`RefundReason::ReplacementInputsMissing`]; never retried, and never
    /// downgraded to a non-cancelling normal submit.
    ReplacementInputsMissing {
        /// Why the forced-input set was unusable.
        detail: String,
    },
    /// A cancelling replacement's recorded inputs do not intersect the superseded
    /// original's on any `(tx_hash, index)` reference, so the replacement does not
    /// actually conflict with the transaction it claims to cancel. The
    /// at-most-one-of-original-or-replacement-can-land invariant rests on the
    /// replacement re-spending an original input, so a non-conflicting replacement
    /// is rejected at record time (never recorded, never broadcast) and is
    /// immediately terminal: rebuilding could not reconstruct the lost conflict.
    ReplacementDoesNotConflict {
        /// What the intersection check found.
        detail: String,
    },
    /// The node rejected the transaction body deterministically (a ledger-invalid
    /// or already-spent submit a non-transient HTTP status reports). The recorded
    /// attempt is abandoned with its inputs restored only once a fresh chain
    /// lookup ALSO proves its own transaction absent — the same reject answers a
    /// re-broadcast of bytes that already landed and now conflict with themselves
    /// — and, on a resume re-broadcast, only once the attempt has outlived
    /// [`INDEXER_ABSENCE_HORIZON`] (a younger absence can be the provider's
    /// indexer lagging its own node on a self-landed transaction). This is the
    /// only abandon not gated on a settlement-deep conflicting spend, so it is
    /// gated on a typed rejection AND a corroborated absence of the attempt's
    /// own transaction.
    NodeRejected {
        /// The provider's diagnostic detail.
        detail: String,
    },
    /// No wallet could be locked (every candidate is busy). Retried.
    WalletLockContention,
}

/// The submission-pipeline job handler.
///
/// Register it on the runtime against [`SUBMIT_QUEUE`] with [`submit_policy`]. It
/// owns its pool, the wallet keyring (for signing), the failover chain gateway,
/// and the wallet config.
pub struct SubmitHandler<G: crate::chain::gateway::ChainGateway> {
    pool: sqlx::PgPool,
    gateway: G,
    config: crate::wallet::config::WalletConfig,
    keyring: Arc<UnlockedKeyring>,
}

impl<G: crate::chain::gateway::ChainGateway> SubmitHandler<G> {
    /// Build a submit handler over a pool, a failover chain gateway, the wallet
    /// config (network, band, lease, canonical count), and the unlocked operator
    /// keyring the build step signs with.
    ///
    /// The keyring is shared (`Arc`) because the same unlocked signers serve every
    /// submit and the replenisher; it is never cloned per job and never exposes a
    /// raw key.
    pub fn new(
        pool: sqlx::PgPool,
        gateway: G,
        config: crate::wallet::config::WalletConfig,
        keyring: Arc<UnlockedKeyring>,
    ) -> Self {
        Self {
            pool,
            gateway,
            config,
            keyring,
        }
    }

    /// Run one submit attempt for a job, returning the resulting record state
    /// transition or the classified failure. The per-wallet advisory lock is held
    /// across the whole call. Used by the handler and by integration tests.
    ///
    /// The lock is taken with [`try_lock_wallet`] and held in a binding for the
    /// whole window (claim -> build -> sign -> submit -> apply), then dropped on
    /// the way out of every arm, so two in-flight transactions on one wallet can
    /// never select the same UTxO. A failure that leaves a UTxO leased
    /// (a cooldown defer, a build/sign/submit failure) releases the lease before
    /// returning so the next attempt does not strand it until the reaper.
    pub async fn submit_once(&self, job: &SubmitJob, _attempt: i32) -> Result<SubmitOutcome> {
        let record = match self.load_record(job.record_id).await? {
            Some(record) => record,
            // A record that is no longer submittable (already terminal, or
            // already submitted by a racing path) is not a failure to refund: the
            // job is simply done. Treat it as a cooldown-free completion by
            // reporting it submitted with no inputs.
            None => {
                return Ok(SubmitOutcome::AlreadyResolved);
            }
        };

        // Resolve the wallet. A first submit picks (or honours an entitled pinned
        // wallet); a cancelling replacement settles its ALREADY-AUTHORIZED in-flight
        // transaction strictly by the pinned wallet id. Either way the result is an
        // AuthorizedWallet capability, so a signer is reachable only for a wallet
        // this path resolved.
        let Some(wallet) = self.resolve_wallet(job, &record).await? else {
            // No wallet resolved: a first submit found no eligible/entitled wallet
            // (none ready, or none the principal may spend), or a replacement's
            // pinned wallet is missing on this network. Retryable: a replenish, a
            // freed wallet, or a fresh grant resolves it.
            return Ok(SubmitOutcome::Failed {
                error: SubmitError::WalletLockContention,
            });
        };

        // The per-wallet session advisory lock guards the whole build window. If
        // another worker already holds it, the job retries rather than racing on
        // the same wallet's UTxOs.
        let lock = match try_lock_wallet(&self.pool, wallet.wallet_id()).await? {
            Some(lock) => lock,
            None => {
                return Ok(SubmitOutcome::Failed {
                    error: SubmitError::WalletLockContention,
                });
            }
        };

        // Run the locked window; the lock guard drops at the end of this scope no
        // matter which arm returns.
        let outcome = self.submit_locked(job, &record, &wallet).await;
        // Release the lock explicitly (closing its detached connection) before
        // returning, rather than relying on the Drop spawn, so the connection is
        // reclaimed promptly under load.
        let _ = lock.release().await;
        outcome
    }

    /// The body of one submit attempt with the per-wallet advisory lock already
    /// held: re-broadcast an already-recorded attempt idempotently, or re-authorize,
    /// bind, claim, build, sign, RECORD-BEFORE-BROADCAST, broadcast, and flip.
    async fn submit_locked(
        &self,
        job: &SubmitJob,
        record: &PoeRecordRow,
        wallet: &AuthorizedWallet,
    ) -> Result<SubmitOutcome> {
        // Idempotent retry preamble. If the record is already riding an attempt
        // THIS job owns, this is a redelivery (a lease lapse, a Fail requeue, a crash
        // between record-before-broadcast and the submitted flip): it must NEVER mint
        // a second transaction. Re-broadcast the EXACT recorded bytes (the node
        // dedupes by tx id) and repair the projection, rather than rebuilding.
        //
        // A FIRST submit owns any current attempt for the record. A cancelling
        // REPLACEMENT owns only a current attempt that is its own already-recorded
        // replacement (kind='replacement'); when the current attempt is instead the
        // ORIGINAL it is meant to supersede (a 'publish' the record still rides), the
        // replacement must fall through to the build path so the atomic supersede-and-
        // record handoff runs.
        if let Some(attempt_id) = record.current_attempt_id {
            let resume = if job.replacement_for.is_some() {
                // Resume only our own recorded replacement, not the original we
                // supersede. The original is a non-replacement attempt the handoff
                // takes over; a replacement attempt already here is our redelivery.
                matches!(
                    attempt::load_attempt(&self.pool, attempt_id).await?,
                    Some(a) if a.kind == AttemptKind::Replacement
                )
            } else {
                true
            };
            if resume {
                return self.resume_recorded_attempt(record, attempt_id).await;
            }
        }

        // Re-resolve the capability on the locked wallet now the lock is held,
        // closing the window between the pre-lock resolve and signing.
        //
        //   - A NEW spend re-runs authorize_spend on the exact locked wallet, so a
        //     grant revoked between resolve and lock cannot leak one last signature;
        //     a no-longer-entitled wallet yields None and fails back to retry. This
        //     locked re-check is what makes revocation forward-looking: revoke is a
        //     plain committed UPDATE that takes no lock, so a spend authorizing here
        //     AFTER the revoke commits reads the stamped revoked_at and is refused,
        //     while an already-authorized in-flight spend (this lock bounds them to
        //     at most one per wallet) completes because it was entitled when checked.
        //   - An IN-FLIGHT settlement (a cancelling replacement) re-resolves by
        //     wallet id only. It must NOT re-run the entitlement check: that spend
        //     was authorized at submit time and the replacement can only be built
        //     against this wallet's UTxOs, so a grant revoked (or the wallet set
        //     draining) after submit must still settle rather than strand the
        //     transaction.
        let reauthorized = if job.replacement_for.is_some() {
            crate::wallet::grant::resolve_inflight_wallet(
                &self.pool,
                wallet.wallet_id(),
                self.config.network.as_str(),
            )
            .await?
        } else {
            authorize_spend(&self.pool, wallet.wallet_id(), spend_principal(record)).await?
        };
        let Some(wallet) = reauthorized else {
            return Ok(SubmitOutcome::Failed {
                error: SubmitError::WalletLockContention,
            });
        };

        // Bind the wallet to the record (unconditional, even on the pinned path,
        // so a re-enqueued retry that pool-picked a fresh wallet records which one
        // it actually used).
        self.bind_wallet(record.id, wallet.wallet_id()).await?;

        // Claim a fresh canonical UTxO. A replacement also re-leases the
        // rolled-back transaction's inputs so it spends at least one of them, which
        // is what prevents the old metadata-only transaction from ever landing.
        let canonical_token = Uuid::now_v7();
        let Some(canonical_lease) = utxo::claim(
            &self.pool,
            wallet.wallet_id(),
            canonical_token,
            &self.config,
        )
        .await?
        else {
            return Ok(SubmitOutcome::Failed {
                error: SubmitError::WalletLockContention,
            });
        };

        let mut leases: Vec<UtxoLease> = vec![canonical_lease.clone()];
        // A job marked as a cancelling replacement MUST carry usable forced
        // inputs. An empty or malformed set means the rolled-back transaction's
        // inputs are not known, so this submit could not cancel it: rather than
        // silently fall through to a normal submit (which would double-publish the
        // record under a new tx while the old metadata-only tx can still land),
        // the replacement is refunded outright.
        if job.replacement_for.is_some() {
            if job.forced_inputs.is_empty() {
                self.release_leases(wallet.wallet_id(), &leases).await;
                return Ok(SubmitOutcome::Failed {
                    error: SubmitError::ReplacementInputsMissing {
                        detail: "a cancelling replacement carried no forced inputs; \
                                 it cannot cancel the rolled-back transaction"
                            .to_string(),
                    },
                });
            }
            let forced_refs = match forced_input_refs(&job.forced_inputs) {
                Ok(refs) => refs,
                Err(e) => {
                    self.release_leases(wallet.wallet_id(), &leases).await;
                    return Ok(SubmitOutcome::Failed {
                        error: SubmitError::ReplacementInputsMissing {
                            detail: format!("malformed forced inputs on a replacement: {e}"),
                        },
                    });
                }
            };
            let replacement_token = Uuid::now_v7();
            let mut replacement_leases = utxo::claim_replacement(
                &self.pool,
                wallet.wallet_id(),
                &forced_refs,
                replacement_token,
                &self.config,
            )
            .await?;
            // A replacement that cannot re-lease ANY of the rolled-back inputs
            // right now cannot guarantee it cancels the old transaction; release
            // what we hold and retry (the inputs may be momentarily unavailable)
            // rather than submit a non-cancelling replacement.
            if replacement_leases.is_empty() {
                self.release_leases(wallet.wallet_id(), &leases).await;
                return Ok(SubmitOutcome::Failed {
                    error: SubmitError::TxBuildFailed {
                        detail: "no rolled-back input could be re-leased for the cancelling \
                                 replacement"
                            .to_string(),
                    },
                });
            }
            leases.append(&mut replacement_leases);
        }

        // Build under the live cached protocol parameters. Every step from here to
        // the submit can fail and must release the leases it holds.
        let params = match self.load_protocol_params().await {
            Ok(params) => params,
            Err(e) => {
                self.release_leases(wallet.wallet_id(), &leases).await;
                return Err(e);
            }
        };

        // Byte-budget fast path: a record whose raw bytes already exceed the
        // protocol maximum can never be submitted, so it is immediately terminal
        // without even attempting a build. The full-transaction oversize check
        // below catches the case where the record fits but the assembled (signed,
        // change-bearing) transaction does not.
        let record_len = record.record_bytes.len() as u64;
        if record_len > params.max_tx_size {
            self.release_leases(wallet.wallet_id(), &leases).await;
            return Ok(SubmitOutcome::Failed {
                error: SubmitError::ByteBudgetExceeded {
                    size: record_len,
                    max: params.max_tx_size,
                },
            });
        }

        let build = self.build_request(record, &wallet, &leases, &canonical_lease, &params);
        let built = match cardano_poe_tx::build_poe_tx(&build) {
            Ok(built) => built,
            // An oversize FINAL transaction is the same terminal byte-budget
            // failure as the raw-record precheck: the assembled transaction can
            // never fit the protocol maximum, so it is refunded with the actual and
            // maximum sizes rather than retried.
            Err(cardano_poe_tx::BuildError::TxTooLarge { size, max }) => {
                self.release_leases(wallet.wallet_id(), &leases).await;
                return Ok(SubmitOutcome::Failed {
                    error: SubmitError::ByteBudgetExceeded { size, max },
                });
            }
            Err(e) => {
                self.release_leases(wallet.wallet_id(), &leases).await;
                return Ok(SubmitOutcome::Failed {
                    error: SubmitError::TxBuildFailed {
                        detail: e.to_string(),
                    },
                });
            }
        };

        // Sign with the keyring signer for the wallet's address. The signer never
        // exposes its key; it returns the raw signature over the body hash, which
        // is attached as the single vkey witness the fee already paid for.
        let signed_tx = match self.sign_built(&built, &wallet) {
            Ok(signed) => signed,
            Err(e) => {
                self.release_leases(wallet.wallet_id(), &leases).await;
                return Ok(SubmitOutcome::Failed {
                    error: SubmitError::TxBuildFailed {
                        detail: e.to_string(),
                    },
                });
            }
        };

        // RECORD-BEFORE-BROADCAST. In ONE transaction, in the lock order
        // attempt -> record -> wallet (so two transactions never take the same row
        // locks in opposite order): for a replacement, atomically supersede the
        // original and run the intersection check; insert the attempt; claim the
        // record's chain generation; advance the leased inputs and insert the
        // change. The signed bytes are durable BEFORE they ever reach the wire, so a
        // crash after this commit leaves a recorded attempt a retry re-broadcasts,
        // and a crash before it leaves nothing on chain to lose. The leases are
        // released only on a failure that does not record; on success they are
        // consumed by the recorded spend.
        let spent_inputs: Vec<SpentInput> = leases
            .iter()
            .map(|lease| SpentInput {
                utxo: lease.utxo,
                lease_token: lease.lease_token,
            })
            .collect();
        let built_tx = BuiltTransaction {
            built: &built,
            signed_tx: &signed_tx,
            leases: &leases,
            spent_inputs: &spent_inputs,
        };
        let attempt_id = match self
            .record_attempt_locked(record, &wallet, &built_tx, job)
            .await
        {
            Ok(RecordedAttempt::Recorded(attempt_id)) => attempt_id,
            Ok(RecordedAttempt::LostGeneration) => {
                // A concurrent generation already recorded the active-broadcaster
                // attempt for this record (the record guard or the one-active unique
                // index rejected this one). Release our leases and report the record
                // already resolved; we must NOT broadcast a second transaction.
                self.release_leases(wallet.wallet_id(), &leases).await;
                return Ok(SubmitOutcome::AlreadyResolved);
            }
            Ok(RecordedAttempt::ReplacementDoesNotConflict { detail }) => {
                // The replacement's inputs do not intersect the original's, so it
                // would not cancel it: never recorded, never broadcast. Terminal.
                self.release_leases(wallet.wallet_id(), &leases).await;
                return Ok(SubmitOutcome::Failed {
                    error: SubmitError::ReplacementDoesNotConflict { detail },
                });
            }
            Err(e) => {
                self.release_leases(wallet.wallet_id(), &leases).await;
                return Err(e);
            }
        };

        // BROADCAST the recorded bytes through the failover gateway. A provider
        // cooldown is a defer (no attempt consumed); a deterministic node reject
        // abandons-with-restore once a fresh lookup proves the attempt's own
        // transaction absent from chain (a rejected re-broadcast of self-landed
        // bytes is repaired instead, never refunded); any other gateway error
        // leaves the recorded attempt in-flight for the confirm authority to
        // reconcile (it is ambiguous whether the body reached a node, so the
        // inputs stay reserved).
        let accepted = match self.gateway.submit_tx(&signed_tx).await {
            Ok(hash) => hash,
            Err(e) => {
                // This is the attempt's genuine FIRST broadcast (the resume
                // preamble routes every already-recorded attempt elsewhere), so
                // an affirmative absence needs no age corroboration: bytes that
                // were never on the wire before cannot have self-landed. That
                // holds even under the failover gateway, which downgrades a
                // secondary reject that followed a failed (ambiguous) primary
                // attempt to a transient class — so a deterministic reject
                // reaching this classifier PROVES the reject was the outcome of
                // the bytes' only wire contact in the call.
                return self
                    .classify_broadcast_failure(
                        record, attempt_id, &e, /* require_absence_corroboration */ false,
                    )
                    .await;
            }
        };

        // The node must echo the id the builder computed; a mismatch means the
        // submission was for a different transaction than the one we recorded, so
        // the recorded spend would not match what landed. Leave the attempt
        // in-flight (the recorded bytes are correct; this is a provider anomaly the
        // confirm authority reconciles).
        if accepted != built.tx_hash {
            return Ok(SubmitOutcome::RecordedInFlight);
        }

        // The broadcast landed: mark the attempt `broadcast` (stamping its mempool
        // entry time) and flip the record to `submitted` from the attempt
        // projection, appending exactly one `submitted` event. A zero-row flip
        // means a racing generation already moved the record; it is AlreadyResolved
        // and emits no duplicate event.
        let _ = attempt::mark_broadcast(&self.pool, attempt_id).await?;
        let flipped = self.mark_broadcast_and_flip(record, attempt_id).await?;
        if !flipped {
            return Ok(SubmitOutcome::AlreadyResolved);
        }

        // Best-effort load-spreading counter; a failure here must not fail a
        // landed submit.
        let _ = record_submission(&self.pool, wallet.wallet_id()).await;
        self.nudge_confirm().await?;

        Ok(SubmitOutcome::Submitted {
            tx_hash: built.tx_hash,
            spent_inputs: spent_inputs.iter().map(|s| s.utxo).collect(),
            fee_lovelace: Some(built.fee),
        })
    }

    /// Mark a record's submit a terminal failure: flip to `permanent_failure`,
    /// write the single refund intent, and emit the events, in one transaction.
    /// Shares [`crate::chain::confirm::record_permanent_failure`] so every refund
    /// path (submit and confirm) writes through one durable single-refund hook
    /// and the single-refund-by-construction invariant has exactly one writer.
    async fn fail_permanently(
        &self,
        record_id: Uuid,
        reason: RefundReason,
        detail: &serde_json::Value,
    ) -> Result<()> {
        record_permanent_failure(&self.pool, record_id, reason, detail).await?;
        Ok(())
    }

    /// Load the submittable fields of a record, or `None` when it is not in a
    /// state a submit may act on (already terminal, draft, or already submitted by
    /// a racing path that this attempt should not redo).
    async fn load_record(&self, record_id: Uuid) -> Result<Option<PoeRecordRow>> {
        let row = sqlx::query_as::<_, RecordRow>(
            "SELECT id, operator_id, account_id, record_bytes, wallet_id, status, \
                    current_attempt_id \
             FROM cw_core.poe_record WHERE id = $1",
        )
        .bind(record_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };
        // A first submit's record is `submitting`; a rollback resubmit's record is
        // `submitted` with cleared coordinates. Both are submittable. Any other
        // state (draft, confirmed, permanent_failure) is not this job's to act on.
        if row.status != "submitting" && row.status != "submitted" {
            return Ok(None);
        }
        Ok(Some(PoeRecordRow {
            id: row.id,
            operator_id: row.operator_id,
            account_id: row.account_id,
            record_bytes: row.record_bytes,
            pinned_wallet_id: row.wallet_id,
            current_attempt_id: row.current_attempt_id,
        }))
    }

    /// Resolve the wallet a submit should use, as an [`AuthorizedWallet`]
    /// capability, on one of two strictly separate paths:
    ///
    ///   - **In-flight settlement** (a cancelling replacement, `replacement_for`
    ///     set): resolve STRICTLY by the record's pinned wallet id via
    ///     [`resolve_inflight_wallet`], with NO entitlement re-check and NO
    ///     fallthrough. The replacement's forced inputs are the original wallet's
    ///     UTxOs, so it can only be built against that same wallet; a grant revoked
    ///     (or the wallet set `draining`) after the original submit must not strand
    ///     it. The spend was already authorized at submit time.
    ///   - **New spend** (a first submit, `replacement_for` absent): the record's
    ///     pinned wallet when one is bound AND the record's principal is still
    ///     entitled to spend it (a status check plus [`authorize_spend`]), else the
    ///     least-loaded pick among the wallets that principal is entitled to. A
    ///     wallet the principal is no longer entitled to (a revoked grant, or a
    ///     drained/retired wallet) falls through to a fresh pick.
    ///
    /// Either way the capability is minted inside the `grant` module, so a signer
    /// is never reached from a bare address.
    async fn resolve_wallet(
        &self,
        job: &SubmitJob,
        record: &PoeRecordRow,
    ) -> Result<Option<AuthorizedWallet>> {
        // A cancelling replacement settles an already-authorized in-flight
        // transaction: it MUST resolve to the wallet the original submit pinned,
        // and only that wallet, because its forced inputs belong to that wallet.
        // It never re-runs the entitlement check and never falls through.
        if job.replacement_for.is_some() {
            let Some(wallet_id) = record.pinned_wallet_id else {
                // A replacement with no pinned wallet has no in-flight binding to
                // settle against; treat as no wallet resolved (retryable). The
                // submit-time bind always records the wallet, so this is degenerate.
                return Ok(None);
            };
            return crate::wallet::grant::resolve_inflight_wallet(
                &self.pool,
                wallet_id,
                self.config.network.as_str(),
            )
            .await;
        }

        let principal = spend_principal(record);

        if let Some(wallet_id) = record.pinned_wallet_id {
            // Gate the pinned wallet on a live spend entitlement AND on it still
            // being active for scheduling on this network: a drained/retired wallet
            // takes no new submits even though its registrar could still authorize
            // it.
            if self.pinned_wallet_is_active(wallet_id).await? {
                if let Some(authorized) = authorize_spend(&self.pool, wallet_id, principal).await? {
                    return Ok(Some(authorized));
                }
            }
        }

        let Some(candidate) =
            pick_wallet(&self.pool, record.operator_id, self.config.network).await?
        else {
            return Ok(None);
        };
        // The pick already filtered on entitlement, but mint the capability the
        // signer needs through authorize_spend so the only path to a signer is the
        // spend check (and the locked-window re-check inside submit_locked closes
        // the TOCTOU between this and signing).
        authorize_spend(&self.pool, candidate.wallet_id, principal).await
    }

    /// Whether a pinned wallet is still `active` on this instance's network
    /// (eligible for new submits). A drained or retired wallet, a wallet bound to a
    /// different network, or an unknown id, returns false so the resolve falls
    /// through to a fresh pick.
    async fn pinned_wallet_is_active(&self, wallet_id: Uuid) -> Result<bool> {
        let active: Option<bool> = sqlx::query_scalar(
            "SELECT (status = 'active') FROM cw_core.operator_wallet \
             WHERE id = $1 AND network = $2",
        )
        .bind(wallet_id)
        .bind(self.config.network.as_str())
        .fetch_optional(&self.pool)
        .await?;
        Ok(active.unwrap_or(false))
    }

    /// Bind the wallet to the record so a later confirm/rollback prefers the same
    /// wallet's change lineage and the row records which wallet actually submitted.
    async fn bind_wallet(&self, record_id: Uuid, wallet_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE cw_core.poe_record SET wallet_id = $2 WHERE id = $1")
            .bind(record_id)
            .bind(wallet_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Load the live cached protocol parameters for the submit's network, with no
    /// network call, projected into the builder's [`cardano_poe_tx::ProtocolParams`].
    async fn load_protocol_params(&self) -> Result<cardano_poe_tx::ProtocolParams> {
        let network = self.config.network.to_params_network();
        let stored = crate::chain::params::load_params(&self.pool, network).await?;
        Ok(cardano_poe_tx::ProtocolParams {
            min_fee_a: stored.min_fee_a,
            min_fee_b: stored.min_fee_b,
            coins_per_utxo_byte: stored.coins_per_utxo_byte,
            max_tx_size: stored.max_tx_size,
        })
    }

    /// Assemble the build request: the canonical lease becomes the candidate set,
    /// every forced (re-leased) input becomes a mandatory spend, and the change
    /// returns to the wallet's own address.
    fn build_request(
        &self,
        record: &PoeRecordRow,
        wallet: &AuthorizedWallet,
        leases: &[UtxoLease],
        canonical_lease: &UtxoLease,
        params: &cardano_poe_tx::ProtocolParams,
    ) -> cardano_poe_tx::BuildRequest {
        // The fresh canonical input is the free candidate; the rolled-back inputs
        // (every lease past the first) are mandatory so the replacement spends at
        // least one of them. The signer for this authorized wallet supplies the
        // vkey the fee sizes the single witness against.
        let verification_key = self
            .keyring
            .signer_for(wallet)
            .map(|s| s.verification_key())
            .unwrap_or([0u8; 32]);
        let candidate = cardano_poe_tx::Utxo {
            tx_hash: hex::encode(canonical_lease.utxo.tx_hash),
            index: canonical_lease.utxo.output_index,
            lovelace: canonical_lease.lovelace,
        };
        let must_spend: Vec<cardano_poe_tx::Utxo> = leases
            .iter()
            .filter(|lease| lease.utxo != canonical_lease.utxo)
            .map(|lease| cardano_poe_tx::Utxo {
                tx_hash: hex::encode(lease.utxo.tx_hash),
                index: lease.utxo.output_index,
                lovelace: lease.lovelace,
            })
            .collect();
        cardano_poe_tx::BuildRequest {
            record_bytes: record.record_bytes.clone(),
            metadata_label: cardano_poe_tx::POE_METADATA_LABEL,
            utxos: vec![candidate],
            must_spend,
            protocol: *params,
            change_address: wallet.address().to_string(),
            network_id: self.config.network.network_id(),
            payment_verification_key: verification_key,
            validity: None,
        }
    }

    /// Sign a built transaction with the keyring signer for an authorized wallet,
    /// attaching the single vkey witness the fee already accounts for. Errors when
    /// the keyring holds no signer for the wallet (its key was not loaded on this
    /// instance), so a wallet the principal is authorized to spend but whose key
    /// is held elsewhere fails to sign rather than producing a bad witness.
    fn sign_built(
        &self,
        built: &cardano_poe_tx::BuiltPoeTx,
        wallet: &AuthorizedWallet,
    ) -> Result<Vec<u8>> {
        let signer = self.keyring.signer_for(wallet).ok_or_else(|| {
            Error::WalletBuild(
                "no keyring signer for the authorized wallet; the wallet's key is not loaded"
                    .to_string(),
            )
        })?;
        // The builder signs the 32-byte body hash; the signer returns the raw
        // signature over it without ever exposing the key.
        let signature = signer.sign_tx_body(&built.tx_hash);
        Ok(witness_tx(
            &built.unsigned_tx_bytes,
            signer.verification_key(),
            &signature,
        ))
    }

    /// Record the attempt before broadcast, in ONE transaction in the lock order
    /// attempt -> record -> wallet, under the wallet advisory lock the caller holds.
    ///
    /// For a cancelling replacement this is the atomic supersede-and-record handoff:
    /// the superseded original is marked `superseded` (it leaves the
    /// active-broadcaster set the instant the replacement enters it, so the
    /// one-active unique index is satisfied at every instant), its
    /// `current_attempt_id` is cleared so the replacement's generation guard can
    /// claim the record, and the replacement is verified to re-spend at least one of
    /// the original's inputs (the intersection check) before it is recorded.
    ///
    /// Returns the recorded attempt id, or a [`RecordedAttempt`] variant for a lost
    /// generation race (the record guard or the one-active index rejected this job)
    /// or a non-conflicting replacement. The leases are left as the caller claimed
    /// them; on a recorded success they are consumed as the attempt's spend, and the
    /// caller releases them on any failure variant.
    async fn record_attempt_locked(
        &self,
        record: &PoeRecordRow,
        wallet: &AuthorizedWallet,
        built_tx: &BuiltTransaction<'_>,
        job: &SubmitJob,
    ) -> Result<RecordedAttempt> {
        let built = built_tx.built;
        let is_replacement = job.replacement_for.is_some();
        let attempt_spent: Vec<AttemptInput> = built_tx
            .leases
            .iter()
            .map(|lease| AttemptInput {
                tx_hash: hex::encode(lease.utxo.tx_hash),
                index: lease.utxo.output_index,
                lovelace: lease.lovelace,
            })
            .collect();
        let produced_outputs: Vec<AttemptOutput> = built
            .change
            .map(|lovelace| vec![AttemptOutput { index: 0, lovelace }])
            .unwrap_or_default();

        let attempt_id = Uuid::now_v7();
        let new_attempt = NewAttempt {
            id: attempt_id,
            kind: if is_replacement {
                AttemptKind::Replacement
            } else {
                AttemptKind::Publish
            },
            record_id: Some(record.id),
            wallet_id: wallet.wallet_id(),
            tx_hash: built.tx_hash,
            // The recorded bytes ARE the bytes that go on the wire: the broadcaster
            // sends only an already-recorded transaction, and a retry re-broadcasts
            // exactly these.
            signed_tx: built_tx.signed_tx.to_vec(),
            fee_lovelace: built.fee,
            spent_inputs: attempt_spent.clone(),
            produced_outputs,
            replaces_tx_hash: parse_replacement_tx_hash(job)?,
        };

        let mut tx = self.pool.begin().await?;

        // (a) For a replacement, supersede the original atomically and enforce the
        //     intersection check, so the active-broadcaster set never contains two
        //     attempts sharing an input and a non-conflicting replacement is
        //     rejected before any spend or broadcast.
        if let Some(original_tx_hash) = new_attempt.replaces_tx_hash {
            match self
                .supersede_original_in_tx(
                    &mut tx,
                    &original_tx_hash,
                    attempt_id,
                    record.id,
                    &attempt_spent,
                )
                .await?
            {
                SupersedeOutcome::Superseded => {}
                SupersedeOutcome::NoLiveOriginal => {
                    tx.rollback().await?;
                    return Ok(RecordedAttempt::LostGeneration);
                }
                SupersedeOutcome::DoesNotConflict { detail } => {
                    tx.rollback().await?;
                    return Ok(RecordedAttempt::ReplacementDoesNotConflict { detail });
                }
            }
        }

        // (b) Insert the attempt row (status='recorded'). A unique-index violation on
        //     chain_attempt_one_active_per_record means a concurrent generation
        //     already recorded the active broadcaster: this job lost the race.
        if let Err(e) = attempt::record_attempt_in_tx(&mut tx, &new_attempt).await {
            tx.rollback().await?;
            if is_one_active_violation(&e) {
                return Ok(RecordedAttempt::LostGeneration);
            }
            return Err(e);
        }

        // (c) Claim the record's chain generation: set current_attempt_id under the
        //     generation guard. A first submit may act only on a `submitting` record
        //     with no current attempt; a replacement only on a `submitted` record
        //     whose prior attempt the supersede above cleared. A zero-row update
        //     means another generation won the record: roll back and lose the race.
        let claimed = self
            .claim_generation_in_tx(&mut tx, record, attempt_id, is_replacement)
            .await?;
        if !claimed {
            tx.rollback().await?;
            return Ok(RecordedAttempt::LostGeneration);
        }

        // (d) Advance the leased inputs to pending_spent (fenced on their tokens) and
        //     insert the change as the attempt's produced output. The wallet writes
        //     are LAST, completing the attempt -> record -> wallet lock order. If a
        //     lease was reaped out from under us, the whole transaction rolls back so
        //     nothing is half-recorded.
        let change = change_output(built);
        let applied =
            utxo::apply_submit_in_tx(&mut tx, wallet.wallet_id(), built_tx.spent_inputs, change)
                .await?;
        if !applied {
            tx.rollback().await?;
            return Ok(RecordedAttempt::LostGeneration);
        }

        tx.commit().await?;
        Ok(RecordedAttempt::Recorded(attempt_id))
    }

    /// The supersede half of the atomic replacement handoff, inside the caller's
    /// record-before-broadcast transaction: load the superseded original by its
    /// transaction hash, verify the replacement re-spends one of its inputs, mark it
    /// `superseded`, and clear the record's `current_attempt_id` so the
    /// replacement's generation guard can claim the record.
    async fn supersede_original_in_tx(
        &self,
        tx: &mut sqlx::PgConnection,
        original_tx_hash: &[u8; 32],
        replacement_id: Uuid,
        record_id: Uuid,
        replacement_spent: &[AttemptInput],
    ) -> Result<SupersedeOutcome> {
        let original = attempt::load_attempt_in_tx(tx, original_tx_hash).await?;
        let Some(original) = original else {
            // The original attempt is gone (already terminalised, or never
            // recorded): there is nothing live to supersede. Treat as a lost race.
            return Ok(SupersedeOutcome::NoLiveOriginal);
        };

        // The intersection check (gateway-enforced, not assumed): the replacement
        // must re-spend at least one (tx_hash, index) the original spent, or it does
        // not conflict and both could land. Abort the whole record-before-broadcast
        // before any spend or broadcast.
        if !inputs_intersect(replacement_spent, &original.spent_inputs) {
            return Ok(SupersedeOutcome::DoesNotConflict {
                detail: format!(
                    "the replacement re-spends none of the {} input(s) of the original it cancels",
                    original.spent_inputs.len()
                ),
            });
        }

        // Mark the original superseded (guarded to an active broadcaster). Zero rows
        // means it is no longer the active broadcaster (already superseded/terminal):
        // a lost race.
        let superseded = attempt::mark_superseded(tx, original.id, replacement_id).await?;
        if !superseded {
            return Ok(SupersedeOutcome::NoLiveOriginal);
        }

        // Clear the record's pointer to the original so the replacement's generation
        // guard (current_attempt_id IS NULL) can claim it in step (c).
        sqlx::query(
            "UPDATE cw_core.poe_record SET current_attempt_id = NULL \
             WHERE id = $1 AND current_attempt_id = $2",
        )
        .bind(record_id)
        .bind(original.id)
        .execute(&mut *tx)
        .await?;

        Ok(SupersedeOutcome::Superseded)
    }

    /// Claim the record's chain generation by setting `current_attempt_id` under the
    /// generation guard, inside the caller's transaction. Returns whether the guard
    /// matched (a zero-row update means another generation won the record).
    ///
    /// A first submit may act only on a `submitting` record with no current attempt;
    /// a cancelling replacement only on a `submitted` record with no current attempt
    /// (the supersede in this same transaction cleared the original's pointer). This
    /// makes a non-replacement job structurally unable to act on a `submitted`
    /// record and vice versa.
    async fn claim_generation_in_tx(
        &self,
        tx: &mut sqlx::PgConnection,
        record: &PoeRecordRow,
        attempt_id: Uuid,
        is_replacement: bool,
    ) -> Result<bool> {
        let guard_status = if is_replacement {
            "submitted"
        } else {
            "submitting"
        };
        let claimed = sqlx::query(
            "UPDATE cw_core.poe_record SET current_attempt_id = $2 \
             WHERE id = $1 AND status = $3 AND current_attempt_id IS NULL",
        )
        .bind(record.id)
        .bind(attempt_id)
        .bind(guard_status)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        Ok(claimed)
    }

    /// Resume an already-recorded attempt idempotently (the redelivery / crash-window
    /// path): re-broadcast the exact recorded bytes and repair the record projection,
    /// never rebuilding a fresh transaction.
    async fn resume_recorded_attempt(
        &self,
        record: &PoeRecordRow,
        attempt_id: Uuid,
    ) -> Result<SubmitOutcome> {
        let Some(attempt) = attempt::load_attempt(&self.pool, attempt_id).await? else {
            // The record points at an attempt that no longer exists; nothing this
            // job can resume. The record is left for the confirm authority.
            return Ok(SubmitOutcome::AlreadyResolved);
        };

        use crate::chain::attempt::AttemptStatus;
        match attempt.status {
            // An attempt that already reached the wire (`broadcast`/`stuck`): the
            // transaction is in a mempool. This is the crash-window case — a crash
            // between the broadcast and the `submitted` flip. Re-broadcast best-effort
            // (the node dedupes by tx id; a `stuck` attempt returns to `broadcast`
            // with a fresh mempool entry) and repair the projection REGARDLESS of the
            // re-broadcast outcome, because the body is already on the wire. A
            // re-broadcast failure here is never abandoned: the bytes may well still
            // be in a mempool, so only a settlement-deep conflicting spend kills them.
            AttemptStatus::Broadcast | AttemptStatus::Stuck => {
                if self.gateway.submit_tx(&attempt.signed_tx).await.is_ok() {
                    let _ = attempt::refresh_broadcast(&self.pool, attempt_id).await?;
                }
                self.repair_projection(record, &attempt).await?;
                self.nudge_confirm().await?;
                Ok(SubmitOutcome::AlreadyResolved)
            }
            // A `recorded` attempt never reached the wire (a crash between
            // record-before-broadcast and the broadcast, or a prior broadcast that
            // failed transiently). It must be broadcast SUCCESSFULLY before the record
            // can flip to `submitted` — the projection must never claim a transaction
            // is on the wire when the broadcast failed. On success, mark broadcast and
            // flip; on failure, classify it (cooldown defer / deterministic abandon /
            // transient retry) exactly as a first broadcast would, leaving the record
            // `submitting` for the next attempt or a terminal refund.
            AttemptStatus::Recorded => {
                match self.gateway.submit_tx(&attempt.signed_tx).await {
                    Ok(accepted) if accepted == attempt.tx_hash => {
                        let _ = attempt::mark_broadcast(&self.pool, attempt_id).await?;
                        let flipped = self.mark_broadcast_and_flip(record, attempt_id).await?;
                        if !flipped {
                            return Ok(SubmitOutcome::AlreadyResolved);
                        }
                        self.nudge_confirm().await?;
                        Ok(SubmitOutcome::Submitted {
                            tx_hash: attempt.tx_hash,
                            spent_inputs: attempt
                                .spent_inputs
                                .iter()
                                .map(AttemptInput::utxo_ref)
                                .collect::<Result<_>>()?,
                            fee_lovelace: Some(attempt.fee_lovelace),
                        })
                    }
                    // A mismatched echoed id is a provider anomaly, not a body
                    // problem: the recorded bytes are correct, so leave the attempt
                    // in-flight for the confirm authority rather than refunding.
                    Ok(_) => Ok(SubmitOutcome::RecordedInFlight),
                    Err(e) => {
                        // A resume RE-broadcast: the recorded bytes may have
                        // reached the wire on an earlier delivery, so an
                        // affirmative absence must be corroborated by the
                        // attempt's age before it can drive a refund.
                        self.classify_broadcast_failure(
                            record, attempt_id, &e, /* require_absence_corroboration */ true,
                        )
                        .await
                    }
                }
            }
            // A terminal or superseded attempt: this generation is done.
            AttemptStatus::Confirmed | AttemptStatus::Abandoned | AttemptStatus::Superseded => {
                Ok(SubmitOutcome::AlreadyResolved)
            }
        }
    }

    /// Repair the record projection for an on-the-wire attempt: the guarded
    /// `submitting -> submitted` flip from the attempt's coordinates, appending the
    /// `submitted` event ONLY when the flip affects a row (so a record already
    /// `submitted`, or one a racing generation moved, yields no duplicate event).
    async fn repair_projection(
        &self,
        record: &PoeRecordRow,
        attempt: &crate::chain::attempt::ChainAttempt,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let flipped = self
            .flip_to_submitted(
                &mut tx, record.id, attempt, /* require_submitting */ true,
            )
            .await?;
        if flipped {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        Ok(())
    }

    /// Flip the record to `submitted` from its broadcast attempt: the guarded
    /// projection copy from the attempt, keyed on `current_attempt_id = $attempt`,
    /// plus exactly one `submitted` event in the same transaction. Returns whether
    /// the flip affected a row (a zero-row flip is a lost generation: no event, and
    /// the outcome is AlreadyResolved).
    async fn mark_broadcast_and_flip(
        &self,
        record: &PoeRecordRow,
        attempt_id: Uuid,
    ) -> Result<bool> {
        let Some(attempt) = attempt::load_attempt(&self.pool, attempt_id).await? else {
            return Ok(false);
        };
        let mut tx = self.pool.begin().await?;
        let flipped = self
            .flip_to_submitted(
                &mut tx, record.id, &attempt, /* require_submitting */ false,
            )
            .await?;
        if flipped {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        Ok(flipped)
    }

    /// The shared guarded `submitted` flip + conditional event over a record's
    /// current attempt, used by both the live broadcast path and the crash-window
    /// projection repair.
    ///
    /// The flip is guarded on `current_attempt_id = $attempt` so a record whose
    /// pointer a racing generation moved updates zero rows and appends no event.
    /// `require_submitting` narrows the guard to `status = 'submitting'` for the
    /// crash-window repair (so a record already `submitted` is a true no-op, not a
    /// re-flip), while the live path admits `submitting`/`submitted` so a redelivery
    /// that re-marks `submitted` is idempotent. The projection columns
    /// (tx_hash / fee / spent_inputs) are copied from the attempt — the attempt
    /// ledger is the source, the record carries the projection.
    async fn flip_to_submitted(
        &self,
        tx: &mut sqlx::PgConnection,
        record_id: Uuid,
        attempt: &crate::chain::attempt::ChainAttempt,
        require_submitting: bool,
    ) -> Result<bool> {
        let spent_json = serde_json::to_value(&attempt.spent_inputs)?;
        let fee = i64::try_from(attempt.fee_lovelace).map_err(|_| {
            Error::Config(format!("fee {} does not fit in i64", attempt.fee_lovelace))
        })?;
        // Two static queries, selected by the caller's contract, so no SQL string is
        // ever built at runtime: the crash-window repair narrows the guard to
        // `submitting` (a record already `submitted` is a true no-op, not a re-flip),
        // while the live broadcast path admits `submitting`/`submitted` so a
        // redelivery that re-marks `submitted` is idempotent.
        let update = if require_submitting {
            "UPDATE cw_core.poe_record \
             SET status = 'submitted', tx_hash = $2, actual_fee_lovelace = $3, spent_inputs = $4 \
             WHERE id = $1 AND current_attempt_id = $5 AND status = 'submitting'"
        } else {
            "UPDATE cw_core.poe_record \
             SET status = 'submitted', tx_hash = $2, actual_fee_lovelace = $3, spent_inputs = $4 \
             WHERE id = $1 AND current_attempt_id = $5 AND status IN ('submitting', 'submitted')"
        };
        let flipped = sqlx::query(update)
            .bind(record_id)
            .bind(attempt.tx_hash.as_slice())
            .bind(fee)
            .bind(spent_json)
            .bind(attempt.id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            == 1;

        if flipped {
            let detail = serde_json::json!({
                "tx_hash": hex::encode(attempt.tx_hash),
                "wallet_id": attempt.wallet_id,
                "fee_lovelace": attempt.fee_lovelace,
            });
            crate::events::append_subject_event(
                tx,
                "poe_record",
                &record_id.to_string(),
                "submitted",
                &detail,
            )
            .await?;
        }
        Ok(flipped)
    }

    /// Classify a broadcast failure for a recorded attempt: a provider cooldown is
    /// a defer; a deterministic node reject abandons-with-restore, but ONLY once a
    /// fresh chain lookup proves the attempt's own transaction absent (a reject of
    /// a re-broadcast is exactly what a node answers when the same bytes already
    /// landed and their inputs are now spent — by themselves); any other failure
    /// leaves the recorded attempt in-flight for the confirm authority (the body
    /// may have reached a node, so the inputs stay reserved — it is abandoned only
    /// on a settlement-deep conflicting spend).
    ///
    /// `require_absence_corroboration` says which entry classified the failure.
    /// `false` is the genuine FIRST broadcast (submit_locked's own just-recorded
    /// attempt, first wire contact): an affirmative absence there refunds
    /// immediately — the bytes were never on the wire before, so self-landing is
    /// impossible. The failover gateway preserves that premise inside a single
    /// call: a secondary's deterministic reject that followed a failed
    /// (ambiguous) primary attempt is downgraded to a transient class before it
    /// ever reaches this classifier, so a reject classified here as
    /// deterministic was provably the outcome of the bytes' only wire contact.
    /// `true` is the RESUME re-broadcast, where an affirmative
    /// absence must additionally be corroborated by the attempt outliving
    /// [`INDEXER_ABSENCE_HORIZON`]: a young absence can be the provider's indexer
    /// lagging its own node on a self-landed transaction, so it defers instead
    /// of refunding.
    async fn classify_broadcast_failure(
        &self,
        record: &PoeRecordRow,
        attempt_id: Uuid,
        error: &Error,
        require_absence_corroboration: bool,
    ) -> Result<SubmitOutcome> {
        if let Some(until) = cooldown_until(error) {
            // The recorded attempt stays `recorded`; a retry re-broadcasts it. A
            // cooldown defer consumes no attempt.
            return Ok(SubmitOutcome::Failed {
                error: SubmitError::OutboundCooldown { until },
            });
        }

        if is_deterministic_node_reject(error) {
            // The node refused the body: no node will ACCEPT this transaction from
            // here on. That is NOT proof it never landed — a re-broadcast of bytes
            // that already confirmed is rejected precisely because their inputs
            // are now spent, by themselves. How to proceed depends on which
            // attempt this is:
            //
            //   - A FIRST submit (no superseded sibling) abandons-and-refunds, but
            //     ONLY once a fresh lookup proves the attempt's OWN transaction
            //     absent from chain. An earlier broadcast that failed transiently
            //     to OUR view may still have reached a relay and confirmed; the
            //     retry's reject is then the transaction conflicting with itself,
            //     and refunding would pay the customer back for a landed publish
            //     while handing its on-chain-spent inputs back to the pool.
            //   - A cancelling REPLACEMENT (replaces_tx_hash set) must NOT refund: the
            //     superseded original it cancels is still a live, reconcilable
            //     broadcaster that can confirm. A "body already spent / ledger-invalid"
            //     reject of a replacement is in fact the EXPECTED signal when the
            //     original is sitting in a mempool or has re-landed (the replacement
            //     re-spends the original's input by construction). Refunding here would
            //     refund the customer AND still let the original anchor the PoE: a
            //     double-spend of money and a free publish. Instead, abandon the
            //     replacement, restore only ITS exclusive inputs, and hand the record
            //     back to the still-live original so the confirm authority can carry it
            //     to confirmed or terminalise it through the real proof-gated path.
            let attempt = attempt::load_attempt(&self.pool, attempt_id).await?;
            if let Some(attempt) = attempt {
                if let Some(original_tx_hash) = attempt.replaces_tx_hash {
                    self.abandon_replacement_restore_original(
                        record,
                        &attempt,
                        &original_tx_hash,
                        error,
                    )
                    .await?;
                    return Ok(SubmitOutcome::Failed {
                        error: SubmitError::NodeRejected {
                            detail: error.to_string(),
                        },
                    });
                }

                match self.attempt_tx_presence(&attempt.tx_hash).await {
                    // Self-landed: the rejected re-broadcast is the transaction
                    // conflicting with ITSELF. Treat it exactly like a broadcast
                    // that succeeded — advance the attempt, repair the record
                    // projection, and hand it to the confirm authority. No refund,
                    // no input restore: the inputs are spent on chain by this very
                    // transaction.
                    Ok(TxPresence::OnChain) => {
                        let _ = attempt::mark_broadcast(&self.pool, attempt.id).await?;
                        self.repair_projection(record, &attempt).await?;
                        self.nudge_confirm().await?;
                        return Ok(SubmitOutcome::AlreadyResolved);
                    }
                    // AFFIRMATIVELY absent. On a RESUME that is still not enough:
                    // the very indexer answering can lag the node that rejected
                    // the re-broadcast (a self-landed transaction's block adopted
                    // but not yet indexed), and that lag answers "no record" too.
                    // A young attempt therefore defers exactly like an
                    // inconclusive lookup and lets a later pass re-observe; only
                    // an absence the attempt's age corroborates — or a genuine
                    // FIRST broadcast, where self-landing is impossible — falls
                    // through to the abandon-and-refund below.
                    Ok(TxPresence::Absent) => {
                        if require_absence_corroboration
                            && !absence_horizon_elapsed(attempt.created_at)
                        {
                            return Ok(SubmitOutcome::RecordedInFlight);
                        }
                    }
                    // A positive-but-incomplete observation (a status endpoint
                    // counted the transaction while the detail endpoint lagged,
                    // exactly the shape our own just-confirmed transaction
                    // produces mid-hydration), or a failed lookup (provider down,
                    // rate-limited): absence is unproven, and a refund must never
                    // ride an inconclusive observation. Leave the attempt
                    // recorded, exactly like a transient broadcast failure; a
                    // later retry re-evaluates with a fresh lookup.
                    Ok(TxPresence::Inconclusive) | Err(_) => {
                        return Ok(SubmitOutcome::RecordedInFlight)
                    }
                }
            }
            // A proven-absent first submit (or an attempt that has since vanished):
            // the abandon-and-refund, safe because no superseded sibling can still
            // land and the attempt's own transaction is not on chain.
            self.abandon_recorded_attempt(record, attempt_id, error)
                .await?;
            return Ok(SubmitOutcome::Failed {
                error: SubmitError::NodeRejected {
                    detail: error.to_string(),
                },
            });
        }

        // Transient / ambiguous: leave the recorded attempt in-flight. The body may
        // have reached a node, so the inputs stay reserved to the recorded attempt
        // and it is NEVER refunded here — only a settlement-deep conflicting spend
        // can abandon it. The job retries the re-broadcast; once its attempts are
        // exhausted, the recorded attempt persists for the confirm authority and the
        // operator-reconcile path.
        Ok(SubmitOutcome::RecordedInFlight)
    }

    /// The presence verdict for an attempt's OWN transaction, from a fresh
    /// gateway lookup.
    ///
    /// This is the gate in front of the only abandon-with-restore not driven by a
    /// settlement-deep conflicting spend. A deterministic node reject proves the
    /// body cannot be ACCEPTED now — not that it never landed: when an earlier
    /// broadcast reached a relay despite failing to our view and the transaction
    /// confirmed, a re-broadcast of the same bytes is rejected precisely because
    /// its inputs are already spent, by itself. Abandoning on the reject alone
    /// would refund a landed publish and hand on-chain-spent inputs back to the
    /// pool as `available`.
    ///
    /// The verdict is three-way ([`TxPresence`]), and the caller must treat only
    /// [`TxPresence::Absent`] — the provider's AFFIRMATIVE "no such
    /// transaction" — as licence to abandon and refund.
    /// [`TxPresence::Inconclusive`] covers exactly the shape a just-confirmed
    /// transaction produces while the provider is mid-hydration (a status count
    /// whose detail row lags): reading that window as absence would re-open the
    /// self-landed refund. A provider answer that omits the requested hash
    /// violates the batched-lookup contract (every requested hash appears in the
    /// map), so it is an error the caller treats like an inconclusive lookup —
    /// never as absence.
    async fn attempt_tx_presence(&self, tx_hash: &[u8; 32]) -> Result<TxPresence> {
        let observed = self
            .gateway
            .get_tx_confirmations(std::slice::from_ref(tx_hash))
            .await?;
        match observed.get(tx_hash) {
            Some(obs) => Ok(obs.presence()),
            None => Err(Error::ChainProvider(
                "the confirmation lookup omitted the requested transaction".to_string(),
            )),
        }
    }

    /// Abandon a recorded attempt the node rejected deterministically AND refund its
    /// record, in ONE transaction under the wallet advisory lock the caller already
    /// holds (lock order attempt -> record -> wallet): mark the attempt `abandoned`
    /// with the reject evidence, clear the record's pointer to it, restore its inputs
    /// to `available`, tombstone its (uncreated) change output, and terminalise the
    /// record with its single refund.
    ///
    /// Caller contract: the attempt's own transaction has been PROVEN absent from
    /// chain by a fresh lookup (or the attempt row vanished before anything could
    /// broadcast), and on a resume re-broadcast the attempt has additionally
    /// outlived [`INDEXER_ABSENCE_HORIZON`]. A deterministic reject alone is not
    /// that proof — the same reject answers a re-broadcast of bytes that already
    /// landed — and restoring inputs a landed transaction spent would corrupt the
    /// wallet accounting while refunding a delivered publish.
    ///
    /// The abandon and the refund are one atomic transaction precisely BECAUSE the
    /// abandoned attempt's deterministic tx_hash stays in the ledger: a crash that
    /// abandoned the attempt but left the record un-refunded could not be recovered
    /// by a redelivery, because the rebuild would produce the identical tx_hash and
    /// collide on the unique index. Committing both together closes that window.
    async fn abandon_recorded_attempt(
        &self,
        record: &PoeRecordRow,
        attempt_id: Uuid,
        error: &Error,
    ) -> Result<()> {
        let Some(attempt) = attempt::load_attempt(&self.pool, attempt_id).await? else {
            return Ok(());
        };

        let mut tx = self.pool.begin().await?;

        // Only proceed when THIS call actually transitioned the attempt to
        // abandoned: a zero-row abandon means a racing path already terminalised
        // it (confirmed it, or abandoned it via a settlement-deep conflict), and
        // the record pointer, the inputs, and any refund must follow that path's
        // decision, not this stale one. The wallet advisory lock makes the race
        // unlikely, but the guard makes the discipline explicit — the same one
        // the split abandon applies.
        let abandoned = attempt::mark_abandoned_in_tx(&mut tx, attempt_id).await?;
        if !abandoned {
            tx.rollback().await?;
            return Ok(());
        }
        // Stamp the deterministic-reject evidence so the transition is auditable:
        // it rides the attempt's subject events so an operator can trace the
        // node-reject abandon distinctly from an abandon driven by a confirmed
        // conflicting spend.
        let evidence = serde_json::json!({
            "reason": "node_rejected",
            "detail": error.to_string(),
        });
        crate::events::append_subject_event(
            &mut tx,
            "chain_attempt",
            &attempt_id.to_string(),
            "attempt_abandoned",
            &evidence,
        )
        .await?;

        // Clear the record's pointer to the dead attempt.
        sqlx::query(
            "UPDATE cw_core.poe_record SET current_attempt_id = NULL \
             WHERE id = $1 AND current_attempt_id = $2",
        )
        .bind(record.id)
        .bind(attempt_id)
        .execute(&mut *tx)
        .await?;

        // Restore the attempt's inputs — the caller proved this attempt's own
        // transaction absent from chain, so nothing of it spent them — and
        // tombstone its uncreated change output.
        let refs: Vec<UtxoRef> = attempt
            .spent_inputs
            .iter()
            .map(AttemptInput::utxo_ref)
            .collect::<Result<_>>()?;
        utxo::restore_inputs_in_tx(&mut tx, attempt.wallet_id, &refs).await?;
        utxo::tombstone_outputs_in_tx(&mut tx, attempt.wallet_id, attempt.tx_hash).await?;

        // Terminalise the record with its single refund in the SAME transaction (the
        // deterministic reject is terminal: no node can ever accept the body).
        let refund_detail = serde_json::json!({ "detail": error.to_string() });
        crate::chain::confirm::record_permanent_failure_in_tx(
            &mut tx,
            record.id,
            RefundReason::NodeRejected,
            &refund_detail,
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Terminalise a cancelling REPLACEMENT the node rejected deterministically
    /// WITHOUT refunding, handing the record back to the still-live original it
    /// superseded, in ONE transaction under the wallet advisory lock the caller holds.
    ///
    /// A replacement re-spends an input of the original it cancels by construction,
    /// so an "input already spent" / ledger-invalid reject is the EXPECTED outcome
    /// when the original is sitting in a mempool or has re-landed: it is NOT proof the
    /// record can never anchor. The original is still a live, reconcilable broadcaster
    /// (the rollback handoff left it active precisely so it can confirm before the
    /// replacement). Refunding here, like a first submit does, would refund the
    /// customer while the original can still anchor the PoE on chain: a double-spend
    /// of money and a free publish. So this arm, in one atomic transaction:
    ///
    ///   1. abandons the replacement (it leaves the active-broadcaster set FIRST, so
    ///      the one-active-per-record index never sees two active brokers when the
    ///      original re-enters it below),
    ///   2. clears the record's pointer to the replacement,
    ///   3. restores the replacement's EXCLUSIVE inputs (the inputs it spent that the
    ///      original did not) to `available`; the SHARED inputs stay
    ///      `pending_spent`/`confirmed_spent` as the original's reservation,
    ///   4. tombstones the replacement's (uncreated) change output,
    ///   5. un-supersedes the original back to the active-broadcaster set and points
    ///      the record at it, leaving the record non-terminal (`submitted`) so the
    ///      confirm authority carries the original to `confirmed` or terminalises it
    ///      through the real settlement-deep proof.
    ///
    /// No refund is written: termination of the record stays gated on a real proof of
    /// death, never on the replacement's reject alone. If the original has already
    /// moved on (a racing confirm/abandon left it no longer `superseded` by this
    /// replacement), the un-supersede affects zero rows: the replacement is still
    /// abandoned and its exclusive inputs restored, but the record's pointer is
    /// instead cleared (not pointed at a stale original), leaving it non-terminal for
    /// the confirm authority to own. No money or PoE-anchoring decision is made here
    /// in that case either.
    async fn abandon_replacement_restore_original(
        &self,
        record: &PoeRecordRow,
        replacement: &crate::chain::attempt::ChainAttempt,
        original_tx_hash: &[u8; 32],
        error: &Error,
    ) -> Result<()> {
        let original = attempt::load_attempt_by_tx_hash(&self.pool, original_tx_hash).await?;

        let mut tx = self.pool.begin().await?;

        // (1) Abandon the replacement FIRST so it leaves the active-broadcaster set
        //     before the original re-enters it, stamping the deterministic-reject
        //     evidence so the transition is auditable.
        let evidence = serde_json::json!({
            "reason": "node_rejected_replacement",
            "detail": error.to_string(),
        });
        sqlx::query(
            "UPDATE cw_core.chain_attempt \
             SET status = 'abandoned', block_height = NULL, block_time = NULL, \
                 updated_at = now() \
             WHERE id = $1 AND status NOT IN ('confirmed', 'abandoned')",
        )
        .bind(replacement.id)
        .execute(&mut *tx)
        .await?;
        crate::events::append_subject_event(
            &mut tx,
            "chain_attempt",
            &replacement.id.to_string(),
            "attempt_abandoned",
            &evidence,
        )
        .await?;

        // (2) Clear the record's pointer to the dead replacement so the generation
        //     slot is free to re-point at the original below.
        sqlx::query(
            "UPDATE cw_core.poe_record SET current_attempt_id = NULL \
             WHERE id = $1 AND current_attempt_id = $2",
        )
        .bind(record.id)
        .bind(replacement.id)
        .execute(&mut *tx)
        .await?;

        // (3) Restore ONLY the replacement's exclusive inputs (those it spent that the
        //     original did not). A shared input the original also spends stays in its
        //     spent state as the original's reservation, so the still-live original
        //     keeps exclusive hold of it and no fresh claim can double-spend it.
        let exclusive = exclusive_inputs(replacement, original.as_ref())?;
        utxo::restore_inputs_in_tx(&mut tx, replacement.wallet_id, &exclusive).await?;

        // (4) Tombstone the replacement's (never-created) change output so no stale
        //     `change`-sourced row lingers for a transaction that never landed.
        utxo::tombstone_outputs_in_tx(&mut tx, replacement.wallet_id, replacement.tx_hash).await?;

        // (5) Hand the record back to the still-live original, leaving it non-terminal.
        //     Guarded so it only fires when the original is exactly the one this
        //     replacement superseded; otherwise the original already moved on and the
        //     record is left with a cleared pointer for the confirm authority.
        if let Some(original) = original.as_ref() {
            let restored = attempt::unsupersede_in_tx(&mut tx, original.id, replacement.id).await?;
            if restored {
                // Re-point the record at the original and keep it `submitted`. The
                // generation slot was cleared in (2), so this re-claims it. Guarded on
                // the record still being live and pointer-free so a racing generation
                // never has its pointer overwritten.
                sqlx::query(
                    "UPDATE cw_core.poe_record \
                     SET current_attempt_id = $2, status = 'submitted' \
                     WHERE id = $1 AND current_attempt_id IS NULL \
                       AND status IN ('submitting', 'submitted')",
                )
                .bind(record.id)
                .bind(original.id)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    /// Resume a stranded `kind='split'` attempt by re-broadcasting its durable
    /// recorded bytes, under the wallet advisory lock, never minting a second
    /// transaction.
    ///
    /// A split records before broadcast exactly like a publish, so a broadcast that
    /// never reached the wire (a crash, a transport error, an ambiguous submit, an
    /// echo mismatch) leaves it `recorded` with `mempool_entered_at` NULL. No confirm
    /// loader sees such a row, and a split has no record and so no record-keyed
    /// recovery — its source would sit `pending_spent` forever, shrinking the wallet.
    /// The recovery sweep re-enqueues this resume, which re-sends the recorded bytes
    /// (the node dedupes by tx id): on a matching echo it marks the attempt
    /// `broadcast` so the confirm authority owns it; on a deterministic reject it
    /// abandons the attempt and restores its source, but only once a fresh lookup
    /// proves the split's own transaction absent from chain (the same reject
    /// answers a re-broadcast of bytes that already landed) AND the attempt has
    /// outlived [`INDEXER_ABSENCE_HORIZON`] (a younger absence can be indexer lag
    /// on a self-landed split); on a transient/ambiguous failure — or an
    /// inconclusive lookup, or an uncorroborated young absence — it leaves the
    /// attempt recorded for the next sweep.
    async fn handle_split_resume(&self, job: &SplitResumeJob) -> JobOutcome {
        match self.resume_split_attempt(job.split_attempt_id).await {
            Ok(()) => JobOutcome::Complete,
            Err(e) => JobOutcome::Fail {
                error: crate::runtime::JobError::new("split_resume_error", e.to_string()),
            },
        }
    }

    async fn resume_split_attempt(&self, attempt_id: Uuid) -> Result<()> {
        use crate::chain::attempt::{AttemptKind, AttemptStatus};

        // A cheap pre-load only to find the wallet to lock; the authoritative re-check
        // happens AFTER the lock so a racing worker that already advanced this attempt
        // (marked it broadcast, abandoned it) cannot drive a re-broadcast/abandon from
        // stale state.
        let Some(pre) = attempt::load_attempt(&self.pool, attempt_id).await? else {
            return Ok(());
        };
        if pre.kind != AttemptKind::Split {
            // A non-split id is a payload bug the sweep never produces.
            return Ok(());
        }

        // Take the wallet advisory lock so the re-broadcast and any abandon-with-
        // restore serialise with live submits/splits on the same wallet (the abandon
        // restores the source through the same fenced state machine a submit uses).
        let Some(lock) = try_lock_wallet(&self.pool, pre.wallet_id).await? else {
            // Another worker holds the wallet; the next sweep pass retries.
            return Ok(());
        };

        // Re-load UNDER the lock and re-validate: only a still-`recorded` split is
        // resumable. A split a concurrent worker advanced to broadcast/abandoned/
        // confirmed between the pre-load and the lock is owned by that worker or the
        // confirm authority; acting on the stale snapshot would re-broadcast or abandon
        // from a state that no longer holds.
        let result = match attempt::load_attempt(&self.pool, attempt_id).await? {
            Some(attempt)
                if attempt.kind == AttemptKind::Split
                    && attempt.status == AttemptStatus::Recorded =>
            {
                self.resume_split_locked(&attempt).await
            }
            _ => Ok(()),
        };
        let _ = lock.release().await;
        result
    }

    /// Re-broadcast a recorded split's bytes with the wallet lock held, classifying
    /// the broadcast outcome exactly as the replenish split path does on its first
    /// broadcast.
    async fn resume_split_locked(
        &self,
        attempt: &crate::chain::attempt::ChainAttempt,
    ) -> Result<()> {
        match self.gateway.submit_tx(&attempt.signed_tx).await {
            // A matching echo: the body is on the wire. Mark it `broadcast` so the
            // confirm authority's mempool reconcile owns it from here.
            Ok(accepted) if accepted == attempt.tx_hash => {
                let _ = attempt::mark_broadcast(&self.pool, attempt.id).await?;
                self.nudge_confirm().await?;
                Ok(())
            }
            // A mismatched echoed id is a provider anomaly, not a body problem: leave
            // the attempt recorded for the next sweep (the recorded bytes are correct).
            Ok(_) => Ok(()),
            Err(e) => {
                if cooldown_until(&e).is_some() {
                    // A provider cooldown: leave it recorded; the next sweep retries.
                    return Ok(());
                }
                if is_deterministic_node_reject(&e) {
                    // The node refused the body — but a reject of a RE-broadcast is
                    // also what a node answers when these exact bytes already landed
                    // and their inputs are now spent, by themselves. Only a fresh
                    // lookup proving the split's own transaction absent makes the
                    // abandon safe: restoring a source the split spent ON CHAIN
                    // would hand a spent UTxO back to the pool.
                    return match self.attempt_tx_presence(&attempt.tx_hash).await {
                        // Self-landed: the split is on the wire after all. Mark it
                        // broadcast so the confirm authority owns it; confirmation
                        // promotes the minted outputs, and the source stays
                        // `pending_spent` — never restored.
                        Ok(TxPresence::OnChain) => {
                            let _ = attempt::mark_broadcast(&self.pool, attempt.id).await?;
                            self.nudge_confirm().await?;
                            Ok(())
                        }
                        // AFFIRMATIVELY absent. A split resume is always a
                        // RE-broadcast, so the absence still needs the attempt's
                        // age as corroboration: a young "no record" can be the
                        // provider's indexer lagging its own node on a
                        // self-landed split. Only a corroborated absence abandons
                        // the split and restores its source in one transaction (a
                        // split has no record, so there is no refund — only the
                        // source returns to the pool and the minted outputs are
                        // tombstoned); a young absence leaves it recorded for the
                        // next sweep to re-observe.
                        Ok(TxPresence::Absent) => {
                            if absence_horizon_elapsed(attempt.created_at) {
                                self.abandon_split_attempt(attempt, &e).await?;
                            }
                            Ok(())
                        }
                        // A positive-but-incomplete observation (the provider is
                        // mid-hydration on our own just-landed split) or a failed
                        // lookup: absence is unproven, so leave the split recorded
                        // (source reserved) for the next sweep to re-evaluate.
                        // Never restore on an inconclusive observation.
                        Ok(TxPresence::Inconclusive) | Err(_) => Ok(()),
                    };
                }
                // Transient/ambiguous: the body may have reached a node, so the source
                // stays reserved and the attempt stays recorded for the next sweep.
                Ok(())
            }
        }
    }

    /// Abandon a recorded split the node rejected deterministically, restoring its
    /// source and tombstoning its (uncreated) minted outputs, in ONE transaction
    /// under the wallet advisory lock the caller holds.
    ///
    /// Mirrors the replenish path's split abandon: a split has no record and no
    /// refund, so the abandon restores the source input to `available` (the caller
    /// proved the split's own transaction absent from chain, so nothing of it
    /// spent the source) and deletes the minted `change`-sourced rows that never
    /// existed on chain.
    async fn abandon_split_attempt(
        &self,
        attempt: &crate::chain::attempt::ChainAttempt,
        error: &Error,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let evidence = serde_json::json!({
            "reason": "node_rejected",
            "detail": error.to_string(),
        });
        // Only restore the source if THIS call actually transitioned the attempt to
        // abandoned: a zero-row abandon means a racing path already terminalised it
        // (confirmed it, or abandoned it via a settlement-deep conflict), and its
        // source must follow that path's decision, not this stale one. Restoring on a
        // lost race could free a source another transaction now legitimately spends.
        let abandoned = attempt::mark_abandoned_in_tx(&mut tx, attempt.id).await?;
        if !abandoned {
            tx.rollback().await?;
            return Ok(());
        }
        crate::events::append_subject_event(
            &mut tx,
            "chain_attempt",
            &attempt.id.to_string(),
            "attempt_abandoned",
            &evidence,
        )
        .await?;

        let refs: Vec<UtxoRef> = attempt
            .spent_inputs
            .iter()
            .map(AttemptInput::utxo_ref)
            .collect::<Result<_>>()?;
        utxo::restore_inputs_in_tx(&mut tx, attempt.wallet_id, &refs).await?;
        utxo::tombstone_outputs_in_tx(&mut tx, attempt.wallet_id, attempt.tx_hash).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Nudge the confirmation loop so a freshly submitted record is reconciled
    /// promptly, deduped so a flood of submits does not pile up redundant wakeups.
    async fn nudge_confirm(&self) -> Result<()> {
        let opts = EnqueueOptions {
            singleton_key: Some(CONFIRM_QUEUE.to_string()),
            ..EnqueueOptions::default()
        };
        // A dedupe collision (the loop is already scheduled) is a successful no-op.
        let _ = enqueue_dedupe(&self.pool, CONFIRM_QUEUE, &serde_json::Value::Null, opts).await?;
        Ok(())
    }

    /// Release every lease back to `available`, fenced on each token. Best-effort:
    /// a release that no longer matches (the lease was reaped) is a harmless no-op.
    async fn release_leases(&self, wallet_id: Uuid, leases: &[UtxoLease]) {
        for lease in leases {
            let _ = utxo::release(&self.pool, wallet_id, lease.utxo, lease.lease_token).await;
        }
    }
}

/// A built, signed transaction and the leases it spends, computed once in the
/// build path and recorded verbatim: the recorded `signed_tx` is the exact bytes
/// broadcast and re-broadcast, so the broadcaster never sends an un-recorded
/// transaction.
struct BuiltTransaction<'a> {
    /// The deterministic build result (tx id, fee, change).
    built: &'a cardano_poe_tx::BuiltPoeTx,
    /// The signed bytes that go on the wire and are recorded on the attempt.
    signed_tx: &'a [u8],
    /// The wallet leases the transaction spends (the canonical input plus any
    /// forced replacement inputs).
    leases: &'a [UtxoLease],
    /// The leased inputs with their fencing tokens, for the wallet-state apply.
    spent_inputs: &'a [SpentInput],
}

/// The outcome of the record-before-broadcast transaction.
enum RecordedAttempt {
    /// The attempt was recorded; broadcast may proceed against this id.
    Recorded(Uuid),
    /// This job lost the chain-generation race for the record (the record guard or
    /// the one-active unique index rejected it). The record is already resolved by
    /// another generation; do NOT broadcast.
    LostGeneration,
    /// A cancelling replacement's inputs do not intersect the superseded original's,
    /// so it would not cancel it. Never recorded, never broadcast; terminal.
    ReplacementDoesNotConflict {
        /// What the intersection check found.
        detail: String,
    },
}

/// The outcome of the supersede half of the atomic replacement handoff.
enum SupersedeOutcome {
    /// The original was superseded and the record pointer cleared; record the
    /// replacement.
    Superseded,
    /// No live original to supersede (already terminalised or never recorded): a
    /// lost race.
    NoLiveOriginal,
    /// The replacement re-spends none of the original's inputs.
    DoesNotConflict {
        /// What the intersection check found.
        detail: String,
    },
}

/// The references a replacement spent that the original it cancels did NOT, decoded
/// to [`UtxoRef`]s.
///
/// When a cancelling replacement dies, only these exclusive inputs may return to
/// `available`: a SHARED input (one the original also spends) must stay in its spent
/// state as the still-live original's reservation, so the original keeps exclusive
/// hold of it and no fresh claim can double-spend it. With no original (it already
/// vanished), every replacement input is exclusive.
fn exclusive_inputs(
    replacement: &crate::chain::attempt::ChainAttempt,
    original: Option<&crate::chain::attempt::ChainAttempt>,
) -> Result<Vec<UtxoRef>> {
    let shared = original.map(|o| o.spent_inputs.as_slice()).unwrap_or(&[]);
    replacement
        .spent_inputs
        .iter()
        .filter(|input| {
            !shared
                .iter()
                .any(|s| s.index == input.index && s.tx_hash == input.tx_hash)
        })
        .map(AttemptInput::utxo_ref)
        .collect()
}

/// Whether two attempt input sets intersect on at least one `(tx_hash, index)`
/// reference. The cancelling-replacement invariant rests on the replacement
/// re-spending an original input, so this is the gateway-enforced verification of
/// it (rather than trusting the build path produced a conflict).
fn inputs_intersect(left: &[AttemptInput], right: &[AttemptInput]) -> bool {
    left.iter().any(|l| {
        right
            .iter()
            .any(|r| r.index == l.index && r.tx_hash == l.tx_hash)
    })
}

/// Parse the `replacement_for` transaction hash a cancelling replacement carries
/// into the attempt's `replaces_tx_hash`. `None` for a first submit.
fn parse_replacement_tx_hash(job: &SubmitJob) -> Result<Option<[u8; 32]>> {
    let Some(hex_hash) = job.replacement_for.as_deref() else {
        return Ok(None);
    };
    let raw = hex::decode(hex_hash)
        .map_err(|_| Error::Config(format!("replacement_for is not hex: {hex_hash}")))?;
    let hash: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| Error::Config(format!("replacement_for is not 32 bytes: {hex_hash}")))?;
    Ok(Some(hash))
}

/// Whether a database error is a unique-violation on the one-active-broadcaster
/// index (`chain_attempt_one_active_per_record`), i.e. a concurrent generation
/// already holds the record's single active-broadcaster slot. Any OTHER
/// unique-violation (the tx_hash key, a redelivery of the exact transaction)
/// surfaces as the same lost-generation outcome at the caller, since either way
/// this job must not broadcast a second transaction.
fn is_one_active_violation(err: &Error) -> bool {
    matches!(
        err,
        Error::Database(sqlx::Error::Database(db))
            if db.code().as_deref() == Some("23505")
    )
}

/// The submittable fields of a `poe_record`, loaded for one attempt.
#[derive(Debug, Clone)]
struct PoeRecordRow {
    /// The record's id.
    id: Uuid,
    /// The operator the record publishes under (the spend principal's operator).
    operator_id: Uuid,
    /// The tenant the record belongs to (the account anchor id). Carried onto
    /// events for tracing AND used to build the spend principal so an account
    /// grant can entitle the wallet. `None` for an operator-direct submit.
    account_id: Option<Uuid>,
    /// The canonical Label 309 record bytes.
    record_bytes: Vec<u8>,
    /// The wallet the record is pinned to, if any.
    pinned_wallet_id: Option<Uuid>,
    /// The attempt the record is currently riding, if any. A non-NULL value means
    /// an attempt is already recorded for this record: the idempotent retry path
    /// re-broadcasts it rather than building a fresh transaction.
    current_attempt_id: Option<Uuid>,
}

/// The spend principal a record submits as: an account principal when the record
/// carries an account (so an account grant can entitle the wallet), else an
/// operator-direct principal. Either way the principal's operator is the record's
/// operator, which the registrar match keys on.
fn spend_principal(record: &PoeRecordRow) -> SpendPrincipal {
    match record.account_id {
        Some(account_id) => SpendPrincipal::Account {
            operator_id: record.operator_id,
            account_id,
        },
        None => SpendPrincipal::Operator {
            operator_id: record.operator_id,
        },
    }
}

/// The row shape [`SubmitHandler::load_record`] reads back.
#[derive(sqlx::FromRow)]
struct RecordRow {
    id: Uuid,
    operator_id: Uuid,
    account_id: Option<Uuid>,
    record_bytes: Vec<u8>,
    wallet_id: Option<Uuid>,
    status: String,
    current_attempt_id: Option<Uuid>,
}

/// Build the cancelling replacement's forced-input set from a superseded original
/// attempt's recorded spent inputs, so the replacement is forced to re-spend at
/// least one of them (the conflict the at-most-one-lands invariant rests on). An
/// empty original input set yields an empty forced set; the submit handler treats
/// that as a degenerate replacement and surfaces the failure through its own
/// terminal path rather than silently double-publishing. Both the confirm loop's
/// rollback resubmit and the recovery sweep's replacement re-enqueue build their
/// `SubmitJob` forced inputs through this one helper.
pub(crate) fn forced_inputs_from_attempt(inputs: &[AttemptInput]) -> Vec<ForcedInput> {
    inputs
        .iter()
        .map(|i| ForcedInput {
            tx_hash: i.tx_hash.clone(),
            index: i.index,
            lovelace: i.lovelace,
        })
        .collect()
}

/// Decode the forced-input references a cancelling replacement must spend.
fn forced_input_refs(forced: &[ForcedInput]) -> Result<Vec<UtxoRef>> {
    forced
        .iter()
        .map(|f| {
            let raw = hex::decode(&f.tx_hash).map_err(|_| {
                Error::Config(format!("forced-input tx_hash is not hex: {}", f.tx_hash))
            })?;
            let tx_hash: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                Error::Config(format!(
                    "forced-input tx_hash is not 32 bytes: {}",
                    f.tx_hash
                ))
            })?;
            Ok(UtxoRef {
                tx_hash,
                output_index: f.index,
            })
        })
        .collect()
}

/// The change output a built transaction produced, recorded locally so the
/// wallet's balance is not understated between submit and confirmation. `None`
/// when the build folded all change into the fee.
fn change_output(built: &cardano_poe_tx::BuiltPoeTx) -> Option<ChangeOutput> {
    built.change.map(|lovelace| ChangeOutput {
        // The change output is the change index of the submit transaction; the
        // builder emits change at index 0 of its own outputs.
        utxo: UtxoRef {
            tx_hash: built.tx_hash,
            output_index: 0,
        },
        lovelace,
    })
}

/// Re-encode an unsigned transaction with a single vkey witness, returning the
/// signed-form bytes. The placeholder/real signature occupies the exact byte
/// budget the fee paid for, so the witnessed bytes are the bytes that go on the
/// wire.
fn witness_tx(
    unsigned_tx_bytes: &[u8],
    verification_key: [u8; 32],
    signature: &[u8; 64],
) -> Vec<u8> {
    let mut tx = ConwayTx::decode_fragment(unsigned_tx_bytes)
        .expect("a builder-produced transaction always re-decodes");
    let witness = pallas_primitives::conway::VKeyWitness {
        vkey: verification_key.to_vec().into(),
        signature: signature.to_vec().into(),
    };
    tx.transaction_witness_set.vkeywitness = Some(
        pallas_primitives::NonEmptySet::from_vec(vec![witness])
            .expect("a one-element witness set is never empty"),
    );
    tx.encode_fragment()
        .expect("a witnessed transaction always re-encodes")
}

/// Classify a chain-provider error as a cooldown defer, returning the instant the
/// cooldown lifts when it is one.
///
/// An all-provider rate-limit storm (every provider in the failover pair returned
/// 429, surfaced as [`Error::ChainRateLimitStorm`]) is a defer to exactly the
/// carried instant, without consuming an attempt. Every other error (a single
/// transport blip the failover already handled, a genuine exhaustion) is not a
/// cooldown and is classified as an exhausted gateway by the caller.
fn cooldown_until(error: &Error) -> Option<chrono::DateTime<chrono::Utc>> {
    match error {
        Error::ChainRateLimitStorm { cooldown_until } => Some(*cooldown_until),
        _ => None,
    }
}

impl<G: crate::chain::gateway::ChainGateway + 'static> JobHandler for SubmitHandler<G> {
    async fn handle(&self, ctx: JobContext) -> JobOutcome {
        // Two payload shapes ride this one queue. A split-recovery re-broadcast
        // carries `split_attempt_id` (which a record submit never has), so it parses
        // as a SplitResumeJob first; a record submit (publish/first or cancelling
        // replacement) parses as a SubmitJob. The discriminant is a required field on
        // SplitResumeJob, so a SubmitJob payload fails that parse and falls through.
        if let Ok(split) = serde_json::from_value::<SplitResumeJob>(ctx.payload.clone()) {
            return self.handle_split_resume(&split).await;
        }

        let job: SubmitJob = match serde_json::from_value(ctx.payload) {
            Ok(job) => job,
            Err(e) => {
                return JobOutcome::Fail {
                    error: crate::runtime::JobError::new(
                        "submit_payload_invalid",
                        format!("could not parse submit job payload: {e}"),
                    ),
                };
            }
        };

        match self.submit_once(&job, ctx.attempt).await {
            // The submit landed; the record is now `submitted`.
            Ok(SubmitOutcome::Submitted { .. }) => JobOutcome::Complete,

            // Nothing to do: the record was already resolved by a racing path.
            Ok(SubmitOutcome::AlreadyResolved) => JobOutcome::Complete,

            // The attempt is durably recorded but its broadcast failed transiently or
            // ambiguously. The recorded spend is never refunded here: retry the
            // re-broadcast while attempts remain, and once they are exhausted leave
            // the recorded attempt for the confirm authority (the body may be in a
            // mempool, so only a settlement-deep conflicting spend can abandon it).
            Ok(SubmitOutcome::RecordedInFlight) => {
                if ctx.is_final_attempt {
                    JobOutcome::Complete
                } else {
                    JobOutcome::Fail {
                        error: crate::runtime::JobError::new(
                            "submit_broadcast_in_flight",
                            "the attempt is recorded; the broadcast failed transiently, retry",
                        ),
                    }
                }
            }

            // A provider cooldown: the recorded attempt stays in-flight and a retry
            // re-broadcasts it. Defer to the cooldown instant WITHOUT consuming an
            // attempt.
            Ok(SubmitOutcome::Failed {
                error: SubmitError::OutboundCooldown { until },
            }) => JobOutcome::Defer { until },

            // Over-budget is immediately terminal: it can never succeed on retry.
            Ok(SubmitOutcome::Failed {
                error: SubmitError::ByteBudgetExceeded { size, max },
            }) => {
                self.terminate(
                    &job,
                    RefundReason::ByteBudgetExceeded,
                    byte_budget_detail(size, max),
                )
                .await
            }

            // A replacement with no usable forced inputs is immediately terminal:
            // it can never cancel the rolled-back transaction, and retrying would
            // never reconstruct the lost inputs.
            Ok(SubmitOutcome::Failed {
                error: SubmitError::ReplacementInputsMissing { detail },
            }) => {
                self.terminate(
                    &job,
                    RefundReason::ReplacementInputsMissing,
                    serde_json::json!({ "detail": detail }),
                )
                .await
            }

            // A non-conflicting replacement is immediately terminal: it was never
            // recorded or broadcast (the intersection check aborted it), so it can
            // never cancel its original and retrying would not change that.
            Ok(SubmitOutcome::Failed {
                error: SubmitError::ReplacementDoesNotConflict { detail },
            }) => {
                self.terminate(
                    &job,
                    RefundReason::ReplacementDoesNotConflict,
                    serde_json::json!({ "detail": detail }),
                )
                .await
            }

            // A deterministic node reject already abandoned the recorded attempt,
            // restored its inputs, AND refunded the record in one atomic transaction
            // (abandon-and-refund are committed together so the deterministic tx_hash
            // can never strand a record). No node can accept the body, so the job is
            // simply complete.
            Ok(SubmitOutcome::Failed {
                error: SubmitError::NodeRejected { .. },
            }) => JobOutcome::Complete,

            // Build/gateway failures refund only at the final attempt; earlier
            // attempts retry via the queue policy.
            Ok(SubmitOutcome::Failed {
                error: SubmitError::TxBuildFailed { detail },
            }) => {
                self.retry_or_terminate(
                    &job,
                    ctx.is_final_attempt,
                    RefundReason::TxBuildFailed,
                    detail,
                )
                .await
            }
            // Wallet contention is raised BEFORE any attempt is recorded (no wallet
            // resolved, the wallet lock is held, a locked re-auth yielded none, or no
            // canonical UTxO to claim), so nothing is durably recorded and nothing is
            // on chain. On a non-final attempt it is a plain retry. On the FINAL
            // attempt a first submit that has never recorded an attempt would
            // otherwise be left stranded in `submitting` forever — charged, with no
            // submit job, no recorded attempt for the recovery sweep to adopt, and no
            // refund. So the final attempt terminalises it with a refund, exactly like
            // the other pre-record retryable failure (TxBuildFailed). A REPLACEMENT
            // never refunds on contention: its superseded original is a live
            // reconcilable broadcaster, so exhausting a replacement's attempts must
            // leave the record for the confirm authority, not refund it.
            Ok(SubmitOutcome::Failed {
                error: SubmitError::WalletLockContention,
            }) => {
                self.contention_retry_or_terminate(&job, ctx.is_final_attempt)
                    .await
            }

            Err(e) => JobOutcome::Fail {
                error: crate::runtime::JobError::new("submit_error", e.to_string()),
            },
        }
    }
}

impl<G: crate::chain::gateway::ChainGateway + 'static> SubmitHandler<G> {
    /// A retryable failure that becomes terminal (refund) only on the final
    /// attempt: earlier attempts fail back to the queue to retry, the last one
    /// flips the record to `permanent_failure` and writes the refund intent.
    async fn retry_or_terminate(
        &self,
        job: &SubmitJob,
        is_final_attempt: bool,
        reason: RefundReason,
        detail: String,
    ) -> JobOutcome {
        if is_final_attempt {
            self.terminate(job, reason, serde_json::json!({ "detail": detail }))
                .await
        } else {
            JobOutcome::Fail {
                error: crate::runtime::JobError::new(reason.as_str(), detail),
            }
        }
    }

    /// Route a wallet-contention failure: a plain retry on a non-final attempt, and
    /// on the FINAL attempt a guarded terminal refund so a charged first submit that
    /// never recorded an attempt cannot strand in `submitting` forever.
    ///
    /// The terminal refund fires ONLY for a first submit (never a replacement, whose
    /// superseded original is a live broadcaster the confirm authority must own)
    /// whose record is still `submitting` with no current attempt — i.e. the exact
    /// state a contention-stranded charged publish is left in, where no recorded
    /// attempt exists for the recovery sweep to adopt and no transaction is on chain,
    /// so a refund is safe. Any record that has since recorded an attempt or moved on
    /// is left as a retry/no-op: the recorded-attempt and confirm paths own it, and
    /// the single-refund-by-construction insert would not double-refund regardless.
    async fn contention_retry_or_terminate(
        &self,
        job: &SubmitJob,
        is_final_attempt: bool,
    ) -> JobOutcome {
        if !is_final_attempt {
            return JobOutcome::Fail {
                error: crate::runtime::JobError::new(
                    "wallet_lock_contention",
                    "every candidate wallet is locked; requeue",
                ),
            };
        }

        // A replacement never refunds on contention: its superseded original can still
        // confirm, so leave the record for the confirm authority rather than refund.
        if job.replacement_for.is_some() {
            return JobOutcome::Complete;
        }

        match self.terminate_stranded_contention(job.record_id).await {
            Ok(()) => JobOutcome::Complete,
            Err(e) => JobOutcome::Fail {
                error: crate::runtime::JobError::new("refund_write_failed", e.to_string()),
            },
        }
    }

    /// Refund a first submit stranded pre-record by exhausted wallet contention, in
    /// ONE transaction that holds the record row locked across the guard and the
    /// refund, so a racing generation cannot record an attempt between the check and
    /// the flip.
    ///
    /// The record is locked `FOR UPDATE`, then the refund fires only while it is still
    /// `submitting` with no current attempt — the exact pre-record stranded state. A
    /// concurrent submit's generation claim
    /// (`UPDATE poe_record SET current_attempt_id = ... WHERE current_attempt_id IS
    /// NULL`) blocks on this row lock, so it either runs BEFORE (the record then rides
    /// an attempt and this refund is skipped) or AFTER (this tx committed the record
    /// terminal, so the claim's guard fails and no second transaction is built). That
    /// closes the check-then-act window that could otherwise refund a record a
    /// duplicate job had just begun to anchor.
    async fn terminate_stranded_contention(&self, record_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let stranded: Option<bool> = sqlx::query_scalar(
            "SELECT (status = 'submitting' AND current_attempt_id IS NULL) \
             FROM cw_core.poe_record WHERE id = $1 FOR UPDATE",
        )
        .bind(record_id)
        .fetch_optional(&mut *tx)
        .await?;

        if stranded != Some(true) {
            // The record recorded an attempt or moved on; the recorded-attempt /
            // confirm paths own it. Nothing to refund.
            tx.rollback().await?;
            return Ok(());
        }

        // No dedicated RefundReason exists for contention; this is the same pre-record
        // "could not proceed to build a transaction" terminal as a build failure, so it
        // shares TxBuildFailed with a contention cause in the detail.
        let detail = serde_json::json!({
            "detail": "every candidate wallet stayed locked across all submit attempts; \
                       the publish could not be built",
            "cause": "wallet_lock_contention",
        });
        crate::chain::confirm::record_permanent_failure_in_tx(
            &mut tx,
            record_id,
            RefundReason::TxBuildFailed,
            &detail,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Flip the record to `permanent_failure` with its refund intent, then
    /// complete the job (the failure is recorded durably, so the job itself is
    /// done).
    async fn terminate(
        &self,
        job: &SubmitJob,
        reason: RefundReason,
        detail: serde_json::Value,
    ) -> JobOutcome {
        match self.fail_permanently(job.record_id, reason, &detail).await {
            Ok(()) => JobOutcome::Complete,
            Err(e) => JobOutcome::Fail {
                error: crate::runtime::JobError::new("refund_write_failed", e.to_string()),
            },
        }
    }
}

/// The refund-intent detail for an over-budget record.
fn byte_budget_detail(size: u64, max: u64) -> serde_json::Value {
    serde_json::json!({ "size": size, "max": max })
}

/// The result of one submit attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// The network accepted the transaction; the record is now `submitted`.
    Submitted {
        /// The accepted transaction id.
        tx_hash: [u8; 32],
        /// The wallet inputs the transaction spent (one or more; a replacement
        /// spends the forced inputs too).
        spent_inputs: Vec<UtxoRef>,
        /// The fee the transaction paid, if it could be extracted.
        fee_lovelace: Option<u64>,
    },
    /// The attempt could not complete; the classified reason drives the handler's
    /// outcome.
    Failed {
        /// The classified failure.
        error: SubmitError,
    },
    /// The record was no longer submittable (already terminal, or already
    /// submitted by a racing path), so this attempt has nothing to do. The job is
    /// complete without a state transition.
    AlreadyResolved,
    /// The attempt is durably recorded but its broadcast failed transiently or
    /// ambiguously (a provider 5xx/429, a transport error, an id-mismatch anomaly):
    /// the body may have reached a node, so the recorded attempt stays in-flight and
    /// is NEVER refunded here. The job retries the re-broadcast; once its attempts
    /// are exhausted, the recorded attempt persists for the confirm authority and the
    /// operator-reconcile path. This is the durability the no-TTL model relies on: a
    /// recorded spend is never abandoned without a settlement-deep conflicting spend.
    RecordedInFlight,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_policy_is_a_standard_five_attempt_queue() {
        let policy = submit_policy();
        assert_eq!(policy.queue, SUBMIT_QUEUE);
        assert_eq!(
            policy.policy,
            crate::runtime::policy::QueuePolicyKind::Standard
        );
        assert_eq!(policy.max_attempts, SUBMIT_MAX_ATTEMPTS);
        assert!(matches!(
            policy.backoff,
            Backoff::Fixed {
                base_secs: SUBMIT_BACKOFF_SECS
            }
        ));
    }

    #[test]
    fn submit_job_omits_replacement_fields_for_a_first_submit() {
        let job = SubmitJob {
            request_id: "req-1".to_string(),
            record_id: Uuid::now_v7(),
            replacement_for: None,
            forced_inputs: Vec::new(),
        };
        let json = serde_json::to_string(&job).expect("serialise");
        // A first submit's payload carries neither replacement field.
        assert!(!json.contains("replacement_for"));
        assert!(!json.contains("forced_inputs"));
        let back: SubmitJob = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, job);
    }

    #[test]
    fn submit_job_round_trips_a_cancelling_replacement() {
        let job = SubmitJob {
            request_id: "req-2".to_string(),
            record_id: Uuid::now_v7(),
            replacement_for: Some("ab".repeat(32)),
            forced_inputs: vec![ForcedInput {
                tx_hash: "cd".repeat(32),
                index: 1,
                lovelace: 6_000_000,
            }],
        };
        let json = serde_json::to_string(&job).expect("serialise");
        let back: SubmitJob = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, job);
    }
}
