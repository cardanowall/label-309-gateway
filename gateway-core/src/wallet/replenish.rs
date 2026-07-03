//! Keeping each wallet stocked with canonical UTxOs.
//!
//! A submit consumes one canonical UTxO and (once confirmed) produces one
//! canonical change output, so a steady-state wallet roughly holds its count. But
//! a wallet seeded with one large source UTxO has zero canonical UTxOs until it is
//! split, and a burst of submits can drain the canonical set faster than
//! confirmations refill it. The replenish job watches each active wallet's
//! canonical available count and, when it falls below the configured minimum,
//! splits a large source UTxO into band-sized outputs.
//!
//! # The split, and the index-cap invariant
//!
//! A split transaction pays the wallet's own address with several band-mid outputs
//! (plus a change output for the remainder). Every minted output lands at an output
//! index below the canonical cap so it is canonical by construction, which bounds a
//! single split to at most `MAX_CANONICAL_OUTPUT_INDEX - 1` self-outputs (the
//! change output takes the next slot). The job signs the split with the wallet's
//! key, then records it as a `kind='split'` chain attempt BEFORE it broadcasts: the
//! signed bytes and the minted outputs are durable the instant the spend could
//! exist on chain, so a crash can never leave the split on the wire but unrecorded.
//! The confirm authority then loads the split attempt alongside publishes and, on
//! settlement, promotes the minted outputs to canonical through the same wallet
//! promotion a publish uses. A split is thus a first-class confirmable attempt, not
//! a fire-and-forget mint, so its minted outputs are always eventually promoted (or,
//! on a settlement-deep conflicting spend, its source is restored).
//!
//! The single-change-output Proof-of-Existence builder cannot emit several
//! self-outputs, so the split transaction is assembled here directly with the
//! Conway transaction builder, reusing the Proof-of-Existence crate's linear-fee
//! and minimum-ADA helpers so its fee math matches the rest of the engine.

use pallas_addresses::Address;
use pallas_codec::minicbor;
use pallas_crypto::hash::Hasher;
use pallas_primitives::conway::Tx as ConwayTx;
use pallas_primitives::Fragment;
use pallas_txbuilder::{BuildConway, Input, Output, StagingTransaction};
use uuid::Uuid;

use cardano_poe_tx::fee::{linear_fee, min_ada_for_output};
use cardano_poe_tx::ProtocolParams;

use super::config::{Network, WalletConfig, MAX_CANONICAL_OUTPUT_INDEX};
use super::keyring::WalletSigner;
use super::pool::try_lock_wallet;
use super::submitter::{SubmitOutcome, Submitter};
use super::utxo::{self, ChangeOutput, ObservedUtxo, SpentInput, UtxoLease, UtxoRef, UtxoSource};
use crate::chain::attempt::{self, AttemptInput, AttemptKind, AttemptOutput, NewAttempt};
use crate::{Error, Result};

/// The most band-mid self-outputs one split transaction may mint.
///
/// Every minted output must sit at an index below the canonical cap to be
/// canonical by construction; reserving the slot below the cap for the change
/// output caps the self-output count at one below the index ceiling.
pub const MAX_SPLIT_OUTPUTS: u32 = MAX_CANONICAL_OUTPUT_INDEX - 1;

/// A planned split of one source UTxO into band-mid canonical outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPlan {
    /// The source UTxO to spend.
    pub source: UtxoRef,
    /// The lovelace the source holds.
    pub source_lovelace: u64,
    /// How many band-mid outputs to mint (each at a distinct index below the
    /// canonical cap). Bounded by [`MAX_SPLIT_OUTPUTS`].
    pub output_count: u32,
    /// The lovelace value of each minted output (the band midpoint).
    pub per_output_lovelace: u64,
}

/// Plan a split for a wallet that has fallen below its canonical minimum.
///
/// Sizes the split to the smallest of three bounds: the per-transaction index cap
/// ([`MAX_SPLIT_OUTPUTS`]), how many more canonical UTxOs the wallet needs to
/// reach its configured minimum, and how many band-mid outputs the source UTxO can
/// fund once room is left for the fee and a minimum-ADA change output. The fee and
/// change reserve are derived from the live protocol parameters the caller passes
/// in, never from a hardcoded fee. Returns `None` when no single source UTxO is
/// large enough to mint even one band-mid output beyond the fee.
#[must_use]
pub fn plan_split(
    source_lovelace: u64,
    source: UtxoRef,
    current_canonical_count: i64,
    params: &ProtocolParams,
    config: &WalletConfig,
) -> Option<SplitPlan> {
    let per_output = config.band.mid;
    if per_output == 0 {
        return None;
    }

    // How many more canonical UTxOs the wallet wants. A non-positive deficit means
    // the wallet is already stocked and should not split at all.
    let have = current_canonical_count.max(0) as u64;
    let want = u64::from(config.min_canonical_count);
    let deficit = want.saturating_sub(have);
    if deficit == 0 {
        return None;
    }

    // Reserve enough for the worst-case fee plus one minimum-ADA change output so
    // the planner never proposes a count the exact-fee build cannot fund. Both come
    // from the live parameters; the build's exact balancing refines the fee.
    let fee_reserve = linear_fee(params, params.max_tx_size);
    let fee_and_change_reserve =
        fee_reserve.saturating_add(min_ada_for_output(params, CHANGE_OUTPUT_SIZE_FLOOR));
    let spendable = source_lovelace.saturating_sub(fee_and_change_reserve);
    let fundable = spendable / per_output;
    if fundable == 0 {
        return None;
    }

    let output_count = deficit
        .min(u64::from(MAX_SPLIT_OUTPUTS))
        .min(fundable)
        // `fundable` and the index cap are both bounded well within u32, so the
        // min is too.
        .min(u64::from(u32::MAX)) as u32;
    if output_count == 0 {
        return None;
    }

    Some(SplitPlan {
        source,
        source_lovelace,
        output_count,
        per_output_lovelace: per_output,
    })
}

/// Run one replenish pass for a single wallet, under the wallet's advisory lock:
/// ingest its chain UTxOs, and if it is below the canonical minimum, lease a source
/// UTxO, plan a split, build + sign it, record the split as a `kind='split'` chain
/// attempt before broadcast, and broadcast the recorded bytes.
///
/// Generic over the [`UtxoSource`] (for ingest) and the [`Submitter`] (for the
/// split tx) so tests drive it with a mock source and the stub submitter. The
/// wallet's [`WalletSigner`] signs the split body; its key never leaves the
/// signer. Returns the outcome of the pass.
///
/// The whole select-source -> build -> sign -> record -> broadcast window runs under
/// the same per-wallet session advisory lock the submit path holds, and the source
/// is leased through the [`utxo`] state machine (`claim_source` then the
/// record-before-broadcast spend) exactly like a publish leases its inputs. That is
/// what stops two concurrent replenish passes (or a replenish racing a submit) from
/// building against the same source: only the lock holder can lease the source, and
/// the source moves `available -> in_flight -> pending_spent` fenced on a token, so a
/// second pass finds it already leased and cannot double-spend it.
pub async fn replenish_wallet<S, U>(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    signer: &WalletSigner,
    utxo_source: &U,
    submitter: &S,
    config: &WalletConfig,
) -> Result<ReplenishOutcome>
where
    S: Submitter,
    U: UtxoSource,
{
    // Serialise replenishment on this wallet with the same lock submits take. If
    // another worker already holds it (a concurrent replenish or a live submit),
    // skip this pass rather than race on the wallet's UTxOs; the singleton-loop
    // schedule retries shortly.
    let Some(lock) = try_lock_wallet(pool, wallet_id).await? else {
        return Ok(ReplenishOutcome::WalletBusy);
    };
    let outcome = replenish_locked(pool, wallet_id, signer, utxo_source, submitter, config).await;
    // Release the lock (closing its detached connection) on every arm.
    let _ = lock.release().await;
    outcome
}

/// The body of one replenish pass with the per-wallet advisory lock already held.
async fn replenish_locked<S, U>(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    signer: &WalletSigner,
    utxo_source: &U,
    submitter: &S,
    config: &WalletConfig,
) -> Result<ReplenishOutcome>
where
    S: Submitter,
    U: UtxoSource,
{
    // Idle gate: decide whether there is any work from the durable canonical count
    // alone (a Postgres read, zero chain calls) BEFORE touching the provider. A
    // wallet already at or above its canonical minimum needs no split, so it must
    // not spend a chain `/address_utxos` call every tick just to confirm it is
    // stocked. The confirm loop promotes a landed split's change to canonical in
    // Postgres, so this cached count already reflects the wallet's groomed state.
    //
    // The cached count is only trustworthy while the local view is FRESH. A wallet
    // spent out of band (a shared keyring across replicas, or a manual operator
    // spend) leaves a canonical `available` row that vanished on chain still counted
    // locally, so a genuinely-understocked wallet can read at/above its minimum. The
    // only code that reconciles such a vanished row down to `confirmed_spent` is the
    // snapshot ingest below, so the idle short-circuit is taken ONLY when the count
    // is high AND the local view was reconciled against the chain recently. A stale
    // (or never-ingested) wallet falls through to a fresh snapshot, which runs the
    // vanished-output reconciliation before the AlreadyStocked decision, so an
    // out-of-band deficit is always discovered. A freshly-ingested stocked wallet
    // still short-circuits, so the idle efficiency win holds for the common
    // single-spender case; only a stale wallet pays a bounded periodic snapshot.
    let canonical_count = utxo::canonical_ready_count(pool, wallet_id).await?;
    if canonical_count >= i64::from(config.min_canonical_count)
        && canonical_view_is_fresh(pool, wallet_id).await?
    {
        return Ok(ReplenishOutcome::AlreadyStocked { canonical_count });
    }

    // Below the minimum, or the local view is stale: bring local state in line with
    // the chain. A split that already landed since the last tick shows up here as
    // canonical change, which can lift the wallet above its minimum and skip a
    // needless second split; an out-of-band spend shows up as a vanished `available`
    // row reconciled to `confirmed_spent`, which lowers the count to the real
    // deficit. The gate is re-checked after the fresh ingest, and the ingest stamps
    // `last_ingest_at` so a now-fresh stocked wallet short-circuits on later ticks.
    let observed = utxo_source.address_utxos(signer.address()).await?;
    utxo::ingest_snapshot(pool, wallet_id, &observed, config).await?;
    mark_ingested(pool, wallet_id).await?;

    let canonical_count = utxo::canonical_ready_count(pool, wallet_id).await?;
    if canonical_count >= i64::from(config.min_canonical_count) {
        return Ok(ReplenishOutcome::AlreadyStocked { canonical_count });
    }

    // The split fee is metered against the live cached protocol parameters, never a
    // hardcoded fee. They are read from Postgres with no network call.
    let params = load_split_params(pool, config.network).await?;

    // Iterate the wallet's splittable sources in descending lovelace order and
    // commit to the first one that actually funds and records a split. A single
    // maximal source that cannot fund a split (too small once the fee and a
    // minimum-ADA change output are reserved, or already leased) must not fail the
    // whole pass when a smaller source could fund it, so the loop falls through to
    // the next candidate. `NoFundableSource` is returned only after the ordered set
    // is exhausted.
    let candidates = splittable_sources_descending(&observed, config);
    if candidates.is_empty() {
        return Ok(ReplenishOutcome::NoFundableSource);
    }

    for source in candidates {
        match try_split_source(
            pool,
            wallet_id,
            signer,
            submitter,
            &source,
            canonical_count,
            &params,
            config,
        )
        .await?
        {
            SourceAttempt::Split { minted } => return Ok(ReplenishOutcome::Split { minted }),
            SourceAttempt::WalletBusy => return Ok(ReplenishOutcome::WalletBusy),
            // This source could not fund or claim a split; fall through to the next
            // candidate in descending order.
            SourceAttempt::NotFundable => {}
        }
    }

    // Every splittable source was unfundable or already claimed.
    Ok(ReplenishOutcome::NoFundableSource)
}

/// The outcome of trying to split one candidate source: a recorded+broadcast split,
/// a wallet-contention yield, or "this source cannot fund a split, try the next".
enum SourceAttempt {
    /// A split was recorded before broadcast and broadcast through the submitter.
    Split { minted: u32 },
    /// A lease was reaped out from under the record-before-broadcast commit, so the
    /// pass reruns once the lease state settles.
    WalletBusy,
    /// This source cannot fund or claim a split; the caller falls through to the
    /// next candidate.
    NotFundable,
}

/// Try to fund, record, and broadcast a split off one candidate source, under the
/// wallet lock the caller already holds.
///
/// Plans a split for the source; if it cannot fund one (`plan_split` returns
/// `None`) or the source is already leased (`claim_source` returns `None`), reports
/// [`SourceAttempt::NotFundable`] so the caller falls through to the next candidate
/// without consuming this pass. A build error returns the leased source to
/// `available` and propagates the error (the caller's loop does not swallow it; a
/// build failure on the chosen source is a real fault). On a fundable, leased source
/// it records the split as a `kind='split'` attempt before broadcast and sends the
/// recorded bytes.
#[allow(clippy::too_many_arguments)]
async fn try_split_source<S>(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    signer: &WalletSigner,
    submitter: &S,
    source: &ObservedUtxo,
    canonical_count: i64,
    params: &ProtocolParams,
    config: &WalletConfig,
) -> Result<SourceAttempt>
where
    S: Submitter,
{
    let Some(plan) = plan_split(
        source.lovelace,
        source.utxo,
        canonical_count,
        params,
        config,
    ) else {
        return Ok(SourceAttempt::NotFundable);
    };

    // Lease the source through the state machine BEFORE building against it, under
    // the wallet lock, so the spend is fenced on a token exactly like a publish. The
    // source is the freshest observed snapshot but is now a tracked row (ingest
    // inserted it `available`); a concurrent pass that already leased it sees `None`
    // here and this candidate is skipped.
    let canonical_token = Uuid::now_v7();
    let Some(lease) =
        utxo::claim_source(pool, wallet_id, source.utxo, canonical_token, config).await?
    else {
        return Ok(SourceAttempt::NotFundable);
    };

    let built = match build_split_tx(
        &plan,
        signer.address(),
        signer.verification_key(),
        params,
        config,
    ) {
        Ok(built) => built,
        Err(e) => {
            // Build failed: return the leased source to `available` so the next pass
            // can retry it rather than wait for the reaper, and propagate the fault.
            let _ = utxo::release(pool, wallet_id, lease.utxo, lease.lease_token).await;
            return Err(e);
        }
    };
    let (signed_tx, tx_hash) = built.sign(signer);

    // RECORD-BEFORE-BROADCAST: in ONE transaction (attempt -> wallet, the lock order
    // for a split, which has no record), insert the chain_attempt row carrying the
    // signed bytes and advance the leased source to pending_spent with the minted
    // outputs as the attempt's produced outputs. The signed bytes are durable BEFORE
    // they ever reach the wire, so a crash after this commit leaves a recorded split
    // the confirm authority reconciles, and a crash before it leaves nothing on chain
    // to lose.
    let attempt_id = Uuid::now_v7();
    let recorded =
        record_split_attempt(pool, wallet_id, attempt_id, &lease, &signed_tx, &built).await?;
    if !recorded {
        // The source lease was reaped between claim and record (only possible if the
        // lock fencing was violated); nothing was recorded and nothing is on the
        // wire. Report contention so the pass reruns once the lease state settles.
        return Ok(SourceAttempt::WalletBusy);
    }

    // BROADCAST the recorded bytes. A deterministic rejection (the node refused the
    // body and no node could ever accept it) is the ONE abandon not gated on a
    // settlement-deep conflicting spend: the transaction was never accepted by any
    // node, so it can never land, and the recorded attempt is abandoned with its
    // source restored immediately. An ambiguous submit or a transport error leaves
    // the recorded attempt in-flight for the confirm authority, which abandons it
    // ONLY on a settlement-deep conflicting spend, never on absence or age.
    match submitter.submit(&signed_tx, tx_hash).await {
        Ok(SubmitOutcome::Accepted { tx_hash: echoed }) => {
            // The node must echo the id the builder computed; a mismatch means a
            // different transaction than the one recorded, so the recorded spend
            // would not match what landed. Leave the attempt `recorded` for the
            // confirm authority in that case (the recorded bytes are correct; this is
            // a provider anomaly), and on a matching echo mark it `broadcast` so the
            // mempool/alert clock starts.
            if echoed == built.tx_hash {
                let _ = attempt::mark_broadcast(pool, attempt_id).await?;
            }
            Ok(SourceAttempt::Split {
                minted: plan.output_count,
            })
        }
        Ok(SubmitOutcome::Rejected { reason }) => {
            // Deterministic reject: abandon the recorded attempt and restore its
            // source in one transaction. This is a true, immediate death proof
            // distinct from "absent after broadcast".
            abandon_split_attempt(pool, wallet_id, attempt_id, &reason).await?;
            Err(Error::WalletBuild(format!(
                "the split transaction was rejected: {reason}"
            )))
        }
        Ok(SubmitOutcome::Ambiguous { detail }) => {
            // The submit may or may not have landed; do NOT abandon and do NOT
            // restore the source. Leave the recorded attempt for the confirm
            // authority to reconcile against chain truth.
            Err(Error::WalletBuild(format!(
                "the split transaction submit was ambiguous: {detail}"
            )))
        }
        Err(e) => {
            // Transport/setup error before any acceptance signal: the body may
            // already be on the wire, so the recorded attempt stays in-flight for the
            // confirm authority. Never restore the source on a transport error.
            Err(e)
        }
    }
}

/// Record a split as a `kind='split'` chain attempt before broadcast, in ONE
/// transaction in the lock order attempt -> wallet (a split has no record).
///
/// Inserts the attempt row (status='recorded') carrying the signed bytes, the source
/// as the single spent input, and the minted band-mid outputs as the attempt's
/// produced outputs; then advances the leased source to `pending_spent` and inserts
/// the minted outputs as `change`-sourced rows the confirm authority later promotes
/// to canonical. Returns `false` when the source lease was reaped out from under the
/// commit (the whole transaction rolls back so nothing is half-recorded), in which
/// case the caller treats it as wallet contention.
async fn record_split_attempt(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    attempt_id: Uuid,
    lease: &UtxoLease,
    signed_tx: &[u8],
    built: &BuiltSplitTx,
) -> Result<bool> {
    let spent_input = AttemptInput {
        tx_hash: hex::encode(lease.utxo.tx_hash),
        index: lease.utxo.output_index,
        lovelace: lease.lovelace,
    };
    let minted = minted_outputs(built, built.tx_hash);
    let produced_outputs: Vec<AttemptOutput> = minted
        .iter()
        .map(|output| AttemptOutput {
            index: output.utxo.output_index,
            lovelace: output.lovelace,
        })
        .collect();

    let new_attempt = NewAttempt {
        id: attempt_id,
        kind: AttemptKind::Split,
        record_id: None,
        wallet_id,
        tx_hash: built.tx_hash,
        // The recorded bytes ARE the bytes that go on the wire; a retry re-broadcasts
        // exactly these.
        signed_tx: signed_tx.to_vec(),
        fee_lovelace: built.fee,
        spent_inputs: vec![spent_input],
        produced_outputs,
        replaces_tx_hash: None,
    };

    let spent = SpentInput {
        utxo: lease.utxo,
        lease_token: lease.lease_token,
    };

    let mut tx = pool.begin().await?;
    attempt::record_attempt_in_tx(&mut tx, &new_attempt).await?;
    let applied = utxo::apply_split_in_tx(&mut tx, wallet_id, &spent, &minted).await?;
    if !applied {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

/// Abandon a recorded split attempt the node rejected deterministically, restoring
/// its source and tombstoning its (uncreated) minted outputs, in ONE transaction.
///
/// A split has no record, so there is no refund: the abandon restores the source
/// input to `available` (the rejected transaction was never accepted by any node, so
/// the source is live again) and deletes the minted `change`-sourced rows that never
/// existed on chain. The reject evidence rides the attempt's subject events so an
/// operator can trace this immediate node-reject abandon distinctly from one driven
/// by a confirmed conflicting spend.
async fn abandon_split_attempt(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    attempt_id: Uuid,
    reason: &str,
) -> Result<()> {
    let Some(attempt) = attempt::load_attempt(pool, attempt_id).await? else {
        return Ok(());
    };

    let mut tx = pool.begin().await?;
    let evidence = serde_json::json!({
        "reason": "node_rejected",
        "detail": reason,
    });
    // Only proceed when THIS call actually transitioned the attempt to
    // abandoned: a zero-row abandon means a racing path already terminalised it
    // (confirmed it, or abandoned it first), and the source restore and the
    // minted-output tombstones must follow that path's decision, not this stale
    // one — the same guard the submit-path abandon applies.
    let abandoned = attempt::mark_abandoned_in_tx(&mut tx, attempt_id).await?;
    if !abandoned {
        tx.rollback().await?;
        return Ok(());
    }
    crate::events::append_subject_event(
        &mut tx,
        "chain_attempt",
        &attempt_id.to_string(),
        "attempt_abandoned",
        &evidence,
    )
    .await?;

    let refs: Vec<UtxoRef> = attempt
        .spent_inputs
        .iter()
        .map(AttemptInput::utxo_ref)
        .collect::<Result<_>>()?;
    utxo::restore_inputs_in_tx(&mut tx, wallet_id, &refs).await?;
    utxo::tombstone_outputs_in_tx(&mut tx, wallet_id, attempt.tx_hash).await?;
    tx.commit().await?;
    Ok(())
}

/// The minted band-mid outputs an accepted split produced: the self-outputs at
/// indexes `0..count`, each referenced by the split transaction id. Confirmation
/// later promotes these `change`-sourced rows to canonical.
fn minted_outputs(built: &BuiltSplitTx, tx_hash: [u8; 32]) -> Vec<ChangeOutput> {
    (0..built.minted)
        .map(|index| ChangeOutput {
            utxo: UtxoRef {
                tx_hash,
                output_index: index,
            },
            lovelace: built.per_output_lovelace,
        })
        .collect()
}

/// The wallet's pure-ADA, non-canonical (oversized) outputs in descending lovelace
/// order, the candidate sources the replenisher tries in turn.
///
/// A band-sized output is already groomed and must not be consumed to mint more, so
/// only outputs above the band are candidates. Ordering largest-first means the
/// replenisher prefers the source that funds the most outputs, but the caller falls
/// through to a smaller fundable source if the largest cannot fund or claim a split,
/// so a wallet with several mid-size outputs (none individually maximal-but-fundable)
/// still replenishes. Returns an empty vector when no oversized source exists.
fn splittable_sources_descending(
    observed: &[ObservedUtxo],
    config: &WalletConfig,
) -> Vec<ObservedUtxo> {
    let mut candidates: Vec<ObservedUtxo> = observed
        .iter()
        .filter(|o| o.pure_ada && o.lovelace > config.band.max)
        .copied()
        .collect();
    candidates.sort_by_key(|o| std::cmp::Reverse(o.lovelace));
    candidates
}

/// What one [`replenish_wallet`] pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplenishOutcome {
    /// The wallet was already at or above its canonical minimum; no split.
    AlreadyStocked {
        /// The wallet's canonical available count.
        canonical_count: i64,
    },
    /// A split transaction was submitted and accepted.
    Split {
        /// How many band-mid outputs the split minted.
        minted: u32,
    },
    /// The wallet was below the minimum but no source UTxO could fund a split.
    NoFundableSource,
    /// The wallet's advisory lock was already held (a concurrent replenish or a
    /// live submit), so this pass yielded without touching the wallet's UTxOs.
    /// The singleton-loop schedule retries it shortly.
    WalletBusy,
}

/// A built, unsigned split transaction plus the facts the apply-change path needs.
struct BuiltSplitTx {
    /// CBOR bytes of the complete unsigned transaction (empty witness set).
    unsigned_tx_bytes: Vec<u8>,
    /// 32-byte Blake2b-256 hash of the transaction body (the transaction id).
    tx_hash: [u8; 32],
    /// The fee the transaction body encodes, recorded on the attempt.
    fee: u64,
    /// How many band-mid self-outputs the split minted (at indexes `0..minted`).
    minted: u32,
    /// The lovelace value of each minted output.
    per_output_lovelace: u64,
}

impl BuiltSplitTx {
    /// Sign the split body with the wallet's signer, returning the complete signed
    /// transaction bytes and the transaction id (unchanged by signing).
    fn sign(&self, signer: &WalletSigner) -> (Vec<u8>, [u8; 32]) {
        let signature = signer.sign_tx_body(&self.tx_hash);
        let signed = witness_tx(
            &self.unsigned_tx_bytes,
            signer.verification_key(),
            &signature,
        );
        (signed, self.tx_hash)
    }
}

/// Build the unsigned split transaction for a plan: one input (the source), the
/// `output_count` band-mid self-outputs at indexes `0..count`, and a change output
/// at the next index for the remainder.
///
/// The fee is balanced to an exact fixed point over the signed transaction size,
/// reusing the Proof-of-Existence crate's linear-fee formula so the fee math
/// matches the rest of the engine. The minted outputs precede the change output in
/// insertion order, and the Conway builder preserves output order, so every minted
/// output lands at an index below the canonical cap.
fn build_split_tx(
    plan: &SplitPlan,
    self_address: &str,
    verification_key: [u8; 32],
    params: &ProtocolParams,
    config: &WalletConfig,
) -> Result<BuiltSplitTx> {
    let address = Address::from_bech32(self_address)
        .map_err(|e| Error::WalletBuild(format!("invalid wallet address: {e}")))?;
    let minted = u64::from(plan.output_count);
    let minted_total = plan
        .per_output_lovelace
        .checked_mul(minted)
        .ok_or_else(|| Error::WalletBuild("split mint total overflows".to_string()))?;

    // Fee fixpoint over the change-bearing shape: change moves opposite the fee as
    // both CBOR widths shift, so iterate until the fee the size implies matches the
    // fee the body encoded. A split spends a single input, so a few steps suffice.
    let mut fee = linear_fee(params, 0);
    for _ in 0..FEE_FIXPOINT_STEPS {
        let unsigned = assemble_split_at_fee(&address, plan, params, config, minted_total, fee)?;
        let signed_size = signed_size(&unsigned, verification_key);
        let required = linear_fee(params, signed_size);
        if required == fee {
            let tx_hash = body_hash(&unsigned);
            return Ok(BuiltSplitTx {
                unsigned_tx_bytes: unsigned,
                tx_hash,
                fee,
                minted: plan.output_count,
                per_output_lovelace: plan.per_output_lovelace,
            });
        }
        fee = required;
    }

    // The fixpoint did not converge within the step bound (a coin-width
    // oscillation across a CBOR boundary). Settle on a shape whose ENCODED fee is at
    // least the fee its signed size implies, so the body is never underfunded: meter
    // one more shape at the last fee, then re-assemble paying the larger of that fee
    // and the size-implied fee (folding the extra into a reduced change output, or
    // dropping change below floor as the convergent path already does). A body that
    // pays less than its size implies would be rejected (or, worse on some encodings,
    // accepted underfunded), so emitting the max-fee shape is the only safe fallback.
    // If the source cannot fund that fee, the build fails rather than emit an invalid
    // transaction, and the caller's source fall-through tries the next source.
    let metered = assemble_split_at_fee(&address, plan, params, config, minted_total, fee)?;
    let metered_size = signed_size(&metered, verification_key);
    let required = linear_fee(params, metered_size);
    let settled_fee = fee.max(required);
    let unsigned =
        assemble_split_at_fee(&address, plan, params, config, minted_total, settled_fee)?;
    let tx_hash = body_hash(&unsigned);
    Ok(BuiltSplitTx {
        unsigned_tx_bytes: unsigned,
        tx_hash,
        fee: settled_fee,
        minted: plan.output_count,
        per_output_lovelace: plan.per_output_lovelace,
    })
}

/// Assemble one split shape at a fixed fee: balance the change as
/// `source - minted_total - fee`, keep the change output only when it clears the
/// minimum-ADA floor (otherwise fold the residual into the fee), and error when the
/// source cannot fund the minted total plus the fee. Shared by every fixpoint step
/// and the non-converging fallback so a fee can always be re-encoded into a balanced
/// body whose change reflects it.
fn assemble_split_at_fee(
    address: &Address,
    plan: &SplitPlan,
    params: &ProtocolParams,
    config: &WalletConfig,
    minted_total: u64,
    fee: u64,
) -> Result<Vec<u8>> {
    let consumed = minted_total
        .checked_add(fee)
        .ok_or_else(|| Error::WalletBuild("split spend overflows".to_string()))?;
    if plan.source_lovelace < consumed {
        return Err(Error::WalletBuild(format!(
            "source {} cannot fund {} minted lovelace plus fee {}",
            plan.source_lovelace, minted_total, fee
        )));
    }
    let change_value = plan.source_lovelace - consumed;

    // Keep the change output only when it clears the minimum-ADA floor; otherwise
    // fold the residual into the fee (a small remainder is not worth an extra
    // output, and a below-floor output is ledger-invalid).
    let change = if change_value == 0 {
        None
    } else {
        let change_floor = min_change_value(params, address, change_value);
        if change_value >= change_floor {
            Some(change_value)
        } else {
            None
        }
    };

    assemble_split(address, plan, config.network.network_id(), fee, change)
}

/// Assemble the unsigned split transaction: the source input, the band-mid
/// self-outputs first (indexes `0..count`), then the change output if kept.
fn assemble_split(
    address: &Address,
    plan: &SplitPlan,
    network_id: u8,
    fee: u64,
    change: Option<u64>,
) -> Result<Vec<u8>> {
    let mut staging = StagingTransaction::new()
        .network_id(network_id)
        .fee(fee)
        .input(Input::new(
            plan.source.tx_hash.into(),
            u64::from(plan.source.output_index),
        ));

    // Minted outputs come first so they occupy indexes 0..count; the Conway
    // builder preserves output order, which keeps every minted output below the
    // canonical index cap.
    for _ in 0..plan.output_count {
        staging = staging.output(Output::new(address.clone(), plan.per_output_lovelace));
    }
    if let Some(value) = change {
        staging = staging.output(Output::new(address.clone(), value));
    }

    let built = staging
        .build_conway_raw()
        .map_err(|e| Error::WalletBuild(format!("assembling the split transaction: {e}")))?;
    Ok(built.tx_bytes.0)
}

/// The minimum-ADA value a change output carrying `change` lovelace must hold,
/// computed over the exact serialised size of that output.
fn min_change_value(params: &ProtocolParams, address: &Address, change: u64) -> u64 {
    let output = Output::new(address.clone(), change.max(1));
    let built = output
        .build_babbage_raw()
        .expect("change output is always encodable");
    let size = minicbor::to_vec(&built)
        .expect("change output always serialises")
        .len() as u64;
    min_ada_for_output(params, size)
}

/// The signed-form size, in bytes, of an unsigned transaction once one vkey
/// witness is added. The placeholder occupies exactly the byte budget the real
/// signature will, so the size measured here is the size the fee pays for.
fn signed_size(unsigned_tx_bytes: &[u8], verification_key: [u8; 32]) -> u64 {
    witness_tx(unsigned_tx_bytes, verification_key, &[0u8; 64]).len() as u64
}

/// Re-encode an unsigned transaction with a single vkey witness (the given key and
/// signature), returning the signed-form bytes.
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

/// The Blake2b-256 hash of the transaction body (the transaction id).
fn body_hash(unsigned_tx_bytes: &[u8]) -> [u8; 32] {
    let tx = ConwayTx::decode_fragment(unsigned_tx_bytes)
        .expect("a builder-produced transaction always re-decodes");
    *Hasher::<256>::hash(tx.transaction_body.raw_cbor())
}

/// Load the live cached protocol parameters for the split's network from
/// Postgres, with no network call, and project them into the builder's
/// [`ProtocolParams`]. The fee is metered against these live values, never a
/// hardcoded fee. Each wallet network maps one-to-one to its own provider/cache
/// network via [`Network::to_params_network`], so a preview deployment reads the
/// preview cache the populate loop filled, never preprod's.
async fn load_split_params(pool: &sqlx::PgPool, network: Network) -> Result<ProtocolParams> {
    let chain_network = network.to_params_network();
    let stored = crate::chain::params::load_params(pool, chain_network).await?;
    Ok(ProtocolParams {
        min_fee_a: stored.min_fee_a,
        min_fee_b: stored.min_fee_b,
        coins_per_utxo_byte: stored.coins_per_utxo_byte,
        max_tx_size: stored.max_tx_size,
    })
}

/// How long the durable canonical count is trusted as proof of stock before the
/// idle gate forces a fresh chain snapshot.
///
/// The replenish cron runs every 15 minutes; a window comfortably larger than one
/// tick keeps a stocked, single-spender wallet on the cheap cached-count path for
/// most ticks while bounding how long an out-of-band spend (shared keyring across
/// replicas, or a manual operator spend) can leave a wallet understocked-but-stale
/// before the next snapshot reconciles its vanished UTxOs. One hour caps the
/// blind spot while still skipping ~3 of every 4 ticks' chain calls for an idle
/// stocked wallet.
const CANONICAL_VIEW_STALENESS: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Whether the wallet's local UTxO view was reconciled against the chain recently
/// enough to trust the cached canonical count without a fresh snapshot.
///
/// `last_ingest_at` is stamped by [`mark_ingested`] on every snapshot ingest. A
/// NULL (never ingested) is treated as stale, so a wallet's first replenish pass
/// always reconciles before trusting its count.
async fn canonical_view_is_fresh(pool: &sqlx::PgPool, wallet_id: Uuid) -> Result<bool> {
    let staleness_secs = CANONICAL_VIEW_STALENESS.as_secs() as f64;
    let fresh: bool = sqlx::query_scalar(
        "SELECT last_ingest_at IS NOT NULL \
                AND last_ingest_at > now() - make_interval(secs => $2) \
         FROM cw_core.operator_wallet \
         WHERE id = $1",
    )
    .bind(wallet_id)
    .bind(staleness_secs)
    .fetch_optional(pool)
    .await?
    .unwrap_or(false);
    Ok(fresh)
}

/// Stamp the wallet's `last_ingest_at` to now after a snapshot ingest, so the idle
/// gate can trust the freshly-reconciled canonical count on later ticks.
async fn mark_ingested(pool: &sqlx::PgPool, wallet_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE cw_core.operator_wallet SET last_ingest_at = now() WHERE id = $1")
        .bind(wallet_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// A conservative serialised-output-size floor for the planner's change reserve.
const CHANGE_OUTPUT_SIZE_FLOOR: u64 = 80;

/// Upper bound on the split fee fixpoint iterations. The fee changes by a few
/// bytes' worth between steps over a single input, so it settles quickly; this
/// caps a pathological coin-width oscillation.
const FEE_FIXPOINT_STEPS: usize = 8;

/// The queue the replenish job runs on.
pub const REPLENISH_QUEUE: &str = "wallet_replenish";

/// What a replenish job is asked to groom.
///
/// The periodic cron enqueues a [`Null`](serde_json::Value::Null) payload and
/// grooms every active wallet. Wallet registration enqueues a [`Targeted`] payload
/// naming the just-registered wallet so it is stocked on the next worker tick
/// rather than waiting for the periodic pass. Both run the same per-wallet body, so
/// a targeted pass racing the periodic one is idempotent (the per-wallet lock and
/// the already-stocked short-circuit make a redundant pass a no-op).
///
/// [`Null`]: ReplenishPayload::AllWallets
/// [`Targeted`]: ReplenishPayload::Wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplenishPayload {
    /// Groom every active wallet (the periodic cron pass).
    AllWallets,
    /// Groom only the named wallet (enqueued at registration).
    Wallet(Uuid),
}

impl ReplenishPayload {
    /// The singleton dedupe key for a targeted pass on `wallet_id`.
    ///
    /// A re-register or a periodic enqueue that races the targeted one collides on
    /// this key, so the enqueue is a no-op rather than a duplicate groom.
    #[must_use]
    pub fn singleton_key(wallet_id: Uuid) -> String {
        format!("wallet_replenish:{wallet_id}")
    }

    /// Parse a job payload into the groom target.
    ///
    /// A JSON null (the cron payload) is the all-wallets pass; an object carrying a
    /// `wallet_id` uuid is a targeted pass. Any other shape is a malformed payload
    /// and is reported as a config error rather than silently grooming everything.
    pub fn parse(payload: &serde_json::Value) -> Result<Self> {
        if payload.is_null() {
            return Ok(Self::AllWallets);
        }
        let wallet_id = payload
            .get("wallet_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                Error::Config(format!(
                    "replenish payload is neither null nor a {{\"wallet_id\": <uuid>}} object: \
                     {payload}"
                ))
            })?;
        Ok(Self::Wallet(wallet_id))
    }
}

/// The serializable form of a targeted replenish payload, the JSON the register
/// route enqueues: `{ "wallet_id": <uuid> }`. The periodic cron enqueues a bare
/// `serde_json::Value::Null` instead, which [`ReplenishPayload::parse`] reads as
/// the all-wallets pass.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct TargetedReplenish {
    /// The wallet the targeted pass grooms.
    pub wallet_id: Uuid,
}

/// The default policy for the replenish queue: a singleton loop so at most one
/// replenish pass is in flight across the deployment.
#[must_use]
pub fn replenish_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        REPLENISH_QUEUE,
        3,
        crate::runtime::Backoff::Fixed { base_secs: 30 },
        300,
    )
}

/// A periodic schedule for the replenish job: groom every active wallet's
/// canonical band a few times an hour. The pass is idempotent (an already-stocked
/// wallet short-circuits; the per-wallet lock and lease fencing make a re-run
/// safe), so a coarse cadence that keeps wallets ahead of a submit burst is
/// enough. Tunable; this is a sensible default for the singleton-loop policy.
#[must_use]
pub fn replenish_schedule() -> crate::runtime::scheduler::CronSchedule {
    crate::runtime::scheduler::CronSchedule::new(
        "*/15 * * * *",
        REPLENISH_QUEUE,
        serde_json::Value::Null,
    )
}

/// What one [`ReplenishHandler`] pass did across the wallets it groomed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplenishPassOutcome {
    /// How many active wallets were inspected this pass.
    pub wallets_seen: u64,
    /// How many wallets were split (restocked) this pass.
    pub wallets_split: u64,
    /// How many band-mid outputs were minted across all the splits.
    pub outputs_minted: u64,
}

/// The replenish job handler: groom every active wallet on the configured network.
///
/// Register it on the runtime against [`REPLENISH_QUEUE`] with [`replenish_policy`]
/// and [`replenish_schedule`], mirroring the wallet-maintenance handler. Each pass
/// lists the active wallets, resolves each to its keyring signer, and runs one
/// [`replenish_wallet`] pass per wallet under that wallet's advisory lock; a wallet
/// whose key is not loaded, or whose lock is held by a live submit, is skipped this
/// pass and retried on the next tick.
///
/// Generic over the [`UtxoSource`] (chain ingest) and [`Submitter`] (split tx) so
/// production wires the keyless chain source and the real submitter while tests
/// drive it through the runtime with a mock source and the stub submitter. The
/// unlocked keyring is shared (`Arc`) and never exposes a raw key.
pub struct ReplenishHandler<S, U> {
    pool: sqlx::PgPool,
    keyring: std::sync::Arc<super::keyring::UnlockedKeyring>,
    utxo_source: U,
    submitter: S,
    config: WalletConfig,
}

impl<S, U> ReplenishHandler<S, U>
where
    S: Submitter,
    U: UtxoSource,
{
    /// Build a replenish handler over a pool, the unlocked operator keyring, the
    /// chain UTxO source, the split submitter, and the wallet config.
    #[must_use]
    pub fn new(
        pool: sqlx::PgPool,
        keyring: std::sync::Arc<super::keyring::UnlockedKeyring>,
        utxo_source: U,
        submitter: S,
        config: WalletConfig,
    ) -> Self {
        Self {
            pool,
            keyring,
            utxo_source,
            submitter,
            config,
        }
    }

    /// Run one replenish pass over every active wallet on the configured network.
    ///
    /// One wallet's failure (a build error, a rejected split) is logged and does
    /// not abort the pass; the remaining wallets are still groomed. A pass that
    /// touched no wallet is a successful no-op.
    pub async fn run_once(&self) -> Result<ReplenishPassOutcome> {
        let wallets = super::operator::list_active_wallets(&self.pool, self.config.network).await?;

        let mut outcome = ReplenishPassOutcome::default();
        for wallet in wallets {
            outcome.wallets_seen += 1;
            match self.groom_one(wallet.id).await {
                Ok(GroomOutcome::Split { minted }) => {
                    outcome.wallets_split += 1;
                    outcome.outputs_minted += u64::from(minted);
                }
                Ok(_) => {}
                Err(e) => {
                    // One wallet's groom failed; keep grooming the rest.
                    tracing::warn!(
                        wallet_id = %wallet.id,
                        error = %e,
                        "replenish pass failed for one wallet"
                    );
                }
            }
        }

        Ok(outcome)
    }

    /// Groom a single wallet by id, the targeted pass a registration enqueues.
    ///
    /// Runs the same per-wallet body the all-wallets pass runs in its loop, so a
    /// targeted pass and the periodic pass are interchangeable and idempotent
    /// against each other. A wallet whose signing key is not held by this
    /// deployment is a skipped no-op ([`GroomOutcome::Skipped`]); another replica
    /// may hold its key. The pass is bounded by the wallet's advisory lock, so a
    /// targeted pass racing the periodic one (or a live submit) yields rather than
    /// double-builds.
    pub async fn run_once_for(&self, wallet_id: Uuid) -> Result<GroomOutcome> {
        self.groom_one(wallet_id).await
    }

    /// One wallet's groom: authorize the system spend, resolve the signer, and run
    /// a replenish pass. Shared by the all-wallets loop and the targeted pass so
    /// there is exactly one per-wallet body.
    async fn groom_one(&self, wallet_id: Uuid) -> Result<GroomOutcome> {
        // Replenish is a system action: it consolidates a wallet's OWN funds, not a
        // cross-tenant spend, so its authority is physical key possession rather
        // than a grant. The system principal is always entitled, so authorize_spend
        // here only mints the capability the keyring lookup requires (no signer is
        // reachable from a bare address). A wallet whose key is not in this
        // deployment's keyring is skipped (another replica may hold its key).
        let Some(authorized) = super::grant::authorize_spend(
            &self.pool,
            wallet_id,
            super::grant::SpendPrincipal::System,
        )
        .await?
        else {
            return Ok(GroomOutcome::Skipped);
        };
        let Some(signer) = self.keyring.signer_for(&authorized) else {
            return Ok(GroomOutcome::Skipped);
        };

        let outcome = replenish_wallet(
            &self.pool,
            wallet_id,
            signer,
            &self.utxo_source,
            &self.submitter,
            &self.config,
        )
        .await?;
        Ok(match outcome {
            ReplenishOutcome::Split { minted } => GroomOutcome::Split { minted },
            ReplenishOutcome::AlreadyStocked { .. }
            | ReplenishOutcome::NoFundableSource
            | ReplenishOutcome::WalletBusy => GroomOutcome::NotSplit,
        })
    }
}

/// What grooming a single wallet did, the result of [`ReplenishHandler::run_once_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroomOutcome {
    /// A split transaction was submitted and accepted, minting `minted` outputs.
    Split {
        /// How many band-mid outputs the split minted.
        minted: u32,
    },
    /// The wallet was inspected but no split was needed or possible this pass
    /// (already stocked, no fundable source, or its lock was held).
    NotSplit,
    /// The wallet's signing key is not held by this deployment, so the pass was a
    /// no-op; another replica may hold it.
    Skipped,
}

impl<S, U> crate::runtime::JobHandler for ReplenishHandler<S, U>
where
    S: Submitter + 'static,
    U: UtxoSource + 'static,
{
    async fn handle(&self, ctx: crate::runtime::JobContext) -> crate::runtime::JobOutcome {
        // A null payload (the periodic cron) grooms every active wallet; a
        // `{ "wallet_id": <uuid> }` payload (enqueued at registration) grooms only
        // that wallet so it is stocked on the next tick rather than waiting for the
        // periodic pass. A malformed payload is a hard fail, not a silent
        // all-wallets fallback.
        let target = match ReplenishPayload::parse(&ctx.payload) {
            Ok(target) => target,
            Err(e) => {
                tracing::warn!(error = %e, "replenish payload was malformed");
                return crate::runtime::JobOutcome::Fail {
                    error: crate::runtime::JobError::new("replenish_bad_payload", e.to_string()),
                };
            }
        };

        let result = match target {
            ReplenishPayload::AllWallets => self.run_once().await.map(|outcome| {
                tracing::info!(
                    wallets_seen = outcome.wallets_seen,
                    wallets_split = outcome.wallets_split,
                    outputs_minted = outcome.outputs_minted,
                    "replenish pass complete"
                );
            }),
            ReplenishPayload::Wallet(wallet_id) => {
                self.run_once_for(wallet_id).await.map(|outcome| {
                    tracing::info!(
                        wallet_id = %wallet_id,
                        outcome = ?outcome,
                        "targeted replenish complete"
                    );
                })
            }
        };

        match result {
            Ok(()) => crate::runtime::JobOutcome::Complete,
            Err(e) => {
                tracing::warn!(error = %e, "replenish pass failed");
                crate::runtime::JobOutcome::Fail {
                    error: crate::runtime::JobError::new("replenish_failed", e.to_string()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::config::{LovelaceBand, Network};
    use pallas_crypto::key::ed25519::SecretKey;

    fn band() -> LovelaceBand {
        LovelaceBand {
            min: 4_000_000,
            max: 8_000_000,
            mid: 6_000_000,
        }
    }

    fn config_with_min(min_canonical_count: u32) -> WalletConfig {
        WalletConfig {
            network: Network::Preprod,
            band: band(),
            lease: std::time::Duration::from_secs(120),
            min_canonical_count,
        }
    }

    fn source_ref(byte: u8, index: u32) -> UtxoRef {
        UtxoRef {
            tx_hash: [byte; 32],
            output_index: index,
        }
    }

    /// Post-Conway preprod fee parameters, used to drive the pure planner and
    /// builder tests without a database. The real path reads these from the cache.
    fn test_params() -> ProtocolParams {
        ProtocolParams {
            min_fee_a: 44,
            min_fee_b: 155_381,
            coins_per_utxo_byte: 4_310,
            max_tx_size: 16_384,
        }
    }

    #[test]
    fn null_payload_is_the_all_wallets_pass() {
        // The periodic cron enqueues a JSON null; it must groom every wallet.
        let parsed = ReplenishPayload::parse(&serde_json::Value::Null).expect("null parses");
        assert_eq!(parsed, ReplenishPayload::AllWallets);
    }

    #[test]
    fn wallet_id_payload_is_a_targeted_pass() {
        // The register route enqueues `{ "wallet_id": <uuid> }`; it must groom only
        // that wallet, and the serializable form must round-trip to that target.
        let wallet_id = Uuid::now_v7();
        let payload = serde_json::to_value(TargetedReplenish { wallet_id }).expect("serialize");
        let parsed = ReplenishPayload::parse(&payload).expect("targeted parses");
        assert_eq!(parsed, ReplenishPayload::Wallet(wallet_id));
    }

    #[test]
    fn malformed_payload_is_an_error_not_a_silent_all_wallets_pass() {
        // A payload that is neither null nor a wallet_id object must surface as an
        // error: silently grooming every wallet on a malformed targeted enqueue
        // would be a worse failure than failing the job.
        assert!(
            ReplenishPayload::parse(&serde_json::json!({ "wallet_id": "not-a-uuid" })).is_err(),
            "a non-uuid wallet_id is rejected"
        );
        assert!(
            ReplenishPayload::parse(&serde_json::json!({ "other": "field" })).is_err(),
            "an object without wallet_id is rejected"
        );
        assert!(
            ReplenishPayload::parse(&serde_json::json!("just-a-string")).is_err(),
            "a bare string is rejected"
        );
    }

    #[test]
    fn singleton_key_is_per_wallet() {
        // The dedupe key must be distinct per wallet (so two wallets' targeted
        // enqueues do not collide) and stable for one wallet (so a re-register
        // dedupes to a no-op).
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        assert_eq!(
            ReplenishPayload::singleton_key(a),
            ReplenishPayload::singleton_key(a),
            "the key is stable for one wallet"
        );
        assert_ne!(
            ReplenishPayload::singleton_key(a),
            ReplenishPayload::singleton_key(b),
            "the key is distinct per wallet"
        );
        assert_eq!(
            ReplenishPayload::singleton_key(a),
            format!("wallet_replenish:{a}")
        );
    }

    #[test]
    fn split_count_caps_at_the_index_ceiling() {
        // A source large enough to fund hundreds of band-mid outputs is still
        // capped at MAX_SPLIT_OUTPUTS so every minted output stays below the
        // canonical index cap.
        let config = config_with_min(1_000);
        let huge = config.band.mid * 1_000 + 50_000_000;
        let plan = plan_split(huge, source_ref(0xAA, 7), 0, &test_params(), &config)
            .expect("a huge source funds a capped split");
        assert_eq!(
            plan.output_count, MAX_SPLIT_OUTPUTS,
            "the split is capped at one below the index ceiling"
        );
        assert!(
            plan.output_count < MAX_CANONICAL_OUTPUT_INDEX,
            "every minted output index is below the canonical cap"
        );
        assert_eq!(plan.per_output_lovelace, config.band.mid);
    }

    #[test]
    fn split_count_is_bounded_by_the_canonical_deficit() {
        // The wallet wants 4 and has 1, so it needs 3 even though the source could
        // fund far more.
        let config = config_with_min(4);
        let big = config.band.mid * 50 + 50_000_000;
        let plan = plan_split(big, source_ref(0xBB, 0), 1, &test_params(), &config)
            .expect("a big source funds the deficit");
        assert_eq!(
            plan.output_count, 3,
            "the split mints only the canonical deficit"
        );
    }

    #[test]
    fn split_count_is_bounded_by_what_the_source_funds() {
        // A source that funds only two band-mid outputs beyond the fee+change
        // reserve mints two even though the deficit is larger.
        let config = config_with_min(10);
        let params = test_params();
        let reserve = linear_fee(&params, params.max_tx_size)
            + min_ada_for_output(&params, CHANGE_OUTPUT_SIZE_FLOOR);
        let source = config.band.mid * 2 + reserve + 1;
        let plan = plan_split(source, source_ref(0xCC, 0), 0, &params, &config)
            .expect("the source funds two outputs");
        assert_eq!(plan.output_count, 2, "the split is funded-bounded to two");
    }

    #[test]
    fn split_is_none_when_the_source_cannot_fund_one_output() {
        let config = config_with_min(4);
        // A source below band-mid + reserve cannot mint even one band-mid output.
        let too_small = config.band.mid; // no room for fee or change reserve
        assert!(
            plan_split(too_small, source_ref(0xDD, 0), 0, &test_params(), &config).is_none(),
            "a source that cannot fund one band-mid output yields no plan"
        );
    }

    #[test]
    fn split_is_none_when_already_stocked() {
        let config = config_with_min(4);
        let big = config.band.mid * 50 + 50_000_000;
        let params = test_params();
        assert!(
            plan_split(big, source_ref(0xEE, 0), 4, &params, &config).is_none(),
            "a wallet at its minimum needs no split"
        );
        assert!(
            plan_split(big, source_ref(0xEE, 0), 5, &params, &config).is_none(),
            "a wallet above its minimum needs no split"
        );
    }

    /// The split builder produces a real, signable, fee-balanced multi-output
    /// transaction: every minted output sits below the canonical index cap, the
    /// fee equals the linear fee over the signed size, and the value balances
    /// (inputs == minted + change + fee). This exercises the actual Conway builder
    /// and ed25519 signing path with a local test key.
    #[test]
    fn split_builder_emits_a_balanced_multi_output_tx() {
        let config = config_with_min(4);
        let params = test_params();
        // A preprod enterprise address for a known key; the build only needs a
        // network-matching bech32 address, so derive one from the test key.
        let seed = [9u8; 32];
        let secret = SecretKey::from(seed);
        let vk: [u8; 32] = {
            let pk = secret.public_key();
            let mut out = [0u8; 32];
            out.copy_from_slice(pk.as_ref());
            out
        };
        let address = enterprise_addr_preprod(&vk);

        // min_canonical_count is 4 and the wallet has 0, so the deficit is 4; the
        // source is large enough to fund all four band-mid outputs.
        let plan = plan_split(
            config.band.mid * 6 + 50_000_000,
            source_ref(0x42, 3),
            0,
            &params,
            &config,
        )
        .expect("plan a split");
        assert_eq!(plan.output_count, 4, "deficit-bounded to four outputs");

        let built = build_split_tx(&plan, &address, vk, &params, &config).expect("build the split");
        assert_eq!(built.minted, 4);

        // The minted outputs are at indexes 0..4 by construction (all < the cap),
        // and the unsigned tx re-decodes to the expected output count.
        let tx = ConwayTx::decode_fragment(&built.unsigned_tx_bytes).expect("decode tx");
        let outputs = &tx.transaction_body.outputs;
        assert!(
            outputs.len() >= 4,
            "at least the four minted outputs are present"
        );
        assert!(
            (outputs.len() as u32) <= MAX_CANONICAL_OUTPUT_INDEX,
            "the change output keeps the total within the index cap"
        );

        // Sign with the test key and confirm the witnessed tx re-encodes (a real,
        // submittable transaction).
        let signature = secret.sign(built.tx_hash);
        let mut sig64 = [0u8; 64];
        sig64.copy_from_slice(<_ as AsRef<[u8]>>::as_ref(&signature));
        let signed = witness_tx(&built.unsigned_tx_bytes, vk, &sig64);
        assert!(
            ConwayTx::decode_fragment(&signed).is_ok(),
            "the signed split transaction re-decodes"
        );

        // Value conservation: the body carries exactly one input (the source) and
        // a fee that is the exact linear fee over the signed size. The change is
        // source - minted_total - fee by construction, so the minted-plus-change
        // plus fee equals the source.
        let fee = tx.transaction_body.fee;
        let minted_total = plan.per_output_lovelace * u64::from(plan.output_count);
        assert_eq!(
            tx.transaction_body.inputs.len(),
            1,
            "the split spends exactly the single source input"
        );
        let signed_size = signed_size(&built.unsigned_tx_bytes, vk);
        assert_eq!(
            fee,
            linear_fee(&params, signed_size),
            "the split fee is the exact linear fee over the signed size"
        );
        // The change the build kept is the source minus the minted total and the
        // fee, and it must clear the minimum-ADA floor (so it was kept, not folded)
        // for this well-funded source.
        let expected_change = plan.source_lovelace - minted_total - fee;
        assert!(expected_change > 0, "a well-funded split leaves change");
        assert_eq!(
            outputs.len() as u32,
            plan.output_count + 1,
            "the minted outputs plus one change output are present"
        );
    }

    fn observed(byte: u8, lovelace: u64, pure_ada: bool) -> ObservedUtxo {
        ObservedUtxo {
            utxo: source_ref(byte, 0),
            lovelace,
            pure_ada,
        }
    }

    /// Candidate sources are returned largest-first, and only pure-ADA outputs above
    /// the band are candidates: a band-sized or token-bearing output is never a split
    /// source. The descending order is what lets the replenisher prefer the source
    /// that funds the most outputs while still falling through to a smaller one.
    #[test]
    fn splittable_sources_are_ordered_largest_first_and_filtered() {
        let config = config_with_min(4);
        let observed = vec![
            observed(0x01, config.band.max + 5_000_000, true), // candidate (mid)
            observed(0x02, config.band.max + 9_000_000, true), // candidate (largest)
            observed(0x03, config.band.mid, true),             // in-band: not a source
            observed(0x04, config.band.max + 12_000_000, false), // token-bearing: excluded
            observed(0x05, config.band.max + 1_000_000, true), // candidate (smallest)
        ];

        let ordered = splittable_sources_descending(&observed, &config);
        let lovelaces: Vec<u64> = ordered.iter().map(|o| o.lovelace).collect();
        assert_eq!(
            lovelaces,
            vec![
                config.band.max + 9_000_000,
                config.band.max + 5_000_000,
                config.band.max + 1_000_000,
            ],
            "only oversized pure-ADA sources, descending; the in-band and \
             token-bearing outputs are excluded"
        );
    }

    /// A wallet with no oversized pure-ADA output has no splittable source at all, so
    /// the candidate set is empty and the pass returns `NoFundableSource` without
    /// leasing anything.
    #[test]
    fn no_oversized_source_yields_no_candidates() {
        let config = config_with_min(4);
        let observed = vec![
            observed(0x01, config.band.mid, true),              // in-band
            observed(0x02, config.band.max, true),              // exactly at the cap, not above
            observed(0x03, config.band.max + 9_000_000, false), // token-bearing
        ];
        assert!(
            splittable_sources_descending(&observed, &config).is_empty(),
            "no source above the band means no candidate to split"
        );
    }

    /// The fee fixpoint's non-converging fallback never emits an underfunded body:
    /// the fee the body encodes is always at least the linear fee its signed size
    /// implies. This is the invariant the `fee = max(metered, required)` fallback
    /// guarantees, so a fee-increase oscillation across a CBOR boundary can never
    /// settle on a body that pays less fee than its size demands. Asserted directly
    /// over the assembled-at-max-fee shape so it does not depend on contriving a real
    /// oscillation.
    #[test]
    fn fee_fallback_is_never_underfunded() {
        let config = config_with_min(4);
        let params = test_params();
        let seed = [0x17u8; 32];
        let secret = SecretKey::from(seed);
        let vk: [u8; 32] = {
            let pk = secret.public_key();
            let mut out = [0u8; 32];
            out.copy_from_slice(pk.as_ref());
            out
        };
        let address = enterprise_addr_preprod(&vk);
        let address_parsed = Address::from_bech32(&address).expect("address");

        let plan = plan_split(
            config.band.mid * 6 + 50_000_000,
            source_ref(0x42, 3),
            0,
            &params,
            &config,
        )
        .expect("plan a split");
        let minted_total = plan.per_output_lovelace * u64::from(plan.output_count);

        // Reproduce the fallback's settle step: meter a low fee, then re-assemble at
        // the larger of that fee and the size-implied fee. The emitted body's encoded
        // fee must be >= the linear fee its signed size implies (never underfunded),
        // even when the starting fee was deliberately too low.
        let low_fee = linear_fee(&params, 0);
        let metered = assemble_split_at_fee(
            &address_parsed,
            &plan,
            &params,
            &config,
            minted_total,
            low_fee,
        )
        .expect("assemble at low fee");
        let metered_size = signed_size(&metered, vk);
        let required = linear_fee(&params, metered_size);
        let settled_fee = low_fee.max(required);
        let body = assemble_split_at_fee(
            &address_parsed,
            &plan,
            &params,
            &config,
            minted_total,
            settled_fee,
        )
        .expect("assemble at settled fee");

        let tx = ConwayTx::decode_fragment(&body).expect("decode body");
        let encoded_fee = tx.transaction_body.fee;
        let size_implied = linear_fee(&params, signed_size(&body, vk));
        assert!(
            encoded_fee >= size_implied,
            "the fallback body pays at least the fee its size implies: \
             encoded {encoded_fee} >= size-implied {size_implied}"
        );

        // The whole builder also upholds the invariant on its returned body, whether
        // it converged or fell through, and the recorded fee matches the encoded one.
        let built = build_split_tx(&plan, &address, vk, &params, &config).expect("build");
        let built_tx = ConwayTx::decode_fragment(&built.unsigned_tx_bytes).expect("decode built");
        assert!(
            built_tx.transaction_body.fee
                >= linear_fee(&params, signed_size(&built.unsigned_tx_bytes, vk)),
            "build_split_tx never returns an underfunded body"
        );
        assert_eq!(
            built.fee, built_tx.transaction_body.fee,
            "the recorded fee matches the encoded body fee"
        );
    }

    /// Derive a preprod enterprise bech32 address from a verification key for the
    /// builder test (the address only needs to be network-matching bech32).
    fn enterprise_addr_preprod(vk: &[u8; 32]) -> String {
        use pallas_addresses::{
            Network as AddrNetwork, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart,
        };
        let key_hash = Hasher::<224>::hash(vk);
        let addr = ShelleyAddress::new(
            AddrNetwork::Testnet,
            ShelleyPaymentPart::key_hash(key_hash),
            ShelleyDelegationPart::Null,
        );
        addr.to_bech32().expect("enterprise address encodes")
    }
}
