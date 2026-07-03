//! Transaction assembly: selection, fee, change balancing, and Ed25519 signing.
//!
//! The flow is:
//!
//! 1. Encode the record into the label-309 auxiliary data and hash it.
//! 2. Order the candidate UTxOs (value first) and select a covering prefix.
//! 3. Compute the linear fee over the *signed* transaction size: the body, the
//!    auxiliary data, and exactly one Ed25519 vkey witness. The witness is a
//!    fixed-size structure (a 32-byte key and a 64-byte signature), so a
//!    zero-filled placeholder witness measures the same number of bytes the
//!    real signature will occupy.
//! 4. Balance the change: keep it when it clears the minimum-ADA threshold,
//!    fold it into the fee when no further input is available, or pull in
//!    another input and re-balance.
//! 5. Emit the unsigned transaction (empty witness set). Signing later replaces
//!    only the witness bytes, never the body, fee, or transaction hash.
//!
//! Every step is a pure function of the [`BuildRequest`], so the resulting
//! bytes are reproducible by an independent implementation.

use pallas_addresses::{Address, Network};
use pallas_codec::minicbor;
use pallas_crypto::hash::Hasher;
use pallas_crypto::key::ed25519::{PublicKey, SecretKey};
use pallas_primitives::conway::Tx as ConwayTx;
use pallas_primitives::Fragment;
use pallas_txbuilder::{
    BuildConway, BuiltTransaction, Input, Output, StagingTransaction, TxBuilderError,
};

use crate::fee::{linear_fee, min_ada_for_output};
use crate::metadata;
use crate::selection::{cover, prioritise, total_lovelace, Candidate};
use crate::types::{BuildError, BuildRequest, BuiltPoeTx, Validity};

/// An Ed25519 signing key used to witness the transaction body.
///
/// Wraps a `pallas_crypto` secret key so the builder's public surface does not
/// leak the underlying crypto crate's types to callers that only need to pass a
/// key in and get signed bytes out.
pub struct SigningKey {
    pub(crate) inner: SecretKey,
}

impl SigningKey {
    /// Construct a signing key from a 32-byte Ed25519 seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: SecretKey::from(seed),
        }
    }

    /// The Ed25519 public key (verification key) for this signing key. A caller
    /// that derives a [`BuildRequest`] needs these 32 bytes for the request's
    /// `payment_verification_key`, so the build can size the witness exactly.
    #[must_use]
    pub fn verification_key(&self) -> [u8; 32] {
        let pk: PublicKey = self.inner.public_key();
        let mut out = [0u8; 32];
        out.copy_from_slice(pk.as_ref());
        out
    }
}

/// Build a Proof-of-Existence transaction from a request.
///
/// Returns the assembled, unsigned [`BuiltPoeTx`] on success, or a
/// [`BuildError`] describing why the request could not be satisfied
/// (insufficient funds, oversized transaction, malformed address or UTxO hash,
/// or network mismatch).
pub fn build_poe_tx(request: &BuildRequest) -> Result<BuiltPoeTx, BuildError> {
    let address = parse_change_address(request)?;
    let candidates = decode_candidates(request)?;
    if candidates.is_empty() && request.must_spend.is_empty() {
        return Err(BuildError::NoUtxos);
    }
    // Place every mandatory input ahead of the candidate selection, in a fixed
    // total order, then append the remaining candidates in prioritised order. A
    // minimum take equal to the forced count keeps all mandatory inputs in the
    // selection prefix no matter how little (or how much) coverage they supply.
    let forced = decode_forced(request)?;
    let forced_count = forced.len();
    let candidates = drop_forced_duplicates(candidates, &forced);
    let ordered = with_forced_first(forced, prioritise(candidates));
    let available = total_lovelace(&ordered);

    let aux_bytes = metadata::encode_auxiliary_data(&request.record_bytes);
    let aux_hash = blake2b_256(&aux_bytes);
    let _ = request.metadata_label; // label is fixed by the standard at 309

    let ctx = BuildCtx {
        request,
        address,
        aux_bytes: &aux_bytes,
    };

    let balanced = balance(&ctx, &ordered, available, forced_count)?;

    // Backstop against any future fee-math regression: a no-change build
    // spends its whole selection as fee, which is legitimate only for a dust
    // residual. Any fee folding more than the dust ceiling over its linear
    // floor would be burning spendable change, so refuse to build rather than
    // hand the wallet such a transaction to sign. Surfaced as a BuildError
    // (not a panic) so a regression fails the publish gracefully — the caller
    // can retry or refund — instead of taking down the request task.
    if balanced.change.is_none() {
        let linear = linear_fee(&ctx.request.protocol, balanced.total_size);
        let folded = balanced.fee.saturating_sub(linear);
        fee_backstop(folded, max_folded_residual(&ctx))?;
    }

    // Assert the size we metered against does not exceed the protocol cap.
    if balanced.total_size > request.protocol.max_tx_size {
        return Err(BuildError::TxTooLarge {
            size: balanced.total_size,
            max: request.protocol.max_tx_size,
        });
    }

    // The unsigned transaction is the staging build with an empty witness set.
    let unsigned = assemble(&ctx, balanced.selected, balanced.fee, balanced.change)
        .map_err(map_builder_err)?;
    let unsigned_tx_bytes = unsigned.tx_bytes.0.clone();
    let body_bytes = extract_body_bytes(&unsigned_tx_bytes);
    let tx_hash = blake2b_256(&body_bytes);

    // The body must carry exactly the auxiliary-data hash we computed, proving
    // the builder hashed the same canonical CBOR the transaction transports.
    let body_aux_hash = extract_aux_data_hash(&unsigned_tx_bytes)
        .expect("a record-bearing transaction always sets auxiliary_data_hash");
    assert_eq!(
        body_aux_hash, aux_hash,
        "builder auxiliary_data_hash must match the encoded auxiliary data"
    );

    let selected_inputs = body_input_order(&unsigned_tx_bytes);

    Ok(BuiltPoeTx {
        unsigned_tx_bytes,
        body_bytes,
        tx_hash,
        fee: balanced.fee,
        selected_inputs,
        change: balanced.change,
        total_size: balanced.total_size,
        aux_data_bytes: aux_bytes,
        aux_data_hash: aux_hash,
    })
}

impl BuiltPoeTx {
    /// Sign the transaction body with `signing_key` and return the complete
    /// signed transaction bytes together with its transaction hash.
    ///
    /// The signature occupies the exact byte budget the fee already paid for,
    /// so the signed transaction has the same body and the same
    /// [`BuiltPoeTx::tx_hash`] as the unsigned one.
    #[must_use]
    pub fn sign(&self, signing_key: &SigningKey) -> (Vec<u8>, [u8; 32]) {
        let mut tx = ConwayTx::decode_fragment(&self.unsigned_tx_bytes)
            .expect("a builder-produced transaction always re-decodes");

        let public: PublicKey = signing_key.inner.public_key();
        let signature = signing_key.inner.sign(self.tx_hash);

        let witness = pallas_primitives::conway::VKeyWitness {
            vkey: public.as_ref().to_vec().into(),
            signature: <_ as AsRef<[u8]>>::as_ref(&signature).to_vec().into(),
        };
        tx.transaction_witness_set.vkeywitness = Some(
            pallas_primitives::NonEmptySet::from_vec(vec![witness])
                .expect("a one-element witness set is never empty"),
        );

        let signed = tx
            .encode_fragment()
            .expect("a witnessed transaction always re-encodes");
        (signed, self.tx_hash)
    }
}

/// The fixed parts of a build, threaded through the balancing helpers.
struct BuildCtx<'a> {
    request: &'a BuildRequest,
    address: Address,
    aux_bytes: &'a [u8],
}

/// The result of the balancing fixpoint: the inputs to spend, the fee to
/// charge, the change to return (or `None` when folded), and the signed size
/// the fee was metered over.
struct Balanced<'a> {
    selected: &'a [Candidate],
    fee: u64,
    change: Option<u64>,
    total_size: u64,
}

/// The exact outcome of balancing a *fixed* selection: its fee, its signed
/// size, and whether the change cleared the minimum-ADA floor (so the caller
/// can decide whether to add an input).
struct Settled {
    fee: u64,
    change: Option<u64>,
    total_size: u64,
    /// True when a change output was kept whose value fell below the
    /// minimum-ADA floor and a spare input is available to lift it. The
    /// selection loop reads this to add an input rather than fold.
    change_below_floor: bool,
}

/// Balance selection, fee, and change to a stable fixed point.
///
/// Loops at most `inputs + 2` times. Each iteration settles the fee for the
/// current selection exactly; if the resulting change is positive but below the
/// minimum-ADA floor and a spare input remains, one is added and the loop
/// repeats. Across iterations the fee is monotonically non-decreasing (the body
/// only ever grows as inputs are added), which the loop asserts so a regression
/// that lets the fee oscillate is caught.
fn balance<'a>(
    ctx: &BuildCtx,
    ordered: &'a [Candidate],
    available: u64,
    forced_count: usize,
) -> Result<Balanced<'a>, BuildError> {
    let params = &ctx.request.protocol;

    // Start from the smallest covering prefix for a lower-bound target: the
    // constant fee plus a minimal change floor. Selection only ever grows from
    // here. The forced inputs occupy the front of `ordered`, so any prefix at
    // least `forced_count` long already contains all of them; the floor below
    // guarantees the selection never drops one. When forced inputs alone already
    // cover the target the cover prefix may be shorter than `forced_count`, so
    // the floor lifts it back up.
    let floor_change = min_change_value(ctx, 0);
    let initial_target = params.min_fee_b.saturating_add(floor_change);
    let mut take = match cover(ordered, initial_target) {
        Some(prefix) => prefix.len(),
        None => ordered.len(),
    }
    .max(forced_count)
    .max(1);

    let bound = ordered.len() + 2;
    let mut prev_fee = 0u64;

    for _ in 0..bound {
        let selected = &ordered[..take];
        let has_spare = take < ordered.len();

        let settled = settle(ctx, selected, has_spare)?;
        match settled {
            None => {
                // The selection cannot cover even its own fee.
                if has_spare {
                    take += 1;
                    continue;
                }
                let fee = no_change_fee(ctx, selected)?;
                return Err(BuildError::InsufficientFunds { available, fee });
            }
            Some(s) => {
                assert!(
                    s.fee >= prev_fee,
                    "fee must not decrease across balancing iterations"
                );
                prev_fee = s.fee;

                if s.change_below_floor && has_spare {
                    // A spare input can lift the change over the floor; add it.
                    take += 1;
                    continue;
                }

                return Ok(Balanced {
                    selected,
                    fee: s.fee,
                    change: s.change,
                    total_size: s.total_size,
                });
            }
        }
    }

    Err(BuildError::InsufficientFunds {
        available,
        fee: prev_fee,
    })
}

/// Settle the fee and change for a *fixed* selection.
///
/// Returns `None` when the selection cannot cover its own fee. Otherwise the
/// returned [`Settled`] reports the fee, the change (kept or folded), the
/// signed size, and whether a kept change fell below the minimum-ADA floor.
/// The fee is the exact linear fee of the emitted body except when the
/// fixpoint cycles across a coin-width boundary, where it overpays by the
/// width step (a few bytes at `min_fee_a` each) so the change is kept.
///
/// Folding only happens when `has_spare` is false: when a below-floor change
/// could instead be cleared by adding an input, settling reports
/// `change_below_floor` so the caller adds one rather than folding.
fn settle(
    ctx: &BuildCtx,
    selected: &[Candidate],
    has_spare: bool,
) -> Result<Option<Settled>, BuildError> {
    let total = total_lovelace(selected);

    // Exact fee fixpoint for the change-bearing shape. The size is metered over
    // the *exact* body the build will emit: that body's fee and change coins
    // are the very values being settled, so their CBOR widths are accounted for
    // byte-for-byte. Fee and change move in opposite directions as those widths
    // shift, so iterate until the fee the size implies matches the fee the body
    // encoded.
    //
    // No fixpoint exists when the change sits within one fee-step of a CBOR
    // coin-width boundary (2^32 lovelace in practice, ~4295 ADA): the higher
    // fee narrows the change by a width step, implying the lower fee, which
    // widens the change again, forever. The iteration then revisits a fee it
    // already produced, closing a cycle whose members are each the exact
    // linear fee of another cycle member's body. Charging the cycle's LARGEST
    // fee while keeping the change therefore always covers the emitted body's
    // linear fee (the ledger accepts any fee at or above the minimum), and the
    // overpay is bounded by the width step — never the change itself.
    let mut fee = linear_fee(&ctx.request.protocol, 0);
    let mut seen: Vec<u64> = Vec::with_capacity(MICRO_BALANCE_STEPS);
    loop {
        if total <= fee {
            // Cannot pay this fee; let the caller add an input or report
            // insufficient funds.
            return Ok(None);
        }
        let change = total - fee;
        let size = signed_size(ctx, selected, fee, Some(change))?;
        let required = linear_fee(&ctx.request.protocol, size);
        if required == fee {
            return keep_or_fold_change(ctx, selected, has_spare, total, fee, change, size);
        }
        seen.push(fee);
        if let Some(entry) = seen.iter().position(|&f| f == required) {
            // The fixpoint is a cycle over `seen[entry..]`; resolve it with the
            // cycle's largest fee. Every cycle member passed the coverage check
            // above while it was current, so `total > fee` holds here.
            let fee = *seen[entry..]
                .iter()
                .max()
                .expect("a detected cycle contains at least one fee");
            let change = total - fee;
            let size = signed_size(ctx, selected, fee, Some(change))?;
            assert!(
                linear_fee(&ctx.request.protocol, size) <= fee,
                "cycle-resolved fee must cover the emitted body's linear fee"
            );
            return keep_or_fold_change(ctx, selected, has_spare, total, fee, change, size);
        }
        assert!(
            seen.len() < MICRO_BALANCE_STEPS,
            "fee fixpoint neither converged nor cycled within {MICRO_BALANCE_STEPS} steps"
        );
        fee = required;
    }
}

/// Complete a settled `(fee, change, size)` triple: keep the change when it
/// clears the minimum-ADA floor, report `change_below_floor` when it does not
/// but a spare input could lift it, or fold a genuine dust residual into the
/// fee as the last resort.
fn keep_or_fold_change(
    ctx: &BuildCtx,
    selected: &[Candidate],
    has_spare: bool,
    total: u64,
    fee: u64,
    change: u64,
    size: u64,
) -> Result<Option<Settled>, BuildError> {
    let min_change = min_change_value(ctx, change);
    if change < min_change {
        if has_spare {
            // Signal the caller to add an input instead of folding.
            return Ok(Some(Settled {
                fee,
                change: Some(change),
                total_size: size,
                change_below_floor: true,
            }));
        }
        // No spare input: the below-floor residual is dust; fold it.
        return fold_residual(ctx, selected, total);
    }
    Ok(Some(Settled {
        fee,
        change: Some(change),
        total_size: size,
        change_below_floor: false,
    }))
}

/// Fold a dust residual into the fee and emit no change output, spending the
/// whole selected value. Only ever reached when the settled change fell below
/// the minimum-ADA floor and no spare input can lift it, so the amount folded
/// on top of the linear fee is bounded by that floor — never a spendable
/// change. Returns `None` when the selection cannot even cover the no-change
/// fee.
fn fold_residual(
    ctx: &BuildCtx,
    selected: &[Candidate],
    total: u64,
) -> Result<Option<Settled>, BuildError> {
    let no_change_size = signed_size(ctx, selected, total, None)?;
    let no_change_fee = linear_fee(&ctx.request.protocol, no_change_size);
    if total < no_change_fee {
        return Ok(None);
    }
    Ok(Some(Settled {
        fee: total,
        change: None,
        total_size: no_change_size,
        change_below_floor: false,
    }))
}

/// Upper bound on the fee-fixpoint iterations for a fixed selection. Each step
/// either converges, closes a width cycle (both terminal), or records a fee
/// value not seen before; distinct values are limited by the handful of CBOR
/// coin-width combinations the fee and change can take, so the bound is never
/// reached and only guards against a size-metering regression.
const MICRO_BALANCE_STEPS: usize = 16;

/// The linear fee for a selection's no-change transaction shape, measured over
/// its exact signed size. Used to report the fee floor an underfunded request
/// fell short of.
fn no_change_fee(ctx: &BuildCtx, selected: &[Candidate]) -> Result<u64, BuildError> {
    let total = total_lovelace(selected);
    let size = signed_size(ctx, selected, total, None)?;
    Ok(linear_fee(&ctx.request.protocol, size))
}

/// The exact serialised size, in bytes, of the signed transaction for a given
/// selection, fee, and change. The body is encoded with the exact fee and
/// change the build will emit, then one placeholder witness is added so the
/// size equals the signed transaction's.
fn signed_size(
    ctx: &BuildCtx,
    selected: &[Candidate],
    fee: u64,
    change: Option<u64>,
) -> Result<u64, BuildError> {
    let built = assemble(ctx, selected, fee, change).map_err(map_builder_err)?;
    let signed = add_placeholder_witness(ctx, built);
    Ok(signed.len() as u64)
}

/// Assemble the unsigned transaction for a selection, fee, and change via the
/// canonical pallas Conway builder.
fn assemble(
    ctx: &BuildCtx,
    selected: &[Candidate],
    fee: u64,
    change: Option<u64>,
) -> Result<BuiltTransaction, TxBuilderError> {
    let mut staging = StagingTransaction::new()
        .network_id(ctx.request.network_id)
        .fee(fee)
        .add_auxiliary_data(ctx.aux_bytes.to_vec());

    for c in selected {
        staging = staging.input(Input::new(c.tx_id.into(), u64::from(c.utxo.index)));
    }

    if let Some(value) = change {
        staging = staging.output(Output::new(ctx.address.clone(), value));
    }

    if let Some(v) = ctx.request.validity {
        staging = apply_validity(staging, v);
    }

    staging.build_conway_raw()
}

/// Apply an optional validity interval to the staging transaction.
fn apply_validity(mut staging: StagingTransaction, validity: Validity) -> StagingTransaction {
    if let Some(ttl) = validity.invalid_hereafter {
        staging = staging.invalid_from_slot(ttl);
    }
    if let Some(from) = validity.valid_from {
        staging = staging.valid_from_slot(from);
    }
    staging
}

/// Re-encode a built transaction with one zero-filled vkey witness, returning
/// the signed-form bytes. The placeholder occupies exactly the byte budget the
/// real signature will, so the size measured here is the size the fee pays for.
fn add_placeholder_witness(ctx: &BuildCtx, built: BuiltTransaction) -> Vec<u8> {
    let mut tx = ConwayTx::decode_fragment(&built.tx_bytes.0)
        .expect("a builder-produced transaction always re-decodes");
    let witness = pallas_primitives::conway::VKeyWitness {
        vkey: ctx.request.payment_verification_key.to_vec().into(),
        signature: vec![0u8; 64].into(),
    };
    tx.transaction_witness_set.vkeywitness = Some(
        pallas_primitives::NonEmptySet::from_vec(vec![witness])
            .expect("a one-element witness set is never empty"),
    );
    tx.encode_fragment()
        .expect("a witnessed transaction always re-encodes")
}

/// The serialised size, in bytes, of a change output to the request's address
/// carrying `coin` lovelace.
fn change_output_size(ctx: &BuildCtx, coin: u64) -> u64 {
    let output = Output::new(ctx.address.clone(), coin.max(1));
    let built = output
        .build_babbage_raw()
        .expect("change output is always encodable");
    minicbor::to_vec(&built)
        .expect("change output always serialises")
        .len() as u64
}

/// The minimum-ADA value a change output carrying `change` lovelace must hold.
/// Computed over the exact serialised size of that output.
fn min_change_value(ctx: &BuildCtx, change: u64) -> u64 {
    min_ada_for_output(&ctx.request.protocol, change_output_size(ctx, change))
}

/// Refuse a no-change build whose folded residual exceeds the dust ceiling.
///
/// `folded` is the amount the build's fee exceeds its exact linear fee by;
/// `ceiling` is [`max_folded_residual`]. Anything over the ceiling means the
/// balancing loop mis-metered and is about to burn spendable change as fee —
/// a must-never-happen the caller turns into a failed (retryable/refundable)
/// publish rather than a signed transaction.
fn fee_backstop(folded: u64, ceiling: u64) -> Result<(), BuildError> {
    if folded > ceiling {
        return Err(BuildError::ExcessiveFeeFold { folded, ceiling });
    }
    Ok(())
}

/// The largest residual a legitimate dust fold can absorb on top of the
/// no-change linear fee: a below-floor change (bounded by the widest change
/// output's minimum-ADA floor) plus the fee delta between the change-bearing
/// and no-change body shapes (bounded by that output's bytes plus framing
/// slack, priced at `min_fee_a` per byte).
fn max_folded_residual(ctx: &BuildCtx) -> u64 {
    let params = &ctx.request.protocol;
    let widest_output = change_output_size(ctx, u64::MAX);
    min_ada_for_output(params, widest_output).saturating_add(
        params
            .min_fee_a
            .saturating_mul(widest_output.saturating_add(8)),
    )
}

/// Parse and validate the request's bech32 change address.
fn parse_change_address(request: &BuildRequest) -> Result<Address, BuildError> {
    let address = Address::from_bech32(&request.change_address)
        .map_err(|e| BuildError::InvalidAddress(e.to_string()))?;
    let network = address.network();
    let want = match request.network_id {
        0 => Network::Testnet,
        1 => Network::Mainnet,
        other => Network::Other(other),
    };
    match network {
        Some(n) if n == want => Ok(address),
        _ => Err(BuildError::NetworkMismatch(request.network_id)),
    }
}

/// Decode every candidate UTxO's transaction hash, failing on malformed hex.
fn decode_candidates(request: &BuildRequest) -> Result<Vec<Candidate>, BuildError> {
    request.utxos.iter().map(decode_one).collect()
}

/// Decode the mandatory-spend UTxOs into candidates, placing them in a fixed
/// total order (transaction-hash bytes then output index ascending) and
/// rejecting any duplicate reference inside the set.
///
/// The order is independent of the order the caller listed them in, so the same
/// mandatory set always lands in the same body position; the duplicate check
/// catches a `(tx_hash, index)` repeated within `must_spend` before it could
/// double-count its value.
fn decode_forced(request: &BuildRequest) -> Result<Vec<Candidate>, BuildError> {
    let mut forced: Vec<Candidate> = request
        .must_spend
        .iter()
        .map(decode_one)
        .collect::<Result<Vec<_>, _>>()?;
    // A fixed total order by (tx_id, index) makes the forced prefix deterministic
    // regardless of the caller's listing order.
    forced.sort_by_key(|c| (c.tx_id, c.utxo.index));
    for pair in forced.windows(2) {
        if pair[0].tx_id == pair[1].tx_id && pair[0].utxo.index == pair[1].utxo.index {
            return Err(BuildError::DuplicateMustSpend {
                tx_hash: pair[0].utxo.tx_hash.clone(),
                index: pair[0].utxo.index,
            });
        }
    }
    Ok(forced)
}

/// Decode one UTxO's transaction hash into a [`Candidate`], failing on malformed
/// hex or a wrong length.
fn decode_one(u: &crate::types::Utxo) -> Result<Candidate, BuildError> {
    let raw =
        hex::decode(&u.tx_hash).map_err(|_| BuildError::InvalidUtxoHash(u.tx_hash.clone()))?;
    let tx_id: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| BuildError::InvalidUtxoHash(u.tx_hash.clone()))?;
    Ok(Candidate {
        utxo: u.clone(),
        tx_id,
    })
}

/// Remove from the candidate set any reference already present in `forced`, so a
/// UTxO the caller listed both as mandatory and as a candidate is spent once,
/// not twice.
fn drop_forced_duplicates(candidates: Vec<Candidate>, forced: &[Candidate]) -> Vec<Candidate> {
    candidates
        .into_iter()
        .filter(|c| {
            !forced
                .iter()
                .any(|f| f.tx_id == c.tx_id && f.utxo.index == c.utxo.index)
        })
        .collect()
}

/// Concatenate the forced prefix (already in its fixed order) with the
/// prioritised candidates, so every mandatory input sits ahead of any optional
/// one in the selection order.
fn with_forced_first(mut forced: Vec<Candidate>, prioritised: Vec<Candidate>) -> Vec<Candidate> {
    forced.extend(prioritised);
    forced
}

/// Blake2b-256 digest as a fixed 32-byte array.
fn blake2b_256(bytes: &[u8]) -> [u8; 32] {
    *Hasher::<256>::hash(bytes)
}

/// Extract the raw CBOR bytes of the transaction body from a full transaction.
fn extract_body_bytes(tx_bytes: &[u8]) -> Vec<u8> {
    let tx = ConwayTx::decode_fragment(tx_bytes)
        .expect("a builder-produced transaction always re-decodes");
    tx.transaction_body.raw_cbor().to_vec()
}

/// Extract the body's `auxiliary_data_hash`, if present.
fn extract_aux_data_hash(tx_bytes: &[u8]) -> Option<[u8; 32]> {
    let tx = ConwayTx::decode_fragment(tx_bytes)
        .expect("a builder-produced transaction always re-decodes");
    tx.transaction_body.auxiliary_data_hash.map(|h| *h)
}

/// The transaction body's input set in serialised order, as `(hex, index)`.
fn body_input_order(tx_bytes: &[u8]) -> Vec<(String, u32)> {
    let tx = ConwayTx::decode_fragment(tx_bytes)
        .expect("a builder-produced transaction always re-decodes");
    tx.transaction_body
        .inputs
        .iter()
        .map(|i| (hex::encode(*i.transaction_id), i.index as u32))
        .collect()
}

/// Map a transaction-builder error into the crate's error surface.
///
/// Every caller-driven failure (a malformed address or UTxO hash, a network
/// mismatch) is caught and reported before the builder is ever invoked, and a
/// Proof-of-Existence transaction carries no scripts, datums, or redeemers, so
/// the only structural inputs the builder validates are already known good.
/// A builder error here therefore means an internal invariant was broken, not
/// that the caller supplied something invalid, so it surfaces as a panic with
/// the underlying cause rather than a misleading [`BuildError`].
fn map_builder_err(e: TxBuilderError) -> BuildError {
    panic!("transaction builder rejected validated inputs: {e}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The no-change fee backstop is a returned build error, never a panic: a
    /// fee-metering regression must fail the publish gracefully (retryable /
    /// refundable), not take down the request task.
    #[test]
    fn the_fee_backstop_refuses_over_ceiling_folds_without_panicking() {
        assert!(fee_backstop(0, 10).is_ok());
        assert!(
            fee_backstop(10, 10).is_ok(),
            "at the ceiling is a dust fold"
        );
        match fee_backstop(11, 10) {
            Err(BuildError::ExcessiveFeeFold { folded, ceiling }) => {
                assert_eq!((folded, ceiling), (11, 10));
            }
            other => panic!("expected ExcessiveFeeFold, got {other:?}"),
        }
    }
}
