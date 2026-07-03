//! Linear fee and minimum-ADA computation.
//!
//! Cardano's fee is `min_fee_a * tx_size + min_fee_b`, where `tx_size` is the
//! serialised size of the fully witnessed transaction in bytes. The minimum
//! value an output may hold is `coins_per_utxo_byte * (serialised_output_size +
//! overhead)` per the post-Babbage rule. Both are pure functions of the
//! protocol parameters and the byte sizes the builder measures.

use crate::types::ProtocolParams;

/// The constant overhead, in bytes, the ledger adds to a serialised output when
/// deriving its minimum-ADA value. It accounts for the UTxO entry's bookkeeping
/// (the input pointer and a small fixed prefix) that an isolated output's own
/// serialisation does not include.
pub const MIN_UTXO_OVERHEAD_BYTES: u64 = 160;

/// Compute the linear fee for a transaction of `tx_size` serialised bytes.
#[must_use]
pub fn linear_fee(params: &ProtocolParams, tx_size: u64) -> u64 {
    params
        .min_fee_a
        .saturating_mul(tx_size)
        .saturating_add(params.min_fee_b)
}

/// Compute the minimum lovelace an output of `output_size` serialised bytes
/// must carry to be ledger-valid under the post-Babbage minimum-ADA rule.
#[must_use]
pub fn min_ada_for_output(params: &ProtocolParams, output_size: u64) -> u64 {
    params
        .coins_per_utxo_byte
        .saturating_mul(output_size.saturating_add(MIN_UTXO_OVERHEAD_BYTES))
}
