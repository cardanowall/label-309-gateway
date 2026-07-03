//! Deterministic coin selection.
//!
//! Selection imposes a total, value-first order on the candidate UTxOs:
//! largest lovelace first, ties broken by transaction-hash bytes ascending and
//! then output index ascending. Because the order is a pure function of the
//! candidate set, the caller-provided order of the UTxOs does not affect which
//! inputs are chosen, so two callers with the same candidate set always select
//! the same subset. The fee grows with each added input, so selection and fee
//! estimation are co-dependent and the builder iterates until they agree.

use crate::types::Utxo;

/// A candidate UTxO with its decoded 32-byte transaction id, ready to sort and
/// select without re-parsing hex on every comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The original request UTxO.
    pub utxo: Utxo,
    /// The decoded 32-byte transaction id used for the tie-break ordering and
    /// for the body's input set.
    pub tx_id: [u8; 32],
}

/// The selection ordering: descending lovelace, then ascending transaction-hash
/// bytes, then ascending output index. This is a strict total order over a
/// candidate set with no duplicate `(tx_id, index)` pairs.
fn order_key(c: &Candidate) -> (std::cmp::Reverse<u64>, [u8; 32], u32) {
    (std::cmp::Reverse(c.utxo.lovelace), c.tx_id, c.utxo.index)
}

/// Sort candidates into the deterministic selection priority order.
#[must_use]
pub fn prioritise(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by_key(order_key);
    candidates
}

/// Take the shortest prefix of `ordered` whose lovelace sums to at least
/// `target`. Returns `None` when even the whole set falls short.
///
/// `ordered` must already be in [`prioritise`] order; this function only walks
/// the prefix, it does not re-sort.
#[must_use]
pub fn cover(ordered: &[Candidate], target: u64) -> Option<&[Candidate]> {
    let mut total: u64 = 0;
    for (i, c) in ordered.iter().enumerate() {
        total = total.saturating_add(c.utxo.lovelace);
        if total >= target {
            return Some(&ordered[..=i]);
        }
    }
    None
}

/// Sum the lovelace of a slice of candidates.
#[must_use]
pub fn total_lovelace(candidates: &[Candidate]) -> u64 {
    candidates
        .iter()
        .fold(0u64, |acc, c| acc.saturating_add(c.utxo.lovelace))
}
