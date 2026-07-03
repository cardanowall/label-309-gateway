//! Public data types for the Proof-of-Existence transaction builder.
//!
//! These types are the entire input/output surface of the crate. They are
//! plain data with no behaviour beyond construction, so a caller can serialise
//! a [`BuildRequest`], hand it to the builder, and compare the resulting
//! [`BuiltPoeTx`] bytes against an independent reference implementation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Protocol parameters that determine the transaction fee and the minimum-ADA
/// value any output (including the change output) must carry.
///
/// All four fields come from the on-chain protocol parameters of the target
/// network; the builder never supplies defaults of its own, so the fee it
/// computes always matches the parameters in force when the caller fetched
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolParams {
    /// Linear fee coefficient (lovelace per transaction byte).
    pub min_fee_a: u64,
    /// Linear fee constant (lovelace).
    pub min_fee_b: u64,
    /// Lovelace charged per byte of a serialised output, used to derive the
    /// minimum-ADA value an output must hold to be ledger-valid.
    pub coins_per_utxo_byte: u64,
    /// Maximum serialised transaction size in bytes. A build that would exceed
    /// this is rejected rather than submitted and bounced by the node.
    pub max_tx_size: u64,
}

/// A single spendable output referenced by its transaction hash and index.
///
/// The order of UTxOs in a [`BuildRequest`] does not change *which* inputs are
/// selected (selection sorts by value, then by a total tie-break order), so the
/// same candidate set in any order selects the same subset and produces the
/// same bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    /// 32-byte transaction id, hex-encoded (64 hex characters).
    pub tx_hash: String,
    /// Output index within that transaction.
    pub index: u32,
    /// Lovelace held by the output.
    pub lovelace: u64,
}

/// Optional transaction validity interval.
///
/// `invalid_hereafter` maps to the transaction's TTL (the highest slot at which
/// it may still be accepted); `valid_from` maps to `validity_interval_start`
/// (the lowest slot). Both are absolute slot numbers supplied by the caller and
/// both are independently optional, so a request may set neither, either, or
/// both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    /// Upper bound: the transaction is invalid at or after this slot (TTL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid_hereafter: Option<u64>,
    /// Lower bound: the transaction is invalid before this slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<u64>,
}

impl Validity {
    /// Whether the interval would write any field into the transaction body.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.invalid_hereafter.is_none() && self.valid_from.is_none()
    }
}

/// Everything the builder needs to produce a transaction. No field is inferred
/// from the environment, so the request fully determines the output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRequest {
    /// The canonical Proof-of-Existence record bytes to embed under the
    /// transaction metadata label.
    pub record_bytes: Vec<u8>,
    /// Transaction metadata label the record is published under. Callers of the
    /// standard pass `309`; it is a parameter so the same builder can target a
    /// test label without a code change.
    pub metadata_label: u64,
    /// Candidate UTxOs to select from.
    pub utxos: Vec<Utxo>,
    /// UTxOs that MUST appear among the transaction's inputs, regardless of
    /// whether coverage would otherwise reach them.
    ///
    /// Every entry here is included before any candidate from [`Self::utxos`] is
    /// considered, and the covering selection then draws from `utxos` for any
    /// remaining shortfall. This is what lets a cancelling-replacement
    /// transaction guarantee it spends a specific input of the transaction it
    /// replaces: by consuming that input, the replaced transaction can never
    /// land afterwards.
    ///
    /// Determinism is preserved: the mandatory inputs are placed in a fixed
    /// total order (by transaction-hash bytes then index, the same tie-break the
    /// candidate selection uses), any entry also present in `utxos` is spent only
    /// once, and the candidate coverage that follows is unchanged. An empty list
    /// (the default, and the only shape the existing corpus exercises) reproduces
    /// the prior behaviour byte-for-byte.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub must_spend: Vec<Utxo>,
    /// Protocol parameters in force for the fee and minimum-ADA computation.
    pub protocol: ProtocolParams,
    /// Bech32 change address that receives the selected value minus the fee.
    pub change_address: String,
    /// Network discriminant (0 = testnet, 1 = mainnet) the change address must
    /// agree with.
    pub network_id: u8,
    /// The 32-byte Ed25519 payment verification key that will witness the
    /// transaction. It is required at build time, not just sign time, so the
    /// fee can account for the exact size of the single vkey witness this key
    /// produces.
    pub payment_verification_key: [u8; 32],
    /// Optional validity interval. Absent by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<Validity>,
}

/// A fully built Proof-of-Existence transaction.
///
/// The transaction is unsigned: its witness set is empty. The fee already
/// accounts for the single Ed25519 vkey witness that [`BuiltPoeTx::sign`] adds,
/// so signing changes only the witness bytes, never the body, fee, or
/// [`BuiltPoeTx::tx_hash`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltPoeTx {
    /// CBOR bytes of the complete unsigned transaction (empty witness set).
    pub unsigned_tx_bytes: Vec<u8>,
    /// CBOR bytes of the transaction body alone.
    pub body_bytes: Vec<u8>,
    /// 32-byte Blake2b-256 hash of the transaction body (the transaction id).
    /// Signing does not change it.
    pub tx_hash: [u8; 32],
    /// Fee in lovelace charged by this transaction.
    pub fee: u64,
    /// The inputs the builder selected, in the order they appear in the
    /// serialised transaction body.
    pub selected_inputs: Vec<(String, u32)>,
    /// Lovelace returned to the change address, or `None` when the selected
    /// value was folded entirely into the fee (no change output emitted).
    pub change: Option<u64>,
    /// Serialised size, in bytes, of the signed transaction the fee was
    /// computed over (body, empty-but-for-one-witness set, and auxiliary data).
    pub total_size: u64,
    /// Canonical CBOR bytes of the transaction auxiliary data (the label-309
    /// metadata).
    pub aux_data_bytes: Vec<u8>,
    /// 32-byte Blake2b-256 hash of [`Self::aux_data_bytes`]; equals the body's
    /// `auxiliary_data_hash`.
    pub aux_data_hash: [u8; 32],
}

/// Failure modes of a build. Each variant is a distinct, testable outcome; the
/// builder never panics on caller error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BuildError {
    /// The candidate UTxOs cannot cover the record's fee plus the minimum-ADA
    /// change output, even after selecting every available input.
    #[error("insufficient funds: available {available} lovelace cannot cover fee {fee}")]
    InsufficientFunds {
        /// Total lovelace across every candidate UTxO.
        available: u64,
        /// Fee the fully built transaction would charge once every input is
        /// selected.
        fee: u64,
    },
    /// The serialised transaction exceeds [`ProtocolParams::max_tx_size`].
    #[error("transaction size {size} exceeds the protocol maximum {max}")]
    TxTooLarge {
        /// Serialised size of the built transaction.
        size: u64,
        /// Protocol-defined maximum.
        max: u64,
    },
    /// The change address could not be parsed as a bech32 Cardano address.
    #[error("invalid change address: {0}")]
    InvalidAddress(String),
    /// The change address belongs to a different network than `network_id`.
    #[error("change address network does not match network_id {0}")]
    NetworkMismatch(u8),
    /// A candidate UTxO carried a `tx_hash` that was not 32 bytes of hex.
    #[error("invalid utxo tx_hash: {0}")]
    InvalidUtxoHash(String),
    /// No candidate UTxOs were supplied at all.
    #[error("no candidate utxos supplied")]
    NoUtxos,
    /// The mandatory-spend set listed the same `(tx_hash, index)` reference more
    /// than once (counting a reference that also appears in the candidate set).
    /// A duplicate input would double-count its value and produce a transaction
    /// the ledger rejects, so it is caught before assembly.
    #[error("duplicate forced-spend utxo: {tx_hash}#{index}")]
    DuplicateMustSpend {
        /// The hex transaction hash of the duplicated reference.
        tx_hash: String,
        /// The output index of the duplicated reference.
        index: u32,
    },
    /// A no-change build folded more lovelace over its exact linear fee than
    /// the dust ceiling permits. A legitimate fold only ever absorbs a
    /// below-minimum-ADA residual, so exceeding the ceiling means the fee
    /// metering regressed and the build was about to burn spendable change as
    /// fee; the build is refused instead of signed.
    #[error(
        "no-change build folds {folded} lovelace over its linear fee, \
         above the dust ceiling {ceiling}"
    )]
    ExcessiveFeeFold {
        /// Lovelace the fee exceeds the exact linear fee by.
        folded: u64,
        /// The largest residual a legitimate dust fold can absorb.
        ceiling: u64,
    },
}
