//! Construction of the transaction metadata map carrying the Proof-of-Existence
//! record under metadata label 309.
//!
//! Cardano caps a single transaction-metadata byte string at 64 bytes, so the
//! record body crosses the ledger as a whole-body chunk array: a CBOR array of
//! byte strings of at most 64 bytes each whose in-order concatenation is the
//! record. The chunk-array form is required regardless of body length — a body
//! of 64 bytes or fewer is still emitted as a one-element array, never as a
//! bare map or bare byte string. A verifier reassembles the record by
//! concatenating the array elements in order. The encoding is deterministic:
//! the same record always yields the same auxiliary-data bytes.

use pallas_primitives::{
    alonzo::PostAlonzoAuxiliaryData,
    conway::{AuxiliaryData, NativeScript},
    Fragment, Metadata, Metadatum,
};

/// The Cardano transaction-metadata label under which Proof-of-Existence
/// records are published.
pub const POE_METADATA_LABEL: u64 = 309;

/// Maximum length, in bytes, of a single metadata byte string. The Cardano
/// ledger rejects any metadata byte string longer than this, so records above
/// the limit are chunked across a list of byte strings.
pub const METADATA_CHUNK_SIZE: usize = 64;

/// Split a record into the ordered list of byte-string chunks the metadatum
/// carries: the minimal split, every chunk except the last exactly 64 bytes.
/// A record of length `n` produces `ceil(n / 64)` chunks.
///
/// An empty record produces a single empty chunk so the metadatum value stays
/// a one-element chunk array rather than an empty list. This is a degenerate
/// input only: zero bytes are not a decodable record, and the publish pipeline
/// validates the record before any transaction is built, so an empty record
/// never reaches a real transaction.
#[must_use]
pub fn chunk_record(record: &[u8]) -> Vec<Vec<u8>> {
    if record.is_empty() {
        return vec![Vec::new()];
    }
    record
        .chunks(METADATA_CHUNK_SIZE)
        .map(<[u8]>::to_vec)
        .collect()
}

/// Build the typed auxiliary data for a record: a single metadata entry keyed
/// by [`POE_METADATA_LABEL`] whose value is the array of byte-string chunks.
///
/// The chunks are wrapped in the Conway-era post-Alonzo auxiliary-data shape
/// (a tagged map) carrying only the metadata field. Native and Plutus script
/// slots stay absent because a Proof-of-Existence transaction publishes data,
/// not scripts.
#[must_use]
pub fn build_auxiliary_data(record: &[u8]) -> AuxiliaryData {
    let chunks = chunk_record(record);
    let value = Metadatum::Array(
        chunks
            .into_iter()
            .map(|chunk| Metadatum::Bytes(chunk.into()))
            .collect(),
    );

    let mut metadata: Metadata = Metadata::new();
    metadata.insert(POE_METADATA_LABEL, value);

    AuxiliaryData::PostAlonzo(PostAlonzoAuxiliaryData {
        metadata: Some(metadata),
        native_scripts: None::<Vec<NativeScript>>,
        plutus_scripts: None,
    })
}

/// Encode the record's auxiliary data to its canonical CBOR bytes.
///
/// These are exactly the bytes that hash to the body's `auxiliary_data_hash`
/// and that the transaction carries in its auxiliary-data slot.
#[must_use]
pub fn encode_auxiliary_data(record: &[u8]) -> Vec<u8> {
    build_auxiliary_data(record)
        .encode_fragment()
        .expect("auxiliary data is always encodable")
}
