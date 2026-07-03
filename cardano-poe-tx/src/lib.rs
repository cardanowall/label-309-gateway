//! Deterministic Cardano Proof-of-Existence transaction builder.
//!
//! This crate turns a Proof-of-Existence record into an unsigned Cardano
//! transaction that publishes the record under transaction metadata label 309,
//! plus a signing step that witnesses it. It performs deterministic coin
//! selection over caller-supplied UTxOs, computes the exact linear fee
//! (including the single Ed25519 vkey witness), folds or adds inputs so the
//! change output clears the minimum-ADA threshold, and signs the transaction
//! body with an Ed25519 key.
//!
//! The builder is side-effect free and fully determined by its inputs: it never
//! reads a clock, draws randomness, or performs I/O, so the same
//! [`BuildRequest`] always produces the same [`BuiltPoeTx`] bytes. That
//! property is what makes its output reproducible by an independent oracle and
//! auditable by a gateway.
//!
//! # Layout
//!
//! - [`types`] — the public input/output data ([`BuildRequest`], [`BuiltPoeTx`],
//!   [`ProtocolParams`], [`Utxo`], [`Validity`], [`BuildError`]).
//! - [`metadata`] — label-309 auxiliary-data construction and record chunking.
//! - [`selection`] — deterministic coin selection.
//! - [`fee`] — linear fee and minimum-ADA computation.
//! - [`build`] — assembly and Ed25519 signing.

pub mod build;
pub mod fee;
pub mod metadata;
pub mod selection;
pub mod types;

pub use build::{build_poe_tx, SigningKey};
pub use metadata::{chunk_record, POE_METADATA_LABEL};
pub use types::{BuildError, BuildRequest, BuiltPoeTx, ProtocolParams, Utxo, Validity};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_record_chunks_to_a_single_empty_chunk() {
        let chunks = chunk_record(&[]);
        assert_eq!(chunks, vec![Vec::<u8>::new()]);
    }

    #[test]
    fn record_at_chunk_boundary_stays_a_single_chunk() {
        let record = vec![0xab_u8; metadata::METADATA_CHUNK_SIZE];
        let chunks = chunk_record(&record);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), metadata::METADATA_CHUNK_SIZE);
    }

    #[test]
    fn record_one_byte_over_boundary_splits_into_two_chunks() {
        let record = vec![0x01_u8; metadata::METADATA_CHUNK_SIZE + 1];
        let chunks = chunk_record(&record);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), metadata::METADATA_CHUNK_SIZE);
        assert_eq!(chunks[1].len(), 1);
    }

    #[test]
    fn fee_is_linear_in_size() {
        let params = ProtocolParams {
            min_fee_a: 44,
            min_fee_b: 155_381,
            coins_per_utxo_byte: 4310,
            max_tx_size: 16384,
        };
        // min_fee_a * size + min_fee_b
        assert_eq!(fee::linear_fee(&params, 0), 155_381);
        assert_eq!(fee::linear_fee(&params, 100), 44 * 100 + 155_381);
    }

    #[test]
    fn signing_key_round_trips_a_signature() {
        // Exercises the real pallas-crypto Ed25519 key path so the dependency
        // pin and the seed/verification-key derivation are covered by a
        // behaviour test.
        let key = SigningKey::from_seed([7u8; 32]);
        let vk = key.verification_key();
        let sig = key.inner.sign(b"poe");
        let public = key.inner.public_key();
        assert_eq!(public.as_ref(), &vk);
        assert!(public.verify(b"poe", &sig));
        assert!(!public.verify(b"tampered", &sig));
    }
}
