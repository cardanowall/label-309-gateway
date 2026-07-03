//! Carriage conformance: the indexer's label-309 unwrap replayed against the
//! standard's carriage vectors.
//!
//! The unwrap is the indexer's provider-API adapter: it accepts the metadatum
//! value a chain provider renders (Blockfrost's `{309: chunks}` metadata-map
//! form, or the bare chunk array) and reassembles the record body the strict
//! validator then gates. These tests pin it to the conformance vectors: every
//! positive vector reassembles to the exact body bytes — under both provider
//! shapes — and every non-conformant value shape the adapter can distinguish
//! is rejected. The reassembled body always feeds the strict record validator
//! before anything is indexed, so the two-layer disposition of the
//! empty-reassembly vectors (transport tolerates, body decode rejects) is
//! asserted across both layers.
//!
//! The two indefinite-length vectors are not replayed at this layer: the
//! provider re-serialises metadata, so the adapter's permissive decode does
//! not distinguish length-encoding definiteness. The reassembled bytes are
//! unaffected (a coalesced byte string concatenates to the same body), and the
//! definiteness rules are enforced where they are normative — the standalone
//! verifier's transport walk over hash-bound transaction bytes.

use gateway_core::chain::gateway::{
    classify_chain_error, unwrap_label309_chunked_metadatum, ChainErrorClass,
};
use gateway_core::chain::records::derive_chain_record_columns;
use std::path::{Path, PathBuf};

/// The CBOR prefix of a one-entry metadata map keyed by label 309 — the
/// Blockfrost `/metadata/txs/labels/{label}/cbor` wrapper shape.
const METADATA_MAP_PREFIX_HEX: &str = "a1190135";

fn carriage_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/carriage")
}

fn load_vectors(file: &str) -> Vec<serde_json::Value> {
    let path = carriage_dir().join(file);
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("vector file is JSON");
    doc["vectors"].as_array().expect("vectors array").clone()
}

fn hex_field(vector: &serde_json::Value, key: &str) -> Vec<u8> {
    let name = vector["name"].as_str().unwrap_or("?");
    hex::decode(
        vector[key]
            .as_str()
            .unwrap_or_else(|| panic!("vector {name} carries {key}")),
    )
    .unwrap_or_else(|e| panic!("vector {name} {key} hex: {e}"))
}

#[test]
fn every_positive_vector_reassembles_to_its_body_under_both_provider_shapes() {
    for vector in load_vectors("chunk-array-positive.json") {
        let name = vector["name"].as_str().expect("name");
        let value = hex_field(&vector, "label_309_value_cbor_hex");
        let body = hex_field(&vector, "expected_record_body_hex");

        // The bare chunk array, as the Koios-style digs deliver it.
        assert_eq!(
            unwrap_label309_chunked_metadatum(&value)
                .unwrap_or_else(|e| panic!("{name}: a positive vector is never corruption: {e}"))
                .as_deref(),
            Some(body.as_slice()),
            "{name}: the bare chunk array reassembles to the vector's body"
        );

        // The same value under the Blockfrost metadata-map wrapper.
        let mut wrapped = hex::decode(METADATA_MAP_PREFIX_HEX).expect("prefix hex");
        wrapped.extend_from_slice(&value);
        assert_eq!(
            unwrap_label309_chunked_metadatum(&wrapped)
                .unwrap_or_else(|e| panic!("{name}: a positive vector is never corruption: {e}"))
                .as_deref(),
            Some(body.as_slice()),
            "{name}: the metadata-map wrapper reassembles to the vector's body"
        );

        // The reassembled body is a valid record the indexer accepts.
        derive_chain_record_columns(&body, gateway_core::chain::params::Network::Mainnet)
            .unwrap_or_else(|e| panic!("{name}: the vector body indexes cleanly: {e}"));
    }
}

#[test]
fn non_conformant_value_shapes_are_rejected_or_fail_body_validation() {
    // The indefinite-length vectors are enforced at the verifier layer, not by
    // the provider adapter (see the module docs); everything else must be
    // dispositioned here exactly as the taxonomy pins it.
    let verifier_layer_only = ["indefinite-length-array", "indefinite-length-bstr-element"];
    // An empty reassembly is tolerated by the transport; the rejection then
    // comes from the canonical decode of the empty body.
    let empty_reassembly = ["empty-array-empty-body", "zero-only-chunks-empty-body"];
    // An over-cap chunk cannot exist on chain at all, so at the provider-API
    // adapter it is a verdict on the PROVIDER — a typed, failover-worthy
    // corruption error — never the "not a label-309 carriage" skip the other
    // negative shapes resolve to (a skip would let the scan cursor advance past
    // a real on-chain record).
    let provider_corrupt = ["chunk-65-bytes"];

    for vector in load_vectors("chunk-array-negative.json") {
        let name = vector["name"].as_str().expect("name");
        if verifier_layer_only.contains(&name) {
            continue;
        }
        let value = hex_field(&vector, "label_309_value_cbor_hex");
        let unwrapped = unwrap_label309_chunked_metadatum(&value);

        if provider_corrupt.contains(&name) {
            let err = unwrapped
                .expect_err("an on-chain-impossible chunk is provider corruption, never a skip");
            assert_eq!(
                classify_chain_error(&err),
                Some(ChainErrorClass::CorruptProvider),
                "{name}: classified as corrupt provider output"
            );
        } else if empty_reassembly.contains(&name) {
            let body = unwrapped
                .unwrap_or_else(|e| panic!("{name}: an empty reassembly is not corruption: {e}"))
                .unwrap_or_else(|| panic!("{name}: an empty reassembly is transport-tolerated"));
            assert!(body.is_empty(), "{name}: reassembles to zero bytes");
            assert!(
                derive_chain_record_columns(&body, gateway_core::chain::params::Network::Mainnet)
                    .is_err(),
                "{name}: the empty body fails record validation, so it is never indexed"
            );
        } else {
            assert_eq!(
                unwrapped.unwrap_or_else(|e| panic!(
                    "{name}: a transaction verdict, never \
                     a provider failure: {e}"
                )),
                None,
                "{name}: a non-conformant label-309 value shape is rejected"
            );
        }
    }
}
