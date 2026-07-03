//! Byte-for-byte cross-checks against a reference data item produced by an
//! independent ANS-104 implementation.
//!
//! The fixture `fixtures/arbundles-reference.json` was produced by signing a
//! fixed item with a fixed key in a reference implementation. These tests prove
//! this crate computes the identical deep-hash, the identical serialised bytes,
//! and the identical id, and that it verifies the reference's own signature.
//! That is the real guarantee a parity twin must give: not that it round-trips
//! with itself, but that it agrees with the rest of the ecosystem.

use std::path::PathBuf;

use ans104::{
    deep_hash_message, verify, Ans104Signer, ArweaveJwkSigner, DataItemBuilder, SignedDataItem,
    Tag, UnsignedDataItem,
};
use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn load_reference() -> Value {
    let path = fixtures_dir().join("arbundles-reference.json");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("reference fixture is valid JSON")
}

fn hex_field(v: &Value, key: &str) -> Vec<u8> {
    let s = v[key].as_str().unwrap_or_else(|| panic!("missing {key}"));
    hex::decode(s).unwrap_or_else(|e| panic!("decode {key}: {e}"))
}

/// Rebuild the reference item with this crate using the fixture's key and the
/// same field values, then sign it. Returns (signed item, reference value).
fn rebuild_from_reference() -> (SignedDataItem, Value) {
    let reference = load_reference();
    let jwk_json = serde_json::to_string(&reference["jwk"]).unwrap();
    let signer = ArweaveJwkSigner::from_jwk_json(&jwk_json).expect("parse fixture jwk");

    let data = hex_field(&reference, "data_hex");
    let anchor = hex_field(&reference, "anchor_hex");

    let signed = DataItemBuilder::new(data)
        .tag("Content-Type", "text/plain")
        .tag("作者".as_bytes().to_vec(), "中本聡".as_bytes().to_vec())
        .anchor(anchor)
        .expect("32-byte anchor")
        .sign(&signer)
        .expect("sign");
    (signed, reference)
}

#[test]
fn deep_hash_matches_the_reference_signature_data() {
    let reference = load_reference();
    let jwk_json = serde_json::to_string(&reference["jwk"]).unwrap();
    let signer = ArweaveJwkSigner::from_jwk_json(&jwk_json).unwrap();

    let unsigned = UnsignedDataItem {
        signature_type: 1,
        owner: signer.owner(),
        target: None,
        anchor: Some(hex_field(&reference, "anchor_hex").try_into().unwrap()),
        tags: vec![
            Tag::new("Content-Type", "text/plain"),
            Tag::new("作者".as_bytes().to_vec(), "中本聡".as_bytes().to_vec()),
        ],
        data: hex_field(&reference, "data_hex"),
    };

    let ours = deep_hash_message(&unsigned).expect("deep hash");
    let expected = hex_field(&reference, "deep_hash_hex");
    assert_eq!(
        ours.as_slice(),
        expected.as_slice(),
        "deep-hash bytes must match the reference implementation exactly"
    );
}

#[test]
fn serialised_bytes_are_byte_identical_to_the_reference() {
    // PSS is randomised, so the signature bytes (and thus the id) differ run to
    // run. The deterministic part of the layout, everything up to the signature
    // and everything after it, must match the reference byte for byte.
    let (signed, reference) = rebuild_from_reference();
    let reference_raw = hex_field(&reference, "raw_hex");

    assert_eq!(
        signed.bytes.len(),
        reference_raw.len(),
        "serialised length must match the reference"
    );

    // Signature occupies bytes [2, 2 + 512). Everything outside it is
    // deterministic given the same fields.
    let sig_start = 2usize;
    let sig_end = sig_start + 512;
    assert_eq!(
        signed.bytes[..sig_start],
        reference_raw[..sig_start],
        "signature-type prefix must match"
    );
    assert_eq!(
        signed.bytes[sig_end..],
        reference_raw[sig_end..],
        "owner, target, anchor, tags, and data framing must match the reference"
    );
}

#[test]
fn this_crate_verifies_the_reference_signature() {
    // The strongest cross-check: take the reference's own signed bytes and
    // verify them here. This exercises the salt-length recovery against a
    // signature produced by a different implementation.
    let reference = load_reference();
    let raw = hex_field(&reference, "raw_hex");

    let view = verify(&raw).expect("reference item must verify");
    assert_eq!(view.id_b64url(), reference["id_b64url"].as_str().unwrap());

    // Tags survived the parse in order and as raw UTF-8 bytes.
    assert_eq!(view.tags.len(), 2);
    assert_eq!(view.tags[0].name, b"Content-Type");
    assert_eq!(view.tags[1].value, "中本聡".as_bytes());
}

#[test]
fn tampering_with_the_reference_data_breaks_verification() {
    let reference = load_reference();
    let mut raw = hex_field(&reference, "raw_hex");
    // Flip the final data byte; the deep-hash no longer matches the signature.
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    assert!(
        verify(&raw).is_err(),
        "a one-bit change to the payload must fail verification"
    );
}

#[test]
fn our_own_signature_round_trips_through_verify() {
    let (signed, reference) = rebuild_from_reference();
    let view = verify(&signed.bytes).expect("our freshly signed item verifies");
    assert_eq!(view.id, signed.id);
    assert_eq!(view.id_b64url(), signed.id_b64url);
    // The reference id is for a different (randomised) signature, so it differs
    // from ours; what must match is the deterministic layout, checked above.
    assert_ne!(view.id_b64url(), reference["id_b64url"].as_str().unwrap());
}
