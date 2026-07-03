//! Vector-driven conformance tests against cross-implementation golden files.
//!
//! `tests/vectors/` holds vectors produced by an independent reference
//! implementation. When the directory has no vectors yet, this binary prints a
//! visible skip notice and passes, so the suite is green before the vectors
//! land. Once present, three vector families are consumed:
//!
//! - `deep-hash-kats.json` — known answers for the recursive SHA-384 deep-hash.
//! - `<name>.bin` + `<name>.json` — signed data items with sidecar metadata.
//! - `tag_bytes_4097_reject.json` — the one-byte-over-limit rejection case.
//!
//! Per the vectors' own contract, the random PSS signature is never byte-
//! compared; signatures are verified, and ids are recomputed as
//! `base64url(SHA-256(signature))` from the signature the item actually carries.

use std::path::{Path, PathBuf};

use ans104::{
    deep_hash, deep_hash_message, encode_tags, verify, Ans104Error, DataItemView, DeepHashItem,
    Tag, MAX_TAG_BYTES,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn has_any_vectors(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Any committed vector content, not the README or the test key.
        (name.ends_with(".json") && name != "test-jwk.json") || name.ends_with(".bin")
    })
}

fn read_json(path: &Path) -> Value {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn hex_str(v: &Value, key: &str, path: &Path) -> Vec<u8> {
    let s = v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{}: missing string field {key}", path.display()));
    hex::decode(s).unwrap_or_else(|e| panic!("{}: bad hex in {key}: {e}", path.display()))
}

#[test]
fn vectors_are_consumed_or_visibly_skipped() {
    let dir = vectors_dir();
    if !has_any_vectors(&dir) {
        println!(
            "SKIP: no vector files in {} yet; this test consumes them once added",
            dir.display()
        );
        return;
    }

    let mut asserted = 0usize;
    asserted += run_deep_hash_kats(&dir);
    asserted += run_signed_item_vectors(&dir);
    asserted += run_oversize_tag_vector(&dir);

    assert!(
        asserted > 0,
        "{}: vector files present but none were recognised",
        dir.display()
    );
    println!("asserted {asserted} vector(s)");
}

/// Consume `deep-hash-kats.json`. Returns the number of KATs checked.
fn run_deep_hash_kats(dir: &Path) -> usize {
    let path = dir.join("deep-hash-kats.json");
    if !path.exists() {
        return 0;
    }
    let doc = read_json(&path);
    let kats = doc["kats"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: missing kats array", path.display()));

    for kat in kats {
        let item = parse_kat_item(kat, &path);
        let expected = hex_str(kat, "deep_hash_hex", &path);
        let got = deep_hash(&item);
        let name = kat["name"].as_str().unwrap_or("<unnamed>");
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "{}: deep-hash KAT '{name}' mismatch",
            path.display()
        );
    }
    kats.len()
}

fn parse_kat_item(kat: &Value, path: &Path) -> DeepHashItem {
    match kat["shape"].as_str() {
        Some("blob") => DeepHashItem::blob(hex_str(kat, "input_hex", path)),
        Some("list") => {
            let children = kat["children"]
                .as_array()
                .unwrap_or_else(|| panic!("{}: list KAT missing children", path.display()));
            DeepHashItem::list(children.iter().map(|c| parse_kat_item(c, path)).collect())
        }
        other => panic!("{}: unknown KAT shape {other:?}", path.display()),
    }
}

/// Consume every `<name>.bin` + `<name>.json` signed-item pair. Returns the
/// number of items checked.
fn run_signed_item_vectors(dir: &Path) -> usize {
    let mut bins: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("bin"))
                .collect()
        })
        .unwrap_or_default();
    bins.sort();

    for bin_path in &bins {
        let sidecar = bin_path.with_extension("json");
        let meta = read_json(&sidecar);
        let bytes =
            std::fs::read(bin_path).unwrap_or_else(|e| panic!("read {}: {e}", bin_path.display()));

        check_signed_item(&bytes, &meta, bin_path, &sidecar);
    }
    bins.len()
}

fn check_signed_item(bytes: &[u8], meta: &Value, bin: &Path, sidecar: &Path) {
    // Reported length must match the actual file.
    if let Some(raw_len) = meta["raw_len"].as_u64() {
        assert_eq!(
            bytes.len() as u64,
            raw_len,
            "{}: raw_len disagrees with file size",
            bin.display()
        );
    }

    // Full verification: parse, recompute deep-hash, check RSA-PSS against the
    // embedded owner. This exercises salt-length recovery against a reference
    // signature.
    let view = verify(bytes).unwrap_or_else(|e| panic!("{}: must verify: {e}", bin.display()));

    // Owner is the byte-stable modulus.
    assert_eq!(
        view.owner,
        hex_str(meta, "owner_hex", sidecar),
        "{}: owner bytes differ from reference",
        bin.display()
    );

    // Target / anchor presence and bytes.
    assert_optional_32(&view.target, meta, "target_hex", "target", bin, sidecar);
    assert_optional_32(&view.anchor, meta, "anchor_hex", "anchor", bin, sidecar);

    // The Avro tag frame this crate would emit for the parsed tags must equal
    // the reference frame byte for byte.
    let expected_avro = hex_str(meta, "tags_avro_hex", sidecar);
    let our_avro = encode_tags(&view.tags).expect("re-encode parsed tags");
    assert_eq!(
        our_avro,
        expected_avro,
        "{}: re-encoded tag frame differs from reference",
        bin.display()
    );

    // Decoded tag name/value pairs match the sidecar's listing.
    if let Some(tag_list) = meta["tags"].as_array() {
        let expected: Vec<Tag> = tag_list
            .iter()
            .map(|t| {
                Tag::new(
                    t["name"].as_str().unwrap().as_bytes().to_vec(),
                    t["value"].as_str().unwrap().as_bytes().to_vec(),
                )
            })
            .collect();
        assert_eq!(
            view.tags,
            expected,
            "{}: decoded tags differ",
            bin.display()
        );
    }

    // Deep-hash of the parsed signed fields equals the reference signed message.
    let our_deep_hash = deep_hash_message(&view.unsigned()).expect("deep hash");
    assert_eq!(
        our_deep_hash.as_slice(),
        hex_str(meta, "deep_hash_hex", sidecar).as_slice(),
        "{}: deep-hash differs from reference",
        bin.display()
    );

    // Payload integrity: SHA-256 of the parsed data equals the recorded digest.
    let data_digest: [u8; 32] = Sha256::digest(&view.data).into();
    assert_eq!(
        data_digest.as_slice(),
        hex_str(meta, "data_sha256_hex", sidecar).as_slice(),
        "{}: data digest differs",
        bin.display()
    );
    if let Some(data_len) = meta["data_len"].as_u64() {
        assert_eq!(
            view.data.len() as u64,
            data_len,
            "{}: data_len",
            bin.display()
        );
    }

    // The id is base64url(SHA-256(signature)); since the .bin carries the same
    // signature the sidecar recorded, the recomputed id matches id_b64url.
    if let Some(expected_id) = meta["id_b64url"].as_str() {
        assert_eq!(
            view.id_b64url(),
            expected_id,
            "{}: recomputed id differs from sidecar",
            bin.display()
        );
    }
}

fn assert_optional_32(
    actual: &Option<[u8; 32]>,
    meta: &Value,
    key: &str,
    field: &str,
    bin: &Path,
    sidecar: &Path,
) {
    match meta[key].as_str() {
        Some("") | None => assert!(
            actual.is_none(),
            "{}: {field} present but reference has none",
            bin.display()
        ),
        Some(_) => {
            let expected = hex_str(meta, key, sidecar);
            assert_eq!(
                actual.map(|a| a.to_vec()),
                Some(expected),
                "{}: {field} bytes differ",
                bin.display()
            );
        }
    }
}

/// Consume `tag_bytes_4097_reject.json`: a tag frame one byte over the limit.
/// Returns 1 if the vector was present.
fn run_oversize_tag_vector(dir: &Path) -> usize {
    let path = dir.join("tag_bytes_4097_reject.json");
    if !path.exists() {
        return 0;
    }
    let meta = read_json(&path);
    let attempted = meta["attempted_avro_len"]
        .as_u64()
        .unwrap_or(MAX_TAG_BYTES as u64 + 1);
    assert!(
        attempted as usize > MAX_TAG_BYTES,
        "{}: vector should be over the limit",
        path.display()
    );

    // Encoding a tag whose frame would be 4097 bytes must be rejected, matching
    // the reference's serialize_error. Find a value length whose frame overflows.
    let oversize = vec![Tag::new("", vec![b'a'; MAX_TAG_BYTES])];
    assert!(
        matches!(encode_tags(&oversize), Err(Ans104Error::InvalidTags(_))),
        "{}: encode must reject an over-limit tag frame",
        path.display()
    );

    // A data item whose declared tag byte-length exceeds the limit must be
    // rejected on parse, matching the reference verifier returning false.
    if meta["verify_rejects_oversize_tag_bytes"]
        .as_bool()
        .unwrap_or(false)
    {
        let bytes = synthetic_item_with_tag_bytes_len(MAX_TAG_BYTES as u64 + 1);
        assert!(
            matches!(
                DataItemView::parse(&bytes),
                Err(Ans104Error::InvalidTags(_))
            ),
            "{}: parse must reject a declared tag byte-length over the limit",
            path.display()
        );
    }
    1
}

/// Build a minimal arweave-type item header whose declared tag byte-length is
/// `tag_bytes_len`, used to confirm the parser rejects an over-limit declaration
/// before attempting to read the (absent) frame.
fn synthetic_item_with_tag_bytes_len(tag_bytes_len: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u16.to_le_bytes()); // arweave type
    bytes.extend(std::iter::repeat_n(0u8, 512)); // signature
    bytes.extend(std::iter::repeat_n(0u8, 512)); // owner
    bytes.push(0); // no target
    bytes.push(0); // no anchor
    bytes.extend_from_slice(&0u64.to_le_bytes()); // tag count
    bytes.extend_from_slice(&tag_bytes_len.to_le_bytes()); // over-limit byte length
    bytes
}
