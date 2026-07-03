//! Carriage conformance: the builder's label-309 metadata encoding replayed
//! against the standard's carriage vectors.
//!
//! The standard transports a record body as a whole-body chunk array — a
//! definite-length CBOR array of definite-length byte strings of at most 64
//! bytes whose in-order concatenation is the body — wrapped in one of the
//! normative Conway auxiliary-data envelope forms. These tests pin the
//! builder's encoder to the conformance vectors byte-for-byte: the emitted
//! auxiliary data is the tag-259 keyed-map form, its label-309 value is the
//! minimal-split chunk array, and the value reassembles to the exact body for
//! every positive carriage vector.

use std::path::{Path, PathBuf};

use cardano_poe_tx::metadata::{encode_auxiliary_data, METADATA_CHUNK_SIZE};

/// The byte prefix of the builder's auxiliary data: tag 259 (`d9 0103`), a
/// one-entry map keyed `0` (`a1 00`), and a one-entry metadata map keyed by
/// label 309 (`a1 19 0135`). Everything after it is the label-309 value.
const AUX_PREFIX_HEX: &str = "d90103a100a1190135";

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

fn field<'a>(vector: &'a serde_json::Value, key: &str) -> &'a str {
    vector[key].as_str().unwrap_or_else(|| {
        panic!(
            "vector {} carries {key}",
            vector["name"].as_str().unwrap_or("?")
        )
    })
}

/// The builder's label-309 value for a record body: the auxiliary-data bytes
/// with the fixed envelope prefix stripped.
fn label_309_value(body: &[u8]) -> Vec<u8> {
    let aux = encode_auxiliary_data(body);
    let prefix = hex::decode(AUX_PREFIX_HEX).expect("prefix hex");
    assert!(
        aux.starts_with(&prefix),
        "auxiliary data must be the tag-259 keyed-map form carrying only label 309"
    );
    aux[prefix.len()..].to_vec()
}

/// Strictly parse a definite-length CBOR array of definite-length byte strings
/// — the only shape the transport permits — returning the chunks. Panics on
/// any other shape, so the producer can never drift to a non-conformant
/// encoding without this harness failing.
fn parse_chunk_array(bytes: &[u8]) -> Vec<Vec<u8>> {
    let (count, mut offset) = read_definite_header(bytes, 0, 0x80, "array");
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        let (len, data_start) = read_definite_header(bytes, offset, 0x40, "byte string");
        let end = data_start + len;
        assert!(end <= bytes.len(), "byte string runs past the buffer");
        chunks.push(bytes[data_start..end].to_vec());
        offset = end;
    }
    assert_eq!(offset, bytes.len(), "trailing bytes after the chunk array");
    chunks
}

/// Read a definite-length CBOR header of the expected major type, returning
/// `(length, offset_after_header)`. Rejects indefinite-length encodings.
fn read_definite_header(bytes: &[u8], offset: usize, major: u8, what: &str) -> (usize, usize) {
    let first = *bytes
        .get(offset)
        .unwrap_or_else(|| panic!("truncated {what} header"));
    assert_eq!(first & 0xe0, major, "expected a {what} at offset {offset}");
    let info = first & 0x1f;
    match info {
        0..=23 => (info as usize, offset + 1),
        24 => (bytes[offset + 1] as usize, offset + 2),
        25 => (
            u16::from_be_bytes([bytes[offset + 1], bytes[offset + 2]]) as usize,
            offset + 3,
        ),
        31 => panic!("indefinite-length {what} is not a conformant transport encoding"),
        _ => panic!("unexpected {what} length encoding at offset {offset}"),
    }
}

#[test]
fn label_309_value_byte_matches_the_single_chunk_vector() {
    // A body of 64 bytes or fewer still travels as a one-element chunk array;
    // for that shape the builder's minimal split IS the vector's encoding, so
    // the emitted value matches the conformance vector byte-for-byte.
    let vectors = load_vectors("chunk-array-positive.json");
    let vector = vectors
        .iter()
        .find(|v| v["name"] == "single-chunk-63-byte-body")
        .expect("single-chunk vector present");
    let body = hex::decode(field(vector, "expected_record_body_hex")).expect("body hex");
    let expected = field(vector, "label_309_value_cbor_hex");
    assert_eq!(
        hex::encode(label_309_value(&body)),
        expected,
        "the builder's label-309 value must equal the conformance vector"
    );
}

#[test]
fn auxiliary_data_byte_matches_the_tag_259_envelope_vector() {
    // The strongest producer pin: the builder's complete auxiliary-data bytes
    // equal the normative tag-259 keyed-map envelope vector for the same body.
    let vectors = load_vectors("aux-data-envelope-forms.json");
    let vector = vectors
        .iter()
        .find(|v| v["name"] == "tag-259-keyed-map")
        .expect("tag-259 vector present");
    let body = hex::decode(
        vector["expected"]["record_body_hex"]
            .as_str()
            .expect("record_body_hex"),
    )
    .expect("body hex");
    let expected = vector["auxiliary_data_cbor_hex"]
        .as_str()
        .expect("auxiliary_data_cbor_hex");
    assert_eq!(
        hex::encode(encode_auxiliary_data(&body)),
        expected,
        "the builder's auxiliary data must equal the tag-259 conformance vector"
    );
}

#[test]
fn every_positive_vector_body_reencodes_to_a_reassembly_identical_value() {
    // Chunk boundaries carry no semantics: whatever split a positive vector
    // uses, re-encoding its body through the builder must yield a conformant
    // chunk array whose concatenation is byte-identical to that body.
    for vector in load_vectors("chunk-array-positive.json") {
        let name = vector["name"].as_str().expect("name");
        let body = hex::decode(field(&vector, "expected_record_body_hex")).expect("body hex");
        let chunks = parse_chunk_array(&label_309_value(&body));
        assert_producer_rule(&chunks, name);
        assert_eq!(
            chunks.concat(),
            body,
            "{name}: the emitted value must reassemble to the vector's body"
        );
    }
}

#[test]
fn emitted_chunk_arrays_satisfy_the_producer_rule_across_body_lengths() {
    // The producer rule: chunks of 1 to 64 bytes, the minimal split (every
    // chunk except the last exactly 64 bytes), no zero-length chunks, and the
    // chunk-array form regardless of body length.
    for len in [1usize, 63, 64, 65, 128, 129, 4096, 15_000] {
        let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let chunks = parse_chunk_array(&label_309_value(&body));
        assert_producer_rule(&chunks, &format!("{len}-byte body"));
        assert_eq!(chunks.concat(), body, "{len}-byte body reassembles");
        assert_eq!(
            chunks.len(),
            len.div_ceil(METADATA_CHUNK_SIZE),
            "{len}-byte body uses the minimal chunk count"
        );
    }
}

/// Assert the producer-rule shape over parsed chunks: every chunk 1..=64
/// bytes, and every chunk except the last exactly 64 (the minimal split).
fn assert_producer_rule(chunks: &[Vec<u8>], context: &str) {
    assert!(!chunks.is_empty(), "{context}: at least one chunk");
    for (i, chunk) in chunks.iter().enumerate() {
        assert!(
            !chunk.is_empty() && chunk.len() <= METADATA_CHUNK_SIZE,
            "{context}: chunk {i} must be 1 to 64 bytes, got {}",
            chunk.len()
        );
        if i + 1 < chunks.len() {
            assert_eq!(
                chunk.len(),
                METADATA_CHUNK_SIZE,
                "{context}: non-final chunk {i} must be exactly 64 bytes (minimal split)"
            );
        }
    }
}
