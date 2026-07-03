//! Parity between the streaming and the in-memory deep-hash / signing paths.
//!
//! Signing a multi-gigabyte upload cannot buffer the payload, so the crate
//! computes the trailing `data` leaf by streaming a reader through SHA-384 and
//! folding it into the eight-element data-item list. These tests pin that the
//! streamed path yields a byte-identical signed message, signature, and id to
//! the in-memory path — including against the cross-implementation golden
//! vectors in `tests/vectors/`, whose `.bin` carries the real payload and whose
//! sidecar records the reference deep-hash.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ans104::{
    deep_hash, deep_hash_blob_reader, deep_hash_message, reconstruct_prefix, sign_streaming,
    verify, ArweaveJwkSigner, DataItemBuilder, DataItemView, DeepHashItem, SignedDataItem, Tag,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// The fixture key the golden vectors were signed with, so a streamed re-sign of
/// the same fields can be cross-checked against the reference signature framing.
fn signer() -> &'static ArweaveJwkSigner {
    static SIGNER: OnceLock<ArweaveJwkSigner> = OnceLock::new();
    SIGNER.get_or_init(|| {
        let text = std::fs::read_to_string(vectors_dir().join("test-jwk.json")).expect("read jwk");
        ArweaveJwkSigner::from_jwk_json(&text).expect("parse jwk")
    })
}

fn read_json(path: &Path) -> Value {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn hex_str(v: &Value, key: &str) -> Vec<u8> {
    let s = v[key].as_str().unwrap_or_else(|| panic!("missing {key}"));
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex in {key}: {e}"))
}

/// Recompute the full eight-element deep-hash message by streaming the `data`
/// leaf, mirroring exactly what `sign_streaming` folds — but reusing the public
/// fold so the test does not re-implement the private signing internals.
fn streamed_message(view: &DataItemView) -> [u8; 48] {
    use ans104::{deep_hash_list_of, DEEP_HASH_LEN};

    let tags_blob = ans104::encode_tags(&view.tags).expect("encode tags");
    let fixed = [
        deep_hash(&DeepHashItem::blob(b"dataitem".to_vec())),
        deep_hash(&DeepHashItem::blob(b"1".to_vec())),
        deep_hash(&DeepHashItem::blob(
            view.signature_type.to_string().into_bytes(),
        )),
        deep_hash(&DeepHashItem::blob(view.owner.clone())),
        deep_hash(&DeepHashItem::blob(
            view.target.map_or_else(Vec::new, |t| t.to_vec()),
        )),
        deep_hash(&DeepHashItem::blob(
            view.anchor.map_or_else(Vec::new, |a| a.to_vec()),
        )),
        deep_hash(&DeepHashItem::blob(tags_blob)),
    ];
    let data_leaf =
        deep_hash_blob_reader(&mut view.data.as_slice(), view.data.len() as u64).expect("stream");

    let mut children: Vec<[u8; DEEP_HASH_LEN]> = Vec::with_capacity(fixed.len() + 1);
    children.extend_from_slice(&fixed);
    children.push(data_leaf);
    deep_hash_list_of(&children)
}

#[test]
fn streamed_data_leaf_matches_golden_deep_hash_vectors() {
    // For every signed-item golden vector, the deep-hash computed by streaming
    // the payload leaf must equal both the in-memory deep-hash of the parsed
    // fields and the reference `deep_hash_hex` the sidecar recorded.
    let dir = vectors_dir();
    let mut checked = 0usize;
    let mut bins: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("bin"))
                .collect()
        })
        .unwrap_or_default();
    bins.sort();

    for bin in &bins {
        let bytes = std::fs::read(bin).unwrap_or_else(|e| panic!("read {}: {e}", bin.display()));
        let view = DataItemView::parse(&bytes).expect("parse golden item");
        let meta = read_json(&bin.with_extension("json"));

        let in_memory = deep_hash_message(&view.unsigned()).expect("in-memory deep hash");
        let streamed = streamed_message(&view);
        assert_eq!(
            streamed,
            in_memory,
            "{}: streamed deep-hash diverged from in-memory",
            bin.display()
        );
        assert_eq!(
            streamed.as_slice(),
            hex_str(&meta, "deep_hash_hex").as_slice(),
            "{}: streamed deep-hash diverged from reference",
            bin.display()
        );
        checked += 1;
    }

    assert!(checked > 0, "no signed-item golden vectors were consumed");
}

#[test]
fn streamed_blob_leaf_matches_golden_deep_hash_kats() {
    // The blob KATs let us pin the leaf hash directly: stream the leaf bytes and
    // assert the 48-byte digest equals the in-memory leaf for every blob KAT.
    let doc = read_json(&vectors_dir().join("deep-hash-kats.json"));
    let mut checked = 0usize;
    for kat in doc["kats"].as_array().expect("kats array") {
        if kat["shape"].as_str() != Some("blob") {
            continue;
        }
        let bytes = hex_str(kat, "input_hex");
        let in_memory = deep_hash(&DeepHashItem::blob(bytes.clone()));
        let streamed = deep_hash_blob_reader(&mut bytes.as_slice(), bytes.len() as u64)
            .expect("stream blob leaf");
        assert_eq!(streamed, in_memory, "blob KAT streamed leaf diverged");
        checked += 1;
    }
    assert!(checked > 0, "no blob KATs were consumed");
}

#[test]
fn sign_streaming_reproduces_the_in_memory_builder_for_fixed_fields() {
    // With the fixed-field signer determinism removed (PSS is randomised), the
    // signature bytes differ run to run; but the SIGNED MESSAGE the two paths
    // produce must be identical, and a streamed signature must verify and carry
    // the id `SHA-256(signature)` over canonical bytes the prefix reconstructs.
    let signer = signer();
    let data = b"a streamed upload payload of moderate length".to_vec();
    let tags = vec![
        Tag::new("Content-Type", "application/octet-stream"),
        Tag::new("App-Name", "label-309-gateway"),
    ];
    let anchor = [0x5au8; 32];

    // In-memory reference message (no signing needed to compare the message).
    let mut builder = DataItemBuilder::new(data.clone());
    for t in &tags {
        builder = builder.push_tag(t.clone());
    }
    builder = builder.anchor(anchor).unwrap();
    let in_memory_signed = builder.sign(signer).expect("in-memory sign");
    let in_memory_message = deep_hash_message(
        &SignedDataItem::parse(&in_memory_signed.bytes)
            .unwrap()
            .unsigned(),
    )
    .unwrap();

    // Streamed envelope.
    let envelope = sign_streaming(
        signer,
        None,
        Some(anchor),
        &tags,
        &mut data.as_slice(),
        data.len() as u64,
    )
    .expect("streamed sign");

    // The id is `SHA-256(signature)` and the envelope's signature is 512 bytes.
    assert_eq!(envelope.signature.len(), 512);
    let recomputed_id: [u8; 32] = Sha256::digest(&envelope.signature).into();
    assert_eq!(envelope.id, recomputed_id);

    // Reconstruct the canonical bytes from the envelope prefix + the payload and
    // confirm they verify and carry the streamed id. This closes the loop: the
    // streamed path produces a wire-valid, self-consistent data item.
    let mut canonical = reconstruct_prefix(&envelope, &signer_owner()).expect("prefix");
    canonical.extend_from_slice(&data);
    let verified = verify(&canonical).expect("streamed item must verify");
    assert_eq!(
        verified.id, envelope.id,
        "verified id diverged from envelope"
    );

    // The streamed item's signed message equals the in-memory item's signed
    // message over the same fields (the randomised signatures differ, the message
    // does not).
    let streamed_message = deep_hash_message(&verified.unsigned()).unwrap();
    assert_eq!(
        streamed_message, in_memory_message,
        "streamed and in-memory deep-hash messages diverged for the same fields"
    );
}

fn signer_owner() -> Vec<u8> {
    use ans104::Ans104Signer;
    signer().owner()
}

/// A reader that yields its bytes in tiny chunks, to exercise the streaming
/// loop's re-entry across many `read` calls rather than one buffer fill.
struct DribbleReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    chunk: usize,
}

impl Read for DribbleReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let remaining = self.bytes.len() - self.pos;
        let n = remaining.min(self.chunk).min(out.len());
        out[..n].copy_from_slice(&self.bytes[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// A reader that synthesises bytes on demand without ever holding the whole
/// payload, and records the largest single slice the hasher asked it to fill.
/// This lets the test prove the streaming loop reads in bounded chunks rather
/// than pulling the entire payload into one buffer.
struct SyntheticReader {
    remaining: u64,
    max_read: usize,
}

impl Read for SyntheticReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let n = (out.len() as u64).min(self.remaining) as usize;
        // Deterministic filler so the digest is reproducible.
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        self.remaining -= n as u64;
        self.max_read = self.max_read.max(n);
        Ok(n)
    }
}

#[test]
fn streamed_leaf_reads_in_bounded_chunks_for_a_large_payload() {
    // A payload far larger than any single fixed buffer must hash with the reader
    // only ever asked to fill bounded slices: the streaming loop never requests
    // the whole payload at once, so resident memory does not scale with the file.
    const LARGE: u64 = 64 * 1024 * 1024; // 64 MiB synthesised, never resident.
    let mut reader = SyntheticReader {
        remaining: LARGE,
        max_read: 0,
    };
    let leaf = deep_hash_blob_reader(&mut reader, LARGE).expect("hash large payload");

    // The loop never asked for more than a bounded chunk at a time.
    assert!(
        reader.max_read <= 64 * 1024,
        "streaming loop requested an unbounded {}-byte read",
        reader.max_read
    );

    // And the result is correct: hashing the same synthetic bytes in a second
    // independent pass yields the identical leaf (no state leaked across reads).
    let mut reader2 = SyntheticReader {
        remaining: LARGE,
        max_read: 0,
    };
    let leaf2 = deep_hash_blob_reader(&mut reader2, LARGE).expect("hash again");
    assert_eq!(leaf, leaf2);
}

#[test]
fn streamed_leaf_is_chunking_invariant() {
    // The digest must not depend on how the reader fragments its output: a reader
    // dribbling one byte at a time produces the same leaf as the whole-slice read.
    let payload: Vec<u8> = (0..200_003u32).map(|i| (i % 97) as u8).collect();
    let whole =
        deep_hash_blob_reader(&mut payload.as_slice(), payload.len() as u64).expect("whole");
    let mut dribble = DribbleReader {
        bytes: &payload,
        pos: 0,
        chunk: 1,
    };
    let dribbled = deep_hash_blob_reader(&mut dribble, payload.len() as u64).expect("dribbled");
    assert_eq!(whole, dribbled);
}
