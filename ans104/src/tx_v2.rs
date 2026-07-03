//! Arweave format-2 base-layer transactions: signing and JSON serialisation.
//!
//! A base-layer (v2) transaction either carries a data payload (committed to by a
//! Merkle `data_root` rather than embedded in the signed fields), moves winston to
//! a `target` wallet, or both; it is authenticated by an RSA-PSS signature over
//! the deep-hash of its fields. This module signs such transactions with the same
//! `arweave` RSA key the data-item signer uses, and renders the JSON body a node
//! accepts at `POST /tx`.
//!
//! Two constructors cover the two transaction archetypes a gateway issues:
//!
//! - [`sign_tx_v2`] — a data carrier (no token movement), handed to a development
//!   emulator that speaks only the base-layer transaction API and needs the
//!   payload framed as an ANS-104 bundle. Production content posting goes through
//!   a bundling service, not this path.
//! - [`sign_transfer_tx_v2`] — a pure winston transfer (no data), used to move AR
//!   from the operator's funding wallet, e.g. to a storage provider's deposit
//!   wallet when converting AR into prepaid upload credits.
//!
//! # Signed fields
//!
//! The signature covers the deep-hash of the list
//! `[ascii(format), owner, target, ascii(quantity), ascii(reward), last_tx,
//! tags, ascii(data_size), data_root]`, where `tags` is itself a list of
//! `[name, value]` two-element lists. `format`, `quantity`, `reward`, and
//! `data_size` are hashed as their ASCII decimal renderings; the rest are raw
//! bytes. The id is `SHA-256(signature)`. This is the field order and encoding the
//! reference node and `arweave-js` agree on.
//!
//! # Data root
//!
//! For a data-carrying transaction, `data_root` is the Merkle root of the payload
//! split into chunks (see [`data_root`]). A node recomputes it from the supplied
//! `data` and rejects a mismatch, so it must be byte-exact. A transaction with no
//! payload carries an EMPTY `data_root` (zero-length bytes, rendered as `""`),
//! never the root of a zero-length chunk — this matches the reference client,
//! which only computes a Merkle root for a non-empty payload.

use sha2::{Digest, Sha256};

use crate::base64url;
use crate::deep_hash::{deep_hash, DeepHashItem};
use crate::error::Ans104Error;
use crate::signer::Ans104Signer;
use crate::tags::Tag;

/// Maximum payload chunk size for the Merkle data-root: 256 KiB.
const MAX_CHUNK_SIZE: usize = 256 * 1024;
/// Minimum payload chunk size that triggers last-two-chunk rebalancing: 32 KiB.
const MIN_CHUNK_SIZE: usize = 32 * 1024;
/// Width of the byte-range "note" hashed into each Merkle node: 32 bytes.
const NOTE_SIZE: usize = 32;

/// The byte length of a decoded Arweave wallet address (the SHA-256 of the owner
/// modulus), which is what the `target` field carries when a transaction moves
/// winston.
const TX_TARGET_LEN: usize = 32;

/// A signed format-2 transaction, ready to serialise to the node's JSON body.
///
/// Holds the fields a node validates: the 32-byte id (`SHA-256(signature)`), the
/// owner and signature bytes, the transfer target/quantity (empty/zero for a pure
/// data carrier), the Merkle `data_root` (empty for a pure transfer), the byte
/// length, the tags, and the payload. [`Self::to_json`] renders the canonical
/// JSON; [`Self::id_b64url`] is the transaction id a node stores it under.
pub struct SignedTxV2 {
    id: [u8; 32],
    owner: Vec<u8>,
    signature: Vec<u8>,
    /// Decoded target address bytes; empty when the transaction moves no tokens.
    target: Vec<u8>,
    /// Winston moved to `target`; zero for a pure data carrier. `u128` because
    /// winston amounts (10^12 per AR) overflow `u64` well inside the AR supply.
    quantity: u128,
    /// Merkle root bytes of the payload; EMPTY (zero-length) when there is no
    /// payload, matching the reference client's empty-data encoding.
    data_root: Vec<u8>,
    data_size: u64,
    reward: u64,
    last_tx: String,
    tags: Vec<Tag>,
    data: Vec<u8>,
}

impl SignedTxV2 {
    /// The transaction id as URL-safe-no-pad base64.
    #[must_use]
    pub fn id_b64url(&self) -> String {
        base64url::encode(&self.id)
    }

    /// Serialise the transaction to the JSON body a node accepts at `POST /tx`.
    ///
    /// Every byte field (`owner`, `target`, `last_tx`, `data_root`, `data`, tag
    /// names/values, and the `signature`) is rendered as URL-safe-no-pad base64
    /// (empty bytes render as `""`); the numeric fields (`format`, `quantity`,
    /// `reward`, `data_size`) are decimal strings. `last_tx` is passed through
    /// verbatim (an empty string anchors to genesis, which a fresh emulator
    /// accepts; a live node requires a recent `GET /tx_anchor` value).
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let tags: Vec<serde_json::Value> = self
            .tags
            .iter()
            .map(|tag| {
                serde_json::json!({
                    "name": base64url::encode(&tag.name),
                    "value": base64url::encode(&tag.value),
                })
            })
            .collect();

        serde_json::json!({
            "format": 2,
            "id": self.id_b64url(),
            "last_tx": self.last_tx,
            "owner": base64url::encode(&self.owner),
            "tags": tags,
            "target": base64url::encode(&self.target),
            "quantity": self.quantity.to_string(),
            "data": base64url::encode(&self.data),
            "data_size": self.data_size.to_string(),
            "data_root": base64url::encode(&self.data_root),
            "reward": self.reward.to_string(),
            "signature": base64url::encode(&self.signature),
        })
    }
}

/// Sign a format-2 transaction carrying `data` under `tags`, with the given
/// `last_tx` anchor and `reward`.
///
/// Computes the Merkle `data_root`, deep-hashes the canonical field list, signs it
/// with the `arweave` RSA key behind `signer`, and derives the id as
/// `SHA-256(signature)`. `target`/`quantity` are fixed empty (no token transfer).
/// The randomised PSS signature makes the id non-deterministic across calls; a
/// caller that needs a stable content address must take it from the payload, not
/// this transaction id.
pub fn sign_tx_v2<S: Ans104Signer>(
    signer: &S,
    data: &[u8],
    tags: &[Tag],
    last_tx: &str,
    reward: u64,
) -> Result<SignedTxV2, Ans104Error> {
    sign_v2(signer, data, tags, last_tx, reward, Vec::new(), 0)
}

/// Sign a format-2 winston transfer: `quantity_winston` to the wallet at
/// `target_b64url`, with no data payload.
///
/// `target_b64url` is the recipient's Arweave address (the URL-safe base64 of the
/// 32-byte owner-modulus hash); it is decoded and length-checked here so a
/// malformed address fails before signing rather than at the node. `last_tx` must
/// be a recent anchor (`GET /tx_anchor`) and `reward` the node-quoted fee for a
/// zero-byte transaction to this target (`GET /price/0/{target}`). The data
/// fields are empty: `data_size` 0 and an EMPTY `data_root`, the reference
/// encoding for a payload-less transaction.
pub fn sign_transfer_tx_v2<S: Ans104Signer>(
    signer: &S,
    target_b64url: &str,
    quantity_winston: u128,
    last_tx: &str,
    reward: u64,
) -> Result<SignedTxV2, Ans104Error> {
    let target = base64url::decode(target_b64url)
        .map_err(|_| Ans104Error::Malformed("transfer target is not valid base64url"))?;
    if target.len() != TX_TARGET_LEN {
        return Err(Ans104Error::FieldLength {
            field: "target",
            actual: target.len(),
            expected: TX_TARGET_LEN,
        });
    }
    if quantity_winston == 0 {
        // A zero-quantity transfer moves nothing and would only burn the reward;
        // refusing it here keeps "a transfer always moves tokens" an invariant.
        return Err(Ans104Error::Malformed("transfer quantity must be nonzero"));
    }
    sign_v2(signer, &[], &[], last_tx, reward, target, quantity_winston)
}

/// The shared signing core both constructors fold into: deep-hash the canonical
/// field list, sign it, and derive the id as `SHA-256(signature)`.
fn sign_v2<S: Ans104Signer>(
    signer: &S,
    data: &[u8],
    tags: &[Tag],
    last_tx: &str,
    reward: u64,
    target: Vec<u8>,
    quantity: u128,
) -> Result<SignedTxV2, Ans104Error> {
    let owner = signer.owner();
    let data_size = data.len() as u64;
    // An empty payload carries an EMPTY data_root (the reference client only
    // Merkle-roots a non-empty payload); a node rejects the zero-length-chunk
    // root for data_size 0.
    let data_root: Vec<u8> = if data.is_empty() {
        Vec::new()
    } else {
        data_root(data).to_vec()
    };

    let message = signature_data(
        &owner, &target, quantity, last_tx, tags, data_size, reward, &data_root,
    )?;
    let signature = signer.sign(&message)?;
    let id: [u8; 32] = Sha256::digest(&signature).into();

    Ok(SignedTxV2 {
        id,
        owner,
        signature,
        target,
        quantity,
        data_root,
        data_size,
        reward,
        last_tx: last_tx.to_string(),
        tags: tags.to_vec(),
        data: data.to_vec(),
    })
}

/// Build the deep-hash message a format-2 transaction signs.
///
/// The list is `[ascii(2), owner, target, ascii(quantity), ascii(reward),
/// last_tx, tags, ascii(data_size), data_root]`; `tags` nests as a list of
/// `[name, value]` pairs. `target` and `data_root` are raw bytes (empty when the
/// transaction moves no tokens / carries no data); `last_tx` is the raw bytes its
/// base64url decodes to (empty for the genesis anchor).
#[allow(clippy::too_many_arguments)]
fn signature_data(
    owner: &[u8],
    target: &[u8],
    quantity: u128,
    last_tx: &str,
    tags: &[Tag],
    data_size: u64,
    reward: u64,
    data_root: &[u8],
) -> Result<[u8; 48], Ans104Error> {
    let last_tx_bytes = if last_tx.is_empty() {
        Vec::new()
    } else {
        base64url::decode(last_tx)?
    };

    let tag_items: Vec<DeepHashItem> = tags
        .iter()
        .map(|tag| {
            DeepHashItem::list(vec![
                DeepHashItem::blob(tag.name.clone()),
                DeepHashItem::blob(tag.value.clone()),
            ])
        })
        .collect();

    let list = DeepHashItem::list(vec![
        DeepHashItem::blob(b"2".to_vec()),
        DeepHashItem::blob(owner.to_vec()),
        DeepHashItem::blob(target.to_vec()),
        DeepHashItem::blob(quantity.to_string().into_bytes()),
        DeepHashItem::blob(reward.to_string().into_bytes()),
        DeepHashItem::blob(last_tx_bytes),
        DeepHashItem::list(tag_items),
        DeepHashItem::blob(data_size.to_string().into_bytes()),
        DeepHashItem::blob(data_root.to_vec()),
    ]);

    Ok(deep_hash(&list))
}

/// The reward a development node charges for a transaction of `data_size` bytes.
///
/// The emulator computes its required fee as `round((data_size / 1000) * rate)`
/// and rejects a transaction whose `reward` (or its own computed floor) the wallet
/// cannot cover; we mint the wallet well above this and pass the same floor as the
/// reward so the field is internally consistent.
pub fn reward_for(data_size: u64) -> u64 {
    /// The per-1000-byte rate the development node applies.
    const RATE_PER_KB: f64 = 65_595_508.0;
    ((data_size as f64 / 1000.0) * RATE_PER_KB).round() as u64
}

/// The Arweave wallet address for an `arweave` owner key: the URL-safe-no-pad
/// base64 of `SHA-256(owner_modulus_bytes)`.
///
/// This is the address a node keys a wallet balance under, so it is the path
/// segment a balance mint and a balance query both use.
#[must_use]
pub fn arweave_address(owner: &[u8]) -> String {
    let digest = Sha256::digest(owner);
    base64url::encode(&digest)
}

/// Compute the Merkle `data_root` of a payload.
///
/// The payload is split into chunks of at most `MAX_CHUNK_SIZE`, with the final
/// two chunks rebalanced when the tail would fall below `MIN_CHUNK_SIZE`; each
/// chunk becomes a leaf, and the leaves are paired up the tree to a single root.
/// This reproduces the reference Merkle construction a node recomputes to validate
/// the transaction, so the bytes must match exactly. An empty payload has the
/// all-zero root (a single zero-length chunk).
#[must_use]
pub fn data_root(data: &[u8]) -> [u8; 32] {
    let chunks = chunk_ranges(data.len());
    let leaves: Vec<Node> = chunks
        .iter()
        .map(|&(min, max)| leaf_node(&data[min..max], max))
        .collect();
    build_root(leaves)
}

/// A Merkle tree node: its id and the byte range it covers.
#[derive(Clone)]
struct Node {
    id: [u8; 32],
    max_byte_range: usize,
}

/// Split a payload length into (min, max) byte ranges, mirroring the reference
/// chunker: greedily take [`MAX_CHUNK_SIZE`] slices, but if the remaining bytes
/// after a full chunk would be below [`MIN_CHUNK_SIZE`], split the remainder in
/// half so the last two chunks are balanced. An empty payload yields one
/// zero-length chunk.
fn chunk_ranges(len: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut cursor = 0usize;
    let mut rest = len;

    while rest >= MAX_CHUNK_SIZE {
        let mut chunk_size = MAX_CHUNK_SIZE;
        // If the tail after a full chunk would be too small, balance the last two.
        let next_rest = rest - MAX_CHUNK_SIZE;
        if next_rest > 0 && next_rest < MIN_CHUNK_SIZE {
            chunk_size = rest.div_ceil(2);
        }
        ranges.push((cursor, cursor + chunk_size));
        cursor += chunk_size;
        rest -= chunk_size;
    }
    // The final (or only) chunk is whatever remains, including a zero-length tail
    // for an empty payload so there is always at least one leaf.
    ranges.push((cursor, cursor + rest));
    ranges
}

/// Build a leaf node from a chunk's bytes and its max byte range.
///
/// `id = SHA-256(SHA-256(data_hash) ‖ SHA-256(note(max_byte_range)))`, where
/// `data_hash = SHA-256(chunk)` and the note is the byte range rendered as a 32-byte
/// big-endian value. The chunk hash is hashed a second time before it is folded into
/// the leaf, matching the reference construction (which stores `data_hash` per chunk
/// and then hashes it again when building the leaf).
fn leaf_node(chunk: &[u8], max_byte_range: usize) -> Node {
    let data_hash = Sha256::digest(chunk);
    let data_hash_hash = Sha256::digest(data_hash);
    let note_hash = Sha256::digest(note_to_buffer(max_byte_range));
    let id = hash_concat(&[&data_hash_hash, &note_hash]);
    Node { id, max_byte_range }
}

/// Fold a layer of leaves into a single root, pairing adjacent nodes and carrying
/// an odd trailing node up unchanged, until one node remains.
fn build_root(mut nodes: Vec<Node>) -> [u8; 32] {
    while nodes.len() > 1 {
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut iter = nodes.into_iter();
        while let Some(left) = iter.next() {
            match iter.next() {
                Some(right) => next.push(branch_node(&left, &right)),
                // An odd final node is promoted to the next layer unchanged.
                None => next.push(left),
            }
        }
        nodes = next;
    }
    nodes
        .first()
        .map(|n| n.id)
        // chunk_ranges always yields at least one chunk, so this is unreachable;
        // the all-zero root is the safe degenerate value if it ever were not.
        .unwrap_or([0u8; 32])
}

/// Build a branch node from its two children.
///
/// `id = SHA-256(SHA-256(left.id) ‖ SHA-256(right.id) ‖ SHA-256(note(left.max)))`,
/// and the branch covers up to the right child's max byte range. This is the
/// branch-hash the reference construction uses.
fn branch_node(left: &Node, right: &Node) -> Node {
    let left_hash = Sha256::digest(left.id);
    let right_hash = Sha256::digest(right.id);
    let note_hash = Sha256::digest(note_to_buffer(left.max_byte_range));
    let id = hash_concat(&[&left_hash, &right_hash, &note_hash]);
    Node {
        id,
        max_byte_range: right.max_byte_range,
    }
}

/// Render a byte range as the 32-byte big-endian "note" the Merkle nodes hash.
fn note_to_buffer(note: usize) -> [u8; NOTE_SIZE] {
    let mut buf = [0u8; NOTE_SIZE];
    buf[NOTE_SIZE - 8..].copy_from_slice(&(note as u64).to_be_bytes());
    buf
}

/// SHA-256 over the concatenation of the given byte slices.
fn hash_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduce the single-chunk leaf root the reference construction yields, so
    /// the assertion pins the algorithm rather than echoing `data_root`'s output.
    /// The chunk hash is hashed twice before folding (the reference stores
    /// `data_hash = SHA-256(chunk)` per chunk, then hashes it again in the leaf).
    fn expected_single_chunk_root(data: &[u8]) -> [u8; 32] {
        let data_hash = Sha256::digest(data);
        let data_hash_hash = Sha256::digest(data_hash);
        let note_hash = Sha256::digest(note_to_buffer(data.len()));
        hash_concat(&[&data_hash_hash, &note_hash])
    }

    #[test]
    fn small_payload_is_a_single_chunk_root() {
        // A payload below MAX_CHUNK_SIZE is one chunk, so the root is the lone
        // leaf id.
        let data = b"a small bundle payload".to_vec();
        assert_eq!(data_root(&data), expected_single_chunk_root(&data));
    }

    #[test]
    fn exactly_max_chunk_appends_a_trailing_zero_length_chunk() {
        // The reference chunker pushes the remainder unconditionally after the
        // loop, so a payload that is an exact multiple of MAX_CHUNK_SIZE ends with
        // a zero-length chunk and the root is a branch over the two leaves, not the
        // single full-chunk leaf. Reproducing this exactly is what makes the root a
        // node accepts.
        let data = vec![0x5au8; MAX_CHUNK_SIZE];
        let ranges = chunk_ranges(data.len());
        assert_eq!(
            ranges,
            vec![(0, MAX_CHUNK_SIZE), (MAX_CHUNK_SIZE, MAX_CHUNK_SIZE)]
        );

        let full_leaf = leaf_node(&data, MAX_CHUNK_SIZE);
        let tail_leaf = leaf_node(&[], MAX_CHUNK_SIZE);
        let expected = branch_node(&full_leaf, &tail_leaf).id;
        assert_eq!(data_root(&data), expected);
    }

    #[test]
    fn just_over_max_chunk_rebalances_the_last_two() {
        // MAX + 1 byte: the tail (1 byte) is below MIN, so the two chunks balance
        // to ceil((MAX+1)/2) and the remainder.
        let len = MAX_CHUNK_SIZE + 1;
        let ranges = chunk_ranges(len);
        let first = len.div_ceil(2);
        assert_eq!(ranges, vec![(0, first), (first, len)]);
        assert_eq!(
            ranges.last().unwrap().1,
            len,
            "ranges cover the whole payload"
        );
    }

    #[test]
    fn large_tail_above_min_is_a_clean_second_chunk() {
        // MAX + MIN: the tail is exactly MIN, not below it, so no rebalancing.
        let len = MAX_CHUNK_SIZE + MIN_CHUNK_SIZE;
        let ranges = chunk_ranges(len);
        assert_eq!(ranges, vec![(0, MAX_CHUNK_SIZE), (MAX_CHUNK_SIZE, len)]);
    }

    #[test]
    fn chunk_ranges_always_cover_the_whole_payload_contiguously() {
        for len in [
            0usize,
            1,
            MIN_CHUNK_SIZE,
            MAX_CHUNK_SIZE - 1,
            MAX_CHUNK_SIZE,
            3 * MAX_CHUNK_SIZE + 5,
        ] {
            let ranges = chunk_ranges(len);
            assert_eq!(ranges.first().unwrap().0, 0);
            assert_eq!(ranges.last().unwrap().1, len);
            for pair in ranges.windows(2) {
                assert_eq!(pair[0].1, pair[1].0, "ranges are contiguous at len {len}");
            }
        }
    }

    #[test]
    fn empty_payload_yields_one_zero_length_chunk() {
        assert_eq!(chunk_ranges(0), vec![(0, 0)]);
        // The root is well-defined (the lone zero-length leaf), not the all-zero
        // fallback.
        assert_eq!(data_root(&[]), expected_single_chunk_root(&[]));
    }

    #[test]
    fn note_to_buffer_is_big_endian_in_the_low_eight_bytes() {
        let note = note_to_buffer(0x0102_0304);
        assert!(note[..NOTE_SIZE - 8].iter().all(|&b| b == 0));
        assert_eq!(&note[NOTE_SIZE - 8..], &0x0102_0304u64.to_be_bytes());
    }

    #[test]
    fn reward_tracks_the_documented_per_kilobyte_rate() {
        // The reward must equal the node's own floor so the signed value and the
        // JSON field agree; pin the arithmetic.
        assert_eq!(reward_for(0), 0);
        assert_eq!(reward_for(1000), 65_595_508);
        assert_eq!(reward_for(500), (0.5_f64 * 65_595_508.0).round() as u64);
    }

    #[test]
    fn arweave_address_is_sha256_of_owner_base64url() {
        let owner = vec![0x11u8; 512];
        let expected = base64url::encode(&Sha256::digest(&owner));
        assert_eq!(arweave_address(&owner), expected);
    }

    /// A deterministic fake signer so the transfer tests exercise field encoding
    /// without an RSA key: `owner` is a fixed blob and `sign` echoes the message,
    /// which also lets a test recover the exact deep-hash that was signed.
    struct EchoSigner;

    impl crate::signer::Ans104Signer for EchoSigner {
        fn owner(&self) -> Vec<u8> {
            vec![0x42u8; 512]
        }

        fn signature_type(&self) -> u16 {
            1
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Ans104Error> {
            Ok(message.to_vec())
        }
    }

    fn target_b64url() -> String {
        base64url::encode(&[0x33u8; 32])
    }

    #[test]
    fn a_transfer_renders_target_quantity_and_empty_data_fields() {
        let quantity: u128 = 5_000_000_000_000; // 5 AR in winston
        let anchor = base64url::encode(&[0x77u8; 48]);
        let tx = sign_transfer_tx_v2(&EchoSigner, &target_b64url(), quantity, &anchor, 7)
            .expect("a well-formed transfer signs");
        let json = tx.to_json();

        assert_eq!(json["target"], target_b64url());
        assert_eq!(json["quantity"], quantity.to_string());
        // A payload-less transaction carries empty data fields and the EMPTY
        // data_root (never the zero-length-chunk Merkle root).
        assert_eq!(json["data"], "");
        assert_eq!(json["data_size"], "0");
        assert_eq!(json["data_root"], "");
        assert_eq!(json["reward"], "7");
        assert_eq!(json["last_tx"], anchor);
        assert_eq!(json["format"], 2);
    }

    #[test]
    fn a_transfer_signs_the_target_and_quantity() {
        // The EchoSigner's signature IS the deep-hash message, so the signed bytes
        // must equal the canonical field list's deep-hash with the decoded target
        // and the ascii quantity folded in. This pins that the transfer fields are
        // inside the signature, not only in the JSON.
        let quantity: u128 = u128::from(u64::MAX) + 1; // beyond u64, still signable
        let tx = sign_transfer_tx_v2(&EchoSigner, &target_b64url(), quantity, "", 9)
            .expect("a well-formed transfer signs");

        let expected = signature_data(
            &EchoSigner.owner(),
            &[0x33u8; 32],
            quantity,
            "",
            &[],
            0,
            9,
            &[],
        )
        .expect("the reference message builds");
        let json = tx.to_json();
        let signed = base64url::decode(json["signature"].as_str().unwrap()).unwrap();
        assert_eq!(signed, expected.to_vec());
        // The id is SHA-256 of the signature bytes.
        let expected_id = base64url::encode(&Sha256::digest(&signed));
        assert_eq!(json["id"], expected_id);
    }

    #[test]
    fn a_transfer_rejects_a_malformed_target_or_zero_quantity() {
        // Wrong-length target.
        let short = base64url::encode(&[0x33u8; 16]);
        assert!(matches!(
            sign_transfer_tx_v2(&EchoSigner, &short, 1, "", 1),
            Err(Ans104Error::FieldLength {
                field: "target",
                ..
            })
        ));
        // Not base64url at all.
        assert!(matches!(
            sign_transfer_tx_v2(&EchoSigner, "not/base64url!", 1, "", 1),
            Err(Ans104Error::Malformed(_))
        ));
        // Zero quantity moves nothing and only burns the reward.
        assert!(matches!(
            sign_transfer_tx_v2(&EchoSigner, &target_b64url(), 0, "", 1),
            Err(Ans104Error::Malformed(_))
        ));
    }

    #[test]
    fn a_data_carrier_still_renders_no_transfer_fields() {
        let data = b"a small bundle payload".to_vec();
        let tx = sign_tx_v2(&EchoSigner, &data, &[], "", 3).expect("a data carrier signs");
        let json = tx.to_json();
        assert_eq!(json["target"], "");
        assert_eq!(json["quantity"], "0");
        assert_eq!(json["data_size"], data.len().to_string());
        assert_eq!(
            json["data_root"],
            base64url::encode(&data_root(&data)),
            "a non-empty payload still carries its Merkle root"
        );
    }

    #[test]
    fn data_root_matches_a_reference_known_answer() {
        // The data root for this deterministic 1500-byte payload was cross-computed
        // by the reference Arweave merkle implementation. Pinning it here locks the
        // chunking + double-hashed-leaf construction to the reference byte-for-byte,
        // so a regression in either is caught without an external tool.
        let data: Vec<u8> = (0..1500usize)
            .map(|i| ((i * 11 + 5) & 0xff) as u8)
            .collect();
        let root = base64url::encode(&data_root(&data));
        assert_eq!(root, "hhgkDvh31rvaboa53Xld-2nUfBGqpLNwtNmwvg7cyKU");
    }
}
