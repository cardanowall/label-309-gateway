//! The ANS-104 deep-hash.
//!
//! ANS-104 signs a recursive SHA-384 "deep hash" over a nested structure of
//! byte blobs and lists rather than a flat concatenation. A blob hashes as
//! `H(H("blob" || ascii(len)) || H(blob))`, where `ascii(len)` is the decimal
//! byte length rendered as ASCII digits. A list of length `n` folds each
//! element into an accumulator seeded with `H("list" || ascii(n))`:
//!
//! ```text
//! acc_0     = H("list" || ascii(n))
//! acc_{i+1} = H(acc_i || deep_hash(element_i))
//! ```
//!
//! This domain separation is what prevents two different structures from
//! colliding to the same signed digest: a blob and a one-element list of that
//! blob hash differently because of the distinct `"blob"`/`"list"` prefixes.
//!
//! A data item's payload can be many gigabytes, so it cannot always be held in
//! memory. [`deep_hash_blob_reader`] computes a blob leaf by streaming its bytes
//! through a single SHA-384 pass, and [`deep_hash_list_of`] folds already-known
//! child digests into a list, so a caller can fold a streamed payload leaf into
//! the eight-element data-item list with a bounded working set. The streamed leaf
//! is byte-identical to [`deep_hash`] of the same blob.

use std::io::Read;

use sha2::{Digest, Sha384};

use crate::error::Ans104Error;

/// Width of a SHA-384 digest in bytes.
pub const DEEP_HASH_LEN: usize = 48;

/// Buffer size for streaming a large payload leaf through the hasher. Sized so a
/// multi-gigabyte payload hashes with a bounded, fixed working set rather than a
/// resident buffer that scales with the file.
const STREAM_CHUNK: usize = 64 * 1024;

/// A deep-hashable value: either a leaf blob or an ordered list of nested
/// values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeepHashItem {
    /// A leaf byte string.
    Blob(Vec<u8>),
    /// An ordered list of nested items.
    List(Vec<DeepHashItem>),
}

impl DeepHashItem {
    /// Construct a leaf from owned bytes.
    #[must_use]
    pub fn blob(bytes: Vec<u8>) -> Self {
        Self::Blob(bytes)
    }

    /// Construct a list node from its child items.
    #[must_use]
    pub fn list(items: Vec<DeepHashItem>) -> Self {
        Self::List(items)
    }
}

fn sha384(parts: &[&[u8]]) -> [u8; DEEP_HASH_LEN] {
    let mut hasher = Sha384::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Compute the 48-byte (SHA-384) deep hash of an item.
#[must_use]
pub fn deep_hash(item: &DeepHashItem) -> [u8; DEEP_HASH_LEN] {
    match item {
        DeepHashItem::Blob(bytes) => {
            let len_ascii = bytes.len().to_string();
            let tagged = sha384(&[b"blob", len_ascii.as_bytes()]);
            let data_hash = sha384(&[bytes]);
            sha384(&[&tagged, &data_hash])
        }
        DeepHashItem::List(items) => {
            let len_ascii = items.len().to_string();
            let mut acc = sha384(&[b"list", len_ascii.as_bytes()]);
            for child in items {
                let child_hash = deep_hash(child);
                acc = sha384(&[&acc, &child_hash]);
            }
            acc
        }
    }
}

/// Compute the deep-hash of a blob leaf by streaming its bytes, never holding the
/// whole payload in memory.
///
/// A blob hashes as `H(H("blob" || ascii(len)) || H(blob))`. The `ascii(len)`
/// tag commits to the byte length *before* the bytes are read, so the caller must
/// supply the exact length; the reader is then drained through a single SHA-384
/// pass for the `H(blob)` term. The result is byte-identical to
/// [`deep_hash`] of [`DeepHashItem::Blob`] over the same bytes.
///
/// The declared `len` is enforced: if the reader yields a different number of
/// bytes than `len`, this returns [`Ans104Error::Io`] rather than signing a
/// digest whose length tag disagrees with its data. This is what keeps a
/// streamed signature reproducible from a persisted length-and-bytes pair.
pub fn deep_hash_blob_reader<R: Read>(
    reader: &mut R,
    len: u64,
) -> Result<[u8; DEEP_HASH_LEN], Ans104Error> {
    let len_ascii = len.to_string();
    let tagged = sha384(&[b"blob", len_ascii.as_bytes()]);

    let mut data_hasher = Sha384::new();
    let mut buf = vec![0u8; STREAM_CHUNK];
    let mut seen: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| Ans104Error::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        seen = seen
            .checked_add(n as u64)
            .ok_or_else(|| Ans104Error::Io("payload length overflow".to_string()))?;
        if seen > len {
            return Err(Ans104Error::Io(format!(
                "stream yielded more than the declared {len} bytes"
            )));
        }
        data_hasher.update(&buf[..n]);
    }
    if seen != len {
        return Err(Ans104Error::Io(format!(
            "stream yielded {seen} bytes, expected {len}"
        )));
    }
    let data_hash: [u8; DEEP_HASH_LEN] = data_hasher.finalize().into();

    Ok(sha384(&[&tagged, &data_hash]))
}

/// Fold a sequence of already-computed child deep-hashes into the deep-hash of a
/// list of that arity.
///
/// `deep_hash` of a [`DeepHashItem::List`] computes each child's hash and folds
/// it; this entry point lets a caller fold children whose hashes were computed
/// out of band, in particular a large trailing element hashed via
/// [`deep_hash_blob_reader`] without materialising it as a `DeepHashItem`. The
/// result is identical to [`deep_hash`] over a list whose children produce the
/// same per-child digests.
#[must_use]
pub fn deep_hash_list_of(child_hashes: &[[u8; DEEP_HASH_LEN]]) -> [u8; DEEP_HASH_LEN] {
    let len_ascii = child_hashes.len().to_string();
    let mut acc = sha384(&[b"list", len_ascii.as_bytes()]);
    for child in child_hashes {
        acc = sha384(&[&acc, child]);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each expected digest below is computed inline from the algorithm this
    // module documents, so the assertions pin the construction itself rather
    // than echoing a value the implementation produced.

    fn h(parts: &[&[u8]]) -> [u8; DEEP_HASH_LEN] {
        sha384(parts)
    }

    fn expected_blob(bytes: &[u8]) -> [u8; DEEP_HASH_LEN] {
        let len_ascii = bytes.len().to_string();
        let tagged = h(&[b"blob", len_ascii.as_bytes()]);
        let data_hash = h(&[bytes]);
        h(&[&tagged, &data_hash])
    }

    fn expected_list(children: &[[u8; DEEP_HASH_LEN]]) -> [u8; DEEP_HASH_LEN] {
        let len_ascii = children.len().to_string();
        let mut acc = h(&[b"list", len_ascii.as_bytes()]);
        for c in children {
            acc = h(&[&acc, c]);
        }
        acc
    }

    #[test]
    fn empty_blob_matches_the_documented_construction() {
        let got = deep_hash(&DeepHashItem::blob(vec![]));
        assert_eq!(got, expected_blob(&[]));
    }

    #[test]
    fn non_empty_blob_uses_ascii_length_tag() {
        let payload = b"the quick brown fox".to_vec();
        let got = deep_hash(&DeepHashItem::blob(payload.clone()));
        assert_eq!(got, expected_blob(&payload));
        // A different-length payload must not collide with the previous tag.
        let other = deep_hash(&DeepHashItem::blob(b"jumps".to_vec()));
        assert_ne!(got, other);
    }

    #[test]
    fn empty_list_is_just_the_seed_hash() {
        let got = deep_hash(&DeepHashItem::list(vec![]));
        assert_eq!(got, expected_list(&[]));
        // The empty list and the empty blob are domain-separated.
        assert_ne!(got, deep_hash(&DeepHashItem::blob(vec![])));
    }

    #[test]
    fn simple_list_folds_children_in_order() {
        let a = b"alpha".to_vec();
        let b = b"beta".to_vec();
        let item = DeepHashItem::list(vec![
            DeepHashItem::blob(a.clone()),
            DeepHashItem::blob(b.clone()),
        ]);
        let got = deep_hash(&item);
        let expected = expected_list(&[expected_blob(&a), expected_blob(&b)]);
        assert_eq!(got, expected);

        // Order is part of the claim: swapping the children changes the hash.
        let swapped = DeepHashItem::list(vec![DeepHashItem::blob(b), DeepHashItem::blob(a)]);
        assert_ne!(deep_hash(&swapped), got);
    }

    #[test]
    fn streamed_blob_leaf_matches_in_memory_leaf() {
        // The streaming blob leaf must produce the identical 48-byte digest as
        // hashing the whole blob in memory, across empty, sub-chunk, exact-chunk,
        // and multi-chunk lengths (the chunk boundary is the interesting case).
        for len in [
            0usize,
            1,
            19,
            STREAM_CHUNK - 1,
            STREAM_CHUNK,
            STREAM_CHUNK + 1,
            3 * STREAM_CHUNK + 7,
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let in_memory = deep_hash(&DeepHashItem::blob(payload.clone()));
            let streamed =
                deep_hash_blob_reader(&mut payload.as_slice(), payload.len() as u64).unwrap();
            assert_eq!(streamed, in_memory, "streamed leaf mismatch at len {len}");
        }
    }

    #[test]
    fn streamed_blob_leaf_rejects_a_short_read() {
        // The length tag is committed before the bytes are read, so a reader that
        // is shorter than declared must fail loudly rather than sign a digest
        // whose "blob"||ascii(len) tag disagrees with the data hashed.
        let payload = b"only nineteen bytes".to_vec();
        let err = deep_hash_blob_reader(&mut payload.as_slice(), payload.len() as u64 + 5)
            .expect_err("short read must error");
        assert!(matches!(err, Ans104Error::Io(_)));
    }

    #[test]
    fn streamed_blob_leaf_rejects_a_long_read() {
        let payload = b"twenty-four payload bytes".to_vec();
        let err = deep_hash_blob_reader(&mut payload.as_slice(), 4)
            .expect_err("over-length read must error");
        assert!(matches!(err, Ans104Error::Io(_)));
    }

    #[test]
    fn list_fold_helper_matches_recursive_list_hash() {
        // Folding pre-computed child digests must reproduce deep_hash over a list
        // whose children yield those same digests. This is what lets the signing
        // path fold a streamed trailing leaf into the eight-element data-item list.
        let a = b"alpha".to_vec();
        let b = b"beta".to_vec();
        let c = b"gamma".to_vec();
        let children = [
            deep_hash(&DeepHashItem::blob(a.clone())),
            deep_hash(&DeepHashItem::blob(b.clone())),
            deep_hash(&DeepHashItem::blob(c.clone())),
        ];
        let folded = deep_hash_list_of(&children);
        let recursive = deep_hash(&DeepHashItem::list(vec![
            DeepHashItem::blob(a),
            DeepHashItem::blob(b),
            DeepHashItem::blob(c),
        ]));
        assert_eq!(folded, recursive);

        // The empty fold is the bare list seed.
        assert_eq!(
            deep_hash_list_of(&[]),
            deep_hash(&DeepHashItem::list(vec![]))
        );
    }

    #[test]
    fn nested_list_recurses_through_sublists() {
        let inner_payload = b"inner".to_vec();
        let outer_payload = b"outer".to_vec();
        let item = DeepHashItem::list(vec![
            DeepHashItem::blob(outer_payload.clone()),
            DeepHashItem::list(vec![DeepHashItem::blob(inner_payload.clone())]),
        ]);
        let got = deep_hash(&item);

        let inner_hash = expected_list(&[expected_blob(&inner_payload)]);
        let expected = expected_list(&[expected_blob(&outer_payload), inner_hash]);
        assert_eq!(got, expected);

        // A one-element list wrapping a blob differs from the bare blob:
        // the "list" vs "blob" domain tags must keep them apart.
        let bare = deep_hash(&DeepHashItem::blob(inner_payload.clone()));
        let wrapped = deep_hash(&DeepHashItem::list(vec![DeepHashItem::blob(inner_payload)]));
        assert_ne!(bare, wrapped);
    }
}
