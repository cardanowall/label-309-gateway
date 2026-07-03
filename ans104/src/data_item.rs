//! The ANS-104 data item: its builder, its signed form, its serialised bytes,
//! and the deep-hash structure that gets signed.
//!
//! # Binary layout
//!
//! A serialised data item is, in order:
//!
//! ```text
//! signature type   u16, little-endian
//! signature        signature_len bytes (per signature type)
//! owner            owner_len bytes (per signature type)
//! target           1-byte presence flag, then 32 bytes if present
//! anchor           1-byte presence flag, then 32 bytes if present
//! tag count        u64, little-endian
//! tag byte-length  u64, little-endian
//! tags             Avro tag block (tag byte-length bytes; empty if no tags)
//! data             remaining bytes
//! ```
//!
//! # Signed message
//!
//! The signature covers the deep-hash of the list
//! `["dataitem", "1", ascii(sig_type), owner, target, anchor, tags, data]`.
//! Absent target and anchor contribute an empty blob (not an omitted element),
//! so the signed structure always has eight elements. Any change to any field
//! changes the deep-hash and invalidates the signature.
//!
//! # Id
//!
//! The id is `SHA-256(signature)`, exposed both as raw bytes and as
//! URL-safe-no-pad base64.

use std::io::Read;

use sha2::{Digest, Sha256};

use crate::base64url;
use crate::deep_hash::{deep_hash, deep_hash_blob_reader, deep_hash_list_of, DeepHashItem};
use crate::error::Ans104Error;
use crate::sig_type::{sig_config, SigConfig, RSA_4096_LEN, SIGNATURE_TYPE_ARWEAVE};
use crate::signer::Ans104Signer;
use crate::tags::{decode_tags, encode_tags, Tag, MAX_TAG_BYTES};

/// Byte length of a data-item target or anchor when present.
pub const TARGET_LEN: usize = 32;
/// Byte length of a data-item anchor when present (same as target).
pub const ANCHOR_LEN: usize = TARGET_LEN;

/// Length of the fixed tag header: an 8-byte count plus an 8-byte byte-length.
const TAG_HEADER_LEN: usize = 16;

/// Builder for a data item. Accumulates the fields, then [`sign`](Self::sign)s
/// them with a signer that supplies the signature type, owner, and signature.
///
/// ```no_run
/// # use ans104::{DataItemBuilder, ArweaveJwkSigner};
/// # fn demo(signer: &ArweaveJwkSigner) -> Result<(), ans104::Ans104Error> {
/// let item = DataItemBuilder::new(b"payload".to_vec())
///     .tag("Content-Type", "text/plain")
///     .anchor([7u8; 32])?
///     .sign(signer)?;
/// let _id = item.id_b64url;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default)]
pub struct DataItemBuilder {
    data: Vec<u8>,
    target: Option<[u8; TARGET_LEN]>,
    anchor: Option<[u8; ANCHOR_LEN]>,
    tags: Vec<Tag>,
}

impl DataItemBuilder {
    /// Start a builder for the given payload bytes.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            ..Self::default()
        }
    }

    /// Append a name/value tag. Tags are signed in insertion order.
    #[must_use]
    pub fn tag(mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        self.tags.push(Tag::new(name, value));
        self
    }

    /// Append an already-built tag.
    #[must_use]
    pub fn push_tag(mut self, tag: Tag) -> Self {
        self.tags.push(tag);
        self
    }

    /// Set the 32-byte target. The target identifies a recipient address; it is
    /// optional and, when present, is exactly 32 bytes.
    pub fn target(mut self, target: impl AsRef<[u8]>) -> Result<Self, Ans104Error> {
        self.target = Some(fixed_32("target", target.as_ref())?);
        Ok(self)
    }

    /// Set the 32-byte anchor. The anchor is an optional caller-chosen nonce; it
    /// is exactly 32 bytes when present.
    pub fn anchor(mut self, anchor: impl AsRef<[u8]>) -> Result<Self, Ans104Error> {
        self.anchor = Some(fixed_32("anchor", anchor.as_ref())?);
        Ok(self)
    }

    /// Sign the accumulated fields, producing a [`SignedDataItem`] carrying the
    /// signature, the id (raw and base64url), and the canonical bytes.
    pub fn sign(self, signer: &impl Ans104Signer) -> Result<SignedDataItem, Ans104Error> {
        let unsigned = UnsignedDataItem {
            signature_type: signer.signature_type(),
            owner: signer.owner(),
            target: self.target,
            anchor: self.anchor,
            tags: self.tags,
            data: self.data,
        };
        // Validate framing-critical invariants (owner length, tag size) before
        // we spend a signing operation on them.
        unsigned.validate()?;

        let message = deep_hash_message(&unsigned)?;
        let signature = signer.sign(&message)?;
        let cfg = sig_config(unsigned.signature_type)?;
        if signature.len() != cfg.signature_len {
            return Err(Ans104Error::FieldLength {
                field: "signature",
                actual: signature.len(),
                expected: cfg.signature_len,
            });
        }

        let id: [u8; 32] = Sha256::digest(&signature).into();
        let bytes = serialize(&unsigned, &signature)?;
        Ok(SignedDataItem {
            item: unsigned,
            signature,
            id,
            id_b64url: base64url::encode(&id),
            bytes,
        })
    }
}

/// A data item's signed fields, independent of the signature itself. Both the
/// signer and the verifier hash exactly this structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedDataItem {
    /// Signature-type tag.
    pub signature_type: u16,
    /// Owner (public-key) bytes; length is fixed by the signature type.
    pub owner: Vec<u8>,
    /// Optional 32-byte target address.
    pub target: Option<[u8; TARGET_LEN]>,
    /// Optional 32-byte anchor.
    pub anchor: Option<[u8; ANCHOR_LEN]>,
    /// Ordered tag list.
    pub tags: Vec<Tag>,
    /// Payload bytes.
    pub data: Vec<u8>,
}

impl UnsignedDataItem {
    /// Check the field invariants the framing depends on: the owner length must
    /// match the signature type, and the tags must serialise within the size
    /// limit. Does not perform any cryptography.
    pub fn validate(&self) -> Result<SigConfig, Ans104Error> {
        let cfg = sig_config(self.signature_type)?;
        if self.owner.len() != cfg.owner_len {
            return Err(Ans104Error::FieldLength {
                field: "owner",
                actual: self.owner.len(),
                expected: cfg.owner_len,
            });
        }
        // Encoding enforces the 4096-byte tag limit.
        let _ = encode_tags(&self.tags)?;
        Ok(cfg)
    }

    /// Build the deep-hash structure ANS-104 signs for this item.
    pub fn deep_hash_item(&self) -> Result<DeepHashItem, Ans104Error> {
        let tags_blob = encode_tags(&self.tags)?;
        Ok(DeepHashItem::list(vec![
            DeepHashItem::blob(b"dataitem".to_vec()),
            DeepHashItem::blob(b"1".to_vec()),
            DeepHashItem::blob(self.signature_type.to_string().into_bytes()),
            DeepHashItem::blob(self.owner.clone()),
            DeepHashItem::blob(self.target.map_or_else(Vec::new, |t| t.to_vec())),
            DeepHashItem::blob(self.anchor.map_or_else(Vec::new, |a| a.to_vec())),
            DeepHashItem::blob(tags_blob),
            DeepHashItem::blob(self.data.clone()),
        ]))
    }
}

/// The deep-hash message (48-byte SHA-384) over an unsigned item's signed
/// fields. This is the value a signer signs and a verifier checks against.
pub fn deep_hash_message(item: &UnsignedDataItem) -> Result<[u8; 48], Ans104Error> {
    Ok(crate::deep_hash::deep_hash(&item.deep_hash_item()?))
}

/// The bounded signed envelope of a data item: everything needed to reconstruct
/// the canonical bytes deterministically, without storing the payload.
///
/// The signature commits, via the deep-hash, to the fixed fields plus the
/// payload bytes; the payload is identified by length and stored out of band
/// (for example a staged file pinned by its SHA-256). Given the same payload
/// bytes plus this envelope and the owner key, `serialize` reproduces the
/// byte-identical data item, and the id `SHA-256(signature)` is unchanged,
/// because the signature already covers exactly those parts. This lets an
/// interrupted upload be re-driven from a small persisted envelope and a durable
/// payload, never re-signing (a re-sign would change the randomised PSS
/// signature and therefore the id).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEnvelope {
    /// Signature-type tag (fixes the owner and signature framing lengths).
    pub signature_type: u16,
    /// Signature over the deep-hash; length is fixed by the signature type.
    pub signature: Vec<u8>,
    /// 32-byte item id, `SHA-256(signature)`.
    pub id: [u8; 32],
    /// The id as URL-safe-no-pad base64.
    pub id_b64url: String,
    /// Optional 32-byte target.
    pub target: Option<[u8; TARGET_LEN]>,
    /// Optional 32-byte anchor.
    pub anchor: Option<[u8; ANCHOR_LEN]>,
    /// The serialised Avro tag block (`encode_tags` output): the exact bytes the
    /// deep-hash and the wire framing both use.
    pub tag_bytes: Vec<u8>,
}

/// Sign a data item whose payload is read from a streaming source rather than
/// held in memory, producing the bounded [`SignedEnvelope`].
///
/// The fixed elements (`"dataitem"`, `"1"`, `ascii(sig_type)`, owner, target,
/// anchor, tags) are deep-hashed in memory — all are bounded — while the trailing
/// `data` element is folded in via a single streaming SHA-384 pass over `reader`,
/// so a multi-gigabyte payload signs with a fixed working set. `data_len` is the
/// exact payload length; it is committed into the `data` leaf's length tag before
/// the bytes are read, and the reader is enforced to yield exactly that many
/// bytes (a short or long read is [`Ans104Error::Io`], never a silently wrong
/// signature).
///
/// The resulting signature is byte-identical to signing the same fields with the
/// whole payload in memory, because both paths hash the identical eight-element
/// deep-hash list. The payload itself is never returned or buffered here; the
/// caller pairs this envelope with the (out-of-band) payload to serialise the
/// canonical bytes via [`reconstruct_prefix`] followed by the payload.
pub fn sign_streaming<S: Ans104Signer, R: Read>(
    signer: &S,
    target: Option<[u8; TARGET_LEN]>,
    anchor: Option<[u8; ANCHOR_LEN]>,
    tags: &[Tag],
    reader: &mut R,
    data_len: u64,
) -> Result<SignedEnvelope, Ans104Error> {
    let signature_type = signer.signature_type();
    let owner = signer.owner();
    let cfg = sig_config(signature_type)?;
    if owner.len() != cfg.owner_len {
        return Err(Ans104Error::FieldLength {
            field: "owner",
            actual: owner.len(),
            expected: cfg.owner_len,
        });
    }
    // Encoding enforces the 4096-byte tag limit; the bytes are reused verbatim in
    // both the deep-hash and the wire framing.
    let tag_bytes = encode_tags(tags)?;

    // Deep-hash the seven bounded leaves in memory, then fold the streamed `data`
    // leaf as the eighth element. The fold reproduces deep_hash over the full
    // eight-element list because each child digest is identical.
    let fixed = [
        deep_hash(&DeepHashItem::blob(b"dataitem".to_vec())),
        deep_hash(&DeepHashItem::blob(b"1".to_vec())),
        deep_hash(&DeepHashItem::blob(signature_type.to_string().into_bytes())),
        deep_hash(&DeepHashItem::blob(owner.clone())),
        deep_hash(&DeepHashItem::blob(
            target.map_or_else(Vec::new, |t| t.to_vec()),
        )),
        deep_hash(&DeepHashItem::blob(
            anchor.map_or_else(Vec::new, |a| a.to_vec()),
        )),
        deep_hash(&DeepHashItem::blob(tag_bytes.clone())),
    ];
    let data_leaf = deep_hash_blob_reader(reader, data_len)?;

    let mut children = Vec::with_capacity(fixed.len() + 1);
    children.extend_from_slice(&fixed);
    children.push(data_leaf);
    let message = deep_hash_list_of(&children);

    let signature = signer.sign(&message)?;
    if signature.len() != cfg.signature_len {
        return Err(Ans104Error::FieldLength {
            field: "signature",
            actual: signature.len(),
            expected: cfg.signature_len,
        });
    }

    let id: [u8; 32] = Sha256::digest(&signature).into();
    Ok(SignedEnvelope {
        signature_type,
        signature,
        id,
        id_b64url: base64url::encode(&id),
        target,
        anchor,
        tag_bytes,
    })
}

/// A fully signed, serialised data item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDataItem {
    /// The signed fields.
    pub item: UnsignedDataItem,
    /// Signature over the deep-hash; length is fixed by the signature type.
    pub signature: Vec<u8>,
    /// 32-byte item id, `SHA-256(signature)`.
    pub id: [u8; 32],
    /// The id as URL-safe-no-pad base64.
    pub id_b64url: String,
    /// Canonical ANS-104 binary form.
    pub bytes: Vec<u8>,
}

impl SignedDataItem {
    /// Parse a serialised data item into a view, validating the framing and the
    /// declared field lengths but not the signature. Use
    /// [`verify`](crate::verify::verify) to additionally check the signature and
    /// recompute the id.
    pub fn parse(bytes: &[u8]) -> Result<DataItemView, Ans104Error> {
        DataItemView::parse(bytes)
    }
}

/// A structured, validated view over the bytes of a data item, produced by
/// parsing. It exposes the signature, owner, target, anchor, tags, and data
/// without copying the whole payload until asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataItemView {
    /// Signature-type tag.
    pub signature_type: u16,
    /// Signature bytes.
    pub signature: Vec<u8>,
    /// Owner (public-key) bytes.
    pub owner: Vec<u8>,
    /// 32-byte target if present.
    pub target: Option<[u8; TARGET_LEN]>,
    /// 32-byte anchor if present.
    pub anchor: Option<[u8; ANCHOR_LEN]>,
    /// Ordered tag list.
    pub tags: Vec<Tag>,
    /// Payload bytes.
    pub data: Vec<u8>,
    /// Recomputed id, `SHA-256(signature)`.
    pub id: [u8; 32],
}

impl DataItemView {
    /// Parse and structurally validate a data item's bytes. Validates the
    /// signature-type framing lengths, the target/anchor presence flags, and
    /// the tag block (count, byte-length, and size limit), but does not verify
    /// the signature.
    pub fn parse(bytes: &[u8]) -> Result<Self, Ans104Error> {
        let mut cursor = Cursor::new(bytes);

        let signature_type = cursor.read_u16_le()?;
        let cfg = sig_config(signature_type)?;

        let signature = cursor.read_bytes(cfg.signature_len, "signature")?.to_vec();
        let owner = cursor.read_bytes(cfg.owner_len, "owner")?.to_vec();

        let target = cursor.read_optional_32("target")?;
        let anchor = cursor.read_optional_32("anchor")?;

        let tag_count = cursor.read_u64_le("tag count")? as usize;
        let tag_bytes_len = cursor.read_u64_le("tag byte-length")? as usize;
        if tag_bytes_len > MAX_TAG_BYTES {
            return Err(Ans104Error::InvalidTags("tag byte-length exceeds 4096"));
        }
        let tag_blob = cursor.read_bytes(tag_bytes_len, "tags")?;
        let tags = decode_tags(tag_blob)?;
        if tags.len() != tag_count {
            return Err(Ans104Error::InvalidTags(
                "declared tag count does not match decoded entries",
            ));
        }

        let data = cursor.rest().to_vec();
        let id: [u8; 32] = Sha256::digest(&signature).into();

        Ok(Self {
            signature_type,
            signature,
            owner,
            target,
            anchor,
            tags,
            data,
            id,
        })
    }

    /// Reconstruct the signed-fields structure for re-hashing.
    pub fn unsigned(&self) -> UnsignedDataItem {
        UnsignedDataItem {
            signature_type: self.signature_type,
            owner: self.owner.clone(),
            target: self.target,
            anchor: self.anchor,
            tags: self.tags.clone(),
            data: self.data.clone(),
        }
    }

    /// The id rendered as URL-safe-no-pad base64.
    #[must_use]
    pub fn id_b64url(&self) -> String {
        base64url::encode(&self.id)
    }
}

fn fixed_32(field: &'static str, bytes: &[u8]) -> Result<[u8; 32], Ans104Error> {
    bytes.try_into().map_err(|_| Ans104Error::FieldLength {
        field,
        actual: bytes.len(),
        expected: 32,
    })
}

/// Build the canonical data-item bytes that PRECEDE the payload — the framing
/// header through the tag block, but not the `data` element.
///
/// The serialised layout is `sig_type | signature | owner | target-frame |
/// anchor-frame | tag-count | tag-byte-length | tag-block | data`. Everything up
/// to `data` is bounded (the signature, the owner key, and a tag block capped at
/// 4096 bytes), so it can be materialised; the trailing `data` is then appended
/// or streamed by the caller. Concatenating this prefix with the exact payload
/// bytes yields the identical bytes [`DataItemBuilder::sign`] produces for the
/// same fields, which is what makes a streamed re-POST byte-identical to the
/// once-signed item.
///
/// `owner` is supplied by the caller (it is the funding key the envelope
/// references, not re-stored in the envelope). This validates the signature and
/// owner lengths against the signature type.
pub fn reconstruct_prefix(envelope: &SignedEnvelope, owner: &[u8]) -> Result<Vec<u8>, Ans104Error> {
    let cfg = sig_config(envelope.signature_type)?;
    if envelope.signature.len() != cfg.signature_len {
        return Err(Ans104Error::FieldLength {
            field: "signature",
            actual: envelope.signature.len(),
            expected: cfg.signature_len,
        });
    }
    if owner.len() != cfg.owner_len {
        return Err(Ans104Error::FieldLength {
            field: "owner",
            actual: owner.len(),
            expected: cfg.owner_len,
        });
    }
    if envelope.tag_bytes.len() > MAX_TAG_BYTES {
        return Err(Ans104Error::InvalidTags("tag byte-length exceeds 4096"));
    }
    // The tag count is part of the wire frame but not of the tag-block bytes, so
    // it is recovered by decoding the persisted block. Decoding also rejects a
    // tampered block before it reaches the wire.
    let tags = decode_tags(&envelope.tag_bytes)?;

    let target_len = 1 + envelope.target.map_or(0, |_| TARGET_LEN);
    let anchor_len = 1 + envelope.anchor.map_or(0, |_| ANCHOR_LEN);
    let total = 2
        + cfg.signature_len
        + cfg.owner_len
        + target_len
        + anchor_len
        + TAG_HEADER_LEN
        + envelope.tag_bytes.len();

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&envelope.signature_type.to_le_bytes());
    out.extend_from_slice(&envelope.signature);
    out.extend_from_slice(owner);

    match &envelope.target {
        Some(t) => {
            out.push(1);
            out.extend_from_slice(t);
        }
        None => out.push(0),
    }
    match &envelope.anchor {
        Some(a) => {
            out.push(1);
            out.extend_from_slice(a);
        }
        None => out.push(0),
    }

    out.extend_from_slice(&(tags.len() as u64).to_le_bytes());
    out.extend_from_slice(&(envelope.tag_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&envelope.tag_bytes);

    Ok(out)
}

/// Serialise an unsigned item plus its signature into the canonical bytes.
fn serialize(item: &UnsignedDataItem, signature: &[u8]) -> Result<Vec<u8>, Ans104Error> {
    let cfg = sig_config(item.signature_type)?;
    if signature.len() != cfg.signature_len {
        return Err(Ans104Error::FieldLength {
            field: "signature",
            actual: signature.len(),
            expected: cfg.signature_len,
        });
    }

    let tag_blob = encode_tags(&item.tags)?;

    let target_len = 1 + item.target.map_or(0, |_| TARGET_LEN);
    let anchor_len = 1 + item.anchor.map_or(0, |_| ANCHOR_LEN);
    let total = 2
        + cfg.signature_len
        + cfg.owner_len
        + target_len
        + anchor_len
        + TAG_HEADER_LEN
        + tag_blob.len()
        + item.data.len();

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&item.signature_type.to_le_bytes());
    out.extend_from_slice(signature);
    out.extend_from_slice(&item.owner);

    match &item.target {
        Some(t) => {
            out.push(1);
            out.extend_from_slice(t);
        }
        None => out.push(0),
    }
    match &item.anchor {
        Some(a) => {
            out.push(1);
            out.extend_from_slice(a);
        }
        None => out.push(0),
    }

    out.extend_from_slice(&(item.tags.len() as u64).to_le_bytes());
    out.extend_from_slice(&(tag_blob.len() as u64).to_le_bytes());
    out.extend_from_slice(&tag_blob);
    out.extend_from_slice(&item.data);

    Ok(out)
}

/// A forward-only reader over the data-item bytes that reports truncation as a
/// [`Ans104Error::Malformed`] instead of panicking on a slice out of range.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_bytes(&mut self, len: usize, _field: &'static str) -> Result<&'a [u8], Ans104Error> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Ans104Error::Malformed("length overflow"))?;
        if end > self.bytes.len() {
            return Err(Ans104Error::Malformed("truncated data item"));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u16_le(&mut self) -> Result<u16, Ans104Error> {
        let b = self.read_bytes(2, "signature type")?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u64_le(&mut self, field: &'static str) -> Result<u64, Ans104Error> {
        let b = self.read_bytes(8, field)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(u64::from_le_bytes(arr))
    }

    fn read_optional_32(&mut self, field: &'static str) -> Result<Option<[u8; 32]>, Ans104Error> {
        let flag = self.read_bytes(1, field)?[0];
        match flag {
            0 => Ok(None),
            1 => {
                let b = self.read_bytes(32, field)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                Ok(Some(arr))
            }
            _ => Err(Ans104Error::Malformed("invalid presence flag")),
        }
    }

    fn rest(&mut self) -> &'a [u8] {
        let slice = &self.bytes[self.pos..];
        self.pos = self.bytes.len();
        slice
    }
}

// Re-exported constants kept for downstream callers that pin the wire values.
pub use crate::sig_type::{
    RSA_4096_LEN as ARWEAVE_OWNER_LEN, SIGNATURE_TYPE_ARWEAVE as ARWEAVE_TYPE,
};

const _: () = {
    // Compile-time assertion that the re-exported aliases track the registry.
    assert!(ARWEAVE_TYPE == SIGNATURE_TYPE_ARWEAVE);
    assert!(ARWEAVE_OWNER_LEN == RSA_4096_LEN);
};
