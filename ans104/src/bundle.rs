//! The ANS-104 bundle envelope: wrapping signed data items for base-layer posting.
//!
//! A data item is posted to Arweave inside a *bundle*: the base-layer transaction
//! carries the bundle bytes as its payload and tags itself `Bundle-Format: binary`
//! / `Bundle-Version: 2.0.0`, and a gateway unbundles the items back out by id. This
//! module encodes that binary bundle envelope from already-serialised data items.
//!
//! # Binary layout
//!
//! ```text
//! item count   32 bytes, little-endian
//! per item:
//!   item size  32 bytes, little-endian (the data item's serialised byte length)
//!   item id    32 bytes (the raw data-item id, SHA-256 of its signature)
//! items        each data item's canonical bytes, concatenated in header order
//! ```
//!
//! The 32-byte little-endian integer fields mirror the reference bundle reader,
//! which reconstructs each value least-significant-byte-first; only the low eight
//! bytes are ever populated, the rest are zero. The header's per-item entries are
//! in the same order as the trailing item bytes, so a reader sums sizes to locate
//! each item.
//!
//! [ANS-104]: https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md

use crate::error::Ans104Error;

/// Byte width of each integer field in the bundle header (the count and each
/// per-item size). The value is stored little-endian in the low bytes.
const BUNDLE_FIELD_LEN: usize = 32;

/// Byte width of a data-item id in the header (`SHA-256` of the signature).
const ITEM_ID_LEN: usize = 32;

/// One already-serialised data item to place in a bundle: its raw id and its
/// canonical bytes.
///
/// The id is the 32-byte `SHA-256(signature)` (the same id the item resolves at);
/// `bytes` are the item's full canonical ANS-104 serialisation. The caller owns
/// producing these (for example from a [`crate::SignedDataItem`] or a streamed
/// reconstruction); this module only frames them into a bundle.
pub struct BundleItem<'a> {
    /// The raw 32-byte data-item id.
    pub id: &'a [u8; ITEM_ID_LEN],
    /// The data item's canonical serialised bytes.
    pub bytes: &'a [u8],
}

/// Encode a binary ANS-104 bundle from its items.
///
/// Writes the 32-byte little-endian item count, then a 64-byte header entry per
/// item (32-byte little-endian size followed by the 32-byte id) in order, then the
/// concatenated item bytes. The result is the payload a base-layer transaction
/// carries under the `Bundle-Format: binary` / `Bundle-Version: 2.0.0` tags.
///
/// Returns [`Ans104Error::Malformed`] if there are more items than the 8-byte
/// integer fields can address (the header integers only populate their low eight
/// bytes), which no realistic bundle approaches.
pub fn encode_bundle(items: &[BundleItem<'_>]) -> Result<Vec<u8>, Ans104Error> {
    let count = u64::try_from(items.len())
        .map_err(|_| Ans104Error::Malformed("bundle item count exceeds u64"))?;

    let header_len = BUNDLE_FIELD_LEN + items.len() * (BUNDLE_FIELD_LEN + ITEM_ID_LEN);
    let body_len: usize = items.iter().map(|item| item.bytes.len()).sum();
    let mut out = Vec::with_capacity(header_len + body_len);

    out.extend_from_slice(&long_to_32(count));
    for item in items {
        let size = u64::try_from(item.bytes.len())
            .map_err(|_| Ans104Error::Malformed("bundle item size exceeds u64"))?;
        out.extend_from_slice(&long_to_32(size));
        out.extend_from_slice(item.id);
    }
    for item in items {
        out.extend_from_slice(item.bytes);
    }

    debug_assert_eq!(out.len(), header_len + body_len);
    Ok(out)
}

/// Render a `u64` as a 32-byte little-endian field: the eight value bytes in the
/// low positions, the remaining 24 bytes zero. This matches the reference bundle
/// reader, which folds the bytes least-significant-first.
fn long_to_32(value: u64) -> [u8; BUNDLE_FIELD_LEN] {
    let mut buf = [0u8; BUNDLE_FIELD_LEN];
    buf[..8].copy_from_slice(&value.to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recover a little-endian value from a 32-byte field the way the reference
    /// reader does, so the assertions pin the wire encoding rather than echoing
    /// `long_to_32`'s own bytes.
    fn read_le_32(field: &[u8]) -> u64 {
        let mut value = 0u64;
        for &byte in field.iter().rev() {
            value = value * 256 + u64::from(byte);
        }
        value
    }

    #[test]
    fn long_to_32_is_little_endian_in_the_low_bytes() {
        let field = long_to_32(0x0102_0304);
        assert_eq!(field[0], 0x04);
        assert_eq!(field[1], 0x03);
        assert_eq!(field[2], 0x02);
        assert_eq!(field[3], 0x01);
        assert!(field[4..].iter().all(|&b| b == 0));
        assert_eq!(read_le_32(&field), 0x0102_0304);
    }

    #[test]
    fn single_item_bundle_has_the_documented_layout() {
        let id = [0xABu8; ITEM_ID_LEN];
        let item_bytes = vec![0x11u8, 0x22, 0x33, 0x44, 0x55];
        let bundle = encode_bundle(&[BundleItem {
            id: &id,
            bytes: &item_bytes,
        }])
        .expect("encode");

        // count(32) + one header entry(64) + body.
        assert_eq!(bundle.len(), 32 + 64 + item_bytes.len());
        assert_eq!(read_le_32(&bundle[0..32]), 1, "item count");
        assert_eq!(
            read_le_32(&bundle[32..64]),
            item_bytes.len() as u64,
            "item size in header"
        );
        assert_eq!(&bundle[64..96], &id, "item id in header");
        assert_eq!(
            &bundle[96..],
            &item_bytes[..],
            "item bytes follow the header"
        );
    }

    #[test]
    fn multi_item_bundle_orders_headers_then_bodies() {
        let id_a = [0x01u8; ITEM_ID_LEN];
        let id_b = [0x02u8; ITEM_ID_LEN];
        let bytes_a = vec![0xAAu8; 7];
        let bytes_b = vec![0xBBu8; 3];
        let bundle = encode_bundle(&[
            BundleItem {
                id: &id_a,
                bytes: &bytes_a,
            },
            BundleItem {
                id: &id_b,
                bytes: &bytes_b,
            },
        ])
        .expect("encode");

        let header_len = 32 + 2 * 64;
        assert_eq!(bundle.len(), header_len + bytes_a.len() + bytes_b.len());
        assert_eq!(read_le_32(&bundle[0..32]), 2, "item count");

        // Header entry 0.
        assert_eq!(read_le_32(&bundle[32..64]), bytes_a.len() as u64);
        assert_eq!(&bundle[64..96], &id_a);
        // Header entry 1.
        assert_eq!(read_le_32(&bundle[96..128]), bytes_b.len() as u64);
        assert_eq!(&bundle[128..160], &id_b);

        // Bodies follow in header order.
        assert_eq!(&bundle[header_len..header_len + 7], &bytes_a[..]);
        assert_eq!(&bundle[header_len + 7..], &bytes_b[..]);
    }

    #[test]
    fn empty_bundle_is_just_a_zero_count() {
        let bundle = encode_bundle(&[]).expect("encode");
        assert_eq!(bundle.len(), 32);
        assert_eq!(read_le_32(&bundle[0..32]), 0);
    }
}
