//! ANS-104 tag encoding.
//!
//! Data-item tags are an ordered list of name/value byte-string pairs encoded
//! with Apache Avro's binary array framing: a zig-zag varint block count, each
//! entry a length-prefixed name then value, terminated by a zero block. The
//! encoding is deterministic given the tag order, so two builders that pass the
//! same tags in the same order produce identical bytes.
//!
//! Two edge rules are load-bearing for byte-compatibility:
//!
//! - An **empty** tag list serialises to a zero-length buffer, not a lone
//!   terminating `0` block. Producers that emit the `0` block would not match.
//! - The serialised block must not exceed [`MAX_TAG_BYTES`]. The limit is
//!   checked on encode (so a too-large list fails fast) and on decode (so a
//!   hostile item cannot force an unbounded read).

use crate::error::Ans104Error;

/// A single name/value tag. Names and values are arbitrary byte strings,
/// bounded only by the overall serialised-block size limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    /// Tag name bytes.
    pub name: Vec<u8>,
    /// Tag value bytes.
    pub value: Vec<u8>,
}

impl Tag {
    /// Construct a tag from string-like name and value.
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Maximum size, in bytes, of the serialised tag block. A data item whose tag
/// block exceeds this is rejected on both create and verify.
pub const MAX_TAG_BYTES: usize = 4096;

/// Encode a signed Avro long as a zig-zag varint, appending to `out`.
fn write_varint(out: &mut Vec<u8>, value: i64) {
    // Zig-zag maps small-magnitude signed values to small unsigned ones.
    let mut zigzag = ((value << 1) ^ (value >> 63)) as u64;
    loop {
        let mut byte = (zigzag & 0x7f) as u8;
        zigzag >>= 7;
        if zigzag != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if zigzag == 0 {
            break;
        }
    }
}

/// Read a zig-zag varint from `buf` at `pos`, advancing `pos`. Returns the
/// decoded signed value.
fn read_varint(buf: &[u8], pos: &mut usize) -> Result<i64, Ans104Error> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if shift >= 64 {
            return Err(Ans104Error::InvalidTags("varint too long"));
        }
        let byte = *buf
            .get(*pos)
            .ok_or(Ans104Error::InvalidTags("truncated varint"))?;
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    // Reverse the zig-zag mapping.
    Ok(((result >> 1) as i64) ^ -((result & 1) as i64))
}

/// Encode an ordered tag list to its Avro binary representation.
///
/// Returns [`Ans104Error::InvalidTags`] when the serialised block would exceed
/// [`MAX_TAG_BYTES`]. An empty list returns an empty buffer (no terminating
/// block), matching the on-the-wire convention.
pub fn encode_tags(tags: &[Tag]) -> Result<Vec<u8>, Ans104Error> {
    if tags.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    // One block holding every entry: a positive count, then the pairs.
    write_varint(&mut out, tags.len() as i64);
    for tag in tags {
        write_varint(&mut out, tag.name.len() as i64);
        out.extend_from_slice(&tag.name);
        write_varint(&mut out, tag.value.len() as i64);
        out.extend_from_slice(&tag.value);
    }
    // Terminating zero block.
    write_varint(&mut out, 0);

    if out.len() > MAX_TAG_BYTES {
        return Err(Ans104Error::InvalidTags(
            "serialised tags exceed 4096 bytes",
        ));
    }
    Ok(out)
}

/// Decode an Avro tag block back into the ordered tag list, the inverse of
/// [`encode_tags`].
///
/// A zero-length buffer decodes to an empty list. Avro permits a block count to
/// be negative, in which case it is followed by a byte-size hint that this
/// decoder reads and discards; both encodings round-trip to the same list.
pub fn decode_tags(bytes: &[u8]) -> Result<Vec<Tag>, Ans104Error> {
    if bytes.len() > MAX_TAG_BYTES {
        return Err(Ans104Error::InvalidTags(
            "serialised tags exceed 4096 bytes",
        ));
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let mut pos = 0usize;
    let mut tags = Vec::new();
    loop {
        let mut count = read_varint(bytes, &mut pos)?;
        if count == 0 {
            break;
        }
        if count < 0 {
            // Negative count: magnitude is the entry count, followed by a
            // block byte-size hint we do not need. `checked_neg` refuses
            // i64::MIN, whose magnitude has no i64 representation — only a
            // crafted varint encodes it, never a real producer.
            count = count
                .checked_neg()
                .ok_or(Ans104Error::InvalidTags("block count overflow"))?;
            let _size = read_varint(bytes, &mut pos)?;
        }
        // Every entry consumes at least two bytes (two zero-length string
        // varints), so a count beyond half the remaining buffer is fabricated.
        // Reject it up front instead of iterating a hostile count until a
        // truncated read happens to stop it.
        let max_entries = (bytes.len() - pos) / 2;
        if count as u64 > max_entries as u64 {
            return Err(Ans104Error::InvalidTags(
                "block count exceeds the tag block",
            ));
        }
        for _ in 0..count {
            let name = read_string(bytes, &mut pos)?;
            let value = read_string(bytes, &mut pos)?;
            tags.push(Tag { name, value });
        }
    }
    if pos != bytes.len() {
        return Err(Ans104Error::InvalidTags("trailing bytes after tag block"));
    }
    Ok(tags)
}

fn read_string(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, Ans104Error> {
    let len = read_varint(buf, pos)?;
    if len < 0 {
        return Err(Ans104Error::InvalidTags("negative string length"));
    }
    let len = len as usize;
    let end = pos
        .checked_add(len)
        .ok_or(Ans104Error::InvalidTags("string length overflow"))?;
    if end > buf.len() {
        return Err(Ans104Error::InvalidTags("string runs past tag block"));
    }
    let slice = buf[*pos..end].to_vec();
    *pos = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_serialises_to_zero_length() {
        let encoded = encode_tags(&[]).unwrap();
        assert!(encoded.is_empty());
        // And decodes back to the empty list, not to a one-block artefact.
        assert_eq!(decode_tags(&encoded).unwrap(), Vec::<Tag>::new());
    }

    #[test]
    fn single_tag_round_trips_to_the_same_bytes_and_list() {
        let tags = vec![Tag::new("Content-Type", "application/octet-stream")];
        let encoded = encode_tags(&tags).unwrap();
        // First varint is the zig-zag of the count (1 -> 2).
        assert_eq!(encoded[0], 2);
        // Last varint is the terminating zero block.
        assert_eq!(*encoded.last().unwrap(), 0);
        assert_eq!(decode_tags(&encoded).unwrap(), tags);
    }

    #[test]
    fn many_tags_round_trip_in_order() {
        let tags: Vec<Tag> = (0..10)
            .map(|i| Tag::new(format!("name-{i}"), format!("value-{i}")))
            .collect();
        let encoded = encode_tags(&tags).unwrap();
        assert_eq!(decode_tags(&encoded).unwrap(), tags);
    }

    #[test]
    fn unicode_names_and_values_survive_round_trip() {
        // Multi-byte UTF-8 in both name and value, including an emoji that is a
        // surrogate pair in UTF-16. The byte length, not the char count, drives
        // the length prefix.
        let tags = vec![
            Tag::new("作者", "中本聡"),
            Tag::new("emoji", "проверка 🔐 ok"),
        ];
        let encoded = encode_tags(&tags).unwrap();
        let decoded = decode_tags(&encoded).unwrap();
        assert_eq!(decoded, tags);
        // The value bytes are the raw UTF-8, not an escaped form.
        assert_eq!(decoded[0].value, "中本聡".as_bytes());
    }

    #[test]
    fn empty_name_and_value_are_permitted() {
        let tags = vec![Tag::new("", ""), Tag::new("x", "")];
        let encoded = encode_tags(&tags).unwrap();
        assert_eq!(decode_tags(&encoded).unwrap(), tags);
    }

    #[test]
    fn block_at_the_4096_byte_boundary_is_accepted() {
        // Grow a single value until the serialised block is exactly 4096 bytes.
        // Framing overhead for one tag with an empty name: count(1) + name-len
        // varint(1) + value-len varint + value bytes + terminator(1).
        let mut value_len = 4000usize;
        loop {
            let tags = vec![Tag::new("", vec![b'a'; value_len])];
            let encoded = encode_tags(&tags).unwrap();
            match encoded.len().cmp(&MAX_TAG_BYTES) {
                std::cmp::Ordering::Equal => {
                    // Boundary value accepted and round-trips.
                    assert_eq!(decode_tags(&encoded).unwrap(), tags);
                    return;
                }
                std::cmp::Ordering::Less => value_len += 1,
                std::cmp::Ordering::Greater => {
                    panic!("overshot 4096 without landing on it; value_len={value_len}")
                }
            }
        }
    }

    #[test]
    fn block_just_over_4096_bytes_is_rejected_on_encode() {
        // A value large enough that the whole block exceeds 4096 bytes.
        let tags = vec![Tag::new("", vec![b'a'; 4096])];
        match encode_tags(&tags) {
            Err(Ans104Error::InvalidTags(_)) => {}
            other => panic!("expected InvalidTags, got {other:?}"),
        }
    }

    #[test]
    fn oversized_block_is_rejected_on_decode() {
        let too_big = vec![0u8; MAX_TAG_BYTES + 1];
        assert!(matches!(
            decode_tags(&too_big),
            Err(Ans104Error::InvalidTags(_))
        ));
    }

    #[test]
    fn a_crafted_i64_min_block_count_is_rejected_not_overflowed() {
        // The zig-zag varint for i64::MIN (u64::MAX after mapping): nine 0xFF
        // continuation bytes and a final 0x01. Negating its magnitude has no
        // i64 representation, so decode must reject it instead of overflowing.
        let mut crafted = vec![0xFFu8; 9];
        crafted.push(0x01);
        // A byte-size hint and a terminator would follow in a real negative
        // block; the count alone must already be refused.
        crafted.push(0x00);
        crafted.push(0x00);
        assert!(matches!(
            decode_tags(&crafted),
            Err(Ans104Error::InvalidTags(_))
        ));
    }

    #[test]
    fn a_fabricated_huge_block_count_is_rejected_before_iterating() {
        // A positive count of 2^40 entries in a buffer that could hold at most
        // a couple: rejected up front by the two-bytes-per-entry bound.
        let mut crafted = Vec::new();
        write_varint(&mut crafted, 1i64 << 40);
        crafted.push(0x00);
        assert!(matches!(
            decode_tags(&crafted),
            Err(Ans104Error::InvalidTags(_))
        ));
    }

    #[test]
    fn truncated_block_is_rejected_not_panicked() {
        let tags = vec![Tag::new("name", "value")];
        let mut encoded = encode_tags(&tags).unwrap();
        // Drop the terminator and part of the last string.
        encoded.truncate(encoded.len() - 3);
        assert!(matches!(
            decode_tags(&encoded),
            Err(Ans104Error::InvalidTags(_))
        ));
    }
}
