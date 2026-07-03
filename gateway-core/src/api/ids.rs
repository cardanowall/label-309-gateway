//! The wire id codec.
//!
//! On the wire a PoE record is identified by `poe_<crockford-base32-of-uuid>`:
//! the `poe_` prefix plus the 16 raw UUID bytes encoded in Crockford base32
//! (lowercase, no padding) — the same alphabet the published SDK ids use. The
//! durable `cw_core.poe_record.id` stays a UUID; this codec maps between the two
//! at the route boundary so the wire never exposes the raw UUID and the database
//! never stores the prefixed form.
//!
//! 16 bytes encode to exactly 26 Crockford base32 characters, so a valid wire id
//! is always `poe_` followed by 26 lowercase base32 characters.

use data_encoding::Encoding;
use uuid::Uuid;

/// The wire prefix a PoE record id carries.
pub const POE_ID_PREFIX: &str = "poe_";

/// The wire prefix an account id carries (the owner-only `account_id` field).
pub const ACCOUNT_ID_PREFIX: &str = "acct_";

/// The number of base32 characters 16 UUID bytes encode to.
const ENCODED_LEN: usize = 26;

/// Build the Crockford base32 alphabet (lowercase, no padding).
///
/// `data_encoding::BASE32_NOPAD` is the RFC 4648 alphabet; Crockford uses a
/// different alphabet (no i, l, o, u) which is what the published SDK ids use, so
/// the encoding is specified explicitly rather than relying on a constant.
fn crockford() -> Encoding {
    // Crockford base32 alphabet, lowercase. 32 symbols: digits 0-9 then the
    // consonant-biased letter set that omits i, l, o, u.
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("0123456789abcdefghjkmnpqrstvwxyz");
    spec.encoding().expect("the Crockford base32 spec is valid")
}

/// Encode a UUID to its wire id (`poe_<26-char-crockford-base32>`).
#[must_use]
pub fn encode_poe_id(id: Uuid) -> String {
    let body = crockford().encode(id.as_bytes());
    format!("{POE_ID_PREFIX}{body}")
}

/// Decode a wire id back to its UUID.
///
/// Returns `None` when the id does not carry the `poe_` prefix, is not the
/// expected length, or does not decode to exactly 16 bytes — so a malformed
/// path segment maps to a 400 rather than a panic.
#[must_use]
pub fn decode_poe_id(wire: &str) -> Option<Uuid> {
    decode_prefixed(wire, POE_ID_PREFIX)
}

/// Encode an account UUID to its wire id (`acct_<26-char-crockford-base32>`).
///
/// The owner-only `account_id` field uses the same Crockford base32 codec as the
/// PoE id, with the `acct_` prefix, so the wire never exposes the raw account
/// UUID and the database never stores the prefixed form.
#[must_use]
pub fn encode_account_id(id: Uuid) -> String {
    let body = crockford().encode(id.as_bytes());
    format!("{ACCOUNT_ID_PREFIX}{body}")
}

/// Decode an account wire id back to its UUID.
#[must_use]
pub fn decode_account_id(wire: &str) -> Option<Uuid> {
    decode_prefixed(wire, ACCOUNT_ID_PREFIX)
}

/// Shared decode: strip a prefix and decode the 26-char Crockford body to a UUID.
fn decode_prefixed(wire: &str, prefix: &str) -> Option<Uuid> {
    let body = wire.strip_prefix(prefix)?;
    if body.len() != ENCODED_LEN {
        return None;
    }
    let bytes = crockford().decode(body.as_bytes()).ok()?;
    let arr: [u8; 16] = bytes.try_into().ok()?;
    Some(Uuid::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_uuid_through_the_wire_id() {
        let id = Uuid::now_v7();
        let wire = encode_poe_id(id);
        assert!(wire.starts_with("poe_"));
        assert_eq!(wire.len(), POE_ID_PREFIX.len() + ENCODED_LEN);
        assert_eq!(decode_poe_id(&wire), Some(id));
    }

    #[test]
    fn encoding_is_lowercase_crockford_with_no_padding() {
        let id = Uuid::from_bytes([0xff; 16]);
        let wire = encode_poe_id(id);
        let body = wire.strip_prefix("poe_").unwrap();
        assert!(!body.contains('='), "no padding");
        assert!(
            body.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "lowercase crockford only"
        );
        // Crockford omits i, l, o, u from its alphabet.
        assert!(
            !body.contains('i')
                && !body.contains('l')
                && !body.contains('o')
                && !body.contains('u')
        );
    }

    #[test]
    fn rejects_a_missing_prefix() {
        let id = Uuid::now_v7();
        let body = crockford().encode(id.as_bytes());
        assert_eq!(decode_poe_id(&body), None);
    }

    #[test]
    fn rejects_a_wrong_length_body() {
        assert_eq!(decode_poe_id("poe_abc"), None);
        assert_eq!(decode_poe_id("poe_"), None);
    }

    #[test]
    fn rejects_a_non_base32_body() {
        // 'i' is not in the Crockford alphabet.
        let bad = format!("poe_{}", "i".repeat(ENCODED_LEN));
        assert_eq!(decode_poe_id(&bad), None);
    }

    #[test]
    fn account_id_round_trips_with_its_own_prefix() {
        let id = Uuid::now_v7();
        let wire = encode_account_id(id);
        assert!(wire.starts_with("acct_"));
        assert_eq!(decode_account_id(&wire), Some(id));
        // The two id spaces do not cross-decode: a poe id is not an account id.
        assert_eq!(decode_account_id(&encode_poe_id(id)), None);
        assert_eq!(decode_poe_id(&wire), None);
    }
}
