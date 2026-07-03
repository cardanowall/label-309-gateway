//! URL-safe, no-padding base64 — the encoding Arweave uses for ids, owners,
//! targets, anchors, and JWK fields.
//!
//! Encoding uses the URL-safe alphabet (`-`/`_` for the last two symbols) and
//! omits trailing `=` padding. Decoding accepts that same form.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::Ans104Error;

/// Encode bytes as URL-safe-no-pad base64.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode URL-safe-no-pad base64 into bytes.
///
/// Returns [`Ans104Error::InvalidJwk`] when the input is not valid base64url;
/// this helper is used to read JWK fields, where a decode failure means the key
/// material is malformed.
pub fn decode(text: &str) -> Result<Vec<u8>, Ans104Error> {
    URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .map_err(|_| Ans104Error::InvalidJwk("field is not valid base64url"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_bytes() {
        let data = (0u8..=255).collect::<Vec<u8>>();
        let text = encode(&data);
        assert_eq!(decode(&text).unwrap(), data);
    }

    #[test]
    fn output_has_no_padding_and_url_safe_alphabet() {
        // 0xFB 0xFF 0xFE exercises the symbols that differ from standard base64
        // (`+` -> `-`, `/` -> `_`); the result must carry no `=` padding.
        let text = encode(&[0xfb, 0xff, 0xfe]);
        assert!(!text.contains('='));
        assert!(!text.contains('+'));
        assert!(!text.contains('/'));
        assert_eq!(decode(&text).unwrap(), vec![0xfb, 0xff, 0xfe]);
    }

    #[test]
    fn padded_or_non_url_safe_input_is_rejected() {
        // A trailing '=' is padding the no-pad decoder must refuse.
        assert!(decode("YQ==").is_err());
    }
}
