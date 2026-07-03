//! Encrypt-at-rest for a webhook signing secret.
//!
//! A webhook secret is unlike an api key: the *server* must read it back on every
//! delivery to recompute the HMAC, so a one-way hash cannot serve. The secret is
//! instead sealed under a 32-byte symmetric data key with XChaCha20-Poly1305, and
//! only its SHA-256 fingerprint is shown after the create/rotate response.
//!
//! # The data key and its id
//!
//! [`SecretWrap`] holds one data key and the `wrap_key_id` that names it. Every
//! `webhook_endpoint` row records the `wrap_key_id` its `secret_enc` was sealed
//! under, so a key rotation can re-encrypt the stored secrets row by row and stay
//! resumable. The data key itself never reaches the database: it is supplied to
//! the running process out of band (minted at instance bootstrap and held in the
//! operator keyring envelope), and this type is the in-memory accessor the
//! registration and delivery paths share.
//!
//! # Wire layout of `secret_enc`
//!
//! The stored ciphertext is `nonce (24 bytes) || AEAD_ciphertext_and_tag`. The
//! random nonce travels with the ciphertext so a decrypt needs only the column
//! bytes and the data key. A fresh nonce is drawn per seal, so re-sealing the same
//! secret never produces the same bytes.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// The length of the symmetric data key (256 bits).
pub const DATA_KEY_LEN: usize = 32;

/// The XChaCha20-Poly1305 nonce length (192 bits).
const NONCE_LEN: usize = 24;

/// A symmetric data key that seals webhook signing secrets at rest, plus the id
/// that names it on each sealed row.
///
/// The key bytes are wiped on drop. The accessor seals a plaintext secret to the
/// `secret_enc` column form and opens it back at delivery time; it never exposes
/// the raw key.
pub struct SecretWrap {
    /// The id recorded on every row this key sealed, so a rotation re-encrypts
    /// row by row keyed on it.
    wrap_key_id: String,
    /// The data key, zeroized on drop.
    data_key: Zeroizing<[u8; DATA_KEY_LEN]>,
}

impl std::fmt::Debug for SecretWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key material; only the id is safe to print.
        f.debug_struct("SecretWrap")
            .field("wrap_key_id", &self.wrap_key_id)
            .field("data_key", &"<redacted>")
            .finish()
    }
}

impl SecretWrap {
    /// Build a wrap accessor over a 32-byte data key and the id that names it.
    #[must_use]
    pub fn new(wrap_key_id: impl Into<String>, data_key: [u8; DATA_KEY_LEN]) -> Self {
        Self {
            wrap_key_id: wrap_key_id.into(),
            data_key: Zeroizing::new(data_key),
        }
    }

    /// The id recorded on a row sealed by this key.
    #[must_use]
    pub fn wrap_key_id(&self) -> &str {
        &self.wrap_key_id
    }

    /// Seal a plaintext secret to the `secret_enc` column form
    /// (`nonce || ciphertext_and_tag`).
    ///
    /// Draws a fresh random nonce per call, so two seals of the same secret never
    /// collide. Returns an error only if the AEAD primitive itself fails, which
    /// for a correctly sized key and nonce does not happen in practice.
    pub fn seal(&self, secret: &str) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new(self.data_key.as_ref().into());
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| Error::Config(format!("webhook secret nonce entropy failed: {e}")))?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, secret.as_bytes())
            .map_err(|_| Error::Config("webhook secret seal failed".into()))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a `secret_enc` column value back to the plaintext secret.
    ///
    /// The plaintext is returned in a [`Zeroizing`] buffer so a caller that signs
    /// with it wipes it on drop. Fails if the bytes are too short to carry a nonce
    /// or if authentication does not verify (a wrong data key or tampered bytes).
    pub fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < NONCE_LEN {
            return Err(Error::Config(
                "webhook secret ciphertext is too short to carry a nonce".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let cipher = XChaCha20Poly1305::new(self.data_key.as_ref().into());
        let nonce = XNonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            Error::Config("webhook secret open failed (bad key or tampered)".into())
        })?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// The one-way fingerprint of a secret shown in listings (never the secret).
///
/// `sha256(secret)`; identical to the `secret_fp` column. A receiver-side audit
/// can confirm which secret signed a delivery without the server ever returning
/// the secret itself.
#[must_use]
pub fn fingerprint(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap() -> SecretWrap {
        SecretWrap::new("wk_test_1", [7u8; DATA_KEY_LEN])
    }

    #[test]
    fn seal_then_open_round_trips_the_secret() {
        let w = wrap();
        let secret = "whsec_round_trip_0123456789";
        let sealed = w.seal(secret).expect("seal");
        let opened = w.open(&sealed).expect("open");
        assert_eq!(opened.as_slice(), secret.as_bytes());
    }

    #[test]
    fn sealed_bytes_never_contain_the_plaintext() {
        let w = wrap();
        let secret = "whsec_secret_material_should_not_leak";
        let sealed = w.seal(secret).expect("seal");
        // The ciphertext must not embed the plaintext bytes anywhere.
        assert!(
            !contains_subslice(&sealed, secret.as_bytes()),
            "sealed bytes must not carry the plaintext secret"
        );
    }

    #[test]
    fn two_seals_of_the_same_secret_differ() {
        let w = wrap();
        let a = w.seal("whsec_same").expect("seal a");
        let b = w.seal("whsec_same").expect("seal b");
        // A fresh nonce per seal means the stored bytes never repeat, even for an
        // identical secret.
        assert_ne!(a, b, "a fresh nonce makes each seal distinct");
        // Both still open to the same plaintext.
        assert_eq!(w.open(&a).unwrap().as_slice(), b"whsec_same");
        assert_eq!(w.open(&b).unwrap().as_slice(), b"whsec_same");
    }

    #[test]
    fn open_under_a_different_key_fails() {
        let secret = "whsec_cross_key";
        let sealed = wrap().seal(secret).expect("seal");
        let other = SecretWrap::new("wk_test_2", [9u8; DATA_KEY_LEN]);
        assert!(
            other.open(&sealed).is_err(),
            "a different data key must not open the ciphertext"
        );
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let w = wrap();
        let mut sealed = w.seal("whsec_tamper").expect("seal");
        // Flip a byte in the ciphertext body (past the nonce) so authentication
        // fails.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(w.open(&sealed).is_err(), "a tampered tag must not open");
    }

    #[test]
    fn open_rejects_truncated_input() {
        let w = wrap();
        assert!(w.open(&[0u8; 4]).is_err(), "too short to hold a nonce");
    }

    #[test]
    fn fingerprint_is_sha256_and_hides_the_secret() {
        let fp = fingerprint("whsec_fp");
        assert_eq!(fp.len(), 32, "sha256 is 32 bytes");
        assert_eq!(fp, Sha256::digest(b"whsec_fp").to_vec());
        // Two different secrets fingerprint differently.
        assert_ne!(fingerprint("a"), fingerprint("b"));
    }

    /// A naive subslice search for the leak assertion.
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
