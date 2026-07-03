//! Signing of ANS-104 data items.
//!
//! A signer supplies three things to the builder: the signature-type tag, the
//! owner (public-key) bytes that go on the wire, and a signature over the
//! deep-hash message. This module defines the [`Ans104Signer`] trait and the
//! [`ArweaveJwkSigner`], which signs the `arweave` type with 4096-bit RSA-PSS.
//!
//! # Salt length
//!
//! Arweave signatures use the maximum PSS salt length: for a 4096-bit modulus
//! (512 bytes) and a SHA-256 digest (32 bytes) that is `512 - 32 - 2 = 478`
//! bytes. This crate fixes the salt length to that value when signing so the
//! produced signatures match other Arweave tooling. Verification accepts any
//! valid salt length, as the salt length is recoverable from the signature.

use num_bigint_dig::ModInverse;
use rand::rngs::OsRng;
use rsa::pss::Pss;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::base64url;
use crate::error::Ans104Error;
use crate::sig_type::{RSA_4096_LEN, SIGNATURE_TYPE_ARWEAVE};

/// PSS salt length for an Arweave (4096-bit modulus, SHA-256 digest) signature:
/// `modulus_bytes - digest_bytes - 2`.
pub const ARWEAVE_PSS_SALT_LEN: usize = RSA_4096_LEN - 32 - 2;

/// A source of ANS-104 signatures. Implementors declare their signature type
/// and owner bytes and produce a signature over the 48-byte deep-hash message.
pub trait Ans104Signer {
    /// The signature-type tag this signer produces.
    fn signature_type(&self) -> u16;

    /// The owner (public-key) bytes to embed in the item.
    fn owner(&self) -> Vec<u8>;

    /// Sign the deep-hash message, returning signature bytes of the length the
    /// signature type mandates.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Ans104Error>;
}

/// An `arweave`-type signer backed by a 4096-bit RSA private key, parsed from a
/// JSON Web Key.
pub struct ArweaveJwkSigner {
    key: RsaPrivateKey,
    owner: Vec<u8>,
}

/// The subset of an RSA JWK this crate reads. Arweave keys are RSA with a public
/// exponent of `AQAB` (65537); the private primes and CRT parameters are present
/// in a full key.
#[derive(Deserialize)]
struct RsaJwk {
    n: String,
    e: String,
    d: String,
    p: String,
    q: String,
}

impl ArweaveJwkSigner {
    /// Parse an Arweave RSA private key from JWK JSON.
    ///
    /// The owner field is the raw decoded bytes of the modulus `n` (512 bytes
    /// for a 4096-bit key). Returns [`Ans104Error::InvalidJwk`] for malformed
    /// JSON or base64url, or a key whose modulus is not 512 bytes.
    ///
    /// Every owned copy of the private components — the JWK text fields and
    /// the byte buffers decoded from them — is held in [`Zeroizing`] so it is
    /// wiped on drop; the constructed [`RsaPrivateKey`] zeroizes its own `d`
    /// and primes on drop (even when construction fails validation). Only the
    /// public `n`/`e` stay in plain buffers.
    pub fn from_jwk_json(json: &str) -> Result<Self, Ans104Error> {
        let RsaJwk { n, e, d, p, q } = serde_json::from_str(json)
            .map_err(|_| Ans104Error::InvalidJwk("not a valid RSA JWK object"))?;
        let (d, p, q) = (Zeroizing::new(d), Zeroizing::new(p), Zeroizing::new(q));

        let n_bytes = base64url::decode(&n)?;
        if n_bytes.len() != RSA_4096_LEN {
            return Err(Ans104Error::FieldLength {
                field: "owner",
                actual: n_bytes.len(),
                expected: RSA_4096_LEN,
            });
        }

        let d_bytes = Zeroizing::new(base64url::decode(&d)?);
        let p_bytes = Zeroizing::new(base64url::decode(&p)?);
        let q_bytes = Zeroizing::new(base64url::decode(&q)?);

        let n = BigUint::from_bytes_be(&n_bytes);
        let e = BigUint::from_bytes_be(&base64url::decode(&e)?);
        let d = BigUint::from_bytes_be(&d_bytes);
        let p = BigUint::from_bytes_be(&p_bytes);
        let q = BigUint::from_bytes_be(&q_bytes);

        let key = RsaPrivateKey::from_components(n, e, d, vec![p, q])
            .map_err(|err| Ans104Error::Rsa(err.to_string()))?;

        Ok(Self {
            key,
            owner: n_bytes,
        })
    }

    /// Construct directly from an in-memory RSA private key, deriving the owner
    /// from the key's modulus. The key must be 4096-bit.
    pub fn from_private_key(key: RsaPrivateKey) -> Result<Self, Ans104Error> {
        let owner = key.n().to_bytes_be();
        if owner.len() != RSA_4096_LEN {
            return Err(Ans104Error::FieldLength {
                field: "owner",
                actual: owner.len(),
                expected: RSA_4096_LEN,
            });
        }
        Ok(Self { key, owner })
    }

    /// Generate a fresh 4096-bit Arweave wallet key from the OS CSPRNG and
    /// return it as full private JWK JSON — the write-side counterpart of
    /// [`Self::from_jwk_json`].
    ///
    /// The JWK carries the complete RFC 7518 private parameter set (`n`, `e`,
    /// `d`, `p`, `q`, `dp`, `dq`, `qi`): this crate's parser reads only the
    /// first five, but ecosystem Arweave tooling (wallets, bundler CLIs,
    /// WebCrypto importers) requires the CRT parameters, so a key generated
    /// here is interchangeable with one any standard wallet produced. The JSON
    /// is returned in a zeroizing buffer; the caller is expected to move it
    /// straight into encrypted storage.
    pub fn generate_jwk_json() -> Result<Zeroizing<String>, Ans104Error> {
        let key = RsaPrivateKey::new(&mut OsRng, RSA_4096_LEN * 8)
            .map_err(|err| Ans104Error::Rsa(err.to_string()))?;
        jwk_json_from_private_key(&key)
    }
}

/// Serialise an RSA private key as full private JWK JSON (base64url, no
/// padding, big-endian, minimal-length — the RFC 7518 encoding).
///
/// The CRT parameters are computed here (`dp = d mod p-1`, `dq = d mod q-1`,
/// `qi = q^-1 mod p`) rather than read from the key's optional precomputed
/// state, so the export never depends on whether the key was precomputed.
///
/// Every private intermediate this function owns — the CRT big integers, the
/// big-endian byte buffers, the base64url text of each private field, and the
/// assembled JSON itself — is held in [`Zeroizing`] so it is wiped on drop.
/// The JSON is assembled by hand into one pre-sized buffer: a `serde_json`
/// value tree would hold the private fields in ordinary allocations it never
/// wipes, and a growing buffer could strand partially written copies behind a
/// reallocation.
fn jwk_json_from_private_key(key: &RsaPrivateKey) -> Result<Zeroizing<String>, Ans104Error> {
    let [p, q] = key.primes() else {
        // A multi-prime key cannot be expressed in the two-prime JWK fields
        // Arweave tooling reads; standard generation always yields two primes.
        return Err(Ans104Error::Rsa(
            "a JWK export requires a two-prime RSA key".to_string(),
        ));
    };
    let one = BigUint::from(1u8);
    let p_minus_one = Zeroizing::new(p - &one);
    let q_minus_one = Zeroizing::new(q - &one);
    let dp = Zeroizing::new(key.d() % &*p_minus_one);
    let dq = Zeroizing::new(key.d() % &*q_minus_one);
    let qi_signed = Zeroizing::new(
        q.mod_inverse(p)
            .ok_or_else(|| Ans104Error::Rsa("computing the CRT coefficient failed".to_string()))?,
    );
    let qi = Zeroizing::new(
        qi_signed
            .to_biguint()
            .ok_or_else(|| Ans104Error::Rsa("computing the CRT coefficient failed".to_string()))?,
    );

    /// base64url of a secret big integer, wiping the intermediate byte buffer.
    fn base64url_secret(value: &BigUint) -> Zeroizing<String> {
        let bytes = Zeroizing::new(value.to_bytes_be());
        Zeroizing::new(base64url::encode(&bytes))
    }

    let n_b64 = base64url::encode(&key.n().to_bytes_be());
    let e_b64 = base64url::encode(&key.e().to_bytes_be());
    let d_b64 = base64url_secret(key.d());
    let p_b64 = base64url_secret(p);
    let q_b64 = base64url_secret(q);
    let dp_b64 = base64url_secret(&dp);
    let dq_b64 = base64url_secret(&dq);
    let qi_b64 = base64url_secret(&qi);

    // base64url text never needs JSON escaping, so plain quoting is exact.
    let fields: [(&str, &str); 9] = [
        ("kty", "RSA"),
        ("n", &n_b64),
        ("e", &e_b64),
        ("d", &d_b64),
        ("p", &p_b64),
        ("q", &q_b64),
        ("dp", &dp_b64),
        ("dq", &dq_b64),
        ("qi", &qi_b64),
    ];
    let capacity = 2 + fields
        .iter()
        .map(|(name, value)| name.len() + value.len() + 6)
        .sum::<usize>();
    let mut json = Zeroizing::new(String::with_capacity(capacity));
    json.push('{');
    for (i, (name, value)) in fields.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push('"');
        json.push_str(name);
        json.push_str("\":\"");
        json.push_str(value);
        json.push('"');
    }
    json.push('}');
    debug_assert!(
        json.len() <= capacity,
        "the pre-sized JWK buffer must never reallocate"
    );
    Ok(json)
}

impl Ans104Signer for ArweaveJwkSigner {
    fn signature_type(&self) -> u16 {
        SIGNATURE_TYPE_ARWEAVE
    }

    fn owner(&self) -> Vec<u8> {
        self.owner.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Ans104Error> {
        // The PSS scheme takes the already-computed message hash. Arweave hashes
        // the 48-byte deep-hash message with SHA-256, then applies PSS with the
        // maximum salt length.
        let digest = Sha256::digest(message);
        let scheme = Pss::new_with_salt::<Sha256>(ARWEAVE_PSS_SALT_LEN);
        self.key
            .sign_with_rng(&mut OsRng, scheme, &digest)
            .map_err(|err| Ans104Error::Rsa(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_length_is_the_arweave_maximum() {
        // 512-byte modulus, 32-byte SHA-256 digest.
        assert_eq!(ARWEAVE_PSS_SALT_LEN, 478);
        assert_eq!(ARWEAVE_PSS_SALT_LEN, RSA_4096_LEN - 32 - 2);
    }

    /// A freshly generated JWK parses back through the read path, carries a
    /// 4096-bit modulus, and the resulting signer produces a signature the
    /// public half verifies. This is the proof the write side (generation)
    /// and the read side (parsing/signing) agree on one JWK format.
    #[test]
    fn generated_jwk_round_trips_and_signs() {
        let jwk = ArweaveJwkSigner::generate_jwk_json().expect("generate a 4096-bit key");
        let signer = ArweaveJwkSigner::from_jwk_json(&jwk).expect("the generated JWK parses");
        assert_eq!(signer.owner().len(), RSA_4096_LEN);

        let message = b"deep-hash message stand-in";
        let signature = signer.sign(message).expect("sign");
        let digest = Sha256::digest(message);
        rsa::RsaPublicKey::from(&signer.key)
            .verify(
                Pss::new_with_salt::<Sha256>(ARWEAVE_PSS_SALT_LEN),
                &digest,
                &signature,
            )
            .expect("the public half verifies the signature");
    }

    /// The exported CRT parameters are arithmetically consistent with the
    /// primes: `qi * q ≡ 1 (mod p)`, `dp = d mod p-1`, `dq = d mod q-1`.
    /// Ecosystem tooling (WebCrypto importers in particular) refuses a private
    /// JWK whose CRT fields are absent or wrong, so this pins the export shape.
    #[test]
    fn generated_jwk_crt_parameters_are_consistent() {
        let jwk = ArweaveJwkSigner::generate_jwk_json().expect("generate a 4096-bit key");
        let value: serde_json::Value = serde_json::from_str(&jwk).expect("the JWK is JSON");
        let field = |name: &str| -> BigUint {
            let text = value[name].as_str().expect("field is a string");
            BigUint::from_bytes_be(&base64url::decode(text).expect("field is base64url"))
        };

        let (d, p, q) = (field("d"), field("p"), field("q"));
        let one = BigUint::from(1u8);
        assert_eq!(field("dp"), &d % (&p - &one));
        assert_eq!(field("dq"), &d % (&q - &one));
        assert_eq!((field("qi") * &q) % &p, one);
        assert_eq!(value["kty"], "RSA");
        assert_eq!(value["e"], "AQAB");
    }
}
