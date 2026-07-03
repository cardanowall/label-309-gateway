//! Verification of ANS-104 data items.
//!
//! Verification is the inverse of signing: parse and structurally validate the
//! bytes, recompute the deep-hash of the signed fields, rebuild the owner's RSA
//! public key from the embedded modulus, and check the RSA-PSS/SHA-256
//! signature. The id is independently recomputed as `SHA-256(signature)`, so a
//! verifier never trusts a supplied id.
//!
//! Only the `arweave` signature type carries a verification scheme here; an
//! item whose type tag names a registered-but-unimplemented scheme parses
//! successfully and then surfaces
//! [`Ans104Error::UnsupportedSignatureType`].
//!
//! # Salt length
//!
//! The signer uses the maximum PSS salt length, but a conforming verifier must
//! accept a signature made with any valid salt length, because the length is
//! recoverable from the encoded message. The underlying RSA library verifies a
//! single, fixed salt length per call, so this module first recovers the salt
//! length structurally from the encoded message (the way a "salt length auto"
//! verifier does) and then performs the constant-salt check.

use rsa::hazmat::rsa_encrypt;
use rsa::pss::Pss;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::data_item::{deep_hash_message, DataItemView};
use crate::error::Ans104Error;
use crate::sig_type::SIGNATURE_TYPE_ARWEAVE;

/// The RSA public exponent every Arweave key uses (`AQAB` in base64url is
/// 65537).
const RSA_PUBLIC_EXPONENT: u64 = 65_537;

/// SHA-256 digest width in bytes.
const SHA256_LEN: usize = 32;

/// Parse and fully verify a serialised data item.
///
/// On success returns the validated [`DataItemView`] (its `id` is the
/// recomputed `SHA-256(signature)`). Returns [`Ans104Error::BadSignature`] when
/// the signature does not verify, [`Ans104Error::UnsupportedSignatureType`]
/// when the item's scheme has no verifier here, or another [`Ans104Error`] when
/// the bytes are structurally invalid.
pub fn verify(bytes: &[u8]) -> Result<DataItemView, Ans104Error> {
    let view = DataItemView::parse(bytes)?;
    verify_view(&view)?;
    Ok(view)
}

/// Verify an already-parsed view: recompute the deep-hash and check the
/// signature against the embedded owner.
pub fn verify_view(view: &DataItemView) -> Result<(), Ans104Error> {
    match view.signature_type {
        SIGNATURE_TYPE_ARWEAVE => verify_arweave(view),
        other => Err(Ans104Error::UnsupportedSignatureType(other)),
    }
}

fn verify_arweave(view: &DataItemView) -> Result<(), Ans104Error> {
    // The owner is the raw RSA modulus; the exponent is the fixed Arweave value.
    let n = BigUint::from_bytes_be(&view.owner);
    let e = BigUint::from(RSA_PUBLIC_EXPONENT);
    let public_key = RsaPublicKey::new(n, e).map_err(|err| Ans104Error::Rsa(err.to_string()))?;

    let message = deep_hash_message(&view.unsigned())?;
    let digest = Sha256::digest(message);

    let salt_len = recover_pss_salt_len(&public_key, &view.signature, SHA256_LEN)?;
    let scheme = Pss::new_with_salt::<Sha256>(salt_len);
    public_key
        .verify(scheme, &digest, &view.signature)
        .map_err(|_| Ans104Error::BadSignature)?;

    // Re-derive the id from the signature and confirm it matches the view's id
    // (which parse already computed the same way); this guards a caller that
    // hand-constructs a view with a mismatched id.
    let recomputed: [u8; SHA256_LEN] = Sha256::digest(&view.signature).into();
    if recomputed != view.id {
        return Err(Ans104Error::BadSignature);
    }
    Ok(())
}

/// Recover the PSS salt length from an encoded message so verification can
/// accept any salt length, mirroring a "salt length auto" verifier.
///
/// Applies the RSA public operation to recover the encoded message `EM`,
/// unmasks the data block with MGF1, and reads the salt length off the position
/// of the `0x01` separator. The returned length is then handed to the library's
/// constant-salt verifier, which performs the actual cryptographic check, so
/// this routine only *locates* the salt; it never decides validity on its own.
fn recover_pss_salt_len(
    key: &RsaPublicKey,
    signature: &[u8],
    h_len: usize,
) -> Result<usize, Ans104Error> {
    let key_bits = key.n().bits();
    let key_len = key.size();
    if signature.len() != key_len {
        return Err(Ans104Error::FieldLength {
            field: "signature",
            actual: signature.len(),
            expected: key_len,
        });
    }

    // Raw RSA public operation: EM = signature^e mod n.
    let sig_int = BigUint::from_bytes_be(signature);
    if &sig_int >= key.n() {
        return Err(Ans104Error::BadSignature);
    }
    let em_int = rsa_encrypt(key, &sig_int).map_err(|err| Ans104Error::Rsa(err.to_string()))?;

    let em_bits = key_bits - 1;
    let em_len = em_bits.div_ceil(8);
    // Left-pad the recovered integer to the encoded-message length.
    let em_be = em_int.to_bytes_be();
    if em_be.len() > em_len {
        return Err(Ans104Error::BadSignature);
    }
    let mut em = vec![0u8; em_len];
    em[em_len - em_be.len()..].copy_from_slice(&em_be);

    // The encoded message ends in the trailer byte 0xbc.
    if *em.last().unwrap_or(&0) != 0xbc {
        return Err(Ans104Error::BadSignature);
    }
    if em_len < h_len + 2 {
        return Err(Ans104Error::BadSignature);
    }

    let db_len = em_len - h_len - 1;
    let (masked_db, rest) = em.split_at(db_len);
    let h = &rest[..h_len];

    // Unmask DB with MGF1(H).
    let mut db = masked_db.to_vec();
    mgf1_xor_sha256(&mut db, h);

    // Clear the leftmost bits beyond em_bits, per the encoding.
    let leading_bits = 8 * em_len - em_bits;
    db[0] &= 0xff >> leading_bits;

    // Find the 0x01 separator: leading bytes must be zero, then a single 0x01.
    let sep = db
        .iter()
        .position(|&b| b != 0)
        .ok_or(Ans104Error::BadSignature)?;
    if db[sep] != 0x01 {
        return Err(Ans104Error::BadSignature);
    }
    // Salt is everything after the separator.
    Ok(db.len() - sep - 1)
}

/// In-place MGF1 mask of `out` using SHA-256 over the seed, matching the mask
/// generation function the PSS encoding uses.
fn mgf1_xor_sha256(out: &mut [u8], seed: &[u8]) {
    let mut counter: u32 = 0;
    let mut offset = 0;
    while offset < out.len() {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let block = hasher.finalize();
        for (o, b) in out[offset..].iter_mut().zip(block.iter()) {
            *o ^= b;
        }
        offset += block.len();
        counter += 1;
    }
}
