//! Error type shared across data-item construction, signing, and verification.

use thiserror::Error;

/// Failure modes of ANS-104 data-item operations. Each variant is a distinct,
/// testable outcome; no operation panics on malformed input.
#[derive(Debug, Error)]
pub enum Ans104Error {
    /// The owner, signature, target, or anchor field was not the length the
    /// declared signature type requires.
    #[error("field {field} has length {actual}, expected {expected}")]
    FieldLength {
        /// Name of the malformed field.
        field: &'static str,
        /// Length supplied.
        actual: usize,
        /// Length the signature type (or fixed format) mandates.
        expected: usize,
    },
    /// The serialised tag block exceeded the maximum size, the count and the
    /// parsed entries disagreed, or a tag block was otherwise malformed.
    #[error("tag encoding rejected: {0}")]
    InvalidTags(&'static str),
    /// The data item's bytes were truncated or structurally malformed.
    #[error("malformed data item: {0}")]
    Malformed(&'static str),
    /// The signature-type field named a type this crate does not implement for
    /// the attempted operation (signing supports only the `arweave` type;
    /// verification supports every type with a registered scheme).
    #[error("unsupported signature type: {0}")]
    UnsupportedSignatureType(u16),
    /// The RSA-PSS signature did not verify against the embedded owner key, or
    /// the recomputed id did not match the supplied id.
    #[error("signature verification failed")]
    BadSignature,
    /// A supplied JSON Web Key could not be parsed into an RSA private key.
    #[error("invalid jwk: {0}")]
    InvalidJwk(&'static str),
    /// An underlying RSA operation (key construction, sign, or verify) failed.
    #[error("rsa error: {0}")]
    Rsa(String),
    /// Reading the payload from a streaming source failed, or the source yielded
    /// a different number of bytes than the caller declared. The declared length
    /// is committed into the signed deep-hash before the bytes are read, so a
    /// short or long read would otherwise sign a digest over the wrong length.
    #[error("payload stream error: {0}")]
    Io(String),
}
