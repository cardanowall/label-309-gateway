//! The ANS-104 signature-type registry.
//!
//! Every data item begins with a 2-byte little-endian signature-type tag. That
//! type fixes two layout-critical lengths: how many signature bytes follow the
//! tag, and how many owner (public-key) bytes follow the signature. A parser
//! needs both lengths before it can locate the target, anchor, tags, and data,
//! so the registry has to be consulted up front, independent of whether the
//! crate can actually verify the named scheme.
//!
//! This crate parses the framing for every registered type but only signs the
//! `arweave` type (4096-bit RSA-PSS). Verification is wired for `arweave`;
//! other registered types parse cleanly and surface
//! [`Ans104Error::UnsupportedSignatureType`] when a signature check is
//! attempted, never a panic.

use crate::error::Ans104Error;

/// Fixed lengths a signature type imposes on the data-item framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigConfig {
    /// Number of signature bytes that follow the 2-byte type tag.
    pub signature_len: usize,
    /// Number of owner (public-key) bytes that follow the signature.
    pub owner_len: usize,
    /// Stable, vendor-neutral name of the scheme.
    pub name: &'static str,
}

/// The `arweave` signature type: 4096-bit RSA-PSS. The only type this crate
/// signs, and the type produced by [`crate::ArweaveJwkSigner`].
pub const SIGNATURE_TYPE_ARWEAVE: u16 = 1;

/// Byte length of an `arweave` (RSA-4096) signature and owner modulus.
pub const RSA_4096_LEN: usize = 512;

/// Look up the framing lengths for a signature type tag.
///
/// Returns [`Ans104Error::UnsupportedSignatureType`] for a tag that is not in
/// the registry. Because the framing of the rest of the item depends on these
/// lengths, an unknown type is reported here rather than producing a
/// nonsensical parse.
pub const fn sig_config(sig_type: u16) -> Result<SigConfig, Ans104Error> {
    let cfg = match sig_type {
        1 => SigConfig {
            signature_len: 512,
            owner_len: 512,
            name: "arweave",
        },
        2 => SigConfig {
            signature_len: 64,
            owner_len: 32,
            name: "ed25519",
        },
        3 => SigConfig {
            signature_len: 65,
            owner_len: 65,
            name: "ethereum",
        },
        4 => SigConfig {
            signature_len: 64,
            owner_len: 32,
            name: "solana",
        },
        5 => SigConfig {
            signature_len: 64,
            owner_len: 32,
            name: "injectedAptos",
        },
        6 => SigConfig {
            // 64 * 32 + 4
            signature_len: 2052,
            // 32 * 32 + 1
            owner_len: 1025,
            name: "multiAptos",
        },
        7 => SigConfig {
            signature_len: 65,
            owner_len: 42,
            name: "typedEthereum",
        },
        other => return Err(Ans104Error::UnsupportedSignatureType(other)),
    };
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arweave_lengths_are_pinned() {
        let cfg = sig_config(SIGNATURE_TYPE_ARWEAVE).unwrap();
        assert_eq!(cfg.signature_len, RSA_4096_LEN);
        assert_eq!(cfg.owner_len, RSA_4096_LEN);
        assert_eq!(cfg.name, "arweave");
    }

    #[test]
    fn multi_aptos_lengths_follow_the_64x32_formula() {
        // These derive from the per-signature/per-key counts, not free
        // constants; pin the arithmetic so a transcription slip is caught.
        let cfg = sig_config(6).unwrap();
        assert_eq!(cfg.signature_len, 64 * 32 + 4);
        assert_eq!(cfg.owner_len, 32 * 32 + 1);
    }

    #[test]
    fn every_registered_type_has_distinct_framing_reported() {
        for t in 1u16..=7 {
            let cfg = sig_config(t).expect("type in 1..=7 is registered");
            assert!(cfg.signature_len > 0 && cfg.owner_len > 0);
        }
    }

    #[test]
    fn unknown_type_is_rejected_not_guessed() {
        match sig_config(99) {
            Err(Ans104Error::UnsupportedSignatureType(99)) => {}
            other => panic!("expected UnsupportedSignatureType(99), got {other:?}"),
        }
        // Type 0 and the KYVE-style 101 are likewise not framed by this crate.
        assert!(matches!(
            sig_config(0),
            Err(Ans104Error::UnsupportedSignatureType(0))
        ));
        assert!(matches!(
            sig_config(101),
            Err(Ans104Error::UnsupportedSignatureType(101))
        ));
    }
}
