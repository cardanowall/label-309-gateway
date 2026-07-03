//! Pure-Rust ANS-104 data items: construction, signing, and verification.
//!
//! This crate implements the [ANS-104] bundled-data-item format used to post
//! content to Arweave. It builds a data item from an owner key, optional target
//! and anchor, an ordered tag list, and a payload; computes the recursive
//! deep-hash that the format signs; signs that hash with RSA-PSS (the `arweave`
//! signature type, a 4096-bit RSA key); and verifies an existing item by
//! recomputing the hash and checking the signature against the embedded owner.
//!
//! Nothing here touches the network: the crate produces and checks canonical
//! data-item bytes and leaves submission to the caller.
//!
//! # Building and signing
//!
//! ```no_run
//! # use ans104::{ArweaveJwkSigner, DataItemBuilder, verify};
//! # fn demo(jwk_json: &str) -> Result<(), ans104::Ans104Error> {
//! let signer = ArweaveJwkSigner::from_jwk_json(jwk_json)?;
//! let signed = DataItemBuilder::new(b"hello".to_vec())
//!     .tag("Content-Type", "text/plain")
//!     .sign(&signer)?;
//!
//! // `signed.bytes` are the canonical ANS-104 bytes ready for submission.
//! let verified = verify(&signed.bytes)?;
//! assert_eq!(verified.id, signed.id);
//! # Ok(())
//! # }
//! ```
//!
//! # Layout
//!
//! - [`mod@deep_hash`] — the recursive SHA-384 deep-hash over blob/list
//!   structures, including a streaming variant for a large payload leaf.
//! - [`tags`] — the Avro tag encoding and its inverse.
//! - [`sig_type`] — the signature-type registry that fixes framing lengths.
//! - [`data_item`] — the builder, the signed item, serialisation, and parsing.
//! - [`bundle`] — framing signed data items into an ANS-104 binary bundle.
//! - [`tx_v2`] — signing an Arweave format-2 base-layer transaction (the envelope
//!   a base-layer-only node accepts for a bundle).
//! - [`signer`] — RSA-PSS signing and the signer trait.
//! - [mod@verify] — signature and id verification.
//! - [`base64url`] — the URL-safe-no-pad base64 Arweave uses for ids and keys.
//! - [`error`] — the shared error type.
//!
//! [ANS-104]: https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md

pub mod base64url;
pub mod bundle;
pub mod data_item;
pub mod deep_hash;
pub mod error;
pub mod sig_type;
pub mod signer;
pub mod tags;
pub mod tx_v2;
pub mod verify;

pub use bundle::{encode_bundle, BundleItem};
pub use data_item::{
    deep_hash_message, reconstruct_prefix, sign_streaming, DataItemBuilder, DataItemView,
    SignedDataItem, SignedEnvelope, UnsignedDataItem, ANCHOR_LEN, TARGET_LEN,
};
pub use deep_hash::{
    deep_hash, deep_hash_blob_reader, deep_hash_list_of, DeepHashItem, DEEP_HASH_LEN,
};
pub use error::Ans104Error;
pub use sig_type::{sig_config, SigConfig, RSA_4096_LEN, SIGNATURE_TYPE_ARWEAVE};
pub use signer::{Ans104Signer, ArweaveJwkSigner, ARWEAVE_PSS_SALT_LEN};
pub use tags::{decode_tags, encode_tags, Tag, MAX_TAG_BYTES};
pub use tx_v2::{
    arweave_address, data_root, reward_for, sign_transfer_tx_v2, sign_tx_v2, SignedTxV2,
};
pub use verify::{verify, verify_view};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_constructor_keeps_name_and_value_bytes() {
        let tag = Tag::new("Content-Type", "application/octet-stream");
        assert_eq!(tag.name, b"Content-Type");
        assert_eq!(tag.value, b"application/octet-stream");
    }

    #[test]
    fn deep_hash_item_variants_construct() {
        let leaf = DeepHashItem::blob(vec![1, 2, 3]);
        let node = DeepHashItem::list(vec![leaf, DeepHashItem::blob(vec![])]);
        // The list node holds exactly the two children we put in it.
        match node {
            DeepHashItem::List(items) => assert_eq!(items.len(), 2),
            DeepHashItem::Blob(_) => panic!("expected a list node"),
        }
    }

    #[test]
    fn arweave_signature_type_constants_are_fixed() {
        // These are wire constants other implementations agree on; pin them so
        // an accidental edit is caught.
        assert_eq!(SIGNATURE_TYPE_ARWEAVE, 1);
        assert_eq!(RSA_4096_LEN, 512);
        assert_eq!(MAX_TAG_BYTES, 4096);
    }
}
