//! End-to-end behaviour of the data-item builder, serialiser, parser, signer,
//! and verifier.
//!
//! These tests assert on bytes, parsed field values, ids, and error variants,
//! not on display strings. They sign with the fixture key so they do not pay
//! for a fresh 4096-bit key generation on every run.

use std::path::PathBuf;
use std::sync::OnceLock;

use ans104::{
    verify, verify_view, Ans104Error, Ans104Signer, ArweaveJwkSigner, DataItemBuilder,
    DataItemView, SignedDataItem, Tag, UnsignedDataItem,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// One fixture-backed signer for the whole test binary. Parsing the JWK is
/// cheap; keeping a single instance avoids repeating it per test.
fn signer() -> &'static ArweaveJwkSigner {
    static SIGNER: OnceLock<ArweaveJwkSigner> = OnceLock::new();
    SIGNER.get_or_init(|| {
        let text = std::fs::read_to_string(fixtures_dir().join("arbundles-reference.json"))
            .expect("read fixture");
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let jwk_json = serde_json::to_string(&v["jwk"]).unwrap();
        ArweaveJwkSigner::from_jwk_json(&jwk_json).expect("parse fixture jwk")
    })
}

/// Helper: sign an item with the given target/anchor/tags and return both the
/// signed item and its re-parsed view.
fn sign_and_parse(
    data: Vec<u8>,
    target: Option<[u8; 32]>,
    anchor: Option<[u8; 32]>,
    tags: &[Tag],
) -> (SignedDataItem, DataItemView) {
    let mut builder = DataItemBuilder::new(data);
    for t in tags {
        builder = builder.push_tag(t.clone());
    }
    if let Some(t) = target {
        builder = builder.target(t).unwrap();
    }
    if let Some(a) = anchor {
        builder = builder.anchor(a).unwrap();
    }
    let signed = builder.sign(signer()).expect("sign");
    let view = SignedDataItem::parse(&signed.bytes).expect("parse");
    (signed, view)
}

#[test]
fn parse_round_trips_every_signed_field() {
    let tags = vec![
        Tag::new("Content-Type", "application/json"),
        Tag::new("App-Name", "label-309-gateway"),
    ];
    let (signed, view) = sign_and_parse(
        b"{\"k\":1}".to_vec(),
        Some([0x11; 32]),
        Some([0x22; 32]),
        &tags,
    );

    assert_eq!(view.signature_type, 1);
    assert_eq!(view.owner, signer().owner());
    assert_eq!(view.signature, signed.signature);
    assert_eq!(view.target, Some([0x11; 32]));
    assert_eq!(view.anchor, Some([0x22; 32]));
    assert_eq!(view.tags, tags);
    assert_eq!(view.data, b"{\"k\":1}");
    assert_eq!(view.id, signed.id);
    assert_eq!(view.id_b64url(), signed.id_b64url);
}

#[test]
fn unsigned_view_rehashes_to_the_same_message() {
    let (signed, view) = sign_and_parse(b"payload".to_vec(), None, None, &[]);
    // The reconstructed unsigned item must hash to the same message the signer
    // signed; verify proves the signature is over exactly that.
    let from_signed = ans104::deep_hash_message(&signed.item).unwrap();
    let from_view = ans104::deep_hash_message(&view.unsigned()).unwrap();
    assert_eq!(from_signed, from_view);
    verify_view(&view).expect("view verifies");
}

#[test]
fn all_four_target_anchor_presence_combinations_round_trip() {
    let cases = [
        (None, None),
        (Some([0xa0; 32]), None),
        (None, Some([0xb0; 32])),
        (Some([0xa1; 32]), Some([0xb1; 32])),
    ];
    for (target, anchor) in cases {
        let (signed, view) = sign_and_parse(b"combo".to_vec(), target, anchor, &[]);
        assert_eq!(view.target, target, "target combo {target:?}/{anchor:?}");
        assert_eq!(view.anchor, anchor, "anchor combo {target:?}/{anchor:?}");
        // Each combination must still verify: the deep-hash includes an empty
        // blob for an absent field, never an omitted element.
        verify(&signed.bytes).expect("combo verifies");
    }
}

#[test]
fn empty_tags_serialise_to_a_zero_length_block() {
    let (signed, view) = sign_and_parse(b"no tags".to_vec(), None, None, &[]);
    assert!(view.tags.is_empty());

    // Locate the tag header: 2 (type) + 512 (sig) + 512 (owner) + 1 (no target)
    // + 1 (no anchor) = 1028, then 8-byte count and 8-byte byte-length.
    let header = 2 + 512 + 512 + 1 + 1;
    let count = u64::from_le_bytes(signed.bytes[header..header + 8].try_into().unwrap());
    let bytes_len = u64::from_le_bytes(signed.bytes[header + 8..header + 16].try_into().unwrap());
    assert_eq!(count, 0, "tag count is zero");
    assert_eq!(
        bytes_len, 0,
        "empty tag list is a zero-length block, not a 0 frame"
    );
}

#[test]
fn empty_data_payload_is_allowed() {
    let (signed, view) = sign_and_parse(Vec::new(), None, None, &[]);
    assert!(view.data.is_empty());
    verify(&signed.bytes).expect("empty-payload item verifies");
}

#[test]
fn unicode_tags_survive_sign_parse_verify() {
    let tags = vec![
        Tag::new("emoji", "lock 🔐 ok"),
        Tag::new("язык", "русский текст"),
    ];
    let (signed, view) = sign_and_parse(b"u".to_vec(), None, None, &tags);
    assert_eq!(view.tags, tags);
    assert_eq!(view.tags[0].value, "lock 🔐 ok".as_bytes());
    verify(&signed.bytes).expect("unicode-tag item verifies");
}

#[test]
fn maximum_tag_block_at_4096_bytes_signs_and_verifies() {
    // Build a tag whose serialised block is at the 4096-byte limit.
    let mut value_len = 4000usize;
    let tags = loop {
        let candidate = vec![Tag::new("", vec![b'a'; value_len])];
        match ans104::encode_tags(&candidate) {
            Ok(encoded) if encoded.len() == ans104::MAX_TAG_BYTES => break candidate,
            Ok(encoded) if encoded.len() < ans104::MAX_TAG_BYTES => value_len += 1,
            _ => panic!("could not land on 4096-byte block"),
        }
    };
    let (signed, view) = sign_and_parse(b"big tags".to_vec(), None, None, &tags);
    assert_eq!(view.tags, tags);
    verify(&signed.bytes).expect("max-tag item verifies");
}

#[test]
fn tag_block_over_4096_bytes_is_rejected_at_build_time() {
    let tags = vec![Tag::new("", vec![b'a'; 4096])];
    let mut builder = DataItemBuilder::new(b"x".to_vec());
    for t in &tags {
        builder = builder.push_tag(t.clone());
    }
    match builder.sign(signer()) {
        Err(Ans104Error::InvalidTags(_)) => {}
        other => panic!("expected InvalidTags, got {other:?}"),
    }
}

#[test]
fn wrong_target_length_is_rejected_by_the_builder() {
    let err = DataItemBuilder::new(b"x".to_vec())
        .target(vec![0u8; 31])
        .unwrap_err();
    match err {
        Ans104Error::FieldLength {
            field, expected, ..
        } => {
            assert_eq!(field, "target");
            assert_eq!(expected, 32);
        }
        other => panic!("expected FieldLength, got {other:?}"),
    }
}

#[test]
fn wrong_anchor_length_is_rejected_by_the_builder() {
    let err = DataItemBuilder::new(b"x".to_vec())
        .anchor(vec![0u8; 33])
        .unwrap_err();
    assert!(matches!(
        err,
        Ans104Error::FieldLength {
            field: "anchor",
            expected: 32,
            ..
        }
    ));
}

#[test]
fn owner_length_must_match_the_signature_type() {
    // An owner of the wrong length for the arweave type must be rejected before
    // any hashing. This is the per-type owner-length validation.
    let item = UnsignedDataItem {
        signature_type: 1,
        owner: vec![0u8; 256], // half the required 512
        target: None,
        anchor: None,
        tags: vec![],
        data: vec![],
    };
    match item.validate() {
        Err(Ans104Error::FieldLength {
            field: "owner",
            actual: 256,
            expected: 512,
        }) => {}
        other => panic!("expected owner FieldLength, got {other:?}"),
    }
}

#[test]
fn parsing_an_unknown_signature_type_is_rejected() {
    // Type 0 is not registered; the parser must refuse it rather than guess a
    // framing.
    let mut bytes = vec![0u8; 200];
    bytes[0] = 0; // sig type 0, little-endian
    bytes[1] = 0;
    match DataItemView::parse(&bytes) {
        Err(Ans104Error::UnsupportedSignatureType(0)) => {}
        other => panic!("expected UnsupportedSignatureType(0), got {other:?}"),
    }
}

#[test]
fn truncated_bytes_are_rejected_without_panicking() {
    let (signed, _) = sign_and_parse(b"truncate me".to_vec(), None, None, &[]);
    // Cut the item off inside the owner field.
    let truncated = &signed.bytes[..300];
    assert!(matches!(
        DataItemView::parse(truncated),
        Err(Ans104Error::Malformed(_))
    ));
}

#[test]
fn declared_tag_count_must_match_decoded_entries() {
    // Take a valid item, then corrupt the on-wire tag count so it disagrees with
    // the actual decoded entries. The parser must reject the mismatch.
    let tags = vec![Tag::new("a", "1"), Tag::new("b", "2")];
    let (signed, _) = sign_and_parse(b"d".to_vec(), None, None, &tags);
    let mut bytes = signed.bytes.clone();
    let header = 2 + 512 + 512 + 1 + 1;
    // Overwrite the little-endian count with 5.
    bytes[header] = 5;
    assert!(matches!(
        DataItemView::parse(&bytes),
        Err(Ans104Error::InvalidTags(_))
    ));
}

#[test]
fn flipping_a_signature_bit_fails_verification() {
    let (signed, _) = sign_and_parse(b"sig integrity".to_vec(), None, None, &[]);
    let mut bytes = signed.bytes.clone();
    // Flip a bit inside the signature region [2, 514).
    bytes[10] ^= 0x80;
    match verify(&bytes) {
        Err(Ans104Error::BadSignature) => {}
        other => panic!("expected BadSignature, got {other:?}"),
    }
}

#[test]
fn signer_owner_is_the_raw_modulus_bytes() {
    // The owner field must be the raw 512-byte big-endian modulus, the value a
    // verifier reconstructs the public key from.
    let owner = signer().owner();
    assert_eq!(owner.len(), 512);
    // Re-deriving the key from these bytes and verifying our own item proves the
    // owner bytes are the modulus, not some other encoding.
    let (signed, _) = sign_and_parse(b"owner".to_vec(), None, None, &[]);
    assert_eq!(signed.item.owner, owner);
    verify(&signed.bytes).expect("verify against embedded owner");
}

#[test]
fn malformed_jwk_is_rejected() {
    assert!(matches!(
        ArweaveJwkSigner::from_jwk_json("not json"),
        Err(Ans104Error::InvalidJwk(_))
    ));
}
