//! Behaviour coverage for the operator keyring: unlock round-trips, address and
//! network verification, malformed-input rejection, and secret hygiene.
//!
//! These tests need no database. Each builds a throwaway age-encrypted envelope
//! in process (a deterministic ed25519 key, its derived address, encrypted under
//! a passphrase with a deliberately low scrypt work factor so the test is fast),
//! then exercises the unlock path against it. They assert real behaviour: that a
//! correct envelope yields a signer whose signature verifies, that a tampered
//! passphrase / wrong address / wrong network is rejected with the right error,
//! and that signing produces a witness the derived public key validates.

use age::secrecy::SecretString;
use ans104::{Ans104Signer, ArweaveJwkSigner};
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::{
    self, arweave_address, derive_enterprise_address, unlock, KeyringEnvelope, UnlockedKeyring,
    WalletSigner,
};
use pallas_crypto::key::ed25519::{PublicKey, SecretKey, Signature};
use zeroize::Zeroizing;

/// A real 4096-bit Arweave RSA JWK fixture shared with the ANS-104 vector suite.
/// Reading it here (rather than generating a key per test, which is slow) keeps
/// the unlock tests exercising a genuine key against its real derived address.
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// The Arweave address the fixture JWK derives to, computed through the same
/// `arweave_address` path the keyring uses, so the test never pins a magic string.
fn fixture_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

/// A deliberately low scrypt work factor so encrypting/decrypting the in-test
/// envelope is fast. Production keyrings use the crate's auto-tuned factor; the
/// unlock path does not care which factor was used.
const TEST_SCRYPT_LOG_N: u8 = 4;

/// One wallet's deterministic material: a fixed-seed ed25519 key, its bech32
/// signing key string, and the payment address it derives to on a network.
struct TestWallet {
    bech32_skey: String,
    verification_key: [u8; 32],
}

/// Build a deterministic test wallet from a 32-byte seed.
fn test_wallet(seed: [u8; 32]) -> TestWallet {
    let secret = SecretKey::from(seed);
    let public: PublicKey = secret.public_key();
    let mut vk = [0u8; 32];
    vk.copy_from_slice(public.as_ref());

    // Re-encode the 32-byte secret as a CIP-5 `ed25519_sk1...` bech32 string,
    // which is exactly the form the keyring carries. `SecretKey` has no public
    // accessor for its bytes, so encode straight from the seed (a normal
    // ed25519 secret IS its 32-byte seed).
    let hrp = bech32::Hrp::parse("ed25519_sk").expect("valid hrp");
    let bech32_skey = bech32::encode::<bech32::Bech32>(hrp, &seed).expect("encode skey");

    TestWallet {
        bech32_skey,
        verification_key: vk,
    }
}

/// Encrypt a keyring JSON document under `passphrase` as an age scrypt envelope.
fn encrypt_envelope(json: &str, passphrase: &str) -> Vec<u8> {
    let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_string()));
    recipient.set_work_factor(TEST_SCRYPT_LOG_N);
    age::encrypt(&recipient, json.as_bytes()).expect("encrypt keyring envelope")
}

/// Extract the error from an unlock result without requiring the success type to
/// be `Debug`. `UnlockedKeyring` deliberately does not implement `Debug` (it
/// holds secret signers), so `Result::expect_err` cannot be used on it.
fn unlock_err(result: Result<UnlockedKeyring, gateway_core::Error>) -> gateway_core::Error {
    match result {
        Ok(_) => panic!("expected unlock to fail, but it succeeded"),
        Err(e) => e,
    }
}

/// Build a single-wallet keyring JSON document with the given (possibly wrong)
/// claimed address.
fn keyring_json(label: &str, bech32_skey: &str, address: &str) -> String {
    serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "cardano-ed25519", "label": label, "address": address,
              "secret": bech32_skey }
        ]
    })
    .to_string()
}

#[test]
fn unlock_round_trips_a_correct_envelope_and_signs_verifiably() {
    let network = Network::Preprod;
    let w = test_wallet([7u8; 32]);
    let address = derive_enterprise_address(&w.verification_key, network).expect("derive address");
    let json = keyring_json("primary", &w.bech32_skey, &address);
    let ciphertext = encrypt_envelope(&json, "correct horse battery staple");

    let unlocked = unlock(
        &ciphertext,
        Zeroizing::new("correct horse battery staple".to_string()),
        network,
    )
    .expect("a correct envelope unlocks");

    // The verified wallet projects its non-secret identity.
    let wallets = unlocked.wallets();
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].label, "primary");
    assert_eq!(wallets[0].address, address);

    // The signer is reachable through an authorized-wallet capability for this
    // address and exposes the right vkey. The capability is minted directly here
    // via the test-only constructor: the keyring is the capability gate, separate
    // from the grant check this in-process test does not exercise.
    let authorized = gateway_core::wallet::grant::AuthorizedWallet::for_tests(
        uuid::Uuid::now_v7(),
        address.clone(),
    );
    let signer = unlocked
        .signer_for(&authorized)
        .expect("the signer is resolvable through the authorized wallet");
    assert_eq!(signer.address(), address);
    assert_eq!(signer.verification_key(), w.verification_key);

    // Signing a body hash yields a signature the derived public key validates,
    // and a tampered hash does not, proving the unlock wired the real key in.
    let body_hash = [0x42u8; 32];
    let sig_bytes = signer.sign_tx_body(&body_hash);
    let public = PublicKey::from(w.verification_key);
    let signature = Signature::from(sig_bytes);
    assert!(
        public.verify(body_hash, &signature),
        "the signature must verify against the derived public key"
    );
    let mut tampered = body_hash;
    tampered[0] ^= 0xFF;
    assert!(
        !public.verify(tampered, &signature),
        "a signature must not verify against a different message"
    );
}

#[test]
fn unlock_rejects_a_wrong_passphrase_cleanly() {
    let network = Network::Preprod;
    let w = test_wallet([9u8; 32]);
    let address = derive_enterprise_address(&w.verification_key, network).expect("derive address");
    let json = keyring_json("primary", &w.bech32_skey, &address);
    let ciphertext = encrypt_envelope(&json, "the right passphrase");

    // `UnlockedKeyring` is intentionally not `Debug` (it holds secret signers),
    // so unwrap the result by hand rather than via `expect_err`.
    let err = unlock_err(unlock(
        &ciphertext,
        Zeroizing::new("a wrong passphrase".to_string()),
        network,
    ));

    assert!(
        matches!(err, gateway_core::Error::KeyringDecrypt),
        "a wrong passphrase is reported as an opaque decrypt failure, got {err:?}"
    );
    // The error message must never echo a passphrase or key material.
    let rendered = err.to_string();
    assert!(!rendered.contains("the right passphrase"));
    assert!(!rendered.contains("a wrong passphrase"));
    assert!(!rendered.contains(&w.bech32_skey));
}

#[test]
fn unlock_refuses_an_address_that_does_not_match_the_key() {
    let network = Network::Preprod;
    let real = test_wallet([11u8; 32]);
    let other = test_wallet([12u8; 32]);
    // Claim the OTHER wallet's address while carrying the real wallet's key.
    let wrong_address =
        derive_enterprise_address(&other.verification_key, network).expect("derive other address");
    let json = keyring_json("primary", &real.bech32_skey, &wrong_address);
    let ciphertext = encrypt_envelope(&json, "pass");

    let err = unlock_err(unlock(
        &ciphertext,
        Zeroizing::new("pass".to_string()),
        network,
    ));

    match err {
        gateway_core::Error::KeyringAddressMismatch { label } => {
            assert_eq!(label, "primary", "the offending entry's label is reported");
        }
        other => panic!("expected an address mismatch, got {other:?}"),
    }
}

#[test]
fn unlock_refuses_a_network_mismatch() {
    // Derive a preprod (test-network) address but configure the deployment for
    // mainnet: the address belongs to a different network than configured.
    let test_network = Network::Preprod;
    let w = test_wallet([13u8; 32]);
    let test_address =
        derive_enterprise_address(&w.verification_key, test_network).expect("derive test address");
    let json = keyring_json("primary", &w.bech32_skey, &test_address);
    let ciphertext = encrypt_envelope(&json, "pass");

    let err = unlock_err(unlock(
        &ciphertext,
        Zeroizing::new("pass".to_string()),
        Network::Mainnet,
    ));

    match err {
        gateway_core::Error::KeyringNetworkMismatch {
            label,
            claimed,
            expected,
        } => {
            assert_eq!(label, "primary");
            assert_eq!(claimed, "testnet");
            assert_eq!(expected, "mainnet");
        }
        other => panic!("expected a network mismatch, got {other:?}"),
    }
}

#[test]
fn unlock_accepts_a_preview_address_under_a_preview_config() {
    // Preprod and preview share the test-network id and `addr_test` HRP, so an
    // address derived "on preprod" is byte-identical to one "on preview"; a
    // preview-configured deployment must accept it without a spurious network
    // mismatch. This pins that the network check is by network id, not by exact
    // enum, for the two test networks.
    let w = test_wallet([14u8; 32]);
    let address =
        derive_enterprise_address(&w.verification_key, Network::Preview).expect("derive address");
    let json = keyring_json("primary", &w.bech32_skey, &address);
    let ciphertext = encrypt_envelope(&json, "pass");

    let unlocked = unlock(
        &ciphertext,
        Zeroizing::new("pass".to_string()),
        Network::Preview,
    )
    .expect("a test-network address unlocks under a preview config");
    let authorized =
        gateway_core::wallet::grant::AuthorizedWallet::for_tests(uuid::Uuid::now_v7(), address);
    assert!(unlocked.signer_for(&authorized).is_some());
}

#[test]
fn unlock_round_trips_a_mixed_cardano_and_arweave_keyring() {
    // A single envelope holding one Cardano wallet and one Arweave funding key
    // must unlock both, exposing each through its own projection and capability.
    let network = Network::Preprod;
    let w = test_wallet([22u8; 32]);
    let cardano_address =
        derive_enterprise_address(&w.verification_key, network).expect("derive address");
    let arweave_addr = fixture_arweave_address();

    let json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "cardano-ed25519", "label": "primary", "address": cardano_address,
              "secret": w.bech32_skey },
            { "kind": "arweave-rsa", "label": "storage", "address": arweave_addr,
              "secret": TEST_JWK_JSON }
        ]
    })
    .to_string();
    let ciphertext = encrypt_envelope(&json, "pass");

    let unlocked = unlock(&ciphertext, Zeroizing::new("pass".to_string()), network)
        .expect("a mixed keyring unlocks");

    // The Cardano wallet projects only as a wallet, not as a funding key.
    let wallets = unlocked.wallets();
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].label, "primary");
    assert_eq!(wallets[0].address, cardano_address);

    // The Arweave key projects only as a funding key, with its derived address.
    let funding = unlocked.arweave_funding_keys();
    assert_eq!(funding.len(), 1);
    assert_eq!(funding[0].label, "storage");
    assert_eq!(funding[0].address, arweave_addr);

    // The Arweave signer is reachable only through a funding capability for its
    // address, and it signs with the right owner/signature type. The capability
    // is minted via the test-only seam: the keyring is the capability gate,
    // separate from the grant check this in-process test does not exercise.
    let authorized = gateway_core::storage::AuthorizedFunding::for_tests(
        uuid::Uuid::now_v7(),
        arweave_addr.clone(),
    );
    let signer = unlocked
        .arweave_signer_for(&authorized)
        .expect("the Arweave signer is resolvable through the funding capability");
    assert_eq!(signer.address(), arweave_addr);
    let reference = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("reference signer");
    assert_eq!(signer.owner(), reference.owner());
    assert_eq!(signer.signature_type(), reference.signature_type());

    // Signing a deep-hash message yields a non-empty RSA-PSS signature, proving
    // the unlock wired the real private key in (a malformed parse would have
    // failed the whole unlock above).
    let sig = signer.sign(b"a deep-hash message").expect("sign succeeds");
    assert_eq!(sig.len(), ans104::RSA_4096_LEN);
}

#[test]
fn arweave_signer_streams_a_signed_envelope_that_reconstructs_and_verifies() {
    // The upload path signs the data item once through the capability-gated keyring
    // signer, streaming the payload, and later reconstructs the canonical bytes from
    // the bounded envelope plus the staged payload. This pins that loop end to end:
    // the streamed envelope's reconstruction is a wire-valid data item carrying the
    // envelope's id, so a retry can re-POST byte-identical bytes without re-signing.
    let network = Network::Preprod;
    let arweave_addr = fixture_arweave_address();
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "arweave-rsa", "label": "storage", "address": arweave_addr,
              "secret": TEST_JWK_JSON }
        ]
    })
    .to_string();
    let ciphertext = encrypt_envelope(&json, "pass");
    let unlocked = unlock(&ciphertext, Zeroizing::new("pass".to_string()), network)
        .expect("an arweave-only keyring unlocks");

    let authorized =
        gateway_core::storage::AuthorizedFunding::for_tests(uuid::Uuid::now_v7(), arweave_addr);
    let signer = unlocked
        .arweave_signer_for(&authorized)
        .expect("the Arweave signer resolves");

    let payload = b"a streamed keyring-signed upload payload".to_vec();
    let tags = vec![ans104::Tag::new("Content-Type", "application/octet-stream")];
    let envelope = signer
        .sign_streaming_envelope(
            None,
            None,
            &tags,
            &mut payload.as_slice(),
            payload.len() as u64,
        )
        .expect("streaming sign through the keyring");

    // The envelope's id is SHA-256(signature) over a 512-byte RSA signature.
    assert_eq!(envelope.signature.len(), ans104::RSA_4096_LEN);

    // Reconstruct the canonical bytes from the envelope prefix + the payload and
    // verify them: the streamed signature is valid over the reconstructed item, and
    // the verified id equals the envelope's.
    let mut canonical = ans104::reconstruct_prefix(&envelope, &signer.owner()).expect("prefix");
    canonical.extend_from_slice(&payload);
    let verified = ans104::verify(&canonical).expect("the reconstructed item verifies");
    assert_eq!(verified.id, envelope.id, "reconstructed id diverged");
}

#[test]
fn unlock_refuses_an_arweave_address_that_does_not_match_the_key() {
    // Carry the fixture JWK but claim a different Arweave address: the derived
    // address will not equal the claim, so the whole unlock must fail loudly,
    // the storage analogue of the Cardano address-mismatch check.
    let wrong_address = "this_is_not_the_keys_real_arweave_address".to_string();
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "arweave-rsa", "label": "storage", "address": wrong_address,
              "secret": TEST_JWK_JSON }
        ]
    })
    .to_string();
    let ciphertext = encrypt_envelope(&json, "pass");

    let err = unlock_err(unlock(
        &ciphertext,
        Zeroizing::new("pass".to_string()),
        Network::Preprod,
    ));
    match err {
        gateway_core::Error::KeyringAddressMismatch { label } => {
            assert_eq!(label, "storage", "the offending entry's label is reported");
        }
        other => panic!("expected an Arweave address mismatch, got {other:?}"),
    }
}

#[test]
fn unlock_refuses_a_malformed_arweave_jwk() {
    // A secret that is not a parseable RSA JWK must fail the whole unlock with a
    // distinct error that never echoes the key material.
    let arweave_addr = fixture_arweave_address();
    let not_a_jwk = r#"{"kty":"RSA","n":"not-base64url-!!!"}"#;
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "arweave-rsa", "label": "storage", "address": arweave_addr,
              "secret": not_a_jwk }
        ]
    })
    .to_string();
    let ciphertext = encrypt_envelope(&json, "pass");

    let err = unlock_err(unlock(
        &ciphertext,
        Zeroizing::new("pass".to_string()),
        Network::Preprod,
    ));
    // The error message never leaks the entry's secret material.
    let rendered = err.to_string();
    assert!(!rendered.contains("not-base64url"));
    match err {
        gateway_core::Error::KeyringInvalidJwk { label } => {
            assert_eq!(label, "storage");
        }
        other => panic!("expected an invalid-JWK error, got {other:?}"),
    }
}

#[test]
fn parse_rejects_a_label_shared_across_key_classes() {
    // A Cardano and an Arweave entry that share a label collide on the
    // operator-facing identity, so parse must reject the envelope before unlock.
    let w = test_wallet([23u8; 32]);
    let cardano_address =
        derive_enterprise_address(&w.verification_key, Network::Preprod).expect("derive address");
    let arweave_addr = fixture_arweave_address();
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "cardano-ed25519", "label": "shared", "address": cardano_address,
              "secret": w.bech32_skey },
            { "kind": "arweave-rsa", "label": "shared", "address": arweave_addr,
              "secret": TEST_JWK_JSON }
        ]
    })
    .to_string();

    let err = KeyringEnvelope::parse(json.as_bytes())
        .expect_err("a label shared across key classes must be rejected");
    assert!(
        matches!(err, gateway_core::Error::KeyringShape(_)),
        "got {err:?}"
    );
}

#[test]
fn parse_rejects_a_duplicate_address() {
    let w = test_wallet([15u8; 32]);
    let address =
        derive_enterprise_address(&w.verification_key, Network::Preprod).expect("derive address");
    // Two entries with distinct labels but the same address.
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "cardano-ed25519", "label": "a", "address": address,
              "secret": w.bech32_skey },
            { "kind": "cardano-ed25519", "label": "b", "address": address,
              "secret": w.bech32_skey }
        ]
    })
    .to_string();

    let err =
        KeyringEnvelope::parse(json.as_bytes()).expect_err("a duplicate address must be rejected");
    assert!(
        matches!(err, gateway_core::Error::KeyringShape(_)),
        "got {err:?}"
    );
}

#[test]
fn parse_rejects_a_duplicate_label() {
    let a = test_wallet([16u8; 32]);
    let b = test_wallet([17u8; 32]);
    let addr_a =
        derive_enterprise_address(&a.verification_key, Network::Preprod).expect("derive a");
    let addr_b =
        derive_enterprise_address(&b.verification_key, Network::Preprod).expect("derive b");
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "cardano-ed25519", "label": "same", "address": addr_a,
              "secret": a.bech32_skey },
            { "kind": "cardano-ed25519", "label": "same", "address": addr_b,
              "secret": b.bech32_skey }
        ]
    })
    .to_string();

    let err =
        KeyringEnvelope::parse(json.as_bytes()).expect_err("a duplicate label must be rejected");
    assert!(
        matches!(err, gateway_core::Error::KeyringShape(_)),
        "got {err:?}"
    );
}

#[test]
fn parse_rejects_an_unsupported_version() {
    let bad_version = serde_json::json!({ "version": 2, "entries": [] }).to_string();
    assert!(matches!(
        KeyringEnvelope::parse(bad_version.as_bytes()),
        Err(gateway_core::Error::KeyringShape(_))
    ));
}

#[test]
fn an_empty_keyring_unlocks_as_empty() {
    // An empty entries list is a valid file state (`gateway keyring init`
    // writes one before the first key is added): the unlock succeeds and
    // reports emptiness, and the binary's serve/bootstrap paths refuse to run
    // on it. Refusing servability is the boot path's job, not the format's.
    let empty = serde_json::json!({ "version": 1, "entries": [] }).to_string();
    let ciphertext = encrypt_envelope(&empty, "passphrase");
    let unlocked = unlock(
        &ciphertext,
        Zeroizing::new("passphrase".to_string()),
        Network::Preprod,
    )
    .expect("an empty keyring is a valid file that unlocks");
    assert!(unlocked.is_empty());
    assert!(unlocked.wallets().is_empty());
    assert!(unlocked.arweave_funding_keys().is_empty());
    assert!(unlocked.active_webhook_wrap_key().is_none());
}

#[test]
fn decode_signing_key_rejects_a_wrong_hrp() {
    // A bech32 string with a non-`ed25519_sk` HRP must be rejected even if it is
    // otherwise well-formed.
    let hrp = bech32::Hrp::parse("addr_vk").expect("hrp");
    let wrong = bech32::encode::<bech32::Bech32>(hrp, &[0u8; 32]).expect("encode");
    let err = keyring::decode_bech32_signing_key(&wrong).expect_err("wrong HRP must be rejected");
    assert!(
        matches!(err, gateway_core::Error::KeyringShape(_)),
        "got {err:?}"
    );
}

#[test]
fn wallet_signer_rejects_a_wrong_length_secret() {
    // A secret that is neither 32 nor 64 bytes is a hard error, surfaced at
    // construction rather than later at sign time.
    let bad = Zeroizing::new(vec![0u8; 16]);
    let err = WalletSigner::new("w".to_string(), "addr".to_string(), bad)
        .expect_err("a 16-byte secret must be rejected");
    assert!(
        matches!(err, gateway_core::Error::KeyringShape(_)),
        "got {err:?}"
    );
}

#[test]
fn wallet_signer_debug_never_renders_key_bytes() {
    // A signer's Debug impl must print only its non-secret identity so an
    // accidental `{:?}` in a log cannot leak the key.
    let seed = [21u8; 32];
    let secret = Zeroizing::new(seed.to_vec());
    let signer = WalletSigner::new("primary".to_string(), "addr_test1...".to_string(), secret)
        .expect("a 32-byte secret builds a signer");
    let rendered = format!("{signer:?}");
    assert!(rendered.contains("primary"));
    assert!(rendered.contains("addr_test1..."));
    // The seed bytes (here all 0x15 = 21) must not appear in any hex/byte form.
    assert!(!rendered.contains("secret"));
    assert!(!rendered.to_lowercase().contains("15151515"));
    assert!(!rendered.contains("[21,"));
}

#[test]
fn unlock_round_trips_a_webhook_wrap_key_from_a_real_envelope() {
    // A keyring holding a Cardano wallet alongside a webhook secret-wrap data key
    // must unlock both. The wrap key is reachable only through its wrap/unwrap
    // accessor (a SecretWrap), distinct from the sign-only wallet accessor, and it
    // seals/opens a webhook secret round-trip.
    let network = Network::Preprod;
    let w = test_wallet([42u8; 32]);
    let cardano_address =
        derive_enterprise_address(&w.verification_key, network).expect("derive address");

    // A deterministic 32-byte wrap-key secret, hex-encoded as the envelope carries.
    let wrap_secret_hex = hex::encode([0x5au8; 32]);
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "cardano-ed25519", "label": "primary", "address": cardano_address,
              "secret": w.bech32_skey },
            { "kind": "webhook-wrap", "label": "webhook-wrap", "key_id": "whk_round_trip",
              "secret": wrap_secret_hex }
        ]
    })
    .to_string();
    let ciphertext = encrypt_envelope(&json, "pass");

    let unlocked = unlock(&ciphertext, Zeroizing::new("pass".to_string()), network)
        .expect("a keyring with a webhook-wrap key unlocks");

    // The wrap key is resolvable both as the active key and by its id, and the two
    // resolve to the same key (the id is recorded on each sealed row).
    let active = unlocked
        .active_webhook_wrap_key()
        .expect("the active wrap key is present");
    assert_eq!(active.key_id(), "whk_round_trip");
    let by_id = unlocked
        .webhook_wrap_key("whk_round_trip")
        .expect("the wrap key resolves by id");
    assert_eq!(by_id.key_id(), "whk_round_trip");

    // The wrap key hands out a SecretWrap that seals and opens a webhook secret.
    let wrap = active.secret_wrap();
    assert_eq!(wrap.wrap_key_id(), "whk_round_trip");
    let sealed = wrap.seal("whsec_unlocked_round_trip").expect("seal");
    assert_eq!(
        wrap.open(&sealed).expect("open").as_slice(),
        b"whsec_unlocked_round_trip"
    );

    // An unknown id does not resolve, so a secret sealed under a rotated-away key
    // cannot be silently opened with the wrong one.
    assert!(unlocked.webhook_wrap_key("whk_absent").is_none());

    // The wrap key never renders its raw bytes: neither the unlocked keyring's wrap
    // key Debug nor secret_hex leaks into a log-shaped rendering.
    let dbg = format!("{active:?}");
    assert!(dbg.contains("whk_round_trip"));
    assert!(!dbg.contains(&*active.secret_hex()));
    assert!(!dbg.contains("5a5a5a5a"));
}
