//! The operator keyring: an age-encrypted envelope of signing keys.
//!
//! The keyring is a JSON document encrypted to a passphrase (age scrypt
//! recipient). It holds three classes of key in one envelope: the Cardano ed25519
//! wallet keys that sign anchoring transactions, the Arweave RSA keys that sign
//! storage data items, and the symmetric webhook secret-wrap data keys that
//! encrypt webhook signing secrets at rest. Each entry is a tagged union on
//! `kind`:
//!
//! ```json
//! {
//!   "version": 1,
//!   "entries": [
//!     { "kind": "cardano-ed25519", "label": "primary", "address": "addr1...",
//!       "secret": "ed25519_sk1..." },
//!     { "kind": "arweave-rsa", "label": "storage", "address": "<arweave-addr>",
//!       "secret": "{ \"kty\": \"RSA\", \"n\": ... }" },
//!     { "kind": "webhook-wrap", "label": "webhook-wrap", "key_id": "whk_...",
//!       "secret": "<64-hex-of-32-bytes>" }
//!   ]
//! }
//! ```
//!
//! `label` is operator-facing metadata that may be renamed. For a signing key the
//! stable upsert identity is `address`; for a webhook-wrap key it is `key_id` (the
//! `wrap_key_id` recorded on every webhook endpoint row). On unlock every signing
//! entry's secret is re-derived to an address and checked against the claimed
//! `address` (a Cardano entry additionally against the configured network); any
//! mismatch fails the whole unlock loudly rather than risk signing with the wrong
//! key on the wrong chain.
//!
//! One file, one passphrase, one unlock backs all three key classes, so they share
//! a single set of zeroizing / redacted-`Debug` / fail-loud guarantees rather than
//! duplicating the hardest part in a sibling store that could drift.
//!
//! # Secret hygiene
//!
//! Decrypted Cardano key material lives only inside a [`WalletSigner`] and
//! Arweave key material only inside an [`ArweaveFundingSigner`], both wiped or
//! redacted on drop. Neither returns the raw key; the only thing a caller can do
//! with a signer is ask it to sign. The webhook-wrap key is a different primitive:
//! the server MUST read a webhook secret back to recompute its HMAC at delivery
//! time, so a one-way hash cannot serve. The wrap key therefore lives in a
//! [`WebhookWrapKey`] that hands out a seal/open accessor through
//! [`WebhookWrapKey::secret_wrap`] — distinct from the sign-only accessors, so the
//! "no raw signing key escapes" guarantee for the ed25519/RSA classes is
//! untouched. The decrypted plaintext buffer is zeroized as soon as the envelope
//! is parsed.

use std::collections::HashSet;

use age::secrecy::SecretString;
use ans104::{Ans104Signer, ArweaveJwkSigner};
use pallas_addresses::{Network as PallasNetwork, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_crypto::hash::{Hash, Hasher};
use pallas_crypto::key::ed25519::{PublicKey, SecretKey, SecretKeyExtended};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::config::Network;
use super::grant::AuthorizedWallet;
use super::operator::address_network_id;
use crate::storage::AuthorizedFunding;
use crate::{Error, Result};

/// The byte length of a normal (non-extended) ed25519 secret key.
const ED25519_SECRET_LEN: usize = 32;
/// The byte length of an extended ed25519 secret key.
const ED25519_EXTENDED_SECRET_LEN: usize = 64;
/// The byte length of a webhook secret-wrap data key. Sourced from the seal/open
/// primitive so the custody key and the AEAD agree on one key size.
const WEBHOOK_WRAP_KEY_LEN: usize = crate::webhook::secret::DATA_KEY_LEN;

/// A keyring entry's secret string, held in a zeroizing buffer that never renders
/// its contents.
///
/// Carries either a Cardano bech32 signing key (`ed25519_sk1...`) or an Arweave
/// RSA private key as JWK JSON, depending on the entry kind. The secret is wiped
/// when the value is dropped (the inner [`Zeroizing`]), the type is deliberately
/// NOT `Clone` (so the plaintext is never duplicated into a second buffer that
/// must also be wiped), and its `Debug` prints only a redacted placeholder. An
/// accidental `{:?}` on a keyring envelope, an entry, or the secret itself can
/// therefore never leak the key into a log.
pub struct SecretMaterial(Zeroizing<String>);

impl SecretMaterial {
    /// Borrow the secret string to decode it. The borrow does not copy the
    /// secret; the only copy that outlives this borrow is the zeroizing buffer
    /// the decode writes its bytes into.
    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for SecretMaterial {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize into a plain String (serde has no zeroizing string), then
        // move it straight into the zeroizing wrapper so the secret lives in a
        // buffer that is wiped on drop from this point on. The transient String
        // serde produced is consumed by the move; no extra copy of the secret
        // outlives this call.
        let raw = String::deserialize(deserializer)?;
        Ok(SecretMaterial(Zeroizing::new(raw)))
    }
}

impl std::fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret; a redacted placeholder keeps any `{:?}` on a
        // containing struct from leaking the key.
        f.write_str("SecretMaterial([redacted])")
    }
}

/// The on-disk keyring shape (after age decryption).
///
/// `version` pins the format so a future incompatible layout is rejected rather
/// than silently mis-parsed. The entries' secrets are NOT retained on this struct
/// past parsing: [`unlock`] consumes the envelope, moving each secret into a
/// zeroizing decode buffer and then into a class-specific signer.
///
/// The type is not `Clone` (cloning would duplicate every secret into a second
/// buffer) and its derived `Debug` is safe because every secret field is a
/// [`SecretMaterial`], which renders redacted.
#[derive(Debug, Deserialize)]
pub struct KeyringEnvelope {
    /// Format version. Only `1` is accepted.
    pub version: u8,
    /// The signing keys the operator can use. A mix of Cardano and Arweave
    /// entries is allowed; both share this one envelope. May be empty while an
    /// operator is still provisioning keys (`gateway keyring init` writes an
    /// empty envelope); the serving binary refuses to boot on an empty keyring,
    /// so emptiness is a file state, not a servable one.
    pub entries: Vec<KeyringEntry>,
}

/// One entry in the keyring envelope, tagged on `kind`.
///
/// The variant selects which key class the `secret` carries and how the claimed
/// `address` is verified at unlock: a Cardano entry's secret is a CIP-5 ed25519
/// signing key checked against an enterprise address on the configured network;
/// an Arweave entry's secret is an RSA JWK checked against its derived Arweave
/// address. Not `Clone` (the secret must never be duplicated) and its derived
/// `Debug` is safe because every secret field is a redacting [`SecretMaterial`].
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum KeyringEntry {
    /// A Cardano ed25519 wallet key that signs anchoring transactions.
    CardanoEd25519 {
        /// Operator-facing display name (renameable; not the stable identity).
        label: String,
        /// The wallet's claimed Cardano payment address. Verified against the
        /// key on the configured network at unlock.
        address: String,
        /// The wallet's ed25519 signing key, CIP-5 bech32 (`ed25519_sk1...`),
        /// in a redacting [`SecretMaterial`].
        secret: SecretMaterial,
    },
    /// An Arweave RSA key that signs storage data items.
    ArweaveRsa {
        /// Operator-facing display name (renameable; not the stable identity).
        label: String,
        /// The funding source's claimed Arweave address. Verified against the
        /// key (the base64url SHA-256 of the modulus) at unlock.
        address: String,
        /// The Arweave RSA private key as JWK JSON, in a redacting
        /// [`SecretMaterial`].
        secret: SecretMaterial,
    },
    /// A symmetric data key that encrypts webhook signing secrets at rest. Unlike
    /// the signing keys, this key is read back at delivery time to recompute a
    /// webhook HMAC, so it is wrapped/unwrapped rather than sign-only.
    WebhookWrap {
        /// Operator-facing display name (renameable; not the stable identity).
        label: String,
        /// The stable id recorded as `wrap_key_id` on every webhook endpoint row,
        /// so a wrap-key rotation can re-encrypt row by row and stay resumable.
        key_id: String,
        /// The 32-byte data key, hex-encoded, in a redacting [`SecretMaterial`].
        secret: SecretMaterial,
    },
}

impl KeyringEntry {
    /// The entry's operator-facing label, regardless of key class.
    fn label(&self) -> &str {
        match self {
            KeyringEntry::CardanoEd25519 { label, .. }
            | KeyringEntry::ArweaveRsa { label, .. }
            | KeyringEntry::WebhookWrap { label, .. } => label,
        }
    }

    /// The entry's stable upsert identity. For a signing key this is its claimed
    /// `address`; for a webhook-wrap key it is its `key_id`. Used by
    /// [`KeyringEnvelope::parse`] to reject a duplicate across all classes.
    fn identity(&self) -> &str {
        match self {
            KeyringEntry::CardanoEd25519 { address, .. }
            | KeyringEntry::ArweaveRsa { address, .. } => address,
            KeyringEntry::WebhookWrap { key_id, .. } => key_id,
        }
    }
}

impl KeyringEnvelope {
    /// Parse a keyring envelope from its decrypted JSON plaintext.
    ///
    /// Rejects an unsupported `version`, a duplicate address, or a duplicate
    /// label (either duplicate would make the boot upsert ambiguous). An empty
    /// `entries` list is a valid file state (a freshly initialised keyring);
    /// the serve path refuses it separately, at boot. The `plaintext` buffer
    /// is the caller's; [`unlock`] zeroizes the buffer it owns after calling
    /// this.
    pub fn parse(plaintext: &[u8]) -> Result<Self> {
        let envelope: KeyringEnvelope = serde_json::from_slice(plaintext)
            .map_err(|e| Error::KeyringShape(format!("plaintext is not the keyring shape: {e}")))?;

        if envelope.version != 1 {
            return Err(Error::KeyringShape(format!(
                "unsupported keyring version {}; only version 1 is accepted",
                envelope.version
            )));
        }

        // A duplicate stable identity (a signing key's address, or a webhook-wrap
        // key's key_id) would make the upsert keyed on it write the same key twice
        // in one unlock; a duplicate label collides on the operator-facing identity.
        // Both are checked across all classes so two entries of any kind cannot
        // share an identity or a label. Reject either so the operator fixes the file
        // before the engine signs anything.
        let mut seen_identities: HashSet<&str> = HashSet::with_capacity(envelope.entries.len());
        let mut seen_labels: HashSet<&str> = HashSet::with_capacity(envelope.entries.len());
        for entry in &envelope.entries {
            if entry.label().is_empty() {
                return Err(Error::KeyringShape(
                    "keyring entry has an empty label".to_string(),
                ));
            }
            if !seen_identities.insert(entry.identity()) {
                return Err(Error::KeyringShape(format!(
                    "keyring contains a duplicate key identity {}",
                    entry.identity()
                )));
            }
            if !seen_labels.insert(entry.label()) {
                return Err(Error::KeyringShape(format!(
                    "keyring contains a duplicate label {:?}",
                    entry.label()
                )));
            }
        }

        Ok(envelope)
    }
}

/// An unlocked operator keyring: a verified signer per entry, addressed by the
/// stable `address`, across both key classes.
///
/// Produced by [`unlock`]. Holds the zeroizing/redacting signers; dropping it
/// wipes every key. Lookups are by address (the stable identity): a scheduled
/// wallet's `operator_wallet.address` resolves to its [`WalletSigner`], and a
/// funding source's `arweave_address` resolves to its [`ArweaveFundingSigner`].
pub struct UnlockedKeyring {
    /// The Cardano ed25519 wallet signers (anchoring transactions).
    signers: Vec<WalletSigner>,
    /// The Arweave RSA funding signers (storage data items).
    arweave_signers: Vec<ArweaveFundingSigner>,
    /// The webhook secret-wrap data keys (encrypt-at-rest for webhook secrets).
    webhook_wrap_keys: Vec<WebhookWrapKey>,
}

impl UnlockedKeyring {
    /// Build a keyring holding only the given webhook secret-wrap data keys, for
    /// the webhook-delivery integration tests.
    ///
    /// The delivery worker needs an unlocked keyring carrying the wrap key a stored
    /// secret was sealed under; building a full age envelope just to exercise the
    /// fan-out and delivery logic is unnecessary ceremony, so the test harness
    /// injects the wrap keys directly. Gated to the integration-test build so it can
    /// never be constructed in production code, where the keyring is only ever
    /// produced by decrypting the real envelope.
    #[cfg(feature = "pg-tests")]
    #[must_use]
    pub fn for_webhook_tests(webhook_wrap_keys: Vec<WebhookWrapKey>) -> Self {
        Self {
            signers: Vec::new(),
            arweave_signers: Vec::new(),
            webhook_wrap_keys,
        }
    }

    /// Build a keyring holding no keys, for tests that exercise a path which fails
    /// before any signer is consulted (for example a backend's production guard).
    ///
    /// Compiled only under this crate's own tests or the `testsupport` feature, so
    /// it cannot be constructed in production code, where the keyring is only ever
    /// produced by decrypting the real envelope.
    #[cfg(any(test, feature = "testsupport"))]
    #[doc(hidden)]
    #[must_use]
    pub fn empty_for_tests() -> Self {
        Self {
            signers: Vec::new(),
            arweave_signers: Vec::new(),
            webhook_wrap_keys: Vec::new(),
        }
    }

    /// Whether the keyring holds no entries of any class.
    ///
    /// An empty keyring is a valid file state (a freshly initialised one, or
    /// one whose last entry was removed) but not a servable one: the binary's
    /// serve and bootstrap paths refuse it with a pointer at the `gateway
    /// keyring add-*` subcommands rather than booting an engine that could
    /// never sign anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
            && self.arweave_signers.is_empty()
            && self.webhook_wrap_keys.is_empty()
    }

    /// The verified Cardano wallet entries' public metadata (label, address), in
    /// file order. Never exposes key material; used to upsert `operator_wallet`
    /// rows and for diagnostics. Arweave entries are excluded — they are not
    /// wallets — and surface via [`Self::arweave_funding_keys`].
    #[must_use]
    pub fn wallets(&self) -> Vec<VerifiedWallet> {
        self.signers
            .iter()
            .map(|s| VerifiedWallet {
                label: s.label.clone(),
                address: s.address.clone(),
            })
            .collect()
    }

    /// The verified Arweave funding entries' public metadata (label, address), in
    /// file order. Never exposes key material; used to upsert
    /// `storage_funding_source` rows and for diagnostics.
    #[must_use]
    pub fn arweave_funding_keys(&self) -> Vec<VerifiedArweaveKey> {
        self.arweave_signers
            .iter()
            .map(|s| VerifiedArweaveKey {
                label: s.label.clone(),
                address: s.address.clone(),
            })
            .collect()
    }

    /// The signer for an authorized wallet, if this keyring holds its key.
    ///
    /// Takes an [`AuthorizedWallet`] rather than a bare address so the signing
    /// surface is reachable only through a capability the `grant` module minted
    /// ([`super::grant::authorize_spend`] for a new spend, or
    /// [`super::grant::resolve_inflight_wallet`] for an in-flight settlement):
    /// there is no way to ask for a signer by an unverified address string. The
    /// keyring is the capability gate (does this instance physically hold the
    /// key?), separate from the authorization gate the token already passed; both
    /// must hold to sign.
    #[must_use]
    pub fn signer_for(&self, wallet: &AuthorizedWallet) -> Option<&WalletSigner> {
        self.signers.iter().find(|s| s.address == wallet.address())
    }

    /// The Arweave signer for an authorized funding source, if this keyring holds
    /// its key.
    ///
    /// Takes an [`AuthorizedFunding`] rather than a bare address so the storage
    /// signing surface is reachable only through a capability the funding engine
    /// minted, exactly as [`Self::signer_for`] gates Cardano signing behind an
    /// [`AuthorizedWallet`]. The keyring is the capability gate (does this
    /// instance physically hold the Arweave key?), separate from the
    /// authorization gate the capability already passed; both must hold to sign.
    #[must_use]
    pub fn arweave_signer_for(&self, funding: &AuthorizedFunding) -> Option<&ArweaveFundingSigner> {
        self.arweave_signers
            .iter()
            .find(|s| s.address == funding.arweave_address())
    }

    /// The active webhook secret-wrap data key — the one a new endpoint's secret is
    /// encrypted under at create.
    ///
    /// The newest entry in file order is the active key (a rotation appends a new
    /// data key and re-wraps existing rows onto it, leaving the superseded keys in
    /// the envelope only until no row references them). Returns `None` when the
    /// keyring holds no webhook-wrap key, so a deployment that never registered one
    /// surfaces the missing-key error at create time rather than signing with the
    /// wrong primitive.
    #[must_use]
    pub fn active_webhook_wrap_key(&self) -> Option<&WebhookWrapKey> {
        self.webhook_wrap_keys.last()
    }

    /// The webhook secret-wrap data key with the given `key_id`, if this keyring
    /// holds it.
    ///
    /// A stored secret records the `wrap_key_id` it was encrypted under, so an
    /// unwrap at delivery time resolves the exact key by id even across a rotation
    /// window where several wrap keys are live. Returns `None` when no key matches,
    /// which a caller treats as "this secret cannot be unwrapped on this instance"
    /// rather than silently trying another key.
    ///
    /// Resolution is by `key_id` only, NOT scoped to an operator or account. This is
    /// the deliberate instance-custody posture, the same model the Cardano signing
    /// keyring and the Arweave funding JWKs use: key custody is instance-level, and
    /// tenant ISOLATION is enforced by the ownership-scoped registration/read queries
    /// (an account bearer or operator token can only ever address its OWN endpoints,
    /// and no read path returns a secret's plaintext or ciphertext — list/detail
    /// return only the one-way fingerprint). The wrap key is used solely to decrypt a
    /// secret the gateway itself is about to HMAC a delivery with; it never hands raw
    /// secret material back to a tenant. A per-operator wrap key would add encryption
    /// domains without changing what any tenant can read, so it is intentionally not
    /// modeled here.
    #[must_use]
    pub fn webhook_wrap_key(&self, key_id: &str) -> Option<&WebhookWrapKey> {
        self.webhook_wrap_keys.iter().find(|k| k.key_id == key_id)
    }
}

/// A verified wallet's non-secret metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWallet {
    /// Operator-facing label.
    pub label: String,
    /// Stable bech32 payment address (verified to match the signing key).
    pub address: String,
}

/// A verified Arweave funding key's non-secret metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArweaveKey {
    /// Operator-facing label.
    pub label: String,
    /// Stable Arweave address (verified to match the RSA key).
    pub address: String,
}

/// Decrypt and verify a keyring against a passphrase and the configured network.
///
/// Decrypts the age envelope with the passphrase (scrypt identity), parses the
/// plaintext via [`KeyringEnvelope::parse`], and verifies every entry against its
/// own key class: a Cardano entry decodes the bech32 signing key, checks the
/// claimed address is on `network`, derives the enterprise address, and refuses
/// the unlock on any mismatch; an Arweave entry parses the RSA JWK, derives the
/// Arweave address, and refuses the unlock if it does not equal the claim. Any
/// failure in ANY entry fails the WHOLE unlock. The decrypted plaintext is
/// zeroized before returning.
///
/// `passphrase` is taken by value into a [`Zeroizing`] wrapper so it is wiped
/// when this function returns.
pub fn unlock(
    ciphertext: &[u8],
    passphrase: Zeroizing<String>,
    network: Network,
) -> Result<UnlockedKeyring> {
    // The age scrypt identity takes the passphrase into a SecretString, which
    // owns its own zeroizing copy. `SecretString::from(&str)` makes that copy
    // directly from our wrapper's contents; our `Zeroizing<String>` is wiped
    // when this function returns, so no plaintext passphrase outlives the call.
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.as_str()));

    // A decryption failure here is always reported as the same opaque error: the
    // message never echoes the passphrase, the ciphertext, or any key material,
    // so a wrong passphrase, a tampered envelope, and a corrupt header are
    // indistinguishable to a caller (and to a log).
    let plaintext =
        Zeroizing::new(age::decrypt(&identity, ciphertext).map_err(|_| Error::KeyringDecrypt)?);

    let envelope = KeyringEnvelope::parse(&plaintext)?;
    verify_entries(envelope, network)
}

/// Verify every parsed entry against its own key class and assemble the
/// unlocked keyring — the per-entry half of [`unlock`], shared with the keyring
/// editor so a file the editor writes is checked by exactly the code the serve
/// path will run on it.
///
/// Consumes the envelope so each entry's secret is MOVED into its decode buffer
/// (and dropped/zeroized as the entry goes out of scope), never left behind in
/// a parsed struct after the signer is built. Any failure in ANY entry fails
/// the whole verification.
pub(crate) fn verify_entries(
    envelope: KeyringEnvelope,
    network: Network,
) -> Result<UnlockedKeyring> {
    let mut signers = Vec::new();
    let mut arweave_signers = Vec::new();
    let mut webhook_wrap_keys = Vec::new();
    for entry in envelope.entries {
        match entry {
            KeyringEntry::CardanoEd25519 {
                label,
                address,
                secret,
            } => {
                signers.push(unlock_cardano(label, address, &secret, network)?);
            }
            KeyringEntry::ArweaveRsa {
                label,
                address,
                secret,
            } => {
                arweave_signers.push(unlock_arweave(label, address, &secret)?);
            }
            KeyringEntry::WebhookWrap {
                label,
                key_id,
                secret,
            } => {
                webhook_wrap_keys.push(WebhookWrapKey::from_hex(label, key_id, &secret)?);
            }
        }
    }

    Ok(UnlockedKeyring {
        signers,
        arweave_signers,
        webhook_wrap_keys,
    })
}

/// Verify one Cardano entry and build its signer, or fail the unlock.
///
/// Checks the claimed address encodes the configured network, decodes the bech32
/// secret, and re-derives the enterprise address to compare against the claim.
fn unlock_cardano(
    label: String,
    address: String,
    secret: &SecretMaterial,
    network: Network,
) -> Result<WalletSigner> {
    // The claimed address must encode the configured network. Catch a network
    // mismatch first so it is reported distinctly from a wrong key: a preprod
    // address under a mainnet config (or the reverse) fails here before the
    // (always-failing) address comparison would. The two test networks (preprod,
    // preview) share the same network id and `addr_test` HRP, so an address can
    // only distinguish mainnet from a test network; the configured network
    // supplies the finer preprod-vs-preview choice.
    let claimed_id = address_network_id(&address).ok_or_else(|| {
        Error::KeyringShape(format!(
            "keyring entry {label:?} address is not a valid Cardano payment address"
        ))
    })?;
    if claimed_id != network.network_id() {
        let claimed = if claimed_id == 1 {
            "mainnet"
        } else {
            "testnet"
        };
        return Err(Error::KeyringNetworkMismatch {
            label,
            claimed: claimed.to_string(),
            expected: network.as_str().to_string(),
        });
    }

    // Decode the bech32 secret into a zeroizing byte buffer, then construct the
    // signer (which takes ownership of that buffer).
    let secret_bytes = decode_bech32_signing_key(secret.expose())?;
    let signer = WalletSigner::new(label.clone(), address.clone(), secret_bytes)?;

    // Re-derive the address from the key and compare to the claim. Any mismatch
    // fails the whole unlock so the engine never signs with a key that does not
    // own the address it was registered under.
    let derived = derive_enterprise_address(&signer.verification_key, network)?;
    if derived != address {
        return Err(Error::KeyringAddressMismatch { label });
    }

    Ok(signer)
}

/// Verify one Arweave entry and build its signer, or fail the unlock.
///
/// Parses the RSA JWK, derives the Arweave address from the key, and compares it
/// against the claimed address. A malformed JWK or a mismatched address fails the
/// whole unlock — the storage analogue of the Cardano address check.
fn unlock_arweave(
    label: String,
    address: String,
    secret: &SecretMaterial,
) -> Result<ArweaveFundingSigner> {
    let signer = ArweaveFundingSigner::from_jwk_json(label.clone(), secret.expose())?;

    if signer.address != address {
        return Err(Error::KeyringAddressMismatch { label });
    }

    Ok(signer)
}

/// A single wallet's signing key, holding either a 32-byte ed25519 secret or a
/// 64-byte extended secret, plus the verified address.
///
/// The key bytes are zeroized on drop. The only operation the public surface
/// permits is signing a 32-byte transaction body hash; the raw key is never
/// returned, never logged, and never serialised.
pub struct WalletSigner {
    /// The stable payment address this key derives to (verified at unlock).
    address: String,
    /// Operator-facing label.
    label: String,
    /// The secret key bytes (32 for a normal key, 64 for an extended key),
    /// wiped on drop.
    secret: Zeroizing<Vec<u8>>,
    /// The 32-byte ed25519 verification key, needed by the builder to size the
    /// witness exactly. Public, so it is not secret, but kept here so a caller
    /// never has to touch the secret to get it.
    verification_key: [u8; 32],
}

impl WalletSigner {
    /// Build a signer from a decoded ed25519 secret key and its verified
    /// address/label. The secret length selects normal (32) vs extended (64);
    /// any other length is a hard error.
    ///
    /// Public (not crate-private) because it is a validated constructor over key
    /// bytes the caller already holds, not a capability seam: it grants no
    /// authority a bare key holder does not already have. The crate's integration
    /// suites (a separate crate) build a signer from a raw seed through it to drive
    /// the replenish/keyring paths without standing up an age envelope.
    pub fn new(label: String, address: String, secret: Zeroizing<Vec<u8>>) -> Result<Self> {
        // Deriving the key here both validates the secret length and yields the
        // verification key, so a malformed secret fails construction rather than
        // surfacing later at sign time.
        let key = Ed25519Key::from_secret_bytes(&secret)?;
        let verification_key = public_key_bytes(&key.public_key());
        Ok(Self {
            address,
            label,
            secret,
            verification_key,
        })
    }

    /// The verified payment address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The operator-facing label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The 32-byte ed25519 verification key. Public material, safe to expose;
    /// the builder needs it to size the single vkey witness the fee pays for.
    #[must_use]
    pub fn verification_key(&self) -> [u8; 32] {
        self.verification_key
    }

    /// Sign a 32-byte transaction body hash, returning the 64-byte ed25519
    /// signature. The only operation that touches the secret key.
    #[must_use]
    pub fn sign_tx_body(&self, body_hash: &[u8; 32]) -> [u8; 64] {
        // The secret length was validated at construction, so reconstruction
        // here cannot fail; a wrong-length secret would have been rejected by
        // `new`. Sign the body hash directly: the builder signs the 32-byte
        // body hash, not the body bytes.
        let key = Ed25519Key::from_secret_bytes(&self.secret)
            .expect("a signer's secret was validated at construction");
        let signature = key.sign(body_hash);
        let mut out = [0u8; 64];
        out.copy_from_slice(signature.as_ref());
        out
    }
}

/// An ed25519 key reconstructed from a wallet's secret bytes, abstracting over
/// the normal (32-byte) and extended (64-byte) key shapes so the signer's
/// derivation and signing paths do not branch on the variant at every call.
enum Ed25519Key {
    /// A normal 32-byte ed25519 secret.
    Normal(SecretKey),
    /// An extended 64-byte ed25519 secret (the shape a CIP-1852 wallet derives).
    Extended(SecretKeyExtended),
}

impl Ed25519Key {
    /// Reconstruct a key from a wallet's raw secret bytes, rejecting any length
    /// that is neither 32 (normal) nor 64 (extended). An extended key whose bit
    /// tweaks are malformed is also rejected.
    ///
    /// The fixed-size staging arrays the pallas constructors are fed from are
    /// held in [`Zeroizing`] so the copy of the private key is wiped when they
    /// drop; the constructed keys themselves scrub their bytes on drop (pallas
    /// implements `Drop` for both key shapes), so no reconstruction leaves the
    /// secret behind on the stack.
    fn from_secret_bytes(secret: &[u8]) -> Result<Self> {
        match secret.len() {
            ED25519_SECRET_LEN => {
                let mut bytes = Zeroizing::new([0u8; ED25519_SECRET_LEN]);
                bytes.copy_from_slice(secret);
                Ok(Ed25519Key::Normal(SecretKey::from(*bytes)))
            }
            ED25519_EXTENDED_SECRET_LEN => {
                let mut bytes = Zeroizing::new([0u8; ED25519_EXTENDED_SECRET_LEN]);
                bytes.copy_from_slice(secret);
                let key = SecretKeyExtended::from_bytes(*bytes).map_err(|_| {
                    Error::KeyringShape(
                        "an extended signing key has malformed ed25519 bit tweaks".to_string(),
                    )
                })?;
                Ok(Ed25519Key::Extended(key))
            }
            other => Err(Error::KeyringShape(format!(
                "a signing key must be {ED25519_SECRET_LEN} or {ED25519_EXTENDED_SECRET_LEN} bytes, got {other}"
            ))),
        }
    }

    /// The verification key for this secret.
    fn public_key(&self) -> PublicKey {
        match self {
            Ed25519Key::Normal(k) => k.public_key(),
            Ed25519Key::Extended(k) => k.public_key(),
        }
    }

    /// Sign a message with this secret.
    fn sign(&self, message: &[u8]) -> pallas_crypto::key::ed25519::Signature {
        match self {
            Ed25519Key::Normal(k) => k.sign(message),
            Ed25519Key::Extended(k) => k.sign(message),
        }
    }
}

/// Copy a [`PublicKey`]'s 32 raw bytes into a fixed array.
fn public_key_bytes(public: &PublicKey) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(public.as_ref());
    out
}

impl std::fmt::Debug for WalletSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key bytes. A signer prints only its non-secret
        // identity so an accidental `{:?}` in a log cannot leak the key.
        f.debug_struct("WalletSigner")
            .field("label", &self.label)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// One Arweave funding key's signer: a parsed RSA private key plus its verified
/// Arweave address.
///
/// The signer wraps an [`ArweaveJwkSigner`] (the parsed RSA key + the modulus
/// bytes that go on the wire) and exposes only signing, never the private key.
/// `Debug` prints only the non-secret identity so an accidental `{:?}` in a log
/// cannot leak the key, and the type is not `Clone` (the key must never be
/// duplicated into a second copy). The provider POST and the data-item id are
/// produced by the storage layer through [`Self::sign`] / [`Self::owner`]; this
/// type never returns the RSA private components.
pub struct ArweaveFundingSigner {
    /// The verified Arweave address this key derives to (checked at unlock).
    address: String,
    /// Operator-facing label.
    label: String,
    /// The parsed RSA signer (private key + owner/modulus bytes).
    signer: ArweaveJwkSigner,
}

impl ArweaveFundingSigner {
    /// Parse an Arweave RSA private key from JWK JSON and derive its address.
    ///
    /// The returned signer's [`Self::address`] is derived FROM the key, so the
    /// caller compares it against the operator's claimed address to verify the
    /// key owns the address it is registered under. Returns an error if the JWK
    /// is not a valid 4096-bit RSA key (malformed JSON, bad base64url, or a
    /// wrong-size modulus).
    pub(crate) fn from_jwk_json(label: String, jwk_json: &str) -> Result<Self> {
        let signer =
            ArweaveJwkSigner::from_jwk_json(jwk_json).map_err(|_| Error::KeyringInvalidJwk {
                label: label.clone(),
            })?;
        // The Arweave address is the base64url SHA-256 of the owner (the raw RSA
        // modulus bytes), the standard Arweave wallet-address derivation. Storing
        // the derived address (not a claim) means a later lookup is always
        // against what the key actually owns.
        let address = arweave_address(&signer.owner());
        Ok(Self {
            address,
            label,
            signer,
        })
    }

    /// The verified Arweave address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The operator-facing label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The owner (modulus) bytes that go on the wire as the data item's owner.
    /// Public RSA material, safe to expose; the storage layer needs it to build
    /// the data item and derive its id.
    #[must_use]
    pub fn owner(&self) -> Vec<u8> {
        self.signer.owner()
    }

    /// The ANS-104 signature-type tag this key produces (`arweave`).
    #[must_use]
    pub fn signature_type(&self) -> u16 {
        self.signer.signature_type()
    }

    /// Sign an ANS-104 deep-hash message, returning the RSA-PSS signature bytes.
    /// The only operation that touches the private key.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signer
            .sign(message)
            .map_err(|e| Error::ArweaveSign(e.to_string()))
    }

    /// Sign a data item whose payload is read from `reader` rather than buffered,
    /// producing the bounded [`ans104::SignedEnvelope`] the upload path persists and
    /// reconstructs from.
    ///
    /// The fixed fields are deep-hashed in memory and the `data` leaf is folded in
    /// via a single streaming SHA-384 pass, so a multi-gigabyte upload signs with a
    /// fixed working set. The signature (and therefore the item id) is fixed here
    /// once: a retry re-POSTs the reconstructed bytes rather than re-signing, which
    /// would change the randomised PSS signature.
    pub fn sign_streaming_envelope<R: std::io::Read>(
        &self,
        target: Option<[u8; ans104::TARGET_LEN]>,
        anchor: Option<[u8; ans104::ANCHOR_LEN]>,
        tags: &[ans104::Tag],
        reader: &mut R,
        data_len: u64,
    ) -> Result<ans104::SignedEnvelope> {
        ans104::sign_streaming(&self.signer, target, anchor, tags, reader, data_len)
            .map_err(|e| Error::ArweaveSign(e.to_string()))
    }

    /// Sign an Arweave format-2 base-layer transaction carrying `data` under
    /// `tags`, with this key.
    ///
    /// Used only by the development storage backend that posts to a base-layer-only
    /// emulator: production storage posts data items through a bundling service, not
    /// a self-signed base-layer transaction. The key never leaves this type; the
    /// transaction id is the randomised-signature hash, so a caller that needs a
    /// stable content address keys on the data item, not this id.
    pub fn sign_tx_v2(
        &self,
        data: &[u8],
        tags: &[ans104::Tag],
        last_tx: &str,
        reward: u64,
    ) -> Result<ans104::SignedTxV2> {
        ans104::sign_tx_v2(&self.signer, data, tags, last_tx, reward)
            .map_err(|e| Error::ArweaveSign(e.to_string()))
    }

    /// Sign an Arweave format-2 winston transfer from this key's wallet to
    /// `target_b64url`, with no data payload.
    ///
    /// Used by the operator storage top-up: converting AR into prepaid upload
    /// credits is an on-chain transfer to the storage provider's deposit wallet.
    /// The key never leaves this type; the transaction id is the
    /// randomised-signature hash, fixed at signing, so the caller can persist the
    /// id BEFORE broadcasting and a crash between sign and submit never loses
    /// track of which transaction may have reached the network.
    pub fn sign_transfer_tx_v2(
        &self,
        target_b64url: &str,
        quantity_winston: u128,
        last_tx: &str,
        reward: u64,
    ) -> Result<ans104::SignedTxV2> {
        ans104::sign_transfer_tx_v2(
            &self.signer,
            target_b64url,
            quantity_winston,
            last_tx,
            reward,
        )
        .map_err(|e| Error::ArweaveSign(e.to_string()))
    }
}

impl std::fmt::Debug for ArweaveFundingSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key. A signer prints only its non-secret identity so
        // an accidental `{:?}` in a log cannot leak the RSA private key.
        f.debug_struct("ArweaveFundingSigner")
            .field("label", &self.label)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// A webhook secret-wrap data key held in the operator keyring: the *custody*
/// side of the symmetric key that encrypts webhook signing secrets at rest.
///
/// Unlike the ed25519/RSA signing keys, a webhook secret must be read back by the
/// server to recompute its HMAC on every delivery, so a one-way hash cannot serve.
/// The keyring is where this 32-byte key lives behind the same boot passphrase and
/// fail-loud/zeroize guarantees as the signing keys. The actual seal/open of a
/// secret is a single primitive in [`crate::webhook::secret::SecretWrap`]; this
/// type does not duplicate it. Its only crypto-facing accessor is
/// [`Self::secret_wrap`], which hands out a `SecretWrap` bound to this key and its
/// `key_id` — distinct from the sign-only [`UnlockedKeyring::signer_for`] /
/// [`UnlockedKeyring::arweave_signer_for`] accessors, so the "no raw signing key
/// escapes" guarantee for the ed25519/RSA classes is untouched. The raw key bytes
/// never leave this type except through [`Self::secret_hex`], the bootstrap-only
/// persistence form; the key is wiped on drop and `Debug` prints only the
/// non-secret `key_id`.
pub struct WebhookWrapKey {
    /// The stable id recorded as `wrap_key_id` on every endpoint row sealed under
    /// this key, so an unwrap resolves the exact key by id and a rotation re-wraps
    /// row by row.
    key_id: String,
    /// Operator-facing label.
    label: String,
    /// The 32-byte data key, wiped on drop.
    key: Zeroizing<[u8; WEBHOOK_WRAP_KEY_LEN]>,
}

impl WebhookWrapKey {
    /// Parse a wrap key from its hex-encoded 32-byte secret.
    ///
    /// Rejects a secret that is not valid hex or does not decode to exactly 32
    /// bytes. The error carries only the label, never the key bytes.
    fn from_hex(label: String, key_id: String, secret: &SecretMaterial) -> Result<Self> {
        let bytes = Zeroizing::new(hex::decode(secret.expose()).map_err(|_| {
            Error::WebhookWrapKeyShape {
                label: label.clone(),
            }
        })?);
        let key: [u8; WEBHOOK_WRAP_KEY_LEN] =
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::WebhookWrapKeyShape {
                    label: label.clone(),
                })?;
        Ok(Self {
            key_id,
            label,
            key: Zeroizing::new(key),
        })
    }

    /// Mint a fresh wrap key from the OS CSPRNG, tagged with `key_id`.
    ///
    /// Used at instance bootstrap to create the active webhook secret-wrap data
    /// key before it is written into the keyring envelope. The minted key is hex-
    /// encoded by [`Self::secret_hex`] for storage; the raw bytes stay inside the
    /// returned value.
    pub fn generate(label: String, key_id: String) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; WEBHOOK_WRAP_KEY_LEN]);
        getrandom::getrandom(key.as_mut_slice()).map_err(|_| Error::WebhookSecretWrap)?;
        Ok(Self { key_id, label, key })
    }

    /// The stable `wrap_key_id`.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The operator-facing label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The hex-encoding of the raw key, for writing the minted key into the keyring
    /// envelope at bootstrap.
    ///
    /// This is the one place the bytes are rendered, and only so the bootstrap can
    /// persist the key into the same age envelope that protects the signing keys.
    /// It is not a general accessor: the delivery path seals/opens via
    /// [`Self::secret_wrap`], so the key never reaches a log or the DB in plaintext.
    #[must_use]
    pub fn secret_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(*self.key))
    }

    /// Hand out the seal/open accessor bound to this key and its `key_id`.
    ///
    /// The registration path seals a new secret with the returned
    /// [`crate::webhook::secret::SecretWrap`] and records its `wrap_key_id`; the
    /// delivery path opens a stored `secret_enc` with the accessor resolved by that
    /// recorded id. This is the one bridge from the custody key to the AEAD
    /// primitive, so there is a single implementation of the seal/open format.
    #[must_use]
    pub fn secret_wrap(&self) -> crate::webhook::secret::SecretWrap {
        crate::webhook::secret::SecretWrap::new(self.key_id.clone(), *self.key)
    }
}

impl std::fmt::Debug for WebhookWrapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key bytes; a wrap key prints only its non-secret
        // identity so an accidental `{:?}` in a log cannot leak the data key.
        f.debug_struct("WebhookWrapKey")
            .field("key_id", &self.key_id)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// Derive the Arweave wallet address for an RSA public key (the owner/modulus
/// bytes): the URL-safe-no-pad base64 of the SHA-256 of the modulus.
///
/// This is the standard Arweave address derivation; the unlock check compares it
/// against the claimed `address` on each Arweave entry.
#[must_use]
pub fn arweave_address(owner: &[u8]) -> String {
    let digest = Sha256::digest(owner);
    ans104::base64url::encode(&digest)
}

/// Decode a CIP-5 bech32 ed25519 signing key (`ed25519_sk1...`) into its raw
/// secret bytes, rejecting a wrong HRP or a length that is neither 32 nor 64.
///
/// Returned in a [`Zeroizing`] wrapper so the decoded secret is wiped when the
/// caller is done with it.
pub fn decode_bech32_signing_key(bech32_skey: &str) -> Result<Zeroizing<Vec<u8>>> {
    let (hrp, payload) = bech32::decode(bech32_skey).map_err(|_| {
        // The error never echoes the key string itself, only that decoding
        // failed, so a malformed key cannot leak its bytes into a log.
        Error::KeyringShape("a signing key is not valid bech32".to_string())
    })?;
    // Wrap the decoded payload in a zeroizing buffer as early as possible so the
    // secret bytes are wiped on every exit path below.
    let payload = Zeroizing::new(payload);
    if hrp.as_str() != SIGNING_KEY_HRP {
        return Err(Error::KeyringShape(format!(
            "a signing key has HRP {:?}, expected {SIGNING_KEY_HRP:?}",
            hrp.as_str()
        )));
    }
    match payload.len() {
        ED25519_SECRET_LEN | ED25519_EXTENDED_SECRET_LEN => Ok(payload),
        other => Err(Error::KeyringShape(format!(
            "a signing key payload must be {ED25519_SECRET_LEN} or {ED25519_EXTENDED_SECRET_LEN} bytes, got {other}"
        ))),
    }
}

/// Derive the bech32 Cardano enterprise (payment-only) address for an ed25519
/// verification key on a network.
///
/// The payment credential is the Blake2b-224 hash of the 32-byte verification
/// key; the enterprise address is the header byte (key-payment, no delegation)
/// followed by that hash, bech32-encoded under the network's `addr`/`addr_test`
/// HRP. This is the derivation the unlock check compares against the claimed
/// address.
pub fn derive_enterprise_address(verification_key: &[u8; 32], network: Network) -> Result<String> {
    // The payment credential is the Blake2b-224 hash of the 32-byte vkey.
    let key_hash: Hash<28> = Hasher::<224>::hash(verification_key);
    let pallas_network = match network {
        Network::Mainnet => PallasNetwork::Mainnet,
        Network::Preprod | Network::Preview => PallasNetwork::Testnet,
    };
    let address = pallas_addresses::ShelleyAddress::new(
        pallas_network,
        ShelleyPaymentPart::key_hash(key_hash),
        // An enterprise address has no delegation part.
        ShelleyDelegationPart::Null,
    );
    address
        .to_bech32()
        .map_err(|e| Error::Config(format!("encoding the derived payment address failed: {e}")))
}

/// Derive the bech32 enterprise address a CIP-5 signing key (`ed25519_sk1...`)
/// controls on a network: decode the secret, derive its verification key, and
/// run [`derive_enterprise_address`].
///
/// This is the one derivation the unlock check compares a claimed address
/// against; the keyring editor uses it to WRITE that address in the first
/// place, so a claim and its check can never come from two implementations.
pub fn address_for_signing_key(bech32_skey: &str, network: Network) -> Result<String> {
    let secret = decode_bech32_signing_key(bech32_skey)?;
    let key = Ed25519Key::from_secret_bytes(&secret)?;
    derive_enterprise_address(&public_key_bytes(&key.public_key()), network)
}

/// The bech32 human-readable part a Cardano ed25519 signing key carries.
pub(crate) const SIGNING_KEY_HRP: &str = "ed25519_sk";

#[cfg(test)]
mod tests {
    use super::*;

    /// The secret of either key class must never appear in any `Debug` rendering,
    /// of the secret itself, of the entry, or of the whole envelope. This guards
    /// the secret-hygiene invariant: an accidental `{:?}` in a log line can never
    /// leak the signing key, for a Cardano bech32 key or an Arweave JWK.
    #[test]
    fn debug_never_renders_any_entry_secret() {
        let cardano_secret = "ed25519_sk1thisisnotarealkeybutmustnotleak0000000000000000000000";
        let arweave_secret = r#"{"kty":"RSA","n":"secretmodulusmustnotleak","d":"privexp"}"#;
        let json = serde_json::json!({
            "version": 1,
            "entries": [
                { "kind": "cardano-ed25519", "label": "primary",
                  "address": "addr_test1xyz", "secret": cardano_secret },
                { "kind": "arweave-rsa", "label": "storage",
                  "address": "arweaveaddr", "secret": arweave_secret }
            ]
        })
        .to_string();
        // Parse deliberately accepts a non-derivable test key (it only enforces
        // shape, not key/address agreement); the derivation check lives in
        // `unlock`, which is exercised against real keys in the integration suite.
        let envelope = KeyringEnvelope::parse(json.as_bytes()).expect("shape parses");

        let envelope_dbg = format!("{envelope:?}");
        let secret_dbgs: Vec<String> = envelope
            .entries
            .iter()
            .map(|entry| match entry {
                KeyringEntry::CardanoEd25519 { secret, .. }
                | KeyringEntry::ArweaveRsa { secret, .. }
                | KeyringEntry::WebhookWrap { secret, .. } => format!("{secret:?}"),
            })
            .collect();
        let entry_dbgs: Vec<String> = envelope.entries.iter().map(|e| format!("{e:?}")).collect();

        for rendered in entry_dbgs
            .iter()
            .chain(secret_dbgs.iter())
            .chain(std::iter::once(&envelope_dbg))
        {
            assert!(
                !rendered.contains(cardano_secret),
                "a Debug rendering must never contain the Cardano signing key: {rendered}"
            );
            assert!(
                !rendered.contains("ed25519_sk1"),
                "a Debug rendering must never contain a signing-key prefix: {rendered}"
            );
            assert!(
                !rendered.contains("secretmodulusmustnotleak"),
                "a Debug rendering must never contain Arweave key material: {rendered}"
            );
            assert!(
                !rendered.contains("privexp"),
                "a Debug rendering must never contain an RSA private exponent: {rendered}"
            );
        }
        for secret_dbg in &secret_dbgs {
            assert!(
                secret_dbg.contains("redacted"),
                "the secret renders as a redacted placeholder, got {secret_dbg}"
            );
        }
        // The non-secret fields are still useful for diagnostics.
        assert!(
            entry_dbgs[0].contains("primary"),
            "the label is still rendered"
        );
        assert!(
            entry_dbgs[0].contains("addr_test1xyz"),
            "the address is still rendered"
        );
    }

    /// A freshly generated wrap key seals a secret through its `SecretWrap` bridge
    /// and opens it byte-for-byte, and the seal is non-deterministic (a fresh nonce
    /// per call) so the same secret encrypts to different bytes each time.
    #[test]
    fn wrap_key_round_trips_through_its_secret_wrap() {
        let key = WebhookWrapKey::generate("webhook-wrap".to_string(), "whk_1".to_string())
            .expect("generate");
        let wrap = key.secret_wrap();
        assert_eq!(wrap.wrap_key_id(), "whk_1");
        let secret = "whsec_test_0123456789abcdef";

        let blob_a = wrap.seal(secret).expect("seal a");
        let blob_b = wrap.seal(secret).expect("seal b");
        assert_ne!(blob_a, blob_b, "a fresh nonce must make each seal distinct");

        assert_eq!(
            wrap.open(&blob_a).expect("open a").as_slice(),
            secret.as_bytes()
        );
        assert_eq!(
            wrap.open(&blob_b).expect("open b").as_slice(),
            secret.as_bytes()
        );
    }

    /// A secret sealed under one wrap key does not open under a different key.
    #[test]
    fn wrap_key_secret_wrap_rejects_a_wrong_key() {
        let key_a = WebhookWrapKey::generate("a".to_string(), "whk_a".to_string()).expect("gen a");
        let key_b = WebhookWrapKey::generate("b".to_string(), "whk_b".to_string()).expect("gen b");
        let blob = key_a.secret_wrap().seal("secret").expect("seal");
        assert!(
            key_b.secret_wrap().open(&blob).is_err(),
            "a different data key must not open the ciphertext"
        );
    }

    /// A wrap-key entry whose secret is not 32 bytes of hex fails the parse-side
    /// construction with a label-only error that never echoes the bytes.
    #[test]
    fn wrap_key_rejects_malformed_secret() {
        // 31 bytes of hex (one short) and non-hex both fail.
        let short = SecretMaterial(Zeroizing::new(hex::encode([0u8; 31])));
        let err = WebhookWrapKey::from_hex("k".to_string(), "whk".to_string(), &short).unwrap_err();
        assert!(matches!(err, Error::WebhookWrapKeyShape { .. }));

        let not_hex = SecretMaterial(Zeroizing::new("zz_not_hex".to_string()));
        let err =
            WebhookWrapKey::from_hex("k".to_string(), "whk".to_string(), &not_hex).unwrap_err();
        assert!(matches!(err, Error::WebhookWrapKeyShape { .. }));
    }

    /// A wrap key's `Debug` renders its id and label but never the raw key bytes,
    /// and `secret_hex` (the bootstrap-only accessor) round-trips the bytes.
    #[test]
    fn wrap_key_debug_and_secret_hex() {
        let key =
            WebhookWrapKey::generate("webhook-wrap".to_string(), "whk_x".to_string()).expect("gen");
        let dbg = format!("{key:?}");
        assert!(dbg.contains("whk_x"));
        assert!(dbg.contains("webhook-wrap"));
        // The 64-hex key string must never appear in a Debug rendering.
        assert!(!dbg.contains(&*key.secret_hex()));

        // The hex round-trips back to the same key: a key re-parsed from secret_hex
        // opens a blob the original sealed, proving secret_hex is the faithful
        // persistence form.
        let reparsed = WebhookWrapKey::from_hex(
            "webhook-wrap".to_string(),
            "whk_x".to_string(),
            &SecretMaterial(Zeroizing::new(key.secret_hex().to_string())),
        )
        .expect("reparse");
        let blob = key.secret_wrap().seal("s").expect("seal");
        assert_eq!(
            reparsed
                .secret_wrap()
                .open(&blob)
                .expect("cross-open")
                .as_slice(),
            b"s"
        );
    }

    /// The keyring envelope parse rejects a duplicate stable identity across key
    /// classes: a webhook-wrap `key_id` that collides with another entry's
    /// identity is refused, just like a duplicate signing-key address.
    #[test]
    fn parse_rejects_duplicate_identity_across_classes() {
        let json = serde_json::json!({
            "version": 1,
            "entries": [
                { "kind": "cardano-ed25519", "label": "primary",
                  "address": "shared-identity", "secret": "ed25519_sk1x" },
                { "kind": "webhook-wrap", "label": "webhook-wrap",
                  "key_id": "shared-identity", "secret": hex::encode([0u8; 32]) }
            ]
        })
        .to_string();
        let err = KeyringEnvelope::parse(json.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::KeyringShape(_)));
    }
}
