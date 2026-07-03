//! Building and editing operator keyrings — the write-side counterpart of
//! [`super::keyring::unlock`].
//!
//! The [`KeyringEditor`] is what the `gateway keyring` subcommands drive: it
//! creates an empty envelope, decrypts an existing one for editing, appends or
//! removes entries, and re-encrypts. Two invariants make a file this editor
//! writes impossible to mis-produce:
//!
//! 1. **One derivation.** Every address or key id the editor writes into an
//!    entry is derived by the same functions the unlock check re-derives with
//!    ([`super::keyring::address_for_signing_key`], the Arweave JWK address
//!    derivation, [`WebhookWrapKey`]'s hex form). The editor never accepts a
//!    caller-claimed identity.
//! 2. **A real unlock before every write.** [`KeyringEditor::encrypt`] runs the
//!    produced ciphertext through [`super::keyring::unlock`] — the exact code
//!    path the serving binary boots with — before returning it. A keyring the
//!    editor hands back is therefore always one the gateway can open.
//!
//! The editor mirrors the envelope's JSON shape in its own serializable structs
//! (the read-side types deliberately implement no `Serialize`, so a parsed
//! production envelope can never be accidentally re-serialised). The two shapes
//! cannot drift: the mandatory unlock round-trip parses every written byte with
//! the read-side types.
//!
//! # Secret hygiene
//!
//! Entry secrets live in `EditSecret` (a zeroizing buffer with a redacted
//! `Debug`), the serialized plaintext lives in a zeroizing buffer until it is
//! encrypted, and the editor exposes no accessor that returns a secret: the
//! only outputs are non-secret [`EntrySummary`] values and the ciphertext.

use age::secrecy::SecretString;
use ans104::ArweaveJwkSigner;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::config::Network;
use super::keyring::{
    address_for_signing_key, unlock, verify_entries, ArweaveFundingSigner, KeyringEnvelope,
    WebhookWrapKey, SIGNING_KEY_HRP,
};
use super::operator::address_network_id;
use crate::{Error, Result};

/// The envelope format version this editor writes (and the only one it reads).
const KEYRING_VERSION: u8 = 1;

/// An editable keyring: the decrypted entries of one envelope, plus the
/// operations that grow, shrink, and re-encrypt it.
///
/// Not `Clone` (cloning would duplicate every secret) and its derived `Debug`
/// is safe because every secret field is a redacting `EditSecret`.
#[derive(Debug, Default)]
pub struct KeyringEditor {
    /// The entries in file order. New entries append, so an existing keyring's
    /// order (which decides the active webhook-wrap key) is preserved.
    entries: Vec<EditEntry>,
}

/// One entry's non-secret metadata, the only thing the editor reports about an
/// entry: its kind, its operator-facing label, and its stable identity (a
/// signing key's address, a webhook-wrap key's key id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary {
    /// The entry's key class.
    pub kind: EntryKind,
    /// The operator-facing label.
    pub label: String,
    /// The stable identity: an address for a signing key, a key id for a
    /// webhook-wrap key.
    pub identity: String,
}

/// The key classes a keyring entry can carry, mirroring the envelope's `kind`
/// tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A Cardano ed25519 wallet key that signs anchoring transactions.
    CardanoEd25519,
    /// An Arweave RSA key that signs storage data items.
    ArweaveRsa,
    /// A symmetric data key that encrypts webhook signing secrets at rest.
    WebhookWrap,
}

impl EntryKind {
    /// The `kind` tag string the envelope carries for this class.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::CardanoEd25519 => "cardano-ed25519",
            EntryKind::ArweaveRsa => "arweave-rsa",
            EntryKind::WebhookWrap => "webhook-wrap",
        }
    }
}

impl KeyringEditor {
    /// A new, empty keyring (what `gateway keyring init` encrypts).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decrypt an existing envelope for editing.
    ///
    /// Runs the full read-side pipeline on the plaintext: the structural parse
    /// (version, duplicate identities/labels) and the per-entry verification
    /// the serve path runs at unlock (every claimed address re-derived from its
    /// key), so a hand-edited file that the gateway could not boot with is
    /// refused here too, before any mutation. A wrong passphrase surfaces as
    /// [`Error::KeyringDecrypt`].
    pub fn decrypt(ciphertext: &[u8], passphrase: &str) -> Result<Self> {
        let identity = age::scrypt::Identity::new(SecretString::from(passphrase));
        let plaintext =
            Zeroizing::new(age::decrypt(&identity, ciphertext).map_err(|_| Error::KeyringDecrypt)?);

        // The read-side parse owns the structural checks; the editor never
        // re-implements them.
        let envelope = KeyringEnvelope::parse(&plaintext)?;

        // Parse the same bytes into the editable shape before verification
        // consumes the read-side envelope. Both parses see identical plaintext.
        let edit: EditEntries = serde_json::from_slice(&plaintext)
            .map_err(|e| Error::KeyringShape(format!("plaintext is not the keyring shape: {e}")))?;
        let editor = Self {
            entries: edit.entries,
        };

        // Re-derive and check every entry exactly as the serve unlock does. The
        // verification network is inferred from the entries themselves (see
        // `verification_network`); the file does not record a network.
        verify_entries(envelope, editor.verification_network())?;

        Ok(editor)
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the keyring holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry's non-secret summary, in file order.
    #[must_use]
    pub fn summaries(&self) -> Vec<EntrySummary> {
        self.entries.iter().map(EditEntry::summary).collect()
    }

    /// Generate a fresh Cardano ed25519 signing key from the OS CSPRNG and
    /// append it as a `cardano-ed25519` entry for `network`, returning the
    /// derived enterprise address in the summary.
    pub fn generate_cardano(&mut self, label: &str, network: Network) -> Result<EntrySummary> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut_slice())
            .map_err(|_| Error::Config("reading the OS random source failed".to_string()))?;
        let hrp = bech32::Hrp::parse(SIGNING_KEY_HRP).expect("the signing-key HRP is valid");
        let secret = Zeroizing::new(
            bech32::encode::<bech32::Bech32>(hrp, seed.as_slice()).map_err(|_| {
                Error::Config("encoding the generated signing key failed".to_string())
            })?,
        );
        self.import_cardano(label, network, secret)
    }

    /// Append an existing CIP-5 signing key (`ed25519_sk1...`, normal or
    /// extended) as a `cardano-ed25519` entry for `network`.
    ///
    /// The entry's address is DERIVED from the key — never claimed — with the
    /// same derivation the unlock check re-runs. Refuses a key whose network
    /// disagrees with the keyring's existing Cardano entries (one keyring
    /// serves one network) and a duplicate identity or label.
    pub fn import_cardano(
        &mut self,
        label: &str,
        network: Network,
        secret_bech32: Zeroizing<String>,
    ) -> Result<EntrySummary> {
        let address = address_for_signing_key(&secret_bech32, network)?;
        self.ensure_single_network(label, &address)?;
        self.ensure_label_and_identity_free(label, &address)?;
        self.entries.push(EditEntry::CardanoEd25519 {
            label: label.to_string(),
            address,
            secret: EditSecret(secret_bech32),
        });
        Ok(self.entries.last().expect("just pushed").summary())
    }

    /// Generate a fresh 4096-bit Arweave RSA key and append it as an
    /// `arweave-rsa` entry, returning the derived Arweave address in the
    /// summary. The JWK never leaves the envelope.
    pub fn generate_arweave(&mut self, label: &str) -> Result<EntrySummary> {
        let jwk = ArweaveJwkSigner::generate_jwk_json()
            .map_err(|e| Error::Config(format!("generating an Arweave RSA key failed: {e}")))?;
        self.import_arweave(label, jwk)
    }

    /// Append an existing Arweave RSA private key (full JWK JSON) as an
    /// `arweave-rsa` entry.
    ///
    /// The entry's address is DERIVED from the key's modulus — never claimed —
    /// with the same derivation the unlock check re-runs. Refuses a malformed
    /// JWK and a duplicate identity or label.
    pub fn import_arweave(
        &mut self,
        label: &str,
        jwk_json: Zeroizing<String>,
    ) -> Result<EntrySummary> {
        // Parsing through the funding signer both validates the JWK (a 4096-bit
        // two-prime RSA key) and derives the address the unlock check verifies.
        let signer = ArweaveFundingSigner::from_jwk_json(label.to_string(), &jwk_json)?;
        let address = signer.address().to_string();
        self.ensure_label_and_identity_free(label, &address)?;
        self.entries.push(EditEntry::ArweaveRsa {
            label: label.to_string(),
            address,
            secret: EditSecret(jwk_json),
        });
        Ok(self.entries.last().expect("just pushed").summary())
    }

    /// Mint a fresh 32-byte webhook secret-wrap data key from the OS CSPRNG and
    /// append it as a `webhook-wrap` entry, returning the minted `whk_...` key
    /// id in the summary.
    ///
    /// Appending matters: the NEWEST wrap key in file order is the active one,
    /// so adding a key to a keyring that already holds one is a rotation (new
    /// secrets seal under the new key; old rows still resolve their recorded
    /// `wrap_key_id` until re-wrapped).
    pub fn generate_webhook_wrap(&mut self, label: &str) -> Result<EntrySummary> {
        let key_id = format!("whk_{}", uuid::Uuid::now_v7().simple());
        let key = WebhookWrapKey::generate(label.to_string(), key_id.clone())?;
        self.ensure_label_and_identity_free(label, &key_id)?;
        self.entries.push(EditEntry::WebhookWrap {
            label: label.to_string(),
            key_id,
            secret: EditSecret(key.secret_hex()),
        });
        Ok(self.entries.last().expect("just pushed").summary())
    }

    /// Remove the entry with the given stable identity (a signing key's
    /// address, a webhook-wrap key's key id), returning its summary. Identities
    /// are unique across all classes, so at most one entry can match.
    pub fn remove(&mut self, identity: &str) -> Result<EntrySummary> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.identity() == identity)
            .ok_or_else(|| {
                Error::KeyringShape(format!(
                    "the keyring holds no entry with identity {identity}"
                ))
            })?;
        let removed = self.entries.remove(index);
        Ok(removed.summary())
    }

    /// Serialise, encrypt under `passphrase` (age scrypt recipient at the age
    /// crate's calibrated default work factor), and prove the result opens by
    /// running it through the REAL serve-path [`unlock`] before returning the
    /// ciphertext. A keyring this returns is, by construction, one the gateway
    /// can boot with.
    pub fn encrypt(&self, passphrase: &str) -> Result<Vec<u8>> {
        self.encrypt_inner(passphrase, None)
    }

    /// [`Self::encrypt`] with an explicit scrypt work factor (`N = 2^log_n`).
    ///
    /// The default calibrates the KDF to roughly a second of work, which is the
    /// right cost for a production keyring but a prohibitive constant factor in
    /// a test suite that encrypts dozens of envelopes; tests pass a small
    /// factor instead. The unlock side reads the factor from the file header,
    /// so files written at any factor open the same way.
    pub fn encrypt_with_work_factor(&self, passphrase: &str, log_n: u8) -> Result<Vec<u8>> {
        self.encrypt_inner(passphrase, Some(log_n))
    }

    /// The shared body of [`Self::encrypt`] / [`Self::encrypt_with_work_factor`].
    fn encrypt_inner(&self, passphrase: &str, work_factor: Option<u8>) -> Result<Vec<u8>> {
        // Serialise from borrowed entries (no secret is cloned) into a
        // zeroizing buffer that is wiped once the encryption below consumed it.
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&WireEnvelope {
                version: KEYRING_VERSION,
                entries: &self.entries,
            })
            .map_err(|e| {
                Error::KeyringShape(format!("serialising the keyring envelope failed: {e}"))
            })?,
        );

        let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase));
        if let Some(log_n) = work_factor {
            recipient.set_work_factor(log_n);
        }
        let ciphertext = age::encrypt(&recipient, &plaintext)
            .map_err(|e| Error::KeyringEncrypt(e.to_string()))?;

        // The write gate: round-trip the ciphertext through the exact unlock
        // the serving binary runs at boot. Any disagreement between the write
        // shape and the read shape — or any entry the serve path would refuse —
        // fails here, before the caller ever writes a file.
        unlock(
            &ciphertext,
            Zeroizing::new(passphrase.to_string()),
            self.verification_network(),
        )?;

        Ok(ciphertext)
    }

    /// The network the entries are verified against.
    ///
    /// The envelope records no network (the serving deployment's config
    /// supplies it), but the Cardano address header pins the network family, so
    /// verification infers it from the first Cardano entry: mainnet for network
    /// id 1, preprod otherwise. Preprod stands in for every test network — the
    /// test networks share one network id and derive identical addresses, so
    /// the distinction cannot affect verification. With no Cardano entry any
    /// network verifies the remaining classes; mainnet is used arbitrarily.
    fn verification_network(&self) -> Network {
        self.entries
            .iter()
            .find_map(|entry| match entry {
                EditEntry::CardanoEd25519 { address, .. } => address_network_id(address),
                _ => None,
            })
            .map(|id| {
                if id == Network::Mainnet.network_id() {
                    Network::Mainnet
                } else {
                    Network::Preprod
                }
            })
            .unwrap_or(Network::Mainnet)
    }

    /// Refuse a Cardano entry whose address family (mainnet vs testnet)
    /// disagrees with the keyring's existing Cardano entries: the serve unlock
    /// verifies every entry against ONE configured network, so a mixed keyring
    /// could never boot.
    fn ensure_single_network(&self, label: &str, address: &str) -> Result<()> {
        let Some(new_id) = address_network_id(address) else {
            // Unreachable for a freshly derived address; guard anyway.
            return Err(Error::KeyringShape(format!(
                "entry {label:?} derived an unparseable address"
            )));
        };
        let family = |id: u8| {
            if id == Network::Mainnet.network_id() {
                "mainnet"
            } else {
                "a test network"
            }
        };
        for entry in &self.entries {
            if let EditEntry::CardanoEd25519 {
                address: existing, ..
            } = entry
            {
                if let Some(existing_id) = address_network_id(existing) {
                    if existing_id != new_id {
                        return Err(Error::KeyringNetworkMismatch {
                            label: label.to_string(),
                            claimed: family(new_id).to_string(),
                            expected: family(existing_id).to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Refuse an empty label, a duplicate stable identity, or a duplicate
    /// label — the same constraints [`KeyringEnvelope::parse`] enforces on
    /// read, checked here so the operator gets a clear message at `add` time
    /// instead of a refused write.
    fn ensure_label_and_identity_free(&self, label: &str, identity: &str) -> Result<()> {
        if label.is_empty() {
            return Err(Error::KeyringShape(
                "an entry label must not be empty".to_string(),
            ));
        }
        if let Some(existing) = self.entries.iter().find(|e| e.identity() == identity) {
            return Err(Error::KeyringShape(format!(
                "the keyring already holds this key: entry {:?} has identity {identity}; \
                 remove it first or import a different key",
                existing.label()
            )));
        }
        if self.entries.iter().any(|e| e.label() == label) {
            return Err(Error::KeyringShape(format!(
                "the keyring already holds an entry labelled {label:?}; choose a different label"
            )));
        }
        Ok(())
    }
}

/// The deserialization shape for editing: just the entries. The version field
/// is validated by the read-side [`KeyringEnvelope::parse`] (which always runs
/// first), so it is not duplicated here.
#[derive(Deserialize)]
struct EditEntries {
    /// The entries in file order.
    entries: Vec<EditEntry>,
}

/// The serialization shape: the envelope written from borrowed entries, so no
/// secret is cloned to serialise.
#[derive(Serialize)]
struct WireEnvelope<'a> {
    /// The format version ([`KEYRING_VERSION`]).
    version: u8,
    /// The entries in file order.
    entries: &'a [EditEntry],
}

/// One editable entry, tagged on `kind` — the write-side mirror of the
/// read-side `KeyringEntry`. The mandatory unlock round-trip in
/// [`KeyringEditor::encrypt`] keeps the two shapes from drifting: a
/// mis-serialised envelope cannot survive the write gate.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum EditEntry {
    /// A Cardano ed25519 wallet key.
    CardanoEd25519 {
        /// Operator-facing display name.
        label: String,
        /// The derived enterprise address (the stable identity).
        address: String,
        /// The CIP-5 bech32 signing key, in a redacting [`EditSecret`].
        secret: EditSecret,
    },
    /// An Arweave RSA key.
    ArweaveRsa {
        /// Operator-facing display name.
        label: String,
        /// The derived Arweave address (the stable identity).
        address: String,
        /// The RSA private key as JWK JSON, in a redacting [`EditSecret`].
        secret: EditSecret,
    },
    /// A webhook secret-wrap data key.
    WebhookWrap {
        /// Operator-facing display name.
        label: String,
        /// The minted `whk_...` id (the stable identity).
        key_id: String,
        /// The 32-byte data key, hex-encoded, in a redacting [`EditSecret`].
        secret: EditSecret,
    },
}

impl EditEntry {
    /// The entry's operator-facing label.
    fn label(&self) -> &str {
        match self {
            EditEntry::CardanoEd25519 { label, .. }
            | EditEntry::ArweaveRsa { label, .. }
            | EditEntry::WebhookWrap { label, .. } => label,
        }
    }

    /// The entry's stable identity (address or key id).
    fn identity(&self) -> &str {
        match self {
            EditEntry::CardanoEd25519 { address, .. } | EditEntry::ArweaveRsa { address, .. } => {
                address
            }
            EditEntry::WebhookWrap { key_id, .. } => key_id,
        }
    }

    /// The entry's non-secret summary.
    fn summary(&self) -> EntrySummary {
        let kind = match self {
            EditEntry::CardanoEd25519 { .. } => EntryKind::CardanoEd25519,
            EditEntry::ArweaveRsa { .. } => EntryKind::ArweaveRsa,
            EditEntry::WebhookWrap { .. } => EntryKind::WebhookWrap,
        };
        EntrySummary {
            kind,
            label: self.label().to_string(),
            identity: self.identity().to_string(),
        }
    }
}

/// An editable entry's secret, held in a zeroizing buffer.
///
/// Serialises as the plain secret string (that is the write path's whole job)
/// but never renders it through `Debug`, so an accidental `{:?}` on the editor
/// or an entry cannot leak a key into a terminal or a log. Wiped on drop; not
/// `Clone`.
struct EditSecret(Zeroizing<String>);

impl Serialize for EditSecret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EditSecret {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Move the transient String serde produced straight into the zeroizing
        // wrapper, the same pattern the read-side secret type uses.
        let raw = String::deserialize(deserializer)?;
        Ok(EditSecret(Zeroizing::new(raw)))
    }
}

impl std::fmt::Debug for EditSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EditSecret([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::keyring::derive_enterprise_address;
    use pallas_crypto::key::ed25519::SecretKey;

    /// A deliberately low scrypt work factor so each in-test encrypt/unlock is
    /// fast. The unlock side reads the factor from the file header.
    const TEST_LOG_N: u8 = 4;

    /// The 4096-bit RSA JWK fixture the ans104 vector suite ships.
    const TEST_JWK_JSON: &str = include_str!("../../../ans104/tests/vectors/test-jwk.json");

    /// A deterministic CIP-5 signing key from a fixed seed, plus the address it
    /// must derive to on `network` (computed independently of the editor).
    fn fixed_wallet(seed: [u8; 32], network: Network) -> (Zeroizing<String>, String) {
        let secret = SecretKey::from(seed);
        let mut vk = [0u8; 32];
        vk.copy_from_slice(secret.public_key().as_ref());
        let hrp = bech32::Hrp::parse("ed25519_sk").expect("valid hrp");
        let bech = bech32::encode::<bech32::Bech32>(hrp, &seed).expect("encode skey");
        let address = derive_enterprise_address(&vk, network).expect("derive address");
        (Zeroizing::new(bech), address)
    }

    /// An empty keyring round-trips: `init` writes it, the serve-path unlock
    /// opens it (reporting empty), and the editor re-opens it for the first
    /// `add`.
    #[test]
    fn an_empty_keyring_round_trips() {
        let editor = KeyringEditor::new();
        let ciphertext = editor
            .encrypt_with_work_factor("passphrase", TEST_LOG_N)
            .expect("encrypt the empty keyring");

        let unlocked = unlock(
            &ciphertext,
            Zeroizing::new("passphrase".to_string()),
            Network::Preprod,
        )
        .expect("the serve-path unlock opens an empty keyring");
        assert!(unlocked.is_empty());

        let reopened = KeyringEditor::decrypt(&ciphertext, "passphrase").expect("reopen");
        assert!(reopened.is_empty());
        assert_eq!(reopened.len(), 0);
    }

    /// A generated Cardano key derives an address on the requested network:
    /// `addr1...` on mainnet, `addr_test1...` on preprod.
    #[test]
    fn generated_cardano_addresses_match_their_network() {
        let mut mainnet = KeyringEditor::new();
        let summary = mainnet
            .generate_cardano("primary", Network::Mainnet)
            .expect("generate mainnet");
        assert!(
            summary.identity.starts_with("addr1"),
            "a mainnet enterprise address starts addr1, got {}",
            summary.identity
        );

        let mut preprod = KeyringEditor::new();
        let summary = preprod
            .generate_cardano("primary", Network::Preprod)
            .expect("generate preprod");
        assert!(
            summary.identity.starts_with("addr_test1"),
            "a preprod enterprise address starts addr_test1, got {}",
            summary.identity
        );
    }

    /// An imported signing key's entry carries exactly the address the key
    /// derives to — the editor never invents or accepts a claim.
    #[test]
    fn an_imported_cardano_key_gets_its_derived_address() {
        let (secret, expected_address) = fixed_wallet([7u8; 32], Network::Preprod);
        let mut editor = KeyringEditor::new();
        let summary = editor
            .import_cardano("imported", Network::Preprod, secret)
            .expect("import");
        assert_eq!(summary.identity, expected_address);
        assert_eq!(summary.kind, EntryKind::CardanoEd25519);
    }

    /// A keyring with one entry of every class encrypts, and the serve-path
    /// unlock sees each entry exactly where its consumer looks for it: the
    /// wallet in `wallets()`, the funding key in `arweave_funding_keys()`, the
    /// wrap key as the active one.
    #[test]
    fn a_full_keyring_unlocks_through_the_serve_path() {
        let mut editor = KeyringEditor::new();
        let wallet = editor
            .generate_cardano("primary", Network::Preprod)
            .expect("generate cardano");
        let funding = editor
            .import_arweave("storage", Zeroizing::new(TEST_JWK_JSON.to_string()))
            .expect("import arweave");
        let wrap = editor
            .generate_webhook_wrap("webhook-wrap")
            .expect("generate wrap key");
        assert!(wrap.identity.starts_with("whk_"));

        let ciphertext = editor
            .encrypt_with_work_factor("passphrase", TEST_LOG_N)
            .expect("encrypt");
        let unlocked = unlock(
            &ciphertext,
            Zeroizing::new("passphrase".to_string()),
            Network::Preprod,
        )
        .expect("the serve-path unlock opens the file");

        let wallets = unlocked.wallets();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].address, wallet.identity);
        assert_eq!(wallets[0].label, "primary");

        let funding_keys = unlocked.arweave_funding_keys();
        assert_eq!(funding_keys.len(), 1);
        assert_eq!(funding_keys[0].address, funding.identity);

        let active = unlocked
            .active_webhook_wrap_key()
            .expect("the wrap key is present");
        assert_eq!(active.key_id(), wrap.identity);
    }

    /// Decrypt-then-mutate preserves the existing entries byte-for-byte: a
    /// keyring grown across several invocations still opens with every key.
    #[test]
    fn editing_an_existing_keyring_preserves_its_entries() {
        let mut editor = KeyringEditor::new();
        let first = editor
            .generate_cardano("primary", Network::Preprod)
            .expect("generate");
        let ciphertext = editor
            .encrypt_with_work_factor("passphrase", TEST_LOG_N)
            .expect("encrypt");

        let mut reopened = KeyringEditor::decrypt(&ciphertext, "passphrase").expect("reopen");
        reopened
            .generate_webhook_wrap("webhook-wrap")
            .expect("add a wrap key");
        let grown = reopened
            .encrypt_with_work_factor("passphrase", TEST_LOG_N)
            .expect("re-encrypt");

        let unlocked = unlock(
            &grown,
            Zeroizing::new("passphrase".to_string()),
            Network::Preprod,
        )
        .expect("unlock the grown keyring");
        assert_eq!(unlocked.wallets()[0].address, first.identity);
        assert!(unlocked.active_webhook_wrap_key().is_some());
    }

    /// The same key cannot be added twice: the stable identity collides even
    /// under a different label.
    #[test]
    fn a_duplicate_identity_is_refused() {
        let (secret, _) = fixed_wallet([3u8; 32], Network::Preprod);
        let secret_again = Zeroizing::new(secret.to_string());
        let mut editor = KeyringEditor::new();
        editor
            .import_cardano("first", Network::Preprod, secret)
            .expect("first import");
        let err = editor
            .import_cardano("second", Network::Preprod, secret_again)
            .expect_err("the same key must be refused");
        assert!(
            err.to_string().contains("already holds this key"),
            "the error explains the duplicate, got: {err}"
        );
    }

    /// Two entries cannot share a label (across classes), and a label cannot be
    /// empty — the same constraints the read-side parse enforces.
    #[test]
    fn a_duplicate_or_empty_label_is_refused() {
        let mut editor = KeyringEditor::new();
        editor
            .generate_cardano("primary", Network::Preprod)
            .expect("first entry");
        let err = editor
            .generate_webhook_wrap("primary")
            .expect_err("a shared label must be refused");
        assert!(err.to_string().contains("labelled"), "got: {err}");

        let err = editor
            .generate_cardano("", Network::Preprod)
            .expect_err("an empty label must be refused");
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    /// One keyring serves one network: a mainnet key cannot join a preprod
    /// keyring (the serve unlock would refuse the file wholesale).
    #[test]
    fn mixed_networks_are_refused() {
        let mut editor = KeyringEditor::new();
        editor
            .generate_cardano("preprod", Network::Preprod)
            .expect("preprod entry");
        let err = editor
            .generate_cardano("mainnet", Network::Mainnet)
            .expect_err("a mainnet key must not join a preprod keyring");
        assert!(
            matches!(err, Error::KeyringNetworkMismatch { .. }),
            "got: {err}"
        );
    }

    /// A wrong passphrase fails the decrypt with the opaque decrypt error.
    #[test]
    fn a_wrong_passphrase_is_refused() {
        let editor = KeyringEditor::new();
        let ciphertext = editor
            .encrypt_with_work_factor("right", TEST_LOG_N)
            .expect("encrypt");
        let err = KeyringEditor::decrypt(&ciphertext, "wrong").expect_err("wrong passphrase");
        assert!(matches!(err, Error::KeyringDecrypt), "got: {err}");
    }

    /// Removal is by stable identity, removes exactly one entry, and an unknown
    /// identity is a clear error.
    #[test]
    fn remove_deletes_one_entry_by_identity() {
        let mut editor = KeyringEditor::new();
        let kept = editor
            .generate_cardano("kept", Network::Preprod)
            .expect("kept entry");
        let removed = editor
            .generate_webhook_wrap("webhook-wrap")
            .expect("doomed entry");

        let summary = editor.remove(&removed.identity).expect("remove");
        assert_eq!(summary.identity, removed.identity);
        assert_eq!(editor.len(), 1);
        assert_eq!(editor.summaries()[0].identity, kept.identity);

        let err = editor
            .remove(&removed.identity)
            .expect_err("removing it twice must fail");
        assert!(err.to_string().contains("no entry"), "got: {err}");
    }

    /// Re-encrypting under a new passphrase rotates it: the old passphrase no
    /// longer opens the file, the new one does, and the entries survive.
    #[test]
    fn reencrypting_rotates_the_passphrase() {
        let mut editor = KeyringEditor::new();
        let wallet = editor
            .generate_cardano("primary", Network::Preprod)
            .expect("entry");
        let old = editor
            .encrypt_with_work_factor("old", TEST_LOG_N)
            .expect("encrypt under old");

        let reopened = KeyringEditor::decrypt(&old, "old").expect("open with old");
        let rotated = reopened
            .encrypt_with_work_factor("new", TEST_LOG_N)
            .expect("re-encrypt under new");

        assert!(matches!(
            KeyringEditor::decrypt(&rotated, "old").expect_err("old passphrase must fail"),
            Error::KeyringDecrypt
        ));
        let unlocked = unlock(
            &rotated,
            Zeroizing::new("new".to_string()),
            Network::Preprod,
        )
        .expect("the new passphrase opens the file");
        assert_eq!(unlocked.wallets()[0].address, wallet.identity);
    }

    /// No `Debug` rendering of the editor leaks a secret: the entries print
    /// labels and identities, the secrets print redacted.
    #[test]
    fn debug_never_renders_an_edit_secret() {
        let (secret, _) = fixed_wallet([5u8; 32], Network::Preprod);
        let secret_str = secret.to_string();
        let mut editor = KeyringEditor::new();
        editor
            .import_cardano("primary", Network::Preprod, secret)
            .expect("import");
        let rendered = format!("{editor:?}");
        assert!(!rendered.contains(&secret_str));
        assert!(!rendered.contains("ed25519_sk1"));
        assert!(rendered.contains("redacted"));
        assert!(rendered.contains("primary"));
    }
}
