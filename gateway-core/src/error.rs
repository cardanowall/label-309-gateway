//! The engine's error type.

/// Convenience alias for results returned by the engine.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors surfaced by the gateway engine.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A database operation failed.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Applying the embedded migrations failed.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// A cron expression could not be parsed or evaluated.
    #[error("cron error: {0}")]
    Cron(String),

    /// A job referenced by id was not found.
    #[error("job not found: {0}")]
    JobNotFound(uuid::Uuid),

    /// A write was attempted against a job this worker no longer owns: its
    /// claim token did not match, or the job was no longer `running`. The
    /// fenced write no-ops; callers treat this as lost ownership and stop side
    /// effects.
    #[error("lost ownership of job {0}")]
    LostOwnership(uuid::Uuid),

    /// A queue was referenced that has no registered policy.
    #[error("no policy registered for queue {0}")]
    UnknownQueue(String),

    /// A payload could not be serialized or deserialized.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A configuration value was missing or malformed (for example a database
    /// URL that carries no database name).
    #[error("configuration error: {0}")]
    Config(String),

    /// A publish quote was requested for a record larger than what could fit a
    /// Cardano transaction's metadata budget. A client error, not an
    /// infrastructure fault: the caller must publish a smaller record. Carries the
    /// requested size and the maximum so the caller can see by how much it
    /// overshot.
    #[error("record of {record_bytes} bytes exceeds the maximum quotable size of {max} bytes")]
    QuoteRecordTooLarge {
        /// The record size, in bytes, the quote was requested for.
        record_bytes: u32,
        /// The maximum record size, in bytes, a quote may be created for.
        max: u32,
    },

    /// An outbound request to a chain data provider failed (transport error,
    /// non-success status, or a response body that did not decode).
    ///
    /// This is the raw, unclassified form. A failure whose transport/status
    /// class the failover wrapper must act on is raised as
    /// [`Error::ChainProviderClassified`] instead, so the class travels in the
    /// type system rather than in a parseable string.
    #[error("chain provider error: {0}")]
    ChainProvider(String),

    /// A chain-provider failure whose transport/status class is carried in the
    /// type, so the failover wrapper decides whether to fail over (and whether to
    /// arm the per-provider cooldown) from the value, never by re-parsing a
    /// message. The `detail` is a human-readable description for logs.
    #[error("chain provider error ({class:?}): {detail}")]
    ChainProviderClassified {
        /// The transport/status class of the failure.
        class: crate::chain::gateway::ChainErrorClass,
        /// A human-readable description of what happened.
        detail: String,
    },

    /// Every chain provider in the failover pair is rate-limiting us: the primary
    /// and the secondary both returned (or are parked behind) an HTTP 429. The
    /// failover wrapper raises this after engaging the cooldown on every parked
    /// provider; the submit, confirm, and scan loops all map it to a defer for the
    /// carried window rather than failing the iteration, so a sustained storm
    /// parks the loops without burning their attempts.
    #[error("all chain providers are rate-limited until {cooldown_until}")]
    ChainRateLimitStorm {
        /// The instant the soonest provider cooldown lifts; the defer targets it.
        cooldown_until: chrono::DateTime<chrono::Utc>,
    },

    /// No stored protocol parameters exist for a network. A reader that finds
    /// the cache empty for the requested network returns this rather than a
    /// silent default, because the fee and minimum-ADA computation has no safe
    /// fallback value to invent.
    #[error("no protocol parameters stored for network {0}")]
    ParamsNotFound(String),

    /// The operator keyring could not be decrypted (wrong passphrase, tampered
    /// file, or a corrupt envelope). The message never echoes the passphrase or
    /// any key material.
    #[error("operator keyring decryption failed")]
    KeyringDecrypt,

    /// The operator keyring plaintext did not match the expected shape: an
    /// unsupported version, a malformed signing key, or a duplicate
    /// address/label. Also raised by the keyring editor when a mutation would
    /// produce such a shape (a duplicate identity or label, an empty label).
    #[error("operator keyring is malformed: {0}")]
    KeyringShape(String),

    /// Encrypting a keyring envelope failed. The message carries only the
    /// underlying encryption error, never the plaintext or the passphrase.
    #[error("operator keyring encryption failed: {0}")]
    KeyringEncrypt(String),

    /// A keyring entry's signing key derived to a different address than the one
    /// it claims. Carries the label so the operator can find the bad entry; it
    /// never includes the key. A wrong-key entry fails the whole unlock.
    #[error("operator keyring entry {label:?} address does not match its signing key")]
    KeyringAddressMismatch {
        /// The operator-facing label of the offending entry.
        label: String,
    },

    /// An Arweave funding entry's secret was not a parseable RSA JWK (malformed
    /// JSON, bad base64url, or a modulus that is not 4096-bit). Carries the label
    /// so the operator can find the bad entry; it never includes the key material.
    /// A malformed JWK fails the whole unlock.
    #[error("operator keyring entry {label:?} is not a valid Arweave RSA key")]
    KeyringInvalidJwk {
        /// The operator-facing label of the offending entry.
        label: String,
    },

    /// A keyring entry's address belongs to a different Cardano network than the
    /// configured one (a preprod address under a mainnet config, or the reverse).
    #[error("operator keyring entry {label:?} is for network {claimed}, expected {expected}")]
    KeyringNetworkMismatch {
        /// The operator-facing label of the offending entry.
        label: String,
        /// The network the entry's address encodes.
        claimed: String,
        /// The network the deployment is configured for.
        expected: String,
    },

    /// Building or signing a wallet transaction failed (a split or submit could
    /// not be assembled from validated inputs).
    #[error("wallet transaction build error: {0}")]
    WalletBuild(String),

    /// Signing an Arweave storage data item with a funding key failed. The
    /// message never echoes the key or the signed bytes.
    #[error("arweave data-item signing error: {0}")]
    ArweaveSign(String),

    /// A webhook secret-wrap data key in the keyring was malformed (not the
    /// expected 32-byte length, or not valid hex). Carries the label so the
    /// operator can find the bad entry; it never includes the key material. A
    /// malformed wrap key fails the whole unlock.
    #[error("operator keyring webhook-wrap entry {label:?} is not a valid 32-byte data key")]
    WebhookWrapKeyShape {
        /// The operator-facing label of the offending entry.
        label: String,
    },

    /// Encrypting or decrypting a webhook signing secret under the wrap data key
    /// failed: a truncated ciphertext, a wrong/rotated key, or a tampered
    /// envelope. The message never echoes the secret, the ciphertext, or the key.
    #[error("webhook secret wrap/unwrap failed")]
    WebhookSecretWrap,
}
