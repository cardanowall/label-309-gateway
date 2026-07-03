//! The `cw_core.storage_upload` receipt ledger.
//!
//! Every accepted upload writes one row recording the content identity (sha256,
//! bytes), the addressable URI and data-item id, the verbatim provider receipt,
//! the bundling parent once known, and which backend produced it. A verifier
//! resolves both the top-level Arweave tx id and the bundled data-item id from
//! these columns.
//!
//! Dedup is by content hash per account AND backend: re-uploading identical
//! bytes to the same backend converges on the existing receipt instead of paying
//! the provider twice, while the same bytes on a different backend is a distinct,
//! separately charged artifact. [`lookup_receipt`] is the pre-upload check the
//! route runs so a dedup hit never reaches the backend; [`persist_receipt`]
//! writes a fresh row and is resilient to a concurrent racer landing the same
//! content first.

use uuid::Uuid;

use crate::storage::backend::StorageReceipt;
use crate::Result;

/// A persisted upload receipt as the route projects it onto the wire.
///
/// The wire `ok` result is `{ idx, ok: true, uri, sha256, bytes }`; this carries
/// the durable identity plus those fields so the route can render either a fresh
/// upload or a dedup hit from the same shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedUpload {
    /// The receipt row's id.
    pub id: Uuid,
    /// The addressable URI (`ar://<data-item-id>`).
    pub uri: String,
    /// The ANS-104 data-item id.
    pub data_item_id: String,
    /// The content SHA-256.
    pub sha256: [u8; 32],
    /// The stored byte count.
    pub bytes: u64,
    /// Whether this row already existed (a dedup hit) rather than being inserted
    /// by this call.
    pub deduped: bool,
}

impl PersistedUpload {
    /// The content digest as lowercase hex (the wire `sha256`).
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }
}

/// The columns read back from a `storage_upload` row.
#[derive(sqlx::FromRow)]
struct UploadRow {
    id: Uuid,
    uri: String,
    data_item_id: String,
    sha256: Vec<u8>,
    bytes: i64,
}

impl UploadRow {
    fn into_persisted(self, deduped: bool) -> Result<PersistedUpload> {
        let sha256: [u8; 32] = self
            .sha256
            .as_slice()
            .try_into()
            .map_err(|_| crate::Error::Config("stored upload sha256 is not 32 bytes".into()))?;
        let bytes = u64::try_from(self.bytes)
            .map_err(|_| crate::Error::Config("stored upload byte count is negative".into()))?;
        Ok(PersistedUpload {
            id: self.id,
            uri: self.uri,
            data_item_id: self.data_item_id,
            sha256,
            bytes,
            deduped,
        })
    }
}

/// Look up an existing receipt for `(account_id, backend, sha256)`, if any.
///
/// The route runs this BEFORE touching the backend: a hit means the account
/// already stored these exact bytes on this backend, so the prior receipt is
/// returned and the provider is never paid a second time. The same bytes stored
/// on a different backend do NOT hit here: each backend's stored copy is its own
/// receipt and its own charge. An account-less (operator-direct) upload is never
/// deduped here (the dedup uniqueness is partial on a non-null account), so this
/// is only meaningful for an account-scoped upload.
pub async fn lookup_receipt(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    backend: &str,
    sha256: &[u8; 32],
) -> Result<Option<PersistedUpload>> {
    let row: Option<UploadRow> = sqlx::query_as(
        "SELECT id, uri, data_item_id, sha256, bytes \
         FROM cw_core.storage_upload \
         WHERE account_id = $1 AND backend = $2 AND sha256 = $3 \
         LIMIT 1",
    )
    .bind(account_id)
    .bind(backend)
    .bind(sha256.as_slice())
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_persisted(true)).transpose()
}

/// Persist a fresh receipt for an account-scoped upload.
///
/// Writes the row with the backend name and content identity. If a concurrent
/// upload of the same content to the same backend for the same account committed
/// first, the account/backend/sha256 dedup uniqueness fires; rather than surface
/// that as an error, the conflict converges on the existing row (the racer's
/// receipt) and reports it as a dedup hit, so two simultaneous uploads of
/// identical bytes to one backend still leave exactly one receipt and both
/// callers get a usable result.
pub async fn persist_receipt(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    sha256: &[u8; 32],
    bytes: u64,
    backend: &str,
    receipt: &StorageReceipt,
) -> Result<PersistedUpload> {
    let id = Uuid::now_v7();
    let bytes_i64 = i64::try_from(bytes)
        .map_err(|_| crate::Error::Config("upload byte count overflows i64".into()))?;

    // INSERT ... ON CONFLICT DO NOTHING returns no row when a racer won the
    // dedup; the caller then reads the winning row back. (The test DB invariant
    // forbids defensive ON CONFLICT for collisions that "cannot happen"; this one
    // genuinely can — two concurrent uploads of identical content to one backend
    // — so the conflict target is the real dedup uniqueness, not a band-aid.)
    let inserted: Option<UploadRow> = sqlx::query_as(
        "INSERT INTO cw_core.storage_upload \
           (id, account_id, sha256, bytes, uri, data_item_id, raw_receipt, root_tx_id, backend) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (account_id, backend, sha256) WHERE account_id IS NOT NULL DO NOTHING \
         RETURNING id, uri, data_item_id, sha256, bytes",
    )
    .bind(id)
    .bind(account_id)
    .bind(sha256.as_slice())
    .bind(bytes_i64)
    .bind(&receipt.uri)
    .bind(&receipt.data_item_id)
    .bind(&receipt.raw_receipt)
    .bind(&receipt.root_tx_id)
    .bind(backend)
    .fetch_optional(pool)
    .await?;

    match inserted {
        Some(row) => row.into_persisted(false),
        None => {
            // A racer landed the same content first; read back its row.
            let existing = lookup_receipt(pool, account_id, backend, sha256)
                .await?
                .ok_or_else(|| {
                    crate::Error::Config(
                        "storage_upload insert hit the dedup conflict but no winning row was found"
                            .into(),
                    )
                })?;
            Ok(existing)
        }
    }
}
