//! The direct-Arweave storage backend (fallback).
//!
//! The zero-third-party fallback: sign and submit a full Arweave transaction
//! (not a bundled ANS-104 data item) directly with the operator's JWK, paying the
//! network fee in AR. It trades Turbo's instant receipt for provider independence.
//!
//! Signing and submitting a full Arweave transaction (the format-2 tx with its
//! own chunked data and reward) is a distinct construction from the ANS-104 data
//! item the `ans104` crate produces, and its signer is not implemented yet. The
//! backend is present as a documented trait impl so the seam is complete and a
//! deployment can select it; it returns a typed misconfiguration until the full
//! Arweave tx builder lands, rather than silently doing nothing.

use std::path::Path;

use crate::storage::backend::{DataItemStatus, StorageBackendExt, StorageError, StorageReceipt};
use crate::storage::funding::AuthorizedFunding;

/// The direct-Arweave fallback backend.
///
/// Constructed over an Arweave gateway URL; the full transaction
/// signing/submission path is not implemented yet.
pub struct DirectArweaveBackend {
    _gateway_url: String,
}

impl DirectArweaveBackend {
    /// Construct the direct-Arweave backend over an Arweave gateway URL.
    #[must_use]
    pub fn new(gateway_url: impl Into<String>) -> Self {
        Self {
            _gateway_url: gateway_url.into(),
        }
    }
}

impl StorageBackendExt for DirectArweaveBackend {
    fn name(&self) -> &'static str {
        "direct-arweave"
    }

    async fn affords(&self, _funding: &AuthorizedFunding, _bytes: u64) -> Result<(), StorageError> {
        // The backend cannot store anything until its full-transaction signer
        // lands, so it affords nothing. The quote and upload routes surface this
        // as a service-unavailable refusal up front rather than failing mid-upload.
        Err(StorageError::Misconfigured(
            "the direct-Arweave backend's full-transaction signer is not yet implemented; \
             use the Turbo backend"
                .into(),
        ))
    }

    async fn upload(
        &self,
        _funding: &AuthorizedFunding,
        _envelope: &ans104::SignedEnvelope,
        _owner: &[u8],
        _staged_path: &Path,
    ) -> Result<StorageReceipt, StorageError> {
        Err(StorageError::Misconfigured(
            "the direct-Arweave backend's full-transaction signer is not yet implemented; \
             use the Turbo backend"
                .into(),
        ))
    }

    async fn lookup_data_item(
        &self,
        _funding: &AuthorizedFunding,
        _data_item_id: &str,
    ) -> Result<DataItemStatus, StorageError> {
        // No provider to query until the full-transaction backend lands; report
        // indeterminate so the recovery sweep never reads a definite answer from a
        // backend that cannot give one.
        Ok(DataItemStatus::Unavailable)
    }
}
