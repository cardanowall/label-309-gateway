//! The ArLocal storage backend (development only).
//!
//! ArLocal is a local Arweave emulator used in dev and integration tests. It speaks
//! only the base-layer transaction API (`POST /tx`): it does not accept a bare
//! ANS-104 data item, only a signed Arweave format-2 transaction whose payload is a
//! bundle, recognised by the `Bundle-Format: binary` / `Bundle-Version: 2.0.0`
//! tags. So this backend reconstructs the once-signed inner data item, frames it
//! into a one-item bundle, signs an outer base-layer transaction carrying that
//! bundle with the operator's Arweave key, funds the wallet on the emulator, posts
//! the transaction, and mines a block. The emulator unbundles the inner item and
//! stores it under its own id — the same content-addressed id production resolves at
//! — so the receipt is keyed on the inner data-item id, exactly as the Turbo path
//! is.
//!
//! The inner data item is still signed ONCE in the route (its signature, and so its
//! id, is fixed before the first POST); this backend never re-signs the inner item,
//! so a retry reconstructs byte-identical inner bytes and resolves to the same
//! `ar://` uri. The outer base-layer transaction is a disposable carrier: it may be
//! re-signed on a retry because its id is not the content address.
//!
//! The backend REFUSES to construct when the deployment is configured for a
//! production network, so a dev emulator can never be left wired in production.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ans104::{reconstruct_prefix, BundleItem, SignedEnvelope, Tag};

use crate::storage::backend::{DataItemStatus, StorageBackendExt, StorageError, StorageReceipt};
use crate::storage::funding::AuthorizedFunding;
use crate::wallet::keyring::UnlockedKeyring;

/// The wall-clock ceiling on any ArLocal HTTP call (mint, post, mine, HEAD).
///
/// Every request this dev backend makes is small — the emulator caps payloads well
/// below the streaming threshold, and mint/mine/HEAD are tiny — so one bounded
/// deadline covers them all. The deadline matters because the singleton
/// crash-recovery sweep drives this backend with NO outer timeout: without a
/// request-level deadline a stalled ArLocal would hang the whole recovery loop, the
/// same hang class the Turbo backend's timeout closes. 30s is ample for a local
/// emulator while still bounding a stall.
const ARLOCAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Balance minted to the outer transaction's wallet before posting, in winston.
///
/// The emulator requires the wallet to afford the transaction's reward floor
/// (`round(data_size/1000 * rate)`); minting a fixed, comfortably large balance per
/// post covers any dev payload without tracking a running balance. The mint is
/// idempotent for a wallet (it sets, not increments, on a fresh emulator), so a
/// retry that re-mints is harmless.
const MINT_BALANCE_WINSTON: u64 = 1_000_000_000_000_000;

/// The ArLocal dev backend: the local endpoint, the keyring that signs the outer
/// transaction, and a production guard.
pub struct ArLocalBackend {
    endpoint: String,
    keyring: Arc<UnlockedKeyring>,
    client: reqwest::Client,
}

impl ArLocalBackend {
    /// Construct the ArLocal backend.
    ///
    /// `is_production` is the deployment's network posture: when true the backend
    /// refuses to construct, because ArLocal is a dev emulator and must never serve
    /// production uploads. `endpoint` is the local ArLocal URL. `keyring` is the
    /// unlocked operator keyring; the outer base-layer transaction is signed with
    /// the Arweave key the upload's funding capability names, resolved through that
    /// capability so a bare address can never reach a signer.
    pub fn new(
        endpoint: impl Into<String>,
        is_production: bool,
        keyring: Arc<UnlockedKeyring>,
    ) -> Result<Self, StorageError> {
        if is_production {
            return Err(StorageError::Misconfigured(
                "the ArLocal backend is a development emulator and must not be used in production"
                    .into(),
            ));
        }
        // A bounded client so a stalled emulator cannot hang the singleton recovery
        // sweep (which calls this backend with no outer timeout). A timeout-only
        // builder is infallible; never fall back to a timeout-less client.
        let client = reqwest::Client::builder()
            .timeout(ARLOCAL_TIMEOUT)
            .build()
            .expect("a reqwest client builder with only a timeout set is infallible");
        Ok(Self {
            endpoint: endpoint.into(),
            keyring,
            client,
        })
    }

    /// The endpoint with any trailing slash trimmed, for joining path segments.
    fn base(&self) -> &str {
        self.endpoint.trim_end_matches('/')
    }
}

impl StorageBackendExt for ArLocalBackend {
    fn name(&self) -> &'static str {
        "arlocal"
    }

    // ArLocal mints free balance, so it always affords any size: the default
    // always-Ok `affords` is exactly right and is intentionally not overridden.

    async fn upload(
        &self,
        funding: &AuthorizedFunding,
        envelope: &SignedEnvelope,
        owner: &[u8],
        staged_path: &Path,
    ) -> Result<StorageReceipt, StorageError> {
        // Resolve the Arweave signer through the funding capability: the keyring is
        // the capability gate, so a bare address can never reach a signing key.
        let signer = self.keyring.arweave_signer_for(funding).ok_or_else(|| {
            StorageError::Misconfigured(
                "this instance does not hold the Arweave key for the resolved funding source"
                    .into(),
            )
        })?;

        // Reconstruct the once-signed inner data item in full: the bounded prefix
        // (which the signature commits to) followed by the staged payload. The
        // emulator caps payloads well below any streaming threshold, so holding the
        // inner item in memory here is safe; this never runs in production.
        let inner_item = reconstruct_inner_item(envelope, owner, staged_path).await?;

        // Frame the inner item into a one-item ANS-104 binary bundle.
        let bundle = ans104::encode_bundle(&[BundleItem {
            id: &envelope.id,
            bytes: &inner_item,
        }])
        .map_err(|e| StorageError::Build(format!("encoding the bundle: {e}")))?;

        // Sign the outer base-layer transaction carrying the bundle. The bundle
        // tags are what make the emulator unbundle and store the inner item under
        // its own id. `last_tx` is empty (the genesis anchor a fresh emulator
        // accepts), and the reward is the emulator's own per-size floor.
        let reward = ans104::reward_for(bundle.len() as u64);
        let bundle_tags = [
            Tag::new("Bundle-Format", "binary"),
            Tag::new("Bundle-Version", "2.0.0"),
        ];
        let tx = signer
            .sign_tx_v2(&bundle, &bundle_tags, "", reward)
            .map_err(|e| StorageError::Build(format!("signing the carrier transaction: {e}")))?;

        // Fund the outer wallet so the emulator accepts the transaction's reward,
        // post the transaction, then mine a block so the item is queryable.
        self.mint(signer.address()).await?;
        self.post_tx(&tx.to_json()).await?;
        self.mine().await?;

        // The receipt resolves at the INNER data-item id (the content address),
        // never the disposable outer transaction id, so dedup, lookup, and recovery
        // key on the same id the Turbo path does.
        let data_item_id = envelope.id_b64url.clone();
        Ok(StorageReceipt {
            uri: format!("ar://{data_item_id}"),
            data_item_id,
            raw_receipt: serde_json::json!({
                "backend": "arlocal",
                "carrier_tx_id": tx.id_b64url(),
            }),
            root_tx_id: Some(tx.id_b64url()),
        })
    }

    async fn lookup_data_item(
        &self,
        _funding: &AuthorizedFunding,
        data_item_id: &str,
    ) -> Result<DataItemStatus, StorageError> {
        // ArLocal serves a stored item at its id off the gateway root; a 2xx is
        // present, a 404 is a definite absent, anything else is indeterminate.
        let url = format!("{}/{data_item_id}", self.base());
        match self.client.head(&url).send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    Ok(DataItemStatus::Present)
                } else if status.as_u16() == 404 {
                    Ok(DataItemStatus::Absent)
                } else {
                    Ok(DataItemStatus::Unavailable)
                }
            }
            Err(_) => Ok(DataItemStatus::Unavailable),
        }
    }
}

impl ArLocalBackend {
    /// Mint a comfortable balance to `address` so the emulator accepts the carrier
    /// transaction's reward. The mint is a GET on a fresh emulator and is idempotent
    /// per wallet, so a retry that re-mints does no harm.
    async fn mint(&self, address: &str) -> Result<(), StorageError> {
        let url = format!("{}/mint/{address}/{MINT_BALANCE_WINSTON}", self.base());
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| StorageError::Unavailable(format!("minting ArLocal balance: {e}")))?;
        if !response.status().is_success() {
            return Err(StorageError::Unavailable(format!(
                "ArLocal mint returned {}",
                response.status()
            )));
        }
        Ok(())
    }

    /// POST the signed format-2 transaction JSON to the emulator's `/tx` endpoint.
    async fn post_tx(&self, tx_json: &serde_json::Value) -> Result<(), StorageError> {
        let url = format!("{}/tx", self.base());
        let response = self
            .client
            .post(&url)
            .json(tx_json)
            .send()
            .await
            .map_err(|e| StorageError::Unavailable(format!("posting to ArLocal: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = crate::http::read_diagnostic_body(response).await;
            return Err(StorageError::Unavailable(format!(
                "ArLocal returned {status}: {body}"
            )));
        }
        Ok(())
    }

    /// Mine a block so the just-posted transaction (and its unbundled item) is
    /// queryable.
    async fn mine(&self) -> Result<(), StorageError> {
        let url = format!("{}/mine", self.base());
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| StorageError::Unavailable(format!("mining ArLocal block: {e}")))?;
        if !response.status().is_success() {
            return Err(StorageError::Unavailable(format!(
                "ArLocal mine returned {}",
                response.status()
            )));
        }
        Ok(())
    }
}

/// Reconstruct the canonical bytes of the once-signed inner data item: the bounded
/// prefix the signature commits to, followed by the staged payload.
///
/// This materialises the inner item in memory, which is acceptable only because the
/// emulator caps payloads at a small size and this path never runs in production;
/// the Turbo path streams instead. Returns [`StorageError::Build`] for a malformed
/// envelope/owner and [`StorageError::Io`] for a missing or unreadable staged file.
async fn reconstruct_inner_item(
    envelope: &SignedEnvelope,
    owner: &[u8],
    staged_path: &Path,
) -> Result<Vec<u8>, StorageError> {
    let prefix = reconstruct_prefix(envelope, owner)
        .map_err(|e| StorageError::Build(format!("reconstructing data-item prefix: {e}")))?;
    let payload = tokio::fs::read(staged_path)
        .await
        .map_err(|e| StorageError::Io(format!("reading staged file: {e}")))?;

    let mut item = Vec::with_capacity(prefix.len() + payload.len());
    item.extend_from_slice(&prefix);
    item.extend_from_slice(&payload);
    Ok(item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::keyring::UnlockedKeyring;

    fn empty_keyring() -> Arc<UnlockedKeyring> {
        // The production guard fails before the keyring is ever consulted, so an
        // empty keyring is sufficient to exercise it.
        Arc::new(UnlockedKeyring::empty_for_tests())
    }

    #[test]
    fn refuses_to_construct_in_production() {
        // The production guard fails before any endpoint is contacted.
        let result = ArLocalBackend::new("http://localhost:1984", true, empty_keyring());
        assert!(
            matches!(result, Err(StorageError::Misconfigured(_))),
            "the production guard rejects the dev backend"
        );
    }
}
