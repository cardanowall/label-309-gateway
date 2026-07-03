//! A minimal Arweave node/gateway HTTP client for the operator funding surface.
//!
//! The base-layer endpoints this client speaks (`/wallet/{address}/balance`,
//! `/tx_anchor`, `/price/{bytes}/{target}`, `POST /tx`) are served identically by
//! a public Arweave gateway (production) and by the ArLocal development emulator,
//! so one client backs both deployments; only the base URL differs. It is used
//! by the control plane's operator-balance read (the live AR balance of the
//! funding wallet) and by the storage top-up (anchor + fee quote + transfer
//! broadcast). It never touches key material: signing happens in the keyring and
//! this client only carries the finished transaction JSON.
//!
//! These calls are operator-initiated (an admin opening the funding console or
//! issuing a top-up), not request-path traffic, so they make live network reads
//! by design — the cached-balance discipline that keeps quotes off external
//! oracles does not apply to an explicit operator refresh.

use crate::storage::backend::StorageError;

/// The minimal Arweave node/gateway client.
pub struct ArweaveNodeClient {
    client: reqwest::Client,
    base_url: String,
}

impl ArweaveNodeClient {
    /// Build a client over an Arweave node/gateway base URL.
    ///
    /// Returns [`StorageError::Misconfigured`] if the TLS-backed client cannot be
    /// built, matching the other storage provider clients.
    pub fn new(base_url: impl Into<String>) -> Result<Self, StorageError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| {
                StorageError::Misconfigured(format!("building Arweave node HTTP client: {e}"))
            })?;
        Ok(Self {
            client,
            base_url: base_url.into(),
        })
    }

    /// Build a client over a caller-supplied reqwest client and base URL, the
    /// seam a behavioural test uses to point the real client at a local fake.
    #[must_use]
    pub fn with_client(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: base_url.into(),
        }
    }

    /// The base URL with any trailing slash trimmed, for joining path segments.
    fn base(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    /// Read a wallet's AR token balance in winston (`GET /wallet/{address}/balance`,
    /// a plain decimal text body).
    pub async fn wallet_balance_winston(&self, address: &str) -> Result<u128, StorageError> {
        let url = format!("{}/wallet/{address}/balance", self.base());
        let text = self.get_text(&url, "AR wallet balance").await?;
        text.trim().parse::<u128>().map_err(|e| {
            StorageError::Unavailable(format!("AR wallet balance is not a number: {e}"))
        })
    }

    /// Fetch the transaction anchor a fresh transaction must reference
    /// (`GET /tx_anchor`, a base64url text body).
    pub async fn tx_anchor(&self) -> Result<String, StorageError> {
        let url = format!("{}/tx_anchor", self.base());
        Ok(self
            .get_text(&url, "transaction anchor")
            .await?
            .trim()
            .to_string())
    }

    /// Quote the network fee, in winston, for a zero-byte transaction to `target`
    /// (`GET /price/0/{target}`, a plain decimal text body) — the reward an AR
    /// transfer must carry.
    pub async fn transfer_price_winston(&self, target: &str) -> Result<u64, StorageError> {
        let url = format!("{}/price/0/{target}", self.base());
        let text = self.get_text(&url, "transfer price").await?;
        text.trim()
            .parse::<u64>()
            .map_err(|e| StorageError::Unavailable(format!("transfer price is not a number: {e}")))
    }

    /// Broadcast a signed format-2 transaction (`POST /tx`).
    ///
    /// A non-2xx is a definite refusal; a transport error is INDETERMINATE (the
    /// node may have received the bytes), which the caller must treat as
    /// "possibly broadcast" rather than "safe to re-sign".
    pub async fn submit_tx(&self, tx_json: &serde_json::Value) -> Result<(), StorageError> {
        let url = format!("{}/tx", self.base());
        let response = self
            .client
            .post(&url)
            .json(tx_json)
            .send()
            .await
            .map_err(|e| StorageError::Unavailable(format!("broadcasting transaction: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = crate::http::read_diagnostic_body(response).await;
            return Err(StorageError::Unavailable(format!(
                "Arweave node refused the transaction ({status}): {}",
                body.chars().take(512).collect::<String>()
            )));
        }
        Ok(())
    }

    /// GET a plain-text endpoint, mapping transport and status failures onto
    /// [`StorageError::Unavailable`] with the operation named.
    async fn get_text(&self, url: &str, what: &str) -> Result<String, StorageError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| StorageError::Unavailable(format!("reading {what}: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(StorageError::Unavailable(format!(
                "{what} endpoint returned {status}"
            )));
        }
        crate::http::read_capped_text(response, crate::http::JSON_BODY_CEILING)
            .await
            .map_err(|e| StorageError::Unavailable(format!("decoding {what}: {e}")))
    }
}
