//! The Turbo storage backend (the default).
//!
//! POSTs a pre-signed ANS-104 data item to a Turbo upload service
//! (`<upload_url>/v1/tx/arweave`). The data item is signed ONCE in the route with
//! the operator's Arweave key (held in the keyring, reached only through a funding
//! capability), so this backend never signs: it reconstructs the canonical bytes
//! from the persisted signed envelope plus the durable staged content — streaming
//! the staged file as the trailing payload so a multi-gigabyte upload is never
//! buffered — and POSTs them. Turbo returns a receipt immediately (the data item is
//! addressable in seconds), so the receipt is acceptance, not on-chain finality.
//!
//! Funding model: content within the free window (handled by the caller's quote)
//! posts at zero balance; larger content draws the operator's prepaid Turbo credit.
//! [`affords`](StorageBackendExt::affords) reads the cached winc balance the
//! reconcile loop maintains (no provider call on the request path); a provider
//! 402/429/503 maps to a typed [`StorageError`] so the upload route can surface the
//! right problem. [`lookup_data_item`](StorageBackendExt::lookup_data_item) asks the
//! provider whether a data item has landed, which the crash-recovery sweep needs.

use std::path::Path;
use std::time::Duration;

use rust_decimal::Decimal;

use crate::storage::backend::{DataItemStatus, StorageBackendExt, StorageError, StorageReceipt};
use crate::storage::body::streamed_data_item_body;
use crate::storage::credit::{affords as cached_affords, AffordVerdict};
use crate::storage::funding::AuthorizedFunding;

/// The wall-clock ceiling on a data-item lookup (the recovery sweep's HEAD). A
/// lookup is a single small request, so it shares the short deadline every other
/// provider client in the gateway uses; only the upload POST — which streams a
/// potentially multi-gigabyte body — gets the longer upload deadline.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(20);

/// The Turbo backend: the upload-service URL, the gateway URL a data-item lookup
/// hits, the pool the cached-credit affordability read uses, and the winc safety
/// floor that read enforces.
///
/// Two HTTP clients carry distinct deadlines: `upload_client` wraps the streamed
/// data-item POST under the operator-configured upload timeout, and `lookup_client`
/// wraps the small data-item HEAD under a short fixed deadline. A request-level
/// deadline on both clients is what keeps a TCP-level stall at the provider from
/// hanging a caller forever — most importantly the singleton crash-recovery sweep,
/// which calls these directly with no outer `tokio::time::timeout`. The live
/// data-plane upload path keeps its own outer deadline as belt-and-suspenders.
pub struct TurboBackend {
    pool: sqlx::PgPool,
    upload_url: String,
    gateway_url: String,
    winc_safety_floor: Decimal,
    upload_client: reqwest::Client,
    lookup_client: reqwest::Client,
}

impl TurboBackend {
    /// Construct the backend.
    ///
    /// `upload_url` is the Turbo upload-service base (the POST target); `gateway_url`
    /// is the Arweave gateway base a data-item GET resolves against. The pool backs
    /// the cached-credit affordability read, and `winc_safety_floor` is the balance
    /// below which the backend refuses (a per-deployment operator setting). No key
    /// material lives here: signing happens in the route through the keyring.
    ///
    /// `upload_timeout` is the same ceiling the data-plane upload path wraps the POST
    /// in; threading it into the POST client means even the crash-recovery sweep's
    /// re-POST (which has no outer deadline) cannot hang on a stalled provider socket.
    /// The lookup HEAD gets the short fixed `LOOKUP_TIMEOUT` instead, matching the
    /// other small-request provider clients.
    #[must_use]
    pub fn new(
        pool: sqlx::PgPool,
        upload_url: impl Into<String>,
        gateway_url: impl Into<String>,
        winc_safety_floor: Decimal,
        upload_timeout: Duration,
    ) -> Self {
        // A timeout-only client builder is infallible (it allocates no TLS backend
        // config that could fail), so the build genuinely cannot error here. Never
        // fall back to a default client on an Err: that would silently produce a
        // TIMEOUT-LESS client and reintroduce the stall it is built to prevent. Panic
        // at boot instead, which a deployment notices immediately rather than
        // discovering a hung recovery loop in production.
        let upload_client = reqwest::Client::builder()
            .timeout(upload_timeout)
            .build()
            .expect("a reqwest client builder with only a timeout set is infallible");
        let lookup_client = reqwest::Client::builder()
            .timeout(LOOKUP_TIMEOUT)
            .build()
            .expect("a reqwest client builder with only a timeout set is infallible");
        Self {
            pool,
            upload_url: upload_url.into(),
            gateway_url: gateway_url.into(),
            winc_safety_floor,
            upload_client,
            lookup_client,
        }
    }
}

impl StorageBackendExt for TurboBackend {
    fn name(&self) -> &'static str {
        "turbo"
    }

    async fn affords(&self, funding: &AuthorizedFunding, bytes: u64) -> Result<(), StorageError> {
        // Read the cached winc balance the reconcile loop maintains for THIS source
        // (no provider call): the request path never touches the network for
        // affordability, exactly as the FX-refresh discipline keeps quote requests
        // off external oracles. An unknown/unfunded source refuses until the first
        // reconcile lands.
        let verdict = cached_affords(
            &self.pool,
            funding.funding_source_id(),
            bytes,
            self.winc_safety_floor,
        )
        .await
        .map_err(|e| StorageError::Unavailable(format!("reading cached storage credit: {e}")))?;
        match verdict {
            AffordVerdict::Affordable => Ok(()),
            AffordVerdict::Unfunded
            | AffordVerdict::BelowSafetyFloor
            | AffordVerdict::InsufficientForBytes => Err(StorageError::InsufficientCredit),
        }
    }

    async fn upload(
        &self,
        _funding: &AuthorizedFunding,
        envelope: &ans104::SignedEnvelope,
        owner: &[u8],
        staged_path: &Path,
    ) -> Result<StorageReceipt, StorageError> {
        // Reconstruct the once-signed data item as a streamed body (the bounded
        // prefix in memory, the staged file streamed as the trailing payload) and
        // POST it. No signing here: the envelope's signature is reused verbatim, so
        // a retry re-POSTs byte-identical bytes and the data-item id is unchanged.
        let body = streamed_data_item_body(envelope, owner, staged_path).await?;

        let url = format!("{}/v1/tx/arweave", self.upload_url.trim_end_matches('/'));
        let response = self
            .upload_client
            .post(&url)
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|e| StorageError::Unavailable(format!("posting to Turbo: {e}")))?;

        let status = response.status();
        if status.as_u16() == 402 {
            return Err(StorageError::InsufficientCredit);
        }
        if !status.is_success() {
            return Err(StorageError::Unavailable(format!(
                "Turbo upload service returned {status}"
            )));
        }

        // A 2xx alone is not proof the bytes are stored: a misconfigured,
        // intercepted, or compromised endpoint can answer 200 with an empty or
        // non-JSON body. The receipt is the only signal the provider accepted THIS
        // data item, so it must be a well-formed Turbo receipt whose `id` is the very
        // item we signed and POSTed before the URI is minted from it and the
        // receipt-gated debit is applied. The data-item id is `SHA-256(signature)`,
        // fixed at signing and present on every genuine Turbo receipt, so an `id` that
        // echoes our envelope is the provider acknowledging the exact bytes we sent.
        let raw_receipt: serde_json::Value =
            crate::http::read_capped_json(response, crate::http::JSON_BODY_CEILING)
                .await
                .map_err(|e| {
                    // A 2xx whose body is not JSON (or is over the ceiling) tells us
                    // nothing about whether the bytes landed. Treat it as indeterminate
                    // (retryable) rather than committing a charge for content that may
                    // not be retrievable; the recovery sweep's authoritative data-item
                    // lookup converges it later.
                    StorageError::Unavailable(format!(
                        "Turbo upload receipt was not valid JSON: {e}"
                    ))
                })?;
        validate_receipt(&raw_receipt, &envelope.id_b64url)?;

        // The data-item id was fixed when the envelope was signed; the receipt's `id`
        // was just confirmed to match it, so the URI resolves at it.
        let data_item_id = envelope.id_b64url.clone();
        let root_tx_id = raw_receipt
            .get("bundledIn")
            .or_else(|| raw_receipt.get("root_tx_id"))
            .and_then(|v| v.as_str())
            .map(str::to_string);

        Ok(StorageReceipt {
            uri: format!("ar://{data_item_id}"),
            data_item_id,
            raw_receipt,
            root_tx_id,
        })
    }

    async fn lookup_data_item(
        &self,
        _funding: &AuthorizedFunding,
        data_item_id: &str,
    ) -> Result<DataItemStatus, StorageError> {
        // A data item is addressable at the Arweave gateway by its id. A 2xx means
        // the bytes landed; a 404 is a definite "the provider does not have it"; any
        // other status or a transport error is indeterminate and must never be read
        // as absent (that would un-charge bytes the provider may hold).
        let url = format!("{}/{data_item_id}", self.gateway_url.trim_end_matches('/'));
        match self.lookup_client.head(&url).send().await {
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

/// Accept a Turbo upload receipt as proof the bytes were stored only if it is a
/// genuine receipt for the item we POSTed.
///
/// The provider returns the data-item id it stored as the receipt's `id`. Our item
/// id is `SHA-256(signature)`, fixed at signing, so a receipt whose `id` echoes our
/// signed envelope is the provider acknowledging the exact bytes we sent — the
/// single field that ties the 2xx to this upload. A receipt that is not a JSON
/// object, carries no `id`, or carries an `id` for some other item is not proof for
/// this upload, so it is treated as indeterminate (retryable, [`StorageError::Unavailable`])
/// rather than letting the caller fabricate the URI from the local envelope and apply
/// the receipt-gated debit. Retryable rather than a definite rejection because the
/// provider answered 2xx: the bytes may well be stored, and the recovery sweep's
/// authoritative data-item lookup is the right place to settle the ambiguity.
fn validate_receipt(receipt: &serde_json::Value, expected_id: &str) -> Result<(), StorageError> {
    let id = receipt.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
        StorageError::Unavailable(
            "Turbo upload receipt is missing the data-item id; the provider did not confirm storage"
                .into(),
        )
    })?;
    if id != expected_id {
        return Err(StorageError::Unavailable(format!(
            "Turbo upload receipt id {id:?} does not match the signed data item {expected_id:?}; \
             the provider did not confirm storage of this item"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ITEM_ID: &str = "k8d2A0kQfH4t5Wj1aZ6cX9bN3mP7rS2uV5yT8wQ1eR0";

    /// A genuine Turbo receipt — the real upload-service shape — whose `id` matches
    /// the signed item is accepted.
    #[test]
    fn a_genuine_receipt_matching_the_signed_id_is_accepted() {
        let receipt = json!({
            "id": ITEM_ID,
            "owner": "abc_owner_address",
            "dataCaches": ["arweave.net"],
            "fastFinalityIndexes": ["arweave.net"],
            "winc": "0",
        });
        assert!(validate_receipt(&receipt, ITEM_ID).is_ok());
    }

    /// An empty object — the old `unwrap_or_else(|| json!({}))` shape, and what a
    /// misconfigured 200-OK endpoint returns — carries no id and is rejected as
    /// indeterminate, NOT accepted as a receipt.
    #[test]
    fn an_empty_object_receipt_is_rejected() {
        let err = validate_receipt(&json!({}), ITEM_ID).expect_err("empty receipt is rejected");
        assert!(
            matches!(err, StorageError::Unavailable(_)),
            "an empty receipt is indeterminate (retryable), not a definite rejection: {err:?}"
        );
    }

    /// A receipt for a DIFFERENT data item (an intercepting or confused endpoint
    /// echoing the wrong id) is rejected: the URI must never be minted from our local
    /// envelope when the provider acknowledged some other item.
    #[test]
    fn a_receipt_for_a_different_item_is_rejected() {
        let receipt = json!({ "id": "some_other_data_item_id_returned_by_the_provider" });
        let err = validate_receipt(&receipt, ITEM_ID).expect_err("mismatched id is rejected");
        assert!(matches!(err, StorageError::Unavailable(_)), "{err:?}");
    }

    /// A non-object body (a bare string or array a broken proxy might wrap a 200 in)
    /// has no `id` field and is rejected.
    #[test]
    fn a_non_object_receipt_is_rejected() {
        for body in [json!("OK"), json!([ITEM_ID]), json!(null), json!(42)] {
            let err = validate_receipt(&body, ITEM_ID)
                .expect_err("a non-object receipt has no data-item id");
            assert!(matches!(err, StorageError::Unavailable(_)), "{err:?}");
        }
    }

    /// An `id` of the wrong JSON type (a number where a string is expected) is not a
    /// usable data-item id and is rejected.
    #[test]
    fn a_receipt_with_a_non_string_id_is_rejected() {
        let err = validate_receipt(&json!({ "id": 12345 }), ITEM_ID)
            .expect_err("a non-string id is not usable");
        assert!(matches!(err, StorageError::Unavailable(_)), "{err:?}");
    }
}
