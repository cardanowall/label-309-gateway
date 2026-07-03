//! The backend-neutral storage trait and receipt.
//!
//! A storage backend POSTs a pre-signed ANS-104 data item, reconstructed from a
//! bounded signed envelope plus the durable staged content, and returns an
//! addressable receipt. The data item is signed ONCE in the route (so a randomised
//! PSS signature, and therefore the item id, is fixed before the first POST); the
//! backend never signs, so a retry re-POSTs byte-identical bytes by construction.
//! The backend also reports — without uploading — whether the operator funding
//! behind a capability can afford a given number of bytes, and looks up whether a
//! data item has already landed at the provider (the crash-recovery sweep needs to
//! distinguish "the provider confirms it is absent" from "the provider is
//! unreachable").
//!
//! Every funded operation is gated by an [`AuthorizedFunding`] capability: the
//! affordability read, the upload, and the lookup all take one, so a backend can
//! never act for a source the caller was not authorised to draw.

use std::path::Path;

use ans104::SignedEnvelope;

use crate::storage::funding::AuthorizedFunding;

/// A storage backend that POSTs a pre-signed data item and returns its receipt.
///
/// The upload takes the funding capability, the bounded signed envelope (signature,
/// id, target/anchor, and the serialised tag block), the owner key bytes the
/// envelope references, and the durable staged file path. It reconstructs the
/// canonical bytes by streaming the staged content as the trailing `data` element
/// (never buffering a multi-gigabyte payload) and POSTs them; the reconstruction is
/// byte-identical to the once-signed item, which is what makes a retry idempotent.
///
/// The trait is object-safe: each method returns a boxed future so a backend can be
/// held behind `Arc<dyn StorageBackend>` in the application state. A concrete
/// backend usually implements [`StorageBackendExt`] (an ergonomic `async fn` form)
/// and gets this trait for free via the blanket impl.
pub trait StorageBackend: Send + Sync {
    /// A short, stable backend identifier persisted on each receipt row (e.g.
    /// `turbo`, `direct-arweave`, `arlocal`). Vendor-neutral and operator-facing;
    /// never a brand string.
    fn name(&self) -> &'static str;

    /// Report whether the funding behind `funding` can afford to store `bytes`
    /// right now, WITHOUT uploading anything.
    ///
    /// Called at quote time so an unaffordable publish surfaces as a 402 before the
    /// user commits to a price, not as a failure after the content has been staged.
    /// The byte count passed is the chargeable size the caller already netted of the
    /// free-storage window; a backend reports [`StorageError::InsufficientCredit`]
    /// when the source's funding cannot cover it. The default returns Ok (a backend
    /// with no notion of a funding ceiling always affords); a funded backend
    /// overrides it. The capability scopes the check to one source's balance so a
    /// backend can never report another source's affordability.
    fn affords<'a>(
        &'a self,
        funding: &'a AuthorizedFunding,
        bytes: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StorageError>> + Send + 'a>>
    {
        let _ = (funding, bytes);
        Box::pin(std::future::ready(Ok(())))
    }

    /// POST the pre-signed data item, returning its addressable receipt as a boxed
    /// future so the trait stays object-safe.
    ///
    /// The backend reconstructs the canonical bytes from `envelope` + `owner` +
    /// the staged content at `staged_path` and POSTs them; it does NOT sign. The
    /// staged file is streamed as the trailing payload, so the resident set does
    /// not grow with the file size.
    fn upload<'a>(
        &'a self,
        funding: &'a AuthorizedFunding,
        envelope: &'a SignedEnvelope,
        owner: &'a [u8],
        staged_path: &'a Path,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<StorageReceipt, StorageError>> + Send + 'a>,
    >;

    /// Ask the provider whether the data item `data_item_id` has landed.
    ///
    /// The crash-recovery sweep calls this to decide an interrupted upload's fate:
    /// [`DataItemStatus::Present`] commits the reservation (the bytes are stored),
    /// [`DataItemStatus::Absent`] drives a re-POST (if the content survived) or a
    /// release, and [`DataItemStatus::Unavailable`] (the lookup API is unreachable)
    /// leaves the reservation in place — an unreachable provider must never be read
    /// as "absent", which would un-charge bytes the provider may actually hold. The
    /// default reports [`DataItemStatus::Unavailable`] so a backend with no lookup
    /// API never claims a definite answer; a backend with a data-item GET overrides
    /// it.
    fn lookup_data_item<'a>(
        &'a self,
        funding: &'a AuthorizedFunding,
        data_item_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<DataItemStatus, StorageError>> + Send + 'a>,
    > {
        let _ = (funding, data_item_id);
        Box::pin(std::future::ready(Ok(DataItemStatus::Unavailable)))
    }
}

/// The ergonomic `async fn` form a concrete backend implements.
///
/// A backend implements this with a plain `async fn upload` (plus its [`name`],
/// optionally an `affords` override when it has a funding ceiling, and optionally a
/// `lookup_data_item` override when it has a data-item GET), and the blanket impl
/// below bridges it to the object-safe [`StorageBackend`] so it can live behind a
/// trait object without the implementer writing `Box::pin` by hand.
///
/// [`name`]: StorageBackendExt::name
pub trait StorageBackendExt: Send + Sync {
    /// The backend's stable identifier (see [`StorageBackend::name`]).
    fn name(&self) -> &'static str;

    /// Report whether `bytes` can be afforded without uploading (see
    /// [`StorageBackend::affords`]). Defaults to always-affordable; a funded
    /// backend overrides it.
    fn affords(
        &self,
        funding: &AuthorizedFunding,
        bytes: u64,
    ) -> impl std::future::Future<Output = Result<(), StorageError>> + Send {
        let _ = (funding, bytes);
        std::future::ready(Ok(()))
    }

    /// POST the pre-signed data item, returning its receipt (see
    /// [`StorageBackend::upload`]).
    fn upload(
        &self,
        funding: &AuthorizedFunding,
        envelope: &SignedEnvelope,
        owner: &[u8],
        staged_path: &Path,
    ) -> impl std::future::Future<Output = Result<StorageReceipt, StorageError>> + Send;

    /// Look up whether a data item has landed (see
    /// [`StorageBackend::lookup_data_item`]). Defaults to
    /// [`DataItemStatus::Unavailable`]; a backend with a data-item GET overrides it.
    fn lookup_data_item(
        &self,
        funding: &AuthorizedFunding,
        data_item_id: &str,
    ) -> impl std::future::Future<Output = Result<DataItemStatus, StorageError>> + Send {
        let _ = (funding, data_item_id);
        std::future::ready(Ok(DataItemStatus::Unavailable))
    }
}

impl<T: StorageBackendExt> StorageBackend for T {
    fn name(&self) -> &'static str {
        StorageBackendExt::name(self)
    }

    fn affords<'a>(
        &'a self,
        funding: &'a AuthorizedFunding,
        bytes: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StorageError>> + Send + 'a>>
    {
        Box::pin(StorageBackendExt::affords(self, funding, bytes))
    }

    fn upload<'a>(
        &'a self,
        funding: &'a AuthorizedFunding,
        envelope: &'a SignedEnvelope,
        owner: &'a [u8],
        staged_path: &'a Path,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<StorageReceipt, StorageError>> + Send + 'a>,
    > {
        Box::pin(StorageBackendExt::upload(
            self,
            funding,
            envelope,
            owner,
            staged_path,
        ))
    }

    fn lookup_data_item<'a>(
        &'a self,
        funding: &'a AuthorizedFunding,
        data_item_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<DataItemStatus, StorageError>> + Send + 'a>,
    > {
        Box::pin(StorageBackendExt::lookup_data_item(
            self,
            funding,
            data_item_id,
        ))
    }
}

/// The receipt a successful upload returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageReceipt {
    /// The addressable URI the content resolves at (`ar://<data-item-id>`).
    pub uri: String,
    /// The ANS-104 data-item id.
    pub data_item_id: String,
    /// The verbatim provider response, retained for reconciliation.
    pub raw_receipt: serde_json::Value,
    /// The top-level Arweave transaction that bundled this item, once known.
    pub root_tx_id: Option<String>,
}

/// Whether a data item has landed at the provider, as the recovery sweep reads it.
///
/// The three arms are deliberately distinct so the sweep never confuses "the
/// provider confirms it does not have this item" with "we could not reach the
/// provider": the former is actionable (re-POST or release), the latter must leave
/// the reservation untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataItemStatus {
    /// The provider has the data item (the bytes landed).
    Present,
    /// The provider confirms it does not have the data item.
    Absent,
    /// The lookup could not be resolved (the API is unreachable or indeterminate).
    /// Never treated as `Absent`.
    Unavailable,
}

/// A storage-backend failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The backend refused the upload because it is misconfigured for the
    /// deployment (for example the dev backend used in production).
    #[error("storage backend misconfigured: {0}")]
    Misconfigured(String),
    /// The backend rejected the upload for lack of funds/credit.
    #[error("storage backend reports insufficient credit")]
    InsufficientCredit,
    /// The backend is temporarily unavailable (transport error, 429, 503).
    #[error("storage backend unavailable: {0}")]
    Unavailable(String),
    /// Signing or building the data item failed.
    #[error("storage data-item construction failed: {0}")]
    Build(String),
    /// An I/O error reading the staged file.
    #[error("storage staging I/O error: {0}")]
    Io(String),
}
