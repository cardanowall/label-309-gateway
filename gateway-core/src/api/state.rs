//! Shared application state for the data-plane handlers.
//!
//! [`AppState`] is the dependency bundle every handler is given: the connection
//! pool, the operator-configured knobs, and the pricing/storage seams the engine
//! does not own (a vendor supplies its own FX oracle and storage backend). The
//! seams are trait objects so a Tier-1 wrapper injects its own without the engine
//! depending on a particular oracle or provider.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::api::sse::{SseLimits, SseState};
use crate::ledger::quote::{FxSnapshot, MarginResolution};
use crate::storage::{StorageBackend, UploadLimits, UploadSessionLimits};
use crate::wallet::keyring::UnlockedKeyring;
use crate::webhook::{EgressConfig, SecretWrap};

/// The default wall-clock ceiling on an ordinary (non-streaming) request, in
/// seconds. Generous for every quick handler; tight enough that a drip-fed body
/// or a wedged dependency frees its connection promptly instead of pinning it
/// for the client's lifetime.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// The default per-client-address budget (requests per minute) anonymous reads
/// on the public records surface meter against. Two orders of magnitude above
/// what an interactive verifier or an SDK page-walk needs, far below what a
/// scan loop wants; the 2x burst allowance in the limiter sits on top.
pub const DEFAULT_ANON_RATE_LIMIT_PER_MIN: i64 = 120;

/// Operator-configured knobs the data plane needs that are not baked into code.
///
/// Everything a deployment must choose for itself: the problem-type base URL
/// (the `type` member of every RFC 7807 body), the free-storage byte window, the
/// upload ceilings, and the staging directory uploads stream through. The
/// API-key secret prefix is per-key operator config (stored on the key row), not
/// a global, so it is not here.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// The base URL the RFC 7807 `type` member is built from
    /// (`<base>#<error-code>`). Operator-configured; no vendor default.
    pub problem_type_base: String,
    /// The number of content bytes a publish stores for free before the storage
    /// charge applies. Operator-configurable; defaults to 100 KiB.
    pub free_storage_bytes: u64,
    /// The per-call upload ceilings (DoS backstops). Operator-tunable; the
    /// defaults match the wire contract.
    pub upload_limits: UploadLimits,
    /// The tunables for the resumable / chunked upload sessions: the per-chunk
    /// ceiling and suggested size, the abandoned-session TTL, and the per-account
    /// open-session cap. Operator-tunable; the defaults sit well under a ~100 MB CDN
    /// body cap. A session's total-size backstop reuses
    /// [`UploadLimits::max_file_bytes`], and its assembling directory reuses the
    /// durable staging directory, so neither is duplicated here.
    pub upload_session_limits: UploadSessionLimits,
    /// The directory content uploads are staged in before they reach the storage
    /// backend. A deployment that wants staged content on a tmpfs mount points
    /// this there; defaults to the system temporary directory.
    pub staging_dir: PathBuf,
    /// The Cardano network this deployment serves (mainnet / preprod / preview).
    /// Surfaced verbatim on `GET /health` so a client can see which network a
    /// gateway is on before it trusts the gateway's records: a client pointed at a
    /// gateway on the wrong network would otherwise see an empty record set with no
    /// error to explain it. Defaults to mainnet (the production network).
    pub network: crate::chain::params::Network,
    /// The wall-clock ceiling on an ordinary request. The router applies it to
    /// every route EXCEPT the streaming surfaces (the SSE streams and the
    /// content-upload ingress), which are long-lived by design and carry their own
    /// bounds. Operator-tunable; defaults to [`DEFAULT_REQUEST_TIMEOUT_SECS`].
    pub request_timeout: Duration,
    /// The per-client-address request budget (per minute) anonymous reads on the
    /// public records surface meter against. Operator-tunable; defaults to
    /// [`DEFAULT_ANON_RATE_LIMIT_PER_MIN`].
    pub anon_rate_limit_per_min: i64,
    /// The caps on concurrently live SSE streams (instance-wide and per-account).
    /// Operator-tunable; see [`SseLimits`] for the defaults and rationale.
    pub sse_limits: SseLimits,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            problem_type_base: String::new(),
            // 100 KiB free-storage window.
            free_storage_bytes: 102_400,
            upload_limits: UploadLimits::default(),
            upload_session_limits: UploadSessionLimits::default(),
            staging_dir: crate::storage::default_staging_dir(),
            network: crate::chain::params::Network::Mainnet,
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            anon_rate_limit_per_min: DEFAULT_ANON_RATE_LIMIT_PER_MIN,
            sse_limits: SseLimits::default(),
        }
    }
}

/// The pricing inputs the engine does not source itself.
///
/// The engine computes the COGS arithmetic and owns the durable quote row, but
/// the FX values, the canonical network fee, and the markup are vendor inputs.
/// A Tier-1 wrapper implements this seam over its own oracle, fee builder, and
/// margin ladder; the data plane calls it once per quote.
pub trait PricingSource: Send + Sync {
    /// Resolve the pricing inputs for a quote of `record_bytes` carrying
    /// `recipient_count` recipients over `file_bytes_total` content bytes.
    fn resolve(
        &self,
        account_id: Uuid,
        record_bytes: u32,
        recipient_count: u32,
        file_bytes_total: u64,
    ) -> impl std::future::Future<Output = crate::Result<PricingInputs>> + Send;
}

/// The storage seam the data plane is given when content uploads are enabled.
///
/// It bundles the configured [`StorageBackend`] (the uploads route signs and POSTs
/// through it) with the optional upload-signing seam. The backend's persisted
/// identifier ([`StorageBackend::name`]) is the same string the funding source and
/// grant rows carry, so the funding resolver keys on it directly and the two can
/// never drift.
///
/// Affordability lives on the backend itself ([`StorageBackend::affords`]): both
/// the quote route and the upload routes resolve the drawing funding source
/// through the funding grant engine and then ask the backend, so an
/// over-the-free-window publish the operator cannot fund is refused at quote
/// time, before the user commits to a price — and the quote's answer can never
/// disagree with the upload's. Funding-policy knobs (the Turbo winc safety floor)
/// belong to the backend that enforces them, not to this seam.
#[derive(Clone)]
pub struct StorageState {
    backend: Arc<dyn StorageBackend>,
    signing: Option<UploadSigning>,
}

/// The extra seam an account-scoped paid upload needs beyond the quote
/// affordability read: the keyring that signs the data item once in the route, the
/// durable directory a reservation's staged content is promoted to, and the two
/// in-flight upload deadlines.
///
/// It is separate from the always-present [`StorageState`] fields because the quote
/// route's affordability check needs neither a keyring nor a staging directory: it
/// reads cached credit only. A deployment that wires storage for quoting but not
/// for paid uploads (no keyring) leaves this `None`, and the uploads route reports
/// the paid path unavailable rather than failing mid-sign.
#[derive(Clone)]
pub struct UploadSigning {
    /// The unlocked keyring the route signs the data item through. Shared (`Arc`)
    /// with the chain-submit signer, because one unlocked keyring serves every
    /// signing surface on the instance.
    keyring: Arc<UnlockedKeyring>,
    /// The durable directory a `reserved` attempt's staged content is promoted to,
    /// so it survives a crash and can be re-POSTed by the recovery sweep. Must be
    /// on non-tmpfs storage.
    durable_staging_dir: PathBuf,
    /// The wall-clock ceiling on a single provider POST. The streamed POST is
    /// aborted when this elapses, strictly before the claim-lease can lapse, so a
    /// healthy-but-slow owner tears its connection down before any second contender
    /// can claim the reclaimed POST window.
    upload_timeout: Duration,
    /// The external-POST claim-lease lifetime. Greater than `upload_timeout` by a
    /// margin so the abort always fires first; a lease older than this is
    /// reclaimable (the prior owner died mid-POST).
    upload_claim_lease_ttl: Duration,
}

impl UploadSigning {
    /// Build the upload-signing seam.
    #[must_use]
    pub fn new(
        keyring: Arc<UnlockedKeyring>,
        durable_staging_dir: PathBuf,
        upload_timeout: Duration,
        upload_claim_lease_ttl: Duration,
    ) -> Self {
        Self {
            keyring,
            durable_staging_dir,
            upload_timeout,
            upload_claim_lease_ttl,
        }
    }

    /// The keyring the route signs the data item through.
    #[must_use]
    pub fn keyring(&self) -> &Arc<UnlockedKeyring> {
        &self.keyring
    }

    /// The durable directory a reservation's staged content is promoted to.
    #[must_use]
    pub fn durable_staging_dir(&self) -> &std::path::Path {
        &self.durable_staging_dir
    }

    /// The single-POST wall-clock ceiling.
    #[must_use]
    pub fn upload_timeout(&self) -> Duration {
        self.upload_timeout
    }

    /// The external-POST claim-lease lifetime.
    #[must_use]
    pub fn upload_claim_lease_ttl(&self) -> Duration {
        self.upload_claim_lease_ttl
    }
}

impl StorageState {
    /// Build the storage seam over a backend. The upload-signing seam is attached
    /// separately via [`Self::with_signing`]; without it the seam serves quote
    /// affordability but the uploads route reports the paid path unavailable.
    #[must_use]
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        Self {
            backend,
            signing: None,
        }
    }

    /// Attach the upload-signing seam (keyring, durable staging dir, deadlines) the
    /// account-scoped paid upload path needs.
    #[must_use]
    pub fn with_signing(mut self, signing: UploadSigning) -> Self {
        self.signing = Some(signing);
        self
    }

    /// The configured upload backend (the uploads route signs and POSTs through
    /// it).
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn StorageBackend> {
        &self.backend
    }

    /// The backend's persisted identifier (`turbo`, `direct-arweave`, `arlocal`),
    /// the same value the funding source and grant rows carry. The funding resolver
    /// keys on it, so it is derived from the backend itself rather than stored
    /// twice.
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    /// The upload-signing seam, when this deployment wired paid uploads. `None`
    /// means storage is enabled for quoting only; the uploads route then reports the
    /// paid path unavailable.
    #[must_use]
    pub fn signing(&self) -> Option<&UploadSigning> {
        self.signing.as_ref()
    }
}

/// The webhook seam every webhook route is given when the feature is enabled.
///
/// It bundles the secret-wrap data key the registration path seals a minted secret
/// under (and the delivery path opens it back through) with the two registration
/// knobs the URL-safety guard reads: whether `http://` targets are permitted and
/// whether the SSRF range-block is loosened to reach a loopback receiver (a
/// test-only escape hatch). A deployment that has not enabled webhooks leaves the
/// whole seam `None`; the webhook routes then report the feature unavailable rather
/// than minting a secret with no place to seal it.
#[derive(Clone)]
pub struct WebhookState {
    /// The data key that seals a webhook signing secret at rest, shared (`Arc`)
    /// with the delivery worker because one unlocked data key serves both the
    /// registration seal and the per-delivery open.
    secret_wrap: Arc<SecretWrap>,
    /// Permit `http://` delivery targets (self-host / dev). Off by default, so a
    /// production registration accepts only `https://`. Loosens only the scheme
    /// requirement — the SSRF range-block stays on regardless.
    allow_insecure_http: bool,
    /// Loosen the SSRF range-block so a loopback receiver is reachable.
    /// Test-only: maps to the SDK guard's `allow_private_for_tests` seam and
    /// loosens only the range-block — plain `http://` still requires
    /// `allow_insecure_http`.
    egress_allow_loopback: bool,
}

impl WebhookState {
    /// Build the webhook seam over the secret-wrap data key and the two
    /// registration knobs.
    #[must_use]
    pub fn new(
        secret_wrap: Arc<SecretWrap>,
        allow_insecure_http: bool,
        egress_allow_loopback: bool,
    ) -> Self {
        Self {
            secret_wrap,
            allow_insecure_http,
            egress_allow_loopback,
        }
    }

    /// The secret-wrap data key the registration path seals through.
    #[must_use]
    pub fn secret_wrap(&self) -> &SecretWrap {
        &self.secret_wrap
    }

    /// The egress posture the registration-time URL guard shares with the
    /// delivery worker. Both stages read the knobs through the one mapping in
    /// [`EgressConfig::assert_options`], so a URL that passes registration also
    /// passes delivery and the two loosenings stay independent axes (`http://`
    /// permission never opens the SSRF range-block, and vice versa).
    #[must_use]
    pub fn egress_config(&self) -> EgressConfig {
        EgressConfig {
            allow_insecure_http: self.allow_insecure_http,
            allow_loopback: self.egress_allow_loopback,
        }
    }
}

/// The pricing inputs a [`PricingSource`] resolves for a quote.
#[derive(Debug, Clone)]
pub struct PricingInputs {
    /// The exact canonical-shape network fee in lovelace.
    pub network_lovelace: u64,
    /// The FX snapshot the cost is priced from.
    pub fx: FxSnapshot,
    /// The age of that snapshot in seconds.
    pub fx_age_seconds: i64,
    /// The markup the vendor's margin policy resolved.
    pub margin: MarginResolution,
}

/// The shared state every data-plane handler is given.
#[derive(Clone)]
pub struct AppState {
    /// The engine's connection pool.
    pub pool: sqlx::PgPool,
    /// The operator-configured knobs.
    pub config: Arc<ApiConfig>,
    /// The vendor's pricing seam, when configured. A deployment that has not
    /// wired pricing leaves it `None`; the quote route then reports the pricing
    /// dependency unavailable rather than inventing a price.
    pub pricing: Option<Arc<dyn DynPricingSource>>,
    /// The storage seam (backend plus operator funding knobs), when content
    /// uploads are enabled. A deployment that has not wired storage leaves it
    /// `None`; the uploads route then reports content storage unavailable and the
    /// quote route skips the storage-affordability branch.
    pub storage: Option<StorageState>,
    /// The webhook seam (secret-wrap data key plus the registration URL-safety
    /// knobs), when webhooks are enabled. A deployment that has not enabled
    /// webhooks leaves it `None`; the webhook routes then report the feature
    /// unavailable.
    pub webhook: Option<WebhookState>,
    /// The SSE seam: the shared NOTIFY fan-out (one listener connection per
    /// instance, regardless of stream count) and the live-stream cap registry.
    /// Built from [`ApiConfig::sse_limits`]; shared by cloning.
    pub sse: SseState,
}

impl AppState {
    /// Construct application state over a pool and operator config, with no
    /// pricing or storage seam wired (the minimal embedding).
    #[must_use]
    pub fn new(pool: sqlx::PgPool, config: ApiConfig) -> Self {
        let sse = SseState::new(config.sse_limits);
        Self {
            pool,
            config: Arc::new(config),
            pricing: None,
            storage: None,
            webhook: None,
            sse,
        }
    }

    /// Attach a pricing seam.
    #[must_use]
    pub fn with_pricing(mut self, pricing: Arc<dyn DynPricingSource>) -> Self {
        self.pricing = Some(pricing);
        self
    }

    /// Attach the storage seam (backend plus funding knobs).
    #[must_use]
    pub fn with_storage(mut self, storage: StorageState) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Attach the webhook seam (secret-wrap data key plus registration knobs).
    #[must_use]
    pub fn with_webhook(mut self, webhook: WebhookState) -> Self {
        self.webhook = Some(webhook);
        self
    }
}

/// Object-safe form of [`PricingSource`] for storage behind an `Arc<dyn …>`.
///
/// The RPITIT trait is not object-safe, so the data plane holds this boxed-future
/// twin; a blanket impl bridges any [`PricingSource`] to it.
pub trait DynPricingSource: Send + Sync {
    /// Resolve pricing inputs, returning a boxed future.
    fn resolve_dyn<'a>(
        &'a self,
        account_id: Uuid,
        record_bytes: u32,
        recipient_count: u32,
        file_bytes_total: u64,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::Result<PricingInputs>> + Send + 'a>,
    >;
}

impl<T: PricingSource> DynPricingSource for T {
    fn resolve_dyn<'a>(
        &'a self,
        account_id: Uuid,
        record_bytes: u32,
        recipient_count: u32,
        file_bytes_total: u64,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::Result<PricingInputs>> + Send + 'a>,
    > {
        Box::pin(self.resolve(account_id, record_bytes, recipient_count, file_bytes_total))
    }
}
