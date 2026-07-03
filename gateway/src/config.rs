//! The binary's on-disk configuration.
//!
//! A deployment supplies a single TOML file plus a handful of environment
//! overrides. The file fixes everything that is stable for a deployment (the
//! network it runs on, the canonical lovelace band, the maintenance cadences),
//! while the environment carries the values an operator rotates or injects at
//! deploy time (the database URL and the operator keyring secrets). Secrets are
//! never written into the config file: the keyring ciphertext lives at a path and
//! its passphrase comes from the environment, so the file can be committed and
//! reviewed without exposing key material.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use serde::Deserialize;
use zeroize::Zeroizing;

/// Environment variable holding the Postgres connection URL.
pub const DATABASE_URL_ENV: &str = "GATEWAY_DATABASE_URL";

/// Environment variable holding the operator keyring passphrase. Read straight
/// into a zeroizing wrapper and never logged.
pub const KEYRING_PASSPHRASE_ENV: &str = "GATEWAY_KEYRING_PASSPHRASE";

/// Environment variable naming a file that holds the operator keyring
/// passphrase (the docker-secrets convention: a path under `/run/secrets`).
/// The file's contents are used with trailing whitespace trimmed. Mutually
/// exclusive with [`KEYRING_PASSPHRASE_ENV`]: setting both is a load error.
pub const KEYRING_PASSPHRASE_FILE_ENV: &str = "GATEWAY_KEYRING_PASSPHRASE_FILE";

/// Environment variable holding the NEW keyring passphrase for `gateway
/// keyring change-passphrase` (the current one is sourced through
/// [`KEYRING_PASSPHRASE_ENV`] as usual). Read straight into a zeroizing
/// wrapper and never logged.
pub const KEYRING_NEW_PASSPHRASE_ENV: &str = "GATEWAY_KEYRING_NEW_PASSPHRASE";

/// Environment variable naming a file that holds the new keyring passphrase
/// (the docker-secrets convention). The file's contents are used with trailing
/// whitespace trimmed. Mutually exclusive with [`KEYRING_NEW_PASSPHRASE_ENV`]:
/// setting both is an error.
pub const KEYRING_NEW_PASSPHRASE_FILE_ENV: &str = "GATEWAY_KEYRING_NEW_PASSPHRASE_FILE";

/// Environment variable that overrides the keyring ciphertext path from the file.
pub const KEYRING_PATH_ENV: &str = "GATEWAY_KEYRING_PATH";

/// Environment variable that overrides the worker identity stamped onto claims.
pub const WORKER_ID_ENV: &str = "GATEWAY_WORKER_ID";

/// Environment variable holding the optional CoinGecko API key. A deploy-time
/// secret, so it is never written into the committed config file. Set it (with
/// `[fx] coingecko_tier`) to use CoinGecko as the primary price provider; absent
/// prices from the keyless CoinPaprika default (which needs no key).
pub const COINGECKO_API_KEY_ENV: &str = "GATEWAY_COINGECKO_API_KEY";

/// Environment variable naming a file that holds the CoinGecko API key (the
/// docker-secrets convention). The file's contents are used with trailing
/// whitespace trimmed. Mutually exclusive with [`COINGECKO_API_KEY_ENV`]:
/// setting both is a load error.
pub const COINGECKO_API_KEY_FILE_ENV: &str = "GATEWAY_COINGECKO_API_KEY_FILE";

/// Environment variable holding the Blockfrost project id the chain gateway's
/// failover secondary authenticates with. A deploy-time secret, so it is never
/// written into the committed config file. When set, a Koios rate-limit (429)
/// fails over to Blockfrost instead of parking both providers behind one keyless
/// Koios tier; absent leaves the secondary a second Koios instance.
pub const BLOCKFROST_PROJECT_ID_ENV: &str = "GATEWAY_BLOCKFROST_PROJECT_ID";

/// Environment variable naming a file that holds the Blockfrost project id (the
/// docker-secrets convention). The file's contents are used with trailing
/// whitespace trimmed. Mutually exclusive with [`BLOCKFROST_PROJECT_ID_ENV`]:
/// setting both is a load error.
pub const BLOCKFROST_PROJECT_ID_FILE_ENV: &str = "GATEWAY_BLOCKFROST_PROJECT_ID_FILE";

/// Environment variable holding the Koios API key every Koios request (the
/// primary chain provider, the protocol-parameter source, and the replenisher's
/// UTxO source) authenticates with as `Authorization: Bearer <key>`. A
/// deploy-time secret, so it is never written into the committed config file.
/// Absent leaves Koios on the keyless public tier (~5,000 requests/day), which
/// suits development; production deployments on the public `koios.rest`
/// gateways should supply a registered-tier key or point `[chain] koios_url`
/// at a self-hosted instance.
pub const KOIOS_API_KEY_ENV: &str = "GATEWAY_KOIOS_API_KEY";

/// Environment variable naming a file that holds the Koios API key (the
/// docker-secrets convention). The file's contents are used with trailing
/// whitespace trimmed. Mutually exclusive with [`KOIOS_API_KEY_ENV`]: setting
/// both is a load error.
pub const KOIOS_API_KEY_FILE_ENV: &str = "GATEWAY_KOIOS_API_KEY_FILE";

/// Environment variable holding the Sentry/GlitchTip DSN that turns on the
/// optional error monitoring. This single variable is the on/off switch: unset or
/// empty leaves monitoring fully inert (no client, no transport, no egress). A
/// deploy-time secret, so it is never written into the committed config file.
pub const SENTRY_DSN_ENV: &str = "GATEWAY_SENTRY_DSN";

/// Environment variable naming a file that holds the Sentry/GlitchTip DSN (the
/// docker-secrets convention). The file's contents are used with trailing
/// whitespace trimmed. Mutually exclusive with [`SENTRY_DSN_ENV`]: setting both
/// is a load error.
pub const SENTRY_DSN_FILE_ENV: &str = "GATEWAY_SENTRY_DSN_FILE";

/// Environment variable carrying the `environment` tag the monitoring stamps onto
/// every event (`production`, `preprod`, …). Absent or empty defaults to
/// `production`. Read only when a DSN is configured.
pub const SENTRY_ENVIRONMENT_ENV: &str = "GATEWAY_SENTRY_ENVIRONMENT";

/// Environment variable carrying the performance-tracing sample rate, a number in
/// `0.0..=1.0`. Absent or empty means `0.0` (errors only, no performance tracing).
/// A value outside the range, or one that is not a number, is a load error. Read
/// only when a DSN is configured.
pub const SENTRY_TRACES_SAMPLE_RATE_ENV: &str = "GATEWAY_SENTRY_TRACES_SAMPLE_RATE";

/// Environment variable overriding the `release` tag events are grouped by. Absent
/// or empty falls back to the compiled-in `name@version`. Useful to stamp a git
/// sha for per-deploy granularity. Read only when a DSN is configured.
pub const SENTRY_RELEASE_ENV: &str = "GATEWAY_RELEASE";

/// The fully resolved configuration the binary assembles its runtime from.
///
/// Distinct from the raw on-disk file shape: that shape is validated and merged
/// with the environment when this is built, and the secrets are loaded, so the
/// rest of the binary works with already-checked values and never re-reads the
/// environment.
pub struct GatewayConfig {
    /// The Postgres connection URL.
    ///
    /// May embed a password; never logged at field granularity by this crate.
    pub database_url: String,
    /// The identity stamped onto job claims (`claimed_by`).
    pub worker_id: String,
    /// The wallet subsystem configuration (network, band, lease, canonical count).
    pub wallet: WalletConfig,
    /// The record sizes the fee-shape stability check certifies the band against
    /// at startup. Must include the largest record the deployment will accept.
    pub fee_shape_record_sizes: Vec<usize>,
    /// The path to the age-encrypted operator keyring ciphertext.
    pub keyring_path: PathBuf,
    /// The operator keyring passphrase, held in a zeroizing wrapper so it is
    /// wiped when the config is dropped.
    pub keyring_passphrase: Zeroizing<String>,
    /// The HTTP data-plane configuration, when the deployment serves it. `None`
    /// runs the background plane alone (the prior behaviour).
    pub http: Option<HttpConfig>,
    /// The content-storage configuration, when the deployment uploads content.
    /// `None` is an intentional hash-only deployment: the uploads route reports
    /// content storage unavailable and the quote route skips the storage
    /// affordability branch. The two config axes (`cardano.network` and
    /// `storage.backend`) are independent: a preprod deployment can run a real
    /// Turbo backend and a mainnet deployment cannot run the ArLocal emulator,
    /// but neither implies the other.
    pub storage: Option<StorageConfig>,
    /// The live-FX configuration. `Some` runs the engine's own FX refresh cron and
    /// prices quotes from the cached snapshot (the live path); `None` leaves the
    /// binary on the static `[http]` rate (the offline/test path). The live path
    /// also requires `[storage]`, since the per-byte oracles reuse its service URLs.
    pub fx: Option<FxSettings>,
    /// The control-plane configuration. Always resolved (with defaults) so the
    /// bootstrap and admin subcommands have their knobs even without an `[http]`
    /// section; the control router is only mounted when `[http]` is also served.
    pub control: ControlSettings,
    /// The webhook delivery configuration. Always resolved (with the
    /// production-safe defaults) so both the registration guard and the delivery
    /// worker read one source for the egress posture.
    pub webhooks: WebhookSettings,
    /// The Blockfrost project id the chain gateway's failover secondary
    /// authenticates with. `Some` makes a Koios 429 fail over to Blockfrost;
    /// `None` leaves the secondary a second Koios instance. Sourced from the
    /// `GATEWAY_BLOCKFROST_PROJECT_ID` environment secret (or its `_FILE` twin),
    /// or read from the file at the optional `[chain] blockfrost_project_id_path`;
    /// the environment wins. Held in a zeroizing wrapper so the secret is wiped
    /// on drop.
    pub blockfrost_project_id: Option<Zeroizing<String>>,
    /// How Koios — the primary chain provider — is addressed: the optional
    /// `[chain] koios_url` base-URL override (validated and normalised to no
    /// trailing slash at load) and the optional `GATEWAY_KOIOS_API_KEY` secret
    /// (or its `_FILE` twin). The default is the keyless public tier on the
    /// per-network URL.
    pub koios: gateway_core::chain::params::KoiosConfig,
    /// The per-provider egress budget (sustained rate + burst) every chain
    /// provider HTTP request is admitted through. Resolved from the optional
    /// `[chain] egress_requests_per_minute` / `egress_burst` overrides, with
    /// engine defaults otherwise. The defaults are tuned for the keyless Koios
    /// free tier; an operator with a registered-tier key or a self-hosted Koios
    /// may raise them.
    pub chain_egress: gateway_core::chain::egress::EgressLimits,
}

/// The resolved webhook delivery configuration.
///
/// Two URL-safety knobs gate the SSRF egress guard, both defaulting to the
/// production-safe posture (HTTPS-only delivery targets, the loopback/private
/// range-block always on). A self-host deployment that targets `http://`
/// endpoints, or a conformance run that must deliver to a loopback receiver, opts
/// the relevant knob in explicitly. The same settings drive BOTH the registration
/// guard ([`gateway_core::api::WebhookState`]) and the delivery worker's
/// [`gateway_core::webhook::EgressConfig`], so a URL that passes registration also
/// passes delivery and the posture can never split between the two stages.
///
/// `Default` is the production-safe posture: both knobs `false` (HTTPS-only, the
/// loopback/private range-block always on).
#[derive(Debug, Clone, Default)]
pub struct WebhookSettings {
    /// Allow `http://` delivery targets (self-host only). Default `false`:
    /// HTTPS-only. Loosens only the scheme requirement — the loopback/private
    /// SSRF range-block stays on regardless.
    pub allow_insecure_http: bool,
    /// Allow loopback/private-range delivery targets — maps to the SDK egress
    /// guard's `allow_private_for_tests` seam and loosens only the range-block
    /// (plain `http://` still needs `allow_insecure_http`). Default `false`.
    /// Test-only; never on in production.
    pub egress_allow_loopback: bool,
}

/// The resolved control-plane configuration.
///
/// Operator-configured per deployment: the secret prefix minted credentials and
/// keys carry (no hardcoded brand string), the token lifetimes, the single-
/// adjustment cap, and whether the bundled static admin UI is served at `/admin`.
#[derive(Debug, Clone)]
pub struct ControlSettings {
    /// The human-readable prefix minted control secrets carry.
    pub secret_prefix: String,
    /// The lifetime of a minted operator token, in seconds.
    pub operator_token_ttl_secs: i64,
    /// The lifetime of a minted account-scoped token, in seconds.
    pub account_token_ttl_secs: i64,
    /// The maximum absolute magnitude (micro-USD) of a single manual adjustment.
    pub adjustment_cap_usd_micros: i64,
    /// Whether the bundled static admin UI is served at `/admin`.
    pub admin_ui_enabled: bool,
    /// The spend scope a newly registered wallet is granted when the register
    /// call names none: `service` (every operator/account may spend it; the
    /// single-tenant default) or `operator` (registrar-only until further grants).
    pub default_wallet_scope: String,
    /// The draw scope a newly registered funding source is granted when the
    /// register call names none: `service` (every account may draw it; the
    /// single-tenant default) or `operator` (owner-only until further grants). The
    /// storage twin of `default_wallet_scope`.
    pub default_storage_scope: String,
}

impl Default for ControlSettings {
    fn default() -> Self {
        Self {
            secret_prefix: "ctl_".to_string(),
            // 24h operator tokens, 1h account tokens (the locked defaults).
            operator_token_ttl_secs: 24 * 3600,
            account_token_ttl_secs: 3600,
            // A $10,000 default cap.
            adjustment_cap_usd_micros: 10_000_000_000,
            admin_ui_enabled: true,
            // Single-tenant default: a fresh wallet is usable by the whole service.
            default_wallet_scope: "service".to_string(),
            // Single-tenant default: a fresh funding source is drawable service-wide.
            default_storage_scope: "service".to_string(),
        }
    }
}

/// The HTTP data-plane configuration.
///
/// Operator-configured per deployment: the socket the API binds, the RFC 7807
/// problem-`type` documentation base (no vendor host is hardcoded), and the
/// pricing inputs the quote route prices a publish from.
///
/// The free-storage byte window lives in `[storage]`, not here: it is a property
/// of how content is stored, so it travels with the storage configuration and is
/// fed into the data plane only when storage is wired.
///
/// The engine does not ship an FX oracle: pricing inputs are a vendor seam. The
/// reference binary reads them from this config so the data plane is fully
/// functional out of the box; a deployment that wants live FX swaps in its own
/// pricing wrapper (the engine's `PricingSource` seam) without changing the
/// engine.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// The socket address the API listens on (e.g. `0.0.0.0:8080`).
    pub bind: String,
    /// The base URL the problem `type` member is built from.
    pub problem_type_base: String,
    /// The ADA→USD conversion the network fee is priced through, in micro-USD per
    /// ADA. The reference binary reads it from config (no live oracle is bundled);
    /// the quote records it verbatim on each quote row so the price is reproducible.
    pub ada_usd_micros: i64,
    /// The markup the quote applies over the cost of goods, as a fraction (e.g.
    /// `0.25` for 25%).
    pub margin_pct: f64,
    /// The wall-clock ceiling on an ordinary request, in seconds. Streaming
    /// surfaces (the SSE streams, the content-upload ingress) are exempt by
    /// construction; everything else is cut off at this bound so a slow-body or
    /// wedged request cannot pin a connection indefinitely.
    pub request_timeout_secs: u64,
    /// The per-client-address request budget (per minute) anonymous reads on the
    /// public records surface meter against.
    pub anon_rate_limit_per_min: i64,
    /// The instance-wide ceiling on concurrently live SSE streams.
    pub sse_max_streams: u32,
    /// The per-account ceiling on concurrently live SSE streams.
    pub sse_max_streams_per_account: u32,
}

/// The resolved live-FX configuration.
///
/// Present means the deployment runs the engine's own FX refresh cron and prices
/// every quote from the cached `cw_core.fx_rate` snapshot it writes (the live
/// path). Absent leaves the binary on the static `[http]` rate (the offline path):
/// no oracle is called and the configured `ada_usd_micros` prices every quote.
///
/// The two per-byte oracle URLs are NOT here: the Turbo price oracle reads the
/// `[storage]` payment-service URL and the Arweave-native fallback reads the
/// `[storage]` gateway URL, so the FX loop reuses the same endpoints the storage
/// subsystem already configures rather than duplicating them. A live-FX deployment
/// therefore also configures `[storage]`.
#[derive(Clone)]
pub struct FxSettings {
    /// The CoinGecko credential, when an operator opts into CoinGecko as the primary
    /// price provider. `None` runs the keyless CoinPaprika default alone — no API
    /// key needed — so a self-hosted gateway prices publishes out of the box.
    pub coingecko: Option<CoinGeckoSettings>,
    /// The cron the FX refresh loop fires on (the only oracle caller). Defaults to
    /// every fifteen minutes.
    pub refresh_schedule: String,
    /// The maximum age, in seconds, a cached `cw_core.fx_rate` snapshot may have and
    /// still price a quote. This is a freshness CEILING, not the refresh interval: a
    /// single missed refresh tick is expected and a slightly stale snapshot still
    /// serves (the skip-and-serve discipline the FX loop relies on). But once the
    /// newest snapshot is older than this, the pricing seam refuses to quote and the
    /// quote route reports the pricing dependency temporarily unavailable, so an
    /// extended oracle outage can never charge a publish at an arbitrarily stale rate.
    /// Defaults to one hour: at the 15-minute refresh cadence a healthy snapshot is at
    /// most ~15 minutes old, so an hour tolerates a few consecutive missed ticks while
    /// still capping accumulated staleness well below the point of material mis-billing.
    pub max_fx_snapshot_age_seconds: i64,
}

/// The CoinGecko credential a deployment optionally configures to use CoinGecko as
/// the primary coin-price provider (with CoinPaprika as the keyless fallback).
#[derive(Clone)]
pub struct CoinGeckoSettings {
    /// The validated tier (`demo` or `pro`).
    pub tier: gateway_core::pricing::CoinGeckoTier,
    /// The API key, sourced from the environment (a deploy-time secret) and
    /// held in a zeroizing wrapper so it is wiped on drop.
    pub api_key: Zeroizing<String>,
}

/// Redact the API key on `{:?}` so a debug format cannot leak the deploy-time secret.
impl std::fmt::Debug for CoinGeckoSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoinGeckoSettings")
            .field("tier", &self.tier)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

/// Redact the API key on `{:?}` (reporting only whether CoinGecko is configured) so
/// a debug format of the resolved config cannot leak the deploy-time secret.
impl std::fmt::Debug for FxSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FxSettings")
            .field("coingecko", &self.coingecko)
            .field("refresh_schedule", &self.refresh_schedule)
            .field(
                "max_fx_snapshot_age_seconds",
                &self.max_fx_snapshot_age_seconds,
            )
            .finish()
    }
}

/// The content-storage backend a deployment selects.
///
/// Carried as a closed enum (rather than a free string) so a misspelled backend
/// is a config-load error, not a runtime surprise, and so `build_storage` can
/// dispatch exhaustively. The persisted identifier each backend carries on its
/// rows (`turbo`, `direct-arweave`, `arlocal`) is the backend's own `name()`, so
/// the enum and the on-row string can never drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackendKind {
    /// The Turbo upload service (the default): an ANS-104 data item POSTed to a
    /// bundler, drawing the operator's prepaid winc credit.
    Turbo,
    /// The direct-Arweave fallback. Selectable but not yet implemented, so it
    /// fails fast at boot rather than serving a backend that cannot store.
    DirectArweave,
    /// The local ArLocal emulator, for dev and integration tests. Refuses to run
    /// on a production network.
    ArLocal,
}

impl StorageBackendKind {
    /// The backend's persisted identifier — the same string its rows carry and
    /// its `StorageBackend::name()` reports, so the enum and the on-row string
    /// can never drift.
    pub fn name(self) -> &'static str {
        match self {
            Self::Turbo => "turbo",
            Self::DirectArweave => "direct-arweave",
            Self::ArLocal => "arlocal",
        }
    }

    /// Parse the on-disk backend discriminator, normalising the underscore alias
    /// to the canonical hyphen form so a `direct_arweave` in the file resolves to
    /// the same backend whose rows carry `direct-arweave`.
    fn parse(value: &str) -> Result<Self> {
        match value {
            "turbo" => Ok(Self::Turbo),
            "direct-arweave" | "direct_arweave" => Ok(Self::DirectArweave),
            "arlocal" => Ok(Self::ArLocal),
            other => Err(anyhow!(
                "unknown storage backend {other:?}; expected \"turbo\", \"direct-arweave\", or \"arlocal\""
            )),
        }
    }
}

/// The resolved content-storage configuration.
///
/// Distinct from the raw `[storage]` file shape: the backend discriminator is
/// parsed to a closed enum (underscore aliases normalised), the per-byte storage
/// rate is validated non-negative, and the in-flight ordering invariants the
/// reservation lifecycle depends on (the recovery horizon and the claim-lease TTL
/// must both exceed the upload timeout) are checked here, at load, before the
/// runtime ever starts.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// The selected backend.
    pub backend: StorageBackendKind,
    /// The Turbo upload-service base URL (the POST target). Required for `turbo`.
    pub upload_url: String,
    /// The Turbo payment-service base URL the winc-credit reconcile loop reads the
    /// live balance through. The upload service and the payment service are
    /// distinct Turbo hosts, so this is a separate value; required for `turbo`.
    pub payment_url: String,
    /// The Arweave gateway base URL a data-item lookup resolves against (the
    /// crash-recovery sweep's `lookup_data_item` and the `ar://` resolution).
    pub gateway_url: String,
    /// The local ArLocal endpoint. Required for `arlocal`; unused otherwise.
    pub arlocal_endpoint: String,
    /// The directory `stage_stream` writes the tmpfs scratch file to. May be a
    /// tmpfs mount: content is streamed through it, never buffered in memory.
    pub staging_dir: PathBuf,
    /// The durable directory a `reserved` attempt's staged content is promoted to
    /// so it survives a process crash. MUST be on non-tmpfs storage; the recovery
    /// sweep re-POSTs from here.
    pub durable_staging_dir: PathBuf,
    /// The free-storage byte window content under which is stored at no charge.
    pub free_storage_bytes: u64,
    /// The per-byte storage rate, in femto-USD per byte, the quote forecasts the
    /// storage cost from. A real operator value (the engine arithmetic is already
    /// correct; only the reference binary fed zero before).
    pub ar_usd_per_byte_femto: i64,
    /// The cron the winc-credit reconcile loop fires on (the only winc network
    /// caller).
    pub winc_refresh_schedule: String,
    /// The believed-winc balance below which the cached-credit affordability read
    /// refuses an upload.
    pub winc_safety_floor: rust_decimal::Decimal,
    /// The drift the reconcile loop alerts on: when `|live - believed|` exceeds
    /// this, the live balance moved more than the gateway's own charges explain.
    pub winc_drift_alert_threshold: rust_decimal::Decimal,
    /// How long a `reserved` attempt must be outstanding before the recovery sweep
    /// may act on it. Validated to exceed `upload_timeout`, so a slow-but-live
    /// upload is never swept.
    pub reconcile_horizon: Duration,
    /// The wall-clock ceiling on a single provider POST. The streamed POST is
    /// aborted when this elapses, strictly before the claim-lease can lapse.
    pub upload_timeout: Duration,
    /// The external-POST claim-lease lifetime. Validated to exceed `upload_timeout`
    /// so a healthy owner's abort always fires before its lease can lapse, leaving
    /// no steady-state overlap of two live POSTs for one data item.
    pub upload_claim_lease_ttl: Duration,
    /// How many consecutive sweep passes a provider-unreachable attempt may stay
    /// unresolved before `storage.attempt.stuck` alerts.
    pub attempt_stuck_passes: u32,
    /// The resumable / chunked upload session tunables (per-chunk ceiling and
    /// suggested size, abandoned-session TTL, per-account open-session cap). Threaded
    /// into the data plane's `ApiConfig`; the session's assembling directory reuses
    /// `durable_staging_dir`, so it is not a separate knob.
    pub session_limits: gateway_core::storage::UploadSessionLimits,
}

impl std::fmt::Debug for GatewayConfig {
    /// A redacted debug rendering: the keyring passphrase is never printed, and
    /// the database URL (which may carry a password) is elided. This keeps the
    /// type usable with combinators like `Result::expect_err` without ever
    /// leaking a secret into a panic message or a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("database_url", &"<redacted>")
            .field("worker_id", &self.worker_id)
            .field("wallet", &self.wallet)
            .field("fee_shape_record_sizes", &self.fee_shape_record_sizes)
            .field("keyring_path", &self.keyring_path)
            .field("keyring_passphrase", &"<redacted>")
            .field("storage", &self.storage)
            .finish()
    }
}

impl GatewayConfig {
    /// Load and resolve the configuration from a TOML file path plus environment
    /// overrides.
    ///
    /// The database URL and keyring passphrase come from the environment (they
    /// are deploy-time secrets); everything else comes from the file. The
    /// resolved wallet config is validated for band shape here; the heavier
    /// fee-shape stability check runs at startup once protocol parameters are
    /// loaded.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let file: FileConfig = toml::from_str(&raw)
            .with_context(|| format!("parsing config file {}", path.display()))?;
        file.resolve(Environment::from_process()?)
    }
}

/// The deploy-time, environment-sourced inputs the file config is merged with.
///
/// Reading the environment is isolated here so the merge logic ([`FileConfig::resolve`])
/// is a pure function of the file plus this struct, and a test can exercise it
/// with explicit values instead of mutating process-global variables.
struct Environment {
    /// The required Postgres URL (`GATEWAY_DATABASE_URL`).
    database_url: Option<String>,
    /// The required keyring passphrase, supplied through
    /// `GATEWAY_KEYRING_PASSPHRASE` or its `_FILE` twin.
    keyring_passphrase: Option<Zeroizing<String>>,
    /// An optional keyring path override (`GATEWAY_KEYRING_PATH`).
    keyring_path: Option<PathBuf>,
    /// An optional worker-id override (`GATEWAY_WORKER_ID`).
    worker_id: Option<String>,
    /// The host name fallback for the worker id when nothing else supplies one.
    hostname: Option<String>,
    /// The optional CoinGecko API key the live FX loop authenticates with,
    /// supplied through `GATEWAY_COINGECKO_API_KEY` or its `_FILE` twin.
    coingecko_api_key: Option<Zeroizing<String>>,
    /// The optional Blockfrost project id the chain gateway's failover secondary
    /// authenticates with, supplied through `GATEWAY_BLOCKFROST_PROJECT_ID` or
    /// its `_FILE` twin.
    blockfrost_project_id: Option<Zeroizing<String>>,
    /// The optional Koios API key every Koios request authenticates with,
    /// supplied through `GATEWAY_KOIOS_API_KEY` or its `_FILE` twin.
    koios_api_key: Option<Zeroizing<String>>,
}

impl Environment {
    /// Snapshot the process environment, resolving each secret that supports the
    /// docker-secrets `_FILE` convention through [`merge_secret_sources`]. Fails
    /// when a secret is supplied through both its plain variable and its `_FILE`
    /// twin, or when a named secret file cannot be read.
    fn from_process() -> Result<Self> {
        Ok(Self {
            database_url: std::env::var(DATABASE_URL_ENV).ok(),
            keyring_passphrase: keyring_passphrase_from_env()?,
            keyring_path: std::env::var_os(KEYRING_PATH_ENV).map(PathBuf::from),
            worker_id: std::env::var(WORKER_ID_ENV).ok(),
            hostname: std::env::var("HOSTNAME").ok(),
            coingecko_api_key: secret_from_env(COINGECKO_API_KEY_ENV, COINGECKO_API_KEY_FILE_ENV)?
                .map(|s| Zeroizing::new(s.trim().to_string()))
                .filter(|s| !s.is_empty()),
            blockfrost_project_id: secret_from_env(
                BLOCKFROST_PROJECT_ID_ENV,
                BLOCKFROST_PROJECT_ID_FILE_ENV,
            )?
            .map(|s| Zeroizing::new(s.trim().to_string()))
            .filter(|s| !s.is_empty()),
            koios_api_key: secret_from_env(KOIOS_API_KEY_ENV, KOIOS_API_KEY_FILE_ENV)?
                .map(|s| Zeroizing::new(s.trim().to_string()))
                .filter(|s| !s.is_empty()),
        })
    }
}

/// Read the operator keyring passphrase from its environment pair
/// ([`KEYRING_PASSPHRASE_ENV`] / [`KEYRING_PASSPHRASE_FILE_ENV`]), straight
/// into a zeroizing wrapper.
///
/// Returns `Ok(None)` when neither variable is set: the serve path then fails
/// its required-secret check, while the `gateway keyring` subcommands fall back
/// to an interactive hidden prompt. Both variables set is an error.
pub fn keyring_passphrase_from_env() -> Result<Option<Zeroizing<String>>> {
    secret_from_env(KEYRING_PASSPHRASE_ENV, KEYRING_PASSPHRASE_FILE_ENV)
}

/// Read the NEW keyring passphrase for `gateway keyring change-passphrase` from
/// its environment pair ([`KEYRING_NEW_PASSPHRASE_ENV`] /
/// [`KEYRING_NEW_PASSPHRASE_FILE_ENV`]), straight into a zeroizing wrapper.
///
/// Returns `Ok(None)` when neither variable is set (the subcommand then prompts
/// interactively). Both variables set is an error.
pub fn keyring_new_passphrase_from_env() -> Result<Option<Zeroizing<String>>> {
    secret_from_env(KEYRING_NEW_PASSPHRASE_ENV, KEYRING_NEW_PASSPHRASE_FILE_ENV)
}

/// Read a `_FILE`-capable secret from the process environment: snapshot the
/// plain variable and its `_FILE` twin, then merge them through
/// [`merge_secret_sources`]. A thin wrapper so the merge semantics stay a pure,
/// directly testable function.
///
/// Exposed to the crate so secrets resolved outside config load — the optional
/// monitoring DSN, which must be read before the config file is even parsed —
/// obey the exact same one-source-only, docker-secret `_FILE` semantics as every
/// other gateway secret rather than re-implementing them.
pub(crate) fn secret_from_env(name: &str, file_name: &str) -> Result<Option<Zeroizing<String>>> {
    merge_secret_sources(
        name,
        file_name,
        std::env::var(name).ok(),
        std::env::var_os(file_name).map(PathBuf::from),
    )
}

/// Merge a secret's two sources: the plain variable and its `_FILE` twin.
///
/// Exactly one source may supply the secret — both set is an error, so an
/// ambiguous deployment fails loudly instead of one source silently winning. A
/// `_FILE` value is read from disk with trailing whitespace trimmed (a docker
/// secret carries a trailing newline; leading whitespace may be meaningful in a
/// passphrase, so only the end is trimmed), and a missing or unreadable file is
/// an error: the variable explicitly pointed at it. A plain value is returned
/// verbatim. Every owned copy of the secret — the raw file contents included —
/// lives in a zeroizing buffer so it is wiped on drop. Pure in its inputs so
/// tests exercise every branch without mutating process-global environment
/// variables.
pub(crate) fn merge_secret_sources(
    name: &str,
    file_name: &str,
    direct: Option<String>,
    file_path: Option<PathBuf>,
) -> Result<Option<Zeroizing<String>>> {
    match (direct, file_path) {
        (Some(_), Some(_)) => Err(anyhow!(
            "both {name} and {file_name} are set; supply the secret through exactly one"
        )),
        (Some(value), None) => Ok(Some(Zeroizing::new(value))),
        (None, Some(path)) => {
            let raw = Zeroizing::new(std::fs::read_to_string(&path).with_context(|| {
                format!(
                    "reading the {name} secret from the file {file_name} names ({})",
                    path.display()
                )
            })?);
            Ok(Some(Zeroizing::new(raw.trim_end().to_string())))
        }
        (None, None) => Ok(None),
    }
}

/// The raw TOML file shape, before validation and environment merging.
#[derive(Debug, Deserialize)]
struct FileConfig {
    /// The Cardano network the deployment runs on (`mainnet`, `preprod`,
    /// `preview`).
    network: String,
    /// The identity stamped onto job claims, if the environment does not
    /// override it. Defaults to the host name when neither is set.
    #[serde(default)]
    worker_id: Option<String>,
    /// The canonical lovelace band.
    band: BandConfig,
    /// The wallet subsystem tuning.
    wallet: WalletTuning,
    /// The operator keyring ciphertext path (an environment override takes
    /// precedence).
    keyring_path: PathBuf,
    /// The record sizes the band's fee-shape stability is certified against.
    #[serde(default = "default_fee_shape_record_sizes")]
    fee_shape_record_sizes: Vec<usize>,
    /// The optional HTTP data-plane section. Absent runs the background plane
    /// alone.
    #[serde(default)]
    http: Option<HttpFileConfig>,
    /// The optional content-storage section. Absent is an intentional hash-only
    /// deployment (uploads report unavailable; the quote skips the storage
    /// affordability branch).
    #[serde(default)]
    storage: Option<StorageFileConfig>,
    /// The optional live-FX section. Present runs the engine's own FX refresh cron
    /// and prices quotes from the cached snapshot; absent leaves the binary on the
    /// static `[http]` rate.
    #[serde(default)]
    fx: Option<FxFileConfig>,
    /// The optional control-plane section. Absent uses the control defaults.
    #[serde(default)]
    control: Option<ControlFileConfig>,
    /// The optional webhook section. Absent uses the production-safe defaults
    /// (HTTPS-only targets, the SSRF range-block always on).
    #[serde(default)]
    webhooks: Option<WebhookFileConfig>,
    /// The optional chain-provider section. Absent (or absent of a Blockfrost
    /// path) leaves the failover secondary a second Koios instance.
    #[serde(default)]
    chain: Option<ChainFileConfig>,
}

/// The raw `[chain]` file section: chain-provider knobs that are not secrets.
///
/// Carries the optional Koios base-URL override, the path to the Blockfrost
/// project-id secret (never the secret itself; the
/// `GATEWAY_BLOCKFROST_PROJECT_ID` environment value takes precedence,
/// mirroring how the CoinGecko key is sourced), and the optional per-provider
/// egress budget overrides. The Koios API key is a secret and rides only the
/// `GATEWAY_KOIOS_API_KEY` environment pair, never this section.
#[derive(Debug, Deserialize)]
struct ChainFileConfig {
    /// A full Koios base URL (e.g. `https://koios.example/api/v1`) that
    /// replaces the per-network public `koios.rest` URL everywhere Koios is
    /// addressed — the chain gateway (both failover arms when no Blockfrost
    /// secret is configured), the protocol-parameter source, and the
    /// replenisher's UTxO source. Koios is open source, so a self-hosted
    /// instance removes the public tiers' limits entirely.
    ///
    /// Validated at load: it must parse as an `http`/`https` URL with a host
    /// and no query or fragment, and is normalised to the canonical no-
    /// trailing-slash form (paths are appended verbatim, e.g. `{koios_url}/tip`).
    ///
    /// The operator is responsible for pointing it at an instance of THIS
    /// deployment's network — the gateway cannot cheaply verify it (a Koios
    /// `/tip` carries no network identifier). On a mismatch the engine would
    /// cache the wrong network's protocol parameters and index the wrong
    /// chain's records; the first hard symptom is a deterministic node
    /// rejection on submit (wrong-network addresses), which abandons the
    /// attempt and auto-refunds rather than publishing.
    #[serde(default)]
    koios_url: Option<String>,
    /// The path to a file holding the Blockfrost project id (trimmed of trailing
    /// whitespace). A missing file means no secret is mounted, so the secondary
    /// degrades to a second Koios instance.
    #[serde(default)]
    blockfrost_project_id_path: Option<PathBuf>,
    /// The sustained per-provider egress rate (requests per minute) the local
    /// budget admits. Absent uses the engine default, which is tuned to keep a
    /// runaway loop under the keyless Koios free tier's daily quota; an
    /// operator with a registered-tier key or a self-hosted Koios may raise it.
    #[serde(default)]
    egress_requests_per_minute: Option<u32>,
    /// The per-provider egress burst capacity. Absent uses the engine default
    /// (same keyless-free-tier tuning note as `egress_requests_per_minute`).
    #[serde(default)]
    egress_burst: Option<u32>,
}

/// The raw `[webhooks]` file section. Absent uses the production-safe defaults.
#[derive(Debug, Deserialize)]
struct WebhookFileConfig {
    /// Allow `http://` delivery targets (self-host only); the SSRF range-block
    /// stays on regardless. Default `false`.
    #[serde(default)]
    allow_insecure_http: bool,
    /// Allow loopback/private-range delivery targets (test only). Maps to the
    /// SDK egress guard's `allow_private_for_tests` seam; loosens only the
    /// range-block, never the HTTPS requirement. Default `false`.
    #[serde(default)]
    egress_allow_loopback: bool,
}

/// The raw `[fx]` file section. Present runs the live FX refresh cron.
#[derive(Debug, Deserialize)]
struct FxFileConfig {
    /// The CoinGecko tier (`demo` or `pro`), set only when configuring CoinGecko as
    /// the primary price provider. Absent runs the keyless CoinPaprika default. The
    /// API key is a secret and comes from the environment, never the file; a tier
    /// without a key (or a key without a tier) is a load error.
    #[serde(default)]
    coingecko_tier: Option<String>,
    /// The FX refresh cron; defaults to every fifteen minutes.
    #[serde(default = "default_fx_refresh_schedule")]
    refresh_schedule: String,
    /// The freshness ceiling, in seconds, beyond which a cached snapshot stops
    /// pricing quotes. Defaults to one hour.
    #[serde(default = "default_max_fx_snapshot_age_seconds")]
    max_fx_snapshot_age_seconds: i64,
}

/// The default FX refresh cron: every fifteen minutes, the engine's default.
fn default_fx_refresh_schedule() -> String {
    gateway_core::pricing::DEFAULT_FX_REFRESH_SCHEDULE.to_string()
}

/// The default FX-snapshot freshness ceiling: one hour. At the default 15-minute
/// refresh cadence a healthy snapshot is at most ~15 minutes old, so an hour rides
/// out a few consecutive missed ticks (the skip-and-serve discipline) while still
/// refusing a quote long before an oracle outage could mis-bill at a badly stale rate.
fn default_max_fx_snapshot_age_seconds() -> i64 {
    3600
}

/// The raw `[control]` file section.
#[derive(Debug, Deserialize)]
struct ControlFileConfig {
    /// The secret prefix minted control credentials and keys carry.
    #[serde(default = "default_control_secret_prefix")]
    secret_prefix: String,
    /// The operator-token lifetime, in seconds.
    #[serde(default = "default_operator_token_ttl_secs")]
    operator_token_ttl_secs: i64,
    /// The account-token lifetime, in seconds.
    #[serde(default = "default_account_token_ttl_secs")]
    account_token_ttl_secs: i64,
    /// The single-adjustment cap, in micro-USD.
    #[serde(default = "default_adjustment_cap_usd_micros")]
    adjustment_cap_usd_micros: i64,
    /// Whether the static admin UI is served at `/admin`.
    #[serde(default = "default_admin_ui_enabled")]
    admin_ui_enabled: bool,
    /// The spend scope a new wallet is granted by default (`service`/`operator`).
    #[serde(default = "default_wallet_scope")]
    default_wallet_scope: String,
    /// The draw scope a new funding source is granted by default
    /// (`service`/`operator`).
    #[serde(default = "default_storage_scope")]
    default_storage_scope: String,
}

/// The default control secret prefix.
fn default_control_secret_prefix() -> String {
    "ctl_".to_string()
}

/// The default spend scope a newly registered wallet is granted: the
/// single-tenant `service` scope (every operator/account may spend it).
fn default_wallet_scope() -> String {
    "service".to_string()
}

/// The default draw scope a newly registered funding source is granted: the
/// single-tenant `service` scope (every account may draw it).
fn default_storage_scope() -> String {
    "service".to_string()
}

/// The default operator-token lifetime (24 hours).
fn default_operator_token_ttl_secs() -> i64 {
    24 * 3600
}

/// The default account-token lifetime (1 hour).
fn default_account_token_ttl_secs() -> i64 {
    3600
}

/// The default single-adjustment cap ($10,000).
fn default_adjustment_cap_usd_micros() -> i64 {
    10_000_000_000
}

/// The static admin UI defaults to served.
fn default_admin_ui_enabled() -> bool {
    true
}

/// The raw `[http]` file section.
#[derive(Debug, Deserialize)]
struct HttpFileConfig {
    /// The socket address the API binds.
    bind: String,
    /// The problem-`type` documentation base URL (operator config).
    #[serde(default)]
    problem_type_base: String,
    /// The ADA→USD conversion (micro-USD per ADA) the quote prices the network fee
    /// through. Required when the HTTP plane is served (no live oracle is bundled).
    ada_usd_micros: i64,
    /// The quote markup over cost of goods, as a fraction (e.g. `0.25`).
    margin_pct: f64,
    /// The ordinary-request wall-clock ceiling in seconds. Defaults to 30.
    #[serde(default = "default_request_timeout_secs")]
    request_timeout_secs: u64,
    /// The anonymous per-client-address budget (requests per minute) on the public
    /// records reads. Defaults to 120.
    #[serde(default = "default_anon_rate_limit_per_min")]
    anon_rate_limit_per_min: i64,
    /// The instance-wide live-SSE-stream ceiling. Defaults to 1024.
    #[serde(default = "default_sse_max_streams")]
    sse_max_streams: u32,
    /// The per-account live-SSE-stream ceiling. Defaults to 32.
    #[serde(default = "default_sse_max_streams_per_account")]
    sse_max_streams_per_account: u32,
}

/// The default ordinary-request ceiling: 30 seconds. Generous for every
/// non-streaming route (quotes, publishes, reads, control-plane CRUD, the
/// chain-balance console reads), tight enough that a wedged handler or a
/// drip-fed body frees its connection promptly.
fn default_request_timeout_secs() -> u64 {
    gateway_core::api::DEFAULT_REQUEST_TIMEOUT_SECS
}

/// The default anonymous per-address budget on the public records reads.
fn default_anon_rate_limit_per_min() -> i64 {
    gateway_core::api::DEFAULT_ANON_RATE_LIMIT_PER_MIN
}

/// The default instance-wide live-SSE-stream ceiling.
fn default_sse_max_streams() -> u32 {
    gateway_core::api::sse::SseLimits::default().max_streams
}

/// The default per-account live-SSE-stream ceiling.
fn default_sse_max_streams_per_account() -> u32 {
    gateway_core::api::sse::SseLimits::default().max_streams_per_account
}

/// The raw `[storage]` file section. Present means the deployment uploads
/// content; absent is an intentional hash-only deployment.
#[derive(Debug, Deserialize)]
struct StorageFileConfig {
    /// The selected backend (`turbo`, `direct-arweave`/`direct_arweave`,
    /// `arlocal`). No default: a `[storage]` section names its backend explicitly.
    backend: String,
    /// The Turbo upload-service base URL. Required for the Turbo backend.
    #[serde(default)]
    upload_url: String,
    /// The Turbo payment-service base URL the winc-credit reconcile loop reads the
    /// live balance through. Required for the Turbo backend (a distinct host from
    /// the upload service).
    #[serde(default)]
    payment_url: String,
    /// The Arweave gateway base URL data-item lookups resolve against.
    #[serde(default = "default_gateway_url")]
    gateway_url: String,
    /// The local ArLocal endpoint. Required for the ArLocal backend.
    #[serde(default)]
    arlocal_endpoint: String,
    /// The tmpfs scratch directory; defaults to the system temp dir.
    #[serde(default)]
    staging_dir: Option<PathBuf>,
    /// The durable directory a reservation's staged content is promoted to.
    /// Required when `[storage]` is present (a crash must not lose in-flight bytes).
    durable_staging_dir: PathBuf,
    /// The free-storage byte window; defaults to 100 KiB when omitted.
    #[serde(default = "default_free_storage_bytes")]
    free_storage_bytes: u64,
    /// The per-byte storage rate, in femto-USD per byte. Required (the engine
    /// arithmetic is already correct; a missing value would silently price storage
    /// at zero).
    ar_usd_per_byte_femto: i64,
    /// The winc-reconcile cron; defaults to every five minutes.
    #[serde(default = "default_winc_refresh_schedule")]
    winc_refresh_schedule: String,
    /// The believed-winc safety floor; defaults to zero (refuse only an unfunded
    /// source).
    #[serde(default)]
    winc_safety_floor: u64,
    /// The winc-drift alert threshold; defaults to zero (alert on any unexplained
    /// provider-side move).
    #[serde(default)]
    winc_drift_alert_threshold: u64,
    /// The recovery-sweep horizon, in seconds. Validated to exceed the upload
    /// timeout. Defaults to 15 minutes.
    #[serde(default = "default_reconcile_horizon_secs")]
    reconcile_horizon_secs: u64,
    /// The single-POST wall-clock ceiling, in seconds. Defaults to 5 minutes.
    #[serde(default = "default_upload_timeout_secs")]
    upload_timeout_secs: u64,
    /// The external-POST claim-lease lifetime, in seconds. Validated to exceed the
    /// upload timeout. Defaults to the upload timeout plus a one-minute margin.
    #[serde(default)]
    upload_claim_lease_ttl_secs: Option<u64>,
    /// Consecutive unresolved sweep passes before `storage.attempt.stuck` alerts.
    #[serde(default = "default_attempt_stuck_passes")]
    attempt_stuck_passes: u32,
    /// The resumable / chunked upload session tunables (the `[storage.sessions]`
    /// subtable). Absent leaves the safe defaults (48 MiB suggested / 64 MiB ceiling
    /// chunks, 24 h TTL, 64 open sessions per account).
    #[serde(default)]
    sessions: SessionFileConfig,
}

/// The raw `[storage.sessions]` subtable: the resumable-upload tunables. Every field
/// defaults to the safe value, so an operator overrides only what its proxy
/// constraints or disk budget require.
#[derive(Debug, Default, Deserialize)]
struct SessionFileConfig {
    /// The hard per-chunk ceiling in bytes (a chunk over this is `413`). Defaults to
    /// 64 MiB, well under a ~100 MB CDN body cap.
    #[serde(default)]
    max_chunk_bytes: Option<u64>,
    /// The chunk-size floor a create request's `chunk_bytes` is clamped up to.
    /// Defaults to 1 MiB — the bound that keeps a session's chunk count (and with
    /// it the received bitmap and the resume sets) small.
    #[serde(default)]
    min_chunk_bytes: Option<u64>,
    /// The suggested chunk size when the client declares none. Defaults to 48 MiB.
    #[serde(default)]
    default_chunk_bytes: Option<u64>,
    /// The abandoned-session horizon in seconds. Defaults to 24 hours.
    #[serde(default)]
    session_ttl_secs: Option<u64>,
    /// The cap on concurrently open sessions per account. Defaults to 64.
    #[serde(default)]
    max_open_sessions_per_account: Option<u32>,
}

impl SessionFileConfig {
    /// Resolve the session tunables, defaulting each field to its safe value and
    /// certifying the chunk-size band is coherent: the floor must be positive (a
    /// zero floor would readmit the degenerate 1-byte chunk grid) and must not
    /// exceed the ceiling (an inverted band can satisfy neither bound).
    fn resolve(self) -> Result<gateway_core::storage::UploadSessionLimits> {
        let defaults = gateway_core::storage::UploadSessionLimits::default();
        let limits = gateway_core::storage::UploadSessionLimits {
            max_chunk_bytes: self.max_chunk_bytes.unwrap_or(defaults.max_chunk_bytes),
            min_chunk_bytes: self.min_chunk_bytes.unwrap_or(defaults.min_chunk_bytes),
            default_chunk_bytes: self
                .default_chunk_bytes
                .unwrap_or(defaults.default_chunk_bytes),
            session_ttl_secs: self.session_ttl_secs.unwrap_or(defaults.session_ttl_secs),
            max_open_sessions_per_account: self
                .max_open_sessions_per_account
                .unwrap_or(defaults.max_open_sessions_per_account),
        };
        if limits.min_chunk_bytes == 0 {
            return Err(anyhow!(
                "storage.sessions.min_chunk_bytes must be positive; a zero floor would let a \
                 client explode a session's chunk count with degenerate 1-byte chunks"
            ));
        }
        if limits.min_chunk_bytes > limits.max_chunk_bytes {
            return Err(anyhow!(
                "storage.sessions.min_chunk_bytes ({}) must not exceed \
                 storage.sessions.max_chunk_bytes ({})",
                limits.min_chunk_bytes,
                limits.max_chunk_bytes
            ));
        }
        Ok(limits)
    }
}

/// The default free-storage byte window (100 KiB).
fn default_free_storage_bytes() -> u64 {
    102_400
}

/// The default Arweave gateway base URL data-item lookups resolve against.
fn default_gateway_url() -> String {
    "https://arweave.net".to_string()
}

/// The default winc-reconcile cron: every five minutes. It is the only winc
/// network caller, so it stays infrequent.
fn default_winc_refresh_schedule() -> String {
    "0 */5 * * * *".to_string()
}

/// The default recovery-sweep horizon (15 minutes). Above the default upload
/// timeout, so a live upload is never swept.
fn default_reconcile_horizon_secs() -> u64 {
    15 * 60
}

/// The default single-POST ceiling (5 minutes).
fn default_upload_timeout_secs() -> u64 {
    5 * 60
}

/// The margin the default claim-lease TTL adds over the upload timeout, covering
/// clock skew and abort teardown.
fn default_lease_margin_secs() -> u64 {
    60
}

/// The default consecutive-unresolved-pass count before the stuck alert fires.
fn default_attempt_stuck_passes() -> u32 {
    12
}

/// The closed lovelace band a canonical UTxO must fall within.
#[derive(Debug, Deserialize)]
struct BandConfig {
    /// Inclusive lower bound.
    min: u64,
    /// Inclusive upper bound.
    max: u64,
    /// The target value the replenisher mints and the quote prices against.
    mid: u64,
}

/// Wallet subsystem tuning carried in the file.
#[derive(Debug, Deserialize)]
struct WalletTuning {
    /// Submit lease lifetime in seconds.
    lease_secs: u64,
    /// Minimum number of canonical, available UTxOs each wallet keeps ready.
    min_canonical_count: u32,
}

/// The default record sizes the band's fee-shape stability is certified against
/// when the file does not specify them. Spans the empty-ish single byte through a
/// large multi-chunk record, so a band that folds anywhere across that spread is
/// rejected at startup.
fn default_fee_shape_record_sizes() -> Vec<usize> {
    vec![1, 64, 65, 1024, 14_000]
}

impl FileConfig {
    /// Validate the file shape and merge in the deploy-time environment inputs.
    /// Pure in `(self, env)`: it touches no global state, so it is deterministic
    /// and testable without mutating process variables.
    fn resolve(self, env: Environment) -> Result<GatewayConfig> {
        let network =
            Network::parse(&self.network).map_err(|e| anyhow!("invalid network in config: {e}"))?;

        let band = LovelaceBand::new(self.band.min, self.band.max, self.band.mid)
            .map_err(|e| anyhow!("invalid lovelace band in config: {e}"))?;

        let wallet = WalletConfig::new(
            network,
            band,
            Duration::from_secs(self.wallet.lease_secs),
            self.wallet.min_canonical_count,
        )
        .map_err(|e| anyhow!("invalid wallet config: {e}"))?;

        if self.fee_shape_record_sizes.is_empty() {
            return Err(anyhow!(
                "fee_shape_record_sizes must list at least one record size to certify the band against"
            ));
        }

        let database_url = env
            .database_url
            .with_context(|| format!("{DATABASE_URL_ENV} must be set"))?;

        let keyring_passphrase = env
            .keyring_passphrase
            .with_context(|| format!("{KEYRING_PASSPHRASE_ENV} must be set"))?;

        // The environment override wins over the file path.
        let keyring_path = env.keyring_path.unwrap_or(self.keyring_path);

        let worker_id = env
            .worker_id
            .or(self.worker_id)
            .or(env.hostname)
            .unwrap_or_else(|| "gateway".to_string());

        let http = self
            .http
            .map(|h| {
                // A zero bound would refuse (or instantly time out) every request:
                // each of these knobs exists to bound abuse, never to disable the
                // surface, so a zero is a load error rather than a dead deployment.
                if h.request_timeout_secs == 0 {
                    return Err(anyhow!(
                        "http.request_timeout_secs must be positive; a zero ceiling would time \
                         out every request"
                    ));
                }
                if h.anon_rate_limit_per_min <= 0 {
                    return Err(anyhow!(
                        "http.anon_rate_limit_per_min must be positive; a zero budget would deny \
                         every anonymous records read"
                    ));
                }
                if h.sse_max_streams == 0 || h.sse_max_streams_per_account == 0 {
                    return Err(anyhow!(
                        "http.sse_max_streams and http.sse_max_streams_per_account must be \
                         positive; a zero cap would refuse every event stream"
                    ));
                }
                Ok(HttpConfig {
                    bind: h.bind,
                    problem_type_base: h.problem_type_base,
                    ada_usd_micros: h.ada_usd_micros,
                    margin_pct: h.margin_pct,
                    request_timeout_secs: h.request_timeout_secs,
                    anon_rate_limit_per_min: h.anon_rate_limit_per_min,
                    sse_max_streams: h.sse_max_streams,
                    sse_max_streams_per_account: h.sse_max_streams_per_account,
                })
            })
            .transpose()?;

        let storage = self.storage.map(StorageFileConfig::resolve).transpose()?;

        let fx = self
            .fx
            .map(|f| FxFileConfig::resolve(f, env.coingecko_api_key))
            .transpose()?;

        let control = self
            .control
            .map(|c| ControlSettings {
                secret_prefix: c.secret_prefix,
                operator_token_ttl_secs: c.operator_token_ttl_secs,
                account_token_ttl_secs: c.account_token_ttl_secs,
                adjustment_cap_usd_micros: c.adjustment_cap_usd_micros,
                admin_ui_enabled: c.admin_ui_enabled,
                default_wallet_scope: c.default_wallet_scope,
                default_storage_scope: c.default_storage_scope,
            })
            .unwrap_or_default();

        // Reject an unrecognised default wallet scope at load, before the runtime
        // starts: only `service` and `operator` are expressible as a registration
        // default (an `account` default names no account at registration time).
        if gateway_core::api::DefaultWalletScope::parse(&control.default_wallet_scope).is_none() {
            return Err(anyhow!(
                "invalid control.default_wallet_scope {:?}; must be \"service\" or \"operator\"",
                control.default_wallet_scope
            ));
        }

        // The storage twin of the same check: a funding-source registration default
        // is `service` or `operator` only (an `account` default names no account).
        if gateway_core::api::DefaultStorageScope::parse(&control.default_storage_scope).is_none() {
            return Err(anyhow!(
                "invalid control.default_storage_scope {:?}; must be \"service\" or \"operator\"",
                control.default_storage_scope
            ));
        }

        let webhooks = self
            .webhooks
            .map(|w| WebhookSettings {
                allow_insecure_http: w.allow_insecure_http,
                egress_allow_loopback: w.egress_allow_loopback,
            })
            .unwrap_or_default();

        // The Blockfrost project id: the environment secret wins; otherwise read
        // it from the configured file path. A missing file degrades to no secret
        // (the failover secondary stays a second Koios instance). The same
        // section carries the optional egress-budget overrides; a zero rate or
        // burst would deny every request, so both are rejected at load.
        let chain = self.chain;
        let chain_project_id_path = chain
            .as_ref()
            .and_then(|c| c.blockfrost_project_id_path.clone());
        let blockfrost_project_id = match env.blockfrost_project_id {
            Some(id) => Some(id),
            None => match chain_project_id_path {
                Some(path) => read_optional_secret_file(&path)?,
                None => None,
            },
        };
        let default_egress = gateway_core::chain::egress::EgressLimits::default();
        let chain_egress = gateway_core::chain::egress::EgressLimits {
            requests_per_minute: chain
                .as_ref()
                .and_then(|c| c.egress_requests_per_minute)
                .unwrap_or(default_egress.requests_per_minute),
            burst: chain
                .as_ref()
                .and_then(|c| c.egress_burst)
                .unwrap_or(default_egress.burst),
        };
        if chain_egress.requests_per_minute == 0 || chain_egress.burst == 0 {
            return Err(anyhow!(
                "chain.egress_requests_per_minute and chain.egress_burst must be positive; \
                 a zero budget would deny every provider request"
            ));
        }

        // How Koios is addressed: the optional `[chain] koios_url` override
        // (validated and normalised here, at load, so a malformed provider URL
        // stops the boot instead of surfacing as a transport error on the first
        // chain call) plus the environment-sourced API key.
        let koios = gateway_core::chain::params::KoiosConfig {
            base_url: chain
                .as_ref()
                .and_then(|c| c.koios_url.as_deref())
                .map(validate_koios_url)
                .transpose()?,
            api_key: validate_koios_api_key(env.koios_api_key)?,
        };

        Ok(GatewayConfig {
            database_url,
            worker_id,
            wallet,
            fee_shape_record_sizes: self.fee_shape_record_sizes,
            keyring_path,
            keyring_passphrase,
            http,
            storage,
            fx,
            control,
            webhooks,
            blockfrost_project_id,
            koios,
            chain_egress,
        })
    }
}

/// Validate and normalise the `[chain] koios_url` override.
///
/// Accepts an absolute `http`/`https` URL with a host and no query or fragment,
/// and returns it in the canonical no-trailing-slash form so path concatenation
/// (`{koios_url}/tip`) can never produce a `//tip`. Rejection here is a load
/// error: a malformed provider URL must stop the boot, never surface as a
/// transport error on the first chain call.
fn validate_koios_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|e| anyhow!("invalid chain.koios_url {trimmed:?}: {e}"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(anyhow!(
            "invalid chain.koios_url {trimmed:?}: the scheme must be http or https"
        ));
    }
    if parsed.host_str().is_none() {
        return Err(anyhow!(
            "invalid chain.koios_url {trimmed:?}: the URL names no host"
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(anyhow!(
            "invalid chain.koios_url {trimmed:?}: a base URL carries no query string or fragment"
        ));
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

/// Validate the Koios API key's shape: a single ASCII token with no whitespace
/// or control characters, since it is sent verbatim inside an HTTP
/// `Authorization: Bearer` header. A malformed key is a load error rather than
/// a per-request header-construction failure on every chain call.
fn validate_koios_api_key(key: Option<Zeroizing<String>>) -> Result<Option<Zeroizing<String>>> {
    let Some(key) = key else { return Ok(None) };
    if key
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || !c.is_ascii())
    {
        return Err(anyhow!(
            "{KOIOS_API_KEY_ENV} contains whitespace, control, or non-ASCII characters; a Koios \
             API key is a single ASCII token sent as an HTTP Authorization header"
        ));
    }
    Ok(Some(key))
}

/// Read a deploy-time secret from a file, returning `None` when the file is
/// absent (no secret mounted) or holds only whitespace, and an error for any
/// other read failure. The value is trimmed of trailing whitespace so a trailing
/// newline never leaks into the secret. Both the raw file contents and the
/// returned value live in zeroizing buffers so every copy is wiped on drop.
fn read_optional_secret_file(path: &Path) -> Result<Option<Zeroizing<String>>> {
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            let raw = Zeroizing::new(raw);
            let trimmed = Zeroizing::new(raw.trim().to_string());
            Ok((!trimmed.is_empty()).then_some(trimmed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("reading secret from {}: {e}", path.display())),
    }
}

impl FxFileConfig {
    /// Validate the `[fx]` file shape and merge in the environment-sourced API key.
    ///
    /// CoinGecko is opt-in and key-bound: a `demo`/`pro` tier and the
    /// `GATEWAY_COINGECKO_API_KEY` secret must both be present, or both absent. A
    /// tier without a key, or a key without a tier, is a boot error — never a silent
    /// fallback. With neither set the deployment prices from the keyless CoinPaprika
    /// default, which needs no configuration.
    fn resolve(self, coingecko_api_key: Option<Zeroizing<String>>) -> Result<FxSettings> {
        let tier_token = self
            .coingecko_tier
            .as_ref()
            .map(|t| t.trim().to_lowercase());
        let coingecko = match (tier_token, coingecko_api_key) {
            // Both present: validate the tier and build the CoinGecko credential.
            (Some(tier), Some(api_key)) => {
                let tier = gateway_core::pricing::CoinGeckoTier::parse(&tier).ok_or_else(|| {
                    anyhow!(
                        "invalid fx.coingecko_tier {tier:?}; must be \"demo\" or \"pro\" \
                         (CoinGecko is used only with a key — the keyless default is CoinPaprika)"
                    )
                })?;
                Some(CoinGeckoSettings { tier, api_key })
            }
            // A tier without a key: CoinGecko cannot authenticate. Fail rather than
            // silently dropping to CoinPaprika and ignoring the operator's tier.
            (Some(tier), None) => {
                return Err(anyhow!(
                    "fx.coingecko_tier {tier:?} is set but {COINGECKO_API_KEY_ENV} is not; \
                     CoinGecko needs a key. Remove the tier to price from the keyless CoinPaprika \
                     default, or set the key."
                ));
            }
            // A key without a tier: ambiguous (demo vs pro use different hosts). Fail
            // rather than guessing the wrong endpoint.
            (None, Some(_)) => {
                return Err(anyhow!(
                    "{COINGECKO_API_KEY_ENV} is set but fx.coingecko_tier is not; set it to \
                     \"demo\" or \"pro\" to use the key, or unset the key to price from the keyless \
                     CoinPaprika default."
                ));
            }
            // Neither: the keyless CoinPaprika default.
            (None, None) => None,
        };
        // The freshness ceiling must be a positive number of seconds: a zero or
        // negative value would refuse every quote (no snapshot can be that fresh),
        // so it is a boot error rather than a deployment that never prices.
        if self.max_fx_snapshot_age_seconds <= 0 {
            return Err(anyhow!(
                "fx.max_fx_snapshot_age_seconds must be a positive number of seconds, got {}; \
                 it is the freshness ceiling beyond which a cached snapshot stops pricing quotes",
                self.max_fx_snapshot_age_seconds
            ));
        }
        Ok(FxSettings {
            coingecko,
            refresh_schedule: self.refresh_schedule,
            max_fx_snapshot_age_seconds: self.max_fx_snapshot_age_seconds,
        })
    }
}

impl StorageFileConfig {
    /// Validate the `[storage]` file shape and resolve it: parse the backend
    /// discriminator (normalising the underscore alias), convert the safety floor
    /// and drift threshold to fixed-point, and certify the two in-flight ordering
    /// invariants the reservation lifecycle rests on — the recovery horizon and the
    /// claim-lease TTL must both exceed the upload timeout, so a slow-but-live
    /// upload is never swept and a healthy owner's POST abort always fires before
    /// its lease can lapse.
    fn resolve(self) -> Result<StorageConfig> {
        let backend = StorageBackendKind::parse(&self.backend)?;

        let upload_timeout = Duration::from_secs(self.upload_timeout_secs);
        let reconcile_horizon = Duration::from_secs(self.reconcile_horizon_secs);
        // Default the claim-lease TTL to the upload timeout plus a margin so the
        // POST abort always precedes the lease lapse without the operator having to
        // hand-tune the relationship.
        let upload_claim_lease_ttl = Duration::from_secs(
            self.upload_claim_lease_ttl_secs
                .unwrap_or(self.upload_timeout_secs + default_lease_margin_secs()),
        );

        // The horizon must exceed the upload timeout, or the sweep could act on an
        // upload that is still live.
        if reconcile_horizon <= upload_timeout {
            return Err(anyhow!(
                "storage.reconcile_horizon_secs ({}) must exceed storage.upload_timeout_secs ({}) \
                 so a live upload is never swept",
                self.reconcile_horizon_secs,
                self.upload_timeout_secs
            ));
        }
        // The claim-lease must outlive the upload timeout, so the in-flight owner's
        // abort fires strictly before its lease can lapse and no second contender
        // can claim the POST window while a healthy owner still holds it.
        if upload_claim_lease_ttl <= upload_timeout {
            return Err(anyhow!(
                "storage.upload_claim_lease_ttl_secs ({}) must exceed storage.upload_timeout_secs \
                 ({}) so the POST abort always precedes the lease lapse",
                upload_claim_lease_ttl.as_secs(),
                self.upload_timeout_secs
            ));
        }

        // The Turbo backend needs both of its service URLs: the upload service it
        // POSTs to and the payment service the reconcile loop reads the winc balance
        // from. A missing URL is a boot failure, never a silently broken backend.
        if backend == StorageBackendKind::Turbo {
            if self.upload_url.trim().is_empty() {
                return Err(anyhow!(
                    "storage.upload_url is required for the turbo backend"
                ));
            }
            if self.payment_url.trim().is_empty() {
                return Err(anyhow!(
                    "storage.payment_url is required for the turbo backend"
                ));
            }
        }
        // The ArLocal backend needs its local endpoint.
        if backend == StorageBackendKind::ArLocal && self.arlocal_endpoint.trim().is_empty() {
            return Err(anyhow!(
                "storage.arlocal_endpoint is required for the arlocal backend"
            ));
        }

        let staging_dir = self
            .staging_dir
            .unwrap_or_else(gateway_core::storage::default_staging_dir);

        Ok(StorageConfig {
            backend,
            upload_url: self.upload_url,
            payment_url: self.payment_url,
            gateway_url: self.gateway_url,
            arlocal_endpoint: self.arlocal_endpoint,
            staging_dir,
            durable_staging_dir: self.durable_staging_dir,
            free_storage_bytes: self.free_storage_bytes,
            ar_usd_per_byte_femto: self.ar_usd_per_byte_femto,
            winc_refresh_schedule: self.winc_refresh_schedule,
            winc_safety_floor: rust_decimal::Decimal::from(self.winc_safety_floor),
            winc_drift_alert_threshold: rust_decimal::Decimal::from(
                self.winc_drift_alert_threshold,
            ),
            reconcile_horizon,
            upload_timeout,
            upload_claim_lease_ttl,
            attempt_stuck_passes: self.attempt_stuck_passes,
            session_limits: self.sessions.resolve()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a file config from a TOML string, for tests.
    fn parse(toml_str: &str) -> FileConfig {
        toml::from_str(toml_str).expect("parse test config")
    }

    /// A fully populated environment with valid secrets. Tests tweak one field at
    /// a time. Passing this explicitly (rather than mutating process globals)
    /// keeps the tests order-independent and parallel-safe.
    fn full_env() -> Environment {
        Environment {
            database_url: Some("postgres://u:p@localhost/db".to_string()),
            keyring_passphrase: Some(Zeroizing::new("correct horse battery staple".to_string())),
            keyring_path: None,
            worker_id: Some("replica-7".to_string()),
            hostname: Some("host-1".to_string()),
            coingecko_api_key: None,
            blockfrost_project_id: None,
            koios_api_key: None,
        }
    }

    const SAMPLE: &str = r#"
        network = "preprod"
        keyring_path = "/etc/gateway/keyring.age"

        [band]
        min = 4000000
        max = 8000000
        mid = 6000000

        [wallet]
        lease_secs = 120
        min_canonical_count = 4
    "#;

    #[test]
    fn resolves_a_valid_config_with_env_secrets() {
        let cfg = parse(SAMPLE).resolve(full_env()).expect("resolve");
        assert_eq!(cfg.database_url, "postgres://u:p@localhost/db");
        assert_eq!(cfg.worker_id, "replica-7");
        assert_eq!(cfg.wallet.network, Network::Preprod);
        assert_eq!(cfg.wallet.band.min, 4_000_000);
        assert_eq!(
            cfg.keyring_path.to_str().unwrap(),
            "/etc/gateway/keyring.age"
        );
        assert_eq!(
            cfg.keyring_passphrase.as_str(),
            "correct horse battery staple"
        );
        assert!(!cfg.fee_shape_record_sizes.is_empty());
        // No `[http]` section: the data plane is not served.
        assert!(cfg.http.is_none());
    }

    #[test]
    fn resolves_the_http_section_with_its_pricing_inputs() {
        // The `[http]` section carries the data-plane socket, the problem-type
        // base, and the pricing inputs (ADA->USD and the markup) the quote route
        // prices a publish from. The free-storage window now lives in `[storage]`.
        let with_http = format!(
            "{SAMPLE}\n[http]\nbind = \"0.0.0.0:8080\"\nproblem_type_base = \"https://errors.example/v1\"\nada_usd_micros = 480000\nmargin_pct = 0.3\n"
        );
        let cfg = parse(&with_http).resolve(full_env()).expect("resolve");
        let http = cfg.http.expect("the [http] section resolves");
        assert_eq!(http.bind, "0.0.0.0:8080");
        assert_eq!(http.problem_type_base, "https://errors.example/v1");
        assert_eq!(http.ada_usd_micros, 480_000);
        assert_eq!(http.margin_pct, 0.3);
        // No `[storage]` section: the deployment is hash-only.
        assert!(cfg.storage.is_none());
    }

    #[test]
    fn an_http_section_without_pricing_inputs_is_rejected() {
        // ada_usd_micros and margin_pct are required when the HTTP plane is served
        // (the engine bundles no FX oracle), so an [http] section missing them is a
        // parse error rather than a silently unpriced data plane.
        let missing = format!("{SAMPLE}\n[http]\nbind = \"0.0.0.0:8080\"\n");
        let err = toml::from_str::<FileConfig>(&missing)
            .expect_err("an [http] section without pricing inputs must fail to parse");
        assert!(
            err.to_string().contains("ada_usd_micros") || err.to_string().contains("margin_pct"),
            "the error names a missing pricing field, got {err}"
        );
    }

    #[test]
    fn worker_id_falls_back_to_file_then_hostname() {
        // No env worker id, but the file supplies one.
        let with_file_id = SAMPLE.replace(
            "keyring_path = \"/etc/gateway/keyring.age\"",
            "keyring_path = \"/k.age\"\nworker_id = \"from-file\"",
        );
        let mut env = full_env();
        env.worker_id = None;
        let cfg = parse(&with_file_id).resolve(env).expect("resolve");
        assert_eq!(cfg.worker_id, "from-file");

        // Neither env nor file: fall back to the host name.
        let mut env = full_env();
        env.worker_id = None;
        env.hostname = Some("host-9".to_string());
        let cfg = parse(SAMPLE).resolve(env).expect("resolve");
        assert_eq!(cfg.worker_id, "host-9");
    }

    #[test]
    fn keyring_path_env_overrides_the_file() {
        let mut env = full_env();
        env.keyring_path = Some(PathBuf::from("/run/secrets/keyring.age"));
        let cfg = parse(SAMPLE).resolve(env).expect("resolve");
        assert_eq!(
            cfg.keyring_path.to_str().unwrap(),
            "/run/secrets/keyring.age",
            "the environment override wins over the file path"
        );
    }

    #[test]
    fn missing_database_url_is_rejected() {
        let mut env = full_env();
        env.database_url = None;
        let err = parse(SAMPLE)
            .resolve(env)
            .expect_err("missing db url must error");
        assert!(
            err.to_string().contains(DATABASE_URL_ENV),
            "error names the missing variable, got {err}"
        );
    }

    #[test]
    fn missing_keyring_passphrase_is_rejected() {
        let mut env = full_env();
        env.keyring_passphrase = None;
        let err = parse(SAMPLE)
            .resolve(env)
            .expect_err("missing passphrase must error");
        assert!(
            err.to_string().contains(KEYRING_PASSPHRASE_ENV),
            "error names the missing variable, got {err}"
        );
    }

    #[test]
    fn an_invalid_band_is_rejected_at_load() {
        // A band straddling a CBOR width boundary: pure-shape validation rejects
        // it before the runtime ever starts.
        let bad = r#"
            network = "preprod"
            keyring_path = "/k.age"
            [band]
            min = 60000
            max = 70000
            mid = 65000
            [wallet]
            lease_secs = 120
            min_canonical_count = 4
        "#;
        let err = parse(bad)
            .resolve(full_env())
            .expect_err("bad band must error");
        assert!(
            err.to_string().contains("band"),
            "error mentions the band, got {err}"
        );
    }

    #[test]
    fn an_unknown_network_is_rejected() {
        let bad = SAMPLE.replace("preprod", "testnet-magic-2");
        let err = parse(&bad)
            .resolve(full_env())
            .expect_err("unknown network must error");
        assert!(
            err.to_string().contains("network"),
            "error mentions the network, got {err}"
        );
    }

    #[test]
    fn an_empty_fee_shape_record_set_is_rejected() {
        let with_empty = SAMPLE.replace("[band]", "fee_shape_record_sizes = []\n[band]");
        let err = parse(&with_empty)
            .resolve(full_env())
            .expect_err("empty fee-shape set must error");
        assert!(
            err.to_string().contains("fee_shape_record_sizes"),
            "error names the field, got {err}"
        );
    }

    #[test]
    fn the_default_wallet_scope_defaults_to_service_and_accepts_operator() {
        // No [control] section: the default wallet scope is the single-tenant
        // `service`.
        let cfg = parse(SAMPLE).resolve(full_env()).expect("resolve");
        assert_eq!(cfg.control.default_wallet_scope, "service");

        // An explicit `operator` default is accepted.
        let with_operator = format!("{SAMPLE}\n[control]\ndefault_wallet_scope = \"operator\"\n");
        let cfg = parse(&with_operator).resolve(full_env()).expect("resolve");
        assert_eq!(cfg.control.default_wallet_scope, "operator");
    }

    #[test]
    fn an_unknown_default_wallet_scope_is_rejected_at_load() {
        // Only service/operator are expressible as a registration default; an
        // `account` (or any other) default is rejected before the runtime starts.
        let bad = format!("{SAMPLE}\n[control]\ndefault_wallet_scope = \"account\"\n");
        let err = parse(&bad)
            .resolve(full_env())
            .expect_err("an account default wallet scope must be rejected");
        assert!(
            err.to_string().contains("default_wallet_scope"),
            "error names the field, got {err}"
        );
    }

    #[test]
    fn the_default_storage_scope_defaults_to_service_and_accepts_operator() {
        // No [control] section: the default storage scope is the single-tenant
        // `service`, the twin of the wallet default.
        let cfg = parse(SAMPLE).resolve(full_env()).expect("resolve");
        assert_eq!(cfg.control.default_storage_scope, "service");

        // An explicit `operator` default is accepted.
        let with_operator = format!("{SAMPLE}\n[control]\ndefault_storage_scope = \"operator\"\n");
        let cfg = parse(&with_operator).resolve(full_env()).expect("resolve");
        assert_eq!(cfg.control.default_storage_scope, "operator");
    }

    #[test]
    fn an_unknown_default_storage_scope_is_rejected_at_load() {
        // Only service/operator are expressible as a registration default; an
        // `account` (or any other) default is rejected before the runtime starts.
        let bad = format!("{SAMPLE}\n[control]\ndefault_storage_scope = \"account\"\n");
        let err = parse(&bad)
            .resolve(full_env())
            .expect_err("an account default storage scope must be rejected");
        assert!(
            err.to_string().contains("default_storage_scope"),
            "error names the field, got {err}"
        );
    }

    /// A `[storage]` block on the Turbo backend with the required fields and short,
    /// validity-preserving timeouts (a 30s upload, a 60s horizon, a 45s lease).
    fn turbo_storage_block() -> &'static str {
        "[storage]\nbackend = \"turbo\"\nupload_url = \"https://upload.example\"\n\
         payment_url = \"https://payment.example\"\n\
         durable_staging_dir = \"/var/lib/gateway/staging\"\nar_usd_per_byte_femto = 1500\n\
         winc_safety_floor = 5000\nwinc_drift_alert_threshold = 100000\n\
         upload_timeout_secs = 30\nreconcile_horizon_secs = 60\nupload_claim_lease_ttl_secs = 45\n"
    }

    #[test]
    fn resolves_a_turbo_storage_section() {
        let with_storage = format!("{SAMPLE}\n{}", turbo_storage_block());
        let cfg = parse(&with_storage).resolve(full_env()).expect("resolve");
        let storage = cfg.storage.expect("the [storage] section resolves");
        assert_eq!(storage.backend, StorageBackendKind::Turbo);
        assert_eq!(storage.upload_url, "https://upload.example");
        assert_eq!(storage.payment_url, "https://payment.example");
        assert_eq!(
            storage.durable_staging_dir.to_str().unwrap(),
            "/var/lib/gateway/staging"
        );
        assert_eq!(storage.ar_usd_per_byte_femto, 1500);
        assert_eq!(storage.winc_safety_floor, rust_decimal::Decimal::from(5000));
        assert_eq!(
            storage.winc_drift_alert_threshold,
            rust_decimal::Decimal::from(100_000)
        );
        assert_eq!(storage.upload_timeout, Duration::from_secs(30));
        assert_eq!(storage.reconcile_horizon, Duration::from_secs(60));
        assert_eq!(storage.upload_claim_lease_ttl, Duration::from_secs(45));
        // The free window defaults to 100 KiB when the section omits it.
        assert_eq!(storage.free_storage_bytes, 102_400);
    }

    #[test]
    fn a_turbo_backend_without_its_service_urls_is_rejected() {
        // The Turbo backend POSTs to the upload service and reads winc from the
        // payment service; a missing URL is a boot failure, not a half-wired backend.
        let no_upload = format!(
            "{SAMPLE}\n[storage]\nbackend = \"turbo\"\npayment_url = \"https://p.example\"\n\
             durable_staging_dir = \"/d\"\nar_usd_per_byte_femto = 1\n"
        );
        let err = parse(&no_upload)
            .resolve(full_env())
            .expect_err("turbo without an upload url must error");
        assert!(
            err.to_string().contains("upload_url"),
            "error names the upload url, got {err}"
        );

        let no_payment = format!(
            "{SAMPLE}\n[storage]\nbackend = \"turbo\"\nupload_url = \"https://u.example\"\n\
             durable_staging_dir = \"/d\"\nar_usd_per_byte_femto = 1\n"
        );
        let err = parse(&no_payment)
            .resolve(full_env())
            .expect_err("turbo without a payment url must error");
        assert!(
            err.to_string().contains("payment_url"),
            "error names the payment url, got {err}"
        );
    }

    #[test]
    fn an_arlocal_backend_without_its_endpoint_is_rejected() {
        let bad = format!(
            "{SAMPLE}\n[storage]\nbackend = \"arlocal\"\ndurable_staging_dir = \"/d\"\n\
             ar_usd_per_byte_femto = 1\n"
        );
        let err = parse(&bad)
            .resolve(full_env())
            .expect_err("arlocal without an endpoint must error");
        assert!(
            err.to_string().contains("arlocal_endpoint"),
            "error names the arlocal endpoint, got {err}"
        );
    }

    #[test]
    fn the_direct_arweave_underscore_alias_normalizes_to_the_hyphen_backend() {
        // A `direct_arweave` in the file resolves to the same backend whose rows
        // carry the canonical hyphenated `direct-arweave`, so the persisted backend
        // name can never split from the config value.
        let with_storage = format!(
            "{SAMPLE}\n[storage]\nbackend = \"direct_arweave\"\n\
             durable_staging_dir = \"/d\"\nar_usd_per_byte_femto = 1\n"
        );
        let cfg = parse(&with_storage).resolve(full_env()).expect("resolve");
        assert_eq!(
            cfg.storage.expect("resolves").backend,
            StorageBackendKind::DirectArweave
        );
    }

    #[test]
    fn an_unknown_storage_backend_is_rejected_at_load() {
        let bad = format!(
            "{SAMPLE}\n[storage]\nbackend = \"s3\"\ndurable_staging_dir = \"/d\"\n\
             ar_usd_per_byte_femto = 1\n"
        );
        let err = parse(&bad)
            .resolve(full_env())
            .expect_err("an unknown backend must error");
        assert!(
            err.to_string().contains("unknown storage backend"),
            "error names the unknown backend, got {err}"
        );
    }

    #[test]
    fn a_storage_section_without_a_durable_staging_dir_is_rejected() {
        // A `reserved` attempt's content must survive a crash, so the durable
        // directory is required: an omission is a parse error, not a silent tmpfs
        // fallback that would lose in-flight bytes on a restart.
        let missing =
            format!("{SAMPLE}\n[storage]\nbackend = \"turbo\"\nar_usd_per_byte_femto = 1\n");
        let err = toml::from_str::<FileConfig>(&missing)
            .expect_err("a [storage] section without a durable staging dir must fail to parse");
        assert!(
            err.to_string().contains("durable_staging_dir"),
            "the error names the missing field, got {err}"
        );
    }

    #[test]
    fn a_storage_section_without_a_per_byte_rate_is_rejected() {
        // The per-byte storage rate is required: a missing value would silently
        // price storage at zero, the exact billing gap this field closes.
        let missing =
            format!("{SAMPLE}\n[storage]\nbackend = \"turbo\"\ndurable_staging_dir = \"/d\"\n");
        let err = toml::from_str::<FileConfig>(&missing)
            .expect_err("a [storage] section without a per-byte rate must fail to parse");
        assert!(
            err.to_string().contains("ar_usd_per_byte_femto"),
            "the error names the missing field, got {err}"
        );
    }

    #[test]
    fn a_horizon_at_or_below_the_upload_timeout_is_rejected() {
        // The recovery horizon must exceed the upload timeout, or a slow-but-live
        // upload could be swept out from under its own handler. The invariant is
        // backend-agnostic, so the URL-free direct-arweave backend exercises it.
        let bad = format!(
            "{SAMPLE}\n[storage]\nbackend = \"direct-arweave\"\ndurable_staging_dir = \"/d\"\n\
             ar_usd_per_byte_femto = 1\nupload_timeout_secs = 300\nreconcile_horizon_secs = 300\n"
        );
        let err = parse(&bad)
            .resolve(full_env())
            .expect_err("a horizon not exceeding the timeout must error");
        assert!(
            err.to_string().contains("reconcile_horizon_secs"),
            "error names the horizon field, got {err}"
        );
    }

    #[test]
    fn a_lease_ttl_at_or_below_the_upload_timeout_is_rejected() {
        // The claim-lease must outlive the upload timeout so the POST abort fires
        // strictly before the lease can lapse; an explicit shorter lease is rejected.
        let bad = format!(
            "{SAMPLE}\n[storage]\nbackend = \"direct-arweave\"\ndurable_staging_dir = \"/d\"\n\
             ar_usd_per_byte_femto = 1\nupload_timeout_secs = 300\nreconcile_horizon_secs = 900\n\
             upload_claim_lease_ttl_secs = 300\n"
        );
        let err = parse(&bad)
            .resolve(full_env())
            .expect_err("a lease not exceeding the timeout must error");
        assert!(
            err.to_string().contains("upload_claim_lease_ttl_secs"),
            "error names the lease field, got {err}"
        );
    }

    #[test]
    fn the_lease_ttl_defaults_to_the_upload_timeout_plus_a_margin() {
        // Omitting the lease TTL derives it from the upload timeout plus a margin,
        // so the ordering invariant holds without operator hand-tuning. The derived
        // lease is backend-agnostic, so the URL-free direct-arweave backend
        // exercises it.
        let with_storage = format!(
            "{SAMPLE}\n[storage]\nbackend = \"direct-arweave\"\ndurable_staging_dir = \"/d\"\n\
             ar_usd_per_byte_femto = 1\nupload_timeout_secs = 120\nreconcile_horizon_secs = 900\n"
        );
        let cfg = parse(&with_storage).resolve(full_env()).expect("resolve");
        let storage = cfg.storage.expect("resolves");
        assert!(
            storage.upload_claim_lease_ttl > storage.upload_timeout,
            "the derived lease always exceeds the upload timeout"
        );
        assert_eq!(storage.upload_claim_lease_ttl, Duration::from_secs(180));
    }

    #[test]
    fn no_fx_section_leaves_the_binary_on_the_static_rate() {
        // Absent `[fx]` is the offline/test path: no live oracle loop, the static
        // `[http]` rate prices quotes.
        let cfg = parse(SAMPLE).resolve(full_env()).expect("resolve");
        assert!(cfg.fx.is_none());
    }

    #[test]
    fn resolves_a_keyless_fx_section_on_the_coinpaprika_default() {
        // A bare `[fx]` section needs no key: it prices from the keyless CoinPaprika
        // default and takes the default refresh cron.
        let with_fx = format!("{SAMPLE}\n[fx]\n");
        let cfg = parse(&with_fx).resolve(full_env()).expect("resolve");
        let fx = cfg.fx.expect("the [fx] section resolves");
        assert!(
            fx.coingecko.is_none(),
            "no CoinGecko key configured means the keyless CoinPaprika default"
        );
        assert_eq!(
            fx.refresh_schedule,
            gateway_core::pricing::DEFAULT_FX_REFRESH_SCHEDULE
        );
        // The freshness ceiling defaults to one hour when the section omits it.
        assert_eq!(fx.max_fx_snapshot_age_seconds, 3600);
    }

    #[test]
    fn an_explicit_fx_snapshot_age_ceiling_is_carried_through() {
        let with_fx = format!("{SAMPLE}\n[fx]\nmax_fx_snapshot_age_seconds = 900\n");
        let cfg = parse(&with_fx).resolve(full_env()).expect("resolve");
        assert_eq!(cfg.fx.expect("resolves").max_fx_snapshot_age_seconds, 900);
    }

    #[test]
    fn a_non_positive_fx_snapshot_age_ceiling_is_rejected_at_load() {
        // A zero or negative ceiling would refuse every quote (no snapshot can be
        // that fresh), so it is a boot error rather than a deployment that never
        // prices a publish.
        for bad in ["0", "-1"] {
            let with_fx = format!("{SAMPLE}\n[fx]\nmax_fx_snapshot_age_seconds = {bad}\n");
            let err = parse(&with_fx)
                .resolve(full_env())
                .expect_err("a non-positive ceiling must error");
            assert!(
                err.to_string().contains("max_fx_snapshot_age_seconds"),
                "the error names the ceiling field, got {err}"
            );
        }
    }

    #[test]
    fn a_coingecko_tier_with_a_key_resolves_to_a_coingecko_credential() {
        // CoinGecko is opt-in: a `demo` tier plus the key secret builds the
        // CoinGecko credential (it becomes the primary, with CoinPaprika the fallback).
        let with_fx = format!("{SAMPLE}\n[fx]\ncoingecko_tier = \"demo\"\n");
        let mut env = full_env();
        env.coingecko_api_key = Some("cg-demo-key".to_string().into());
        let cfg = parse(&with_fx).resolve(env).expect("resolve");
        let coingecko = cfg
            .fx
            .expect("resolves")
            .coingecko
            .expect("the CoinGecko credential is configured");
        assert_eq!(coingecko.tier, gateway_core::pricing::CoinGeckoTier::Demo);
        assert_eq!(coingecko.api_key.as_str(), "cg-demo-key");
    }

    #[test]
    fn a_coingecko_tier_without_a_key_is_rejected() {
        // A `demo`/`pro` tier without the API-key secret is a boot error, not a loop
        // that silently drops to CoinPaprika and ignores the operator's tier.
        let with_fx = format!("{SAMPLE}\n[fx]\ncoingecko_tier = \"demo\"\n");
        let err = parse(&with_fx)
            .resolve(full_env())
            .expect_err("a tier without a key must error");
        assert!(
            err.to_string().contains(COINGECKO_API_KEY_ENV),
            "the error names the missing key secret, got {err}"
        );
    }

    #[test]
    fn a_coingecko_key_without_a_tier_is_rejected() {
        // A key with no tier is ambiguous (demo vs pro use different hosts), so it is
        // a boot error rather than a guessed endpoint.
        let with_fx = format!("{SAMPLE}\n[fx]\n");
        let mut env = full_env();
        env.coingecko_api_key = Some("cg-key-no-tier".to_string().into());
        let err = parse(&with_fx)
            .resolve(env)
            .expect_err("a key without a tier must error");
        assert!(
            err.to_string().contains(COINGECKO_API_KEY_ENV),
            "the error names the key secret, got {err}"
        );
    }

    #[test]
    fn an_unrecognised_coingecko_tier_is_rejected() {
        // The keyless CoinGecko `public` tier no longer exists (CoinPaprika is the
        // keyless default), so it — and any other unknown token — is a boot error.
        let with_fx = format!("{SAMPLE}\n[fx]\ncoingecko_tier = \"public\"\n");
        let mut env = full_env();
        env.coingecko_api_key = Some("cg-key".to_string().into());
        let err = parse(&with_fx)
            .resolve(env)
            .expect_err("an unknown tier must error");
        assert!(
            err.to_string().contains("coingecko_tier"),
            "the error names the tier field, got {err}"
        );
    }

    #[test]
    fn no_fx_section_with_a_key_present_is_not_rejected() {
        // The reverse-footgun guard lives inside the `[fx]` resolver, so a
        // deployment with no live-FX section but a stray key in the environment is
        // unaffected: the key simply goes unused, exactly as before.
        let mut env = full_env();
        env.coingecko_api_key = Some("cg-key-no-fx".to_string().into());
        let cfg = parse(SAMPLE).resolve(env).expect("resolve");
        assert!(cfg.fx.is_none());
    }

    #[test]
    fn an_unknown_fx_tier_is_rejected_at_load() {
        let with_fx = format!("{SAMPLE}\n[fx]\ncoingecko_tier = \"enterprise\"\n");
        let err = parse(&with_fx)
            .resolve(full_env())
            .expect_err("an unknown tier must error");
        assert!(
            err.to_string().contains("coingecko_tier"),
            "the error names the tier field, got {err}"
        );
    }

    /// A unique scratch file path under the system temp dir for the `_FILE`
    /// secret-source tests, so parallel test runs never collide on a path.
    fn scratch_secret_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "gateway-secret-{tag}-{}",
            uuid::Uuid::now_v7().simple()
        ))
    }

    #[test]
    fn a_secret_supplied_through_both_sources_is_rejected() {
        let err = merge_secret_sources(
            KEYRING_PASSPHRASE_ENV,
            KEYRING_PASSPHRASE_FILE_ENV,
            Some("direct".to_string()),
            Some(PathBuf::from("/run/secrets/keyring-passphrase")),
        )
        .expect_err("both sources set must error");
        let msg = err.to_string();
        assert!(
            msg.contains(KEYRING_PASSPHRASE_ENV) && msg.contains(KEYRING_PASSPHRASE_FILE_ENV),
            "the error names both variables so the operator knows which pair collided, got {msg}"
        );
    }

    #[test]
    fn a_file_source_reads_the_secret_and_trims_only_trailing_whitespace() {
        let path = scratch_secret_path("file-source");
        // A docker secret carries a trailing newline; leading whitespace may be
        // meaningful in a passphrase, so only the end is trimmed.
        std::fs::write(&path, "  hunter2  \n").expect("write secret file");
        let value = merge_secret_sources(
            KEYRING_PASSPHRASE_ENV,
            KEYRING_PASSPHRASE_FILE_ENV,
            None,
            Some(path.clone()),
        )
        .expect("a file-only source resolves")
        .expect("the file holds a value");
        assert_eq!(value.as_str(), "  hunter2");
        std::fs::remove_file(&path).expect("remove secret file");
    }

    #[test]
    fn a_missing_secret_file_is_rejected() {
        // The `_FILE` variable explicitly pointed at the path, so a missing or
        // unreadable file is an error, never a silent absence.
        let path = scratch_secret_path("missing-file");
        let err = merge_secret_sources(
            KEYRING_PASSPHRASE_ENV,
            KEYRING_PASSPHRASE_FILE_ENV,
            None,
            Some(path.clone()),
        )
        .expect_err("a missing secret file must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(KEYRING_PASSPHRASE_FILE_ENV) && msg.contains(path.to_str().unwrap()),
            "the error names the file variable and the path, got {msg}"
        );
    }

    #[test]
    fn a_direct_secret_passes_through_verbatim() {
        let value = merge_secret_sources(
            COINGECKO_API_KEY_ENV,
            COINGECKO_API_KEY_FILE_ENV,
            Some(" raw value \n".to_string()),
            None,
        )
        .expect("a direct-only source resolves")
        .expect("the variable holds a value");
        assert_eq!(
            value.as_str(),
            " raw value \n",
            "a plain-variable secret is returned untouched"
        );
    }

    #[test]
    fn no_secret_source_resolves_to_none() {
        let value = merge_secret_sources(
            BLOCKFROST_PROJECT_ID_ENV,
            BLOCKFROST_PROJECT_ID_FILE_ENV,
            None,
            None,
        )
        .expect("neither source set resolves cleanly");
        assert!(value.is_none(), "an unsupplied secret is simply absent");
    }

    #[test]
    fn the_koios_api_key_supplied_through_both_sources_is_rejected() {
        let err = merge_secret_sources(
            KOIOS_API_KEY_ENV,
            KOIOS_API_KEY_FILE_ENV,
            Some("direct".to_string()),
            Some(PathBuf::from("/run/secrets/gateway-koios-api-key")),
        )
        .expect_err("both koios key sources set must error");
        let msg = err.to_string();
        assert!(
            msg.contains(KOIOS_API_KEY_ENV) && msg.contains(KOIOS_API_KEY_FILE_ENV),
            "the error names both variables so the operator knows which pair collided, got {msg}"
        );
    }

    #[test]
    fn the_koios_api_key_file_source_is_read_and_trimmed() {
        let path = scratch_secret_path("koios-key");
        std::fs::write(&path, "ey.signed.jwt\n").expect("write secret file");
        let value = merge_secret_sources(
            KOIOS_API_KEY_ENV,
            KOIOS_API_KEY_FILE_ENV,
            None,
            Some(path.clone()),
        )
        .expect("a file-only source resolves")
        .expect("the file holds a value");
        assert_eq!(value.as_str(), "ey.signed.jwt");
        std::fs::remove_file(&path).expect("remove secret file");
    }

    #[test]
    fn the_koios_api_key_lands_in_the_resolved_config_with_no_chain_section() {
        // The key authenticates against the public koios.rest registered tiers,
        // so it needs no [chain] section at all (the per-network default URL
        // stays selected).
        let mut env = full_env();
        env.koios_api_key = Some("registered-tier-token".to_string().into());
        let cfg = parse(SAMPLE).resolve(env).expect("resolve");
        assert_eq!(
            cfg.koios.api_key.as_ref().map(|k| k.as_str()),
            Some("registered-tier-token")
        );
        assert!(
            cfg.koios.base_url.is_none(),
            "no [chain] koios_url leaves the per-network default selected"
        );
    }

    #[test]
    fn a_koios_api_key_with_whitespace_or_non_ascii_is_rejected_at_load() {
        // The key is sent verbatim inside an Authorization header; a malformed
        // one must stop the boot, not fail header construction on every call.
        for bad in ["two words", "tab\tseparated", "ключ", "line\nbreak"] {
            let mut env = full_env();
            env.koios_api_key = Some(bad.to_string().into());
            let err = parse(SAMPLE)
                .resolve(env)
                .expect_err("a malformed koios key must be rejected");
            assert!(
                err.to_string().contains(KOIOS_API_KEY_ENV),
                "the error names the key variable, got {err}"
            );
        }
    }

    #[test]
    fn a_koios_url_override_resolves_and_normalises_to_no_trailing_slash() {
        // The canonical form is no trailing slash (paths are appended verbatim
        // as `{koios_url}/tip`), so a trailing slash in the file is normalised
        // rather than producing `//tip` on every request.
        for (raw, want) in [
            (
                "https://koios.example/api/v1",
                "https://koios.example/api/v1",
            ),
            (
                "https://koios.example/api/v1/",
                "https://koios.example/api/v1",
            ),
            ("http://10.0.0.7:8053/api/v1", "http://10.0.0.7:8053/api/v1"),
        ] {
            let with_chain = format!("{SAMPLE}\n[chain]\nkoios_url = \"{raw}\"\n");
            let cfg = parse(&with_chain).resolve(full_env()).expect("resolve");
            assert_eq!(cfg.koios.base_url.as_deref(), Some(want), "for {raw:?}");
        }
    }

    #[test]
    fn an_invalid_koios_url_is_rejected_at_load() {
        // Not a URL, a non-http scheme, and a query string or fragment are all
        // load errors: a malformed provider URL must stop the boot rather than
        // surface as a transport error on the first chain call.
        for bad in [
            "koios.example/api/v1",
            "ftp://koios.example/api/v1",
            "https://koios.example/api/v1?key=x",
            "https://koios.example/api/v1#frag",
            "",
        ] {
            let with_chain = format!("{SAMPLE}\n[chain]\nkoios_url = \"{bad}\"\n");
            let err = parse(&with_chain)
                .resolve(full_env())
                .expect_err("an invalid koios_url must be rejected");
            assert!(
                err.to_string().contains("koios_url"),
                "the error names the field for {bad:?}, got {err}"
            );
        }
    }

    #[test]
    fn no_chain_section_leaves_koios_on_the_per_network_keyless_default() {
        let cfg = parse(SAMPLE).resolve(full_env()).expect("resolve");
        assert_eq!(
            cfg.koios,
            gateway_core::chain::params::KoiosConfig::default(),
            "absent [chain] and key means the keyless per-network public tier"
        );
    }
}
