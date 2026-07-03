//! Shared state for the control-plane handlers.
//!
//! [`ControlState`] is the dependency bundle every control route is given: the
//! connection pool and the operator-configured control knobs. It is distinct from
//! the data plane's [`crate::api::state::AppState`] because the control surface is
//! a separate router with its own configuration (token TTLs, the secret prefix
//! minted credentials carry, the adjustment cap, the static-UI toggle).

use chrono::Duration;
use rust_decimal::Decimal;
use std::sync::Arc;

use crate::api::control::credential::{DEFAULT_ACCOUNT_TOKEN_TTL, DEFAULT_OPERATOR_TOKEN_TTL};
use crate::api::state::WebhookState;
use crate::chain::params::KoiosConfig;

/// Operator-configured knobs the control plane needs.
///
/// Everything a deployment chooses for its control surface: the RFC 7807
/// problem-type base (shared style with the data plane), the human-readable
/// prefix minted credentials and keys carry (no hardcoded brand string), the
/// token lifetimes, the adjustment cap, and whether the bundled static admin UI
/// is served.
#[derive(Debug, Clone)]
pub struct ControlConfig {
    /// The base URL the RFC 7807 `type` member is built from (`<base>#<code>`).
    /// Operator-configured; no vendor default.
    pub problem_type_base: String,
    /// The human-readable prefix minted secrets carry (a deployment's chosen
    /// label, e.g. an operator-token or api-key prefix). The engine ships no
    /// default brand string, so the operator supplies it.
    pub secret_prefix: String,
    /// The lifetime of a minted operator token.
    pub operator_token_ttl: Duration,
    /// The lifetime of a minted account-scoped token.
    pub account_token_ttl: Duration,
    /// The maximum absolute magnitude (micro-USD) of a single manual ledger
    /// adjustment, a guard against a fat-finger grant.
    pub adjustment_cap_usd_micros: i64,
    /// Whether the bundled static admin UI is served at `/admin`.
    pub admin_ui_enabled: bool,
    /// The spend scope a newly registered wallet is granted by default when the
    /// register call does not name one. The single-tenant default is
    /// [`DefaultWalletScope::Service`] (every operator/account on the instance may
    /// spend the wallet); a multi-tenant host sets it to
    /// [`DefaultWalletScope::Operator`] so a fresh wallet is registrar-only until
    /// the registrar issues grants.
    pub default_wallet_scope: DefaultWalletScope,
    /// The draw scope a newly registered funding source is granted by default when
    /// the register call does not name one. The storage twin of
    /// [`Self::default_wallet_scope`]: [`DefaultStorageScope::Service`] makes a
    /// fresh source drawable by every account on the instance (the single-tenant
    /// default), [`DefaultStorageScope::Operator`] pins it to the registering
    /// operator until it issues further grants.
    pub default_storage_scope: DefaultStorageScope,
    /// The operator-default markup fraction applied over the cost of goods when an
    /// account carries no per-account override. The same `[http].margin_pct` the
    /// live pricing seam resolves against, surfaced so the FX-snapshot console can
    /// show the default margin alongside the raw conversion rates.
    pub operator_default_margin_pct: Decimal,
    /// The maximum age, in seconds, of the newest FX snapshot that may still price a
    /// quote. The same freshness ceiling the live pricing seam refuses past, surfaced
    /// so the FX-snapshot console can flag a snapshot as stale on the same threshold
    /// the quote path enforces.
    pub fx_freshness_ceiling_seconds: i64,
}

/// The default spend scope a register call confers on a new wallet.
///
/// Only `service` and `operator` are expressible as a registration default: a
/// `service` grant entitles everyone, an `operator` grant pins the wallet to its
/// own registrar. An `account` default is meaningless at registration (there is
/// no account named yet), so it is not a variant; account grants are issued
/// explicitly through the grant route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultWalletScope {
    /// Every operator/account on the instance may spend the wallet (the
    /// single-tenant default).
    Service,
    /// Only the registrar may spend the wallet until it issues further grants.
    Operator,
}

impl DefaultWalletScope {
    /// Parse the configured token.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "service" => Some(DefaultWalletScope::Service),
            "operator" => Some(DefaultWalletScope::Operator),
            _ => None,
        }
    }

    /// The stable wire token for this default scope.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DefaultWalletScope::Service => "service",
            DefaultWalletScope::Operator => "operator",
        }
    }
}

/// The default draw scope a register call confers on a new funding source.
///
/// The storage twin of [`DefaultWalletScope`]. Only `service` and `operator` are
/// expressible as a registration default: a `service` grant entitles every account,
/// an `operator` grant pins the source to its own owner. An `account` default is
/// meaningless at registration (there is no account named yet), so it is not a
/// variant; account grants are issued explicitly through the grant route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultStorageScope {
    /// Every account on the instance may draw the source (the single-tenant
    /// default).
    Service,
    /// Only the registering operator may draw the source until it issues further
    /// grants.
    Operator,
}

impl DefaultStorageScope {
    /// Parse the configured token.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "service" => Some(DefaultStorageScope::Service),
            "operator" => Some(DefaultStorageScope::Operator),
            _ => None,
        }
    }

    /// The stable wire token for this default scope.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DefaultStorageScope::Service => "service",
            DefaultStorageScope::Operator => "operator",
        }
    }
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            problem_type_base: String::new(),
            secret_prefix: String::new(),
            operator_token_ttl: DEFAULT_OPERATOR_TOKEN_TTL,
            account_token_ttl: DEFAULT_ACCOUNT_TOKEN_TTL,
            // A $10,000 default cap (10_000 * 1_000_000 micro-USD).
            adjustment_cap_usd_micros: 10_000_000_000,
            admin_ui_enabled: true,
            // Single-tenant default: a fresh wallet is usable by the whole service.
            default_wallet_scope: DefaultWalletScope::Service,
            // Single-tenant default: a fresh funding source is drawable service-wide.
            default_storage_scope: DefaultStorageScope::Service,
            // No markup by default; the binary supplies the real fraction from
            // `[http].margin_pct`.
            operator_default_margin_pct: Decimal::ZERO,
            // One hour, matching the live pricing seam's default freshness ceiling.
            fx_freshness_ceiling_seconds: 3_600,
        }
    }
}

/// A verified Cardano wallet key the instance physically holds, as the control
/// plane sees it.
///
/// The control plane never touches key material: this is the non-secret metadata
/// the unlocked keyring exposes for its Cardano entries (the verified address and
/// the operator label). The wallet register route consults this set to confirm the
/// instance actually holds a signer for a claimed address before it writes a row
/// the submit path could never sign. An unsignable wallet is an operational
/// hazard: it would be auto-granted, externally-funded UTxOs would be ingested for
/// it, the scheduler could pick it, and every submit would then fail at signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlWalletKey {
    /// The verified Cardano payment address the keyring holds a signer for.
    pub address: String,
    /// The operator-facing label of the keyring entry.
    pub label: String,
}

/// A verified Arweave funding key the instance physically holds, as the control
/// plane sees it.
///
/// The control plane never touches key material: this is the non-secret metadata
/// the unlocked keyring exposes for its Arweave entries (the verified address and
/// the operator label). The funding-source register route consults this set to
/// confirm the instance actually holds a signer for a claimed address before it
/// writes a row a signer could never back. The `address` doubles as the `key_ref`
/// the source row stores, since the keyring resolves an Arweave signer by address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFundingKey {
    /// The verified Arweave address the keyring holds a signer for.
    pub address: String,
    /// The operator-facing label of the keyring entry.
    pub label: String,
}

/// The storage funding-console seam: what the control plane's operator-balance
/// and top-up routes need to reach the deployment's storage providers.
///
/// Built from the resolved `[storage]` config plus the unlocked keyring. The
/// keyring here does NOT weaken the "control plane never touches key material"
/// posture: a signer is reachable only through the same unforgeable
/// [`crate::storage::AuthorizedFunding`] capability the upload path uses
/// ([`crate::wallet::keyring::UnlockedKeyring::arweave_signer_for`]), minted
/// after the owner-entitlement check, and no raw key ever leaves the keyring.
#[derive(Clone)]
pub struct ControlStorage {
    /// The backend's persisted identifier (`turbo`, `arlocal`, `direct-arweave`),
    /// the same string the funding-source rows carry.
    pub backend: String,
    /// The Arweave node/gateway base URL live AR balances are read from and a
    /// top-up transfer is broadcast to: the ArLocal endpoint under the dev
    /// emulator, the configured Arweave gateway otherwise.
    pub node_url: String,
    /// The Turbo payment-service base URL (live winc reads, deposit-address
    /// discovery, fund-transaction registration). `None` for a backend with no
    /// payment service (ArLocal / direct Arweave), in which case the routes
    /// report the Turbo features unavailable with a machine-readable reason
    /// instead of inventing a balance.
    pub payment_url: Option<String>,
    /// The unlocked operator keyring the top-up resolves its transfer signer
    /// from, through the funding capability.
    pub keyring: Arc<crate::wallet::keyring::UnlockedKeyring>,
}

/// The chain seam the control plane's wallet-balance route reads live on-chain
/// ADA balances through.
///
/// Carries the deployment's [`KoiosConfig`] (the operator base-URL override and
/// optional API key) so the balance route can address Koios exactly as the
/// engine's other chain clients do — the public per-network tier by default, a
/// self-hosted instance or a paid key when the operator configures one. The
/// route picks the per-network base URL from each wallet's own network, so a
/// single seam serves every wallet the operator holds.
#[derive(Clone, Debug)]
pub struct ControlChain {
    /// How the balance route addresses Koios (base-URL override + optional API
    /// key), shared with every other Koios client the engine builds.
    pub koios: KoiosConfig,
}

/// The shared state every control-plane handler is given.
#[derive(Clone)]
pub struct ControlState {
    /// The engine's connection pool.
    pub pool: sqlx::PgPool,
    /// The operator-configured control knobs.
    pub config: Arc<ControlConfig>,
    /// The verified Cardano wallet keys this instance holds, for the wallet register
    /// route to confirm physical possession before writing a row. Empty when the
    /// keyring holds no Cardano entry (a hash-only or storage-only deployment), in
    /// which case a wallet register has no signer to back and is refused.
    pub wallet_keys: Arc<Vec<ControlWalletKey>>,
    /// The verified Arweave funding keys this instance holds, for the funding-source
    /// register route to confirm physical possession before writing a row. Empty
    /// when the keyring holds no Arweave entry (a hash-only or wallet-only
    /// deployment), in which case a source register has no key to back and is
    /// refused.
    pub funding_keys: Arc<Vec<ControlFundingKey>>,
    /// The webhook seam (the secret-wrap data key plus the registration URL-safety
    /// knobs) the operator firehose routes seal a minted secret under. Shared with
    /// the data plane's [`crate::api::state::AppState::webhook`] so both arms seal
    /// under the same instance data key. `None` when webhooks are not enabled; the
    /// operator firehose routes then report the feature unavailable rather than
    /// minting a secret they cannot seal.
    pub webhook: Option<WebhookState>,
    /// The storage funding-console seam (live balances + top-up). `None` for a
    /// hash-only deployment with no `[storage]`; the funding-console routes then
    /// report storage not configured.
    pub storage: Option<ControlStorage>,
    /// The chain seam the wallet-balance route reads live on-chain ADA balances
    /// through. `None` when no chain access is wired (the test constructors); the
    /// wallet-balance route then reports chain not configured rather than
    /// inventing a balance.
    pub chain: Option<ControlChain>,
}

impl ControlState {
    /// Construct control state over a pool and operator config, with no held keys (a
    /// deployment that registers neither a wallet nor a storage source through the
    /// control plane).
    #[must_use]
    pub fn new(pool: sqlx::PgPool, config: ControlConfig) -> Self {
        Self::with_keys(pool, config, Vec::new(), Vec::new())
    }

    /// Construct control state with the verified keys the instance physically holds,
    /// so the register routes can confirm possession before writing a row: the
    /// Cardano wallet keys back a wallet registration, the Arweave funding keys back
    /// a funding-source registration.
    #[must_use]
    pub fn with_keys(
        pool: sqlx::PgPool,
        config: ControlConfig,
        wallet_keys: Vec<ControlWalletKey>,
        funding_keys: Vec<ControlFundingKey>,
    ) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            wallet_keys: Arc::new(wallet_keys),
            funding_keys: Arc::new(funding_keys),
            webhook: None,
            storage: None,
            chain: None,
        }
    }

    /// Attach the webhook seam the operator firehose routes seal a minted secret
    /// under. The same [`WebhookState`] the data plane carries, so an account-scoped
    /// subscription and an operator firehose seal under one instance data key.
    #[must_use]
    pub fn with_webhook(mut self, webhook: WebhookState) -> Self {
        self.webhook = Some(webhook);
        self
    }

    /// Attach the storage funding-console seam (live AR/winc balance reads and the
    /// AR -> credit top-up), built from the resolved `[storage]` config.
    #[must_use]
    pub fn with_storage(mut self, storage: ControlStorage) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Attach the chain seam the wallet-balance route reads live on-chain ADA
    /// balances through, built from the deployment's resolved Koios config.
    #[must_use]
    pub fn with_chain(mut self, chain: ControlChain) -> Self {
        self.chain = Some(chain);
        self
    }
}
