//! Live FX pricing: the oracle refresh loop, its cache, and the DB-backed pricing
//! seam.
//!
//! The engine prices the network fee deterministically from the cached protocol
//! parameters, but the two market prices a quote also needs (ADA->USD for the fee
//! conversion, per-byte Arweave for the storage forecast) move continuously and
//! have no on-chain source. This module owns the whole FX lane:
//!
//! - [`fx_refresh`](mod@fx_refresh) — the only writer of `cw_core.fx_rate`. A scheduled loop reads
//!   the coin-price provider chain (keyless CoinPaprika by default, with CoinGecko
//!   as the primary when a key is configured) and Turbo / the Arweave gateway
//!   (per-byte storage) and inserts one snapshot per tick. Live-data-only: no
//!   hardcoded fallback ratio, a skip-and-serve-the-last-row on a per-byte-oracle
//!   miss, and a restart-survivable cooldown on an exhausted CoinGecko quota.
//! - [`pg_pricing`] — the [`crate::api::state::PricingSource`] implementation every
//!   quote resolves through. It reuses the exact canonical fee math and reads the
//!   two FX prices from the newest snapshot, reporting the snapshot's true age.
//! - [`cooldown`] / [`oracle`] / [`units`] — the supporting cooldown gate, the
//!   oracle HTTP clients (all on the engine's single hardened egress), and the
//!   exact integer money conversions.
//!
//! The refresh loop is the only oracle caller; quote/upload requests read the
//! cached newest row and make zero oracle calls, the same discipline the protocol
//! parameter cache and the winc-credit cache hold.

pub mod cooldown;
pub mod fx_refresh;
pub mod margin_override;
pub mod oracle;
pub mod pg_pricing;
pub mod units;

pub use fx_refresh::{
    ensure_fx_seeded, fx_refresh, fx_refresh_policy, fx_refresh_schedule, FxRefreshConfig,
    FxRefreshHandler, FxRefreshOutcome, SkipReason, DEFAULT_FX_REFRESH_SCHEDULE, FX_REFRESH_QUEUE,
};
pub use oracle::{
    CoinGeckoConfig, CoinGeckoTier, CoinPriceProvider, CoinPrices, PriceProviderError,
};
pub use pg_pricing::PgFxPricing;
