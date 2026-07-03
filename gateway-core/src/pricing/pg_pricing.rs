//! The DB-backed pricing seam: live FX from the cached `cw_core.fx_rate` row.
//!
//! This is the engine's own [`PricingSource`] implementation. It prices the
//! network fee exactly the way the reference static seam does, from the cached
//! protocol parameters through the canonical-shape fee helper, but it reads the
//! two FX prices from the NEWEST `cw_core.fx_rate` row (the FX refresh loop is the
//! only writer) instead of static config, and reports the row's true age as
//! `fx_age_seconds`. A deployment that wires the FX refresh cron gets live pricing
//! out of the box, with no second pricing path to maintain.
//!
//! Reads serve the newest row as long as it is within the configured freshness
//! ceiling: a single missed refresh tick is expected, so a slightly stale
//! conversion still prices a quote (the skip-and-serve discipline the FX loop
//! relies on). But the staleness is bounded — once the newest row is OLDER than
//! the ceiling (an extended oracle outage: the upstream feeds down for hours, or
//! the refresh task dead), the read path refuses to quote with the SAME
//! pricing-unavailable error the no-row case returns, so a publish can never be
//! charged at an arbitrarily stale rate. The complete ABSENCE of any row is a hard
//! error for the same reason — there is no safe rate to invent; the cold-start seed
//! guarantees a row exists before the data plane serves.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::api::state::{PricingInputs, PricingSource};
use crate::chain::params::{load_params, Network};
use crate::ledger::quote::FxSnapshot;
use crate::wallet::config::WalletConfig;
use crate::wallet::quote::quote_fee;
use crate::{Error, Result};

/// The DB-backed pricing seam.
///
/// Holds everything fixed for the process lifetime: the pool (to read the cached
/// protocol parameters and the newest FX row), the canonical change address and a
/// synthetic witness key (the fee depends only on the record length and the
/// parameters, never on the specific key or UTxO), the wallet config (the
/// canonical band), the network, the markup, and the freshness ceiling beyond which
/// a stale snapshot stops pricing. The FX prices are NOT held here: they are read
/// per quote from the newest `cw_core.fx_rate` row.
pub struct PgFxPricing {
    pool: sqlx::PgPool,
    change_address: String,
    verification_key: [u8; 32],
    wallet: WalletConfig,
    network: Network,
    margin_pct: Decimal,
    /// The maximum age, in seconds, of the newest `cw_core.fx_rate` snapshot that
    /// may still price a quote. Once the snapshot exceeds this, `resolve` refuses
    /// with the same pricing-unavailable error the no-row case returns, so an
    /// extended oracle outage cannot charge a publish at an arbitrarily stale rate.
    max_fx_snapshot_age_seconds: i64,
}

impl PgFxPricing {
    /// Build the pricing seam from the resolved deployment inputs.
    ///
    /// `change_address` is any verified operator wallet address (the canonical fee
    /// is independent of which one); `margin_pct` is the markup fraction the quote
    /// applies over the cost of goods; `max_fx_snapshot_age_seconds` is the freshness
    /// ceiling beyond which a stale `cw_core.fx_rate` snapshot stops pricing quotes.
    #[must_use]
    pub fn new(
        pool: sqlx::PgPool,
        change_address: String,
        verification_key: [u8; 32],
        wallet: WalletConfig,
        network: Network,
        margin_pct: Decimal,
        max_fx_snapshot_age_seconds: i64,
    ) -> Self {
        Self {
            pool,
            change_address,
            verification_key,
            wallet,
            network,
            margin_pct,
            max_fx_snapshot_age_seconds,
        }
    }
}

/// The newest FX snapshot row, as the pricing read path needs it.
#[derive(sqlx::FromRow)]
struct FxRateRow {
    ada_usd_micros: i64,
    ar_usd_per_byte_femto: i64,
    fetched_at: DateTime<Utc>,
    source: String,
}

/// Read the newest `cw_core.fx_rate` row. The absence of any row is a hard error:
/// there is no safe rate to invent, and the cold-start seed guarantees a row
/// before the data plane serves.
async fn load_latest_fx(pool: &sqlx::PgPool) -> Result<FxRateRow> {
    sqlx::query_as::<_, FxRateRow>(
        "SELECT ada_usd_micros, ar_usd_per_byte_femto, fetched_at, source \
         FROM cw_core.fx_rate ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| {
        Error::Config(
            "no cw_core.fx_rate row exists; the FX refresh loop must seed one before quoting"
                .to_string(),
        )
    })
}

impl PricingSource for PgFxPricing {
    async fn resolve(
        &self,
        account_id: Uuid,
        record_bytes: u32,
        _recipient_count: u32,
        _file_bytes_total: u64,
    ) -> Result<PricingInputs> {
        // Read the cached protocol parameters (the populate loop is the only network
        // caller; this is a pure DB read), then price the canonical one-input +
        // one-change transaction shape for a record of this length. The returned fee
        // is exact: a later submit spending any canonical UTxO of the same shape pays
        // it byte-for-byte. This is the identical fee math the static seam uses.
        let params = load_params(&self.pool, self.network).await?;
        let builder_params = cardano_poe_tx::ProtocolParams {
            min_fee_a: params.min_fee_a,
            min_fee_b: params.min_fee_b,
            coins_per_utxo_byte: params.coins_per_utxo_byte,
            max_tx_size: params.max_tx_size,
        };

        let fee = quote_fee(
            record_bytes as usize,
            &builder_params,
            &self.change_address,
            self.verification_key,
            &self.wallet,
        )?;

        // The two FX prices come from the newest snapshot the refresh loop wrote.
        let fx = load_latest_fx(&self.pool).await?;
        // The real age of the snapshot, surfaced on the quote so a caller sees how
        // fresh the conversion was (no longer the static seam's hardcoded zero). A
        // clock skew that would make this negative is clamped to zero.
        let fx_age_seconds = (Utc::now() - fx.fetched_at).num_seconds().max(0);

        // Bounded staleness: a single missed refresh tick is expected and a slightly
        // stale snapshot still prices, but once the newest row is older than the
        // configured ceiling the upstream feeds have been down (or the refresh task
        // dead) long enough that the conversion can no longer be trusted to bill a
        // publish. Refuse with the SAME error the no-row case returns — the quote
        // route maps it to a retryable "pricing temporarily unavailable" — so a
        // publish is never charged at an arbitrarily stale rate. This is an
        // operator-actionable condition (the oracle pipeline needs attention), so it
        // is raised at error level to page ops rather than refuse silently.
        if fx_age_seconds > self.max_fx_snapshot_age_seconds {
            tracing::error!(
                fx_age_seconds,
                max_fx_snapshot_age_seconds = self.max_fx_snapshot_age_seconds,
                fx_source = %fx.source,
                "fx snapshot exceeds the freshness ceiling; refusing to price a quote until the \
                 FX refresh loop writes a current snapshot"
            );
            return Err(Error::Config(format!(
                "the newest cw_core.fx_rate snapshot is {fx_age_seconds}s old, beyond the \
                 {}s freshness ceiling; refusing to quote against a stale conversion until the \
                 FX refresh loop writes a current snapshot",
                self.max_fx_snapshot_age_seconds
            )));
        }

        // Resolve the effective markup per account through the shared reader: a
        // pushed per-account override when one exists, else the operator-default
        // margin held on this seam. The static seam calls the SAME reader, so the
        // override is honored identically regardless of how the FX rate is sourced.
        let margin = crate::pricing::margin_override::resolve_margin(
            &self.pool,
            account_id,
            self.margin_pct,
        )
        .await?;

        Ok(PricingInputs {
            network_lovelace: fee.fee,
            fx: FxSnapshot {
                ada_usd_micros: fx.ada_usd_micros,
                ar_usd_per_byte_femto: fx.ar_usd_per_byte_femto,
                source: fx.source,
            },
            fx_age_seconds,
            margin,
        })
    }
}
