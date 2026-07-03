//! The binary's pricing seam for the HTTP data plane.
//!
//! The engine does not bundle an FX oracle: pricing inputs are a vendor seam
//! ([`gateway_core::api::state::PricingSource`]). The reference binary supplies a
//! concrete seam so its data plane is fully functional out of the box. It prices
//! the network fee deterministically from the engine's own canonical-fee helper
//! (the exact lovelace a later submit will pay for a record of that length) and
//! converts it through the operator-configured ADA→USD rate, applying the resolved
//! markup — the operator-default margin, or a per-account override when one is set,
//! read through the same shared reader the live FX seam uses. A deployment that
//! wants a live FX oracle replaces this seam with its own wrapper without touching
//! the engine.

use gateway_core::api::state::{PricingInputs, PricingSource};
use gateway_core::chain::params::{load_params, Network};
use gateway_core::ledger::quote::FxSnapshot;
use gateway_core::wallet::config::WalletConfig;
use gateway_core::wallet::quote::quote_fee;
use rust_decimal::Decimal;
use uuid::Uuid;

/// The reference binary's pricing seam.
///
/// Holds everything the per-quote price computation needs that is fixed for the
/// process lifetime: the pool (to read the cached protocol parameters), the
/// canonical change address and a synthetic witness key (the fee depends only on
/// the record length and the parameters, never on the specific key or UTxO), the
/// wallet config (the canonical band), the network, the operator-configured FX
/// rate, and the operator-default markup (the per-account override is read from
/// Postgres per quote, so it is not held here).
pub struct BinaryPricing {
    pool: sqlx::PgPool,
    change_address: String,
    verification_key: [u8; 32],
    wallet: WalletConfig,
    network: Network,
    rates: FxRates,
    /// The operator-default markup fraction, applied when a quote's account has no
    /// per-account override. Resolved per quote against the override table.
    margin_pct: Decimal,
}

/// The operator-configured conversion rates a quote is priced through.
///
/// The two rates travel together because they are read from the same operator
/// config and recorded together on the quote's FX snapshot: `ada_usd_micros`
/// converts the network fee, `ar_usd_per_byte_femto` forecasts the storage cost.
#[derive(Debug, Clone, Copy)]
pub struct FxRates {
    /// USD per ADA, in micro-USD per ADA, for the network fee.
    pub ada_usd_micros: i64,
    /// USD per stored byte, in femto-USD per byte, for the storage forecast. Zero
    /// for a hash-only deployment (no storage cost to forecast).
    pub ar_usd_per_byte_femto: i64,
}

impl BinaryPricing {
    /// Build the pricing seam from the resolved deployment inputs.
    ///
    /// `change_address` is any verified operator wallet address (the canonical fee
    /// is independent of which one); `rates` carries the ADA→USD and per-byte
    /// storage conversions the quote prices through; `margin_pct` is the
    /// operator-default markup fraction applied over the cost of goods, used unless
    /// the quote's account carries a per-account override.
    #[must_use]
    pub fn new(
        pool: sqlx::PgPool,
        change_address: String,
        verification_key: [u8; 32],
        wallet: WalletConfig,
        network: Network,
        rates: FxRates,
        margin_pct: Decimal,
    ) -> Self {
        Self {
            pool,
            change_address,
            verification_key,
            wallet,
            network,
            rates,
            margin_pct,
        }
    }
}

impl PricingSource for BinaryPricing {
    async fn resolve(
        &self,
        account_id: Uuid,
        record_bytes: u32,
        _recipient_count: u32,
        _file_bytes_total: u64,
    ) -> gateway_core::Result<PricingInputs> {
        // Read the cached protocol parameters (the populate loop is the only
        // network caller; this is a pure DB read), then price the canonical
        // one-input + one-change transaction shape for a record of this length.
        // The returned fee is exact: a later submit spending any canonical UTxO of
        // the same shape pays it byte-for-byte.
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

        Ok(PricingInputs {
            network_lovelace: fee.fee,
            fx: FxSnapshot {
                ada_usd_micros: self.rates.ada_usd_micros,
                // The per-byte storage rate the quote forecasts the storage cost
                // from. The operator configures it (the engine arithmetic is already
                // correct); a hash-only deployment has no storage section and feeds
                // zero, so the storage component of the forecast is zero.
                ar_usd_per_byte_femto: self.rates.ar_usd_per_byte_femto,
                source: "operator-config".to_string(),
            },
            // The configured rate is the freshest the deployment has; the quote
            // records it verbatim, so the age is reported as zero (current).
            fx_age_seconds: 0,
            // The markup honors a per-account override through the SAME shared
            // reader the live FX seam uses, falling back to the operator-default
            // margin held on this seam. Margin resolution is orthogonal to FX-rate
            // sourcing: a static-priced quote attributes the markup with the same
            // account-override / operator-default vocabulary a live-FX quote does.
            margin: gateway_core::pricing::margin_override::resolve_margin(
                &self.pool,
                account_id,
                self.margin_pct,
            )
            .await?,
        })
    }
}
