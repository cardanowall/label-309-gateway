//! Integration tests for the reference binary's static pricing seam
//! ([`gateway::pricing::BinaryPricing`]).
//!
//! The static seam prices a quote from the operator-configured `[http]` rate and
//! markup — the offline path a deployment runs before it wires a live FX oracle.
//! It must honor the SAME per-account margin override the live DB-backed seam does,
//! because margin resolution is orthogonal to how the FX rate is sourced. These
//! tests pin that a stored override wins over the operator default and is
//! attributed as `account-override`, and that an account with no override falls
//! back to the `[http]` margin attributed as `operator-default`. They also assert
//! the FX-snapshot `source` keeps its own rate-source attribution — that string is
//! the RATE source, never a margin source.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use gateway::pricing::{BinaryPricing, FxRates};
use gateway_core::api::state::PricingSource;
use gateway_core::chain::params::Network as ParamsNetwork;
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use rust_decimal::Decimal;

/// A real preprod enterprise address. The canonical fee is address-shape
/// invariant, so this stands in as the probe change address the seam prices
/// against.
const CHANGE_ADDRESS: &str = "addr_test1vpa8ukd77k05gc3etxeyzylxxmyhzg0hvne9qplxvsyl44q6pl7v4";

/// The synthetic witness key the fee-shape probe uses. The witness size is
/// identical for any 32-byte key.
const VERIFICATION_KEY: [u8; 32] = [0x07; 32];

/// The canonical 4-8 ADA band, the one the reference deployment runs.
fn wallet_config() -> WalletConfig {
    WalletConfig {
        network: Network::Preprod,
        band: LovelaceBand::new(4_000_000, 8_000_000, 6_000_000).expect("band"),
        lease: std::time::Duration::from_secs(120),
        min_canonical_count: 4,
    }
}

/// Cache a realistic preprod protocol-parameter row so the seam's network fee
/// resolves from a pure DB read.
async fn seed_params(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO cw_core.cardano_protocol_params \
           (network, epoch, min_fee_a, min_fee_b, coins_per_utxo_byte, max_tx_size, raw) \
         VALUES ('preprod', 213, 44, 155381, 4310, 16384, '{}'::jsonb)",
    )
    .execute(pool)
    .await
    .expect("seed protocol params");
}

/// Seed an operator and an account under it, returning the account id, so the
/// per-account margin override (which FK-references `cw_api.account`) can be set.
async fn seed_account(pool: &sqlx::PgPool) -> uuid::Uuid {
    let operator_id = uuid::Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'op')")
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert operator");
    gateway_core::ledger::account::create_account(pool, operator_id)
        .await
        .expect("create account")
}

/// The static seam under the reference deployment's inputs: a 0.25 operator-default
/// markup and a fixed ADA→USD rate (no live oracle wired).
fn pricing(pool: sqlx::PgPool) -> BinaryPricing {
    BinaryPricing::new(
        pool,
        CHANGE_ADDRESS.to_string(),
        VERIFICATION_KEY,
        wallet_config(),
        ParamsNetwork::Preprod,
        FxRates {
            ada_usd_micros: 500_000,
            ar_usd_per_byte_femto: 0,
        },
        Decimal::new(25, 2), // 0.25 operator-default markup
    )
}

#[tokio::test]
async fn static_pricing_reports_the_operator_default_margin_when_no_override_exists() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_params(&db.pool).await;
    let account = seed_account(&db.pool).await;

    let inputs = pricing(db.pool.clone())
        .resolve(account, 256, 0, 0)
        .await
        .expect("resolve a quote against the static rate");

    // No override: the seam uses the operator-default markup (0.25) and attributes
    // it as the operator-default, NOT the old "operator-config" string.
    assert_eq!(inputs.margin.margin_pct, Decimal::new(25, 2));
    assert_eq!(inputs.margin.margin_source, "operator-default");
    // The FX-snapshot source keeps the static seam's own rate attribution; it is the
    // RATE source and must never leak into the margin vocabulary.
    assert_eq!(inputs.fx.source, "operator-config");
    // A real canonical network fee was priced.
    assert!(inputs.network_lovelace > 0, "a real network fee was priced");
}

#[tokio::test]
async fn static_pricing_prefers_a_per_account_override_over_the_operator_default() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_params(&db.pool).await;
    let account = seed_account(&db.pool).await;

    // A pushed per-account override of 0.50 replaces the operator-default 0.25. This
    // is the exact live reproduction: static mode + a stored override must price at
    // the override, not the `[http].margin_pct`.
    sqlx::query(
        "INSERT INTO cw_core.account_margin_override (account_id, margin_pct) VALUES ($1, $2)",
    )
    .bind(account)
    .bind(Decimal::new(50, 2))
    .execute(&db.pool)
    .await
    .expect("insert override");

    let inputs = pricing(db.pool.clone())
        .resolve(account, 256, 0, 0)
        .await
        .expect("resolve");
    assert_eq!(
        inputs.margin.margin_pct,
        Decimal::new(50, 2),
        "the override pct wins over the operator default"
    );
    assert_eq!(inputs.margin.margin_source, "account-override");

    // A DIFFERENT account with no override still gets the operator default, proving
    // the override is per-account, not global.
    let other = seed_account(&db.pool).await;
    let other_inputs = pricing(db.pool.clone())
        .resolve(other, 256, 0, 0)
        .await
        .expect("resolve other");
    assert_eq!(other_inputs.margin.margin_pct, Decimal::new(25, 2));
    assert_eq!(other_inputs.margin.margin_source, "operator-default");
}
