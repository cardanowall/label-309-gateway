//! Integration tests for the live FX lane: the `cw_core.fx_rate` cache, the
//! restart-survivable oracle cooldown, and the DB-backed pricing seam.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test stands up an isolated, freshly migrated database via the harness, so
//! the schema is applied end to end. No test reaches an external oracle: the
//! refresh loop is the only oracle caller, and these tests exercise the DB read
//! path and the cooldown gate by seeding rows directly, the same way a quote reads
//! the cached snapshot the cron writes in production.

#![cfg(feature = "pg-tests")]

use gateway_core::api::state::PricingSource;
use gateway_core::chain::params::Network as ParamsNetwork;
use gateway_core::pricing::cooldown::{clear_cooldown, read_cooldown, write_cooldown};
use gateway_core::pricing::pg_pricing::PgFxPricing;
use gateway_core::pricing::{ensure_fx_seeded, FxRefreshConfig};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};

/// A real preprod enterprise address. The canonical fee is address-shape
/// invariant, so this stands in as the probe change address the pricing seam
/// prices against.
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

/// Cache a realistic preprod protocol-parameter row so the pricing seam's network
/// fee resolves from a pure DB read.
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

/// Insert one fx_rate snapshot with an explicit age (`fetched_at` set back by
/// `age_seconds`) so a test can assert the reported age. Returns the row id.
async fn seed_fx_rate(
    pool: &sqlx::PgPool,
    ada_usd_micros: i64,
    ar_usd_per_byte_femto: i64,
    age_seconds: i64,
) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO cw_core.fx_rate (ada_usd_micros, ar_usd_per_byte_femto, source, fetched_at) \
         VALUES ($1, $2, 'turbo+coinpaprika', now() - make_interval(secs => $3)) RETURNING id",
    )
    .bind(ada_usd_micros)
    .bind(ar_usd_per_byte_femto)
    .bind(age_seconds as f64)
    .fetch_one(pool)
    .await
    .expect("seed fx rate")
}

/// The freshness ceiling the default-pricing helper uses: one hour, the binary's
/// default. Tests that probe the ceiling itself construct a seam with a tighter one.
const DEFAULT_MAX_FX_SNAPSHOT_AGE_SECONDS: i64 = 3_600;

fn pricing(pool: sqlx::PgPool) -> PgFxPricing {
    pricing_with_ceiling(pool, DEFAULT_MAX_FX_SNAPSHOT_AGE_SECONDS)
}

/// Build the pricing seam with an explicit freshness ceiling, so a test can drive
/// the staleness-refusal path with a snapshot just over the ceiling.
fn pricing_with_ceiling(pool: sqlx::PgPool, max_fx_snapshot_age_seconds: i64) -> PgFxPricing {
    PgFxPricing::new(
        pool,
        CHANGE_ADDRESS.to_string(),
        VERIFICATION_KEY,
        wallet_config(),
        ParamsNetwork::Preprod,
        rust_decimal::Decimal::new(25, 2), // 0.25 markup
        max_fx_snapshot_age_seconds,
    )
}

#[tokio::test]
async fn migration_creates_the_fx_rate_and_cooldown_tables() {
    let db = TestDb::fresh().await.expect("fresh db");
    // Both tables exist in cw_core on a freshly migrated database.
    for table in ["fx_rate", "coingecko_cooldown"] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
             WHERE table_schema = 'cw_core' AND table_name = $1)",
        )
        .bind(table)
        .fetch_one(&db.pool)
        .await
        .expect("table existence check");
        assert!(
            exists,
            "cw_core.{table} must exist on a freshly migrated database"
        );
    }
}

#[tokio::test]
async fn the_fx_rate_check_constraints_reject_non_positive_prices() {
    let db = TestDb::fresh().await.expect("fresh db");
    // A zero ADA price would silently price the network fee at nothing; the CHECK
    // rejects it.
    let zero_ada = sqlx::query(
        "INSERT INTO cw_core.fx_rate (ada_usd_micros, ar_usd_per_byte_femto, source) \
         VALUES (0, 1, 'x')",
    )
    .execute(&db.pool)
    .await;
    assert!(zero_ada.is_err(), "a zero ada_usd_micros must be rejected");

    let zero_femto = sqlx::query(
        "INSERT INTO cw_core.fx_rate (ada_usd_micros, ar_usd_per_byte_femto, source) \
         VALUES (1, 0, 'x')",
    )
    .execute(&db.pool)
    .await;
    assert!(
        zero_femto.is_err(),
        "a zero ar_usd_per_byte_femto must be rejected"
    );
}

#[tokio::test]
async fn pricing_reads_the_newest_snapshot_and_reports_its_age() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_params(&db.pool).await;

    // An older snapshot then a newer one: the read path must serve the newest by id,
    // not the one with the smaller age or the first inserted.
    seed_fx_rate(&db.pool, 400_000, 18_000_000, 3_600).await;
    let newest_id = seed_fx_rate(&db.pool, 450_000, 20_955_000, 120).await;

    let inputs = pricing(db.pool.clone())
        .resolve(uuid::Uuid::now_v7(), 256, 0, 0)
        .await
        .expect("resolve a quote against the cached snapshot");

    // The newest row's prices flow onto the quote's FX snapshot verbatim.
    assert_eq!(inputs.fx.ada_usd_micros, 450_000);
    assert_eq!(inputs.fx.ar_usd_per_byte_femto, 20_955_000);
    assert_eq!(inputs.fx.source, "turbo+coinpaprika");
    // The reported age is the real age of the newest row (~120s), not zero and not
    // the older row's age.
    assert!(
        (110..=240).contains(&inputs.fx_age_seconds),
        "expected ~120s age for the newest snapshot, got {}",
        inputs.fx_age_seconds
    );
    // The markup is carried through.
    assert_eq!(inputs.margin.margin_pct, rust_decimal::Decimal::new(25, 2));
    // The exact canonical network fee was priced (a positive lovelace amount).
    assert!(inputs.network_lovelace > 0, "a real network fee was priced");

    // Sanity: the newest id is the one served.
    let served: i64 = sqlx::query_scalar("SELECT id FROM cw_core.fx_rate ORDER BY id DESC LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(served, newest_id);
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

#[tokio::test]
async fn pricing_reports_the_operator_default_margin_when_no_override_exists() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_params(&db.pool).await;
    seed_fx_rate(&db.pool, 450_000, 20_955_000, 30).await;
    let account = seed_account(&db.pool).await;

    let inputs = pricing(db.pool.clone())
        .resolve(account, 256, 0, 0)
        .await
        .expect("resolve");
    // No override: the seam uses the operator-default margin (0.25) and attributes
    // it as the operator-default.
    assert_eq!(inputs.margin.margin_pct, rust_decimal::Decimal::new(25, 2));
    assert_eq!(inputs.margin.margin_source, "operator-default");
}

#[tokio::test]
async fn pricing_prefers_a_per_account_override_over_the_operator_default() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_params(&db.pool).await;
    seed_fx_rate(&db.pool, 450_000, 20_955_000, 30).await;
    let account = seed_account(&db.pool).await;

    // A pushed per-account override of 0.40 replaces the operator-default 0.25.
    sqlx::query(
        "INSERT INTO cw_core.account_margin_override (account_id, margin_pct) VALUES ($1, $2)",
    )
    .bind(account)
    .bind(rust_decimal::Decimal::new(40, 2))
    .execute(&db.pool)
    .await
    .expect("insert override");

    let inputs = pricing(db.pool.clone())
        .resolve(account, 256, 0, 0)
        .await
        .expect("resolve");
    assert_eq!(
        inputs.margin.margin_pct,
        rust_decimal::Decimal::new(40, 2),
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
    assert_eq!(
        other_inputs.margin.margin_pct,
        rust_decimal::Decimal::new(25, 2)
    );
    assert_eq!(other_inputs.margin.margin_source, "operator-default");
}

#[tokio::test]
async fn pricing_errors_when_no_snapshot_exists() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_params(&db.pool).await;
    // No fx_rate row seeded: there is no safe rate to invent, so the seam errors
    // rather than quoting against a missing conversion.
    let result = pricing(db.pool.clone())
        .resolve(uuid::Uuid::now_v7(), 256, 0, 0)
        .await;
    assert!(
        result.is_err(),
        "pricing must refuse to quote with no fx_rate row"
    );
}

#[tokio::test]
async fn pricing_serves_a_snapshot_within_the_freshness_ceiling() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_params(&db.pool).await;
    // A snapshot 30 minutes old against a one-hour ceiling: a single missed refresh
    // tick is expected, so a slightly stale snapshot still prices normally.
    seed_fx_rate(&db.pool, 450_000, 20_955_000, 1_800).await;

    let inputs = pricing_with_ceiling(db.pool.clone(), 3_600)
        .resolve(uuid::Uuid::now_v7(), 256, 0, 0)
        .await
        .expect("a snapshot within the ceiling prices a quote");

    // The within-ceiling snapshot's prices and a real network fee flow onto the
    // quote: this is a genuine price, not a refusal.
    assert_eq!(inputs.fx.ada_usd_micros, 450_000);
    assert_eq!(inputs.fx.ar_usd_per_byte_femto, 20_955_000);
    assert!(inputs.network_lovelace > 0, "a real network fee was priced");
    assert!(
        inputs.fx_age_seconds <= 3_600,
        "the served snapshot is within the ceiling, got {}s",
        inputs.fx_age_seconds
    );
}

#[tokio::test]
async fn pricing_refuses_a_snapshot_older_than_the_freshness_ceiling() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_params(&db.pool).await;
    // A snapshot two hours old against a one-hour ceiling models an extended oracle
    // outage: the refresh loop has written nothing current for hours. The seam must
    // refuse to quote rather than charge a publish at this stale conversion. Only
    // this stale row exists, so a price would have to come from it; the test proves
    // none is returned.
    seed_fx_rate(&db.pool, 450_000, 20_955_000, 7_200).await;

    let result = pricing_with_ceiling(db.pool.clone(), 3_600)
        .resolve(uuid::Uuid::now_v7(), 256, 0, 0)
        .await;

    // The refusal is the same kind of error the no-row case returns; the quote route
    // maps it to a retryable 503. The key assertion is the ABSENCE of any priced
    // result: no `PricingInputs` (and thus no fabricated price) is ever produced from
    // a snapshot past the ceiling.
    assert!(
        result.is_err(),
        "pricing must refuse a snapshot older than the freshness ceiling, never return a price"
    );

    // And the no-row refusal and the too-stale refusal are the same variant, so the
    // quote route's single `Err(_)` -> 503 arm covers both without a special case.
    let err = result.unwrap_err();
    assert!(
        matches!(err, gateway_core::Error::Config(_)),
        "the staleness refusal reuses the pricing-unavailable error, got {err:?}"
    );
}

#[tokio::test]
async fn pricing_refuses_just_over_the_ceiling_and_prices_just_under_it() {
    // The boundary behaves exactly as configured: a snapshot inside the window
    // prices, one just past it refuses, with no other change between the two runs.
    let db = TestDb::fresh().await.expect("fresh db");
    seed_params(&db.pool).await;
    // Just under a 1000s ceiling (with margin for the test clock): prices.
    seed_fx_rate(&db.pool, 450_000, 20_955_000, 200).await;
    let priced = pricing_with_ceiling(db.pool.clone(), 1_000)
        .resolve(uuid::Uuid::now_v7(), 256, 0, 0)
        .await;
    assert!(
        priced.is_ok(),
        "a snapshot comfortably within the ceiling prices"
    );

    // A second, far older snapshot becomes the newest row; now the read path serves a
    // row past the ceiling and refuses.
    seed_fx_rate(&db.pool, 460_000, 21_000_000, 5_000).await;
    let refused = pricing_with_ceiling(db.pool.clone(), 1_000)
        .resolve(uuid::Uuid::now_v7(), 256, 0, 0)
        .await;
    assert!(
        refused.is_err(),
        "once the newest snapshot is past the ceiling the seam refuses"
    );
}

#[tokio::test]
async fn the_cooldown_gate_is_restart_survivable() {
    let db = TestDb::fresh().await.expect("fresh db");

    // No row yet: the gate is open (a fresh process makes its first oracle call).
    let initial = read_cooldown(&db.pool).await.expect("read cooldown");
    assert!(!initial.is_closed(chrono::Utc::now()));
    assert!(initial.cooldown_until.is_none());

    // A quota signal arms the gate for an hour. Reading it back (as a restarted
    // process would) shows the gate closed, so the next tick will skip the call.
    let until = chrono::Utc::now() + chrono::Duration::hours(1);
    write_cooldown(&db.pool, until, 429, "Rate limit exceeded")
        .await
        .expect("write cooldown");
    let armed = read_cooldown(&db.pool).await.expect("re-read cooldown");
    assert!(
        armed.is_closed(chrono::Utc::now()),
        "an armed cooldown closes the gate across a restart"
    );
    assert_eq!(armed.last_quota_status, Some(429));

    // A successful call after the window reopens the gate.
    clear_cooldown(&db.pool).await.expect("clear cooldown");
    let cleared = read_cooldown(&db.pool)
        .await
        .expect("read cleared cooldown");
    assert!(!cleared.is_closed(chrono::Utc::now()));
    assert!(cleared.cooldown_until.is_none());
}

#[tokio::test]
async fn the_cooldown_row_is_pinned_to_a_single_gate() {
    let db = TestDb::fresh().await.expect("fresh db");
    // Two arming writes upsert the same logical gate, never two rows.
    write_cooldown(&db.pool, chrono::Utc::now(), 429, "a")
        .await
        .unwrap();
    write_cooldown(&db.pool, chrono::Utc::now(), 503, "b")
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.coingecko_cooldown")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "the cooldown is a single pinned gate row");
}

/// An FX refresh config whose oracle URLs are deliberately unreachable. The seed
/// idempotence test seeds a row first, so `ensure_fx_seeded` must short-circuit
/// before any oracle call; if it ever reached out, these URLs would make the test
/// fail loudly rather than the seed silently re-running.
fn unreachable_fx_config() -> FxRefreshConfig {
    FxRefreshConfig {
        // An empty provider chain: every coin-price fetch fails immediately with no
        // network call at all, so a regressed seed that reached the oracles would
        // error loudly rather than touching the network. The unreachable per-byte
        // URLs are the same belt-and-braces for the storage oracle.
        coin_price_providers: Vec::new(),
        turbo_payment_url: "http://127.0.0.1:1/turbo".to_string(),
        arweave_gateway_url: "http://127.0.0.1:1/arweave".to_string(),
    }
}

#[tokio::test]
async fn ensure_fx_seeded_is_idempotent_and_never_duplicates_the_seed() {
    let db = TestDb::fresh().await.expect("fresh db");

    // Stand in for the row a first replica's seed (or a prior boot) committed. With
    // a row already present, `ensure_fx_seeded` must be a no-op: it neither calls an
    // oracle nor inserts a second row. This is the exact race a second replica hits
    // when it boots after the first has seeded.
    seed_fx_rate(&db.pool, 450_000, 20_955_000, 5).await;

    // Call the seed twice with the row present. The unreachable oracle URLs prove no
    // oracle traffic happens: if the guard regressed and the seed re-ran, the refresh
    // would try to reach 127.0.0.1:1 and the call would not return Ok cleanly.
    ensure_fx_seeded(&db.pool, &unreachable_fx_config())
        .await
        .expect("seed is a no-op when a row already exists");
    ensure_fx_seeded(&db.pool, &unreachable_fx_config())
        .await
        .expect("a repeated seed stays a no-op");

    // Exactly one row remains: the seed never duplicated it.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.fx_rate")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "ensure_fx_seeded must leave exactly one row, never a duplicate seed"
    );
}
