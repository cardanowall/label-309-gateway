//! The quote route's storage-affordability contract.
//!
//! Storing content beyond the free window is priced and funded out of an operator's
//! storage funding source. The quote route checks at QUOTE time (not mid-publish)
//! that the caller is entitled to draw a source for the configured backend AND that
//! the BACKEND can fund the chargeable bytes — the same `affords` seam the upload
//! routes consult, so a quote and the upload it precedes can never disagree. For
//! the Turbo backend that answer is its cached winc balance; for a backend with no
//! funding ceiling (the dev emulator) the trait default always affords. These
//! suites drive the real axum router in-process and pin that behaviour against a
//! real Postgres:
//!
//!   - free-window content (`chargeable == 0`) never touches the funding path and
//!     quotes with no grant and no credit;
//!   - over-the-window content with NO entitling grant is a `402 no-funding-grant`;
//!   - on the Turbo backend, over-the-window content whose source has no cached
//!     balance, a balance at or below the safety floor, or a provider capacity
//!     below the chargeable bytes is a `402 insufficient-storage-credit`;
//!   - on the Turbo backend, over-the-window content drawn against a funded source
//!     above the floor quotes, and the wire total still sums its breakdown
//!     (`network + storage + service`);
//!   - on a default-affords backend, over-the-window content quotes with no credit
//!     row at all — and even with a negative materialized balance left by past
//!     charges (such a backend has no winc economy to reconcile).
//!
//! The price the route stores is unchanged by this gate: the storage component stays
//! a forecast inside the wire total. The affordability check only decides whether the
//! quote is issued at all, never the number.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::path::Path;
use std::sync::Arc;

use ans104::SignedEnvelope;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use gateway_core::api::state::{
    ApiConfig, AppState, DynPricingSource, PricingInputs, PricingSource, StorageState,
};
use gateway_core::storage::{
    insert_credit_entry, issue_grant, AuthorizedFunding, CreditEntry, CreditKind,
    StorageBackendExt, StorageError, StorageGrantScope, StorageReceipt, TurboBackend,
};
use gateway_core::testsupport::TestDb;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// The canonical backend the storage suites exercise (the Turbo rail). It must
/// match the test backend's `name()` and the funding source's `backend` column, so
/// the funding resolver keys on the same string the deployment persists.
const BACKEND: &str = "turbo";

/// The operator-chosen api-key secret prefix (no hardcoded brand string).
const KEY_PREFIX: &str = "tk_live_";

/// The per-byte storage price the test FX charges, in femto-USD per byte. A nonzero
/// price makes the storage component (and the chargeable-bytes branch) real.
const AR_USD_PER_BYTE_FEMTO: i64 = 2_000_000_000;

/// A backend whose `affords` is the trait default (always Ok): the dev/emulator
/// family, where the provider mints balance freely and no winc economy exists.
/// The quote route must take its affordability answer from the backend — the
/// same seam the upload routes consult — so this backend quotes over-window
/// content even though its funding source can never carry a reconciled credit.
struct AlwaysAffordsBackend;

impl StorageBackendExt for AlwaysAffordsBackend {
    fn name(&self) -> &'static str {
        "arlocal"
    }

    async fn upload(
        &self,
        _funding: &AuthorizedFunding,
        _envelope: &SignedEnvelope,
        _owner: &[u8],
        _staged_path: &Path,
    ) -> Result<StorageReceipt, StorageError> {
        // The quote route never uploads; a real upload is the uploads route's path.
        Err(StorageError::Misconfigured(
            "the quote affordability suite never uploads".into(),
        ))
    }
}

/// A test pricing seam: a fixed network fee, FX snapshot, and margin. The engine
/// computes the COGS and persists the quote; this only supplies the vendor inputs.
/// The per-byte storage price is nonzero so chargeable content has a real cost.
struct TestPricing;

impl PricingSource for TestPricing {
    async fn resolve(
        &self,
        _account_id: Uuid,
        _record_bytes: u32,
        _recipient_count: u32,
        _file_bytes_total: u64,
    ) -> gateway_core::Result<PricingInputs> {
        Ok(PricingInputs {
            network_lovelace: 2_000_000,
            fx: gateway_core::ledger::quote::FxSnapshot {
                ada_usd_micros: 500_000,
                ar_usd_per_byte_femto: AR_USD_PER_BYTE_FEMTO,
                source: "test-oracle".to_string(),
            },
            fx_age_seconds: 7,
            margin: gateway_core::ledger::quote::MarginResolution {
                margin_pct: Decimal::new(25, 2),
                margin_source: "test".to_string(),
            },
        })
    }
}

/// Build app state with the test pricing seam and a storage seam over the given
/// backend.
fn state_with_backend(
    pool: sqlx::PgPool,
    backend: Arc<dyn gateway_core::storage::StorageBackend>,
) -> AppState {
    AppState::new(
        pool,
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..Default::default()
        },
    )
    .with_pricing(Arc::new(TestPricing) as Arc<dyn DynPricingSource>)
    .with_storage(StorageState::new(backend))
}

/// Build app state with the test pricing seam and a storage seam over the REAL
/// Turbo backend (its winc-cached affordability policy is the contract under
/// test), refusing below `winc_safety_floor`. The upload URLs are never hit: the
/// quote path reads only the database.
fn state(pool: sqlx::PgPool, winc_safety_floor: i64) -> AppState {
    let backend = TurboBackend::new(
        pool.clone(),
        "http://turbo.invalid",
        "http://gateway.invalid",
        Decimal::from(winc_safety_floor),
        std::time::Duration::from_secs(300),
    );
    state_with_backend(pool, Arc::new(backend))
}

/// A handle to a provisioned tenant.
struct Tenant {
    operator_id: Uuid,
    account_id: Uuid,
}

/// Provision an operator and an account under it, returning the tenant handle.
async fn seed_tenant(pool: &sqlx::PgPool) -> Tenant {
    let operator_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'op')")
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert operator");

    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("insert account anchor");
    sqlx::query(
        "INSERT INTO cw_core.account_detail (account_id, operator_id, status) \
         VALUES ($1, $2, 'active')",
    )
    .bind(account_id)
    .bind(operator_id)
    .execute(pool)
    .await
    .expect("insert account detail");

    Tenant {
        operator_id,
        account_id,
    }
}

/// Register a funding source owned by `owner` for `backend`, returning its id.
/// The backend string must match the storage seam's `backend_name()` for the
/// funding resolver to key on it.
async fn register_source_for(pool: &sqlx::PgPool, owner: Uuid, backend: &str, seed: u8) -> Uuid {
    let id = Uuid::now_v7();
    let address = format!("ar-address-{seed:02x}");
    sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'primary', $3, $4, $5)",
    )
    .bind(id)
    .bind(owner)
    .bind(backend)
    .bind(&address)
    .bind(format!("key-{seed:02x}"))
    .execute(pool)
    .await
    .expect("seed funding source");
    id
}

/// Register a funding source owned by `owner` for [`BACKEND`], returning its id.
async fn register_source(pool: &sqlx::PgPool, owner: Uuid, seed: u8) -> Uuid {
    register_source_for(pool, owner, BACKEND, seed).await
}

/// Append a believed-credit delta so the source's materialized `storage_credit`
/// balance carries `winc`. A positive `refund` delta is the simplest way to stamp a
/// believed balance without driving the reconcile loop; the trigger materializes it.
async fn fund_source(pool: &sqlx::PgPool, source: Uuid, winc: i64) {
    insert_credit_entry(
        pool,
        &CreditEntry {
            funding_source_id: source,
            kind: CreditKind::Refund,
            winc_delta: Decimal::from(winc),
            r#ref: Some(format!("seed-{}", Uuid::now_v7())),
        },
    )
    .await
    .expect("seed credit balance");
}

/// Issue an api key for an account with the `poe:create` scope, returning the bearer
/// secret to present.
async fn issue_key(pool: &sqlx::PgPool, account_id: Uuid) -> String {
    let secret = format!("{KEY_PREFIX}{}", Uuid::now_v7().simple());
    let full = Sha256::digest(secret.as_bytes());
    let lookup = full[..8].to_vec();

    sqlx::query(
        "INSERT INTO cw_core.api_key \
           (id, account_id, prefix, key_lookup, key_hash_sha256, scopes, rate_limit_per_min) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(Uuid::now_v7())
    .bind(account_id)
    .bind(KEY_PREFIX)
    .bind(lookup)
    .bind(full.to_vec())
    .bind(vec!["poe:create".to_string()])
    .bind(1000_i32)
    .execute(pool)
    .await
    .expect("insert api key");

    secret
}

// ---------------------------------------------------------------------------
// Request helpers.
// ---------------------------------------------------------------------------

/// Drive a quote request for `file_bytes_total` content bytes and return the
/// (status, json body).
async fn quote_for(state: &AppState, secret: &str, file_bytes_total: u64) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/poe/quote")
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "record_bytes": 64,
                "recipient_count": 0,
                "file_bytes_total": file_bytes_total,
            })
            .to_string(),
        ))
        .expect("build request");

    let router = gateway_core::api::router(state.clone());
    let response = router.oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

/// The free-storage window the default config quotes for free (100 KiB).
const FREE_WINDOW: u64 = 102_400;

// ---------------------------------------------------------------------------
// (a) The free window never touches the funding path.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn free_window_content_quotes_without_a_grant_or_credit() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone(), 0);
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id).await;

    // No funding source, no grant, no credit. Content AT the free window is not
    // chargeable, so the storage-affordability gate is never reached.
    let (status, body) = quote_for(&st, &secret, FREE_WINDOW).await;
    assert_eq!(status, StatusCode::OK, "free-window content quotes: {body}");
    assert_eq!(
        body["breakdown"]["storage_usd_micros"],
        json!("0"),
        "content at the free window carries no storage cost"
    );
}

// ---------------------------------------------------------------------------
// (b) Over the window with no entitling grant -> 402 no-funding-grant.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn over_window_with_no_grant_is_refused_no_funding_grant() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone(), 0);
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id).await;

    // A source exists but NO grant entitles the account to draw it: the resolver
    // returns no source, so the quote is refused before any credit read.
    let _source = register_source(&db.pool, t.operator_id, 0x01).await;

    let (status, body) = quote_for(&st, &secret, FREE_WINDOW + 1_000).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "no grant entitles the account: {body}"
    );
    assert_eq!(body["code"], json!("no-funding-grant"));
}

// ---------------------------------------------------------------------------
// (c) Over the window, granted, but the credit gate refuses.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn over_window_granted_but_no_cached_balance_is_insufficient_storage_credit() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone(), 0);
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id).await;

    let source = register_source(&db.pool, t.operator_id, 0x02).await;
    issue_grant(&db.pool, t.operator_id, source, StorageGrantScope::Service)
        .await
        .expect("issue grant");

    // The grant entitles the account, but the source has no reconciled credit row
    // yet: unknown is treated as unfunded, so the quote is refused.
    let (status, body) = quote_for(&st, &secret, FREE_WINDOW + 1_000).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "an unreconciled source is unfunded: {body}"
    );
    assert_eq!(body["code"], json!("insufficient-storage-credit"));
}

#[tokio::test]
async fn over_window_granted_with_balance_at_or_below_floor_is_insufficient_storage_credit() {
    let db = TestDb::fresh().await.expect("db");
    // A safety floor of 10_000 winc: a believed balance at the floor does not afford.
    let st = state(db.pool.clone(), 10_000);
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id).await;

    let source = register_source(&db.pool, t.operator_id, 0x03).await;
    issue_grant(&db.pool, t.operator_id, source, StorageGrantScope::Service)
        .await
        .expect("issue grant");
    // A believed balance exactly at the floor: the affordability check refuses at or
    // below the floor.
    fund_source(&db.pool, source, 10_000).await;

    let (status, body) = quote_for(&st, &secret, FREE_WINDOW + 1_000).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "a balance at the floor does not afford: {body}"
    );
    assert_eq!(body["code"], json!("insufficient-storage-credit"));
}

// ---------------------------------------------------------------------------
// (d) Over the window, granted, funded above the floor -> the quote issues and the
//     wire total still sums its breakdown.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn over_window_granted_and_funded_quotes_and_total_sums_the_breakdown() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone(), 10_000);
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id).await;

    let source = register_source(&db.pool, t.operator_id, 0x04).await;
    issue_grant(&db.pool, t.operator_id, source, StorageGrantScope::Service)
        .await
        .expect("issue grant");
    // Funded well above the floor.
    fund_source(&db.pool, source, 5_000_000).await;

    // 1_000 chargeable bytes at 2e9 femto-USD/byte = 2e12 femto-USD = 2_000 micro-USD.
    let (status, body) = quote_for(&st, &secret, FREE_WINDOW + 1_000).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a funded, granted source quotes over the window: {body}"
    );

    // The storage component is nonzero (the content is over the window), and the wire
    // total is exactly the sum of the breakdown: the affordability gate did not
    // change the price, only whether the quote was issued.
    let network: i64 = body["breakdown"]["network_usd_micros"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("network component");
    let storage: i64 = body["breakdown"]["storage_usd_micros"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("storage component");
    let service: i64 = body["breakdown"]["service_usd_micros"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("service component");
    let total: i64 = body["usd_micros"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("wire total");

    assert!(storage > 0, "over-window content carries a storage cost");
    assert_eq!(
        total,
        network + storage + service,
        "the wire total equals network + storage + service"
    );
    assert_eq!(
        body["amount"], body["usd_micros"],
        "the SDK amount mirrors the wire total"
    );
}

// ---------------------------------------------------------------------------
// (e) Affordability is the BACKEND's answer, not a winc-cache read. A backend
//     whose `affords` is the trait default (the dev/emulator family: the provider
//     mints balance freely, no winc economy exists, the reconcile loop never
//     stamps a credit) must quote over-window content — with no credit row at
//     all, and even with a negative materialized balance left by past charges.
//     The upload routes already consult the backend; the quote route must agree,
//     or a publish the upload would accept dies at the quote step.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn over_window_on_default_affords_backend_quotes_with_no_credit_row() {
    let db = TestDb::fresh().await.expect("db");
    let st = state_with_backend(db.pool.clone(), Arc::new(AlwaysAffordsBackend));
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id).await;

    // Granted, but no storage_credit row exists and none can ever be reconciled
    // (the backend has no winc-balance provider). The backend's own affordability
    // answer is what the quote must honour.
    let source = register_source_for(&db.pool, t.operator_id, "arlocal", 0x05).await;
    issue_grant(&db.pool, t.operator_id, source, StorageGrantScope::Service)
        .await
        .expect("issue grant");

    let (status, body) = quote_for(&st, &secret, FREE_WINDOW + 1_000).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a default-affords backend quotes over the window with zero credit: {body}"
    );
    assert_ne!(
        body["breakdown"]["storage_usd_micros"],
        json!("0"),
        "the storage forecast is still priced"
    );
}

#[tokio::test]
async fn over_window_on_default_affords_backend_quotes_despite_negative_balance() {
    let db = TestDb::fresh().await.expect("db");
    let st = state_with_backend(db.pool.clone(), Arc::new(AlwaysAffordsBackend));
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id).await;

    let source = register_source_for(&db.pool, t.operator_id, "arlocal", 0x06).await;
    issue_grant(&db.pool, t.operator_id, source, StorageGrantScope::Service)
        .await
        .expect("issue grant");
    // Past paid uploads journalled charges against a balance that started (and
    // stays) at zero: the materialized winc balance is negative. That is normal
    // bookkeeping for a backend with no winc economy and must not gate the quote.
    insert_credit_entry(
        &db.pool,
        &CreditEntry {
            funding_source_id: source,
            kind: CreditKind::Charge,
            winc_delta: Decimal::from(-102_400),
            r#ref: Some(format!("charge-{}", Uuid::now_v7())),
        },
    )
    .await
    .expect("journal a past charge");

    let (status, body) = quote_for(&st, &secret, FREE_WINDOW + 1_000).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a default-affords backend quotes despite a negative materialized balance: {body}"
    );
}

// ---------------------------------------------------------------------------
// (f) A deployment with no storage seam wired quotes free-window content but skips
//     the affordability branch entirely (hash-only deployment).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_storage_seam_quotes_over_window_content_unfunded() {
    let db = TestDb::fresh().await.expect("db");
    // State WITHOUT a storage seam: an intentional hash-only deployment.
    let st = AppState::new(
        db.pool.clone(),
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..Default::default()
        },
    )
    .with_pricing(Arc::new(TestPricing) as Arc<dyn DynPricingSource>);
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id).await;

    // Over-the-window content quotes: with no storage seam there is no funding gate
    // to fail. The price still carries a storage forecast.
    let (status, body) = quote_for(&st, &secret, FREE_WINDOW + 1_000).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "with no storage seam, the affordability gate is skipped: {body}"
    );
    assert_ne!(
        body["breakdown"]["storage_usd_micros"],
        json!("0"),
        "the storage forecast is still priced"
    );
}
