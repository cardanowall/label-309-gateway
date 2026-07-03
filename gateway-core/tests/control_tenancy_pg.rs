//! Cross-operator tenancy isolation on the control plane.
//!
//! The control surface is multi-tenant: many operators share one engine and one
//! database. Every account / wallet / key / audit row belongs to exactly one
//! operator, and an operator's credential must never reach another operator's
//! rows. These suites drive the REAL control router (and, for the access-token
//! case, the real data router) with two operators A and B, and assert that A's
//! operator token cannot read or mutate ANY of B's resources across every route
//! that takes a resource id from the path, plus the audit read.
//!
//! # The isolation contract these tests pin
//!
//!   - A non-owned resource is a 404, never a 403: a cross-tenant access is
//!     shaped exactly like a missing one, so a probe cannot use the status code
//!     as an existence oracle. (Documented on the route helper `not_found`.)
//!   - A rejected mutation has NO side effect: the target row's state is asserted
//!     unchanged after the call.
//!   - The audit read returns only the querying operator's own rows: A's audit
//!     query never returns a single one of B's rows.
//!   - The positive path still works: A acts freely on A's own resources, and an
//!     account token A minted for A's account still authenticates the data plane.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Duration;
use gateway_core::api::control::credential::mint_root_credential;
use gateway_core::api::control::ledger_adjust::register_manual_adjustment_kind;
use gateway_core::api::control::{ControlConfig, ControlState};
use gateway_core::api::state::{DynPricingSource, PricingInputs, PricingSource};
use gateway_core::api::{control_router, ApiConfig, AppState};
use gateway_core::ledger::quote::{FxSnapshot, MarginResolution};
use gateway_core::testsupport::TestDb;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

/// The operator-chosen secret prefix the control plane mints credentials under.
const PREFIX: &str = "ctl_";

/// A test pricing seam so the data-plane quote route can price a publish; the
/// access-token positive case reads the balance, which does not consult pricing,
/// but the data router build path needs a pricing source wired.
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
            fx: FxSnapshot {
                ada_usd_micros: 500_000,
                ar_usd_per_byte_femto: 0,
                source: "test-oracle".to_string(),
            },
            fx_age_seconds: 12,
            margin: MarginResolution {
                margin_pct: Decimal::new(25, 2),
                margin_source: "test".to_string(),
            },
        })
    }
}

/// Build the data-plane router with the test pricing seam wired.
fn data_router(pool: sqlx::PgPool) -> axum::Router {
    let state = AppState::new(
        pool,
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..Default::default()
        },
    )
    .with_pricing(Arc::new(TestPricing) as Arc<dyn DynPricingSource>);
    gateway_core::api::router(state)
}

/// The tenant labels this suite provisions. Each tenant's wallet address is derived
/// from its label's first byte, so the test instance must declare it holds a signer
/// for exactly these seeds for the wallet-register route to accept them.
const PROVISIONED_TENANT_LABELS: &[&str] = &["a", "b"];

/// Build the control router state with a permissive config, declaring the instance
/// holds a signing key for every wallet address the suite's tenants register (the
/// wallet-register route now refuses an address no instance signer backs).
fn control_state(pool: sqlx::PgPool) -> ControlState {
    let wallet_keys = PROVISIONED_TENANT_LABELS
        .iter()
        .map(|label| {
            let seed = label.bytes().next().unwrap_or(b'x');
            gateway_core::api::ControlWalletKey {
                address: preprod_address(seed),
                label: (*label).to_string(),
            }
        })
        .collect();
    ControlState::with_keys(
        pool,
        ControlConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            secret_prefix: PREFIX.to_string(),
            operator_token_ttl: Duration::hours(1),
            account_token_ttl: Duration::hours(1),
            adjustment_cap_usd_micros: 10_000_000_000,
            admin_ui_enabled: false,
            default_wallet_scope: gateway_core::api::DefaultWalletScope::Service,
            default_storage_scope: gateway_core::api::DefaultStorageScope::Service,
            ..Default::default()
        },
        wallet_keys,
        Vec::new(),
    )
}

/// A real preprod enterprise bech32 address derived from a per-tenant seed, so
/// each provisioned tenant registers a DISTINCT, validly-encoded address (the
/// register route now parses the address and checks its network id).
fn preprod_address(seed: u8) -> String {
    let key = pallas_crypto::key::ed25519::SecretKey::from([seed; 32]);
    let vk = {
        let pk = key.public_key();
        let mut out = [0u8; 32];
        out.copy_from_slice(pk.as_ref());
        out
    };
    gateway_core::wallet::keyring::derive_enterprise_address(
        &vk,
        gateway_core::wallet::config::Network::Preprod,
    )
    .expect("derive preprod address")
}

/// Issue a control request and return (status, body json).
async fn call(
    router: &axum::Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let req = if let Some(b) = body {
        req.header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        req.body(Body::empty()).unwrap()
    };
    let resp = router.clone().oneshot(req).await.expect("router responds");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

/// One operator and everything it owns: its root credential, an operator token
/// minted from it, an account under it, an api key on that account, and a wallet.
struct Tenant {
    operator_id: Uuid,
    operator_token: String,
    account_id: Uuid,
    key_id: Uuid,
    wallet_id: Uuid,
}

/// Provision an operator with a full set of resources and return the handles a
/// cross-tenant test needs.
async fn provision_tenant(router: &axum::Router, pool: &sqlx::PgPool, label: &str) -> Tenant {
    // The wallet-register route enqueues a targeted replenish in the same
    // transaction as the wallet row and its grant; the enqueue resolves its
    // attempt/backoff defaults from the replenish queue policy, so that policy must
    // exist before a register can run. The supervised runtime reconciles it at
    // startup in production; this tenancy suite registers wallets without booting
    // the runtime, so it seeds the policy here (idempotent per call).
    gateway_core::runtime::policy::reconcile(
        pool,
        &gateway_core::wallet::replenish::replenish_policy(),
    )
    .await
    .expect("reconcile replenish policy");

    let operator_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(operator_id)
        .bind(label)
        .execute(pool)
        .await
        .expect("insert operator");

    let root = mint_root_credential(pool, operator_id, PREFIX, None)
        .await
        .expect("mint root");
    let (status, body) = call(
        router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let operator_token = body["token"].as_str().expect("operator token").to_string();

    // An account, funded so it has a non-zero balance to detect tampering.
    let (status, body) = call(
        router,
        "POST",
        "/control/v1/accounts",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let account_id = Uuid::parse_str(body["account_id"].as_str().unwrap()).unwrap();

    let (status, _) = call(
        router,
        "POST",
        &format!("/control/v1/accounts/{account_id}/ledger-adjustment"),
        Some(&operator_token),
        Some(json!({ "amount_usd_micros": 7_000_000, "reason": "seed funding" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // An api key on the account.
    let (status, body) = call(
        router,
        "POST",
        &format!("/control/v1/accounts/{account_id}/keys"),
        Some(&operator_token),
        Some(json!({ "scopes": ["poe:read"], "rate_limit_per_min": 120, "label": "orig" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let key_id = Uuid::parse_str(body["key_id"].as_str().unwrap()).unwrap();

    // A wallet at a real, distinct preprod address (the register route now parses
    // and network-checks the address). A distinct per-tenant seed keeps two
    // tenants' wallets at different global identities. Registration binds a
    // shared-keyring signing key to an owner, so it is a root-only action; the
    // operator token administers the wallet afterward (drain, reactivate, grant).
    let seed = label.bytes().next().unwrap_or(b'x');
    let (status, body) = call(
        router,
        "POST",
        "/control/v1/wallets",
        Some(&root.secret),
        Some(json!({
            "label": "primary",
            "address": preprod_address(seed),
            "network": "preprod",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let wallet_id = Uuid::parse_str(body["wallet_id"].as_str().unwrap()).unwrap();

    Tenant {
        operator_id,
        operator_token,
        account_id,
        key_id,
        wallet_id,
    }
}

/// Read an account's lifecycle status straight from the satellite.
async fn account_status_of(pool: &sqlx::PgPool, account_id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM cw_core.account_detail WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(pool)
        .await
        .expect("status")
}

/// Read an account's materialised balance (0 when no row).
async fn balance_of(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE((SELECT balance_micros FROM cw_core.balance WHERE account_id = $1), 0)",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("balance")
}

/// Read a wallet's lifecycle status straight from the row.
async fn wallet_status_of(pool: &sqlx::PgPool, wallet_id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM cw_core.operator_wallet WHERE id = $1")
        .bind(wallet_id)
        .fetch_one(pool)
        .await
        .expect("wallet status")
}

/// Read a key's revoked marker and label.
async fn key_state_of(pool: &sqlx::PgPool, key_id: Uuid) -> (bool, Option<String>) {
    let (revoked_at, label): (Option<chrono::DateTime<chrono::Utc>>, Option<String>) =
        sqlx::query_as("SELECT revoked_at, label FROM cw_core.api_key WHERE id = $1")
            .bind(key_id)
            .fetch_one(pool)
            .await
            .expect("key state");
    (revoked_at.is_some(), label)
}

/// Count the access tokens minted under an operator.
async fn token_count_of(pool: &sqlx::PgPool, operator_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.access_token WHERE operator_id = $1")
        .bind(operator_id)
        .fetch_one(pool)
        .await
        .expect("token count")
}

/// Count the api keys on an account.
async fn key_count_of(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.api_key WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(pool)
        .await
        .expect("key count")
}

/// The full cross-operator breach matrix: operator A's token, presented against
/// every one of operator B's resources, returns the non-owned status (404) and
/// changes NOTHING. One test so the whole matrix shares one fixture and the
/// before/after side-effect snapshots are taken against the same database state.
#[tokio::test]
async fn an_operator_token_cannot_touch_another_operators_resources() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let router = control_router(control_state(db.pool.clone()));

    let a = provision_tenant(&router, &db.pool, "a").await;
    let b = provision_tenant(&router, &db.pool, "b").await;

    // Snapshot B's state before A's hostile probes.
    let b_status_before = account_status_of(&db.pool, b.account_id).await;
    let b_balance_before = balance_of(&db.pool, b.account_id).await;
    let b_wallet_status_before = wallet_status_of(&db.pool, b.wallet_id).await;
    let b_key_state_before = key_state_of(&db.pool, b.key_id).await;
    let b_token_count_before = token_count_of(&db.pool, b.operator_id).await;
    let b_key_count_before = key_count_of(&db.pool, b.account_id).await;
    assert_eq!(b_status_before, "active");
    assert_eq!(b_balance_before, 7_000_000);

    // ---- The 11 mutating / reading breach vectors, each must 404. ----
    let at = Some(a.operator_token.as_str());

    // 1. accounts/{B}/disable
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/disable", b.account_id),
        at,
        Some(json!({ "reason": "hostile" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "disable B's account");

    // 2. accounts/{B}/enable (first disable B legitimately so enable would change
    // it if isolation leaked; do that through B's own token).
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/disable", b.account_id),
        Some(b.operator_token.as_str()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B may disable its own account");
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/enable", b.account_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "enable B's account");
    assert_eq!(
        account_status_of(&db.pool, b.account_id).await,
        "disabled",
        "A's failed enable must not re-activate B's account"
    );
    // Restore B to active through B's own token for the remaining snapshots.
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/enable", b.account_id),
        Some(b.operator_token.as_str()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 3. accounts/{B}/usage
    let (status, _) = call(
        &router,
        "GET",
        &format!("/control/v1/accounts/{}/usage", b.account_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "read B's usage");

    // 4. accounts/{B}/token
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/token", b.account_id),
        at,
        Some(json!({ "scopes": ["poe:read"] })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "mint a token for B's account"
    );

    // 5. accounts/{B}/keys (create)
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/keys", b.account_id),
        at,
        Some(json!({ "scopes": ["poe:read"], "rate_limit_per_min": 60 })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "create a key on B's account");

    // 6. accounts/{B}/keys (list)
    let (status, _) = call(
        &router,
        "GET",
        &format!("/control/v1/accounts/{}/keys", b.account_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "list B's keys");

    // 7. accounts/{B}/keys/{key}/revoke
    let (status, _) = call(
        &router,
        "POST",
        &format!(
            "/control/v1/accounts/{}/keys/{}/revoke",
            b.account_id, b.key_id
        ),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "revoke B's key");

    // 8. accounts/{B}/keys/{key}/relabel
    let (status, _) = call(
        &router,
        "POST",
        &format!(
            "/control/v1/accounts/{}/keys/{}/relabel",
            b.account_id, b.key_id
        ),
        at,
        Some(json!({ "label": "pwned" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "relabel B's key");

    // 9. accounts/{B}/ledger-adjustment
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/ledger-adjustment", b.account_id),
        at,
        Some(json!({ "amount_usd_micros": -7_000_000, "reason": "drain it" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "adjust B's balance");

    // 10. wallets/{B}/drain
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{}/drain", b.wallet_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "drain B's wallet");

    // 11. wallets/{B}/reactivate (drain B legitimately first so a leaked
    // reactivate would visibly change state).
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{}/drain", b.wallet_id),
        Some(b.operator_token.as_str()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B may drain its own wallet");
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{}/reactivate", b.wallet_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "reactivate B's wallet");
    assert_eq!(
        wallet_status_of(&db.pool, b.wallet_id).await,
        "draining",
        "A's failed reactivate must not return B's wallet to active"
    );

    // ---- No side effects: every mutable handle is back where it started
    // (modulo the legitimate B-driven drain above). ----
    assert_eq!(account_status_of(&db.pool, b.account_id).await, "active");
    assert_eq!(balance_of(&db.pool, b.account_id).await, b_balance_before);
    assert_eq!(key_state_of(&db.pool, b.key_id).await, b_key_state_before);
    assert_eq!(
        token_count_of(&db.pool, b.operator_id).await,
        b_token_count_before
    );
    assert_eq!(
        key_count_of(&db.pool, b.account_id).await,
        b_key_count_before
    );
    // B's wallet is draining (B drained it itself); A never reactivated it.
    let _ = b_wallet_status_before;
}

/// An ACCOUNT token A minted for A's account cannot reach a DIFFERENT account's
/// account-level routes, even one under the same engine. The account-scope guard
/// rejects it before any engine call, and nothing on the foreign account changes.
#[tokio::test]
async fn an_account_token_cannot_act_on_another_account() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let router = control_router(control_state(db.pool.clone()));

    let a = provision_tenant(&router, &db.pool, "a").await;
    let b = provision_tenant(&router, &db.pool, "b").await;

    // A mints an account token for A's OWN account.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/token", a.account_id),
        Some(a.operator_token.as_str()),
        Some(json!({ "scopes": ["poe:read"] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let a_account_token = body["token"].as_str().unwrap().to_string();
    let at = Some(a_account_token.as_str());

    let b_balance_before = balance_of(&db.pool, b.account_id).await;
    let b_key_state_before = key_state_of(&db.pool, b.key_id).await;
    let b_token_count_before = token_count_of(&db.pool, b.operator_id).await;
    let b_key_count_before = key_count_of(&db.pool, b.account_id).await;

    // Every account-level route aimed at B's account is forbidden: the account
    // token is bound to A's account, so the scope guard rejects it (403). It never
    // reaches the engine, so it cannot even probe existence.
    for (method, path, body) in [
        (
            "GET",
            format!("/control/v1/accounts/{}/usage", b.account_id),
            None,
        ),
        (
            "POST",
            format!("/control/v1/accounts/{}/token", b.account_id),
            Some(json!({ "scopes": ["poe:read"] })),
        ),
        (
            "POST",
            format!("/control/v1/accounts/{}/keys", b.account_id),
            Some(json!({ "scopes": ["poe:read"], "rate_limit_per_min": 60 })),
        ),
        (
            "GET",
            format!("/control/v1/accounts/{}/keys", b.account_id),
            None,
        ),
        (
            "POST",
            format!(
                "/control/v1/accounts/{}/keys/{}/revoke",
                b.account_id, b.key_id
            ),
            None,
        ),
        (
            "POST",
            format!(
                "/control/v1/accounts/{}/keys/{}/relabel",
                b.account_id, b.key_id
            ),
            Some(json!({ "label": "pwned" })),
        ),
    ] {
        let (status, _) = call(&router, method, &path, at, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an account token bound to A must not act on B via {method} {path}"
        );
    }

    // Nothing on B changed.
    assert_eq!(balance_of(&db.pool, b.account_id).await, b_balance_before);
    assert_eq!(key_state_of(&db.pool, b.key_id).await, b_key_state_before);
    assert_eq!(
        token_count_of(&db.pool, b.operator_id).await,
        b_token_count_before
    );
    assert_eq!(
        key_count_of(&db.pool, b.account_id).await,
        b_key_count_before
    );
}

/// The audit read is tenancy-scoped: operator A's audit query returns ZERO of
/// operator B's rows, no matter how it is filtered, while still returning A's own.
#[tokio::test]
async fn the_audit_read_is_isolated_per_operator() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let router = control_router(control_state(db.pool.clone()));

    let a = provision_tenant(&router, &db.pool, "a").await;
    let b = provision_tenant(&router, &db.pool, "b").await;

    // A's unfiltered audit read returns rows, none of which target B's resources.
    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/audit",
        Some(a.operator_token.as_str()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().expect("audit rows").clone();
    assert!(!rows.is_empty(), "A produced audit rows of its own");

    let b_account = b.account_id.to_string();
    let b_wallet = b.wallet_id.to_string();
    let b_key = b.key_id.to_string();
    let b_operator = b.operator_id.to_string();
    for row in &rows {
        let target_id = row["target_id"].as_str().unwrap_or_default();
        let actor_id = row["actor_id"].as_str().unwrap_or_default();
        assert_ne!(
            target_id, b_account,
            "A must not see a row targeting B's account"
        );
        assert_ne!(
            target_id, b_wallet,
            "A must not see a row targeting B's wallet"
        );
        assert_ne!(target_id, b_key, "A must not see a row targeting B's key");
        assert_ne!(actor_id, b_operator, "A must not see a row B authored");
    }

    // A filtered read (by an action B definitely produced) still returns zero B
    // rows: the operator scope is applied before the filter, so B's account.create
    // is invisible even when A asks for that exact verb.
    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/audit?action=account.create",
        Some(a.operator_token.as_str()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().expect("audit rows");
    // Exactly one account.create: A's own account, never B's.
    assert_eq!(rows.len(), 1, "A sees only its own account.create row");
    assert_eq!(
        rows[0]["target_id"].as_str().unwrap(),
        a.account_id.to_string()
    );

    // Symmetry: B's audit read sees B's account.create, not A's.
    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/audit?action=account.create",
        Some(b.operator_token.as_str()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().expect("audit rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["target_id"].as_str().unwrap(),
        b.account_id.to_string()
    );
}

/// The positive path is intact: operator A acts freely on ALL of A's own
/// resources, exactly the routes the breach matrix denies it on B's.
#[tokio::test]
async fn an_operator_acts_freely_on_its_own_resources() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let router = control_router(control_state(db.pool.clone()));

    let a = provision_tenant(&router, &db.pool, "a").await;
    // A second operator exists alongside, to prove A's success is not because it
    // is the only tenant.
    let _b = provision_tenant(&router, &db.pool, "b").await;
    let at = Some(a.operator_token.as_str());

    // usage
    let (status, body) = call(
        &router,
        "GET",
        &format!("/control/v1/accounts/{}/usage", a.account_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["balance_usd_micros"], 7_000_000);

    // list keys
    let (status, body) = call(
        &router,
        "GET",
        &format!("/control/v1/accounts/{}/keys", a.account_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);

    // relabel + revoke the key
    let (status, body) = call(
        &router,
        "POST",
        &format!(
            "/control/v1/accounts/{}/keys/{}/relabel",
            a.account_id, a.key_id
        ),
        at,
        Some(json!({ "label": "renamed" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["relabeled"], true);

    let (status, body) = call(
        &router,
        "POST",
        &format!(
            "/control/v1/accounts/{}/keys/{}/revoke",
            a.account_id, a.key_id
        ),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], true);

    // adjust the balance
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/ledger-adjustment", a.account_id),
        at,
        Some(json!({ "amount_usd_micros": 1_000_000, "reason": "top up" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(balance_of(&db.pool, a.account_id).await, 8_000_000);

    // drain + reactivate the wallet
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{}/drain", a.wallet_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], true);
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{}/reactivate", a.wallet_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], true);
    assert_eq!(wallet_status_of(&db.pool, a.wallet_id).await, "active");

    // disable + enable the account
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/disable", a.account_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(account_status_of(&db.pool, a.account_id).await, "disabled");
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/enable", a.account_id),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(account_status_of(&db.pool, a.account_id).await, "active");
}

/// The data plane is unaffected by the control-plane tenancy fix: an access token
/// operator A mints for A's own account still authenticates the data plane as that
/// account. (The data plane's account binding comes from the resolved credential,
/// never a path id, so it was always sound; this pins that it stays so.)
#[tokio::test]
async fn an_access_token_still_authenticates_the_data_plane_after_the_fix() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let router = control_router(control_state(db.pool.clone()));
    let data = data_router(db.pool.clone());

    let a = provision_tenant(&router, &db.pool, "a").await;

    // A mints an account token for A's account carrying account:read.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{}/token", a.account_id),
        Some(a.operator_token.as_str()),
        Some(json!({ "scopes": ["account:read"] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let token = body["token"].as_str().unwrap().to_string();

    // The token reads the balance on the data plane (the dogfood bridge).
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/account/balance")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = data
        .clone()
        .oneshot(req)
        .await
        .expect("data router responds");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an account token minted by A for A's account still works on the data plane"
    );
}
