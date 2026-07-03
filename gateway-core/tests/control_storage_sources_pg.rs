//! The storage funding-source control plane: register, list, drain, grant,
//! revoke, and the funding aggregate, with cross-operator tenancy isolation.
//!
//! These suites drive the REAL control router with two operators A and B and the
//! verified Arweave funding keys the instance holds, and pin the contract the
//! source triad must satisfy:
//!
//!   - Register writes a row only for an address the instance physically holds a
//!     signing key for; an unheld address is a 422, not a half-registered source.
//!   - Register auto-issues the resolved draw grant, so a fresh source is usable
//!     with no second call; a second `service`-default registration converges on
//!     the backend's existing live service grant (the single-source rule) rather
//!     than minting a second service default.
//!   - The owner acts freely on its own source (list, drain, grant, revoke,
//!     funding aggregate); operator A cannot see, drain, grant on, or revoke a
//!     grant on operator B's source, and a cross-tenant access is a 404, never a
//!     403 (no existence oracle).
//!   - The list and aggregate project the cached winc balance; a source with no
//!     reconcile reads as unknown/stale.
//!   - Every mutation appends an audit row under the acting operator.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use ans104::{Ans104Signer, ArweaveJwkSigner};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Duration;
use gateway_core::api::control::credential::mint_root_credential;
use gateway_core::api::control::{ControlConfig, ControlFundingKey, ControlState};
use gateway_core::api::{control_router, DefaultStorageScope, DefaultWalletScope};
use gateway_core::storage::{insert_credit_entry, CreditEntry, CreditKind};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::keyring::arweave_address;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

/// The operator-chosen secret prefix the control plane mints credentials under.
const PREFIX: &str = "ctl_";

/// A real 4096-bit Arweave RSA JWK fixture, shared with the ANS-104 vector suite.
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// The Arweave address the fixture JWK derives to, through the same path the
/// keyring uses, so the test never pins a magic string. This is the one address
/// the control state declares the instance holds a signing key for.
fn held_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

/// Build the control router state declaring the instance holds the fixture
/// Arweave signing key, so the source-register route can confirm possession.
fn control_state(pool: sqlx::PgPool) -> ControlState {
    ControlState::with_keys(
        pool,
        ControlConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            secret_prefix: PREFIX.to_string(),
            operator_token_ttl: Duration::hours(1),
            account_token_ttl: Duration::hours(1),
            adjustment_cap_usd_micros: 10_000_000_000,
            admin_ui_enabled: false,
            default_wallet_scope: DefaultWalletScope::Service,
            default_storage_scope: DefaultStorageScope::Service,
            ..Default::default()
        },
        Vec::new(),
        vec![ControlFundingKey {
            address: held_arweave_address(),
            label: "storage".to_string(),
        }],
    )
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

/// One operator and its provisioning handles.
struct Tenant {
    operator_id: Uuid,
    operator_token: String,
    /// The operator root credential secret. Source registration binds a
    /// shared-keyring key to an owner, so it is a root-only (instance-admin)
    /// action; the operator token authorizes everything else (list, drain, grant,
    /// revoke).
    root_secret: String,
}

/// Provision an operator with a root credential and an operator token.
async fn provision_tenant(router: &axum::Router, pool: &sqlx::PgPool, label: &str) -> Tenant {
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

    Tenant {
        operator_id,
        operator_token,
        root_secret: root.secret,
    }
}

/// Register a turbo source at the held address under `token`, returning the body.
async fn register_source(router: &axum::Router, token: &str, body: Value) -> (StatusCode, Value) {
    call(
        router,
        "POST",
        "/control/v1/storage/sources",
        Some(token),
        Some(body),
    )
    .await
}

/// Read a source's status straight from the row.
async fn source_status_of(pool: &sqlx::PgPool, source_id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM cw_core.storage_funding_source WHERE id = $1")
        .bind(source_id)
        .fetch_one(pool)
        .await
        .expect("source status")
}

/// Count the live grants on a source.
async fn live_grant_count(pool: &sqlx::PgPool, source_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_grant \
         WHERE funding_source_id = $1 AND revoked_at IS NULL",
    )
    .bind(source_id)
    .fetch_one(pool)
    .await
    .expect("grant count")
}

/// Whether a specific grant is live.
async fn grant_is_live(pool: &sqlx::PgPool, grant_id: Uuid) -> bool {
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM cw_core.storage_grant WHERE id = $1")
            .bind(grant_id)
            .fetch_one(pool)
            .await
            .expect("grant revoked_at");
    revoked_at.is_none()
}

/// Count the live service grants for a backend (the single-source invariant).
async fn live_service_grants(pool: &sqlx::PgPool, backend: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_grant \
         WHERE backend = $1 AND scope_kind = 'service' AND revoked_at IS NULL",
    )
    .bind(backend)
    .fetch_one(pool)
    .await
    .expect("service grant count")
}

/// The happy path: register auto-issues the default service grant, the source is
/// listed with its cached winc, drain transitions it, and a grant + revoke cycle
/// works — all under the owner's token, all audited.
#[tokio::test]
async fn an_operator_runs_the_full_source_lifecycle() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let at = Some(a.operator_token.as_str());
    let address = held_arweave_address();

    // Register the source under root (key custody is an instance-admin action). The
    // default storage scope is `service`, so a grant is auto-issued and the source is
    // immediately drawable.
    let (status, body) = register_source(
        &router,
        &a.root_secret,
        json!({ "label": "primary", "backend": "turbo", "address": address }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["created"], true);
    let source_id = Uuid::parse_str(body["source_id"].as_str().unwrap()).unwrap();
    let grant_id = Uuid::parse_str(body["grant_id"].as_str().unwrap()).unwrap();

    // The auto-issued grant is live, and it is the backend's one service grant.
    assert!(grant_is_live(&db.pool, grant_id).await);
    assert_eq!(live_service_grants(&db.pool, "turbo").await, 1);
    assert_eq!(live_grant_count(&db.pool, source_id).await, 1);

    // A source with no reconcile yet reads as stale (unknown balance): the first
    // list call sees no materialized credit row, so winc_balance is null.
    let (status, body) = call(&router, "GET", "/control/v1/storage/sources", at, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);
    assert!(body["data"][0]["winc_balance"].is_null());
    assert_eq!(body["data"][0]["stale"], true, "no reconcile yet is stale");

    // Seed a charge (which materializes the row) then a reconcile (which stamps
    // last_reconciled_at), so the row reads as fresh with the net believed balance.
    insert_credit_entry(
        &db.pool,
        &CreditEntry {
            funding_source_id: source_id,
            kind: CreditKind::Charge,
            winc_delta: Decimal::new(-1_000_000, 0),
            r#ref: Some("attempt-1".to_string()),
        },
    )
    .await
    .expect("seed charge");
    insert_credit_entry(
        &db.pool,
        &CreditEntry {
            funding_source_id: source_id,
            kind: CreditKind::Reconcile,
            winc_delta: Decimal::new(6_000_000, 0),
            r#ref: Some("tick-1".to_string()),
        },
    )
    .await
    .expect("seed reconcile");

    let (status, body) = call(&router, "GET", "/control/v1/storage/sources", at, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);
    let row = &body["data"][0];
    assert_eq!(row["source_id"].as_str().unwrap(), source_id.to_string());
    assert_eq!(row["backend"], "turbo");
    assert_eq!(row["arweave_address"], address);
    // -1_000_000 (charge) + 6_000_000 (reconcile) = 5_000_000 believed winc.
    assert_eq!(row["winc_balance"], "5000000");
    assert_eq!(row["stale"], false);

    // The funding aggregate rolls it up.
    let (status, body) = call(&router, "GET", "/control/v1/storage/funding", at, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["source_count"], 1);
    assert_eq!(body["total_winc_balance"], "5000000");
    assert_eq!(body["stale_source_count"], 0);

    // Drain transitions active -> draining.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/drain"),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], true);
    assert_eq!(body["status"], "draining");
    assert_eq!(source_status_of(&db.pool, source_id).await, "draining");
    // Idempotent: a second drain reports the real status, no change.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/drain"),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], false);
    assert_eq!(body["status"], "draining");

    // The auto-issued service grant can be revoked, then a fresh operator grant
    // issued. Revoke mirrors the wallet convention: POST .../revoke.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/grants/{grant_id}/revoke"),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], true);
    assert!(!grant_is_live(&db.pool, grant_id).await);
    // Idempotent revoke: a second revoke reports revoked=false.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/grants/{grant_id}/revoke"),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], false);

    // Issue an operator-scope grant explicitly.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/grants"),
        at,
        Some(json!({ "scope": "operator" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["issued"], true);

    // The drain + register + grant + revoke each appended an audit row under A.
    let (status, body) = call(&router, "GET", "/control/v1/audit", at, None).await;
    assert_eq!(status, StatusCode::OK);
    let actions: Vec<String> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["action"].as_str().unwrap_or_default().to_string())
        .collect();
    for expected in [
        "storage.register",
        "storage.drain",
        "storage.revoke",
        "storage.grant",
    ] {
        assert!(
            actions.iter().any(|a| a == expected),
            "expected an audit row for {expected}, saw {actions:?}"
        );
    }
}

/// A register naming an address the instance does NOT hold a signing key for is a
/// 422, and no source row is written: the upload path can never resolve an
/// unsignable source.
#[tokio::test]
async fn a_register_for_an_unheld_address_is_refused_and_writes_no_row() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;

    let (status, _) = register_source(
        &router,
        &a.root_secret,
        json!({ "label": "x", "backend": "turbo", "address": "an-address-no-key-backs" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_funding_source")
        .fetch_one(&db.pool)
        .await
        .expect("count");
    assert_eq!(count, 0, "an unheld address must not leave a source row");
}

/// A second `service`-default registration of the SAME address by the same owner
/// renames in place and converges on the one live service grant: there is never a
/// second live service grant for one backend (the single-source rule).
#[tokio::test]
async fn a_re_register_converges_on_the_single_service_grant() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let address = held_arweave_address();

    let (status, body) = register_source(
        &router,
        &a.root_secret,
        json!({ "label": "first", "backend": "turbo", "address": address }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["created"], true);
    let first_grant = body["grant_id"].as_str().unwrap().to_string();

    // Re-register the same address (a rename): inserted=false, and the grant
    // converges on the existing service grant rather than minting a second one.
    let (status, body) = register_source(
        &router,
        &a.root_secret,
        json!({ "label": "renamed", "backend": "turbo", "address": address }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["created"], false);
    assert_eq!(body["grant_id"].as_str().unwrap(), first_grant);
    assert_eq!(live_service_grants(&db.pool, "turbo").await, 1);

    // The label was renamed in place (one source row, the updated label).
    let label: String =
        sqlx::query_scalar("SELECT label FROM cw_core.storage_funding_source WHERE backend = $1")
            .bind("turbo")
            .fetch_one(&db.pool)
            .await
            .expect("label");
    assert_eq!(label, "renamed");
}

/// The full cross-operator breach matrix: operator A's token cannot register over,
/// list, drain, grant on, or revoke a grant on operator B's source. A cross-tenant
/// access is a 404 (never a 403), and nothing on B's source changes.
#[tokio::test]
async fn an_operator_cannot_touch_another_operators_source() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let b = provision_tenant(&router, &db.pool, "b").await;
    let address = held_arweave_address();

    // B registers the only source under B's root. It owns the address; A cannot
    // re-register it even with A's own root credential.
    let (status, body) = register_source(
        &router,
        &b.root_secret,
        json!({ "label": "b-source", "backend": "turbo", "address": address }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let source_id = Uuid::parse_str(body["source_id"].as_str().unwrap()).unwrap();
    let b_grant = Uuid::parse_str(body["grant_id"].as_str().unwrap()).unwrap();

    let status_before = source_status_of(&db.pool, source_id).await;
    let grant_count_before = live_grant_count(&db.pool, source_id).await;
    let at = Some(a.operator_token.as_str());

    // A re-registering B's address (even under A's root) is a 409: the address backs
    // B's credit pool and is never silently aliased into A's tenancy. Root custody
    // gates WHO may register a key; it does not let one operator's root claim a key
    // already owned by another operator.
    let (status, _) = register_source(
        &router,
        &a.root_secret,
        json!({ "label": "steal", "backend": "turbo", "address": address }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "A's root cannot re-register B's address"
    );

    // A's list does not include B's source (operator-scoped).
    let (status, body) = call(&router, "GET", "/control/v1/storage/sources", at, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 0, "A's roster excludes B's source");

    // A's funding aggregate counts zero of B's sources.
    let (status, body) = call(&router, "GET", "/control/v1/storage/funding", at, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["source_count"], 0);

    // A drain / grant / revoke on B's source is a 404, never a 403.
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/drain"),
        at,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "A cannot drain B's source");

    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/grants"),
        at,
        Some(json!({ "scope": "operator" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "A cannot grant on B's source"
    );

    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/grants/{b_grant}/revoke"),
        at,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "A cannot revoke a grant on B's source"
    );

    // Nothing on B's source changed.
    assert_eq!(source_status_of(&db.pool, source_id).await, status_before);
    assert_eq!(
        live_grant_count(&db.pool, source_id).await,
        grant_count_before
    );
    assert!(
        grant_is_live(&db.pool, b_grant).await,
        "B's grant is untouched"
    );
}

/// An account-scope grant requires an account the registrar owns: a foreign or
/// absent account is a 404, and a missing account_id is a 422.
#[tokio::test]
async fn an_account_grant_requires_an_owned_account() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let address = held_arweave_address();

    let (status, body) = register_source(
        &router,
        &a.root_secret,
        json!({ "label": "s", "backend": "turbo", "address": address }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let source_id = body["source_id"].as_str().unwrap().to_string();
    let at = Some(a.operator_token.as_str());

    // account scope with no account_id is a 422.
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/grants"),
        at,
        Some(json!({ "scope": "account" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // account scope naming an account A does not own is a 404.
    let foreign_account = Uuid::now_v7();
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/grants"),
        at,
        Some(json!({ "scope": "account", "account_id": foreign_account })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // An account A DOES own can be granted account scope.
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(&db.pool)
        .await
        .expect("insert account");
    sqlx::query(
        "INSERT INTO cw_core.account_detail (account_id, operator_id, status) \
         VALUES ($1, $2, 'active')",
    )
    .bind(account_id)
    .bind(a.operator_id)
    .execute(&db.pool)
    .await
    .expect("insert account_detail");

    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/sources/{source_id}/grants"),
        at,
        Some(json!({ "scope": "account", "account_id": account_id })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["issued"], true);
}

/// Registration is a root-only action: an ordinary operator token is refused with a
/// 403 (it shares custody of the keyring key but may not claim ownership), no
/// credential is a 401, and an unknown backend under root is a 422.
#[tokio::test]
async fn register_requires_root_and_validates_the_backend() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let address = held_arweave_address();

    // An operator token (not root) is refused: it shares custody of the shared
    // keyring but may not claim a funding key as its own.
    let (status, _) = register_source(
        &router,
        &a.operator_token,
        json!({ "label": "x", "backend": "turbo", "address": address }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an operator token may not register a funding source"
    );

    // No source row was written by the refused operator-token registration.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_funding_source")
        .fetch_one(&db.pool)
        .await
        .expect("count");
    assert_eq!(count, 0, "a refused registration writes no source row");

    // Root with an unknown backend is a 422 (the auth gate passed, the validation
    // gate caught it).
    let (status, _) = register_source(
        &router,
        &a.root_secret,
        json!({ "label": "x", "backend": "ipfs", "address": address }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "unknown backend");

    // No credential at all is a 401.
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/storage/sources",
        None,
        Some(json!({ "label": "x", "backend": "turbo", "address": address })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Root with a valid backend at the held address succeeds (the happy path under
    // the corrected auth posture).
    let (status, body) = register_source(
        &router,
        &a.root_secret,
        json!({ "label": "ok", "backend": "turbo", "address": address }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "root may register, body = {body}"
    );
}
