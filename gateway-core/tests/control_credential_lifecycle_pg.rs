//! Credential rotation and revocation against a real Postgres.
//!
//! These suites exercise the operator-credential kill switch end to end: a
//! revoked access token stops resolving, revoking a root credential cascades
//! through the mint lineage to every token minted beneath it (on the control
//! AND data planes), root rotation mints a working successor while killing the
//! old chain, a targeted token revoke kills exactly one token, the last live
//! root refuses revocation, and every mutation lands in the admin audit log.
//! Assertions are end-state: HTTP status, response JSON, resolved principals,
//! and DB rows, never log strings.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Duration;
use gateway_core::api::control::credential::{
    mint_root_credential, resolve_access_token, resolve_root_credential,
};
use gateway_core::api::control::{ControlConfig, ControlState};
use gateway_core::api::{control_router, ApiConfig, AppState};
use gateway_core::testsupport::TestDb;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

/// The operator-chosen secret prefix the control plane mints credentials under.
const PREFIX: &str = "ctl_";

/// Build the control router state. No wallet / funding keys: this suite touches
/// only the credential lifecycle.
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
            ..Default::default()
        },
        Vec::new(),
        Vec::new(),
    )
}

/// Build the data-plane router, so the suite can prove a revocation kills the
/// token on BOTH planes (the cascade lives in the shared token resolve).
fn data_router(pool: sqlx::PgPool) -> axum::Router {
    gateway_core::api::router(AppState::new(
        pool,
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..Default::default()
        },
    ))
}

/// Provision an operator row and return its id.
async fn seed_operator(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'op')")
        .bind(id)
        .execute(pool)
        .await
        .expect("insert operator");
    id
}

/// Provision an account anchor + satellite under an operator and return its id.
async fn seed_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(id)
        .execute(pool)
        .await
        .expect("insert account anchor");
    sqlx::query("INSERT INTO cw_core.account_detail (account_id, operator_id) VALUES ($1, $2)")
        .bind(id)
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert account detail");
    id
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

/// Mint an operator token through the route (real lineage: `minted_by` is the
/// presented root's credential id), returning `(token_id, secret)`.
async fn mint_operator_token_via_route(router: &axum::Router, root_secret: &str) -> (Uuid, String) {
    let (status, body) = call(
        router,
        "POST",
        "/control/v1/operator/token",
        Some(root_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "operator token mint: {body}");
    (
        body["token_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .expect("token_id"),
        body["token"].as_str().expect("token secret").to_string(),
    )
}

/// Mint an account token through the route (real lineage: `minted_by` is the
/// bearer's credential row id), returning `(token_id, secret)`.
async fn mint_account_token_via_route(
    router: &axum::Router,
    bearer: &str,
    account_id: Uuid,
    scopes: &[&str],
) -> (Uuid, String) {
    let (status, body) = call(
        router,
        "POST",
        &format!("/control/v1/accounts/{account_id}/token"),
        Some(bearer),
        Some(json!({ "scopes": scopes })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "account token mint: {body}");
    (
        body["token_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .expect("token_id"),
        body["token"].as_str().expect("token secret").to_string(),
    )
}

/// Count the audit rows carrying an action + target id, the end-state proof a
/// mutation was journalled.
async fn audit_rows(pool: &sqlx::PgPool, action: &str, target_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.admin_audit WHERE action = $1 AND target_id = $2",
    )
    .bind(action)
    .bind(target_id)
    .fetch_one(pool)
    .await
    .expect("count audit rows")
}

/// The HTTP status a data-plane GET with a Bearer secret returns.
async fn data_get_status(router: &axum::Router, path: &str, bearer: &str) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    router
        .clone()
        .oneshot(req)
        .await
        .expect("data router responds")
        .status()
}

#[tokio::test]
async fn a_targeted_token_revoke_kills_one_token_without_affecting_siblings() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));

    let (victim_id, victim_secret) = mint_operator_token_via_route(&router, &root.secret).await;
    let (_, sibling_secret) = mint_operator_token_via_route(&router, &root.secret).await;

    // Another tenant cannot revoke the token: an oracle-safe 404.
    let other_op = seed_operator(&db.pool).await;
    let other_root = mint_root_credential(&db.pool, other_op, PREFIX, None)
        .await
        .expect("mint other root");
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/tokens/{victim_id}/revoke"),
        Some(&other_root.secret),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a cross-tenant token id must be indistinguishable from a missing one"
    );

    // The sibling operator token (operator authority, not the root) performs the
    // targeted revoke.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/tokens/{victim_id}/revoke"),
        Some(&sibling_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], json!(true));

    // The revoked token stops resolving and stops authorizing routes; the
    // sibling and the root are untouched.
    assert!(resolve_access_token(&db.pool, &victim_secret)
        .await
        .expect("resolve victim")
        .is_none());
    let (status, _) = call(
        &router,
        "GET",
        "/control/v1/accounts",
        Some(&victim_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &router,
        "GET",
        "/control/v1/accounts",
        Some(&sibling_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the sibling token must survive");
    assert!(resolve_root_credential(&db.pool, &root.secret)
        .await
        .expect("resolve root")
        .is_some());

    // A second revoke is an idempotent no-op.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/tokens/{victim_id}/revoke"),
        Some(&sibling_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], json!(false));

    // Exactly one audit row: the idempotent replay journals nothing.
    assert_eq!(
        audit_rows(&db.pool, "access_token.revoke", &victim_id.to_string()).await,
        1
    );

    // The roster lists both tokens, the victim with its revocation stamped.
    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/tokens",
        Some(&sibling_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().expect("token roster");
    let victim_row = rows
        .iter()
        .find(|r| r["token_id"] == json!(victim_id))
        .expect("the revoked token stays listed");
    assert!(
        victim_row["revoked_at"].is_string(),
        "the roster shows the revocation timestamp"
    );
}

#[tokio::test]
async fn revoking_an_operator_token_cascades_to_the_account_tokens_it_minted() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));

    let (op_tok_id, op_tok_secret) = mint_operator_token_via_route(&router, &root.secret).await;
    let (_, child_secret) =
        mint_account_token_via_route(&router, &op_tok_secret, account, &["account:read"]).await;
    // A sibling account token minted under the ROOT directly, to prove the
    // cascade follows lineage, not the account.
    let (_, root_child_secret) =
        mint_account_token_via_route(&router, &root.secret, account, &["account:read"]).await;

    let data = data_router(db.pool.clone());
    assert_eq!(
        data_get_status(&data, "/api/v1/account/balance", &child_secret).await,
        StatusCode::OK,
        "the child account token works on the data plane before the revoke"
    );

    // Revoke the operator token; its child dies with it, the root's child lives.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/tokens/{op_tok_id}/revoke"),
        Some(&root.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], json!(true));

    assert!(
        resolve_access_token(&db.pool, &child_secret)
            .await
            .expect("resolve child")
            .is_none(),
        "an account token minted under a revoked operator token must die with it"
    );
    assert_eq!(
        data_get_status(&data, "/api/v1/account/balance", &child_secret).await,
        StatusCode::UNAUTHORIZED,
        "the cascade applies on the data plane too"
    );
    assert!(
        resolve_access_token(&db.pool, &root_child_secret)
            .await
            .expect("resolve root child")
            .is_some(),
        "a token minted under a different (live) credential survives"
    );
}

#[tokio::test]
async fn revoking_a_root_credential_cascades_to_its_whole_chain() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let compromised = mint_root_credential(&db.pool, op, PREFIX, Some("leaked"))
        .await
        .expect("mint compromised root");
    let surviving = mint_root_credential(&db.pool, op, PREFIX, Some("vault"))
        .await
        .expect("mint surviving root");
    let router = control_router(control_state(db.pool.clone()));

    // The chain under the compromised root: root -> operator token -> account
    // token, all minted through the routes so the lineage is real.
    let (_, op_tok_secret) = mint_operator_token_via_route(&router, &compromised.secret).await;
    let (_, acct_tok_secret) =
        mint_account_token_via_route(&router, &op_tok_secret, account, &["account:read"]).await;
    // A parallel chain under the surviving root.
    let (_, safe_op_tok_secret) = mint_operator_token_via_route(&router, &surviving.secret).await;

    // Revoke the compromised root, presenting the surviving one.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/credentials/{}/revoke", compromised.id),
        Some(&surviving.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");
    assert_eq!(body["revoked"], json!(true));

    // The whole chain is dead: root, operator token, account token — on both
    // planes.
    assert!(resolve_root_credential(&db.pool, &compromised.secret)
        .await
        .expect("resolve compromised")
        .is_none());
    assert!(resolve_access_token(&db.pool, &op_tok_secret)
        .await
        .expect("resolve op token")
        .is_none());
    assert!(resolve_access_token(&db.pool, &acct_tok_secret)
        .await
        .expect("resolve account token")
        .is_none());
    let data = data_router(db.pool.clone());
    assert_eq!(
        data_get_status(&data, "/api/v1/account/balance", &acct_tok_secret).await,
        StatusCode::UNAUTHORIZED,
        "the account token minted beneath the revoked root must die on the data plane"
    );

    // The surviving root's chain is untouched.
    let (status, _) = call(
        &router,
        "GET",
        "/control/v1/accounts",
        Some(&safe_op_tok_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The mutation is journalled once, and the credential roster shows the
    // revocation.
    assert_eq!(
        audit_rows(&db.pool, "credential.revoke", &compromised.id.to_string()).await,
        1
    );
    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/credentials",
        Some(&surviving.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["data"].as_array().expect("credential roster");
    let revoked_row = rows
        .iter()
        .find(|r| r["credential_id"] == json!(compromised.id))
        .expect("the revoked credential stays listed");
    assert!(revoked_row["revoked_at"].is_string());
}

#[tokio::test]
async fn rotate_root_mints_a_working_successor_and_kills_the_old_chain() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let old_root = mint_root_credential(&db.pool, op, PREFIX, Some("v1"))
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));

    let (_, op_tok_secret) = mint_operator_token_via_route(&router, &old_root.secret).await;
    let (_, acct_tok_secret) =
        mint_account_token_via_route(&router, &op_tok_secret, account, &["account:read"]).await;

    // Rotate: the presented (only) root is replaced atomically — the
    // last-live-root guard does not apply because the successor is minted in
    // the same transaction.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/operator/root/rotate",
        Some(&old_root.secret),
        Some(json!({ "label": "v2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "rotate: {body}");
    assert_eq!(body["revoked_credential_id"], json!(old_root.id));
    assert_eq!(body["operator_id"], json!(op));
    let new_secret = body["secret"].as_str().expect("successor secret");
    let new_id = body["credential_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("successor id");
    assert_ne!(new_id, old_root.id);

    // The successor authenticates and mints; the old root and everything under
    // it are dead, including on the data plane.
    let resolved = resolve_root_credential(&db.pool, new_secret)
        .await
        .expect("resolve successor")
        .expect("successor is live");
    assert_eq!(resolved.operator_id, op);
    let (_, fresh_op_tok) = mint_operator_token_via_route(&router, new_secret).await;
    let (status, _) = call(
        &router,
        "GET",
        "/control/v1/accounts",
        Some(&fresh_op_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert!(resolve_root_credential(&db.pool, &old_root.secret)
        .await
        .expect("resolve old root")
        .is_none());
    assert!(resolve_access_token(&db.pool, &op_tok_secret)
        .await
        .expect("resolve old op token")
        .is_none());
    let data = data_router(db.pool.clone());
    assert_eq!(
        data_get_status(&data, "/api/v1/account/balance", &acct_tok_secret).await,
        StatusCode::UNAUTHORIZED,
        "the account token under the rotated-away root must die"
    );

    // The old root cannot rotate again: it is no longer a live credential at
    // all, so the guard rejects it as unknown.
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/operator/root/rotate",
        Some(&old_root.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The rotation is journalled against the successor, naming the revoked
    // predecessor.
    assert_eq!(
        audit_rows(&db.pool, "root_credential.rotate", &new_id.to_string()).await,
        1
    );
    let prev: Value = sqlx::query_scalar(
        "SELECT prev_state FROM cw_core.admin_audit \
         WHERE action = 'root_credential.rotate' AND target_id = $1",
    )
    .bind(new_id.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("rotation audit prev_state");
    assert_eq!(prev["revoked_credential_id"], json!(old_root.id));

    // The audit body never carries the successor's secret.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.admin_audit \
         WHERE prev_state::text LIKE '%' || $1 || '%' \
            OR new_state::text LIKE '%' || $1 || '%'",
    )
    .bind(new_secret)
    .fetch_one(&db.pool)
    .await
    .expect("scan audit for the secret");
    assert_eq!(leaked, 0, "a minted secret must never reach the audit log");
}

#[tokio::test]
async fn revoking_the_last_live_root_is_refused() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));

    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/credentials/{}/revoke", root.id),
        Some(&root.secret),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "revoking the only live root must be refused: {body}"
    );
    assert_eq!(body["code"], json!("last-live-root"));

    // The root is untouched and still authenticates.
    assert!(resolve_root_credential(&db.pool, &root.secret)
        .await
        .expect("resolve root")
        .is_some());
    // Nothing was journalled: the refusal mutated nothing.
    assert_eq!(
        audit_rows(&db.pool, "credential.revoke", &root.id.to_string()).await,
        0
    );
}

#[tokio::test]
async fn revoking_a_mid_chain_token_kills_its_self_service_descendants() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));

    // A four-link chain, every link minted through the routes: root -> operator
    // token -> account token A -> account token B (self-service: A mints B for
    // its own account, with scopes it already holds).
    let (_, op_tok_secret) = mint_operator_token_via_route(&router, &root.secret).await;
    let (parent_id, parent_secret) =
        mint_account_token_via_route(&router, &op_tok_secret, account, &["account:read"]).await;
    let (_, child_secret) =
        mint_account_token_via_route(&router, &parent_secret, account, &["account:read"]).await;
    assert!(resolve_access_token(&db.pool, &child_secret)
        .await
        .expect("resolve child")
        .is_some());

    // Revoke the MIDDLE link. The walk follows the chain from the leaf, so the
    // child dies even though its own row and every other ancestor stay live.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/tokens/{parent_id}/revoke"),
        Some(&op_tok_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "parent revoke: {body}");
    assert!(
        resolve_access_token(&db.pool, &child_secret)
            .await
            .expect("resolve child after parent revoke")
            .is_none(),
        "a self-service token minted under a revoked token must die with it"
    );
    // The links ABOVE the revoked one are untouched.
    assert!(resolve_access_token(&db.pool, &op_tok_secret)
        .await
        .expect("resolve operator token")
        .is_some());
}

/// The mint lineage anchor is validated at mint time: `minted_by` must
/// reference a live credential of the SAME operator. A phantom id, another
/// operator's credential, and an already-revoked minter are all refused — a
/// token minted under any of them would dead-end the lineage walk and sit
/// outside every kill switch short of its own targeted revoke. The legitimate
/// path (the authenticated root's own row id) still mints.
#[tokio::test]
async fn minting_requires_a_live_same_operator_lineage_anchor() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");

    let other_op = seed_operator(&db.pool).await;
    let other_root = mint_root_credential(&db.pool, other_op, PREFIX, None)
        .await
        .expect("mint other operator's root");

    use gateway_core::api::control::credential::mint_operator_token;

    // A fabricated minted_by that references no credential row at all.
    assert!(
        mint_operator_token(&db.pool, op, PREFIX, Duration::hours(1), Uuid::now_v7())
            .await
            .is_err(),
        "a phantom minted_by must be refused"
    );

    // Another operator's live root: real, but not THIS operator's.
    assert!(
        mint_operator_token(&db.pool, op, PREFIX, Duration::hours(1), other_root.id)
            .await
            .is_err(),
        "a cross-operator minted_by must be refused"
    );

    // The authenticated root's own row id still mints, and the token resolves.
    let minted = mint_operator_token(&db.pool, op, PREFIX, Duration::hours(1), root.id)
        .await
        .expect("the legitimate lineage anchor mints");
    let resolved = resolve_access_token(&db.pool, &minted.minted.secret)
        .await
        .expect("resolve")
        .expect("the minted token resolves");
    assert_eq!(resolved.operator_id, op);

    // A revoked minter no longer anchors a mint: revoke the second root of the
    // other operator scenario is covered above; here revoke this operator's
    // root after minting a sibling root so the last-live-root guard permits it.
    let successor = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint successor root");
    sqlx::query("UPDATE cw_core.control_credential SET revoked_at = now() WHERE id = $1")
        .bind(root.id)
        .execute(&db.pool)
        .await
        .expect("revoke the old root");
    assert!(
        mint_operator_token(&db.pool, op, PREFIX, Duration::hours(1), root.id)
            .await
            .is_err(),
        "a revoked minted_by must be refused"
    );
    assert!(
        mint_operator_token(&db.pool, op, PREFIX, Duration::hours(1), successor.id)
            .await
            .is_ok(),
        "the live successor still anchors a mint"
    );
}
