//! Control-plane behaviour against a real Postgres.
//!
//! These suites exercise the control surface end-to-end: the schema applies,
//! credential and access-token lookup resolve the right typed principal, the
//! data-plane guard rejects an operator token (the privilege-confusion fix), and
//! the control router drives the operator runbook (bootstrap an operator and root,
//! mint an operator token, create an account, mint a key, register a wallet,
//! adjust the balance, read usage and audit). Assertions are end-state: resolved
//! principals, HTTP status, response JSON, and the resulting DB rows, never log
//! strings.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Duration;
use gateway_core::api::control::audit::{self, ActorKind, AuditQuery};
use gateway_core::api::control::credential::{
    mint_account_token, mint_operator_token, mint_root_credential, resolve_access_token,
    resolve_root_credential, revoke_credential, AccountTokenMint, CredentialRevocation,
    MintedToken,
};
use gateway_core::api::control::ledger_adjust::{
    apply_adjustment, register_manual_adjustment_kind, MANUAL_ADJUSTMENT_KIND,
};
use gateway_core::api::control::principal::{resolve_principal, AuthOutcome, Principal};
use gateway_core::api::control::{ControlConfig, ControlState};
use gateway_core::api::state::{DynPricingSource, PricingInputs, PricingSource};
use gateway_core::api::{control_router, ApiConfig, AppState};
use gateway_core::ledger::quote::{FxSnapshot, MarginResolution};
use gateway_core::testsupport::TestDb;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

/// A real preprod enterprise bech32 address derived from a seed, for the wallet
/// registration tests (the register route now parses and network-checks the
/// address). Distinct seeds yield distinct global identities.
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

/// A test pricing seam so the data-plane quote route can price a publish (an
/// account that is NOT disabled reaches pricing; a disabled account is rejected
/// before this is ever consulted). Mirrors the data-plane suite's fixture.
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

/// Build the data-plane router with the test pricing seam wired, so the quote
/// route can price (rather than report its pricing dependency unavailable).
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

/// Issue a data-plane api key for an account with the given scopes, returning the
/// bearer secret to present. Mirrors the data-plane suite's key seeding.
async fn issue_key(pool: &sqlx::PgPool, account_id: Uuid, scopes: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let secret = format!("{PREFIX}{}", Uuid::now_v7().simple());
    let full = Sha256::digest(secret.as_bytes());
    let lookup = full[..8].to_vec();
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    sqlx::query(
        "INSERT INTO cw_core.api_key \
           (id, account_id, prefix, key_lookup, key_hash_sha256, scopes, rate_limit_per_min) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(Uuid::now_v7())
    .bind(account_id)
    .bind(PREFIX)
    .bind(lookup)
    .bind(full.to_vec())
    .bind(&scopes)
    .bind(600)
    .execute(pool)
    .await
    .expect("insert api key");
    secret
}

/// Drive a GET against the data-plane router with a Bearer secret, returning the
/// HTTP status.
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

/// Drive a JSON POST against the data-plane router with a Bearer secret, returning
/// the HTTP status.
async fn data_post_status(
    router: &axum::Router,
    path: &str,
    bearer: &str,
    body: Value,
) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    router
        .clone()
        .oneshot(req)
        .await
        .expect("data router responds")
        .status()
}

/// The operator-chosen secret prefix the control plane mints credentials under.
const PREFIX: &str = "ctl_";

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

/// The wallet seeds this suite registers through the control route. The
/// wallet-register route now refuses an address no instance signer backs, so the
/// test instance declares it holds a signing key for exactly these.
const HELD_WALLET_SEEDS: &[u8] = &[0x11, 0x22];

/// Build the control router state with a permissive config, declaring the instance
/// holds a signing key for every wallet address the suite registers through the
/// route.
fn control_state(pool: sqlx::PgPool) -> ControlState {
    let wallet_keys = HELD_WALLET_SEEDS
        .iter()
        .map(|&seed| gateway_core::api::ControlWalletKey {
            address: preprod_address(seed),
            label: format!("held-{seed:#04x}"),
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

/// Reconcile the replenish queue policy, the boot invariant the wallet-register
/// route relies on. Registration enqueues a targeted replenish in the same
/// transaction as the wallet row and its grant; the enqueue resolves its
/// attempt/backoff defaults from the policy row, so the policy must exist before a
/// register can run. The supervised runtime reconciles it at startup in production;
/// a control-plane test that registers a wallet without booting the runtime seeds it
/// here.
async fn seed_replenish_policy(pool: &sqlx::PgPool) {
    gateway_core::runtime::policy::reconcile(
        pool,
        &gateway_core::wallet::replenish::replenish_policy(),
    )
    .await
    .expect("reconcile replenish policy");
}

/// An audit query scoped to one operator with a page size, leaving every filter
/// unset. The audit read is always tenancy-scoped, so a test must name the
/// operator whose rows it expects to see.
fn audit_query(operator_id: Uuid, limit: i64) -> AuditQuery {
    AuditQuery {
        operator_id,
        actor_kind: None,
        action: None,
        target_type: None,
        target_id: None,
        limit,
    }
}

/// Mint an operator token under a freshly minted root. The engine validates the
/// mint-lineage anchor (`minted_by` must reference a live credential of the
/// operator), so a test cannot hand it a fabricated id; every token needs a
/// real root behind it.
async fn mint_operator_token_with_root(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    ttl: Duration,
) -> MintedToken {
    let root = mint_root_credential(pool, operator_id, PREFIX, None)
        .await
        .expect("mint lineage root");
    mint_operator_token(pool, operator_id, PREFIX, ttl, root.id)
        .await
        .expect("mint operator token")
}

/// Mint an account-scoped token for an account the operator owns, asserting the
/// mint succeeded (the account belongs to the operator). The cross-tenant
/// `AccountNotFound` path is exercised by the tenancy suite, not here.
async fn mint_owned_account_token(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
    scopes: &[String],
) -> MintedToken {
    // The mint-lineage anchor must reference a live credential of the operator
    // (the engine refuses a dangling id), so mint a real root to anchor on.
    let root = mint_root_credential(pool, operator_id, PREFIX, None)
        .await
        .expect("mint lineage root");
    match mint_account_token(
        pool,
        operator_id,
        account_id,
        scopes,
        None,
        PREFIX,
        Duration::hours(1),
        root.id,
    )
    .await
    .expect("mint account token")
    {
        AccountTokenMint::Minted(m) => m,
        AccountTokenMint::AccountNotFound => panic!("account is owned by the operator"),
    }
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

#[tokio::test]
async fn migration_creates_the_control_plane_tables() {
    let db = TestDb::fresh().await.expect("fresh db");
    // The three control tables exist after the migrator runs.
    for table in ["control_credential", "access_token", "admin_audit"] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
             WHERE table_schema = 'cw_core' AND table_name = $1)",
        )
        .bind(table)
        .fetch_one(&db.pool)
        .await
        .expect("table existence query");
        assert!(
            exists,
            "cw_core.{table} must exist on a freshly migrated database"
        );
    }
}

#[tokio::test]
async fn admin_audit_is_append_only() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let id = audit::record(
        &db.pool,
        &audit::AuditEntry {
            actor_kind: ActorKind::Operator,
            actor_id: Some(op),
            action: "test.action".into(),
            target_type: "account".into(),
            target_id: Uuid::now_v7().to_string(),
            prev_state: None,
            new_state: Some(json!({ "k": "v" })),
            request_id: None,
        },
    )
    .await
    .expect("record audit row");

    // UPDATE and DELETE are refused by the append-only triggers.
    let upd = sqlx::query("UPDATE cw_core.admin_audit SET action = 'x' WHERE id = $1")
        .bind(id)
        .execute(&db.pool)
        .await;
    assert!(upd.is_err(), "UPDATE on the audit journal must be refused");
    let del = sqlx::query("DELETE FROM cw_core.admin_audit WHERE id = $1")
        .bind(id)
        .execute(&db.pool)
        .await;
    assert!(del.is_err(), "DELETE on the audit journal must be refused");
}

#[tokio::test]
async fn root_credential_resolves_and_revokes() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let minted = mint_root_credential(&db.pool, op, PREFIX, Some("vault"))
        .await
        .expect("mint root");
    // A second live root, so revoking the first does not trip the
    // last-live-root guard (an operator may never lose its only root).
    let successor = mint_root_credential(&db.pool, op, PREFIX, Some("vault-2"))
        .await
        .expect("mint successor root");

    // The minted secret resolves to the operator.
    let resolved = resolve_root_credential(&db.pool, &minted.secret)
        .await
        .expect("resolve root")
        .expect("a live root credential");
    assert_eq!(resolved.operator_id, op);
    assert_eq!(resolved.credential_id, minted.id);

    // A wrong secret resolves to nothing.
    assert!(resolve_root_credential(&db.pool, "ctl_wrong")
        .await
        .expect("resolve")
        .is_none());

    // After revocation the same secret no longer resolves.
    assert_eq!(
        revoke_credential(&db.pool, op, minted.id)
            .await
            .expect("revoke"),
        CredentialRevocation::Revoked
    );
    assert!(resolve_root_credential(&db.pool, &minted.secret)
        .await
        .expect("resolve")
        .is_none());
    // Revoking again is an idempotent no-op.
    assert_eq!(
        revoke_credential(&db.pool, op, minted.id)
            .await
            .expect("revoke again"),
        CredentialRevocation::AlreadyRevoked
    );

    // The successor is now the operator's only live root: revoking it is
    // refused, and it keeps resolving.
    assert_eq!(
        revoke_credential(&db.pool, op, successor.id)
            .await
            .expect("revoke last root"),
        CredentialRevocation::LastLiveRoot
    );
    assert!(resolve_root_credential(&db.pool, &successor.secret)
        .await
        .expect("resolve successor")
        .is_some());

    // A credential of another operator is an oracle-safe NotFound.
    let other_op = seed_operator(&db.pool).await;
    assert_eq!(
        revoke_credential(&db.pool, other_op, successor.id)
            .await
            .expect("cross-tenant revoke"),
        CredentialRevocation::NotFound
    );
}

#[tokio::test]
async fn principal_resolution_types_each_credential_class() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;

    // An operator token resolves to OperatorToken.
    let op_tok = mint_operator_token_with_root(&db.pool, op, Duration::hours(1)).await;
    match resolve_principal(&db.pool, &op_tok.minted.secret)
        .await
        .expect("resolve operator token")
    {
        AuthOutcome::Resolved(Principal::OperatorToken { operator_id, .. }) => {
            assert_eq!(operator_id, op);
        }
        other => panic!("expected an operator token principal, got {other:?}"),
    }

    // An account token resolves to AccountToken bound to the account.
    let acct_tok = mint_owned_account_token(&db.pool, op, account, &["poe:read".to_string()]).await;
    match resolve_principal(&db.pool, &acct_tok.minted.secret)
        .await
        .expect("resolve account token")
    {
        AuthOutcome::Resolved(Principal::AccountToken {
            account_id, scopes, ..
        }) => {
            assert_eq!(account_id, account);
            assert_eq!(scopes, vec!["poe:read".to_string()]);
        }
        other => panic!("expected an account token principal, got {other:?}"),
    }

    // The root credential resolves to OperatorRoot.
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    match resolve_principal(&db.pool, &root.secret)
        .await
        .expect("resolve root")
    {
        AuthOutcome::Resolved(Principal::OperatorRoot { operator_id, .. }) => {
            assert_eq!(operator_id, op);
        }
        other => panic!("expected an operator root principal, got {other:?}"),
    }

    // An unknown secret resolves to Unknown.
    assert_eq!(
        resolve_principal(&db.pool, "ctl_nope")
            .await
            .expect("resolve unknown"),
        AuthOutcome::Unknown
    );
}

#[tokio::test]
async fn an_expired_access_token_does_not_resolve() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    // Mint with a 1-second TTL, then move the row's expiry into the past.
    let tok = mint_operator_token_with_root(&db.pool, op, Duration::seconds(1)).await;
    sqlx::query(
        "UPDATE cw_core.access_token SET expires_at = now() - interval '1 hour' WHERE id = $1",
    )
    .bind(tok.minted.id)
    .execute(&db.pool)
    .await
    .expect("backdate expiry");
    assert!(resolve_access_token(&db.pool, &tok.minted.secret)
        .await
        .expect("resolve")
        .is_none());
}

#[tokio::test]
async fn the_data_plane_guard_rejects_an_operator_token() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    // The publish path's queue policy is needed by the data router build path; the
    // balance route does not need it, so the read route is enough to exercise the
    // guard. Build the data-plane router.
    let data = gateway_core::api::router(AppState::new(
        db.pool.clone(),
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..Default::default()
        },
    ));

    // An operator token presented to a data-plane authed route is rejected (403),
    // never resolved as an account.
    let op_tok = mint_operator_token_with_root(&db.pool, op, Duration::hours(1)).await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/account/balance")
        .header("authorization", format!("Bearer {}", op_tok.minted.secret))
        .body(Body::empty())
        .unwrap();
    let resp = data
        .clone()
        .oneshot(req)
        .await
        .expect("data router responds");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "an operator token must be rejected on the data plane"
    );
}

#[tokio::test]
async fn operator_runbook_drives_the_control_surface() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_replenish_policy(&db.pool).await;
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register manual adjustment kind");
    let op = seed_operator(&db.pool).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));

    // The root mints an operator token.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let operator_token = body["token"].as_str().expect("operator token").to_string();

    // An operator token may NOT mint another operator token (root only).
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "only the root may mint an operator token"
    );

    // Create an account.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/accounts",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let account_id = body["account_id"].as_str().expect("account id").to_string();

    // The account appears in the roster.
    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/accounts",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);

    // Mint an api key for the account; the secret is shown once.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account_id}/keys"),
        Some(&operator_token),
        Some(json!({ "scopes": ["poe:read", "poe:create"], "rate_limit_per_min": 120 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["secret"].as_str().unwrap().starts_with(PREFIX));
    let key_id = body["key_id"].as_str().unwrap().to_string();

    // The key listing carries metadata but never a secret.
    let (status, body) = call(
        &router,
        "GET",
        &format!("/control/v1/accounts/{account_id}/keys"),
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);
    assert!(
        body["data"][0].get("secret").is_none(),
        "a key listing must never include a secret"
    );

    // Revoke the key.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account_id}/keys/{key_id}/revoke"),
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], true);

    // Fund the account via a ledger adjustment.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account_id}/ledger-adjustment"),
        Some(&operator_token),
        Some(json!({ "amount_usd_micros": 5_000_000, "reason": "initial funding" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);

    // Usage reflects the funded balance.
    let (status, body) = call(
        &router,
        "GET",
        &format!("/control/v1/accounts/{account_id}/usage"),
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["balance_usd_micros"], 5_000_000);
    assert_eq!(
        body["status"], "active",
        "usage reports the account's live lifecycle status so a credit caller can refuse a disabled account"
    );

    // Register a wallet (a root-only action: it binds a shared-keyring key to an
    // owner), then drain and reactivate it under the operator token.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        Some(&root.secret),
        Some(json!({ "label": "primary", "address": preprod_address(0x11), "network": "preprod" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["created"], true);
    let wallet_id = body["wallet_id"].as_str().unwrap().to_string();

    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{wallet_id}/drain"),
        Some(&operator_token),
        Some(json!({ "reason": "rotation" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], true);
    assert_eq!(body["status"], "draining");

    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{wallet_id}/reactivate"),
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], true);
    assert_eq!(body["status"], "active");

    // The wallet roster carries the UTxO statistics (zero for a fresh wallet).
    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/wallets",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"][0]["available_utxos"], 0);
    assert_eq!(body["data"][0]["canonical_utxos"], 0);

    // The audit log records every mutation; filter to the account-create verb.
    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/audit?action=account.create",
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);
    assert_eq!(body["data"][0]["target_id"], account_id);

    // The full audit log holds the whole runbook's mutations, scoped to the
    // operator that drove the runbook.
    let rows = audit::list(&db.pool, &audit_query(op, 100))
        .await
        .expect("list audit");
    let actions: Vec<&str> = rows.iter().map(|r| r.action.as_str()).collect();
    for expected in [
        "operator_token.mint",
        "account.create",
        "key.create",
        "key.revoke",
        "ledger.adjust",
        "wallet.register",
        "wallet.drain",
        "wallet.reactivate",
    ] {
        assert!(
            actions.contains(&expected),
            "the audit log must record {expected}, got {actions:?}"
        );
    }
}

#[tokio::test]
async fn an_account_token_cannot_reach_operator_routes() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let router = control_router(control_state(db.pool.clone()));

    let acct_tok = mint_owned_account_token(&db.pool, op, account, &["poe:read".to_string()]).await;

    // An account token may not create an account (operator-only).
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/accounts",
        Some(&acct_tok.minted.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // But it MAY mint a token for its own account (self-service), as long as the
    // token stays within the scopes it already holds.
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/token"),
        Some(&acct_tok.minted.secret),
        Some(json!({ "scopes": ["poe:read"] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // And it may NOT act on a different account.
    let other = seed_account(&db.pool, op).await;
    let (status, _) = call(
        &router,
        "GET",
        &format!("/control/v1/accounts/{other}/usage"),
        Some(&acct_tok.minted.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_self_service_credential_cannot_escalate_its_scopes() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let router = control_router(control_state(db.pool.clone()));

    // A read-only account token: the kind an operator hands out for a dashboard.
    let read_only =
        mint_owned_account_token(&db.pool, op, account, &["account:read".to_string()]).await;
    let secret = &read_only.minted.secret;

    // It may not mint itself a stronger token (escalating into poe:create).
    let (status, problem) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/token"),
        Some(secret),
        Some(json!({ "scopes": ["account:read", "poe:create"] })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], "insufficient-scope");

    // Nor a stronger persistent api key.
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/keys"),
        Some(secret),
        Some(json!({ "scopes": ["poe:create"] })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Nor inflate its per-minute budget beyond its own.
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/keys"),
        Some(secret),
        Some(json!({ "scopes": ["account:read"], "rate_limit_per_min": 1_000_000 })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A same-or-narrower grant is fine: a key carrying exactly what it holds.
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/keys"),
        Some(secret),
        Some(json!({ "scopes": ["account:read"] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // And an operator (acting on the same account) is unconstrained: it may
    // grant the broad scope the account token could not.
    let op_token = mint_operator_token_with_root(&db.pool, op, Duration::hours(1)).await;
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/keys"),
        Some(&op_token.minted.secret),
        Some(json!({ "scopes": ["poe:create"] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn a_ledger_adjustment_over_the_cap_is_rejected() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    // A tiny cap so a normal adjustment exceeds it.
    let state = ControlState::new(
        db.pool.clone(),
        ControlConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            secret_prefix: PREFIX.to_string(),
            operator_token_ttl: Duration::hours(1),
            account_token_ttl: Duration::hours(1),
            adjustment_cap_usd_micros: 1_000,
            admin_ui_enabled: false,
            default_wallet_scope: gateway_core::api::DefaultWalletScope::Service,
            default_storage_scope: gateway_core::api::DefaultStorageScope::Service,
            ..Default::default()
        },
    );
    let router = control_router(state);
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/ledger-adjustment"),
        Some(&token),
        Some(json!({ "amount_usd_micros": 1_000_000, "reason": "too big" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // No ledger row was written.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("count");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn an_overdrawing_adjustment_is_a_validation_error_not_an_internal_error() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    // A debit on a zero-balance account would overdraw; the kind is non-
    // overdrawing, so the trigger refuses it. That is operator input, surfaced as
    // a 422 (validation), never a 500 (internal).
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/ledger-adjustment"),
        Some(&token),
        Some(json!({ "amount_usd_micros": -500_000, "reason": "debit below zero" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("count");
    assert_eq!(count, 0, "the refused adjustment wrote no ledger row");
}

#[tokio::test]
async fn a_redelivered_adjustment_with_the_same_ref_is_an_idempotent_no_op() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    let path = format!("/control/v1/accounts/{account}/ledger-adjustment");
    let payload = json!({
        "amount_usd_micros": 5_000_000,
        "reason": "welcome grant",
        "ref": "welcome-grant:fixed-event-id",
    });

    // First delivery applies the credit.
    let (status, first) = call(&router, "POST", &path, Some(&token), Some(payload.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["applied"], json!(true));

    // A redelivery carrying the SAME ref collapses to a no-op: the (kind, ref)
    // idempotency index rejects the second insert, so the balance moves once.
    let (status, second) = call(&router, "POST", &path, Some(&token), Some(payload)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        second["applied"],
        json!(false),
        "the redelivered same-ref adjustment must not apply a second time"
    );

    // The supplied ref is stored under the operator-scoped prefix (the engine
    // namespaces an operator-supplied idempotency ref by the owning operator so
    // operators cannot collide on a shared key). The pinned-ref idempotency is what
    // this asserts: exactly one row exists for this operator's `welcome-grant:...`.
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1 AND ref = $2",
    )
    .bind(account)
    .bind(format!("op:{op}:welcome-grant:fixed-event-id"))
    .fetch_one(&db.pool)
    .await
    .expect("count");
    assert_eq!(count, 1, "exactly one ledger row exists for the pinned ref");

    let balance: i64 =
        sqlx::query_scalar("SELECT balance_micros FROM cw_core.balance WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("balance");
    assert_eq!(balance, 5_000_000, "the credit landed exactly once");
}

/// A positive credit to a disabled account is refused atomically (no ledger row,
/// balance untouched, code account-not-active); a debit to that same disabled
/// account STILL applies (a closing account must be settleable); and once the
/// account is re-enabled the credit applies. This is the authoritative,
/// server-side, in-transaction guard — not a caller preflight.
#[tokio::test]
async fn a_credit_to_a_disabled_account_is_refused_atomically_but_a_debit_still_applies() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();
    let adjust_path = format!("/control/v1/accounts/{account}/ledger-adjustment");

    // Fund the account while active so a later debit has a balance to move.
    let (status, _) = call(
        &router,
        "POST",
        &adjust_path,
        Some(&token),
        Some(json!({ "amount_usd_micros": 5_000_000, "reason": "initial funding" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Disable the account.
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/disable"),
        Some(&token),
        Some(json!({ "reason": "closing" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let ledger_count = |pool: sqlx::PgPool, acct: Uuid| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1",
        )
        .bind(acct)
        .fetch_one(&pool)
        .await
        .expect("count")
    };
    let read_balance = |pool: sqlx::PgPool, acct: Uuid| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT balance_micros FROM cw_core.balance WHERE account_id = $1",
        )
        .bind(acct)
        .fetch_one(&pool)
        .await
        .expect("balance")
    };

    let before_count = ledger_count(db.pool.clone(), account).await;

    // A positive credit to the disabled account is refused atomically: 409,
    // account-not-active, no new ledger row, balance unchanged.
    let (status, refusal) = call(
        &router,
        "POST",
        &adjust_path,
        Some(&token),
        Some(json!({ "amount_usd_micros": 2_000_000, "reason": "credit to closing" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refusal["code"], "account-not-active");
    assert_eq!(
        ledger_count(db.pool.clone(), account).await,
        before_count,
        "the refused credit wrote no ledger row"
    );
    assert_eq!(
        read_balance(db.pool.clone(), account).await,
        5_000_000,
        "the refused credit moved no balance"
    );

    // A DEBIT to the SAME disabled account still applies — a closing account must
    // remain settleable.
    let (status, debit) = call(
        &router,
        "POST",
        &adjust_path,
        Some(&token),
        Some(json!({ "amount_usd_micros": -1_000_000, "reason": "settle on close" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(debit["applied"], json!(true));
    assert_eq!(
        read_balance(db.pool.clone(), account).await,
        4_000_000,
        "the debit applied to the disabled account"
    );

    // Re-enable, then the credit applies normally.
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/enable"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, credit) = call(
        &router,
        "POST",
        &adjust_path,
        Some(&token),
        Some(json!({ "amount_usd_micros": 2_000_000, "reason": "credit after re-enable" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(credit["applied"], json!(true));
    assert_eq!(
        read_balance(db.pool.clone(), account).await,
        6_000_000,
        "the credit applied once the account was active again"
    );
}

/// Regression: an empty (or whitespace-only) `ref` is a 422, not a real idempotency
/// key, and distinct refs keep distinct adjustments independent.
///
/// The optional `ref` was once passed verbatim, so `{"ref": ""}` became a real
/// `(kind, ref)` key even though the wire contract requires a non-empty ref: two
/// unrelated empty-ref adjustments then collided on that one key and the second
/// silently no-op'd. This validates an empty ref is rejected with a 422 and writes
/// no row, while two adjustments carrying distinct refs each land independently.
#[tokio::test]
async fn an_empty_ref_is_rejected_and_distinct_refs_are_independent() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    let path = format!("/control/v1/accounts/{account}/ledger-adjustment");

    // An empty ref is a 422 before any write, never a real idempotency key.
    let (status, problem) = call(
        &router,
        "POST",
        &path,
        Some(&token),
        Some(json!({
            "amount_usd_micros": 5_000_000,
            "reason": "empty ref grant",
            "ref": "",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an empty ref is a 422, not a real idempotency key"
    );
    assert_eq!(problem["code"], json!("validation-failed"));

    // A whitespace-only ref is rejected on the same grounds.
    let (status, _) = call(
        &router,
        "POST",
        &path,
        Some(&token),
        Some(json!({
            "amount_usd_micros": 5_000_000,
            "reason": "whitespace ref grant",
            "ref": "   ",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Neither rejected request wrote a ledger row.
    let after_rejects: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("count after rejects");
    assert_eq!(
        after_rejects, 0,
        "a rejected empty/whitespace ref writes no row"
    );

    // Two adjustments carrying DISTINCT refs are independent: both land.
    for r in ["grant:event-a", "grant:event-b"] {
        let (status, applied) = call(
            &router,
            "POST",
            &path,
            Some(&token),
            Some(json!({
                "amount_usd_micros": 1_000_000,
                "reason": "distinct ref grant",
                "ref": r,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            applied["applied"],
            json!(true),
            "ref {r} applies independently"
        );
    }

    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("count distinct-ref rows");
    assert_eq!(
        rows, 2,
        "two distinct refs produce two independent ledger rows"
    );

    let balance: i64 =
        sqlx::query_scalar("SELECT balance_micros FROM cw_core.balance WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("balance");
    assert_eq!(balance, 2_000_000, "both distinct-ref credits landed");
}

#[tokio::test]
async fn a_margin_override_can_be_set_and_cleared_by_the_owning_operator() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    let path = format!("/control/v1/accounts/{account}/margin");

    // Set an override.
    let (status, set) = call(
        &router,
        "PUT",
        &path,
        Some(&token),
        Some(json!({ "margin_pct": 0.4 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(set["margin_source"], json!("account-override"));

    let stored: Option<rust_decimal::Decimal> = sqlx::query_scalar(
        "SELECT margin_pct FROM cw_core.account_margin_override WHERE account_id = $1",
    )
    .bind(account)
    .fetch_optional(&db.pool)
    .await
    .expect("read override");
    assert_eq!(stored, Some(rust_decimal::Decimal::new(40, 2)));

    // Clear it.
    let (status, cleared) = call(&router, "DELETE", &path, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cleared["cleared"], json!(true));
    assert_eq!(cleared["margin_source"], json!("operator-default"));

    let after: Option<rust_decimal::Decimal> = sqlx::query_scalar(
        "SELECT margin_pct FROM cw_core.account_margin_override WHERE account_id = $1",
    )
    .bind(account)
    .fetch_optional(&db.pool)
    .await
    .expect("read override after clear");
    assert_eq!(after, None, "the override row was removed");

    // A second clear is an idempotent no-op.
    let (status, again) = call(&router, "DELETE", &path, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["cleared"], json!(false));
}

#[tokio::test]
async fn a_margin_override_for_an_unowned_account_is_an_oracle_safe_404() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    // An account under a DIFFERENT operator: the override target is foreign.
    let other_op = seed_operator(&db.pool).await;
    let foreign_account = seed_account(&db.pool, other_op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    let path = format!("/control/v1/accounts/{foreign_account}/margin");
    let (status, _) = call(
        &router,
        "PUT",
        &path,
        Some(&token),
        Some(json!({ "margin_pct": 0.4 })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a foreign account is a 404");

    // No row was written for the foreign account.
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.account_margin_override WHERE account_id = $1",
    )
    .bind(foreign_account)
    .fetch_one(&db.pool)
    .await
    .expect("count");
    assert_eq!(count, 0);
}

/// Regression: a non-negative `margin_pct` outside the column's `numeric(6,4)` bound
/// or scale must be rejected with a 422 before the write, not surface as an opaque
/// Postgres-overflow 500.
///
/// The handler once rejected only a negative `margin_pct`; a value `>= 100` (the
/// column leaves two integer digits) or one with more than four fractional digits
/// reached Postgres and failed as a numeric-overflow 500. This validates both
/// out-of-range shapes return the same 422 validation shape the other control routes
/// use and that no override row is written.
#[tokio::test]
async fn an_out_of_range_margin_override_is_a_422_and_writes_no_row() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    let path = format!("/control/v1/accounts/{account}/margin");

    // Too large for the column (>= 100, only two integer digits available).
    let (status, problem) = call(
        &router,
        "PUT",
        &path,
        Some(&token),
        Some(json!({ "margin_pct": 100 })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a too-large margin is a 422, not a 500"
    );
    assert_eq!(problem["code"], json!("validation-failed"));

    // Too precise for the column (more than four fractional digits would round).
    let (status, problem) = call(
        &router,
        "PUT",
        &path,
        Some(&token),
        Some(json!({ "margin_pct": 0.12345 })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a too-precise margin is a 422, not a 500"
    );
    assert_eq!(problem["code"], json!("validation-failed"));

    // Neither rejected request wrote an override row.
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.account_margin_override WHERE account_id = $1",
    )
    .bind(account)
    .fetch_one(&db.pool)
    .await
    .expect("count");
    assert_eq!(count, 0, "a rejected margin override writes no row");
}

#[tokio::test]
async fn a_minted_account_token_honours_a_custom_rate_limit_budget() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;

    // Mint an account token with an explicit per-minute budget.
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint lineage root");
    let minted = match mint_account_token(
        &db.pool,
        op,
        account,
        &[],
        Some(7),
        PREFIX,
        Duration::hours(1),
        root.id,
    )
    .await
    .expect("mint")
    {
        AccountTokenMint::Minted(m) => m,
        AccountTokenMint::AccountNotFound => panic!("account is owned"),
    };

    // The custom budget is persisted on the row.
    let stored: Option<i32> =
        sqlx::query_scalar("SELECT rate_limit_per_min FROM cw_core.access_token WHERE id = $1")
            .bind(minted.minted.id)
            .fetch_one(&db.pool)
            .await
            .expect("read budget");
    assert_eq!(stored, Some(7));

    // The resolved principal carries the budget, so the data-plane limiter meters
    // against it rather than the fixed fallback.
    let resolved = match resolve_principal(&db.pool, &minted.minted.secret)
        .await
        .expect("resolve")
    {
        AuthOutcome::Resolved(p) => p,
        AuthOutcome::Unknown => panic!("the minted token must resolve"),
    };
    match resolved {
        Principal::AccountToken {
            rate_limit_per_min, ..
        } => assert_eq!(rate_limit_per_min, Some(7)),
        other => panic!("expected an account token, got {other:?}"),
    }
}

#[tokio::test]
async fn a_minted_account_token_without_a_budget_falls_back_to_the_default() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;

    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint lineage root");
    let minted = match mint_account_token(
        &db.pool,
        op,
        account,
        &[],
        None,
        PREFIX,
        Duration::hours(1),
        root.id,
    )
    .await
    .expect("mint")
    {
        AccountTokenMint::Minted(m) => m,
        AccountTokenMint::AccountNotFound => panic!("account is owned"),
    };

    let stored: Option<i32> =
        sqlx::query_scalar("SELECT rate_limit_per_min FROM cw_core.access_token WHERE id = $1")
            .bind(minted.minted.id)
            .fetch_one(&db.pool)
            .await
            .expect("read budget");
    assert_eq!(stored, None, "no custom budget is stored");

    let resolved = match resolve_principal(&db.pool, &minted.minted.secret)
        .await
        .expect("resolve")
    {
        AuthOutcome::Resolved(p) => p,
        AuthOutcome::Unknown => panic!("the minted token must resolve"),
    };
    match resolved {
        Principal::AccountToken {
            rate_limit_per_min, ..
        } => assert_eq!(
            rate_limit_per_min, None,
            "no budget -> fixed fallback applies"
        ),
        other => panic!("expected an account token, got {other:?}"),
    }
}

#[tokio::test]
async fn a_custom_token_budget_out_of_range_is_rejected() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;

    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint lineage root");
    for bad in [0, -1, 1_000_001] {
        let err = mint_account_token(
            &db.pool,
            op,
            account,
            &[],
            Some(bad),
            PREFIX,
            Duration::hours(1),
            root.id,
        )
        .await
        .expect_err("an out-of-range budget must be rejected");
        assert!(matches!(err, gateway_core::Error::Config(_)), "got {err:?}");
    }
}

#[tokio::test]
async fn the_control_openapi_document_is_served_unauthenticated() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));

    // No Bearer credential: the document is public, like the data-plane one.
    let (status, body) = call(&router, "GET", "/control/v1/openapi.json", None, None).await;
    assert_eq!(status, StatusCode::OK);

    // The served body is byte-for-byte the embedded asset (compared as parsed
    // JSON so formatting is irrelevant to the assertion).
    let embedded: Value = serde_json::from_str(gateway_core::api::OPENAPI_CONTROL_JSON)
        .expect("the embedded control spec parses");
    assert_eq!(
        body, embedded,
        "the route serves the embedded control OpenAPI document verbatim"
    );
}

#[tokio::test]
async fn minting_a_token_with_unregistered_scopes_is_rejected_with_the_catalogue() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    // Scopes that exist in no registry row are refused at mint, and the problem
    // detail names the registered catalogue so the caller can self-correct.
    let (status, problem) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/token"),
        Some(&token),
        Some(json!({ "scopes": ["quote", "publish"] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["code"], json!("validation-failed"));
    let detail = problem["detail"].as_str().expect("a problem detail");
    assert!(detail.contains("not registered"), "got detail {detail:?}");
    assert!(detail.contains("poe:create"), "got detail {detail:?}");
    assert!(detail.contains("account:read"), "got detail {detail:?}");

    // No token row was written for the rejected mint.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.access_token WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("count tokens");
    assert_eq!(count, 0, "the rejected mint wrote no token row");
}

#[tokio::test]
async fn creating_a_key_with_an_unregistered_scope_is_rejected_with_the_catalogue() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    let (status, problem) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/keys"),
        Some(&token),
        Some(json!({ "scopes": ["quote"], "rate_limit_per_min": 120 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["code"], json!("validation-failed"));
    let detail = problem["detail"].as_str().expect("a problem detail");
    assert!(detail.contains("not registered"), "got detail {detail:?}");
    assert!(detail.contains("poe:create"), "got detail {detail:?}");
    assert!(detail.contains("account:read"), "got detail {detail:?}");

    // No key row was written for the rejected create.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.api_key WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("count keys");
    assert_eq!(count, 0, "the rejected create wrote no key row");
}

#[tokio::test]
async fn a_key_minted_without_a_budget_meters_against_the_default() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let control = control_router(control_state(db.pool.clone()));
    let data = data_router(db.pool.clone());
    let (_, body) = call(
        &control,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    // No rate_limit_per_min in the body: the key carries no custom budget.
    let (status, body) = call(
        &control,
        "POST",
        &format!("/control/v1/accounts/{account}/keys"),
        Some(&token),
        Some(json!({ "scopes": ["poe:read"], "label": "x" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(
        body["rate_limit_per_min"].is_null(),
        "the response reports no custom budget, got {body:?}"
    );
    let key_id = body["key_id"].as_str().expect("key id").to_string();
    let secret = body["secret"].as_str().expect("secret").to_string();

    // The column is NULL, not some invented default value.
    let stored: Option<i32> =
        sqlx::query_scalar("SELECT rate_limit_per_min FROM cw_core.api_key WHERE id = $1")
            .bind(Uuid::parse_str(&key_id).unwrap())
            .fetch_one(&db.pool)
            .await
            .expect("read budget");
    assert_eq!(stored, None, "no custom budget is stored");

    // The default-budget path works end-to-end: the secret authorizes a
    // data-plane read metered against the fixed default budget.
    assert_eq!(
        data_get_status(&data, "/api/v1/records", &secret).await,
        StatusCode::OK,
        "a key without a custom budget authorizes the data plane"
    );
}

#[tokio::test]
async fn a_revoked_root_cannot_mint_an_operator_token() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));

    // While live, the root mints an operator token.
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // After revocation the same root resolves to no live credential, so the route
    // sees an unknown bearer and answers 401 (not 403): a revoked secret is
    // indistinguishable from an unknown one at the boundary. A second live root
    // satisfies the last-live-root guard.
    mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint successor root");
    assert_eq!(
        revoke_credential(&db.pool, op, root.id)
            .await
            .expect("revoke root"),
        CredentialRevocation::Revoked
    );
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked root credential must be rejected with 401"
    );
}

#[tokio::test]
async fn an_expired_operator_token_is_rejected_at_the_route() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let tok = mint_operator_token_with_root(&db.pool, op, Duration::seconds(1)).await;
    // Backdate the token so it has lapsed.
    sqlx::query(
        "UPDATE cw_core.access_token SET expires_at = now() - interval '1 hour' WHERE id = $1",
    )
    .bind(tok.minted.id)
    .execute(&db.pool)
    .await
    .expect("backdate expiry");
    let router = control_router(control_state(db.pool.clone()));

    // An expired token resolves to nothing, so an operator route answers 401.
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/accounts",
        Some(&tok.minted.secret),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an expired operator token must be rejected with 401"
    );
}

#[tokio::test]
async fn disabling_an_account_blocks_the_data_plane_and_enabling_restores_it() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");

    let control = control_router(control_state(db.pool.clone()));
    let data = data_router(db.pool.clone());

    // The account holds a data-plane key that may quote and read its balance.
    let key = issue_key(&db.pool, account, &["poe:create", "account:read"]).await;
    let quote_body = json!({ "record_bytes": 64, "recipient_count": 0, "file_bytes_total": 0 });

    // While active, both data-plane routes succeed.
    assert_eq!(
        data_post_status(&data, "/api/v1/poe/quote", &key, quote_body.clone()).await,
        StatusCode::OK,
        "an active account may quote"
    );
    assert_eq!(
        data_get_status(&data, "/api/v1/account/balance", &key).await,
        StatusCode::OK,
        "an active account may read its balance"
    );

    // The operator disables the account through the control plane.
    let (_, body) = call(
        &control,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let operator_token = body["token"].as_str().unwrap().to_string();
    let (status, body) = call(
        &control,
        "POST",
        &format!("/control/v1/accounts/{account}/disable"),
        Some(&operator_token),
        Some(json!({ "reason": "abuse review" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], true);

    // The usage read now reports the disabled status, the signal a credit caller
    // (e.g. the welcome-grant / top-up jobs) reads to refuse crediting an account
    // that is on its way out rather than orphaning money on a dead account.
    let (status, body) = call(
        &control,
        "GET",
        &format!("/control/v1/accounts/{account}/usage"),
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "disabled");

    // Now the SAME key is blocked on the data plane: the credential is still live,
    // but the account is administratively disabled, so quote and balance are
    // forbidden. The gate sits on the account, not the key.
    assert_eq!(
        data_post_status(&data, "/api/v1/poe/quote", &key, quote_body.clone()).await,
        StatusCode::FORBIDDEN,
        "a disabled account may not quote"
    );
    assert_eq!(
        data_get_status(&data, "/api/v1/account/balance", &key).await,
        StatusCode::FORBIDDEN,
        "a disabled account may not read its balance"
    );

    // Re-enabling restores data-plane access with no key churn.
    let (status, body) = call(
        &control,
        "POST",
        &format!("/control/v1/accounts/{account}/enable"),
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], true);
    assert_eq!(
        data_post_status(&data, "/api/v1/poe/quote", &key, quote_body).await,
        StatusCode::OK,
        "re-enabling restores data-plane access"
    );
}

#[tokio::test]
async fn an_account_token_authenticates_the_data_plane() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_replenish_policy(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let data = data_router(db.pool.clone());

    // An account-scoped token carrying account:read reads the balance on the data
    // plane (the dogfood bridge: it authenticates AS the account, like a key).
    let tok = mint_owned_account_token(&db.pool, op, account, &["account:read".to_string()]).await;
    assert_eq!(
        data_get_status(&data, "/api/v1/account/balance", &tok.minted.secret).await,
        StatusCode::OK,
        "an account token may read its account's balance on the data plane"
    );

    // The same token carries poe:create too once minted with it.
    let create_tok =
        mint_owned_account_token(&db.pool, op, account, &["poe:create".to_string()]).await;
    assert_eq!(
        data_post_status(
            &data,
            "/api/v1/poe/quote",
            &create_tok.minted.secret,
            json!({ "record_bytes": 64, "recipient_count": 0, "file_bytes_total": 0 }),
        )
        .await,
        StatusCode::OK,
        "an account token carrying poe:create may quote on the data plane"
    );

    // But it is rejected on an operator control route (account-bound, not operator).
    let control = control_router(control_state(db.pool.clone()));
    let (status, _) = call(
        &control,
        "GET",
        "/control/v1/wallets",
        Some(&tok.minted.secret),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an account token may not reach an operator control route"
    );
}

#[tokio::test]
async fn revoking_a_key_kills_data_plane_auth_immediately() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let control = control_router(control_state(db.pool.clone()));
    let data = data_router(db.pool.clone());

    let operator_token = {
        let root = mint_root_credential(&db.pool, op, PREFIX, None)
            .await
            .expect("mint root");
        let (_, body) = call(
            &control,
            "POST",
            "/control/v1/operator/token",
            Some(&root.secret),
            None,
        )
        .await;
        body["token"].as_str().unwrap().to_string()
    };

    // Mint a key with account:read through the control plane; the secret is shown
    // once and authenticates the data plane.
    let (status, body) = call(
        &control,
        "POST",
        &format!("/control/v1/accounts/{account}/keys"),
        Some(&operator_token),
        Some(json!({ "scopes": ["account:read"], "rate_limit_per_min": 120 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let secret = body["secret"].as_str().unwrap().to_string();
    let key_id = body["key_id"].as_str().unwrap().to_string();
    assert_eq!(
        data_get_status(&data, "/api/v1/account/balance", &secret).await,
        StatusCode::OK,
        "a freshly minted key authenticates the data plane"
    );

    // Revoke it through the control plane; the same secret is now rejected on the
    // data plane on the very next request (no cache, no grace window).
    let (status, body) = call(
        &control,
        "POST",
        &format!("/control/v1/accounts/{account}/keys/{key_id}/revoke"),
        Some(&operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], true);
    assert_eq!(
        data_get_status(&data, "/api/v1/account/balance", &secret).await,
        StatusCode::UNAUTHORIZED,
        "a revoked key must not authenticate the data plane"
    );
}

#[tokio::test]
async fn an_adjustment_inserts_a_manual_adjustment_entry_with_an_audit_row() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/accounts/{account}/ledger-adjustment"),
        Some(&token),
        Some(json!({ "amount_usd_micros": 2_500_000, "reason": "goodwill credit" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Exactly one ledger row landed, of the manual_adjustment kind, carrying the
    // reason in its metadata.
    let (kind, reason): (String, String) = sqlx::query_as(
        "SELECT kind, metadata->>'reason' FROM cw_core.balance_ledger WHERE account_id = $1",
    )
    .bind(account)
    .fetch_one(&db.pool)
    .await
    .expect("the adjustment row exists");
    assert_eq!(kind, MANUAL_ADJUSTMENT_KIND);
    assert_eq!(reason, "goodwill credit");

    // The mutation appended a ledger.adjust audit row targeting this account.
    let rows = audit::list(
        &db.pool,
        &AuditQuery {
            action: Some("ledger.adjust".to_string()),
            ..audit_query(op, 10)
        },
    )
    .await
    .expect("list audit");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target_id, account.to_string());
    assert_eq!(rows[0].actor_kind, "operator");
}

#[tokio::test]
async fn an_adjustment_without_the_registered_kind_is_an_error() {
    let db = TestDb::fresh().await.expect("fresh db");
    // Deliberately skip register_manual_adjustment_kind to model a bootstrap that
    // never registered the reference kind.
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;

    let err = apply_adjustment(
        &db.pool,
        op,
        account,
        1_000_000,
        "missing kind",
        10_000_000_000,
        None,
        None,
    )
    .await
    .expect_err("an unregistered kind must error");
    // The journal rejects an entry whose kind is not in the registry.
    assert!(
        matches!(err, gateway_core::Error::Config(ref m) if m.contains("not registered")),
        "expected a not-registered config error, got {err:?}"
    );

    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("count");
    assert_eq!(
        count, 0,
        "no ledger row is written when the kind is missing"
    );
}

#[tokio::test]
async fn a_short_reason_is_rejected_before_any_ledger_write() {
    let db = TestDb::fresh().await.expect("fresh db");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;

    let err = apply_adjustment(
        &db.pool,
        op,
        account,
        1_000_000,
        "no",
        10_000_000_000,
        None,
        None,
    )
    .await
    .expect_err("a too-short reason must error");
    assert!(
        matches!(err, gateway_core::Error::Config(_)),
        "a short reason is a validation error, got {err:?}"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("count");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn a_retired_wallet_cannot_be_drained_or_reactivated() {
    let db = TestDb::fresh().await.expect("fresh db");
    seed_replenish_policy(&db.pool).await;
    let op = seed_operator(&db.pool).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    let router = control_router(control_state(db.pool.clone()));
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/operator/token",
        Some(&root.secret),
        None,
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    // Register a wallet under root (registration binds a shared-keyring key to an
    // owner), then force it to the terminal retired state directly (the sweep job is
    // what retires a wallet in production; here we set it to assert the control
    // transitions refuse a retired wallet).
    let (_, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        Some(&root.secret),
        Some(json!({ "label": "primary", "address": preprod_address(0x22), "network": "preprod" })),
    )
    .await;
    let wallet_id = body["wallet_id"].as_str().unwrap().to_string();
    sqlx::query("UPDATE cw_core.operator_wallet SET status = 'retired' WHERE id = $1")
        .bind(Uuid::parse_str(&wallet_id).unwrap())
        .execute(&db.pool)
        .await
        .expect("retire wallet");

    // Drain reports no change AND the wallet's real status (retired is terminal):
    // the route reports the row's actual state, never the requested "draining".
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{wallet_id}/drain"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], false, "a retired wallet does not drain");
    assert_eq!(
        body["status"], "retired",
        "drain reports the wallet's real status, not the requested target"
    );

    // Reactivate reports no change AND the real status too (never "active").
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{wallet_id}/reactivate"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["changed"], false,
        "a retired wallet does not reactivate"
    );
    assert_eq!(
        body["status"], "retired",
        "reactivate reports the wallet's real status, not the requested target"
    );

    // The wallet is still retired in the roster.
    let (_, body) = call(&router, "GET", "/control/v1/wallets", Some(&token), None).await;
    assert_eq!(body["data"][0]["status"], "retired");
}

#[tokio::test]
async fn the_audit_query_filters_by_target_type_and_actor_kind() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let acct = seed_account(&db.pool, op).await;
    // The audit read is tenancy-scoped, so a row is only visible when its target
    // is a real resource of the operator. Register a real wallet under the
    // operator so the wallet-targeted row passes the ownership predicate.
    let wallet = match gateway_core::wallet::operator::register_wallet(
        &db.pool,
        op,
        "primary",
        &preprod_address(0x33),
        gateway_core::wallet::config::Network::Preprod,
    )
    .await
    .expect("register wallet")
    {
        gateway_core::wallet::operator::RegisterOutcome::Registered(r) => r.wallet_id,
        gateway_core::wallet::operator::RegisterOutcome::AddressTaken { .. } => {
            panic!("a fresh address must register")
        }
    };

    // Two operator rows on different target types, plus one account-actor row.
    for (actor_kind, actor_id, action, target_type, target_id) in [
        (ActorKind::Operator, op, "account.create", "account", acct),
        (
            ActorKind::Operator,
            op,
            "wallet.register",
            "operator_wallet",
            wallet,
        ),
        (ActorKind::Account, acct, "key.create", "api_key", acct),
    ] {
        audit::record(
            &db.pool,
            &audit::AuditEntry {
                actor_kind,
                actor_id: Some(actor_id),
                action: action.into(),
                target_type: target_type.into(),
                target_id: target_id.to_string(),
                prev_state: None,
                new_state: None,
                request_id: None,
            },
        )
        .await
        .expect("record audit row");
    }

    // Filter by target_type narrows to the matching row.
    let by_target = audit::list(
        &db.pool,
        &AuditQuery {
            target_type: Some("operator_wallet".to_string()),
            ..audit_query(op, 10)
        },
    )
    .await
    .expect("filter by target");
    assert_eq!(by_target.len(), 1);
    assert_eq!(by_target[0].action, "wallet.register");

    // Filter by actor_kind narrows to the account-actor row.
    let by_actor = audit::list(
        &db.pool,
        &AuditQuery {
            actor_kind: Some(ActorKind::Account),
            ..audit_query(op, 10)
        },
    )
    .await
    .expect("filter by actor kind");
    assert_eq!(by_actor.len(), 1);
    assert_eq!(by_actor[0].action, "key.create");
}

/// `GET /control/v1/chain/provider-usage` returns the per-day provider request
/// buckets the egress gate records (newest day first), requires operator
/// authority, and respects the trailing-days window.
#[tokio::test]
async fn provider_usage_returns_the_day_buckets_to_an_operator() {
    use gateway_core::chain::egress::record_requests;
    use gateway_core::chain::gateway::ProviderKind;
    use gateway_core::chain::params::Network as ChainNetwork;

    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let tok = mint_operator_token_with_root(&db.pool, op, Duration::hours(1)).await;
    let router = control_router(control_state(db.pool.clone()));

    // Unauthenticated reads are refused.
    let (status, _) = call(
        &router,
        "GET",
        "/control/v1/chain/provider-usage",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Two buckets today, one outside a 1-day window.
    let today = chrono::Utc::now().date_naive();
    let last_month = today - chrono::Days::new(30);
    record_requests(
        &db.pool,
        ProviderKind::Koios,
        ChainNetwork::Preprod,
        today,
        7,
        1,
    )
    .await
    .expect("seed koios bucket");
    record_requests(
        &db.pool,
        ProviderKind::Blockfrost,
        ChainNetwork::Preprod,
        today,
        3,
        0,
    )
    .await
    .expect("seed blockfrost bucket");
    record_requests(
        &db.pool,
        ProviderKind::Koios,
        ChainNetwork::Preprod,
        last_month,
        99,
        0,
    )
    .await
    .expect("seed an old bucket");

    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/chain/provider-usage",
        Some(&tok.minted.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let data = body["data"].as_array().expect("a list envelope");
    assert_eq!(
        data.len(),
        2,
        "the default 7-day window holds today's two buckets"
    );
    let koios = data
        .iter()
        .find(|row| row["provider"] == "koios")
        .expect("the koios bucket");
    assert_eq!(koios["network"], "preprod");
    assert_eq!(koios["day"], today.to_string());
    assert_eq!(koios["request_count"], 7);
    assert_eq!(koios["denied_count"], 1);

    // A wider window picks up the old bucket too.
    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/chain/provider-usage?days=90",
        Some(&tok.minted.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["count"], 3,
        "the 90-day window includes the month-old bucket"
    );
}

/// Build control state with explicit FX-console knobs (a known operator-default
/// margin and freshness ceiling) so the FX-snapshot route's assertions are exact.
fn fx_console_state(
    pool: sqlx::PgPool,
    operator_default_margin_pct: Decimal,
    fx_freshness_ceiling_seconds: i64,
) -> ControlState {
    ControlState::new(
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
            operator_default_margin_pct,
            fx_freshness_ceiling_seconds,
        },
    )
}

/// Insert one fx_rate snapshot aged `age_seconds` back from now.
async fn seed_fx_rate(
    pool: &sqlx::PgPool,
    ada_usd_micros: i64,
    ar_usd_per_byte_femto: i64,
    age_seconds: i64,
) {
    sqlx::query(
        "INSERT INTO cw_core.fx_rate (ada_usd_micros, ar_usd_per_byte_femto, source, fetched_at) \
         VALUES ($1, $2, 'turbo', now() - make_interval(secs => $3))",
    )
    .bind(ada_usd_micros)
    .bind(ar_usd_per_byte_femto)
    .bind(age_seconds as f64)
    .execute(pool)
    .await
    .expect("seed fx rate");
}

#[tokio::test]
async fn pricing_fx_returns_the_newest_snapshot_with_age_and_margin() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let tok = mint_operator_token_with_root(&db.pool, op, Duration::hours(1)).await;
    // A 25% operator-default margin and a one-hour freshness ceiling.
    let router = control_router(fx_console_state(
        db.pool.clone(),
        Decimal::new(25, 2),
        3_600,
    ));

    // An unauthenticated read is refused.
    let (status, _) = call(&router, "GET", "/control/v1/pricing/fx", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // An older row plus a newer one; the route serves the NEWEST (highest id), and a
    // ~2-minute-old fresh snapshot is not stale under the one-hour ceiling.
    seed_fx_rate(&db.pool, 400_000, 18_000_000, 3_500).await;
    seed_fx_rate(&db.pool, 450_000, 20_955_000, 120).await;

    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/pricing/fx",
        Some(&tok.minted.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["available"], true);
    assert_eq!(body["ada_usd_micros"], 450_000);
    assert_eq!(body["ar_usd_per_byte_femto"], 20_955_000_i64);
    // 20_955_000 femto/byte * 1_048_576 bytes / 1e15 = 0.02197291... USD/MiB,
    // rounded to six places.
    assert_eq!(body["ar_usd_per_mib"], "0.021973");
    assert_eq!(body["source"], "turbo");
    assert_eq!(body["freshness_ceiling_seconds"], 3_600);
    assert_eq!(body["operator_default_margin_pct"], "0.25");
    assert_eq!(body["stale"], false);
    let age = body["age_seconds"]
        .as_i64()
        .expect("age_seconds is an integer");
    assert!(
        (115..=180).contains(&age),
        "the ~120s-old newest snapshot reports a near-120s age, got {age}"
    );
}

#[tokio::test]
async fn pricing_fx_flags_a_snapshot_past_the_ceiling_as_stale() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let tok = mint_operator_token_with_root(&db.pool, op, Duration::hours(1)).await;
    // A tight 60-second ceiling; the seeded row is older than that.
    let router = control_router(fx_console_state(db.pool.clone(), Decimal::ZERO, 60));
    seed_fx_rate(&db.pool, 450_000, 20_955_000, 7_200).await;

    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/pricing/fx",
        Some(&tok.minted.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["available"], true);
    assert_eq!(
        body["stale"], true,
        "a snapshot older than the freshness ceiling is stale"
    );
}

#[tokio::test]
async fn pricing_fx_reports_unavailable_when_no_snapshot_exists() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let tok = mint_operator_token_with_root(&db.pool, op, Duration::hours(1)).await;
    let router = control_router(fx_console_state(db.pool.clone(), Decimal::ZERO, 3_600));

    // No fx_rate row seeded: a cold start. The route degrades to available:false +
    // stale:true rather than 500-ing.
    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/pricing/fx",
        Some(&tok.minted.secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["available"], false);
    assert_eq!(body["stale"], true);
    assert_eq!(body["freshness_ceiling_seconds"], 3_600);
    assert!(
        body["ada_usd_micros"].is_null(),
        "no rate fields are present on a cold start"
    );
}
