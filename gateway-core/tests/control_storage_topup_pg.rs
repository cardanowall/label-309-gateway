//! The storage funding console: the live operator-balance read and the
//! AR -> provider-credit top-up, with cross-operator tenancy isolation.
//!
//! These suites drive the REAL control router against a fake Arweave node and a
//! fake Turbo payment service, with the fixture JWK unlocked in a real keyring,
//! and pin the contract the funding console must satisfy:
//!
//!   - The operator-balance read reports the live on-chain AR balance and the
//!     live winc balance per funding wallet, plus the cached source diagnostics,
//!     and degrades per-field (an unavailable payment service never blanks the
//!     AR side).
//!   - A top-up signs ONE transfer whose target/quantity/reward are exactly the
//!     deposit wallet, the requested winston, and the node-quoted fee; persists
//!     the journal row before any broadcast effect is observable; advances it
//!     to `registered` on a pending acceptance; and settles it to terminal
//!     `credited` — journalling the winc into the believed balance exactly
//!     once — when the provider reports the credit landed.
//!   - The create is idempotent on a REQUIRED operator-scoped idempotency key:
//!     a same-key retry replays the journalled conversion (never a second
//!     signed transfer), and reusing the key with different parameters is
//!     refused.
//!   - A registration failure leaves a retryable `submitted` row; the register
//!     route retries FORWARD (no second broadcast of an already-submitted
//!     transfer, never a re-sign).
//!   - An unaffordable amount is refused BEFORE signing: no journal row, no
//!     broadcast.
//!   - Operator B cannot top up, list, or retry operator A's conversions (404,
//!     never a 403 existence oracle).
//!   - A backend with no payment service reports the Turbo fields unavailable
//!     with a machine-readable reason and refuses a top-up with the same reason.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use age::secrecy::SecretString;
use ans104::{Ans104Signer, ArweaveJwkSigner};
use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Duration;
use gateway_core::api::control::credential::mint_root_credential;
use gateway_core::api::control::{ControlConfig, ControlFundingKey, ControlState, ControlStorage};
use gateway_core::api::{control_router, DefaultStorageScope, DefaultWalletScope};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::{arweave_address, unlock, UnlockedKeyring};
use rust_decimal::Decimal;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The operator-chosen secret prefix the control plane mints credentials under.
const PREFIX: &str = "ctl_";

/// A real 4096-bit Arweave RSA JWK fixture, shared with the ANS-104 vector suite.
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// A low scrypt work factor so the in-test keyring envelope decrypts fast.
const TEST_SCRYPT_LOG_N: u8 = 4;

/// The fee every fake-node price quote returns, in winston.
const FAKE_FEE: &str = "1000";

fn held_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

/// The fake provider's deposit wallet: a valid 32-byte base64url address.
fn deposit_address() -> String {
    ans104::base64url::encode(&[0x33u8; 32])
}

/// An unlocked keyring holding the fixture Arweave funding key, so the top-up
/// resolves the same signer the upload path would.
fn unlocked_keyring() -> Arc<UnlockedKeyring> {
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            {
                "kind": "arweave-rsa",
                "label": "storage",
                "address": held_arweave_address(),
                "secret": TEST_JWK_JSON,
            }
        ]
    })
    .to_string();
    let mut recipient = age::scrypt::Recipient::new(SecretString::from("test-pass".to_string()));
    recipient.set_work_factor(TEST_SCRYPT_LOG_N);
    let ciphertext = age::encrypt(&recipient, json.as_bytes()).expect("encrypt keyring");
    let keyring = unlock(
        &ciphertext,
        Zeroizing::new("test-pass".to_string()),
        Network::Mainnet,
    )
    .expect("the fixture keyring unlocks");
    Arc::new(keyring)
}

// ---------------------------------------------------------------------------
// Fake providers: an Arweave node and a Turbo payment service.
// ---------------------------------------------------------------------------

/// The scripted fake Arweave node: a settable wallet balance and a journal of
/// every transaction POSTed to it.
#[derive(Clone)]
struct FakeNode {
    balance: Arc<Mutex<String>>,
    posted: Arc<Mutex<Vec<Value>>>,
}

impl FakeNode {
    fn new(balance: &str) -> Self {
        Self {
            balance: Arc::new(Mutex::new(balance.to_string())),
            posted: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn posted_txs(&self) -> Vec<Value> {
        self.posted.lock().unwrap().clone()
    }
}

fn fake_node_router(node: FakeNode) -> Router {
    Router::new()
        .route(
            "/wallet/{address}/balance",
            get(|State(n): State<FakeNode>| async move { n.balance.lock().unwrap().clone() }),
        )
        .route(
            "/tx_anchor",
            get(|| async { ans104::base64url::encode(&[0x77u8; 48]) }),
        )
        .route("/price/0/{target}", get(|| async { FAKE_FEE }))
        .route(
            "/tx",
            post(
                |State(n): State<FakeNode>, Json(v): Json<Value>| async move {
                    n.posted.lock().unwrap().push(v);
                    StatusCode::OK
                },
            ),
        )
        .with_state(node)
}

/// One scripted fund-transaction registration reply.
#[derive(Clone, Copy)]
enum FundReply {
    /// 200 with a pendingTransaction verdict: accepted, credits at
    /// confirmation depth. The realistic answer for a fresh transfer, and the
    /// row lands on `registered`.
    Pending,
    /// 200 with a creditedTransaction verdict: the credit landed, and the row
    /// settles to terminal `credited` with its winc journalled.
    Credited,
    /// A 503 (the service cannot see the transfer yet).
    Unavailable,
}

/// The scripted fake Turbo payment service: the deposit-address info document,
/// an unauthenticated winc balance, and a scripted fund-registration queue
/// (empty queue = always pending, the fresh-transfer answer).
#[derive(Clone)]
struct FakePayment {
    replies: Arc<Mutex<VecDeque<FundReply>>>,
    registrations: Arc<Mutex<Vec<Value>>>,
}

impl FakePayment {
    fn new(replies: Vec<FundReply>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(replies.into())),
            registrations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn registered(&self) -> Vec<Value> {
        self.registrations.lock().unwrap().clone()
    }
}

fn fake_payment_router(payment: FakePayment) -> Router {
    Router::new()
        .route(
            "/v1/info",
            get(|| async { Json(json!({ "addresses": { "arweave": deposit_address() } })) }),
        )
        .route(
            "/v1/account/balance/arweave",
            get(|| async { Json(json!({ "winc": "777000", "fundable_bytes": 4096 })) }).post(
                |State(p): State<FakePayment>, Json(v): Json<Value>| async move {
                    p.registrations.lock().unwrap().push(v.clone());
                    let reply = p
                        .replies
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or(FundReply::Pending);
                    match reply {
                        FundReply::Pending => (
                            StatusCode::OK,
                            Json(json!({
                                "pendingTransaction": {
                                    "transactionId": v["tx_id"],
                                    "winstonCreditAmount": "424242",
                                }
                            })),
                        ),
                        FundReply::Credited => (
                            StatusCode::OK,
                            Json(json!({
                                "creditedTransaction": {
                                    "transactionId": v["tx_id"],
                                    "winstonCreditAmount": "424242",
                                }
                            })),
                        ),
                        FundReply::Unavailable => (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({ "error": "tx not found yet" })),
                        ),
                    }
                },
            ),
        )
        .with_state(payment)
}

/// Boot a fake provider router on an ephemeral local port, returning its base URL.
async fn serve(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fake");
    });
    format!("http://{addr}")
}

// ---------------------------------------------------------------------------
// Control-state and tenant plumbing.
// ---------------------------------------------------------------------------

fn control_config() -> ControlConfig {
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
    }
}

/// Control state over the Turbo rail: the fake node + payment URLs and the
/// unlocked fixture keyring.
fn turbo_state(pool: sqlx::PgPool, node_url: &str, payment_url: &str) -> ControlState {
    ControlState::with_keys(
        pool,
        control_config(),
        Vec::new(),
        vec![ControlFundingKey {
            address: held_arweave_address(),
            label: "storage".to_string(),
        }],
    )
    .with_storage(ControlStorage {
        backend: "turbo".to_string(),
        node_url: node_url.to_string(),
        payment_url: Some(payment_url.to_string()),
        keyring: unlocked_keyring(),
    })
}

/// Control state for a backend with NO payment service (the ArLocal posture).
fn arlocal_state(pool: sqlx::PgPool, node_url: &str) -> ControlState {
    ControlState::with_keys(
        pool,
        control_config(),
        Vec::new(),
        vec![ControlFundingKey {
            address: held_arweave_address(),
            label: "storage".to_string(),
        }],
    )
    .with_storage(ControlStorage {
        backend: "arlocal".to_string(),
        node_url: node_url.to_string(),
        payment_url: None,
        keyring: unlocked_keyring(),
    })
}

/// Issue a control request and return (status, body json).
async fn call(
    router: &Router,
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
    operator_token: String,
    root_secret: String,
}

/// Provision an operator with a root credential and an operator token.
async fn provision_tenant(router: &Router, pool: &sqlx::PgPool, label: &str) -> Tenant {
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
        operator_token,
        root_secret: root.secret,
    }
}

/// Register the held address as a funding source under `backend`, returning its id.
async fn register_held_source(router: &Router, root_secret: &str, backend: &str) -> Uuid {
    let (status, body) = call(
        router,
        "POST",
        "/control/v1/storage/sources",
        Some(root_secret),
        Some(json!({ "label": "primary", "backend": backend, "address": held_arweave_address() })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "source registers: {body}");
    Uuid::parse_str(body["source_id"].as_str().unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// The suites.
// ---------------------------------------------------------------------------

/// The operator-balance read reports the live AR and winc balances for the
/// operator's source, with the top-up rail enabled.
#[tokio::test]
async fn the_operator_balance_reports_live_ar_and_winc() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("9000000000000");
    let node_url = serve(fake_node_router(node.clone())).await;
    let payment_url = serve(fake_payment_router(FakePayment::new(vec![]))).await;
    let router = control_router(turbo_state(db.pool.clone(), &node_url, &payment_url));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let source_id = register_held_source(&router, &a.root_secret, "turbo").await;

    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/storage/operator-balance",
        Some(&a.operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["storage_configured"], true);
    assert_eq!(body["backend"], "turbo");
    assert!(body["fetched_at"].is_string(), "a fetch instant is stamped");

    let wallets = body["wallets"].as_array().expect("wallets array");
    assert_eq!(wallets.len(), 1, "one funding wallet: {body}");
    let w = &wallets[0];
    assert_eq!(w["arweave_address"], held_arweave_address());
    assert_eq!(w["key_held"], true);
    assert_eq!(w["ar_balance_winston"], "9000000000000");
    assert_eq!(w["ar_balance_error"], Value::Null);
    assert_eq!(w["turbo"]["available"], true);
    assert_eq!(w["turbo"]["winc"], "777000");
    assert_eq!(w["turbo"]["fundable_bytes"], 4096);
    assert_eq!(w["source"]["source_id"], source_id.to_string());
    assert_eq!(w["source"]["status"], "active");

    assert_eq!(body["top_up"]["enabled"], true);
}

/// A top-up signs one transfer with exactly the requested winston, the
/// node-quoted fee, and the provider's deposit wallet; journals it; and
/// advances it to `registered` on the provider's acceptance.
#[tokio::test]
async fn a_top_up_signs_broadcasts_registers_and_journals() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("9000000000000");
    let node_url = serve(fake_node_router(node.clone())).await;
    let payment = FakePayment::new(vec![]);
    let payment_url = serve(fake_payment_router(payment.clone())).await;
    let router = control_router(turbo_state(db.pool.clone(), &node_url, &payment_url));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let source_id = register_held_source(&router, &a.root_secret, "turbo").await;

    // The source is unambiguous, so funding_source_id may be omitted.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(json!({ "ar_amount_winston": "5000000000000", "idempotency_key": "journal-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "top-up succeeds: {body}");
    assert_eq!(body["status"], "registered");
    assert_eq!(body["funding_source_id"], source_id.to_string());
    assert_eq!(body["ar_amount_winston"], "5000000000000");
    assert_eq!(body["fee_winston"], FAKE_FEE);
    assert_eq!(body["target_address"], deposit_address());
    assert_eq!(body["registered_winc"], "424242");
    assert_eq!(body["last_error"], Value::Null);
    let tx_id = body["tx_id"].as_str().expect("tx id").to_string();

    // Exactly one transfer reached the node, and its signed fields are the
    // deposit wallet, the requested winston, the quoted fee, and no data.
    let posted = node.posted_txs();
    assert_eq!(posted.len(), 1, "one broadcast");
    let tx = &posted[0];
    assert_eq!(tx["id"], tx_id);
    assert_eq!(tx["target"], deposit_address());
    assert_eq!(tx["quantity"], "5000000000000");
    assert_eq!(tx["reward"], FAKE_FEE);
    assert_eq!(tx["data_size"], "0");
    assert_eq!(tx["data_root"], "");

    // The registration carried the same tx id.
    let registrations = payment.registered();
    assert_eq!(registrations.len(), 1);
    assert_eq!(registrations[0]["tx_id"], tx_id);

    // The journal row is durable and the mutation is audited.
    let (db_status, db_tx_id): (String, String) =
        sqlx::query_as("SELECT status, tx_id FROM cw_core.storage_topup WHERE id = $1")
            .bind(Uuid::parse_str(body["topup_id"].as_str().unwrap()).unwrap())
            .fetch_one(&db.pool)
            .await
            .expect("journal row");
    assert_eq!(db_status, "registered");
    assert_eq!(db_tx_id, tx_id);
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.admin_audit WHERE action = 'storage.topup'",
    )
    .fetch_one(&db.pool)
    .await
    .expect("audit count");
    assert_eq!(audits, 1, "the top-up is audited");

    // The journal list serves it back.
    let (status, list) = call(
        &router,
        "GET",
        "/control/v1/storage/top-ups",
        Some(&a.operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["count"], 1);
    assert_eq!(list["data"][0]["tx_id"], tx_id);

    // The balance view folds the conversion into its recent list.
    let (_, balance) = call(
        &router,
        "GET",
        "/control/v1/storage/operator-balance",
        Some(&a.operator_token),
        None,
    )
    .await;
    assert_eq!(balance["recent_top_ups"][0]["tx_id"], tx_id);
}

/// A registration failure leaves a retryable `submitted` row; the register route
/// retries forward without broadcasting a second transfer.
#[tokio::test]
async fn a_registration_failure_stays_submitted_and_retries_forward() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("9000000000000");
    let node_url = serve(fake_node_router(node.clone())).await;
    let payment = FakePayment::new(vec![FundReply::Unavailable, FundReply::Pending]);
    let payment_url = serve(fake_payment_router(payment.clone())).await;
    let router = control_router(turbo_state(db.pool.clone(), &node_url, &payment_url));
    let a = provision_tenant(&router, &db.pool, "a").await;
    register_held_source(&router, &a.root_secret, "turbo").await;

    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(json!({ "ar_amount_winston": "1000000000", "idempotency_key": "stuck-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        body["status"], "submitted",
        "the transfer is on the wire, the registration is not: {body}"
    );
    assert!(
        body["last_error"].as_str().unwrap_or("").contains("503"),
        "the failure detail is recorded: {body}"
    );
    let topup_id = body["topup_id"].as_str().unwrap().to_string();

    // Retry forward: re-register the SAME id; the already-submitted transfer is
    // NOT broadcast again.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/top-ups/{topup_id}/register"),
        Some(&a.operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "registered", "the retry lands: {body}");
    assert_eq!(body["registered_winc"], "424242");
    assert_eq!(body["last_error"], Value::Null);

    assert_eq!(node.posted_txs().len(), 1, "exactly one broadcast ever");
    let registrations = payment.registered();
    assert_eq!(registrations.len(), 2, "two registration attempts");
    assert_eq!(
        registrations[0]["tx_id"], registrations[1]["tx_id"],
        "the retry registers the SAME transaction, never a re-sign"
    );
}

/// A register poll whose verdict is `creditedTransaction` settles the
/// conversion: the row transitions to terminal `credited` with its credit
/// instant stamped, the winc lands in the believed balance through exactly one
/// `topup` journal row, and a further register call is a no-op that re-polls
/// nothing and journals nothing.
#[tokio::test]
async fn a_credited_verdict_journals_the_winc_exactly_once() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("9000000000000");
    let node_url = serve(fake_node_router(node.clone())).await;
    let payment = FakePayment::new(vec![FundReply::Unavailable, FundReply::Credited]);
    let payment_url = serve(fake_payment_router(payment.clone())).await;
    let router = control_router(turbo_state(db.pool.clone(), &node_url, &payment_url));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let source_id = register_held_source(&router, &a.root_secret, "turbo").await;

    // The create broadcasts, but the payment service cannot see the transfer
    // yet: the row parks on `submitted`.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(json!({ "ar_amount_winston": "1000000000", "idempotency_key": "credit-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "top-up created: {body}");
    assert_eq!(body["status"], "submitted");
    let topup_id = body["topup_id"].as_str().unwrap().to_string();

    // The register retry meets the credited verdict.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/top-ups/{topup_id}/register"),
        Some(&a.operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "credited", "the credit landed: {body}");
    assert_eq!(body["registered_winc"], "424242");
    assert_eq!(body["last_error"], Value::Null);

    // The row is terminal with the credit instant stamped.
    let (db_status, credited_at_set): (String, bool) = sqlx::query_as(
        "SELECT status, credited_at IS NOT NULL FROM cw_core.storage_topup WHERE id = $1",
    )
    .bind(Uuid::parse_str(&topup_id).unwrap())
    .fetch_one(&db.pool)
    .await
    .expect("top-up row");
    assert_eq!(db_status, "credited");
    assert!(credited_at_set, "credited_at is stamped");

    // Exactly one `topup` journal row, keyed on the conversion, moved the
    // materialized winc balance by exactly the credited amount.
    let (journal_rows, journalled): (i64, Decimal) = sqlx::query_as(
        "SELECT count(*), COALESCE(sum(winc_delta), 0) \
         FROM cw_core.storage_credit_ledger \
         WHERE funding_source_id = $1 AND kind = 'topup' AND ref = $2",
    )
    .bind(source_id)
    .bind(&topup_id)
    .fetch_one(&db.pool)
    .await
    .expect("journal rows");
    assert_eq!(journal_rows, 1);
    assert_eq!(journalled, Decimal::from(424_242));

    let balance: Decimal = sqlx::query_scalar(
        "SELECT winc_balance FROM cw_core.storage_credit WHERE funding_source_id = $1",
    )
    .bind(source_id)
    .fetch_one(&db.pool)
    .await
    .expect("materialized balance");
    assert_eq!(
        balance,
        Decimal::from(424_242),
        "the believed balance moved by exactly the credited amount"
    );

    // Replaying the register step is a no-op: the row is terminal, so the
    // service is not re-polled and no second journal row lands.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/top-ups/{topup_id}/register"),
        Some(&a.operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "credited");
    assert_eq!(
        payment.registered().len(),
        2,
        "create + first retry only; a terminal row is not re-polled"
    );
    let topup_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_credit_ledger \
         WHERE funding_source_id = $1 AND kind = 'topup'",
    )
    .bind(source_id)
    .fetch_one(&db.pool)
    .await
    .expect("journal rows");
    assert_eq!(topup_rows, 1, "the winc is journalled exactly once");
}

/// An amount the live wallet balance cannot cover is refused before signing:
/// nothing is journalled and nothing reaches the node.
#[tokio::test]
async fn an_unaffordable_top_up_is_refused_before_signing() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("10");
    let node_url = serve(fake_node_router(node.clone())).await;
    let payment_url = serve(fake_payment_router(FakePayment::new(vec![]))).await;
    let router = control_router(turbo_state(db.pool.clone(), &node_url, &payment_url));
    let a = provision_tenant(&router, &db.pool, "a").await;
    register_held_source(&router, &a.root_secret, "turbo").await;

    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(json!({ "ar_amount_winston": "5000000000000", "idempotency_key": "poor-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "refused: {body}");

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_topup")
        .fetch_one(&db.pool)
        .await
        .expect("row count");
    assert_eq!(rows, 0, "nothing journalled");
    assert!(node.posted_txs().is_empty(), "nothing broadcast");
}

/// Operator B cannot top up A's source, see A's journal, or retry A's top-up;
/// every cross-tenant touch is a 404.
#[tokio::test]
async fn a_foreign_operators_conversions_are_invisible() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("9000000000000");
    let node_url = serve(fake_node_router(node.clone())).await;
    let payment_url = serve(fake_payment_router(FakePayment::new(vec![]))).await;
    let router = control_router(turbo_state(db.pool.clone(), &node_url, &payment_url));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let b = provision_tenant(&router, &db.pool, "b").await;
    let source_id = register_held_source(&router, &a.root_secret, "turbo").await;

    // A's top-up succeeds.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(json!({ "ar_amount_winston": "1000000000", "idempotency_key": "tenant-a-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let topup_id = body["topup_id"].as_str().unwrap().to_string();

    // B cannot draw on A's source by naming it.
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&b.operator_token),
        Some(json!({
            "ar_amount_winston": "1000000000",
            "idempotency_key": "tenant-b-1",
            "funding_source_id": source_id
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a foreign source is a 404");

    // B's journal is empty; A's top-up does not leak.
    let (_, list) = call(
        &router,
        "GET",
        "/control/v1/storage/top-ups",
        Some(&b.operator_token),
        None,
    )
    .await;
    assert_eq!(list["count"], 0);

    // B cannot retry A's top-up.
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/storage/top-ups/{topup_id}/register"),
        Some(&b.operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a foreign top-up is a 404");

    // Exactly one transfer ever reached the node (A's).
    assert_eq!(node.posted_txs().len(), 1);
}

/// A backend with no payment service (the ArLocal posture) reports the Turbo
/// fields unavailable with a machine-readable reason and refuses a top-up with
/// the same reason; the AR balance still serves.
#[tokio::test]
async fn a_backend_without_a_payment_service_degrades_cleanly() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("123456789");
    let node_url = serve(fake_node_router(node.clone())).await;
    let router = control_router(arlocal_state(db.pool.clone(), &node_url));
    let a = provision_tenant(&router, &db.pool, "a").await;
    register_held_source(&router, &a.root_secret, "arlocal").await;

    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/storage/operator-balance",
        Some(&a.operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["backend"], "arlocal");
    let w = &body["wallets"][0];
    assert_eq!(w["ar_balance_winston"], "123456789", "AR still serves");
    assert_eq!(w["turbo"]["available"], false);
    assert_eq!(w["turbo"]["reason"], "turbo-not-active");
    assert_eq!(body["top_up"]["enabled"], false);
    assert_eq!(body["top_up"]["reason"], "turbo-not-active");

    // The top-up rail refuses with the same machine-readable reason.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(json!({ "ar_amount_winston": "1000", "idempotency_key": "arlocal-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "turbo-not-active");
    assert!(node.posted_txs().is_empty(), "nothing broadcast");
}

/// A held keyring funding key no source row claims yet is still visible in the
/// balance view (the pre-bootstrap posture), with its live AR balance.
#[tokio::test]
async fn an_unregistered_held_key_is_visible_before_bootstrap() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("555");
    let node_url = serve(fake_node_router(node.clone())).await;
    let payment_url = serve(fake_payment_router(FakePayment::new(vec![]))).await;
    let router = control_router(turbo_state(db.pool.clone(), &node_url, &payment_url));
    let a = provision_tenant(&router, &db.pool, "a").await;

    let (status, body) = call(
        &router,
        "GET",
        "/control/v1/storage/operator-balance",
        Some(&a.operator_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let w = &body["wallets"][0];
    assert_eq!(w["arweave_address"], held_arweave_address());
    assert_eq!(w["key_held"], true);
    assert_eq!(w["source"], Value::Null, "no source row claims it yet");
    assert_eq!(w["ar_balance_winston"], "555");
    // No active source: the top-up rail is visible but not enabled.
    assert_eq!(body["top_up"]["enabled"], false);
    assert_eq!(body["top_up"]["reason"], "no-funding-source");
}

/// Retrying a top-up create with the same idempotency key — the lost-response
/// recovery path — replays the journalled conversion instead of signing a
/// second irreversible transfer; a different key is a genuinely new
/// conversion. Pins the double-conversion money bug: without the key, every
/// create retry signed a fresh randomised transfer and moved the funds again.
#[tokio::test]
async fn a_same_key_create_retry_replays_instead_of_resigning_regression() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("9000000000000");
    let node_url = serve(fake_node_router(node.clone())).await;
    let payment = FakePayment::new(vec![]);
    let payment_url = serve(fake_payment_router(payment.clone())).await;
    let router = control_router(turbo_state(db.pool.clone(), &node_url, &payment_url));
    let a = provision_tenant(&router, &db.pool, "a").await;
    register_held_source(&router, &a.root_secret, "turbo").await;

    let request = json!({ "ar_amount_winston": "1000000000", "idempotency_key": "retry-1" });
    let (status, first) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(request.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "first create: {first}");
    assert_eq!(first["status"], "registered");
    assert_eq!(first["idempotency_key"], "retry-1");

    // The lost-response retry: byte-identical request, same key.
    let (status, second) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a replay is a 200: {second}");
    assert_eq!(second["topup_id"], first["topup_id"]);
    assert_eq!(second["tx_id"], first["tx_id"]);
    assert_eq!(second["status"], "registered");

    // Exactly one transfer was ever signed and broadcast, and exactly one
    // conversion is journalled. The replay re-POLLS the registration (a
    // `registered` row is advanced until its credit lands), so two idempotent
    // registrations of the SAME id reached the service — never a re-sign.
    assert_eq!(node.posted_txs().len(), 1, "one broadcast ever");
    let registrations = payment.registered();
    assert_eq!(
        registrations.len(),
        2,
        "the replay re-polls the pending registration"
    );
    assert_eq!(
        registrations[0]["tx_id"], registrations[1]["tx_id"],
        "the replay polls the SAME transaction, never a re-sign"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_topup")
        .fetch_one(&db.pool)
        .await
        .expect("row count");
    assert_eq!(rows, 1, "one journal row");

    // The audit trail counts one real conversion and one replay.
    let creates: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.admin_audit WHERE action = $1")
            .bind("storage.topup")
            .fetch_one(&db.pool)
            .await
            .expect("audit count");
    assert_eq!(creates, 1, "one real conversion audited");
    let replays: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.admin_audit WHERE action = $1")
            .bind("storage.topup_replay")
            .fetch_one(&db.pool)
            .await
            .expect("audit count");
    assert_eq!(replays, 1, "the retry is audited as a replay");

    // A DIFFERENT key is a new conversion: a second transfer, a second row.
    let (status, third) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(json!({ "ar_amount_winston": "1000000000", "idempotency_key": "retry-2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "a new key creates: {third}");
    assert_ne!(third["tx_id"], first["tx_id"], "a distinct transfer");
    assert_eq!(node.posted_txs().len(), 2, "two broadcasts for two keys");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_topup")
        .fetch_one(&db.pool)
        .await
        .expect("row count");
    assert_eq!(rows, 2, "two journal rows for two keys");
}

/// A same-key retry of a top-up stuck before registration converges it
/// FORWARD — re-registering the persisted transfer exactly like the register
/// route — without a second broadcast and without re-signing.
#[tokio::test]
async fn a_same_key_retry_converges_a_stuck_top_up_forward_regression() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("9000000000000");
    let node_url = serve(fake_node_router(node.clone())).await;
    let payment = FakePayment::new(vec![FundReply::Unavailable, FundReply::Pending]);
    let payment_url = serve(fake_payment_router(payment.clone())).await;
    let router = control_router(turbo_state(db.pool.clone(), &node_url, &payment_url));
    let a = provision_tenant(&router, &db.pool, "a").await;
    register_held_source(&router, &a.root_secret, "turbo").await;

    let request = json!({ "ar_amount_winston": "1000000000", "idempotency_key": "stuck-retry" });
    let (status, first) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(request.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        first["status"], "submitted",
        "registration pending: {first}"
    );

    let (status, second) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["status"], "registered", "the retry lands: {second}");
    assert_eq!(second["topup_id"], first["topup_id"]);
    assert_eq!(second["registered_winc"], "424242");

    assert_eq!(node.posted_txs().len(), 1, "exactly one broadcast ever");
    let registrations = payment.registered();
    assert_eq!(registrations.len(), 2, "two registration attempts");
    assert_eq!(
        registrations[0]["tx_id"], registrations[1]["tx_id"],
        "the replay registers the SAME transaction, never a re-sign"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_topup")
        .fetch_one(&db.pool)
        .await
        .expect("row count");
    assert_eq!(rows, 1, "one journal row");
}

/// The idempotency key is required before any effect, and binds the
/// conversion's parameters: reusing it with a different amount is refused
/// rather than silently replaying (or worse, signing a second transfer).
#[tokio::test]
async fn the_idempotency_key_is_required_and_binds_its_parameters() {
    let db = TestDb::fresh().await.expect("fresh db");
    let node = FakeNode::new("9000000000000");
    let node_url = serve(fake_node_router(node.clone())).await;
    let payment_url = serve(fake_payment_router(FakePayment::new(vec![]))).await;
    let router = control_router(turbo_state(db.pool.clone(), &node_url, &payment_url));
    let a = provision_tenant(&router, &db.pool, "a").await;
    register_held_source(&router, &a.root_secret, "turbo").await;

    // Missing and blank keys are refused before anything is signed.
    for body in [
        json!({ "ar_amount_winston": "1000000000" }),
        json!({ "ar_amount_winston": "1000000000", "idempotency_key": "   " }),
    ] {
        let (status, problem) = call(
            &router,
            "POST",
            "/control/v1/storage/top-up",
            Some(&a.operator_token),
            Some(body),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused: {problem}"
        );
    }
    assert!(node.posted_txs().is_empty(), "nothing broadcast");

    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(json!({ "ar_amount_winston": "1000000000", "idempotency_key": "bind-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // The same key with a different amount is a caller bug, not a replay.
    let (status, problem) = call(
        &router,
        "POST",
        "/control/v1/storage/top-up",
        Some(&a.operator_token),
        Some(json!({ "ar_amount_winston": "2000000000", "idempotency_key": "bind-1" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a parameter mismatch is refused: {problem}"
    );

    assert_eq!(node.posted_txs().len(), 1, "still exactly one broadcast");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_topup")
        .fetch_one(&db.pool)
        .await
        .expect("row count");
    assert_eq!(rows, 1, "still one journal row");
}
