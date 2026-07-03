//! Control-plane conformance (C1-C4): the operator surface driven over real HTTP
//! against a booted gateway.
//!
//! The control plane previously had only its in-code route-coverage test; these
//! scenarios exercise it as a repeatable suite the same way a deployment's operator
//! runbook does:
//!
//!   - C1: bootstrap -> operator token -> account create -> key create -> key
//!     list/revoke (the operator onboarding path as a suite step);
//!   - C2: wallet register (root) -> grant -> grant-revoke -> list (the routes the
//!     new admin CLI drives);
//!   - C3: plane isolation — an operator token is rejected on the data plane, an
//!     account bearer is rejected on the operator routes;
//!   - C4: a manual ledger adjustment moves the balance and is audited.
//!
//! Gated behind the `live` feature: the suite boots a real gateway over a real
//! Postgres.

#![cfg(feature = "live")]

use conformance::BootedGateway;
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::derive_enterprise_address;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// A small HTTP client (the control surface is driven directly, not via the SDK).
// ---------------------------------------------------------------------------

struct Resp {
    status: u16,
    body: Value,
}

struct Client {
    http: reqwest::Client,
    base: String,
}

impl Client {
    fn new(base: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: base.to_string(),
        }
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> Resp {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.expect("request sends");
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, body }
    }

    async fn post(&self, path: &str, bearer: &str, body: Value) -> Resp {
        self.call(reqwest::Method::POST, path, Some(bearer), Some(body))
            .await
    }

    async fn get(&self, path: &str, bearer: &str) -> Resp {
        self.call(reqwest::Method::GET, path, Some(bearer), None)
            .await
    }
}

/// A valid preprod enterprise address derived from a seed, plus its held-key
/// metadata. The wallet-register route refuses an address the instance holds no
/// signer for, so the harness wires this address as a held key (see
/// [`BootedGateway::start_with_control_wallet_keys`]).
fn held_address(seed: u8) -> String {
    derive_enterprise_address(&[seed; 32], Network::Preprod).expect("derive preprod address")
}

// ---------------------------------------------------------------------------
// C1 — bootstrap -> operator token -> account -> key create/list/revoke.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn c1_operator_runbook_account_and_key_lifecycle() {
    let gw = BootedGateway::start().await.expect("boot");
    let (_operator_id, root_secret) = gw.seed_operator_root("cfm_").await.expect("operator root");
    let client = Client::new(&gw.base_url);

    // The root mints an operator token; an operator token may NOT mint another.
    let token_resp = client
        .post("/control/v1/operator/token", &root_secret, json!({}))
        .await;
    assert_eq!(token_resp.status, 201, "root mints an operator token");
    let operator_token = token_resp.body["token"]
        .as_str()
        .expect("token")
        .to_string();

    let denied = client
        .post("/control/v1/operator/token", &operator_token, json!({}))
        .await;
    assert_eq!(
        denied.status, 403,
        "only the root may mint an operator token"
    );

    // Create an account; it appears in the roster.
    let create = client
        .post("/control/v1/accounts", &operator_token, json!({}))
        .await;
    assert_eq!(create.status, 201);
    let account_id = create.body["account_id"]
        .as_str()
        .expect("account")
        .to_string();

    let roster = client.get("/control/v1/accounts", &operator_token).await;
    assert_eq!(roster.body["count"], 1, "the account is in the roster");

    // Mint an api key (secret shown once), list it (no secret), revoke it.
    let key = client
        .post(
            &format!("/control/v1/accounts/{account_id}/keys"),
            &operator_token,
            json!({ "scopes": ["poe:read", "poe:create"], "rate_limit_per_min": 120 }),
        )
        .await;
    assert_eq!(key.status, 201);
    assert!(key.body["secret"].as_str().unwrap().starts_with("cfm_"));
    let key_id = key.body["key_id"].as_str().unwrap().to_string();

    let key_list = client
        .get(
            &format!("/control/v1/accounts/{account_id}/keys"),
            &operator_token,
        )
        .await;
    assert_eq!(key_list.body["count"], 1);
    assert!(
        key_list.body["data"][0].get("secret").is_none(),
        "a key listing never includes a secret"
    );

    let revoke = client
        .post(
            &format!("/control/v1/accounts/{account_id}/keys/{key_id}/revoke"),
            &operator_token,
            json!({}),
        )
        .await;
    assert_eq!(revoke.body["revoked"], true, "the key is revoked");

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// C2 — wallet register (root) -> grant -> grant-revoke -> list.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn c2_wallet_register_grant_revoke_list() {
    // Wire the held wallet key the register route validates possession against.
    let address = held_address(0x42);
    let gw =
        BootedGateway::start_with_control_wallet_keys(vec![gateway_core::api::ControlWalletKey {
            address: address.clone(),
            label: "conformance-wallet".to_string(),
        }])
        .await
        .expect("boot");
    let (_operator_id, root_secret) = gw.seed_operator_root("cfm_").await.expect("operator root");
    let client = Client::new(&gw.base_url);

    let token_resp = client
        .post("/control/v1/operator/token", &root_secret, json!({}))
        .await;
    let operator_token = token_resp.body["token"]
        .as_str()
        .expect("token")
        .to_string();

    // Register the wallet under the ROOT credential (a root-only action). The
    // register auto-issues a grant and returns its id.
    let register = client
        .post(
            "/control/v1/wallets",
            &root_secret,
            json!({ "label": "primary", "address": address, "network": "preprod" }),
        )
        .await;
    assert_eq!(
        register.status, 201,
        "wallet register succeeds: {:?}",
        register.body
    );
    assert_eq!(register.body["created"], true);
    let wallet_id = register.body["wallet_id"]
        .as_str()
        .expect("wallet id")
        .to_string();

    // A non-root credential (the operator token) is refused on register.
    let register_denied = client
        .post(
            "/control/v1/wallets",
            &operator_token,
            json!({ "label": "x", "address": held_address(0x43), "network": "preprod" }),
        )
        .await;
    assert_eq!(
        register_denied.status, 403,
        "a non-root credential is refused on wallet register"
    );

    // Issue an explicit operator-scoped grant, then revoke it.
    let grant = client
        .post(
            &format!("/control/v1/wallets/{wallet_id}/grants"),
            &operator_token,
            json!({ "scope": "operator" }),
        )
        .await;
    assert_eq!(
        grant.status, 201,
        "operator issues a grant: {:?}",
        grant.body
    );
    let grant_id = grant.body["grant_id"]
        .as_str()
        .expect("grant id")
        .to_string();

    let revoke = client
        .post(
            &format!("/control/v1/wallets/{wallet_id}/grants/{grant_id}/revoke"),
            &operator_token,
            json!({}),
        )
        .await;
    assert_eq!(
        revoke.status, 200,
        "the grant is revoked: {:?}",
        revoke.body
    );

    // The wallet roster lists the registered wallet.
    let roster = client.get("/control/v1/wallets", &operator_token).await;
    let data = roster.body["data"].as_array().expect("wallet roster");
    assert!(
        data.iter()
            .any(|w| w["wallet_id"] == wallet_id || w["id"] == wallet_id),
        "the registered wallet appears in the roster"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// C3 — plane isolation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn c3_plane_isolation() {
    let gw = BootedGateway::start().await.expect("boot");
    let (_operator_id, root_secret) = gw.seed_operator_root("cfm_").await.expect("operator root");
    let client = Client::new(&gw.base_url);

    let token_resp = client
        .post("/control/v1/operator/token", &root_secret, json!({}))
        .await;
    let operator_token = token_resp.body["token"]
        .as_str()
        .expect("token")
        .to_string();

    // An operator token is rejected on a data-plane route.
    let on_data = client.get("/api/v1/account/balance", &operator_token).await;
    assert_eq!(
        on_data.status, 403,
        "an operator token must be rejected on the data plane"
    );

    // An account bearer is rejected on an operator-only control route.
    let tenant = gw
        .seed_tenant("cfm_", &["poe:read"], 0)
        .await
        .expect("tenant");
    let on_control = client.get("/control/v1/accounts", &tenant.api_key).await;
    assert!(
        on_control.status == 401 || on_control.status == 403,
        "an account bearer must be rejected on the operator routes, got {}",
        on_control.status
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// C4 — manual ledger adjustment moves balance and is audited.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn c4_ledger_adjustment_moves_balance_and_audits() {
    let gw = BootedGateway::start().await.expect("boot");
    let (operator_id, root_secret) = gw.seed_operator_root("cfm_").await.expect("operator root");
    let client = Client::new(&gw.base_url);

    let token_resp = client
        .post("/control/v1/operator/token", &root_secret, json!({}))
        .await;
    let operator_token = token_resp.body["token"]
        .as_str()
        .expect("token")
        .to_string();

    let create = client
        .post("/control/v1/accounts", &operator_token, json!({}))
        .await;
    let account_id = create.body["account_id"]
        .as_str()
        .expect("account")
        .to_string();

    // Apply a manual adjustment; the usage read reflects the new balance.
    let adjust = client
        .post(
            &format!("/control/v1/accounts/{account_id}/ledger-adjustment"),
            &operator_token,
            json!({ "amount_usd_micros": 5_000_000, "reason": "conformance funding" }),
        )
        .await;
    assert_eq!(adjust.status, 200);
    assert_eq!(adjust.body["applied"], true);

    let usage = client
        .get(
            &format!("/control/v1/accounts/{account_id}/usage"),
            &operator_token,
        )
        .await;
    assert_eq!(
        usage.body["balance_usd_micros"], 5_000_000,
        "usage reflects the adjusted balance"
    );

    // The audit log records the adjustment, scoped to the operator.
    let audit = client
        .get("/control/v1/audit?action=ledger.adjust", &operator_token)
        .await;
    assert_eq!(audit.status, 200);
    assert!(
        audit.body["count"].as_i64().unwrap_or(0) >= 1,
        "the adjustment is audited"
    );
    assert_eq!(
        audit.body["data"][0]["target_id"], account_id,
        "the audit row targets the adjusted account"
    );

    let _ = operator_id;
    gw.shutdown().await;
}
