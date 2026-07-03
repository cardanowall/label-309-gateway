//! The operator firehose: the control-plane operator-scoped subscription surface.
//!
//! These pin the operator arm of the webhook subscription model (the data plane is
//! the account arm):
//!
//!   - **Cross-account fan-out.** One operator-scoped firehose receives every event
//!     under the operator: across all of its accounts AND its operator-plane-only
//!     subjects (a storage funding refund). A second operator's firehose never sees
//!     it. This is the matcher scope that distinguishes the firehose from an
//!     account subscription.
//!   - **Operator-only auth + owner scope.** The control routes require operator
//!     authority (an account bearer is rejected) and are pinned to the owning
//!     operator (a second operator can never read, mutate, or delete the first's
//!     firehose; a foreign row is reported absent identically to a missing one).
//!   - **The full operator lifecycle over the control router.** Create (secret shown
//!     once), list (fingerprint only), get, patch (pause/resume), the deliveries
//!     dead-letter view + redrive, the dual-signed rotation window + commit, and
//!     soft-delete, all driven through the actual `/control/v1/webhooks` router.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use tower::ServiceExt;
use uuid::Uuid;

use gateway_core::api::state::WebhookState;
use gateway_core::events::append_subject_event;
use gateway_core::testsupport::TestDb;
use gateway_core::webhook::secret::SecretWrap;
use gateway_core::webhook::signer::sign_delivery;
use gateway_core::webhook::{
    claim_unfanned, create_endpoint, delivery, get_endpoint, EndpointScope, NewEndpoint,
};

type HmacSha256 = Hmac<Sha256>;

/// A deterministic wrap key for the suite (production mints it at bootstrap).
fn wrap() -> SecretWrap {
    SecretWrap::new("whk_test", [0x5au8; 32])
}

async fn seed_operator(pool: &sqlx::PgPool, label: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(id)
        .bind(label)
        .execute(pool)
        .await
        .expect("seed operator");
    id
}

async fn seed_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("seed account anchor");
    sqlx::query("INSERT INTO cw_core.account_detail (account_id, operator_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("seed account detail");
    account_id
}

async fn seed_poe_record(pool: &sqlx::PgPool, operator_id: Uuid, account_id: Option<Uuid>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record (id, operator_id, account_id, record_bytes) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(account_id)
    .bind(vec![0x01u8, 0x02, 0x03])
    .execute(pool)
    .await
    .expect("seed poe_record");
    id
}

async fn seed_funding_source(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'src', 'turbo', $3, 'keyref')",
    )
    .bind(id)
    .bind(operator_id)
    .bind(format!("ar-addr-{}", id.simple()))
    .execute(pool)
    .await
    .expect("seed funding source");
    id
}

/// A standard operator-firehose input (no event filter = every wire event).
fn operator_endpoint(operator_id: Uuid) -> NewEndpoint {
    NewEndpoint {
        scope: EndpointScope::Operator(operator_id),
        url: "https://hooks.example.test/firehose".to_string(),
        enabled_events: Vec::new(),
        label: Some("firehose".to_string()),
    }
}

/// Append an event and drain the fan-out spine for it, so the matched
/// subscriptions get their `webhook_delivery` rows. Mirrors the production fan-out
/// worker: claim the un-fanned outbox rows as a set, explode each in its own
/// transaction.
async fn append_and_fan_out(
    pool: &sqlx::PgPool,
    subject_kind: &str,
    subject_id: &str,
    event_type: &str,
) {
    append_subject_event(pool, subject_kind, subject_id, event_type, &json!({}))
        .await
        .expect("append subject event");
    let rows = {
        let mut tx = pool.begin().await.expect("begin claim");
        let batch = claim_unfanned(&mut tx, 50).await.expect("claim");
        tx.commit().await.expect("commit claim");
        batch
    };
    for row in rows {
        let mut tx = pool.begin().await.expect("begin explode");
        delivery::explode_outbox_row(pool, &mut tx, &row)
            .await
            .expect("explode");
        tx.commit().await.expect("commit explode");
    }
}

/// Count the deliveries fanned out to an endpoint.
async fn delivery_count(pool: &sqlx::PgPool, endpoint_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
        .bind(endpoint_id)
        .fetch_one(pool)
        .await
        .expect("count deliveries")
}

/// The subject ids the deliveries for an endpoint carry, sorted for a stable
/// assertion.
async fn delivery_event_types(pool: &sqlx::PgPool, endpoint_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_type FROM cw_core.webhook_delivery WHERE endpoint_id = $1 \
         ORDER BY event_type",
    )
    .bind(endpoint_id)
    .fetch_all(pool)
    .await
    .expect("delivery event types")
}

/// An operator-scoped firehose receives events across EVERY account under the
/// operator plus the operator-plane-only funding subject; a second operator's
/// firehose receives none of them.
#[tokio::test]
async fn firehose_fans_out_across_accounts_and_operator_subjects() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool, "op").await;
    let other_operator = seed_operator(&pool, "other").await;
    let account_a = seed_account(&pool, operator).await;
    let account_b = seed_account(&pool, operator).await;

    // The operator's firehose, and a second operator's firehose that must stay empty.
    let firehose = create_endpoint(&pool, &wrap(), &operator_endpoint(operator))
        .await
        .expect("operator firehose")
        .id;
    let other_firehose = create_endpoint(&pool, &wrap(), &operator_endpoint(other_operator))
        .await
        .expect("other firehose")
        .id;

    // An event on a record under account A, one under account B, and an
    // operator-plane-only storage refund on a funding source the operator owns.
    let record_a = seed_poe_record(&pool, operator, Some(account_a)).await;
    let record_b = seed_poe_record(&pool, operator, Some(account_b)).await;
    let funding = seed_funding_source(&pool, operator).await;

    append_and_fan_out(&pool, "poe_record", &record_a.to_string(), "confirmed").await;
    append_and_fan_out(&pool, "poe_record", &record_b.to_string(), "confirmed").await;
    append_and_fan_out(
        &pool,
        "storage_funding_source",
        &funding.to_string(),
        "storage.refund-intent",
    )
    .await;

    // The firehose received all three events (both accounts + the operator subject).
    assert_eq!(
        delivery_count(&pool, firehose).await,
        3,
        "the firehose fans out every event under the operator across all accounts"
    );
    let types = delivery_event_types(&pool, firehose).await;
    assert!(
        types.contains(&"confirmed".to_string()),
        "the firehose carries the poe events from both accounts"
    );
    assert!(
        types.contains(&"storage.refund-intent".to_string()),
        "the firehose carries the operator-plane-only storage refund"
    );

    // The second operator's firehose saw none of them (cross-operator isolation).
    assert_eq!(
        delivery_count(&pool, other_firehose).await,
        0,
        "a second operator's firehose never receives another operator's events"
    );
}

/// The firehose filter is on the projected wire name: an operator subscription that
/// names only `balance_changed` receives a balance event but not a poe status
/// change under the same operator.
#[tokio::test]
async fn firehose_event_filter_is_on_the_wire_name() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool, "op").await;
    let account = seed_account(&pool, operator).await;

    let filtered = create_endpoint(
        &pool,
        &wrap(),
        &NewEndpoint {
            scope: EndpointScope::Operator(operator),
            url: "https://hooks.example.test/balance".to_string(),
            enabled_events: vec!["balance_changed".to_string()],
            label: None,
        },
    )
    .await
    .expect("filtered firehose")
    .id;

    // A poe status change (filtered out) and a balance change (matched).
    let record = seed_poe_record(&pool, operator, Some(account)).await;
    append_and_fan_out(&pool, "poe_record", &record.to_string(), "confirmed").await;
    append_and_fan_out(&pool, "account", &account.to_string(), "balance.changed").await;

    let types = delivery_event_types(&pool, filtered).await;
    assert_eq!(
        types,
        vec!["balance.changed".to_string()],
        "the firehose filter delivers only the named wire event"
    );
}

// ---------------------------------------------------------------------------
// HTTP route-level tests over the control router.
// ---------------------------------------------------------------------------

/// Build control state with the webhook seam wired under explicit egress knobs.
/// The wrap key matches the suite's so a seeded delivery's secret round-trips.
fn control_state_with_flags(
    pool: sqlx::PgPool,
    allow_insecure_http: bool,
    egress_allow_loopback: bool,
) -> gateway_core::api::ControlState {
    gateway_core::api::ControlState::new(
        pool,
        gateway_core::api::ControlConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            secret_prefix: "ctl_test_".to_string(),
            ..Default::default()
        },
    )
    .with_webhook(WebhookState::new(
        Arc::new(SecretWrap::new("whk_test", [0x5au8; 32])),
        allow_insecure_http,
        egress_allow_loopback,
    ))
}

/// Build control state with the webhook seam wired (loopback allowed so a test URL
/// passes the SSRF guard at create/rotate).
fn control_state(pool: sqlx::PgPool) -> gateway_core::api::ControlState {
    // The suite's HTTPS loopback URLs need only the range-block seam.
    control_state_with_flags(pool, false, true)
}

/// Mint an operator token for `operator_id`, anchored on a freshly minted root
/// (the engine validates the mint lineage: `minted_by` must reference a live
/// credential of the operator, so a fabricated id no longer mints).
async fn operator_token(pool: &sqlx::PgPool, operator_id: Uuid) -> String {
    let root = gateway_core::api::control::credential::mint_root_credential(
        pool,
        operator_id,
        "ctl_test_",
        None,
    )
    .await
    .expect("mint lineage root");
    gateway_core::api::control::credential::mint_operator_token(
        pool,
        operator_id,
        "ctl_test_",
        Duration::hours(1),
        root.id,
    )
    .await
    .expect("mint operator token")
    .minted
    .secret
}

/// Issue an account api key carrying `scopes`, returning the bearer secret. Used to
/// prove an account bearer cannot reach the operator firehose surface.
async fn issue_account_key(pool: &sqlx::PgPool, account_id: Uuid, scopes: &[&str]) -> String {
    use sha2::Digest;
    let secret = format!("ak_test_{}", Uuid::now_v7().simple());
    let full = Sha256::digest(secret.as_bytes());
    let lookup = full[..8].to_vec();
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "INSERT INTO cw_core.api_key \
           (id, account_id, prefix, key_lookup, key_hash_sha256, scopes, rate_limit_per_min) \
         VALUES ($1, $2, 'ak_test_', $3, $4, $5, 1000)",
    )
    .bind(Uuid::now_v7())
    .bind(account_id)
    .bind(lookup)
    .bind(full.to_vec())
    .bind(&scopes)
    .execute(pool)
    .await
    .expect("insert api key");
    secret
}

async fn seed_delivery(
    pool: &sqlx::PgPool,
    endpoint_id: Uuid,
    seq: i64,
    state: &str,
    attempts: i32,
    next_attempt_at: chrono::DateTime<Utc>,
) -> Uuid {
    let id = Uuid::now_v7();
    let dedupe = format!("operator:{endpoint_id}:{seq}:{endpoint_id}");
    sqlx::query(
        "INSERT INTO cw_core.webhook_delivery \
           (id, endpoint_id, subject_kind, subject_id, subject_seq, event_type, body, \
            dedupe_key, outbox_id, state, attempts, next_attempt_at) \
         VALUES ($1, $2, 'poe_record', $3, $4, 'confirmed', '{}'::jsonb, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(endpoint_id)
    .bind(Uuid::now_v7().to_string())
    .bind(seq)
    .bind(&dedupe)
    // The outbox FK must reference a real row; seed a stamped one.
    .bind(seed_stamped_outbox(pool).await)
    .bind(state)
    .bind(attempts)
    .bind(next_attempt_at)
    .execute(pool)
    .await
    .expect("insert delivery");
    id
}

/// Seed a stamped (already fanned-out) outbox row a delivery's FK can reference.
async fn seed_stamped_outbox(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.delivery_outbox \
           (id, subject_kind, subject_id, subject_seq, event_type, payload, dedupe_key, \
            fanned_out_at) \
         VALUES ($1, 'poe_record', $2, 1, 'confirmed', '{}'::jsonb, $3, now())",
    )
    .bind(id)
    .bind(Uuid::now_v7().to_string())
    .bind(format!("dedupe-{}", id.simple()))
    .execute(pool)
    .await
    .expect("seed stamped outbox");
    id
}

async fn call(router: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

fn get_auth(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request")
}

fn post_json(path: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build request")
}

fn post_auth(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request")
}

fn patch_json(path: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build request")
}

fn delete_auth(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request")
}

/// The control-plane registration guard keeps the SSRF range-block under the
/// self-host `allow_insecure_http` knob: plain HTTP into a blocked range is
/// refused, plain HTTP to a public address registers. Same posture as the data
/// plane — both read the knobs through the one `EgressConfig` mapping.
#[tokio::test]
async fn http_firehose_register_with_insecure_http_keeps_the_range_block() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    // Self-host posture: plain HTTP permitted, range-block NOT loosened.
    let router =
        gateway_core::api::control_router(control_state_with_flags(pool.clone(), true, false));

    let operator = seed_operator(&pool, "op").await;
    let token = operator_token(&pool, operator).await;

    for url in [
        "http://127.0.0.1/firehose",
        "http://10.0.0.9/firehose",
        "http://169.254.169.254/latest/meta-data",
    ] {
        let (status, body) = call(
            &router,
            post_json("/control/v1/webhooks", &token, json!({ "url": url })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{url} must be refused by the SSRF guard despite allow_insecure_http"
        );
        assert_eq!(body["code"], json!("invalid-webhook-url"));
    }

    let (status, created) = call(
        &router,
        post_json(
            "/control/v1/webhooks",
            &token,
            json!({ "url": "http://8.8.8.8/firehose" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a public plain-HTTP target registers under allow_insecure_http"
    );
    assert!(created["secret"].as_str().is_some());
}

/// The full operator-firehose lifecycle over the control router: register (secret
/// shown once), list (fingerprint only), get, pause via PATCH, then delete.
#[tokio::test]
async fn http_firehose_register_list_patch_delete_lifecycle() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let router = gateway_core::api::control_router(control_state(pool.clone()));

    let operator = seed_operator(&pool, "op").await;
    let token = operator_token(&pool, operator).await;

    // Register: 201, the signing secret shown exactly once.
    let (status, created) = call(
        &router,
        post_json(
            "/control/v1/webhooks",
            &token,
            json!({ "url": "https://127.0.0.1/firehose", "label": "fh" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let secret = created["secret"].as_str().expect("secret shown once");
    assert!(secret.starts_with("whsec_"));
    let endpoint_id = created["id"].as_str().expect("id").to_string();

    // List: the firehose is present, carries the fingerprint, never the secret.
    let (status, list) = call(&router, get_auth("/control/v1/webhooks", &token)).await;
    assert_eq!(status, StatusCode::OK);
    let item = list["data"]
        .as_array()
        .expect("data array")
        .iter()
        .find(|e| e["id"] == endpoint_id)
        .expect("the firehose is listed");
    assert!(item["secret_fp"].as_str().is_some(), "fingerprint is shown");
    assert!(item.get("secret").is_none(), "the secret is never listed");

    // Get: 200, same row.
    let (status, got) = call(
        &router,
        get_auth(&format!("/control/v1/webhooks/{endpoint_id}"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got["status"], "active");

    // PATCH to paused: 200, status reflects the persisted change.
    let (status, patched) = call(
        &router,
        patch_json(
            &format!("/control/v1/webhooks/{endpoint_id}"),
            &token,
            json!({ "status": "paused" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(patched["status"], "paused");

    // DELETE: 204, then GET is 404 (soft-deleted).
    let (status, _) = call(
        &router,
        delete_auth(&format!("/control/v1/webhooks/{endpoint_id}"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &router,
        get_auth(&format!("/control/v1/webhooks/{endpoint_id}"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The deliveries dead-letter view + redrive, and the dual-signed rotation window +
/// commit, over the control router.
#[tokio::test]
async fn http_firehose_deliveries_redrive_and_rotation() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let router = gateway_core::api::control_router(control_state(pool.clone()));

    let operator = seed_operator(&pool, "op").await;
    let token = operator_token(&pool, operator).await;
    // Create the firehose through the suite wrap key so a seeded delivery's secret
    // round-trips under the same key.
    let endpoint = create_endpoint(&pool, &wrap(), &operator_endpoint(operator))
        .await
        .expect("create firehose")
        .id;

    // Seed one failed (dead-letter) and one pending delivery.
    let now = Utc::now();
    let failed = seed_delivery(&pool, endpoint, 1, "failed", 12, now + Duration::hours(6)).await;
    seed_delivery(&pool, endpoint, 2, "pending", 0, now).await;

    // Deliveries list: both states present, the frozen body is not echoed.
    let (status, body) = call(
        &router,
        get_auth(
            &format!("/control/v1/webhooks/{endpoint}/deliveries"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["data"].as_array().expect("data array");
    assert_eq!(items.len(), 2);
    assert!(items.iter().any(|d| d["state"] == "failed"));
    assert!(items.iter().any(|d| d["state"] == "pending"));
    assert!(items.iter().all(|d| d.get("body").is_none()));
    assert!(items.iter().all(|d| d["webhook_id"].as_str().is_some()));

    // Redrive the failed one: 200, re-armed pending, attempts preserved.
    let (status, body) = call(
        &router,
        post_auth(
            &format!("/control/v1/webhooks/{endpoint}/deliveries/{failed}/retry"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "pending");
    let attempts: i32 =
        sqlx::query_scalar("SELECT attempts FROM cw_core.webhook_delivery WHERE id = $1")
            .bind(failed)
            .fetch_one(&pool)
            .await
            .expect("read attempts");
    assert_eq!(attempts, 12, "redrive resets schedule, not attempts");

    // Redriving the now-pending row is 422 (only a failed row is redrivable).
    let (status, body) = call(
        &router,
        post_auth(
            &format!("/control/v1/webhooks/{endpoint}/deliveries/{failed}/retry"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "validation-failed");

    // Rotate the secret: 200, successor shown once, both fingerprints in GET.
    let (status, rotated) = call(
        &router,
        post_auth(
            &format!("/control/v1/webhooks/{endpoint}/rotate-secret"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let next_secret = rotated["secret_next"].as_str().expect("successor shown");
    assert!(next_secret.starts_with("whsec_"));

    // Both secrets validate a delivery while the window is open (dual-sign): the
    // header carries one v1 per active secret, and EITHER recomputes a match. The
    // delivery worker opens both sealed secrets and signs with both; here the
    // successor plaintext came back from the rotate response, and the primary is
    // opened from its ciphertext under the suite wrap key.
    let view = get_endpoint(&pool, EndpointScope::Operator(operator), endpoint)
        .await
        .expect("get")
        .expect("present");
    assert!(
        view.secret_next_fp.is_some(),
        "the rotation window is open: both fingerprints present"
    );
    let primary = wrap()
        .open(&enc(&pool, endpoint).await)
        .expect("open primary")
        .to_vec();
    let timestamp = 1_700_000_000;
    let body = [0xAAu8; 16];
    let webhook_id = view.id.to_string();
    let signed = sign_delivery(
        &webhook_id,
        timestamp,
        &body,
        &[primary, next_secret.as_bytes().to_vec()],
    );
    let v1s: Vec<&str> = signed
        .signature
        .split(',')
        .filter_map(|p| p.strip_prefix("v1="))
        .collect();
    assert_eq!(v1s.len(), 2, "the open window carries two v1 values");
    // The successor secret independently recomputes one of the two v1 values over
    // the Standard-Webhooks signed content "{id}.{t}.{body}", so a receiver that
    // deployed only the successor still validates the delivery.
    let mut mac = HmacSha256::new_from_slice(next_secret.as_bytes()).expect("hmac");
    mac.update(format!("{webhook_id}.{timestamp}.").as_bytes());
    mac.update(&body);
    let expected = hex::encode(mac.finalize().into_bytes());
    assert!(
        v1s.contains(&expected.as_str()),
        "the successor secret validates one of the dual-signed v1 values"
    );

    // Commit: 200, the window closes (one fingerprint).
    let (status, _) = call(
        &router,
        post_auth(
            &format!("/control/v1/webhooks/{endpoint}/rotate-secret/commit"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let view = get_endpoint(&pool, EndpointScope::Operator(operator), endpoint)
        .await
        .expect("get")
        .expect("present");
    assert!(
        view.secret_next_fp.is_none(),
        "the rotation window is closed after commit"
    );

    // A second commit with no open window is 404.
    let (status, _) = call(
        &router,
        post_auth(
            &format!("/control/v1/webhooks/{endpoint}/rotate-secret/commit"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Read the sealed primary secret ciphertext for an endpoint (the signer needs the
/// opened plaintext to recompute the dual-sign MAC).
async fn enc(pool: &sqlx::PgPool, endpoint_id: Uuid) -> Vec<u8> {
    sqlx::query_scalar("SELECT secret_enc FROM cw_core.webhook_endpoint WHERE id = $1")
        .bind(endpoint_id)
        .fetch_one(pool)
        .await
        .expect("read secret_enc")
}

/// The control firehose routes require operator authority and are pinned to the
/// owning operator: an account bearer is rejected (plane isolation), and a second
/// operator can never see, read, mutate, or delete the first operator's firehose
/// (a foreign row is reported absent identically to a missing one).
#[tokio::test]
async fn http_firehose_is_operator_only_and_owner_scoped() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let router = gateway_core::api::control_router(control_state(pool.clone()));

    let operator = seed_operator(&pool, "op").await;
    let other_operator = seed_operator(&pool, "other").await;
    let account = seed_account(&pool, operator).await;
    let token = operator_token(&pool, operator).await;
    let other_token = operator_token(&pool, other_operator).await;

    // The operator registers a firehose.
    let (status, created) = call(
        &router,
        post_json(
            "/control/v1/webhooks",
            &token,
            json!({ "url": "https://127.0.0.1/firehose" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let endpoint_id = created["id"].as_str().expect("id").to_string();

    // An account bearer is rejected on the control firehose surface (plane isolation).
    let account_bearer =
        issue_account_key(&pool, account, &["webhooks:read", "webhooks:write"]).await;
    let (status, _) = call(&router, get_auth("/control/v1/webhooks", &account_bearer)).await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "an account bearer may not reach the operator firehose, got {status}"
    );

    // The second operator does not see the first operator's firehose in its list.
    let (status, list) = call(&router, get_auth("/control/v1/webhooks", &other_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        list["data"]
            .as_array()
            .expect("data array")
            .iter()
            .all(|e| e["id"] != endpoint_id),
        "a second operator never sees another operator's firehose"
    );

    // The second operator cannot read it (404, no cross-operator existence oracle).
    let (status, _) = call(
        &router,
        get_auth(&format!("/control/v1/webhooks/{endpoint_id}"), &other_token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The second operator cannot patch or delete it either (404 identically).
    let (status, _) = call(
        &router,
        patch_json(
            &format!("/control/v1/webhooks/{endpoint_id}"),
            &other_token,
            json!({ "status": "paused" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &router,
        delete_auth(&format!("/control/v1/webhooks/{endpoint_id}"), &other_token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The owning operator can still read its own firehose (it was untouched).
    let (status, got) = call(
        &router,
        get_auth(&format!("/control/v1/webhooks/{endpoint_id}"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        got["status"], "active",
        "the foreign patch never reached the owner's row"
    );
}
