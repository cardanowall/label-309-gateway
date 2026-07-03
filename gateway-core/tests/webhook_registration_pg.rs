//! Account-scoped webhook subscription registration against a real Postgres.
//!
//! Two contracts are pinned here:
//!
//!   - **Secret custody.** A created subscription's signing secret is returned
//!     exactly once and stored encrypted at rest: the `secret_enc` column never
//!     contains the plaintext, the `secret_fp` is its SHA-256 fingerprint, and no
//!     read path (list / get) ever returns the secret again, only the fingerprint.
//!     The sealed bytes round-trip back to the plaintext under the same wrap key.
//!   - **Mid-stream cutoff (no backlog replay).** Registration is a plain INSERT
//!     with no cutoff column. An outbox row already fanned out (stamped
//!     `fanned_out_at`) before a subscription is registered is permanently outside
//!     the un-fanned set the fan-out reader drains, so a freshly registered
//!     endpoint never receives an event that was already exploded. An endpoint
//!     registered while a later event is still un-fanned is in that row's match
//!     set.
//!
//! These exercise the registration data layer (`webhook::registration`) and the
//! presence-based fan-out spine (`webhook::fanout`) directly. The signed delivery
//! and the fan-out worker are exercised by their own suites.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use gateway_core::api::state::{ApiConfig, AppState, WebhookState};
use gateway_core::events::append_subject_event;
use gateway_core::testsupport::TestDb;
use gateway_core::webhook::owner::kind;
use gateway_core::webhook::registration::{
    create_endpoint, get_endpoint, list_endpoints, patch_endpoint, soft_delete_endpoint,
    EndpointChange, EndpointPatch, EndpointScope, EndpointStatus, NewEndpoint,
};
use gateway_core::webhook::secret::SecretWrap;
use gateway_core::webhook::{claim_unfanned, resolve_owner, stamp_fanned_out, OwnerResolution};

/// A deterministic wrap key for the suite. In production this is minted at
/// bootstrap and held in the operator keyring; a fixed key here keeps the
/// encrypt-at-rest assertions reproducible.
fn wrap() -> SecretWrap {
    SecretWrap::new("whk_test", [0x5au8; 32])
}

/// Seed an operator and return its id.
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

/// Seed an account anchor plus its `account_detail` satellite under `operator_id`
/// and return the account id.
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

/// A standard new-endpoint input for `account_id`.
fn new_endpoint(account_id: Uuid) -> NewEndpoint {
    NewEndpoint {
        scope: EndpointScope::Account(account_id),
        url: "https://hooks.example.test/ingest".to_string(),
        enabled_events: vec!["poe_status_changed".to_string()],
        label: Some("primary".to_string()),
    }
}

/// The signing secret is returned exactly once at create, stored encrypted at
/// rest (never as plaintext, never as the secret bytes), and the stored
/// fingerprint matches. No read path returns the secret again.
#[tokio::test]
async fn secret_is_shown_once_and_encrypted_at_rest() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;

    let created = create_endpoint(&pool, &w, &new_endpoint(account_id))
        .await
        .expect("create endpoint");

    // The create response carries the plaintext secret exactly once.
    assert!(
        created.secret.starts_with("whsec_"),
        "the create response returns the plaintext signing secret"
    );
    assert!(
        !created.secret.is_empty(),
        "the secret carries an entropy tail"
    );

    // The stored row encrypts the secret: the secret_enc bytes do NOT contain the
    // plaintext, and the stored fingerprint is sha256(secret).
    let (secret_enc, secret_fp): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT secret_enc, secret_fp FROM cw_core.webhook_endpoint WHERE id = $1")
            .bind(created.id)
            .fetch_one(&pool)
            .await
            .expect("read stored secret columns");

    assert!(
        !contains_subslice(&secret_enc, created.secret.as_bytes()),
        "the encrypted column must not embed the plaintext secret"
    );
    use sha2::{Digest, Sha256};
    assert_eq!(
        secret_fp,
        Sha256::digest(created.secret.as_bytes()).to_vec(),
        "the stored fingerprint is sha256(secret)"
    );

    // The sealed bytes round-trip back to the plaintext under the same wrap key,
    // proving the encrypt-at-rest is a real seal, not a discard.
    let opened = w.open(&secret_enc).expect("open the stored ciphertext");
    assert_eq!(
        opened.as_slice(),
        created.secret.as_bytes(),
        "the stored ciphertext decrypts to the minted secret"
    );

    // No read path returns the secret again: the get/list views carry only the
    // fingerprint.
    let view = get_endpoint(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(view.secret_fp, secret_fp, "get returns the fingerprint");
    assert!(
        view.secret_next_fp.is_none(),
        "no rotation window is open at create"
    );

    let listed = list_endpoints(&pool, EndpointScope::Account(account_id))
        .await
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, created.id);
    assert_eq!(
        listed[0].secret_fp, secret_fp,
        "list returns the fingerprint"
    );
}

/// A subscription is owner-scoped end to end: an endpoint created for one account
/// is invisible to another account's list/get, so one tenant can never read
/// another tenant's subscription.
#[tokio::test]
async fn endpoints_are_owner_scoped() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_a = seed_account(&pool, operator_id).await;
    let account_b = seed_account(&pool, operator_id).await;

    let created = create_endpoint(&pool, &w, &new_endpoint(account_a))
        .await
        .expect("create for account A");

    // Account B cannot see account A's endpoint by id or in its list.
    assert!(
        get_endpoint(&pool, EndpointScope::Account(account_b), created.id)
            .await
            .expect("get")
            .is_none(),
        "another account's endpoint reads as absent (no cross-tenant oracle)"
    );
    assert!(
        list_endpoints(&pool, EndpointScope::Account(account_b))
            .await
            .expect("list")
            .is_empty(),
        "another account's list does not carry the endpoint"
    );
}

/// Lifecycle: pause (active -> paused) retains the row but is reflected in reads;
/// re-activating resets the auto-disable failure counter; soft-delete makes the
/// row read as absent and is idempotent against a second delete.
#[tokio::test]
async fn lifecycle_pause_reactivate_and_soft_delete() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let created = create_endpoint(&pool, &w, &new_endpoint(account_id))
        .await
        .expect("create");

    // Pause: the read reflects the paused status, the row is retained.
    let change = patch_endpoint(
        &pool,
        EndpointScope::Account(account_id),
        created.id,
        &EndpointPatch {
            status: Some(EndpointStatus::Paused),
            ..EndpointPatch::default()
        },
    )
    .await
    .expect("pause");
    assert_eq!(change, EndpointChange::Changed);
    let view = get_endpoint(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(view.status, EndpointStatus::Paused);

    // Drive the failure accumulator up, then re-activate and assert it resets.
    sqlx::query("UPDATE cw_core.webhook_endpoint SET consecutive_failures = 7 WHERE id = $1")
        .bind(created.id)
        .execute(&pool)
        .await
        .expect("bump failures");
    let change = patch_endpoint(
        &pool,
        EndpointScope::Account(account_id),
        created.id,
        &EndpointPatch {
            status: Some(EndpointStatus::Active),
            ..EndpointPatch::default()
        },
    )
    .await
    .expect("reactivate");
    assert_eq!(change, EndpointChange::Changed);
    let view = get_endpoint(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(view.status, EndpointStatus::Active);
    assert_eq!(
        view.consecutive_failures, 0,
        "re-activating resets the auto-disable accumulator"
    );

    // Soft-delete: the row reads as absent; a second delete is a no-op NotFound.
    let change = soft_delete_endpoint(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("delete");
    assert_eq!(change, EndpointChange::Changed);
    assert!(
        get_endpoint(&pool, EndpointScope::Account(account_id), created.id)
            .await
            .expect("get")
            .is_none(),
        "a soft-deleted endpoint reads as absent"
    );
    let change = soft_delete_endpoint(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("second delete");
    assert_eq!(
        change,
        EndpointChange::NotFound,
        "deleting an already-deleted endpoint is a no-op NotFound"
    );
}

/// A PATCH may replace the event filter and the URL, and set or clear the label.
#[tokio::test]
async fn patch_replaces_filter_url_and_label() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let created = create_endpoint(&pool, &w, &new_endpoint(account_id))
        .await
        .expect("create");

    let change = patch_endpoint(
        &pool,
        EndpointScope::Account(account_id),
        created.id,
        &EndpointPatch {
            enabled_events: Some(vec!["balance_changed".to_string()]),
            url: Some("https://hooks.example.test/v2".to_string()),
            label: Some(None), // clear the label
            ..EndpointPatch::default()
        },
    )
    .await
    .expect("patch");
    assert_eq!(change, EndpointChange::Changed);

    let view = get_endpoint(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(view.enabled_events, vec!["balance_changed".to_string()]);
    assert_eq!(view.url, "https://hooks.example.test/v2");
    assert!(view.label.is_none(), "label cleared by a null patch");
}

/// No backlog replay. An outbox row already fanned out (stamped) before a
/// subscription is registered is permanently outside the un-fanned set, so a
/// freshly registered endpoint never receives an already-exploded event. A
/// subscription registered while a later event is still un-fanned is in that
/// later row's match set.
///
/// This pins the presence-based cutoff at the registration boundary: there is no
/// cutoff column; the boundary is purely "did the subscription exist when this
/// outbox row was stamped?".
#[tokio::test]
async fn registration_cutoff_excludes_already_fanned_events() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;

    // Event A is appended and FANNED OUT (stamped) before any endpoint exists. The
    // subject is the account itself (a balance.changed-style event).
    let ev_a = append_subject_event(
        &pool,
        kind::ACCOUNT,
        &account_id.to_string(),
        "balance.changed",
        &serde_json::json!({ "marker": "A" }),
    )
    .await
    .expect("append A");
    let outbox_a = locate_outbox(&pool, &ev_a).await;

    // Stamp A as fanned out (the fan-out reader claims it before any endpoint
    // exists, so its match set is empty).
    {
        let mut tx = pool.begin().await.expect("begin");
        let batch = claim_unfanned(&mut tx, 10).await.expect("claim A");
        assert!(
            batch.iter().any(|r| r.id == outbox_a),
            "A is in the un-fanned set before any endpoint exists"
        );
        for row in &batch {
            stamp_fanned_out(&mut tx, row.id).await.expect("stamp");
        }
        tx.commit().await.expect("commit stamp A");
    }

    // NOW register the endpoint. A is already stamped, so it is permanently out of
    // the un-fanned set the fan-out reader drains.
    let created = create_endpoint(&pool, &w, &new_endpoint(account_id))
        .await
        .expect("create endpoint after A");

    // The owner resolves to this account, so the endpoint WOULD match an event for
    // it — the only reason A is not delivered is the presence-based cutoff (A was
    // already fanned out before the endpoint existed).
    let owner = match resolve_owner(&pool, kind::ACCOUNT, &account_id.to_string())
        .await
        .expect("resolve")
    {
        OwnerResolution::Resolved(owner) => owner,
        OwnerResolution::NotDeliverable => panic!("the account owner must resolve"),
    };
    assert_eq!(owner.account_id, Some(account_id));

    // Event B is appended AFTER the endpoint exists and is still un-fanned.
    let ev_b = append_subject_event(
        &pool,
        kind::ACCOUNT,
        &account_id.to_string(),
        "balance.changed",
        &serde_json::json!({ "marker": "B" }),
    )
    .await
    .expect("append B");
    let outbox_b = locate_outbox(&pool, &ev_b).await;

    // The un-fanned set now contains ONLY B (A is permanently stamped). This is the
    // no-backlog-replay guarantee: the freshly registered endpoint's fan-out reader
    // will see B and never A.
    let mut tx = pool.begin().await.expect("begin");
    let unfanned = claim_unfanned(&mut tx, 100).await.expect("claim un-fanned");
    tx.rollback().await.expect("rollback (peek only)");

    let unfanned_ids: Vec<Uuid> = unfanned.iter().map(|r| r.id).collect();
    assert!(
        !unfanned_ids.contains(&outbox_a),
        "an already-fanned-out event (A) is never re-presented for fan-out: no backlog replay"
    );
    assert!(
        unfanned_ids.contains(&outbox_b),
        "an event appended after the endpoint exists (B) is in the un-fanned set, so it is delivered"
    );

    // The endpoint is the live, active, account-scoped subscription B would match.
    // (The fan-out worker's actual delivery insert is a downstream concern; here we
    // confirm the registration produced a matchable subscription for the owner.)
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.webhook_endpoint \
         WHERE scope_kind = 'account' AND account_id = $1 \
           AND status = 'active' AND deleted_at IS NULL",
    )
    .bind(account_id)
    .fetch_one(&pool)
    .await
    .expect("count live endpoints");
    assert_eq!(
        live, 1,
        "the registered endpoint is a live match for owner B"
    );
    let _ = created.id;
}

// ---------------------------------------------------------------------------
// HTTP route-level tests: drive the actual axum router with an account bearer.
// ---------------------------------------------------------------------------

/// Build app state with the webhook seam wired under explicit egress knobs.
fn state_with_webhook_flags(
    pool: sqlx::PgPool,
    allow_insecure_http: bool,
    egress_allow_loopback: bool,
) -> AppState {
    AppState::new(
        pool,
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..Default::default()
        },
    )
    .with_webhook(WebhookState::new(
        Arc::new(SecretWrap::new("whk_test", [0x5au8; 32])),
        allow_insecure_http,
        egress_allow_loopback,
    ))
}

/// Build app state with the webhook seam wired (loopback allowed so a test URL
/// passes the SSRF guard).
fn state_with_webhook(pool: sqlx::PgPool) -> AppState {
    // The suite's HTTPS loopback URLs need only the range-block seam.
    state_with_webhook_flags(pool, false, true)
}

/// Issue an api key for an account carrying `scopes`, returning the bearer secret.
async fn issue_key(pool: &sqlx::PgPool, account_id: Uuid, scopes: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let secret = format!("wh_test_{}", Uuid::now_v7().simple());
    let full = Sha256::digest(secret.as_bytes());
    let lookup = full[..8].to_vec();
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "INSERT INTO cw_core.api_key \
           (id, account_id, prefix, key_lookup, key_hash_sha256, scopes, rate_limit_per_min) \
         VALUES ($1, $2, 'wh_test_', $3, $4, $5, 1000)",
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

/// Drive one request through the data-plane router and return (status, json body).
async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, Value) {
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

fn post_json(path: &str, secret: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build request")
}

fn patch_json(path: &str, secret: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(path)
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build request")
}

fn get_auth(path: &str, secret: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", format!("Bearer {secret}"))
        .body(Body::empty())
        .expect("build request")
}

fn delete_auth(path: &str, secret: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(path)
        .header("authorization", format!("Bearer {secret}"))
        .body(Body::empty())
        .expect("build request")
}

/// The full HTTP lifecycle over the router: create (201, secret once), list
/// (fingerprint only, never the secret), pause via PATCH, delete (204).
#[tokio::test]
async fn http_create_lists_secret_once_then_pause_and_delete() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    let st = state_with_webhook(pool.clone());

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let secret = issue_key(&pool, account_id, &["webhooks:read", "webhooks:write"]).await;

    // Create: 201 with the plaintext secret returned exactly once.
    let (status, body) = call(
        &st,
        post_json(
            "/api/v1/webhooks",
            &secret,
            json!({ "url": "https://127.0.0.1/ingest", "enabled_events": ["poe_status_changed"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let endpoint_id = body["id"].as_str().expect("created id").to_string();
    let plaintext = body["secret"].as_str().expect("create returns the secret");
    assert!(plaintext.starts_with("whsec_"));

    // The DB row stores the secret encrypted, never the plaintext.
    let secret_enc: Vec<u8> =
        sqlx::query_scalar("SELECT secret_enc FROM cw_core.webhook_endpoint WHERE id = $1::uuid")
            .bind(&endpoint_id)
            .fetch_one(&pool)
            .await
            .expect("read secret_enc");
    assert!(
        !contains_subslice(&secret_enc, plaintext.as_bytes()),
        "the stored ciphertext must not embed the plaintext secret"
    );

    // List: carries the fingerprint, NEVER the secret.
    let (status, body) = call(&st, get_auth("/api/v1/webhooks", &secret)).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], json!(endpoint_id));
    assert!(
        items[0]["secret_fp"].as_str().is_some(),
        "the list carries the secret fingerprint"
    );
    assert!(
        items[0].get("secret").is_none(),
        "the list must NEVER return the secret plaintext"
    );

    // Get one: same — fingerprint, never the secret.
    let (status, body) = call(
        &st,
        get_auth(&format!("/api/v1/webhooks/{endpoint_id}"), &secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("secret").is_none(),
        "get must not return the secret"
    );
    assert!(body["secret_fp"].as_str().is_some());

    // Pause via PATCH.
    let (status, body) = call(
        &st,
        patch_json(
            &format!("/api/v1/webhooks/{endpoint_id}"),
            &secret,
            json!({ "status": "paused" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], json!("paused"));

    // Delete: 204, then a re-read is 404.
    let (status, _b) = call(
        &st,
        delete_auth(&format!("/api/v1/webhooks/{endpoint_id}"), &secret),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _b) = call(
        &st,
        get_auth(&format!("/api/v1/webhooks/{endpoint_id}"), &secret),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a deleted endpoint reads 404"
    );
}

/// The write routes require `webhooks:write`; a read-only key is rejected with a
/// 403 insufficient-scope.
#[tokio::test]
async fn http_create_requires_the_write_scope() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    let st = state_with_webhook(pool.clone());

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    // Only the read scope.
    let secret = issue_key(&pool, account_id, &["webhooks:read"]).await;

    let (status, body) = call(
        &st,
        post_json(
            "/api/v1/webhooks",
            &secret,
            json!({ "url": "https://127.0.0.1/ingest" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], json!("insufficient-scope"));
}

/// An unknown event-filter name is rejected at create with 422
/// invalid-event-filter; a loopback URL with loopback disallowed is rejected with
/// invalid-webhook-url by the SSRF guard.
#[tokio::test]
async fn http_create_rejects_bad_filter_and_unsafe_url() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let secret = issue_key(&pool, account_id, &["webhooks:write"]).await;

    // Bad event filter, with loopback allowed so the URL is not the rejection.
    let st_loopback = state_with_webhook(pool.clone());
    let (status, body) = call(
        &st_loopback,
        post_json(
            "/api/v1/webhooks",
            &secret,
            json!({ "url": "https://127.0.0.1/ingest", "enabled_events": ["not_a_real_event"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], json!("invalid-event-filter"));

    // A loopback URL with loopback NOT allowed is rejected by the SSRF guard.
    let st_strict = AppState::new(
        pool.clone(),
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..Default::default()
        },
    )
    .with_webhook(WebhookState::new(
        Arc::new(SecretWrap::new("whk_test", [0x5au8; 32])),
        false,
        false, // loopback NOT allowed
    ));
    let (status, body) = call(
        &st_strict,
        post_json(
            "/api/v1/webhooks",
            &secret,
            json!({ "url": "https://127.0.0.1/ingest" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], json!("invalid-webhook-url"));
}

/// The self-host `allow_insecure_http` knob loosens ONLY the URL scheme: a
/// registration targeting a blocked range over plain HTTP is refused exactly as
/// in production, while plain HTTP to a public address registers. A tenant with
/// `webhooks:write` on a self-hosted deployment therefore cannot point the
/// delivery egress at loopback, RFC 1918, or the cloud-metadata IP.
#[tokio::test]
async fn http_create_with_insecure_http_keeps_the_range_block() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    // Self-host posture: plain HTTP permitted, range-block NOT loosened.
    let st = state_with_webhook_flags(pool.clone(), true, false);

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let secret = issue_key(&pool, account_id, &["webhooks:write"]).await;

    for url in [
        "http://127.0.0.1/ingest",
        "http://10.0.0.9/ingest",
        "http://169.254.169.254/latest/meta-data",
    ] {
        let (status, body) = call(
            &st,
            post_json("/api/v1/webhooks", &secret, json!({ "url": url })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{url} must be refused by the SSRF guard despite allow_insecure_http"
        );
        assert_eq!(body["code"], json!("invalid-webhook-url"));
    }

    // Plain HTTP to a public address is exactly what the knob is for.
    let (status, body) = call(
        &st,
        post_json(
            "/api/v1/webhooks",
            &secret,
            json!({ "url": "http://8.8.8.8/ingest" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a public plain-HTTP target registers under allow_insecure_http"
    );
    assert!(body["secret"].as_str().is_some());
}

/// When webhooks are not enabled (no seam wired), every webhook route reports
/// 503 webhooks-disabled.
#[tokio::test]
async fn http_routes_report_disabled_when_feature_off() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();
    // No `.with_webhook(...)`: the feature is off.
    let st = AppState::new(
        pool.clone(),
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..Default::default()
        },
    );

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let secret = issue_key(&pool, account_id, &["webhooks:read", "webhooks:write"]).await;

    let (status, body) = call(
        &st,
        post_json(
            "/api/v1/webhooks",
            &secret,
            json!({ "url": "https://hooks.example.test/x" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], json!("webhooks-disabled"));
}

/// Locate the `delivery_outbox` row id for an appended event.
async fn locate_outbox(pool: &sqlx::PgPool, ev: &gateway_core::events::SubjectEvent) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM cw_core.delivery_outbox \
         WHERE subject_kind = $1 AND subject_id = $2 AND subject_seq = $3",
    )
    .bind(&ev.subject_kind)
    .bind(&ev.subject_id)
    .bind(ev.subject_seq)
    .fetch_one(pool)
    .await
    .expect("locate outbox row")
}

/// A naive subslice search for the encrypt-at-rest leak assertion.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
