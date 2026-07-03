//! HTTP data-plane route behaviour against a real Postgres.
//!
//! These suites drive the actual axum router in-process (no network) and assert
//! the byte-stable wire contract field-by-field: the quote response, the
//! exactly-once publish (202 fresh vs 200 dedup, one debit), the records list
//! envelope and its privacy invariant (anonymous sees only anchored public rows;
//! the owner sees their own pending records and the owner-only `account_id`), the
//! single-record read with content negotiation and ETag, the balance read, and
//! the middleware behaviours (bearer auth, scope, rate-limit, idempotent replay
//! and conflict, the non-committing 402). The assertions are end-state — response
//! status, headers, and JSON shape, plus the resulting ledger/quote DB rows —
//! never log strings.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use cardanowall::poe_standard::{encode_poe_record, EncryptionEnvelope, ItemEntry, PoeRecord};
use gateway_core::api::control::ledger_adjust::{
    apply_adjustment, register_manual_adjustment_kind, AdjustmentOutcome,
};
use gateway_core::api::ids::encode_account_id;
use gateway_core::api::state::{
    ApiConfig, AppState, DynPricingSource, PricingInputs, PricingSource,
};
use gateway_core::ledger::journal::InsertOutcome;
use gateway_core::ledger::journal::{insert_ledger_entry, register_kind, LedgerEntry};
use gateway_core::ledger::quote::{
    create_quote, FixedMarginHook, FxSnapshot, MarginResolution, QuoteRequest,
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

/// The operator-chosen api-key secret prefix (no hardcoded brand string).
const KEY_PREFIX: &str = "tk_live_";

/// A vendor credit kind to fund a test account's balance.
const TOPUP_KIND: &str = "topup_test";

/// A test pricing seam: a fixed network fee, FX snapshot, and margin. The engine
/// computes the COGS and persists the quote; this only supplies the vendor inputs.
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
            // 2 ADA fee.
            network_lovelace: 2_000_000,
            fx: FxSnapshot {
                // $0.50 per ADA.
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

/// A handle to a provisioned tenant: its operator and account ids. Api keys are
/// issued separately (per test) with the scopes and rate limit each test needs.
struct Tenant {
    operator_id: Uuid,
    account_id: Uuid,
}

/// Build the app state with the test pricing seam and a permissive rate limit.
fn state(pool: sqlx::PgPool) -> AppState {
    AppState::new(
        pool,
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..Default::default()
        },
    )
    .with_pricing(Arc::new(TestPricing) as Arc<dyn DynPricingSource>)
}

/// Provision an operator and an account, returning the tenant handle. No api key
/// yet (callers seed keys with the scopes and rate limit they need).
async fn seed_tenant(pool: &sqlx::PgPool) -> Tenant {
    // The publish path enqueues onto the cardano_submit queue, which needs its
    // policy registered (the runtime assembly does this in production). Reconcile
    // is idempotent, so seeding it per tenant is safe.
    gateway_core::runtime::policy::reconcile(pool, &gateway_core::chain::submit::submit_policy())
        .await
        .expect("register submit policy");

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

/// Issue an api key for an account with the given scopes and per-minute limit,
/// returning the bearer secret to present.
async fn issue_key(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    scopes: &[&str],
    rate_limit_per_min: i32,
) -> String {
    // The secret is the operator prefix plus a unique random tail.
    let secret = format!("{KEY_PREFIX}{}", Uuid::now_v7().simple());
    let full = Sha256::digest(secret.as_bytes());
    let lookup = full[..8].to_vec();
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();

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
    .bind(&scopes)
    .bind(rate_limit_per_min)
    .execute(pool)
    .await
    .expect("insert api key");

    secret
}

/// Credit an account's balance in micro-USD through a vendor top-up kind.
async fn credit(pool: &sqlx::PgPool, account_id: Uuid, micros: i64) {
    // Register the vendor credit kind once (idempotent across calls in one db).
    let _ = register_kind(pool, TOPUP_KIND, false, "vendor").await;
    insert_ledger_entry(
        pool,
        &LedgerEntry {
            account_id,
            kind: TOPUP_KIND.to_string(),
            amount_micros: micros,
            r#ref: Some(format!("topup-{}", Uuid::now_v7())),
            quote_id: None,
            metadata: json!({}),
            request_id: None,
        },
    )
    .await
    .expect("credit balance");
}

/// Create a pending quote for an account and return its id.
///
/// The quote is priced for a record size comfortably larger than any record these
/// tests publish (the open and sealed records are a few hundred bytes at most), so
/// the publish-time size contract — a published record must be no larger than the
/// quote was priced for — is satisfied. The price is metered from the network fee
/// and storage bytes, not from `record_bytes`, so the generous size leaves
/// `PUBLISH_COST` unchanged.
async fn make_quote(pool: &sqlx::PgPool, account_id: Uuid) -> Uuid {
    create_quote(
        pool,
        &FixedMarginHook::new(Decimal::new(25, 2)),
        &QuoteRequest {
            account_id,
            record_bytes: 4_096,
            recipient_count: 0,
            file_bytes_total: 0,
            free_storage_bytes: 102_400,
            network_lovelace: 2_000_000,
            fx: FxSnapshot {
                ada_usd_micros: 500_000,
                ar_usd_per_byte_femto: 0,
                source: "test-oracle".to_string(),
            },
            fx_age_seconds: 0,
            request_id: None,
        },
    )
    .await
    .expect("create quote")
    .id
}

/// The cost of one publish at the test pricing (COGS 1_000_000 + 25% margin).
const PUBLISH_COST: i64 = 1_250_000;

/// A minimal valid open Label 309 record (one item, one hash).
fn open_record(seed: u8) -> Vec<u8> {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![seed; 32])],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    encode_poe_record(&record).expect("encode record")
}

/// A recipient-sealed (slots) Label 309 record, for the `sealed` projection.
fn sealed_record(seed: u8) -> Vec<u8> {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![seed; 32])],
            uris: None,
            enc: Some(EncryptionEnvelope::Scheme1(
                cardanowall::poe_standard::EncScheme1 {
                    scheme: 1,
                    aead: "chacha20-poly1305-stream64k".to_string(),
                    nonce: vec![0u8; 24],
                    kem: Some("x25519".to_string()),
                    slots: Some(vec![cardanowall::poe_standard::Slot {
                        epk: Some(vec![1u8; 32]),
                        kem_ct: None,
                        wrap: Some(vec![2u8; 48]),
                    }]),
                    slots_mac: Some(vec![3u8; 32]),
                    passphrase: None,
                },
            )),
        }]),
        ..PoeRecord::default()
    };
    encode_poe_record(&record).expect("encode sealed record")
}

// ---------------------------------------------------------------------------
// Request helpers.
// ---------------------------------------------------------------------------

/// Drive one request through the router and return (status, headers, json body).
async fn call(
    state: &AppState,
    request: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let router = gateway_core::api::router(state.clone());
    let response = router.oneshot(request).await.expect("router responds");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, headers, body)
}

/// A POST request with a JSON body and a bearer credential.
fn post_json(path: &str, secret: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build request")
}

/// A GET request with a bearer credential.
fn get_auth(path: &str, secret: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", format!("Bearer {secret}"))
        .body(Body::empty())
        .expect("build request")
}

/// An anonymous GET request.
fn get_anon(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("build request")
}

// ---------------------------------------------------------------------------
// Quote.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quote_response_carries_the_byte_stable_fields() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;

    let (status, _h, body) = call(
        &st,
        post_json(
            "/api/v1/poe/quote",
            &secret,
            json!({ "record_bytes": 64, "recipient_count": 0, "file_bytes_total": 0 }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // The published SDK REQUIRES amount + currency: the additive quote-response fix.
    assert_eq!(body["amount"], json!(PUBLISH_COST.to_string()));
    assert_eq!(body["currency"], json!("USD"));
    // The web/dashboard fields stay present.
    assert_eq!(body["usd_micros"], json!(PUBLISH_COST.to_string()));
    assert_eq!(body["breakdown"]["network_usd_micros"], json!("1000000"));
    assert_eq!(body["breakdown"]["storage_usd_micros"], json!("0"));
    assert_eq!(body["breakdown"]["service_usd_micros"], json!("250000"));
    // margin_pct is a JSON number (the markup fraction), per the reference.
    assert_eq!(body["margin_pct"], json!(0.25));
    // The quote surfaces the margin's attribution from the resolved pricing inputs.
    assert_eq!(body["margin_source"], json!("test"));
    assert_eq!(body["fx_age_seconds"], json!(12));
    assert!(body["quote_id"].as_str().is_some(), "carries a quote id");
    assert!(body["expires_at"].as_str().is_some(), "carries an expiry");
}

#[tokio::test]
async fn quote_requires_the_create_scope() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    // A read-only key cannot quote.
    let secret = issue_key(&db.pool, t.account_id, &["poe:read"], 1000).await;

    let (status, _h, body) = call(
        &st,
        post_json("/api/v1/poe/quote", &secret, json!({ "record_bytes": 64 })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], json!("insufficient-scope"));
    // The documented 403 extension members: the scope the endpoint requires and
    // the scopes the credential actually carries.
    assert_eq!(body["required"], json!(["poe:create"]));
    assert_eq!(body["granted"], json!(["poe:read"]));
}

// ---------------------------------------------------------------------------
// Publish: exactly-once, 202 vs 200 dedup, one debit.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_fresh_returns_202_with_full_projection() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;
    credit(&db.pool, t.account_id, 5_000_000).await;
    let quote_id = make_quote(&db.pool, t.account_id).await;

    let record = open_record(0xab);
    let (status, _h, body) = call(
        &st,
        post_json(
            "/api/v1/poe/publish",
            &secret,
            json!({ "record": hex::encode(&record), "quote_id": quote_id.to_string() }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::ACCEPTED, "a fresh publish is 202");
    assert!(
        body["id"].as_str().unwrap().starts_with("poe_"),
        "the id is the poe_ wire id"
    );
    assert_eq!(
        body["tx_hash"],
        Value::Null,
        "no tx hash before submit lands"
    );
    assert_eq!(body["status"], json!("submitting"));
    assert_eq!(body["items_count"], json!(1));
    assert_eq!(body["signed"], json!(false));
    assert_eq!(body["sealed"], json!(false));
    assert_eq!(body["conformance_profile"], json!("core"));
    assert_eq!(body["items"][0]["item_idx"], json!(0));
    assert_eq!(
        body["items"][0]["hashes"]["sha2-256"],
        json!(hex::encode([0xab; 32]))
    );
    assert_eq!(
        body["balance_after_usd_micros"],
        json!((5_000_000 - PUBLISH_COST).to_string()),
        "the balance reflects the single debit"
    );

    // The exactly-once writes all committed: a submit job is enqueued, the quote is
    // consumed and bound, and the submitting event is appended.
    let submit_jobs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.job WHERE queue = 'cardano_submit'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(submit_jobs, 1, "exactly one submit job enqueued");
    let (qstatus, bound): (String, Option<Uuid>) =
        sqlx::query_as("SELECT status, poe_record_id FROM cw_core.publish_quote WHERE id = $1")
            .bind(quote_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(qstatus, "consumed");
    assert!(bound.is_some(), "the quote is bound to the record");
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event WHERE subject_kind = 'poe_record' AND event_type = 'submitting'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(events, 1, "exactly one submitting event appended");
}

#[tokio::test]
async fn publish_same_record_twice_dedups_to_200_with_one_debit() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;
    credit(&db.pool, t.account_id, 5_000_000).await;
    let record = open_record(0x11);

    // First publish: fresh (202).
    let quote1 = make_quote(&db.pool, t.account_id).await;
    let (s1, _h1, b1) = call(
        &st,
        post_json(
            "/api/v1/poe/publish",
            &secret,
            json!({ "record": hex::encode(&record), "quote_id": quote1.to_string() }),
        ),
    )
    .await;
    assert_eq!(s1, StatusCode::ACCEPTED);
    let first_id = b1["id"].as_str().unwrap().to_string();

    // Second publish of the SAME record bytes: dedup (200), same id, no new debit.
    let quote2 = make_quote(&db.pool, t.account_id).await;
    let (s2, _h2, b2) = call(
        &st,
        post_json(
            "/api/v1/poe/publish",
            &secret,
            json!({ "record": hex::encode(&record), "quote_id": quote2.to_string() }),
        ),
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "a dedup hit is 200");
    assert_eq!(b2["id"], json!(first_id), "the dedup returns the prior id");

    // Exactly one publish debit landed; the second quote was never consumed.
    let debits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1 AND kind = 'poe_publish'",
    )
    .bind(t.account_id)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(debits, 1, "the dedup applied no second debit");
    let balance: i64 =
        sqlx::query_scalar("SELECT balance_micros FROM cw_core.balance WHERE account_id = $1")
            .bind(t.account_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(balance, 5_000_000 - PUBLISH_COST, "charged exactly once");
    let q2_status: String =
        sqlx::query_scalar("SELECT status FROM cw_core.publish_quote WHERE id = $1")
            .bind(quote2)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(
        q2_status, "pending",
        "the dedup left the second quote unspent"
    );
}

#[tokio::test]
async fn concurrent_same_record_publishes_yield_one_202_one_200_one_debit() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;
    credit(&db.pool, t.account_id, 5_000_000).await;
    let record = open_record(0x22);

    // Two distinct quotes, two concurrent publishes of the SAME record bytes.
    let quote_a = make_quote(&db.pool, t.account_id).await;
    let quote_b = make_quote(&db.pool, t.account_id).await;
    let rec_hex = hex::encode(&record);

    let st_a = st.clone();
    let st_b = st.clone();
    let secret_a = secret.clone();
    let secret_b = secret.clone();
    let hex_a = rec_hex.clone();
    let hex_b = rec_hex.clone();

    let (ra, rb) = tokio::join!(
        async move {
            call(
                &st_a,
                post_json(
                    "/api/v1/poe/publish",
                    &secret_a,
                    json!({ "record": hex_a, "quote_id": quote_a.to_string() }),
                ),
            )
            .await
        },
        async move {
            call(
                &st_b,
                post_json(
                    "/api/v1/poe/publish",
                    &secret_b,
                    json!({ "record": hex_b, "quote_id": quote_b.to_string() }),
                ),
            )
            .await
        }
    );

    let mut statuses = [ra.0, rb.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::ACCEPTED],
        "exactly one fresh (202) and one dedup (200)"
    );

    // Exactly one debit regardless of the race.
    let debits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1 AND kind = 'poe_publish'",
    )
    .bind(t.account_id)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(debits, 1, "the dedup race applied exactly one debit");
    // Exactly one record row exists for the bytes.
    let records: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.poe_record WHERE account_id = $1")
            .bind(t.account_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(records, 1, "the dedup race inserted exactly one record");
}

#[tokio::test]
async fn publish_with_no_funds_is_a_non_committing_402() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;
    // No credit: the balance is zero.
    let quote_id = make_quote(&db.pool, t.account_id).await;

    let (status, _h, body) = call(
        &st,
        post_json(
            "/api/v1/poe/publish",
            &secret,
            json!({ "record": hex::encode(open_record(0x33)), "quote_id": quote_id.to_string() }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(body["code"], json!("insufficient-funds"));
    // The documented 402 extension members: the balance and the uncovered
    // charge ride the problem body as decimal strings. The account is unfunded,
    // so the balance is exactly zero and the required charge is positive.
    assert_eq!(body["balance_usd_micros"], json!("0"));
    let required: i64 = body["required_usd_micros"]
        .as_str()
        .expect("required_usd_micros is a decimal string")
        .parse()
        .expect("required_usd_micros parses as an integer");
    assert!(required > 0, "the uncovered charge is positive");

    // Nothing committed: no debit, no record, the quote is still pending.
    let debits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE kind = 'poe_publish'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(debits, 0);
    let records: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.poe_record")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(records, 0);
    let qstatus: String =
        sqlx::query_scalar("SELECT status FROM cw_core.publish_quote WHERE id = $1")
            .bind(quote_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(qstatus, "pending");
}

// ---------------------------------------------------------------------------
// Idempotency.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn idempotency_replays_a_committed_publish_byte_for_byte() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;
    credit(&db.pool, t.account_id, 5_000_000).await;
    let quote_id = make_quote(&db.pool, t.account_id).await;
    let record = open_record(0x44);
    let body = json!({ "record": hex::encode(&record), "quote_id": quote_id.to_string() });

    let req = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/poe/publish")
            .header("authorization", format!("Bearer {secret}"))
            .header("content-type", "application/json")
            .header("idempotency-key", "key-1")
            .body(Body::from(body.to_string()))
            .unwrap()
    };

    let (s1, _h1, b1) = call(&st, req()).await;
    assert_eq!(s1, StatusCode::ACCEPTED);

    let (s2, h2, b2) = call(&st, req()).await;
    assert_eq!(
        s2,
        StatusCode::ACCEPTED,
        "the replay keeps the original status"
    );
    assert_eq!(b2, b1, "the replay body is byte-identical");
    assert_eq!(
        h2.get("idempotent-replayed").unwrap(),
        "true",
        "the replay is marked"
    );

    // Only one debit and one submit job: the replay did not re-run the handler.
    let debits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE kind = 'poe_publish'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(debits, 1, "the replay applied no second debit");
}

#[tokio::test]
async fn idempotency_key_reused_with_a_different_body_conflicts() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;
    credit(&db.pool, t.account_id, 5_000_000).await;
    let q1 = make_quote(&db.pool, t.account_id).await;
    let q2 = make_quote(&db.pool, t.account_id).await;

    let make = |record: Vec<u8>, quote: Uuid| {
        let b = json!({ "record": hex::encode(&record), "quote_id": quote.to_string() });
        Request::builder()
            .method("POST")
            .uri("/api/v1/poe/publish")
            .header("authorization", format!("Bearer {secret}"))
            .header("content-type", "application/json")
            .header("idempotency-key", "reused")
            .body(Body::from(b.to_string()))
            .unwrap()
    };

    let (s1, _h1, _b1) = call(&st, make(open_record(0x55), q1)).await;
    assert_eq!(s1, StatusCode::ACCEPTED);

    // Same key, different body (a different record): a conflict.
    let (s2, _h2, b2) = call(&st, make(open_record(0x56), q2)).await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(b2["code"], json!("idempotency-key-conflict"));
}

#[tokio::test]
async fn idempotency_does_not_persist_a_non_committing_402() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;
    // No funds at first: the publish 402s.
    let q1 = make_quote(&db.pool, t.account_id).await;
    let record = open_record(0x66);

    let make = |quote: Uuid| {
        let b = json!({ "record": hex::encode(&record), "quote_id": quote.to_string() });
        Request::builder()
            .method("POST")
            .uri("/api/v1/poe/publish")
            .header("authorization", format!("Bearer {secret}"))
            .header("content-type", "application/json")
            .header("idempotency-key", "topup-retry")
            .body(Body::from(b.to_string()))
            .unwrap()
    };

    let (s1, _h1, _b1) = call(&st, make(q1)).await;
    assert_eq!(s1, StatusCode::PAYMENT_REQUIRED);

    // Top up, then retry with the SAME key. The 402 was non-committing, so the
    // retry runs fresh and succeeds rather than replaying the 402.
    credit(&db.pool, t.account_id, 5_000_000).await;
    let q2 = make_quote(&db.pool, t.account_id).await;
    let (s2, _h2, _b2) = call(&st, make(q2)).await;
    assert_eq!(
        s2,
        StatusCode::ACCEPTED,
        "the topped-up retry runs fresh, not a 402 replay"
    );
}

// ---------------------------------------------------------------------------
// Auth + rate limit.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_and_unknown_bearer_collapse_to_401() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let _t = seed_tenant(&db.pool).await;

    // No Authorization header.
    let (s_missing, _h, b_missing) = call(
        &st,
        Request::builder()
            .method("GET")
            .uri("/api/v1/account/balance")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s_missing, StatusCode::UNAUTHORIZED);
    assert_eq!(b_missing["code"], json!("unauthorized"));

    // A well-formed but unknown secret: same 401 (no scanner leakage).
    let (s_unknown, _h2, b_unknown) = call(
        &st,
        get_auth("/api/v1/account/balance", "tk_live_unknownsecret"),
    )
    .await;
    assert_eq!(s_unknown, StatusCode::UNAUTHORIZED);
    assert_eq!(b_unknown["code"], json!("unauthorized"));
}

#[tokio::test]
async fn rate_limit_rejects_past_the_burst_with_headers() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    // A tiny per-minute limit; the burst ceiling is 2x = 2 tokens.
    let secret = issue_key(&db.pool, t.account_id, &["account:read"], 1).await;

    // First two requests fit within the 2x burst.
    let (s1, h1, _b1) = call(&st, get_auth("/api/v1/account/balance", &secret)).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(h1.get("ratelimit-limit").unwrap(), "1");
    let (s2, _h2, _b2) = call(&st, get_auth("/api/v1/account/balance", &secret)).await;
    assert_eq!(s2, StatusCode::OK);

    // The third exceeds the burst ceiling: 429 with Retry-After.
    let (s3, h3, b3) = call(&st, get_auth("/api/v1/account/balance", &secret)).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b3["code"], json!("rate-limited"));
    assert!(h3.get("retry-after").is_some(), "a 429 carries Retry-After");
}

// ---------------------------------------------------------------------------
// Balance.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn balance_is_a_decimal_string() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["account:read"], 1000).await;
    credit(&db.pool, t.account_id, 7_500_000).await;

    let (status, _h, body) = call(&st, get_auth("/api/v1/account/balance", &secret)).await;
    assert_eq!(status, StatusCode::OK);
    // A decimal STRING, never a JSON number (precision past 2^53).
    assert_eq!(body["balance_usd_micros"], json!("7500000"));
    assert!(body["balance_usd_micros"].is_string());
}

// ---------------------------------------------------------------------------
// Ledger history.
// ---------------------------------------------------------------------------

/// The journal's own ordering for an account, as `(id, amount)` text pairs.
/// Pagination assertions compare against this instead of assuming timestamp
/// uniqueness across fast sequential inserts.
async fn journal_order(pool: &sqlx::PgPool, account_id: Uuid) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT id::text, amount_micros::text FROM cw_core.balance_ledger \
         WHERE account_id = $1 ORDER BY occurred_at DESC, id DESC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
    .expect("journal order")
}

#[tokio::test]
async fn ledger_pages_newest_first_with_an_opaque_cursor() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["account:read"], 1000).await;

    // Three credits and one publish debit: four journal rows.
    credit(&db.pool, t.account_id, 1_000_000).await;
    credit(&db.pool, t.account_id, 2_000_000).await;
    credit(&db.pool, t.account_id, 3_000_000).await;
    insert_ledger_entry(
        &db.pool,
        &LedgerEntry {
            account_id: t.account_id,
            kind: "poe_publish".to_string(),
            amount_micros: -500_000,
            r#ref: Some(Uuid::now_v7().to_string()),
            quote_id: None,
            metadata: json!({}),
            request_id: None,
        },
    )
    .await
    .expect("publish debit");

    let expected = journal_order(&db.pool, t.account_id).await;
    assert_eq!(expected.len(), 4);

    // Page 1: the two newest entries, with a resumable cursor.
    let (status, _h, body) = call(&st, get_auth("/api/v1/account/ledger?limit=2", &secret)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], json!("list"));
    assert_eq!(body["url"], json!("/api/v1/account/ledger"));
    assert_eq!(body["has_more"], json!(true));
    let cursor = body["next_cursor"].as_str().expect("cursor").to_string();
    let page1 = body["data"].as_array().expect("data").clone();
    assert_eq!(page1.len(), 2);

    // Page 2: the remaining two, terminal.
    let (status, _h, body) = call(
        &st,
        get_auth(
            &format!("/api/v1/account/ledger?limit=2&cursor={cursor}"),
            &secret,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["has_more"], json!(false));
    assert_eq!(body["next_cursor"], Value::Null);
    let page2 = body["data"].as_array().expect("data").clone();
    assert_eq!(page2.len(), 2);

    // The cursor walk reproduces the journal's own newest-first order exactly:
    // no skip, no repeat, signed decimal-string amounts verbatim.
    let walked: Vec<(String, String)> = page1
        .iter()
        .chain(page2.iter())
        .map(|e| {
            assert!(e["amount_usd_micros"].is_string());
            assert!(e["occurred_at"].is_string());
            (
                e["id"].as_str().expect("id").to_string(),
                e["amount_usd_micros"].as_str().expect("amount").to_string(),
            )
        })
        .collect();
    assert_eq!(walked, expected);
    // The debit travels signed-negative.
    assert!(walked.iter().any(|(_, amount)| amount == "-500000"));
}

#[tokio::test]
async fn ledger_is_scoped_to_the_callers_account() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let owner = seed_tenant(&db.pool).await;
    let other = seed_tenant(&db.pool).await;
    let empty = seed_tenant(&db.pool).await;

    credit(&db.pool, owner.account_id, 4_000_000).await;
    credit(&db.pool, other.account_id, 9_000_000).await;

    // The owner sees exactly their own entries — never the other tenant's.
    let owner_secret = issue_key(&db.pool, owner.account_id, &["account:read"], 1000).await;
    let (status, _h, body) = call(&st, get_auth("/api/v1/account/ledger", &owner_secret)).await;
    assert_eq!(status, StatusCode::OK);
    let data = body["data"].as_array().expect("data");
    let expected = journal_order(&db.pool, owner.account_id).await;
    assert_eq!(data.len(), expected.len());
    for (entry, (id, amount)) in data.iter().zip(expected.iter()) {
        assert_eq!(entry["id"].as_str(), Some(id.as_str()));
        assert_eq!(entry["amount_usd_micros"].as_str(), Some(amount.as_str()));
    }
    assert!(
        !data
            .iter()
            .any(|e| e["amount_usd_micros"] == json!("9000000")),
        "another account's entry leaked into the page"
    );

    // An account with no ledger activity reads an empty terminal page.
    let empty_secret = issue_key(&db.pool, empty.account_id, &["account:read"], 1000).await;
    let (status, _h, body) = call(&st, get_auth("/api/v1/account/ledger", &empty_secret)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"], json!([]));
    assert_eq!(body["has_more"], json!(false));
    assert_eq!(body["next_cursor"], Value::Null);
}

/// A `poe_publish` ledger row inlines its cost breakdown from the consumed
/// quote — the Cardano network fee, the service (margin) fee, and the markup —
/// and the network + service components sum to the publish debit amount. A
/// non-publish row (a storage charge here, with no quote) carries nulls for all
/// three breakdown fields, so the account history can decompose a publish line
/// into figures the user can reconcile while leaving other movements untouched.
#[tokio::test]
async fn ledger_inlines_the_publish_cost_breakdown_and_nulls_it_for_other_kinds() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["account:read"], 1000).await;
    // `storage_upload` is a core ledger kind the baseline migration seeds, so no
    // registration is needed here.
    // Fund the account so the (non-overdrawing) publish and storage debits land.
    credit(&db.pool, t.account_id, 5_000_000).await;

    // A quote captures the per-publish cost components; read them back so the
    // test asserts against the exact figures the engine persisted rather than
    // re-deriving them.
    let quote_id = make_quote(&db.pool, t.account_id).await;
    let (network, service, margin): (i64, i64, Decimal) = sqlx::query_as(
        "SELECT network_usd_micros, service_usd_micros, margin_pct \
         FROM cw_core.publish_quote WHERE id = $1",
    )
    .bind(quote_id)
    .fetch_one(&db.pool)
    .await
    .expect("quote breakdown");
    // The publish line amount is the network + service components; the margin is
    // parked here, not on the (separately billed) storage charge.
    let publish_amount = -(network + service);

    insert_ledger_entry(
        &db.pool,
        &LedgerEntry {
            account_id: t.account_id,
            kind: "poe_publish".to_string(),
            amount_micros: publish_amount,
            r#ref: Some(Uuid::now_v7().to_string()),
            quote_id: Some(quote_id),
            metadata: json!({}),
            request_id: None,
        },
    )
    .await
    .expect("publish debit");
    // A storage charge: raw cost, no quote, so no breakdown to inline.
    insert_ledger_entry(
        &db.pool,
        &LedgerEntry {
            account_id: t.account_id,
            kind: "storage_upload".to_string(),
            amount_micros: -127_400,
            r#ref: Some(Uuid::now_v7().to_string()),
            quote_id: None,
            metadata: json!({}),
            request_id: None,
        },
    )
    .await
    .expect("storage debit");

    let (status, _h, body) = call(&st, get_auth("/api/v1/account/ledger", &secret)).await;
    assert_eq!(status, StatusCode::OK);
    let data = body["data"].as_array().expect("data");

    let publish = data
        .iter()
        .find(|e| e["kind"] == json!("poe_publish"))
        .expect("publish row present");
    // The components travel as decimal strings (precision-safe), the margin as a
    // JSON number fraction, and they sum to the publish debit amount.
    let network_wire: i64 = publish["network_usd_micros"]
        .as_str()
        .expect("network is a string")
        .parse()
        .expect("network parses");
    let service_wire: i64 = publish["service_usd_micros"]
        .as_str()
        .expect("service is a string")
        .parse()
        .expect("service parses");
    assert_eq!(network_wire, network);
    assert_eq!(service_wire, service);
    assert_eq!(
        publish["margin_pct"].as_f64().expect("margin is a number"),
        rust_decimal::prelude::ToPrimitive::to_f64(&margin).expect("margin to f64")
    );
    let publish_amount_wire: i64 = publish["amount_usd_micros"]
        .as_str()
        .expect("amount is a string")
        .parse()
        .expect("amount parses");
    assert_eq!(network_wire + service_wire, -publish_amount_wire);

    let storage = data
        .iter()
        .find(|e| e["kind"] == json!("storage_upload"))
        .expect("storage row present");
    // A non-publish row carries explicit nulls for every breakdown field.
    assert_eq!(storage["network_usd_micros"], Value::Null);
    assert_eq!(storage["service_usd_micros"], Value::Null);
    assert_eq!(storage["margin_pct"], Value::Null);
}

/// A manual-adjustment ref is stored operator-scoped internally, but the
/// account's ledger read serves back the ORIGINAL operator-supplied ref — never
/// the engine's `op:<operator_id>:` prefix, so the operator id never leaks onto an
/// account-facing read. The engine-minted ref of a ref-less adjustment is served
/// verbatim too (it carries no operator prefix).
#[tokio::test]
async fn ledger_read_de_namespaces_the_operator_scoped_adjustment_ref() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");
    let secret = issue_key(&db.pool, t.account_id, &["account:read"], 1000).await;

    // The operator grants the account a balance pinned to its own supplied ref.
    let applied = apply_adjustment(
        &db.pool,
        t.operator_id,
        t.account_id,
        4_000_000,
        "welcome grant",
        1_000_000_000,
        Some("stripe_pi_12345"),
        None,
    )
    .await
    .expect("operator adjustment");
    assert_eq!(applied, AdjustmentOutcome::Applied(InsertOutcome::Inserted));

    // And a ref-less adjustment, whose engine-minted ref must pass through verbatim.
    apply_adjustment(
        &db.pool,
        t.operator_id,
        t.account_id,
        1_000_000,
        "correction",
        1_000_000_000,
        None,
        None,
    )
    .await
    .expect("ref-less adjustment");

    // The row IS stored under the operator-scoped prefix internally.
    let stored: String = sqlx::query_scalar(
        "SELECT ref FROM cw_core.balance_ledger \
         WHERE account_id = $1 AND kind = 'manual_adjustment' AND amount_micros = 4000000",
    )
    .bind(t.account_id)
    .fetch_one(&db.pool)
    .await
    .expect("stored ref");
    assert_eq!(stored, format!("op:{}:stripe_pi_12345", t.operator_id));

    // The account-facing read serves the ORIGINAL ref, and the operator id appears
    // in NO ref the account can see.
    let (status, _h, body) = call(&st, get_auth("/api/v1/account/ledger", &secret)).await;
    assert_eq!(status, StatusCode::OK);
    let data = body["data"].as_array().expect("data");
    let refs: Vec<&str> = data.iter().filter_map(|e| e["ref"].as_str()).collect();
    assert!(
        refs.contains(&"stripe_pi_12345"),
        "the original supplied ref must be served back, got {refs:?}"
    );
    let op_id = t.operator_id.to_string();
    for r in &refs {
        assert!(
            !r.contains(&op_id),
            "the operator id must never leak into an account-facing ref ({r})"
        );
        assert!(
            !r.starts_with("op:"),
            "no account-facing ref may carry the operator-scope prefix ({r})"
        );
    }
}

#[tokio::test]
async fn ledger_rejects_a_malformed_cursor() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["account:read"], 1000).await;

    let (status, _h, body) = call(
        &st,
        get_auth("/api/v1/account/ledger?cursor=bogus--cursor", &secret),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], json!("invalid-cursor"));
}

#[tokio::test]
async fn ledger_requires_the_account_read_scope() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;

    let (status, _h, body) = call(&st, get_auth("/api/v1/account/ledger", &secret)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], json!("insufficient-scope"));
}

// ---------------------------------------------------------------------------
// Records: list envelope, privacy, get + content negotiation.
// ---------------------------------------------------------------------------

/// Index an anchored chain record at `block_height`, optionally owned by an
/// account (a `poe_record` row joined on the same tx hash).
async fn index_anchored(
    pool: &sqlx::PgPool,
    tx_hash: [u8; 32],
    block_height: i64,
    record_bytes: &[u8],
    owner: Option<(Uuid, Uuid)>,
) {
    // The rich chain_records row references the thin cw_api.records anchor; insert
    // the anchor first (the single writer does this in one CTE).
    sqlx::query("INSERT INTO cw_api.records (tx_hash) VALUES ($1)")
        .bind(tx_hash.as_slice())
        .execute(pool)
        .await
        .expect("anchor row");
    sqlx::query(
        "INSERT INTO cw_core.chain_records \
           (tx_hash, block_height, block_time, metadata_cbor, item_count, scheme) \
         VALUES ($1, $2, now(), $3, 1, 0)",
    )
    .bind(tx_hash.as_slice())
    .bind(block_height)
    .bind(record_bytes)
    .execute(pool)
    .await
    .expect("index chain record");

    if let Some((operator_id, account_id)) = owner {
        sqlx::query(
            "INSERT INTO cw_core.poe_record \
               (id, operator_id, account_id, record_bytes, record_sha256, status, tx_hash, block_height) \
             VALUES ($1, $2, $3, $4, $5, 'confirmed', $6, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(operator_id)
        .bind(account_id)
        .bind(record_bytes)
        .bind(Sha256::digest(record_bytes).to_vec())
        .bind(tx_hash.as_slice())
        .bind(block_height)
        .execute(pool)
        .await
        .expect("owner poe_record");
    }
}

#[tokio::test]
async fn records_list_is_the_envelope_and_anonymous_sees_only_anchored() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;

    sqlx::query(
        "INSERT INTO cw_core.cardano_tip (network, tip_block_height) VALUES ('preprod', 110)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    index_anchored(
        &db.pool,
        [0x01; 32],
        100,
        &open_record(1),
        Some((t.operator_id, t.account_id)),
    )
    .await;

    // An owner with a pending (un-anchored) record.
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, account_id, record_bytes, record_sha256, status) \
         VALUES ($1, $2, $3, $4, $5, 'submitting')",
    )
    .bind(Uuid::now_v7())
    .bind(t.operator_id)
    .bind(t.account_id)
    .bind(open_record(2))
    .bind(Sha256::digest(open_record(2)).to_vec())
    .execute(&db.pool)
    .await
    .unwrap();

    // Anonymous: only the anchored row; the envelope is the Stripe/OpenAI shape.
    let (status, _h, body) = call(&st, get_anon("/api/v1/records")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], json!("list"));
    assert_eq!(body["url"], json!("/api/v1/records"));
    assert_eq!(body["has_more"], json!(false));
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 1, "anonymous sees only the one anchored record");
    assert_eq!(data[0]["tx_hash"], json!(hex::encode([0x01; 32])));
    // num_confirmations = tip - block + 1 = 110 - 100 + 1 = 11.
    assert_eq!(data[0]["num_confirmations"], json!(11));
    // account_id is NEVER on the wire for an anonymous reader.
    assert!(data[0].get("account_id").is_none() || data[0]["account_id"].is_null());
}

#[tokio::test]
async fn records_list_shows_owner_pending_and_owner_only_account_id() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:read"], 1000).await;

    sqlx::query(
        "INSERT INTO cw_core.cardano_tip (network, tip_block_height) VALUES ('preprod', 50)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    index_anchored(
        &db.pool,
        [0x02; 32],
        40,
        &open_record(3),
        Some((t.operator_id, t.account_id)),
    )
    .await;

    // The owner's pending un-anchored record.
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, account_id, record_bytes, record_sha256, status) \
         VALUES ($1, $2, $3, $4, $5, 'submitting')",
    )
    .bind(Uuid::now_v7())
    .bind(t.operator_id)
    .bind(t.account_id)
    .bind(open_record(4))
    .bind(Sha256::digest(open_record(4)).to_vec())
    .execute(&db.pool)
    .await
    .unwrap();

    let (status, _h, body) = call(&st, get_auth("/api/v1/records", &secret)).await;
    assert_eq!(status, StatusCode::OK);
    let data = body["data"].as_array().unwrap();
    assert_eq!(
        data.len(),
        2,
        "the owner sees the pending record + the anchored row"
    );

    // The first entry is the prepended pending record (un-anchored).
    let pending = &data[0];
    assert_eq!(pending["status"], json!("submitting"));
    assert_eq!(pending["block_height"], Value::Null);
    assert_eq!(
        pending["account_id"],
        json!(encode_account_id(t.account_id)),
        "the owner sees their own account id"
    );

    // The anchored row carries the owner-only account_id for its owner.
    let anchored = data
        .iter()
        .find(|r| r["block_height"] == json!(40))
        .unwrap();
    assert_eq!(
        anchored["account_id"],
        json!(encode_account_id(t.account_id))
    );
}

#[tokio::test]
async fn non_owner_never_sees_account_id() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let owner = seed_tenant(&db.pool).await;
    let other = seed_tenant(&db.pool).await;
    let other_secret = issue_key(&db.pool, other.account_id, &["poe:read"], 1000).await;

    index_anchored(
        &db.pool,
        [0x03; 32],
        10,
        &open_record(5),
        Some((owner.operator_id, owner.account_id)),
    )
    .await;

    // A different account reads the list: the owner's account_id is never exposed.
    let (status, _h, body) = call(&st, get_auth("/api/v1/records", &other_secret)).await;
    assert_eq!(status, StatusCode::OK);
    let anchored = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tx_hash"] == json!(hex::encode([0x03; 32])))
        .unwrap();
    assert!(
        anchored.get("account_id").is_none() || anchored["account_id"].is_null(),
        "a non-owner never sees who published a record"
    );
}

// ---------------------------------------------------------------------------
// Records count: the exact filtered total, its safety rule, and its public auth.
// ---------------------------------------------------------------------------

/// Index `n` anchored records signed by `signer`, at ascending block heights.
async fn index_signed(pool: &sqlx::PgPool, signer: [u8; 32], n: u8) {
    use gateway_core::chain::records::{insert_chain_record, ChainRecordColumns};
    for byte in 1..=n {
        insert_chain_record(
            pool,
            [byte; 32],
            u64::from(byte) * 10,
            chrono::Utc::now(),
            &open_record(byte),
            &ChainRecordColumns {
                signer_ed25519: Some(signer),
                verified_signers: vec![signer],
                item_count: 1,
                scheme: 0,
            },
        )
        .await
        .expect("index signed record");
    }
}

#[tokio::test]
async fn records_count_is_the_count_envelope_and_matches_the_list_total() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let _t = seed_tenant(&db.pool).await;
    let signer = [0x7a_u8; 32];
    index_signed(&db.pool, signer, 4).await;

    let hex = hex::encode(signer);
    let (status, _h, body) = call(
        &st,
        get_anon(&format!("/api/v1/records/count?signer={hex}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], json!("count"));
    assert_eq!(body["url"], json!("/api/v1/records/count"));
    // The count is a JSON number equal to the number of records by that signer.
    assert_eq!(body["count"], json!(4));

    // Cross-check: the count equals the number of rows the same filter lists.
    let (lstatus, _lh, lbody) = call(&st, get_anon(&format!("/api/v1/records?signer={hex}"))).await;
    assert_eq!(lstatus, StatusCode::OK);
    assert_eq!(
        lbody["data"].as_array().unwrap().len() as u64,
        body["count"].as_u64().unwrap(),
        "the count matches the list total for the same filter"
    );

    // A signer with no records counts zero (a clean 200, not a 404).
    let other = hex::encode([0x99_u8; 32]);
    let (zstatus, _zh, zbody) = call(
        &st,
        get_anon(&format!("/api/v1/records/count?signer={other}")),
    )
    .await;
    assert_eq!(zstatus, StatusCode::OK);
    assert_eq!(zbody["count"], json!(0));
}

#[tokio::test]
async fn records_count_is_public_anonymous_with_no_owner_projection() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let signer = [0x3b_u8; 32];
    index_signed(&db.pool, signer, 2).await;

    // Anonymous succeeds and the body carries no per-account projection at all.
    let hex = hex::encode(signer);
    let (status, _h, body) = call(
        &st,
        get_anon(&format!("/api/v1/records/count?signer={hex}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], json!(2));
    assert!(
        body.get("account_id").is_none(),
        "a count carries no owner-only projection"
    );
}

#[tokio::test]
async fn records_count_requires_a_signer_scope() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let signer = [0x4c_u8; 32];
    index_signed(&db.pool, signer, 3).await;

    // A count's cost is the size of the matching set, so only a signer (which scopes
    // the count to one publisher's records) bounds it. Every other filter shape is
    // refused with 422, because it can still match the whole chain.

    // No filter at all: an unbounded full-index COUNT(*) is refused.
    let (status, _h, body) = call(&st, get_anon("/api/v1/records/count")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], json!("validation-failed"));

    // A scheme-only filter only partitions the chain; it does not bound the count.
    let (s_scheme, _hs, b_scheme) = call(&st, get_anon("/api/v1/records/count?scheme=1")).await;
    assert_eq!(s_scheme, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b_scheme["code"], json!("validation-failed"));

    // A bare block window can span the whole chain, so it does NOT bound the count
    // on its own (an index range scan over the whole table is still O(table)).
    let (s_block, _hb, b_block) = call(&st, get_anon("/api/v1/records/count?from_block=0")).await;
    assert_eq!(s_block, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b_block["code"], json!("validation-failed"));

    // A bare time window likewise does not bound the count.
    let (s_time, _ht, b_time) = call(
        &st,
        get_anon("/api/v1/records/count?from_time=2020-01-01T00:00:00Z"),
    )
    .await;
    assert_eq!(s_time, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b_time["code"], json!("validation-failed"));

    // A signer scope IS accepted, and the block/time/scheme filters narrow it
    // further on top (here a signer + a block window the records fall inside).
    let hex = hex::encode(signer);
    let (s_ok, _ho, b_ok) = call(
        &st,
        get_anon(&format!("/api/v1/records/count?signer={hex}&from_block=0")),
    )
    .await;
    assert_eq!(
        s_ok,
        StatusCode::OK,
        "a signer scope is the accepted bound; other filters narrow it further"
    );
    assert_eq!(b_ok["count"], json!(3));
}

#[tokio::test]
async fn record_get_negotiates_json_and_cbor_with_etag() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let _t = seed_tenant(&db.pool).await;
    let record = open_record(7);
    index_anchored(&db.pool, [0x04; 32], 5, &record, None).await;
    let tx = hex::encode([0x04; 32]);

    // JSON branch.
    let (sj, _hj, bj) = call(&st, get_anon(&format!("/api/v1/records/{tx}"))).await;
    assert_eq!(sj, StatusCode::OK);
    assert_eq!(bj["tx_hash"], json!(tx));
    assert_eq!(bj["scheme"], json!(0));

    // CBOR branch via Accept.
    let cbor_req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/records/{tx}"))
        .header("accept", "application/cbor")
        .body(Body::empty())
        .unwrap();
    let router = gateway_core::api::router(st.clone());
    let resp = router.oneshot(cbor_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/cbor"
    );
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let cbor_body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        cbor_body.as_ref(),
        record.as_slice(),
        "the CBOR is the raw metadata"
    );

    // A matching If-None-Match yields 304.
    let inm_req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/records/{tx}"))
        .header("accept", "application/cbor")
        .header("if-none-match", etag)
        .body(Body::empty())
        .unwrap();
    let router2 = gateway_core::api::router(st.clone());
    let resp2 = router2.oneshot(inm_req).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn record_get_is_oracle_safe_404_for_an_unknown_hash() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let _t = seed_tenant(&db.pool).await;
    let unknown = "ff".repeat(32);

    let (status, _h, body) = call(&st, get_anon(&format!("/api/v1/records/{unknown}"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], json!("not-found"));

    // A malformed hash is a 400, distinct from the oracle-safe 404.
    let (s_bad, _h2, b_bad) = call(&st, get_anon("/api/v1/records/not-a-hash")).await;
    assert_eq!(s_bad, StatusCode::BAD_REQUEST);
    assert_eq!(b_bad["code"], json!("invalid-tx-hash"));
}

// ---------------------------------------------------------------------------
// Anonymous read metering and the global request timeout.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn anonymous_records_reads_meter_against_the_client_address_budget() {
    let db = TestDb::fresh().await.expect("db");
    // A budget of 1/min: the limiter's 2x burst admits two, the third trips.
    let st = AppState::new(
        db.pool.clone(),
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            anon_rate_limit_per_min: 1,
            ..Default::default()
        },
    )
    .with_pricing(Arc::new(TestPricing) as Arc<dyn DynPricingSource>);
    let t = seed_tenant(&db.pool).await;
    let record = open_record(9);
    index_anchored(&db.pool, [0x09; 32], 5, &record, None).await;

    // The oneshot harness carries no connect-info, so every anonymous request
    // meters against the one shared unknown-peer bucket — which is itself the
    // fail-safe under test: an absent peer address means a shared budget, never
    // no metering.
    let (s1, ..) = call(&st, get_anon("/api/v1/records")).await;
    let (s2, ..) = call(&st, get_anon("/api/v1/records")).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    let (s3, h3, b3) = call(&st, get_anon("/api/v1/records")).await;
    assert_eq!(
        s3,
        StatusCode::TOO_MANY_REQUESTS,
        "the anonymous budget throttles the read"
    );
    assert_eq!(b3["code"], json!("rate-limited"));
    assert!(
        h3.contains_key("retry-after"),
        "a throttle names when to retry"
    );

    // The single-record read shares the same per-address budget.
    let tx = hex::encode([0x09; 32]);
    let (s_get, ..) = call(&st, get_anon(&format!("/api/v1/records/{tx}"))).await;
    assert_eq!(s_get, StatusCode::TOO_MANY_REQUESTS);

    // An authenticated caller meters against its own credential, untouched by
    // the exhausted anonymous bucket…
    let secret = issue_key(&db.pool, t.account_id, &["poe:read"], 1000).await;
    let (s_auth, ..) = call(&st, get_auth("/api/v1/records", &secret)).await;
    assert_eq!(s_auth, StatusCode::OK);

    // …and a PRESENT-but-invalid bearer is still rejected as unauthorized,
    // never silently downgraded to an anonymous (throttled or not) read.
    let (s_bad, _hb, b_bad) = call(&st, get_auth("/api/v1/records", "tk_live_nope")).await;
    assert_eq!(s_bad, StatusCode::UNAUTHORIZED);
    assert_eq!(b_bad["code"], json!("unauthorized"));
}

#[tokio::test]
async fn a_bad_bearer_on_the_cbor_record_read_is_rejected_not_treated_as_anonymous() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let _t = seed_tenant(&db.pool).await;
    let record = open_record(3);
    index_anchored(&db.pool, [0x0B; 32], 5, &record, None).await;
    let tx = hex::encode([0x0B; 32]);

    // The CBOR negotiation resolves the caller exactly as the JSON one does: a
    // present-but-invalid credential is a 401, not a silent anonymous read.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/records/{tx}"))
        .header("accept", "application/cbor")
        .header("authorization", "Bearer tk_live_nope")
        .body(Body::empty())
        .unwrap();
    let (status, _h, body) = call(&st, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], json!("unauthorized"));
}

#[tokio::test]
async fn a_wedged_ordinary_request_is_cut_off_at_the_request_timeout() {
    let db = TestDb::fresh().await.expect("db");
    let st = AppState::new(
        db.pool.clone(),
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            request_timeout: std::time::Duration::from_millis(250),
            ..Default::default()
        },
    )
    .with_pricing(Arc::new(TestPricing) as Arc<dyn DynPricingSource>);
    let _t = seed_tenant(&db.pool).await;

    // Wedge the read path: an open transaction holding an exclusive lock on the
    // index table blocks the /records page read for as long as it is held.
    let mut blocker = db.pool.begin().await.expect("blocker txn");
    sqlx::query("LOCK TABLE cw_core.chain_records IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .expect("take the lock");

    let started = std::time::Instant::now();
    let (status, _h, _b) = call(&st, get_anon("/api/v1/records")).await;
    assert_eq!(
        status,
        StatusCode::REQUEST_TIMEOUT,
        "the request-timeout layer cuts the wedged handler off"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "the cutoff fires at the request ceiling, well before the statement timeout"
    );
    blocker.rollback().await.expect("release the lock");
}

// ---------------------------------------------------------------------------
// Publish-batch.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_batch_is_per_record_independent() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;
    // Fund exactly one publish, so the first record commits and the second 402s.
    credit(&db.pool, t.account_id, PUBLISH_COST).await;
    let q1 = make_quote(&db.pool, t.account_id).await;
    let q2 = make_quote(&db.pool, t.account_id).await;

    let (status, _h, body) = call(
        &st,
        post_json(
            "/api/v1/poe/publish-batch",
            &secret,
            json!({
                "records": [
                    { "record": hex::encode(open_record(0x81)), "quote_id": q1.to_string() },
                    { "record": hex::encode(open_record(0x82)), "quote_id": q2.to_string() },
                ]
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "the batch always answers 200");
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    // The first record committed (it has an id), the second failed with 402-class.
    assert_eq!(results[0]["record_idx"], json!(0));
    assert!(results[0]["id"].as_str().unwrap().starts_with("poe_"));
    assert_eq!(results[1]["record_idx"], json!(1));
    assert_eq!(results[1]["error"]["code"], json!("insufficient-funds"));

    // Exactly one debit: the failing record did not roll back the successful one.
    let debits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE kind = 'poe_publish'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        debits, 1,
        "per-record independence: one commit survives the other's 402"
    );
}

#[tokio::test]
async fn publish_sealed_record_projects_the_sealed_profile() {
    let db = TestDb::fresh().await.expect("db");
    let st = state(db.pool.clone());
    let t = seed_tenant(&db.pool).await;
    let secret = issue_key(&db.pool, t.account_id, &["poe:create"], 1000).await;
    credit(&db.pool, t.account_id, 5_000_000).await;
    let quote_id = make_quote(&db.pool, t.account_id).await;

    let (status, _h, body) = call(
        &st,
        post_json(
            "/api/v1/poe/publish",
            &secret,
            json!({ "record": hex::encode(sealed_record(0x91)), "quote_id": quote_id.to_string() }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["sealed"], json!(true));
    assert_eq!(body["conformance_profile"], json!("sealed"));
    // The item carries the sealed envelope projection.
    assert_eq!(body["items"][0]["enc"]["scheme"], json!(1));
    assert_eq!(body["items"][0]["enc"]["slots_count"], json!(1));
}
