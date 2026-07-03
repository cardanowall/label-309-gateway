//! End-to-end coverage of the content-upload slice against a real Postgres.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Three layers are exercised: the receipt-ledger primitives (`persist_receipt` /
//! `lookup_receipt`, including dedup convergence) directly against the DB; the full
//! `/api/v1/poe/uploads` route booted over the real data-plane router with a
//! recording mock backend AND a real keyring signing the data item once in the
//! route; and the billing/concurrency contract (reserve -> hold -> charge once, live
//! retry attaches, idempotency-key batch replay, definite-fail no-charge,
//! ambiguous-leave-reserved, the poll route's terminal states + ownership 404).
//!
//! The signing key, the funding source, and its grant are real: the route resolves
//! the funding capability, signs through the keyring's Arweave entry, reserves and
//! holds before the (mock) provider is paid, and commits the charge on the 2xx. So
//! the billing assertions are over the actual ledger rows the saga writes.
//!
//! Live legs against the dev ArLocal emulator and a Turbo free-tier endpoint run
//! only when their environment variables are set.

#![cfg(feature = "pg-tests")]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use age::secrecy::SecretString;
use ans104::{Ans104Signer, ArweaveJwkSigner, SignedEnvelope};
use gateway_core::api::middleware::auth::hash_secret;
use gateway_core::api::router;
use gateway_core::api::state::{
    ApiConfig, AppState, DynPricingSource, PricingInputs, PricingSource, StorageState,
    UploadSigning,
};
use gateway_core::storage::{
    insert_credit_entry, lookup_receipt, persist_receipt, ArLocalBackend, AuthorizedFunding,
    CreditEntry, CreditKind, StorageBackend, StorageBackendExt, StorageError, StorageReceipt,
    TurboBackend, UploadLimits, UploadSessionLimits, DEFAULT_MIN_CHUNK_BYTES, MAX_SESSION_CHUNKS,
};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::{arweave_address, unlock, UnlockedKeyring};
use rust_decimal::Decimal;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use uuid::Uuid;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Fixtures and shared config.
// ---------------------------------------------------------------------------

/// The canonical backend the storage suites exercise (the Turbo rail). Matches the
/// mock backend's `name()` and the funding source's `backend` column.
const BACKEND: &str = "turbo";

/// The per-byte storage price the test FX charges, in femto-USD per byte. A nonzero
/// price makes the chargeable-bytes branch real; this value makes one chargeable
/// byte cost one micro-USD (1e9 femto = 1 micro).
const AR_USD_PER_BYTE_FEMTO: i64 = 1_000_000_000;

/// The throwaway Arweave JWK every keyring in this suite signs with (the same
/// fixture the keyring round-trip and ans104 tests use).
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// The Arweave address the fixture JWK derives to (the funding source's address and
/// the keyring entry the route resolves a signer through).
fn fixture_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

/// A low scrypt work factor so the in-test keyring envelope encrypts/decrypts fast.
const TEST_SCRYPT_LOG_N: u8 = 4;

/// Build an unlocked keyring holding the fixture Arweave funding key.
fn unlocked_keyring() -> Arc<UnlockedKeyring> {
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            {
                "kind": "arweave-rsa",
                "label": "storage",
                "address": fixture_arweave_address(),
                "secret": TEST_JWK_JSON,
            }
        ]
    })
    .to_string();
    let mut recipient = age::scrypt::Recipient::new(SecretString::from("test-pass".to_string()));
    recipient.set_work_factor(TEST_SCRYPT_LOG_N);
    let ciphertext = age::encrypt(&recipient, json.as_bytes()).expect("encrypt keyring");
    // Arweave entries do not check a Cardano network; mainnet is arbitrary here.
    let keyring = unlock(
        &ciphertext,
        Zeroizing::new("test-pass".to_string()),
        Network::Mainnet,
    )
    .expect("the fixture keyring unlocks");
    Arc::new(keyring)
}

/// A test pricing seam: the FX the storage charge is priced from. Only the per-byte
/// storage price matters to the upload path.
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
            network_lovelace: 0,
            fx: gateway_core::ledger::quote::FxSnapshot {
                ada_usd_micros: 500_000,
                ar_usd_per_byte_femto: AR_USD_PER_BYTE_FEMTO,
                source: "test-oracle".to_string(),
            },
            fx_age_seconds: 1,
            margin: gateway_core::ledger::quote::MarginResolution {
                margin_pct: Decimal::ZERO,
                margin_source: "test".to_string(),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Seeding.
// ---------------------------------------------------------------------------

/// Seed an operator + account and return both ids.
async fn seed_account(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
    let operator_id = Uuid::now_v7();
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'test')")
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert operator");
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
    (operator_id, account_id)
}

/// Register a funding source owned by `operator` for the fixture address plus a live
/// service grant, returning the source id. The address is the JWK's derived address,
/// so the route's keyring resolves a signer for it.
async fn seed_funded_source(pool: &sqlx::PgPool, operator: Uuid) -> Uuid {
    seed_funded_source_for_backend(pool, operator, BACKEND).await
}

/// Like [`seed_funded_source`], but for a specific backend name. The funding grant
/// is scoped to the backend, and the route resolves it by the live backend's
/// `name()`, so a test against a non-default backend (the ArLocal emulator) must
/// seed the source and grant under that backend or the funding lookup misses.
async fn seed_funded_source_for_backend(
    pool: &sqlx::PgPool,
    operator: Uuid,
    backend: &str,
) -> Uuid {
    let source_id = Uuid::now_v7();
    let address = fixture_arweave_address();
    sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'primary', $3, $4, $4)",
    )
    .bind(source_id)
    .bind(operator)
    .bind(backend)
    .bind(&address)
    .execute(pool)
    .await
    .expect("seed funding source");

    sqlx::query(
        "INSERT INTO cw_core.storage_grant \
           (id, funding_source_id, backend, scope_kind) \
         VALUES ($1, $2, $3, 'service')",
    )
    .bind(Uuid::now_v7())
    .bind(source_id)
    .bind(backend)
    .execute(pool)
    .await
    .expect("seed service grant");

    source_id
}

/// Stamp a believed winc balance and a provider fundable-bytes capacity on a source,
/// so `affords` passes for the chargeable bytes the tests upload.
async fn fund_credit(pool: &sqlx::PgPool, source: Uuid, winc: i64, fundable_bytes: i64) {
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
    .expect("seed winc balance");
    sqlx::query(
        "UPDATE cw_core.storage_credit SET fundable_bytes = $2 WHERE funding_source_id = $1",
    )
    .bind(source)
    .bind(fundable_bytes)
    .execute(pool)
    .await
    .expect("stamp fundable bytes");
}

/// Credit the account's USD balance so a storage hold does not overdraw.
async fn fund_balance(pool: &sqlx::PgPool, account_id: Uuid, micros: i64) {
    gateway_core::ledger::journal::register_kind(pool, "test_topup", true, "test")
        .await
        .expect("register topup kind");
    gateway_core::ledger::journal::insert_ledger_entry(
        pool,
        &gateway_core::ledger::journal::LedgerEntry {
            account_id,
            kind: "test_topup".to_string(),
            amount_micros: micros,
            r#ref: Some(format!("topup-{}", Uuid::now_v7())),
            quote_id: None,
            metadata: serde_json::json!({}),
            request_id: None,
        },
    )
    .await
    .expect("seed balance");
}

/// Issue an api-key for an account with the given scopes; returns the bearer secret.
async fn issue_key(pool: &sqlx::PgPool, account_id: Uuid, scopes: &[&str]) -> String {
    let secret = format!("op_{}", Uuid::now_v7().simple());
    let (lookup, hash) = hash_secret(&secret);
    let scopes_owned: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "INSERT INTO cw_core.api_key \
           (id, account_id, prefix, key_lookup, key_hash_sha256, scopes, rate_limit_per_min) \
         VALUES ($1, $2, 'op_', $3, $4, $5, 6000)",
    )
    .bind(Uuid::now_v7())
    .bind(account_id)
    .bind(&lookup)
    .bind(&hash)
    .bind(&scopes_owned)
    .execute(pool)
    .await
    .expect("insert api key");
    secret
}

// ---------------------------------------------------------------------------
// State + HTTP helpers.
// ---------------------------------------------------------------------------

/// The durable staging directory for a test state, kept alive by the returned
/// `TempDir` so the promoted files persist for the duration of the test.
struct TestState {
    state: AppState,
    _durable: tempfile::TempDir,
}

/// Build full app state: the backend, the pricing seam, and the upload-signing seam
/// (keyring + durable dir + deadlines). `lease_secs` is the claim-lease TTL.
fn state_with(pool: sqlx::PgPool, backend: Arc<dyn StorageBackend>, lease_secs: u64) -> TestState {
    state_with_config(
        pool,
        backend,
        lease_secs,
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..ApiConfig::default()
        },
    )
}

/// Like [`state_with`], with an explicit `ApiConfig` for tests that override the
/// session tunables.
fn state_with_config(
    pool: sqlx::PgPool,
    backend: Arc<dyn StorageBackend>,
    lease_secs: u64,
    config: ApiConfig,
) -> TestState {
    let durable = tempfile::tempdir().expect("durable dir");
    let signing = UploadSigning::new(
        unlocked_keyring(),
        durable.path().to_path_buf(),
        Duration::from_secs(30),
        Duration::from_secs(lease_secs),
    );
    let storage = StorageState::new(backend).with_signing(signing);
    let state = AppState::new(pool, config)
        .with_pricing(Arc::new(TestPricing) as Arc<dyn DynPricingSource>)
        .with_storage(storage);
    TestState {
        state,
        _durable: durable,
    }
}

/// Boot the data-plane router over a state on an ephemeral port.
async fn serve(state: AppState) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

/// A parsed multipart file part.
struct Part {
    field: String,
    content_type: String,
    bytes: Vec<u8>,
}

/// Frame a `multipart/form-data` body and its boundary from the given parts.
fn build_multipart(parts: &[Part]) -> (String, Vec<u8>) {
    let boundary = format!("----gwtest{}", Uuid::now_v7().simple());
    let mut body: Vec<u8> = Vec::new();
    for part in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"; filename=\"{}.bin\"\r\n",
                part.field, part.field
            )
            .as_bytes(),
        );
        body.extend_from_slice(format!("Content-Type: {}\r\n\r\n", part.content_type).as_bytes());
        body.extend_from_slice(&part.bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

/// POST a multipart body to `/api/v1/poe/uploads`, optionally with an idempotency
/// key, and return (status, json).
async fn post_uploads_keyed(
    addr: std::net::SocketAddr,
    bearer: Option<&str>,
    idempotency_key: Option<&str>,
    parts: &[Part],
) -> (u16, Value) {
    let (boundary, body) = build_multipart(parts);
    let client = reqwest::Client::new();
    let mut req = client
        .post(format!("http://{addr}/api/v1/poe/uploads"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body);
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if let Some(key) = idempotency_key {
        req = req.header("idempotency-key", key);
    }
    let resp = req.send().await.expect("send uploads");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if status != 200 {
        eprintln!("uploads -> {status}: {text}");
    }
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

async fn post_uploads(
    addr: std::net::SocketAddr,
    bearer: Option<&str>,
    parts: &[Part],
) -> (u16, Value) {
    post_uploads_keyed(addr, bearer, None, parts).await
}

/// GET the attempt poll route and return (status, json).
async fn get_attempt(
    addr: std::net::SocketAddr,
    bearer: Option<&str>,
    attempt_id: &str,
) -> (u16, Value) {
    let client = reqwest::Client::new();
    let mut req = client.get(format!(
        "http://{addr}/api/v1/poe/uploads/attempts/{attempt_id}"
    ));
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await.expect("send attempt poll");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

/// A part of `bytes` zero bytes (one part). A payload over the free window is paid.
fn paid_part(field: &str, bytes: usize) -> Part {
    Part {
        field: field.into(),
        content_type: "application/octet-stream".into(),
        bytes: vec![0xABu8; bytes],
    }
}

/// The free-storage window the default config quotes for free (100 KiB).
const FREE_WINDOW: usize = 102_400;

/// A payload one byte over the free window, so exactly one chargeable byte.
fn one_chargeable_byte(field: &str) -> Part {
    paid_part(field, FREE_WINDOW + 1)
}

// ---------------------------------------------------------------------------
// A recording mock backend: counts uploads, returns a deterministic receipt keyed
// on the signed item id, and can be told to fail or to delay each upload.
// ---------------------------------------------------------------------------

struct MockBackend {
    uploads: AtomicUsize,
    /// When set, every upload fails with a definite (non-Unavailable) error.
    fail_definite: bool,
    /// When set, every upload sleeps this long before returning, so a tight upload
    /// timeout aborts it (the ambiguous path).
    delay: Option<Duration>,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            uploads: AtomicUsize::new(0),
            fail_definite: false,
            delay: None,
        }
    }

    fn failing() -> Self {
        Self {
            uploads: AtomicUsize::new(0),
            fail_definite: true,
            delay: None,
        }
    }

    fn slow(delay: Duration) -> Self {
        Self {
            uploads: AtomicUsize::new(0),
            fail_definite: false,
            delay: Some(delay),
        }
    }

    fn upload_count(&self) -> usize {
        self.uploads.load(Ordering::SeqCst)
    }
}

impl StorageBackendExt for MockBackend {
    fn name(&self) -> &'static str {
        BACKEND
    }

    async fn upload(
        &self,
        _funding: &AuthorizedFunding,
        envelope: &SignedEnvelope,
        _owner: &[u8],
        _staged_path: &Path,
    ) -> Result<StorageReceipt, StorageError> {
        self.uploads.fetch_add(1, Ordering::SeqCst);
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        if self.fail_definite {
            // A 402-style definite refusal: the bytes never landed.
            return Err(StorageError::InsufficientCredit);
        }
        let data_item_id = envelope.id_b64url.clone();
        Ok(StorageReceipt {
            uri: format!("ar://{data_item_id}"),
            data_item_id,
            raw_receipt: serde_json::json!({ "backend": "mock" }),
            root_tx_id: None,
        })
    }
}

/// Read an account's USD balance.
async fn balance_of(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT coalesce(balance_micros, 0) FROM cw_core.balance WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or(0)
}

/// Read the materialized winc balance for a funding source.
async fn credit_balance(pool: &sqlx::PgPool, source: Uuid) -> Decimal {
    sqlx::query_scalar(
        "SELECT winc_balance FROM cw_core.storage_credit WHERE funding_source_id = $1",
    )
    .bind(source)
    .fetch_one(pool)
    .await
    .expect("credit balance")
}

/// Sum the ledger debits/credits of a kind for an account.
async fn ledger_sum(pool: &sqlx::PgPool, account_id: Uuid, kind: &str) -> i64 {
    // sum() over bigint yields numeric; cast back to bigint for an i64 decode.
    sqlx::query_scalar(
        "SELECT coalesce(sum(amount_micros), 0)::bigint FROM cw_core.balance_ledger \
         WHERE account_id = $1 AND kind = $2",
    )
    .bind(account_id)
    .bind(kind)
    .fetch_one(pool)
    .await
    .expect("ledger sum")
}

// ---------------------------------------------------------------------------
// Receipt-ledger primitives.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn persist_then_lookup_round_trips_a_receipt() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (_op, account_id) = seed_account(&db.pool).await;

    let sha: [u8; 32] = Sha256::digest(b"some content").into();
    let receipt = StorageReceipt {
        uri: "ar://abc123".into(),
        data_item_id: "abc123".into(),
        raw_receipt: serde_json::json!({ "ok": true }),
        root_tx_id: Some("root-tx".into()),
    };

    let persisted = persist_receipt(&db.pool, account_id, &sha, 12, BACKEND, &receipt)
        .await
        .expect("persist");
    assert!(!persisted.deduped, "a first persist is a fresh insert");
    assert_eq!(persisted.uri, "ar://abc123");
    assert_eq!(persisted.bytes, 12);

    let found = lookup_receipt(&db.pool, account_id, BACKEND, &sha)
        .await
        .expect("lookup")
        .expect("the row is found");
    assert_eq!(found.id, persisted.id);
    assert!(found.deduped, "a lookup hit is flagged deduped");

    // The same bytes on a DIFFERENT backend are a separate artifact: the dedup
    // lookup misses, so a second backend would store and charge its own copy.
    let other_backend = lookup_receipt(&db.pool, account_id, "arlocal", &sha)
        .await
        .expect("lookup");
    assert!(
        other_backend.is_none(),
        "a receipt on one backend must not dedup an upload to another backend"
    );
}

// ---------------------------------------------------------------------------
// Auth, 503, and ceiling guards (no billing path needed).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn uploads_require_the_bearer_and_the_create_scope() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (_op, account_id) = seed_account(&db.pool).await;
    let ts = state_with(db.pool.clone(), Arc::new(MockBackend::new()), 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![paid_part("file_0", 4)];

    let (no_auth, _) = post_uploads(addr, None, &parts).await;
    assert_eq!(no_auth, 401, "an unauthenticated upload is rejected");

    let read_only = issue_key(&db.pool, account_id, &["poe:read"]).await;
    let (wrong_scope, json) = post_uploads(addr, Some(&read_only), &parts).await;
    assert_eq!(wrong_scope, 403, "a key lacking poe:create is rejected");
    assert_eq!(json["code"], "insufficient-scope");
}

#[tokio::test]
async fn uploads_report_503_when_no_storage_is_configured() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (_op, account_id) = seed_account(&db.pool).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;

    let parts = vec![paid_part("file_0", 4)];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 503);
    assert_eq!(json["code"], "service-unavailable");
}

#[tokio::test]
async fn an_unknown_target_is_rejected_400() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    seed_funded_source(&db.pool, op).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let ts = state_with(db.pool.clone(), Arc::new(MockBackend::new()), 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![
        Part {
            field: "target".into(),
            content_type: "text/plain".into(),
            bytes: b"ipfs".to_vec(),
        },
        paid_part("file_0", 4),
    ];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(
        status, 400,
        "an unknown target is a hard 400, body = {json}"
    );
    assert_eq!(json["code"], "unsupported-storage-target");
}

#[tokio::test]
async fn a_file_over_the_ceiling_is_rejected_413() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    seed_funded_source(&db.pool, op).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;

    let durable = tempfile::tempdir().expect("durable");
    let signing = UploadSigning::new(
        unlocked_keyring(),
        durable.path().to_path_buf(),
        Duration::from_secs(30),
        Duration::from_secs(60),
    );
    let storage = StorageState::new(Arc::new(MockBackend::new())).with_signing(signing);
    let config = ApiConfig {
        upload_limits: UploadLimits {
            max_file_bytes: 4,
            max_batch_bytes: 1024,
            max_files: 32,
        },
        ..ApiConfig::default()
    };
    let state = AppState::new(db.pool.clone(), config)
        .with_pricing(Arc::new(TestPricing) as Arc<dyn DynPricingSource>)
        .with_storage(storage);
    let addr = serve(state).await;

    let parts = vec![paid_part("file_0", 100)];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 413, "an over-ceiling file is a 413, body = {json}");
    assert_eq!(json["code"], "envelope-too-large");
}

// ---------------------------------------------------------------------------
// Free-window path: signs and posts, persists a zero-charge receipt.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_free_window_file_posts_at_zero_charge() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    seed_funded_source(&db.pool, op).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![paid_part("file_0", 100)]; // under the free window
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200, "free upload succeeds, body = {json}");
    assert_eq!(json["uploads"][0]["ok"], true);
    assert_eq!(json["uploads"][0]["charged_usd_micros"], 0);
    assert_eq!(backend.upload_count(), 1);

    // No attempt, no hold: the free path takes no reservation.
    let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_upload_attempt")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(attempts, 0, "a free upload writes no attempt");
    assert_eq!(balance_of(&db.pool, account_id).await, 0, "no charge");
}

// ---------------------------------------------------------------------------
// The billed path: reserve -> hold -> charge exactly once.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_funded_paid_upload_charges_exactly_once() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    // One chargeable byte = one micro-USD at the test FX.
    let parts = vec![one_chargeable_byte("file_0")];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200, "paid upload succeeds, body = {json}");
    assert_eq!(json["uploads"][0]["ok"], true);
    assert_eq!(
        json["uploads"][0]["charged_usd_micros"], 1,
        "one chargeable byte costs one micro-USD"
    );

    // The attempt committed and the ledger nets to exactly one storage charge: the
    // hold and its release cancel, leaving the single storage_upload debit.
    let attempt_state: String =
        sqlx::query_scalar("SELECT state FROM cw_core.storage_upload_attempt LIMIT 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(attempt_state, "committed");

    assert_eq!(ledger_sum(&db.pool, account_id, "storage_hold").await, -1);
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_hold_release").await,
        1
    );
    assert_eq!(ledger_sum(&db.pool, account_id, "storage_upload").await, -1);
    // Net: the user paid exactly one micro-USD for storage.
    assert_eq!(balance_of(&db.pool, account_id).await, 10_000_000 - 1);

    // A receipt exists, linked to the attempt.
    let linked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1 AND attempt_id IS NOT NULL",
    )
    .bind(account_id)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(linked, 1, "the receipt links back to its paying attempt");
}

// ---------------------------------------------------------------------------
// Definite provider failure: no net charge, the attempt is released.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_definite_provider_failure_leaves_zero_net_charge() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::failing());
    let ts = state_with(db.pool.clone(), backend, 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200);
    assert_eq!(json["uploads"][0]["ok"], false, "the upload failed");

    // The attempt is released with a provider-rejected reason, and the hold/release
    // net to zero so the user is not charged.
    let (state, reason): (String, Option<String>) =
        sqlx::query_as("SELECT state, release_reason FROM cw_core.storage_upload_attempt LIMIT 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(state, "released");
    assert_eq!(reason.as_deref(), Some("provider_rejected"));
    assert_eq!(
        balance_of(&db.pool, account_id).await,
        10_000_000,
        "a failed upload leaves the balance untouched"
    );
    // No receipt was persisted.
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(receipts, 0);
}

// ---------------------------------------------------------------------------
// Ambiguous Unavailable (a timeout): the attempt stays reserved, no release.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_aborted_upload_leaves_the_attempt_reserved_before_the_lease_lapses() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    // The backend sleeps longer than the upload timeout, so the POST is aborted.
    let backend = Arc::new(MockBackend::slow(Duration::from_secs(5)));

    // A short upload timeout (1s) and a longer claim lease (60s): the abort fires
    // strictly before the lease can lapse.
    let durable = tempfile::tempdir().expect("durable");
    let signing = UploadSigning::new(
        unlocked_keyring(),
        durable.path().to_path_buf(),
        Duration::from_secs(1),
        Duration::from_secs(60),
    );
    let storage = StorageState::new(backend).with_signing(signing);
    let state = AppState::new(
        db.pool.clone(),
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..ApiConfig::default()
        },
    )
    .with_pricing(Arc::new(TestPricing) as Arc<dyn DynPricingSource>)
    .with_storage(storage);
    let addr = serve(state).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200);
    assert_eq!(json["uploads"][0]["ok"], false, "the aborted upload errors");
    assert_eq!(json["uploads"][0]["error"]["code"], "service-unavailable");

    // The attempt is left RESERVED (the bytes may have landed), the hold is still in
    // place (the user's funds remain reserved), and the lease was freed for the sweep.
    let (state, token, expires): (String, Option<Uuid>, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as(
            "SELECT state, upload_claim_token, upload_claim_expires_at \
             FROM cw_core.storage_upload_attempt LIMIT 1",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(state, "reserved", "an ambiguous failure does NOT release");
    assert!(token.is_none(), "the claim lease was freed for the sweep");
    assert!(expires.is_none());
    // The hold reserved the user's funds but no final charge applied yet.
    assert_eq!(ledger_sum(&db.pool, account_id, "storage_hold").await, -1);
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_hold_release").await,
        0
    );
    assert_eq!(balance_of(&db.pool, account_id).await, 10_000_000 - 1);
}

// ---------------------------------------------------------------------------
// Insufficient user balance: refused before any provider call.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unaffordable_balance_refuses_before_the_provider() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    // No USD balance: the hold would overdraw.
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200);
    assert_eq!(json["uploads"][0]["ok"], false);
    assert_eq!(json["uploads"][0]["error"]["code"], "insufficient-funds");
    assert_eq!(
        backend.upload_count(),
        0,
        "the provider is never called when the balance cannot cover the hold"
    );
    // The reservation was rolled back: no live attempt, no hold.
    let reserved: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload_attempt WHERE state = 'reserved'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(reserved, 0);
}

// ---------------------------------------------------------------------------
// Dedup: a re-upload of identical committed bytes is not re-billed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn re_uploading_identical_paid_bytes_is_not_rebilled() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (s1, _) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(s1, 200);
    let after_first = balance_of(&db.pool, account_id).await;

    let (s2, j2) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(s2, 200);
    assert_eq!(j2["uploads"][0]["ok"], true, "the dedup hit succeeds");
    assert_eq!(
        backend.upload_count(),
        1,
        "the second upload of identical bytes never reaches the backend"
    );
    // The response must not claim a charge the dedup never made: the pre-POST dedup
    // path omits the charge field entirely (the prior receipt is the source of
    // truth), and where it is present it is never a positive estimate.
    let charged = &j2["uploads"][0]["charged_usd_micros"];
    assert!(
        charged.is_null() || charged.as_i64() == Some(0),
        "a dedup hit must not report a positive charge, got {charged}"
    );
    assert_eq!(
        balance_of(&db.pool, account_id).await,
        after_first,
        "a dedup hit is not re-billed"
    );
}

// ---------------------------------------------------------------------------
// Structural no-charge-without-a-receipt: a commit whose receipt deduplicates
// against an existing one for the same account+backend+content must NOT debit.
// This pins the F1 contingency: the storage_upload charge is gated on the
// receipt actually inserting, so a deduped commit is a no-rebill (hold released,
// winc refunded), never a charge with no receipt row.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_deduped_commit_releases_the_hold_and_never_debits() {
    use gateway_core::storage::{commit_attempt, reserve_attempt, ReserveOutcome, ReserveSpec};

    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;

    let sha: [u8; 32] = Sha256::digest(b"already-stored-content").into();

    // A receipt already exists for this account+backend+content (a prior committed
    // upload). Its presence is what makes the next attempt's receipt insert dedup.
    let prior = StorageReceipt {
        uri: "ar://prior".into(),
        data_item_id: "prior-id".into(),
        raw_receipt: serde_json::json!({ "ok": true }),
        root_tx_id: None,
    };
    persist_receipt(&db.pool, account_id, &sha, 4, BACKEND, &prior)
        .await
        .expect("seed the prior receipt");

    // Reserve a fresh attempt for the SAME content+backend. (In production the
    // route's pre-upload lookup_receipt would short-circuit before reaching here;
    // this drives the commit path directly to prove the structural invariant in the
    // residual race window where two same-content attempts both reach commit.)
    let spec = ReserveSpec {
        id: Uuid::now_v7(),
        account_id,
        operator_id: op,
        funding_source_id: source,
        backend: BACKEND,
        sha256: sha,
        bytes: 4,
        chargeable_bytes: 4,
        charged_usd_micros: 4,
        estimated_winc: Decimal::from(10),
        data_item_id: "fresh-id",
        data_item_signature: &[0u8; 512],
        data_item_anchor: None,
        data_item_tag_bytes: &[],
        staged_path: "/tmp/fresh.stage",
        request_id: None,
    };
    let attempt = match reserve_attempt(&db.pool, &spec).await.expect("reserve") {
        ReserveOutcome::Claimed(a) => a,
        other => panic!("expected a fresh reservation, got a non-claim outcome: {other:?}"),
    };

    // The hold is placed and the believed winc is charged at reserve time.
    assert_eq!(ledger_sum(&db.pool, account_id, "storage_hold").await, -4);
    let winc_after_reserve = credit_balance(&db.pool, source).await;

    // Commit on a (mock) 2xx. The receipt insert dedups against the prior receipt, so
    // the contingency fires: the hold is released, NO storage_upload charge lands, and
    // the believed winc is refunded.
    let receipt = StorageReceipt {
        uri: "ar://fresh".into(),
        data_item_id: "fresh-id".into(),
        raw_receipt: serde_json::json!({ "ok": true }),
        root_tx_id: None,
    };
    let outcome = commit_attempt(&db.pool, attempt.id, &receipt, None)
        .await
        .expect("commit");
    // A deduped commit settles, but the settlement reports a realized charge of 0:
    // the poll route and the live upload response must echo this, not the estimate.
    assert_eq!(
        outcome,
        gateway_core::storage::SettleOutcome::Settled {
            charged_usd_micros: 0,
        },
        "a deduped commit settles but bills nothing"
    );
    // The realized charge is also persisted on the attempt row, so the poll route
    // (which reads the row) reports 0 rather than the reserve-time estimate.
    let settled_charge: Option<i64> = sqlx::query_scalar(
        "SELECT settled_charge_usd_micros FROM cw_core.storage_upload_attempt WHERE id = $1",
    )
    .bind(attempt.id)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        settled_charge,
        Some(0),
        "the deduped commit stamps a realized charge of 0 on the attempt row"
    );

    // No storage_upload debit: a deduped commit charges nothing.
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_upload").await,
        0,
        "a deduped commit must not debit the user"
    );
    // The hold was released, netting the reservation to zero.
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_hold_release").await,
        4,
    );
    assert_eq!(
        balance_of(&db.pool, account_id).await,
        10_000_000,
        "a deduped commit leaves the balance untouched"
    );
    // The believed winc charge was refunded back to the source.
    assert_eq!(
        credit_balance(&db.pool, source).await,
        winc_after_reserve + Decimal::from(10),
        "a deduped commit refunds the believed winc"
    );
    // The prior receipt is the only one for this account+backend+content (the
    // deduped insert created none).
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1 AND sha256 = $2",
    )
    .bind(account_id)
    .bind(sha.as_slice())
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(receipts, 1, "the deduped commit inserts no second receipt");
}

// ---------------------------------------------------------------------------
// Live-retry attach: a retry of bytes already in flight produces ONE attempt,
// hold, charge, and POST. The retry attaches and returns the same attempt_id.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_retry_of_in_flight_bytes_attaches_to_the_one_live_attempt() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    // Pre-seed a live (reserved) attempt for the exact bytes this upload carries, as
    // if a first request were still in flight. The route must ATTACH to it: no second
    // sign, hold, charge, or POST. This is the deterministic stand-in for a concurrent
    // retry winning the partial-unique race; the DB unique on
    // (account_id, backend, sha256) WHERE state='reserved' is what enforces it.
    let payload = vec![0xABu8; FREE_WINDOW + 1];
    let sha: [u8; 32] = Sha256::digest(&payload).into();
    let existing_attempt = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_upload_attempt \
           (id, account_id, operator_id, funding_source_id, backend, sha256, bytes, \
            chargeable_bytes, charged_usd_micros, estimated_winc, data_item_id, \
            data_item_signature, data_item_tag_bytes, staged_path, state) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1, 1, 1, 'existing-id', \
                 $8, '\\x'::bytea, '/tmp/existing.stage', 'reserved')",
    )
    .bind(existing_attempt)
    .bind(account_id)
    .bind(op)
    .bind(source)
    .bind(BACKEND)
    .bind(sha.as_slice())
    .bind((FREE_WINDOW + 1) as i64)
    .bind(vec![0u8; 512]) // a 512-byte placeholder signature
    .execute(&db.pool)
    .await
    .expect("seed an in-flight attempt");

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200, "the retry returns 200, body = {json}");

    // The retry ATTACHED: an accepted disposition keyed to the existing attempt id.
    assert_eq!(json["uploads"][0]["accepted"], true, "the retry attaches");
    assert_eq!(
        json["uploads"][0]["attempt_id"],
        existing_attempt.to_string(),
        "the attach returns the existing live attempt's id"
    );

    // No second attempt, no second hold/charge, no provider POST.
    let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_upload_attempt")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        attempts, 1,
        "exactly one attempt exists for the logical upload"
    );
    assert_eq!(
        backend.upload_count(),
        0,
        "the attaching retry never POSTs to the provider"
    );
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_hold").await,
        0,
        "the attaching retry places no second hold"
    );
}

// ---------------------------------------------------------------------------
// Whole-batch idempotency-key replay.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_idempotency_key_replays_the_batch_after_commit() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (s1, j1) = post_uploads_keyed(addr, Some(&key), Some("batch-key-1"), &parts).await;
    assert_eq!(s1, 200);
    let balance_after = balance_of(&db.pool, account_id).await;

    // Replay under the SAME key with DIFFERENT bytes: the recorded batch is replayed
    // verbatim (the body is not hashed), so the handler does no new work.
    let other = vec![paid_part("file_0", FREE_WINDOW + 99)];
    let (s2, j2) = post_uploads_keyed(addr, Some(&key), Some("batch-key-1"), &other).await;
    assert_eq!(s2, 200);
    assert_eq!(j2, j1, "the same key replays the recorded batch verbatim");
    assert_eq!(
        backend.upload_count(),
        1,
        "the replay does no new upload work"
    );
    assert_eq!(
        balance_of(&db.pool, account_id).await,
        balance_after,
        "the replay charges nothing new"
    );
}

// ---------------------------------------------------------------------------
// Charge-once under concurrency: identical bytes uploaded concurrently must POST
// to the provider at most once and bill exactly once, even when a contender
// commits inside another's sign window (the same-backend dedup TOCTOU).
// ---------------------------------------------------------------------------

/// Two concurrent uploads of identical paid bytes must pay the provider at most
/// once. The committed-receipt dedup is checked before the reservation, but the
/// live-slot uniqueness only constrains `reserved` rows: a contender that COMMITS
/// (leaving the slot, inserting the receipt) inside another request's sign window
/// is invisible to that request's reserve insert, which then wins `Claimed` and
/// would POST the same bytes a second time. The post-reserve committed-receipt
/// re-check (and its free-window twin) closes that window, so the provider is
/// POSTed at most once per logical file. A slow backend widens the window so the
/// interleaving is actually exercised; the assertion is the invariant, not a
/// specific interleaving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_identical_paid_uploads_pay_the_provider_at_most_once() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    // A brief per-upload delay widens the sign/reserve/commit window so the
    // committed-receipt race is actually explored across the concurrent requests.
    let backend = Arc::new(MockBackend::slow(Duration::from_millis(150)));
    // A claim lease comfortably longer than the backend delay, so a held POST is
    // never reclaimed mid-flight.
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    // Fire several concurrent uploads of the EXACT same bytes.
    let concurrency = 8;
    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            let parts = vec![one_chargeable_byte("file_0")];
            post_uploads(addr, Some(&key), &parts).await
        }));
    }
    for h in handles {
        let (status, _json) = h.await.expect("join upload");
        assert_eq!(status, 200, "every concurrent upload returns 200");
    }

    // The provider was POSTed at most once for the one logical file: the dedup
    // (live-slot attach OR the committed-receipt re-check) prevented every other
    // request from transmitting the same bytes to the backend a second time.
    assert!(
        backend.upload_count() <= 1,
        "identical concurrent uploads POST the provider at most once, got {}",
        backend.upload_count()
    );

    // Exactly one committed receipt exists, and the user was billed exactly once
    // for the logical file (one storage_upload debit nets to one micro-USD).
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1 AND sha256 = $2",
    )
    .bind(account_id)
    .bind(Sha256::digest(vec![0xABu8; FREE_WINDOW + 1]).as_slice())
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(receipts, 1, "exactly one receipt for the logical file");
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_upload").await,
        -1,
        "the logical file is billed exactly once"
    );
    assert_eq!(
        balance_of(&db.pool, account_id).await,
        10_000_000 - 1,
        "the account paid exactly one micro-USD net for the one logical file"
    );

    // No dedup loser is left as a sweep-recoverable reserved-with-a-staged-file
    // attempt: the recovery sweep re-POSTs a stale `reserved` attempt only while its
    // staged file is present, so a leaked reserved+file pair would re-POST the
    // already-deduped bytes. Every dedup loser deleted its staged file (and released
    // its reservation), so no `reserved` row retains a staged_path.
    let reserved_with_file: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload_attempt \
         WHERE state = 'reserved' AND staged_path IS NOT NULL",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        reserved_with_file, 0,
        "no dedup loser is left sweep-recoverable (reserved with a staged file)"
    );
}

/// The committed-receipt convergence is enforced even on the slot-winning path: an
/// upload that wins the reservation but finds a committed receipt for the same
/// bytes (the race outcome) must NOT POST the provider; it dedups against the
/// existing receipt. Pre-seeding the receipt is the deterministic stand-in for a
/// contender having committed inside the sign window. The provider POST count
/// stays zero and the user is not re-billed.
#[tokio::test]
async fn a_committed_receipt_for_the_same_bytes_is_never_re_posted() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    // A committed receipt already holds these exact bytes for this account+backend
    // (a concurrent winner committed first). Persist it directly.
    let payload = vec![0xABu8; FREE_WINDOW + 1];
    let sha: [u8; 32] = Sha256::digest(&payload).into();
    let receipt = StorageReceipt {
        uri: "ar://prior-winner".to_string(),
        data_item_id: "prior-winner".to_string(),
        raw_receipt: serde_json::json!({ "backend": "mock" }),
        root_tx_id: None,
    };
    let persisted = persist_receipt(
        &db.pool,
        account_id,
        &sha,
        payload.len() as u64,
        BACKEND,
        &receipt,
    )
    .await
    .expect("seed a committed receipt");
    assert!(!persisted.deduped);

    let balance_before = balance_of(&db.pool, account_id).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200, "the dedup upload succeeds, body = {json}");
    assert_eq!(
        json["uploads"][0]["ok"], true,
        "it converges as a dedup hit"
    );
    assert_eq!(
        json["uploads"][0]["uri"], "ar://prior-winner",
        "it returns the prior winner's receipt"
    );

    assert_eq!(
        backend.upload_count(),
        0,
        "an already-committed logical file is never re-POSTed to the provider"
    );
    assert_eq!(
        balance_of(&db.pool, account_id).await,
        balance_before,
        "a dedup hit is not billed"
    );
    // No reservation lingers: any slot won by the re-check was released, leaving
    // exactly the one prior receipt and no second one.
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1 AND sha256 = $2",
    )
    .bind(account_id)
    .bind(sha.as_slice())
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(receipts, 1, "no second receipt is created for the dedup");
}

/// Concurrent identical FREE-window uploads must POST the provider exactly once.
/// The free path takes no reservation row, so nothing in the database serialises
/// two concurrent callers: without the per-(account, backend, sha256) dedup lock
/// both would pass the lookup and each POST the same bytes (a duplicate provider
/// store / two data items for one logical file). The lock makes exactly one store
/// the bytes while the losers block, then converge on its committed receipt. A slow
/// backend widens the window so the race is genuinely exercised. Unlike the billed
/// path this is not a money double-charge (free uploads cost nothing), but
/// charge/dedup-once must still hold under concurrency.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_identical_free_uploads_post_the_provider_exactly_once() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    seed_funded_source(&db.pool, op).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    // A slow backend widens the lookup -> POST -> persist window so concurrent
    // callers genuinely race for the dedup lock rather than serialising by luck.
    let backend = Arc::new(MockBackend::slow(Duration::from_millis(150)));
    // The server pool needs headroom: each concurrent free upload holds one detached
    // advisory-lock connection while the loser blocks AND runs handler queries, so a
    // small pool would deadlock. Size it well above the concurrency.
    let server_pool = db.pool_with(24).await.expect("server pool");
    let ts = state_with(server_pool, backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    // Several concurrent uploads of the EXACT same sub-free-window bytes.
    let payload_len = 100; // under the free window
    let concurrency = 6;
    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            let parts = vec![paid_part("file_0", payload_len)];
            post_uploads(addr, Some(&key), &parts).await
        }));
    }
    for h in handles {
        let (status, json) = h.await.expect("join free upload");
        assert_eq!(status, 200, "every concurrent free upload returns 200");
        assert_eq!(json["uploads"][0]["ok"], true, "each free upload succeeds");
    }

    // The provider was POSTed EXACTLY once: the dedup lock let one contender store
    // the bytes and the rest converged on its receipt without a second POST.
    assert_eq!(
        backend.upload_count(),
        1,
        "concurrent identical free uploads POST the provider exactly once, got {}",
        backend.upload_count()
    );

    // Exactly one receipt exists for the logical file, and no charge was made.
    let sha: [u8; 32] = Sha256::digest(vec![0xABu8; payload_len]).into();
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1 AND sha256 = $2",
    )
    .bind(account_id)
    .bind(sha.as_slice())
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(receipts, 1, "exactly one receipt for the logical free file");
    assert_eq!(
        balance_of(&db.pool, account_id).await,
        0,
        "free uploads cost nothing"
    );
}

// ---------------------------------------------------------------------------
// Idempotency: a 402-class per-file failure is NON-committing, so a same-key
// retry after a top-up runs fresh and uploads (it does not replay the failure).
// ---------------------------------------------------------------------------

/// An Idempotency-Key'd uploads batch that contains a 402-class (insufficient
/// funds) per-file outcome must NOT commit the idempotency record. A same-key
/// retry after the account tops up therefore runs FRESH and actually uploads the
/// now-affordable file, instead of replaying the stored failure until expiry. This
/// mirrors the publish-batch partial-402 policy.
#[tokio::test]
async fn a_402_per_file_failure_does_not_poison_the_idempotency_key() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    // No USD balance yet: the only file in the batch is unaffordable (402-class).
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (s1, j1) = post_uploads_keyed(addr, Some(&key), Some("topup-key"), &parts).await;
    assert_eq!(s1, 200);
    assert_eq!(
        j1["uploads"][0]["error"]["code"], "insufficient-funds",
        "the unaffordable file fails 402-class, body = {j1}"
    );
    assert_eq!(
        backend.upload_count(),
        0,
        "an unaffordable file never reaches the provider"
    );

    // The account tops up and retries under the SAME idempotency key. Because the
    // first batch was non-committing (402-class), the retry must run FRESH and
    // actually upload, NOT replay the stored failure.
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let (s2, j2) = post_uploads_keyed(addr, Some(&key), Some("topup-key"), &parts).await;
    assert_eq!(s2, 200);
    assert_eq!(
        j2["uploads"][0]["ok"], true,
        "after top-up the same-key retry uploads fresh, body = {j2}"
    );
    assert_eq!(
        backend.upload_count(),
        1,
        "the topped-up retry actually POSTs the file (no stale-failure replay)"
    );
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_upload").await,
        -1,
        "the retried upload is billed once"
    );
}

// ---------------------------------------------------------------------------
// The poll route: each terminal state + ownership 404.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_poll_route_returns_committed_with_uri_and_charge() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend, 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, _) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200);

    let attempt_id: Uuid =
        sqlx::query_scalar("SELECT id FROM cw_core.storage_upload_attempt LIMIT 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();

    let (s, body) = get_attempt(addr, Some(&key), &attempt_id.to_string()).await;
    assert_eq!(s, 200, "the poll succeeds, body = {body}");
    assert_eq!(body["state"], "committed");
    assert_eq!(body["attempt_id"], attempt_id.to_string());
    assert_eq!(body["charged_usd_micros"], 1);
    assert!(
        body["uri"].as_str().unwrap().starts_with("ar://"),
        "committed carries the receipt uri"
    );
}

#[tokio::test]
async fn the_poll_route_returns_released_with_a_reason() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::failing());
    let ts = state_with(db.pool.clone(), backend, 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, _) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200);

    let attempt_id: Uuid =
        sqlx::query_scalar("SELECT id FROM cw_core.storage_upload_attempt LIMIT 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();

    let (s, body) = get_attempt(addr, Some(&key), &attempt_id.to_string()).await;
    assert_eq!(s, 200, "the poll succeeds, body = {body}");
    assert_eq!(body["state"], "released");
    assert_eq!(body["reason"], "provider_rejected");
}

#[tokio::test]
async fn the_poll_route_404s_an_attempt_the_caller_does_not_own() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let owner_key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend, 60);
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, _) = post_uploads(addr, Some(&owner_key), &parts).await;
    assert_eq!(status, 200);
    let attempt_id: Uuid =
        sqlx::query_scalar("SELECT id FROM cw_core.storage_upload_attempt LIMIT 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();

    // A different account polling the same attempt id gets a 404, indistinguishable
    // from a non-existent attempt (no cross-account existence oracle).
    let (_op2, other_account) = seed_account(&db.pool).await;
    let other_key = issue_key(&db.pool, other_account, &["poe:create"]).await;
    let (s, body) = get_attempt(addr, Some(&other_key), &attempt_id.to_string()).await;
    assert_eq!(s, 404, "an attempt the caller does not own is a 404");
    assert_eq!(body["code"], "not-found");

    // A syntactically invalid id is also a 404.
    let (s2, _) = get_attempt(addr, Some(&owner_key), "not-a-uuid").await;
    assert_eq!(s2, 404);
}

// ---------------------------------------------------------------------------
// Live legs (env-gated).
// ---------------------------------------------------------------------------

fn live_jwk() -> Option<String> {
    let path = std::env::var("GATEWAY_TEST_ARWEAVE_JWK_PATH").ok()?;
    std::fs::read_to_string(path).ok()
}

/// The ArLocal endpoint a live test posts against: the env override or the
/// conventional local default port.
fn arlocal_endpoint() -> Option<String> {
    match std::env::var("GATEWAY_TEST_ARLOCAL_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var("GATEWAY_TEST_ARLOCAL").is_ok() => {
            Some("http://localhost:1984".to_string())
        }
        Err(_) => None,
    }
}

/// Whether a live ArLocal is reachable at the endpoint (a quick `/info` probe), so
/// the test runs only when one is actually up rather than failing on a dead port.
async fn arlocal_reachable(endpoint: &str) -> bool {
    let url = format!("{}/info", endpoint.trim_end_matches('/'));
    matches!(reqwest::get(&url).await, Ok(r) if r.status().is_success())
}

#[tokio::test]
async fn live_arlocal_upload_through_the_full_route() {
    // Runs against a real ArLocal (the local emulator on its default port, or the
    // GATEWAY_TEST_ARLOCAL_URL override). The outer carrier transaction is signed
    // with the fixture keyring's Arweave key, which is exactly the funded source the
    // route resolves, so no separate JWK is needed.
    let Some(endpoint) = arlocal_endpoint() else {
        eprintln!("skipping: set GATEWAY_TEST_ARLOCAL=1 (or GATEWAY_TEST_ARLOCAL_URL)");
        return;
    };
    if !arlocal_reachable(&endpoint).await {
        eprintln!("skipping: no ArLocal reachable at {endpoint}");
        return;
    }

    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    // The funding grant is resolved by the live backend's name, so seed it under the
    // ArLocal backend rather than the default Turbo rail.
    seed_funded_source_for_backend(&db.pool, op, "arlocal").await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;

    // The backend signs the outer base-layer transaction with the same fixture
    // keyring the route signs the inner data item through.
    let backend =
        ArLocalBackend::new(endpoint.clone(), false, unlocked_keyring()).expect("arlocal backend");
    let ts = state_with(db.pool.clone(), Arc::new(backend), 60);
    let addr = serve(ts.state.clone()).await;

    // A small RANDOM payload so each run uploads distinct content.
    let payload: Vec<u8> = (0..777u32).map(|_| rand_byte()).collect();
    let expected_sha = hex::encode(Sha256::digest(&payload));
    let parts = vec![Part {
        field: "file_0".into(),
        content_type: "application/octet-stream".into(),
        bytes: payload.clone(),
    }];

    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200, "arlocal upload succeeds, body = {json}");
    assert_eq!(
        json["uploads"][0]["ok"], true,
        "upload failed, body = {json}"
    );
    assert_eq!(json["uploads"][0]["sha256"], expected_sha);

    // The receipt resolves at the inner data-item id (ar://{inner id}).
    let uri = json["uploads"][0]["uri"]
        .as_str()
        .expect("an ar:// uri on a successful upload");
    let inner_id = uri.strip_prefix("ar://").expect("an ar:// scheme uri");

    // The unbundled inner item is retrievable from the emulator by its own id off
    // the gateway root (the 43-char data route), and its served bytes are the
    // verbatim payload. This is the root-cause guard: the upload must exercise the
    // live mint/tx/mine contract and produce an item the emulator actually serves,
    // not a mock.
    let data_url = format!("{}/{inner_id}", endpoint.trim_end_matches('/'));
    let response = reqwest::get(&data_url)
        .await
        .expect("fetch the stored item");
    assert!(
        response.status().is_success(),
        "the inner data item is served at /{inner_id}, got {}",
        response.status()
    );
    let served = response.bytes().await.expect("read the served bytes");
    assert_eq!(
        served.as_ref(),
        payload.as_slice(),
        "the emulator served the verbatim payload for the inner data-item id"
    );
}

/// A cheap per-call random byte, seeded from the wall clock and a thread-local
/// counter, sufficient to make a test payload distinct across runs without pulling
/// a crypto-rng dependency into the integration target.
fn rand_byte() -> u8 {
    use std::cell::Cell;
    use std::time::{SystemTime, UNIX_EPOCH};
    thread_local! {
        static STATE: Cell<u64> = Cell::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9E37_79B9_7F4A_7C15),
        );
    }
    STATE.with(|s| {
        // A SplitMix64 step: good enough for non-cryptographic test entropy.
        let mut x = s.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
        s.set(x);
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((x ^ (x >> 31)) & 0xff) as u8
    })
}

#[tokio::test]
async fn live_turbo_free_tier_upload_through_the_full_route() {
    let Ok(upload_url) = std::env::var("GATEWAY_TEST_TURBO_URL") else {
        eprintln!("skipping: GATEWAY_TEST_TURBO_URL not set");
        return;
    };
    let Some(_jwk) = live_jwk() else {
        eprintln!("skipping: GATEWAY_TEST_ARWEAVE_JWK_PATH not set");
        return;
    };

    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    seed_funded_source(&db.pool, op).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;

    let backend = TurboBackend::new(
        db.pool.clone(),
        &upload_url,
        &upload_url,
        Decimal::ZERO,
        Duration::from_secs(300),
    );
    let ts = state_with(db.pool.clone(), Arc::new(backend), 60);
    let addr = serve(ts.state.clone()).await;

    let payload = format!("turbo free-tier content {}", Uuid::now_v7()).into_bytes();
    let expected_sha = hex::encode(Sha256::digest(&payload));
    let parts = vec![Part {
        field: "file_0".into(),
        content_type: "application/octet-stream".into(),
        bytes: payload,
    }];

    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(
        status, 200,
        "turbo free-tier upload succeeds, body = {json}"
    );
    assert_eq!(json["uploads"][0]["ok"], true);
    assert_eq!(json["uploads"][0]["sha256"], expected_sha);
}

// ---------------------------------------------------------------------------
// Multi-megabyte ingress: the wire cap must be the gateway's OWN ceiling, not
// the HTTP framework's built-in default. Content is billed per byte with no
// product size limit, so the only caps on these routes are the configured DoS
// backstops (10 GiB batch, 64 MiB chunk) — a 7 MiB single-shot body and a
// 3 MiB chunk body must both stream through.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_multi_megabyte_single_shot_upload_streams_through() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 100_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 50_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    // 7 MiB: comfortably over axum's 2 MiB built-in default body limit, far
    // under the 10 GiB batch ceiling the route is documented to enforce.
    const FILE_BYTES: usize = 7 * 1024 * 1024;
    let parts = vec![paid_part("file_0", FILE_BYTES)];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(
        status, 200,
        "a 7 MiB single-shot upload streams through, body = {json}"
    );
    assert_eq!(json["uploads"][0]["ok"], true, "body = {json}");
    assert_eq!(json["uploads"][0]["bytes"], FILE_BYTES as u64);

    // The billed saga holds at multi-MB scale: chargeable bytes priced at one
    // micro-USD per byte (the test FX), debited exactly once.
    let chargeable = (FILE_BYTES - FREE_WINDOW) as i64;
    assert_eq!(json["uploads"][0]["charged_usd_micros"], chargeable);
    assert_eq!(backend.upload_count(), 1);
    assert_eq!(
        balance_of(&db.pool, account_id).await,
        50_000_000 - chargeable
    );
}

/// JSON-POST the session-create route, returning (status, json).
async fn create_session(addr: std::net::SocketAddr, bearer: &str, body: Value) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/v1/poe/uploads/sessions"))
        .header("authorization", format!("Bearer {bearer}"))
        .json(&body)
        .send()
        .await
        .expect("send create session");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

/// PUT one chunk body with the required RFC 9530 Digest header, returning
/// (status, json).
async fn put_session_chunk(
    addr: std::net::SocketAddr,
    bearer: &str,
    session_id: &str,
    index: u32,
    bytes: Vec<u8>,
) -> (u16, Value) {
    use base64::Engine as _;
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&bytes));
    let client = reqwest::Client::new();
    let resp = client
        .put(format!(
            "http://{addr}/api/v1/poe/uploads/sessions/{session_id}/chunks/{index}"
        ))
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/octet-stream")
        .header("digest", format!("sha-256=:{digest}:"))
        .body(bytes)
        .send()
        .await
        .expect("send chunk");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

/// POST the session-complete route, returning (status, json).
async fn complete_session(
    addr: std::net::SocketAddr,
    bearer: &str,
    session_id: &str,
) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://{addr}/api/v1/poe/uploads/sessions/{session_id}/complete"
        ))
        .header("authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .expect("send complete");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn multi_megabyte_chunks_stream_through_the_session_route() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 100_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 50_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    // A 6 MiB file in two 3 MiB chunks: each chunk PUT body alone exceeds
    // axum's 2 MiB built-in default, and sits under the 64 MiB chunk ceiling.
    const CHUNK_BYTES: usize = 3 * 1024 * 1024;
    const TOTAL_BYTES: usize = 2 * CHUNK_BYTES;
    let content = vec![0xCDu8; TOTAL_BYTES];
    let sha_hex = hex::encode(Sha256::digest(&content));

    let (status, created) = create_session(
        addr,
        &key,
        serde_json::json!({
            "sha256": sha_hex,
            "total_bytes": TOTAL_BYTES as u64,
            "chunk_bytes": CHUNK_BYTES as u64,
            "content_type": "application/octet-stream",
        }),
    )
    .await;
    assert_eq!(status, 201, "session create succeeds, body = {created}");
    assert_eq!(created["chunk_bytes"], CHUNK_BYTES as u64);
    assert_eq!(created["chunk_count"], 2);
    let sid = created["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    for index in 0..2u32 {
        let start = index as usize * CHUNK_BYTES;
        let chunk = content[start..start + CHUNK_BYTES].to_vec();
        let (status, body) = put_session_chunk(addr, &key, &sid, index, chunk).await;
        assert_eq!(
            status, 200,
            "a 3 MiB chunk PUT streams through, body = {body}"
        );
    }

    let (status, completed) = complete_session(addr, &key, &sid).await;
    assert_eq!(status, 200, "complete succeeds, body = {completed}");
    assert_eq!(completed["ok"], true, "body = {completed}");
    assert_eq!(completed["bytes"], TOTAL_BYTES as u64);
    let chargeable = (TOTAL_BYTES - FREE_WINDOW) as i64;
    assert_eq!(completed["charged_usd_micros"], chargeable);
    assert_eq!(backend.upload_count(), 1, "one POST for the assembled file");
}

// ---------------------------------------------------------------------------
// The real TurboBackend against a controllable upstream upload service.
//
// These boot the genuine TurboBackend (not the recording MockBackend) so the
// receipt-validation gate and the client-level upload timeout are exercised on
// the production code path: a 2xx alone is NOT a receipt, and a TCP-level stall
// must abort rather than hang. Assertions are on the resulting DB rows (the
// receipt row, the storage_upload debit, the attempt state, the balance), never
// on log strings.
// ---------------------------------------------------------------------------

/// How the stand-in Turbo upload service answers a POST.
#[derive(Clone)]
enum UpstreamReply {
    /// A 200 whose body echoes the POSTed data item's real id, plus the rest of a
    /// genuine Turbo receipt — the only answer the validator accepts.
    GenuineReceiptEchoingId,
    /// A 200 with a fixed JSON body that is NOT a valid receipt for this item.
    TwoHundredWithBody(Value),
    /// A 200 with a non-JSON body (a broken proxy wrapping the response).
    TwoHundredNonJson(&'static str),
    /// Accept the connection and never answer, to exercise the upload deadline.
    StallForever,
}

/// Boot a stand-in Turbo upload service on an ephemeral port that answers
/// `POST /v1/tx/arweave` with the configured reply, and return its base URL.
///
/// For [`UpstreamReply::GenuineReceiptEchoingId`] it parses the POSTed ANS-104 data
/// item to recover its id (`SHA-256(signature)`) and echoes it as the receipt `id`,
/// so the receipt genuinely matches the item the route signed — the signature is
/// randomised, so the id is not knowable ahead of the POST.
async fn serve_upstream_turbo(reply: UpstreamReply) -> String {
    use axum::body::Bytes;
    use axum::http::StatusCode;
    use axum::response::Response as AxumResponse;
    use axum::routing::post;
    use axum::Router;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");

    let handler = move |body: Bytes| {
        let reply = reply.clone();
        async move {
            match reply {
                UpstreamReply::GenuineReceiptEchoingId => {
                    let view = ans104::SignedDataItem::parse(&body)
                        .expect("the route POSTs a well-formed data item");
                    let receipt = serde_json::json!({
                        "id": view.id_b64url(),
                        "owner": "the-operator-arweave-address",
                        "dataCaches": ["arweave.net"],
                        "fastFinalityIndexes": ["arweave.net"],
                        "winc": "0",
                    });
                    axum::Json(receipt).into_response()
                }
                UpstreamReply::TwoHundredWithBody(value) => axum::Json(value).into_response(),
                UpstreamReply::TwoHundredNonJson(text) => AxumResponse::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(text))
                    .expect("build non-json response"),
                UpstreamReply::StallForever => {
                    // Hold the request open past any reasonable test deadline without
                    // ever responding, so only a client-level timeout breaks the wait.
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    StatusCode::OK.into_response()
                }
            }
        }
    };

    use axum::response::IntoResponse;
    let app = Router::new().route("/v1/tx/arweave", post(handler));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve upstream");
    });
    format!("http://{addr}")
}

/// Build app state over a REAL TurboBackend pointed at `upload_url`, with the given
/// upload timeout, so the receipt-validation gate and the client deadline are on the
/// live code path. The gateway URL is unused by these tests (no lookup is driven).
fn turbo_state(pool: sqlx::PgPool, upload_url: &str, upload_timeout: Duration) -> TestState {
    let backend = TurboBackend::new(
        pool.clone(),
        upload_url,
        "http://gateway.invalid",
        Decimal::ZERO,
        upload_timeout,
    );
    let durable = tempfile::tempdir().expect("durable dir");
    let signing = UploadSigning::new(
        unlocked_keyring(),
        durable.path().to_path_buf(),
        upload_timeout,
        // The claim lease must exceed the upload timeout; keep it comfortably above.
        upload_timeout + Duration::from_secs(60),
    );
    let storage = StorageState::new(Arc::new(backend)).with_signing(signing);
    let state = AppState::new(
        pool,
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..ApiConfig::default()
        },
    )
    .with_pricing(Arc::new(TestPricing) as Arc<dyn DynPricingSource>)
    .with_storage(storage);
    TestState {
        state,
        _durable: durable,
    }
}

/// Count the committed receipt rows for an account.
async fn receipt_rows(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(pool)
        .await
        .expect("count receipts")
}

/// The single attempt row's state, or `None` when no attempt exists.
async fn only_attempt_state(pool: &sqlx::PgPool) -> Option<String> {
    sqlx::query_scalar("SELECT state FROM cw_core.storage_upload_attempt LIMIT 1")
        .fetch_optional(pool)
        .await
        .expect("attempt state")
}

/// Assert that a rejected receipt left NO partial charge: the only money movement is
/// the reversible reserve-time hold, with no final storage charge and no release yet.
///
/// The seeded fixtures fund the account with 50_000_000 micro-USD and upload exactly
/// one chargeable byte (1 micro-USD at the test FX), so the held amount is 1 micro.
/// On a rejected receipt the attempt is left `reserved`: the hold is in place but not
/// released, and the `storage_upload` debit never ran. So the balance reflects ONLY
/// the reversible hold (50_000_000 - 1), and the recovery sweep can still release it
/// to make the account whole. A partial or fabricated charge would show up as a
/// non-zero `storage_upload` debit or a balance below the held figure.
async fn assert_no_partial_charge(pool: &sqlx::PgPool, account_id: Uuid) {
    const SEEDED_BALANCE: i64 = 50_000_000;
    const HELD_MICROS: i64 = 1;

    assert_eq!(
        ledger_sum(pool, account_id, "storage_hold").await,
        -HELD_MICROS,
        "exactly the reversible hold was placed, no more"
    );
    assert_eq!(
        ledger_sum(pool, account_id, "storage_hold_release").await,
        0,
        "the hold is not released while the attempt is still reserved"
    );
    assert_eq!(
        ledger_sum(pool, account_id, "storage_upload").await,
        0,
        "no final storage charge was applied"
    );
    assert_eq!(
        balance_of(pool, account_id).await,
        SEEDED_BALANCE - HELD_MICROS,
        "the balance reflects only the reversible hold, never a partial charge"
    );
}

#[tokio::test]
async fn a_genuine_turbo_receipt_commits_and_debits_once() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 100_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 50_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;

    let upstream = serve_upstream_turbo(UpstreamReply::GenuineReceiptEchoingId).await;
    let ts = turbo_state(db.pool.clone(), &upstream, Duration::from_secs(30));
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200, "a genuine receipt commits, body = {json}");
    assert_eq!(json["uploads"][0]["ok"], true, "body = {json}");
    // The URI resolves at the data item the route signed.
    assert!(json["uploads"][0]["uri"]
        .as_str()
        .expect("uri")
        .starts_with("ar://"));

    // Exactly one receipt row and exactly one storage_upload debit of one micro-USD
    // (one chargeable byte at the test FX), and the held USD was returned so the net
    // balance change is exactly the one charge.
    assert_eq!(receipt_rows(&db.pool, account_id).await, 1);
    assert_eq!(ledger_sum(&db.pool, account_id, "storage_upload").await, -1);
    assert_eq!(
        only_attempt_state(&db.pool).await.as_deref(),
        Some("committed")
    );
    assert_eq!(balance_of(&db.pool, account_id).await, 50_000_000 - 1);
}

#[tokio::test]
async fn a_two_hundred_with_an_empty_body_is_not_a_receipt() {
    // The pre-fix bug: a 200 with `{}` was coerced to an empty receipt, the URI was
    // fabricated from the local envelope id, and the receipt-gated debit applied —
    // charging for content the provider may never have stored. The validator now
    // rejects it as indeterminate, so nothing commits and nothing is charged.
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 100_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 50_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;

    let upstream =
        serve_upstream_turbo(UpstreamReply::TwoHundredWithBody(serde_json::json!({}))).await;
    let ts = turbo_state(db.pool.clone(), &upstream, Duration::from_secs(30));
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    // The single-shot route returns 200 with a per-file failure entry; the upload is
    // surfaced as not-ok (retryable) rather than a fabricated success.
    assert_eq!(status, 200, "the route responds, body = {json}");
    assert_eq!(
        json["uploads"][0]["ok"], false,
        "an empty receipt must not be reported as a successful upload, body = {json}"
    );

    // No receipt row, no storage_upload debit, and the attempt is left reserved (the
    // recovery sweep's authoritative lookup will resolve it). The hold was placed and
    // not yet released, so the balance still shows the hold but never the final charge.
    assert_eq!(
        receipt_rows(&db.pool, account_id).await,
        0,
        "no receipt was committed"
    );
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_upload").await,
        0,
        "no storage charge was applied for an unconfirmed upload"
    );
    assert_eq!(
        only_attempt_state(&db.pool).await.as_deref(),
        Some("reserved"),
        "the attempt is left retryable, not committed or released"
    );
    assert_no_partial_charge(&db.pool, account_id).await;
}

#[tokio::test]
async fn a_two_hundred_for_a_different_data_item_is_not_a_receipt() {
    // An intercepting or confused endpoint that returns 200 with a receipt for some
    // OTHER data item must not let the route mint an ar:// URI from its own envelope.
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 100_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 50_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;

    let wrong =
        serde_json::json!({ "id": "some_other_data_item_the_provider_stored", "winc": "0" });
    let upstream = serve_upstream_turbo(UpstreamReply::TwoHundredWithBody(wrong)).await;
    let ts = turbo_state(db.pool.clone(), &upstream, Duration::from_secs(30));
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200, "the route responds, body = {json}");
    assert_eq!(json["uploads"][0]["ok"], false, "body = {json}");
    assert_eq!(receipt_rows(&db.pool, account_id).await, 0);
    assert_eq!(ledger_sum(&db.pool, account_id, "storage_upload").await, 0);
    assert_eq!(
        only_attempt_state(&db.pool).await.as_deref(),
        Some("reserved")
    );
    assert_no_partial_charge(&db.pool, account_id).await;
}

#[tokio::test]
async fn a_two_hundred_with_a_non_json_body_is_not_a_receipt() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 100_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 50_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;

    let upstream = serve_upstream_turbo(UpstreamReply::TwoHundredNonJson("OK, stored")).await;
    let ts = turbo_state(db.pool.clone(), &upstream, Duration::from_secs(30));
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    let (status, json) = post_uploads(addr, Some(&key), &parts).await;
    assert_eq!(status, 200, "the route responds, body = {json}");
    assert_eq!(json["uploads"][0]["ok"], false, "body = {json}");
    assert_eq!(receipt_rows(&db.pool, account_id).await, 0);
    assert_eq!(ledger_sum(&db.pool, account_id, "storage_upload").await, 0);
    assert_eq!(
        only_attempt_state(&db.pool).await.as_deref(),
        Some("reserved")
    );
    assert_no_partial_charge(&db.pool, account_id).await;
}

#[tokio::test]
async fn a_stalled_upstream_aborts_on_the_client_timeout_rather_than_hanging() {
    // The defect this guards: a TurboBackend client with no timeout hangs forever on
    // a TCP-level stall. With the client-level deadline wired, a stalling upstream is
    // aborted promptly. A short upload timeout means the whole upload resolves well
    // inside the outer test guard; a no-timeout client would blow past it.
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 100_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 50_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;

    let upstream = serve_upstream_turbo(UpstreamReply::StallForever).await;
    // A 2-second client timeout on the POST; the upload must resolve quickly.
    let ts = turbo_state(db.pool.clone(), &upstream, Duration::from_secs(2));
    let addr = serve(ts.state.clone()).await;

    let parts = vec![one_chargeable_byte("file_0")];
    // The outer guard is far below "hangs forever": if the client deadline were not
    // wired, the request would still be stalled here and this would time out.
    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        post_uploads(addr, Some(&key), &parts),
    )
    .await;
    let (status, json) = outcome.expect("the upload aborts on the client timeout, not a hang");
    assert_eq!(status, 200, "the route responds, body = {json}");
    // A stalled upload is the ambiguous path: not-ok (retryable), the attempt left
    // reserved for the recovery sweep, no receipt, no charge.
    assert_eq!(json["uploads"][0]["ok"], false, "body = {json}");
    assert_eq!(receipt_rows(&db.pool, account_id).await, 0);
    assert_eq!(ledger_sum(&db.pool, account_id, "storage_upload").await, 0);
    assert_eq!(
        only_attempt_state(&db.pool).await.as_deref(),
        Some("reserved")
    );
    assert_no_partial_charge(&db.pool, account_id).await;
}

// ---------------------------------------------------------------------------
// The session chunk grid is bounded BEFORE anything is allocated.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_session_create_below_the_chunk_floor_gets_the_clamped_grid() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 100_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 50_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let ts = state_with(db.pool.clone(), Arc::new(MockBackend::new()), 60);
    let addr = serve(ts.state.clone()).await;

    // A degenerate 1-byte chunk request is clamped UP to the floor (never down
    // to a grid of one chunk per byte), and the response's grid is authoritative.
    const TOTAL: u64 = 3 * 1024 * 1024;
    let (status, created) = create_session(
        addr,
        &key,
        serde_json::json!({
            "sha256": "ab".repeat(32),
            "total_bytes": TOTAL,
            "chunk_bytes": 1,
        }),
    )
    .await;
    assert_eq!(status, 201, "the clamped create lands, body = {created}");
    assert_eq!(created["chunk_bytes"], DEFAULT_MIN_CHUNK_BYTES);
    assert_eq!(
        created["chunk_count"],
        TOTAL.div_ceil(DEFAULT_MIN_CHUNK_BYTES),
        "the grid is computed from the clamped size"
    );
}

#[tokio::test]
async fn a_session_create_whose_grid_exceeds_the_chunk_ceiling_is_rejected_before_allocation() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 100_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 50_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;

    // With the default 1 MiB floor the default per-file ceiling can never reach
    // the grid bound, so loosen the floor to 1 byte — an operator CAN configure
    // that — and prove the hard MAX_SESSION_CHUNKS backstop still refuses the
    // grid before any file or bitmap exists.
    let ts = state_with_config(
        db.pool.clone(),
        Arc::new(MockBackend::new()),
        60,
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            upload_session_limits: UploadSessionLimits {
                min_chunk_bytes: 1,
                ..UploadSessionLimits::default()
            },
            ..ApiConfig::default()
        },
    );
    let addr = serve(ts.state.clone()).await;

    // 32 MiB at 1-byte chunks: ~33.5 million chunks, three orders past the bound.
    let (status, body) = create_session(
        addr,
        &key,
        serde_json::json!({
            "sha256": "cd".repeat(32),
            "total_bytes": 32 * 1024 * 1024,
            "chunk_bytes": 1,
        }),
    )
    .await;
    assert_eq!(
        status, 422,
        "an over-bound grid is a validation rejection, body = {body}"
    );
    assert_eq!(body["code"], serde_json::json!("validation-failed"));
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains(&MAX_SESSION_CHUNKS.to_string()),
        "the rejection names the grid bound and the workable chunk size: {body}"
    );

    // NOTHING was allocated for the refused create: no session row landed and no
    // assembling file was preallocated in the durable directory.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_upload_session")
        .fetch_one(&db.pool)
        .await
        .expect("count sessions");
    assert_eq!(rows, 0, "no session row for a rejected grid");
    let mut entries = tokio::fs::read_dir(ts._durable.path())
        .await
        .expect("read durable dir");
    let mut files = Vec::new();
    while let Some(entry) = entries.next_entry().await.expect("scan durable dir") {
        files.push(entry.path());
    }
    assert!(
        files.is_empty(),
        "no assembling file for a rejected grid: {files:?}"
    );
}
