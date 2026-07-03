//! The storage billing conformance suite: the cross-cutting reservation /
//! single-POST / crash-recovery contract proven as one coherent whole, against a
//! real Postgres and the real `/api/v1/poe/uploads` data-plane router.
//!
//! The per-subsystem suites pin each mechanism in isolation (the migration guards,
//! the funding-grant selection, the credit reconcile drift backstop, the upload
//! billing saga, the attempt-reconcile sweep matrix). This suite proves the
//! invariants that only emerge when the mechanisms run TOGETHER, under genuine
//! concurrency and in a mixed batch, plus the two purely-cryptographic facts the
//! whole crash-recovery design rests on:
//!
//!   - two genuinely concurrent uploads of the SAME bytes against one source
//!     converge on ONE attempt, ONE hold, ONE charge, ONE provider POST (the live
//!     partial-unique + the attach path, exercised by real overlapping requests
//!     rather than a pre-seeded row);
//!   - a partial-multipart batch (one file commits, a later file overdraws) leaves
//!     the committed file charged and the failed file uncharged, in one 200 batch;
//!   - the reconstruction `prefix(envelope) | staged-content` is byte-identical to
//!     the once-signed canonical item and verifies under the stored id, so a
//!     re-POST never re-signs (the byte-identity load-bearing fact);
//!   - two independent signs of identical content yield DIFFERENT ids (the PSS
//!     signature is randomised), so persisting the envelope is the ONLY way to
//!     reproduce the item id across a crash — re-signing is never an option;
//!   - the poll route alone resolves an attempt to its terminal outcome with no SSE
//!     subscription at all (the poll-authoritative contract: correctness never
//!     depends on receiving an event).
//!
//! The paid-window duplicate-POST probe (whether a funded Turbo source re-charges
//! winc for a second byte-identical POST of one data-item id) is an env-gated live
//! test: the free-tier `winc:0` case is already settled empirically; the paid case
//! needs a funded operator Turbo account, which is provisioned out of band. The
//! mechanism does not depend on the answer (a paid double-charge is bounded to
//! operator winc drift the reconcile cron corrects), but the probe settles the fact
//! rather than assuming provider dedup.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use age::secrecy::SecretString;
use ans104::{
    reconstruct_prefix, verify, Ans104Signer, ArweaveJwkSigner, SignedEnvelope, Tag,
    SIGNATURE_TYPE_ARWEAVE,
};
use gateway_core::api::middleware::auth::hash_secret;
use gateway_core::api::router;
use gateway_core::api::state::{
    ApiConfig, AppState, DynPricingSource, PricingInputs, PricingSource, StorageState,
    UploadSigning,
};
use gateway_core::storage::{
    insert_credit_entry, AuthorizedFunding, CreditEntry, CreditKind, StorageBackendExt,
    StorageError, StorageReceipt,
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

/// The canonical backend the conformance suite exercises (the Turbo rail). Matches
/// the mock backend's `name()` and the funding source's `backend` column.
const BACKEND: &str = "turbo";

/// The per-byte storage price the test FX charges: one chargeable byte costs one
/// micro-USD (1e9 femto = 1 micro), so the ledger arithmetic is exact and readable.
const AR_USD_PER_BYTE_FEMTO: i64 = 1_000_000_000;

/// The free-storage window the default config quotes for free (100 KiB).
const FREE_WINDOW: usize = 102_400;

/// The throwaway Arweave JWK every keyring in this suite signs with (the same
/// fixture the keyring round-trip and ans104 tests use).
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// A low scrypt work factor so the in-test keyring envelope encrypts/decrypts fast.
const TEST_SCRYPT_LOG_N: u8 = 4;

/// The Arweave address the fixture JWK derives to (the funding source's address and
/// the keyring entry the route resolves a signer through).
fn fixture_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

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

/// A test pricing seam: only the per-byte storage price matters to the upload path.
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
/// service grant. The address is the JWK's derived address, so the route's keyring
/// resolves a signer for it.
async fn seed_funded_source(pool: &sqlx::PgPool, operator: Uuid) -> Uuid {
    let source_id = Uuid::now_v7();
    let address = fixture_arweave_address();
    sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'primary', $3, $4, $4)",
    )
    .bind(source_id)
    .bind(operator)
    .bind(BACKEND)
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
    .bind(BACKEND)
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
fn state_with(
    pool: sqlx::PgPool,
    backend: Arc<dyn gateway_core::storage::StorageBackend>,
    lease_secs: u64,
) -> TestState {
    let durable = tempfile::tempdir().expect("durable dir");
    let signing = UploadSigning::new(
        unlocked_keyring(),
        durable.path().to_path_buf(),
        Duration::from_secs(30),
        Duration::from_secs(lease_secs),
    );
    let storage = StorageState::new(backend).with_signing(signing);
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

/// POST a multipart body to `/api/v1/poe/uploads` and return (status, json).
async fn post_uploads(addr: std::net::SocketAddr, bearer: &str, parts: &[Part]) -> (u16, Value) {
    let (boundary, body) = build_multipart(parts);
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/v1/poe/uploads"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("authorization", format!("Bearer {bearer}"))
        .body(body)
        .send()
        .await
        .expect("send uploads");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if status != 200 {
        eprintln!("uploads -> {status}: {text}");
    }
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

/// GET the attempt poll route and return (status, json). No SSE subscription is ever
/// opened by this helper: the poll alone is the authoritative outcome read.
async fn get_attempt(addr: std::net::SocketAddr, bearer: &str, attempt_id: &str) -> (u16, Value) {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://{addr}/api/v1/poe/uploads/attempts/{attempt_id}"
        ))
        .header("authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .expect("send attempt poll");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

/// A paid part of `bytes` bytes (one field). A payload over the free window is paid.
fn paid_part(field: &str, bytes: usize) -> Part {
    Part {
        field: field.into(),
        content_type: "application/octet-stream".into(),
        bytes: vec![0xABu8; bytes],
    }
}

/// A paid part whose bytes are distinct per `tag`, so its sha256 (and therefore its
/// logical-upload identity and data-item id) differs from another part's.
fn distinct_paid_part(field: &str, bytes: usize, tag: u8) -> Part {
    Part {
        field: field.into(),
        content_type: "application/octet-stream".into(),
        bytes: vec![tag; bytes],
    }
}

// ---------------------------------------------------------------------------
// A recording mock backend that counts uploads and can stall, so a test can prove
// the single-POST contract holds under genuine request overlap.
// ---------------------------------------------------------------------------

struct MockBackend {
    uploads: AtomicUsize,
    /// When set, every upload sleeps this long before returning, so two concurrent
    /// requests for the same logical upload genuinely overlap on the live attempt.
    delay: Option<Duration>,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            uploads: AtomicUsize::new(0),
            delay: None,
        }
    }

    fn slow(delay: Duration) -> Self {
        Self {
            uploads: AtomicUsize::new(0),
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
        let data_item_id = envelope.id_b64url.clone();
        Ok(StorageReceipt {
            uri: format!("ar://{data_item_id}"),
            data_item_id,
            raw_receipt: serde_json::json!({ "backend": "mock" }),
            root_tx_id: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Ledger / state readers.
// ---------------------------------------------------------------------------

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

async fn ledger_sum(pool: &sqlx::PgPool, account_id: Uuid, kind: &str) -> i64 {
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

async fn attempt_count(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_upload_attempt")
        .fetch_one(pool)
        .await
        .expect("count attempts")
}

// ---------------------------------------------------------------------------
// Concurrency: two genuinely concurrent uploads of the same bytes converge on one
// attempt, one hold, one charge, one POST. (The live partial-unique + the attach
// path, exercised by real overlapping requests rather than a pre-seeded row.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_concurrent_uploads_of_one_logical_upload_charge_and_post_once() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;

    // The backend stalls each POST so the two requests are guaranteed to overlap on
    // the one live attempt: whichever wins the live partial-unique holds the slot
    // open while the other arrives and must ATTACH rather than mint a second attempt.
    let backend = Arc::new(MockBackend::slow(Duration::from_millis(300)));
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    // Identical bytes over the free window: the same (account_id, backend, sha256)
    // logical upload from two requests.
    let bytes = FREE_WINDOW + 1;
    let (r1, r2) = tokio::join!(
        {
            let key = key.clone();
            async move { post_uploads(addr, &key, &[paid_part("file_0", bytes)]).await }
        },
        {
            let key = key.clone();
            async move { post_uploads(addr, &key, &[paid_part("file_0", bytes)]).await }
        },
    );
    let (s1, j1) = r1;
    let (s2, j2) = r2;
    assert_eq!(s1, 200, "first concurrent upload returns 200, body = {j1}");
    assert_eq!(s2, 200, "second concurrent upload returns 200, body = {j2}");

    // Exactly one provider POST across both requests: the attach path never POSTs.
    assert_eq!(
        backend.upload_count(),
        1,
        "only the winner POSTs; the attacher converges without a second POST"
    );

    // Exactly one attempt, one hold, one final charge: the user paid for the bytes
    // exactly once even though two requests asked to store them.
    assert_eq!(attempt_count(&db.pool).await, 1, "one logical attempt only");
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_upload").await,
        -1,
        "exactly one storage charge"
    );
    assert_eq!(
        balance_of(&db.pool, account_id).await,
        10_000_000 - 1,
        "the user is charged exactly one micro-USD across both requests"
    );

    // Both responses point at the SAME attempt id (the winner's): one as a committed
    // result, the other either committed (it lost the slot but read the receipt) or
    // accepted (it attached while the winner was still in flight). Either way it is
    // the SAME attempt id, never a second one.
    let only_attempt: Uuid =
        sqlx::query_scalar("SELECT id FROM cw_core.storage_upload_attempt LIMIT 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    for body in [&j1, &j2] {
        let file = &body["uploads"][0];
        let referenced = file["attempt_id"].as_str();
        if let Some(id) = referenced {
            assert_eq!(
                id,
                only_attempt.to_string(),
                "a response that names an attempt names the ONE live attempt, body = {body}"
            );
        } else {
            // A committed result that does not echo an attempt_id still must be `ok`.
            assert_eq!(file["ok"], true, "a committed result is ok, body = {body}");
        }
    }
}

// ---------------------------------------------------------------------------
// Partial-multipart success: one file commits, a later file overdraws. The
// committed file stays charged; the failed file is uncharged; one 200 batch.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_partial_multipart_batch_charges_only_the_committed_file() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    // Fund the balance to cover exactly ONE chargeable byte. The first paid file
    // commits (1 micro); the second paid file's hold would overdraw and is refused.
    fund_balance(&db.pool, account_id, 1).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    // Two distinct paid files (distinct bytes => distinct logical uploads), each one
    // chargeable byte over the free window. Files are processed in order, so file 0
    // commits and updates the balance to 0 before file 1's hold is evaluated.
    let parts = vec![
        distinct_paid_part("file_0", FREE_WINDOW + 1, 0x01),
        distinct_paid_part("file_1", FREE_WINDOW + 1, 0x02),
    ];
    let (status, json) = post_uploads(addr, &key, &parts).await;
    assert_eq!(status, 200, "the batch returns one 200, body = {json}");

    // File 0 committed; file 1 was refused for funds. Both outcomes are in one batch.
    assert_eq!(json["uploads"][0]["ok"], true, "the first file committed");
    assert_eq!(
        json["uploads"][0]["charged_usd_micros"], 1,
        "the committed file charged one micro-USD"
    );
    assert_eq!(json["uploads"][1]["ok"], false, "the second file failed");
    assert_eq!(
        json["uploads"][1]["error"]["code"], "insufficient-funds",
        "the overdrawing file is refused before its provider POST"
    );

    // Only the committed file reached the provider.
    assert_eq!(
        backend.upload_count(),
        1,
        "only the affordable file POSTs; the refused file never reaches the backend"
    );

    // The committed file's charge stands; the failed file left no residual hold.
    assert_eq!(
        balance_of(&db.pool, account_id).await,
        0,
        "the balance reflects exactly the one committed charge"
    );
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_upload").await,
        -1,
        "exactly one final storage charge (the committed file)"
    );

    // Exactly one committed attempt; the refused file rolled its reservation back, so
    // no live `reserved` row is left dangling.
    let committed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload_attempt WHERE state = 'committed'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(committed, 1, "one committed attempt");
    let reserved: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload_attempt WHERE state = 'reserved'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(reserved, 0, "the refused file leaves no live reservation");
}

// ---------------------------------------------------------------------------
// Poll-authoritative contract: an attached client resolves the terminal outcome by
// polling alone, with no SSE subscription. Correctness never depends on receiving an
// event; the poll route reads the attempt row post-CAS, so it is the authoritative
// source of the outcome.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_attached_client_resolves_the_outcome_by_polling_alone() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account_id) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000, 1_000_000_000).await;
    fund_balance(&db.pool, account_id, 10_000_000).await;
    let key = issue_key(&db.pool, account_id, &["poe:create"]).await;
    // A stalled backend so the first request is in flight while the second attaches
    // and reads `accepted` rather than a receipt.
    let backend = Arc::new(MockBackend::slow(Duration::from_millis(400)));
    let ts = state_with(db.pool.clone(), backend.clone(), 60);
    let addr = serve(ts.state.clone()).await;

    let bytes = FREE_WINDOW + 1;
    let key_clone = key.clone();
    let addr_clone = addr;
    // Fire the first (winning) upload in the background; it stalls in the provider.
    let winner = tokio::spawn(async move {
        post_uploads(addr_clone, &key_clone, &[paid_part("file_0", bytes)]).await
    });

    // Give the winner time to reserve the live attempt before the attacher arrives.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (s2, attach) = post_uploads(addr, &key, &[paid_part("file_0", bytes)]).await;
    assert_eq!(s2, 200, "the attacher returns 200, body = {attach}");

    // The attacher got an `accepted` shape pointing at the live attempt id (the
    // winner is still stalled in the provider). The attacher holds ONLY the attempt
    // id and NEVER subscribes to SSE.
    let attempt_id = attach["uploads"][0]["attempt_id"]
        .as_str()
        .expect("the attacher receives an attempt_id to poll")
        .to_string();
    assert_eq!(
        attach["uploads"][0]["accepted"], true,
        "the attacher attaches to the in-flight winner"
    );

    // Poll, with no event stream at all, until the attempt reaches its terminal
    // state. The poll route alone is the authoritative outcome read.
    let mut terminal: Option<Value> = None;
    for _ in 0..50 {
        let (s, body) = get_attempt(addr, &key, &attempt_id).await;
        assert_eq!(s, 200, "the poll succeeds, body = {body}");
        match body["state"].as_str() {
            Some("committed") | Some("released") => {
                terminal = Some(body);
                break;
            }
            Some("reserved") => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            other => panic!("unexpected poll state {other:?}"),
        }
    }
    let terminal = terminal.expect("the poll resolved a terminal outcome with no SSE");
    assert_eq!(
        terminal["state"], "committed",
        "the winner's success is observable to the attacher by polling alone"
    );
    assert_eq!(terminal["attempt_id"], attempt_id);
    assert!(
        terminal["uri"].as_str().unwrap().starts_with("ar://"),
        "the committed poll carries the receipt uri"
    );
    assert_eq!(terminal["charged_usd_micros"], 1);

    // The winner finished; the whole logical upload charged exactly once.
    let (ws, _) = winner.await.expect("winner task");
    assert_eq!(ws, 200, "the winner returns 200");
    assert_eq!(backend.upload_count(), 1, "one POST for the logical upload");
    assert_eq!(
        ledger_sum(&db.pool, account_id, "storage_upload").await,
        -1,
        "the logical upload is charged exactly once across both requests"
    );
}

// ---------------------------------------------------------------------------
// Byte-identity of the reconstruction (a pure crypto invariant, no DB needed): the
// persisted envelope plus the staged content reconstructs the EXACT bytes that were
// signed once, verifying under the stored id, so a re-POST never re-signs.
// ---------------------------------------------------------------------------

/// Sign `content` once with the fixture keyring exactly as the upload route does
/// (streaming the data leaf), returning the bounded envelope and the signer owner.
fn sign_once(content: &[u8]) -> (SignedEnvelope, Vec<u8>) {
    let keyring = unlocked_keyring();
    let funding = AuthorizedFunding::for_tests(Uuid::now_v7(), fixture_arweave_address());
    let signer = keyring
        .arweave_signer_for(&funding)
        .expect("the keyring holds the fixture funding key");
    let tags = vec![Tag::new(
        "Content-Type",
        b"application/octet-stream".to_vec(),
    )];
    let mut reader = content;
    let envelope = signer
        .sign_streaming_envelope(None, None, &tags, &mut reader, content.len() as u64)
        .expect("sign the data item once");
    (envelope, signer.owner())
}

#[tokio::test]
async fn the_persisted_envelope_reconstructs_the_byte_identical_signed_item() {
    let content: Vec<u8> = (0..200_003u32).map(|i| (i % 211) as u8).collect();
    let (envelope, owner) = sign_once(&content);

    // The signature is exactly the RSA-4096 length, and the id is SHA-256(signature).
    assert_eq!(envelope.signature.len(), 512, "RSA-4096 signature length");
    assert_eq!(envelope.signature_type, SIGNATURE_TYPE_ARWEAVE);
    let recomputed_id: [u8; 32] = Sha256::digest(&envelope.signature).into();
    assert_eq!(
        envelope.id, recomputed_id,
        "the stored id is SHA-256 of the stored signature"
    );

    // Reconstruct `prefix(envelope) | staged-content` (what the re-POST body builder
    // streams) and confirm it is a wire-valid data item whose id equals the stored
    // id. This is the load-bearing fact: a crashed attempt re-POSTs these exact bytes
    // from the persisted envelope + the durable staged file, never re-signing.
    let mut canonical = reconstruct_prefix(&envelope, &owner).expect("reconstruct prefix");
    canonical.extend_from_slice(&content);
    let verified = verify(&canonical).expect("the reconstructed item must verify");
    assert_eq!(
        verified.id, envelope.id,
        "the reconstructed item carries the stored id"
    );

    // Reconstruction is deterministic: a second reconstruction from the same envelope
    // + content yields byte-identical bytes (so a re-POST is reproducible).
    let mut again = reconstruct_prefix(&envelope, &owner).expect("reconstruct again");
    again.extend_from_slice(&content);
    assert_eq!(
        canonical, again,
        "reconstruction from the persisted envelope is byte-stable"
    );
}

// ---------------------------------------------------------------------------
// ANS-104 re-sign non-determinism (a pure crypto invariant): two independent signs
// of identical content yield DIFFERENT ids, because the PSS signature is randomised.
// This is WHY the envelope must be persisted: re-signing across a crash is not an
// option, so the once-signed envelope is the only way to reproduce the item id.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_signs_of_identical_content_yield_different_ids() {
    let content = b"identical content signed twice".to_vec();
    let (first, _) = sign_once(&content);
    let (second, _) = sign_once(&content);

    assert_ne!(
        first.signature, second.signature,
        "the randomised PSS signature differs run to run for identical content"
    );
    assert_ne!(
        first.id, second.id,
        "the item id (SHA-256 of the signature) differs, so re-signing changes the id"
    );
    assert_ne!(
        first.id_b64url, second.id_b64url,
        "the base64url id differs too"
    );

    // Both are nonetheless valid items over the same fields: the divergence is in the
    // signature, not the signed message — which is exactly why a re-POST must reuse
    // the persisted signature rather than produce a fresh one.
    let owner = {
        let (_, o) = sign_once(&content);
        o
    };
    for env in [&first, &second] {
        let mut bytes = reconstruct_prefix(env, &owner).expect("prefix");
        bytes.extend_from_slice(&content);
        let verified = verify(&bytes).expect("each independently-signed item verifies");
        assert_eq!(verified.id, env.id);
    }
}

// ---------------------------------------------------------------------------
// Paid-window duplicate-POST probe (env-gated live test).
//
// The free-tier case is settled empirically (a byte-identical re-POST returned the
// same data-item id and `winc:0`). The paid-window case — whether a FUNDED Turbo
// source re-charges winc for a second byte-identical POST of one id — needs a funded
// operator Turbo account, which is provisioned out of band. This probe POSTs one
// paid data item twice and records whether the second POST cost additional winc. The
// design does NOT depend on the answer (a paid double-charge is bounded to operator
// winc drift the reconcile cron corrects), but the probe settles the fact rather
// than assuming provider dedup.
//
// It runs only when both GATEWAY_TEST_TURBO_URL and GATEWAY_TEST_ARWEAVE_JWK_PATH
// (a FUNDED key) are set; otherwise it records that the paid-window result is
// pending funding and returns without failing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paid_window_duplicate_post_probe() {
    let Ok(upload_url) = std::env::var("GATEWAY_TEST_TURBO_URL") else {
        eprintln!(
            "paid-window duplicate-POST probe: PENDING FUNDING \
             (GATEWAY_TEST_TURBO_URL not set; the free-tier winc:0 case is already settled)"
        );
        return;
    };
    let Ok(jwk_path) = std::env::var("GATEWAY_TEST_ARWEAVE_JWK_PATH") else {
        eprintln!(
            "paid-window duplicate-POST probe: PENDING FUNDING \
             (GATEWAY_TEST_ARWEAVE_JWK_PATH not set)"
        );
        return;
    };
    let jwk = std::fs::read_to_string(&jwk_path).expect("read the funded JWK");
    let signer = ArweaveJwkSigner::from_jwk_json(&jwk).expect("parse the funded JWK");

    // A payload comfortably over the free window so a paid charge is in play.
    let payload: Vec<u8> = format!("paid-window probe {}", Uuid::now_v7())
        .into_bytes()
        .into_iter()
        .cycle()
        .take(FREE_WINDOW * 2)
        .collect();
    let tags = vec![Tag::new(
        "Content-Type",
        b"application/octet-stream".to_vec(),
    )];
    let mut reader = payload.as_slice();
    let envelope = ans104::sign_streaming(
        &signer,
        None,
        None,
        &tags,
        &mut reader,
        payload.len() as u64,
    )
    .expect("sign the probe item once");
    let mut body = reconstruct_prefix(&envelope, &signer.owner()).expect("prefix");
    body.extend_from_slice(&payload);

    let client = reqwest::Client::new();
    let post = |bytes: Vec<u8>| {
        let client = client.clone();
        let url = upload_url.clone();
        async move {
            let resp = client
                .post(format!("{url}/tx"))
                .header("content-type", "application/octet-stream")
                .body(bytes)
                .send()
                .await
                .expect("POST the data item");
            let status = resp.status();
            let json: Value = resp.json().await.unwrap_or(Value::Null);
            (status, json)
        }
    };

    let (s1, j1) = post(body.clone()).await;
    let (s2, j2) = post(body.clone()).await;

    // Record the observed behavior for the ship decision. The mechanism is correct
    // regardless; this settles the empirical fact.
    eprintln!(
        "paid-window duplicate-POST probe RESULT: \
         post#1 status={s1} winc={} id={}; post#2 status={s2} winc={} id={}",
        j1.get("winc").and_then(Value::as_str).unwrap_or("?"),
        j1.get("id").and_then(Value::as_str).unwrap_or("?"),
        j2.get("winc").and_then(Value::as_str).unwrap_or("?"),
        j2.get("id").and_then(Value::as_str).unwrap_or("?"),
    );

    // The data-item id is byte-identity-stable across the two POSTs (the design's
    // load-bearing assumption: a re-POST converges on the SAME stored item). This is
    // the assertion the design DOES rely on; the winc re-charge is informational.
    assert!(s1.is_success(), "the first paid POST is accepted");
    assert!(
        s2.is_success(),
        "the second byte-identical POST is accepted"
    );
    let id1 = j1.get("id").and_then(Value::as_str);
    let id2 = j2.get("id").and_then(Value::as_str);
    if let (Some(id1), Some(id2)) = (id1, id2) {
        assert_eq!(
            id1, id2,
            "a byte-identical re-POST returns the SAME data-item id"
        );
        assert_eq!(
            id1, envelope.id_b64url,
            "the provider id matches the locally-computed id"
        );
    }
}
