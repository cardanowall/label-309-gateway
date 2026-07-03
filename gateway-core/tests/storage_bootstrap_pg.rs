//! The self-host bootstrap path end to end, against a real Postgres.
//!
//! Proves the contract a single-key deployment relies on: from an operator + one
//! Arweave funding key, ONE engine call ([`bootstrap_service_source`]) registers a
//! drawable service-scoped source with no per-operator or per-account grant
//! choreography; the first reconcile stamps its winc balance; and an upload through
//! the real `/api/v1/poe/uploads` route then reserves, holds, and charges exactly
//! once. So the whole "unlock -> register one service source -> first reconcile ->
//! upload works" sequence is exercised in one test, asserting the end-state ledger
//! rows the saga writes, not log strings.
//!
//! It also pins the path's idempotency (a re-run renames the source in place and
//! converges on the one live service grant, never a second default) and its single
//! hard failure (a foreign-owned address is rejected, not silently aliased).
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::path::Path;
use std::pin::Pin;
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
    affords, bootstrap_service_source, reconcile_source, ActiveFundingSource, AffordVerdict,
    AuthorizedFunding, FundTxAck, FundTxRegistrar, ReconcileConfig, StorageBackend,
    StorageBackendExt, StorageError, StorageReceipt, WincBalance, WincBalanceProvider,
};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::{arweave_address, unlock, UnlockedKeyring};
use rust_decimal::Decimal;
use serde_json::Value;
use tokio::net::TcpListener;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The backend the bootstrap registers and the route uploads against.
const BACKEND: &str = "turbo";

/// One chargeable byte costs one micro-USD at this rate (1e9 femto = 1 micro).
const AR_USD_PER_BYTE_FEMTO: i64 = 1_000_000_000;

/// The free-storage window the default config quotes for free (100 KiB).
const FREE_WINDOW: usize = 102_400;

/// The throwaway Arweave JWK the keyring signs with (the ans104 test fixture).
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// A low scrypt work factor so the in-test keyring envelope encrypts/decrypts fast.
const TEST_SCRYPT_LOG_N: u8 = 4;

/// The Arweave address the fixture JWK derives to (the funding key the bootstrap
/// registers and the route resolves a signer through).
fn fixture_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

/// Build an unlocked keyring holding the fixture Arweave funding key, the same way
/// the binary unlocks the operator keyring before bootstrap.
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

/// A winc-balance provider that reports one fixed balance for any address, so the
/// first reconcile stamps a funded credit row exactly as a live provider read
/// would.
struct StubWincProvider {
    winc: Decimal,
    fundable_bytes: Option<i64>,
}

impl WincBalanceProvider for StubWincProvider {
    fn get_winc_balance<'a>(
        &'a self,
        _address: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<WincBalance, StorageError>> + Send + 'a>>
    {
        let balance = WincBalance {
            winc: self.winc,
            fundable_bytes: self.fundable_bytes,
        };
        Box::pin(async move { Ok(balance) })
    }
}

// ---------------------------------------------------------------------------
// Seeding + HTTP helpers (the same harness the uploads suite uses).
// ---------------------------------------------------------------------------

/// Insert one operator and return its id, the self-host owner after `operator
/// bootstrap`.
async fn seed_operator(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'self-host')")
        .bind(id)
        .execute(pool)
        .await
        .expect("insert operator");
    id
}

/// Insert one account under an operator and return its id.
async fn seed_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
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
    account_id
}

/// Credit an account's USD balance so a storage hold does not overdraw.
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

/// A registrar for a suite whose sources hold no registered top-ups: the
/// reconcile pass never polls it, so it unconditionally reports the payment
/// service unreachable.
struct NoTopUpRegistrar;

impl FundTxRegistrar for NoTopUpRegistrar {
    fn submit_fund_transaction<'a>(
        &'a self,
        _tx_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<FundTxAck, StorageError>> + Send + 'a>>
    {
        Box::pin(async {
            Err(StorageError::Unavailable(
                "no top-ups exist in this suite".to_string(),
            ))
        })
    }
}

/// Drive one reconcile pass over the bootstrapped source through a stub provider,
/// stamping its believed winc balance the way the serving runtime's reconcile loop
/// would on its first pass.
async fn first_reconcile(pool: &sqlx::PgPool, source_id: Uuid, winc: i64, fundable_bytes: i64) {
    let provider = StubWincProvider {
        winc: Decimal::from(winc),
        fundable_bytes: Some(fundable_bytes),
    };
    let source = ActiveFundingSource {
        id: source_id,
        arweave_address: fixture_arweave_address(),
        backend: BACKEND.to_string(),
    };
    let config = ReconcileConfig {
        winc_safety_floor: Decimal::ZERO,
        winc_drift_alert_threshold: Decimal::from(1_000_000_000_i64),
    };
    let mut summary = gateway_core::storage::ReconcileSummary::default();
    reconcile_source(
        pool,
        &provider,
        &NoTopUpRegistrar,
        &source,
        "first-tick",
        &config,
        &mut summary,
    )
    .await
    .expect("first reconcile stamps the balance");
}

/// A recording mock backend: returns a deterministic receipt keyed on the signed
/// item id, the same minimal backend the uploads suite signs through.
struct MockBackend {
    uploads: AtomicUsize,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            uploads: AtomicUsize::new(0),
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
        let data_item_id = envelope.id_b64url.clone();
        Ok(StorageReceipt {
            uri: format!("ar://{data_item_id}"),
            data_item_id,
            raw_receipt: serde_json::json!({ "backend": "mock" }),
            root_tx_id: None,
        })
    }
}

/// The durable staging directory, kept alive by the `TempDir` for the test.
struct TestState {
    state: AppState,
    _durable: tempfile::TempDir,
}

/// Build full app state: the backend, the pricing seam, and the upload-signing seam.
fn state_with(pool: sqlx::PgPool, backend: Arc<dyn StorageBackend>) -> TestState {
    let durable = tempfile::tempdir().expect("durable dir");
    let signing = UploadSigning::new(
        unlocked_keyring(),
        durable.path().to_path_buf(),
        Duration::from_secs(30),
        Duration::from_secs(60),
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

/// A multipart file part.
struct Part {
    field: String,
    content_type: String,
    bytes: Vec<u8>,
}

/// Frame a `multipart/form-data` body and its boundary from the given parts.
fn build_multipart(parts: &[Part]) -> (String, Vec<u8>) {
    let boundary = format!("----gwboot{}", Uuid::now_v7().simple());
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

/// One chargeable-byte payload (one byte over the free window).
fn one_chargeable_byte(field: &str) -> Part {
    Part {
        field: field.into(),
        content_type: "application/octet-stream".into(),
        bytes: vec![0xABu8; FREE_WINDOW + 1],
    }
}

/// Sum the ledger debits/credits of a kind for an account.
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

/// Count the live service grants for the backend, the cardinality the single-source
/// rule pins (exactly one live service default per backend).
async fn live_service_grants(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_grant \
         WHERE backend = $1 AND scope_kind = 'service' AND revoked_at IS NULL",
    )
    .bind(BACKEND)
    .fetch_one(pool)
    .await
    .expect("count live service grants")
}

// ---------------------------------------------------------------------------
// The end-to-end self-host path: bootstrap -> reconcile -> upload works.
// ---------------------------------------------------------------------------

/// The headline contract: one bootstrap call + the first reconcile is all a
/// single-key deployment needs before an upload reserves, holds, and charges once.
#[tokio::test]
async fn bootstrap_then_first_reconcile_makes_a_paid_upload_charge_exactly_once() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, operator).await;
    fund_balance(&db.pool, account, 10_000_000).await;
    let address = fixture_arweave_address();

    // Step 1: bootstrap registers a drawable service source with NO grant
    // choreography. The source is created and the service grant issued in one call.
    let outcome =
        bootstrap_service_source(&db.pool, operator, "primary", BACKEND, &address, &address)
            .await
            .expect("bootstrap registers the service source");
    assert!(outcome.source_created, "the source row is freshly created");
    assert!(outcome.grant_issued, "the service grant is freshly issued");
    assert_eq!(
        live_service_grants(&db.pool).await,
        1,
        "exactly one live service grant backs the backend"
    );

    // Before the first reconcile the source is unfunded: affords refuses, so an
    // upload could not proceed. This is the "explicit unknown/unfunded" state.
    let funding = AuthorizedFunding::for_tests(outcome.source_id, address.clone());
    assert_eq!(
        affords(&db.pool, funding.funding_source_id(), 1, Decimal::ZERO)
            .await
            .expect("affords reads cached credit"),
        AffordVerdict::Unfunded,
        "a never-reconciled source is unfunded until the first reconcile stamps it"
    );

    // Step 2: the first reconcile stamps the believed winc balance from the provider.
    first_reconcile(&db.pool, outcome.source_id, 1_000_000, 1_000_000_000).await;
    assert_eq!(
        affords(&db.pool, funding.funding_source_id(), 1, Decimal::ZERO)
            .await
            .expect("affords reads cached credit"),
        AffordVerdict::Affordable,
        "after the first reconcile the source affords the chargeable byte"
    );

    // Step 3: an upload through the real route now works, end to end, with no extra
    // setup. The resolver picks the bootstrapped service source for the account.
    let key = issue_key(&db.pool, account, &["poe:create"]).await;
    let backend = Arc::new(MockBackend::new());
    let ts = state_with(db.pool.clone(), backend.clone());
    let addr = serve(ts.state.clone()).await;

    let (status, json) = post_uploads(addr, &key, &[one_chargeable_byte("file_0")]).await;
    assert_eq!(
        status, 200,
        "the bootstrapped upload succeeds, body = {json}"
    );
    assert_eq!(json["uploads"][0]["ok"], true);
    assert_eq!(
        json["uploads"][0]["charged_usd_micros"], 1,
        "one chargeable byte costs one micro-USD"
    );
    assert_eq!(backend.upload_count(), 1, "the provider was POSTed once");

    // The attempt committed and the ledger nets to exactly one storage charge: the
    // hold and its release cancel, leaving the single storage_upload debit. This is
    // the proof that the bootstrapped source drew a real charge, end to end.
    let attempt_state: String =
        sqlx::query_scalar("SELECT state FROM cw_core.storage_upload_attempt LIMIT 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(attempt_state, "committed");
    assert_eq!(ledger_sum(&db.pool, account, "storage_hold").await, -1);
    assert_eq!(
        ledger_sum(&db.pool, account, "storage_hold_release").await,
        1
    );
    assert_eq!(ledger_sum(&db.pool, account, "storage_upload").await, -1);
    assert_eq!(
        balance_of(&db.pool, account).await,
        10_000_000 - 1,
        "the user paid exactly one micro-USD for storage"
    );

    // The receipt links back to the attempt the charge paid for, and the winc charge
    // landed on the bootstrapped source.
    let linked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1 AND attempt_id IS NOT NULL",
    )
    .bind(account)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(linked, 1, "the receipt links to its paying attempt");
    let winc_charges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_credit_ledger \
         WHERE funding_source_id = $1 AND kind = 'charge'",
    )
    .bind(outcome.source_id)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        winc_charges, 1,
        "the winc charge drew the bootstrapped source"
    );
}

/// Re-running the bootstrap is safe: a same-owner re-run renames the source in place
/// and converges on the one live service grant rather than minting a second default.
#[tokio::test]
async fn re_running_bootstrap_is_idempotent_and_keeps_one_service_grant() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool).await;
    let address = fixture_arweave_address();

    let first =
        bootstrap_service_source(&db.pool, operator, "primary", BACKEND, &address, &address)
            .await
            .expect("first bootstrap");
    assert!(first.source_created);
    assert!(first.grant_issued);

    // A re-run with a new label: the SAME source id (renamed in place), the SAME live
    // grant (converged), and still exactly one live service grant for the backend.
    let second =
        bootstrap_service_source(&db.pool, operator, "renamed", BACKEND, &address, &address)
            .await
            .expect("re-run bootstrap");
    assert_eq!(
        second.source_id, first.source_id,
        "the re-run renames the same source rather than minting a second"
    );
    assert_eq!(
        second.grant_id, first.grant_id,
        "the re-run converges on the existing live service grant"
    );
    assert!(!second.source_created, "no second source row was inserted");
    assert!(!second.grant_issued, "no second service grant was issued");

    assert_eq!(
        live_service_grants(&db.pool).await,
        1,
        "the single-source rule keeps exactly one live service grant per backend"
    );
    let label: String =
        sqlx::query_scalar("SELECT label FROM cw_core.storage_funding_source WHERE id = $1")
            .bind(first.source_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(label, "renamed", "the re-run renamed the source in place");
}

/// A foreign-owned address is the one hard failure: a second operator cannot
/// bootstrap a source for an address already owned by another, since that would
/// alias one provider credit pool. The right expression of a shared key is the
/// owner issuing a grant, not a parallel bootstrap.
#[tokio::test]
async fn bootstrapping_a_foreign_owned_address_is_rejected() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = seed_operator(&db.pool).await;
    let intruder = seed_operator(&db.pool).await;
    let address = fixture_arweave_address();

    bootstrap_service_source(&db.pool, owner, "primary", BACKEND, &address, &address)
        .await
        .expect("the owner bootstraps the source");

    let err = bootstrap_service_source(&db.pool, intruder, "steal", BACKEND, &address, &address)
        .await
        .expect_err("a different operator cannot re-bootstrap the same address");
    assert!(
        err.to_string().contains("another operator"),
        "the error explains the address is owned by another operator, got: {err}"
    );

    // The intruder created nothing: the source is still owned by the original owner,
    // and there is still exactly one live service grant.
    let source_owner: Uuid = sqlx::query_scalar(
        "SELECT owner_operator_id FROM cw_core.storage_funding_source \
         WHERE backend = $1 AND arweave_address = $2",
    )
    .bind(BACKEND)
    .bind(&address)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        source_owner, owner,
        "the source is still the original owner's"
    );
    assert_eq!(live_service_grants(&db.pool).await, 1);
}
