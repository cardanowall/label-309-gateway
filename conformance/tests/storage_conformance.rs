//! Storage-upload conformance (S1, S3): the content-upload surface driven over real
//! HTTP against a booted gateway with a stub storage backend.
//!
//! The upload-billing saga (reservation -> sign-once -> POST -> success-gated
//! charge, the partial-batch / concurrency / crash-recovery invariants, and the
//! poll-authoritative terminal read on a billed attempt — **S2**, **S4**) is proven
//! exhaustively at the engine level over real HTTP, where a non-zero per-byte
//! storage price produces the billed attempt rows those contracts read. This suite
//! exercises the published `/api/v1/poe/uploads` surface against a booted gateway,
//! with a harness stub backend in place of a live provider, to pin the conformance
//! contract a third party observes on the free-window path:
//!
//!   - **S1 (free-window data item):** a ≤free-window upload signs an ANS-104 data
//!     item, POSTs it through the backend, and returns an `ar://` URI plus the
//!     content sha256 — the same shape a record then carries as its `ar://` URI.
//!   - **S3 (duplicate-POST dedup):** a byte-identical re-upload is re-keyed on
//!     `(account, backend, sha256)`, reuses the first item's id (same `ar://` URI),
//!     and never POSTs the provider a second time, so it is never charged again.
//!
//! The live Turbo leg (**S1** against a real provider) is the gate. This suite uses
//! a stub backend, so it proves the route contract without a funded provider
//! account.
//!
//! Gated behind the `live` feature: the suite boots a real gateway over a real
//! Postgres.

#![cfg(feature = "live")]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use age::secrecy::SecretString;
use ans104::{Ans104Signer, ArweaveJwkSigner, SignedEnvelope};
use base64::Engine;
use conformance::BootedGateway;
use gateway_core::api::state::{ApiConfig, StorageState, UploadSigning};
use gateway_core::storage::{
    sweep_abandoned_sessions, AuthorizedFunding, StorageBackend, StorageBackendExt, StorageError,
    StorageReceipt, UploadSessionLimits,
};
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::{arweave_address, unlock, UnlockedKeyring};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The persisted backend identifier the stub registers under (the funding source,
/// grant, and receipt rows all carry it).
const BACKEND: &str = "turbo";

/// A low scrypt work factor so the in-test keyring envelope encrypts/decrypts fast.
const TEST_SCRYPT_LOG_N: u8 = 4;

/// The fixture Arweave key the upload route signs every data item through. A test
/// fixture, never a funded key.
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

// ---------------------------------------------------------------------------
// The stub storage backend: records each upload and returns a receipt derived from
// the once-signed item id, exactly as a real provider would echo it.
// ---------------------------------------------------------------------------

struct StubBackend {
    uploads: AtomicUsize,
    /// When set, `affords` reports `InsufficientCredit`, exactly as a real backend
    /// does when the operator's winc credit is below the floor for the requested
    /// bytes. Drives the create-time affordability rejection scenario.
    refuse_affordability: bool,
    /// When this flag is on, `affords` reports a transient `Unavailable` (a backend
    /// check fault), exactly as a real backend does on a 503/429/transport blip. The
    /// test toggles it to inject a TRANSIENT, PRE-RESERVE store failure during
    /// `/complete` and then clear it for the retry, so a session's recovery from a
    /// transient store error can be exercised without re-uploading a chunk.
    affords_unavailable: Arc<std::sync::atomic::AtomicBool>,
    /// When this flag is on, `upload` reports a transient `Unavailable` AFTER the
    /// attempt has been reserved (the POST step). This injects a POST-RESERVE store
    /// failure during `/complete`: the attempt is left `reserved` (it owns the
    /// promoted, renamed `.stage` file) and the route returns a retryable error, so a
    /// retried `/complete` must BRIDGE to the live attempt rather than revert the
    /// session to a vanished-file `open` and re-run the store.
    upload_unavailable: Arc<std::sync::atomic::AtomicBool>,
}

impl StubBackend {
    fn new() -> Self {
        Self {
            uploads: AtomicUsize::new(0),
            refuse_affordability: false,
            affords_unavailable: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            upload_unavailable: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// A stub whose affordability check refuses, simulating an account/operator
    /// below the storage-credit floor for the requested bytes.
    fn refusing_affordability() -> Self {
        Self {
            uploads: AtomicUsize::new(0),
            refuse_affordability: true,
            affords_unavailable: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            upload_unavailable: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// A stub whose `affords` check is gated on a shared toggle: while the returned
    /// flag is on, `affords` reports a transient `Unavailable`. The test flips it to
    /// inject and then clear a transient pre-reserve store failure.
    fn with_affords_toggle() -> (Self, Arc<std::sync::atomic::AtomicBool>) {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stub = Self {
            uploads: AtomicUsize::new(0),
            refuse_affordability: false,
            affords_unavailable: Arc::clone(&flag),
            upload_unavailable: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        (stub, flag)
    }

    /// A stub whose `upload` (the POST step, AFTER the attempt is reserved) is gated
    /// on a shared toggle: while the flag is on, `upload` reports a transient
    /// `Unavailable`. The test flips it to inject a POST-RESERVE store failure, then
    /// clears it for the retry, exercising the bridge-to-live-attempt recovery.
    fn with_upload_toggle() -> (Self, Arc<std::sync::atomic::AtomicBool>) {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stub = Self {
            uploads: AtomicUsize::new(0),
            refuse_affordability: false,
            affords_unavailable: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            upload_unavailable: Arc::clone(&flag),
        };
        (stub, flag)
    }

    fn upload_count(&self) -> usize {
        self.uploads.load(Ordering::SeqCst)
    }
}

impl StorageBackendExt for StubBackend {
    fn name(&self) -> &'static str {
        BACKEND
    }

    async fn affords(&self, _funding: &AuthorizedFunding, _bytes: u64) -> Result<(), StorageError> {
        if self
            .affords_unavailable
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(StorageError::Unavailable(
                "transient backend check fault".to_string(),
            ));
        }
        if self.refuse_affordability {
            Err(StorageError::InsufficientCredit)
        } else {
            Ok(())
        }
    }

    async fn upload(
        &self,
        _funding: &AuthorizedFunding,
        envelope: &SignedEnvelope,
        _owner: &[u8],
        _staged_path: &Path,
    ) -> Result<StorageReceipt, StorageError> {
        // A POST-RESERVE transient fault: the attempt is already reserved (it owns the
        // renamed `.stage` file) when this fires, so the route leaves it reserved and
        // returns a retryable error. No upload is counted on the failed POST.
        if self
            .upload_unavailable
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(StorageError::Unavailable(
                "transient POST fault".to_string(),
            ));
        }
        self.uploads.fetch_add(1, Ordering::SeqCst);
        let data_item_id = envelope.id_b64url.clone();
        Ok(StorageReceipt {
            uri: format!("ar://{data_item_id}"),
            data_item_id,
            raw_receipt: serde_json::json!({ "backend": "stub" }),
            root_tx_id: None,
        })
    }
}

// ---------------------------------------------------------------------------
// The fixture upload-signing keyring (an age-encrypted envelope holding the JWK).
// ---------------------------------------------------------------------------

/// The Arweave address the fixture JWK derives to (the funding source's address and
/// the keyring entry the route resolves a signer through).
fn fixture_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

/// An unlocked keyring holding the fixture Arweave funding key, exactly as the
/// running binary holds it (an age-encrypted envelope unlocked with a passphrase).
fn upload_keyring() -> Arc<UnlockedKeyring> {
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
    // Arweave entries do not carry a Cardano network; mainnet is arbitrary here.
    let keyring = unlock(
        &ciphertext,
        Zeroizing::new("test-pass".to_string()),
        Network::Mainnet,
    )
    .expect("the fixture keyring unlocks");
    Arc::new(keyring)
}

/// Build the storage seam the booted gateway serves uploads through: the stub
/// backend plus the upload-signing seam (fixture keyring + a durable staging dir).
fn storage_state(backend: Arc<StubBackend>, durable: &Path) -> StorageState {
    let signing = UploadSigning::new(
        upload_keyring(),
        durable.to_path_buf(),
        Duration::from_secs(30),
        Duration::from_secs(60),
    );
    StorageState::new(backend as Arc<dyn StorageBackend>).with_signing(signing)
}

// ---------------------------------------------------------------------------
// Seeding: a funded source the route resolves a signer through, plus an api key.
// ---------------------------------------------------------------------------

/// Register a funding source owned by `operator` for the fixture address, plus a
/// live service grant. The route's keyring resolves a signer for this address.
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

/// Frame a single-part `multipart/form-data` body and its boundary.
fn build_multipart(field: &str, bytes: &[u8]) -> (String, Vec<u8>) {
    let boundary = format!("----cfm{}", Uuid::now_v7().simple());
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{field}\"; filename=\"{field}.bin\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

/// POST a single-file multipart upload, returning (status, json).
async fn post_upload(base: &str, bearer: &str, field: &str, bytes: &[u8]) -> (u16, Value) {
    let (boundary, body) = build_multipart(field, bytes);
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/v1/poe/uploads"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .bearer_auth(bearer)
        .body(body)
        .send()
        .await
        .expect("send upload");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

/// Issue an api key with the given scopes for a seeded tenant, returning the bearer.
async fn issue_upload_key(pool: &sqlx::PgPool, account_id: Uuid) -> String {
    issue_upload_key_with_id(pool, account_id).await.0
}

/// Issue an api key and return both the bearer secret and the key row id. The key id
/// is the rate-limit subject (`viewer.key_id`), so a test that meters token spend
/// reads `rate_limit_bucket` keyed on this id.
async fn issue_upload_key_with_id(pool: &sqlx::PgPool, account_id: Uuid) -> (String, Uuid) {
    let secret = format!("cfm_{}", Uuid::now_v7().simple());
    let (lookup, hash) = gateway_core::api::middleware::auth::hash_secret(&secret);
    let key_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.api_key \
           (id, account_id, prefix, key_lookup, key_hash_sha256, scopes, rate_limit_per_min) \
         VALUES ($1, $2, 'cfm_', $3, $4, ARRAY['poe:create'], 6000)",
    )
    .bind(key_id)
    .bind(account_id)
    .bind(&lookup)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("insert api key");
    (secret, key_id)
}

/// The total rate-limit tokens reserved for a subject (the api-key id) across all
/// windows. `guard::authorize` reserves one token per admitted request via
/// `check_and_reserve`, which sums into `rate_limit_bucket.count`; summing the
/// subject's buckets is the authoritative count of tokens consumed by that key.
async fn rate_tokens_reserved(pool: &sqlx::PgPool, key_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT coalesce(sum(count), 0)::bigint FROM cw_core.rate_limit_bucket \
         WHERE subject = $1",
    )
    .bind(key_id.to_string())
    .fetch_one(pool)
    .await
    .expect("sum rate tokens")
}

// ---------------------------------------------------------------------------
// S1 — a free-window upload signs an ANS-104 data item, POSTs it, and returns an
// ar:// URI plus the content sha256 (the shape a record carries).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn s1_free_window_upload_returns_data_item_and_ar_uri() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage(storage_state(Arc::clone(&backend), durable.path()))
        .await
        .expect("boot");

    // A tenant with a funded source whose address the route signs through.
    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    // A small (free-window) payload: it signs an ANS-104 item and POSTs the stub.
    let content = b"conformance content";
    let (status, json) = post_upload(&gw.base_url, &key, "file_0", content).await;
    assert_eq!(status, 200, "the upload returns 200: {json}");
    let result = &json["uploads"][0];
    assert_eq!(result["ok"], true, "the free-window file committed: {json}");
    assert_eq!(
        result["charged_usd_micros"], 0,
        "a free-window file charges 0"
    );
    let uri = result["uri"].as_str().expect("an ar:// uri");
    assert!(
        uri.starts_with("ar://"),
        "the receipt carries an ar:// uri: {uri}"
    );
    // The data item id is the ar:// path; it is the same id a record references.
    let data_item_id = uri.strip_prefix("ar://").expect("ar:// prefix");
    assert!(
        !data_item_id.is_empty(),
        "the ar:// uri carries the data-item id"
    );
    // The content sha256 is echoed, so a verifier can recompute it from the bytes.
    let expected_sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(content));
    assert_eq!(
        result["sha256"], expected_sha,
        "the content sha256 is echoed"
    );
    assert_eq!(backend.upload_count(), 1, "exactly one provider POST");

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// S3 — byte-identical re-upload is re-keyed on (account, backend, sha256) and
// charges 0, reusing the first item's id, with no second provider POST.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn s3_duplicate_post_dedup_charges_zero() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage(storage_state(Arc::clone(&backend), durable.path()))
        .await
        .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let content = b"byte-identical-conformance-content";

    // First upload: signs + POSTs once.
    let (s1, j1) = post_upload(&gw.base_url, &key, "file_0", content).await;
    assert_eq!(s1, 200);
    let first_uri = j1["uploads"][0]["uri"].as_str().expect("uri").to_string();
    assert_eq!(backend.upload_count(), 1, "the first upload POSTs once");

    // Second, byte-identical upload: deduped, same uri, NO second provider POST.
    // The dedup hit converges on the prior receipt: it reuses the first item's id
    // and applies no charge (the charge field is absent because no new charge was
    // made), and the provider is never paid twice — the load-bearing dedup fact.
    let (s2, j2) = post_upload(&gw.base_url, &key, "file_0", content).await;
    assert_eq!(s2, 200);
    let second = &j2["uploads"][0];
    assert_eq!(second["ok"], true, "the dedup hit is a success: {j2}");
    assert!(
        second
            .get("charged_usd_micros")
            .is_none_or(|v| v == &Value::from(0)),
        "a dedup re-upload applies no new charge (absent or 0): {j2}"
    );
    assert_eq!(
        second["uri"].as_str().unwrap(),
        first_uri,
        "the dedup re-upload reuses the first item's id (same ar:// uri)"
    );
    assert_eq!(
        backend.upload_count(),
        1,
        "a byte-identical re-upload does NOT POST the provider a second time"
    );

    gw.shutdown().await;
}

// ===========================================================================
// Resumable / chunked upload conformance.
//
// The single-shot route is byte-stable; chunking is an additive session
// sub-resource that ENDS by handing one assembled durable file into the SAME
// `store_one` the single-shot route uses. These scenarios prove that, end to end,
// over real HTTP against a booted gateway:
//
//   - the single-shot path is unperturbed (regression guard, R1);
//   - a multi-chunk file (mixed-order PUTs) assembles, charges EXACTLY once, and
//     leaves NO per-chunk ledger rows (R2);
//   - a dropped chunk resumes, a matching re-PUT is an idempotent 200, a differing
//     re-PUT is 409 (R3);
//   - dedup at create short-circuits with no session, no upload, no charge (R4);
//   - an unaffordable upload is rejected at create with no session (R5);
//   - the assembled-hash integrity gate fails a corrupt-but-complete upload before
//     a byte is signed or charged, deleting the file (R6);
//   - the abandoned-session janitor reclaims an expired session's file (R7);
//   - two sessions for the same content converge on ONE attempt / ONE charge (R8);
//   - the crash-safety hazard (metadata ahead of bytes, or its inverse) never
//     yields a corrupt-but-accepted upload (R9, the durable-write-before-receipt
//     backstop).
//
// All chunked scenarios boot the gateway with a small chunk grid (so a tiny file
// spans several chunks) and a per-byte price (so a charge is real, not zero), via
// `start_with_storage_config`. The single billing event is the storage attempt
// reserve reached exactly once at `/complete`; chunks carry zero ledger effects.
// ===========================================================================

/// A per-byte storage price (femto-USD) that turns one chargeable byte into one
/// USD-micro: `price_storage(bytes, 1e9) = ceil(bytes * 1e9 / 1e9) = bytes`. So a
/// file of N bytes over a zero free window charges exactly N micros, identical on
/// the single-shot and the chunked path (both run `store_one` under this price).
const ONE_MICRO_PER_BYTE_FEMTO: i64 = 1_000_000_000;

/// A small chunk size for the tests: a few dozen bytes per chunk, so a ~50-byte
/// file spans several chunks and the bodies stay tiny. A real client chunks at tens
/// of megabytes; the protocol is size-agnostic, so a small grid exercises the same
/// offset/bitmap/assembly machinery.
const TEST_CHUNK_BYTES: u64 = 16;

/// The data-plane config the chunked scenarios boot under: a small chunk grid and a
/// zero free window (so a tiny file is chargeable and the charge is exactly its
/// byte count). The durable assembling directory is the storage seam's durable
/// staging directory, set by the harness boot.
fn chunked_config() -> ApiConfig {
    ApiConfig {
        // A zero free window so every test byte is chargeable; the charge is then a
        // clean function of the byte count, identical across both ingress paths.
        free_storage_bytes: 0,
        upload_session_limits: UploadSessionLimits {
            max_chunk_bytes: TEST_CHUNK_BYTES,
            default_chunk_bytes: TEST_CHUNK_BYTES,
            ..UploadSessionLimits::default()
        },
        ..ApiConfig::default()
    }
}

/// The lowercase-hex whole-file digest a session declares at create.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The RFC 9530 `Digest: sha-256=<base64>` value for a chunk's bytes.
fn chunk_digest_header(bytes: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(bytes));
    format!("sha-256={b64}")
}

/// The byte range chunk `index` covers against a known total and chunk size.
fn chunk_slice(content: &[u8], index: u32, chunk_bytes: u64) -> &[u8] {
    let start = (u64::from(index) * chunk_bytes) as usize;
    let end = ((u64::from(index) + 1) * chunk_bytes).min(content.len() as u64) as usize;
    &content[start..end]
}

/// POST a session-create body, returning (status, json).
async fn create_session(base: &str, bearer: &str, body: Value) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/v1/poe/uploads/sessions"))
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await
        .expect("send create session");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// PUT one chunk's raw bytes with its required Content-Length and Digest header,
/// returning (status, json). `digest_override` injects a deliberately wrong digest
/// (the conflict / corruption probes); otherwise the true chunk digest is sent.
async fn put_chunk(
    base: &str,
    bearer: &str,
    session_id: &str,
    index: u32,
    bytes: &[u8],
    digest_override: Option<&str>,
) -> (u16, Value) {
    let digest = digest_override
        .map(|d| d.to_string())
        .unwrap_or_else(|| chunk_digest_header(bytes));
    let resp = reqwest::Client::new()
        .put(format!(
            "{base}/api/v1/poe/uploads/sessions/{session_id}/chunks/{index}"
        ))
        .bearer_auth(bearer)
        .header("content-type", "application/octet-stream")
        .header("content-length", bytes.len().to_string())
        .header("digest", digest)
        .body(bytes.to_vec())
        .send()
        .await
        .expect("send chunk");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// GET a session's resume status, returning (status, json).
async fn get_session(base: &str, bearer: &str, session_id: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/v1/poe/uploads/sessions/{session_id}"))
        .bearer_auth(bearer)
        .send()
        .await
        .expect("send get session");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// POST a session complete, returning (status, json).
async fn complete_session(base: &str, bearer: &str, session_id: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!(
            "{base}/api/v1/poe/uploads/sessions/{session_id}/complete"
        ))
        .bearer_auth(bearer)
        .send()
        .await
        .expect("send complete");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

// ---------------------------------------------------------------------------
// Row-count assertions: a logical file produces EXACTLY one attempt, one committed
// receipt, and one believed-winc charge — and chunks produce NONE of these.
// ---------------------------------------------------------------------------

async fn count_attempts(pool: &sqlx::PgPool, account_id: Uuid, sha256: &[u8]) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload_attempt \
         WHERE account_id = $1 AND backend = $2 AND sha256 = $3",
    )
    .bind(account_id)
    .bind(BACKEND)
    .bind(sha256)
    .fetch_one(pool)
    .await
    .expect("count attempts")
}

async fn count_committed_uploads(pool: &sqlx::PgPool, account_id: Uuid, sha256: &[u8]) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload \
         WHERE account_id = $1 AND backend = $2 AND sha256 = $3",
    )
    .bind(account_id)
    .bind(BACKEND)
    .bind(sha256)
    .fetch_one(pool)
    .await
    .expect("count committed uploads")
}

/// The believed-winc `charge` rows whose `ref` is one of this account's attempt
/// ids (the charge is keyed on `attempt.id`). One charge per billed attempt.
async fn count_winc_charges(pool: &sqlx::PgPool, account_id: Uuid, sha256: &[u8]) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_credit_ledger l \
         WHERE l.kind = 'charge' AND l.ref IN ( \
             SELECT a.id::text FROM cw_core.storage_upload_attempt a \
             WHERE a.account_id = $1 AND a.backend = $2 AND a.sha256 = $3)",
    )
    .bind(account_id)
    .bind(BACKEND)
    .bind(sha256)
    .fetch_one(pool)
    .await
    .expect("count winc charges")
}

async fn count_sessions(pool: &sqlx::PgPool, account_id: Uuid, sha256: &[u8]) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload_session \
         WHERE account_id = $1 AND sha256 = $2",
    )
    .bind(account_id)
    .bind(sha256)
    .fetch_one(pool)
    .await
    .expect("count sessions")
}

/// The lifecycle state string a session row carries, read straight from the DB (the
/// authoritative truth a `GET` would also report).
async fn session_state_in_db(pool: &sqlx::PgPool, session_id: Uuid) -> String {
    sqlx::query_scalar("SELECT state FROM cw_core.storage_upload_session WHERE id = $1")
        .bind(session_id)
        .fetch_one(pool)
        .await
        .expect("read session state")
}

/// Count an account's currently open/assembling sessions (the live backpressure set
/// the create cap is enforced against).
async fn count_open_sessions_in_db(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload_session \
         WHERE account_id = $1 AND state IN ('open', 'assembling')",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("count open sessions")
}

/// The total `storage_credit_ledger` row count for this account's funding source,
/// of any kind. Used to prove a chunk PUT appends NO ledger row.
async fn count_all_ledger_for_account(pool: &sqlx::PgPool, operator_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_credit_ledger l \
         JOIN cw_core.storage_funding_source s ON s.id = l.funding_source_id \
         WHERE s.owner_operator_id = $1",
    )
    .bind(operator_id)
    .fetch_one(pool)
    .await
    .expect("count ledger rows")
}

// ---------------------------------------------------------------------------
// R1 — single-shot still works unchanged. A regression guard: chunking is purely
// additive, so a single-shot multipart upload under the chunked-scenario boot
// (small grid + a price) behaves exactly as it always has.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r1_single_shot_still_works_unchanged() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    // A 50-byte file: with a zero free window and the one-micro-per-byte price, the
    // single-shot path charges exactly 50 micros, signs once, and POSTs once.
    let content = vec![0xABu8; 50];
    let (status, json) = post_upload(&gw.base_url, &key, "file_0", &content).await;
    assert_eq!(status, 200, "the single-shot upload returns 200: {json}");
    let result = &json["uploads"][0];
    assert_eq!(result["ok"], true, "the file committed: {json}");
    assert_eq!(
        result["charged_usd_micros"], 50,
        "50 chargeable bytes charge 50 micros"
    );
    assert!(
        result["uri"].as_str().expect("uri").starts_with("ar://"),
        "the receipt carries an ar:// uri"
    );
    assert_eq!(
        result["sha256"],
        sha256_hex(&content),
        "the sha256 is echoed"
    );
    assert_eq!(backend.upload_count(), 1, "exactly one provider POST");

    // Exactly one attempt, one committed receipt, one believed-winc charge.
    let sha = Sha256::digest(&content).to_vec();
    assert_eq!(count_attempts(&gw.pool, tenant.account_id, &sha).await, 1);
    assert_eq!(
        count_committed_uploads(&gw.pool, tenant.account_id, &sha).await,
        1
    );
    assert_eq!(
        count_winc_charges(&gw.pool, tenant.account_id, &sha).await,
        1
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R2 — chunked upload of a >=3-chunk file (mixed-order PUTs) assembles, charges
// EXACTLY once, and produces NO per-chunk ledger rows. The charge equals the
// single-shot charge for the identical bytes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r2_chunked_upload_assembles_and_charges_once() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    // 50 bytes over a 16-byte chunk = 4 chunks (16,16,16,2). PUT them out of order
    // and assert assembly is order-independent (positional writes).
    let content: Vec<u8> = (0..50u8).collect();
    let sha = Sha256::digest(&content).to_vec();

    // The believed-winc ledger is empty before this upload; a chunk PUT must not add
    // to it. Snapshot the count to prove chunks have zero ledger effect.
    let ledger_before = count_all_ledger_for_account(&gw.pool, tenant.operator_id).await;
    assert_eq!(ledger_before, 0, "no ledger rows before the upload");

    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id = created["session_id"]
        .as_str()
        .expect("session_id")
        .to_string();
    assert_eq!(created["chunk_count"], 4, "50 / 16 -> 4 chunks");

    // Mixed / out-of-order PUTs; after each chunk the ledger is still empty (chunks
    // carry zero ledger effect, asserted BY observation).
    for &idx in &[2u32, 0, 3, 1] {
        let slice = chunk_slice(&content, idx, TEST_CHUNK_BYTES);
        let (ps, pj) = put_chunk(&gw.base_url, &key, &session_id, idx, slice, None).await;
        assert_eq!(ps, 200, "chunk {idx} accepted: {pj}");
        assert_eq!(
            count_all_ledger_for_account(&gw.pool, tenant.operator_id).await,
            0,
            "a chunk PUT appends NO ledger row (chunk {idx})"
        );
        // No attempt row exists yet either — billing has not begun.
        assert_eq!(
            count_attempts(&gw.pool, tenant.account_id, &sha).await,
            0,
            "no attempt before complete (after chunk {idx})"
        );
    }

    let (comp_status, comp_json) = complete_session(&gw.base_url, &key, &session_id).await;
    assert_eq!(comp_status, 200, "complete committed: {comp_json}");
    assert_eq!(comp_json["ok"], true, "the assembled file committed");
    assert!(
        comp_json["uri"].as_str().expect("uri").starts_with("ar://"),
        "one ar:// uri for the assembled file"
    );
    assert_eq!(
        comp_json["sha256"],
        sha256_hex(&content),
        "the whole-file sha256"
    );
    // 50 bytes at one-micro-per-byte = 50 micros, IDENTICAL to the single-shot R1
    // charge for the same byte count.
    assert_eq!(
        comp_json["charged_usd_micros"], 50,
        "the chunked charge equals the single-shot charge for the same bytes"
    );

    // Exactly one provider POST (sign-once, post-once), one attempt, one committed
    // receipt, one believed-winc charge — and no per-chunk rows of any kind.
    assert_eq!(backend.upload_count(), 1, "exactly one provider POST");
    assert_eq!(
        count_attempts(&gw.pool, tenant.account_id, &sha).await,
        1,
        "exactly one storage_upload_attempt row"
    );
    assert_eq!(
        count_committed_uploads(&gw.pool, tenant.account_id, &sha).await,
        1,
        "exactly one storage_upload debit"
    );
    assert_eq!(
        count_winc_charges(&gw.pool, tenant.account_id, &sha).await,
        1,
        "exactly one believed-winc charge"
    );
    // The full ledger has exactly the one charge row; no chunk added anything.
    assert_eq!(
        count_all_ledger_for_account(&gw.pool, tenant.operator_id).await,
        1,
        "the only ledger row is the single attempt charge — no per-chunk rows"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R3 — resume after a dropped chunk: PUT all but one, GET asserts missing==[k],
// PUT k, complete succeeds. Also: a re-PUT of a received chunk is an idempotent
// 200; a re-PUT with a different digest is 409.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r3_resume_after_dropped_chunk_and_idempotent_reput() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let content: Vec<u8> = (0..40u8).collect(); // 16,16,8 -> 3 chunks
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id = created["session_id"]
        .as_str()
        .expect("session_id")
        .to_string();
    assert_eq!(created["chunk_count"], 3);

    // PUT chunks 0 and 2; drop chunk 1.
    for idx in [0u32, 2] {
        let slice = chunk_slice(&content, idx, TEST_CHUNK_BYTES);
        let (ps, _) = put_chunk(&gw.base_url, &key, &session_id, idx, slice, None).await;
        assert_eq!(ps, 200);
    }

    // A premature complete is 409 incomplete-upload and lists the missing index.
    let (incomp_status, incomp_json) = complete_session(&gw.base_url, &key, &session_id).await;
    assert_eq!(
        incomp_status, 409,
        "complete before all chunks is 409: {incomp_json}"
    );
    assert_eq!(incomp_json["code"], "incomplete-upload");
    assert_eq!(
        incomp_json["missing"],
        json!([1]),
        "the missing index is surfaced"
    );

    // GET status: the resume contract reports exactly the missing index.
    let (gs, status_json) = get_session(&gw.base_url, &key, &session_id).await;
    assert_eq!(gs, 200, "status returns 200: {status_json}");
    assert_eq!(status_json["state"], "open");
    assert_eq!(status_json["missing"], json!([1]), "GET missing == [1]");
    assert_eq!(status_json["received"], json!([0, 2]));

    // A re-PUT of an already-received chunk with the SAME digest is an idempotent 200.
    let slice0 = chunk_slice(&content, 0, TEST_CHUNK_BYTES);
    let (re_status, re_json) = put_chunk(&gw.base_url, &key, &session_id, 0, slice0, None).await;
    assert_eq!(
        re_status, 200,
        "a matching re-PUT is an idempotent 200: {re_json}"
    );
    // Still 2 received, not 3 — the re-PUT did not double-count.
    assert_eq!(re_json["received"], json!([0, 2]));

    // A re-PUT of a received chunk with a DIFFERENT digest is 409 chunk-conflict (the
    // client contradicts itself for a fixed offset). Send bytes that would hash
    // differently but carry a Digest header for THOSE bytes, so the ingress digest
    // check passes and the conflict is decided at the bitmap CAS.
    let other_bytes = vec![0x99u8; slice0.len()];
    let (conf_status, conf_json) =
        put_chunk(&gw.base_url, &key, &session_id, 0, &other_bytes, None).await;
    assert_eq!(conf_status, 409, "a differing re-PUT is 409: {conf_json}");
    assert_eq!(conf_json["code"], "chunk-conflict");

    // Now resume: PUT the missing chunk 1, then complete succeeds.
    let slice1 = chunk_slice(&content, 1, TEST_CHUNK_BYTES);
    let (ps1, pj1) = put_chunk(&gw.base_url, &key, &session_id, 1, slice1, None).await;
    assert_eq!(ps1, 200, "the resumed chunk is accepted: {pj1}");
    assert_eq!(pj1["complete"], true, "all chunks now received");

    let (comp_status, comp_json) = complete_session(&gw.base_url, &key, &session_id).await;
    assert_eq!(
        comp_status, 200,
        "complete after resume succeeds: {comp_json}"
    );
    assert_eq!(comp_json["ok"], true);
    assert_eq!(comp_json["sha256"], sha256_hex(&content));
    assert_eq!(backend.upload_count(), 1, "still exactly one provider POST");

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R4 — dedup at create short-circuits: commit a file single-shot, then create a
// session for the same (account, backend, sha256). Assert 200 deduplicated with the
// existing URI, NO session row, no chunk upload, no charge.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r4_dedup_at_create_short_circuits() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    // Commit the file single-shot first.
    let content = vec![0x42u8; 50];
    let (s1, j1) = post_upload(&gw.base_url, &key, "file_0", &content).await;
    assert_eq!(s1, 200);
    let committed_uri = j1["uploads"][0]["uri"].as_str().expect("uri").to_string();
    assert_eq!(backend.upload_count(), 1, "the first upload POSTs once");

    // Now create a session for the IDENTICAL content: it must short-circuit.
    let sha = Sha256::digest(&content).to_vec();
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(
        cs, 200,
        "a dedup hit at create returns 200, not 201: {created}"
    );
    assert_eq!(
        created["deduplicated"], true,
        "the create dedup is signalled"
    );
    assert_eq!(
        created["uri"].as_str().unwrap(),
        committed_uri,
        "the existing receipt URI is returned"
    );
    assert_eq!(created["charged_usd_micros"], 0, "no charge on a dedup hit");
    assert!(
        created.get("session_id").is_none(),
        "a dedup hit creates NO session: {created}"
    );

    // No session row was created (the dedup short-circuited before any insert).
    assert_eq!(
        count_sessions(&gw.pool, tenant.account_id, &sha).await,
        0,
        "no session row exists for the deduped content"
    );
    // No second provider POST, exactly one committed receipt, one attempt (the
    // single-shot one), one charge — the dedup added nothing.
    assert_eq!(
        backend.upload_count(),
        1,
        "the dedup did NOT POST the provider"
    );
    assert_eq!(
        count_committed_uploads(&gw.pool, tenant.account_id, &sha).await,
        1
    );
    assert_eq!(count_attempts(&gw.pool, tenant.account_id, &sha).await, 1);
    assert_eq!(
        count_winc_charges(&gw.pool, tenant.account_id, &sha).await,
        1
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R5 — affordability rejected at create: an account whose funding cannot fund the
// chargeable bytes gets 402 BEFORE any chunk. Assert no session row.
//
// The stub's `affords` is configured to refuse, exactly as a real backend reports
// `InsufficientCredit` when the operator's winc credit is below the floor for the
// requested bytes — the create-time affordability check the billed path also runs.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r5_affordability_rejected_at_create() {
    let backend = Arc::new(StubBackend::refusing_affordability());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    // A chargeable file (50 bytes over a zero free window): the create-time
    // affordability check refuses it before a single chunk.
    let content = vec![0x7Fu8; 50];
    let sha = Sha256::digest(&content).to_vec();
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(
        cs, 402,
        "an unaffordable upload is 402 at create: {created}"
    );
    assert_eq!(
        created["code"], "insufficient-storage-credit",
        "the funding-refusal problem code"
    );

    // No session row, no provider POST.
    assert_eq!(
        count_sessions(&gw.pool, tenant.account_id, &sha).await,
        0,
        "an unaffordable create leaves NO session row"
    );
    assert_eq!(backend.upload_count(), 0, "no upload was attempted");

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R6 — integrity gate: complete a session whose assembled bytes do not match the
// declared sha256. Assert 400 sha256-mismatch, session failed, assembling file
// deleted, no attempt, no charge.
//
// The whole-file gate is exercised honestly: the client declares the hash of one
// content but uploads the chunks of a DIFFERENT content (each chunk carrying its
// OWN correct per-chunk Digest, so the ingress digest checks pass). The assembled
// file is internally consistent but is not what was declared, so the whole-file
// SHA-256 != declared, and the session fails before a byte is signed or charged.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r6_integrity_gate_fails_a_mismatched_assembly() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let declared: Vec<u8> = (0..40u8).collect();
    let actual: Vec<u8> = (100..140u8).collect(); // same length, different bytes
    let declared_sha = Sha256::digest(&declared).to_vec();

    // Declare the hash of `declared` but upload the chunks of `actual`. The chunk
    // grid is the same length (3 chunks), and each chunk carries its OWN digest.
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&declared), "total_bytes": declared.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id = created["session_id"]
        .as_str()
        .expect("session_id")
        .to_string();

    for idx in 0..3u32 {
        let slice = chunk_slice(&actual, idx, TEST_CHUNK_BYTES);
        let (ps, pj) = put_chunk(&gw.base_url, &key, &session_id, idx, slice, None).await;
        assert_eq!(
            ps, 200,
            "the per-chunk digest passes (each chunk is self-consistent): {pj}"
        );
    }

    // Complete: the whole-file hash != declared, so the integrity gate fails it.
    let (comp_status, comp_json) = complete_session(&gw.base_url, &key, &session_id).await;
    assert_eq!(
        comp_status, 400,
        "the integrity gate fails the assembly: {comp_json}"
    );
    assert_eq!(comp_json["code"], "sha256-mismatch");

    // The session is failed; no attempt, no committed receipt, no charge.
    let (gs, status_json) = get_session(&gw.base_url, &key, &session_id).await;
    assert_eq!(gs, 200);
    assert_eq!(status_json["state"], "failed", "the session is failed");
    assert_eq!(
        count_attempts(&gw.pool, tenant.account_id, &declared_sha).await,
        0,
        "no attempt for a failed integrity gate"
    );
    assert_eq!(
        count_committed_uploads(&gw.pool, tenant.account_id, &declared_sha).await,
        0
    );
    assert_eq!(backend.upload_count(), 0, "nothing was signed or POSTed");

    // The assembling file was deleted (the session's assembling_path is cleared on
    // failure, and the durable directory holds no .assembling file for this session).
    let assembling = durable
        .path()
        .join(format!("{}.assembling", session_id.replace('-', "")));
    assert!(
        !assembling.exists(),
        "the assembling file is deleted on a failed integrity gate"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R7 — abandoned-session janitor: create a session, PUT one chunk, advance past
// expires_at, run the session janitor. Assert the assembling file is reclaimed and
// the session is expired (the twin of the staging-orphan janitor test).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r7_abandoned_session_janitor_reclaims_the_file() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let content: Vec<u8> = (0..40u8).collect();
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id_str = created["session_id"]
        .as_str()
        .expect("session_id")
        .to_string();
    let session_id = Uuid::parse_str(&session_id_str).expect("uuid");

    // PUT one chunk, then abandon the upload (no further chunks, no complete).
    let slice = chunk_slice(&content, 0, TEST_CHUNK_BYTES);
    let (ps, _) = put_chunk(&gw.base_url, &key, &session_id_str, 0, slice, None).await;
    assert_eq!(ps, 200);

    // The assembling file exists on disk while the session is live.
    let assembling = durable
        .path()
        .join(format!("{}.assembling", session_id.simple()));
    assert!(assembling.exists(), "the assembling file exists while live");

    // Advance the session past its TTL (the harness owns the DB, so it ages the row
    // directly — the same effect as wall-clock passing the TTL).
    sqlx::query("UPDATE cw_core.storage_upload_session SET expires_at = now() - interval '1 hour' WHERE id = $1")
        .bind(session_id)
        .execute(&gw.pool)
        .await
        .expect("age the session");

    // Run the session janitor sweep over the durable assembling directory.
    let summary = sweep_abandoned_sessions(&gw.pool, durable.path())
        .await
        .expect("janitor sweep");
    assert!(
        summary.sessions_expired >= 1,
        "the abandoned session is expired"
    );
    assert!(
        summary.files_reclaimed >= 1,
        "the assembling file is reclaimed"
    );

    // The session is now expired and the file is gone.
    let (gs, status_json) = get_session(&gw.base_url, &key, &session_id_str).await;
    assert_eq!(gs, 200);
    assert_eq!(
        status_json["state"], "expired",
        "the session is marked expired"
    );
    assert!(
        !assembling.exists(),
        "the assembling file is reclaimed by the janitor"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R8 — two sessions, same content, both complete: one wins reserve_attempt and the
// other ATTACHES (no second charge), exercising the convergence-at-reserve path.
// The session table is permissive (two sessions for one sha256 may coexist); the
// attempt table's live-uniqueness is the convergence point.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r8_two_sessions_same_content_converge_on_one_charge() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let content: Vec<u8> = (0..50u8).collect();
    let sha = Sha256::digest(&content).to_vec();

    // Open TWO sessions for the same content (each not knowing of the other), fill
    // both fully.
    let (sa, created_a) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(sa, 201, "session A created: {created_a}");
    let session_a = created_a["session_id"].as_str().unwrap().to_string();

    let (sb, created_b) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(sb, 201, "session B created: {created_b}");
    let session_b = created_b["session_id"].as_str().unwrap().to_string();
    assert_ne!(
        session_a, session_b,
        "two distinct sessions for one content"
    );
    // Two permissive session rows coexist for one sha256.
    assert_eq!(
        count_sessions(&gw.pool, tenant.account_id, &sha).await,
        2,
        "the session table permits two sessions for one content"
    );

    for session in [&session_a, &session_b] {
        for idx in 0..4u32 {
            let slice = chunk_slice(&content, idx, TEST_CHUNK_BYTES);
            let (ps, _) = put_chunk(&gw.base_url, &key, session, idx, slice, None).await;
            assert_eq!(ps, 200);
        }
    }

    // Complete A: it wins reserve_attempt, commits, and charges once.
    let (ca, comp_a) = complete_session(&gw.base_url, &key, &session_a).await;
    assert_eq!(ca, 200, "session A completes: {comp_a}");
    assert_eq!(comp_a["ok"], true, "session A committed the bytes");
    let uri_a = comp_a["uri"].as_str().expect("uri").to_string();

    // Complete B: the bytes are already committed for this content, so B converges on
    // the prior receipt — a deduped completion with NO second charge and NO second
    // provider POST. (Whether B reports `ok`-dedup or `accepted` depends on timing;
    // either way it must not produce a second charge.)
    let (cb, comp_b) = complete_session(&gw.base_url, &key, &session_b).await;
    assert_eq!(cb, 200, "session B completes: {comp_b}");
    if comp_b.get("ok").is_some() {
        assert_eq!(comp_b["ok"], true);
        assert_eq!(
            comp_b["uri"].as_str().unwrap(),
            uri_a,
            "B resolves to A's URI"
        );
        assert_eq!(
            comp_b["charged_usd_micros"], 0,
            "B's completion charges nothing"
        );
    } else {
        assert_eq!(
            comp_b["accepted"], true,
            "B attached to A's attempt: {comp_b}"
        );
    }

    // The convergence invariant: exactly ONE committed receipt, ONE believed-winc
    // charge, and ONE provider POST for the logical upload, regardless of two
    // sessions. (Two attempt rows MAY exist — A's claimed and B's that lost the
    // live-slot race and was released/deduped — but only ONE charge is applied.)
    assert_eq!(
        count_committed_uploads(&gw.pool, tenant.account_id, &sha).await,
        1,
        "exactly one committed receipt for the logical upload"
    );
    assert_eq!(
        count_winc_charges(&gw.pool, tenant.account_id, &sha).await,
        1,
        "exactly one believed-winc charge — the second session did not re-charge"
    );
    assert_eq!(
        backend.upload_count(),
        1,
        "exactly one provider POST across both sessions"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R9 — crash-safety: the metadata-ahead-of-bytes hazard, and its inverse, never
// yield a corrupt-but-accepted upload.
//
// The crash-safe ordering writes (and fsyncs) the chunk bytes FIRST, then flips the
// received bit; so the only physically-possible crash gap is "bytes on disk, bit
// unset" (resume re-PUTs the index). This test injects BOTH directions of the
// hazard directly into the session state and proves the system repairs or rejects:
//
//   (a) BYTES PRESENT, BIT UNSET (the real crash gap): the index shows as missing,
//       so complete is blocked until the client re-PUTs it; after the re-PUT the
//       assembled file matches and the upload commits cleanly.
//   (b) BIT SET, BYTES ABSENT (the structurally-impossible inverse, injected to
//       prove the whole-file gate is the final backstop even if it somehow arose):
//       complete sees every bit set, but the assembled bytes are torn, so the
//       whole-file SHA-256 != declared and the session FAILS before any sign/charge.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r9_crash_safety_metadata_ahead_of_bytes_never_accepts_corruption() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    // --- (a) BYTES PRESENT, BIT UNSET: the real crash gap. ---
    let content_a: Vec<u8> = (0..40u8).collect(); // 3 chunks
    let sha_a = Sha256::digest(&content_a).to_vec();
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content_a), "total_bytes": content_a.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_a = created["session_id"].as_str().unwrap().to_string();

    // PUT chunks 0 and 2 fully (bytes durable, bit set). Then SIMULATE the crash gap
    // for chunk 1: write its bytes to the assembling file at the right offset WITHOUT
    // recording the received bit (exactly the durable-write-before-bit window).
    for idx in [0u32, 2] {
        let slice = chunk_slice(&content_a, idx, TEST_CHUNK_BYTES);
        let (ps, _) = put_chunk(&gw.base_url, &key, &session_a, idx, slice, None).await;
        assert_eq!(ps, 200);
    }
    let assembling_a = durable
        .path()
        .join(format!("{}.assembling", session_a.replace('-', "")));
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&assembling_a)
            .expect("open assembling for crash-gap inject");
        f.seek(SeekFrom::Start(u64::from(1u32) * TEST_CHUNK_BYTES))
            .expect("seek");
        f.write_all(chunk_slice(&content_a, 1, TEST_CHUNK_BYTES))
            .expect("write chunk-1 bytes without the bit");
        f.sync_all().expect("fsync");
    }

    // The bit for chunk 1 is UNSET, so the session still lists it as missing and a
    // complete is blocked — the bitmap never claimed an index the receipt CAS did not
    // record, so the metadata can NEVER run ahead of the durable truth.
    let (gs, status_json) = get_session(&gw.base_url, &key, &session_a).await;
    assert_eq!(gs, 200);
    assert_eq!(
        status_json["missing"],
        json!([1]),
        "the crash gap leaves the bit UNSET, so the index is still missing"
    );
    let (incomp_status, incomp_json) = complete_session(&gw.base_url, &key, &session_a).await;
    assert_eq!(
        incomp_status, 409,
        "complete is blocked while the bit is unset: {incomp_json}"
    );

    // Resume: the client re-PUTs the missing index (an idempotent positional re-write
    // of the same bytes at the same offset). Now complete commits a CORRECT file.
    let slice1 = chunk_slice(&content_a, 1, TEST_CHUNK_BYTES);
    let (ps1, _) = put_chunk(&gw.base_url, &key, &session_a, 1, slice1, None).await;
    assert_eq!(ps1, 200, "the resumed re-PUT repairs the gap");
    let (comp_status, comp_json) = complete_session(&gw.base_url, &key, &session_a).await;
    assert_eq!(
        comp_status, 200,
        "the repaired upload commits cleanly: {comp_json}"
    );
    assert_eq!(comp_json["sha256"], sha256_hex(&content_a));
    assert_eq!(
        count_committed_uploads(&gw.pool, tenant.account_id, &sha_a).await,
        1,
        "the repaired upload is committed exactly once"
    );

    // --- (b) BIT SET, BYTES ABSENT: the inverse hazard; the whole-file gate is the
    // final backstop. Inject a fully-received bitmap whose assembled bytes are torn,
    // and prove complete REJECTS it (sha256-mismatch) before any sign/charge. ---
    let content_b: Vec<u8> = (50..90u8).collect(); // 3 chunks
    let sha_b = Sha256::digest(&content_b).to_vec();
    let (cs2, created2) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content_b), "total_bytes": content_b.len() }),
    )
    .await;
    assert_eq!(cs2, 201, "session created: {created2}");
    let session_b = created2["session_id"].as_str().unwrap().to_string();
    let session_b_id = Uuid::parse_str(&session_b).unwrap();

    // PUT chunks 0 and 1 honestly (bytes + bits). Leave chunk 2's bytes ABSENT (the
    // assembling file was sized at create, so chunk 2's region reads as zero), but
    // forcibly mark the WHOLE bitmap received (the structurally-impossible inverse):
    // set every bit and record a digest row for index 2 so the session believes it is
    // complete.
    for idx in [0u32, 1] {
        let slice = chunk_slice(&content_b, idx, TEST_CHUNK_BYTES);
        let (ps, _) = put_chunk(&gw.base_url, &key, &session_b, idx, slice, None).await;
        assert_eq!(ps, 200);
    }
    // Inject "bit set, bytes absent" for index 2 directly: OR its bit, bump the count
    // to full, and write a chunk-digest row so a re-PUT would also see it as received.
    sqlx::query(
        "UPDATE cw_core.storage_upload_session \
            SET received_bitmap = set_byte(received_bitmap, 0, get_byte(received_bitmap, 0) | 4), \
                received_count = chunk_count \
          WHERE id = $1",
    )
    .bind(session_b_id)
    .execute(&gw.pool)
    .await
    .expect("inject the bit-set-bytes-absent hazard");
    sqlx::query(
        "INSERT INTO cw_core.storage_upload_session_chunk (session_id, index, chunk_sha256, bytes) \
         VALUES ($1, 2, $2, $3)",
    )
    .bind(session_b_id)
    .bind(Sha256::digest(chunk_slice(&content_b, 2, TEST_CHUNK_BYTES)).to_vec())
    .bind(chunk_slice(&content_b, 2, TEST_CHUNK_BYTES).len() as i32)
    .execute(&gw.pool)
    .await
    .expect("inject the chunk-2 digest row");

    // The session now BELIEVES it is complete, but chunk 2's bytes are zeros on disk
    // (never written). Complete must reach the whole-file gate and REJECT: the
    // assembled SHA-256 != declared, so the session fails before a byte is signed or
    // charged. This is the final backstop the crash-safety design rests on.
    let (cgate_status, cgate_json) = complete_session(&gw.base_url, &key, &session_b).await;
    assert_eq!(
        cgate_status, 400,
        "the whole-file gate rejects torn-but-complete bytes: {cgate_json}"
    );
    assert_eq!(cgate_json["code"], "sha256-mismatch");
    assert_eq!(
        count_attempts(&gw.pool, tenant.account_id, &sha_b).await,
        0,
        "no attempt for the rejected torn upload"
    );
    assert_eq!(
        count_committed_uploads(&gw.pool, tenant.account_id, &sha_b).await,
        0,
        "no committed receipt for the rejected torn upload"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R10 — a TRANSIENT, pre-reserve store failure at `/complete` reverts the session
// to `open` (never stranding it in `assembling`), so a second `/complete` succeeds
// with NO chunk re-upload and the logical file is charged EXACTLY once.
//
// A `/complete` wins the `open -> assembling` CAS, then a transient backend check
// fault aborts the store BEFORE any attempt is reserved. Without the revert, the
// session would be stuck `assembling` until the 24h TTL, forcing a full re-upload.
// With it, the retried `/complete` runs from a clean `open` state over the same
// assembling file and bitmap.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r10_transient_store_failure_reverts_to_open_and_retry_charges_once() {
    let (stub, affords_toggle) = StubBackend::with_affords_toggle();
    let backend = Arc::new(stub);
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let content: Vec<u8> = (0..50u8).collect(); // 4 chunks at 16 bytes
    let sha = Sha256::digest(&content).to_vec();

    // Create + fill the session (affords is healthy at create, so the create-time
    // affordability check passes).
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id_str = created["session_id"].as_str().unwrap().to_string();
    let session_id = Uuid::parse_str(&session_id_str).unwrap();
    for idx in 0..4u32 {
        let slice = chunk_slice(&content, idx, TEST_CHUNK_BYTES);
        let (ps, _) = put_chunk(&gw.base_url, &key, &session_id_str, idx, slice, None).await;
        assert_eq!(ps, 200);
    }

    // Inject a TRANSIENT store failure: turn the backend's affordability check
    // Unavailable, then `/complete`. The complete wins begin_assembling, reaches the
    // pre-reserve affords check, and gets `service-unavailable`.
    affords_toggle.store(true, std::sync::atomic::Ordering::SeqCst);
    let (fs, fj) = complete_session(&gw.base_url, &key, &session_id_str).await;
    assert_eq!(
        fs, 503,
        "a transient store failure surfaces service-unavailable: {fj}"
    );

    // The session reverted to `open` (NOT stranded in `assembling`), so the retry
    // contract holds: no attempt was reserved, and the assembling file + bitmap are
    // intact.
    assert_eq!(
        session_state_in_db(&gw.pool, session_id).await,
        "open",
        "a transient pre-reserve failure reverts the session to open"
    );
    assert_eq!(
        count_attempts(&gw.pool, tenant.account_id, &sha).await,
        0,
        "no attempt was reserved by the failed complete"
    );
    let assembling = durable
        .path()
        .join(format!("{}.assembling", session_id.simple()));
    assert!(
        assembling.exists(),
        "the assembling file survives the transient failure"
    );

    // Clear the transient fault and retry `/complete` WITHOUT re-uploading a chunk:
    // it succeeds and charges exactly once for the same bytes.
    affords_toggle.store(false, std::sync::atomic::Ordering::SeqCst);
    let (rs, rj) = complete_session(&gw.base_url, &key, &session_id_str).await;
    assert_eq!(rs, 200, "the retried complete succeeds: {rj}");
    assert_eq!(rj["ok"], true, "the retry committed the assembled file");
    assert_eq!(
        rj["charged_usd_micros"], 50,
        "the retry charges exactly the byte count, once"
    );
    assert_eq!(
        session_state_in_db(&gw.pool, session_id).await,
        "completed",
        "the retried complete settles the session"
    );

    // Exactly one provider POST, one attempt, one committed receipt, one winc charge —
    // the transient failure and the revert did not double-charge or double-store.
    assert_eq!(
        backend.upload_count(),
        1,
        "exactly one provider POST overall"
    );
    assert_eq!(
        count_attempts(&gw.pool, tenant.account_id, &sha).await,
        1,
        "exactly one attempt across the failed + retried complete"
    );
    assert_eq!(
        count_committed_uploads(&gw.pool, tenant.account_id, &sha).await,
        1,
        "exactly one committed receipt"
    );
    assert_eq!(
        count_winc_charges(&gw.pool, tenant.account_id, &sha).await,
        1,
        "exactly one believed-winc charge"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R11 — the per-account open-session cap is enforced (atomically, in the same
// transaction that inserts the row): once an account holds the cap of open
// sessions, a further create is refused `too-many-open-sessions` with no row, and a
// burst of concurrent creates never overshoots the cap.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r11_open_session_cap_is_enforced_atomically() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    // A tiny cap so the test does not need 64 sessions to reach it.
    let cap = 3u32;
    let mut config = chunked_config();
    config.upload_session_limits.max_open_sessions_per_account = cap;
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        config,
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    // Fire a burst of concurrent creates (more than the cap) for distinct content, so
    // each would-be session is its own logical upload. The atomic cap means at most
    // `cap` of them land; the rest are refused.
    let attempts = 8usize;
    let mut handles = Vec::new();
    for i in 0..attempts {
        let base = gw.base_url.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            // Distinct content per create so each is a fresh session (not a dedup).
            let content: Vec<u8> = (0..40u8).map(|b| b.wrapping_add(i as u8)).collect();
            create_session(
                &base,
                &key,
                json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
            )
            .await
        }));
    }

    let mut created = 0usize;
    let mut refused = 0usize;
    for h in handles {
        let (status, body) = h.await.expect("join");
        match status {
            201 => created += 1,
            429 | 409 | 400 => {
                assert_eq!(
                    body["code"], "too-many-open-sessions",
                    "a refused create is the backpressure code: {body}"
                );
                refused += 1;
            }
            other => panic!("unexpected create status {other}: {body}"),
        }
    }

    // The cap held atomically: exactly `cap` landed, the rest were refused, and the
    // live open-session count never exceeded the cap (the TOCTOU a separate count
    // check would have allowed to overshoot).
    assert_eq!(created, cap as usize, "exactly the cap of sessions landed");
    assert_eq!(refused, attempts - cap as usize, "the rest were refused");
    assert_eq!(
        count_open_sessions_in_db(&gw.pool, tenant.account_id).await,
        i64::from(cap),
        "the live open-session count never overshot the cap"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R12 — the session janitor never expires a session that has bridged to an attempt
// (a post-reserve in-flight `/complete`): from the reserve on, the attempt lifecycle
// owns the durable file, so the session janitor must not expire it (and delete its
// file) out from under the attempt, even past the create TTL.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r12_session_janitor_skips_a_bridged_assembling_session() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let content: Vec<u8> = (0..40u8).collect();
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id = Uuid::parse_str(created["session_id"].as_str().unwrap()).unwrap();

    // Model a post-reserve in-flight `/complete`: the session is `assembling` and has
    // bridged to a reserved attempt that now owns the (renamed) file. Insert a minimal
    // reserved attempt and stamp it on the session, then age the session past its TTL.
    let attempt_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_upload_attempt \
           (id, account_id, operator_id, funding_source_id, backend, sha256, bytes, \
            chargeable_bytes, charged_usd_micros, estimated_winc, data_item_id, \
            staged_path, state) \
         VALUES ($1, $2, $3, \
                 (SELECT id FROM cw_core.storage_funding_source WHERE owner_operator_id = $3 LIMIT 1), \
                 $4, $5, $6, $6, 0, 0, 'stub-item', $7, 'reserved')",
    )
    .bind(attempt_id)
    .bind(tenant.account_id)
    .bind(tenant.operator_id)
    .bind(BACKEND)
    .bind(Sha256::digest(&content).to_vec())
    .bind(content.len() as i64)
    .bind(format!("{}.stage", attempt_id.simple()))
    .execute(&gw.pool)
    .await
    .expect("insert reserved attempt");
    sqlx::query(
        "UPDATE cw_core.storage_upload_session \
            SET state = 'assembling', attempt_id = $2, \
                expires_at = now() - interval '1 hour' \
          WHERE id = $1",
    )
    .bind(session_id)
    .bind(attempt_id)
    .execute(&gw.pool)
    .await
    .expect("bridge + age the session");

    // Run the janitor: the bridged session past its TTL must NOT be expired, because
    // the attempt lifecycle owns its file now.
    let summary = sweep_abandoned_sessions(&gw.pool, durable.path())
        .await
        .expect("janitor sweep");
    assert_eq!(
        summary.sessions_expired, 0,
        "the bridged assembling session is not expired by the session janitor"
    );
    assert_eq!(
        session_state_in_db(&gw.pool, session_id).await,
        "assembling",
        "the bridged session stays assembling (the attempt lifecycle owns recovery)"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R13 — `/complete` honours `Idempotency-Key`: a second `/complete` of the same
// session under the same key replays the recorded terminal body (the request-replay
// layer, consistent with single-shot POST /uploads), and a key reused for a
// DIFFERENT session is a conflict.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r13_complete_honours_idempotency_key() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let content: Vec<u8> = (0..50u8).collect();
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id = created["session_id"].as_str().unwrap().to_string();
    for idx in 0..4u32 {
        let slice = chunk_slice(&content, idx, TEST_CHUNK_BYTES);
        let (ps, _) = put_chunk(&gw.base_url, &key, &session_id, idx, slice, None).await;
        assert_eq!(ps, 200);
    }

    let idem_key = format!("idem-{}", Uuid::now_v7().simple());

    // First complete under the key: commits and records the terminal body.
    let (s1, j1, replayed1) =
        complete_with_idempotency(&gw.base_url, &key, &session_id, &idem_key).await;
    assert_eq!(s1, 200, "first complete commits: {j1}");
    assert_eq!(j1["ok"], true);
    assert!(
        !replayed1,
        "the first complete is fresh, not a replay: {j1}"
    );
    let uri1 = j1["uri"].as_str().expect("uri").to_string();

    // Second complete under the SAME key: replays the recorded terminal body verbatim
    // (stamped Idempotent-Replayed), with no second provider POST.
    let (s2, j2, replayed2) =
        complete_with_idempotency(&gw.base_url, &key, &session_id, &idem_key).await;
    assert_eq!(s2, 200, "the same-key complete replays: {j2}");
    assert!(replayed2, "the replay is flagged Idempotent-Replayed: {j2}");
    assert_eq!(j2["uri"].as_str().unwrap(), uri1, "the replay is verbatim");
    assert_eq!(
        backend.upload_count(),
        1,
        "no second provider POST on replay"
    );

    // The SAME key reused for a DIFFERENT session is a conflict (the request hash
    // binds the concrete session path).
    let other_content: Vec<u8> = (100..150u8).collect();
    let (ocs, ocreated) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&other_content), "total_bytes": other_content.len() }),
    )
    .await;
    assert_eq!(ocs, 201, "other session created: {ocreated}");
    let other_session = ocreated["session_id"].as_str().unwrap().to_string();
    for idx in 0..4u32 {
        let slice = chunk_slice(&other_content, idx, TEST_CHUNK_BYTES);
        let (ps, _) = put_chunk(&gw.base_url, &key, &other_session, idx, slice, None).await;
        assert_eq!(ps, 200);
    }
    let (cs_conflict, jc, _) =
        complete_with_idempotency(&gw.base_url, &key, &other_session, &idem_key).await;
    assert_eq!(
        cs_conflict, 409,
        "the same key on a different session conflicts: {jc}"
    );
    assert_eq!(jc["code"], "idempotency-key-conflict");

    gw.shutdown().await;
}

/// POST a session complete with an `Idempotency-Key`, returning (status, json,
/// was-replayed).
async fn complete_with_idempotency(
    base: &str,
    bearer: &str,
    session_id: &str,
    idempotency_key: &str,
) -> (u16, Value, bool) {
    let resp = reqwest::Client::new()
        .post(format!(
            "{base}/api/v1/poe/uploads/sessions/{session_id}/complete"
        ))
        .bearer_auth(bearer)
        .header("idempotency-key", idempotency_key)
        .send()
        .await
        .expect("send complete");
    let status = resp.status().as_u16();
    let replayed = resp
        .headers()
        .get("idempotent-replayed")
        .is_some_and(|v| v == "true");
    let text = resp.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        replayed,
    )
}

// ---------------------------------------------------------------------------
// R14 — a non-final `/complete` outcome must NOT poison the idempotency key. A
// client that calls `/complete` early (before every chunk is uploaded) with a key
// gets `409 incomplete-upload`; that 409 is NOT stored under the key, so after the
// client uploads the remaining chunks and retries `/complete` with the SAME key it
// succeeds (`200`, charged once), rather than replaying the stale 409 forever.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r14_incomplete_complete_does_not_poison_the_idempotency_key() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let content: Vec<u8> = (0..50u8).collect(); // 4 chunks at 16 bytes
    let sha = Sha256::digest(&content).to_vec();
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id = created["session_id"].as_str().unwrap().to_string();

    // Upload only the first three of four chunks, then call `/complete` EARLY under a
    // key. The precondition fails: 409 incomplete-upload, listing the missing index.
    for idx in 0..3u32 {
        let slice = chunk_slice(&content, idx, TEST_CHUNK_BYTES);
        let (ps, _) = put_chunk(&gw.base_url, &key, &session_id, idx, slice, None).await;
        assert_eq!(ps, 200);
    }
    let idem_key = format!("idem-{}", Uuid::now_v7().simple());
    let (early_status, early_json, _) =
        complete_with_idempotency(&gw.base_url, &key, &session_id, &idem_key).await;
    assert_eq!(
        early_status, 409,
        "an early complete is incomplete-upload: {early_json}"
    );
    assert_eq!(early_json["code"], "incomplete-upload");

    // Upload the remaining chunk and retry `/complete` with the SAME key. The 409 must
    // NOT have been stored under the key, so this runs FRESH and commits — never a
    // replayed 409.
    let slice = chunk_slice(&content, 3, TEST_CHUNK_BYTES);
    let (ps, _) = put_chunk(&gw.base_url, &key, &session_id, 3, slice, None).await;
    assert_eq!(ps, 200);

    let (retry_status, retry_json, replayed) =
        complete_with_idempotency(&gw.base_url, &key, &session_id, &idem_key).await;
    assert_eq!(
        retry_status, 200,
        "the same-key retry after uploading the rest commits, not a replayed 409: {retry_json}"
    );
    assert_eq!(retry_json["ok"], true);
    assert!(
        !replayed,
        "the retry ran fresh (the 409 never poisoned the key): {retry_json}"
    );
    assert_eq!(
        retry_json["charged_usd_micros"], 50,
        "the logical file is charged exactly its byte count, once"
    );

    // Exactly one provider POST, one attempt, one committed receipt, one winc charge.
    assert_eq!(backend.upload_count(), 1, "exactly one provider POST");
    assert_eq!(count_attempts(&gw.pool, tenant.account_id, &sha).await, 1);
    assert_eq!(
        count_committed_uploads(&gw.pool, tenant.account_id, &sha).await,
        1
    );
    assert_eq!(
        count_winc_charges(&gw.pool, tenant.account_id, &sha).await,
        1
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R15 — a fresh `/complete` reserves EXACTLY ONE rate token, not two. The
// idempotency wrapper authorizes once and threads the resolved viewer + rate
// decision into the inner body, so the full principal-resolve + account-status +
// scope + rate-reserve chain runs once per request (matching the one token a
// replayed `/complete` costs).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r15_fresh_complete_reserves_exactly_one_rate_token() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    // A fresh key whose subject we meter; no other request has spent against it yet.
    let (key, key_id) = issue_upload_key_with_id(&gw.pool, tenant.account_id).await;

    let content: Vec<u8> = (0..50u8).collect();
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id = created["session_id"].as_str().unwrap().to_string();
    for idx in 0..4u32 {
        let slice = chunk_slice(&content, idx, TEST_CHUNK_BYTES);
        let (ps, _) = put_chunk(&gw.base_url, &key, &session_id, idx, slice, None).await;
        assert_eq!(ps, 200);
    }

    // Measure tokens reserved by the create + 4 chunk PUTs, then by exactly one fresh
    // `/complete`. A single `/complete` must move the meter by exactly 1: the prior
    // double-authorize spent 2 per complete.
    let before = rate_tokens_reserved(&gw.pool, key_id).await;
    let (comp_status, comp_json) = complete_session(&gw.base_url, &key, &session_id).await;
    assert_eq!(comp_status, 200, "complete committed: {comp_json}");
    let after = rate_tokens_reserved(&gw.pool, key_id).await;

    assert_eq!(
        after - before,
        1,
        "a fresh /complete reserves exactly one rate token (not two)"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R16 — a POST-RESERVE store failure during `/complete` must NOT revert the session
// to a vanished-file `open` (the attempt already renamed the assembling file to its
// `.stage` path). Instead the `/complete` BRIDGES to the live reserved attempt
// (`accepted` + attempt_id) so the client polls the attempt for the terminal outcome,
// the logical file is charged exactly once, and a re-`complete` replays the same
// accepted bridge. (Pre-fix, the `load_live_attempt`-errored / no-bridge path could
// revert the session to an `open` state pointing at the renamed-away file, so a retry
// 500'd until TTL.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r16_post_reserve_failure_bridges_not_reverts_to_vanished_file() {
    let (stub, upload_toggle) = StubBackend::with_upload_toggle();
    let backend = Arc::new(stub);
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let content: Vec<u8> = (0..50u8).collect(); // 4 chunks at 16 bytes
    let sha = Sha256::digest(&content).to_vec();
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id_str = created["session_id"].as_str().unwrap().to_string();
    let session_id = Uuid::parse_str(&session_id_str).unwrap();
    for idx in 0..4u32 {
        let slice = chunk_slice(&content, idx, TEST_CHUNK_BYTES);
        let (ps, _) = put_chunk(&gw.base_url, &key, &session_id_str, idx, slice, None).await;
        assert_eq!(ps, 200);
    }

    // The assembling file exists before the failing complete.
    let assembling = durable
        .path()
        .join(format!("{}.assembling", session_id.simple()));
    assert!(
        assembling.exists(),
        "the assembling file exists pre-complete"
    );

    // Inject a POST-RESERVE transient fault: the attempt reserves (renaming the file to
    // its `.stage` path), then the POST fails Unavailable. The route must NOT revert the
    // session to a vanished-file `open`; it BRIDGES to the live reserved attempt.
    upload_toggle.store(true, std::sync::atomic::Ordering::SeqCst);
    let (fs, fj) = complete_session(&gw.base_url, &key, &session_id_str).await;
    assert_eq!(fs, 200, "the failing-POST complete bridges, not 500s: {fj}");
    assert_eq!(
        fj["accepted"], true,
        "the complete bridges to the live attempt instead of reverting: {fj}"
    );
    let bridged_attempt = fj["attempt_id"].as_str().expect("attempt_id").to_string();

    // The attempt was reserved and owns the renamed file; the assembling-path file is
    // gone (renamed to `.stage`). The session is `completed` (bridged), NEVER reverted
    // to a vanished-file `open`.
    assert_eq!(
        count_attempts(&gw.pool, tenant.account_id, &sha).await,
        1,
        "the attempt was reserved by the failing complete"
    );
    assert!(
        !assembling.exists(),
        "the assembling file was renamed to the attempt's .stage path"
    );
    assert_eq!(
        session_state_in_db(&gw.pool, session_id).await,
        "completed",
        "the session bridged (completed), NOT reverted to a vanished-file open"
    );

    // The reserve already appended exactly one believed-winc charge keyed on that
    // attempt id; the failed POST and the bridge did not double-charge or open a second
    // attempt.
    let attempt_in_db: Uuid = sqlx::query_scalar(
        "SELECT id FROM cw_core.storage_upload_attempt \
         WHERE account_id = $1 AND backend = $2 AND sha256 = $3",
    )
    .bind(tenant.account_id)
    .bind(BACKEND)
    .bind(&sha)
    .fetch_one(&gw.pool)
    .await
    .expect("read the bridged attempt");
    assert_eq!(
        attempt_in_db.to_string(),
        bridged_attempt,
        "the session bridged to the one reserved attempt"
    );
    assert_eq!(
        count_winc_charges(&gw.pool, tenant.account_id, &sha).await,
        1,
        "exactly one believed-winc charge"
    );

    // Clear the fault and re-`complete`: the bridged session replays the SAME accepted
    // bridge (no re-upload, no second attempt, no double-charge).
    upload_toggle.store(false, std::sync::atomic::Ordering::SeqCst);
    let (rs, rj) = complete_session(&gw.base_url, &key, &session_id_str).await;
    assert_eq!(rs, 200, "the re-complete replays the bridge: {rj}");
    assert_eq!(
        rj["accepted"], true,
        "the re-complete replays accepted: {rj}"
    );
    assert_eq!(
        rj["attempt_id"].as_str().unwrap(),
        bridged_attempt,
        "the replay points at the same attempt"
    );
    assert_eq!(
        count_attempts(&gw.pool, tenant.account_id, &sha).await,
        1,
        "still exactly one attempt after the re-complete"
    );
    assert_eq!(
        count_winc_charges(&gw.pool, tenant.account_id, &sha).await,
        1,
        "still exactly one believed-winc charge"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// R17 — a second `/complete` arriving on an `assembling` session whose attempt is
// already reserved BRIDGES to that attempt (`accepted`), rather than returning a
// permanent `409 incomplete-upload`. This is the in-flight-finalisation case: the
// first `/complete` is mid-store (attempt reserved, file renamed) and a retry/poll
// must pick up the live attempt.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r17_second_complete_on_assembling_session_bridges_to_the_attempt() {
    let backend = Arc::new(StubBackend::new());
    let durable = tempfile::tempdir().expect("durable dir");
    let gw = BootedGateway::start_with_storage_config(
        storage_state(Arc::clone(&backend), durable.path()),
        chunked_config(),
        ONE_MICRO_PER_BYTE_FEMTO,
    )
    .await
    .expect("boot");

    let tenant = gw
        .seed_tenant("cfm_", &["poe:create"], 10_000_000)
        .await
        .expect("tenant");
    seed_funded_source(&gw.pool, tenant.operator_id).await;
    let key = issue_upload_key(&gw.pool, tenant.account_id).await;

    let content: Vec<u8> = (0..40u8).collect();
    let (cs, created) = create_session(
        &gw.base_url,
        &key,
        json!({ "sha256": sha256_hex(&content), "total_bytes": content.len() }),
    )
    .await;
    assert_eq!(cs, 201, "session created: {created}");
    let session_id_str = created["session_id"].as_str().unwrap().to_string();
    let session_id = Uuid::parse_str(&session_id_str).unwrap();

    // Model an in-flight `/complete` mid-store: the session is `assembling` and a
    // reserved attempt for its content already exists (the file is the attempt's now).
    // The attempt_id is left UNSET on the session, forcing the route through the
    // load_live_attempt bridge lookup (the strictest path).
    let attempt_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_upload_attempt \
           (id, account_id, operator_id, funding_source_id, backend, sha256, bytes, \
            chargeable_bytes, charged_usd_micros, estimated_winc, data_item_id, \
            staged_path, state) \
         VALUES ($1, $2, $3, \
                 (SELECT id FROM cw_core.storage_funding_source WHERE owner_operator_id = $3 LIMIT 1), \
                 $4, $5, $6, $6, 0, 0, 'stub-item', $7, 'reserved')",
    )
    .bind(attempt_id)
    .bind(tenant.account_id)
    .bind(tenant.operator_id)
    .bind(BACKEND)
    .bind(Sha256::digest(&content).to_vec())
    .bind(content.len() as i64)
    .bind(format!("{}.stage", attempt_id.simple()))
    .execute(&gw.pool)
    .await
    .expect("insert reserved attempt");
    sqlx::query(
        "UPDATE cw_core.storage_upload_session \
            SET state = 'assembling', attempt_id = NULL \
          WHERE id = $1",
    )
    .bind(session_id)
    .execute(&gw.pool)
    .await
    .expect("set the session assembling");

    // A `/complete` on this assembling session must BRIDGE to the reserved attempt, not
    // return a permanent 409.
    let (s, j) = complete_session(&gw.base_url, &key, &session_id_str).await;
    assert_eq!(s, 200, "the assembling-session complete bridges: {j}");
    assert_eq!(j["accepted"], true, "it bridges (accepted), not a 409: {j}");
    assert_eq!(
        j["attempt_id"].as_str().unwrap(),
        attempt_id.to_string(),
        "it bridges to the one reserved attempt"
    );

    gw.shutdown().await;
}
