//! Backend-level coverage of the ArLocal dev backend's wire contract: the bundle
//! it wraps the once-signed data item into, the base-layer transaction it signs and
//! posts, the mint/tx/mine sequence the emulator requires, and the lookup status
//! mapping.
//!
//! These run against a tiny in-process HTTP server (no real Arweave, no database),
//! so they pin exactly what the backend puts on the wire. The inner data item is
//! signed ONCE (the backend never re-signs it); the backend frames it into a
//! one-item bundle, signs an outer base-layer transaction carrying the bundle, and
//! posts that as JSON. The receipt resolves at the INNER data-item id (the content
//! address), not the disposable outer transaction id, so a retry that re-signs the
//! outer carrier still resolves to the same `ar://` uri. The lookup maps a 2xx /
//! 404 / 5xx to `Present` / `Absent` / `Unavailable`.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use age::secrecy::SecretString;
use ans104::{Ans104Signer, ArweaveJwkSigner, Tag};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{any, get, post};
use axum::{Json, Router};
use gateway_core::storage::{
    ArLocalBackend, AuthorizedFunding, DataItemStatus, StorageBackendExt, StorageError,
    TurboBackend,
};
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::{arweave_address, unlock, UnlockedKeyring};
use rust_decimal::Decimal;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The throwaway Arweave JWK the backend signs the outer carrier transaction with;
/// the same fixture the keyring round-trip and ans104 suites use.
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// scrypt work factor for the in-test keyring envelope: the minimum the age scrypt
/// recipient accepts, so the unlock is fast in tests.
const TEST_SCRYPT_LOG_N: u8 = 10;

/// The Arweave address the fixture JWK derives to (the funding source's address and
/// the keyring entry the backend resolves a signer through).
fn fixture_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

/// An unlocked keyring carrying the fixture Arweave entry, the key the backend signs
/// the outer carrier transaction with.
fn fixture_keyring() -> Arc<UnlockedKeyring> {
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

/// A funding capability for the fixture source, scoped to the fixture address so the
/// backend's keyring lookup resolves the fixture signer.
fn fixture_funding() -> AuthorizedFunding {
    AuthorizedFunding::for_tests(Uuid::now_v7(), fixture_arweave_address())
}

/// Sign a real inner data item with the fixture key, streaming it from a staged
/// file, and return the envelope, the owner bytes, and the staged file (kept alive
/// for the duration of the test).
fn sign_inner_item(payload: &[u8]) -> (ans104::SignedEnvelope, Vec<u8>, tempfile::NamedTempFile) {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    let owner = signer.owner();

    let mut staged = tempfile::NamedTempFile::new().expect("temp file");
    staged.write_all(payload).expect("write staged");
    staged.flush().expect("flush staged");

    let tags = [Tag::new("Content-Type", "application/octet-stream")];
    let mut reader = std::io::Cursor::new(payload.to_vec());
    let envelope = ans104::sign_streaming(
        &signer,
        None,
        None,
        &tags,
        &mut reader,
        payload.len() as u64,
    )
    .expect("sign the inner data item");
    (envelope, owner, staged)
}

/// A capturing ArLocal stand-in: records the minted addresses, every posted
/// transaction body, and the mine calls, and answers the validation-relevant reads
/// (`/info`) so the backend's sequence completes.
#[derive(Clone, Default)]
struct FakeArLocal {
    minted: Arc<Mutex<Vec<String>>>,
    posted_tx: Arc<Mutex<Option<Value>>>,
    mined: Arc<Mutex<usize>>,
}

async fn handle_mint(
    State(state): State<FakeArLocal>,
    axum::extract::Path((address, _balance)): axum::extract::Path<(String, String)>,
) -> StatusCode {
    state.minted.lock().await.push(address);
    StatusCode::OK
}

async fn handle_post_tx(State(state): State<FakeArLocal>, Json(body): Json<Value>) -> StatusCode {
    *state.posted_tx.lock().await = Some(body);
    StatusCode::OK
}

async fn handle_mine(State(state): State<FakeArLocal>) -> StatusCode {
    *state.mined.lock().await += 1;
    StatusCode::OK
}

/// Serve the capturing endpoints; return the bound address and the capture handle.
async fn serve_fake_arlocal() -> (SocketAddr, FakeArLocal) {
    let state = FakeArLocal::default();
    let app = Router::new()
        .route("/mint/{address}/{balance}", get(handle_mint))
        .route("/tx", post(handle_post_tx))
        .route("/mine", get(handle_mine))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (addr, state)
}

#[tokio::test]
async fn upload_signs_and_posts_a_bundle_carrier_transaction() {
    let (addr, fake) = serve_fake_arlocal().await;
    let backend = ArLocalBackend::new(format!("http://{addr}"), false, fixture_keyring())
        .expect("arlocal backend (dev)");

    let payload: Vec<u8> = (0..130_017u32).map(|i| (i % 253) as u8).collect();
    let (envelope, owner, staged) = sign_inner_item(&payload);

    let funding = fixture_funding();
    let receipt = backend
        .upload(&funding, &envelope, &owner, staged.path())
        .await
        .expect("upload");

    // The receipt resolves at the INNER data-item id, never the outer carrier tx id.
    assert_eq!(receipt.data_item_id, envelope.id_b64url);
    assert_eq!(receipt.uri, format!("ar://{}", envelope.id_b64url));
    assert_ne!(
        receipt.root_tx_id.as_deref(),
        Some(envelope.id_b64url.as_str()),
        "the carrier tx id is distinct from the content-addressed inner id"
    );

    // The emulator's required sequence ran: fund the wallet, post the tx, mine.
    assert_eq!(
        fake.minted.lock().await.as_slice(),
        &[fixture_arweave_address()],
        "the outer wallet is funded before posting"
    );
    assert_eq!(
        *fake.mined.lock().await,
        1,
        "a block is mined to seal the tx"
    );

    // The posted transaction is a format-2 bundle carrier: the bundle tags are set,
    // and the data field decodes to a one-item ANS-104 bundle whose single item is
    // the byte-identical reconstruction of the once-signed inner data item.
    let tx = fake
        .posted_tx
        .lock()
        .await
        .clone()
        .expect("a transaction was posted");
    assert_eq!(tx["format"], 2);
    assert_tag(&tx, "Bundle-Format", "binary");
    assert_tag(&tx, "Bundle-Version", "2.0.0");

    let bundle = decode_b64url(tx["data"].as_str().expect("tx carries data"));
    let inner = extract_single_bundle_item(&bundle);
    let mut expected_inner =
        ans104::reconstruct_prefix(&envelope, &owner).expect("reconstruct inner prefix");
    expected_inner.extend_from_slice(&payload);
    assert_eq!(
        inner, expected_inner,
        "the bundled item is the once-signed inner reconstruction (prefix then payload)"
    );

    // The transaction id is sha256(signature) base64url and data_size matches.
    let signature = decode_b64url(tx["signature"].as_str().expect("tx carries a signature"));
    let expected_id = {
        use sha2::{Digest, Sha256};
        base64_url(&Sha256::digest(&signature))
    };
    assert_eq!(tx["id"].as_str().unwrap(), expected_id, "id == sha256(sig)");
    assert_eq!(
        tx["data_size"].as_str().unwrap(),
        bundle.len().to_string(),
        "data_size matches the bundle byte length"
    );
}

#[tokio::test]
async fn retry_resolves_to_the_same_inner_uri() {
    // A re-driven upload (the same once-signed envelope) resolves to the same
    // content-addressed inner id even though the outer carrier transaction is
    // re-signed with a fresh randomised signature each time.
    let (addr, fake) = serve_fake_arlocal().await;
    let backend = ArLocalBackend::new(format!("http://{addr}"), false, fixture_keyring())
        .expect("arlocal backend (dev)");

    let payload = b"retry-idempotency-probe".to_vec();
    let (envelope, owner, staged) = sign_inner_item(&payload);
    let funding = fixture_funding();

    let first = backend
        .upload(&funding, &envelope, &owner, staged.path())
        .await
        .expect("first upload");
    let first_tx_id = first.root_tx_id.clone();

    let second = backend
        .upload(&funding, &envelope, &owner, staged.path())
        .await
        .expect("retry upload");

    assert_eq!(
        first.uri, second.uri,
        "a retry resolves to the same ar://{{inner id}}"
    );
    assert_eq!(first.data_item_id, second.data_item_id);
    // The wallet was minted on each attempt (idempotent re-mint), and two blocks
    // were mined; the inner uri is stable regardless.
    assert_eq!(*fake.mined.lock().await, 2);
    assert!(
        first_tx_id.is_some() && second.root_tx_id.is_some(),
        "each attempt records its own carrier tx id"
    );
}

#[tokio::test]
async fn upload_surfaces_a_missing_funding_key_as_misconfigured() {
    // A funding capability the keyring cannot back (a different address) must fail
    // before any network call: the backend cannot sign the carrier transaction.
    let (addr, _fake) = serve_fake_arlocal().await;
    let backend = ArLocalBackend::new(format!("http://{addr}"), false, fixture_keyring())
        .expect("arlocal backend (dev)");

    let payload = b"no key for this source".to_vec();
    let (envelope, owner, staged) = sign_inner_item(&payload);
    let stranger =
        AuthorizedFunding::for_tests(Uuid::now_v7(), "an-address-not-in-the-keyring".into());

    let err = backend
        .upload(&stranger, &envelope, &owner, staged.path())
        .await
        .expect_err("an unbacked funding capability cannot sign");
    assert!(
        matches!(err, gateway_core::storage::StorageError::Misconfigured(_)),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// lookup_data_item status mapping.
// ---------------------------------------------------------------------------

async fn serve_status(code: StatusCode) -> SocketAddr {
    let app = Router::new().route("/{*rest}", any(move || async move { code }));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

#[tokio::test]
async fn lookup_maps_2xx_to_present() {
    let addr = serve_status(StatusCode::OK).await;
    let backend =
        ArLocalBackend::new(format!("http://{addr}"), false, fixture_keyring()).expect("backend");
    let status = backend
        .lookup_data_item(&fixture_funding(), "some-data-item-id")
        .await
        .expect("lookup");
    assert_eq!(status, DataItemStatus::Present);
}

#[tokio::test]
async fn lookup_maps_404_to_absent() {
    let addr = serve_status(StatusCode::NOT_FOUND).await;
    let backend =
        ArLocalBackend::new(format!("http://{addr}"), false, fixture_keyring()).expect("backend");
    let status = backend
        .lookup_data_item(&fixture_funding(), "some-data-item-id")
        .await
        .expect("lookup");
    assert_eq!(status, DataItemStatus::Absent);
}

#[tokio::test]
async fn lookup_maps_5xx_to_unavailable_never_absent() {
    // A provider error or any non-404 failure must NOT be read as a definite
    // absent: that would un-charge bytes the provider may actually hold.
    let addr = serve_status(StatusCode::INTERNAL_SERVER_ERROR).await;
    let backend =
        ArLocalBackend::new(format!("http://{addr}"), false, fixture_keyring()).expect("backend");
    let status = backend
        .lookup_data_item(&fixture_funding(), "some-data-item-id")
        .await
        .expect("lookup");
    assert_eq!(status, DataItemStatus::Unavailable);
}

#[tokio::test]
async fn lookup_maps_transport_error_to_unavailable() {
    // A dead address (nothing listening) is a transport failure, mapped to
    // Unavailable, never Absent.
    let backend =
        ArLocalBackend::new("http://127.0.0.1:1", false, fixture_keyring()).expect("backend");
    let status = backend
        .lookup_data_item(&fixture_funding(), "some-data-item-id")
        .await
        .expect("lookup returns a status, never errors on transport failure");
    assert_eq!(status, DataItemStatus::Unavailable);
}

// ---------------------------------------------------------------------------
// The Turbo backend's client-level upload timeout — the direct regression guard
// for STORAGE-01.
//
// This drives TurboBackend::upload DIRECTLY (no route, no outer
// tokio::time::timeout), which is the exact shape the singleton crash-recovery
// sweep uses. If the upload client were ever built without a timeout, this test
// hangs past its outer guard and FAILS, so it genuinely proves the client-level
// deadline rather than an outer wrapper.
// ---------------------------------------------------------------------------

/// A Turbo upload stand-in that accepts `POST /v1/tx/arweave` and then NEVER
/// answers, holding the request open far past any reasonable deadline so only a
/// client-level timeout breaks the wait. Returns the base URL.
async fn serve_stalling_turbo() -> String {
    async fn stall(_body: axum::body::Bytes) -> StatusCode {
        // Hold the connection open without responding. A timeout-less client waits
        // here forever; a client with a deadline aborts.
        tokio::time::sleep(Duration::from_secs(3600)).await;
        StatusCode::OK
    }
    let app = Router::new().route("/v1/tx/arweave", post(stall));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stall");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve stall");
    });
    format!("http://{addr}")
}

/// A lazy pool to an unreachable URL: TurboBackend::upload never queries the pool
/// (only `affords` does), so the upload path needs no live database and this test
/// stays DB-free.
fn idle_pool() -> sqlx::PgPool {
    sqlx::PgPool::connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("a lazy pool builds without connecting")
}

#[tokio::test]
async fn turbo_upload_aborts_on_the_client_timeout_against_a_stalling_provider() {
    let upstream = serve_stalling_turbo().await;
    // A 2-second upload timeout baked into the client; the gateway URL is unused on
    // the upload path.
    let upload_timeout = Duration::from_secs(2);
    let backend = TurboBackend::new(
        idle_pool(),
        &upstream,
        "http://gateway.invalid",
        Decimal::ZERO,
        upload_timeout,
    );

    let payload = b"stall-probe content".to_vec();
    let (envelope, owner, staged) = sign_inner_item(&payload);
    let funding = fixture_funding();

    // The outer guard is far above the 2s client timeout but far below "hangs
    // forever". If the upload client had no timeout, this guard would trip (the call
    // would still be parked in the stalled POST) and `expect` would panic — that is
    // the regression this test catches.
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        backend.upload(&funding, &envelope, &owner, staged.path()),
    )
    .await
    .expect("the upload aborts on the client-level timeout, not a hang");

    // The aborted POST surfaces as the ambiguous Unavailable (the bytes may or may
    // not have landed), which the recovery path leaves reserved for a later pass.
    match result {
        Err(StorageError::Unavailable(_)) => {}
        other => panic!("expected an Unavailable timeout abort, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Assert a base64url-encoded tag name/value pair is present on the transaction.
fn assert_tag(tx: &Value, name: &str, value: &str) {
    let want_name = base64_url(name.as_bytes());
    let want_value = base64_url(value.as_bytes());
    let found = tx["tags"]
        .as_array()
        .expect("tags array")
        .iter()
        .any(|t| t["name"] == want_name && t["value"] == want_value);
    assert!(found, "tag {name}={value} not present on the carrier tx");
}

/// Decode the single item out of a one-item ANS-104 binary bundle: skip the
/// 32-byte count and the 64-byte header entry, then take the item bytes.
fn extract_single_bundle_item(bundle: &[u8]) -> Vec<u8> {
    assert!(
        bundle.len() >= 96,
        "a one-item bundle has at least a header"
    );
    // count(32) is 1.
    assert_eq!(read_le_32(&bundle[0..32]), 1, "exactly one item");
    let size = read_le_32(&bundle[32..64]) as usize;
    let body = &bundle[96..];
    assert_eq!(body.len(), size, "item body length matches the header size");
    body.to_vec()
}

/// Fold a 32-byte little-endian field back to a u64 the way the reference reader
/// does.
fn read_le_32(field: &[u8]) -> u64 {
    let mut value = 0u64;
    for &byte in field.iter().rev() {
        value = value * 256 + u64::from(byte);
    }
    value
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64url(text: &str) -> Vec<u8> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .expect("valid base64url")
}
