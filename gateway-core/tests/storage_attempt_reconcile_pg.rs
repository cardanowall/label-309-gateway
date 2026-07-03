//! The crash-recovery sweep over interrupted upload attempts against a real
//! Postgres.
//!
//! These suites seed a real `reserved` attempt (the USD hold + the believed winc
//! charge placed by `reserve_attempt`, the data item signed once by the fixture
//! keyring, the content promoted to a durable staged file) and drive the recovery
//! sweep through a scripted stub backend that controls the provider data-item status
//! and counts every POST. They assert the converged terminal state, the net ledger
//! effect, and the emitted events for every (provider-status, staged-file,
//! contender) cell:
//!
//!   - a crash after a provider 2xx (kill before commit) → `Present` → commit, ONE
//!     net charge, no re-POST;
//!   - a never-posted attempt whose staged file survived → `Absent`+present →
//!     re-POST then commit, ONE net charge, exactly ONE POST;
//!   - a never-posted attempt whose staged file is gone → `Absent`+gone → release +
//!     ONE terminal `storage.upload.failed` event + a winc refund, and the hold is
//!     returned (zero net charge), and nothing is re-signed;
//!   - a provider lookup that is down → `Unavailable` → the attempt stays `reserved`
//!     (hold intact), and `storage.attempt.stuck` alerts after N consecutive passes;
//!   - a fresh (within-horizon) attempt is NEVER swept;
//!   - a sweep that races a live handler's commit settles exactly ONCE (the CAS);
//!   - two sweep workers on one `Absent`+staged attempt issue exactly ONE re-POST
//!     (the claim-lease admits one).
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use age::secrecy::SecretString;
use ans104::{Ans104Signer, ArweaveJwkSigner, SignedEnvelope, Tag};
use gateway_core::storage::{
    insert_credit_entry, load_attempt, persist_receipt, promote_to_durable, reserve_attempt,
    stage_stream, AttemptReconcileConfig, AttemptReconcileHandler, AttemptReconcileSummary,
    AttemptState, AuthorizedFunding, CreditEntry, CreditKind, DataItemStatus, ReleaseReason,
    ReserveOutcome, ReserveSpec, StorageBackendExt, StorageError, StorageReceipt,
    ATTEMPT_STUCK_EVENT, STORAGE_UPLOAD_FAILED_EVENT,
};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::{arweave_address, unlock, UnlockedKeyring};
use rust_decimal::Decimal;
use uuid::Uuid;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Fixtures: the funding key, the keyring, and the storage backend.
// ---------------------------------------------------------------------------

const BACKEND: &str = "turbo";

/// The throwaway Arweave JWK every keyring in this suite signs with.
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// A low scrypt work factor so the in-test keyring envelope encrypts/decrypts fast.
const TEST_SCRYPT_LOG_N: u8 = 4;

fn fixture_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

/// Build an unlocked keyring holding the fixture Arweave funding key, so the sweep
/// resolves the owner key for a re-POST and the test can sign the same way the route
/// does.
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

/// What the stub backend reports for a `lookup_data_item` call.
#[derive(Debug, Clone, Copy)]
enum LookupReply {
    Present,
    Absent,
    Unavailable,
}

/// What the stub backend does on a re-POST.
#[derive(Debug, Clone, Copy)]
enum UploadReply {
    /// Return a deterministic receipt keyed on the signed item id.
    Ok,
    /// A definite refusal (a 402), the bytes never landed.
    Definite,
    /// An ambiguous transport failure (the POST may have been accepted).
    Ambiguous,
}

/// A scripted storage backend: it answers `lookup_data_item` with a fixed reply,
/// performs a scripted re-POST, and counts every POST so a test can prove the
/// claim-lease admits exactly one re-POST among contenders.
struct StubBackend {
    lookup: LookupReply,
    upload: UploadReply,
    posts: AtomicUsize,
    /// When set, the re-POST sleeps this long, so two concurrent sweep passes
    /// overlap on the same attempt and the lease (not timing) is what serializes the
    /// POST.
    delay: Option<Duration>,
}

impl StubBackend {
    fn new(lookup: LookupReply, upload: UploadReply) -> Self {
        Self {
            lookup,
            upload,
            posts: AtomicUsize::new(0),
            delay: None,
        }
    }

    fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    fn post_count(&self) -> usize {
        self.posts.load(Ordering::SeqCst)
    }
}

impl StorageBackendExt for StubBackend {
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
        self.posts.fetch_add(1, Ordering::SeqCst);
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        match self.upload {
            UploadReply::Ok => {
                let data_item_id = envelope.id_b64url.clone();
                Ok(StorageReceipt {
                    uri: format!("ar://{data_item_id}"),
                    data_item_id,
                    raw_receipt: serde_json::json!({ "backend": "stub" }),
                    root_tx_id: None,
                })
            }
            UploadReply::Definite => Err(StorageError::InsufficientCredit),
            UploadReply::Ambiguous => Err(StorageError::Unavailable("connection reset".into())),
        }
    }

    async fn lookup_data_item(
        &self,
        _funding: &AuthorizedFunding,
        _data_item_id: &str,
    ) -> Result<DataItemStatus, StorageError> {
        Ok(match self.lookup {
            LookupReply::Present => DataItemStatus::Present,
            LookupReply::Absent => DataItemStatus::Absent,
            LookupReply::Unavailable => DataItemStatus::Unavailable,
        })
    }
}

// ---------------------------------------------------------------------------
// Seeding.
// ---------------------------------------------------------------------------

/// Seed an operator + account; return both ids.
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

/// Register a funding source owned by `operator` at the fixture address + a live
/// service grant. The address is the JWK's derived address, so the sweep's keyring
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
    source_id
}

/// Stamp a believed winc balance on a source so the credit ledger can refund it on a
/// release without going negative in a confusing way; the balance is not read by the
/// sweep, but the `charge`/`refund` pair must net cleanly.
async fn fund_credit(pool: &sqlx::PgPool, source: Uuid, winc: i64) {
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
}

/// Credit the account's USD balance so the storage hold does not overdraw.
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

/// A durable staging directory kept alive for the test by the returned `TempDir`.
struct StagedAttempt {
    attempt_id: Uuid,
    #[allow(dead_code)]
    sha256: [u8; 32],
    charged_usd_micros: i64,
    // The durable directory holds the promoted staged file the recovery sweep
    // re-POSTs from; the scratch directory backed the pre-promotion staging. Both
    // are kept alive for the duration of the test by these guards.
    _durable: tempfile::TempDir,
    _scratch: tempfile::TempDir,
}

/// Build a real `reserved` attempt for `content`: stage the bytes, sign the data
/// item once with the fixture keyring (so the persisted envelope reconstructs a
/// byte-identical body the stub can re-POST), promote the staged file to durable
/// disk, and call `reserve_attempt` so the USD hold and the believed winc charge are
/// real ledger rows. Returns the staged-attempt handle (the durable dir kept alive).
async fn reserve(
    pool: &sqlx::PgPool,
    keyring: &UnlockedKeyring,
    operator: Uuid,
    account: Uuid,
    source: Uuid,
    content: &[u8],
) -> StagedAttempt {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let durable = tempfile::tempdir().expect("durable dir");

    // Stage the content to a tmpfs scratch file with a rolling hash.
    let chunk = content.to_vec();
    let staged = stage_stream(
        scratch.path(),
        1 << 20,
        futures_util::stream::iter(vec![Ok::<Vec<u8>, std::convert::Infallible>(chunk)]),
    )
    .await
    .expect("stage the content");
    let sha256 = staged.sha256;
    let bytes = staged.bytes;

    // Sign the data item once through the keyring, exactly as the route does.
    let funding = AuthorizedFunding::for_tests(source, fixture_arweave_address());
    let signer = keyring
        .arweave_signer_for(&funding)
        .expect("the keyring holds the fixture funding key");
    let tags = vec![Tag::new(
        "Content-Type",
        b"application/octet-stream".to_vec(),
    )];
    let mut file = std::fs::File::open(staged.path()).expect("open staged for signing");
    let envelope = signer
        .sign_streaming_envelope(None, None, &tags, &mut file, bytes)
        .expect("sign the data item once");

    // Mint the attempt id ONCE and name the durable file by it, then carry the same
    // id into the reservation so the row and its content file share one id (the sweep
    // still reads the stored `staged_path`, but the name now equals the row id, which
    // is what the orphan janitor and operator debugging rely on).
    let attempt_id = Uuid::now_v7();
    let staged_path = promote_to_durable(staged, durable.path(), attempt_id)
        .await
        .expect("promote staged to durable");
    let staged_path_str = staged_path.to_string_lossy().into_owned();

    // chargeable bytes = the whole content here (no free window in this seed); price
    // it at one micro-USD per byte so the hold is a real, non-zero reservation.
    let charged_usd_micros = i64::try_from(bytes).expect("bytes fit i64");
    let spec = ReserveSpec {
        id: attempt_id,
        account_id: account,
        operator_id: operator,
        funding_source_id: source,
        backend: BACKEND,
        sha256,
        bytes,
        chargeable_bytes: bytes,
        charged_usd_micros,
        estimated_winc: Decimal::from(bytes.max(1)),
        data_item_id: &envelope.id_b64url,
        data_item_signature: &envelope.signature,
        data_item_anchor: envelope.anchor.as_ref().map(|a| a.as_slice()),
        data_item_tag_bytes: &envelope.tag_bytes,
        staged_path: &staged_path_str,
        request_id: None,
    };

    match reserve_attempt(pool, &spec).await.expect("reserve") {
        // The reservation uses the id the spec carries, so the claimed attempt id is
        // the one that named the durable file.
        ReserveOutcome::Claimed(attempt) => assert_eq!(attempt.id, attempt_id),
        ReserveOutcome::Attached(_) => {
            panic!("a fresh reservation must claim, not attach to an existing live attempt")
        }
        ReserveOutcome::Deduplicated(_) => {
            panic!("a fresh reservation must claim, not dedup against a prior receipt")
        }
        ReserveOutcome::InsufficientFunds => {
            panic!("the seeded account balance must cover the storage hold")
        }
    };

    StagedAttempt {
        attempt_id,
        sha256,
        charged_usd_micros,
        _durable: durable,
        _scratch: scratch,
    }
}

// ---------------------------------------------------------------------------
// Ledger / state readers.
// ---------------------------------------------------------------------------

async fn attempt_state(pool: &sqlx::PgPool, attempt_id: Uuid) -> AttemptState {
    load_attempt(pool, attempt_id)
        .await
        .expect("load attempt")
        .expect("attempt exists")
        .state
}

/// The net USD charged to the account: every storage ledger kind summed. A committed
/// upload nets to exactly `-charged` (hold + release + final debit); a released one
/// nets to zero (hold + release).
async fn net_storage_micros(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT coalesce(sum(amount_micros), 0)::bigint FROM cw_core.balance_ledger \
         WHERE account_id = $1 \
           AND kind IN ('storage_hold', 'storage_hold_release', 'storage_upload', 'storage_refund')",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("net storage micros")
}

async fn account_events(pool: &sqlx::PgPool, account_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_type FROM cw_core.subject_event \
         WHERE subject_kind = 'account' AND subject_id = $1 ORDER BY subject_seq",
    )
    .bind(account_id.to_string())
    .fetch_all(pool)
    .await
    .expect("read account events")
}

async fn funding_events(pool: &sqlx::PgPool, source: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_type FROM cw_core.subject_event \
         WHERE subject_kind = 'storage_funding_source' AND subject_id = $1 ORDER BY subject_seq",
    )
    .bind(source.to_string())
    .fetch_all(pool)
    .await
    .expect("read funding events")
}

/// Count the receipt rows for an account (the committed `storage_upload` ledger).
async fn receipt_count(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(pool)
        .await
        .expect("count receipts")
}

fn config(stuck_passes: u32) -> AttemptReconcileConfig {
    AttemptReconcileConfig {
        // A zero horizon makes a freshly-inserted attempt immediately eligible.
        reconcile_horizon: Duration::from_secs(0),
        upload_claim_lease_ttl: Duration::from_secs(60),
        attempt_stuck_passes: stuck_passes,
    }
}

fn handler(
    pool: sqlx::PgPool,
    backend: Arc<StubBackend>,
    config: AttemptReconcileConfig,
) -> AttemptReconcileHandler<StubBackend> {
    AttemptReconcileHandler::new(pool, backend, unlocked_keyring(), config)
}

// ---------------------------------------------------------------------------
// Present: a crash after a provider 2xx converges to one charge, no re-POST.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn present_commits_with_one_charge_and_no_repost() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let seeded = reserve(&db.pool, &keyring, op, account, source, b"present payload").await;

    let backend = Arc::new(StubBackend::new(LookupReply::Present, UploadReply::Ok));
    let h = handler(db.pool.clone(), backend.clone(), config(12));
    let summary = h.run_once().await.expect("sweep pass");

    assert_eq!(summary.committed, 1, "the present attempt committed");
    assert_eq!(
        backend.post_count(),
        0,
        "a present attempt is committed WITHOUT a re-POST"
    );
    assert_eq!(
        attempt_state(&db.pool, seeded.attempt_id).await,
        AttemptState::Committed
    );

    // One net charge: hold (-c) + release (+c) + storage_upload (-c) = -c.
    assert_eq!(
        net_storage_micros(&db.pool, account).await,
        -seeded.charged_usd_micros,
        "the committed upload nets to exactly one storage charge"
    );
    assert_eq!(
        receipt_count(&db.pool, account).await,
        1,
        "one receipt landed"
    );
}

// ---------------------------------------------------------------------------
// Absent + staged present: re-POST then commit, exactly one POST, one charge.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn absent_with_staged_content_reposts_then_commits() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let seeded = reserve(
        &db.pool,
        &keyring,
        op,
        account,
        source,
        b"recoverable payload",
    )
    .await;

    let backend = Arc::new(StubBackend::new(LookupReply::Absent, UploadReply::Ok));
    let h = handler(db.pool.clone(), backend.clone(), config(12));
    let summary = h.run_once().await.expect("sweep pass");

    assert_eq!(summary.reposted, 1, "the recoverable attempt was re-POSTed");
    assert_eq!(
        backend.post_count(),
        1,
        "exactly one re-POST of the byte-identical reconstruction"
    );
    assert_eq!(
        attempt_state(&db.pool, seeded.attempt_id).await,
        AttemptState::Committed
    );
    assert_eq!(
        net_storage_micros(&db.pool, account).await,
        -seeded.charged_usd_micros,
        "the re-POSTed upload nets to exactly one storage charge"
    );
    assert_eq!(receipt_count(&db.pool, account).await, 1);
}

// ---------------------------------------------------------------------------
// Absent + staged gone: release + one upload-failed event, zero net charge.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn absent_with_staged_content_gone_releases_unrecoverable() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let seeded = reserve(&db.pool, &keyring, op, account, source, b"lost payload").await;

    // Simulate the staged content not surviving the crash: delete the durable file.
    let staged_path: String =
        sqlx::query_scalar("SELECT staged_path FROM cw_core.storage_upload_attempt WHERE id = $1")
            .bind(seeded.attempt_id)
            .fetch_one(&db.pool)
            .await
            .expect("read staged path");
    tokio::fs::remove_file(&staged_path)
        .await
        .expect("delete the staged file");

    let backend = Arc::new(StubBackend::new(LookupReply::Absent, UploadReply::Ok));
    let h = handler(db.pool.clone(), backend.clone(), config(12));
    let summary = h.run_once().await.expect("sweep pass");

    assert_eq!(
        summary.released_unrecoverable, 1,
        "the unrecoverable attempt was released"
    );
    assert_eq!(
        backend.post_count(),
        0,
        "an unrecoverable attempt is NEVER re-POSTed (no content to reconstruct)"
    );
    assert_eq!(
        attempt_state(&db.pool, seeded.attempt_id).await,
        AttemptState::Released
    );

    // The hold was returned: zero net charge.
    assert_eq!(
        net_storage_micros(&db.pool, account).await,
        0,
        "the released attempt charges the user nothing"
    );
    assert_eq!(
        receipt_count(&db.pool, account).await,
        0,
        "no receipt landed"
    );

    // Exactly one terminal client-facing failure event on the account subject.
    let events = account_events(&db.pool, account).await;
    let failures = events
        .iter()
        .filter(|e| *e == STORAGE_UPLOAD_FAILED_EVENT)
        .count();
    assert_eq!(
        failures, 1,
        "exactly one storage.upload.failed event, got {events:?}"
    );

    // A winc refund compensated the believed charge.
    let refunds: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_credit_ledger \
         WHERE funding_source_id = $1 AND kind = 'refund' AND ref = $2",
    )
    .bind(source)
    .bind(seeded.attempt_id.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("count winc refunds");
    assert_eq!(refunds, 1, "the believed winc charge was refunded");
}

/// A dedup loser whose refund (release_attempt) FAILED is left `reserved`, but the
/// upload route deletes its staged file FIRST (before the release), so the loser is
/// `reserved`-without-a-staged-file. The recovery sweep must NOT re-POST it even
/// though a committed winner receipt already holds these exact bytes: re-POSTing
/// would transmit already-deduped bytes to the provider a second time (the
/// double-POST this delete-first ordering prevents). With the staged file gone the
/// sweep releases the loser as unrecoverable and POSTs nothing, and the winner's
/// receipt is left intact. This pins the no-double-POST invariant for the failed-
/// release dedup branch: the leaked hold is reconciled (released) here, never by a
/// re-POST.
#[tokio::test]
async fn a_dedup_loser_reserved_without_its_staged_file_is_never_re_posted() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    // The loser's reservation: a real reserved attempt with a hold + believed winc.
    let content = b"deduped payload";
    let seeded = reserve(&db.pool, &keyring, op, account, source, content).await;

    // A concurrent WINNER already committed these exact bytes: a storage_upload
    // receipt holds (account, backend, sha256). This is what the loser deduped
    // against.
    let winner = StorageReceipt {
        uri: "ar://winner-committed".to_string(),
        data_item_id: "winner-committed".to_string(),
        raw_receipt: serde_json::json!({ "backend": "stub" }),
        root_tx_id: None,
    };
    let persisted = persist_receipt(
        &db.pool,
        account,
        &seeded.sha256,
        content.len() as u64,
        BACKEND,
        &winner,
    )
    .await
    .expect("seed the winner receipt");
    assert!(!persisted.deduped, "the winner receipt is a fresh insert");

    // The post-fix loser state on a FAILED release: the route deleted the staged
    // file BEFORE the release, so even though the release failed (the row is still
    // `reserved`), no staged file remains for the sweep to re-POST from.
    let staged_path: String =
        sqlx::query_scalar("SELECT staged_path FROM cw_core.storage_upload_attempt WHERE id = $1")
            .bind(seeded.attempt_id)
            .fetch_one(&db.pool)
            .await
            .expect("read staged path");
    tokio::fs::remove_file(&staged_path)
        .await
        .expect("delete the loser's staged file");

    // The loser's distinct data item is not on the provider (only the winner's is),
    // so the sweep's lookup is Absent. With the staged file gone it MUST release as
    // unrecoverable, never re-POST.
    let backend = Arc::new(StubBackend::new(LookupReply::Absent, UploadReply::Ok));
    let h = handler(db.pool.clone(), backend.clone(), config(12));
    let summary = h.run_once().await.expect("sweep pass");

    assert_eq!(
        backend.post_count(),
        0,
        "an already-deduped loser with no staged file is NEVER re-POSTed (no double-POST)"
    );
    assert_eq!(
        summary.released_unrecoverable, 1,
        "the fileless reserved loser is released, resolving the leaked hold"
    );
    assert_eq!(
        attempt_state(&db.pool, seeded.attempt_id).await,
        AttemptState::Released,
        "the loser reaches a terminal released state via the sweep"
    );

    // The winner's receipt is untouched: exactly one receipt for the logical file.
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1 AND sha256 = $2",
    )
    .bind(account)
    .bind(seeded.sha256.as_slice())
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(receipts, 1, "the winner's single receipt is intact");
}

// ---------------------------------------------------------------------------
// Unavailable: stay reserved; alert after N consecutive passes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unavailable_stays_reserved_and_alerts_after_n_passes() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let seeded = reserve(&db.pool, &keyring, op, account, source, b"stuck payload").await;

    let backend = Arc::new(StubBackend::new(LookupReply::Unavailable, UploadReply::Ok));
    // Alert on the THIRD consecutive unresolved pass.
    let h = handler(db.pool.clone(), backend.clone(), config(3));

    // Passes 1 and 2: stay reserved, no alert yet.
    for pass in 1..=2 {
        let summary = h.run_once().await.expect("sweep pass");
        assert_eq!(summary.left_reserved, 1, "pass {pass} leaves it reserved");
        assert_eq!(summary.stuck_emitted, 0, "no alert before the threshold");
        assert_eq!(
            attempt_state(&db.pool, seeded.attempt_id).await,
            AttemptState::Reserved,
            "the hold stays in place while the provider is down"
        );
    }

    // Pass 3 crosses the threshold: alert fires exactly once.
    let summary = h.run_once().await.expect("third pass");
    assert_eq!(summary.stuck_emitted, 1, "the stuck alert fires on pass 3");
    assert_eq!(
        attempt_state(&db.pool, seeded.attempt_id).await,
        AttemptState::Reserved,
        "the attempt is still reserved, never abandoned"
    );

    // Pass 4 does not re-alert (the alert fires only on the crossing pass).
    let summary = h.run_once().await.expect("fourth pass");
    assert_eq!(
        summary.stuck_emitted, 0,
        "the alert does not re-fire each pass"
    );

    let events = funding_events(&db.pool, source).await;
    let stuck = events.iter().filter(|e| *e == ATTEMPT_STUCK_EVENT).count();
    assert_eq!(
        stuck, 1,
        "exactly one storage.attempt.stuck event, got {events:?}"
    );

    // The hold is never leaked: it remains held while reserved.
    assert_eq!(
        net_storage_micros(&db.pool, account).await,
        -seeded.charged_usd_micros,
        "the hold is still in place (returned only on a terminal settlement)"
    );
}

// ---------------------------------------------------------------------------
// Horizon: a fresh (within-horizon) attempt is NEVER swept.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_attempt_within_the_horizon_is_never_swept() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let seeded = reserve(
        &db.pool,
        &keyring,
        op,
        account,
        source,
        b"in-flight payload",
    )
    .await;

    // A horizon far in the future: the just-inserted attempt is younger than it, so
    // a live upload is never swept out from under its handler.
    let backend = Arc::new(StubBackend::new(LookupReply::Absent, UploadReply::Ok));
    let cfg = AttemptReconcileConfig {
        reconcile_horizon: Duration::from_secs(3600),
        upload_claim_lease_ttl: Duration::from_secs(60),
        attempt_stuck_passes: 12,
    };
    let h = handler(db.pool.clone(), backend.clone(), cfg);
    let summary = h.run_once().await.expect("sweep pass");

    assert_eq!(
        summary,
        AttemptReconcileSummary::default(),
        "no attempt past the horizon, so the pass does nothing"
    );
    assert_eq!(
        backend.post_count(),
        0,
        "a within-horizon attempt is not POSTed"
    );
    assert_eq!(
        attempt_state(&db.pool, seeded.attempt_id).await,
        AttemptState::Reserved
    );
}

// ---------------------------------------------------------------------------
// Race: a sweep that loses the settlement CAS produces exactly one charge.
// ---------------------------------------------------------------------------

/// A live handler commits the attempt out from under the sweep (the sweep reads it
/// as `reserved`, then the live handler commits before the sweep's CAS). The sweep's
/// commit CAS finds no `reserved` row and no-ops, so the net effect is exactly ONE
/// charge, not two.
#[tokio::test]
async fn a_sweep_that_races_a_committed_attempt_settles_once() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let seeded = reserve(&db.pool, &keyring, op, account, source, b"raced payload").await;

    // The live handler already committed the attempt (the bytes landed and the
    // receipt + final charge were written).
    let receipt = StorageReceipt {
        uri: "ar://raced-id".into(),
        data_item_id: "raced-id".into(),
        raw_receipt: serde_json::json!({ "by": "live-handler" }),
        root_tx_id: None,
    };
    let settle = gateway_core::storage::commit_attempt(&db.pool, seeded.attempt_id, &receipt, None)
        .await
        .expect("live handler commit");
    assert_eq!(
        settle,
        gateway_core::storage::SettleOutcome::Settled {
            charged_usd_micros: seeded.charged_usd_micros,
        },
        "the live handler won the CAS and debited the held amount"
    );

    // Now the sweep runs, reading the attempt as already committed (it is no longer
    // reserved, so the horizon scan does not even pick it up). Either way it must not
    // double-charge.
    let backend = Arc::new(StubBackend::new(LookupReply::Present, UploadReply::Ok));
    let h = handler(db.pool.clone(), backend.clone(), config(12));
    h.run_once().await.expect("sweep pass");

    assert_eq!(
        net_storage_micros(&db.pool, account).await,
        -seeded.charged_usd_micros,
        "the raced attempt is charged exactly once (the CAS is single-winner)"
    );
    assert_eq!(
        receipt_count(&db.pool, account).await,
        1,
        "one receipt only"
    );
}

// ---------------------------------------------------------------------------
// Two sweep workers on one Absent+staged attempt: exactly one re-POST.
// ---------------------------------------------------------------------------

/// Two sweep workers run the same pass concurrently against one `Absent`+staged
/// attempt. The claim-lease admits exactly one to the POST window, so the stub
/// provider sees exactly ONE re-POST and the attempt commits once. The stub's POST
/// sleeps, so both passes genuinely overlap and the lease (not timing) is what
/// serializes them.
#[tokio::test]
async fn two_sweep_workers_issue_exactly_one_repost() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let seeded = reserve(
        &db.pool,
        &keyring,
        op,
        account,
        source,
        b"contended payload",
    )
    .await;

    // One shared backend so both workers count POSTs against the same counter; the
    // POST sleeps so the two passes overlap on the same attempt.
    let backend = Arc::new(
        StubBackend::new(LookupReply::Absent, UploadReply::Ok)
            .with_delay(Duration::from_millis(200)),
    );
    let h1 = Arc::new(handler(db.pool.clone(), backend.clone(), config(12)));
    let h2 = Arc::new(handler(db.pool.clone(), backend.clone(), config(12)));

    let (s1, s2) = tokio::join!(
        {
            let h = h1.clone();
            async move { h.run_once().await }
        },
        {
            let h = h2.clone();
            async move { h.run_once().await }
        },
    );
    let s1 = s1.expect("worker 1 pass");
    let s2 = s2.expect("worker 2 pass");

    assert_eq!(
        backend.post_count(),
        1,
        "the claim-lease admits exactly ONE re-POST among the two sweep workers"
    );
    // Exactly one worker re-POSTed; the other skipped (could not claim the lease).
    assert_eq!(
        s1.reposted + s2.reposted,
        1,
        "exactly one worker performed the re-POST"
    );
    assert_eq!(
        s1.skipped + s2.skipped,
        1,
        "the other worker skipped (it could not claim the POST window)"
    );

    assert_eq!(
        attempt_state(&db.pool, seeded.attempt_id).await,
        AttemptState::Committed
    );
    assert_eq!(
        net_storage_micros(&db.pool, account).await,
        -seeded.charged_usd_micros,
        "the contended attempt is charged exactly once"
    );
    assert_eq!(receipt_count(&db.pool, account).await, 1);
}

// ---------------------------------------------------------------------------
// Absent + staged present, but the re-POST is definitively refused: release as a
// provider rejection, zero net charge, no terminal upload-failed event (the bytes
// could still be re-uploaded; this is the same disposition the live handler's
// definite-failure path uses).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_definitely_refused_repost_releases_as_provider_rejected() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let seeded = reserve(&db.pool, &keyring, op, account, source, b"refused payload").await;

    let backend = Arc::new(StubBackend::new(LookupReply::Absent, UploadReply::Definite));
    let h = handler(db.pool.clone(), backend.clone(), config(12));
    let summary = h.run_once().await.expect("sweep pass");

    assert_eq!(summary.released_rejected, 1, "the refused re-POST released");
    assert_eq!(backend.post_count(), 1, "it did re-POST once");
    let attempt = load_attempt(&db.pool, seeded.attempt_id)
        .await
        .expect("load")
        .expect("exists");
    assert_eq!(attempt.state, AttemptState::Released);
    assert_eq!(
        attempt.release_reason,
        Some(ReleaseReason::ProviderRejected),
        "a definite re-POST refusal is a provider rejection, not unrecoverable"
    );
    assert_eq!(
        net_storage_micros(&db.pool, account).await,
        0,
        "the released attempt charges nothing"
    );
    // A provider rejection is NOT a terminal upload-failed event.
    let events = account_events(&db.pool, account).await;
    assert!(
        !events.contains(&STORAGE_UPLOAD_FAILED_EVENT.to_string()),
        "a provider rejection does not emit the terminal upload-failed event"
    );
}

// ---------------------------------------------------------------------------
// Absent + staged present, but the re-POST is ambiguous: leave reserved.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_ambiguous_repost_leaves_the_attempt_reserved() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let seeded = reserve(
        &db.pool,
        &keyring,
        op,
        account,
        source,
        b"ambiguous payload",
    )
    .await;

    let backend = Arc::new(StubBackend::new(
        LookupReply::Absent,
        UploadReply::Ambiguous,
    ));
    let h = handler(db.pool.clone(), backend.clone(), config(12));
    let summary = h.run_once().await.expect("sweep pass");

    assert_eq!(
        summary.left_reserved, 1,
        "an ambiguous re-POST leaves the attempt reserved (the bytes may have landed)"
    );
    assert_eq!(
        attempt_state(&db.pool, seeded.attempt_id).await,
        AttemptState::Reserved,
        "the hold is not released on an ambiguous re-POST"
    );
    assert_eq!(
        net_storage_micros(&db.pool, account).await,
        -seeded.charged_usd_micros,
        "the hold stays in place for the next pass"
    );
}
