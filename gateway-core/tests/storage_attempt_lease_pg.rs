//! Lease-fencing and lost-slot convergence for the upload-attempt state machine,
//! against a real Postgres.
//!
//! Two contracts are pinned here:
//!
//!   - The POST-window lease release is TOKEN-FENCED: a handler whose lease lapsed
//!     and was re-granted to a recovery sweep cannot wipe the sweep's fresh lease by
//!     releasing under its own stale token. The release matches no row and is a
//!     benign no-op.
//!   - The lost-then-vanished reserve race CONVERGES: when a reserve loses the
//!     live-slot race to a contender that has already committed the bytes, the
//!     reservation returns a dedup success carrying the committed receipt, never an
//!     opaque error.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use age::secrecy::SecretString;
use ans104::{Ans104Signer, ArweaveJwkSigner, Tag};
use gateway_core::storage::{
    claim_post_lease, commit_attempt, insert_credit_entry, promote_to_durable, race_window,
    release_post_lease, reserve_attempt, stage_stream, AuthorizedFunding, CreditEntry, CreditKind,
    ReserveOutcome, ReserveSpec, SettleOutcome, StorageReceipt,
};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::{arweave_address, unlock, UnlockedKeyring};
use rust_decimal::Decimal;
use uuid::Uuid;
use zeroize::Zeroizing;

const BACKEND: &str = "turbo";

/// The throwaway Arweave JWK every keyring in this suite signs with.
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// A low scrypt work factor so the in-test keyring envelope encrypts/decrypts fast.
const TEST_SCRYPT_LOG_N: u8 = 4;

fn fixture_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

fn unlocked_keyring() -> UnlockedKeyring {
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
    unlock(
        &ciphertext,
        Zeroizing::new("test-pass".to_string()),
        Network::Mainnet,
    )
    .expect("the fixture keyring unlocks")
}

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

/// A reserved attempt plus the temp dirs keeping its durable staged file alive.
struct Reserved {
    attempt_id: Uuid,
    sha256: [u8; 32],
    #[allow(dead_code)]
    durable: tempfile::TempDir,
    #[allow(dead_code)]
    scratch: tempfile::TempDir,
}

/// Sign, stage, and `reserve_attempt` real bytes for `content`, returning the
/// claimed attempt id (the same path the live route takes).
async fn reserve(
    pool: &sqlx::PgPool,
    keyring: &UnlockedKeyring,
    operator: Uuid,
    account: Uuid,
    source: Uuid,
    content: &[u8],
) -> Reserved {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let durable = tempfile::tempdir().expect("durable dir");

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

    let attempt_id = Uuid::now_v7();
    let staged_path = promote_to_durable(staged, durable.path(), attempt_id)
        .await
        .expect("promote staged to durable");
    let staged_path_str = staged_path.to_string_lossy().into_owned();

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
        ReserveOutcome::Claimed(attempt) => assert_eq!(attempt.id, attempt_id),
        other => panic!("a fresh reservation must claim, got {other:?}"),
    };

    Reserved {
        attempt_id,
        sha256,
        durable,
        scratch,
    }
}

/// The current lease token on an attempt row, if any.
async fn lease_token(pool: &sqlx::PgPool, attempt_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar(
        "SELECT upload_claim_token FROM cw_core.storage_upload_attempt WHERE id = $1",
    )
    .bind(attempt_id)
    .fetch_one(pool)
    .await
    .expect("read lease token")
}

/// Force the attempt's lease to read as lapsed so a fresh claim can take it,
/// simulating the prior owner dying mid-POST.
async fn expire_lease(pool: &sqlx::PgPool, attempt_id: Uuid) {
    sqlx::query(
        "UPDATE cw_core.storage_upload_attempt \
            SET upload_claim_expires_at = now() - make_interval(secs => 1) \
          WHERE id = $1",
    )
    .bind(attempt_id)
    .execute(pool)
    .await
    .expect("expire the lease");
}

// ---------------------------------------------------------------------------
// FENCE: a stale-token release after a lapse-takeover is a no-op.
// ---------------------------------------------------------------------------

/// Handler A claims the POST window (token A). Its lease then lapses and a recovery
/// sweep re-claims the window (token B). A, resuming under its stale token, releases
/// the lease — which must be a NO-OP: the row still carries token B, so the sweep's
/// fresh ownership of the POST window is preserved.
#[tokio::test]
async fn a_stale_token_release_after_lapse_takeover_is_a_noop() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let reserved = reserve(&db.pool, &keyring, op, account, source, b"fenced payload").await;

    // Handler A claims the POST window.
    let token_a = claim_post_lease(&db.pool, reserved.attempt_id, 60)
        .await
        .expect("claim succeeds")
        .expect("the unheld lease is granted");

    // A's lease lapses (A stalled past its lease lifetime).
    expire_lease(&db.pool, reserved.attempt_id).await;

    // A recovery sweep re-claims the lapsed window with a fresh token.
    let token_b = claim_post_lease(&db.pool, reserved.attempt_id, 60)
        .await
        .expect("re-claim succeeds")
        .expect("the lapsed lease is re-granted");
    assert_ne!(token_a, token_b, "the takeover minted a distinct token");
    assert_eq!(
        lease_token(&db.pool, reserved.attempt_id).await,
        Some(token_b),
        "the sweep now owns the POST window"
    );

    // A resumes and releases under its STALE token. This must not clear token B.
    release_post_lease(&db.pool, reserved.attempt_id, token_a)
        .await
        .expect("the stale release returns Ok");

    assert_eq!(
        lease_token(&db.pool, reserved.attempt_id).await,
        Some(token_b),
        "the stale-token release was a no-op: the new owner's lease is intact"
    );
}

/// The current owner releasing under its OWN token does clear the lease (the
/// forward-looking, idempotent path the ambiguous-POST arm relies on).
#[tokio::test]
async fn a_release_under_the_current_token_clears_the_lease() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000).await;
    fund_balance(&db.pool, account, 1_000_000).await;
    let keyring = unlocked_keyring();

    let reserved = reserve(&db.pool, &keyring, op, account, source, b"owner release").await;

    let token = claim_post_lease(&db.pool, reserved.attempt_id, 60)
        .await
        .expect("claim succeeds")
        .expect("granted");

    release_post_lease(&db.pool, reserved.attempt_id, token)
        .await
        .expect("release Ok");

    assert_eq!(
        lease_token(&db.pool, reserved.attempt_id).await,
        None,
        "the holder's own release frees the lease"
    );
}

// ---------------------------------------------------------------------------
// CONVERGENCE: a reserve that loses the slot to a committed winner deduplicates.
// ---------------------------------------------------------------------------

/// An owned copy of the borrowed `ReserveSpec` fields, so a spec can outlive the
/// signing scope and be lent to `reserve_attempt` in a concurrent task.
struct OwnedSpec {
    id: Uuid,
    account_id: Uuid,
    operator_id: Uuid,
    funding_source_id: Uuid,
    sha256: [u8; 32],
    bytes: u64,
    charged_usd_micros: i64,
    data_item_id: String,
    data_item_signature: Vec<u8>,
    data_item_anchor: Option<Vec<u8>>,
    data_item_tag_bytes: Vec<u8>,
    staged_path: String,
}

impl OwnedSpec {
    fn borrow(&self) -> ReserveSpec<'_> {
        ReserveSpec {
            id: self.id,
            account_id: self.account_id,
            operator_id: self.operator_id,
            funding_source_id: self.funding_source_id,
            backend: BACKEND,
            sha256: self.sha256,
            bytes: self.bytes,
            chargeable_bytes: self.bytes,
            charged_usd_micros: self.charged_usd_micros,
            estimated_winc: Decimal::from(self.bytes.max(1)),
            data_item_id: &self.data_item_id,
            data_item_signature: &self.data_item_signature,
            data_item_anchor: self.data_item_anchor.as_deref(),
            data_item_tag_bytes: &self.data_item_tag_bytes,
            staged_path: &self.staged_path,
            request_id: None,
        }
    }
}

/// Sign + stage `content` and return an owned [`ReserveSpec`] (plus the temp dirs
/// keeping the durable staged file alive for the call). Re-signing the same bytes
/// yields the same logical-upload key `(account, backend, sha256)`.
async fn make_spec(
    keyring: &UnlockedKeyring,
    operator: Uuid,
    account: Uuid,
    source: Uuid,
    content: &[u8],
) -> (OwnedSpec, [u8; 32], tempfile::TempDir, tempfile::TempDir) {
    let scratch = tempfile::tempdir().expect("scratch");
    let durable = tempfile::tempdir().expect("durable");
    let staged = stage_stream(
        scratch.path(),
        1 << 20,
        futures_util::stream::iter(vec![Ok::<Vec<u8>, std::convert::Infallible>(
            content.to_vec(),
        )]),
    )
    .await
    .expect("stage");
    let sha256 = staged.sha256;
    let bytes = staged.bytes;

    let funding = AuthorizedFunding::for_tests(source, fixture_arweave_address());
    let signer = keyring.arweave_signer_for(&funding).expect("signer");
    let tags = vec![Tag::new(
        "Content-Type",
        b"application/octet-stream".to_vec(),
    )];
    let mut file = std::fs::File::open(staged.path()).expect("open staged");
    let envelope = signer
        .sign_streaming_envelope(None, None, &tags, &mut file, bytes)
        .expect("sign");

    let id = Uuid::now_v7();
    let staged_path = promote_to_durable(staged, durable.path(), id)
        .await
        .expect("promote");
    let owned = OwnedSpec {
        id,
        account_id: account,
        operator_id: operator,
        funding_source_id: source,
        sha256,
        bytes,
        charged_usd_micros: i64::try_from(bytes).expect("fits") + 1,
        data_item_id: envelope.id_b64url,
        data_item_signature: envelope.signature,
        data_item_anchor: envelope.anchor.map(|a| a.to_vec()),
        data_item_tag_bytes: envelope.tag_bytes,
        staged_path: staged_path.to_string_lossy().into_owned(),
    };
    (owned, sha256, durable, scratch)
}

/// Two reservers race the same logical upload: the winner commits the receipt while
/// the loser is mid-reserve. Two properties are pinned:
///
///   1. The conflict-then-vanish window converges to a dedup success. The window
///      (the loser's insert conflicts, then the winner commits before the loser's
///      attach read) spans microseconds, so instead of racing tasks and hoping the
///      scheduler produces it, the loser is parked INSIDE the window by the
///      `race_window` test gate; the winner then commits, and the released loser
///      must return the winner's receipt (the prior behaviour was a hard
///      `internal-error` from exactly this interleaving).
///   2. Under an unconstrained race the loser must NEVER error: whatever the
///      scheduler does, it converges to a dedup, an attach to the still-live
///      winner, or its own claim.
#[tokio::test]
async fn a_reserve_racing_a_committing_winner_never_errors_and_can_dedup() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000_000).await;
    fund_balance(&db.pool, account, 1_000_000_000).await;
    let keyring = unlocked_keyring();

    // Property 1 — the deterministic window. The gate parks the loser after its
    // conflicting insert and before its attach read; the winner settles inside
    // that pause.
    {
        let content = b"converge payload deterministic".to_vec();
        let winner = reserve(&db.pool, &keyring, op, account, source, &content).await;
        let (loser_spec, loser_sha, _durable, _scratch) =
            make_spec(&keyring, op, account, source, &content).await;
        assert_eq!(loser_sha, winner.sha256, "same logical upload");

        let mut window = race_window::arm(loser_sha);
        let pool_l = db.pool.clone();
        let loser =
            tokio::spawn(async move { reserve_attempt(&pool_l, &loser_spec.borrow()).await });

        window.entered().await;
        let receipt = StorageReceipt {
            uri: "ar://winner-deterministic".to_string(),
            data_item_id: "winner-deterministic".to_string(),
            raw_receipt: serde_json::json!({ "by": "winner" }),
            root_tx_id: None,
        };
        commit_attempt(&db.pool, winner.attempt_id, &receipt, None)
            .await
            .expect("winner commit");
        window.release();

        let outcome = loser
            .await
            .expect("loser task")
            .expect("the loser's reserve never errors");
        match outcome {
            ReserveOutcome::Deduplicated(existing) => {
                assert_eq!(
                    existing.uri, "ar://winner-deterministic",
                    "dedup converged on the winner's receipt"
                );
            }
            other => panic!("the vanished-winner window must dedup, got {other:?}"),
        }
    }

    // Property 2 — unconstrained races. Every convergence is legal; an error never
    // is. A handful of trials suffices since the window itself is pinned above.
    for trial in 0..8u32 {
        // A distinct logical upload per trial, so each trial is independent and no
        // stale receipt short-circuits the next.
        let content = format!("converge payload {trial}").into_bytes();

        // The winner reserves and holds the live slot.
        let winner = reserve(&db.pool, &keyring, op, account, source, &content).await;

        // The loser's spec for the SAME content (same logical upload).
        let (loser_spec, loser_sha, _durable, _scratch) =
            make_spec(&keyring, op, account, source, &content).await;
        assert_eq!(loser_sha, winner.sha256, "same logical upload");
        let loser_id = loser_spec.id;

        let receipt = StorageReceipt {
            uri: format!("ar://winner-{trial}"),
            data_item_id: format!("winner-{trial}"),
            raw_receipt: serde_json::json!({ "by": "winner" }),
            root_tx_id: None,
        };

        // Concurrently: the winner commits its receipt (leaving 'reserved'), while
        // the loser runs its full reserve loop. Whichever side wins the scheduler,
        // the loser must converge without erroring.
        let pool_w = db.pool.clone();
        let pool_l = db.pool.clone();
        let winner_attempt = winner.attempt_id;
        let (commit_res, reserve_res) = tokio::join!(
            async move { commit_attempt(&pool_w, winner_attempt, &receipt, None).await },
            async move { reserve_attempt(&pool_l, &loser_spec.borrow()).await },
        );
        let _ = commit_res.expect("winner commit");
        let outcome = reserve_res.expect("the loser's reserve never errors");

        match outcome {
            ReserveOutcome::Deduplicated(existing) => {
                assert!(
                    existing.uri.starts_with("ar://winner-"),
                    "dedup converged on the winner's receipt"
                );
            }
            // The loser's insert ran before the winner left 'reserved': it attached
            // to the still-live winner. Acceptable convergence, no second charge.
            ReserveOutcome::Attached(att) => {
                assert_ne!(att.id, loser_id, "attached to the winner, not itself");
            }
            // The loser's insert ran after the slot freed: it legitimately claimed.
            // Settle it (a commit dedups against the winner's receipt) so the next
            // trial starts clean.
            ReserveOutcome::Claimed(att) => {
                assert_eq!(att.id, loser_id);
                let r = StorageReceipt {
                    uri: format!("ar://loser-{trial}"),
                    data_item_id: format!("loser-{trial}"),
                    raw_receipt: serde_json::json!({ "by": "loser" }),
                    root_tx_id: None,
                };
                commit_attempt(&db.pool, loser_id, &r, None)
                    .await
                    .expect("settle the loser's own claim");
            }
            ReserveOutcome::InsufficientFunds => panic!("the account is funded"),
        }
    }
}

/// The lost-slot resolution never surfaces an error: when the live slot is gone and
/// a committed receipt already exists for the logical upload, a fresh reserve
/// converges (it claims the freed slot here; the commit then dedups against the
/// winner's receipt for zero second charge). The prior code returned an opaque
/// `Error::Config` on this path.
#[tokio::test]
async fn a_reserve_against_an_already_committed_upload_never_errors() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (op, account) = seed_account(&db.pool).await;
    let source = seed_funded_source(&db.pool, op).await;
    fund_credit(&db.pool, source, 1_000_000_000).await;
    fund_balance(&db.pool, account, 1_000_000_000).await;
    let keyring = unlocked_keyring();

    let content = b"focused convergence";
    let winner = reserve(&db.pool, &keyring, op, account, source, content).await;

    // The winner commits, freeing the live slot and leaving a committed receipt.
    let receipt = StorageReceipt {
        uri: "ar://focused-winner".into(),
        data_item_id: "focused-winner".into(),
        raw_receipt: serde_json::json!({ "by": "winner" }),
        root_tx_id: None,
    };
    assert!(matches!(
        commit_attempt(&db.pool, winner.attempt_id, &receipt, None)
            .await
            .expect("winner commit"),
        SettleOutcome::Settled { .. }
    ));

    // A fresh reserve for the same logical upload converges without erroring.
    let (loser_spec, loser_sha, _durable, _scratch) =
        make_spec(&keyring, op, account, source, content).await;
    assert_eq!(loser_sha, winner.sha256);
    let loser_id = loser_spec.id;
    let outcome = reserve_attempt(&db.pool, &loser_spec.borrow())
        .await
        .expect("the reserve never errors");
    match outcome {
        ReserveOutcome::Claimed(att) => {
            assert_eq!(att.id, loser_id, "claimed the freed slot");
            let r = StorageReceipt {
                uri: "ar://focused-loser".into(),
                data_item_id: "focused-loser".into(),
                raw_receipt: serde_json::json!({ "by": "loser" }),
                root_tx_id: None,
            };
            assert_eq!(
                commit_attempt(&db.pool, loser_id, &r, None)
                    .await
                    .expect("loser commit"),
                SettleOutcome::Settled {
                    charged_usd_micros: 0
                },
                "the commit deduped against the winner's receipt: no second charge"
            );
        }
        ReserveOutcome::Deduplicated(existing) => {
            assert_eq!(existing.uri, "ar://focused-winner");
        }
        other => panic!("expected a settled convergence, got {other:?}"),
    }

    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_upload WHERE account_id = $1")
            .bind(account)
            .fetch_one(&db.pool)
            .await
            .expect("count receipts");
    assert_eq!(receipts, 1, "exactly one receipt survives the dedup");
}
