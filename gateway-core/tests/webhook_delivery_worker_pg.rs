//! Integration tests for the webhook fan-out drain and the delivery worker.
//!
//! These pin the delivery contract end to end:
//!
//!   - fan-out explodes an outbox row into one delivery row per matching live
//!     subscription, exactly once even across a crash between the per-subscription
//!     inserts and the `fanned_out_at` stamp;
//!   - the mid-stream cutoff is presence-based: an event fanned out before a
//!     subscription exists is never delivered to it (no backlog replay), and one
//!     fanned out after it exists is (no miss);
//!   - the frontier claim keeps per-subject ordering per subscription, an exhausted
//!     delivery unblocks the next seq (skip-after-exhaustion), and one slow
//!     subject/endpoint never blocks another (no head-of-line blocking);
//!   - a failing endpoint retries then dead-letters then auto-disables, emitting a
//!     `webhook.endpoint_disabled` event;
//!   - the delivery worker signs and POSTs a real receiver, resets the failure
//!     budget on a 2xx, and re-schedules a failure with the capped backoff.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use gateway_core::events::append_subject_event;
use gateway_core::runtime::{JobContext, JobHandler, JobOutcome};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::keyring::{UnlockedKeyring, WebhookWrapKey};
use gateway_core::webhook::delivery::{self, DeliveryPolicy};
use gateway_core::webhook::egress::EgressConfig;
use gateway_core::webhook::fanout::claim_unfanned;
use gateway_core::webhook::{DeliveryHandler, FanoutHandler};

// ---------------------------------------------------------------------------
// Seed helpers (operator / account / poe_record / endpoint).
// ---------------------------------------------------------------------------

async fn seed_operator(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'op')")
        .bind(id)
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

/// Seed a `poe_record` owned by `operator_id` with an optional account owner, and
/// return its id (the `poe_record` subject id).
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

/// Seal a secret under the keyring's webhook-wrap key, returning the
/// `(secret_enc, secret_fp, wrap_key_id)` an endpoint row carries. Resolving the
/// wrap through the shared keyring means the delivery worker unwraps the same key.
fn seal_secret(keyring: &UnlockedKeyring, plaintext: &str) -> (Vec<u8>, Vec<u8>, String) {
    let wrap = keyring
        .active_webhook_wrap_key()
        .expect("the test keyring holds a wrap key")
        .secret_wrap();
    let secret_enc = wrap.seal(plaintext).expect("seal");
    let secret_fp = gateway_core::webhook::secret::fingerprint(plaintext);
    (secret_enc, secret_fp, wrap.wrap_key_id().to_string())
}

/// Insert an account-scoped endpoint and return its id.
async fn seed_account_endpoint(
    pool: &sqlx::PgPool,
    keyring: &UnlockedKeyring,
    account_id: Uuid,
    url: &str,
    enabled_events: Vec<String>,
) -> Uuid {
    let id = Uuid::now_v7();
    let (secret_enc, secret_fp, wrap_key_id) = seal_secret(keyring, "whsec_account_secret_0123");
    sqlx::query(
        "INSERT INTO cw_core.webhook_endpoint \
           (id, scope_kind, account_id, url, secret_enc, secret_fp, wrap_key_id, enabled_events) \
         VALUES ($1, 'account', $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(account_id)
    .bind(url)
    .bind(&secret_enc)
    .bind(&secret_fp)
    .bind(&wrap_key_id)
    .bind(&enabled_events)
    .execute(pool)
    .await
    .expect("seed account endpoint");
    id
}

/// Insert an operator-scoped firehose endpoint and return its id.
async fn seed_operator_endpoint(
    pool: &sqlx::PgPool,
    keyring: &UnlockedKeyring,
    operator_id: Uuid,
    url: &str,
    enabled_events: Vec<String>,
) -> Uuid {
    let id = Uuid::now_v7();
    let (secret_enc, secret_fp, wrap_key_id) = seal_secret(keyring, "whsec_operator_secret_0123");
    sqlx::query(
        "INSERT INTO cw_core.webhook_endpoint \
           (id, scope_kind, operator_id, url, secret_enc, secret_fp, wrap_key_id, enabled_events) \
         VALUES ($1, 'operator', $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(url)
    .bind(&secret_enc)
    .bind(&secret_fp)
    .bind(&wrap_key_id)
    .bind(&enabled_events)
    .execute(pool)
    .await
    .expect("seed operator endpoint");
    id
}

/// Append a `poe_record` event and drain the fan-out for it, returning how many
/// delivery rows it produced.
async fn append_and_fanout(pool: &sqlx::PgPool, record_id: Uuid, event_type: &str) -> u64 {
    append_subject_event(
        pool,
        "poe_record",
        &record_id.to_string(),
        event_type,
        &json!({}),
    )
    .await
    .expect("append");
    FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("fanout")
}

/// Claim a specific delivery row through the lease-granting claim path and return
/// its lease token, so a test that drives `record_failure` directly presents the
/// claim token the terminal CAS is fenced on. The row must be the due frontier row
/// for its (endpoint, subject); the tests that use this prepared it to be exactly
/// that.
async fn claim_lease_for(pool: &sqlx::PgPool, delivery_id: Uuid) -> Uuid {
    let mut tx = pool.begin().await.expect("begin");
    let leases = delivery::claim_due(&mut tx, 64, Duration::seconds(60))
        .await
        .expect("claim");
    tx.commit().await.expect("commit");
    leases
        .into_iter()
        .find(|l| l.id == delivery_id)
        .map(|l| l.claim_token)
        .expect("the target delivery is claimable as its due frontier row")
}

/// Count delivery rows for an endpoint.
async fn delivery_count(pool: &sqlx::PgPool, endpoint_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
        .bind(endpoint_id)
        .fetch_one(pool)
        .await
        .expect("count")
}

/// A keyring holding one fresh webhook-wrap key. Endpoints seal their secret under
/// it, and the delivery worker unwraps the same key by its `wrap_key_id`.
fn test_keyring() -> Arc<UnlockedKeyring> {
    let key = WebhookWrapKey::generate("webhook-wrap".to_string(), "whk_test".to_string())
        .expect("generate wrap key");
    Arc::new(UnlockedKeyring::for_webhook_tests(vec![key]))
}

// ---------------------------------------------------------------------------
// A multi-request loopback receiver sink with per-request scripted statuses.
// ---------------------------------------------------------------------------

/// One received delivery: its `Webhook-Id` and body.
#[derive(Clone)]
struct Delivered {
    webhook_id: String,
    body: String,
}

/// A loopback receiver that answers each request with the next scripted status
/// (the last status repeats once the script runs out) and records every request.
struct ReceiverSink {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Delivered>>>,
}

impl ReceiverSink {
    /// Spawn a receiver answering each request with `statuses[i]` (clamped to the
    /// last), recording each request body and `Webhook-Id`.
    fn spawn(statuses: Vec<u16>) -> Self {
        Self::spawn_with_delay(statuses, std::time::Duration::ZERO)
    }

    /// Spawn a receiver that records every request but waits `delay` before
    /// answering each one, widening the POST window so two concurrent delivery
    /// workers genuinely overlap on the same delivery rather than racing past it.
    fn spawn_with_delay(statuses: Vec<u16>, delay: std::time::Duration) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_for_thread = Arc::clone(&received);
        let counter = AtomicUsize::new(0);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let req = read_request(&mut stream);
                let idx = counter.fetch_add(1, Ordering::SeqCst);
                let status = statuses
                    .get(idx)
                    .copied()
                    .unwrap_or_else(|| *statuses.last().unwrap_or(&200));
                // Record the request the moment it is fully read, BEFORE the delay,
                // so a POST-counting assertion sees the request even while the
                // response is still pending.
                if let Some(req) = req {
                    received_for_thread.lock().unwrap().push(req);
                }
                if !delay.is_zero() {
                    thread::sleep(delay);
                }
                let resp = format!(
                    "HTTP/1.1 {status} STATUS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        Self { addr, received }
    }

    fn url(&self) -> String {
        format!("http://{}/hook", self.addr)
    }

    fn deliveries(&self) -> Vec<Delivered> {
        self.received.lock().unwrap().clone()
    }

    fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Delivered> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_len = pos + 4;
            let content_len = content_length(&buf[..header_len]).unwrap_or(0);
            if buf.len() >= header_len + content_len {
                break;
            }
        }
    }
    let pos = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
    let body = String::from_utf8_lossy(&buf[pos + 4..]).to_string();
    let webhook_id = header_value(&headers, "webhook-id").unwrap_or_default();
    Some(Delivered { webhook_id, body })
}

fn content_length(headers: &[u8]) -> Option<usize> {
    header_value(&String::from_utf8_lossy(headers), "content-length")?
        .parse()
        .ok()
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// The egress config that reaches the suite's local plain-HTTP receiver. The two
/// loosenings are independent axes, so both are opened explicitly: the scheme
/// (`allow_insecure_http`) and the range-block (`allow_loopback`).
fn loopback_egress() -> EgressConfig {
    EgressConfig {
        allow_insecure_http: true,
        allow_loopback: true,
    }
}

// ---------------------------------------------------------------------------
// Fan-out: matching, exactly-once, crash dedupe.
// ---------------------------------------------------------------------------

/// Fan-out explodes one event into one delivery row per matching live
/// subscription: the owning account and the operator firehose both receive it; a
/// second account under the same operator does NOT.
#[tokio::test]
async fn fanout_matches_account_and_operator_subscriptions() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let other_account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;

    let keyring = test_keyring();
    let acct_ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;
    let op_ep = seed_operator_endpoint(&pool, &keyring, operator, "https://x/", vec![]).await;
    let other_ep =
        seed_account_endpoint(&pool, &keyring, other_account, "https://x/", vec![]).await;

    let produced = append_and_fanout(&pool, record, "confirmed").await;
    assert_eq!(produced, 1, "one outbox row was fanned out");

    assert_eq!(
        delivery_count(&pool, acct_ep).await,
        1,
        "owning account receives it"
    );
    assert_eq!(
        delivery_count(&pool, op_ep).await,
        1,
        "operator firehose receives it"
    );
    assert_eq!(
        delivery_count(&pool, other_ep).await,
        0,
        "a different account under the same operator does not receive it"
    );
}

/// A `poe_record` with a NULL account owner (an operator-direct publish) fans out
/// to the operator firehose only, never to an account subscription.
#[tokio::test]
async fn operator_direct_record_fans_to_operator_only() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, None).await;

    let keyring = test_keyring();
    let acct_ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;
    let op_ep = seed_operator_endpoint(&pool, &keyring, operator, "https://x/", vec![]).await;

    append_and_fanout(&pool, record, "submitted").await;

    assert_eq!(
        delivery_count(&pool, acct_ep).await,
        0,
        "an operator-direct record has no account owner, so no account subscription matches"
    );
    assert_eq!(
        delivery_count(&pool, op_ep).await,
        1,
        "the operator firehose still matches"
    );
}

/// The `enabled_events` filter only matches a subscription whose filter contains
/// the projected wire name (or is empty).
#[tokio::test]
async fn fanout_applies_the_enabled_events_filter() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;

    let keyring = test_keyring();
    // One endpoint filters on the matching wire name; one filters on a different
    // one and must not match.
    let matching = seed_account_endpoint(
        &pool,
        &keyring,
        account,
        "https://x/",
        vec!["poe_status_changed".into()],
    )
    .await;
    let mismatched = seed_account_endpoint(
        &pool,
        &keyring,
        account,
        "https://x/",
        vec!["balance_changed".into()],
    )
    .await;

    append_and_fanout(&pool, record, "confirmed").await;

    assert_eq!(
        delivery_count(&pool, matching).await,
        1,
        "the filter that includes the name matches"
    );
    assert_eq!(
        delivery_count(&pool, mismatched).await,
        0,
        "a filter that excludes the name does not match"
    );
}

/// Fan-out is exactly-once even when the explode transaction crashes between the
/// delivery inserts and the `fanned_out_at` stamp: on replay each subscription has
/// exactly one delivery row, with no duplicate and no unique-violation wedge.
#[tokio::test]
async fn fanout_is_exactly_once_across_a_mid_fanout_crash() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;

    let keyring = test_keyring();
    let acct_ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    append_subject_event(
        &pool,
        "poe_record",
        &record.to_string(),
        "confirmed",
        &json!({}),
    )
    .await
    .expect("append");

    // Claim the outbox row, explode it (inserting the delivery rows + stamp), then
    // ROLL BACK to simulate a crash before the explode transaction committed.
    let row = {
        let mut tx = pool.begin().await.expect("begin");
        let batch = claim_unfanned(&mut tx, 10).await.expect("claim");
        tx.commit().await.expect("commit claim");
        batch.into_iter().next().expect("one row")
    };
    {
        let mut tx = pool.begin().await.expect("begin");
        delivery::explode_outbox_row(&pool, &mut tx, &row)
            .await
            .expect("explode");
        tx.rollback().await.expect("rollback (simulated crash)");
    }

    // The crashed explode left no delivery row and no stamp.
    assert_eq!(
        delivery_count(&pool, acct_ep).await,
        0,
        "the rolled-back explode left no rows"
    );
    let unfanned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.delivery_outbox WHERE fanned_out_at IS NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(unfanned, 1, "the row is still un-fanned after the crash");

    // Replay: run the fan-out twice. The first run explodes-and-commits; the second
    // finds nothing un-fanned. Each subscription has exactly one delivery row.
    FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("replay 1");
    FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("replay 2");
    assert_eq!(
        delivery_count(&pool, acct_ep).await,
        1,
        "exactly one delivery row after replay; no duplicate, no unique-violation wedge"
    );
}

// ---------------------------------------------------------------------------
// Presence-based mid-stream cutoff.
// ---------------------------------------------------------------------------

/// An event fanned out BEFORE a subscription exists is never delivered to it (no
/// backlog replay), and an event fanned out AFTER it exists is (no miss).
#[tokio::test]
async fn mid_stream_cutoff_excludes_pre_fanout_and_delivers_post_fanout() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;

    // Event A is fanned out BEFORE any subscription exists.
    append_and_fanout(&pool, record, "submitted").await;

    // Now register the subscription, AFTER A was fanned out.
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    // A was fanned out before the endpoint existed, so the endpoint has no delivery
    // for it: no backlog replay above any stale boundary.
    assert_eq!(
        delivery_count(&pool, ep).await,
        0,
        "an event fanned out before the subscription existed is never delivered to it"
    );

    // Events C, D, E are fanned out after the endpoint exists: all three delivered.
    append_and_fanout(&pool, record, "confirmed").await;
    append_and_fanout(&pool, record, "confirmed").await;
    append_and_fanout(&pool, record, "confirmed").await;
    assert_eq!(
        delivery_count(&pool, ep).await,
        3,
        "every event fanned out after the subscription is delivered (no miss)"
    );
}

/// A subscriber that registers mid-stream starts at the current subject position.
/// Its FIRST delivery for a subject carries a `subject_seq > 1` (the earlier seqs
/// were fanned out before it existed), and its delivered run is contiguous from
/// that start point.
#[tokio::test]
async fn new_subscriber_starts_at_a_subject_seq_above_one() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;

    // Fan out seq 1 and 2 BEFORE the endpoint exists.
    append_and_fanout(&pool, record, "submitted").await;
    append_and_fanout(&pool, record, "confirmed").await;

    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    // Then emit seq 3 and 4 after it exists.
    append_and_fanout(&pool, record, "confirmed").await;
    append_and_fanout(&pool, record, "confirmed").await;

    let seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT subject_seq FROM cw_core.webhook_delivery \
         WHERE endpoint_id = $1 ORDER BY subject_seq",
    )
    .bind(ep)
    .fetch_all(&pool)
    .await
    .expect("seqs");
    assert_eq!(
        seqs,
        vec![3, 4],
        "the first delivered seq is 3 (a valid mid-stream start point, not seq 1), and the run is contiguous"
    );
}

// ---------------------------------------------------------------------------
// Delivery ordering, skip-after-exhaustion, no-HOL (the §2a claim).
// ---------------------------------------------------------------------------

/// The frontier claim returns only the lowest pending seq per (endpoint, subject):
/// seq N+1 is never claimable while seq N is still pending.
#[tokio::test]
async fn claim_returns_only_the_lowest_pending_seq_per_subject() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;
    let keyring = test_keyring();
    // The endpoint must exist for fan-out to produce delivery rows; its id is not
    // referenced because the claim is asserted on the deliveries it produces.
    let _ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    // Fan out three events for one subject (seq 1, 2, 3).
    for _ in 0..3 {
        append_and_fanout(&pool, record, "confirmed").await;
    }

    // The claim returns exactly one row, and it is the lowest seq (1).
    let mut tx = pool.begin().await.expect("begin");
    let claimed = delivery::claim_due(&mut tx, 10, chrono::Duration::seconds(60))
        .await
        .expect("claim");
    assert_eq!(
        claimed.len(),
        1,
        "only the frontier row per (endpoint, subject) is claimable"
    );
    let seq: i64 =
        sqlx::query_scalar("SELECT subject_seq FROM cw_core.webhook_delivery WHERE id = $1")
            .bind(claimed[0].id)
            .fetch_one(&mut *tx)
            .await
            .expect("seq");
    assert_eq!(seq, 1, "the frontier is the lowest pending seq");
    tx.rollback().await.expect("rollback");
}

/// An exhausted (failed) delivery unblocks the next seq for its (endpoint,
/// subject): once seq 1 is terminally `failed`, the claim returns seq 2.
#[tokio::test]
async fn exhausted_delivery_unblocks_the_next_seq() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    for _ in 0..2 {
        append_and_fanout(&pool, record, "confirmed").await;
    }
    // Force seq 1's delivery terminal: a max_attempts=1 row that fails once is
    // exhausted.
    let seq1: Uuid = sqlx::query_scalar(
        "SELECT id FROM cw_core.webhook_delivery WHERE endpoint_id = $1 AND subject_seq = 1",
    )
    .bind(ep)
    .fetch_one(&pool)
    .await
    .expect("seq1 id");
    sqlx::query("UPDATE cw_core.webhook_delivery SET max_attempts = 1 WHERE id = $1")
        .bind(seq1)
        .execute(&pool)
        .await
        .expect("cap attempts");

    // Claim seq 1 to obtain its POST lease, then record the (exhausting) failure
    // under that lease — the terminal CAS is fenced on the claim token.
    let token1 = claim_lease_for(&pool, seq1).await;
    let outcome = delivery::record_failure(
        &pool,
        seq1,
        token1,
        Some(500),
        "forced exhaustion",
        &DeliveryPolicy::default(),
    )
    .await
    .expect("record failure");
    assert_eq!(outcome, delivery::FailureOutcome::Exhausted);

    let state: String =
        sqlx::query_scalar("SELECT state FROM cw_core.webhook_delivery WHERE id = $1")
            .bind(seq1)
            .fetch_one(&pool)
            .await
            .expect("state");
    assert_eq!(
        state, "failed",
        "the exhausted delivery is a terminal dead-letter"
    );

    // The claim now returns seq 2: the failed predecessor does not block it.
    let mut tx = pool.begin().await.expect("begin");
    let claimed = delivery::claim_due(&mut tx, 10, chrono::Duration::seconds(60))
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    let seq: i64 =
        sqlx::query_scalar("SELECT subject_seq FROM cw_core.webhook_delivery WHERE id = $1")
            .bind(claimed[0].id)
            .fetch_one(&mut *tx)
            .await
            .expect("seq");
    assert_eq!(seq, 2, "skip-after-exhaustion: the next seq is unblocked");
    tx.rollback().await.expect("rollback");
}

/// No head-of-line blocking: a pending-but-not-yet-due seq 1 for one subject does
/// not block another subject's (or another endpoint's) frontier.
#[tokio::test]
async fn no_head_of_line_blocking_across_subjects_and_endpoints() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let keyring = test_keyring();
    let ep_a = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;
    // The second endpoint must exist so the no-HOL claim has another frontier group;
    // its id is not referenced (the assertion is on the count of claimable rows).
    let _ep_b = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    // Two distinct subjects, each fanned to both endpoints.
    let record_one = seed_poe_record(&pool, operator, Some(account)).await;
    let record_two = seed_poe_record(&pool, operator, Some(account)).await;
    append_and_fanout(&pool, record_one, "confirmed").await;
    append_and_fanout(&pool, record_two, "confirmed").await;

    // Push endpoint A's record_one delivery into the future (a slow/retrying row).
    sqlx::query(
        "UPDATE cw_core.webhook_delivery SET next_attempt_at = now() + interval '1 hour' \
         WHERE endpoint_id = $1 AND subject_id = $2",
    )
    .bind(ep_a)
    .bind(record_one.to_string())
    .execute(&pool)
    .await
    .expect("delay one row");

    // The claim still returns the other three frontier rows (A/record_two,
    // B/record_one, B/record_two); only A/record_one is held back by its own
    // not-yet-due time, blocking neither the other subject nor the other endpoint.
    let mut tx = pool.begin().await.expect("begin");
    let claimed = delivery::claim_due(&mut tx, 10, chrono::Duration::seconds(60))
        .await
        .expect("claim");
    assert_eq!(
        claimed.len(),
        3,
        "a not-yet-due row blocks only its own (endpoint, subject) frontier, not others"
    );
    tx.rollback().await.expect("rollback");
}

// ---------------------------------------------------------------------------
// End-to-end delivery: happy path, retry-then-success, auto-disable.
// ---------------------------------------------------------------------------

/// The delivery worker signs and POSTs to a live receiver; a 2xx marks the
/// delivery `delivered`, resets the endpoint's failure budget, and the receiver
/// observes the `Webhook-Id` and the JSON envelope.
#[tokio::test]
async fn delivery_worker_delivers_and_marks_delivered() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;

    let receiver = ReceiverSink::spawn(vec![200]);
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, &receiver.url(), vec![]).await;

    append_and_fanout(&pool, record, "confirmed").await;

    let handler = DeliveryHandler::new(
        pool.clone(),
        keyring,
        loopback_egress(),
        DeliveryPolicy::default(),
    );
    handler.run_once().await.expect("delivery pass");

    // The delivery row is delivered, attempts counted, and the endpoint's failure
    // budget is reset (last_success_at set).
    let (state, attempts): (String, i32) = sqlx::query_as(
        "SELECT state, attempts FROM cw_core.webhook_delivery WHERE endpoint_id = $1",
    )
    .bind(ep)
    .fetch_one(&pool)
    .await
    .expect("delivery row");
    assert_eq!(state, "delivered");
    assert_eq!(attempts, 1);

    let last_success: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_success_at FROM cw_core.webhook_endpoint WHERE id = $1")
            .bind(ep)
            .fetch_one(&pool)
            .await
            .expect("endpoint");
    assert!(
        last_success.is_some(),
        "a 2xx resets the failure budget and stamps last_success_at"
    );

    // The receiver saw exactly one POST carrying the per-delivery Webhook-Id and the
    // typed envelope.
    let got = receiver.deliveries();
    assert_eq!(got.len(), 1, "exactly one delivery POST");
    assert!(
        got[0].webhook_id.contains(&ep.to_string()),
        "Webhook-Id is per-delivery"
    );
    assert!(
        got[0].body.contains("poe_status_changed"),
        "the envelope carries the wire type"
    );
}

/// A receiver that 500s then 200s: the first delivery pass records a transient
/// failure (still pending, next_attempt_at advanced); after the row is made due
/// again a second pass succeeds, reusing the SAME Webhook-Id and body.
#[tokio::test]
async fn delivery_worker_retries_a_500_then_succeeds() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;

    let receiver = ReceiverSink::spawn(vec![500, 200]);
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, &receiver.url(), vec![]).await;

    append_and_fanout(&pool, record, "confirmed").await;

    let handler = DeliveryHandler::new(
        pool.clone(),
        keyring,
        loopback_egress(),
        DeliveryPolicy::default(),
    );

    // Drive delivery passes, re-arming the row to due between passes, until the
    // receiver has seen both the 500 and the 200. Full jitter means a retry MIGHT
    // re-fire within one pass, so the loop bounds the run rather than asserting a
    // single intermediate state: the contract is "a 500 is retried, not dropped,
    // and the same delivery eventually succeeds", which the end state proves.
    let mut state = String::new();
    for _ in 0..5 {
        handler.run_once().await.expect("delivery pass");
        // Re-arm a still-pending row so the next pass retries it without waiting on
        // the (possibly multi-second) jittered backoff.
        sqlx::query(
            "UPDATE cw_core.webhook_delivery SET next_attempt_at = now() \
             WHERE endpoint_id = $1 AND state = 'pending'",
        )
        .bind(ep)
        .execute(&pool)
        .await
        .expect("re-arm");
        state =
            sqlx::query_scalar("SELECT state FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
                .bind(ep)
                .fetch_one(&pool)
                .await
                .expect("row");
        if state == "delivered" {
            break;
        }
    }
    assert_eq!(
        state, "delivered",
        "the retry after a 500 eventually succeeds"
    );

    // The receiver saw the 500 then the 200; both POSTs carried the identical
    // Webhook-Id and body (a retry re-uses the frozen delivery, re-signed).
    let got = receiver.deliveries();
    assert_eq!(got.len(), 2, "exactly the 500 attempt then the 200 attempt");
    assert_eq!(
        got[0].webhook_id, got[1].webhook_id,
        "a retry reuses the same Webhook-Id"
    );
    assert_eq!(
        got[0].body, got[1].body,
        "a retry signs the same frozen body"
    );
}

/// An endpoint that always fails accrues consecutive exhausted deliveries until the
/// auto-disable budget flips it to `disabled`, emitting a `webhook.endpoint_disabled`
/// event on the owning account's subject.
#[tokio::test]
async fn sustained_failure_auto_disables_and_emits_an_event() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    // A fast budget so the test drives it quickly: disable after 3 consecutive
    // exhausted deliveries.
    let policy = DeliveryPolicy {
        auto_disable_consecutive: 3,
        ..DeliveryPolicy::default()
    };

    // Drive three exhausted deliveries (each a distinct subject so they are
    // independent frontier rows), forcing each to exhaust with max_attempts=1.
    for _ in 0..3 {
        let record = seed_poe_record(&pool, operator, Some(account)).await;
        append_and_fanout(&pool, record, "confirmed").await;
        let id: Uuid = sqlx::query_scalar(
            "SELECT id FROM cw_core.webhook_delivery WHERE endpoint_id = $1 AND subject_id = $2",
        )
        .bind(ep)
        .bind(record.to_string())
        .fetch_one(&pool)
        .await
        .expect("delivery id");
        sqlx::query("UPDATE cw_core.webhook_delivery SET max_attempts = 1 WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("cap");
        let token = claim_lease_for(&pool, id).await;
        delivery::record_failure(&pool, id, token, Some(500), "always fails", &policy)
            .await
            .expect("record failure");
    }

    // The endpoint is auto-disabled with the consecutive-failures reason.
    let (status, reason, consecutive): (String, Option<String>, i32) = sqlx::query_as(
        "SELECT status, disabled_reason, consecutive_failures \
         FROM cw_core.webhook_endpoint WHERE id = $1",
    )
    .bind(ep)
    .fetch_one(&pool)
    .await
    .expect("endpoint");
    assert_eq!(
        status, "disabled",
        "the budget exhausts and auto-disables the endpoint"
    );
    assert_eq!(reason.as_deref(), Some("consecutive_failures"));
    assert_eq!(consecutive, 3, "three consecutive exhausted deliveries");

    // A `webhook.endpoint_disabled` event was appended on the owning account's
    // subject so the operator's firehose/SSE hears the disable.
    let disable_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'account' AND subject_id = $1 \
           AND event_type = 'webhook.endpoint_disabled'",
    )
    .bind(account.to_string())
    .fetch_one(&pool)
    .await
    .expect("count disable events");
    assert_eq!(
        disable_events, 1,
        "exactly one auto-disable event is emitted"
    );

    // A disabled endpoint contributes no claimable rows: its pending backlog freezes.
    let mut tx = pool.begin().await.expect("begin");
    let claimed = delivery::claim_due(&mut tx, 10, chrono::Duration::seconds(60))
        .await
        .expect("claim");
    assert!(
        claimed.is_empty(),
        "a disabled endpoint contributes no claimable deliveries"
    );
    tx.rollback().await.expect("rollback");
}

/// Regression: a second exhaustion that finds the endpoint already auto-disabled
/// appends NO second `webhook.endpoint_disabled` event.
///
/// `disable_endpoint` once appended the disable event unconditionally, gated only by
/// a `status <> 'disabled'` UPDATE whose row count it ignored. Two exhaustions that
/// both crossed the budget therefore each emitted the subject event, so a downstream
/// automation fired the disable twice for one logical enabled→disabled transition.
/// The fix gates the event on the flip's `rows_affected`: only the transition emits
/// it. This drives two exhausting deliveries on the same endpoint (distinct subjects,
/// so independent frontier rows) past a budget of 1 and asserts exactly one event.
#[tokio::test]
async fn a_second_exhaustion_on_an_already_disabled_endpoint_emits_no_duplicate_event() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    // Disable on the FIRST exhaustion, so the second exhaustion finds the endpoint
    // already disabled — the duplicate-event path.
    let policy = DeliveryPolicy {
        auto_disable_consecutive: 1,
        ..DeliveryPolicy::default()
    };

    // Fan out two deliveries on distinct subjects (independent frontier rows for the
    // same endpoint) BEFORE either exhausts, so BOTH delivery rows exist while the
    // endpoint is still active. (A disabled endpoint is excluded from fan-out, so the
    // second row would never be created if we disabled before fanning it out.)
    let mut delivery_ids = Vec::new();
    for _ in 0..2 {
        let record = seed_poe_record(&pool, operator, Some(account)).await;
        append_and_fanout(&pool, record, "confirmed").await;
        let id: Uuid = sqlx::query_scalar(
            "SELECT id FROM cw_core.webhook_delivery WHERE endpoint_id = $1 AND subject_id = $2",
        )
        .bind(ep)
        .bind(record.to_string())
        .fetch_one(&pool)
        .await
        .expect("delivery id");
        sqlx::query("UPDATE cw_core.webhook_delivery SET max_attempts = 1 WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("cap");
        delivery_ids.push(id);
    }

    // Claim BOTH leases up front while the endpoint is still active (the first
    // exhaustion will disable it, after which claim_due excludes its rows). Both
    // distinct-subject frontier rows are claimable in one pass.
    let tokens: Vec<(Uuid, Uuid)> = {
        let mut tx = pool.begin().await.expect("begin claim");
        let leases = delivery::claim_due(&mut tx, 64, Duration::seconds(60))
            .await
            .expect("claim both leases");
        tx.commit().await.expect("commit claim");
        delivery_ids
            .iter()
            .map(|id| {
                let token = leases
                    .iter()
                    .find(|l| l.id == *id)
                    .map(|l| l.claim_token)
                    .expect("both deliveries are claimable while active");
                (*id, token)
            })
            .collect()
    };

    // Exhaust both, one after another. The first crosses the budget and disables; the
    // second crosses it again (consecutive_failures = 2 >= 1) and re-enters
    // disable_endpoint, which must now be a no-op because the endpoint is already
    // disabled — emitting no second event.
    for (id, token) in tokens {
        delivery::record_failure(&pool, id, token, Some(500), "always fails", &policy)
            .await
            .expect("record failure");
    }

    // The endpoint is disabled, and its consecutive counter kept climbing (the second
    // exhaustion still accrued), proving the second pass DID re-enter the disable
    // decision — yet emitted no second event.
    let (status, consecutive): (String, i32) = sqlx::query_as(
        "SELECT status, consecutive_failures FROM cw_core.webhook_endpoint WHERE id = $1",
    )
    .bind(ep)
    .fetch_one(&pool)
    .await
    .expect("endpoint");
    assert_eq!(status, "disabled");
    assert_eq!(
        consecutive, 2,
        "both exhaustions accrued, so the second re-entered the disable decision"
    );

    let disable_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'account' AND subject_id = $1 \
           AND event_type = 'webhook.endpoint_disabled'",
    )
    .bind(account.to_string())
    .fetch_one(&pool)
    .await
    .expect("count disable events");
    assert_eq!(
        disable_events, 1,
        "exactly one disable event for one logical transition; the second exhaustion appends none"
    );
}

/// Regression: a replica that does not hold an endpoint's wrap key must NOT burn the
/// delivery's attempt budget or auto-disable a live endpoint.
///
/// `deliver_one` once recorded a custody gap (this instance lacks the wrap key) as a
/// delivery failure, bumping `attempts` and feeding the auto-disable accumulator — so
/// a keyless replica repeatedly winning a row could dead-letter the delivery and
/// disable a perfectly reachable endpoint. The fix releases the lease and re-arms the
/// row without consuming the budget. This drives a delivery worker whose keyring does
/// NOT hold the endpoint's wrap key and asserts the row stays pending with attempts
/// unchanged, the lease released, and the endpoint still active.
#[tokio::test]
async fn a_replica_without_the_wrap_key_does_not_burn_attempts_or_disable_the_endpoint() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;

    // The endpoint's secret is sealed under one keyring's wrap key.
    let key_holding_keyring = test_keyring();
    let receiver = ReceiverSink::spawn(vec![200]);
    let ep = seed_account_endpoint(
        &pool,
        &key_holding_keyring,
        account,
        &receiver.url(),
        vec![],
    )
    .await;
    append_and_fanout(&pool, record, "confirmed").await;

    // A worker on a DIFFERENT replica whose keyring holds a wrap key with a DIFFERENT
    // id (so `webhook_wrap_key(this endpoint's id)` returns None — the custody gap).
    // A budget of 1 means that, if a custody gap were (wrongly) counted as a failure,
    // a single pass would exhaust the delivery and auto-disable the endpoint.
    let keyless_keyring = {
        let other = WebhookWrapKey::generate("webhook-wrap".to_string(), "whk_other".to_string())
            .expect("generate a different wrap key");
        Arc::new(UnlockedKeyring::for_webhook_tests(vec![other]))
    };
    let policy = DeliveryPolicy {
        auto_disable_consecutive: 1,
        ..DeliveryPolicy::default()
    };
    let id: Uuid =
        sqlx::query_scalar("SELECT id FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
            .bind(ep)
            .fetch_one(&pool)
            .await
            .expect("delivery id");
    sqlx::query("UPDATE cw_core.webhook_delivery SET max_attempts = 1 WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("cap attempts to 1");

    DeliveryHandler::new(pool.clone(), keyless_keyring, loopback_egress(), policy)
        .run_once()
        .await
        .expect("keyless delivery pass");

    // The receiver was never POSTed: a keyless replica cannot sign, so it must not
    // reach the network.
    assert_eq!(
        receiver.count(),
        0,
        "a keyless replica never POSTs (it cannot sign the delivery)"
    );

    // The delivery is still pending, its attempt budget untouched, and its lease
    // released for a key-holding replica to claim.
    let (state, attempts, claim_token): (String, i32, Option<Uuid>) = sqlx::query_as(
        "SELECT state, attempts, claim_token FROM cw_core.webhook_delivery WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .expect("delivery row");
    assert_eq!(
        state, "pending",
        "the delivery stays pending, not dead-lettered"
    );
    assert_eq!(
        attempts, 0,
        "a local custody gap burns no attempt (budget of 1 is intact)"
    );
    assert_eq!(
        claim_token, None,
        "the lease is released for a key-holding replica"
    );

    // The endpoint is still active: a missing key on one replica must never
    // auto-disable a live endpoint.
    let (status, consecutive): (String, i32) = sqlx::query_as(
        "SELECT status, consecutive_failures FROM cw_core.webhook_endpoint WHERE id = $1",
    )
    .bind(ep)
    .fetch_one(&pool)
    .await
    .expect("endpoint");
    assert_eq!(
        status, "active",
        "a keyless replica does not auto-disable the endpoint"
    );
    assert_eq!(consecutive, 0, "the auto-disable accumulator is untouched");

    // The key-holding replica then claims the re-armed row and delivers it: the
    // custody gap only deferred the delivery, never failed it.
    sqlx::query("UPDATE cw_core.webhook_delivery SET next_attempt_at = now() WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("re-arm to due now");
    DeliveryHandler::new(
        pool.clone(),
        key_holding_keyring,
        loopback_egress(),
        DeliveryPolicy::default(),
    )
    .run_once()
    .await
    .expect("key-holding delivery pass");
    let state: String =
        sqlx::query_scalar("SELECT state FROM cw_core.webhook_delivery WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("state");
    assert_eq!(
        state, "delivered",
        "the key-holding replica delivers the row the keyless one deferred"
    );
    assert_eq!(
        receiver.count(),
        1,
        "exactly one POST, from the key-holding replica"
    );
}

/// A transient failure re-arms the delivery with a capped backoff: the
/// `next_attempt_at` is in the future but never beyond the 6h cap.
#[tokio::test]
async fn transient_failure_reschedules_within_the_backoff_cap() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    append_and_fanout(&pool, record, "confirmed").await;
    let id: Uuid =
        sqlx::query_scalar("SELECT id FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
            .bind(ep)
            .fetch_one(&pool)
            .await
            .expect("id");

    let policy = DeliveryPolicy::default();
    let before = Utc::now();
    let token = claim_lease_for(&pool, id).await;
    let outcome = delivery::record_failure(&pool, id, token, Some(503), "transient", &policy)
        .await
        .expect("record failure");
    match outcome {
        delivery::FailureOutcome::Retry { next_attempt_at } => {
            assert!(
                next_attempt_at >= before,
                "the next attempt is not in the past"
            );
            assert!(
                next_attempt_at <= before + Duration::hours(6) + Duration::seconds(2),
                "the next attempt is within the 6h cap"
            );
        }
        delivery::FailureOutcome::Exhausted => {
            panic!("a single failure on a 12-attempt budget is not exhausted")
        }
    }

    // The row is still pending and re-armed.
    let (state, next_due): (String, chrono::DateTime<Utc>) =
        sqlx::query_as("SELECT state, next_attempt_at FROM cw_core.webhook_delivery WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(state, "pending");
    assert!(
        next_due > before,
        "the delivery is re-armed for a future attempt"
    );
}

/// The delivery handler, driven through the runtime `JobHandler` surface, defers to
/// the soonest pending due instant when work remains and completes when nothing is
/// pending.
#[tokio::test]
async fn delivery_handler_defers_when_work_remains_and_completes_when_idle() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    // A pending delivery that is not yet due (far in the future) leaves the handler
    // with nothing to deliver this pass but something pending, so it defers.
    append_and_fanout(&pool, record, "confirmed").await;
    sqlx::query(
        "UPDATE cw_core.webhook_delivery SET next_attempt_at = now() + interval '30 minutes' \
         WHERE endpoint_id = $1",
    )
    .bind(ep)
    .execute(&pool)
    .await
    .expect("delay");

    let handler = DeliveryHandler::new(
        pool.clone(),
        keyring,
        loopback_egress(),
        DeliveryPolicy::default(),
    );
    let ctx = JobContext {
        job_id: Uuid::now_v7(),
        queue: "webhook_delivery".to_string(),
        payload: serde_json::Value::Null,
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    };
    match handler.handle(ctx.clone()).await {
        JobOutcome::Defer { until } => {
            assert!(until > Utc::now(), "defers to a future due instant");
        }
        other => panic!("expected a defer while a pending delivery is not yet due, got {other:?}"),
    }

    // Once the only delivery is terminally settled, the handler completes (nothing
    // pending).
    sqlx::query("UPDATE cw_core.webhook_delivery SET state = 'failed' WHERE endpoint_id = $1")
        .bind(ep)
        .execute(&pool)
        .await
        .expect("settle");
    match handler.handle(ctx).await {
        JobOutcome::Complete => {}
        other => panic!("expected complete when nothing is pending, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Exclusive POST claim-lease (no routine concurrent double-delivery).
// ---------------------------------------------------------------------------

/// The claim grants an exclusive POST lease: once one worker claims a due delivery,
/// a second worker's claim sees the lease held and returns nothing for that row, so
/// only one worker ever owns the POST window. This is the database-level invariant
/// the concurrent-race test exercises end to end.
#[tokio::test]
async fn a_held_lease_excludes_a_second_claim() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;
    let keyring = test_keyring();
    let _ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    append_and_fanout(&pool, record, "confirmed").await;

    // Worker A claims the row, granting itself the lease.
    let mut tx_a = pool.begin().await.expect("begin A");
    let claimed_a = delivery::claim_due(&mut tx_a, 10, Duration::seconds(60))
        .await
        .expect("claim A");
    tx_a.commit().await.expect("commit A");
    assert_eq!(claimed_a.len(), 1, "worker A claims the one due delivery");

    // Worker B claims while A still holds the (unexpired) lease: the row is excluded
    // even though it is still `pending` and due.
    let mut tx_b = pool.begin().await.expect("begin B");
    let claimed_b = delivery::claim_due(&mut tx_b, 10, Duration::seconds(60))
        .await
        .expect("claim B");
    tx_b.commit().await.expect("commit B");
    assert!(
        claimed_b.is_empty(),
        "the held lease excludes a second claim of the same pending row"
    );
}

/// Two delivery workers racing one due delivery POST it exactly once: the lease
/// makes the claim exclusive across the network POST, so a POST-counting receiver
/// sees a single request even though both workers run concurrently against a slow
/// receiver that holds the POST window open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_workers_racing_one_delivery_post_it_exactly_once() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;

    // A slow receiver holds each POST open for 300ms, so if both workers claimed the
    // same row their POSTs would genuinely overlap and the count would be 2.
    let receiver = ReceiverSink::spawn_with_delay(vec![200], std::time::Duration::from_millis(300));
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, &receiver.url(), vec![]).await;

    append_and_fanout(&pool, record, "confirmed").await;

    // Two independent delivery workers over the same pool, started together.
    let worker = |pool: sqlx::PgPool, keyring: Arc<UnlockedKeyring>| async move {
        DeliveryHandler::new(pool, keyring, loopback_egress(), DeliveryPolicy::default())
            .run_once()
            .await
            .expect("delivery pass");
    };
    let a = tokio::spawn(worker(pool.clone(), Arc::clone(&keyring)));
    let b = tokio::spawn(worker(pool.clone(), Arc::clone(&keyring)));
    a.await.expect("worker A");
    b.await.expect("worker B");

    // Exactly one POST reached the receiver, and the row is delivered once.
    assert_eq!(
        receiver.count(),
        1,
        "two racing workers POST the delivery exactly once"
    );
    let (state, attempts): (String, i32) = sqlx::query_as(
        "SELECT state, attempts FROM cw_core.webhook_delivery WHERE endpoint_id = $1",
    )
    .bind(ep)
    .fetch_one(&pool)
    .await
    .expect("delivery row");
    assert_eq!(state, "delivered");
    assert_eq!(attempts, 1, "the delivery counts exactly one attempt");
}

/// A crashed worker's lease lapses and another worker reclaims and redelivers:
/// at-least-once is preserved. The first claim grants a lease that is then forced to
/// have already expired (modeling a worker that died mid-POST); the worker reclaims
/// the now-lapsed row and delivers it.
#[tokio::test]
async fn a_lapsed_lease_is_reclaimed_and_redelivered() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;

    let receiver = ReceiverSink::spawn(vec![200]);
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, &receiver.url(), vec![]).await;

    append_and_fanout(&pool, record, "confirmed").await;

    // A worker claims the row, then "crashes" mid-POST: the row stays pending but
    // holds a lease. Force the lease to have already lapsed to model the crashed
    // owner without waiting out a real TTL.
    let mut tx = pool.begin().await.expect("begin");
    let claimed = delivery::claim_due(&mut tx, 10, Duration::seconds(60))
        .await
        .expect("claim");
    tx.commit().await.expect("commit");
    assert_eq!(claimed.len(), 1, "the crashed worker claimed the row");
    sqlx::query(
        "UPDATE cw_core.webhook_delivery SET claim_expires_at = now() - interval '1 minute' \
         WHERE id = $1",
    )
    .bind(claimed[0].id)
    .execute(&pool)
    .await
    .expect("force the lease to lapse");

    // The row is still pending (no terminal write happened), and its lapsed lease
    // makes it reclaimable.
    let state: String =
        sqlx::query_scalar("SELECT state FROM cw_core.webhook_delivery WHERE id = $1")
            .bind(claimed[0].id)
            .fetch_one(&pool)
            .await
            .expect("state");
    assert_eq!(
        state, "pending",
        "a crashed mid-POST leaves the row pending"
    );

    // A fresh worker reclaims the lapsed-lease row and delivers it: at-least-once is
    // preserved (a real crash mid-POST may redeliver; the receiver dedupes on id).
    DeliveryHandler::new(
        pool.clone(),
        keyring,
        loopback_egress(),
        DeliveryPolicy::default(),
    )
    .run_once()
    .await
    .expect("redelivery pass");

    let state: String =
        sqlx::query_scalar("SELECT state FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
            .bind(ep)
            .fetch_one(&pool)
            .await
            .expect("state");
    assert_eq!(state, "delivered", "the reclaimed row is redelivered");
    assert_eq!(receiver.count(), 1, "the redelivery POSTed the row");
}

/// The token fence settles a lapsed-lease takeover deterministically: after worker
/// B reclaims a row whose lease lapsed under worker A and records its own outcome,
/// worker A's terminal CAS with its now-stale token is a no-op. The row reflects
/// B's outcome only; A's late write changes nothing, so a takeover never produces a
/// double terminal write. This holds whether or not the claim CTE was already
/// exclusive, because it is the `WHERE claim_token = $token` fence on
/// `record_success`/`record_failure` that decides the terminal state.
#[tokio::test]
async fn a_stale_token_terminal_write_is_a_no_op_after_a_lapsed_lease_takeover() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let record = seed_poe_record(&pool, operator, Some(account)).await;
    let keyring = test_keyring();
    let ep = seed_account_endpoint(&pool, &keyring, account, "https://x/", vec![]).await;

    append_and_fanout(&pool, record, "confirmed").await;
    let delivery_id: Uuid =
        sqlx::query_scalar("SELECT id FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
            .bind(ep)
            .fetch_one(&pool)
            .await
            .expect("delivery row");

    // Worker A claims row R, taking lease token T_a, and is now "mid-POST" (it has
    // not yet recorded its outcome).
    let token_a = claim_lease_for(&pool, delivery_id).await;

    // R's lease lapses (A died mid-POST, or its POST outran the TTL).
    sqlx::query(
        "UPDATE cw_core.webhook_delivery SET claim_expires_at = now() - interval '1 minute' \
         WHERE id = $1",
    )
    .bind(delivery_id)
    .execute(&pool)
    .await
    .expect("force A's lease to lapse");

    // Worker B reclaims the now-lapsed row, taking a distinct lease token T_b, and
    // delivers it (records success under T_b).
    let token_b = claim_lease_for(&pool, delivery_id).await;
    assert_ne!(
        token_a, token_b,
        "the takeover grants a fresh lease token, not A's stale one"
    );
    delivery::record_success(&pool, delivery_id, token_b, 200)
        .await
        .expect("B records its delivery");

    // The row is now B's terminal outcome.
    let (state_after_b, attempts_after_b, last_status): (String, i32, Option<i32>) =
        sqlx::query_as(
            "SELECT state, attempts, last_status FROM cw_core.webhook_delivery WHERE id = $1",
        )
        .bind(delivery_id)
        .fetch_one(&pool)
        .await
        .expect("state after B");
    assert_eq!(state_after_b, "delivered", "B's success is the row's state");
    assert_eq!(attempts_after_b, 1, "exactly one terminal write counted");
    assert_eq!(last_status, Some(200));

    // Worker A now resumes from its (completed) POST and attempts its terminal CAS
    // with the STALE token T_a. Both terminal writes must be no-ops: the token fence
    // `WHERE claim_token = T_a` matches zero rows because B cleared the lease on its
    // terminal write, so A's late outcome cannot overwrite B's.
    delivery::record_success(&pool, delivery_id, token_a, 200)
        .await
        .expect("A's stale record_success runs without error");
    let stale_failure = delivery::record_failure(
        &pool,
        delivery_id,
        token_a,
        Some(500),
        "A's stale outcome",
        &DeliveryPolicy::default(),
    )
    .await
    .expect("A's stale record_failure runs without error");
    // A lost the lease, so its failure path bumps no attempt and re-schedules
    // nothing: it reports Exhausted (the no-row terminal short-circuit), not a Retry.
    assert_eq!(
        stale_failure,
        delivery::FailureOutcome::Exhausted,
        "a stale-token failure is a no-op, not a re-schedule"
    );

    // The row still reflects B's outcome ONLY: A's stale writes changed nothing.
    let (state_final, attempts_final, last_status_final, last_error): (
        String,
        i32,
        Option<i32>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT state, attempts, last_status, last_error FROM cw_core.webhook_delivery \
         WHERE id = $1",
    )
    .bind(delivery_id)
    .fetch_one(&pool)
    .await
    .expect("final state");
    assert_eq!(state_final, "delivered", "B's terminal state is preserved");
    assert_eq!(
        attempts_final, 1,
        "A's stale writes bumped no attempt (no double terminal write)"
    );
    assert_eq!(last_status_final, Some(200), "A's stale 500 did not land");
    assert_eq!(
        last_error, None,
        "A's stale error did not overwrite B's clean success"
    );
}

// ---------------------------------------------------------------------------
// Operator-subject auto-disable fan-out + the unresolvable-subject backstop.
// ---------------------------------------------------------------------------

/// An operator-scoped firehose endpoint that auto-disables emits its
/// `webhook.endpoint_disabled` event on the operator subject, and that event fans
/// out to the operator firehose (the matching live endpoint), never to an account
/// subscription — and the fan-out drain does not wedge on the operator subject.
#[tokio::test]
async fn operator_firehose_auto_disable_fans_to_the_firehose_without_wedging() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    let operator = seed_operator(&pool).await;
    let account = seed_account(&pool, operator).await;
    let keyring = test_keyring();

    // The firehose endpoint whose own auto-disable we drive, plus a SECOND operator
    // firehose endpoint that should receive the disable event, plus an account
    // endpoint that must NOT (the disable is operator-only).
    let target = seed_operator_endpoint(&pool, &keyring, operator, "https://x/", vec![]).await;
    let listener = seed_operator_endpoint(&pool, &keyring, operator, "https://y/", vec![]).await;
    let acct_ep = seed_account_endpoint(&pool, &keyring, account, "https://z/", vec![]).await;

    // Force the target firehose endpoint to auto-disable by exhausting its budget on
    // a single delivery. The disable event is appended on the operator subject.
    let policy = DeliveryPolicy {
        auto_disable_consecutive: 1,
        ..DeliveryPolicy::default()
    };
    let record = seed_poe_record(&pool, operator, Some(account)).await;
    append_and_fanout(&pool, record, "confirmed").await;
    let target_delivery: Uuid = sqlx::query_scalar(
        "SELECT id FROM cw_core.webhook_delivery WHERE endpoint_id = $1 AND subject_id = $2",
    )
    .bind(target)
    .bind(record.to_string())
    .fetch_one(&pool)
    .await
    .expect("target delivery");
    sqlx::query("UPDATE cw_core.webhook_delivery SET max_attempts = 1 WHERE id = $1")
        .bind(target_delivery)
        .execute(&pool)
        .await
        .expect("cap");
    let token = claim_lease_for(&pool, target_delivery).await;
    let outcome =
        delivery::record_failure(&pool, target_delivery, token, Some(500), "fail", &policy)
            .await
            .expect("record failure");
    assert_eq!(outcome, delivery::FailureOutcome::Exhausted);

    // The disable event landed on the operator subject.
    let disable_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'operator' AND subject_id = $1 \
           AND event_type = 'webhook.endpoint_disabled'",
    )
    .bind(operator.to_string())
    .fetch_one(&pool)
    .await
    .expect("count disable events");
    assert_eq!(disable_events, 1, "the disable rides the operator subject");

    // The fan-out drain processes the operator-subject outbox row WITHOUT wedging:
    // it resolves the operator owner and fans the disable to the operator firehose.
    let processed = FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("fan-out drains the operator-subject row");
    assert!(processed >= 1, "the operator-subject outbox row was fanned");

    // A repeat drain is a no-op (the row is stamped, not re-claimed): the drain
    // never wedges on the operator subject.
    let again = FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("second drain");
    assert_eq!(
        again, 0,
        "the operator-subject row is not re-fanned (no wedge)"
    );

    // The OTHER firehose endpoint received the disable; the account endpoint did not.
    let listener_disable: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.webhook_delivery \
         WHERE endpoint_id = $1 AND event_type = 'webhook.endpoint_disabled'",
    )
    .bind(listener)
    .fetch_one(&pool)
    .await
    .expect("listener deliveries");
    assert_eq!(
        listener_disable, 1,
        "the operator firehose receives the disable event"
    );
    let acct_disable: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.webhook_delivery \
         WHERE endpoint_id = $1 AND event_type = 'webhook.endpoint_disabled'",
    )
    .bind(acct_ep)
    .fetch_one(&pool)
    .await
    .expect("account deliveries");
    assert_eq!(
        acct_disable, 0,
        "an account subscription never receives an operator-only disable event"
    );
}

/// An injected outbox row whose subject kind has a wire form but no resolvable owner
/// is terminally stamped with zero deliveries — never left to re-block the set-drain
/// forever. This is the structural poison-row backstop: even a producer/consumer
/// mismatch cannot wedge the drain.
#[tokio::test]
async fn an_unresolvable_subject_row_is_terminally_skipped_not_re_scanned() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    // Append an event on the operator subject for an operator id that does NOT exist:
    // project_wire_event gives it a wire form (the auto-disable wire name), but
    // resolve_owner cannot find the operator, so the owner is unresolvable. Without
    // the backstop this row would re-claim and re-fail forever.
    let phantom_operator = Uuid::now_v7();
    append_subject_event(
        &pool,
        "operator",
        &phantom_operator.to_string(),
        "webhook.endpoint_disabled",
        &json!({ "endpoint_id": Uuid::now_v7().to_string(), "reason": "stale" }),
    )
    .await
    .expect("append phantom operator event");

    // The drain processes it without error and stamps it fanned-out with no
    // deliveries.
    let processed = FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("the unresolvable row does not error the drain");
    assert_eq!(processed, 1, "the row was processed (not skipped over)");

    let (fanned, deliveries): (bool, i64) = sqlx::query_as(
        "SELECT o.fanned_out_at IS NOT NULL, \
                (SELECT count(*) FROM cw_core.webhook_delivery d WHERE d.outbox_id = o.id) \
         FROM cw_core.delivery_outbox o \
         WHERE o.subject_kind = 'operator' AND o.subject_id = $1",
    )
    .bind(phantom_operator.to_string())
    .fetch_one(&pool)
    .await
    .expect("outbox row");
    assert!(
        fanned,
        "the unresolvable row is terminally stamped fanned-out"
    );
    assert_eq!(deliveries, 0, "it produced zero deliveries");

    // A second drain never re-claims it (no wedge).
    let again = FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("second drain");
    assert_eq!(again, 0, "the stamped row is never re-scanned");
}
