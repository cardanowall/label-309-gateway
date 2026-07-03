//! End-to-end tests for the durable, resumable SSE streams.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test boots the real data-plane router over a `TestDb`, seeds an
//! operator/account/api-key directly, then drives the SSE endpoint with a raw
//! HTTP/1.1 client so the assertions are over the actual bytes on the wire (the
//! `event:`/`id:`/`data:` frames a published SDK parses).
//!
//! The streams ride the durable `cw_core.subject_event` log, so the tests append
//! events with the engine's own `append_subject_event` (the same call the chain
//! and ledger paths use) and assert they surface on the stream in sequence order,
//! with the correct wire event name and a payload reprojected from the current
//! DB row. Disconnect + reconnect with `Last-Event-ID` proves the resume contract:
//! exactly the missed events replay, none twice.

#![cfg(feature = "pg-tests")]

use std::time::Duration;

use gateway_core::api::middleware::auth::hash_secret;
use gateway_core::api::{router, ApiConfig, AppState};
use gateway_core::events::append_subject_event;
use gateway_core::testsupport::TestDb;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// The outer deadline on any single wait for stream bytes (response headers or
/// the next frame). Generous on purpose: the product promises progress within
/// its 5-second poll-fallback interval even when every NOTIFY wake-hint is
/// lost, so the deadline asserts liveness with a wide margin for a loaded
/// machine rather than timing the product.
const STREAM_DEADLINE: Duration = Duration::from_secs(20);

/// Find the first index of `needle` in `haystack`, byte-wise.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// One parsed SSE frame: its `event:` name, optional `id:`, and `data:` payload
/// parsed as JSON.
#[derive(Debug, Clone)]
struct SseFrame {
    event: String,
    id: Option<String>,
    data: Value,
}

/// A minimal raw-TCP SSE client.
///
/// axum streams an SSE response with HTTP/1.1 chunked transfer-encoding, so the
/// client decodes the chunk framing off the socket into a plain SSE-text buffer
/// and then parses `event:`/`id:`/`data:` frames out of that. Keeping the two
/// layers separate is what makes frame parsing robust regardless of where a chunk
/// boundary happens to fall.
struct SseClient {
    stream: TcpStream,
    /// Raw bytes read off the socket, still chunk-framed.
    raw: Vec<u8>,
    /// Decoded SSE body text, chunk framing removed.
    body: String,
}

impl SseClient {
    /// Open `GET <path>` against the server with the given headers, returning a
    /// client positioned at the first body byte (response headers consumed).
    async fn open(addr: std::net::SocketAddr, path: &str, extra_headers: &[(&str, &str)]) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut client = SseClient {
            stream,
            raw: Vec::new(),
            body: String::new(),
        };

        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n",
        );
        for (k, v) in extra_headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        client
            .stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");

        // Consume up to the end of the response headers. Whatever chunk-framed
        // body bytes arrived in the same read stay in the raw buffer.
        let header_end = loop {
            if let Some(idx) = find(&client.raw, b"\r\n\r\n") {
                break idx;
            }
            tokio::time::timeout(STREAM_DEADLINE, client.read_more())
                .await
                .expect("response headers should arrive before the deadline");
        };
        // Every caller expects a live stream, so a non-200 (a problem response
        // whose JSON body carries no SSE frames) must fail HERE, naming the
        // status and headers — not minutes later as an opaque frame timeout.
        let head = String::from_utf8_lossy(&client.raw[..header_end]).to_string();
        client.raw.drain(..header_end + 4);
        let status: Option<u16> = head.split_whitespace().nth(1).and_then(|s| s.parse().ok());
        assert_eq!(
            status,
            Some(200),
            "the stream open must succeed; response head: {head:?}"
        );
        client
    }

    /// Read another chunk of bytes off the socket into the raw buffer, then
    /// decode as much chunk-framed body as is now complete into the SSE body text.
    async fn read_more(&mut self) {
        let mut chunk = [0u8; 4096];
        let n = self.stream.read(&mut chunk).await.expect("read socket");
        assert!(n > 0, "the server closed the stream unexpectedly");
        self.raw.extend_from_slice(&chunk[..n]);
        self.decode_chunks();
    }

    /// Drain every complete HTTP/1.1 chunk from the raw buffer into the decoded
    /// SSE body. A partial trailing chunk is left in place for the next read.
    fn decode_chunks(&mut self) {
        loop {
            // A chunk is `<hex-size>\r\n<size bytes>\r\n`.
            let Some(line_end) = find(&self.raw, b"\r\n") else {
                return; // size line not fully arrived yet.
            };
            let size_line = String::from_utf8_lossy(&self.raw[..line_end]).to_string();
            // The size may carry chunk extensions after a ';'; ignore them.
            let hex = size_line.split(';').next().unwrap_or("").trim();
            let Ok(size) = usize::from_str_radix(hex, 16) else {
                return; // not a valid size line yet (partial read).
            };
            let chunk_start = line_end + 2;
            let chunk_end = chunk_start + size;
            // Need the chunk body plus its trailing CRLF.
            if self.raw.len() < chunk_end + 2 {
                return; // chunk body not fully arrived yet.
            }
            let data = &self.raw[chunk_start..chunk_end];
            self.body
                .push_str(std::str::from_utf8(data).expect("utf-8 chunk"));
            self.raw.drain(..chunk_end + 2);
            if size == 0 {
                return; // terminal chunk.
            }
        }
    }

    /// Yield the next SSE frame, reading from the socket until a blank-line frame
    /// terminator is seen. Panics if no frame arrives within [`STREAM_DEADLINE`]
    /// (the poll fallback guarantees progress well inside it, hint or no hint).
    async fn next_frame(&mut self) -> SseFrame {
        loop {
            if let Some(frame) = self.take_frame() {
                return frame;
            }
            tokio::time::timeout(STREAM_DEADLINE, self.read_more())
                .await
                .expect("a frame should arrive before the timeout");
        }
    }

    /// Read frames until one with the given event name is seen, skipping pings.
    async fn next_named(&mut self, name: &str) -> SseFrame {
        loop {
            let frame = self.next_frame().await;
            if frame.event == name {
                return frame;
            }
            assert_eq!(
                frame.event, "ping",
                "unexpected interleaved event {:?} while waiting for {name}",
                frame.event
            );
        }
    }

    /// Pull one complete frame out of the decoded body if a terminator is present.
    fn take_frame(&mut self) -> Option<SseFrame> {
        let term = self.body.find("\n\n")?;
        let raw: String = self.body.drain(..term + 2).collect();

        let mut event = "message".to_string();
        let mut id = None;
        let mut data = String::new();
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                event = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("id:") {
                id = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(rest.trim_start());
            }
        }
        let parsed = if data.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&data).expect("data is JSON")
        };
        Some(SseFrame {
            event,
            id,
            data: parsed,
        })
    }
}

/// Boot the data-plane router over a fresh DB on an ephemeral port, returning the
/// bound address (the server task runs detached for the test's lifetime).
async fn serve(state: AppState) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

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

/// Issue an api-key for an account with the given scopes; returns the bearer
/// secret to present. The secret is hashed the same way the auth path expects.
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

/// Seed a PoE record owned by an operator/account and return its id.
async fn seed_record(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
    status: &str,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, account_id, record_bytes, status, request_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(account_id)
    .bind(vec![0xa1u8, 0x01, 0x02])
    .bind(status)
    .bind("req-seed")
    .execute(pool)
    .await
    .expect("insert poe record");
    id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poe_stream_opens_with_the_record_snapshot_then_streams_events_in_order() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let secret = issue_key(&db.pool, account_id, &["poe:read"]).await;
    let record_id = seed_record(&db.pool, operator_id, account_id, "submitting").await;
    let wire_id = gateway_core::api::ids::encode_poe_id(record_id);

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;
    let mut client = SseClient::open(
        addr,
        &format!("/api/v1/poe/events/{wire_id}"),
        &[("Authorization", &format!("Bearer {secret}"))],
    )
    .await;

    // The initial state event reflects the seeded row: a submitting record
    // projects to the wire status `submitting` and carries the wire id.
    let state = client.next_named("state").await;
    assert_eq!(state.data["id"], json!(wire_id));
    assert_eq!(
        state.data["status"],
        json!("submitting"),
        "engine submitting projects to the wire status submitting"
    );
    assert_eq!(state.data["num_confirmations"], json!(0));
    // No events yet, so the state id is the zero high-water mark.
    assert_eq!(state.id.as_deref(), Some("0"));

    // Append two status events; they must arrive in sequence order with the
    // status-change wire name.
    append_subject_event(
        &db.pool,
        "poe_record",
        &record_id.to_string(),
        "submitted",
        &json!({ "tx_hash": "ab".repeat(32) }),
    )
    .await
    .expect("append submitted");

    let first = client.next_named("poe_status_changed").await;
    assert_eq!(
        first.id.as_deref(),
        Some("1"),
        "first event is subject_seq 1"
    );

    // Flip the record to confirmed and append the confirmed event; the payload is
    // reprojected from the current row, so the wire status is now `confirmed`.
    sqlx::query("UPDATE cw_core.poe_record SET status = 'confirmed' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("flip confirmed");
    append_subject_event(
        &db.pool,
        "poe_record",
        &record_id.to_string(),
        "confirmed",
        &json!({ "block_height": 100 }),
    )
    .await
    .expect("append confirmed");

    let second = client.next_named("poe_status_changed").await;
    assert_eq!(
        second.id.as_deref(),
        Some("2"),
        "second event is subject_seq 2"
    );
    assert_eq!(
        second.data["status"],
        json!("confirmed"),
        "the event payload reprojects the current row's status"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poe_stream_projects_a_terminal_submit_failure_to_a_submission_failed_event() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let secret = issue_key(&db.pool, account_id, &["poe:read"]).await;
    let record_id = seed_record(&db.pool, operator_id, account_id, "submitting").await;
    let wire_id = gateway_core::api::ids::encode_poe_id(record_id);

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;
    let mut client = SseClient::open(
        addr,
        &format!("/api/v1/poe/events/{wire_id}"),
        &[("Authorization", &format!("Bearer {secret}"))],
    )
    .await;
    let _ = client.next_named("state").await;

    // A permanent_failure carrying a terminal submit reason projects to the
    // submission-failed wire event, not the generic status change.
    append_subject_event(
        &db.pool,
        "poe_record",
        &record_id.to_string(),
        "permanent_failure",
        &json!({ "reason": "tx_build_failed" }),
    )
    .await
    .expect("append failure");

    let frame = client.next_named("cardano_submission_failed").await;
    assert_eq!(
        frame.event, "cardano_submission_failed",
        "a terminal submit reason projects to the submission-failed event name"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poe_stream_skips_the_operator_only_refund_intent_and_emits_no_duplicate_frame() {
    // A terminal record failure appends two PoE-subject events back to back: a
    // `poe.refund-intent` (an operator-only billing-hook event) at seq N, then a
    // `permanent_failure` at seq N+1. The account-grade SSE stream must skip the
    // refund-intent entirely (it is not visible to an account reader) and surface
    // exactly ONE frame for the failure, not a duplicate pair.
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let secret = issue_key(&db.pool, account_id, &["poe:read"]).await;
    let record_id = seed_record(&db.pool, operator_id, account_id, "submitting").await;
    let wire_id = gateway_core::api::ids::encode_poe_id(record_id);

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;
    let mut client = SseClient::open(
        addr,
        &format!("/api/v1/poe/events/{wire_id}"),
        &[("Authorization", &format!("Bearer {secret}"))],
    )
    .await;
    let _ = client.next_named("state").await;

    // Flip to permanent_failure and append the refund-intent (seq 1) then the
    // permanent_failure (seq 2), exactly as the terminalization path does.
    sqlx::query("UPDATE cw_core.poe_record SET status = 'permanent_failure' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("flip permanent_failure");
    append_subject_event(
        &db.pool,
        "poe_record",
        &record_id.to_string(),
        "poe.refund-intent",
        &json!({ "reason": "rollback_retries_exhausted" }),
    )
    .await
    .expect("append refund-intent");
    append_subject_event(
        &db.pool,
        "poe_record",
        &record_id.to_string(),
        "permanent_failure",
        &json!({ "reason": "rollback_retries_exhausted" }),
    )
    .await
    .expect("append permanent_failure");

    // The first surfaced frame is the permanent_failure (seq 2). The refund-intent
    // at seq 1 was skipped, so its sequence never appears on the wire.
    let failure = client.next_named("poe_status_changed").await;
    assert_eq!(
        failure.id.as_deref(),
        Some("2"),
        "the only surfaced frame is the permanent_failure at seq 2; the refund-intent at seq 1 is skipped"
    );
    assert_eq!(
        failure.data["status"],
        json!("failed"),
        "the failure frame reprojects the current row to the failed wire status"
    );

    // Append a sentinel status event (seq 3). If the refund-intent had leaked a
    // duplicate poe_status_changed at seq 1, the next surfaced frame would be that
    // duplicate, not the sentinel. Asserting the next frame is exactly seq 3 proves
    // no duplicate frame was emitted for the one logical failure.
    append_subject_event(
        &db.pool,
        "poe_record",
        &record_id.to_string(),
        "confirmed",
        &json!({ "sentinel": true }),
    )
    .await
    .expect("append sentinel");
    let sentinel = client.next_named("poe_status_changed").await;
    assert_eq!(
        sentinel.id.as_deref(),
        Some("3"),
        "the next frame after the single failure frame is the sentinel at seq 3, proving no duplicate was emitted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_stream_upload_failure_carries_the_upload_identity_not_a_balance() {
    // A storage.upload.failed event rides the account subject. Its wire `data` must
    // carry the failed upload's identity (the keys the client needs to re-send it),
    // not a balance snapshot, and it surfaces under its own wire event name.
    let db = TestDb::fresh().await.expect("fresh db");
    let (_operator_id, account_id) = seed_account(&db.pool).await;
    let secret = issue_key(&db.pool, account_id, &["account:read"]).await;

    sqlx::query("INSERT INTO cw_core.balance (account_id, balance_micros) VALUES ($1, 5000000)")
        .bind(account_id)
        .execute(&db.pool)
        .await
        .expect("seed balance");

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;
    let mut client = SseClient::open(
        addr,
        "/api/v1/account/balance/events",
        &[("Authorization", &format!("Bearer {secret}"))],
    )
    .await;
    let _ = client.next_named("state").await;

    let attempt_id = Uuid::now_v7();
    let sha256 = "ab".repeat(32);
    append_subject_event(
        &db.pool,
        "account",
        &account_id.to_string(),
        "storage.upload.failed",
        &json!({
            "attempt_id": attempt_id,
            "sha256": sha256,
            "bytes": 4096,
            "backend": "turbo",
            "reason": "backend_rejected",
        }),
    )
    .await
    .expect("append upload failure");

    let frame = client.next_named("storage_upload_failed").await;
    assert_eq!(
        frame.data["attempt_id"],
        json!(attempt_id.to_string()),
        "the upload-failure frame carries the attempt id to re-send"
    );
    assert_eq!(frame.data["sha256"], json!(sha256));
    assert_eq!(frame.data["bytes"], json!(4096));
    assert_eq!(frame.data["backend"], json!("turbo"));
    assert_eq!(frame.data["reason"], json!("backend_rejected"));
    assert!(
        frame.data.get("balance_usd_micros").is_none(),
        "the upload-failure frame is the upload identity, not a balance snapshot"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poe_stream_resumes_exactly_the_missed_events_with_last_event_id() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let secret = issue_key(&db.pool, account_id, &["poe:read"]).await;
    let record_id = seed_record(&db.pool, operator_id, account_id, "submitting").await;
    let wire_id = gateway_core::api::ids::encode_poe_id(record_id);

    // Append three events BEFORE the first connection: a fresh connect starts at
    // the current high-water mark, so it streams none of them live.
    for n in 1..=3 {
        append_subject_event(
            &db.pool,
            "poe_record",
            &record_id.to_string(),
            "submitted",
            &json!({ "n": n }),
        )
        .await
        .expect("append");
    }

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;

    // First connection: the state event's id is the high-water mark (3). Then a
    // fourth event arrives live.
    let path = format!("/api/v1/poe/events/{wire_id}");
    let bearer = format!("Bearer {secret}");
    {
        let mut client = SseClient::open(addr, &path, &[("Authorization", &bearer)]).await;
        let state = client.next_named("state").await;
        assert_eq!(
            state.id.as_deref(),
            Some("3"),
            "the initial state id is the current high-water sequence"
        );

        append_subject_event(
            &db.pool,
            "poe_record",
            &record_id.to_string(),
            "confirmed",
            &json!({ "n": 4 }),
        )
        .await
        .expect("append 4");
        let live = client.next_named("poe_status_changed").await;
        assert_eq!(live.id.as_deref(), Some("4"));
        // Drop the client: simulate a disconnect after seeing seq 4.
    }

    // While disconnected, two more events land (seq 5 and 6).
    for n in 5..=6 {
        append_subject_event(
            &db.pool,
            "poe_record",
            &record_id.to_string(),
            "confirmed",
            &json!({ "n": n }),
        )
        .await
        .expect("append while disconnected");
    }

    // Reconnect with Last-Event-ID: 4. A reconnecting client presents a fresh
    // credential (a realistic rotation, and it keeps the resume assertion focused
    // on the durable event log rather than on a single key's limiter window). The
    // stream must replay exactly seq 5 then 6 (the missed events), none twice and
    // none skipped.
    let secret2 = issue_key(&db.pool, account_id, &["poe:read"]).await;
    let bearer2 = format!("Bearer {secret2}");
    let mut client = SseClient::open(
        addr,
        &path,
        &[("Authorization", &bearer2), ("Last-Event-ID", "4")],
    )
    .await;
    // The state event still comes first; its id is the new high-water mark (6).
    let state = client.next_named("state").await;
    assert_eq!(state.id.as_deref(), Some("6"));

    let replay_5 = client.next_named("poe_status_changed").await;
    assert_eq!(
        replay_5.id.as_deref(),
        Some("5"),
        "resume replays seq 5 first"
    );
    let replay_6 = client.next_named("poe_status_changed").await;
    assert_eq!(
        replay_6.id.as_deref(),
        Some("6"),
        "then seq 6, exactly once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn balance_stream_opens_with_the_balance_and_streams_changes() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (_operator_id, account_id) = seed_account(&db.pool).await;
    let secret = issue_key(&db.pool, account_id, &["account:read"]).await;

    // Seed an opening balance row so the snapshot is non-zero.
    sqlx::query("INSERT INTO cw_core.balance (account_id, balance_micros) VALUES ($1, 5000000)")
        .bind(account_id)
        .execute(&db.pool)
        .await
        .expect("seed balance");

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;
    let mut client = SseClient::open(
        addr,
        "/api/v1/account/balance/events",
        &[("Authorization", &format!("Bearer {secret}"))],
    )
    .await;

    // The initial state carries the balance as a decimal STRING (precision past
    // 2^53 must survive, so never a JSON number).
    let state = client.next_named("state").await;
    assert_eq!(state.data["balance_usd_micros"], json!("5000000"));

    // A balance-changed event re-reads the (now lower) balance and carries the
    // signed change the triggering ledger entry recorded.
    sqlx::query("UPDATE cw_core.balance SET balance_micros = 4000000 WHERE account_id = $1")
        .bind(account_id)
        .execute(&db.pool)
        .await
        .expect("debit");
    append_subject_event(
        &db.pool,
        "account",
        &account_id.to_string(),
        "balance.changed",
        &json!({ "kind": "publish_debit", "amount_micros": -1000000 }),
    )
    .await
    .expect("append balance event");

    let frame = client.next_named("balance_changed").await;
    assert_eq!(frame.data["balance_usd_micros"], json!("4000000"));
    assert_eq!(
        frame.data["change_usd_micros"],
        json!("-1000000"),
        "the change is surfaced as a decimal string from the ledger entry amount"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poe_stream_rejects_a_missing_credential() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let record_id = seed_record(&db.pool, operator_id, account_id, "submitting").await;
    let wire_id = gateway_core::api::ids::encode_poe_id(record_id);

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;

    // No Authorization header: the response is a 401 problem, not a stream.
    let stream = TcpStream::connect(addr).await.expect("connect");
    let (status, _body) =
        read_full_response(stream, &format!("/api/v1/poe/events/{wire_id}")).await;
    assert_eq!(status, 401, "an unauthenticated stream request is rejected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poe_stream_404s_for_a_record_owned_by_another_account() {
    // A `poe_record` is account-owned engine state, not public chain data. A viewer
    // holding `poe:read` who supplies a poe_id belonging to ANOTHER account must get
    // an oracle-safe 404 (indistinguishable from a missing record), never a stream of
    // that record's status, tx hash, and event log.
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_a) = seed_account(&db.pool).await;
    // Account B is a second account under the same operator; it holds poe:read but
    // does not own account A's record.
    let account_b = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_b)
        .execute(&db.pool)
        .await
        .expect("insert account B anchor");
    sqlx::query(
        "INSERT INTO cw_core.account_detail (account_id, operator_id, status) \
         VALUES ($1, $2, 'active')",
    )
    .bind(account_b)
    .bind(operator_id)
    .execute(&db.pool)
    .await
    .expect("insert account B detail");
    let secret_b = issue_key(&db.pool, account_b, &["poe:read"]).await;

    // The record is owned by account A.
    let record_id = seed_record(&db.pool, operator_id, account_a, "submitting").await;
    let wire_id = gateway_core::api::ids::encode_poe_id(record_id);

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;
    // Account B opens the stream for account A's record: it must be a 404, not a
    // stream.
    let stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "GET /api/v1/poe/events/{wire_id} HTTP/1.1\r\nHost: localhost\r\n\
         Authorization: Bearer {secret_b}\r\nConnection: close\r\n\r\n",
    );
    let (status, _body) = send_and_read(stream, &req).await;
    assert_eq!(
        status, 404,
        "a viewer cannot stream a PoE record owned by another account; it is an oracle-safe 404"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poe_stream_404s_for_an_unknown_record() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (_operator_id, account_id) = seed_account(&db.pool).await;
    let secret = issue_key(&db.pool, account_id, &["poe:read"]).await;
    // A well-formed wire id for a record that does not exist.
    let wire_id = gateway_core::api::ids::encode_poe_id(Uuid::now_v7());

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;
    let stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "GET /api/v1/poe/events/{wire_id} HTTP/1.1\r\nHost: localhost\r\n\
         Authorization: Bearer {secret}\r\nConnection: close\r\n\r\n",
    );
    let (status, _body) = send_and_read(stream, &req).await;
    assert_eq!(
        status, 404,
        "a stream for an unknown record is a 404 before the stream opens"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_water_read_failure_closes_the_stream_without_replaying_history() {
    // A high-water read failure must NOT silently reset the resume floor to seq 0 and
    // replay the subject's entire event history. With the durable event log
    // unavailable, a fresh connection ends rather than emitting a `state` id of 0 and
    // streaming every prior event back from seq 1.
    let db = TestDb::fresh().await.expect("fresh db");
    let (_operator_id, account_id) = seed_account(&db.pool).await;
    let secret = issue_key(&db.pool, account_id, &["account:read"]).await;

    // Seed history on the account subject: if the bug were present, a high-water
    // failure would replay all of these from seq 1.
    for n in 1..=3 {
        append_subject_event(
            &db.pool,
            "account",
            &account_id.to_string(),
            "balance.changed",
            &json!({ "amount_micros": n }),
        )
        .await
        .expect("seed history");
    }

    // Make the durable event log unavailable, modelling a transient DB failure on the
    // high-water read. The balance stream's first action after connect is the
    // high-water query, so this fails it.
    sqlx::query("ALTER TABLE cw_core.subject_event RENAME TO subject_event_unavailable")
        .execute(&db.pool)
        .await
        .expect("simulate a transient subject_event outage");

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;

    // The connection opens (200 headers), but the body ends immediately: no `state`
    // frame, and crucially no replay of the seeded history. The stream terminates
    // rather than defaulting the resume floor to 0. `Connection: close` makes the
    // server close the socket once the (empty) body is flushed, so the reader reaches
    // EOF instead of blocking on a reusable keep-alive connection.
    let stream = TcpStream::connect(addr).await.expect("connect");
    let req = "GET /api/v1/account/balance/events HTTP/1.1\r\nHost: localhost\r\n\
         Accept: text/event-stream\r\nConnection: close\r\nAuthorization: Bearer "
        .to_string()
        + &secret
        + "\r\n\r\n";
    let (status, body) = send_and_read(stream, &req).await;
    assert_eq!(
        status, 200,
        "the SSE response headers are sent before the body"
    );
    assert!(
        !body.contains("event: state") && !body.contains("event:state"),
        "a high-water read failure emits no fabricated state frame; got body: {body:?}"
    );
    assert!(
        !body.contains("balance_changed"),
        "a high-water read failure never replays the subject's event history; got body: {body:?}"
    );

    // Restore the table so the test DB is left clean for sibling suites.
    sqlx::query("ALTER TABLE cw_core.subject_event_unavailable RENAME TO subject_event")
        .execute(&db.pool)
        .await
        .expect("restore the subject_event table");
}

/// Send a bare `GET <path>` with `Connection: close` and read the whole response
/// (status code + body). For the non-streaming error paths only.
async fn read_full_response(stream: TcpStream, path: &str) -> (u16, String) {
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",);
    send_and_read(stream, &req).await
}

/// Write a full request and read the entire response until the socket closes.
async fn send_and_read(mut stream: TcpStream, req: &str) -> (u16, String) {
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .expect("read within timeout")
            .expect("read");
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .expect("status code");
    (status, text)
}

/// Open `GET <path>` with a bearer and return only the response status code,
/// dropping the connection immediately. For cap probes: a 200 is a live stream
/// whose slot frees again the moment this socket drops; a 429 is the cap.
async fn open_stream_status(addr: std::net::SocketAddr, path: &str, secret: &str) -> u16 {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n\
         Authorization: Bearer {secret}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(idx) = find(&raw, b"\r\n") {
            let line = String::from_utf8_lossy(&raw[..idx]).to_string();
            return line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .expect("status code");
        }
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .expect("status line within timeout")
            .expect("read");
        assert!(n > 0, "server closed before a status line");
        raw.extend_from_slice(&chunk[..n]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_instance_stream_cap_rejects_beyond_the_limit_and_frees_on_disconnect() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (_op_a, account_a) = seed_account(&db.pool).await;
    let (_op_b, account_b) = seed_account(&db.pool).await;
    let secret_a = issue_key(&db.pool, account_a, &["account:read"]).await;
    let secret_b = issue_key(&db.pool, account_b, &["account:read"]).await;

    // One live stream for the whole instance.
    let config = ApiConfig {
        sse_limits: gateway_core::api::SseLimits {
            max_streams: 1,
            max_streams_per_account: 1,
        },
        ..ApiConfig::default()
    };
    let addr = serve(AppState::new(db.pool.clone(), config)).await;

    // The first stream takes the only slot (the state frame proves it is live).
    let mut live = SseClient::open(
        addr,
        "/api/v1/account/balance/events",
        &[("Authorization", &format!("Bearer {secret_a}"))],
    )
    .await;
    let state = live.next_named("state").await;
    assert_eq!(state.data["balance_usd_micros"], json!("0"));

    // A DIFFERENT account is refused: its own per-account budget is untouched,
    // so this is the instance-wide ceiling.
    let refused = open_stream_status(addr, "/api/v1/account/balance/events", &secret_b).await;
    assert_eq!(refused, 429, "the instance cap refuses the second stream");

    // Dropping the live stream frees its slot on the disconnect path: a fresh
    // open succeeds once the server observes the drop.
    drop(live);
    let mut reopened = 0u16;
    for _ in 0..50 {
        reopened = open_stream_status(addr, "/api/v1/account/balance/events", &secret_b).await;
        if reopened == 200 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(reopened, 200, "the dropped stream's slot was released");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_per_account_stream_cap_binds_one_account_without_starving_another() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (_op_a, account_a) = seed_account(&db.pool).await;
    let (_op_b, account_b) = seed_account(&db.pool).await;
    let secret_a = issue_key(&db.pool, account_a, &["account:read"]).await;
    let secret_b = issue_key(&db.pool, account_b, &["account:read"]).await;

    // Plenty of instance headroom; one live stream per account.
    let config = ApiConfig {
        sse_limits: gateway_core::api::SseLimits {
            max_streams: 10,
            max_streams_per_account: 1,
        },
        ..ApiConfig::default()
    };
    let addr = serve(AppState::new(db.pool.clone(), config)).await;

    let mut live = SseClient::open(
        addr,
        "/api/v1/account/balance/events",
        &[("Authorization", &format!("Bearer {secret_a}"))],
    )
    .await;
    let _ = live.next_named("state").await;

    // The same account's second stream trips ITS cap…
    let refused = open_stream_status(addr, "/api/v1/account/balance/events", &secret_a).await;
    assert_eq!(
        refused, 429,
        "the per-account cap refuses the second stream"
    );

    // …while another account, under the same instance, still opens freely.
    let other = open_stream_status(addr, "/api/v1/account/balance/events", &secret_b).await;
    assert_eq!(other, 200, "one account's cap never starves another");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sse_streams_outlive_the_ordinary_request_timeout() {
    let db = TestDb::fresh().await.expect("fresh db");
    let (operator_id, account_id) = seed_account(&db.pool).await;
    let secret = issue_key(&db.pool, account_id, &["poe:read"]).await;
    let record_id = seed_record(&db.pool, operator_id, account_id, "submitting").await;
    let wire_id = gateway_core::api::ids::encode_poe_id(record_id);

    // An aggressive ordinary-request ceiling: if the timeout layer covered the
    // SSE routes, the stream would be cut off long before the event below.
    let config = ApiConfig {
        request_timeout: Duration::from_millis(300),
        ..ApiConfig::default()
    };
    let addr = serve(AppState::new(db.pool.clone(), config)).await;

    let mut client = SseClient::open(
        addr,
        &format!("/api/v1/poe/events/{wire_id}"),
        &[("Authorization", &format!("Bearer {secret}"))],
    )
    .await;
    let _ = client.next_named("state").await;

    // Hold the stream well past the request ceiling, then prove it still
    // delivers: the streaming surfaces are exempt by construction.
    tokio::time::sleep(Duration::from_millis(900)).await;
    append_subject_event(
        &db.pool,
        "poe_record",
        &record_id.to_string(),
        "submitted",
        &json!({ "tx_hash": "cd".repeat(32) }),
    )
    .await
    .expect("append event");
    let frame = client.next_named("poe_status_changed").await;
    assert_eq!(frame.id.as_deref(), Some("1"));
}
