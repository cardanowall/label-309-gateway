//! Conformance: durable SSE resume against a booted gateway.
//!
//! The published SDK is a read/quote/publish/verify client and deliberately does
//! NOT consume the SSE stream (the per-subject resume id is an additive gateway
//! feature an SDK ignores). So this leg drives the gateway's
//! `GET /api/v1/poe/events/{poe_id}` stream directly with a raw HTTP/1.1 client —
//! the same bytes a browser `EventSource` or a hand-rolled consumer would see —
//! and proves the durable-resume contract: disconnect mid-stream, reconnect with
//! `Last-Event-ID`, and exactly the missed events replay, none twice, none lost.
//!
//! Gated behind the `live` feature (it boots a gateway over a real database).

#![cfg(feature = "live")]

use std::time::Duration;

use conformance::BootedGateway;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// One parsed SSE frame: its event name, optional id, and JSON data.
#[derive(Debug, Clone)]
struct SseFrame {
    event: String,
    id: Option<String>,
    data: serde_json::Value,
}

/// A minimal raw-TCP SSE client that decodes HTTP/1.1 chunked framing into SSE
/// frames, so the assertions are over the literal bytes on the wire.
struct SseClient {
    stream: TcpStream,
    raw: Vec<u8>,
    body: String,
}

impl SseClient {
    /// Open `GET <path>` against `host:port` with the given headers.
    async fn open(addr: std::net::SocketAddr, path: &str, extra: &[(&str, &str)]) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut client = SseClient {
            stream,
            raw: Vec::new(),
            body: String::new(),
        };
        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n",
        );
        for (k, v) in extra {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        client
            .stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");
        loop {
            if let Some(idx) = find(&client.raw, b"\r\n\r\n") {
                client.raw.drain(..idx + 4);
                break;
            }
            client.read_more().await;
        }
        client
    }

    async fn read_more(&mut self) {
        let mut chunk = [0u8; 4096];
        let n = self.stream.read(&mut chunk).await.expect("read socket");
        assert!(n > 0, "the server closed the stream unexpectedly");
        self.raw.extend_from_slice(&chunk[..n]);
        self.decode_chunks();
    }

    fn decode_chunks(&mut self) {
        loop {
            let Some(line_end) = find(&self.raw, b"\r\n") else {
                return;
            };
            let size_line = String::from_utf8_lossy(&self.raw[..line_end]).to_string();
            let hex = size_line.split(';').next().unwrap_or("").trim();
            let Ok(size) = usize::from_str_radix(hex, 16) else {
                return;
            };
            let chunk_start = line_end + 2;
            let chunk_end = chunk_start + size;
            if self.raw.len() < chunk_end + 2 {
                return;
            }
            let data = &self.raw[chunk_start..chunk_end];
            self.body
                .push_str(std::str::from_utf8(data).expect("utf-8 chunk"));
            self.raw.drain(..chunk_end + 2);
            if size == 0 {
                return;
            }
        }
    }

    async fn next_frame(&mut self) -> SseFrame {
        loop {
            if let Some(frame) = self.take_frame() {
                return frame;
            }
            tokio::time::timeout(Duration::from_secs(20), self.read_more())
                .await
                .expect("a frame should arrive before the timeout");
        }
    }

    /// Read frames until one with the given event name, skipping keep-alive pings.
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
            serde_json::Value::Null
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

/// Find the first index of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A minimal open Label 309 record (the subject the SSE stream rides).
fn open_record(seed: u8) -> Vec<u8> {
    use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};
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

/// Disconnect mid-stream, reconnect with `Last-Event-ID`, and prove exactly the
/// missed events replay: none lost, none duplicated.
#[tokio::test(flavor = "multi_thread")]
async fn sse_resumes_exactly_the_missed_events() {
    let gw = BootedGateway::start().await.expect("boot the gateway");
    let tenant = gw
        .seed_tenant("ck_live_", &["poe:read"], 0)
        .await
        .expect("seed a tenant");

    // A record subject with no events yet, addressed by its wire id.
    let record = open_record(0xc3);
    let record_id = gw.seed_record(&tenant, &record).await.expect("seed record");
    let wire_id = encode_poe_id(record_id);
    let addr: std::net::SocketAddr = gw
        .base_url
        .trim_start_matches("http://")
        .parse()
        .expect("parse the booted address");
    let bearer = format!("Bearer {}", tenant.api_key);
    let path = format!("/api/v1/poe/events/{wire_id}");

    // Append four events BEFORE connecting, so the initial state's high-water is 4.
    for i in 1..=4 {
        gw.append_poe_event(
            record_id,
            "submitted",
            serde_json::json!({ "status": "confirming", "n": i }),
        )
        .await
        .expect("append pre-connect event");
    }

    // First connection: the initial `state` event carries the current high-water
    // sequence (4) as its id. The client then disconnects (drops the socket).
    {
        eprintln!("CHECKPOINT: opening first connection");
        let mut c = SseClient::open(addr, &path, &[("Authorization", &bearer)]).await;
        let state = c.next_named("state").await;
        assert_eq!(
            state.id.as_deref(),
            Some("4"),
            "the initial state id is the subject's high-water sequence"
        );
        // Drop the connection here (c goes out of scope), simulating a mid-stream
        // disconnect after the client has seen up through sequence 4.
    }

    // While disconnected, two more events land (sequences 5 and 6).
    let seq5 = gw
        .append_poe_event(
            record_id,
            "confirmed",
            serde_json::json!({ "status": "confirmed", "n": 5 }),
        )
        .await
        .expect("append seq 5");
    let seq6 = gw
        .append_poe_event(
            record_id,
            "confirmed",
            serde_json::json!({ "status": "confirmed", "n": 6 }),
        )
        .await
        .expect("append seq 6");
    assert_eq!((seq5, seq6), (5, 6), "the two missed events are 5 and 6");

    // Reconnect with Last-Event-ID: 4. Resume must replay exactly 5 then 6.
    let mut c = SseClient::open(
        addr,
        &path,
        &[("Authorization", &bearer), ("Last-Event-ID", "4")],
    )
    .await;
    // The reconnect still sends an initial state (its id is the new high-water, 6).
    let state = c.next_named("state").await;
    assert_eq!(
        state.id.as_deref(),
        Some("6"),
        "the resumed state id is the new high-water sequence"
    );

    // The next non-ping events are exactly the missed ones, in order, once each:
    // no event is lost across the disconnect and none is replayed twice.
    let first = c.next_named("poe_status_changed").await;
    assert_eq!(first.id.as_deref(), Some("5"), "resume replays seq 5 first");
    // The payload is re-projected from the record's CURRENT row (not the durable
    // event delta), so every replayed event carries the record's live wire id and
    // status. The seeded record is still `submitting`.
    assert_eq!(
        first.data.get("id").and_then(|v| v.as_str()),
        Some(wire_id.as_str()),
        "the replayed event carries the record's wire id"
    );
    assert_eq!(
        first.data.get("status").and_then(|v| v.as_str()),
        Some("submitting"),
        "the replayed event re-projects the record's current status"
    );
    let second = c.next_named("poe_status_changed").await;
    assert_eq!(
        second.id.as_deref(),
        Some("6"),
        "resume replays seq 6 next, exactly once"
    );
    assert_eq!(
        second.data.get("id").and_then(|v| v.as_str()),
        Some(wire_id.as_str()),
        "the second replayed event likewise carries the wire id"
    );

    // Disconnect before tearing the gateway down so the server-side stream ends
    // and the pool drains cleanly.
    drop(c);
    gw.shutdown().await;
}

/// Encode a UUID to its `poe_<crockford>` wire id (the codec the gateway uses).
fn encode_poe_id(id: uuid::Uuid) -> String {
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("0123456789abcdefghjkmnpqrstvwxyz");
    let encoding = spec.encoding().expect("valid crockford spec");
    format!("poe_{}", encoding.encode(id.as_bytes()))
}
