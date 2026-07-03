//! The harness-local webhook receiver sink.
//!
//! A webhook receiver is inherently harness-local: the conformance suite must
//! observe what the gateway delivered, so it stands up a loopback HTTP sink and
//! asserts on the requests that arrive. This module is that sink — a small,
//! dependency-light HTTP/1.1 receiver running on a background thread that records
//! every delivery (its headers and body) and answers each with a scripted status.
//!
//! It implements the documented receiver contract so the suite can prove the
//! signed-payload chain end to end:
//!
//!   - it parses `Webhook-Id`, `Webhook-Timestamp`, and `Webhook-Signature`;
//!   - it recomputes `HMAC_SHA256(secret, "{id}.{t}.{body}")` for each secret it
//!     holds and accepts on any constant-time match (the dual-sign rotation
//!     contract), exactly the Standard-Webhooks signed content;
//!   - in **strict-verify** mode it rejects a delivery whose signature does not
//!     validate (returning a non-2xx the gateway treats as a transient failure),
//!     proving the signature is actually enforced (W12);
//!   - in **redirect** mode it answers a 30x toward a second URL, so the suite can
//!     prove the hardened egress does NOT follow a redirect toward a private IP
//!     (W13).
//!
//! Because it never decodes the wire envelope semantically (it only verifies the
//! MAC and records the bytes), it is transport-agnostic and reusable across every
//! webhook scenario.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// One received delivery: the parsed headers and the raw body bytes.
#[derive(Clone, Debug)]
pub struct Received {
    /// Lowercased header name to value (last wins on a repeat, which the webhook
    /// header set never produces).
    pub headers: HashMap<String, String>,
    /// The exact request body bytes, signed verbatim by the gateway.
    pub body: String,
}

impl Received {
    /// The value of a header by name (case-insensitive), if present.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// The `Webhook-Id` header value (the per-delivery dedupe key).
    #[must_use]
    pub fn webhook_id(&self) -> Option<&str> {
        self.header("webhook-id")
    }

    /// The `Webhook-Timestamp` header value parsed as Unix seconds, if present and
    /// numeric.
    #[must_use]
    pub fn timestamp(&self) -> Option<i64> {
        self.header("webhook-timestamp")?.parse().ok()
    }

    /// The `v1=` MAC values parsed out of the `Webhook-Signature` header
    /// (`t=…,v1=…[,v1=…]`).
    #[must_use]
    pub fn signature_v1s(&self) -> Vec<String> {
        let Some(sig) = self.header("webhook-signature") else {
            return Vec::new();
        };
        sig.split(',')
            .filter_map(|p| p.strip_prefix("v1="))
            .map(str::to_string)
            .collect()
    }

    /// Whether this delivery's signature validates under any of `secrets`,
    /// recomputing `HMAC_SHA256(secret, "{id}.{t}.{body}")` over the delivered
    /// `Webhook-Id` and comparing constant-time against each `v1`. This is exactly
    /// the Standard-Webhooks receiver verification step; the suite calls it to
    /// assert a valid signature arrived (W3) and a tampered one does not (W12).
    /// A delivery missing a `Webhook-Id` cannot have its signed content
    /// reconstructed, so it never validates.
    #[must_use]
    pub fn signature_valid_under(&self, secrets: &[&[u8]]) -> bool {
        let Some(timestamp) = self.timestamp() else {
            return false;
        };
        let Some(id) = self.webhook_id() else {
            return false;
        };
        let presented = self.signature_v1s();
        if presented.is_empty() {
            return false;
        }
        for secret in secrets {
            let expected = recompute_v1(id, secret, timestamp, self.body.as_bytes());
            for got in &presented {
                if constant_time_eq(got.as_bytes(), expected.as_bytes()) {
                    return true;
                }
            }
        }
        false
    }
}

/// How a receiver answers a delivery.
#[derive(Clone)]
enum Mode {
    /// Answer each request with the next scripted status (the last status repeats
    /// once the script runs out). The default sink: it records every request and
    /// acknowledges (or fails) per the script.
    Scripted(Vec<u16>),
    /// Verify the signature against the held secrets and answer 200 only when it
    /// validates; a delivery whose signature does not validate is answered 400 (a
    /// non-2xx the gateway retries). Pins the signed-payload contract end to end
    /// (W12).
    StrictVerify(Vec<Vec<u8>>),
    /// Answer every request with a 307 redirect toward `location`, never a 2xx, so
    /// the suite can prove the hardened egress does not follow it (W13).
    Redirect(String),
}

/// A loopback webhook receiver sink the suite asserts deliveries against.
///
/// Spawns a background thread that accepts connections, records each request, and
/// answers per the response mode it was constructed with (scripted statuses,
/// strict signature verification, or a redirect). Cloneable handles share the same
/// recorded log.
pub struct ReceiverSink {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
}

impl ReceiverSink {
    /// Spawn a receiver that answers each request with `statuses[i]` (clamped to the
    /// last entry once the script runs out), recording every request. A single
    /// `200` script makes a plain always-ack sink.
    #[must_use]
    pub fn scripted(statuses: Vec<u16>) -> Self {
        Self::spawn(Mode::Scripted(statuses))
    }

    /// Spawn a receiver that verifies the delivery signature against `secrets` and
    /// answers 200 only on a valid signature, 400 otherwise. The W12 strict
    /// receiver.
    #[must_use]
    pub fn strict_verify(secrets: Vec<Vec<u8>>) -> Self {
        Self::spawn(Mode::StrictVerify(secrets))
    }

    /// Spawn a receiver that answers every request with a 307 toward `location` and
    /// never a 2xx. The W13 redirecting receiver.
    #[must_use]
    pub fn redirect_to(location: impl Into<String>) -> Self {
        Self::spawn(Mode::Redirect(location.into()))
    }

    fn spawn(mode: Mode) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind receiver");
        let addr = listener.local_addr().expect("receiver addr");
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_for_thread = Arc::clone(&received);
        let counter = AtomicUsize::new(0);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let Some(req) = read_request(&mut stream) else {
                    continue;
                };
                let idx = counter.fetch_add(1, Ordering::SeqCst);
                let status_line = response_for(&mode, &req, idx);
                received_for_thread.lock().unwrap().push(req);
                let _ = stream.write_all(status_line.as_bytes());
                let _ = stream.flush();
            }
        });
        Self { addr, received }
    }

    /// The `http://` URL a webhook endpoint is registered against to reach this
    /// sink. The harness egress seam loosens the range-block so loopback is
    /// reachable; production keeps the deny-list.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/hook", self.addr)
    }

    /// The loopback socket address, for the cases that need the bare host:port.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// A snapshot of every delivery this sink has received, in arrival order.
    #[must_use]
    pub fn deliveries(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    /// How many deliveries this sink has received.
    #[must_use]
    pub fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }
}

/// Build the HTTP/1.1 response line for one request under a mode.
fn response_for(mode: &Mode, req: &Received, idx: usize) -> String {
    match mode {
        Mode::Scripted(statuses) => {
            let status = statuses
                .get(idx)
                .copied()
                .unwrap_or_else(|| *statuses.last().unwrap_or(&200));
            simple_response(status)
        }
        Mode::StrictVerify(secrets) => {
            let refs: Vec<&[u8]> = secrets.iter().map(Vec::as_slice).collect();
            // A valid signature is acknowledged; a tampered/mismatched one is
            // rejected with a 400 the gateway treats as a transient failure.
            if req.signature_valid_under(&refs) {
                simple_response(200)
            } else {
                simple_response(400)
            }
        }
        Mode::Redirect(location) => format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    }
}

/// A bodyless HTTP/1.1 response with the given status.
fn simple_response(status: u16) -> String {
    format!("HTTP/1.1 {status} STATUS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

/// Read one HTTP/1.1 request off the stream: the header block (parsed into a map)
/// and the declared body. Returns `None` if the stream closes before a full
/// request arrives.
fn read_request(stream: &mut TcpStream) -> Option<Received> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = header_end(&buf) {
            let header_len = pos + 4;
            let content_len = content_length(&buf[..header_len]).unwrap_or(0);
            if buf.len() >= header_len + content_len {
                break;
            }
        }
    }
    let pos = header_end(&buf)?;
    let header_block = String::from_utf8_lossy(&buf[..pos]).to_string();
    let body = String::from_utf8_lossy(&buf[pos + 4..]).to_string();
    let headers = parse_headers(&header_block);
    Some(Received { headers, body })
}

/// Find the `\r\n\r\n` that ends the header block.
fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse a header block (after the request line) into a lowercased-name map.
fn parse_headers(block: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    // Skip the request line; parse `Name: Value` headers.
    for line in block.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    map
}

/// Parse the `Content-Length` of a header block, if declared.
fn content_length(headers: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().ok();
            }
        }
    }
    None
}

/// Recompute the lowercase-hex `HMAC_SHA256(secret, "{id}.{t}.{body}")` a receiver
/// validates against (the Standard-Webhooks signed content).
#[must_use]
pub fn recompute_v1(id: &str, secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time byte-slice equality, so the receiver's compare leaks no timing
/// signal — the same discipline the gateway's own verify path uses.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
