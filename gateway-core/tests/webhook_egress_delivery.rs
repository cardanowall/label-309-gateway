//! End-to-end webhook delivery over a real socket: the signer and the hardened
//! egress compose to POST a signed body a receiver can verify.
//!
//! These cases drive the blocking egress against a std-only loopback receiver, so
//! they need no database. They pin three properties the unit tests cannot prove
//! over a socket:
//!
//!   - the two explicit opt-ins (`allow_insecure_http` for the plain-HTTP scheme,
//!     `allow_loopback` for the range-block) let the egress reach a local
//!     plain-HTTP receiver WITHOUT weakening the production posture (a separate
//!     case still refuses a blocked range with the seam off);
//!   - the signed headers (`Webhook-Id`, `Webhook-Timestamp`, `Webhook-Signature`)
//!     arrive on the wire intact and the receiver can recompute the HMAC over
//!     `"{id}.{timestamp}.{body}"` and match the `v1`;
//!   - a dual-signed delivery carries one `v1` per active secret, and the receiver
//!     validates with EITHER secret.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use gateway_core::webhook::{deliver, sign_delivery, DeliveryError, EgressConfig};

type HmacSha256 = Hmac<Sha256>;

/// The raw bytes of one received request, split into its header block and body.
struct Received {
    headers: String,
    body: String,
}

impl Received {
    /// The value of a request header, case-insensitively.
    fn header(&self, name: &str) -> Option<String> {
        let want = name.to_ascii_lowercase();
        for line in self.headers.lines().skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().to_ascii_lowercase() == want {
                    return Some(v.trim().to_string());
                }
            }
        }
        None
    }
}

/// Spawn a one-shot loopback receiver that reads one request, captures it, and
/// answers `status`. Returns its address and a channel that yields the request.
fn spawn_receiver(status: u16) -> (SocketAddr, mpsc::Receiver<Received>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Read until the headers terminate, then drain the declared body.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = stream.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_header_end(&buf) {
                    let header_len = pos + 4;
                    let content_len = parse_content_length(&buf[..header_len]).unwrap_or(0);
                    if buf.len() >= header_len + content_len {
                        break;
                    }
                }
            }
            let pos = find_header_end(&buf).unwrap_or(buf.len().saturating_sub(0));
            let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
            let body = String::from_utf8_lossy(&buf[pos + 4..]).to_string();
            let _ = tx.send(Received { headers, body });
            let resp =
                format!("HTTP/1.1 {status} OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    (addr, rx)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
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

/// Recompute the lowercase-hex HMAC the receiver would over `"{id}.{t}.{body}"`.
fn recompute_v1(id: &str, secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Parse the `v1` values out of a `Webhook-Signature: t=…,v1=…[,v1=…]` header.
fn parse_v1s(sig: &str) -> Vec<String> {
    sig.split(',')
        .filter_map(|p| p.strip_prefix("v1="))
        .map(|s| s.to_string())
        .collect()
}

/// The egress config a test uses to reach a local plain-HTTP receiver. The two
/// loosenings are independent axes, so a receiver that is both plain-HTTP and
/// loopback needs both opened explicitly: `allow_insecure_http` for the scheme,
/// `allow_loopback` for the range-block.
fn test_seam() -> EgressConfig {
    EgressConfig {
        allow_insecure_http: true,
        allow_loopback: true,
    }
}

#[test]
fn delivers_a_signed_body_a_receiver_can_verify() {
    let (addr, rx) = spawn_receiver(200);

    let secret = b"whsec_e2e_0123456789".to_vec();
    let webhook_id = "poe_record:00000000-0000-7000-8000-000000000001:7:endpoint-uuid";
    let timestamp = 1_733_600_500;
    let body = br#"{"id":"poe_record:...:7:endpoint-uuid","type":"poe_status_changed","data":{}}"#;

    let signed = sign_delivery(webhook_id, timestamp, body, std::slice::from_ref(&secret));
    let url = format!("http://{addr}/hook");

    let resp = deliver(&url, body, &signed.to_pairs(), test_seam()).expect("deliver");
    assert!(resp.is_success(), "the receiver acked with 200");

    let received = rx.recv().expect("the receiver got the request");
    // The signed headers arrived intact.
    assert_eq!(received.header("Webhook-Id").as_deref(), Some(webhook_id));
    assert_eq!(
        received.header("Webhook-Timestamp").as_deref(),
        Some(timestamp.to_string().as_str())
    );
    assert_eq!(received.body.as_bytes(), body, "the body arrived verbatim");

    // The receiver recomputes the HMAC over "{id}.{t}.{body}" — using the
    // Webhook-Id it received — and matches the v1.
    let sig = received
        .header("Webhook-Signature")
        .expect("signature header");
    let v1s = parse_v1s(&sig);
    assert_eq!(v1s.len(), 1, "one v1 outside a rotation window");
    assert_eq!(v1s[0], recompute_v1(webhook_id, &secret, timestamp, body));

    // A receiver that reconstructs the signed content WITHOUT the id (the old,
    // non-conformant `"{t}.{body}"`) does not match — the id is in the MAC.
    let id_less = {
        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    };
    assert_ne!(
        v1s[0], id_less,
        "the signed content includes the Webhook-Id"
    );
}

#[test]
fn dual_signed_delivery_validates_with_either_secret() {
    let (addr, rx) = spawn_receiver(200);

    let primary = b"whsec_primary_000".to_vec();
    let successor = b"whsec_successor_111".to_vec();
    let timestamp = 1_733_600_600;
    let body = br#"{"type":"balance_changed","data":{}}"#;

    let webhook_id = "acct:1:endpoint";
    let signed = sign_delivery(
        webhook_id,
        timestamp,
        body,
        &[primary.clone(), successor.clone()],
    );
    let url = format!("http://{addr}/hook");

    deliver(&url, body, &signed.to_pairs(), test_seam()).expect("deliver");
    let received = rx.recv().expect("received");

    let sig = received
        .header("Webhook-Signature")
        .expect("signature header");
    let v1s = parse_v1s(&sig);
    assert_eq!(v1s.len(), 2, "dual-signed: one v1 per active secret");
    // A receiver holding only the primary matches the first v1; one holding only
    // the successor matches the second — either secret validates the delivery.
    assert!(v1s.contains(&recompute_v1(webhook_id, &primary, timestamp, body)));
    assert!(v1s.contains(&recompute_v1(webhook_id, &successor, timestamp, body)));
}

#[test]
fn production_config_refuses_a_loopback_target_without_the_seam() {
    // With the seam OFF (production), the same loopback URL the test seam reaches
    // is refused by the range-block before any socket is opened.
    let err = deliver(
        "https://127.0.0.1/hook",
        b"{}",
        &[],
        EgressConfig::default(),
    )
    .unwrap_err();
    assert!(matches!(err, DeliveryError::Refused(_)));
}
