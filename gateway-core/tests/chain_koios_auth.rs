//! Behavioural coverage for Koios authentication and addressing: when a
//! [`KoiosConfig`] carries an API key, EVERY Koios HTTP request — the chain
//! gateway's GET and POST paths, the protocol-parameter source, and the wallet
//! UTxO source — carries `Authorization: Bearer <key>`; a keyless config sends
//! no `Authorization` header at all. A configured base URL replaces the
//! per-network public URL on the same clients, and a keyed gateway widens its
//! bulk POST chunking to the registered-tier body cap.
//!
//! Driven over a loopback socket with no live HTTP and no Postgres: the fake
//! server records each request's full head (request line + headers) so the
//! assertions read what was actually sent on the wire.

use std::sync::{Arc, Mutex};

use gateway_core::chain::gateway::{ChainGateway, KoiosGateway};
use gateway_core::chain::params::{KoiosConfig, KoiosParamsSource, Network, ProtocolParamsSource};
use gateway_core::wallet::utxo::{KoiosUtxoSource, UtxoSource};

/// One recorded request: the request line's path plus the raw head (request
/// line and headers, before the body separator).
#[derive(Clone, Debug)]
struct SeenRequest {
    path: String,
    head: String,
}

impl SeenRequest {
    /// The `Authorization` header value, if the request carried one.
    fn authorization(&self) -> Option<String> {
        self.head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_string())
        })
    }
}

#[derive(Clone)]
struct FakeServer {
    base_url: String,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
}

impl FakeServer {
    fn seen(&self) -> Vec<SeenRequest> {
        self.seen.lock().unwrap().clone()
    }

    fn requests_with_prefix(&self, prefix: &str) -> Vec<SeenRequest> {
        self.seen()
            .into_iter()
            .filter(|r| r.path.starts_with(prefix))
            .collect()
    }
}

/// Spawn a server that answers `total_requests` connections by routing each
/// request path to the first matching `(prefix, body)` route (an unrouted path
/// gets a 404), recording every request's head for the auth assertions.
async fn spawn_recording_router(
    routes: Vec<(&'static str, String)>,
    total_requests: usize,
) -> FakeServer {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake");
    let addr = listener.local_addr().expect("addr");
    let base_url = format!("http://{addr}");
    let seen: Arc<Mutex<Vec<SeenRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_for_server = seen.clone();

    tokio::spawn(async move {
        for _ in 0..total_requests {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let mut buf = vec![0u8; 64 * 1024];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let head = request
                .split("\r\n\r\n")
                .next()
                .unwrap_or(&request)
                .to_string();
            let path = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            seen_for_server.lock().unwrap().push(SeenRequest {
                path: path.clone(),
                head,
            });

            let matched = routes.iter().find(|(prefix, _)| path.starts_with(prefix));
            let (status_line, body) = match matched {
                Some((_, body)) => ("HTTP/1.1 200 OK", body.as_str()),
                None => ("HTTP/1.1 404 Not Found", "{}"),
            };
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        }
    });

    FakeServer { base_url, seen }
}

fn keyed_config(base_url: String) -> KoiosConfig {
    KoiosConfig {
        base_url: Some(base_url),
        api_key: Some("test-koios-jwt".to_string().into()),
    }
}

fn keyless_config(base_url: String) -> KoiosConfig {
    KoiosConfig {
        base_url: Some(base_url),
        api_key: None,
    }
}

fn gateway_at(config: KoiosConfig) -> KoiosGateway {
    let client = reqwest::Client::builder().build().expect("reqwest client");
    KoiosGateway::with_client(client, Network::Preprod, config)
}

/// The route set covering every distinct transport seam in [`KoiosGateway`]:
/// the raw GETs (`/tip`, `/blocks`), the raw POST (`/submittx`), the JSON POST
/// (`/tx_status`), and the scan's GET list (`/tx_by_metalabel`, answered empty
/// so no follow-up metadata call is made).
fn all_seam_routes() -> Vec<(&'static str, String)> {
    vec![
        (
            "/tip",
            r#"[{"block_height": 1000, "epoch_no": 213}]"#.to_string(),
        ),
        ("/tx_by_metalabel", "[]".to_string()),
        ("/tx_status", "[]".to_string()),
        ("/blocks", "[]".to_string()),
        ("/submittx", format!("\"{}\"", "11".repeat(32))),
    ]
}

/// Drive one call through each transport seam of the gateway.
async fn exercise_every_seam(gateway: &KoiosGateway) {
    gateway.get_tip().await.expect("tip");
    gateway
        .get_block_info(999)
        .await
        .expect("block info (empty rows resolve to None)");
    gateway.submit_tx(&[0x84, 0xa0]).await.expect("submit");
    gateway
        .get_tx_confirmations(&[[0x11; 32]])
        .await
        .expect("confirmations");
    gateway
        .fetch_label309_records_since(0, &[], 1000, 10)
        .await
        .expect("forward scan list");
}

#[tokio::test]
async fn a_keyed_gateway_sends_bearer_auth_on_every_request() {
    let server = spawn_recording_router(all_seam_routes(), 5).await;
    let gateway = gateway_at(keyed_config(server.base_url.clone()));

    exercise_every_seam(&gateway).await;

    let seen = server.seen();
    assert_eq!(seen.len(), 5, "every seam made exactly one request");
    for request in &seen {
        assert_eq!(
            request.authorization().as_deref(),
            Some("Bearer test-koios-jwt"),
            "request to {} must carry the bearer key",
            request.path
        );
    }
}

#[tokio::test]
async fn a_keyless_gateway_sends_no_authorization_header() {
    let server = spawn_recording_router(all_seam_routes(), 5).await;
    let gateway = gateway_at(keyless_config(server.base_url.clone()));

    exercise_every_seam(&gateway).await;

    let seen = server.seen();
    assert_eq!(seen.len(), 5, "every seam made exactly one request");
    for request in &seen {
        assert!(
            request.authorization().is_none(),
            "a keyless request to {} must carry no Authorization header",
            request.path
        );
    }
}

#[tokio::test]
async fn a_keyed_gateway_widens_bulk_posts_to_the_registered_chunk() {
    // 30 hashes: a keyless gateway splits them into three /tx_status chunks (the
    // ~1 KiB public body cap), while a keyed gateway sends ONE request under the
    // registered tiers' ~5 KiB cap. The empty rows answer leaves every hash
    // not-on-chain, so no /tx_info follow-up muddies the count.
    let hashes: Vec<[u8; 32]> = (0..30u8).map(|i| [i; 32]).collect();

    let keyless_server = spawn_recording_router(vec![("/tx_status", "[]".to_string())], 3).await;
    gateway_at(keyless_config(keyless_server.base_url.clone()))
        .get_tx_confirmations(&hashes)
        .await
        .expect("keyless confirmations");
    assert_eq!(
        keyless_server.requests_with_prefix("/tx_status").len(),
        3,
        "30 hashes at the 14-hash keyless chunk split into three requests"
    );

    let keyed_server = spawn_recording_router(vec![("/tx_status", "[]".to_string())], 1).await;
    gateway_at(keyed_config(keyed_server.base_url.clone()))
        .get_tx_confirmations(&hashes)
        .await
        .expect("keyed confirmations");
    assert_eq!(
        keyed_server.requests_with_prefix("/tx_status").len(),
        1,
        "a keyed gateway carries all 30 hashes in one registered-tier body"
    );
}

#[tokio::test]
async fn the_params_source_uses_the_override_url_and_the_bearer_key() {
    let server = spawn_recording_router(
        vec![(
            "/tip",
            r#"[{"block_height": 1000, "epoch_no": 213}]"#.to_string(),
        )],
        1,
    )
    .await;
    let client = reqwest::Client::builder().build().expect("reqwest client");
    let source = KoiosParamsSource::with_client(client, keyed_config(server.base_url.clone()));

    // The call answering from the loopback fake proves the override replaced
    // the per-network public URL; the recorded head proves the key rode along.
    let epoch = source
        .current_epoch(Network::Preprod)
        .await
        .expect("current epoch through the override");
    assert_eq!(epoch, 213);

    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/tip");
    assert_eq!(
        seen[0].authorization().as_deref(),
        Some("Bearer test-koios-jwt")
    );
}

#[tokio::test]
async fn the_utxo_source_sends_the_bearer_key_and_a_keyless_one_does_not() {
    let server = spawn_recording_router(vec![("/address_utxos", "[]".to_string())], 2).await;
    let client = reqwest::Client::builder().build().expect("reqwest client");

    let keyed = KoiosUtxoSource::with_client(
        client.clone(),
        server.base_url.clone(),
        Some("test-koios-jwt".to_string().into()),
    );
    keyed
        .address_utxos("addr_test1vqexample")
        .await
        .expect("keyed utxo read");

    let keyless = KoiosUtxoSource::with_client(client, server.base_url.clone(), None);
    keyless
        .address_utxos("addr_test1vqexample")
        .await
        .expect("keyless utxo read");

    let seen = server.requests_with_prefix("/address_utxos");
    assert_eq!(seen.len(), 2);
    assert_eq!(
        seen[0].authorization().as_deref(),
        Some("Bearer test-koios-jwt"),
        "the keyed source authenticates its POST"
    );
    assert!(
        seen[1].authorization().is_none(),
        "the keyless source sends no Authorization header"
    );
}
