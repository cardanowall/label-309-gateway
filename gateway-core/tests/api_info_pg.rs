//! End-to-end tests for the public info routes: health, the error registry, the
//! OpenAPI document, and the docs page.
//!
//! Gated behind `pg-tests`: `health` reads the database (a `SELECT 1` liveness
//! probe and the materialised chain tip), so it needs a real Postgres. The error
//! registry and OpenAPI routes do not touch the database, but they are exercised
//! here too so the whole public meta surface is covered against the live router
//! over the wire.

#![cfg(feature = "pg-tests")]

use std::time::Duration;

use gateway_core::api::{router, ApiConfig, AppState};
use gateway_core::testsupport::TestDb;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Boot the router over a state on an ephemeral port; return the bound address.
async fn serve(state: AppState) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

/// Issue `GET <path>` with the given `Accept` header and read the full response,
/// returning `(status, content_type, body)`.
async fn get(addr: std::net::SocketAddr, path: &str, accept: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: {accept}\r\nConnection: close\r\n\r\n",
    );
    stream.write_all(req.as_bytes()).await.expect("write");

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
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
    let (head, body) = text.split_once("\r\n\r\n").expect("response has a body");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .expect("status code");
    let content_type = head
        .lines()
        .find_map(|l| {
            let l = l.to_ascii_lowercase();
            l.strip_prefix("content-type:")
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_default();
    (status, content_type, body.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_is_ok_with_a_fresh_tip() {
    let db = TestDb::fresh().await.expect("fresh db");
    // A tip observed just now is fresh.
    sqlx::query(
        "INSERT INTO cw_core.cardano_tip (network, tip_block_height, tip_observed_at) \
         VALUES ('preprod', 12345, now())",
    )
    .execute(&db.pool)
    .await
    .expect("seed fresh tip");

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;
    let (status, _ct, body) = get(addr, "/api/v1/health", "application/json").await;
    let json: Value = serde_json::from_str(&body).expect("health body is JSON");

    assert_eq!(status, 200, "a fresh tip and a live DB is a healthy 200");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["db_ok"], true);
    // The health body reports the deployment's CONFIGURED network (the default
    // ApiConfig serves mainnet) — not the network of any cardano_tip row.
    assert_eq!(json["network"], "mainnet");
    assert_eq!(json["cardano_tip_height"], 12345);
    assert!(
        json["cardano_tip_age_seconds"].as_i64().unwrap_or(i64::MAX) < 60,
        "a just-now tip reads as seconds old"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_degrades_to_503_on_a_stale_tip() {
    let db = TestDb::fresh().await.expect("fresh db");
    // A tip observed well past the staleness threshold (the indexer has stalled).
    sqlx::query(
        "INSERT INTO cw_core.cardano_tip (network, tip_block_height, tip_observed_at) \
         VALUES ('preprod', 999, now() - interval '30 minutes')",
    )
    .execute(&db.pool)
    .await
    .expect("seed stale tip");

    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;
    let (status, _ct, body) = get(addr, "/api/v1/health", "application/json").await;
    let json: Value = serde_json::from_str(&body).expect("health body is JSON");

    assert_eq!(status, 503, "a stale tip degrades health to 503");
    assert_eq!(json["status"], "degraded");
    assert_eq!(
        json["db_ok"], true,
        "the DB is still live; only the tip degraded the service"
    );
    assert!(
        json["cardano_tip_age_seconds"].as_i64().unwrap_or(0) > 600,
        "the reported tip age exceeds the staleness threshold"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_reports_null_tip_when_the_indexer_has_not_observed_one() {
    let db = TestDb::fresh().await.expect("fresh db");
    // No cardano_tip row at all: a brand-new deployment before the first scan.
    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;
    let (status, _ct, body) = get(addr, "/api/v1/health", "application/json").await;
    let json: Value = serde_json::from_str(&body).expect("health body is JSON");

    // No tip is not itself a degradation (a tip that has never been observed
    // cannot be stale); the DB is live, so health is ok with a null tip.
    assert_eq!(status, 200);
    assert_eq!(json["status"], "ok");
    assert!(json["cardano_tip_height"].is_null());
    assert!(json["cardano_tip_age_seconds"].is_null());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn errors_returns_the_registry_as_a_json_list() {
    let db = TestDb::fresh().await.expect("fresh db");
    let config = ApiConfig {
        problem_type_base: "https://errors.example/api".to_string(),
        ..ApiConfig::default()
    };
    let addr = serve(AppState::new(db.pool.clone(), config)).await;

    let (status, ct, body) = get(addr, "/api/v1/errors", "application/json").await;
    assert_eq!(status, 200);
    assert!(
        ct.contains("application/json"),
        "errors default to JSON, got {ct}"
    );

    let json: Value = serde_json::from_str(&body).expect("errors body is JSON");
    assert_eq!(json["object"], "list");
    let data = json["data"].as_array().expect("data is a list");
    assert!(!data.is_empty(), "the registry is not empty");

    // Each entry carries the machine-readable code, an HTTP status, and a ref_url
    // built from the operator-configured problem-type base (so the registry links
    // match the `type` member of an actual problem body).
    let entry = &data[0];
    assert!(entry["code"].is_string());
    assert!(entry["http_status"].is_number());
    let ref_url = entry["ref_url"].as_str().expect("ref_url is a string");
    assert!(
        ref_url.starts_with("https://errors.example/api#"),
        "ref_url is anchored under the operator base, got {ref_url}"
    );

    // Every entry carries a non-empty remediation (the OpenAPI schema marks the
    // field required, so a missing or empty one breaks the published contract).
    for e in data {
        let remediation = e["remediation"].as_str().unwrap_or_default();
        assert!(
            !remediation.is_empty(),
            "code {} must document a remediation",
            e["code"]
        );
    }

    // A well-known code is present and well-formed.
    let not_found = data
        .iter()
        .find(|e| e["code"] == "not-found")
        .expect("the not-found code is registered");
    assert_eq!(not_found["http_status"], 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn errors_renders_html_when_the_client_asks_for_it() {
    let db = TestDb::fresh().await.expect("fresh db");
    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;

    let (status, ct, body) = get(addr, "/api/v1/errors", "text/html").await;
    assert_eq!(status, 200);
    assert!(
        ct.contains("text/html"),
        "an HTML Accept yields HTML, got {ct}"
    );
    assert!(body.contains("<table"), "the HTML registry renders a table");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openapi_serves_the_frozen_document() {
    let db = TestDb::fresh().await.expect("fresh db");
    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;

    let (status, ct, body) = get(addr, "/api/v1/openapi.json", "application/json").await;
    assert_eq!(status, 200);
    assert!(ct.contains("application/json"), "openapi is JSON, got {ct}");

    let doc: Value = serde_json::from_str(&body).expect("openapi body is JSON");
    // The served document is the same byte-stable contract the embedded asset
    // carries; the route-coverage test pins its route set, so here we only assert
    // it is the real document (it parses and declares an OpenAPI version + paths).
    assert!(doc["openapi"]
        .as_str()
        .unwrap_or_default()
        .starts_with("3."));
    // Paths are BARE; the version segment lives in `servers`. The document is
    // served at `/api/v1/openapi.json` (the nest), but its path keys carry no
    // version prefix and its server advertises `/api/v1`.
    assert!(doc["paths"]
        .as_object()
        .expect("paths")
        .contains_key("/health"));
    assert_eq!(
        doc["servers"][0]["url"].as_str(),
        Some("/api/v1"),
        "the data-plane spec advertises the versioned server base"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn docs_serves_an_html_reference_page() {
    let db = TestDb::fresh().await.expect("fresh db");
    let addr = serve(AppState::new(db.pool.clone(), ApiConfig::default())).await;

    let (status, ct, body) = get(addr, "/api/v1/docs", "text/html").await;
    assert_eq!(status, 200);
    assert!(ct.contains("text/html"), "docs is HTML, got {ct}");
    // The page points a renderer at the sibling openapi.json (the contract doc).
    assert!(
        body.contains("openapi.json"),
        "docs references the spec document"
    );
    // The rendered page is not a canonical surface: the robots meta tag keeps
    // search engines off it, exactly as the OpenAPI description promises.
    assert!(
        body.contains("noindex, nofollow"),
        "docs carries the robots noindex meta tag"
    );
}
