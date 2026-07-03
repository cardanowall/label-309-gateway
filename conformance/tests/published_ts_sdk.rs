//! Conformance: drive the PUBLISHED TypeScript SDK against a booted gateway.
//!
//! Boots the in-repo gateway, seeds a tenant directly, then runs the Node driver
//! (`tools/sdk-ts-flows.mjs`) as a subprocess with the seeded base URL + API key
//! in the environment. The driver pins `@cardanowall/sdk-ts@0.8.0` as a normal
//! npm dependency, so a wire-shape regression surfaces as a deserialize failure
//! in the real published TS client. The Rust side only orchestrates; every
//! wire-contract assertion lives in the Node driver against the published
//! deserializers.
//!
//! Gated behind the `live` feature. Skips (passing trivially) when `node` or
//! `npm` are not on PATH, so a Rust-only environment never fails this leg.

#![cfg(feature = "live")]

use std::path::PathBuf;
use std::process::Stdio;

use conformance::BootedGateway;

/// The conformance tools directory (the Node driver + its package.json).
fn tools_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools")
}

/// Whether a command is runnable (used to skip the leg when Node is absent).
async fn has_command(cmd: &str) -> bool {
    tokio::process::Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Install the pinned published SDK into the tools directory (idempotent: npm
/// resolves the lockfile and reuses the cache on a second run).
async fn npm_install(dir: &PathBuf) -> bool {
    tokio::process::Command::new("npm")
        .args(["install", "--no-audit", "--no-fund"])
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread")]
async fn published_ts_sdk_quote_publish_dedup_balance_flow() {
    if !has_command("node").await || !has_command("npm").await {
        eprintln!("skipping published TS SDK leg: node/npm not on PATH");
        return;
    }

    let dir = tools_dir();
    assert!(
        npm_install(&dir).await,
        "npm install of the pinned @cardanowall/sdk-ts must succeed"
    );

    let gw = BootedGateway::start().await.expect("boot the gateway");
    let tenant = gw
        .seed_tenant(
            "ck_live_",
            &["poe:create", "poe:read", "account:read"],
            50_000_000,
        )
        .await
        .expect("seed a tenant");

    // Run the Node driver against the booted gateway. The api key is passed via the
    // environment (never an argv, never logged); the driver asserts the full
    // quote/publish/dedup/balance contract through the published deserializers.
    let output = tokio::process::Command::new("node")
        .arg("sdk-ts-flows.mjs")
        .current_dir(&dir)
        .env("GATEWAY_BASE_URL", &gw.base_url)
        .env("GATEWAY_CONFORMANCE_API_KEY", &tenant.api_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run the Node driver");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    gw.shutdown().await;

    assert!(
        output.status.success(),
        "the published TS SDK driver must exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("ts-sdk conformance: quote/publish/dedup/balance flows green"),
        "the driver must report all flows green.\nstdout: {stdout}\nstderr: {stderr}"
    );
}
