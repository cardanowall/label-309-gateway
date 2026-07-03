//! Conformance: drive the PUBLISHED `cardanowall` CLI against a booted gateway.
//!
//! The CLI is the third published artifact (crates.io `cardanowall-cli`, bin
//! `cardanowall`). This leg drives the EXACT installed binary (a `cargo install
//! cardanowall-cli --version 0.8.0`), so a wire regression in the gateway breaks
//! the real CLI a third party would run.
//!
//! Two legs:
//!
//! - **submit** — the CLI's client-side publish (quote + publish) against the
//!   booted conformance gateway. Proves the CLI speaks the byte-stable
//!   quote/publish contract end to end (its decoder requires the quote
//!   `amount`/`currency` fields the published deserializer requires).
//! - **verify** — the CLI's standalone verifier against a real, already-anchored
//!   Cardano transaction through a public explorer. Env-gated (it needs the
//!   network and a known anchored tx), so it skips cleanly offline.
//!
//! The CLI binary is located via `CARDANOWALL_CLI_BIN` (an absolute path) or
//! `cardanowall` on PATH; the leg skips (passing trivially) when neither
//! resolves, so a CLI-less environment never fails the suite.

#![cfg(feature = "live")]

use std::process::Stdio;

use conformance::BootedGateway;

/// Resolve the published CLI binary: an explicit `CARDANOWALL_CLI_BIN` path wins,
/// else `cardanowall` on PATH. Returns `None` when neither runs.
async fn cli_bin() -> Option<String> {
    let candidate = std::env::var("CARDANOWALL_CLI_BIN").unwrap_or_else(|_| "cardanowall".into());
    let ok = tokio::process::Command::new(&candidate)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    ok.then_some(candidate)
}

/// The CLI's `submit` drives the gateway's quote + publish from a precomputed
/// hash, against the booted conformance gateway. A success proves the CLI's
/// quote/publish decoders agree with the gateway's byte-stable wire shapes.
#[tokio::test(flavor = "multi_thread")]
async fn published_cli_submit_against_the_booted_gateway() {
    let Some(bin) = cli_bin().await else {
        eprintln!("skipping published CLI submit leg: no cardanowall binary on PATH");
        return;
    };

    let gw = BootedGateway::start().await.expect("boot the gateway");
    let tenant = gw
        .seed_tenant("ck_live_", &["poe:create", "poe:read"], 50_000_000)
        .await
        .expect("seed a tenant");

    // A deterministic 32-byte hex digest to anchor (hash-only PoE; no content,
    // no signature). The CLI quotes for it, then publishes it.
    let digest = "d4".repeat(32);

    let output = tokio::process::Command::new(&bin)
        .args([
            "submit",
            "--hash",
            &digest,
            "--base-url",
            &gw.base_url,
            "--api-key",
            &tenant.api_key,
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run the published CLI submit");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    gw.shutdown().await;

    assert!(
        output.status.success(),
        "the published CLI submit must succeed against the booted gateway.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The CLI's --json summary carries the published record's wire id. A wire
    // regression in quote or publish would have failed the CLI's own decoders
    // before this point.
    let summary: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("CLI --json output is not JSON: {e}\nstdout: {stdout}"));
    let id = find_poe_id(&summary).unwrap_or_else(|| {
        panic!("the CLI submit summary carries no poe_ wire id.\nstdout: {stdout}")
    });
    assert!(
        id.starts_with("poe_"),
        "the CLI submit returns a poe_ wire id, got {id}"
    );
}

/// The CLI's standalone `verify` against a real, already-anchored preprod
/// transaction through a public explorer.
///
/// Env-gated: set `CONFORMANCE_VERIFY_TX` to a 64-hex preprod tx hash carrying a
/// Label 309 record and `CONFORMANCE_VERIFY_GATEWAY` to a Koios-compatible
/// preprod gateway URL. Skips (passing) when either is unset, so the suite stays
/// green offline. The gate sets both to the tx the live preprod leg anchored.
#[tokio::test(flavor = "multi_thread")]
async fn published_cli_verify_against_a_real_transaction() {
    let Some(bin) = cli_bin().await else {
        eprintln!("skipping published CLI verify leg: no cardanowall binary on PATH");
        return;
    };
    let (Ok(tx), Ok(gateway)) = (
        std::env::var("CONFORMANCE_VERIFY_TX"),
        std::env::var("CONFORMANCE_VERIFY_GATEWAY"),
    ) else {
        eprintln!(
            "skipping published CLI verify leg: set CONFORMANCE_VERIFY_TX and CONFORMANCE_VERIFY_GATEWAY"
        );
        return;
    };

    let output = tokio::process::Command::new(&bin)
        .args([
            "verify",
            &tx,
            "--profile",
            "core",
            "--cardano-gateway",
            &gateway,
            "--threshold",
            "1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run the published CLI verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "the published CLI verify must exit 0 for a valid record.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("Verdict:") && stdout.contains("valid"),
        "the CLI verify must report a valid verdict.\nstdout: {stdout}"
    );
}

/// Find the first `poe_<...>` id anywhere in a JSON value (the CLI summary nests
/// the record id under a key whose exact name is the CLI's choice, not the wire
/// contract, so the test looks for the id by its stable prefix).
fn find_poe_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) if s.starts_with("poe_") => Some(s.clone()),
        serde_json::Value::Object(map) => map.values().find_map(find_poe_id),
        serde_json::Value::Array(items) => items.iter().find_map(find_poe_id),
        _ => None,
    }
}
