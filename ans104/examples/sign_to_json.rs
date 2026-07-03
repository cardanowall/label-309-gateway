//! Sign a fresh data item and print it as JSON for cross-implementation checks.
//!
//! Reads an Arweave RSA JWK from the path in `$ANS104_JWK`, signs a small data
//! item carrying a couple of tags, and writes a JSON object to stdout with the
//! canonical bytes (hex) and the computed id. A reference implementation can
//! then load the same bytes and confirm it verifies and derives the same id,
//! proving the two stacks agree on the wire format and the signature scheme.
//!
//! This is a developer tool, not part of the library surface: it exists so an
//! external verifier can be pointed at bytes this crate just produced.

use std::io::Write;

use ans104::{ArweaveJwkSigner, DataItemBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jwk_path = std::env::var("ANS104_JWK")
        .map_err(|_| "set ANS104_JWK to the path of an Arweave RSA JWK")?;
    let jwk_json = std::fs::read_to_string(&jwk_path)?;
    let signer = ArweaveJwkSigner::from_jwk_json(&jwk_json)?;

    // A deterministic ~2 KiB payload so the bytes are reproducible field-for-
    // field (only the random PSS signature, and thus the id, vary per run).
    let mut data = vec![0u8; 2048];
    for (i, b) in data.iter_mut().enumerate() {
        *b = ((i * 7 + 13) & 0xff) as u8;
    }

    let signed = DataItemBuilder::new(data)
        .tag("content-type", "application/octet-stream")
        .tag("app", "label-309-gate-check")
        .anchor([0x5au8; 32])?
        .sign(&signer)?;

    let out = format!(
        "{{\"id_b64url\":\"{}\",\"raw_hex\":\"{}\"}}\n",
        signed.id_b64url,
        to_hex(&signed.bytes),
    );
    std::io::stdout().write_all(out.as_bytes())?;
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
