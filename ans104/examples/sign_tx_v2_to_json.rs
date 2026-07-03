//! Sign a format-2 base-layer transaction over a fixed payload and print the JSON.
//!
//! Reads an Arweave RSA JWK from `$ANS104_JWK`, builds a deterministic payload,
//! signs a format-2 transaction carrying it under the binary-bundle tags, and
//! writes the transaction JSON to stdout. A reference implementation (arweave-js)
//! can then verify the signature, recompute the data root, and confirm the id,
//! proving this crate agrees on the base-layer transaction wire format.
//!
//! Developer tool, not part of the library surface.

use std::io::Write;

use ans104::{ArweaveJwkSigner, Tag};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jwk_path = std::env::var("ANS104_JWK")
        .map_err(|_| "set ANS104_JWK to the path of an Arweave RSA JWK")?;
    let jwk_json = std::fs::read_to_string(&jwk_path)?;
    let signer = ArweaveJwkSigner::from_jwk_json(&jwk_json)?;

    // A deterministic payload so the signed fields are reproducible field-for-field
    // (only the randomised PSS signature, and thus the id, vary per run). The length
    // is overridable so the cross-check can exercise multi-chunk and rebalanced
    // payloads, not just a single small chunk.
    let len: usize = std::env::var("ANS104_TX_PAYLOAD_LEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1500);
    let mut data = vec![0u8; len];
    for (i, b) in data.iter_mut().enumerate() {
        *b = ((i * 11 + 5) & 0xff) as u8;
    }

    let tags = [
        Tag::new("Bundle-Format", "binary"),
        Tag::new("Bundle-Version", "2.0.0"),
    ];
    let reward = ans104::reward_for(data.len() as u64);
    let tx = ans104::sign_tx_v2(&signer, &data, &tags, "", reward)?;

    let mut out = tx.to_json();
    // Echo the payload (hex) so the reference can recompute the data root from the
    // identical bytes without re-deriving them.
    out["_payload_hex"] = serde_json::Value::String(to_hex(&data));
    let line = format!("{}\n", serde_json::to_string(&out)?);
    std::io::stdout().write_all(line.as_bytes())?;
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
