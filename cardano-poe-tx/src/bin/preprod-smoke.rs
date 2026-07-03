//! Network smoke test for the Proof-of-Existence builder.
//!
//! This binary is the one place the crate touches the network. It is excluded
//! from a default build (it requires the `smoke` feature) so the library stays
//! provably I/O-free. Invoked with the right environment, it fetches live
//! protocol parameters and UTxOs from a Koios endpoint, runs the *same*
//! [`cardano_poe_tx::build_poe_tx`] the tests exercise, signs the result, and
//! submits the CBOR to the node's `/submittx` endpoint.
//!
//! Required environment:
//!
//! - `KOIOS_BASE_URL`     e.g. `https://preprod.koios.rest/api/v1`
//! - `WALLET_ADDRESS`     bech32 payment address holding the UTxOs and change
//! - `WALLET_SKEY_BECH32` bech32-encoded 32-byte Ed25519 signing seed
//! - `RECORD_HEX`         the Proof-of-Existence record bytes, hex-encoded
//!
//! It prints the transaction hash and the exact fee on success.

use std::process::ExitCode;

use cardano_poe_tx::{build_poe_tx, BuildRequest, ProtocolParams, SigningKey, Utxo};
use serde::Deserialize;

const METADATA_LABEL: u64 = 309;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("preprod-smoke: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let koios = env("KOIOS_BASE_URL")?;
    let address = env("WALLET_ADDRESS")?;
    let skey_bech32 = env("WALLET_SKEY_BECH32")?;
    let record_hex = env("RECORD_HEX")?;

    let record_bytes = hex::decode(record_hex.trim()).map_err(|e| format!("RECORD_HEX: {e}"))?;
    let signing_key = signing_key_from_bech32(skey_bech32.trim())?;
    let verification_key = signing_key.verification_key();
    let network_id = network_id_for(&address)?;

    let client = reqwest::blocking::Client::new();
    let protocol = fetch_protocol_params(&client, &koios)?;
    let utxos = fetch_utxos(&client, &koios, &address)?;
    if utxos.is_empty() {
        return Err(format!("no UTxOs at {address}"));
    }

    let request = BuildRequest {
        record_bytes,
        metadata_label: METADATA_LABEL,
        utxos,
        must_spend: Vec::new(),
        protocol,
        change_address: address.clone(),
        network_id,
        payment_verification_key: verification_key,
        validity: None,
    };

    let built = build_poe_tx(&request).map_err(|e| format!("build failed: {e}"))?;
    let (signed_tx, tx_hash) = built.sign(&signing_key);

    submit(&client, &koios, &signed_tx)?;

    println!("tx_hash: {}", hex::encode(tx_hash));
    println!("fee: {}", built.fee);
    Ok(())
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("missing required environment variable {name}"))
}

/// Decode a 32-byte Ed25519 seed from its bech32 form and build a signing key.
fn signing_key_from_bech32(bech: &str) -> Result<SigningKey, String> {
    let (_hrp, data) = bech32::decode(bech).map_err(|e| format!("WALLET_SKEY_BECH32: {e}"))?;
    let seed: [u8; 32] = data
        .as_slice()
        .try_into()
        .map_err(|_| "WALLET_SKEY_BECH32 must decode to 32 bytes".to_string())?;
    Ok(SigningKey::from_seed(seed))
}

/// Map the address's bech32 human-readable part to its network discriminant.
fn network_id_for(address: &str) -> Result<u8, String> {
    if address.starts_with("addr_test") || address.starts_with("stake_test") {
        Ok(0)
    } else if address.starts_with("addr") || address.starts_with("stake") {
        Ok(1)
    } else {
        Err(format!("unrecognised address prefix: {address}"))
    }
}

#[derive(Deserialize)]
struct KoiosProtocolParams {
    #[serde(deserialize_with = "de_u64_lenient")]
    min_fee_a: u64,
    #[serde(deserialize_with = "de_u64_lenient")]
    min_fee_b: u64,
    #[serde(deserialize_with = "de_u64_lenient")]
    coins_per_utxo_size: u64,
    #[serde(deserialize_with = "de_u64_lenient")]
    max_tx_size: u64,
}

/// Deserialize a `u64` that the source may encode either as a JSON number or as
/// a JSON string. Koios renders lovelace-scale protocol parameters (such as
/// `coins_per_utxo_size`) as quoted strings to keep full precision for clients
/// whose native numbers are IEEE-754 doubles, while smaller fields stay bare
/// numbers; the boundary is not contractually fixed, so every numeric field is
/// accepted in either form.
fn de_u64_lenient<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| D::Error::custom(format!("not a u64: {n}"))),
        serde_json::Value::String(s) => s
            .parse::<u64>()
            .map_err(|e| D::Error::custom(format!("not a u64 string: {s}: {e}"))),
        other => Err(D::Error::custom(format!(
            "expected a u64 number or string, got {other}"
        ))),
    }
}

fn fetch_protocol_params(
    client: &reqwest::blocking::Client,
    koios: &str,
) -> Result<ProtocolParams, String> {
    let url = format!("{}/epoch_params?limit=1", koios.trim_end_matches('/'));
    let rows: Vec<KoiosProtocolParams> = client
        .get(&url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| format!("epoch_params: {e}"))?
        .json()
        .map_err(|e| format!("epoch_params decode: {e}"))?;
    let p = rows
        .into_iter()
        .next()
        .ok_or_else(|| "epoch_params returned no rows".to_string())?;
    Ok(ProtocolParams {
        min_fee_a: p.min_fee_a,
        min_fee_b: p.min_fee_b,
        coins_per_utxo_byte: p.coins_per_utxo_size,
        max_tx_size: p.max_tx_size,
    })
}

#[derive(Deserialize)]
struct KoiosAddressInfo {
    utxo_set: Vec<KoiosUtxo>,
}

#[derive(Deserialize)]
struct KoiosUtxo {
    tx_hash: String,
    tx_index: u32,
    value: String,
}

fn fetch_utxos(
    client: &reqwest::blocking::Client,
    koios: &str,
    address: &str,
) -> Result<Vec<Utxo>, String> {
    let url = format!("{}/address_info", koios.trim_end_matches('/'));
    let body = serde_json::json!({ "_addresses": [address] });
    let rows: Vec<KoiosAddressInfo> = client
        .post(&url)
        .json(&body)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| format!("address_info: {e}"))?
        .json()
        .map_err(|e| format!("address_info decode: {e}"))?;

    let mut out = Vec::new();
    for row in rows {
        for u in row.utxo_set {
            let lovelace: u64 = u
                .value
                .parse()
                .map_err(|e| format!("utxo value {}: {e}", u.value))?;
            out.push(Utxo {
                tx_hash: u.tx_hash,
                index: u.tx_index,
                lovelace,
            });
        }
    }
    Ok(out)
}

fn submit(client: &reqwest::blocking::Client, koios: &str, signed_tx: &[u8]) -> Result<(), String> {
    let url = format!("{}/submittx", koios.trim_end_matches('/'));
    client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(signed_tx.to_vec())
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| format!("submittx: {e}"))?;
    Ok(())
}
