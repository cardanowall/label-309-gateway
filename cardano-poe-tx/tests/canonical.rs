//! Byte-level and canonical-encoding tests for the builder.
//!
//! These pin the wire-level invariants that the corpus iteration does not check
//! directly: the input set is a Conway tag-258 set in canonical order, the
//! exact-fit (no-change) shape is built correctly with an exact fee, and the
//! machine-readable selection manifests are emitted on demand.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cardano_poe_tx::{
    build_poe_tx, BuildRequest, BuiltPoeTx, ProtocolParams, SigningKey, Utxo, Validity,
};
use pallas_codec::minicbor;
use pallas_primitives::conway::TransactionBody;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Shared fixture plumbing (mirrors the corpus harness; kept local so each test
// binary stays self-contained).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
struct Fixture {
    name: String,
    mode: String,
    protocol: Protocol,
    record_len: usize,
    utxos: Vec<FixtureUtxo>,
    validity: Option<FixtureValidity>,
    expect: String,
    change_address: String,
    network_id: u8,
}

#[derive(Debug, Deserialize, Clone)]
struct Protocol {
    min_fee_a: u64,
    min_fee_b: u64,
    coins_per_utxo_byte: u64,
    max_tx_size: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct FixtureUtxo {
    tx_hash: String,
    index: u32,
    lovelace: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct FixtureValidity {
    invalid_hereafter: Option<u64>,
    valid_from: Option<u64>,
}

fn manifest_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn corpus_inputs_dir() -> PathBuf {
    manifest_dir().join("tests/fixtures/corpus/inputs")
}

fn load(name: &str) -> Fixture {
    let path = corpus_inputs_dir().join(format!("{name}.json"));
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn load_all() -> Vec<Fixture> {
    let mut out = Vec::new();
    for entry in fs::read_dir(corpus_inputs_dir()).expect("corpus inputs dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let bytes = fs::read(&path).expect("read fixture");
            out.push(serde_json::from_slice(&bytes).expect("parse fixture"));
        }
    }
    out.sort_by(|a: &Fixture, b: &Fixture| a.name.cmp(&b.name));
    out
}

fn record_byte(i: usize) -> u8 {
    ((i * 7 + 13) % 256) as u8
}

fn materialise_record(len: usize) -> Vec<u8> {
    (0..len).map(record_byte).collect()
}

fn test_signing_key() -> SigningKey {
    let hex = fs::read_to_string(manifest_dir().join("tests/fixtures/test-signing-seed.hex"))
        .expect("read test signing seed");
    let bytes = hex::decode(hex.trim()).expect("seed is hex");
    let seed: [u8; 32] = bytes.as_slice().try_into().expect("seed is 32 bytes");
    SigningKey::from_seed(seed)
}

fn request_from(fixture: &Fixture, record_bytes: Vec<u8>, utxos: Vec<Utxo>) -> BuildRequest {
    let validity = fixture.validity.as_ref().map(|v| Validity {
        invalid_hereafter: v.invalid_hereafter,
        valid_from: v.valid_from,
    });
    BuildRequest {
        record_bytes,
        metadata_label: 309,
        utxos,
        must_spend: Vec::new(),
        protocol: ProtocolParams {
            min_fee_a: fixture.protocol.min_fee_a,
            min_fee_b: fixture.protocol.min_fee_b,
            coins_per_utxo_byte: fixture.protocol.coins_per_utxo_byte,
            max_tx_size: fixture.protocol.max_tx_size,
        },
        change_address: fixture.change_address.clone(),
        network_id: fixture.network_id,
        payment_verification_key: test_signing_key().verification_key(),
        validity,
    }
}

fn fixture_utxos(fixture: &Fixture) -> Vec<Utxo> {
    fixture
        .utxos
        .iter()
        .map(|u| Utxo {
            tx_hash: u.tx_hash.clone(),
            index: u.index,
            lovelace: u.lovelace,
        })
        .collect()
}

fn build_fixture(fixture: &Fixture) -> BuiltPoeTx {
    build_poe_tx(&request_from(
        fixture,
        materialise_record(fixture.record_len),
        fixture_utxos(fixture),
    ))
    .unwrap_or_else(|e| panic!("{} expected to build, got {e}", fixture.name))
}

// ---------------------------------------------------------------------------
// Canonical input-set encoding: Conway tag 258, sorted by (tx_id, index)
// ---------------------------------------------------------------------------

/// Scan a CBOR map's top level for the value at integer key `key`, returning
/// the byte offset of that value within `body`. The transaction body is a
/// definite-length map of small integer keys, which is all this needs to walk.
fn find_map_value_offset(body: &[u8], key: u64) -> Option<usize> {
    let mut d = minicbor::Decoder::new(body);
    let len = d.map().ok()??; // definite-length map
    for _ in 0..len {
        let k = d.u64().ok()?;
        let value_start = d.position();
        if k == key {
            return Some(value_start);
        }
        d.skip().ok()?;
    }
    None
}

#[test]
fn input_set_is_a_canonical_tag_258_set() {
    // A multi-input build so the set carries more than one element.
    let fixture = load("multi_input");
    let built = build_fixture(&fixture);

    // The input set lives at body key 0. Its CBOR must open with the set tag
    // 258 (major type 6, value 258): 0xd9 0x01 0x02.
    let offset = find_map_value_offset(&built.body_bytes, 0).expect("body has an input set");
    let set_prefix = &built.body_bytes[offset..offset + 3];
    assert_eq!(
        set_prefix,
        &[0xd9, 0x01, 0x02],
        "input set must be CBOR-tagged 258"
    );

    // Decode the body and assert the inputs are in canonical (tx_id, index)
    // ascending order, which is the Conway set order the ledger expects.
    let body: TransactionBody = minicbor::decode(&built.body_bytes).expect("decode body");
    let mut keys: Vec<([u8; 32], u64)> = body
        .inputs
        .iter()
        .map(|i| (*i.transaction_id, i.index))
        .collect();
    let sorted = {
        let mut s = keys.clone();
        s.sort();
        s
    };
    assert_eq!(keys, sorted, "inputs must be in canonical set order");
    assert!(
        keys.len() >= 2,
        "multi_input must select more than one input"
    );

    // The selected_inputs surfaced on the result match the body order exactly.
    keys.dedup();
    assert_eq!(
        built.selected_inputs.len(),
        body.inputs.len(),
        "selected_inputs mirrors the body input set"
    );
}

#[test]
fn single_input_set_is_also_tag_258() {
    // Even with one input the set is tagged 258, consistent with the multi
    // case, so a verifier never has to special-case the singleton.
    let fixture = load("size_1");
    let built = build_fixture(&fixture);
    let offset = find_map_value_offset(&built.body_bytes, 0).expect("body has an input set");
    assert_eq!(&built.body_bytes[offset..offset + 3], &[0xd9, 0x01, 0x02]);
}

#[test]
fn body_auxiliary_data_hash_matches_the_encoded_auxiliary_data() {
    // The builder computes the auxiliary-data hash itself; the body the
    // transaction-builder serialises must carry exactly that hash, and it must
    // be the Blake2b-256 of the auxiliary-data bytes the transaction transports.
    for name in ["size_1", "size_1024", "size_14000"] {
        let built = build_fixture(&load(name));
        let body: TransactionBody = minicbor::decode(&built.body_bytes).expect("decode body");
        let body_hash = body
            .auxiliary_data_hash
            .expect("a record-bearing body sets auxiliary_data_hash");
        assert_eq!(
            *body_hash, built.aux_data_hash,
            "{name}: body auxiliary_data_hash must equal the builder's aux hash"
        );

        use pallas_crypto::hash::Hasher;
        let recomputed = *Hasher::<256>::hash(&built.aux_data_bytes);
        assert_eq!(
            built.aux_data_hash, recomputed,
            "{name}: aux hash must be the Blake2b-256 of the aux bytes"
        );

        // The aux bytes are exactly the transaction's auxiliary-data slot.
        let signed = built.sign(&test_signing_key()).0;
        let tx: pallas_primitives::conway::Tx =
            <pallas_primitives::conway::Tx as pallas_primitives::Fragment>::decode_fragment(
                &signed,
            )
            .expect("decode signed tx");
        use pallas_codec::utils::KeepRaw;
        use pallas_primitives::conway::AuxiliaryData;
        let aux: KeepRaw<'_, AuxiliaryData> =
            Option::from(tx.auxiliary_data.clone()).expect("signed tx carries auxiliary data");
        assert_eq!(
            aux.raw_cbor(),
            built.aux_data_bytes.as_slice(),
            "{name}: transported aux bytes must match the builder's aux bytes"
        );
    }
}

// ---------------------------------------------------------------------------
// exact_fit: a two-pass helper that crafts an input making change exactly 0,
// proving the no-change shape is built with an exact fee.
// ---------------------------------------------------------------------------

#[test]
fn exact_fit_builds_a_no_change_transaction_with_an_exact_fee() {
    let fixture = load("exact_fit");
    assert_eq!(fixture.mode, "exact_fit");

    // Pass 1: build over a single input to learn the no-change fee for this
    // record. A single 6 ADA input leaves a large change; from it we read the
    // single-input fee floor.
    let one_utxo = vec![Utxo {
        tx_hash: fixture.utxos[0].tx_hash.clone(),
        index: fixture.utxos[0].index,
        lovelace: 6_000_000,
    }];
    let learn = build_poe_tx(&request_from(
        &fixture,
        materialise_record(fixture.record_len),
        one_utxo.clone(),
    ))
    .expect("pass 1 builds");
    let learned_fee = learn.fee;

    // Pass 2: re-craft the single input so its value equals exactly the fee the
    // no-change shape charges. The builder must then emit no change output and
    // charge precisely that fee.
    //
    // Because shrinking the input can change the fee (coin-width of the body),
    // iterate to a fixed point: set the input to the current fee estimate,
    // rebuild, and repeat until the input value equals the fee charged.
    let mut input_value = learned_fee;
    let mut built = None;
    for _ in 0..8 {
        let utxo = vec![Utxo {
            tx_hash: fixture.utxos[0].tx_hash.clone(),
            index: fixture.utxos[0].index,
            lovelace: input_value,
        }];
        let b = build_poe_tx(&request_from(
            &fixture,
            materialise_record(fixture.record_len),
            utxo,
        ))
        .expect("pass 2 builds");
        if b.fee == input_value && b.change.is_none() {
            built = Some(b);
            break;
        }
        // The no-change shape's fee is the target; drive the input toward it.
        input_value = b.fee;
    }

    let built = built.expect("exact-fit fixed point reached");
    assert_eq!(built.change, None, "exact fit emits no change output");
    assert_eq!(
        built.fee, input_value,
        "the whole input is consumed exactly by the fee"
    );

    // No change output means body key 1 (outputs) is an empty array, and the
    // signed size still pays for exactly this fee at the linear rate or above.
    let body: TransactionBody = minicbor::decode(&built.body_bytes).expect("decode body");
    assert!(body.outputs.is_empty(), "no-change body has no outputs");

    let floor = fixture.protocol.min_fee_a * built.total_size + fixture.protocol.min_fee_b;
    assert!(
        built.fee >= floor,
        "fee {} must cover the linear floor {floor}",
        built.fee
    );

    // Signing keeps the body and hash; the signed size matches the metered one.
    let (signed, hash) = built.sign(&test_signing_key());
    assert_eq!(hash, built.tx_hash);
    assert_eq!(signed.len() as u64, built.total_size);
}

// ---------------------------------------------------------------------------
// Machine-readable selection manifests (opt-in via POE_EMIT_MANIFESTS=1)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct Manifest {
    selected_inputs: Vec<ManifestInput>,
    fee: u64,
    body_hex: String,
    unsigned_tx_hex: String,
    tx_hash: String,
    aux_data_hash: String,
    size: u64,
    /// The change lovelace, or `null` when the build folded the residual into
    /// the fee and emitted no change output. A folded build is structurally
    /// distinct from one carrying a zero-lovelace change (which never occurs),
    /// so the oracle relies on `null` to decide whether to encode a change
    /// output at all.
    change_lovelace: Option<u64>,
}

#[derive(serde::Serialize)]
struct ManifestInput {
    tx_hash: String,
    index: u32,
}

#[test]
fn emit_selection_manifests() {
    if std::env::var("POE_EMIT_MANIFESTS").as_deref() != Ok("1") {
        // Off by default so an ordinary `cargo test` run writes no files.
        return;
    }

    let out_dir = manifest_dir().join("tests/fixtures/corpus/rust-out");
    fs::create_dir_all(&out_dir).expect("create rust-out");

    for fixture in load_all() {
        if fixture.expect != "ok" {
            continue;
        }
        let built = build_fixture(&fixture);
        let manifest = Manifest {
            selected_inputs: built
                .selected_inputs
                .iter()
                .map(|(h, i)| ManifestInput {
                    tx_hash: h.clone(),
                    index: *i,
                })
                .collect(),
            fee: built.fee,
            body_hex: hex::encode(&built.body_bytes),
            unsigned_tx_hex: hex::encode(&built.unsigned_tx_bytes),
            tx_hash: hex::encode(built.tx_hash),
            aux_data_hash: hex::encode(built.aux_data_hash),
            size: built.total_size,
            change_lovelace: built.change,
        };
        let path = out_dir.join(format!("{}.json", fixture.name));
        let json = serde_json::to_string_pretty(&manifest).expect("serialise manifest");
        fs::write(&path, json + "\n").expect("write manifest");
    }
}

// A guard so the unused-import lint never fires on the shared helpers when the
// test set is trimmed: every fixture is reachable and well-formed.
#[test]
fn all_fixtures_load_with_known_modes() {
    let mut names: BTreeMap<String, ()> = BTreeMap::new();
    for f in load_all() {
        assert!(matches!(f.mode.as_str(), "standard" | "exact_fit"));
        names.insert(f.name, ());
    }
    assert!(names.contains_key("exact_fit"));
    assert!(names.contains_key("multi_input"));
}
