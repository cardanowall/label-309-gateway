//! Pins the classified builder-vs-oracle divergence report.
//!
//! The out-of-tree Node oracle re-prices and re-builds every corpus case with
//! two independent encoders (Cardano Serialization Library and Lucid Evolution)
//! and writes a classified parity report to
//! `tests/fixtures/oracle/parity-report.json`. Byte equality with those oracles
//! is the goal, but both predate the Conway-era canonical encoding and
//! re-serialise three fields in their legacy forms, so the builder's modern
//! transaction diverges from them in a small, fixed set of fee-neutral ways.
//! That set is the committed report; this test is its guard.
//!
//! The test does two independent things:
//!
//! 1. It re-derives, directly from the live builder, the three structural facts
//!    that justify each divergence class (the body sets `network_id`, the change
//!    output is the post-Babbage map form, and the auxiliary data is the Conway
//!    tag-259 shape), and that the builder's fee never falls below the ledger
//!    linear floor over its own exact metered size. So the report cannot drift
//!    away from what the builder actually emits.
//!
//! 2. It asserts the committed report contains only the known divergence
//!    classes and that its per-case claims match what the builder produces. A
//!    new divergence class, or a case whose claims no longer hold, fails here
//!    before it can be re-pinned without review.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cardano_poe_tx::{
    build_poe_tx, BuildRequest, BuiltPoeTx, ProtocolParams, SigningKey, Utxo, Validity,
};
use pallas_codec::minicbor;
use pallas_primitives::babbage::GenTransactionOutput;
use pallas_primitives::conway::TransactionBody;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Fixture plumbing (mirrors the corpus harness; kept local so the test binary
// stays self-contained).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
struct Fixture {
    name: String,
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

fn request_from(fixture: &Fixture) -> BuildRequest {
    let validity = fixture.validity.as_ref().map(|v| Validity {
        invalid_hereafter: v.invalid_hereafter,
        valid_from: v.valid_from,
    });
    BuildRequest {
        record_bytes: materialise_record(fixture.record_len),
        metadata_label: 309,
        utxos: fixture
            .utxos
            .iter()
            .map(|u| Utxo {
                tx_hash: u.tx_hash.clone(),
                index: u.index,
                lovelace: u.lovelace,
            })
            .collect(),
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

fn build_fixture(fixture: &Fixture) -> BuiltPoeTx {
    build_poe_tx(&request_from(fixture))
        .unwrap_or_else(|e| panic!("{} expected to build, got {e}", fixture.name))
}

// ---------------------------------------------------------------------------
// Pinned parity report
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ParityReport {
    known_divergence_classes: Vec<String>,
    cases: Vec<ParityCase>,
}

#[derive(Debug, Deserialize)]
struct ParityCase {
    case: String,
    fee_csl_floor_ok: bool,
    lucid_status: String,
    divergence_classes: Vec<String>,
}

fn load_parity_report() -> ParityReport {
    let path = manifest_dir().join("tests/fixtures/oracle/parity-report.json");
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// The only divergence classes between the builder's modern Conway encoding and
/// the legacy forms the CSL/Lucid oracles re-serialise. A class outside this
/// set is an unclassified encoding difference that must be reviewed, not
/// re-pinned.
const KNOWN_CLASSES: [&str; 3] = ["aux-data-format", "network-id", "output-format"];

// ---------------------------------------------------------------------------
// Structural facts the builder must exhibit to justify each divergence class.
// ---------------------------------------------------------------------------

/// Decode the body and report whether it sets the `network_id` field (the body
/// key the legacy re-encode omits, the `network-id` divergence class).
fn body_sets_network_id(built: &BuiltPoeTx) -> bool {
    let body: TransactionBody = minicbor::decode(&built.body_bytes).expect("decode body");
    body.network_id.is_some()
}

/// Whether every output the body carries is the post-Babbage map form
/// (`PostAlonzo`) rather than the legacy `[address, value]` array. This is the
/// builder side of the `output-format` divergence class.
fn outputs_are_babbage_map(built: &BuiltPoeTx) -> bool {
    let body: TransactionBody = minicbor::decode(&built.body_bytes).expect("decode body");
    body.outputs
        .iter()
        .all(|o| matches!(o, GenTransactionOutput::PostAlonzo(_)))
}

/// Whether the auxiliary data is the Conway tag-259 shape (`d9 01 03`), the
/// builder side of the `aux-data-format` divergence class. The legacy re-encode
/// emits the untagged Shelley metadata map, which hashes differently.
fn aux_is_conway_tag_259(built: &BuiltPoeTx) -> bool {
    built.aux_data_bytes.starts_with(&[0xd9, 0x01, 0x03])
}

/// The ledger's linear fee over the builder's exact metered signed size. The
/// builder's fee must never fall below this, or the node would reject it with
/// FeeTooSmallUTxO.
fn ledger_linear_floor(fixture: &Fixture, built: &BuiltPoeTx) -> u64 {
    fixture.protocol.min_fee_a * built.total_size + fixture.protocol.min_fee_b
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn report_pins_only_the_known_divergence_classes() {
    let report = load_parity_report();
    let pinned: BTreeSet<&str> = report
        .known_divergence_classes
        .iter()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = KNOWN_CLASSES.iter().copied().collect();
    assert_eq!(
        pinned, expected,
        "the report's known_divergence_classes must match the pinned set; \
         a new class means an unreviewed encoding divergence appeared"
    );

    // No case may carry a divergence class outside the known set.
    for case in &report.cases {
        for class in &case.divergence_classes {
            assert!(
                expected.contains(class.as_str()),
                "{}: unclassified divergence class {class:?}",
                case.case
            );
        }
    }
}

#[test]
fn report_covers_exactly_the_buildable_corpus_cases() {
    let report = load_parity_report();
    let reported: BTreeSet<&str> = report.cases.iter().map(|c| c.case.as_str()).collect();
    let buildable: BTreeSet<String> = load_all()
        .into_iter()
        .filter(|f| f.expect == "ok")
        .map(|f| f.name)
        .collect();
    let buildable_refs: BTreeSet<&str> = buildable.iter().map(String::as_str).collect();
    assert_eq!(
        reported, buildable_refs,
        "the parity report must cover exactly the buildable corpus cases"
    );
}

#[test]
fn every_case_meets_the_ledger_fee_floor_over_its_exact_bytes() {
    // The HARD guarantee: the builder's fee is at least the ledger linear fee
    // over the exact bytes it submits, so FeeTooSmallUTxO is impossible by
    // construction. The report's `fee_csl_floor_ok` must agree.
    let report = load_parity_report();
    for fixture in load_all() {
        if fixture.expect != "ok" {
            continue;
        }
        let built = build_fixture(&fixture);
        let floor = ledger_linear_floor(&fixture, &built);
        assert!(
            built.fee >= floor,
            "{}: fee {} below ledger floor {floor}",
            fixture.name,
            built.fee
        );

        let case = report
            .cases
            .iter()
            .find(|c| c.case == fixture.name)
            .unwrap_or_else(|| panic!("{} missing from parity report", fixture.name));
        assert!(
            case.fee_csl_floor_ok,
            "{}: report claims the fee floor does not hold",
            fixture.name
        );
    }
}

#[test]
fn builder_exhibits_the_structural_facts_each_case_claims() {
    // For every case, re-derive from the live builder the structural facts that
    // justify the divergence classes the report lists, so the report can never
    // claim a class the builder no longer produces (or omit one it does).
    let report = load_parity_report();
    for fixture in load_all() {
        if fixture.expect != "ok" {
            continue;
        }
        let built = build_fixture(&fixture);
        let case = report
            .cases
            .iter()
            .find(|c| c.case == fixture.name)
            .unwrap_or_else(|| panic!("{} missing from parity report", fixture.name));
        let classes: BTreeSet<&str> = case.divergence_classes.iter().map(String::as_str).collect();

        // network-id and aux-data-format are present for every buildable case:
        // the builder always sets the body network_id and always emits Conway
        // tag-259 auxiliary data.
        assert!(
            body_sets_network_id(&built),
            "{}: body must set network_id",
            fixture.name
        );
        assert!(
            classes.contains("network-id"),
            "{}: report must list network-id",
            fixture.name
        );

        assert!(
            aux_is_conway_tag_259(&built),
            "{}: aux must be Conway tag-259",
            fixture.name
        );
        assert!(
            classes.contains("aux-data-format"),
            "{}: report must list aux-data-format",
            fixture.name
        );

        // output-format is present exactly when the build emits a change
        // output: a folded (no-change) build has no output to encode, so it
        // carries no output-format divergence.
        let has_change_output = built.change.is_some();
        if has_change_output {
            assert!(
                outputs_are_babbage_map(&built),
                "{}: change output must be the Babbage map form",
                fixture.name
            );
            assert!(
                classes.contains("output-format"),
                "{}: change-bearing case must list output-format",
                fixture.name
            );
        } else {
            let body: TransactionBody = minicbor::decode(&built.body_bytes).expect("decode body");
            assert!(
                body.outputs.is_empty(),
                "{}: folded case must have no outputs",
                fixture.name
            );
            assert!(
                !classes.contains("output-format"),
                "{}: folded case must not list output-format",
                fixture.name
            );
        }
    }
}

#[test]
fn lucid_status_matches_whether_the_build_folds() {
    // Lucid's balancer cannot fold the whole value into the fee, so a no-change
    // build is reported as `no-change-fold` and a change-bearing build as
    // `built`. Re-derive the fold/keep decision from the builder and check it.
    let report = load_parity_report();
    for fixture in load_all() {
        if fixture.expect != "ok" {
            continue;
        }
        let built = build_fixture(&fixture);
        let case = report
            .cases
            .iter()
            .find(|c| c.case == fixture.name)
            .unwrap_or_else(|| panic!("{} missing from parity report", fixture.name));
        let expected = if built.change.is_some() {
            "built"
        } else {
            "no-change-fold"
        };
        assert_eq!(
            case.lucid_status, expected,
            "{}: lucid_status must reflect whether the build folds",
            fixture.name
        );
    }
}
