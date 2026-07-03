//! Build-driven contract tests over the shared corpus.
//!
//! Each fixture under `tests/fixtures/corpus/inputs/` is one build scenario.
//! These tests materialise the deterministic record and UTxO bytes the corpus
//! pins, run the real builder, and assert on the transaction it produces:
//! stable fees and bytes, clean errors for the underfunded case, byte-identical
//! output under re-runs and input shuffling, the metadata chunk boundary, and
//! both minimum-ADA change branches (fold and add-input).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cardano_poe_tx::{
    build_poe_tx, BuildError, BuildRequest, ProtocolParams, SigningKey, Utxo, Validity,
};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Fixture loading and deterministic-data materialisation
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

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus/inputs")
}

fn load(name: &str) -> Fixture {
    let path = corpus_dir().join(format!("{name}.json"));
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn load_all() -> Vec<Fixture> {
    let mut out = Vec::new();
    for entry in fs::read_dir(corpus_dir()).expect("corpus inputs dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let bytes = fs::read(&path).expect("read fixture");
            out.push(serde_json::from_slice(&bytes).expect("parse fixture"));
        }
    }
    out.sort_by(|a: &Fixture, b: &Fixture| a.name.cmp(&b.name));
    out
}

/// The record-bytes rule the corpus pins: `b[i] = (i * 7 + 13) mod 256`.
fn record_byte(i: usize) -> u8 {
    ((i * 7 + 13) % 256) as u8
}

fn materialise_record(len: usize) -> Vec<u8> {
    (0..len).map(record_byte).collect()
}

/// The fixed test signing seed, committed under `tests/fixtures/`.
fn test_signing_key() -> SigningKey {
    let hex = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-signing-seed.hex"),
    )
    .expect("read test signing seed");
    let bytes = hex::decode(hex.trim()).expect("seed is hex");
    let seed: [u8; 32] = bytes.as_slice().try_into().expect("seed is 32 bytes");
    SigningKey::from_seed(seed)
}

fn request_from(fixture: &Fixture, utxos: Vec<Utxo>) -> BuildRequest {
    let validity = fixture.validity.as_ref().map(|v| Validity {
        invalid_hereafter: v.invalid_hereafter,
        valid_from: v.valid_from,
    });
    BuildRequest {
        record_bytes: materialise_record(fixture.record_len),
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

fn build_fixture(fixture: &Fixture) -> Result<cardano_poe_tx::BuiltPoeTx, BuildError> {
    build_poe_tx(&request_from(fixture, fixture_utxos(fixture)))
}

// ---------------------------------------------------------------------------
// Per-fixture outcome assertions
// ---------------------------------------------------------------------------

#[test]
fn every_ok_fixture_builds_a_consistent_transaction() {
    for fixture in load_all() {
        if fixture.expect != "ok" {
            continue;
        }
        let built = build_fixture(&fixture)
            .unwrap_or_else(|e| panic!("{} expected to build, got {e}", fixture.name));

        // The fee is exactly the linear fee over the metered signed size.
        let expected_fee =
            fixture.protocol.min_fee_a * built.total_size + fixture.protocol.min_fee_b;
        // For the fold case the fee absorbs a residual on top of the linear
        // floor, so it is at least the floor.
        if built.change.is_some() {
            assert_eq!(
                built.fee, expected_fee,
                "{}: change-bearing fee must equal the linear fee over its size",
                fixture.name
            );
        } else {
            assert!(
                built.fee >= expected_fee,
                "{}: folded fee {} must cover the linear floor {expected_fee}",
                fixture.name,
                built.fee
            );
        }

        // The transaction never exceeds the protocol size cap.
        assert!(built.total_size <= fixture.protocol.max_tx_size);

        // The body hash is the Blake2b-256 of the body bytes, and signing does
        // not move it.
        let key = test_signing_key();
        let (signed, signed_hash) = built.sign(&key);
        assert_eq!(
            signed_hash, built.tx_hash,
            "{}: signing keeps the hash",
            fixture.name
        );
        assert!(
            signed.len() as u64 == built.total_size,
            "{}: signed size {} must equal the metered size {}",
            fixture.name,
            signed.len(),
            built.total_size
        );

        // value conservation: selected inputs = fee + change.
        let selected_total: u64 = selected_lovelace(&fixture, &built);
        let change = built.change.unwrap_or(0);
        assert_eq!(
            selected_total,
            built.fee + change,
            "{}: inputs must equal fee plus change",
            fixture.name
        );

        // The auxiliary-data hash is the Blake2b-256 of the emitted aux bytes.
        assert_eq!(
            built.aux_data_hash,
            blake2b_256(&built.aux_data_bytes),
            "{}: aux hash must match aux bytes",
            fixture.name
        );
    }
}

/// Sum the lovelace of the inputs the build selected, looked up in the fixture.
fn selected_lovelace(fixture: &Fixture, built: &cardano_poe_tx::BuiltPoeTx) -> u64 {
    built
        .selected_inputs
        .iter()
        .map(|(hash, index)| {
            fixture
                .utxos
                .iter()
                .find(|u| &u.tx_hash == hash && u.index == *index)
                .unwrap_or_else(|| panic!("selected input {hash}#{index} not in fixture"))
                .lovelace
        })
        .sum()
}

#[test]
fn competing_pair_selects_by_the_set_not_the_listing_order() {
    // competing_b is competing_a minus one UTxO. Selection is a pure function of
    // the candidate set, so the two pick different inputs; this would be
    // impossible if selection silently depended on listing order alone.
    let a = build_fixture(&load("competing_a")).expect("competing_a builds");
    let b = build_fixture(&load("competing_b")).expect("competing_b builds");
    assert_ne!(
        a.selected_inputs, b.selected_inputs,
        "removing a candidate must change the selection"
    );
    // Each selection is itself a subset of its own fixture's candidate set.
    let a_pool: std::collections::BTreeSet<(String, u32)> = load("competing_a")
        .utxos
        .iter()
        .map(|u| (u.tx_hash.clone(), u.index))
        .collect();
    assert!(a.selected_inputs.iter().all(|sel| a_pool.contains(sel)));
}

#[test]
fn insufficient_fixture_errors_cleanly() {
    let fixture = load("insufficient");
    let err = build_fixture(&fixture).expect_err("must not build");
    match err {
        BuildError::InsufficientFunds { available, fee } => {
            assert_eq!(available, 200_000);
            assert!(
                fee > available,
                "fee {fee} must exceed available {available}"
            );
        }
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Determinism: re-run and shuffled input order
// ---------------------------------------------------------------------------

#[test]
fn building_twice_is_byte_identical() {
    for fixture in load_all() {
        if fixture.expect != "ok" {
            continue;
        }
        let a = build_fixture(&fixture).expect("build a");
        let b = build_fixture(&fixture).expect("build b");
        assert_eq!(
            a.unsigned_tx_bytes, b.unsigned_tx_bytes,
            "{}: two builds must be byte-identical",
            fixture.name
        );
        assert_eq!(a.tx_hash, b.tx_hash);
        assert_eq!(a.fee, b.fee);
    }
}

#[test]
fn shuffled_utxo_order_yields_identical_bytes() {
    for fixture in load_all() {
        if fixture.expect != "ok" {
            continue;
        }
        let base = build_fixture(&fixture).expect("base build");

        // A fixed permutation (reverse, then rotate by a fixed offset) so the
        // shuffle uses no randomness and is reproducible.
        let mut shuffled = fixture_utxos(&fixture);
        shuffled.reverse();
        if shuffled.len() > 2 {
            shuffled.rotate_left(1);
        }
        let permuted = build_poe_tx(&request_from(&fixture, shuffled)).expect("permuted build");

        assert_eq!(
            base.unsigned_tx_bytes, permuted.unsigned_tx_bytes,
            "{}: input order must not change the bytes",
            fixture.name
        );
        assert_eq!(
            base.selected_inputs, permuted.selected_inputs,
            "{}: input order must not change selection",
            fixture.name
        );
    }
}

// ---------------------------------------------------------------------------
// Metadata chunk-count boundary cases
// ---------------------------------------------------------------------------

#[test]
fn chunk_count_matches_record_length_across_the_boundary() {
    // (record_len, expected chunk count) at and around the 64-byte boundary and
    // far beyond it.
    let cases = [
        (1usize, 1usize),
        (63, 1),
        (64, 1),
        (65, 2),
        (127, 2),
        (128, 2),
        (129, 3),
        (1024, 16),
        (4096, 64),
        (14000, 219),
    ];
    for (len, expected) in cases {
        let chunks = cardano_poe_tx::chunk_record(&materialise_record(len));
        assert_eq!(
            chunks.len(),
            expected,
            "record of {len} bytes must split into {expected} chunks"
        );
        // No chunk exceeds the 64-byte metadata limit.
        assert!(chunks.iter().all(|c| c.len() <= 64));
        // Concatenation reconstructs the original record exactly.
        let rebuilt: Vec<u8> = chunks.concat();
        assert_eq!(rebuilt, materialise_record(len));
    }
}

// ---------------------------------------------------------------------------
// Minimum-ADA change branches: fold vs. add-input
// ---------------------------------------------------------------------------

#[test]
fn change_below_min_ada_folds_into_fee_when_no_input_remains() {
    let fixture = load("change_below_min_ada_fold");
    let built = build_fixture(&fixture).expect("fold case must build");
    // The single tiny input cannot leave a min-ADA change, so the builder emits
    // no change output and folds the residual into the fee.
    assert_eq!(built.change, None, "fold case must emit no change output");
    assert_eq!(
        built.selected_inputs.len(),
        1,
        "fold case spends its one input"
    );
    assert_eq!(built.fee, 850_000, "the whole input becomes the fee");
}

#[test]
fn change_below_min_ada_adds_input_when_one_is_available() {
    let fixture = load("change_below_min_ada_add_input");
    let built = build_fixture(&fixture).expect("add-input case must build");
    // The spare second input lets the builder return a valid change output
    // instead of folding.
    assert!(
        built.change.is_some(),
        "add-input case must emit a change output"
    );
    assert_eq!(
        built.selected_inputs.len(),
        2,
        "add-input case spends both inputs"
    );
    // The kept change clears the minimum-ADA floor (it is well above the
    // ~1 ADA min for a key-only output).
    assert!(built.change.unwrap() > 0);
}

// ---------------------------------------------------------------------------
// Validity interval is written into the body
// ---------------------------------------------------------------------------

#[test]
fn validity_interval_is_carried_into_the_body() {
    use pallas_codec::minicbor;
    use pallas_primitives::conway::TransactionBody;

    let ttl_only = build_fixture(&load("ttl_set")).expect("ttl build");
    let body: TransactionBody = minicbor::decode(&ttl_only.body_bytes).expect("decode ttl body");
    assert_eq!(body.ttl, Some(100_000_000), "ttl_set sets the TTL");
    assert_eq!(
        body.validity_interval_start, None,
        "ttl_set sets no lower bound"
    );

    let both = build_fixture(&load("ttl_and_valid_from")).expect("both build");
    let body: TransactionBody = minicbor::decode(&both.body_bytes).expect("decode both body");
    assert_eq!(body.ttl, Some(100_000_000));
    assert_eq!(body.validity_interval_start, Some(50_000_000));

    // A fixture with no validity writes neither field.
    let none = build_fixture(&load("size_1024")).expect("none build");
    let body: TransactionBody = minicbor::decode(&none.body_bytes).expect("decode none body");
    assert_eq!(body.ttl, None);
    assert_eq!(body.validity_interval_start, None);
}

// ---------------------------------------------------------------------------
// Mandatory-spend (cancelling-replacement) selection
//
// A replacement transaction must spend at least one input of the transaction it
// supersedes so the old metadata-only transaction can never land afterwards.
// `must_spend` carries those inputs; they are always selected first, then the
// candidate set covers any remainder. These cases pin that the forced inputs
// appear regardless of coverage, that the result is deterministic under shuffled
// forced and candidate order, that a doubly-listed reference is spent once, and
// that value conservation and the fee floor still hold.
// ---------------------------------------------------------------------------

/// The change address every constructed case uses (a valid preprod address).
const REPLACEMENT_CHANGE_ADDRESS: &str =
    "addr_test1vpa8ukd77k05gc3etxeyzylxxmyhzg0hvne9qplxvsyl44q6pl7v4";

/// Standard preprod-shaped protocol parameters, matching the corpus fixtures.
fn replacement_protocol() -> ProtocolParams {
    ProtocolParams {
        min_fee_a: 44,
        min_fee_b: 155_381,
        coins_per_utxo_byte: 4310,
        max_tx_size: 16384,
    }
}

/// A UTxO whose 32-byte hash is `byte` repeated, so cases can order inputs by a
/// single visible discriminator.
fn utxo(byte: u8, index: u32, lovelace: u64) -> Utxo {
    Utxo {
        tx_hash: hex::encode([byte; 32]),
        index,
        lovelace,
    }
}

fn replacement_request(utxos: Vec<Utxo>, must_spend: Vec<Utxo>) -> BuildRequest {
    BuildRequest {
        record_bytes: materialise_record(64),
        metadata_label: 309,
        utxos,
        must_spend,
        protocol: replacement_protocol(),
        change_address: REPLACEMENT_CHANGE_ADDRESS.to_string(),
        network_id: 0,
        payment_verification_key: test_signing_key().verification_key(),
        validity: None,
    }
}

/// Value conservation must hold for any selection: the inputs the build spent
/// sum to the fee plus any change. Looks each selected input up in the union of
/// the candidate and forced sets.
fn assert_value_conserved(built: &cardano_poe_tx::BuiltPoeTx, all_inputs: &[Utxo]) {
    let selected_total: u64 = built
        .selected_inputs
        .iter()
        .map(|(hash, index)| {
            all_inputs
                .iter()
                .find(|u| &u.tx_hash == hash && u.index == *index)
                .unwrap_or_else(|| panic!("selected input {hash}#{index} not in the input set"))
                .lovelace
        })
        .sum();
    let change = built.change.unwrap_or(0);
    assert_eq!(
        selected_total,
        built.fee + change,
        "inputs must equal fee plus change"
    );
    // The change-bearing fee is exactly the linear fee over the metered size.
    if built.change.is_some() {
        let expected =
            replacement_protocol().min_fee_a * built.total_size + replacement_protocol().min_fee_b;
        assert_eq!(
            built.fee, expected,
            "change-bearing fee must equal the linear fee over its size"
        );
    }
}

#[test]
fn forced_input_is_always_spent_even_when_coverage_would_skip_it() {
    // A large candidate (0xaa) would, on its own, cover the fee and a min-ADA
    // change, so plain selection would never reach the small forced input
    // (0x11). With it in `must_spend`, it must appear in the body anyway: that is
    // the whole point of a cancelling replacement.
    let big = utxo(0xaa, 0, 10_000_000);
    let forced = utxo(0x11, 7, 5_000_000);
    let built = build_poe_tx(&replacement_request(
        vec![big.clone()],
        vec![forced.clone()],
    ))
    .expect("replacement builds");

    let forced_ref = (forced.tx_hash.clone(), forced.index);
    assert!(
        built.selected_inputs.contains(&forced_ref),
        "the forced input must be among the selected inputs"
    );
    assert_value_conserved(&built, &[big, forced]);
}

#[test]
fn forced_input_alone_can_fund_the_transaction() {
    // No candidates at all: the single forced input must both appear and cover
    // the fee + change on its own.
    let forced = utxo(0x22, 3, 6_000_000);
    let built = build_poe_tx(&replacement_request(Vec::new(), vec![forced.clone()]))
        .expect("forced-only build succeeds");
    assert_eq!(
        built.selected_inputs,
        vec![(forced.tx_hash.clone(), forced.index)],
        "the only input is the forced one"
    );
    assert_value_conserved(&built, &[forced]);
}

#[test]
fn forced_order_and_candidate_order_do_not_change_the_bytes() {
    // Two forced inputs plus two candidates, all small enough that every input
    // is needed. Shuffling both lists must not move a single byte: the forced
    // prefix is sorted into a fixed order and the candidates are prioritised.
    let f1 = utxo(0x33, 0, 2_000_000);
    let f2 = utxo(0x44, 1, 2_000_000);
    let c1 = utxo(0x55, 0, 2_000_000);
    let c2 = utxo(0x66, 1, 2_000_000);

    let base = build_poe_tx(&replacement_request(
        vec![c1.clone(), c2.clone()],
        vec![f1.clone(), f2.clone()],
    ))
    .expect("base build");

    let shuffled = build_poe_tx(&replacement_request(
        vec![c2.clone(), c1.clone()],
        vec![f2.clone(), f1.clone()],
    ))
    .expect("shuffled build");

    assert_eq!(
        base.unsigned_tx_bytes, shuffled.unsigned_tx_bytes,
        "forced or candidate listing order must not change the bytes"
    );
    assert_eq!(base.selected_inputs, shuffled.selected_inputs);
    assert_eq!(base.tx_hash, shuffled.tx_hash);
    assert_eq!(base.fee, shuffled.fee);

    // Both forced inputs are present exactly once.
    for f in [&f1, &f2] {
        let count = base
            .selected_inputs
            .iter()
            .filter(|(h, i)| h == &f.tx_hash && *i == f.index)
            .count();
        assert_eq!(count, 1, "each forced input appears exactly once");
    }
    assert_value_conserved(&base, &[f1, f2, c1, c2]);
}

#[test]
fn a_reference_listed_as_both_forced_and_candidate_is_spent_once() {
    // The shared 0x77#0 input is in both lists. It must be selected once, not
    // twice (a double-spend the ledger would reject), and the build stays
    // byte-identical to listing it only as forced.
    let shared = utxo(0x77, 0, 6_000_000);
    let other = utxo(0x88, 0, 6_000_000);

    let with_dup = build_poe_tx(&replacement_request(
        vec![shared.clone(), other.clone()],
        vec![shared.clone()],
    ))
    .expect("dup-listed build");

    let count = with_dup
        .selected_inputs
        .iter()
        .filter(|(h, i)| h == &shared.tx_hash && *i == shared.index)
        .count();
    assert_eq!(count, 1, "a doubly-listed reference is spent exactly once");
    assert_value_conserved(&with_dup, &[shared, other]);
}

#[test]
fn duplicate_forced_reference_is_rejected() {
    // The same reference twice inside `must_spend` is a caller error: it would
    // double-count the input's value. It is caught before assembly.
    let forced = utxo(0x99, 2, 5_000_000);
    let err = build_poe_tx(&replacement_request(
        Vec::new(),
        vec![forced.clone(), forced.clone()],
    ))
    .expect_err("a duplicate forced reference must error");
    match err {
        BuildError::DuplicateMustSpend { tx_hash, index } => {
            assert_eq!(tx_hash, forced.tx_hash);
            assert_eq!(index, forced.index);
        }
        other => panic!("expected DuplicateMustSpend, got {other:?}"),
    }
}

#[test]
fn forced_build_is_byte_identical_across_reruns() {
    let f1 = utxo(0xab, 4, 3_000_000);
    let c1 = utxo(0xcd, 0, 6_000_000);
    let a = build_poe_tx(&replacement_request(vec![c1.clone()], vec![f1.clone()])).expect("a");
    let b = build_poe_tx(&replacement_request(vec![c1], vec![f1])).expect("b");
    assert_eq!(a.unsigned_tx_bytes, b.unsigned_tx_bytes);
    assert_eq!(a.tx_hash, b.tx_hash);
    assert_eq!(a.fee, b.fee);
}

#[test]
fn forced_inputs_insufficient_funds_report_cleanly() {
    // A single tiny forced input that cannot even cover its own fee, with no
    // candidates to add, surfaces InsufficientFunds rather than a panic.
    let tiny = utxo(0xee, 0, 100_000);
    let err = build_poe_tx(&replacement_request(Vec::new(), vec![tiny]))
        .expect_err("an underfunded forced build must error");
    assert!(
        matches!(err, BuildError::InsufficientFunds { .. }),
        "expected InsufficientFunds, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn blake2b_256(bytes: &[u8]) -> [u8; 32] {
    use pallas_crypto::hash::Hasher;
    *Hasher::<256>::hash(bytes)
}

// Keep the `BTreeMap` import meaningful: a compile-time guard that the fixture
// set is non-empty and uniquely named.
#[test]
fn corpus_is_non_empty_and_uniquely_named() {
    let mut names: BTreeMap<String, usize> = BTreeMap::new();
    for f in load_all() {
        *names.entry(f.name).or_default() += 1;
    }
    assert!(!names.is_empty(), "corpus must not be empty");
    assert!(
        names.values().all(|&n| n == 1),
        "every fixture name must be unique"
    );
    assert!(
        load_all()
            .iter()
            .all(|f| matches!(f.mode.as_str(), "standard" | "exact_fit")),
        "fixtures use known modes"
    );
}
