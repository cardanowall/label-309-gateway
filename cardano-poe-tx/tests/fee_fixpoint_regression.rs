//! Regression tests for the fee fixpoint's coin-width cycle.
//!
//! When the change lands within one fee-step of the 2^32-lovelace CBOR
//! coin-width boundary, no exact fee fixpoint exists: the higher fee narrows
//! the change to a 4-byte coin (implying the lower fee) and the lower fee
//! widens it back to an 8-byte coin (implying the higher fee). The builder
//! must resolve that cycle by keeping the change and charging the cycle's
//! larger fee — a one-width-step overpay of a few hundred lovelace — never by
//! folding the whole ~4295 ADA change into the fee.

use std::fs;
use std::path::Path;

use cardano_poe_tx::{build_poe_tx, BuildRequest, ProtocolParams, SigningKey, Utxo};

/// A valid preprod enterprise address, matching the corpus fixtures.
const CHANGE_ADDRESS: &str = "addr_test1vpa8ukd77k05gc3etxeyzylxxmyhzg0hvne9qplxvsyl44q6pl7v4";

const MIN_FEE_A: u64 = 44;
const MIN_FEE_B: u64 = 155_381;

/// The CBOR coin-width boundary the fixpoint can straddle: coins at or above
/// 2^32 lovelace encode as 8-byte uints, below as 4-byte uints.
const WIDTH_BOUNDARY: u64 = 1 << 32;

fn protocol() -> ProtocolParams {
    ProtocolParams {
        min_fee_a: MIN_FEE_A,
        min_fee_b: MIN_FEE_B,
        coins_per_utxo_byte: 4310,
        max_tx_size: 16384,
    }
}

fn test_verification_key() -> [u8; 32] {
    let hex = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-signing-seed.hex"),
    )
    .expect("read test signing seed");
    let bytes = hex::decode(hex.trim()).expect("seed is hex");
    let seed: [u8; 32] = bytes.as_slice().try_into().expect("seed is 32 bytes");
    SigningKey::from_seed(seed).verification_key()
}

/// A single-UTxO build request carrying `lovelace`, so the change is exactly
/// the input minus the fee and can be steered onto the width boundary.
fn request(lovelace: u64) -> BuildRequest {
    BuildRequest {
        record_bytes: (0..64usize).map(|i| ((i * 7 + 13) % 256) as u8).collect(),
        metadata_label: 309,
        utxos: vec![Utxo {
            tx_hash: hex::encode([0x42u8; 32]),
            index: 0,
            lovelace,
        }],
        must_spend: Vec::new(),
        protocol: protocol(),
        change_address: CHANGE_ADDRESS.to_string(),
        network_id: 0,
        payment_verification_key: test_verification_key(),
        validity: None,
    }
}

/// Learn the two stable fees around the boundary from builds that converge
/// safely away from it: the narrow-change shape (change < 2^32, 4-byte coin)
/// and the wide-change shape (change >= 2^32, 8-byte coin).
fn stable_fees() -> (u64, u64) {
    let narrow = build_poe_tx(&request(WIDTH_BOUNDARY)).expect("narrow-change build");
    assert!(narrow.change.expect("narrow build keeps change") < WIDTH_BOUNDARY);

    let wide = build_poe_tx(&request(WIDTH_BOUNDARY + 10_000_000)).expect("wide-change build");
    assert!(wide.change.expect("wide build keeps change") >= WIDTH_BOUNDARY);

    // The two shapes differ by exactly the coin-width step: four bytes of
    // change coin at min_fee_a lovelace each.
    assert_eq!(wide.fee, narrow.fee + 4 * MIN_FEE_A);
    (narrow.fee, wide.fee)
}

#[test]
fn width_boundary_two_cycle_keeps_change_regression() {
    let (fee_narrow, fee_wide) = stable_fees();

    // For every total in [2^32 + fee_narrow, 2^32 + fee_wide) the exact
    // fixpoint two-cycles: paying fee_wide leaves a narrow change (implying
    // fee_narrow) and paying fee_narrow leaves a wide change (implying
    // fee_wide). Sweep the whole window: the builder must keep the ~4295 ADA
    // change and charge fee_wide — never spend the entire input as fee.
    for total in (WIDTH_BOUNDARY + fee_narrow)..(WIDTH_BOUNDARY + fee_wide) {
        let built = build_poe_tx(&request(total))
            .unwrap_or_else(|e| panic!("total {total} must build, got {e}"));
        let change = built
            .change
            .unwrap_or_else(|| panic!("total {total}: change was burned into the fee"));
        assert_eq!(
            built.fee + change,
            total,
            "total {total}: inputs must equal fee plus change"
        );
        assert_eq!(
            built.fee, fee_wide,
            "total {total}: the cycle resolves to the larger stable fee"
        );
        // The emitted body carries a narrow change coin, so the fee overpays
        // its exact linear floor by exactly the four-byte width step.
        let floor = MIN_FEE_A * built.total_size + MIN_FEE_B;
        assert_eq!(
            built.fee,
            floor + 4 * MIN_FEE_A,
            "total {total}: overpay is one coin-width step, not the change"
        );
        assert!(
            change > 4_000 * 1_000_000,
            "total {total}: the ~4295 ADA change is retained"
        );
    }
}

#[test]
fn width_boundary_window_edges_converge_to_the_exact_fee() {
    let (fee_narrow, fee_wide) = stable_fees();

    // One lovelace below the window the fixpoint converges on the narrow
    // shape with an exact fee and no overpay...
    let below =
        build_poe_tx(&request(WIDTH_BOUNDARY + fee_narrow - 1)).expect("below-window build");
    assert_eq!(below.fee, fee_narrow);
    assert_eq!(below.change, Some(WIDTH_BOUNDARY - 1));
    assert_eq!(below.fee, MIN_FEE_A * below.total_size + MIN_FEE_B);

    // ...and at the window's top edge it converges on the wide shape.
    let above = build_poe_tx(&request(WIDTH_BOUNDARY + fee_wide)).expect("top-edge build");
    assert_eq!(above.fee, fee_wide);
    assert_eq!(above.change, Some(WIDTH_BOUNDARY));
    assert_eq!(above.fee, MIN_FEE_A * above.total_size + MIN_FEE_B);
}

#[test]
fn dust_residual_still_folds_into_the_fee() {
    // A single input too small to leave a minimum-ADA change: the whole input
    // is legitimately spent as fee with no change output. This is the only
    // shape allowed to fold, and the fold stays bounded by the min-ADA floor.
    let built = build_poe_tx(&request(850_000)).expect("dust build");
    assert_eq!(built.change, None, "dust residual folds; no change output");
    assert_eq!(built.fee, 850_000, "the whole input becomes the fee");
    assert!(built.fee >= MIN_FEE_A * built.total_size + MIN_FEE_B);
}
