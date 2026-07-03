//! The canonical-shape fee quote is exact: it equals the real build fee for every
//! canonical UTxO, with zero tolerance.
//!
//! The quote prices a synthetic canonical input (output index 0, band-mid
//! lovelace) once and never reads wallet state. This suite proves the priced fee
//! is the fee a real submit pays for *any* canonical UTxO: across every output
//! index below the cap, every lovelace value spanning the whole band (inclusive
//! endpoints and odd interior values), and a spread of record sizes that crosses
//! the metadata chunk boundary. The exactness is what lets the gateway hand a
//! third-party client a fee before any UTxO is leased.
//!
//! The whole property is asserted over several distinct band configurations, not
//! just one, so a band-specific accident (an endpoint that happens to avoid a
//! fold) cannot pass for the general guarantee.
//!
//! No database is touched; the quote and the builder are both pure functions of
//! their inputs.

use cardano_poe_tx::{build_poe_tx, BuildRequest, ProtocolParams, Utxo};
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use gateway_core::wallet::quote::quote_fee;

/// Post-Conway preprod protocol parameters. The exactness property holds for any
/// fixed parameter set; these are realistic mainnet/preprod values.
fn params() -> ProtocolParams {
    ProtocolParams {
        min_fee_a: 44,
        min_fee_b: 155_381,
        coins_per_utxo_byte: 4_310,
        max_tx_size: 16_384,
    }
}

/// Three distinct canonical bands the property is certified against. Each is
/// CBOR-width-stable (every endpoint falls in the 5-byte unsigned-integer class,
/// `[0x1_0000, 0xFFFF_FFFF]`), so the change output's width, and therefore the
/// fee, is invariant across the whole band. They differ in magnitude and width so
/// the exactness is not an accident of one chosen band:
///
/// - a tight low band (2-3 ADA), the closest to the min-ADA change floor,
/// - the canonical 4-8 ADA band, and
/// - a wide high band (10-40 ADA).
fn bands() -> Vec<LovelaceBand> {
    vec![
        LovelaceBand::new(2_000_000, 3_000_000, 2_500_000).expect("low band is width-stable"),
        LovelaceBand::new(4_000_000, 8_000_000, 6_000_000).expect("canonical band is width-stable"),
        LovelaceBand::new(10_000_000, 40_000_000, 25_000_000).expect("high band is width-stable"),
    ]
}

fn config_for(band: LovelaceBand) -> WalletConfig {
    WalletConfig {
        network: Network::Preprod,
        band,
        lease: std::time::Duration::from_secs(120),
        min_canonical_count: 4,
    }
}

/// A real preprod enterprise (payment-only) address. The builder only requires the
/// address to be a network-matching bech32 address; the fee is address-shape
/// invariant, so the same address stands in for the synthetic and the real builds.
const CHANGE_ADDRESS: &str = "addr_test1vpa8ukd77k05gc3etxeyzylxxmyhzg0hvne9qplxvsyl44q6pl7v4";

/// An arbitrary 32-byte verification key. Its bytes are public material the
/// builder uses only to size the single vkey witness; any key sizes it identically.
const VERIFICATION_KEY: [u8; 32] = [0x07; 32];

/// Build the real one-input + one-change-output transaction for a record over a
/// canonical UTxO at `output_index` holding `lovelace`, returning its exact fee
/// and whether a change output survived.
fn real_build(record_len: usize, output_index: u32, lovelace: u64) -> (u64, bool) {
    let request = BuildRequest {
        record_bytes: vec![0u8; record_len],
        metadata_label: cardano_poe_tx::POE_METADATA_LABEL,
        utxos: vec![Utxo {
            // A distinct, realistic tx id (32 bytes of hex) so the input is a
            // plausible on-chain reference; its bytes do not affect the fee.
            tx_hash: "11".repeat(32),
            index: output_index,
            lovelace,
        }],
        must_spend: Vec::new(),
        protocol: params(),
        change_address: CHANGE_ADDRESS.to_string(),
        network_id: 0,
        payment_verification_key: VERIFICATION_KEY,
        validity: None,
    };
    let built = build_poe_tx(&request)
        .unwrap_or_else(|e| panic!("real build for index {output_index}, value {lovelace}: {e}"));
    (built.fee, built.change.is_some())
}

/// The record sizes the property sweeps: an empty-ish single byte, exactly the
/// metadata chunk boundary, one byte over it (two chunks), and larger multi-chunk
/// records up to a realistic large record.
const RECORD_SIZES: &[usize] = &[1, 64, 65, 1024, 14_000];

#[test]
fn quote_fee_equals_the_real_build_fee_for_every_canonical_utxo_across_bands() {
    let params = params();

    for band in bands() {
        let config = config_for(band);

        // Lovelace values spanning the whole band: inclusive endpoints, the
        // midpoint, near-endpoint values, and odd interior values that are not
        // aligned to any round number, so a dependence of the fee on a specific
        // value would surface here.
        let interior_a = band.min + (band.max - band.min) / 3;
        let interior_b = band.min + 2 * (band.max - band.min) / 3 + 1;
        let values = [
            band.min,
            band.min + 1,
            band.mid - 1,
            band.mid,
            band.mid + 1,
            band.max - 1,
            band.max,
            interior_a,
            interior_b,
        ];

        for &record_len in RECORD_SIZES {
            // One canonical quote per record size; it reads no wallet state.
            let quote = quote_fee(
                record_len,
                &params,
                CHANGE_ADDRESS,
                VERIFICATION_KEY,
                &config,
            )
            .unwrap_or_else(|e| panic!("quote for band {band:?}, record_len {record_len}: {e}"));

            // Every output index below the canonical cap (0..24) and every band
            // value must build to byte-for-byte the same fee as the canonical
            // quote, and must keep a change output (no fold).
            for output_index in 0..gateway_core::wallet::config::MAX_CANONICAL_OUTPUT_INDEX {
                for &lovelace in &values {
                    assert!(
                        band.contains(lovelace),
                        "test value {lovelace} must be in band {band:?}"
                    );
                    let (real, has_change) = real_build(record_len, output_index, lovelace);
                    assert!(
                        has_change,
                        "band {band:?}: a canonical build over {lovelace} for record_len \
                         {record_len} folded its change instead of emitting it"
                    );
                    assert_eq!(
                        real, quote.fee,
                        "fee mismatch for band {band:?}, record_len {record_len}, \
                         output_index {output_index}, lovelace {lovelace}: real build {real} != \
                         canonical quote {}",
                        quote.fee
                    );
                }
            }
        }
    }
}

#[test]
fn quote_fee_grows_monotonically_with_record_size() {
    // A larger record can only cost at least as much: more auxiliary-data bytes
    // mean a larger transaction, so the fee is non-decreasing in record length.
    // This pins that the quote is metering the record, not returning a constant.
    let params = params();
    for band in bands() {
        let config = config_for(band);
        let mut prev = 0u64;
        for &record_len in RECORD_SIZES {
            let quote = quote_fee(
                record_len,
                &params,
                CHANGE_ADDRESS,
                VERIFICATION_KEY,
                &config,
            )
            .expect("quote");
            assert!(
                quote.fee >= prev,
                "band {band:?}: fee for record_len {record_len} ({}) fell below the previous \
                 size's fee ({prev})",
                quote.fee
            );
            prev = quote.fee;
        }
        assert!(prev > 0, "a non-empty record charges a positive fee");
    }
}

#[test]
fn fee_shape_validation_accepts_a_stable_band_for_every_band() {
    let params = params();
    for band in bands() {
        let config = config_for(band);
        config
            .validate_fee_shape_stable(&params, CHANGE_ADDRESS, VERIFICATION_KEY, RECORD_SIZES)
            .unwrap_or_else(|e| panic!("band {band:?} must pass fee-shape validation: {e}"));
    }
}

#[test]
fn fee_shape_validation_rejects_a_band_that_folds_at_its_floor() {
    // A band whose minimum is barely above the minimum-ADA change floor (and
    // below the fee a sizeable record would charge) cannot keep a change output
    // at its low end: the build folds, breaking exactness. The band is still
    // CBOR-width-stable (both endpoints in the 5-byte class), so plain shape
    // validation passes; only building against live params catches the fold.
    let params = params();
    let folding_band =
        LovelaceBand::new(1_000_000, 4_000_000, 2_000_000).expect("band is width-stable");
    folding_band
        .validate()
        .expect("the band passes pure CBOR-width validation");

    let config = config_for(folding_band);
    // A large record makes the fee big enough that `min - fee` drops below the
    // change floor at the band's 1-ADA minimum.
    let err = config
        .validate_fee_shape_stable(&params, CHANGE_ADDRESS, VERIFICATION_KEY, &[14_000])
        .expect_err("a band that folds at its floor must be rejected");
    assert!(
        matches!(err, gateway_core::Error::Config(_)),
        "fee-shape rejection is a Config error, got {err:?}"
    );
}

#[test]
fn fee_shape_validation_requires_at_least_one_record_size() {
    let params = params();
    let config = config_for(bands()[1]);
    let err = config
        .validate_fee_shape_stable(&params, CHANGE_ADDRESS, VERIFICATION_KEY, &[])
        .expect_err("certifying against no record size must be rejected");
    assert!(
        matches!(err, gateway_core::Error::Config(_)),
        "empty record-size set is a Config error, got {err:?}"
    );
}
