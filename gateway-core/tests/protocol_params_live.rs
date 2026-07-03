//! Live network round-trip against the keyless preprod Koios endpoint.
//!
//! This is the one test that touches the network. It is gated on
//! `GATEWAY_LIVE_TESTS=1` and skips (passing trivially) when that variable is
//! unset, so CI and the default `cargo test` never make an outbound request. Run
//! it deliberately with:
//!
//! ```text
//! GATEWAY_LIVE_TESTS=1 cargo test -p gateway-core --test protocol_params_live -- --nocapture
//! ```
//!
//! It needs no database: it exercises only the source's fetch path.

use gateway_core::chain::params::{KoiosParamsSource, Network, ProtocolParamsSource};

/// A keyless preprod fetch returns a plausible current epoch and non-trivial fee
/// parameters. Prints the fetched values so a manual run can record them.
#[tokio::test]
async fn keyless_preprod_round_trip() {
    if std::env::var("GATEWAY_LIVE_TESTS").as_deref() != Ok("1") {
        eprintln!("skipping live Koios round-trip: set GATEWAY_LIVE_TESTS=1 to enable");
        return;
    }

    let source = KoiosParamsSource::new(Default::default()).expect("build Koios source");

    let epoch = source
        .current_epoch(Network::Preprod)
        .await
        .expect("fetch current epoch from preprod /tip");
    assert!(epoch > 0, "preprod is well past epoch 0");

    let params = source
        .fetch_params(Network::Preprod, epoch)
        .await
        .expect("fetch epoch_params from preprod");

    assert_eq!(params.epoch, epoch, "fetched the requested epoch");
    // The Cardano fee parameters have been non-zero for the entire life of the
    // network; a zero here would mean the provider shape drifted.
    assert!(params.min_fee_a > 0, "min_fee_a must be positive");
    assert!(params.min_fee_b > 0, "min_fee_b must be positive");
    assert!(
        params.coins_per_utxo_byte > 0,
        "coins_per_utxo_byte must be positive"
    );
    assert!(params.max_tx_size > 0, "max_tx_size must be positive");

    eprintln!(
        "live preprod params: epoch={} min_fee_a={} min_fee_b={} coins_per_utxo_byte={} max_tx_size={}",
        params.epoch,
        params.min_fee_a,
        params.min_fee_b,
        params.coins_per_utxo_byte,
        params.max_tx_size,
    );
}
