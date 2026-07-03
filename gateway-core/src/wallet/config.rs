//! Configuration for the operator-wallet subsystem.
//!
//! Every code path in this module is parameterised by these values rather than
//! hardcoding a network or an amount: a deployment supplies the network it runs
//! on, the lovelace band a canonical UTxO must fall in, how long a submit lease
//! lives, and how many canonical UTxOs each wallet should keep ready. The band
//! is the linchpin of the exact-quote guarantee (see [`crate::wallet::quote`]):
//! every canonical UTxO in the band serialises to the same CBOR width, so the
//! fee of a one-input transaction over any of them is identical.

use crate::{Error, Result};

/// The Cardano network the wallet subsystem operates on.
///
/// A typed enum rather than free text so a network-mismatched wallet (a preprod
/// address under a mainnet config, say) is a compile-checked variant the unlock
/// path can reject, not a stringly-typed comparison. The `production` predicate
/// gates the stub submitter so a stub can never be constructed on mainnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// The production network. A stub submitter is forbidden here.
    Mainnet,
    /// The pre-production test network.
    Preprod,
    /// The preview test network.
    Preview,
}

impl Network {
    /// The stable string stored in the `network` column and used in tracing.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Preprod => "preprod",
            Network::Preview => "preview",
        }
    }

    /// Parse the on-disk network discriminator.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "mainnet" => Ok(Network::Mainnet),
            "preprod" => Ok(Network::Preprod),
            "preview" => Ok(Network::Preview),
            other => Err(Error::Config(format!("unknown cardano network: {other}"))),
        }
    }

    /// The Cardano network id this network signs under: 1 for mainnet, 0 for
    /// every test network. This is the discriminant the transaction body and
    /// the address header carry.
    #[must_use]
    pub fn network_id(self) -> u8 {
        match self {
            Network::Mainnet => 1,
            Network::Preprod | Network::Preview => 0,
        }
    }

    /// Whether this is the production network. The stub submitter refuses to be
    /// constructed when this is true.
    #[must_use]
    pub fn is_production(self) -> bool {
        matches!(self, Network::Mainnet)
    }

    /// The bech32 human-readable part a payment address on this network carries:
    /// `addr` on mainnet, `addr_test` on every test network.
    #[must_use]
    pub fn address_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "addr",
            Network::Preprod | Network::Preview => "addr_test",
        }
    }

    /// The matching protocol-parameter / chain-provider network.
    ///
    /// Every wallet network has its own provider network with a working keyless
    /// endpoint, so the mapping is one-to-one: a preview wallet reads preview
    /// parameters from the preview provider, never preprod's. This is what makes
    /// the populate loop, the quote read path, and submit all agree on a single
    /// `network` key in the cache for a given deployment.
    #[must_use]
    pub fn to_params_network(self) -> crate::chain::params::Network {
        match self {
            Network::Mainnet => crate::chain::params::Network::Mainnet,
            Network::Preprod => crate::chain::params::Network::Preprod,
            Network::Preview => crate::chain::params::Network::Preview,
        }
    }
}

/// The lovelace band a canonical UTxO must fall within.
///
/// The band is closed (`min..=max`). `mid` is the value the replenisher targets
/// when splitting a source UTxO and the value the quote prices its synthetic
/// canonical input at. The exactness proof requires that every value in
/// `[min, max]` serialises to the same CBOR integer width, so a deployment must
/// pick a band whose endpoints share a width (validated by [`Self::validate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LovelaceBand {
    /// Inclusive lower bound a canonical UTxO's value must clear.
    pub min: u64,
    /// Inclusive upper bound a canonical UTxO's value must not exceed.
    pub max: u64,
    /// The target value the replenisher mints and the quote prices against.
    pub mid: u64,
}

impl LovelaceBand {
    /// Construct and validate a band.
    pub fn new(min: u64, max: u64, mid: u64) -> Result<Self> {
        let band = Self { min, max, mid };
        band.validate()?;
        Ok(band)
    }

    /// Whether `lovelace` falls inside the closed band.
    #[must_use]
    pub fn contains(&self, lovelace: u64) -> bool {
        lovelace >= self.min && lovelace <= self.max
    }

    /// Validate the band: `min <= mid <= max`, all positive, and the endpoints
    /// share a CBOR integer width so the canonical-shape fee is value-invariant
    /// across the whole band.
    ///
    /// The fee is metered over the signed transaction's serialised size, and the
    /// only value in that transaction that varies with which canonical UTxO is
    /// spent is the change output's coin (`input_lovelace - fee`). A CBOR
    /// unsigned integer's encoded width is a step function of its magnitude, so
    /// the change coin keeps a constant width across the band exactly when every
    /// value in the band shares one width. We require the endpoints to share a
    /// width, which (since width is monotonic in magnitude) forces every interior
    /// value to share it too. The fee subtracted before encoding the change is
    /// strictly less than `min`, so the change range `[min - fee, max - fee]`
    /// never crosses below the band's own width floor for any realistic fee; the
    /// property test pins the resulting fee equality byte-for-byte.
    pub fn validate(&self) -> Result<()> {
        if self.min == 0 {
            return Err(Error::Config(
                "the canonical lovelace band minimum must be positive".to_string(),
            ));
        }
        if !(self.min <= self.mid && self.mid <= self.max) {
            return Err(Error::Config(format!(
                "the canonical lovelace band must satisfy min <= mid <= max, got min={}, mid={}, max={}",
                self.min, self.mid, self.max
            )));
        }
        let min_width = cbor_uint_width(self.min);
        let max_width = cbor_uint_width(self.max);
        if min_width != max_width {
            return Err(Error::Config(format!(
                "the canonical lovelace band endpoints must share a CBOR integer width \
                 (min={} encodes in {} bytes, max={} encodes in {} bytes); a width change \
                 inside the band would make the canonical-shape fee value-dependent",
                self.min, min_width, self.max, max_width
            )));
        }
        Ok(())
    }
}

/// The number of bytes the CBOR encoding of an unsigned integer occupies.
///
/// CBOR encodes an unsigned integer in the major-type byte itself for values
/// below 24, then in a fixed-width tail of 1, 2, 4, or 8 bytes for the next
/// magnitude classes. The width is a monotonic step function of the value, so
/// two values sharing a width guarantees every value between them shares it.
#[must_use]
fn cbor_uint_width(value: u64) -> u8 {
    match value {
        0..=23 => 1,
        24..=0xFF => 2,
        0x100..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

/// The maximum output index a canonical UTxO may occupy.
///
/// A Cardano output index below this serialises as a single-byte CBOR integer,
/// keeping the change-output reference (and therefore the fee) width-stable. The
/// replenisher enforces this by construction: a split transaction emits at most
/// this many self-outputs, so every minted canonical UTxO lands below the cap.
pub const MAX_CANONICAL_OUTPUT_INDEX: u32 = 24;

/// The full configuration for the wallet subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletConfig {
    /// The network every wallet and submit is pinned to.
    pub network: Network,
    /// The lovelace band a canonical UTxO must fall within.
    pub band: LovelaceBand,
    /// How long a submit lease lives before the reaper returns the UTxO to
    /// available. Minutes-scale, and deliberately distinct from the 15-minute
    /// quote TTL: the lease covers only build -> sign -> submit, not the quote's
    /// validity window.
    pub lease: std::time::Duration,
    /// The minimum number of canonical, available UTxOs a wallet should keep
    /// ready. The replenisher splits a source UTxO when a wallet falls below it.
    pub min_canonical_count: u32,
}

impl WalletConfig {
    /// Construct a config, validating the band.
    pub fn new(
        network: Network,
        band: LovelaceBand,
        lease: std::time::Duration,
        min_canonical_count: u32,
    ) -> Result<Self> {
        band.validate()?;
        Ok(Self {
            network,
            band,
            lease,
            min_canonical_count,
        })
    }

    /// Validate that the configured band is fee-shape-stable against a concrete
    /// set of protocol parameters: the canonical quote fee equals the real
    /// one-input build fee for *every* value in the band, with no fold and no
    /// min-ADA boundary anywhere inside it.
    ///
    /// [`LovelaceBand::validate`] is a pure check of the band's own shape (the
    /// CBOR-width parity that keeps the change output's width constant). That is
    /// necessary but not sufficient: whether the change output survives at all
    /// depends on the live fee, which depends on the protocol parameters and the
    /// record size. If a value in the band minus the fee falls below the minimum
    /// ADA a change output must hold, a one-input build over that value folds the
    /// residual into the fee and emits no change output. The folded shape has a
    /// different size, and therefore a different fee, than the canonical quote
    /// priced at the band midpoint, so the exact-quote guarantee silently breaks
    /// for the low end of the band.
    ///
    /// This check proves the guarantee holds by building the real one-input
    /// transaction at both band endpoints (the worst cases for the fold and
    /// min-ADA boundary) over a spread of record sizes and asserting that every
    /// build keeps a change output and pays exactly the canonical quote fee. The
    /// endpoints bound the interior: the fee is value-invariant across the band
    /// (the CBOR-width parity guarantees that), so if neither endpoint folds, no
    /// interior value can either. A deployment runs this at startup with the
    /// freshly loaded protocol parameters and refuses to come up if the band it
    /// was configured with cannot hold the exactness guarantee under them.
    ///
    /// `record_sizes` is the spread of record byte lengths to certify the band
    /// against; it must cover the largest record the deployment will accept,
    /// since a larger record means a larger fee and the smallest surviving
    /// change. An empty slice is rejected: certifying nothing certifies nothing.
    pub fn validate_fee_shape_stable(
        &self,
        params: &cardano_poe_tx::ProtocolParams,
        change_address: &str,
        verification_key: [u8; 32],
        record_sizes: &[usize],
    ) -> Result<()> {
        if record_sizes.is_empty() {
            return Err(Error::Config(
                "fee-shape validation needs at least one record size to certify the band against"
                    .to_string(),
            ));
        }

        for &record_len in record_sizes {
            // The canonical quote prices the band midpoint at output index 0.
            let quote_fee = self.one_input_build(
                record_len,
                self.band.mid,
                0,
                params,
                change_address,
                verification_key,
            )?;

            // Both endpoints (and every value between them) must build to a
            // change-bearing transaction paying exactly the quote fee. The
            // endpoints are the extreme cases: `min` is the smallest surviving
            // change (closest to folding), `max` the largest.
            for &value in &[self.band.min, self.band.max] {
                let built = self.one_input_built(
                    record_len,
                    value,
                    0,
                    params,
                    change_address,
                    verification_key,
                )?;
                if built.change.is_none() {
                    return Err(Error::Config(format!(
                        "the configured lovelace band is not fee-shape-stable under the current \
                         protocol parameters: a one-input build over {value} lovelace for a \
                         {record_len}-byte record folds the residual into the fee instead of \
                         emitting a change output (the value minus the fee is below the minimum-ADA \
                         change floor); pick a band whose minimum clears the fee plus the minimum \
                         change for the largest record"
                    )));
                }
                if built.fee != quote_fee {
                    return Err(Error::Config(format!(
                        "the configured lovelace band is not fee-shape-stable under the current \
                         protocol parameters: a one-input build over {value} lovelace for a \
                         {record_len}-byte record pays fee {} but the canonical quote priced at the \
                         band midpoint pays {quote_fee}; the exact-quote guarantee requires these \
                         to be identical across the whole band",
                        built.fee
                    )));
                }
            }
        }

        Ok(())
    }

    /// Build the real one-input Proof-of-Existence transaction over a synthetic
    /// canonical UTxO of `lovelace` at `output_index`, returning its fee.
    fn one_input_build(
        &self,
        record_len: usize,
        lovelace: u64,
        output_index: u32,
        params: &cardano_poe_tx::ProtocolParams,
        change_address: &str,
        verification_key: [u8; 32],
    ) -> Result<u64> {
        Ok(self
            .one_input_built(
                record_len,
                lovelace,
                output_index,
                params,
                change_address,
                verification_key,
            )?
            .fee)
    }

    /// Build the real one-input Proof-of-Existence transaction over a synthetic
    /// canonical UTxO of `lovelace` at `output_index`.
    fn one_input_built(
        &self,
        record_len: usize,
        lovelace: u64,
        output_index: u32,
        params: &cardano_poe_tx::ProtocolParams,
        change_address: &str,
        verification_key: [u8; 32],
    ) -> Result<cardano_poe_tx::BuiltPoeTx> {
        let request = cardano_poe_tx::BuildRequest {
            record_bytes: vec![0u8; record_len],
            metadata_label: cardano_poe_tx::POE_METADATA_LABEL,
            utxos: vec![cardano_poe_tx::Utxo {
                // A synthetic but plausible 32-byte tx id; only its CBOR width
                // matters to the fee and every canonical input shares it.
                tx_hash: "11".repeat(32),
                index: output_index,
                lovelace,
            }],
            must_spend: Vec::new(),
            protocol: *params,
            change_address: change_address.to_string(),
            network_id: self.network.network_id(),
            payment_verification_key: verification_key,
            validity: None,
        };
        cardano_poe_tx::build_poe_tx(&request).map_err(|e| {
            Error::Config(format!(
                "fee-shape validation could not build a one-input transaction over {lovelace} \
                 lovelace for a {record_len}-byte record: {e}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_width_matches_the_encoding_class_boundaries() {
        assert_eq!(cbor_uint_width(0), 1);
        assert_eq!(cbor_uint_width(23), 1);
        assert_eq!(cbor_uint_width(24), 2);
        assert_eq!(cbor_uint_width(0xFF), 2);
        assert_eq!(cbor_uint_width(0x100), 3);
        assert_eq!(cbor_uint_width(0xFFFF), 3);
        assert_eq!(cbor_uint_width(0x1_0000), 5);
        assert_eq!(cbor_uint_width(0xFFFF_FFFF), 5);
        assert_eq!(cbor_uint_width(0x1_0000_0000), 9);
    }

    #[test]
    fn a_band_whose_endpoints_share_a_width_validates() {
        // The 4-8 ADA window: both endpoints fall in the 5-byte CBOR class.
        LovelaceBand::new(4_000_000, 8_000_000, 6_000_000)
            .expect("a single-width band is accepted");
    }

    #[test]
    fn a_band_straddling_a_cbor_width_boundary_is_rejected() {
        // min is in the 3-byte class (< 65536), max is in the 5-byte class, so a
        // canonical UTxO's change-output width would change inside the band and
        // the fee would no longer be value-invariant.
        let err = LovelaceBand::new(60_000, 70_000, 65_000)
            .expect_err("a width-straddling band must be rejected");
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }

    #[test]
    fn a_band_with_mid_outside_min_max_is_rejected() {
        assert!(
            LovelaceBand::new(4_000_000, 8_000_000, 9_000_000).is_err(),
            "mid above max is rejected"
        );
        assert!(
            LovelaceBand::new(4_000_000, 8_000_000, 3_000_000).is_err(),
            "mid below min is rejected"
        );
        assert!(
            LovelaceBand::new(8_000_000, 4_000_000, 6_000_000).is_err(),
            "max below min is rejected"
        );
    }

    #[test]
    fn a_zero_minimum_band_is_rejected() {
        let err = LovelaceBand::new(0, 23, 10).expect_err("a zero minimum must be rejected");
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }

    #[test]
    fn wallet_network_maps_one_to_one_to_a_params_network() {
        use crate::chain::params::Network as ParamsNetwork;
        // Every wallet network maps to its same-named provider network: no test
        // network is silently collapsed onto another's cache/provider.
        assert_eq!(Network::Mainnet.to_params_network(), ParamsNetwork::Mainnet);
        assert_eq!(Network::Preprod.to_params_network(), ParamsNetwork::Preprod);
        assert_eq!(Network::Preview.to_params_network(), ParamsNetwork::Preview);
        // The mapping is injective: distinct wallet networks never share a
        // provider network (which would make two deployments fight over one
        // cache key).
        let mapped = [
            Network::Mainnet.to_params_network(),
            Network::Preprod.to_params_network(),
            Network::Preview.to_params_network(),
        ];
        for (i, a) in mapped.iter().enumerate() {
            for b in &mapped[i + 1..] {
                assert_ne!(
                    a, b,
                    "wallet networks must map to distinct provider networks"
                );
            }
        }
    }

    #[test]
    fn wallet_config_new_propagates_band_validation() {
        let bad = LovelaceBand {
            min: 60_000,
            max: 70_000,
            mid: 65_000,
        };
        assert!(
            WalletConfig::new(
                Network::Preprod,
                bad,
                std::time::Duration::from_secs(120),
                4,
            )
            .is_err(),
            "WalletConfig::new rejects an invalid band"
        );
    }
}
