//! The canonical-shape fee quote.
//!
//! A quote must return the exact fee a later submit will pay, without reading
//! any wallet's UTxOs and without reserving anything. It works because every
//! canonical UTxO has the same CBOR width: a transaction with one canonical
//! input and one change output has a fee that depends only on the record length,
//! never on which specific UTxO is spent. So the quote prices a *synthetic*
//! canonical input (output index 0, band-mid lovelace) through the real builder
//! and returns its fee; the submit, spending some real canonical UTxO of the
//! same shape, charges byte-for-byte the same fee.
//!
//! This is the property the exactness proof pins (see the property test in
//! `tests/`): for every output index below the cap, every lovelace value across
//! the whole band, and a spread of record sizes, the real build fee equals this
//! canonical quote fee.

use cardano_poe_tx::{build_poe_tx, BuildRequest, ProtocolParams, Utxo};

use super::config::WalletConfig;
use crate::{Error, Result};

/// A fee quote for a record of a given length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeQuote {
    /// The exact lovelace fee a submit of a record this long will pay.
    pub fee: u64,
    /// The serialised size, in bytes, the fee was metered over. Diagnostic.
    pub tx_size: u64,
}

/// Price the canonical one-input + one-change-output transaction shape for a
/// record of `record_len` bytes, reading no wallet state.
///
/// Builds against a synthetic canonical UTxO (output index 0, band-mid lovelace)
/// with [`build_poe_tx`], using the supplied protocol parameters, change address,
/// and verification key (the same shape a real submit uses). The returned fee is
/// exact for any real canonical UTxO of the same shape because the band and index
/// caps make every canonical input the same CBOR width.
///
/// `change_address` and `verification_key` come from the operator's canonical
/// wallet shape; in practice the quote can use any wallet's address since the fee
/// is address-shape invariant, but the caller passes the concrete values so the
/// synthetic build is a faithful stand-in.
pub fn quote_fee(
    record_len: usize,
    params: &ProtocolParams,
    change_address: &str,
    verification_key: [u8; 32],
    config: &WalletConfig,
) -> Result<FeeQuote> {
    // A record whose only property the fee depends on is its length: the fee is
    // metered over the serialised transaction, and the auxiliary data grows with
    // the record bytes, so any `record_len`-byte filler produces the canonical
    // fee for that length.
    let record_bytes = vec![0u8; record_len];

    let request = canonical_build_request(
        record_bytes,
        params,
        change_address,
        verification_key,
        config,
    );

    let built = build_poe_tx(&request).map_err(|e| {
        Error::WalletBuild(format!("pricing the canonical quote shape failed: {e}"))
    })?;

    Ok(FeeQuote {
        fee: built.fee,
        tx_size: built.total_size,
    })
}

/// Assemble the [`BuildRequest`] for the canonical quote shape: one synthetic
/// canonical input at output index 0 holding band-mid lovelace.
///
/// Split out so the exactness property test can build the same canonical request
/// and compare it against a request that spends a real-shaped UTxO at any index
/// across the whole band.
#[must_use]
pub fn canonical_build_request(
    record_bytes: Vec<u8>,
    params: &ProtocolParams,
    change_address: &str,
    verification_key: [u8; 32],
    config: &WalletConfig,
) -> BuildRequest {
    BuildRequest {
        record_bytes,
        metadata_label: cardano_poe_tx::POE_METADATA_LABEL,
        utxos: vec![Utxo {
            tx_hash: hex::encode(SYNTHETIC_QUOTE_TX_HASH),
            index: 0,
            lovelace: config.band.mid,
        }],
        // The quote prices the canonical one-input shape; no input is forced.
        must_spend: Vec::new(),
        protocol: *params,
        change_address: change_address.to_string(),
        network_id: config.network.network_id(),
        payment_verification_key: verification_key,
        validity: None,
    }
}

/// The synthetic transaction id the canonical quote spends. A fixed, obviously
/// synthetic 32-byte value (all `0xCA`) so the priced input is unambiguously not
/// a real on-chain UTxO; only its CBOR width matters to the fee, and that width
/// is shared by every real canonical input.
pub const SYNTHETIC_QUOTE_TX_HASH: [u8; 32] = [0xCA; 32];
