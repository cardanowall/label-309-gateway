//! The exact integer money conversions the FX oracle records a row in.
//!
//! Two scales are involved and must never be confused: the ADA->USD rate is held
//! in micro-USD (USD x 1e6) per ADA, and the per-byte Arweave price is held in
//! femto-USD (USD x 1e15) per byte. Femto is used for the per-byte price because a
//! single byte costs a vanishing fraction of a cent; micro-USD would round it to
//! zero and silently price storage at nothing.
//!
//! A wrong constant here mis-bills every quote, so the conversions are factored
//! out as pure functions and unit-tested against the same arithmetic the rest of
//! the system prices with.

use crate::Error;

/// Winston per AR: 1 AR is 10^12 winston, Arweave's smallest denomination. Used to
/// turn a winston-per-byte cost back into an AR-per-byte cost before applying the
/// AR->USD price.
pub const WINSTON_PER_AR: u128 = 1_000_000_000_000;

/// The femto scale: USD x 1e15. The per-byte storage price is held at this
/// precision.
const FEMTO_PER_USD: f64 = 1e15;

/// The micro scale: USD x 1e6. The ADA->USD price is held at this precision.
const MICRO_PER_USD: f64 = 1e6;

/// Convert a decimal USD price into micro-USD (USD x 1e6), rounding to the nearest
/// micro.
///
/// Scaling with `(price * 1e6).round()` rather than `(price * 1e6) as i64` is what
/// keeps a price like `0.2517` from drifting down a micro: the exact product is
/// `251700`, but in binary float it lands at `251699.999...`, which a bare cast
/// would truncate to `251699`. Rounding to the nearest micro (not toward zero)
/// recovers the intended `251700`, so the conversion is unbiased rather than
/// systematically a sub-micro low. Rejects a non-finite or negative price: a
/// missing/garbage oracle value must surface as an error, never as a silent zero.
pub fn decimal_usd_to_micros(price: f64) -> crate::Result<i64> {
    if !price.is_finite() || price < 0.0 {
        return Err(Error::Config(format!(
            "expected a non-negative finite USD price, got {price}"
        )));
    }
    // Scale to micros and round to the nearest integer, so binary-float
    // representation error never biases the stored value downward.
    let micros = (price * MICRO_PER_USD).round();
    // The product is far below i64::MAX for any plausible ADA price, but guard the
    // cast so an absurd oracle value errors instead of wrapping negative.
    if micros > i64::MAX as f64 {
        return Err(Error::Config(format!(
            "USD price {price} overflows the micro-USD range"
        )));
    }
    Ok(micros as i64)
}

/// Convert a winston-per-`sample_bytes` storage cost into femto-USD per byte using
/// the live AR->USD price.
///
/// The math chain, all in f64 until the final integer round (a 1 MiB sample of AR
/// pricing is many orders of magnitude under the f64 mantissa limit):
///
/// ```text
///   winston_per_byte = winston / sample_bytes
///   ar_per_byte      = winston_per_byte / WINSTON_PER_AR
///   usd_per_byte     = ar_per_byte * ar_usd_price
///   femto_per_byte   = usd_per_byte * 1e15
/// ```
///
/// Returns at least `1` so the table's positive-price CHECK holds even on an
/// absurdly cheap (subsidised / regionally discounted) quote. Rejects a
/// non-positive winston, sample size, or AR price: each would derive a zero or
/// negative per-byte price, which must error rather than silently zero-bill.
pub fn ar_usd_per_byte_femto(
    winston: u128,
    sample_bytes: u64,
    ar_usd_price: f64,
) -> crate::Result<i64> {
    if winston == 0 {
        return Err(Error::Config(
            "winston cost must be > 0 to derive a per-byte price".to_string(),
        ));
    }
    if sample_bytes == 0 {
        return Err(Error::Config(
            "sample byte count must be > 0 to derive a per-byte price".to_string(),
        ));
    }
    if !ar_usd_price.is_finite() || ar_usd_price <= 0.0 {
        return Err(Error::Config(format!(
            "expected a positive finite AR/USD price, got {ar_usd_price}"
        )));
    }

    let winston_per_byte = winston as f64 / sample_bytes as f64;
    let ar_per_byte = winston_per_byte / WINSTON_PER_AR as f64;
    let femto_per_byte = ar_per_byte * ar_usd_price * FEMTO_PER_USD;

    if !femto_per_byte.is_finite() || femto_per_byte <= 0.0 {
        return Err(Error::Config(format!(
            "derived a non-positive femto-per-byte price from winston={winston}"
        )));
    }
    let rounded = femto_per_byte.round();
    if rounded > i64::MAX as f64 {
        return Err(Error::Config(format!(
            "derived femto-per-byte price overflows the bigint range from winston={winston}"
        )));
    }
    let value = rounded as i64;
    Ok(value.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ada_price_rounds_to_the_nearest_micro() {
        // $0.45 -> 450_000 micro-USD, matching the test FX fixture point.
        assert_eq!(decimal_usd_to_micros(0.45).unwrap(), 450_000);
        // A six-significant-digit price rounds, not truncates.
        assert_eq!(decimal_usd_to_micros(0.2517).unwrap(), 251_700);
    }

    #[test]
    fn a_negative_or_nan_ada_price_errors() {
        assert!(decimal_usd_to_micros(-0.1).is_err());
        assert!(decimal_usd_to_micros(f64::NAN).is_err());
        assert!(decimal_usd_to_micros(f64::INFINITY).is_err());
    }

    #[test]
    fn per_byte_femto_lands_in_the_realistic_range() {
        // The test fixture pins AR ~= $15 with a 1 GiB upload ~= $21, which is the
        // per-byte femto value `seedTestFxRate` derives. Reproduce that point: a
        // 1 MiB sample at the winston/byte rate behind a ~$21/GiB price, AR/USD 15.
        //
        // Target: 20_955_000 femto/byte (the shared test fixture value). Solve the
        // winston for a 1 MiB sample that yields it at AR/USD 15:
        //   femto = (winston / 2^20 / 1e12) * 15 * 1e15
        //   winston = femto * 2^20 * 1e12 / (15 * 1e15)
        let sample_bytes: u64 = 1_048_576;
        let ar_usd = 15.0_f64;
        let target_femto = 20_955_000.0_f64;
        let winston = (target_femto * sample_bytes as f64 * 1e12 / (ar_usd * 1e15)).round() as u128;
        let femto = ar_usd_per_byte_femto(winston, sample_bytes, ar_usd).unwrap();
        // The round-trip lands within one femto of the fixture (the inverse solve
        // rounds the winston input).
        assert!(
            (femto - 20_955_000).abs() <= 1,
            "expected ~20_955_000 femto/byte, got {femto}"
        );
    }

    #[test]
    fn per_byte_femto_floors_at_one() {
        // An absurdly cheap (subsidised) quote still yields a positive price so the
        // table's CHECK holds.
        let femto = ar_usd_per_byte_femto(1, 1_048_576, 0.0001).unwrap();
        assert_eq!(femto, 1);
    }

    #[test]
    fn a_zero_input_errors_rather_than_zero_billing() {
        assert!(ar_usd_per_byte_femto(0, 1_048_576, 15.0).is_err());
        assert!(ar_usd_per_byte_femto(1_000, 0, 15.0).is_err());
        assert!(ar_usd_per_byte_femto(1_000, 1_048_576, 0.0).is_err());
    }
}
