//! The live price oracles the FX refresh loop reads.
//!
//! Every feed is reached through the engine's single hardened egress
//! ([`cardanowall::verifier::fetch::fetch_outbound`]) so there is no second
//! outbound HTTP path to audit: the same deny-host short circuit, protocol/method
//! allowlist, and body cap that guard chain and storage traffic guard these calls
//! too. The SDK transport is blocking, so each call runs on a blocking task, the
//! same way webhook delivery drives it.
//!
//! Two kinds of feed:
//!
//! - **Coin prices** (ADA/USD + AR/USD), read through a [`CoinPriceProvider`]
//!   chain:
//!   - **CoinPaprika** `/v1/tickers/{id}` is the keyless default — no API key, no
//!     registration, ~1,000 requests/day free. It is always present in the chain
//!     (as the sole provider, or as the fallback behind a configured CoinGecko
//!     key) so a self-hosted gateway prices publishes out of the box.
//!   - **CoinGecko** `/simple/price` is used only when an operator configures a
//!     key. It is the one provider with a finite, key-bound monthly budget, so an
//!     exhausted quota (HTTP 429 or a body signal) arms a cooldown rather than a
//!     retry; the chain then falls through to CoinPaprika.
//! - **Per-byte storage price**, read from **Turbo** `/v1/price/bytes/{n}` (the
//!   primary) and the **Arweave gateway** `/price/{n}` (the fallback).

use cardanowall::verifier::fetch::{
    fetch_outbound, FetchOutboundOptions, HttpMethod, HttpPurpose, OutboundError, RetryConfig,
    WrapFetchOutboundConfig, DENY_HOSTS_DEFAULT,
};
use zeroize::Zeroizing;

use crate::pricing::units::decimal_usd_to_micros;
use crate::Error;

/// The byte sample the per-byte oracles are queried at. The per-call cost
/// amortises out across a representative payload; 1 MiB is large enough that the
/// integer winston-per-byte ratio is stable and small enough to always fit one
/// response.
pub const SAMPLE_BYTES: u64 = 1_048_576;

/// The CoinGecko tier a keyed deployment authenticates as.
///
/// CoinGecko is used only with an API key here (the keyless default is
/// CoinPaprika), so there is no anonymous tier: both are key-bound and differ only
/// in host and auth header. The tier is operator config so a deployment does not
/// pay an auto-detection probe on every boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinGeckoTier {
    /// The paid plan: `pro-api.coingecko.com`, `x-cg-pro-api-key` header.
    Pro,
    /// The free-with-key Demo plan: `api.coingecko.com`, `x-cg-demo-api-key`
    /// header. A finite monthly budget (~10,000 calls/month).
    Demo,
}

impl CoinGeckoTier {
    /// Parse the operator-configured tier token. There is no default: the token is
    /// only read when a CoinGecko key is configured, and an unrecognised value is a
    /// config error.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "pro" => Some(Self::Pro),
            "demo" => Some(Self::Demo),
            _ => None,
        }
    }

    /// The stable token recorded on the resulting row's `source`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CoinGeckoTier::Pro => "pro",
            CoinGeckoTier::Demo => "demo",
        }
    }

    /// The base URL and auth header name for this tier.
    fn gateway(self) -> (&'static str, &'static str) {
        match self {
            CoinGeckoTier::Pro => ("https://pro-api.coingecko.com/api/v3", "x-cg-pro-api-key"),
            CoinGeckoTier::Demo => ("https://api.coingecko.com/api/v3", "x-cg-demo-api-key"),
        }
    }
}

/// The CoinGecko credential and tier a keyed deployment authenticates with.
#[derive(Clone)]
pub struct CoinGeckoConfig {
    /// The configured tier.
    pub tier: CoinGeckoTier,
    /// The API key. CoinGecko is used only with a key, so this is always
    /// present. Wiped on drop; the `Debug` rendering redacts it.
    pub api_key: Zeroizing<String>,
}

/// Redact the API key on `{:?}` so a debug format of the provider chain cannot
/// leak the deploy-time secret.
impl std::fmt::Debug for CoinGeckoConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoinGeckoConfig")
            .field("tier", &self.tier)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

/// One coin-price reading: the two USD spot prices a quote needs.
///
/// Provider-agnostic — every [`CoinPriceProvider`] returns this same shape.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CoinPrices {
    /// ADA/USD as a decimal.
    pub ada_usd: f64,
    /// AR/USD as a decimal.
    pub ar_usd: f64,
}

impl CoinPrices {
    /// The ADA/USD price as micro-USD, the form the row stores.
    pub fn ada_usd_micros(self) -> crate::Result<i64> {
        decimal_usd_to_micros(self.ada_usd)
    }
}

/// The error a coin-price provider fetch surfaces.
#[derive(Debug)]
pub enum PriceProviderError {
    /// The provider signalled an exhausted quota (HTTP 429 or an equivalent body
    /// pattern). For a cooldown-gated provider the caller arms a cooldown and falls
    /// through to the next provider rather than retrying into the quota. Carries the
    /// status and a body excerpt for the diagnostic.
    QuotaExhausted {
        /// The HTTP status the quota signal arrived on.
        status: u16,
        /// The response body (the caller truncates before persisting).
        body: String,
    },
    /// The fetch failed for any other reason (transport, non-success status that is
    /// not a quota signal, or a response that did not carry a price). The chain
    /// falls through to the next provider.
    Failed(String),
}

impl std::fmt::Display for PriceProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PriceProviderError::QuotaExhausted { status, .. } => {
                write!(f, "price provider quota exhausted (HTTP {status})")
            }
            PriceProviderError::Failed(detail) => {
                write!(f, "price provider fetch failed: {detail}")
            }
        }
    }
}

/// The deny-host + single-attempt egress policy every oracle call rides.
///
/// The canonical deny-host list rejects the operator's own host and loopback (the
/// service-independence guard); a single attempt avoids burning the per-minute
/// price-API budget twice under pressure, the same posture the worker's port uses
/// (the cron retries the whole tick on its own cadence).
fn egress_config() -> WrapFetchOutboundConfig {
    WrapFetchOutboundConfig {
        deny_hosts: DENY_HOSTS_DEFAULT.iter().map(|s| s.to_string()).collect(),
        retry: RetryConfig {
            retries: 0,
            ..RetryConfig::default()
        },
    }
}

/// Whether a status + body looks like an exhausted-quota signal.
///
/// The primary signal is HTTP 429. Some providers front their API with a CDN that
/// serves an intercept page (403/503 with "rate limit" wording) when the upstream
/// key is past its allowance, and CoinGecko's JSON body carries `error_code 10006`
/// for a reached monthly cap; matching those too suppresses a retry storm.
fn body_signals_quota(status: u16, body: &str) -> bool {
    if status == 429 {
        return true;
    }
    if body.is_empty() {
        return false;
    }
    if body.contains("10006") {
        return true;
    }
    let lower = body.to_lowercase();
    lower.contains("rate limit")
        || lower.contains("rate-limit")
        || lower.contains("quota exceeded")
        || lower.contains("exceeded the rate limit")
        || lower.contains("you've reached")
}

/// Run a blocking egress fetch on the runtime's blocking pool. The SDK transport
/// is blocking, so it must not run on an async worker thread.
async fn blocking_fetch(
    url: String,
    opts: FetchOutboundOptions,
) -> std::result::Result<(u16, Vec<u8>), OutboundError> {
    tokio::task::spawn_blocking(move || {
        let mut audit = Vec::new();
        fetch_outbound(&url, &opts, &mut audit, &egress_config())
            .map(|result| (result.status, result.bytes))
    })
    .await
    .map_err(|e| OutboundError::Transport {
        url: String::new(),
        message: format!("blocking fetch task panicked: {e}"),
    })?
}

/// A coin-price source the FX refresh chain reads ADA/USD + AR/USD from.
///
/// The chain tries its providers in order until one answers. CoinPaprika is the
/// keyless default that is always present — as the sole provider when no CoinGecko
/// key is configured, or as the fallback behind CoinGecko when one is.
#[derive(Debug, Clone)]
pub enum CoinPriceProvider {
    /// CoinGecko, used only when an operator configures a key. The one provider
    /// with a finite, key-bound monthly budget, so the refresh loop gates it behind
    /// the quota cooldown.
    CoinGecko(CoinGeckoConfig),
    /// CoinPaprika, keyless and free (~1,000 requests/day, no registration). The
    /// default provider and the always-available fallback.
    CoinPaprika,
}

impl CoinPriceProvider {
    /// The token stamped on a written row's `source` recording which feed produced
    /// the prices (`coingecko-pro`, `coingecko-demo`, `coinpaprika`).
    #[must_use]
    pub fn source_label(&self) -> String {
        match self {
            CoinPriceProvider::CoinGecko(config) => format!("coingecko-{}", config.tier.as_str()),
            CoinPriceProvider::CoinPaprika => "coinpaprika".to_string(),
        }
    }

    /// Whether this provider is gated behind the quota cooldown. Only CoinGecko is:
    /// it is the provider with a finite, key-bound monthly budget that an exhausted
    /// quota should stop re-probing for a while. CoinPaprika is keyless and simply
    /// retried on the next tick.
    #[must_use]
    pub fn is_cooldown_gated(&self) -> bool {
        matches!(self, CoinPriceProvider::CoinGecko(_))
    }

    /// Read ADA/USD + AR/USD from this provider.
    pub async fn fetch(&self) -> std::result::Result<CoinPrices, PriceProviderError> {
        match self {
            CoinPriceProvider::CoinGecko(config) => fetch_coingecko_prices(config).await,
            CoinPriceProvider::CoinPaprika => fetch_coinpaprika_prices().await,
        }
    }
}

/// Fetch ADA/USD and AR/USD from CoinGecko at the configured tier.
///
/// Both prices come back in one `/simple/price?ids=cardano,arweave` call. Returns
/// [`PriceProviderError::QuotaExhausted`] on a quota signal so the caller can arm a
/// cooldown without retrying; every other failure is [`PriceProviderError::Failed`].
pub async fn fetch_coingecko_prices(
    config: &CoinGeckoConfig,
) -> std::result::Result<CoinPrices, PriceProviderError> {
    let (base_url, auth_header) = config.tier.gateway();
    let url = format!("{base_url}/simple/price?ids=cardano,arweave&vs_currencies=usd");

    let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Https);
    opts.headers
        .push(("accept".to_string(), "application/json".to_string()));
    if !config.api_key.is_empty() {
        // The header list is the send path: it needs an owned plain String the
        // HTTP client consumes, so this is the one place the key intentionally
        // leaves its zeroizing wrapper.
        opts.headers
            .push((auth_header.to_string(), config.api_key.as_str().to_string()));
    }

    let (status, bytes) = match blocking_fetch(url, opts).await {
        Ok(pair) => pair,
        Err(e) => return Err(PriceProviderError::Failed(e.to_string())),
    };

    // A quota signal can arrive as a non-200 OR as an HTTP-200 error envelope —
    // CoinGecko's free tier returns `{"status":{"error_code":10006,…}}` with a 200
    // when the monthly cap is hit. `provider_error` classifies it as a quota signal
    // at every "no usable price" exit, so the cooldown arms and the chain falls
    // through rather than treating an exhausted key as a transient failure.
    if status != 200 {
        return Err(provider_error(
            status,
            &bytes,
            format!("CoinGecko returned HTTP {status}"),
        ));
    }

    let raw: CoinGeckoBody = match serde_json::from_slice(&bytes) {
        Ok(raw) => raw,
        Err(e) => {
            return Err(provider_error(
                status,
                &bytes,
                format!("CoinGecko response was not valid JSON: {e}"),
            ))
        }
    };
    let (Some(ada_usd), Some(ar_usd)) = (
        positive_price(raw.cardano.and_then(|c| c.usd)),
        positive_price(raw.arweave.and_then(|a| a.usd)),
    ) else {
        return Err(provider_error(
            status,
            &bytes,
            "CoinGecko response missing a positive cardano.usd/arweave.usd".to_string(),
        ));
    };
    Ok(CoinPrices { ada_usd, ar_usd })
}

/// The keyless CoinPaprika REST base. No API key, no registration; the free
/// allowance is ~1,000 requests/day, far above the refresh cadence.
const COINPAPRIKA_BASE_URL: &str = "https://api.coinpaprika.com/v1";

/// CoinPaprika's coin ids for the two assets a quote prices from.
const COINPAPRIKA_CARDANO_ID: &str = "ada-cardano";
const COINPAPRIKA_ARWEAVE_ID: &str = "ar-arweave";

/// Fetch ADA/USD and AR/USD from CoinPaprika.
///
/// CoinPaprika has no batch-by-id endpoint, so this reads the two single-coin
/// tickers (`/v1/tickers/{id}?quotes=USD`) — two small requests rather than the
/// multi-megabyte all-coins feed, which would also risk the egress body cap. Both
/// must answer to produce a reading.
pub async fn fetch_coinpaprika_prices() -> std::result::Result<CoinPrices, PriceProviderError> {
    let ada_usd = fetch_coinpaprika_usd(COINPAPRIKA_CARDANO_ID).await?;
    let ar_usd = fetch_coinpaprika_usd(COINPAPRIKA_ARWEAVE_ID).await?;
    Ok(CoinPrices { ada_usd, ar_usd })
}

/// Read one coin's USD spot price from CoinPaprika.
async fn fetch_coinpaprika_usd(coin_id: &str) -> std::result::Result<f64, PriceProviderError> {
    let url = format!("{COINPAPRIKA_BASE_URL}/tickers/{coin_id}?quotes=USD");
    let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Https);
    opts.headers
        .push(("accept".to_string(), "application/json".to_string()));

    let (status, bytes) = match blocking_fetch(url, opts).await {
        Ok(pair) => pair,
        Err(e) => return Err(PriceProviderError::Failed(e.to_string())),
    };

    if status != 200 {
        return Err(provider_error(
            status,
            &bytes,
            format!("CoinPaprika returned HTTP {status} for {coin_id}"),
        ));
    }

    let raw: CoinPaprikaTicker = match serde_json::from_slice(&bytes) {
        Ok(raw) => raw,
        Err(e) => {
            return Err(provider_error(
                status,
                &bytes,
                format!("CoinPaprika response was not valid JSON: {e}"),
            ))
        }
    };
    let Some(price) = positive_price(raw.quotes.and_then(|q| q.usd).and_then(|u| u.price)) else {
        return Err(provider_error(
            status,
            &bytes,
            format!("CoinPaprika response for {coin_id} missing a positive quotes.USD.price"),
        ));
    };
    Ok(price)
}

/// A price is usable only if it is finite and strictly positive; anything else
/// (null, NaN, 0, negative) is treated as missing.
fn positive_price(value: Option<f64>) -> Option<f64> {
    value.filter(|p| p.is_finite() && *p > 0.0)
}

/// Classify a fetched-but-unusable response into a provider error.
///
/// A quota signal — HTTP 429, or a body that announces an exhausted quota even on
/// an HTTP-200 (CoinGecko's `error_code 10006` monthly-cap envelope) — becomes
/// [`PriceProviderError::QuotaExhausted`] so a gated provider cools down and the
/// chain falls through; anything else is [`PriceProviderError::Failed`] with the
/// given context. This is consulted ONLY when a response yielded no usable price,
/// so a valid price body is never misread as a quota signal.
fn provider_error(status: u16, bytes: &[u8], context: String) -> PriceProviderError {
    let body = String::from_utf8_lossy(bytes).into_owned();
    if body_signals_quota(status, &body) {
        PriceProviderError::QuotaExhausted { status, body }
    } else {
        PriceProviderError::Failed(context)
    }
}

/// Fetch the live Turbo winc cost of `sample_bytes` from the payment service's
/// `/v1/price/bytes/{n}` endpoint. The response carries `winc` as a decimal
/// string (winc can exceed a JSON-safe integer), parsed into a `u128`.
pub async fn fetch_turbo_winc(payment_url: &str, sample_bytes: u64) -> crate::Result<u128> {
    let url = format!(
        "{}/v1/price/bytes/{sample_bytes}",
        payment_url.trim_end_matches('/')
    );
    let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Https);
    opts.headers
        .push(("accept".to_string(), "application/json".to_string()));

    let (status, bytes) = blocking_fetch(url, opts)
        .await
        .map_err(|e| Error::Config(format!("Turbo price fetch failed: {e}")))?;
    if status != 200 {
        return Err(Error::Config(format!("Turbo price returned HTTP {status}")));
    }
    let raw: TurboPriceBody = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Config(format!("Turbo price response was not valid JSON: {e}")))?;
    let winc = raw
        .winc
        .trim()
        .parse::<u128>()
        .map_err(|e| Error::Config(format!("Turbo winc is not an integer: {e}")))?;
    if winc == 0 {
        return Err(Error::Config(
            "Turbo winc must be > 0 to derive a per-byte price".to_string(),
        ));
    }
    Ok(winc)
}

/// Fetch the live Arweave-native winston cost of `sample_bytes` from the gateway's
/// `/price/{n}` endpoint. The response is a plain-text integer.
pub async fn fetch_arweave_native_winston(
    gateway_url: &str,
    sample_bytes: u64,
) -> crate::Result<u128> {
    let url = format!("{}/price/{sample_bytes}", gateway_url.trim_end_matches('/'));
    let mut opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Arweave);
    opts.headers
        .push(("accept".to_string(), "text/plain".to_string()));

    let (status, bytes) = blocking_fetch(url, opts)
        .await
        .map_err(|e| Error::Config(format!("Arweave price fetch failed: {e}")))?;
    if status != 200 {
        return Err(Error::Config(format!(
            "Arweave price returned HTTP {status}"
        )));
    }
    let text = String::from_utf8_lossy(&bytes);
    let winston = text
        .trim()
        .parse::<u128>()
        .map_err(|e| Error::Config(format!("Arweave price is not an integer: {e}")))?;
    if winston == 0 {
        return Err(Error::Config(
            "Arweave winston must be > 0 to derive a per-byte price".to_string(),
        ));
    }
    Ok(winston)
}

/// The CoinGecko `/simple/price` body shape, limited to the two assets read.
#[derive(serde::Deserialize)]
struct CoinGeckoBody {
    cardano: Option<AssetPrice>,
    arweave: Option<AssetPrice>,
}

#[derive(serde::Deserialize)]
struct AssetPrice {
    usd: Option<f64>,
}

/// The CoinPaprika `/v1/tickers/{id}` body shape, limited to the USD quote.
#[derive(serde::Deserialize)]
struct CoinPaprikaTicker {
    quotes: Option<CoinPaprikaQuotes>,
}

#[derive(serde::Deserialize)]
struct CoinPaprikaQuotes {
    #[serde(rename = "USD")]
    usd: Option<CoinPaprikaQuote>,
}

#[derive(serde::Deserialize)]
struct CoinPaprikaQuote {
    price: Option<f64>,
}

/// The Turbo `/v1/price/bytes/{n}` body shape. `winc` is a decimal string.
#[derive(serde::Deserialize)]
struct TurboPriceBody {
    winc: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_parses_and_round_trips() {
        assert_eq!(CoinGeckoTier::parse("pro"), Some(CoinGeckoTier::Pro));
        assert_eq!(CoinGeckoTier::parse("DEMO"), Some(CoinGeckoTier::Demo));
        // There is no keyless CoinGecko tier any more — the keyless default is
        // CoinPaprika — so "public"/empty no longer parse.
        assert_eq!(CoinGeckoTier::parse(""), None);
        assert_eq!(CoinGeckoTier::parse("public"), None);
        assert_eq!(CoinGeckoTier::parse("nonsense"), None);
        assert_eq!(CoinGeckoTier::Pro.as_str(), "pro");
    }

    #[test]
    fn each_tier_carries_its_auth_header() {
        let (pro_url, pro_header) = CoinGeckoTier::Pro.gateway();
        assert!(pro_url.contains("pro-api.coingecko.com"));
        assert_eq!(pro_header, "x-cg-pro-api-key");
        let (demo_url, demo_header) = CoinGeckoTier::Demo.gateway();
        assert!(demo_url.contains("api.coingecko.com"));
        assert_eq!(demo_header, "x-cg-demo-api-key");
    }

    #[test]
    fn provider_labels_and_cooldown_gating() {
        let coingecko = CoinPriceProvider::CoinGecko(CoinGeckoConfig {
            tier: CoinGeckoTier::Demo,
            api_key: "cg-demo".to_string().into(),
        });
        assert_eq!(coingecko.source_label(), "coingecko-demo");
        assert!(coingecko.is_cooldown_gated());

        assert_eq!(CoinPriceProvider::CoinPaprika.source_label(), "coinpaprika");
        assert!(!CoinPriceProvider::CoinPaprika.is_cooldown_gated());
    }

    #[test]
    fn provider_error_classifies_a_quota_signal_even_on_http_200() {
        // CoinGecko's free tier announces a reached monthly cap as an HTTP-200 error
        // envelope, not a 429. The classifier must catch it as a quota signal so the
        // cooldown arms and the chain falls through — not a generic Failed.
        let quota_200 = provider_error(
            200,
            br#"{"status":{"error_code":10006,"error_message":"monthly cap"}}"#,
            "missing price".to_string(),
        );
        assert!(matches!(
            quota_200,
            PriceProviderError::QuotaExhausted { status: 200, .. }
        ));

        // A genuine 429 is a quota signal regardless of body.
        assert!(matches!(
            provider_error(429, b"", "ctx".to_string()),
            PriceProviderError::QuotaExhausted { status: 429, .. }
        ));

        // A 200 with no quota wording (e.g. an empty/garbage body) stays a Failed
        // carrying the context, so a transient blip is not mistaken for an exhausted
        // quota.
        assert!(matches!(
            provider_error(200, b"{}", "missing price".to_string()),
            PriceProviderError::Failed(_)
        ));
        assert!(matches!(
            provider_error(500, b"internal error", "ctx".to_string()),
            PriceProviderError::Failed(_)
        ));
    }

    #[test]
    fn parses_a_well_formed_coinpaprika_ticker() {
        let body = br#"{"id":"ar-arweave","symbol":"AR","quotes":{"USD":{"price":1.9734}}}"#;
        let raw: CoinPaprikaTicker = serde_json::from_slice(body).unwrap();
        assert_eq!(raw.quotes.unwrap().usd.unwrap().price, Some(1.9734));
    }

    #[test]
    fn positive_price_rejects_unusable_values() {
        assert_eq!(positive_price(Some(0.45)), Some(0.45));
        assert_eq!(positive_price(None), None);
        assert_eq!(positive_price(Some(0.0)), None);
        assert_eq!(positive_price(Some(-1.0)), None);
        assert_eq!(positive_price(Some(f64::NAN)), None);
        assert_eq!(positive_price(Some(f64::INFINITY)), None);
    }

    #[test]
    fn quota_signals_are_recognised() {
        assert!(body_signals_quota(429, ""));
        assert!(body_signals_quota(403, "you've reached your monthly limit"));
        assert!(body_signals_quota(
            200,
            r#"{"status":{"error_code":10006}}"#
        ));
        assert!(body_signals_quota(503, "Rate limit exceeded"));
        assert!(!body_signals_quota(200, "ok"));
        assert!(!body_signals_quota(500, "internal error"));
    }

    #[test]
    fn parses_a_well_formed_coingecko_body() {
        let body = br#"{"cardano":{"usd":0.45},"arweave":{"usd":15.0}}"#;
        let raw: CoinGeckoBody = serde_json::from_slice(body).unwrap();
        assert_eq!(raw.cardano.unwrap().usd, Some(0.45));
        assert_eq!(raw.arweave.unwrap().usd, Some(15.0));
    }

    #[test]
    fn parses_a_turbo_winc_string() {
        let body = br#"{"winc":"9882740299","adjustments":[]}"#;
        let raw: TurboPriceBody = serde_json::from_slice(body).unwrap();
        assert_eq!(raw.winc, "9882740299");
    }
}
