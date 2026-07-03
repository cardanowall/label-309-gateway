//! Cardano protocol parameters: fetch, cache, and read.
//!
//! # Roles
//!
//! - A [`ProtocolParamsSource`] talks to the network: it reports the current
//!   epoch and fetches the parameters for a given epoch. [`KoiosParamsSource`]
//!   is the Koios implementation (keyless public tier by default; an operator
//!   API key and/or self-hosted base URL via [`KoiosConfig`]).
//! - [`populate_params`] is the loop body the engine runs on a schedule. It asks
//!   the source for the current epoch and, only if that epoch is not already
//!   cached, fetches and inserts it. It never overwrites a stored epoch, so a
//!   recorded epoch's values are immutable.
//! - [`load_params`] and [`load_params_for_epoch`] are the read path. They touch
//!   only Postgres and never call a source, so a quote or a build resolves its
//!   parameters with zero oracle traffic.
//!
//! # Staleness posture
//!
//! [`load_params`] returns the newest stored epoch for a network even if the
//! populate loop has fallen behind the live chain, logging a warning so the lag
//! is observable. Protocol parameters change rarely and a slightly stale fee is
//! recoverable; an *absent* row is not, so the complete absence of any row for a
//! network is a hard [`Error::ParamsNotFound`] rather than a silent default.
//!
//! The staleness warning is driven off loop *liveness*, not epoch age. The fee
//! table holds one immutable row per (network, epoch), so its `fetched_at` only
//! reflects when an epoch first appeared and freezes for the ~five days that
//! epoch is current — it cannot say whether the loop is still running. So every
//! successful populate pass (including the common pass that finds the current
//! epoch already cached and writes no fee row) stamps `last_checked_at` in
//! the `cw_core.cardano_params_refresh` marker table, and [`load_params`] warns when that
//! marker — not `fetched_at` — has gone stale, which is the genuine "the loop
//! has stalled" signal.

use std::time::Duration;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// A Cardano network the engine can fetch and cache parameters for.
///
/// Every variant has a working keyless Koios endpoint, so the protocol-parameter
/// populate loop, the chain gateway, and the read loaders all operate on any of
/// them end to end. The wallet subsystem carries the same set of networks (see
/// [`crate::wallet::config::Network`]); the two enums are kept in lockstep so a
/// wallet network always has a matching parameter/provider network rather than
/// being silently mapped onto a different one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// The production network.
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

    /// The default Koios API base URL for this network: the public
    /// `koios.rest` gateways. An operator replaces it with a self-hosted
    /// instance through [`KoiosConfig::base_url`]; authentication is never part
    /// of the URL (an API key rides the `Authorization` header).
    #[must_use]
    pub fn koios_base_url(self) -> &'static str {
        match self {
            Network::Mainnet => "https://api.koios.rest/api/v1",
            Network::Preprod => "https://preprod.koios.rest/api/v1",
            Network::Preview => "https://preview.koios.rest/api/v1",
        }
    }

    /// The network class record-level signature verification runs under.
    ///
    /// Wallet-path (CIP-30) record signatures bind a CIP-19 stake address whose
    /// header byte the verifier derives from the CARRYING transaction's network.
    /// CIP-19 splits that header into mainnet and one shared testnet class, so
    /// mainnet maps to itself and every test network (preprod, preview) verifies
    /// under the testnet class.
    #[must_use]
    pub fn verifier_network(self) -> cardanowall::verifier::types::CardanoNetwork {
        match self {
            Network::Mainnet => cardanowall::verifier::types::CardanoNetwork::Mainnet,
            Network::Preprod | Network::Preview => {
                cardanowall::verifier::types::CardanoNetwork::Preprod
            }
        }
    }
}

/// How the engine addresses Koios: an optional operator base-URL override and
/// an optional API key, shared by every Koios client the engine constructs
/// (the chain gateway, this module's parameter source, and the wallet
/// replenisher's UTxO source).
///
/// The default value is the keyless public tier on the per-network base URL
/// ([`Network::koios_base_url`]). That tier is deliberately limited (about
/// 5,000 requests/day, ~1 KiB POST bodies) — fine for development, weak for a
/// production cadence. An operator raises the ceiling two ways, independently:
///
/// - `api_key` — a Koios API token (the registered/paid tiers). Every Koios
///   HTTP request then carries `Authorization: Bearer <key>`, and bulk POST
///   bodies may use the registered tiers' larger payload cap (see
///   [`super::gateway::KOIOS_REGISTERED_CHUNK`]).
/// - `base_url` — a full base URL for a self-hosted (or third-party) Koios
///   instance, replacing the per-network public URL everywhere Koios is
///   addressed. Canonical form: no trailing slash — paths are appended
///   verbatim as `{base_url}/tip`, so `https://koios.example/api/v1` is
///   correct and `https://koios.example/api/v1/` would produce `//tip`. The
///   binary's config loader normalises and validates this form.
///
/// The override names ONE instance, so the operator is responsible for
/// pointing it at the deployment's own network. A wrong-network instance is
/// not cheaply detectable: a Koios `/tip` row carries no network identifier,
/// so the engine would cache the wrong network's protocol parameters and scan
/// the wrong chain's records without an immediate error. The first hard
/// symptom is the submit path — a transaction built with this deployment's
/// network-tagged addresses is deterministically rejected by the other
/// network's nodes (a non-transient 4xx), which abandons the attempt and
/// auto-refunds rather than publishing.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct KoiosConfig {
    /// The base URL that replaces the per-network public URL when set
    /// (canonical form: no trailing slash).
    pub base_url: Option<String>,
    /// The Koios API key. When set, every Koios request carries
    /// `Authorization: Bearer <key>`. Never logged; the `Debug` rendering
    /// redacts it, and the zeroizing wrapper wipes the key on drop.
    pub api_key: Option<Zeroizing<String>>,
}

impl KoiosConfig {
    /// The base URL Koios is addressed at for `network`: the operator override
    /// when set, else the network's public URL.
    #[must_use]
    pub fn base_url_for(&self, network: Network) -> &str {
        self.base_url
            .as_deref()
            .unwrap_or_else(|| network.koios_base_url())
    }
}

impl std::fmt::Debug for KoiosConfig {
    /// A redacted rendering: the API key is a deploy-time secret and must never
    /// reach a log line or a panic message through a derived `Debug`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KoiosConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Parameters fetched from a source for one epoch, plus the verbatim provider
/// response so a future reader can recover a field this struct does not name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedParams {
    /// The epoch these parameters are in force for.
    pub epoch: u64,
    /// Linear fee coefficient (lovelace per transaction byte).
    pub min_fee_a: u64,
    /// Linear fee constant (lovelace).
    pub min_fee_b: u64,
    /// Lovelace charged per byte of a serialised output (minimum-ADA input).
    pub coins_per_utxo_byte: u64,
    /// Maximum serialised transaction size in bytes.
    pub max_tx_size: u64,
    /// The provider's full response for this epoch, retained for forward
    /// compatibility.
    pub raw: serde_json::Value,
}

/// Typed protocol parameters as read back from the cache. Carries the network
/// and epoch the row was recorded for alongside the four fee-relevant values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolParams {
    /// The network the row belongs to.
    pub network: String,
    /// The epoch the parameters were in force for.
    pub epoch: u64,
    /// Linear fee coefficient (lovelace per transaction byte).
    pub min_fee_a: u64,
    /// Linear fee constant (lovelace).
    pub min_fee_b: u64,
    /// Lovelace charged per byte of a serialised output (minimum-ADA input).
    pub coins_per_utxo_byte: u64,
    /// Maximum serialised transaction size in bytes.
    pub max_tx_size: u64,
}

/// A source of Cardano protocol parameters.
///
/// The populate loop drives the two methods in sequence: it reads the current
/// epoch, and only on a cache miss does it fetch that epoch's parameters. An
/// implementation that talks to the network is the production case; tests
/// substitute an in-memory implementation so the populate logic is exercised
/// with no HTTP.
pub trait ProtocolParamsSource: Send + Sync {
    /// The epoch the network is currently in.
    fn current_epoch(
        &self,
        network: Network,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;

    /// The protocol parameters in force for `epoch` on `network`.
    fn fetch_params(
        &self,
        network: Network,
        epoch: u64,
    ) -> impl std::future::Future<Output = Result<FetchedParams>> + Send;
}

/// The Koios protocol-parameter source.
///
/// Reads the current epoch from `/tip` and an epoch's parameters from
/// `/epoch_params?_epoch_no=`. Addressed per the carried [`KoiosConfig`]: the
/// public per-network URL and no authentication by default, an operator
/// base-URL override and/or `Authorization: Bearer` key when configured. The
/// client uses rustls so no system OpenSSL is needed.
pub struct KoiosParamsSource {
    client: reqwest::Client,
    config: KoiosConfig,
}

impl KoiosParamsSource {
    /// Build a source with a sensible request timeout, addressed per `config`
    /// (`KoiosConfig::default()` is the keyless public tier).
    ///
    /// Returns [`Error::ChainProvider`] if the TLS-backed client cannot be
    /// constructed (which only fails on a broken platform crypto backend).
    pub fn new(config: KoiosConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| Error::ChainProvider(format!("building HTTP client: {e}")))?;
        Ok(Self { client, config })
    }

    /// Build a source over a caller-provided client (for shared connection
    /// pooling, a custom timeout, or a test pointing `config.base_url` at a
    /// local fake).
    #[must_use]
    pub fn with_client(client: reqwest::Client, config: KoiosConfig) -> Self {
        Self { client, config }
    }

    /// GET a Koios path on `network`, decoding the JSON body into `T`. Maps both
    /// transport failures and non-success statuses to [`Error::ChainProvider`]
    /// so a caller need not distinguish reqwest's error taxonomy.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        network: Network,
        path: &str,
    ) -> Result<T> {
        let url = format!("{}{path}", self.config.base_url_for(network));
        let mut request = self.client.get(&url);
        if let Some(key) = self.config.api_key.as_deref() {
            request = request.bearer_auth(key);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| Error::ChainProvider(format!("GET {url}: {e}")))?;
        let resp = resp
            .error_for_status()
            .map_err(|e| Error::ChainProvider(format!("GET {url}: {e}")))?;
        crate::http::read_capped_json::<T>(resp, crate::http::JSON_BODY_CEILING)
            .await
            .map_err(|e| Error::ChainProvider(format!("decoding {url}: {e}")))
    }
}

impl ProtocolParamsSource for KoiosParamsSource {
    async fn current_epoch(&self, network: Network) -> Result<u64> {
        let body: serde_json::Value = self.get_json(network, "/tip").await?;
        parse_koios_tip(&body)
    }

    async fn fetch_params(&self, network: Network, epoch: u64) -> Result<FetchedParams> {
        let path = format!("/epoch_params?_epoch_no={epoch}");
        let body: serde_json::Value = self.get_json(network, &path).await?;
        parse_koios_epoch_params(epoch, &body)
    }
}

/// Extract the current epoch from a Koios `/tip` response body.
///
/// The body is the raw JSON array Koios returns. Split out from the transport so
/// the parse (including the number-or-string leniency) is testable against a
/// committed fixture with no network.
pub fn parse_koios_tip(body: &serde_json::Value) -> Result<u64> {
    let rows: Vec<KoiosTip> = serde_json::from_value(body.clone())?;
    rows.into_iter()
        .next()
        .map(|t| t.epoch_no)
        .ok_or_else(|| Error::ChainProvider("/tip returned no rows".to_string()))
}

/// Extract one epoch's [`FetchedParams`] from a Koios `/epoch_params` response
/// body, retaining the matching row verbatim as the forward-compatible `raw`.
///
/// The body is the raw JSON array Koios returns. Split out from the transport so
/// the parse (including the number-or-string leniency) is testable against a
/// committed fixture with no network.
pub fn parse_koios_epoch_params(epoch: u64, body: &serde_json::Value) -> Result<FetchedParams> {
    let mut rows: Vec<serde_json::Value> = serde_json::from_value(body.clone())?;
    // Keep the full provider row verbatim, then re-interpret the same value into
    // the typed shape, so the cached `raw` stays byte-faithful to what Koios sent
    // (a future reader can recover a column this struct does not name).
    let raw = rows.drain(..).next().ok_or_else(|| {
        Error::ChainProvider(format!("/epoch_params returned no rows for epoch {epoch}"))
    })?;
    let parsed: KoiosEpochParams = serde_json::from_value(raw.clone())?;
    Ok(FetchedParams {
        epoch,
        min_fee_a: parsed.min_fee_a,
        min_fee_b: parsed.min_fee_b,
        coins_per_utxo_byte: parsed.coins_per_utxo_size,
        max_tx_size: parsed.max_tx_size,
        raw,
    })
}

/// The `/tip` row shape (only the epoch is needed).
#[derive(Deserialize)]
struct KoiosTip {
    #[serde(deserialize_with = "de_u64_lenient")]
    epoch_no: u64,
}

/// The `/epoch_params` row shape, limited to the fee-relevant fields. Koios
/// returns many more columns; the rest ride along in the cached `raw` value.
#[derive(Deserialize)]
struct KoiosEpochParams {
    #[serde(deserialize_with = "de_u64_lenient")]
    min_fee_a: u64,
    #[serde(deserialize_with = "de_u64_lenient")]
    min_fee_b: u64,
    #[serde(deserialize_with = "de_u64_lenient")]
    coins_per_utxo_size: u64,
    #[serde(deserialize_with = "de_u64_lenient")]
    max_tx_size: u64,
}

/// Deserialize a `u64` that the source may encode either as a JSON number or as
/// a JSON string. Koios renders lovelace-scale parameters as quoted strings to
/// preserve precision for clients whose native numbers are IEEE-754 doubles,
/// while smaller fields stay bare numbers; the boundary is not contractually
/// fixed, so every numeric field accepts either form.
fn de_u64_lenient<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| D::Error::custom(format!("not a u64: {n}"))),
        serde_json::Value::String(s) => s
            .parse::<u64>()
            .map_err(|e| D::Error::custom(format!("not a u64 string: {s}: {e}"))),
        other => Err(D::Error::custom(format!(
            "expected a u64 number or string, got {other}"
        ))),
    }
}

/// One populate pass: cache the current epoch's parameters if not already
/// stored.
///
/// Learns the current epoch the cheap way: from the materialised tip the forward
/// scan keeps in `cw_core.cardano_tip` (a Postgres read, no provider call). The
/// scan is the single owner of the `/tip` HTTP read, so in steady state this loop
/// makes no `/tip` call of its own; it only asks the [`ProtocolParamsSource`] for
/// the current epoch on a cold start, before the scan has materialised a tip yet.
/// Either way, if `(network, epoch)` is already in
/// `cw_core.cardano_protocol_params` the pass fetches nothing and reports
/// [`PopulateOutcome::AlreadyCurrent`]. Otherwise it fetches the epoch's
/// parameters and inserts them with `ON CONFLICT DO NOTHING`, so two replicas
/// running this loop at once never collide and an already-stored epoch is never
/// overwritten. The insert reporting zero rows affected (another replica won the
/// race in the gap between the existence check and the insert) is also reported
/// as [`PopulateOutcome::AlreadyCurrent`].
///
/// The `/epoch_params` fetch (the only provider call this loop makes in steady
/// state) is the single function in the module that reaches the network on an
/// actual epoch change; the read path never does.
///
/// Either way, a pass that completes successfully — whether it inserted a new
/// epoch or found the current one already cached — stamps the per-network
/// loop-liveness marker (`cw_core.cardano_params_refresh.last_checked_at`), so
/// the read path can tell a healthy-but-idle loop from a stalled one. A pass
/// that fails (no epoch learned, provider error) returns early and does NOT
/// stamp the marker, so a sustained outage shows up as a stale marker.
pub async fn populate_params<S: ProtocolParamsSource>(
    pool: &sqlx::PgPool,
    source: &S,
    network: Network,
) -> Result<PopulateOutcome> {
    // Prefer the materialised tip's epoch (a DB read) so the scan stays the sole
    // owner of the `/tip` call. Only when no tip has been materialised yet (cold
    // start, before the scan loop's first tick) fall back to a single source
    // `/tip` read.
    let epoch = match current_epoch_from_tip(pool, network).await? {
        Some(epoch) => epoch,
        None => source.current_epoch(network).await?,
    };

    // Cheap pre-check: skip the network fetch entirely when the epoch is already
    // cached, which is the steady state once a network is caught up. The pass
    // still succeeded — the loop is alive and the current epoch is present — so
    // it stamps the liveness marker before reporting the no-op.
    if epoch_is_cached(pool, network, epoch).await? {
        mark_loop_checked(pool, network).await?;
        return Ok(PopulateOutcome::AlreadyCurrent { epoch });
    }

    let fetched = source.fetch_params(network, epoch).await?;
    let inserted = sqlx::query(
        "INSERT INTO cw_core.cardano_protocol_params \
           (network, epoch, min_fee_a, min_fee_b, coins_per_utxo_byte, max_tx_size, raw) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (network, epoch) DO NOTHING",
    )
    .bind(network.as_str())
    .bind(epoch_to_i32(fetched.epoch)?)
    .bind(u64_to_i64(fetched.min_fee_a, "min_fee_a")?)
    .bind(u64_to_i64(fetched.min_fee_b, "min_fee_b")?)
    .bind(u64_to_i64(
        fetched.coins_per_utxo_byte,
        "coins_per_utxo_byte",
    )?)
    .bind(u64_to_i64(fetched.max_tx_size, "max_tx_size")?)
    .bind(&fetched.raw)
    .execute(pool)
    .await?
    .rows_affected();

    if inserted == 0 {
        // A concurrent replica inserted the same epoch between the pre-check and
        // this insert. The stored row is authoritative and immutable, so this is
        // a benign no-op, not a failure. The pass still ran to completion, so it
        // stamps the liveness marker like any other successful pass.
        mark_loop_checked(pool, network).await?;
        return Ok(PopulateOutcome::AlreadyCurrent {
            epoch: fetched.epoch,
        });
    }

    mark_loop_checked(pool, network).await?;
    tracing::info!(
        network = network.as_str(),
        epoch = fetched.epoch,
        min_fee_a = fetched.min_fee_a,
        min_fee_b = fetched.min_fee_b,
        coins_per_utxo_byte = fetched.coins_per_utxo_byte,
        max_tx_size = fetched.max_tx_size,
        "cached new epoch protocol parameters"
    );
    Ok(PopulateOutcome::Inserted {
        epoch: fetched.epoch,
    })
}

/// Stamp the per-network loop-liveness marker to `now()`.
///
/// Upserts one row per network in [`cw_core.cardano_params_refresh`]. Called at
/// the end of every successful populate pass — including the no-op pass that
/// finds the current epoch already cached — so the marker's age reflects how
/// recently the loop ran, independent of when the newest epoch's fee row was
/// inserted (which freezes for the duration of an epoch).
async fn mark_loop_checked(pool: &sqlx::PgPool, network: Network) -> Result<()> {
    sqlx::query(
        "INSERT INTO cw_core.cardano_params_refresh (network, last_checked_at) \
         VALUES ($1, now()) \
         ON CONFLICT (network) DO UPDATE SET last_checked_at = now()",
    )
    .bind(network.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// What one [`populate_params`] pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopulateOutcome {
    /// A new epoch's parameters were fetched and inserted.
    Inserted {
        /// The epoch that was inserted.
        epoch: u64,
    },
    /// The current epoch was already cached; nothing was fetched or written.
    AlreadyCurrent {
        /// The epoch found already present.
        epoch: u64,
    },
}

/// The queue the protocol-parameter populate loop runs on.
pub const PARAMS_POPULATE_QUEUE: &str = "cardano_params_populate";

/// The default policy for the populate queue: a singleton loop so at most one
/// populate pass is in flight across the whole deployment, with a short fixed
/// backoff and an attempt budget that rides out a transient provider blip until
/// the next scheduled tick.
#[must_use]
pub fn params_populate_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        PARAMS_POPULATE_QUEUE,
        // A handful of attempts absorbs a transient provider error; a sustained
        // outage simply leaves the prior epoch serving until a later tick wins.
        3,
        crate::runtime::Backoff::Fixed { base_secs: 30 },
        // The pass is short (one or two HTTP calls); a 2-minute lease is ample
        // and reclaims promptly if a replica dies mid-pass.
        120,
    )
}

/// A schedule that fires the populate loop every ten minutes. Protocol
/// parameters change at most once per epoch, so ten minutes catches a rollover
/// well within the epoch while making almost no provider traffic in steady
/// state (the pass fetches only on a cache miss).
#[must_use]
pub fn params_populate_schedule() -> crate::runtime::scheduler::CronSchedule {
    crate::runtime::scheduler::CronSchedule::new(
        "*/10 * * * *",
        PARAMS_POPULATE_QUEUE,
        serde_json::Value::Null,
    )
}

/// The job handler that runs one populate pass per configured network.
///
/// Register it on the runtime against [`PARAMS_POPULATE_QUEUE`] with
/// [`params_populate_policy`] and [`params_populate_schedule`]. It owns its pool
/// and source, so the runtime can drive it with only a [`crate::runtime::JobContext`].
/// The handler is the *only* path that reaches the network; the read loaders
/// never construct one.
pub struct ParamsPopulateHandler<S: ProtocolParamsSource> {
    pool: sqlx::PgPool,
    source: S,
    networks: Vec<Network>,
}

impl<S: ProtocolParamsSource> ParamsPopulateHandler<S> {
    /// Build a handler that populates `networks` from `source`.
    pub fn new(pool: sqlx::PgPool, source: S, networks: Vec<Network>) -> Self {
        Self {
            pool,
            source,
            networks,
        }
    }

    /// Run one populate pass over every configured network, returning the
    /// per-network outcomes. Each network is independent: a failure on one is
    /// surfaced but does not abort the others, so a single network's provider
    /// outage cannot starve the rest.
    pub async fn run_once(&self) -> Vec<(Network, Result<PopulateOutcome>)> {
        let mut out = Vec::with_capacity(self.networks.len());
        for &network in &self.networks {
            let result = populate_params(&self.pool, &self.source, network).await;
            out.push((network, result));
        }
        out
    }
}

impl<S: ProtocolParamsSource + 'static> crate::runtime::JobHandler for ParamsPopulateHandler<S> {
    async fn handle(&self, _ctx: crate::runtime::JobContext) -> crate::runtime::JobOutcome {
        let mut first_error: Option<String> = None;
        for (network, result) in self.run_once().await {
            match result {
                Ok(PopulateOutcome::Inserted { epoch }) => {
                    tracing::info!(
                        network = network.as_str(),
                        epoch,
                        "populate pass cached a new epoch"
                    );
                }
                Ok(PopulateOutcome::AlreadyCurrent { epoch }) => {
                    tracing::debug!(
                        network = network.as_str(),
                        epoch,
                        "populate pass found the current epoch already cached"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        network = network.as_str(),
                        error = %e,
                        "populate pass failed for a network"
                    );
                    if first_error.is_none() {
                        first_error = Some(format!("{network:?}: {e}"));
                    }
                }
            }
        }

        match first_error {
            // Any network failing fails the attempt so the runtime retries per
            // the queue policy; a network that succeeded already wrote its row,
            // and a retry of an already-cached network is a cheap no-op.
            Some(message) => crate::runtime::JobOutcome::Fail {
                error: crate::runtime::JobError::new("params_populate_failed", message),
            },
            None => crate::runtime::JobOutcome::Complete,
        }
    }
}

/// The current epoch as recorded on the materialised chain tip, or `None` when no
/// tip has been materialised yet (cold start) or the recorded tip carries no
/// epoch (a provider that omitted it, or a row from before the epoch was
/// materialised). The populate loop prefers this Postgres read over a provider
/// `/tip` call so the forward scan stays the single owner of the `/tip` read.
async fn current_epoch_from_tip(pool: &sqlx::PgPool, network: Network) -> Result<Option<u64>> {
    super::confirm::read_tip_epoch(pool, network.as_str()).await
}

/// Whether `(network, epoch)` already has a cached row.
async fn epoch_is_cached(pool: &sqlx::PgPool, network: Network, epoch: u64) -> Result<bool> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM cw_core.cardano_protocol_params \
         WHERE network = $1 AND epoch = $2)",
    )
    .bind(network.as_str())
    .bind(epoch_to_i32(epoch)?)
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

/// How long the populate loop may go without completing a pass before the read
/// path warns the loop has stalled. The loop runs every ten minutes, so this is
/// roughly three dozen missed cadences — well past any transient provider blip,
/// but far short of an epoch, so a healthy-but-idle loop never trips it. Driven
/// off the per-network liveness marker, never off the fee row's insert time.
const LOOP_STALE_AFTER: chrono::Duration = chrono::Duration::hours(6);

/// How long the newest cached epoch may remain the newest before the read path
/// warns the epoch is overdue to roll over. A Cardano epoch lasts about five
/// days, so a newest-epoch fee row older than this means a rollover should have
/// been observed and was not (the loop ran but never advanced the epoch — a
/// distinct fault from the loop being dead). Six days = one epoch plus a day of
/// slack for boundary timing. Driven off the fee row's insert time, which for an
/// immutable per-epoch row is exactly when that epoch first appeared.
const EPOCH_OVERDUE_AFTER: chrono::Duration = chrono::Duration::days(6);

/// Load the newest stored protocol parameters for a network.
///
/// Returns the row with the highest epoch. This is the read path quotes and
/// builds use; it never calls a source. When the newest stored epoch lags the
/// chain it is still returned (with a `tracing::warn` under the two staleness
/// checks below) because a stale fee is recoverable and forcing a network call
/// on the read path is not acceptable. The complete absence of any row is a hard
/// [`Error::ParamsNotFound`], since there is no safe parameter to invent.
///
/// Two independent staleness checks fire here, deliberately distinct:
///
/// - *Loop liveness* — has the populate loop completed a pass recently? Read off
///   the per-network `cardano_params_refresh` marker, which every successful
///   pass stamps. A stale marker (or one absent past the threshold) means the
///   loop has stalled and the cache could be epochs behind. Absent-on-first-boot
///   is treated as not-yet-observed, not stale, so a cold start does not alarm.
/// - *Epoch overdue* — has the newest epoch stayed newest longer than an epoch
///   should last? Read off the fee row's own insert time. This catches the loop
///   running yet never advancing the epoch, which the liveness marker alone
///   cannot see (the marker is fresh, the epoch is stale).
pub async fn load_params(pool: &sqlx::PgPool, network: Network) -> Result<ProtocolParams> {
    let row = sqlx::query_as::<_, ParamsRow>(
        "SELECT network, epoch, min_fee_a, min_fee_b, coins_per_utxo_byte, max_tx_size, fetched_at \
         FROM cw_core.cardano_protocol_params \
         WHERE network = $1 \
         ORDER BY epoch DESC \
         LIMIT 1",
    )
    .bind(network.as_str())
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| Error::ParamsNotFound(network.as_str().to_string()))?;

    let now = chrono::Utc::now();

    // Loop liveness: warn when the populate loop has not completed a pass within
    // the window. A NULL marker means no pass has finished since deploy yet (cold
    // start) — treated as not-yet-observed, not a stall.
    if let Some(last_checked_at) = load_last_checked_at(pool, network).await? {
        let idle = now - last_checked_at;
        if idle > LOOP_STALE_AFTER {
            tracing::warn!(
                network = network.as_str(),
                epoch = row.epoch,
                idle_seconds = idle.num_seconds(),
                "protocol-parameter populate loop has stalled: no successful pass within the liveness window"
            );
        }
    }

    // Epoch overdue: warn when the newest epoch has been newest longer than an
    // epoch should last, i.e. a rollover should have been observed and was not.
    let epoch_age = now - row.fetched_at;
    if epoch_age > EPOCH_OVERDUE_AFTER {
        tracing::warn!(
            network = network.as_str(),
            epoch = row.epoch,
            epoch_age_seconds = epoch_age.num_seconds(),
            "newest cached protocol-parameter epoch is overdue to roll over: the loop has not advanced the epoch within an epoch's length"
        );
    }

    ProtocolParams::try_from(row)
}

/// The instant the populate loop last completed a successful pass for `network`,
/// or `None` when no pass has finished since deploy (no marker row yet).
///
/// Read-only; the marker is written exclusively by the populate loop. The read
/// path uses it as a loop-liveness signal independent of any fee row's age.
async fn load_last_checked_at(
    pool: &sqlx::PgPool,
    network: Network,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    let last_checked_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT last_checked_at FROM cw_core.cardano_params_refresh WHERE network = $1",
    )
    .bind(network.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(last_checked_at)
}

/// Load the protocol parameters stored for a specific epoch, if present.
///
/// Returns `None` when that exact epoch has not been cached. Read-only; never
/// calls a source.
pub async fn load_params_for_epoch(
    pool: &sqlx::PgPool,
    network: Network,
    epoch: u64,
) -> Result<Option<ProtocolParams>> {
    let row = sqlx::query_as::<_, ParamsRow>(
        "SELECT network, epoch, min_fee_a, min_fee_b, coins_per_utxo_byte, max_tx_size, fetched_at \
         FROM cw_core.cardano_protocol_params \
         WHERE network = $1 AND epoch = $2",
    )
    .bind(network.as_str())
    .bind(epoch_to_i32(epoch)?)
    .fetch_optional(pool)
    .await?;
    row.map(ProtocolParams::try_from).transpose()
}

/// Convert a `u64` value to the `i64` Postgres `bigint` binds expect, rejecting
/// a value too large to represent rather than silently wrapping. Protocol
/// parameters never approach this bound in practice; the check exists so a
/// malformed provider value surfaces as an error instead of a negative row.
fn u64_to_i64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| Error::ChainProvider(format!("{field} value {value} does not fit in i64")))
}

/// Convert an epoch number to the `i32` the `integer` epoch column binds expect.
/// A real epoch is far below the 32-bit ceiling; a value that overflows is a
/// malformed provider response, surfaced as an error rather than a wrapped row.
fn epoch_to_i32(epoch: u64) -> Result<i32> {
    i32::try_from(epoch)
        .map_err(|_| Error::ChainProvider(format!("epoch {epoch} does not fit in i32")))
}

/// Raw `cardano_protocol_params` row as read from Postgres before the i64 → u64
/// widening. The columns are `bigint` (i64); the CHECK constraints guarantee
/// they are non-negative, so the conversion back to u64 cannot fail in practice
/// but is validated rather than assumed.
#[derive(sqlx::FromRow)]
struct ParamsRow {
    network: String,
    // The `epoch` column is `integer` (INT4): an epoch number is far below the
    // 32-bit ceiling and the natural key reads smaller as int4. The fee columns
    // are `bigint` (INT8) because lovelace-scale values can exceed 32 bits.
    epoch: i32,
    min_fee_a: i64,
    min_fee_b: i64,
    coins_per_utxo_byte: i64,
    max_tx_size: i64,
    fetched_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<ParamsRow> for ProtocolParams {
    type Error = Error;

    fn try_from(row: ParamsRow) -> Result<Self> {
        let to_u64 = |value: i64, field: &str| -> Result<u64> {
            u64::try_from(value).map_err(|_| {
                Error::Config(format!(
                    "stored {field} is negative ({value}); the column CHECK should prevent this"
                ))
            })
        };
        let epoch = u64::try_from(row.epoch).map_err(|_| {
            Error::Config(format!(
                "stored epoch is negative ({}); the column CHECK should prevent this",
                row.epoch
            ))
        })?;
        Ok(ProtocolParams {
            network: row.network,
            epoch,
            min_fee_a: to_u64(row.min_fee_a, "min_fee_a")?,
            min_fee_b: to_u64(row.min_fee_b, "min_fee_b")?,
            coins_per_utxo_byte: to_u64(row.coins_per_utxo_byte, "coins_per_utxo_byte")?,
            max_tx_size: to_u64(row.max_tx_size, "max_tx_size")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A committed Koios `/epoch_params` response. It deliberately mixes numeric
    // encodings: `min_fee_a`/`min_fee_b` are bare JSON numbers while
    // `max_tx_size`/`coins_per_utxo_size` are quoted strings, so a single parse
    // exercises both branches of the number-or-string leniency.
    const EPOCH_PARAMS_FIXTURE: &str =
        include_str!("../../tests/fixtures/epoch_params_preprod.json");
    const TIP_FIXTURE: &str = include_str!("../../tests/fixtures/tip_preprod.json");

    #[test]
    fn parses_epoch_params_with_mixed_number_and_string_forms() {
        let body: serde_json::Value = serde_json::from_str(EPOCH_PARAMS_FIXTURE).unwrap();
        let fetched = parse_koios_epoch_params(213, &body).expect("parse fixture");

        // Bare-number fields and quoted-string fields both decode to u64.
        assert_eq!(fetched.epoch, 213);
        assert_eq!(fetched.min_fee_a, 44); // number in the fixture
        assert_eq!(fetched.min_fee_b, 155_381); // number in the fixture
        assert_eq!(fetched.max_tx_size, 16_384); // string in the fixture
        assert_eq!(fetched.coins_per_utxo_byte, 4_310); // string in the fixture
    }

    #[test]
    fn retains_the_full_provider_row_verbatim_as_raw() {
        let body: serde_json::Value = serde_json::from_str(EPOCH_PARAMS_FIXTURE).unwrap();
        let fetched = parse_koios_epoch_params(213, &body).expect("parse fixture");

        // A column this struct does not name survives in `raw` for forward
        // compatibility, and keeps the exact JSON form Koios sent.
        assert_eq!(fetched.raw["max_val_size"], serde_json::json!("5000"));
        assert_eq!(fetched.raw["collateral_percent"], serde_json::json!(150));
        assert_eq!(fetched.raw["min_pool_cost"], serde_json::json!("170000000"));
    }

    #[test]
    fn parses_current_epoch_from_tip() {
        let body: serde_json::Value = serde_json::from_str(TIP_FIXTURE).unwrap();
        assert_eq!(parse_koios_tip(&body).expect("parse tip"), 213);
    }

    #[test]
    fn rejects_an_empty_epoch_params_array() {
        let body = serde_json::json!([]);
        let err = parse_koios_epoch_params(7, &body).expect_err("empty array must error");
        assert!(matches!(err, Error::ChainProvider(_)), "got {err:?}");
    }

    #[test]
    fn rejects_an_empty_tip_array() {
        let body = serde_json::json!([]);
        let err = parse_koios_tip(&body).expect_err("empty array must error");
        assert!(matches!(err, Error::ChainProvider(_)), "got {err:?}");
    }

    #[test]
    fn rejects_a_non_numeric_string_field() {
        // A quoted field that is not a base-10 integer is a hard parse error,
        // not a silent zero.
        let body = serde_json::json!([{
            "min_fee_a": 44,
            "min_fee_b": 155381,
            "coins_per_utxo_size": "not-a-number",
            "max_tx_size": "16384"
        }]);
        let err = parse_koios_epoch_params(1, &body).expect_err("bad string must error");
        assert!(matches!(err, Error::Serde(_)), "got {err:?}");
    }

    #[test]
    fn accepts_a_string_epoch_in_tip() {
        // Some Koios deployments quote even the epoch number; the lenient
        // deserializer accepts it.
        let body = serde_json::json!([{ "epoch_no": "508" }]);
        assert_eq!(parse_koios_tip(&body).expect("parse string epoch"), 508);
    }

    #[test]
    fn koios_config_default_selects_the_per_network_url_and_an_override_replaces_it() {
        // The default is the public per-network URL: network selection stays
        // automatic when no override is configured.
        let keyless = KoiosConfig::default();
        for network in [Network::Mainnet, Network::Preprod, Network::Preview] {
            assert_eq!(keyless.base_url_for(network), network.koios_base_url());
        }

        // An override replaces the per-network default for EVERY network: the
        // operator named one instance and it answers regardless of which network
        // enum value resolves the URL.
        let overridden = KoiosConfig {
            base_url: Some("https://koios.example/api/v1".to_string()),
            api_key: None,
        };
        for network in [Network::Mainnet, Network::Preprod, Network::Preview] {
            assert_eq!(
                overridden.base_url_for(network),
                "https://koios.example/api/v1"
            );
        }
    }

    #[test]
    fn koios_config_debug_redacts_the_api_key() {
        let config = KoiosConfig {
            base_url: Some("https://koios.example/api/v1".to_string()),
            api_key: Some("a-very-secret-jwt".to_string().into()),
        };
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("a-very-secret-jwt"),
            "the API key must never appear in a Debug rendering, got {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        assert!(
            rendered.contains("https://koios.example/api/v1"),
            "the base URL is not a secret and stays visible for the operator"
        );
    }

    #[test]
    fn networks_map_to_distinct_keyless_base_urls() {
        assert_eq!(Network::Mainnet.as_str(), "mainnet");
        assert_eq!(Network::Preprod.as_str(), "preprod");
        assert_eq!(Network::Preview.as_str(), "preview");
        assert!(Network::Mainnet
            .koios_base_url()
            .starts_with("https://api.koios.rest"));
        assert!(Network::Preprod
            .koios_base_url()
            .starts_with("https://preprod.koios.rest"));
        assert!(Network::Preview
            .koios_base_url()
            .starts_with("https://preview.koios.rest"));
        // Every network resolves to a distinct base URL, so no two networks
        // share a provider endpoint.
        let urls = [
            Network::Mainnet.koios_base_url(),
            Network::Preprod.koios_base_url(),
            Network::Preview.koios_base_url(),
        ];
        for (i, a) in urls.iter().enumerate() {
            for b in &urls[i + 1..] {
                assert_ne!(a, b, "each network must have its own keyless endpoint");
            }
        }
        // Keyless: no API-key query parameter is ever appended.
        for url in urls {
            assert!(!url.contains("api_key"), "keyless endpoint: {url}");
        }
    }
}
