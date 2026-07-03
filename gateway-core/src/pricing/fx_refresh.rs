//! The FX refresh loop: the only writer of `cw_core.fx_rate`.
//!
//! On each tick the loop reads the live ADA/USD and AR/USD prices from CoinGecko
//! and the live per-byte Arweave storage price from Turbo (with the Arweave-native
//! gateway as a fallback), then inserts ONE `cw_core.fx_rate` row. Every quote
//! reads the newest row, so the request path never touches an oracle.
//!
//! The discipline is live-data-only, mirroring how the rest of the system prices:
//!
//! - The cron is the only oracle caller; quote/upload requests read the cached
//!   newest row.
//! - There is NO hardcoded fallback ratio. If BOTH per-byte oracles fail in one
//!   tick the loop writes NO row and returns a skip: the previous row keeps
//!   serving quotes and the next tick retries. The Arweave storage market is not
//!   stable enough to pin a constant, and a wrong constant would silently mis-bill
//!   every quote.
//! - A finite-budget price key answers an exhausted quota with HTTP 429. The loop
//!   NEVER retries into the quota: it arms a restart-survivable cooldown and
//!   returns cleanly. Subsequent ticks read the cooldown before any call.
//! - On a fresh database with no row, a single cold-start seed runs at boot. If it
//!   cannot seed (oracle down, or a cooldown is already in effect with no prior
//!   row), the deployment reports the pricing dependency unavailable rather than
//!   quoting against a missing snapshot.

use chrono::Utc;
use serde_json::json;

use crate::pricing::cooldown::{clear_cooldown, read_cooldown, write_cooldown};
use crate::pricing::oracle::{
    fetch_arweave_native_winston, fetch_turbo_winc, CoinPriceProvider, CoinPrices,
    PriceProviderError, SAMPLE_BYTES,
};
use crate::pricing::units::ar_usd_per_byte_femto;
use crate::{Error, Result};

/// How long oracle calls are suspended after a quota signal. A monthly-budget key
/// that is clearly exhausted for the hour should not be re-probed every tick; an
/// hour is long enough to stop the churn yet short enough that a transient upstream
/// blip recovers on its own.
const COOLDOWN_DURATION: chrono::Duration = chrono::Duration::hours(1);

/// The configuration one refresh tick reads its oracles through.
///
/// All of it is operator config the binary supplies: the coin-price provider chain
/// and the two storage-service URLs the per-byte oracles live on. The engine
/// bundles no per-byte defaults here, so a deployment that wires the FX loop
/// chooses those endpoints; the coin-price chain always ends in keyless CoinPaprika.
#[derive(Debug, Clone)]
pub struct FxRefreshConfig {
    /// The ordered coin-price provider chain (ADA/USD + AR/USD). The tick tries
    /// them in order until one answers. CoinPaprika is always the keyless tail, so
    /// the chain is never empty.
    pub coin_price_providers: Vec<CoinPriceProvider>,
    /// The Turbo payment-service base URL the primary per-byte oracle reads
    /// `/v1/price/bytes/{n}` from.
    pub turbo_payment_url: String,
    /// The Arweave gateway base URL the fallback per-byte oracle reads
    /// `/price/{n}` from.
    pub arweave_gateway_url: String,
}

/// What one refresh tick did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FxRefreshOutcome {
    /// A fresh row was inserted; carries its id and the two prices it recorded.
    Wrote {
        /// The inserted row's id.
        fx_rate_id: i64,
        /// The ADA/USD price the row recorded, in micro-USD.
        ada_usd_micros: i64,
        /// The per-byte Arweave price the row recorded, in femto-USD.
        ar_usd_per_byte_femto: i64,
    },
    /// The tick exited cleanly without writing a row. `reason` records why.
    Skipped {
        /// The cause of the skip.
        reason: SkipReason,
    },
}

/// Why a tick skipped writing a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// No coin-price provider produced ADA/AR prices: a cooldown-gated provider was
    /// exhausted or cooling and the keyless fallback could not fill in. The previous
    /// row keeps serving quotes.
    CoinPricesUnavailable,
    /// Both per-byte oracles failed; the previous row keeps serving quotes.
    PerByteOraclesUnavailable,
}

impl SkipReason {
    /// The stable token for logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::CoinPricesUnavailable => "coin_prices_unavailable",
            SkipReason::PerByteOraclesUnavailable => "per_byte_oracles_unavailable",
        }
    }
}

/// What the coin-price provider chain produced this tick.
enum CoinPriceResolution {
    /// A provider answered. Carries the prices, the winning provider's source
    /// label, and a per-provider diagnostic of the attempts made.
    Resolved {
        /// The ADA/USD + AR/USD reading.
        prices: CoinPrices,
        /// The winning provider's `source_label` (stamped on the row).
        source: String,
        /// Per-provider attempt diagnostics, recorded in the row's `raw_response`.
        attempts: serde_json::Value,
    },
    /// No provider produced prices, and a cooldown-gated provider was exhausted or
    /// cooling (the keyless fallback could not fill in). Skip the tick and serve the
    /// previous row rather than failing — this is the recoverable case.
    Skip {
        /// Per-provider attempt diagnostics.
        attempts: serde_json::Value,
    },
}

/// Read ADA/USD + AR/USD from the provider chain, trying each provider in order
/// until one answers.
///
/// The discipline mirrors the rest of the FX lane:
///
/// - A cooldown-gated provider (CoinGecko) is skipped while its cooldown is open,
///   and an exhausted-quota signal from it arms the cooldown — the loop NEVER
///   retries into the quota. The chain then falls through to the next provider.
/// - The keyless fallback (CoinPaprika) is never gated; a quota or transient error
///   from it just moves on.
/// - If a provider succeeds after the cooldown was armed, the gate is cleared (the
///   quota window rolled over).
///
/// Returns [`CoinPriceResolution::Resolved`] on the first success;
/// [`CoinPriceResolution::Skip`] when no provider produced prices but a
/// quota/cooldown was in play (serve the previous row); and `Err` only when every
/// provider failed transiently (no quota involved), so the schedule retries.
async fn resolve_coin_prices(
    pool: &sqlx::PgPool,
    providers: &[CoinPriceProvider],
) -> Result<CoinPriceResolution> {
    // Read the cooldown once: it gates the (single) CoinGecko provider in the chain.
    let cooldown = read_cooldown(pool).await?;
    let cooldown_closed = cooldown.is_closed(Utc::now());

    let mut attempts: Vec<serde_json::Value> = Vec::new();
    // True once a quota signal or an active cooldown blocked a provider this tick.
    // It selects skip-and-serve-the-previous-row over a hard retry when the chain
    // ends without prices.
    let mut saw_quota_or_cooldown = false;
    let mut transient_failures: Vec<String> = Vec::new();

    for provider in providers {
        let label = provider.source_label();
        let gated = provider.is_cooldown_gated();

        // A cooling, cooldown-gated provider is not even probed; fall through.
        if gated && cooldown_closed {
            attempts.push(json!({ "provider": label, "skipped": "cooldown" }));
            saw_quota_or_cooldown = true;
            continue;
        }

        match provider.fetch().await {
            Ok(prices) => {
                // The quota window rolled over: clear the gate so the next tick
                // probes the gated provider again. Best-effort; a failed clear is
                // non-fatal (the next success retries).
                if gated && cooldown.cooldown_until.is_some() {
                    if let Err(e) = clear_cooldown(pool).await {
                        tracing::warn!(error = %e, "fx refresh: clearing the oracle cooldown after success failed");
                    }
                }
                attempts.push(json!({
                    "provider": label, "ada_usd": prices.ada_usd, "ar_usd": prices.ar_usd
                }));
                return Ok(CoinPriceResolution::Resolved {
                    prices,
                    source: label,
                    attempts: json!(attempts),
                });
            }
            Err(PriceProviderError::QuotaExhausted { status, body }) => {
                saw_quota_or_cooldown = true;
                // Only a gated provider arms the persistent cooldown; the keyless
                // fallback is just retried next tick.
                if gated {
                    let until = Utc::now() + COOLDOWN_DURATION;
                    write_cooldown(pool, until, status, &body).await?;
                    tracing::warn!(
                        provider = %label,
                        status,
                        cooldown_until = %until,
                        "fx refresh: price provider quota exhausted; armed cooldown, trying the next provider"
                    );
                }
                attempts.push(json!({ "provider": label, "quota_exhausted": status }));
            }
            Err(PriceProviderError::Failed(detail)) => {
                transient_failures.push(format!("{label}: {detail}"));
                attempts.push(json!({ "provider": label, "error": detail }));
            }
        }
    }

    // The chain ended without prices. A quota or cooldown in the mix is the
    // recoverable case (serve the previous row); purely transient failures fail the
    // tick so the schedule retries within its attempt budget.
    if saw_quota_or_cooldown {
        Ok(CoinPriceResolution::Skip {
            attempts: json!(attempts),
        })
    } else {
        Err(Error::Config(format!(
            "fx refresh: every coin-price provider failed: {}",
            transient_failures.join("; ")
        )))
    }
}

/// Run one refresh tick: read the oracles and, on success, insert one row.
///
/// The contract is the live-data-only discipline at the top of this module. The
/// coin-price provider chain is the gate: without ADA/USD there is nothing to
/// write. The chain tries each provider in order (skipping a cooling CoinGecko),
/// so a CoinGecko quota signal falls through to keyless CoinPaprika rather than
/// skipping the tick. Only when no provider produces prices does the tick skip
/// (serving the previous row) or, on purely transient failures, fail so the
/// schedule retries. A per-byte miss on BOTH oracles returns a skip with no row.
pub async fn fx_refresh(pool: &sqlx::PgPool, config: &FxRefreshConfig) -> Result<FxRefreshOutcome> {
    // Live ADA/USD + AR/USD from the provider chain.
    let resolution = resolve_coin_prices(pool, &config.coin_price_providers).await?;
    let (prices, price_source, mut raw) = match resolution {
        CoinPriceResolution::Resolved {
            prices,
            source,
            attempts,
        } => {
            let raw = json!({
                "coin_prices": { "ada_usd": prices.ada_usd, "ar_usd": prices.ar_usd, "source": source },
                "coin_price_attempts": attempts,
            });
            (prices, source, raw)
        }
        CoinPriceResolution::Skip { attempts } => {
            tracing::warn!(
                attempts = %attempts,
                "fx refresh: no coin-price provider produced prices; serving the previous row"
            );
            return Ok(FxRefreshOutcome::Skipped {
                reason: SkipReason::CoinPricesUnavailable,
            });
        }
    };
    let ada_usd_micros = prices.ada_usd_micros()?;

    // Per-byte storage price: Turbo first, the Arweave-native gateway second. One
    // must answer to write a row; if both fail we skip and the previous row serves.
    let (ar_usd_per_byte_femto_value, per_byte_source) = match fetch_turbo_winc(
        &config.turbo_payment_url,
        SAMPLE_BYTES,
    )
    .await
    {
        Ok(winc) => {
            let femto = ar_usd_per_byte_femto(winc, SAMPLE_BYTES, prices.ar_usd)?;
            raw["turbo"] = json!({ "sample_bytes": SAMPLE_BYTES, "winc": winc.to_string() });
            (femto, "turbo")
        }
        Err(turbo_err) => {
            tracing::warn!(error = %turbo_err, "fx refresh: Turbo per-byte oracle unavailable, trying the Arweave gateway");
            raw["turbo_error"] = json!(turbo_err.to_string());
            match fetch_arweave_native_winston(&config.arweave_gateway_url, SAMPLE_BYTES).await {
                Ok(winston) => {
                    let femto = ar_usd_per_byte_femto(winston, SAMPLE_BYTES, prices.ar_usd)?;
                    raw["arweave_native"] =
                        json!({ "sample_bytes": SAMPLE_BYTES, "winston": winston.to_string() });
                    (femto, "arweave-native")
                }
                Err(arweave_err) => {
                    tracing::warn!(
                        turbo_error = %turbo_err,
                        arweave_error = %arweave_err,
                        "fx refresh: both per-byte oracles unavailable; serving the previous row"
                    );
                    // No hardcoded fallback ratio: write nothing, the prior row serves.
                    return Ok(FxRefreshOutcome::Skipped {
                        reason: SkipReason::PerByteOraclesUnavailable,
                    });
                }
            }
        }
    };

    // The `source` records the per-byte oracle that won and the coin-price provider
    // that produced the prices, so the stamped value stays human-scannable yet tells
    // which feeds produced the row (e.g. `turbo+coinpaprika`, `turbo+coingecko-pro`).
    let source = compose_source(per_byte_source, &price_source);

    let fx_rate_id: i64 = sqlx::query_scalar(
        "INSERT INTO cw_core.fx_rate (ada_usd_micros, ar_usd_per_byte_femto, source, raw_response) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(ada_usd_micros)
    .bind(ar_usd_per_byte_femto_value)
    .bind(&source)
    .bind(&raw)
    .fetch_one(pool)
    .await?;

    tracing::info!(
        fx_rate_id,
        ada_usd_micros,
        ar_usd_per_byte_femto = ar_usd_per_byte_femto_value,
        source = %source,
        "fx refresh wrote a new snapshot"
    );

    Ok(FxRefreshOutcome::Wrote {
        fx_rate_id,
        ada_usd_micros,
        ar_usd_per_byte_femto: ar_usd_per_byte_femto_value,
    })
}

/// The advisory-lock name the cold-start seed serializes on. `cw_core.fx_rate`
/// has only a `bigserial` primary key, so there is no natural-key constraint to
/// dedupe an insert against (unlike the protocol-parameter cache, whose
/// `(network, epoch)` key lets two racing replicas both insert under
/// `ON CONFLICT DO NOTHING`). To give the seed the same "two replicas -> at most
/// one effective seed" guarantee, the whole check-then-insert runs under this one
/// transaction-scoped advisory lock, keyed with the SQL-side
/// `hashtext(name)::bigint` idiom the event-sequence allocator and the
/// session-create serializer share.
const FX_SEED_LOCK_NAME: &str = "cw_core:fx_rate:cold_start_seed";

/// Seed the FX snapshot once on a cold start.
///
/// If a row already exists this returns immediately (the recurring schedule keeps
/// it fresh). On a fresh database it runs a single refresh so the very first quote
/// sees a row. A cold-start tick that cannot write a row (oracle down, or a
/// cooldown already in effect with no prior row to fall back to) is a hard error:
/// the deployment must not begin quoting against a missing snapshot. This mirrors
/// the protocol-parameter cold-start gate.
///
/// Two replicas booting on a fresh database would each observe an empty
/// `cw_core.fx_rate`, each call the oracles, and each insert, leaving a duplicate
/// seed row (the table has no constraint to dedupe on). The seed therefore takes
/// a transaction-scoped advisory lock and re-checks for a row *inside* it: the
/// replica that wins the lock seeds; any replica that arrives after sees the row
/// the winner committed and returns without touching the oracles. The result is
/// exactly one seed row and no redundant oracle traffic at cold start. The hard
/// "cannot seed an empty table" boot error still applies to the replica that
/// actually does the seeding.
pub async fn ensure_fx_seeded(pool: &sqlx::PgPool, config: &FxRefreshConfig) -> Result<()> {
    // A cheap unlocked pre-check: in steady state a row already exists and no lock
    // contention is needed.
    if fx_row_exists(pool).await? {
        return Ok(());
    }

    // The table is empty as far as this replica saw. Serialize the seed under the
    // advisory lock so a concurrent replica cannot insert a second seed row in the
    // gap between the check and the insert.
    let mut txn = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(FX_SEED_LOCK_NAME)
        .execute(&mut *txn)
        .await?;

    // Re-check under the lock: a replica that held the lock first has already
    // committed its seed, so this read (a fresh post-lock snapshot) sees it and we
    // return without calling the oracles or inserting.
    if fx_row_exists_in(&mut txn).await? {
        txn.commit().await?;
        tracing::info!("fx refresh: cold-start seed already done by another replica");
        return Ok(());
    }

    // Still empty under the lock: this replica is the seeder. Hold the lock across
    // the refresh so a competitor blocks until the seeded row is committed.
    tracing::info!("fx refresh: cold start detected; seeding the first snapshot");
    let outcome = fx_refresh(pool, config).await?;
    txn.commit().await?;
    match outcome {
        FxRefreshOutcome::Wrote { fx_rate_id, .. } => {
            tracing::info!(fx_rate_id, "fx refresh: cold-start snapshot seeded");
            Ok(())
        }
        FxRefreshOutcome::Skipped { reason } => Err(Error::Config(format!(
            "fx refresh skipped at cold start (reason={}); cannot seed an empty cw_core.fx_rate",
            reason.as_str()
        ))),
    }
}

/// Whether any `cw_core.fx_rate` row exists, read through a pool.
async fn fx_row_exists(pool: &sqlx::PgPool) -> Result<bool> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM cw_core.fx_rate)")
        .fetch_one(pool)
        .await?;
    Ok(exists)
}

/// Whether any `cw_core.fx_rate` row exists, read inside the seed transaction so
/// the check shares the advisory lock's snapshot ordering.
async fn fx_row_exists_in(txn: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<bool> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM cw_core.fx_rate)")
        .fetch_one(&mut **txn)
        .await?;
    Ok(exists)
}

/// Compose the row's `source` from the winning per-byte oracle and the coin-price
/// provider that produced the prices, e.g. `turbo+coinpaprika` or
/// `arweave-native+coingecko-pro`. Human-scannable and records both feeds.
fn compose_source(per_byte: &str, price_source: &str) -> String {
    format!("{per_byte}+{price_source}")
}

// ---------------------------------------------------------------------------
// The cron handler, policy, and schedule.
// ---------------------------------------------------------------------------

/// The queue the FX refresh loop runs on.
pub const FX_REFRESH_QUEUE: &str = "fx_refresh";

/// The default cadence: every fifteen minutes.
///
/// This default is chosen to keep an unconfigured deployment — which prices from
/// keyless CoinPaprika — safely inside CoinPaprika's free allowance (~1,000
/// requests/day, no API key). CoinPaprika has no batch-by-id endpoint, so one tick
/// makes TWO requests (one per coin: `ada-cardano`, `ar-arweave`). At two calls per
/// tick:
///
///   2 calls/tick x 4 ticks/hour x 24 hours = 192 calls/day
///
/// which is well under the ~1,000/day keyless allowance, with wide room for the
/// cold-start seed and the odd retry. (The per-byte storage oracle is a separate
/// Turbo/Arweave-gateway call and does not count toward the coin-price budget. A
/// deployment that configures a CoinGecko key instead makes one batched
/// `/simple/price` call per tick against CoinGecko, falling back to CoinPaprika.)
/// Fifteen minutes is also frequent enough that a quote rarely outlives its TTL
/// before a fresh snapshot lands.
///
/// This is only the DEFAULT, used when `[fx] refresh_schedule` is absent. An
/// operator can set a faster cadence in config; one who wants to spend even less of
/// the free budget can set a slower one.
pub const DEFAULT_FX_REFRESH_SCHEDULE: &str = "0 */15 * * * *";

/// The policy for the FX refresh queue: a singleton loop so a single tick is in
/// flight across the whole deployment (two replicas must never both hit the
/// oracles per occurrence), with a short fixed backoff and a small attempt budget
/// that rides out a transient oracle blip until the next scheduled tick.
#[must_use]
pub fn fx_refresh_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        FX_REFRESH_QUEUE,
        3,
        crate::runtime::Backoff::Fixed { base_secs: 60 },
        // One tick makes a handful of HTTP calls; a 2-minute lease is ample and
        // reclaims promptly if a replica dies mid-tick.
        120,
    )
}

/// The schedule that fires the FX refresh loop on the configured cadence. The
/// scheduler's `cron_tick` gate ensures exactly one replica enqueues each
/// occurrence.
#[must_use]
pub fn fx_refresh_schedule(cron: impl Into<String>) -> crate::runtime::scheduler::CronSchedule {
    crate::runtime::scheduler::CronSchedule::new(
        cron.into(),
        FX_REFRESH_QUEUE,
        serde_json::Value::Null,
    )
}

/// The FX refresh job handler.
///
/// Register it on the runtime against [`FX_REFRESH_QUEUE`] with
/// [`fx_refresh_policy`] and [`fx_refresh_schedule`]. It owns its pool and the
/// oracle configuration, so the runtime can drive it with only a
/// [`crate::runtime::JobContext`]. A quota signal or a per-byte miss is a clean
/// completion (the discipline is to skip, not fail); only a true oracle failure
/// fails the attempt so the schedule retries.
pub struct FxRefreshHandler {
    pool: sqlx::PgPool,
    config: FxRefreshConfig,
}

impl FxRefreshHandler {
    /// Build the handler over a pool and the oracle configuration.
    #[must_use]
    pub fn new(pool: sqlx::PgPool, config: FxRefreshConfig) -> Self {
        Self { pool, config }
    }

    /// Run one refresh tick. Exposed so the cold-start seed and integration tests
    /// drive the same path the cron does.
    pub async fn run_once(&self) -> Result<FxRefreshOutcome> {
        fx_refresh(&self.pool, &self.config).await
    }
}

impl crate::runtime::JobHandler for FxRefreshHandler {
    async fn handle(&self, _ctx: crate::runtime::JobContext) -> crate::runtime::JobOutcome {
        match self.run_once().await {
            Ok(outcome) => {
                tracing::debug!(?outcome, "fx refresh tick complete");
                crate::runtime::JobOutcome::Complete
            }
            Err(e) => {
                tracing::warn!(error = %e, "fx refresh tick failed");
                crate::runtime::JobOutcome::Fail {
                    error: crate::runtime::JobError::new("fx_refresh_failed", e.to_string()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_reasons_have_stable_tokens() {
        assert_eq!(
            SkipReason::CoinPricesUnavailable.as_str(),
            "coin_prices_unavailable"
        );
        assert_eq!(
            SkipReason::PerByteOraclesUnavailable.as_str(),
            "per_byte_oracles_unavailable"
        );
    }

    #[test]
    fn source_records_both_the_per_byte_oracle_and_the_price_provider() {
        assert_eq!(compose_source("turbo", "coinpaprika"), "turbo+coinpaprika");
        assert_eq!(
            compose_source("turbo", "coingecko-pro"),
            "turbo+coingecko-pro"
        );
        assert_eq!(
            compose_source("arweave-native", "coingecko-demo"),
            "arweave-native+coingecko-demo"
        );
    }

    #[test]
    fn the_refresh_policy_is_a_singleton_loop() {
        let policy = fx_refresh_policy();
        assert_eq!(policy.queue, FX_REFRESH_QUEUE);
    }

    #[test]
    fn the_default_schedule_stays_inside_the_keyless_coinpaprika_budget() {
        // The default cadence must keep an unconfigured deployment — which prices
        // from keyless CoinPaprika — inside CoinPaprika's free daily allowance.
        // CoinPaprika has no batch-by-id endpoint, so one tick makes TWO calls (one
        // per coin). Count the cron's occurrences over a single day and assert the
        // resulting daily spend clears the keyless allowance with margin.
        use chrono::{Duration, TimeZone, Utc};
        use croner::parser::{CronParser, Seconds};

        let cron = CronParser::builder()
            .seconds(Seconds::Optional)
            .build()
            .parse(DEFAULT_FX_REFRESH_SCHEDULE)
            .expect("the default schedule must be a valid cron expression");

        let start = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let window_end = start + Duration::days(1);

        let mut ticks_per_day = 0u32;
        let mut cursor = start;
        while let Ok(next) = cron.find_next_occurrence(&cursor, false) {
            if next >= window_end {
                break;
            }
            ticks_per_day += 1;
            cursor = next;
        }

        // Two CoinPaprika calls per tick. The keyless allowance is ~1,000
        // calls/day; keep the default comfortably below that. A 15-minute cadence
        // is 96 ticks/day = 192 calls/day, leaving wide margin for the cold-start
        // seed, the odd retry, and a faster operator-set cadence.
        const KEYLESS_DAILY_BUDGET: u32 = 1_000;
        const COINPAPRIKA_CALLS_PER_TICK: u32 = 2;
        let daily_calls = ticks_per_day * COINPAPRIKA_CALLS_PER_TICK;
        assert!(
            daily_calls < KEYLESS_DAILY_BUDGET,
            "default FX cadence fires {ticks_per_day} ticks/day = {daily_calls} CoinPaprika \
             calls/day, which is not safely under the {KEYLESS_DAILY_BUDGET}/day keyless allowance"
        );
        // Also assert it is not so sparse that quotes routinely outlive the FX
        // snapshot's freshness window; a 15-minute cadence sits well above this.
        assert!(
            ticks_per_day >= 60,
            "default FX cadence of {ticks_per_day} ticks/day is sparser than intended"
        );
    }
}
