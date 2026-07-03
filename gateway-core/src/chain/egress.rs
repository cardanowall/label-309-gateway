//! The per-provider egress budget and request accounting.
//!
//! Every HTTP request a chain provider implementation issues passes through
//! one [`ProviderEgress::admit`] call first: a token-bucket budget that makes a
//! single gateway process physically unable to stampede a provider, plus a
//! request counter persisted into per-day Postgres buckets so the operator can
//! see exactly how much of each provider's quota the instance is consuming.
//!
//! # Why a local budget exists at all
//!
//! The chain loops are individually well-paced, but pacing is an emergent
//! property of queue policies, re-enqueue delays, and cron dedupe — a defect in
//! any one of them can collapse the effective cadence to HTTP latency and burn
//! a provider's entire daily quota in an afternoon. The budget is the
//! invariant those layers can no longer break: however fast callers iterate,
//! the egress refuses to issue more than the configured sustained rate (plus a
//! bounded burst) per provider.
//!
//! # Failure semantics
//!
//! An exhausted budget fails the call with the provider rate-limit class
//! ([`ChainErrorClass::Http`] status 429), so every existing seam reacts the
//! way it already reacts to a real provider 429: the failover wrapper tries
//! the secondary, engages the persisted cooldown, and raises the all-provider
//! storm that parks the submit/confirm/scan loops until the window passes.
//! Nothing upstream needs to know whether the 429 came from the provider or
//! from this local backstop.
//!
//! # Accounting
//!
//! Issued (admitted) and denied requests are counted per `(provider, network,
//! UTC day)` and upserted into `cw_core.chain_provider_request_day`. The write
//! is best-effort: accounting must never fail or slow a data-path call beyond
//! the single cheap upsert, so a persistence error is logged and the call
//! proceeds. The control plane exposes the rows for operator visibility.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::gateway::{chain_error, ChainErrorClass, ProviderKind};
use super::params::Network;
use crate::Result;

/// The tunable egress budget for one provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressLimits {
    /// Sustained request rate: the bucket refills at this many tokens per
    /// minute.
    pub requests_per_minute: u32,
    /// Burst capacity: the most requests that can be issued back-to-back from
    /// a full bucket (a deep forward-scan catch-up legitimately bursts).
    pub burst: u32,
}

impl Default for EgressLimits {
    /// The default budget: 30 sustained requests per minute with a 300-request
    /// burst, per provider.
    ///
    /// 30/min caps a runaway loop at 43,200 requests per provider per day —
    /// under the smallest paid-relevant daily quota among the configured
    /// providers — while sitting far above the legitimate steady state (a
    /// caught-up instance makes a handful of calls per minute). The burst
    /// absorbs a deep catch-up tick (a Blockfrost label-scan page walk
    /// hydrates coordinates per row) without throttling it mid-window; a
    /// catch-up deeper than the burst simply fails over / parks and resumes,
    /// because the scan never advances its cursor past an unread range.
    fn default() -> Self {
        Self {
            requests_per_minute: 30,
            burst: 300,
        }
    }
}

/// A token bucket over a caller-supplied clock instant.
///
/// Pure state machine: `try_take` is handed `now` so the refill math is
/// directly testable without sleeping.
#[derive(Debug)]
struct TokenBucket {
    /// Current tokens, fractional so slow refills accumulate smoothly.
    tokens: f64,
    /// When the bucket last refilled.
    last_refill: Instant,
    /// The bucket's capacity (the burst).
    capacity: f64,
    /// Tokens added per second (the sustained rate).
    refill_per_sec: f64,
}

impl TokenBucket {
    fn new(limits: EgressLimits, now: Instant) -> Self {
        let capacity = f64::from(limits.burst.max(1));
        Self {
            tokens: capacity,
            last_refill: now,
            capacity,
            refill_per_sec: f64::from(limits.requests_per_minute) / 60.0,
        }
    }

    /// Refill for the time elapsed since the last call, then take one token if
    /// available. Returns whether a token was taken.
    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The egress gate one provider's HTTP requests pass through.
///
/// Shared (as an `Arc`) by every gateway instance that talks to the same
/// provider+network, so the budget and the counters are process-global per
/// provider no matter how many failover pairs the handlers construct.
pub struct ProviderEgress {
    provider: ProviderKind,
    network: Network,
    /// The budget, or `None` for an unlimited gate (counting only).
    bucket: Option<Mutex<TokenBucket>>,
    /// The per-day accounting store, or `None` for in-memory counting only.
    accounting: Option<sqlx::PgPool>,
    /// Requests admitted (issued to the provider) over this process's lifetime.
    issued: AtomicU64,
    /// Requests denied by the budget over this process's lifetime.
    denied: AtomicU64,
}

impl ProviderEgress {
    /// A budgeted, Postgres-accounted egress: the production gate.
    #[must_use]
    pub fn new(
        provider: ProviderKind,
        network: Network,
        limits: EgressLimits,
        pool: sqlx::PgPool,
    ) -> Self {
        Self {
            provider,
            network,
            bucket: Some(Mutex::new(TokenBucket::new(limits, Instant::now()))),
            accounting: Some(pool),
            issued: AtomicU64::new(0),
            denied: AtomicU64::new(0),
        }
    }

    /// A budgeted, in-memory egress: throttles and counts but persists nothing.
    /// The default a bare provider constructor attaches, so even a gateway
    /// built outside the failover assembly cannot stampede a provider.
    #[must_use]
    pub fn budgeted_in_memory(
        provider: ProviderKind,
        network: Network,
        limits: EgressLimits,
    ) -> Self {
        Self {
            provider,
            network,
            bucket: Some(Mutex::new(TokenBucket::new(limits, Instant::now()))),
            accounting: None,
            issued: AtomicU64::new(0),
            denied: AtomicU64::new(0),
        }
    }

    /// An unlimited, in-memory egress: counts but never denies. A test seam for
    /// suites that drive a provider through thousands of scripted calls.
    #[must_use]
    pub fn unlimited(provider: ProviderKind, network: Network) -> Self {
        Self {
            provider,
            network,
            bucket: None,
            accounting: None,
            issued: AtomicU64::new(0),
            denied: AtomicU64::new(0),
        }
    }

    /// The provider this gate fronts.
    #[must_use]
    pub fn provider(&self) -> ProviderKind {
        self.provider
    }

    /// The network this gate fronts.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// Requests admitted over this process's lifetime.
    #[must_use]
    pub fn issued_total(&self) -> u64 {
        self.issued.load(Ordering::Relaxed)
    }

    /// Requests denied by the budget over this process's lifetime.
    #[must_use]
    pub fn denied_total(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }

    /// Admit one outbound HTTP request, or fail with the provider rate-limit
    /// error class when the budget is exhausted.
    ///
    /// Called by the provider implementations immediately before every HTTP
    /// send, so pagination and per-row hydration are each counted as the
    /// requests they really are. The admitted/denied tally is upserted into
    /// the per-day accounting bucket best-effort: an accounting write failure
    /// is logged and never fails the call.
    pub async fn admit(&self) -> Result<()> {
        let admitted = match &self.bucket {
            None => true,
            Some(bucket) => bucket
                .lock()
                .expect("egress token bucket lock poisoned")
                .try_take(Instant::now()),
        };

        if admitted {
            self.issued.fetch_add(1, Ordering::Relaxed);
            self.persist(1, 0).await;
            Ok(())
        } else {
            self.denied.fetch_add(1, Ordering::Relaxed);
            self.persist(0, 1).await;
            Err(chain_error(
                ChainErrorClass::Http { status: 429 },
                format!(
                    "local egress budget exhausted for {} on {}; refusing to issue the request",
                    self.provider.as_str(),
                    self.network.as_str()
                ),
            ))
        }
    }

    /// Best-effort upsert of one admit/deny observation into the per-day bucket.
    async fn persist(&self, issued: i64, denied: i64) {
        let Some(pool) = &self.accounting else {
            return;
        };
        if let Err(err) = record_requests(
            pool,
            self.provider,
            self.network,
            chrono::Utc::now().date_naive(),
            issued,
            denied,
        )
        .await
        {
            tracing::warn!(
                provider = self.provider.as_str(),
                network = self.network.as_str(),
                error = %err,
                "provider request accounting write failed; the request proceeds uncounted"
            );
        }
    }
}

/// Upsert a request-count observation into `cw_core.chain_provider_request_day`.
///
/// Split out from [`ProviderEgress`] so the accounting write is directly
/// testable and reusable (the egress calls it best-effort; a test asserts the
/// row arithmetic exactly).
pub async fn record_requests(
    pool: &sqlx::PgPool,
    provider: ProviderKind,
    network: Network,
    day: chrono::NaiveDate,
    issued: i64,
    denied: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO cw_core.chain_provider_request_day \
           (provider, network, day, request_count, denied_count, updated_at) \
         VALUES ($1, $2, $3, $4, $5, now()) \
         ON CONFLICT (provider, network, day) DO UPDATE SET \
           request_count = cw_core.chain_provider_request_day.request_count + EXCLUDED.request_count, \
           denied_count = cw_core.chain_provider_request_day.denied_count + EXCLUDED.denied_count, \
           updated_at = now()",
    )
    .bind(provider.as_str())
    .bind(network.as_str())
    .bind(day)
    .bind(issued)
    .bind(denied)
    .execute(pool)
    .await?;
    Ok(())
}

/// The pair of per-provider egress gates one deployment shares.
///
/// Built once at assembly and cloned into every failover pair, so the budget
/// is process-global per provider: four handler-owned failover gateways all
/// draw from the same two buckets. The no-Blockfrost deployment (a second
/// Koios secondary) shares the single Koios gate across both arms, because
/// both arms consume the same Koios quota.
#[derive(Clone)]
pub struct ChainEgress {
    koios: Arc<ProviderEgress>,
    blockfrost: Arc<ProviderEgress>,
}

impl ChainEgress {
    /// The production pair: budgeted and Postgres-accounted, one gate per
    /// provider, both on the same limits.
    #[must_use]
    pub fn new(network: Network, limits: EgressLimits, pool: sqlx::PgPool) -> Self {
        Self {
            koios: Arc::new(ProviderEgress::new(
                ProviderKind::Koios,
                network,
                limits,
                pool.clone(),
            )),
            blockfrost: Arc::new(ProviderEgress::new(
                ProviderKind::Blockfrost,
                network,
                limits,
                pool,
            )),
        }
    }

    /// An unlimited in-memory pair (a test seam).
    #[must_use]
    pub fn unlimited(network: Network) -> Self {
        Self {
            koios: Arc::new(ProviderEgress::unlimited(ProviderKind::Koios, network)),
            blockfrost: Arc::new(ProviderEgress::unlimited(ProviderKind::Blockfrost, network)),
        }
    }

    /// The gate for a provider kind.
    #[must_use]
    pub fn provider(&self, kind: ProviderKind) -> Arc<ProviderEgress> {
        match kind {
            ProviderKind::Koios => Arc::clone(&self.koios),
            ProviderKind::Blockfrost => Arc::clone(&self.blockfrost),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::gateway::classify_chain_error;
    use std::time::Duration;

    #[test]
    fn the_bucket_admits_the_burst_then_denies() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(
            EgressLimits {
                requests_per_minute: 60,
                burst: 3,
            },
            now,
        );
        assert!(bucket.try_take(now), "burst token 1");
        assert!(bucket.try_take(now), "burst token 2");
        assert!(bucket.try_take(now), "burst token 3");
        assert!(
            !bucket.try_take(now),
            "the bucket is empty after the burst with no elapsed time"
        );
    }

    #[test]
    fn the_bucket_refills_at_the_sustained_rate() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(
            EgressLimits {
                requests_per_minute: 60, // one token per second
                burst: 2,
            },
            start,
        );
        assert!(bucket.try_take(start));
        assert!(bucket.try_take(start));
        assert!(!bucket.try_take(start), "drained");

        // Half a second refills half a token: still denied.
        assert!(!bucket.try_take(start + Duration::from_millis(500)));
        // Another 600ms crosses one whole token: admitted again. (The refill
        // accumulates across the denied call: the bucket keeps its fraction.)
        assert!(bucket.try_take(start + Duration::from_millis(1100)));
        assert!(
            !bucket.try_take(start + Duration::from_millis(1100)),
            "exactly one token had accrued"
        );
    }

    #[test]
    fn the_bucket_never_refills_past_its_capacity() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(
            EgressLimits {
                requests_per_minute: 6000,
                burst: 2,
            },
            start,
        );
        // An hour of refill cannot exceed the burst capacity.
        let later = start + Duration::from_secs(3600);
        assert!(bucket.try_take(later));
        assert!(bucket.try_take(later));
        assert!(
            !bucket.try_take(later),
            "capacity caps the accrual at the burst"
        );
    }

    #[tokio::test]
    async fn an_exhausted_budget_fails_with_the_rate_limited_class() {
        // A one-request budget with a negligible refill: the second admit must
        // fail with the same 429 class a real provider rate limit carries, so
        // the failover/cooldown seams treat it identically.
        let egress = ProviderEgress::budgeted_in_memory(
            ProviderKind::Koios,
            Network::Preprod,
            EgressLimits {
                requests_per_minute: 1,
                burst: 1,
            },
        );
        egress.admit().await.expect("the burst token admits");
        let err = egress.admit().await.expect_err("the drained budget denies");
        let class = classify_chain_error(&err).expect("a classified chain error");
        assert!(
            class.is_rate_limited(),
            "a budget denial must carry the provider rate-limit class, got {class:?}"
        );
        assert_eq!(egress.issued_total(), 1);
        assert_eq!(egress.denied_total(), 1);
    }

    #[tokio::test]
    async fn an_unlimited_egress_counts_but_never_denies() {
        let egress = ProviderEgress::unlimited(ProviderKind::Blockfrost, Network::Preprod);
        for _ in 0..5 {
            egress.admit().await.expect("unlimited always admits");
        }
        assert_eq!(egress.issued_total(), 5);
        assert_eq!(egress.denied_total(), 0);
    }

    #[test]
    fn default_limits_cap_a_runaway_day_under_the_provider_quotas() {
        let limits = EgressLimits::default();
        let per_day = u64::from(limits.requests_per_minute) * 60 * 24;
        assert!(
            per_day < 50_000,
            "a full day at the sustained default ({per_day}) must stay under the \
             smallest configured provider's daily quota"
        );
        assert!(
            limits.burst >= 100,
            "the burst must absorb a one-page label-scan hydration without throttling"
        );
    }
}
