//! The restart-survivable sliding-window rate limiter.
//!
//! The limiter meters a sliding 60-second window per subject. Two subject
//! families share the one table and algorithm: an authenticated credential
//! meters under its api-key / account-token row id (the guard's `authorize`
//! path), and an anonymous read meters under the hashed client address
//! [`anonymous_subject`] derives (the guard's `limit_anonymous` path, used by
//! the public records surface). The sliding window is approximated by two
//! fixed 60-second windows: the spend in the current window plus a time-weighted
//! fraction of the previous window's spend estimates the rolling 60-second count,
//! which is the standard sliding-window-counter approximation. A 2x burst
//! allowance lets a short spike through without tripping an honest client.
//!
//! The buckets live in `cw_core.rate_limit_bucket`, so a process restart does not
//! reset a subject's budget and a fresh replica honors a limit a peer was already
//! enforcing. A request reserves a token by incrementing the current window's
//! bucket; the decision and the IETF `RateLimit-*` headers are derived from the
//! weighted count.

use chrono::{DateTime, Utc};

use crate::Result;

/// The metering subject for an anonymous request from a client address.
///
/// The address is the SOCKET peer address the server accepted the connection
/// from (never a client-supplied header such as `X-Forwarded-For`, which any
/// caller can forge; a deployment behind a trusted proxy meters the proxy's
/// address, i.e. one shared anonymous budget, until a trusted-proxy seam
/// exists). The subject stores a truncated SHA-256 of the address text, so raw
/// client addresses never persist in `cw_core.rate_limit_bucket`. `None` — an
/// embedding that serves the router without connect-info — collapses onto one
/// shared subject: an unknown peer meters against a common budget rather than
/// escaping metering entirely.
#[must_use]
pub fn anonymous_subject(client_ip: Option<std::net::IpAddr>) -> String {
    use sha2::{Digest, Sha256};
    match client_ip {
        Some(ip) => {
            let digest = Sha256::digest(ip.to_string().as_bytes());
            // 16 bytes of the digest: far past collision concerns for a rate
            // bucket, half the row width of the full hash.
            format!("anon:{}", hex::encode(&digest[..16]))
        }
        None => "anon:unknown".to_string(),
    }
}

/// The fixed window length the sliding estimate is built from.
const WINDOW_SECONDS: i64 = 60;

/// The burst multiplier: a subject may spend up to `limit * BURST` in a burst
/// before the limiter rejects, smoothing over a short spike.
const BURST: f64 = 2.0;

/// The outcome of a limiter check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateDecision {
    /// Whether the request is admitted.
    pub allowed: bool,
    /// The per-window limit (the `RateLimit-Limit` header value).
    pub limit: i64,
    /// Tokens remaining in the window after this request (`RateLimit-Remaining`).
    pub remaining: i64,
    /// Seconds until the window resets (`RateLimit-Reset`, and `Retry-After` on a
    /// rejection).
    pub reset_seconds: i64,
}

/// Truncate an instant to the start of its fixed 60-second window.
fn window_start(now: DateTime<Utc>) -> DateTime<Utc> {
    let secs = now.timestamp();
    let floored = secs - secs.rem_euclid(WINDOW_SECONDS);
    DateTime::from_timestamp(floored, 0).unwrap_or(now)
}

/// Check (and on success, reserve) a token for `subject` against `limit`
/// requests per 60-second window, charging `tokens` (>= 1; batch routes charge N).
///
/// One transaction: read the current and previous window buckets, compute the
/// weighted sliding count, and if admitting would keep the count within the burst
/// ceiling, increment the current bucket by `tokens`. The decision and the
/// `RateLimit-*` values are returned for the caller to stamp on the response.
pub async fn check_and_reserve(
    pool: &sqlx::PgPool,
    subject: &str,
    limit: i64,
    tokens: i64,
    now: DateTime<Utc>,
) -> Result<RateDecision> {
    let tokens = tokens.max(1);
    let current_start = window_start(now);
    let previous_start = current_start - chrono::Duration::seconds(WINDOW_SECONDS);
    let elapsed = (now - current_start).num_seconds().clamp(0, WINDOW_SECONDS);
    let reset_seconds = WINDOW_SECONDS - elapsed;

    let mut txn = pool.begin().await?;

    // Read both windows under the transaction so a concurrent reservation cannot
    // race between the read and the increment. The `count` column is `integer`
    // (INT4); cast to bigint in SQL so an existing row decodes straight into the
    // i64 the sliding-window arithmetic uses (a bare `count` read would only work
    // while the bucket is empty and the row is absent).
    let current: i64 = sqlx::query_scalar(
        "SELECT coalesce(count, 0)::bigint FROM cw_core.rate_limit_bucket \
         WHERE subject = $1 AND window_start = $2 FOR UPDATE",
    )
    .bind(subject)
    .bind(current_start)
    .fetch_optional(&mut *txn)
    .await?
    .unwrap_or(0);

    let previous: i64 = sqlx::query_scalar(
        "SELECT coalesce(count, 0)::bigint FROM cw_core.rate_limit_bucket \
         WHERE subject = $1 AND window_start = $2",
    )
    .bind(subject)
    .bind(previous_start)
    .fetch_optional(&mut *txn)
    .await?
    .unwrap_or(0);

    // Sliding-window-counter estimate: the current window's spend plus the
    // fraction of the previous window still inside the rolling 60 seconds.
    let prev_weight = (WINDOW_SECONDS - elapsed) as f64 / WINDOW_SECONDS as f64;
    let weighted_before = current as f64 + previous as f64 * prev_weight;
    let ceiling = limit as f64 * BURST;

    let allowed = weighted_before + tokens as f64 <= ceiling;

    if allowed {
        sqlx::query(
            "INSERT INTO cw_core.rate_limit_bucket (subject, window_start, count, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (subject, window_start) \
             DO UPDATE SET count = cw_core.rate_limit_bucket.count + EXCLUDED.count, \
                           updated_at = now()",
        )
        .bind(subject)
        .bind(current_start)
        .bind(tokens)
        .execute(&mut *txn)
        .await?;
        txn.commit().await?;
    } else {
        txn.rollback().await?;
    }

    let weighted_after = if allowed {
        weighted_before + tokens as f64
    } else {
        weighted_before
    };
    let remaining = (limit as f64 - weighted_after).floor().max(0.0) as i64;

    Ok(RateDecision {
        allowed,
        limit,
        remaining,
        reset_seconds,
    })
}

/// Prune buckets whose window has fully lapsed (older than two windows ago).
/// The scheduled maintenance pass keeps the table from growing without bound.
pub async fn prune_stale_buckets(pool: &sqlx::PgPool, now: DateTime<Utc>) -> Result<u64> {
    let cutoff = window_start(now) - chrono::Duration::seconds(WINDOW_SECONDS * 2);
    let affected = sqlx::query("DELETE FROM cw_core.rate_limit_bucket WHERE window_start < $1")
        .bind(cutoff)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_start_truncates_to_the_minute_boundary() {
        let now = DateTime::from_timestamp(1_000_037, 0).unwrap();
        let start = window_start(now);
        assert_eq!(start.timestamp() % WINDOW_SECONDS, 0);
        assert!(start <= now);
        assert!(now - start < chrono::Duration::seconds(WINDOW_SECONDS));
    }

    #[test]
    fn burst_allows_more_than_the_nominal_limit() {
        // The ceiling is limit * BURST, so a limit of 10 admits up to 20 in a
        // burst within one window.
        assert!((10.0 * BURST) as i64 >= 20);
    }

    #[test]
    fn anonymous_subject_hashes_the_address_and_pools_the_unknown() {
        let a: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let b: std::net::IpAddr = "203.0.113.8".parse().unwrap();
        let sa = anonymous_subject(Some(a));
        // Distinct addresses meter independently; the same address is stable.
        assert_ne!(sa, anonymous_subject(Some(b)));
        assert_eq!(sa, anonymous_subject(Some(a)));
        // The raw address never appears in the subject (only its hash does).
        assert!(sa.starts_with("anon:"));
        assert!(!sa.contains("203.0.113.7"));
        // No peer address collapses to the one shared bucket, never to no bucket.
        assert_eq!(anonymous_subject(None), "anon:unknown");
    }
}
