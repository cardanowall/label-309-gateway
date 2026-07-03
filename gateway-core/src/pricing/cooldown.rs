//! The restart-survivable price-oracle quota cooldown.
//!
//! A finite-budget price oracle (a free price-API key) answers an exhausted quota
//! with an HTTP 429 (or an equivalent body signal). Retrying into that quota only
//! accelerates the saturation, so the refresh loop instead persists a
//! `cooldown_until` instant in `cw_core.coingecko_cooldown` and reads it BEFORE
//! every oracle call: while the gate is closed the tick exits without spending a
//! request. The row lives in Postgres so a worker restart inherits the gate; an
//! in-memory gate would re-burn the quota on the first tick after a crash.

use chrono::{DateTime, Utc};

use crate::Result;

/// The persisted cooldown gate state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CooldownState {
    /// The instant oracle calls may resume, or `None` when no cooldown is active.
    pub cooldown_until: Option<DateTime<Utc>>,
    /// When the most recent quota signal was observed.
    pub last_quota_at: Option<DateTime<Utc>>,
    /// The HTTP status of the most recent quota signal.
    pub last_quota_status: Option<i32>,
}

impl CooldownState {
    /// Whether the gate is closed right now: a cooldown instant in the future
    /// suppresses the oracle call this tick.
    #[must_use]
    pub fn is_closed(&self, now: DateTime<Utc>) -> bool {
        self.cooldown_until.is_some_and(|until| until > now)
    }
}

/// Read the current cooldown gate, or the default (open) state when no row exists
/// yet.
pub async fn read_cooldown(pool: &sqlx::PgPool) -> Result<CooldownState> {
    let row: Option<CooldownRow> = sqlx::query_as(
        "SELECT cooldown_until, last_quota_at, last_quota_status \
         FROM cw_core.coingecko_cooldown WHERE id = true",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into).unwrap_or_default())
}

/// The cooldown gate row as read from Postgres.
#[derive(sqlx::FromRow)]
struct CooldownRow {
    cooldown_until: Option<DateTime<Utc>>,
    last_quota_at: Option<DateTime<Utc>>,
    last_quota_status: Option<i32>,
}

impl From<CooldownRow> for CooldownState {
    fn from(row: CooldownRow) -> Self {
        Self {
            cooldown_until: row.cooldown_until,
            last_quota_at: row.last_quota_at,
            last_quota_status: row.last_quota_status,
        }
    }
}

/// The most a quota-signal body excerpt is stored at. A provider's quota response
/// can be an oversized HTML intercept page, so the writer keeps only a diagnostic
/// prefix.
const MAX_BODY_EXCERPT: usize = 500;

/// Arm the cooldown gate after a quota signal: stamp the resume instant and the
/// diagnostic detail. Upserts the single pinned row.
pub async fn write_cooldown(
    pool: &sqlx::PgPool,
    cooldown_until: DateTime<Utc>,
    status: u16,
    body: &str,
) -> Result<()> {
    let excerpt: String = body.chars().take(MAX_BODY_EXCERPT).collect();
    sqlx::query(
        "INSERT INTO cw_core.coingecko_cooldown \
           (id, cooldown_until, last_quota_at, last_quota_status, last_quota_body, updated_at) \
         VALUES (true, $1, now(), $2, $3, now()) \
         ON CONFLICT (id) DO UPDATE SET \
           cooldown_until = EXCLUDED.cooldown_until, \
           last_quota_at = EXCLUDED.last_quota_at, \
           last_quota_status = EXCLUDED.last_quota_status, \
           last_quota_body = EXCLUDED.last_quota_body, \
           updated_at = now()",
    )
    .bind(cooldown_until)
    .bind(i32::from(status))
    .bind(excerpt)
    .execute(pool)
    .await?;
    Ok(())
}

/// Clear the cooldown gate after a successful call: the quota window has rolled
/// over. Best-effort at the call site, but the write itself is a plain update.
pub async fn clear_cooldown(pool: &sqlx::PgPool) -> Result<()> {
    sqlx::query(
        "UPDATE cw_core.coingecko_cooldown \
         SET cooldown_until = NULL, updated_at = now() WHERE id = true",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_gate_does_not_suppress_a_call() {
        let state = CooldownState::default();
        assert!(!state.is_closed(Utc::now()));
    }

    #[test]
    fn a_future_cooldown_closes_the_gate() {
        let state = CooldownState {
            cooldown_until: Some(Utc::now() + chrono::Duration::hours(1)),
            ..Default::default()
        };
        assert!(state.is_closed(Utc::now()));
    }

    #[test]
    fn an_elapsed_cooldown_reopens_the_gate() {
        let state = CooldownState {
            cooldown_until: Some(Utc::now() - chrono::Duration::minutes(1)),
            ..Default::default()
        };
        assert!(!state.is_closed(Utc::now()));
    }
}
