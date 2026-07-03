//! The per-account margin override: a control plane pushes an effective markup.
//!
//! The base plane keeps pricing policy minimal: it knows an operator-default
//! margin and, optionally, a single per-account override. A control plane that
//! runs a richer policy (tiers, delegation, loyalty) computes its own effective
//! percentage and PUSHES it as an override here; the engine never models the
//! policy itself. The DB-backed pricing seam resolves the override ahead of the
//! default at quote time.
//!
//! Every mutation is operator-scoped: an override may be set or cleared only for
//! an account the calling operator owns, so the override surface cannot reach
//! across a tenancy boundary. A target the operator does not own resolves to
//! [`MarginOverrideOutcome::AccountNotFound`] (the route renders an oracle-safe
//! 404), exactly like every other account-addressed control mutation.

use rust_decimal::Decimal;
use uuid::Uuid;

use crate::ledger::account::account_belongs_to_operator;
use crate::ledger::quote::MarginResolution;
use crate::Result;

/// Resolve the effective markup for an account: the per-account override when one
/// exists, else the operator-default margin.
///
/// This is the single margin-resolution reader BOTH pricing seams call — the
/// reference binary's static seam and the engine's DB-backed FX seam — so margin
/// resolution is orthogonal to how the FX rate itself is sourced: a static-priced
/// quote and a live-FX quote resolve the override the same way and attribute it
/// with the same two-value vocabulary (`account-override` / `operator-default`).
/// The base plane knows only these two sources; a control plane that runs a richer
/// policy (tiers, delegation, badges) computes its own effective fraction and
/// PUSHES it as an override row (see [`set_margin_override`]), and this reader just
/// prefers an override over the default and attributes which one it used.
pub async fn resolve_margin(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    operator_default: Decimal,
) -> Result<MarginResolution> {
    let override_pct: Option<Decimal> = sqlx::query_scalar(
        "SELECT margin_pct FROM cw_core.account_margin_override WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    Ok(match override_pct {
        Some(margin_pct) => MarginResolution {
            margin_pct,
            margin_source: "account-override".to_string(),
        },
        None => MarginResolution {
            margin_pct: operator_default,
            margin_source: "operator-default".to_string(),
        },
    })
}

/// The outcome of an operator-scoped margin-override mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarginOverrideOutcome {
    /// The target account is absent or owned by another operator: no row touched.
    AccountNotFound,
    /// The override was upserted (set/replaced) for an owned account.
    Set,
    /// The override was removed for an owned account.
    Cleared,
    /// No override existed to clear for an owned account (idempotent no-op).
    NotPresent,
}

/// The number of fractional digits the `margin_pct` column stores (`numeric(6,4)`,
/// scale 4). A value with more fractional precision cannot be stored without a
/// silent round, so it is rejected rather than truncated.
const MARGIN_PCT_SCALE: u32 = 4;

/// The exclusive upper bound on `margin_pct`. The column is `numeric(6,4)`
/// (precision 6, scale 4), so the integer part holds at most `6 - 4 = 2` digits:
/// any value `>= 100` overflows the column. A control plane pushes an effective
/// fraction here (`0.25` = 25%), so values approaching 100 are themselves implausible,
/// but the bound is the column's, enforced before the write rather than as an opaque
/// Postgres numeric-overflow 500.
const MARGIN_PCT_EXCLUSIVE_MAX: i64 = 100;

/// Set (or replace) an account's margin override under `operator_id`.
///
/// Confirms the operator owns the account before any write. The upsert is
/// idempotent: re-setting the same percentage replaces the row and refreshes
/// `updated_at`. `margin_pct` is a non-negative fraction (e.g. `0.25` = 25%),
/// stored in the same `numeric(6,4)` shape the quote row records. The value is
/// validated against that column's bound and scale before the write: a negative
/// value, a value `>= 100` (the column's precision/scale leaves only two integer
/// digits), or one with more than four fractional digits is rejected as a
/// validation error so it never reaches Postgres as an opaque overflow 500.
pub async fn set_margin_override(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
    margin_pct: Decimal,
) -> Result<MarginOverrideOutcome> {
    if margin_pct.is_sign_negative() {
        return Err(crate::Error::Config(
            "a margin override must be non-negative".into(),
        ));
    }
    // Check the significant scale (trailing zeros dropped) so `0.2500` and `0.25`
    // both pass while `0.12345` is rejected: the column rounds the latter silently,
    // so refuse it rather than store a value that differs from what was requested.
    if margin_pct.normalize().scale() > MARGIN_PCT_SCALE {
        return Err(crate::Error::Config(format!(
            "a margin override must have at most {MARGIN_PCT_SCALE} fractional digits"
        )));
    }
    if margin_pct >= Decimal::from(MARGIN_PCT_EXCLUSIVE_MAX) {
        return Err(crate::Error::Config(format!(
            "a margin override must be below {MARGIN_PCT_EXCLUSIVE_MAX}"
        )));
    }
    if !account_belongs_to_operator(pool, operator_id, account_id).await? {
        return Ok(MarginOverrideOutcome::AccountNotFound);
    }

    sqlx::query(
        "INSERT INTO cw_core.account_margin_override (account_id, margin_pct, updated_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (account_id) DO UPDATE SET margin_pct = EXCLUDED.margin_pct, updated_at = now()",
    )
    .bind(account_id)
    .bind(margin_pct)
    .execute(pool)
    .await?;

    Ok(MarginOverrideOutcome::Set)
}

/// Clear an account's margin override under `operator_id`.
///
/// Confirms the operator owns the account before any write. Reports
/// [`MarginOverrideOutcome::Cleared`] when a row was removed and
/// [`MarginOverrideOutcome::NotPresent`] when none existed (idempotent).
pub async fn clear_margin_override(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
) -> Result<MarginOverrideOutcome> {
    if !account_belongs_to_operator(pool, operator_id, account_id).await? {
        return Ok(MarginOverrideOutcome::AccountNotFound);
    }

    let removed = sqlx::query("DELETE FROM cw_core.account_margin_override WHERE account_id = $1")
        .bind(account_id)
        .execute(pool)
        .await?
        .rows_affected();

    Ok(if removed == 1 {
        MarginOverrideOutcome::Cleared
    } else {
        MarginOverrideOutcome::NotPresent
    })
}
