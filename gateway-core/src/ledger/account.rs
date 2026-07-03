//! Account (tenant) provisioning.
//!
//! An account is split across two tables by privilege model: the stable
//! `cw_api.account` anchor (the columns a vendor may FK-reference) and the
//! volatile `cw_core.account_detail` satellite (the engine-internal owning
//! operator and lifecycle status). [`create_account`] writes both in one
//! transaction so an account always has exactly its anchor and its satellite.
//!
//! Removal is a soft-delete: [`soft_delete_account`] stamps `deleted_at` on the
//! anchor. A hard row delete is structurally impossible (the satellite, the
//! balance, the quotes, and the records all reference the anchor ON DELETE
//! RESTRICT), so soft-delete is the only removal path and the engine never loses
//! the historical graph hanging off an account.
//!
//! # Tenancy
//!
//! Every administrative mutation here carries the owning `operator_id` and its
//! SQL pins the row to that operator (`cw_core.account_detail.operator_id`). An
//! account belonging to a different operator simply does not match the predicate,
//! so the helper reports [`ScopedChange::NotFound`] rather than touching a row
//! across the tenant boundary. There is no unscoped variant: the operator binding
//! is part of the signature, so a route cannot mutate an account it does not own.

use uuid::Uuid;

use crate::Result;

/// A tenant's lifecycle status, stored on the `cw_core.account_detail` satellite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum AccountStatus {
    /// The account may be quoted and may publish.
    Active,
    /// The account is administratively disabled.
    Disabled,
}

impl AccountStatus {
    /// The stable wire token for this status (the same lowercase string the
    /// satellite stores), so a route reports the row's real state rather than a
    /// hardcoded literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AccountStatus::Active => "active",
            AccountStatus::Disabled => "disabled",
        }
    }
}

/// The outcome of a tenancy-scoped mutation with no meaningful status to report
/// back (a binary effect such as revoking or relabelling a key).
///
/// A mutation that targets a resource the caller's operator does not own resolves
/// to [`ScopedChange::NotFound`] (the row is invisible across the tenant boundary,
/// indistinguishable from a genuinely absent one). An owned resource resolves to
/// [`ScopedChange::Changed`] when this call performed the effect or
/// [`ScopedChange::Unchanged`] when it was already in the target state (the
/// idempotent no-op). Status-machine transitions instead return
/// [`ScopedTransition`], which carries the row's real state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedChange {
    /// No matching row under the caller's operator (absent or owned by another).
    NotFound,
    /// The effect was applied by this call.
    Changed,
    /// The row exists under the operator but was already in the target state.
    Unchanged,
}

/// The outcome of a tenancy-scoped lifecycle *status* transition, carrying the
/// row's real state so a caller never reports a hardcoded status literal.
///
/// A transition that targets a resource the caller's operator does not own
/// resolves to [`ScopedTransition::NotFound`] (invisible across the tenant
/// boundary). For an owned row the outcome carries the actual status:
/// [`ScopedTransition::Changed`] reports the verified `from` and `to` states this
/// call moved between, and [`ScopedTransition::Unchanged`] reports the row's real
/// current `status` (which may be a *different* terminal state than the requested
/// target, e.g. draining a wallet that is already `retired`), so the no-op is
/// reported truthfully rather than as the requested target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedTransition<S> {
    /// No matching row under the caller's operator (absent or owned by another).
    NotFound,
    /// The transition was applied: the row moved from `from` to `to`.
    Changed {
        /// The verified state the row held before this call.
        from: S,
        /// The state the row holds now (the requested target).
        to: S,
    },
    /// The row exists under the operator and was left untouched; `status` is its
    /// real current state (already the target, or a terminal state the requested
    /// transition does not apply to).
    Unchanged {
        /// The row's actual current state.
        status: S,
    },
}

/// Create an account under an operator, returning its id.
///
/// Writes the `cw_api.account` anchor and the `cw_core.account_detail` satellite
/// in one transaction, so the 1:1 invariant (every anchor has exactly one
/// satellite) holds by construction. The id is a UUIDv7 minted here, so a B-tree
/// index on it tracks creation order. The account starts `active`.
pub async fn create_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Result<Uuid> {
    let account_id = Uuid::now_v7();

    let mut txn = pool.begin().await?;
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(&mut *txn)
        .await?;
    sqlx::query("INSERT INTO cw_core.account_detail (account_id, operator_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(operator_id)
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;

    Ok(account_id)
}

/// Disable an account under `operator_id`: flip its satellite `status` to
/// `disabled`.
///
/// A disabled account is administratively blocked: the data plane gates new
/// quotes and publishes on this column. The transition is pinned to the owning
/// operator, so an account belonging to another operator reports
/// [`ScopedTransition::NotFound`] and is never touched. Idempotent for an owned
/// account already disabled ([`ScopedTransition::Unchanged`], reporting its real
/// status).
pub async fn disable_account(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
) -> Result<ScopedTransition<AccountStatus>> {
    scoped_status_transition(
        pool,
        operator_id,
        account_id,
        AccountStatus::Active,
        AccountStatus::Disabled,
    )
    .await
}

/// Re-enable a disabled account under `operator_id`: flip its satellite `status`
/// back to `active`.
///
/// Pinned to the owning operator (an account of another operator reports
/// [`ScopedTransition::NotFound`]). Idempotent for an owned account already active
/// ([`ScopedTransition::Unchanged`], reporting its real status).
pub async fn enable_account(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
) -> Result<ScopedTransition<AccountStatus>> {
    scoped_status_transition(
        pool,
        operator_id,
        account_id,
        AccountStatus::Disabled,
        AccountStatus::Active,
    )
    .await
}

/// Drive an operator-scoped `from -> to` status transition on an account's
/// satellite, distinguishing not-owned, applied, and idempotent-no-op outcomes,
/// and reporting the row's real status in every owned outcome.
///
/// A single round trip: the CTE locates the operator's own row (the existence
/// arm, reading back its current `status`) and a conditional UPDATE flips it only
/// when it is in the `from` state. An account outside the operator's tenancy
/// never matches the existence arm, so it is reported as absent rather than acted
/// on across the boundary. The `SELECT` returns the row's pre-update status so an
/// `Unchanged` outcome reports the account's actual state (which may be a state
/// other than the requested target), never the requested target.
async fn scoped_status_transition(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
    from: AccountStatus,
    to: AccountStatus,
) -> Result<ScopedTransition<AccountStatus>> {
    let row: Option<(bool, AccountStatus)> = sqlx::query_as(
        "WITH owned AS ( \
             SELECT account_id, status FROM cw_core.account_detail \
             WHERE account_id = $1 AND operator_id = $2 \
         ), \
         updated AS ( \
             UPDATE cw_core.account_detail d SET status = $4 \
             FROM owned \
             WHERE d.account_id = owned.account_id AND d.status = $3 \
             RETURNING d.account_id \
         ) \
         SELECT EXISTS (SELECT 1 FROM updated) AS changed, owned.status FROM owned",
    )
    .bind(account_id)
    .bind(operator_id)
    .bind(from.as_str())
    .bind(to.as_str())
    .fetch_optional(pool)
    .await?;

    Ok(match row {
        None => ScopedTransition::NotFound,
        // The UPDATE fired, so the row really was in `from` and now holds `to`.
        Some((true, _)) => ScopedTransition::Changed { from, to },
        // No update: report the row's actual current status, not the target.
        Some((false, status)) => ScopedTransition::Unchanged { status },
    })
}

/// Read an account's current lifecycle status, or `None` when the account does
/// not exist (no satellite row).
///
/// Unscoped on purpose: this is the data plane's self-account gate, where the
/// account id comes from the caller's own resolved credential (never a path
/// segment), so there is no tenant boundary to cross. A control-plane caller that
/// addresses an account by a path id instead pins ownership with
/// [`account_belongs_to_operator`] before acting.
pub async fn account_status(
    pool: &sqlx::PgPool,
    account_id: Uuid,
) -> Result<Option<AccountStatus>> {
    let status: Option<AccountStatus> =
        sqlx::query_scalar("SELECT status FROM cw_core.account_detail WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;
    Ok(status)
}

/// The operator an account belongs to, or `None` when the account has no satellite
/// row.
///
/// A data-plane caller is already pinned to its own account by its credential, so
/// this is not a tenant-boundary check; it is the lookup the storage-funding path
/// needs to name the account's owning operator when it asks which funding source a
/// charge may draw (the funding grant resolver matches an operator-scoped grant on
/// the account's operator). An account whose satellite is missing returns `None`.
pub async fn operator_for_account(pool: &sqlx::PgPool, account_id: Uuid) -> Result<Option<Uuid>> {
    let operator_id: Option<Uuid> =
        sqlx::query_scalar("SELECT operator_id FROM cw_core.account_detail WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;
    Ok(operator_id)
}

/// Whether an account exists under the given operator.
///
/// The control plane's ownership probe: a mutation or read that takes an
/// `account_id` from a path segment first confirms the operator owns it. An
/// account that is absent or owned by another operator returns `false`, which the
/// route renders as a 404 (no cross-tenant existence oracle).
pub async fn account_belongs_to_operator<'e, E>(
    executor: E,
    operator_id: Uuid,
    account_id: Uuid,
) -> Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM cw_core.account_detail \
             WHERE account_id = $1 AND operator_id = $2 \
         )",
    )
    .bind(account_id)
    .bind(operator_id)
    .fetch_one(executor)
    .await?;
    Ok(exists)
}

/// Soft-delete an account under `operator_id` by stamping `deleted_at` on its
/// anchor.
///
/// Pinned to the owning operator (the satellite's `operator_id`): an account that
/// is absent or owned by another operator reports [`ScopedChange::NotFound`] and
/// is never touched, so this administrative mutation cannot cross the tenant
/// boundary. Idempotent for an owned account already soft-deleted: it keeps its
/// original `deleted_at` and the call reports [`ScopedChange::Unchanged`]. A hard
/// delete is impossible by design (the RESTRICT foreign keys), so this is the
/// only removal path.
pub async fn soft_delete_account(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
) -> Result<ScopedChange> {
    // The CTE's existence arm pins ownership to the operator's satellite, so a
    // row outside the tenancy never matches and is reported absent. The
    // conditional UPDATE stamps `deleted_at` only on the operator's own,
    // not-yet-deleted anchor, leaving an already-deleted account's timestamp
    // intact (the idempotent no-op).
    let row: Option<(bool,)> = sqlx::query_as(
        "WITH owned AS ( \
             SELECT a.id, a.deleted_at FROM cw_api.account a \
             JOIN cw_core.account_detail d ON d.account_id = a.id \
             WHERE a.id = $1 AND d.operator_id = $2 \
         ), \
         updated AS ( \
             UPDATE cw_api.account a SET deleted_at = now() \
             FROM owned \
             WHERE a.id = owned.id AND owned.deleted_at IS NULL \
             RETURNING a.id \
         ) \
         SELECT EXISTS (SELECT 1 FROM updated) AS changed FROM owned",
    )
    .bind(account_id)
    .bind(operator_id)
    .fetch_optional(pool)
    .await?;

    Ok(match row {
        None => ScopedChange::NotFound,
        Some((true,)) => ScopedChange::Changed,
        Some((false,)) => ScopedChange::Unchanged,
    })
}
