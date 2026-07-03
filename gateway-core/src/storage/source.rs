//! The row side of a storage funding source: register, drain, and list.
//!
//! A funding source is an Arweave key plus the prepaid credit balance attached to
//! that key's address at a storage provider. This module owns the source's
//! lifecycle rows; who may DRAW charges against a source is a separate question
//! answered by [`super::funding`]'s grants, and the prepaid winc balance is the
//! [`super::credit`] module's.
//!
//! Registration mirrors [`crate::wallet::operator::register_wallet`]: a source is a
//! global identity keyed on `(backend, arweave_address)` (one credit pool per
//! address), so a fresh address inserts a source owned by the registering operator,
//! the same owner re-registering renames in place, and a different operator
//! re-registering an already-registered address is rejected
//! ([`RegisterSourceOutcome::AddressTaken`]) rather than aliasing the credit pool.
//! The lifecycle transition ([`begin_draining_source`]) and the operator-scoped
//! listing are the storage twins of the wallet `drain` and roster routes.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::ledger::account::ScopedTransition;
use crate::Result;

/// A funding source's lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum SourceStatus {
    /// Eligible to draw new charges and to be refreshed by the reconcile loop.
    Active,
    /// No new charges, but in-flight uploads settle by `funding_source_id`.
    Draining,
    /// Terminal: never selected and never refreshed.
    Retired,
}

impl SourceStatus {
    /// The stable wire token for this status (the same lowercase string the column
    /// stores), so a route reports the row's real state rather than a hardcoded
    /// literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SourceStatus::Active => "active",
            SourceStatus::Draining => "draining",
            SourceStatus::Retired => "retired",
        }
    }
}

/// A successful registration: the source's id and whether it is new.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredSource {
    /// The source's persistent id.
    pub source_id: Uuid,
    /// True when this register inserted a fresh row (vs renaming an existing one).
    pub inserted: bool,
}

/// The outcome of a [`register_source`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterSourceOutcome {
    /// The source was inserted or renamed under the calling operator.
    Registered(RegisteredSource),
    /// The `(backend, arweave_address)` is already a source owned by a DIFFERENT
    /// operator; nothing was written. The caller surfaces this as a conflict, never
    /// a silent overwrite: a second registrar cannot alias another operator's
    /// credit pool, and the right expression of a shared key is the owner issuing a
    /// grant.
    AddressTaken {
        /// The id of the existing source that holds the address on this backend.
        source_id: Uuid,
    },
}

/// Register a funding source under `owner_operator_id`, keyed on its global
/// `(backend, arweave_address)` identity.
///
/// A source is a global identity: there is one row per `(backend, arweave_address)`,
/// because a winc balance is the credit pool attached to one address at one
/// provider. A new address inserts a fresh `active` source owned by this operator.
/// The SAME operator re-registering its own address updates the label and `key_ref`
/// only (a rename) and never re-activates a source it has drained or retired. A
/// DIFFERENT operator registering an already-registered address is rejected
/// ([`RegisterSourceOutcome::AddressTaken`]): the address backs one credit pool, so
/// a second registrar cannot mint a parallel row that aliases it.
///
/// `key_ref` names the keyring entry whose Arweave key signs for this source; the
/// caller verifies the instance physically holds that key BEFORE calling, so a row
/// is never written for an address no signer backs.
pub async fn register_source(
    pool: &sqlx::PgPool,
    owner_operator_id: Uuid,
    label: &str,
    backend: &str,
    arweave_address: &str,
    key_ref: &str,
) -> Result<RegisterSourceOutcome> {
    // ON CONFLICT (backend, arweave_address) keys on the source's global identity.
    // The DO UPDATE fires only when the conflicting row's owner is THIS operator (the
    // `WHERE` on the conflict), so a same-operator re-register renames in place while
    // a different operator's collision updates nothing. The update touches only the
    // label and key_ref, never `status`, so re-running a register on a source the
    // operator has drained or retired leaves it drained/retired rather than silently
    // re-activating it.
    //
    // `xmax = 0` in the inserting transaction's snapshot distinguishes an insert (no
    // prior version) from a DO UPDATE (carries the updating txn's xmax) in a single
    // RETURNING. When the conflict's owner differs the `WHERE` makes the UPDATE a
    // no-op, so the statement RETURNs no row: that empty result is the "address
    // taken" signal, which a second query resolves into the source that holds it.
    let candidate_id = Uuid::now_v7();
    let row: Option<RegisteredRow> = sqlx::query_as(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (backend, arweave_address) \
             DO UPDATE SET label = EXCLUDED.label, key_ref = EXCLUDED.key_ref \
             WHERE cw_core.storage_funding_source.owner_operator_id \
                 = EXCLUDED.owner_operator_id \
         RETURNING id, (xmax = 0) AS inserted",
    )
    .bind(candidate_id)
    .bind(owner_operator_id)
    .bind(label)
    .bind(backend)
    .bind(arweave_address)
    .bind(key_ref)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(row) => Ok(RegisterSourceOutcome::Registered(RegisteredSource {
            source_id: row.id,
            inserted: row.inserted,
        })),
        // No row returned: the address is already a source owned by a DIFFERENT
        // operator (the conflict's WHERE excluded the update). Read back which source
        // holds it so the caller can report it without a second guess.
        None => {
            let existing: Uuid = sqlx::query_scalar(
                "SELECT id FROM cw_core.storage_funding_source \
                 WHERE backend = $1 AND arweave_address = $2",
            )
            .bind(backend)
            .bind(arweave_address)
            .fetch_one(pool)
            .await?;
            Ok(RegisterSourceOutcome::AddressTaken {
                source_id: existing,
            })
        }
    }
}

/// Begin draining a source owned by `operator_id`: it takes no new charges, but its
/// in-flight uploads settle by `funding_source_id`.
///
/// Only an `active` source transitions to `draining`; the call is idempotent for a
/// source already draining or retired ([`ScopedTransition::Unchanged`], reporting
/// the source's real status). The UPDATE is pinned to the owner, so a source another
/// operator owns reports [`ScopedTransition::NotFound`] and is never touched. The
/// lifecycle is the owner's prerogative, so it keys on `owner_operator_id`, not on
/// any draw grant.
///
/// The executor is generic so the transition can ride the route's transaction
/// (committing atomically with its audit row) or run standalone against a pool.
pub async fn begin_draining_source<'a, A>(
    executor: A,
    operator_id: Uuid,
    source_id: Uuid,
) -> Result<ScopedTransition<SourceStatus>>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    // A single round trip: the CTE locates the operator's own source (the existence
    // arm, reading back its current status) and a conditional UPDATE flips it only
    // when it is `active`. A source another operator owns never matches the existence
    // arm, so it is reported absent rather than acted on across the boundary. Setting
    // `retired_at` is left for a future retire transition; draining is reversible in
    // the model, so it stamps no terminal timestamp.
    let row: Option<(bool, SourceStatus)> = sqlx::query_as(
        "WITH owned AS ( \
             SELECT id, status FROM cw_core.storage_funding_source \
             WHERE id = $1 AND owner_operator_id = $2 \
         ), \
         updated AS ( \
             UPDATE cw_core.storage_funding_source s SET status = 'draining' \
             FROM owned \
             WHERE s.id = owned.id AND s.status = 'active' \
             RETURNING s.id \
         ) \
         SELECT EXISTS (SELECT 1 FROM updated) AS changed, owned.status FROM owned",
    )
    .bind(source_id)
    .bind(operator_id)
    .fetch_optional(executor)
    .await?;

    Ok(match row {
        None => ScopedTransition::NotFound,
        // The UPDATE fired, so the source really was `active` and now `draining`.
        Some((true, _)) => ScopedTransition::Changed {
            from: SourceStatus::Active,
            to: SourceStatus::Draining,
        },
        // No update: report the source's actual current status, not the target.
        Some((false, status)) => ScopedTransition::Unchanged { status },
    })
}

/// One source row in the operator's funding roster, with its cached credit
/// diagnostics.
#[derive(Debug, Clone)]
pub struct SourceSummary {
    /// The source id.
    pub source_id: Uuid,
    /// The operator that owns (administers) the source.
    pub owner_operator_id: Uuid,
    /// The operator label.
    pub label: String,
    /// The backend the source draws from.
    pub backend: String,
    /// The verified Arweave address (the provider balance key).
    pub arweave_address: String,
    /// The source's lifecycle status.
    pub status: SourceStatus,
    /// The cached believed winc balance, when a reconcile has stamped one.
    pub winc_balance: Option<Decimal>,
    /// The provider-reported fundable bytes, when the last reconcile carried one.
    pub fundable_bytes: Option<i64>,
    /// When the last reconcile stamped the cached balance.
    pub last_reconciled_at: Option<DateTime<Utc>>,
    /// A stale-visibility marker set when the last refresh attempt failed.
    pub last_error: Option<String>,
    /// When the source was registered.
    pub created_at: DateTime<Utc>,
}

/// List the funding sources an operator owns, with their cached credit
/// diagnostics, newest-first up to `limit`.
///
/// Scoped to the sources this operator owns (its `owner_operator_id`), so the roster
/// is the operator's own sources, not every source a grant may let it draw. The
/// cached winc balance and its diagnostics come from a LEFT JOIN on the materialized
/// `storage_credit` row: a source with no reconcile yet reports `NULL` for the
/// balance (the operator sees "unknown/unfunded" until the first reconcile stamps
/// it). The read never calls the provider; it projects the cached row only.
pub async fn list_sources(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    limit: i64,
) -> Result<Vec<SourceSummary>> {
    let rows: Vec<SourceRow> = sqlx::query_as(
        "SELECT s.id, s.owner_operator_id, s.label, s.backend, s.arweave_address, \
                s.status, s.created_at, \
                c.winc_balance, c.fundable_bytes, c.last_reconciled_at, c.last_error \
         FROM cw_core.storage_funding_source s \
         LEFT JOIN cw_core.storage_credit c ON c.funding_source_id = s.id \
         WHERE s.owner_operator_id = $1 \
         ORDER BY s.id DESC \
         LIMIT $2",
    )
    .bind(operator_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| SourceSummary {
            source_id: r.id,
            owner_operator_id: r.owner_operator_id,
            label: r.label,
            backend: r.backend,
            arweave_address: r.arweave_address,
            status: r.status,
            winc_balance: r.winc_balance,
            fundable_bytes: r.fundable_bytes,
            last_reconciled_at: r.last_reconciled_at,
            last_error: r.last_error,
            created_at: r.created_at,
        })
        .collect())
}

/// The row [`register_source`]'s `RETURNING` reads back: the persistent source id
/// and whether the register inserted (rather than renamed) the row.
#[derive(sqlx::FromRow)]
struct RegisteredRow {
    id: Uuid,
    inserted: bool,
}

/// The columns the source-roster query reads back. The credit diagnostics are all
/// `NULL`able because a source may have no materialized credit row yet (a LEFT
/// JOIN), which is the "unknown/unfunded" state.
#[derive(sqlx::FromRow)]
struct SourceRow {
    id: Uuid,
    owner_operator_id: Uuid,
    label: String,
    backend: String,
    arweave_address: String,
    status: SourceStatus,
    created_at: DateTime<Utc>,
    winc_balance: Option<Decimal>,
    fundable_bytes: Option<i64>,
    last_reconciled_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}
