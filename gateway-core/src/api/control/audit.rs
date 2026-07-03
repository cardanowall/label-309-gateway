//! The append-only administrative audit journal.
//!
//! Every control-plane mutation appends exactly one row to `cw_core.admin_audit`
//! through [`record`]. The row records who acted (an operator, an account acting
//! on itself, or the system), the action verb, the target it touched, the
//! before/after state as opaque JSON, and the request id that originated it. The
//! table refuses UPDATE / DELETE / TRUNCATE by trigger, so the journal can only
//! grow: an administrative record cannot be edited after the fact.

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::Result;

/// The actor classes an audit row can record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    /// An operator acting through the control plane.
    Operator,
    /// An account acting on its own resources (self-service).
    Account,
    /// An automated, principal-less transition the engine performed.
    System,
}

impl ActorKind {
    /// The stable lowercase token stored in the `actor_kind` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ActorKind::Operator => "operator",
            ActorKind::Account => "account",
            ActorKind::System => "system",
        }
    }
}

/// One administrative mutation to record.
///
/// `prev_state` / `new_state` are opaque snapshots of the mutated state (a create
/// has a `None` prev; a transition carries both). The engine never interprets
/// them; they exist so an operator can read exactly what a mutation changed.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// The class of actor that performed the mutation.
    pub actor_kind: ActorKind,
    /// The acting principal's id, when there is one (NULL for a system action).
    pub actor_id: Option<Uuid>,
    /// The action verb (e.g. `account.create`, `wallet.drain`, `ledger.adjust`).
    pub action: String,
    /// The kind of thing acted on (`account`, `api_key`, `operator_wallet`, ...).
    pub target_type: String,
    /// The acted-on thing's id, as text so any id shape fits.
    pub target_id: String,
    /// The state before the mutation, or `None` for a create.
    pub prev_state: Option<Value>,
    /// The state after the mutation, or `None` for a removal.
    pub new_state: Option<Value>,
    /// The request id that originated the mutation, for correlation.
    pub request_id: Option<Uuid>,
}

/// Append one audit row, returning its id.
///
/// The id is a UUIDv7 minted here, so a B-tree index on it tracks insertion
/// order. The executor is generic so the insert can ride the caller's transaction
/// (recording the audit row in the SAME transaction as the mutation it describes,
/// so the two commit or roll back together) or run standalone against a pool.
pub async fn record<'a, A>(executor: A, entry: &AuditEntry) -> Result<Uuid>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.admin_audit \
           (id, actor_kind, actor_id, action, target_type, target_id, prev_state, new_state, request_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(entry.actor_kind.as_str())
    .bind(entry.actor_id)
    .bind(&entry.action)
    .bind(&entry.target_type)
    .bind(&entry.target_id)
    .bind(&entry.prev_state)
    .bind(&entry.new_state)
    .bind(entry.request_id)
    .execute(executor)
    .await?;
    Ok(id)
}

/// A recorded audit row, as the audit read surface returns it.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// The row id.
    pub id: Uuid,
    /// The actor class.
    pub actor_kind: String,
    /// The acting principal's id, when there was one.
    pub actor_id: Option<Uuid>,
    /// The action verb.
    pub action: String,
    /// The acted-on thing's kind.
    pub target_type: String,
    /// The acted-on thing's id.
    pub target_id: String,
    /// The before state, when recorded.
    pub prev_state: Option<Value>,
    /// The after state, when recorded.
    pub new_state: Option<Value>,
    /// The originating request id.
    pub request_id: Option<Uuid>,
    /// When the mutation occurred.
    pub occurred_at: DateTime<Utc>,
}

/// A filter over the audit read surface. Every optional field narrows the query;
/// an unset field does not constrain it. `operator_id` is NOT optional: the read
/// is always tenancy-scoped to one operator (see [`list`]).
#[derive(Debug, Clone)]
pub struct AuditQuery {
    /// The operator whose audit rows the read returns. The read returns ONLY rows
    /// that this operator produced or that concern one of its resources; rows of
    /// another tenant are never visible.
    pub operator_id: Uuid,
    /// Constrain to one actor class.
    pub actor_kind: Option<ActorKind>,
    /// Constrain to one action verb.
    pub action: Option<String>,
    /// Constrain to one target kind.
    pub target_type: Option<String>,
    /// Constrain to one target id.
    pub target_id: Option<String>,
    /// The maximum number of rows to return (the page size).
    pub limit: i64,
}

/// List audit rows newest-first for one operator, applying the optional filters.
///
/// # Tenancy
///
/// The audit journal carries no `operator_id` column (its rows reference accounts,
/// keys, and wallets by id), so the read derives ownership from the rows it
/// touches: a row belongs to the queried operator when EITHER the actor is the
/// operator (or one of its accounts acting on itself), OR the target is one of the
/// operator's accounts, that account's api keys, an access token of the operator,
/// or one of the operator's wallets. Any row outside that union is invisible, so
/// one operator can never read another's administrative history.
///
/// The optional `actor_kind` / `action` / `target_type` / `target_id` filters then
/// narrow within the operator's own rows; an unset filter matches all of them.
/// Rows come back newest-first up to `limit`.
pub async fn list(pool: &sqlx::PgPool, query: &AuditQuery) -> Result<Vec<AuditRecord>> {
    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT a.id, a.actor_kind, a.actor_id, a.action, a.target_type, a.target_id, \
                a.prev_state, a.new_state, a.request_id, a.occurred_at \
         FROM cw_core.admin_audit a \
         WHERE ( \
                 -- The operator acting directly (actor_id IS the operator id).
                 (a.actor_kind = 'operator' AND a.actor_id = $1) \
                 -- One of the operator's accounts acting on itself (self-service).
              OR (a.actor_kind = 'account' AND a.actor_id IN ( \
                     SELECT account_id FROM cw_core.account_detail WHERE operator_id = $1)) \
                 -- A row targeting one of the operator's accounts.
              OR (a.target_type = 'account' AND a.target_id IN ( \
                     SELECT account_id::text FROM cw_core.account_detail WHERE operator_id = $1)) \
                 -- A row targeting an api key on one of the operator's accounts.
              OR (a.target_type = 'api_key' AND a.target_id IN ( \
                     SELECT k.id::text FROM cw_core.api_key k \
                     JOIN cw_core.account_detail d ON d.account_id = k.account_id \
                     WHERE d.operator_id = $1)) \
                 -- A ledger row targets the account it adjusted.
              OR (a.target_type = 'ledger' AND a.target_id IN ( \
                     SELECT account_id::text FROM cw_core.account_detail WHERE operator_id = $1)) \
                 -- An access token minted under the operator.
              OR (a.target_type = 'access_token' AND a.target_id IN ( \
                     SELECT id::text FROM cw_core.access_token WHERE operator_id = $1)) \
                 -- A wallet the operator registered (administers).
              OR (a.target_type = 'operator_wallet' AND a.target_id IN ( \
                     SELECT id::text FROM cw_core.operator_wallet \
                     WHERE registrar_operator_id = $1)) \
                 -- A grant on a wallet the operator registered.
              OR (a.target_type = 'wallet_grant' AND a.target_id IN ( \
                     SELECT g.id::text FROM cw_core.wallet_grant g \
                     JOIN cw_core.operator_wallet w ON w.id = g.wallet_id \
                     WHERE w.registrar_operator_id = $1)) \
           ) \
           AND ($2::text IS NULL OR a.actor_kind = $2) \
           AND ($3::text IS NULL OR a.action = $3) \
           AND ($4::text IS NULL OR a.target_type = $4) \
           AND ($5::text IS NULL OR a.target_id = $5) \
         ORDER BY a.occurred_at DESC, a.id DESC \
         LIMIT $6",
    )
    .bind(query.operator_id)
    .bind(query.actor_kind.map(ActorKind::as_str))
    .bind(query.action.as_deref())
    .bind(query.target_type.as_deref())
    .bind(query.target_id.as_deref())
    .bind(query.limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(AuditRecord::from).collect())
}

/// The columns the audit list query reads back.
#[derive(sqlx::FromRow)]
struct AuditRow {
    id: Uuid,
    actor_kind: String,
    actor_id: Option<Uuid>,
    action: String,
    target_type: String,
    target_id: String,
    prev_state: Option<Value>,
    new_state: Option<Value>,
    request_id: Option<Uuid>,
    occurred_at: DateTime<Utc>,
}

impl From<AuditRow> for AuditRecord {
    fn from(r: AuditRow) -> Self {
        Self {
            id: r.id,
            actor_kind: r.actor_kind,
            actor_id: r.actor_id,
            action: r.action,
            target_type: r.target_type,
            target_id: r.target_id,
            prev_state: r.prev_state,
            new_state: r.new_state,
            request_id: r.request_id,
            occurred_at: r.occurred_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_kind_tokens_are_stable() {
        assert_eq!(ActorKind::Operator.as_str(), "operator");
        assert_eq!(ActorKind::Account.as_str(), "account");
        assert_eq!(ActorKind::System.as_str(), "system");
    }
}
