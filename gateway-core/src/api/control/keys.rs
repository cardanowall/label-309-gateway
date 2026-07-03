//! Api-key lifecycle: create (scope-validated, secret shown once), revoke, relabel.
//!
//! These port the data-plane api-key lifecycle onto the control surface. A key is
//! created for an account with an operator-chosen secret prefix and a scope set
//! validated against the registry (`cw_core.api_scope`); the plaintext secret is
//! returned exactly once and never stored (only its SHA-256 hash is). Revoke and
//! relabel are timestamp / column edits that preserve the key's history. Each
//! mutation's audit row is written by the calling route, which holds the principal
//! that performed it.
//!
//! # Tenancy
//!
//! `cw_core.api_key` carries only an `account_id`, so every helper here pins the
//! key to the owning operator by joining through `cw_core.account_detail`
//! (`account_id -> operator_id`). A key whose account belongs to another operator
//! never matches the predicate: create rejects with [`KeyError::AccountNotFound`],
//! and revoke / relabel report [`ScopedChange::NotFound`]. The operator binding is
//! part of the signature, so a route cannot mutate a key it does not own.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::api::control::credential::{generate_secret, validate_rate_limit};
use crate::api::middleware::auth::hash_secret;
use crate::api::middleware::scope;
use crate::ledger::account::ScopedChange;
use crate::{Error, Result};

/// The ways creating an api key can fail before any row is written.
#[derive(Debug)]
pub enum KeyError {
    /// The target account is absent or owned by another operator. The route
    /// renders this as a 404 (no cross-tenant existence oracle).
    AccountNotFound,
    /// A validation or storage fault (empty scopes, an unknown scope, a database
    /// error). Carries the underlying engine error for the route to map.
    Engine(Error),
}

impl From<Error> for KeyError {
    fn from(e: Error) -> Self {
        KeyError::Engine(e)
    }
}

/// A newly created api key: its id, the operator prefix, the granted scopes, and
/// the plaintext secret shown exactly once.
#[derive(Clone)]
pub struct CreatedKey {
    /// The key row id.
    pub key_id: Uuid,
    /// The operator-chosen secret prefix the key was issued under.
    pub prefix: String,
    /// The scopes the key carries.
    pub scopes: Vec<String>,
    /// The key's custom per-minute request budget, or `None` when it meters
    /// against the data-plane default budget.
    pub rate_limit_per_min: Option<i32>,
    /// The plaintext secret, shown exactly once. Never logged.
    pub secret: String,
    /// When the key was created.
    pub created_at: DateTime<Utc>,
}

/// Redact the plaintext on `{:?}` so a stray debug-format cannot leak the
/// shown-once key secret; every non-secret field stays visible.
impl std::fmt::Debug for CreatedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedKey")
            .field("key_id", &self.key_id)
            .field("prefix", &self.prefix)
            .field("scopes", &self.scopes)
            .field("rate_limit_per_min", &self.rate_limit_per_min)
            .field("secret", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Create an api key for an account under `operator_id`.
///
/// Confirms the operator owns the target account before writing anything (a key
/// for an account of another operator fails with [`KeyError::AccountNotFound`]),
/// validates every requested scope is registered in `cw_core.api_scope` (an
/// unknown scope is a caller error, never silently dropped), generates a secret
/// with the operator prefix, stores its hash, and returns the plaintext exactly
/// once. The scope set must be non-empty. `rate_limit_per_min` is an OPTIONAL
/// per-minute request budget: `None` stores NULL and the data plane meters the
/// key against its fixed default budget, exactly as an account token minted
/// without one; a custom budget is bounded by the shared mint validation. The
/// ownership check and the insert ride one transaction, so a concurrently
/// soft-deleted or reassigned account cannot slip a key in.
///
/// The executor is generic over [`sqlx::Acquire`] so the create can ride the
/// route's transaction (committing atomically with its audit row — the internal
/// begin becomes a savepoint there) or run standalone against a pool.
pub async fn create_key<'a, A>(
    executor: A,
    operator_id: Uuid,
    account_id: Uuid,
    prefix: &str,
    scopes: &[String],
    rate_limit_per_min: Option<i32>,
    label: Option<&str>,
) -> std::result::Result<CreatedKey, KeyError>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    if scopes.is_empty() {
        return Err(Error::Config("an api key must carry at least one scope".into()).into());
    }
    validate_rate_limit(rate_limit_per_min)?;

    let secret = generate_secret(prefix);
    let (lookup, full_hash) = hash_secret(&secret);
    let key_id = Uuid::now_v7();

    let mut txn = executor.begin().await.map_err(Error::from)?;
    scope::validate_registered(&mut *txn, scopes).await?;

    // Pin the account to the operator inside the transaction. A row that does not
    // belong to the operator yields no match, and the key is never inserted.
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM cw_core.account_detail \
             WHERE account_id = $1 AND operator_id = $2 \
         )",
    )
    .bind(account_id)
    .bind(operator_id)
    .fetch_one(&mut *txn)
    .await
    .map_err(Error::from)?;
    if !owned {
        return Err(KeyError::AccountNotFound);
    }

    let created_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO cw_core.api_key \
           (id, account_id, prefix, key_lookup, key_hash_sha256, scopes, rate_limit_per_min, label) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         RETURNING created_at",
    )
    .bind(key_id)
    .bind(account_id)
    .bind(prefix)
    .bind(&lookup)
    .bind(&full_hash)
    .bind(scopes)
    .bind(rate_limit_per_min)
    .bind(label)
    .fetch_one(&mut *txn)
    .await
    .map_err(Error::from)?;

    txn.commit().await.map_err(Error::from)?;

    Ok(CreatedKey {
        key_id,
        prefix: prefix.to_string(),
        scopes: scopes.to_vec(),
        rate_limit_per_min,
        secret,
        created_at,
    })
}

/// Revoke an api key belonging to `account_id` under `operator_id` by stamping
/// `revoked_at`.
///
/// Pinned to both the account AND its owning operator (joined through
/// `cw_core.account_detail`), so an operator can only revoke keys on accounts it
/// owns. A key on an account of another operator, or a key id that does not
/// belong to the account, reports [`ScopedChange::NotFound`]. An owned key already
/// revoked reports [`ScopedChange::Unchanged`].
///
/// The executor is generic so the revocation can ride the route's transaction
/// (committing atomically with its audit row) or run standalone against a pool.
pub async fn revoke_key<'a, A>(
    executor: A,
    operator_id: Uuid,
    account_id: Uuid,
    key_id: Uuid,
) -> Result<ScopedChange>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let row: Option<(bool,)> = sqlx::query_as(
        "WITH owned AS ( \
             SELECT k.id, k.revoked_at FROM cw_core.api_key k \
             JOIN cw_core.account_detail d ON d.account_id = k.account_id \
             WHERE k.id = $1 AND k.account_id = $2 AND d.operator_id = $3 \
         ), \
         updated AS ( \
             UPDATE cw_core.api_key k SET revoked_at = now() \
             FROM owned \
             WHERE k.id = owned.id AND owned.revoked_at IS NULL \
             RETURNING k.id \
         ) \
         SELECT EXISTS (SELECT 1 FROM updated) AS changed FROM owned",
    )
    .bind(key_id)
    .bind(account_id)
    .bind(operator_id)
    .fetch_optional(executor)
    .await?;

    Ok(match row {
        None => ScopedChange::NotFound,
        Some((true,)) => ScopedChange::Changed,
        Some((false,)) => ScopedChange::Unchanged,
    })
}

/// Relabel an api key belonging to `account_id` under `operator_id`.
///
/// Pinned to both the account AND its owning operator. A `None` label clears the
/// label. A key on an account of another operator (or a key id not on the
/// account) reports [`ScopedChange::NotFound`]; an owned key is reported
/// [`ScopedChange::Changed`] (the label is set regardless of its prior value).
///
/// The executor is generic so the relabel can ride the route's transaction
/// (committing atomically with its audit row) or run standalone against a pool.
pub async fn relabel_key<'a, A>(
    executor: A,
    operator_id: Uuid,
    account_id: Uuid,
    key_id: Uuid,
    label: Option<&str>,
) -> Result<ScopedChange>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let affected = sqlx::query(
        "UPDATE cw_core.api_key k SET label = $4 \
         FROM cw_core.account_detail d \
         WHERE k.id = $1 AND k.account_id = $2 \
           AND d.account_id = k.account_id AND d.operator_id = $3",
    )
    .bind(key_id)
    .bind(account_id)
    .bind(operator_id)
    .bind(label)
    .execute(executor)
    .await?
    .rows_affected();

    Ok(if affected == 1 {
        ScopedChange::Changed
    } else {
        ScopedChange::NotFound
    })
}
