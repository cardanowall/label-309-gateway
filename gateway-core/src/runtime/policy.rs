//! The queue-policy registry and startup reconciliation.
//!
//! Policies are declared in code and persisted to `cw_core.queue_policy`. The
//! row is the live source of truth that the claim, retry, and sweep paths read.
//! At startup the runtime compares each code-declared policy against its row and
//! reconciles drift by UPDATE-ing the row to match the code and logging a
//! warning, so a deploy that changes a policy takes effect without a manual
//! migration while leaving an auditable trace of the change.

use super::Backoff;
use crate::{Error, Result};

/// How a queue's jobs are scheduled relative to each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum QueuePolicyKind {
    /// Ordinary worker-pool concurrency.
    Standard,
    /// At most one in-flight job; handlers typically take a session advisory
    /// lock to serialize across replicas.
    SingletonLoop,
}

impl QueuePolicyKind {
    /// The on-disk discriminator stored in `queue_policy.policy`.
    fn as_db(self) -> &'static str {
        match self {
            QueuePolicyKind::Standard => "standard",
            QueuePolicyKind::SingletonLoop => "singleton_loop",
        }
    }

    /// Parse the on-disk discriminator.
    fn from_db(value: &str) -> Result<Self> {
        match value {
            "standard" => Ok(QueuePolicyKind::Standard),
            "singleton_loop" => Ok(QueuePolicyKind::SingletonLoop),
            other => Err(Error::Config(format!("unknown queue policy kind: {other}"))),
        }
    }
}

/// A queue's runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuePolicy {
    /// Queue name (primary key).
    pub queue: String,
    /// Scheduling discipline.
    pub policy: QueuePolicyKind,
    /// Attempt budget for jobs that do not override it.
    pub max_attempts: i32,
    /// Default backoff for jobs that do not override it.
    pub backoff: Backoff,
    /// Reclaim lease: a running job idle past this is swept back to available.
    pub lease_secs: i32,
    /// Advisory worker-pool fan-out for the queue.
    pub concurrency: i32,
}

impl QueuePolicy {
    /// Construct a standard-discipline policy.
    pub fn standard(
        queue: impl Into<String>,
        max_attempts: i32,
        backoff: Backoff,
        lease_secs: i32,
        concurrency: i32,
    ) -> Self {
        Self {
            queue: queue.into(),
            policy: QueuePolicyKind::Standard,
            max_attempts,
            backoff,
            lease_secs,
            concurrency,
        }
    }

    /// Construct a singleton-loop policy (at most one in-flight job).
    pub fn singleton_loop(
        queue: impl Into<String>,
        max_attempts: i32,
        backoff: Backoff,
        lease_secs: i32,
    ) -> Self {
        Self {
            queue: queue.into(),
            policy: QueuePolicyKind::SingletonLoop,
            max_attempts,
            backoff,
            lease_secs,
            // A singleton loop runs one job at a time by definition; the
            // claim loop never fans out beyond a single row for it.
            concurrency: 1,
        }
    }
}

/// The outcome of reconciling one declared policy against its stored row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciliation {
    /// No row existed; the declared policy was inserted.
    Inserted,
    /// The stored row already matched the declared policy.
    Unchanged,
    /// The stored row differed and was updated to match the declared policy.
    Updated,
}

/// Reconcile a single declared policy against `cw_core.queue_policy`.
///
/// Inserts the row if absent, updates it (and reports [`Reconciliation::Updated`])
/// if it drifted from the declared config, and reports
/// [`Reconciliation::Unchanged`] otherwise. Drift is logged at warn level here:
/// the code config is the source of truth, so a divergent row is corrected and
/// the change is left as an auditable trace.
pub async fn reconcile(pool: &sqlx::PgPool, declared: &QueuePolicy) -> Result<Reconciliation> {
    let backoff_json = serde_json::to_value(declared.backoff)?;

    // Read first so we can decide insert / unchanged / update and emit a
    // warning that names exactly what drifted. A single upsert with
    // `xmax = 0` insert-detection would tell us inserted-vs-not but not what
    // changed, and the warning's value is in naming the drift.
    match load(pool, &declared.queue).await? {
        None => {
            sqlx::query(
                "INSERT INTO cw_core.queue_policy \
                   (queue, policy, max_attempts, backoff, lease_secs, concurrency) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&declared.queue)
            .bind(declared.policy.as_db())
            .bind(declared.max_attempts)
            .bind(&backoff_json)
            .bind(declared.lease_secs)
            .bind(declared.concurrency)
            .execute(pool)
            .await?;
            Ok(Reconciliation::Inserted)
        }
        Some(stored) if stored == *declared => Ok(Reconciliation::Unchanged),
        Some(stored) => {
            tracing::warn!(
                queue = %declared.queue,
                stored.policy = ?stored.policy,
                stored.max_attempts = stored.max_attempts,
                stored.lease_secs = stored.lease_secs,
                stored.concurrency = stored.concurrency,
                declared.policy = ?declared.policy,
                declared.max_attempts = declared.max_attempts,
                declared.lease_secs = declared.lease_secs,
                declared.concurrency = declared.concurrency,
                "queue policy drifted from code; reconciling row to declared config"
            );
            sqlx::query(
                "UPDATE cw_core.queue_policy \
                 SET policy = $2, max_attempts = $3, backoff = $4, \
                     lease_secs = $5, concurrency = $6, updated_at = now() \
                 WHERE queue = $1",
            )
            .bind(&declared.queue)
            .bind(declared.policy.as_db())
            .bind(declared.max_attempts)
            .bind(&backoff_json)
            .bind(declared.lease_secs)
            .bind(declared.concurrency)
            .execute(pool)
            .await?;
            Ok(Reconciliation::Updated)
        }
    }
}

/// Load the stored policy for a queue, if any.
pub async fn load(pool: &sqlx::PgPool, queue: &str) -> Result<Option<QueuePolicy>> {
    let row = sqlx::query_as::<_, PolicyRow>(
        "SELECT queue, policy, max_attempts, backoff, lease_secs, concurrency \
         FROM cw_core.queue_policy WHERE queue = $1",
    )
    .bind(queue)
    .fetch_optional(pool)
    .await?;

    row.map(QueuePolicy::try_from).transpose()
}

/// Raw `queue_policy` row as read from Postgres before validation.
#[derive(sqlx::FromRow)]
struct PolicyRow {
    queue: String,
    policy: String,
    max_attempts: i32,
    backoff: serde_json::Value,
    lease_secs: i32,
    concurrency: i32,
}

impl TryFrom<PolicyRow> for QueuePolicy {
    type Error = Error;

    fn try_from(row: PolicyRow) -> Result<Self> {
        Ok(QueuePolicy {
            queue: row.queue,
            policy: QueuePolicyKind::from_db(&row.policy)?,
            max_attempts: row.max_attempts,
            backoff: serde_json::from_value(row.backoff)?,
            lease_secs: row.lease_secs,
            concurrency: row.concurrency,
        })
    }
}
