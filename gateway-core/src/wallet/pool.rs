//! The wallet pool and least-loaded scheduler.
//!
//! [`pick_wallet`] chooses the wallet a new submit should use within an operator
//! and network. Eligible wallets are `active`, with at least one canonical
//! available UTxO, AND the operator is entitled to spend them: the wallet's
//! registrar (always entitled to its own wallet) or any wallet a live grant
//! entitles the operator to (a `service` grant entitling everyone, or an
//! `operator` grant naming this operator). Under the single-tenant `service`
//! default that entitlement set is "every wallet on the instance", so the
//! selection set is identical to a flat operator-scoped pool. Among the eligible
//! wallets it prefers the least in-flight, then the most canonical-ready, then
//! the least-used in the trailing day, then the oldest-used. The row is claimed
//! with `FOR UPDATE SKIP LOCKED` so concurrent schedulers never hand the same
//! wallet to two submits, and the caller then takes a per-wallet session advisory
//! lock (a dedicated detached connection, reusing [`crate::runtime::locks`]) held
//! across build -> sign -> submit so two in-flight transactions on one wallet can
//! never select the same UTxO.
//!
//! Selection is necessary but not sufficient: [`crate::wallet::grant::authorize_spend`]
//! is re-run on the chosen row inside the locked window (and on a pinned wallet)
//! before signing, so a grant revoked between selection and signing cannot leak a
//! signature.

use uuid::Uuid;

use super::config::Network;
use crate::runtime::locks::AdvisoryLock;
use crate::Result;

/// A wallet the scheduler may pick, with the live counters it ranks on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCandidate {
    /// The wallet's id.
    pub wallet_id: Uuid,
    /// The operator that registered (administers) it. Not necessarily the
    /// spending operator: a `service` or `operator` grant lets a different
    /// operator be handed this wallet.
    pub registrar_operator_id: Uuid,
    /// Operator-facing label.
    pub label: String,
    /// Stable payment address.
    pub address: String,
    /// Number of UTxOs currently `in_flight` for this wallet (lower is better).
    pub in_flight_count: i64,
    /// Number of canonical available UTxOs (higher is better).
    pub canonical_ready_count: i64,
    /// Submits in the trailing 24h (lower is better).
    pub submission_count_24h: i64,
    /// Last time the wallet was picked; `None` sorts first (never used).
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Pick the least-loaded wallet `operator_id` is entitled to spend on a network.
///
/// Eligibility: `status = 'active'`, `canonical_ready_count > 0`, the registrar
/// is an active operator, AND `operator_id` is entitled to spend the wallet (its
/// registrar, or a live `service`/`operator` grant). Ordering: `in_flight_count
/// ASC, canonical_ready_count DESC, submission_count_24h ASC, last_used_at ASC
/// NULLS FIRST`. The chosen row is locked with `FOR UPDATE SKIP LOCKED` so a
/// concurrent scheduler skips it and picks the next best wallet. Returns
/// `Ok(None)` when no entitled wallet is eligible (none ready, or none granted),
/// which the caller resolves by triggering a replenish or shedding load.
///
/// # Account-scoped selection is intentionally deferred
///
/// The grant model carries an `account` scope (and [`super::grant::authorize_spend`]
/// matches it), but selection here joins only the `service` and `operator` grant
/// arms by design. An account grant can be issued today only for an account the
/// wallet's registrar owns, and every account belongs to exactly one operator, so
/// such a grant is selection-redundant: the record's principal carries that same
/// operator, which is already covered by the registrar match (and any
/// `service`/`operator` grant). Turning on per-account selection means: (1) add an
/// `account` arm here keyed on the submitting account, (2) thread the submitting
/// account into this function (it currently takes only the operator), and
/// (3) tighten `poe_record.account_id` to a real account reference. Until
/// per-account wallets ship, those changes would add no reachable behaviour, so
/// the arm is deliberately omitted rather than dead.
pub async fn pick_wallet(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    network: Network,
) -> Result<Option<WalletCandidate>> {
    // The candidate's counters are computed from `wallet_utxo` (canonical-ready
    // and in-flight counts) joined onto `operator_wallet` (the load hints). The
    // row is locked with FOR UPDATE SKIP LOCKED so a concurrent picker skips it
    // and lands on the next-best wallet; only the `operator_wallet` row is
    // locked (FOR UPDATE OF), never the per-UTxO aggregates, so the lock is on
    // the wallet identity the caller then takes a session advisory lock against.
    //
    // Eligibility requires an active wallet whose registrar is an active operator
    // (a disabled registrar's wallets are off the books) with at least one
    // canonical available UTxO, AND that the picking operator is entitled to
    // spend it. Entitlement is the registrar match OR a live grant (service, or
    // operator naming this operator) tested via EXISTS, so a wallet carrying two
    // matching grants is still selected exactly once (no row fan-out). Ordering
    // spreads load: fewest in-flight first, then most ready, then least-used in
    // the trailing day, then oldest-used.
    let row = sqlx::query_as::<_, CandidateRow>(
        "SELECT \
             w.id                    AS wallet_id, \
             w.registrar_operator_id AS registrar_operator_id, \
             w.label                 AS label, \
             w.address               AS address, \
             coalesce(c.in_flight_count, 0)        AS in_flight_count, \
             coalesce(c.canonical_ready_count, 0)  AS canonical_ready_count, \
             w.submission_count_24h               AS submission_count_24h, \
             w.last_used_at                        AS last_used_at \
         FROM cw_core.operator_wallet w \
         JOIN cw_core.operator o ON o.id = w.registrar_operator_id \
         LEFT JOIN LATERAL ( \
             SELECT \
                 count(*) FILTER (WHERE u.state = 'in_flight')                       AS in_flight_count, \
                 count(*) FILTER (WHERE u.state = 'available' AND u.canonical)        AS canonical_ready_count \
             FROM cw_core.wallet_utxo u \
             WHERE u.wallet_id = w.id \
         ) c ON true \
         WHERE w.network = $2 \
           AND w.status = 'active' \
           AND o.status = 'active' \
           AND coalesce(c.canonical_ready_count, 0) > 0 \
           AND ( \
               w.registrar_operator_id = $1 \
               OR EXISTS ( \
                   SELECT 1 FROM cw_core.wallet_grant g \
                   WHERE g.wallet_id = w.id AND g.revoked_at IS NULL AND ( \
                       g.scope_kind = 'service' \
                       OR (g.scope_kind = 'operator' AND g.operator_id = $1) \
                   ) \
               ) \
           ) \
         ORDER BY \
             coalesce(c.in_flight_count, 0) ASC, \
             coalesce(c.canonical_ready_count, 0) DESC, \
             w.submission_count_24h ASC, \
             w.last_used_at ASC NULLS FIRST \
         FOR UPDATE OF w SKIP LOCKED \
         LIMIT 1",
    )
    .bind(operator_id)
    .bind(network.as_str())
    .fetch_optional(pool)
    .await?;

    Ok(row.map(WalletCandidate::from))
}

/// Raw scheduler-candidate row as read from Postgres.
///
/// The id columns are UUIDs and the counts are `bigint` (the `count(*)`
/// aggregates and the `submission_count_24h` column), mapped straight onto the
/// public [`WalletCandidate`].
#[derive(sqlx::FromRow)]
struct CandidateRow {
    wallet_id: Uuid,
    registrar_operator_id: Uuid,
    label: String,
    address: String,
    in_flight_count: i64,
    canonical_ready_count: i64,
    submission_count_24h: i64,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<CandidateRow> for WalletCandidate {
    fn from(row: CandidateRow) -> Self {
        WalletCandidate {
            wallet_id: row.wallet_id,
            registrar_operator_id: row.registrar_operator_id,
            label: row.label,
            address: row.address,
            in_flight_count: row.in_flight_count,
            canonical_ready_count: row.canonical_ready_count,
            submission_count_24h: row.submission_count_24h,
            last_used_at: row.last_used_at,
        }
    }
}

/// Take the per-wallet session advisory lock, held across build -> sign ->
/// submit so two in-flight transactions on one wallet can never select the same
/// UTxO.
///
/// The lock key is namespaced by wallet id so wallets never contend with each
/// other. The guard owns a dedicated detached connection (see
/// [`crate::runtime::locks::AdvisoryLock`]); dropping it releases the lock even
/// if the submit path panics.
pub async fn lock_wallet(pool: &sqlx::PgPool, wallet_id: Uuid) -> Result<AdvisoryLock> {
    AdvisoryLock::acquire(pool, &wallet_lock_name(wallet_id)).await
}

/// Try to take the per-wallet advisory lock without blocking. `Ok(None)` means
/// another submit on this wallet already holds it.
pub async fn try_lock_wallet(pool: &sqlx::PgPool, wallet_id: Uuid) -> Result<Option<AdvisoryLock>> {
    AdvisoryLock::try_acquire(pool, &wallet_lock_name(wallet_id)).await
}

/// Take the per-wallet advisory lock with a bounded wait, returning `Ok(None)`
/// if the deadline elapsed before the lock was free.
///
/// The confirm authority's wallet-mutating arms acquire with [`try_lock_wallet`]
/// and yield rather than block; after a mutation has yielded too many times it
/// escalates to this bounded-fair acquire so a persistently-contended record's
/// mutation is applied in bounded time rather than only eventually. It still takes
/// the wallet advisory lock before any `wallet_utxo` row lock, so the lock-order
/// invariant is preserved.
pub async fn try_lock_wallet_with_deadline(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    deadline: std::time::Duration,
) -> Result<Option<AdvisoryLock>> {
    AdvisoryLock::acquire_with_deadline(pool, &wallet_lock_name(wallet_id), deadline).await
}

/// Record that a wallet was used for a submit: bump its 24h counter and stamp
/// `last_used_at = now()`. Called on an accepted submit so the scheduler spreads
/// the next pick away from a freshly used wallet.
pub async fn record_submission(pool: &sqlx::PgPool, wallet_id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE cw_core.operator_wallet \
         SET submission_count_24h = submission_count_24h + 1, last_used_at = now() \
         WHERE id = $1",
    )
    .bind(wallet_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reset every wallet's trailing-24h submission counter to zero.
///
/// Run daily by the decay job. The counter is a load-spreading hint, not an
/// accounting record, so a hard daily reset (rather than a rolling window) is
/// enough to keep the scheduler's tie-break meaningful. Returns how many wallets
/// were reset.
pub async fn decay_submission_counters(pool: &sqlx::PgPool) -> Result<u64> {
    // Only touch rows that actually carry a non-zero counter, so the reset is a
    // no-op (and reports zero) once everything is already at zero. last_used_at
    // is left intact: it is the round-robin tie-break, not a daily metric.
    let reset = sqlx::query(
        "UPDATE cw_core.operator_wallet \
         SET submission_count_24h = 0 \
         WHERE submission_count_24h <> 0",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(reset)
}

/// Finalise draining wallets that have no UTxO still in flight.
///
/// A `draining` wallet takes no new claims but lets its in-flight transactions
/// finish; once it has zero `in_flight` UTxOs it is moved to `retired` with
/// `retired_at = now()`. Run by the retire sweep. Returns how many wallets were
/// retired.
pub async fn sweep_drained_wallets(pool: &sqlx::PgPool) -> Result<u64> {
    // A draining wallet retires once it has nothing left in flight. The
    // NOT EXISTS guard is the "in-flight transactions may finish" rule: a
    // draining wallet whose last leased UTxO is still `in_flight` is left alone
    // until that submit resolves (release, reap, or apply_submit_in_tx) and the
    // row is no longer in_flight.
    let retired = sqlx::query(
        "UPDATE cw_core.operator_wallet w \
         SET status = 'retired', retired_at = now() \
         WHERE w.status = 'draining' \
           AND NOT EXISTS ( \
               SELECT 1 FROM cw_core.wallet_utxo u \
               WHERE u.wallet_id = w.id AND u.state = 'in_flight' \
           )",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(retired)
}

/// The queue the daily decay + retire sweep runs on.
pub const WALLET_MAINTENANCE_QUEUE: &str = "wallet_maintenance";

/// The default policy for the wallet-maintenance queue: a singleton loop so the
/// daily reset and retire sweep run once across the deployment.
#[must_use]
pub fn wallet_maintenance_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        WALLET_MAINTENANCE_QUEUE,
        3,
        crate::runtime::Backoff::Fixed { base_secs: 60 },
        120,
    )
}

/// A daily schedule for the wallet-maintenance job: reset the 24h submission
/// counters and retire fully drained wallets once per day, just after midnight
/// UTC. The decay only needs to be coarse (it feeds a load-spreading tie-break),
/// and the retire sweep is idempotent, so a once-daily cadence is sufficient.
#[must_use]
pub fn wallet_maintenance_schedule() -> crate::runtime::scheduler::CronSchedule {
    crate::runtime::scheduler::CronSchedule::new(
        "0 0 * * *",
        WALLET_MAINTENANCE_QUEUE,
        serde_json::Value::Null,
    )
}

/// What one wallet-maintenance pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletMaintenanceOutcome {
    /// How many wallets had their 24h submission counter reset to zero.
    pub counters_reset: u64,
    /// How many drained wallets were retired (no UTxO still in flight).
    pub wallets_retired: u64,
}

/// The daily decay + retire-sweep job handler.
///
/// Register it on the runtime against [`WALLET_MAINTENANCE_QUEUE`] with
/// [`wallet_maintenance_policy`] and [`wallet_maintenance_schedule`]. It owns its
/// pool so the runtime can drive it with only a [`crate::runtime::JobContext`].
/// Both steps are idempotent (the counter reset only touches non-zero rows; the
/// retire sweep only moves drained wallets with nothing in flight), so an
/// at-least-once retry is harmless.
pub struct WalletMaintenanceHandler {
    pool: sqlx::PgPool,
}

impl WalletMaintenanceHandler {
    /// Build a handler bound to a pool.
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Run one maintenance pass: reset the daily submission counters, then
    /// retire any draining wallet that has finished its in-flight work.
    pub async fn run_once(&self) -> Result<WalletMaintenanceOutcome> {
        let counters_reset = decay_submission_counters(&self.pool).await?;
        let wallets_retired = sweep_drained_wallets(&self.pool).await?;
        Ok(WalletMaintenanceOutcome {
            counters_reset,
            wallets_retired,
        })
    }
}

impl crate::runtime::JobHandler for WalletMaintenanceHandler {
    async fn handle(&self, _ctx: crate::runtime::JobContext) -> crate::runtime::JobOutcome {
        match self.run_once().await {
            Ok(outcome) => {
                tracing::info!(
                    counters_reset = outcome.counters_reset,
                    wallets_retired = outcome.wallets_retired,
                    "wallet maintenance pass complete"
                );
                crate::runtime::JobOutcome::Complete
            }
            Err(e) => {
                tracing::warn!(error = %e, "wallet maintenance pass failed");
                crate::runtime::JobOutcome::Fail {
                    error: crate::runtime::JobError::new(
                        "wallet_maintenance_failed",
                        e.to_string(),
                    ),
                }
            }
        }
    }
}

/// The advisory-lock name for a wallet, namespaced so per-wallet locks never
/// collide with each other or with the engine's other lock names.
fn wallet_lock_name(wallet_id: Uuid) -> String {
    format!("cw_core:wallet:{wallet_id}")
}
