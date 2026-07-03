//! Background maintenance: partition lifecycle and terminal-job archival.
//!
//! These tasks keep the live tables small and the partitioned tables provisioned
//! ahead of time. They are designed to run as ordinary engine jobs and are
//! idempotent so an at-least-once retry is harmless.

pub mod partitions;

use crate::runtime::{JobContext, JobError, JobHandler, JobOutcome};
use crate::storage::OrphanRefundSweep;
use crate::Result;

use partitions::{engine_tables, maintain, PartitionWindow};

/// Move terminal jobs out of the live table into history.
///
/// Copies up to `batch` `completed | failed | cancelled` rows from
/// `cw_core.job` into `cw_core.job_history` (range-partitioned by `finished_at`)
/// and deletes them from the live table, all in one statement so a row is never
/// lost or duplicated. Keeping the live table small is what preserves cheap
/// claim scans and global singleton uniqueness. Returns how many rows moved.
///
/// Only rows whose `finished_at` is older than `min_age_minutes` are moved, so a
/// row that just reached a terminal state stays briefly in the live table where
/// the worker that finished it (and any inspection right after) can still see it
/// at its primary key before it migrates to a partitioned table.
pub async fn archive_terminal_jobs(
    pool: &sqlx::PgPool,
    min_age_minutes: i64,
    batch: i64,
) -> Result<u64> {
    // A single data-modifying CTE deletes a bounded batch of eligible rows and
    // re-inserts them into history in the same statement and snapshot, so the
    // move is atomic without an explicit transaction. SKIP LOCKED lets two
    // replicas archive disjoint batches concurrently. finished_at is NOT NULL
    // for terminal rows (set when they reached a terminal state), so the
    // history partition key is always present.
    let moved = sqlx::query(
        r#"
        WITH eligible AS (
            SELECT id
            FROM cw_core.job
            WHERE state IN ('completed', 'failed', 'cancelled')
              AND finished_at IS NOT NULL
              AND finished_at < now() - make_interval(mins => $1::int)
            ORDER BY finished_at, id
            FOR UPDATE SKIP LOCKED
            LIMIT $2
        ),
        moved AS (
            DELETE FROM cw_core.job j
            USING eligible e
            WHERE j.id = e.id
            RETURNING j.id, j.queue, j.payload, j.state, j.run_at, j.attempts,
                      j.max_attempts, j.backoff, j.singleton_key, j.defer_count,
                      j.deadline, j.last_error, j.created_at, j.started_at,
                      j.finished_at
        )
        INSERT INTO cw_core.job_history
            (id, queue, payload, state, run_at, attempts, max_attempts, backoff,
             singleton_key, defer_count, deadline, last_error, created_at,
             started_at, finished_at)
        SELECT id, queue, payload, state, run_at, attempts, max_attempts, backoff,
               singleton_key, defer_count, deadline, last_error, created_at,
               started_at, finished_at
        FROM moved
        "#,
    )
    .bind(min_age_minutes)
    .bind(batch)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(moved)
}

/// Prune `cron_tick` rows older than the retention window.
///
/// The double-fire guard only needs ticks recent enough that a replica could
/// still be evaluating them; older rows are pure history and are pruned.
/// Returns how many rows were removed.
pub async fn prune_cron_ticks(pool: &sqlx::PgPool, older_than_days: i64) -> Result<u64> {
    let pruned = sqlx::query(
        "DELETE FROM cw_core.cron_tick \
         WHERE enqueued_at < now() - make_interval(days => $1::int)",
    )
    .bind(older_than_days)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(pruned)
}

/// Prune the webhook delivery firehose: terminal deliveries past the retention
/// window, stranded pending deliveries of dead endpoints past the same window,
/// then the outbox rows they leave fully dereferenced.
///
/// Every publish fans out into ~3 `delivery_outbox` rows and one
/// `webhook_delivery` row per matching endpoint, so without a retention path
/// these two flat tables grow without bound. They are not partitioned —
/// `delivery_outbox.dedupe_key` is globally unique and `webhook_delivery` carries
/// a cascading FK to it — so the firehose is pruned by bounded batch deletes
/// rather than by dropping partitions.
///
/// Three stages, in FK-safe order:
///
/// 1. Delete `webhook_delivery` rows in a terminal state (`delivered` | `failed`)
///    whose `created_at` is older than the window. A `pending` row is never
///    touched here, so a delivery still mid-retry — or a `failed` dead-letter
///    still inside the window where an operator can redrive it — is kept until it
///    resolves or ages out. `created_at` is the age key because a `failed` row
///    leaves `delivered_at` NULL, so it is the only terminal timestamp present on
///    every terminal row.
/// 2. Delete `pending` deliveries older than the window whose endpoint cannot
///    currently be delivered to: soft-deleted, auto-`disabled`, or subscriber-
///    `paused`. The delivery claim only serves `active`, non-deleted endpoints,
///    so such a row can only reach a terminal state if the subscriber revives the
///    endpoint — and the retention window is the system's bound on how long any
///    delivery is kept awaiting that. Inside the window the row is preserved (a
///    re-enable or unpause resumes it exactly where it stopped); past the window
///    it is reclaimed like a terminal row, or a single dead endpoint would pin
///    its deliveries — and the outbox rows they reference — forever. A pending
///    row on an `active` endpoint is never pruned at any age: it is still
///    genuinely deliverable.
/// 3. Delete `delivery_outbox` rows that have been fanned out
///    (`fanned_out_at IS NOT NULL`), are older than the window, and are no longer
///    referenced by any surviving `webhook_delivery` row. A row still awaiting
///    fan-out (`fanned_out_at IS NULL`) is kept so its events are never dropped
///    before the fan-out reader explodes them; a row whose children outlived the
///    window (still pending/within-window deliveries) is kept until those
///    children are themselves pruned on a later pass.
///
/// All stages run in bounded passes (`batch` rows per statement, at most
/// `MAX_SWEEP_PASSES` passes), so a large backlog drains over successive daily
/// runs without holding a long lock on either table. Returns the totals deleted
/// from each table.
pub async fn prune_webhook_firehose(
    pool: &sqlx::PgPool,
    older_than_days: i64,
    batch: i64,
) -> Result<WebhookFirehoseSweep> {
    let mut deliveries_deleted = 0u64;
    for _ in 0..MAX_SWEEP_PASSES {
        // A self-join delete bounded by a CTE that selects at most `batch`
        // eligible ids; SKIP LOCKED lets a concurrent delivery worker keep its
        // own rows out of the batch instead of blocking the sweep.
        let n = sqlx::query(
            r#"
            WITH eligible AS (
                SELECT id
                FROM cw_core.webhook_delivery
                WHERE state IN ('delivered', 'failed')
                  AND created_at < now() - make_interval(days => $1::int)
                ORDER BY created_at, id
                FOR UPDATE SKIP LOCKED
                LIMIT $2
            )
            DELETE FROM cw_core.webhook_delivery d
            USING eligible e
            WHERE d.id = e.id
            "#,
        )
        .bind(older_than_days)
        .bind(batch)
        .execute(pool)
        .await?
        .rows_affected();

        deliveries_deleted += n;
        if (n as i64) < batch {
            break;
        }
    }

    let mut stranded_deleted = 0u64;
    for _ in 0..MAX_SWEEP_PASSES {
        // Pending deliveries of dead endpoints, aged past the window. Driven
        // from the (small) endpoint table so the per-endpoint probe rides the
        // pending-state claim index; a live (`active`, non-deleted) endpoint's
        // pending rows are structurally outside the join and can never be
        // selected. SKIP LOCKED keeps the sweep from blocking behind a
        // concurrent claim or redrive touching the same row.
        let n = sqlx::query(
            r#"
            WITH eligible AS (
                SELECT d.id
                FROM cw_core.webhook_delivery d
                JOIN cw_core.webhook_endpoint e ON e.id = d.endpoint_id
                WHERE d.state = 'pending'
                  AND d.created_at < now() - make_interval(days => $1::int)
                  AND (e.deleted_at IS NOT NULL OR e.status <> 'active')
                ORDER BY d.created_at, d.id
                FOR UPDATE OF d SKIP LOCKED
                LIMIT $2
            )
            DELETE FROM cw_core.webhook_delivery d
            USING eligible e
            WHERE d.id = e.id
            "#,
        )
        .bind(older_than_days)
        .bind(batch)
        .execute(pool)
        .await?
        .rows_affected();

        stranded_deleted += n;
        if (n as i64) < batch {
            break;
        }
    }

    let mut outbox_deleted = 0u64;
    for _ in 0..MAX_SWEEP_PASSES {
        // Only fanned-out, aged rows with no surviving delivery child are
        // removed. The NOT EXISTS keeps any outbox row whose deliveries outlived
        // the window (still pending or still within retention); those rows are
        // collected on a later pass once their children are pruned.
        let n = sqlx::query(
            r#"
            WITH eligible AS (
                SELECT o.id
                FROM cw_core.delivery_outbox o
                WHERE o.fanned_out_at IS NOT NULL
                  AND o.created_at < now() - make_interval(days => $1::int)
                  AND NOT EXISTS (
                      SELECT 1
                      FROM cw_core.webhook_delivery d
                      WHERE d.outbox_id = o.id
                  )
                ORDER BY o.created_at, o.id
                FOR UPDATE SKIP LOCKED
                LIMIT $2
            )
            DELETE FROM cw_core.delivery_outbox o
            USING eligible e
            WHERE o.id = e.id
            "#,
        )
        .bind(older_than_days)
        .bind(batch)
        .execute(pool)
        .await?
        .rows_affected();

        outbox_deleted += n;
        if (n as i64) < batch {
            break;
        }
    }

    Ok(WebhookFirehoseSweep {
        deliveries_deleted,
        stranded_deliveries_deleted: stranded_deleted,
        outbox_deleted,
    })
}

/// What one webhook-firehose sweep removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WebhookFirehoseSweep {
    /// Terminal `webhook_delivery` rows deleted past the retention window.
    pub deliveries_deleted: u64,
    /// Aged `pending` deliveries of soft-deleted / disabled / paused endpoints
    /// deleted past the retention window.
    pub stranded_deliveries_deleted: u64,
    /// Fanned-out, fully-dereferenced `delivery_outbox` rows deleted.
    pub outbox_deleted: u64,
}

/// The daily maintenance queue: partition provisioning/pruning and `cron_tick`
/// history pruning, which only need to run once a day.
pub const MAINTENANCE_DAILY_QUEUE: &str = "maintenance_daily";

/// The hourly maintenance queue: moving aged terminal jobs out of the live table
/// into history, which runs frequently so the live table stays small between
/// daily passes.
pub const MAINTENANCE_HOURLY_QUEUE: &str = "maintenance_hourly";

/// Terminal jobs older than this many minutes are eligible to be archived. A
/// short grace period leaves a just-finished row briefly visible at its primary
/// key (for the worker that finished it and any immediate inspection) before it
/// migrates to a partitioned table.
const ARCHIVE_MIN_AGE_MINUTES: i64 = 15;

/// How many terminal rows one archive pass relocates. Bounded so a single pass
/// is a short, predictable statement; the hourly cadence drains any backlog over
/// successive passes, and two replicas archive disjoint batches concurrently.
const ARCHIVE_BATCH: i64 = 5_000;

/// `cron_tick` rows older than this many days are pruned. Comfortably longer than
/// any replica could still be evaluating an occurrence, so pruning never removes
/// a tick that still serves as a double-fire guard.
const CRON_TICK_RETENTION_DAYS: i64 = 7;

/// Terminal webhook deliveries (and the outbox rows they leave dereferenced)
/// older than this many days are pruned. Long enough that an operator can still
/// inspect or redrive a recent dead-letter, short enough that the per-publish
/// firehose does not grow without bound.
const WEBHOOK_FIREHOSE_RETENTION_DAYS: i64 = 30;

/// How long after a charged upload, with no published record referencing it, the
/// orphaned-upload sweep refunds the charge.
///
/// The grace window must exceed the maximum lifetime of a not-yet-published
/// upload, and that lifetime is not bounded by the gateway alone. The gateway
/// sees only its own records table; it cannot observe a vendor's draft that has
/// reserved an upload's URI but not yet published it. A vendor reconcile loop that
/// retries a stuck publish (a prolonged gateway/network outage, say) can keep a
/// legitimate draft alive far longer than the seconds-to-minutes a healthy
/// upload-then-publish takes. Refunding at the healthy-path timescale would race
/// that retry: the gateway could refund the upload, the vendor could then finally
/// publish, and the resulting record would reference a now-refunded upload —
/// leaving permanently-stored Arweave content unbilled.
///
/// Seven days is comfortably past any such retry: a normal upload publishes within
/// minutes, and a vendor reconcile loop runs on the order of minutes, so an upload
/// still unreferenced after a week is genuinely abandoned, not merely waiting on a
/// retry. The longer window only delays the WP-2 double-charge correction; it
/// never weakens it, because the orphan stays a refund candidate until it is
/// published or the week elapses.
const ORPHAN_REFUND_GRACE_SECONDS: i64 = 7 * 24 * 60 * 60;

/// How many orphaned-upload candidates one sweep claim considers per pass. Bounded
/// so a single statement is short; the daily cadence drains any backlog over
/// successive passes within a run and across runs.
const ORPHAN_REFUND_BATCH: i64 = 1_000;

/// How many firehose rows one delete pass removes from each table. Bounded so a
/// single statement is short and never holds a long lock; the daily cadence
/// drains any backlog over successive passes within a run and across runs.
const WEBHOOK_FIREHOSE_BATCH: i64 = 5_000;

/// The most delete passes a single firehose sweep makes per table in one run. A
/// hard cap so one daily pass is predictably bounded even against a huge
/// backlog; the remainder is collected on the next day's run.
const MAX_SWEEP_PASSES: usize = 50;

/// Which maintenance tasks a [`MaintenanceHandler`] performs per pass.
///
/// The two cadences are split because their work has different urgency: the
/// hourly pass keeps the live `job` table small, while the daily pass provisions
/// partitions ahead and prunes long-dead history. One handler type covers both;
/// the cadence is the only thing that differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceCadence {
    /// Provision/prune partitions and prune the `cron_tick` history.
    Daily,
    /// Move aged terminal jobs from the live table into history.
    Hourly,
}

impl MaintenanceCadence {
    /// The queue this cadence's job runs on.
    #[must_use]
    pub fn queue(self) -> &'static str {
        match self {
            MaintenanceCadence::Daily => MAINTENANCE_DAILY_QUEUE,
            MaintenanceCadence::Hourly => MAINTENANCE_HOURLY_QUEUE,
        }
    }
}

/// The default policy for a maintenance queue: a singleton loop so at most one
/// maintenance pass of a given cadence is in flight across the whole deployment.
/// A short fixed backoff and a small attempt budget ride out a transient
/// database blip until the next scheduled tick; the work is idempotent, so a
/// retry of an already-done pass is a cheap no-op.
#[must_use]
pub fn maintenance_policy(cadence: MaintenanceCadence) -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        cadence.queue(),
        3,
        crate::runtime::Backoff::Fixed { base_secs: 60 },
        // A maintenance pass touches catalog/partition metadata and bounded row
        // batches; a 10-minute lease is ample and reclaims promptly if a replica
        // dies mid-pass.
        600,
    )
}

/// The schedule that fires a maintenance cadence.
///
/// The daily cadence runs once a day in the small hours (UTC); the hourly
/// cadence runs at the top of every hour. The scheduler's `cron_tick` gate
/// ensures exactly one replica enqueues each occurrence.
#[must_use]
pub fn maintenance_schedule(
    cadence: MaintenanceCadence,
) -> crate::runtime::scheduler::CronSchedule {
    let cron = match cadence {
        // 03:17 UTC daily: an off-peak, non-round minute so the daily pass does
        // not pile onto every other top-of-hour schedule.
        MaintenanceCadence::Daily => "17 3 * * *",
        // Top of every hour.
        MaintenanceCadence::Hourly => "0 * * * *",
    };
    crate::runtime::scheduler::CronSchedule::new(cron, cadence.queue(), serde_json::Value::Null)
}

/// The job handler that runs one maintenance pass for a cadence.
///
/// Register it on the runtime against [`MaintenanceCadence::queue`] with
/// [`maintenance_policy`] and [`maintenance_schedule`]. It owns its pool, so the
/// runtime can drive it with only a [`JobContext`]. Every pass is idempotent, so
/// the at-least-once delivery the runtime guarantees is harmless.
pub struct MaintenanceHandler {
    pool: sqlx::PgPool,
    cadence: MaintenanceCadence,
}

impl MaintenanceHandler {
    /// Build a handler for a cadence against a pool.
    #[must_use]
    pub fn new(pool: sqlx::PgPool, cadence: MaintenanceCadence) -> Self {
        Self { pool, cadence }
    }

    /// The cadence this handler runs.
    #[must_use]
    pub fn cadence(&self) -> MaintenanceCadence {
        self.cadence
    }

    /// Run one maintenance pass for this handler's cadence, returning a summary
    /// of what changed. Idempotent: re-running with nothing newly eligible is a
    /// no-op.
    pub async fn run_once(&self) -> Result<MaintenanceSummary> {
        match self.cadence {
            MaintenanceCadence::Daily => {
                let reports =
                    maintain(&self.pool, &engine_tables(), PartitionWindow::default()).await?;
                let partitions_created =
                    reports.iter().map(|(_, r)| r.created.len()).sum::<usize>();
                let partitions_dropped =
                    reports.iter().map(|(_, r)| r.dropped.len()).sum::<usize>();
                let cron_ticks_pruned =
                    prune_cron_ticks(&self.pool, CRON_TICK_RETENTION_DAYS).await?;
                let webhook_firehose = prune_webhook_firehose(
                    &self.pool,
                    WEBHOOK_FIREHOSE_RETENTION_DAYS,
                    WEBHOOK_FIREHOSE_BATCH,
                )
                .await?;
                let orphan_refund = crate::storage::refund_orphaned_uploads(
                    &self.pool,
                    ORPHAN_REFUND_GRACE_SECONDS,
                    ORPHAN_REFUND_BATCH,
                )
                .await?;
                Ok(MaintenanceSummary {
                    partitions_created,
                    partitions_dropped,
                    cron_ticks_pruned,
                    jobs_archived: 0,
                    webhook_firehose,
                    orphan_refund,
                })
            }
            MaintenanceCadence::Hourly => {
                let jobs_archived =
                    archive_terminal_jobs(&self.pool, ARCHIVE_MIN_AGE_MINUTES, ARCHIVE_BATCH)
                        .await?;
                Ok(MaintenanceSummary {
                    partitions_created: 0,
                    partitions_dropped: 0,
                    cron_ticks_pruned: 0,
                    jobs_archived,
                    webhook_firehose: WebhookFirehoseSweep::default(),
                    orphan_refund: OrphanRefundSweep::default(),
                })
            }
        }
    }
}

/// What one maintenance pass changed. All counters are zero for the cadence that
/// does not perform a given task.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaintenanceSummary {
    /// Future partitions created across all registered tables.
    pub partitions_created: usize,
    /// Past partitions dropped across all registered tables.
    pub partitions_dropped: usize,
    /// `cron_tick` history rows pruned.
    pub cron_ticks_pruned: u64,
    /// Aged terminal jobs moved from the live table into history.
    pub jobs_archived: u64,
    /// Terminal webhook deliveries and dereferenced outbox rows pruned.
    pub webhook_firehose: WebhookFirehoseSweep,
    /// Charged uploads no record referenced, refunded past the grace window.
    pub orphan_refund: OrphanRefundSweep,
}

impl JobHandler for MaintenanceHandler {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        match self.run_once().await {
            Ok(summary) => {
                tracing::info!(
                    cadence = ?self.cadence,
                    partitions_created = summary.partitions_created,
                    partitions_dropped = summary.partitions_dropped,
                    cron_ticks_pruned = summary.cron_ticks_pruned,
                    jobs_archived = summary.jobs_archived,
                    webhook_deliveries_pruned = summary.webhook_firehose.deliveries_deleted,
                    webhook_stranded_pruned = summary.webhook_firehose.stranded_deliveries_deleted,
                    webhook_outbox_pruned = summary.webhook_firehose.outbox_deleted,
                    orphan_uploads_refunded = summary.orphan_refund.uploads_refunded,
                    orphan_refunded_usd_micros = summary.orphan_refund.refunded_usd_micros,
                    orphan_intents_backfilled = summary.orphan_refund.intents_backfilled,
                    "maintenance pass complete"
                );
                JobOutcome::Complete
            }
            Err(e) => {
                tracing::warn!(cadence = ?self.cadence, error = %e, "maintenance pass failed");
                JobOutcome::Fail {
                    error: JobError::new("maintenance_failed", e.to_string()),
                }
            }
        }
    }
}
