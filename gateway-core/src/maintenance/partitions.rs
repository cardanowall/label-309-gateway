//! Generic monthly-partition maintenance.
//!
//! Each range-partitioned table (`cw_core.job_history`, `cw_core.subject_event`)
//! is registered once with its partition column. A single maintenance pass then,
//! for every registered table:
//!
//! - creates the partitions for the next N months ahead of time (so an insert
//!   never lands in an unprovisioned range),
//! - drains any rows stranded in the table's DEFAULT partition into real
//!   monthly partitions, and
//! - drops partitions whose entire range falls before the configured hot window.
//!
//! Every step is idempotent: partition creation uses `CREATE TABLE IF NOT
//! EXISTS` and introspects `pg_partition_tree` before acting, and a drop only
//! targets a partition wholly outside the hot window. The pass runs under a
//! session advisory lock so two replicas never race to create or drop the same
//! partition.
//!
//! # Two layers of "an insert never fails on a missing partition"
//!
//! Provisioning runs from two places: [`provision`] executes synchronously when
//! the runtime is built (before any loop starts, so a fresh deployment — or one
//! restarting after a long lapse — always has the current month and the
//! lookahead attached before the first insert), and the daily maintenance job
//! keeps the lookahead topped up while the process runs. The DEFAULT partition
//! each table carries is the backstop for the residual case both can miss: a
//! process that outlives its provisioned lookahead without a restart and
//! without a successful daily pass. A row routed to DEFAULT is not lost and
//! does not wedge later provisioning — the ensure pass detaches the DEFAULT
//! partition, creates the months its rows span, moves them, and re-attaches,
//! all in one transaction under the parent's lock — so DEFAULT rows are a
//! self-healing transient and the steady state keeps DEFAULT empty.

use chrono::{DateTime, Datelike, TimeZone, Utc};

use crate::runtime::locks::AdvisoryLock;
use crate::Result;

/// The advisory-lock name the maintenance pass serializes on. One pass at a
/// time across all replicas so two never race to create or drop a partition.
const MAINTENANCE_LOCK: &str = "cw_core:partition_maintenance";

/// A range-partitioned table under maintenance.
#[derive(Debug, Clone)]
pub struct PartitionedTable {
    /// Schema-qualified table name (e.g. `cw_core.subject_event`).
    pub table: String,
    /// The `timestamptz` column the table is range-partitioned on.
    pub partition_column: String,
}

impl PartitionedTable {
    /// Register a table for monthly-partition maintenance.
    pub fn new(table: impl Into<String>, partition_column: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            partition_column: partition_column.into(),
        }
    }

    /// The unqualified table name (drops the `schema.` prefix if present). Used
    /// to build child-partition names.
    fn bare_name(&self) -> &str {
        self.table.rsplit('.').next().unwrap_or(&self.table)
    }

    /// The child-partition name for a given month, e.g. `subject_event_2026_07`.
    fn partition_name(&self, month: &MonthBounds) -> String {
        format!("{}_{:04}_{:02}", self.bare_name(), month.year, month.month)
    }

    /// The table's DEFAULT-partition name, e.g. `subject_event_default`. The
    /// migration corpus attaches one per registered table as the backstop that
    /// catches an insert whose month has no partition yet.
    fn default_partition_name(&self) -> String {
        format!("{}_default", self.bare_name())
    }
}

/// The two tables the engine partitions, in their canonical registration.
pub fn engine_tables() -> Vec<PartitionedTable> {
    vec![
        PartitionedTable::new("cw_core.job_history", "finished_at"),
        PartitionedTable::new("cw_core.subject_event", "created_at"),
    ]
}

/// How far to provision ahead and how long to retain.
#[derive(Debug, Clone, Copy)]
pub struct PartitionWindow {
    /// Number of future monthly partitions to keep provisioned.
    pub create_ahead_months: u32,
    /// Number of past months to retain before dropping partitions.
    pub retain_months: u32,
}

impl Default for PartitionWindow {
    /// The engine's operating window: three months of lookahead gives ample
    /// headroom for an insert with a near-future timestamp (and for a lapse in
    /// the daily maintenance job), and twelve months of retention keeps a year
    /// of history queryable before a partition is dropped. Shared by the
    /// startup provisioning and the daily maintenance pass so the two never
    /// disagree about the working set.
    fn default() -> Self {
        Self {
            create_ahead_months: 3,
            retain_months: 12,
        }
    }
}

/// What one maintenance pass changed for a single table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartitionReport {
    /// Names of partitions created this pass.
    pub created: Vec<String>,
    /// Names of partitions dropped this pass.
    pub dropped: Vec<String>,
}

/// The half-open `[start, end)` UTC bounds of a single calendar month, plus the
/// month's identifying year/month numbers.
#[derive(Debug, Clone, Copy)]
struct MonthBounds {
    year: i32,
    month: u32,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

/// The first instant of the calendar month containing `at`.
fn month_floor(at: DateTime<Utc>) -> MonthBounds {
    let year = at.year();
    let month = at.month();
    let start = Utc
        .with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
        .expect("first-of-month is always a valid instant");
    bounds_from_start(year, month, start)
}

/// Advance a month by `offset` calendar months (offset may be negative).
fn add_months(base: MonthBounds, offset: i32) -> MonthBounds {
    // Convert to a zero-based absolute month index, shift, convert back.
    let abs = base.year as i64 * 12 + (base.month as i64 - 1) + offset as i64;
    let year = (abs.div_euclid(12)) as i32;
    let month = (abs.rem_euclid(12) + 1) as u32;
    let start = Utc
        .with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
        .expect("first-of-month is always a valid instant");
    bounds_from_start(year, month, start)
}

/// The bounds of the calendar month identified by `(year, month)`.
fn month_bounds(year: i32, month: u32) -> MonthBounds {
    let start = Utc
        .with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
        .expect("first-of-month is always a valid instant");
    bounds_from_start(year, month, start)
}

fn bounds_from_start(year: i32, month: u32, start: DateTime<Utc>) -> MonthBounds {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let end = Utc
        .with_ymd_and_hms(next_year, next_month, 1, 0, 0, 0)
        .single()
        .expect("first-of-next-month is always a valid instant");
    MonthBounds {
        year,
        month,
        start,
        end,
    }
}

/// Names of the existing child partitions of `table`, via `pg_partition_tree`.
///
/// `pg_partition_tree` lists the parent and all descendants; the parent row
/// (`isleaf = false`) is filtered out so only the leaf partitions remain.
async fn existing_partitions<'e, E>(executor: E, table: &PartitionedTable) -> Result<Vec<String>>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT relid::regclass::text \
         FROM pg_partition_tree($1::regclass) \
         WHERE isleaf",
    )
    .bind(&table.table)
    .fetch_all(executor)
    .await?;

    // regclass text may be schema-qualified; reduce to the bare child name so it
    // compares cleanly against the generated partition names.
    Ok(rows
        .into_iter()
        .map(|(name,)| name.rsplit('.').next().unwrap_or(&name).to_string())
        .collect())
}

/// The distinct `(year, month)` UTC months of the rows currently sitting in the
/// table's DEFAULT partition. Empty in the healthy steady state.
async fn months_in_default<'e, E>(executor: E, table: &PartitionedTable) -> Result<Vec<(i32, u32)>>
where
    E: sqlx::PgExecutor<'e>,
{
    // Identifiers are engine-controlled (see create_partition). The month is
    // derived in UTC explicitly — date_part on a bare timestamptz would use the
    // session time zone and could split a row into the wrong month.
    let sql = format!(
        "SELECT DISTINCT \
             date_part('year',  \"{col}\" AT TIME ZONE 'UTC')::int, \
             date_part('month', \"{col}\" AT TIME ZONE 'UTC')::int \
         FROM cw_core.\"{default_name}\"",
        col = table.partition_column,
        default_name = table.default_partition_name(),
    );
    let rows: Vec<(i32, i32)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_all(executor)
        .await?;
    Ok(rows.into_iter().map(|(y, m)| (y, m as u32)).collect())
}

/// Ensure the next `window.create_ahead_months` monthly partitions exist for a
/// table and that its DEFAULT partition is empty, creating months and draining
/// stranded rows as needed. Idempotent.
///
/// The provisioned set spans the current month through `create_ahead_months`
/// months ahead, so an insert with a near-future timestamp always finds a home
/// and re-running the pass creates nothing new. Rows found in the DEFAULT
/// partition (inserts that raced a missing month) are relocated into real
/// monthly partitions, so retention pruning applies to them and DEFAULT never
/// blocks a later create.
///
/// The steady-state probe runs lock-free; only when a month is missing or the
/// DEFAULT partition holds rows does the pass take the parent's lock and do
/// DDL, so the daily re-run is a pair of cheap reads.
pub async fn ensure_ahead(
    pool: &sqlx::PgPool,
    table: &PartitionedTable,
    window: PartitionWindow,
) -> Result<Vec<String>> {
    let existing = existing_partitions(pool, table).await?;
    let current = month_floor(Utc::now());
    let all_months_exist = (0..=window.create_ahead_months as i32).all(|offset| {
        let name = table.partition_name(&add_months(current, offset));
        existing.iter().any(|e| e == &name)
    });
    if all_months_exist && months_in_default(pool, table).await?.is_empty() {
        return Ok(Vec::new());
    }

    provision_locked(pool, table, window).await
}

/// Create the missing monthly partitions (and drain the DEFAULT partition) in
/// one transaction under the parent's `ACCESS EXCLUSIVE` lock.
///
/// The explicit lock is taken first so everything below sees a frozen world:
/// no concurrent insert can slip a row into DEFAULT between the emptiness
/// check and a `CREATE TABLE ... PARTITION OF` (which would fail on the
/// conflicting row), and no sibling replica can race the same DDL. Writers
/// block for the duration rather than erroring; the transaction is short in
/// the common case (a handful of `CREATE TABLE`s a month) and bounded by the
/// stranded-row volume in the repair case. `CREATE TABLE ... PARTITION OF`
/// takes the same lock on the parent anyway, so the explicit acquisition adds
/// determinism, not contention.
///
/// When DEFAULT holds rows the drain runs the standard detach/create/move/
/// re-attach recipe: partitions cannot be created over ranges DEFAULT already
/// has rows for, so DEFAULT is detached, the months its rows span (plus the
/// forward window) are created, the rows are re-inserted through the parent
/// (routing them into their new months), and the emptied DEFAULT is
/// re-attached. Crash-safety is the transaction itself: any failure rolls the
/// whole repair back with DEFAULT still attached and every row still in it.
async fn provision_locked(
    pool: &sqlx::PgPool,
    table: &PartitionedTable,
    window: PartitionWindow,
) -> Result<Vec<String>> {
    let mut tx = pool.begin().await?;

    // Identifiers below are engine-controlled, never user input (see
    // create_partition); AssertSqlSafe records each splice as deliberate.
    let lock_sql = format!("LOCK TABLE {} IN ACCESS EXCLUSIVE MODE", table.table);
    sqlx::query(sqlx::AssertSqlSafe(lock_sql))
        .execute(&mut *tx)
        .await?;

    // Re-derive the world under the lock: the lock-free probe that got us here
    // may be stale (another replica may have provisioned in between).
    let existing = existing_partitions(&mut *tx, table).await?;
    let stranded = months_in_default(&mut *tx, table).await?;

    // Target months: the forward window plus every month stranded rows span,
    // deduplicated, minus what already exists.
    let current = month_floor(Utc::now());
    let mut targets: Vec<MonthBounds> = (0..=window.create_ahead_months as i32)
        .map(|offset| add_months(current, offset))
        .collect();
    for &(year, month) in &stranded {
        if !targets.iter().any(|t| (t.year, t.month) == (year, month)) {
            targets.push(month_bounds(year, month));
        }
    }
    targets.retain(|month| {
        let name = table.partition_name(month);
        !existing.iter().any(|e| e == &name)
    });

    let default_name = table.default_partition_name();
    let draining = !stranded.is_empty();
    if draining {
        let detach = format!(
            "ALTER TABLE {parent} DETACH PARTITION cw_core.\"{default_name}\"",
            parent = table.table,
        );
        sqlx::query(sqlx::AssertSqlSafe(detach))
            .execute(&mut *tx)
            .await?;
    }

    let mut created = Vec::new();
    for month in &targets {
        let name = table.partition_name(month);
        create_partition(&mut *tx, table, &name, month).await?;
        created.push(name);
    }

    if draining {
        // Route every stranded row back through the parent — the months just
        // created (plus any that already existed) receive them — then re-attach
        // the emptied DEFAULT. The ATTACH's validation scan sees zero rows.
        let move_rows = format!(
            "INSERT INTO {parent} SELECT * FROM cw_core.\"{default_name}\"",
            parent = table.table,
        );
        sqlx::query(sqlx::AssertSqlSafe(move_rows))
            .execute(&mut *tx)
            .await?;
        let clear = format!("TRUNCATE cw_core.\"{default_name}\"");
        sqlx::query(sqlx::AssertSqlSafe(clear))
            .execute(&mut *tx)
            .await?;
        let attach = format!(
            "ALTER TABLE {parent} ATTACH PARTITION cw_core.\"{default_name}\" DEFAULT",
            parent = table.table,
        );
        sqlx::query(sqlx::AssertSqlSafe(attach))
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(created)
}

/// Create one monthly partition. `CREATE TABLE IF NOT EXISTS` makes a concurrent
/// or repeated create a harmless no-op.
async fn create_partition<'e, E>(
    executor: E,
    table: &PartitionedTable,
    name: &str,
    month: &MonthBounds,
) -> Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    // Identifiers (schema, table, partition name) are engine-controlled, never
    // user input: the table comes from the registered set and the partition name
    // is built from numeric year/month. The range bounds are formatted as
    // literal RFC3339 instants. Nothing here is attacker-influenced.
    let sql = format!(
        "CREATE TABLE IF NOT EXISTS cw_core.\"{name}\" \
         PARTITION OF {parent} \
         FOR VALUES FROM ('{from}') TO ('{to}')",
        name = name,
        parent = table.table,
        from = month.start.to_rfc3339(),
        to = month.end.to_rfc3339(),
    );
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .execute(executor)
        .await?;
    Ok(())
}

/// Drop partitions of a table whose range falls entirely before the retention
/// window. Idempotent.
///
/// A partition is dropped only when its month is strictly older than
/// `retain_months` before the current month, so the current month and the hot
/// window are always preserved and a partition still receiving inserts is never
/// dropped. Re-running drops nothing the first pass already removed.
pub async fn drop_old(
    pool: &sqlx::PgPool,
    table: &PartitionedTable,
    window: PartitionWindow,
) -> Result<Vec<String>> {
    let existing = existing_partitions(pool, table).await?;
    let current = month_floor(Utc::now());
    // The oldest month still retained. Anything before this is droppable.
    let cutoff = add_months(current, -(window.retain_months as i32));

    let mut dropped = Vec::new();
    for offset in 1..=MAX_DROP_LOOKBACK {
        let month = add_months(cutoff, -offset);
        let name = table.partition_name(&month);
        if !existing.iter().any(|e| e == &name) {
            continue;
        }
        drop_partition(pool, &name).await?;
        dropped.push(name);
    }

    Ok(dropped)
}

/// How many months before the retention cutoff `drop_old` scans for droppable
/// partitions. Generous enough to clear a long-idle database in one pass while
/// keeping the scan bounded.
const MAX_DROP_LOOKBACK: i32 = 120;

/// Drop one partition. `IF EXISTS` makes a concurrent or repeated drop a no-op.
async fn drop_partition(pool: &sqlx::PgPool, name: &str) -> Result<()> {
    // `name` is engine-generated (see create_partition); never user input.
    let sql = format!("DROP TABLE IF EXISTS cw_core.\"{name}\"");
    sqlx::query(sqlx::AssertSqlSafe(sql)).execute(pool).await?;
    Ok(())
}

/// Synchronously provision every registered table's partition working set:
/// the current month, the forward window, and an empty DEFAULT partition.
///
/// This is the startup half of the two-layer guarantee (see the module docs):
/// the runtime calls it while being built, before any loop starts, so a fresh
/// deployment — or one restarting after the months hardcoded at its last
/// provisioning have lapsed — has a home for every insert before the first one
/// happens. Unlike [`maintain`], the advisory lock is acquired *blocking*: a
/// provisioned working set is a startup postcondition, not best-effort work,
/// so a replica boots behind a sibling's in-flight pass rather than skipping.
///
/// Returns the partitions created per table (empty on an already-provisioned
/// database).
pub async fn provision(
    pool: &sqlx::PgPool,
    tables: &[PartitionedTable],
    window: PartitionWindow,
) -> Result<Vec<(String, Vec<String>)>> {
    let guard = AdvisoryLock::acquire(pool, MAINTENANCE_LOCK).await?;

    let mut reports = Vec::with_capacity(tables.len());
    for table in tables {
        let created = ensure_ahead(pool, table, window).await?;
        reports.push((table.table.clone(), created));
    }

    guard.release().await?;
    Ok(reports)
}

/// Run a full maintenance pass over all registered tables under a session
/// advisory lock so replicas never race.
///
/// The advisory lock is taken without blocking: if another replica already
/// holds it, this pass returns an empty report rather than queueing behind it,
/// because the holder is already doing the same idempotent work.
pub async fn maintain(
    pool: &sqlx::PgPool,
    tables: &[PartitionedTable],
    window: PartitionWindow,
) -> Result<Vec<(String, PartitionReport)>> {
    let Some(guard) = AdvisoryLock::try_acquire(pool, MAINTENANCE_LOCK).await? else {
        return Ok(Vec::new());
    };

    let mut reports = Vec::with_capacity(tables.len());
    for table in tables {
        let created = ensure_ahead(pool, table, window).await?;
        let dropped = drop_old(pool, table, window).await?;
        reports.push((table.table.clone(), PartitionReport { created, dropped }));
    }

    guard.release().await?;
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_floor_lands_on_first_of_month() {
        let at = Utc
            .with_ymd_and_hms(2026, 7, 18, 13, 45, 0)
            .single()
            .unwrap();
        let m = month_floor(at);
        assert_eq!((m.year, m.month), (2026, 7));
        assert_eq!(
            m.start,
            Utc.with_ymd_and_hms(2026, 7, 1, 0, 0, 0).single().unwrap()
        );
        assert_eq!(
            m.end,
            Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).single().unwrap()
        );
    }

    #[test]
    fn add_months_crosses_year_boundaries_both_ways() {
        let nov = month_floor(Utc.with_ymd_and_hms(2026, 11, 9, 0, 0, 0).single().unwrap());
        let jan = add_months(nov, 2);
        assert_eq!((jan.year, jan.month), (2027, 1));
        let prev = add_months(nov, -11);
        assert_eq!((prev.year, prev.month), (2025, 12));
    }

    #[test]
    fn partition_name_is_zero_padded_and_unqualified() {
        let table = PartitionedTable::new("cw_core.subject_event", "created_at");
        let m = month_floor(Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).single().unwrap());
        assert_eq!(table.partition_name(&m), "subject_event_2026_03");
    }
}
