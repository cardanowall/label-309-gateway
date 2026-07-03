//! The forward-scan indexer loop.
//!
//! A singleton loop ([`SCAN_QUEUE`]) walks the chain forward from a durable
//! cursor, discovering every Label 309 Proof-of-Existence transaction and
//! mirroring it into the on-chain record index so a verifier, the read feed, and
//! third-party tooling can query it without re-fetching from chain. It is the
//! single owner of the `/tip` HTTP read (it writes the materialised tip, which
//! the confirm loop reads with zero HTTP) and one of the two producers of indexed
//! records (the other is the confirm loop's threshold-flip); every record write,
//! delete, and read goes through the single index writer in
//! [`crate::chain::records`].
//!
//! # Zero-knowledge
//!
//! The on-chain index is zero-knowledge about who a sealed record was addressed
//! to. The scan derives and stores only the chain-public first-signer Ed25519
//! key, the item count, the first item's scheme, and the verbatim public
//! transaction bytes. No recipient pubkey, account/identity reference, slot-match
//! hint, or any per-user correlator is ever read or written. A CI guard scans
//! this module and the migration for forbidden vocabulary.
//!
//! # Iteration: plan, then commit, then apply, then backfill
//!
//! Each iteration is four phases in a fixed order:
//!
//! - **PLAN** ([`ScanHandler::plan_iteration`]) does all the network: a
//!   head-of-tick tip refresh, a durable-pool re-check, reorg detection, the
//!   forward fetch and validation, and the cursor-advancement decision. It opens
//!   no transaction and produces a pure-data [`IterationPlan`].
//! - **COMMIT** ([`ScanHandler::commit_plan`]) runs the plan in one short write
//!   transaction: the reorg delete, the record inserts, the pool mutations, and
//!   the cursor advance, so a crash mid-commit rolls back atomically.
//! - **APPLY POOL** is folded into COMMIT: the durable pool lives in Postgres, so
//!   its mutations ride the same transaction as the records and cursor (this is
//!   the deliberate improvement over a process-memory pool that an abort or a
//!   restart would desynchronise).
//! - **BACKFILL** ([`ScanHandler::backfill_tx_cbor`]) repairs a bounded batch of
//!   rows the scan inserted without their full transaction bytes. It never throws:
//!   a provider failure leaves the rows NULL for the next tick.
//!
//! # Self-paced cadence
//!
//! The handler decides its own next wake-up: the active cadence when there is
//! live work (records just indexed, a non-empty pool, or a record still awaiting
//! confirmation), the idle cadence when caught up with nothing in flight, and an
//! immediate resume on a reorg so the rewound range is re-covered at once. A
//! caught-up idle tick costs a single `/tip` call. An all-429 storm parks the
//! loop with a defer for the rate-limit backoff window, which never burns the
//! single attempt the queue allows.

use chrono::{DateTime, Utc};

use super::gateway::{ChainGateway, ScanFrontier as ChainScanFrontier};
use super::params::Network;
use super::records::{derive_chain_record_columns, ChainRecordColumns};
use crate::runtime::{Backoff, JobContext, JobHandler, JobOutcome};
use crate::Result;

/// The queue the forward-scan loop runs on.
pub const SCAN_QUEUE: &str = "chain_scan";

/// The active loop cadence: the cron tick rate, and the re-enqueue delay the
/// handler returns whenever the scan has live work.
pub const SCAN_ACTIVE_POLL_SECS: u32 = 20;

/// The idle loop cadence: the re-enqueue delay the handler returns once it is
/// caught up to the tip with an empty pool and no record awaiting confirmation.
/// A caught-up idle tick costs a single `/tip` call, so a long cadence keeps the
/// no-API-key provider budget low.
pub const SCAN_IDLE_POLL_SECS: i64 = 150;

/// The maximum number of Label 309 records a single forward fetch returns. The
/// scan bounds work by record count, never by block range (per-block enumeration
/// is forbidden), and re-enqueues to resume past a capped response. A single
/// block carrying more records than this is consumed piecemeal across ticks via
/// the durable intra-block exclusion set, so the cap is a page size, never a
/// liveness wall.
pub const SCAN_MAX_RECORDS_PER_ITERATION: u32 = 200;

/// The reorg rewind horizon, in blocks. Reorg detection runs only when the cursor
/// is within this many blocks of the tip, and a detected reorg rewinds the cursor
/// (and deletes `chain_records`) this far back.
pub const SCAN_REORG_WINDOW_BLOCKS: u64 = 30;

/// The durable confirmation pool's size cap. When the pool reaches this many
/// entries the oldest is evicted (and a warning logged) to bound its growth.
pub const SCAN_CONFIRMATION_POOL_MAX_SIZE: i64 = 1000;

/// The maximum number of rows the backfill pass repairs per tick, so the
/// self-healing tx_cbor backfill never holds up cursor advancement.
pub const SCAN_TX_CBOR_BACKFILL_PER_TICK: i64 = 50;

/// Seconds between bounded periodic rewinds. The frontier-hash reorg check is
/// armed on every tick once the frontier carries a real hash, so this periodic
/// re-scan of the last `reorg_window_blocks` is a backstop: it re-covers the
/// window even when the frontier hash is momentarily absent (right after a
/// reorg rewind, or a genesis cursor that has just reached the tip), so a
/// near-tip reorg that landed during such a window is still caught.
///
/// The cadence is wall-clock, never iteration-count: what the backstop bounds
/// is the real-time window during which a missed reorg could go uncaught, and
/// an iteration count is only a proxy for that — one that breaks whenever the
/// re-enqueue pacing changes (an active phase ticks 7x faster than an idle
/// one, and any pacing defect that drives iterations at HTTP latency would
/// fire an every-Nth-iteration rewind every couple of seconds, multiplying
/// provider traffic instead of bounding it). Fifty minutes keeps the extra
/// forward fetch off the steady-state idle budget.
pub const SCAN_BOUNDED_REWIND_INTERVAL_SECS: i64 = 3000;

/// Consecutive non-advancing ticks at the SAME stuck frontier height after which
/// the scan re-fetches the stuck window via the ALTERNATE provider, so one
/// provider's blind spot (an un-hydratable transaction) cannot stall the whole
/// global feed when the other provider can resolve it. `1` means the very next
/// tick after a stall is first observed already tries the alternate.
pub const SCAN_STUCK_GAP_ALTERNATE_AFTER_TICKS: i64 = 1;

/// Consecutive non-advancing ticks at the same stuck frontier height after which
/// an indefinite stall is escalated to an operator-visible error-level alert, so a
/// gap NEITHER provider can hydrate is never silent. Chosen a few ticks beyond the
/// alternate-provider attempt so a transient blip self-heals without alerting.
pub const SCAN_STUCK_GAP_ALERT_AFTER_TICKS: i64 = 5;

/// The forward-scan loop's tuning, read from config so a deployment can override
/// the thresholds without a code change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanConfig {
    /// Confirmations a record must accrue before it is persisted rather than
    /// pooled. Mirrors the confirm loop's threshold so the two paths agree on
    /// when a record is settled.
    pub confirmation_threshold: u64,
    /// The reorg rewind horizon in blocks.
    pub reorg_window_blocks: u64,
    /// The maximum records a single forward fetch returns.
    pub max_records_per_iteration: u32,
    /// The durable pool's size cap.
    pub pool_max_size: i64,
    /// The maximum rows the backfill pass repairs per tick.
    pub tx_cbor_backfill_per_tick: i64,
    /// Seconds between bounded periodic rewinds of the last
    /// `reorg_window_blocks` (wall-clock; `0` or negative disables). A backstop
    /// for a near-tip reorg that landed while the frontier hash was momentarily
    /// absent.
    pub bounded_rewind_interval_secs: i64,
    /// Consecutive non-advancing ticks at the stuck frontier after which the scan
    /// re-fetches the stuck window via the alternate provider (`<= 0` disables the
    /// alternate-provider recovery).
    pub stuck_gap_alternate_after_ticks: i64,
    /// Consecutive non-advancing ticks at the stuck frontier after which an
    /// indefinite stall is escalated to an operator alert (`<= 0` disables the
    /// alert).
    pub stuck_gap_alert_after_ticks: i64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            confirmation_threshold: super::confirm::DEFAULT_CONFIRMATION_THRESHOLD,
            reorg_window_blocks: SCAN_REORG_WINDOW_BLOCKS,
            max_records_per_iteration: SCAN_MAX_RECORDS_PER_ITERATION,
            pool_max_size: SCAN_CONFIRMATION_POOL_MAX_SIZE,
            tx_cbor_backfill_per_tick: SCAN_TX_CBOR_BACKFILL_PER_TICK,
            bounded_rewind_interval_secs: SCAN_BOUNDED_REWIND_INTERVAL_SECS,
            stuck_gap_alternate_after_ticks: SCAN_STUCK_GAP_ALTERNATE_AFTER_TICKS,
            stuck_gap_alert_after_ticks: SCAN_STUCK_GAP_ALERT_AFTER_TICKS,
        }
    }
}

/// The policy for the scan queue: a singleton loop (one in-flight iteration
/// across the deployment), a single attempt (the handler defers on a storm rather
/// than failing, so it never needs the runtime's retry), a fixed re-enqueue
/// cadence at the active rate, and a long lease covering a full forward fetch
/// plus its commit.
#[must_use]
pub fn scan_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        SCAN_QUEUE,
        1,
        Backoff::Fixed {
            base_secs: SCAN_ACTIVE_POLL_SECS,
        },
        600,
    )
}

/// A schedule that re-seeds the forward-scan loop at the active cadence.
///
/// The loop is self-pacing: the handler defers its own job for the active or
/// idle interval, so while that job is alive every cron tick dedupes against it
/// and enqueues nothing (the scheduler's cron singleton key). The tick is purely
/// a liveness guarantee — it re-seeds the queue within twenty seconds whenever
/// the standing job reaches a terminal state (a non-storm provider failure on
/// the single attempt the policy allows).
#[must_use]
pub fn scan_schedule() -> crate::runtime::scheduler::CronSchedule {
    crate::runtime::scheduler::CronSchedule::new(
        "*/20 * * * * *",
        SCAN_QUEUE,
        serde_json::Value::Null,
    )
}

/// The advisory-lock name the singleton scan handler serializes on, so at most
/// one replica runs an iteration even though every replica runs the cron tick.
///
/// The singleton-loop queue policy already keeps a single iteration in flight,
/// but the handler also takes this session advisory lock for the duration of an
/// iteration as defense in depth: the network phase mutates a shared cursor and
/// the durable pool, and two replicas observing the chain at once (a brief queue
/// race, a misconfigured policy) must never interleave there. A replica that
/// cannot take the lock skips the tick; the holder runs to completion and
/// releases it.
pub const SCAN_ADVISORY_LOCK: &str = "cw_core_chain_scan";

/// One record the plan will write to `chain_records`, with the columns already
/// derived from its validated bytes and whether it was promoted from the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordToPersist {
    /// 32-byte transaction id.
    pub tx_hash: [u8; 32],
    /// The block height the transaction landed in.
    pub block_height: u64,
    /// The block time the transaction landed in.
    pub block_time: DateTime<Utc>,
    /// The verbatim Label 309 metadata CBOR.
    pub metadata_cbor: Vec<u8>,
    /// The full transaction CBOR, when the plan resolved it; `None` persists the
    /// row with a NULL `tx_cbor` the backfill pass repairs later.
    pub tx_cbor: Option<Vec<u8>>,
    /// The indexed columns derived from the record bytes.
    pub columns: ChainRecordColumns,
    /// Whether this record was promoted from the durable pool (so COMMIT deletes
    /// its pool entry) rather than freshly fetched.
    pub from_pool: bool,
}

/// One below-threshold record the plan will add to the durable pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolAdd {
    /// 32-byte transaction id.
    pub tx_hash: [u8; 32],
    /// The block height the transaction landed in.
    pub block_height: u64,
    /// The block time the transaction landed in.
    pub block_time: DateTime<Utc>,
    /// The verbatim Label 309 metadata CBOR, so a re-check promotes the entry
    /// without re-fetching it.
    pub metadata_cbor: Vec<u8>,
    /// The indexed columns derived from the record bytes.
    pub columns: ChainRecordColumns,
}

/// Where the cursor should advance to at the end of an iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorUpdate {
    /// The new scan-frontier block height.
    pub block_height: u64,
    /// The frontier block hash. A productive fetch always carries a real hash so
    /// the next tick's frontier-hash reorg check is armed: a capped batch anchors
    /// at the last record's hash, and a head-reached jump to the tip carries the
    /// tip block's hash (resolved by the network phase). `None` appears only on a
    /// degraded path where the tip block hash could not be resolved AND the batch
    /// returned no records, in which case the cursor is left unchanged rather than
    /// written with a NULL hash (so an earlier real anchor is never overwritten).
    pub block_hash: Option<[u8; 32]>,
    /// `Some` when the frontier block at `block_height` is only PARTIALLY
    /// consumed: the hashes are every transaction within it already indexed,
    /// pooled, or deliberately skipped, and the next fetch re-reads the block
    /// excluding exactly them. `None` (the ordinary case) means the block is
    /// fully consumed and the next fetch resumes strictly above it. This is what
    /// lets the scan page THROUGH a block holding more label-309 transactions
    /// than the per-tick cap instead of stalling on it.
    pub intra_block_done: Option<Vec<[u8; 32]>>,
}

/// The fully-resolved plan the network phase produces.
///
/// Pure data: it captures no database or network handle, so COMMIT replays it in
/// one write transaction deterministically. The durable pool is mutated only
/// inside that transaction, so a rollback leaves the pool, the records, and the
/// cursor in lockstep and the next tick re-derives an equivalent plan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IterationPlan {
    /// When set, COMMIT deletes every `chain_records` row above this height and
    /// purges every pool entry above it (the reorg rewind boundary).
    pub reorg_rewind_from: Option<u64>,
    /// Records to insert (and pool entries to drop for the promoted ones).
    pub records_to_persist: Vec<RecordToPersist>,
    /// Below-threshold records to add to the durable pool.
    pub pool_adds: Vec<PoolAdd>,
    /// Pool entries to delete that were NOT persisted (orphaned by the re-check).
    /// A promoted entry is dropped via its [`RecordToPersist::from_pool`] flag, so
    /// it is never duplicated here.
    pub pool_drop_hashes: Vec<[u8; 32]>,
    /// Where the cursor advances, or `None` to leave it unchanged.
    pub cursor_update: Option<CursorUpdate>,
    /// How COMMIT updates the durable stuck-gap tracking on the cursor row.
    pub stuck_gap_update: StuckGapUpdate,
    /// The iteration outcome the cadence decision and the summary read.
    pub outcome: ScanOutcome,
}

/// How one iteration updates the durable stuck-gap tracking on the cursor row.
///
/// A stuck gap is a frontier height the scan keeps failing to advance past because
/// the answering provider cannot hydrate the transaction sitting there. Tracking
/// it durably (one set of columns on `indexer_cursor`) is what makes an indefinite
/// stall both recoverable (escalate to the alternate provider) and observable
/// (alert once it outlives a threshold) across restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StuckGapUpdate {
    /// The frontier advanced (or there is nothing to track): clear any stuck state.
    #[default]
    Clear,
    /// The frontier did not advance and is not caught up to the tip: it is stuck at
    /// `height`. COMMIT records the height (resetting the counter when it is a new
    /// height) and increments the consecutive-stuck tick count.
    Record {
        /// The frontier height the scan failed to advance past.
        height: u64,
    },
}

/// An operator-visible alert that a stuck gap has outlived its threshold and the
/// global feed is stalled, carried out of the plan so the handler emits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StuckGapAlert {
    /// The frontier height the feed is stalled at.
    pub height: u64,
    /// How many consecutive ticks the frontier has been stuck there.
    pub tick_count: i64,
    /// Whether the alternate-provider recovery was attempted and still failed to
    /// advance the frontier (so neither provider could resolve the gap).
    pub alternate_attempted: bool,
}

/// The plan pieces one forward-fetch result implies, before the stuck-gap decision
/// and the pool-promotion merge layer them in. Shared by the primary fetch and the
/// alternate-provider stuck-gap recovery so both run identical validation and
/// frontier resolution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ProcessedFetch {
    records_to_persist: Vec<RecordToPersist>,
    pool_adds: Vec<PoolAdd>,
    cursor_update: Option<CursorUpdate>,
    records_returned: u64,
    records_persisted: u64,
    reached_chain_head: bool,
}

/// The observable outcome of one scan iteration, for the cadence decision and the
/// summary log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanOutcome {
    /// Whether the iteration left the frontier block only partially consumed
    /// (mid-way through an over-cap block). Live work by definition — the rest
    /// of the block is waiting — so the cadence stays active even on a tick
    /// whose page produced no indexable records.
    pub intra_block_in_progress: bool,
    /// Records the forward fetch returned (before validation/threshold filtering).
    pub records_returned: u64,
    /// Records the plan will persist this iteration.
    pub records_persisted: u64,
    /// The scan frontier the iteration ended at.
    pub last_processed_height: u64,
    /// The tip the iteration saw.
    pub tip_height: u64,
    /// Whether the forward fetch reported reaching the chain head.
    pub reached_chain_head: bool,
    /// Whether this iteration detected a reorg.
    pub reorg_detected: bool,
    /// When every provider in the failover pair was rate-limited this iteration,
    /// the instant the cooldown lifts; `None` otherwise. The handler defers until
    /// this instant rather than failing the iteration.
    pub rate_limited_until: Option<DateTime<Utc>>,
    /// When the scan frontier has been stuck past the alert threshold this
    /// iteration, the alert the handler emits so an indefinite global-feed stall is
    /// never silent; `None` otherwise.
    pub stuck_gap_alert: Option<StuckGapAlert>,
}

/// The reason a startup self-heal rewrote the cursor, for the boot log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfHealReason {
    /// The cursor was consistent; nothing was changed.
    None,
    /// `chain_records` was empty but the cursor had advanced: reset to genesis.
    EmptyChainRecords,
    /// A confirmed record was absent from `chain_records`: rewind below it.
    MissingPublishedRecord,
}

/// The outcome of the startup cursor self-heal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfHealOutcome {
    /// Whether the cursor was rewritten.
    pub healed: bool,
    /// The cursor height before the heal.
    pub previous_height: u64,
    /// Why the heal fired (or [`SelfHealReason::None`]).
    pub reason: SelfHealReason,
}

/// The forward-scan loop's job handler.
///
/// Register it on the runtime against [`SCAN_QUEUE`] with [`scan_policy`] and
/// [`scan_schedule`]. It owns its pool, the chain gateway it scans through, the
/// network it serves, and the tuning config. [`Self::self_heal_cursor`] runs once
/// at process start before the loop begins.
pub struct ScanHandler<G: ChainGateway> {
    pool: sqlx::PgPool,
    gateway: G,
    /// The single network this gateway instance scans. Typed, not a free
    /// string: its stable string keys the durable cursor/tip rows, and its
    /// CIP-19 class is the signature-verification context the signer column is
    /// derived under.
    network: Network,
    config: ScanConfig,
    /// When the bounded periodic rewind last fired (initialised to handler
    /// construction, so a fresh process waits a full interval before its first
    /// backstop re-scan). It need not survive a restart: re-arming the cadence
    /// only delays an idempotent re-scan of the reorg window, never a
    /// correctness hazard.
    last_bounded_rewind: std::sync::Mutex<DateTime<Utc>>,
}

impl<G: ChainGateway> ScanHandler<G> {
    /// Build a scan handler.
    pub fn new(pool: sqlx::PgPool, gateway: G, network: Network, config: ScanConfig) -> Self {
        Self {
            pool,
            gateway,
            network,
            config,
            last_bounded_rewind: std::sync::Mutex::new(Utc::now()),
        }
    }

    /// The network this handler scans.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    // -----------------------------------------------------------------------
    // Startup self-heal
    // -----------------------------------------------------------------------

    /// Repair an inconsistent cursor once at process start, before the loop runs.
    ///
    /// Two corruptions are detected and rewound so the forward scan re-covers the
    /// affected range:
    ///
    /// - **Empty index, advanced cursor.** `chain_records` is empty yet the cursor
    ///   has advanced past genesis (a dropped index left a stale cursor). Reset
    ///   the cursor to 0 for a full re-scan.
    /// - **Confirmed record missing from the index.** A `poe_record` is
    ///   `confirmed` with a block height, yet its transaction is absent from
    ///   `chain_records` (the scan advanced past its block without persisting it).
    ///   Rewind the cursor to one reorg window below the lowest missed block.
    ///
    /// A cursor at or below genesis needs no heal. Idempotent: a second run after
    /// a heal finds the cursor consistent and changes nothing.
    pub async fn self_heal_cursor(&self) -> Result<SelfHealOutcome> {
        let previous_height = match read_cursor(&self.pool, self.network.as_str()).await? {
            Some(cursor) => cursor.last_processed_block_height,
            None => 0,
        };
        if previous_height == 0 {
            return Ok(SelfHealOutcome {
                healed: false,
                previous_height: 0,
                reason: SelfHealReason::None,
            });
        }

        // Case A: the index is empty but the cursor advanced -> reset to genesis.
        if !super::records::any_chain_record_exists(&self.pool).await? {
            self.write_cursor(0, None).await?;
            tracing::warn!(
                network = %self.network.as_str(),
                previous_cursor_height = previous_height,
                new_cursor_height = 0,
                "indexer cursor self-healed at boot: chain_records empty but cursor advanced; reset to genesis for a full re-scan"
            );
            return Ok(SelfHealOutcome {
                healed: true,
                previous_height,
                reason: SelfHealReason::EmptyChainRecords,
            });
        }

        // Case B: a confirmed record whose transaction is absent from the index.
        // The scan must have advanced past its block. Rewind below the lowest such
        // block so the forward scan re-covers the range.
        let missing_height =
            super::records::lowest_missing_confirmed_block_height(&self.pool).await?;
        if let Some(missing_height) = missing_height {
            if missing_height > 0 && missing_height < previous_height {
                let new_height = missing_height.saturating_sub(self.config.reorg_window_blocks);
                self.write_cursor(new_height, None).await?;
                tracing::warn!(
                    network = %self.network.as_str(),
                    previous_cursor_height = previous_height,
                    new_cursor_height = new_height,
                    missing_record_block_height = missing_height,
                    "indexer cursor self-healed at boot: a confirmed record was absent from chain_records; rewound below the missed block"
                );
                return Ok(SelfHealOutcome {
                    healed: true,
                    previous_height,
                    reason: SelfHealReason::MissingPublishedRecord,
                });
            }
        }

        Ok(SelfHealOutcome {
            healed: false,
            previous_height,
            reason: SelfHealReason::None,
        })
    }

    // -----------------------------------------------------------------------
    // PLAN
    // -----------------------------------------------------------------------

    /// Run the network phase and produce the iteration plan.
    ///
    /// All provider traffic happens here, with no transaction open: the
    /// head-of-tick tip refresh, the durable-pool re-check, reorg detection, the
    /// forward fetch with validation, and the cursor-advancement decision. The
    /// returned [`IterationPlan`] is pure data the COMMIT phase replays atomically.
    pub async fn plan_iteration(&self) -> Result<IterationPlan> {
        // Phase 0: head-of-tick tip refresh. The single owner of the /tip read.
        // A rate-limit storm (every provider returned 429) parks the loop with a
        // rate-limited plan: the handler defers until the cooldown lifts, which
        // does not burn the single attempt the queue allows. Any other fetch
        // failure is non-fatal here: fall back to the cached tip row so a missed
        // refresh self-heals next tick instead of killing the loop.
        let tip_height = match self.refresh_tip().await {
            Ok(tip) => tip,
            Err(err) => match rate_limit_storm_until(&err) {
                Some(until) => return Ok(rate_limited_plan(until)),
                None => match super::confirm::read_tip(&self.pool, self.network.as_str()).await? {
                    Some(cached) => cached,
                    None => {
                        // No tip observed yet and none cached: nothing to scan
                        // against.
                        return Ok(IterationPlan::default());
                    }
                },
            },
        };

        let cursor = read_cursor(&self.pool, self.network.as_str())
            .await?
            .unwrap_or_default();

        // Pool re-check, reorg detection, the forward fetch, and validation all
        // live in the helpers below so this body stays the locked phase ordering.
        // A rate-limit storm anywhere in the network phase parks the loop with a
        // rate-limited plan rather than failing the iteration, so a sustained
        // storm never burns the single attempt the queue allows and never mutates
        // state on a tick it could not fully observe.
        match self.build_plan(cursor, tip_height).await {
            Ok(plan) => Ok(plan),
            Err(err) => match rate_limit_storm_until(&err) {
                Some(until) => Ok(rate_limited_plan(until)),
                None => Err(err),
            },
        }
    }

    /// Assemble the plan from the cursor and the refreshed tip: re-check the
    /// durable pool, then either short-circuit (caught up), detect a reorg, or run
    /// the forward fetch and decide cursor advancement.
    async fn build_plan(&self, cursor: Cursor, tip_height: u64) -> Result<IterationPlan> {
        let last_height = cursor.last_processed_block_height;
        // A non-empty durable exclusion set means the frontier block itself is
        // only partially consumed (it holds more label-309 transactions than one
        // window): the fetch must re-read that block minus the set, and the
        // caught-up short-circuit must not fire while it has known un-consumed
        // work at exactly the cursor height.
        let resume_done: Option<&[[u8; 32]]> = cursor
            .intra_block_done
            .as_deref()
            .filter(|done| !done.is_empty());

        // Bounded periodic rewind: on a cadence, re-cover the last
        // `reorg_window_blocks` when the frontier sits near the tip, even when the
        // frontier-hash check would pass or is disarmed (a NULL-hash frontier right
        // after a reorg rewind). This catches a near-tip reorg that landed during a
        // window where the frontier hash could not arm the per-tick check. It runs
        // before the caught-up short-circuit so it still fires in the steady state
        // (frontier at the tip), which is exactly where reorgs happen.
        if let Some(plan) = self.bounded_rewind_plan(last_height, tip_height) {
            return Ok(plan);
        }

        // Pool re-check is independent of the forward fetch: it re-derives the
        // confirmation of every held entry against the fresh tip and decides
        // promote/drop/keep, so an in-flight record settles even on a caught-up
        // tick.
        let (pool_persist, pool_drop_hashes) = self.recheck_pool(tip_height).await?;

        // Caught-up short-circuit: the cursor has reached the tip, so there is no
        // forward fetch this tick. Still persist any pool promotions and leave the
        // cursor unchanged. A partially-consumed frontier block never
        // short-circuits: its remainder sits AT the cursor height, so the fetch
        // must run even when no block above it exists yet.
        if last_height >= tip_height && resume_done.is_none() {
            return Ok(IterationPlan {
                reorg_rewind_from: None,
                records_to_persist: pool_persist.clone(),
                pool_adds: Vec::new(),
                pool_drop_hashes,
                cursor_update: None,
                // Caught up to the tip: the feed is not stalled, so clear any stuck
                // tracking.
                stuck_gap_update: StuckGapUpdate::Clear,
                outcome: ScanOutcome {
                    intra_block_in_progress: false,
                    records_returned: 0,
                    records_persisted: pool_persist.len() as u64,
                    last_processed_height: last_height,
                    tip_height,
                    reached_chain_head: true,
                    reorg_detected: false,
                    rate_limited_until: None,
                    stuck_gap_alert: None,
                },
            });
        }

        // Reorg detection: only when the cursor carries a stored hash and is
        // within the rewind window of the tip. Re-fetch the frontier block and
        // compare its hash; a mismatch or a failed fetch is a reorg.
        if let Some(stored_hash) = cursor.last_processed_block_hash {
            if tip_height.saturating_sub(last_height) < self.config.reorg_window_blocks {
                let chain_hash = self
                    .gateway
                    .get_block_info(last_height)
                    .await?
                    .map(|info| info.block_hash);
                if chain_hash != Some(stored_hash) {
                    let rewind_from = last_height.saturating_sub(self.config.reorg_window_blocks);
                    tracing::warn!(
                        network = %self.network.as_str(),
                        previous_height = last_height,
                        rewind_from,
                        "indexer detected a reorg at the scan frontier; rewinding"
                    );
                    // Discard any pool promotions planned this tick: they sat on
                    // the invalidated branch. The reorg purge in COMMIT removes the
                    // pool entries above the rewind boundary directly.
                    return Ok(IterationPlan {
                        reorg_rewind_from: Some(rewind_from),
                        records_to_persist: Vec::new(),
                        pool_adds: Vec::new(),
                        pool_drop_hashes: Vec::new(),
                        // The rewind clears any intra-block exclusion set along
                        // with the records it accounted for: the re-scan covers
                        // the whole window from scratch on the surviving branch.
                        cursor_update: Some(CursorUpdate {
                            block_height: rewind_from,
                            block_hash: None,
                            intra_block_done: None,
                        }),
                        // A reorg rewinds the cursor and re-covers the window: any
                        // prior stuck state no longer applies.
                        stuck_gap_update: StuckGapUpdate::Clear,
                        outcome: ScanOutcome {
                            intra_block_in_progress: false,
                            records_returned: 0,
                            records_persisted: 0,
                            last_processed_height: rewind_from,
                            tip_height,
                            reached_chain_head: false,
                            reorg_detected: true,
                            rate_limited_until: None,
                            stuck_gap_alert: None,
                        },
                    });
                }
            }
        }

        // Forward fetch: the Label 309 records above the cursor, by count. A
        // partially-consumed frontier block re-reads from just below itself with
        // its durable exclusion set, so the fetch returns exactly the block's
        // remainder (plus anything above); an ordinary fetch reads strictly above
        // the cursor with no exclusions.
        let (fetch_after, exclude): (u64, &[[u8; 32]]) = match resume_done {
            Some(done) => (last_height.saturating_sub(1), done),
            None => (last_height, &[]),
        };
        let fetched = self
            .gateway
            .fetch_label309_records_since(
                fetch_after,
                exclude,
                tip_height,
                self.config.max_records_per_iteration,
            )
            .await?;
        let mut processed = self
            .process_forward_fetch(
                last_height,
                tip_height,
                resume_done,
                cursor.last_processed_block_hash,
                fetched,
            )
            .await?;

        // Stuck-gap recovery + observability. The frontier "advanced" when the
        // cursor moved forward; it is "caught up" when the provider had nothing
        // more up to its watermark. A tick that neither advanced nor caught up is
        // STUCK: the answering provider cannot hydrate the transaction at the
        // frontier, and re-running the same provider would stall the whole feed
        // forever. Escalate to the ALTERNATE provider, and, past a threshold, alert.
        let advanced = processed.cursor_update.is_some();
        let mut alternate_attempted = false;
        if !advanced && !processed.reached_chain_head {
            // Consecutive ticks the frontier will have been stuck if this one does
            // not recover: the stored count plus this tick (reset when the stuck
            // height changed since last tick).
            let same_height = cursor.stuck_gap_height == Some(last_height);
            let prospective_ticks = if same_height {
                cursor.stuck_gap_tick_count + 1
            } else {
                1
            };

            // ALTERNATE-PROVIDER RECOVERY: once the stall has persisted to the
            // configured threshold, re-fetch the SAME window via the other provider.
            // A provider-specific hydration failure must not halt the whole feed
            // when the other provider can resolve the stuck height.
            if self.config.stuck_gap_alternate_after_ticks > 0
                && prospective_ticks >= self.config.stuck_gap_alternate_after_ticks
            {
                alternate_attempted = true;
                if let Ok(alt) = self
                    .gateway
                    .fetch_label309_records_since_alternate(
                        fetch_after,
                        exclude,
                        tip_height,
                        self.config.max_records_per_iteration,
                    )
                    .await
                {
                    let alt_processed = self
                        .process_forward_fetch(
                            last_height,
                            tip_height,
                            resume_done,
                            cursor.last_processed_block_hash,
                            alt,
                        )
                        .await?;
                    // Adopt the alternate result only when it actually ADVANCES the
                    // cursor (real progress past the gap). A `cursor_update` is only
                    // ever produced for a forward move, so its presence is the proof
                    // of progress; `reached_chain_head` alone is NOT — the alternate
                    // being at its own tip with the gap still un-hydrated below the
                    // cursor advances nothing and would falsely clear the stall.
                    // Keeping the primary result there leaves the stall recorded and
                    // alertable until a provider truly resolves the gap.
                    if alt_processed.cursor_update.is_some() {
                        tracing::info!(
                            network = %self.network.as_str(),
                            stuck_height = last_height,
                            "indexer recovered a stuck scan gap via the alternate provider"
                        );
                        processed = alt_processed;
                    }
                }
            }
        }

        // Re-derive progress after a possible alternate recovery, and build the
        // durable stuck-gap update + any operator alert. The cursor ADVANCING is the
        // only proof the feed is moving: a `cursor_update` is produced solely for a
        // forward move. `reached_chain_head` alone is NOT progress — a provider
        // whose own metadata watermark sits at or below the cursor while the real
        // tip is higher reports caught-up-to-its-watermark yet advances nothing, and
        // that is exactly the lagging-provider stall that must stay tracked and
        // alertable, never falsely cleared.
        let advanced = processed.cursor_update.is_some();
        let (stuck_gap_update, stuck_gap_alert) = if advanced {
            // The cursor moved forward: the feed is making progress, so clear any
            // stuck tracking.
            (StuckGapUpdate::Clear, None)
        } else {
            let same_height = cursor.stuck_gap_height == Some(last_height);
            let tick_count = if same_height {
                cursor.stuck_gap_tick_count + 1
            } else {
                1
            };
            // Alert EXACTLY when the stall first crosses the threshold, not on every
            // tick at or beyond it: the count resets to 1 when the gap resolves and
            // a new stall begins, so a fresh stall re-alerts, but a single persistent
            // stall fires the operator alert once rather than spamming every tick.
            let alert = if self.config.stuck_gap_alert_after_ticks > 0
                && tick_count == self.config.stuck_gap_alert_after_ticks
            {
                Some(StuckGapAlert {
                    height: last_height,
                    tick_count,
                    alternate_attempted,
                })
            } else {
                None
            };
            (
                StuckGapUpdate::Record {
                    height: last_height,
                },
                alert,
            )
        };

        let new_height = processed
            .cursor_update
            .as_ref()
            .map_or(last_height, |update| update.block_height);
        let intra_block_in_progress = processed
            .cursor_update
            .as_ref()
            .is_some_and(|update| update.intra_block_done.is_some());

        // Pool promotions (re-checked against the fresh tip earlier) persist
        // regardless of which provider answered the forward fetch, so they ride the
        // same plan as the freshly-fetched records.
        let mut records_to_persist = pool_persist;
        records_to_persist.extend(processed.records_to_persist);
        let records_persisted = records_to_persist.len() as u64;

        Ok(IterationPlan {
            reorg_rewind_from: None,
            records_to_persist,
            pool_adds: processed.pool_adds,
            pool_drop_hashes,
            cursor_update: processed.cursor_update,
            stuck_gap_update,
            outcome: ScanOutcome {
                intra_block_in_progress,
                records_returned: processed.records_returned,
                records_persisted,
                last_processed_height: new_height,
                tip_height,
                reached_chain_head: processed.reached_chain_head,
                reorg_detected: false,
                rate_limited_until: None,
                stuck_gap_alert,
            },
        })
    }

    /// Turn one forward-fetch result into the plan pieces it implies: the records
    /// to persist (validated + tx-cbor-resolved), the below-threshold pool adds, and
    /// the cursor advance derived from the fetch's safe frontier. Shared by the
    /// primary fetch and the alternate-provider stuck-gap recovery so both go
    /// through identical validation and frontier resolution.
    ///
    /// `resume_done` is the durable exclusion set when the cursor block is only
    /// partially consumed (the fetch ran with those hashes excluded), and
    /// `resume_anchor` is that cursor's stored block hash — the anchor a
    /// completion flip re-writes when the provider proves the block finished at
    /// exactly the cursor height.
    async fn process_forward_fetch(
        &self,
        last_height: u64,
        tip_height: u64,
        resume_done: Option<&[[u8; 32]]>,
        resume_anchor: Option<[u8; 32]>,
        fetched: super::gateway::Label309RecordsResult,
    ) -> Result<ProcessedFetch> {
        let super::gateway::Label309RecordsResult {
            records: fetched_records,
            frontier,
        } = fetched;
        let mut records_to_persist: Vec<RecordToPersist> = Vec::new();
        let mut pool_adds: Vec<PoolAdd> = Vec::new();
        let mut tx_cbor_wanted: Vec<[u8; 32]> = Vec::new();

        for record in &fetched_records {
            // An invalid record is skipped (not persisted, not pooled): a
            // malformed transaction never enters the index with fabricated
            // columns. The derivation runs under this scan's configured network
            // so the signer column holds only a key whose signature verified.
            let columns = match derive_chain_record_columns(&record.metadata_cbor, self.network) {
                Ok(columns) => columns,
                Err(_) => {
                    tracing::debug!(
                        network = %self.network.as_str(),
                        block_height = record.block_height,
                        "indexer dropped a record: metadata is not a valid Label 309 record"
                    );
                    continue;
                }
            };
            if record.num_confirmations < self.config.confirmation_threshold {
                // Below threshold: hold it in the durable pool for a later tick.
                pool_adds.push(PoolAdd {
                    tx_hash: record.tx_hash,
                    block_height: record.block_height,
                    block_time: record.block_time,
                    metadata_cbor: record.metadata_cbor.clone(),
                    columns,
                });
            } else {
                tx_cbor_wanted.push(record.tx_hash);
                records_to_persist.push(RecordToPersist {
                    tx_hash: record.tx_hash,
                    block_height: record.block_height,
                    block_time: record.block_time,
                    metadata_cbor: record.metadata_cbor.clone(),
                    tx_cbor: None,
                    columns,
                    from_pool: false,
                });
            }
        }

        // Resolve the full transaction bytes for the fresh persist candidates in
        // one batched call. A failure leaves them NULL; the backfill repairs them.
        if !tx_cbor_wanted.is_empty() {
            let cbor_by_hash = self
                .gateway
                .fetch_tx_cbor_by_hashes(&tx_cbor_wanted)
                .await
                .unwrap_or_default();
            for record in &mut records_to_persist {
                if !record.from_pool {
                    record.tx_cbor = cbor_by_hash.get(&record.tx_hash).cloned();
                }
            }
        }

        // Resolve where the cursor advances from the fetch's safe frontier. An
        // intra-block frontier anchors AT the partially-consumed block and grows
        // its durable exclusion set (see [`intra_block_cursor_update`]). A
        // caught-up frontier jumps the cursor to `min(tip, provider watermark)` —
        // never past what the answering provider can actually see — anchored with
        // that block's real hash so the next tick's reorg check stays armed; a
        // gap/cap anchor advances to the highest proven-complete block with its own
        // hash; a hold leaves the cursor where it was. A caught-up jump needs the
        // target block's hash, fetched once here. If that hash cannot be resolved,
        // the frontier falls back to the highest emitted record's own hash (a real
        // anchor at or below the watermark) rather than disarming the frontier with
        // a NULL hash; with no records to anchor on either, the cursor is left
        // unchanged. The capped/anchor frontier carries its own hash and needs no
        // tip read.
        let cursor_update = if let ChainScanFrontier::IntraBlock {
            height,
            block_hash,
            consumed_no_record,
        } = &frontier
        {
            intra_block_cursor_update(
                last_height,
                resume_done,
                *height,
                *block_hash,
                &fetched_records,
                consumed_no_record,
            )
        } else {
            let caught_up_target = match &frontier {
                ChainScanFrontier::CaughtUpTo { indexed_to } => Some((*indexed_to).min(tip_height)),
                _ => None,
            };
            let caught_up_block_hash = match caught_up_target {
                // Only read the target block's hash when the jump would actually move
                // the cursor forward: a target at or below the cursor needs no read.
                Some(target) if target > last_height => self
                    .gateway
                    .get_block_info(target)
                    .await
                    .ok()
                    .flatten()
                    .map(|info| info.block_hash),
                _ => None,
            };
            let last_record_anchor = fetched_records
                .last()
                .map(|last| (last.block_height, last.block_hash));

            cursor_advancement(
                last_height,
                &frontier,
                tip_height,
                caught_up_block_hash,
                last_record_anchor,
                resume_done.and(resume_anchor),
            )
        };
        let records_returned = fetched_records.len() as u64;
        let records_persisted = records_to_persist.len() as u64;
        let reached_chain_head = matches!(frontier, ChainScanFrontier::CaughtUpTo { .. });

        Ok(ProcessedFetch {
            records_to_persist,
            pool_adds,
            cursor_update,
            records_returned,
            records_persisted,
            reached_chain_head,
        })
    }

    /// Re-check every durable-pool entry against the fresh tip: promote the ones
    /// that have now crossed the threshold (returned as persist records flagged
    /// `from_pool`), and drop the ones a fresh gateway lookup shows have left the
    /// chain (returned as drop hashes). An entry still below threshold and still on
    /// chain is left in place.
    ///
    /// A promotion candidate (an entry that has crossed the threshold by the
    /// arithmetic `tip - block_height + 1`) is verified against chain truth before
    /// it is promoted: a freshly-crossed entry is still inside the reorg window, so
    /// arithmetic alone could promote a transaction that a reorg has already
    /// removed. The fresh `get_tx_confirmations` lookup is bounded to exactly the
    /// promotion candidates (entries still below threshold stay pooled with no
    /// lookup), so the no-API-key budget only pays for entries actually leaving the
    /// pool. A candidate the gateway reports gone is dropped; a candidate whose
    /// lookup could not be resolved this tick stays pooled and retries next tick,
    /// so a reorged-out entry is never promoted on a failed or absent lookup.
    async fn recheck_pool(&self, tip_height: u64) -> Result<(Vec<RecordToPersist>, Vec<[u8; 32]>)> {
        let entries = load_pool_entries(&self.pool).await?;
        let threshold = self.config.confirmation_threshold;

        // Partition the pool into promotion candidates (crossed the threshold
        // arithmetically) and the rest (still below threshold, left pooled).
        let candidates: Vec<PoolEntry> = entries
            .into_iter()
            .filter(|entry| {
                tip_height >= entry.block_height
                    && tip_height.saturating_sub(entry.block_height) + 1 >= threshold
            })
            .collect();
        if candidates.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        // Before promoting, verify each candidate against chain truth: a freshly
        // threshold-crossed entry is still within the reorg window, so a reorg
        // could have removed it after it was pooled. A gone candidate is dropped;
        // an unresolved one stays pooled.
        let hashes: Vec<[u8; 32]> = candidates.iter().map(|entry| entry.tx_hash).collect();
        let confirmations = self.gateway.get_tx_confirmations(&hashes).await?;

        let mut promote = Vec::new();
        let mut drop_hashes = Vec::new();
        for entry in candidates {
            match confirmations.get(&entry.tx_hash) {
                // Still on chain: promote it (the gateway's block coordinates are
                // authoritative for a re-included tx, falling back to the pooled
                // coordinates when the lookup did not carry them).
                Some(conf) if conf.block_height.is_some() => {
                    let columns = ChainRecordColumns {
                        signer_ed25519: entry.signer_ed25519,
                        verified_signers: entry.verified_signers,
                        item_count: entry.item_count,
                        scheme: entry.scheme,
                    };
                    promote.push(RecordToPersist {
                        tx_hash: entry.tx_hash,
                        block_height: conf.block_height.unwrap_or(entry.block_height),
                        block_time: conf.block_time.unwrap_or(entry.block_time),
                        metadata_cbor: entry.metadata_cbor,
                        tx_cbor: None,
                        columns,
                        from_pool: true,
                    });
                }
                // Reported gone (not on chain): a reorg removed it after it was
                // pooled. Drop it instead of promoting a vanished transaction.
                Some(_) => {
                    tracing::warn!(
                        network = %self.network.as_str(),
                        block_height = entry.block_height,
                        "indexer dropped a pooled record: a fresh lookup shows it is no longer on chain"
                    );
                    drop_hashes.push(entry.tx_hash);
                }
                // No answer for this hash this tick: leave it pooled and retry
                // next tick rather than promote on an unresolved lookup.
                None => {}
            }
        }
        Ok((promote, drop_hashes))
    }

    /// The bounded periodic rewind: on a wall-clock cadence, when the frontier
    /// sits within the reorg window of the tip, return a plan that re-covers the
    /// last `reorg_window_blocks`. Returns `None` when the interval has not
    /// elapsed since the last firing, when the cadence is disabled
    /// (`interval <= 0`), or when the frontier is more than a reorg window below
    /// the tip (the ordinary forward scan re-covers that range and re-anchors a
    /// real frontier hash before it nears the tip).
    ///
    /// This is the backstop for a near-tip reorg that the per-tick frontier-hash
    /// check could miss because the frontier hash was momentarily absent (right
    /// after a reorg rewind). Forcing a window re-scan re-anchors a real frontier
    /// hash and re-arms the per-tick check. The cadence is measured in elapsed
    /// time, never iterations, so it stays at its configured rate no matter how
    /// the loop's re-enqueue pacing shifts between the active, idle, and
    /// immediate-resume cadences. Two consecutive ticks can therefore never both
    /// fire it.
    fn bounded_rewind_plan(&self, last_height: u64, tip_height: u64) -> Option<IterationPlan> {
        let interval = self.config.bounded_rewind_interval_secs;
        if interval <= 0 {
            return None;
        }
        // Only near the tip: a frontier well below the tip is re-covered by the
        // ordinary forward scan, which re-anchors a real hash, so a forced rewind
        // there would be pure churn. Checked before the cadence so a deep
        // catch-up never consumes the interval; the backstop fires as soon as the
        // scan is both near the tip and due.
        if tip_height.saturating_sub(last_height) >= self.config.reorg_window_blocks {
            return None;
        }
        {
            let now = Utc::now();
            let mut last = self
                .last_bounded_rewind
                .lock()
                .expect("bounded-rewind instant lock poisoned");
            if now.signed_duration_since(*last) < chrono::Duration::seconds(interval) {
                return None;
            }
            *last = now;
        }
        let rewind_from = last_height.saturating_sub(self.config.reorg_window_blocks);
        tracing::info!(
            network = %self.network.as_str(),
            previous_height = last_height,
            rewind_from,
            "indexer running a bounded periodic rewind of the reorg window"
        );
        Some(IterationPlan {
            reorg_rewind_from: Some(rewind_from),
            records_to_persist: Vec::new(),
            pool_adds: Vec::new(),
            pool_drop_hashes: Vec::new(),
            cursor_update: Some(CursorUpdate {
                block_height: rewind_from,
                block_hash: None,
                intra_block_done: None,
            }),
            // The bounded rewind moves the cursor back to re-cover the window: clear
            // any stuck tracking so it is re-derived from the rewound frontier.
            stuck_gap_update: StuckGapUpdate::Clear,
            outcome: ScanOutcome {
                intra_block_in_progress: false,
                records_returned: 0,
                records_persisted: 0,
                last_processed_height: rewind_from,
                tip_height,
                reached_chain_head: false,
                reorg_detected: true,
                rate_limited_until: None,
                stuck_gap_alert: None,
            },
        })
    }

    /// Refresh the chain tip: read it once and upsert the materialised row with a
    /// monotonic GREATEST so a behind-the-times observation cannot regress it. The
    /// single `/tip` read carries the epoch alongside the height, so both are
    /// materialised here and the protocol-parameter populate loop reads the epoch
    /// from that row instead of making its own `/tip` call.
    ///
    /// Returns the MATERIALISED (monotonic) height, never the raw observation, so a
    /// stale fallback `/tip` or a momentarily regressed provider tip can never make
    /// the scan look caught-up: the cursor is always compared against the highest
    /// tip ever seen.
    async fn refresh_tip(&self) -> Result<u64> {
        let tip = self.gateway.get_tip().await?;
        super::confirm::upsert_tip(
            &self.pool,
            self.network.as_str(),
            tip.block_height,
            tip.epoch,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // COMMIT (and the durable-pool APPLY folded into it)
    // -----------------------------------------------------------------------

    /// Run the plan in one write transaction: the reorg delete and purge, the
    /// record inserts and pool-entry drops, the new pool adds, and the cursor
    /// advance. The pool mutations ride the same transaction as the records and
    /// the cursor, so an abort leaves all three in lockstep.
    pub async fn commit_plan(&self, plan: &IterationPlan) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        if let Some(rewind_from) = plan.reorg_rewind_from {
            // Reorg: delete the invalidated chain_records rows and purge the pool
            // entries above the rewind boundary, both inside this transaction.
            super::records::reorg_delete_above_in_tx(&mut *tx, rewind_from).await?;
            delete_pool_above_in_tx(&mut *tx, rewind_from).await?;
        }

        for record in &plan.records_to_persist {
            super::records::insert_chain_record_in_tx(
                &mut tx,
                record.tx_hash,
                record.block_height,
                record.block_time,
                &record.metadata_cbor,
                record.tx_cbor.as_deref(),
                &record.columns,
            )
            .await?;
            // A promoted entry's pool row is deleted now that it is persisted.
            if record.from_pool {
                delete_pool_entry_in_tx(&mut *tx, record.tx_hash).await?;
            }
        }

        // Drop the orphaned (non-persisted) pool entries the re-check flagged.
        for hash in &plan.pool_drop_hashes {
            delete_pool_entry_in_tx(&mut *tx, *hash).await?;
        }

        // Add the fresh below-threshold entries, then evict down to the cap.
        for add in &plan.pool_adds {
            insert_pool_entry_in_tx(&mut *tx, add).await?;
        }
        if !plan.pool_adds.is_empty() {
            let evicted = evict_pool_to_cap_in_tx(&mut *tx, self.config.pool_max_size).await?;
            if evicted > 0 {
                tracing::warn!(
                    network = %self.network.as_str(),
                    evicted,
                    cap = self.config.pool_max_size,
                    "confirmation pool reached its cap; evicted the oldest entries"
                );
            }
        }

        if let Some(update) = &plan.cursor_update {
            write_cursor_in_tx(
                &mut *tx,
                self.network.as_str(),
                update.block_height,
                update.block_hash,
                update.intra_block_done.as_deref(),
            )
            .await?;
        }

        // Apply the durable stuck-gap tracking after the cursor write (so a `Clear`
        // runs against the freshly-advanced row, and a `Record` upserts the row when
        // none exists yet at a genesis stall).
        write_stuck_gap_in_tx(&mut *tx, self.network.as_str(), plan.stuck_gap_update).await?;

        tx.commit().await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // BACKFILL
    // -----------------------------------------------------------------------

    /// Repair a bounded batch of `chain_records` rows that were inserted without
    /// their full transaction bytes.
    ///
    /// Selects the oldest rows with a NULL `tx_cbor`, fetches their bytes in one
    /// batched call, and writes each under a `tx_cbor IS NULL` guard. Never throws:
    /// a provider failure leaves the rows NULL for the next tick. Returns how many
    /// rows it filled.
    pub async fn backfill_tx_cbor(&self) -> Result<u64> {
        let pending = super::records::tx_cbor_backfill_candidates(
            &self.pool,
            self.config.tx_cbor_backfill_per_tick,
        )
        .await?;
        if pending.is_empty() {
            return Ok(0);
        }
        let cbor_by_hash = match self.gateway.fetch_tx_cbor_by_hashes(&pending).await {
            Ok(map) => map,
            Err(_) => {
                // tx_cbor is enrichment, never load-bearing for the index: a fetch
                // failure leaves the rows NULL and the next tick retries.
                tracing::warn!(
                    network = %self.network.as_str(),
                    candidate_count = pending.len(),
                    "tx_cbor backfill fetch failed; rows stay NULL for the next tick"
                );
                return Ok(0);
            }
        };
        let mut filled = 0u64;
        for hash in &pending {
            if let Some(cbor) = cbor_by_hash.get(hash) {
                if super::records::update_tx_cbor_backfill(&self.pool, *hash, cbor).await? {
                    filled += 1;
                }
            }
        }
        Ok(filled)
    }

    // -----------------------------------------------------------------------
    // Cadence
    // -----------------------------------------------------------------------

    /// Decide the next re-enqueue delay from an iteration's outcome: resume at
    /// once on a reorg, run the active cadence while there is live work (records
    /// indexed, a non-empty pool, or a record awaiting confirmation), and the idle
    /// cadence once caught up with nothing in flight.
    async fn next_delay_secs(&self, outcome: &ScanOutcome) -> Result<i64> {
        if outcome.reorg_detected {
            return Ok(0);
        }
        let indexed = outcome.records_returned > 0;
        let pool_non_empty = pool_count(&self.pool).await? > 0;
        let pending = has_pending_submitted_record(&self.pool, self.network.as_str()).await?;
        // A partially-consumed frontier block is live work by definition — the
        // rest of the block is waiting — even on a page that produced no
        // indexable records (all no-record consumptions).
        if indexed || pool_non_empty || pending || outcome.intra_block_in_progress {
            Ok(i64::from(SCAN_ACTIVE_POLL_SECS))
        } else {
            Ok(SCAN_IDLE_POLL_SECS)
        }
    }

    /// Run one full iteration: plan, commit, then backfill. Used by the handler
    /// and by integration tests that drive the loop directly. Returns the outcome
    /// the cadence decision reads.
    pub async fn run_iteration(&self) -> Result<ScanOutcome> {
        let plan = self.plan_iteration().await?;
        self.commit_plan(&plan).await?;
        // A stuck gap that has outlived its threshold (the alternate provider could
        // not resolve it either) is escalated to an operator-visible error-level
        // event so an indefinite global-feed stall is never silent. Error level so
        // the observability pipeline captures it as an alert; the structured fields
        // give the operator the stuck height and how long it has held.
        if let Some(alert) = plan.outcome.stuck_gap_alert {
            tracing::error!(
                network = %self.network.as_str(),
                stuck_gap_height = alert.height,
                stuck_gap_tick_count = alert.tick_count,
                alternate_provider_attempted = alert.alternate_attempted,
                "indexer scan frontier is stuck: a Label 309 transaction at this height \
                 cannot be hydrated by either provider, stalling the global records feed; \
                 the cursor is held below the gap so no record is lost, but delivery of \
                 every record above it is blocked until the gap resolves"
            );
        }
        // Backfill after the commit so a slow tx_cbor fetch never holds up cursor
        // advancement; it never throws so a failure cannot fail the iteration.
        let _ = self.backfill_tx_cbor().await?;
        Ok(plan.outcome)
    }

    // -----------------------------------------------------------------------
    // Cursor write helpers
    // -----------------------------------------------------------------------

    /// Upsert the cursor row outside a transaction (the self-heal path). A heal
    /// always rewinds to a fully-consumed frontier, so any partial-consumption
    /// state is cleared along with it.
    async fn write_cursor(&self, height: u64, hash: Option<[u8; 32]>) -> Result<()> {
        write_cursor_in_tx(&self.pool, self.network.as_str(), height, hash, None).await
    }
}

impl<G: ChainGateway + 'static> JobHandler for ScanHandler<G> {
    async fn handle(&self, _ctx: JobContext) -> JobOutcome {
        // Defense in depth over the singleton-loop queue policy: hold the scan
        // advisory lock for the whole iteration so two replicas can never
        // interleave the cursor/pool mutations the network phase performs. A
        // replica that does not get the lock skips this tick; the holder runs.
        let lock =
            match crate::runtime::locks::AdvisoryLock::try_acquire(&self.pool, SCAN_ADVISORY_LOCK)
                .await
            {
                Ok(Some(lock)) => lock,
                // Another replica holds the lock and is mid-iteration: this tick is a
                // no-op. The cron re-fires the loop, so nothing is lost.
                Ok(None) => return JobOutcome::Complete,
                Err(e) => {
                    return JobOutcome::Fail {
                        error: crate::runtime::JobError::new("scan_lock_failed", e.to_string()),
                    };
                }
            };

        let outcome = self.run_iteration().await;
        // Release the lock (closing its detached connection) before returning so
        // the next tick on this or another replica can take it promptly.
        let _ = lock.release().await;

        match outcome {
            Ok(outcome) => match outcome.rate_limited_until {
                // An all-provider 429 storm defers until the cooldown lifts,
                // which does not burn the single attempt the queue allows.
                Some(until) => JobOutcome::Defer { until },
                None => match self.next_delay_secs(&outcome).await {
                    Ok(secs) => JobOutcome::Defer {
                        until: Utc::now() + chrono::Duration::seconds(secs),
                    },
                    Err(e) => JobOutcome::Fail {
                        error: crate::runtime::JobError::new("scan_cadence_failed", e.to_string()),
                    },
                },
            },
            Err(e) => JobOutcome::Fail {
                error: crate::runtime::JobError::new("scan_iteration_failed", e.to_string()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Rate-limit storm (pure)
// ---------------------------------------------------------------------------

/// The instant a rate-limit storm parks the scan until, or `None` when the error
/// is not a storm.
///
/// A [`crate::Error::ChainRateLimitStorm`] (every provider in the failover pair
/// rate-limiting us) carries the instant the soonest provider cooldown lifts: the
/// scan parks until exactly that instant, which never burns the single attempt
/// the queue allows. A database error or any other provider failure
/// mid-iteration is `None`: a real failure that must surface, never be silently
/// parked.
#[must_use]
fn rate_limit_storm_until(error: &crate::Error) -> Option<DateTime<Utc>> {
    match error {
        crate::Error::ChainRateLimitStorm { cooldown_until } => Some(*cooldown_until),
        _ => None,
    }
}

/// The plan a rate-limit storm produces: no mutations, the cooldown instant set so
/// the handler defers until the storm clears.
///
/// The storm parks the loop on a tick it could not fully observe, so it carries
/// no records, no pool changes, and no cursor advance: nothing is mutated, and
/// the next tick re-derives an equivalent plan once the storm clears.
#[must_use]
fn rate_limited_plan(until: DateTime<Utc>) -> IterationPlan {
    IterationPlan {
        outcome: ScanOutcome {
            rate_limited_until: Some(until),
            ..ScanOutcome::default()
        },
        ..IterationPlan::default()
    }
}

// ---------------------------------------------------------------------------
// Cursor advancement (pure)
// ---------------------------------------------------------------------------

/// Decide where the cursor advances after a forward fetch, from the safe frontier
/// the answering provider reported.
///
/// The cursor records the SCAN frontier (the highest block whose Label 309
/// contents the scan has PROVEN both fully indexed and fully hydrated), not the
/// highest persisted record. It never advances past a height the answering
/// provider could not see or a hydration gap could not clear, so a lagging
/// provider or an un-hydrated transaction is a re-tried barrier, never a permanent
/// skip. A productive advance always leaves the frontier carrying a real block
/// hash so the next tick's reorg check is armed; the frontier is only ever left at
/// a NULL hash by a reorg rewind (handled elsewhere), never by a normal advance.
///
/// - [`ChainScanFrontier::CaughtUpTo`]: the provider has no more records up to its
///   own metadata watermark. The frontier jumps to `min(tip, indexed_to)` — never
///   past what the provider can actually see — anchored with that block's real
///   hash (`caught_up_block_hash`, resolved by the network phase). When that hash
///   could not be resolved, the frontier falls back to the highest emitted record
///   (`last_record_anchor`: a real anchor at or below the watermark) rather than
///   disarming the frontier with a NULL hash. When the jump target is at or below
///   the current cursor, or there is no record to fall back on either, the cursor
///   is left unchanged so it never regresses and an earlier real anchor is never
///   overwritten with NULL.
/// - [`ChainScanFrontier::Anchor`]: a capped window, a split boundary block, or a
///   hydration-gap clamp. The frontier advances to the anchor (its own real hash)
///   only when it moves the cursor forward; otherwise it holds.
/// - [`ChainScanFrontier::Hold`]: no safe height this fetch; the cursor is left
///   unchanged and the next tick re-fetches the same window.
/// - [`ChainScanFrontier::IntraBlock`] never reaches this function — the network
///   phase resolves it through [`intra_block_cursor_update`], which also needs
///   the fetched records and the prior exclusion set. Passed anyway (a provider
///   defect), it holds the cursor rather than corrupt the frontier.
///
/// `resume_anchor` is `Some` (carrying the cursor's stored block hash) when the
/// cursor block is only partially consumed and the fetch ran with its exclusion
/// set. In that state a frontier that proves the block finished at EXACTLY the
/// cursor height — an anchor at it, or a caught-up watermark reaching it — is a
/// real advance: it flips the block to fully consumed (clearing the exclusion
/// set) even though the height does not move, so a completed boundary block can
/// never be re-fetched forever.
#[must_use]
pub fn cursor_advancement(
    last_height: u64,
    frontier: &ChainScanFrontier,
    tip_height: u64,
    caught_up_block_hash: Option<[u8; 32]>,
    last_record_anchor: Option<(u64, [u8; 32])>,
    resume_anchor: Option<[u8; 32]>,
) -> Option<CursorUpdate> {
    match *frontier {
        ChainScanFrontier::CaughtUpTo { indexed_to } => {
            let target = indexed_to.min(tip_height);
            // Advance forward only, with a real anchor hash. Prefer the target
            // block's own hash; if it could not be resolved, fall back to the
            // highest emitted record's hash (still at or below the watermark) so
            // the frontier stays armed rather than going NULL.
            if target > last_height {
                if let Some(hash) = caught_up_block_hash {
                    return Some(CursorUpdate {
                        block_height: target,
                        block_hash: Some(hash),
                        intra_block_done: None,
                    });
                }
            }
            // A partially-consumed cursor block whose watermark reached it is
            // COMPLETE: the provider listed the block and had nothing new beyond
            // the exclusions. Flip it to fully consumed at its stored anchor so
            // the exclusion set is retired instead of re-fetched forever.
            if target == last_height {
                if let Some(anchor) = resume_anchor {
                    return Some(CursorUpdate {
                        block_height: last_height,
                        block_hash: Some(anchor),
                        intra_block_done: None,
                    });
                }
            }
            // Either the jump did not move the cursor, or the target hash was
            // unavailable: fall back to anchoring at the highest emitted record,
            // but only when it advances the cursor forward.
            match last_record_anchor {
                Some((height, block_hash)) if height > last_height => Some(CursorUpdate {
                    block_height: height,
                    block_hash: Some(block_hash),
                    intra_block_done: None,
                }),
                _ => None,
            }
        }
        ChainScanFrontier::Anchor { height, block_hash } => {
            // Advance to the anchor only when it moves the cursor forward; a
            // gap-clamp at or below the cursor holds. One exception: an anchor at
            // EXACTLY a partially-consumed cursor block completes that block (the
            // provider proved it fully resolved through its height), flipping it
            // to fully consumed.
            if height > last_height {
                Some(CursorUpdate {
                    block_height: height,
                    block_hash: Some(block_hash),
                    intra_block_done: None,
                })
            } else if height == last_height && resume_anchor.is_some() {
                Some(CursorUpdate {
                    block_height: last_height,
                    block_hash: Some(block_hash),
                    intra_block_done: None,
                })
            } else {
                None
            }
        }
        ChainScanFrontier::Hold => None,
        // Resolved by `intra_block_cursor_update` in the network phase; a stray
        // arrival here holds the cursor (safe: the next tick re-fetches).
        ChainScanFrontier::IntraBlock { .. } => None,
    }
}

/// Decide the cursor update for an intra-block frontier: the boundary block at
/// `height` holds more label-309 transactions than one window, so the cursor
/// anchors AT it and the durable exclusion set grows by everything this fetch
/// consumed — the emitted records (indexed or pooled this commit, and equally
/// the ones scan-level validation rejects: consumed-as-invalid, or they would be
/// re-fetched forever) plus the provider-reported no-record consumptions.
///
/// Continuing the SAME partial block merges into the prior exclusion set; a NEW
/// boundary block (the cursor moved up to it) starts a fresh set — the old
/// block's hashes can never be listed again from above it. The set is
/// deduplicated and sorted so the durable row is deterministic. A defective
/// fetch that grew nothing (every "consumed" hash already excluded) reports no
/// progress, so the stuck-gap machinery — not a busy loop of idempotent
/// re-writes — owns that pathology; a frontier below the cursor never regresses
/// it.
#[must_use]
pub fn intra_block_cursor_update(
    last_height: u64,
    prior_done: Option<&[[u8; 32]]>,
    height: u64,
    block_hash: [u8; 32],
    fetched_records: &[super::gateway::Label309Record],
    consumed_no_record: &[[u8; 32]],
) -> Option<CursorUpdate> {
    if height < last_height {
        return None;
    }
    let mut done: std::collections::BTreeSet<[u8; 32]> = if height == last_height {
        prior_done.unwrap_or_default().iter().copied().collect()
    } else {
        std::collections::BTreeSet::new()
    };
    let before = done.len();
    done.extend(
        fetched_records
            .iter()
            .filter(|r| r.block_height == height)
            .map(|r| r.tx_hash),
    );
    done.extend(consumed_no_record.iter().copied());
    if done.len() == before {
        return None;
    }
    Some(CursorUpdate {
        block_height: height,
        block_hash: Some(block_hash),
        intra_block_done: Some(done.into_iter().collect()),
    })
}

// ---------------------------------------------------------------------------
// Cursor + pool DB access
// ---------------------------------------------------------------------------

/// The durable scan-frontier cursor for one network.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Cursor {
    last_processed_block_height: u64,
    last_processed_block_hash: Option<[u8; 32]>,
    /// `Some` when the frontier block is only PARTIALLY consumed: the
    /// transactions within it already indexed, pooled, or deliberately skipped.
    /// The next fetch re-reads the block excluding exactly them. `None` means
    /// the block is fully consumed (the ordinary state).
    intra_block_done: Option<Vec<[u8; 32]>>,
    /// The frontier height the scan is currently stuck at (cannot advance past),
    /// or `None` when the scan is making progress.
    stuck_gap_height: Option<u64>,
    /// How many consecutive non-advancing ticks the frontier has been stuck.
    stuck_gap_tick_count: i64,
}

/// Read the cursor row for a network, or `None` when none exists yet.
async fn read_cursor(pool: &sqlx::PgPool, network: &str) -> Result<Option<Cursor>> {
    type CursorRow = (i64, Option<String>, Option<Vec<Vec<u8>>>, Option<i64>, i64);
    let row: Option<CursorRow> = sqlx::query_as(
        "SELECT last_processed_block_height, last_processed_block_hash, \
                intra_block_done_tx_hashes, stuck_gap_height, stuck_gap_tick_count \
         FROM cw_core.indexer_cursor WHERE network = $1",
    )
    .bind(network)
    .fetch_optional(pool)
    .await?;
    let Some((height, hash_hex, done_rows, stuck_height, stuck_ticks)) = row else {
        return Ok(None);
    };
    let last_processed_block_height = u64::try_from(height.max(0)).unwrap_or(0);
    let last_processed_block_hash = match hash_hex {
        Some(hex_str) => Some(parse_block_hash(&hex_str)?),
        None => None,
    };
    // An empty stored set is normalised to "fully consumed": partial state is
    // only ever written with at least one consumed transaction.
    let intra_block_done = match done_rows.filter(|done| !done.is_empty()) {
        Some(done) => Some(
            done.iter()
                .map(|bytes| {
                    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                        crate::Error::Config("cursor intra-block tx hash must be 32 bytes".into())
                    })
                })
                .collect::<Result<Vec<[u8; 32]>>>()?,
        ),
        None => None,
    };
    let stuck_gap_height = stuck_height.map(|h| u64::try_from(h.max(0)).unwrap_or(0));
    Ok(Some(Cursor {
        last_processed_block_height,
        last_processed_block_hash,
        intra_block_done,
        stuck_gap_height,
        stuck_gap_tick_count: stuck_ticks.max(0),
    }))
}

/// Upsert the cursor row for a network inside a caller-supplied executor. The
/// block hash is stored lowercase hex so reorg detection compares like for like.
/// The intra-block exclusion set rides the same write, so the frontier height,
/// its hash, and the partial-consumption state can never drift apart.
async fn write_cursor_in_tx<'e, E>(
    executor: E,
    network: &str,
    height: u64,
    hash: Option<[u8; 32]>,
    intra_block_done: Option<&[[u8; 32]]>,
) -> Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    let height =
        i64::try_from(height).map_err(|_| crate::Error::Config("cursor height overflow".into()))?;
    let hash_hex = hash.map(hex::encode);
    let done_rows: Option<Vec<Vec<u8>>> =
        intra_block_done.map(|done| done.iter().map(|h| h.to_vec()).collect());
    sqlx::query(
        "INSERT INTO cw_core.indexer_cursor \
           (network, last_processed_block_height, last_processed_block_hash, \
            intra_block_done_tx_hashes, updated_at) \
         VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (network) DO UPDATE SET \
           last_processed_block_height = EXCLUDED.last_processed_block_height, \
           last_processed_block_hash = EXCLUDED.last_processed_block_hash, \
           intra_block_done_tx_hashes = EXCLUDED.intra_block_done_tx_hashes, \
           updated_at = now()",
    )
    .bind(network)
    .bind(height)
    .bind(hash_hex)
    .bind(done_rows)
    .execute(executor)
    .await?;
    Ok(())
}

/// Apply a [`StuckGapUpdate`] to the cursor row's stuck-gap tracking inside a
/// transaction. `Clear` nulls the tracking (the frontier advanced); `Record`
/// either starts tracking a new stuck height (count 1, first-seen now) or, when the
/// height is unchanged, increments the consecutive-stuck tick count. The cursor row
/// always exists by the time this runs (the scan reads or seeds it first), so this
/// only ever UPDATEs.
async fn write_stuck_gap_in_tx<'e, E>(
    executor: E,
    network: &str,
    update: StuckGapUpdate,
) -> Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    match update {
        StuckGapUpdate::Clear => {
            sqlx::query(
                "UPDATE cw_core.indexer_cursor SET \
                   stuck_gap_height = NULL, \
                   stuck_gap_first_seen_at = NULL, \
                   stuck_gap_tick_count = 0 \
                 WHERE network = $1",
            )
            .bind(network)
            .execute(executor)
            .await?;
        }
        StuckGapUpdate::Record { height } => {
            let height = i64::try_from(height)
                .map_err(|_| crate::Error::Config("stuck gap height overflow".into()))?;
            // Upsert so a stall at the genesis frontier (no cursor row yet) still
            // accumulates a tick count and can alert: the row is created at the stuck
            // frontier height with a NULL hash (the cursor has not advanced), and on
            // conflict the stuck tracking is updated. A NEW stuck height resets the
            // counter to 1 and stamps first-seen; the SAME height increments the
            // consecutive count and keeps first-seen. The CASE keys off whether the
            // stored stuck height already equals this one. `last_processed_*` is left
            // untouched on conflict — the cursor never advances on a stuck tick.
            sqlx::query(
                "INSERT INTO cw_core.indexer_cursor \
                   (network, last_processed_block_height, last_processed_block_hash, \
                    stuck_gap_height, stuck_gap_first_seen_at, stuck_gap_tick_count, updated_at) \
                 VALUES ($1, $2, NULL, $2, now(), 1, now()) \
                 ON CONFLICT (network) DO UPDATE SET \
                   stuck_gap_height = $2, \
                   stuck_gap_first_seen_at = CASE \
                     WHEN cw_core.indexer_cursor.stuck_gap_height IS DISTINCT FROM $2 THEN now() \
                     ELSE COALESCE(cw_core.indexer_cursor.stuck_gap_first_seen_at, now()) \
                   END, \
                   stuck_gap_tick_count = CASE \
                     WHEN cw_core.indexer_cursor.stuck_gap_height IS DISTINCT FROM $2 THEN 1 \
                     ELSE cw_core.indexer_cursor.stuck_gap_tick_count + 1 \
                   END, \
                   updated_at = now()",
            )
            .bind(network)
            .bind(height)
            .execute(executor)
            .await?;
        }
    }
    Ok(())
}

/// A durable confirmation-pool entry as loaded for the re-check pass.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PoolEntry {
    tx_hash: [u8; 32],
    block_height: u64,
    block_time: DateTime<Utc>,
    metadata_cbor: Vec<u8>,
    signer_ed25519: Option<[u8; 32]>,
    /// The full verified-signer set, carried so a promotion writes the signer-set
    /// rows without re-verifying. Empty for an unsigned record.
    verified_signers: Vec<[u8; 32]>,
    item_count: u32,
    scheme: u8,
}

/// Load every durable-pool entry for the re-check pass, oldest-first.
async fn load_pool_entries(pool: &sqlx::PgPool) -> Result<Vec<PoolEntry>> {
    let rows: Vec<PoolEntryRow> = sqlx::query_as(
        "SELECT tx_hash, block_height, block_time, metadata_cbor, signer_ed25519, signer_set, item_count, scheme \
         FROM cw_core.confirmation_pool ORDER BY first_seen_at",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(PoolEntry::try_from).collect()
}

/// The number of entries currently in the durable pool.
async fn pool_count(pool: &sqlx::PgPool) -> Result<i64> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.confirmation_pool")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Whether any `poe_record` is still awaiting confirmation. Drives the active vs
/// idle cadence: while a record is in flight the scan stays active so the cached
/// tip stays fresh for the confirm loop's live counter.
async fn has_pending_submitted_record(pool: &sqlx::PgPool, _network: &str) -> Result<bool> {
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM cw_core.poe_record WHERE status = 'submitted')",
    )
    .fetch_one(pool)
    .await?;
    Ok(pending)
}

/// Insert one below-threshold entry into the durable pool inside a transaction.
/// `ON CONFLICT (tx_hash) DO NOTHING` keeps a re-observed record's original
/// first-seen time so eviction order stays stable.
async fn insert_pool_entry_in_tx<'e, E>(executor: E, add: &PoolAdd) -> Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    let block_height = i64::try_from(add.block_height)
        .map_err(|_| crate::Error::Config("block height overflow".into()))?;
    let item_count = i32::try_from(add.columns.item_count)
        .map_err(|_| crate::Error::Config("item count overflow".into()))?;
    let signer_set: Vec<&[u8]> = add
        .columns
        .verified_signers
        .iter()
        .map(<[u8; 32]>::as_slice)
        .collect();
    sqlx::query(
        "INSERT INTO cw_core.confirmation_pool \
           (tx_hash, block_height, block_time, metadata_cbor, signer_ed25519, signer_set, item_count, scheme) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (tx_hash) DO NOTHING",
    )
    .bind(add.tx_hash.as_slice())
    .bind(block_height)
    .bind(add.block_time)
    .bind(&add.metadata_cbor)
    .bind(
        add.columns
            .signer_ed25519
            .as_ref()
            .map(<[u8; 32]>::as_slice),
    )
    .bind(signer_set.as_slice())
    .bind(item_count)
    .bind(i16::from(add.columns.scheme))
    .execute(executor)
    .await?;
    Ok(())
}

/// Delete one durable-pool entry by hash inside a transaction (a promotion or an
/// orphan drop).
async fn delete_pool_entry_in_tx<'e, E>(executor: E, tx_hash: [u8; 32]) -> Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("DELETE FROM cw_core.confirmation_pool WHERE tx_hash = $1")
        .bind(tx_hash.as_slice())
        .execute(executor)
        .await?;
    Ok(())
}

/// Purge every durable-pool entry above a reorg rewind boundary inside a
/// transaction. Their block heights now point at the invalidated branch.
async fn delete_pool_above_in_tx<'e, E>(executor: E, rewind_from: u64) -> Result<u64>
where
    E: sqlx::PgExecutor<'e>,
{
    let rewind_from = i64::try_from(rewind_from)
        .map_err(|_| crate::Error::Config("rewind height overflow".into()))?;
    let affected = sqlx::query("DELETE FROM cw_core.confirmation_pool WHERE block_height > $1")
        .bind(rewind_from)
        .execute(executor)
        .await?
        .rows_affected();
    Ok(affected)
}

/// Evict the oldest durable-pool entries until the pool is within `cap`, inside a
/// transaction. Returns how many were evicted.
async fn evict_pool_to_cap_in_tx<'e, E>(executor: E, cap: i64) -> Result<u64>
where
    E: sqlx::PgExecutor<'e>,
{
    let affected = sqlx::query(
        "DELETE FROM cw_core.confirmation_pool \
         WHERE tx_hash IN ( \
           SELECT tx_hash FROM cw_core.confirmation_pool \
           ORDER BY first_seen_at DESC OFFSET $1 \
         )",
    )
    .bind(cap)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(affected)
}

/// Parse a lowercase-hex block hash from the cursor into 32 bytes.
fn parse_block_hash(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| crate::Error::Config(format!("cursor block hash is not hex: {e}")))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| crate::Error::Config("cursor block hash must be 32 bytes".into()))
}

/// The raw pool row shape, mapped onto [`PoolEntry`] in one place.
#[derive(sqlx::FromRow)]
struct PoolEntryRow {
    tx_hash: Vec<u8>,
    block_height: i64,
    block_time: DateTime<Utc>,
    metadata_cbor: Vec<u8>,
    signer_ed25519: Option<Vec<u8>>,
    signer_set: Vec<Vec<u8>>,
    item_count: i32,
    scheme: i16,
}

impl TryFrom<PoolEntryRow> for PoolEntry {
    type Error = crate::Error;

    fn try_from(row: PoolEntryRow) -> Result<Self> {
        let tx_hash = <[u8; 32]>::try_from(row.tx_hash.as_slice())
            .map_err(|_| crate::Error::Config("pool tx_hash is not 32 bytes".into()))?;
        let signer_ed25519 = match row.signer_ed25519 {
            Some(bytes) => Some(
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| crate::Error::Config("pool signer key is not 32 bytes".into()))?,
            ),
            None => None,
        };
        let mut verified_signers = row
            .signer_set
            .iter()
            .map(|bytes| {
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| crate::Error::Config("pool signer-set key is not 32 bytes".into()))
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        // Defense in depth: if a row carries a scalar primary signer but an empty
        // set (a row written by a path that set only the scalar), seed the set
        // from the scalar so the promoted record is never invisible to a signer
        // query.
        if verified_signers.is_empty() {
            if let Some(primary) = signer_ed25519 {
                verified_signers.push(primary);
            }
        }
        Ok(PoolEntry {
            tx_hash,
            block_height: u64::try_from(row.block_height.max(0)).unwrap_or(0),
            block_time: row.block_time,
            metadata_cbor: row.metadata_cbor,
            signer_ed25519,
            verified_signers,
            item_count: u32::try_from(row.item_count.max(0)).unwrap_or(0),
            scheme: u8::try_from(row.scheme.clamp(0, 2)).unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_policy_is_a_single_attempt_singleton_loop() {
        let policy = scan_policy();
        assert_eq!(policy.queue, SCAN_QUEUE);
        assert_eq!(
            policy.policy,
            crate::runtime::policy::QueuePolicyKind::SingletonLoop
        );
        // One attempt: a 429 storm defers (which does not consume an attempt)
        // rather than failing the loop.
        assert_eq!(policy.max_attempts, 1);
        assert_eq!(policy.lease_secs, 600);
    }

    #[test]
    fn scan_schedule_targets_the_scan_queue() {
        let schedule = scan_schedule();
        assert_eq!(schedule.queue, SCAN_QUEUE);
    }

    #[test]
    fn default_config_uses_the_documented_thresholds() {
        let c = ScanConfig::default();
        assert_eq!(c.confirmation_threshold, 15);
        assert_eq!(c.reorg_window_blocks, 30);
        assert_eq!(c.max_records_per_iteration, 200);
        assert_eq!(c.pool_max_size, 1000);
        assert_eq!(c.tx_cbor_backfill_per_tick, 50);
        assert_eq!(c.bounded_rewind_interval_secs, 3000);
    }

    #[test]
    fn caught_up_jumps_to_the_provider_watermark_clamped_by_the_tip() {
        // A caught-up frontier jumps the cursor to min(tip, indexed_to) with the
        // target block's real hash so reorg detection stays armed.
        let hash = [0x77_u8; 32];
        // Watermark above the tip: clamped to the tip.
        let update = cursor_advancement(
            100,
            &ChainScanFrontier::CaughtUpTo { indexed_to: 99_999 },
            12_345,
            Some(hash),
            None,
            None,
        )
        .expect("an update");
        assert_eq!(
            update.block_height, 12_345,
            "the caught-up frontier clamps to the tip when the watermark is higher"
        );
        assert_eq!(update.block_hash, Some(hash));
        assert_eq!(update.intra_block_done, None);
    }

    #[test]
    fn caught_up_never_advances_past_the_provider_watermark() {
        // The provider's own metadata watermark sits BELOW the externally-observed
        // tip (the lag case). The cursor must jump only to the watermark, never the
        // tip, so the lag gap is re-read next tick rather than skipped forever.
        let hash = [0x55_u8; 32];
        let update = cursor_advancement(
            100,
            &ChainScanFrontier::CaughtUpTo { indexed_to: 5_000 },
            12_345,
            Some(hash),
            None,
            None,
        )
        .expect("an update");
        assert_eq!(
            update.block_height, 5_000,
            "the cursor clamps to the answering provider's watermark, not the tip"
        );
        assert_eq!(update.block_hash, Some(hash));
    }

    #[test]
    fn caught_up_at_or_below_the_cursor_leaves_it_unchanged() {
        // A watermark/tip at or below the cursor (a lagging fallback tip, an empty
        // page) never regresses the cursor and never disarms its hash.
        assert_eq!(
            cursor_advancement(
                500,
                &ChainScanFrontier::CaughtUpTo { indexed_to: 500 },
                500,
                Some([0x01; 32]),
                None,
                None,
            ),
            None
        );
        assert_eq!(
            cursor_advancement(
                500,
                &ChainScanFrontier::CaughtUpTo { indexed_to: 400 },
                450,
                Some([0x01; 32]),
                None,
                None,
            ),
            None,
            "a regressed tip below the cursor never moves it"
        );
    }

    #[test]
    fn caught_up_without_a_target_hash_falls_back_to_the_last_record_anchor() {
        // The jump target's block hash could not be resolved this tick: rather than
        // disarm the frontier with a NULL hash, anchor at the highest emitted record
        // (a real anchor at or below the watermark) so the frontier stays armed.
        let last = [0x44_u8; 32];
        let update = cursor_advancement(
            100,
            &ChainScanFrontier::CaughtUpTo { indexed_to: 9_999 },
            9_999,
            None,
            Some((300, last)),
            None,
        )
        .expect("an update via the last-record fallback");
        assert_eq!(
            update.block_height, 300,
            "with no target hash the frontier falls back to the highest record"
        );
        assert_eq!(update.block_hash, Some(last));
    }

    #[test]
    fn caught_up_without_a_hash_or_a_record_leaves_the_cursor_unchanged() {
        // No target-block hash AND no emitted record to fall back on: hold the
        // cursor rather than disarm the frontier with a NULL hash.
        assert_eq!(
            cursor_advancement(
                100,
                &ChainScanFrontier::CaughtUpTo { indexed_to: 9_999 },
                9_999,
                None,
                None,
                None,
            ),
            None
        );
    }

    #[test]
    fn anchor_advances_to_the_anchor_block_with_its_hash() {
        // A capped or gap-clamped window anchors at its highest proven-complete
        // block, carrying that block's real hash.
        let hash = [0x22_u8; 32];
        let update = cursor_advancement(
            100,
            &ChainScanFrontier::Anchor {
                height: 205,
                block_hash: hash,
            },
            99_999,
            None,
            None,
            None,
        )
        .expect("an update");
        assert_eq!(
            update.block_height, 205,
            "the frontier anchors at the block"
        );
        assert_eq!(update.block_hash, Some(hash));
    }

    #[test]
    fn anchor_at_or_below_the_cursor_holds() {
        // A gap clamp at or below the cursor never regresses it.
        assert_eq!(
            cursor_advancement(
                205,
                &ChainScanFrontier::Anchor {
                    height: 205,
                    block_hash: [0x22; 32]
                },
                99_999,
                None,
                None,
                None,
            ),
            None
        );
    }

    #[test]
    fn hold_leaves_the_cursor_unchanged() {
        // No safe height this fetch: the cursor holds and the next tick re-reads.
        assert_eq!(
            cursor_advancement(
                500,
                &ChainScanFrontier::Hold,
                9_999,
                Some([0x01; 32]),
                Some((9_000, [0x02; 32])),
                None,
            ),
            None
        );
    }

    #[test]
    fn a_productive_anchor_or_caught_up_always_carries_a_real_hash() {
        // Every advancing frontier must carry a real hash so the next tick's reorg
        // check is armed; the frontier is only left NULL by a reorg rewind.
        let advancing = [
            (
                ChainScanFrontier::Anchor {
                    height: 410,
                    block_hash: [0x41; 32],
                },
                None,
            ),
            (
                ChainScanFrontier::CaughtUpTo { indexed_to: 410 },
                Some([0xbb; 32]),
            ),
        ];
        for (frontier, caught_up_hash) in advancing {
            let update = cursor_advancement(100, &frontier, 99_999, caught_up_hash, None, None)
                .expect("a productive frontier advances the cursor");
            assert!(
                update.block_hash.is_some(),
                "a productive advance must never write a NULL hash: {frontier:?}"
            );
        }
    }

    #[test]
    fn a_completed_boundary_block_flips_to_fully_consumed_at_its_own_height() {
        // The cursor sits mid-block (a durable exclusion set exists). A frontier
        // proving the block finished at EXACTLY the cursor height — an anchor at
        // it, or a caught-up watermark reaching it — must flip it to fully
        // consumed (clearing the set) even though the height does not move;
        // otherwise a finished boundary block would be re-fetched forever.
        let stored = [0xaa_u8; 32];
        let anchored = cursor_advancement(
            700,
            &ChainScanFrontier::Anchor {
                height: 700,
                block_hash: stored,
            },
            9_999,
            None,
            None,
            Some(stored),
        )
        .expect("an anchor at the partial cursor block completes it");
        assert_eq!(anchored.block_height, 700);
        assert_eq!(anchored.block_hash, Some(stored));
        assert_eq!(
            anchored.intra_block_done, None,
            "completion retires the exclusion set"
        );

        let caught_up = cursor_advancement(
            700,
            &ChainScanFrontier::CaughtUpTo { indexed_to: 700 },
            700,
            None,
            None,
            Some(stored),
        )
        .expect("a watermark reaching the partial cursor block completes it");
        assert_eq!(caught_up.block_height, 700);
        assert_eq!(caught_up.block_hash, Some(stored));
        assert_eq!(caught_up.intra_block_done, None);

        // A watermark BELOW the partial block proves nothing about it: the
        // provider's index has not reached the block, so it must not complete.
        assert_eq!(
            cursor_advancement(
                700,
                &ChainScanFrontier::CaughtUpTo { indexed_to: 600 },
                9_999,
                None,
                None,
                Some(stored),
            ),
            None
        );
    }

    #[test]
    fn intra_block_update_starts_a_fresh_set_for_a_new_boundary_block() {
        // The cursor was fully consumed at 100; the fetch overflowed at block 205:
        // the update anchors AT 205 with exactly this fetch's consumed hashes (no
        // stale carry-over from any earlier block).
        let hash_a = [0x01_u8; 32];
        let hash_b = [0x02_u8; 32];
        let records = vec![test_record(hash_a, 205, [0x99; 32])];
        let update = intra_block_cursor_update(100, None, 205, [0x99; 32], &records, &[hash_b])
            .expect("a first intra-block page advances the cursor to the block");
        assert_eq!(update.block_height, 205);
        assert_eq!(update.block_hash, Some([0x99; 32]));
        let done = update.intra_block_done.expect("a partial-block set");
        assert_eq!(done.len(), 2, "records AND no-record consumptions join");
        assert!(done.contains(&hash_a) && done.contains(&hash_b));
    }

    #[test]
    fn intra_block_update_merges_into_the_prior_set_when_continuing_the_same_block() {
        // A later page of the SAME boundary block merges with the durable set (and
        // dedupes), so no consumed transaction is ever re-fetched.
        let prior = [[0x01_u8; 32], [0x02; 32]];
        let new_record = test_record([0x03; 32], 205, [0x99; 32]);
        let update = intra_block_cursor_update(
            205,
            Some(&prior),
            205,
            [0x99; 32],
            std::slice::from_ref(&new_record),
            &[[0x02; 32]],
        )
        .expect("a continuing page still records progress");
        let done = update.intra_block_done.expect("a partial-block set");
        assert_eq!(done.len(), 3, "the prior set merges and dedupes");
    }

    #[test]
    fn intra_block_update_without_growth_or_below_the_cursor_reports_no_progress() {
        // Every "consumed" hash was already excluded: no growth, no progress —
        // the stuck-gap machinery owns that pathology rather than a busy loop of
        // idempotent cursor re-writes. A frontier below the cursor never
        // regresses it.
        let prior = [[0x01_u8; 32]];
        assert_eq!(
            intra_block_cursor_update(205, Some(&prior), 205, [0x99; 32], &[], &[[0x01; 32]]),
            None
        );
        assert_eq!(
            intra_block_cursor_update(300, None, 299, [0x99; 32], &[], &[[0x05; 32]]),
            None
        );
    }

    /// A minimal fetched record for the intra-block cursor tests.
    fn test_record(
        tx_hash: [u8; 32],
        block_height: u64,
        block_hash: [u8; 32],
    ) -> super::super::gateway::Label309Record {
        super::super::gateway::Label309Record {
            tx_hash,
            block_hash,
            block_height,
            block_time: chrono::Utc::now(),
            num_confirmations: 1,
            metadata_cbor: Vec::new(),
        }
    }

    #[test]
    fn self_heal_reasons_are_distinct() {
        // The three reasons are distinct discriminants the boot log branches on.
        assert_ne!(SelfHealReason::None, SelfHealReason::EmptyChainRecords);
        assert_ne!(
            SelfHealReason::EmptyChainRecords,
            SelfHealReason::MissingPublishedRecord
        );
    }

    /// Zero-knowledge guard: the scan and single-writer sources, and the
    /// migration's indexer blocks, must never name a recipient/identity/secret
    /// concept. The on-chain index is zero-knowledge about who a sealed record was
    /// addressed to; a forbidden term in this executable code or its schema would
    /// be a privacy regression (a recipient or identity field leaking into the
    /// index). Scans the COMMENT-STRIPPED source so a word in prose (for example
    /// the doc-comment explaining what is forbidden) does not trip the guard;
    /// only code tokens count.
    #[test]
    fn scan_sources_and_migration_carry_no_recipient_or_identity_vocabulary() {
        use std::path::Path;

        // The recipient/identity/secret vocabulary the on-chain index must never
        // name. These are the genuine privacy-leak terms: a recipient pubkey, a
        // per-user/identity correlator, a sealed-envelope key, or seed material.
        // They are forbidden everywhere this guard scans (the indexer code AND the
        // schema that defines the index tables).
        const PRIVACY_LEAK_WORDS: &[&str] = &[
            "recipient",
            "user_id",
            "identity_id",
            "x25519_pubkey",
            "slot_match",
            "match_hint",
            "cek",
            "kek",
            "priv",
            "seed",
        ];

        // `account_id` and `wallet`/`wallet_id` are additionally forbidden in the
        // indexer SOURCE: the scan and single-writer code must stay zero-knowledge,
        // so they never touch account-tenancy or wallet-funding state even though
        // those columns legitimately exist elsewhere. They are NOT forbidden in the
        // chain-table migrations, where `poe_record.account_id` and the
        // `chain_attempt` wallet-funding columns are legitimate structural
        // references, so the migration scan checks only the privacy-leak words.
        const SOURCE_ONLY_FORBIDDEN_WORDS: &[&str] = &["account_id", "wallet"];

        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));

        // The indexer source files: privacy-leak words plus the source-only
        // tenancy/wallet words apply.
        let source_files = [
            manifest.join("src/chain/scan.rs"),
            manifest.join("src/chain/records.rs"),
        ];
        // Every migration that defines or alters the on-chain-index / chain-effect
        // tables. Globbed (not a fixed list) so a future migration touching these
        // tables is scanned automatically and cannot silently introduce
        // recipient/identity vocabulary into the index schema.
        let migration_files = chain_table_migrations(&manifest.join("migrations"));
        assert!(
            migration_files
                .iter()
                .any(|p| p.ends_with("0001_baseline_schema.sql")),
            "the chain-table migration glob must include the baseline schema that \
             defines chain_records / chain_scan / chain_attempt"
        );

        let scan_one = |path: &std::path::Path, words: &[&str]| {
            let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
                panic!(
                    "reading {} for the zero-knowledge guard: {e}",
                    path.display()
                )
            });
            // Scan only the production code: the `#[cfg(test)]` module (this very
            // guard, whose forbidden-words list is itself made of the words it
            // forbids) is test-only, never shipped, and must not self-trip.
            let production = raw.split("#[cfg(test)]").next().unwrap_or(&raw);
            let code = strip_comments(production, path);
            let lower = code.to_ascii_lowercase();

            for word in words {
                assert!(
                    !contains_whole_word(&lower, word),
                    "forbidden term {word:?} appears in the comment-stripped code of {}; the on-chain \
                     index must stay zero-knowledge about recipients and identities",
                    path.display()
                );
            }

            // An age1-prefixed bech32 recipient address literal (age1 followed by
            // bech32 characters). The on-chain index never stores or names one.
            assert!(
                !contains_age1_recipient(&lower),
                "an age1 recipient address literal appears in the comment-stripped code of {}",
                path.display()
            );
        };

        for path in &source_files {
            let mut words: Vec<&str> = PRIVACY_LEAK_WORDS.to_vec();
            words.extend_from_slice(SOURCE_ONLY_FORBIDDEN_WORDS);
            scan_one(path, &words);
        }
        for path in &migration_files {
            scan_one(path, PRIVACY_LEAK_WORDS);
        }
    }

    /// Every migration file that defines or alters an on-chain-index / chain-effect
    /// table the zero-knowledge guard must scan. Matched by name marker so a new
    /// migration touching these tables is picked up without editing the guard.
    ///
    /// The chain-effect ledger (`chain_attempt`) and the on-chain index
    /// (`chain_records`, the scan cursor/pool) are the tables that must stay
    /// recipient/identity-free. They are defined in the baseline schema, so its
    /// file is always matched; the additional markers keep any future
    /// chain-table migration whose name carries `chain_records`, `chain_scan`, or
    /// `chain_attempt` in scope automatically.
    #[cfg(test)]
    fn chain_table_migrations(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        const MARKERS: &[&str] = &[
            "baseline_schema",
            "chain_records",
            "chain_scan",
            "chain_attempt",
        ];
        let mut out: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("reading migrations dir {}: {e}", dir.display()))
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                name.ends_with(".sql") && MARKERS.iter().any(|m| name.contains(m))
            })
            .collect();
        out.sort();
        out
    }

    /// Strip line and block comments so the forbidden-vocab scan sees only code
    /// tokens. Rust sources use `//` and `/* */`; the SQL migration uses `--`.
    /// String contents are kept (a forbidden term in a SQL identifier or a Rust
    /// string literal must still trip the guard); only comment spans are removed.
    fn strip_comments(src: &str, path: &std::path::Path) -> String {
        let is_sql = path.extension().and_then(|e| e.to_str()) == Some("sql");
        let mut out = String::with_capacity(src.len());
        for line in src.lines() {
            let stripped = if is_sql {
                line.split("--").next().unwrap_or("")
            } else {
                // Drop a `//` line comment. Block comments in these files only ever
                // appear as the module-level doc banner (`//!`), already covered by
                // the `//` split, so a dedicated block-comment scanner is not needed.
                line.split("//").next().unwrap_or("")
            };
            out.push_str(stripped);
            out.push('\n');
        }
        out
    }

    /// Whether `haystack` contains `needle` as a whole word (delimited by a
    /// non-`[a-z0-9_]` boundary on each side), so a substring inside a larger
    /// identifier (for example `private` containing `priv`, or `keksomething`)
    /// does not falsely match.
    fn contains_whole_word(haystack: &str, needle: &str) -> bool {
        let bytes = haystack.as_bytes();
        let n = needle.as_bytes();
        if n.is_empty() {
            return false;
        }
        let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let mut i = 0;
        while let Some(pos) = haystack[i..].find(needle) {
            let start = i + pos;
            let end = start + n.len();
            let before_ok = start == 0 || !is_word(bytes[start - 1]);
            let after_ok = end >= bytes.len() || !is_word(bytes[end]);
            if before_ok && after_ok {
                return true;
            }
            i = start + 1;
        }
        false
    }

    /// Whether the (lowercased) code contains an `age1`-prefixed bech32 recipient
    /// address literal: `age1` immediately followed by at least one bech32
    /// character. The literal word `age1` with no bech32 tail (it never appears)
    /// would not match.
    fn contains_age1_recipient(haystack: &str) -> bool {
        let bytes = haystack.as_bytes();
        let mut i = 0;
        while let Some(pos) = haystack[i..].find("age1") {
            let start = i + pos;
            let tail = start + 4;
            if bytes
                .get(tail)
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            {
                return true;
            }
            i = start + 1;
        }
        false
    }
}
