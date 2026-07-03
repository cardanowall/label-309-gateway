//! Postgres-backed coverage for the forward-scan indexer (the scan schema and
//! the `ScanHandler` loop), plus the zero-knowledge column manifests.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! The schema half asserts the migration applies cleanly, `chain_records`
//! carries its nullable `tx_cbor` column, the durable cursor and pool tables
//! exist with their primary keys, the read-feed indexes exist, and, as the
//! zero-knowledge guard's schema half, the exact column manifest of each indexer
//! table carries no recipient/identity/secret column.
//!
//! The behavioural half drives the real `ScanHandler` against a SCRIPTED chain
//! gateway with programmable per-tick forward-fetch responses, asserting the
//! locked PLAN -> COMMIT -> APPLY -> BACKFILL semantics through their durable
//! side effects (the `chain_records`, `indexer_cursor`, and `confirmation_pool`
//! rows and the iteration outcome), never log strings:
//!
//! - A clean genesis scan anchors the cursor at the last record of a capped batch,
//!   then jumps to the tip with a null hash once it reaches the chain head.
//! - An invalid record is skipped: it never reaches `chain_records` or the pool.
//! - A below-threshold record enters the durable pool, then a later tick promotes
//!   it to `chain_records` once it crosses the threshold.
//! - A reorg at the scan frontier (a frontier-hash mismatch) deletes the records
//!   above the rewind boundary, purges the pool above it, and the re-scan
//!   re-inserts the surviving records at their true heights.
//! - The durable pool survives a restart: a fresh handler resumes from the exact
//!   pool + cursor it left off with (the process-memory pool's empty-at-boot
//!   weakness, proven fixed).
//! - The startup self-heal resets a stale advanced cursor over an empty index, and
//!   rewinds below a confirmed record the scan skipped.
//! - The tx_cbor backfill fills a row inserted with NULL bytes, and a conflicting
//!   re-observation never clobbers bytes already stored (COALESCE).
//! - An all-429 storm parks the loop with a rate-limited outcome and mutates no
//!   state.

#![cfg(feature = "pg-tests")]

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use cardanowall::cose::{cose_sign1_label309_build, CoseHeader, Label309Signer};
use cardanowall::poe_standard::{
    encode_poe_record, encode_record_body_for_signing, EncryptionEnvelope, ItemEntry, PoeRecord,
    SigEntry, Slot,
};
use chrono::{DateTime, TimeZone, Utc};
use gateway_core::chain::confirm::read_tip_epoch;
use gateway_core::chain::gateway::{
    chain_error, classify_chain_error, BlockInfo, ChainErrorClass, ChainGateway, ChainTip,
    FailoverGateway, Label309Record, Label309RecordsResult, ProviderCooldown, ProviderKind,
    ScanFrontier, TxCborMap, TxConfirmation, TxConfirmationMap,
};
use gateway_core::chain::params::Network as ParamsNetwork;
use gateway_core::chain::scan::{
    ScanConfig, ScanHandler, SelfHealReason, SCAN_ADVISORY_LOCK, SCAN_QUEUE,
};
use gateway_core::runtime::locks::AdvisoryLock;
use gateway_core::runtime::{JobContext, JobHandler, JobOutcome};
use gateway_core::testsupport::TestDb;
use uuid::Uuid;

/// The network every behavioural test scans (always a test network).
const NETWORK: &str = "preprod";

/// The set of column names on a `cw_core` table.
async fn columns_of(pool: &sqlx::PgPool, table: &str) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = 'cw_core' AND table_name = $1",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .expect("read column manifest");
    rows.into_iter().collect()
}

/// Whether a named index exists on a `cw_core` table.
async fn index_exists(pool: &sqlx::PgPool, index: &str) -> bool {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes WHERE schemaname = 'cw_core' AND indexname = $1",
    )
    .bind(index)
    .fetch_optional(pool)
    .await
    .expect("read index catalogue");
    found.is_some()
}

/// The migration applies cleanly: each scan-schema object
/// is queryable on a freshly migrated database, and the new tables start empty.
#[tokio::test]
async fn migration_creates_the_scan_schema() {
    let db = TestDb::fresh().await.expect("test database");

    for table in ["indexer_cursor", "confirmation_pool"] {
        let sql = format!("SELECT count(*) FROM cw_core.{table}");
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&db.pool)
            .await
            .unwrap_or_else(|e| panic!("querying cw_core.{table} should succeed: {e}"));
        assert_eq!(count, 0, "a fresh {table} starts empty");
    }

    // chain_records carries the nullable tx_cbor column.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.chain_records WHERE tx_cbor IS NULL")
            .fetch_one(&db.pool)
            .await
            .expect("tx_cbor column is queryable");
    assert_eq!(count, 0);
}

/// The read-feed access paths the scan and the read feed depend on exist: the
/// ascending range/keyset index, the sealed-record partial fast-path, and the
/// signer index, plus the durable-pool eviction index.
#[tokio::test]
async fn migration_creates_the_read_feed_indexes() {
    let db = TestDb::fresh().await.expect("test database");
    for index in [
        "chain_records_block_asc_idx",
        "chain_records_sealed_idx",
        "chain_records_signer_idx",
        "confirmation_pool_first_seen_idx",
    ] {
        assert!(
            index_exists(&db.pool, index).await,
            "expected index {index} to exist after the migration corpus applies"
        );
    }

    // The sealed fast-path's predicate must be the read feed's sealed predicate
    // verbatim: `scheme <> 0` (recipient-sealed AND passphrase). A narrower
    // predicate cannot serve the sealed filter and silently degrades it to
    // wider scans.
    let sealed_def: String = sqlx::query_scalar(
        "SELECT pg_get_indexdef(i.indexrelid) \
         FROM pg_index i \
         JOIN pg_class c ON c.oid = i.indexrelid \
         WHERE c.relname = 'chain_records_sealed_idx'",
    )
    .fetch_one(&db.pool)
    .await
    .expect("read the sealed index definition");
    assert!(
        sealed_def.contains("scheme <> 0"),
        "the sealed partial index must cover every sealed scheme (scheme <> 0); \
         definition was: {sealed_def}"
    );
}

/// Zero-knowledge guard (schema half): each indexer table's column manifest is
/// exactly the public, derived set. No recipient pubkey, account/identity
/// reference, or per-user correlator column ever appears on the on-chain index.
#[tokio::test]
async fn indexer_table_column_manifests_carry_no_recipient_or_identity_columns() {
    let db = TestDb::fresh().await.expect("test database");

    let chain_records = columns_of(&db.pool, "chain_records").await;
    assert_eq!(
        chain_records,
        BTreeSet::from([
            "tx_hash".to_string(),
            "block_height".to_string(),
            "block_time".to_string(),
            "metadata_cbor".to_string(),
            "tx_cbor".to_string(),
            "signer_ed25519".to_string(),
            "item_count".to_string(),
            "scheme".to_string(),
            "indexed_at".to_string(),
        ]),
        "chain_records carries only the public, derived columns"
    );

    let cursor = columns_of(&db.pool, "indexer_cursor").await;
    assert_eq!(
        cursor,
        BTreeSet::from([
            "network".to_string(),
            "last_processed_block_height".to_string(),
            "last_processed_block_hash".to_string(),
            "updated_at".to_string(),
            // The intra-block exclusion set: the chain-public transaction hashes of
            // a partially-consumed boundary block already indexed, so the scan pages
            // through an over-cap block. Chain-public tx ids, never a
            // recipient/account reference.
            "intra_block_done_tx_hashes".to_string(),
            // Stuck-gap liveness tracking: a stalled frontier height and how long it
            // has held. Chain-public scan state, never a recipient/account reference.
            "stuck_gap_height".to_string(),
            "stuck_gap_first_seen_at".to_string(),
            "stuck_gap_tick_count".to_string(),
        ]),
        "indexer_cursor carries only the scan frontier + stuck-gap tracking, never a \
         recipient/account reference"
    );

    let pool = columns_of(&db.pool, "confirmation_pool").await;
    assert_eq!(
        pool,
        BTreeSet::from([
            "tx_hash".to_string(),
            "block_height".to_string(),
            "block_time".to_string(),
            "metadata_cbor".to_string(),
            "signer_ed25519".to_string(),
            // The full verified-signer set carried to a promotion: the chain-public
            // signer keys (those already in the on-chain COSE_Sign1 headers), never
            // a recipient/account reference.
            "signer_set".to_string(),
            "item_count".to_string(),
            "scheme".to_string(),
            "first_seen_at".to_string(),
            "created_at".to_string(),
        ]),
        "confirmation_pool carries only the public, derived columns"
    );

    let signer_set = columns_of(&db.pool, "chain_record_signer").await;
    assert_eq!(
        signer_set,
        BTreeSet::from([
            // A verified signer's chain-public Ed25519 key, the transaction it
            // signed, and that transaction's block height (denormalized for the
            // signer-scoped list ordering). No recipient/account/identity column.
            "signer_ed25519".to_string(),
            "tx_hash".to_string(),
            "block_height".to_string(),
        ]),
        "chain_record_signer carries only the public verified-signer set columns"
    );
}

/// The indexer_cursor primary key is the network: a second row for the same
/// network collides, so the cursor stays a single row per network.
#[tokio::test]
async fn indexer_cursor_primary_key_is_per_network() {
    let db = TestDb::fresh().await.expect("test database");

    sqlx::query("INSERT INTO cw_core.indexer_cursor (network, last_processed_block_height) VALUES ('preprod', 100)")
        .execute(&db.pool)
        .await
        .expect("first cursor row");

    let dup = sqlx::query("INSERT INTO cw_core.indexer_cursor (network, last_processed_block_height) VALUES ('preprod', 200)")
        .execute(&db.pool)
        .await
        .expect_err("a second cursor row for the same network must collide");
    assert!(
        matches!(dup, sqlx::Error::Database(ref d) if d.code().as_deref() == Some("23505")),
        "expected a unique violation, got {dup:?}"
    );

    // A different network coexists.
    sqlx::query("INSERT INTO cw_core.indexer_cursor (network, last_processed_block_height) VALUES ('mainnet', 50)")
        .execute(&db.pool)
        .await
        .expect("a different network is an independent cursor");
}

/// The confirmation_pool primary key is the transaction hash: a re-observed
/// record collides, and `ON CONFLICT DO NOTHING` folds it into a no-op that
/// preserves the original first-seen ordering.
#[tokio::test]
async fn confirmation_pool_primary_key_dedupes_by_tx_hash() {
    let db = TestDb::fresh().await.expect("test database");
    let tx_hash = vec![0x55_u8; 32];

    let insert = |scheme: i16| {
        let pool = db.pool.clone();
        let hash = tx_hash.clone();
        async move {
            sqlx::query(
                "INSERT INTO cw_core.confirmation_pool \
                   (tx_hash, block_height, block_time, metadata_cbor, item_count, scheme) \
                 VALUES ($1, 10, now(), $2, 1, $3) ON CONFLICT (tx_hash) DO NOTHING",
            )
            .bind(hash)
            .bind(vec![0xa1_u8])
            .bind(scheme)
            .execute(&pool)
            .await
            .expect("pool insert")
            .rows_affected()
        }
    };

    assert_eq!(insert(0).await, 1, "the first pool entry is inserted");
    assert_eq!(
        insert(1).await,
        0,
        "a re-observed transaction folds into a no-op, never a second entry"
    );

    // The scheme CHECK pins the legal set even on the pool.
    let bad = sqlx::query(
        "INSERT INTO cw_core.confirmation_pool \
           (tx_hash, block_height, block_time, metadata_cbor, item_count, scheme) \
         VALUES ($1, 10, now(), $2, 1, 9)",
    )
    .bind(vec![0x66_u8; 32])
    .bind(vec![0xa1_u8])
    .execute(&db.pool)
    .await
    .expect_err("scheme 9 must be rejected by the pool CHECK");
    assert!(
        matches!(bad, sqlx::Error::Database(ref d) if d.code().as_deref() == Some("23514")),
        "expected a CHECK violation, got {bad:?}"
    );
}

// ===========================================================================
// Behavioural coverage: the ScanHandler loop driven against a scripted gateway.
// ===========================================================================

// ---------------------------------------------------------------------------
// Scripted chain gateway: per-tick forward-fetch responses, seeded blocks/tip,
// per-hash CBOR, and an armable all-429 storm. The shared state lives behind an
// Arc<Mutex<..>> so the gateway is Clone: a test keeps one handle to script and
// inspect it while the handler owns an independent clone over the same state.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ScriptState {
    /// Forward-fetch responses consumed in order; an exhausted script answers an
    /// empty, caught-up result (the steady-state idle tick).
    label309_script: VecDeque<Label309RecordsResult>,
    /// ALTERNATE-provider forward-fetch responses consumed in order (the
    /// stuck-gap recovery path). An exhausted alternate script answers a `Hold`
    /// (the alternate could not resolve the gap either), so a test must seed an
    /// alternate response for any gap it expects the other provider to resolve.
    alternate_script: VecDeque<Label309RecordsResult>,
    /// How many times the alternate-provider fetch was called, so a test can assert
    /// the stuck-gap recovery actually reached for the other provider.
    alternate_calls: u32,
    /// The `(after_block_height, exclude_tx_hashes, tip_block_height,
    /// max_records)` of each forward-fetch call, in order, for assertions.
    label309_calls: Vec<(u64, Vec<[u8; 32]>, u64, u32)>,
    /// Per-height block answers for reorg detection and self-heal.
    blocks: HashMap<u64, BlockInfo>,
    /// The tip height every tip read returns.
    tip: u64,
    /// The tip epoch every tip read returns (`None` until a test seeds one,
    /// matching a provider response that omitted the epoch).
    tip_epoch: Option<u64>,
    /// Per-hash full-transaction CBOR for the backfill / enrich passes.
    cbor: HashMap<[u8; 32], Vec<u8>>,
    /// Per-hash confirmation answers for the pool-recheck verification before a
    /// promotion. An unseeded hash answers not-on-chain, so a test must seed a
    /// confirmation for any pooled record it expects to be promoted.
    confirmations: HashMap<[u8; 32], TxConfirmation>,
    /// Hashes the pool re-check looked up, in order, so a test can assert the
    /// fresh lookup actually ran before a promotion.
    confirmation_lookups: Vec<[u8; 32]>,
}

/// A scriptable [`ChainGateway`] for the forward scan. Cloning shares the same
/// underlying state, so the test's handle and the handler's handle drive one
/// script.
#[derive(Clone, Default)]
struct ScriptedGateway {
    state: Arc<Mutex<ScriptState>>,
}

impl ScriptedGateway {
    fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ScriptState> {
        self.state.lock().expect("script state poisoned")
    }

    /// Push one forward-fetch response onto the script (consumed in order).
    fn push_response(&self, response: Label309RecordsResult) {
        self.lock().label309_script.push_back(response);
    }

    /// Push a caught-up response: every listed record hydrated and the provider has
    /// nothing more up to its own watermark `indexed_to`. The cursor jumps to
    /// `min(tip, indexed_to)`.
    fn push_caught_up(&self, records: Vec<Label309Record>, indexed_to: u64) {
        self.push_response(Label309RecordsResult {
            records,
            frontier: ScanFrontier::CaughtUpTo { indexed_to },
        });
    }

    /// Push a capped response: more records exist above the kept set, so the cursor
    /// anchors at the highest returned record (its real block hash).
    fn push_capped(&self, records: Vec<Label309Record>) {
        let frontier = records
            .last()
            .map_or(ScanFrontier::Hold, |last| ScanFrontier::Anchor {
                height: last.block_height,
                block_hash: last.block_hash,
            });
        self.push_response(Label309RecordsResult { records, frontier });
    }

    /// Push an intra-block page: the boundary block at `height` holds more records
    /// than one window, so this page consumes `records` of it (all at `height`) and
    /// reports the block partially done. `consumed_no_record` are transactions in
    /// the block observed to carry no record (consumed with nothing to index).
    fn push_intra_block(
        &self,
        height: u64,
        block_hash: [u8; 32],
        records: Vec<Label309Record>,
        consumed_no_record: Vec<[u8; 32]>,
    ) {
        self.push_response(Label309RecordsResult {
            records,
            frontier: ScanFrontier::IntraBlock {
                height,
                block_hash,
                consumed_no_record,
            },
        });
    }

    /// Push a `Hold` response: the answering provider could not hydrate the lowest
    /// record above the cursor, so there is no safe height to advance to. The cursor
    /// stays put and the scan registers a stuck gap.
    fn push_hold(&self) {
        self.push_response(Label309RecordsResult {
            records: Vec::new(),
            frontier: ScanFrontier::Hold,
        });
    }

    /// Push one ALTERNATE-provider forward-fetch response (consumed in order by the
    /// stuck-gap recovery path).
    fn push_alternate(&self, response: Label309RecordsResult) {
        self.lock().alternate_script.push_back(response);
    }

    /// Push an alternate-provider caught-up response that resolves a stuck gap.
    fn push_alternate_caught_up(&self, records: Vec<Label309Record>, indexed_to: u64) {
        self.push_alternate(Label309RecordsResult {
            records,
            frontier: ScanFrontier::CaughtUpTo { indexed_to },
        });
    }

    /// How many times the alternate-provider fetch was called.
    fn alternate_calls(&self) -> u32 {
        self.lock().alternate_calls
    }

    /// Seed a block answer for a height (reorg detection / self-heal frontier).
    fn set_block(&self, block: BlockInfo) {
        self.lock().blocks.insert(block.block_height, block);
    }

    /// Set the tip height every tip read returns.
    fn set_tip(&self, tip: u64) {
        self.lock().tip = tip;
    }

    /// Set the tip epoch every tip read returns (so a scan tick materialises it
    /// into `cw_core.cardano_tip`).
    fn set_tip_epoch(&self, epoch: u64) {
        self.lock().tip_epoch = Some(epoch);
    }

    /// Seed full-transaction CBOR for a hash.
    fn set_cbor(&self, hash: [u8; 32], cbor: Vec<u8>) {
        self.lock().cbor.insert(hash, cbor);
    }

    /// Seed a confirmation answer for a hash (the pool re-check verifies a
    /// promotion candidate against chain truth before promoting it).
    fn set_confirmation(&self, hash: [u8; 32], confirmation: TxConfirmation) {
        self.lock().confirmations.insert(hash, confirmation);
    }

    /// The hashes the pool re-check looked up, in order.
    fn confirmation_lookups(&self) -> Vec<[u8; 32]> {
        self.lock().confirmation_lookups.clone()
    }

    /// The forward-fetch call arguments observed so far.
    fn calls(&self) -> Vec<(u64, Vec<[u8; 32]>, u64, u32)> {
        self.lock().label309_calls.clone()
    }
}

impl ChainGateway for ScriptedGateway {
    async fn submit_tx(&self, _signed_tx: &[u8]) -> gateway_core::Result<[u8; 32]> {
        // The scan never submits.
        Ok([0u8; 32])
    }

    async fn get_tx_confirmations(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxConfirmationMap> {
        // The durable-pool re-check verifies a promotion candidate against chain
        // truth before promoting it: a seeded hash answers its seeded confirmation,
        // an unseeded one answers not-on-chain (so a test must seed a confirmation
        // for any pooled record it expects to be promoted).
        let mut state = self.lock();
        state.confirmation_lookups.extend_from_slice(tx_hashes);
        Ok(tx_hashes
            .iter()
            .map(|h| {
                (
                    *h,
                    state
                        .confirmations
                        .get(h)
                        .copied()
                        .unwrap_or_else(TxConfirmation::not_on_chain),
                )
            })
            .collect())
    }

    async fn get_block_info(&self, block_height: u64) -> gateway_core::Result<Option<BlockInfo>> {
        Ok(self.lock().blocks.get(&block_height).cloned())
    }

    async fn get_tip(&self) -> gateway_core::Result<ChainTip> {
        let state = self.lock();
        Ok(ChainTip {
            block_height: state.tip,
            epoch: state.tip_epoch,
        })
    }

    async fn fetch_tx_cbor_by_hashes(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxCborMap> {
        let state = self.lock();
        Ok(tx_hashes
            .iter()
            .filter_map(|h| state.cbor.get(h).map(|c| (*h, c.clone())))
            .collect())
    }

    async fn fetch_label309_records_since(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> gateway_core::Result<Label309RecordsResult> {
        let mut state = self.lock();
        state.label309_calls.push((
            after_block_height,
            exclude_tx_hashes.to_vec(),
            tip_block_height,
            max_records,
        ));
        Ok(state
            .label309_script
            .pop_front()
            .unwrap_or(Label309RecordsResult {
                records: Vec::new(),
                frontier: ScanFrontier::CaughtUpTo {
                    indexed_to: tip_block_height,
                },
            }))
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> gateway_core::Result<Label309RecordsResult> {
        let mut state = self.lock();
        state.alternate_calls += 1;
        state.label309_calls.push((
            after_block_height,
            exclude_tx_hashes.to_vec(),
            tip_block_height,
            max_records,
        ));
        // Consume the next alternate-scripted response; an exhausted alternate
        // script answers `Hold` (the other provider could not resolve the gap
        // either), so a test must seed an alternate response for any gap it expects
        // the other provider to resolve.
        Ok(state
            .alternate_script
            .pop_front()
            .unwrap_or(Label309RecordsResult {
                records: Vec::new(),
                frontier: ScanFrontier::Hold,
            }))
    }
}

/// A chain gateway whose every call returns a classified HTTP 429, so a
/// `FailoverGateway` over two of these is a real all-provider rate-limit storm
/// rather than a synthesised marker.
struct RateLimitedGateway;

impl ChainGateway for RateLimitedGateway {
    async fn submit_tx(&self, _signed_tx: &[u8]) -> gateway_core::Result<[u8; 32]> {
        Err(chain_error(ChainErrorClass::Http { status: 429 }, "429"))
    }

    async fn get_tx_confirmations(
        &self,
        _tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxConfirmationMap> {
        Err(chain_error(ChainErrorClass::Http { status: 429 }, "429"))
    }

    async fn get_block_info(&self, _block_height: u64) -> gateway_core::Result<Option<BlockInfo>> {
        Err(chain_error(ChainErrorClass::Http { status: 429 }, "429"))
    }

    async fn get_tip(&self) -> gateway_core::Result<ChainTip> {
        Err(chain_error(ChainErrorClass::Http { status: 429 }, "429"))
    }

    async fn fetch_tx_cbor_by_hashes(
        &self,
        _tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxCborMap> {
        Err(chain_error(ChainErrorClass::Http { status: 429 }, "429"))
    }

    async fn fetch_label309_records_since(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<Label309RecordsResult> {
        Err(chain_error(ChainErrorClass::Http { status: 429 }, "429"))
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<Label309RecordsResult> {
        Err(chain_error(ChainErrorClass::Http { status: 429 }, "429"))
    }
}

/// A chain gateway whose tip reads succeed but whose forward fetch reports
/// corrupt provider output (the failover wrapper exhausted both providers), so a
/// scan tick gets past the tip refresh and fails exactly at the fetch.
struct CorruptFetchGateway {
    tip: u64,
}

impl ChainGateway for CorruptFetchGateway {
    async fn submit_tx(&self, _signed_tx: &[u8]) -> gateway_core::Result<[u8; 32]> {
        Ok([0u8; 32])
    }

    async fn get_tx_confirmations(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxConfirmationMap> {
        Ok(tx_hashes
            .iter()
            .map(|h| (*h, TxConfirmation::not_on_chain()))
            .collect())
    }

    async fn get_block_info(&self, _block_height: u64) -> gateway_core::Result<Option<BlockInfo>> {
        Ok(None)
    }

    async fn get_tip(&self) -> gateway_core::Result<ChainTip> {
        Ok(ChainTip {
            block_height: self.tip,
            epoch: None,
        })
    }

    async fn fetch_tx_cbor_by_hashes(
        &self,
        _tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxCborMap> {
        Ok(HashMap::new())
    }

    async fn fetch_label309_records_since(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<Label309RecordsResult> {
        Err(chain_error(
            ChainErrorClass::CorruptProvider,
            "provider served a 65-byte label-309 metadata chunk",
        ))
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<Label309RecordsResult> {
        Err(chain_error(
            ChainErrorClass::CorruptProvider,
            "provider served a 65-byte label-309 metadata chunk",
        ))
    }
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// A fixed block time so every fixture record carries a stable, comparable
/// timestamp.
fn block_time() -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000, 0).single().expect("time")
}

/// A 32-byte value filled with one repeated byte.
fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// The canonical bytes of a minimal valid open record carrying one content item.
fn open_record_cbor() -> Vec<u8> {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0xab; 32])],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    encode_poe_record(&record).expect("encode open record")
}

/// The canonical bytes of a record whose first item is recipient-sealed
/// (slots), and a path-1 signature so the derived signer column is populated.
fn sealed_signed_record_cbor(seed: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let pubkey = cardanowall::cose::ed25519_public_key_from_seed(seed);
    let mut record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0xcd; 32])],
            uris: None,
            enc: Some(EncryptionEnvelope::Scheme1(
                cardanowall::poe_standard::EncScheme1 {
                    scheme: 1,
                    aead: "chacha20-poly1305-stream64k".to_string(),
                    nonce: vec![0x05; 24],
                    kem: Some("x25519".to_string()),
                    slots: Some(vec![Slot {
                        epk: Some(vec![0x01; 32]),
                        kem_ct: None,
                        wrap: Some(vec![0x09; 48]),
                    }]),
                    slots_mac: Some(vec![0x07; 32]),
                    passphrase: None,
                },
            )),
        }]),
        ..PoeRecord::default()
    };
    let body = encode_record_body_for_signing(&record).expect("encode body");
    let protected = CoseHeader::new()
        .with_int(1, cardanowall::cbor::CborValue::int(-8)) // alg: EdDSA
        .with_int(4, cardanowall::cbor::CborValue::bytes(pubkey.to_vec())); // kid: raw pubkey
    let sign1 = cose_sign1_label309_build(
        &protected,
        &CoseHeader::new(),
        &body,
        Label309Signer::Seed(seed),
    )
    .expect("build cose_sign1");
    record.sigs = Some(vec![SigEntry {
        cose_sign1: sign1,
        cose_key: None,
    }]);
    let bytes = encode_poe_record(&record).expect("encode sealed signed record");
    (bytes, pubkey)
}

/// Build one forward-scan record at a height with a given confirmation count and
/// metadata, deriving the tx hash and block hash from one fill byte each.
fn record(
    tx_fill: u8,
    block_fill: u8,
    block_height: u64,
    num_confirmations: u64,
    metadata_cbor: Vec<u8>,
) -> Label309Record {
    Label309Record {
        tx_hash: fill(tx_fill),
        block_hash: fill(block_fill),
        block_height,
        block_time: block_time(),
        num_confirmations,
        metadata_cbor,
    }
}

/// The default scan config the behavioural tests run with (the documented
/// thresholds), with the bounded periodic rewind disabled so a deterministic
/// per-tick behavioural assertion is never perturbed by a periodic window
/// re-scan. The bounded rewind has its own dedicated test that enables it.
fn scan_config() -> ScanConfig {
    ScanConfig {
        bounded_rewind_interval_secs: 0,
        ..ScanConfig::default()
    }
}

/// An on-chain confirmation answer at a height (the pool re-check verifies a
/// promotion candidate against chain truth before promoting it).
fn on_chain_confirmation(block_height: u64) -> TxConfirmation {
    TxConfirmation::on_chain(1, block_height, block_time())
}

// ---------------------------------------------------------------------------
// DB read helpers (assertions read the durable side effects, not log strings).
// ---------------------------------------------------------------------------

/// The set of `chain_records` transaction hashes currently persisted.
async fn persisted_hashes(pool: &sqlx::PgPool) -> BTreeSet<Vec<u8>> {
    sqlx::query_scalar::<_, Vec<u8>>("SELECT tx_hash FROM cw_core.chain_records")
        .fetch_all(pool)
        .await
        .expect("read chain_records hashes")
        .into_iter()
        .collect()
}

/// One persisted `chain_records` row, projected to the columns the behavioural
/// assertions read. The `signer_ed25519` bytea is read raw; assertions only ask
/// whether it is present (`signer_present`), never the key itself.
#[derive(sqlx::FromRow)]
struct PersistedRow {
    block_height: i64,
    scheme: i16,
    item_count: i32,
    signer_ed25519: Option<Vec<u8>>,
    tx_cbor: Option<Vec<u8>>,
}

impl PersistedRow {
    /// Whether the derived signer column is populated.
    fn signer_present(&self) -> bool {
        self.signer_ed25519.is_some()
    }
}

/// The persisted projection of one transaction, or `None` when it is not in
/// `chain_records`.
async fn persisted_row(pool: &sqlx::PgPool, tx_hash: [u8; 32]) -> Option<PersistedRow> {
    sqlx::query_as(
        "SELECT block_height, scheme, item_count, signer_ed25519, tx_cbor \
         FROM cw_core.chain_records WHERE tx_hash = $1",
    )
    .bind(tx_hash.as_slice())
    .fetch_optional(pool)
    .await
    .expect("read chain_records row")
}

/// The set of `confirmation_pool` transaction hashes currently held.
async fn pool_hashes(pool: &sqlx::PgPool) -> BTreeSet<Vec<u8>> {
    sqlx::query_scalar::<_, Vec<u8>>("SELECT tx_hash FROM cw_core.confirmation_pool")
        .fetch_all(pool)
        .await
        .expect("read pool hashes")
        .into_iter()
        .collect()
}

/// The current scan-frontier cursor `(height, hash_hex)`, or `None` when unset.
async fn cursor_state(pool: &sqlx::PgPool) -> Option<(i64, Option<String>)> {
    sqlx::query_as(
        "SELECT last_processed_block_height, last_processed_block_hash \
         FROM cw_core.indexer_cursor WHERE network = $1",
    )
    .bind(NETWORK)
    .fetch_optional(pool)
    .await
    .expect("read cursor")
}

/// The durable intra-block exclusion set on the cursor (the transactions of a
/// partially-consumed boundary block already consumed), or `None` when the
/// frontier block is fully consumed / no cursor row exists.
async fn cursor_intra_block_done(pool: &sqlx::PgPool) -> Option<Vec<Vec<u8>>> {
    sqlx::query_scalar::<_, Option<Vec<Vec<u8>>>>(
        "SELECT intra_block_done_tx_hashes FROM cw_core.indexer_cursor WHERE network = $1",
    )
    .bind(NETWORK)
    .fetch_optional(pool)
    .await
    .expect("read intra-block done set")
    .flatten()
    .filter(|done| !done.is_empty())
}

/// The durable stuck-gap tracking `(stuck_gap_height, stuck_gap_tick_count)`, or
/// `None` when no cursor row exists yet.
async fn stuck_gap_state(pool: &sqlx::PgPool) -> Option<(Option<i64>, i64)> {
    sqlx::query_as(
        "SELECT stuck_gap_height, stuck_gap_tick_count \
         FROM cw_core.indexer_cursor WHERE network = $1",
    )
    .bind(NETWORK)
    .fetch_optional(pool)
    .await
    .expect("read stuck gap state")
}

/// Seed an operator and a draft/confirmed `poe_record` directly in SQL, returning
/// the record id. Used by the self-heal Case B test (a confirmed record whose
/// transaction the scan must re-cover).
async fn seed_confirmed_record(pool: &sqlx::PgPool, tx_hash: [u8; 32], block_height: i64) -> Uuid {
    let operator_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'scan-test-op')")
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert operator");
    let record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, record_bytes, status, tx_hash, block_height, block_time) \
         VALUES ($1, $2, $3, 'confirmed', $4, $5, now())",
    )
    .bind(record_id)
    .bind(operator_id)
    .bind(open_record_cbor())
    .bind(tx_hash.as_slice())
    .bind(block_height)
    .execute(pool)
    .await
    .expect("insert confirmed poe_record");
    record_id
}

// ---------------------------------------------------------------------------
// Golden sequence: clean genesis scan.
// ---------------------------------------------------------------------------

/// A clean scan from genesis over two scripted batches. Tick 1 returns a capped
/// batch (not at chain head): every confirmed record is persisted and the cursor
/// anchors at the LAST record with its real hash (the scan-frontier rule, not the
/// highest record). Tick 2 reaches the chain head: the cursor jumps to the tip and
/// anchors it with the tip block's real hash so reorg detection stays armed.
#[tokio::test]
async fn clean_genesis_scan_anchors_then_jumps_to_the_tip() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // Two confirmed records (num_confirmations well over the threshold) in a
    // capped batch: not at chain head, so the cursor must anchor at the last one.
    gateway.push_capped(vec![
        record(0x01, 0xa1, 100, 50, open_record_cbor()),
        record(0x02, 0xa2, 105, 45, open_record_cbor()),
    ]);
    // Tick 2: caught up to the tip. No more records up to the provider's watermark.
    gateway.push_caught_up(Vec::new(), 200);
    gateway.set_tip(200);
    // The tip block carries a real hash the head-reached jump anchors on.
    gateway.set_block(BlockInfo {
        block_height: 200,
        block_hash: fill(0xc8),
        block_time: block_time(),
    });

    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );

    // Tick 1.
    let out = handler.run_iteration().await.expect("tick 1");
    assert_eq!(out.records_returned, 2);
    assert_eq!(out.records_persisted, 2, "both confirmed records persist");
    assert!(!out.reached_chain_head);
    assert_eq!(
        persisted_hashes(&db.pool).await,
        BTreeSet::from([fill(0x01).to_vec(), fill(0x02).to_vec()]),
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((105, Some(hex::encode(fill(0xa2))))),
        "the frontier anchors at the LAST record with its real hash, not the tip"
    );

    // Tick 2.
    let out = handler.run_iteration().await.expect("tick 2");
    assert!(out.reached_chain_head);
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((200, Some(hex::encode(fill(0xc8))))),
        "reaching the chain head jumps the frontier to the tip with the tip block's real hash"
    );

    // The first forward-fetch started from genesis (cursor 0); the second resumed
    // from the anchored frontier (105).
    let calls = gateway.calls();
    assert_eq!(calls[0].0, 0, "tick 1 fetched from genesis");
    assert_eq!(calls[1].0, 105, "tick 2 resumed from the anchored frontier");
}

/// An over-cap block — one block carrying more label-309 transactions than the
/// per-tick cap — is fully indexed across successive ticks with NO stall, NO
/// skip, and NO double-emit. This is the liveness fix: the per-tick cap is a page
/// size, never a wall, so a single stuffed block can never wedge the global feed.
#[tokio::test]
async fn an_over_cap_block_is_fully_indexed_across_ticks_without_stalling() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // Block 300 carries FIVE confirmed label-309 transactions; the per-tick cap is
    // two. The provider (scripted here, exercised for real in the provider-level
    // tests) hands the scan a two-record page each tick under an intra-block
    // frontier, then the remainder, then reports the block caught up.
    let block_hash = fill(0xb3);
    let mk = |tx: u8| record(tx, 0xb3, 300, 50, open_record_cbor());
    gateway.push_intra_block(300, block_hash, vec![mk(0x01), mk(0x02)], Vec::new());
    gateway.push_intra_block(300, block_hash, vec![mk(0x03), mk(0x04)], Vec::new());
    // Final page: the last record, then the provider is caught up to the block.
    gateway.push_response(gateway_core::chain::gateway::Label309RecordsResult {
        records: vec![mk(0x05)],
        frontier: ScanFrontier::CaughtUpTo { indexed_to: 300 },
    });
    gateway.set_tip(300);
    gateway.set_block(BlockInfo {
        block_height: 300,
        block_hash,
        block_time: block_time(),
    });

    let config = ScanConfig {
        max_records_per_iteration: 2,
        ..scan_config()
    };
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        config,
    );

    // Tick 1: first page. Two records indexed; the cursor anchors AT block 300 and
    // remembers the two consumed transactions.
    let out = handler.run_iteration().await.expect("tick 1");
    assert_eq!(out.records_persisted, 2);
    assert!(
        out.intra_block_in_progress,
        "the block is only partially consumed"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((300, Some(hex::encode(block_hash)))),
        "the cursor anchors AT the partially-consumed block with its real hash"
    );
    let done = cursor_intra_block_done(&db.pool)
        .await
        .expect("a partial set");
    assert_eq!(done.len(), 2);

    // Tick 2: the resume fetch excludes exactly the two consumed transactions.
    let out = handler.run_iteration().await.expect("tick 2");
    assert_eq!(out.records_persisted, 2);
    assert!(out.intra_block_in_progress);
    let done = cursor_intra_block_done(&db.pool)
        .await
        .expect("a grown set");
    assert_eq!(done.len(), 4, "the exclusion set grows, never resets");

    // Tick 3: the last record indexes and the block flips to fully consumed.
    let out = handler.run_iteration().await.expect("tick 3");
    assert_eq!(out.records_persisted, 1);
    assert!(!out.intra_block_in_progress, "the block is now complete");
    assert!(out.reached_chain_head);
    assert_eq!(
        cursor_intra_block_done(&db.pool).await,
        None,
        "completing the block retires the exclusion set"
    );

    // Exactly-once: all five transactions indexed, none skipped, none duplicated.
    assert_eq!(
        persisted_hashes(&db.pool).await,
        BTreeSet::from([
            fill(0x01).to_vec(),
            fill(0x02).to_vec(),
            fill(0x03).to_vec(),
            fill(0x04).to_vec(),
            fill(0x05).to_vec(),
        ]),
    );

    // The resume ticks excluded the growing consumed set (never re-fetching a
    // consumed transaction), and all resumed from just below the boundary block.
    let calls = gateway.calls();
    assert_eq!(calls[0].1.len(), 0, "tick 1 excludes nothing");
    assert_eq!(calls[1].1.len(), 2, "tick 2 excludes the first page");
    assert_eq!(calls[2].1.len(), 4, "tick 3 excludes the first two pages");
    assert_eq!(
        calls[1].0, 299,
        "the resume re-reads from just below the block"
    );
    assert_eq!(calls[2].0, 299);
}

/// A reorg that lands WHILE a block is being paged mid-consumption rewinds the
/// cursor and clears the intra-block exclusion set, so the surviving branch is
/// re-scanned whole rather than resumed against a stale done-set.
#[tokio::test]
async fn a_reorg_mid_intra_block_clears_the_exclusion_set() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    let block_hash = fill(0xb3);
    let mk = |tx: u8| record(tx, 0xb3, 300, 50, open_record_cbor());
    // Tick 1 consumes a page of block 300 (partial).
    gateway.push_intra_block(300, block_hash, vec![mk(0x01), mk(0x02)], Vec::new());
    gateway.set_tip(305); // within the reorg window of the frontier at 300
                          // Tick 2: the frontier block's hash no longer matches — a reorg.
    gateway.set_block(BlockInfo {
        block_height: 300,
        block_hash: fill(0xee), // different hash than the stored 0xb3 anchor
        block_time: block_time(),
    });

    let config = ScanConfig {
        max_records_per_iteration: 2,
        reorg_window_blocks: 30,
        ..scan_config()
    };
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        config,
    );

    handler
        .run_iteration()
        .await
        .expect("tick 1 (partial page)");
    assert!(
        cursor_intra_block_done(&db.pool).await.is_some(),
        "the block is partially consumed after tick 1"
    );

    let out = handler.run_iteration().await.expect("tick 2 (reorg)");
    assert!(out.reorg_detected, "the frontier-hash mismatch is a reorg");
    assert_eq!(
        cursor_intra_block_done(&db.pool).await,
        None,
        "the rewind clears the intra-block exclusion set"
    );
    let (height, _) = cursor_state(&db.pool).await.expect("a cursor row");
    assert!(height < 300, "the cursor rewound below the reorged block");
}

/// The scan's single `/tip` read carries the epoch, and one scan iteration
/// materialises it into `cw_core.cardano_tip` so the protocol-parameter populate
/// loop reads the current epoch from Postgres rather than making its own `/tip`
/// call. This is the read side of the keyless-budget efficiency fix.
#[tokio::test]
async fn scan_materialises_the_tip_epoch_for_the_populate_loop() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // No tip materialised yet (cold start).
    assert_eq!(
        read_tip_epoch(&db.pool, NETWORK)
            .await
            .expect("read epoch before scan"),
        None,
    );

    // The provider reports a tip at height 200 in epoch 213. A caught-up tick is
    // enough: the head-of-tick tip refresh writes the materialised row.
    gateway.push_caught_up(Vec::new(), 200);
    gateway.set_tip(200);
    gateway.set_tip_epoch(213);
    gateway.set_block(BlockInfo {
        block_height: 200,
        block_hash: fill(0xc8),
        block_time: block_time(),
    });

    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    handler.run_iteration().await.expect("one scan tick");

    // The epoch the scan observed on the tip is now readable from Postgres, so the
    // populate loop never needs its own `/tip` call.
    assert_eq!(
        read_tip_epoch(&db.pool, NETWORK)
            .await
            .expect("read epoch after scan"),
        Some(213),
        "the scan materialises the tip epoch into cardano_tip",
    );
}

// ---------------------------------------------------------------------------
// Golden sequence: validator-reject skip.
// ---------------------------------------------------------------------------

/// An invalid record in a batch is skipped: it never reaches `chain_records` or
/// the pool, while a valid sibling in the same batch is persisted. A malformed
/// transaction never enters the index with fabricated columns.
#[tokio::test]
async fn an_invalid_record_is_skipped_not_indexed() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    gateway.push_caught_up(
        vec![
            // Not a valid Label 309 record: three arbitrary bytes.
            record(0x0b, 0xb1, 100, 50, vec![0x00, 0x01, 0x02]),
            // A valid sibling.
            record(0x0c, 0xb2, 101, 50, open_record_cbor()),
        ],
        200,
    );
    gateway.set_tip(200);

    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    let out = handler.run_iteration().await.expect("iteration");

    assert_eq!(out.records_returned, 2, "the gateway returned two records");
    assert_eq!(out.records_persisted, 1, "only the valid record persists");
    assert_eq!(
        persisted_hashes(&db.pool).await,
        BTreeSet::from([fill(0x0c).to_vec()]),
        "the invalid record is skipped, never indexed"
    );
    assert!(
        pool_hashes(&db.pool).await.is_empty(),
        "an invalid record is never pooled either"
    );
}

/// A corrupt-provider failure on the forward fetch (the provider served data
/// that cannot exist on chain, and the failover pair could not serve the page)
/// fails the WHOLE tick: the iteration errors, nothing is indexed, and — the
/// completeness invariant — no cursor frontier is written, so the next tick
/// re-reads the same window instead of advancing past a transaction the
/// provider mis-rendered. Contrast with `an_invalid_record_is_skipped_not_indexed`,
/// where the verdict is on the transaction and the tick proceeds.
#[tokio::test]
async fn a_corrupt_provider_fetch_fails_the_tick_with_the_cursor_unmoved() {
    let db = TestDb::fresh().await.expect("db");
    let handler = ScanHandler::new(
        db.pool.clone(),
        CorruptFetchGateway { tip: 600 },
        ParamsNetwork::Preprod,
        scan_config(),
    );

    let err = handler
        .run_iteration()
        .await
        .expect_err("a corrupt-provider fetch must fail the tick, not skip records");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::CorruptProvider),
        "the typed corruption class surfaces to the tick"
    );

    assert_eq!(
        cursor_state(&db.pool).await,
        None,
        "a failed tick writes no scan frontier: the cursor cannot advance past \
         a mis-rendered transaction"
    );
    assert!(
        persisted_hashes(&db.pool).await.is_empty(),
        "nothing is indexed off a corrupt page"
    );
}

// ---------------------------------------------------------------------------
// Golden sequence: below-threshold pool -> later promote.
// ---------------------------------------------------------------------------

/// A below-threshold record enters the durable pool rather than `chain_records`;
/// a later tick, against an advanced tip, re-checks the pool, finds it has crossed
/// the threshold, promotes it into `chain_records`, and removes the pool entry.
/// The persisted columns are the ones derived from the record bytes (scheme 1,
/// the signer key present), proving the pool carried the full derivation.
#[tokio::test]
async fn a_below_threshold_record_pools_then_promotes() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();
    let (sealed, signer) = sealed_signed_record_cbor(&fill(0x42));

    // Tick 1: the record is at height 100 with only 3 confirmations (threshold is
    // 15), so it pools instead of persisting. The tick is caught up to the tip; the
    // tip block (102) is not seeded, so the frontier falls back to anchoring at the
    // emitted record's own block (100, hash 0xe1) — a real anchor at/below the tip.
    gateway.push_caught_up(vec![record(0xd1, 0xe1, 100, 3, sealed)], 102);
    gateway.set_tip(102); // 102 - 100 + 1 = 3 confirmations.

    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    let out = handler.run_iteration().await.expect("tick 1");
    assert_eq!(
        out.records_persisted, 0,
        "below threshold: nothing persists"
    );
    assert_eq!(
        pool_hashes(&db.pool).await,
        BTreeSet::from([fill(0xd1).to_vec()]),
        "the below-threshold record is held in the durable pool"
    );
    assert!(persisted_hashes(&db.pool).await.is_empty());

    // Tick 2: the tip advances to 120, so the pooled record now has
    // 120 - 100 + 1 = 21 >= 15 confirmations. The re-check verifies it is still on
    // chain (the gateway confirms it at its height) and promotes it. No new
    // forward-fetch record is needed (the script is exhausted -> empty/caught-up).
    // Tick 1 anchored a real frontier hash (height 100, hash 0xe1), so the resumed
    // frontier's per-tick reorg check needs that block to still match on the valid
    // chain; seed it so the reorg check passes and the promotion proceeds.
    gateway.set_tip(120);
    gateway.set_block(BlockInfo {
        block_height: 100,
        block_hash: fill(0xe1),
        block_time: block_time(),
    });
    gateway.set_confirmation(fill(0xd1), on_chain_confirmation(100));
    let _ = handler.run_iteration().await.expect("tick 2");

    // The promotion did a fresh chain-truth lookup of exactly the candidate.
    assert_eq!(
        gateway.confirmation_lookups(),
        vec![fill(0xd1)],
        "the pool re-check verified the promotion candidate against chain truth"
    );
    assert!(
        pool_hashes(&db.pool).await.is_empty(),
        "the promoted record leaves the pool"
    );
    let row = persisted_row(&db.pool, fill(0xd1))
        .await
        .expect("the promoted record is now persisted");
    assert_eq!(
        row.block_height, 100,
        "the promoted record keeps its real block height"
    );
    assert_eq!(row.scheme, 1, "the derived scheme is the sealed scheme");
    assert_eq!(row.item_count, 1, "the derived item count is one");
    assert!(
        row.signer_present(),
        "the derived signer column is populated"
    );
    let _ = signer; // the signer derivation is asserted via signer_present.
}

// ---------------------------------------------------------------------------
// Pool re-check verifies a promotion candidate against chain truth.
// ---------------------------------------------------------------------------

/// A pooled record that has crossed the confirmation threshold arithmetically but
/// that a fresh gateway lookup reports is no longer on chain (a reorg removed it
/// after it was pooled) is DROPPED, never promoted. A freshly threshold-crossed
/// entry is still within the reorg window, so arithmetic alone could otherwise
/// promote a vanished transaction into the durable index. The re-check's
/// chain-truth verification is what closes that gap.
#[tokio::test]
async fn a_pooled_record_a_fresh_lookup_reports_gone_is_dropped_not_promoted() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // Tick 1: a capped batch carries a below-threshold record (height 100, only 3
    // confirmations -> pools) and a confirmed record at a higher frontier (height
    // 900). The frontier anchors at 900 with its real hash, ABOVE the pooled record
    // -- so the resumed frontier's reorg check is independent of the pooled record's
    // own block, isolating the gone-drop path under test.
    gateway.push_capped(vec![
        record(0xd1, 0xe1, 100, 3, open_record_cbor()),
        record(0xd2, 0xe2, 900, 200, open_record_cbor()),
    ]);
    gateway.set_tip(902);
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    handler.run_iteration().await.expect("tick 1");
    assert_eq!(
        pool_hashes(&db.pool).await,
        BTreeSet::from([fill(0xd1).to_vec()]),
        "the below-threshold record is pooled"
    );

    // Tick 2: the tip advances to 920 (the frontier at 900 is still well within the
    // 30-block window and its block hash 0xe2 still matches, so the per-tick reorg
    // check passes). The pooled record at 100 is now deeply confirmed
    // arithmetically (920 - 100 + 1 = 821 >= 15) and is a promotion candidate. But
    // the fresh gateway lookup reports it not-on-chain: a reorg removed it after it
    // was pooled. The re-check must DROP it, not promote a vanished transaction.
    gateway.set_tip(920);
    gateway.set_block(BlockInfo {
        block_height: 900,
        block_hash: fill(0xe2),
        block_time: block_time(),
    });
    gateway.set_confirmation(fill(0xd1), TxConfirmation::not_on_chain());
    handler.run_iteration().await.expect("tick 2");

    assert_eq!(
        gateway.confirmation_lookups(),
        vec![fill(0xd1)],
        "the re-check did a fresh chain-truth lookup of the promotion candidate"
    );
    assert!(
        pool_hashes(&db.pool).await.is_empty(),
        "the gone candidate is dropped from the pool"
    );
    assert!(
        !persisted_hashes(&db.pool)
            .await
            .contains(fill(0xd1).as_slice()),
        "a vanished transaction is never promoted into the durable index"
    );
}

/// A promotion candidate the fresh lookup does NOT positively confirm on chain is
/// never promoted; the same candidate IS promoted once a fresh lookup positively
/// confirms it on chain. Drives the two outcomes against the same seeded pool
/// entry while the scan sits caught up at the tip (so the only mover of pool state
/// is the re-check itself), with a real frontier hash that keeps the per-tick reorg
/// check passing.
#[tokio::test]
async fn a_candidate_is_promoted_only_once_chain_truth_confirms_it() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // The scan sits caught up at a high frontier (height 900) with a real hash, so
    // every tick short-circuits the forward fetch and the only thing that touches
    // pool state is the re-check. Seed the cursor and the frontier block directly.
    sqlx::query(
        "INSERT INTO cw_core.indexer_cursor \
           (network, last_processed_block_height, last_processed_block_hash) \
         VALUES ($1, 900, $2)",
    )
    .bind(NETWORK)
    .bind(hex::encode(fill(0xb6)))
    .execute(&db.pool)
    .await
    .expect("seed a caught-up frontier");
    gateway.set_tip(900);
    gateway.set_block(BlockInfo {
        block_height: 900,
        block_hash: fill(0xb6),
        block_time: block_time(),
    });

    // Seed a pool entry that has already crossed the threshold arithmetically
    // (height 100, frontier/tip 900): it is a promotion candidate every tick.
    let seed_pool_entry = || {
        let pool = db.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO cw_core.confirmation_pool \
                   (tx_hash, block_height, block_time, metadata_cbor, item_count, scheme) \
                 VALUES ($1, 100, now(), $2, 1, 0) ON CONFLICT (tx_hash) DO NOTHING",
            )
            .bind(fill(0xa5).as_slice())
            .bind(open_record_cbor())
            .execute(&pool)
            .await
            .expect("seed pool entry");
        }
    };
    seed_pool_entry().await;
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );

    // Tick A: the fresh lookup does NOT confirm the candidate on chain (the unseeded
    // stub answers not-on-chain), so it is dropped, never promoted on an unverified
    // lookup.
    handler.run_iteration().await.expect("tick A");
    assert!(
        !persisted_hashes(&db.pool)
            .await
            .contains(fill(0xa5).as_slice()),
        "an entry not positively confirmed on chain is never promoted"
    );
    assert!(
        pool_hashes(&db.pool).await.is_empty(),
        "the unverified candidate is dropped, not left to be promoted later by arithmetic"
    );

    // Tick B: re-seed the same pool entry, now WITH a positive chain-truth
    // confirmation. The re-check promotes it.
    seed_pool_entry().await;
    gateway.set_confirmation(fill(0xa5), on_chain_confirmation(100));
    handler.run_iteration().await.expect("tick B");
    assert!(
        persisted_hashes(&db.pool)
            .await
            .contains(fill(0xa5).as_slice()),
        "once chain truth confirms the entry it is promoted"
    );
}

// ---------------------------------------------------------------------------
// Bounded periodic rewind: a near-tip window re-scan on a cadence.
// ---------------------------------------------------------------------------

/// The bounded periodic rewind re-covers the last `reorg_window_blocks` on its
/// wall-clock cadence when the frontier sits near the tip, even when the
/// per-tick frontier-hash check would otherwise pass or is disarmed. This is
/// the backstop for a near-tip reorg that landed while the frontier hash was
/// momentarily absent. The test asserts the full cadence contract:
///
/// - a tick before the interval has elapsed does NOT fire it;
/// - once the interval elapses, the next near-tip tick rewinds the cursor one
///   reorg window and reports a reorg (so the loop re-covers the range at once);
/// - the tick immediately after a firing does NOT fire it again — consecutive
///   ticks can never both rewind, no matter how fast the loop re-enqueues.
///   (This pins down the regression where iteration-count pacing let a
///   re-enqueue storm fire the rewind every second or two.)
#[tokio::test]
async fn the_bounded_periodic_rewind_fires_on_wall_clock_never_consecutive_ticks() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // A short wall-clock interval so the test reaches the firing instant quickly.
    // The frontier is seeded at the tip (caught up) with a real hash, so without
    // the bounded rewind the loop would simply idle; the periodic rewind is the
    // only thing that can move the cursor here.
    let config = ScanConfig {
        bounded_rewind_interval_secs: 2,
        ..ScanConfig::default()
    };
    let frontier_height: i64 = 1000;
    sqlx::query(
        "INSERT INTO cw_core.indexer_cursor \
           (network, last_processed_block_height, last_processed_block_hash) \
         VALUES ($1, $2, $3)",
    )
    .bind(NETWORK)
    .bind(frontier_height)
    .bind(hex::encode(fill(0xaa)))
    .execute(&db.pool)
    .await
    .expect("seed a caught-up frontier with a real hash");
    // The tip equals the frontier (caught up), so the ordinary tick short-circuits
    // without a forward fetch and leaves the cursor in place. Block 1000's info is
    // seeded so the post-rewind tick can re-anchor the frontier at the tip with a
    // real hash.
    gateway.set_tip(1000);
    gateway.set_block(BlockInfo {
        block_height: 1000,
        block_hash: fill(0xaa),
        block_time: block_time(),
    });

    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        config,
    );

    // Before the interval elapses, ticks do not fire the cadence: the cursor
    // stays caught up at the tip with its real hash.
    for tick in 1..=2 {
        let out = handler.run_iteration().await.unwrap_or_else(|e| {
            panic!("tick {tick}: {e}");
        });
        assert!(
            !out.reorg_detected,
            "tick {tick} runs before the interval elapsed and must not fire the cadence"
        );
        assert_eq!(
            cursor_state(&db.pool).await,
            Some((1000, Some(hex::encode(fill(0xaa))))),
            "tick {tick} leaves the caught-up frontier in place"
        );
    }

    // Let the wall-clock interval elapse, then tick: the bounded rewind fires,
    // re-covers the last reorg window (1000 - 30 = 970), and reports a reorg so
    // the loop resumes at once.
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    let out = handler
        .run_iteration()
        .await
        .expect("the post-interval tick fires the cadence");
    assert!(
        out.reorg_detected,
        "the bounded periodic rewind reports a reorg so the loop re-covers the range at once"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((970, None)),
        "the cursor rewinds one reorg window below the frontier"
    );

    // The immediate next tick re-covers the rewound window (the ordinary forward
    // fetch) and re-anchors the frontier at the tip with its real hash; it must
    // NOT fire the rewind again.
    let out = handler.run_iteration().await.expect("the re-cover tick");
    assert!(
        !out.reorg_detected,
        "the tick immediately after a rewind never fires the cadence again"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((1000, Some(hex::encode(fill(0xaa))))),
        "the re-cover tick re-anchors the frontier at the tip with a real hash"
    );

    // And the tick after that — back in the caught-up steady state, interval just
    // consumed — stays quiet too: consecutive firings are impossible.
    let out = handler.run_iteration().await.expect("a steady-state tick");
    assert!(
        !out.reorg_detected,
        "a caught-up tick right after a firing must not rewind again"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((1000, Some(hex::encode(fill(0xaa))))),
        "the steady-state frontier is undisturbed"
    );
}

/// The bounded periodic rewind does NOT fire when the frontier is more than a
/// reorg window below the tip: that range is re-covered by the ordinary forward
/// scan (which re-anchors a real frontier hash), so a forced rewind there would be
/// pure churn. The wall-clock interval is long since elapsed, but a far-from-tip
/// tick is a no-op rewind.
#[tokio::test]
async fn the_bounded_periodic_rewind_does_not_fire_far_below_the_tip() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    let config = ScanConfig {
        bounded_rewind_interval_secs: 1, // a short interval the sleep below outlives
        ..ScanConfig::default()
    };
    // The frontier sits far below the tip (2000 blocks, well past the 30-block
    // window), with a real hash. The interval elapses before the tick, but the
    // far-from-tip guard must suppress the rewind.
    sqlx::query(
        "INSERT INTO cw_core.indexer_cursor \
           (network, last_processed_block_height, last_processed_block_hash) \
         VALUES ($1, 1000, $2)",
    )
    .bind(NETWORK)
    .bind(hex::encode(fill(0xaa)))
    .execute(&db.pool)
    .await
    .expect("seed a far-below-tip frontier");
    gateway.set_tip(3000);
    // No forward-scan records: the ordinary forward fetch returns empty/caught-up,
    // so the only thing that could move the cursor is a (suppressed) rewind.
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        config,
    );
    // Outlive the interval so the cadence is due; only the far-from-tip guard
    // can suppress the rewind now.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let out = handler.run_iteration().await.expect("a far-below-tip tick");
    assert!(
        !out.reorg_detected,
        "the bounded rewind is suppressed far below the tip"
    );
    // The key assertion is that no rewind happened: the cursor did not move
    // BACKWARD to 970. The forward fetch returned an empty caught-up result with no
    // resolvable tip-block hash, so the frontier is left in place rather than
    // overwritten with a NULL hash.
    let (height, _hash) = cursor_state(&db.pool).await.expect("the cursor row exists");
    assert!(
        height >= 1000,
        "a far-below-tip tick never rewinds the cursor below its frontier"
    );
}

// ---------------------------------------------------------------------------
// Golden sequence: reorg at the scan frontier.
// ---------------------------------------------------------------------------

/// A reorg at the scan frontier: the stored frontier hash no longer matches the
/// block the gateway now reports at that height. The commit deletes every
/// `chain_records` row above the rewind boundary, purges every pool entry above
/// it, rewinds the cursor, and the re-scan re-inserts the surviving record at its
/// (new) height on the valid branch. This tick's candidates are discarded.
#[tokio::test]
async fn a_frontier_reorg_rewinds_deletes_above_and_rescans() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // Tick 1: index two records on what will become the invalidated branch, and
    // anchor the frontier at the last one (height 1000, hash 0xaa) by capping.
    gateway.push_capped(vec![
        record(0x01, 0x90, 990, 40, open_record_cbor()),
        record(0x02, 0xaa, 1000, 30, open_record_cbor()),
    ]);
    gateway.set_tip(1010); // within the 30-block reorg window of the frontier.

    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    handler.run_iteration().await.expect("tick 1");
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((1000, Some(hex::encode(fill(0xaa))))),
        "the frontier anchored at the last record with hash 0xaa"
    );
    assert_eq!(persisted_hashes(&db.pool).await.len(), 2);

    // Also hold a pool entry above the rewind boundary so the reorg purge is
    // observable: index a below-threshold record at height 1005.
    sqlx::query(
        "INSERT INTO cw_core.confirmation_pool \
           (tx_hash, block_height, block_time, metadata_cbor, item_count, scheme) \
         VALUES ($1, 1005, now(), $2, 1, 0)",
    )
    .bind(fill(0x03).as_slice())
    .bind(open_record_cbor())
    .execute(&db.pool)
    .await
    .expect("seed a pool entry above the rewind boundary");

    // Tick 2: the gateway now reports a DIFFERENT hash at the frontier height
    // 1000 (the block was reorged out), so reorg detection fires. The rewind
    // boundary is 1000 - 30 = 970, so everything above 970 is deleted/purged.
    gateway.set_block(BlockInfo {
        block_height: 1000,
        block_hash: fill(0xbb), // != the stored 0xaa
        block_time: block_time(),
    });
    let out = handler.run_iteration().await.expect("tick 2");
    assert!(out.reorg_detected, "a frontier-hash mismatch is a reorg");
    assert_eq!(
        out.records_persisted, 0,
        "the tick's candidates are discarded"
    );

    // Both records above the rewind boundary (990 and 1000 are both > 970) are
    // deleted; the pool entry at 1005 is purged.
    assert!(
        persisted_hashes(&db.pool).await.is_empty(),
        "every chain_records row above the rewind boundary is deleted"
    );
    assert!(
        pool_hashes(&db.pool).await.is_empty(),
        "every pool entry above the rewind boundary is purged"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((970, None)),
        "the cursor rewinds 30 blocks below the frontier with a null hash"
    );

    // Tick 3: the re-scan from 970 (a NULL-hash frontier, so reorg detection skips
    // naturally) re-discovers the surviving record on the valid branch at its NEW
    // height (1001) with enough confirmations to persist, and inserts it fresh.
    gateway.set_tip(1030); // 1030 - 1001 + 1 = 30 confirmations, over threshold.
    gateway.push_caught_up(vec![record(0x01, 0x91, 1001, 30, open_record_cbor())], 1030);
    handler.run_iteration().await.expect("tick 3");
    let row = persisted_row(&db.pool, fill(0x01))
        .await
        .expect("the surviving record is re-inserted");
    assert_eq!(
        row.block_height, 1001,
        "the re-inserted record records its NEW height on the valid branch"
    );
}

// ---------------------------------------------------------------------------
// Golden sequence: restart resilience (durable pool + cursor).
// ---------------------------------------------------------------------------

/// The durable pool survives a process restart: a below-threshold record pooled
/// by one handler is promoted by a FRESH handler (a new in-memory state, as after
/// a restart), proving the pool is not lost the way a process-memory pool would
/// be. The cursor likewise resumes from its durable row.
#[tokio::test]
async fn the_durable_pool_and_cursor_survive_a_restart() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();
    let (sealed, _signer) = sealed_signed_record_cbor(&fill(0x77));

    // Handler A pools a below-threshold record and advances the cursor.
    gateway.push_capped(vec![record(0xf1, 0xf2, 500, 3, sealed)]);
    gateway.set_tip(502);
    {
        let handler_a = ScanHandler::new(
            db.pool.clone(),
            gateway.clone(),
            ParamsNetwork::Preprod,
            scan_config(),
        );
        handler_a.run_iteration().await.expect("handler A tick");
    }
    assert_eq!(
        pool_hashes(&db.pool).await,
        BTreeSet::from([fill(0xf1).to_vec()]),
        "handler A left the record in the durable pool"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((500, Some(hex::encode(fill(0xf2))))),
        "handler A advanced the durable cursor"
    );

    // Simulate a restart: drop handler A, build a brand-new handler B with its own
    // (empty) in-memory state. A process-memory pool would be empty here; the
    // durable pool is not. Advance the tip so the re-check promotes the entry. The
    // frontier block (height 500) still has its real hash on the valid chain, so
    // reorg detection at the resumed frontier sees a match and does not fire.
    gateway.set_block(BlockInfo {
        block_height: 500,
        block_hash: fill(0xf2),
        block_time: block_time(),
    });
    gateway.set_tip(520);
    // The pooled record is still on chain at its height, so the re-check's
    // chain-truth verification confirms it and the promotion proceeds.
    gateway.set_confirmation(fill(0xf1), on_chain_confirmation(500));
    let handler_b = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    handler_b.run_iteration().await.expect("handler B tick");

    assert!(
        pool_hashes(&db.pool).await.is_empty(),
        "the restarted handler found the record in the durable pool and promoted it"
    );
    assert!(
        persisted_hashes(&db.pool).await.contains(fill(0xf1).as_slice()),
        "the record the first process pooled is persisted by the second (no empty-pool-at-boot loss)"
    );
}

// ---------------------------------------------------------------------------
// Golden sequence: startup self-heal (both cases).
// ---------------------------------------------------------------------------

/// Self-heal Case A: an empty `chain_records` with an advanced cursor (a dropped
/// index left a stale cursor) resets the cursor to genesis for a full re-scan.
#[tokio::test]
async fn self_heal_case_a_resets_an_advanced_cursor_over_an_empty_index() {
    let db = TestDb::fresh().await.expect("db");
    // Advance the cursor with no chain_records rows behind it.
    sqlx::query(
        "INSERT INTO cw_core.indexer_cursor \
           (network, last_processed_block_height, last_processed_block_hash) \
         VALUES ($1, 5000, $2)",
    )
    .bind(NETWORK)
    .bind(hex::encode(fill(0x12)))
    .execute(&db.pool)
    .await
    .expect("seed an advanced cursor");

    let gateway = ScriptedGateway::new();
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway,
        ParamsNetwork::Preprod,
        scan_config(),
    );
    let outcome = handler.self_heal_cursor().await.expect("self-heal");

    assert!(outcome.healed);
    assert_eq!(outcome.reason, SelfHealReason::EmptyChainRecords);
    assert_eq!(outcome.previous_height, 5000);
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((0, None)),
        "the cursor resets to genesis for a full re-scan"
    );
}

/// Self-heal Case B: a confirmed `poe_record` whose transaction is absent from
/// `chain_records` (the scan advanced past its block) rewinds the cursor to one
/// reorg window below the missed block, so the forward scan re-covers it.
#[tokio::test]
async fn self_heal_case_b_rewinds_below_a_missed_confirmed_record() {
    let db = TestDb::fresh().await.expect("db");

    // A confirmed record at height 1000 that the scan never persisted.
    seed_confirmed_record(&db.pool, fill(0x33), 1000).await;

    // Persist an UNRELATED record so chain_records is non-empty (Case A must not
    // fire; Case B must). chain_records.tx_hash FK-references the cw_api.records
    // anchor, so seed the anchor first (the single writer does both in one
    // statement; a raw-SQL seed mirrors that ordering).
    sqlx::query("INSERT INTO cw_api.records (tx_hash) VALUES ($1)")
        .bind(fill(0x44).as_slice())
        .execute(&db.pool)
        .await
        .expect("seed record anchor");
    sqlx::query(
        "INSERT INTO cw_core.chain_records \
           (tx_hash, block_height, block_time, metadata_cbor, item_count, scheme) \
         VALUES ($1, 2000, now(), $2, 1, 0)",
    )
    .bind(fill(0x44).as_slice())
    .bind(open_record_cbor())
    .execute(&db.pool)
    .await
    .expect("seed an unrelated indexed record");

    // The cursor has advanced past the missed record's block.
    sqlx::query(
        "INSERT INTO cw_core.indexer_cursor \
           (network, last_processed_block_height, last_processed_block_hash) \
         VALUES ($1, 3000, $2)",
    )
    .bind(NETWORK)
    .bind(hex::encode(fill(0x55)))
    .execute(&db.pool)
    .await
    .expect("seed an advanced cursor");

    let gateway = ScriptedGateway::new();
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway,
        ParamsNetwork::Preprod,
        scan_config(),
    );
    let outcome = handler.self_heal_cursor().await.expect("self-heal");

    assert!(outcome.healed);
    assert_eq!(outcome.reason, SelfHealReason::MissingPublishedRecord);
    assert_eq!(
        cursor_state(&db.pool).await,
        // 1000 - 30 (the reorg window) = 970, with a null hash for a clean re-scan.
        Some((970, None)),
        "the cursor rewinds one reorg window below the missed block"
    );
}

// ---------------------------------------------------------------------------
// Golden sequence: tx_cbor backfill + COALESCE conflict semantics.
// ---------------------------------------------------------------------------

/// The bounded backfill fills a row inserted with NULL `tx_cbor`, and a later
/// conflicting re-observation never clobbers bytes already stored: the COALESCE
/// conflict clause keeps the first bytes that landed.
#[tokio::test]
async fn tx_cbor_backfill_fills_null_rows_and_coalesce_never_clobbers() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // Tick 1: a confirmed record whose full transaction bytes are NOT yet
    // resolvable (the gateway has no CBOR for it), so it persists with NULL.
    gateway.push_caught_up(vec![record(0x61, 0x71, 100, 50, open_record_cbor())], 200);
    gateway.set_tip(200);
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    handler.run_iteration().await.expect("tick 1");

    let row = persisted_row(&db.pool, fill(0x61))
        .await
        .expect("persisted");
    assert_eq!(row.tx_cbor, None, "the row persisted with a NULL tx_cbor");

    // Now the bytes become resolvable; the next tick's backfill fills them.
    gateway.set_cbor(fill(0x61), vec![0xde, 0xad, 0xbe, 0xef]);
    let filled = handler.backfill_tx_cbor().await.expect("backfill");
    assert_eq!(filled, 1, "the backfill filled exactly the one NULL row");
    let row = persisted_row(&db.pool, fill(0x61))
        .await
        .expect("persisted");
    assert_eq!(
        row.tx_cbor,
        Some(vec![0xde, 0xad, 0xbe, 0xef]),
        "the backfill wrote the resolved transaction bytes"
    );

    // A conflicting re-observation arrives carrying DIFFERENT bytes. The COALESCE
    // conflict clause must keep the bytes already stored, never clobber them.
    gateway.set_cbor(fill(0x61), vec![0x00, 0x00]);
    gateway.push_caught_up(vec![record(0x61, 0x71, 100, 60, open_record_cbor())], 200);
    handler.run_iteration().await.expect("re-observation tick");
    let row = persisted_row(&db.pool, fill(0x61))
        .await
        .expect("persisted");
    assert_eq!(
        row.tx_cbor,
        Some(vec![0xde, 0xad, 0xbe, 0xef]),
        "COALESCE preserves the first stored bytes; a re-observation never clobbers them"
    );
}

// ---------------------------------------------------------------------------
// Golden sequence: all-429 storm parks the loop.
// ---------------------------------------------------------------------------

/// A REAL all-provider 429 storm, driven through a production `FailoverGateway`
/// whose primary AND secondary both return HTTP 429, parks the loop: the iteration
/// outcome carries a cooldown instant and NO state changes (no records, no pool
/// entry, no cursor advance), and the wrapper persisted a cooldown on BOTH
/// providers. The handler turns the rate-limited outcome into a Defer, which never
/// burns the single attempt the queue allows.
#[tokio::test]
async fn an_all_429_storm_through_real_failover_parks_the_loop_without_changing_state() {
    let db = TestDb::fresh().await.expect("db");

    // Both providers 429 on every call, so the scan's head-of-tick tip refresh is
    // a genuine all-provider storm rather than a synthesised marker.
    let gateway: FailoverGateway<RateLimitedGateway, RateLimitedGateway> = FailoverGateway::new(
        RateLimitedGateway,
        RateLimitedGateway,
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        ProviderCooldown::new(db.pool.clone()),
        ParamsNetwork::Preprod,
    );

    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway,
        ParamsNetwork::Preprod,
        scan_config(),
    );
    let out = handler
        .run_iteration()
        .await
        .expect("the storm never fails the iteration");

    assert!(
        out.rate_limited_until.is_some(),
        "a real primary+secondary 429 is an all-provider rate-limit storm"
    );
    assert_eq!(out.records_persisted, 0);
    assert!(
        persisted_hashes(&db.pool).await.is_empty(),
        "the storm mutates no chain_records"
    );
    assert!(
        pool_hashes(&db.pool).await.is_empty(),
        "the storm mutates no pool"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        None,
        "the storm leaves the cursor untouched (no advance on a tick it could not observe)"
    );

    // Both providers were cooled down by the storm path.
    let cooldown = ProviderCooldown::new(db.pool.clone());
    assert!(
        cooldown
            .active_until(ProviderKind::Koios, ParamsNetwork::Preprod)
            .await
            .expect("read koios cooldown")
            .is_some(),
        "the primary's cooldown is engaged"
    );
    assert!(
        cooldown
            .active_until(ProviderKind::Blockfrost, ParamsNetwork::Preprod)
            .await
            .expect("read blockfrost cooldown")
            .is_some(),
        "the secondary's cooldown is engaged too on an all-provider storm"
    );
}

// ---------------------------------------------------------------------------
// Defense-in-depth: the scan handler serializes on the advisory lock.
// ---------------------------------------------------------------------------

/// The scan handler takes the scan advisory lock for the duration of an iteration.
/// When another session already holds the lock (a stray second replica running the
/// cron tick), the handler skips the tick as a no-op rather than running a second
/// concurrent iteration: it never advances the cursor or persists a record while
/// contended, and never fails the job.
#[tokio::test]
async fn scan_handler_skips_the_tick_when_the_advisory_lock_is_held() {
    let db = TestDb::fresh().await.expect("db");

    // Seed a forward fetch that WOULD persist a record and advance the cursor if
    // the iteration ran, so "skipped" is observable as the absence of those
    // mutations.
    let gateway = ScriptedGateway::new();
    gateway.set_tip(200);
    gateway.push_caught_up(vec![record(0x42, 0xb0, 100, 50, open_record_cbor())], 200);

    // Hold the scan advisory lock from this test, simulating another replica
    // mid-iteration.
    let held = AdvisoryLock::try_acquire(&db.pool, SCAN_ADVISORY_LOCK)
        .await
        .expect("acquire lock")
        .expect("the lock is free at the start of the test");

    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    let outcome = handler.handle(scan_ctx()).await;

    // A contended tick is a no-op completion, never a failure.
    assert!(
        matches!(outcome, JobOutcome::Complete),
        "a contended scan tick completes as a no-op, got {outcome:?}"
    );
    assert!(
        persisted_hashes(&db.pool).await.is_empty(),
        "the contended tick persisted nothing"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        None,
        "the contended tick advanced no cursor"
    );
    assert!(
        gateway.calls().is_empty(),
        "the contended tick never reached the gateway"
    );

    // Once the lock is released, the next tick runs and persists the record,
    // proving the lock (not a permanent skip) was what gated the iteration.
    held.release().await.expect("release lock");
    let outcome = handler.handle(scan_ctx()).await;
    assert!(
        matches!(outcome, JobOutcome::Defer { .. }),
        "an uncontended tick runs and self-paces with a Defer, got {outcome:?}"
    );
    assert_eq!(
        persisted_hashes(&db.pool).await.len(),
        1,
        "the uncontended tick persisted the record"
    );
}

/// A job context for invoking the scan handler directly (the values the runtime
/// would supply for a singleton-loop attempt).
fn scan_ctx() -> JobContext {
    JobContext {
        job_id: Uuid::now_v7(),
        queue: SCAN_QUEUE.to_string(),
        payload: serde_json::Value::Null,
        attempt: 1,
        is_final_attempt: true,
        defer_count: 0,
    }
}

/// A caught-up scan PARKS: with the cursor at the tip, an empty pool, and no
/// record awaiting confirmation, the handler defers itself for the full idle
/// cadence — never an immediate (or active-cadence) re-enqueue — and a tick
/// costs exactly one provider call (the `/tip` read). This is the regression
/// guard for the cadence collapse that ran iterations back-to-back at HTTP
/// latency and burned the providers' daily request quotas.
#[tokio::test]
async fn a_caught_up_scan_parks_for_the_idle_cadence() {
    use gateway_core::chain::scan::SCAN_IDLE_POLL_SECS;

    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // Caught up: the frontier sits at the tip with a real hash. No pool entries,
    // no submitted poe_record rows (a fresh database has neither).
    gateway.set_tip(5000);
    sqlx::query(
        "INSERT INTO cw_core.indexer_cursor \
           (network, last_processed_block_height, last_processed_block_hash) \
         VALUES ($1, 5000, $2)",
    )
    .bind(NETWORK)
    .bind(hex::encode(fill(0xcc)))
    .execute(&db.pool)
    .await
    .expect("seed a caught-up frontier");

    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );

    for tick in 1..=2 {
        let before = chrono::Utc::now();
        let outcome = handler.handle(scan_ctx()).await;
        let JobOutcome::Defer { until } = outcome else {
            panic!("a caught-up tick must self-pace with a Defer, got {outcome:?}");
        };
        let delay = (until - before).num_seconds();
        assert!(
            delay >= SCAN_IDLE_POLL_SECS - 2,
            "tick {tick}: a caught-up scan parks for the idle cadence \
             (~{SCAN_IDLE_POLL_SECS}s), got a {delay}s defer"
        );
    }

    // Each caught-up tick made no forward fetch: the only provider traffic is the
    // tip read, so the steady-state budget is one call per idle interval.
    assert!(
        gateway.calls().is_empty(),
        "a caught-up tick never runs the forward fetch"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((5000, Some(hex::encode(fill(0xcc))))),
        "a caught-up tick leaves the frontier exactly where it was"
    );
}

// ---------------------------------------------------------------------------
// Index completeness: the cursor never advances past a height the answering
// provider could not see, nor past a hydration gap, so a permanently lost
// record (a recipient never sees their sealed message) is impossible.
// ---------------------------------------------------------------------------

/// The answering provider's metadata index LAGS the observed tip (Blockfrost
/// behind the Koios tip). The provider reports it is caught up only to its own
/// watermark, BELOW the tip. The cursor must clamp to that watermark and never
/// jump to the tip, or the lag gap [watermark, tip] is skipped forever and any
/// record landing in it is never indexed.
#[tokio::test]
async fn a_provider_lagging_the_tip_advances_only_to_its_own_watermark() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // The observed tip is 5000, but the answering provider has only indexed
    // metadata up to block 4000 (its watermark). It returns its records up to 4000
    // and reports caught-up to 4000, NOT to the tip.
    gateway.push_caught_up(
        vec![record(0x01, 0xa1, 3990, 1011, open_record_cbor())],
        4000,
    );
    gateway.set_tip(5000);
    // The watermark block (4000) carries a real hash the caught-up jump anchors on.
    gateway.set_block(BlockInfo {
        block_height: 4000,
        block_hash: fill(0x40),
        block_time: block_time(),
    });

    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    handler
        .run_iteration()
        .await
        .expect("lagging-provider tick");

    assert_eq!(
        cursor_state(&db.pool).await,
        Some((4000, Some(hex::encode(fill(0x40))))),
        "the cursor clamps to the provider's own watermark (4000), never the tip (5000); \
         the lag gap (4000, 5000] is re-read next tick, never skipped"
    );

    // The next tick: the provider has caught up to the tip and surfaces a record
    // that lived in the former lag gap. It is now discovered and indexed — proving
    // the gap was a re-tried barrier, not a permanent skip.
    gateway.push_caught_up(
        vec![record(0x02, 0xa2, 4500, 501, open_record_cbor())],
        5000,
    );
    gateway.set_block(BlockInfo {
        block_height: 4000,
        block_hash: fill(0x40),
        block_time: block_time(),
    });
    gateway.set_block(BlockInfo {
        block_height: 5000,
        block_hash: fill(0x50),
        block_time: block_time(),
    });
    handler.run_iteration().await.expect("recovery tick");

    assert!(
        persisted_hashes(&db.pool)
            .await
            .contains(fill(0x02).as_slice()),
        "the record that lived in the former lag gap is indexed once the provider catches up"
    );
    // The second forward fetch resumed strictly above the clamped watermark.
    let calls = gateway.calls();
    assert_eq!(
        calls[1].0, 4000,
        "the recovery tick resumes from the clamped watermark, re-covering the gap"
    );
}

/// A hydration gap (the list proved a record exists, but its bytes did not
/// hydrate) halts the cursor BELOW the gap; the next tick, once the bytes
/// hydrate, re-discovers and indexes the record. Driven at the handler level: the
/// scripted gateway returns an `Anchor` below the gap on tick 1 (the resolver's
/// gap-clamp output), then the full set on tick 2.
#[tokio::test]
async fn a_hydration_gap_halts_below_it_and_the_next_tick_recovers_the_record() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // Tick 1: the record at block 600 hydrated, but a higher one (block 605) is a
    // hydration gap — so the fetch emits only the hydrated record and anchors the
    // frontier at 600 (strictly below the gap), exactly as the provider resolver
    // does. The cursor must stop at 600, never advance toward the tip past 605.
    gateway.push_capped(vec![record(0x01, 0xb1, 600, 100, open_record_cbor())]);
    gateway.set_tip(700);
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    handler.run_iteration().await.expect("gap tick");

    assert_eq!(
        cursor_state(&db.pool).await,
        Some((600, Some(hex::encode(fill(0xb1))))),
        "the cursor anchors strictly below the hydration gap, never advances past it"
    );
    assert!(
        !persisted_hashes(&db.pool)
            .await
            .contains(fill(0x02).as_slice()),
        "the un-hydrated record at the gap is not indexed yet"
    );

    // Tick 2: the gap's bytes have hydrated; the fetch (resuming from 600) now
    // surfaces the record at 605 and reaches the head. It is indexed — the gap was
    // re-tried, not lost.
    gateway.push_caught_up(vec![record(0x02, 0xb2, 605, 96, open_record_cbor())], 700);
    gateway.set_block(BlockInfo {
        block_height: 600,
        block_hash: fill(0xb1),
        block_time: block_time(),
    });
    gateway.set_block(BlockInfo {
        block_height: 700,
        block_hash: fill(0x70),
        block_time: block_time(),
    });
    handler.run_iteration().await.expect("recovery tick");

    assert!(
        persisted_hashes(&db.pool)
            .await
            .contains(fill(0x02).as_slice()),
        "the formerly-un-hydrated record is indexed once its bytes hydrate"
    );
    let calls = gateway.calls();
    assert_eq!(
        calls[1].0, 600,
        "the recovery tick re-fetches strictly above the gap-clamped frontier"
    );
}

/// A regressed observed tip (a stale fallback `/tip`, a provider whose tip went
/// backwards) must NOT make the scan look caught-up and stall, nor let the cursor
/// regress. The materialised tip is monotonic, so the scan always works against
/// the highest tip ever seen.
#[tokio::test]
async fn a_regressed_observed_tip_neither_stalls_nor_regresses_the_scan() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // Tick 1: tip 5000, a capped batch anchors the frontier at 4000.
    gateway.push_capped(vec![record(0x01, 0xc1, 4000, 1001, open_record_cbor())]);
    gateway.set_tip(5000);
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        scan_config(),
    );
    handler.run_iteration().await.expect("tick 1");
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((4000, Some(hex::encode(fill(0xc1))))),
        "tick 1 anchors the frontier at 4000 under the tip of 5000"
    );

    // Tick 2: the provider's tip REGRESSES to 4500 (a stale fallback read). A naive
    // raw-tip path would compare the cursor (4000) against 4500 and still scan, but
    // worse, a regression below the cursor would short-circuit as caught-up. The
    // materialised tip stays at 5000 (monotonic), so the scan keeps working against
    // 5000: it runs a real forward fetch and advances, never stalls.
    gateway.set_tip(4500);
    gateway.push_capped(vec![record(0x02, 0xc2, 4600, 401, open_record_cbor())]);
    let outcome = handler.run_iteration().await.expect("tick 2");
    assert_eq!(
        outcome.tip_height, 5000,
        "the scan works against the monotonic materialised tip, never the regressed observation"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((4600, Some(hex::encode(fill(0xc2))))),
        "the cursor advances forward despite the regressed observed tip; it never stalls or regresses"
    );
}

// ---------------------------------------------------------------------------
// Stuck-gap liveness: a hydration gap one provider cannot resolve must not stall
// the whole feed (the other provider recovers it), and a gap NEITHER can resolve
// must hold the cursor AND alert (never silently stall, never lose a record).
// ---------------------------------------------------------------------------

/// A `Hold` (the answering/primary provider could not hydrate the lowest record
/// above the cursor) is recovered by the ALTERNATE provider: the scan escalates to
/// the other provider for the stuck window, which resolves the gap, so the cursor
/// advances and the feed keeps moving. One provider's blind spot never stalls the
/// global feed when the other can see the record.
#[tokio::test]
async fn a_stuck_gap_is_recovered_by_the_alternate_provider() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // The primary forward fetch holds: the transaction at the frontier cannot be
    // hydrated by the primary, so there is no safe height to advance to.
    gateway.push_hold();
    // The ALTERNATE provider CAN hydrate it: it returns the record and is caught up
    // to the tip, resolving the gap.
    gateway.push_alternate_caught_up(vec![record(0x01, 0xa1, 700, 301, open_record_cbor())], 1000);
    gateway.set_tip(1000);
    gateway.set_block(BlockInfo {
        block_height: 1000,
        block_hash: fill(0xa0),
        block_time: block_time(),
    });

    // `stuck_gap_alternate_after_ticks: 1` so the very first stuck tick already
    // tries the alternate provider.
    let config = ScanConfig {
        bounded_rewind_interval_secs: 0,
        stuck_gap_alternate_after_ticks: 1,
        stuck_gap_alert_after_ticks: 5,
        ..ScanConfig::default()
    };
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        config,
    );
    let outcome = handler
        .run_iteration()
        .await
        .expect("stuck-then-recover tick");

    // The alternate provider was reached, the gap's record is indexed, the cursor
    // advanced, and no stall was recorded.
    assert_eq!(
        gateway.alternate_calls(),
        1,
        "the stuck-gap recovery reached for the alternate provider"
    );
    assert!(
        persisted_hashes(&db.pool)
            .await
            .contains(fill(0x01).as_slice()),
        "the record the primary could not hydrate is indexed via the alternate provider"
    );
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((1000, Some(hex::encode(fill(0xa0))))),
        "the cursor advances to the tip once the alternate provider resolves the gap"
    );
    assert_eq!(
        stuck_gap_state(&db.pool).await,
        Some((None, 0)),
        "a recovered gap clears the stuck tracking"
    );
    assert!(
        outcome.stuck_gap_alert.is_none(),
        "a recovered gap raises no alert"
    );
}

/// The alternate provider reaching its OWN tip without advancing past the gap is
/// NOT a recovery: a `reached_chain_head` whose watermark sits at or below the
/// cursor (the alternate is also caught up to its lagging watermark, with the gap
/// still un-hydrated below the real tip) advances nothing, so the stall must stay
/// tracked — never falsely cleared by a head-reached-but-no-progress alternate.
#[tokio::test]
async fn an_alternate_reaching_head_without_advancing_does_not_clear_the_stall() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();

    // Establish a real frontier at 500 first.
    gateway.push_capped(vec![record(0x01, 0xb1, 500, 600, open_record_cbor())]);
    gateway.set_tip(1000);
    let config = ScanConfig {
        bounded_rewind_interval_secs: 0,
        stuck_gap_alternate_after_ticks: 1,
        stuck_gap_alert_after_ticks: 5,
        ..ScanConfig::default()
    };
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        config,
    );
    handler
        .run_iteration()
        .await
        .expect("tick 1 anchors at 500");
    assert_eq!(cursor_state(&db.pool).await.map(|(h, _)| h), Some(500));

    // Tick 2: the primary holds at the frontier (cannot hydrate the gap above 500).
    // The alternate reports caught-up to a watermark AT the cursor (500) — it has
    // nothing above 500 to offer either, so `min(tip, 500) = 500 <= cursor`: it
    // reaches its head but advances NOTHING. This must NOT clear the stall.
    gateway.push_hold();
    gateway.push_alternate_caught_up(Vec::new(), 500);
    let outcome = handler.run_iteration().await.expect("stuck tick 2");

    assert_eq!(
        gateway.alternate_calls(),
        1,
        "the alternate provider was consulted"
    );
    assert_eq!(
        cursor_state(&db.pool).await.map(|(h, _)| h),
        Some(500),
        "the cursor stays put: a head-reached-but-no-advance alternate is not progress"
    );
    assert_eq!(
        stuck_gap_state(&db.pool).await,
        Some((Some(500), 1)),
        "the stall stays tracked (recorded at the frontier), never falsely cleared"
    );
    assert!(
        outcome.stuck_gap_alert.is_none(),
        "below the alert threshold, no alert yet — but the stall is still recorded"
    );
}

/// A gap NEITHER provider can hydrate holds the cursor (never advances past the
/// gap, so no record above it is lost) AND, once the stall outlives the alert
/// threshold, fires an operator-visible alert so an indefinite stall is never
/// silent. This is the floor: never-advance + observable.
#[tokio::test]
async fn a_gap_neither_provider_can_hydrate_holds_and_alerts() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();
    gateway.set_tip(1000);

    // Both the primary and the alternate hold on every tick (the alternate script
    // is left empty, so the alternate also answers `Hold`). Seed the primary script
    // with holds for every tick.
    let config = ScanConfig {
        bounded_rewind_interval_secs: 0,
        stuck_gap_alternate_after_ticks: 1,
        stuck_gap_alert_after_ticks: 3,
        ..ScanConfig::default()
    };
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        config,
    );

    // Ticks 1 and 2: stuck, below the alert threshold (3). The cursor holds at
    // genesis (0) and the stuck count accumulates.
    for tick in 1..=2u32 {
        gateway.push_hold();
        let outcome = handler.run_iteration().await.expect("stuck tick");
        assert_eq!(
            cursor_state(&db.pool).await.map(|(h, _)| h),
            Some(0),
            "tick {tick}: the cursor never advances past the un-hydratable gap"
        );
        assert!(
            persisted_hashes(&db.pool).await.is_empty(),
            "tick {tick}: nothing above the gap is indexed"
        );
        assert!(
            outcome.stuck_gap_alert.is_none(),
            "tick {tick}: below the alert threshold, no alert yet"
        );
    }
    assert_eq!(
        stuck_gap_state(&db.pool).await,
        Some((Some(0), 2)),
        "the stuck tracking accumulated two consecutive stuck ticks at the genesis frontier"
    );

    // Tick 3: still stuck, now at the alert threshold. The cursor still holds (never
    // skips the record) and an operator alert fires.
    gateway.push_hold();
    let outcome = handler.run_iteration().await.expect("alerting stuck tick");
    assert_eq!(
        cursor_state(&db.pool).await.map(|(h, _)| h),
        Some(0),
        "the cursor still holds at the alert threshold: a record is never skipped to break a stall"
    );
    let alert = outcome
        .stuck_gap_alert
        .expect("a stall past the threshold fires an operator alert");
    assert_eq!(alert.height, 0, "the alert names the stuck frontier height");
    assert_eq!(
        alert.tick_count, 3,
        "the alert carries the consecutive stuck count"
    );
    assert!(
        alert.alternate_attempted,
        "the alert records that the alternate-provider recovery was attempted and still failed"
    );
    // The alternate was tried on every stuck tick (threshold 1).
    assert_eq!(gateway.alternate_calls(), 3);

    // Tick 4: still stuck, now PAST the threshold. The alert must NOT fire again —
    // it fires exactly once when the stall first crosses the threshold, never every
    // tick beyond it (no operator-alert spam). The cursor still holds and the stuck
    // count keeps climbing so the durable state still reflects the ongoing stall.
    gateway.push_hold();
    let outcome = handler
        .run_iteration()
        .await
        .expect("post-threshold stuck tick");
    assert!(
        outcome.stuck_gap_alert.is_none(),
        "the alert fires once at the threshold, not on every subsequent stuck tick"
    );
    assert_eq!(
        cursor_state(&db.pool).await.map(|(h, _)| h),
        Some(0),
        "the cursor still holds past the threshold: a record is never skipped"
    );
    assert_eq!(
        stuck_gap_state(&db.pool).await,
        Some((Some(0), 4)),
        "the durable stuck count keeps climbing while the stall persists"
    );
}

/// Transient-tick cursor invariance on a real DB: the cursor is UNCHANGED after a
/// stuck (non-advancing) tick and ADVANCES once the gap recovers — the cursor only
/// ever moves on real progress, never on a failed/held tick.
#[tokio::test]
async fn the_cursor_is_invariant_across_a_stuck_tick_and_advances_on_recovery() {
    let db = TestDb::fresh().await.expect("db");
    let gateway = ScriptedGateway::new();
    gateway.set_tip(1000);

    // Establish a real frontier first (so "unchanged" is observable as staying at a
    // non-genesis height across the stuck tick).
    gateway.push_capped(vec![record(0x01, 0xb1, 500, 600, open_record_cbor())]);
    // Disable the alternate recovery for the stall tick so the stuck-hold is
    // observable as an unchanged cursor (the alternate would otherwise resolve it).
    let config = ScanConfig {
        bounded_rewind_interval_secs: 0,
        stuck_gap_alternate_after_ticks: 0, // disabled
        stuck_gap_alert_after_ticks: 0,     // disabled
        ..ScanConfig::default()
    };
    let handler = ScanHandler::new(
        db.pool.clone(),
        gateway.clone(),
        ParamsNetwork::Preprod,
        config,
    );

    handler
        .run_iteration()
        .await
        .expect("tick 1 establishes the frontier");
    let after_first = cursor_state(&db.pool).await;
    assert_eq!(
        after_first,
        Some((500, Some(hex::encode(fill(0xb1))))),
        "tick 1 anchors the frontier at 500"
    );

    // Tick 2: a stuck hold. The cursor must be UNCHANGED (no advance, no regress).
    gateway.push_hold();
    handler.run_iteration().await.expect("stuck tick 2");
    assert_eq!(
        cursor_state(&db.pool).await,
        after_first,
        "a stuck tick leaves the cursor exactly where it was: it moves only on real progress"
    );

    // Tick 3: the gap recovers (the provider now hydrates the record above 500). The
    // cursor advances.
    gateway.set_block(BlockInfo {
        block_height: 1000,
        block_hash: fill(0xb0),
        block_time: block_time(),
    });
    gateway.push_caught_up(vec![record(0x02, 0xb2, 600, 401, open_record_cbor())], 1000);
    handler.run_iteration().await.expect("recovery tick 3");
    assert_eq!(
        cursor_state(&db.pool).await,
        Some((1000, Some(hex::encode(fill(0xb0))))),
        "the cursor advances once the gap recovers"
    );
    assert!(
        persisted_hashes(&db.pool)
            .await
            .contains(fill(0x02).as_slice()),
        "the formerly-stuck record is indexed on recovery"
    );
}

// ===========================================================================
// Read-feed index readiness: the spec's pagination/filter query shapes plan
// against the read-feed indexes, never a sequential scan of chain_records.
// ===========================================================================

/// The text plan for a query, as a single string for substring assertions.
async fn explain(pool: &sqlx::PgPool, query: &str) -> String {
    let rows: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("EXPLAIN {query}")))
        .fetch_all(pool)
        .await
        .unwrap_or_else(|e| panic!("EXPLAIN failed for {query}: {e}"));
    rows.join("\n")
}

/// Seed enough `chain_records` rows that the planner prefers an index over a
/// sequential scan on the read-feed query shapes. A mix of schemes and a handful
/// of distinct signers exercises the sealed partial index and the signer index.
async fn seed_chain_records_for_explain(pool: &sqlx::PgPool, count: i64) {
    // Each chain_records row references its cw_api.records anchor, so seed the
    // anchors first over the same key range.
    sqlx::query(
        "INSERT INTO cw_api.records (tx_hash) \
         SELECT decode(lpad(to_hex(g), 64, '0'), 'hex') \
         FROM generate_series(1, $1) AS g",
    )
    .bind(count)
    .execute(pool)
    .await
    .expect("seed record anchors for the explain corpus");
    sqlx::query(
        "INSERT INTO cw_core.chain_records \
           (tx_hash, block_height, block_time, metadata_cbor, signer_ed25519, item_count, scheme) \
         SELECT \
           decode(lpad(to_hex(g), 64, '0'), 'hex'), \
           g, \
           now() - (g || ' seconds')::interval, \
           '\\xa101'::bytea, \
           decode(lpad(to_hex(g % 7), 64, '0'), 'hex'), \
           1, \
           (g % 3)::smallint \
         FROM generate_series(1, $1) AS g",
    )
    .bind(count)
    .execute(pool)
    .await
    .expect("seed chain_records for EXPLAIN");
    // ANALYZE so the planner has real statistics and does not fall back to a
    // sequential scan on a table it believes is tiny.
    sqlx::query(sqlx::AssertSqlSafe("ANALYZE cw_core.chain_records"))
        .execute(pool)
        .await
        .expect("analyze chain_records");
}

/// Read-feed readiness: keyset pagination, the signer filter, and the sealed
/// fast-path each plan against an index on `chain_records`, never a sequential
/// scan of the whole table. Proves the migrated access paths actually serve the
/// read feed's hot queries.
#[tokio::test]
async fn read_feed_query_shapes_use_the_indexes_not_a_seq_scan() {
    let db = TestDb::fresh().await.expect("test database");
    seed_chain_records_for_explain(&db.pool, 5_000).await;

    // Keyset pagination, newest-first within a block: the `(block_height, tx_hash)`
    // boundary the read feed walks. The ascending index serves the ORDER BY + the
    // tuple comparison.
    let pagination = "SELECT tx_hash, block_height FROM cw_core.chain_records \
         WHERE (block_height, tx_hash) > (2500, '\\x00'::bytea) \
         ORDER BY block_height, tx_hash LIMIT 50";
    let plan = explain(&db.pool, pagination).await;
    assert!(
        plan.contains("Index") && !plan.contains("Seq Scan on chain_records"),
        "keyset pagination must use an index, not a chain_records seq scan; plan was:\n{plan}"
    );

    // A single signer's records, newest-first: served by the signer index.
    let signer = "SELECT tx_hash, block_height FROM cw_core.chain_records \
         WHERE signer_ed25519 = decode(lpad(to_hex(3), 64, '0'), 'hex') \
         ORDER BY block_height DESC LIMIT 50";
    let plan = explain(&db.pool, signer).await;
    assert!(
        plan.contains("Index") && !plan.contains("Seq Scan on chain_records"),
        "the signer filter must use the signer index, not a chain_records seq scan; plan was:\n{plan}"
    );

    // The sealed-only feed: `scheme <> 0` (recipient-sealed AND passphrase rows),
    // newest-first — exactly the predicate the read feed's sealed filter reduces
    // to. It must be served by the partial sealed index, whose predicate matches
    // it verbatim; a narrower index predicate (the original `scheme = 1`) could
    // not serve this query and would push passphrase records onto wider scans.
    let sealed = "SELECT tx_hash, block_height FROM cw_core.chain_records \
         WHERE scheme <> 0 ORDER BY block_height DESC, tx_hash DESC LIMIT 50";
    let plan = explain(&db.pool, sealed).await;
    assert!(
        plan.contains("chain_records_sealed_idx"),
        "the sealed-only feed must plan against the partial sealed index; plan was:\n{plan}"
    );
}
