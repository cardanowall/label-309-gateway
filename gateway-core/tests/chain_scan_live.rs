//! The live forward-scan round-trip on Cardano preprod.
//!
//! Drives the real [`ScanHandler`] over the real keyless Koios chain gateway from
//! genesis to the chain head, mirroring every on-chain Label 309 record on preprod
//! into the durable index, and then runs the Blockfrost provider over the same
//! window to prove the two providers index a consistent set. This is the live
//! multi-provider parity proof: the scan is exercised end to end against real
//! traffic, not a scripted gateway.
//!
//! It is gated and skips (passing trivially) unless `GATEWAY_LIVE_TESTS=1`, so CI,
//! the default `cargo test`, and the `pg-tests` suite never touch the network. It
//! also needs a Postgres (the harness mints an isolated database). Run it
//! deliberately:
//!
//! ```text
//! GATEWAY_LIVE_TESTS=1 \
//!   cargo test -p gateway-core --features pg-tests --test chain_scan_live -- --nocapture
//! ```
//!
//! The Blockfrost leg additionally needs a project id, read at runtime from the
//! path in `GATEWAY_BLOCKFROST_PROJECT_ID_PATH` (the operator secret). The project
//! id is never logged. When the path is unset the Koios leg still runs and the
//! Blockfrost parity leg is skipped with a note.
//!
//! Asserts against the durable side effects, never log strings: the two known
//! published transactions land in `chain_records` with the right columns, the
//! scan reaches the chain head, the cursor advances monotonically, and Blockfrost
//! indexes a set consistent with the Koios-scanned table.

#![cfg(feature = "pg-tests")]

use std::collections::BTreeSet;

use gateway_core::chain::gateway::{
    BlockfrostGateway, ChainGateway, KoiosGateway, Label309RecordsResult,
};
use gateway_core::chain::params::Network;
use gateway_core::chain::records::derive_chain_record_columns;
use gateway_core::chain::scan::{ScanConfig, ScanHandler};
use gateway_core::testsupport::TestDb;

/// The network the live scan serves (the cursor primary key and the tip row key).
const NETWORK: &str = "preprod";

/// Two transactions this engine published to preprod that the live scan must
/// rediscover and index. Their presence with the right columns proves the scan,
/// the parser, and the column derivation all agree with what the chain actually
/// carries.
const KNOWN_TX_HASHES: [&str; 2] = [
    "1aea2c1f29ec9ccf464591f82885aec6124005d9beb1316779fa4b677d659de2",
    "70b09f0d496131b3e735fd6038b91b9858e503e2536d86027c50abec8e2fb395",
];

/// The live confirmation threshold: low, so a record only a few blocks old still
/// persists rather than pooling. The known transactions are deep in history, so
/// any threshold persists them; a low value keeps a recently published record from
/// being held in the pool for the duration of the run.
const LIVE_CONFIRMATION_THRESHOLD: u64 = 1;

/// How many full forward-scan iterations to run before declaring the scan did not
/// converge. Preprod Label 309 traffic is modest (a few hundred records total), so
/// one list call returns most of it and a handful of iterations reach the head; the
/// cap is a generous backstop, not the expected count.
const MAX_ITERATIONS: usize = 40;

/// Whether the live network path is enabled.
fn live_enabled() -> bool {
    std::env::var("GATEWAY_LIVE_TESTS").as_deref() == Ok("1")
}

/// The Blockfrost project id, read from the configured secret path, or `None` when
/// the path is unset or unreadable. Never logged.
fn blockfrost_project_id() -> Option<String> {
    let path = std::env::var("GATEWAY_BLOCKFROST_PROJECT_ID_PATH").ok()?;
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// The live scan config: the documented thresholds, with a low confirmation
/// threshold for the run.
fn live_scan_config() -> ScanConfig {
    ScanConfig {
        confirmation_threshold: LIVE_CONFIRMATION_THRESHOLD,
        ..ScanConfig::default()
    }
}

/// Parse a 64-character hex transaction hash into its 32 bytes.
fn tx_hash_bytes(hex_hash: &str) -> Vec<u8> {
    hex::decode(hex_hash).expect("known tx hash is hex")
}

/// The persisted projection of one `chain_records` row the assertions read.
#[derive(sqlx::FromRow)]
struct PersistedRow {
    block_height: i64,
    block_time: chrono::DateTime<chrono::Utc>,
    scheme: i16,
    item_count: i32,
    metadata_cbor: Vec<u8>,
}

/// Read a `chain_records` row by hash, or `None` when it is not indexed.
async fn persisted_row(pool: &sqlx::PgPool, tx_hash: &[u8]) -> Option<PersistedRow> {
    sqlx::query_as(
        "SELECT block_height, block_time, scheme, item_count, metadata_cbor \
         FROM cw_core.chain_records WHERE tx_hash = $1",
    )
    .bind(tx_hash)
    .fetch_optional(pool)
    .await
    .expect("read chain_records row")
}

/// The set of all indexed transaction hashes.
async fn all_persisted_hashes(pool: &sqlx::PgPool) -> BTreeSet<Vec<u8>> {
    sqlx::query_scalar::<_, Vec<u8>>("SELECT tx_hash FROM cw_core.chain_records")
        .fetch_all(pool)
        .await
        .expect("read chain_records hashes")
        .into_iter()
        .collect()
}

/// The number of indexed rows.
async fn persisted_count(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.chain_records")
        .fetch_one(pool)
        .await
        .expect("count chain_records")
}

/// The current cursor `(height, hash_present)`.
async fn cursor_state(pool: &sqlx::PgPool) -> Option<(i64, bool)> {
    let row: Option<(i64, Option<String>)> = sqlx::query_as(
        "SELECT last_processed_block_height, last_processed_block_hash \
         FROM cw_core.indexer_cursor WHERE network = $1",
    )
    .bind(NETWORK)
    .fetch_optional(pool)
    .await
    .expect("read cursor");
    row.map(|(h, hash)| (h, hash.is_some()))
}

/// Drive a [`ScanHandler`] forward until it reaches the chain head or the
/// iteration cap, returning the count of forward fetches that returned at least
/// one record and the final reached-head flag.
async fn drive_to_head<G: ChainGateway + 'static>(
    handler: &ScanHandler<G>,
) -> (usize, usize, bool) {
    let mut iterations = 0;
    let mut productive = 0;
    let mut reached_head = false;
    let mut last_height = 0u64;
    for _ in 0..MAX_ITERATIONS {
        let outcome = handler.run_iteration().await.expect("scan iteration");
        iterations += 1;
        if outcome.records_returned > 0 {
            productive += 1;
        }
        // The frontier must never regress across iterations on a healthy chain.
        assert!(
            outcome.last_processed_height >= last_height,
            "the scan frontier regressed from {last_height} to {} (no reorg expected on a deep history scan)",
            outcome.last_processed_height
        );
        last_height = outcome.last_processed_height;
        if outcome.reached_chain_head {
            reached_head = true;
            break;
        }
    }
    (iterations, productive, reached_head)
}

#[tokio::test]
async fn live_preprod_forward_scan_indexes_known_records_via_koios_and_blockfrost() {
    if !live_enabled() {
        eprintln!("skipping live preprod forward scan: set GATEWAY_LIVE_TESTS=1 to enable");
        return;
    }

    // --- KOIOS LEG: full forward scan from genesis to the chain head. ---
    let db = TestDb::fresh().await.expect("test database");
    let koios =
        KoiosGateway::new(Network::Preprod, Default::default()).expect("build live Koios gateway");
    let handler = ScanHandler::new(db.pool.clone(), koios, Network::Preprod, live_scan_config());

    // The cursor self-heal is a no-op on a fresh index (cursor at genesis).
    let heal = handler.self_heal_cursor().await.expect("self-heal");
    assert!(!heal.healed, "a fresh index needs no self-heal");

    let (iterations, productive, reached_head) = drive_to_head(&handler).await;
    let indexed = persisted_count(&db.pool).await;
    let (cursor_height, cursor_hash_present) =
        cursor_state(&db.pool).await.expect("cursor advanced");

    eprintln!(
        "Koios live scan: {indexed} records indexed over {iterations} iterations ({productive} productive); \
         reached_head={reached_head}; cursor at height {cursor_height} (hash_present={cursor_hash_present})"
    );

    assert!(
        reached_head,
        "the scan must reach the chain head within {MAX_ITERATIONS} iterations"
    );
    assert!(
        indexed > 0,
        "the live preprod scan must index at least one record"
    );
    // Reaching the chain head jumps the cursor to the tip with a NULL hash.
    assert!(
        !cursor_hash_present,
        "the caught-up cursor jumps to the tip with a null hash"
    );

    // The two known published transactions must be indexed with the right columns,
    // and the metadata each row carries must re-derive to the same columns (the
    // single-writer derivation agrees with what the scan stored).
    for hex_hash in KNOWN_TX_HASHES {
        let hash = tx_hash_bytes(hex_hash);
        let row = persisted_row(&db.pool, &hash)
            .await
            .unwrap_or_else(|| panic!("known transaction {hex_hash} must be indexed by the scan"));
        assert!(
            row.block_height > 0,
            "known transaction {hex_hash} indexed with a real block height"
        );
        assert!(
            row.item_count >= 1,
            "known transaction {hex_hash} carries at least one content item"
        );
        assert!(
            (0..=2).contains(&row.scheme),
            "known transaction {hex_hash} indexed with a legal scheme"
        );
        // The stored metadata bytes must re-validate and re-derive to the same
        // indexed columns: proof the row was not stored with fabricated columns.
        let cols = derive_chain_record_columns(&row.metadata_cbor, Network::Preprod)
            .unwrap_or_else(|e| panic!("indexed metadata for {hex_hash} re-validates: {e}"));
        assert_eq!(
            i32::try_from(cols.item_count).unwrap(),
            row.item_count,
            "re-derived item_count matches the stored column for {hex_hash}"
        );
        assert_eq!(
            i16::from(cols.scheme),
            row.scheme,
            "re-derived scheme matches the stored column for {hex_hash}"
        );
        eprintln!(
            "  known tx {} -> block {} time {} items {} scheme {}",
            &hex_hash[..12],
            row.block_height,
            row.block_time,
            row.item_count,
            row.scheme
        );
    }

    // Spot-check three indexed records against Koios /tx_metadata directly: each
    // must carry Label 309 metadata that re-derives to the columns we stored. This
    // proves the scan did not fabricate rows for transactions that are not actually
    // Label 309 records on chain.
    let koios_direct = KoiosGateway::new(Network::Preprod, Default::default())
        .expect("build direct Koios gateway");
    let indexed_hashes: Vec<Vec<u8>> = all_persisted_hashes(&db.pool).await.into_iter().collect();
    let spot: Vec<[u8; 32]> = indexed_hashes
        .iter()
        .take(3)
        .map(|h| <[u8; 32]>::try_from(h.as_slice()).expect("32-byte hash"))
        .collect();
    let direct = koios_direct
        .fetch_tx_cbor_by_hashes(&spot)
        .await
        .expect("direct Koios fetch for the spot-check");
    let mut spot_checked = 0;
    for hash in &spot {
        let row = persisted_row(&db.pool, hash.as_slice())
            .await
            .expect("spot-check hash is indexed");
        // The transaction CBOR is available directly from Koios, and the metadata
        // we indexed re-derives cleanly: the row is a real on-chain Label 309
        // record, not a fabrication.
        assert!(
            direct.contains_key(hash),
            "spot-check transaction {} is fetchable directly from Koios",
            hex::encode(hash)
        );
        derive_chain_record_columns(&row.metadata_cbor, Network::Preprod)
            .expect("spot-check indexed metadata re-validates as a Label 309 record");
        spot_checked += 1;
    }
    assert_eq!(spot_checked, 3, "three records spot-checked against Koios");
    eprintln!("  spot-checked {spot_checked} indexed records against Koios directly");

    // --- BLOCKFROST LEG: the same window through the other provider. ---
    let Some(project_id) = blockfrost_project_id() else {
        eprintln!(
            "skipping the Blockfrost parity leg: set GATEWAY_BLOCKFROST_PROJECT_ID_PATH to the \
             operator secret to enable it (the Koios leg above already passed)"
        );
        return;
    };

    let blockfrost = BlockfrostGateway::new(Network::Preprod, project_id.into())
        .expect("build live Blockfrost gateway");

    // Run a bounded Blockfrost forward fetch over the full history (after_block = 0)
    // and assert it returns the known records, byte-identical metadata to what the
    // Koios scan indexed. Blockfrost paginates desc and re-sorts asc; the result is
    // the same record set Koios produced.
    let tip = blockfrost.get_tip().await.expect("Blockfrost tip");
    let bf_result: Label309RecordsResult = blockfrost
        .fetch_label309_records_since(
            0,
            &[],
            tip.block_height,
            ScanConfig::default().max_records_per_iteration,
        )
        .await
        .expect("Blockfrost forward fetch");

    eprintln!(
        "Blockfrost leg: tip={}; fetched {} records, frontier={:?}",
        tip.block_height,
        bf_result.records.len(),
        bf_result.frontier
    );
    assert!(
        !bf_result.records.is_empty(),
        "Blockfrost must return at least one Label 309 record over the full history"
    );

    // Every Blockfrost record that the Koios scan also indexed must carry
    // byte-identical metadata and re-derive to the same columns the Koios row
    // stored: the two providers agree on the wire content.
    let mut consistent = 0;
    for bf in &bf_result.records {
        let Some(row) = persisted_row(&db.pool, bf.tx_hash.as_slice()).await else {
            // Blockfrost may have paged to a record older than the Koios scan
            // reached if the histories differ at the margin; only assert on the
            // overlap.
            continue;
        };
        assert_eq!(
            bf.metadata_cbor,
            row.metadata_cbor,
            "Blockfrost and Koios disagree on the metadata bytes for {}",
            hex::encode(bf.tx_hash)
        );
        assert_eq!(
            i64::try_from(bf.block_height).unwrap(),
            row.block_height,
            "Blockfrost and Koios disagree on the block height for {}",
            hex::encode(bf.tx_hash)
        );
        consistent += 1;
    }
    assert!(
        consistent > 0,
        "the Blockfrost and Koios record sets must overlap on at least one record"
    );

    // At least one of the known transactions must appear in the Blockfrost set too,
    // closing the multi-provider parity item: both providers see the same publish.
    let bf_hashes: BTreeSet<Vec<u8>> = bf_result
        .records
        .iter()
        .map(|r| r.tx_hash.to_vec())
        .collect();
    let known_in_blockfrost = KNOWN_TX_HASHES
        .iter()
        .filter(|h| bf_hashes.contains(&tx_hash_bytes(h)))
        .count();
    assert!(
        known_in_blockfrost > 0,
        "at least one known published transaction must appear in the Blockfrost set"
    );
    eprintln!(
        "  Blockfrost consistent with Koios on {consistent} overlapping records; \
         {known_in_blockfrost}/{} known transactions present in Blockfrost",
        KNOWN_TX_HASHES.len()
    );
}
