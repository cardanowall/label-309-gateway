//! Behavioural coverage for the forward-scan fetch (`fetch_label309_records_since`)
//! on the real Koios and Blockfrost gateways, driven over a loopback socket with
//! no live HTTP.
//!
//! Each gateway is pointed at a tiny path-routing fake server that answers the
//! committed `label309_*` fixtures by request path and records every path it was
//! asked for. The records the gateway assembles are asserted byte-for-byte (the
//! chunked on-chain wrapper unwrapped into the bare record bytes the validator
//! expects), the same bytes from both providers, and the recorded path set proves
//! the scan never walks the chain block by block: it lists records by count and
//! hydrates only the listed hashes.
//!
//! No test here needs Postgres. The failover policy (which consults the
//! database-backed cooldown) is covered in `chain_label_fetch_failover`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gateway_core::chain::gateway::{
    classify_chain_error, is_deterministic_node_reject, is_transient_chain_error,
    BlockfrostGateway, ChainErrorClass, ChainGateway, KoiosGateway, Label309Record, ScanFrontier,
};
use gateway_core::chain::params::{KoiosConfig, Network};

// ---------------------------------------------------------------------------
// A path-routing fake HTTP server.
//
// Unlike a connection-order script, this answers by the request path so the
// multi-request forward scan (list, then chunked/ per-tx hydration) is served
// deterministically however the gateway interleaves its calls, and the set of
// paths the gateway actually hit can be asserted afterwards. A path is matched by
// prefix so a query string (Koios) or a trailing segment (Blockfrost `/txs/...`)
// still resolves to its route.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct FakeServer {
    base_url: String,
    /// Every request path the server received, in arrival order.
    seen_paths: Arc<Mutex<Vec<String>>>,
}

impl FakeServer {
    /// The request paths the gateway hit, in arrival order.
    fn seen_paths(&self) -> Vec<String> {
        self.seen_paths.lock().unwrap().clone()
    }

    /// How many of the seen paths begin with `prefix`.
    fn count_paths_with_prefix(&self, prefix: &str) -> usize {
        self.seen_paths()
            .iter()
            .filter(|p| p.starts_with(prefix))
            .count()
    }
}

/// One route: a path prefix, an HTTP status line, and the JSON body to return.
struct Route {
    prefix: String,
    status_line: &'static str,
    body: String,
}

fn route(prefix: impl Into<String>, body: impl Into<String>) -> Route {
    Route {
        prefix: prefix.into(),
        status_line: "HTTP/1.1 200 OK",
        body: body.into(),
    }
}

fn route_status(
    prefix: impl Into<String>,
    status_line: &'static str,
    body: impl Into<String>,
) -> Route {
    Route {
        prefix: prefix.into(),
        status_line,
        body: body.into(),
    }
}

/// Spawn a server that answers `total_requests` connections by routing each
/// request path to the first matching [`Route`]; an unrouted path gets a 404.
/// Returns once the listener is bound so the gateway can connect immediately.
async fn spawn_router(routes: Vec<Route>, total_requests: usize) -> FakeServer {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake");
    let addr = listener.local_addr().expect("addr");
    let base_url = format!("http://{addr}");
    let seen_paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_for_server = seen_paths.clone();

    let routes: Vec<(String, String, String)> = routes
        .into_iter()
        .map(|r| (r.prefix.to_string(), r.status_line.to_string(), r.body))
        .collect();

    tokio::spawn(async move {
        for _ in 0..total_requests {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let mut buf = vec![0u8; 64 * 1024];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            // The request line is "METHOD PATH HTTP/1.1"; take the path.
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            seen_for_server.lock().unwrap().push(path.clone());

            let matched = routes
                .iter()
                .find(|(prefix, _, _)| path.starts_with(prefix.as_str()));
            let (status_line, body) = match matched {
                Some((_, status_line, body)) => (status_line.as_str(), body.as_str()),
                None => ("HTTP/1.1 404 Not Found", "{}"),
            };
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        }
    });

    FakeServer {
        base_url,
        seen_paths,
    }
}

const KOIOS_METALABEL: &str = include_str!("fixtures/chain/label309_koios_metalabel.json");
const KOIOS_METALABEL_CLEAN: &str =
    include_str!("fixtures/chain/label309_koios_metalabel_clean.json");
const KOIOS_METADATA: &str = include_str!("fixtures/chain/label309_koios_metadata.json");
const BLOCKFROST_LABELS_PAGE1: &str =
    include_str!("fixtures/chain/label309_blockfrost_labels_page1.json");
const BLOCKFROST_TX_11: &str = include_str!("fixtures/chain/label309_blockfrost_tx_11.json");
const BLOCKFROST_TX_22: &str = include_str!("fixtures/chain/label309_blockfrost_tx_22.json");
const BLOCKFROST_TX_33: &str = include_str!("fixtures/chain/label309_blockfrost_tx_33.json");

/// A 32-byte hash whose every byte is `b`.
fn hash(b: u8) -> [u8; 32] {
    [b; 32]
}

/// Index the assembled records by their transaction id for order-independent
/// assertions (Koios returns ascending, Blockfrost re-sorts ascending).
fn by_hash(records: &[Label309Record]) -> HashMap<[u8; 32], &Label309Record> {
    records.iter().map(|r| (r.tx_hash, r)).collect()
}

fn koios_at(base_url: String) -> KoiosGateway {
    let client = reqwest::Client::builder().build().expect("reqwest client");
    KoiosGateway::with_client(
        client,
        Network::Preprod,
        KoiosConfig {
            base_url: Some(base_url),
            api_key: None,
        },
    )
}

fn blockfrost_at(base_url: String) -> BlockfrostGateway {
    let client = reqwest::Client::builder().build().expect("reqwest client");
    BlockfrostGateway::with_client(
        client,
        Network::Preprod,
        base_url,
        "test-project-id".to_string().into(),
    )
}

// ---------------------------------------------------------------------------
// Koios forward scan.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn koios_scan_lists_then_reassembles_multi_chunk_metadata() {
    // One /tx_by_metalabel list call, then one /tx_metadata chunk for the two
    // well-formed listed hashes (3 < the keyless chunk limit, so a single chunk).
    let server = spawn_router(
        vec![
            route("/tx_by_metalabel", KOIOS_METALABEL_CLEAN),
            route("/tx_metadata", KOIOS_METADATA),
        ],
        2,
    )
    .await;

    let result = koios_at(server.base_url.clone())
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("koios forward scan");

    // Two well-formed rows are listed; the metadata fixture's label-674 row never
    // matched a listed hash. Two records survive, ascending by block height.
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.records[0].block_height, 500);
    assert_eq!(result.records[1].block_height, 501);

    let indexed = by_hash(&result.records);

    // Record 0x11: a two-chunk on-chain wrapper "0xa101"+"0x182a" reassembles
    // into the bare canonical record bytes the validator receives.
    let r11 = indexed.get(&hash(0x11)).expect("record 0x11");
    assert_eq!(
        r11.metadata_cbor,
        vec![0xa1, 0x01, 0x18, 0x2a],
        "multi-chunk metadata concatenates into the bare record bytes"
    );
    assert_eq!(r11.block_hash, hash(0xaa));
    // Confirmations derive from the tip the call was given: 600 - 500 + 1.
    assert_eq!(r11.num_confirmations, 101);

    // Record 0x22: a single-chunk wrapper, tip 600 - 501 + 1 = 100.
    let r22 = indexed.get(&hash(0x22)).expect("record 0x22");
    assert_eq!(r22.metadata_cbor, vec![0xa2, 0x01, 0x02, 0x03]);
    assert_eq!(r22.num_confirmations, 100);

    // Fewer than max_records were listed and every one hydrated, so the scan is
    // caught up to its own tip (the caller clamps to min(tip, watermark)).
    assert_eq!(
        result.frontier,
        ScanFrontier::CaughtUpTo { indexed_to: 600 }
    );

    // The scan never enumerated blocks: no /blocks request was made. It listed by
    // metalabel once and hydrated metadata once, both O(records).
    assert_eq!(
        server.count_paths_with_prefix("/blocks"),
        0,
        "the forward scan must not walk the chain block by block"
    );
    assert_eq!(server.count_paths_with_prefix("/tx_by_metalabel"), 1);
    assert_eq!(server.count_paths_with_prefix("/tx_metadata"), 1);
}

#[tokio::test]
async fn koios_scan_caps_reached_chain_head_at_the_max_records_boundary() {
    // The scan fetches max_records + 1 rows so it can see whether the cap falls
    // mid-block. With THREE distinct-height rows above the cursor and a cap of two,
    // the provider returns all three; the cap is genuinely exceeded and the boundary
    // block (height 501) is complete (the next height 502 is higher), so exactly the
    // oldest two records are kept and the scan reports it did NOT reach the head.
    let metalabel = serde_json::json!([
        { "tx_hash": "11".repeat(32), "block_hash": "aa".repeat(32), "block_height": 500, "tx_timestamp": 1_700_000_000_u64 },
        { "tx_hash": "22".repeat(32), "block_hash": "bb".repeat(32), "block_height": 501, "tx_timestamp": 1_700_000_100_u64 },
        { "tx_hash": "33".repeat(32), "block_hash": "cc".repeat(32), "block_height": 502, "tx_timestamp": 1_700_000_200_u64 },
    ])
    .to_string();
    let metadata = serde_json::json!([
        { "tx_hash": "11".repeat(32), "metadata": { "309": ["0xa101"] } },
        { "tx_hash": "22".repeat(32), "metadata": { "309": ["0xa101"] } },
        { "tx_hash": "33".repeat(32), "metadata": { "309": ["0xa101"] } },
    ])
    .to_string();
    let server = spawn_router(
        vec![
            route("/tx_by_metalabel", metalabel),
            route("/tx_metadata", metadata),
        ],
        2,
    )
    .await;

    let result = koios_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 2)
        .await
        .expect("capped scan");

    assert_eq!(result.records.len(), 2, "the oldest two records are kept");
    assert_eq!(result.records[0].block_height, 500);
    assert_eq!(result.records[1].block_height, 501);
    assert_eq!(
        result.frontier,
        ScanFrontier::Anchor {
            height: 501,
            block_hash: hash(0xbb),
        },
        "a response past the max_records cap anchors at the highest kept block, \
         leaving more records above it for the next tick"
    );
}

#[tokio::test]
async fn koios_scan_empty_list_is_caught_up_with_no_metadata_call() {
    // An empty /tx_by_metalabel array means nothing above the cursor: caught up,
    // and the gateway never makes the metadata call.
    let server = spawn_router(vec![route("/tx_by_metalabel", "[]")], 1).await;

    let result = koios_at(server.base_url.clone())
        .fetch_label309_records_since(1000, &[], 1000, 200)
        .await
        .expect("empty list scan");

    assert!(result.records.is_empty());
    assert_eq!(
        result.frontier,
        ScanFrontier::CaughtUpTo { indexed_to: 1000 },
        "an empty list is caught up to the tip the call was given"
    );
    assert_eq!(
        server.count_paths_with_prefix("/tx_metadata"),
        0,
        "an empty list short-circuits before the metadata fetch"
    );
}

#[tokio::test]
async fn koios_scan_caps_below_an_un_hydrated_listed_tx_instead_of_advancing_past_it() {
    // The list carries hashes 0x11 @ 500 and 0x22 @ 501, but the metadata response
    // only hydrates 0x11. The un-hydrated 0x22 is a hydration gap at block 501: the
    // scan must NOT advance the cursor past it (a `/tx_metadata` replica lag would
    // otherwise lose the record forever). Only the record below the gap (0x11) is
    // emitted, and the frontier anchors strictly below the gap so the next tick
    // re-fetches 0x22.
    let metadata_only_11 = serde_json::json!([
        {
            "tx_hash": "11".repeat(32),
            "metadata": { "309": ["0xa101", "0x182a"] }
        }
    ])
    .to_string();
    let server = spawn_router(
        vec![
            route("/tx_by_metalabel", KOIOS_METALABEL_CLEAN),
            route("/tx_metadata", metadata_only_11),
        ],
        2,
    )
    .await;

    let result = koios_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("partial metadata scan");

    assert_eq!(
        result.records.len(),
        1,
        "only the record below the gap is emitted"
    );
    assert_eq!(result.records[0].tx_hash, hash(0x11));
    assert_eq!(
        result.frontier,
        ScanFrontier::Anchor {
            height: 500,
            block_hash: hash(0xaa),
        },
        "the frontier anchors strictly below the un-hydrated tx, never jumps the tip past it"
    );
}

#[tokio::test]
async fn koios_scan_holds_when_the_lowest_listed_tx_does_not_hydrate() {
    // The lowest listed tx (0x11 @ 500) does not hydrate: there is no safe height
    // below the gap, so the scan emits nothing and HOLDS the cursor — the next tick
    // re-fetches the same window rather than skipping 0x11.
    let metadata_only_22 = serde_json::json!([
        { "tx_hash": "22".repeat(32), "metadata": { "309": ["0xa101"] } }
    ])
    .to_string();
    let server = spawn_router(
        vec![
            route("/tx_by_metalabel", KOIOS_METALABEL_CLEAN),
            route("/tx_metadata", metadata_only_22),
        ],
        2,
    )
    .await;

    let result = koios_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("lowest-gap scan");

    assert!(
        result.records.is_empty(),
        "nothing below the lowest-block gap can be emitted"
    );
    assert_eq!(
        result.frontier,
        ScanFrontier::Hold,
        "the cursor holds rather than advancing past the un-hydrated lowest tx"
    );
}

/// A malformed `/tx_by_metalabel` row (a tx_hash that does not decode) is NOT
/// silently dropped while the cursor advances past it: every metalabel row IS a
/// label-309 transaction by construction, so an unparseable one is malformed
/// provider data that must fail the tick. The scan returns a retryable
/// BadResponse, leaving the cursor un-advanced so the page is re-fetched and no
/// real on-chain record is skipped.
#[tokio::test]
async fn koios_scan_malformed_row_fails_the_tick_and_does_not_advance() {
    // The committed metalabel fixture deliberately carries a `"not-a-hash"` row
    // alongside two well-formed ones. Under the corrected scan this is a hard
    // provider error, not a 2-record success.
    let server = spawn_router(
        vec![
            route("/tx_by_metalabel", KOIOS_METALABEL),
            route("/tx_metadata", KOIOS_METADATA),
        ],
        2,
    )
    .await;

    let err = koios_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect_err("a malformed metalabel row must fail the tick, never silently skip");
    // A malformed-but-successful response is a deterministic BadResponse the
    // failover/retry handles; the cursor never advances past the unread row.
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::BadResponse)
    );
}

/// A `/tx_metadata` chunk above the ledger's 64-byte metadata-string cap cannot
/// be a rendering of chain data, so the fetch must fail as a CORRUPT-PROVIDER
/// error (typed transient: the failover wrapper asks the secondary, and the
/// scan tick aborts with the cursor un-advanced). Treating it as "not a
/// label-309 transaction" would drop the record and advance the cursor past a
/// real on-chain transaction forever.
#[tokio::test]
async fn koios_scan_over_cap_metadata_chunk_is_a_corrupt_provider_failure() {
    // Listed hash 0x11 hydrates with a 65-byte chunk (impossible on chain).
    let metadata_over_cap = serde_json::json!([
        {
            "tx_hash": "11".repeat(32),
            "metadata": { "309": [format!("0x{}", "ee".repeat(65))] }
        }
    ])
    .to_string();
    let server = spawn_router(
        vec![
            route("/tx_by_metalabel", KOIOS_METALABEL_CLEAN),
            route("/tx_metadata", metadata_over_cap),
        ],
        2,
    )
    .await;

    let err = koios_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect_err("an over-cap chunk must fail the fetch, never skip the transaction");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::CorruptProvider),
        "an on-chain-impossible chunk is a provider-level failure"
    );
}

/// A label-309 metadatum that is genuinely not the chunk-array carriage (here a
/// bare number under the 309 key — perfectly possible on chain) is a verdict on
/// the TRANSACTION: that transaction is skipped, the rest of the page is
/// served, and the tick succeeds.
#[tokio::test]
async fn koios_scan_skips_a_non_carriage_label309_metadatum_without_failing() {
    let metadata_mixed = serde_json::json!([
        { "tx_hash": "11".repeat(32), "metadata": { "309": 42 } },
        { "tx_hash": "22".repeat(32), "metadata": { "309": ["0xa2010203"] } },
    ])
    .to_string();
    let server = spawn_router(
        vec![
            route("/tx_by_metalabel", KOIOS_METALABEL_CLEAN),
            route("/tx_metadata", metadata_mixed),
        ],
        2,
    )
    .await;

    let result = koios_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("a malformed-on-chain carriage skips its transaction, not the tick");
    assert_eq!(
        result.records.len(),
        1,
        "only the chunk-array record survives"
    );
    assert_eq!(result.records[0].tx_hash, hash(0x22));
}

/// Koios parity for the within-block tie-break: when the provider's `limit` caps
/// the response with a PARTIAL trailing block (more records share the highest
/// returned height than were returned), the scan trims that whole block so the
/// cursor anchors at the last fully-included block. The next tick re-reads the
/// partial block from one below it; nothing at the boundary height is skipped.
#[tokio::test]
async fn koios_capped_window_trims_a_partial_trailing_block() {
    // The scan fetches max_records + 1 rows. With a cap of 2 and THREE rows ascending
    // (height 200, then two at height 300), the response exceeds the cap and the
    // boundary block 300 is split (the third row shares its height). A naive anchor
    // at 300 would skip any further 300-records; the fix trims block 300 and anchors
    // at 200, re-reading the 300-block on the next tick.
    let metalabel = serde_json::json!([
        { "tx_hash": "21".repeat(32), "block_hash": "aa".repeat(32), "block_height": 200, "tx_timestamp": 1_700_000_000_u64 },
        { "tx_hash": "31".repeat(32), "block_hash": "bb".repeat(32), "block_height": 300, "tx_timestamp": 1_700_000_100_u64 },
        { "tx_hash": "32".repeat(32), "block_hash": "bb".repeat(32), "block_height": 300, "tx_timestamp": 1_700_000_100_u64 },
    ])
    .to_string();
    let metadata = serde_json::json!([
        { "tx_hash": "21".repeat(32), "metadata": { "309": ["0xa101"] } },
        { "tx_hash": "31".repeat(32), "metadata": { "309": ["0xa101"] } },
        { "tx_hash": "32".repeat(32), "metadata": { "309": ["0xa101"] } },
    ])
    .to_string();
    let server = spawn_router(
        vec![
            route("/tx_by_metalabel", metalabel),
            route("/tx_metadata", metadata),
        ],
        2,
    )
    .await;

    let result = koios_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 2)
        .await
        .expect("capped koios scan with a partial trailing block");

    assert_eq!(
        result.records.len(),
        1,
        "the partial trailing block is trimmed so the cursor never splits a block"
    );
    assert_eq!(result.records[0].block_height, 200);
    assert_eq!(
        result.frontier,
        ScanFrontier::Anchor {
            height: 200,
            block_hash: hash(0xaa),
        },
        "more records remain (the trimmed 300-block), so the cursor anchors at block 200"
    );
}

/// Koios parity: a capped window that is ENTIRELY one over-cap block is consumed
/// PIECEMEAL — the fetch returns a page of the block under an intra-block
/// frontier instead of failing the tick, so no block can ever stall the feed.
#[tokio::test]
async fn koios_single_block_over_the_cap_pages_through_it() {
    // THREE listed rows all at height 200 with a cap of 2: the whole window is one
    // block, un-pageable by a height cursor. The fetch consumes a two-record page
    // and reports the block partially done.
    let metalabel = serde_json::json!([
        { "tx_hash": "21".repeat(32), "block_hash": "aa".repeat(32), "block_height": 200, "tx_timestamp": 1_700_000_000_u64 },
        { "tx_hash": "22".repeat(32), "block_hash": "aa".repeat(32), "block_height": 200, "tx_timestamp": 1_700_000_000_u64 },
        { "tx_hash": "23".repeat(32), "block_hash": "aa".repeat(32), "block_height": 200, "tx_timestamp": 1_700_000_000_u64 },
    ])
    .to_string();
    let metadata = serde_json::json!([
        { "tx_hash": "21".repeat(32), "metadata": { "309": ["0xa101"] } },
        { "tx_hash": "22".repeat(32), "metadata": { "309": ["0xa101"] } },
        { "tx_hash": "23".repeat(32), "metadata": { "309": ["0xa101"] } },
    ])
    .to_string();
    let server = spawn_router(
        vec![
            route("/tx_by_metalabel", metalabel),
            route("/tx_metadata", metadata),
        ],
        2,
    )
    .await;

    let result = koios_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 2)
        .await
        .expect("an over-cap block pages instead of failing");
    assert_eq!(result.records.len(), 2, "one full page of the block");
    assert!(result.records.iter().all(|r| r.block_height == 200));
    assert_eq!(
        result.frontier,
        ScanFrontier::IntraBlock {
            height: 200,
            block_hash: hash(0xaa),
            consumed_no_record: Vec::new(),
        },
        "the frontier anchors AT the partially-consumed block"
    );
}

/// The resume tick of a partially-consumed Koios block: the fetch re-reads the
/// block with the already-consumed hashes excluded, returns exactly the
/// remainder, and — with nothing above — reports caught-up so the scan closes
/// the block out. No transaction is skipped and none is returned twice.
#[tokio::test]
async fn koios_intra_block_resume_excludes_consumed_and_completes_the_block() {
    let metalabel = serde_json::json!([
        { "tx_hash": "21".repeat(32), "block_hash": "aa".repeat(32), "block_height": 200, "tx_timestamp": 1_700_000_000_u64 },
        { "tx_hash": "22".repeat(32), "block_hash": "aa".repeat(32), "block_height": 200, "tx_timestamp": 1_700_000_000_u64 },
        { "tx_hash": "23".repeat(32), "block_hash": "aa".repeat(32), "block_height": 200, "tx_timestamp": 1_700_000_000_u64 },
    ])
    .to_string();
    let metadata = serde_json::json!([
        { "tx_hash": "23".repeat(32), "metadata": { "309": ["0xa101"] } },
    ])
    .to_string();
    let server = spawn_router(
        vec![
            route("/tx_by_metalabel", metalabel),
            route("/tx_metadata", metadata),
        ],
        2,
    )
    .await;

    // Two of the three block-200 transactions were consumed by the previous tick.
    let consumed = [hash(0x21), hash(0x22)];
    let result = koios_at(server.base_url.clone())
        .fetch_label309_records_since(199, &consumed, 600, 2)
        .await
        .expect("resume of a partially-consumed block");
    assert_eq!(result.records.len(), 1, "exactly the remainder, no re-emit");
    assert_eq!(result.records[0].tx_hash, hash(0x23));
    assert_eq!(
        result.frontier,
        ScanFrontier::CaughtUpTo { indexed_to: 600 },
        "the remainder fits the window and nothing exists above: caught up"
    );
    // The widened list limit carries the exclusion count so the consumed rows can
    // never crowd the remainder out of the response.
    let list_path = server
        .seen_paths()
        .into_iter()
        .find(|p| p.starts_with("/tx_by_metalabel"))
        .expect("a list call");
    assert!(
        list_path.contains("limit=5"),
        "limit = max_records + exclusions + 1, got {list_path}"
    );
}

#[tokio::test]
async fn koios_scan_http_error_on_the_list_is_a_chain_provider_error() {
    let server = spawn_router(
        vec![route_status(
            "/tx_by_metalabel",
            "HTTP/1.1 500 Internal Server Error",
            "{}",
        )],
        1,
    )
    .await;

    let err = koios_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect_err("a 5xx on the list must surface as a provider error");
    // A 5xx is a transient HTTP class (the failover wrapper retries it on the
    // secondary), carried in the typed error.
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::Http { status: 500 })
    );
}

// ---------------------------------------------------------------------------
// Blockfrost forward scan.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn blockfrost_scan_pages_desc_hydrates_coords_and_resorts_asc() {
    // One descending label page returns three rows (heights 501, 500, 400); the
    // per-tx coords hydrate each, and the row at 400 dips to/below the cursor 499
    // so the scan stops there. Records re-sort ascending to match Koios.
    let server = spawn_router(
        vec![
            route("/metadata/txs/labels", BLOCKFROST_LABELS_PAGE1),
            // Order matters within the routes vec only for disambiguation; these
            // are distinct full paths so prefix matching is exact per hash.
            route(format!("/txs/{}", "11".repeat(32)), BLOCKFROST_TX_11),
            route(format!("/txs/{}", "22".repeat(32)), BLOCKFROST_TX_22),
            route(format!("/txs/{}", "33".repeat(32)), BLOCKFROST_TX_33),
        ],
        4,
    )
    .await;

    let result = blockfrost_at(server.base_url.clone())
        .fetch_label309_records_since(499, &[], 600, 200)
        .await
        .expect("blockfrost forward scan");

    // Heights 500 and 501 are above the cursor; 400 is below and stops the scan.
    assert_eq!(result.records.len(), 2);
    assert_eq!(
        result.records[0].block_height, 500,
        "records re-sort ascending after a descending page walk"
    );
    assert_eq!(result.records[1].block_height, 501);
    assert_eq!(
        result.frontier,
        ScanFrontier::CaughtUpTo { indexed_to: 501 },
        "the caught-up frontier reports Blockfrost's OWN watermark (its highest \
         hydrated record, 501), never the given tip 600 — so a Blockfrost metadata \
         lag behind the tip can never drive the cursor past what Blockfrost has indexed"
    );

    let indexed = by_hash(&result.records);

    // Byte-parity with Koios: the same bare record bytes, unwrapped from the full
    // metadatum hex Blockfrost returns rather than the JSON chunk array Koios
    // returns.
    let r11 = indexed.get(&hash(0x11)).expect("record 0x11");
    assert_eq!(r11.metadata_cbor, vec![0xa1, 0x01, 0x18, 0x2a]);
    assert_eq!(r11.block_hash, hash(0xaa));
    assert_eq!(r11.num_confirmations, 101); // 600 - 500 + 1

    let r22 = indexed.get(&hash(0x22)).expect("record 0x22");
    assert_eq!(r22.metadata_cbor, vec![0xa2, 0x01, 0x02, 0x03]);
    assert_eq!(r22.num_confirmations, 100); // 600 - 501 + 1

    // The row at height 400 was below the cursor: never hydrated past the stop,
    // never indexed, and its later siblings were skipped.
    assert!(!indexed.contains_key(&hash(0x33)));
}

/// The Blockfrost CBOR-path twin of the Koios over-cap rule: a label row whose
/// metadatum CBOR carries a byte-string chunk above the ledger's 64-byte cap is
/// corrupt provider output. The fetch must fail with the typed corrupt-provider
/// class (transient: the failover wrapper asks the other provider, and the scan
/// tick aborts with the cursor un-advanced) — never skip the transaction.
#[tokio::test]
async fn blockfrost_scan_over_cap_metadatum_chunk_is_a_corrupt_provider_failure() {
    // `{309: [bstr(65)]}`: a1 19 0135 (map keyed 309), 81 (array(1)),
    // 58 41 (bstr, one-byte length 65), then 65 bytes.
    let metadatum_hex = format!("a1190135815841{}", "ee".repeat(65));
    let labels_page = serde_json::json!([
        { "tx_hash": "11".repeat(32), "metadata": metadatum_hex },
    ])
    .to_string();
    let server = spawn_router(
        vec![
            route("/metadata/txs/labels", labels_page),
            route(format!("/txs/{}", "11".repeat(32)), BLOCKFROST_TX_11),
        ],
        2,
    )
    .await;

    let err = blockfrost_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect_err("an over-cap chunk must fail the fetch, never skip the transaction");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::CorruptProvider),
        "an on-chain-impossible chunk is a provider-level failure"
    );
}

/// A capped Blockfrost tick (more matching records above the cursor than the cap)
/// must leave the cursor at the OLDEST returned record, never the newest, so no
/// record between the cursor and the window bottom is ever skipped.
///
/// Blockfrost pages newest-first, so a naive "stop at the cap" would return the
/// NEWEST `max_records` and advance the cursor past the older unread ones forever.
/// The corrected scan pages down to the cursor boundary, sorts ascending, and
/// keeps the OLDEST `max_records` (parity with the Koios ascending window) so the
/// cursor anchors at that window's top and the next tick walks the gap upward.
#[tokio::test]
async fn blockfrost_capped_tick_anchors_at_the_oldest_window_not_the_newest() {
    // A single descending page of five label rows at heights 600..200 (newest
    // first), all above the cursor at 100. The page is short (< the page size), so
    // the walk knows the whole range above the cursor has been read.
    let labels_page = serde_json::json!([
        { "tx_hash": "25".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "24".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "23".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "22".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "21".repeat(32), "metadata": "a11901358144a2010203" },
    ])
    .to_string();
    let coords = |byte: u8, height: u64| {
        let hex = format!("{byte:02x}").repeat(32);
        route(
            format!("/txs/{hex}"),
            serde_json::json!({
                "hash": hex,
                "block": "aa".repeat(32),
                "block_height": height,
                "block_time": 1_700_000_000_u64,
            })
            .to_string(),
        )
    };
    let server = spawn_router(
        vec![
            route("/metadata/txs/labels", labels_page),
            coords(0x25, 600),
            coords(0x24, 500),
            coords(0x23, 400),
            coords(0x22, 300),
            coords(0x21, 200),
        ],
        6,
    )
    .await;

    // Cursor 100, cap 2: five records exist above the cursor but only two fit a
    // tick.
    let result = blockfrost_at(server.base_url.clone())
        .fetch_label309_records_since(100, &[], 600, 2)
        .await
        .expect("capped blockfrost scan");

    // The OLDEST two (heights 200, 300) are returned, ascending, and the scan is
    // NOT at the head, so the cursor anchors at 300 (records.last()). The next tick
    // resumes from 300 and walks 400/500/600 upward; nothing in (100, 300] is ever
    // skipped.
    assert_eq!(result.records.len(), 2, "the tick returns at most the cap");
    assert_eq!(
        result.records[0].block_height, 200,
        "the oldest record above the cursor is the window bottom"
    );
    assert_eq!(
        result.records[1].block_height, 300,
        "the window is the contiguous oldest pair, never the newest"
    );
    assert_eq!(
        result.frontier,
        ScanFrontier::Anchor {
            height: 300,
            block_hash: hash(0xaa),
        },
        "a capped window leaves more records above it, so the cursor anchors at the window top, not the tip"
    );
}

/// A capped Blockfrost window whose trailing (highest) block is PARTIAL must trim
/// the whole partial block off, so the cursor anchors at the last FULLY-included
/// block and the next tick re-reads the partial block. The cursor advances by
/// height and requests strictly above it, so anchoring mid-block would skip the
/// same-block remainder forever.
#[tokio::test]
async fn blockfrost_capped_window_trims_a_partial_trailing_block() {
    // Above the cursor: one record at height 200, then THREE records at height 300.
    // Cap 3 would naively keep [200, 300, 300] and anchor at 300, skipping the third
    // 300-record forever. The fix trims the partial 300-block and anchors at 200.
    let labels_page = serde_json::json!([
        { "tx_hash": "33".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "32".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "31".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "21".repeat(32), "metadata": "a11901358144a2010203" },
    ])
    .to_string();
    let coords = |byte: u8, height: u64| {
        let hex = format!("{byte:02x}").repeat(32);
        route(
            format!("/txs/{hex}"),
            serde_json::json!({
                "hash": hex,
                "block": "aa".repeat(32),
                "block_height": height,
                "block_time": 1_700_000_000_u64,
            })
            .to_string(),
        )
    };
    let server = spawn_router(
        vec![
            route("/metadata/txs/labels", labels_page),
            coords(0x33, 300),
            coords(0x32, 300),
            coords(0x31, 300),
            coords(0x21, 200),
        ],
        5,
    )
    .await;

    let result = blockfrost_at(server.base_url.clone())
        .fetch_label309_records_since(100, &[], 600, 3)
        .await
        .expect("capped blockfrost scan with a partial trailing block");

    // Only the fully-included block 200 survives; the partial 300-block is trimmed.
    assert_eq!(
        result.records.len(),
        1,
        "the partial trailing block is trimmed so the cursor never splits a block"
    );
    assert_eq!(result.records[0].block_height, 200);
    assert_eq!(
        result.frontier,
        ScanFrontier::Anchor {
            height: 200,
            block_hash: hash(0xaa),
        },
        "more records remain (the trimmed 300-block), so the cursor anchors at block 200"
    );
}

/// A capped Blockfrost window that is ENTIRELY one block carrying more label-309
/// records than the cap is consumed PIECEMEAL — a page of the block under an
/// intra-block frontier — instead of failing the tick.
#[tokio::test]
async fn blockfrost_single_block_over_the_cap_pages_through_it() {
    // Three records all at height 200, above the cursor, with a cap of 2.
    let labels_page = serde_json::json!([
        { "tx_hash": "23".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "22".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "21".repeat(32), "metadata": "a11901358144a2010203" },
    ])
    .to_string();
    let coords = |byte: u8| {
        let hex = format!("{byte:02x}").repeat(32);
        route(
            format!("/txs/{hex}"),
            serde_json::json!({
                "hash": hex,
                "block": "aa".repeat(32),
                "block_height": 200_u64,
                "block_time": 1_700_000_000_u64,
            })
            .to_string(),
        )
    };
    let server = spawn_router(
        vec![
            route("/metadata/txs/labels", labels_page),
            coords(0x23),
            coords(0x22),
            coords(0x21),
        ],
        4,
    )
    .await;

    let result = blockfrost_at(server.base_url)
        .fetch_label309_records_since(100, &[], 600, 2)
        .await
        .expect("an over-cap block pages instead of failing");
    assert_eq!(result.records.len(), 2, "one full page of the block");
    assert!(result.records.iter().all(|r| r.block_height == 200));
    assert!(
        matches!(
            result.frontier,
            ScanFrontier::IntraBlock {
                height: 200,
                block_hash,
                ref consumed_no_record,
            } if block_hash == hash(0xaa) && consumed_no_record.is_empty()
        ),
        "the frontier anchors AT the partially-consumed block, got {:?}",
        result.frontier
    );
}

/// The resume tick of a partially-consumed Blockfrost block: excluded rows are
/// skipped BEFORE coordinate hydration (no per-tx call for them), the remainder
/// is returned exactly once, and with nothing new beyond the exclusions the
/// provider reports caught-up-to-the-block so the scan closes it out.
#[tokio::test]
async fn blockfrost_intra_block_resume_excludes_consumed_and_completes_the_block() {
    let labels_page = serde_json::json!([
        { "tx_hash": "23".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "22".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "21".repeat(32), "metadata": "a11901358144a2010203" },
    ])
    .to_string();
    let coords = |byte: u8| {
        let hex = format!("{byte:02x}").repeat(32);
        route(
            format!("/txs/{hex}"),
            serde_json::json!({
                "hash": hex,
                "block": "aa".repeat(32),
                "block_height": 200_u64,
                "block_time": 1_700_000_000_u64,
            })
            .to_string(),
        )
    };
    let server = spawn_router(
        vec![
            route("/metadata/txs/labels", labels_page),
            coords(0x23),
            coords(0x22),
            coords(0x21),
        ],
        3,
    )
    .await;

    let consumed = [hash(0x21), hash(0x22)];
    let result = blockfrost_at(server.base_url.clone())
        .fetch_label309_records_since(199, &consumed, 600, 2)
        .await
        .expect("resume of a partially-consumed block");
    assert_eq!(result.records.len(), 1, "exactly the remainder, no re-emit");
    assert_eq!(result.records[0].tx_hash, hash(0x23));
    assert_eq!(
        result.frontier,
        ScanFrontier::CaughtUpTo { indexed_to: 200 },
        "caught up to the boundary block itself, never the given tip"
    );
    // Excluded rows must not be hydrated: exactly one /txs call (the remainder).
    assert_eq!(
        server.count_paths_with_prefix("/txs/"),
        1,
        "already-consumed transactions are skipped before coordinate hydration"
    );
}

/// Regression (never-skip): a resume tick of a partially-consumed block whose
/// remaining transactions sit in a coordinate-hydration gap must NOT complete
/// the block — seen exclusions alone are no proof the remainder hydrated. The
/// fetch HOLDS, and once the gap hydrates a later tick returns the remainder
/// exactly once. Completing here would clear the exclusion set, advance the
/// cursor past the block, and permanently skip a confirmed on-chain record.
#[tokio::test]
async fn blockfrost_intra_block_resume_with_a_gap_holds_instead_of_completing() {
    let labels_page = serde_json::json!([
        { "tx_hash": "23".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "22".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "21".repeat(32), "metadata": "a11901358144a2010203" },
    ])
    .to_string();

    // Tick 1: the un-consumed remainder (tx 23) fails coordinate hydration —
    // /txs/{23} has no route, so it answers 404 (mempool / partial row).
    let gapped = spawn_router(vec![route("/metadata/txs/labels", labels_page.clone())], 2).await;
    let consumed = [hash(0x21), hash(0x22)];
    let result = blockfrost_at(gapped.base_url.clone())
        .fetch_label309_records_since(199, &consumed, 600, 2)
        .await
        .expect("resume fetch with a hydration gap");
    assert!(result.records.is_empty());
    assert_eq!(
        result.frontier,
        ScanFrontier::Hold,
        "a gap in the block's remainder must HOLD, never complete the block on \
         the strength of seen exclusions alone"
    );

    // Tick 2: the gap has hydrated. The same resume fetch now returns the
    // remainder exactly once and only then reports the block caught up.
    let hydrated = spawn_router(
        vec![
            route("/metadata/txs/labels", labels_page),
            route(
                format!("/txs/{}", "23".repeat(32)),
                serde_json::json!({
                    "hash": "23".repeat(32),
                    "block": "aa".repeat(32),
                    "block_height": 200_u64,
                    "block_time": 1_700_000_000_u64,
                })
                .to_string(),
            ),
        ],
        2,
    )
    .await;
    let result = blockfrost_at(hydrated.base_url)
        .fetch_label309_records_since(199, &consumed, 600, 2)
        .await
        .expect("resume fetch after the gap hydrated");
    assert_eq!(
        result.records.len(),
        1,
        "the record is indexed, never skipped"
    );
    assert_eq!(result.records[0].tx_hash, hash(0x23));
    assert_eq!(
        result.frontier,
        ScanFrontier::CaughtUpTo { indexed_to: 200 }
    );
}

/// Regression (never-skip): a gap observed BEFORE anything hydrated is bounded
/// by the NEXT hydrated row — which can share the gap's own block — so a
/// same-height record must not anchor the cursor over the gap. The old bound
/// (derived from the lowest record kept so far) was both dropped entirely when
/// no record had been kept yet and taken from the wrong side of the gap.
#[tokio::test]
async fn blockfrost_gap_before_a_same_height_record_holds_instead_of_anchoring() {
    let labels_page = serde_json::json!([
        // The gap: a listed label-309 row with no usable hash (un-hydratable),
        // arriving while nothing has been kept yet.
        { "metadata": "a11901358144a2010203" },
        // A record that hydrates at height 200 — possibly the gap's own block.
        { "tx_hash": "21".repeat(32), "metadata": "a11901358144a2010203" },
    ])
    .to_string();
    let server = spawn_router(
        vec![
            route("/metadata/txs/labels", labels_page),
            route(
                format!("/txs/{}", "21".repeat(32)),
                serde_json::json!({
                    "hash": "21".repeat(32),
                    "block": "aa".repeat(32),
                    "block_height": 200_u64,
                    "block_time": 1_700_000_000_u64,
                })
                .to_string(),
            ),
        ],
        2,
    )
    .await;

    let result = blockfrost_at(server.base_url)
        .fetch_label309_records_since(100, &[], 600, 200)
        .await
        .expect("scan with a gap ahead of a same-height record");
    assert!(
        result.records.is_empty(),
        "a record at the gap's bound is not safe to emit-and-anchor this tick"
    );
    assert_eq!(
        result.frontier,
        ScanFrontier::Hold,
        "the gap could sit in the record's own block, so the cursor must hold"
    );
}

/// A window whose only label-309 transactions carry no chunk-array record
/// (non-carriage metadata) must ADVANCE past them — they are resolved, clean
/// skips — rather than hold forever. This mirrors the Koios highest-complete
/// semantics; holding would let cheap non-carriage label spam pin the frontier.
#[tokio::test]
async fn blockfrost_non_carriage_only_window_advances_instead_of_holding() {
    // "a1616101" = {"a": 1}: valid on-chain label-309 metadata that is not the
    // chunk-array carriage, so it resolves to a no-record skip.
    let labels_page = serde_json::json!([
        { "tx_hash": "22".repeat(32), "metadata": "a1616101" },
        { "tx_hash": "21".repeat(32), "metadata": "a1616101" },
    ])
    .to_string();
    let coords = |byte: u8, height: u64| {
        let hex = format!("{byte:02x}").repeat(32);
        route(
            format!("/txs/{hex}"),
            serde_json::json!({
                "hash": hex,
                "block": "aa".repeat(32),
                "block_height": height,
                "block_time": 1_700_000_000_u64,
            })
            .to_string(),
        )
    };
    let server = spawn_router(
        vec![
            route("/metadata/txs/labels", labels_page),
            coords(0x22, 210),
            coords(0x21, 200),
        ],
        3,
    )
    .await;

    let result = blockfrost_at(server.base_url)
        .fetch_label309_records_since(100, &[], 600, 200)
        .await
        .expect("scan over a non-carriage-only window");
    assert!(result.records.is_empty(), "nothing to index");
    assert_eq!(
        result.frontier,
        ScanFrontier::CaughtUpTo { indexed_to: 210 },
        "resolved no-record transactions advance the frontier, never hold it"
    );
}

/// A resume tick where EVERYTHING in the boundary block was already consumed:
/// the walk sees only excluded rows, proving the provider's index covers the
/// block with nothing new beyond the exclusions — and NO gap is outstanding —
/// so it reports caught-up-to-the-block and the scan can close it out instead
/// of holding forever.
#[tokio::test]
async fn blockfrost_intra_block_resume_with_nothing_left_reports_the_block_caught_up() {
    let labels_page = serde_json::json!([
        { "tx_hash": "22".repeat(32), "metadata": "a11901358144a2010203" },
        { "tx_hash": "21".repeat(32), "metadata": "a11901358144a2010203" },
    ])
    .to_string();
    let server = spawn_router(vec![route("/metadata/txs/labels", labels_page)], 2).await;

    let consumed = [hash(0x21), hash(0x22)];
    let result = blockfrost_at(server.base_url.clone())
        .fetch_label309_records_since(199, &consumed, 600, 2)
        .await
        .expect("resume with a fully-consumed block");
    assert!(result.records.is_empty());
    assert_eq!(
        result.frontier,
        ScanFrontier::CaughtUpTo { indexed_to: 200 },
        "seen exclusions prove the block is covered: caught up to it, not held"
    );
    assert_eq!(
        server.count_paths_with_prefix("/txs/"),
        0,
        "no coordinate hydration for already-consumed transactions"
    );
}

#[tokio::test]
async fn blockfrost_scan_does_not_enumerate_blocks_by_height() {
    // The Blockfrost scan hydrates coordinates per listed transaction via
    // /txs/{hash}, never per block height via /blocks/{height}. Proving the
    // absence of /blocks calls keeps the no-per-block-enumeration invariant.
    let server = spawn_router(
        vec![
            route("/metadata/txs/labels", BLOCKFROST_LABELS_PAGE1),
            route(format!("/txs/{}", "11".repeat(32)), BLOCKFROST_TX_11),
            route(format!("/txs/{}", "22".repeat(32)), BLOCKFROST_TX_22),
            route(format!("/txs/{}", "33".repeat(32)), BLOCKFROST_TX_33),
        ],
        4,
    )
    .await;

    blockfrost_at(server.base_url.clone())
        .fetch_label309_records_since(499, &[], 600, 200)
        .await
        .expect("blockfrost forward scan");

    assert_eq!(
        server.count_paths_with_prefix("/blocks"),
        0,
        "the forward scan must hydrate by tx hash, never enumerate blocks"
    );
    // It read the label page once and hydrated only the listed hashes (the stop
    // at the below-cursor row means at most the three listed coords).
    assert_eq!(server.count_paths_with_prefix("/metadata/txs/labels"), 1);
    let coord_calls = server.count_paths_with_prefix("/txs/");
    assert!(
        coord_calls <= 3,
        "coordinate hydration is bounded by the listed hashes, saw {coord_calls}"
    );
}

#[tokio::test]
async fn blockfrost_scan_empty_first_page_holds_rather_than_jumping_the_given_tip() {
    let server = spawn_router(vec![route("/metadata/txs/labels", "[]")], 1).await;

    let result = blockfrost_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("empty page scan");

    assert!(result.records.is_empty());
    // An empty page does NOT prove Blockfrost's own metadata watermark reached the
    // given tip (which may come from the other provider, ahead of Blockfrost). The
    // scan HOLDS rather than jumping the cursor to the given tip and skipping a lag
    // gap; the next tick re-reads once Blockfrost surfaces a record.
    assert_eq!(result.frontier, ScanFrontier::Hold);
}

#[tokio::test]
async fn blockfrost_scan_404_on_the_first_page_holds_rather_than_jumping_the_given_tip() {
    // Blockfrost answers 404 when there are no rows for the label at this page; the
    // scan treats that as the head of ITS OWN index, but holds the cursor rather
    // than jumping the given tip past a possible metadata lag.
    let server = spawn_router(
        vec![route_status(
            "/metadata/txs/labels",
            "HTTP/1.1 404 Not Found",
            "{}",
        )],
        1,
    )
    .await;

    let result = blockfrost_at(server.base_url)
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("404 page scan");

    assert!(result.records.is_empty());
    assert_eq!(result.frontier, ScanFrontier::Hold);
}

#[tokio::test]
async fn both_providers_produce_byte_identical_record_bytes() {
    // The same two on-chain records, fetched through each provider's distinct wire
    // shape (Koios JSON chunk arrays vs Blockfrost full-metadatum hex), must yield
    // byte-identical bare record bytes so a record indexed from either provider
    // validates the same.
    let koios_server = spawn_router(
        vec![
            route("/tx_by_metalabel", KOIOS_METALABEL_CLEAN),
            route("/tx_metadata", KOIOS_METADATA),
        ],
        2,
    )
    .await;
    let blockfrost_server = spawn_router(
        vec![
            route("/metadata/txs/labels", BLOCKFROST_LABELS_PAGE1),
            route(format!("/txs/{}", "11".repeat(32)), BLOCKFROST_TX_11),
            route(format!("/txs/{}", "22".repeat(32)), BLOCKFROST_TX_22),
            route(format!("/txs/{}", "33".repeat(32)), BLOCKFROST_TX_33),
        ],
        4,
    )
    .await;

    let koios_records = koios_at(koios_server.base_url)
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("koios scan");
    let blockfrost_records = blockfrost_at(blockfrost_server.base_url)
        .fetch_label309_records_since(499, &[], 600, 200)
        .await
        .expect("blockfrost scan");

    let koios_by = by_hash(&koios_records.records);
    let blockfrost_by = by_hash(&blockfrost_records.records);

    for h in [hash(0x11), hash(0x22)] {
        let k = koios_by.get(&h).expect("koios record");
        let b = blockfrost_by.get(&h).expect("blockfrost record");
        assert_eq!(
            k.metadata_cbor, b.metadata_cbor,
            "both providers feed the validator byte-identical record bytes"
        );
        assert_eq!(k.block_height, b.block_height);
        assert_eq!(k.block_hash, b.block_hash);
        assert_eq!(k.block_time, b.block_time);
    }
}

// ---------------------------------------------------------------------------
// Submit-path error classification through the FULL HTTP path (GC-2).
//
// The submit paths read the error body off a real HTTP response and classify it.
// These drive `submit_tx` over the loopback server with real 400 bodies, so the
// status-read + body-inspection + classification all run end to end — not a
// pre-classified enum. A generic provider/proxy 400 must NOT become a NodeReject
// (it stays transient → failover, never a permanent-fail+refund of a valid tx); a
// real verbatim node ledger-reject body must become a NodeReject.
// ---------------------------------------------------------------------------

/// A bare signed-tx body the submit echoes back to the server; the content does
/// not matter because the server is scripted to reject by status.
fn dummy_signed_tx() -> Vec<u8> {
    vec![0x84, 0xa0, 0xa0, 0xf5, 0xf6]
}

#[tokio::test]
async fn koios_submit_generic_400_body_is_transient_failover_not_a_node_reject() {
    // A misconfigured Koios/proxy returns HTTP 400 with a GENERIC JSON envelope
    // (the shape a routing/auth error carries). The submit path must classify this
    // as a transient HTTP failure — so the failover wrapper retries the secondary —
    // NEVER a deterministic node reject that would permanently fail and auto-refund
    // a valid, never-broadcast transaction.
    let server = spawn_router(
        vec![route_status(
            "/submittx",
            "HTTP/1.1 400 Bad Request",
            "{\"error\":\"Bad Request\",\"message\":\"route not found\"}",
        )],
        1,
    )
    .await;

    let err = koios_at(server.base_url)
        .submit_tx(&dummy_signed_tx())
        .await
        .expect_err("a generic 400 must surface as an error, not a success");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::Http { status: 400 }),
        "a generic 400 envelope is a transient provider failure, not a ledger reject"
    );
    assert!(is_transient_chain_error(&err), "it must fail over");
    assert!(
        !is_deterministic_node_reject(&err),
        "it must NEVER permanently-fail+refund a valid tx"
    );
}

#[tokio::test]
async fn koios_submit_real_ledger_reject_body_is_a_node_reject() {
    // Koios proxies cardano-submit-api, which relays the node's structured
    // submit-validation error verbatim on a real ledger reject. The submit path
    // must classify this as a deterministic NodeReject (no node can accept it).
    let ledger_body = "{\"tag\":\"TxSubmitFail\",\"contents\":{\"tag\":\
        \"TxCmdTxSubmitValidationError\",\"contents\":{\"tag\":\
        \"TxValidationErrorInCardanoMode\",\"contents\":{\"kind\":\
        \"ShelleyTxValidationError\",\"error\":[\"ApplyTxError [UtxoFailure ...]\"]}}}}";
    let server = spawn_router(
        vec![route_status(
            "/submittx",
            "HTTP/1.1 400 Bad Request",
            ledger_body,
        )],
        1,
    )
    .await;

    let err = koios_at(server.base_url)
        .submit_tx(&dummy_signed_tx())
        .await
        .expect_err("a ledger reject must surface as an error");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::NodeReject { status: 400 }),
        "a verbatim node ledger-reject body is a deterministic node reject"
    );
    assert!(is_deterministic_node_reject(&err));
    assert!(
        !is_transient_chain_error(&err),
        "a proven ledger reject must not fail over"
    );
}

#[tokio::test]
async fn blockfrost_submit_generic_400_body_is_transient_failover_not_a_node_reject() {
    // Blockfrost's own routing/auth errors carry a generic `{status_code,error,
    // message}` envelope. A 400 of that shape must stay transient → failover.
    let server = spawn_router(
        vec![route_status(
            "/tx/submit",
            "HTTP/1.1 400 Bad Request",
            "{\"status_code\":400,\"error\":\"Bad Request\",\"message\":\"Invalid request\"}",
        )],
        1,
    )
    .await;

    let err = blockfrost_at(server.base_url)
        .submit_tx(&dummy_signed_tx())
        .await
        .expect_err("a generic 400 must surface as an error");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::Http { status: 400 }),
        "a generic Blockfrost 400 envelope is transient, not a ledger reject"
    );
    assert!(is_transient_chain_error(&err));
    assert!(!is_deterministic_node_reject(&err));
}

#[tokio::test]
async fn blockfrost_submit_real_ledger_reject_body_is_a_node_reject() {
    // Blockfrost relays the node's reject as a `transaction submit error
    // ShelleyTxValidationError ... (ApplyTxError [...])` string on a real reject.
    let ledger_body = "transaction submit error ShelleyTxValidationError \
        ShelleyBasedEraBabbage (ApplyTxError [UtxoFailure (FeeTooSmallUTxO ...)])";
    let server = spawn_router(
        vec![route_status(
            "/tx/submit",
            "HTTP/1.1 400 Bad Request",
            ledger_body,
        )],
        1,
    )
    .await;

    let err = blockfrost_at(server.base_url)
        .submit_tx(&dummy_signed_tx())
        .await
        .expect_err("a ledger reject must surface as an error");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::NodeReject { status: 400 }),
        "a verbatim Blockfrost node ledger-reject string is a deterministic node reject"
    );
    assert!(is_deterministic_node_reject(&err));
    assert!(!is_transient_chain_error(&err));
}

#[tokio::test]
async fn submit_provider_misconfig_404_is_transient_failover_regardless_of_body() {
    // A provider-side 404 (routing/auth misconfig) is transient → failover, even if
    // the body happens to look like a ledger reject: only a 400/422 can carry a real
    // ledger verdict, so a 404 is always a provider failure.
    let server = spawn_router(
        vec![route_status(
            "/submittx",
            "HTTP/1.1 404 Not Found",
            "ApplyTxError this body is ignored on a 404",
        )],
        1,
    )
    .await;

    let err = koios_at(server.base_url)
        .submit_tx(&dummy_signed_tx())
        .await
        .expect_err("a 404 must surface as an error");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::Http { status: 404 }),
        "a 404 is a provider-side failure, never a ledger reject"
    );
    assert!(is_transient_chain_error(&err));
    assert!(!is_deterministic_node_reject(&err));
}
