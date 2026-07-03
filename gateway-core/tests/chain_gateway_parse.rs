//! Fixture-driven coverage for the chain gateway's response parsing and error
//! classification, with no live HTTP.
//!
//! These exercise the pure parse/merge helpers the Koios gateway delegates to,
//! against committed Koios response fixtures that deliberately mix numeric and
//! quoted-string forms and include the missing-`/tx_info` fallback case. The
//! transient-error classification is table-driven so the failover set is pinned
//! exactly. The chunking constant is asserted to keep the keyless body within the
//! public-tier limit.

use std::collections::HashMap;

use gateway_core::chain::gateway::{
    chain_error, classify_chain_error, is_transient_chain_error, merge_koios_confirmations,
    parse_blockfrost_label_row, parse_koios_chain_tip, parse_koios_metadata_row,
    parse_koios_metalabel_rows, parse_koios_tx_status, resolve_scan_frontier,
    unwrap_label309_chunked_metadatum, ChainErrorClass, ListedTx, ScanFrontier, TxPresence,
    KOIOS_KEYLESS_CHUNK, KOIOS_REGISTERED_CHUNK,
};
use gateway_core::Error;

const TX_STATUS_FIXTURE: &str = include_str!("fixtures/chain/tx_status.json");
const TX_INFO_FIXTURE: &str = include_str!("fixtures/chain/tx_info.json");
const TIP_FIXTURE: &str = include_str!("fixtures/chain/tip.json");
const TIP_STRING_FIXTURE: &str = include_str!("fixtures/chain/tip_string_height.json");

/// A 32-byte hash whose every byte is `b`.
fn hash(b: u8) -> [u8; 32] {
    [b; 32]
}

fn rows(fixture: &str) -> Vec<serde_json::Value> {
    serde_json::from_str(fixture).expect("fixture is a JSON array")
}

#[test]
fn tip_parses_block_height_and_epoch_as_number() {
    let tip = parse_koios_chain_tip(&rows(TIP_FIXTURE)).expect("parse tip");
    assert_eq!(tip.block_height, 2_891_234);
    // The same `/tip` read carries the epoch, so the scan can materialise it for
    // the protocol-parameter populate loop.
    assert_eq!(tip.epoch, Some(213));
}

#[test]
fn tip_parses_block_height_and_epoch_as_quoted_string() {
    // Some Koios deployments quote even the tip height and epoch; the lenient
    // parse accepts both, and the deprecated block_no in the same row is never
    // read.
    let tip = parse_koios_chain_tip(&rows(TIP_STRING_FIXTURE)).expect("parse string tip");
    assert_eq!(tip.block_height, 2_891_234);
    assert_eq!(tip.epoch, Some(508));
}

#[test]
fn tip_with_no_rows_is_a_bad_response_error() {
    // An empty tip body is a malformed-but-successful response: a deterministic
    // BadResponse the failover wrapper must surface, not retry on a second
    // provider or treat as a cooldown.
    let empty: Vec<serde_json::Value> = vec![];
    let err = parse_koios_chain_tip(&empty).expect_err("an empty tip body is rejected");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::BadResponse)
    );
}

#[test]
fn tx_status_keeps_on_chain_rows_in_both_numeric_forms_and_drops_mempool() {
    let parsed = parse_koios_tx_status(&rows(TX_STATUS_FIXTURE)).expect("parse tx_status");
    let by_hash: HashMap<[u8; 32], u64> = parsed.into_iter().collect();

    // A bare-number confirmation and a quoted-string confirmation both decode.
    assert_eq!(by_hash.get(&hash(0x11)).copied(), Some(5));
    assert_eq!(by_hash.get(&hash(0x33)).copied(), Some(12));
    assert_eq!(by_hash.get(&hash(0x44)).copied(), Some(1));
    // A null-confirmation row is still in the mempool: not on chain.
    assert!(!by_hash.contains_key(&hash(0x22)));
}

#[test]
fn full_two_step_merge_hydrates_coordinates_and_drops_a_coordinateless_confirmation() {
    // Reproduce the gateway's two-step shape from the fixtures: the on-chain
    // subset from /tx_status, then the /tx_info rows that hydrate coordinates.
    let conf_by_hash: HashMap<[u8; 32], u64> = parse_koios_tx_status(&rows(TX_STATUS_FIXTURE))
        .expect("parse tx_status")
        .into_iter()
        .collect();
    let info_rows = rows(TX_INFO_FIXTURE);

    let requested = [hash(0x11), hash(0x22), hash(0x33), hash(0x44)];
    let map = merge_koios_confirmations(&requested, &conf_by_hash, &info_rows);

    // Every requested hash is answered (never omitted).
    assert_eq!(map.len(), requested.len());

    // 0x11: on chain and present in /tx_info -> full coordinates.
    let c11 = map.get(&hash(0x11)).unwrap();
    assert_eq!(c11.num_confirmations, 5);
    assert_eq!(c11.block_height, Some(2_891_230));
    assert!(c11.block_time.is_some(), "tx_timestamp hydrates block_time");
    assert_eq!(c11.presence(), TxPresence::OnChain);

    // 0x33: string-form confirmation, hydrated from /tx_info.
    let c33 = map.get(&hash(0x33)).unwrap();
    assert_eq!(c33.num_confirmations, 12);
    assert_eq!(c33.block_height, Some(2_891_223));

    // 0x22: null at /tx_status -> AFFIRMATIVELY not on chain.
    let c22 = map.get(&hash(0x22)).unwrap();
    assert_eq!(c22.num_confirmations, 0);
    assert!(c22.block_height.is_none());
    assert_eq!(c22.presence(), TxPresence::Absent);

    // 0x44: had a confirmation at /tx_status but is ABSENT from /tx_info (cross-
    // endpoint lag, a truncated response, or a rollback race). A confirmation count
    // without coordinates is an INCOMPLETE observation: it keeps the not-on-chain
    // NUMERIC shape (the confirm authority must not settle a record at a
    // fabricated height 0) but its presence is INCONCLUSIVE, never absent — the
    // lag window is exactly what a just-confirmed transaction looks like, and a
    // money decision reading it as absence would refund a landed publish.
    let c44 = map.get(&hash(0x44)).unwrap();
    assert_eq!(
        c44.num_confirmations, 0,
        "a confirmation with no block height is incomplete data, not an on-chain sighting"
    );
    assert!(
        c44.block_height.is_none(),
        "no coordinates means no on-chain claim, never an invented height"
    );
    assert_eq!(
        c44.presence(),
        TxPresence::Inconclusive,
        "a counted-but-unhydrated hash is inconclusive, never affirmative absence"
    );
}

#[test]
fn merge_with_no_on_chain_rows_answers_every_hash_not_on_chain() {
    let requested = [hash(0xaa), hash(0xbb)];
    let conf_by_hash: HashMap<[u8; 32], u64> = HashMap::new();
    let map = merge_koios_confirmations(&requested, &conf_by_hash, &[]);
    assert_eq!(map.len(), 2);
    for h in requested {
        let c = map.get(&h).unwrap();
        assert_eq!(c.num_confirmations, 0);
        assert!(c.block_height.is_none());
        assert_eq!(
            c.presence(),
            TxPresence::Absent,
            "a hash /tx_status never counted is affirmatively absent"
        );
    }
}

#[test]
fn merge_confirms_a_quoted_string_block_height() {
    // Some Koios deployments quote even numeric /tx_info fields. The confirm-side
    // merge must accept a quoted-string block_height exactly like the scan path, or
    // a legitimately confirmed tx would be skipped (and could be falsely rolled
    // back) purely because of number-vs-string encoding.
    let requested = [hash(0x11)];
    let conf_by_hash: HashMap<[u8; 32], u64> = [(hash(0x11), 9)].into_iter().collect();
    let info_rows = vec![serde_json::json!({
        "tx_hash": "11".repeat(32),
        "block_height": "2891230",
        "tx_timestamp": 1_700_000_000_u64,
    })];
    let map = merge_koios_confirmations(&requested, &conf_by_hash, &info_rows);
    let c11 = map.get(&hash(0x11)).unwrap();
    assert_eq!(
        c11.num_confirmations, 9,
        "a quoted-string height still confirms"
    );
    assert_eq!(
        c11.block_height,
        Some(2_891_230),
        "the quoted-string block height decodes"
    );
    assert!(c11.block_time.is_some());
}

#[test]
fn merge_drops_an_on_chain_row_with_a_missing_or_malformed_block_time() {
    // A confirmation must carry a REAL ledger block_time: a row with a real height
    // but an absent or unparseable tx_timestamp is an incomplete observation. It
    // must NOT confirm (the confirm path would otherwise synthesize a now() block
    // time and write a fabricated on-chain coordinate): the numeric shape stays
    // not-on-chain. But /tx_status positively counted the hash, so its presence
    // is INCONCLUSIVE — a money decision must not read the partial row as proof
    // the transaction does not exist.
    let requested = [hash(0x11), hash(0x22)];
    let conf_by_hash: HashMap<[u8; 32], u64> =
        [(hash(0x11), 9), (hash(0x22), 9)].into_iter().collect();
    let info_rows = vec![
        // 0x11: height present but tx_timestamp absent.
        serde_json::json!({
            "tx_hash": "11".repeat(32),
            "block_height": 2_891_230_u64,
        }),
        // 0x22: height present but tx_timestamp is not an epoch integer.
        serde_json::json!({
            "tx_hash": "22".repeat(32),
            "block_height": 2_891_231_u64,
            "tx_timestamp": "not-a-time",
        }),
    ];
    let map = merge_koios_confirmations(&requested, &conf_by_hash, &info_rows);
    for h in [hash(0x11), hash(0x22)] {
        let c = map.get(&h).unwrap();
        assert_eq!(
            c.num_confirmations, 0,
            "a confirmation with no real block_time is incomplete, never confirms"
        );
        assert!(
            c.block_height.is_none(),
            "an incomplete observation never carries a coordinate"
        );
        assert!(c.block_time.is_none());
        assert_eq!(
            c.presence(),
            TxPresence::Inconclusive,
            "a counted hash with a partial /tx_info row is inconclusive, never absent"
        );
    }
}

/// Transient classification is table-driven: every entry pins whether the class
/// triggers a failover and whether it arms the per-provider cooldown.
#[test]
fn transient_classification_table() {
    struct Case {
        class: ChainErrorClass,
        transient: bool,
        rate_limited: bool,
    }
    let cases = [
        Case {
            class: ChainErrorClass::Transport,
            transient: true,
            rate_limited: false,
        },
        Case {
            class: ChainErrorClass::Http { status: 425 },
            transient: true,
            rate_limited: false,
        },
        Case {
            class: ChainErrorClass::Http { status: 429 },
            transient: true,
            rate_limited: true,
        },
        Case {
            class: ChainErrorClass::Http { status: 500 },
            transient: true,
            rate_limited: false,
        },
        Case {
            class: ChainErrorClass::Http { status: 502 },
            transient: true,
            rate_limited: false,
        },
        Case {
            class: ChainErrorClass::Http { status: 503 },
            transient: true,
            rate_limited: false,
        },
        // A provider-side 4xx that is not a proven ledger reject (a bare 400, a
        // 401/403 auth misconfig, a 404 routing error) is TRANSIENT: it fails over
        // to the secondary rather than failing a well-formed request.
        Case {
            class: ChainErrorClass::Http { status: 400 },
            transient: true,
            rate_limited: false,
        },
        Case {
            class: ChainErrorClass::Http { status: 401 },
            transient: true,
            rate_limited: false,
        },
        Case {
            class: ChainErrorClass::Http { status: 404 },
            transient: true,
            rate_limited: false,
        },
        // The only non-transient classes: a malformed body and a proven ledger
        // reject — neither of which a second provider would answer differently.
        Case {
            class: ChainErrorClass::BadResponse,
            transient: false,
            rate_limited: false,
        },
        Case {
            class: ChainErrorClass::NodeReject { status: 400 },
            transient: false,
            rate_limited: false,
        },
        Case {
            class: ChainErrorClass::NodeReject { status: 422 },
            transient: false,
            rate_limited: false,
        },
    ];

    for case in cases {
        assert_eq!(
            case.class.is_transient(),
            case.transient,
            "transient classification for {:?}",
            case.class
        );
        assert_eq!(
            case.class.is_rate_limited(),
            case.rate_limited,
            "rate-limit classification for {:?}",
            case.class
        );
        // The class must survive a round trip through Error::ChainProvider so the
        // failover wrapper can recover it from the error alone.
        let err = chain_error(case.class, "detail for the operator");
        assert_eq!(classify_chain_error(&err), Some(case.class));
        assert_eq!(is_transient_chain_error(&err), case.transient);
    }
}

#[test]
fn an_unmarked_or_non_chain_error_is_never_transient() {
    // A ChainProvider string built without the classification marker (a plain
    // transport message) is treated as non-transient so it surfaces.
    let unmarked = Error::ChainProvider("building HTTP client failed".to_string());
    assert!(classify_chain_error(&unmarked).is_none());
    assert!(!is_transient_chain_error(&unmarked));

    // A non-provider error (a database error mid-call) never masquerades as a
    // transient provider blip.
    let config = Error::Config("not a provider error".to_string());
    assert!(!is_transient_chain_error(&config));
}

#[test]
fn keyless_chunk_size_stays_within_the_public_tier_body_limit() {
    // 14 hashes at 64 hex chars each is ~896 bytes plus the JSON envelope, under
    // the ~1 KB keyless POST body cap. The constant is load-bearing: a larger
    // value would have the public tier reject the request body.
    assert_eq!(KOIOS_KEYLESS_CHUNK, 14);
    let body_bytes = KOIOS_KEYLESS_CHUNK * 64;
    assert!(
        body_bytes < 1024,
        "the keyless chunk must fit the public-tier body limit"
    );
}

#[test]
fn registered_chunk_size_stays_within_the_registered_tier_body_limit() {
    // The registered tiers cap the request body at ~5 KiB (vs ~1 KiB keyless).
    // Budget the whole body, not just the raw hex: each hash costs 67 bytes
    // quoted and comma-separated, and the largest envelope is `/tx_info`'s with
    // its pinned boolean flags (~160 bytes). The keyed chunk must stay under
    // the cap with that worst-case envelope, and must actually be larger than
    // the keyless chunk (otherwise the key would buy nothing on the bulk paths).
    assert_eq!(KOIOS_REGISTERED_CHUNK, 70);
    let body_bytes = KOIOS_REGISTERED_CHUNK * 67 + 160;
    assert!(
        body_bytes < 5 * 1024,
        "the registered chunk must fit the registered-tier body limit with the \
         /tx_info flag envelope, got {body_bytes} bytes"
    );
    let (keyless, registered) = (KOIOS_KEYLESS_CHUNK, KOIOS_REGISTERED_CHUNK);
    assert!(
        registered > keyless,
        "the key must actually widen the bulk POST bodies ({registered} vs {keyless})"
    );
}

// ---------------------------------------------------------------------------
// Forward-scan list, metadata, and chunk-unwrap parsing.
// ---------------------------------------------------------------------------

/// Encode a definite-length CBOR array of byte-string chunks: the on-chain Label
/// 309 metadatum wrapper. Each chunk is encoded as a CBOR `bstr` with a
/// single-byte length (every chunk here is <= 23 bytes), so the wrapper is the
/// array header followed by the bstr-encoded chunks.
fn cbor_chunk_array(chunks: &[&[u8]]) -> Vec<u8> {
    assert!(chunks.len() < 24, "test chunk count fits a one-byte header");
    let mut out = vec![0x80 | (chunks.len() as u8)]; // array(n)
    for chunk in chunks {
        assert!(chunk.len() < 24, "test chunk fits a one-byte bstr header");
        out.push(0x40 | (chunk.len() as u8)); // bstr(len)
        out.extend_from_slice(chunk);
    }
    out
}

#[test]
fn unwrap_concatenates_the_on_chain_chunk_array_into_the_record_bytes() {
    // The on-chain wrapper is a CBOR array of bstr chunks; unwrapping must
    // concatenate them back into the bare record bytes the validator expects.
    let wrapped = cbor_chunk_array(&[&[0xaa, 0xbb], &[0xcc], &[0xdd, 0xee, 0xff]]);
    let unwrapped = unwrap_label309_chunked_metadatum(&wrapped)
        .expect("a well-formed chunk array is not provider corruption")
        .expect("a chunk array unwraps");
    assert_eq!(unwrapped, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
}

#[test]
fn unwrap_peels_the_blockfrost_label_keyed_metadata_map() {
    // Blockfrost's /metadata/txs/labels/{label}/cbor returns the whole
    // transaction-metadata map for the label, `{309: [chunk, ...]}`, not the bare
    // chunk array Koios's JSON path digs out. The unwrap must peel the `309` map
    // key and recover the SAME record bytes the bare-array form yields, so a record
    // indexed via Blockfrost is byte-identical to one indexed via Koios.
    let bare = cbor_chunk_array(&[&[0xaa, 0xbb], &[0xcc], &[0xdd, 0xee, 0xff]]);
    // Wrap the bare chunk array in a `{309: <array>}` CBOR map: a1 (map(1)) 19 0135
    // (unsigned key 309) followed by the chunk-array bytes.
    let mut wrapped_map = vec![0xa1, 0x19, 0x01, 0x35];
    wrapped_map.extend_from_slice(&bare);

    let from_map = unwrap_label309_chunked_metadatum(&wrapped_map)
        .expect("a well-formed map is not provider corruption")
        .expect("the label-keyed map unwraps");
    let from_bare = unwrap_label309_chunked_metadatum(&bare)
        .expect("a well-formed array is not provider corruption")
        .expect("the bare chunk array unwraps");
    assert_eq!(
        from_map, from_bare,
        "the Blockfrost label-keyed map and the bare chunk array recover identical record bytes"
    );
    assert_eq!(from_map, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
}

#[test]
fn unwrap_rejects_a_metadata_map_without_the_label_309_key() {
    // A metadata map carrying some OTHER label, but not 309, is not a label-309
    // metadatum and must not be coerced into one.
    // a1 (map(1)) 18 2a (unsigned key 42) 81 41 a0 (array of one one-byte chunk).
    let other_label = vec![0xa1, 0x18, 0x2a, 0x81, 0x41, 0xa0];
    assert_eq!(
        unwrap_label309_chunked_metadatum(&other_label).expect("a verdict on the transaction"),
        None
    );
}

#[test]
fn unwrap_rejects_bytes_that_are_not_a_chunk_array() {
    // A bare integer (not an array of byte strings, nor a label-keyed map) is not a
    // chunk wrapper.
    assert_eq!(
        unwrap_label309_chunked_metadatum(&[0x01]).expect("a verdict on the transaction"),
        None
    );
}

#[test]
fn unwrap_fails_an_over_cap_chunk_as_corrupt_provider_not_a_transaction_verdict() {
    // A 65-byte byte-string chunk cannot exist on chain (the ledger caps metadata
    // strings at 64 bytes), so a CBOR metadatum carrying one is corrupt provider
    // output. The unwrap must FAIL — a typed, failover-worthy provider error —
    // never resolve to "not a label-309 transaction", because that verdict would
    // let the scan cursor advance past a real on-chain record forever.
    // 81 (array(1)) 58 41 (bstr, one-byte length 65) + 65 bytes.
    let mut over_cap = vec![0x81, 0x58, 0x41];
    over_cap.extend_from_slice(&[0xab; 65]);

    let err = unwrap_label309_chunked_metadatum(&over_cap)
        .expect_err("an over-cap chunk is a provider failure, not a skip");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::CorruptProvider)
    );
    assert!(
        is_transient_chain_error(&err),
        "provider corruption must be failover-worthy: the secondary serves the true bytes"
    );

    // A chunk at exactly the cap is fine: 64 bytes is the ledger's limit.
    let mut at_cap = vec![0x81, 0x58, 0x40];
    at_cap.extend_from_slice(&[0xab; 64]);
    assert_eq!(
        unwrap_label309_chunked_metadatum(&at_cap)
            .expect("a 64-byte chunk is legal on chain")
            .expect("and unwraps"),
        vec![0xab; 64]
    );
}

#[test]
fn metalabel_rows_parse_coordinates_and_skip_malformed() {
    let body = serde_json::json!([
        {
            "tx_hash": "11".repeat(32),
            "block_hash": "22".repeat(32),
            "block_height": 500,
            "tx_timestamp": 1_700_000_000_u64,
        },
        // Missing block_hash: skipped, never silently coerced.
        { "tx_hash": "33".repeat(32), "block_height": 501, "tx_timestamp": 1_700_000_001_u64 },
    ]);
    let rows = serde_json::from_value::<Vec<serde_json::Value>>(body).unwrap();
    let page = parse_koios_metalabel_rows(&rows);
    assert_eq!(
        page.listed.len(),
        1,
        "the row missing a block hash is dropped"
    );
    assert_eq!(
        page.dropped, 1,
        "the malformed row is counted, not silently lost"
    );
    assert_eq!(page.listed[0].tx_hash, hash(0x11));
    assert_eq!(page.listed[0].block_hash, hash(0x22));
    assert_eq!(page.listed[0].block_height, 500);
}

#[test]
fn metalabel_rows_accept_a_quoted_string_block_height() {
    // Some Koios deployments render even numeric fields as quoted strings. The
    // metalabel parser must accept a quoted-string block_height, exactly like the
    // tip/tx_status parsers, so a quoting deployment does not drop every real row.
    let body = serde_json::json!([
        {
            "tx_hash": "11".repeat(32),
            "block_hash": "22".repeat(32),
            "block_height": "500",
            "tx_timestamp": 1_700_000_000_u64,
        },
    ]);
    let rows = serde_json::from_value::<Vec<serde_json::Value>>(body).unwrap();
    let page = parse_koios_metalabel_rows(&rows);
    assert_eq!(page.dropped, 0, "a quoted-string height is not malformed");
    assert_eq!(page.listed.len(), 1);
    assert_eq!(page.listed[0].block_height, 500);
}

#[test]
fn koios_metadata_row_unwraps_the_label309_chunk_array_from_json() {
    // Koios renders the on-chain chunk array as a JSON array of "0x<hex>"
    // strings under the label-309 key; the parse concatenates them.
    let body = serde_json::json!({
        "tx_hash": "ab".repeat(32),
        "metadata": { "309": ["0xa101", "0x8203"] },
    });
    let (tx_hash, cbor) = parse_koios_metadata_row(&body)
        .expect("a well-formed row is not provider corruption")
        .expect("a label-309 row parses");
    assert_eq!(tx_hash, hash(0xab));
    assert_eq!(cbor, vec![0xa1, 0x01, 0x82, 0x03]);
}

#[test]
fn koios_metadata_row_without_label_309_is_none() {
    // A transaction carrying only some OTHER metadata label is not a PoE record.
    let body = serde_json::json!({
        "tx_hash": "cd".repeat(32),
        "metadata": { "674": ["0xa0"] },
    });
    assert_eq!(
        parse_koios_metadata_row(&body).expect("a verdict on the transaction"),
        None
    );
}

#[test]
fn koios_metadata_row_with_an_over_cap_chunk_is_corrupt_provider_output() {
    // The JSON twin of the CBOR over-cap rule: a 65-byte hex chunk under the
    // label-309 key cannot be a rendering of chain data, so the row parse fails
    // as a typed, failover-worthy provider error rather than skipping the
    // transaction (which would advance the scan cursor past a real record).
    let body = serde_json::json!({
        "tx_hash": "ab".repeat(32),
        "metadata": { "309": [format!("0x{}", "cd".repeat(65))] },
    });
    let err = parse_koios_metadata_row(&body)
        .expect_err("an over-cap chunk is a provider failure, not a skip");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::CorruptProvider)
    );
    assert!(is_transient_chain_error(&err));

    // A non-chunk-array label-309 value (possible on chain) stays a transaction
    // verdict: skipped, never a provider failure.
    let non_carriage = serde_json::json!({
        "tx_hash": "ab".repeat(32),
        "metadata": { "309": 42 },
    });
    assert_eq!(
        parse_koios_metadata_row(&non_carriage).expect("a verdict on the transaction"),
        None
    );
}

#[test]
fn blockfrost_label_row_prefers_metadata_over_deprecated_cbor_metadata() {
    // The non-deprecated `metadata` hex field wins; a `\x` prefix on the
    // deprecated field is only consulted when the new field is absent.
    let preferred = serde_json::json!({
        "tx_hash": "ef".repeat(32),
        "metadata": "a101",
        "cbor_metadata": "\\xdead",
    });
    let (tx_hash, cbor) = parse_blockfrost_label_row(&preferred).expect("the new field wins");
    assert_eq!(tx_hash, hash(0xef));
    assert_eq!(cbor, vec![0xa1, 0x01]);

    let deprecated_only = serde_json::json!({
        "tx_hash": "ef".repeat(32),
        "cbor_metadata": "\\xa102",
    });
    let (_, cbor) =
        parse_blockfrost_label_row(&deprecated_only).expect("the deprecated field is the fallback");
    assert_eq!(cbor, vec![0xa1, 0x02], "the \\x prefix is stripped");
}

/// A listed transaction at `height` with one-byte-fill hashes.
fn listed_at(tx_fill: u8, block_fill: u8, height: u64) -> ListedTx {
    ListedTx {
        tx_hash: hash(tx_fill),
        block_hash: hash(block_fill),
        block_height: height,
        block_time: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    }
}

/// The set of tx hashes whose `/tx_metadata` row was observed (returned at all).
fn observed(fills: &[u8]) -> std::collections::HashSet<[u8; 32]> {
    fills.iter().map(|&b| hash(b)).collect()
}

#[test]
fn resolve_caught_up_with_no_gap_reports_the_provider_tip_watermark() {
    // Every listed transaction hydrated and the window was kept whole: the provider
    // is caught up to its own tip, so the frontier is `CaughtUpTo` the tip the call
    // was given (the caller then clamps to min(tip, watermark)).
    let listed = vec![listed_at(0x01, 0x02, 100), listed_at(0x03, 0x04, 101)];
    let mut metadata = HashMap::new();
    metadata.insert(hash(0x01), vec![0xa1, 0x01]);
    metadata.insert(hash(0x03), vec![0xa1, 0x02]);

    let result = resolve_scan_frontier(&listed, &metadata, &observed(&[0x01, 0x03]), 150, true);
    assert_eq!(result.records.len(), 2, "both hydrated records survive");
    assert_eq!(
        result.records[0].num_confirmations, 51,
        "confirmations = tip - block_height + 1 = 150 - 100 + 1"
    );
    assert_eq!(
        result.frontier,
        ScanFrontier::CaughtUpTo { indexed_to: 150 },
        "a gap-free caught-up window reports the tip watermark"
    );
}

#[test]
fn resolve_caps_below_a_metadata_hydration_gap_and_drops_records_above_it() {
    // The list query proved a label-309 record exists at block 101, but its
    // metadata row was NOT returned (a `/tx_metadata` gap). The frontier must anchor
    // STRICTLY below the gap (at the hydrated block 100) so the next tick re-fetches
    // the gap, and the record at/above the gap must NOT be emitted — never advance
    // the cursor past an un-hydrated record or it is lost forever.
    let listed = vec![
        listed_at(0x01, 0x02, 100),
        listed_at(0x03, 0x04, 101),
        listed_at(0x05, 0x06, 102),
    ];
    // hash(0x03) @ 101's row was NOT returned (the gap); hash(0x05) @ 102 hydrated
    // but sits above the gap, so it must not be emitted this fetch.
    let mut metadata = HashMap::new();
    metadata.insert(hash(0x01), vec![0xa1, 0x01]);
    metadata.insert(hash(0x05), vec![0xa1, 0x03]);

    let result = resolve_scan_frontier(&listed, &metadata, &observed(&[0x01, 0x05]), 150, true);
    assert_eq!(
        result.records.len(),
        1,
        "only the record below the gap is emitted; the one above it waits"
    );
    assert_eq!(result.records[0].tx_hash, hash(0x01));
    assert_eq!(
        result.frontier,
        ScanFrontier::Anchor {
            height: 100,
            block_hash: hash(0x02),
        },
        "the frontier anchors strictly below the gap, never jumps the tip past it"
    );
}

#[test]
fn resolve_holds_when_the_lowest_record_is_a_gap() {
    // The very first (lowest) listed record's row was NOT returned: there is no safe
    // height below the gap, so the cursor must HOLD and re-fetch the window next tick.
    let listed = vec![listed_at(0x01, 0x02, 100), listed_at(0x03, 0x04, 101)];
    let metadata = HashMap::new(); // nothing hydrated.

    let result = resolve_scan_frontier(&listed, &metadata, &observed(&[]), 150, true);
    assert!(result.records.is_empty(), "nothing below the gap to emit");
    assert_eq!(
        result.frontier,
        ScanFrontier::Hold,
        "with the lowest record a gap, the cursor holds rather than skip it"
    );
}

#[test]
fn resolve_anchors_at_the_highest_block_when_the_window_is_capped() {
    // A gap-free capped window (more records exist above it) anchors at the highest
    // kept block so the next tick resumes strictly above it, never `CaughtUpTo`.
    let listed = vec![listed_at(0x01, 0x02, 100), listed_at(0x03, 0x04, 101)];
    let mut metadata = HashMap::new();
    metadata.insert(hash(0x01), vec![0xa1, 0x01]);
    metadata.insert(hash(0x03), vec![0xa1, 0x02]);

    let result = resolve_scan_frontier(&listed, &metadata, &observed(&[0x01, 0x03]), 150, false);
    assert_eq!(result.records.len(), 2);
    assert_eq!(
        result.frontier,
        ScanFrontier::Anchor {
            height: 101,
            block_hash: hash(0x04),
        },
        "a capped window anchors at its highest block, not the tip"
    );
}

#[test]
fn resolve_treats_a_returned_non_carriage_as_a_clean_skip_not_a_gap() {
    // A listed tx whose `/tx_metadata` row WAS returned but is genuinely not a
    // chunk-array carriage (a verdict on the TRANSACTION, valid on chain) is NOT a
    // hydration gap: it produces no record, but its block is fully resolved, so the
    // frontier safely advances PAST it to the higher carriage record. Only a row
    // that was never returned is a barrier.
    let listed = vec![
        listed_at(0x01, 0x02, 100), // observed, non-carriage (a clean skip).
        listed_at(0x03, 0x04, 101), // observed, a real carriage record.
    ];
    let mut metadata = HashMap::new();
    metadata.insert(hash(0x03), vec![0xa1, 0x02]); // only 0x03 is a carriage.

    let result = resolve_scan_frontier(&listed, &metadata, &observed(&[0x01, 0x03]), 150, true);
    assert_eq!(
        result.records.len(),
        1,
        "the non-carriage produces no record, but the carriage above it is emitted"
    );
    assert_eq!(result.records[0].tx_hash, hash(0x03));
    assert_eq!(
        result.frontier,
        ScanFrontier::CaughtUpTo { indexed_to: 150 },
        "a returned non-carriage is a clean skip, never a barrier: the frontier \
         reaches the watermark"
    );
}
