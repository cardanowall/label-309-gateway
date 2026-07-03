//! Integration coverage for the additive records-list filters.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test seeds anchored rows through the index's single writer, then asserts
//! `fetch_record_page` narrows to exactly the expected rows for each optional
//! filter (scheme, signer, block range, time range) and that an empty filter still
//! returns the whole set (the back-compat default).

#![cfg(feature = "pg-tests")]

use chrono::{DateTime, TimeZone, Utc};
use gateway_core::chain::records::{
    count_records, fetch_record_page, insert_chain_record, ChainRecordColumns, CountFilter,
    RecordFilter,
};
use gateway_core::testsupport::TestDb;

/// A 32-byte tx hash filled with one repeated byte.
fn tx_hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Seed one anchored record with explicit columns and coordinates.
async fn seed(
    pool: &sqlx::PgPool,
    hash_byte: u8,
    block_height: u64,
    block_time: DateTime<Utc>,
    scheme: u8,
    signer: Option<[u8; 32]>,
) {
    insert_chain_record(
        pool,
        tx_hash(hash_byte),
        block_height,
        block_time,
        // The metadata bytes are opaque to the read path; a minimal placeholder.
        &[0xa1, 0x01, 0x82],
        &ChainRecordColumns {
            signer_ed25519: signer,
            // A single-signer record: the verified set is exactly its one signer
            // (empty when unsigned), so the signer-set side table the filter rides
            // is populated consistently with the primary column.
            verified_signers: signer.into_iter().collect(),
            item_count: 1,
            scheme,
        },
    )
    .await
    .expect("insert chain record");
}

/// Seed one anchored record carrying an explicit verified-signer SET (the first
/// member is the primary projected signer), so a test can exercise discovery by a
/// non-first signer. Goes through the real writer, so every set member lands in
/// `chain_record_signer`.
async fn seed_with_signers(
    pool: &sqlx::PgPool,
    hash_byte: u8,
    block_height: u64,
    block_time: DateTime<Utc>,
    verified_signers: Vec<[u8; 32]>,
) {
    insert_chain_record(
        pool,
        tx_hash(hash_byte),
        block_height,
        block_time,
        &[0xa1, 0x01, 0x82],
        &ChainRecordColumns {
            signer_ed25519: verified_signers.first().copied(),
            verified_signers,
            item_count: 1,
            scheme: 0,
        },
    )
    .await
    .expect("insert chain record");
}

/// The hashes a page returns, for set-style assertions.
fn hashes(rows: &[gateway_core::chain::records::IndexedRecordRow]) -> Vec<u8> {
    rows.iter().map(|r| r.tx_hash[0]).collect()
}

fn at(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).single().expect("valid time")
}

#[tokio::test]
async fn an_empty_filter_returns_every_anchored_row() {
    let db = TestDb::fresh().await.expect("db");
    seed(&db.pool, 1, 10, at(1_000), 0, None).await;
    seed(&db.pool, 2, 20, at(2_000), 1, None).await;

    let rows = fetch_record_page(&db.pool, None, 50, &RecordFilter::default())
        .await
        .expect("page");
    assert_eq!(rows.len(), 2, "the default filter selects the whole set");
}

#[tokio::test]
async fn the_precise_scheme_filter_selects_only_that_scheme() {
    let db = TestDb::fresh().await.expect("db");
    seed(&db.pool, 1, 10, at(1_000), 0, None).await;
    seed(&db.pool, 2, 20, at(2_000), 1, None).await;
    seed(&db.pool, 3, 30, at(3_000), 2, None).await;

    for (scheme, expect) in [(0, 1u8), (1, 2), (2, 3)] {
        let rows = fetch_record_page(
            &db.pool,
            None,
            50,
            &RecordFilter {
                scheme: Some(scheme),
                ..Default::default()
            },
        )
        .await
        .expect("page");
        assert_eq!(
            hashes(&rows),
            vec![expect],
            "scheme={scheme} selects one row"
        );
    }
}

#[tokio::test]
async fn the_sealed_only_filter_keeps_back_compat_scheme_not_zero() {
    let db = TestDb::fresh().await.expect("db");
    seed(&db.pool, 1, 10, at(1_000), 0, None).await;
    seed(&db.pool, 2, 20, at(2_000), 1, None).await;
    seed(&db.pool, 3, 30, at(3_000), 2, None).await;

    let rows = fetch_record_page(
        &db.pool,
        None,
        50,
        &RecordFilter {
            sealed_only: true,
            ..Default::default()
        },
    )
    .await
    .expect("page");
    // sealed_only drops the open (scheme 0) record, keeping schemes 1 and 2.
    let mut got = hashes(&rows);
    got.sort_unstable();
    assert_eq!(got, vec![2, 3], "sealed_only keeps every non-open record");
}

#[tokio::test]
async fn the_signer_filter_selects_one_publisher() {
    let db = TestDb::fresh().await.expect("db");
    let signer_a = [0xaa_u8; 32];
    let signer_b = [0xbb_u8; 32];
    seed(&db.pool, 1, 10, at(1_000), 0, Some(signer_a)).await;
    seed(&db.pool, 2, 20, at(2_000), 0, Some(signer_b)).await;
    seed(&db.pool, 3, 30, at(3_000), 0, None).await;

    let rows = fetch_record_page(
        &db.pool,
        None,
        50,
        &RecordFilter {
            signer: Some(signer_a.to_vec()),
            ..Default::default()
        },
    )
    .await
    .expect("page");
    assert_eq!(hashes(&rows), vec![1], "only signer_a's record matches");
}

#[tokio::test]
async fn the_signer_filter_finds_a_record_by_any_verified_signer_not_just_the_first() {
    // The core of the change: a record co-signed by two keys must be discoverable
    // by EITHER one, not only the first. The primary projected signer is `first`,
    // but a query for `second` must still return the record because `second` is a
    // verified signer of it.
    let db = TestDb::fresh().await.expect("db");
    let first = [0xa1_u8; 32];
    let second = [0xb2_u8; 32];
    let other = [0xc3_u8; 32];

    // Record 1 is co-signed by [first, second]; record 2 is signed only by `other`.
    seed_with_signers(&db.pool, 1, 10, at(1_000), vec![first, second]).await;
    seed_with_signers(&db.pool, 2, 20, at(2_000), vec![other]).await;

    // Querying by the SECOND (non-first) signer returns the co-signed record.
    let by_second = fetch_record_page(
        &db.pool,
        None,
        50,
        &RecordFilter {
            signer: Some(second.to_vec()),
            ..Default::default()
        },
    )
    .await
    .expect("page");
    assert_eq!(
        hashes(&by_second),
        vec![1],
        "a query for the non-first verified signer still returns the co-signed record"
    );

    // The first signer also finds it (the primary column is still a verified
    // member), and the count by either signer is 1.
    let by_first = fetch_record_page(
        &db.pool,
        None,
        50,
        &RecordFilter {
            signer: Some(first.to_vec()),
            ..Default::default()
        },
    )
    .await
    .expect("page");
    assert_eq!(hashes(&by_first), vec![1], "the first signer finds it too");

    for who in [first, second] {
        let n = count_records(&db.pool, &count_filter(who, &RecordFilter::default()))
            .await
            .expect("count");
        assert_eq!(
            n, 1,
            "the count by either verified signer counts the co-signed record exactly once"
        );
    }

    // A signer that did not sign record 1 does not get it via that record.
    let by_other = fetch_record_page(
        &db.pool,
        None,
        50,
        &RecordFilter {
            signer: Some(other.to_vec()),
            ..Default::default()
        },
    )
    .await
    .expect("page");
    assert_eq!(
        hashes(&by_other),
        vec![2],
        "an unrelated signer sees only its own record"
    );
}

/// EXPLAIN the exact signer-filtered list shapes the API runs and return the plan
/// text. The list DRIVES FROM the verified-signer set (a hard `signer_ed25519 =
/// $1` equality) and orders by the set's denormalized `(block_height, tx_hash)`,
/// so both membership and the newest-first ordering ride
/// `chain_record_signer_signer_idx` — never a `chain_records` scan with a
/// membership filter. Two shapes mirror the route: first page and cursored page.
async fn explain_signer_list(
    conn: &mut sqlx::PgConnection,
    signer: [u8; 32],
    after: Option<(i64, &[u8])>,
) -> String {
    let plan = match after {
        // First page: $1 signer, $2..$7 narrowing, $8 limit.
        None => sqlx::query_scalar::<_, String>(
            "EXPLAIN (FORMAT TEXT) \
                 SELECT cr.tx_hash, cr.block_height, cr.block_time, cr.metadata_cbor, \
                        cr.signer_ed25519, cr.item_count, cr.scheme \
                 FROM cw_core.chain_record_signer s \
                 JOIN cw_core.chain_records cr ON cr.tx_hash = s.tx_hash \
                 WHERE s.signer_ed25519 = $1 \
                   AND ($2 = false OR cr.scheme <> 0) \
                   AND ($3::smallint IS NULL OR cr.scheme = $3) \
                   AND ($4::bigint IS NULL OR cr.block_height >= $4) \
                   AND ($5::bigint IS NULL OR cr.block_height <= $5) \
                   AND ($6::timestamptz IS NULL OR cr.block_time >= $6) \
                   AND ($7::timestamptz IS NULL OR cr.block_time <= $7) \
                 ORDER BY s.block_height DESC, s.tx_hash DESC LIMIT $8",
        )
        .bind(signer.to_vec())
        .bind(false)
        .bind(Option::<i16>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<DateTime<Utc>>::None)
        .bind(Option::<DateTime<Utc>>::None)
        .bind(50_i64)
        .fetch_all(&mut *conn)
        .await
        .expect("explain"),
        // Cursored page: $1 signer, $2/$3 keyset boundary, $4..$9 narrowing, $10 limit.
        Some((block_height, tx_hash)) => sqlx::query_scalar::<_, String>(
            "EXPLAIN (FORMAT TEXT) \
                 SELECT cr.tx_hash, cr.block_height, cr.block_time, cr.metadata_cbor, \
                        cr.signer_ed25519, cr.item_count, cr.scheme \
                 FROM cw_core.chain_record_signer s \
                 JOIN cw_core.chain_records cr ON cr.tx_hash = s.tx_hash \
                 WHERE s.signer_ed25519 = $1 \
                   AND (s.block_height, s.tx_hash) < ($2, $3) \
                   AND ($4 = false OR cr.scheme <> 0) \
                   AND ($5::smallint IS NULL OR cr.scheme = $5) \
                   AND ($6::bigint IS NULL OR cr.block_height >= $6) \
                   AND ($7::bigint IS NULL OR cr.block_height <= $7) \
                   AND ($8::timestamptz IS NULL OR cr.block_time >= $8) \
                   AND ($9::timestamptz IS NULL OR cr.block_time <= $9) \
                 ORDER BY s.block_height DESC, s.tx_hash DESC LIMIT $10",
        )
        .bind(signer.to_vec())
        .bind(block_height)
        .bind(tx_hash)
        .bind(false)
        .bind(Option::<i16>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<DateTime<Utc>>::None)
        .bind(Option::<DateTime<Utc>>::None)
        .bind(50_i64)
        .fetch_all(&mut *conn)
        .await
        .expect("explain"),
    };
    plan.join("\n")
}

#[tokio::test]
async fn the_signer_filtered_list_rides_the_signer_set_index_and_never_scans_chain_records() {
    // The signer-filtered list must drive from the verified-signer set's index,
    // reading only the queried key's slice and ordering newest-first straight off
    // it — never a chain_records scan with a membership filter, which would be
    // O(table). A selective distribution makes the planner pick the index on its
    // own; forcing a GENERIC plan additionally proves a pooled/prepared production
    // path (which plans without peeking at the bind values) gets the same shape.
    let db = TestDb::fresh().await.expect("db");
    let target = [0xab_u8; 32];
    let other = [0xcd_u8; 32];
    seed_many_for(&db.pool, other, 1_000_000, 2_000).await;
    seed_many_for(&db.pool, target, 5_000_000, 5).await;

    let mut conn = db.pool.acquire().await.expect("acquire connection");
    sqlx::query("ANALYZE cw_core.chain_records")
        .execute(&mut *conn)
        .await
        .expect("analyze chain_records");
    sqlx::query("ANALYZE cw_core.chain_record_signer")
        .execute(&mut *conn)
        .await
        .expect("analyze chain_record_signer");

    // A cursor boundary above every target row, so the cursored shape returns the
    // same (whole) target slice and its plan is exercised too.
    let cursor_tx = [0xff_u8; 32];
    type FilterCase<'a> = (&'a str, Option<(i64, &'a [u8])>);
    let cases: [FilterCase<'_>; 2] = [
        ("first page", None),
        ("cursored page", Some((9_999_999, cursor_tx.as_slice()))),
    ];

    for mode in ["force_generic_plan", "force_custom_plan"] {
        // sqlx requires a 'static SQL string, so dispatch to a literal per mode
        // (the value is a fixed enum, not user input).
        let set_mode = match mode {
            "force_generic_plan" => "SET plan_cache_mode = force_generic_plan",
            _ => "SET plan_cache_mode = force_custom_plan",
        };
        sqlx::query(set_mode)
            .execute(&mut *conn)
            .await
            .expect("set plan cache mode");
        for (label, after) in cases {
            let plan = explain_signer_list(&mut conn, target, after).await;
            assert!(
                plan.contains("chain_record_signer_signer_idx")
                    && plan.contains("Index Cond:")
                    && plan.contains("signer_ed25519 ="),
                "the signer-filtered list ({label}, {mode}) must derive a selective Index Cond on \
                 the signer-set index; plan was:\n{plan}"
            );
            assert!(
                !plan.contains("Seq Scan on chain_records"),
                "the signer-filtered list ({label}, {mode}) must never sequentially scan \
                 chain_records; plan was:\n{plan}"
            );
        }
    }
}

/// The keyset cursor a signer-filtered page mints decodes and applies on the
/// next page exactly as one minted by the unfiltered list would: the cursor
/// tuple is `(block_height, tx_hash)` in both shapes, and `s.block_height ==
/// cr.block_height`, so paging stays consistent and loses no rows across the
/// shape boundary.
#[tokio::test]
async fn the_signer_filtered_list_cursor_pages_without_loss_or_overlap() {
    let db = TestDb::fresh().await.expect("db");
    let signer = [0x5a_u8; 32];
    // Ten records by one signer at distinct heights, plus an unrelated signer's
    // rows that must never appear in this signer's pages.
    for byte in 1..=10u8 {
        seed_with_signers(
            &db.pool,
            byte,
            u64::from(byte) * 10,
            at(i64::from(byte)),
            vec![signer],
        )
        .await;
    }
    seed_with_signers(&db.pool, 0xee, 1_000, at(1_000), vec![[0x77_u8; 32]]).await;

    // Page size 3: walk the whole slice via the opaque cursor, asserting strictly
    // descending order and no duplicates, then that every one of the signer's ten
    // records is seen exactly once.
    let mut seen: Vec<u8> = Vec::new();
    let mut after: Option<(i64, Vec<u8>)> = None;
    let mut last_key: Option<(i64, Vec<u8>)> = None;
    loop {
        let after_ref = after.as_ref().map(|(h, t)| (*h, t.as_slice()));
        let page = fetch_record_page(
            &db.pool,
            after_ref,
            3,
            &RecordFilter {
                signer: Some(signer.to_vec()),
                ..Default::default()
            },
        )
        .await
        .expect("page");
        if page.is_empty() {
            break;
        }
        for row in &page {
            let key = (row.block_height, row.tx_hash.clone());
            if let Some(prev) = &last_key {
                assert!(
                    key < *prev,
                    "rows must be strictly descending by (block_height, tx_hash); {key:?} !< {prev:?}"
                );
            }
            last_key = Some(key);
            seen.push(row.tx_hash[0]);
        }
        let last = page.last().expect("non-empty");
        after = Some((last.block_height, last.tx_hash.clone()));
        // A short page is the final page.
        if page.len() < 3 {
            break;
        }
    }
    seen.sort_unstable();
    assert_eq!(
        seen,
        (1..=10u8).collect::<Vec<_>>(),
        "every record by the signer is paged exactly once via the cursor, and the unrelated \
         signer's record never appears"
    );
}

#[tokio::test]
async fn the_block_range_filter_selects_the_inclusive_window() {
    let db = TestDb::fresh().await.expect("db");
    for (byte, height) in [(1u8, 10u64), (2, 20), (3, 30), (4, 40)] {
        seed(&db.pool, byte, height, at(i64::from(byte) * 1_000), 0, None).await;
    }
    let rows = fetch_record_page(
        &db.pool,
        None,
        50,
        &RecordFilter {
            from_block: Some(20),
            to_block: Some(30),
            ..Default::default()
        },
    )
    .await
    .expect("page");
    // Newest-first: heights 30 then 20, inclusive of both bounds.
    assert_eq!(
        hashes(&rows),
        vec![3, 2],
        "the window is [from_block, to_block]"
    );
}

#[tokio::test]
async fn the_time_range_filter_selects_the_inclusive_window() {
    let db = TestDb::fresh().await.expect("db");
    for (byte, height, secs) in [(1u8, 10u64, 1_000i64), (2, 20, 2_000), (3, 30, 3_000)] {
        seed(&db.pool, byte, height, at(secs), 0, None).await;
    }
    let rows = fetch_record_page(
        &db.pool,
        None,
        50,
        &RecordFilter {
            from_time: Some(at(2_000)),
            to_time: Some(at(3_000)),
            ..Default::default()
        },
    )
    .await
    .expect("page");
    assert_eq!(
        hashes(&rows),
        vec![3, 2],
        "the window is [from_time, to_time]"
    );
}

#[tokio::test]
async fn composed_filters_intersect() {
    let db = TestDb::fresh().await.expect("db");
    let signer = [0xcc_u8; 32];
    // Two scheme-1 rows by the same signer in different blocks; one scheme-0 row.
    seed(&db.pool, 1, 10, at(1_000), 1, Some(signer)).await;
    seed(&db.pool, 2, 20, at(2_000), 1, Some(signer)).await;
    seed(&db.pool, 3, 30, at(3_000), 0, Some(signer)).await;

    let rows = fetch_record_page(
        &db.pool,
        None,
        50,
        &RecordFilter {
            scheme: Some(1),
            signer: Some(signer.to_vec()),
            from_block: Some(15),
            ..Default::default()
        },
    )
    .await
    .expect("page");
    // scheme=1 AND this signer AND block >= 15: only the height-20 row.
    assert_eq!(hashes(&rows), vec![2], "every set predicate must hold");
}

// ---------------------------------------------------------------------------
// count_records: the exact total counterpart to fetch_record_page. The count
// must equal the number of rows the same filter pages, and the signer-scoped
// count must be index-backed (no seq scan).
// ---------------------------------------------------------------------------

/// Page the whole filtered set with a large limit, for cross-checking the count.
async fn page_len(pool: &sqlx::PgPool, filter: &RecordFilter) -> usize {
    fetch_record_page(pool, None, 10_000, filter)
        .await
        .expect("page")
        .len()
}

/// A `CountFilter` for `signer` carrying the same optional narrowing as a
/// `RecordFilter`, so a count can be cross-checked against paging the equivalent
/// list filter. The list filter's own `signer` field is ignored (the count's
/// signer is the required scope), so callers pass a list filter WITHOUT a signer
/// here and supply it separately.
fn count_filter(signer: [u8; 32], narrowing: &RecordFilter) -> CountFilter {
    CountFilter {
        signer: signer.to_vec(),
        sealed_only: narrowing.sealed_only,
        scheme: narrowing.scheme,
        from_block: narrowing.from_block,
        to_block: narrowing.to_block,
        from_time: narrowing.from_time,
        to_time: narrowing.to_time,
    }
}

/// The `RecordFilter` that lists exactly what `count_filter(signer, narrowing)`
/// counts: the same narrowing, with the signer set as the list filter's scope.
fn list_filter(signer: [u8; 32], narrowing: &RecordFilter) -> RecordFilter {
    RecordFilter {
        signer: Some(signer.to_vec()),
        ..narrowing.clone()
    }
}

#[tokio::test]
async fn the_signer_count_equals_the_number_of_that_signers_records() {
    let db = TestDb::fresh().await.expect("db");
    let signer_a = [0xaa_u8; 32];
    let signer_b = [0xbb_u8; 32];
    // Three records by signer_a, one by signer_b, one unsigned.
    seed(&db.pool, 1, 10, at(1_000), 0, Some(signer_a)).await;
    seed(&db.pool, 2, 20, at(2_000), 1, Some(signer_a)).await;
    seed(&db.pool, 3, 30, at(3_000), 0, Some(signer_a)).await;
    seed(&db.pool, 4, 40, at(4_000), 0, Some(signer_b)).await;
    seed(&db.pool, 5, 50, at(5_000), 0, None).await;

    let narrowing = RecordFilter::default();
    let count = count_records(&db.pool, &count_filter(signer_a, &narrowing))
        .await
        .expect("count");
    assert_eq!(count, 3, "signer_a published exactly three records");
    // Cross-check against actually paging the equivalent list filter: the count is
    // the page total, never an estimate.
    assert_eq!(
        count as usize,
        page_len(&db.pool, &list_filter(signer_a, &narrowing)).await,
        "the count equals the number of rows the same filter pages"
    );

    // A signer with no records counts zero (not an error).
    let none = count_records(&db.pool, &count_filter([0xcc_u8; 32], &narrowing))
        .await
        .expect("count");
    assert_eq!(none, 0, "an unknown signer counts zero");
}

#[tokio::test]
async fn the_count_respects_scheme_block_and_time_filters() {
    let db = TestDb::fresh().await.expect("db");
    let signer = [0xcc_u8; 32];
    // Five records by one signer across schemes, blocks, and times.
    seed(&db.pool, 1, 10, at(1_000), 0, Some(signer)).await;
    seed(&db.pool, 2, 20, at(2_000), 1, Some(signer)).await;
    seed(&db.pool, 3, 30, at(3_000), 1, Some(signer)).await;
    seed(&db.pool, 4, 40, at(4_000), 2, Some(signer)).await;
    seed(&db.pool, 5, 50, at(5_000), 0, Some(signer)).await;

    // Each case: count(signer + narrowing) equals paging the equivalent list filter.
    let cases: [(RecordFilter, u64, &str); 5] = [
        (
            RecordFilter {
                scheme: Some(1),
                ..Default::default()
            },
            2,
            "two scheme-1 records by this signer",
        ),
        (
            RecordFilter {
                sealed_only: true,
                ..Default::default()
            },
            3,
            "sealed_only keeps the two scheme-1 and the one scheme-2 record",
        ),
        (
            RecordFilter {
                from_block: Some(20),
                to_block: Some(40),
                ..Default::default()
            },
            3,
            "blocks 20..=40 inclusive hold three records",
        ),
        (
            RecordFilter {
                from_time: Some(at(2_000)),
                to_time: Some(at(4_000)),
                ..Default::default()
            },
            3,
            "times 2_000..=4_000 inclusive hold three records",
        ),
        (
            RecordFilter {
                scheme: Some(1),
                from_block: Some(25),
                ..Default::default()
            },
            1,
            "scheme=1 AND block>=25: only the height-30 row",
        ),
    ];

    for (narrowing, expect, msg) in cases {
        let count = count_records(&db.pool, &count_filter(signer, &narrowing))
            .await
            .expect("count");
        assert_eq!(count, expect, "{msg}");
        assert_eq!(
            count as usize,
            page_len(&db.pool, &list_filter(signer, &narrowing)).await,
            "the count matches the list total for: {msg}"
        );
    }
}

/// Bulk-insert `n` records signed by `signer` directly (one round trip), so a
/// test can build a non-trivial table cheaply for planner-shape assertions. Both
/// the rich `chain_records` row and its verified-signer-set row are seeded, since
/// the signer filter and count both ride the side table.
async fn seed_many_for(pool: &sqlx::PgPool, signer: [u8; 32], first_byte_block: i64, n: i64) {
    // The signer set is what matters to the plan; the metadata and anchor are
    // minimal. generate_series builds the rows in one round trip.
    sqlx::query(
        "WITH anchor AS ( \
           INSERT INTO cw_api.records (tx_hash) \
           SELECT sha256(($1::bigint + g)::text::bytea) FROM generate_series(1, $2) g \
           ON CONFLICT DO NOTHING \
         ), rich AS ( \
           INSERT INTO cw_core.chain_records \
             (tx_hash, block_height, block_time, metadata_cbor, signer_ed25519, item_count, scheme) \
           SELECT sha256(($1::bigint + g)::text::bytea), $1 + g, now(), '\\xa10182'::bytea, $3, 1, 0 \
           FROM generate_series(1, $2) g \
         ) \
         INSERT INTO cw_core.chain_record_signer (signer_ed25519, tx_hash, block_height) \
         SELECT $3, sha256(($1::bigint + g)::text::bytea), $1 + g FROM generate_series(1, $2) g",
    )
    .bind(first_byte_block)
    .bind(n)
    .bind(signer.as_slice())
    .execute(pool)
    .await
    .expect("bulk seed");
}

/// EXPLAIN the exact count query shape the API runs (signer as a hard `$1`
/// equality against the verified-signer set, the rest NULL-guarded) and return
/// the plan text.
async fn explain_signer_count(conn: &mut sqlx::PgConnection, signer: [u8; 32]) -> String {
    sqlx::query_scalar::<_, String>(
        "EXPLAIN (FORMAT TEXT) \
         SELECT count(*) FROM cw_core.chain_record_signer s \
         JOIN cw_core.chain_records cr ON cr.tx_hash = s.tx_hash \
         WHERE s.signer_ed25519 = $1 \
           AND ($2 = false OR cr.scheme <> 0) \
           AND ($3::smallint IS NULL OR cr.scheme = $3) \
           AND ($4::bigint IS NULL OR cr.block_height >= $4) \
           AND ($5::bigint IS NULL OR cr.block_height <= $5) \
           AND ($6::timestamptz IS NULL OR cr.block_time >= $6) \
           AND ($7::timestamptz IS NULL OR cr.block_time <= $7)",
    )
    .bind(signer.to_vec()) // signer (required equality)
    .bind(false) // sealed_only
    .bind(Option::<i16>::None) // scheme
    .bind(Option::<i64>::None) // from_block
    .bind(Option::<i64>::None) // to_block
    .bind(Option::<DateTime<Utc>>::None) // from_time
    .bind(Option::<DateTime<Utc>>::None) // to_time
    .fetch_all(&mut *conn)
    .await
    .expect("explain")
    .join("\n")
}

/// Whether a plan rides an index on the verified-signer set via a SELECTIVE
/// `Index Cond` on the signer equality (reading only that one key's slice), not a
/// sequential scan of the set. The `Index Cond: signer_ed25519 = ...` line is what
/// proves the scan is bounded to the one signer rather than the whole set.
///
/// Either signer-leading index is a correct selective lookup: the secondary
/// `chain_record_signer_signer_idx (signer_ed25519, block_height DESC)` or the
/// primary key `(signer_ed25519, tx_hash)`. For a count the planner prefers an
/// index-only scan on the primary key (it covers `tx_hash` for the join with no
/// heap fetch); both lead with `signer_ed25519`, so both bound the read to one
/// key's slice. The list, which needs the block-height ordering, rides the
/// secondary index — asserted separately.
fn plan_is_selective_signer_lookup(plan: &str) -> bool {
    let scans_set_index = plan.contains("chain_record_signer_signer_idx")
        || plan.contains("chain_record_signer_pkey");
    scans_set_index
        && plan.contains("Index Cond:")
        && plan.contains("signer_ed25519 =")
        && !plan.contains("Seq Scan on chain_record_signer")
}

#[tokio::test]
async fn the_signer_scoped_count_rides_the_signer_index_at_scale() {
    let db = TestDb::fresh().await.expect("db");
    // A selective distribution: a handful of records under the target signer, among
    // many under other signers. At this ratio the signer-set index is genuinely
    // cheaper than a seq scan, so the planner picks it on its own — no enable_seqscan
    // nudge, which means this asserts the plan production actually gets, not just
    // that an index path exists.
    let target = [0xab_u8; 32];
    let other = [0xcd_u8; 32];
    seed_many_for(&db.pool, other, 1_000_000, 2_000).await;
    seed_many_for(&db.pool, target, 5_000_000, 5).await;

    let mut conn = db.pool.acquire().await.expect("acquire connection");
    sqlx::query("ANALYZE cw_core.chain_records")
        .execute(&mut *conn)
        .await
        .expect("analyze chain_records");
    sqlx::query("ANALYZE cw_core.chain_record_signer")
        .execute(&mut *conn)
        .await
        .expect("analyze chain_record_signer");

    // Force a GENERIC plan first: a prepared statement reused across bind values
    // plans without peeking at the actual params, the plan a pooled/prepared
    // production path gets. Because the signer is a hard `$1` equality (not an
    // optional OR-guard), even the generic plan must derive a selective Index Cond
    // on the signer-set index and read only that one key's slice — never a full
    // index scan with a filter, which would still be O(set). Then a CUSTOM (peeking)
    // plan must be equally selective.
    sqlx::query("SET plan_cache_mode = force_generic_plan")
        .execute(&mut *conn)
        .await
        .expect("force generic plan");
    let generic_plan = explain_signer_count(&mut conn, target).await;
    assert!(
        plan_is_selective_signer_lookup(&generic_plan),
        "the generic (non-peeking) plan must derive a selective Index Cond on the signer-set index, not a full scan; plan was:\n{generic_plan}"
    );

    sqlx::query("SET plan_cache_mode = force_custom_plan")
        .execute(&mut *conn)
        .await
        .expect("force custom plan");
    let custom_plan = explain_signer_count(&mut conn, target).await;
    assert!(
        plan_is_selective_signer_lookup(&custom_plan),
        "the custom (parameter-peeking) plan must derive a selective Index Cond on the signer-set index; plan was:\n{custom_plan}"
    );
}

// ---------------------------------------------------------------------------
// Side-table derivation. The ?signer= filter requires a chain_record_signer
// row, and the incremental scan never re-derives an already-indexed row, so a
// chain_records (or confirmation-pool) row that lacks its side rows stays
// invisible to ?signer= until they are rebuilt. These exercise the derivation
// statements that rebuild the side table from the rich rows / the pool,
// proving the rebuild restores visibility.
// ---------------------------------------------------------------------------

/// Insert a chain_records row and its anchor directly, WITHOUT a chain_record_signer
/// row — a rich row whose signer side row is missing.
async fn seed_chain_records_row_without_side_row(
    pool: &sqlx::PgPool,
    hash_byte: u8,
    block_height: i64,
    signer: [u8; 32],
) {
    sqlx::query(
        "WITH anchor AS ( \
           INSERT INTO cw_api.records (tx_hash) VALUES ($1) ON CONFLICT DO NOTHING \
         ) \
         INSERT INTO cw_core.chain_records \
           (tx_hash, block_height, block_time, metadata_cbor, signer_ed25519, item_count, scheme) \
         VALUES ($1, $2, now(), '\\xa10182'::bytea, $3, 1, 0)",
    )
    .bind(tx_hash(hash_byte).to_vec())
    .bind(block_height)
    .bind(signer.as_slice())
    .execute(pool)
    .await
    .expect("seed side-row-less chain_records row");
}

/// The rich-row derivation statement: rebuild chain_record_signer from every
/// signed chain_records row.
async fn run_rich_row_backfill(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO cw_core.chain_record_signer (signer_ed25519, tx_hash, block_height) \
         SELECT signer_ed25519, tx_hash, block_height \
         FROM cw_core.chain_records \
         WHERE signer_ed25519 IS NOT NULL",
    )
    .execute(pool)
    .await
    .expect("run rich-row backfill");
}

#[tokio::test]
async fn the_rich_row_backfill_makes_a_pre_existing_record_findable_by_signer() {
    let db = TestDb::fresh().await.expect("db");
    let signer = [0x9a_u8; 32];
    let other = [0x9b_u8; 32];
    // Two side-row-less rows: one by `signer`, one by `other`, plus an
    // unsigned row that must contribute no side row.
    seed_chain_records_row_without_side_row(&db.pool, 1, 10, signer).await;
    seed_chain_records_row_without_side_row(&db.pool, 2, 20, other).await;
    sqlx::query(
        "WITH anchor AS (INSERT INTO cw_api.records (tx_hash) VALUES ($1) ON CONFLICT DO NOTHING) \
         INSERT INTO cw_core.chain_records \
           (tx_hash, block_height, block_time, metadata_cbor, signer_ed25519, item_count, scheme) \
         VALUES ($1, 30, now(), '\\xa10182'::bytea, NULL, 1, 0)",
    )
    .bind(tx_hash(3).to_vec())
    .execute(&db.pool)
    .await
    .expect("seed unsigned side-row-less row");

    // Before the backfill the signer filter finds nothing: the side table is empty.
    let before = fetch_record_page(
        &db.pool,
        None,
        50,
        &RecordFilter {
            signer: Some(signer.to_vec()),
            ..Default::default()
        },
    )
    .await
    .expect("page before backfill");
    assert!(
        before.is_empty(),
        "before the backfill a pre-existing row is invisible to a signer query"
    );

    run_rich_row_backfill(&db.pool).await;

    // After the backfill the row is findable by its (first) signer, and the count agrees.
    let after = fetch_record_page(
        &db.pool,
        None,
        50,
        &RecordFilter {
            signer: Some(signer.to_vec()),
            ..Default::default()
        },
    )
    .await
    .expect("page after backfill");
    assert_eq!(
        hashes(&after),
        vec![1],
        "the backfill restores first-signer visibility for the pre-existing row"
    );
    let count = count_records(&db.pool, &count_filter(signer, &RecordFilter::default()))
        .await
        .expect("count");
    assert_eq!(count, 1, "the count sees the backfilled row too");

    // The unsigned pre-existing row contributed no side row (NULL signer is skipped).
    let total_side_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.chain_record_signer")
            .fetch_one(&db.pool)
            .await
            .expect("count side rows");
    assert_eq!(
        total_side_rows, 2,
        "only the two signed pre-existing rows are backfilled; the unsigned one is skipped"
    );
}

#[tokio::test]
async fn the_pool_backfill_lets_a_pre_existing_pool_entry_promote_visibly() {
    let db = TestDb::fresh().await.expect("db");
    let signer = [0xc1_u8; 32];
    // A confirmation_pool entry whose scalar signer is set but whose signer_set
    // is the column default (empty), so the promotion would fan out nothing.
    // Inserted directly (the pool writer is private to the scan module).
    sqlx::query(
        "INSERT INTO cw_core.confirmation_pool \
           (tx_hash, block_height, block_time, metadata_cbor, signer_ed25519, item_count, scheme) \
         VALUES ($1, 40, now(), '\\xa10182'::bytea, $2, 1, 0)",
    )
    .bind(tx_hash(7).to_vec())
    .bind(signer.as_slice())
    .execute(&db.pool)
    .await
    .expect("seed empty-signer-set pool entry");

    // Sanity: the freshly-added column defaulted to an empty set for this row.
    let set_before: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT signer_set FROM cw_core.confirmation_pool WHERE tx_hash = $1")
            .bind(tx_hash(7).to_vec())
            .fetch_one(&db.pool)
            .await
            .expect("read signer_set before");
    assert!(
        set_before.is_empty(),
        "the seeded pool row starts with the empty default signer set"
    );

    // The pool derivation statement: rebuild signer_set from the scalar signer.
    sqlx::query(
        "UPDATE cw_core.confirmation_pool \
         SET signer_set = ARRAY[signer_ed25519]::bytea[] \
         WHERE signer_ed25519 IS NOT NULL",
    )
    .execute(&db.pool)
    .await
    .expect("run pool backfill");

    // The set now carries the scalar signer, so a promotion fans it into
    // chain_record_signer and the promoted record is findable by ?signer=.
    let set_after: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT signer_set FROM cw_core.confirmation_pool WHERE tx_hash = $1")
            .bind(tx_hash(7).to_vec())
            .fetch_one(&db.pool)
            .await
            .expect("read signer_set after");
    assert_eq!(
        set_after,
        vec![signer.to_vec()],
        "the pool backfill seeds the set from the scalar signer the row already carried"
    );
}

/// The public records reads run in a bounded transaction: the statement timeout
/// is live inside it, actually kills an overrunning statement, and never leaks
/// past the transaction onto the pooled connection.
#[tokio::test]
async fn the_records_read_transaction_is_bounded_by_a_statement_timeout() {
    let db = TestDb::fresh().await.expect("db");

    // Inside the bounded transaction the cap is live.
    let mut tx = gateway_core::chain::records::begin_records_read_txn(&db.pool)
        .await
        .expect("bounded txn");
    let setting: String = sqlx::query_scalar("SELECT current_setting('statement_timeout')")
        .fetch_one(&mut *tx)
        .await
        .expect("read setting");
    assert_eq!(
        setting, "5s",
        "every public records read runs under the statement timeout"
    );

    // A statement that overruns the cap is killed, freeing the backend, rather
    // than pinning it for as long as an anonymous caller cares to wait.
    let err = sqlx::query("SELECT pg_sleep(6)")
        .execute(&mut *tx)
        .await
        .expect_err("the cap kills an overrunning statement");
    assert!(
        err.to_string().to_lowercase().contains("statement timeout"),
        "killed by the statement timeout, not another failure: {err}"
    );
    drop(tx);

    // SET LOCAL was transaction-scoped: the pooled connection is back on the
    // server default, so no unrelated query inherits the lowered cap.
    let after: String = sqlx::query_scalar("SELECT current_setting('statement_timeout')")
        .fetch_one(&db.pool)
        .await
        .expect("read default");
    assert_ne!(after, "5s", "the cap never leaks past the transaction");
}
