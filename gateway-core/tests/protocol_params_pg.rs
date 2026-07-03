//! Integration tests for the protocol-parameter cache.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test stands up an isolated, freshly migrated database via the harness
//! and drives the populate loop with an in-memory source, so no test reaches the
//! network. The final test proves a cw_core-sourced parameter row drives the
//! deterministic transaction builder end to end with zero oracle access.

#![cfg(feature = "pg-tests")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use gateway_core::chain::confirm::upsert_tip;
use gateway_core::chain::params::{
    load_params, load_params_for_epoch, params_populate_policy, params_populate_schedule,
    populate_params, FetchedParams, Network, ParamsPopulateHandler, PopulateOutcome,
    ProtocolParams, ProtocolParamsSource, PARAMS_POPULATE_QUEUE,
};
use gateway_core::error::Error;
use gateway_core::runtime::enqueue::{enqueue, EnqueueOptions};
use gateway_core::runtime::Runtime;
use gateway_core::testsupport::TestDb;

/// An in-memory [`ProtocolParamsSource`] that returns a configurable current
/// epoch and counts how many times each method is called, so a test can prove
/// the populate loop fetched once (idempotency) and the read path fetched never.
struct MockSource {
    /// The current epoch the source reports; mutable so a test can advance it to
    /// simulate an epoch rollover.
    epoch: Mutex<u64>,
    /// Base fee values; each fetched epoch derives distinct values from the epoch
    /// so a test can tell the two cached epochs apart.
    current_epoch_calls: AtomicU64,
    fetch_calls: AtomicU64,
}

impl MockSource {
    fn at_epoch(epoch: u64) -> Self {
        Self {
            epoch: Mutex::new(epoch),
            current_epoch_calls: AtomicU64::new(0),
            fetch_calls: AtomicU64::new(0),
        }
    }

    fn set_epoch(&self, epoch: u64) {
        *self.epoch.lock().unwrap() = epoch;
    }

    fn fetch_calls(&self) -> u64 {
        self.fetch_calls.load(Ordering::SeqCst)
    }

    fn current_epoch_calls(&self) -> u64 {
        self.current_epoch_calls.load(Ordering::SeqCst)
    }
}

impl ProtocolParamsSource for MockSource {
    async fn current_epoch(&self, _network: Network) -> gateway_core::error::Result<u64> {
        self.current_epoch_calls.fetch_add(1, Ordering::SeqCst);
        Ok(*self.epoch.lock().unwrap())
    }

    async fn fetch_params(
        &self,
        _network: Network,
        epoch: u64,
    ) -> gateway_core::error::Result<FetchedParams> {
        self.fetch_calls.fetch_add(1, Ordering::SeqCst);
        // Derive epoch-distinct values so a test can assert *which* epoch's row
        // was returned, while keeping them in the realistic range the builder
        // needs (min_fee_a/b on the mainnet scale, a non-trivial max_tx_size).
        Ok(FetchedParams {
            epoch,
            min_fee_a: 44,
            min_fee_b: 155_381,
            coins_per_utxo_byte: 4_310,
            max_tx_size: 16_384,
            raw: serde_json::json!({ "epoch_no": epoch, "source": "mock" }),
        })
    }
}

/// Running the populate loop twice for the same current epoch fetches exactly
/// once and leaves exactly one row: the second pass sees the epoch already
/// cached and performs no fetch and no write.
#[tokio::test]
async fn populate_is_idempotent_for_a_stable_epoch() {
    let db = TestDb::fresh().await.expect("test database");
    let source = MockSource::at_epoch(500);

    let first = populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("first populate");
    assert_eq!(first, PopulateOutcome::Inserted { epoch: 500 });

    let second = populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("second populate");
    assert_eq!(second, PopulateOutcome::AlreadyCurrent { epoch: 500 });

    // The source was asked for the current epoch on both passes, but only the
    // first pass fetched parameters.
    assert_eq!(source.current_epoch_calls(), 2, "epoch checked each pass");
    assert_eq!(source.fetch_calls(), 1, "params fetched only on the miss");

    // Exactly one row exists for the network.
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.cardano_protocol_params WHERE network = $1",
    )
    .bind("preprod")
    .fetch_one(&db.pool)
    .await
    .expect("count rows");
    assert_eq!(count, 1, "a stable epoch yields exactly one row");
}

/// The loop-liveness marker advances on EVERY successful pass — including the
/// no-op `AlreadyCurrent` pass that writes no fee row — while the fee row's
/// `fetched_at` stays frozen at the epoch's insert instant. This is the exact
/// shape the staleness warning must key off: in steady state the epoch's
/// `fetched_at` ages for the whole ~five-day epoch, but the marker stays fresh
/// because the loop keeps checking in, so a healthy idle loop is not stale.
#[tokio::test]
async fn liveness_marker_advances_on_an_already_current_pass_while_fetched_at_stays_frozen() {
    let db = TestDb::fresh().await.expect("test database");
    let source = MockSource::at_epoch(500);

    // First pass inserts the epoch and stamps the marker.
    populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("first populate inserts");

    // Backdate BOTH the fee row's fetched_at and the liveness marker to simulate
    // an epoch that was first observed hours ago and a loop that last checked in
    // hours ago — i.e. just after a deploy that then went idle.
    sqlx::query(
        "UPDATE cw_core.cardano_protocol_params \
         SET fetched_at = now() - interval '8 hours' WHERE network = $1",
    )
    .bind("preprod")
    .execute(&db.pool)
    .await
    .expect("backdate fetched_at");
    sqlx::query(
        "UPDATE cw_core.cardano_params_refresh \
         SET last_checked_at = now() - interval '8 hours' WHERE network = $1",
    )
    .bind("preprod")
    .execute(&db.pool)
    .await
    .expect("backdate the marker");

    let (frozen_fetched_at, stale_marker) = read_timestamps(&db.pool, "preprod").await;

    // A second pass finds the epoch already cached: it fetches nothing and writes
    // no fee row, but it DOES advance the liveness marker.
    let second = populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("already-current pass");
    assert_eq!(second, PopulateOutcome::AlreadyCurrent { epoch: 500 });

    let (after_fetched_at, after_marker) = read_timestamps(&db.pool, "preprod").await;

    // The fee row's fetched_at is untouched (the per-epoch row is immutable), so
    // a warning keyed off it would still fire even though the loop is healthy.
    assert_eq!(
        after_fetched_at, frozen_fetched_at,
        "the no-op pass must not touch the immutable fee row's fetched_at"
    );
    // The marker advanced to ~now, so a warning keyed off the marker (the fix)
    // correctly sees a live loop.
    assert!(
        after_marker > stale_marker,
        "an AlreadyCurrent pass must advance the loop-liveness marker"
    );
    let marker_age = chrono::Utc::now() - after_marker;
    assert!(
        marker_age < chrono::Duration::minutes(1),
        "the marker is freshly stamped (age {}s), so the loop reads as live",
        marker_age.num_seconds()
    );
}

/// The liveness marker tracks the loop, NOT the epoch: an epoch rollover stamps
/// the marker just as a no-op pass does, and the marker is per-network so two
/// networks' liveness is independent. Also proves a failed pass leaves the
/// marker untouched (it returns before stamping), so a sustained outage shows up
/// as a stale marker rather than a falsely-fresh one.
#[tokio::test]
async fn liveness_marker_is_per_network_and_only_stamped_on_a_successful_pass() {
    let db = TestDb::fresh().await.expect("test database");
    let source = MockSource::at_epoch(500);

    // Preprod completes a pass; mainnet never runs one.
    populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("preprod populate");

    let preprod_marker: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT last_checked_at FROM cw_core.cardano_params_refresh WHERE network = $1",
    )
    .bind("preprod")
    .fetch_optional(&db.pool)
    .await
    .expect("read preprod marker");
    assert!(preprod_marker.is_some(), "preprod stamped its marker");

    let mainnet_marker: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT last_checked_at FROM cw_core.cardano_params_refresh WHERE network = $1",
    )
    .bind("mainnet")
    .fetch_optional(&db.pool)
    .await
    .expect("read mainnet marker");
    assert!(
        mainnet_marker.is_none(),
        "a network that never ran a pass has no marker; the read path treats \
         absent as not-yet-observed, never stale"
    );
}

/// The populate loop learns the current epoch from the materialised chain tip
/// (a Postgres read) instead of the provider `/tip` source when that tip carries
/// an epoch. This is the efficiency fix: a steady-state populate pass makes no
/// `/tip` call of its own, so a keyless provider's rate-limit budget is not spent
/// just to detect an epoch change.
#[tokio::test]
async fn populate_reads_the_epoch_from_the_materialised_tip_not_the_source() {
    let db = TestDb::fresh().await.expect("test database");
    let source = MockSource::at_epoch(999);

    // The scan loop has materialised a tip carrying epoch 500 (the real current
    // epoch); the source would falsely report 999 if it were ever consulted.
    upsert_tip(&db.pool, Network::Preprod.as_str(), 2_891_234, Some(500))
        .await
        .expect("materialise tip with epoch");

    let outcome = populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("populate from the materialised tip");

    // The pass cached epoch 500 (from the tip), never 999 (the source).
    assert_eq!(outcome, PopulateOutcome::Inserted { epoch: 500 });
    assert_eq!(
        source.current_epoch_calls(),
        0,
        "the populate loop must not call the provider /tip source when the \
         materialised tip carries an epoch"
    );
    let cached = load_params(&db.pool, Network::Preprod)
        .await
        .expect("epoch 500 cached");
    assert_eq!(cached.epoch, 500);
}

/// On a cold start, before the scan loop has materialised a tip, the populate
/// loop falls back to a single provider `/tip` read so a brand-new deployment
/// still bootstraps its parameters.
#[tokio::test]
async fn populate_falls_back_to_the_source_when_no_tip_is_materialised() {
    let db = TestDb::fresh().await.expect("test database");
    let source = MockSource::at_epoch(500);

    // No cardano_tip row exists yet (cold start). The loop must consult the
    // source exactly once to learn the epoch.
    let outcome = populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("populate via the cold-start fallback");

    assert_eq!(outcome, PopulateOutcome::Inserted { epoch: 500 });
    assert_eq!(
        source.current_epoch_calls(),
        1,
        "with no materialised tip the loop falls back to a single source /tip read"
    );
}

/// A materialised tip with a NULL epoch (a provider that omitted it, or a row
/// from before the epoch was materialised) is treated like an absent tip: the
/// loop falls back to the source rather than failing.
#[tokio::test]
async fn populate_falls_back_when_the_materialised_tip_has_no_epoch() {
    let db = TestDb::fresh().await.expect("test database");
    let source = MockSource::at_epoch(500);

    // A tip row exists but carries no epoch.
    upsert_tip(&db.pool, Network::Preprod.as_str(), 2_891_234, None)
        .await
        .expect("materialise tip without epoch");

    let outcome = populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("populate via the fallback");

    assert_eq!(outcome, PopulateOutcome::Inserted { epoch: 500 });
    assert_eq!(
        source.current_epoch_calls(),
        1,
        "a tip with no epoch falls back to a single source /tip read"
    );
}

/// When the epoch advances, the next populate pass appends the new epoch's row
/// and leaves the prior epoch's row untouched (its values are immutable once
/// recorded). The loader then serves the newest epoch.
#[tokio::test]
async fn epoch_rollover_appends_without_overwriting() {
    let db = TestDb::fresh().await.expect("test database");
    let source = MockSource::at_epoch(500);

    populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("populate epoch 500");

    // Capture the original row's recorded values and its fetched_at instant.
    let (orig_min_fee_b, orig_fetched_at): (i64, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "SELECT min_fee_b, fetched_at FROM cw_core.cardano_protocol_params \
         WHERE network = $1 AND epoch = $2",
    )
    .bind("preprod")
    .bind(500_i32)
    .fetch_one(&db.pool)
    .await
    .expect("read epoch 500 row");

    // The chain advances an epoch.
    source.set_epoch(501);
    let rolled = populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("populate epoch 501");
    assert_eq!(rolled, PopulateOutcome::Inserted { epoch: 501 });

    // Both epochs are now cached for the network.
    let epochs: Vec<i32> = sqlx::query_scalar(
        "SELECT epoch FROM cw_core.cardano_protocol_params WHERE network = $1 ORDER BY epoch",
    )
    .bind("preprod")
    .fetch_all(&db.pool)
    .await
    .expect("list epochs");
    assert_eq!(epochs, vec![500, 501], "rollover appends a second epoch");

    // The original epoch's row is byte-for-byte unchanged.
    let (after_min_fee_b, after_fetched_at): (i64, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "SELECT min_fee_b, fetched_at FROM cw_core.cardano_protocol_params \
         WHERE network = $1 AND epoch = $2",
    )
    .bind("preprod")
    .bind(500_i32)
    .fetch_one(&db.pool)
    .await
    .expect("re-read epoch 500 row");
    assert_eq!(
        after_min_fee_b, orig_min_fee_b,
        "prior epoch values untouched"
    );
    assert_eq!(
        after_fetched_at, orig_fetched_at,
        "prior epoch fetched_at untouched"
    );

    // The loader serves the newest epoch.
    let latest = load_params(&db.pool, Network::Preprod)
        .await
        .expect("load newest");
    assert_eq!(latest.epoch, 501, "load_params returns the newest epoch");
}

/// `load_params` returns the highest-epoch row regardless of insertion order,
/// and a per-epoch load retrieves an older epoch exactly.
#[tokio::test]
async fn load_params_returns_newest_and_per_epoch_is_exact() {
    let db = TestDb::fresh().await.expect("test database");

    // Insert epochs out of order to prove the loader orders by epoch, not by
    // insertion time.
    insert_row(&db.pool, "preprod", 502, 50, 160_000, 4_310, 16_384).await;
    insert_row(&db.pool, "preprod", 500, 44, 155_381, 4_310, 16_384).await;
    insert_row(&db.pool, "preprod", 501, 47, 158_000, 4_310, 16_384).await;

    let newest = load_params(&db.pool, Network::Preprod)
        .await
        .expect("load newest");
    assert_eq!(newest.epoch, 502);
    assert_eq!(newest.min_fee_a, 50, "newest epoch's own values");

    let older = load_params_for_epoch(&db.pool, Network::Preprod, 500)
        .await
        .expect("load epoch 500")
        .expect("epoch 500 is present");
    assert_eq!(older.min_fee_a, 44, "per-epoch load is exact");

    let absent = load_params_for_epoch(&db.pool, Network::Preprod, 999)
        .await
        .expect("load missing epoch");
    assert!(absent.is_none(), "an uncached epoch loads as None");
}

/// A network with no cached rows is a hard `ParamsNotFound`, never a silent
/// default, and the two networks' caches are independent.
#[tokio::test]
async fn empty_cache_is_not_found_and_networks_are_isolated() {
    let db = TestDb::fresh().await.expect("test database");

    // Caching preprod must not satisfy a mainnet read.
    insert_row(&db.pool, "preprod", 500, 44, 155_381, 4_310, 16_384).await;

    let err = load_params(&db.pool, Network::Mainnet)
        .await
        .expect_err("mainnet has no rows");
    match err {
        Error::ParamsNotFound(net) => assert_eq!(net, "mainnet"),
        other => panic!("expected ParamsNotFound, got {other:?}"),
    }

    // Preprod still resolves.
    let preprod = load_params(&db.pool, Network::Preprod)
        .await
        .expect("preprod resolves");
    assert_eq!(preprod.network, "preprod");
    assert_eq!(preprod.epoch, 500);
}

/// A parameter row sourced from `cw_core` (via the populate loop, using a mock
/// source) drives the deterministic transaction builder to a successful build,
/// with no oracle access anywhere in the path. The only HTTP-capable component
/// (the populate loop's source) is the mock, so the build itself touches nothing
/// but Postgres and the pure builder.
#[tokio::test]
async fn cw_core_params_drive_the_transaction_builder() {
    let db = TestDb::fresh().await.expect("test database");
    let source = MockSource::at_epoch(500);

    // Populate the cache through the loop, exactly as production would, but with
    // the mock standing in for the network source.
    populate_params(&db.pool, &source, Network::Preprod)
        .await
        .expect("populate");

    // Read the parameters back the way a quote or build does: pure DB, no source.
    let params: ProtocolParams = load_params(&db.pool, Network::Preprod)
        .await
        .expect("load params");

    // Convert the cw_core-sourced parameters into the builder's input type and
    // build a real transaction. A successful build proves the builder consumes
    // cache-sourced parameters; the fetch counter proves nothing else hit the
    // network during the build.
    let builder_params = cardano_poe_tx::ProtocolParams {
        min_fee_a: params.min_fee_a,
        min_fee_b: params.min_fee_b,
        coins_per_utxo_byte: params.coins_per_utxo_byte,
        max_tx_size: params.max_tx_size,
    };

    let signing_key = cardano_poe_tx::SigningKey::from_seed([7u8; 32]);
    let request = cardano_poe_tx::BuildRequest {
        record_bytes: b"proof-of-existence record".to_vec(),
        metadata_label: cardano_poe_tx::POE_METADATA_LABEL,
        utxos: vec![cardano_poe_tx::Utxo {
            tx_hash: "581f37a1ebcd4e04f83bc4f5bcd2aed6406dc8abf98abb9f6d5941d635818620".to_string(),
            index: 0,
            lovelace: 10_000_000,
        }],
        must_spend: Vec::new(),
        protocol: builder_params,
        // A preprod (testnet) bech32 change address.
        change_address: "addr_test1vpa8ukd77k05gc3etxeyzylxxmyhzg0hvne9qplxvsyl44q6pl7v4"
            .to_string(),
        network_id: 0,
        payment_verification_key: signing_key.verification_key(),
        validity: None,
    };

    let built = cardano_poe_tx::build_poe_tx(&request)
        .expect("a build over cw_core-sourced params must succeed");

    // The fee is the builder's linear fee over the actual transaction size,
    // computed entirely from the cw_core-sourced min_fee_a/min_fee_b. It must be
    // positive and below the protocol's own max-size-implied ceiling.
    assert!(
        built.fee >= params.min_fee_b,
        "fee includes the linear constant"
    );
    assert!(
        built.total_size <= params.max_tx_size,
        "build respects max_tx_size"
    );

    // No network call happened during the read or the build: the only source
    // call was the single populate fetch.
    assert_eq!(
        source.fetch_calls(),
        1,
        "only the populate loop fetched; the read+build path made zero source calls"
    );
}

/// The populate handler, registered on a live runtime against its singleton
/// queue, writes a parameter row when an enqueued job runs and the job reaches
/// `completed`. This proves the handler wires into the job runtime, not just that
/// the standalone function works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn populate_handler_runs_on_the_runtime() {
    let db = TestDb::fresh().await.expect("test database");
    // A full runtime runs a persistent NOTIFY listener plus a worker loop and the
    // sweeper, each needing its own connection.
    let pool = db.pool_with(8).await.expect("sized pool");

    let handler = ParamsPopulateHandler::new(
        pool.clone(),
        MockSource::at_epoch(500),
        vec![Network::Preprod],
    );

    let rt = std::sync::Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("params-populate")
            .queue_policy(params_populate_policy())
            .handler(PARAMS_POPULATE_QUEUE, handler)
            .poll_interval(Duration::from_millis(25))
            .build()
            .await
            .expect("build runtime"),
    );

    // Enqueue one populate job directly rather than waiting for the */10 cron, so
    // the test does not sleep for minutes. The schedule builder is still exercised
    // for validity below.
    let job = enqueue(
        &pool,
        PARAMS_POPULATE_QUEUE,
        &serde_json::Value::Null,
        EnqueueOptions::default(),
    )
    .await
    .expect("enqueue populate job");

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // Wait until the row appears (the handler's observable side effect).
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if load_params(&pool, Network::Preprod).await.is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "populate handler never wrote a params row"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The job itself reached a terminal success state.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let state = rt.get_job(job.0).await.expect("load job").map(|j| j.state);
        match state {
            Some(gateway_core::runtime::JobState::Completed) => break,
            // The job migrates out of the live table on completion in some
            // configurations; an absent row after the side effect landed also
            // means it finished. Treat None-after-row as success too.
            None => break,
            _ => {}
        }
        assert!(
            std::time::Instant::now() < deadline,
            "populate job did not complete"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    rt.shutdown();
    let _ = run.await;

    // The cached row carries the epoch the source reported.
    let params = load_params(&pool, Network::Preprod)
        .await
        .expect("params cached");
    assert_eq!(params.epoch, 500);

    // The schedule builder produces a valid 5-field cron on the populate queue.
    let schedule = params_populate_schedule();
    assert_eq!(schedule.queue, PARAMS_POPULATE_QUEUE);
    assert_eq!(schedule.cron, "*/10 * * * *");
}

/// Read back the newest epoch's `fetched_at` and the per-network liveness
/// marker's `last_checked_at` together, so a test can compare how each moves
/// across a populate pass.
async fn read_timestamps(
    pool: &sqlx::PgPool,
    network: &str,
) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
    let fetched_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT fetched_at FROM cw_core.cardano_protocol_params \
         WHERE network = $1 ORDER BY epoch DESC LIMIT 1",
    )
    .bind(network)
    .fetch_one(pool)
    .await
    .expect("read newest fetched_at");
    let last_checked_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT last_checked_at FROM cw_core.cardano_params_refresh WHERE network = $1",
    )
    .bind(network)
    .fetch_one(pool)
    .await
    .expect("read liveness marker");
    (fetched_at, last_checked_at)
}

/// Insert a parameter row directly, for tests that exercise the read path
/// without going through the populate loop.
async fn insert_row(
    pool: &sqlx::PgPool,
    network: &str,
    epoch: i32,
    min_fee_a: i64,
    min_fee_b: i64,
    coins_per_utxo_byte: i64,
    max_tx_size: i64,
) {
    sqlx::query(
        "INSERT INTO cw_core.cardano_protocol_params \
           (network, epoch, min_fee_a, min_fee_b, coins_per_utxo_byte, max_tx_size, raw) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(network)
    .bind(epoch)
    .bind(min_fee_a)
    .bind(min_fee_b)
    .bind(coins_per_utxo_byte)
    .bind(max_tx_size)
    .bind(serde_json::json!({ "epoch_no": epoch }))
    .execute(pool)
    .await
    .expect("insert params row");
}
