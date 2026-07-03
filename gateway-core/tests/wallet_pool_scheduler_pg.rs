//! Integration coverage for the wallet scheduler, daily decay, and retire sweep.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test stands up an isolated, freshly migrated database via the harness and
//! seeds operators, wallets, and per-UTxO rows directly in SQL, then drives the
//! `pool` API. These assert real behaviour the submit path relies on: the
//! least-loaded ordering (fewest in-flight wins), cross-operator isolation, that
//! `FOR UPDATE SKIP LOCKED` hands two concurrent pickers different wallets, that
//! a draining wallet is excluded from picks but its in-flight work still counts,
//! and that decay/retire move the right rows.

#![cfg(feature = "pg-tests")]

use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::Network;
use gateway_core::wallet::pool::{
    self, decay_submission_counters, pick_wallet, record_submission, sweep_drained_wallets,
};
use uuid::Uuid;

/// Counters and lifecycle to plant on a seeded wallet.
#[derive(Clone, Copy)]
struct WalletSeed {
    /// `operator_wallet.status`.
    status: &'static str,
    /// `operator_wallet.submission_count_24h`.
    submission_count_24h: i64,
    /// How many canonical, available UTxO rows to plant (drives ready count).
    canonical_available: usize,
    /// How many in_flight UTxO rows to plant (drives in-flight count).
    in_flight: usize,
}

impl Default for WalletSeed {
    fn default() -> Self {
        Self {
            status: "active",
            submission_count_24h: 0,
            canonical_available: 1,
            in_flight: 0,
        }
    }
}

/// Insert an operator, returning its id.
async fn seed_operator(pool: &sqlx::PgPool, status: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label, status) VALUES ($1, $2, $3)")
        .bind(id)
        .bind("op")
        .bind(status)
        .execute(pool)
        .await
        .expect("insert operator");
    id
}

/// Insert a wallet under an operator with the given seed, plus its UTxO rows.
/// Returns the wallet id. `last_used_at` is left NULL unless explicitly stamped.
async fn seed_wallet(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    label: &str,
    seed: WalletSeed,
) -> Uuid {
    let wallet_id = Uuid::now_v7();
    let address = format!("addr_test_{}", wallet_id.simple());
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet \
           (id, registrar_operator_id, label, address, network, status, submission_count_24h) \
         VALUES ($1, $2, $3, $4, 'preprod', $5, $6)",
    )
    .bind(wallet_id)
    .bind(operator_id)
    .bind(label)
    .bind(address)
    .bind(seed.status)
    .bind(seed.submission_count_24h)
    .execute(pool)
    .await
    .expect("insert wallet");

    for i in 0..seed.canonical_available {
        insert_utxo(pool, wallet_id, "available", true, i as i32).await;
    }
    for i in 0..seed.in_flight {
        // in_flight rows must carry a lease token + expiry (schema CHECK), and
        // get a distinct index so the per-UTxO primary key never collides with
        // the available rows.
        let index = (1000 + i) as i32;
        sqlx::query(
            "INSERT INTO cw_core.wallet_utxo \
               (wallet_id, tx_hash, output_index, lovelace, state, canonical, \
                lease_token, lease_expires_at, source) \
             VALUES ($1, $2, $3, 6000000, 'in_flight', true, $4, now() + interval '5 minutes', 'snapshot')",
        )
        .bind(wallet_id)
        .bind(unique_tx_hash())
        .bind(index)
        .bind(Uuid::now_v7())
        .execute(pool)
        .await
        .expect("insert in_flight utxo");
    }

    wallet_id
}

/// Insert one available/canonical wallet_utxo row at a distinct index.
async fn insert_utxo(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    state: &str,
    canonical: bool,
    index: i32,
) {
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, $3, 6000000, $4, $5, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(unique_tx_hash())
    .bind(index)
    .bind(state)
    .bind(canonical)
    .execute(pool)
    .await
    .expect("insert utxo");
}

/// A fresh 32-byte tx hash so each UTxO row has a distinct primary key.
fn unique_tx_hash() -> Vec<u8> {
    Uuid::now_v7().as_bytes().repeat(2)
}

#[tokio::test]
async fn pick_wallet_prefers_the_fewest_in_flight() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;

    // Two ready wallets; "busy" has more in-flight, "idle" has none. in_flight
    // ASC dominates the ordering, so "idle" must be chosen even though both are
    // ready.
    let _busy = seed_wallet(
        &db.pool,
        operator,
        "busy",
        WalletSeed {
            canonical_available: 3,
            in_flight: 2,
            ..WalletSeed::default()
        },
    )
    .await;
    let idle = seed_wallet(
        &db.pool,
        operator,
        "idle",
        WalletSeed {
            canonical_available: 1,
            in_flight: 0,
            ..WalletSeed::default()
        },
    )
    .await;

    let picked = pick_wallet(&db.pool, operator, Network::Preprod)
        .await
        .expect("pick should not error")
        .expect("a ready wallet must be picked");
    assert_eq!(
        picked.wallet_id, idle,
        "the wallet with the fewest in-flight UTxOs must win"
    );
    assert_eq!(picked.in_flight_count, 0);
    assert_eq!(picked.canonical_ready_count, 1);
}

#[tokio::test]
async fn pick_wallet_breaks_in_flight_ties_by_submission_count() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;

    // Both wallets are idle (zero in-flight) and equally ready, so the next
    // tie-break is the trailing-24h submission count: the less-used wallet wins.
    let _heavy = seed_wallet(
        &db.pool,
        operator,
        "heavy",
        WalletSeed {
            submission_count_24h: 50,
            ..WalletSeed::default()
        },
    )
    .await;
    let light = seed_wallet(
        &db.pool,
        operator,
        "light",
        WalletSeed {
            submission_count_24h: 3,
            ..WalletSeed::default()
        },
    )
    .await;

    let picked = pick_wallet(&db.pool, operator, Network::Preprod)
        .await
        .expect("pick")
        .expect("a wallet must be picked");
    assert_eq!(
        picked.wallet_id, light,
        "the least-used wallet must win the submission-count tie-break"
    );
}

#[tokio::test]
async fn pick_wallet_excludes_wallets_with_no_canonical_ready_utxo() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;

    // A wallet with only in-flight UTxOs (zero canonical-available) is not
    // eligible, even though it is active. With no ready wallet anywhere, the
    // pick returns None.
    let _drained = seed_wallet(
        &db.pool,
        operator,
        "drained",
        WalletSeed {
            canonical_available: 0,
            in_flight: 2,
            ..WalletSeed::default()
        },
    )
    .await;

    let picked = pick_wallet(&db.pool, operator, Network::Preprod)
        .await
        .expect("pick");
    assert!(
        picked.is_none(),
        "no wallet with a canonical-ready UTxO means no pick"
    );
}

#[tokio::test]
async fn pick_wallet_excludes_a_non_canonical_available_utxo() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;

    // A wallet whose only available UTxO is non-canonical is not ready: the
    // ready count filters on `canonical`.
    let wallet_id = Uuid::now_v7();
    let address = format!("addr_test_{}", wallet_id.simple());
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet (id, registrar_operator_id, label, address, network) \
         VALUES ($1, $2, 'noncanon', $3, 'preprod')",
    )
    .bind(wallet_id)
    .bind(operator)
    .bind(address)
    .execute(&db.pool)
    .await
    .expect("insert wallet");
    insert_utxo(&db.pool, wallet_id, "available", false, 0).await;

    let picked = pick_wallet(&db.pool, operator, Network::Preprod)
        .await
        .expect("pick");
    assert!(
        picked.is_none(),
        "a non-canonical available UTxO does not make a wallet ready"
    );
}

#[tokio::test]
async fn pick_wallet_excludes_a_draining_wallet() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;

    // A draining wallet, even with canonical-ready UTxOs, takes no new picks.
    let _draining = seed_wallet(
        &db.pool,
        operator,
        "draining",
        WalletSeed {
            status: "draining",
            canonical_available: 5,
            ..WalletSeed::default()
        },
    )
    .await;

    let picked = pick_wallet(&db.pool, operator, Network::Preprod)
        .await
        .expect("pick");
    assert!(picked.is_none(), "a draining wallet must not be picked");

    // But an active sibling under the same operator is still picked.
    let active = seed_wallet(&db.pool, operator, "active", WalletSeed::default()).await;
    let picked = pick_wallet(&db.pool, operator, Network::Preprod)
        .await
        .expect("pick")
        .expect("the active sibling is pickable");
    assert_eq!(picked.wallet_id, active);
}

#[tokio::test]
async fn pick_wallet_excludes_a_disabled_operators_wallets() {
    let db = TestDb::fresh().await.expect("test database");
    let disabled = seed_operator(&db.pool, "disabled").await;
    let _wallet = seed_wallet(&db.pool, disabled, "w", WalletSeed::default()).await;

    let picked = pick_wallet(&db.pool, disabled, Network::Preprod)
        .await
        .expect("pick");
    assert!(
        picked.is_none(),
        "a disabled operator's wallets are off the books"
    );
}

#[tokio::test]
async fn pick_wallet_is_isolated_across_operators_even_with_identical_labels() {
    let db = TestDb::fresh().await.expect("test database");
    let operator_a = seed_operator(&db.pool, "active").await;
    let operator_b = seed_operator(&db.pool, "active").await;

    // Both operators have a wallet labelled "primary"; operator A's pick must
    // never return operator B's wallet, and vice versa. Adversarial: the labels
    // are identical so only the operator scoping can keep them apart.
    let a_primary = seed_wallet(&db.pool, operator_a, "primary", WalletSeed::default()).await;
    let b_primary = seed_wallet(&db.pool, operator_b, "primary", WalletSeed::default()).await;

    let picked_a = pick_wallet(&db.pool, operator_a, Network::Preprod)
        .await
        .expect("pick a")
        .expect("operator A has a ready wallet");
    assert_eq!(picked_a.wallet_id, a_primary);
    assert_eq!(picked_a.registrar_operator_id, operator_a);
    assert_ne!(
        picked_a.wallet_id, b_primary,
        "operator A must never be handed operator B's wallet"
    );

    let picked_b = pick_wallet(&db.pool, operator_b, Network::Preprod)
        .await
        .expect("pick b")
        .expect("operator B has a ready wallet");
    assert_eq!(picked_b.wallet_id, b_primary);
    assert_eq!(picked_b.registrar_operator_id, operator_b);
}

#[tokio::test]
async fn pick_wallet_filters_by_network() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;
    let _preprod = seed_wallet(&db.pool, operator, "preprod-wallet", WalletSeed::default()).await;

    // No wallet is pinned to preview, so a preview pick finds nothing even
    // though the operator has a ready preprod wallet.
    let picked = pick_wallet(&db.pool, operator, Network::Preview)
        .await
        .expect("pick");
    assert!(
        picked.is_none(),
        "a preview pick must not return a preprod wallet"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn for_update_skip_locked_hands_concurrent_pickers_different_wallets() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;

    // Two equally-ranked ready wallets. Two pickers, each holding its own
    // transaction across the SELECT ... FOR UPDATE SKIP LOCKED, must end up with
    // distinct wallets: the first locks the best row, the second skips it.
    let w1 = seed_wallet(&db.pool, operator, "w1", WalletSeed::default()).await;
    let w2 = seed_wallet(&db.pool, operator, "w2", WalletSeed::default()).await;

    // Picker one starts a transaction and picks, then holds the lock by NOT
    // committing while picker two picks on a separate connection.
    let mut tx1 = db.pool.begin().await.expect("begin tx1");
    let picked1 = sqlx::query_scalar::<_, Uuid>(
        "SELECT w.id FROM cw_core.operator_wallet w \
         JOIN cw_core.operator o ON o.id = w.registrar_operator_id \
         JOIN LATERAL ( \
             SELECT count(*) FILTER (WHERE u.state = 'available' AND u.canonical) AS ready \
             FROM cw_core.wallet_utxo u WHERE u.wallet_id = w.id \
         ) c ON true \
         WHERE w.registrar_operator_id = $1 AND w.network = 'preprod' AND w.status = 'active' \
           AND o.status = 'active' AND c.ready > 0 \
         ORDER BY w.id \
         FOR UPDATE OF w SKIP LOCKED LIMIT 1",
    )
    .bind(operator)
    .fetch_one(&mut *tx1)
    .await
    .expect("picker one picks a wallet");

    // Picker two, on a fresh connection, must skip the row picker one holds.
    let picked2 = sqlx::query_scalar::<_, Uuid>(
        "SELECT w.id FROM cw_core.operator_wallet w \
         JOIN cw_core.operator o ON o.id = w.registrar_operator_id \
         JOIN LATERAL ( \
             SELECT count(*) FILTER (WHERE u.state = 'available' AND u.canonical) AS ready \
             FROM cw_core.wallet_utxo u WHERE u.wallet_id = w.id \
         ) c ON true \
         WHERE w.registrar_operator_id = $1 AND w.network = 'preprod' AND w.status = 'active' \
           AND o.status = 'active' AND c.ready > 0 \
         ORDER BY w.id \
         FOR UPDATE OF w SKIP LOCKED LIMIT 1",
    )
    .bind(operator)
    .fetch_one(&db.pool)
    .await
    .expect("picker two picks a different wallet");

    assert_ne!(
        picked1, picked2,
        "two concurrent pickers must get different wallets"
    );
    let mut got = [picked1, picked2];
    got.sort();
    let mut want = [w1, w2];
    want.sort();
    assert_eq!(got, want, "between them the pickers cover both wallets");

    tx1.rollback().await.expect("release picker one's lock");
}

#[tokio::test]
async fn record_submission_bumps_the_counter_and_stamps_last_used() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;
    let wallet = seed_wallet(&db.pool, operator, "w", WalletSeed::default()).await;

    record_submission(&db.pool, wallet)
        .await
        .expect("record submission");
    record_submission(&db.pool, wallet)
        .await
        .expect("record submission again");

    let (count, last_used): (i64, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "SELECT submission_count_24h, last_used_at FROM cw_core.operator_wallet WHERE id = $1",
    )
    .bind(wallet)
    .fetch_one(&db.pool)
    .await
    .expect("read wallet");
    assert_eq!(count, 2, "each submission bumps the counter by one");
    assert!(last_used.is_some(), "last_used_at is stamped on submit");
}

#[tokio::test]
async fn decay_resets_only_non_zero_counters() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;
    let busy = seed_wallet(
        &db.pool,
        operator,
        "busy",
        WalletSeed {
            submission_count_24h: 7,
            ..WalletSeed::default()
        },
    )
    .await;
    let _idle = seed_wallet(
        &db.pool,
        operator,
        "idle",
        WalletSeed {
            submission_count_24h: 0,
            ..WalletSeed::default()
        },
    )
    .await;

    let reset = decay_submission_counters(&db.pool)
        .await
        .expect("decay pass");
    assert_eq!(reset, 1, "only the wallet with a non-zero counter is reset");

    let count: i64 = sqlx::query_scalar(
        "SELECT submission_count_24h FROM cw_core.operator_wallet WHERE id = $1",
    )
    .bind(busy)
    .fetch_one(&db.pool)
    .await
    .expect("read busy");
    assert_eq!(count, 0, "the busy wallet's counter is now zero");

    // Idempotent: a second decay with everything already zero resets nothing.
    let again = decay_submission_counters(&db.pool)
        .await
        .expect("second decay");
    assert_eq!(again, 0);
}

#[tokio::test]
async fn retire_sweep_retires_only_fully_drained_wallets() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;

    // A draining wallet with nothing in flight: eligible to retire.
    let drained = seed_wallet(
        &db.pool,
        operator,
        "drained",
        WalletSeed {
            status: "draining",
            canonical_available: 0,
            in_flight: 0,
            ..WalletSeed::default()
        },
    )
    .await;
    // A draining wallet still finishing an in-flight tx: must NOT retire yet.
    let still_busy = seed_wallet(
        &db.pool,
        operator,
        "still-busy",
        WalletSeed {
            status: "draining",
            canonical_available: 0,
            in_flight: 1,
            ..WalletSeed::default()
        },
    )
    .await;
    // An active wallet: never touched by the retire sweep.
    let active = seed_wallet(&db.pool, operator, "active", WalletSeed::default()).await;

    let retired = sweep_drained_wallets(&db.pool).await.expect("retire sweep");
    assert_eq!(retired, 1, "only the fully drained wallet retires");

    assert_eq!(status_of(&db.pool, drained).await, "retired");
    assert_eq!(
        status_of(&db.pool, still_busy).await,
        "draining",
        "a draining wallet with in-flight work keeps draining"
    );
    assert_eq!(status_of(&db.pool, active).await, "active");

    // The retired wallet got a retired_at stamp.
    let retired_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT retired_at FROM cw_core.operator_wallet WHERE id = $1")
            .bind(drained)
            .fetch_one(&db.pool)
            .await
            .expect("read retired_at");
    assert!(retired_at.is_some(), "retired_at is stamped on retire");

    // Idempotent: a second sweep retires nothing more (still-busy still busy).
    let again = sweep_drained_wallets(&db.pool).await.expect("second sweep");
    assert_eq!(again, 0);
}

#[tokio::test]
async fn maintenance_handler_runs_decay_and_retire_in_one_pass() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool, "active").await;
    let busy = seed_wallet(
        &db.pool,
        operator,
        "busy",
        WalletSeed {
            submission_count_24h: 9,
            ..WalletSeed::default()
        },
    )
    .await;
    let drained = seed_wallet(
        &db.pool,
        operator,
        "drained",
        WalletSeed {
            status: "draining",
            canonical_available: 0,
            in_flight: 0,
            ..WalletSeed::default()
        },
    )
    .await;

    let handler = pool::WalletMaintenanceHandler::new(db.pool.clone());
    let outcome = handler.run_once().await.expect("maintenance pass");
    assert_eq!(outcome.counters_reset, 1);
    assert_eq!(outcome.wallets_retired, 1);

    let count: i64 = sqlx::query_scalar(
        "SELECT submission_count_24h FROM cw_core.operator_wallet WHERE id = $1",
    )
    .bind(busy)
    .fetch_one(&db.pool)
    .await
    .expect("read busy");
    assert_eq!(count, 0);
    assert_eq!(status_of(&db.pool, drained).await, "retired");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_wallet_locks_are_namespaced_by_wallet() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet_a = Uuid::now_v7();
    let wallet_b = Uuid::now_v7();

    // The per-wallet session advisory lock serialises submits on ONE wallet:
    // while wallet A's lock is held, a second attempt on A fails fast, but a
    // lock on a different wallet B is independent and succeeds. This is the
    // contention boundary the submit path relies on (one wallet, one builder).
    let held_a = pool::lock_wallet(&db.pool, wallet_a)
        .await
        .expect("acquire wallet A's lock");

    let contend_a = pool::try_lock_wallet(&db.pool, wallet_a)
        .await
        .expect("try_lock should not error");
    assert!(
        contend_a.is_none(),
        "a second lock on the same wallet must fail while held"
    );

    let lock_b = pool::try_lock_wallet(&db.pool, wallet_b)
        .await
        .expect("try_lock should not error")
        .expect("a different wallet's lock is independent and free");

    lock_b.release().await.expect("release B");
    held_a.release().await.expect("release A");

    // After release, the wallet A lock is reacquirable.
    let reacquired = pool::try_lock_wallet(&db.pool, wallet_a)
        .await
        .expect("try_lock should not error")
        .expect("wallet A's lock is free after release");
    reacquired.release().await.expect("release reacquired A");
}

/// The current status string of a wallet.
async fn status_of(pool: &sqlx::PgPool, wallet_id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM cw_core.operator_wallet WHERE id = $1")
        .bind(wallet_id)
        .fetch_one(pool)
        .await
        .expect("read status")
}
