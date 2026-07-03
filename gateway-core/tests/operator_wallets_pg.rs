//! Integration coverage for the operator-wallet schema.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test stands up an isolated, freshly migrated database via the harness.
//! These assert real schema behaviour the wallet module relies on: the
//! per-UTxO primary key rejects a duplicate output reference, and the durable
//! state machine's CHECK constraints enforce the lease/state invariant and the
//! non-negative output index, so a malformed row can never be inserted out of
//! band of the code paths.

#![cfg(feature = "pg-tests")]

use gateway_core::ledger::account::ScopedTransition;
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, MAX_CANONICAL_OUTPUT_INDEX};
use gateway_core::wallet::operator::{
    begin_draining, create_operator, load_wallet, reactivate, register_wallet, RegisterOutcome,
    WalletStatus,
};
use gateway_core::wallet::utxo::{is_canonical, ObservedUtxo, UtxoRef};
use sqlx::Row;
use uuid::Uuid;

/// Unwrap a [`register_wallet`] result that must have inserted/renamed under the
/// calling operator (not been rejected as a foreign address). Returns the
/// `(wallet_id, inserted)` pair the assertions read.
fn expect_registered(outcome: RegisterOutcome) -> (Uuid, bool) {
    match outcome {
        RegisterOutcome::Registered(r) => (r.wallet_id, r.inserted),
        RegisterOutcome::AddressTaken { .. } => {
            panic!("registration was unexpectedly rejected as an address already taken")
        }
    }
}

/// A real preprod enterprise bech32 address, reused by the registration tests
/// (the address must now parse as a Cardano payment address on the network).
const PREPROD_ADDRESS: &str = "addr_test1vpa8ukd77k05gc3etxeyzylxxmyhzg0hvne9qplxvsyl44q6pl7v4";

/// A canonical band whose endpoints share a CBOR width: the 4-8 ADA window the
/// replenisher grooms toward. Used by the predicate test.
fn test_band() -> LovelaceBand {
    LovelaceBand {
        min: 4_000_000,
        max: 8_000_000,
        mid: 6_000_000,
    }
}

/// Insert an operator and one active wallet, returning the wallet's id. The
/// schema tests below assert raw column behaviour, so they seed the parent rows
/// directly in SQL; the `operator` helpers have their own behaviour coverage
/// further down this file.
async fn seed_wallet(pool: &sqlx::PgPool) -> Uuid {
    let operator_id = Uuid::now_v7();
    let wallet_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(operator_id)
        .bind("test-operator")
        .execute(pool)
        .await
        .expect("insert operator");
    // `address` is the wallet's global identity, so each seeded wallet gets a
    // distinct address derived from its id (the value's shape is irrelevant to
    // these raw-schema tests; only its global uniqueness matters here).
    let address = format!("addr_test_{}", wallet_id.simple());
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet (id, registrar_operator_id, label, address, network) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(wallet_id)
    .bind(operator_id)
    .bind("primary")
    .bind(address)
    .bind("preprod")
    .execute(pool)
    .await
    .expect("insert wallet");
    wallet_id
}

/// The migration applies cleanly: a query against each of the
/// new tables succeeds on a freshly migrated database.
#[tokio::test]
async fn migration_creates_the_operator_wallet_tables() {
    let db = TestDb::fresh().await.expect("test database");

    for table in ["operator", "operator_wallet", "wallet_utxo"] {
        let sql = format!("SELECT count(*) FROM cw_core.{table}");
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&db.pool)
            .await
            .unwrap_or_else(|e| panic!("querying cw_core.{table} should succeed: {e}"));
        assert_eq!(count, 0, "a fresh {table} starts empty");
    }
}

/// The `wallet_utxo` primary key is the on-chain reference
/// `(wallet_id, tx_hash, output_index)`: inserting the same reference twice for a
/// wallet is rejected, while the same `(tx_hash, output_index)` under a
/// different wallet is allowed (the key is wallet-scoped).
#[tokio::test]
async fn wallet_utxo_primary_key_is_the_on_chain_reference() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet_a = seed_wallet(&db.pool).await;
    let wallet_b = seed_wallet(&db.pool).await;
    let tx_hash = vec![0xAB_u8; 32];

    let insert = |wallet: Uuid, hash: Vec<u8>, index: i32| {
        let pool = db.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO cw_core.wallet_utxo \
                   (wallet_id, tx_hash, output_index, lovelace, source) \
                 VALUES ($1, $2, $3, $4, 'snapshot')",
            )
            .bind(wallet)
            .bind(hash)
            .bind(index)
            .bind(6_000_000_i64)
            .execute(&pool)
            .await
        }
    };

    insert(wallet_a, tx_hash.clone(), 0)
        .await
        .expect("first insert of a reference succeeds");

    // Same wallet + same reference is a primary-key collision.
    let dup = insert(wallet_a, tx_hash.clone(), 0).await;
    assert!(
        dup.is_err(),
        "a duplicate (wallet_id, tx_hash, output_index) must be rejected by the PK"
    );

    // The identical on-chain reference under a different wallet is a distinct
    // key and is accepted.
    insert(wallet_b, tx_hash.clone(), 0)
        .await
        .expect("the same reference under another wallet is a different key");

    // A different output index under the same tx for wallet A is also distinct.
    insert(wallet_a, tx_hash, 1)
        .await
        .expect("a different output index is a different key");
}

/// The state/lease CHECK enforces the fencing invariant at the schema level: an
/// `in_flight` row must carry a lease token and expiry, and a non-`in_flight`
/// row must carry neither. A row violating either half is rejected.
#[tokio::test]
async fn state_lease_check_enforces_the_fencing_invariant() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;

    // in_flight without a lease token is rejected.
    let bad_in_flight = sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, source) \
         VALUES ($1, $2, 0, 6000000, 'in_flight', 'snapshot')",
    )
    .bind(wallet)
    .bind(vec![0x01_u8; 32])
    .execute(&db.pool)
    .await;
    assert!(
        bad_in_flight.is_err(),
        "an in_flight row without a lease token must be rejected"
    );

    // available WITH a lease token is rejected (a freed row must not retain a
    // lease).
    let bad_available = sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, lease_token, lease_expires_at, source) \
         VALUES ($1, $2, 0, 6000000, 'available', $3, now(), 'snapshot')",
    )
    .bind(wallet)
    .bind(vec![0x02_u8; 32])
    .bind(Uuid::now_v7())
    .execute(&db.pool)
    .await;
    assert!(
        bad_available.is_err(),
        "an available row carrying a lease token must be rejected"
    );

    // A well-formed in_flight row (token + expiry present) is accepted.
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, lease_token, lease_expires_at, source) \
         VALUES ($1, $2, 0, 6000000, 'in_flight', $3, now() + interval '5 minutes', 'snapshot')",
    )
    .bind(wallet)
    .bind(vec![0x03_u8; 32])
    .bind(Uuid::now_v7())
    .execute(&db.pool)
    .await
    .expect("a well-formed in_flight row is accepted");
}

/// The output-index CHECK rejects a negative index, so a malformed chain read
/// can never land a negative-index row.
#[tokio::test]
async fn output_index_must_be_non_negative() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;

    let negative = sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, source) \
         VALUES ($1, $2, -1, 6000000, 'snapshot')",
    )
    .bind(wallet)
    .bind(vec![0x04_u8; 32])
    .execute(&db.pool)
    .await;
    assert!(
        negative.is_err(),
        "a negative output_index must be rejected by the CHECK"
    );
}

/// `operator_wallet.address` is GLOBALLY unique per network: a second wallet row
/// at the same `(network, address)` is rejected by the UNIQUE constraint, even
/// when a different operator registered it. This is the schema-level guarantee
/// that an on-chain identity can never be aliased by a parallel row, regardless of
/// which operator inserts it.
#[tokio::test]
async fn wallet_address_is_globally_unique_per_network() {
    let db = TestDb::fresh().await.expect("test database");
    let op_a = Uuid::now_v7();
    let op_b = Uuid::now_v7();
    for (id, label) in [(op_a, "a"), (op_b, "b")] {
        sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
            .bind(id)
            .bind(label)
            .execute(&db.pool)
            .await
            .expect("insert operator");
    }

    let insert = |wallet: Uuid, registrar: Uuid| {
        let pool = db.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO cw_core.operator_wallet \
                   (id, registrar_operator_id, label, address, network) \
                 VALUES ($1, $2, 'w', $3, 'preprod')",
            )
            .bind(wallet)
            .bind(registrar)
            .bind(PREPROD_ADDRESS)
            .execute(&pool)
            .await
        }
    };

    insert(Uuid::now_v7(), op_a)
        .await
        .expect("the first wallet at an address inserts");
    // The SAME operator inserting the address again collides.
    assert!(
        insert(Uuid::now_v7(), op_a).await.is_err(),
        "a second row at the same address under the same operator is rejected"
    );
    // A DIFFERENT operator inserting the same address also collides: the identity
    // is global, not operator-scoped.
    assert!(
        insert(Uuid::now_v7(), op_b).await.is_err(),
        "a second operator cannot mint a parallel row for an already-registered address"
    );
}

/// The canonical predicate the quote depends on: a pure-ADA output at a low
/// index whose value is in the band is canonical; a token-bearing output, an
/// out-of-band value, or a high output index is not. This is the in-code
/// computation the ingest stores in the `canonical` column.
#[tokio::test]
async fn canonical_predicate_matches_the_band_and_index_rules() {
    let band = test_band();

    let pure_in_band = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0u8; 32],
            output_index: 0,
        },
        lovelace: band.mid,
        pure_ada: true,
    };
    assert!(
        is_canonical(&pure_in_band, &band),
        "a pure-ADA band-mid output at index 0 is canonical"
    );

    // Inclusive band endpoints are canonical.
    let at_min = ObservedUtxo {
        lovelace: band.min,
        ..pure_in_band
    };
    let at_max = ObservedUtxo {
        lovelace: band.max,
        ..pure_in_band
    };
    assert!(
        is_canonical(&at_min, &band),
        "the band minimum is canonical"
    );
    assert!(
        is_canonical(&at_max, &band),
        "the band maximum is canonical"
    );

    // Just outside the band is not canonical.
    let below = ObservedUtxo {
        lovelace: band.min - 1,
        ..pure_in_band
    };
    let above = ObservedUtxo {
        lovelace: band.max + 1,
        ..pure_in_band
    };
    assert!(
        !is_canonical(&below, &band),
        "below the band is not canonical"
    );
    assert!(
        !is_canonical(&above, &band),
        "above the band is not canonical"
    );

    // A token-bearing output is never canonical, even in band at index 0.
    let with_token = ObservedUtxo {
        pure_ada: false,
        ..pure_in_band
    };
    assert!(
        !is_canonical(&with_token, &band),
        "a token-bearing output is never canonical"
    );

    // An output at or above the index cap is not canonical.
    let high_index = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0u8; 32],
            output_index: MAX_CANONICAL_OUTPUT_INDEX,
        },
        ..pure_in_band
    };
    assert!(
        !is_canonical(&high_index, &band),
        "an output at the index cap is not canonical"
    );
}

/// A planted row reads back at its primary key with the expected defaults: a
/// snapshot-sourced available row is non-canonical and non-spendable-unconfirmed
/// until the ingest computes otherwise. This pins the column defaults the code
/// relies on.
#[tokio::test]
async fn inserted_row_defaults_match_the_state_machine() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let tx_hash = vec![0x05_u8; 32];

    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, source) \
         VALUES ($1, $2, 3, 6000000, 'change')",
    )
    .bind(wallet)
    .bind(tx_hash.clone())
    .execute(&db.pool)
    .await
    .expect("insert change row");

    let row = sqlx::query(
        "SELECT state, canonical, spendable_unconfirmed, source \
         FROM cw_core.wallet_utxo WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = 3",
    )
    .bind(wallet)
    .bind(tx_hash)
    .fetch_one(&db.pool)
    .await
    .expect("read back the row");

    let state: String = row.get("state");
    let canonical: bool = row.get("canonical");
    let spendable: bool = row.get("spendable_unconfirmed");
    let source: String = row.get("source");
    assert_eq!(state, "available", "a fresh row defaults to available");
    assert!(!canonical, "a change row is not canonical by default");
    assert!(!spendable, "unconfirmed change is not spendable by default");
    assert_eq!(source, "change");
}

/// `create_operator` mints a UUIDv7 row that loads back active, and
/// `register_wallet` keyed on the global address inserts a fresh active wallet the
/// first time and updates only its label (preserving id and status) on a re-unlock
/// by the same operator.
#[tokio::test]
async fn register_wallet_inserts_then_renames_in_place() {
    let db = TestDb::fresh().await.expect("test database");
    let operator_id = create_operator(&db.pool, "acme")
        .await
        .expect("create operator");

    let address = PREPROD_ADDRESS;
    let (first_id, inserted) = expect_registered(
        register_wallet(&db.pool, operator_id, "primary", address, Network::Preprod)
            .await
            .expect("first register"),
    );
    assert!(inserted, "the first register inserts a fresh wallet");

    let loaded = load_wallet(&db.pool, first_id)
        .await
        .expect("load")
        .expect("the wallet exists");
    assert_eq!(loaded.registrar_operator_id, operator_id);
    assert_eq!(loaded.label, "primary");
    assert_eq!(loaded.address, address);
    assert_eq!(loaded.network, Network::Preprod);
    assert_eq!(
        loaded.status,
        WalletStatus::Active,
        "a new wallet is active"
    );

    // A second register at the same address by the same operator is a rename:
    // same persistent id, new label, not reported as an insert.
    let (second_id, second_inserted) = expect_registered(
        register_wallet(&db.pool, operator_id, "renamed", address, Network::Preprod)
            .await
            .expect("second register"),
    );
    assert!(
        !second_inserted,
        "re-registering an address updates, not inserts"
    );
    assert_eq!(
        second_id, first_id,
        "the persistent id is stable across a rename"
    );
    let reloaded = load_wallet(&db.pool, first_id)
        .await
        .expect("load")
        .expect("still exists");
    assert_eq!(reloaded.label, "renamed", "only the label changed");
}

/// A re-register of a wallet that has been drained must NOT silently re-activate
/// it: the status column is untouched by the conflict update.
#[tokio::test]
async fn register_wallet_does_not_reactivate_a_drained_wallet() {
    let db = TestDb::fresh().await.expect("test database");
    let operator_id = create_operator(&db.pool, "acme")
        .await
        .expect("create operator");
    let address = PREPROD_ADDRESS;
    let (wallet_id, _) = expect_registered(
        register_wallet(&db.pool, operator_id, "primary", address, Network::Preprod)
            .await
            .expect("insert"),
    );

    // Drain it, then re-run the register.
    assert_eq!(
        begin_draining(&db.pool, operator_id, wallet_id)
            .await
            .expect("drain"),
        ScopedTransition::Changed {
            from: WalletStatus::Active,
            to: WalletStatus::Draining
        },
        "an active wallet transitions to draining"
    );
    register_wallet(&db.pool, operator_id, "primary", address, Network::Preprod)
        .await
        .expect("re-register");

    let reloaded = load_wallet(&db.pool, wallet_id)
        .await
        .expect("load")
        .expect("exists");
    assert_eq!(
        reloaded.status,
        WalletStatus::Draining,
        "a re-register must not resurrect a drained wallet to active"
    );
}

/// `begin_draining` is idempotent and guarded: it transitions an active wallet
/// once and is an idempotent no-op on a wallet already draining.
#[tokio::test]
async fn begin_draining_is_idempotent() {
    let db = TestDb::fresh().await.expect("test database");
    let operator_id = create_operator(&db.pool, "acme")
        .await
        .expect("create operator");
    let address = PREPROD_ADDRESS;
    let (wallet_id, _) = expect_registered(
        register_wallet(&db.pool, operator_id, "primary", address, Network::Preprod)
            .await
            .expect("insert"),
    );

    assert_eq!(
        begin_draining(&db.pool, operator_id, wallet_id)
            .await
            .expect("first drain"),
        ScopedTransition::Changed {
            from: WalletStatus::Active,
            to: WalletStatus::Draining
        },
        "the first drain transitions the wallet"
    );
    assert_eq!(
        begin_draining(&db.pool, operator_id, wallet_id)
            .await
            .expect("second drain"),
        ScopedTransition::Unchanged {
            status: WalletStatus::Draining
        },
        "draining an already-draining wallet is an idempotent no-op"
    );

    // A different operator cannot drain this wallet: it is reported as absent
    // (the lifecycle is the registrar's prerogative).
    let other = create_operator(&db.pool, "other")
        .await
        .expect("create other operator");
    assert_eq!(
        begin_draining(&db.pool, other, wallet_id)
            .await
            .expect("cross-operator drain"),
        ScopedTransition::NotFound,
        "a wallet registered by another operator is invisible to the drain transition"
    );
}

/// A wallet already in the terminal `retired` state reports its REAL status on
/// both drain and reactivate, with `changed = false` and no row mutation: the
/// transition helpers never report the requested target for a no-op, so a route
/// built on them cannot falsely claim a retired wallet is "draining"/"active".
#[tokio::test]
async fn a_retired_wallet_reports_its_real_status_on_drain_and_reactivate() {
    let db = TestDb::fresh().await.expect("test database");
    let operator_id = create_operator(&db.pool, "acme")
        .await
        .expect("create operator");
    let address = PREPROD_ADDRESS;
    let (wallet_id, _) = expect_registered(
        register_wallet(&db.pool, operator_id, "primary", address, Network::Preprod)
            .await
            .expect("insert"),
    );

    // Force the wallet to the terminal retired state (the sweep job does this in
    // production; here we set it directly to exercise the transition reporting).
    sqlx::query("UPDATE cw_core.operator_wallet SET status = 'retired' WHERE id = $1")
        .bind(wallet_id)
        .execute(&db.pool)
        .await
        .expect("retire wallet");

    // Draining a retired wallet is a no-op that reports `retired`, not `draining`.
    assert_eq!(
        begin_draining(&db.pool, operator_id, wallet_id)
            .await
            .expect("drain retired"),
        ScopedTransition::Unchanged {
            status: WalletStatus::Retired
        },
        "draining a retired wallet reports its real status, not the target"
    );
    // Reactivating a retired wallet is likewise a no-op that reports `retired`.
    assert_eq!(
        reactivate(&db.pool, operator_id, wallet_id)
            .await
            .expect("reactivate retired"),
        ScopedTransition::Unchanged {
            status: WalletStatus::Retired
        },
        "reactivating a retired wallet reports its real status, not the target"
    );

    // Neither call moved the wallet off retired.
    let reloaded = load_wallet(&db.pool, wallet_id)
        .await
        .expect("load")
        .expect("exists");
    assert_eq!(
        reloaded.status,
        WalletStatus::Retired,
        "the wallet stays retired after both no-op transitions"
    );
}

/// A wallet is a global identity: a second operator that registers an address the
/// first already registered is REJECTED ([`RegisterOutcome::AddressTaken`]), not
/// given a parallel row. The first operator's wallet is left completely untouched,
/// and the rejection points at the existing wallet so the caller can report it.
#[tokio::test]
async fn same_address_second_operator_is_rejected() {
    let db = TestDb::fresh().await.expect("test database");
    let op_a = create_operator(&db.pool, "operator-a")
        .await
        .expect("create operator A");
    let op_b = create_operator(&db.pool, "operator-b")
        .await
        .expect("create operator B");
    let address = PREPROD_ADDRESS;

    // B registers the address first and gets a fresh wallet.
    let (b_wallet, b_inserted) = expect_registered(
        register_wallet(&db.pool, op_b, "b-label", address, Network::Preprod)
            .await
            .expect("B registers"),
    );
    assert!(b_inserted, "B's registration inserts a fresh wallet");

    // A registers the SAME address. The global identity is taken, so A is
    // rejected and pointed at B's existing wallet, never given a parallel row.
    let a_outcome = register_wallet(&db.pool, op_a, "a-label", address, Network::Preprod)
        .await
        .expect("A registers");
    match a_outcome {
        RegisterOutcome::AddressTaken { wallet_id } => {
            assert_eq!(
                wallet_id, b_wallet,
                "the rejection points at the wallet that already holds the address"
            );
        }
        RegisterOutcome::Registered(_) => {
            panic!("a second operator must not be able to register an already-registered address")
        }
    }

    // B's row is completely untouched: same id, registrar, label, status, address,
    // and there is exactly one row at the address.
    let b_row = load_wallet(&db.pool, b_wallet)
        .await
        .expect("load B")
        .expect("B still exists");
    assert_eq!(
        b_row.registrar_operator_id, op_b,
        "B's wallet is still B's; A's rejected register did not steal it"
    );
    assert_eq!(b_row.label, "b-label", "A's register did not rename B");
    assert_eq!(b_row.address, address);
    assert_eq!(b_row.status, WalletStatus::Active);

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.operator_wallet WHERE network = 'preprod' AND address = $1",
    )
    .bind(address)
    .fetch_one(&db.pool)
    .await
    .expect("count rows at the address");
    assert_eq!(count, 1, "exactly one wallet row exists at the address");
}

/// `load_wallet` returns `None` for an unknown id rather than erroring.
#[tokio::test]
async fn load_wallet_returns_none_for_an_unknown_id() {
    let db = TestDb::fresh().await.expect("test database");
    assert!(
        load_wallet(&db.pool, Uuid::now_v7())
            .await
            .expect("load")
            .is_none(),
        "an unknown wallet id loads to None"
    );
}
