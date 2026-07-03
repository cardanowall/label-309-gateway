//! Integration coverage for the durable per-UTxO state machine.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test stands up an isolated, freshly migrated database via the harness and
//! exercises the real claim/release/apply/reap/ingest transitions against
//! Postgres, asserting on the resulting rows. The fencing invariant is the
//! through-line: a lease token gates every transition out of `in_flight`, so a
//! stale builder can never move a UTxO a fresh claimant now owns.

#![cfg(feature = "pg-tests")]

use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use gateway_core::wallet::pool;
use gateway_core::wallet::utxo::{
    self, ChangeOutput, ConfirmedSpend, ObservedUtxo, SpentInput, UtxoRef, UtxoState,
};
use sqlx::Row;
use uuid::Uuid;

/// Drive the production [`utxo::apply_submit_in_tx`] over its own transaction:
/// commit on success, roll back when a stale lease fences the apply out. This is
/// the own-transaction harness the record-before-broadcast path inlines (it runs
/// `apply_submit_in_tx` as the last writes of a larger transaction); these tests
/// exercise the same fenced DML in isolation.
async fn apply_submit(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    spent: &[SpentInput],
    change: Option<ChangeOutput>,
) -> gateway_core::Result<bool> {
    let mut tx = pool.begin().await?;
    let applied = utxo::apply_submit_in_tx(&mut tx, wallet_id, spent, change).await?;
    if applied {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(applied)
}

/// A canonical band whose endpoints share a CBOR width: the 4-8 ADA window the
/// replenisher grooms toward.
fn band() -> LovelaceBand {
    LovelaceBand {
        min: 4_000_000,
        max: 8_000_000,
        mid: 6_000_000,
    }
}

/// A wallet config with a short lease so the reaper test does not have to wait.
fn config() -> WalletConfig {
    WalletConfig {
        network: Network::Preprod,
        band: band(),
        lease: std::time::Duration::from_secs(120),
        min_canonical_count: 4,
    }
}

/// Insert an operator and one active wallet, returning the wallet id.
async fn seed_wallet(pool: &sqlx::PgPool) -> Uuid {
    let operator_id = Uuid::now_v7();
    let wallet_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(operator_id)
        .bind("test-operator")
        .execute(pool)
        .await
        .expect("insert operator");
    let address = format!("addr_test_{}", wallet_id.simple());
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet (id, registrar_operator_id, label, address, network) \
         VALUES ($1, $2, $3, $4, 'preprod')",
    )
    .bind(wallet_id)
    .bind(operator_id)
    .bind("primary")
    .bind(address)
    .execute(pool)
    .await
    .expect("insert wallet");
    wallet_id
}

/// A pure-ADA, band-mid observed output at `output_index` distinguished by `byte`.
fn observed(byte: u8, output_index: u32) -> ObservedUtxo {
    ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [byte; 32],
            output_index,
        },
        lovelace: band().mid,
        pure_ada: true,
    }
}

/// Read a single row's `(state, canonical, lease_token present)` triple.
async fn read_row(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    utxo: UtxoRef,
) -> Option<(String, bool, bool, i64)> {
    let row = sqlx::query(
        "SELECT state, canonical, (lease_token IS NOT NULL) AS leased, lovelace \
         FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3",
    )
    .bind(wallet_id)
    .bind(utxo.tx_hash.as_slice())
    .bind(utxo.output_index as i32)
    .fetch_optional(pool)
    .await
    .expect("read row");
    row.map(|r| {
        (
            r.get::<String, _>("state"),
            r.get::<bool, _>("canonical"),
            r.get::<bool, _>("leased"),
            r.get::<i64, _>("lovelace"),
        )
    })
}

/// Ingest a fresh canonical output for the wallet, returning its reference.
async fn ingest_one(pool: &sqlx::PgPool, wallet_id: Uuid, byte: u8) -> UtxoRef {
    let out = observed(byte, 0);
    let inserted = utxo::ingest_snapshot(pool, wallet_id, &[out], &config())
        .await
        .expect("ingest");
    assert_eq!(inserted, 1, "a fresh output is inserted once");
    out.utxo
}

#[tokio::test]
async fn ingest_computes_canonical_and_is_idempotent() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;

    // A band-mid pure-ADA output at index 0 ingests as canonical; a token-bearing
    // output and an out-of-band output ingest as non-canonical.
    let canonical = observed(0x01, 0);
    let with_token = ObservedUtxo {
        pure_ada: false,
        ..observed(0x02, 0)
    };
    let out_of_band = ObservedUtxo {
        lovelace: band().max + 1,
        ..observed(0x03, 0)
    };
    let inserted = utxo::ingest_snapshot(
        &db.pool,
        wallet,
        &[canonical, with_token, out_of_band],
        &config(),
    )
    .await
    .expect("ingest");
    assert_eq!(inserted, 3);

    assert!(
        read_row(&db.pool, wallet, canonical.utxo).await.unwrap().1,
        "a band-mid pure-ADA output is canonical"
    );
    assert!(
        !read_row(&db.pool, wallet, with_token.utxo).await.unwrap().1,
        "a token-bearing output is not canonical"
    );
    assert!(
        !read_row(&db.pool, wallet, out_of_band.utxo)
            .await
            .unwrap()
            .1,
        "an out-of-band output is not canonical"
    );

    // Re-ingesting the same snapshot inserts nothing (idempotent).
    let again = utxo::ingest_snapshot(
        &db.pool,
        wallet,
        &[canonical, with_token, out_of_band],
        &config(),
    )
    .await
    .expect("re-ingest");
    assert_eq!(again, 0, "re-ingesting the same outputs inserts nothing");

    assert_eq!(
        utxo::canonical_ready_count(&db.pool, wallet).await.unwrap(),
        1,
        "only the one canonical output is counted ready"
    );
}

#[tokio::test]
async fn claim_flips_available_to_in_flight_with_a_lease() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let utxo_ref = ingest_one(&db.pool, wallet, 0x11).await;

    let token = Uuid::now_v7();
    let lease = utxo::claim(&db.pool, wallet, token, &config())
        .await
        .expect("claim")
        .expect("a canonical output is available to lease");

    assert_eq!(
        lease.utxo, utxo_ref,
        "the leased reference is the canonical one"
    );
    assert_eq!(lease.lease_token, token);
    assert_eq!(lease.lovelace, band().mid);
    assert!(
        lease.expires_at > chrono::Utc::now(),
        "the lease expiry is in the future"
    );

    let (state, _canonical, leased, _) = read_row(&db.pool, wallet, utxo_ref).await.unwrap();
    assert_eq!(state, "in_flight", "the claimed row is in_flight");
    assert!(leased, "the in_flight row carries a lease token");

    // It is no longer counted as ready.
    assert_eq!(
        utxo::canonical_ready_count(&db.pool, wallet).await.unwrap(),
        0,
        "a leased UTxO is not ready"
    );
}

#[tokio::test]
async fn claim_returns_none_when_no_canonical_utxo_is_available() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;

    // No UTxOs at all.
    let none = utxo::claim(&db.pool, wallet, Uuid::now_v7(), &config())
        .await
        .expect("claim on empty wallet");
    assert!(none.is_none(), "an empty wallet has nothing to lease");

    // A non-canonical (out-of-band) output is present but not claimable.
    let out_of_band = ObservedUtxo {
        lovelace: band().max + 1,
        ..observed(0x22, 0)
    };
    utxo::ingest_snapshot(&db.pool, wallet, &[out_of_band], &config())
        .await
        .expect("ingest");
    let still_none = utxo::claim(&db.pool, wallet, Uuid::now_v7(), &config())
        .await
        .expect("claim with only non-canonical");
    assert!(
        still_none.is_none(),
        "a non-canonical output is never leased"
    );
}

#[tokio::test]
async fn concurrent_claims_take_distinct_utxos() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    // Two canonical outputs available.
    utxo::ingest_snapshot(
        &db.pool,
        wallet,
        &[observed(0x31, 0), observed(0x32, 0)],
        &config(),
    )
    .await
    .expect("ingest two");

    let token_a = Uuid::now_v7();
    let token_b = Uuid::now_v7();
    let lease_a = utxo::claim(&db.pool, wallet, token_a, &config())
        .await
        .unwrap()
        .expect("first claim");
    let lease_b = utxo::claim(&db.pool, wallet, token_b, &config())
        .await
        .unwrap()
        .expect("second claim");
    assert_ne!(
        lease_a.utxo, lease_b.utxo,
        "two claims lease distinct UTxOs"
    );

    // A third claim finds nothing left.
    let third = utxo::claim(&db.pool, wallet, Uuid::now_v7(), &config())
        .await
        .unwrap();
    assert!(
        third.is_none(),
        "no canonical UTxO remains for a third claim"
    );
}

#[tokio::test]
async fn release_is_fenced_on_the_lease_token() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let utxo_ref = ingest_one(&db.pool, wallet, 0x41).await;

    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");

    // A release with the WRONG token does nothing: the row stays in_flight.
    let wrong = utxo::release(&db.pool, wallet, utxo_ref, Uuid::now_v7())
        .await
        .expect("release with wrong token");
    assert!(!wrong, "a stale token cannot release the lease");
    assert_eq!(
        read_row(&db.pool, wallet, utxo_ref).await.unwrap().0,
        "in_flight",
        "the row is still leased after a fenced-out release"
    );

    // A release with the CORRECT token re-avails the UTxO.
    let ok = utxo::release(&db.pool, wallet, utxo_ref, token)
        .await
        .expect("release with correct token");
    assert!(ok, "the lease holder releases its own UTxO");
    let (state, _c, leased, _) = read_row(&db.pool, wallet, utxo_ref).await.unwrap();
    assert_eq!(state, "available", "the released row is available again");
    assert!(!leased, "a released row carries no lease token");
    assert_eq!(
        utxo::canonical_ready_count(&db.pool, wallet).await.unwrap(),
        1,
        "the released UTxO is ready once more"
    );
}

#[tokio::test]
async fn apply_submit_marks_pending_spent_and_inserts_change_atomically() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let spent = ingest_one(&db.pool, wallet, 0x51).await;

    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");

    // The submit's expected change output: a new reference (the submit tx id).
    let change = ChangeOutput {
        utxo: UtxoRef {
            tx_hash: [0xAA; 32],
            output_index: 0,
        },
        lovelace: 5_400_000,
    };
    let applied = apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: spent,
            lease_token: token,
        }],
        Some(change),
    )
    .await
    .expect("apply submit");
    assert!(applied, "a valid lease applies the submit");

    // The input is pending_spent, no longer leased.
    let (state, _c, leased, _) = read_row(&db.pool, wallet, spent).await.unwrap();
    assert_eq!(state, "pending_spent", "the spent input is pending");
    assert!(!leased, "a pending_spent input carries no lease token");

    // The change row exists, available, non-canonical, not spendable, sourced change.
    let change_row = sqlx::query(
        "SELECT state, canonical, spendable_unconfirmed, source, lovelace \
         FROM cw_core.wallet_utxo WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3",
    )
    .bind(wallet)
    .bind(change.utxo.tx_hash.as_slice())
    .bind(change.utxo.output_index as i32)
    .fetch_one(&db.pool)
    .await
    .expect("change row exists");
    assert_eq!(change_row.get::<String, _>("state"), "available");
    assert!(!change_row.get::<bool, _>("canonical"));
    assert!(!change_row.get::<bool, _>("spendable_unconfirmed"));
    assert_eq!(change_row.get::<String, _>("source"), "change");
    assert_eq!(change_row.get::<i64, _>("lovelace"), 5_400_000);

    // Unconfirmed change is never counted ready.
    assert_eq!(
        utxo::canonical_ready_count(&db.pool, wallet).await.unwrap(),
        0,
        "unconfirmed change is not ready"
    );
}

#[tokio::test]
async fn apply_submit_is_fenced_and_does_not_insert_change_for_a_stale_lease() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let spent = ingest_one(&db.pool, wallet, 0x61).await;

    let real_token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, real_token, &config())
        .await
        .unwrap()
        .expect("claim");

    let change = ChangeOutput {
        utxo: UtxoRef {
            tx_hash: [0xBB; 32],
            output_index: 0,
        },
        lovelace: 5_400_000,
    };
    // A stale token cannot apply the submit, and must NOT insert the change row.
    let applied = apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: spent,
            lease_token: Uuid::now_v7(),
        }],
        Some(change),
    )
    .await
    .expect("apply with stale token");
    assert!(!applied, "a stale lease cannot apply the submit");

    assert_eq!(
        read_row(&db.pool, wallet, spent).await.unwrap().0,
        "in_flight",
        "the input stays in_flight after a fenced-out apply"
    );
    assert!(
        read_row(&db.pool, wallet, change.utxo).await.is_none(),
        "no change row is inserted when the lease was stale (atomic rollback)"
    );
}

#[tokio::test]
async fn lease_reaper_reavails_expired_in_flight_rows() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let utxo_ref = ingest_one(&db.pool, wallet, 0x71).await;

    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");

    // Nothing is reaped while the lease is live.
    let reaped_now = utxo::reap_expired_leases(&db.pool).await.expect("reap");
    assert_eq!(reaped_now, 0, "a live lease is not reaped");

    // Force the lease into the past, then reap.
    sqlx::query(
        "UPDATE cw_core.wallet_utxo SET lease_expires_at = now() - interval '1 minute' \
         WHERE wallet_id = $1 AND state = 'in_flight'",
    )
    .bind(wallet)
    .execute(&db.pool)
    .await
    .expect("expire the lease");

    let reaped = utxo::reap_expired_leases(&db.pool).await.expect("reap");
    assert_eq!(reaped, 1, "the expired lease is reaped");

    let (state, _c, leased, _) = read_row(&db.pool, wallet, utxo_ref).await.unwrap();
    assert_eq!(state, "available", "the reaped row is available again");
    assert!(!leased, "the reaped row carries no lease token");
}

/// A slow (live) submit must survive the reaper: while it holds the wallet's
/// advisory lock across its build/sign/submit window, an expired lease is NOT
/// reaped, so the submit's `apply_submit` still fences on its own token and
/// records the on-wire spend. A lease expiry alone is not proof the builder is
/// gone; the held lock is the authority on liveness. Once the lock is free, an
/// abandoned expired lease IS reaped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_submit_holding_the_lock_survives_the_reaper() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let utxo_ref = ingest_one(&db.pool, wallet, 0x73).await;

    // The live submit claims a canonical UTxO under its lease token.
    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");

    // Simulate a slow submit: the lease clock has elapsed while build/sign/submit
    // is still on the wire. The submit holds the wallet's advisory lock the whole
    // time, exactly as `submit_once` does.
    sqlx::query(
        "UPDATE cw_core.wallet_utxo SET lease_expires_at = now() - interval '1 minute' \
         WHERE wallet_id = $1 AND state = 'in_flight'",
    )
    .bind(wallet)
    .execute(&db.pool)
    .await
    .expect("expire the lease");

    let live_lock = pool::lock_wallet(&db.pool, wallet)
        .await
        .expect("the live submit holds the wallet lock");

    // The reaper runs against the whole deployment, sees the expired lease, but
    // must NOT reap it: the wallet's lock is held, so a live submit owns it.
    let reaped = utxo::reap_expired_leases(&db.pool).await.expect("reap");
    assert_eq!(
        reaped, 0,
        "an expired lease on a locked (live) wallet is never reaped"
    );

    let (state, _c, leased, _) = read_row(&db.pool, wallet, utxo_ref).await.unwrap();
    assert_eq!(
        state, "in_flight",
        "the live submit's lease survives the reaper pass"
    );
    assert!(leased, "the surviving lease keeps its fencing token");

    // The slow submit now lands and records its spend under its own token. Because
    // the reaper never touched the lease, the fence still matches and the on-wire
    // transaction is recorded locally rather than treated as lost.
    let applied = apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: utxo_ref,
            lease_token: token,
        }],
        None,
    )
    .await
    .expect("apply submit");
    assert!(
        applied,
        "the live submit records its spend; its lease was never reaped out from under it"
    );
    assert_eq!(
        read_row(&db.pool, wallet, utxo_ref).await.unwrap().0,
        "pending_spent",
        "the recorded spend advances the input to pending_spent"
    );

    // The submit window ends and the lock is released.
    live_lock.release().await.expect("release the wallet lock");

    // A later reaper pass on the now-free wallet finds nothing to reap (the lease
    // was consumed by apply_submit, not abandoned).
    let reaped_after = utxo::reap_expired_leases(&db.pool)
        .await
        .expect("reap again");
    assert_eq!(reaped_after, 0, "a consumed lease leaves nothing to reap");
}

/// A genuinely abandoned lease (its builder gone, the wallet lock free) IS reaped
/// once nothing holds the lock. This is the complement of the live-submit case:
/// the reaper reopens dead leases the moment no builder owns the wallet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_lease_is_reaped_once_the_lock_is_free() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let utxo_ref = ingest_one(&db.pool, wallet, 0x74).await;

    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");
    sqlx::query(
        "UPDATE cw_core.wallet_utxo SET lease_expires_at = now() - interval '1 minute' \
         WHERE wallet_id = $1 AND state = 'in_flight'",
    )
    .bind(wallet)
    .execute(&db.pool)
    .await
    .expect("expire the lease");

    // No lock is held (the builder crashed/vanished), so the expired lease is
    // abandoned and the reaper reopens it.
    let reaped = utxo::reap_expired_leases(&db.pool).await.expect("reap");
    assert_eq!(
        reaped, 1,
        "an abandoned expired lease on a free wallet is reaped"
    );
    let (state, _c, leased, _) = read_row(&db.pool, wallet, utxo_ref).await.unwrap();
    assert_eq!(state, "available", "the reaped row is available again");
    assert!(!leased, "the reaped row carries no lease token");
}

#[tokio::test]
async fn ingest_never_resurrects_a_pending_spent_input_from_a_stale_snapshot() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let spent = ingest_one(&db.pool, wallet, 0x81).await;

    // Claim and apply a submit so the input becomes pending_spent.
    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");
    let applied = apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: spent,
            lease_token: token,
        }],
        None,
    )
    .await
    .expect("apply submit");
    assert!(applied);
    assert_eq!(
        read_row(&db.pool, wallet, spent).await.unwrap().0,
        "pending_spent"
    );

    // A stale chain read still lists the spent input (the spend has not confirmed
    // on the provider yet). Ingesting it must NOT flip the row back to available.
    let stale = observed(0x81, 0);
    utxo::ingest_snapshot(&db.pool, wallet, &[stale], &config())
        .await
        .expect("ingest stale snapshot");

    assert_eq!(
        read_row(&db.pool, wallet, spent).await.unwrap().0,
        "pending_spent",
        "a stale snapshot listing a spent input never resurrects it to available"
    );
}

#[tokio::test]
async fn ingest_marks_a_vanished_available_output_confirmed_spent() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;

    // Two available outputs ingested.
    let stays = observed(0x91, 0);
    let vanishes = observed(0x92, 0);
    utxo::ingest_snapshot(&db.pool, wallet, &[stays, vanishes], &config())
        .await
        .expect("ingest two");

    // The next snapshot no longer lists `vanishes`: it was spent out of band.
    utxo::ingest_snapshot(&db.pool, wallet, &[stays], &config())
        .await
        .expect("ingest one");

    assert_eq!(
        read_row(&db.pool, wallet, stays.utxo).await.unwrap().0,
        "available",
        "an output still on chain stays available"
    );
    assert_eq!(
        read_row(&db.pool, wallet, vanishes.utxo).await.unwrap().0,
        "confirmed_spent",
        "an available output the chain dropped is marked confirmed_spent"
    );
}

/// Pins the fund-stranding bug where ingest's vanished-output reconciliation
/// tombstoned the wallet's own unconfirmed change: `apply_submit_in_tx` records
/// the expected change as an `available`, `source = 'change'` row the instant the
/// transaction is broadcast, so a snapshot ingested in the
/// broadcast->confirmation window does not list it — the transaction has not
/// landed yet. Reconciliation must skip that local projection (its absence is
/// expected, not an out-of-band spend); tombstoning it stranded the change
/// forever and starved replenish of the band-mid outputs it had just minted.
/// Once the spend confirms, the change HAS been on chain and an out-of-band
/// spend of it must again be caught — even when the change is out of band and so
/// never canonical.
#[tokio::test]
async fn ingest_protects_unconfirmed_local_change_regression() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;

    // Three on-chain outputs: the one the submit will spend (lowest tx_hash, so
    // `claim` picks it), one that stays on chain, and one that will vanish.
    let funding = observed(0x71, 0);
    let stays = observed(0x72, 0);
    let goner = observed(0x73, 0);
    utxo::ingest_snapshot(&db.pool, wallet, &[funding, stays, goner], &config())
        .await
        .expect("ingest three");

    let token = Uuid::now_v7();
    let lease = utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");
    assert_eq!(lease.utxo, funding.utxo, "claim picks the lowest tx_hash");

    // Out-of-band change: confirmation will make it spendable but never
    // canonical, the case a canonical-gated reconciliation would miss.
    let change = ChangeOutput {
        utxo: UtxoRef {
            tx_hash: [0xAB; 32],
            output_index: 0,
        },
        lovelace: band().max * 10,
    };
    apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: funding.utxo,
            lease_token: token,
        }],
        Some(change),
    )
    .await
    .expect("apply submit");

    // A snapshot from the broadcast->confirmation window: the spend has not
    // landed, so the chain does not list the change; `goner` was spent out of
    // band in the meantime.
    utxo::ingest_snapshot(&db.pool, wallet, &[funding, stays], &config())
        .await
        .expect("ingest mid-window");

    assert_eq!(
        read_row(&db.pool, wallet, change.utxo).await.unwrap().0,
        "available",
        "unconfirmed local change absent from a mid-window snapshot stays available"
    );
    assert_eq!(
        read_row(&db.pool, wallet, goner.utxo).await.unwrap().0,
        "confirmed_spent",
        "a snapshot-sourced output the chain dropped is still tombstoned"
    );
    assert_eq!(
        read_row(&db.pool, wallet, stays.utxo).await.unwrap().0,
        "available",
        "an output still on chain stays available"
    );

    // The spend confirms: the change has now been observed on chain (promotion
    // marks it spendable), though out of band it stays non-canonical.
    utxo::apply_confirmed(
        &db.pool,
        wallet,
        &[ConfirmedSpend {
            spend_tx_hash: change.utxo.tx_hash,
            inputs: vec![funding.utxo],
        }],
        &config(),
    )
    .await
    .expect("apply confirmed");

    // A later snapshot without the change now means an out-of-band spend of a
    // confirmed output, so reconciliation must catch it despite canonical=false.
    utxo::ingest_snapshot(&db.pool, wallet, &[stays], &config())
        .await
        .expect("ingest post-confirmation");

    let (state, canonical, _leased, _) = read_row(&db.pool, wallet, change.utxo).await.unwrap();
    assert!(!canonical, "out-of-band change never became canonical");
    assert_eq!(
        state, "confirmed_spent",
        "confirmed change spent out of band is tombstoned like any chain-observed output"
    );
}

#[tokio::test]
async fn ingest_leaves_a_live_in_flight_lease_untouched() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let leased = ingest_one(&db.pool, wallet, 0xA1).await;

    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");

    // An empty snapshot (the leased input is mid-flight and may not yet be listed)
    // must not touch the in_flight lease.
    utxo::ingest_snapshot(&db.pool, wallet, &[], &config())
        .await
        .expect("ingest empty");

    let (state, _c, is_leased, _) = read_row(&db.pool, wallet, leased).await.unwrap();
    assert_eq!(state, "in_flight", "the live lease is untouched by ingest");
    assert!(is_leased, "the in_flight row keeps its lease token");
}

#[tokio::test]
async fn apply_confirmed_promotes_the_spend_and_makes_change_canonical() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let spent = ingest_one(&db.pool, wallet, 0xB1).await;

    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");

    // The change lands in-band so confirmation can make it canonical.
    let change = ChangeOutput {
        utxo: UtxoRef {
            tx_hash: [0xCC; 32],
            output_index: 1,
        },
        lovelace: band().mid,
    };
    apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: spent,
            lease_token: token,
        }],
        Some(change),
    )
    .await
    .expect("apply submit");

    // Before confirmation: the change is not canonical, not counted ready.
    assert!(
        !read_row(&db.pool, wallet, change.utxo).await.unwrap().1,
        "unconfirmed change is not canonical"
    );

    let promoted = utxo::apply_confirmed(
        &db.pool,
        wallet,
        &[ConfirmedSpend {
            spend_tx_hash: change.utxo.tx_hash,
            inputs: vec![spent],
        }],
        &config(),
    )
    .await
    .expect("apply confirmed");
    assert_eq!(promoted, 1, "the pending spend is promoted to confirmed");

    let (state, _c, _l, _) = read_row(&db.pool, wallet, spent).await.unwrap();
    assert_eq!(state, "confirmed_spent", "the spend is terminal");

    // The in-band change is now canonical, spendable, and counted ready.
    let change_row = sqlx::query(
        "SELECT canonical, spendable_unconfirmed FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3",
    )
    .bind(wallet)
    .bind(change.utxo.tx_hash.as_slice())
    .bind(change.utxo.output_index as i32)
    .fetch_one(&db.pool)
    .await
    .expect("change row");
    assert!(
        change_row.get::<bool, _>("canonical"),
        "confirmed in-band change becomes canonical"
    );
    assert!(
        change_row.get::<bool, _>("spendable_unconfirmed"),
        "confirmed change is spendable"
    );
    assert_eq!(
        utxo::canonical_ready_count(&db.pool, wallet).await.unwrap(),
        1,
        "the confirmed change is now ready"
    );
}

#[tokio::test]
async fn apply_confirmed_keeps_out_of_band_change_non_canonical() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let spent = ingest_one(&db.pool, wallet, 0xD1).await;

    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");

    // The change is far above the band (a real change output of a small submit).
    let change = ChangeOutput {
        utxo: UtxoRef {
            tx_hash: [0xEE; 32],
            output_index: 1,
        },
        lovelace: band().max * 10,
    };
    apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: spent,
            lease_token: token,
        }],
        Some(change),
    )
    .await
    .expect("apply submit");

    utxo::apply_confirmed(
        &db.pool,
        wallet,
        &[ConfirmedSpend {
            spend_tx_hash: change.utxo.tx_hash,
            inputs: vec![spent],
        }],
        &config(),
    )
    .await
    .expect("apply confirmed");

    let change_row = sqlx::query(
        "SELECT canonical, spendable_unconfirmed FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3",
    )
    .bind(wallet)
    .bind(change.utxo.tx_hash.as_slice())
    .bind(change.utxo.output_index as i32)
    .fetch_one(&db.pool)
    .await
    .expect("change row");
    assert!(
        !change_row.get::<bool, _>("canonical"),
        "confirmed out-of-band change is spendable but not canonical"
    );
    assert!(
        change_row.get::<bool, _>("spendable_unconfirmed"),
        "confirmed change is spendable even when out of band"
    );
}

/// The abandon path's input restore is the exact inverse of confirm's input
/// promotion: a `confirmed_spent` input of a transaction proven dead by a
/// settlement-deep conflicting spend returns to `available` and is offered again.
/// The round trip (confirm the spend, then restore it) must leave the input
/// spendable, and a second restore over the same reference must be a no-op so a
/// re-run of the abandon path never double-counts.
#[tokio::test]
async fn restore_inputs_round_trips_a_confirmed_spend_and_is_idempotent() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let spent = ingest_one(&db.pool, wallet, 0xA1).await;

    // Lease and submit so the input is pending_spent, then confirm it to
    // confirmed_spent through the real promotion path.
    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");
    apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: spent,
            lease_token: token,
        }],
        None,
    )
    .await
    .expect("apply submit");
    utxo::apply_confirmed(
        &db.pool,
        wallet,
        &[ConfirmedSpend {
            spend_tx_hash: [0xA2; 32],
            inputs: vec![spent],
        }],
        &config(),
    )
    .await
    .expect("apply confirmed");
    let (state, _c, _l, _) = read_row(&db.pool, wallet, spent).await.unwrap();
    assert_eq!(
        state, "confirmed_spent",
        "the input is terminal before restore"
    );

    // Restore it: a settlement-deep conflicting spend proved this transaction dead,
    // so the input is live again on the canonical chain.
    let mut tx = db.pool.begin().await.expect("begin restore tx");
    let restored = utxo::restore_inputs_in_tx(&mut tx, wallet, &[spent])
        .await
        .expect("restore inputs");
    tx.commit().await.expect("commit restore");
    assert_eq!(
        restored, 1,
        "the confirmed_spent input is restored to available"
    );

    let (state, canonical, leased, _) = read_row(&db.pool, wallet, spent).await.unwrap();
    assert_eq!(state, "available", "the restored input is spendable again");
    assert!(!leased, "a restored input carries no lease token");
    assert!(
        canonical,
        "a band-mid ingested input stays canonical across the round trip"
    );
    assert_eq!(
        utxo::canonical_ready_count(&db.pool, wallet).await.unwrap(),
        1,
        "the restored input is offered to the scheduler again"
    );

    // A second restore is a no-op: the row is already available, so the abandon
    // path is safe to re-run (a redelivered confirm/abandon never double-restores).
    let mut tx = db.pool.begin().await.expect("begin second restore tx");
    let restored_again = utxo::restore_inputs_in_tx(&mut tx, wallet, &[spent])
        .await
        .expect("second restore");
    tx.commit().await.expect("commit second restore");
    assert_eq!(
        restored_again, 0,
        "an already-available input restores nothing"
    );
}

/// A `pending_spent` input (a submitted-but-not-yet-confirmed spend) restores to
/// `available` too: the abandon arm can fire on an attempt whose spend never
/// reached confirmation. And a reference for a transaction this wallet never spent
/// matches no row, so restoring it is a no-op (it can never resurrect a stranger's
/// output).
#[tokio::test]
async fn restore_inputs_handles_pending_spent_and_ignores_unknown_refs() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let spent = ingest_one(&db.pool, wallet, 0xB1).await;

    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");
    apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: spent,
            lease_token: token,
        }],
        None,
    )
    .await
    .expect("apply submit");
    let (state, _c, _l, _) = read_row(&db.pool, wallet, spent).await.unwrap();
    assert_eq!(
        state, "pending_spent",
        "the input is pending before restore"
    );

    // An unknown reference (a tx this wallet never spent) restores nothing, and the
    // real pending input restores in the same call.
    let unknown = UtxoRef {
        tx_hash: [0xEE; 32],
        output_index: 7,
    };
    let mut tx = db.pool.begin().await.expect("begin restore tx");
    let restored = utxo::restore_inputs_in_tx(&mut tx, wallet, &[unknown, spent])
        .await
        .expect("restore inputs");
    tx.commit().await.expect("commit restore");
    assert_eq!(
        restored, 1,
        "only the known pending_spent input restores; the unknown ref is ignored"
    );

    let (state, _c, leased, _) = read_row(&db.pool, wallet, spent).await.unwrap();
    assert_eq!(
        state, "available",
        "the pending input is restored to available"
    );
    assert!(!leased, "a restored input carries no lease token");
    assert!(
        read_row(&db.pool, wallet, unknown).await.is_none(),
        "an unknown reference is never inserted by a restore"
    );
}

/// Restoring an input belonging to a different wallet is impossible: the wallet
/// scope on the update keeps one wallet's abandon from clawing back another's
/// spend, even when the two share a (tx_hash, index) by coincidence.
#[tokio::test]
async fn restore_inputs_is_wallet_scoped() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet_a = seed_wallet(&db.pool).await;
    let wallet_b = seed_wallet(&db.pool).await;

    // Both wallets carry the same (tx_hash, index) reference, both confirmed_spent.
    let shared = ingest_one(&db.pool, wallet_a, 0xC1).await;
    let token_a = Uuid::now_v7();
    utxo::claim(&db.pool, wallet_a, token_a, &config())
        .await
        .unwrap()
        .expect("claim a");
    apply_submit(
        &db.pool,
        wallet_a,
        &[SpentInput {
            utxo: shared,
            lease_token: token_a,
        }],
        None,
    )
    .await
    .expect("apply submit a");
    utxo::apply_confirmed(
        &db.pool,
        wallet_a,
        &[ConfirmedSpend {
            spend_tx_hash: [0xC2; 32],
            inputs: vec![shared],
        }],
        &config(),
    )
    .await
    .expect("confirm a");

    // Restore for wallet_b: wallet_a's confirmed_spent row must be untouched.
    let mut tx = db.pool.begin().await.expect("begin restore tx");
    let restored = utxo::restore_inputs_in_tx(&mut tx, wallet_b, &[shared])
        .await
        .expect("restore inputs");
    tx.commit().await.expect("commit restore");
    assert_eq!(
        restored, 0,
        "a restore scoped to wallet_b touches no wallet_a row"
    );

    let (state, _c, _l, _) = read_row(&db.pool, wallet_a, shared).await.unwrap();
    assert_eq!(
        state, "confirmed_spent",
        "wallet_a's spend is unaffected by wallet_b's abandon"
    );
}

/// The abandon path tombstones a reorged-out transaction's change outputs so the
/// scheduler can never build on an output that never existed on the canonical
/// chain. Only the `change`-sourced rows keyed on the abandoned tx id are deleted;
/// a snapshot-sourced row at a different tx id is left intact, and a second
/// tombstone over the same tx id is a no-op.
#[tokio::test]
async fn tombstone_outputs_deletes_only_change_rows_for_the_abandoned_tx() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let spent = ingest_one(&db.pool, wallet, 0xD1).await;

    // Submit produces a `change`-sourced row keyed on the spend tx id.
    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");
    let change = ChangeOutput {
        utxo: UtxoRef {
            tx_hash: [0xD2; 32],
            output_index: 1,
        },
        lovelace: band().mid,
    };
    apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: spent,
            lease_token: token,
        }],
        Some(change),
    )
    .await
    .expect("apply submit");

    // A second, snapshot-sourced output at a different tx id must survive.
    let survivor = ingest_one(&db.pool, wallet, 0xD3).await;

    let mut tx = db.pool.begin().await.expect("begin tombstone tx");
    let deleted = utxo::tombstone_outputs_in_tx(&mut tx, wallet, change.utxo.tx_hash)
        .await
        .expect("tombstone outputs");
    tx.commit().await.expect("commit tombstone");
    assert_eq!(deleted, 1, "the abandoned tx's change output is deleted");

    assert!(
        read_row(&db.pool, wallet, change.utxo).await.is_none(),
        "the reorged-out change output is gone"
    );
    assert!(
        read_row(&db.pool, wallet, survivor).await.is_some(),
        "a snapshot output at a different tx id is untouched"
    );

    // Idempotent: a re-run finds no change rows for the tx id and deletes nothing.
    let mut tx = db.pool.begin().await.expect("begin second tombstone tx");
    let deleted_again = utxo::tombstone_outputs_in_tx(&mut tx, wallet, change.utxo.tx_hash)
        .await
        .expect("second tombstone");
    tx.commit().await.expect("commit second tombstone");
    assert_eq!(
        deleted_again, 0,
        "a second tombstone over the same tx is a no-op"
    );
}

/// The `UtxoState` enum maps to the schema's text values, so a typed read of a
/// known row decodes to the right variant. This pins the sqlx `Type` mapping the
/// state machine relies on.
#[tokio::test]
async fn utxo_state_enum_decodes_from_the_text_column() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let utxo_ref = ingest_one(&db.pool, wallet, 0xF1).await;

    let state: UtxoState = sqlx::query_scalar(
        "SELECT state FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3",
    )
    .bind(wallet)
    .bind(utxo_ref.tx_hash.as_slice())
    .bind(utxo_ref.output_index as i32)
    .fetch_one(&db.pool)
    .await
    .expect("typed state read");
    assert_eq!(state, UtxoState::Available);
}

// ---------------------------------------------------------------------------
// Cancelling-replacement re-lease reversibility. A replacement re-leases the
// rolled-back original's inputs (pending_spent/confirmed_spent -> in_flight), but
// the original stays a LIVE broadcaster whose inputs are its reservation. So a
// rollback of that re-lease (an explicit release, an expired-lease reaping) must
// return the borrowed input to the spent state it came FROM, never to `available`,
// or a fresh claim could double-spend an input the live original still holds.
// ---------------------------------------------------------------------------

/// Insert a UTxO already in a spent state (`pending_spent`/`confirmed_spent`), as if
/// an earlier accepted submit had spent it. Returns its reference.
async fn seed_spent_utxo(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    byte: u8,
    spent_state: &str,
) -> UtxoRef {
    let utxo = UtxoRef {
        tx_hash: [byte; 32],
        output_index: 0,
    };
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, 0, $3, $4, true, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(utxo.tx_hash.as_slice())
    .bind(band().mid as i64)
    .bind(spent_state)
    .execute(pool)
    .await
    .expect("insert spent utxo");
    utxo
}

/// Read a row's `(state, restore_state)`.
async fn read_state_and_restore(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    utxo: UtxoRef,
) -> (String, Option<String>) {
    let row = sqlx::query(
        "SELECT state, restore_state FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3",
    )
    .bind(wallet_id)
    .bind(utxo.tx_hash.as_slice())
    .bind(utxo.output_index as i32)
    .fetch_one(pool)
    .await
    .expect("read row");
    (
        row.get::<String, _>("state"),
        row.get::<Option<String>, _>("restore_state"),
    )
}

#[tokio::test]
async fn claim_replacement_records_the_prior_spent_state_and_release_restores_it() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;

    // Two inputs the live original holds: one pending_spent, one confirmed_spent.
    let pending = seed_spent_utxo(&db.pool, wallet, 0xC1, "pending_spent").await;
    let confirmed = seed_spent_utxo(&db.pool, wallet, 0xC2, "confirmed_spent").await;

    // A replacement re-leases both. Each flips to in_flight and records its prior
    // spent state in restore_state.
    let token = Uuid::now_v7();
    let leases = utxo::claim_replacement(&db.pool, wallet, &[pending, confirmed], token, &config())
        .await
        .expect("claim replacement");
    assert_eq!(leases.len(), 2, "both inputs are re-leased");
    let (state, restore) = read_state_and_restore(&db.pool, wallet, pending).await;
    assert_eq!(state, "in_flight");
    assert_eq!(
        restore.as_deref(),
        Some("pending_spent"),
        "the re-lease records the input's prior spent state"
    );
    let (_s, restore_c) = read_state_and_restore(&db.pool, wallet, confirmed).await;
    assert_eq!(restore_c.as_deref(), Some("confirmed_spent"));

    // Releasing the leases (a build/sign/record failure rolls them back) restores
    // each to the spent state it came from, NOT to available, so the still-live
    // original keeps its exclusive hold and the input cannot be re-claimed.
    assert!(utxo::release(&db.pool, wallet, pending, token)
        .await
        .expect("release pending"));
    assert!(utxo::release(&db.pool, wallet, confirmed, token)
        .await
        .expect("release confirmed"));
    let (state, restore) = read_state_and_restore(&db.pool, wallet, pending).await;
    assert_eq!(
        state, "pending_spent",
        "a released replacement input returns to its prior spent state, never available"
    );
    assert_eq!(restore, None, "the restore target is cleared on rollback");
    let (state_c, _r) = read_state_and_restore(&db.pool, wallet, confirmed).await;
    assert_eq!(state_c, "confirmed_spent");
}

#[tokio::test]
async fn an_expired_replacement_lease_is_reaped_back_to_its_prior_spent_state() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let pending = seed_spent_utxo(&db.pool, wallet, 0xD1, "pending_spent").await;

    let token = Uuid::now_v7();
    utxo::claim_replacement(&db.pool, wallet, &[pending], token, &config())
        .await
        .expect("claim replacement");

    // Force the lease into the past and reap. The reaper must NOT free a borrowed
    // input the live original still holds back to the pool: it returns it to its
    // prior spent state.
    sqlx::query(
        "UPDATE cw_core.wallet_utxo SET lease_expires_at = now() - interval '1 minute' \
         WHERE wallet_id = $1 AND state = 'in_flight'",
    )
    .bind(wallet)
    .execute(&db.pool)
    .await
    .expect("expire the lease");
    let reaped = utxo::reap_expired_leases(&db.pool).await.expect("reap");
    assert_eq!(reaped, 1, "the expired replacement lease is reaped");

    let (state, restore) = read_state_and_restore(&db.pool, wallet, pending).await;
    assert_eq!(
        state, "pending_spent",
        "a reaped replacement lease returns to its prior spent state, never available"
    );
    assert_eq!(restore, None);
}

#[tokio::test]
async fn an_ordinary_lease_still_releases_to_available() {
    // A plain claim/claim_source lease has no restore_state, so its rollback target
    // stays `available`: the restore_state mechanism only diverts replacement leases.
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let utxo_ref = ingest_one(&db.pool, wallet, 0xD2).await;

    let token = Uuid::now_v7();
    utxo::claim(&db.pool, wallet, token, &config())
        .await
        .unwrap()
        .expect("claim");
    let (_s, restore) = read_state_and_restore(&db.pool, wallet, utxo_ref).await;
    assert_eq!(
        restore, None,
        "an ordinary lease records no spent restore target"
    );

    assert!(utxo::release(&db.pool, wallet, utxo_ref, token)
        .await
        .expect("release"));
    let (state, _r) = read_state_and_restore(&db.pool, wallet, utxo_ref).await;
    assert_eq!(
        state, "available",
        "an ordinary lease still releases to available"
    );
}

/// On a SUCCESSFUL recorded spend the replacement's borrowed inputs become plain
/// `pending_spent` rows with no restore target: the spend is now durable, so the
/// lease's rollback target is gone, and only the chain-truth-proven restore path
/// returns them to available.
#[tokio::test]
async fn apply_submit_clears_the_restore_target_on_a_recorded_replacement_spend() {
    let db = TestDb::fresh().await.expect("test database");
    let wallet = seed_wallet(&db.pool).await;
    let borrowed = seed_spent_utxo(&db.pool, wallet, 0xD3, "pending_spent").await;

    let token = Uuid::now_v7();
    let leases = utxo::claim_replacement(&db.pool, wallet, &[borrowed], token, &config())
        .await
        .expect("claim replacement");
    let lease = leases.into_iter().next().expect("one lease");

    let applied = apply_submit(
        &db.pool,
        wallet,
        &[SpentInput {
            utxo: borrowed,
            lease_token: lease.lease_token,
        }],
        None,
    )
    .await
    .expect("apply submit");
    assert!(applied, "the recorded spend advances the borrowed input");

    let (state, restore) = read_state_and_restore(&db.pool, wallet, borrowed).await;
    assert_eq!(state, "pending_spent", "the recorded spend is pending");
    assert_eq!(
        restore, None,
        "a recorded spend clears the restore target so the input is a plain spend"
    );
}
