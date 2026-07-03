//! End-to-end load and resilience coverage for the operator-wallet submit path.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! This is the integration proof that the wallet machinery holds its two binding
//! guarantees under concurrency, against a real Postgres and the real
//! Proof-of-Existence transaction builder:
//!
//!   - No double-spend within a wallet, and no cross-operator leakage, when many
//!     submit flows run at once. Every flow does the full sequence a production
//!     submit does: pick the least-loaded wallet, take the per-wallet session
//!     advisory lock, claim a canonical UTxO under a fencing token, build and
//!     sign a real transaction over it, simulate acceptance, apply the change
//!     locally, then release the lock. A side-effect ledger table records every
//!     claimed UTxO so a double-claim or a cross-operator claim is caught by an
//!     assertion, not merely hoped against.
//!
//!   - The quote equals the submit fee by construction. While the load runs,
//!     quote calls are interleaved; every flow's actual build fee is asserted to
//!     equal the canonical quote for its record size, with zero tolerance.
//!
//! A separate resilience test kills a flow while it holds a lease mid-window and
//! proves the lease reaper plus the advisory-lock release recover the UTxO so it
//! is claimable again, with no double-spend.

#![cfg(feature = "pg-tests")]

use std::collections::HashSet;
use std::sync::Arc;

use cardano_poe_tx::{build_poe_tx, BuildRequest, ProtocolParams, SigningKey, Utxo};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use gateway_core::wallet::keyring::derive_enterprise_address;
use gateway_core::wallet::operator::{create_operator, register_wallet, RegisterOutcome};
use gateway_core::wallet::pool::{self, lock_wallet};
use gateway_core::wallet::quote::quote_fee;
use gateway_core::wallet::submitter::{StubSubmitter, SubmitOutcome, Submitter};
use gateway_core::wallet::utxo::{self, ChangeOutput, ObservedUtxo, SpentInput, UtxoRef};
use uuid::Uuid;

/// Drive the production [`utxo::apply_submit_in_tx`] over its own transaction:
/// commit on success, roll back when a stale lease fences the apply out. The
/// production submit path runs `apply_submit_in_tx` as the last writes of the
/// record-before-broadcast transaction; this harness exercises the same fenced
/// DML in isolation so the flow's apply step asserts on real wallet rows.
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

/// The 4-8 ADA canonical band: both endpoints share a CBOR integer width.
fn band() -> LovelaceBand {
    LovelaceBand::new(4_000_000, 8_000_000, 6_000_000).expect("a single-width band")
}

/// A wallet config with a short lease so the resilience test's reaper does not
/// have to wait long. The lease covers build -> sign -> submit only.
fn config(lease: std::time::Duration) -> WalletConfig {
    WalletConfig::new(Network::Preprod, band(), lease, 4).expect("config")
}

/// Realistic post-Conway preprod fee parameters. The build fee and the quote
/// both meter against these; the test seeds them into the cache too so any path
/// that reads the cache (the replenisher) sees the same values.
fn params() -> ProtocolParams {
    ProtocolParams {
        min_fee_a: 44,
        min_fee_b: 155_381,
        coins_per_utxo_byte: 4_310,
        max_tx_size: 16_384,
    }
}

/// A wallet's signing key, derived address, and verification key, owned by the
/// test so each flow can build and sign a real transaction over the wallet.
struct TestWallet {
    wallet_id: Uuid,
    operator_id: Uuid,
    address: String,
    signing_key: Arc<SigningKey>,
    verification_key: [u8; 32],
}

/// Seed the side-effect ledger that records every UTxO a flow claims. A unique
/// index on the on-chain reference turns a double-claim into a hard insert
/// failure the flow surfaces, so a double-spend cannot pass silently.
async fn create_claim_ledger(pool: &sqlx::PgPool) {
    sqlx::query(
        "CREATE TABLE claim_ledger ( \
            operator_id uuid NOT NULL, \
            wallet_id   uuid NOT NULL, \
            tx_hash     bytea NOT NULL, \
            output_index integer NOT NULL, \
            UNIQUE (wallet_id, tx_hash, output_index) \
        )",
    )
    .execute(pool)
    .await
    .expect("create claim ledger");
}

/// Seed the preprod protocol parameters into the cache so cache-reading paths
/// agree with the in-memory params the builds use.
async fn seed_params(pool: &sqlx::PgPool) {
    let p = params();
    sqlx::query(
        "INSERT INTO cw_core.cardano_protocol_params \
           (network, epoch, min_fee_a, min_fee_b, coins_per_utxo_byte, max_tx_size, raw) \
         VALUES ('preprod', 500, $1, $2, $3, $4, $5)",
    )
    .bind(p.min_fee_a as i64)
    .bind(p.min_fee_b as i64)
    .bind(p.coins_per_utxo_byte as i64)
    .bind(p.max_tx_size as i64)
    .bind(serde_json::json!({ "epoch_no": 500 }))
    .execute(pool)
    .await
    .expect("seed params");
}

/// Create an operator with `wallet_count` active wallets, each with a real
/// signing key and derived preprod address, and seed each with `utxos_per_wallet`
/// canonical band-mid UTxOs. `seed` salts the key derivation so wallets across
/// operators are all distinct.
async fn seed_operator(
    pool: &sqlx::PgPool,
    label: &str,
    wallet_count: usize,
    utxos_per_wallet: usize,
    seed: u8,
    config: &WalletConfig,
) -> (Uuid, Vec<TestWallet>) {
    let operator_id = create_operator(pool, label).await.expect("create operator");
    let mut wallets = Vec::with_capacity(wallet_count);

    for w in 0..wallet_count {
        // A distinct 32-byte seed per wallet, salted by the operator seed so two
        // operators never derive the same address (which the UNIQUE constraint
        // would reject and which would also defeat cross-operator isolation).
        let mut key_seed = [0u8; 32];
        key_seed[0] = seed;
        key_seed[1] = w as u8;
        let signing_key = SigningKey::from_seed(key_seed);
        let verification_key = signing_key.verification_key();
        let address =
            derive_enterprise_address(&verification_key, config.network).expect("derive address");

        let registered = match register_wallet(
            pool,
            operator_id,
            &format!("{label}-w{w}"),
            &address,
            config.network,
        )
        .await
        .expect("register wallet")
        {
            RegisterOutcome::Registered(r) => r,
            RegisterOutcome::AddressTaken { .. } => {
                panic!("each seeded wallet has a distinct address, so registration must succeed")
            }
        };

        // Seed canonical band-mid available UTxOs. A distinct tx_hash per UTxO so
        // every claim targets a unique on-chain reference.
        let observed: Vec<ObservedUtxo> = (0..utxos_per_wallet)
            .map(|u| ObservedUtxo {
                utxo: UtxoRef {
                    tx_hash: utxo_hash(seed, w as u8, u as u16),
                    output_index: 0,
                },
                lovelace: config.band.mid,
                pure_ada: true,
            })
            .collect();
        let inserted = utxo::ingest_snapshot(pool, registered.wallet_id, &observed, config)
            .await
            .expect("ingest canonical utxos");
        assert_eq!(
            inserted as usize, utxos_per_wallet,
            "every seeded canonical UTxO was inserted"
        );

        wallets.push(TestWallet {
            wallet_id: registered.wallet_id,
            operator_id,
            address,
            signing_key: Arc::new(signing_key),
            verification_key,
        });
    }

    (operator_id, wallets)
}

/// A deterministic, collision-free 32-byte UTxO tx hash from a wallet's coords.
fn utxo_hash(seed: u8, wallet: u8, index: u16) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = seed;
    h[1] = wallet;
    h[2] = (index >> 8) as u8;
    h[3] = (index & 0xFF) as u8;
    h[4] = 0xEE;
    h
}

/// Build and sign a real Proof-of-Existence transaction spending one canonical
/// UTxO, returning the signed bytes, the transaction id, the fee, and the change
/// value. This is the real builder, not a stand-in.
fn build_and_sign(
    record_len: usize,
    leased: &UtxoRef,
    leased_lovelace: u64,
    wallet: &TestWallet,
    params: &ProtocolParams,
    config: &WalletConfig,
) -> (Vec<u8>, [u8; 32], u64, Option<u64>) {
    let request = BuildRequest {
        record_bytes: vec![0u8; record_len],
        metadata_label: cardano_poe_tx::POE_METADATA_LABEL,
        utxos: vec![Utxo {
            tx_hash: hex::encode(leased.tx_hash),
            index: leased.output_index,
            lovelace: leased_lovelace,
        }],
        must_spend: Vec::new(),
        protocol: *params,
        change_address: wallet.address.clone(),
        network_id: config.network.network_id(),
        payment_verification_key: wallet.verification_key,
        validity: None,
    };
    let built = build_poe_tx(&request).expect("build poe tx");
    let (signed, tx_hash) = built.sign(&wallet.signing_key);
    (signed, tx_hash, built.fee, built.change)
}

/// One submit flow's outcome, returned to the driver for aggregate assertions.
#[derive(Debug, Clone)]
struct FlowResult {
    /// The fee the real build charged. Asserted equal to the canonical quote.
    fee: u64,
    /// The record size this flow submitted, to look up the matching quote.
    record_len: usize,
}

/// The record sizes flows submit, spanning the metadata chunk boundary so the
/// fee is not a single constant.
const RECORD_SIZES: &[usize] = &[1, 64, 65, 512];

/// Run one full submit flow against an operator: pick the least-loaded wallet,
/// take its advisory lock, claim a canonical UTxO, build + sign a real tx,
/// simulate acceptance, apply the change locally, record the claim in the ledger,
/// bump the submission counter, and release the lock. Returns the flow's fee and
/// record size, or `None` if no wallet could be picked (every wallet drained).
async fn run_flow(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    wallets: &[TestWallet],
    submitter: &StubSubmitter,
    params: &ProtocolParams,
    config: &WalletConfig,
    record_len: usize,
) -> Option<FlowResult> {
    // Pick the least-loaded eligible wallet for this operator. Retry a bounded
    // number of times: a concurrent picker may have taken the row (FOR UPDATE OF
    // ... SKIP LOCKED returns nothing when every candidate wallet row is locked by
    // another picker's in-flight query) or claimed the last canonical UTxO in the
    // gap between pick and claim. Both are transient under contention, so a `None`
    // pick yields and retries rather than failing the flow; only a genuinely
    // exhausted band would keep returning `None` until the bound trips.
    for _ in 0..2_000 {
        let Some(candidate) = pool::pick_wallet(pool, operator_id, config.network)
            .await
            .expect("pick wallet")
        else {
            // All candidate wallet rows were momentarily SKIP LOCKED by other
            // pickers; back off and retry.
            tokio::task::yield_now().await;
            continue;
        };

        // The per-wallet session advisory lock, held across build -> sign ->
        // submit so two in-flight transactions on one wallet never select the
        // same UTxO. A flow on the same wallet queues here.
        let lock = lock_wallet(pool, candidate.wallet_id)
            .await
            .expect("lock wallet");

        let lease_token = Uuid::now_v7();
        let Some(lease) = utxo::claim(pool, candidate.wallet_id, lease_token, config)
            .await
            .expect("claim")
        else {
            // Another wallet still has UTxOs; release this lock and re-pick.
            lock.release().await.expect("release lock");
            continue;
        };

        // Resolve the signer for the picked wallet by its stable address.
        let wallet = wallets
            .iter()
            .find(|w| w.wallet_id == candidate.wallet_id)
            .expect("the picked wallet is one of ours");
        assert_eq!(
            wallet.operator_id, operator_id,
            "pick_wallet must never hand a wallet from another operator"
        );

        // Record the claim in the side-effect ledger. The UNIQUE index turns a
        // double-claim of the same UTxO into an insert failure, so a double-spend
        // is caught here rather than passing silently.
        let inserted = sqlx::query(
            "INSERT INTO claim_ledger (operator_id, wallet_id, tx_hash, output_index) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(operator_id)
        .bind(candidate.wallet_id)
        .bind(lease.utxo.tx_hash.as_slice())
        .bind(lease.utxo.output_index as i32)
        .execute(pool)
        .await;
        inserted.expect("a claimed UTxO must be unique in the ledger (no double-claim)");

        // Build and sign a real transaction over the leased UTxO.
        let (signed, tx_hash, fee, change) = build_and_sign(
            record_len,
            &lease.utxo,
            lease.lovelace,
            wallet,
            params,
            config,
        );

        // Simulate acceptance through the stub submitter.
        let outcome = submitter
            .submit(&signed, tx_hash)
            .await
            .expect("stub submit");
        let SubmitOutcome::Accepted { tx_hash: accepted } = outcome else {
            panic!("the stub always accepts");
        };

        // Apply the change locally in the same transaction: the input becomes
        // pending_spent and the expected change lands as a pending change row.
        let change_output = change.map(|value| ChangeOutput {
            utxo: UtxoRef {
                tx_hash: accepted,
                output_index: 0,
            },
            lovelace: value,
        });
        let applied = apply_submit(
            pool,
            candidate.wallet_id,
            &[SpentInput {
                utxo: lease.utxo,
                lease_token,
            }],
            change_output,
        )
        .await
        .expect("apply submit");
        assert!(applied, "the lease was still valid at apply time");

        pool::record_submission(pool, candidate.wallet_id)
            .await
            .expect("record submission");

        lock.release().await.expect("release lock");

        return Some(FlowResult { fee, record_len });
    }
    panic!("a flow exhausted its pick retries without claiming a UTxO");
}

/// The load test: two operators, three wallets each, with a heavy concurrent
/// burst of submit flows running against all six wallets at once. Asserts zero
/// double-claims, zero cross-operator leakage, full completion, end-state
/// conservation, and quote == submit fee for every flow.
///
/// Concurrency is bounded by a semaphore rather than launching all flows truly
/// simultaneously, because a flow waiting on a wallet's session advisory lock
/// holds a detached connection while it blocks; the production submit path is
/// likewise bounded by its connection pool. The bound is set well above the
/// wallet count, so many flows still contend on each wallet's lock at once,
/// which is exactly the path a double-claim would slip through.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_submit_load_holds_all_invariants() {
    let config = config(std::time::Duration::from_secs(120));
    let params = params();
    let db = TestDb::fresh().await.expect("test database");
    // The flows take per-wallet advisory locks (each on a detached connection)
    // plus pool connections for claim/apply; size the pool above the concurrency
    // bound with headroom for the locks and the per-flow query connections.
    let pool = db.pool_with(64).await.expect("sized pool");
    // At most this many flows are in flight at once. Kept below the pool size so
    // a flow blocked on a wallet's advisory lock (holding a detached connection)
    // can never exhaust the pool, while staying far above the six wallets so the
    // lock-contention path is exercised hard.
    let max_concurrent = 40;
    let gate = Arc::new(tokio::sync::Semaphore::new(max_concurrent));

    create_claim_ledger(&pool).await;
    seed_params(&pool).await;

    let wallets_per_operator = 3;
    let flows_per_wallet = 60;
    let flows_per_operator = wallets_per_operator * flows_per_wallet; // 180
                                                                      // Seed each wallet with a comfortable surplus of canonical UTxOs over the
                                                                      // flows the operator runs, so a flow never starves on a momentarily empty
                                                                      // band while still draining a large, known number of them. End-state
                                                                      // accounting then asserts exactly `flows_per_operator` were consumed and the
                                                                      // surplus remains canonical, which is a deterministic conservation check.
    let utxos_per_wallet = flows_per_wallet + 20; // 80; surplus = 60 per operator
    let seeded_per_operator = utxos_per_wallet * wallets_per_operator; // 240

    let (op_a, wallets_a) = seed_operator(
        &pool,
        "operator-a",
        wallets_per_operator,
        utxos_per_wallet,
        0x10,
        &config,
    )
    .await;
    let (op_b, wallets_b) = seed_operator(
        &pool,
        "operator-b",
        wallets_per_operator,
        utxos_per_wallet,
        0x20,
        &config,
    )
    .await;

    let wallets_a = Arc::new(wallets_a);
    let wallets_b = Arc::new(wallets_b);
    let submitter = Arc::new(StubSubmitter::new(config.network).expect("stub"));

    // Pre-compute the canonical quote per record size; every flow's actual fee
    // must equal the quote for the size it submitted. The quote reads no wallet
    // state, so one address stands in for all.
    let quote_address = wallets_a[0].address.clone();
    let quote_vk = wallets_a[0].verification_key;
    let quotes: std::collections::HashMap<usize, u64> = RECORD_SIZES
        .iter()
        .map(|&len| {
            let q = quote_fee(len, &params, &quote_address, quote_vk, &config)
                .expect("quote")
                .fee;
            (len, q)
        })
        .collect();

    // Launch every flow under the concurrency gate. Each operator runs
    // flows_per_operator flows; the two operators interleave on the same pool,
    // proving isolation. Each flow holds a semaphore permit for its lifetime, so
    // at most `max_concurrent` flows are racing for locks and connections at once.
    let mut handles = Vec::new();
    for op in 0..flows_per_operator {
        for (operator_id, wallets) in [(op_a, wallets_a.clone()), (op_b, wallets_b.clone())] {
            let pool = pool.clone();
            let submitter = submitter.clone();
            let gate = gate.clone();
            let record_len = RECORD_SIZES[op % RECORD_SIZES.len()];
            handles.push(tokio::spawn(async move {
                let _permit = gate.acquire().await.expect("semaphore permit");
                run_flow(
                    &pool,
                    operator_id,
                    &wallets,
                    &submitter,
                    &params,
                    &config,
                    record_len,
                )
                .await
            }));
        }
    }

    // Interleave quote calls during the load to prove a quote never reads or
    // disturbs wallet state and stays exact under churn.
    let mut quote_handles = Vec::new();
    for _ in 0..50 {
        let pool = pool.clone();
        let address = quote_address.clone();
        quote_handles.push(tokio::spawn(async move {
            // A quote touches no wallet rows; assert it equals the precomputed
            // value for a mid-range record even while submits churn the wallets.
            let q = quote_fee(64, &params, &address, quote_vk, &config)
                .expect("quote under churn")
                .fee;
            let _ = &pool; // the quote deliberately makes no DB call
            q
        }));
    }

    let mut completed = 0usize;
    let mut fees_ok = 0usize;
    for handle in handles {
        let result = handle.await.expect("flow task");
        let flow = result.expect("every flow completes with a wallet and a claim");
        let expected = quotes[&flow.record_len];
        assert_eq!(
            flow.fee, expected,
            "the real build fee must equal the canonical quote for record_len {} \
             (build {} != quote {})",
            flow.record_len, flow.fee, expected
        );
        fees_ok += 1;
        completed += 1;
    }
    let churn_quote = quotes[&64];
    for handle in quote_handles {
        let q = handle.await.expect("quote task");
        assert_eq!(
            q, churn_quote,
            "a quote under churn stays exactly the canonical fee"
        );
    }

    let total_flows = flows_per_operator * 2;
    assert_eq!(completed, total_flows, "every launched flow completed");
    assert_eq!(fees_ok, total_flows, "every flow's fee equalled its quote");

    // --- Side-effect ledger assertions: no double-claim, no cross-operator leak.

    // No UTxO appears twice (the UNIQUE index already guarantees this at insert
    // time; assert the row count matches the distinct count as a belt-and-braces
    // check, and that exactly one operator owns each claimed wallet's rows).
    let ledger_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM claim_ledger")
        .fetch_one(&pool)
        .await
        .expect("count ledger");
    let distinct_utxos: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT (wallet_id, tx_hash, output_index)) FROM claim_ledger",
    )
    .fetch_one(&pool)
    .await
    .expect("count distinct");
    assert_eq!(
        ledger_rows, distinct_utxos,
        "no UTxO was ever claimed by two flows"
    );
    assert_eq!(
        ledger_rows, total_flows as i64,
        "exactly one ledger row per flow"
    );

    // Cross-operator leakage: every wallet a flow claimed must belong to the
    // operator the flow ran for. Join the ledger to the wallet table and assert
    // no row's recorded operator_id disagrees with the wallet's true owner.
    let leaks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claim_ledger l \
         JOIN cw_core.operator_wallet w ON w.id = l.wallet_id \
         WHERE w.registrar_operator_id <> l.operator_id",
    )
    .fetch_one(&pool)
    .await
    .expect("count leaks");
    assert_eq!(leaks, 0, "no flow ever claimed another operator's wallet");

    // Each operator claimed exactly its own flow count.
    for (operator_id, expected) in [(op_a, flows_per_operator), (op_b, flows_per_operator)] {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM claim_ledger WHERE operator_id = $1")
            .bind(operator_id)
            .fetch_one(&pool)
            .await
            .expect("count per operator");
        assert_eq!(
            n, expected as i64,
            "operator {operator_id} claimed exactly its flow count"
        );
    }

    // --- End-state conservation across all wallets.

    // Every seeded canonical UTxO was either claimed (now pending_spent) and is
    // accounted for in the ledger, and a matching pending change row exists for
    // each accepted submit. Conservation: pending_spent inputs == ledger rows,
    // and each pending_spent input produced exactly one change row (the build for
    // these well-funded canonical UTxOs always returns change).
    let pending_spent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_utxo WHERE state = 'pending_spent' AND source = 'snapshot'",
    )
    .fetch_one(&pool)
    .await
    .expect("count pending spent");
    assert_eq!(
        pending_spent, total_flows as i64,
        "every claimed canonical input is now pending_spent"
    );

    let change_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.wallet_utxo WHERE source = 'change'")
            .fetch_one(&pool)
            .await
            .expect("count change");
    assert_eq!(
        change_rows, total_flows as i64,
        "every accepted submit recorded exactly one change row"
    );

    // No UTxO is left dangling in_flight: every lease was either applied or
    // released, so the wallets are in a clean steady state.
    let still_in_flight: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.wallet_utxo WHERE state = 'in_flight'")
            .fetch_one(&pool)
            .await
            .expect("count in flight");
    assert_eq!(still_in_flight, 0, "no UTxO is left leased after the load");

    // Canonical conservation per operator: the load consumed exactly
    // flows_per_operator canonical UTxOs, so the surplus the seeding left over is
    // exactly what remains canonical and available (the recorded change is
    // unconfirmed and therefore not canonical, so it does not count toward this).
    // This is the deterministic drain check: every claimed UTxO left the canonical
    // set and none of the change re-entered it.
    let expected_remaining = (seeded_per_operator - flows_per_operator) as i64;
    for wallets in [wallets_a.as_ref(), wallets_b.as_ref()] {
        let mut operator_remaining = 0i64;
        for w in wallets {
            operator_remaining += utxo::canonical_ready_count(&pool, w.wallet_id)
                .await
                .expect("ready count");
        }
        assert_eq!(
            operator_remaining, expected_remaining,
            "the load drained exactly flows_per_operator canonical UTxOs, leaving the surplus"
        );
    }

    // The submission counters sum to the total flow count: every accepted submit
    // bumped exactly one wallet's counter.
    // sum() over a bigint column yields NUMERIC in Postgres, so cast back to
    // bigint for a clean i64 decode.
    let total_submissions: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(submission_count_24h), 0)::bigint FROM cw_core.operator_wallet",
    )
    .fetch_one(&pool)
    .await
    .expect("sum submissions");
    assert_eq!(
        total_submissions, total_flows as i64,
        "the submission counters account for every accepted submit"
    );
}

/// Crash-resilience: a flow that takes a lease and then dies mid-window (before
/// applying or releasing) leaves the UTxO `in_flight` with an expired lease. The
/// lease reaper returns it to `available`, and a fresh flow can then claim and
/// spend it exactly once. No double-spend results.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crashed_flow_lease_is_reaped_and_the_utxo_is_reusable() {
    // A very short lease so the reaper can recover the UTxO without a long wait.
    let config = config(std::time::Duration::from_secs(1));
    let params = params();
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool_with(8).await.expect("sized pool");
    seed_params(&pool).await;
    create_claim_ledger(&pool).await;

    let (operator_id, wallets) = seed_operator(&pool, "operator", 1, 1, 0x30, &config).await;
    let wallet = &wallets[0];

    // A flow takes the lock and claims the only canonical UTxO, then "crashes":
    // we drop the lock guard and abandon the lease without applying or releasing.
    let crashed_token = Uuid::now_v7();
    let leased = {
        let lock = lock_wallet(&pool, wallet.wallet_id)
            .await
            .expect("lock wallet");
        let lease = utxo::claim(&pool, wallet.wallet_id, crashed_token, &config)
            .await
            .expect("claim")
            .expect("the canonical UTxO is claimable");
        // The crash: the lock guard drops here (its detached connection closes,
        // releasing the advisory lock), and the lease is never applied or
        // released. The durable row stays in_flight with a short expiry.
        drop(lock);
        lease.utxo
    };

    // The UTxO is in_flight and not claimable by a fresh flow yet.
    let blocked = utxo::claim(&pool, wallet.wallet_id, Uuid::now_v7(), &config)
        .await
        .expect("claim attempt");
    assert!(
        blocked.is_none(),
        "the abandoned lease still blocks a fresh claim until it is reaped"
    );

    // Wait for the lease to expire, then run the reaper. The advisory lock was
    // already released when the crashed flow's guard dropped, so the reaper can
    // safely reopen the row.
    wait_until_lease_expired(&pool, wallet.wallet_id, &leased).await;
    let reaped = utxo::reap_expired_leases(&pool).await.expect("reap");
    assert_eq!(
        reaped, 1,
        "the reaper recovered exactly the abandoned lease"
    );

    // A fresh flow now claims the recovered UTxO and spends it exactly once.
    let recovered_token = Uuid::now_v7();
    let lock = lock_wallet(&pool, wallet.wallet_id).await.expect("relock");
    let lease = utxo::claim(&pool, wallet.wallet_id, recovered_token, &config)
        .await
        .expect("reclaim")
        .expect("the reaped UTxO is claimable again");
    assert_eq!(
        lease.utxo, leased,
        "the recovered UTxO is the same one the crashed flow held"
    );

    let (signed, tx_hash, _fee, change) =
        build_and_sign(64, &lease.utxo, lease.lovelace, wallet, &params, &config);
    let submitter = StubSubmitter::new(config.network).expect("stub");
    let SubmitOutcome::Accepted { tx_hash: accepted } =
        submitter.submit(&signed, tx_hash).await.expect("submit")
    else {
        panic!("the stub accepts");
    };
    let change_output = change.map(|value| ChangeOutput {
        utxo: UtxoRef {
            tx_hash: accepted,
            output_index: 0,
        },
        lovelace: value,
    });

    // The crashed flow's stale token must NOT be able to apply now (fencing): the
    // row carries the recovered flow's token.
    let stale_applied = apply_submit(
        &pool,
        wallet.wallet_id,
        &[SpentInput {
            utxo: lease.utxo,
            lease_token: crashed_token,
        }],
        change_output,
    )
    .await
    .expect("stale apply attempt");
    assert!(
        !stale_applied,
        "the crashed flow's stale lease token can never apply the recovered UTxO"
    );

    // The live flow's token applies exactly once.
    let applied = apply_submit(
        &pool,
        wallet.wallet_id,
        &[SpentInput {
            utxo: lease.utxo,
            lease_token: recovered_token,
        }],
        change_output,
    )
    .await
    .expect("apply");
    assert!(applied, "the recovered flow applies its own lease");
    lock.release().await.expect("release lock");

    // The UTxO was spent exactly once: it is pending_spent and there is exactly
    // one matching change row. No double-spend.
    let state: String = sqlx::query_scalar(
        "SELECT state FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3",
    )
    .bind(wallet.wallet_id)
    .bind(leased.tx_hash.as_slice())
    .bind(leased.output_index as i32)
    .fetch_one(&pool)
    .await
    .expect("read state");
    assert_eq!(state, "pending_spent", "the recovered UTxO was spent once");

    let change_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.wallet_utxo WHERE source = 'change'")
            .fetch_one(&pool)
            .await
            .expect("count change");
    assert_eq!(
        change_count, 1,
        "exactly one spend produced exactly one change"
    );

    let _ = operator_id;
}

/// Poll until the wallet's UTxO lease has expired on the server clock, so the
/// reaper's `lease_expires_at < now()` predicate matches it. Bounds the wait so a
/// stuck clock fails the test rather than hanging.
async fn wait_until_lease_expired(pool: &sqlx::PgPool, wallet_id: Uuid, utxo: &UtxoRef) {
    for _ in 0..100 {
        let expired: Option<bool> = sqlx::query_scalar(
            "SELECT lease_expires_at < now() FROM cw_core.wallet_utxo \
             WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3 AND state = 'in_flight'",
        )
        .bind(wallet_id)
        .bind(utxo.tx_hash.as_slice())
        .bind(utxo.output_index as i32)
        .fetch_optional(pool)
        .await
        .expect("poll expiry");
        if expired == Some(true) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the lease never expired within the poll bound");
}

/// A small grooming check: the scheduler's quote-shape canonical fee equals the
/// real build fee for a freshly seeded canonical UTxO, the link between the load
/// test's per-flow assertion and the standalone exactness property.
#[tokio::test]
async fn a_seeded_canonical_utxo_builds_to_its_quote_fee() {
    let config = config(std::time::Duration::from_secs(120));
    let params = params();
    let db = TestDb::fresh().await.expect("test database");
    seed_params(&db.pool).await;
    let (_op, wallets) = seed_operator(&db.pool, "operator", 1, 1, 0x40, &config).await;
    let wallet = &wallets[0];

    let token = Uuid::now_v7();
    let lease = utxo::claim(&db.pool, wallet.wallet_id, token, &config)
        .await
        .expect("claim")
        .expect("the seeded canonical UTxO is claimable");

    let mut seen = HashSet::new();
    for &record_len in RECORD_SIZES {
        let quote = quote_fee(
            record_len,
            &params,
            &wallet.address,
            wallet.verification_key,
            &config,
        )
        .expect("quote")
        .fee;
        let (_signed, _hash, fee, _change) = build_and_sign(
            record_len,
            &lease.utxo,
            lease.lovelace,
            wallet,
            &params,
            &config,
        );
        assert_eq!(
            fee, quote,
            "a real build over a seeded canonical UTxO charges exactly its quote \
             for record_len {record_len}"
        );
        seen.insert(record_len);
    }
    assert_eq!(
        seen.len(),
        RECORD_SIZES.len(),
        "every record size was checked"
    );
}
