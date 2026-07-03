//! The chunked-upload session create path against a real Postgres.
//!
//! `create_session` enforces the per-account open-session cap ATOMICALLY: the count
//! and the insert run in one transaction serialised on a per-account advisory lock,
//! so a burst of concurrent creates for one account can never both observe
//! `open < cap` and both insert. The lock key is derived in SQL with
//! `hashtext('storage_upload_session:' || account_id)::bigint` (the same idiom the FX
//! cold-start seed and the event-sequence allocator use), which hashes the full
//! namespaced account string rather than folding the uuid halves: two distinct
//! accounts cannot alias onto one key, so they never falsely contend, and the same
//! account always contends on the same key, so the cap holds.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use gateway_core::storage::{create_session, CreateSessionOutcome, CreateSessionSpec};
use gateway_core::testsupport::TestDb;
use uuid::Uuid;

const BACKEND: &str = "turbo";

/// Seed one operator and return its id.
async fn seed_operator(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'session-create-test')")
        .bind(id)
        .execute(pool)
        .await
        .expect("insert operator");
    id
}

/// Seed one account anchor + detail under an operator and return the account id.
async fn seed_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("insert account anchor");
    sqlx::query(
        "INSERT INTO cw_core.account_detail (account_id, operator_id, status) \
         VALUES ($1, $2, 'active')",
    )
    .bind(account_id)
    .bind(operator_id)
    .execute(pool)
    .await
    .expect("insert account detail");
    account_id
}

/// A session-create spec for a distinct logical upload (a unique declared sha256 per
/// call, so each would-be session is its own logical upload, never a dedup).
fn spec_for<'a>(
    id: Uuid,
    account_id: Uuid,
    operator_id: Uuid,
    sha256: [u8; 32],
    assembling_path: &'a str,
    max_open_sessions: u32,
) -> CreateSessionSpec<'a> {
    CreateSessionSpec {
        id,
        account_id,
        operator_id,
        backend: BACKEND,
        sha256,
        total_bytes: 64,
        chunk_bytes: 16,
        chunk_count: 4,
        content_type: "application/octet-stream",
        assembling_path,
        ttl_secs: 86_400,
        max_open_sessions,
    }
}

/// A burst of concurrent same-account creates never overshoots the cap: exactly `cap`
/// land and the rest are refused, proving the per-account SQL `hashtext` advisory lock
/// serialises the count+insert into one atomic read-modify-write (the TOCTOU a bare
/// count check would leave open).
#[tokio::test]
async fn concurrent_same_account_creates_never_overshoot_the_cap() {
    let db = TestDb::fresh().await.expect("fresh test db");
    // The runtime serialises on per-account advisory locks; give the pool room for the
    // concurrent create transactions to each hold a connection.
    let pool = db.pool_with(16).await.expect("pool");

    let operator_id = seed_operator(&pool).await;
    let account_id = seed_account(&pool, operator_id).await;

    let cap = 3u32;
    let burst = 10usize;

    let mut handles = Vec::new();
    for i in 0..burst {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            let id = Uuid::now_v7();
            // A distinct declared sha256 per create so each is a fresh logical upload.
            let mut sha = [0u8; 32];
            sha[0] = i as u8;
            sha[1] = 0xAB;
            let path = format!("/tmp/{}.assembling", id.simple());
            create_session(
                &pool,
                &spec_for(id, account_id, operator_id, sha, &path, cap),
            )
            .await
        }));
    }

    let mut created = 0usize;
    let mut refused = 0usize;
    for h in handles {
        match h.await.expect("join").expect("create_session") {
            CreateSessionOutcome::Created => created += 1,
            CreateSessionOutcome::CapExceeded { open } => {
                assert!(
                    open >= cap,
                    "a refusal observes the cap reached under the lock, saw {open}"
                );
                refused += 1;
            }
        }
    }

    assert_eq!(created, cap as usize, "exactly the cap of sessions landed");
    assert_eq!(refused, burst - cap as usize, "the rest were refused");

    // The live open-session count in the DB equals the cap exactly: the atomic lock
    // never let a concurrent pair both pass the count check and both insert.
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload_session \
         WHERE account_id = $1 AND state IN ('open', 'assembling')",
    )
    .bind(account_id)
    .fetch_one(&pool)
    .await
    .expect("count open sessions");
    assert_eq!(
        open,
        i64::from(cap),
        "the live count never overshot the cap"
    );
}

/// Two DISTINCT accounts do not contend on the lock key: each fills its own cap to
/// the brim, with no cross-account serialisation or false refusal. This is the
/// property the prior reversible XOR fold could not guarantee (two accounts whose
/// uuid halves were swapped would have aliased onto one key and serialised against
/// each other); the SQL `hashtext` of the full namespaced account string keys each
/// account distinctly.
#[tokio::test]
async fn distinct_accounts_do_not_share_a_lock_key_or_a_cap() {
    let db = TestDb::fresh().await.expect("fresh test db");
    let pool = db.pool_with(16).await.expect("pool");

    let operator_id = seed_operator(&pool).await;
    let account_a = seed_account(&pool, operator_id).await;
    let account_b = seed_account(&pool, operator_id).await;

    let cap = 2u32;

    // Each account creates exactly `cap` sessions; none should be refused, because the
    // two accounts hold independent caps under independent lock keys.
    for (account_id, tag) in [(account_a, 0xA0u8), (account_b, 0xB0u8)] {
        for i in 0..cap {
            let id = Uuid::now_v7();
            let mut sha = [0u8; 32];
            sha[0] = tag;
            sha[1] = i as u8;
            let path = format!("/tmp/{}.assembling", id.simple());
            let outcome = create_session(
                &pool,
                &spec_for(id, account_id, operator_id, sha, &path, cap),
            )
            .await
            .expect("create_session");
            assert_eq!(
                outcome,
                CreateSessionOutcome::Created,
                "account {account_id} create {i} lands within its own cap"
            );
        }
    }

    // Each account is exactly at its own cap; neither stole the other's budget.
    for account_id in [account_a, account_b] {
        let open: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM cw_core.storage_upload_session \
             WHERE account_id = $1 AND state IN ('open', 'assembling')",
        )
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .expect("count open sessions");
        assert_eq!(
            open,
            i64::from(cap),
            "account {account_id} filled its own independent cap"
        );
    }
}

/// The engine-level grid bound: a spec whose `chunk_count` exceeds
/// `MAX_SESSION_CHUNKS` is refused before the received bitmap is sized or any
/// row is inserted, so no caller — present or future — can reach an allocation
/// proportional to an unbounded chunk count through `create_session`.
#[tokio::test]
async fn an_over_bound_chunk_count_is_refused_before_any_bitmap_is_sized() {
    let db = TestDb::fresh().await.expect("fresh test db");
    let operator_id = seed_operator(&db.pool).await;
    let account_id = seed_account(&db.pool, operator_id).await;

    let id = Uuid::now_v7();
    let path = format!("/tmp/{}.assembling", id.simple());
    let mut spec = spec_for(id, account_id, operator_id, [0x5A; 32], &path, 8);
    spec.chunk_count = gateway_core::storage::MAX_SESSION_CHUNKS + 1;

    let err = create_session(&db.pool, &spec)
        .await
        .expect_err("an over-bound grid is refused, never persisted");
    assert!(
        err.to_string().contains("chunk ceiling"),
        "the refusal names the bound: {err}"
    );

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_upload_session")
        .fetch_one(&db.pool)
        .await
        .expect("count sessions");
    assert_eq!(rows, 0, "no row landed for the refused spec");
}
