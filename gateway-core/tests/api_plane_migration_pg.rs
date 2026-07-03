//! Data-plane schema smoke test: the data-plane tables, the publish dedup column,
//! and the subject-event NOTIFY trigger behave against a real Postgres.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Proves the migration applies (TestDb::fresh runs the full MIGRATOR) and that
//! the objects it adds work as the data plane relies on: the api-key lookup
//! index, the per-account record-sha256 uniqueness, and the NOTIFY wake-hint on a
//! subject-event insert.

#![cfg(feature = "pg-tests")]

use gateway_core::events::append_subject_event;
use gateway_core::testsupport::TestDb;
use sqlx::postgres::PgListener;
use uuid::Uuid;

/// Seed an operator + account so the FK-bearing data-plane rows can be inserted.
async fn seed_account(pool: &sqlx::PgPool) -> Uuid {
    let operator_id = Uuid::now_v7();
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'test')")
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert operator");
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

#[tokio::test]
async fn migration_applies_and_seeds_the_core_scopes() {
    let db = TestDb::fresh().await.expect("fresh db");

    // The in-code catalogue and the migration seed must not drift apart: every
    // scope the engine's own routes enforce is a 'core' registry row. The
    // reserved billing:read scope gates no engine route (so it is not in
    // CORE_SCOPES) but is seeded for a vendor billing plane.
    let core_seeded: Vec<String> = sqlx::query_scalar(
        "SELECT scope FROM cw_core.api_scope WHERE registered_by = 'core' ORDER BY scope",
    )
    .fetch_all(&db.pool)
    .await
    .expect("read core scopes");

    for scope in gateway_core::api::middleware::scope::CORE_SCOPES {
        assert!(
            core_seeded.iter().any(|s| s == scope),
            "core scope {scope} is registered, got {core_seeded:?}"
        );
    }
    assert!(
        core_seeded.iter().any(|s| s == "billing:read"),
        "the reserved billing:read scope is registered, got {core_seeded:?}"
    );
}

#[tokio::test]
async fn api_key_lookup_index_supports_the_auth_query() {
    let db = TestDb::fresh().await.expect("fresh db");
    let account_id = seed_account(&db.pool).await;

    let lookup = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let hash = vec![9u8; 32];
    sqlx::query(
        "INSERT INTO cw_core.api_key \
           (id, account_id, prefix, key_lookup, key_hash_sha256, scopes, rate_limit_per_min) \
         VALUES ($1, $2, 'op_', $3, $4, ARRAY['poe:read'], 600)",
    )
    .bind(Uuid::now_v7())
    .bind(account_id)
    .bind(&lookup)
    .bind(&hash)
    .execute(&db.pool)
    .await
    .expect("insert api key");

    // The auth query: narrow by lookup prefix among live keys.
    let found: Option<(Vec<u8>, Vec<String>)> = sqlx::query_as(
        "SELECT key_hash_sha256, scopes FROM cw_core.api_key \
         WHERE key_lookup = $1 AND revoked_at IS NULL",
    )
    .bind(&lookup)
    .fetch_optional(&db.pool)
    .await
    .expect("auth query");
    let (stored_hash, scopes) = found.expect("the key is found by its lookup prefix");
    assert_eq!(stored_hash, hash);
    assert_eq!(scopes, vec!["poe:read".to_string()]);
}

#[tokio::test]
async fn poe_record_dedup_is_unique_per_account_and_hash() {
    let db = TestDb::fresh().await.expect("fresh db");
    let account_id = seed_account(&db.pool).await;
    let operator_id: Uuid =
        sqlx::query_scalar("SELECT operator_id FROM cw_core.account_detail WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&db.pool)
            .await
            .expect("operator id");

    let record_sha = vec![7u8; 32];

    let insert = |id: Uuid| {
        let pool = db.pool.clone();
        let record_sha = record_sha.clone();
        async move {
            sqlx::query(
                "INSERT INTO cw_core.poe_record \
                   (id, operator_id, account_id, record_bytes, status, record_sha256) \
                 VALUES ($1, $2, $3, $4, 'submitting', $5)",
            )
            .bind(id)
            .bind(operator_id)
            .bind(account_id)
            .bind(vec![0u8, 1, 2])
            .bind(&record_sha)
            .execute(&pool)
            .await
        }
    };

    insert(Uuid::now_v7()).await.expect("first publish inserts");
    let second = insert(Uuid::now_v7()).await;
    assert!(
        second.is_err(),
        "a second record with the same (account, record_sha256) violates the dedup uniqueness"
    );
}

#[tokio::test]
async fn subject_event_insert_fires_a_notify_wake_hint() {
    let db = TestDb::fresh().await.expect("fresh db");

    // LISTEN on the subject-event channel, then append an event and observe the
    // NOTIFY the trigger fires (the SSE wake-hint).
    let mut listener = PgListener::connect_with(&db.pool)
        .await
        .expect("connect listener");
    listener
        .listen(gateway_core::SUBJECT_EVENT_CHANNEL)
        .await
        .expect("listen");

    let subject_id = Uuid::now_v7().to_string();
    append_subject_event(
        &db.pool,
        "poe_record",
        &subject_id,
        "submitted",
        &serde_json::json!({ "status": "submitting" }),
    )
    .await
    .expect("append event");

    // The trigger fires on commit; the payload is `<kind>:<id>`.
    let notification = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
        .await
        .expect("a NOTIFY arrives within the timeout")
        .expect("notification");
    assert_eq!(
        notification.payload(),
        format!("poe_record:{subject_id}"),
        "the wake-hint carries the subject coordinates"
    );
}

#[tokio::test]
async fn storage_upload_dedups_by_account_and_content_hash() {
    let db = TestDb::fresh().await.expect("fresh db");
    let account_id = seed_account(&db.pool).await;
    let sha = vec![3u8; 32];

    let insert = |id: Uuid| {
        let pool = db.pool.clone();
        let sha = sha.clone();
        async move {
            sqlx::query(
                "INSERT INTO cw_core.storage_upload \
                   (id, account_id, sha256, bytes, uri, data_item_id, backend) \
                 VALUES ($1, $2, $3, 100, 'ar://x', 'x', 'turbo')",
            )
            .bind(id)
            .bind(account_id)
            .bind(&sha)
            .execute(&pool)
            .await
        }
    };

    insert(Uuid::now_v7()).await.expect("first upload inserts");
    let second = insert(Uuid::now_v7()).await;
    assert!(
        second.is_err(),
        "a second upload of identical bytes for the same account hits the dedup uniqueness"
    );
}
