//! Integration coverage for the account anchor, the append-only balance ledger,
//! and the publish-quote schema.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test stands up an isolated, freshly migrated database and asserts the
//! schema behaviour the ledger and quote modules rely on: the `balance_apply`
//! trigger materialises the balance and refuses an unauthorised overdraft, the
//! append-only triggers reject UPDATE/DELETE, the ledger idempotency indexes
//! collapse a retry and pin single-refund across the two refund kinds, the
//! account anchor/satellite are 1:1 with a hard-delete-blocking RESTRICT FK, and
//! the quote `poe_record_id` partial unique binds a record to one quote.

#![cfg(feature = "pg-tests")]

use gateway_core::testsupport::TestDb;
use uuid::Uuid;

/// Seed an operator and return its id.
async fn seed_operator(pool: &sqlx::PgPool) -> Uuid {
    let operator_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'op')")
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert operator");
    operator_id
}

/// Seed an account anchor and its satellite under an operator, returning the
/// account id.
async fn seed_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("insert account anchor");
    sqlx::query("INSERT INTO cw_core.account_detail (account_id, operator_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert account satellite");
    account_id
}

/// Insert one ledger entry directly in SQL, stamping `allows_overdraft` from the
/// registry the way the Rust module will, and return the result so a test can
/// assert success or a trigger rejection.
async fn insert_entry(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    kind: &str,
    amount_micros: i64,
    r#ref: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO cw_core.balance_ledger \
           (account_id, kind, amount_micros, ref, allows_overdraft) \
         SELECT $1, $2, $3, $4, r.allows_overdraft \
         FROM cw_core.ledger_kind_registry r WHERE r.kind = $2",
    )
    .bind(account_id)
    .bind(kind)
    .bind(amount_micros)
    .bind(r#ref)
    .execute(pool)
    .await
    .map(|_| ())
}

/// The materialised balance for an account, or 0 when no row exists.
async fn balance(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, Option<i64>>(
        "SELECT balance_micros FROM cw_core.balance WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .expect("read balance")
    .flatten()
    .unwrap_or(0)
}

/// The migration applies cleanly and seeds the engine's own ledger kinds, all
/// non-overdrawing.
///
/// The seeded catalogue also carries the four storage kinds
/// (hold/release/upload/refund), so this checks the three publish/refund kinds
/// are each present exactly once and non-overdrawing, rather than asserting
/// they are the only core rows.
#[tokio::test]
async fn migration_seeds_the_core_ledger_kinds() {
    let db = TestDb::fresh().await.expect("test database");

    for kind in ["poe_publish", "refund_rollback", "refund_user"] {
        let rows: Vec<bool> = sqlx::query_scalar(
            "SELECT allows_overdraft FROM cw_core.ledger_kind_registry \
             WHERE registered_by = 'core' AND kind = $1",
        )
        .bind(kind)
        .fetch_all(&db.pool)
        .await
        .expect("read seeded kind");
        assert_eq!(
            rows,
            vec![false],
            "{kind} is seeded exactly once and is non-overdrawing"
        );
    }
}

/// A credit then a debit materialise the running balance through the
/// `balance_apply` trigger, with no row until the first entry.
#[tokio::test]
async fn balance_apply_trigger_materialises_the_running_balance() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let acct = seed_account(&db.pool, op).await;

    // No ledger activity reads as a zero balance with no row.
    assert_eq!(balance(&db.pool, acct).await, 0);

    // A 5_000_000 credit (registered as a vendor top-up kind) lands the row.
    sqlx::query(
        "INSERT INTO cw_core.ledger_kind_registry (kind, allows_overdraft, registered_by) \
         VALUES ('topup', false, 'vendor')",
    )
    .execute(&db.pool)
    .await
    .expect("register a vendor credit kind");
    insert_entry(&db.pool, acct, "topup", 5_000_000, Some("topup-1"))
        .await
        .expect("credit");
    assert_eq!(balance(&db.pool, acct).await, 5_000_000);

    // A publish debit of 2_000_000 reduces it.
    insert_entry(&db.pool, acct, "poe_publish", -2_000_000, Some("rec-1"))
        .await
        .expect("debit");
    assert_eq!(balance(&db.pool, acct).await, 3_000_000);
}

/// A non-overdrawing kind cannot drive the balance negative: the `balance_apply`
/// trigger refuses it. A kind registered as overdraft-allowed (a vendor clawback)
/// is permitted to go negative, proving the rule reads the entry's stamped flag,
/// not a hardcoded kind list.
#[tokio::test]
async fn overdraft_is_refused_unless_the_entrys_flag_permits_it() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let acct = seed_account(&db.pool, op).await;

    // A bare publish debit with no funds overdraws -> refused.
    let refused = insert_entry(&db.pool, acct, "poe_publish", -1_000_000, Some("rec-x"))
        .await
        .expect_err("a non-overdrawing debit into a zero balance must be refused");
    assert_eq!(
        refused
            .as_database_error()
            .and_then(|d| d.code())
            .as_deref(),
        Some("23514"),
        "expected a check_violation from the overdraft guard, got {refused:?}"
    );
    assert_eq!(
        balance(&db.pool, acct).await,
        0,
        "the refused debit left no balance row change"
    );

    // A vendor clawback kind registered allows_overdraft=true may go negative.
    sqlx::query(
        "INSERT INTO cw_core.ledger_kind_registry (kind, allows_overdraft, registered_by) \
         VALUES ('clawback', true, 'vendor')",
    )
    .execute(&db.pool)
    .await
    .expect("register an overdrawing kind");
    insert_entry(&db.pool, acct, "clawback", -1_000_000, Some("cb-1"))
        .await
        .expect("an overdraft-allowed entry may drive the balance negative");
    assert_eq!(balance(&db.pool, acct).await, -1_000_000);
}

/// The ledger is append-only: UPDATE and DELETE on an entry are rejected by the
/// guard triggers.
#[tokio::test]
async fn ledger_is_append_only() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let acct = seed_account(&db.pool, op).await;

    sqlx::query(
        "INSERT INTO cw_core.ledger_kind_registry (kind, allows_overdraft, registered_by) \
         VALUES ('topup', false, 'vendor')",
    )
    .execute(&db.pool)
    .await
    .expect("register kind");
    insert_entry(&db.pool, acct, "topup", 1_000_000, Some("t-1"))
        .await
        .expect("seed one entry");

    let updated =
        sqlx::query("UPDATE cw_core.balance_ledger SET amount_micros = 9 WHERE ref = 't-1'")
            .execute(&db.pool)
            .await
            .expect_err("UPDATE on the ledger must be refused");
    assert!(
        updated.as_database_error().is_some(),
        "UPDATE is blocked by the append-only trigger, got {updated:?}"
    );

    let deleted = sqlx::query("DELETE FROM cw_core.balance_ledger WHERE ref = 't-1'")
        .execute(&db.pool)
        .await
        .expect_err("DELETE on the ledger must be refused");
    assert!(
        deleted.as_database_error().is_some(),
        "DELETE is blocked by the append-only trigger, got {deleted:?}"
    );

    // The entry is still there, unchanged.
    let amount: i64 =
        sqlx::query_scalar("SELECT amount_micros FROM cw_core.balance_ledger WHERE ref = 't-1'")
            .fetch_one(&db.pool)
            .await
            .expect("entry survives");
    assert_eq!(amount, 1_000_000);
}

/// The `(kind, ref)` partial unique index makes a retried publish debit collide,
/// so an idempotent insert path (`ON CONFLICT DO NOTHING`) charges once.
#[tokio::test]
async fn kind_ref_idempotency_index_collapses_a_retry() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let acct = seed_account(&db.pool, op).await;

    sqlx::query(
        "INSERT INTO cw_core.ledger_kind_registry (kind, allows_overdraft, registered_by) \
         VALUES ('topup', false, 'vendor')",
    )
    .execute(&db.pool)
    .await
    .expect("register a credit kind");
    insert_entry(&db.pool, acct, "topup", 10_000_000, Some("fund"))
        .await
        .expect("fund the account");

    // First publish debit for record R lands.
    insert_entry(&db.pool, acct, "poe_publish", -3_000_000, Some("R"))
        .await
        .expect("first debit");

    // A second debit for the SAME (kind, ref) collides on the partial unique.
    let dup = insert_entry(&db.pool, acct, "poe_publish", -3_000_000, Some("R"))
        .await
        .expect_err("a duplicate (kind, ref) must violate the partial unique");
    assert_eq!(
        dup.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("23505"),
        "expected a unique violation, got {dup:?}"
    );

    // The balance reflects exactly one debit.
    assert_eq!(balance(&db.pool, acct).await, 7_000_000);
}

/// The refund partial unique pins single-refund ACROSS both refund kinds: a
/// record already refunded by a rollback cannot also receive a user refund.
#[tokio::test]
async fn a_record_is_refunded_at_most_once_across_both_refund_kinds() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let acct = seed_account(&db.pool, op).await;

    // Rollback refund for record R.
    insert_entry(&db.pool, acct, "refund_rollback", 2_000_000, Some("R"))
        .await
        .expect("rollback refund");

    // A user refund for the SAME record is refused by the cross-kind refund index.
    let second = insert_entry(&db.pool, acct, "refund_user", 2_000_000, Some("R"))
        .await
        .expect_err("a second refund for the same record across kinds must be refused");
    assert_eq!(
        second.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("23505"),
        "expected a unique violation from the refund index, got {second:?}"
    );

    assert_eq!(
        balance(&db.pool, acct).await,
        2_000_000,
        "exactly one refund applied"
    );
}

/// The account anchor cannot be hard-deleted while its satellite references it
/// RESTRICT; soft-delete (stamping `deleted_at`) is the supported path.
#[tokio::test]
async fn account_anchor_hard_delete_is_blocked_soft_delete_works() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let acct = seed_account(&db.pool, op).await;

    let del = sqlx::query("DELETE FROM cw_api.account WHERE id = $1")
        .bind(acct)
        .execute(&db.pool)
        .await
        .expect_err("the satellite RESTRICT FK must block the anchor delete");
    // An explicit ON DELETE RESTRICT raises SQLSTATE 23001 (restrict_violation),
    // distinct from the 23503 (foreign_key_violation) a default NO ACTION check
    // would defer to statement end.
    assert_eq!(
        del.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("23001"),
        "expected a RESTRICT violation, got {del:?}"
    );

    let soft = sqlx::query("UPDATE cw_api.account SET deleted_at = now() WHERE id = $1")
        .bind(acct)
        .execute(&db.pool)
        .await
        .expect("soft-delete succeeds")
        .rows_affected();
    assert_eq!(soft, 1);
}

/// The quote `poe_record_id` partial unique binds a record to at most one quote:
/// two consumed quotes cannot both claim the same record.
#[tokio::test]
async fn a_record_binds_to_at_most_one_quote() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let acct = seed_account(&db.pool, op).await;

    let insert_quote = |poe_record_id: Option<Uuid>| {
        let pool = db.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO cw_core.publish_quote \
                   (id, account_id, expires_at, record_bytes, file_bytes_total, network_lovelace, \
                    network_usd_micros, storage_usd_micros, margin_pct, margin_source, \
                    service_usd_micros, total_usd_micros, fx_snapshot, status, poe_record_id) \
                 VALUES ($1, $2, now() + interval '15 minutes', 100, 0, 200000, \
                    50000, 0, 0.2500, 'fixed', 12500, 62500, '{}'::jsonb, 'consumed', $3)",
            )
            .bind(Uuid::now_v7())
            .bind(acct)
            .bind(poe_record_id)
            .execute(&pool)
            .await
        }
    };

    let record = Uuid::now_v7();
    insert_quote(Some(record))
        .await
        .expect("first quote binds the record");

    let dup = insert_quote(Some(record))
        .await
        .expect_err("a second quote for the same record must violate the partial unique");
    assert_eq!(
        dup.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("23505"),
        "expected a unique violation on poe_record_id, got {dup:?}"
    );

    // Two PENDING quotes with NULL poe_record_id coexist (the partial index only
    // covers non-NULL bindings).
    insert_quote(None)
        .await
        .expect("an unbound quote is allowed");
    insert_quote(None)
        .await
        .expect("a second unbound quote is allowed (NULL is not unique-constrained)");
}

/// A chain_records row requires its cw_api.records anchor: inserting the rich row
/// without the anchor is refused by the foreign key.
#[tokio::test]
async fn chain_record_requires_its_anchor() {
    let db = TestDb::fresh().await.expect("test database");
    let tx_hash = vec![0x77_u8; 32];

    let no_anchor = sqlx::query(
        "INSERT INTO cw_core.chain_records \
           (tx_hash, block_height, block_time, metadata_cbor, item_count, scheme) \
         VALUES ($1, 1, now(), $2, 1, 0)",
    )
    .bind(tx_hash.as_slice())
    .bind(vec![0xa1_u8])
    .execute(&db.pool)
    .await
    .expect_err("a rich row without its anchor must violate the foreign key");
    assert_eq!(
        no_anchor
            .as_database_error()
            .and_then(|d| d.code())
            .as_deref(),
        Some("23503"),
        "expected a foreign-key violation, got {no_anchor:?}"
    );

    // With the anchor present, the rich row inserts.
    sqlx::query("INSERT INTO cw_api.records (tx_hash) VALUES ($1)")
        .bind(tx_hash.as_slice())
        .execute(&db.pool)
        .await
        .expect("seed anchor");
    sqlx::query(
        "INSERT INTO cw_core.chain_records \
           (tx_hash, block_height, block_time, metadata_cbor, item_count, scheme) \
         VALUES ($1, 1, now(), $2, 1, 0)",
    )
    .bind(tx_hash.as_slice())
    .bind(vec![0xa1_u8])
    .execute(&db.pool)
    .await
    .expect("the rich row inserts once the anchor exists");
}
