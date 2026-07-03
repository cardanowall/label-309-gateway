//! Integration coverage for the Rust ledger module: account provisioning, the
//! kind registry, and the append-only money journal.
//!
//! These exercise the module functions (`create_account`, `insert_ledger_entry`,
//! `register_kind`, `load_balance_micros`, ...) against a freshly migrated
//! database, asserting the behaviour the schema and the trigger guarantee end to
//! end: a race-safe materialised balance, the stamped-flag overdraft rule, the
//! idempotent insert path with same-row verification, single-refund across the
//! refund kinds, and the balance-change event the insert emits in its own
//! transaction.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;

use gateway_core::api::control::ledger_adjust::{
    apply_adjustment, clamp_debit, register_manual_adjustment_kind, AdjustmentOutcome,
    ClampedDebitResult,
};
use gateway_core::ledger::account::{create_account, soft_delete_account, ScopedChange};
use gateway_core::ledger::journal::{
    insert_clamped_debit, insert_ledger_entry, load_balance_micros, register_kind, seed_core_kinds,
    InsertOutcome, LedgerEntry, CORE_REGISTRANT,
};
use gateway_core::testsupport::TestDb;
use serde_json::json;
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

/// A ledger entry against `account` of `kind`/`amount`, optionally keyed on `ref`.
fn entry(account_id: Uuid, kind: &str, amount_micros: i64, r#ref: Option<&str>) -> LedgerEntry {
    LedgerEntry {
        account_id,
        kind: kind.to_string(),
        amount_micros,
        r#ref: r#ref.map(str::to_string),
        quote_id: None,
        metadata: json!({}),
        request_id: None,
    }
}

/// The SQLSTATE of a database error wrapped in the engine's error type, or `None`
/// for a non-database engine error.
fn sqlstate(err: &gateway_core::Error) -> Option<String> {
    match err {
        gateway_core::Error::Database(e) => {
            e.as_database_error().and_then(|d| d.code()).map(Into::into)
        }
        _ => None,
    }
}

/// Register a vendor credit kind once, so a test can fund an account.
async fn register_topup(pool: &sqlx::PgPool, allows_overdraft: bool) {
    register_kind(pool, "topup", allows_overdraft, "vendor")
        .await
        .expect("register topup kind");
}

/// `create_account` writes the anchor and its satellite, and `soft_delete_account`
/// stamps `deleted_at` idempotently while a hard delete stays impossible. The
/// soft-delete is operator-scoped: another operator cannot reach the account.
#[tokio::test]
async fn create_and_soft_delete_account() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;

    let account_id = create_account(&db.pool, op).await.expect("create account");

    // The anchor exists and the satellite is bound to the operator, active.
    let (status, anchor_exists): (String, bool) = sqlx::query_as(
        "SELECT d.status, EXISTS (SELECT 1 FROM cw_api.account a WHERE a.id = d.account_id) \
         FROM cw_core.account_detail d WHERE d.account_id = $1",
    )
    .bind(account_id)
    .fetch_one(&db.pool)
    .await
    .expect("read satellite");
    assert_eq!(status, "active");
    assert!(anchor_exists, "the anchor row must exist");

    // A hard delete is impossible (the satellite RESTRICT FK); soft-delete is the
    // only path and is idempotent.
    let hard = sqlx::query("DELETE FROM cw_api.account WHERE id = $1")
        .bind(account_id)
        .execute(&db.pool)
        .await
        .expect_err("hard delete must be blocked by the satellite RESTRICT FK");
    assert_eq!(
        hard.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("23001"),
        "expected a RESTRICT violation, got {hard:?}"
    );

    // A different operator cannot soft-delete this account: it is reported absent
    // (no cross-tenant mutation, no existence oracle).
    let other = seed_operator(&db.pool).await;
    assert_eq!(
        soft_delete_account(&db.pool, other, account_id)
            .await
            .expect("cross-operator soft-delete"),
        ScopedChange::NotFound,
        "an account of another operator is invisible to the soft-delete"
    );
    let still_live: bool =
        sqlx::query_scalar("SELECT deleted_at IS NULL FROM cw_api.account WHERE id = $1")
            .bind(account_id)
            .fetch_one(&db.pool)
            .await
            .expect("read deleted_at");
    assert!(
        still_live,
        "a cross-operator soft-delete must not stamp deleted_at"
    );

    assert_eq!(
        soft_delete_account(&db.pool, op, account_id)
            .await
            .expect("first soft-delete"),
        ScopedChange::Changed,
        "the first soft-delete performs the change"
    );
    assert_eq!(
        soft_delete_account(&db.pool, op, account_id)
            .await
            .expect("second soft-delete"),
        ScopedChange::Unchanged,
        "a second soft-delete is a no-op (deleted_at is preserved)"
    );
}

/// `seed_core_kinds` is the idempotent code-side reconcile of the engine's neutral
/// kinds: calling it twice reconciles its three kinds without duplicating a row,
/// and each lands non-overdrawing. The migration seeds additional core-registered
/// kinds (the storage hold/release/charge/refund triad), so the assertion checks
/// the reconciled kinds are present rather than that they are the only core rows.
#[tokio::test]
async fn seed_core_kinds_is_idempotent() {
    let db = TestDb::fresh().await.expect("test database");

    seed_core_kinds(&db.pool).await.expect("first seed");
    seed_core_kinds(&db.pool).await.expect("second seed");

    for kind in ["poe_publish", "refund_rollback", "refund_user"] {
        let rows: Vec<bool> = sqlx::query_scalar(
            "SELECT allows_overdraft FROM cw_core.ledger_kind_registry \
             WHERE registered_by = $1 AND kind = $2",
        )
        .bind(CORE_REGISTRANT)
        .bind(kind)
        .fetch_all(&db.pool)
        .await
        .expect("read core kind");
        assert_eq!(
            rows,
            vec![false],
            "{kind} is reconciled exactly once and is non-overdrawing"
        );
    }
}

/// An unregistered kind is rejected before any row is written.
#[tokio::test]
async fn an_unregistered_kind_is_rejected() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("create account");

    let err = insert_ledger_entry(&db.pool, &entry(account_id, "no_such_kind", 1, Some("k")))
        .await
        .expect_err("an unregistered kind must be refused");
    assert!(
        err.to_string().contains("not registered"),
        "expected a not-registered error, got {err:?}"
    );
}

/// A credit with no ref is refused at the engine layer: without a `(kind, ref)`
/// idempotency key, a redelivered credit (a webhook retry, a re-run job) would
/// silently apply twice. The guard is what keeps a future vendor credit kind
/// from double-applying; a keyed credit of the same kind still lands.
#[tokio::test]
async fn an_unkeyed_credit_is_refused_a_keyed_one_lands() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("create account");
    register_topup(&db.pool, false).await;

    let err = insert_ledger_entry(&db.pool, &entry(account_id, "topup", 5, None))
        .await
        .expect_err("an unkeyed credit must be refused");
    assert!(
        err.to_string().contains("must carry a ref"),
        "expected the unkeyed-credit refusal, got {err:?}"
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id)
            .await
            .expect("balance"),
        0,
        "the refused credit wrote nothing"
    );

    assert_eq!(
        insert_ledger_entry(&db.pool, &entry(account_id, "topup", 5, Some("t")))
            .await
            .expect("a keyed credit lands"),
        InsertOutcome::Inserted
    );
}

/// `insert_ledger_entry` stamps `allows_overdraft` from the registry, so the
/// trigger refuses a debit for a non-overdrawing kind into a zero balance but
/// permits one whose registered kind allows overdraft.
#[tokio::test]
async fn overdraft_follows_the_registered_flag_not_a_hardcoded_kind() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("create account");

    // A publish debit (allows_overdraft = false) into an empty balance is refused
    // by the trigger's overdraft guard (SQLSTATE 23514), and nothing is written:
    // the balance stays zero.
    let refused = insert_ledger_entry(&db.pool, &entry(account_id, "poe_publish", -1, Some("r")))
        .await
        .expect_err("a non-overdrawing debit into a zero balance must be refused");
    assert_eq!(
        sqlstate(&refused).as_deref(),
        Some("23514"),
        "expected a check_violation from the overdraft guard, got {refused:?}"
    );
    assert_eq!(load_balance_micros(&db.pool, account_id).await.unwrap(), 0);

    // A vendor kind registered allows_overdraft = true may drive the balance
    // negative, proving the rule is the entry's stamped flag, not a kind list.
    register_kind(&db.pool, "clawback", true, "vendor")
        .await
        .expect("register overdrawing kind");
    let outcome = insert_ledger_entry(&db.pool, &entry(account_id, "clawback", -5, Some("cb")))
        .await
        .expect("an overdraft-allowed entry may go negative");
    assert_eq!(outcome, InsertOutcome::Inserted);
    assert_eq!(load_balance_micros(&db.pool, account_id).await.unwrap(), -5);
}

/// 20 concurrent inserts against one account materialise the balance exactly: the
/// loop-and-catch upsert in `balance_apply` is race-safe, so the sum is the sum of
/// the deltas with no lost update.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_inserts_materialise_the_balance_exactly() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = Arc::new(db.pool_with(24).await.expect("wide pool"));
    let op = seed_operator(pool.as_ref()).await;
    let account_id = create_account(pool.as_ref(), op).await.expect("account");

    register_topup(pool.as_ref(), false).await;

    const N: i64 = 20;
    const PER: i64 = 1_000_000;

    let mut handles = Vec::new();
    for i in 0..N {
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            let r = format!("credit-{i}");
            insert_ledger_entry(pool.as_ref(), &entry(account_id, "topup", PER, Some(&r)))
                .await
                .expect("concurrent credit");
        }));
    }
    for h in handles {
        h.await.expect("task panicked");
    }

    assert_eq!(
        load_balance_micros(pool.as_ref(), account_id)
            .await
            .unwrap(),
        N * PER,
        "every concurrent credit must be summed into the materialised balance"
    );
    // Exactly N ledger rows landed (no duplicate from the upsert retry loop).
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = $1 AND kind = 'topup'",
    )
    .bind(account_id)
    .fetch_one(pool.as_ref())
    .await
    .expect("count rows");
    assert_eq!(rows, N);
}

/// A faithful retry of the same `(kind, ref)` entry is a verified-success no-op:
/// `insert_ledger_entry` returns `AlreadyApplied` and the balance is charged once.
#[tokio::test]
async fn a_retried_entry_is_a_verified_no_op() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    register_topup(&db.pool, false).await;

    insert_ledger_entry(&db.pool, &entry(account_id, "topup", 10, Some("fund")))
        .await
        .expect("fund");

    let first = insert_ledger_entry(&db.pool, &entry(account_id, "poe_publish", -3, Some("R")))
        .await
        .expect("first debit");
    assert_eq!(first, InsertOutcome::Inserted);

    // The identical entry again: idempotent no-op, no second charge.
    let retry = insert_ledger_entry(&db.pool, &entry(account_id, "poe_publish", -3, Some("R")))
        .await
        .expect("retry of the same entry");
    assert_eq!(retry, InsertOutcome::AlreadyApplied);

    assert_eq!(load_balance_micros(&db.pool, account_id).await.unwrap(), 7);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE kind = 'poe_publish' AND ref = 'R'",
    )
    .fetch_one(&db.pool)
    .await
    .expect("count");
    assert_eq!(count, 1, "exactly one debit row exists for the record");
}

/// Register the manual-adjustment kind (non-overdrawing), the kind the clamped
/// debit rides.
async fn register_adjust(pool: &sqlx::PgPool) {
    register_kind(pool, "manual_adjustment", false, "reference")
        .await
        .expect("register manual_adjustment kind");
}

/// A clamped debit takes the FULL amount when the balance covers it, the
/// AVAILABLE balance when it does not (never overdrawing), and NOTHING when the
/// balance is empty — and is idempotent on its ref, recovering the original
/// debited amount even after the balance has moved underneath.
#[tokio::test]
async fn clamped_debit_clamps_at_balance_and_is_idempotent() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    register_topup(&db.pool, false).await;
    register_adjust(&db.pool).await;

    insert_ledger_entry(&db.pool, &entry(account_id, "topup", 10, Some("fund")))
        .await
        .expect("fund $10");

    // Fully covered: debits the whole amount, balance 10 → 7.
    let covered = insert_clamped_debit(
        &db.pool,
        account_id,
        "manual_adjustment",
        3,
        "dp_a",
        "won",
        None,
    )
    .await
    .expect("covered clamp");
    assert_eq!(covered.debited_micros, 3);
    assert!(covered.newly_applied);
    assert_eq!(load_balance_micros(&db.pool, account_id).await.unwrap(), 7);

    // Over-balance: requests 12 against the remaining 7, debits exactly 7,
    // clamps the balance at 0 (NEVER overdraws, never refused).
    let clamped = insert_clamped_debit(
        &db.pool,
        account_id,
        "manual_adjustment",
        12,
        "dp_b",
        "lost",
        None,
    )
    .await
    .expect("clamped clamp");
    assert_eq!(clamped.debited_micros, 7);
    assert!(clamped.newly_applied);
    assert_eq!(load_balance_micros(&db.pool, account_id).await.unwrap(), 0);

    // Empty balance: debits nothing and writes no ledger row, but DOES memoize
    // the zero result in clamp_debit_log (so a later same-ref retry returns the
    // stored 0). This first call computed the result, so newly_applied is true.
    let empty = insert_clamped_debit(
        &db.pool,
        account_id,
        "manual_adjustment",
        5,
        "dp_c",
        "lost",
        None,
    )
    .await
    .expect("empty clamp");
    assert_eq!(empty.debited_micros, 0);
    assert!(empty.newly_applied);
    assert_eq!(load_balance_micros(&db.pool, account_id).await.unwrap(), 0);
    // No ledger row was written for the zero debit.
    let dp_c_ledger: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE kind = 'manual_adjustment' AND ref = 'dp_c'",
    )
    .fetch_one(&db.pool)
    .await
    .expect("count");
    assert_eq!(dp_c_ledger, 0, "a zero clamp writes no ledger row");

    // Idempotent recovery: replay dp_b AFTER the balance moved (a credit lands).
    // The original debited 7 is recovered from the stored row, NOT recomputed
    // against the new balance.
    insert_ledger_entry(&db.pool, &entry(account_id, "topup", 100, Some("refund")))
        .await
        .expect("credit lands");
    let replay = insert_clamped_debit(
        &db.pool,
        account_id,
        "manual_adjustment",
        12,
        "dp_b",
        "lost",
        None,
    )
    .await
    .expect("replay clamp");
    assert_eq!(
        replay.debited_micros, 7,
        "replay recovers the original debited amount"
    );
    assert!(!replay.newly_applied, "replay is an idempotent no-op");
    // The replay moved no money: balance is the funded 0 + 100 credit = 100,
    // proving the clamp leg dedup'd rather than debiting a second 7.
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        100
    );

    // Exactly one row exists for dp_b.
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE kind = 'manual_adjustment' AND ref = 'dp_b'",
    )
    .fetch_one(&db.pool)
    .await
    .expect("count");
    assert_eq!(count, 1);
}

/// A clamped debit refuses a non-positive amount and a ref already used by a
/// DIFFERENT account (a globally-unique clawback ref reused across accounts is a
/// caller bug, surfaced rather than honoured cross-account).
#[tokio::test]
async fn clamped_debit_rejects_bad_input_and_cross_account_ref() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_a = create_account(&db.pool, op).await.expect("account a");
    let account_b = create_account(&db.pool, op).await.expect("account b");
    register_topup(&db.pool, false).await;
    register_adjust(&db.pool).await;

    insert_ledger_entry(&db.pool, &entry(account_a, "topup", 10, Some("fund-a")))
        .await
        .expect("fund a");
    insert_ledger_entry(&db.pool, &entry(account_b, "topup", 10, Some("fund-b")))
        .await
        .expect("fund b");

    // Non-positive amount is rejected.
    let zero = insert_clamped_debit(
        &db.pool,
        account_a,
        "manual_adjustment",
        0,
        "z",
        "won",
        None,
    )
    .await;
    assert!(zero.is_err(), "a zero clamped debit must be rejected");

    // Establish a debit under ref `shared` for account A.
    insert_clamped_debit(
        &db.pool,
        account_a,
        "manual_adjustment",
        3,
        "shared",
        "won",
        None,
    )
    .await
    .expect("a's debit");

    // The same ref for account B is a caller bug: surfaced, never applied.
    let cross = insert_clamped_debit(
        &db.pool,
        account_b,
        "manual_adjustment",
        3,
        "shared",
        "won",
        None,
    )
    .await;
    assert!(
        cross.is_err(),
        "a ref already used by a different account must not be honoured"
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_b).await.unwrap(),
        10,
        "account B's balance is untouched by the cross-account ref attempt"
    );
}

/// A `(kind, ref)` collision whose existing row disagrees on amount is an ERROR,
/// not a silent success: it signals a caller bug rather than a benign retry.
#[tokio::test]
async fn a_mismatched_conflict_is_an_error() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    register_topup(&db.pool, false).await;
    insert_ledger_entry(&db.pool, &entry(account_id, "topup", 100, Some("fund")))
        .await
        .expect("fund");

    insert_ledger_entry(&db.pool, &entry(account_id, "poe_publish", -3, Some("R")))
        .await
        .expect("first debit");

    // Same (kind, ref), DIFFERENT amount -> error.
    let err = insert_ledger_entry(&db.pool, &entry(account_id, "poe_publish", -9, Some("R")))
        .await
        .expect_err("a mismatched amount on the same (kind, ref) must error");
    assert!(
        err.to_string().contains("different"),
        "expected a mismatch error, got {err:?}"
    );

    // Same (kind, ref), DIFFERENT account -> error.
    let other = create_account(&db.pool, op).await.expect("second account");
    let err = insert_ledger_entry(&db.pool, &entry(other, "poe_publish", -3, Some("R")))
        .await
        .expect_err("a mismatched account on the same (kind, ref) must error");
    assert!(
        err.to_string().contains("different"),
        "expected a mismatch error, got {err:?}"
    );

    // Only the original debit was ever applied.
    assert_eq!(load_balance_micros(&db.pool, account_id).await.unwrap(), 97);
}

/// A record is refunded at most once across BOTH refund kinds: a `refund_user`
/// for a record already refunded by `refund_rollback` (a DIFFERENT kind, same
/// ref) is an error, not an idempotent no-op (there is no same-(kind, ref) row to
/// verify against).
#[tokio::test]
async fn single_refund_across_both_refund_kinds_is_an_error() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");

    insert_ledger_entry(
        &db.pool,
        &entry(account_id, "refund_rollback", 5, Some("R")),
    )
    .await
    .expect("rollback refund");

    let err = insert_ledger_entry(&db.pool, &entry(account_id, "refund_user", 5, Some("R")))
        .await
        .expect_err("a second refund across kinds for the same record must error");
    assert!(
        err.to_string().contains("single-refund"),
        "expected the cross-refund error, got {err:?}"
    );

    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        5,
        "exactly one refund applied"
    );
}

/// Every successful insert appends a `balance.changed` subject event and its
/// outbox row in the SAME transaction; a rejected insert appends nothing.
#[tokio::test]
async fn an_insert_emits_a_balance_changed_event_and_outbox_row() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    register_topup(&db.pool, false).await;

    let req = Uuid::now_v7();
    let mut e = entry(account_id, "topup", 4_000_000, Some("t1"));
    e.request_id = Some(req);
    insert_ledger_entry(&db.pool, &e).await.expect("credit");

    // The subject event records the kind, amount, and request id under the
    // 'account' subject keyed by the account id.
    let (event_type, payload): (String, serde_json::Value) = sqlx::query_as(
        "SELECT event_type, payload FROM cw_core.subject_event \
         WHERE subject_kind = 'account' AND subject_id = $1",
    )
    .bind(account_id.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("read the balance-change event");
    assert_eq!(event_type, "balance.changed");
    assert_eq!(payload["kind"], json!("topup"));
    assert_eq!(payload["amount_micros"], json!(4_000_000));
    assert_eq!(payload["request_id"], json!(req.to_string()));

    // Its outbox row landed too.
    let outbox: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.delivery_outbox \
         WHERE subject_kind = 'account' AND subject_id = $1 AND event_type = 'balance.changed'",
    )
    .bind(account_id.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("count outbox");
    assert_eq!(outbox, 1);

    // A rejected debit (overdraft) leaves NO new event: the whole transaction,
    // including the event append, rolls back with the failed insert.
    let _ = insert_ledger_entry(
        &db.pool,
        &entry(account_id, "poe_publish", -99_000_000, Some("x")),
    )
    .await
    .expect_err("the overdraft is refused");
    let events_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'account' AND subject_id = $1",
    )
    .bind(account_id.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("count events");
    assert_eq!(
        events_after, 1,
        "a refused insert appends no balance-change event"
    );
}

/// `insert_ledger_entry` can ride the caller's transaction: when the caller rolls
/// back, neither the ledger row, the materialised balance, nor the event survive.
#[tokio::test]
async fn insert_rides_the_callers_transaction_and_rolls_back_with_it() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    register_topup(&db.pool, false).await;

    {
        let mut txn = db.pool.begin().await.expect("begin");
        insert_ledger_entry(&mut *txn, &entry(account_id, "topup", 7, Some("t")))
            .await
            .expect("insert inside the caller's transaction");
        txn.rollback().await.expect("rollback");
    }

    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        0,
        "the rolled-back credit left no balance"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.balance_ledger")
        .fetch_one(&db.pool)
        .await
        .expect("count rows");
    assert_eq!(rows, 0, "no ledger row survived the rollback");
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.subject_event")
        .fetch_one(&db.pool)
        .await
        .expect("count events");
    assert_eq!(events, 0, "no event survived the rollback");
}

/// A positive credit can never overdraw a balance, so the overdraft guard must
/// accept one regardless of the current balance sign, even for a credit whose
/// kind is classified non-overdraft. The original guard rejected any insert that
/// left the balance negative for a non-overdraft kind, sign-blind, so a positive
/// refund credit landing on an already-negative balance was wrongly refused. The
/// guard is now direction-aware: it fires only for a debit (`amount < 0`). The
/// sibling auto-refund credits (`refund_rollback`, `refund_user`,
/// `storage_hold_release`) and the positive arm of the dual-sign
/// `manual_adjustment` all share this path, so the same fix covers them.
#[tokio::test]
async fn a_positive_credit_is_accepted_on_a_negative_balance_regression() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("create account");

    // Drive the balance negative through the only door that can: an
    // overdraft-allowed debit. (Normal paths affordability-gate every debit, so
    // the live balance is always >= 0; this seeds the arrears state the guard is
    // meant to tolerate a credit against.)
    register_kind(&db.pool, "clawback", true, "vendor")
        .await
        .expect("register overdrawing kind");
    insert_ledger_entry(&db.pool, &entry(account_id, "clawback", -100, Some("cb")))
        .await
        .expect("an overdraft-allowed debit may go negative");
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        -100
    );

    // A positive refund_rollback credit (a non-overdraft core kind) is ACCEPTED
    // onto the negative balance: it raises the balance, so it can never overdraw,
    // and the direction-aware guard does not fire. The balance moves by the credit.
    let credited = insert_ledger_entry(
        &db.pool,
        &entry(account_id, "refund_rollback", 30, Some("rr")),
    )
    .await
    .expect("a positive refund credit on a negative balance must be accepted");
    assert_eq!(credited, InsertOutcome::Inserted);
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        -70,
        "the credit applied even though the balance stayed negative"
    );

    // The sibling auto-refund credit storage_hold_release (also non-overdraft)
    // behaves identically: a positive credit on the still-negative balance lands.
    let released = insert_ledger_entry(
        &db.pool,
        &entry(account_id, "storage_hold_release", 20, Some("shr")),
    )
    .await
    .expect("the sibling storage release credit must also be accepted while negative");
    assert_eq!(released, InsertOutcome::Inserted);
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        -50
    );

    // The guard is unchanged in the other direction: a non-overdraft DEBIT against
    // the negative balance is still refused (SQLSTATE 23514) and writes nothing.
    let refused = insert_ledger_entry(&db.pool, &entry(account_id, "poe_publish", -1, Some("p")))
        .await
        .expect_err("a non-overdrawing debit on a negative balance must still be refused");
    assert_eq!(
        sqlstate(&refused).as_deref(),
        Some("23514"),
        "expected a check_violation from the overdraft guard, got {refused:?}"
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        -50,
        "the refused debit left the balance untouched"
    );

    // ...while an overdraft-allowed debit on the negative balance is still allowed,
    // proving the negative arm remains driven purely by the stamped flag.
    insert_ledger_entry(&db.pool, &entry(account_id, "clawback", -5, Some("cb2")))
        .await
        .expect("an overdraft-allowed debit may still deepen a negative balance");
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        -55
    );
}

/// Two CONCURRENT clamped debits under the SAME ref return the identical debited
/// amount to both callers and move the balance exactly once. The `cw_core.balance`
/// row `FOR UPDATE` lock (the same row publish/storage debits lock) serialises
/// them: the loser blocks until the winner commits its clamp_debit_log row, then
/// reads it back and returns the memoized result instead of re-clamping.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_same_ref_clamp_returns_one_result_and_moves_once() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = Arc::new(db.pool_with(8).await.expect("wide pool"));
    let op = seed_operator(pool.as_ref()).await;
    let account_id = create_account(pool.as_ref(), op).await.expect("account");
    register_topup(pool.as_ref(), false).await;
    register_adjust(pool.as_ref()).await;

    insert_ledger_entry(pool.as_ref(), &entry(account_id, "topup", 10, Some("fund")))
        .await
        .expect("fund $10");

    // Two deliveries of the same clawback race. Each requests 4 against the $10.
    let mut handles = Vec::new();
    for _ in 0..2 {
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            insert_clamped_debit(
                pool.as_ref(),
                account_id,
                "manual_adjustment",
                4,
                "race",
                "won",
                None,
            )
            .await
            .expect("concurrent clamp")
        }));
    }
    let mut debited = Vec::new();
    let mut newly = 0;
    for h in handles {
        let out = h.await.expect("task panicked");
        debited.push(out.debited_micros);
        if out.newly_applied {
            newly += 1;
        }
    }

    // Both callers saw the SAME debited amount (4); exactly one computed it.
    assert_eq!(debited, vec![4, 4]);
    assert_eq!(
        newly, 1,
        "exactly one delivery computed the clamp; the other replayed"
    );
    // The balance moved exactly once: 10 - 4 = 6.
    assert_eq!(
        load_balance_micros(pool.as_ref(), account_id)
            .await
            .unwrap(),
        6
    );
    // Exactly one ledger row and one log row for the ref.
    let ledger_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE kind = 'manual_adjustment' AND ref = 'race'",
    )
    .fetch_one(pool.as_ref())
    .await
    .expect("ledger count");
    assert_eq!(ledger_rows, 1);
    let log_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.clamp_debit_log WHERE ref = 'race'")
            .fetch_one(pool.as_ref())
            .await
            .expect("log count");
    assert_eq!(log_rows, 1);
}

/// Two CONCURRENT same-ref clamps on a NEVER-FUNDED account (no cw_core.balance
/// row exists) return identical zero results and insert exactly one log row.
/// There is no balance row to lock, so the `clamp_debit_log (ref)` primary key
/// is the serialization point here: the racers both read no log row and both try
/// to insert, and the loser's unique-violation is resolved by re-reading the
/// committed row. (A never-funded account has nothing to debit anyway, so no
/// balance-overdraw race exists.)
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_same_ref_clamp_on_never_funded_account_inserts_one_log_row() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = Arc::new(db.pool_with(8).await.expect("wide pool"));
    let op = seed_operator(pool.as_ref()).await;
    // Created but NEVER funded: no balance row, no ledger activity.
    let account_id = create_account(pool.as_ref(), op).await.expect("account");
    register_adjust(pool.as_ref()).await;

    let mut handles = Vec::new();
    for _ in 0..2 {
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            insert_clamped_debit(
                pool.as_ref(),
                account_id,
                "manual_adjustment",
                5,
                "unfunded-race",
                "lost",
                None,
            )
            .await
            .expect("concurrent clamp on never-funded account")
        }));
    }
    let mut newly = 0;
    for h in handles {
        let out = h.await.expect("task panicked");
        assert_eq!(
            out.debited_micros, 0,
            "a never-funded account debits nothing"
        );
        if out.newly_applied {
            newly += 1;
        }
    }
    assert_eq!(newly, 1, "exactly one delivery recorded the zero result");

    // Exactly one log row; no ledger row (a zero clamp writes none); no balance row.
    let log_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.clamp_debit_log WHERE ref = 'unfunded-race'",
    )
    .fetch_one(pool.as_ref())
    .await
    .expect("log count");
    assert_eq!(log_rows, 1);
    let ledger_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE ref = 'unfunded-race'",
    )
    .fetch_one(pool.as_ref())
    .await
    .expect("ledger count");
    assert_eq!(ledger_rows, 0);
    assert_eq!(
        load_balance_micros(pool.as_ref(), account_id)
            .await
            .unwrap(),
        0
    );
}

/// A clamp racing a publish/storage-style balance debit on the SAME funded
/// account never trips the overdraft trigger and leaves a correct, non-negative
/// balance. The clamp locks the `cw_core.balance` row FOR UPDATE — the same row a
/// publish-quote consume / storage attempt locks — so the two serialise: whoever
/// acquires the lock second sees the other's committed debit and clamps against
/// the post-debit balance, instead of computing a stale `debited` that would
/// overdraw. We drive many concurrent pairs to exercise both orderings.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn clamp_serialises_against_a_concurrent_balance_debit() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = Arc::new(db.pool_with(16).await.expect("wide pool"));
    let op = seed_operator(pool.as_ref()).await;
    register_topup(pool.as_ref(), false).await;
    register_adjust(pool.as_ref()).await;

    // Each iteration: a fresh account funded with exactly $6, then a $4 clamp and
    // a $5 publish-style debit race. Whichever serialises first takes its full
    // amount; the second clamps/affords against the remainder. The clamp can
    // never overdraw (it clamps), and the publish debit is affordability-gated
    // exactly as consume_quote does, so neither trips the trigger.
    for i in 0..16 {
        let account_id = create_account(pool.as_ref(), op).await.expect("account");
        insert_ledger_entry(
            pool.as_ref(),
            &entry(account_id, "topup", 6, Some(&format!("fund-{i}"))),
        )
        .await
        .expect("fund $6");

        let clamp_pool = Arc::clone(&pool);
        let clamp_ref = format!("clamp-{i}");
        let clamp = tokio::spawn(async move {
            insert_clamped_debit(
                clamp_pool.as_ref(),
                account_id,
                "manual_adjustment",
                4,
                &clamp_ref,
                "won",
                None,
            )
            .await
            .expect("clamp must never fail with a spurious trigger refusal")
        });

        // A publish-style debit: lock the balance row FOR UPDATE, affordability-
        // gate, then insert the negative entry — exactly consume_quote's discipline.
        let debit_pool = Arc::clone(&pool);
        let debit_ref = format!("publish-{i}");
        let debit = tokio::spawn(async move {
            let mut txn = debit_pool.begin().await.expect("begin");
            let balance: i64 = sqlx::query_scalar(
                "SELECT balance_micros FROM cw_core.balance WHERE account_id = $1 FOR UPDATE",
            )
            .bind(account_id)
            .fetch_optional(&mut *txn)
            .await
            .expect("balance read")
            .unwrap_or(0);
            // Affordable only if $5 fits; otherwise skip (the clamp took enough
            // that a $5 publish can't afford), mirroring consume_quote's reject.
            let afforded = balance >= 5;
            if afforded {
                insert_ledger_entry(
                    &mut *txn,
                    &entry(account_id, "poe_publish", -5, Some(&debit_ref)),
                )
                .await
                .expect("publish debit must not overdraw under the lock");
            }
            txn.commit().await.expect("commit");
            afforded
        });

        let clamp_out = clamp.await.expect("clamp task");
        let debit_afforded = debit.await.expect("debit task");

        // Final balance is exact and non-negative: $6 minus the clamp's debited
        // minus the publish debit (when it afforded).
        let expected = 6 - clamp_out.debited_micros - if debit_afforded { 5 } else { 0 };
        assert!(
            expected >= 0,
            "iteration {i}: balance went negative ({expected})"
        );
        assert_eq!(
            load_balance_micros(pool.as_ref(), account_id)
                .await
                .unwrap(),
            expected,
            "iteration {i}: clamp debited {} + publish {} must match the $6 start",
            clamp_out.debited_micros,
            if debit_afforded { 5 } else { 0 },
        );
        // At least one of the two moved money, and they never both took more than
        // the $6 available (the lock made them serialise, not double-spend).
        assert!(
            clamp_out.debited_micros + if debit_afforded { 5 } else { 0 } <= 6,
            "iteration {i}: the two debits together exceeded the funded balance",
        );
    }
}

/// A zero-balance clamp memoizes its 0 result, so a same-ref retry AFTER a credit
/// lands returns the stored 0 and does NOT re-debit the now-funded balance. This
/// is the bug the dedicated log table fixes: without it the zero result left no
/// row and the retry would clamp against the new balance.
#[tokio::test]
async fn zero_clamp_then_credit_then_retry_does_not_redebit() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    register_topup(&db.pool, false).await;
    register_adjust(&db.pool).await;

    // No funds yet: the clamp debits nothing and memoizes 0.
    let first = insert_clamped_debit(
        &db.pool,
        account_id,
        "manual_adjustment",
        5,
        "rz",
        "lost",
        None,
    )
    .await
    .expect("zero clamp");
    assert_eq!(first.debited_micros, 0);
    assert!(
        first.newly_applied,
        "the first call computed (and stored) the zero result"
    );

    // A credit lands AFTER the zero clamp.
    insert_ledger_entry(
        &db.pool,
        &entry(account_id, "topup", 100, Some("late-credit")),
    )
    .await
    .expect("credit lands");
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        100
    );

    // Same-ref retry: returns the stored 0, debits nothing, leaves the $100.
    let retry = insert_clamped_debit(
        &db.pool,
        account_id,
        "manual_adjustment",
        5,
        "rz",
        "lost",
        None,
    )
    .await
    .expect("zero clamp replay");
    assert_eq!(
        retry.debited_micros, 0,
        "the retry returns the memoized zero, not a fresh clamp"
    );
    assert!(!retry.newly_applied);
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        100,
        "the retry must not re-debit the now-funded balance"
    );
}

/// A replay under the same ref carrying a DIFFERENT requested amount is a hard
/// invariant violation. Stripe dispute and refund amounts are immutable over the
/// object lifecycle, so the clamp ref (derived from that id) can only ever be
/// replayed with the SAME amount; a mismatch is a must-never-happen and is
/// rejected rather than silently resolved (which would under- or over-charge).
/// The committed clamp stands; the divergent replay moves nothing.
#[tokio::test]
async fn clamp_replay_with_different_requested_amount_is_rejected() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    register_topup(&db.pool, false).await;
    register_adjust(&db.pool).await;

    insert_ledger_entry(&db.pool, &entry(account_id, "topup", 10, Some("fund")))
        .await
        .expect("fund $10");

    let first = insert_clamped_debit(
        &db.pool,
        account_id,
        "manual_adjustment",
        4,
        "amt",
        "won",
        None,
    )
    .await
    .expect("first clamp");
    assert_eq!(first.debited_micros, 4);
    assert!(first.newly_applied);

    // Same ref, DIFFERENT requested amount: rejected (must-never-happen).
    let revised = insert_clamped_debit(
        &db.pool,
        account_id,
        "manual_adjustment",
        5,
        "amt",
        "won",
        None,
    )
    .await;
    assert!(
        revised.is_err(),
        "a replay with a different requested amount under the same ref must be rejected"
    );
    // The committed clamp stands; the divergent replay moved no money.
    assert_eq!(load_balance_micros(&db.pool, account_id).await.unwrap(), 6);

    // The same SAME amount under the same ref is the normal idempotent replay.
    let same = insert_clamped_debit(
        &db.pool,
        account_id,
        "manual_adjustment",
        4,
        "amt",
        "won",
        None,
    )
    .await
    .expect("same-amount replay is idempotent");
    assert_eq!(same.debited_micros, 4);
    assert!(!same.newly_applied);
    assert_eq!(load_balance_micros(&db.pool, account_id).await.unwrap(), 6);

    // A cross-ACCOUNT reuse remains a hard error (a genuine invariant violation).
    let other = create_account(&db.pool, op).await.expect("other account");
    insert_ledger_entry(&db.pool, &entry(other, "topup", 10, Some("fund-other")))
        .await
        .expect("fund other");
    let cross =
        insert_clamped_debit(&db.pool, other, "manual_adjustment", 4, "amt", "won", None).await;
    assert!(
        cross.is_err(),
        "the same ref under a different account is still rejected"
    );
}

// ---------------------------------------------------------------------------
// Operator-scoped idempotency: the operator-supplied ref is the engine's hard
// isolation boundary. These exercise `apply_adjustment` and `clamp_debit` (the
// operator-scoped layer over the journal) directly, asserting the stored rows.
// ---------------------------------------------------------------------------

/// A permissive adjustment/clamp cap so amount validation never gets in the way.
const TEST_CAP: i64 = 1_000_000_000;

/// Count the manual-adjustment ledger rows on an account.
async fn adjust_ledger_count(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger \
         WHERE account_id = $1 AND kind = 'manual_adjustment'",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("count manual_adjustment rows")
}

/// Read the single stored ref of an account's one manual-adjustment ledger row.
async fn the_adjust_ref(pool: &sqlx::PgPool, account_id: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT ref FROM cw_core.balance_ledger \
         WHERE account_id = $1 AND kind = 'manual_adjustment'",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("read the manual_adjustment ref")
}

/// Two DIFFERENT operators each post a ledger-adjustment with the SAME supplied
/// `ref` against their OWN accounts: BOTH succeed independently, producing two
/// distinct stored rows under disjoint operator-scoped keys, with NO collision.
/// Without the operator-scoping, operator A's later call would collide with B's
/// global `(manual_adjustment, "shared-ref")` row on a different account and the
/// journal would hard-error — the cross-operator denial-of-service this fixes.
#[tokio::test]
async fn two_operators_share_a_supplied_adjustment_ref_without_colliding() {
    let db = TestDb::fresh().await.expect("test database");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");

    let op_a = seed_operator(&db.pool).await;
    let op_b = seed_operator(&db.pool).await;
    let acct_a = create_account(&db.pool, op_a).await.expect("account a");
    let acct_b = create_account(&db.pool, op_b).await.expect("account b");

    // Operator B posts first under the shared ref (B occupies the global key in the
    // unfixed world), then operator A posts under the SAME supplied ref.
    let b = apply_adjustment(
        &db.pool,
        op_b,
        acct_b,
        5_000_000,
        "grant b",
        TEST_CAP,
        Some("shared-ref"),
        None,
    )
    .await
    .expect("operator b adjustment");
    assert_eq!(b, AdjustmentOutcome::Applied(InsertOutcome::Inserted));

    let a = apply_adjustment(
        &db.pool,
        op_a,
        acct_a,
        7_000_000,
        "grant a",
        TEST_CAP,
        Some("shared-ref"),
        None,
    )
    .await
    .expect("operator a adjustment must not collide with b's");
    assert_eq!(
        a,
        AdjustmentOutcome::Applied(InsertOutcome::Inserted),
        "A's same-ref adjustment lands as a fresh row, not a collision error"
    );

    // Both balances moved exactly once; two distinct rows exist under disjoint keys.
    assert_eq!(
        load_balance_micros(&db.pool, acct_a).await.unwrap(),
        7_000_000
    );
    assert_eq!(
        load_balance_micros(&db.pool, acct_b).await.unwrap(),
        5_000_000
    );
    assert_eq!(adjust_ledger_count(&db.pool, acct_a).await, 1);
    assert_eq!(adjust_ledger_count(&db.pool, acct_b).await, 1);
    // The stored refs are operator-scoped and distinct.
    assert_eq!(
        the_adjust_ref(&db.pool, acct_a).await,
        format!("op:{op_a}:shared-ref")
    );
    assert_eq!(
        the_adjust_ref(&db.pool, acct_b).await,
        format!("op:{op_b}:shared-ref")
    );
}

/// Two DIFFERENT operators each post a clamp-debit with the SAME supplied `ref`
/// against their OWN funded accounts: BOTH succeed, each debiting its own balance,
/// with two distinct `clamp_debit_log` rows under disjoint operator-scoped keys.
/// Without the scoping, A's clamp would hit B's global `clamp_debit_log (ref)`
/// row recorded for a different account and hard-error.
#[tokio::test]
async fn two_operators_share_a_supplied_clamp_ref_without_colliding() {
    let db = TestDb::fresh().await.expect("test database");
    register_topup(&db.pool, false).await;
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");

    let op_a = seed_operator(&db.pool).await;
    let op_b = seed_operator(&db.pool).await;
    let acct_a = create_account(&db.pool, op_a).await.expect("account a");
    let acct_b = create_account(&db.pool, op_b).await.expect("account b");
    insert_ledger_entry(&db.pool, &entry(acct_a, "topup", 10, Some("fund-a")))
        .await
        .expect("fund a");
    insert_ledger_entry(&db.pool, &entry(acct_b, "topup", 10, Some("fund-b")))
        .await
        .expect("fund b");

    // B claws back 4 under the shared ref, then A claws back 3 under the SAME ref.
    let b = clamp_debit(
        &db.pool,
        op_b,
        acct_b,
        4,
        "dispute",
        TEST_CAP,
        "shared-ref",
        None,
    )
    .await
    .expect("operator b clamp");
    let ClampedDebitResult::Applied(b) = b else {
        panic!("operator b clamp must apply to its own account");
    };
    assert_eq!(b.debited_micros, 4);
    assert!(b.newly_applied);

    let a = clamp_debit(
        &db.pool,
        op_a,
        acct_a,
        3,
        "dispute",
        TEST_CAP,
        "shared-ref",
        None,
    )
    .await
    .expect("operator a clamp must not collide with b's");
    let ClampedDebitResult::Applied(a) = a else {
        panic!("operator a clamp must apply to its own account");
    };
    assert_eq!(a.debited_micros, 3);
    assert!(
        a.newly_applied,
        "A's same-ref clamp computes its own result, not a collision error"
    );

    // Each balance moved by its own debit; two distinct log rows exist.
    assert_eq!(load_balance_micros(&db.pool, acct_a).await.unwrap(), 7);
    assert_eq!(load_balance_micros(&db.pool, acct_b).await.unwrap(), 6);
    let a_log: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.clamp_debit_log WHERE ref = $1 AND account_id = $2",
    )
    .bind(format!("op:{op_a}:shared-ref"))
    .bind(acct_a)
    .fetch_one(&db.pool)
    .await
    .expect("a log count");
    let b_log: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.clamp_debit_log WHERE ref = $1 AND account_id = $2",
    )
    .bind(format!("op:{op_b}:shared-ref"))
    .bind(acct_b)
    .fetch_one(&db.pool)
    .await
    .expect("b log count");
    assert_eq!(a_log, 1);
    assert_eq!(b_log, 1);
}

/// The SAME operator posting the SAME supplied ref to the SAME account is the
/// idempotent no-op: a single applied entry, and the second call memoizes rather
/// than charging twice. Operator-scoping must not weaken within-operator
/// idempotency.
#[tokio::test]
async fn same_operator_same_ref_same_account_is_idempotent() {
    let db = TestDb::fresh().await.expect("test database");
    register_topup(&db.pool, false).await;
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");

    let op = seed_operator(&db.pool).await;
    let acct = create_account(&db.pool, op).await.expect("account");

    // Adjustment: first applies, the retry is AlreadyApplied; charged once.
    let first = apply_adjustment(
        &db.pool,
        op,
        acct,
        4_000_000,
        "grant",
        TEST_CAP,
        Some("evt-1"),
        None,
    )
    .await
    .expect("first adjustment");
    assert_eq!(first, AdjustmentOutcome::Applied(InsertOutcome::Inserted));
    let retry = apply_adjustment(
        &db.pool,
        op,
        acct,
        4_000_000,
        "grant",
        TEST_CAP,
        Some("evt-1"),
        None,
    )
    .await
    .expect("retry adjustment");
    assert_eq!(
        retry,
        AdjustmentOutcome::Applied(InsertOutcome::AlreadyApplied),
        "a redelivered same-ref adjustment is the idempotent no-op"
    );
    assert_eq!(
        load_balance_micros(&db.pool, acct).await.unwrap(),
        4_000_000,
        "the balance moved exactly once"
    );
    assert_eq!(adjust_ledger_count(&db.pool, acct).await, 1);

    // Clamp-debit: first applies, the retry replays the memoized result.
    let first = clamp_debit(
        &db.pool, op, acct, 1_000_000, "clawback", TEST_CAP, "claw-1", None,
    )
    .await
    .expect("first clamp");
    let ClampedDebitResult::Applied(first) = first else {
        panic!("first clamp must apply");
    };
    assert_eq!(first.debited_micros, 1_000_000);
    assert!(first.newly_applied);
    let retry = clamp_debit(
        &db.pool, op, acct, 1_000_000, "clawback", TEST_CAP, "claw-1", None,
    )
    .await
    .expect("retry clamp");
    let ClampedDebitResult::Applied(retry) = retry else {
        panic!("retry clamp must apply");
    };
    assert_eq!(retry.debited_micros, 1_000_000);
    assert!(
        !retry.newly_applied,
        "a redelivered same-ref clamp replays the memoized result"
    );
    assert_eq!(
        load_balance_micros(&db.pool, acct).await.unwrap(),
        3_000_000,
        "the clamp debited exactly once (4M grant - 1M clawback)"
    );
}

/// The SAME operator posting the SAME supplied ref to TWO of its OWN different
/// accounts still trips the journal's must-never-happen cross-account error,
/// because both map to the same `op:<operator>:<ref>` stored key. The
/// operator-scoping does NOT collapse this within-operator tripwire.
#[tokio::test]
async fn same_operator_same_ref_across_two_own_accounts_still_errors() {
    let db = TestDb::fresh().await.expect("test database");
    register_topup(&db.pool, false).await;
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register kind");

    let op = seed_operator(&db.pool).await;
    let acct_1 = create_account(&db.pool, op).await.expect("account 1");
    let acct_2 = create_account(&db.pool, op).await.expect("account 2");
    insert_ledger_entry(&db.pool, &entry(acct_1, "topup", 10, Some("fund-1")))
        .await
        .expect("fund 1");
    insert_ledger_entry(&db.pool, &entry(acct_2, "topup", 10, Some("fund-2")))
        .await
        .expect("fund 2");

    // Adjustment: account 1 takes the ref; account 2 under the same ref errors.
    apply_adjustment(
        &db.pool,
        op,
        acct_1,
        1_000_000,
        "grant",
        TEST_CAP,
        Some("dup"),
        None,
    )
    .await
    .expect("first account's adjustment");
    let cross = apply_adjustment(
        &db.pool,
        op,
        acct_2,
        1_000_000,
        "grant",
        TEST_CAP,
        Some("dup"),
        None,
    )
    .await;
    assert!(
        cross.is_err(),
        "the same operator's same ref on a second account must hard-error"
    );
    assert_eq!(
        load_balance_micros(&db.pool, acct_2).await.unwrap(),
        10,
        "the rejected adjustment left account 2 untouched"
    );

    // Clamp-debit: account 1 takes the ref; account 2 under the same ref errors.
    clamp_debit(
        &db.pool, op, acct_1, 2, "clawback", TEST_CAP, "dup-claw", None,
    )
    .await
    .expect("first account's clamp");
    let cross = clamp_debit(
        &db.pool, op, acct_2, 2, "clawback", TEST_CAP, "dup-claw", None,
    )
    .await;
    assert!(
        cross.is_err(),
        "the same operator's same clamp ref on a second account must hard-error"
    );
    assert_eq!(
        load_balance_micros(&db.pool, acct_2).await.unwrap(),
        10,
        "the rejected clamp left account 2 untouched"
    );
}

/// A replayed credit (same caller-supplied ref) whose account has since been
/// disabled reports the APPLIED outcome, not `AccountNotActive`: the credit
/// landed while the account was active, and a redelivery must not read as a
/// refusal (the caller would re-issue the grant under a fresh ref and pay
/// twice). Only a genuinely NEW credit to the disabled account is refused, and
/// a mismatched reuse of the ref stays a hard error.
#[tokio::test]
async fn a_replayed_credit_to_a_now_disabled_account_reports_applied() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    register_adjust(&db.pool).await;

    let applied = apply_adjustment(
        &db.pool,
        op,
        account_id,
        500,
        "welcome grant",
        1_000_000,
        Some("grant-1"),
        None,
    )
    .await
    .expect("first credit applies");
    assert_eq!(applied, AdjustmentOutcome::Applied(InsertOutcome::Inserted));

    sqlx::query("UPDATE cw_core.account_detail SET status = 'disabled' WHERE account_id = $1")
        .bind(account_id)
        .execute(&db.pool)
        .await
        .expect("disable the account");

    // The redelivery of the SAME ref: an idempotent no-op reported as applied.
    let replay = apply_adjustment(
        &db.pool,
        op,
        account_id,
        500,
        "welcome grant",
        1_000_000,
        Some("grant-1"),
        None,
    )
    .await
    .expect("replay resolves");
    assert_eq!(
        replay,
        AdjustmentOutcome::Applied(InsertOutcome::AlreadyApplied)
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        500,
        "the balance moved exactly once"
    );

    // A genuinely NEW credit to the disabled account is still refused.
    let fresh = apply_adjustment(
        &db.pool,
        op,
        account_id,
        500,
        "second grant",
        1_000_000,
        Some("grant-2"),
        None,
    )
    .await
    .expect("fresh credit resolves");
    assert_eq!(fresh, AdjustmentOutcome::AccountNotActive);

    // The same ref reused with a DIFFERENT amount is a caller bug, surfaced as
    // an error rather than resolved to either outcome.
    let mismatch = apply_adjustment(
        &db.pool,
        op,
        account_id,
        700,
        "welcome grant",
        1_000_000,
        Some("grant-1"),
        None,
    )
    .await;
    assert!(
        mismatch.is_err(),
        "a mismatched replay is an error, not a silent outcome"
    );
}
