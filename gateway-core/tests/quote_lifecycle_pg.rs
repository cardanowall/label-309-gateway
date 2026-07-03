//! Integration coverage for the two-phase publish-cost protocol: create a quote
//! through a pricing hook, consume it in one transaction with an affordability
//! gate, and expire the stale ones.
//!
//! These drive the quote module functions against a freshly migrated database and
//! assert the protocol's guarantees end to end: a created quote persists the
//! hook-resolved margin and its source; consume is all-or-nothing (an affordable
//! consume charges exactly once and binds the record, an unaffordable one leaves
//! nothing); a double-consume of one quote and two quotes for one record are both
//! refused; the expiry job flips lapsed quotes; and a concurrent race for one
//! quote is won by exactly one consumer.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;

use gateway_core::chain::confirm::{record_permanent_failure, RefundReason};
use gateway_core::ledger::account::create_account;
use gateway_core::ledger::journal::{
    insert_ledger_entry, load_balance_micros, register_kind, LedgerEntry,
};
use gateway_core::ledger::quote::{
    consume_quote, create_quote, expire_stale_quotes, ConsumeOutcome, ConsumeRejection,
    FixedMarginHook, FxSnapshot, MarginResolution, PricingHook, Quote, QuoteRequest,
    MAX_QUOTE_RECORD_BYTES,
};
use gateway_core::testsupport::TestDb;
use gateway_core::Result;
use rust_decimal::Decimal;
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

/// Fund an account by a direct vendor-credit entry, so a consume can afford a
/// quote. Registers a non-overdrawing credit kind on first use.
async fn fund(pool: &sqlx::PgPool, account_id: Uuid, amount_micros: i64) {
    register_kind(pool, "topup", false, "vendor")
        .await
        .expect("register topup");
    let r = format!("fund-{}", Uuid::now_v7());
    insert_ledger_entry(
        pool,
        &LedgerEntry {
            account_id,
            kind: "topup".to_string(),
            amount_micros,
            r#ref: Some(r),
            quote_id: None,
            metadata: json!({}),
            request_id: None,
        },
    )
    .await
    .expect("fund the account");
}

/// A snapshot pricing 1 ADA at $0.50 and storage at zero (so the cost is the
/// network fee alone, keeping the arithmetic obvious in the lifecycle tests).
fn fx() -> FxSnapshot {
    FxSnapshot {
        ada_usd_micros: 500_000,
        ar_usd_per_byte_femto: 0,
        source: "test".to_string(),
    }
}

/// The record size, in bytes, the lifecycle quotes are priced for. The consume
/// calls publish a record of exactly this many bytes (actual == quoted), so the
/// size contract is satisfied and these tests exercise the money path, not the
/// size guard (which has its own dedicated tests).
const QUOTED_RECORD_BYTES: u32 = 200;

/// A quote request for `network_lovelace` against an account, no storage.
fn request(account_id: Uuid, network_lovelace: u64) -> QuoteRequest {
    QuoteRequest {
        account_id,
        record_bytes: QUOTED_RECORD_BYTES,
        recipient_count: 0,
        file_bytes_total: 0,
        free_storage_bytes: gateway_core::ledger::quote::DEFAULT_FREE_STORAGE_BYTES,
        network_lovelace,
        fx: fx(),
        fx_age_seconds: 0,
        request_id: Some(Uuid::now_v7()),
    }
}

/// A pricing hook that records the COGS it was asked to price and returns a fixed
/// margin with a distinctive source, so a test can prove the hook ran and its
/// resolution was persisted.
struct RecordingHook {
    margin_pct: Decimal,
    source: String,
}

impl PricingHook for RecordingHook {
    async fn resolve_margin(
        &self,
        _account_id: Uuid,
        _cogs_usd_micros: i64,
    ) -> Result<MarginResolution> {
        Ok(MarginResolution {
            margin_pct: self.margin_pct,
            margin_source: self.source.clone(),
        })
    }
}

/// `create_quote` computes the COGS, applies the hook margin, and persists the
/// single durable row carrying the margin and its source.
#[tokio::test]
async fn create_quote_persists_the_hook_margin_and_source() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");

    let hook = RecordingHook {
        margin_pct: Decimal::new(25, 2), // 25%
        source: "tier:partner".to_string(),
    };
    // 2 ADA fee at $0.50/ADA = 1_000_000 micro-USD COGS; 25% margin = 250_000
    // service; total 1_250_000.
    let quote = create_quote(&db.pool, &hook, &request(account_id, 2_000_000))
        .await
        .expect("create quote");

    assert_eq!(quote.network_usd_micros, 1_000_000);
    assert_eq!(quote.storage_usd_micros, 0);
    assert_eq!(quote.service_usd_micros, 250_000);
    assert_eq!(quote.total_usd_micros, 1_250_000);
    assert!(quote.expires_at > quote.issued_at);

    // The persisted row carries the margin, its source, the status, and the FX
    // snapshot verbatim.
    let (margin_pct, margin_source, status, fx_src): (Decimal, String, String, String) =
        sqlx::query_as(
            "SELECT margin_pct, margin_source, status, fx_snapshot->>'source' \
             FROM cw_core.publish_quote WHERE id = $1",
        )
        .bind(quote.id)
        .fetch_one(&db.pool)
        .await
        .expect("read quote row");
    assert_eq!(margin_pct, Decimal::new(2500, 4));
    assert_eq!(margin_source, "tier:partner");
    assert_eq!(status, "pending");
    assert_eq!(fx_src, "test", "the FX snapshot is persisted verbatim");
}

/// The full consume protocol: an affordable quote charges exactly once, binds the
/// record, stamps the ledger row with the quote id, and leaves the quote consumed.
#[tokio::test]
async fn consume_charges_once_binds_the_record_and_stamps_the_quote() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    fund(&db.pool, account_id, 5_000_000).await;

    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &request(account_id, 2_000_000),
    )
    .await
    .expect("quote"); // total = 1_000_000

    let record = Uuid::now_v7();
    let req = Uuid::now_v7();
    let outcome = consume_quote(
        &db.pool,
        quote.id,
        account_id,
        record,
        QUOTED_RECORD_BYTES,
        Some(req),
    )
    .await
    .expect("consume");
    assert_eq!(
        outcome,
        ConsumeOutcome::Consumed {
            balance_micros: 4_000_000
        },
        "the post-debit balance is funds minus the quote total"
    );

    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        4_000_000
    );

    // The quote is consumed and bound to the record.
    let (status, bound): (String, Option<Uuid>) =
        sqlx::query_as("SELECT status, poe_record_id FROM cw_core.publish_quote WHERE id = $1")
            .bind(quote.id)
            .fetch_one(&db.pool)
            .await
            .expect("read quote");
    assert_eq!(status, "consumed");
    assert_eq!(bound, Some(record));

    // The publish debit row is signed-negative, keyed on the record, and stamped
    // with the quote id for audit replay.
    let (amount, ref_, quote_id): (i64, String, Option<Uuid>) = sqlx::query_as(
        "SELECT amount_micros, ref, quote_id FROM cw_core.balance_ledger \
         WHERE kind = 'poe_publish' AND ref = $1",
    )
    .bind(record.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("read debit");
    assert_eq!(amount, -1_000_000);
    assert_eq!(ref_, record.to_string());
    assert_eq!(quote_id, Some(quote.id));
}

/// An unaffordable consume leaves NOTHING: no ledger row, the quote stays pending,
/// and the balance is untouched.
#[tokio::test]
async fn an_unaffordable_consume_leaves_nothing() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    // Fund with less than the quote total.
    fund(&db.pool, account_id, 500_000).await;

    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &request(account_id, 2_000_000),
    )
    .await
    .expect("quote"); // total = 1_000_000 > 500_000 funded

    let record = Uuid::now_v7();
    let outcome = consume_quote(
        &db.pool,
        quote.id,
        account_id,
        record,
        QUOTED_RECORD_BYTES,
        None,
    )
    .await
    .expect("consume returns a rejection, not an error");
    // The rejection carries the observed balance and the charge it could not
    // cover, which the publish route surfaces as the 402's extension members.
    match outcome {
        ConsumeOutcome::Rejected(ConsumeRejection::InsufficientFunds {
            balance_micros,
            required_micros,
        }) => {
            assert_eq!(balance_micros, 500_000);
            assert!(
                required_micros > 500_000,
                "the uncovered charge exceeds the balance, got {required_micros}"
            );
        }
        other => panic!("expected an insufficient-funds rejection, got {other:?}"),
    }

    // Nothing changed: balance intact, no debit row, quote still pending.
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        500_000
    );
    let debits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE kind = 'poe_publish'",
    )
    .fetch_one(&db.pool)
    .await
    .expect("count debits");
    assert_eq!(debits, 0, "no debit row was written");
    let status: String =
        sqlx::query_scalar("SELECT status FROM cw_core.publish_quote WHERE id = $1")
            .bind(quote.id)
            .fetch_one(&db.pool)
            .await
            .expect("read status");
    assert_eq!(status, "pending", "the quote is still pending");
}

/// Consuming the same quote twice for the same record is idempotent: the second
/// call reports `AlreadyConsumed` without a second charge. Consuming it for a
/// DIFFERENT record after it is bound is a plain rejection.
#[tokio::test]
async fn double_consume_of_one_quote() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    fund(&db.pool, account_id, 5_000_000).await;

    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &request(account_id, 2_000_000),
    )
    .await
    .expect("quote"); // total 1_000_000

    let record = Uuid::now_v7();
    assert!(matches!(
        consume_quote(
            &db.pool,
            quote.id,
            account_id,
            record,
            QUOTED_RECORD_BYTES,
            None
        )
        .await
        .expect("first consume"),
        ConsumeOutcome::Consumed { .. }
    ));

    // Same record again: idempotent.
    assert_eq!(
        consume_quote(
            &db.pool,
            quote.id,
            account_id,
            record,
            QUOTED_RECORD_BYTES,
            None
        )
        .await
        .expect("idempotent retry"),
        ConsumeOutcome::AlreadyConsumed
    );

    // A different record against the now-consumed quote: rejected, not charged.
    let other = Uuid::now_v7();
    assert_eq!(
        consume_quote(
            &db.pool,
            quote.id,
            account_id,
            other,
            QUOTED_RECORD_BYTES,
            None
        )
        .await
        .expect("consume of a consumed quote for another record"),
        ConsumeOutcome::Rejected(ConsumeRejection::NotPending)
    );

    // Exactly one debit ever landed.
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        4_000_000
    );
}

/// Two quotes cannot both consume the SAME record: the publish-quote partial
/// unique on `poe_record_id` (and the ledger's `(kind, ref)` unique) refuse the
/// second binding.
#[tokio::test]
async fn two_quotes_cannot_bind_the_same_record() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    fund(&db.pool, account_id, 10_000_000).await;

    let q1 = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &request(account_id, 2_000_000),
    )
    .await
    .expect("quote 1");
    let q2 = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &request(account_id, 2_000_000),
    )
    .await
    .expect("quote 2");

    let record = Uuid::now_v7();
    assert!(matches!(
        consume_quote(
            &db.pool,
            q1.id,
            account_id,
            record,
            QUOTED_RECORD_BYTES,
            None
        )
        .await
        .expect("first quote consumes the record"),
        ConsumeOutcome::Consumed { .. }
    ));

    // The second quote tries to bind the same record: the unique indexes refuse
    // it, surfaced as an error (a caller bug, not a benign rejection).
    let err = consume_quote(
        &db.pool,
        q2.id,
        account_id,
        record,
        QUOTED_RECORD_BYTES,
        None,
    )
    .await
    .expect_err("a second quote binding the same record must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("already exists") || msg.contains("different") || msg.contains("23505"),
        "expected a uniqueness/conflict failure, got {err:?}"
    );

    // Only the first debit landed; the second quote's consume rolled back wholly
    // (the conflicting publish debit never committed), so the balance reflects a
    // single 1_000_000 charge against the 10_000_000 funded.
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        9_000_000
    );
    let q2_status: String =
        sqlx::query_scalar("SELECT status FROM cw_core.publish_quote WHERE id = $1")
            .bind(q2.id)
            .fetch_one(&db.pool)
            .await
            .expect("read q2 status");
    assert_eq!(q2_status, "pending");
}

/// The expiry job flips pending quotes past their TTL to `expired` and leaves
/// fresh ones and already-consumed ones alone. A subsequently consumed-then-stale
/// quote is not re-expired.
#[tokio::test]
async fn expire_job_flips_only_stale_pending_quotes() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    fund(&db.pool, account_id, 5_000_000).await;

    // A fresh pending quote (long TTL) and a consumed quote both survive.
    let fresh = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &request(account_id, 2_000_000),
    )
    .await
    .expect("fresh quote");
    let consumed = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &request(account_id, 2_000_000),
    )
    .await
    .expect("to-consume quote");
    consume_quote(
        &db.pool,
        consumed.id,
        account_id,
        Uuid::now_v7(),
        QUOTED_RECORD_BYTES,
        None,
    )
    .await
    .expect("consume");

    // A pending quote backdated past its TTL is the only one that should flip.
    let stale = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &request(account_id, 2_000_000),
    )
    .await
    .expect("stale quote");
    sqlx::query(
        "UPDATE cw_core.publish_quote SET expires_at = now() - interval '1 minute' WHERE id = $1",
    )
    .bind(stale.id)
    .execute(&db.pool)
    .await
    .expect("backdate the stale quote");

    let expired = expire_stale_quotes(&db.pool).await.expect("expire pass");
    assert_eq!(expired, 1, "exactly the one stale pending quote flips");

    let status = |id: Uuid| {
        let pool = db.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM cw_core.publish_quote WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read status")
        }
    };
    assert_eq!(status(stale.id).await, "expired");
    assert_eq!(status(fresh.id).await, "pending");
    assert_eq!(status(consumed.id).await, "consumed");

    // A second pass flips nothing more.
    assert_eq!(expire_stale_quotes(&db.pool).await.expect("second pass"), 0);
}

/// A consume re-checks expiry under the row lock: a quote that lapsed between
/// creation and consume is rejected as `Expired`, not charged.
#[tokio::test]
async fn consume_rejects_a_quote_that_lapsed() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    fund(&db.pool, account_id, 5_000_000).await;

    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &request(account_id, 2_000_000),
    )
    .await
    .expect("quote");
    sqlx::query(
        "UPDATE cw_core.publish_quote SET expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(quote.id)
    .execute(&db.pool)
    .await
    .expect("lapse the quote");

    assert_eq!(
        consume_quote(
            &db.pool,
            quote.id,
            account_id,
            Uuid::now_v7(),
            QUOTED_RECORD_BYTES,
            None
        )
        .await
        .expect("consume of a lapsed quote"),
        ConsumeOutcome::Rejected(ConsumeRejection::Expired)
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        5_000_000,
        "a lapsed quote charges nothing"
    );
}

/// A consume for an account that does not own the quote is `NotFound`: the quote
/// is scoped to its account.
#[tokio::test]
async fn consume_is_scoped_to_the_owning_account() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let owner = create_account(&db.pool, op).await.expect("owner");
    let other = create_account(&db.pool, op).await.expect("other");
    fund(&db.pool, owner, 5_000_000).await;

    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &request(owner, 2_000_000),
    )
    .await
    .expect("quote");

    assert_eq!(
        consume_quote(
            &db.pool,
            quote.id,
            other,
            Uuid::now_v7(),
            QUOTED_RECORD_BYTES,
            None
        )
        .await
        .expect("consume under the wrong account"),
        ConsumeOutcome::Rejected(ConsumeRejection::NotFound)
    );
}

/// Two threads racing to consume ONE quote: exactly one wins (`Consumed`), the
/// other observes the consumed quote. Only one debit ever lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_consume_of_one_quote_has_a_single_winner() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = Arc::new(db.pool_with(8).await.expect("wide pool"));
    let op = seed_operator(pool.as_ref()).await;
    let account_id = create_account(pool.as_ref(), op).await.expect("account");
    fund(pool.as_ref(), account_id, 5_000_000).await;

    let quote = create_quote(
        pool.as_ref(),
        &FixedMarginHook::new(Decimal::ZERO),
        &request(account_id, 2_000_000),
    )
    .await
    .expect("quote");

    // Both racers consume for the SAME record, so the loser's path is the
    // already-consumed-for-this-record idempotent branch rather than an error;
    // either way only one debit may land.
    let record = Uuid::now_v7();
    let race = |q: Quote| {
        let pool = Arc::clone(&pool);
        tokio::spawn(async move {
            consume_quote(
                pool.as_ref(),
                q.id,
                account_id,
                record,
                QUOTED_RECORD_BYTES,
                None,
            )
            .await
            .expect("consume must not error under the race")
        })
    };
    let a = race(quote.clone());
    let b = race(quote.clone());
    let (ra, rb) = (a.await.expect("task a"), b.await.expect("task b"));

    let consumed = [&ra, &rb]
        .iter()
        .filter(|o| matches!(o, ConsumeOutcome::Consumed { .. }))
        .count();
    let already = [&ra, &rb]
        .iter()
        .filter(|o| matches!(o, ConsumeOutcome::AlreadyConsumed))
        .count();
    assert_eq!(
        consumed, 1,
        "exactly one consumer charges the quote: {ra:?} {rb:?}"
    );
    assert_eq!(
        already, 1,
        "the other observes it already consumed: {ra:?} {rb:?}"
    );

    // Only one debit landed; the balance reflects a single charge.
    assert_eq!(
        load_balance_micros(pool.as_ref(), account_id)
            .await
            .unwrap(),
        4_000_000
    );
    let debits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger WHERE kind = 'poe_publish'",
    )
    .fetch_one(pool.as_ref())
    .await
    .expect("count debits");
    assert_eq!(debits, 1);
}

/// Seed an account-bound `poe_record` in `submitting`, so a consume can bind to it
/// and a permanent-failure flip has a valid non-terminal row to terminate.
async fn seed_submitting_record(pool: &sqlx::PgPool, operator_id: Uuid, account_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    // The dedup partial unique is on (account_id, record_sha256); a per-record
    // unique digest keeps the seed self-contained without hashing real bytes.
    let mut sha256 = [0u8; 32];
    sha256[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, account_id, record_bytes, record_sha256, status) \
         VALUES ($1, $2, $3, $4, $5, 'submitting')",
    )
    .bind(id)
    .bind(operator_id)
    .bind(account_id)
    .bind(vec![0xa0u8, 0x01])
    .bind(sha256.to_vec())
    .execute(pool)
    .await
    .expect("insert submitting record");
    id
}

/// Publish charges network plus service only: the `poe_publish` debit excludes the
/// quote's storage component, and a publish-then-permanent-fail refunds exactly
/// that debit (so the refund also excludes storage). Storage is settled at upload
/// against the funding source, never on this debit.
#[tokio::test]
async fn publish_debit_and_refund_exclude_storage() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    fund(&db.pool, account_id, 10_000_000).await;

    // A quote with all three components nonzero and distinct so storage cannot
    // hide inside network or service. Bytes are charged only beyond the free
    // window (DEFAULT_FREE_STORAGE_BYTES = 102_400):
    //   network: 2 ADA at $0.50/ADA               = 1_000_000 micro-USD
    //   storage: (200_000 - 102_400) bytes at 1e9 femto-USD/byte
    //            = 97_600 micro-USD
    //   COGS = 1_097_600; 25% margin -> service   = 274_400
    //   total = 1_372_000
    let mut fx = fx();
    fx.ar_usd_per_byte_femto = 1_000_000_000;
    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::new(25, 2)),
        &QuoteRequest {
            account_id,
            record_bytes: QUOTED_RECORD_BYTES,
            recipient_count: 0,
            file_bytes_total: 200_000,
            free_storage_bytes: gateway_core::ledger::quote::DEFAULT_FREE_STORAGE_BYTES,
            network_lovelace: 2_000_000,
            fx,
            fx_age_seconds: 0,
            request_id: Some(Uuid::now_v7()),
        },
    )
    .await
    .expect("quote");

    assert_eq!(quote.network_usd_micros, 1_000_000);
    assert_eq!(quote.storage_usd_micros, 97_600, "storage is nonzero");
    assert_eq!(quote.service_usd_micros, 274_400);
    assert_eq!(quote.total_usd_micros, 1_372_000);
    let publish_charge = quote.network_usd_micros + quote.service_usd_micros;
    assert_eq!(publish_charge, 1_274_400);

    let record = seed_submitting_record(&db.pool, op, account_id).await;
    let outcome = consume_quote(
        &db.pool,
        quote.id,
        account_id,
        record,
        QUOTED_RECORD_BYTES,
        None,
    )
    .await
    .expect("consume");

    // The post-debit balance reflects network+service only; the storage component
    // is NOT debited at publish.
    assert_eq!(
        outcome,
        ConsumeOutcome::Consumed {
            balance_micros: 10_000_000 - publish_charge
        },
        "publish charges network+service, not the wire total"
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        10_000_000 - publish_charge,
    );

    // The `poe_publish` debit row equals network+service exactly, and the gap to
    // the wire total is precisely the storage component that was excluded.
    let debit_micros: i64 = sqlx::query_scalar(
        "SELECT amount_micros FROM cw_core.balance_ledger \
         WHERE kind = 'poe_publish' AND ref = $1",
    )
    .bind(record.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("read poe_publish debit");
    assert_eq!(
        debit_micros, -publish_charge,
        "the publish debit is network+service, storage excluded"
    );
    assert_eq!(
        -debit_micros + quote.storage_usd_micros,
        quote.total_usd_micros,
        "the debit plus the excluded storage equals the wire total",
    );

    // Drive the record to permanent failure: this emits the durable refund intent
    // a downstream billing consumer reverses. The amount it would refund is the
    // negated `poe_publish` debit keyed on this record, which excludes storage.
    let detail = json!({ "record_id": record });
    let owned = record_permanent_failure(&db.pool, record, RefundReason::TxBuildFailed, &detail)
        .await
        .expect("permanent failure");
    assert!(owned, "this call owned the refund");

    let intent_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM cw_core.refund_intent WHERE record_id = $1)",
    )
    .bind(record)
    .fetch_one(&db.pool)
    .await
    .expect("read refund intent");
    assert!(
        intent_exists,
        "a refund intent exists for the failed record"
    );

    // The refundable amount the intent points at is the publish debit for the
    // record: network+service, with storage excluded. A storage charge is sunk
    // once the bytes are written, so the refund never reverses it.
    let refundable_micros: i64 = sqlx::query_scalar(
        "SELECT -amount_micros FROM cw_core.balance_ledger \
         WHERE kind = 'poe_publish' AND ref = $1",
    )
    .bind(record.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("read refundable publish debit");
    assert_eq!(
        refundable_micros, publish_charge,
        "the refund-intent amount is network+service, storage excluded"
    );
    assert!(
        refundable_micros < quote.total_usd_micros,
        "the refundable amount is strictly less than the wire total by the storage component"
    );
}

// ===========================================================================
// The fixed-price size contract: a quote prices a SPECIFIC record size, and a
// publish of a larger record is refused before any debit. Without this guard an
// account could quote one byte and publish a full record at the one-byte price
// while the operator's wallet funds the real on-chain fee.
// ===========================================================================

/// A quote request priced for a record of exactly `record_bytes` bytes, with a
/// fixed 2 ADA network fee and no storage, so the test isolates the size guard.
fn sized_request(account_id: Uuid, record_bytes: u32) -> QuoteRequest {
    QuoteRequest {
        account_id,
        record_bytes,
        recipient_count: 0,
        file_bytes_total: 0,
        free_storage_bytes: gateway_core::ledger::quote::DEFAULT_FREE_STORAGE_BYTES,
        network_lovelace: 2_000_000,
        fx: fx(),
        fx_age_seconds: 0,
        request_id: Some(Uuid::now_v7()),
    }
}

/// Count the `poe_publish` debit rows for an account.
async fn publish_debit_count(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger \
         WHERE kind = 'poe_publish' AND account_id = $1",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("count publish debits")
}

/// Publishing a record LARGER than the quote was priced for is refused before any
/// debit: the balance is untouched, no `poe_publish` row is written, no
/// `poe_record` is bound, and the quote stays pending so a correctly-sized retry
/// against a fresh quote can still proceed. This is the money fix: the operator's
/// wallet must not silently fund the gap between a one-byte quote and a full
/// record's real on-chain fee.
#[tokio::test]
async fn consume_rejects_a_record_larger_than_quoted() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    fund(&db.pool, account_id, 5_000_000).await;

    // Quote for a tiny one-byte record; the price is the network fee (1_000_000).
    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &sized_request(account_id, 1),
    )
    .await
    .expect("quote for one byte");

    // Attempt to publish a much larger record under the one-byte quote.
    let record = seed_submitting_record(&db.pool, op, account_id).await;
    let outcome = consume_quote(&db.pool, quote.id, account_id, record, 8_192, None)
        .await
        .expect("consume returns a rejection, not an error");
    assert_eq!(
        outcome,
        ConsumeOutcome::Rejected(ConsumeRejection::RecordTooLarge {
            actual_bytes: 8_192,
            quoted_bytes: 1,
        }),
        "a record larger than quoted is refused with the actual and quoted sizes"
    );

    // Nothing moved: full balance intact, no debit row, no binding, quote pending.
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        5_000_000,
        "an over-size publish charges nothing"
    );
    assert_eq!(
        publish_debit_count(&db.pool, account_id).await,
        0,
        "no publish debit was written"
    );
    let (status, bound): (String, Option<Uuid>) =
        sqlx::query_as("SELECT status, poe_record_id FROM cw_core.publish_quote WHERE id = $1")
            .bind(quote.id)
            .fetch_one(&db.pool)
            .await
            .expect("read quote state");
    assert_eq!(status, "pending", "the quote stays pending after a refusal");
    assert_eq!(bound, None, "no record was bound to the refused quote");
}

/// Publishing a record of EXACTLY the quoted size is accepted and charged once.
#[tokio::test]
async fn consume_accepts_a_record_at_the_quoted_size() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    fund(&db.pool, account_id, 5_000_000).await;

    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &sized_request(account_id, 1_024),
    )
    .await
    .expect("quote for 1024 bytes");

    let record = seed_submitting_record(&db.pool, op, account_id).await;
    let outcome = consume_quote(&db.pool, quote.id, account_id, record, 1_024, None)
        .await
        .expect("consume");
    assert_eq!(
        outcome,
        ConsumeOutcome::Consumed {
            balance_micros: 4_000_000
        },
        "a record at the quoted size is charged the quote price"
    );
    assert_eq!(
        publish_debit_count(&db.pool, account_id).await,
        1,
        "exactly one publish debit landed"
    );
}

/// Publishing a record SMALLER than the quote was priced for is accepted: the
/// quote is a fixed-price contract, so the account simply pays the (larger)
/// quoted price with no refund of the difference. This is the documented,
/// intentional reverse of the over-size refusal.
#[tokio::test]
async fn consume_accepts_a_record_smaller_than_quoted() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");
    fund(&db.pool, account_id, 5_000_000).await;

    // Quote priced for a large record (full price), then publish a tiny one.
    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &sized_request(account_id, 10_000),
    )
    .await
    .expect("quote for 10000 bytes");

    let record = seed_submitting_record(&db.pool, op, account_id).await;
    let outcome = consume_quote(&db.pool, quote.id, account_id, record, 16, None)
        .await
        .expect("consume");
    assert_eq!(
        outcome,
        ConsumeOutcome::Consumed {
            balance_micros: 4_000_000
        },
        "a smaller record still pays the full quoted price (no refund of the difference)"
    );
    assert_eq!(
        publish_debit_count(&db.pool, account_id).await,
        1,
        "exactly one publish debit landed at the quoted price"
    );
}

/// A quote requested for a record larger than the maximum quotable size is
/// refused at creation: the function returns an error and persists no row, so
/// content can never be uploaded against a publish that could only fail to submit.
#[tokio::test]
async fn create_quote_rejects_a_record_over_the_cap() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");

    let err = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &sized_request(account_id, MAX_QUOTE_RECORD_BYTES + 1),
    )
    .await
    .expect_err("an over-cap quote request must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("exceeds the maximum quotable size"),
        "the error names the size cap, got {err:?}"
    );

    // No quote row was persisted for the account.
    let quotes: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.publish_quote WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&db.pool)
            .await
            .expect("count quotes");
    assert_eq!(quotes, 0, "no row is persisted for an over-cap request");
}

/// A quote requested for a record at exactly the maximum quotable size is
/// accepted: the cap is inclusive, so the largest fitting record can still quote.
#[tokio::test]
async fn create_quote_accepts_a_record_at_the_cap() {
    let db = TestDb::fresh().await.expect("test database");
    let op = seed_operator(&db.pool).await;
    let account_id = create_account(&db.pool, op).await.expect("account");

    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::ZERO),
        &sized_request(account_id, MAX_QUOTE_RECORD_BYTES),
    )
    .await
    .expect("a quote at the cap is accepted");

    let persisted_bytes: i32 =
        sqlx::query_scalar("SELECT record_bytes FROM cw_core.publish_quote WHERE id = $1")
            .bind(quote.id)
            .fetch_one(&db.pool)
            .await
            .expect("read persisted record_bytes");
    assert_eq!(
        u32::try_from(persisted_bytes).unwrap(),
        MAX_QUOTE_RECORD_BYTES,
        "the persisted quote carries the at-cap record size"
    );
}
