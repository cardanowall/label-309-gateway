//! Integration tests for the webhook fan-out spine and subject-owner resolution.
//!
//! Two properties are pinned here:
//!
//!   - the presence-based set-drain reader claims every un-fanned outbox row
//!     exactly once across concurrent passes and across a mid-fan-out crash (no
//!     skip, no double-fan, no wedge, since there is no sequence to wedge on), and
//!   - owner resolution for all three real subject kinds, including the
//!     null-`account_id` `poe_record` (operator-only, no account owner) and the
//!     operator-only `storage_funding_source`.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::json;
use uuid::Uuid;

use gateway_core::events::append_subject_event;
use gateway_core::runtime::{JobContext, JobHandler, JobOutcome};
use gateway_core::testsupport::TestDb;
use gateway_core::webhook::fanout::ClaimedOutboxRow;
use gateway_core::webhook::owner::kind;
use gateway_core::webhook::{
    build_envelope, claim_unfanned, explode_outbox_row, resolve_owner, stamp_fanned_out,
    FanoutHandler, OwnerResolution, SubjectOwner,
};

/// Seed an operator and return its id.
async fn seed_operator(pool: &sqlx::PgPool, label: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(id)
        .bind(label)
        .execute(pool)
        .await
        .expect("seed operator");
    id
}

/// Seed an account anchor plus its `account_detail` satellite under `operator_id`
/// and return the account id.
async fn seed_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("seed account anchor");
    sqlx::query("INSERT INTO cw_core.account_detail (account_id, operator_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("seed account detail");
    account_id
}

/// Seed a `poe_record` with an optional account owner. `account_id` is the
/// nullable UUID FK into the account anchor: `Some(account)` for a tenant-owned
/// record, `None` for an operator-direct publish.
async fn seed_poe_record(pool: &sqlx::PgPool, operator_id: Uuid, account_id: Option<Uuid>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record (id, operator_id, account_id, record_bytes) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(account_id)
    .bind(vec![0x01u8, 0x02, 0x03])
    .execute(pool)
    .await
    .expect("seed poe_record");
    id
}

/// Seed an active account-scoped webhook endpoint with no event filter and return
/// its id. The fan-out only inserts the delivery body and never reads the secret, so
/// the secret material is a dummy here (signing is the delivery worker's job, not
/// fan-out's).
async fn seed_account_endpoint(pool: &sqlx::PgPool, account_id: Uuid, url: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.webhook_endpoint \
           (id, scope_kind, account_id, url, secret_enc, secret_fp, wrap_key_id, enabled_events) \
         VALUES ($1, 'account', $2, $3, $4, $5, 'whk_test', '{}')",
    )
    .bind(id)
    .bind(account_id)
    .bind(url)
    .bind(vec![0u8; 16])
    .bind(vec![0u8; 32])
    .execute(pool)
    .await
    .expect("seed account endpoint");
    id
}

/// Seed a `storage_funding_source` owned by `operator_id` and return its id.
async fn seed_funding_source(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'src', 'turbo', $3, 'keyref')",
    )
    .bind(id)
    .bind(operator_id)
    // A unique address per row keeps the (backend, arweave_address) integrity
    // guard happy across seeds in the same database.
    .bind(format!("ar-addr-{}", id.simple()))
    .execute(pool)
    .await
    .expect("seed funding source");
    id
}

/// Resolve a subject and unwrap its [`OwnerResolution::Resolved`] owner, failing
/// the test on a transient error or a not-deliverable disposition.
async fn resolved_owner(pool: &sqlx::PgPool, kind: &str, id: &str) -> SubjectOwner {
    match resolve_owner(pool, kind, id).await.expect("resolve") {
        OwnerResolution::Resolved(owner) => owner,
        OwnerResolution::NotDeliverable => panic!("expected a resolved owner, got NotDeliverable"),
    }
}

/// Owner resolution returns the operator and the optional account for a
/// `poe_record` carrying an account, and operator-only (no account) for an
/// operator-direct `poe_record` with a NULL `account_id`.
#[tokio::test]
async fn resolves_poe_record_owner_with_and_without_account() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;

    // A record owned by an account: both owners resolve.
    let with_account = seed_poe_record(&pool, operator_id, Some(account_id)).await;
    let owner = resolved_owner(&pool, kind::POE_RECORD, &with_account.to_string()).await;
    assert_eq!(owner.operator_id, operator_id);
    assert_eq!(
        owner.account_id,
        Some(account_id),
        "an account-owned record resolves its account owner"
    );

    // An operator-direct record (NULL account_id): operator-only, no account.
    let direct = seed_poe_record(&pool, operator_id, None).await;
    let owner = resolved_owner(&pool, kind::POE_RECORD, &direct.to_string()).await;
    assert_eq!(owner.operator_id, operator_id);
    assert_eq!(
        owner.account_id, None,
        "an operator-direct record has no account owner, so no account subscription can match it"
    );
}

/// An `account` subject id is the account id; the account is its own account
/// owner and the operator is joined from `account_detail`.
#[tokio::test]
async fn resolves_account_owner_via_account_detail() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;

    let owner = resolved_owner(&pool, kind::ACCOUNT, &account_id.to_string()).await;
    assert_eq!(owner.operator_id, operator_id);
    assert_eq!(
        owner.account_id,
        Some(account_id),
        "an account subject is its own account owner"
    );
}

/// A `storage_funding_source` subject is operator-plane only: the owner is the
/// funding source's operator and there is no account owner, so no account-scoped
/// subscription can ever match it.
#[tokio::test]
async fn resolves_funding_source_owner_operator_only() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let operator_id = seed_operator(&pool, "op").await;
    let source_id = seed_funding_source(&pool, operator_id).await;

    let owner = resolved_owner(&pool, kind::STORAGE_FUNDING_SOURCE, &source_id.to_string()).await;
    assert_eq!(owner.operator_id, operator_id);
    assert_eq!(
        owner.account_id, None,
        "a funding source is operator-plane only and never account-visible"
    );
}

/// Both an unknown subject *id* and an unknown subject *kind* resolve to the same
/// terminal [`OwnerResolution::NotDeliverable`] disposition (never an `Err`), so
/// the fan-out reader stamps the row past with an empty match set rather than
/// wedging or terminally dropping it on a transient fault. A transient DB fault is
/// the only thing that surfaces as `Err`, which the caller propagates and retries.
#[tokio::test]
async fn unknown_subject_id_and_unknown_kind_both_resolve_not_deliverable() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    // A well-formed-but-absent id is not deliverable.
    let missing = resolve_owner(&pool, kind::POE_RECORD, &Uuid::now_v7().to_string())
        .await
        .expect("resolve a missing record");
    assert_eq!(
        missing,
        OwnerResolution::NotDeliverable,
        "a missing subject is not deliverable"
    );

    // A non-UUID poe_record subject id cannot match any row: not deliverable, no error.
    let malformed = resolve_owner(&pool, kind::POE_RECORD, "not-a-uuid")
        .await
        .expect("a malformed id is not a hard error");
    assert_eq!(malformed, OwnerResolution::NotDeliverable);

    // An unrecognized kind has no resolver: a producer/consumer mismatch that is by
    // design not deliverable, NOT a transient error. It must resolve terminally so
    // the backstop stamps it past rather than re-claiming and re-failing forever.
    let bad_kind = resolve_owner(&pool, "not_a_real_kind", &Uuid::now_v7().to_string())
        .await
        .expect("an unknown kind is a terminal disposition, not an error");
    assert_eq!(
        bad_kind,
        OwnerResolution::NotDeliverable,
        "an unknown subject kind is not deliverable, never a propagated error"
    );
}

/// The fan-out reader claims un-fanned outbox rows as a set and, once stamped,
/// never returns them again. A second claim after stamping the whole batch sees
/// nothing left, and the stamped rows carry `fanned_out_at`.
#[tokio::test]
async fn claim_then_stamp_marks_each_row_exactly_once() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    const N: usize = 12;
    for i in 0..N {
        append_subject_event(&pool, "order", "alpha", "touched", &json!({ "i": i }))
            .await
            .expect("append");
    }

    // Drain in two passes, stamping each claimed row in its own transaction, and
    // collect the claimed ids to prove no row is claimed twice.
    let mut seen: Vec<Uuid> = Vec::new();
    loop {
        let mut tx = pool.begin().await.expect("begin");
        let batch = claim_unfanned(&mut tx, 5).await.expect("claim");
        if batch.is_empty() {
            tx.rollback().await.expect("rollback empty");
            break;
        }
        for row in &batch {
            seen.push(row.id);
            stamp_fanned_out(&mut tx, row.id).await.expect("stamp");
        }
        tx.commit().await.expect("commit batch");
    }

    // Every appended row was claimed exactly once.
    assert_eq!(seen.len(), N, "every un-fanned row is claimed");
    let distinct: BTreeSet<Uuid> = seen.iter().copied().collect();
    assert_eq!(distinct.len(), N, "no row is claimed twice across passes");

    // Nothing remains un-fanned, and every outbox row is stamped.
    let unfanned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.delivery_outbox WHERE fanned_out_at IS NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("count un-fanned");
    assert_eq!(unfanned, 0, "no un-fanned rows remain after the drain");
}

/// A crash between claim and commit leaves the row un-fanned and re-claimable: a
/// claiming transaction that rolls back without stamping does not consume the row,
/// and a later pass picks it up and stamps it exactly once. This is the no-wedge,
/// no-skip, no-double-fan property: there is no sequence cursor to wedge on.
#[tokio::test]
async fn rolled_back_claim_does_not_consume_the_row() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let ev = append_subject_event(&pool, "order", "beta", "touched", &json!({}))
        .await
        .expect("append");
    let outbox_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM cw_core.delivery_outbox \
         WHERE subject_kind = $1 AND subject_id = $2 AND subject_seq = $3",
    )
    .bind(&ev.subject_kind)
    .bind(&ev.subject_id)
    .bind(ev.subject_seq)
    .fetch_one(&pool)
    .await
    .expect("locate outbox row");

    // A pass that claims and stamps but then rolls back (a crash before commit)
    // leaves the row un-fanned.
    {
        let mut tx = pool.begin().await.expect("begin");
        let batch = claim_unfanned(&mut tx, 10).await.expect("claim");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].id, outbox_id);
        stamp_fanned_out(&mut tx, outbox_id).await.expect("stamp");
        tx.rollback().await.expect("rollback (simulated crash)");
    }

    // The stamp was rolled back with the transaction; the row is still claimable.
    let still_unfanned: bool = sqlx::query_scalar(
        "SELECT fanned_out_at IS NULL FROM cw_core.delivery_outbox WHERE id = $1",
    )
    .bind(outbox_id)
    .fetch_one(&pool)
    .await
    .expect("read marker");
    assert!(
        still_unfanned,
        "a rolled-back claim must not stamp the row; it stays un-fanned"
    );

    // A second pass re-claims it and commits the stamp; now it is fanned out.
    {
        let mut tx = pool.begin().await.expect("begin");
        let batch = claim_unfanned(&mut tx, 10).await.expect("re-claim");
        assert_eq!(batch.len(), 1, "the un-fanned row is re-claimable");
        assert_eq!(batch[0].id, outbox_id);
        stamp_fanned_out(&mut tx, outbox_id).await.expect("stamp");
        tx.commit().await.expect("commit");
    }

    let unfanned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.delivery_outbox WHERE fanned_out_at IS NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("count un-fanned");
    assert_eq!(
        unfanned, 0,
        "the row is fanned out exactly once after replay"
    );
}

/// Concurrent claim passes get disjoint batches and, after stamping, every row is
/// fanned out exactly once. `FOR UPDATE SKIP LOCKED` means a row locked by one
/// pass is skipped by the other, so the two passes never double-process a row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_passes_claim_disjoint_sets() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = Arc::new(db.pool_with(8).await.expect("pool"));

    const N: usize = 40;
    for i in 0..N {
        // Spread across several subjects so the outbox holds N independent rows.
        let subject = format!("s{}", i % 5);
        append_subject_event(
            pool.as_ref(),
            "order",
            &subject,
            "touched",
            &json!({ "i": i }),
        )
        .await
        .expect("append");
    }

    // Two workers drain concurrently. Each claims a small batch per transaction,
    // stamps it, and commits, until the un-fanned set is empty.
    async fn drain(pool: Arc<sqlx::PgPool>) -> Vec<Uuid> {
        let mut claimed = Vec::new();
        loop {
            let mut tx = pool.begin().await.expect("begin");
            let batch = claim_unfanned(&mut tx, 3).await.expect("claim");
            if batch.is_empty() {
                tx.rollback().await.expect("rollback empty");
                break;
            }
            for row in &batch {
                claimed.push(row.id);
                stamp_fanned_out(&mut tx, row.id).await.expect("stamp");
            }
            tx.commit().await.expect("commit");
        }
        claimed
    }

    let a = tokio::spawn(drain(Arc::clone(&pool)));
    let b = tokio::spawn(drain(Arc::clone(&pool)));
    let mut all = a.await.expect("worker a");
    all.extend(b.await.expect("worker b"));

    // Across both workers, every row was claimed exactly once (disjoint sets).
    assert_eq!(
        all.len(),
        N,
        "every row claimed exactly once across workers"
    );
    let distinct: BTreeSet<Uuid> = all.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        N,
        "no row was claimed by both workers (SKIP LOCKED disjointness)"
    );

    let unfanned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.delivery_outbox WHERE fanned_out_at IS NULL",
    )
    .fetch_one(pool.as_ref())
    .await
    .expect("count un-fanned");
    assert_eq!(unfanned, 0, "the whole set is fanned out exactly once");
}

/// A transient owner-lookup failure (a database error) is NOT a poison row: it
/// propagates out of `explode_outbox_row` so the fan-out transaction rolls back
/// and the still-un-fanned row is retried, never terminally stamped with zero
/// deliveries on a momentary blip. This pins the typed line between
/// [`OwnerResolution::NotDeliverable`] (a terminal stamp-past) and an operational
/// `Err` (a propagate-and-retry).
#[tokio::test]
async fn a_transient_owner_lookup_error_leaves_the_row_unfanned_for_retry() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    // Append an event on a real operator subject so the resolver WOULD find an owner
    // under normal conditions. The transient failure, not a missing subject, is what
    // we are exercising.
    let operator_id = seed_operator(&pool, "op").await;
    append_subject_event(
        &pool,
        kind::OPERATOR,
        &operator_id.to_string(),
        "webhook.endpoint_disabled",
        &json!({ "endpoint_id": Uuid::now_v7().to_string(), "reason": "stale" }),
    )
    .await
    .expect("append operator event");

    let outbox_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM cw_core.delivery_outbox \
         WHERE subject_kind = $1 AND subject_id = $2",
    )
    .bind(kind::OPERATOR)
    .bind(operator_id.to_string())
    .fetch_one(&pool)
    .await
    .expect("locate outbox row");

    // Inject a transient database fault on the resolver's read path: rename the table
    // the operator resolver queries so its `SELECT` raises a `sqlx::Error`
    // (Error::Database), exactly as a connection blip or a momentary unavailability
    // would. This stands in for any non-deterministic operational failure.
    sqlx::query("ALTER TABLE cw_core.operator RENAME TO operator_unavailable")
        .execute(&pool)
        .await
        .expect("simulate a transient operator-table outage");

    // Claim and try to explode the row inside a transaction. The owner lookup now
    // fails operationally, so explode_outbox_row must surface an Err rather than
    // stamping the row past.
    let result = {
        let mut tx = pool.begin().await.expect("begin");
        let batch = claim_unfanned(&mut tx, 10).await.expect("claim");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].id, outbox_id);
        let result = explode_outbox_row(&pool, &mut tx, &batch[0]).await;
        // A real worker would roll back its transaction on the error; mirror that so
        // the un-fanned state is what the next pass would see.
        tx.rollback().await.expect("rollback on transient error");
        result
    };
    assert!(
        result.is_err(),
        "a transient owner-lookup failure propagates rather than stamping the row past"
    );

    // Restore the table so the row is deliverable again, exactly as the next tick
    // would find it once the blip clears.
    sqlx::query("ALTER TABLE cw_core.operator_unavailable RENAME TO operator")
        .execute(&pool)
        .await
        .expect("restore the operator table");

    // The row was never stamped: it is still un-fanned and re-claimable.
    let still_unfanned: bool = sqlx::query_scalar(
        "SELECT fanned_out_at IS NULL FROM cw_core.delivery_outbox WHERE id = $1",
    )
    .bind(outbox_id)
    .fetch_one(&pool)
    .await
    .expect("read marker");
    assert!(
        still_unfanned,
        "a transient owner-lookup error must not terminally stamp the row; it stays un-fanned for retry"
    );

    // A retry after the blip clears fans the row out normally (the typed line holds:
    // the transient error did not consume the row).
    let processed = FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("the retry fans the row out once the blip clears");
    assert_eq!(
        processed, 1,
        "the previously-un-fanned row is processed on retry"
    );
    let now_fanned: bool = sqlx::query_scalar(
        "SELECT fanned_out_at IS NOT NULL FROM cw_core.delivery_outbox WHERE id = $1",
    )
    .bind(outbox_id)
    .fetch_one(&pool)
    .await
    .expect("read marker");
    assert!(
        now_fanned,
        "the row fans out on the retry after the transient error clears"
    );
}

/// A fan-out `JobContext` for invoking [`FanoutHandler::handle`] directly. The
/// fan-out drain ignores the payload and attempt fields (it is a set-scan, not a
/// payload-driven job), so a minimal context is enough to exercise the handler's
/// error-to-outcome mapping.
fn fanout_ctx() -> JobContext {
    JobContext {
        job_id: Uuid::now_v7(),
        queue: "webhook_fanout".to_string(),
        payload: serde_json::Value::Null,
        attempt: 1,
        is_final_attempt: false,
        defer_count: 0,
    }
}

/// The same transient owner-lookup fault, surfaced at the JOB level: when
/// `explode_outbox_row` errors under the injected blip, [`FanoutHandler::handle`]
/// must return the retriable-failure outcome ([`JobOutcome::Fail`], which the
/// runtime retries while attempts remain), NOT a terminal [`JobOutcome::Complete`]
/// that would drop the un-fanned row. The row stays `fanned_out_at IS NULL` so the
/// retry can pick it up. This pins that the handler does not swallow an operational
/// error into a success.
#[tokio::test]
async fn a_transient_owner_lookup_error_makes_the_fanout_job_retriable() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    // A real operator subject so the resolver WOULD find an owner under normal
    // conditions: the transient failure, not a missing subject, is what we exercise.
    let operator_id = seed_operator(&pool, "op").await;
    append_subject_event(
        &pool,
        kind::OPERATOR,
        &operator_id.to_string(),
        "webhook.endpoint_disabled",
        &json!({ "endpoint_id": Uuid::now_v7().to_string(), "reason": "stale" }),
    )
    .await
    .expect("append operator event");

    let outbox_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM cw_core.delivery_outbox \
         WHERE subject_kind = $1 AND subject_id = $2",
    )
    .bind(kind::OPERATOR)
    .bind(operator_id.to_string())
    .fetch_one(&pool)
    .await
    .expect("locate outbox row");

    // Inject the same transient fault as the explode-level test: rename the table the
    // operator resolver reads so its `SELECT` raises a `sqlx::Error`, exactly as a
    // connection blip or a momentary unavailability would.
    sqlx::query("ALTER TABLE cw_core.operator RENAME TO operator_unavailable")
        .execute(&pool)
        .await
        .expect("simulate a transient operator-table outage");

    // Drive the whole handler (not just explode_outbox_row): the fan-out pass hits the
    // operational error and must report it as a retriable failure.
    let outcome = FanoutHandler::new(pool.clone()).handle(fanout_ctx()).await;
    assert!(
        matches!(outcome, JobOutcome::Fail { .. }),
        "a transient owner-lookup failure must surface as a retriable JobOutcome::Fail \
         (the runtime retries it), not a terminal Complete that would drop the row, got {outcome:?}"
    );

    // The handler rolled its transaction back on the error: the row was never stamped
    // and is still un-fanned, so the retry will pick it up.
    let still_unfanned: bool = sqlx::query_scalar(
        "SELECT fanned_out_at IS NULL FROM cw_core.delivery_outbox WHERE id = $1",
    )
    .bind(outbox_id)
    .fetch_one(&pool)
    .await
    .expect("read marker");
    assert!(
        still_unfanned,
        "a failed fan-out job must not stamp the row; it stays un-fanned for the retry"
    );

    // Once the blip clears, the retried job completes and fans the row out — proving the
    // Fail was a transient retry, not a terminal drop.
    sqlx::query("ALTER TABLE cw_core.operator_unavailable RENAME TO operator")
        .execute(&pool)
        .await
        .expect("restore the operator table");

    let retry = FanoutHandler::new(pool.clone()).handle(fanout_ctx()).await;
    assert!(
        matches!(retry, JobOutcome::Complete),
        "the retried fan-out job completes once the transient fault clears, got {retry:?}"
    );
    let now_fanned: bool = sqlx::query_scalar(
        "SELECT fanned_out_at IS NOT NULL FROM cw_core.delivery_outbox WHERE id = $1",
    )
    .bind(outbox_id)
    .fetch_one(&pool)
    .await
    .expect("read marker");
    assert!(
        now_fanned,
        "the row fans out on the job-level retry after the transient error clears"
    );
}

/// The delivery envelope carries an explicit `account_id` routing field for an
/// account subject (the subject id IS the account) and a `poe_record` subject (the
/// account that published the record), plus a `subject_id` field, so a receiver
/// routes by a documented member rather than parsing the composite Webhook-Id.
#[tokio::test]
async fn the_delivery_envelope_carries_an_explicit_account_id_and_subject_id() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool, "op").await;
    let account = seed_account(&db.pool, op).await;
    let record = seed_poe_record(&db.pool, op, Some(account)).await;

    let now = chrono::Utc::now();

    // An account subject: the envelope's account_id is the account itself, and the
    // subject_id is the raw account id (not a poe id).
    let account_row = ClaimedOutboxRow {
        id: Uuid::now_v7(),
        subject_kind: kind::ACCOUNT.to_string(),
        subject_id: account.to_string(),
        subject_seq: 1,
        event_type: "balance.changed".to_string(),
        payload: json!({ "amount_micros": 5_000_000 }),
        created_at: now,
    };
    let account_owner = resolved_owner(&db.pool, kind::ACCOUNT, &account.to_string()).await;
    let env = build_envelope(
        &db.pool,
        &account_row,
        "account:abc:1:endpoint",
        "balance_changed",
        account_owner.account_id,
    )
    .await
    .expect("build account envelope");
    assert_eq!(
        env["account_id"],
        json!(gateway_core::api::ids::encode_account_id(account)),
        "an account subject's envelope account_id is the account"
    );
    assert_eq!(env["subject_id"], json!(account.to_string()));
    // The prior fields are unchanged (additive widening).
    assert_eq!(env["id"], json!("account:abc:1:endpoint"));
    assert_eq!(env["type"], json!("balance_changed"));
    assert!(env.get("data").is_some());

    // A poe_record subject: the envelope's account_id is the record's owner, and
    // the subject_id is the wire-encoded poe id.
    let poe_row = ClaimedOutboxRow {
        id: Uuid::now_v7(),
        subject_kind: kind::POE_RECORD.to_string(),
        subject_id: record.to_string(),
        subject_seq: 1,
        event_type: "submitted".to_string(),
        payload: json!({}),
        created_at: now,
    };
    let poe_owner = resolved_owner(&db.pool, kind::POE_RECORD, &record.to_string()).await;
    let env = build_envelope(
        &db.pool,
        &poe_row,
        "poe_record:abc:1:endpoint",
        "poe_status_changed",
        poe_owner.account_id,
    )
    .await
    .expect("build poe envelope");
    assert_eq!(
        env["account_id"],
        json!(gateway_core::api::ids::encode_account_id(account)),
        "a poe subject's envelope account_id is the publishing account"
    );
    assert_eq!(
        env["subject_id"],
        json!(gateway_core::api::ids::encode_poe_id(record)),
        "a poe subject's subject_id is the wire poe id"
    );
}

/// Regression: a transient balance-read error in the fan-out must NOT freeze a
/// signed `balance_changed` body reporting balance 0.
///
/// `balance_snapshot` once coerced any DB error to `Ok(0)` via `unwrap_or(0)`, so a
/// momentary outage of `cw_core.balance` during fan-out committed and then signed an
/// authentic-looking zero-balance event. The fix makes the snapshot fallible: a
/// transient read error propagates through `build_envelope`, aborting the explode
/// transaction so the still-un-fanned outbox row is retried instead of freezing a
/// false signed zero. This pins both halves: the read error aborts the explode (no
/// delivery row frozen), and after recovery the body carries the real balance.
#[tokio::test]
async fn a_transient_balance_read_never_freezes_a_signed_zero_balance_body() {
    let db = TestDb::fresh().await.expect("fresh db");
    let pool = db.pool.clone();
    let op = seed_operator(&pool, "op").await;
    let account = seed_account(&pool, op).await;

    // The account has a real, non-zero balance: a fabricated zero would be plainly
    // wrong.
    sqlx::query("INSERT INTO cw_core.balance (account_id, balance_micros) VALUES ($1, 7000000)")
        .bind(account)
        .execute(&pool)
        .await
        .expect("seed balance");

    // A live subscription must exist so the explode actually builds (and signs) a
    // body — the snapshot read that swallowed the error is only reached when there is
    // a matching endpoint to deliver to.
    let ep = seed_account_endpoint(&pool, account, "https://x/").await;

    // Append a balance.changed event so there is an un-fanned outbox row to explode.
    append_subject_event(
        &pool,
        "account",
        &account.to_string(),
        "balance.changed",
        &json!({ "amount_micros": -1_000_000 }),
    )
    .await
    .expect("append balance event");

    // Claim the un-fanned outbox row.
    let row = {
        let mut tx = pool.begin().await.expect("begin claim");
        let batch = claim_unfanned(&mut tx, 10).await.expect("claim");
        tx.commit().await.expect("commit claim");
        batch.into_iter().next().expect("one un-fanned row")
    };

    // Make the balance table transiently unavailable, exactly as a connection blip
    // would for the snapshot read.
    sqlx::query("ALTER TABLE cw_core.balance RENAME TO balance_unavailable")
        .execute(&pool)
        .await
        .expect("simulate a transient balance outage");

    // Exploding the row must ERROR (so the fan-out transaction rolls back) rather
    // than committing a delivery row carrying a fabricated zero-balance body.
    let result = {
        let mut tx = pool.begin().await.expect("begin explode");
        let r = explode_outbox_row(&pool, &mut tx, &row).await;
        // Roll back regardless: a real fan-out would roll back on the propagated Err.
        tx.rollback().await.expect("rollback");
        r
    };
    assert!(
        result.is_err(),
        "a transient balance-read error must abort the fan-out, not freeze a zero-balance body"
    );

    // No delivery row was frozen, and the outbox row is still un-fanned (retriable).
    let frozen: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
            .bind(ep)
            .fetch_one(&pool)
            .await
            .expect("count frozen deliveries");
    assert_eq!(
        frozen, 0,
        "no delivery body was frozen on the transient error"
    );
    let still_unfanned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.delivery_outbox \
         WHERE subject_id = $1 AND fanned_out_at IS NULL",
    )
    .bind(account.to_string())
    .fetch_one(&pool)
    .await
    .expect("count un-fanned");
    assert_eq!(
        still_unfanned, 1,
        "the row is still un-fanned and will retry"
    );

    // The blip clears: fan out for real; the delivered body carries the real balance,
    // never a swallowed zero.
    sqlx::query("ALTER TABLE cw_core.balance_unavailable RENAME TO balance")
        .execute(&pool)
        .await
        .expect("restore the balance table");
    FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("fan out after recovery");
    let body: serde_json::Value =
        sqlx::query_scalar("SELECT body FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
            .bind(ep)
            .fetch_one(&pool)
            .await
            .expect("delivered body");
    assert_eq!(
        body["data"]["balance_usd_micros"],
        json!("7000000"),
        "the recovered body carries the real balance, never a swallowed zero"
    );
}

/// Regression: a transient PoE-record-read error in the fan-out must NOT freeze a
/// stripped id-only `poe_status_changed` body.
///
/// `poe_snapshot` once swallowed any DB error with `.ok().flatten()` and returned a
/// minimal `{ "id": ... }` payload, so a momentary outage of `cw_core.poe_record`
/// during fan-out committed and signed a status event missing tx_hash, status,
/// confirmations, and request_id. The fix makes the snapshot fallible: a transient
/// read error propagates and aborts the explode so the row is retried, rather than
/// freezing a degraded payload presented as a real status change.
#[tokio::test]
async fn a_transient_poe_read_never_freezes_a_stripped_status_body() {
    let db = TestDb::fresh().await.expect("fresh db");
    let pool = db.pool.clone();
    let op = seed_operator(&pool, "op").await;
    let account = seed_account(&pool, op).await;
    let record = seed_poe_record(&pool, op, Some(account)).await;
    let ep = seed_account_endpoint(&pool, account, "https://x/").await;

    append_subject_event(
        &pool,
        "poe_record",
        &record.to_string(),
        "confirmed",
        &json!({}),
    )
    .await
    .expect("append poe event");

    let row = {
        let mut tx = pool.begin().await.expect("begin claim");
        let batch = claim_unfanned(&mut tx, 10).await.expect("claim");
        tx.commit().await.expect("commit claim");
        batch.into_iter().next().expect("one un-fanned row")
    };

    // Make the record table transiently unavailable: both the owner resolution and
    // the body snapshot read `poe_record`, so a blip on either aborts the fan-out.
    sqlx::query("ALTER TABLE cw_core.poe_record RENAME TO poe_record_unavailable")
        .execute(&pool)
        .await
        .expect("simulate a transient poe_record outage");

    let result = {
        let mut tx = pool.begin().await.expect("begin explode");
        let r = explode_outbox_row(&pool, &mut tx, &row).await;
        tx.rollback().await.expect("rollback");
        r
    };
    assert!(
        result.is_err(),
        "a transient poe_record-read error must abort the fan-out, not freeze a stripped body"
    );

    let frozen: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
            .bind(ep)
            .fetch_one(&pool)
            .await
            .expect("count frozen deliveries");
    assert_eq!(
        frozen, 0,
        "no stripped delivery body was frozen on the transient error"
    );

    // After recovery the fan-out builds a complete body carrying the real status,
    // proving the snapshot path is exercised end to end (not just owner resolution).
    sqlx::query("ALTER TABLE cw_core.poe_record_unavailable RENAME TO poe_record")
        .execute(&pool)
        .await
        .expect("restore the poe_record table");
    FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("fan out after recovery");
    let body: serde_json::Value =
        sqlx::query_scalar("SELECT body FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
            .bind(ep)
            .fetch_one(&pool)
            .await
            .expect("delivered body");
    assert_eq!(
        body["data"]["id"],
        json!(gateway_core::api::ids::encode_poe_id(record)),
        "the recovered body carries the record's wire id"
    );
    assert!(
        body["data"].get("status").is_some(),
        "the recovered body carries the full status snapshot, not a stripped id-only payload"
    );
}

/// An operator-only subject (a `poe_record` published with no account owner) has a
/// null envelope `account_id`: there is no owning account to route to.
#[tokio::test]
async fn an_operator_only_poe_record_envelope_has_a_null_account_id() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool, "op").await;
    let record = seed_poe_record(&db.pool, op, None).await;

    let row = ClaimedOutboxRow {
        id: Uuid::now_v7(),
        subject_kind: kind::POE_RECORD.to_string(),
        subject_id: record.to_string(),
        subject_seq: 1,
        event_type: "submitted".to_string(),
        payload: json!({}),
        created_at: chrono::Utc::now(),
    };
    let owner = resolved_owner(&db.pool, kind::POE_RECORD, &record.to_string()).await;
    assert_eq!(
        owner.account_id, None,
        "an operator-direct record resolves with no owning account"
    );
    let env = build_envelope(
        &db.pool,
        &row,
        "poe_record:abc:1:endpoint",
        "poe_status_changed",
        owner.account_id,
    )
    .await
    .expect("build operator-direct poe envelope");
    assert_eq!(
        env["account_id"],
        serde_json::Value::Null,
        "an operator-direct record has no owning account"
    );
}

/// Regression: a transient PoE-owner lookup error must NOT freeze a signed envelope
/// with `account_id: null` for an account-owned record.
///
/// The envelope's `account_id` once came from a second, best-effort `poe_record`
/// lookup inside the body builder that swallowed any error to `None`. A momentary DB
/// blip on that read therefore signed and delivered an immutable body claiming an
/// account-owned PoE had no owning account, unrecoverably mis-routing it. The fix
/// removes that second lookup: the envelope reuses the owner the fan-out already
/// resolved (with full error propagation), so a transient lookup error aborts the
/// whole fan-out for retry before any body is built. This test pins both halves: a
/// transient `poe_record` outage makes owner resolution error (it can never yield a
/// spurious `None`), while a genuinely operator-only record still resolves to a
/// legitimate `None`.
#[tokio::test]
async fn a_transient_poe_lookup_never_signs_a_null_account_owned_envelope() {
    let db = TestDb::fresh().await.expect("fresh db");
    let pool = db.pool.clone();
    let op = seed_operator(&pool, "op").await;
    let account = seed_account(&pool, op).await;
    let owned_record = seed_poe_record(&pool, op, Some(account)).await;
    let operator_only_record = seed_poe_record(&pool, op, None).await;

    // Make the table the PoE owner resolver reads transiently unavailable, exactly as
    // a connection blip would.
    sqlx::query("ALTER TABLE cw_core.poe_record RENAME TO poe_record_unavailable")
        .execute(&pool)
        .await
        .expect("simulate a transient poe_record outage");

    // Owner resolution for the account-owned record now ERRORS rather than yielding a
    // spurious `None`: the only path that could have produced a null account_id under
    // the old best-effort lookup. With no `None` to encode, no null-account envelope
    // can ever be signed for an account-owned subject.
    let resolution = resolve_owner(&pool, kind::POE_RECORD, &owned_record.to_string()).await;
    assert!(
        resolution.is_err(),
        "a transient poe_record outage must surface as an Err, never a spurious no-owner resolution"
    );

    // Restore the table; the blip has cleared.
    sqlx::query("ALTER TABLE cw_core.poe_record_unavailable RENAME TO poe_record")
        .execute(&pool)
        .await
        .expect("restore the poe_record table");

    // After recovery the account-owned record resolves to its real account, and the
    // envelope carries the wire-encoded owner, never null.
    let owner = resolved_owner(&pool, kind::POE_RECORD, &owned_record.to_string()).await;
    assert_eq!(owner.account_id, Some(account));
    let owned_row = ClaimedOutboxRow {
        id: Uuid::now_v7(),
        subject_kind: kind::POE_RECORD.to_string(),
        subject_id: owned_record.to_string(),
        subject_seq: 1,
        event_type: "submitted".to_string(),
        payload: json!({}),
        created_at: chrono::Utc::now(),
    };
    let env = build_envelope(
        &pool,
        &owned_row,
        "poe_record:abc:1:endpoint",
        "poe_status_changed",
        owner.account_id,
    )
    .await
    .expect("build owned poe envelope after recovery");
    assert_eq!(
        env["account_id"],
        json!(gateway_core::api::ids::encode_account_id(account)),
        "an account-owned record's envelope carries its real owner, never a swallowed null"
    );

    // A genuinely operator-only record still resolves to a legitimate null: "no
    // account" is distinct from "lookup errored".
    let operator_only =
        resolved_owner(&pool, kind::POE_RECORD, &operator_only_record.to_string()).await;
    assert_eq!(
        operator_only.account_id, None,
        "an operator-only record legitimately has no owning account"
    );
    let operator_only_row = ClaimedOutboxRow {
        id: Uuid::now_v7(),
        subject_kind: kind::POE_RECORD.to_string(),
        subject_id: operator_only_record.to_string(),
        subject_seq: 1,
        event_type: "submitted".to_string(),
        payload: json!({}),
        created_at: chrono::Utc::now(),
    };
    let operator_only_env = build_envelope(
        &pool,
        &operator_only_row,
        "poe_record:def:1:endpoint",
        "poe_status_changed",
        operator_only.account_id,
    )
    .await
    .expect("build operator-only poe envelope");
    assert_eq!(
        operator_only_env["account_id"],
        serde_json::Value::Null,
        "an operator-only record's envelope account_id is legitimately null"
    );
}

/// A fan-out pass that materialises delivery rows wakes the delivery worker in
/// the same transaction: a `webhook_delivery` wake job exists, due immediately,
/// without waiting for the fallback cron tick. Paired with the append-side
/// fan-out wake, this is what carries a lifecycle event from outbox to POST at
/// NOTIFY latency instead of up to two cron intervals.
#[tokio::test]
async fn a_fanout_pass_wakes_the_delivery_worker_without_the_cron() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    // A subscribed account so the explode actually materialises a delivery row.
    let operator_id = seed_operator(&pool, "wake-op").await;
    let account_id = seed_account(&pool, operator_id).await;
    seed_account_endpoint(&pool, account_id, "https://receiver.example/hook").await;
    append_subject_event(
        &pool,
        kind::ACCOUNT,
        &account_id.to_string(),
        "balance.changed",
        &json!({ "balance": "1" }),
    )
    .await
    .expect("append the event");

    let processed = FanoutHandler::new(pool.clone())
        .run_once()
        .await
        .expect("the fan-out pass runs");
    assert!(processed >= 1, "the pass fanned the outbox row out");

    let delivery_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.webhook_delivery")
        .fetch_one(&pool)
        .await
        .expect("count delivery rows");
    assert!(delivery_rows >= 1, "the pass materialised a delivery row");

    let wake: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT run_at FROM cw_core.job \
         WHERE queue = $1 AND singleton_key = $2 AND state = 'available'",
    )
    .bind(gateway_core::webhook::DELIVERY_QUEUE)
    .bind(gateway_core::runtime::enqueue::WAKE_SINGLETON_KEY)
    .fetch_optional(&pool)
    .await
    .expect("read the delivery wake job");
    let run_at = wake.expect("the fan-out pass enqueued a delivery wake job");
    assert!(
        run_at <= chrono::Utc::now(),
        "the delivery wake is due immediately, never deferred to a cron tick"
    );
}
