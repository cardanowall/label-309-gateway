//! Integration tests for durable subject events and the delivery outbox.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Each test stands up an isolated, freshly migrated database via the harness.

#![cfg(feature = "pg-tests")]

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::json;

use gateway_core::events::append_subject_event;
use gateway_core::maintenance::partitions::{ensure_ahead, PartitionWindow, PartitionedTable};
use gateway_core::testsupport::TestDb;

/// 20 concurrent appends to ONE subject produce exactly the sequences 1..=20,
/// with no gaps and no duplicates, while a second subject's appends interleave
/// without affecting the first subject's numbering.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_appends_to_one_subject_are_gapless_and_unique() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = Arc::new(db.pool.clone());

    const N: i64 = 20;

    // Fire N appends at the same subject and N at a different subject, all
    // concurrently, so the two subjects' allocations interleave in time.
    let mut handles = Vec::new();
    for i in 0..N {
        let pool_alpha = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            append_subject_event(
                pool_alpha.as_ref(),
                "order",
                "alpha",
                "touched",
                &json!({ "i": i }),
            )
            .await
            .expect("append to subject alpha")
            .subject_seq
        }));

        let pool_beta = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            append_subject_event(
                pool_beta.as_ref(),
                "order",
                "beta",
                "touched",
                &json!({ "i": i }),
            )
            .await
            .expect("append to subject beta")
            .subject_seq
        }));
    }
    for h in handles {
        h.await.expect("append task should not panic");
    }

    // Each subject independently got exactly the contiguous run 1..=N.
    for subject in ["alpha", "beta"] {
        let seqs: Vec<i64> = sqlx::query_scalar(
            "SELECT subject_seq FROM cw_core.subject_event \
             WHERE subject_kind = 'order' AND subject_id = $1 \
             ORDER BY subject_seq",
        )
        .bind(subject)
        .fetch_all(pool.as_ref())
        .await
        .expect("read sequences");

        assert_eq!(
            seqs,
            (1..=N).collect::<Vec<_>>(),
            "subject {subject} must hold exactly 1..={N} with no gaps or dupes"
        );
        // Cross-check: the set has full cardinality (no duplicate slipped past
        // the ORDER BY).
        let distinct: BTreeSet<i64> = seqs.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            N as usize,
            "subject {subject} has duplicates"
        );
    }

    // One outbox row per appended event per subject (2 * N total).
    let outbox_total: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.delivery_outbox")
        .fetch_one(pool.as_ref())
        .await
        .expect("count outbox");
    assert_eq!(outbox_total, 2 * N);
}

/// A resume query (`subject_seq > last_seen`) returns exactly the events a
/// consumer missed, in order.
#[tokio::test]
async fn resume_after_last_seen_returns_exactly_the_missed_events() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    for i in 1..=5 {
        append_subject_event(&pool, "doc", "x1", "rev", &json!({ "n": i }))
            .await
            .expect("append");
    }

    // Consumer last saw seq 2; it should resume with seqs 3, 4, 5.
    let resumed: Vec<i64> = sqlx::query_scalar(
        "SELECT subject_seq FROM cw_core.subject_event \
         WHERE subject_kind = 'doc' AND subject_id = 'x1' AND subject_seq > $1 \
         ORDER BY subject_seq",
    )
    .bind(2_i64)
    .fetch_all(&pool)
    .await
    .expect("resume query");

    assert_eq!(resumed, vec![3, 4, 5]);
}

/// The append API allocates the seq inside the caller's transaction: if the
/// caller's transaction rolls back, no event and no outbox row survive, and the
/// next committed append reuses the sequence (the rolled-back number left no
/// gap).
#[tokio::test]
async fn append_is_atomic_with_the_callers_transaction() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    // First, a committed append reaches seq 1.
    let first = append_subject_event(&pool, "tx", "s", "e", &json!({}))
        .await
        .expect("committed append");
    assert_eq!(first.subject_seq, 1);

    // An append inside a transaction that is then rolled back.
    {
        let mut txn = pool.begin().await.expect("begin");
        let inside = append_subject_event(&mut *txn, "tx", "s", "e", &json!({}))
            .await
            .expect("append inside txn");
        assert_eq!(
            inside.subject_seq, 2,
            "seq is allocated as 2 inside the txn"
        );
        txn.rollback().await.expect("rollback");
    }

    // After rollback, that seq-2 row is gone; the next committed append takes 2.
    let next = append_subject_event(&pool, "tx", "s", "e", &json!({}))
        .await
        .expect("post-rollback append");
    assert_eq!(
        next.subject_seq, 2,
        "the rolled-back allocation must not leave a permanent gap"
    );

    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'tx' AND subject_id = 's'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(total, 2, "only the two committed events persist");
}

/// The outbox `dedupe_key` is unique per logical event, so an at-least-once
/// retry of the same append (same subject + same seq) cannot create a second
/// outbox row. We simulate the collision by attempting a manual duplicate
/// insert with the deterministic key and asserting the unique constraint bites.
#[tokio::test]
async fn outbox_dedupe_key_is_unique_per_event() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    let ev = append_subject_event(&pool, "dk", "s", "e", &json!({}))
        .await
        .expect("append");

    let dedupe = format!("{}:{}:{}", ev.subject_kind, ev.subject_id, ev.subject_seq);
    let dup = sqlx::query(
        "INSERT INTO cw_core.delivery_outbox \
         (id, subject_kind, subject_id, subject_seq, event_type, payload, dedupe_key) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(&ev.subject_kind)
    .bind(&ev.subject_id)
    .bind(ev.subject_seq)
    .bind(&ev.event_type)
    .bind(serde_json::json!({}))
    .bind(&dedupe)
    .execute(&pool)
    .await;

    assert!(
        dup.is_err(),
        "a second outbox row with the same dedupe_key must violate the unique constraint"
    );
}

/// The per-subject sequence is durable across retention pruning of the event
/// log. When the partition holding a subject's earlier events is dropped (the
/// retention path's `DROP TABLE`), a subsequent append must continue from the
/// subject's true high-water, not regress to 1. Regressing would re-mint a
/// `dedupe_key` the never-pruned `delivery_outbox` still holds, colliding on the
/// unique constraint and aborting the wrapping transaction.
#[tokio::test]
async fn sequence_survives_dropping_the_partition_that_held_earlier_events() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool.clone();

    const N: i64 = 5;
    for i in 1..=N {
        let ev = append_subject_event(
            &pool,
            "account",
            "long-silent",
            "balance.changed",
            &json!({ "i": i }),
        )
        .await
        .expect("append before pruning");
        assert_eq!(ev.subject_seq, i, "sequence climbs 1..=N before pruning");
    }

    // The leaf partition(s) currently holding this subject's events. Dropping
    // them models the retention path discarding a long-silent subject's history.
    let to_drop: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT tableoid::regclass::text \
         FROM cw_core.subject_event \
         WHERE subject_kind = 'account' AND subject_id = 'long-silent'",
    )
    .fetch_all(&pool)
    .await
    .expect("locate the subject's event partitions");
    assert!(
        !to_drop.is_empty(),
        "the subject's events must live in at least one partition"
    );
    for partition in &to_drop {
        // The partition name comes from the catalog (`regclass`), not user input.
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE {partition}")))
            .execute(&pool)
            .await
            .expect("drop the partition holding earlier events");
    }

    // The event rows are gone, so an allocator keyed on max(subject_event) would
    // now hand out seq 1 again. Prove the rows are actually gone.
    let surviving: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'account' AND subject_id = 'long-silent'",
    )
    .fetch_one(&pool)
    .await
    .expect("count surviving events");
    assert_eq!(
        surviving, 0,
        "the partition drop must remove the prior events"
    );

    // Retention only drops partitions older than the hot window; the current
    // month stays provisioned by the create-ahead pass, so a reactivating
    // subject always has a partition to land in. Re-provision it the same way.
    ensure_ahead(
        &pool,
        &PartitionedTable::new("cw_core.subject_event", "created_at"),
        PartitionWindow {
            create_ahead_months: 0,
            retain_months: 12,
        },
    )
    .await
    .expect("re-provision the current-month partition");

    // The next append continues monotonically from the durable high-water, and
    // its outbox row does not collide with the seq-1 row the old partition left
    // behind in delivery_outbox.
    let next = append_subject_event(
        &pool,
        "account",
        "long-silent",
        "balance.changed",
        &json!({ "reactivated": true }),
    )
    .await
    .expect("append after pruning must not collide on the outbox dedupe_key");
    assert_eq!(
        next.subject_seq,
        N + 1,
        "sequence must continue at N+1 after the partition drop, not regress to 1"
    );

    // The reactivated append produced a fresh outbox row keyed on the new seq;
    // the original seq-1..N rows are still present (delivery_outbox is never
    // pruned), so a regressed allocation would have failed the unique key.
    let outbox_seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT subject_seq FROM cw_core.delivery_outbox \
         WHERE subject_kind = 'account' AND subject_id = 'long-silent' \
         ORDER BY subject_seq",
    )
    .fetch_all(&pool)
    .await
    .expect("read outbox sequences");
    assert_eq!(
        outbox_seqs,
        (1..=N + 1).collect::<Vec<_>>(),
        "outbox holds the original 1..=N plus the reactivated N+1, with no collision"
    );
}

/// Appending an event wakes the webhook fan-out drain in the SAME transaction
/// as the outbox row: a `webhook_fanout` wake job (the shared wake singleton
/// key) exists, due immediately, without waiting for the fallback cron tick.
/// A burst of appends dedupes to ONE in-flight wake job. This is the regression
/// guard for the firehose latency defect where nothing ever enqueued a fan-out
/// job on an outbox write, so every lifecycle event waited for the next
/// minute-cadence cron tick (up to ~120s outbox-to-delivery).
#[tokio::test]
async fn an_appended_event_wakes_the_fanout_drain_without_the_cron() {
    let db = TestDb::fresh().await.expect("test database");

    append_subject_event(
        &db.pool,
        "poe",
        "wake-test",
        "status.changed",
        &json!({ "status": "submitted" }),
    )
    .await
    .expect("append the event");

    let wakes: Vec<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT singleton_key, run_at FROM cw_core.job \
         WHERE queue = $1 AND state = 'available'",
    )
    .bind(gateway_core::webhook::FANOUT_QUEUE)
    .fetch_all(&db.pool)
    .await
    .expect("read fan-out jobs");
    assert_eq!(
        wakes.len(),
        1,
        "the append enqueued exactly one fan-out wake job"
    );
    assert_eq!(
        wakes[0].0,
        gateway_core::runtime::enqueue::WAKE_SINGLETON_KEY,
        "the wake carries the shared wake singleton key"
    );
    assert!(
        wakes[0].1 <= chrono::Utc::now(),
        "the wake is due immediately, never deferred to a cron tick"
    );

    // A burst of further appends dedupes against the in-flight wake: still one.
    for i in 0..3 {
        append_subject_event(
            &db.pool,
            "poe",
            "wake-test",
            "status.changed",
            &json!({ "i": i }),
        )
        .await
        .expect("append another event");
    }
    let wake_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.job WHERE queue = $1 AND state = 'available'",
    )
    .bind(gateway_core::webhook::FANOUT_QUEUE)
    .fetch_one(&db.pool)
    .await
    .expect("count fan-out jobs");
    assert_eq!(
        wake_count, 1,
        "an event burst dedupes to one in-flight fan-out wake"
    );
}
