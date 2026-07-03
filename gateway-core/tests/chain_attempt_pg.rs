//! Integration coverage for the chain-effect ledger schema and the
//! `chain::attempt` row API.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! These assert the schema invariants the submit and confirm paths rely on:
//!
//! - The migration applies cleanly: the `chain_attempt` table and its
//!   unique/partial indexes exist on a freshly migrated database, `poe_record`
//!   carries `current_attempt_id`, and there is deliberately no
//!   created_at-keyed mempool index.
//! - `chain_attempt_one_active_per_record` admits exactly one active-broadcaster
//!   attempt (`recorded`/`broadcast`/`stuck`) per record, rejecting a second one,
//!   yet PERMITS a `superseded` original to coexist with its replacement, which is
//!   the precise shape the cancelling-replacement handoff needs.
//! - `chain_attempt_tx_hash_uk` rejects recording the same transaction twice, so
//!   a redelivered record-before-broadcast is an idempotent no-op.
//! - The `chain_attempt_subject` CHECK pins the kind/subject pairing (a publish
//!   names a record, a split names none).
//! - The lifecycle transitions (`mark_broadcast`, `mark_stuck`,
//!   `mark_superseded`) and the loaders round-trip an attempt's fields.

#![cfg(feature = "pg-tests")]

use gateway_core::chain::attempt::{
    self, AttemptInput, AttemptKind, AttemptOutput, AttemptStatus, NewAttempt,
};
use gateway_core::testsupport::TestDb;
use uuid::Uuid;

const NETWORK: &str = "preprod";

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

async fn seed_operator(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'test-op')")
        .bind(id)
        .execute(pool)
        .await
        .expect("insert operator");
    id
}

async fn seed_wallet(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet (id, registrar_operator_id, label, address, network) \
         VALUES ($1, $2, 'w', $3, $4)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(format!("addr_test_{id}"))
    .bind(NETWORK)
    .execute(pool)
    .await
    .expect("insert wallet");
    id
}

async fn seed_record(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record (id, operator_id, record_bytes) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(vec![0xa1_u8, 0x01, 0x82])
    .execute(pool)
    .await
    .expect("insert poe_record");
    id
}

/// Build a publish attempt over one input, with a distinct transaction hash so
/// the chain key is unique.
fn publish_attempt(record_id: Uuid, wallet_id: Uuid, marker: u8) -> NewAttempt {
    NewAttempt {
        id: Uuid::now_v7(),
        kind: AttemptKind::Publish,
        record_id: Some(record_id),
        wallet_id,
        tx_hash: [marker; 32],
        signed_tx: vec![marker, 0x01, 0x02],
        fee_lovelace: 169_197,
        spent_inputs: vec![AttemptInput {
            tx_hash: hex::encode([marker.wrapping_add(0x80); 32]),
            index: 0,
            lovelace: 5_000_000,
        }],
        produced_outputs: vec![AttemptOutput {
            index: 0,
            lovelace: 4_800_000,
        }],
        replaces_tx_hash: None,
    }
}

/// Whether a named index exists on a `cw_core` table.
async fn index_exists(pool: &sqlx::PgPool, index: &str) -> bool {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes WHERE schemaname = 'cw_core' AND indexname = $1",
    )
    .bind(index)
    .fetch_optional(pool)
    .await
    .expect("read index catalogue");
    found.is_some()
}

/// Record an attempt in its own transaction, surfacing the database error (so a
/// unique-index rejection is observable) rather than swallowing it.
async fn record(pool: &sqlx::PgPool, attempt: &NewAttempt) -> gateway_core::Result<Uuid> {
    let mut tx = pool.begin().await.expect("begin");
    let result = attempt::record_attempt_in_tx(&mut tx, attempt).await;
    match &result {
        Ok(_) => tx.commit().await.expect("commit"),
        Err(_) => tx.rollback().await.expect("rollback"),
    }
    result
}

/// Whether an error is a Postgres unique-violation (SQLSTATE 23505).
fn is_unique_violation(err: &gateway_core::Error) -> bool {
    matches!(
        err,
        gateway_core::Error::Database(sqlx::Error::Database(db))
            if db.code().as_deref() == Some("23505")
    )
}

// ---------------------------------------------------------------------------
// Migration shape
// ---------------------------------------------------------------------------

/// The migration applies cleanly: the chain-effect ledger and its indexes
/// exist, `poe_record` carries `current_attempt_id`, and there is deliberately
/// no created_at-keyed mempool index.
#[tokio::test]
async fn migration_creates_the_chain_attempt_schema() {
    let db = TestDb::fresh().await.expect("test database");

    // The new table is queryable and starts empty.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.chain_attempt")
        .fetch_one(&db.pool)
        .await
        .expect("count chain_attempt");
    assert_eq!(count, 0);

    for index in [
        "chain_attempt_one_active_per_record",
        "chain_attempt_tx_hash_uk",
        "chain_attempt_reconcile_idx",
        "chain_attempt_onchain_idx",
        "chain_attempt_superseded_by_idx",
        "chain_attempt_split_idx",
    ] {
        assert!(
            index_exists(&db.pool, index).await,
            "expected index {index} on a freshly migrated database"
        );
    }

    // poe_record carries the current_attempt_id projection join.
    let has_column: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = 'cw_core' AND table_name = 'poe_record' \
           AND column_name = 'current_attempt_id')",
    )
    .fetch_one(&db.pool)
    .await
    .expect("read poe_record columns");
    assert!(has_column, "poe_record must carry current_attempt_id");

    // The stale created_at-keyed mempool index is gone: reconcile keys on
    // chain_attempt.mempool_entered_at, and there is no cull-by-age path.
    assert!(
        !index_exists(&db.pool, "poe_record_mempool_idx").await,
        "poe_record_mempool_idx must be dropped"
    );
}

// ---------------------------------------------------------------------------
// One-active-broadcaster invariant — the durable CHAIN-1 backstop
// ---------------------------------------------------------------------------

/// A second active-broadcaster attempt for the same record is rejected by
/// `chain_attempt_one_active_per_record`. This is the durable half of the submit
/// generation claim: a redelivered first submit cannot mint a second
/// non-cancelling transaction for a record that already has one in flight.
#[tokio::test]
async fn one_active_index_rejects_a_second_active_attempt_for_a_record() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, operator).await;
    let record_id = seed_record(&db.pool, operator).await;

    // First active-broadcaster attempt records.
    let first = publish_attempt(record_id, wallet, 0x11);
    record(&db.pool, &first)
        .await
        .expect("first attempt records");

    // A second attempt for the same record, recorded (active broadcaster), is
    // rejected by the partial unique index.
    let second = publish_attempt(record_id, wallet, 0x22);
    let err = record(&db.pool, &second)
        .await
        .expect_err("second active attempt must be rejected");
    assert!(
        is_unique_violation(&err),
        "expected a unique-violation, got {err:?}"
    );

    // The first attempt is still the sole active broadcaster.
    let attempts = attempt::load_record_attempts(&db.pool, record_id)
        .await
        .expect("load attempts");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].id, first.id);
    assert_eq!(attempts[0].status, AttemptStatus::Recorded);
}

/// A `superseded` original is permitted to coexist with its replacement under the
/// one-active index: the original leaves the active-broadcaster set the instant
/// the replacement enters it. Both stay reconcilable (the original can still land
/// before the replacement does). This is the exact shape the cancelling-
/// replacement handoff records atomically.
#[tokio::test]
async fn superseded_original_coexists_with_its_replacement() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, operator).await;
    let record_id = seed_record(&db.pool, operator).await;

    // Record the original active-broadcaster attempt.
    let original = publish_attempt(record_id, wallet, 0x33);
    record(&db.pool, &original)
        .await
        .expect("original attempt records");

    // Build the replacement: a kind='replacement' attempt that re-spends the
    // original's input (so it conflicts) and points at the original tx.
    let mut replacement = publish_attempt(record_id, wallet, 0x44);
    replacement.kind = AttemptKind::Replacement;
    replacement.replaces_tx_hash = Some(original.tx_hash);
    replacement.spent_inputs = original.spent_inputs.clone();

    // The handoff is one transaction: supersede the original (it leaves the
    // active set) AND record the replacement (it enters the active set). Because
    // the original is superseded in the same transaction, the one-active partial
    // unique index is satisfied at every instant.
    let mut tx = db.pool.begin().await.expect("begin handoff");
    let superseded = attempt::mark_superseded(&mut tx, original.id, replacement.id)
        .await
        .expect("supersede original");
    assert!(superseded, "the active original must be superseded");
    attempt::record_attempt_in_tx(&mut tx, &replacement)
        .await
        .expect("record replacement in the same transaction");
    tx.commit().await.expect("commit handoff");

    // Both attempts survive and are reconcilable: the superseded original AND its
    // replacement. The replacement is the sole active broadcaster; the original is
    // superseded but still in the watch set.
    let attempts = attempt::load_record_attempts(&db.pool, record_id)
        .await
        .expect("load attempts");
    assert_eq!(attempts.len(), 2, "both attempts stay reconcilable");

    let loaded_original = attempt::load_attempt(&db.pool, original.id)
        .await
        .expect("load original")
        .expect("original exists");
    assert_eq!(loaded_original.status, AttemptStatus::Superseded);
    assert_eq!(loaded_original.superseded_by, Some(replacement.id));

    let loaded_replacement = attempt::load_attempt(&db.pool, replacement.id)
        .await
        .expect("load replacement")
        .expect("replacement exists");
    assert_eq!(loaded_replacement.status, AttemptStatus::Recorded);
    assert_eq!(loaded_replacement.kind, AttemptKind::Replacement);
    assert_eq!(
        loaded_replacement.replaces_tx_hash,
        Some(original.tx_hash),
        "the replacement links back to the original transaction"
    );

    // Now that the original is superseded, a fresh active-broadcaster attempt is
    // blocked again: the replacement holds the single active slot.
    let intruder = publish_attempt(record_id, wallet, 0x55);
    let err = record(&db.pool, &intruder)
        .await
        .expect_err("a third active attempt must be rejected");
    assert!(
        is_unique_violation(&err),
        "expected a unique-violation, got {err:?}"
    );
}

/// Two attempts for DIFFERENT records can both be active broadcasters: the
/// one-active index is scoped per record, not per wallet.
#[tokio::test]
async fn one_active_index_is_scoped_per_record() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, operator).await;
    let record_a = seed_record(&db.pool, operator).await;
    let record_b = seed_record(&db.pool, operator).await;

    record(&db.pool, &publish_attempt(record_a, wallet, 0x66))
        .await
        .expect("record A active");
    record(&db.pool, &publish_attempt(record_b, wallet, 0x77))
        .await
        .expect("record B active");
}

// ---------------------------------------------------------------------------
// Unique chain key + subject CHECK
// ---------------------------------------------------------------------------

/// Recording the same transaction twice is rejected by `chain_attempt_tx_hash_uk`,
/// so a redelivered record-before-broadcast is an idempotent no-op rather than a
/// duplicate ledger row.
#[tokio::test]
async fn tx_hash_unique_rejects_recording_the_same_transaction_twice() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, operator).await;
    let record_a = seed_record(&db.pool, operator).await;
    let record_b = seed_record(&db.pool, operator).await;

    let first = publish_attempt(record_a, wallet, 0x88);
    record(&db.pool, &first).await.expect("first records");

    // A different attempt id and different record, but the SAME tx_hash, collides
    // on the chain key.
    let mut clash = publish_attempt(record_b, wallet, 0x99);
    clash.tx_hash = first.tx_hash;
    let err = record(&db.pool, &clash)
        .await
        .expect_err("the same tx_hash must be rejected");
    assert!(
        is_unique_violation(&err),
        "expected a unique-violation, got {err:?}"
    );
}

/// The `chain_attempt_subject` CHECK pins the kind/subject pairing: a publish must
/// name a record, and a split must not.
#[tokio::test]
async fn subject_check_pins_the_kind_to_its_subject() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, operator).await;
    let record_id = seed_record(&db.pool, operator).await;

    // A publish with no record violates the subject CHECK.
    let mut publish_without_record = publish_attempt(record_id, wallet, 0xa1);
    publish_without_record.record_id = None;
    let err = record(&db.pool, &publish_without_record)
        .await
        .expect_err("a publish must name a record");
    assert!(
        matches!(
            &err,
            gateway_core::Error::Database(sqlx::Error::Database(db))
                if db.code().as_deref() == Some("23514")
        ),
        "expected a check-violation, got {err:?}"
    );

    // A split with a record also violates it (a split serves only its wallet).
    let split_with_record = NewAttempt {
        id: Uuid::now_v7(),
        kind: AttemptKind::Split,
        record_id: Some(record_id),
        wallet_id: wallet,
        tx_hash: [0xa2; 32],
        signed_tx: vec![0xa2],
        fee_lovelace: 0,
        spent_inputs: vec![],
        produced_outputs: vec![],
        replaces_tx_hash: None,
    };
    let err = record(&db.pool, &split_with_record)
        .await
        .expect_err("a split must not name a record");
    assert!(
        matches!(
            &err,
            gateway_core::Error::Database(sqlx::Error::Database(db))
                if db.code().as_deref() == Some("23514")
        ),
        "expected a check-violation, got {err:?}"
    );

    // A split with NO record records cleanly, serving only its wallet.
    let split = NewAttempt {
        id: Uuid::now_v7(),
        kind: AttemptKind::Split,
        record_id: None,
        wallet_id: wallet,
        tx_hash: [0xa3; 32],
        signed_tx: vec![0xa3],
        fee_lovelace: 0,
        spent_inputs: vec![AttemptInput {
            tx_hash: hex::encode([0xa4; 32]),
            index: 0,
            lovelace: 10_000_000,
        }],
        produced_outputs: vec![
            AttemptOutput {
                index: 0,
                lovelace: 4_900_000,
            },
            AttemptOutput {
                index: 1,
                lovelace: 4_900_000,
            },
        ],
        replaces_tx_hash: None,
    };
    record(&db.pool, &split).await.expect("split records");
    let loaded = attempt::load_attempt(&db.pool, split.id)
        .await
        .expect("load split")
        .expect("split exists");
    assert_eq!(loaded.kind, AttemptKind::Split);
    assert!(loaded.record_id.is_none());
    assert_eq!(loaded.produced_outputs.len(), 2);
}

// ---------------------------------------------------------------------------
// Lifecycle transitions and full-row round-trip
// ---------------------------------------------------------------------------

/// `mark_broadcast` advances a recorded attempt once and stamps its mempool entry;
/// `mark_stuck` then moves it to the operator-visible reconcile state. The
/// transitions are guarded, so a stale call is a benign no-op.
#[tokio::test]
async fn lifecycle_transitions_advance_and_round_trip_the_attempt() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, operator).await;
    let record_id = seed_record(&db.pool, operator).await;

    let new = publish_attempt(record_id, wallet, 0xb1);
    record(&db.pool, &new).await.expect("records");

    // recorded -> broadcast, stamping mempool_entered_at.
    assert!(attempt::mark_broadcast(&db.pool, new.id)
        .await
        .expect("mark_broadcast"));
    let after_broadcast = attempt::load_attempt(&db.pool, new.id)
        .await
        .expect("load")
        .expect("exists");
    assert_eq!(after_broadcast.status, AttemptStatus::Broadcast);
    assert!(
        after_broadcast.mempool_entered_at.is_some(),
        "broadcast stamps the mempool entry"
    );

    // A second mark_broadcast is a no-op: the attempt is no longer 'recorded'.
    assert!(
        !attempt::mark_broadcast(&db.pool, new.id)
            .await
            .expect("idempotent mark_broadcast"),
        "mark_broadcast only advances a recorded attempt"
    );

    // broadcast -> stuck (the alert/reconcile state, NOT a refund).
    assert!(attempt::mark_stuck(&db.pool, new.id)
        .await
        .expect("mark_stuck"));
    let after_stuck = attempt::load_attempt(&db.pool, new.id)
        .await
        .expect("load")
        .expect("exists");
    assert_eq!(after_stuck.status, AttemptStatus::Stuck);

    // The full row round-trips: every field the producers wrote reads back.
    assert_eq!(after_stuck.id, new.id);
    assert_eq!(after_stuck.kind, AttemptKind::Publish);
    assert_eq!(after_stuck.record_id, Some(record_id));
    assert_eq!(after_stuck.wallet_id, wallet);
    assert_eq!(after_stuck.tx_hash, new.tx_hash);
    assert_eq!(after_stuck.signed_tx, new.signed_tx);
    assert_eq!(after_stuck.fee_lovelace, new.fee_lovelace);
    assert_eq!(after_stuck.spent_inputs, new.spent_inputs);
    assert_eq!(after_stuck.produced_outputs, new.produced_outputs);
    assert_eq!(after_stuck.yield_count, 0);
    assert!(after_stuck.block_height.is_none());
}

/// `mark_superseded` only supersedes an active-broadcaster original. A call
/// against an already-superseded (or otherwise non-active) attempt affects zero
/// rows, so the handoff cannot double-supersede.
#[tokio::test]
async fn mark_superseded_only_acts_on_an_active_original() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, operator).await;
    let record_id = seed_record(&db.pool, operator).await;

    let original = publish_attempt(record_id, wallet, 0xc1);
    record(&db.pool, &original).await.expect("records");

    let mut replacement = publish_attempt(record_id, wallet, 0xc2);
    replacement.kind = AttemptKind::Replacement;
    replacement.replaces_tx_hash = Some(original.tx_hash);

    let mut tx = db.pool.begin().await.expect("begin");
    assert!(
        attempt::mark_superseded(&mut tx, original.id, replacement.id)
            .await
            .expect("first supersede")
    );
    // A second supersede in the same transaction is a no-op: the original is no
    // longer active.
    assert!(
        !attempt::mark_superseded(&mut tx, original.id, replacement.id)
            .await
            .expect("second supersede"),
        "an already-superseded attempt cannot be superseded again"
    );
    // Record the replacement the original now points at so the deferred
    // self-reference resolves at commit.
    attempt::record_attempt_in_tx(&mut tx, &replacement)
        .await
        .expect("record replacement");
    tx.commit().await.expect("commit");
}

/// `load_record_attempts` returns every non-terminal attempt and excludes
/// terminal ones, oldest first. A `superseded` original is included (still
/// reconcilable); a `confirmed`/`abandoned` attempt is not.
#[tokio::test]
async fn load_record_attempts_returns_the_non_terminal_watch_set() {
    let db = TestDb::fresh().await.expect("test database");
    let operator = seed_operator(&db.pool).await;
    let wallet = seed_wallet(&db.pool, operator).await;
    let record_id = seed_record(&db.pool, operator).await;

    // One superseded original.
    let original = publish_attempt(record_id, wallet, 0xd1);
    record(&db.pool, &original).await.expect("records original");
    let mut replacement = publish_attempt(record_id, wallet, 0xd2);
    replacement.kind = AttemptKind::Replacement;
    replacement.replaces_tx_hash = Some(original.tx_hash);
    let mut tx = db.pool.begin().await.expect("begin");
    attempt::mark_superseded(&mut tx, original.id, replacement.id)
        .await
        .expect("supersede");
    attempt::record_attempt_in_tx(&mut tx, &replacement)
        .await
        .expect("record replacement");
    tx.commit().await.expect("commit");

    // Both the superseded original and the active replacement are in the watch set.
    let watch = attempt::load_record_attempts(&db.pool, record_id)
        .await
        .expect("load watch set");
    assert_eq!(watch.len(), 2);
    // Oldest first: the original precedes its replacement.
    assert_eq!(watch[0].id, original.id);
    assert_eq!(watch[1].id, replacement.id);

    // Drive the replacement to a terminal status directly, then it drops out of
    // the watch set while the superseded original (still non-terminal) remains.
    sqlx::query("UPDATE cw_core.chain_attempt SET status = 'confirmed' WHERE id = $1")
        .bind(replacement.id)
        .execute(&db.pool)
        .await
        .expect("confirm replacement");
    let watch = attempt::load_record_attempts(&db.pool, record_id)
        .await
        .expect("reload watch set");
    assert_eq!(
        watch.len(),
        1,
        "a confirmed attempt drops out of the watch set"
    );
    assert_eq!(watch[0].id, original.id);
}
