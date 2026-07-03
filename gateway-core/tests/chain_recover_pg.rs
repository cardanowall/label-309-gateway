//! Integration coverage for the chain-attempt recovery sweep.
//!
//! The submission pipeline records a `chain_attempt` (`status='recorded'`) BEFORE
//! it broadcasts. If the broadcast fails before the projection learns it reached a
//! node (a provider 429 storm, a transport error, a malformed provider response, a
//! crash before the broadcast) the attempt stays `recorded` with
//! `mempool_entered_at IS NULL`, the submit job that owned it completes after its
//! retry budget, and nothing recovers it: the confirm authority's mempool reconcile
//! keys on `mempool_entered_at` (NULL here) and the publish-time submit enqueue is
//! gone. The record is stranded in `submitting` (balance debited, no tx on chain).
//!
//! These suites seed exactly that stranded state and drive the real
//! `ChainRecoverHandler` directly. The assertions are behavioural: the re-enqueued
//! `cardano_submit` job rows, the one-shot stranded alert, and the UNCHANGED
//! `chain_attempt`/`poe_record`/`wallet_utxo`/`refund_intent` end-states. The
//! through-lines are the locked recovery semantics:
//!
//!   - a stranded attempt past the grace gets a submit re-enqueued (the safe
//!     idempotent re-broadcast); a fresh recorded attempt within the grace is left
//!     alone;
//!   - the re-enqueue is idempotent (sweeping twice nets one job);
//!   - past the alert horizon the sweep raises a ONE-SHOT operator alert AND keeps
//!     re-enqueuing, but NEVER refunds, abandons, or restores inputs on age (a
//!     no-validity-interval tx may yet be in a mempool); the record stays live and
//!     the inputs stay reserved;
//!   - a confirmed/already-terminal record, or one that moved to a fresher
//!     generation, is untouched.
//!
//! The operator resolution lever for a stranded recorded attempt (the cancelling
//! replacement that produces the settlement-deep conflict proof) is covered in
//! `chain_confirm_pg.rs`.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::time::Duration;

use gateway_core::chain::attempt::{
    self, AttemptInput, AttemptKind, AttemptOutput, AttemptStatus, NewAttempt,
};
use gateway_core::chain::recover::{
    ChainRecoverConfig, ChainRecoverHandler, CHAIN_RECOVER_QUEUE, CHAIN_RECOVER_STRANDED_EVENT,
};
use gateway_core::chain::submit::{submit_policy, SUBMIT_QUEUE};
use gateway_core::testsupport::TestDb;
use uuid::Uuid;

const NETWORK: &str = "preprod";

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// A grace/alert config whose horizons a test can outrun by aging a row, so a suite
/// never sleeps: the grace is one second and the alert horizon one hour, and the
/// tests age `created_at` directly to land a row in the wanted window.
fn config() -> ChainRecoverConfig {
    ChainRecoverConfig {
        grace: Duration::from_secs(1),
        alert_after: Duration::from_secs(3600),
    }
}

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

/// Insert a `submitting` record under an operator, returning its id.
async fn seed_record(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, record_bytes, status, request_id) \
         VALUES ($1, $2, $3, 'submitting', 'req-1')",
    )
    .bind(id)
    .bind(operator_id)
    .bind(vec![0xa1_u8, 0x01, 0x82])
    .execute(pool)
    .await
    .expect("insert poe_record");
    id
}

/// Seed one `pending_spent` canonical UTxO for a wallet at `(tx_hash, index)`, the
/// state an attempt's recorded spend leaves its input in, so a test can assert the
/// sweep leaves it reserved (never restores it on age).
async fn seed_pending_spent_input(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    tx_hash: [u8; 32],
    output_index: i32,
    lovelace: i64,
) {
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, $3, $4, 'pending_spent', true, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(tx_hash.as_slice())
    .bind(output_index)
    .bind(lovelace)
    .execute(pool)
    .await
    .expect("insert pending_spent utxo");
}

/// Record a `recorded` attempt for a record and point the record at it
/// (`current_attempt_id`), the exact record-before-broadcast end-state a submit that
/// never reached the wire leaves behind. The attempt's single input is the
/// `(input_marker, 0)` reference, seeded `pending_spent`.
async fn seed_recorded_attempt(
    pool: &sqlx::PgPool,
    record_id: Uuid,
    wallet_id: Uuid,
    tx_marker: u8,
    input_marker: u8,
) -> Uuid {
    let attempt_id = Uuid::now_v7();
    let input_tx_hash = [input_marker; 32];
    seed_pending_spent_input(pool, wallet_id, input_tx_hash, 0, 5_000_000).await;

    let new_attempt = NewAttempt {
        id: attempt_id,
        kind: AttemptKind::Publish,
        record_id: Some(record_id),
        wallet_id,
        tx_hash: [tx_marker; 32],
        signed_tx: vec![tx_marker, 0x01, 0x02],
        fee_lovelace: 169_197,
        spent_inputs: vec![AttemptInput {
            tx_hash: hex::encode(input_tx_hash),
            index: 0,
            lovelace: 5_000_000,
        }],
        produced_outputs: vec![AttemptOutput {
            index: 0,
            lovelace: 4_800_000,
        }],
        replaces_tx_hash: None,
    };

    let mut tx = pool.begin().await.expect("begin");
    attempt::record_attempt_in_tx(&mut tx, &new_attempt)
        .await
        .expect("record attempt");
    tx.commit().await.expect("commit");

    sqlx::query("UPDATE cw_core.poe_record SET current_attempt_id = $2 WHERE id = $1")
        .bind(record_id)
        .bind(attempt_id)
        .execute(pool)
        .await
        .expect("point record at attempt");

    attempt_id
}

/// Record a `recorded` cancelling REPLACEMENT attempt naming `replaces_tx_hash`,
/// WITHOUT pointing the record at it. Returns the replacement's id. Used to build a
/// replacement chain: a `superseded` original plus its recorded replacement, the
/// state a rollback handoff leaves whose replacement recorded but the record pointer
/// was then cleared (here set up directly so a test can drive the sweep over it).
async fn seed_recorded_replacement(
    pool: &sqlx::PgPool,
    record_id: Uuid,
    wallet_id: Uuid,
    tx_marker: u8,
    input_marker: u8,
    replaces_tx_hash: [u8; 32],
) -> Uuid {
    let attempt_id = Uuid::now_v7();
    let input_tx_hash = [input_marker; 32];
    seed_pending_spent_input(pool, wallet_id, input_tx_hash, 0, 5_000_000).await;

    let new_attempt = NewAttempt {
        id: attempt_id,
        kind: AttemptKind::Replacement,
        record_id: Some(record_id),
        wallet_id,
        tx_hash: [tx_marker; 32],
        signed_tx: vec![tx_marker, 0x01, 0x02],
        fee_lovelace: 169_197,
        spent_inputs: vec![AttemptInput {
            tx_hash: hex::encode(input_tx_hash),
            index: 0,
            lovelace: 5_000_000,
        }],
        produced_outputs: vec![AttemptOutput {
            index: 0,
            lovelace: 4_800_000,
        }],
        replaces_tx_hash: Some(replaces_tx_hash),
    };

    let mut tx = pool.begin().await.expect("begin");
    attempt::record_attempt_in_tx(&mut tx, &new_attempt)
        .await
        .expect("record replacement");
    tx.commit().await.expect("commit");
    attempt_id
}

/// Record a stranded `kind='split'` attempt: a split records before broadcast and
/// advances its source to `pending_spent`, but the broadcast never reached the wire
/// (ambiguous submit / echo mismatch / crash), so it sits `recorded` with
/// `mempool_entered_at` NULL and NO record. Returns the attempt id.
async fn seed_recorded_split_attempt(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    tx_marker: u8,
    source_marker: u8,
) -> Uuid {
    let attempt_id = Uuid::now_v7();
    let source_tx_hash = [source_marker; 32];
    seed_pending_spent_input(pool, wallet_id, source_tx_hash, 0, 20_000_000).await;

    let new_attempt = NewAttempt {
        id: attempt_id,
        kind: AttemptKind::Split,
        record_id: None,
        wallet_id,
        tx_hash: [tx_marker; 32],
        signed_tx: vec![tx_marker, 0x01, 0x02],
        fee_lovelace: 180_000,
        spent_inputs: vec![AttemptInput {
            tx_hash: hex::encode(source_tx_hash),
            index: 0,
            lovelace: 20_000_000,
        }],
        produced_outputs: vec![AttemptOutput {
            index: 0,
            lovelace: 6_000_000,
        }],
        replaces_tx_hash: None,
    };

    let mut tx = pool.begin().await.expect("begin");
    attempt::record_attempt_in_tx(&mut tx, &new_attempt)
        .await
        .expect("record split attempt");
    tx.commit().await.expect("commit");
    attempt_id
}

/// Count available `cardano_submit` split-resume jobs for a split attempt (its
/// payload carries `split_attempt_id`), the side effect a split recovery produces.
async fn count_split_resume_jobs(pool: &sqlx::PgPool, attempt_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM cw_core.job \
         WHERE queue = $1 AND payload->>'split_attempt_id' = $2",
    )
    .bind(SUBMIT_QUEUE)
    .bind(attempt_id.to_string())
    .fetch_one(pool)
    .await
    .expect("count split resume jobs")
}

/// Age an attempt's `created_at` back by `age`, so the sweep sees it past the grace
/// (or the alert horizon) without the test sleeping.
async fn age_attempt(pool: &sqlx::PgPool, attempt_id: Uuid, age: Duration) {
    sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET created_at = now() - make_interval(secs => $2) WHERE id = $1",
    )
    .bind(attempt_id)
    .bind(age.as_secs_f64())
    .execute(pool)
    .await
    .expect("age attempt");
}

/// Register the submit queue policy so the recovery re-enqueue resolves a policy.
async fn register_submit_policy(pool: &sqlx::PgPool) {
    gateway_core::runtime::policy::reconcile(pool, &submit_policy())
        .await
        .expect("reconcile submit policy");
}

/// Count available `cardano_submit` jobs for a record (its payload carries the
/// record id), the side effect a recovery re-enqueue produces.
async fn count_submit_jobs(pool: &sqlx::PgPool, record_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM cw_core.job \
         WHERE queue = $1 AND payload->>'record_id' = $2",
    )
    .bind(SUBMIT_QUEUE)
    .bind(record_id.to_string())
    .fetch_one(pool)
    .await
    .expect("count submit jobs")
}

/// A record's `(status, current_attempt_id)`.
async fn read_record(pool: &sqlx::PgPool, record_id: Uuid) -> (String, Option<Uuid>) {
    sqlx::query_as::<_, (String, Option<Uuid>)>(
        "SELECT status, current_attempt_id FROM cw_core.poe_record WHERE id = $1",
    )
    .bind(record_id)
    .fetch_one(pool)
    .await
    .expect("read record")
}

/// Count `refund_intent` rows for a record.
async fn count_refunds(pool: &sqlx::PgPool, record_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM cw_core.refund_intent WHERE record_id = $1")
        .bind(record_id)
        .fetch_one(pool)
        .await
        .expect("count refunds")
}

/// The state of a wallet UTxO, or `None` when no row exists.
async fn utxo_state(pool: &sqlx::PgPool, wallet_id: Uuid, input_marker: u8) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT state FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = 0",
    )
    .bind(wallet_id)
    .bind([input_marker; 32].as_slice())
    .fetch_optional(pool)
    .await
    .expect("read utxo state")
}

/// An attempt's status string.
async fn attempt_status(pool: &sqlx::PgPool, attempt_id: Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT status FROM cw_core.chain_attempt WHERE id = $1")
        .bind(attempt_id)
        .fetch_one(pool)
        .await
        .expect("read attempt status")
}

/// Count `chain.attempt.stranded` events on an attempt subject.
async fn count_stranded_alerts(pool: &sqlx::PgPool, attempt_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'chain_attempt' AND subject_id = $1 AND event_type = $2",
    )
    .bind(attempt_id.to_string())
    .bind(CHAIN_RECOVER_STRANDED_EVENT)
    .fetch_one(pool)
    .await
    .expect("count stranded alerts")
}

// ---------------------------------------------------------------------------
// Migration shape.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migration_0022_creates_the_stranded_recovery_index() {
    let db = TestDb::fresh().await.expect("test database");
    let found: Option<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname = 'cw_core' AND indexname = 'chain_attempt_stranded_idx'",
    )
    .fetch_optional(&db.pool)
    .await
    .expect("read index catalogue");
    assert!(
        found.is_some(),
        "the stranded-attempt recovery index must exist on a freshly migrated database"
    );
}

// ---------------------------------------------------------------------------
// (a) Re-enqueue past the grace; a fresh attempt within the grace is left alone.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_stranded_attempt_past_the_grace_gets_a_submit_re_enqueued() {
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let record_id = seed_record(&db.pool, operator_id).await;
    let attempt_id = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x11, 0x22).await;
    // Age it past the one-second grace but well inside the one-hour alert horizon.
    age_attempt(&db.pool, attempt_id, Duration::from_secs(120)).await;

    assert_eq!(count_submit_jobs(&db.pool, record_id).await, 0);

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());
    let summary = handler.run_once().await.expect("sweep runs");

    assert_eq!(summary.re_enqueued, 1, "one stranded attempt re-enqueued");
    assert_eq!(summary.alerted, 0, "not yet past the alert horizon");
    assert_eq!(
        count_submit_jobs(&db.pool, record_id).await,
        1,
        "a cardano_submit job is now available for the record"
    );
    // The record, its recorded attempt, and its reserved input are untouched: the
    // re-broadcast happens on the submit queue, not here.
    let (status, current) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitting");
    assert_eq!(current, Some(attempt_id));
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "recorded");
    assert_eq!(
        utxo_state(&db.pool, wallet_id, 0x22).await.as_deref(),
        Some("pending_spent"),
        "the input stays reserved"
    );
    assert_eq!(count_refunds(&db.pool, record_id).await, 0);
}

#[tokio::test]
async fn a_fresh_recorded_attempt_within_the_grace_is_left_alone() {
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let record_id = seed_record(&db.pool, operator_id).await;
    // No ageing: the attempt was just recorded, well inside the grace. This is the
    // normal record-before-broadcast window a live submit owns; the sweep must never
    // race it.
    let _attempt_id = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x33, 0x44).await;

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());
    let summary = handler.run_once().await.expect("sweep runs");

    assert_eq!(
        summary.re_enqueued, 0,
        "a within-grace attempt is not swept"
    );
    assert_eq!(summary.alerted, 0);
    assert_eq!(
        count_submit_jobs(&db.pool, record_id).await,
        0,
        "no submit job is enqueued for a within-grace attempt"
    );
}

// ---------------------------------------------------------------------------
// (b) The re-enqueue is idempotent: sweeping twice nets one job.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn re_enqueue_is_idempotent_across_two_sweep_passes() {
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let record_id = seed_record(&db.pool, operator_id).await;
    let attempt_id = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x55, 0x66).await;
    age_attempt(&db.pool, attempt_id, Duration::from_secs(120)).await;

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());

    let first = handler.run_once().await.expect("first sweep");
    assert_eq!(first.re_enqueued, 1);
    assert_eq!(first.already_in_flight, 0);

    // The first job is still `available` (nothing drained it), so the second sweep's
    // per-record singleton key collides and suppresses the duplicate.
    let second = handler.run_once().await.expect("second sweep");
    assert_eq!(
        second.re_enqueued, 0,
        "the second sweep enqueues nothing new"
    );
    assert_eq!(
        second.already_in_flight, 1,
        "the duplicate is the dedupe no-op"
    );

    assert_eq!(
        count_submit_jobs(&db.pool, record_id).await,
        1,
        "exactly one submit job exists across two sweeps"
    );
}

// ---------------------------------------------------------------------------
// (c) Past the alert horizon: a one-shot alert is raised AND the re-enqueue still
//     applies, but NOTHING is refunded/abandoned/restored on age.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn past_the_alert_horizon_the_sweep_alerts_once_and_never_refunds_on_age() {
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let record_id = seed_record(&db.pool, operator_id).await;
    let attempt_id = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x77, 0x88).await;
    // Age it well past the one-hour alert horizon.
    age_attempt(&db.pool, attempt_id, Duration::from_secs(7200)).await;

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());

    let first = handler.run_once().await.expect("first sweep");
    assert_eq!(first.alerted, 1, "the stranded alert fired once");
    assert_eq!(
        first.re_enqueued, 1,
        "the re-enqueue still applies past the alert horizon"
    );

    // The alert is one-shot: a second pass re-enqueues (deduped) but does NOT re-alert.
    let second = handler.run_once().await.expect("second sweep");
    assert_eq!(second.alerted, 0, "the alert does not re-fire");
    assert_eq!(second.already_in_flight, 1);

    assert_eq!(
        count_stranded_alerts(&db.pool, attempt_id).await,
        1,
        "exactly one stranded alert exists across two passes"
    );

    // CRITICAL: age never moves money or inputs. The attempt is still recorded, the
    // record still live, the input still reserved, and NO refund exists. A
    // no-validity-interval tx may still be in a mempool, so an age-based abandon would
    // be a double-spend + double-pay.
    assert_eq!(
        attempt_status(&db.pool, attempt_id).await,
        "recorded",
        "the stranded attempt is NOT abandoned on age"
    );
    let (status, current) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitting", "the record stays live (not refunded)");
    assert_eq!(current, Some(attempt_id));
    assert_eq!(
        utxo_state(&db.pool, wallet_id, 0x88).await.as_deref(),
        Some("pending_spent"),
        "the input stays reserved (never restored on age)"
    );
    assert_eq!(
        count_refunds(&db.pool, record_id).await,
        0,
        "NO refund is written on age"
    );
}

// ---------------------------------------------------------------------------
// (d) A confirmed / terminal record, or one riding a fresher generation, is
//     untouched.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_confirmed_record_is_never_swept() {
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let record_id = seed_record(&db.pool, operator_id).await;
    let attempt_id = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0xbb, 0xcc).await;
    age_attempt(&db.pool, attempt_id, Duration::from_secs(7200)).await;

    // Flip the record terminal (a confirmed record whose stranded attempt is a stale
    // generation the confirm authority already left behind). The sweep must skip it.
    sqlx::query("UPDATE cw_core.poe_record SET status = 'confirmed' WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("flip record confirmed");

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());
    let summary = handler.run_once().await.expect("sweep runs");

    assert_eq!(summary.re_enqueued, 0);
    assert_eq!(summary.alerted, 0);
    assert_eq!(count_refunds(&db.pool, record_id).await, 0);
    assert_eq!(count_submit_jobs(&db.pool, record_id).await, 0);
    let (status, _) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "confirmed", "a confirmed record is left untouched");
}

#[tokio::test]
async fn a_record_no_longer_riding_the_stranded_attempt_is_not_swept() {
    // A stranded recorded attempt the record NO LONGER rides (current_attempt_id
    // points at a different generation) must not be re-enqueued or alerted: acting on
    // the stale one would double-submit. The guard is `r.current_attempt_id = a.id`,
    // so a record whose pointer has moved on never matches the stranded scan.
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let record_id = seed_record(&db.pool, operator_id).await;
    let stale_attempt = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0xab, 0xcd).await;
    age_attempt(&db.pool, stale_attempt, Duration::from_secs(7200)).await;

    // Point the record's current_attempt_id at a DIFFERENT live generation. The FK
    // only requires a chain_attempt row to exist (its record_id need not match), so a
    // separate record's broadcast attempt is a valid, clearly-distinct pointer. The
    // one-active-per-record index is per record_id, so a second record's attempt does
    // not collide with the stale one.
    let other_record = seed_record(&db.pool, operator_id).await;
    let fresher = Uuid::now_v7();
    let mut tx = db.pool.begin().await.expect("begin");
    attempt::record_attempt_in_tx(
        &mut tx,
        &NewAttempt {
            id: fresher,
            kind: AttemptKind::Publish,
            record_id: Some(other_record),
            wallet_id,
            tx_hash: [0xef; 32],
            signed_tx: vec![0xef],
            fee_lovelace: 169_197,
            spent_inputs: vec![AttemptInput {
                tx_hash: hex::encode([0x01; 32]),
                index: 0,
                lovelace: 5_000_000,
            }],
            produced_outputs: vec![],
            replaces_tx_hash: None,
        },
    )
    .await
    .expect("record fresher attempt");
    tx.commit().await.expect("commit");
    sqlx::query("UPDATE cw_core.poe_record SET current_attempt_id = $2 WHERE id = $1")
        .bind(record_id)
        .bind(fresher)
        .execute(&db.pool)
        .await
        .expect("re-point record at a different generation");

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());
    let summary = handler.run_once().await.expect("sweep runs");

    assert_eq!(
        summary.re_enqueued, 0,
        "a stale attempt the record no longer rides is not re-enqueued"
    );
    assert_eq!(summary.alerted, 0, "and not alerted");
    assert_eq!(count_submit_jobs(&db.pool, record_id).await, 0);
    assert_eq!(count_refunds(&db.pool, record_id).await, 0);
    // The stale attempt is untouched (still recorded).
    assert_eq!(attempt_status(&db.pool, stale_attempt).await, "recorded");
}

// ---------------------------------------------------------------------------
// Stranded split recovery. A split records before broadcast and advances its source
// to `pending_spent`, but has no record and no confirm loader sees a recorded+NULL
// attempt, so a broadcast that never reached the wire would leave the source spent
// forever, shrinking the wallet. The sweep must include splits and re-enqueue an
// idempotent re-broadcast, so the source can recover (land -> confirm) or be
// abandoned-and-restored on a deterministic reject.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_stranded_split_past_the_grace_gets_a_split_resume_re_enqueued() {
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let attempt_id = seed_recorded_split_attempt(&db.pool, wallet_id, 0x31, 0x32).await;
    age_attempt(&db.pool, attempt_id, Duration::from_secs(120)).await;

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());
    let summary = handler.run_once().await.expect("sweep runs");

    assert_eq!(
        summary.re_enqueued, 1,
        "a stranded split past the grace gets a split-resume re-enqueued"
    );
    assert_eq!(
        count_split_resume_jobs(&db.pool, attempt_id).await,
        1,
        "a split-resume job keyed by the split's attempt id is enqueued"
    );

    // The sweep itself never moves money or inputs: the split stays recorded and its
    // source stays reserved (the re-broadcast and any abandon happen on the submit
    // queue, on a real proof, not on age).
    assert_eq!(attempt_status(&db.pool, attempt_id).await, "recorded");
    assert_eq!(
        utxo_state(&db.pool, wallet_id, 0x32).await,
        Some("pending_spent".to_string()),
        "the sweep leaves the split source reserved, never restored on age"
    );

    // Idempotent: a second sweep nets one split-resume job, not two.
    let again = handler.run_once().await.expect("second sweep");
    assert_eq!(
        again.re_enqueued, 0,
        "the split-resume re-enqueue is deduped"
    );
    assert_eq!(again.already_in_flight, 1);
    assert_eq!(count_split_resume_jobs(&db.pool, attempt_id).await, 1);
}

#[tokio::test]
async fn an_orphaned_original_is_re_adopted_onto_its_record_and_re_enqueued() {
    // A rollback handoff cleared the record's pointer to enqueue a cancelling
    // replacement, but that replacement exhausted wallet contention and never
    // recorded. The original sits `recorded`+NULL-mempool, the record is `submitted`
    // with current_attempt_id NULL: a CHARGED record with no live job and no path to
    // recover, because the steady recovery predicate requires current_attempt_id =
    // a.id. The sweep must re-adopt the original onto its record and re-enqueue.
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let record_id = seed_record(&db.pool, operator_id).await;
    let attempt_id = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x51, 0x52).await;
    // The rollback left the record `submitted` with its pointer cleared.
    sqlx::query(
        "UPDATE cw_core.poe_record SET status = 'submitted', current_attempt_id = NULL \
         WHERE id = $1",
    )
    .bind(record_id)
    .execute(&db.pool)
    .await
    .expect("orphan the record");
    age_attempt(&db.pool, attempt_id, Duration::from_secs(120)).await;

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());
    let summary = handler.run_once().await.expect("sweep runs");

    assert_eq!(
        summary.re_enqueued, 1,
        "an orphaned original is re-enqueued"
    );
    assert_eq!(count_submit_jobs(&db.pool, record_id).await, 1);
    // The record is re-pointed at the original so the resume preamble re-broadcasts it.
    let (status, current) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitted");
    assert_eq!(
        current,
        Some(attempt_id),
        "the orphaned original is re-adopted as the record's current attempt"
    );
    // No money or inputs moved; the source stays reserved.
    assert_eq!(count_refunds(&db.pool, record_id).await, 0);
    assert_eq!(
        utxo_state(&db.pool, wallet_id, 0x52).await,
        Some("pending_spent".to_string())
    );
}

#[tokio::test]
async fn an_orphan_with_a_live_non_terminal_sibling_is_not_re_adopted() {
    // A pointer-NULL record that still has a non-terminal SIBLING (here a `superseded`
    // original still reconcilable) is ambiguous: re-adopting the recorded attempt could
    // race the sibling. The orphan guard requires the attempt be the record's ONLY
    // non-terminal attempt, so it is not re-adopted while a live sibling exists; the
    // pointer is left untouched for the generation logic, never re-pointed by the sweep.
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let record_id = seed_record(&db.pool, operator_id).await;
    // A live `superseded` sibling (still reconcilable, NOT in the one-active index so it
    // coexists with the recorded orphan).
    let sibling = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x53, 0x54).await;
    sqlx::query("UPDATE cw_core.chain_attempt SET status = 'superseded' WHERE id = $1")
        .bind(sibling)
        .execute(&db.pool)
        .await
        .expect("mark sibling superseded");
    sqlx::query("UPDATE cw_core.poe_record SET current_attempt_id = NULL WHERE id = $1")
        .bind(record_id)
        .execute(&db.pool)
        .await
        .expect("clear pointer");
    // The recorded orphan.
    let orphan = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x55, 0x56).await;
    sqlx::query(
        "UPDATE cw_core.poe_record SET status = 'submitted', current_attempt_id = NULL \
         WHERE id = $1",
    )
    .bind(record_id)
    .execute(&db.pool)
    .await
    .expect("orphan the record");
    age_attempt(&db.pool, orphan, Duration::from_secs(120)).await;

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());
    let _ = handler.run_once().await.expect("sweep runs");

    // The orphan is NOT re-adopted while a live sibling exists; the pointer stays NULL.
    let (_status, current) = read_record(&db.pool, record_id).await;
    assert_eq!(
        current, None,
        "the sweep does not re-adopt an orphan that has a live non-terminal sibling"
    );
}

#[tokio::test]
async fn an_orphaned_recorded_replacement_behind_its_own_superseded_original_is_re_adopted() {
    // A cancelling replacement records, superseding its original (original ->
    // superseded, superseded_by = replacement), but the rollback then cleared the
    // record's pointer and the replacement never reached the wire. The replacement is
    // an orphan that sits BEHIND its own superseded original. The orphan guard must NOT
    // count that superseded original as a competing sibling (it is this replacement's
    // own cancelled predecessor), or the charged record would strand permanently.
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let record_id = seed_record(&db.pool, operator_id).await;

    // The original publish; supersede it FIRST so the recorded replacement can coexist
    // under the one-active index.
    let original = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x61, 0x62).await;
    let original_tx_hash = [0x61u8; 32];
    sqlx::query("UPDATE cw_core.chain_attempt SET status = 'superseded' WHERE id = $1")
        .bind(original)
        .execute(&db.pool)
        .await
        .expect("supersede the original");
    // The recorded replacement that supersedes it: its replaces_tx_hash names the
    // original's tx hash. (A distinct input marker keeps the seeded wallet_utxo rows
    // unique; the sweep does not re-validate input intersection, only re-points and
    // re-enqueues.)
    let replacement =
        seed_recorded_replacement(&db.pool, record_id, wallet_id, 0x63, 0x64, original_tx_hash)
            .await;
    sqlx::query("UPDATE cw_core.chain_attempt SET superseded_by = $2 WHERE id = $1")
        .bind(original)
        .bind(replacement)
        .execute(&db.pool)
        .await
        .expect("link superseded_by to the replacement");
    // The rollback cleared the record's pointer; the replacement never broadcast.
    sqlx::query(
        "UPDATE cw_core.poe_record SET status = 'submitted', current_attempt_id = NULL \
         WHERE id = $1",
    )
    .bind(record_id)
    .execute(&db.pool)
    .await
    .expect("orphan the record");
    age_attempt(&db.pool, replacement, Duration::from_secs(120)).await;

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());
    let summary = handler.run_once().await.expect("sweep runs");

    assert_eq!(
        summary.re_enqueued, 1,
        "the orphaned replacement behind its own superseded original is re-enqueued"
    );
    assert_eq!(count_submit_jobs(&db.pool, record_id).await, 1);
    // The record is re-pointed at the REPLACEMENT (not the superseded original) so the
    // resume preamble re-broadcasts the cancelling replacement.
    let (status, current) = read_record(&db.pool, record_id).await;
    assert_eq!(status, "submitted");
    assert_eq!(
        current,
        Some(replacement),
        "the replacement is re-adopted as the record's current attempt"
    );
    assert_eq!(count_refunds(&db.pool, record_id).await, 0);
}

#[tokio::test]
async fn an_orphaned_replacement_with_an_unrelated_superseded_sibling_is_not_re_adopted() {
    // The carve-out exempts ONLY the replacement's OWN superseded predecessor. A
    // DIFFERENT superseded sibling (one this replacement did not supersede — an
    // unrelated chain) is still a competing live sibling and must keep blocking
    // re-adoption, so the guard does not over-loosen. (An active-broadcaster competitor
    // cannot coexist with a recorded orphan under the one-active index, so the realistic
    // competing sibling is a superseded one from another chain.)
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    let record_id = seed_record(&db.pool, operator_id).await;

    // Only ONE recorded/broadcast/stuck attempt may exist per record (the one-active
    // index), so every sibling is superseded before the next recorded row is inserted.
    // This replacement's own superseded predecessor.
    let original = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x81, 0x82).await;
    let original_tx_hash = [0x81u8; 32];
    sqlx::query("UPDATE cw_core.chain_attempt SET status = 'superseded' WHERE id = $1")
        .bind(original)
        .execute(&db.pool)
        .await
        .expect("supersede the original");
    // An UNRELATED superseded chain (superseded by some other attempt, NOT this
    // replacement): a genuine competing live sibling that must still block re-adoption.
    let unrelated = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x84, 0x85).await;
    sqlx::query("UPDATE cw_core.chain_attempt SET status = 'superseded' WHERE id = $1")
        .bind(unrelated)
        .execute(&db.pool)
        .await
        .expect("supersede the unrelated sibling");
    let other = seed_recorded_attempt(&db.pool, record_id, wallet_id, 0x86, 0x87).await;
    sqlx::query("UPDATE cw_core.chain_attempt SET status = 'superseded' WHERE id = $1")
        .bind(other)
        .execute(&db.pool)
        .await
        .expect("supersede the other attempt");
    // Link the unrelated sibling's superseded_by at `other` (NOT this replacement), so
    // it is a competing live sibling from a different chain.
    sqlx::query("UPDATE cw_core.chain_attempt SET superseded_by = $2 WHERE id = $1")
        .bind(unrelated)
        .bind(other)
        .execute(&db.pool)
        .await
        .expect("link the unrelated chain");
    // Now the replacement is the only recorded row; record it and link the original.
    // A distinct input marker keeps the seeded wallet_utxo rows unique.
    let replacement =
        seed_recorded_replacement(&db.pool, record_id, wallet_id, 0x83, 0x88, original_tx_hash)
            .await;
    sqlx::query("UPDATE cw_core.chain_attempt SET superseded_by = $2 WHERE id = $1")
        .bind(original)
        .bind(replacement)
        .execute(&db.pool)
        .await
        .expect("link the original to the replacement");
    sqlx::query(
        "UPDATE cw_core.poe_record SET status = 'submitted', current_attempt_id = NULL \
         WHERE id = $1",
    )
    .bind(record_id)
    .execute(&db.pool)
    .await
    .expect("orphan the record pointer");
    age_attempt(&db.pool, replacement, Duration::from_secs(120)).await;

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());
    let _ = handler.run_once().await.expect("sweep runs");

    // The replacement is NOT re-adopted while an unrelated superseded sibling exists.
    let (_status, current) = read_record(&db.pool, record_id).await;
    assert_eq!(
        current, None,
        "an orphaned replacement is not re-adopted while an unrelated superseded sibling exists"
    );
}

#[tokio::test]
async fn a_fresh_split_within_the_grace_is_left_alone() {
    let db = TestDb::fresh().await.expect("test database");
    register_submit_policy(&db.pool).await;

    let operator_id = seed_operator(&db.pool).await;
    let wallet_id = seed_wallet(&db.pool, operator_id).await;
    // A freshly recorded split (its created_at is now) is within the grace, so the
    // sweep must not race the submit that may still be broadcasting it.
    let attempt_id = seed_recorded_split_attempt(&db.pool, wallet_id, 0x41, 0x42).await;

    let handler = ChainRecoverHandler::new(db.pool.clone(), config());
    let summary = handler.run_once().await.expect("sweep runs");

    assert_eq!(
        summary.re_enqueued, 0,
        "a fresh split within the grace is left alone"
    );
    assert_eq!(count_split_resume_jobs(&db.pool, attempt_id).await, 0);
}

// ---------------------------------------------------------------------------
// Queue identity.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_recover_queue_name_is_stable() {
    assert_eq!(CHAIN_RECOVER_QUEUE, "cardano_recover");
    assert_eq!(AttemptStatus::Recorded.as_str(), "recorded");
}
