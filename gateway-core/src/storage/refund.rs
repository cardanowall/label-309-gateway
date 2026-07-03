//! The storage-refund intent: a durable single-emit hook the operator's billing
//! integration consumes to credit a `storage_refund` ledger entry.
//!
//! Like the Cardano-side refund intent, the engine never moves money on a storage
//! refund. It writes one durable intent row plus one outbox event, and a
//! downstream consumer applies the actual `storage_refund` credit. The asymmetry
//! between the two refunds is expressed entirely by *which intent exists*, not by
//! any per-kind carve-out in a trigger or a ledger:
//!
//!   - A publish that permanently fails refunds the network+service portion only.
//!     That is structural: the publish debit (`poe_publish`) covers network+service
//!     only (storage is debited at upload, not at publish), so reversing the
//!     publish debit can never touch storage. No `storage_refund_intent` is written
//!     on a publish failure, and there is deliberately no `published_record_failed`
//!     reason — a published-then-failed upload keeps its storage charge because the
//!     bytes are permanently stored.
//!   - A storage refund exists only for the narrow cases this module names: an
//!     upload that was never durably committed (`upload_uncommitted`), a charge
//!     that was applied more than once for the same bytes (`overcharge_replay`),
//!     or an upload that landed and was charged but which no published record ever
//!     referenced (`upload_orphaned`).
//!
//! Single-emit is a by-construction property: the intent's primary key is the
//! upload id, so however many paths converge on one upload, at most one intent and
//! one billing event ever exist for it. The downstream consumer keys the
//! `storage_refund` credit on the upload's `attempt_id`, the same key the original
//! `storage_upload` debit used, so the refund nets exactly that one charge.
//!
//! # The orphaned-upload sweep
//!
//! The orphaned-upload case is the only one the engine cannot detect at the moment
//! of the charge: an upload is orphaned only once it is clear no publish is coming,
//! which is a function of elapsed time, not of any single request's outcome. A
//! sealed multi-file publish charges each ciphertext upload at upload time, before
//! the record is anchored; if a later upload fails and the composer aborts, a retry
//! re-wraps the content under a fresh content-encryption key, so the ciphertext
//! bytes (and the sha256, and the dedup key) differ and the gateway charges a
//! second upload. The first charged upload is then referenced by no record.
//!
//! [`refund_orphaned_uploads`] is the self-correcting backstop: it credits the
//! user's USD `storage_upload` charge back (and emits the operator-facing refund
//! intent) for a charged account upload that no published record references, once
//! a grace window has elapsed. Each candidate settles in ONE transaction — the
//! credit and the intent+event either both commit or neither does, so a crash can
//! never leave the user refunded with the operator's billing signal dropped. Both
//! money moves are also keyed so a re-run never double-refunds: the USD credit on
//! the upload's `attempt_id` (the same key the original debit used, so the
//! single-refund-across-refund-kinds index nets it) and the intent on the
//! upload's id.
//!
//! The event rides the operator-facing funding-source subject, not a customer's
//! balance stream: a storage refund concerns an operator's funding source and is
//! consumed by an operator's billing integration, so a customer never sees it.

use std::sync::LazyLock;

use serde_json::json;
use uuid::Uuid;

use crate::ledger::journal::{insert_ledger_entry, InsertOutcome, LedgerEntry};
use crate::storage::credit::FUNDING_SOURCE_SUBJECT_KIND;
use crate::Result;

/// The outbox event type emitted alongside a storage-refund intent. The operator's
/// billing integration consumes it to credit a `storage_refund` ledger entry; the
/// engine never moves money itself.
pub const STORAGE_REFUND_INTENT_EVENT_TYPE: &str = "storage.refund-intent";

/// Why an upload is being refunded. The wire spelling matches the
/// `storage_refund_intent.reason` CHECK constraint exactly, so the enum is the
/// single source of truth for the reasons.
///
/// There is deliberately no published-then-failed reason: a publish that fails
/// after a successful upload keeps the storage charge because the bytes are
/// permanently stored, so no storage refund is owed. The orphaned-upload reason
/// is distinct from that: it covers bytes that landed and were charged but which
/// NO record ever referenced at all (the composer aborted before publish and a
/// retry re-wrapped the content), so there is no published record whose
/// permanence justifies keeping the charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageRefundReason {
    /// The upload never reached a durable committed state (a reservation that was
    /// later proven not to have landed the bytes).
    UploadUncommitted,
    /// The same bytes were charged more than once and the duplicate charge is being
    /// reversed.
    OverchargeReplay,
    /// The upload's bytes landed and were charged, but no published record ever
    /// referenced them and the grace window for one to arrive has elapsed (a
    /// publish that was abandoned after this upload was billed). The reversed
    /// charge belongs to nothing the user ever published.
    UploadOrphaned,
}

impl StorageRefundReason {
    /// The stable string stored in `storage_refund_intent.reason`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            StorageRefundReason::UploadUncommitted => "upload_uncommitted",
            StorageRefundReason::OverchargeReplay => "overcharge_replay",
            StorageRefundReason::UploadOrphaned => "upload_orphaned",
        }
    }
}

/// The outcome of [`record_storage_refund_intent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageRefundOutcome {
    /// This call wrote the intent and emitted the billing event; it owns the refund.
    Recorded,
    /// An intent already existed for this upload; the call was an idempotent no-op
    /// and no second billing event was emitted.
    AlreadyRecorded,
}

/// Write the single refund intent for an upload and emit the billing event, both in
/// one transaction.
///
/// The insert is `ON CONFLICT (storage_upload_id) DO NOTHING`, so however many
/// paths converge on one upload, at most one intent and one billing event ever
/// exist for it. The event is appended only when this call performed the insert, so
/// a converging or replayed call never re-emits. Returns
/// [`StorageRefundOutcome::Recorded`] when this call owned the refund and
/// [`StorageRefundOutcome::AlreadyRecorded`] when an intent already existed.
///
/// Passing a `&PgPool` runs the pair in its own transaction. Passing a caller's
/// open transaction/connection rides it via a savepoint, so a caller that settles
/// money alongside the intent (the orphaned-upload sweep) makes the credit and the
/// intent durable atomically — either both commit or neither does.
///
/// The event rides the upload's funding-source subject, read from the receipt row,
/// so the operator's billing integration receives it on the same operator-facing
/// channel the credit-reconcile signals use. The payload carries the upload id, the
/// attempt id (the key the downstream `storage_refund` credit nets on), the funding
/// source, and the reason, so the consumer can apply the credit without re-reading
/// the receipt.
pub async fn record_storage_refund_intent<'a, A>(
    executor: A,
    storage_upload_id: Uuid,
    reason: StorageRefundReason,
    detail: &serde_json::Value,
) -> Result<StorageRefundOutcome>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    let mut tx = executor.begin().await?;

    // The PK is the upload id, so a second insert (a converging path, a crash
    // replay) is a no-op. `rows_affected() == 1` means this call wrote the row, so
    // only the owner proceeds to emit the event.
    let recorded = sqlx::query(
        "INSERT INTO cw_core.storage_refund_intent (storage_upload_id, reason, detail) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (storage_upload_id) DO NOTHING",
    )
    .bind(storage_upload_id)
    .bind(reason.as_str())
    .bind(detail)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;

    if !recorded {
        tx.rollback().await?;
        return Ok(StorageRefundOutcome::AlreadyRecorded);
    }

    // Resolve the upload's billing correlation keys from the receipt row. The
    // funding source carries the event's subject (the operator-facing channel); the
    // attempt id is the key the downstream `storage_refund` credit nets on, the same
    // key the original `storage_upload` debit used.
    let receipt: ReceiptKeys = sqlx::query_as(
        "SELECT funding_source_id, attempt_id FROM cw_core.storage_upload WHERE id = $1",
    )
    .bind(storage_upload_id)
    .fetch_one(&mut *tx)
    .await?;

    let payload = json!({
        "storage_upload_id": storage_upload_id,
        "attempt_id": receipt.attempt_id,
        "funding_source_id": receipt.funding_source_id,
        "reason": reason.as_str(),
        "detail": detail,
    });

    // The event rides the funding-source subject when the upload carries one; a
    // refund of an upload with no funding link (a free-window or legacy receipt)
    // still records its intent but has no operator funding subject to address, so
    // the billing consumer reads such a refund off the intent table directly.
    if let Some(funding_source_id) = receipt.funding_source_id {
        crate::events::append_subject_event(
            &mut tx,
            FUNDING_SOURCE_SUBJECT_KIND,
            &funding_source_id.to_string(),
            STORAGE_REFUND_INTENT_EVENT_TYPE,
            &payload,
        )
        .await?;
    }

    tx.commit().await?;
    Ok(StorageRefundOutcome::Recorded)
}

/// The receipt-row correlation keys a refund intent threads its billing event on.
#[derive(sqlx::FromRow)]
struct ReceiptKeys {
    funding_source_id: Option<Uuid>,
    attempt_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// The orphaned-upload sweep.
// ---------------------------------------------------------------------------

/// The user's USD storage-debit ledger kind whose charge an orphan refund reverses.
/// A `storage_refund` credit keyed on the same `attempt_id` nets exactly this debit.
const STORAGE_UPLOAD_DEBIT_KIND: &str = "storage_upload";

/// The user's USD storage-refund credit kind. Idempotent both on its own
/// `(kind, ref)` and across the refund kinds on `ref` alone, so re-issuing one for
/// the same `attempt_id` is a no-op.
const STORAGE_REFUND_CREDIT_KIND: &str = "storage_refund";

/// The shortest a real upload URI can be: `ar://` (5) + a 43-char base64url
/// data-item id. The orphan candidate query requires a URI at least this long and
/// `ar://`-prefixed, so a short or malformed URI can never drive a coincidental
/// substring match against an unrelated record's bytes and refund a live upload.
/// The gateway's storage backends only ever mint `ar://<43-char-id>` URIs, so this
/// excludes nothing it produces.
const MIN_AR_URI_LEN: i64 = 5 + 43;

/// One orphaned upload a settlement is about to refund: the receipt id (the intent
/// PK), the paying attempt id (the USD credit key), the charged account, the
/// amount to credit back, and the funding source the operator-facing event rides.
#[derive(sqlx::FromRow)]
struct OrphanCandidate {
    upload_id: Uuid,
    attempt_id: Uuid,
    account_id: Uuid,
    charged_usd_micros: i64,
    funding_source_id: Option<Uuid>,
}

/// What one orphaned-upload sweep refunded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrphanRefundSweep {
    /// Orphaned uploads newly refunded this run (a USD credit applied and an intent
    /// emitted, atomically). A re-run over the same orphans counts zero: each was
    /// already refunded.
    pub uploads_refunded: u64,
    /// Total micro-USD credited back across the refunded uploads.
    pub refunded_usd_micros: i64,
    /// Operator-facing intents emitted for uploads whose USD credit had landed
    /// without one — half-settlements the pre-atomic sweep could leave behind
    /// when it crashed between the credit and the intent. Zero on every run over
    /// post-atomic history.
    pub intents_backfilled: u64,
}

/// The orphan-candidate predicate over `cw_core.storage_upload u`, shared verbatim
/// by the discovery scan and the per-candidate settlement re-check so the two can
/// never drift. Binds: `$1` is the grace window in seconds and `$3` the minimum
/// well-formed `ar://` URI length ([`MIN_AR_URI_LEN`]); `$2` is left to the
/// enclosing query (the discovery `LIMIT`, the settlement upload id).
const ORPHAN_CANDIDATE_PREDICATE: &str = r#"
          u.account_id IS NOT NULL
          AND u.attempt_id IS NOT NULL
          AND u.charged_usd_micros > 0
          -- URI shape guard: only a well-formed ar://<id> URI can be matched.
          -- A short or malformed URI could otherwise be a coincidental
          -- substring of an unrelated record's bytes; requiring the scheme and
          -- a minimum length closes that false-positive path.
          AND u.uri LIKE 'ar://%'
          AND char_length(u.uri) >= $3
          AND u.created_at < now() - make_interval(secs => $1::double precision)
          -- Reference test, keyed on the EXACT-CASE data-item id (the bytes of
          -- u.uri after the 'ar://' scheme prefix), not the full scheme-prefixed
          -- URI. Label 309 case-folds only a URI's scheme (RFC 3986 §3.1), so a
          -- valid record may reference this upload as 'AR://<id>' while the
          -- gateway minted the lowercase 'ar://<id>'; matching the full URI would
          -- miss that and wrongly refund a live upload. The id itself is
          -- case-SIGNIFICANT base64url, so it is matched verbatim, and its 43
          -- chars of entropy rule out a coincidental substring hit — making the
          -- test both scheme-case-independent and false-positive-safe.
          AND NOT EXISTS (
              SELECT 1 FROM cw_core.poe_record r
              WHERE position(
                  convert_to(substring(u.uri FROM char_length('ar://') + 1), 'UTF8')
                  IN r.record_bytes
              ) > 0
          )
          AND NOT EXISTS (
              SELECT 1 FROM cw_core.storage_refund_intent i
              WHERE i.storage_upload_id = u.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM cw_core.balance_ledger l
              WHERE l.kind = 'storage_refund'
                AND l.ref = u.attempt_id::text
          )
"#;

/// The discovery scan: a bounded batch of orphan-candidate ids, oldest first.
/// Read-only and lock-free — the locks a plain `FOR UPDATE` would take here could
/// not outlive the statement anyway (it runs outside any transaction), so the
/// per-candidate settlement takes the real claim instead.
static DISCOVER_ORPHANS_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT u.id FROM cw_core.storage_upload u \
         WHERE {ORPHAN_CANDIDATE_PREDICATE} \
         ORDER BY u.created_at, u.id \
         LIMIT $2"
    )
});

/// The settlement re-check: the SAME predicate narrowed to one upload, run inside
/// the settling transaction with `FOR UPDATE SKIP LOCKED` so (a) concurrent
/// replicas serialize per upload without blocking, and (b) a candidate that
/// stopped qualifying between discovery and settlement (a publish landed, another
/// sweep settled it) simply returns no row.
static SETTLE_ORPHAN_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT u.id           AS upload_id, \
                u.attempt_id   AS attempt_id, \
                u.account_id   AS account_id, \
                u.charged_usd_micros AS charged_usd_micros, \
                u.funding_source_id  AS funding_source_id \
         FROM cw_core.storage_upload u \
         WHERE u.id = $2 AND {ORPHAN_CANDIDATE_PREDICATE} \
         FOR UPDATE OF u SKIP LOCKED"
    )
});

/// Refund charged account uploads that no published record references, after a
/// grace window, crediting the user's USD `storage_upload` charge back and emitting
/// the operator-facing refund intent — both keyed so a re-run never double-refunds.
///
/// # What counts as orphaned
///
/// A `cw_core.storage_upload` row is an orphan candidate when it is a billed account
/// upload (`account_id` and `attempt_id` set, `charged_usd_micros > 0` — a
/// free-window or deduped upload was charged nothing and has nothing to reverse),
/// is older than `grace_seconds`, and no `cw_core.poe_record` references it. The
/// publish path is content-addressed: a published record's canonical-CBOR
/// `record_bytes` embed the upload's `ar://<data-item-id>` URI as a text string, so
/// "referenced by a publish" is tested by the upload's `record_bytes` containing the
/// upload's data-item id. The test keys on the EXACT-CASE id (the bytes after the
/// `ar://` scheme prefix), not the full URI: Label 309 case-folds only a URI's
/// scheme, so a valid record may write `AR://<id>` where the gateway minted
/// `ar://<id>`, and matching the full URI would miss it; the id is case-significant
/// base64url and its 43 chars of entropy make a coincidental match impossible. That
/// match holds for a record in ANY status — `submitting`, `submitted`, `confirmed`,
/// even `permanent_failure` — because a record that ever referenced the upload keeps
/// the charge (a published-then-failed record's bytes are permanently stored). The
/// orphan is content uploaded but referenced by NO record at all.
///
/// The grace window is what makes the elapsed-time judgement safe: a publish may
/// legitimately arrive seconds or minutes after its upload, so only an upload past
/// the window — long after any same-session publish would have landed — is treated
/// as abandoned.
///
/// # Atomic settlement
///
/// Each candidate settles in ONE transaction (`settle_orphaned_upload`): the
/// settlement re-verifies the full orphan predicate under `FOR UPDATE SKIP
/// LOCKED` of the upload row and then, on that same transaction, appends the
/// user's USD credit and records the operator-facing intent + billing event. The
/// credit and the intent are all-or-nothing — a crash can never leave the user
/// refunded with the operator's `storage.refund-intent` signal dropped.
/// Re-verifying inside the settling transaction also closes the
/// discovery-to-settlement window: a publish that lands (or a concurrent sweep
/// that settles) in between de-qualifies the row and the settlement is a no-op.
///
/// # Refund-once
///
/// An upload already refunded is excluded from the candidate set two ways, either
/// of which suffices: a `storage_refund_intent` row exists for its id, or a
/// `storage_refund` ledger row exists for its `attempt_id`. The refund itself then
/// rides two idempotency guarantees so even a concurrent or replayed run cannot
/// double-pay: [`insert_ledger_entry`] collides on the cross-refund-kind `ref`
/// unique index (returning a no-op) and [`record_storage_refund_intent`] collides
/// on the intent PK. The candidate exclusion keeps the common re-run cheap; the
/// idempotency keys are the actual safety net.
///
/// # Legacy half-settlement repair
///
/// Before settlement was one transaction, a crash between the credit and the
/// intent could leave an upload credited with its intent permanently unemitted —
/// and the credit itself excludes the upload from the candidate set, so no later
/// sweep would revisit it. Every run therefore starts by backfilling the missing
/// intent for any such row ([`OrphanRefundSweep::intents_backfilled`]); against
/// post-atomic history the scan finds nothing. The scan is bounded per run and
/// durably disables itself (`cw_core.repair_completion`) once it observes the
/// legacy set drained, so steady-state sweeps pay one existence probe, never a
/// re-walk of the refund credits.
///
/// # Bounded
///
/// Like the firehose sweep, it drains in bounded passes (`batch` candidates per
/// discovery, at most [`MAX_ORPHAN_SWEEP_PASSES`]), so a large backlog of
/// abandoned uploads is collected over successive runs without one run doing
/// unbounded work. The per-upload `FOR UPDATE SKIP LOCKED` claim lets a second
/// replica settle a disjoint set rather than block.
pub async fn refund_orphaned_uploads(
    pool: &sqlx::PgPool,
    grace_seconds: i64,
    batch: i64,
) -> Result<OrphanRefundSweep> {
    let mut sweep = OrphanRefundSweep {
        intents_backfilled: backfill_orphan_refund_intents(pool).await?,
        ..OrphanRefundSweep::default()
    };

    for _ in 0..MAX_ORPHAN_SWEEP_PASSES {
        // Discover a bounded batch of candidate ids, then settle each one in its
        // own transaction. The discovery is a cheap read; the settlement re-runs
        // the same predicate under lock, so a stale discovery can never mis-pay.
        let candidates: Vec<Uuid> = sqlx::query_scalar(DISCOVER_ORPHANS_SQL.as_str())
            .bind(grace_seconds as f64)
            .bind(batch)
            .bind(MIN_AR_URI_LEN)
            .fetch_all(pool)
            .await?;

        let claimed = candidates.len();
        for &upload_id in &candidates {
            if let Some(credited) = settle_orphaned_upload(pool, upload_id, grace_seconds).await? {
                sweep.uploads_refunded += 1;
                sweep.refunded_usd_micros = sweep.refunded_usd_micros.saturating_add(credited);
            }
        }

        // A discovery smaller than the batch means the eligible set is drained for
        // this run; stop rather than spin a final empty pass.
        if (claimed as i64) < batch {
            break;
        }
    }

    Ok(sweep)
}

/// Settle one discovered orphan candidate atomically: within a single
/// transaction, re-verify the orphan predicate under `FOR UPDATE SKIP LOCKED`,
/// credit the user's USD charge back, and record the operator-facing intent +
/// billing event. Commit makes all of it durable together; any failure rolls all
/// of it back together.
///
/// Returns the credited micro-USD when this call performed the refund, `None`
/// when the row no longer qualifies (a publish referenced it meanwhile, another
/// sweep settled it, or a concurrent settlement holds its lock) — in which case
/// nothing was written.
async fn settle_orphaned_upload(
    pool: &sqlx::PgPool,
    upload_id: Uuid,
    grace_seconds: i64,
) -> Result<Option<i64>> {
    let mut tx = pool.begin().await?;

    let candidate: Option<OrphanCandidate> = sqlx::query_as(SETTLE_ORPHAN_SQL.as_str())
        .bind(grace_seconds as f64)
        .bind(upload_id)
        .bind(MIN_AR_URI_LEN)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(candidate) = candidate else {
        tx.rollback().await?;
        return Ok(None);
    };

    // (1) Credit the user's USD storage charge back, keyed on the paying attempt
    // id — the same key the original storage_upload debit used, so the credit
    // nets exactly that debit and a replay collides on the
    // single-refund-across-refund-kinds ref index (an idempotent no-op). The
    // entry rides THIS transaction, so it commits or rolls back with the intent.
    let credit = LedgerEntry {
        account_id: candidate.account_id,
        kind: STORAGE_REFUND_CREDIT_KIND.to_string(),
        amount_micros: candidate.charged_usd_micros,
        r#ref: Some(candidate.attempt_id.to_string()),
        quote_id: None,
        metadata: json!({
            "reason": StorageRefundReason::UploadOrphaned.as_str(),
            "storage_upload_id": candidate.upload_id,
            "reversed_kind": STORAGE_UPLOAD_DEBIT_KIND,
        }),
        request_id: None,
    };
    let credit_outcome = insert_ledger_entry(&mut *tx, &credit).await?;

    // (2) Record the durable operator-facing refund intent (single-emit on the
    // upload id) and its billing event, on the same transaction. The detail
    // carries the credited amount for the operator's reconciliation.
    record_storage_refund_intent(
        &mut *tx,
        candidate.upload_id,
        StorageRefundReason::UploadOrphaned,
        &json!({
            "charged_usd_micros": candidate.charged_usd_micros,
            "funding_source_id": candidate.funding_source_id,
        }),
    )
    .await?;

    tx.commit().await?;

    Ok(match credit_outcome {
        InsertOutcome::Inserted => Some(candidate.charged_usd_micros),
        // The settlement predicate excludes an attempt that already carries a
        // storage_refund row, so a collision means another refund kind slipped in
        // under the cross-kind ref index concurrently: the ledger absorbed the
        // insert and no money moved in this call (the intent still recorded).
        InsertOutcome::AlreadyApplied => None,
    })
}

/// One credited-but-unsignalled upload the repair scan heals: the upload id (the
/// intent PK), the credited amount, and the funding source for the intent detail.
#[derive(sqlx::FromRow)]
struct HalfSettledRefund {
    upload_id: Uuid,
    amount_micros: i64,
    funding_source_id: Option<Uuid>,
}

/// The `cw_core.repair_completion` key under which the intent backfill records
/// that it has observed a clean state and may skip every later run.
const ORPHAN_INTENT_BACKFILL_REPAIR: &str = "orphan_refund_intent_backfill";

/// The most half-settled rows one backfill run heals. The legacy set is finite
/// (only the retired pre-atomic sweep could produce such rows), so a bounded
/// batch per sweep drains it across a few runs without one run doing unbounded
/// work over a large ledger.
const ORPHAN_INTENT_BACKFILL_LIMIT: i64 = 200;

/// Emit the operator-facing refund intent for any upload whose orphan-refund USD
/// credit landed without one — the durable half-settlement the pre-atomic sweep
/// could leave when it crashed between the credit and the intent.
///
/// The scan keys on the credit's own stamp (the sweep writes `reason` and
/// `storage_upload_id` into every credit's metadata), joined back to the upload
/// by uuid TEXT equality so a foreign `storage_refund` credit — one some other
/// party wrote with its own metadata — is never given an invented intent.
/// Idempotent: [`record_storage_refund_intent`] is single-emit on the upload id,
/// and a healed row leaves the scan's anti-join on the next run.
///
/// SELF-DISABLING. Settlement is atomic now, so no NEW half-settlement can ever
/// appear: the scan only repairs history written by the retired pre-atomic
/// sweep. The metadata join it needs is unindexed, so left ungated it would
/// re-scan every `storage_refund` credit on every sweep forever. Instead each
/// run is bounded to [`ORPHAN_INTENT_BACKFILL_LIMIT`] rows, and the run that
/// observes the backlog drained records [`ORPHAN_INTENT_BACKFILL_REPAIR`] in
/// `cw_core.repair_completion` — after which every later run (across restarts
/// and replicas) skips the scan outright, making the steady-state cost one
/// primary-key existence probe.
async fn backfill_orphan_refund_intents(pool: &sqlx::PgPool) -> Result<u64> {
    let completed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM cw_core.repair_completion WHERE repair = $1)",
    )
    .bind(ORPHAN_INTENT_BACKFILL_REPAIR)
    .fetch_one(pool)
    .await?;
    if completed {
        return Ok(0);
    }

    let rows: Vec<HalfSettledRefund> = sqlx::query_as(
        r#"
        SELECT u.id                AS upload_id,
               l.amount_micros     AS amount_micros,
               u.funding_source_id AS funding_source_id
        FROM cw_core.balance_ledger l
        JOIN cw_core.storage_upload u
          ON u.id::text = l.metadata->>'storage_upload_id'
        WHERE l.kind = 'storage_refund'
          AND l.metadata->>'reason' = 'upload_orphaned'
          AND NOT EXISTS (
              SELECT 1 FROM cw_core.storage_refund_intent i
              WHERE i.storage_upload_id = u.id
          )
        ORDER BY u.id
        LIMIT $1
        "#,
    )
    .bind(ORPHAN_INTENT_BACKFILL_LIMIT)
    .fetch_all(pool)
    .await?;

    let drained = (rows.len() as i64) < ORPHAN_INTENT_BACKFILL_LIMIT;
    let mut backfilled = 0u64;
    for row in rows {
        let outcome = record_storage_refund_intent(
            pool,
            row.upload_id,
            StorageRefundReason::UploadOrphaned,
            &json!({
                "charged_usd_micros": row.amount_micros,
                "funding_source_id": row.funding_source_id,
            }),
        )
        .await?;
        if outcome == StorageRefundOutcome::Recorded {
            backfilled += 1;
        }
    }

    if drained {
        // Every legacy row is healed (a short batch means the anti-join is
        // empty once this loop's intents land). Record the completion so no
        // later run pays for the scan; a concurrent replica recording it first
        // is the same outcome.
        sqlx::query(
            "INSERT INTO cw_core.repair_completion (repair) VALUES ($1) \
             ON CONFLICT (repair) DO NOTHING",
        )
        .bind(ORPHAN_INTENT_BACKFILL_REPAIR)
        .execute(pool)
        .await?;
    }
    Ok(backfilled)
}

/// The most claim passes one orphaned-upload sweep makes in a single run. A hard
/// cap so one daily pass is predictably bounded even against a large backlog of
/// abandoned uploads; the remainder is collected on the next run.
pub const MAX_ORPHAN_SWEEP_PASSES: usize = 50;
