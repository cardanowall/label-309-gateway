//! The publish surface: single publish, batch publish, and content uploads.
//!
//! The publish path is the engine's exactly-once write: one transaction inserts
//! the `poe_record`, consumes the quote (the signed-negative debit, bound to the
//! record), enqueues the Cardano submit job, and appends the `submitting` subject
//! event. Because all four writes share one transaction the debit and the submit
//! can never diverge: a record is charged exactly once and its submit is enqueued
//! exactly once. A fresh publish returns 202; submitting identical record bytes
//! for the same account again returns 200 with the prior row's projection (dedup
//! on `(account_id, record_sha256)`), so a retry is idempotent without the caller
//! supplying a key.
//!
//! Batch publish carries per-record independence: one record's affordability
//! failure does not roll back another's commit. The batch idempotency key replays
//! the whole response; a 402 on any record is non-committing so a same-key retry
//! runs fresh against the new balance.
//!
//! [`consume_quote_in_tx`]: crate::ledger::quote::consume_quote_in_tx

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api::ids::encode_poe_id;
use crate::api::middleware::auth::Viewer;
use crate::api::middleware::idempotency::{self, StoredResponse};
use crate::api::middleware::rate_limit::RateDecision;
use crate::api::middleware::scope;
use crate::api::problem::Problem;
use crate::api::routes::guard;
use crate::api::state::AppState;
use crate::api::wire::{project_record, RecordProjection};
use crate::chain::submit::{SubmitJob, SUBMIT_QUEUE};
use crate::ledger::quote::{consume_quote_in_tx, ConsumeOutcome, ConsumeRejection};
use crate::runtime::enqueue::{enqueue, EnqueueOptions};

/// The maximum records a single publish-batch may carry.
const MAX_BATCH_RECORDS: usize = 50;

/// The `POST /api/v1/poe/publish` request body.
#[derive(Debug, Deserialize)]
struct PublishBody {
    /// Hex canonical-CBOR record bytes.
    record: String,
    /// The quote id from `/poe/quote`.
    quote_id: String,
    /// Optional path-2 wallet signature sidecars.
    #[serde(default)]
    #[allow(dead_code)]
    signatures: Option<Vec<Value>>,
}

/// `POST /api/v1/poe/publish` — publish a single record.
///
/// Requires `poe:create`. Validates the record, runs the idempotency replay
/// check, then either dedups (200) or runs the exactly-once publish transaction
/// (202: record insert + in-transaction quote consume + submit enqueue +
/// `submitting` subject event). A 402 is non-committing so a retry after a top-up
/// runs fresh.
pub async fn publish_one(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_POE_CREATE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // Idempotency replay: a stored response for this (account, key, body) replays
    // verbatim before any work, so a retry never re-enters the publish transaction.
    let idem = match resolve_idempotency(
        &state,
        &viewer,
        &headers,
        "/api/v1/poe/publish",
        &body,
        trace,
    )
    .await
    {
        Ok(IdempotencyState::Replay(resp)) => return finish(resp, &decision),
        Ok(IdempotencyState::Fresh(ctx)) => ctx,
        Err(resp) => return finish(resp, &decision),
    };

    let parsed: PublishBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return finish(
                Problem::of(
                    "invalid-body",
                    format!("request body is not valid JSON: {e}"),
                )
                .into_response_with(base, trace),
                &decision,
            )
        }
    };

    let response =
        match publish_record(&state, &viewer, &parsed.record, &parsed.quote_id, trace).await {
            Ok(outcome) => {
                let (status, body) = outcome.into_single_parts();
                if let Some(ctx) = &idem {
                    ctx.store_if_committing(status, &body).await;
                }
                (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
            }
            Err(failure) => {
                // A 402 is non-committing: the idempotency context deliberately does not
                // store it, so a retry after a top-up runs fresh.
                failure.into_problem(base, trace)
            }
        };

    finish(response, &decision)
}

/// One entry in a publish-batch request.
#[derive(Debug, Deserialize)]
struct BatchEntry {
    /// Hex canonical-CBOR record bytes.
    record: String,
    /// The quote id from `/poe/quote`.
    quote_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    signatures: Option<Vec<Value>>,
}

/// The `POST /api/v1/poe/publish-batch` request body.
#[derive(Debug, Deserialize)]
struct BatchBody {
    records: Vec<BatchEntry>,
}

/// `POST /api/v1/poe/publish-batch` — publish 1..50 records with per-record
/// independence.
///
/// Requires `poe:create`. Charges N rate tokens (one per record). Each record
/// succeeds or fails independently; a 402 on one does not roll back the others.
/// The batch idempotency key replays the whole 200 body; a 402 on any record is
/// non-committing so a same-key retry runs fresh.
pub async fn publish_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    // Parse first to learn N (the rate-limit token cost), but authorize before any
    // observable answer so an unauthenticated caller never learns the body shape.
    let parsed: std::result::Result<BatchBody, _> = serde_json::from_slice(&body);

    let token_cost = match &parsed {
        Ok(b) if !b.records.is_empty() && b.records.len() <= MAX_BATCH_RECORDS => {
            b.records.len() as i64
        }
        // Malformed, empty, or over-large: authorize with one token; the specific
        // error is reported after auth succeeds.
        _ => 1,
    };

    let (viewer, decision) = match guard::authorize(
        &state,
        &headers,
        scope::SCOPE_POE_CREATE,
        token_cost,
        trace,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let parsed = match parsed {
        Ok(b) => b,
        Err(e) => {
            return finish(
                Problem::of(
                    "invalid-body",
                    format!("request body is not valid JSON: {e}"),
                )
                .into_response_with(base, trace),
                &decision,
            )
        }
    };

    if parsed.records.is_empty() {
        return finish(
            Problem::of("validation-failed", "records must carry at least one entry")
                .into_response_with(base, trace),
            &decision,
        );
    }
    if parsed.records.len() > MAX_BATCH_RECORDS {
        return finish(
            Problem::of(
                "batch-too-large",
                format!("a publish-batch carries at most {MAX_BATCH_RECORDS} records"),
            )
            .into_response_with(base, trace),
            &decision,
        );
    }

    let idem = match resolve_idempotency(
        &state,
        &viewer,
        &headers,
        "/api/v1/poe/publish-batch",
        &body,
        trace,
    )
    .await
    {
        Ok(IdempotencyState::Replay(resp)) => return finish(resp, &decision),
        Ok(IdempotencyState::Fresh(ctx)) => ctx,
        Err(resp) => return finish(resp, &decision),
    };

    // Run each record independently; a per-record failure becomes an error object
    // in the results array, never an aborted batch.
    let mut results: Vec<Value> = Vec::with_capacity(parsed.records.len());
    let mut last_balance: Option<String> = None;
    let mut any_non_committing = false;

    for (idx, entry) in parsed.records.iter().enumerate() {
        match publish_record(&state, &viewer, &entry.record, &entry.quote_id, trace).await {
            Ok(outcome) => {
                last_balance = Some(outcome.balance_after.clone());
                let mut item = outcome.into_wire();
                if let Value::Object(ref mut map) = item {
                    map.insert("record_idx".into(), json!(idx));
                }
                results.push(item);
            }
            Err(failure) => {
                if failure.non_committing {
                    any_non_committing = true;
                }
                results.push(json!({
                    "record_idx": idx,
                    "error": { "code": failure.code, "detail": failure.detail },
                }));
            }
        }
    }

    // The batch balance is the latest successful debit's post-balance, or the
    // current balance when nothing committed.
    let balance_after = match last_balance {
        Some(b) => b,
        None => current_balance(&state, viewer.account_id).await.to_string(),
    };

    let body = serde_json::to_string(&json!({
        "results": results,
        "balance_after_usd_micros": balance_after,
    }))
    .unwrap_or_else(|_| "{}".into());

    // A batch with any non-committing (402) record is itself non-committing: a
    // same-key retry must run fresh so the topped-up records publish.
    if let Some(ctx) = &idem {
        if !any_non_committing {
            ctx.store_if_committing(StatusCode::OK, &body).await;
        }
    }

    finish(
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        &decision,
    )
}

// ===========================================================================
// The single-record publish core, shared by publish and publish-batch.
// ===========================================================================

/// A successful single-record publish outcome, fresh or deduped.
struct PublishOutcome {
    /// The wire id (`poe_<crockford>`).
    id: String,
    /// The transaction hash, once a submit has landed (None on a fresh publish).
    tx_hash: Option<String>,
    /// The lifecycle status string the SDK reads.
    status: String,
    /// The record projection (items, signed, sealed, conformance profile).
    projection: RecordProjection,
    /// The balance after the debit, as a decimal string.
    balance_after: String,
    /// 202 for a fresh publish, 200 for a dedup replay.
    fresh: bool,
}

impl PublishOutcome {
    /// The single-publish `(status, body)` parts: 202 fresh, 200 dedup.
    fn into_single_parts(self) -> (StatusCode, String) {
        let status = if self.fresh {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        };
        let body = serde_json::to_string(&self.into_wire()).unwrap_or_else(|_| "{}".into());
        (status, body)
    }

    /// The publish-response JSON object (the SDK `PublishResponse` shape).
    fn into_wire(self) -> Value {
        json!({
            "id": self.id,
            "tx_hash": self.tx_hash,
            "status": self.status,
            "items_count": self.projection.items_count,
            "signed": self.projection.signed,
            "sealed": self.projection.sealed,
            "items": self.projection.items,
            "conformance_profile": self.projection.conformance_profile(),
            "balance_after_usd_micros": self.balance_after,
        })
    }
}

/// A single-record publish failure: a stable code, a detail, whether the
/// failure is non-committing (a 402, so a same-key retry runs fresh), and any
/// extension members the problem body carries (e.g. the 402's balance/shortfall).
struct PublishFailure {
    code: String,
    detail: String,
    non_committing: bool,
    extensions: serde_json::Map<String, Value>,
}

impl PublishFailure {
    /// Render the failure as an RFC 7807 problem (the single-publish route).
    fn into_problem(self, base: &str, trace: Uuid) -> Response {
        let mut problem = Problem::of(&self.code, self.detail);
        for (key, value) in self.extensions {
            problem = problem.with_extension(key, value);
        }
        problem.into_response_with(base, trace)
    }
}

/// Run the exactly-once publish for one record, deduping on
/// `(account_id, record_sha256)`.
///
/// On a fresh record: one transaction inserts the record (`submitting`), consumes
/// the quote (the debit, bound to the record), enqueues the Cardano submit, and
/// appends the `submitting` subject event, then commits, returning the 202
/// outcome. Submitting identical bytes for the same account again returns the
/// prior row's projection (the 200 dedup outcome). A consume rejection rolls the
/// whole transaction back, leaving no debit and no record.
async fn publish_record(
    state: &AppState,
    viewer: &Viewer,
    record_hex: &str,
    quote_id_str: &str,
    trace: Uuid,
) -> std::result::Result<PublishOutcome, PublishFailure> {
    let record_bytes =
        hex::decode(record_hex).map_err(|_| validation("record must be canonical-CBOR hex"))?;
    let quote_id = Uuid::parse_str(quote_id_str)
        .map_err(|_| validation("quote_id must be a valid quote id"))?;

    // Reject a structurally invalid record before any write.
    let projection = project_record(&record_bytes)
        .ok_or_else(|| validation("record is not a valid Label 309 canonical-CBOR record"))?;

    let record_sha256 = Sha256::digest(&record_bytes).to_vec();

    // Dedup: the same record bytes for this account return the prior row (200).
    if let Some(existing) = find_existing(state, viewer.account_id, &record_sha256)
        .await
        .map_err(db_failure)?
    {
        let balance = current_balance(state, viewer.account_id).await;
        return Ok(dedup_outcome(existing, projection, balance));
    }

    // Resolve the operator that owns this account (its wallet pool publishes).
    let operator_id = operator_for_account(state, viewer.account_id)
        .await
        .map_err(db_failure)?
        .ok_or_else(|| PublishFailure {
            code: "not-found".into(),
            detail: "no operator is provisioned for this account".into(),
            non_committing: false,
            extensions: serde_json::Map::new(),
        })?;

    let record_id = Uuid::now_v7();
    let request_id = trace.to_string();

    let mut txn = state.pool.begin().await.map_err(|e| db_failure(e.into()))?;

    // Insert the record in `submitting` so the submit handler picks it up. The
    // ON CONFLICT guards the dedup race: a concurrent publish of the same record
    // makes one INSERT a no-op.
    let inserted = sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, account_id, record_bytes, record_sha256, status, request_id) \
         VALUES ($1, $2, $3, $4, $5, 'submitting', $6) \
         ON CONFLICT (account_id, record_sha256) \
           WHERE account_id IS NOT NULL AND record_sha256 IS NOT NULL \
           DO NOTHING",
    )
    .bind(record_id)
    .bind(operator_id)
    .bind(viewer.account_id)
    .bind(&record_bytes)
    .bind(&record_sha256)
    .bind(&request_id)
    .execute(&mut *txn)
    .await
    .map_err(|e| db_failure(e.into()))?;

    if inserted.rows_affected() == 0 {
        // A concurrent publish of the same record won the race between the SELECT
        // and this INSERT. Roll back and replay the winner.
        txn.rollback().await.ok();
        let existing = find_existing(state, viewer.account_id, &record_sha256)
            .await
            .map_err(db_failure)?
            .ok_or_else(|| PublishFailure {
                code: "internal-error".into(),
                detail: "the dedup race left no winning row".into(),
                non_committing: false,
                extensions: serde_json::Map::new(),
            })?;
        let balance = current_balance(state, viewer.account_id).await;
        return Ok(dedup_outcome(existing, projection, balance));
    }

    // Consume the quote on the SAME transaction: the signed-negative debit for the
    // network plus service charge, bound to the record, charged against the
    // balance. Storage is charged separately at upload, so it is not part of this
    // debit and a publish-then-permanent-fail refund excludes it. The actual
    // decoded record length is passed so the consume can refuse a record larger
    // than the quote was priced for before any debit lands; a record this long
    // already fits a u32 because the quote it consumes was created for a record of
    // at most MAX_QUOTE_RECORD_BYTES.
    let actual_record_bytes = u32::try_from(record_bytes.len())
        .map_err(|_| validation("record is larger than any quote could have been priced for"))?;
    let consume = consume_quote_in_tx(
        &mut txn,
        quote_id,
        viewer.account_id,
        record_id,
        actual_record_bytes,
        Some(trace),
    )
    .await
    .map_err(db_failure)?;

    let balance_after = match consume {
        ConsumeOutcome::Consumed { balance_micros } => balance_micros,
        ConsumeOutcome::AlreadyConsumed => {
            // Impossible for a freshly minted record id; treat as an invariant
            // breach rather than a silent success.
            txn.rollback().await.ok();
            return Err(PublishFailure {
                code: "internal-error".into(),
                detail: "the quote was already consumed for a fresh record".into(),
                non_committing: false,
                extensions: serde_json::Map::new(),
            });
        }
        ConsumeOutcome::Rejected(reason) => {
            txn.rollback().await.ok();
            return Err(reject_to_failure(reason));
        }
    };

    // Enqueue the Cardano submit on the SAME transaction.
    enqueue(
        &mut *txn,
        SUBMIT_QUEUE,
        &SubmitJob {
            request_id: request_id.clone(),
            record_id,
            replacement_for: None,
            forced_inputs: Vec::new(),
        },
        EnqueueOptions::default(),
    )
    .await
    .map_err(db_failure)?;

    // Append the `submitting` subject event on the SAME transaction, so an SSE
    // stream sees the record enter its lifecycle as part of the publish commit.
    crate::events::append_subject_event(
        &mut txn,
        "poe_record",
        &record_id.to_string(),
        "submitting",
        &json!({
            "id": encode_poe_id(record_id),
            "status": "submitting",
            "request_id": request_id,
        }),
    )
    .await
    .map_err(db_failure)?;

    txn.commit().await.map_err(|e| db_failure(e.into()))?;

    Ok(PublishOutcome {
        id: encode_poe_id(record_id),
        tx_hash: None,
        status: "submitting".into(),
        projection,
        balance_after: balance_after.to_string(),
        fresh: true,
    })
}

/// Build the 200 dedup outcome from an existing record row.
fn dedup_outcome(
    existing: ExistingRecord,
    projection: RecordProjection,
    balance: i64,
) -> PublishOutcome {
    PublishOutcome {
        id: encode_poe_id(existing.id),
        tx_hash: existing.tx_hash.map(hex::encode),
        status: existing.status,
        projection,
        balance_after: balance.to_string(),
        fresh: false,
    }
}

/// A validation failure (a 422 publish failure).
fn validation(detail: &str) -> PublishFailure {
    PublishFailure {
        code: "validation-failed".into(),
        detail: detail.into(),
        non_committing: false,
        extensions: serde_json::Map::new(),
    }
}

/// Map a consume rejection to its publish failure (and HTTP semantics).
fn reject_to_failure(reason: ConsumeRejection) -> PublishFailure {
    match reason {
        ConsumeRejection::NotFound => PublishFailure {
            code: "quote-not-found".into(),
            detail: "the quote does not exist for this account".into(),
            non_committing: false,
            extensions: serde_json::Map::new(),
        },
        ConsumeRejection::NotPending => PublishFailure {
            code: "quote-already-consumed".into(),
            detail: "the quote was already spent by a prior publish".into(),
            non_committing: false,
            extensions: serde_json::Map::new(),
        },
        ConsumeRejection::Expired => PublishFailure {
            code: "quote-expired".into(),
            detail: "the quote's time-to-live lapsed before it was consumed".into(),
            non_committing: false,
            extensions: serde_json::Map::new(),
        },
        ConsumeRejection::RecordTooLarge {
            actual_bytes,
            quoted_bytes,
        } => PublishFailure {
            // A quote is a fixed-price contract for a specific record size, so a
            // larger record violates the contract the request submitted. This is a
            // client validation failure (422), not a money/availability problem:
            // the caller must request a new quote for the record it is publishing.
            code: "validation-failed".into(),
            detail: format!(
                "the record is {actual_bytes} bytes but the quote was priced for at most \
                 {quoted_bytes} bytes; request a new quote for this record size"
            ),
            non_committing: false,
            extensions: serde_json::Map::new(),
        },
        ConsumeRejection::InsufficientFunds {
            balance_micros,
            required_micros,
        } => {
            // The documented 402 extension members: the balance observed under the
            // consume lock and the charge it could not cover, as decimal strings
            // (micro-USD amounts stay strings on the wire, like every ledger
            // amount, so a bigint never loses precision in JSON).
            let mut extensions = serde_json::Map::new();
            extensions.insert(
                "balance_usd_micros".into(),
                json!(balance_micros.to_string()),
            );
            extensions.insert(
                "required_usd_micros".into(),
                json!(required_micros.to_string()),
            );
            PublishFailure {
                code: "insufficient-funds".into(),
                detail: "the account balance does not cover the quoted price".into(),
                // A 402 is non-committing: a retry after a top-up runs fresh.
                non_committing: true,
                extensions,
            }
        }
    }
}

/// Map a database error to an internal publish failure.
fn db_failure(_e: crate::Error) -> PublishFailure {
    PublishFailure {
        code: "service-unavailable".into(),
        detail: "the publish path could not reach the database".into(),
        non_committing: false,
        extensions: serde_json::Map::new(),
    }
}

/// An existing record row (the dedup hit).
struct ExistingRecord {
    id: Uuid,
    tx_hash: Option<Vec<u8>>,
    status: String,
}

/// Find an existing record by `(account_id, record_sha256)`.
async fn find_existing(
    state: &AppState,
    account_id: Uuid,
    record_sha256: &[u8],
) -> crate::Result<Option<ExistingRecord>> {
    let row: Option<(Uuid, Option<Vec<u8>>, String)> = sqlx::query_as(
        "SELECT id, tx_hash, status FROM cw_core.poe_record \
         WHERE account_id = $1 AND record_sha256 = $2",
    )
    .bind(account_id)
    .bind(record_sha256)
    .fetch_optional(&state.pool)
    .await?;
    Ok(row.map(|(id, tx_hash, status)| ExistingRecord {
        id,
        tx_hash,
        status,
    }))
}

/// Resolve the operator that owns an account (its `account_detail` satellite).
async fn operator_for_account(state: &AppState, account_id: Uuid) -> crate::Result<Option<Uuid>> {
    let op: Option<Uuid> =
        sqlx::query_scalar("SELECT operator_id FROM cw_core.account_detail WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(&state.pool)
            .await?;
    Ok(op)
}

/// The account's current balance in micro-USD (0 when no ledger activity).
async fn current_balance(state: &AppState, account_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT coalesce((SELECT balance_micros FROM cw_core.balance WHERE account_id = $1), 0)",
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0)
}

/// Stamp the rate-limit headers onto a finished response.
fn finish(mut response: Response, decision: &RateDecision) -> Response {
    guard::apply_rate_headers(&mut response, decision);
    response
}

// ===========================================================================
// Idempotent replay for the mutating publish routes.
// ===========================================================================

/// The idempotency decision for a request: replay a stored response, or carry the
/// context to store the committing response after the handler runs.
enum IdempotencyState {
    /// Replay this stored response verbatim (stamped `Idempotent-Replayed`).
    Replay(Response),
    /// Run the handler; the context (when `Some`) stores the committing response.
    Fresh(Option<IdempotencyContext>),
}

/// The context for storing a committing response under an idempotency key.
struct IdempotencyContext {
    pool: sqlx::PgPool,
    account_id: Uuid,
    key: String,
    request_hash: Vec<u8>,
}

impl IdempotencyContext {
    /// Store a committing response (status not in the non-committing set) for
    /// replay. Best-effort: a store failure never fails the already-produced
    /// response.
    async fn store_if_committing(&self, status: StatusCode, body: &str) {
        if idempotency::is_non_committing(status.as_u16()) {
            return;
        }
        let stored = StoredResponse {
            status: status.as_u16(),
            body: body.as_bytes().to_vec(),
            content_type: "application/json".into(),
        };
        let _ = idempotency::store(
            &self.pool,
            self.account_id,
            &self.key,
            &self.request_hash,
            &stored,
            chrono::Utc::now(),
        )
        .await;
    }
}

/// Resolve the idempotency state for a mutating request from its
/// `Idempotency-Key` header.
///
/// A request without the header runs fresh with no replay storage. A request with
/// a key that has a stored response for the same (account, key, body) replays it;
/// a key reused with a different body is a conflict (409); otherwise the handler
/// runs and the context records the committing response.
async fn resolve_idempotency(
    state: &AppState,
    viewer: &Viewer,
    headers: &HeaderMap,
    path: &str,
    body: &[u8],
    trace: Uuid,
) -> std::result::Result<IdempotencyState, Response> {
    let base = &state.config.problem_type_base;
    let Some(key) = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    else {
        return Ok(IdempotencyState::Fresh(None));
    };

    let request_hash = idempotency::request_hash("POST", path, body);

    match idempotency::lookup(
        &state.pool,
        viewer.account_id,
        &key,
        &request_hash,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(idempotency::Lookup::Miss) => Ok(IdempotencyState::Fresh(Some(IdempotencyContext {
            pool: state.pool.clone(),
            account_id: viewer.account_id,
            key,
            request_hash,
        }))),
        Ok(idempotency::Lookup::Hit(stored)) => {
            Ok(IdempotencyState::Replay(replay_response(stored)))
        }
        Ok(idempotency::Lookup::Conflict) => Err(Problem::of(
            "idempotency-key-conflict",
            "the idempotency key was reused with a different request payload",
        )
        .into_response_with(base, trace)),
        Err(_) => Err(Problem::of(
            "service-unavailable",
            "the idempotency store is temporarily unavailable",
        )
        .into_response_with(base, trace)),
    }
}

/// Replay a stored response, stamping the `Idempotent-Replayed` header so a caller
/// can distinguish a replay from a fresh result.
fn replay_response(stored: StoredResponse) -> Response {
    let status = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK);
    let content_type = header::HeaderValue::from_str(&stored.content_type)
        .unwrap_or_else(|_| header::HeaderValue::from_static("application/json"));
    let mut response = (status, stored.body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response.headers_mut().insert(
        "idempotent-replayed",
        header::HeaderValue::from_static("true"),
    );
    response
}

/// Whether a status code is a fresh-vs-replay marker. A successful fresh publish
/// is 202; a dedup replay is 200. Exposed for the publish-pipeline tests.
#[must_use]
pub fn is_fresh_publish(status: StatusCode) -> bool {
    status == StatusCode::ACCEPTED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_publish_is_202() {
        assert!(is_fresh_publish(StatusCode::ACCEPTED));
        assert!(!is_fresh_publish(StatusCode::OK));
    }

    #[test]
    fn insufficient_funds_is_non_committing_and_carries_the_shortfall() {
        let f = reject_to_failure(ConsumeRejection::InsufficientFunds {
            balance_micros: 100,
            required_micros: 500,
        });
        assert_eq!(f.code, "insufficient-funds");
        assert!(f.non_committing);
        // The documented 402 extension members ride the problem body as decimal
        // strings, so the payer sees exactly how short the account is.
        assert_eq!(f.extensions["balance_usd_micros"], json!("100"));
        assert_eq!(f.extensions["required_usd_micros"], json!("500"));
    }

    #[test]
    fn quote_rejections_map_to_their_codes() {
        assert_eq!(
            reject_to_failure(ConsumeRejection::NotFound).code,
            "quote-not-found"
        );
        assert_eq!(
            reject_to_failure(ConsumeRejection::NotPending).code,
            "quote-already-consumed"
        );
        assert_eq!(
            reject_to_failure(ConsumeRejection::Expired).code,
            "quote-expired"
        );
        assert!(!reject_to_failure(ConsumeRejection::NotFound).non_committing);
    }

    #[test]
    fn record_too_large_is_a_committing_validation_failure() {
        // A record larger than the quote was priced for is a client validation
        // failure (the quote is a fixed-price contract for a record size), not a
        // money/availability problem: it maps to the 422 validation code and is
        // committing so a same-key retry is not silently re-run against a balance.
        let f = reject_to_failure(ConsumeRejection::RecordTooLarge {
            actual_bytes: 8_192,
            quoted_bytes: 1,
        });
        assert_eq!(f.code, "validation-failed");
        assert!(!f.non_committing);
        assert!(
            f.detail.contains("8192") && f.detail.contains('1'),
            "the detail names the actual and quoted sizes"
        );
    }

    #[test]
    fn replay_response_stamps_the_replayed_header() {
        let stored = StoredResponse {
            status: 202,
            body: b"{\"id\":\"poe_x\"}".to_vec(),
            content_type: "application/json".into(),
        };
        let resp = replay_response(stored);
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert_eq!(resp.headers().get("idempotent-replayed").unwrap(), "true");
    }
}
