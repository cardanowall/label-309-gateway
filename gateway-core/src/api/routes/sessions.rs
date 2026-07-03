//! The resumable / chunked upload session sub-resource.
//!
//! A file too large for a single `multipart/form-data` POST (a CDN caps a single
//! request body) is uploaded as a session: create, PUT each chunk, complete. The
//! session assembles the chunks into one durable file and hands it, unchanged, into
//! the SAME `store_one` the single-shot route uses, so a logical file is signed
//! once, deduped once, and charged exactly once regardless of how its bytes arrived.
//!
//! The session is a PRECURSOR to the upload attempt, never the attempt: chunks carry
//! ZERO ledger side effects. The only billing event is the attempt reserve reached
//! exactly once at `complete`. The free window is netted once over the assembled
//! byte count, never per chunk.
//!
//! All five operations require `poe:create` and are account-scoped: a session the
//! caller does not own returns `404` indistinguishably from a non-existent one, the
//! same non-oracle rule the attempt poll uses.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::middleware::{idempotency, scope};
use crate::api::problem::Problem;
use crate::api::routes::guard;
use crate::api::routes::uploads::{store_one, StoreOutcome, UploadContext};
use crate::api::state::{AppState, StorageState};
use crate::ledger::account::operator_for_account;
use crate::storage::{
    assembling_path, begin_assembling, chunk_count_for, create_assembling_file, create_session,
    delete_durable, delete_session, ingest_chunk, load_session_for_account, lookup_receipt,
    mark_completed, mark_failed, record_chunk, recorded_chunk_digest, revert_to_open,
    ChunkIngestError, CreateSessionOutcome, CreateSessionSpec, RecordOutcome, SessionDisposition,
    SessionState, StagedFile, UploadSession,
};

/// The JSON body of a session-create request.
#[derive(Debug, Deserialize)]
struct CreateRequest {
    /// The storage target (absent or `arweave`; any other value is rejected, the
    /// same enum as the single-shot route).
    #[serde(default)]
    target: Option<String>,
    /// The declared whole-file content digest, 64 lowercase hex.
    sha256: String,
    /// The declared total file size.
    total_bytes: u64,
    /// The client's intended chunk size; the server clamps it to its ceiling.
    #[serde(default)]
    chunk_bytes: Option<u64>,
    /// The content type recorded for the data-item Content-Type tag.
    #[serde(default)]
    content_type: Option<String>,
}

/// `POST /api/v1/poe/uploads/sessions` — create a chunked upload session.
///
/// Two no-bytes-flowing short-circuits at create preserve the single-shot billing
/// invariants: a dedup hit returns the existing `ar://` URI with NO session row, and
/// an unaffordable upload returns `402` with the same problem codes the billed path
/// emits, also with NO session row. Otherwise it creates the session row plus the
/// durable assembling file and returns the authoritative chunk grid.
pub async fn create(State(state): State<AppState>, headers: HeaderMap, body: Body) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_POE_CREATE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let Some(storage) = state.storage.as_ref() else {
        return problem(
            base,
            trace,
            "service-unavailable",
            "content storage is not configured",
        );
    };

    let req: CreateRequest = match read_json(body).await {
        Ok(r) => r,
        Err(detail) => return problem(base, trace, "invalid-body", detail),
    };

    // Validate the declared target against the same enum the single-shot route uses.
    if let Some(target) = req.target.as_deref() {
        if !target.is_empty() && target != "arweave" {
            return problem(
                base,
                trace,
                "unsupported-storage-target",
                format!("storage target {target:?} is not supported; use \"arweave\""),
            );
        }
    }

    let Some(sha256) = parse_hex32(&req.sha256) else {
        return problem(
            base,
            trace,
            "validation-failed",
            "sha256 must be 64 lowercase hex characters",
        );
    };

    let limits = state.config.upload_limits;
    if req.total_bytes > limits.max_file_bytes {
        return problem(
            base,
            trace,
            "envelope-too-large",
            format!(
                "the declared total {} bytes exceeds the {} byte per-file ceiling",
                req.total_bytes, limits.max_file_bytes
            ),
        );
    }

    let backend = storage.backend_name();
    let account_id = viewer.account_id;

    // Short-circuit 1: dedup at create. If these exact bytes are already a committed
    // receipt for this account+backend, return them with no session and no upload,
    // identical to the single-shot dedup fast path.
    match lookup_receipt(&state.pool, account_id, backend, &sha256).await {
        Ok(Some(existing)) => {
            let body = json!({
                "deduplicated": true,
                "uri": existing.uri,
                "sha256": existing.sha256_hex(),
                "bytes": existing.bytes,
                "charged_usd_micros": 0,
            });
            return ok_json(body, &decision);
        }
        Ok(None) => {}
        Err(_) => {
            return problem(
                base,
                trace,
                "internal-error",
                "the upload dedup lookup failed",
            )
        }
    }

    // Resolve the funding/pricing context (the same seam the single-shot route
    // resolves). This is also where a not-provisioned account or a missing pricing
    // seam surfaces as a 503.
    let ctx = match UploadContext::resolve(&state, storage, account_id).await {
        Ok(ctx) => ctx,
        Err(p) => return p.into_response_with(base, trace),
    };

    // Short-circuit 2: affordability at create. A chargeable upload an entitled
    // account cannot fund is rejected before the first chunk, with the same problem
    // codes the billed path emits. A free-window upload skips this (no charge).
    let chargeable = req
        .total_bytes
        .saturating_sub(state.config.free_storage_bytes);
    if chargeable > 0 {
        if let Some(p) = check_affordability(&state, storage, &ctx, chargeable).await {
            return p.into_response_with(base, trace);
        }
    }

    // The per-account open-session backpressure cap is enforced ATOMICALLY inside
    // create_session (count + insert under one per-account lock), so two concurrent
    // creates cannot both pass the check and overshoot it. The value is read here and
    // carried into the spec.
    let session_limits = state.config.upload_session_limits;

    // Resolve the authoritative, server-clamped chunk size (into the configured
    // [min, max] band) and the chunk grid. The grid is CHECKED before anything is
    // sized from it: a total that would imply more than the hard chunk ceiling is
    // a validation rejection here — before the assembling file, the bitmap row, or
    // any other per-chunk structure exists — never a saturated or clamped-degenerate
    // count. The rejection names the smallest workable chunk size for the declared
    // total, so a client (or an operator who raised `max_file_bytes`) can act on it.
    let chunk_bytes = session_limits.resolve_chunk_bytes(req.chunk_bytes);
    let Some(chunk_count) = chunk_count_for(req.total_bytes, chunk_bytes) else {
        let max_chunks = crate::storage::MAX_SESSION_CHUNKS;
        return problem(
            base,
            trace,
            "validation-failed",
            format!(
                "the {} byte total at {chunk_bytes} byte chunks implies more than the {max_chunks} \
                 chunk ceiling; use chunk_bytes of at least {}",
                req.total_bytes,
                req.total_bytes.div_ceil(u64::from(max_chunks)),
            ),
        );
    };

    let operator_id = match operator_for_account(&state.pool, account_id).await {
        Ok(Some(id)) => id,
        _ => {
            return problem(
                base,
                trace,
                "service-unavailable",
                "the account is not provisioned under an operator",
            )
        }
    };

    let session_id = Uuid::now_v7();
    let assembling = assembling_path(signing_dir(storage), session_id);
    let assembling_str = assembling.to_string_lossy().into_owned();

    // Create the durable assembling file FIRST, then the row that points at it: a
    // crash after the file but before the row leaves an orphan the janitor reclaims
    // (the file's name is its session id, but no session row references it), never a
    // row pointing at a missing file.
    if let Err(e) = create_assembling_file(&assembling, req.total_bytes).await {
        return problem(
            base,
            trace,
            "internal-error",
            format!("the assembling file could not be created: {e}"),
        );
    }

    let content_type = req
        .content_type
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let spec = CreateSessionSpec {
        id: session_id,
        account_id,
        operator_id,
        backend,
        sha256,
        total_bytes: req.total_bytes,
        chunk_bytes,
        chunk_count,
        content_type: &content_type,
        assembling_path: &assembling_str,
        ttl_secs: session_limits.session_ttl_secs,
        max_open_sessions: session_limits.max_open_sessions_per_account,
    };
    match create_session(&state.pool, &spec).await {
        Ok(CreateSessionOutcome::Created) => {}
        Ok(CreateSessionOutcome::CapExceeded { open }) => {
            // The backpressure cap was hit (checked atomically with the insert). Roll
            // back the assembling file we created before the insert so a refused create
            // leaves no orphan.
            let _ = delete_durable(&assembling).await;
            return problem(
                base,
                trace,
                "too-many-open-sessions",
                format!(
                    "this account already has {open} open upload sessions (max {})",
                    session_limits.max_open_sessions_per_account
                ),
            );
        }
        Err(_) => {
            // Roll back the assembling file we just created so a failed insert leaves no
            // orphan beyond what the janitor would anyway reclaim.
            let _ = delete_durable(&assembling).await;
            return problem(
                base,
                trace,
                "internal-error",
                "the session could not be created",
            );
        }
    }

    // Read the created row back so the response carries the authoritative expires_at.
    let session = match load_session_for_account(&state.pool, session_id, account_id).await {
        Ok(Some(s)) => s,
        _ => {
            return problem(
                base,
                trace,
                "internal-error",
                "the session vanished after create",
            )
        }
    };

    let body = json!({
        "session_id": session_id.to_string(),
        "chunk_bytes": chunk_bytes,
        "chunk_count": chunk_count,
        "received": Vec::<u32>::new(),
        "expires_at": session.expires_at.to_rfc3339(),
        "max_chunk_bytes": session_limits.max_chunk_bytes,
    });
    let mut response = (
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    )
        .into_response();
    guard::apply_rate_headers(&mut response, &decision);
    response
}

/// `PUT /api/v1/poe/uploads/sessions/{sid}/chunks/{index}` — send one chunk.
///
/// The raw `application/octet-stream` body is streamed to the chunk's deterministic
/// offset through a rolling SHA-256 (the `stage_stream` discipline) and `fsync`ed
/// BEFORE the received bit is flipped (the crash-safe ordering, guardrail 3). A
/// `Content-Length` over the per-chunk ceiling is `413` before the body is read; a
/// length not equal to the implied range is `400 chunk-size-mismatch`; a digest
/// mismatch is `400 chunk-digest-mismatch`; a re-PUT with a differing digest is
/// `409 chunk-conflict`; a matching re-PUT is an idempotent `200`.
pub async fn put_chunk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((sid, index)): Path<(String, u32)>,
    body: Body,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_POE_CREATE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if state.storage.is_none() {
        return problem(
            base,
            trace,
            "service-unavailable",
            "content storage is not configured",
        );
    }

    let Ok(session_id) = Uuid::parse_str(&sid) else {
        return problem(base, trace, "not-found", "no such upload session");
    };

    // The per-chunk ceiling is a cheap early-out, BEFORE the body is read: a chunk
    // whose declared length exceeds the ceiling is refused outright.
    let max_chunk_bytes = state.config.upload_session_limits.max_chunk_bytes;
    if let Some(declared) = content_length(&headers) {
        if declared > max_chunk_bytes {
            return problem(
                base,
                trace,
                "envelope-too-large",
                format!(
                    "the chunk Content-Length {declared} exceeds the {max_chunk_bytes} ceiling"
                ),
            );
        }
    }

    // The required RFC 9530 per-chunk digest. A missing or malformed header is a
    // hard 400 before the body is read.
    let declared_digest = match parse_digest_header(&headers) {
        Ok(d) => d,
        Err(detail) => return problem(base, trace, "chunk-digest-mismatch", detail),
    };

    let session = match load_session_for_account(&state.pool, session_id, viewer.account_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return problem(base, trace, "not-found", "no such upload session"),
        Err(_) => return problem(base, trace, "internal-error", "the session lookup failed"),
    };

    // A non-open session takes no more chunks; report a stable terminal signal.
    if session.state != SessionState::Open {
        return session_not_open(base, trace, &session);
    }

    let Some((offset, end)) = session.chunk_range(index) else {
        return problem(
            base,
            trace,
            "validation-failed",
            format!(
                "chunk index {index} is out of range 0..{}",
                session.chunk_count
            ),
        );
    };
    let expected_len = end - offset;

    // The Content-Length, when present, must equal the implied range length. (The
    // streaming ingest re-checks the actual streamed length regardless, so a body
    // that lies about or omits its length is still caught.)
    if let Some(declared) = content_length(&headers) {
        if declared != expected_len {
            return problem(
                base,
                trace,
                "chunk-size-mismatch",
                format!(
                    "chunk {index} Content-Length {declared} does not equal the implied length {expected_len}"
                ),
            );
        }
    }

    let Some(assembling) = session.assembling_path.as_deref() else {
        return problem(
            base,
            trace,
            "internal-error",
            "the session has no assembling file",
        );
    };

    // A re-PUT of an already-received index is resolved from the recorded digest
    // WITHOUT writing the body: the bytes for this offset are already durable, so a
    // matching digest is an idempotent no-op and a differing one is a conflict. This
    // is the guard that keeps a contradicting re-PUT from overwriting the good bytes
    // on disk (the positional write would otherwise scribble the rejected bytes over a
    // chunk already received). The first-arrival path still writes-then-flips (the
    // crash-safe ordering); a concurrent first-PUT race is decided by the record CAS
    // below, with the complete-time whole-file hash as the final backstop.
    if session.is_received(index) {
        return match recorded_chunk_digest(&state.pool, session_id, index).await {
            Ok(Some(recorded)) if recorded == declared_digest => {
                received_chunk_ok(&state, viewer.account_id, session_id, index, &decision).await
            }
            Ok(_) => problem(
                base,
                trace,
                "chunk-conflict",
                format!("chunk {index} was already received with a different digest"),
            ),
            Err(_) => problem(base, trace, "internal-error", "the chunk lookup failed"),
        };
    }

    // Stream the body to the chunk's offset, hashing as we go, and fsync BEFORE any
    // received bit is flipped. The bytes are durable on disk first; only then is the
    // index claimed.
    let stream = body.into_data_stream();
    match ingest_chunk(
        std::path::Path::new(assembling),
        offset,
        expected_len,
        &declared_digest,
        stream,
    )
    .await
    {
        Ok(()) => {}
        Err(ChunkIngestError::DigestMismatch) => {
            return problem(
                base,
                trace,
                "chunk-digest-mismatch",
                "the chunk bytes do not match the declared Digest",
            );
        }
        Err(ChunkIngestError::LengthMismatch { expected, actual }) => {
            return problem(
                base,
                trace,
                "chunk-size-mismatch",
                format!("chunk {index} carried {actual} bytes, expected {expected}"),
            );
        }
        Err(ChunkIngestError::Stream(detail)) => {
            return problem(
                base,
                trace,
                "invalid-body",
                format!("the chunk stream was truncated or malformed: {detail}"),
            );
        }
        Err(ChunkIngestError::Io(detail)) => {
            return problem(base, trace, "internal-error", detail);
        }
    }

    // Bytes are durable; NOW flip the received bit + record the digest under the CAS.
    match record_chunk(
        &state.pool,
        session_id,
        index,
        &declared_digest,
        expected_len,
    )
    .await
    {
        Ok(RecordOutcome::Recorded) | Ok(RecordOutcome::AlreadyMatches) => {}
        Ok(RecordOutcome::Conflict) => {
            return problem(
                base,
                trace,
                "chunk-conflict",
                format!("chunk {index} was already received with a different digest"),
            );
        }
        Ok(RecordOutcome::NotOpen) => {
            // The session settled or expired between the load and the CAS; re-read it
            // for the precise terminal signal.
            return match load_session_for_account(&state.pool, session_id, viewer.account_id).await
            {
                Ok(Some(s)) => session_not_open(base, trace, &s),
                _ => problem(base, trace, "not-found", "no such upload session"),
            };
        }
        Err(_) => return problem(base, trace, "internal-error", "recording the chunk failed"),
    }

    // Read back the authoritative received set for the response.
    received_chunk_ok(&state, viewer.account_id, session_id, index, &decision).await
}

/// `GET /api/v1/poe/uploads/sessions/{sid}` — the resume contract.
pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sid): Path<String>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_POE_CREATE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if state.storage.is_none() {
        return problem(
            base,
            trace,
            "service-unavailable",
            "content storage is not configured",
        );
    }

    let Ok(session_id) = Uuid::parse_str(&sid) else {
        return problem(base, trace, "not-found", "no such upload session");
    };
    let session = match load_session_for_account(&state.pool, session_id, viewer.account_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return problem(base, trace, "not-found", "no such upload session"),
        Err(_) => return problem(base, trace, "internal-error", "the session lookup failed"),
    };

    // The `received`/`missing` sets are materialized per read, but they are
    // BOUNDED: the create path admits no grid over `MAX_SESSION_CHUNKS` (16,384),
    // so the two arrays together never exceed one index per chunk of that ceiling.
    // The wire shape (explicit index arrays) is the published resume contract the
    // SDKs parse; the grid bound is what keeps it safe, not a representation trick.
    let body = json!({
        "session_id": session.id.to_string(),
        "state": session.state.as_str(),
        "sha256": session.sha256_hex(),
        "total_bytes": session.total_bytes,
        "chunk_bytes": session.chunk_bytes,
        "chunk_count": session.chunk_count,
        "received": session.received_indices(),
        "missing": session.missing_indices(),
        "expires_at": session.expires_at.to_rfc3339(),
        "attempt_id": session.attempt_id.map(|a| a.to_string()),
        "uri": session.uri,
    });
    ok_json(body, &decision)
}

/// `POST /api/v1/poe/uploads/sessions/{sid}/complete` — finalise the session.
///
/// Preconditions: all chunks received (else `409 incomplete-upload` + missing). On
/// success: `open -> assembling`, verify the assembled whole-file SHA-256 against the
/// declaration (else `400 sha256-mismatch`, session `failed`, file deleted, no
/// attempt, no charge), then hand the assembled durable file into the EXISTING
/// `store_one` via [`StagedFile::adopt_durable`] (Option A). The response mirrors the
/// single-shot per-file disposition. A re-`complete` of a completed session replays
/// the recorded terminal outcome.
pub async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sid): Path<String>,
) -> Response {
    let trace = guard::new_trace_id();

    // Authorize EXACTLY ONCE for the whole request: resolve the principal, check the
    // account is active, enforce `poe:create`, and reserve one rate token. The
    // resolved viewer and rate decision are threaded into `complete_inner` so the
    // inner body never re-authorizes. (A replayed `/complete` short-circuits below
    // BEFORE the handler runs, so it too consumes exactly this one token — the fresh
    // and replay paths are symmetric.)
    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_POE_CREATE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // Request-replay idempotency, the same layer the single-shot POST /uploads uses
    // (`resolve_idempotency`): a `/complete` carrying an `Idempotency-Key` whose
    // (account, key) already committed replays the recorded terminal body verbatim,
    // and a key reused for a DIFFERENT session is a conflict. The request hash binds
    // the concrete `{sid}` path so the same key on two sessions never aliases. This is
    // layered on top of the session-state replay (a re-`complete` of a `completed`
    // session also replays): the key layer additionally covers the in-flight retry
    // window, exactly as it does for the single-shot batch.
    let idem = match resolve_complete_idempotency(&state, viewer.account_id, &sid, &headers, trace)
        .await
    {
        Ok(idem) => idem,
        Err(resp) => return resp,
    };
    let store_ctx = match idem {
        CompleteIdempotency::Replay(response) => return response,
        CompleteIdempotency::Fresh(ctx) => ctx,
    };

    let response = complete_inner(&state, &sid, &viewer, decision, trace).await;

    // With no key supplied there is nothing to record; return the response untouched.
    let Some(ctx) = store_ctx else {
        return response;
    };

    // Buffer the terminal body so it can be both recorded under the key and returned
    // to the client. The `/complete` body is a small JSON document, so buffering it is
    // fine (the multi-GB content never flows through this response). The response is
    // rebuilt from the buffered bytes, preserving status and content type.
    let (status, body) = match split_response_body(response).await {
        Ok(parts) => parts,
        Err(response) => return response,
    };
    ctx.store(status, &body).await;
    rebuild_json_response(status, body)
}

/// Split a response into its status and buffered body bytes, or return the original
/// response unchanged when the body cannot be buffered (a defensive guard for an
/// unexpectedly large/streaming body, which `/complete` never produces).
async fn split_response_body(
    response: Response,
) -> std::result::Result<(StatusCode, Vec<u8>), Response> {
    let status = response.status();
    let (parts, body) = response.into_parts();
    match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(bytes) => Ok((status, bytes.to_vec())),
        Err(_) => Err(Response::from_parts(parts, Body::empty())),
    }
}

/// Rebuild a JSON response from a buffered body and status.
fn rebuild_json_response(status: StatusCode, body: Vec<u8>) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// The body of `/complete`, returning the terminal `Response` so the idempotency
/// wrapper above can record/replay it. Split out so the request-replay layer wraps
/// one entry/exit point rather than threading a store through every early return.
///
/// Authorization (principal resolve, account-status, scope, and the single rate-token
/// reservation) is done ONCE by the wrapper and threaded in as `viewer` + `decision`;
/// this body never re-authorizes, so a fresh `/complete` reserves exactly one token,
/// matching the one a replayed `/complete` costs.
async fn complete_inner(
    state: &AppState,
    sid: &str,
    viewer: &crate::api::middleware::auth::Viewer,
    decision: crate::api::middleware::rate_limit::RateDecision,
    trace: Uuid,
) -> Response {
    let base = &state.config.problem_type_base;

    let Some(storage) = state.storage.as_ref() else {
        return problem(
            base,
            trace,
            "service-unavailable",
            "content storage is not configured",
        );
    };

    let Ok(session_id) = Uuid::parse_str(sid) else {
        return problem(base, trace, "not-found", "no such upload session");
    };

    let session = match load_session_for_account(&state.pool, session_id, viewer.account_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return problem(base, trace, "not-found", "no such upload session"),
        Err(_) => return problem(base, trace, "internal-error", "the session lookup failed"),
    };

    // A re-complete of a settled session replays the recorded terminal outcome rather
    // than re-reserving.
    match session.state {
        SessionState::Open => {}
        SessionState::Completed => return completed_replay(&session, &decision),
        SessionState::Failed => {
            return problem(
                base,
                trace,
                "sha256-mismatch",
                session
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| "the session previously failed".to_string()),
            );
        }
        SessionState::Expired => {
            return problem(
                base,
                trace,
                "session-expired",
                "the upload session has expired",
            );
        }
        SessionState::Assembling => {
            // A `/complete` arriving on an already-`assembling` session must BRIDGE to a
            // live attempt if `store_one` already reserved one (the common post-reserve
            // case: a prior `/complete` reserved the attempt, which renamed the file to
            // its `.stage` path, then returned a retryable uncertainty). Returning a
            // permanent `409 incomplete-upload` here would mislead the client into
            // thinking chunks are missing when the upload is actually in flight, and
            // re-running `store_one` against the renamed-away file would 500. When there
            // is genuinely no attempt yet (a concurrent winner is mid-store before its
            // reserve), report finalisation-in-progress (retryable), never a permanent
            // 409.
            return assembling_bridge_or_in_progress(state, &session, &decision, base, trace).await;
        }
    }

    // Precondition: every chunk received.
    if !session.is_complete() {
        return Problem::of("incomplete-upload", "not every chunk has been received")
            .with_extension("missing", json!(session.missing_indices()))
            .into_response_with(base, trace);
    }

    let Some(assembling) = session.assembling_path.clone() else {
        return problem(
            base,
            trace,
            "internal-error",
            "the session has no assembling file",
        );
    };
    let assembling = std::path::PathBuf::from(assembling);

    // open -> assembling under a CAS: the single winner verifies + stores; a racing
    // re-complete loses and (on its next read) replays the recorded outcome. Winning
    // also refreshes the session's TTL so the in-flight store is never expired by the
    // janitor mid-flight (the working `assembling` state is not an abandoned one).
    let ttl_secs = state.config.upload_session_limits.session_ttl_secs;
    match begin_assembling(&state.pool, session_id, ttl_secs).await {
        Ok(true) => {}
        Ok(false) => {
            // Lost the `open -> assembling` CAS to a concurrent `/complete`. Re-read the
            // session: a winner that already settled replays its terminal outcome; a
            // winner still mid-store bridges to its live attempt if one is reserved, or
            // reports finalisation-in-progress (retryable), never a permanent 409.
            return match load_session_for_account(&state.pool, session_id, viewer.account_id).await
            {
                Ok(Some(s)) if s.state == SessionState::Completed => {
                    completed_replay(&s, &decision)
                }
                Ok(Some(s)) => {
                    assembling_bridge_or_in_progress(state, &s, &decision, base, trace).await
                }
                _ => problem(base, trace, "not-found", "no such upload session"),
            };
        }
        Err(_) => {
            return problem(
                base,
                trace,
                "internal-error",
                "the session transition failed",
            )
        }
    }

    // The integrity gate: the assembled whole-file hash must equal the declaration.
    let assembled = match crate::storage::assembled_sha256(&assembling).await {
        Ok(h) => h,
        Err(_) => {
            // A transient I/O fault reading a file we just assembled is NOT terminal:
            // the chunks are still durably on disk and the bitmap is intact. Revert to
            // `open` (keeping the file) so a retried `/complete` re-reads it without a
            // single chunk re-upload, rather than failing the session and deleting it.
            let _ = revert_to_open(&state.pool, session_id).await;
            return problem(
                base,
                trace,
                "internal-error",
                "the assembled file could not be read; retry complete",
            );
        }
    };
    if assembled != session.sha256 {
        let _ = mark_failed(&state.pool, session_id, "sha256_mismatch").await;
        let _ = delete_durable(&assembling).await;
        return problem(
            base,
            trace,
            "sha256-mismatch",
            "the assembled file does not match the declared sha256",
        );
    }

    // Hand the already-durable assembled file into the EXISTING pipeline. No re-stage,
    // no re-hash beyond the gate; the source of the staged file is invisible to
    // store_one. From here the dedup / free-window / billed saga is byte-identical to
    // the single-shot path.
    let ctx = match UploadContext::resolve(state, storage, viewer.account_id).await {
        Ok(ctx) => ctx,
        Err(p) => {
            // A transient dependency failure (pricing/operator not resolvable yet),
            // reached BEFORE any attempt is reserved. Revert the session to `open`,
            // keeping the assembling file and the received bitmap intact, so a retried
            // `/complete` re-runs from a clean state with NO chunk re-upload. Leaving
            // it `assembling` would strand it until the TTL janitor, forcing a full
            // re-upload; there is no other path out of `assembling`.
            let _ = revert_to_open(&state.pool, session_id).await;
            return p.into_response_with(base, trace);
        }
    };

    let staged = StagedFile::adopt_durable(assembling.clone(), session.sha256, session.total_bytes);
    let outcome = store_one(state, storage, &ctx, &session.content_type, staged).await;

    finalize_complete(
        state,
        session_id,
        &session,
        outcome,
        &assembling,
        &decision,
        base,
        trace,
    )
    .await
}

/// `DELETE /api/v1/poe/uploads/sessions/{sid}` — abandon a session.
pub async fn abandon(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sid): Path<String>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_POE_CREATE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if state.storage.is_none() {
        return problem(
            base,
            trace,
            "service-unavailable",
            "content storage is not configured",
        );
    }

    let Ok(session_id) = Uuid::parse_str(&sid) else {
        return problem(base, trace, "not-found", "no such upload session");
    };
    let session = match load_session_for_account(&state.pool, session_id, viewer.account_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return problem(base, trace, "not-found", "no such upload session"),
        Err(_) => return problem(base, trace, "internal-error", "the session lookup failed"),
    };

    // Only a pre-reservation session's file is ours to delete here; a completed
    // session's file is already adopted by the attempt lifecycle (assembling_path is
    // NULL), so deleting the row leaves it for the attempt's owner.
    if let Some(path) = session.assembling_path.as_deref() {
        let _ = delete_durable(std::path::Path::new(path)).await;
    }
    if delete_session(&state.pool, session_id).await.is_err() {
        return problem(
            base,
            trace,
            "internal-error",
            "the session could not be abandoned",
        );
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    guard::apply_rate_headers(&mut response, &decision);
    response
}

// ---------------------------------------------------------------------------
// Completion finalisation: stamp the session, mirror the single-shot disposition.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn finalize_complete(
    state: &AppState,
    session_id: Uuid,
    session: &UploadSession,
    outcome: StoreOutcome,
    assembling: &std::path::Path,
    decision: &crate::api::middleware::rate_limit::RateDecision,
    base: &str,
    trace: Uuid,
) -> Response {
    match outcome {
        StoreOutcome::Ok {
            uri,
            sha256_hex,
            bytes,
            charged_usd_micros,
        } => {
            // A committed or deduped upload. The disposition records whether a charge
            // was made: a dedup hit (charge absent) replays as 'deduplicated', a fresh
            // or settled upload as 'committed'. The bridge attempt id is read back
            // from the receipt's paying attempt when present.
            let disposition = if charged_usd_micros.is_none() {
                SessionDisposition::Deduplicated
            } else {
                SessionDisposition::Committed
            };
            let attempt_id = receipt_attempt_id(state, session).await;
            // The committed attempt + its receipt are the authoritative record of this
            // upload; the session row is a best-effort bridge cache for the resume/poll
            // contract. Do not fail the (correct) 200 if stamping the row loses: the
            // upload genuinely committed and was charged exactly once, and the ar:// URI
            // came from `store_one`, not the row. A row left in `assembling` self-heals
            // on the next retry (the assembling bridge resolves it from the attempt), on
            // an idempotency-key replay, or via the abandoned-session janitor. Log the
            // swallowed write so an operator can see when the cache lagged the truth.
            if let Err(e) = mark_completed(
                &state.pool,
                session_id,
                attempt_id,
                Some(&uri),
                disposition,
                charged_usd_micros.or(Some(0)),
            )
            .await
            {
                tracing::warn!(
                    session_id = %session_id,
                    attempt_id = ?attempt_id,
                    error = %e,
                    "stamping the committed session row failed; the attempt + receipt remain authoritative and the stale row self-heals on retry/replay/janitor"
                );
            }
            // store_one already deleted the durable staged file on a committed path;
            // a dedup-before-reserve path leaves the adopted assembling file, so
            // reclaim it here. delete is idempotent.
            let _ = delete_durable(assembling).await;
            let mut body = json!({
                "ok": true,
                "uri": uri,
                "sha256": sha256_hex,
                "bytes": bytes,
            });
            if let Some(charge) = charged_usd_micros.or(Some(0)) {
                body["charged_usd_micros"] = json!(charge);
            }
            ok_json(body, decision)
        }
        StoreOutcome::Accepted { attempt_id } => {
            // The bytes are in flight under a concurrent attempt for the same content;
            // the session bridges to it. The assembling file was adopted as the
            // attempt's staged content (or dropped by the losing reserve), so it is
            // out of the session's hands now. delete is idempotent and only reclaims a
            // leftover.
            //
            // The reserved attempt is the authoritative record; the session row is a
            // best-effort bridge cache. A failed `accepted` stamp does not invalidate the
            // (correct) 200: a row left in `assembling` self-heals on the next `/complete`
            // retry (the assembling bridge re-finds the live attempt), on an
            // idempotency-key replay, or via the abandoned-session janitor. Log it.
            if let Err(e) = mark_completed(
                &state.pool,
                session_id,
                Some(attempt_id),
                None,
                SessionDisposition::Accepted,
                None,
            )
            .await
            {
                tracing::warn!(
                    session_id = %session_id,
                    attempt_id = %attempt_id,
                    error = %e,
                    "stamping the bridged session row failed; the reserved attempt remains authoritative and the stale row self-heals on retry/replay/janitor"
                );
            }
            let _ = delete_durable(assembling).await;
            let body = json!({ "accepted": true, "attempt_id": attempt_id.to_string() });
            ok_json(body, decision)
        }
        StoreOutcome::Error { code, detail, .. } => {
            // A non-terminal store failure: sign / affordability / transport / commit.
            // The session must not be stranded in `assembling` (its only other exits are
            // a winning store or the TTL janitor), but the recovery must be SAFE against
            // the fact that `store_one` may have ALREADY renamed the assembling file to
            // the attempt's `.stage` path (`promote_to_durable` runs before
            // `reserve_attempt`). The recovery is decided by two observations:
            //
            //   1. A live (reserved) attempt for this content -> BRIDGE: the file is now
            //      the attempt's, under its `.stage` name; stamp the attempt on the
            //      session and return `accepted`, so the client polls the attempt for the
            //      terminal outcome and never re-uploads a chunk. The attempt reconcile
            //      sweep owns finishing or releasing it.
            //   2. No live attempt to bridge to: whether reverting to `open` is safe
            //      turns ENTIRELY on whether the assembling file is still on disk. It is
            //      provably intact only when `store_one` failed BEFORE it renamed it (a
            //      pre-promote failure: a transient affordability/sign/dependency fault).
            //      So:
            //        * file present  -> revert to `open`; a retried `/complete`
            //          re-assembles from the intact file + bitmap with no chunk
            //          re-upload, then returns the original transient error.
            //        * file gone, OR its existence cannot be determined (the bridge
            //          readback itself errored, so we also cannot trust a "no attempt"
            //          read) -> the file may have been renamed away; reverting would
            //          point the session at a vanished path. Leave the session
            //          `assembling` and return a RETRYABLE 503: a retried `/complete`
            //          re-enters the assembling-bridge below, picking up the attempt once
            //          it (or its reconcile) surfaces, never re-running `store_one`
            //          against a vanished file.
            //
            // sha256-mismatch (terminal `failed`) is handled before this point and never
            // reaches here.
            let backend = storage_backend_name(state);
            let live = crate::storage::load_live_attempt(
                &state.pool,
                session.account_id,
                &backend,
                &session.sha256,
            )
            .await;
            match live {
                Ok(Some(attempt)) => {
                    bridge_to_attempt(state, session_id, attempt.id, decision).await
                }
                Ok(None) => match assembling_file_present(assembling).await {
                    Some(true) => {
                        // Pre-promote failure: the assembling file is provably intact, so
                        // reverting to `open` is safe and a retry needs no re-upload.
                        let _ = revert_to_open(&state.pool, session_id).await;
                        problem(base, trace, &code, detail)
                    }
                    // The file is gone (renamed away) or its presence is unknown: never
                    // revert to a vanished-file `open`. Leave `assembling` and ask the
                    // client to retry, where the bridge resolves it.
                    _ => finalisation_in_progress(base, trace),
                },
                Err(_) => {
                    // The bridge readback transiently errored: we cannot tell whether an
                    // attempt was reserved, and `store_one` may have renamed the file.
                    // Leave `assembling` and return a retryable 503 so the retried bridge
                    // resolves it, rather than risk reverting to a vanished file.
                    finalisation_in_progress(base, trace)
                }
            }
        }
    }
}

/// Resolve a `/complete` that arrived on an `assembling` session: bridge to the live
/// attempt `store_one` already reserved (returning `accepted`), or, when there is
/// genuinely no attempt yet (a concurrent winner is mid-store before its reserve),
/// return a retryable finalisation-in-progress signal. Never returns a permanent 409
/// for an assembling session, and never re-runs `store_one` against a file the winner
/// may already have renamed to its attempt's `.stage` path.
async fn assembling_bridge_or_in_progress(
    state: &AppState,
    session: &UploadSession,
    decision: &crate::api::middleware::rate_limit::RateDecision,
    base: &str,
    trace: Uuid,
) -> Response {
    // A session that already stamped its bridge attempt resolves from the row alone,
    // with no readback. That `attempt_id` is written by `finalize_complete` /
    // `bridge_to_attempt` (the `mark_completed` accepted-bridge stamp), as early as the
    // route can learn the attempt id from the prior `/complete` that reserved it; it is
    // NOT stamped adjacent to `reserve_attempt` inside `store_one`.
    if let Some(attempt_id) = session.attempt_id {
        return bridge_to_attempt(state, session.id, attempt_id, decision).await;
    }
    let backend = storage_backend_name(state);
    match crate::storage::load_live_attempt(
        &state.pool,
        session.account_id,
        &backend,
        &session.sha256,
    )
    .await
    {
        Ok(Some(attempt)) => bridge_to_attempt(state, session.id, attempt.id, decision).await,
        // No attempt reserved yet, or the readback errored: the winner is still mid-store
        // (or the read blipped). Retryable, never a permanent 409.
        _ => finalisation_in_progress(base, trace),
    }
}

/// Stamp a reserved attempt onto a session as the `accepted` bridge and clear the
/// assembling path (the file is the attempt's now, under its `.stage` name). The
/// client polls `GET /uploads/attempts/{attempt_id}` for the terminal outcome.
async fn bridge_to_attempt(
    state: &AppState,
    session_id: Uuid,
    attempt_id: Uuid,
    decision: &crate::api::middleware::rate_limit::RateDecision,
) -> Response {
    // The reserved attempt is the authoritative record; the session row is a
    // best-effort bridge cache pointing the resume/poll contract at it. A failed
    // `accepted` stamp does not invalidate the (correct) 200: a row left in
    // `assembling` self-heals on the next `/complete` retry (this same bridge re-finds
    // the live attempt), on an idempotency-key replay, or via the abandoned-session
    // janitor. Log the swallowed write so the cache-vs-truth lag is observable.
    if let Err(e) = mark_completed(
        &state.pool,
        session_id,
        Some(attempt_id),
        None,
        SessionDisposition::Accepted,
        None,
    )
    .await
    {
        tracing::warn!(
            session_id = %session_id,
            attempt_id = %attempt_id,
            error = %e,
            "stamping the bridged session row failed; the reserved attempt remains authoritative and the stale row self-heals on retry/replay/janitor"
        );
    }
    let body = json!({ "accepted": true, "attempt_id": attempt_id.to_string() });
    ok_json(body, decision)
}

/// Whether the assembling file is still on disk: `Some(true)` present, `Some(false)`
/// provably absent, `None` when the check itself failed (treat as "unknown", never
/// "intact"). The caller reverts to `open` only on `Some(true)`.
///
/// This is a deliberate, currently-unreachable TOCTOU residual: a `false`/`None` here
/// guards a revert-to-`open` decision against a missing file, but in the present design
/// no other code path removes the assembling file between this check and the revert.
/// The only deleter is `store_one`, which renames (not deletes) the file to its
/// attempt's `.stage` path before reserving, and that case is already caught by the
/// live-attempt bridge above this check. The revert itself is a CAS gated on
/// `state = 'assembling'`, so it can only ever undo this caller's own transition. Even
/// if a future change did let the file vanish under a revert, the whole-file SHA-256
/// gate re-run on any `/complete` retry plus the abandoned-session janitor make a
/// missing-file revert safe (a retry against a vanished file fails the gate rather than
/// charging or corrupting; the janitor reclaims the orphaned row). The check is kept as
/// defence in depth, not because the unsafe path is reachable today.
async fn assembling_file_present(assembling: &std::path::Path) -> Option<bool> {
    tokio::fs::try_exists(assembling).await.ok()
}

/// A retryable signal for a `/complete` whose finalisation is in flight (a concurrent
/// winner is mid-store before it reserved, or a transient fault left the outcome
/// unresolved). The client retries `/complete`, where the assembling-session bridge
/// picks up the live attempt once it surfaces. 503 (not a permanent 409) so the client
/// knows to retry rather than treat the upload as failed.
fn finalisation_in_progress(base: &str, trace: Uuid) -> Response {
    Problem::of(
        "service-unavailable",
        "the upload is being finalised; retry complete",
    )
    .into_response_with(base, trace)
}

/// The backend identifier the session's content is keyed under for an attempt
/// lookup, read from the resolved storage seam (the same value `store_one` keys the
/// attempt and receipt rows on).
fn storage_backend_name(state: &AppState) -> String {
    state
        .storage
        .as_ref()
        .map(|s| s.backend_name().to_string())
        .unwrap_or_default()
}

/// Read the paying attempt id linked to a committed receipt for this session's
/// content, so the completed session bridges to the existing attempt poll. Best
/// effort: a free-window upload has no attempt, so this is `None`.
async fn receipt_attempt_id(state: &AppState, session: &UploadSession) -> Option<Uuid> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT attempt_id FROM cw_core.storage_upload \
         WHERE account_id = $1 AND backend = $2 AND sha256 = $3 LIMIT 1",
    )
    .bind(session.account_id)
    .bind(&session.backend)
    .bind(session.sha256.as_slice())
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .flatten()
}

// ---------------------------------------------------------------------------
// Request-replay idempotency for /complete (the same layer single-shot uses).
// ---------------------------------------------------------------------------

/// The idempotency decision for a `/complete` request.
enum CompleteIdempotency {
    /// Replay this stored terminal body verbatim (a same-key retry that already
    /// committed).
    Replay(Response),
    /// Run the handler; the context (when `Some`) records the committing terminal
    /// body under the key.
    Fresh(Option<CompleteIdempotencyContext>),
}

/// The context that records a `/complete` terminal body under its idempotency key.
struct CompleteIdempotencyContext {
    pool: sqlx::PgPool,
    account_id: Uuid,
    key: String,
    request_hash: Vec<u8>,
}

impl CompleteIdempotencyContext {
    /// Record a TERMINAL `/complete` body for replay. Best-effort: a store failure
    /// never fails the already-produced response. A NON-FINAL outcome is skipped so a
    /// same-key retry runs fresh: a `/complete` called before every chunk arrived
    /// (`409 incomplete-upload`), a transient dependency outage (`503`/`500`), an
    /// affordability rejection (`402`), or a validation failure (`422`) must NOT poison
    /// the key, because uploading the remaining chunks, topping up, or waiting out a
    /// blip and retrying the SAME key has to succeed. Only a settled (`200`),
    /// permanently failed (`400`), or expired (`410`) outcome is committing.
    async fn store(&self, status: StatusCode, body: &[u8]) {
        if !idempotency::complete_outcome_is_committing(status.as_u16()) {
            return;
        }
        let stored = idempotency::StoredResponse {
            status: status.as_u16(),
            body: body.to_vec(),
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

/// Resolve the `/complete` request-replay state from the `Idempotency-Key` header.
///
/// The request hash binds the concrete `{sid}` path, so a key reused across two
/// sessions is a conflict (never a false replay of a different session's outcome).
/// Mirrors `resolve_idempotency` on the single-shot route, using the same public
/// idempotency primitives and the same `idempotency_keys` table.
async fn resolve_complete_idempotency(
    state: &AppState,
    account_id: Uuid,
    sid: &str,
    headers: &HeaderMap,
    trace: Uuid,
) -> Result<CompleteIdempotency, Response> {
    let base = &state.config.problem_type_base;
    let Some(key) = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    else {
        return Ok(CompleteIdempotency::Fresh(None));
    };

    let path = format!("/api/v1/poe/uploads/sessions/{sid}/complete");
    let request_hash = idempotency::request_hash("POST", &path, b"");

    match idempotency::lookup(
        &state.pool,
        account_id,
        &key,
        &request_hash,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(idempotency::Lookup::Miss) => Ok(CompleteIdempotency::Fresh(Some(
            CompleteIdempotencyContext {
                pool: state.pool.clone(),
                account_id,
                key,
                request_hash,
            },
        ))),
        Ok(idempotency::Lookup::Hit(stored)) => {
            Ok(CompleteIdempotency::Replay(replay_stored(stored)))
        }
        Ok(idempotency::Lookup::Conflict) => Err(problem(
            base,
            trace,
            "idempotency-key-conflict",
            "the idempotency key was reused with a different request",
        )),
        Err(_) => Err(problem(
            base,
            trace,
            "service-unavailable",
            "the idempotency store is temporarily unavailable",
        )),
    }
}

/// Replay a stored terminal body, stamping `Idempotent-Replayed`.
fn replay_stored(stored: idempotency::StoredResponse) -> Response {
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

/// Replay a completed session's recorded terminal body.
fn completed_replay(
    session: &UploadSession,
    decision: &crate::api::middleware::rate_limit::RateDecision,
) -> Response {
    let body = match session.settled_disposition {
        Some(SessionDisposition::Accepted) => json!({
            "accepted": true,
            "attempt_id": session.attempt_id.map(|a| a.to_string()),
        }),
        _ => {
            let mut b = json!({
                "ok": true,
                "uri": session.uri,
                "sha256": session.sha256_hex(),
                "bytes": session.total_bytes,
            });
            b["charged_usd_micros"] = json!(session.charged_usd_micros.unwrap_or(0));
            b
        }
    };
    ok_json(body, decision)
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// The session's assembling directory: the durable staging directory the attempt
/// promotion also uses, so a session's pre-reservation file and the attempt's
/// post-reservation file share one place.
fn signing_dir(storage: &StorageState) -> &std::path::Path {
    // A storage seam wired for uploads always carries the signing seam; a deployment
    // without it cannot reach the paid path. The session create already resolved the
    // funding context, so the signing seam is present.
    storage
        .signing()
        .map(|s| s.durable_staging_dir())
        .unwrap_or_else(|| std::path::Path::new("."))
}

/// Run the same cached-credit affordability check the billed path runs, returning a
/// problem when the entitled account cannot fund the chargeable bytes.
async fn check_affordability(
    state: &AppState,
    storage: &StorageState,
    ctx: &UploadContext,
    chargeable: u64,
) -> Option<Problem> {
    let Some(funding) = ctx.funding() else {
        return Some(Problem::of(
            "no-funding-grant",
            "no storage funding source entitles this account to store content beyond the free window",
        ));
    };
    let _ = state;
    match storage.backend().affords(funding, chargeable).await {
        Ok(()) => None,
        Err(crate::storage::StorageError::InsufficientCredit) => Some(Problem::of(
            "insufficient-storage-credit",
            "the storage funding source cannot fund content of this size",
        )),
        Err(_) => Some(Problem::of(
            "service-unavailable",
            "content storage could not be checked",
        )),
    }
}

/// A stable terminal signal for a chunk PUT against a non-open session.
fn session_not_open(base: &str, trace: Uuid, session: &UploadSession) -> Response {
    match session.state {
        SessionState::Expired => problem(
            base,
            trace,
            "session-expired",
            "the upload session has expired",
        ),
        SessionState::Completed => problem(
            base,
            trace,
            "validation-failed",
            "the session is already complete; no more chunks are accepted",
        ),
        SessionState::Failed => problem(
            base,
            trace,
            "sha256-mismatch",
            session
                .failure_reason
                .clone()
                .unwrap_or_else(|| "the session previously failed".to_string()),
        ),
        SessionState::Assembling => problem(
            base,
            trace,
            "validation-failed",
            "the session is being finalised; no more chunks are accepted",
        ),
        SessionState::Open => {
            // Unreachable for this helper, but render a benign signal rather than panic.
            problem(
                base,
                trace,
                "internal-error",
                "unexpected open session state",
            )
        }
    }
}

/// Build a problem response from a code and detail.
fn problem(base: &str, trace: Uuid, code: &str, detail: impl Into<String>) -> Response {
    Problem::of(code, detail).into_response_with(base, trace)
}

/// Read back a session's authoritative received set and render the chunk-PUT 200
/// body. Shared by the first-arrival path and the idempotent re-PUT path so both
/// report the same `received`/`remaining`/`complete` shape from the same source.
async fn received_chunk_ok(
    state: &AppState,
    account_id: Uuid,
    session_id: Uuid,
    index: u32,
    decision: &crate::api::middleware::rate_limit::RateDecision,
) -> Response {
    let session = match load_session_for_account(&state.pool, session_id, account_id).await {
        Ok(Some(s)) => s,
        _ => {
            return Problem::of("internal-error", "the session vanished after a chunk")
                .into_response_with(&state.config.problem_type_base, guard::new_trace_id())
        }
    };
    let body = json!({
        "index": index,
        "received": session.received_indices(),
        "remaining": session.chunk_count.saturating_sub(session.received_count),
        "complete": session.is_complete(),
    });
    ok_json(body, decision)
}

/// Render a 200 JSON body and stamp the rate headers.
fn ok_json(body: Value, decision: &crate::api::middleware::rate_limit::RateDecision) -> Response {
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    )
        .into_response();
    guard::apply_rate_headers(&mut response, decision);
    response
}

/// Read the whole request body and parse it as the create JSON. The create body is
/// small (a declaration, never content), so buffering it is fine.
async fn read_json(body: Body) -> std::result::Result<CreateRequest, String> {
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|e| format!("the request body could not be read: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("the request body was not valid JSON: {e}"))
}

/// Parse a 64-lowercase-hex string into a 32-byte digest.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    let raw = hex::decode(s).ok()?;
    raw.try_into().ok()
}

/// The declared request `Content-Length`, when present and parseable.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

/// Parse the required RFC 9530 `Digest: sha-256=<base64>` header into a 32-byte
/// digest. The header value is a structured-field dictionary; this reads the
/// `sha-256` member's base64 byte-sequence value. A missing header, an absent
/// `sha-256` member, or a non-32-byte value is an error.
fn parse_digest_header(headers: &HeaderMap) -> std::result::Result<[u8; 32], String> {
    let raw = headers
        .get("digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "the required Digest header is missing".to_string())?;

    for member in raw.split(',') {
        let member = member.trim();
        let Some((alg, value)) = member.split_once('=') else {
            continue;
        };
        if !alg.trim().eq_ignore_ascii_case("sha-256") {
            continue;
        }
        // RFC 9530 wraps the byte-sequence value in colons (`:<base64>:`); accept it
        // with or without the wrapping colons for client leniency.
        let value = value.trim().trim_matches(':');
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| "the Digest sha-256 value is not valid base64".to_string())?;
        return decoded
            .try_into()
            .map_err(|_| "the Digest sha-256 value is not 32 bytes".to_string());
    }
    Err("the Digest header does not carry a sha-256 member".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex32_accepts_lowercase_64_hex_only() {
        let hex = "ab".repeat(32);
        assert!(parse_hex32(&hex).is_some());
        // Wrong length.
        assert!(parse_hex32("abcd").is_none());
        // Uppercase is rejected (the wire form is lowercase).
        assert!(parse_hex32(&"AB".repeat(32)).is_none());
        // Non-hex.
        assert!(parse_hex32(&"zz".repeat(32)).is_none());
    }

    #[test]
    fn parse_digest_header_reads_the_sha256_member() {
        let digest = [0x11u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);

        // Bare form.
        let mut headers = HeaderMap::new();
        headers.insert("digest", format!("sha-256={b64}").parse().unwrap());
        assert_eq!(parse_digest_header(&headers).unwrap(), digest);

        // RFC 9530 colon-wrapped byte-sequence form.
        let mut wrapped = HeaderMap::new();
        wrapped.insert("digest", format!("sha-256=:{b64}:").parse().unwrap());
        assert_eq!(parse_digest_header(&wrapped).unwrap(), digest);

        // Case-insensitive algorithm token, with other members present.
        let mut mixed = HeaderMap::new();
        mixed.insert(
            "digest",
            format!("md5=xxxx, SHA-256={b64}").parse().unwrap(),
        );
        assert_eq!(parse_digest_header(&mixed).unwrap(), digest);
    }

    #[test]
    fn parse_digest_header_rejects_missing_or_malformed() {
        let empty = HeaderMap::new();
        assert!(parse_digest_header(&empty).is_err());

        let mut wrong_len = HeaderMap::new();
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        wrong_len.insert("digest", format!("sha-256={short}").parse().unwrap());
        assert!(parse_digest_header(&wrong_len).is_err());

        let mut no_member = HeaderMap::new();
        no_member.insert("digest", "md5=abcd".parse().unwrap());
        assert!(parse_digest_header(&no_member).is_err());
    }
}
