//! The content-upload surface: streamed multipart staging, sign-once-in-route,
//! a durable pre-upload reservation, and a success-gated storage charge.
//!
//! `POST /api/v1/poe/uploads` accepts a `multipart/form-data` body whose `file*`
//! parts each carry a content blob. Each part is streamed to a tmpfs staging file
//! with a rolling SHA-256 and a byte ceiling (the smaller of the per-file limit
//! and what is left of the batch budget), so a multi-gigabyte blob is never
//! buffered in memory.
//!
//! A staged file is then deduped by `(account, sha256)` — re-uploading identical
//! bytes converges on the prior receipt rather than paying the provider twice. A
//! fresh file beyond the free-storage window is BILLED: the route signs the ANS-104
//! data item once (the randomised PSS signature, and so the item id, is fixed before
//! the first POST), writes a durable reservation plus a USD hold and a believed winc
//! charge BEFORE the provider is paid, claims the single-POST lease, streams the
//! reconstructed bytes to the backend under an abort deadline, and on a 2xx commits
//! the receipt and the final charge — all keyed on the attempt id so the upload is
//! charged exactly once even under a concurrent retry or a crash. A file within the
//! free window posts at zero charge with no reservation.
//!
//! The route returns 200 with a per-file ok/accepted/error result even when
//! individual files failed; a concurrent retry of the same in-flight bytes attaches
//! to the existing attempt and returns its `attempt_id` (the client reads the
//! terminal outcome through [`attempt_status`]). A crossed batch ceiling, too many
//! files, an over-declared `Content-Length`, an unknown `target`, or a malformed
//! multipart frame are hard problem responses.

use std::time::Duration;

use axum::extract::{Multipart, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::middleware::{idempotency, scope};
use crate::api::problem::Problem;
use crate::api::routes::guard;
use crate::api::state::{AppState, StorageState, UploadSigning};
use crate::ledger::account::operator_for_account;
use crate::storage::{
    authorize_charge, claim_post_lease, commit_attempt, load_attempt, lookup_receipt,
    persist_receipt, release_attempt, release_post_lease, reserve_attempt, stage_stream, Attempt,
    AttemptState, AuthorizedFunding, ReleaseReason, ReserveOutcome, ReserveSpec, SettleOutcome,
    StagedFile, StagingError, StorageChargePrincipal, StorageError, StorageReceipt,
};

/// The multipart field prefix marking a content file part. Any other field name
/// (e.g. the `target` selector) is read by the staging loop.
const FILE_FIELD_PREFIX: &str = "file";

/// The multipart field naming the storage backend target.
const TARGET_FIELD: &str = "target";

/// `POST /api/v1/poe/uploads` — stream content to the storage backend.
///
/// Requires `poe:create`. See the module docs for the streaming, dedup, billing,
/// and per-file-result semantics. An `Idempotency-Key` header makes the whole batch
/// body replayable after it commits (the multipart body is not hashed, so the key is
/// the caller's promise of sameness).
pub async fn uploads(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_POE_CREATE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    let Some(storage) = state.storage.as_ref() else {
        return Problem::of(
            "service-unavailable",
            "content storage is not configured for this deployment",
        )
        .into_response_with(base, trace);
    };

    let limits = state.config.upload_limits;
    // Cheap early-out: reject an honestly-declared over-large request before
    // streaming a byte. An under-declared length is still caught by the streaming
    // ceilings in the file loop.
    if let Some(declared) = content_length(&headers) {
        if limits.rejects_declared_length(declared) {
            return Problem::of(
                "envelope-too-large",
                format!(
                    "the declared request size {declared} bytes exceeds the {} byte batch ceiling",
                    limits.max_batch_bytes
                ),
            )
            .into_response_with(base, trace);
        }
    }

    // Whole-request replay (request-replay layer): a same-key retry that arrives
    // AFTER the first request stored its committed batch response replays the body
    // verbatim and the handler does no work. The hash is over (method, path) only —
    // the multipart body is multi-GB-streamed and cannot be buffered — so the key is
    // the caller's promise that the retried batch is the same one.
    let idem = match resolve_idempotency(&state, viewer.account_id, &headers, trace).await {
        Ok(idem) => idem,
        Err(resp) => return resp,
    };
    if let IdempotencyState::Replay(response) = idem {
        return response;
    }
    let IdempotencyState::Fresh(idem_ctx) = idem else {
        unreachable!("idempotency state is replay or fresh");
    };

    let ctx = match UploadContext::resolve(&state, storage, viewer.account_id).await {
        Ok(ctx) => ctx,
        Err(resp) => return resp.into_response_with(base, trace),
    };

    let batch = match drive_batch(&state, storage, &ctx, multipart).await {
        Ok(batch) => batch,
        Err(resp) => return resp,
    };

    let payload = serde_json::to_string(&batch.body).unwrap_or_else(|_| "{}".into());
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        payload.clone(),
    )
        .into_response();

    // Store the committing batch body for replay under the idempotency key, if one
    // was supplied. A batch carrying any 402-class (affordability) per-file failure
    // is NON-committing: a same-key retry after the account tops up must run fresh so
    // the now-affordable files upload, mirroring the publish-batch policy. A batch
    // with no 402-class failure (including an all-non-402-error batch) is a recorded
    // outcome the client should not re-run, so it commits.
    if let Some(ctx) = idem_ctx {
        if !batch.any_non_committing {
            ctx.store(StatusCode::OK, &payload).await;
        }
    }

    guard::apply_rate_headers(&mut response, &decision);
    response
}

/// The per-request funding/signing context resolved once before the file loop.
///
/// Resolved once for a single-shot batch and once per resumable-upload `complete`,
/// so both ingress surfaces price and fund a stored file through the same seam.
pub(crate) struct UploadContext {
    account_id: Uuid,
    operator_id: Uuid,
    /// The funding capability the paid path draws, when this caller is entitled.
    /// `None` means no live grant entitles the caller for the backend; a paid file
    /// then surfaces a per-file no-funding-grant error, while a free file still
    /// posts.
    funding: Option<AuthorizedFunding>,
    /// The per-byte storage price (femto-USD) the route bills paid bytes at,
    /// resolved from the pricing seam.
    ar_usd_per_byte_femto: i64,
}

impl UploadContext {
    /// The funding capability the paid path draws, when this caller is entitled. The
    /// session create-time affordability check reads it through the same seam the
    /// billed path uses.
    pub(crate) fn funding(&self) -> Option<&AuthorizedFunding> {
        self.funding.as_ref()
    }

    /// Resolve the operator, the funding capability, and the storage price. A
    /// missing pricing seam or operator is a retryable 503; a missing funding grant
    /// is carried as `None` so a free-window file still succeeds.
    pub(crate) async fn resolve(
        state: &AppState,
        storage: &StorageState,
        account_id: Uuid,
    ) -> Result<Self, Problem> {
        let operator_id = match operator_for_account(&state.pool, account_id).await {
            Ok(Some(operator_id)) => operator_id,
            Ok(None) => {
                return Err(Problem::of(
                    "service-unavailable",
                    "the account is not provisioned under an operator",
                ))
            }
            Err(_) => {
                return Err(Problem::of(
                    "service-unavailable",
                    "content storage could not be resolved",
                ))
            }
        };

        let principal = StorageChargePrincipal::Account {
            operator_id,
            account_id,
        };
        let funding = match authorize_charge(&state.pool, storage.backend_name(), principal).await {
            Ok(funding) => funding,
            Err(_) => {
                return Err(Problem::of(
                    "service-unavailable",
                    "content storage funding could not be resolved",
                ))
            }
        };

        // Resolve the storage price once for the batch. The pricing seam supplies the
        // FX the engine prices bytes at; without it the route cannot price a paid
        // upload, so report the dependency unavailable.
        let Some(pricing) = state.pricing.as_ref() else {
            return Err(Problem::of(
                "service-unavailable",
                "the pricing dependency is unavailable",
            ));
        };
        let inputs = match pricing.resolve_dyn(account_id, 0, 0, 0).await {
            Ok(inputs) => inputs,
            Err(_) => {
                return Err(Problem::of(
                    "service-unavailable",
                    "the pricing dependency is unavailable",
                ))
            }
        };

        Ok(Self {
            account_id,
            operator_id,
            funding,
            ar_usd_per_byte_femto: inputs.fx.ar_usd_per_byte_femto,
        })
    }
}

/// Drive the multipart loop: validate the `target`, stage each `file*` part, and
/// store it, returning the batch wire body. A hard fault (bad target, crossed
/// ceiling, too many files, malformed frame) short-circuits with a problem response.
async fn drive_batch(
    state: &AppState,
    storage: &StorageState,
    ctx: &UploadContext,
    mut multipart: Multipart,
) -> Result<BatchOutcome, Response> {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;
    let limits = state.config.upload_limits;

    let mut results: Vec<Value> = Vec::new();
    let mut file_count: usize = 0;
    let mut staged_total: u64 = 0;
    // A 402-class per-file outcome makes the whole batch non-committing for the
    // idempotency store, so a same-key retry after a top-up uploads fresh.
    let mut any_non_committing = false;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                return Err(Problem::of(
                    "invalid-body",
                    format!("the multipart body could not be parsed: {e}"),
                )
                .into_response_with(base, trace));
            }
        };

        let name = field.name().unwrap_or("").to_string();

        // The `target` selector is a validated enum: absent or `arweave` is accepted,
        // an explicit unknown value is rejected for the whole request (the backend
        // dispatch is keyed on it). Other non-file fields are drained and skipped so
        // the parser advances.
        //
        // Non-file fields are NEVER buffered whole: the route's body limit is sized
        // for multi-gigabyte file parts, so a metadata field read on trust would let
        // one hostile part allocate the whole batch ceiling in memory. `target` is
        // read through a tiny bounded collector; anything else is discarded
        // chunk-by-chunk.
        if name == TARGET_FIELD {
            let value = match read_bounded_text(field, MAX_METADATA_FIELD_BYTES).await {
                Ok(value) => value,
                Err(detail) => {
                    return Err(Problem::of("invalid-body", detail).into_response_with(base, trace));
                }
            };
            if !value.is_empty() && value != "arweave" {
                return Err(Problem::of(
                    "unsupported-storage-target",
                    format!("storage target {value:?} is not supported; use \"arweave\""),
                )
                .into_response_with(base, trace));
            }
            continue;
        }
        if !name.starts_with(FILE_FIELD_PREFIX) {
            if let Err(e) = drain_field(field).await {
                return Err(Problem::of(
                    "invalid-body",
                    format!("the multipart body could not be parsed: {e}"),
                )
                .into_response_with(base, trace));
            }
            continue;
        }

        file_count += 1;
        if file_count > limits.max_files {
            return Err(Problem::of(
                "envelope-too-large",
                format!("an upload carries at most {} files", limits.max_files),
            )
            .into_response_with(base, trace));
        }

        let content_type = field
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_string();
        let idx = file_count - 1;

        let remaining = limits.remaining_batch_budget(staged_total);
        let ceiling = limits.max_file_bytes.min(remaining);

        let staged = match stage_stream(&state.config.staging_dir, ceiling, field).await {
            Ok(s) => s,
            Err(StagingError::TooLarge { .. }) => {
                return Err(Problem::of(
                    "envelope-too-large",
                    "an uploaded file exceeded the size ceiling",
                )
                .into_response_with(base, trace));
            }
            Err(StagingError::Stream(detail)) => {
                return Err(Problem::of(
                    "invalid-body",
                    format!("the upload stream was truncated or malformed: {detail}"),
                )
                .into_response_with(base, trace));
            }
            Err(StagingError::Io(detail)) => {
                results.push(upload_error(idx, "internal-error", &detail));
                continue;
            }
        };

        staged_total = staged_total.saturating_add(staged.bytes);

        let outcome = store_one(state, storage, ctx, &content_type, staged).await;
        if let StoreOutcome::Error {
            non_committing: true,
            ..
        } = &outcome
        {
            any_non_committing = true;
        }
        results.push(outcome.into_batch_value(idx));
    }

    Ok(BatchOutcome {
        body: json!({ "uploads": results }),
        any_non_committing,
    })
}

/// The result of driving the multipart batch: the wire body plus whether any
/// per-file outcome was 402-class (which makes the batch non-committing for the
/// idempotency store).
struct BatchOutcome {
    body: Value,
    any_non_committing: bool,
}

/// The disposition of storing one logical file, independent of the wire shape it is
/// rendered onto.
///
/// `store_one` produces this so both ingress surfaces — the single-shot multipart
/// batch and the resumable-upload `complete` — share one pipeline yet render their
/// own contract. The batch path keys it on a per-file `idx`
/// ([`StoreOutcome::into_batch_value`]); the session path renders the single-file
/// `ok`/`accepted`/dedup shape directly.
#[derive(Debug, Clone)]
pub(crate) enum StoreOutcome {
    /// A committed (or deduped) upload. `charged_usd_micros` is `None` for a
    /// pre-POST dedup hit (the prior receipt is the source of truth) and `Some` for
    /// a fresh or settled upload (`0` on a free-window or deduped commit).
    Ok {
        uri: String,
        sha256_hex: String,
        bytes: u64,
        charged_usd_micros: Option<i64>,
    },
    /// The bytes are already in flight under a concurrent upload of the same content;
    /// the caller polls the attempt for the terminal outcome.
    Accepted { attempt_id: Uuid },
    /// The store failed; retry this content. `non_committing` marks a 402-class
    /// (affordability) failure that must NOT commit the batch idempotency record, so
    /// a same-key retry after a top-up runs fresh rather than replaying the failure.
    Error {
        code: String,
        detail: String,
        non_committing: bool,
    },
}

impl StoreOutcome {
    fn ok_with(uri: &str, sha256_hex: &str, bytes: u64, charged: Option<i64>) -> Self {
        StoreOutcome::Ok {
            uri: uri.to_string(),
            sha256_hex: sha256_hex.to_string(),
            bytes,
            charged_usd_micros: charged,
        }
    }

    fn error(code: &str, detail: impl Into<String>) -> Self {
        StoreOutcome::Error {
            non_committing: is_non_committing_code(code),
            code: code.to_string(),
            detail: detail.into(),
        }
    }

    fn from_storage_error(error: &StorageError) -> Self {
        let (code, detail) = storage_error_parts(error);
        StoreOutcome::Error {
            non_committing: is_non_committing_code(&code),
            code,
            detail,
        }
    }

    /// Project onto the per-file batch wire shape, keyed on the file's `idx`.
    fn into_batch_value(self, idx: usize) -> Value {
        match self {
            StoreOutcome::Ok {
                uri,
                sha256_hex,
                bytes,
                charged_usd_micros,
            } => upload_ok(idx, &uri, &sha256_hex, bytes, charged_usd_micros),
            StoreOutcome::Accepted { attempt_id } => json!({
                "idx": idx,
                "accepted": true,
                "attempt_id": attempt_id.to_string(),
            }),
            StoreOutcome::Error { code, detail, .. } => upload_error(idx, &code, &detail),
        }
    }
}

/// Whether a per-file error code is 402-class (affordability), so it must not
/// commit the batch idempotency record. These are exactly the codes the problem
/// registry maps to HTTP 402: a same-key retry after the account tops up must run
/// the upload fresh rather than replay the stored failure. Kept as the single
/// definition both this route and any future caller share, mirroring the
/// publish-batch `PublishFailure::non_committing` policy.
fn is_non_committing_code(code: &str) -> bool {
    matches!(
        code,
        "insufficient-funds" | "no-funding-grant" | "insufficient-storage-credit"
    )
}

/// Store one staged file: dedup, free-window fast path, or the full billed
/// reservation -> sign -> POST -> commit saga.
///
/// The source of the staged file (single-shot tmpfs scratch, or a resumable-upload
/// assembled durable file adopted via [`StagedFile::adopt_durable`]) is invisible
/// here: this is the single billing/dedup/free-window entry point both ingress
/// surfaces converge on, so a logical file is charged exactly once regardless of how
/// its bytes arrived.
pub(crate) async fn store_one(
    state: &AppState,
    storage: &StorageState,
    ctx: &UploadContext,
    content_type: &str,
    staged: StagedFile,
) -> StoreOutcome {
    let pool = &state.pool;
    let account_id = ctx.account_id;
    let backend = storage.backend_name();

    // Dedup BEFORE any work: an account re-uploading identical bytes to this backend
    // converges on the prior receipt and the provider is never paid twice. The same
    // bytes on a different backend are a separate artifact, so the backend is part of
    // the dedup key.
    match lookup_receipt(pool, account_id, backend, &staged.sha256).await {
        Ok(Some(existing)) => {
            return StoreOutcome::ok_with(
                &existing.uri,
                &existing.sha256_hex(),
                existing.bytes,
                None,
            )
        }
        Ok(None) => {}
        Err(_) => return StoreOutcome::error("internal-error", "the upload dedup lookup failed"),
    }

    let free_storage_bytes = state.config.free_storage_bytes;
    let chargeable_bytes = staged.bytes.saturating_sub(free_storage_bytes);

    // The free-window fast path: nothing to charge, so no reservation, hold, or winc
    // touch. Sign once and POST through the backend, persist the receipt at zero
    // charge. The committed dedup unique converges concurrent free-window retries.
    if chargeable_bytes == 0 {
        return free_window_upload(state, storage, ctx, content_type, &staged).await;
    }

    billed_upload(state, storage, ctx, content_type, staged, chargeable_bytes).await
}

/// Sign and POST a free-window file (zero charge), persisting the receipt.
///
/// Unlike the billed path, the free path takes no reservation row, so nothing in
/// the database serialises two concurrent identical free uploads: both would pass
/// the dedup lookup and each POST the same bytes to the provider (a duplicate
/// provider store / two data items for one logical file) before `persist_receipt`
/// converges them on the receipt unique. The dedup-once invariant must hold under
/// concurrency for free uploads too, so the whole lookup -> sign -> POST -> persist
/// section runs under a per-(account, backend, sha256) advisory lock: exactly one
/// concurrent identical upload POSTs, and the losers block until it commits, then
/// see the committed receipt on their lookup and dedup without a second POST.
async fn free_window_upload(
    state: &AppState,
    storage: &StorageState,
    ctx: &UploadContext,
    content_type: &str,
    staged: &StagedFile,
) -> StoreOutcome {
    // Serialise concurrent identical free uploads. The lock is held across the whole
    // dedup -> POST -> persist critical section (released when `_dedup_lock` drops on
    // return), so only one contender stores the bytes and the rest converge on its
    // receipt. The billed path is serialised by its reserved-slot unique instead.
    let lock_name = upload_dedup_lock_name(ctx.account_id, storage.backend_name(), &staged.sha256);
    let _dedup_lock =
        match crate::runtime::locks::AdvisoryLock::acquire(&state.pool, &lock_name).await {
            Ok(lock) => lock,
            Err(_) => {
                return StoreOutcome::error(
                    "service-unavailable",
                    "the upload dedup lock could not be acquired",
                )
            }
        };

    let Some(signing) = storage.signing() else {
        return StoreOutcome::error(
            "service-unavailable",
            "the upload signing seam is not configured for this deployment",
        );
    };
    // The free path still needs a funding source to name the signer (the operator's
    // key signs every data item); resolve it the same way the paid path does.
    let Some(funding) = ctx.funding.as_ref() else {
        return StoreOutcome::error(
            "no-funding-grant",
            "no storage funding source entitles this account to upload content",
        );
    };

    // Under the dedup lock: a concurrent identical free upload that already stored
    // these bytes has committed its receipt before releasing the lock, so this
    // lookup hits and we dedup without signing or POSTing. The losers of the race
    // converge here.
    match lookup_receipt(
        &state.pool,
        ctx.account_id,
        storage.backend_name(),
        &staged.sha256,
    )
    .await
    {
        Ok(Some(existing)) => {
            return StoreOutcome::ok_with(
                &existing.uri,
                &existing.sha256_hex(),
                existing.bytes,
                None,
            )
        }
        Ok(None) => {}
        Err(_) => return StoreOutcome::error("internal-error", "the upload dedup re-check failed"),
    }

    let envelope = match sign_staged(signing, funding, content_type, staged).await {
        Ok(env) => env,
        Err(detail) => return StoreOutcome::error("internal-error", detail),
    };
    let owner = match signing.keyring().arweave_signer_for(funding) {
        Some(signer) => signer.owner(),
        None => {
            return StoreOutcome::error(
                "service-unavailable",
                "this instance does not hold the funding key for the resolved source",
            )
        }
    };

    let receipt = match post_with_deadline(
        storage,
        funding,
        &envelope,
        &owner,
        staged.path(),
        signing.upload_timeout(),
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(e) => return StoreOutcome::from_storage_error(&e),
    };

    match persist_receipt(
        &state.pool,
        ctx.account_id,
        &staged.sha256,
        staged.bytes,
        storage.backend_name(),
        &receipt,
    )
    .await
    {
        Ok(persisted) => StoreOutcome::ok_with(
            &persisted.uri,
            &persisted.sha256_hex(),
            persisted.bytes,
            Some(0),
        ),
        Err(_) => StoreOutcome::error(
            "internal-error",
            "the upload receipt could not be persisted",
        ),
    }
}

/// The full billed saga for a chargeable file. See the §3.3 flow in the module docs:
/// attach-check -> affords -> sign once -> promote -> reserve+hold+winc-charge ->
/// claim the POST lease -> POST under the abort deadline -> commit/release.
#[allow(clippy::too_many_arguments)]
async fn billed_upload(
    state: &AppState,
    storage: &StorageState,
    ctx: &UploadContext,
    content_type: &str,
    staged: StagedFile,
    chargeable_bytes: u64,
) -> StoreOutcome {
    let pool = &state.pool;
    let backend = storage.backend_name();
    let account_id = ctx.account_id;

    let Some(signing) = storage.signing() else {
        return StoreOutcome::error(
            "service-unavailable",
            "the upload signing seam is not configured for this deployment",
        );
    };
    let Some(funding) = ctx.funding.as_ref() else {
        return StoreOutcome::error(
            "no-funding-grant",
            "no storage funding source entitles this account to store content beyond the free window",
        );
    };

    // Fast-path attach: if an in-flight attempt for these exact bytes already exists,
    // attach to it without signing. This is a cheap optimisation; the authoritative
    // claim is the ON CONFLICT insert in reserve_attempt.
    match crate::storage::load_live_attempt(pool, account_id, backend, &staged.sha256).await {
        Ok(Some(live)) => return attach_outcome(&live),
        Ok(None) => {}
        Err(_) => return StoreOutcome::error("internal-error", "the upload attach lookup failed"),
    }

    // Affordability against the cached operator credit (no provider call).
    match storage.backend().affords(funding, chargeable_bytes).await {
        Ok(()) => {}
        Err(StorageError::InsufficientCredit) => {
            return StoreOutcome::error(
                "insufficient-storage-credit",
                "the storage funding source cannot fund content of this size",
            )
        }
        Err(_) => {
            return StoreOutcome::error(
                "service-unavailable",
                "content storage could not be checked",
            )
        }
    }

    // Sign ONCE. The randomised PSS signature, and so the item id, is fixed here.
    let envelope = match sign_staged(signing, funding, content_type, &staged).await {
        Ok(env) => env,
        Err(detail) => return StoreOutcome::error("internal-error", detail),
    };
    let owner = match signing.keyring().arweave_signer_for(funding) {
        Some(signer) => signer.owner(),
        None => {
            return StoreOutcome::error(
                "service-unavailable",
                "this instance does not hold the funding key for the resolved source",
            )
        }
    };

    // The deterministic user-facing USD charge: chargeable bytes priced at the
    // engine's femto-USD-per-byte, rounded up (the same arithmetic the quote uses).
    let charged_usd_micros = match price_storage(chargeable_bytes, ctx.ar_usd_per_byte_femto) {
        Ok(price) => price,
        Err(detail) => return StoreOutcome::error("internal-error", detail),
    };
    let estimated_winc = estimate_winc(state, funding, chargeable_bytes).await;

    // Carry the staged identity before the file is consumed by the durable promotion.
    let sha256 = staged.sha256;
    let bytes = staged.bytes;

    // Mint the attempt id ONCE and name the durable staged file by it, then carry the
    // same id into the reservation so the attempt row and its content file share one
    // id (the recovery sweep, the orphan janitor, and operator debugging read one id,
    // never two). A crash after the POST is recoverable from the row + this file.
    let attempt_id = Uuid::now_v7();
    let staged_path =
        match crate::storage::promote_to_durable(staged, signing.durable_staging_dir(), attempt_id)
            .await
        {
            Ok(path) => path,
            Err(e) => {
                return StoreOutcome::error(
                    "internal-error",
                    format!("durable staging failed: {e}"),
                )
            }
        };
    let staged_path_str = staged_path.to_string_lossy().into_owned();

    let spec = ReserveSpec {
        id: attempt_id,
        account_id,
        operator_id: ctx.operator_id,
        funding_source_id: funding.funding_source_id(),
        backend,
        sha256,
        bytes,
        chargeable_bytes,
        charged_usd_micros,
        estimated_winc,
        data_item_id: &envelope.id_b64url,
        data_item_signature: &envelope.signature,
        data_item_anchor: envelope.anchor.as_ref().map(|a| a.as_slice()),
        data_item_tag_bytes: &envelope.tag_bytes,
        staged_path: &staged_path_str,
        request_id: None,
    };

    let outcome = match reserve_attempt(pool, &spec).await {
        Ok(o) => o,
        Err(_) => {
            let _ = crate::storage::delete_durable(&staged_path).await;
            return StoreOutcome::error("internal-error", "the upload reservation failed");
        }
    };

    let attempt = match outcome {
        ReserveOutcome::Claimed(attempt) => {
            // Close the committed-receipt race BEFORE paying the provider. Winning
            // the reserved slot only guards against another LIVE attempt; a
            // contender that already COMMITTED these exact bytes (between this
            // request's pre-upload dedup lookup and the reserve insert) left a
            // storage_upload receipt the reserve insert does not see, because the
            // live-slot unique is partial on state='reserved'. The live-slot unique
            // also guarantees no OTHER attempt can be reserved for this key while we
            // hold the slot, so any receipt that could race our POST is already
            // visible now: a single re-check here fully closes the window. If a
            // committed receipt exists, release the reservation (refunding the hold
            // and believed winc), drop the durable file, and dedup — never POST.
            match lookup_receipt(pool, account_id, backend, &sha256).await {
                Ok(Some(existing)) => {
                    // Resolve the losing reservation: DELETE the staged file FIRST,
                    // then release. The order is load-bearing for the no-double-POST
                    // invariant. The storage reconcile sweep re-POSTs a stale `reserved`
                    // attempt only while its staged file is still present; if the
                    // release (refund) fails, the attempt stays `reserved`, so the file
                    // must already be gone or the sweep would re-POST these
                    // already-deduped bytes (a second provider POST + a leaked hold).
                    // Deleting this loser's own staged copy is safe: the winner's
                    // committed content is an independent receipt. A failed release is
                    // then surfaced as a 5xx (never a silent success over a leaked hold);
                    // the sweep later releases the now-fileless reserved attempt.
                    let _ = crate::storage::delete_durable(&staged_path).await;
                    if let Err(_e) =
                        release_attempt(pool, attempt.id, ReleaseReason::ProviderRejected, None)
                            .await
                    {
                        return StoreOutcome::error(
                            "internal-error",
                            "the upload reservation could not be released after a dedup hit",
                        );
                    }
                    return StoreOutcome::ok_with(
                        &existing.uri,
                        &existing.sha256_hex(),
                        existing.bytes,
                        None,
                    );
                }
                Ok(None) => attempt,
                Err(_) => {
                    // The dedup re-check failed; do not pay the provider on an
                    // unverified slot. Same delete-first-then-release ordering as the
                    // dedup-hit branch: the staged file is dropped BEFORE the release so
                    // a failed release can never leave a sweep-recoverable
                    // reserved-with-file attempt that re-POSTs. A failed release is
                    // surfaced (not swallowed) so a leaked hold is never hidden behind
                    // the re-check error.
                    let _ = crate::storage::delete_durable(&staged_path).await;
                    let release =
                        release_attempt(pool, attempt.id, ReleaseReason::ProviderRejected, None)
                            .await;
                    let detail = if release.is_err() {
                        "the upload dedup re-check failed and the reservation could not be released"
                    } else {
                        "the upload dedup re-check failed"
                    };
                    return StoreOutcome::error("internal-error", detail);
                }
            }
        }
        ReserveOutcome::Attached(winner) => {
            // Lost the live-slot race: a contender owns the logical upload. Drop our
            // durable file and the wasted signature, and attach to the winner.
            let _ = crate::storage::delete_durable(&staged_path).await;
            return attach_outcome(&winner);
        }
        ReserveOutcome::Deduplicated(existing) => {
            // Lost the slot to a contender that has since committed these exact bytes.
            // Drop our durable file and the wasted signature, and return the winner's
            // receipt as a dedup hit (no charge).
            let _ = crate::storage::delete_durable(&staged_path).await;
            return StoreOutcome::ok_with(
                &existing.uri,
                &existing.sha256_hex(),
                existing.bytes,
                None,
            );
        }
        ReserveOutcome::InsufficientFunds => {
            let _ = crate::storage::delete_durable(&staged_path).await;
            return StoreOutcome::error(
                "insufficient-funds",
                "the account balance does not cover the storage charge",
            );
        }
    };

    // Claim the external-POST window. The handler that just inserted wins this
    // trivially; the lease keeps a sweep worker from POSTing the same item. The
    // granted token fences the later lease release, so a stalled handler whose lease
    // has lapsed (and been re-granted to a recovery sweep) cannot wipe the new
    // owner's lease.
    let lease_secs = signing.upload_claim_lease_ttl().as_secs() as i64;
    let claim_token = match claim_post_lease(pool, attempt.id, lease_secs).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            return StoreOutcome::Accepted {
                attempt_id: attempt.id,
            }
        }
        Err(_) => return StoreOutcome::error("internal-error", "the upload claim lease failed"),
    };

    // POST the reconstructed bytes under the abort deadline.
    let receipt = match post_with_deadline(
        storage,
        funding,
        &envelope,
        &owner,
        &staged_path,
        signing.upload_timeout(),
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(StorageError::Unavailable(detail)) => {
            // Ambiguous: the POST may have been accepted before the connection
            // dropped (or the deadline aborted it). Do NOT release; leave the attempt
            // reserved and free the lease so the recovery sweep can resolve it. The
            // release is fenced on the token we claimed, so a lapsed-then-resumed
            // handler frees only its own lease, never a sweep's fresh one.
            let _ = release_post_lease(pool, attempt.id, claim_token).await;
            return StoreOutcome::error(
                "service-unavailable",
                format!("storage backend unavailable, retry pending: {detail}"),
            );
        }
        Err(e) => {
            // Definite failure (a 402, or a build fault before any bytes were sent):
            // the bytes never landed. Release the hold and refund the believed winc.
            if let Ok(SettleOutcome::Settled { .. }) =
                release_attempt(pool, attempt.id, ReleaseReason::ProviderRejected, None).await
            {
                let _ = crate::storage::delete_durable(&staged_path).await;
            }
            return StoreOutcome::from_storage_error(&e);
        }
    };

    // Success: commit the receipt + the final charge under the CAS. The reported
    // charge is the amount the settlement ACTUALLY debited, not the reserve-time
    // estimate: a deduped commit (the bytes were already stored for this account on
    // this backend) charges nothing, so it reports `0` and returns the existing
    // receipt's URI.
    match commit_attempt(pool, attempt.id, &receipt, None).await {
        Ok(SettleOutcome::Settled { charged_usd_micros }) => {
            let _ = crate::storage::delete_durable(&staged_path).await;
            // A deduped commit returns no new artifact; surface the committed
            // receipt's URI (which is the existing one on a dedup, ours otherwise).
            match lookup_receipt(pool, account_id, backend, &sha256).await {
                Ok(Some(existing)) => StoreOutcome::ok_with(
                    &existing.uri,
                    &existing.sha256_hex(),
                    existing.bytes,
                    Some(charged_usd_micros),
                ),
                _ => StoreOutcome::ok_with(
                    &receipt.uri,
                    &hex::encode(sha256),
                    bytes,
                    Some(charged_usd_micros),
                ),
            }
        }
        Ok(SettleOutcome::AlreadySettled) => {
            // The sweep committed it first; read back the receipt and the realized
            // charge the winning settler stamped on the attempt row.
            let charged = load_attempt(pool, attempt.id)
                .await
                .ok()
                .flatten()
                .and_then(|a| a.settled_charge_usd_micros)
                .unwrap_or(0);
            match lookup_receipt(pool, account_id, backend, &sha256).await {
                Ok(Some(existing)) => StoreOutcome::ok_with(
                    &existing.uri,
                    &existing.sha256_hex(),
                    existing.bytes,
                    Some(charged),
                ),
                _ => {
                    StoreOutcome::ok_with(&receipt.uri, &hex::encode(sha256), bytes, Some(charged))
                }
            }
        }
        Err(_) => StoreOutcome::error("internal-error", "the upload commit failed"),
    }
}

/// `GET /api/v1/poe/uploads/attempts/{attempt_id}` — the authoritative terminal
/// outcome of an upload attempt.
///
/// A client that attached to an in-flight attempt (or whose original connection
/// dropped) polls this for the result: `reserved` (still in flight), `committed`
/// (success, with the `uri` and `charged_usd_micros`), or `released` (failure, with
/// the `reason`). The row is read POST-CAS, so it never dangles. An attempt the
/// caller does not own returns 404 indistinguishably from a non-existent one.
pub async fn attempt_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(attempt_id): Path<String>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_POE_CREATE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    if state.storage.is_none() {
        return Problem::of(
            "service-unavailable",
            "content storage is not configured for this deployment",
        )
        .into_response_with(base, trace);
    }

    let Ok(attempt_id) = Uuid::parse_str(&attempt_id) else {
        return Problem::of("not-found", "no such upload attempt").into_response_with(base, trace);
    };

    let attempt = match load_attempt(&state.pool, attempt_id).await {
        Ok(Some(attempt)) => attempt,
        Ok(None) => {
            return Problem::of("not-found", "no such upload attempt")
                .into_response_with(base, trace)
        }
        Err(_) => {
            return Problem::of(
                "service-unavailable",
                "the upload attempt could not be read",
            )
            .into_response_with(base, trace)
        }
    };

    // Ownership: an attempt the caller does not own is indistinguishable from a
    // non-existent one (no cross-account existence oracle).
    if attempt.account_id != viewer.account_id {
        return Problem::of("not-found", "no such upload attempt").into_response_with(base, trace);
    }

    let body = match attempt.state {
        AttemptState::Reserved => json!({
            "attempt_id": attempt.id.to_string(),
            "state": "reserved",
            "sha256": attempt.sha256_hex(),
            "bytes": attempt.bytes,
            "backend": attempt.backend,
        }),
        AttemptState::Committed => {
            // Join the committed receipt for the URI; the charge is what the
            // settlement ACTUALLY debited, which is 0 for a deduped commit (the bytes
            // were already stored) and the held amount for a fresh receipt.
            let uri = lookup_receipt(
                &state.pool,
                attempt.account_id,
                &attempt.backend,
                &attempt.sha256,
            )
            .await
            .ok()
            .flatten()
            .map(|r| r.uri)
            .unwrap_or_default();
            json!({
                "attempt_id": attempt.id.to_string(),
                "state": "committed",
                "sha256": attempt.sha256_hex(),
                "bytes": attempt.bytes,
                "backend": attempt.backend,
                "uri": uri,
                "charged_usd_micros": attempt.settled_charge_usd_micros.unwrap_or(0),
            })
        }
        AttemptState::Released => json!({
            "attempt_id": attempt.id.to_string(),
            "state": "released",
            "sha256": attempt.sha256_hex(),
            "bytes": attempt.bytes,
            "backend": attempt.backend,
            "reason": attempt
                .release_reason
                .map(|r| r.as_str())
                .unwrap_or("provider_rejected"),
        }),
    };

    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    )
        .into_response();
    guard::apply_rate_headers(&mut response, &decision);
    response
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Sign a staged file's data item once, streaming the content through the deep-hash
/// so a multi-GB body is never buffered.
///
/// The signer is resolved INSIDE the blocking task from the shared keyring and the
/// funding capability, so the secret never crosses the await boundary and the
/// synchronous `std::io::Read`-based streaming sign never stalls the async runtime.
/// A funding source whose key this instance does not hold is an error here, not a
/// silent miss.
async fn sign_staged(
    signing: &UploadSigning,
    funding: &AuthorizedFunding,
    content_type: &str,
    staged: &StagedFile,
) -> Result<ans104::SignedEnvelope, String> {
    let path = staged.path().to_path_buf();
    let data_len = staged.bytes;
    let content_type = content_type.to_string();
    let keyring = signing.keyring().clone();
    let funding = funding.clone();
    tokio::task::spawn_blocking(move || {
        let signer = keyring
            .arweave_signer_for(&funding)
            .ok_or_else(|| "this instance does not hold the funding key".to_string())?;
        let mut file = std::fs::File::open(&path)
            .map_err(|e| format!("opening staged file for signing: {e}"))?;
        let tags = vec![ans104::Tag::new("Content-Type", content_type.into_bytes())];
        signer
            .sign_streaming_envelope(None, None, &tags, &mut file, data_len)
            .map_err(|e| format!("signing the data item: {e}"))
    })
    .await
    .map_err(|e| format!("the signing task panicked: {e}"))?
}

/// POST the reconstructed data item under a wall-clock deadline. A timeout maps to
/// `Unavailable` (the ambiguous path) so the abort fires before the lease lapses.
async fn post_with_deadline(
    storage: &StorageState,
    funding: &AuthorizedFunding,
    envelope: &ans104::SignedEnvelope,
    owner: &[u8],
    staged_path: &std::path::Path,
    timeout: Duration,
) -> Result<StorageReceipt, StorageError> {
    match tokio::time::timeout(
        timeout,
        storage
            .backend()
            .upload(funding, envelope, owner, staged_path),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(StorageError::Unavailable(
            "the upload exceeded the in-flight timeout and was aborted".into(),
        )),
    }
}

/// The deterministic USD storage charge for `chargeable_bytes` at the engine's
/// femto-USD-per-byte price, rounded up (the same arithmetic the quote uses).
fn price_storage(chargeable_bytes: u64, ar_usd_per_byte_femto: i64) -> Result<i64, String> {
    if ar_usd_per_byte_femto < 0 {
        return Err("storage price must be non-negative".into());
    }
    let product = i128::from(chargeable_bytes) * i128::from(ar_usd_per_byte_femto);
    let mut micros = product / 1_000_000_000;
    if product % 1_000_000_000 != 0 {
        micros += 1;
    }
    i64::try_from(micros).map_err(|_| "storage charge overflows i64".into())
}

/// Estimate the believed winc this upload consumes, for the operator's winc charge.
///
/// The user-facing USD charge is deterministic and quotable; the winc figure is a
/// best-effort belief the reconcile cron corrects against the actual provider
/// balance. When the cached credit row carries a provider-reported `fundable_bytes`
/// against a known `winc_balance`, that ratio is the most honest per-byte estimate;
/// otherwise fall back to a one-winc-per-chargeable-byte proxy. The result is clamped
/// to at least one winc, because the winc-credit ledger rejects a zero delta and a
/// charge must always register some belief the reconcile can then correct.
async fn estimate_winc(
    state: &AppState,
    funding: &AuthorizedFunding,
    chargeable_bytes: u64,
) -> rust_decimal::Decimal {
    use rust_decimal::Decimal;
    let bytes = Decimal::from(chargeable_bytes.max(1));
    let estimate = match crate::storage::load_credit(&state.pool, funding.funding_source_id()).await
    {
        Ok(Some(credit)) => match (credit.fundable_bytes, credit.winc_balance) {
            (Some(fundable), balance) if fundable > 0 && balance > Decimal::ZERO => {
                // winc per byte = balance / fundable; scale to the chargeable bytes
                // and round up so the believed charge never under-reserves.
                let per_byte = balance / Decimal::from(fundable);
                (per_byte * bytes)
                    .round_dp_with_strategy(0, rust_decimal::RoundingStrategy::AwayFromZero)
            }
            _ => bytes,
        },
        // No cached credit, or a read failure: fall back to the byte-count proxy. The
        // reconcile cron is the authority on the real consumption regardless.
        _ => bytes,
    };
    estimate.max(Decimal::ONE)
}

/// The declared request `Content-Length`, when present and parseable.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

/// The ceiling on a non-file metadata field's value (the `target` selector). The
/// longest valid value is a short backend name; 256 bytes leaves headroom without
/// letting a metadata part allocate anything worth attacking.
const MAX_METADATA_FIELD_BYTES: usize = 256;

/// Collect a small text field, refusing it the instant it crosses `cap` bytes.
/// Used instead of `Field::text()` for metadata fields, because the route's body
/// limit is sized for multi-gigabyte file parts and a whole-field read on trust
/// would buffer up to that limit into memory.
async fn read_bounded_text(
    mut field: axum::extract::multipart::Field<'_>,
    cap: usize,
) -> Result<String, String> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| format!("the multipart body could not be parsed: {e}"))?
    {
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(format!("a metadata field exceeded the {cap} byte ceiling"));
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|_| "a metadata field was not valid UTF-8".to_string())
}

/// Discard an unrecognised field chunk-by-chunk so the parser advances without
/// buffering it (the streaming counterpart of `Field::bytes()`).
async fn drain_field(
    mut field: axum::extract::multipart::Field<'_>,
) -> Result<(), axum::extract::multipart::MultipartError> {
    while field.chunk().await?.is_some() {}
    Ok(())
}

/// The advisory-lock name serialising concurrent free-window uploads of one
/// logical file. Keyed on the same `(account, backend, sha256)` identity the
/// receipt dedup uses, so two callers race for the lock exactly when they would
/// race for the receipt. The `poe:upload-dedup:` namespace keeps it from colliding
/// with the wallet locks' key space.
fn upload_dedup_lock_name(account_id: Uuid, backend: &str, sha256: &[u8; 32]) -> String {
    format!(
        "poe:upload-dedup:{account_id}:{backend}:{}",
        hex::encode(sha256)
    )
}

/// Project an attached winner onto a store outcome: the caller polls the winner's
/// attempt for the terminal result. A reserved winner is still in flight; a settled
/// winner (committed/released) has its committed dedup as the source of truth, but
/// either way the disposition is `accepted` keyed to the same attempt id.
fn attach_outcome(winner: &Attempt) -> StoreOutcome {
    StoreOutcome::Accepted {
        attempt_id: winner.id,
    }
}

/// A successful per-file upload result, optionally carrying the storage charge.
fn upload_ok(
    idx: usize,
    uri: &str,
    sha256_hex: &str,
    bytes: u64,
    charged_usd_micros: Option<i64>,
) -> Value {
    let mut v = json!({
        "idx": idx,
        "ok": true,
        "uri": uri,
        "sha256": sha256_hex,
        "bytes": bytes,
    });
    if let Some(charge) = charged_usd_micros {
        v["charged_usd_micros"] = json!(charge);
    }
    v
}

/// A failed per-file upload result.
fn upload_error(idx: usize, code: &str, detail: &str) -> Value {
    json!({
        "idx": idx,
        "ok": false,
        "error": { "code": code, "detail": detail },
    })
}

/// Map a storage-backend error to a stable problem code and human detail, shared by
/// the batch per-file result and the session-complete disposition.
fn storage_error_parts(error: &StorageError) -> (String, String) {
    match error {
        StorageError::InsufficientCredit => (
            "insufficient-storage-credit".to_string(),
            "the storage backend has insufficient credit to store this content".to_string(),
        ),
        StorageError::Unavailable(d) => (
            "service-unavailable".to_string(),
            format!("storage backend unavailable: {d}"),
        ),
        StorageError::Misconfigured(d) => (
            "service-unavailable".to_string(),
            format!("storage backend misconfigured: {d}"),
        ),
        StorageError::Build(d) => (
            "internal-error".to_string(),
            format!("storage upload failed: {d}"),
        ),
        StorageError::Io(d) => (
            "internal-error".to_string(),
            format!("storage staging error: {d}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Idempotency (whole-batch request replay).
// ---------------------------------------------------------------------------

/// The idempotency decision for an uploads request.
enum IdempotencyState {
    /// Replay this stored batch response verbatim.
    Replay(Response),
    /// Run the handler; the context (when `Some`) stores the committing batch.
    Fresh(Option<UploadIdempotencyContext>),
}

/// The context for storing the committing batch response under an idempotency key.
struct UploadIdempotencyContext {
    pool: sqlx::PgPool,
    account_id: Uuid,
    key: String,
    request_hash: Vec<u8>,
}

impl UploadIdempotencyContext {
    /// Store the committing batch body for replay. Best-effort: a store failure never
    /// fails the already-produced response.
    async fn store(&self, status: StatusCode, body: &str) {
        if idempotency::is_non_committing(status.as_u16()) {
            return;
        }
        let stored = idempotency::StoredResponse {
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

/// Resolve the idempotency state from the `Idempotency-Key` header. The request hash
/// is over (method, path) only, because the multipart body is multi-GB-streamed and
/// cannot be buffered; the key is the caller's promise that the retried batch is the
/// same.
async fn resolve_idempotency(
    state: &AppState,
    account_id: Uuid,
    headers: &HeaderMap,
    trace: Uuid,
) -> Result<IdempotencyState, Response> {
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

    let request_hash = idempotency::request_hash("POST", "/api/v1/poe/uploads", b"");

    match idempotency::lookup(
        &state.pool,
        account_id,
        &key,
        &request_hash,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(idempotency::Lookup::Miss) => {
            Ok(IdempotencyState::Fresh(Some(UploadIdempotencyContext {
                pool: state.pool.clone(),
                account_id,
                key,
                request_hash,
            })))
        }
        Ok(idempotency::Lookup::Hit(stored)) => {
            Ok(IdempotencyState::Replay(replay_response(stored)))
        }
        // The body is not hashed, so a same-key request can never differ by body; a
        // Conflict would only arise from a different (method, path), which cannot
        // happen on this single route. Treat it as a replay of the recorded response.
        Ok(idempotency::Lookup::Conflict) => Err(Problem::of(
            "idempotency-key-conflict",
            "the idempotency key was reused with a different request",
        )
        .into_response_with(base, trace)),
        Err(_) => Err(Problem::of(
            "service-unavailable",
            "the idempotency store is temporarily unavailable",
        )
        .into_response_with(base, trace)),
    }
}

/// Replay a stored batch response, stamping `Idempotent-Replayed`.
fn replay_response(stored: idempotency::StoredResponse) -> Response {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_ok_carries_the_wire_shape_and_optional_charge() {
        let v = upload_ok(2, "ar://abc", "ff00", 42, Some(1_000));
        assert_eq!(v["idx"], 2);
        assert_eq!(v["ok"], true);
        assert_eq!(v["uri"], "ar://abc");
        assert_eq!(v["sha256"], "ff00");
        assert_eq!(v["bytes"], 42);
        assert_eq!(v["charged_usd_micros"], 1_000);

        // The free path omits the charge field entirely (not present, not null).
        let free = upload_ok(0, "ar://x", "00", 1, None);
        assert!(free.get("charged_usd_micros").is_none());
    }

    #[test]
    fn upload_error_carries_a_code_and_detail() {
        let v = upload_error(0, "internal-error", "boom");
        assert_eq!(v["idx"], 0);
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "internal-error");
        assert_eq!(v["error"]["detail"], "boom");
    }

    #[test]
    fn storage_error_maps_to_a_stable_code() {
        let (code, _) = storage_error_parts(&StorageError::InsufficientCredit);
        assert_eq!(code, "insufficient-storage-credit");

        let (code, _) = storage_error_parts(&StorageError::Unavailable("429".to_string()));
        assert_eq!(code, "service-unavailable");

        let (code, _) = storage_error_parts(&StorageError::Build("sign".to_string()));
        assert_eq!(code, "internal-error");
    }

    #[test]
    fn store_outcome_renders_the_batch_dispositions() {
        let ok = StoreOutcome::ok_with("ar://abc", "ff00", 42, Some(7)).into_batch_value(2);
        assert_eq!(ok["idx"], 2);
        assert_eq!(ok["ok"], true);
        assert_eq!(ok["uri"], "ar://abc");
        assert_eq!(ok["charged_usd_micros"], 7);

        let attempt_id = Uuid::now_v7();
        let accepted = StoreOutcome::Accepted { attempt_id }.into_batch_value(3);
        assert_eq!(accepted["idx"], 3);
        assert_eq!(accepted["accepted"], true);
        assert_eq!(accepted["attempt_id"], attempt_id.to_string());

        let err = StoreOutcome::error("internal-error", "boom").into_batch_value(0);
        assert_eq!(err["ok"], false);
        assert_eq!(err["error"]["code"], "internal-error");
    }

    #[test]
    fn price_storage_rounds_up_like_the_quote() {
        // 1 byte at 1 femto-USD rounds up to 1 micro-USD.
        assert_eq!(price_storage(1, 1).unwrap(), 1);
        // Exact multiples do not over-round.
        assert_eq!(price_storage(1_000_000_000, 1).unwrap(), 1);
        assert_eq!(price_storage(2_000_000_000, 1).unwrap(), 2);
        // Zero price is zero charge.
        assert_eq!(price_storage(5_000, 0).unwrap(), 0);
    }

    #[test]
    fn attach_outcome_is_accepted_keyed_to_the_winner() {
        let attempt = Attempt {
            id: Uuid::now_v7(),
            account_id: Uuid::now_v7(),
            funding_source_id: Uuid::now_v7(),
            backend: "turbo".into(),
            sha256: [0u8; 32],
            bytes: 1,
            chargeable_bytes: 0,
            charged_usd_micros: 0,
            settled_charge_usd_micros: None,
            data_item_id: "id".into(),
            state: AttemptState::Reserved,
            release_reason: None,
        };
        match attach_outcome(&attempt) {
            StoreOutcome::Accepted { attempt_id } => assert_eq!(attempt_id, attempt.id),
            other => panic!("expected an accepted attach, got {other:?}"),
        }
    }
}
