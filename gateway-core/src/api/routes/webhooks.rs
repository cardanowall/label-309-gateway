//! The account-scoped webhook subscription routes (data plane).
//!
//! `POST/GET/PATCH/DELETE /api/v1/webhooks` let a third party that authenticates
//! AS an account manage its own delivery subscriptions. Every route is pinned to
//! the bearer's account, so one tenant can never see or mutate another's
//! subscription. The operator firehose is a separate control-plane surface.
//!
//! # Secret custody
//!
//! Create returns the signing secret exactly once. Thereafter only the secret
//! *fingerprint* appears in any response: the secret is encrypted at rest under the
//! webhook secret-wrap data key (the server must read it back to MAC each delivery,
//! so it is encrypted rather than one-way hashed), and no read path returns the
//! plaintext or ciphertext.
//!
//! # The mid-stream cutoff is implicit
//!
//! Create is a plain INSERT. A subscription receives exactly the events fanned out
//! after its row commits; there is no cutoff value to read or freeze, so the route
//! never touches the outbox.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::middleware::scope;
use crate::api::problem::Problem;
use crate::api::routes::guard;
use crate::api::state::{AppState, WebhookState};
use crate::api::wire::is_wire_event_name;
use crate::webhook::registration::{
    self, CreatedEndpoint, DeliveryView, EndpointChange, EndpointPatch, EndpointScope,
    EndpointStatus, EndpointView, NewEndpoint, RedriveOutcome, RotatedSecret,
};

use cardanowall::verifier::fetch::{assert_webhook_url_safe, WebhookUrlUnsafeError};

/// Resolve the webhook seam or return the feature-unavailable problem.
///
/// A deployment that has not enabled webhooks (no secret-wrap data key) leaves the
/// seam `None`; every webhook route then reports `webhooks-disabled` rather than
/// minting a secret it cannot seal.
#[allow(clippy::result_large_err)]
fn require_webhook(state: &AppState, trace: Uuid) -> std::result::Result<&WebhookState, Response> {
    state.webhook.as_ref().ok_or_else(|| {
        Problem::of(
            "webhooks-disabled",
            "webhook subscriptions are not enabled on this deployment",
        )
        .into_response_with(&state.config.problem_type_base, trace)
    })
}

/// `POST /api/v1/webhooks` — register an account-scoped subscription.
///
/// Requires `webhooks:write`. Validates the URL through the SSRF guard, validates
/// the event filter against the published wire vocabulary, mints + seals a signing
/// secret, and returns the secret exactly once (201). The created body carries the
/// row metadata plus the one-time `secret`.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let trace = guard::new_trace_id();
    let base = state.config.problem_type_base.clone();

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_WEBHOOKS_WRITE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let webhook = match require_webhook(&state, trace) {
        Ok(w) => w,
        Err(resp) => return finish(resp, &decision),
    };

    let parsed: CreateBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return finish(
                Problem::of(
                    "invalid-body",
                    format!("request body is not valid JSON: {e}"),
                )
                .into_response_with(&base, trace),
                &decision,
            )
        }
    };

    let enabled_events = match validate_events(&parsed.enabled_events, &base, trace) {
        Ok(v) => v,
        Err(resp) => return finish(resp, &decision),
    };

    // Validate the target URL through the SDK's SSRF guard (HTTPS-only by default,
    // resolve A+AAAA, reject any blocked range). DNS resolution is blocking, so it
    // runs on a blocking task.
    if let Err(resp) = validate_url(&parsed.url, webhook, &base, trace).await {
        return finish(resp, &decision);
    }

    let input = NewEndpoint {
        scope: EndpointScope::Account(viewer.account_id),
        url: parsed.url,
        enabled_events,
        label: parsed.label,
    };

    let created =
        match registration::create_endpoint(&state.pool, webhook.secret_wrap(), &input).await {
            Ok(c) => c,
            Err(_) => {
                return finish(
                    Problem::of("service-unavailable", "could not register the subscription")
                        .into_response_with(&base, trace),
                    &decision,
                )
            }
        };

    let body = create_response_body(&created);
    let response = (
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    )
        .into_response();
    finish(response, &decision)
}

/// `GET /api/v1/webhooks` — list the account's subscriptions.
///
/// Requires `webhooks:read`. Returns the metadata view of each subscription
/// (fingerprint only, never the secret), newest first.
pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let trace = guard::new_trace_id();
    let base = state.config.problem_type_base.clone();

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_WEBHOOKS_READ, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Err(resp) = require_webhook(&state, trace) {
        return finish(resp, &decision);
    }

    let views =
        match registration::list_endpoints(&state.pool, EndpointScope::Account(viewer.account_id))
            .await
        {
            Ok(v) => v,
            Err(_) => {
                return finish(
                    Problem::of("service-unavailable", "could not list subscriptions")
                        .into_response_with(&base, trace),
                    &decision,
                )
            }
        };

    let items: Vec<Value> = views.iter().map(view_to_json).collect();
    let body = json!({ "items": items });
    let response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    )
        .into_response();
    finish(response, &decision)
}

/// `GET /api/v1/webhooks/{id}` — read one subscription owned by the account.
///
/// Requires `webhooks:read`. A row owned by another account, soft-deleted, or
/// absent reports 404 identically, so a caller cannot probe for another tenant's
/// endpoints.
pub async fn get_one(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = state.config.problem_type_base.clone();

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_WEBHOOKS_READ, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Err(resp) = require_webhook(&state, trace) {
        return finish(resp, &decision);
    }
    let id = match parse_id(&id, &base, trace) {
        Ok(id) => id,
        Err(resp) => return finish(resp, &decision),
    };

    match registration::get_endpoint(&state.pool, EndpointScope::Account(viewer.account_id), id)
        .await
    {
        Ok(Some(view)) => {
            let body = view_to_json(&view);
            let response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
            )
                .into_response();
            finish(response, &decision)
        }
        Ok(None) => finish(not_found(&base, trace), &decision),
        Err(_) => finish(
            Problem::of("service-unavailable", "could not read the subscription")
                .into_response_with(&base, trace),
            &decision,
        ),
    }
}

/// `PATCH /api/v1/webhooks/{id}` — update a subscription owned by the account.
///
/// Requires `webhooks:write`. A data-plane caller may move `status` between
/// `active` and `paused` (re-activating resets the auto-disable counter), replace
/// the URL (re-validated through the SSRF guard) or event filter, and set/clear the
/// label. `disabled` is server-only and rejected here.
pub async fn patch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let trace = guard::new_trace_id();
    let base = state.config.problem_type_base.clone();

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_WEBHOOKS_WRITE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let webhook = match require_webhook(&state, trace) {
        Ok(w) => w,
        Err(resp) => return finish(resp, &decision),
    };
    let id = match parse_id(&id, &base, trace) {
        Ok(id) => id,
        Err(resp) => return finish(resp, &decision),
    };

    let parsed: PatchBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return finish(
                Problem::of(
                    "invalid-body",
                    format!("request body is not valid JSON: {e}"),
                )
                .into_response_with(&base, trace),
                &decision,
            )
        }
    };

    let patch = match build_patch(parsed, webhook, &base, trace).await {
        Ok(p) => p,
        Err(resp) => return finish(resp, &decision),
    };

    match registration::patch_endpoint(
        &state.pool,
        EndpointScope::Account(viewer.account_id),
        id,
        &patch,
    )
    .await
    {
        Ok(EndpointChange::Changed) => {
            // Re-read so the response reflects the persisted state, including the
            // counters the patch may have reset.
            match registration::get_endpoint(
                &state.pool,
                EndpointScope::Account(viewer.account_id),
                id,
            )
            .await
            {
                Ok(Some(view)) => {
                    let body = view_to_json(&view);
                    let response = (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/json")],
                        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
                    )
                        .into_response();
                    finish(response, &decision)
                }
                _ => finish(not_found(&base, trace), &decision),
            }
        }
        Ok(EndpointChange::NotFound) => finish(not_found(&base, trace), &decision),
        Err(_) => finish(
            Problem::of("service-unavailable", "could not update the subscription")
                .into_response_with(&base, trace),
            &decision,
        ),
    }
}

/// `DELETE /api/v1/webhooks/{id}` — soft-delete a subscription owned by the
/// account.
///
/// Requires `webhooks:write`. Returns 204 on a delete that took effect, 404 if no
/// such row exists for this account (including an already-deleted row).
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = state.config.problem_type_base.clone();

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_WEBHOOKS_WRITE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Err(resp) = require_webhook(&state, trace) {
        return finish(resp, &decision);
    }
    let id = match parse_id(&id, &base, trace) {
        Ok(id) => id,
        Err(resp) => return finish(resp, &decision),
    };

    match registration::soft_delete_endpoint(
        &state.pool,
        EndpointScope::Account(viewer.account_id),
        id,
    )
    .await
    {
        Ok(EndpointChange::Changed) => {
            let response = StatusCode::NO_CONTENT.into_response();
            finish(response, &decision)
        }
        Ok(EndpointChange::NotFound) => finish(not_found(&base, trace), &decision),
        Err(_) => finish(
            Problem::of("service-unavailable", "could not delete the subscription")
                .into_response_with(&base, trace),
            &decision,
        ),
    }
}

/// `GET /api/v1/webhooks/{id}/deliveries` — list a subscription's deliveries.
///
/// Requires `webhooks:read`. This is the dead-letter view: every delivery state
/// (`pending`, `delivered`, `failed`) is returned, newest first, so a subscriber
/// sees both what is in flight and what was dropped after exhausting attempts. The
/// endpoint is the single ownership gate — a foreign, soft-deleted, or absent
/// endpoint reports 404 identically, so a caller cannot reach another tenant's
/// deliveries.
pub async fn deliveries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = state.config.problem_type_base.clone();

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_WEBHOOKS_READ, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Err(resp) = require_webhook(&state, trace) {
        return finish(resp, &decision);
    }
    let id = match parse_id(&id, &base, trace) {
        Ok(id) => id,
        Err(resp) => return finish(resp, &decision),
    };
    let limit = i64::from(
        query
            .limit
            .unwrap_or(DEFAULT_DELIVERY_LIMIT)
            .clamp(1, MAX_DELIVERY_LIMIT),
    );

    match registration::list_deliveries(
        &state.pool,
        EndpointScope::Account(viewer.account_id),
        id,
        limit,
    )
    .await
    {
        Ok(Some(views)) => {
            let items: Vec<Value> = views.iter().map(delivery_to_json).collect();
            let body = json!({ "items": items });
            let response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
            )
                .into_response();
            finish(response, &decision)
        }
        Ok(None) => finish(not_found(&base, trace), &decision),
        Err(_) => finish(
            Problem::of("service-unavailable", "could not list deliveries")
                .into_response_with(&base, trace),
            &decision,
        ),
    }
}

/// `POST /api/v1/webhooks/{id}/deliveries/{delivery_id}/retry` — redrive a failed
/// delivery.
///
/// Requires `webhooks:write`. Re-arms a `failed` (dead-letter) delivery to
/// `pending` with an immediate `next_attempt_at`, leaving `attempts` so the prior
/// failures stand in the audit trail and the redelivery reuses the same `Webhook-Id`
/// and body. A delivery that is not under an owned endpoint is 404; one that exists
/// but is not `failed` (still pending or already delivered) is 409.
pub async fn retry_delivery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, delivery_id)): Path<(String, String)>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = state.config.problem_type_base.clone();

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_WEBHOOKS_WRITE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Err(resp) = require_webhook(&state, trace) {
        return finish(resp, &decision);
    }
    let id = match parse_id(&id, &base, trace) {
        Ok(id) => id,
        Err(resp) => return finish(resp, &decision),
    };
    let delivery_id = match parse_id(&delivery_id, &base, trace) {
        Ok(id) => id,
        Err(resp) => return finish(resp, &decision),
    };

    match registration::retry_delivery(
        &state.pool,
        EndpointScope::Account(viewer.account_id),
        id,
        delivery_id,
    )
    .await
    {
        Ok(RedriveOutcome::Redriven) => {
            let body = json!({ "id": delivery_id.to_string(), "state": "pending" });
            let response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
            )
                .into_response();
            finish(response, &decision)
        }
        Ok(RedriveOutcome::NotFound) => finish(not_found(&base, trace), &decision),
        Ok(RedriveOutcome::NotFailed) => finish(
            Problem::of(
                "validation-failed",
                "only a failed delivery can be redriven",
            )
            .into_response_with(&base, trace),
            &decision,
        ),
        Err(_) => finish(
            Problem::of("service-unavailable", "could not redrive the delivery")
                .into_response_with(&base, trace),
            &decision,
        ),
    }
}

/// `POST /api/v1/webhooks/{id}/rotate-secret` — open a secret rotation window.
///
/// Requires `webhooks:write`. Mints a successor signing secret, seals it at rest,
/// and returns the plaintext exactly once (like create). While the window is open
/// the delivery worker dual-signs (one MAC per active secret), so a receiver
/// validates with either; the subscriber commits once its fleet is cut over.
pub async fn rotate_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = state.config.problem_type_base.clone();

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_WEBHOOKS_WRITE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let webhook = match require_webhook(&state, trace) {
        Ok(w) => w,
        Err(resp) => return finish(resp, &decision),
    };
    let id = match parse_id(&id, &base, trace) {
        Ok(id) => id,
        Err(resp) => return finish(resp, &decision),
    };

    // The successor is sealed under the ROW's recorded wrap key, not the process-active
    // one, so the two ciphertexts on a row always share a key. A row recorded under a
    // wrap key this instance does not hold is a server-side custody condition (Err ->
    // 503), never a 404 that would tell the subscriber its live endpoint is absent.
    match registration::rotate_secret(
        &state.pool,
        webhook.secret_wrap(),
        EndpointScope::Account(viewer.account_id),
        id,
    )
    .await
    {
        Ok(Some(rotated)) => {
            let body = rotate_response_body(&rotated);
            let response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
            )
                .into_response();
            finish(response, &decision)
        }
        Ok(None) => finish(not_found(&base, trace), &decision),
        Err(_) => finish(
            Problem::of("service-unavailable", "could not rotate the secret")
                .into_response_with(&base, trace),
            &decision,
        ),
    }
}

/// `POST /api/v1/webhooks/{id}/rotate-secret/commit` — close a rotation window.
///
/// Requires `webhooks:write`. Promotes the successor secret to primary and clears
/// the successor, so the delivery worker drops back to a single `v1`. Explicit so a
/// multi-instance receiver is never cut over before its fleet is ready. A commit
/// with no open window is 404 (nothing to promote), so a redundant commit never
/// clears the only secret.
pub async fn commit_rotation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = state.config.problem_type_base.clone();

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_WEBHOOKS_WRITE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Err(resp) = require_webhook(&state, trace) {
        return finish(resp, &decision);
    }
    let id = match parse_id(&id, &base, trace) {
        Ok(id) => id,
        Err(resp) => return finish(resp, &decision),
    };

    match registration::commit_rotation(&state.pool, EndpointScope::Account(viewer.account_id), id)
        .await
    {
        Ok(EndpointChange::Changed) => {
            // Re-read so the response reflects the closed window (one fingerprint).
            match registration::get_endpoint(
                &state.pool,
                EndpointScope::Account(viewer.account_id),
                id,
            )
            .await
            {
                Ok(Some(view)) => {
                    let body = view_to_json(&view);
                    let response = (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/json")],
                        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
                    )
                        .into_response();
                    finish(response, &decision)
                }
                _ => finish(not_found(&base, trace), &decision),
            }
        }
        Ok(EndpointChange::NotFound) => finish(not_found(&base, trace), &decision),
        Err(_) => finish(
            Problem::of("service-unavailable", "could not commit the rotation")
                .into_response_with(&base, trace),
            &decision,
        ),
    }
}

// ---------------------------------------------------------------------------
// Request bodies.
// ---------------------------------------------------------------------------

/// The `POST /api/v1/webhooks` request body.
#[derive(Debug, Deserialize)]
struct CreateBody {
    /// The HTTPS delivery target.
    url: String,
    /// The wire event names to deliver; omitted/empty = all.
    #[serde(default)]
    enabled_events: Vec<String>,
    /// An optional human label.
    #[serde(default)]
    label: Option<String>,
}

/// The `PATCH /api/v1/webhooks/{id}` request body. Every field is optional; an
/// absent field is left untouched.
#[derive(Debug, Deserialize)]
struct PatchBody {
    /// New lifecycle status (`active` or `paused` only).
    #[serde(default)]
    status: Option<String>,
    /// Replace the event filter.
    #[serde(default)]
    enabled_events: Option<Vec<String>>,
    /// Replace the delivery URL.
    #[serde(default)]
    url: Option<String>,
    /// Set or clear the label. A JSON `null` clears it; an absent field leaves it.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    label: OptionalField<String>,
}

/// The default page size for the deliveries list.
const DEFAULT_DELIVERY_LIMIT: u32 = 50;

/// The maximum page size a caller may request for the deliveries list.
const MAX_DELIVERY_LIMIT: u32 = 200;

/// The query parameters of the deliveries list (page size only; the list is
/// newest-first).
#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
    /// The page size, clamped to `[1, MAX_DELIVERY_LIMIT]`.
    #[serde(default)]
    limit: Option<u32>,
}

/// A tri-state field for a PATCH: absent (leave untouched), present-null (clear),
/// or present-value (set).
#[derive(Debug, Default)]
enum OptionalField<T> {
    /// The field was absent from the body.
    #[default]
    Absent,
    /// The field was present and null (clear it).
    Null,
    /// The field was present with a value (set it).
    Value(T),
}

/// Deserialize a present field as `Null` or `Value`; a missing field stays
/// `Absent` via `#[serde(default)]` on the struct field, so this is only invoked
/// when the key is present.
fn deserialize_optional_field<'de, D, T>(
    deserializer: D,
) -> std::result::Result<OptionalField<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let opt = Option::<T>::deserialize(deserializer)?;
    Ok(match opt {
        Some(v) => OptionalField::Value(v),
        None => OptionalField::Null,
    })
}

// ---------------------------------------------------------------------------
// Validation + projection helpers.
// ---------------------------------------------------------------------------

/// Validate every requested event name against the published wire vocabulary,
/// returning the (possibly empty) filter on success.
#[allow(clippy::result_large_err)]
fn validate_events(
    requested: &[String],
    base: &str,
    trace: Uuid,
) -> std::result::Result<Vec<String>, Response> {
    for name in requested {
        if !is_wire_event_name(name) {
            return Err(Problem::of(
                "invalid-event-filter",
                format!("{name:?} is not a published wire event type"),
            )
            .into_response_with(base, trace));
        }
    }
    Ok(requested.to_vec())
}

/// Validate a delivery URL through the SDK's SSRF guard.
///
/// Runs the (blocking) DNS resolution on a blocking task. Maps every unsafe reason
/// onto the single `invalid-webhook-url` problem so a caller cannot use the
/// distinct reasons as a network-probe oracle.
///
/// The deployment's two knobs reach the guard through the single mapping in
/// `EgressConfig::assert_options`, shared with the delivery worker, and stay
/// independent axes there: `allow_insecure_http` permits `http://` targets only
/// (the loopback/private range-block stays enforced) and `egress_allow_loopback`
/// opens the range-block only (for a loopback test receiver). Both default off,
/// so a production registration is HTTPS-only and range-blocked.
#[allow(clippy::result_large_err)]
async fn validate_url(
    url: &str,
    webhook: &WebhookState,
    base: &str,
    trace: Uuid,
) -> std::result::Result<(), Response> {
    let url = url.to_string();
    let egress = webhook.egress_config();
    let result = tokio::task::spawn_blocking(move || {
        assert_webhook_url_safe(&url, &egress.assert_options()).map(|_| ())
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(unsafe_url)) => Err(url_problem(&unsafe_url, base, trace)),
        Err(_) => Err(Problem::of("service-unavailable", "URL validation failed")
            .into_response_with(base, trace)),
    }
}

/// Map an SSRF-guard rejection onto the `invalid-webhook-url` problem. The
/// human detail names the reason; the machine code stays one value so the distinct
/// reasons are not a probe oracle.
fn url_problem(err: &WebhookUrlUnsafeError, base: &str, trace: Uuid) -> Response {
    Problem::of(
        "invalid-webhook-url",
        format!("delivery URL rejected: {}", err.reason.as_str()),
    )
    .into_response_with(base, trace)
}

/// Build the registration patch from the request body, validating the status,
/// event filter, and URL.
#[allow(clippy::result_large_err)]
async fn build_patch(
    parsed: PatchBody,
    webhook: &WebhookState,
    base: &str,
    trace: Uuid,
) -> std::result::Result<EndpointPatch, Response> {
    let status = match parsed.status.as_deref() {
        None => None,
        Some("active") => Some(EndpointStatus::Active),
        Some("paused") => Some(EndpointStatus::Paused),
        // `disabled` is a server-only transition; a subscriber re-enables, it does
        // not self-disable through this route.
        Some(other) => {
            return Err(Problem::of(
                "validation-failed",
                format!("status must be \"active\" or \"paused\", got {other:?}"),
            )
            .into_response_with(base, trace))
        }
    };

    let enabled_events = match parsed.enabled_events {
        None => None,
        Some(list) => Some(validate_events(&list, base, trace)?),
    };

    if let Some(url) = &parsed.url {
        validate_url(url, webhook, base, trace).await?;
    }

    let label = match parsed.label {
        OptionalField::Absent => None,
        OptionalField::Null => Some(None),
        OptionalField::Value(v) => Some(Some(v)),
    };

    Ok(EndpointPatch {
        status,
        enabled_events,
        url: parsed.url,
        label,
    })
}

/// The metadata projection of a subscription a list/read/patch returns. Carries
/// the secret *fingerprint* (hex), never the secret.
fn view_to_json(view: &EndpointView) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("id".into(), json!(view.id.to_string()));
    obj.insert("url".into(), json!(view.url));
    obj.insert("enabled_events".into(), json!(view.enabled_events));
    obj.insert("status".into(), json!(view.status.as_str()));
    if let Some(reason) = &view.disabled_reason {
        obj.insert("disabled_reason".into(), json!(reason));
    }
    obj.insert("secret_fp".into(), json!(hex::encode(&view.secret_fp)));
    if let Some(next_fp) = &view.secret_next_fp {
        obj.insert("secret_next_fp".into(), json!(hex::encode(next_fp)));
    }
    obj.insert(
        "consecutive_failures".into(),
        json!(view.consecutive_failures),
    );
    // The dead-letter population surfaced inline so a subscriber sees a growing
    // failure count without a separate deliveries-list call.
    obj.insert("dead_deliveries".into(), json!(view.dead_deliveries));
    obj.insert(
        "last_success_at".into(),
        view.last_success_at
            .map(|t| json!(t.to_rfc3339()))
            .unwrap_or(Value::Null),
    );
    obj.insert(
        "label".into(),
        view.label.clone().map(Value::String).unwrap_or(Value::Null),
    );
    obj.insert("created_at".into(), json!(view.created_at.to_rfc3339()));
    obj.insert("updated_at".into(), json!(view.updated_at.to_rfc3339()));
    Value::Object(obj)
}

/// The projection of one delivery row the deliveries list returns. The frozen body
/// is deliberately omitted (large, and it is what the receiver already received).
fn delivery_to_json(view: &DeliveryView) -> Value {
    json!({
        "id": view.id.to_string(),
        // The Webhook-Id the receiver dedupes on; the subscriber correlates a
        // dead-letter back to a logged delivery by it.
        "webhook_id": view.dedupe_key,
        "subject_kind": view.subject_kind,
        "subject_id": view.subject_id,
        "subject_seq": view.subject_seq,
        "event_type": view.event_type,
        "state": view.state,
        "attempts": view.attempts,
        "max_attempts": view.max_attempts,
        "next_attempt_at": view.next_attempt_at.to_rfc3339(),
        "delivered_at": view.delivered_at.map(|t| t.to_rfc3339()),
        "last_status": view.last_status,
        "last_error": view.last_error,
        "created_at": view.created_at.to_rfc3339(),
    })
}

/// The rotate-secret response: the successor secret shown exactly once plus both
/// active fingerprints (the window is now open).
fn rotate_response_body(rotated: &RotatedSecret) -> Value {
    json!({
        "id": rotated.id.to_string(),
        "secret_fp": hex::encode(&rotated.secret_fp),
        "secret_next_fp": hex::encode(&rotated.secret_next_fp),
        // The successor signing secret, returned exactly once. It is never
        // retrievable again; only its fingerprint appears in later reads.
        "secret_next": rotated.secret_next,
    })
}

/// The create response body: the row metadata plus the one-time plaintext secret.
fn create_response_body(created: &CreatedEndpoint) -> Value {
    json!({
        "id": created.id.to_string(),
        "url": created.url,
        "enabled_events": created.enabled_events,
        "status": created.status.as_str(),
        "label": created.label,
        "created_at": created.created_at.to_rfc3339(),
        // The signing secret, returned exactly once. It is never retrievable
        // again; only its fingerprint appears in later reads.
        "secret": created.secret,
    })
}

/// Parse a `{id}` path segment to a UUID, mapping a malformed value to a 404 (the
/// same outcome as an unknown id, so a malformed probe is indistinguishable from a
/// miss).
#[allow(clippy::result_large_err)]
fn parse_id(raw: &str, base: &str, trace: Uuid) -> std::result::Result<Uuid, Response> {
    Uuid::parse_str(raw).map_err(|_| not_found(base, trace))
}

/// The shared 404 for an absent / cross-tenant / soft-deleted subscription.
fn not_found(base: &str, trace: Uuid) -> Response {
    Problem::of("not-found", "no such webhook subscription").into_response_with(base, trace)
}

/// Stamp the rate-limit headers onto a finished response.
fn finish(
    mut response: Response,
    decision: &crate::api::middleware::rate_limit::RateDecision,
) -> Response {
    guard::apply_rate_headers(&mut response, decision);
    response
}
