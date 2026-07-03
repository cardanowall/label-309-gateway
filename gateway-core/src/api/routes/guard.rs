//! Per-request guard helpers shared by the data-plane handlers.
//!
//! A handler that needs a Bearer credential calls [`authorize`], which resolves
//! the credential, checks the scope, and applies the rate limiter, returning the
//! [`Viewer`] on success or a ready-to-return RFC 7807 [`Response`] on any
//! failure (401, 403, 429). Keeping this in one place means every authed route
//! enforces the chain identically.

use axum::http::HeaderMap;
use axum::response::Response;
use chrono::Utc;
use uuid::Uuid;

use crate::api::control::principal::{AuthOutcome, Principal};
use crate::api::middleware::{auth, rate_limit, scope};
use crate::api::problem::Problem;
use crate::api::state::AppState;

pub use crate::api::middleware::auth::Viewer;

/// The per-minute request budget any account-bound credential minted without a
/// custom one meters against — an api key created with no `rate_limit_per_min`
/// or an account token whose mint did not pin a budget.
///
/// A mint may carry its own per-credential budget; absent one, the credential
/// falls back to this fixed budget, generous because both credential classes
/// are minted under operator control rather than handed out anonymously.
///
/// `pub(crate)` so the control plane's self-service grant check resolves the
/// same effective budget a credential without an explicit limit will meter
/// against, rather than pinning a second copy of the number.
pub(crate) const DEFAULT_RATE_LIMIT_PER_MIN: i32 = 600;

/// Map an account-bound principal onto the data-plane [`Viewer`], or reject an
/// operator principal presented to the data plane.
///
/// The data plane accepts an api key or an account-scoped token ONLY (the same
/// account-bound guard path; the account token is the dogfood bridge with no
/// backdoor). An operator token or root credential carries no account binding and
/// is rejected here, so operator authority can never act on the data plane.
fn data_plane_viewer(principal: Principal) -> std::result::Result<Viewer, ()> {
    match principal {
        Principal::ApiKey {
            key_id,
            account_id,
            scopes,
            rate_limit_per_min,
        } => Ok(Viewer {
            key_id,
            account_id,
            scopes,
            rate_limit_per_min,
        }),
        Principal::AccountToken {
            token_id,
            account_id,
            scopes,
            rate_limit_per_min,
            ..
        } => Ok(Viewer {
            // The token row id is the rate-limit subject and audit handle, the
            // same role the api-key id plays for a key.
            key_id: token_id,
            account_id,
            scopes,
            rate_limit_per_min,
        }),
        // An operator token or root credential has no place on the data plane.
        Principal::OperatorToken { .. } | Principal::OperatorRoot { .. } => Err(()),
    }
}

/// Resolve, scope-check, and rate-limit a Bearer credential.
///
/// `tokens` is the rate-limit cost (1 for a normal request, N for a batch). On
/// success returns the [`Viewer`] and the `RateLimit-*` header values the caller
/// stamps on its response; on failure returns a finished problem response.
pub async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
    tokens: i64,
    trace_id: Uuid,
) -> std::result::Result<(Viewer, rate_limit::RateDecision), Response> {
    let base = &state.config.problem_type_base;

    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(auth::bearer_token);

    let Some(token) = token else {
        return Err(
            Problem::of("unauthorized", "missing or malformed Bearer credential")
                .into_response_with(base, trace_id),
        );
    };

    let principal =
        match crate::api::control::principal::resolve_principal(&state.pool, token).await {
            Ok(AuthOutcome::Resolved(p)) => p,
            Ok(AuthOutcome::Unknown) => {
                // Format failure and unknown credential collapse to one outcome so a
                // scanner cannot distinguish them.
                return Err(Problem::of("unauthorized", "invalid Bearer credential")
                    .into_response_with(base, trace_id));
            }
            Err(_) => {
                return Err(
                    Problem::of("service-unavailable", "credential lookup failed")
                        .into_response_with(base, trace_id),
                );
            }
        };

    // The data plane accepts account-bound principals only; an operator token
    // presented here is rejected (the privilege-confusion guard).
    let viewer = match data_plane_viewer(principal) {
        Ok(v) => v,
        Err(()) => {
            // The documented 403 extension members: an operator credential grants
            // no data-plane scopes at all, so `granted` is honestly empty.
            return Err(Problem::of(
                "insufficient-scope",
                "operator credentials are not valid on the data plane",
            )
            .with_extension("required", serde_json::json!([required_scope]))
            .with_extension("granted", serde_json::json!([]))
            .into_response_with(base, trace_id));
        }
    };

    // An administratively disabled account may not exercise the data plane: gate
    // every authed route on the account's lifecycle status, the same column the
    // control plane's disable/enable transitions flip. Checking here (the single
    // account-bound chokepoint) blocks quotes, publishes, and reads uniformly,
    // rather than gating each route by hand. A disabled account that still holds a
    // live credential is rejected; re-enabling restores access with no credential
    // churn. A missing satellite (an impossible state for a resolved credential)
    // is treated as not-active and rejected, never silently allowed.
    match crate::ledger::account::account_status(&state.pool, viewer.account_id).await {
        Ok(Some(crate::ledger::account::AccountStatus::Active)) => {}
        Ok(_) => {
            return Err(Problem::of(
                "account-disabled",
                "this account is administratively disabled",
            )
            .into_response_with(base, trace_id));
        }
        Err(_) => {
            return Err(
                Problem::of("service-unavailable", "account status check failed")
                    .into_response_with(base, trace_id),
            );
        }
    }

    if !scope::authorizes(&viewer.scopes, required_scope) {
        // The documented 403 extension members: the scope the endpoint requires
        // and the scopes the credential actually carries, so the caller can see
        // exactly which grant is missing without a support round-trip.
        return Err(Problem::of(
            "insufficient-scope",
            format!("this endpoint requires the {required_scope} scope"),
        )
        .with_extension("required", serde_json::json!([required_scope]))
        .with_extension("granted", serde_json::json!(viewer.scopes))
        .into_response_with(base, trace_id));
    }

    let subject = viewer.key_id.to_string();
    // The single metering point resolves the effective budget: a credential
    // minted with a custom budget meters against it, any other against the
    // fixed default.
    let decision = match rate_limit::check_and_reserve(
        &state.pool,
        &subject,
        i64::from(
            viewer
                .rate_limit_per_min
                .unwrap_or(DEFAULT_RATE_LIMIT_PER_MIN),
        ),
        tokens,
        Utc::now(),
    )
    .await
    {
        Ok(d) => d,
        Err(_) => {
            return Err(
                Problem::of("service-unavailable", "rate-limit check failed")
                    .into_response_with(base, trace_id),
            );
        }
    };

    if !decision.allowed {
        return Err(
            Problem::of("rate-limited", "request budget exhausted for this window")
                .with_retry_after(decision.reset_seconds.max(0) as u64)
                .into_response_with(base, trace_id),
        );
    }

    Ok((viewer, decision))
}

/// The connecting client's peer address, for anonymous-read metering.
///
/// Reads the socket address the connect-info layer stamped on the request (the
/// binary serves with `into_make_service_with_connect_info`), NEVER a
/// client-supplied header: `X-Forwarded-For` is forgeable by any caller, so it
/// is trusted only if a future config knob designates a trusted proxy. Absent
/// connect-info (an embedder's router, a test driving the service directly)
/// yields `None`, which the anonymous limiter meters against one shared budget
/// rather than leaving unmetered.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(pub Option<std::net::IpAddr>);

impl<S> axum::extract::FromRequestParts<S> for ClientAddr
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|connect| connect.0.ip()),
        ))
    }
}

/// Rate-limit an anonymous request against its client address's budget.
///
/// The anonymous counterpart to [`authorize`] for the public records reads: no
/// credential resolves, so the meter keys on the hashed peer address (see
/// [`rate_limit::anonymous_subject`]) against the operator-configured
/// `anon_rate_limit_per_min`. Returns the decision for the caller's headers, or
/// a finished 429/503 problem response. A request that CARRIES a Bearer never
/// takes this path — a present credential must resolve via [`authorize`] or be
/// rejected, never silently downgraded to anonymous.
pub async fn limit_anonymous(
    state: &AppState,
    client_ip: Option<std::net::IpAddr>,
    tokens: i64,
    trace_id: Uuid,
) -> std::result::Result<rate_limit::RateDecision, Response> {
    let base = &state.config.problem_type_base;
    let subject = rate_limit::anonymous_subject(client_ip);
    let decision = match rate_limit::check_and_reserve(
        &state.pool,
        &subject,
        state.config.anon_rate_limit_per_min,
        tokens,
        Utc::now(),
    )
    .await
    {
        Ok(d) => d,
        Err(_) => {
            return Err(
                Problem::of("service-unavailable", "rate-limit check failed")
                    .into_response_with(base, trace_id),
            );
        }
    };

    if !decision.allowed {
        return Err(Problem::of(
            "rate-limited",
            "anonymous request budget exhausted for this client address",
        )
        .with_retry_after(decision.reset_seconds.max(0) as u64)
        .into_response_with(base, trace_id));
    }

    Ok(decision)
}

/// Stamp the IETF `RateLimit-*` headers onto a response from a limiter decision.
pub fn apply_rate_headers(response: &mut Response, decision: &rate_limit::RateDecision) {
    use axum::http::HeaderValue;
    let h = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&decision.limit.to_string()) {
        h.insert("ratelimit-limit", v);
    }
    if let Ok(v) = HeaderValue::from_str(&decision.remaining.to_string()) {
        h.insert("ratelimit-remaining", v);
    }
    if let Ok(v) = HeaderValue::from_str(&decision.reset_seconds.to_string()) {
        h.insert("ratelimit-reset", v);
    }
}

/// A fresh trace id for a request, echoed in problem bodies and `X-Request-Id`.
#[must_use]
pub fn new_trace_id() -> Uuid {
    Uuid::now_v7()
}
