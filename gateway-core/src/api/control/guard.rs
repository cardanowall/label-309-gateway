//! Per-request authorization for the control surface.
//!
//! Two guards enforce the control plane's principal subsets:
//!
//!   - [`authorize_operator`] accepts an operator token or the operator root
//!     credential ONLY. An account-bound principal (an api key or account token)
//!     presented to an operator route is rejected.
//!   - [`authorize_account_scope`] resolves the principal allowed to act on a
//!     named account: an account token acting on its OWN account, or an operator
//!     principal acting on any account under it. An account token aimed at a
//!     different account is rejected.
//!   - [`enforce_grantable`] gates the two self-service routes that issue a NEW
//!     credential (account-token mint, api-key create): an account-bound caller
//!     may not hand its own newly minted credential more scopes or a larger rate
//!     budget than it holds itself, so a narrow token cannot escalate into a
//!     broad one for the same account. An operator caller is unconstrained.
//!
//! Both guards return the resolved [`Principal`] on success or a ready-to-return
//! RFC 7807 [`Response`] on any failure, so every control route enforces the
//! chain identically.

use axum::http::HeaderMap;
use axum::response::Response;
use uuid::Uuid;

use crate::api::control::principal::{resolve_principal, AuthOutcome, Principal};
use crate::api::control::state::ControlState;
use crate::api::middleware::auth::bearer_token;
use crate::api::problem::Problem;
use crate::api::routes::guard::DEFAULT_RATE_LIMIT_PER_MIN;

/// A fresh trace id for a control request, echoed in problem bodies and
/// `X-Request-Id`.
#[must_use]
pub fn new_trace_id() -> Uuid {
    Uuid::now_v7()
}

/// Resolve the Bearer principal for a control request, or a ready problem
/// response (401 missing/invalid, 503 on a lookup failure).
async fn resolve(
    state: &ControlState,
    headers: &HeaderMap,
    trace_id: Uuid,
) -> std::result::Result<Principal, Response> {
    let base = &state.config.problem_type_base;

    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token);

    let Some(token) = token else {
        return Err(
            Problem::of("unauthorized", "missing or malformed Bearer credential")
                .into_response_with(base, trace_id),
        );
    };

    match resolve_principal(&state.pool, token).await {
        Ok(AuthOutcome::Resolved(p)) => Ok(p),
        Ok(AuthOutcome::Unknown) => Err(Problem::of("unauthorized", "invalid Bearer credential")
            .into_response_with(base, trace_id)),
        Err(_) => Err(
            Problem::of("service-unavailable", "credential lookup failed")
                .into_response_with(base, trace_id),
        ),
    }
}

/// Authorize an operator-only control route.
///
/// Accepts an operator token or the operator root credential; rejects any
/// account-bound principal with a 403. Returns the resolved operator principal.
pub async fn authorize_operator(
    state: &ControlState,
    headers: &HeaderMap,
    trace_id: Uuid,
) -> std::result::Result<Principal, Response> {
    let principal = resolve(state, headers, trace_id).await?;
    if principal.is_operator() {
        Ok(principal)
    } else {
        Err(Problem::of(
            "insufficient-scope",
            "this endpoint requires operator authority",
        )
        .into_response_with(&state.config.problem_type_base, trace_id))
    }
}

/// Authorize an account-scoped control route acting on `account_id`.
///
/// Accepts an operator principal (acting on any account under it) or an account
/// token bound to exactly `account_id` (self-service). An account token aimed at a
/// different account is rejected with a 403. Returns the resolved principal so the
/// route can record the correct actor on its audit row.
pub async fn authorize_account_scope(
    state: &ControlState,
    headers: &HeaderMap,
    trace_id: Uuid,
    account_id: Uuid,
) -> std::result::Result<Principal, Response> {
    let principal = resolve(state, headers, trace_id).await?;
    let permitted = principal.is_operator() || principal.account_id() == Some(account_id);
    if permitted {
        Ok(principal)
    } else {
        Err(Problem::of(
            "insufficient-scope",
            "this credential may not act on the requested account",
        )
        .into_response_with(&state.config.problem_type_base, trace_id))
    }
}

/// Gate a self-service credential-issuing route so an account-bound caller
/// cannot mint a credential more privileged than itself.
///
/// The two routes that issue a new data-plane credential — account-token mint
/// and api-key create — accept an account principal acting on its own account
/// (via [`authorize_account_scope`]). Without this check a token carrying only
/// `account:read` could mint itself a `poe:create` key and spend the account's
/// balance, making the scope set decorative rather than a real boundary. So when
/// the caller is account-bound, every requested scope must be one the caller
/// already holds, and the requested per-minute budget must not exceed the
/// caller's own effective budget (the explicit limit it carries, or the
/// data-plane default when it carries none). An operator caller holds full
/// authority over its accounts and is unconstrained.
///
/// Returns `Ok(())` when the grant is permissible, or a ready-to-return 403
/// naming the offending scopes / budget otherwise.
#[allow(clippy::result_large_err)]
pub fn enforce_grantable(
    state: &ControlState,
    trace_id: Uuid,
    principal: &Principal,
    requested_scopes: &[String],
    requested_rate_limit: Option<i32>,
) -> std::result::Result<(), Response> {
    let (granted_scopes, caller_rate_limit) = match principal {
        // An operator acts with full authority over the account; nothing to cap.
        Principal::OperatorToken { .. } | Principal::OperatorRoot { .. } => return Ok(()),
        Principal::AccountToken {
            scopes,
            rate_limit_per_min,
            ..
        }
        | Principal::ApiKey {
            scopes,
            rate_limit_per_min,
            ..
        } => (scopes, *rate_limit_per_min),
    };

    let mut escalated: Vec<&String> = requested_scopes
        .iter()
        .filter(|s| !granted_scopes.contains(s))
        .collect();
    escalated.sort();
    escalated.dedup();
    if !escalated.is_empty() {
        let escalated_list = escalated
            .iter()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let held = if granted_scopes.is_empty() {
            "none".to_string()
        } else {
            granted_scopes.join(", ")
        };
        return Err(Problem::of(
            "insufficient-scope",
            format!(
                "a self-service credential may not be granted scopes the issuing \
                 credential does not hold; it does not hold: {escalated_list} \
                 (it holds: {held})"
            ),
        )
        .into_response_with(&state.config.problem_type_base, trace_id));
    }

    // The effective budget a credential without an explicit limit meters
    // against is the data-plane default; comparing effective-to-effective stops
    // a default-budget caller from pinning a higher explicit limit on its issue.
    let caller_effective = caller_rate_limit.unwrap_or(DEFAULT_RATE_LIMIT_PER_MIN);
    let requested_effective = requested_rate_limit.unwrap_or(DEFAULT_RATE_LIMIT_PER_MIN);
    if requested_effective > caller_effective {
        return Err(Problem::of(
            "insufficient-scope",
            format!(
                "a self-service credential may not be granted a larger per-minute \
                 budget ({requested_effective}) than the issuing credential holds \
                 ({caller_effective})"
            ),
        )
        .into_response_with(&state.config.problem_type_base, trace_id));
    }

    Ok(())
}

/// Authorize an instance-administrator route: it requires the operator ROOT
/// credential specifically. These are the routes that exercise instance-level
/// authority an ordinary operator token must not hold: minting operator tokens,
/// and binding a shared-keyring signing key (wallet or storage funding source) to
/// an owning operator. Custody of a shared instance secret is assigned by the
/// root, not captured first-come by any operator that shares access to it.
pub async fn authorize_root(
    state: &ControlState,
    headers: &HeaderMap,
    trace_id: Uuid,
) -> std::result::Result<Principal, Response> {
    let principal = resolve(state, headers, trace_id).await?;
    match principal {
        Principal::OperatorRoot { .. } => Ok(principal),
        _ => Err(Problem::of(
            "insufficient-scope",
            "this endpoint requires the operator root credential",
        )
        .into_response_with(&state.config.problem_type_base, trace_id)),
    }
}
