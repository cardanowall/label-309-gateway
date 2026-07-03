//! The control-plane route handlers and the router factory.
//!
//! [`build`] assembles every control-plane route over a [`ControlState`] into one
//! axum [`Router`], with each resource path written ONCE as a bare suffix (e.g.
//! `/accounts`, `/wallets`). The version segment is applied in exactly one place —
//! [`crate::api::control::router`] nests this router under `/control/v1` — so the
//! served surface is `/control/v1/*` while the route declarations stay
//! version-free. The control surface is operator-only (token / account
//! provisioning, wallet registration, balance adjustment, the audit read); a small
//! account-level subset (own keys, own token) accepts an account token acting on
//! itself. Every mutation appends an [`audit`] row carrying the actor, the
//! before/after state, and the request id. The money and credential mutations
//! commit that row in the SAME transaction as the mutation, so the two land or
//! roll back together; the multi-step / provider-I/O paths, which cannot share
//! one transaction, append it after their own commit through
//! `record_audit_best_effort`, where a failure is logged, never dropped.
//!
//! The handlers project engine state onto JSON list/object envelopes and surface
//! errors as the same RFC 7807 problems the data plane uses.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::control::audit::{self, ActorKind, AuditEntry, AuditQuery};
use crate::api::control::credential::{
    mint_account_token, mint_operator_token, revoke_access_token, revoke_credential,
    rotate_root_credential, AccountTokenMint, CredentialRevocation, RootRotation,
};
use crate::api::control::guard::{
    authorize_account_scope, authorize_operator, authorize_root, enforce_grantable, new_trace_id,
};
use crate::api::control::keys::KeyError;
use crate::api::control::ledger_adjust::{
    apply_adjustment, clamp_debit, AdjustmentOutcome, ClampedDebitResult,
};
use crate::api::control::principal::Principal;
use crate::api::control::queries;
use crate::api::control::state::{
    ControlState, ControlStorage, DefaultStorageScope, DefaultWalletScope,
};
use crate::api::control::{keys, ControlConfig};
use crate::api::problem::Problem;
use crate::api::state::WebhookState;
use crate::api::wire::is_wire_event_name;
use crate::ledger::account::{
    account_belongs_to_operator, create_account, disable_account, enable_account, ScopedChange,
    ScopedTransition,
};
use crate::ledger::journal::InsertOutcome;
use crate::pricing::margin_override::{
    clear_margin_override, set_margin_override, MarginOverrideOutcome,
};
use crate::storage::{
    authorize_owner_topup, begin_draining_source, execute_topup,
    issue_grant as issue_storage_grant, list_operator_topups, list_sources, register_source,
    register_topup, revoke_grant as revoke_storage_grant, ArweaveNodeClient,
    IssueOutcome as StorageIssueOutcome, RegisterSourceOutcome,
    RevokeOutcome as StorageRevokeOutcome, SourceSummary, StorageGrantScope, TopUpRecord,
    TurboPaymentClient, TurboWincProvider, WincBalanceProvider,
};
use crate::wallet::config::Network;
use crate::wallet::grant::{issue_grant, revoke_grant, GrantScope, IssueOutcome, RevokeOutcome};
use crate::wallet::operator::{
    address_network_id, begin_draining, reactivate, register_wallet_and_grant,
    RegisterAndGrantOutcome,
};
use crate::wallet::utxo::{KoiosUtxoSource, UtxoSource};
use crate::webhook::registration::{
    self, CreatedEndpoint, DeliveryView, EndpointChange, EndpointPatch, EndpointScope,
    EndpointStatus, EndpointView, NewEndpoint, RedriveOutcome, RotatedSecret,
};

use cardanowall::verifier::fetch::{assert_webhook_url_safe, WebhookUrlUnsafeError};

/// The set of route templates the control router serves, as `(method, path)`
/// pairs, written as BARE suffixes (no version prefix — the router nests them
/// under `/control/v1`). The in-code inventory the control route-coverage test
/// cross-checks against the served control OpenAPI document (whose paths are
/// likewise bare, with the version carried by `servers`), in both directions.
pub const SERVED_CONTROL_ROUTES: &[(&str, &str)] = &[
    ("get", "/openapi.json"),
    ("get", "/docs"),
    ("get", "/docs/scalar.js"),
    ("post", "/operator/token"),
    ("post", "/operator/root/rotate"),
    ("get", "/credentials"),
    ("post", "/credentials/{credential_id}/revoke"),
    ("get", "/tokens"),
    ("post", "/tokens/{token_id}/revoke"),
    ("post", "/accounts"),
    ("get", "/accounts"),
    ("post", "/accounts/{account_id}/disable"),
    ("post", "/accounts/{account_id}/enable"),
    ("get", "/accounts/{account_id}/usage"),
    ("post", "/accounts/{account_id}/ledger-adjustment"),
    ("post", "/accounts/{account_id}/ledger-clamp-debit"),
    ("put", "/accounts/{account_id}/margin"),
    ("delete", "/accounts/{account_id}/margin"),
    ("post", "/accounts/{account_id}/token"),
    ("post", "/accounts/{account_id}/keys"),
    ("get", "/accounts/{account_id}/keys"),
    ("post", "/accounts/{account_id}/keys/{key_id}/revoke"),
    ("post", "/accounts/{account_id}/keys/{key_id}/relabel"),
    ("post", "/wallets"),
    ("get", "/wallets"),
    ("get", "/wallets/operator-balance"),
    ("post", "/wallets/{wallet_id}/drain"),
    ("post", "/wallets/{wallet_id}/reactivate"),
    ("post", "/wallets/{wallet_id}/grants"),
    ("post", "/wallets/{wallet_id}/grants/{grant_id}/revoke"),
    ("post", "/storage/sources"),
    ("get", "/storage/sources"),
    ("post", "/storage/sources/{source_id}/drain"),
    ("post", "/storage/sources/{source_id}/grants"),
    (
        "post",
        "/storage/sources/{source_id}/grants/{grant_id}/revoke",
    ),
    ("get", "/storage/funding"),
    ("get", "/storage/operator-balance"),
    ("post", "/storage/top-up"),
    ("get", "/storage/top-ups"),
    ("post", "/storage/top-ups/{topup_id}/register"),
    ("get", "/chain/provider-usage"),
    ("get", "/pricing/fx"),
    ("get", "/webhooks/health"),
    ("post", "/webhooks"),
    ("get", "/webhooks"),
    ("get", "/webhooks/{id}"),
    ("patch", "/webhooks/{id}"),
    ("delete", "/webhooks/{id}"),
    ("post", "/webhooks/{id}/rotate-secret"),
    ("post", "/webhooks/{id}/rotate-secret/commit"),
    ("get", "/webhooks/{id}/deliveries"),
    ("post", "/webhooks/{id}/deliveries/{delivery_id}/retry"),
    ("get", "/audit"),
];

/// The default page size for a control list endpoint.
const DEFAULT_LIST_LIMIT: i64 = 100;

/// The maximum page size a caller may request.
const MAX_LIST_LIMIT: i64 = 500;

/// Bounded concurrency for the wallet-balance route's live Koios reads: high
/// enough to keep the realistic small signing pool fast, low enough not to burst
/// the public Koios tier into rate-limiting.
const WALLET_BALANCE_READ_CONCURRENCY: usize = 8;

/// Overall wall-clock budget for the wallet-balance route's live reads. Bounds the
/// worst case — a full roster (`MAX_LIST_LIMIT` wallets) during a Koios outage,
/// each read able to stall up to the client timeout — so the admin refresh returns
/// promptly with the unread wallets marked rather than hanging for minutes.
const WALLET_BALANCE_READ_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// Build the control-plane router over a resolved [`ControlState`].
///
/// Every route is declared with a bare suffix; the version segment is applied by
/// the caller ([`crate::api::control::router`]) via a single
/// `nest("/control/v1", …)`.
pub fn build(state: ControlState) -> Router {
    Router::new()
        .route("/openapi.json", get(control_openapi))
        .route("/docs", get(control_docs))
        .route("/docs/scalar.js", get(control_docs_scalar_js))
        .route("/operator/token", post(operator_token))
        .route("/operator/root/rotate", post(rotate_root_route))
        .route("/credentials", get(list_credentials_route))
        .route(
            "/credentials/{credential_id}/revoke",
            post(revoke_credential_route),
        )
        .route("/tokens", get(list_tokens_route))
        .route("/tokens/{token_id}/revoke", post(revoke_token_route))
        .route(
            "/accounts",
            post(create_account_route).get(list_accounts_route),
        )
        .route(
            "/accounts/{account_id}/disable",
            post(disable_account_route),
        )
        .route("/accounts/{account_id}/enable", post(enable_account_route))
        .route("/accounts/{account_id}/usage", get(account_usage_route))
        .route(
            "/accounts/{account_id}/ledger-adjustment",
            post(ledger_adjustment_route),
        )
        .route(
            "/accounts/{account_id}/ledger-clamp-debit",
            post(ledger_clamp_debit_route),
        )
        .route(
            "/accounts/{account_id}/margin",
            put(set_margin_route).delete(clear_margin_route),
        )
        .route("/accounts/{account_id}/token", post(account_token_route))
        .route(
            "/accounts/{account_id}/keys",
            post(create_key_route).get(list_keys_route),
        )
        .route(
            "/accounts/{account_id}/keys/{key_id}/revoke",
            post(revoke_key_route),
        )
        .route(
            "/accounts/{account_id}/keys/{key_id}/relabel",
            post(relabel_key_route),
        )
        .route(
            "/wallets",
            post(register_wallet_route).get(list_wallets_route),
        )
        .route(
            "/wallets/operator-balance",
            get(wallet_operator_balance_route),
        )
        .route("/wallets/{wallet_id}/drain", post(drain_wallet_route))
        .route(
            "/wallets/{wallet_id}/reactivate",
            post(reactivate_wallet_route),
        )
        .route("/wallets/{wallet_id}/grants", post(issue_grant_route))
        .route(
            "/wallets/{wallet_id}/grants/{grant_id}/revoke",
            post(revoke_grant_route),
        )
        .route(
            "/storage/sources",
            post(register_source_route).get(list_sources_route),
        )
        .route(
            "/storage/sources/{source_id}/drain",
            post(drain_source_route),
        )
        .route(
            "/storage/sources/{source_id}/grants",
            post(issue_source_grant_route),
        )
        .route(
            "/storage/sources/{source_id}/grants/{grant_id}/revoke",
            post(revoke_source_grant_route),
        )
        .route("/storage/funding", get(storage_funding_route))
        .route(
            "/storage/operator-balance",
            get(storage_operator_balance_route),
        )
        .route("/storage/top-up", post(storage_topup_route))
        .route("/storage/top-ups", get(list_storage_topups_route))
        .route(
            "/storage/top-ups/{topup_id}/register",
            post(register_storage_topup_route),
        )
        .route("/chain/provider-usage", get(chain_provider_usage_route))
        .route("/pricing/fx", get(pricing_fx_route))
        .route("/webhooks/health", get(webhook_health_route))
        .route(
            "/webhooks",
            post(create_webhook_route).get(list_webhooks_route),
        )
        .route(
            "/webhooks/{id}",
            get(get_webhook_route)
                .patch(patch_webhook_route)
                .delete(delete_webhook_route),
        )
        .route(
            "/webhooks/{id}/rotate-secret",
            post(rotate_webhook_secret_route),
        )
        .route(
            "/webhooks/{id}/rotate-secret/commit",
            post(commit_webhook_rotation_route),
        )
        .route("/webhooks/{id}/deliveries", get(webhook_deliveries_route))
        .route(
            "/webhooks/{id}/deliveries/{delivery_id}/retry",
            post(retry_webhook_delivery_route),
        )
        .route("/audit", get(list_audit_route))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

/// Render a JSON object response with a status and the trace id echoed in
/// `X-Request-Id`.
fn json_response(status: StatusCode, trace_id: Uuid, body: Value) -> Response {
    let mut response = (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    )
        .into_response();
    if let Ok(v) = header::HeaderValue::from_str(&trace_id.to_string()) {
        response.headers_mut().insert("x-request-id", v);
    }
    response
}

/// A list envelope with a `data` array and its element count.
fn list_envelope(status: StatusCode, trace_id: Uuid, data: Vec<Value>) -> Response {
    json_response(
        status,
        trace_id,
        json!({ "object": "list", "data": data, "count": data.len() }),
    )
}

/// Clamp a caller-requested page size into the allowed range.
fn clamp_limit(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT)
}

/// Map an engine [`crate::Error`] onto a control problem response. A config /
/// validation error surfaces as a 422; anything else as a 500.
fn engine_error(config: &ControlConfig, trace_id: Uuid, err: &crate::Error) -> Response {
    let base = &config.problem_type_base;
    match err {
        crate::Error::Config(detail) => {
            Problem::of("validation-failed", detail.clone()).into_response_with(base, trace_id)
        }
        // Every other engine error collapses to an opaque 500 on the wire (the
        // detail must not leak to the caller), but it MUST be logged with its real
        // cause and the trace id so the 500 is diagnosable. Without this, a route
        // that fails on, say, a missing queue policy (UnknownQueue) surfaces as a
        // bare 500 with nothing to grep, which is what made the register-route
        // failure opaque in the first place.
        _ => {
            tracing::error!(%trace_id, error = %err, "control route engine error mapped to 500");
            Problem::of("internal-error", "an unexpected error occurred")
                .into_response_with(base, trace_id)
        }
    }
}

/// Parse a UUID path segment, or a 404 (the resource cannot exist).
///
/// Returns the ready-to-return problem response in the `Err` arm, matching the
/// guard idiom used across both planes (a guard returns either the resolved value
/// or a finished response). The error type is an axum `Response`, which is large;
/// that is the deliberate, uniform shape of every per-request guard here, so the
/// large-error lint is allowed for this helper.
#[allow(clippy::result_large_err)]
fn parse_id(
    config: &ControlConfig,
    trace_id: Uuid,
    raw: &str,
) -> std::result::Result<Uuid, Response> {
    Uuid::parse_str(raw).map_err(|_| {
        Problem::of("not-found", "no such resource")
            .into_response_with(&config.problem_type_base, trace_id)
    })
}

/// The 404 a control route returns for a resource the caller's operator does not
/// own.
///
/// Tenancy isolation deliberately collapses "the resource does not exist" and
/// "the resource exists but belongs to another operator" into ONE response: a
/// 404. A 403 would leak existence (a probe could distinguish a real id under
/// another tenant from a random one), so a cross-tenant access is shaped exactly
/// like a missing one. Applied uniformly to every account / wallet / key the
/// control plane addresses by a path id.
fn not_found(config: &ControlConfig, trace_id: Uuid) -> Response {
    Problem::of("not-found", "no such resource")
        .into_response_with(&config.problem_type_base, trace_id)
}

/// Append an audit row for a mutation that has already committed on its own —
/// a multi-step or provider-I/O path that cannot share one transaction (a
/// storage top-up broadcasts between journal writes; webhook rotation spans
/// user interaction). The mutation is real either way, so the request must not
/// fail retroactively; but a missing audit row must never be invisible, so the
/// failure is logged at error level instead of being dropped. Money and
/// credential mutations do NOT come through here: their routes commit the
/// mutation and the audit row in one transaction.
async fn record_audit_best_effort(pool: &sqlx::PgPool, entry: &AuditEntry) {
    if let Err(e) = audit::record(pool, entry).await {
        tracing::error!(
            action = %entry.action,
            target_type = %entry.target_type,
            target_id = %entry.target_id,
            error = %e,
            "audit row append failed after a committed mutation"
        );
    }
}

/// The operator a control principal acts under.
///
/// Every account / wallet / audit helper is tenancy-scoped by this id. Both an
/// operator principal and an account token carry one (a token is minted under the
/// operator that owns its account); only a bare data-plane api key does not, and
/// such a principal never reaches a control route (the guards reject it first).
/// This is the single place the route threads its operator binding into the
/// engine, so an unscoped engine call is not expressible.
#[allow(clippy::result_large_err)]
fn operator_binding(
    config: &ControlConfig,
    trace_id: Uuid,
    principal: &Principal,
) -> std::result::Result<Uuid, Response> {
    principal.operator_id().ok_or_else(|| {
        // A principal with no operator binding cannot act on the control plane;
        // the guards already reject it, so this is defensive only.
        Problem::of(
            "insufficient-scope",
            "this credential carries no operator authority",
        )
        .into_response_with(&config.problem_type_base, trace_id)
    })
}

// ---------------------------------------------------------------------------
// Meta.
// ---------------------------------------------------------------------------

/// `GET /control/v1/openapi.json` — the frozen control-plane OpenAPI 3.1
/// document.
///
/// Served verbatim from the embedded asset; public like the data-plane document
/// (no auth gate), so an integrator can read the contract before holding any
/// credential. The control route-coverage test asserts the served routes match
/// this document in both directions.
async fn control_openapi() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        crate::api::control::OPENAPI_CONTROL_JSON,
    )
        .into_response()
}

/// `GET /control/v1/docs` — the interactive reference UI for the control plane.
///
/// The same vendored, offline renderer the data plane serves, pointed at this
/// plane's sibling `openapi.json`. Public — the SAME posture as `openapi.json`
/// above (the contract it renders is already public, and the page is static HTML
/// that embeds no secret); an operator still needs a token to CALL any endpoint.
async fn control_docs() -> Response {
    crate::api::docs::reference_page("Control plane API reference")
}

/// `GET /control/v1/docs/scalar.js` — the vendored renderer bundle the control-plane
/// docs page loads, served from the binary so the page never reaches a public CDN.
async fn control_docs_scalar_js() -> Response {
    crate::api::docs::scalar_js()
}

// ---------------------------------------------------------------------------
// Token minting.
// ---------------------------------------------------------------------------

/// `POST /control/v1/operator/token` — mint a short-lived operator token.
///
/// Authenticated by the operator ROOT credential (only the root may mint operator
/// tokens). The token carries no account binding and authorizes the operator
/// control surface for the configured TTL.
async fn operator_token(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_root(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let Principal::OperatorRoot {
        operator_id,
        credential_id,
    } = principal
    else {
        // authorize_root guarantees this variant; defensive only.
        return Problem::of("internal-error", "unexpected principal")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let minted = match mint_operator_token(
        &mut *txn,
        operator_id,
        &state.config.secret_prefix,
        state.config.operator_token_ttl,
        credential_id,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    if let Err(e) = audit::record(
        &mut *txn,
        &AuditEntry {
            actor_kind: ActorKind::Operator,
            actor_id: Some(operator_id),
            action: "operator_token.mint".into(),
            target_type: "access_token".into(),
            target_id: minted.minted.id.to_string(),
            prev_state: None,
            new_state: Some(json!({ "kind": "operator", "expires_at": minted.expires_at })),
            request_id: Some(trace_id),
        },
    )
    .await
    {
        return engine_error(&state.config, trace_id, &e);
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }

    json_response(
        StatusCode::CREATED,
        trace_id,
        json!({
            "token": minted.minted.secret,
            "token_id": minted.minted.id,
            "expires_at": minted.expires_at,
        }),
    )
}

/// `POST /control/v1/accounts/{account_id}/token` — mint an account-scoped token.
///
/// The dogfood bridge: an operator (or the account itself) mints a short-lived
/// token that authenticates the data plane AS the account, carrying the requested
/// data-plane scopes.
#[derive(Deserialize)]
struct AccountTokenBody {
    /// The data-plane scopes the minted token carries.
    #[serde(default)]
    scopes: Vec<String>,
    /// An OPTIONAL per-minute request budget the data-plane limiter meters this
    /// token against. Omitted, the token meters against the data-plane default
    /// budget (the same fallback an api key minted without one uses).
    #[serde(default)]
    rate_limit_per_min: Option<i32>,
}

async fn account_token_route(
    State(state): State<ControlState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<AccountTokenBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let principal = match authorize_account_scope(&state, &headers, trace_id, account_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let (scopes, rate_limit_per_min) = body
        .map(|b| (b.0.scopes, b.0.rate_limit_per_min))
        .unwrap_or_default();

    // A self-service caller may not mint a token broader than itself.
    if let Err(resp) = enforce_grantable(&state, trace_id, &principal, &scopes, rate_limit_per_min)
    {
        return resp;
    }

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let minted = match mint_account_token(
        &mut *txn,
        operator_id,
        account_id,
        &scopes,
        rate_limit_per_min,
        &state.config.secret_prefix,
        state.config.account_token_ttl,
        // The mint lineage: the row id of the credential that authenticated this
        // call (an operator token, the root, or the account's own token / key
        // acting self-service), NOT the actor's operator/account id. Revoking
        // that exact credential is what invalidates this token at resolve time.
        principal.credential_row_id(),
    )
    .await
    {
        Ok(AccountTokenMint::Minted(m)) => m,
        Ok(AccountTokenMint::AccountNotFound) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    if let Err(e) = audit::record(
        &mut *txn,
        &AuditEntry {
            actor_kind: ActorKind::from_principal(&principal),
            actor_id: principal.actor_id(),
            action: "account_token.mint".into(),
            target_type: "access_token".into(),
            target_id: minted.minted.id.to_string(),
            prev_state: None,
            new_state: Some(json!({
                "account_id": account_id,
                "scopes": scopes,
                "rate_limit_per_min": rate_limit_per_min,
                "expires_at": minted.expires_at,
            })),
            request_id: Some(trace_id),
        },
    )
    .await
    {
        return engine_error(&state.config, trace_id, &e);
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }

    json_response(
        StatusCode::CREATED,
        trace_id,
        json!({
            "token": minted.minted.secret,
            "token_id": minted.minted.id,
            "account_id": account_id,
            "scopes": scopes,
            "rate_limit_per_min": rate_limit_per_min,
            "expires_at": minted.expires_at,
        }),
    )
}

// ---------------------------------------------------------------------------
// Credential lifecycle: rotation and revocation.
// ---------------------------------------------------------------------------

/// `POST /control/v1/operator/root/rotate` — rotate the presented root
/// credential.
///
/// Root-gated: the rotation replaces the exact credential that authenticated
/// the call. One transaction revokes the presented root and mints its
/// successor, so the operator is never rootless and a concurrently revoked root
/// cannot mint a replacement. Revocation cascades through the mint lineage at
/// resolve time: the moment this returns, every operator token minted from the
/// old root — and every account token minted beneath those — stops
/// authenticating. Data-plane api keys are untouched. The successor's plaintext
/// secret is returned exactly once, like bootstrap's.
#[derive(Deserialize)]
struct RotateRootBody {
    /// An optional label for the successor. Omitted, the old root's label
    /// carries over.
    #[serde(default)]
    label: Option<String>,
}

async fn rotate_root_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Option<Json<RotateRootBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_root(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let Principal::OperatorRoot {
        operator_id,
        credential_id,
    } = principal
    else {
        // authorize_root guarantees this variant; defensive only.
        return Problem::of("internal-error", "unexpected principal")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };
    let label = body.and_then(|b| b.0.label);

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let rotated = match rotate_root_credential(
        &mut *txn,
        operator_id,
        credential_id,
        &state.config.secret_prefix,
        label.as_deref(),
    )
    .await
    {
        Ok(RootRotation::Rotated(r)) => r,
        Ok(RootRotation::PresentedRootRevoked) => {
            // The presented root lost its liveness between the guard and the
            // rotation transaction (a concurrent revocation). Nothing was
            // minted; the caller no longer holds a live credential.
            return Problem::of(
                "unauthorized",
                "the presented root credential is no longer live",
            )
            .into_response_with(&state.config.problem_type_base, trace_id);
        }
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    if let Err(e) = audit::record(
        &mut *txn,
        &AuditEntry {
            actor_kind: ActorKind::Operator,
            actor_id: Some(operator_id),
            action: "root_credential.rotate".into(),
            target_type: "control_credential".into(),
            target_id: rotated.minted.id.to_string(),
            prev_state: Some(json!({
                "revoked_credential_id": rotated.revoked_credential_id,
            })),
            new_state: Some(json!({
                "credential_id": rotated.minted.id,
                "label_set": label.is_some(),
            })),
            request_id: Some(trace_id),
        },
    )
    .await
    {
        return engine_error(&state.config, trace_id, &e);
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }

    json_response(
        StatusCode::CREATED,
        trace_id,
        json!({
            "credential_id": rotated.minted.id,
            "secret": rotated.minted.secret,
            "revoked_credential_id": rotated.revoked_credential_id,
            "operator_id": operator_id,
        }),
    )
}

/// `GET /control/v1/credentials` — the operator's control-credential roster.
///
/// Ids and lifecycle only (a stored secret is unrecoverable by design): the
/// enumeration an operator needs to pick a rotation / revocation target.
/// Revoked credentials stay listed, so the roster doubles as rotation history.
async fn list_credentials_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let limit = clamp_limit(params.limit);

    let credentials = match queries::list_credentials(&state.pool, operator_id, limit).await {
        Ok(c) => c,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let data = credentials
        .into_iter()
        .map(|c| {
            json!({
                "credential_id": c.credential_id,
                "kind": c.kind,
                "label": c.label,
                "created_at": c.created_at,
                "revoked_at": c.revoked_at,
            })
        })
        .collect();
    list_envelope(StatusCode::OK, trace_id, data)
}

/// `POST /control/v1/credentials/{credential_id}/revoke` — revoke a control
/// credential.
///
/// Root-gated: a control credential is instance-level authority, so only the
/// root retires one. Revocation cascades at resolve time to every token minted
/// under the credential. The operator's LAST live root is refused (409
/// `last-live-root`): revoking it would leave the tenant recoverable only by
/// database surgery, and rotation covers that incident (it revokes just as
/// immediately while minting the successor). Idempotent; a cross-tenant id is
/// an oracle-safe 404.
async fn revoke_credential_route(
    State(state): State<ControlState>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_root(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let credential_id = match parse_id(&state.config, trace_id, &credential_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let revoked = match revoke_credential(&mut *txn, operator_id, credential_id).await {
        Ok(CredentialRevocation::NotFound) => return not_found(&state.config, trace_id),
        Ok(CredentialRevocation::LastLiveRoot) => {
            return Problem::of(
                "last-live-root",
                "this is the operator's only live root credential; rotate it instead \
                 (POST /operator/root/rotate), or provision an additional root first",
            )
            .into_response_with(&state.config.problem_type_base, trace_id);
        }
        Ok(CredentialRevocation::Revoked) => true,
        Ok(CredentialRevocation::AlreadyRevoked) => false,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    if revoked {
        if let Err(e) = audit::record(
            &mut *txn,
            &AuditEntry {
                actor_kind: ActorKind::Operator,
                actor_id: Some(operator_id),
                action: "credential.revoke".into(),
                target_type: "control_credential".into(),
                target_id: credential_id.to_string(),
                prev_state: Some(json!({ "revoked_at": Value::Null })),
                new_state: Some(json!({ "revoked": true })),
                request_id: Some(trace_id),
            },
        )
        .await
        {
            return engine_error(&state.config, trace_id, &e);
        }
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "credential_id": credential_id, "revoked": revoked }),
    )
}

/// `GET /control/v1/tokens` — the operator's access-token roster.
///
/// Ids and lifecycle only (a token secret is unrecoverable by design): the
/// enumeration an operator needs to pick a targeted revocation. Expired and
/// revoked tokens stay listed within the page as recent history.
async fn list_tokens_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let limit = clamp_limit(params.limit);

    let tokens = match queries::list_access_tokens(&state.pool, operator_id, limit).await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let data = tokens
        .into_iter()
        .map(|t| {
            json!({
                "token_id": t.token_id,
                "account_id": t.account_id,
                "scopes": t.scopes,
                "minted_by": t.minted_by,
                "expires_at": t.expires_at,
                "created_at": t.created_at,
                "revoked_at": t.revoked_at,
            })
        })
        .collect();
    list_envelope(StatusCode::OK, trace_id, data)
}

/// `POST /control/v1/tokens/{token_id}/revoke` — revoke one access token.
///
/// The targeted kill switch for a single leaked token, without a full rotation.
/// Operator-gated rather than root-gated: an operator token can already MINT
/// tokens, and revocation is strictly destructive (it cannot escalate), so
/// requiring the cold-stored root for a routine token kill would only push
/// operators toward keeping the root warm. Revoking a token also invalidates
/// any token minted UNDER it (the mint lineage), so killing a leaked operator
/// token takes down the account tokens an attacker minted with it. Idempotent;
/// a cross-tenant id is an oracle-safe 404.
async fn revoke_token_route(
    State(state): State<ControlState>,
    Path(token_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let token_id = match parse_id(&state.config, trace_id, &token_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let change = match revoke_access_token(&mut *txn, operator_id, token_id).await {
        Ok(c) => c,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let revoked = match change {
        ScopedChange::NotFound => return not_found(&state.config, trace_id),
        ScopedChange::Changed => true,
        ScopedChange::Unchanged => false,
    };
    if revoked {
        if let Err(e) = audit::record(
            &mut *txn,
            &AuditEntry {
                actor_kind: ActorKind::Operator,
                actor_id: Some(operator_id),
                action: "access_token.revoke".into(),
                target_type: "access_token".into(),
                target_id: token_id.to_string(),
                prev_state: Some(json!({ "revoked_at": Value::Null })),
                new_state: Some(json!({ "revoked": true })),
                request_id: Some(trace_id),
            },
        )
        .await
        {
            return engine_error(&state.config, trace_id, &e);
        }
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "token_id": token_id, "revoked": revoked }),
    )
}

// ---------------------------------------------------------------------------
// Accounts.
// ---------------------------------------------------------------------------

/// `POST /control/v1/accounts` — create an account under the operator.
async fn create_account_route(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator principal carries an operator id");

    let account_id = match create_account(&state.pool, operator_id).await {
        Ok(id) => id,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    record_audit_best_effort(
        &state.pool,
        &AuditEntry {
            actor_kind: ActorKind::Operator,
            actor_id: Some(operator_id),
            action: "account.create".into(),
            target_type: "account".into(),
            target_id: account_id.to_string(),
            prev_state: None,
            new_state: Some(json!({ "operator_id": operator_id, "status": "active" })),
            request_id: Some(trace_id),
        },
    )
    .await;

    json_response(
        StatusCode::CREATED,
        trace_id,
        json!({ "account_id": account_id, "status": "active" }),
    )
}

/// Query parameters shared by the list endpoints.
#[derive(Deserialize)]
struct ListParams {
    limit: Option<i64>,
}

/// `GET /control/v1/accounts` — list the operator's accounts.
async fn list_accounts_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator principal carries an operator id");
    let limit = clamp_limit(params.limit);

    let accounts = match queries::list_accounts(&state.pool, operator_id, limit).await {
        Ok(a) => a,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let data = accounts
        .into_iter()
        .map(|a| {
            json!({
                "account_id": a.account_id,
                "operator_id": a.operator_id,
                "status": a.status,
                "balance_usd_micros": a.balance_micros,
                "created_at": a.created_at,
            })
        })
        .collect();
    list_envelope(StatusCode::OK, trace_id, data)
}

/// A body carrying an operator's free-text reason for a mutation.
#[derive(Deserialize)]
struct ReasonBody {
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /control/v1/accounts/{account_id}/disable` — administratively disable.
async fn disable_account_route(
    State(state): State<ControlState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ReasonBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let reason = body.and_then(|b| b.0.reason);

    let change = match disable_account(&state.pool, operator_id, account_id).await {
        Ok(c) => c,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let (changed, status) = match change {
        ScopedTransition::NotFound => return not_found(&state.config, trace_id),
        ScopedTransition::Changed { from, to } => {
            record_audit_best_effort(
                &state.pool,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: principal.actor_id(),
                    action: "account.disable".into(),
                    target_type: "account".into(),
                    target_id: account_id.to_string(),
                    prev_state: Some(json!({ "status": from.as_str() })),
                    new_state: Some(json!({ "status": to.as_str(), "reason": reason })),
                    request_id: Some(trace_id),
                },
            )
            .await;
            (true, to)
        }
        ScopedTransition::Unchanged { status } => (false, status),
    };
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "account_id": account_id, "status": status.as_str(), "changed": changed }),
    )
}

/// `POST /control/v1/accounts/{account_id}/enable` — re-enable a disabled account.
async fn enable_account_route(
    State(state): State<ControlState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ReasonBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let reason = body.and_then(|b| b.0.reason);

    let change = match enable_account(&state.pool, operator_id, account_id).await {
        Ok(c) => c,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let (changed, status) = match change {
        ScopedTransition::NotFound => return not_found(&state.config, trace_id),
        ScopedTransition::Changed { from, to } => {
            record_audit_best_effort(
                &state.pool,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: principal.actor_id(),
                    action: "account.enable".into(),
                    target_type: "account".into(),
                    target_id: account_id.to_string(),
                    prev_state: Some(json!({ "status": from.as_str() })),
                    new_state: Some(json!({ "status": to.as_str(), "reason": reason })),
                    request_id: Some(trace_id),
                },
            )
            .await;
            (true, to)
        }
        ScopedTransition::Unchanged { status } => (false, status),
    };
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "account_id": account_id, "status": status.as_str(), "changed": changed }),
    )
}

/// `GET /control/v1/accounts/{account_id}/usage` — the account's usage counters.
async fn account_usage_route(
    State(state): State<ControlState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let principal = match authorize_account_scope(&state, &headers, trace_id, account_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let usage = match queries::account_usage(&state.pool, operator_id, account_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    json_response(
        StatusCode::OK,
        trace_id,
        json!({
            "account_id": account_id,
            "status": usage.status,
            "balance_usd_micros": usage.balance_micros,
            "ledger_entry_count": usage.ledger_entry_count,
            "quote_count": usage.quote_count,
            "publish_count": usage.publish_count,
        }),
    )
}

/// `POST /control/v1/accounts/{account_id}/ledger-adjustment` — adjust a balance.
///
/// An optional `ref` pins the entry's `(kind, ref)` idempotency key to the
/// originating event (a Stripe payment intent, a welcome grant keyed by account
/// id, ...), so a redelivered call collapses to a no-op rather than a second
/// balance move. Omitted, the engine mints a fresh per-call ref.
#[derive(Deserialize)]
struct AdjustmentBody {
    amount_usd_micros: i64,
    reason: String,
    #[serde(default)]
    r#ref: Option<String>,
}

async fn ledger_adjustment_route(
    State(state): State<ControlState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<AdjustmentBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let Some(Json(body)) = body else {
        return Problem::of("invalid-body", "an adjustment body is required")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };

    // The mutation and its audit row commit in ONE transaction: `cw_core.
    // admin_audit`'s invariant is exactly one row per landed mutation, and a
    // separately committed audit append could silently fail after the balance
    // already moved. An early-return arm below just returns — dropping the
    // transaction rolls back whatever the refused mutation touched.
    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let outcome = match apply_adjustment(
        &mut *txn,
        operator_id,
        account_id,
        body.amount_usd_micros,
        &body.reason,
        state.config.adjustment_cap_usd_micros,
        body.r#ref.as_deref(),
        Some(trace_id),
    )
    .await
    {
        Ok(AdjustmentOutcome::Applied(o)) => o,
        Ok(AdjustmentOutcome::AccountNotFound) => return not_found(&state.config, trace_id),
        Ok(AdjustmentOutcome::AccountNotActive) => {
            // The credit was refused atomically because the account is not active
            // (no ledger row written). A distinct, machine-readable code so a
            // caller can tell this apart from a 404 (account absent) or a 422
            // (malformed request) and act on it (retry until re-enabled, or stop).
            return Problem::of(
                "account-not-active",
                "the account is not active; a credit cannot be applied to it",
            )
            .into_response_with(&state.config.problem_type_base, trace_id);
        }
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    // Only a mutation that actually landed is journalled: an idempotent replay
    // must not double-write an audit row.
    if outcome == InsertOutcome::Inserted {
        if let Err(e) = audit::record(
            &mut *txn,
            &AuditEntry {
                actor_kind: ActorKind::Operator,
                actor_id: principal.actor_id(),
                action: "ledger.adjust".into(),
                target_type: "ledger".into(),
                target_id: account_id.to_string(),
                prev_state: None,
                new_state: Some(json!({
                    "amount_usd_micros": body.amount_usd_micros,
                    "reason": body.reason,
                })),
                request_id: Some(trace_id),
            },
        )
        .await
        {
            return engine_error(&state.config, trace_id, &e);
        }
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }

    json_response(
        StatusCode::OK,
        trace_id,
        json!({
            "account_id": account_id,
            "amount_usd_micros": body.amount_usd_micros,
            "applied": outcome == InsertOutcome::Inserted,
        }),
    )
}

/// `POST /control/v1/accounts/{account_id}/ledger-clamp-debit` — debit a balance
/// toward zero by up to an amount, clamped at the available balance.
///
/// The clawback primitive: it removes only what the balance can cover and
/// returns `debited_usd_micros` (the amount actually taken), so the caller
/// carries `amount − debited` as its own arrears without a stamp-time balance
/// split that goes stale before the debit lands. `ref` is required (the
/// originating clawback id); a redelivery returns the same debited amount with
/// `applied = false`.
#[derive(Deserialize)]
struct ClampDebitBody {
    amount_usd_micros: i64,
    reason: String,
    r#ref: String,
}

async fn ledger_clamp_debit_route(
    State(state): State<ControlState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ClampDebitBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let Some(Json(body)) = body else {
        return Problem::of("invalid-body", "a clamp-debit body is required")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let outcome = match clamp_debit(
        &mut *txn,
        operator_id,
        account_id,
        body.amount_usd_micros,
        &body.reason,
        state.config.adjustment_cap_usd_micros,
        &body.r#ref,
        Some(trace_id),
    )
    .await
    {
        Ok(ClampedDebitResult::Applied(o)) => o,
        Ok(ClampedDebitResult::AccountNotFound) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    if outcome.newly_applied {
        if let Err(e) = audit::record(
            &mut *txn,
            &AuditEntry {
                actor_kind: ActorKind::Operator,
                actor_id: principal.actor_id(),
                action: "ledger.clamp_debit".into(),
                target_type: "ledger".into(),
                target_id: account_id.to_string(),
                prev_state: None,
                new_state: Some(json!({
                    "requested_usd_micros": body.amount_usd_micros,
                    "debited_usd_micros": outcome.debited_micros,
                    "reason": body.reason,
                })),
                request_id: Some(trace_id),
            },
        )
        .await
        {
            return engine_error(&state.config, trace_id, &e);
        }
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }

    json_response(
        StatusCode::OK,
        trace_id,
        json!({
            "account_id": account_id,
            "debited_usd_micros": outcome.debited_micros,
            "applied": outcome.newly_applied,
        }),
    )
}

/// `PUT /control/v1/accounts/{account_id}/margin` — set the account's markup
/// override.
///
/// The base plane keeps pricing policy minimal: it knows only an
/// operator-default margin and, optionally, this single per-account override. A
/// control plane that runs its own policy (tiers, delegation, loyalty) computes
/// an effective fraction and PUSHES it here; the engine never models the policy.
/// `margin_pct` is a non-negative fraction (e.g. `0.25` = 25%). The upsert is
/// idempotent. A target the operator does not own is an oracle-safe 404.
#[derive(Deserialize)]
struct MarginBody {
    margin_pct: rust_decimal::Decimal,
}

async fn set_margin_route(
    State(state): State<ControlState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<MarginBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let Some(Json(body)) = body else {
        return Problem::of("invalid-body", "a margin body is required")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };

    let outcome =
        match set_margin_override(&state.pool, operator_id, account_id, body.margin_pct).await {
            Ok(o) => o,
            Err(e) => return engine_error(&state.config, trace_id, &e),
        };
    match outcome {
        MarginOverrideOutcome::AccountNotFound => return not_found(&state.config, trace_id),
        MarginOverrideOutcome::Set => {
            record_audit_best_effort(
                &state.pool,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: principal.actor_id(),
                    action: "account.margin.set".into(),
                    target_type: "account".into(),
                    target_id: account_id.to_string(),
                    prev_state: None,
                    new_state: Some(json!({ "margin_pct": body.margin_pct.to_string() })),
                    request_id: Some(trace_id),
                },
            )
            .await;
        }
        // set_margin_override never reports Cleared / NotPresent.
        MarginOverrideOutcome::Cleared | MarginOverrideOutcome::NotPresent => {}
    }

    json_response(
        StatusCode::OK,
        trace_id,
        json!({
            "account_id": account_id,
            "margin_pct": rust_decimal::prelude::ToPrimitive::to_f64(&body.margin_pct),
            "margin_source": "account-override",
        }),
    )
}

/// `DELETE /control/v1/accounts/{account_id}/margin` — clear the account's
/// markup override, reverting it to the operator-default margin.
///
/// Idempotent: a clear with no override present succeeds with `cleared: false`. A
/// target the operator does not own is an oracle-safe 404.
async fn clear_margin_route(
    State(state): State<ControlState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let outcome = match clear_margin_override(&state.pool, operator_id, account_id).await {
        Ok(o) => o,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let cleared = match outcome {
        MarginOverrideOutcome::AccountNotFound => return not_found(&state.config, trace_id),
        MarginOverrideOutcome::Cleared => true,
        MarginOverrideOutcome::NotPresent => false,
        // clear_margin_override never reports Set.
        MarginOverrideOutcome::Set => true,
    };
    if cleared {
        record_audit_best_effort(
            &state.pool,
            &AuditEntry {
                actor_kind: ActorKind::Operator,
                actor_id: principal.actor_id(),
                action: "account.margin.clear".into(),
                target_type: "account".into(),
                target_id: account_id.to_string(),
                prev_state: None,
                new_state: Some(json!({ "cleared": true })),
                request_id: Some(trace_id),
            },
        )
        .await;
    }

    json_response(
        StatusCode::OK,
        trace_id,
        json!({
            "account_id": account_id,
            "cleared": cleared,
            "margin_source": "operator-default",
        }),
    )
}

// ---------------------------------------------------------------------------
// Api keys.
// ---------------------------------------------------------------------------

/// `POST /control/v1/accounts/{account_id}/keys` — create an api key.
#[derive(Deserialize)]
struct CreateKeyBody {
    /// The data-plane scopes the key carries. Must be non-empty and registered
    /// in the scope registry.
    scopes: Vec<String>,
    /// An OPTIONAL per-minute request budget the data-plane limiter meters this
    /// key against. Omitted, the key meters against the data-plane default
    /// budget (the same fallback an account token minted without one uses).
    #[serde(default)]
    rate_limit_per_min: Option<i32>,
    /// An optional human label for the key.
    #[serde(default)]
    label: Option<String>,
}

async fn create_key_route(
    State(state): State<ControlState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<CreateKeyBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let principal = match authorize_account_scope(&state, &headers, trace_id, account_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let Some(Json(body)) = body else {
        return Problem::of("invalid-body", "a key body is required")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };

    // A self-service caller may not issue a key broader than itself.
    if let Err(resp) = enforce_grantable(
        &state,
        trace_id,
        &principal,
        &body.scopes,
        body.rate_limit_per_min,
    ) {
        return resp;
    }

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let created = match keys::create_key(
        &mut *txn,
        operator_id,
        account_id,
        &state.config.secret_prefix,
        &body.scopes,
        body.rate_limit_per_min,
        body.label.as_deref(),
    )
    .await
    {
        Ok(c) => c,
        Err(KeyError::AccountNotFound) => return not_found(&state.config, trace_id),
        Err(KeyError::Engine(e)) => return engine_error(&state.config, trace_id, &e),
    };

    if let Err(e) = audit::record(
        &mut *txn,
        &AuditEntry {
            actor_kind: ActorKind::from_principal(&principal),
            actor_id: principal.actor_id(),
            action: "key.create".into(),
            target_type: "api_key".into(),
            target_id: created.key_id.to_string(),
            prev_state: None,
            new_state: Some(json!({
                "account_id": account_id,
                "prefix": created.prefix,
                "scopes": created.scopes,
                "rate_limit_per_min": created.rate_limit_per_min,
                "label_set": body.label.is_some(),
            })),
            request_id: Some(trace_id),
        },
    )
    .await
    {
        return engine_error(&state.config, trace_id, &e);
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }

    json_response(
        StatusCode::CREATED,
        trace_id,
        json!({
            "key_id": created.key_id,
            "secret": created.secret,
            "prefix": created.prefix,
            "scopes": created.scopes,
            "rate_limit_per_min": created.rate_limit_per_min,
            "created_at": created.created_at,
        }),
    )
}

/// `GET /control/v1/accounts/{account_id}/keys` — list an account's keys.
async fn list_keys_route(
    State(state): State<ControlState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let trace_id = new_trace_id();
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let principal = match authorize_account_scope(&state, &headers, trace_id, account_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let limit = clamp_limit(params.limit);
    let keys = match queries::list_account_keys(&state.pool, operator_id, account_id, limit).await {
        Ok(Some(k)) => k,
        Ok(None) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let data = keys
        .into_iter()
        .map(|k| {
            json!({
                "key_id": k.key_id,
                "prefix": k.prefix,
                "scopes": k.scopes,
                "rate_limit_per_min": k.rate_limit_per_min,
                "label": k.label,
                "created_at": k.created_at,
                "last_used_at": k.last_used_at,
                "revoked_at": k.revoked_at,
            })
        })
        .collect();
    list_envelope(StatusCode::OK, trace_id, data)
}

/// `POST .../keys/{key_id}/revoke` — revoke an account's key.
async fn revoke_key_route(
    State(state): State<ControlState>,
    Path((account_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let key_id = match parse_id(&state.config, trace_id, &key_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let principal = match authorize_account_scope(&state, &headers, trace_id, account_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let change = match keys::revoke_key(&mut *txn, operator_id, account_id, key_id).await {
        Ok(c) => c,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let changed = match change {
        ScopedChange::NotFound => return not_found(&state.config, trace_id),
        ScopedChange::Changed => true,
        ScopedChange::Unchanged => false,
    };
    if changed {
        if let Err(e) = audit::record(
            &mut *txn,
            &AuditEntry {
                actor_kind: ActorKind::from_principal(&principal),
                actor_id: principal.actor_id(),
                action: "key.revoke".into(),
                target_type: "api_key".into(),
                target_id: key_id.to_string(),
                prev_state: Some(json!({ "revoked_at": Value::Null })),
                new_state: Some(json!({ "revoked": true })),
                request_id: Some(trace_id),
            },
        )
        .await
        {
            return engine_error(&state.config, trace_id, &e);
        }
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "key_id": key_id, "revoked": changed }),
    )
}

/// `POST .../keys/{key_id}/relabel` — rename an account's key.
#[derive(Deserialize)]
struct RelabelBody {
    #[serde(default)]
    label: Option<String>,
}

async fn relabel_key_route(
    State(state): State<ControlState>,
    Path((account_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Option<Json<RelabelBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let account_id = match parse_id(&state.config, trace_id, &account_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let key_id = match parse_id(&state.config, trace_id, &key_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let principal = match authorize_account_scope(&state, &headers, trace_id, account_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let label = body.and_then(|b| b.0.label);

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let change =
        match keys::relabel_key(&mut *txn, operator_id, account_id, key_id, label.as_deref()).await
        {
            Ok(c) => c,
            Err(e) => return engine_error(&state.config, trace_id, &e),
        };
    let relabeled = match change {
        ScopedChange::NotFound => return not_found(&state.config, trace_id),
        // A relabel is not gated on a value change: an owned key always matches.
        ScopedChange::Changed | ScopedChange::Unchanged => true,
    };
    if let Err(e) = audit::record(
        &mut *txn,
        &AuditEntry {
            actor_kind: ActorKind::from_principal(&principal),
            actor_id: principal.actor_id(),
            action: "key.relabel".into(),
            target_type: "api_key".into(),
            target_id: key_id.to_string(),
            prev_state: None,
            new_state: Some(json!({ "label_set": label.is_some() })),
            request_id: Some(trace_id),
        },
    )
    .await
    {
        return engine_error(&state.config, trace_id, &e);
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "key_id": key_id, "relabeled": relabeled }),
    )
}

// ---------------------------------------------------------------------------
// Wallets.
// ---------------------------------------------------------------------------

/// `POST /control/v1/wallets` — register a wallet from a keyring entry.
///
/// Requires the operator ROOT credential. Registration binds a keyring Cardano
/// signing key to an owning operator, and the keyring is shared across every
/// operator on the instance; an ordinary operator token must not be able to claim
/// a key it merely shares custody of, which would let a second tenant register
/// another tenant's wallet address and spend its funds. Key custody is an
/// instance-level responsibility, so the root decides which operator owns a key.
/// Grants on an already-owned wallet stay operator-manageable (the owner-only
/// grant routes).
///
/// `address` must be a verified Cardano payment address the instance physically
/// holds a signer for (the keyring derived it from the signing key at unlock): a
/// row is never written for an address no signer can back, so a wallet the submit
/// path can never sign is unrepresentable. Registering an unsignable wallet would
/// auto-grant it, let externally-funded UTxOs be ingested for it, and let the
/// scheduler pick it, only for every submit to then fail at signing.
///
/// `scope` is the spend scope the registration grants. Omitted, it defaults to
/// the instance's `default_wallet_scope`. `service` makes the wallet usable by
/// every operator/account; `operator` pins it to the registrar only; `account`
/// pins it to a named account the registrar owns (requires `scope_account_id`).
#[derive(Deserialize)]
struct RegisterWalletBody {
    label: String,
    address: String,
    network: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scope_account_id: Option<String>,
}

async fn register_wallet_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Option<Json<RegisterWalletBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_root(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator root principal carries an operator id");
    let Some(Json(body)) = body else {
        return Problem::of("invalid-body", "a wallet body is required")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };
    let network = match Network::parse(&body.network) {
        Ok(n) => n,
        Err(_) => {
            return Problem::of(
                "validation-failed",
                "network must be mainnet, preprod, or preview",
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
    };

    // Validate the address is a Cardano payment address on the requested network
    // BEFORE creating any row: a malformed address, or one whose network-id does
    // not match `network`, is a 422 rather than a row the signer can never back.
    // The two test networks share a network id, so this catches a mainnet/testnet
    // mix-up; the deployment's own network distinguishes preprod from preview.
    match address_network_id(&body.address) {
        Some(id) if id == network.network_id() => {}
        Some(_) => {
            return Problem::of(
                "validation-failed",
                "the address network does not match the requested network",
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
        None => {
            return Problem::of(
                "validation-failed",
                "address is not a valid Cardano payment address",
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
    }

    // Confirm the instance physically holds a verified signer for this address
    // BEFORE writing a row. The keyring already derived the address from the signing
    // key at unlock, so a match here proves the key -> address binding without
    // re-deriving it; an address no signer backs is refused so the submit path can
    // never resolve an unsignable wallet. Without this gate a registered-but-
    // unsignable wallet is auto-granted, has externally-funded UTxOs ingested for
    // it, and is pickable by the scheduler, only for every submit to fail at
    // signing.
    if !state.wallet_keys.iter().any(|k| k.address == body.address) {
        return Problem::of(
            "validation-failed",
            "no verified Cardano signing key for this address is held by this instance",
        )
        .into_response_with(&state.config.problem_type_base, trace_id);
    }

    // Resolve the spend scope the registration grants: the body's `scope` when
    // present, else the instance default. An `account` scope must name an account
    // the registrar owns (a cross-operator account grant is forbidden).
    let scope = match resolve_register_scope(
        &state,
        operator_id,
        body.scope.as_deref(),
        body.scope_account_id.as_deref(),
        trace_id,
    )
    .await
    {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };

    // Register the wallet, auto-grant the resolved scope, and enqueue a targeted
    // replenish in ONE transaction so the wallet row, its spend grant, and the
    // grooming that makes it spendable all commit together. Without the in-transaction
    // enqueue a freshly registered wallet would have no canonical UTxOs until the
    // periodic replenish cron next ticks; the targeted enqueue grooms exactly this
    // wallet on the next worker tick instead. The grant id is returned so the caller
    // can revoke this auto-issued grant without a second list call (mirrors the
    // storage source register response).
    let (registered, grant_id) = match register_wallet_and_grant(
        &state.pool,
        operator_id,
        &body.label,
        &body.address,
        network,
        scope,
    )
    .await
    {
        Ok(RegisterAndGrantOutcome::Registered { wallet, grant_id }) => (wallet, grant_id),
        // The address is already a wallet under a DIFFERENT operator. A global
        // identity cannot be re-registered by a second tenant; the right
        // expression of a shared key is the registrar issuing an operator grant.
        Ok(RegisterAndGrantOutcome::AddressTaken { .. }) => {
            return Problem::of(
                "address-already-registered",
                "this address is already registered as a wallet by another operator",
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
        // The wallet vanished between the register and the grant (a concurrent
        // delete), or its account scope no longer resolves: report it as a transient
        // not-found rather than a half-registered wallet.
        Ok(RegisterAndGrantOutcome::GrantUnresolved) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    record_audit_best_effort(
        &state.pool,
        &AuditEntry {
            actor_kind: ActorKind::Operator,
            actor_id: Some(operator_id),
            action: "wallet.register".into(),
            target_type: "operator_wallet".into(),
            target_id: registered.wallet_id.to_string(),
            prev_state: None,
            new_state: Some(json!({
                "label": body.label,
                "address": body.address,
                "network": network.as_str(),
                "inserted": registered.inserted,
                "scope": grant_scope_kind(scope),
                "grant_id": grant_id,
            })),
            request_id: Some(trace_id),
        },
    )
    .await;

    json_response(
        StatusCode::CREATED,
        trace_id,
        json!({
            "wallet_id": registered.wallet_id,
            "created": registered.inserted,
            "grant_id": grant_id,
        }),
    )
}

/// Resolve the spend scope a registration confers, or a ready problem response.
///
/// An omitted `scope` uses the instance's `default_wallet_scope`. An explicit
/// `service`/`operator` resolves directly (operator pins to the registrar). An
/// `account` scope requires a `scope_account_id` the registrar owns: a
/// cross-operator account grant is rejected (the account must belong to the
/// registering operator), and a missing account is shaped like any not-found
/// resource (no cross-tenant existence oracle).
#[allow(clippy::result_large_err)]
async fn resolve_register_scope(
    state: &ControlState,
    operator_id: Uuid,
    scope: Option<&str>,
    scope_account_id: Option<&str>,
    trace_id: Uuid,
) -> std::result::Result<GrantScope, Response> {
    let base = &state.config.problem_type_base;
    match scope {
        None => Ok(match state.config.default_wallet_scope {
            DefaultWalletScope::Service => GrantScope::Service,
            DefaultWalletScope::Operator => GrantScope::Operator { operator_id },
        }),
        Some("service") => Ok(GrantScope::Service),
        Some("operator") => Ok(GrantScope::Operator { operator_id }),
        Some("account") => {
            let raw = scope_account_id.ok_or_else(|| {
                Problem::of(
                    "validation-failed",
                    "an account scope requires scope_account_id",
                )
                .into_response_with(base, trace_id)
            })?;
            let account_id = parse_id(&state.config, trace_id, raw)?;
            // The registrar may grant account scope only for an account it owns.
            let owns = account_belongs_to_operator(&state.pool, operator_id, account_id)
                .await
                .map_err(|e| engine_error(&state.config, trace_id, &e))?;
            if !owns {
                return Err(not_found(&state.config, trace_id));
            }
            Ok(GrantScope::Account { account_id })
        }
        Some(_) => Err(Problem::of(
            "validation-failed",
            "scope must be service, operator, or account",
        )
        .into_response_with(base, trace_id)),
    }
}

/// The wire token a [`GrantScope`] records on its audit row.
fn grant_scope_kind(scope: GrantScope) -> &'static str {
    match scope {
        GrantScope::Service => "service",
        GrantScope::Operator { .. } => "operator",
        GrantScope::Account { .. } => "account",
    }
}

/// `GET /control/v1/wallets` — list the operator's wallets with UTxO statistics.
async fn list_wallets_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator principal carries an operator id");
    let limit = clamp_limit(params.limit);

    let wallets = match queries::list_wallets(&state.pool, operator_id, limit).await {
        Ok(w) => w,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let data = wallets
        .into_iter()
        .map(|w| {
            json!({
                "wallet_id": w.wallet_id,
                "operator_id": w.registrar_operator_id,
                "label": w.label,
                "address": w.address,
                "network": w.network.as_str(),
                "status": w.status.as_str(),
                "available_utxos": w.available_utxos,
                "canonical_utxos": w.canonical_utxos,
                "created_at": w.created_at,
            })
        })
        .collect();
    list_envelope(StatusCode::OK, trace_id, data)
}

/// `GET /control/v1/wallets/operator-balance` — the operator's live on-chain ADA
/// balance per Cardano signing wallet, as a pure overlay keyed by wallet id.
///
/// Unlike the quote-path UTxO reads, this is a LIVE chain read by design: it backs
/// an explicit operator refresh in an admin console so the operator can see how
/// much ADA each signing wallet holds and decide whether to top it up — exactly the
/// posture [`storage_operator_balance_route`] takes for the Arweave side. The
/// per-wallet balance is the total lovelace across every UTxO at the wallet's
/// address (asset-bearing outputs included, since their locked ADA is still the
/// operator's funds), summed from the same Koios `/address_utxos` read the coin
/// selector uses.
///
/// This is a balance OVERLAY, not a second roster: the identity fields (label,
/// address, status, UTxO counts) stay owned by `GET /wallets`, so the console
/// joins this onto that roster by `wallet_id`. Degrades gracefully rather than
/// erroring: a deployment with no chain seam wired reports `chain_configured:
/// false`; an unreachable provider lands as a per-wallet error string while every
/// other wallet's balance still serves.
async fn wallet_operator_balance_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator principal carries an operator id");
    let limit = clamp_limit(params.limit);

    let wallets = match queries::list_wallets(&state.pool, operator_id, limit).await {
        Ok(w) => w,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    let Some(chain) = state.chain.clone() else {
        // No chain seam wired (the test constructors): emit the wallet ids with the
        // balance reported unavailable rather than inventing a figure.
        let balances: Vec<Value> = wallets
            .into_iter()
            .map(|w| balance_overlay_json(w.wallet_id, None, None))
            .collect();
        return json_response(
            StatusCode::OK,
            trace_id,
            json!({
                "chain_configured": false,
                "fetched_at": chrono::Utc::now(),
                "balances": balances,
            }),
        );
    };

    // One HTTP client shared across the per-wallet reads, built with the same
    // request timeout the engine's other Koios clients use so a hung connection
    // bounds the admin request instead of stalling it; each wallet is then
    // addressed at its own network's Koios base URL so a single seam serves all.
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return engine_error(
                &state.config,
                trace_id,
                &crate::Error::ChainProvider(format!("building HTTP client: {e}")),
            )
        }
    };
    // Read each wallet's balance with bounded concurrency, then collect under an
    // overall wall-clock budget. The per-wallet read is a single Koios
    // `/address_utxos` page — the same read the coin selector trusts as the
    // wallet's full UTxO set. Operator signing wallets are kept to a small
    // canonical band that never approaches a page, so the lovelace sum is exact in
    // practice; were a page ever truncated it could only under-report, the safe
    // direction for a "top this up" signal.
    // Snapshot the fields each read needs as owned values so the concurrent futures
    // borrow nothing from the roster (a borrowed `&WalletSummary` can't satisfy the
    // handler's lifetime bound through the stream).
    let read_inputs: Vec<(usize, String, crate::chain::params::Network)> = wallets
        .iter()
        .enumerate()
        .map(|(idx, w)| (idx, w.address.clone(), w.network.to_params_network()))
        .collect();
    let reads =
        futures_util::stream::iter(read_inputs.into_iter().map(|(idx, address, network)| {
            let client = client.clone();
            let koios = chain.koios.clone();
            async move {
                let source = KoiosUtxoSource::with_client(
                    client,
                    koios.base_url_for(network),
                    koios.api_key.clone(),
                );
                let outcome = match source.address_utxos(&address).await {
                    Ok(utxos) => {
                        let total: u128 = utxos.iter().map(|u| u128::from(u.lovelace)).sum();
                        (Some(total.to_string()), None)
                    }
                    Err(e) => (None, Some(e.to_string())),
                };
                (idx, outcome)
            }
        }))
        .buffer_unordered(WALLET_BALANCE_READ_CONCURRENCY);

    // Drain into roster order. Any wallet still unread when the budget elapses stays
    // `None` and is surfaced as a deadline error, so the response is bounded even if
    // a full roster's reads all stall.
    let mut outcomes: Vec<Option<(Option<String>, Option<String>)>> = vec![None; wallets.len()];
    let deadline = tokio::time::Instant::now() + WALLET_BALANCE_READ_BUDGET;
    let mut reads = reads;
    while let Ok(Some((idx, outcome))) = tokio::time::timeout_at(deadline, reads.next()).await {
        outcomes[idx] = Some(outcome);
    }

    let balances: Vec<Value> = wallets
        .iter()
        .zip(outcomes)
        .map(|(wallet, outcome)| {
            let (balance, error) =
                outcome.unwrap_or_else(|| (None, Some("balance read budget exceeded".to_string())));
            balance_overlay_json(wallet.wallet_id, balance, error)
        })
        .collect();

    json_response(
        StatusCode::OK,
        trace_id,
        json!({
            "chain_configured": true,
            "fetched_at": chrono::Utc::now(),
            "balances": balances,
        }),
    )
}

/// One wallet's balance overlay row: the wallet id plus its live total lovelace
/// (`balance_lovelace` as a decimal string to survive a JSON-unsafe magnitude, or
/// `balance_error` when the live read failed).
fn balance_overlay_json(
    wallet_id: Uuid,
    balance_lovelace: Option<String>,
    balance_error: Option<String>,
) -> Value {
    json!({
        "wallet_id": wallet_id,
        "balance_lovelace": balance_lovelace,
        "balance_error": balance_error,
    })
}

/// `POST /control/v1/wallets/{wallet_id}/drain` — transition active -> draining.
async fn drain_wallet_route(
    State(state): State<ControlState>,
    Path(wallet_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ReasonBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let wallet_id = match parse_id(&state.config, trace_id, &wallet_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let reason = body.and_then(|b| b.0.reason);

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let change = match begin_draining(&mut *txn, operator_id, wallet_id).await {
        Ok(c) => c,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let (changed, status) = match change {
        ScopedTransition::NotFound => return not_found(&state.config, trace_id),
        ScopedTransition::Changed { from, to } => {
            if let Err(e) = audit::record(
                &mut *txn,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: principal.actor_id(),
                    action: "wallet.drain".into(),
                    target_type: "operator_wallet".into(),
                    target_id: wallet_id.to_string(),
                    prev_state: Some(json!({ "status": from.as_str() })),
                    new_state: Some(json!({ "status": to.as_str(), "reason": reason })),
                    request_id: Some(trace_id),
                },
            )
            .await
            {
                return engine_error(&state.config, trace_id, &e);
            }
            (true, to)
        }
        ScopedTransition::Unchanged { status } => (false, status),
    };
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "wallet_id": wallet_id, "status": status.as_str(), "changed": changed }),
    )
}

/// `POST /control/v1/wallets/{wallet_id}/reactivate` — draining -> active.
async fn reactivate_wallet_route(
    State(state): State<ControlState>,
    Path(wallet_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ReasonBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let wallet_id = match parse_id(&state.config, trace_id, &wallet_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let reason = body.and_then(|b| b.0.reason);

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let change = match reactivate(&mut *txn, operator_id, wallet_id).await {
        Ok(c) => c,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let (changed, status) = match change {
        ScopedTransition::NotFound => return not_found(&state.config, trace_id),
        ScopedTransition::Changed { from, to } => {
            if let Err(e) = audit::record(
                &mut *txn,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: principal.actor_id(),
                    action: "wallet.reactivate".into(),
                    target_type: "operator_wallet".into(),
                    target_id: wallet_id.to_string(),
                    prev_state: Some(json!({ "status": from.as_str() })),
                    new_state: Some(json!({ "status": to.as_str(), "reason": reason })),
                    request_id: Some(trace_id),
                },
            )
            .await
            {
                return engine_error(&state.config, trace_id, &e);
            }
            (true, to)
        }
        ScopedTransition::Unchanged { status } => (false, status),
    };
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "wallet_id": wallet_id, "status": status.as_str(), "changed": changed }),
    )
}

// ---------------------------------------------------------------------------
// Wallet grants.
// ---------------------------------------------------------------------------

/// `POST /control/v1/wallets/{wallet_id}/grants` — issue a spend grant.
///
/// Only the wallet's registrar may grant on it (a foreign or missing wallet is a
/// 404, no cross-tenant existence oracle). The `scope` is `service` (everyone),
/// `operator` (the registrar), or `account` (a named account the registrar
/// owns). Issuing is idempotent per scope subject.
#[derive(Deserialize)]
struct IssueGrantBody {
    scope: String,
    #[serde(default)]
    account_id: Option<String>,
}

async fn issue_grant_route(
    State(state): State<ControlState>,
    Path(wallet_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<IssueGrantBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let wallet_id = match parse_id(&state.config, trace_id, &wallet_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let Some(Json(body)) = body else {
        return Problem::of("invalid-body", "a grant body is required")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };

    // Resolve the scope. `operator` always names the registering operator (a
    // registrar cannot mint a grant for some other operator through this route;
    // cross-operator sharing is the registrar issuing an operator grant for a
    // grantee it explicitly names, which is out of this slice's scope and would
    // be a distinct, audited capability). `account` must name an account the
    // registrar owns.
    let scope = match body.scope.as_str() {
        "service" => GrantScope::Service,
        "operator" => GrantScope::Operator { operator_id },
        "account" => {
            let raw = match body.account_id.as_deref() {
                Some(raw) => raw,
                None => {
                    return Problem::of("validation-failed", "an account grant requires account_id")
                        .into_response_with(&state.config.problem_type_base, trace_id)
                }
            };
            let account_id = match parse_id(&state.config, trace_id, raw) {
                Ok(id) => id,
                Err(resp) => return resp,
            };
            match account_belongs_to_operator(&state.pool, operator_id, account_id).await {
                Ok(true) => GrantScope::Account { account_id },
                Ok(false) => return not_found(&state.config, trace_id),
                Err(e) => return engine_error(&state.config, trace_id, &e),
            }
        }
        _ => {
            return Problem::of(
                "validation-failed",
                "scope must be service, operator, or account",
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
    };

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let outcome = match issue_grant(&mut *txn, operator_id, wallet_id, scope).await {
        Ok(Some(o)) => o,
        // The wallet is absent or registered by another operator.
        Ok(None) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let (grant_id, issued) = match outcome {
        IssueOutcome::Issued { grant_id } => (grant_id, true),
        IssueOutcome::AlreadyGranted { grant_id } => (grant_id, false),
    };
    if issued {
        if let Err(e) = audit::record(
            &mut *txn,
            &AuditEntry {
                actor_kind: ActorKind::Operator,
                actor_id: Some(operator_id),
                action: "wallet.grant.issue".into(),
                target_type: "wallet_grant".into(),
                target_id: grant_id.to_string(),
                prev_state: None,
                new_state: Some(json!({
                    "wallet_id": wallet_id,
                    "scope": grant_scope_kind(scope),
                })),
                request_id: Some(trace_id),
            },
        )
        .await
        {
            return engine_error(&state.config, trace_id, &e);
        }
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::CREATED,
        trace_id,
        json!({ "grant_id": grant_id, "wallet_id": wallet_id, "issued": issued }),
    )
}

/// `POST /control/v1/wallets/{wallet_id}/grants/{grant_id}/revoke` — revoke a
/// spend grant.
///
/// Only the wallet's registrar may revoke a grant on its own wallet (a grant on a
/// foreign or missing wallet is a 404). Revocation gates NEW picks only; an
/// in-flight submit keys on the wallet id and still settles.
async fn revoke_grant_route(
    State(state): State<ControlState>,
    Path((wallet_id, grant_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let wallet_id = match parse_id(&state.config, trace_id, &wallet_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let grant_id = match parse_id(&state.config, trace_id, &grant_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let outcome = match revoke_grant(&mut *txn, operator_id, wallet_id, grant_id).await {
        Ok(Some(o)) => o,
        Ok(None) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let revoked = match outcome {
        RevokeOutcome::Revoked => true,
        RevokeOutcome::AlreadyRevoked => false,
    };
    if revoked {
        if let Err(e) = audit::record(
            &mut *txn,
            &AuditEntry {
                actor_kind: ActorKind::Operator,
                actor_id: Some(operator_id),
                action: "wallet.grant.revoke".into(),
                target_type: "wallet_grant".into(),
                target_id: grant_id.to_string(),
                prev_state: Some(json!({ "revoked_at": Value::Null })),
                new_state: Some(json!({ "wallet_id": wallet_id, "revoked": true })),
                request_id: Some(trace_id),
            },
        )
        .await
        {
            return engine_error(&state.config, trace_id, &e);
        }
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "grant_id": grant_id, "wallet_id": wallet_id, "revoked": revoked }),
    )
}

// ---------------------------------------------------------------------------
// Storage funding sources.
// ---------------------------------------------------------------------------

/// The canonical persisted backend identifier for a source registration.
///
/// One source per backend per address; the persisted backend is normalized to its
/// canonical hyphen form so credit, grant, and receipt rows never split on a name
/// variant. Config-level aliasing (`direct_arweave`) is the binary's concern; the
/// control wire accepts only the canonical tokens.
fn normalize_backend(raw: &str) -> Option<&'static str> {
    match raw {
        "turbo" => Some("turbo"),
        "direct-arweave" | "direct_arweave" => Some("direct-arweave"),
        "arlocal" => Some("arlocal"),
        _ => None,
    }
}

/// `POST /control/v1/storage/sources` — register a funding source from a keyring
/// Arweave entry.
///
/// Requires the operator ROOT credential. Registration binds a keyring Arweave key
/// to an owning operator, and the keyring is shared across every operator on the
/// instance; an ordinary operator token must not be able to claim a key it merely
/// shares custody of, which would let a second tenant register another tenant's
/// funding address and draw its prepaid winc. Key custody is an instance-level
/// responsibility, so the root decides which operator owns a key. Grants on an
/// already-owned source stay operator-manageable (the owner-only grant routes).
///
/// `address` must be a verified Arweave address the instance physically holds a
/// signer for (the keyring derived it from the JWK at unlock): a row is never
/// written for an address no signer can back, so a source the upload path can never
/// sign is unrepresentable. `scope` is the draw scope the registration confers;
/// omitted, it defaults to the instance's `default_storage_scope`. The resolved
/// scope is auto-issued as a grant, so the common case (register and use) needs no
/// second call; a `service` scope is refused when the backend already has a live
/// service grant (the single-source rule).
#[derive(Deserialize)]
struct RegisterSourceBody {
    label: String,
    backend: String,
    address: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scope_account_id: Option<String>,
}

async fn register_source_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Option<Json<RegisterSourceBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_root(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator root principal carries an operator id");
    let Some(Json(body)) = body else {
        return Problem::of("invalid-body", "a funding source body is required")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };

    let Some(backend) = normalize_backend(&body.backend) else {
        return Problem::of(
            "validation-failed",
            "backend must be turbo, direct-arweave, or arlocal",
        )
        .into_response_with(&state.config.problem_type_base, trace_id);
    };

    // Confirm the instance physically holds a verified signer for this address
    // BEFORE writing a row. The keyring already derived the address from the JWK at
    // unlock, so a match here proves the JWK -> address binding without re-deriving
    // it; an address no signer backs is refused so the upload path can never resolve
    // an unsignable source. The address doubles as the source's key_ref, since the
    // keyring resolves an Arweave signer by address.
    if !state.funding_keys.iter().any(|k| k.address == body.address) {
        return Problem::of(
            "validation-failed",
            "no verified Arweave signing key for this address is held by this instance",
        )
        .into_response_with(&state.config.problem_type_base, trace_id);
    }
    let key_ref = body.address.clone();

    // Resolve the draw scope the registration grants: the body's `scope` when
    // present, else the instance default. An `account` scope must name an account
    // the registrar owns (a cross-operator account grant is forbidden).
    let scope = match resolve_register_storage_scope(
        &state,
        operator_id,
        body.scope.as_deref(),
        body.scope_account_id.as_deref(),
        trace_id,
    )
    .await
    {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };

    let outcome = match register_source(
        &state.pool,
        operator_id,
        &body.label,
        backend,
        &body.address,
        &key_ref,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let registered = match outcome {
        RegisterSourceOutcome::Registered(r) => r,
        // The address is already a source under a DIFFERENT operator. A global credit
        // pool cannot be re-registered by a second tenant; the right expression of a
        // shared key is the owner issuing a grant.
        RegisterSourceOutcome::AddressTaken { .. } => {
            return Problem::of(
                "address-already-registered",
                "this address is already registered as a funding source by another operator",
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
    };

    // Auto-grant the resolved scope so the common case (register and use) needs no
    // second call. Idempotent per `(backend, scope subject)`: re-registering an
    // existing source re-asserts the grant rather than duplicating it. A `service`
    // scope for a backend that already has a live service grant converges on that
    // existing grant (the single-source rule), so a second source cannot silently
    // become a second service default.
    let grant_id =
        match issue_storage_grant(&state.pool, operator_id, registered.source_id, scope).await {
            Ok(Some(StorageIssueOutcome::Issued { grant_id }))
            | Ok(Some(StorageIssueOutcome::AlreadyGranted { grant_id })) => grant_id,
            // The backend's service default is already held by another operator. The
            // per-backend single-source rule allows exactly one live service grant, so
            // a second operator cannot register a second service default. Report the
            // conflict WITHOUT the foreign grant id (it belongs to another tenant).
            Ok(Some(StorageIssueOutcome::ServiceDefaultHeldByOtherOwner)) => {
                return Problem::of(
                    "address-already-registered",
                    "the service default for this backend is already held by another operator; a backend carries one shared service funding default",
                )
                .into_response_with(&state.config.problem_type_base, trace_id)
            }
            // The source vanished between the register and the grant (a concurrent
            // delete), or its account scope no longer resolves: report it as a transient
            // not-found rather than a half-registered source.
            Ok(None) => return not_found(&state.config, trace_id),
            Err(e) => return engine_error(&state.config, trace_id, &e),
        };

    record_audit_best_effort(
        &state.pool,
        &AuditEntry {
            actor_kind: ActorKind::Operator,
            actor_id: Some(operator_id),
            action: "storage.register".into(),
            target_type: "storage_funding_source".into(),
            target_id: registered.source_id.to_string(),
            prev_state: None,
            new_state: Some(json!({
                "label": body.label,
                "backend": backend,
                "address": body.address,
                "inserted": registered.inserted,
                "scope": storage_grant_scope_kind(scope),
                "grant_id": grant_id,
            })),
            request_id: Some(trace_id),
        },
    )
    .await;

    json_response(
        StatusCode::CREATED,
        trace_id,
        json!({
            "source_id": registered.source_id,
            "created": registered.inserted,
            "grant_id": grant_id,
        }),
    )
}

/// Resolve the draw scope a source registration confers, or a ready problem
/// response.
///
/// An omitted `scope` uses the instance's `default_storage_scope`. An explicit
/// `service`/`operator` resolves directly (operator pins to the registrar). An
/// `account` scope requires a `scope_account_id` the registrar owns: a
/// cross-operator account grant is rejected, and a missing account is shaped like
/// any not-found resource (no cross-tenant existence oracle). The owner-belongs
/// check also lives in the engine `issue_grant`, so this is a fast-fail before the
/// register write, not the only gate.
#[allow(clippy::result_large_err)]
async fn resolve_register_storage_scope(
    state: &ControlState,
    operator_id: Uuid,
    scope: Option<&str>,
    scope_account_id: Option<&str>,
    trace_id: Uuid,
) -> std::result::Result<StorageGrantScope, Response> {
    let base = &state.config.problem_type_base;
    match scope {
        None => Ok(match state.config.default_storage_scope {
            DefaultStorageScope::Service => StorageGrantScope::Service,
            DefaultStorageScope::Operator => StorageGrantScope::Operator { operator_id },
        }),
        Some("service") => Ok(StorageGrantScope::Service),
        Some("operator") => Ok(StorageGrantScope::Operator { operator_id }),
        Some("account") => {
            let raw = scope_account_id.ok_or_else(|| {
                Problem::of(
                    "validation-failed",
                    "an account scope requires scope_account_id",
                )
                .into_response_with(base, trace_id)
            })?;
            let account_id = parse_id(&state.config, trace_id, raw)?;
            // The registrar may grant account scope only for an account it owns.
            let owns = account_belongs_to_operator(&state.pool, operator_id, account_id)
                .await
                .map_err(|e| engine_error(&state.config, trace_id, &e))?;
            if !owns {
                return Err(not_found(&state.config, trace_id));
            }
            Ok(StorageGrantScope::Account { account_id })
        }
        Some(_) => Err(Problem::of(
            "validation-failed",
            "scope must be service, operator, or account",
        )
        .into_response_with(base, trace_id)),
    }
}

/// The wire token a [`StorageGrantScope`] records on its audit row.
fn storage_grant_scope_kind(scope: StorageGrantScope) -> &'static str {
    match scope {
        StorageGrantScope::Service => "service",
        StorageGrantScope::Operator { .. } => "operator",
        StorageGrantScope::Account { .. } => "account",
    }
}

/// `GET /control/v1/storage/sources` — list the operator's funding sources with
/// their cached credit diagnostics and a low-credit flag.
async fn list_sources_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator principal carries an operator id");
    let limit = clamp_limit(params.limit);

    let sources = match list_sources(&state.pool, operator_id, limit).await {
        Ok(s) => s,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let data = sources
        .into_iter()
        .map(|s| {
            json!({
                "source_id": s.source_id,
                "operator_id": s.owner_operator_id,
                "label": s.label,
                "backend": s.backend,
                "arweave_address": s.arweave_address,
                "status": s.status.as_str(),
                "winc_balance": s.winc_balance.map(|w| w.to_string()),
                "fundable_bytes": s.fundable_bytes,
                "last_reconciled_at": s.last_reconciled_at,
                "last_error": s.last_error,
                // The cached balance is stale when a refresh failed; surface it so an
                // operator does not read an unreconciled or errored balance as fresh.
                "stale": s.last_error.is_some() || s.last_reconciled_at.is_none(),
            })
        })
        .collect();
    list_envelope(StatusCode::OK, trace_id, data)
}

/// `POST /control/v1/storage/sources/{source_id}/drain` — transition active ->
/// draining (take no new charges; in-flight uploads settle by source id).
async fn drain_source_route(
    State(state): State<ControlState>,
    Path(source_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ReasonBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let source_id = match parse_id(&state.config, trace_id, &source_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let reason = body.and_then(|b| b.0.reason);

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let change = match begin_draining_source(&mut *txn, operator_id, source_id).await {
        Ok(c) => c,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let (changed, status) = match change {
        ScopedTransition::NotFound => return not_found(&state.config, trace_id),
        ScopedTransition::Changed { from, to } => {
            if let Err(e) = audit::record(
                &mut *txn,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: principal.actor_id(),
                    action: "storage.drain".into(),
                    target_type: "storage_funding_source".into(),
                    target_id: source_id.to_string(),
                    prev_state: Some(json!({ "status": from.as_str() })),
                    new_state: Some(json!({ "status": to.as_str(), "reason": reason })),
                    request_id: Some(trace_id),
                },
            )
            .await
            {
                return engine_error(&state.config, trace_id, &e);
            }
            (true, to)
        }
        ScopedTransition::Unchanged { status } => (false, status),
    };
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "source_id": source_id, "status": status.as_str(), "changed": changed }),
    )
}

/// `POST /control/v1/storage/sources/{source_id}/grants` — issue a draw grant.
///
/// Only the source's owner may grant on it (a foreign or missing source is a 404, no
/// cross-tenant existence oracle). The `scope` is `service` (every account),
/// `operator` (the registrar), or `account` (a named account the registrar owns).
/// Issuing is idempotent per `(backend, scope subject)`.
#[derive(Deserialize)]
struct IssueSourceGrantBody {
    scope: String,
    #[serde(default)]
    account_id: Option<String>,
}

async fn issue_source_grant_route(
    State(state): State<ControlState>,
    Path(source_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<IssueSourceGrantBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let source_id = match parse_id(&state.config, trace_id, &source_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let Some(Json(body)) = body else {
        return Problem::of("invalid-body", "a grant body is required")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };

    // Resolve the scope. `operator` always names the registering operator (a
    // registrar cannot mint a grant for some other operator through this route).
    // `account` must name an account the registrar owns; the engine `issue_grant`
    // re-checks ownership, so this is a fast pre-check, not the only gate.
    let scope = match body.scope.as_str() {
        "service" => StorageGrantScope::Service,
        "operator" => StorageGrantScope::Operator { operator_id },
        "account" => {
            let raw = match body.account_id.as_deref() {
                Some(raw) => raw,
                None => {
                    return Problem::of("validation-failed", "an account grant requires account_id")
                        .into_response_with(&state.config.problem_type_base, trace_id)
                }
            };
            let account_id = match parse_id(&state.config, trace_id, raw) {
                Ok(id) => id,
                Err(resp) => return resp,
            };
            match account_belongs_to_operator(&state.pool, operator_id, account_id).await {
                Ok(true) => StorageGrantScope::Account { account_id },
                Ok(false) => return not_found(&state.config, trace_id),
                Err(e) => return engine_error(&state.config, trace_id, &e),
            }
        }
        _ => {
            return Problem::of(
                "validation-failed",
                "scope must be service, operator, or account",
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
    };

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let outcome = match issue_storage_grant(&mut *txn, operator_id, source_id, scope).await {
        Ok(Some(o)) => o,
        // The source is absent or owned by another operator.
        Ok(None) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let (grant_id, issued) = match outcome {
        StorageIssueOutcome::Issued { grant_id } => (grant_id, true),
        StorageIssueOutcome::AlreadyGranted { grant_id } => (grant_id, false),
        // The backend's service default is already held by another operator. The
        // single-source rule allows exactly one live service grant per backend;
        // report the conflict WITHOUT the foreign grant id (it belongs to another
        // tenant), never the caller's AlreadyGranted carrying a leaked id.
        StorageIssueOutcome::ServiceDefaultHeldByOtherOwner => {
            return Problem::of(
                "address-already-registered",
                "the service default for this backend is already held by another operator; a backend carries one shared service funding default",
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
    };
    if issued {
        if let Err(e) = audit::record(
            &mut *txn,
            &AuditEntry {
                actor_kind: ActorKind::Operator,
                actor_id: Some(operator_id),
                action: "storage.grant".into(),
                target_type: "storage_grant".into(),
                target_id: grant_id.to_string(),
                prev_state: None,
                new_state: Some(json!({
                    "source_id": source_id,
                    "scope": storage_grant_scope_kind(scope),
                })),
                request_id: Some(trace_id),
            },
        )
        .await
        {
            return engine_error(&state.config, trace_id, &e);
        }
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::CREATED,
        trace_id,
        json!({ "grant_id": grant_id, "source_id": source_id, "issued": issued }),
    )
}

/// `POST /control/v1/storage/sources/{source_id}/grants/{grant_id}/revoke` —
/// revoke a draw grant.
///
/// A soft revoke (it sets `revoked_at` and is idempotent, not a resource delete),
/// so it mirrors the wallet grant-revoke verb and shape: `POST .../revoke`
/// returning `200 { grant_id, source_id, revoked }`. Only the source's owner may
/// revoke a grant on its own source (a grant on a foreign or missing source is a
/// 404). Revocation gates NEW charges only; an in-flight upload settles by
/// `funding_source_id` and is never stranded.
async fn revoke_source_grant_route(
    State(state): State<ControlState>,
    Path((source_id, grant_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let source_id = match parse_id(&state.config, trace_id, &source_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let grant_id = match parse_id(&state.config, trace_id, &grant_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut txn = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let outcome = match revoke_storage_grant(&mut *txn, operator_id, source_id, grant_id).await {
        Ok(Some(o)) => o,
        Ok(None) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let revoked = match outcome {
        StorageRevokeOutcome::Revoked => true,
        StorageRevokeOutcome::AlreadyRevoked => false,
    };
    if revoked {
        if let Err(e) = audit::record(
            &mut *txn,
            &AuditEntry {
                actor_kind: ActorKind::Operator,
                actor_id: Some(operator_id),
                action: "storage.revoke".into(),
                target_type: "storage_grant".into(),
                target_id: grant_id.to_string(),
                prev_state: Some(json!({ "revoked_at": Value::Null })),
                new_state: Some(json!({ "source_id": source_id, "revoked": true })),
                request_id: Some(trace_id),
            },
        )
        .await
        {
            return engine_error(&state.config, trace_id, &e);
        }
    }
    if let Err(e) = txn.commit().await {
        return engine_error(&state.config, trace_id, &e.into());
    }
    json_response(
        StatusCode::OK,
        trace_id,
        json!({ "grant_id": grant_id, "source_id": source_id, "revoked": revoked }),
    )
}

/// `GET /control/v1/storage/funding` — the aggregate funding status across the
/// operator's sources: total believed winc, total fundable bytes, and a low-credit
/// roll-up.
///
/// This is the visibility surface the per-source list rolls up: it sums the cached
/// believed winc across every source the operator owns, sums the provider-reported
/// fundable bytes where present, and flags whether any source is stale (no reconcile
/// or a refresh error). It reads only cached rows; no provider call is made.
async fn storage_funding_route(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator principal carries an operator id");

    // Aggregate across every source the operator owns (not just `active`: a draining
    // source still carries credit an operator must see). The cap is the same as the
    // list page size: a single operator is not expected to own thousands of sources,
    // and the aggregate is over the cached rows.
    let sources = match list_sources(&state.pool, operator_id, MAX_LIST_LIMIT).await {
        Ok(s) => s,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    let mut total_winc = rust_decimal::Decimal::ZERO;
    let mut total_fundable_bytes: i64 = 0;
    let mut source_count: usize = 0;
    let mut stale_count: usize = 0;
    for s in &sources {
        source_count += 1;
        if let Some(w) = s.winc_balance {
            total_winc += w;
        }
        if let Some(b) = s.fundable_bytes {
            total_fundable_bytes = total_fundable_bytes.saturating_add(b);
        }
        if s.last_error.is_some() || s.last_reconciled_at.is_none() {
            stale_count += 1;
        }
    }

    json_response(
        StatusCode::OK,
        trace_id,
        json!({
            "source_count": source_count,
            "total_winc_balance": total_winc.to_string(),
            "total_fundable_bytes": total_fundable_bytes,
            "stale_source_count": stale_count,
        }),
    )
}

// ---------------------------------------------------------------------------
// The storage funding console: live operator balances + the AR -> credit top-up.
// ---------------------------------------------------------------------------

/// The machine-readable reason a Turbo-rail feature is unavailable on this
/// deployment: the configured backend has no payment service (ArLocal / direct
/// Arweave), so there is no winc balance to read and nothing to top up.
const TURBO_NOT_ACTIVE: &str = "turbo-not-active";

/// The machine-readable reason the funding console is empty: the deployment
/// configures no `[storage]` at all (a hash-only gateway).
const STORAGE_NOT_CONFIGURED: &str = "storage-not-configured";

/// The machine-readable reason a top-up cannot be issued yet: the operator owns
/// no active funding source on this backend.
const NO_FUNDING_SOURCE: &str = "no-funding-source";

/// How many recent top-ups the operator-balance response carries.
const RECENT_TOPUP_LIMIT: i64 = 10;

/// `GET /control/v1/storage/operator-balance` — the operator's live storage
/// funding position: for every funding wallet, the on-chain AR balance read from
/// the configured Arweave node and (on the Turbo backend) the live prepaid winc
/// balance read from the payment service, plus the cached reconcile diagnostics
/// and the recent top-ups.
///
/// Unlike every quote-path read, this is a LIVE provider read by design: it backs
/// an explicit operator refresh in an admin console, not request-path traffic.
/// The wallets listed are the operator's own sources on the configured backend,
/// plus any keyring funding key no source row claims yet (so a fresh deployment
/// sees the address derived from its JWK before bootstrap). A key claimed by
/// ANOTHER operator's source is omitted entirely — the shared keyring must not
/// become a cross-tenant balance oracle.
///
/// Degrades gracefully rather than erroring: a deployment with no `[storage]`
/// reports `storage_configured: false`; a backend with no payment service marks
/// the Turbo fields unavailable with the machine-readable reason
/// `turbo-not-active`; an unreachable provider lands as a per-field error string
/// while the rest of the response still serves.
async fn storage_operator_balance_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator principal carries an operator id");

    // The recent conversions are pure database rows, served regardless of the
    // storage configuration (the journal outlives a config change).
    let recent = match list_operator_topups(&state.pool, operator_id, RECENT_TOPUP_LIMIT).await {
        Ok(rows) => rows,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let recent_json: Vec<Value> = recent.iter().map(topup_json).collect();

    let Some(storage) = state.storage.clone() else {
        return json_response(
            StatusCode::OK,
            trace_id,
            json!({
                "storage_configured": false,
                "backend": Value::Null,
                "fetched_at": chrono::Utc::now(),
                "wallets": [],
                "top_up": { "enabled": false, "reason": STORAGE_NOT_CONFIGURED },
                "recent_top_ups": recent_json,
            }),
        );
    };

    // The operator's own sources on this deployment's backend, with their cached
    // reconcile diagnostics.
    let sources = match list_sources(&state.pool, operator_id, MAX_LIST_LIMIT).await {
        Ok(s) => s,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let sources: Vec<SourceSummary> = sources
        .into_iter()
        .filter(|s| s.backend == storage.backend)
        .collect();

    // Keyring funding keys no source row claims on this backend: visible so a
    // fresh deployment sees its JWK-derived address before bootstrap. Keys
    // claimed by another operator are excluded (no cross-tenant balance oracle).
    let claimed: Vec<String> = match sqlx::query_scalar(
        "SELECT arweave_address FROM cw_core.storage_funding_source WHERE backend = $1",
    )
    .bind(&storage.backend)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };
    let unclaimed_keys: Vec<_> = state
        .funding_keys
        .iter()
        .filter(|k| !claimed.contains(&k.address))
        .cloned()
        .collect();

    let node = match ArweaveNodeClient::new(storage.node_url.clone()) {
        Ok(node) => node,
        Err(e) => {
            return engine_error(
                &state.config,
                trace_id,
                &crate::Error::Config(e.to_string()),
            )
        }
    };
    let winc_provider = match &storage.payment_url {
        Some(url) => match TurboWincProvider::new(url.clone()) {
            Ok(p) => Some(p),
            Err(e) => {
                return engine_error(
                    &state.config,
                    trace_id,
                    &crate::Error::Config(e.to_string()),
                )
            }
        },
        None => None,
    };

    let mut wallets: Vec<Value> = Vec::new();
    for entry in sources
        .iter()
        .map(|s| (s.arweave_address.clone(), Some(s)))
        .chain(unclaimed_keys.iter().map(|k| (k.address.clone(), None)))
    {
        let (address, source) = entry;
        let key_label = state
            .funding_keys
            .iter()
            .find(|k| k.address == address)
            .map(|k| k.label.clone());

        // The live on-chain AR balance. An unreachable node lands as a per-field
        // error so the rest of the console still renders.
        let (ar_balance, ar_error) = match node.wallet_balance_winston(&address).await {
            Ok(winston) => (Some(winston.to_string()), None),
            Err(e) => (None, Some(e.to_string())),
        };

        // The live prepaid winc balance, only meaningful on a payment-service
        // backend; otherwise unavailable with the machine-readable reason.
        let turbo = match &winc_provider {
            Some(provider) => match provider.get_winc_balance(&address).await {
                Ok(balance) => json!({
                    "available": true,
                    "winc": balance.winc.to_string(),
                    "fundable_bytes": balance.fundable_bytes,
                }),
                Err(e) => json!({
                    "available": false,
                    "reason": "provider-unavailable",
                    "detail": e.to_string(),
                }),
            },
            None => json!({ "available": false, "reason": TURBO_NOT_ACTIVE }),
        };

        wallets.push(json!({
            "arweave_address": address,
            "key_label": key_label,
            "key_held": key_label.is_some(),
            "source": source.map(|s| json!({
                "source_id": s.source_id,
                "label": s.label,
                "status": s.status.as_str(),
                "winc_balance": s.winc_balance.map(|w| w.to_string()),
                "fundable_bytes": s.fundable_bytes,
                "last_reconciled_at": s.last_reconciled_at,
                "last_error": s.last_error,
            })),
            "ar_balance_winston": ar_balance,
            "ar_balance_error": ar_error,
            "turbo": turbo,
        }));
    }

    // Whether a top-up can be issued right now, with the blocking reason when
    // not, so the console renders the disabled state without re-deriving it.
    let has_active_source = sources
        .iter()
        .any(|s| s.status == crate::storage::SourceStatus::Active);
    let top_up = if storage.payment_url.is_none() {
        json!({ "enabled": false, "reason": TURBO_NOT_ACTIVE })
    } else if !has_active_source {
        json!({ "enabled": false, "reason": NO_FUNDING_SOURCE })
    } else {
        json!({ "enabled": true })
    };

    json_response(
        StatusCode::OK,
        trace_id,
        json!({
            "storage_configured": true,
            "backend": storage.backend,
            "fetched_at": chrono::Utc::now(),
            "wallets": wallets,
            "top_up": top_up,
            "recent_top_ups": recent_json,
        }),
    )
}

/// `POST /control/v1/storage/top-up` — convert AR from the operator's funding
/// wallet into prepaid provider credits.
///
/// Body: `{ "ar_amount_winston": "<decimal string>", "idempotency_key":
/// "<string>", "funding_source_id": "<uuid>" }`, the source optional when the
/// operator owns exactly one active source on the backend. The amount is a
/// STRING because winston amounts overflow a JSON-safe integer; a JSON integer
/// is accepted for small values.
///
/// The idempotency key is REQUIRED: the conversion is an irreversible
/// fund movement, so a create whose response is lost must be retryable
/// without signing a second transfer. A repeat call with the same key (and
/// the same source + amount) replays the existing conversion — converged
/// forward, never re-signed — as a 200; only a genuinely new key signs and
/// returns 201. Reusing a key with a different source or amount is refused.
///
/// Owner-only: the source must be owned by the calling operator and `active`
/// (a top-up spends the wallet behind the source, which no draw grant
/// entitles). The conversion is irreversible, so the route never retries a
/// failure by re-signing; a failed broadcast/registration is recorded on the
/// returned record and retried forward via the register route.
#[derive(Deserialize)]
struct TopUpBody {
    ar_amount_winston: Value,
    #[serde(default)]
    idempotency_key: Option<String>,
    #[serde(default)]
    funding_source_id: Option<String>,
}

async fn storage_topup_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Option<Json<TopUpBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let Some(Json(body)) = body else {
        return Problem::of("invalid-body", "a top-up body is required")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };

    let (storage, node, payment) = match turbo_rail(&state, trace_id) {
        Ok(rail) => rail,
        Err(resp) => return resp,
    };

    let Some(amount) = parse_winston_amount(&body.ar_amount_winston) else {
        return Problem::of(
            "validation-failed",
            "ar_amount_winston must be a positive winston amount (as a decimal string)",
        )
        .into_response_with(&state.config.problem_type_base, trace_id);
    };

    // The conversion is irreversible, so the create is idempotent on a
    // REQUIRED caller-supplied key — a lost response is retried with the same
    // key and replays the journalled conversion instead of signing again.
    let idempotency_key = match body.idempotency_key.as_deref() {
        Some(key)
            if !key.trim().is_empty() && key.len() <= crate::storage::MAX_IDEMPOTENCY_KEY_LEN =>
        {
            key
        }
        _ => {
            return Problem::of(
                "validation-failed",
                "idempotency_key is required: a non-empty string (at most 200 characters) \
                 naming this conversion, so a retry replays it instead of signing a second \
                 irreversible transfer",
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
    };

    // Resolve the source being funded: the named one, or the operator's single
    // active source on this backend when unambiguous.
    let source_id = match body.funding_source_id.as_deref() {
        Some(raw) => match parse_id(&state.config, trace_id, raw) {
            Ok(id) => id,
            Err(resp) => return resp,
        },
        None => {
            let sources = match list_sources(&state.pool, operator_id, MAX_LIST_LIMIT).await {
                Ok(s) => s,
                Err(e) => return engine_error(&state.config, trace_id, &e),
            };
            let mut active = sources.into_iter().filter(|s| {
                s.backend == storage.backend && s.status == crate::storage::SourceStatus::Active
            });
            match (active.next(), active.next()) {
                (Some(only), None) => only.source_id,
                (None, _) => {
                    return Problem::of(
                        NO_FUNDING_SOURCE,
                        "the operator owns no active funding source on this backend",
                    )
                    .into_response_with(&state.config.problem_type_base, trace_id)
                }
                (Some(_), Some(_)) => {
                    return Problem::of(
                        "validation-failed",
                        "the operator owns several active funding sources; name one as funding_source_id",
                    )
                    .into_response_with(&state.config.problem_type_base, trace_id)
                }
            }
        }
    };

    // The owner-only capability: a missing, foreign, or non-active source is a
    // 404 (no cross-tenant existence oracle).
    let funding = match authorize_owner_topup(&state.pool, operator_id, source_id).await {
        Ok(Some(funding)) => funding,
        Ok(None) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    let outcome = match execute_topup(
        &state.pool,
        &storage.keyring,
        &node,
        &payment,
        &funding,
        operator_id,
        amount,
        idempotency_key,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    // One conversion, one `storage.topup` audit row: a same-key replay is its
    // own action so the audit trail still counts real transfers exactly.
    record_audit_best_effort(
        &state.pool,
        &AuditEntry {
            actor_kind: ActorKind::Operator,
            actor_id: Some(operator_id),
            action: if outcome.created {
                "storage.topup".into()
            } else {
                "storage.topup_replay".into()
            },
            target_type: "storage_topup".into(),
            target_id: outcome.record.id.to_string(),
            prev_state: None,
            new_state: Some(topup_json(&outcome.record)),
            request_id: Some(trace_id),
        },
    )
    .await;

    let status = if outcome.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    json_response(status, trace_id, topup_json(&outcome.record))
}

/// `GET /control/v1/storage/top-ups` — the operator's conversion journal,
/// newest-first.
async fn list_storage_topups_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator principal carries an operator id");
    let limit = clamp_limit(params.limit);

    let rows = match list_operator_topups(&state.pool, operator_id, limit).await {
        Ok(rows) => rows,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    list_envelope(
        StatusCode::OK,
        trace_id,
        rows.iter().map(topup_json).collect(),
    )
}

/// `POST /control/v1/storage/top-ups/{topup_id}/register` — retry an unfinished
/// top-up FORWARD: re-broadcast the persisted, byte-identical transfer when its
/// broadcast is unconfirmed, then re-register the same transaction id with the
/// payment service. Never re-signs (a re-sign would mint a second transfer and
/// move the funds twice). Idempotent for an already-registered top-up.
async fn register_storage_topup_route(
    State(state): State<ControlState>,
    Path(topup_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let topup_id = match parse_id(&state.config, trace_id, &topup_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let (_storage, node, payment) = match turbo_rail(&state, trace_id) {
        Ok(rail) => rail,
        Err(resp) => return resp,
    };

    let outcome = match register_topup(&state.pool, &node, &payment, operator_id, topup_id).await {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return not_found(&state.config, trace_id),
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };

    record_audit_best_effort(
        &state.pool,
        &AuditEntry {
            actor_kind: ActorKind::Operator,
            actor_id: Some(operator_id),
            action: "storage.topup_register".into(),
            target_type: "storage_topup".into(),
            target_id: outcome.record.id.to_string(),
            prev_state: None,
            new_state: Some(topup_json(&outcome.record)),
            request_id: Some(trace_id),
        },
    )
    .await;

    json_response(StatusCode::OK, trace_id, topup_json(&outcome.record))
}

/// Resolve the Turbo token-funding rail (the storage seam plus its node and
/// payment clients), or the ready problem response when the deployment cannot
/// top up: no `[storage]` at all, or a backend with no payment service.
#[allow(clippy::result_large_err)]
fn turbo_rail(
    state: &ControlState,
    trace_id: Uuid,
) -> std::result::Result<(ControlStorage, ArweaveNodeClient, TurboPaymentClient), Response> {
    let base = &state.config.problem_type_base;
    let Some(storage) = state.storage.clone() else {
        return Err(Problem::of(
            STORAGE_NOT_CONFIGURED,
            "this deployment configures no content storage",
        )
        .into_response_with(base, trace_id));
    };
    let Some(payment_url) = storage.payment_url.clone() else {
        return Err(Problem::of(
            TURBO_NOT_ACTIVE,
            "the configured storage backend has no payment service, so prepaid credits cannot be topped up",
        )
        .into_response_with(base, trace_id));
    };
    let node = ArweaveNodeClient::new(storage.node_url.clone()).map_err(|e| {
        engine_error(
            &state.config,
            trace_id,
            &crate::Error::Config(e.to_string()),
        )
    })?;
    let payment = TurboPaymentClient::new(payment_url).map_err(|e| {
        engine_error(
            &state.config,
            trace_id,
            &crate::Error::Config(e.to_string()),
        )
    })?;
    Ok((storage, node, payment))
}

/// Parse the wire `ar_amount_winston` (a decimal string, or a JSON integer for
/// small values) into winston. `None` for anything non-positive or malformed.
fn parse_winston_amount(value: &Value) -> Option<u128> {
    let amount = match value {
        Value::String(s) => s.trim().parse::<u128>().ok()?,
        Value::Number(n) => u128::from(n.as_u64()?),
        _ => return None,
    };
    (amount > 0).then_some(amount)
}

/// The wire projection of one top-up journal row.
fn topup_json(t: &TopUpRecord) -> Value {
    json!({
        "topup_id": t.id,
        "funding_source_id": t.funding_source_id,
        "ar_amount_winston": t.ar_amount_winston.to_string(),
        "fee_winston": t.fee_winston.to_string(),
        "target_address": t.target_address,
        "tx_id": t.tx_id,
        "idempotency_key": t.idempotency_key,
        "status": t.status.as_str(),
        "last_error": t.last_error,
        "registered_winc": t.registered_winc.map(|w| w.to_string()),
        "credited_at": t.credited_at,
        "created_at": t.created_at,
        "updated_at": t.updated_at,
    })
}

// ---------------------------------------------------------------------------
// Chain-provider request usage.
// ---------------------------------------------------------------------------

/// Query parameters for the provider-usage window.
#[derive(Deserialize)]
struct ProviderUsageParams {
    /// How many trailing UTC days to return (today inclusive). Defaults to 7,
    /// clamped to 1..=90.
    days: Option<i64>,
}

/// `GET /control/v1/chain/provider-usage` — the per-day chain-provider request
/// counts the egress gate records.
///
/// Instance-level diagnostics: the chain providers (and their daily quotas) are
/// shared infrastructure, so the rows carry no per-account or per-operator data
/// and any operator on the instance may read them. Each row is one
/// `(provider, network, UTC day)` bucket with the requests issued to the
/// provider and the requests the local egress budget denied. A non-zero denied
/// count means the runaway backstop fired and is itself worth investigating. A
/// pure cached read: no provider is called.
async fn chain_provider_usage_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(params): Query<ProviderUsageParams>,
) -> Response {
    let trace_id = new_trace_id();
    if let Err(resp) = authorize_operator(&state, &headers, trace_id).await {
        return resp;
    }

    let days = params.days.unwrap_or(7).clamp(1, 90);
    let rows: Vec<(String, String, chrono::NaiveDate, i64, i64)> = match sqlx::query_as(
        "SELECT provider, network, day, request_count, denied_count \
         FROM cw_core.chain_provider_request_day \
         WHERE day > (now() AT TIME ZONE 'utc')::date - $1::int \
         ORDER BY day DESC, provider, network",
    )
    .bind(days)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };

    let data: Vec<Value> = rows
        .into_iter()
        .map(|(provider, network, day, request_count, denied_count)| {
            json!({
                "provider": provider,
                "network": network,
                "day": day.to_string(),
                "request_count": request_count,
                "denied_count": denied_count,
            })
        })
        .collect();
    list_envelope(StatusCode::OK, trace_id, data)
}

// ---------------------------------------------------------------------------
// Live FX snapshot.
// ---------------------------------------------------------------------------

/// The number of bytes in a mebibyte, the unit the per-MiB storage price is shown
/// in: a per-byte price is too small to read, while a per-MiB price lands in the
/// human-legible cents-to-dollars range.
const BYTES_PER_MIB: i64 = 1_048_576;

/// `GET /control/v1/pricing/fx` — the live FX snapshot the gateway prices every
/// publish from, plus how fresh it is.
///
/// Surfaces the newest `cw_core.fx_rate` row (the FX refresh loop is the only
/// writer) so an operator can see the conversion rates a quote is built on and
/// catch a stale or wrong oracle BEFORE it mis-prices users. The staleness verdict
/// uses the SAME freshness ceiling the live pricing seam refuses a quote past, so
/// the console and the quote path agree on when a snapshot has gone stale.
///
/// A pure cached-row read: no provider or network call is made (the refresh loop is
/// the only oracle caller). When no snapshot exists yet (cold start, before the
/// refresh loop has written its first row) the response reports `available: false`
/// with `stale: true` rather than erroring — the absence is itself the operator
/// signal that pricing is not yet live.
async fn pricing_fx_route(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    let trace_id = new_trace_id();
    if let Err(resp) = authorize_operator(&state, &headers, trace_id).await {
        return resp;
    }

    let ceiling = state.config.fx_freshness_ceiling_seconds;
    let margin_pct = state.config.operator_default_margin_pct;

    // The newest snapshot, or none on a cold start before the refresh loop has
    // written its first row. A pure cached read; no oracle is consulted.
    let row: Option<(i64, i64, chrono::DateTime<chrono::Utc>, String)> = match sqlx::query_as(
        "SELECT ada_usd_micros, ar_usd_per_byte_femto, fetched_at, source \
         FROM cw_core.fx_rate ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    {
        Ok(row) => row,
        Err(e) => return engine_error(&state.config, trace_id, &e.into()),
    };

    let Some((ada_usd_micros, ar_usd_per_byte_femto, fetched_at, source)) = row else {
        // No snapshot yet: report unavailable rather than 500. The absence is the
        // operator signal that live pricing has not started; treat it as maximally
        // stale so the console flags it red.
        return json_response(
            StatusCode::OK,
            trace_id,
            json!({
                "available": false,
                "stale": true,
                "freshness_ceiling_seconds": ceiling,
                "operator_default_margin_pct": margin_pct.to_string(),
            }),
        );
    };

    // The age of the snapshot, clamped at zero so a clock skew never reports a
    // negative age. The staleness verdict uses the same ceiling the quote path
    // refuses past, so the console and the pricing seam agree.
    let age_seconds = (chrono::Utc::now() - fetched_at).num_seconds().max(0);
    let stale = age_seconds > ceiling;

    // The per-MiB storage price, derived from the stored femto-per-byte value
    // (USD x 1e15 per byte): femto * BYTES_PER_MIB / 1e15. Computed in Decimal so the
    // displayed dollar figure is exact, not float-rounded. Formatted to six decimal
    // places — enough to show a sub-cent per-MiB storage price without trailing noise.
    let ar_usd_per_mib = (rust_decimal::Decimal::from(ar_usd_per_byte_femto)
        * rust_decimal::Decimal::from(BYTES_PER_MIB)
        / rust_decimal::Decimal::from(1_000_000_000_000_000_i64))
    .round_dp(6)
    .to_string();

    json_response(
        StatusCode::OK,
        trace_id,
        json!({
            "available": true,
            "ada_usd_micros": ada_usd_micros,
            "ar_usd_per_byte_femto": ar_usd_per_byte_femto,
            "ar_usd_per_mib": ar_usd_per_mib,
            "fetched_at": fetched_at,
            "age_seconds": age_seconds,
            "source": source,
            "freshness_ceiling_seconds": ceiling,
            "stale": stale,
            "operator_default_margin_pct": margin_pct.to_string(),
        }),
    )
}

// ---------------------------------------------------------------------------
// Webhook health.
// ---------------------------------------------------------------------------

/// `GET /control/v1/webhooks/health` — the per-endpoint webhook health summary
/// across every subscription under the operator.
///
/// Operator-scoped: it covers the operator's own firehose subscriptions and every
/// account-scoped subscription under an account the operator owns. For each it
/// surfaces the failure population (dead/pending deliveries, the oldest pending
/// instants, the auto-disable accumulator, the last success) so a degrading or dead
/// endpoint is observable without scanning its deliveries list. Endpoints sort
/// worst-first. A read of the live `webhook_health` view: cached aggregate only, no
/// delivery is attempted.
async fn webhook_health_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = principal
        .operator_id()
        .expect("operator principal carries an operator id");
    let limit = clamp_limit(params.limit);

    let summaries = match queries::webhook_health(&state.pool, operator_id, limit).await {
        Ok(s) => s,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let data = summaries
        .into_iter()
        .map(|h| {
            json!({
                "endpoint_id": h.endpoint_id,
                "scope_kind": h.scope_kind,
                "status": h.status,
                "consecutive_failures": h.consecutive_failures,
                "last_success_at": h.last_success_at,
                "dead_deliveries": h.dead_deliveries,
                "pending_deliveries": h.pending_deliveries,
                "oldest_pending_due": h.oldest_pending_due,
                "oldest_pending_at": h.oldest_pending_at,
            })
        })
        .collect();
    list_envelope(StatusCode::OK, trace_id, data)
}

// ---------------------------------------------------------------------------
// Webhook firehose (operator-scoped subscriptions).
// ---------------------------------------------------------------------------

/// The default page size for the operator deliveries list.
const DEFAULT_DELIVERY_LIMIT: i64 = 50;

/// The maximum page size a caller may request for the deliveries list.
const MAX_DELIVERY_LIMIT: i64 = 200;

/// Resolve the webhook seam or return the feature-unavailable problem.
///
/// A deployment that has not enabled webhooks (no secret-wrap data key) leaves the
/// seam `None`; the operator firehose routes then report `webhooks-disabled` rather
/// than minting a secret they cannot seal. Mirrors the data plane's gate so both
/// arms behave identically when webhooks are off.
#[allow(clippy::result_large_err)]
fn require_webhook(
    state: &ControlState,
    trace_id: Uuid,
) -> std::result::Result<&WebhookState, Response> {
    state.webhook.as_ref().ok_or_else(|| {
        Problem::of(
            "webhooks-disabled",
            "webhook subscriptions are not enabled on this deployment",
        )
        .into_response_with(&state.config.problem_type_base, trace_id)
    })
}

/// The `POST /control/v1/webhooks` request body.
#[derive(Deserialize)]
struct CreateWebhookBody {
    /// The HTTPS delivery target.
    url: String,
    /// The wire event names to deliver; omitted/empty = all.
    #[serde(default)]
    enabled_events: Vec<String>,
    /// An optional human label.
    #[serde(default)]
    label: Option<String>,
}

/// The `PATCH /control/v1/webhooks/{id}` request body. Every field is optional; an
/// absent field is left untouched. A JSON `null` `label` clears it.
#[derive(Deserialize)]
struct PatchWebhookBody {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    enabled_events: Option<Vec<String>>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_label")]
    label: OptionalLabel,
}

/// A tri-state PATCH label: absent (leave), present-null (clear), present-value
/// (set).
#[derive(Default)]
enum OptionalLabel {
    /// The field was absent from the body.
    #[default]
    Absent,
    /// The field was present and null (clear it).
    Null,
    /// The field was present with a value (set it).
    Value(String),
}

/// Deserialize a present `label` as `Null` or `Value`; an absent key stays `Absent`
/// via `#[serde(default)]` on the field.
fn deserialize_optional_label<'de, D>(
    deserializer: D,
) -> std::result::Result<OptionalLabel, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(match opt {
        Some(v) => OptionalLabel::Value(v),
        None => OptionalLabel::Null,
    })
}

/// The query parameters of the operator deliveries list (page size only).
#[derive(Deserialize)]
struct DeliveryListParams {
    limit: Option<i64>,
}

/// Validate every requested event name against the published wire vocabulary,
/// returning the (possibly empty) filter on success.
#[allow(clippy::result_large_err)]
fn validate_webhook_events(
    config: &ControlConfig,
    trace_id: Uuid,
    requested: &[String],
) -> std::result::Result<Vec<String>, Response> {
    for name in requested {
        if !is_wire_event_name(name) {
            return Err(Problem::of(
                "invalid-event-filter",
                format!("{name:?} is not a published wire event type"),
            )
            .into_response_with(&config.problem_type_base, trace_id));
        }
    }
    Ok(requested.to_vec())
}

/// Validate a delivery URL through the SDK's SSRF guard (blocking DNS resolution on
/// a blocking task). Maps every unsafe reason onto the single `invalid-webhook-url`
/// problem so a caller cannot use the distinct reasons as a network-probe oracle.
#[allow(clippy::result_large_err)]
async fn validate_webhook_url(
    config: &ControlConfig,
    trace_id: Uuid,
    webhook: &WebhookState,
    url: &str,
) -> std::result::Result<(), Response> {
    let url = url.to_string();
    // The knobs reach the guard through the one mapping shared with the delivery
    // worker (`EgressConfig::assert_options`), where they stay independent axes:
    // `allow_insecure_http` never loosens the SSRF range-block.
    let egress = webhook.egress_config();
    let result = tokio::task::spawn_blocking(move || {
        assert_webhook_url_safe(&url, &egress.assert_options()).map(|_| ())
    })
    .await;

    let base = &config.problem_type_base;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(unsafe_url)) => Err(webhook_url_problem(base, trace_id, &unsafe_url)),
        Err(_) => Err(Problem::of("service-unavailable", "URL validation failed")
            .into_response_with(base, trace_id)),
    }
}

/// Map an SSRF-guard rejection onto the `invalid-webhook-url` problem. The human
/// detail names the reason; the machine code stays one value so the distinct reasons
/// are not a probe oracle.
fn webhook_url_problem(base: &str, trace_id: Uuid, err: &WebhookUrlUnsafeError) -> Response {
    Problem::of(
        "invalid-webhook-url",
        format!("delivery URL rejected: {}", err.reason.as_str()),
    )
    .into_response_with(base, trace_id)
}

/// The 404 a webhook firehose route returns for an absent / cross-operator /
/// soft-deleted subscription, shaped like every other control not-found so a caller
/// cannot probe for another operator's endpoints.
fn webhook_not_found(config: &ControlConfig, trace_id: Uuid) -> Response {
    Problem::of("not-found", "no such webhook subscription")
        .into_response_with(&config.problem_type_base, trace_id)
}

/// The metadata projection of an operator firehose subscription (fingerprint only,
/// never the secret).
fn webhook_view_json(view: &EndpointView) -> Value {
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

/// The projection of one delivery row the operator deliveries list returns (the
/// frozen body is omitted: large, and it is what the receiver already received).
fn webhook_delivery_json(view: &DeliveryView) -> Value {
    json!({
        "id": view.id.to_string(),
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

/// The create response: the row metadata plus the one-time plaintext secret.
fn webhook_created_json(created: &CreatedEndpoint) -> Value {
    json!({
        "id": created.id.to_string(),
        "url": created.url,
        "enabled_events": created.enabled_events,
        "status": created.status.as_str(),
        "label": created.label,
        "created_at": created.created_at.to_rfc3339(),
        // The signing secret, returned exactly once. It is never retrievable again;
        // only its fingerprint appears in later reads.
        "secret": created.secret,
    })
}

/// The rotate-secret response: the successor secret shown once plus both active
/// fingerprints (the window is now open).
fn webhook_rotated_json(rotated: &RotatedSecret) -> Value {
    json!({
        "id": rotated.id.to_string(),
        "secret_fp": hex::encode(&rotated.secret_fp),
        "secret_next_fp": hex::encode(&rotated.secret_next_fp),
        // The successor signing secret, returned exactly once.
        "secret_next": rotated.secret_next,
    })
}

/// `POST /control/v1/webhooks` — register an operator-scoped firehose subscription.
///
/// Requires operator authority. Validates the URL through the SSRF guard and the
/// event filter against the published wire vocabulary, mints + seals a signing
/// secret, and returns the secret exactly once (201). The firehose receives every
/// event under the operator (across all its accounts plus its operator-plane-only
/// subjects), so this is the wrapper's drive-everything subscription.
async fn create_webhook_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    body: Option<Json<CreateWebhookBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let webhook = match require_webhook(&state, trace_id) {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let Some(Json(body)) = body else {
        return Problem::of("invalid-body", "a webhook body is required")
            .into_response_with(&state.config.problem_type_base, trace_id);
    };

    let enabled_events =
        match validate_webhook_events(&state.config, trace_id, &body.enabled_events) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Err(resp) = validate_webhook_url(&state.config, trace_id, webhook, &body.url).await {
        return resp;
    }

    let input = NewEndpoint {
        scope: EndpointScope::Operator(operator_id),
        url: body.url,
        enabled_events,
        label: body.label,
    };
    let created =
        match registration::create_endpoint(&state.pool, webhook.secret_wrap(), &input).await {
            Ok(c) => c,
            Err(e) => return engine_error(&state.config, trace_id, &e),
        };

    record_audit_best_effort(
        &state.pool,
        &AuditEntry {
            actor_kind: ActorKind::Operator,
            actor_id: Some(operator_id),
            action: "webhook.create".into(),
            target_type: "webhook_endpoint".into(),
            target_id: created.id.to_string(),
            prev_state: None,
            new_state: Some(json!({
                "scope": "operator",
                "url": created.url,
                "enabled_events": created.enabled_events,
            })),
            request_id: Some(trace_id),
        },
    )
    .await;

    json_response(
        StatusCode::CREATED,
        trace_id,
        webhook_created_json(&created),
    )
}

/// `GET /control/v1/webhooks` — list the operator's firehose subscriptions.
///
/// Requires operator authority. Returns the metadata view of each firehose
/// subscription (fingerprint only, never the secret), newest first.
async fn list_webhooks_route(State(state): State<ControlState>, headers: HeaderMap) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_webhook(&state, trace_id) {
        return resp;
    }

    let views =
        match registration::list_endpoints(&state.pool, EndpointScope::Operator(operator_id)).await
        {
            Ok(v) => v,
            Err(e) => return engine_error(&state.config, trace_id, &e),
        };
    let data = views.iter().map(webhook_view_json).collect();
    list_envelope(StatusCode::OK, trace_id, data)
}

/// `GET /control/v1/webhooks/{id}` — read one of the operator's firehose
/// subscriptions.
///
/// Requires operator authority. A subscription owned by another operator,
/// soft-deleted, or absent returns 404 identically (no cross-operator existence
/// oracle).
async fn get_webhook_route(
    State(state): State<ControlState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_webhook(&state, trace_id) {
        return resp;
    }
    let id = match parse_id(&state.config, trace_id, &id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match registration::get_endpoint(&state.pool, EndpointScope::Operator(operator_id), id).await {
        Ok(Some(view)) => json_response(StatusCode::OK, trace_id, webhook_view_json(&view)),
        Ok(None) => webhook_not_found(&state.config, trace_id),
        Err(e) => engine_error(&state.config, trace_id, &e),
    }
}

/// `PATCH /control/v1/webhooks/{id}` — update one of the operator's firehose
/// subscriptions.
///
/// Requires operator authority. Move `status` between `active` and `paused`
/// (re-activating resets the auto-disable counter), replace the URL (re-validated
/// through the SSRF guard) or the event filter, and set/clear the label. `disabled`
/// is server-only and rejected here.
async fn patch_webhook_route(
    State(state): State<ControlState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<PatchWebhookBody>>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let webhook = match require_webhook(&state, trace_id) {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let id = match parse_id(&state.config, trace_id, &id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let body = body.map(|b| b.0).unwrap_or(PatchWebhookBody {
        status: None,
        enabled_events: None,
        url: None,
        label: OptionalLabel::Absent,
    });

    let status = match body.status.as_deref() {
        None => None,
        Some("active") => Some(EndpointStatus::Active),
        Some("paused") => Some(EndpointStatus::Paused),
        Some(other) => {
            return Problem::of(
                "validation-failed",
                format!("status must be \"active\" or \"paused\", got {other:?}"),
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
    };
    let enabled_events = match body.enabled_events {
        None => None,
        Some(list) => match validate_webhook_events(&state.config, trace_id, &list) {
            Ok(v) => Some(v),
            Err(resp) => return resp,
        },
    };
    if let Some(url) = &body.url {
        if let Err(resp) = validate_webhook_url(&state.config, trace_id, webhook, url).await {
            return resp;
        }
    }
    let label = match body.label {
        OptionalLabel::Absent => None,
        OptionalLabel::Null => Some(None),
        OptionalLabel::Value(v) => Some(Some(v)),
    };

    let patch = EndpointPatch {
        status,
        enabled_events,
        url: body.url,
        label,
    };
    match registration::patch_endpoint(
        &state.pool,
        EndpointScope::Operator(operator_id),
        id,
        &patch,
    )
    .await
    {
        Ok(EndpointChange::Changed) => {
            record_audit_best_effort(
                &state.pool,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: Some(operator_id),
                    action: "webhook.patch".into(),
                    target_type: "webhook_endpoint".into(),
                    target_id: id.to_string(),
                    prev_state: None,
                    new_state: Some(json!({ "patched": true })),
                    request_id: Some(trace_id),
                },
            )
            .await;
            // Re-read so the response reflects the persisted state.
            match registration::get_endpoint(&state.pool, EndpointScope::Operator(operator_id), id)
                .await
            {
                Ok(Some(view)) => json_response(StatusCode::OK, trace_id, webhook_view_json(&view)),
                _ => webhook_not_found(&state.config, trace_id),
            }
        }
        Ok(EndpointChange::NotFound) => webhook_not_found(&state.config, trace_id),
        Err(e) => engine_error(&state.config, trace_id, &e),
    }
}

/// `DELETE /control/v1/webhooks/{id}` — soft-delete one of the operator's firehose
/// subscriptions.
///
/// Requires operator authority. Returns 204 on a delete that took effect, 404 if no
/// such row exists for this operator (including an already-deleted row).
async fn delete_webhook_route(
    State(state): State<ControlState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_webhook(&state, trace_id) {
        return resp;
    }
    let id = match parse_id(&state.config, trace_id, &id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match registration::soft_delete_endpoint(&state.pool, EndpointScope::Operator(operator_id), id)
        .await
    {
        Ok(EndpointChange::Changed) => {
            record_audit_best_effort(
                &state.pool,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: Some(operator_id),
                    action: "webhook.delete".into(),
                    target_type: "webhook_endpoint".into(),
                    target_id: id.to_string(),
                    prev_state: None,
                    new_state: Some(json!({ "deleted": true })),
                    request_id: Some(trace_id),
                },
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(EndpointChange::NotFound) => webhook_not_found(&state.config, trace_id),
        Err(e) => engine_error(&state.config, trace_id, &e),
    }
}

/// `POST /control/v1/webhooks/{id}/rotate-secret` — open a secret rotation window.
///
/// Requires operator authority. Mints a successor signing secret, seals it at rest,
/// and returns the plaintext exactly once. While the window is open the delivery
/// worker dual-signs (one MAC per active secret), so a receiver validates with
/// either; the operator commits once its fleet is cut over.
async fn rotate_webhook_secret_route(
    State(state): State<ControlState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let webhook = match require_webhook(&state, trace_id) {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let id = match parse_id(&state.config, trace_id, &id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match registration::rotate_secret(
        &state.pool,
        webhook.secret_wrap(),
        EndpointScope::Operator(operator_id),
        id,
    )
    .await
    {
        Ok(Some(rotated)) => {
            record_audit_best_effort(
                &state.pool,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: Some(operator_id),
                    action: "webhook.rotate-secret".into(),
                    target_type: "webhook_endpoint".into(),
                    target_id: id.to_string(),
                    prev_state: None,
                    new_state: Some(json!({ "rotation_window": "open" })),
                    request_id: Some(trace_id),
                },
            )
            .await;
            json_response(StatusCode::OK, trace_id, webhook_rotated_json(&rotated))
        }
        Ok(None) => webhook_not_found(&state.config, trace_id),
        Err(e) => engine_error(&state.config, trace_id, &e),
    }
}

/// `POST /control/v1/webhooks/{id}/rotate-secret/commit` — close a rotation window.
///
/// Requires operator authority. Promotes the successor secret to primary and clears
/// the successor, so the delivery worker drops back to a single `v1`. A commit with
/// no open window is 404 (nothing to promote), so a redundant commit never clears
/// the only secret.
async fn commit_webhook_rotation_route(
    State(state): State<ControlState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_webhook(&state, trace_id) {
        return resp;
    }
    let id = match parse_id(&state.config, trace_id, &id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match registration::commit_rotation(&state.pool, EndpointScope::Operator(operator_id), id).await
    {
        Ok(EndpointChange::Changed) => {
            record_audit_best_effort(
                &state.pool,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: Some(operator_id),
                    action: "webhook.rotate-secret.commit".into(),
                    target_type: "webhook_endpoint".into(),
                    target_id: id.to_string(),
                    prev_state: Some(json!({ "rotation_window": "open" })),
                    new_state: Some(json!({ "rotation_window": "closed" })),
                    request_id: Some(trace_id),
                },
            )
            .await;
            match registration::get_endpoint(&state.pool, EndpointScope::Operator(operator_id), id)
                .await
            {
                Ok(Some(view)) => json_response(StatusCode::OK, trace_id, webhook_view_json(&view)),
                _ => webhook_not_found(&state.config, trace_id),
            }
        }
        Ok(EndpointChange::NotFound) => webhook_not_found(&state.config, trace_id),
        Err(e) => engine_error(&state.config, trace_id, &e),
    }
}

/// `GET /control/v1/webhooks/{id}/deliveries` — list a firehose subscription's
/// deliveries (the dead-letter view).
///
/// Requires operator authority. Returns every delivery state (`pending`,
/// `delivered`, `failed`), newest first, so the operator sees both what is in flight
/// and what was dropped after exhausting attempts. The endpoint is the single
/// ownership gate: a foreign, soft-deleted, or absent endpoint reports 404
/// identically.
async fn webhook_deliveries_route(
    State(state): State<ControlState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<DeliveryListParams>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_webhook(&state, trace_id) {
        return resp;
    }
    let id = match parse_id(&state.config, trace_id, &id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let limit = params
        .limit
        .unwrap_or(DEFAULT_DELIVERY_LIMIT)
        .clamp(1, MAX_DELIVERY_LIMIT);

    match registration::list_deliveries(
        &state.pool,
        EndpointScope::Operator(operator_id),
        id,
        limit,
    )
    .await
    {
        Ok(Some(views)) => {
            let data = views.iter().map(webhook_delivery_json).collect();
            list_envelope(StatusCode::OK, trace_id, data)
        }
        Ok(None) => webhook_not_found(&state.config, trace_id),
        Err(e) => engine_error(&state.config, trace_id, &e),
    }
}

/// `POST /control/v1/webhooks/{id}/deliveries/{delivery_id}/retry` — redrive a
/// failed firehose delivery.
///
/// Requires operator authority. Re-arms a `failed` (dead-letter) delivery to
/// `pending` with an immediate `next_attempt_at`, leaving `attempts` so the prior
/// failures stand and the redelivery reuses the same `Webhook-Id` and body. A
/// delivery not under an owned endpoint is 404; one that exists but is not `failed`
/// is 422.
async fn retry_webhook_delivery_route(
    State(state): State<ControlState>,
    Path((id, delivery_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_webhook(&state, trace_id) {
        return resp;
    }
    let id = match parse_id(&state.config, trace_id, &id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let delivery_id = match parse_id(&state.config, trace_id, &delivery_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match registration::retry_delivery(
        &state.pool,
        EndpointScope::Operator(operator_id),
        id,
        delivery_id,
    )
    .await
    {
        Ok(RedriveOutcome::Redriven) => {
            record_audit_best_effort(
                &state.pool,
                &AuditEntry {
                    actor_kind: ActorKind::Operator,
                    actor_id: Some(operator_id),
                    action: "webhook.delivery.redrive".into(),
                    target_type: "webhook_delivery".into(),
                    target_id: delivery_id.to_string(),
                    prev_state: Some(json!({ "state": "failed" })),
                    new_state: Some(json!({ "state": "pending" })),
                    request_id: Some(trace_id),
                },
            )
            .await;
            json_response(
                StatusCode::OK,
                trace_id,
                json!({ "id": delivery_id.to_string(), "state": "pending" }),
            )
        }
        Ok(RedriveOutcome::NotFound) => webhook_not_found(&state.config, trace_id),
        Ok(RedriveOutcome::NotFailed) => Problem::of(
            "validation-failed",
            "only a failed delivery can be redriven",
        )
        .into_response_with(&state.config.problem_type_base, trace_id),
        Err(e) => engine_error(&state.config, trace_id, &e),
    }
}

// ---------------------------------------------------------------------------
// Audit.
// ---------------------------------------------------------------------------

/// Query parameters for the audit read.
#[derive(Deserialize)]
struct AuditParams {
    actor_kind: Option<String>,
    action: Option<String>,
    target_type: Option<String>,
    target_id: Option<String>,
    limit: Option<i64>,
}

/// `GET /control/v1/audit` — the filterable administrative audit log.
async fn list_audit_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(params): Query<AuditParams>,
) -> Response {
    let trace_id = new_trace_id();
    let principal = match authorize_operator(&state, &headers, trace_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let operator_id = match operator_binding(&state.config, trace_id, &principal) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let actor_kind = match params.actor_kind.as_deref() {
        None => None,
        Some("operator") => Some(ActorKind::Operator),
        Some("account") => Some(ActorKind::Account),
        Some("system") => Some(ActorKind::System),
        Some(_) => {
            return Problem::of(
                "validation-failed",
                "actor_kind must be operator, account, or system",
            )
            .into_response_with(&state.config.problem_type_base, trace_id)
        }
    };

    let query = AuditQuery {
        operator_id,
        actor_kind,
        action: params.action,
        target_type: params.target_type,
        target_id: params.target_id,
        limit: clamp_limit(params.limit),
    };

    let rows = match audit::list(&state.pool, &query).await {
        Ok(r) => r,
        Err(e) => return engine_error(&state.config, trace_id, &e),
    };
    let data = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "actor_kind": r.actor_kind,
                "actor_id": r.actor_id,
                "action": r.action,
                "target_type": r.target_type,
                "target_id": r.target_id,
                "prev_state": r.prev_state,
                "new_state": r.new_state,
                "request_id": r.request_id,
                "occurred_at": r.occurred_at,
            })
        })
        .collect();
    list_envelope(StatusCode::OK, trace_id, data)
}

impl ActorKind {
    /// The audit actor class a principal records its actions under.
    fn from_principal(principal: &Principal) -> Self {
        if principal.is_operator() {
            ActorKind::Operator
        } else {
            ActorKind::Account
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_control_routes_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for entry in SERVED_CONTROL_ROUTES {
            assert!(
                seen.insert(entry),
                "duplicate served control route {entry:?}"
            );
        }
    }

    #[test]
    fn clamp_limit_bounds_the_page_size() {
        assert_eq!(clamp_limit(None), DEFAULT_LIST_LIMIT);
        assert_eq!(clamp_limit(Some(0)), 1);
        assert_eq!(clamp_limit(Some(10_000)), MAX_LIST_LIMIT);
        assert_eq!(clamp_limit(Some(50)), 50);
    }
}
