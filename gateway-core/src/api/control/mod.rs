//! The HTTP control plane.
//!
//! This module is the engine's `/control/v1/*` surface: the operator-only
//! administrative API that provisions accounts, mints credentials, registers
//! wallets, adjusts balances, and serves the audit log. It is a SEPARATE router
//! from the data plane ([`crate::api::routes`]) with its own frozen OpenAPI
//! document and its own route-coverage test; it never shares or extends the
//! data-plane spec. The binary mounts it beside `/api/v1`.
//!
//! # Authority model
//!
//! Authentication resolves a typed [`principal::Principal`] across three
//! credential stores (api key, access token, operator root credential). The
//! control plane's operator routes accept an operator token or root credential
//! only; its account-level routes (own keys, own token) accept an account token
//! acting on itself, or an operator acting on a named account. The data plane
//! ([`crate::api::routes::guard`]) accepts account-bound principals only and
//! rejects an operator credential, so authority can never cross between planes.
//!
//! # Layout
//!
//! - [`state`] — the shared control state and its operator-configured knobs.
//! - [`principal`] — the typed principal enum and its cross-store resolution.
//! - [`credential`] — operator root credentials and short-lived access tokens.
//! - [`keys`] — the api-key lifecycle (create / revoke / relabel).
//! - [`ledger_adjust`] — the manual operator balance adjustment.
//! - [`audit`] — the append-only administrative audit journal.
//! - [`queries`] — the operator-facing list/usage read projections.
//! - [`guard`] — per-request operator / account-scope authorization.
//! - [`routes`] — the route handlers and the control router factory.

pub mod audit;
pub mod credential;
pub mod guard;
pub mod keys;
pub mod ledger_adjust;
pub mod principal;
pub mod queries;
pub mod routes;
pub mod state;

pub use routes::SERVED_CONTROL_ROUTES;
pub use state::{
    ControlChain, ControlConfig, ControlFundingKey, ControlState, ControlStorage, ControlWalletKey,
    DefaultStorageScope, DefaultWalletScope,
};

/// The frozen OpenAPI 3.1 document for the control surface, served statically at
/// `/control/v1/openapi.json`. Separate from the data-plane document; vendor-
/// neutral (the server URL, problem-type base, and secret prefix are operator
/// config).
pub const OPENAPI_CONTROL_JSON: &str = include_str!("assets/openapi-control.json");

/// Build the control-plane router over a resolved [`ControlState`].
///
/// The returned router carries every `/control/v1/*` route with the typed-principal
/// guard applied per route (operator-only, or account-scoped). Exported so the
/// binary mounts it beside the data-plane router; an embedder may merge it too.
///
/// [`routes::build`] declares every route as a bare suffix; this factory is the
/// single place the `/control/v1` version segment is applied, via one `nest`.
pub fn router(state: ControlState) -> axum::Router {
    axum::Router::new().nest("/control/v1", routes::build(state))
}
