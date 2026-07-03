//! The HTTP data plane.
//!
//! This module is the engine's `/api/v1/*` surface: the byte-stable contract the
//! published SDKs and CLI speak. The router is built by [`router`], which an
//! embedding application can mount beside its own routes; the gateway binary
//! mounts it under the same supervised task set as the background plane.
//!
//! # Layout
//!
//! - [`state`] — the shared application state every handler is given.
//! - [`problem`] — the RFC 7807 problem+json envelope and the error registry.
//! - [`ids`] — the wire id codec (`poe_<crockford-base32-of-uuid>`).
//! - [`wire`] — the explicit projection layer mapping engine state onto the wire
//!   shapes (record status, event types, the quote/record/publish projections).
//! - `middleware` — bearer auth, the sliding-window rate limiter, and
//!   idempotent replay.
//! - `routes` — the route handlers, one module per resource group.
//! - `sse` — the durable, resumable Server-Sent Events streams.
//!
//! # Byte stability
//!
//! The wire shapes here are frozen against the published SDK deserializers. The
//! frozen `openapi.json` (served statically from this module's assets) is the
//! contract document; a route-coverage test asserts every served route exists in
//! the spec.

pub mod control;
pub mod docs;
pub mod ids;
pub mod problem;
pub mod state;
pub mod wire;

pub mod middleware;
pub mod routes;
pub mod sse;

pub use control::{
    ControlChain, ControlConfig, ControlFundingKey, ControlState, ControlStorage, ControlWalletKey,
    DefaultStorageScope, DefaultWalletScope, OPENAPI_CONTROL_JSON,
};
pub use sse::{SseLimits, SseState};
pub use state::{
    ApiConfig, AppState, StorageState, UploadSigning, WebhookState,
    DEFAULT_ANON_RATE_LIMIT_PER_MIN, DEFAULT_REQUEST_TIMEOUT_SECS,
};

/// The frozen OpenAPI 3.1 document for the core surface, served statically at
/// `/api/v1/openapi.json`. Trimmed to the data-plane routes and vendor-neutral
/// (the problem-type base, server URL, and key prefix are operator-configured).
pub const OPENAPI_JSON: &str = include_str!("assets/openapi.json");

/// Build the data-plane router over a resolved [`AppState`].
///
/// The returned router carries every `/api/v1/*` route with the middleware stack
/// (request id, auth, rate-limit, idempotency) applied per the route's needs.
/// Exported so a Tier-2 embedder can `Router::merge` it into its own app; the
/// binary serves it directly.
///
/// [`routes::build`] declares every route as a bare suffix; this factory is the
/// single place the `/api/v1` version segment is applied, via one `nest`. A v2
/// surface would be a second nest here, not a rewrite of every route literal.
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new().nest("/api/v1", routes::build(state))
}

/// Build the control-plane router over a resolved [`ControlState`].
///
/// The operator-only `/control/v1/*` surface, a separate router from the data
/// plane with its own frozen spec. The binary mounts it beside the data-plane
/// router under the same supervised task set.
pub fn control_router(state: ControlState) -> axum::Router {
    control::router(state)
}
