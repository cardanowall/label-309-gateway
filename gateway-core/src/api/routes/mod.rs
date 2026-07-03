//! The data-plane route handlers and the router factory.
//!
//! [`build`] assembles every data-plane route over an [`AppState`] into one axum
//! [`Router`], with each resource path written ONCE as a bare suffix (e.g.
//! `/poe/quote`, `/records`). The version segment is not written here: it is
//! applied in exactly one place — [`crate::api::router`] nests this router under
//! `/api/v1` — so the served surface is `/api/v1/*` while the route declarations
//! stay version-free. A Tier-2 embedder merges the nested router, and the binary
//! serves it directly.
//!
//! Routes are grouped by resource:
//!
//! - [`meta`] — health, the error registry, the OpenAPI document, the docs page.
//! - [`quote`] — the publish-cost quote.
//! - [`publish`] — single and batch publish.
//! - [`uploads`] — streamed content uploads to the storage backend.
//! - [`records`] — the indexer read surface (list, count, single-record read).
//! - [`account`] — the balance read and the ledger history list.
//! - SSE streams (PoE events, balance events) live in [`crate::api::sse`].
//!
//! The handlers project engine state onto the byte-stable wire shapes via
//! [`crate::api::wire`] and surface errors as RFC 7807 problems via
//! [`crate::api::problem`].

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use axum::Router;
use tower_http::timeout::TimeoutLayer;

use crate::api::state::AppState;

pub mod account;
pub mod guard;
pub mod meta;
pub mod publish;
pub mod quote;
pub mod records;
pub mod sessions;
pub mod uploads;
pub mod webhooks;

/// The set of route templates the router serves, as `(method, path)` pairs,
/// written as BARE suffixes (no version prefix — the router nests them under
/// `/api/v1`).
///
/// This is the in-code inventory the route-coverage test cross-checks against the
/// served OpenAPI document: every entry here must exist in the spec (whose paths
/// are likewise bare, with the version carried by `servers`), and every spec
/// path/method must be served. Keeping the list explicit (rather than reflecting
/// over the axum router, which exposes no path inventory) makes the contract
/// auditable in one place.
pub const SERVED_ROUTES: &[(&str, &str)] = &[
    ("post", "/poe/quote"),
    ("post", "/poe/publish"),
    ("post", "/poe/publish-batch"),
    ("post", "/poe/uploads"),
    ("get", "/poe/uploads/attempts/{attempt_id}"),
    ("post", "/poe/uploads/sessions"),
    ("put", "/poe/uploads/sessions/{sid}/chunks/{index}"),
    ("get", "/poe/uploads/sessions/{sid}"),
    ("post", "/poe/uploads/sessions/{sid}/complete"),
    ("delete", "/poe/uploads/sessions/{sid}"),
    ("get", "/poe/events/{poe_id}"),
    ("get", "/records"),
    ("get", "/records/count"),
    ("get", "/records/{tx_hash}"),
    ("get", "/account/balance"),
    ("get", "/account/balance/events"),
    ("get", "/account/ledger"),
    ("post", "/webhooks"),
    ("get", "/webhooks"),
    ("get", "/webhooks/{id}"),
    ("patch", "/webhooks/{id}"),
    ("delete", "/webhooks/{id}"),
    ("get", "/webhooks/{id}/deliveries"),
    ("post", "/webhooks/{id}/deliveries/{delivery_id}/retry"),
    ("post", "/webhooks/{id}/rotate-secret"),
    ("post", "/webhooks/{id}/rotate-secret/commit"),
    ("get", "/health"),
    ("get", "/errors"),
    ("get", "/docs"),
    ("get", "/docs/scalar.js"),
    ("get", "/openapi.json"),
];

/// Build the data-plane router over a resolved [`AppState`].
///
/// Every route is declared with a bare suffix; the version segment is applied by
/// the caller ([`crate::api::router`]) via a single `nest("/api/v1", …)`.
pub fn build(state: AppState) -> Router {
    // The content-ingress routes carry multi-gigabyte bodies by design (content is
    // billed per byte; the only size caps are the operator-tunable DoS backstops in
    // the upload limits). axum ships a built-in 2 MiB default body limit on every
    // body-buffering extractor — including the `Multipart` the single-shot route
    // uses — which would silently override the gateway's own ceilings, so those
    // routes install an explicit limit derived from the configured ceilings. Every
    // other route keeps the framework default: their bodies are small JSON/CBOR
    // declarations for which 2 MiB is already generous.
    let uploads_body_limit = state.config.upload_limits.request_body_limit();
    let chunk_body_limit = state
        .config
        .upload_session_limits
        .chunk_request_body_limit();
    let request_timeout = state.config.request_timeout;

    // The streaming surfaces, exempt from the global request timeout. Each is
    // long-lived (or long-running) BY DESIGN and carries its own bound, so a
    // wall-clock ceiling sized for a quick handler would cut it off mid-work:
    //
    // - The two SSE streams live until the client disconnects; their concurrency
    //   is bounded by the live-stream caps, not a duration.
    // - The single-shot upload and the chunk PUT ingest bodies whose only size
    //   caps are the multi-GiB operator backstops — a legitimate client on a slow
    //   link streams for far longer than any sane request ceiling. The bytes are
    //   bounded by the body limits, and the backend POST by the storage
    //   `upload_timeout`.
    // - Session `complete` hashes a file of up to the per-file ceiling and runs
    //   the bounded backend store; its deadline is the storage `upload_timeout`,
    //   which an operator sizes independently of (and above) the request ceiling.
    let streaming = Router::new()
        .route(
            "/poe/uploads",
            post(uploads::uploads).layer(DefaultBodyLimit::max(uploads_body_limit)),
        )
        .route(
            "/poe/uploads/sessions/{sid}/chunks/{index}",
            put(sessions::put_chunk).layer(DefaultBodyLimit::max(chunk_body_limit)),
        )
        .route(
            "/poe/uploads/sessions/{sid}/complete",
            post(sessions::complete),
        )
        .route("/poe/events/{poe_id}", get(crate::api::sse::poe_events))
        .route(
            "/account/balance/events",
            get(crate::api::sse::balance_events),
        );

    // Every other route is an ordinary request/response exchange and runs under
    // the global request timeout, so a drip-fed body, a wedged dependency, or a
    // pathological read frees its connection at the ceiling (a 408) instead of
    // pinning it for the client's lifetime.
    let timed = Router::new()
        // Public, unauthenticated meta routes.
        .route("/health", get(meta::health))
        .route("/errors", get(meta::errors))
        .route("/docs", get(meta::docs))
        .route("/docs/scalar.js", get(meta::docs_scalar_js))
        .route("/openapi.json", get(meta::openapi))
        // PoE create surface (poe:create).
        .route("/poe/quote", post(quote::create))
        .route("/poe/publish", post(publish::publish_one))
        .route("/poe/publish-batch", post(publish::publish_batch))
        .route(
            "/poe/uploads/attempts/{attempt_id}",
            get(uploads::attempt_status),
        )
        // Resumable / chunked upload sessions (additive sub-resource, poe:create).
        .route("/poe/uploads/sessions", post(sessions::create))
        .route(
            "/poe/uploads/sessions/{sid}",
            get(sessions::status).delete(sessions::abandon),
        )
        // PoE read surface (poe:read or anonymous).
        .route("/records", get(records::list))
        .route("/records/count", get(records::count))
        .route("/records/{tx_hash}", get(records::get_one))
        // Account surface (account:read).
        .route("/account/balance", get(account::balance))
        .route("/account/ledger", get(account::ledger))
        // Webhook subscription surface (webhooks:read / webhooks:write).
        .route("/webhooks", post(webhooks::create).get(webhooks::list))
        .route(
            "/webhooks/{id}",
            get(webhooks::get_one)
                .patch(webhooks::patch)
                .delete(webhooks::delete),
        )
        .route("/webhooks/{id}/deliveries", get(webhooks::deliveries))
        .route(
            "/webhooks/{id}/deliveries/{delivery_id}/retry",
            post(webhooks::retry_delivery),
        )
        .route(
            "/webhooks/{id}/rotate-secret",
            post(webhooks::rotate_secret),
        )
        .route(
            "/webhooks/{id}/rotate-secret/commit",
            post(webhooks::commit_rotation),
        )
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ));

    timed.merge(streaming).with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_routes_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for entry in SERVED_ROUTES {
            assert!(seen.insert(entry), "duplicate served route {entry:?}");
        }
    }
}
