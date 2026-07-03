//! The gateway application's library surface.
//!
//! The binary (`main.rs`) is a thin shim over this crate: it wires the tracing
//! subscriber, loads the configuration, migrates, builds the supervised runtime,
//! and runs it under signal-driven shutdown. Exposing the assembly here (rather
//! than burying it inside `main.rs`) lets an integration test boot the whole
//! plane against a real Postgres and assert it starts, registers its scheduled
//! work, and stops cleanly.
//!
//! When the configuration carries an `[http]` section the binary also serves the
//! engine's data-plane API beside the background plane, under the same supervised
//! shutdown; without it the background plane runs alone.

pub mod admin;
pub mod assembly;
pub mod bootstrap;
pub mod config;
pub mod handlers;
pub mod keyring;
pub mod observability;
pub mod pricing;
pub mod storage_bootstrap;

/// The bundled static admin UI, served at `/admin` when enabled. A no-build,
/// dependency-free HTML+vanilla-JS page that is a thin HTTP client of the control
/// plane (the operator pastes a token; the page calls `/control/v1/*`).
pub const ADMIN_UI_HTML: &str = include_str!("assets/admin.html");

/// Mount the static admin UI onto a router at `/admin`.
///
/// Factored out so the binary and the integration test serve the exact same route
/// from the exact same handler: the test then proves the contract the binary
/// actually ships. The page itself carries no server-side auth (it is a thin HTTP
/// client of the control plane; the operator pastes a token that the page presents
/// on every `/control/v1/*` call), so this route serves the HTML unconditionally
/// when mounted. A deployment that does not want the UI simply never mounts it
/// (the binary gates the mount on `admin_ui_enabled`).
pub fn mount_admin_ui(router: axum::Router) -> axum::Router {
    router.route("/admin", axum::routing::get(serve_admin_ui))
}

/// Serve the bundled static admin UI page as `text/html`.
///
/// Sent with `Cache-Control: no-store` because the page is an embedded asset with
/// no validators (no ETag, no Last-Modified): without it browsers heuristically
/// cache the document and an operator keeps driving a stale console after a
/// gateway upgrade.
async fn serve_admin_ui() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        ADMIN_UI_HTML,
    )
        .into_response()
}
