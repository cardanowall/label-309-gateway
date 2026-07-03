//! The interactive API reference UI, served fully offline for both planes.
//!
//! A self-hosted product must not reach a third-party CDN at view time, so the
//! renderer bundle is vendored into the binary and served from the gateway
//! itself. Both the data plane and the control plane render the same shell over
//! their own sibling `openapi.json`; the shell and the bundle are plane-agnostic
//! (they carry no secret and reference only same-origin relative URLs), so one
//! module serves both.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

/// The vendored Scalar API Reference standalone bundle, embedded so the docs page
/// loads its renderer from this gateway instead of a public CDN.
///
/// Upstream: `@scalar/api-reference` 1.61.0 (MIT); the bundle's own license banner
/// is preserved verbatim at the head of the asset. Refresh it by replacing the
/// asset file with the same package version — never by fetching a different build
/// at runtime.
pub const SCALAR_STANDALONE_JS: &str = include_str!("assets/scalar-standalone.js");

/// The bare suffix, relative to a plane's `…/docs` page, that serves the vendored
/// bundle. Resolved by the browser against the page URL (`…/docs` → `…/docs/scalar.js`),
/// so the shell hardcodes no version segment and names no external origin.
const SCALAR_JS_SUFFIX: &str = "docs/scalar.js";

/// The Content-Security-Policy the docs page is served under.
///
/// The offline guarantee cannot rest on the renderer's own configuration: the
/// vendored Scalar bundle carries hosted-service integrations (an "Ask AI" agent
/// and a public-API registry search) that fetch `api.scalar.com` on load,
/// regardless of the `createApiReference` options. `connect-src 'self'` closes
/// that at the browser: every fetch/XHR the page can make is pinned to this
/// gateway's own origin, so the registry calls are refused before they leave the
/// browser and no third party ever learns the docs were opened. The remaining
/// directives are the minimum the vendored renderer needs to paint from this
/// origin alone — its inline bootstrap and injected styles (`'unsafe-inline'`),
/// its lazily-instantiated WebAssembly (`'wasm-unsafe-eval'`, which permits WASM
/// compilation without opening general `eval`), and its inline `data:` icons —
/// while `object-src`, `base-uri`, and `frame-ancestors` shut the usual injection
/// and clickjacking vectors. The single-shot "Try it" requests still reach this
/// gateway because its server URL is same-origin (`/api/v1`, `/control/v1`).
const DOCS_CSP: &str = "default-src 'self'; \
     script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     font-src 'self' data:; \
     connect-src 'self'; \
     object-src 'none'; \
     base-uri 'none'; \
     frame-ancestors 'none'";

/// Render the interactive reference page for a plane.
///
/// The shell loads the vendored bundle and points it at the sibling `openapi.json`
/// (resolved relative to the page URL, so the version segment is never hardcoded).
/// `withDefaultFonts: false` keeps the renderer from fetching its default webfonts
/// from an external origin, and the `DOCS_CSP` header the response carries pins every
/// network call the page can make to this gateway's own origin — so the page
/// reaches nothing but this gateway even though the vendored bundle ships hosted
/// integrations that would otherwise phone home. Served `noindex,nofollow` (an
/// X-Robots-Tag header plus a robots meta tag) so a crawler never indexes the
/// rendered HTML as a surface distinct from the OpenAPI document it renders.
pub fn reference_page(title: &str) -> Response {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>{title}</title>\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex, nofollow\">\
         </head><body><div id=\"app\"></div>\
         <script src=\"{SCALAR_JS_SUFFIX}\"></script>\
         <script>window.addEventListener('DOMContentLoaded',function(){{\
         window.Scalar.createApiReference('#app',{{url:'openapi.json',theme:'default',\
         layout:'modern',darkMode:true,withDefaultFonts:false}});}});</script>\
         </body></html>"
    );
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                header::HeaderName::from_static("x-robots-tag"),
                "noindex, nofollow",
            ),
            (header::CONTENT_SECURITY_POLICY, DOCS_CSP),
        ],
        html,
    )
        .into_response()
}

/// Serve the vendored renderer bundle.
///
/// Long-lived caching: the bytes change only when the gateway binary is rebuilt
/// against a new vendored bundle, so a day-long cache spares every reader a 3.5 MiB
/// re-fetch while still self-healing within a day of an upgrade.
pub fn scalar_js() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        SCALAR_STANDALONE_JS,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_reference_page_is_offline_and_noindex() {
        // The served shell must reach only this gateway's own origin — no CDN, no
        // external webfont host — and carry both noindex signals.
        let resp = reference_page("API reference");
        assert_eq!(
            resp.headers()
                .get("x-robots-tag")
                .and_then(|v| v.to_str().ok()),
            Some("noindex, nofollow"),
            "the X-Robots-Tag header rides the docs page"
        );
        // The offline guarantee is enforced by the CSP, not by the shell markup:
        // the vendored renderer ships hosted integrations that fetch a third-party
        // origin on load whatever the shell says, so `connect-src 'self'` is what
        // actually keeps the page from phoning home. Asserting the shell alone (as
        // this test once did) passed even while the rendered page leaked requests.
        let csp = resp
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok())
            .expect("the docs page carries a Content-Security-Policy");
        assert!(
            csp.contains("connect-src 'self'"),
            "the CSP pins every network call to this gateway's own origin, got: {csp}"
        );
        assert!(
            csp.contains("default-src 'self'"),
            "the CSP defaults every fetch directive to this origin, got: {csp}"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read the docs body");
        let html = String::from_utf8(bytes.to_vec()).expect("docs body is UTF-8");
        assert!(
            html.contains("<meta name=\"robots\" content=\"noindex, nofollow\">"),
            "the robots meta tag rides the page"
        );
        assert!(
            !html.contains("http://") && !html.contains("https://"),
            "the served HTML names no external origin, got: {html}"
        );
        assert!(
            html.contains("withDefaultFonts:false"),
            "the renderer is configured not to fetch external webfonts"
        );
        assert!(
            html.contains("src=\"docs/scalar.js\""),
            "the shell loads the vendored bundle from this gateway"
        );
    }

    #[test]
    fn the_vendored_bundle_is_embedded_with_its_license_banner() {
        // The bundle ships from the binary (offline), with its upstream MIT banner
        // preserved so attribution travels with the served asset.
        assert!(
            SCALAR_STANDALONE_JS.len() > 1_000_000,
            "the standalone bundle is embedded, not a stub"
        );
        assert!(
            SCALAR_STANDALONE_JS.contains("@scalar/api-reference 1.61.0"),
            "the upstream package and version banner is preserved"
        );
    }
}
