//! The public meta routes: health, the error registry, the OpenAPI document,
//! and the docs page. None require authentication; chain/health data is public.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use crate::api::problem::ERROR_REGISTRY;
use crate::api::state::AppState;
use crate::api::OPENAPI_JSON;

/// The crate version, surfaced as the health `version`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The tip-age threshold past which the indexer is considered stalled and health
/// degrades to 503.
const TIP_STALE_SECONDS: i64 = 600;

/// `GET /api/v1/health` — liveness with dependency status.
///
/// 200 with `status: "ok"` when the database answers and the chain tip is fresh;
/// 503 with `status: "degraded"` when the database is unreachable or the tip is
/// stale (the indexer has fallen behind). The body always carries the version,
/// the tip height/age, and the db-ok flag so an operator can see which dependency
/// degraded.
pub async fn health(State(state): State<AppState>) -> Response {
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();

    // The freshest tip across networks: the gateway runs one network per
    // deployment, so at most one row is meaningful, but MAX keeps it robust.
    let tip: Option<(i64, i64)> = sqlx::query_as(
        "SELECT tip_block_height, \
                EXTRACT(EPOCH FROM (now() - tip_observed_at))::bigint AS age \
         FROM cw_core.cardano_tip \
         ORDER BY tip_observed_at DESC LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let (tip_height, tip_age) = match tip {
        Some((h, a)) => (Some(h), Some(a)),
        None => (None, None),
    };

    let tip_stale = tip_age.map(|a| a > TIP_STALE_SECONDS).unwrap_or(false);
    let healthy = db_ok && !tip_stale;

    let body = json!({
        "status": if healthy { "ok" } else { "degraded" },
        "version": VERSION,
        // The network this deployment serves, so a client can tell a preprod
        // gateway from a mainnet one before trusting its records.
        "network": state.config.network.as_str(),
        "cardano_tip_height": tip_height,
        "cardano_tip_age_seconds": tip_age,
        "db_ok": db_ok,
    });

    let status = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    )
        .into_response()
}

/// `GET /api/v1/errors` — the machine-readable error registry.
///
/// Content-negotiated: `Accept: text/html` renders a simple documentation page,
/// anything else returns the JSON list. The `ref_url` of each entry is built from
/// the operator-configured problem-type base, so the registry's links match the
/// `type` member of an actual problem body.
pub async fn errors(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let wants_html = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);

    if wants_html {
        return errors_html(&state).into_response();
    }

    let base = state.config.problem_type_base.trim_end_matches('/');
    let data: Vec<Value> = ERROR_REGISTRY
        .iter()
        .map(|e| {
            let ref_url = if base.is_empty() {
                format!("#{}", e.code)
            } else {
                format!("{base}#{}", e.code)
            };
            json!({
                "code": e.code,
                "title": e.title,
                "http_status": e.status,
                "description": e.description,
                "remediation": e.remediation,
                "ref_url": ref_url,
            })
        })
        .collect();

    let body = json!({ "object": "list", "data": data });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    )
        .into_response()
}

/// Render the error registry as a minimal HTML documentation page.
fn errors_html(state: &AppState) -> Response {
    let base = state.config.problem_type_base.trim_end_matches('/');
    let mut rows = String::new();
    for e in ERROR_REGISTRY {
        let anchor = if base.is_empty() {
            e.code.to_string()
        } else {
            format!("{base}#{}", e.code)
        };
        rows.push_str(&format!(
            "<tr id=\"{code}\"><td><a href=\"{anchor}\"><code>{code}</code></a></td><td>{status}</td><td>{title}</td><td>{desc}</td><td>{remediation}</td></tr>",
            code = html_escape(e.code),
            anchor = html_escape(&anchor),
            status = e.status,
            title = html_escape(e.title),
            desc = html_escape(e.description),
            remediation = html_escape(e.remediation),
        ));
    }
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Error registry</title></head>\
         <body><h1>Error registry</h1><table border=\"1\" cellpadding=\"6\">\
         <thead><tr><th>Code</th><th>HTTP</th><th>Title</th><th>Description</th><th>Remediation</th></tr></thead>\
         <tbody>{rows}</tbody></table></body></html>"
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

/// `GET /api/v1/openapi.json` — the frozen OpenAPI 3.1 document.
///
/// Served verbatim from the embedded asset. The document is the byte-stable
/// contract; a route-coverage test asserts the served routes match it.
pub async fn openapi() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        OPENAPI_JSON,
    )
        .into_response()
}

/// `GET /api/v1/docs` — a reference UI that renders the OpenAPI document.
///
/// A minimal HTML page that points the renderer at the sibling `openapi.json`. The
/// renderer bundle is served from this gateway (`docs/scalar.js`), never a public
/// CDN, so the page works fully offline. Served `noindex,nofollow` (header and meta
/// tag) so search engines never index the rendered HTML as a canonical surface
/// distinct from the OpenAPI document.
pub async fn docs() -> Response {
    crate::api::docs::reference_page("API reference")
}

/// `GET /api/v1/docs/scalar.js` — the vendored renderer bundle the docs page loads.
///
/// Served from the binary with a long-lived cache so a self-hosted deployment never
/// reaches a third-party CDN at view time.
pub async fn docs_scalar_js() -> Response {
    crate::api::docs::scalar_js()
}

/// Escape the five XML/HTML special characters for safe interpolation into the
/// generated docs/registry pages.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn docs_is_served_noindex() {
        // The OpenAPI description promises `noindex,nofollow` via both the
        // X-Robots-Tag header and a robots meta tag; both must actually ship.
        let resp = docs().await;
        assert_eq!(
            resp.headers()
                .get("x-robots-tag")
                .and_then(|v| v.to_str().ok()),
            Some("noindex, nofollow"),
            "the X-Robots-Tag header rides the docs page"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read the docs body");
        let html = String::from_utf8(bytes.to_vec()).expect("docs body is UTF-8");
        assert!(
            html.contains("<meta name=\"robots\" content=\"noindex, nofollow\">"),
            "the robots meta tag rides the page"
        );
    }
}
