//! The RFC 7807 problem+json error envelope and the error registry.
//!
//! Every error response is an `application/problem+json` body carrying a stable
//! machine-readable `code`, a `type` URI built from the operator-configured base
//! (`<base>#<code>`), the matching HTTP `status`, a human `title` and `detail`,
//! optional per-field `errors`, and a `trace_id` echoed in the `X-Request-Id`
//! header for log correlation. The `type` base is operator config, never a
//! hardcoded vendor host.
//!
//! The error registry ([`ERROR_REGISTRY`]) is the closed catalogue of codes the
//! data plane emits, each pinned to its HTTP status and title. The `/api/v1/errors`
//! route serves it (JSON and HTML); a route raises an error by code and the
//! registry supplies the status/title so the two never drift.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use uuid::Uuid;

/// The content type of an RFC 7807 body.
pub const PROBLEM_JSON_CONTENT_TYPE: &str = "application/problem+json";

/// A single per-field validation error inside a problem body.
#[derive(Debug, Clone)]
pub struct FieldError {
    /// The dotted field path (empty string for a body-level error).
    pub field: String,
    /// The field-specific error code.
    pub code: String,
    /// The field-specific human detail.
    pub detail: String,
}

/// A catalogue entry: a stable code pinned to its HTTP status and title.
#[derive(Debug, Clone, Copy)]
pub struct ErrorSpec {
    /// The stable lowercase-kebab machine code.
    pub code: &'static str,
    /// The HTTP status this code maps to.
    pub status: u16,
    /// A short human title.
    pub title: &'static str,
    /// A longer human description (the catalogue entry's documentation).
    pub description: &'static str,
    /// The recommended caller action: what to change or do so the retry
    /// succeeds. Served by `/api/v1/errors` alongside the description.
    pub remediation: &'static str,
}

/// The closed catalogue of data-plane error codes.
///
/// A route raises an error by code; the registry supplies the status and title,
/// so a route and its documented contract can never disagree on a code's status.
/// The `/api/v1/errors` route serves this list.
pub const ERROR_REGISTRY: &[ErrorSpec] = &[
    ErrorSpec {
        code: "invalid-body",
        status: 400,
        title: "Invalid request body",
        description: "The request body was not valid JSON or could not be parsed.",
        remediation: "Send a syntactically valid JSON body that matches the endpoint's request schema, then retry.",
    },
    ErrorSpec {
        code: "validation-failed",
        status: 422,
        title: "Validation failed",
        description: "The request body or query parameters did not satisfy the schema.",
        remediation: "Correct the fields the problem detail (and any per-field errors) names, then retry.",
    },
    ErrorSpec {
        code: "invalid-tx-hash",
        status: 400,
        title: "Invalid transaction hash",
        description: "The transaction hash path segment was not 64 lowercase hex characters.",
        remediation: "Pass the transaction hash as exactly 64 lowercase hex characters.",
    },
    ErrorSpec {
        code: "invalid-poe-id",
        status: 400,
        title: "Invalid PoE id",
        description: "The PoE id path segment did not decode to a valid record id.",
        remediation: "Pass the PoE id exactly as the publish response returned it (poe_<26-char-crockford-base32>).",
    },
    ErrorSpec {
        code: "invalid-cursor",
        status: 400,
        title: "Invalid pagination cursor",
        description: "The pagination cursor could not be decoded.",
        remediation: "Restart pagination from the first page; cursors are opaque and must be replayed byte-for-byte from next_cursor.",
    },
    ErrorSpec {
        code: "unauthorized",
        status: 401,
        title: "Unauthorized",
        description: "The Authorization header was missing or the Bearer credential was malformed or unknown.",
        remediation: "Send a live credential as `Authorization: Bearer <secret>`; mint a fresh one if this credential was revoked or expired.",
    },
    ErrorSpec {
        code: "insufficient-scope",
        status: 403,
        title: "Insufficient scope",
        description: "The Bearer credential does not carry the scope this endpoint requires.",
        remediation: "Present a credential that carries the scope this endpoint requires (the problem body lists `required` and `granted`), or mint one with that scope.",
    },
    ErrorSpec {
        code: "account-disabled",
        status: 403,
        title: "Account disabled",
        description: "The account this credential belongs to is administratively disabled.",
        remediation: "Have the operator re-enable the account on the control plane; existing credentials resume working once it is active again.",
    },
    ErrorSpec {
        code: "account-not-active",
        status: 409,
        title: "Account not active",
        description: "A balance credit was posted for an account that is not active (it is disabled or being closed). Crediting a non-active account would orphan funds on an account on its way out, so the credit is refused atomically and no balance is moved. Debits and reversals to such an account are still accepted so it can be settled. Re-enable the account, then retry the credit.",
        remediation: "Re-enable the account, then retry the credit; debits and reversals are still accepted while it settles.",
    },
    ErrorSpec {
        code: "not-found",
        status: 404,
        title: "Not found",
        description: "The requested resource does not exist (or is not visible to the caller).",
        remediation: "Check the resource id; resources are tenant-scoped, so a foreign or deleted resource reads as absent.",
    },
    ErrorSpec {
        code: "insufficient-funds",
        status: 402,
        title: "Insufficient funds",
        description: "The account balance does not cover the quoted price.",
        remediation: "Top up the account balance, then retry; the problem body carries balance_usd_micros and required_usd_micros.",
    },
    ErrorSpec {
        code: "no-funding-grant",
        status: 402,
        title: "No storage funding grant",
        description: "Storing content beyond the free window requires a storage funding source the caller is entitled to draw, and no live grant entitles this caller for the configured backend.",
        remediation: "Have the operator issue a storage funding grant entitling this caller on the configured backend, then retry.",
    },
    ErrorSpec {
        code: "insufficient-storage-credit",
        status: 402,
        title: "Insufficient storage credit",
        description: "The storage funding source the caller draws cannot fund content of this size: its prepaid credit is below the safety floor or its provider-reported capacity cannot cover the chargeable bytes.",
        remediation: "Top up the funding source's prepaid credit (the control-plane storage top-up), or upload smaller content.",
    },
    ErrorSpec {
        code: "unsupported-storage-target",
        status: 400,
        title: "Unsupported storage target",
        description: "The upload named a storage target the deployment does not support; only \"arweave\" is accepted.",
        remediation: "Omit `target` or set it to \"arweave\", the only supported backend.",
    },
    ErrorSpec {
        code: "storage-not-configured",
        status: 422,
        title: "Storage not configured",
        description: "The deployment configures no content storage, so the storage funding console has nothing to read or fund.",
        remediation: "Configure a storage backend for the deployment; a hash-only gateway has no storage to fund or read.",
    },
    ErrorSpec {
        code: "turbo-not-active",
        status: 422,
        title: "Turbo not active on this backend",
        description: "The configured storage backend has no payment service, so there is no prepaid credit balance to read and nothing to top up.",
        remediation: "Run the storage backend against a payment service (Turbo) to hold prepaid credit, or skip prepaid-credit operations on this backend.",
    },
    ErrorSpec {
        code: "no-funding-source",
        status: 422,
        title: "No funding source",
        description: "The operator owns no active storage funding source on the configured backend, so a top-up has nothing to fund.",
        remediation: "Register an active storage funding source for the operator on the configured backend, then retry the top-up.",
    },
    ErrorSpec {
        code: "quote-not-found",
        status: 404,
        title: "Quote not found",
        description: "The quote id does not exist for this account.",
        remediation: "Request a fresh quote and publish with the quote_id it returns.",
    },
    ErrorSpec {
        code: "quote-already-consumed",
        status: 409,
        title: "Quote already consumed",
        description: "The quote was already spent by a prior publish.",
        remediation: "Request a fresh quote; each quote funds exactly one publish.",
    },
    ErrorSpec {
        code: "quote-expired",
        status: 410,
        title: "Quote expired",
        description: "The quote's time-to-live lapsed before it was consumed.",
        remediation: "Request a fresh quote and consume it before its expires_at.",
    },
    ErrorSpec {
        code: "idempotency-key-conflict",
        status: 409,
        title: "Idempotency key conflict",
        description: "The idempotency key was reused with a different request payload.",
        remediation: "Send the changed payload under a new Idempotency-Key; a key permanently names one exact request body.",
    },
    ErrorSpec {
        code: "address-already-registered",
        status: 409,
        title: "Address already registered",
        description: "The wallet address is already registered as a wallet by another operator; a global on-chain identity cannot be re-registered by a second tenant.",
        remediation: "Register a different wallet address; a global on-chain identity binds to exactly one operator.",
    },
    ErrorSpec {
        code: "last-live-root",
        status: 409,
        title: "Last live root credential",
        description: "The revocation targeted the operator's only live root credential. Revoking it would leave the operator with no way to mint tokens or rotate. Rotate the root instead (the rotation revokes it while minting its successor atomically), or provision an additional root credential first.",
        remediation: "Rotate the root instead (the rotation revokes it while minting its successor atomically), or provision an additional root credential first.",
    },
    ErrorSpec {
        code: "rate-limited",
        status: 429,
        title: "Rate limited",
        description: "The per-key request budget for the current window is exhausted.",
        remediation: "Wait the Retry-After window, then retry; spread bursts or mint a credential with a higher per-minute budget.",
    },
    ErrorSpec {
        code: "envelope-too-large",
        status: 413,
        title: "Payload too large",
        description: "An uploaded file or the batch total exceeded the size ceiling.",
        remediation: "Split the content into smaller files or batches under the size ceiling, then re-upload.",
    },
    ErrorSpec {
        code: "batch-too-large",
        status: 422,
        title: "Batch too large",
        description: "The publish-batch carried more records than the per-call maximum.",
        remediation: "Split the batch into calls of at most the per-call record maximum.",
    },
    ErrorSpec {
        code: "not-implemented",
        status: 501,
        title: "Not implemented",
        description: "The requested filter or feature is recognized but not implemented.",
        remediation: "Drop the unsupported filter or feature the problem detail names, then retry.",
    },
    ErrorSpec {
        code: "webhooks-disabled",
        status: 503,
        title: "Webhooks not enabled",
        description: "Webhook subscriptions are not enabled on this deployment.",
        remediation: "Have the operator enable webhook subscriptions on the deployment, or poll the read endpoints instead.",
    },
    ErrorSpec {
        code: "invalid-webhook-url",
        status: 422,
        title: "Invalid webhook URL",
        description: "The webhook delivery URL is not a permitted target: it is not a valid https:// URL, or it resolves to a blocked IP range (private, loopback, link-local, or a cloud metadata address).",
        remediation: "Use a public https:// delivery URL that does not resolve to a private, loopback, link-local, or cloud metadata address.",
    },
    ErrorSpec {
        code: "invalid-event-filter",
        status: 422,
        title: "Invalid event filter",
        description: "The webhook event filter named an event that is not a published wire event type.",
        remediation: "Filter only on published wire event types; list a subscription to see the accepted names.",
    },
    ErrorSpec {
        code: "chunk-digest-mismatch",
        status: 400,
        title: "Chunk digest mismatch",
        description: "A resumable-upload chunk's bytes did not match its declared per-chunk Digest, or the required Digest header was missing or malformed.",
        remediation: "Recompute the chunk's Digest header over the exact bytes sent and re-send the chunk with a matching digest.",
    },
    ErrorSpec {
        code: "chunk-size-mismatch",
        status: 400,
        title: "Chunk size mismatch",
        description: "A resumable-upload chunk's length did not equal the implied range length for its index.",
        remediation: "Send the chunk at exactly the length its index implies (only the final chunk may be shorter), then re-send it.",
    },
    ErrorSpec {
        code: "chunk-conflict",
        status: 409,
        title: "Chunk conflict",
        description: "A resumable-upload chunk index was re-sent with a different digest than the one already received for it.",
        remediation: "Re-send the chunk index with the same bytes as first received, or abandon the session and start a new one.",
    },
    ErrorSpec {
        code: "incomplete-upload",
        status: 409,
        title: "Incomplete upload",
        description: "A resumable upload was completed before every chunk index was received; the missing indices are listed.",
        remediation: "Upload the missing chunk indices the problem body lists, then complete the session again.",
    },
    ErrorSpec {
        code: "sha256-mismatch",
        status: 400,
        title: "Assembled hash mismatch",
        description: "A completed resumable upload's assembled bytes did not match the sha256 declared at session create.",
        remediation: "Re-hash the source content, create a new session declaring the correct sha256, and re-upload.",
    },
    ErrorSpec {
        code: "session-expired",
        status: 410,
        title: "Upload session expired",
        description: "The resumable upload session passed its time-to-live before it was completed.",
        remediation: "Create a new upload session and re-upload; an expired session cannot be resumed.",
    },
    ErrorSpec {
        code: "too-many-open-sessions",
        status: 429,
        title: "Too many open upload sessions",
        description: "The account already has the maximum number of concurrently open resumable upload sessions.",
        remediation: "Complete or abandon an open session before creating another.",
    },
    ErrorSpec {
        code: "service-unavailable",
        status: 503,
        title: "Service unavailable",
        description: "A dependency the request needs (pricing snapshot, indexer, database) is temporarily unavailable.",
        remediation: "Retry after a short backoff; the dependency outage is transient.",
    },
    ErrorSpec {
        code: "internal-error",
        status: 500,
        title: "Internal error",
        description: "An unexpected error occurred while processing the request.",
        remediation: "Retry once; if the error persists, report the trace_id from the problem body to the operator.",
    },
];

/// Look up a registry entry by code.
#[must_use]
pub fn lookup(code: &str) -> Option<&'static ErrorSpec> {
    ERROR_REGISTRY.iter().find(|e| e.code == code)
}

/// A problem ready to be turned into a response.
///
/// Built by code from the registry; the operator-configured `type` base and the
/// `trace_id` are folded in at render time so a problem value stays cheap to
/// construct and carry.
#[derive(Debug, Clone)]
pub struct Problem {
    /// The registry code (drives status, title, and the `type` fragment).
    pub code: String,
    /// The HTTP status (from the registry; overridable for a derived code).
    pub status: u16,
    /// The human title (from the registry).
    pub title: String,
    /// The instance-specific human detail.
    pub detail: String,
    /// Per-field validation errors, when any.
    pub errors: Vec<FieldError>,
    /// Extension members merged into the body (e.g. balance/required on a 402).
    pub extensions: serde_json::Map<String, Value>,
    /// Seconds a client should wait before retrying (only emitted on 429).
    pub retry_after_secs: Option<u64>,
}

impl Problem {
    /// Build a problem from a registry code and an instance detail.
    ///
    /// Falls back to `internal-error` (500) when the code is not in the
    /// registry, so a typo can never produce a body with no status.
    #[must_use]
    pub fn of(code: &str, detail: impl Into<String>) -> Self {
        let spec = lookup(code)
            .unwrap_or_else(|| lookup("internal-error").expect("internal-error registered"));
        Self {
            code: spec.code.to_string(),
            status: spec.status,
            title: spec.title.to_string(),
            detail: detail.into(),
            errors: Vec::new(),
            extensions: serde_json::Map::new(),
            retry_after_secs: None,
        }
    }

    /// Attach per-field validation errors.
    #[must_use]
    pub fn with_field_errors(mut self, errors: Vec<FieldError>) -> Self {
        self.errors = errors;
        self
    }

    /// Merge an extension member into the body.
    #[must_use]
    pub fn with_extension(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    /// Set the `Retry-After` window (only meaningful on a 429).
    #[must_use]
    pub fn with_retry_after(mut self, secs: u64) -> Self {
        self.retry_after_secs = Some(secs);
        self
    }

    /// Render the problem to an axum [`Response`].
    ///
    /// `type_base` is the operator-configured documentation base; the `type`
    /// member becomes `<type_base>#<code>` (or just `#<code>` when no base is
    /// configured, keeping the body valid without inventing a host). `trace_id`
    /// is written into the body and echoed in `X-Request-Id`.
    #[must_use]
    pub fn into_response_with(self, type_base: &str, trace_id: Uuid) -> Response {
        let type_uri = if type_base.is_empty() {
            format!("#{}", self.code)
        } else {
            format!("{}#{}", type_base.trim_end_matches('/'), self.code)
        };

        let mut body = serde_json::Map::new();
        body.insert("type".into(), json!(type_uri));
        body.insert("title".into(), json!(self.title));
        body.insert("status".into(), json!(self.status));
        body.insert("detail".into(), json!(self.detail));
        body.insert("code".into(), json!(self.code));
        if !self.errors.is_empty() {
            let errs: Vec<Value> = self
                .errors
                .iter()
                .map(|e| json!({ "field": e.field, "code": e.code, "detail": e.detail }))
                .collect();
            body.insert("errors".into(), json!(errs));
        }
        body.insert("trace_id".into(), json!(trace_id.to_string()));
        for (k, v) in self.extensions {
            body.insert(k, v);
        }

        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = (
            status,
            [(header::CONTENT_TYPE, PROBLEM_JSON_CONTENT_TYPE)],
            serde_json::to_string(&Value::Object(body)).unwrap_or_else(|_| "{}".into()),
        )
            .into_response();

        if let Ok(value) = HeaderValue::from_str(&trace_id.to_string()) {
            response.headers_mut().insert("x-request-id", value);
        }
        if let Some(secs) = self.retry_after_secs {
            if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn registry_codes_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for spec in ERROR_REGISTRY {
            assert!(seen.insert(spec.code), "duplicate code {}", spec.code);
        }
    }

    #[test]
    fn registry_statuses_are_valid_http() {
        for spec in ERROR_REGISTRY {
            assert!(
                StatusCode::from_u16(spec.status).is_ok(),
                "invalid status for {}",
                spec.code
            );
        }
    }

    #[tokio::test]
    async fn renders_type_from_operator_base_and_echoes_trace_id() {
        let trace = Uuid::now_v7();
        let resp = Problem::of("not-found", "no such record")
            .into_response_with("https://docs.example/errors", trace);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            PROBLEM_JSON_CONTENT_TYPE
        );
        assert_eq!(
            resp.headers().get("x-request-id").unwrap(),
            &trace.to_string()
        );
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], "not-found");
        assert_eq!(body["status"], 404);
        assert_eq!(body["type"], "https://docs.example/errors#not-found");
        assert_eq!(body["trace_id"], trace.to_string());
    }

    #[tokio::test]
    async fn renders_a_relative_type_when_no_base_is_configured() {
        let resp = Problem::of("validation-failed", "bad").into_response_with("", Uuid::now_v7());
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["type"], "#validation-failed");
    }

    #[tokio::test]
    async fn rate_limited_emits_retry_after() {
        let resp = Problem::of("rate-limited", "slow down")
            .with_retry_after(30)
            .into_response_with("", Uuid::now_v7());
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "30");
    }

    #[tokio::test]
    async fn insufficient_funds_carries_extensions() {
        let resp = Problem::of("insufficient-funds", "balance too low")
            .with_extension("balance_usd_micros", json!("100"))
            .with_extension("required_usd_micros", json!("500"))
            .into_response_with("", Uuid::now_v7());
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["balance_usd_micros"], "100");
        assert_eq!(body["required_usd_micros"], "500");
    }

    #[test]
    fn unknown_code_falls_back_to_internal_error() {
        let p = Problem::of("totally-made-up", "x");
        assert_eq!(p.code, "internal-error");
        assert_eq!(p.status, 500);
    }
}
