//! The publish-cost quote route.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::api::middleware::scope;
use crate::api::problem::{FieldError, Problem};
use crate::api::routes::guard;
use crate::api::state::AppState;
use crate::ledger::account::operator_for_account;
use crate::ledger::quote::{create_quote, EchoMarginHook, QuoteRequest};
use crate::storage::{authorize_charge, StorageChargePrincipal, StorageError};

/// The `POST /api/v1/poe/quote` request body.
#[derive(Debug, Deserialize)]
struct QuoteBody {
    /// Canonical Label 309 record length in bytes.
    record_bytes: u32,
    /// Number of sealed-PoE recipients.
    #[serde(default)]
    recipient_count: u32,
    /// Total content bytes (0 for hash-only).
    #[serde(default)]
    file_bytes_total: u64,
}

/// `POST /api/v1/poe/quote` — price a publish.
///
/// Requires the `poe:create` scope. Validates the byte counts, resolves the
/// vendor pricing inputs, computes and persists the durable quote row, and
/// returns the byte-stable wire shape: the SDK's `{ quote_id, amount, currency,
/// expires_at }` PLUS the additive web fields (`usd_micros`, `breakdown`,
/// `margin_pct`, `fx_age_seconds`) the dashboard surfaces. A deployment with no
/// pricing seam wired reports the dependency unavailable rather than inventing a
/// price.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_POE_CREATE, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    let parsed: QuoteBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return Problem::of(
                "invalid-body",
                format!("request body is not valid JSON: {e}"),
            )
            .into_response_with(base, trace);
        }
    };

    if parsed.record_bytes == 0 {
        return Problem::of("validation-failed", "record_bytes must be positive")
            .with_field_errors(vec![FieldError {
                field: "record_bytes".into(),
                code: "out-of-range".into(),
                detail: "record_bytes must be a positive integer".into(),
            }])
            .into_response_with(base, trace);
    }

    let Some(pricing) = state.pricing.as_ref() else {
        return Problem::of(
            "service-unavailable",
            "pricing is not configured for this deployment",
        )
        .into_response_with(base, trace);
    };

    let inputs = match pricing
        .resolve_dyn(
            viewer.account_id,
            parsed.record_bytes,
            parsed.recipient_count,
            parsed.file_bytes_total,
        )
        .await
    {
        Ok(i) => i,
        Err(_) => {
            return Problem::of(
                "service-unavailable",
                "pricing inputs are temporarily unavailable",
            )
            .into_response_with(base, trace);
        }
    };

    // Storage affordability is checked at QUOTE time, not mid-publish: a publish
    // that stores more than the free window must fail here with a 402 if the
    // operator cannot fund it, so the user never commits to a price the gateway
    // then cannot honour. Content within the free window (chargeable == 0) is
    // always affordable; a deployment with no storage seam wired skips the branch
    // entirely (an intentional hash-only deployment quotes for free-window content
    // only).
    //
    // The check is two gates, neither making a provider call (so a thousand
    // concurrent quotes add zero provider traffic):
    //   1. funding capability: resolve "the" funding source this caller may draw
    //      for the configured backend through the funding grant resolver; no live
    //      grant entitles it -> 402 no-funding-grant;
    //   2. backend affordability: ask the BACKEND whether that source can fund the
    //      chargeable bytes -> 402 insufficient-storage-credit on refusal. This is
    //      the same seam the upload routes consult, so the quote and the upload can
    //      never disagree: the Turbo backend reads its cached winc balance (a DB
    //      read, never the provider), while a backend with no funding ceiling (the
    //      dev emulator mints balance freely) affords by default.
    let chargeable_bytes = parsed
        .file_bytes_total
        .saturating_sub(state.config.free_storage_bytes);
    if chargeable_bytes > 0 {
        if let Some(storage) = state.storage.as_ref() {
            // Name the account's owning operator so the resolver can match an
            // operator-scoped grant on it; an account whose satellite is missing
            // is a misconfigured tenant, surfaced as a retryable 503 rather than a
            // funding refusal.
            let operator_id = match operator_for_account(&state.pool, viewer.account_id).await {
                Ok(Some(operator_id)) => operator_id,
                Ok(None) => {
                    return Problem::of(
                        "service-unavailable",
                        "the account is not provisioned under an operator",
                    )
                    .into_response_with(base, trace);
                }
                Err(_) => {
                    return Problem::of(
                        "service-unavailable",
                        "content storage could not be checked",
                    )
                    .into_response_with(base, trace);
                }
            };

            let principal = StorageChargePrincipal::Account {
                operator_id,
                account_id: viewer.account_id,
            };
            let funding =
                match authorize_charge(&state.pool, storage.backend_name(), principal).await {
                    Ok(Some(funding)) => funding,
                    Ok(None) => {
                        return Problem::of(
                            "no-funding-grant",
                            "no storage funding source entitles this account to store content \
                             beyond the free window",
                        )
                        .into_response_with(base, trace);
                    }
                    Err(_) => {
                        return Problem::of(
                            "service-unavailable",
                            "content storage could not be checked",
                        )
                        .into_response_with(base, trace);
                    }
                };

            match storage.backend().affords(&funding, chargeable_bytes).await {
                Ok(()) => {}
                // The backend cannot promise to fund this size (for Turbo: an
                // unreconciled source, a balance at or below the safety floor, or a
                // provider-reported capacity below the chargeable bytes): refuse at
                // quote time with a 402 so the user never commits to an unfundable
                // price. The upload route maps the same error the same way.
                Err(StorageError::InsufficientCredit) => {
                    return Problem::of(
                        "insufficient-storage-credit",
                        "the storage funding source cannot fund content of this size",
                    )
                    .into_response_with(base, trace);
                }
                Err(_) => {
                    return Problem::of(
                        "service-unavailable",
                        "content storage could not be checked",
                    )
                    .into_response_with(base, trace);
                }
            }
        }
    }

    // The margin the seam resolved: both its fraction and its attribution
    // (a pushed per-account override, or the operator-default) flow onto the
    // durable row and the wire, so a caller can see which one priced the quote.
    let margin_source = inputs.margin.margin_source.clone();
    let resolved_margin = inputs.margin.clone();

    let request = QuoteRequest {
        account_id: viewer.account_id,
        record_bytes: parsed.record_bytes,
        recipient_count: parsed.recipient_count,
        file_bytes_total: parsed.file_bytes_total,
        free_storage_bytes: state.config.free_storage_bytes,
        network_lovelace: inputs.network_lovelace,
        fx: inputs.fx,
        fx_age_seconds: inputs.fx_age_seconds,
        request_id: Some(trace),
    };

    // The vendor margin was already resolved by the pricing seam (fraction plus
    // its attribution); echo the whole resolution onto the durable row so the
    // persisted margin_source equals the one the wire reports.
    let hook = EchoMarginHook::new(resolved_margin);
    let quote = match create_quote(&state.pool, &hook, &request).await {
        Ok(q) => q,
        Err(_) => {
            return Problem::of("service-unavailable", "could not persist the quote")
                .into_response_with(base, trace);
        }
    };

    // Byte-stable wire shape: the SDK requires amount/currency/expires_at, and the
    // dashboard reads the additive breakdown fields.
    let wire = json!({
        "quote_id": quote.id.to_string(),
        "amount": quote.wire_amount(),
        "currency": quote.wire_currency(),
        "expires_at": quote.expires_at.to_rfc3339(),
        "usd_micros": quote.total_usd_micros.to_string(),
        "breakdown": {
            "network_usd_micros": quote.network_usd_micros.to_string(),
            "storage_usd_micros": quote.storage_usd_micros.to_string(),
            "service_usd_micros": quote.service_usd_micros.to_string(),
        },
        // The dashboard reads margin_pct as a JSON number (the markup fraction),
        // matching the reference; the exact-decimal column is rendered to f64 for
        // the wire so it is a number, not a quoted decimal string.
        "margin_pct": rust_decimal::prelude::ToPrimitive::to_f64(&quote.margin_pct),
        // The attribution of the margin: "account-override" when a pushed
        // per-account override priced the quote, else "operator-default".
        "margin_source": margin_source,
        "fx_age_seconds": quote.fx_age_seconds,
    });

    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&wire).unwrap_or_else(|_| "{}".into()),
    )
        .into_response();
    guard::apply_rate_headers(&mut response, &decision);
    response
}
