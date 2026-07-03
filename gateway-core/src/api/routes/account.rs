//! The account surface: the balance read and the ledger history list.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::control::ledger_adjust::strip_operator_scoped_ref;
use crate::api::middleware::scope;
use crate::api::problem::Problem;
use crate::api::routes::guard;
use crate::api::state::AppState;
use crate::ledger::account::operator_for_account;
use crate::ledger::journal::{list_ledger_entries, LedgerHistoryRow};

/// `GET /api/v1/account/balance` — the caller's prepaid USD balance.
///
/// Requires the `account:read` scope. The balance is USD micro-cents serialized
/// as a decimal STRING (never a JSON number, which would lose precision past
/// 2^53). An account with no ledger activity reads `"0"`.
pub async fn balance(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let trace = guard::new_trace_id();
    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_ACCOUNT_READ, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    let balance_micros: i64 = sqlx::query_scalar(
        "SELECT coalesce((SELECT balance_micros FROM cw_core.balance WHERE account_id = $1), 0)",
    )
    .bind(viewer.account_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let body = json!({ "balance_usd_micros": balance_micros.to_string() });
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    )
        .into_response();
    guard::apply_rate_headers(&mut response, &decision);
    response
}

/// The query parameters the ledger list accepts.
#[derive(Debug, Default, Deserialize)]
pub struct LedgerQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

/// The default and maximum ledger page sizes.
const LEDGER_DEFAULT_LIMIT: u32 = 50;
const LEDGER_MAX_LIMIT: u32 = 100;

/// `GET /api/v1/account/ledger` — the caller's balance-ledger history.
///
/// Requires the `account:read` scope and is strictly account-scoped: every row
/// belongs to the credential's own account. Returns the Stripe/OpenAI list
/// envelope `{ object, data, has_more, next_cursor, url }`, newest first, with
/// an opaque keyset cursor over `(occurred_at, id)`. Each entry carries the
/// journal's signed semantics verbatim — `amount_usd_micros` is a signed
/// decimal STRING (negative debit, positive credit), `ref` is the entry's
/// cross-reference key (the poe record id for a publish debit/refund, the
/// upload attempt id for a storage charge, a vendor's own key for an
/// adjustment), and `metadata` is the opaque context stamped at insert.
///
/// A manual-adjustment ref is stored under an operator-scoped prefix (the engine
/// namespaces an operator-supplied idempotency ref by the owning operator so two
/// operators can never collide on the same key). That prefix is an internal
/// storage detail and carries the operator id, so it is stripped here: the account
/// sees the original ref it/its operator chose, never the engine's namespacing or
/// the operator's id. The account belongs to exactly one operator, so the row's
/// owning operator is the prefix to peel.
pub async fn ledger(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LedgerQuery>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let (viewer, decision) =
        match guard::authorize(&state, &headers, scope::SCOPE_ACCOUNT_READ, 1, trace).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    let limit = query
        .limit
        .unwrap_or(LEDGER_DEFAULT_LIMIT)
        .clamp(1, LEDGER_MAX_LIMIT);

    let before = match query.cursor.as_deref().map(decode_ledger_cursor) {
        Some(Some(c)) => Some(c),
        Some(None) => {
            let mut response = Problem::of(
                "invalid-cursor",
                "the pagination cursor could not be decoded",
            )
            .into_response_with(base, trace);
            guard::apply_rate_headers(&mut response, &decision);
            return response;
        }
        None => None,
    };

    // The account's owning operator, needed to strip the operator-scoped prefix off
    // any manual-adjustment ref before it is served back. A resolved credential
    // always has a satellite row, so a missing operator is an impossible state; it
    // is surfaced as a transient unavailability rather than silently leaking the
    // raw, prefixed ref.
    let operator_id = match operator_for_account(&state.pool, viewer.account_id).await {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => {
            let mut response = Problem::of(
                "service-unavailable",
                "the ledger is temporarily unavailable",
            )
            .into_response_with(base, trace);
            guard::apply_rate_headers(&mut response, &decision);
            return response;
        }
    };

    // Fetch one extra row to decide has_more without a second query.
    let rows =
        match list_ledger_entries(&state.pool, viewer.account_id, before, i64::from(limit) + 1)
            .await
        {
            Ok(r) => r,
            Err(_) => {
                let mut response = Problem::of(
                    "service-unavailable",
                    "the ledger is temporarily unavailable",
                )
                .into_response_with(base, trace);
                guard::apply_rate_headers(&mut response, &decision);
                return response;
            }
        };

    let has_more = rows.len() as u32 > limit;
    let page: Vec<&LedgerHistoryRow> = rows.iter().take(limit as usize).collect();
    let next_cursor = if has_more {
        page.last()
            .map(|r| encode_ledger_cursor(r.occurred_at, r.id))
    } else {
        None
    };

    let data: Vec<Value> = page
        .iter()
        .map(|r| ledger_row_to_wire(r, operator_id))
        .collect();
    let envelope = json!({
        "object": "list",
        "data": data,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "url": "/api/v1/account/ledger",
    });

    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".into()),
    )
        .into_response();
    guard::apply_rate_headers(&mut response, &decision);
    response
}

/// Project one journal row to its wire shape, served under `operator_id` (the
/// account's owning operator).
///
/// `amount_usd_micros` is a signed decimal string for the same reason the
/// balance read serializes a string: a JSON number would lose precision past
/// 2^53. Timestamps are RFC 3339 in UTC. The `ref` is de-namespaced: a
/// manual-adjustment ref stored under this operator's `op:<operator_id>:` prefix
/// is peeled back to the original operator-supplied value, so the account sees the
/// ref it/its operator chose rather than the engine's internal namespacing (and
/// the operator id never appears on the wire). A ref without this operator's prefix
/// (an engine-minted `adjust-<uuid>`, a publish record id, a storage attempt id) is
/// served verbatim.
fn ledger_row_to_wire(row: &LedgerHistoryRow, operator_id: Uuid) -> Value {
    let entry_ref = row
        .entry_ref
        .as_deref()
        .map(|r| strip_operator_scoped_ref(operator_id, r));
    json!({
        "id": row.id.to_string(),
        "kind": row.kind,
        "amount_usd_micros": row.amount_micros.to_string(),
        "ref": entry_ref,
        "quote_id": row.quote_id.map(|q| q.to_string()),
        // The publish-cost breakdown, LEFT JOINed from the consumed quote: the
        // network fee and service fee (which sum to the publish debit amount)
        // and the markup the publish was priced at. Null on every non-publish
        // entry (it has no quote to join). Micro-USD components travel as
        // decimal strings for the same precision reason as the amount; the
        // margin travels as a JSON number fraction (e.g. 0.25 for 25%),
        // matching the quote response's `margin_pct`.
        "network_usd_micros": row.network_usd_micros.map(|m| m.to_string()),
        "service_usd_micros": row.service_usd_micros.map(|m| m.to_string()),
        "margin_pct": row
            .margin_pct
            .and_then(|m| rust_decimal::prelude::ToPrimitive::to_f64(&m)),
        "metadata": row.metadata,
        "occurred_at": row.occurred_at.to_rfc3339(),
    })
}

/// Encode the opaque ledger cursor as base64url of `occurred_at_micros:uuid`.
///
/// Microseconds-since-epoch round-trips a `timestamptz` exactly (Postgres
/// stores microsecond precision), so the keyset resume point is byte-exact and
/// a row on the page boundary is never skipped or repeated.
fn encode_ledger_cursor(occurred_at: DateTime<Utc>, id: Uuid) -> String {
    let raw = format!("{}:{}", occurred_at.timestamp_micros(), id.simple());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

/// Decode the opaque ledger cursor; `None` on any malformation.
fn decode_ledger_cursor(cursor: &str) -> Option<(DateTime<Utc>, Uuid)> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_bytes())
        .ok()?;
    let s = String::from_utf8(raw).ok()?;
    let (micros, id) = s.split_once(':')?;
    let micros: i64 = micros.parse().ok()?;
    let occurred_at = DateTime::<Utc>::from_timestamp_micros(micros)?;
    let id = Uuid::parse_str(id).ok()?;
    Some((occurred_at, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_cursor_round_trips_microsecond_precision() {
        let at = DateTime::<Utc>::from_timestamp_micros(1_765_432_109_876_543).expect("timestamp");
        let id = Uuid::now_v7();
        let cursor = encode_ledger_cursor(at, id);
        assert_eq!(decode_ledger_cursor(&cursor), Some((at, id)));
    }

    #[test]
    fn ledger_cursor_rejects_malformed_input() {
        // Not base64url at all.
        assert_eq!(decode_ledger_cursor("%%%"), None);
        // Valid base64url, wrong interior shape.
        let bogus = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-cursor");
        assert_eq!(decode_ledger_cursor(&bogus), None);
        // Valid shape, non-uuid tail.
        let bogus =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"123456789:not-a-uuid");
        assert_eq!(decode_ledger_cursor(&bogus), None);
    }
}
