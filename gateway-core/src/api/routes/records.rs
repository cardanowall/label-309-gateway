//! The indexer read surface: list, count, and single-record read.
//!
//! The list and single-record reads are public (chain data is issuer-agnostic);
//! a Bearer credential only adds owner-only projections.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::middleware::scope;
use crate::api::problem::Problem;
use crate::api::routes::guard;
use crate::api::state::AppState;
use crate::api::wire::{conformance_profile, WireStatus};
use crate::chain::records::IndexedRecordRow;

/// The query parameters the list route accepts.
///
/// `cursor`, `limit`, and `sealed` are the original byte-stable subset; the rest
/// are additive optional narrowing filters backed by the existing index access
/// paths. `sealed=true` stays for back-compat (it narrows to scheme != 0);
/// `scheme` is the precise counterpart. `label` is accepted for wire compatibility
/// but is a no-op in the core index: every indexed record carries the single fixed
/// on-chain metadata label, so there is no per-row label to filter on (a control
/// plane that multiplexes labels filters in its own layer).
#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
    cursor: Option<String>,
    limit: Option<u32>,
    sealed: Option<bool>,
    scheme: Option<i16>,
    signer: Option<String>,
    from_block: Option<i64>,
    to_block: Option<i64>,
    from_time: Option<chrono::DateTime<chrono::Utc>>,
    to_time: Option<chrono::DateTime<chrono::Utc>>,
    #[allow(dead_code)]
    label: Option<String>,
}

/// The default and maximum list page sizes.
const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 100;

/// `GET /api/v1/records` — the paginated indexer query surface.
///
/// Anonymous callers (and non-owners) see only chain-anchored rows; a Bearer
/// credential adds the owner-only `account_id` projection for the caller's rows.
/// The response is the Stripe/OpenAI list envelope `{ object, data, has_more,
/// next_cursor, url }` with an opaque cursor over `(block_height, tx_hash)`.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    client: guard::ClientAddr,
    Query(query): Query<ListQuery>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    // Auth is optional here. When a Bearer is present it must be valid+scoped
    // (never silently downgraded to anonymous); when absent the caller is
    // anonymous, sees only anchored public rows, and meters against the
    // per-client-address anonymous budget.
    let viewer = if headers.contains_key(header::AUTHORIZATION) {
        match guard::authorize(&state, &headers, scope::SCOPE_POE_READ, 1, trace).await {
            Ok((v, _)) => Some(v),
            Err(resp) => return resp,
        }
    } else {
        if let Err(resp) = guard::limit_anonymous(&state, client.0, 1, trace).await {
            return resp;
        }
        None
    };

    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let after = match query.cursor.as_deref().map(decode_cursor) {
        Some(Some(c)) => Some(c),
        Some(None) => {
            return Problem::of(
                "invalid-cursor",
                "the pagination cursor could not be decoded",
            )
            .into_response_with(base, trace);
        }
        None => None,
    };

    // Build the narrowing filter from the additive query params. The indexer never
    // stores a per-recipient column, so "addressed to me" is resolved by the vendor
    // wrapper, not here; the core read narrows on scheme, signer, and the
    // block/time coordinate ranges, all served by the existing index access paths.
    let filter = match build_record_filter(&query) {
        Ok(f) => f,
        Err((code, detail)) => return Problem::of(code, detail).into_response_with(base, trace),
    };

    let owner_account = viewer.as_ref().map(|v| v.account_id);
    let is_first_page = after.is_none();

    // Confirmations are derived from the materialised tip: a row at `block_height`
    // is `tip - block_height + 1` confirmations deep, never refreshed per-row.
    let tip = current_tip(&state).await;

    // Fetch one extra row to decide has_more without a second query.
    let rows: Vec<IndexedRecordRow> = match fetch_page(&state, after, limit + 1, &filter).await {
        Ok(r) => r,
        Err(_) => {
            return Problem::of(
                "service-unavailable",
                "the indexer is temporarily unavailable",
            )
            .into_response_with(base, trace);
        }
    };

    let has_more = rows.len() as u32 > limit;
    let page: Vec<&IndexedRecordRow> = rows.iter().take(limit as usize).collect();
    let next_cursor = if has_more {
        page.last()
            .map(|r| encode_cursor(r.block_height, &r.tx_hash))
    } else {
        None
    };

    // Owner-only: on the first page (no cursor) prepend the caller's own pending
    // records. These un-anchored rows live in `cw_core.poe_record`, are visible
    // only to their owner, and are not part of the cursor walk (which paginates the
    // anchored chain index alone).
    let mut data: Vec<Value> = Vec::new();
    if is_first_page {
        if let Some(account) = owner_account {
            match fetch_pending(&state, account, &filter).await {
                Ok(pending) => data.extend(pending.into_iter().map(|p| p.to_wire(account))),
                Err(_) => {
                    return Problem::of(
                        "service-unavailable",
                        "the indexer is temporarily unavailable",
                    )
                    .into_response_with(base, trace);
                }
            }
        }
    }
    // Resolve, in one lookup, which of this page's records the caller published, so
    // the owner-only `account_id` is attached to exactly those. An anonymous reader
    // owns nothing. Ownership is resolved against this engine's publishing state, not
    // the zero-knowledge index.
    let owned = match owner_account {
        Some(viewer) => {
            let hashes: Vec<Vec<u8>> = page.iter().map(|r| r.tx_hash.clone()).collect();
            viewer_owned_tx_hashes(&state, viewer, &hashes).await
        }
        None => std::collections::HashSet::new(),
    };
    data.extend(page.iter().map(|r| {
        let viewer_owned = owner_account.filter(|_| owned.contains(&r.tx_hash));
        record_row_to_wire(r, viewer_owned, tip)
    }));

    let mut envelope = json!({
        "object": "list",
        "data": data,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "url": "/api/v1/records",
    });
    if let (Value::Object(map), Some(tip)) = (&mut envelope, tip) {
        map.insert("tip_block_height".into(), json!(tip));
    }

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".into()),
    )
        .into_response()
}

/// `GET /api/v1/records/count` — the exact count of records matching a filter.
///
/// The counting counterpart to [`list`]: the cursor-paginated feed never carries
/// a total, so a consumer that needs "how many records match this filter" (a
/// public profile's proof count, an explorer facet) asks here. Accepts the same
/// narrowing filter grammar as the list route (`signer`, `scheme`, `sealed`,
/// `from_block`/`to_block`, `from_time`/`to_time`) so a count is always "the total
/// matching the same filter as a list page".
///
/// The count is over the public anchored set only. It carries no owner-only
/// projection (a total needs no per-account view), so it never reads engine
/// publishing state and is identical for every caller; a Bearer is accepted but
/// changes nothing. Anonymous is fine, matching the list route's public read.
///
/// Safety: a count's cost is the cardinality of the matching set, not just the
/// index it rides. On a global multi-operator index, a `COUNT(*)` over the whole
/// chain (or over a wide block window, which is most of the chain) is an
/// arbitrarily large scan — an index-only scan over the entire table is still
/// O(table). The route therefore REQUIRES a `signer`: a count is always scoped to
/// one signer's records, the primary use case, whose cardinality is bounded by
/// that one key's lifetime output and which the verified-signer set's
/// `(signer_ed25519, block_height)` index serves directly (so the count matches
/// the list filter — every record the key signed, first or not). `scheme`,
/// `sealed`, and the block/time windows remain
/// valid ADDITIONAL narrowing on top of the signer, but none of them bounds the
/// cardinality on its own (a block or time window can still span the whole chain;
/// `scheme`/`sealed` partition it), so a count without a signer is rejected with
/// 422. As defense in depth, the count query also runs under a short
/// statement timeout, so even a pathological signer-scoped count cannot tie up a
/// connection; a timeout surfaces as a 503 rather than a wrong answer.
pub async fn count(
    State(state): State<AppState>,
    headers: HeaderMap,
    client: guard::ClientAddr,
    Query(query): Query<ListQuery>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    // Auth is optional and immaterial to the result: the count is over the public
    // anchored set with no owner projection. When a Bearer is present it must be
    // valid+scoped (so a bad token is still rejected, exactly as on the list
    // route); when absent the caller is anonymous, gets the same public count,
    // and meters against the per-client-address anonymous budget.
    if headers.contains_key(header::AUTHORIZATION) {
        if let Err(resp) = guard::authorize(&state, &headers, scope::SCOPE_POE_READ, 1, trace).await
        {
            return resp;
        }
    } else if let Err(resp) = guard::limit_anonymous(&state, client.0, 1, trace).await {
        return resp;
    }

    // Build the filter, then require it to carry a signer: a count's cost is the
    // cardinality of the match, so it must be scoped to one publisher's records
    // (bounded by that key's output and served by the signer index). A bare
    // block/time window can still span the whole chain and a scheme/sealed predicate
    // only partitions it, so none of them bounds the count on its own; only a signer
    // does. `build_record_filter` already validates every field, so reusing it keeps
    // the count's grammar byte-identical to the list route's.
    let count_filter = match build_record_filter(&query) {
        Ok(filter) => match count_filter_from(filter) {
            Some(cf) => cf,
            None => {
                return Problem::of(
                    "validation-failed",
                    "a records count must be scoped to a signer: supply a signer (a count's cost is the size of the matching set, which only a signer bounds; scheme, sealed, and block/time windows narrow but do not bound it)",
                )
                .into_response_with(base, trace);
            }
        },
        Err((code, detail)) => return Problem::of(code, detail).into_response_with(base, trace),
    };

    let total = match crate::chain::records::count_records(&state.pool, &count_filter).await {
        Ok(n) => n,
        Err(_) => {
            return Problem::of(
                "service-unavailable",
                "the indexer is temporarily unavailable",
            )
            .into_response_with(base, trace);
        }
    };

    let body = json!({
        "object": "count",
        "count": total,
        "url": "/api/v1/records/count",
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| "{}".into()),
    )
        .into_response()
}

/// Lift a validated list filter into a count filter, requiring the signer scope.
///
/// A count is always scoped to one publisher's key (the only bound on the match
/// cardinality), so this returns `None` when the filter carries no signer — the
/// route maps that to a 422. The remaining predicates carry over unchanged as
/// optional narrowing on top of the signer scope.
fn count_filter_from(
    filter: crate::chain::records::RecordFilter,
) -> Option<crate::chain::records::CountFilter> {
    let signer = filter.signer?;
    Some(crate::chain::records::CountFilter {
        signer,
        sealed_only: filter.sealed_only,
        scheme: filter.scheme,
        from_block: filter.from_block,
        to_block: filter.to_block,
        from_time: filter.from_time,
        to_time: filter.to_time,
    })
}

/// `GET /api/v1/records/{tx_hash}` — the canonical single-record read.
///
/// Content-negotiated: `application/cbor` (or `?format=cbor`) returns the raw
/// canonical metadata bytes with a strong ETag and immutable cache headers;
/// otherwise a JSON record resource. An un-indexed (or un-anchored, non-owner)
/// hash returns 404 indistinguishably (oracle-safe).
pub async fn get_one(
    State(state): State<AppState>,
    headers: HeaderMap,
    client: guard::ClientAddr,
    Path(tx_hash): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    if !is_tx_hash(&tx_hash) {
        return Problem::of(
            "invalid-tx-hash",
            "transaction hash must be 64 lowercase hex characters",
        )
        .into_response_with(base, trace);
    }
    let tx_bytes = hex::decode(&tx_hash).expect("validated hex");

    // Resolve the caller ONCE, before any index read, for both content
    // negotiations: a present Bearer must be valid+scoped (a bad token is
    // rejected on the CBOR path too, never silently treated as anonymous), and
    // an anonymous caller meters against the per-client-address budget.
    let viewer = if headers.contains_key(header::AUTHORIZATION) {
        match guard::authorize(&state, &headers, scope::SCOPE_POE_READ, 1, trace).await {
            Ok((v, _)) => Some(v),
            Err(resp) => return resp,
        }
    } else {
        if let Err(resp) = guard::limit_anonymous(&state, client.0, 1, trace).await {
            return resp;
        }
        None
    };

    let wants_cbor = query.get("format").map(|f| f == "cbor").unwrap_or(false)
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|a| a.contains("application/cbor"))
            .unwrap_or(false);

    let row: Option<IndexedRecordRow> =
        crate::chain::records::fetch_record_by_tx_hash(&state.pool, &tx_bytes)
            .await
            .ok()
            .flatten();

    let Some(row) = row else {
        return Problem::of("not-found", "no record indexed for this transaction hash")
            .into_response_with(base, trace);
    };

    if wants_cbor {
        let etag = format!("\"{}\"", hex::encode(sha256(&row.metadata_cbor)));
        if let Some(inm) = headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
        {
            if inm == etag {
                return StatusCode::NOT_MODIFIED.into_response();
            }
        }
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/cbor".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"record-{tx_hash}.cbor\""),
                ),
                (
                    header::CACHE_CONTROL,
                    "public, max-age=3600, immutable".to_string(),
                ),
                (header::ETAG, etag),
            ],
            row.metadata_cbor.clone(),
        )
            .into_response();
    }

    // JSON branch: resolve the optional owner projection from the caller
    // resolved above.
    let owner_account = viewer.as_ref().map(|v| v.account_id);
    let tip = current_tip(&state).await;

    // Attach the owner-only `account_id` only when the caller published this exact
    // record, resolved against this engine's publishing state (not the index).
    let viewer_owned = match owner_account {
        Some(viewer) => {
            let owned =
                viewer_owned_tx_hashes(&state, viewer, std::slice::from_ref(&row.tx_hash)).await;
            owner_account.filter(|_| owned.contains(&row.tx_hash))
        }
        None => None,
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&record_row_to_wire(&row, viewer_owned, tip))
            .unwrap_or_else(|_| "{}".into()),
    )
        .into_response()
}

/// Project an anchored index row to the SDK `RecordResource` wire shape.
///
/// `viewer_owned` is the authenticated caller's account when the caller owns THIS
/// record (resolved against this engine's own publishing state, not the
/// zero-knowledge index), else `None`. The owner-only `account_id` field is attached
/// ONLY then, so a non-owner (and an anonymous reader) never sees who published a
/// record. `tip` derives the confirmation depth. The index read lives in the index's
/// single SQL owner (`chain::records`); ownership is resolved separately so the index
/// itself stays tenancy-free.
fn record_row_to_wire(
    row: &IndexedRecordRow,
    viewer_owned: Option<uuid::Uuid>,
    tip: Option<i64>,
) -> Value {
    // The index column holds only a VERIFIED signer (the derivation checks the
    // signature, never just the named key), so `signed` here means "carries a
    // signature that verified at index time".
    let signed = row.signer_ed25519.is_some();
    let scheme = row.scheme.max(0) as u8;
    // An anchored record is on chain; until it crosses the confirmation threshold
    // it is `confirming`. The core read reports the depth and the wire status the
    // SDK reads; the threshold itself is the verifier's concern, so the list status
    // stays `confirming` once anchored.
    let status = WireStatus::Confirming.as_str();
    let num_confirmations = tip.map(|t| (t - row.block_height + 1).max(0)).unwrap_or(0);

    let mut obj = serde_json::Map::new();
    obj.insert("tx_hash".into(), json!(hex::encode(&row.tx_hash)));
    obj.insert("status".into(), json!(status));
    obj.insert("block_height".into(), json!(row.block_height));
    obj.insert("block_time".into(), json!(row.block_time.to_rfc3339()));
    obj.insert("num_confirmations".into(), json!(num_confirmations));
    obj.insert("scheme".into(), json!(scheme));
    obj.insert("item_count".into(), json!(row.item_count.max(0)));
    obj.insert(
        "signer_ed25519".into(),
        json!(row.signer_ed25519.as_ref().map(hex::encode)),
    );
    obj.insert(
        "metadata_cbor_base64".into(),
        json!(base64::engine::general_purpose::STANDARD.encode(&row.metadata_cbor)),
    );
    obj.insert(
        "conformance_profile".into(),
        json!(conformance_profile(scheme, signed)),
    );
    if let Some(account) = viewer_owned {
        obj.insert(
            "account_id".into(),
            json!(crate::api::ids::encode_account_id(account)),
        );
    }
    Value::Object(obj)
}

/// Of a set of anchored transaction hashes, the subset the viewer published.
///
/// Resolves ownership against this engine's own publishing state
/// (`cw_core.poe_record`), NOT the zero-knowledge on-chain index, so the index stays
/// tenancy-free. Returns the hashes the viewer owns, as the lookup set the wire
/// projection consults to decide whether to attach the owner-only `account_id`.
async fn viewer_owned_tx_hashes(
    state: &AppState,
    viewer: uuid::Uuid,
    tx_hashes: &[Vec<u8>],
) -> std::collections::HashSet<Vec<u8>> {
    if tx_hashes.is_empty() {
        return std::collections::HashSet::new();
    }
    let owned: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT tx_hash FROM cw_core.poe_record \
         WHERE account_id = $1 AND tx_hash = ANY($2)",
    )
    .bind(viewer)
    .bind(tx_hashes)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    owned.into_iter().collect()
}

/// A pending (un-anchored) record the owner sees prepended on page 1.
///
/// These live in `cw_core.poe_record` before a submit lands a block; only the
/// owning account sees them. The wire status maps from the engine lifecycle, and
/// the indexed columns are derived from the stored record bytes.
#[derive(sqlx::FromRow)]
struct PendingRecord {
    #[sqlx(rename = "id")]
    record_id: uuid::Uuid,
    tx_hash: Option<Vec<u8>>,
    status: String,
    record_bytes: Vec<u8>,
}

impl PendingRecord {
    /// Project a pending record to the wire shape, always attaching the owner-only
    /// `account_id` (the caller is, by construction, the owner).
    fn to_wire(&self, owner_account: uuid::Uuid) -> Value {
        let projection = crate::api::wire::project_record(&self.record_bytes);
        let (scheme, signed, item_count) = projection
            .as_ref()
            .map(|p| (p.scheme, p.signed, p.items_count))
            .unwrap_or((0, false, 0));
        let status = WireStatus::from_core(&self.status)
            .map(|s| s.as_str())
            .unwrap_or("submitting");

        json!({
            "tx_hash": self.tx_hash.as_ref().map(hex::encode),
            "status": status,
            "block_height": Value::Null,
            "block_time": Value::Null,
            "num_confirmations": 0,
            "scheme": scheme,
            "item_count": item_count,
            "signer_ed25519": Value::Null,
            "metadata_cbor_base64": base64::engine::general_purpose::STANDARD.encode(&self.record_bytes),
            "conformance_profile": conformance_profile(scheme, signed),
            "account_id": crate::api::ids::encode_account_id(owner_account),
            // The pending record's stable id, so a client can stream its events.
            "id": crate::api::ids::encode_poe_id(self.record_id),
        })
    }
}

/// Fetch a page of anchored records after an optional cursor boundary.
///
/// Delegates to the index's single SQL owner (`chain::records::fetch_record_page`);
/// ownership is filtered at projection time, not in the query, because the page
/// itself is the public anchored set regardless of who is reading. `filter` carries
/// the additive narrowing predicates.
async fn fetch_page(
    state: &AppState,
    after: Option<(i64, Vec<u8>)>,
    limit: u32,
    filter: &crate::chain::records::RecordFilter,
) -> crate::Result<Vec<IndexedRecordRow>> {
    let after_ref = after.as_ref().map(|(bh, tx)| (*bh, tx.as_slice()));
    crate::chain::records::fetch_record_page(&state.pool, after_ref, i64::from(limit), filter).await
}

/// Fetch the caller's own pending (un-anchored) records for the page-1 prepend.
///
/// A pending record is one this account published that has not yet been anchored
/// in a block (`block_height IS NULL`) and is still in flight (`submitting` or
/// `submitted`). They are owner-private: only the caller sees their own pending
/// records, and they are never part of the anchored cursor walk.
///
/// A pending record carries no block coordinates and no indexed signer, so any
/// block/time/signer filter excludes all of them by construction (such a filter is
/// a request for anchored rows in a window a pending record cannot be in). When
/// only the scheme/sealed filters are set, they are applied from the record bytes,
/// mirroring the anchored page's narrowing.
async fn fetch_pending(
    state: &AppState,
    account_id: uuid::Uuid,
    filter: &crate::chain::records::RecordFilter,
) -> crate::Result<Vec<PendingRecord>> {
    // A pending record has no block height, no block time, and no indexed signer;
    // a filter that constrains any of those cannot match a pending record, so the
    // page-1 prepend is empty when one is set.
    if filter.signer.is_some()
        || filter.from_block.is_some()
        || filter.to_block.is_some()
        || filter.from_time.is_some()
        || filter.to_time.is_some()
    {
        return Ok(Vec::new());
    }

    let mut pending: Vec<PendingRecord> = sqlx::query_as(
        "SELECT id, tx_hash, status, record_bytes FROM cw_core.poe_record \
         WHERE account_id = $1 AND block_height IS NULL \
           AND status IN ('submitting', 'submitted') \
         ORDER BY created_at DESC",
    )
    .bind(account_id)
    .fetch_all(&state.pool)
    .await?;

    // Apply the scheme/sealed narrowing the anchored page uses, derived from the
    // record bytes: the coarse `sealed_only` drops open (scheme 0) records, and the
    // precise `scheme` keeps only the matching scheme. Both must hold when both set.
    if filter.sealed_only || filter.scheme.is_some() {
        pending.retain(|p| {
            let scheme = crate::api::wire::project_record(&p.record_bytes).map(|proj| proj.scheme);
            let Some(scheme) = scheme else {
                return false;
            };
            if filter.sealed_only && scheme == 0 {
                return false;
            }
            if let Some(want) = filter.scheme {
                if i16::from(scheme) != want {
                    return false;
                }
            }
            true
        });
    }
    Ok(pending)
}

/// The materialised chain tip height (the freshest across networks), or `None`
/// when no tip is known yet (a fresh deployment before the indexer's first tip).
async fn current_tip(state: &AppState) -> Option<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT tip_block_height FROM cw_core.cardano_tip \
         ORDER BY tip_observed_at DESC LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
}

/// Encode the opaque list cursor as base64url of `block_height:tx_hash`.
fn encode_cursor(block_height: i64, tx_hash: &[u8]) -> String {
    let raw = format!("{block_height}:{}", hex::encode(tx_hash));
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

/// Decode the opaque list cursor; `None` on any malformation.
fn decode_cursor(cursor: &str) -> Option<(i64, Vec<u8>)> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_bytes())
        .ok()?;
    let s = String::from_utf8(raw).ok()?;
    let (bh, tx) = s.split_once(':')?;
    let block_height: i64 = bh.parse().ok()?;
    let tx_hash = hex::decode(tx).ok()?;
    Some((block_height, tx_hash))
}

/// Build the index narrowing filter from the list query, validating each param.
///
/// Returns a ready [`crate::chain::records::RecordFilter`], or a `(problem_code,
/// detail)` pair the caller renders as a 422. The validation mirrors the wire
/// contract: `scheme` must be in `{0,1,2}`, `signer` must be 64 lowercase hex
/// (a 32-byte Ed25519 key), and a block/time window must not be inverted.
/// `sealed=true` stays back-compat (scheme != 0); `label` is accepted but has no
/// effect in the core single-label index.
#[allow(clippy::result_large_err)]
fn build_record_filter(
    query: &ListQuery,
) -> std::result::Result<crate::chain::records::RecordFilter, (&'static str, String)> {
    if let Some(scheme) = query.scheme {
        if !(0..=2).contains(&scheme) {
            return Err((
                "validation-failed",
                "scheme must be one of 0 (open), 1 (sealed), or 2 (passphrase)".into(),
            ));
        }
    }

    let signer = match query.signer.as_deref() {
        Some(hex) => {
            if !is_signer_hex(hex) {
                return Err((
                    "validation-failed",
                    "signer must be 64 lowercase hex characters (a 32-byte Ed25519 key)".into(),
                ));
            }
            Some(hex::decode(hex).expect("validated hex"))
        }
        None => None,
    };

    if let (Some(from), Some(to)) = (query.from_block, query.to_block) {
        if from > to {
            return Err((
                "validation-failed",
                "from_block must not exceed to_block".into(),
            ));
        }
    }
    if let (Some(from), Some(to)) = (query.from_time, query.to_time) {
        if from > to {
            return Err((
                "validation-failed",
                "from_time must not exceed to_time".into(),
            ));
        }
    }

    Ok(crate::chain::records::RecordFilter {
        sealed_only: query.sealed.unwrap_or(false),
        scheme: query.scheme,
        signer,
        from_block: query.from_block,
        to_block: query.to_block,
        from_time: query.from_time,
        to_time: query.to_time,
    })
}

/// Whether a string is exactly 64 lowercase hex characters (a raw 32-byte key).
fn is_signer_hex(s: &str) -> bool {
    is_tx_hash(s)
}

/// Whether a string is exactly 64 lowercase hex characters.
fn is_tx_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// SHA-256 of a byte slice (the strong ETag of the CBOR body).
fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_hash_validation_is_strict() {
        assert!(is_tx_hash(&"a".repeat(64)));
        assert!(is_tx_hash(&"0123456789abcdef".repeat(4)));
        assert!(!is_tx_hash(&"A".repeat(64)), "uppercase rejected");
        assert!(!is_tx_hash(&"a".repeat(63)), "wrong length rejected");
        assert!(!is_tx_hash(&"g".repeat(64)), "non-hex rejected");
    }

    #[test]
    fn cursor_round_trips() {
        let c = encode_cursor(12345, &hex::decode("ab".repeat(32)).unwrap());
        let (bh, tx) = decode_cursor(&c).expect("decode");
        assert_eq!(bh, 12345);
        assert_eq!(tx, hex::decode("ab".repeat(32)).unwrap());
    }

    #[test]
    fn cursor_rejects_garbage() {
        assert_eq!(decode_cursor("!!!not-base64!!!"), None);
        assert_eq!(decode_cursor(""), None);
    }
}
