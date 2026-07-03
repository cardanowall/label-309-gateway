//! Projecting a claimed outbox row into the webhook wire envelope.
//!
//! Every delivery carries a lean envelope `{ id, type, created_at, data }`:
//!
//! - `id` is the per-delivery `Webhook-Id` (`kind:id:seq:endpoint_id`).
//! - `type` is the published wire event name (the same vocabulary the SSE stream
//!   and the published SDKs use), never an internal `event_type` literal.
//! - `created_at` is the RFC3339 instant the subject event was appended.
//! - `data` is the same JSON the SSE stream emits for that event, reused verbatim
//!   from the SSE snapshot builders so a webhook delivery and an SSE event for the
//!   same subject event carry byte-identical `data`: one projection, two
//!   transports.
//!
//! # One projection, both transports
//!
//! The `(subject_kind, event_type, payload)` triple a subject event carries is
//! projected to its wire name and visibility in exactly one place
//! ([`project_event`]), used by both the webhook fan-out and the SSE stream. A PoE
//! refund-intent is a billing-hook event: it projects to its own
//! `poe_refund_intent` wire name with `OperatorOnly` visibility and never reaches
//! an account-scoped reader, on either transport. Routing both transports through
//! the same closed mapping is what keeps a PoE refund-intent from collapsing into a
//! duplicate `poe_status_changed` on the SSE side, and what keeps every wire name
//! and visibility identical across the two transports.
//!
//! The `data` body is likewise built once per subject kind (`build_data` /
//! `build_account_event_data`) and reused by both transports, so a webhook
//! delivery and an SSE event for the same subject event carry byte-identical
//! `data`.

use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::ids::encode_poe_id;
use crate::api::sse::{balance_snapshot, poe_snapshot};
use crate::api::wire::is_wire_event_name;
use crate::chain::confirm::REFUND_INTENT_EVENT_TYPE;
use crate::webhook::fanout::ClaimedOutboxRow;
use crate::webhook::owner::kind;

/// Whether the wire event a subject event projects to is visible to an
/// account-scoped subscription, an operator-scoped subscription, or both.
///
/// Most events are visible to both an account and its operator firehose. A PoE
/// refund-intent is a billing-hook event the operator drives, so it is
/// operator-only even though it rides an account-owned `poe_record` subject; a
/// storage refund-intent rides an operator-only subject and is operator-only by
/// construction. The fan-out matcher consults this so an account subscription is
/// never offered an operator-only event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireVisibility {
    /// Delivered to the owning account and to its operator firehose.
    AccountAndOperator,
    /// Delivered only to the operator firehose; never to an account subscription.
    OperatorOnly,
}

/// The projected wire event name and its visibility for a claimed outbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEvent {
    /// The published wire event name (`poe_status_changed`, `balance_changed`, …).
    pub name: String,
    /// Which subscription scopes may receive this event.
    pub visibility: WireVisibility,
}

/// The internal event type the delivery worker appends when it auto-disables an
/// endpoint. It rides the endpoint owner's subject and projects to the
/// [`WEBHOOK_ENDPOINT_DISABLED_WIRE`] wire name.
pub const WEBHOOK_ENDPOINT_DISABLED_EVENT: &str = "webhook.endpoint_disabled";

/// The wire name an auto-disable event projects to.
pub const WEBHOOK_ENDPOINT_DISABLED_WIRE: &str = "webhook_endpoint_disabled";

/// Project a claimed outbox row to its wire event name and visibility.
///
/// A thin adapter over [`project_event`] for the webhook fan-out's row shape.
#[must_use]
pub fn project_wire_event(row: &ClaimedOutboxRow) -> Option<WireEvent> {
    project_event(&row.subject_kind, &row.event_type, &row.payload)
}

/// Project a subject event's `(subject_kind, event_type, payload)` to its wire
/// event name and visibility, transport-agnostically.
///
/// The mapping is closed against the engine's emitted `(subject_kind, event_type)`
/// pairs and is shared by every transport so a wire name and its visibility never
/// drift between the webhook fan-out and the SSE stream. An unrecognized
/// PoE/account event type falls through to the catch-all status/balance name so a
/// future additive event still delivers as a status change rather than being
/// dropped; an unrecognized subject kind is a producer/consumer mismatch the caller
/// treats as "no wire form".
#[must_use]
pub fn project_event(subject_kind: &str, event_type: &str, payload: &Value) -> Option<WireEvent> {
    match subject_kind {
        kind::POE_RECORD => Some(project_poe_event(event_type, payload)),
        kind::ACCOUNT => Some(project_account_event(event_type)),
        kind::STORAGE_FUNDING_SOURCE => Some(WireEvent {
            name: "storage_refund_intent".to_string(),
            // A storage refund-intent rides an operator-only subject; an account
            // subscription can never match it.
            visibility: WireVisibility::OperatorOnly,
        }),
        // An operator subject carries an operator-scoped endpoint's administrative
        // events; only the auto-disable rides it today, and it is operator-only.
        kind::OPERATOR if event_type == WEBHOOK_ENDPOINT_DISABLED_EVENT => Some(WireEvent {
            name: WEBHOOK_ENDPOINT_DISABLED_WIRE.to_string(),
            visibility: WireVisibility::OperatorOnly,
        }),
        _ => None,
    }
}

/// Project a `poe_record` event type to its wire name and visibility.
fn project_poe_event(event_type: &str, payload: &Value) -> WireEvent {
    match event_type {
        // A refund-intent is a billing-hook event the operator drives; a customer
        // never sees it, so it is operator-firehose only even though it rides an
        // account-owned record subject.
        REFUND_INTENT_EVENT_TYPE => WireEvent {
            name: "poe_refund_intent".to_string(),
            visibility: WireVisibility::OperatorOnly,
        },
        // A terminal Cardano submit error projects to its own wire name; every
        // other status transition is a status change.
        "permanent_failure" if terminal_submit_reason(payload) => WireEvent {
            name: "cardano_submission_failed".to_string(),
            visibility: WireVisibility::AccountAndOperator,
        },
        _ => WireEvent {
            name: "poe_status_changed".to_string(),
            visibility: WireVisibility::AccountAndOperator,
        },
    }
}

/// Project an `account` event type to its wire name. Account events are visible to
/// the owning account and its operator firehose.
fn project_account_event(event_type: &str) -> WireEvent {
    let name = match event_type {
        // A terminal upload failure rides the account stream but is not a balance
        // change: the account that sent the upload must re-send it, so it projects
        // to its own wire name rather than the balance catch-all.
        "storage.upload.failed" => "storage_upload_failed",
        // An auto-disable of one of this account's endpoints rides the account
        // subject; it is its own administrative event, not a balance change, so it
        // must not be misprojected onto the balance catch-all below.
        WEBHOOK_ENDPOINT_DISABLED_EVENT => WEBHOOK_ENDPOINT_DISABLED_WIRE,
        _ => "balance_changed",
    };
    WireEvent {
        name: name.to_string(),
        visibility: WireVisibility::AccountAndOperator,
    }
}

/// Whether a `permanent_failure` payload carries a terminal Cardano submit reason
/// (a build or byte-budget error raised on the submit path) rather than, say, a
/// post-confirm reorg.
fn terminal_submit_reason(payload: &Value) -> bool {
    payload
        .get("reason")
        .and_then(|r| r.as_str())
        .map(|reason| matches!(reason, "tx_build_failed" | "byte_budget_exceeded"))
        .unwrap_or(false)
}

/// The per-delivery `Webhook-Id` / `webhook_delivery.dedupe_key`:
/// `kind:id:seq:endpoint_id`.
///
/// Per-(event, subscription): the same logical event fans out to N subscriptions
/// and each subscriber must dedupe its own delivery stream, so the endpoint id is
/// part of the identity. A bare `kind:id:seq` would collide across two endpoints a
/// single receiver host runs.
#[must_use]
pub fn delivery_id(
    subject_kind: &str,
    subject_id: &str,
    subject_seq: i64,
    endpoint_id: uuid::Uuid,
) -> String {
    format!("{subject_kind}:{subject_id}:{subject_seq}:{endpoint_id}")
}

/// Build the frozen wire envelope body for a delivery: `{ id, type, created_at,
/// account_id, subject_id, data }`.
///
/// `webhook_id` is the per-delivery id (`delivery_id`), `wire_name` the projected
/// event name, and `data` is built from the shared SSE snapshot so the webhook
/// `data` equals the SSE `data` for the same event. The body is stored verbatim on
/// the delivery row and signed byte-for-byte, so a retry signs the identical bytes.
///
/// The top-level `account_id` and `subject_id` are documented routing fields so a
/// receiver routes by an explicit member rather than by string-parsing the
/// composite `Webhook-Id`. `account_id` is the wire-encoded owning account passed
/// in by the fan-out, which already resolved the subject's owner: `Some(account)`
/// for an account-owned subject (the account itself for an account subject, the
/// publishing account for a PoE subject), `None` for an operator-scoped subject
/// with no account. The envelope reuses that authoritative resolution rather than
/// re-querying, so a transient lookup error in the fan-out aborts the delivery (and
/// is retried) before any body is signed, instead of silently freezing a wrong
/// `account_id: null` into a signed envelope. `subject_id` is the wire-encoded
/// subject identity (the PoE record's wire id for a PoE subject, otherwise the raw
/// subject id). Both are additive: the prior `{ id, type, created_at, data }`
/// fields are unchanged.
pub async fn build_envelope(
    pool: &sqlx::PgPool,
    row: &ClaimedOutboxRow,
    webhook_id: &str,
    wire_name: &str,
    account_id: Option<Uuid>,
) -> crate::Result<Value> {
    // A transient DB error building the `data` snapshot propagates so the fan-out
    // transaction rolls back and the still-un-fanned outbox row is retried, rather
    // than freezing a materially wrong body (a stripped id-only PoE row, or a false
    // zero balance) into a delivery that is then signed byte-for-byte and sent.
    let data = build_data(pool, row).await?;
    let account_id = account_id
        .map(|a| json!(crate::api::ids::encode_account_id(a)))
        .unwrap_or(Value::Null);
    Ok(json!({
        "id": webhook_id,
        "type": wire_name,
        "created_at": row.created_at.to_rfc3339(),
        "account_id": account_id,
        "subject_id": envelope_subject_id(row),
        "data": data,
    }))
}

/// The wire-encoded subject identity for the envelope's `subject_id` routing field.
///
/// A PoE subject carries the record's wire id (the same id a client streams events
/// on); every other subject carries its raw subject id verbatim. A PoE subject id
/// that does not parse as a UUID falls back to the raw id, so the envelope is
/// always well-formed.
fn envelope_subject_id(row: &ClaimedOutboxRow) -> String {
    if row.subject_kind == kind::POE_RECORD {
        if let Ok(record_uuid) = Uuid::parse_str(&row.subject_id) {
            return encode_poe_id(record_uuid);
        }
    }
    row.subject_id.clone()
}

/// Build the `data` payload for a claimed outbox row, reusing the shared snapshot
/// builders so the webhook `data` matches the SSE `data`.
///
/// A transient DB error from a snapshot read propagates so the fan-out aborts and
/// retries rather than committing an incomplete body. A malformed subject id is not
/// an error: it cannot snapshot a row, so the envelope carries the raw id and is
/// still well-formed.
async fn build_data(pool: &sqlx::PgPool, row: &ClaimedOutboxRow) -> crate::Result<Value> {
    match row.subject_kind.as_str() {
        kind::POE_RECORD => match uuid::Uuid::parse_str(&row.subject_id) {
            // The fan-out resolves the subject's owner before building the body, and
            // a record event rides the record's own subject, so the snapshot is not
            // re-scoped to an account here (`None`).
            Ok(record_uuid) => {
                build_poe_event_data(pool, record_uuid, None, &row.event_type, &row.payload).await
            }
            // A malformed subject id cannot snapshot a record; carry the raw id so
            // the envelope is still well-formed rather than panicking.
            Err(_) => Ok(json!({ "id": row.subject_id })),
        },
        kind::ACCOUNT => match uuid::Uuid::parse_str(&row.subject_id) {
            Ok(account_id) => {
                build_account_event_data(pool, account_id, &row.event_type, &row.payload).await
            }
            Err(_) => Ok(json!({ "id": row.subject_id })),
        },
        // A storage funding-source subject (refund-intent) has no live snapshot to
        // re-project; the event payload itself is the data the operator's billing
        // integration consumes.
        _ => Ok(row.payload.clone()),
    }
}

/// Build the `data` body for an event on a `poe_record` subject, branching on the
/// event type so the SSE stream and the webhook fan-out project a record event
/// identically.
///
/// Every record event carries the record's current projected snapshot. A
/// `poe.refund-intent` additionally surfaces the network+service amount the engine
/// auto-credited back to the account on the permanent failure, lifted from the event
/// payload the emitter wrote, so an operator's billing integration can display
/// "refunded X" without summing the ledger. (Storage is never part of this amount:
/// the publish debit it reverses is network+service only, the ciphertext stays on
/// Arweave, and the storage charge is preserved.)
pub(crate) async fn build_poe_event_data(
    pool: &sqlx::PgPool,
    record_uuid: Uuid,
    account_scope: Option<Uuid>,
    event_type: &str,
    payload: &Value,
) -> crate::Result<Value> {
    let wire_id = encode_poe_id(record_uuid);
    let mut snapshot = poe_snapshot(pool, record_uuid, account_scope, &wire_id).await?;
    if event_type == REFUND_INTENT_EVENT_TYPE {
        if let (Some(obj), Some(refund)) = (
            snapshot.as_object_mut(),
            payload.get("refund_usd_micros").and_then(Value::as_i64),
        ) {
            obj.insert("refund_usd_micros".to_string(), Value::from(refund));
        }
    }
    Ok(snapshot)
}

/// Build the `data` body for an event on an account subject, branching on the
/// event type, so the SSE stream and the webhook fan-out project an account event
/// identically.
///
/// A `balance.changed` projects the current balance snapshot plus the signed delta
/// the triggering ledger entry recorded. A `storage.upload.failed` projects the
/// failed upload's identity (the attempt id, content hash, byte count, backend, and
/// reason) straight from the event payload, since the client must know which upload
/// to re-send, not its current balance. Any other account event carries the bare
/// balance snapshot.
pub(crate) async fn build_account_event_data(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    event_type: &str,
    payload: &Value,
) -> crate::Result<Value> {
    if event_type == crate::storage::STORAGE_UPLOAD_FAILED_EVENT {
        return Ok(project_upload_failure(payload));
    }

    let mut snapshot = balance_snapshot(pool, account_id).await?;
    // A balance change surfaces the signed delta the triggering ledger entry
    // recorded.
    if let Some(amount) = payload.get("amount_micros").and_then(Value::as_i64) {
        if let Some(obj) = snapshot.as_object_mut() {
            obj.insert(
                "change_usd_micros".to_string(),
                Value::String(amount.to_string()),
            );
        }
    }
    Ok(snapshot)
}

/// Project a `storage.upload.failed` event payload to its wire `data`: the upload's
/// identity (`attempt_id`, `sha256`, `bytes`, `backend`, `reason`) the client needs
/// to re-send the failed upload. The fields are carried verbatim from the durable
/// event payload the emitter wrote; an absent field is simply omitted.
fn project_upload_failure(payload: &Value) -> Value {
    let mut obj = serde_json::Map::new();
    for field in ["attempt_id", "sha256", "bytes", "backend", "reason"] {
        if let Some(value) = payload.get(field) {
            obj.insert(field.to_string(), value.clone());
        }
    }
    Value::Object(obj)
}

/// Whether a wire event name is one a subscription may filter on. Re-exported via
/// [`is_wire_event_name`] so the fan-out filter and the registration validation
/// share one vocabulary.
#[must_use]
pub fn is_filterable(name: &str) -> bool {
    is_wire_event_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn row(subject_kind: &str, event_type: &str, payload: Value) -> ClaimedOutboxRow {
        ClaimedOutboxRow {
            id: Uuid::now_v7(),
            subject_kind: subject_kind.to_string(),
            subject_id: Uuid::now_v7().to_string(),
            subject_seq: 1,
            event_type: event_type.to_string(),
            payload,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn poe_status_transitions_project_to_status_changed_for_both_scopes() {
        for event_type in ["submitted", "confirmed"] {
            let ev = project_wire_event(&row(kind::POE_RECORD, event_type, json!({}))).unwrap();
            assert_eq!(ev.name, "poe_status_changed");
            assert_eq!(ev.visibility, WireVisibility::AccountAndOperator);
        }
    }

    #[test]
    fn terminal_submit_failure_projects_to_submission_failed() {
        for reason in ["tx_build_failed", "byte_budget_exceeded"] {
            let ev = project_wire_event(&row(
                kind::POE_RECORD,
                "permanent_failure",
                json!({ "reason": reason }),
            ))
            .unwrap();
            assert_eq!(ev.name, "cardano_submission_failed");
            assert_eq!(ev.visibility, WireVisibility::AccountAndOperator);
        }
    }

    #[test]
    fn non_terminal_permanent_failure_is_a_status_change() {
        // A post-confirm reorg failure is a status change, not a submission error.
        let ev = project_wire_event(&row(
            kind::POE_RECORD,
            "permanent_failure",
            json!({ "reason": "rollback_retries_exhausted" }),
        ))
        .unwrap();
        assert_eq!(ev.name, "poe_status_changed");
    }

    #[test]
    fn poe_refund_intent_is_operator_only() {
        // A PoE refund-intent is a billing-hook event: it projects to its own wire
        // name and is suppressed for an account subscription.
        let ev =
            project_wire_event(&row(kind::POE_RECORD, "poe.refund-intent", json!({}))).unwrap();
        assert_eq!(ev.name, "poe_refund_intent");
        assert_eq!(ev.visibility, WireVisibility::OperatorOnly);
    }

    #[test]
    fn account_events_project_to_balance_and_upload_failed() {
        let balance =
            project_wire_event(&row(kind::ACCOUNT, "balance.changed", json!({}))).unwrap();
        assert_eq!(balance.name, "balance_changed");
        assert_eq!(balance.visibility, WireVisibility::AccountAndOperator);

        let upload =
            project_wire_event(&row(kind::ACCOUNT, "storage.upload.failed", json!({}))).unwrap();
        assert_eq!(upload.name, "storage_upload_failed");
        assert_eq!(upload.visibility, WireVisibility::AccountAndOperator);
    }

    #[test]
    fn storage_funding_source_refund_intent_is_operator_only() {
        let ev = project_wire_event(&row(
            kind::STORAGE_FUNDING_SOURCE,
            "storage.refund-intent",
            json!({}),
        ))
        .unwrap();
        assert_eq!(ev.name, "storage_refund_intent");
        assert_eq!(ev.visibility, WireVisibility::OperatorOnly);
    }

    #[test]
    fn auto_disable_on_an_account_subject_projects_to_its_own_wire_name() {
        // The auto-disable event rides the account subject but must NOT be
        // misprojected onto the balance catch-all; it is its own administrative
        // event, visible to the account and its operator firehose.
        let ev = project_wire_event(&row(
            kind::ACCOUNT,
            WEBHOOK_ENDPOINT_DISABLED_EVENT,
            json!({ "endpoint_id": "x", "reason": "consecutive_failures" }),
        ))
        .unwrap();
        assert_eq!(ev.name, WEBHOOK_ENDPOINT_DISABLED_WIRE);
        assert_ne!(ev.name, "balance_changed");
        assert_eq!(ev.visibility, WireVisibility::AccountAndOperator);
    }

    #[test]
    fn auto_disable_on_an_operator_subject_is_operator_only() {
        let ev = project_wire_event(&row(
            kind::OPERATOR,
            WEBHOOK_ENDPOINT_DISABLED_EVENT,
            json!({ "endpoint_id": "x", "reason": "stale" }),
        ))
        .unwrap();
        assert_eq!(ev.name, WEBHOOK_ENDPOINT_DISABLED_WIRE);
        assert_eq!(ev.visibility, WireVisibility::OperatorOnly);
    }

    #[test]
    fn unknown_subject_kind_has_no_wire_form() {
        assert!(project_wire_event(&row("not_a_real_kind", "whatever", json!({}))).is_none());
        // An operator subject carrying an unexpected event type also has no wire
        // form (only the auto-disable rides the operator subject today).
        assert!(project_wire_event(&row(kind::OPERATOR, "something_else", json!({}))).is_none());
    }

    #[test]
    fn every_projected_name_is_filterable() {
        // Every name the projection can emit must be in the published filter
        // vocabulary, so a subscription that filters on a real delivered name never
        // silently never-matches.
        for ev in [
            project_wire_event(&row(kind::POE_RECORD, "submitted", json!({}))),
            project_wire_event(&row(
                kind::POE_RECORD,
                "permanent_failure",
                json!({ "reason": "tx_build_failed" }),
            )),
            project_wire_event(&row(kind::POE_RECORD, "poe.refund-intent", json!({}))),
            project_wire_event(&row(kind::ACCOUNT, "balance.changed", json!({}))),
            project_wire_event(&row(kind::ACCOUNT, "storage.upload.failed", json!({}))),
            project_wire_event(&row(
                kind::STORAGE_FUNDING_SOURCE,
                "storage.refund-intent",
                json!({}),
            )),
        ] {
            let ev = ev.expect("a known kind projects");
            assert!(is_filterable(&ev.name), "{} must be filterable", ev.name);
        }
    }

    #[test]
    fn delivery_id_is_kind_id_seq_endpoint() {
        let endpoint = Uuid::now_v7();
        let id = delivery_id("poe_record", "abc", 7, endpoint);
        assert_eq!(id, format!("poe_record:abc:7:{endpoint}"));
    }

    #[test]
    fn project_event_matches_project_wire_event_for_every_known_pair() {
        // The transport-agnostic projection and the outbox-row adapter must agree:
        // both transports read the same closed mapping, so a wire name and its
        // visibility never drift between the SSE stream and the webhook fan-out.
        for (subject_kind, event_type, payload) in [
            (kind::POE_RECORD, "submitted", json!({})),
            (
                kind::POE_RECORD,
                "permanent_failure",
                json!({ "reason": "tx_build_failed" }),
            ),
            (kind::POE_RECORD, "poe.refund-intent", json!({})),
            (kind::ACCOUNT, "balance.changed", json!({})),
            (kind::ACCOUNT, "storage.upload.failed", json!({})),
            (
                kind::STORAGE_FUNDING_SOURCE,
                "storage.refund-intent",
                json!({}),
            ),
            (kind::OPERATOR, WEBHOOK_ENDPOINT_DISABLED_EVENT, json!({})),
            ("not_a_real_kind", "whatever", json!({})),
        ] {
            assert_eq!(
                project_event(subject_kind, event_type, &payload),
                project_wire_event(&row(subject_kind, event_type, payload.clone())),
                "project_event and project_wire_event disagree on ({subject_kind}, {event_type})"
            );
        }
    }

    #[test]
    fn upload_failure_data_carries_the_upload_identity() {
        // The storage.upload.failed event data projects the upload's identity (the
        // keys the client needs to re-send), not a balance snapshot.
        let payload = json!({
            "attempt_id": "11111111-1111-1111-1111-111111111111",
            "sha256": "ab".repeat(32),
            "bytes": 4096,
            "backend": "turbo",
            "reason": "backend_rejected",
        });
        let data = project_upload_failure(&payload);
        assert_eq!(data["attempt_id"], payload["attempt_id"]);
        assert_eq!(data["sha256"], payload["sha256"]);
        assert_eq!(data["bytes"], json!(4096));
        assert_eq!(data["backend"], json!("turbo"));
        assert_eq!(data["reason"], json!("backend_rejected"));
        // It is not a balance snapshot.
        assert!(data.get("balance_usd_micros").is_none());
    }

    #[test]
    fn upload_failure_data_omits_absent_fields() {
        // A payload missing some identity fields projects only the present ones,
        // rather than emitting nulls.
        let data = project_upload_failure(&json!({ "attempt_id": "x", "reason": "lost" }));
        assert_eq!(data["attempt_id"], json!("x"));
        assert_eq!(data["reason"], json!("lost"));
        assert!(data.get("sha256").is_none());
        assert!(data.get("bytes").is_none());
        assert!(data.get("backend").is_none());
    }
}
