//! Durable, resumable Server-Sent Events streams.
//!
//! Two streams ride the durable `cw_core.subject_event` log: the PoE status
//! stream (`subject_kind = 'poe_record'`) and the balance stream
//! (`subject_kind = 'account'`). Each connection sends an initial `state` event
//! built from the current DB row, then replays events as their `subject_seq`
//! advances.
//!
//! # Durable resume
//!
//! The SSE `id` of each event is its `subject_seq`. The initial `state` event
//! carries the subject's current high-water sequence as its id, so a client that
//! disconnects after seeing only the state event still resumes correctly. A
//! reconnecting client sends `Last-Event-ID: <seq>`; the stream replays only
//! events `WHERE subject_seq > last`, so no event is missed across a reconnect.
//! Resume is additive: a published SDK that ignores the id still sees the initial
//! state and every subsequent event live.
//!
//! # Wake-hint + poll fallback
//!
//! One shared [`PgListener`] per instance LISTENs on the `subject_event` NOTIFY
//! channel and fans every notification out to the live streams as a unit
//! wake-hint over a broadcast channel — a stream never holds a Postgres
//! connection of its own, so ten thousand streams still cost exactly one
//! listener backend. Correctness never depends on a notification arriving: each
//! stream also polls the durable log on a fixed interval, so a dropped, lagged,
//! or coalesced wake-hint only adds latency. A ping is emitted every 30 seconds
//! to keep intermediaries from closing an idle connection.
//!
//! # Live-stream caps
//!
//! A stream is long-lived state (a task, a broadcast receiver, periodic log
//! reads), and the request rate limiter meters only its OPEN, so concurrency is
//! bounded separately: [`SseState`] enforces a per-account and an instance-wide
//! ceiling on live streams, releasing the slot when the stream drops on any path
//! (client disconnect, error, completion) via an RAII guard held by the stream
//! itself.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use futures_util::stream::{self, Stream};
use sqlx::postgres::PgListener;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::api::ids::decode_poe_id;
use crate::api::middleware::scope;
use crate::api::problem::Problem;
use crate::api::routes::guard;
use crate::api::state::AppState;
use crate::api::wire::WireStatus;
use crate::ledger::journal::ACCOUNT_SUBJECT_KIND;
use crate::webhook::{
    build_account_event_data, build_poe_event_data, project_event, WireEvent, WireVisibility,
};
use crate::SUBJECT_EVENT_CHANNEL;

/// The keep-alive ping cadence.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// The poll-fallback cadence for re-reading the durable event log when no
/// wake-hint arrives.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The engine `subject_kind` discriminator for a PoE record's events.
const POE_SUBJECT_KIND: &str = "poe_record";

/// The default instance-wide ceiling on concurrently live SSE streams. Bounds
/// the total long-lived stream state one instance carries; three decimal orders
/// above what a single-instance deployment's interactive clients need.
pub const DEFAULT_SSE_MAX_STREAMS: u32 = 1024;

/// The default per-account ceiling on concurrently live SSE streams. One
/// account legitimately holds a few streams (a balance stream plus a record
/// stream per in-flight publish, times a handful of tabs); 32 clears that with
/// room while keeping any single credential from monopolising the instance cap.
pub const DEFAULT_SSE_MAX_STREAMS_PER_ACCOUNT: u32 = 32;

/// The caps on concurrently live SSE streams.
///
/// Both ceilings exist because a stream's cost is CONCURRENCY, not request
/// rate: the sliding-window limiter meters only the open. The per-account cap
/// stops one credential from monopolising the instance; the instance cap bounds
/// the aggregate even across many accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseLimits {
    /// The instance-wide ceiling on concurrently live streams.
    pub max_streams: u32,
    /// The per-account ceiling on concurrently live streams.
    pub max_streams_per_account: u32,
}

impl Default for SseLimits {
    fn default() -> Self {
        Self {
            max_streams: DEFAULT_SSE_MAX_STREAMS,
            max_streams_per_account: DEFAULT_SSE_MAX_STREAMS_PER_ACCOUNT,
        }
    }
}

/// The shared SSE seam: the live-stream cap registry and the one-per-instance
/// NOTIFY fan-out.
///
/// Cloning shares the underlying registry and fan-out, so every handler (and
/// every clone of [`crate::api::state::AppState`]) enforces one set of caps and
/// rides one listener connection.
#[derive(Clone)]
pub struct SseState {
    inner: Arc<SseShared>,
}

/// The state behind [`SseState`]: the caps, the live-stream counts, and the
/// lazily started shared listener's broadcast sender.
struct SseShared {
    limits: SseLimits,
    registry: Mutex<SseRegistry>,
    /// The shared NOTIFY fan-out, started on the first stream that subscribes.
    /// Lazy because starting it needs a running async runtime, which a plain
    /// `AppState::new` construction site (a test building state synchronously)
    /// does not have.
    wake: OnceLock<broadcast::Sender<()>>,
}

/// The live-stream counts the caps are enforced against.
#[derive(Default)]
struct SseRegistry {
    /// Live streams across the whole instance.
    total: u32,
    /// Live streams per account. Entries are removed when they reach zero so the
    /// map never grows past the set of accounts with a live stream.
    per_account: HashMap<Uuid, u32>,
}

/// An RAII slot in the live-stream registry. Held by the stream's unfold state,
/// so it is released on EVERY termination path — client disconnect (the stream
/// is dropped), a read error (the unfold returns `None` and the state drops),
/// or completion — without any path having to remember to release it.
pub(crate) struct SseSlot {
    shared: Arc<SseShared>,
    account_id: Uuid,
}

impl Drop for SseSlot {
    fn drop(&mut self) {
        let mut registry = self
            .shared
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.total = registry.total.saturating_sub(1);
        if let Some(count) = registry.per_account.get_mut(&self.account_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                registry.per_account.remove(&self.account_id);
            }
        }
    }
}

impl SseState {
    /// Build the seam over a set of caps.
    #[must_use]
    pub fn new(limits: SseLimits) -> Self {
        Self {
            inner: Arc::new(SseShared {
                limits,
                registry: Mutex::new(SseRegistry::default()),
                wake: OnceLock::new(),
            }),
        }
    }

    /// Reserve a live-stream slot for an account, or `None` when either ceiling
    /// is already reached. The returned guard releases the slot on drop.
    fn try_acquire(&self, account_id: Uuid) -> Option<SseSlot> {
        let mut registry = self
            .inner
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if registry.total >= self.inner.limits.max_streams {
            return None;
        }
        let count = registry.per_account.entry(account_id).or_insert(0);
        if *count >= self.inner.limits.max_streams_per_account {
            return None;
        }
        *count += 1;
        registry.total += 1;
        Some(SseSlot {
            shared: self.inner.clone(),
            account_id,
        })
    }

    /// Subscribe to the shared NOTIFY fan-out, starting its listener task on the
    /// first call. Every subscriber shares the one listener connection; a
    /// subscriber that lags simply misses coalesced wake-hints, which the poll
    /// fallback already tolerates.
    fn subscribe(&self, pool: &sqlx::PgPool) -> broadcast::Receiver<()> {
        self.inner
            .wake
            .get_or_init(|| spawn_shared_listener(pool.clone()))
            .subscribe()
    }
}

/// Start the one-per-instance NOTIFY listener task and return its fan-out
/// sender.
///
/// The task holds the instance's single listener connection, LISTENs on the
/// subject-event channel, and forwards every notification as a unit wake-hint.
/// It is deliberately indestructible: a connect or listen failure backs off one
/// poll interval and retries, and while it is down every stream still makes
/// progress on the poll fallback — the wake-hint is an optimisation, never a
/// correctness dependency.
fn spawn_shared_listener(pool: sqlx::PgPool) -> broadcast::Sender<()> {
    // A small buffer is enough: the hint carries no data, and a lagged receiver
    // just re-reads the log once, exactly as it would on a poll tick.
    let (sender, _) = broadcast::channel(64);
    let fan_out = sender.clone();
    tokio::spawn(async move {
        loop {
            let mut listener = match PgListener::connect_with(&pool).await {
                Ok(l) => l,
                Err(_) => {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            };
            if listener.listen(SUBJECT_EVENT_CHANNEL).await.is_err() {
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
            // Fan every NOTIFY out as a unit hint. The notification names a
            // subject, but each stream re-reads its own slice of the log on any
            // wake, so the subject is not forwarded (an unrelated wake costs one
            // extra query, the same trade the per-stream listener made).
            while let Ok(_notification) = listener.recv().await {
                let _ = fan_out.send(());
            }
            // recv failed: the connection was lost. Back off a beat and rebuild.
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
    sender
}

/// `GET /api/v1/poe/events/{poe_id}` — stream a record's status changes.
///
/// Requires `poe:read`. Validates and decodes the `poe_<crockford>` id, confirms
/// the record exists **and belongs to the viewer's account**, then opens the
/// durable SSE stream over the record's subject events. Each event projects to its
/// wire SSE name via the shared projection and carries the record's current row
/// snapshot as its payload; an operator-only event such as a billing-hook
/// refund-intent is suppressed on this account-grade stream.
///
/// The ownership predicate makes a foreign or non-existent id indistinguishably a
/// 404: a `poe_record` is account-owned engine state, not public chain data, so a
/// viewer must never stream the status, tx hash, or event log of a record under
/// another account.
pub async fn poe_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(poe_id): Path<String>,
) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let viewer = match guard::authorize(&state, &headers, scope::SCOPE_POE_READ, 1, trace).await {
        Ok((v, _)) => v,
        Err(resp) => return resp,
    };

    let Some(record_uuid) = decode_poe_id(&poe_id) else {
        return Problem::of("invalid-poe-id", "the PoE id could not be decoded")
            .into_response_with(base, trace);
    };

    // Confirm the record exists AND is owned by the viewer's account before opening
    // the stream (a 404 cannot be sent mid-stream). A DB error here is surfaced as a
    // 503 rather than masked as a 404, so a transient blip never reads as "no such
    // record". A record owned by another account is indistinguishable from a missing
    // one: the stream is an account-scoped read, never a cross-tenant oracle.
    let exists: Result<Option<i32>, sqlx::Error> =
        sqlx::query_scalar("SELECT 1 FROM cw_core.poe_record WHERE id = $1 AND account_id = $2")
            .bind(record_uuid)
            .bind(viewer.account_id)
            .fetch_optional(&state.pool)
            .await;
    match exists {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Problem::of("not-found", "no such PoE record").into_response_with(base, trace);
        }
        Err(_) => {
            return Problem::of(
                "service-unavailable",
                "the record lookup is temporarily unavailable",
            )
            .into_response_with(base, trace);
        }
    }

    let Some(slot) = state.sse.try_acquire(viewer.account_id) else {
        return stream_cap_reached(base, trace);
    };

    let last_event_id = parse_last_event_id(&headers);
    open_stream(
        state,
        SubjectStream::Poe {
            record_uuid,
            account_id: viewer.account_id,
            wire_id: poe_id,
        },
        record_uuid.to_string(),
        last_event_id,
        slot,
    )
    .into_response()
}

/// `GET /api/v1/account/balance/events` — stream the account's balance changes.
///
/// Requires `account:read`. Opens the durable SSE stream over the account's
/// `balance.changed` subject events, each carrying the account's current balance.
pub async fn balance_events(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let trace = guard::new_trace_id();
    let base = &state.config.problem_type_base;

    let viewer = match guard::authorize(&state, &headers, scope::SCOPE_ACCOUNT_READ, 1, trace).await
    {
        Ok((v, _)) => v,
        Err(resp) => return resp,
    };

    let Some(slot) = state.sse.try_acquire(viewer.account_id) else {
        return stream_cap_reached(base, trace);
    };

    let last_event_id = parse_last_event_id(&headers);
    let account_id = viewer.account_id;
    open_stream(
        state,
        SubjectStream::Balance { account_id },
        account_id.to_string(),
        last_event_id,
        slot,
    )
    .into_response()
}

/// The 429 a stream open receives when a live-stream ceiling is already
/// reached. `Retry-After` names the poll interval: by then a just-closed
/// stream's slot has certainly been released, so an honest client that lost a
/// race with its own reconnect retries successfully.
fn stream_cap_reached(base: &str, trace: Uuid) -> Response {
    Problem::of(
        "rate-limited",
        "too many concurrent event streams are open for this account or this instance; \
         close an existing stream and retry",
    )
    .with_retry_after(POLL_INTERVAL.as_secs())
    .into_response_with(base, trace)
}

/// Which wire stream a connection is, carrying the coordinates each handler needs
/// to build the `state` snapshot and project event payloads.
#[derive(Debug, Clone)]
enum SubjectStream {
    /// A PoE status stream over one record.
    Poe {
        /// The record's UUID (the durable key, and the `subject_id`).
        record_uuid: Uuid,
        /// The viewer's account id. Every record-row read on this stream carries it
        /// as an ownership predicate, so a record that changed hands (or was never
        /// the viewer's) never projects.
        account_id: Uuid,
        /// The record's wire id (`poe_<crockford>`), echoed in payloads.
        wire_id: String,
    },
    /// A balance stream over one account.
    Balance {
        /// The account's UUID (the `subject_id`).
        account_id: Uuid,
    },
}

impl SubjectStream {
    /// The engine `subject_kind` this stream rides.
    fn subject_kind(&self) -> &'static str {
        match self {
            SubjectStream::Poe { .. } => POE_SUBJECT_KIND,
            SubjectStream::Balance { .. } => ACCOUNT_SUBJECT_KIND,
        }
    }
}

/// Open the durable SSE stream for a subject from an optional resume point.
///
/// Emits the initial `state` event built from the current DB row (its `id` the
/// subject's current high-water sequence), then streams every event with
/// `subject_seq` greater than the last delivered: a shared NOTIFY wake-hint or
/// the poll fallback drives each re-read. A 30-second keep-alive ping holds the
/// connection open. When the client resumes with `Last-Event-ID`, replay starts
/// immediately after that sequence so no event is missed.
///
/// `slot` is the stream's reservation in the live-stream registry; parking it in
/// the unfold state ties its release to the stream's own lifetime, so every
/// disconnect path (client drop, read error, completion) frees the slot.
fn open_stream(
    state: AppState,
    kind: SubjectStream,
    subject_id: String,
    resume_after: Option<i64>,
    slot: SseSlot,
) -> Sse<impl Stream<Item = std::result::Result<Event, Infallible>>> {
    // State threaded through the unfold: the pool, the subject coordinates, the
    // last-delivered sequence, the shared wake-hint receiver, whether the initial
    // state event has been sent, and the live-stream slot (held only for its Drop).
    struct StreamState {
        pool: sqlx::PgPool,
        kind: SubjectStream,
        subject_kind: &'static str,
        subject_id: String,
        resume_after: Option<i64>,
        last_seq: i64,
        sent_initial: bool,
        wake: broadcast::Receiver<()>,
        _slot: SseSlot,
    }

    // Subscribe to the shared fan-out BEFORE the first log read, so an event
    // committed between the initial snapshot and the first wait still hints; the
    // poll fallback covers it regardless.
    let wake = state.sse.subscribe(&state.pool);

    let subject_kind = kind.subject_kind();
    let seed = StreamState {
        pool: state.pool.clone(),
        kind,
        subject_kind,
        subject_id,
        resume_after,
        last_seq: 0,
        sent_initial: false,
        wake,
        _slot: slot,
    };

    let body = stream::unfold(seed, move |mut st| async move {
        // First poll: build the current snapshot, set the resume high-water mark,
        // attach the NOTIFY listener, and emit the initial `state` event.
        if !st.sent_initial {
            st.sent_initial = true;

            // A high-water read failure ends the stream rather than defaulting to 0:
            // a default-0 resume floor would replay the subject's entire event
            // history. Ending the connection lets the client reconnect and re-read a
            // real high-water mark instead.
            let high_water = match current_max_seq(&st.pool, st.subject_kind, &st.subject_id).await
            {
                Ok(seq) => seq,
                Err(_) => return None,
            };
            // Replay from where the client left off; a fresh connection starts at
            // the current high-water mark so it streams only NEW events.
            st.last_seq = st.resume_after.unwrap_or(high_water);

            // A snapshot read failure ends the stream rather than emitting a
            // fabricated state payload (a false zero balance, or a stripped id-only
            // PoE row). The client reconnects and re-reads the true snapshot.
            let payload = match build_state_payload(&st.pool, &st.kind).await {
                Ok(payload) => payload,
                Err(_) => return None,
            };
            let ev = Event::default()
                .id(high_water.to_string())
                .event("state")
                .data(payload.to_string());
            return Some((Ok(ev), st));
        }

        loop {
            // Re-read the durable log for the next event past the last delivered. A
            // read failure ends the stream (the client reconnects and resumes from
            // its Last-Event-ID) rather than silently stalling past the failure.
            let next: Option<(i64, String, serde_json::Value)> = match sqlx::query_as(
                "SELECT subject_seq, event_type, payload FROM cw_core.subject_event \
                 WHERE subject_kind = $1 AND subject_id = $2 AND subject_seq > $3 \
                 ORDER BY subject_seq LIMIT 1",
            )
            .bind(st.subject_kind)
            .bind(&st.subject_id)
            .bind(st.last_seq)
            .fetch_optional(&st.pool)
            .await
            {
                Ok(row) => row,
                Err(_) => return None,
            };

            if let Some((seq, event_type, payload)) = next {
                st.last_seq = seq;
                // Project through the one shared mapping the webhook fan-out uses,
                // so a wire name and its visibility never drift between the two
                // transports. An event with no wire form, or one visible only to the
                // operator firehose (a billing-hook event such as a PoE
                // refund-intent), is not surfaced on this account-grade stream: it is
                // skipped and the loop advances to the next event rather than
                // emitting a spurious frame.
                let Some(wire) = project_stream_event(st.subject_kind, &event_type, &payload)
                else {
                    continue;
                };
                // A snapshot read failure while building the event payload ends the
                // stream rather than emitting a degraded payload (a stripped id-only
                // row, or a false zero balance) under a real wire event name.
                let data =
                    match build_event_payload(&st.pool, &st.kind, &event_type, &payload).await {
                        Ok(data) => data,
                        Err(_) => return None,
                    };
                let ev = Event::default()
                    .id(seq.to_string())
                    .event(wire.name)
                    .data(data.to_string());
                return Some((Ok(ev), st));
            }

            // No new event: wait for a wake-hint or the poll interval, then
            // re-check. The keep-alive layer emits pings independently so the
            // connection stays open while we wait.
            wait_for_wake(&mut st.wake).await;
        }
    });

    Sse::new(body).keep_alive(
        KeepAlive::new()
            .interval(PING_INTERVAL)
            .event(Event::default().event("ping").data("{}")),
    )
}

/// Wait for the next wake: a hint from the shared NOTIFY fan-out, or the poll
/// interval elapsing, whichever comes first.
///
/// The hint is unit: the underlying notification named a subject, but the
/// stream re-reads its own slice of the log on any wake, so an unrelated hint
/// only costs one extra query. A lagged receiver (the fan-out coalesced hints
/// past its buffer) is just a wake; a closed fan-out — unreachable while any
/// stream holds its `SseState` — degrades to the plain poll sleep rather than a
/// busy loop.
async fn wait_for_wake(wake: &mut broadcast::Receiver<()>) {
    if let Ok(Err(broadcast::error::RecvError::Closed)) =
        tokio::time::timeout(POLL_INTERVAL, wake.recv()).await
    {
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The subject's current maximum `subject_seq`, or 0 when it has no events yet.
///
/// A DB error returns `Err` rather than collapsing to 0: a high-water read failure
/// must not be indistinguishable from a genuinely empty subject, or a fresh
/// connection would resume from seq 0 and replay the subject's entire history. Only
/// a successful query with no rows (an empty subject) yields `Ok(0)`.
async fn current_max_seq(
    pool: &sqlx::PgPool,
    subject_kind: &str,
    subject_id: &str,
) -> crate::Result<i64> {
    let max: Option<i64> = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT max(subject_seq) FROM cw_core.subject_event \
         WHERE subject_kind = $1 AND subject_id = $2",
    )
    .bind(subject_kind)
    .bind(subject_id)
    .fetch_one(pool)
    .await?;
    Ok(max.unwrap_or(0))
}

/// Build the initial `state` event payload from the current DB row.
///
/// For a PoE stream this is the record's current projected snapshot scoped to the
/// viewer's account; for a balance stream the account's current balance. A DB error
/// propagates so the stream fails the connection rather than emitting a fabricated
/// snapshot.
async fn build_state_payload(
    pool: &sqlx::PgPool,
    kind: &SubjectStream,
) -> crate::Result<serde_json::Value> {
    match kind {
        SubjectStream::Poe {
            record_uuid,
            account_id,
            wire_id,
        } => poe_snapshot(pool, *record_uuid, Some(*account_id), wire_id).await,
        SubjectStream::Balance { account_id } => balance_snapshot(pool, *account_id).await,
    }
}

/// Build the payload for a live event.
///
/// Both branches go through the shared event-data builders so the SSE stream and
/// the webhook fan-out project the same subject event to byte-identical `data`. A
/// PoE event re-projects the record's current row so every `poe_status_changed`
/// carries the full current state (the durable event row alone holds only the delta
/// that triggered it), and a `poe_refund_intent` additionally surfaces the
/// auto-credited refund amount. An account event branches on the event type so a
/// balance change carries the new balance plus its delta while an upload failure
/// carries the failed upload's identity.
async fn build_event_payload(
    pool: &sqlx::PgPool,
    kind: &SubjectStream,
    event_type: &str,
    event_payload: &serde_json::Value,
) -> crate::Result<serde_json::Value> {
    match kind {
        SubjectStream::Poe {
            record_uuid,
            account_id,
            ..
        } => {
            build_poe_event_data(
                pool,
                *record_uuid,
                Some(*account_id),
                event_type,
                event_payload,
            )
            .await
        }
        SubjectStream::Balance { account_id } => {
            build_account_event_data(pool, *account_id, event_type, event_payload).await
        }
    }
}

/// The current projected snapshot of a PoE record, as the `state`/event payload.
///
/// Mirrors the record read surface: the wire id, the projected wire status,
/// tx hash, on-chain coordinates, and confirmations derived from the materialised
/// tip (`max(0, tip - block_height + 1)`). A record that does not exist (or, under
/// an `account_scope`, is not owned by that account) projects to a minimal payload
/// carrying just its id.
///
/// `account_scope` constrains the read to a record owned by that account, for the
/// account-scoped SSE stream. The webhook fan-out passes `None`: it has already
/// resolved the subject's owner before building the body, and a record event rides
/// the record's own subject, so re-scoping there would be redundant.
///
/// A transient DB error returns `Err` rather than a fabricated id-only payload, so
/// a caller (the webhook fan-out, or the SSE stream) fails and retries instead of
/// freezing a materially incomplete projection. The id-only payload is reserved for
/// a genuine "no such (owned) record" — a successful query that returned no row.
///
/// Shared with the webhook fan-out so a `poe_status_changed` delivered over a
/// webhook carries byte-identical `data` to the same event streamed over SSE: one
/// projection, two transports.
pub(crate) async fn poe_snapshot(
    pool: &sqlx::PgPool,
    record_uuid: Uuid,
    account_scope: Option<Uuid>,
    wire_id: &str,
) -> crate::Result<serde_json::Value> {
    let row: Option<PoeRow> = sqlx::query_as(
        "SELECT r.status, r.tx_hash, r.block_height, r.block_time, r.request_id, \
                t.tip_block_height \
         FROM cw_core.poe_record r \
         LEFT JOIN LATERAL ( \
             SELECT tip_block_height FROM cw_core.cardano_tip \
             ORDER BY tip_observed_at DESC LIMIT 1 \
         ) t ON true \
         WHERE r.id = $1 AND ($2::uuid IS NULL OR r.account_id = $2)",
    )
    .bind(record_uuid)
    .bind(account_scope)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(serde_json::json!({ "id": wire_id }));
    };

    let status = WireStatus::from_core(&row.status).map(WireStatus::as_str);
    let num_confirmations = match (row.tip_block_height, row.block_height) {
        (Some(tip), Some(height)) => (tip - height + 1).max(0),
        _ => 0,
    };

    Ok(serde_json::json!({
        "id": wire_id,
        "status": status,
        "tx_hash": row.tx_hash.as_deref().map(hex::encode),
        "block_height": row.block_height,
        "block_time": row.block_time.map(|t| t.to_rfc3339()),
        "num_confirmations": num_confirmations,
        "request_id": row.request_id,
    }))
}

/// The current balance snapshot for an account, as the `state`/event payload. A
/// micro-USD bigint serialized as a decimal string (never a JSON number, which
/// would lose precision past 2^53). An account with no ledger activity reads "0".
///
/// A transient DB error returns `Err` rather than coercing the failure into a
/// signed `"0"` balance: the `"0"` payload is reserved for a SUCCESSFUL query that
/// `coalesce`s a missing balance row to zero (genuine no-activity), never for a
/// read failure. A caller that signs this projection (the webhook fan-out) must
/// fail and retry the whole delivery rather than freeze a false zero-balance event
/// that cannot be retracted once signed and sent.
///
/// Shared with the webhook fan-out so a `balance_changed` delivered over a webhook
/// carries the same balance projection as the SSE balance stream.
pub(crate) async fn balance_snapshot(
    pool: &sqlx::PgPool,
    account_id: Uuid,
) -> crate::Result<serde_json::Value> {
    let balance_micros: i64 = sqlx::query_scalar(
        "SELECT coalesce((SELECT balance_micros FROM cw_core.balance WHERE account_id = $1), 0)",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await?;

    Ok(serde_json::json!({ "balance_usd_micros": balance_micros.to_string() }))
}

/// The columns the PoE snapshot reads, with the materialised tip joined in.
#[derive(sqlx::FromRow)]
struct PoeRow {
    status: String,
    tx_hash: Option<Vec<u8>>,
    block_height: Option<i64>,
    block_time: Option<DateTime<Utc>>,
    request_id: Option<String>,
    tip_block_height: Option<i64>,
}

/// Project an engine event to the wire event a connection should surface, or
/// `None` when it must be skipped.
///
/// This delegates to the one shared projection the webhook fan-out also uses, so a
/// wire name never differs between the two transports. The SSE reader of either
/// stream is account-grade (an `account:read`/`poe:read` credential), so an
/// operator-only event (a billing-hook event such as a PoE refund-intent) is not
/// surfaced here, exactly as it is suppressed for an account-scoped webhook
/// subscription. An event with no wire form is likewise skipped rather than
/// collapsed onto a catch-all status/balance name.
fn project_stream_event(
    subject_kind: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> Option<WireEvent> {
    match project_event(subject_kind, event_type, payload) {
        Some(wire) if wire.visibility == WireVisibility::AccountAndOperator => Some(wire),
        // OperatorOnly or no wire form: not visible to this account-grade stream.
        _ => None,
    }
}

/// Parse a `Last-Event-ID` header into a resume sequence, if present and numeric.
fn parse_last_event_id(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n >= 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ids::encode_poe_id;

    #[test]
    fn last_event_id_parses_a_numeric_resume_point() {
        let mut h = HeaderMap::new();
        h.insert("last-event-id", "42".parse().unwrap());
        assert_eq!(parse_last_event_id(&h), Some(42));
    }

    #[test]
    fn last_event_id_ignores_garbage() {
        let mut h = HeaderMap::new();
        h.insert("last-event-id", "not-a-number".parse().unwrap());
        assert_eq!(parse_last_event_id(&h), None);
        assert_eq!(parse_last_event_id(&HeaderMap::new()), None);
    }

    #[test]
    fn last_event_id_rejects_a_negative_resume_point() {
        let mut h = HeaderMap::new();
        h.insert("last-event-id", "-1".parse().unwrap());
        assert_eq!(parse_last_event_id(&h), None);
    }

    /// The wire name a stream surfaces for an event, or `None` when it is skipped.
    fn stream_name(
        subject_kind: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Option<String> {
        project_stream_event(subject_kind, event_type, &payload).map(|w| w.name)
    }

    #[test]
    fn poe_event_projection_picks_submission_failed_for_terminal_reasons() {
        for reason in ["tx_build_failed", "byte_budget_exceeded"] {
            let payload = serde_json::json!({ "reason": reason });
            assert_eq!(
                stream_name(POE_SUBJECT_KIND, "permanent_failure", payload).as_deref(),
                Some("cardano_submission_failed"),
                "terminal submit reason {reason} projects to a submission failure"
            );
        }
    }

    #[test]
    fn poe_event_projection_falls_back_to_status_changed() {
        // A permanent_failure that did NOT carry a terminal submit reason (a
        // post-confirm reorg, say) is still a status change.
        assert_eq!(
            stream_name(
                POE_SUBJECT_KIND,
                "permanent_failure",
                serde_json::json!({ "reason": "rollback_retries_exhausted" }),
            )
            .as_deref(),
            Some("poe_status_changed")
        );
        assert_eq!(
            stream_name(POE_SUBJECT_KIND, "confirmed", serde_json::json!({})).as_deref(),
            Some("poe_status_changed")
        );
        assert_eq!(
            stream_name(POE_SUBJECT_KIND, "submitted", serde_json::json!({})).as_deref(),
            Some("poe_status_changed")
        );
    }

    #[test]
    fn poe_refund_intent_is_skipped_on_the_account_grade_stream() {
        // A PoE refund-intent is an operator-only billing-hook event. On the SSE
        // stream (an account-grade reader) it must be skipped, not collapsed onto
        // poe_status_changed where it would emit a spurious duplicate frame ahead of
        // the permanent_failure that follows it.
        assert_eq!(
            project_stream_event(
                POE_SUBJECT_KIND,
                "poe.refund-intent",
                &serde_json::json!({})
            ),
            None
        );
    }

    #[test]
    fn balance_event_projection_is_balance_changed() {
        assert_eq!(
            stream_name(
                ACCOUNT_SUBJECT_KIND,
                "balance.changed",
                serde_json::json!({})
            )
            .as_deref(),
            Some("balance_changed")
        );
    }

    #[test]
    fn upload_failure_projects_to_its_own_wire_name() {
        assert_eq!(
            stream_name(
                ACCOUNT_SUBJECT_KIND,
                "storage.upload.failed",
                serde_json::json!({}),
            )
            .as_deref(),
            Some("storage_upload_failed")
        );
    }

    #[test]
    fn poe_subject_stream_round_trips_a_wire_id() {
        // The handler decodes the wire id to a UUID and carries both; the snapshot
        // echoes the wire id back unchanged.
        let id = Uuid::now_v7();
        let wire = encode_poe_id(id);
        let kind = SubjectStream::Poe {
            record_uuid: id,
            account_id: Uuid::now_v7(),
            wire_id: wire.clone(),
        };
        assert_eq!(kind.subject_kind(), POE_SUBJECT_KIND);
        if let SubjectStream::Poe { wire_id, .. } = kind {
            assert_eq!(wire_id, wire);
        }
    }

    #[test]
    fn balance_subject_stream_kind_is_the_account_subject() {
        let kind = SubjectStream::Balance {
            account_id: Uuid::now_v7(),
        };
        assert_eq!(kind.subject_kind(), ACCOUNT_SUBJECT_KIND);
    }
}
