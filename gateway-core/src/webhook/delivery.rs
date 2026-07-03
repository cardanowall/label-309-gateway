//! Per-(event, subscription) delivery state: fan-out explode, the ordered due
//! claim, and the attempt-recording transitions.
//!
//! The fan-out reader explodes one un-fanned `delivery_outbox` row into one
//! [`webhook_delivery`] row per matching subscription, then stamps the outbox row,
//! all in one transaction so a crash mid-explode self-heals. The delivery worker
//! claims due rows with a frontier query that keeps per-subject ordering per
//! subscription while never blocking one subject (or subscription) behind another,
//! delivers them, and records the outcome — a success that resets the failure
//! budget, a transient failure that re-schedules with capped+jittered backoff, or
//! an exhaustion that drops the event (unblocking later seq) and may auto-disable a
//! sustained-failing endpoint.
//!
//! [`webhook_delivery`]: crate::webhook

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::webhook::fanout::ClaimedOutboxRow;
use crate::webhook::owner::{resolve_owner, OwnerResolution, SubjectOwner};
use crate::webhook::projection::{
    build_envelope, delivery_id, project_wire_event, WireEvent, WireVisibility,
};
use crate::{Error, Result};

/// The thresholds the delivery path reads when recording a failure.
///
/// Carried as a value (not read from a config table per call) so the worker is
/// driven by its constructed config and a test can drive a fast budget. `backoff`
/// is the per-delivery retry envelope; `auto_disable` is the per-subscription
/// failure budget.
#[derive(Debug, Clone, Copy)]
pub struct DeliveryPolicy {
    /// The first retry delay (doubles each attempt up to `backoff_cap`).
    pub backoff_base: Duration,
    /// The ceiling a backoff interval is clamped to.
    pub backoff_cap: Duration,
    /// Consecutive fully-exhausted deliveries that auto-disable the endpoint.
    pub auto_disable_consecutive: i32,
    /// No successful delivery for this long (while attempts were made) auto-
    /// disables the endpoint.
    pub auto_disable_stale: Duration,
    /// How long an exclusive POST claim-lease is held on a delivery row. It must
    /// exceed the egress timeout (plus signing/scheduling overhead) so a healthy
    /// worker always settles its delivery before the lease lapses; a worker that
    /// crashes mid-POST lets the lease lapse and another worker reclaims the row
    /// after this long.
    pub claim_lease: Duration,
}

impl Default for DeliveryPolicy {
    fn default() -> Self {
        Self {
            backoff_base: Duration::seconds(10),
            backoff_cap: Duration::hours(6),
            auto_disable_consecutive: 20,
            auto_disable_stale: Duration::hours(72),
            // Comfortably above the 10s egress timeout so a live delivery never
            // races its own lease lapse, yet short enough that a crashed worker's
            // row is reclaimed promptly.
            claim_lease: Duration::seconds(60),
        }
    }
}

/// A claimed delivery row plus the endpoint material the worker needs to sign and
/// POST it.
///
/// Loaded after a claim wins the row: the frozen body, the active secret
/// ciphertext(s) and the `wrap_key_id` that sealed them, the target URL, and the
/// attempt accounting. The secrets are still encrypted here; the worker unwraps
/// them through the keyring just before signing and never persists the plaintext.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimedDelivery {
    /// The delivery row id.
    pub id: Uuid,
    /// The owning endpoint.
    pub endpoint_id: Uuid,
    /// The per-delivery `Webhook-Id`.
    pub dedupe_key: String,
    /// The frozen wire envelope bytes, signed verbatim on every attempt.
    pub body: serde_json::Value,
    /// Attempts consumed so far.
    pub attempts: i32,
    /// The per-delivery attempt budget.
    pub max_attempts: i32,
    /// The delivery target URL.
    pub url: String,
    /// The active secret ciphertext (`secret_enc`).
    pub secret_enc: Vec<u8>,
    /// The rotation-successor ciphertext, present while a rotation window is open.
    pub secret_next_enc: Option<Vec<u8>>,
    /// The wrap key id the secrets were sealed under.
    pub wrap_key_id: String,
}

/// The owner subject the auto-disable event is appended to, resolved once when a
/// terminal failure may flip the endpoint.
#[derive(Debug, Clone, Copy)]
struct EndpointOwner {
    subject_kind: &'static str,
    subject_id: Uuid,
}

/// Explode one claimed outbox row into per-subscription delivery rows and stamp it
/// fanned-out, all inside the caller's transaction.
///
/// Resolves the row's owner, projects its wire event name + visibility, matches
/// every live subscription (account-scoped for an account-owned subject, operator-
/// scoped firehose for the operator owner) that passes the `enabled_events`
/// filter, inserts one delivery row per match with `ON CONFLICT (dedupe_key) DO
/// NOTHING`, and stamps `fanned_out_at`. The match query and the stamp share the
/// caller's snapshot, so the mid-stream cutoff is "did the subscription exist when
/// this row was exploded?". A row whose owner is not deliverable by design (the
/// subject was hard-removed, or its kind has no resolver) or whose event has no
/// wire form is stamped with an empty match set rather than retried forever.
///
/// A *transient* owner-lookup failure (a database error) is not a poison row: it
/// propagates so the caller's transaction rolls back and the still-un-fanned row
/// is re-claimed and retried on the next pass, never terminally dropped on a blip.
///
/// Returns how many delivery rows were inserted this call (a re-fan after a crash
/// inserts only the rows that did not already land).
pub async fn explode_outbox_row(
    pool: &sqlx::PgPool,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &ClaimedOutboxRow,
) -> Result<u64> {
    // A row whose event has no wire form (an unknown subject kind) is stamped with
    // no deliveries: there is nothing to deliver, and leaving it un-fanned would
    // wedge the drain on it forever.
    let Some(wire) = project_wire_event(row) else {
        crate::webhook::fanout::stamp_fanned_out(tx, row.id).await?;
        return Ok(0);
    };

    // Resolve the owner on the pool (a read that does not need the fan-out
    // transaction's row lock). The resolver draws a typed line between the two
    // outcomes the backstop must treat differently:
    //
    //   - NotDeliverable: the subject was hard-removed (or its id is unknown), or
    //     its kind has no resolver (a producer/consumer mismatch). Either is by
    //     design not deliverable and never will be, so stamp it past with an empty
    //     match set and warn — a propagated error here would re-claim and re-fail
    //     the row forever (a wedge).
    //   - Err: a transient/operational failure (a database error). This is NOT a
    //     poison row, so it is propagated: the fan-out transaction rolls back and
    //     the still-un-fanned row is retried on the next pass rather than being
    //     terminally stamped with zero deliveries on a momentary blip.
    let owner = match resolve_owner(pool, &row.subject_kind, &row.subject_id).await? {
        OwnerResolution::Resolved(owner) => owner,
        OwnerResolution::NotDeliverable => {
            tracing::warn!(
                outbox_id = %row.id,
                subject_kind = %row.subject_kind,
                "webhook fan-out: subject owner not deliverable; stamping past with no deliveries"
            );
            crate::webhook::fanout::stamp_fanned_out(tx, row.id).await?;
            return Ok(0);
        }
    };

    let endpoints = match_subscriptions(tx, &owner, &wire).await?;

    let mut inserted = 0u64;
    for endpoint_id in endpoints {
        let webhook_id = delivery_id(
            &row.subject_kind,
            &row.subject_id,
            row.subject_seq,
            endpoint_id,
        );
        // Reuse the owner already resolved above (with full error propagation) for
        // the envelope's account_id routing field, rather than a second best-effort
        // lookup: a transient lookup error has already aborted this fan-out via `?`,
        // so we never sign a body with a wrongly-null account_id for an account-owned
        // subject. A subject with no owning account legitimately carries null. The
        // envelope's own snapshot reads propagate too: a DB blip while projecting the
        // body aborts the fan-out (rolling back and retrying) rather than freezing a
        // wrong projection that is later signed byte-for-byte.
        let body = build_envelope(pool, row, &webhook_id, &wire.name, owner.account_id).await?;
        inserted += insert_delivery(tx, row, endpoint_id, &webhook_id, &body).await?;
    }

    crate::webhook::fanout::stamp_fanned_out(tx, row.id).await?;
    Ok(inserted)
}

/// Match the live subscriptions that should receive this event.
///
/// An account-scoped subscription matches only when the subject names an account
/// and the event is account-visible; the operator firehose matches every event
/// under the operator. Both arms apply the `enabled_events` filter on the projected
/// wire name (an empty filter means all). Disabled, paused, and soft-deleted
/// endpoints are excluded. The match runs under the caller's snapshot, which is
/// what makes the mid-stream cutoff "live when this row was exploded".
async fn match_subscriptions(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: &SubjectOwner,
    wire: &WireEvent,
) -> Result<Vec<Uuid>> {
    let mut endpoints = Vec::new();

    // The account arm: only when the subject has an account owner AND the event is
    // account-visible (a billing-hook event is operator-only even on an account
    // subject).
    if let (Some(account_id), WireVisibility::AccountAndOperator) =
        (owner.account_id, wire.visibility)
    {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM cw_core.webhook_endpoint \
             WHERE scope_kind = 'account' AND account_id = $1 \
               AND status = 'active' AND deleted_at IS NULL \
               AND (cardinality(enabled_events) = 0 OR $2 = ANY(enabled_events))",
        )
        .bind(account_id)
        .bind(&wire.name)
        .fetch_all(&mut **tx)
        .await?;
        endpoints.extend(rows.into_iter().map(|(id,)| id));
    }

    // The operator firehose arm: every event under the operator, including the
    // operator-only billing-hook events.
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM cw_core.webhook_endpoint \
         WHERE scope_kind = 'operator' AND operator_id = $1 \
           AND status = 'active' AND deleted_at IS NULL \
           AND (cardinality(enabled_events) = 0 OR $2 = ANY(enabled_events))",
    )
    .bind(owner.operator_id)
    .bind(&wire.name)
    .fetch_all(&mut **tx)
    .await?;
    endpoints.extend(rows.into_iter().map(|(id,)| id));

    Ok(endpoints)
}

/// Insert one delivery row for an endpoint, returning 1 if it landed and 0 if a
/// prior fan-out of the same `(outbox_id, endpoint)` already created it.
///
/// `ON CONFLICT (dedupe_key) DO NOTHING` makes a crash-replayed fan-out idempotent:
/// the same `dedupe_key` no-ops rather than aborting the transaction with a unique
/// violation, so only the rows that did not already land are inserted before the
/// stamp commits.
async fn insert_delivery(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &ClaimedOutboxRow,
    endpoint_id: Uuid,
    dedupe_key: &str,
    body: &serde_json::Value,
) -> Result<u64> {
    let affected = sqlx::query(
        "INSERT INTO cw_core.webhook_delivery \
           (id, endpoint_id, subject_kind, subject_id, subject_seq, event_type, body, \
            dedupe_key, outbox_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (dedupe_key) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(endpoint_id)
    .bind(&row.subject_kind)
    .bind(&row.subject_id)
    .bind(row.subject_seq)
    .bind(&row.event_type)
    .bind(body)
    .bind(dedupe_key)
    .bind(row.id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    Ok(affected)
}

/// An exclusively claimed delivery: its row id and the lease token the worker must
/// present on the terminal write so a lost-race worker performs no second POST and
/// no second state write.
#[derive(Debug, Clone, Copy)]
pub struct ClaimedLease {
    /// The delivery row id.
    pub id: Uuid,
    /// The lease token that fences this delivery's POST window. The terminal CAS
    /// (`record_success`/`record_failure`) requires it to match the row's current
    /// `claim_token`, so a worker whose lease lapsed (and was re-granted to another
    /// worker) writes nothing.
    pub claim_token: Uuid,
}

/// Claim up to `limit` due delivery rows, granting each an exclusive POST
/// claim-lease, inside the caller's transaction.
///
/// Three CTE stages in one statement. The `frontier` CTE is the lowest pending
/// `subject_seq` per `(endpoint, subject)`: a `delivered` or `failed` predecessor
/// is settled and does not block, so an exhausted delivery is transparent to
/// ordering (skip-after-exhaustion). `eligible` filters that frontier to the rows
/// that are due (`next_attempt_at <= now`), whose endpoint is active, and whose
/// POST lease is unheld or lapsed (`claim_token IS NULL OR claim_expires_at <
/// now()`), bounded by `LIMIT`.
///
/// The exclusion point is the `claimed` CTE: it ranges **directly over the base
/// `webhook_delivery` rows** the frontier selected and takes the
/// `FOR UPDATE SKIP LOCKED` row lock there. The lock must be taken over base-table
/// rows: a locking clause attached to a CTE that reads from another CTE (such as
/// `frontier`, which is grouped by `DISTINCT ON` and cannot itself be locked) does
/// not propagate down to the base rows and silently locks nothing, so two workers
/// could both compute the same unclaimed id from their own snapshots and both
/// stamp it. Locking the base rows with `SKIP LOCKED` makes a concurrent claimer
/// skip a row this transaction holds, and re-checking the due/live/unheld
/// predicates against the freshly locked row (in both `claimed` and the final
/// `UPDATE`) means a row whose eligibility changed while a claimer waited on the
/// lock is no longer granted. Exactly one worker wins a delivery's POST window.
///
/// The outer `UPDATE` then stamps a fresh `claim_token` + `claim_expires_at` on
/// the locked, still-eligible rows and returns the token. The row stays `pending`
/// (the lease, not the state, is the exclusion), so a crashed owner's lease lapses
/// by TTL and the row is reclaimable — at-least-once is preserved. Cross-subject
/// and cross-endpoint rows are independent frontier groups, so one slow subject
/// never blocks another and one slow endpoint never blocks another subscriber.
pub async fn claim_due(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    limit: i64,
    lease: Duration,
) -> Result<Vec<ClaimedLease>> {
    let lease_secs = lease.num_seconds().max(1) as f64;
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        r#"
        WITH frontier AS (
            SELECT DISTINCT ON (endpoint_id, subject_kind, subject_id)
                id, endpoint_id, subject_seq, next_attempt_at,
                claim_token, claim_expires_at
            FROM cw_core.webhook_delivery
            WHERE state = 'pending'
            ORDER BY endpoint_id, subject_kind, subject_id, subject_seq
        ),
        eligible AS (
            SELECT id
            FROM frontier
            WHERE next_attempt_at <= now()
              AND (claim_token IS NULL OR claim_expires_at < now())
              AND endpoint_id IN (
                  SELECT id FROM cw_core.webhook_endpoint
                  WHERE status = 'active' AND deleted_at IS NULL
              )
            ORDER BY subject_seq
            LIMIT $1
        ),
        claimed AS (
            SELECT d.id
            FROM cw_core.webhook_delivery d
            WHERE d.id IN (SELECT id FROM eligible)
              AND d.state = 'pending'
              AND d.next_attempt_at <= now()
              AND (d.claim_token IS NULL OR d.claim_expires_at < now())
            FOR UPDATE SKIP LOCKED
        )
        UPDATE cw_core.webhook_delivery d
           SET claim_token = gen_random_uuid(),
               claim_expires_at = now() + make_interval(secs => $2)
          FROM claimed c
         WHERE d.id = c.id
           AND d.state = 'pending'
           AND d.next_attempt_at <= now()
           AND (d.claim_token IS NULL OR d.claim_expires_at < now())
        RETURNING d.id, d.claim_token
        "#,
    )
    .bind(limit)
    .bind(lease_secs)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, claim_token)| ClaimedLease { id, claim_token })
        .collect())
}

/// Load the endpoint material for a claimed delivery so the worker can sign and
/// POST it. Returns `None` if the row vanished (a soft-delete cascade) between the
/// claim and the load.
pub async fn load_for_delivery(
    pool: &sqlx::PgPool,
    delivery_id: Uuid,
) -> Result<Option<ClaimedDelivery>> {
    let row = sqlx::query_as::<_, ClaimedDelivery>(
        "SELECT d.id, d.endpoint_id, d.dedupe_key, d.body, d.attempts, d.max_attempts, \
                e.url, e.secret_enc, e.secret_next_enc, e.wrap_key_id \
         FROM cw_core.webhook_delivery d \
         JOIN cw_core.webhook_endpoint e ON e.id = d.endpoint_id \
         WHERE d.id = $1",
    )
    .bind(delivery_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Record a successful (`2xx`) delivery: mark it delivered, stamp the status, and
/// reset the endpoint's failure budget (`consecutive_failures = 0`,
/// `last_success_at = now()`), all in one transaction.
///
/// The terminal CAS is fenced on `claim_token`: only the worker that still holds
/// the lease this delivery was POSTed under writes the outcome. A worker whose
/// lease lapsed (so another worker re-claimed and is re-delivering the row) matches
/// nothing and writes no second state, which is what makes a lost race a no-op
/// rather than a double terminal write.
pub async fn record_success(
    pool: &sqlx::PgPool,
    delivery_id: Uuid,
    claim_token: Uuid,
    status: u16,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let endpoint_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE cw_core.webhook_delivery \
         SET state = 'delivered', delivered_at = now(), attempts = attempts + 1, \
             last_status = $3, last_error = NULL, \
             claim_token = NULL, claim_expires_at = NULL \
         WHERE id = $1 AND state = 'pending' AND claim_token = $2 \
         RETURNING endpoint_id",
    )
    .bind(delivery_id)
    .bind(claim_token)
    .bind(i32::from(status))
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(endpoint_id) = endpoint_id {
        sqlx::query(
            "UPDATE cw_core.webhook_endpoint \
             SET consecutive_failures = 0, last_success_at = now(), updated_at = now() \
             WHERE id = $1",
        )
        .bind(endpoint_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The outcome the worker re-schedules a delivery on after a non-2xx attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureOutcome {
    /// The delivery stays `pending`; retry at the carried instant.
    Retry {
        /// When the delivery becomes due again.
        next_attempt_at: DateTime<Utc>,
    },
    /// The delivery exhausted its attempts and is now a terminal dead-letter; the
    /// next seq for its `(endpoint, subject)` is unblocked.
    Exhausted,
}

/// Record a failed attempt (a non-2xx status, a timeout, an egress refusal).
///
/// Bumps `attempts` and stamps the status/error. If attempts remain the delivery
/// stays `pending` with `next_attempt_at` set to the capped+jittered backoff and a
/// [`FailureOutcome::Retry`] is returned. If the attempt was the last the delivery
/// flips to `failed` (the dead-letter), the endpoint's `consecutive_failures` is
/// incremented, the endpoint is auto-disabled when the budget is exhausted, and
/// [`FailureOutcome::Exhausted`] is returned. `status` is `None` for a transport
/// error that produced no HTTP status (timeout, connection refused, egress refusal).
pub async fn record_failure(
    pool: &sqlx::PgPool,
    delivery_id: Uuid,
    claim_token: Uuid,
    status: Option<u16>,
    error: &str,
    policy: &DeliveryPolicy,
) -> Result<FailureOutcome> {
    let mut tx = pool.begin().await?;

    // Bump the attempt and read back the new count + the budget + the endpoint so
    // the terminal decision is made from the freshly written state. Fenced on
    // `claim_token`: only the worker still holding this delivery's lease records the
    // failure, so a worker that lost the lease race writes nothing and double-counts
    // no attempt.
    let bumped: Option<(Uuid, i32, i32)> = sqlx::query_as(
        "UPDATE cw_core.webhook_delivery \
         SET attempts = attempts + 1, last_status = $3, last_error = $4 \
         WHERE id = $1 AND state = 'pending' AND claim_token = $2 \
         RETURNING endpoint_id, attempts, max_attempts",
    )
    .bind(delivery_id)
    .bind(claim_token)
    .bind(status.map(i32::from))
    .bind(error)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((endpoint_id, attempts, max_attempts)) = bumped else {
        // The row was no longer pending under this lease (a redrive, a delete, or a
        // lapsed-lease takeover raced the attempt); nothing to re-schedule.
        tx.commit().await?;
        return Ok(FailureOutcome::Exhausted);
    };

    if attempts < max_attempts {
        // Attempts remain: stay pending, schedule the next try with the application
        // retry envelope (capped + jittered), and release the lease so the
        // rescheduled row can be re-claimed when it next comes due.
        let next_attempt_at = next_attempt_at(attempts, policy);
        sqlx::query(
            "UPDATE cw_core.webhook_delivery \
             SET next_attempt_at = $2, claim_token = NULL, claim_expires_at = NULL \
             WHERE id = $1 AND state = 'pending'",
        )
        .bind(delivery_id)
        .bind(next_attempt_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(FailureOutcome::Retry { next_attempt_at });
    }

    // Exhausted: the row is the terminal dead-letter. Skip-after-exhaustion means
    // the next pending seq for this (endpoint, subject) is no longer blocked by it
    // (the frontier excludes a failed row). The lease is released as the row leaves
    // `pending`.
    sqlx::query(
        "UPDATE cw_core.webhook_delivery \
         SET state = 'failed', claim_token = NULL, claim_expires_at = NULL \
         WHERE id = $1 AND state = 'pending'",
    )
    .bind(delivery_id)
    .execute(&mut *tx)
    .await?;

    // The endpoint accrues one more consecutive exhaustion; read back the new
    // accumulator and the last-success window so the auto-disable decision is made
    // from the written state.
    let (consecutive, last_success_at): (i32, Option<DateTime<Utc>>) = sqlx::query_as(
        "UPDATE cw_core.webhook_endpoint \
         SET consecutive_failures = consecutive_failures + 1, updated_at = now() \
         WHERE id = $1 \
         RETURNING consecutive_failures, last_success_at",
    )
    .bind(endpoint_id)
    .fetch_one(&mut *tx)
    .await?;

    if let Some(reason) = auto_disable_reason(consecutive, last_success_at, policy) {
        disable_endpoint(&mut tx, endpoint_id, reason).await?;
    }

    tx.commit().await?;
    Ok(FailureOutcome::Exhausted)
}

/// Release a claimed delivery for a later retry WITHOUT recording a delivery
/// failure, for a local custody gap (this replica does not hold the endpoint's wrap
/// key, so it cannot sign here even though the endpoint and receiver are fine).
///
/// A custody gap is not a delivery failure: it must not consume the per-delivery
/// attempt budget or feed the per-endpoint auto-disable accumulator, or a keyless
/// replica repeatedly winning the row would dead-letter the delivery and auto-disable
/// a perfectly live endpoint. This re-arms the row (`next_attempt_at` bounded by the
/// first-retry backoff, lease cleared) so a key-holding replica can claim it, leaving
/// `attempts`, `consecutive_failures`, and the endpoint status untouched. Fenced on
/// `claim_token` so a lapsed-lease takeover by another worker is a no-op here too.
pub async fn release_for_custody_retry(
    pool: &sqlx::PgPool,
    delivery_id: Uuid,
    claim_token: Uuid,
    policy: &DeliveryPolicy,
) -> Result<()> {
    // Re-arm at the first-retry backoff (jittered, capped) so a keyless replica does
    // not hot-loop the row, but a key-holding replica picks it up promptly. `attempts`
    // is the count consumed; passing 1 yields the base interval without bumping it.
    let next_attempt_at = next_attempt_at(1, policy);
    sqlx::query(
        "UPDATE cw_core.webhook_delivery \
         SET next_attempt_at = $2, claim_token = NULL, claim_expires_at = NULL, \
             last_error = $3 \
         WHERE id = $1 AND state = 'pending' AND claim_token = $4",
    )
    .bind(delivery_id)
    .bind(next_attempt_at)
    .bind("webhook secret wrap key unavailable on this instance; awaiting a key-holding replica")
    .bind(claim_token)
    .execute(pool)
    .await?;
    Ok(())
}

/// Whether a sustained-failing endpoint should now be auto-disabled, and why.
///
/// `consecutive` exhausted deliveries past the budget is the primary trigger; a
/// stale window (no success for `auto_disable_stale` while attempts were made) is
/// the secondary one. Returns the `disabled_reason` to record, or `None` to leave
/// the endpoint active.
fn auto_disable_reason(
    consecutive: i32,
    last_success_at: Option<DateTime<Utc>>,
    policy: &DeliveryPolicy,
) -> Option<&'static str> {
    if consecutive >= policy.auto_disable_consecutive {
        return Some("consecutive_failures");
    }
    // The stale window only fires once the endpoint has been attempted (this path
    // runs after an exhaustion, so it has) and has gone too long without a success.
    // An endpoint that has never succeeded is stale once it has been failing for
    // the window relative to its first attempt; we anchor on last_success_at when
    // present and treat its absence as "never succeeded", which the consecutive
    // budget already bounds, so the stale arm only adds the time-based cutoff for an
    // endpoint that DID succeed once and then went dark.
    if let Some(last_success) = last_success_at {
        if Utc::now() - last_success >= policy.auto_disable_stale {
            return Some("stale");
        }
    }
    None
}

/// Flip an endpoint to `disabled`, recording the reason and emitting the
/// `webhook.endpoint_disabled` event on its owner subject — exactly once per logical
/// enabled→disabled transition.
///
/// A disabled endpoint is excluded from fan-out matching (the active filter) and
/// from the delivery claim, so it stops costing egress and outbox growth. The
/// emitted event rides the endpoint owner's subject so an operator's own
/// firehose/SSE consumer is told the moment an endpoint is auto-disabled.
///
/// The status flip and the alert event are gated together on the `rows_affected`
/// of the flip: the `status <> 'disabled'` guard makes only the first caller's
/// UPDATE touch a row, and only that caller appends the event. A concurrent
/// exhaustion that finds the endpoint already disabled (another delivery worker
/// flipped it first) updates zero rows and appends nothing, so two workers racing
/// on the same exhausted endpoint emit a single disable event rather than a
/// duplicate per worker.
async fn disable_endpoint(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    endpoint_id: Uuid,
    reason: &str,
) -> Result<()> {
    let flipped = sqlx::query(
        "UPDATE cw_core.webhook_endpoint \
         SET status = 'disabled', disabled_reason = $2, updated_at = now() \
         WHERE id = $1 AND status <> 'disabled'",
    )
    .bind(endpoint_id)
    .bind(reason)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    // Only the transition from enabled→disabled appends the alert. If the row was
    // already disabled (a concurrent worker won the flip), this is a no-op so the
    // disable event is emitted exactly once for the one logical transition.
    if flipped == 0 {
        return Ok(());
    }

    // Resolve the owner subject the alert event rides. The endpoint owner is its
    // account (account-scoped) or operator (operator-scoped); the event is appended
    // to that subject so the owner's own firehose hears the disable.
    let owner = endpoint_owner(tx, endpoint_id).await?;
    let payload = serde_json::json!({
        "endpoint_id": endpoint_id.to_string(),
        "reason": reason,
    });
    crate::events::append_subject_event(
        &mut **tx,
        owner.subject_kind,
        &owner.subject_id.to_string(),
        crate::webhook::projection::WEBHOOK_ENDPOINT_DISABLED_EVENT,
        &payload,
    )
    .await?;
    Ok(())
}

/// Resolve the subject an endpoint's auto-disable event rides: the endpoint's
/// account (account-scoped) or operator (operator-scoped).
async fn endpoint_owner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    endpoint_id: Uuid,
) -> Result<EndpointOwner> {
    let (scope_kind, account_id, operator_id): (String, Option<Uuid>, Option<Uuid>) =
        sqlx::query_as(
            "SELECT scope_kind, account_id, operator_id FROM cw_core.webhook_endpoint \
             WHERE id = $1",
        )
        .bind(endpoint_id)
        .fetch_one(&mut **tx)
        .await?;

    match scope_kind.as_str() {
        "account" => account_id
            .map(|id| EndpointOwner {
                subject_kind: crate::webhook::owner::kind::ACCOUNT,
                subject_id: id,
            })
            .ok_or_else(|| {
                Error::Config(format!(
                    "account-scoped endpoint {endpoint_id} has no account_id"
                ))
            }),
        "operator" => operator_id
            .map(|id| EndpointOwner {
                // An operator-scoped endpoint's alert rides the operator as a
                // first-class subject so the firehose hears its own disable.
                subject_kind: crate::webhook::owner::kind::OPERATOR,
                subject_id: id,
            })
            .ok_or_else(|| {
                Error::Config(format!(
                    "operator-scoped endpoint {endpoint_id} has no operator_id"
                ))
            }),
        other => Err(Error::Config(format!(
            "endpoint {endpoint_id} has an unknown scope_kind {other:?}"
        ))),
    }
}

/// Compute the next retry instant: exponential `base * 2^(attempt-1)`, clamped to
/// `cap`, with full jitter (a uniform draw in `[0, capped]`).
///
/// `attempts` is the count already consumed (so the first retry uses `base`). Full
/// jitter spreads a thundering herd of receivers that all failed at once; the cap
/// bounds the tail so the worst-case horizon stays the application envelope rather
/// than the runtime's uncapped doubling.
fn next_attempt_at(attempts: i32, policy: &DeliveryPolicy) -> DateTime<Utc> {
    let capped = backoff_interval(attempts, policy);
    let capped_secs = capped.num_seconds().max(0);
    // Full jitter: a uniform draw in [0, capped]. A zero ceiling (a sub-second
    // base) degenerates to an immediate retry, which is correct.
    let jittered = if capped_secs == 0 {
        0
    } else {
        jitter_secs(capped_secs)
    };
    Utc::now() + Duration::seconds(jittered)
}

/// The capped (pre-jitter) backoff interval for `attempts` already consumed.
fn backoff_interval(attempts: i32, policy: &DeliveryPolicy) -> Duration {
    let base = policy.backoff_base.num_seconds().max(0);
    // base * 2^(attempts-1), saturated so a large attempt count never overflows.
    let shift = u32::try_from(attempts.max(1) - 1)
        .unwrap_or(u32::MAX)
        .min(62);
    let raw = base.saturating_mul(1i64 << shift);
    let cap = policy.backoff_cap.num_seconds().max(0);
    Duration::seconds(raw.min(cap))
}

/// A uniform random integer in `[0, max]` (inclusive) for full-jitter backoff.
fn jitter_secs(max: i64) -> i64 {
    let mut buf = [0u8; 8];
    // A jitter draw need not be cryptographically strong, but the keyring already
    // depends on getrandom, so use it rather than pulling another RNG crate.
    if getrandom::getrandom(&mut buf).is_err() {
        // On the practically-impossible entropy failure, fall back to the full cap
        // (still a valid, bounded delay) rather than panicking in the worker loop.
        return max;
    }
    let n = u64::from_le_bytes(buf);
    // Map into [0, max] inclusive. max+1 fits in i64 here because max is a seconds
    // count bounded by the 6h cap.
    let span = u64::try_from(max).unwrap_or(0).saturating_add(1);
    i64::try_from(n % span).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> DeliveryPolicy {
        DeliveryPolicy::default()
    }

    #[test]
    fn backoff_doubles_then_caps() {
        let p = policy();
        // 10s, 20s, 40s, ... doubling.
        assert_eq!(backoff_interval(1, &p), Duration::seconds(10));
        assert_eq!(backoff_interval(2, &p), Duration::seconds(20));
        assert_eq!(backoff_interval(3, &p), Duration::seconds(40));
        // The tail clamps at the 6h cap rather than growing unbounded.
        assert_eq!(backoff_interval(30, &p), Duration::hours(6));
        assert_eq!(backoff_interval(62, &p), Duration::hours(6));
    }

    #[test]
    fn jitter_stays_within_the_capped_interval() {
        let p = policy();
        // The jittered next-attempt instant is never further out than the cap, and
        // never in the past, across many draws.
        for attempts in [1, 5, 30] {
            let cap = backoff_interval(attempts, &p);
            for _ in 0..200 {
                let now = Utc::now();
                let next = next_attempt_at(attempts, &p);
                let delta = next - now;
                assert!(delta >= Duration::zero(), "next attempt is not in the past");
                // Allow a small slack for the now() taken inside next_attempt_at.
                assert!(
                    delta <= cap + Duration::seconds(1),
                    "jittered delay {delta:?} exceeds the cap {cap:?}"
                );
            }
        }
    }

    #[test]
    fn jitter_is_not_always_the_ceiling() {
        // Full jitter must actually spread: over many draws at a wide interval the
        // values are not all the ceiling (which a no-jitter schedule would be).
        let cap = 1000i64;
        let mut distinct = std::collections::BTreeSet::new();
        for _ in 0..200 {
            distinct.insert(jitter_secs(cap));
        }
        assert!(
            distinct.len() > 10,
            "full jitter must produce a spread of delays, got {} distinct",
            distinct.len()
        );
    }

    #[test]
    fn auto_disable_on_the_consecutive_budget() {
        let p = policy();
        // Below the budget: stay active.
        assert_eq!(
            auto_disable_reason(p.auto_disable_consecutive - 1, None, &p),
            None
        );
        // At the budget: disable for consecutive failures.
        assert_eq!(
            auto_disable_reason(p.auto_disable_consecutive, None, &p),
            Some("consecutive_failures")
        );
    }

    #[test]
    fn auto_disable_on_a_stale_window() {
        let p = policy();
        // An endpoint that succeeded long ago and is now failing is stale even
        // before the consecutive budget is reached.
        let long_ago = Utc::now() - Duration::hours(100);
        assert_eq!(auto_disable_reason(1, Some(long_ago), &p), Some("stale"));
        // A recent success keeps it active.
        let recent = Utc::now() - Duration::minutes(5);
        assert_eq!(auto_disable_reason(1, Some(recent), &p), None);
    }
}
