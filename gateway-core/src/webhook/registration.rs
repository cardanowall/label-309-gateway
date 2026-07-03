//! The webhook subscription lifecycle (create, list, read, patch, soft-delete).
//!
//! These helpers own the `cw_core.webhook_endpoint` access for both subscription
//! arms. Every query takes an [`EndpointScope`] naming the owner the call is pinned
//! to: an account (the data-plane routes pass the bearer's account) or an operator
//! firehose (the control-plane routes pass the operator). One tenant can never read,
//! mutate, or delete another's endpoint, because the scope filters the owner column
//! the row was written under. The data plane registers account-scoped subscriptions;
//! the control plane registers operator-scoped firehoses.
//!
//! # Secret custody
//!
//! Create and rotate mint a fresh signing secret, seal it at rest under the
//! [`SecretWrap`] data key, and return the plaintext exactly once. After that, only
//! the SHA-256 fingerprint is ever read back: no list, read, or rotate path returns
//! the plaintext or the ciphertext bytes again. This mirrors the api-key
//! show-once discipline, but a webhook secret is *encrypted* (not hashed) because
//! the signer must read it back to MAC each delivery.
//!
//! # The mid-stream cutoff is implicit
//!
//! Registration is a plain INSERT. There is no cutoff column to read or freeze: a
//! subscription receives exactly the events the fan-out reader explodes after its
//! row commits (the presence-based boundary). The create path therefore never
//! touches the outbox.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::api::control::credential::generate_secret;
use crate::wallet::keyring::UnlockedKeyring;
use crate::webhook::secret::{fingerprint, SecretWrap};
use crate::{Error, Result};

/// The lifecycle status of a subscription.
///
/// `active` delivers; `paused` is a subscriber-requested hold (no delivery, state
/// retained); `disabled` is a server auto-disable after a sustained failure budget
/// is exhausted. A data-plane caller may move between `active` and `paused`; only
/// the delivery worker sets `disabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointStatus {
    /// Delivering.
    Active,
    /// Subscriber-paused: retained, not delivered.
    Paused,
    /// Server auto-disabled after a sustained failure budget.
    Disabled,
}

impl EndpointStatus {
    /// The stored string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            EndpointStatus::Active => "active",
            EndpointStatus::Paused => "paused",
            EndpointStatus::Disabled => "disabled",
        }
    }

    /// Parse a stored status string.
    #[must_use]
    pub fn parse(s: &str) -> Option<EndpointStatus> {
        match s {
            "active" => Some(EndpointStatus::Active),
            "paused" => Some(EndpointStatus::Paused),
            "disabled" => Some(EndpointStatus::Disabled),
            _ => None,
        }
    }
}

/// The owner a subscription is pinned to: an account (data plane) or an operator
/// firehose (control plane).
///
/// Every lifecycle query is pinned to one of these, so one tenant can never read,
/// mutate, or delete another's subscription. The two arms differ only in the owner
/// column they filter on (`account_id` vs `operator_id`) and the `scope_kind`
/// discriminator, so the SQL is written once over this value and the public
/// account/operator entry points are thin wrappers that name their owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointScope {
    /// An account-scoped subscription: the owning account's id.
    Account(Uuid),
    /// An operator-scoped firehose: the owning operator's id.
    Operator(Uuid),
}

impl EndpointScope {
    /// The stored `scope_kind` discriminator for this owner.
    const fn kind(self) -> &'static str {
        match self {
            EndpointScope::Account(_) => "account",
            EndpointScope::Operator(_) => "operator",
        }
    }

    /// The owner id this scope filters on (the account id or the operator id).
    const fn owner_id(self) -> Uuid {
        match self {
            EndpointScope::Account(id) | EndpointScope::Operator(id) => id,
        }
    }
}

/// The validated input to create a subscription.
///
/// The URL has already passed the SSRF guard at the route; `enabled_events` has
/// already been validated against the published wire-name vocabulary. An empty
/// `enabled_events` means every wire event type. `scope` names the owner the
/// subscription is pinned to (an account on the data plane, an operator on the
/// control plane).
#[derive(Debug, Clone)]
pub struct NewEndpoint {
    /// The owner the subscription is pinned to.
    pub scope: EndpointScope,
    /// The HTTPS delivery target.
    pub url: String,
    /// The wire event names this subscription filters on; empty = all.
    pub enabled_events: Vec<String>,
    /// An optional human label.
    pub label: Option<String>,
}

/// A freshly created subscription: its row id, the plaintext secret (shown once),
/// and the stored metadata a create response echoes.
#[derive(Clone)]
pub struct CreatedEndpoint {
    /// The endpoint row id.
    pub id: Uuid,
    /// The plaintext signing secret, returned exactly once. Never stored, never
    /// returned again.
    pub secret: String,
    /// The delivery URL.
    pub url: String,
    /// The wire event filter (empty = all).
    pub enabled_events: Vec<String>,
    /// The lifecycle status (always `active` at create).
    pub status: EndpointStatus,
    /// The optional label.
    pub label: Option<String>,
    /// When the row was created.
    pub created_at: DateTime<Utc>,
}

/// Redact the plaintext signing secret on `{:?}` so a stray debug-format (a log
/// line, a panic, a test assertion) cannot leak the shown-once secret; every
/// non-secret field stays visible.
impl std::fmt::Debug for CreatedEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedEndpoint")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .field("url", &self.url)
            .field("enabled_events", &self.enabled_events)
            .field("status", &self.status)
            .field("label", &self.label)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// The metadata view of a subscription a list/read returns.
///
/// Carries the secret *fingerprint* (and the rotation-window fingerprint when one
/// is open), never the secret. The failure counters are surfaced inline so a
/// subscriber sees a degrading endpoint without a separate health call.
#[derive(Debug, Clone)]
pub struct EndpointView {
    /// The endpoint row id.
    pub id: Uuid,
    /// The delivery URL.
    pub url: String,
    /// The wire event filter (empty = all).
    pub enabled_events: Vec<String>,
    /// The lifecycle status.
    pub status: EndpointStatus,
    /// Why the server auto-disabled it, when it did.
    pub disabled_reason: Option<String>,
    /// The active secret's fingerprint (`sha256(secret)`), hex on the wire.
    pub secret_fp: Vec<u8>,
    /// The rotation-window secret's fingerprint, present only while a rotation is
    /// open.
    pub secret_next_fp: Option<Vec<u8>>,
    /// Consecutive fully-exhausted deliveries (the auto-disable accumulator).
    pub consecutive_failures: i32,
    /// The count of `failed` (dead-letter) deliveries for this endpoint, surfaced
    /// inline so a subscriber sees a growing failure population without a separate
    /// deliveries-list scan.
    pub dead_deliveries: i64,
    /// The last instant a delivery to this endpoint succeeded.
    pub last_success_at: Option<DateTime<Utc>>,
    /// The optional label.
    pub label: Option<String>,
    /// When the row was created.
    pub created_at: DateTime<Utc>,
    /// When the row was last updated.
    pub updated_at: DateTime<Utc>,
}

/// The columns the list/read query reads back.
#[derive(sqlx::FromRow)]
struct EndpointRow {
    id: Uuid,
    url: String,
    enabled_events: Vec<String>,
    status: String,
    disabled_reason: Option<String>,
    secret_fp: Vec<u8>,
    secret_next_fp: Option<Vec<u8>>,
    consecutive_failures: i32,
    dead_deliveries: i64,
    last_success_at: Option<DateTime<Utc>>,
    label: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<EndpointRow> for EndpointView {
    type Error = Error;

    fn try_from(row: EndpointRow) -> Result<Self> {
        let status = EndpointStatus::parse(&row.status).ok_or_else(|| {
            Error::Config(format!("unknown webhook endpoint status {:?}", row.status))
        })?;
        Ok(EndpointView {
            id: row.id,
            url: row.url,
            enabled_events: row.enabled_events,
            status,
            disabled_reason: row.disabled_reason,
            secret_fp: row.secret_fp,
            secret_next_fp: row.secret_next_fp,
            consecutive_failures: row.consecutive_failures,
            dead_deliveries: row.dead_deliveries,
            last_success_at: row.last_success_at,
            label: row.label,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// The shared SELECT list for the list/get endpoint views, joining the live
/// `webhook_health` aggregate so each row carries its `dead_deliveries` count
/// inline. The view is keyed on `endpoint_id`, so the LEFT JOIN adds the count
/// without changing cardinality; a coalesce keeps an endpoint with no deliveries at
/// zero rather than NULL. Kept as a `concat!` fragment so the full queries below
/// stay compile-time `&'static str` (sqlx requires a statically-safe SQL string).
macro_rules! endpoint_view_columns {
    () => {
        "e.id, e.url, e.enabled_events, e.status, e.disabled_reason, \
         e.secret_fp, e.secret_next_fp, e.consecutive_failures, \
         COALESCE(h.dead_deliveries, 0) AS dead_deliveries, \
         e.last_success_at, e.label, e.created_at, e.updated_at"
    };
}

/// The scope-generic owner predicate, parameterized by a table alias.
///
/// One predicate serves both arms: `$1` is the `scope_kind` discriminator and `$2`
/// is the owner id, matched against `account_id` for an account scope and
/// `operator_id` for an operator firehose. Because exactly one owner column is set
/// per row (the table check constraint) and `scope_kind` pins which, comparing the
/// scope-selected column to the bound owner id can never match across owners: an
/// account scope reads only account rows and an operator scope only operator rows.
/// Emitted as a `concat!`-able `&'static str` so the queries stay statically safe.
///
/// The single argument is the table alias the columns are qualified by (`"e"` for
/// the joined view queries, `""` for an unaliased single-table UPDATE/DELETE).
macro_rules! owner_match {
    ("") => {
        "scope_kind = $1 AND \
         CASE WHEN $1 = 'account' THEN account_id ELSE operator_id END = $2"
    };
    ($alias:literal) => {
        concat!(
            $alias,
            ".scope_kind = $1 AND CASE WHEN $1 = 'account' THEN ",
            $alias,
            ".account_id ELSE ",
            $alias,
            ".operator_id END = $2"
        )
    };
}

/// The operator-chosen prefix on a minted webhook signing secret.
///
/// A short, conventional marker so a leaked secret is recognizable in logs and a
/// receiver SDK can sanity-check it; the entropy tail is what a guesser must
/// defeat. Vendor-neutral (`whsec_`, the de-facto webhook-secret convention).
const SECRET_PREFIX: &str = "whsec_";

/// Create a subscription pinned to the input's owner scope.
///
/// Mints a signing secret, seals it under `wrap`, stores the ciphertext plus its
/// fingerprint and the `wrap_key_id`, and returns the plaintext exactly once. The
/// insert is a plain INSERT: there is no cutoff to read, because a subscription
/// receives exactly the events fanned out after its row commits.
///
/// The owner column is selected by `input.scope`: an account-scoped subscription
/// sets `account_id` and an operator-scoped firehose sets `operator_id` (the
/// `webhook_endpoint` check constraint enforces exactly one is set). The caller has
/// already validated the URL (SSRF guard) and the `enabled_events` vocabulary, so
/// this never re-parses them.
pub async fn create_endpoint(
    pool: &sqlx::PgPool,
    wrap: &SecretWrap,
    input: &NewEndpoint,
) -> Result<CreatedEndpoint> {
    let secret = generate_secret(SECRET_PREFIX);
    let secret_enc = wrap.seal(&secret)?;
    let secret_fp = fingerprint(&secret);
    let id = Uuid::now_v7();

    // One INSERT shape for both arms: the owner id binds to whichever of
    // account_id / operator_id matches the scope, and the other column is NULL,
    // honoring the table's exactly-one-owner constraint.
    let (account_id, operator_id) = match input.scope {
        EndpointScope::Account(id) => (Some(id), None),
        EndpointScope::Operator(id) => (None, Some(id)),
    };

    let created_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO cw_core.webhook_endpoint \
           (id, scope_kind, account_id, operator_id, url, secret_enc, secret_fp, wrap_key_id, \
            enabled_events, label) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         RETURNING created_at",
    )
    .bind(id)
    .bind(input.scope.kind())
    .bind(account_id)
    .bind(operator_id)
    .bind(&input.url)
    .bind(&secret_enc)
    .bind(&secret_fp)
    .bind(wrap.wrap_key_id())
    .bind(&input.enabled_events)
    .bind(input.label.as_deref())
    .fetch_one(pool)
    .await?;

    Ok(CreatedEndpoint {
        id,
        secret,
        url: input.url.clone(),
        enabled_events: input.enabled_events.clone(),
        status: EndpointStatus::Active,
        label: input.label.clone(),
        created_at,
    })
}

/// List the subscriptions under an owner scope, newest first.
///
/// Pinned to the scope's owner column and `scope_kind`; soft-deleted rows are
/// excluded. Never returns another owner's rows and never returns secret or
/// ciphertext bytes (only the fingerprint). The `owner_match!` predicate filters
/// the same column the scope names, so an account scope can never see an operator
/// firehose and vice versa.
pub async fn list_endpoints(
    pool: &sqlx::PgPool,
    scope: EndpointScope,
) -> Result<Vec<EndpointView>> {
    let rows: Vec<EndpointRow> = sqlx::query_as(concat!(
        "SELECT ",
        endpoint_view_columns!(),
        " FROM cw_core.webhook_endpoint e \
          LEFT JOIN cw_core.webhook_health h ON h.endpoint_id = e.id \
          WHERE ",
        owner_match!("e"),
        " AND e.deleted_at IS NULL \
          ORDER BY e.created_at DESC",
    ))
    .bind(scope.kind())
    .bind(scope.owner_id())
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(EndpointView::try_from).collect()
}

/// Read one subscription owned by `scope`, or `None` if it does not exist, is
/// soft-deleted, or belongs to another owner.
///
/// The single existence oracle: a row owned by another account/operator is reported
/// absent exactly like a non-existent one, so a caller cannot probe for another
/// tenant's endpoint ids.
pub async fn get_endpoint(
    pool: &sqlx::PgPool,
    scope: EndpointScope,
    id: Uuid,
) -> Result<Option<EndpointView>> {
    let row: Option<EndpointRow> = sqlx::query_as(concat!(
        "SELECT ",
        endpoint_view_columns!(),
        " FROM cw_core.webhook_endpoint e \
          LEFT JOIN cw_core.webhook_health h ON h.endpoint_id = e.id \
          WHERE ",
        owner_match!("e"),
        " AND e.id = $3 AND e.deleted_at IS NULL",
    ))
    .bind(scope.kind())
    .bind(scope.owner_id())
    .bind(id)
    .fetch_optional(pool)
    .await?;

    row.map(EndpointView::try_from).transpose()
}

/// The fields a PATCH may change on a subscription.
///
/// Each is optional: a `None` leaves that field untouched. `status` accepts only
/// `active` or `paused` from a data-plane caller (re-enabling resets the
/// auto-disable accumulator); `disabled` is server-only and rejected upstream.
#[derive(Debug, Clone, Default)]
pub struct EndpointPatch {
    /// Move between `active` and `paused`. A re-enable resets the failure counter.
    pub status: Option<EndpointStatus>,
    /// Replace the wire-event filter (already validated). Empty vec = all events.
    pub enabled_events: Option<Vec<String>>,
    /// Replace the URL (already SSRF-validated).
    pub url: Option<String>,
    /// Set or clear the label (`Some(None)` clears it).
    pub label: Option<Option<String>>,
}

/// The outcome of a scoped patch / delete: whether the row existed for this
/// account and whether the call changed anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointChange {
    /// No such row for this account (absent, soft-deleted, or another tenant's).
    NotFound,
    /// The row existed and the call applied its change.
    Changed,
}

/// Apply a PATCH to a subscription owned by `scope`.
///
/// Pinned to the owning account or operator. Re-activating a previously `disabled`
/// (or `paused`) endpoint resets `consecutive_failures` to 0 so a fixed endpoint
/// starts its failure budget fresh. Only the columns named in the patch move;
/// `updated_at` is always bumped on a matched row.
pub async fn patch_endpoint(
    pool: &sqlx::PgPool,
    scope: EndpointScope,
    id: Uuid,
    patch: &EndpointPatch,
) -> Result<EndpointChange> {
    // A re-activation resets the auto-disable accumulator; any other status (or no
    // status change) leaves the accumulator alone. Expressed as a CASE so the
    // single UPDATE stays one statement and one round trip.
    let reset_failures = matches!(patch.status, Some(EndpointStatus::Active));

    let affected = sqlx::query(concat!(
        "UPDATE cw_core.webhook_endpoint SET \
             status = coalesce($4, status), \
             enabled_events = coalesce($5, enabled_events), \
             url = coalesce($6, url), \
             label = CASE WHEN $7 THEN $8 ELSE label END, \
             consecutive_failures = CASE WHEN $9 THEN 0 ELSE consecutive_failures END, \
             disabled_reason = CASE WHEN $9 THEN NULL ELSE disabled_reason END, \
             updated_at = now() \
         WHERE ",
        owner_match!(""),
        " AND id = $3 AND deleted_at IS NULL",
    ))
    .bind(scope.kind())
    .bind(scope.owner_id())
    .bind(id)
    .bind(patch.status.map(EndpointStatus::as_str))
    .bind(patch.enabled_events.as_ref())
    .bind(patch.url.as_ref())
    // $7 = label provided?  $8 = the new label value (NULL clears it).
    .bind(patch.label.is_some())
    .bind(patch.label.clone().flatten())
    .bind(reset_failures)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(if affected == 1 {
        EndpointChange::Changed
    } else {
        EndpointChange::NotFound
    })
}

/// One delivery row as the deliveries list (the dead-letter view) returns it.
///
/// Carries the per-delivery state a subscriber needs to investigate and redrive a
/// failure: the logical event identity (`subject_*`, the wire `event_type`, the
/// `dedupe_key` that is the receiver's `Webhook-Id`), the attempt accounting, and
/// the last status/error seen. The frozen body is deliberately NOT returned: it is
/// large, it is what the receiver already got (or will get on a redrive), and a
/// subscriber investigates by id and status, not by re-reading the payload.
#[derive(Debug, Clone)]
pub struct DeliveryView {
    /// The delivery row id (the redrive target).
    pub id: Uuid,
    /// The per-delivery `Webhook-Id` the receiver dedupes on.
    pub dedupe_key: String,
    /// The subject kind the event rode.
    pub subject_kind: String,
    /// The subject id the event rode.
    pub subject_id: String,
    /// The per-subject sequence (lets a receiver place a gap).
    pub subject_seq: i64,
    /// The internal event type (projected to a wire name on delivery).
    pub event_type: String,
    /// The delivery state: `pending`, `delivered`, or `failed` (the dead-letter).
    pub state: String,
    /// Attempts consumed so far.
    pub attempts: i32,
    /// The per-delivery attempt budget.
    pub max_attempts: i32,
    /// When the delivery next becomes due (a pending row).
    pub next_attempt_at: DateTime<Utc>,
    /// When it was delivered, if it succeeded.
    pub delivered_at: Option<DateTime<Utc>>,
    /// The last HTTP status seen.
    pub last_status: Option<i32>,
    /// The last error recorded.
    pub last_error: Option<String>,
    /// When the delivery row was created (the fan-out instant).
    pub created_at: DateTime<Utc>,
}

/// The columns the deliveries-list query reads back.
#[derive(sqlx::FromRow)]
struct DeliveryRow {
    id: Uuid,
    dedupe_key: String,
    subject_kind: String,
    subject_id: String,
    subject_seq: i64,
    event_type: String,
    state: String,
    attempts: i32,
    max_attempts: i32,
    next_attempt_at: DateTime<Utc>,
    delivered_at: Option<DateTime<Utc>>,
    last_status: Option<i32>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<DeliveryRow> for DeliveryView {
    fn from(row: DeliveryRow) -> Self {
        DeliveryView {
            id: row.id,
            dedupe_key: row.dedupe_key,
            subject_kind: row.subject_kind,
            subject_id: row.subject_id,
            subject_seq: row.subject_seq,
            event_type: row.event_type,
            state: row.state,
            attempts: row.attempts,
            max_attempts: row.max_attempts,
            next_attempt_at: row.next_attempt_at,
            delivered_at: row.delivered_at,
            last_status: row.last_status,
            last_error: row.last_error,
            created_at: row.created_at,
        }
    }
}

/// List the deliveries of a subscription owned by `scope`, newest first.
///
/// This is the dead-letter view: an exhausted delivery is a `failed` row, and the
/// list carries every state (`pending`, `delivered`, `failed`) so a subscriber sees
/// both what is in flight and what was dropped.
///
/// Returns `None` when the endpoint does not exist, is soft-deleted, or belongs to
/// another owner, shaped identically to any other not-found so a caller cannot probe
/// for another tenant's endpoint. The deliveries themselves are reached only through
/// the owned endpoint, so this is the single ownership gate.
pub async fn list_deliveries(
    pool: &sqlx::PgPool,
    scope: EndpointScope,
    endpoint_id: Uuid,
    limit: i64,
) -> Result<Option<Vec<DeliveryView>>> {
    if !endpoint_belongs_to_scope(pool, scope, endpoint_id).await? {
        return Ok(None);
    }
    let rows: Vec<DeliveryRow> = sqlx::query_as(
        "SELECT id, dedupe_key, subject_kind, subject_id, subject_seq, event_type, state, \
                attempts, max_attempts, next_attempt_at, delivered_at, last_status, last_error, \
                created_at \
         FROM cw_core.webhook_delivery \
         WHERE endpoint_id = $1 \
         ORDER BY created_at DESC \
         LIMIT $2",
    )
    .bind(endpoint_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(Some(rows.into_iter().map(DeliveryView::from).collect()))
}

/// The outcome of a manual redrive request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedriveOutcome {
    /// No such endpoint+delivery pair for this account (absent, soft-deleted
    /// endpoint, another tenant's, or the delivery is not under this endpoint).
    NotFound,
    /// The delivery was a `failed` dead-letter and is now re-armed `pending`.
    Redriven,
    /// The delivery exists under the endpoint but was not `failed` (it is still
    /// `pending` or already `delivered`), so there is nothing to redrive.
    NotFailed,
}

/// Manually redrive a `failed` delivery owned (through its endpoint) by `scope`.
///
/// Resets the schedule, not the history: `state` flips back to `pending` and
/// `next_attempt_at` to now, but `attempts` is left intact so the record of the
/// prior failures stands and the receiver sees the same `Webhook-Id` and body on
/// the redelivery. Only a `failed` row is redrivable; a still-pending or already
/// delivered row is left untouched. The delivery is reached only through an
/// endpoint owned by the scope, so a redrive on another tenant's delivery reports
/// `NotFound`.
///
/// Note that re-arming alone is not enough to deliver if the endpoint itself is
/// `disabled`; a subscriber re-enables the endpoint (a PATCH to `active`, which
/// also resets the auto-disable accumulator) and then redrives.
pub async fn retry_delivery(
    pool: &sqlx::PgPool,
    scope: EndpointScope,
    endpoint_id: Uuid,
    delivery_id: Uuid,
) -> Result<RedriveOutcome> {
    if !endpoint_belongs_to_scope(pool, scope, endpoint_id).await? {
        return Ok(RedriveOutcome::NotFound);
    }

    // Re-arm only a failed row, and only one that is genuinely under this endpoint.
    // A row that does not exist under the endpoint affects zero rows; a row that is
    // not failed is filtered by the state predicate, so a separate existence read
    // distinguishes NotFound from NotFailed.
    let affected = sqlx::query(
        "UPDATE cw_core.webhook_delivery \
         SET state = 'pending', next_attempt_at = now(), last_error = NULL, \
             claim_token = NULL, claim_expires_at = NULL \
         WHERE id = $1 AND endpoint_id = $2 AND state = 'failed'",
    )
    .bind(delivery_id)
    .bind(endpoint_id)
    .execute(pool)
    .await?
    .rows_affected();

    if affected == 1 {
        return Ok(RedriveOutcome::Redriven);
    }

    // The update matched nothing: either the delivery is not under this endpoint
    // (NotFound) or it is under it but not failed (NotFailed). Disambiguate so the
    // route returns the honest 404 vs 409.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cw_core.webhook_delivery \
         WHERE id = $1 AND endpoint_id = $2)",
    )
    .bind(delivery_id)
    .bind(endpoint_id)
    .fetch_one(pool)
    .await?;

    Ok(if exists {
        RedriveOutcome::NotFailed
    } else {
        RedriveOutcome::NotFound
    })
}

/// Resolves the secret-wrap data key a stored row was sealed under, by the row's
/// recorded `wrap_key_id`, and seals a fresh secret under it.
///
/// A `webhook_endpoint` row records the `wrap_key_id` its `secret_enc` was sealed
/// under, and the delivery worker opens both the primary and the rotation successor
/// with that one recorded key. The successor must therefore be sealed under the row's
/// key, never under whatever key happens to be active in the rotating process: an
/// endpoint created under a now-superseded key keeps its secrets openable, and a
/// rotation never strands a row whose ciphertexts disagree on their key.
///
/// `seal_for` returns `None` when this instance does not hold the named key (uneven
/// key custody across replicas), distinct from a seal that fails, so the caller can
/// surface a custody gap as a service condition rather than a successful seal under
/// the wrong key.
pub trait WrapKeyResolver {
    /// Seal `secret` under the key named `key_id`, or `None` if this resolver does
    /// not hold that key.
    fn seal_for(&self, key_id: &str, secret: &str) -> Option<Result<Vec<u8>>>;
}

impl WrapKeyResolver for SecretWrap {
    /// A single active wrap key resolves only its own id. A row sealed under any
    /// other key is reported as not held, so the single-key callers (and a
    /// single-key deployment) keep their existing behaviour and a stale-key row is
    /// never sealed under the wrong key.
    fn seal_for(&self, key_id: &str, secret: &str) -> Option<Result<Vec<u8>>> {
        (self.wrap_key_id() == key_id).then(|| self.seal(secret))
    }
}

impl WrapKeyResolver for UnlockedKeyring {
    /// The full keyring resolves any wrap key it holds by id, the same lookup the
    /// delivery worker uses to open a row, so a rotation seals the successor under
    /// the row's recorded key even after a newer key became active.
    fn seal_for(&self, key_id: &str, secret: &str) -> Option<Result<Vec<u8>>> {
        self.webhook_wrap_key(key_id)
            .map(|wrap_key| wrap_key.secret_wrap().seal(secret))
    }
}

/// A freshly minted rotation-successor secret: shown exactly once, like the
/// create-time secret.
#[derive(Clone)]
pub struct RotatedSecret {
    /// The endpoint the rotation opened on.
    pub id: Uuid,
    /// The plaintext successor secret, returned exactly once. Never stored, never
    /// returned again.
    pub secret_next: String,
    /// The active secret's fingerprint (unchanged by the rotation).
    pub secret_fp: Vec<u8>,
    /// The successor secret's fingerprint, now visible in GET while the window is
    /// open.
    pub secret_next_fp: Vec<u8>,
}

/// Redact the plaintext successor secret on `{:?}` so a stray debug-format cannot
/// leak the shown-once rotation secret; the id and the (non-secret) fingerprints
/// stay visible.
impl std::fmt::Debug for RotatedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotatedSecret")
            .field("id", &self.id)
            .field("secret_next", &"<redacted>")
            .field("secret_fp", &self.secret_fp)
            .field("secret_next_fp", &self.secret_next_fp)
            .finish()
    }
}

/// Open a secret rotation window on a subscription owned by `scope`.
///
/// Mints a fresh successor secret, seals it under the ROW's recorded wrap key, stores
/// its ciphertext and fingerprint, and returns the plaintext exactly once. While the
/// window is open the delivery worker dual-signs (one MAC per active secret) so a
/// receiver that has deployed either secret validates the delivery; a subscriber
/// closes the window by calling [`commit_rotation`] once its fleet is cut over.
///
/// The successor is sealed under the row's own `wrap_key_id`, not under whatever key
/// is active in the rotating process, because a row carries one key and the delivery
/// worker opens BOTH ciphertexts with it. An endpoint created under a now-superseded
/// wrap key therefore still rotates: its successor lands under the same key as its
/// primary, so both stay openable. The `resolver` supplies the row's key by id (a
/// single active [`SecretWrap`] resolves only its own id; the full
/// [`UnlockedKeyring`] resolves any held key, the same lookup delivery uses).
///
/// Pinned to the owning scope (a foreign or missing endpoint is reported absent,
/// `Ok(None)`). A live owned endpoint whose recorded key this instance does not hold
/// (uneven key custody across replicas) is a service condition, not an absence, so it
/// returns `Err` rather than masquerading as a 404. Opening a rotation while one is
/// already open simply re-mints the successor (the prior un-committed successor is
/// replaced), which is the natural retry if the plaintext was lost before it was
/// deployed.
pub async fn rotate_secret(
    pool: &sqlx::PgPool,
    resolver: &impl WrapKeyResolver,
    scope: EndpointScope,
    endpoint_id: Uuid,
) -> Result<Option<RotatedSecret>> {
    // Read the row's recorded wrap key (and active fingerprint) under the ownership
    // gate first: a foreign, soft-deleted, or absent endpoint is reported absent here,
    // identically to any other not-found, so a caller cannot probe another tenant's
    // ids. The successor is then sealed under THIS key, never the process-active one.
    let row: Option<(String, Vec<u8>)> = sqlx::query_as(concat!(
        "SELECT wrap_key_id, secret_fp FROM cw_core.webhook_endpoint \
         WHERE ",
        owner_match!(""),
        " AND id = $3 AND deleted_at IS NULL",
    ))
    .bind(scope.kind())
    .bind(scope.owner_id())
    .bind(endpoint_id)
    .fetch_optional(pool)
    .await?;

    let Some((wrap_key_id, secret_fp)) = row else {
        return Ok(None);
    };

    let secret_next = generate_secret(SECRET_PREFIX);
    // Seal under the row's recorded key. A resolver that does not hold the key is a
    // custody gap on this instance, surfaced as a service error, not a successful seal
    // under a key the delivery worker could not open the row with.
    let secret_next_enc = resolver
        .seal_for(&wrap_key_id, &secret_next)
        .ok_or(Error::WebhookSecretWrap)??;
    let secret_next_fp = fingerprint(&secret_next);

    // Attach the successor to the same owned, live row. No wrap-key predicate is
    // needed: the ciphertext was just sealed under the row's own recorded key, so the
    // two ciphertexts already share a key. A zero-row result means the row was deleted
    // between the read and this write (a benign race), reported absent.
    let updated = sqlx::query(concat!(
        "UPDATE cw_core.webhook_endpoint \
         SET secret_next_enc = $4, secret_next_fp = $5, updated_at = now() \
         WHERE ",
        owner_match!(""),
        " AND id = $3 AND deleted_at IS NULL",
    ))
    .bind(scope.kind())
    .bind(scope.owner_id())
    .bind(endpoint_id)
    .bind(&secret_next_enc)
    .bind(&secret_next_fp)
    .execute(pool)
    .await?
    .rows_affected();

    Ok((updated == 1).then_some(RotatedSecret {
        id: endpoint_id,
        secret_next,
        secret_fp,
        secret_next_fp,
    }))
}

/// Commit a secret rotation on a subscription owned by `scope`: promote the
/// successor to primary and close the window.
///
/// Moves `secret_next_enc`/`secret_next_fp` into `secret_enc`/`secret_fp` and
/// clears the successor columns, so the delivery worker is back to a single `v1`.
/// Explicit (not auto-on-first-2xx) so a multi-instance receiver mid-rollout is
/// never cut over before the operator says its fleet is ready.
///
/// Pinned to the owning scope. Reports `NotFound` when the endpoint is absent,
/// soft-deleted, another tenant's, or when no rotation window is open (there is no
/// successor to promote), so a redundant commit is a no-op rather than clearing the
/// only secret.
pub async fn commit_rotation(
    pool: &sqlx::PgPool,
    scope: EndpointScope,
    endpoint_id: Uuid,
) -> Result<EndpointChange> {
    let affected = sqlx::query(concat!(
        "UPDATE cw_core.webhook_endpoint \
         SET secret_enc = secret_next_enc, secret_fp = secret_next_fp, \
             secret_next_enc = NULL, secret_next_fp = NULL, updated_at = now() \
         WHERE ",
        owner_match!(""),
        " AND id = $3 AND deleted_at IS NULL AND secret_next_enc IS NOT NULL",
    ))
    .bind(scope.kind())
    .bind(scope.owner_id())
    .bind(endpoint_id)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(if affected == 1 {
        EndpointChange::Changed
    } else {
        EndpointChange::NotFound
    })
}

/// Whether `endpoint_id` is a live (non-deleted) endpoint owned by `scope`.
///
/// The shared ownership gate for every per-endpoint read/redrive: a foreign,
/// soft-deleted, or absent endpoint reads as not owned, so a caller cannot reach
/// another tenant's deliveries or redrive them.
async fn endpoint_belongs_to_scope(
    pool: &sqlx::PgPool,
    scope: EndpointScope,
    endpoint_id: Uuid,
) -> Result<bool> {
    let owned: bool = sqlx::query_scalar(concat!(
        "SELECT EXISTS(SELECT 1 FROM cw_core.webhook_endpoint \
         WHERE ",
        owner_match!(""),
        " AND id = $3 AND deleted_at IS NULL)",
    ))
    .bind(scope.kind())
    .bind(scope.owner_id())
    .bind(endpoint_id)
    .fetch_one(pool)
    .await?;
    Ok(owned)
}

/// Soft-delete a subscription owned by `scope` by stamping `deleted_at`, and
/// fail its still-pending deliveries in the same transaction.
///
/// Pinned to the owning scope. Idempotent against a second delete: a row already
/// soft-deleted no longer matches the `deleted_at IS NULL` predicate, so the call
/// reports `NotFound` (the row is gone from the caller's perspective). Soft-delete
/// (not a row removal) keeps any in-flight `webhook_delivery` rows' FK intact for
/// the audit trail; the partial fan-out index already excludes a deleted endpoint
/// from matching.
///
/// Deletion has no undo — every lifecycle gate filters on `deleted_at IS NULL` —
/// so a `pending` delivery under a deleted endpoint can never be claimed again.
/// Left `pending` it would be a lie the state machine never resolves: excluded
/// from the claim, excluded from the terminal-state retention prune, pinning its
/// outbox row forever. Flipping such rows to `failed` here keeps the pending
/// working set truthful (and the claim frontier small) and lets the retention
/// sweep reclaim them like any other terminal row. A delivery worker holding a
/// POST lease on one of these rows loses the terminal CAS (`state = 'pending'`
/// no longer matches), which is the same lost-ownership no-op a lapsed lease
/// produces.
pub async fn soft_delete_endpoint(
    pool: &sqlx::PgPool,
    scope: EndpointScope,
    id: Uuid,
) -> Result<EndpointChange> {
    let mut tx = pool.begin().await?;

    let affected = sqlx::query(concat!(
        "UPDATE cw_core.webhook_endpoint SET deleted_at = now(), updated_at = now() \
         WHERE ",
        owner_match!(""),
        " AND id = $3 AND deleted_at IS NULL",
    ))
    .bind(scope.kind())
    .bind(scope.owner_id())
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if affected != 1 {
        tx.commit().await?;
        return Ok(EndpointChange::NotFound);
    }

    sqlx::query(
        "UPDATE cw_core.webhook_delivery \
         SET state = 'failed', last_error = 'endpoint deleted', \
             claim_token = NULL, claim_expires_at = NULL \
         WHERE endpoint_id = $1 AND state = 'pending'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(EndpointChange::Changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_its_string_form() {
        for s in [
            EndpointStatus::Active,
            EndpointStatus::Paused,
            EndpointStatus::Disabled,
        ] {
            assert_eq!(EndpointStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(EndpointStatus::parse("bogus"), None);
    }

    #[test]
    fn secret_prefix_is_vendor_neutral() {
        // The minted secret carries the conventional, non-branded webhook-secret
        // marker so it is recognizable without naming a vendor.
        let secret = generate_secret(SECRET_PREFIX);
        assert!(secret.starts_with("whsec_"));
        assert!(!secret.to_lowercase().contains("cardanowall"));
    }

    #[test]
    fn created_endpoint_debug_redacts_the_secret() {
        // The plaintext is the shown-once value: a `{:?}` of the struct (a log
        // line, a panic message) must never carry it. The non-secret fields stay
        // visible so the debug rendering is still useful.
        let secret = "whsec_super_secret_plaintext_value";
        let created = CreatedEndpoint {
            id: Uuid::now_v7(),
            secret: secret.to_string(),
            url: "https://hooks.example/ingest".to_string(),
            enabled_events: vec!["poe_status_changed".to_string()],
            status: EndpointStatus::Active,
            label: Some("prod firehose".to_string()),
            created_at: Utc::now(),
        };
        let rendered = format!("{created:?}");
        assert!(
            !rendered.contains(secret),
            "the plaintext secret must not appear in Debug output, got {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        // Non-secret fields remain visible.
        assert!(rendered.contains("https://hooks.example/ingest"));
        assert!(rendered.contains("prod firehose"));
    }

    #[test]
    fn rotated_secret_debug_redacts_the_successor_secret() {
        let secret_next = "whsec_rotation_successor_plaintext";
        let rotated = RotatedSecret {
            id: Uuid::now_v7(),
            secret_next: secret_next.to_string(),
            secret_fp: vec![0xAB, 0xCD],
            secret_next_fp: vec![0xEF, 0x01],
        };
        let rendered = format!("{rotated:?}");
        assert!(
            !rendered.contains(secret_next),
            "the plaintext successor secret must not appear in Debug output, got {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        // The (non-secret) fingerprints are still rendered (a `Vec<u8>` Debug is
        // the decimal byte list, so 0xAB == 171 and 0xEF == 239 appear).
        assert!(
            rendered.contains("171"),
            "secret_fp byte visible, got {rendered}"
        );
        assert!(
            rendered.contains("239"),
            "secret_next_fp byte visible, got {rendered}"
        );
    }
}
