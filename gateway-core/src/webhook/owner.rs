//! Resolve the owner of a subject event so the fan-out reader can match
//! subscriptions.
//!
//! Subjects do not carry an owner column; ownership is a join performed at
//! fan-out time. Each subject kind the engine writes resolves its owner
//! differently:
//!
//! - `poe_record`: the record carries both an operator owner (`operator_id`, NOT
//!   NULL) and an optional account owner (`account_id`, a UUID FK into the account
//!   anchor that is NULL for an operator-direct publish). An account-scoped
//!   subscription matches only when the record names an account; the operator
//!   firehose always matches via the operator owner.
//! - `account`: the subject id *is* the account id, and the owning operator is
//!   joined from `account_detail`.
//! - `storage_funding_source`: an operator-plane-only subject; the owner is the
//!   funding source's `owner_operator_id` and there is no account owner, so an
//!   account-scoped subscription never sees it.
//! - `operator`: an operator is itself a first-class subject — the delivery worker
//!   appends administrative events (an endpoint auto-disable today) on the operator
//!   so its own firehose hears them. The subject id *is* the operator id and there
//!   is no account owner, so only the operator firehose matches, never an account
//!   subscription.
//!
//! The owner returned here is what the subscription matcher filters on: an
//! account-scoped subscription matches `account_id`, an operator-scoped
//! subscription matches `operator_id`.

use uuid::Uuid;

use crate::Result;

/// The owner of a subject event.
///
/// `operator_id` is always present (every subject has an operator owner). An
/// account-scoped subscription matches a subject only when `account_id` is set
/// and equal to its account; an operator-scoped subscription matches on
/// `operator_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectOwner {
    /// The owning operator. Always present.
    pub operator_id: Uuid,
    /// The owning account, when the subject has one. `None` for an
    /// operator-direct `poe_record` (NULL `account_id`) and for every
    /// `storage_funding_source` subject, which is operator-plane only.
    pub account_id: Option<Uuid>,
}

/// The outcome of resolving a subject's owner.
///
/// The two non-error variants are the two terminal dispositions the fan-out
/// backstop acts on: a resolved owner is fanned out; anything that is not
/// deliverable by design is stamped past with an empty match set. A transient
/// or operational failure is *not* one of these variants — it is the `Err` arm
/// of the returned [`Result`], so the caller propagates it and retries rather
/// than terminally dropping a still-deliverable event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerResolution {
    /// The subject has an owner; fan it out to the matching subscriptions.
    Resolved(SubjectOwner),
    /// The subject is not deliverable by design and never will be: its row was
    /// hard-removed (or its id is malformed/unknown), or its kind has no
    /// resolver (a producer/consumer mismatch). Either way there is no owner to
    /// fan out to, so the row is stamped past rather than retried forever. This
    /// is a *terminal* disposition, distinct from a transient `Err`.
    NotDeliverable,
}

/// The subject kinds the engine emits events on. These are the only kinds the
/// fan-out reader can resolve; an unknown kind has no resolver and resolves to
/// [`OwnerResolution::NotDeliverable`] (a producer/consumer mismatch the fan-out
/// backstop stamps past rather than wedging on).
pub mod kind {
    /// PoE record subjects (`submitted`, `confirmed`, `permanent_failure`,
    /// refund-intent). Owner: `poe_record.operator_id` and the optional
    /// `poe_record.account_id`.
    pub const POE_RECORD: &str = "poe_record";
    /// Account subjects (`balance.changed`, `storage.upload.failed`). The subject
    /// id is the account id; the operator is joined from `account_detail`.
    pub const ACCOUNT: &str = "account";
    /// Storage funding source subjects (`storage.refund-intent`). Operator-plane
    /// only; owner is `storage_funding_source.owner_operator_id`.
    pub const STORAGE_FUNDING_SOURCE: &str = "storage_funding_source";
    /// Operator subjects: the operator is itself the subject for administrative
    /// events about its own resources (an endpoint auto-disable). The subject id is
    /// the operator id; there is no account owner, so only the operator firehose
    /// matches.
    pub const OPERATOR: &str = "operator";
}

/// Resolve the owner of `(subject_kind, subject_id)`.
///
/// The two non-error outcomes are the terminal dispositions the fan-out backstop
/// acts on:
///
///   - [`OwnerResolution::Resolved`] when the subject has an owner.
///   - [`OwnerResolution::NotDeliverable`] when no such subject row exists (the
///     subject was hard-removed between the event append and this resolution, or
///     the id is malformed/unknown) *or* the kind has no resolver (a
///     producer/consumer mismatch). Either is by design not deliverable, so the
///     caller stamps the outbox row past with an empty match set rather than
///     retrying forever.
///
/// A database or otherwise transient/operational failure is *not* folded into
/// `NotDeliverable`: it surfaces as the `Err` arm so the caller propagates it and
/// the fan-out transaction rolls back, leaving the row un-fanned for a retry. A
/// momentary DB blip therefore never terminally drops a still-deliverable event.
pub async fn resolve_owner(
    pool: &sqlx::PgPool,
    subject_kind: &str,
    subject_id: &str,
) -> Result<OwnerResolution> {
    let owner = match subject_kind {
        kind::POE_RECORD => resolve_poe_record(pool, subject_id).await?,
        kind::ACCOUNT => resolve_account(pool, subject_id).await?,
        kind::STORAGE_FUNDING_SOURCE => resolve_storage_funding_source(pool, subject_id).await?,
        kind::OPERATOR => resolve_operator(pool, subject_id).await?,
        // An unrecognized kind is a producer/consumer mismatch, not a transient
        // fault: there is no resolver and there never will be at runtime, so it is
        // a terminal not-deliverable disposition rather than a propagated error
        // that would re-claim and re-fail the row forever.
        _ => None,
    };
    Ok(match owner {
        Some(owner) => OwnerResolution::Resolved(owner),
        None => OwnerResolution::NotDeliverable,
    })
}

/// A `poe_record` subject id is the record's UUID. The record carries the
/// operator owner directly (NOT NULL) and an optional account owner: `account_id`
/// is a nullable UUID FK into the account anchor, NULL for an operator-direct
/// publish. A NULL account owner means no account-scoped subscription can match
/// the record (operator-only fan-out).
async fn resolve_poe_record(pool: &sqlx::PgPool, subject_id: &str) -> Result<Option<SubjectOwner>> {
    let id = match Uuid::parse_str(subject_id) {
        Ok(id) => id,
        // A malformed subject id cannot match any record row; treat it as an
        // unknown subject (empty match set) rather than a hard error.
        Err(_) => return Ok(None),
    };

    let row: Option<(Option<Uuid>, Uuid)> =
        sqlx::query_as("SELECT account_id, operator_id FROM cw_core.poe_record WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;

    Ok(row.map(|(account_id, operator_id)| SubjectOwner {
        operator_id,
        account_id,
    }))
}

/// An `account` subject id is the account's UUID. The account is its own account
/// owner; the operator owner is joined from `account_detail`.
async fn resolve_account(pool: &sqlx::PgPool, subject_id: &str) -> Result<Option<SubjectOwner>> {
    let account_id = match Uuid::parse_str(subject_id) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };

    let operator_id: Option<Uuid> =
        sqlx::query_scalar("SELECT operator_id FROM cw_core.account_detail WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;

    Ok(operator_id.map(|operator_id| SubjectOwner {
        operator_id,
        account_id: Some(account_id),
    }))
}

/// A `storage_funding_source` subject id is the funding source's UUID. It is an
/// operator-plane-only subject: the owner is `owner_operator_id` and there is no
/// account owner, so an account-scoped subscription never matches it.
async fn resolve_storage_funding_source(
    pool: &sqlx::PgPool,
    subject_id: &str,
) -> Result<Option<SubjectOwner>> {
    let source_id = match Uuid::parse_str(subject_id) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };

    let operator_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT owner_operator_id FROM cw_core.storage_funding_source WHERE id = $1",
    )
    .bind(source_id)
    .fetch_optional(pool)
    .await?;

    Ok(operator_id.map(|operator_id| SubjectOwner {
        operator_id,
        account_id: None,
    }))
}

/// An `operator` subject id is the operator's own UUID. The operator is its own
/// owner and there is no account owner, so only the operator firehose matches this
/// subject. The operator row is confirmed to exist so a stale or malformed id
/// resolves to an empty match set (stamped past) rather than fanning a phantom
/// owner.
async fn resolve_operator(pool: &sqlx::PgPool, subject_id: &str) -> Result<Option<SubjectOwner>> {
    let operator_id = match Uuid::parse_str(subject_id) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };

    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM cw_core.operator WHERE id = $1")
        .bind(operator_id)
        .fetch_optional(pool)
        .await?;

    Ok(exists.map(|operator_id| SubjectOwner {
        operator_id,
        account_id: None,
    }))
}
