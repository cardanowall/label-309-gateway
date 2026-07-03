//! Storage funding authority: the scope-bound charge capability.
//!
//! A storage funding source is an Arweave key plus the prepaid credit balance
//! attached to that key's address at a storage provider. Who may DRAW charges
//! against a source is a separate question from owning it, answered by a grant;
//! the capability minted after that check is an [`AuthorizedFunding`].
//!
//! The capability is the storage twin of [`crate::wallet::grant::AuthorizedWallet`]:
//! its fields are private, so a caller cannot fabricate one, and the keyring's
//! Arweave signer is reachable only through it
//! ([`crate::wallet::keyring::UnlockedKeyring::arweave_signer_for`] takes
//! `&AuthorizedFunding`). No code path can sign an upload from a bare address: a
//! signer is obtainable only via a token minted after an entitlement check.
//!
//! # Two independent gates
//!
//! Drawing a charge requires BOTH:
//!
//!   - **Authorization**: is the principal entitled to draw a source for this
//!     backend? A live grant (service, operator, or account scope) says yes; the
//!     resolver selects "the" source for the principal and mints the capability.
//!   - **Capability** (the keyring): does this instance physically hold the
//!     Arweave key? The keyring is the capability store; a grant the keyring
//!     cannot back is an authorization with no key to act on.
//!
//! # Single-source selection vs. owner entitlement
//!
//! Unlike a wallet (chosen by a least-loaded scheduler across many wallets, so a
//! scope may hold many live grants), a backend has exactly one drawing source per
//! principal. [`authorize_charge`] therefore SELECTS that source rather than
//! taking its id: it resolves the most specific live grant for the principal in
//! the order `account -> operator -> service` and mints the capability for the
//! source that grant draws. The owning operator is NOT a special always-entitled
//! arm (the wallet registrar is): a source is drawable only through a grant, and
//! the register path auto-issues the owner's grant, so every principal including
//! the owner reaches its source through the grant indexes. The schema makes a
//! second live grant at the same `(backend, subject)` unrepresentable, so the
//! resolved source is always unambiguous.
//!
//! # New charge vs. committed-upload settlement
//!
//! Two paths mint a capability, for two distinct questions:
//!
//!   - [`authorize_charge`] gates a NEW charge (is this principal entitled to draw
//!     a source for this backend right now?). It consults live grants and selects
//!     the source; a principal with no entitling grant gets `None`.
//!   - [`resolve_committed_upload`] settles an ALREADY-AUTHORIZED upload (a commit,
//!     release, or refund) strictly by its pinned `funding_source_id`, with no
//!     entitlement re-check: that upload was authorized at reserve time, and its
//!     settlement must draw the same source even if the source was set `draining`
//!     or its grant revoked afterwards. Both mint the same field-private,
//!     unforgeable token; the keyring is still the separate capability gate.

use uuid::Uuid;

use crate::Result;

/// Proof that a principal may charge a specific storage funding source.
///
/// The fields are private so a caller cannot fabricate one. It carries the
/// source's id and its verified Arweave address, so any signer reached through it
/// ([`crate::wallet::keyring::UnlockedKeyring::arweave_signer_for`]) is provably
/// scope-checked: the address-keyed keyring lookup is never reachable from a bare
/// string.
#[derive(Debug, Clone)]
pub struct AuthorizedFunding {
    funding_source_id: Uuid,
    arweave_address: String,
}

impl AuthorizedFunding {
    /// The authorized funding source's id (the credit-ledger and grant subject).
    #[must_use]
    pub fn funding_source_id(&self) -> Uuid {
        self.funding_source_id
    }

    /// The authorized source's verified Arweave address (the keyring signer key).
    #[must_use]
    pub fn arweave_address(&self) -> &str {
        &self.arweave_address
    }

    /// Mint a capability directly, for tests that exercise a signer path without a
    /// live grant in the database.
    ///
    /// Compiled only under `cfg(test)` (this crate's own unit tests) or the
    /// `testsupport` feature (which this crate's integration suites turn on via a
    /// dev-dependency self-reference). In a normal `cargo build` or release the
    /// feature is off, so this constructor does not exist at all. A downstream
    /// dependent could in principle turn on the off-by-default `testsupport`
    /// feature to reach it, so that feature MUST never be enabled by a production
    /// dependent. Within this workspace it is enabled only by this crate's own
    /// test/example targets and transitively by `pg-tests`.
    #[cfg(any(test, feature = "testsupport"))]
    #[doc(hidden)]
    #[must_use]
    pub fn for_tests(funding_source_id: Uuid, arweave_address: String) -> Self {
        Self {
            funding_source_id,
            arweave_address,
        }
    }
}

/// A principal asking to draw a storage charge.
///
/// The variant carries exactly the identity dimensions a grant can match. An
/// account upload (the data-plane path) carries both its operator and account, so
/// it can be entitled by an account grant, an operator grant for its operator, or
/// a service grant. An operator-direct charge carries only its operator. There is
/// deliberately no system actor: every storage charge is drawn under an
/// account/operator, and the crash-recovery settlement path
/// ([`resolve_committed_upload`]) resolves by `funding_source_id`, not a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageChargePrincipal {
    /// An operator-direct charge: entitled by a service grant or an operator grant
    /// for this operator.
    Operator {
        /// The charging operator.
        operator_id: Uuid,
    },
    /// An account charge: entitled by a service grant, an operator grant for the
    /// account's operator, or an account grant for this account.
    Account {
        /// The operator the account belongs to.
        operator_id: Uuid,
        /// The charging account.
        account_id: Uuid,
    },
}

impl StorageChargePrincipal {
    /// The operator this principal acts under.
    fn operator_id(self) -> Uuid {
        match self {
            StorageChargePrincipal::Operator { operator_id }
            | StorageChargePrincipal::Account { operator_id, .. } => operator_id,
        }
    }

    /// The account this principal acts as, if any.
    fn account_id(self) -> Option<Uuid> {
        match self {
            StorageChargePrincipal::Account { account_id, .. } => Some(account_id),
            StorageChargePrincipal::Operator { .. } => None,
        }
    }
}

/// The single entry to a drawable source for a NEW charge: resolve "the" source a
/// `principal` may draw for `backend`, and mint an [`AuthorizedFunding`] if one
/// exists.
///
/// Storage selection is single-source: there is no least-loaded scheduler across
/// many sources, so for any `(backend, principal)` there is at most one drawable
/// source. This resolves the MOST SPECIFIC live grant in the order
/// `account -> operator -> service` (an account grant wins over an operator grant,
/// which wins over a service grant) and mints the capability for the source that
/// grant draws. The selection is one round trip: it ranks the principal's live
/// grants and returns the winning source's id and verified Arweave address.
///
/// Returns `Ok(None)` when no live grant entitles the principal for this backend
/// (no funding grant). A revoked grant, a `draining`/`retired` source, or a source
/// owned by another operator never entitles a charge here — entitlement flows only
/// through a live grant on an `active` source, so an operator cannot draw another
/// operator's source unless that source's owner explicitly granted it, and a source
/// taken out of service by its owner takes no new charge.
///
/// The `account` grant arm is resolved for completeness; per-account grant ISSUANCE
/// is deferred (the schema, the index, and this resolver arm all ship so the scope
/// turns on additively without a signature change), exactly as the wallet
/// `account` arm was resolver-aware before its control route shipped.
pub async fn authorize_charge(
    pool: &sqlx::PgPool,
    backend: &str,
    principal: StorageChargePrincipal,
) -> Result<Option<AuthorizedFunding>> {
    // Independently verify the (operator, account) pairing before consulting any
    // grant. The principal carries both ids, but a caller could pair an account with
    // an operator it does not belong to; an operator-scoped grant for that operator
    // would then wrongly entitle a charge against a foreign account. The pairing is
    // verified here, in the engine signature, so the entitlement can never name an
    // account the operator does not own regardless of which caller reached this
    // function. A mismatched pair reports None, shaped exactly like a missing grant.
    if let StorageChargePrincipal::Account {
        operator_id,
        account_id,
    } = principal
    {
        let owns_account =
            crate::ledger::account::account_belongs_to_operator(pool, operator_id, account_id)
                .await?;
        if !owns_account {
            return Ok(None);
        }
    }

    // Rank the principal's live grants on an active source for this backend and take
    // the most specific: account (3) beats operator (2) beats service (1). The
    // per-(backend, subject) live-grant unique indexes make this pick deterministic
    // (no scope can hold two live grants for one backend/subject), so ordering by
    // specificity then by id yields the single drawable source. Selection admits only
    // an `active` source: a `draining` or `retired` source takes no NEW charge here
    // (a wound-down source never draws), while resolve_committed_upload stays
    // status-agnostic so an in-flight upload on a now-draining source still settles by
    // its pinned id.
    let row: Option<Row> = sqlx::query_as(
        "SELECT s.id AS funding_source_id, s.arweave_address AS arweave_address \
         FROM cw_core.storage_grant g \
         JOIN cw_core.storage_funding_source s \
             ON s.id = g.funding_source_id AND s.backend = g.backend \
         WHERE g.backend = $1 \
           AND g.revoked_at IS NULL \
           AND s.status = 'active' \
           AND ( \
               g.scope_kind = 'service' \
               OR (g.scope_kind = 'operator' AND g.operator_id = $2) \
               OR (g.scope_kind = 'account'  AND g.account_id  = $3) \
           ) \
         ORDER BY \
             CASE g.scope_kind \
                 WHEN 'account'  THEN 3 \
                 WHEN 'operator' THEN 2 \
                 ELSE 1 \
             END DESC, \
             s.id ASC \
         LIMIT 1",
    )
    .bind(backend)
    .bind(principal.operator_id())
    .bind(principal.account_id())
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| AuthorizedFunding {
        funding_source_id: row.funding_source_id,
        arweave_address: row.arweave_address,
    }))
}

/// The columns [`authorize_charge`]/[`resolve_committed_upload`] read back: the
/// selected source's id and its verified Arweave address.
#[derive(sqlx::FromRow)]
struct Row {
    funding_source_id: Uuid,
    arweave_address: String,
}

/// Resolve the capability for an ALREADY-AUTHORIZED committed/in-flight upload,
/// keyed strictly on `funding_source_id` with NO entitlement check.
///
/// This is the settlement counterpart to [`authorize_charge`], the storage twin of
/// the wallet `resolve_inflight_wallet`. The two answer different questions:
///
///   - [`authorize_charge`] gates a NEW charge: may this principal draw a source
///     for this backend? It consults live grants and may report `None`.
///   - this function settles an upload whose charge was already authorized at
///     reserve time (a success commit, a failure release, or a later refund). The
///     reservation pinned `funding_source_id`, so the settlement MUST draw that
///     same source; a grant revoked or the source set `draining` AFTER the
///     reservation must not strand it. There is therefore no entitlement query and
///     no fallthrough — a `draining` source still settles its own in-flight upload.
///
/// `backend` is a defense-in-depth filter (a source's backend is immutable and an
/// instance serves one backend per source, so it can never select a source bound to
/// a different backend), symmetric with the wallet path's `network` filter.
///
/// Returns `Ok(None)` only when no source row matches the id on this backend. The
/// mint stays inside this module so the capability's field-private, unforgeable
/// property holds: a settlement capability is produced solely by this crate.
pub async fn resolve_committed_upload(
    pool: &sqlx::PgPool,
    funding_source_id: Uuid,
    backend: &str,
) -> Result<Option<AuthorizedFunding>> {
    let address: Option<String> = sqlx::query_scalar(
        "SELECT arweave_address FROM cw_core.storage_funding_source \
         WHERE id = $1 AND backend = $2",
    )
    .bind(funding_source_id)
    .bind(backend)
    .fetch_optional(pool)
    .await?;

    Ok(address.map(|arweave_address| AuthorizedFunding {
        funding_source_id,
        arweave_address,
    }))
}

/// Mint the capability for an owner-initiated top-up of `funding_source_id`:
/// the source must be owned by `operator_id` and still `active`.
///
/// A top-up signs an OUTBOUND AR transfer from the source's wallet, so it is the
/// owner's prerogative alone — a draw grant entitles charging the source's
/// prepaid credit, never spending the wallet behind it, which is why this
/// resolver keys on ownership rather than consulting grants. Only an `active`
/// source can be topped up: funding a source its owner is winding down would
/// strand the credit (the conversion is one-way). Returns `Ok(None)` for a
/// missing, foreign, or non-active source, all collapsed to one shape so a probe
/// cannot tell a foreign source from a missing one.
///
/// The mint stays inside this module so the capability's field-private,
/// unforgeable property holds; the keyring is still the separate physical gate
/// (an owner whose instance does not hold the key gets no signer).
pub async fn authorize_owner_topup(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    funding_source_id: Uuid,
) -> Result<Option<AuthorizedFunding>> {
    let address: Option<String> = sqlx::query_scalar(
        "SELECT arweave_address FROM cw_core.storage_funding_source \
         WHERE id = $1 AND owner_operator_id = $2 AND status = 'active'",
    )
    .bind(funding_source_id)
    .bind(operator_id)
    .fetch_optional(pool)
    .await?;

    Ok(address.map(|arweave_address| AuthorizedFunding {
        funding_source_id,
        arweave_address,
    }))
}

/// The scope a storage grant entitles. Mirrors the `storage_grant.scope_kind` enum
/// and the wallet `GrantScope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageGrantScope {
    /// Every operator/account on the instance may draw the source (the default).
    Service,
    /// A named operator may draw the source.
    Operator {
        /// The entitled operator.
        operator_id: Uuid,
    },
    /// A named account may draw the source.
    Account {
        /// The entitled account.
        account_id: Uuid,
    },
}

impl StorageGrantScope {
    /// The `scope_kind` wire token this scope stores.
    fn kind(self) -> &'static str {
        match self {
            StorageGrantScope::Service => "service",
            StorageGrantScope::Operator { .. } => "operator",
            StorageGrantScope::Account { .. } => "account",
        }
    }

    /// The operator subject column value (set only for an operator grant).
    fn operator_id(self) -> Option<Uuid> {
        match self {
            StorageGrantScope::Operator { operator_id } => Some(operator_id),
            StorageGrantScope::Service | StorageGrantScope::Account { .. } => None,
        }
    }

    /// The account subject column value (set only for an account grant).
    fn account_id(self) -> Option<Uuid> {
        match self {
            StorageGrantScope::Account { account_id } => Some(account_id),
            StorageGrantScope::Service | StorageGrantScope::Operator { .. } => None,
        }
    }
}

/// The outcome of issuing a storage grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueOutcome {
    /// A new grant row was inserted.
    Issued {
        /// The new grant's id.
        grant_id: Uuid,
    },
    /// A live grant of the same scope subject, owned by THIS operator, already
    /// exists for the source's backend, so nothing was inserted (issuing a grant is
    /// idempotent). The id is the caller's own existing grant.
    AlreadyGranted {
        /// The id of the existing live grant, owned by the calling operator.
        grant_id: Uuid,
    },
    /// The backend's single live grant of this scope subject is held on a source
    /// owned by a DIFFERENT operator, so no grant could be inserted and none may be
    /// disclosed.
    ///
    /// Reachable only at `service` scope: a service grant is unique per backend
    /// across ALL sources (the single-source rule), so a second operator registering
    /// or granting `service` for a backend whose service default another operator
    /// already holds collides on that foreign grant. The outcome carries NO grant id
    /// — the conflicting grant belongs to another tenant — so the caller reports a
    /// conflict without leaking the foreign grant's identity. (`operator`/`account`
    /// grants are keyed per `(backend, subject)`; their subject is always the
    /// caller's own operator/account, so an idempotent re-issue there can only read
    /// back the caller's own grant and never reaches this arm.)
    ServiceDefaultHeldByOtherOwner,
}

/// Issue a charge grant on a funding source the `owner_operator_id` owns.
///
/// Only the source's owner may grant on it: the insert is gated on the source
/// existing with this owner, so an operator cannot grant on a source it does not
/// own (the call reports [`None`], shaped like a missing source, no cross-tenant
/// existence oracle). An `account`-scoped grant additionally requires that the
/// named account belongs to this same operator, so the owner cannot entitle another
/// operator's account to draw its source; this ownership check lives in the engine
/// signature, not only in the route, so a future caller cannot bypass it. A foreign
/// or missing account reports [`None`].
///
/// The denormalized `backend` written on the grant is read from the source itself
/// (never taken from the caller), so a grant always carries its source's backend
/// and the composite FK is satisfied by construction.
///
/// Issuing is idempotent per `(backend, scope subject)`, and idempotent ATOMICALLY:
/// the insert is `ON CONFLICT ... DO NOTHING` against the per-backend live-grant
/// partial unique index, so two concurrent issues of the same subject never both
/// insert and the loser reports [`IssueOutcome::AlreadyGranted`] (read back from the
/// winning row) rather than surfacing a raw unique violation.
///
/// A service grant is unique per backend across ALL sources (the single-source rule:
/// one live service grant per backend), so a service-scope issue for a backend that
/// already holds one converges on that existing grant even if it draws a different
/// source. The idempotent read-back is OWNER-SCOPED: it returns
/// [`IssueOutcome::AlreadyGranted`] only when the existing grant is held on a source
/// THIS operator owns. When the backend's live service grant is held on a source
/// another operator owns, the read-back reports
/// [`IssueOutcome::ServiceDefaultHeldByOtherOwner`] (which carries no id) rather than
/// disclosing the foreign tenant's grant. `operator`/`account` scopes are keyed per
/// `(backend, subject)` and their subject is always the caller's own
/// operator/account, so their idempotent read-back can only resolve the caller's own
/// grant.
///
/// The executor is generic over [`sqlx::Acquire`] so the issue can ride the
/// route's transaction (committing atomically with its audit row) or run
/// standalone against a pool.
pub async fn issue_grant<'a, A>(
    executor: A,
    owner_operator_id: Uuid,
    funding_source_id: Uuid,
    scope: StorageGrantScope,
) -> Result<Option<IssueOutcome>>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    // One transaction for the ownership read, the insert, and the idempotent
    // read-back (a savepoint when riding a caller's transaction, a real
    // transaction against a pool).
    let mut txn = executor.begin().await?;

    // First confirm the source exists and is owned by this operator, and read its
    // backend. The insert below is gated on the same ownership predicate, so this
    // read is what lets a missing/foreign source report None rather than silently
    // no-op. The backend is denormalized onto the grant FROM HERE (never from the
    // caller), so the composite FK to (id, backend) always holds.
    let source: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT owner_operator_id, backend FROM cw_core.storage_funding_source \
         WHERE id = $1",
    )
    .bind(funding_source_id)
    .fetch_optional(&mut *txn)
    .await?;
    let backend = match source {
        Some((owner, backend)) if owner == owner_operator_id => backend,
        // Absent, or owned by another operator: both collapse to None so a probe
        // cannot tell a foreign source from a missing one.
        _ => return Ok(None),
    };

    // An account grant names an account, which must belong to the SAME operator that
    // owns the source. Enforce that here, in the engine, so the entitlement (this
    // account may draw this source) can never name an account the operator does not
    // own, regardless of which caller reached this function. A foreign/absent
    // account reports None, shaped like a foreign source.
    if let StorageGrantScope::Account { account_id } = scope {
        let owns_account = crate::ledger::account::account_belongs_to_operator(
            &mut *txn,
            owner_operator_id,
            account_id,
        )
        .await?;
        if !owns_account {
            return Ok(None);
        }
    }

    // Insert atomically against the per-backend live-grant partial unique index for
    // this scope, so two concurrent issues of the same subject can never both
    // insert: at most one wins, the other's ON CONFLICT is a no-op (empty
    // RETURNING). This is the idempotency boundary; a prior SELECT-then-INSERT had a
    // race window where two callers each saw no live grant and the loser hit a raw
    // unique violation instead of reporting AlreadyGranted. Each scope uses a
    // literal statement whose conflict target names that scope's partial index
    // (columns plus the `revoked_at IS NULL` predicate) so Postgres infers it.
    let candidate_id = Uuid::now_v7();
    let inserted: Option<(Uuid,)> = match scope {
        StorageGrantScope::Service => {
            sqlx::query_as(
                "INSERT INTO cw_core.storage_grant \
               (id, funding_source_id, backend, scope_kind, operator_id, account_id, granted_by) \
             VALUES ($1, $2, $3, 'service', NULL, NULL, $4) \
             ON CONFLICT (backend) WHERE scope_kind = 'service' AND revoked_at IS NULL \
             DO NOTHING \
             RETURNING id",
            )
            .bind(candidate_id)
            .bind(funding_source_id)
            .bind(&backend)
            .bind(owner_operator_id)
            .fetch_optional(&mut *txn)
            .await?
        }
        StorageGrantScope::Operator { operator_id } => {
            sqlx::query_as(
                "INSERT INTO cw_core.storage_grant \
               (id, funding_source_id, backend, scope_kind, operator_id, account_id, granted_by) \
             VALUES ($1, $2, $3, 'operator', $4, NULL, $5) \
             ON CONFLICT (backend, operator_id) \
                 WHERE scope_kind = 'operator' AND revoked_at IS NULL \
             DO NOTHING \
             RETURNING id",
            )
            .bind(candidate_id)
            .bind(funding_source_id)
            .bind(&backend)
            .bind(operator_id)
            .bind(owner_operator_id)
            .fetch_optional(&mut *txn)
            .await?
        }
        StorageGrantScope::Account { account_id } => {
            sqlx::query_as(
                "INSERT INTO cw_core.storage_grant \
               (id, funding_source_id, backend, scope_kind, operator_id, account_id, granted_by) \
             VALUES ($1, $2, $3, 'account', NULL, $4, $5) \
             ON CONFLICT (backend, account_id) \
                 WHERE scope_kind = 'account' AND revoked_at IS NULL \
             DO NOTHING \
             RETURNING id",
            )
            .bind(candidate_id)
            .bind(funding_source_id)
            .bind(&backend)
            .bind(account_id)
            .bind(owner_operator_id)
            .fetch_optional(&mut *txn)
            .await?
        }
    };

    if let Some((grant_id,)) = inserted {
        txn.commit().await?;
        return Ok(Some(IssueOutcome::Issued { grant_id }));
    }

    // The insert hit the per-backend live-grant partial unique index: a grant of
    // this subject already exists for this backend. Read it back so the call stays
    // idempotent rather than surfacing the conflict as an error. The match keys on
    // the backend + the scope's own subject column (NULL-safe for service, which
    // names no subject), NOT on funding_source_id: a service grant is unique per
    // backend across all sources, so the existing live grant may draw a DIFFERENT
    // source than the one this call named — and that other source may be owned by a
    // DIFFERENT operator. Join the source and read its owner so the outcome is
    // owner-aware: the caller's own grant id is disclosed only when the conflicting
    // grant draws a source this operator owns.
    let existing: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT g.id, s.owner_operator_id \
         FROM cw_core.storage_grant g \
         JOIN cw_core.storage_funding_source s ON s.id = g.funding_source_id \
         WHERE g.backend = $1 AND g.revoked_at IS NULL AND g.scope_kind = $2 \
           AND g.operator_id IS NOT DISTINCT FROM $3 \
           AND g.account_id  IS NOT DISTINCT FROM $4",
    )
    .bind(&backend)
    .bind(scope.kind())
    .bind(scope.operator_id())
    .bind(scope.account_id())
    .fetch_optional(&mut *txn)
    .await?;
    txn.commit().await?;
    match existing {
        // The conflicting live grant draws a source this operator owns: the call is
        // idempotent and may name its own grant.
        Some((grant_id, owner)) if owner == owner_operator_id => {
            Ok(Some(IssueOutcome::AlreadyGranted { grant_id }))
        }
        // The conflicting live grant draws a source ANOTHER operator owns. This is
        // only reachable at service scope (its subject names no operator/account, so
        // it collides across owners); report the conflict WITHOUT the foreign grant's
        // id, so the caller surfaces a tenancy conflict rather than leaking another
        // operator's grant identity.
        Some(_) => Ok(Some(IssueOutcome::ServiceDefaultHeldByOtherOwner)),
        // The conflicting row was revoked between the failed insert and this read (a
        // concurrent revoke). No live grant exists now; report it as a
        // not-yet-granted no-op shaped like the missing-source None so the caller
        // can retry. This is a vanishingly small window and self-heals on retry.
        None => Ok(None),
    }
}

/// The outcome of revoking a storage grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// A live grant was revoked by this call.
    Revoked,
    /// The grant exists on a source this operator owns but was already revoked (an
    /// idempotent no-op).
    AlreadyRevoked,
}

/// Revoke a grant on a funding source the `owner_operator_id` owns.
///
/// Only the owner may revoke a grant on its own source: the UPDATE is gated on the
/// grant's source having this owner, so a grant on a foreign source reports [`None`]
/// (shaped like a missing grant). Idempotent: an already-revoked grant reports
/// [`RevokeOutcome::AlreadyRevoked`] without re-stamping its `revoked_at`. It is a
/// plain committed UPDATE: revoke takes NO lock and holds no detached connection.
///
/// # Revocation is forward-looking
///
/// A new charge re-resolves entitlement through [`authorize_charge`] (a read of the
/// live grants) before signing; under read-committed visibility a charge authorizing
/// AFTER the revoke commits observes the stamped `revoked_at` and is refused. An
/// upload already past that check settles by `funding_source_id` via
/// [`resolve_committed_upload`] (no re-check), so a revoked grant never strands an
/// in-flight upload. Revocation therefore gates only NEW charges, exactly the
/// wallet `revoke_grant` discipline.
///
/// The executor is generic so the revocation can ride the route's transaction
/// (committing atomically with its audit row) or run standalone against a pool.
pub async fn revoke_grant<'a, A>(
    executor: A,
    owner_operator_id: Uuid,
    funding_source_id: Uuid,
    grant_id: Uuid,
) -> Result<Option<RevokeOutcome>>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    // The CTE's existence arm pins the grant to a source this operator owns, so a
    // grant on a foreign or missing source never matches and is reported absent. The
    // conditional UPDATE stamps `revoked_at` only on a still-live grant, leaving an
    // already-revoked one's timestamp intact. A plain committed UPDATE is enough:
    // revocation is forward-looking, so no lock is taken.
    let row: Option<(bool,)> = sqlx::query_as(
        "WITH owned AS ( \
             SELECT g.id, g.revoked_at FROM cw_core.storage_grant g \
             JOIN cw_core.storage_funding_source s ON s.id = g.funding_source_id \
             WHERE g.id = $1 AND g.funding_source_id = $2 AND s.owner_operator_id = $3 \
         ), \
         updated AS ( \
             UPDATE cw_core.storage_grant g SET revoked_at = now() \
             FROM owned \
             WHERE g.id = owned.id AND owned.revoked_at IS NULL \
             RETURNING g.id \
         ) \
         SELECT EXISTS (SELECT 1 FROM updated) AS changed FROM owned",
    )
    .bind(grant_id)
    .bind(funding_source_id)
    .bind(owner_operator_id)
    .fetch_optional(executor)
    .await?;

    Ok(match row {
        None => None,
        Some((true,)) => Some(RevokeOutcome::Revoked),
        Some((false,)) => Some(RevokeOutcome::AlreadyRevoked),
    })
}
