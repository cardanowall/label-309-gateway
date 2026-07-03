//! Wallet spend authority: the scope-bound signing capability and its grants.
//!
//! A wallet is a global on-chain identity ([`super::operator`]); who may SPEND it
//! is a separate question answered here. The entry to a spendable wallet for a
//! NEW spend is [`authorize_spend`], which confirms a principal is entitled and,
//! only then, mints an [`AuthorizedWallet`] capability; an in-flight settlement
//! resolves an already-authorized capability through [`resolve_inflight_wallet`]
//! (see "New spend vs. in-flight settlement" below). Both minters live inside this
//! module, and the capability's fields are private, so it is unforgeable from
//! outside. The keyring's signer is reachable only through that capability
//! ([`super::keyring::UnlockedKeyring::signer_for`] takes `&AuthorizedWallet`), so
//! no code path can sign from a bare address: a signer can be obtained only via a
//! token one of these two paths produced.
//!
//! # Two independent gates
//!
//! Spending a wallet requires BOTH:
//!
//!   - **Authorization** (this module): is the principal entitled? A live grant
//!     or the always-entitled registrar (or system key possession) says yes.
//!   - **Capability** (the keyring): does this instance physically hold the key?
//!     The keyring is the capability store; a grant the keyring cannot back is an
//!     authorization with no key to act on.
//!
//! The control plane writes grants but never signs (the keyring stays out of its
//! state); the runtime handlers that sign run the grant check as a `pool` query
//! they already have a pool for.
//!
//! # New spend vs. in-flight settlement
//!
//! Two production paths mint a capability, for two distinct questions:
//!
//!   - [`authorize_spend`] gates a NEW pick (is this principal entitled right
//!     now?). It consults live grants and may fall through to a different wallet.
//!   - [`resolve_inflight_wallet`] settles an ALREADY-AUTHORIZED in-flight
//!     transaction (a reorg rollback's cancelling replacement) strictly by its
//!     pinned `wallet_id`, with no entitlement re-check and no fallthrough: that
//!     spend was authorized at submit time, and its replacement must consume the
//!     original wallet's UTxOs, so a grant revoked (or the wallet set `draining`)
//!     after submit must not strand it. Both mint the same field-private,
//!     unforgeable token; the keyring is still the separate capability gate.
//!
//! # Who is entitled
//!
//! [`authorize_spend`] returns a capability when ANY of these hold for the
//! principal:
//!
//!   - the principal is [`SpendPrincipal::System`] (the instance holds the key,
//!     e.g. a wallet consolidating its own funds), or
//!   - the principal's operator is the wallet's registrar (always entitled to its
//!     own wallet, even after a `service` grant is revoked), or
//!   - a live `service` grant on the wallet (every principal is entitled), or
//!   - a live `operator` grant matching the principal's operator, or
//!   - a live `account` grant matching the principal's account.

use uuid::Uuid;

use crate::Result;

/// Proof that a principal may spend a specific wallet.
///
/// The fields are private so a caller cannot fabricate one. It is minted only
/// inside this `grant` module: by [`authorize_spend`] for a NEW spend (after the
/// entitlement check passes) or by [`resolve_inflight_wallet`] for an IN-FLIGHT
/// settlement (a spend already authorized at submit time). It carries the
/// wallet's id and verified address, so any signer reached through it
/// ([`super::keyring::UnlockedKeyring::signer_for`]) is provably scope-checked:
/// the address-keyed keyring lookup is never reachable from a bare string.
#[derive(Debug, Clone)]
pub struct AuthorizedWallet {
    wallet_id: Uuid,
    address: String,
}

impl AuthorizedWallet {
    /// The authorized wallet's id (the lease/submit-counter subject).
    #[must_use]
    pub fn wallet_id(&self) -> Uuid {
        self.wallet_id
    }

    /// The authorized wallet's verified payment address (the change address and
    /// the keyring signer key).
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Mint a capability directly, for tests that exercise a signer path without a
    /// live grant in the database.
    ///
    /// Compiled only under `cfg(test)` (this crate's own unit tests) or the
    /// `testsupport` feature (which this crate's integration suites turn on via a
    /// dev-dependency self-reference). In a normal `cargo build` or release the
    /// feature is off, so this constructor does not exist at all.
    ///
    /// An [`AuthorizedWallet`] is therefore minted only inside this `grant`
    /// module: by [`authorize_spend`] for a new spend, or by
    /// [`resolve_inflight_wallet`] for an in-flight settlement (both back a real,
    /// already-checked entitlement, so the capability stays unforgeable from
    /// outside the module); plus this `for_tests` seam, which is gated behind
    /// `#[cfg(any(test, feature = "testsupport"))]` and absent from a production
    /// build. The seam lets a keyring/grant test build a signer capability without
    /// standing up a database.
    ///
    /// This is a test-only seam: a downstream dependent could in principle turn on
    /// the off-by-default `testsupport` feature to reach this constructor, so that
    /// feature MUST never be enabled by a production dependent. Within this
    /// workspace it is enabled only by this crate's own test/example targets (the
    /// dev-dependency self-reference) and transitively by `pg-tests`; no production
    /// dependency turns it on.
    #[cfg(any(test, feature = "testsupport"))]
    #[doc(hidden)]
    #[must_use]
    pub fn for_tests(wallet_id: Uuid, address: String) -> Self {
        Self { wallet_id, address }
    }
}

/// A principal asking to spend a wallet.
///
/// The variant carries exactly the identity dimensions a grant can match: an
/// operator-direct submit carries its operator; an account submit carries both
/// its operator and account (so it matches either an operator grant or an account
/// grant); a system actor carries neither (its authority is key possession, not a
/// grant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendPrincipal {
    /// An operator-direct spend: entitled by the registrar match, a service
    /// grant, or an operator grant for this operator.
    Operator {
        /// The spending operator.
        operator_id: Uuid,
    },
    /// An account spend: entitled by the registrar match (the account's
    /// operator), a service grant, an operator grant for the account's operator,
    /// or an account grant for this account.
    Account {
        /// The operator the account belongs to.
        operator_id: Uuid,
        /// The spending account.
        account_id: Uuid,
    },
    /// A system actor whose authority is physical key possession, not a grant
    /// (e.g. the replenisher consolidating a wallet's own funds). It does not
    /// cross a tenant boundary, so no grant is required.
    System,
}

impl SpendPrincipal {
    /// The operator this principal acts under, if any (system carries none).
    fn operator_id(self) -> Option<Uuid> {
        match self {
            SpendPrincipal::Operator { operator_id }
            | SpendPrincipal::Account { operator_id, .. } => Some(operator_id),
            SpendPrincipal::System => None,
        }
    }

    /// The account this principal acts as, if any.
    fn account_id(self) -> Option<Uuid> {
        match self {
            SpendPrincipal::Account { account_id, .. } => Some(account_id),
            SpendPrincipal::Operator { .. } | SpendPrincipal::System => None,
        }
    }
}

/// The single entry to a spendable wallet: confirm `principal` is entitled to
/// spend `wallet_id`, and mint an [`AuthorizedWallet`] capability if so.
///
/// Returns `Ok(None)` when the wallet does not exist or the principal is not
/// entitled (the two are indistinguishable to the caller, so a probe cannot use
/// the result as an existence oracle). The check is a single round trip: it reads
/// the wallet's registrar and address and, in the same query, whether any live
/// grant entitles the principal. A `System` principal is entitled unconditionally
/// (its authority is key possession); every other principal is entitled by the
/// registrar match or a live grant.
///
/// The `account` grant arm is matched here for completeness (an account grant
/// entitles its named account), but per-account wallet SELECTION is intentionally
/// deferred: today an account grant can be issued only for an account the wallet's
/// registrar owns, and an account belongs to exactly one operator, so the
/// registrar/operator arms already entitle every such spend. The arm is kept so
/// the scope turns on additively later (see [`super::pool::pick_wallet`] for what
/// enabling per-account selection requires) without a schema or signature change.
pub async fn authorize_spend(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    principal: SpendPrincipal,
) -> Result<Option<AuthorizedWallet>> {
    let is_system = matches!(principal, SpendPrincipal::System);
    let row: Option<Row> = sqlx::query_as(
        "SELECT \
             w.address AS address, \
             ( \
                 $2 \
                 OR ($3::uuid IS NOT NULL AND w.registrar_operator_id = $3) \
                 OR EXISTS ( \
                     SELECT 1 FROM cw_core.wallet_grant g \
                     WHERE g.wallet_id = w.id AND g.revoked_at IS NULL AND ( \
                         g.scope_kind = 'service' \
                         OR (g.scope_kind = 'operator' AND g.operator_id = $3) \
                         OR (g.scope_kind = 'account'  AND g.account_id  = $4) \
                     ) \
                 ) \
             ) AS entitled \
         FROM cw_core.operator_wallet w \
         WHERE w.id = $1",
    )
    .bind(wallet_id)
    .bind(is_system)
    .bind(principal.operator_id())
    .bind(principal.account_id())
    .fetch_optional(pool)
    .await?;

    Ok(match row {
        Some(row) if row.entitled => Some(AuthorizedWallet {
            wallet_id,
            address: row.address,
        }),
        // The wallet is absent, or it exists but the principal is not entitled:
        // both collapse to None so the caller falls through to a fresh pick (or
        // refuses to sign) without learning which case it hit.
        _ => None,
    })
}

/// The columns [`authorize_spend`] reads back: the verified address and whether
/// the principal is entitled.
#[derive(sqlx::FromRow)]
struct Row {
    address: String,
    entitled: bool,
}

/// Resolve the capability for an ALREADY-AUTHORIZED in-flight spend, keyed
/// strictly on `wallet_id` with NO entitlement check and NO fallthrough.
///
/// This is the settlement counterpart to [`authorize_spend`]. The two answer
/// different questions and must not be conflated:
///
///   - [`authorize_spend`] gates a NEW pick: may this principal start spending
///     this wallet? It consults live grants and may report `None`, letting the
///     caller fall through to a different wallet.
///   - this function settles an IN-FLIGHT transaction (a reorg rollback's
///     cancelling replacement) whose spend was already authorized at submit time.
///     The replacement's forced inputs are the ORIGINAL wallet's UTxOs, so it can
///     only be built against that same wallet; switching wallets would strand the
///     transaction. Authority here is the binding the submit already recorded, not
///     a current grant, so a grant revoked (or a wallet set `draining`) AFTER
///     submit must NOT block settlement: a draining/revoked wallet still rolls back
///     its own in-flight transaction. There is therefore no entitlement query and
///     no fallthrough.
///
/// Returns `Ok(None)` only when the wallet row does not exist on `network` (an
/// id that names no wallet on this instance's chain). The mint stays inside this
/// module so the capability's field-private, unforgeable property holds: a
/// settlement capability is still produced solely by this crate, never by a
/// caller assembling one from a bare address.
pub async fn resolve_inflight_wallet(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    network: &str,
) -> Result<Option<AuthorizedWallet>> {
    // A single instance serves one network, and a wallet's network is immutable,
    // so the network predicate is a defense-in-depth filter (it can never select a
    // wallet bound to a different chain), symmetric with the new-pick path.
    let address: Option<String> = sqlx::query_scalar(
        "SELECT address FROM cw_core.operator_wallet WHERE id = $1 AND network = $2",
    )
    .bind(wallet_id)
    .bind(network)
    .fetch_optional(pool)
    .await?;

    Ok(address.map(|address| AuthorizedWallet { wallet_id, address }))
}

/// The scope a grant entitles. Mirrors the `wallet_grant.scope_kind` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantScope {
    /// Every operator/account on the instance may spend the wallet.
    Service,
    /// A named operator may spend the wallet.
    Operator {
        /// The entitled operator.
        operator_id: Uuid,
    },
    /// A named account may spend the wallet.
    Account {
        /// The entitled account.
        account_id: Uuid,
    },
}

impl GrantScope {
    /// The `scope_kind` wire token this scope stores.
    fn kind(self) -> &'static str {
        match self {
            GrantScope::Service => "service",
            GrantScope::Operator { .. } => "operator",
            GrantScope::Account { .. } => "account",
        }
    }

    /// The operator subject column value (set only for an operator grant).
    fn operator_id(self) -> Option<Uuid> {
        match self {
            GrantScope::Operator { operator_id } => Some(operator_id),
            GrantScope::Service | GrantScope::Account { .. } => None,
        }
    }

    /// The account subject column value (set only for an account grant).
    fn account_id(self) -> Option<Uuid> {
        match self {
            GrantScope::Account { account_id } => Some(account_id),
            GrantScope::Service | GrantScope::Operator { .. } => None,
        }
    }
}

/// The outcome of issuing a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueOutcome {
    /// A new grant row was inserted.
    Issued {
        /// The new grant's id.
        grant_id: Uuid,
    },
    /// A live grant of the same scope subject already exists on the wallet, so
    /// nothing was inserted (issuing a grant is idempotent).
    AlreadyGranted {
        /// The id of the existing live grant.
        grant_id: Uuid,
    },
}

/// Issue a spend grant on a wallet `registrar_operator_id` registered.
///
/// Only the wallet's registrar may grant on it: the insert is gated on the wallet
/// existing with this registrar, so an operator cannot grant on a wallet it does
/// not administer (the call reports [`None`], shaped like a missing wallet, no
/// cross-tenant existence oracle). An `account`-scoped grant additionally requires
/// that the named account belongs to this same operator, so the registrar cannot
/// entitle another operator's account to spend its wallet; this ownership check
/// lives in the engine signature, not only in the route, so a future caller cannot
/// bypass it. A foreign or missing account reports [`None`], the same shape as a
/// foreign wallet (no cross-tenant existence oracle).
///
/// Issuing is idempotent per scope subject, and idempotent ATOMICALLY: the insert
/// is `ON CONFLICT ... DO NOTHING` against the live-grant partial unique index, so
/// two concurrent issues of the same subject never both insert and the loser
/// reports [`IssueOutcome::AlreadyGranted`] (read back from the winning row)
/// rather than surfacing a raw unique violation.
pub async fn issue_grant<'a, A>(
    executor: A,
    registrar_operator_id: Uuid,
    wallet_id: Uuid,
    scope: GrantScope,
) -> Result<Option<IssueOutcome>>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    let mut txn = executor.begin().await?;

    // First confirm the wallet exists and is administered by this operator. The
    // insert below is gated on the same predicate, so this read is what lets a
    // missing/foreign wallet report None rather than silently no-op. Reading it on
    // the same transaction lets the register route issue a grant on a wallet it
    // just inserted but has not yet committed.
    let owns: Option<(bool,)> = sqlx::query_as(
        "SELECT (registrar_operator_id = $2) AS owns \
         FROM cw_core.operator_wallet WHERE id = $1",
    )
    .bind(wallet_id)
    .bind(registrar_operator_id)
    .fetch_optional(&mut *txn)
    .await?;
    match owns {
        None | Some((false,)) => return Ok(None),
        Some((true,)) => {}
    }

    // An account grant names an account, which must belong to the SAME operator
    // that administers the wallet. Enforce that here, in the engine, so the
    // entitlement (this account may spend this wallet) can never name an account
    // the operator does not own, regardless of which caller reached this function.
    // A foreign/absent account reports None, shaped like a foreign wallet.
    if let GrantScope::Account { account_id } = scope {
        let owns_account = crate::ledger::account::account_belongs_to_operator(
            &mut *txn,
            registrar_operator_id,
            account_id,
        )
        .await?;
        if !owns_account {
            return Ok(None);
        }
    }

    // Insert atomically against the partial unique index for this scope, so two
    // concurrent issues of the same subject can never both insert: at most one
    // wins, the other's ON CONFLICT is a no-op (empty RETURNING). This is the
    // idempotency boundary; a prior SELECT-then-INSERT had a race window where two
    // callers each saw no live grant and the loser hit a raw unique violation
    // instead of reporting AlreadyGranted. Each scope uses a literal statement
    // whose conflict target names that scope's partial index (columns plus the
    // `revoked_at IS NULL` predicate) so Postgres infers it; keeping the three
    // statements as literals avoids assembling SQL dynamically.
    let candidate_id = Uuid::now_v7();
    let inserted: Option<(Uuid,)> = match scope {
        GrantScope::Service => {
            sqlx::query_as(
                "INSERT INTO cw_core.wallet_grant \
               (id, wallet_id, scope_kind, operator_id, account_id, granted_by) \
             VALUES ($1, $2, 'service', NULL, NULL, $3) \
             ON CONFLICT (wallet_id) WHERE scope_kind = 'service' AND revoked_at IS NULL \
             DO NOTHING \
             RETURNING id",
            )
            .bind(candidate_id)
            .bind(wallet_id)
            .bind(registrar_operator_id)
            .fetch_optional(&mut *txn)
            .await?
        }
        GrantScope::Operator { operator_id } => {
            sqlx::query_as(
                "INSERT INTO cw_core.wallet_grant \
               (id, wallet_id, scope_kind, operator_id, account_id, granted_by) \
             VALUES ($1, $2, 'operator', $3, NULL, $4) \
             ON CONFLICT (wallet_id, operator_id) \
                 WHERE scope_kind = 'operator' AND revoked_at IS NULL \
             DO NOTHING \
             RETURNING id",
            )
            .bind(candidate_id)
            .bind(wallet_id)
            .bind(operator_id)
            .bind(registrar_operator_id)
            .fetch_optional(&mut *txn)
            .await?
        }
        GrantScope::Account { account_id } => {
            sqlx::query_as(
                "INSERT INTO cw_core.wallet_grant \
               (id, wallet_id, scope_kind, operator_id, account_id, granted_by) \
             VALUES ($1, $2, 'account', NULL, $3, $4) \
             ON CONFLICT (wallet_id, account_id) \
                 WHERE scope_kind = 'account' AND revoked_at IS NULL \
             DO NOTHING \
             RETURNING id",
            )
            .bind(candidate_id)
            .bind(wallet_id)
            .bind(account_id)
            .bind(registrar_operator_id)
            .fetch_optional(&mut *txn)
            .await?
        }
    };

    if let Some((grant_id,)) = inserted {
        txn.commit().await?;
        return Ok(Some(IssueOutcome::Issued { grant_id }));
    }

    // The insert hit the live-grant partial unique index: a grant of this subject
    // already exists. Read it back so the call stays idempotent (AlreadyGranted),
    // rather than surfacing the conflict as an error. The subject predicate matches
    // the scope's own column (NULL-safe for service, which names no subject).
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM cw_core.wallet_grant \
         WHERE wallet_id = $1 AND revoked_at IS NULL AND scope_kind = $2 \
           AND operator_id IS NOT DISTINCT FROM $3 \
           AND account_id  IS NOT DISTINCT FROM $4",
    )
    .bind(wallet_id)
    .bind(scope.kind())
    .bind(scope.operator_id())
    .bind(scope.account_id())
    .fetch_optional(&mut *txn)
    .await?;
    // A read-back row reports AlreadyGranted (idempotent re-issue). An empty
    // read-back means the conflicting row was revoked between the failed insert and
    // this read (a concurrent revoke): no live grant exists now, so it is reported
    // as a not-yet-granted None shaped like the missing-wallet case, which the
    // caller retries. This is a vanishingly small window and self-heals on retry.
    let outcome = existing.map(|(grant_id,)| IssueOutcome::AlreadyGranted { grant_id });
    txn.commit().await?;
    Ok(outcome)
}

/// The outcome of revoking a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// A live grant was revoked by this call.
    Revoked,
    /// The grant exists on a wallet this operator registered but was already
    /// revoked (an idempotent no-op).
    AlreadyRevoked,
}

/// Revoke a grant on a wallet `registrar_operator_id` registered.
///
/// Only the registrar may revoke a grant on its own wallet: the UPDATE is gated
/// on the grant's wallet having this registrar, so a grant on a foreign wallet
/// reports [`None`] (shaped like a missing grant). Idempotent: an already-revoked
/// grant reports [`RevokeOutcome::AlreadyRevoked`] without re-stamping its
/// `revoked_at`. It is a plain committed UPDATE: revoke takes NO lock and holds
/// no detached connection while it runs.
///
/// # Revocation is forward-looking
///
/// A new spend re-checks entitlement under the per-wallet advisory lock
/// ([`authorize_spend`] inside `submit_locked`) before signing; a spend that has
/// already passed that check holds the wallet lock and completes (it was entitled
/// when authorized). This is the same in-flight-completes principle the
/// rollback/settlement path follows. The per-wallet lock bounds in-flight spends
/// to at most one per wallet, so at most one already-authorized spend can complete
/// after a concurrent revoke.
///
/// `revoke_grant` therefore does NOT take the wallet lock: a spend authorizing
/// AFTER the revoke commits is refused (read-committed: its entitlement query
/// observes the stamped `revoked_at`), and an already-authorized in-flight spend
/// completes. No unentitled spend can ever sign, because [`authorize_spend`] would
/// return `None` for a principal whose only entitlement was the revoked grant.
///
/// Taking the wallet lock here would add no safety (with or without it the one
/// already-authorized in-flight spend completes and every subsequent spend sees
/// the revocation) while introducing a pool-deadlock hazard: the lock acquire
/// detaches a pooled connection and blocks, so a burst of blocked revokes could
/// starve the pool the lock-holding spend needs to finish its critical section.
/// The plain UPDATE avoids that entirely.
///
/// An in-flight SETTLEMENT (a reorg rollback's cancelling replacement) is
/// likewise unaffected: it resolves by wallet id via [`resolve_inflight_wallet`]
/// with no [`authorize_spend`], so a wallet whose grant is revoked (or that is set
/// `draining`) after submit still settles its own in-flight transaction.
///
/// The executor is generic so the revocation can ride the route's transaction
/// (committing atomically with its audit row) or run standalone against a pool.
pub async fn revoke_grant<'a, A>(
    executor: A,
    registrar_operator_id: Uuid,
    wallet_id: Uuid,
    grant_id: Uuid,
) -> Result<Option<RevokeOutcome>>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    // The CTE's existence arm pins the grant to a wallet this operator
    // registered, so a grant on a foreign or missing wallet never matches and is
    // reported absent. The conditional UPDATE stamps `revoked_at` only on a
    // still-live grant, leaving an already-revoked one's timestamp intact. A plain
    // committed UPDATE is enough: revocation is forward-looking (see the docs), so
    // no lock is taken and no connection is held detached while blocking.
    let row: Option<(bool,)> = sqlx::query_as(
        "WITH owned AS ( \
             SELECT g.id, g.revoked_at FROM cw_core.wallet_grant g \
             JOIN cw_core.operator_wallet w ON w.id = g.wallet_id \
             WHERE g.id = $1 AND g.wallet_id = $2 AND w.registrar_operator_id = $3 \
         ), \
         updated AS ( \
             UPDATE cw_core.wallet_grant g SET revoked_at = now() \
             FROM owned \
             WHERE g.id = owned.id AND owned.revoked_at IS NULL \
             RETURNING g.id \
         ) \
         SELECT EXISTS (SELECT 1 FROM updated) AS changed FROM owned",
    )
    .bind(grant_id)
    .bind(wallet_id)
    .bind(registrar_operator_id)
    .fetch_optional(executor)
    .await?;

    Ok(match row {
        None => None,
        Some((true,)) => Some(RevokeOutcome::Revoked),
        Some((false,)) => Some(RevokeOutcome::AlreadyRevoked),
    })
}
