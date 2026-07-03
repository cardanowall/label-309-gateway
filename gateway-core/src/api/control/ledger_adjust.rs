//! The manual ledger adjustment: an operator's balance grant or debit.
//!
//! The control plane lets an operator adjust an account's balance directly (a
//! goodwill credit, a correction, a manual settlement). The adjustment is one
//! signed ledger entry of the [`MANUAL_ADJUSTMENT_KIND`].
//!
//! That kind is NOT one of the engine's core-seeded kinds: the engine seeds only
//! its own neutral kinds (publish debit, the two refunds) and leaves every other
//! kind to a registrant. The reference binary's bootstrap subcommand registers
//! the manual-adjustment kind through [`register_manual_adjustment_kind`] as the
//! reference adapter (`registered_by = "reference"`, `allows_overdraft = false`),
//! so an adjustment behaves like every other non-overdrawing kind: the
//! `balance_apply` trigger refuses one that would drive the balance negative.

use uuid::Uuid;

use crate::ledger::account::AccountStatus;
use crate::ledger::journal::{self, ClampedDebitOutcome, InsertOutcome, LedgerEntry};
use crate::{Error, Result};

/// The outcome of an operator-scoped balance adjustment.
///
/// A target account the operator does not own resolves to
/// [`AdjustmentOutcome::AccountNotFound`] (the route renders it as a 404, no
/// cross-tenant existence oracle); an owned account carries the underlying ledger
/// [`InsertOutcome`] (a fresh insert, or an idempotent no-op). A positive credit
/// to an owned-but-non-active account resolves to
/// [`AdjustmentOutcome::AccountNotActive`] — the credit is refused atomically and
/// no ledger row is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdjustmentOutcome {
    /// The target account is absent or owned by another operator.
    AccountNotFound,
    /// The target account is owned by the operator but is not `active`, and the
    /// adjustment is a GENUINELY NEW positive credit. Crediting an account on its
    /// way out (the account-close flow disables before tombstoning) would orphan
    /// funds on a dead account, so the credit is refused. The status is read and
    /// locked inside the SAME transaction the ledger insert would ride, so the
    /// refusal is atomic against a concurrent enable/disable — there is no
    /// check-then-write window. Debits and reversals are NOT subject to this and
    /// still apply to a disabled account (a closing account must remain
    /// settleable). A REPLAY is not refused: a caller-supplied ref whose entry
    /// already landed reports [`AdjustmentOutcome::Applied`] (an idempotent
    /// no-op) even after the account left `active`, so a redelivery never
    /// masquerades as a refusal.
    AccountNotActive,
    /// The account is owned; the adjustment landed (or was an idempotent no-op).
    Applied(InsertOutcome),
}

/// The ledger kind a manual operator adjustment is recorded under.
pub const MANUAL_ADJUSTMENT_KIND: &str = "manual_adjustment";

/// The registrant tag the reference binary stamps when it registers the manual
/// adjustment kind: it is the reference adapter, not a core-seeded kind.
pub const MANUAL_ADJUSTMENT_REGISTRANT: &str = "reference";

/// The minimum length of an adjustment reason. A bare adjustment with no
/// rationale is rejected so the audit trail always carries why a balance moved.
pub const MIN_REASON_LEN: usize = 3;

/// Bind an operator-supplied idempotency ref into a per-operator namespace.
///
/// The operator is the engine's hard isolation boundary, but the journal's
/// `(kind, ref)` idempotency key (and the clamp log's `ref` primary key) are a
/// SINGLE GLOBAL namespace shared by every operator. A ref is operator-chosen, so
/// without this namespacing two operators can pick the same string: operator B
/// posting an adjustment/clamp to B's own account under ref `x` writes the only
/// `(manual_adjustment, x)` row, and operator A's later legitimate call under the
/// same `x` then collides with B's row on a DIFFERENT account — which the journal
/// treats as a must-never-happen hard error. That is a cross-operator
/// denial-of-service: one tenant can occupy another tenant's idempotency keys.
///
/// Prefixing the supplied ref with the AUTHENTICATED operator id gives each
/// operator a disjoint key space, so A's `x` and B's `x` never meet. The operator
/// id comes from the route's authenticated principal, never from operator input,
/// so a malicious operator cannot craft a ref that escapes its own prefix: B
/// supplying the literal `op:<A>:x` is stored as `op:<B>:op:<A>:x`, which still
/// lives in B's namespace and never collides with A's `op:<A>:x`. The WITHIN-operator
/// tripwire is preserved: the SAME operator posting the SAME supplied ref to two of
/// its OWN different accounts still maps both to one stored key, so the journal's
/// cross-account mismatch error still fires.
#[must_use]
pub fn operator_scoped_ref(operator_id: Uuid, supplied_ref: &str) -> String {
    format!("{OPERATOR_REF_PREFIX}{operator_id}:{supplied_ref}")
}

/// The fixed marker that opens an [`operator_scoped_ref`]. The stored ref is
/// `op:<operator_id>:<supplied_ref>`; this is the leading `op:` literal.
const OPERATOR_REF_PREFIX: &str = "op:";

/// Recover the operator-supplied ref from a stored one, for a read scoped to a
/// known operator.
///
/// The inverse of [`operator_scoped_ref`] for exactly `operator_id`: strips the
/// `op:<operator_id>:` prefix this engine wrote, returning the original
/// operator-supplied string. A ref that does NOT carry this operator's prefix is
/// returned verbatim — it was minted by the engine (the un-prefixed `adjust-<uuid>`
/// of a ref-less adjustment, or a non-adjustment kind's natural key such as a
/// publish record id), so it has no operator prefix to peel. The internal
/// namespacing therefore never leaks the operator id onto an account-facing read.
#[must_use]
pub fn strip_operator_scoped_ref(operator_id: Uuid, stored_ref: &str) -> &str {
    let prefix = format!("{OPERATOR_REF_PREFIX}{operator_id}:");
    stored_ref.strip_prefix(&prefix).unwrap_or(stored_ref)
}

/// Register the manual-adjustment kind, declaring it non-overdrawing.
///
/// Idempotent (re-registering leaves the existing row unchanged). The bootstrap
/// subcommand calls this once so the kind exists before any adjustment is made.
/// Registered as the reference adapter, not as a core kind. The executor is
/// generic so bootstrap can register it inside its provisioning transaction.
pub async fn register_manual_adjustment_kind<'a, A>(executor: A) -> Result<()>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    journal::register_kind(
        executor,
        MANUAL_ADJUSTMENT_KIND,
        false,
        MANUAL_ADJUSTMENT_REGISTRANT,
    )
    .await
}

/// Apply a manual balance adjustment to an account under `operator_id`.
///
/// Confirms the operator owns the target account before any ledger write (an
/// account of another operator yields [`AdjustmentOutcome::AccountNotFound`] and
/// no row is touched). `amount_usd_micros` is signed (a positive grant or a
/// negative debit) and must be nonzero. `reason` must be at least
/// [`MIN_REASON_LEN`] characters. `cap` bounds the absolute magnitude of a single
/// adjustment (an operator-configured guard against a fat-finger grant); an amount
/// exceeding it is rejected. The reason is stamped into the entry metadata for the
/// audit trail.
///
/// `idempotency_ref` lets a caller pin the entry's `(kind, ref)` idempotency key
/// to a deterministic value derived from the originating event (a Stripe payment
/// intent, a welcome grant tied to an account id, ...). A redelivered call with
/// the same ref collapses to an idempotent no-op rather than a second balance
/// move. `None` falls back to a fresh per-call ref, preserving the prior
/// "every adjustment is distinct" behaviour for callers that have no stable key. An
/// empty or whitespace-only `Some(ref)` is rejected: it is not a meaningful
/// idempotency key (the wire contract requires a non-empty `ref`), and accepting it
/// would silently collapse two unrelated empty-ref adjustments onto one key. A
/// caller with no stable key omits the ref (passing `None`) rather than passing an
/// empty string.
///
/// The kind must already be registered (the bootstrap path does this); the
/// `balance_apply` trigger refuses an adjustment that would overdraw the account.
/// On an owned account returns the entry insert outcome (a fresh insert, or an
/// idempotent no-op when the same `ref` was already applied).
///
/// CREDIT GUARD (atomic). A positive amount is a credit. A credit lands ONLY when
/// the target account is `active`, and the status is read with `SELECT ... FOR
/// UPDATE` INSIDE the same transaction the ledger row is inserted on. That makes
/// the check and the write one atomic unit: a concurrent enable/disable either
/// commits fully before the lock (the credit then sees the settled status) or
/// blocks behind the credit (and observes the credit's effect), so there is no
/// window where a disable slips between a status check and the insert. A credit to
/// a non-active owned account returns [`AdjustmentOutcome::AccountNotActive`] with
/// NO ledger row written and the balance untouched. Debits and reversals (a
/// non-positive amount) are never gated — a closing account must remain
/// settleable — and take the plain insert.
///
/// The executor is generic over [`sqlx::Acquire`] so the adjustment can ride the
/// route's transaction (committing atomically with its audit row — the internal
/// begin becomes a savepoint there) or run standalone against a pool.
#[allow(clippy::too_many_arguments)]
pub async fn apply_adjustment<'a, A>(
    executor: A,
    operator_id: Uuid,
    account_id: Uuid,
    amount_usd_micros: i64,
    reason: &str,
    cap_usd_micros: i64,
    idempotency_ref: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<AdjustmentOutcome>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    if amount_usd_micros == 0 {
        return Err(Error::Config(
            "a manual adjustment amount must be nonzero".into(),
        ));
    }
    if reason.trim().len() < MIN_REASON_LEN {
        return Err(Error::Config(format!(
            "an adjustment reason must be at least {MIN_REASON_LEN} characters"
        )));
    }
    if amount_usd_micros.unsigned_abs() > cap_usd_micros.unsigned_abs() {
        return Err(Error::Config(format!(
            "adjustment magnitude exceeds the configured cap of {cap_usd_micros} micro-USD"
        )));
    }
    // A supplied ref must be a meaningful idempotency key. An empty or whitespace-only
    // ref is not: it would become a real (kind, ref) key that two unrelated empty-ref
    // adjustments collide on. A caller with no stable key omits the ref entirely
    // (None mints a fresh uuid), rather than passing an empty string.
    if let Some(r) = idempotency_ref {
        if r.trim().is_empty() {
            return Err(Error::Config(
                "an adjustment ref, when provided, must not be empty".into(),
            ));
        }
    }

    let entry = LedgerEntry {
        account_id,
        kind: MANUAL_ADJUSTMENT_KIND.to_string(),
        amount_micros: amount_usd_micros,
        // A caller-supplied ref pins the (kind, ref) idempotency key to the
        // originating event so a redelivered call is a no-op; absent one, mint a
        // fresh ref per adjustment so every distinct operator adjustment lands.
        //
        // A supplied ref is namespaced to the AUTHENTICATED operator before it
        // reaches the global (kind, ref) key space, so one operator's ref can never
        // collide with another's. A minted ref is a fresh UUIDv7, globally unique by
        // construction and untargetable by another operator, so it is left as-is.
        r#ref: Some(match idempotency_ref {
            Some(r) => operator_scoped_ref(operator_id, r),
            None => format!("adjust-{}", Uuid::now_v7()),
        }),
        quote_id: None,
        metadata: serde_json::json!({ "reason": reason }),
        request_id,
    };

    // A debit larger than the balance is refused by the `balance_apply` trigger
    // (the kind is non-overdrawing), surfacing as a Postgres check_violation. That
    // is operator input, not an engine fault, so translate it into a validation
    // error (a 4xx) rather than letting it surface as an internal (5xx) error.
    let translate_overdraw = |e: Error| match would_overdraw(&e) {
        true => Error::Config("the adjustment would drive the account balance below zero".into()),
        false => e,
    };

    // One transaction for the whole adjustment (a savepoint when riding a
    // caller's transaction, a real transaction against a pool).
    let mut txn = executor.begin().await?;

    // A debit / reversal (non-positive) is never status-gated: a closing account
    // must stay settleable. Ownership is checked the same way credits check it.
    if amount_usd_micros <= 0 {
        if !crate::ledger::account::account_belongs_to_operator(&mut *txn, operator_id, account_id)
            .await?
        {
            return Ok(AdjustmentOutcome::AccountNotFound);
        }
        let outcome = journal::insert_ledger_entry(&mut *txn, &entry)
            .await
            .map_err(translate_overdraw)?;
        txn.commit().await?;
        return Ok(AdjustmentOutcome::Applied(outcome));
    }

    // A positive credit: the status check and the ledger insert share this
    // transaction, so the guard is atomic against a concurrent enable/disable.

    // Lock the account's satellite row (tenancy-scoped) and read its status. A
    // missing row is "not owned / absent" — the same 404 the ownership probe gives.
    // `FOR UPDATE` serialises this against the enable/disable transition, closing
    // the check-then-write window.
    let status: Option<AccountStatus> = sqlx::query_scalar(
        "SELECT status FROM cw_core.account_detail \
         WHERE account_id = $1 AND operator_id = $2 \
         FOR UPDATE",
    )
    .bind(account_id)
    .bind(operator_id)
    .fetch_optional(&mut *txn)
    .await?;

    let Some(status) = status else {
        // No owned row: roll back (nothing was written) and report not-found.
        txn.rollback().await?;
        return Ok(AdjustmentOutcome::AccountNotFound);
    };
    if status != AccountStatus::Active {
        // Before refusing, distinguish a REPLAY from a genuinely new credit. A
        // caller-supplied ref pins the credit to its originating event; if that
        // entry already landed (it applied while the account was still active),
        // a redelivery must report the applied outcome — returning
        // AccountNotActive would hide the applied credit and invite the caller
        // to re-issue it under a fresh ref. Only a caller-supplied ref can
        // replay: a minted `adjust-<uuid>` ref is fresh per call.
        if idempotency_ref.is_some() {
            let existing: Option<(Uuid, i64)> = sqlx::query_as(
                "SELECT account_id, amount_micros FROM cw_core.balance_ledger \
                 WHERE kind = $1 AND ref = $2",
            )
            .bind(MANUAL_ADJUSTMENT_KIND)
            .bind(entry.r#ref.as_deref())
            .fetch_optional(&mut *txn)
            .await?;
            if let Some((applied_account, applied_amount)) = existing {
                txn.rollback().await?;
                // Mirror the journal's replay verification: a matching row is
                // the idempotent no-op; the same ref reused with a different
                // account or amount is a caller bug, never a silent success.
                return if applied_account == account_id && applied_amount == amount_usd_micros {
                    Ok(AdjustmentOutcome::Applied(InsertOutcome::AlreadyApplied))
                } else {
                    Err(Error::Config(format!(
                        "ledger entry for ({MANUAL_ADJUSTMENT_KIND:?}, ref {:?}) already \
                         exists with different account/amount",
                        entry.r#ref
                    )))
                };
            }
        }
        // A genuinely new credit to an owned-but-non-active account is refused.
        // The transaction holds no write, so the rollback leaves the balance and
        // ledger untouched.
        txn.rollback().await?;
        return Ok(AdjustmentOutcome::AccountNotActive);
    }

    // The account is active and its status row is locked for the life of this
    // transaction; insert the credit on the same transaction so the two commit
    // together (or roll back together).
    let outcome = journal::insert_ledger_entry(&mut *txn, &entry)
        .await
        .map_err(translate_overdraw)?;
    txn.commit().await?;
    Ok(AdjustmentOutcome::Applied(outcome))
}

/// The outcome of an operator-scoped clamped debit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClampedDebitResult {
    /// The target account is absent or owned by another operator.
    AccountNotFound,
    /// The account is owned; the clamped debit ran (possibly debiting 0 when the
    /// balance was empty, or an idempotent no-op on retry).
    Applied(ClampedDebitOutcome),
}

/// Debit an account toward zero by up to `amount_usd_micros`, clamping at the
/// available balance, under the manual-adjustment kind, idempotent on `ref`.
///
/// This is the clawback primitive: it removes from the balance only what the
/// balance can cover and reports the actual amount taken, so the vendor carries
/// `requested − debited` as arrears WITHOUT a stamp-time balance read that goes
/// stale before the debit lands. Unlike [`apply_adjustment`], it can never be
/// refused for overdraft — the inserted entry is exactly the clamped amount.
///
/// Ownership, cap, and reason validation mirror [`apply_adjustment`]:
/// a target the operator does not own is [`ClampedDebitResult::AccountNotFound`];
/// `amount_usd_micros` must be positive (a clamped debit only removes money) and
/// within `cap_usd_micros`; `reason` at least [`MIN_REASON_LEN`] chars. `ref` is
/// required (a clawback always has a stable originating id) and non-empty.
///
/// The executor is generic over [`sqlx::Acquire`] so the debit can ride the
/// route's transaction (committing atomically with its audit row) or run
/// standalone against a pool.
#[allow(clippy::too_many_arguments)]
pub async fn clamp_debit<'a, A>(
    executor: A,
    operator_id: Uuid,
    account_id: Uuid,
    amount_usd_micros: i64,
    reason: &str,
    cap_usd_micros: i64,
    idempotency_ref: &str,
    request_id: Option<Uuid>,
) -> Result<ClampedDebitResult>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    if amount_usd_micros <= 0 {
        return Err(Error::Config(
            "a clamped debit amount must be positive".into(),
        ));
    }
    if reason.trim().len() < MIN_REASON_LEN {
        return Err(Error::Config(format!(
            "an adjustment reason must be at least {MIN_REASON_LEN} characters"
        )));
    }
    if amount_usd_micros.unsigned_abs() > cap_usd_micros.unsigned_abs() {
        return Err(Error::Config(format!(
            "adjustment magnitude exceeds the configured cap of {cap_usd_micros} micro-USD"
        )));
    }
    if idempotency_ref.trim().is_empty() {
        return Err(Error::Config(
            "a clamped debit ref must not be empty".into(),
        ));
    }

    // One transaction for the ownership check and the clamp (a savepoint when
    // riding a caller's transaction, a real transaction against a pool).
    let mut txn = executor.begin().await?;
    if !crate::ledger::account::account_belongs_to_operator(&mut *txn, operator_id, account_id)
        .await?
    {
        return Ok(ClampedDebitResult::AccountNotFound);
    }

    // Namespace the operator-supplied ref to the AUTHENTICATED operator before it
    // reaches the clamp log's GLOBAL `ref` primary key, so one operator's clawback
    // ref can never occupy another operator's key. The within-operator semantics are
    // unchanged: the same operator replaying the same supplied ref maps to the same
    // stored ref and is the idempotent no-op, while the same ref against two of its
    // OWN accounts still trips the log's cross-account invariant.
    let scoped_ref = operator_scoped_ref(operator_id, idempotency_ref);

    let outcome = journal::insert_clamped_debit(
        &mut *txn,
        account_id,
        MANUAL_ADJUSTMENT_KIND,
        amount_usd_micros,
        &scoped_ref,
        reason,
        request_id,
    )
    .await?;
    txn.commit().await?;
    Ok(ClampedDebitResult::Applied(outcome))
}

/// Whether an engine error is the `balance_apply` trigger refusing an overdraft
/// (a Postgres `check_violation`, SQLSTATE 23514).
fn would_overdraw(error: &Error) -> bool {
    matches!(
        error,
        Error::Database(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23514")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kind_and_registrant_are_the_locked_reference_values() {
        assert_eq!(MANUAL_ADJUSTMENT_KIND, "manual_adjustment");
        assert_eq!(MANUAL_ADJUSTMENT_REGISTRANT, "reference");
    }

    /// Two operators supplying the SAME ref produce DISTINCT stored refs, so they
    /// land in disjoint namespaces; the same operator + same ref is stable (the
    /// idempotency key), and strip is the exact inverse for the right operator.
    #[test]
    fn operator_scoping_is_disjoint_stable_and_invertible() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();

        let a_x = operator_scoped_ref(a, "x");
        let b_x = operator_scoped_ref(b, "x");
        assert_ne!(
            a_x, b_x,
            "two operators' same supplied ref must not collide"
        );
        assert_eq!(
            a_x,
            operator_scoped_ref(a, "x"),
            "the scoping is deterministic"
        );

        // Strip is the inverse for the owning operator, and a no-op for a foreign one.
        assert_eq!(strip_operator_scoped_ref(a, &a_x), "x");
        assert_eq!(
            strip_operator_scoped_ref(b, &a_x),
            a_x,
            "a ref under another operator's prefix is not peeled"
        );

        // An engine-minted (un-prefixed) ref is returned verbatim by strip.
        let minted = format!("adjust-{}", Uuid::now_v7());
        assert_eq!(strip_operator_scoped_ref(a, &minted), minted);
    }

    /// A malicious operator cannot escape its own namespace by crafting a ref that
    /// already looks operator-scoped: B supplying the literal `op:<A>:x` is stored
    /// under B's prefix and never collides with A's genuine `op:<A>:x`.
    #[test]
    fn a_crafted_prefix_cannot_escape_the_suppliers_namespace() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();

        let a_genuine = operator_scoped_ref(a, "x");
        let b_crafted = operator_scoped_ref(b, &format!("op:{a}:x"));
        assert_ne!(
            a_genuine, b_crafted,
            "B forging A's prefix must not land on A's stored key"
        );
        // Peeling B's prefix recovers exactly what B supplied — A's id stays buried
        // inside B's value, so it is never read as A's namespace.
        assert_eq!(
            strip_operator_scoped_ref(b, &b_crafted),
            format!("op:{a}:x")
        );
    }
}
