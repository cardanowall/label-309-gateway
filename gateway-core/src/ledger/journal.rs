//! The append-only money journal.
//!
//! Every balance change is one immutable row in `cw_core.balance_ledger`; the
//! materialised per-account balance is maintained by the `balance_apply`
//! database trigger on insert. This module is the only code that inserts ledger
//! rows and reads balances.
//!
//! # Kinds and the registry
//!
//! Each entry has a `kind` that must be registered in
//! `cw_core.ledger_kind_registry` before an entry of that kind can be inserted.
//! The engine seeds three neutral kinds ([`CORE_LEDGER_KINDS`]); a vendor
//! registers its own with [`register_kind`], declaring per kind whether an entry
//! may overdraw the balance. [`insert_ledger_entry`] consults the registry to
//! validate the kind and to STAMP the entry's `allows_overdraft` flag; the
//! database trigger then enforces non-negativity purely from that stamped flag,
//! never re-reading the registry, so enforcement is a pure function of the row.
//!
//! # Idempotency
//!
//! An entry that carries a `ref` is unique on `(kind, ref)` (and refunds are
//! unique on `ref` across both refund kinds). [`insert_ledger_entry`] is
//! therefore idempotent on `ref`: a retried insert that collides with an
//! existing entry verifies the existing row matches (same account, amount, and
//! quote) and reports success without inserting a second charge, rather than
//! erroring on the conflict.
//!
//! # Events
//!
//! Every successful insert appends a `balance.changed` subject event (subject
//! kind `account`) and its delivery-outbox row in the SAME transaction as the
//! ledger row, through the [`crate::events`] module. The engine never calls
//! `pg_notify` directly for balance changes; the durable event log is the single
//! mechanism a consumer rides.

use serde_json::json;
use sqlx::Connection as _;
use uuid::Uuid;

use crate::{Error, Result};

/// The subject kind a balance-change event is recorded under.
pub const ACCOUNT_SUBJECT_KIND: &str = "account";

/// The event type appended on every ledger insert.
pub const BALANCE_CHANGED_EVENT: &str = "balance.changed";

/// The `registered_by` tag the engine stamps on its own seeded kinds.
pub const CORE_REGISTRANT: &str = "core";

/// The engine's own neutral ledger kinds, each declaring whether it may overdraw
/// the balance. All three are non-overdrawing: a publish debit is gated by an
/// affordability check before insert, and a refund only ever credits. The
/// migration seeds these same rows; [`seed_core_kinds`] is the idempotent
/// code-side reconcile a fresh deployment can call to converge the registry with
/// this list.
pub const CORE_LEDGER_KINDS: &[(&str, bool)] = &[
    ("poe_publish", false),
    ("refund_rollback", false),
    ("refund_user", false),
];

/// A single ledger entry to insert.
///
/// `amount_micros` is a signed micro-USD delta (a debit is negative, a credit
/// positive) and must be nonzero. `ref` is the idempotency / cross-reference key
/// (the `poe_record` id for a publish debit or a refund); an entry with a `ref`
/// is idempotent on it. `quote_id` is stamped on a publish debit for audit
/// replay. `metadata` is opaque structured context the engine never interprets.
#[derive(Debug, Clone)]
pub struct LedgerEntry {
    /// The account the entry belongs to.
    pub account_id: Uuid,
    /// The registered kind of the entry.
    pub kind: String,
    /// Signed micro-USD delta; must be nonzero.
    pub amount_micros: i64,
    /// Idempotency / cross-reference key, or `None` for a debit with no natural
    /// key. A credit (positive delta) must carry one: [`insert_ledger_entry`]
    /// refuses an unkeyed credit, because without a `(kind, ref)` key a
    /// redelivered credit would silently apply twice.
    pub r#ref: Option<String>,
    /// The quote a publish debit consumed, stamped for audit; `None` otherwise.
    pub quote_id: Option<Uuid>,
    /// Opaque structured context for the entry.
    pub metadata: serde_json::Value,
    /// The request id that originated the entry, for tracing.
    pub request_id: Option<Uuid>,
}

/// The outcome of an [`insert_ledger_entry`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The entry was inserted as a new row.
    Inserted,
    /// An entry with the same `ref` already existed and matched this entry's
    /// account, amount, and quote; the insert was an idempotent no-op.
    AlreadyApplied,
}

/// Register a ledger kind, declaring whether an entry of that kind may overdraw
/// the balance.
///
/// Idempotent: re-registering an existing kind leaves it unchanged. A vendor
/// calls this at startup to register its own kinds (top-ups, grants, disputes)
/// before inserting entries of those kinds; `registered_by` is a free-text
/// attribution tag (the engine uses [`CORE_REGISTRANT`] for its own). The
/// executor is generic so the registration can ride a caller's transaction
/// (bootstrap registers the manual-adjustment kind atomically with the
/// operator it provisions) or run standalone against a pool.
pub async fn register_kind<'a, A>(
    executor: A,
    kind: &str,
    allows_overdraft: bool,
    registered_by: &str,
) -> Result<()>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO cw_core.ledger_kind_registry (kind, allows_overdraft, registered_by) \
         VALUES ($1, $2, $3) ON CONFLICT (kind) DO NOTHING",
    )
    .bind(kind)
    .bind(allows_overdraft)
    .bind(registered_by)
    .execute(executor)
    .await?;
    Ok(())
}

/// Reconcile the engine's own neutral kinds ([`CORE_LEDGER_KINDS`]) into the
/// registry, idempotently.
///
/// The migration already seeds these rows; this is the code-side equivalent a
/// caller can run to converge a registry that drifted (or to make the seed
/// explicit in a test harness). Existing rows are left untouched.
pub async fn seed_core_kinds(pool: &sqlx::PgPool) -> Result<()> {
    for (kind, allows_overdraft) in CORE_LEDGER_KINDS {
        register_kind(pool, kind, *allows_overdraft, CORE_REGISTRANT).await?;
    }
    Ok(())
}

/// Whether a kind is registered, and its overdraft flag, or `None` when the kind
/// is not registered.
///
/// [`insert_ledger_entry`] uses this to validate a kind and to stamp the entry's
/// `allows_overdraft` from the registry.
pub async fn lookup_kind(pool: &sqlx::PgPool, kind: &str) -> Result<Option<bool>> {
    let allows_overdraft: Option<bool> = sqlx::query_scalar(
        "SELECT allows_overdraft FROM cw_core.ledger_kind_registry WHERE kind = $1",
    )
    .bind(kind)
    .fetch_optional(pool)
    .await?;
    Ok(allows_overdraft)
}

/// Insert one ledger entry, idempotently on its `ref`, emitting a balance-change
/// event in the same transaction.
///
/// Validates the entry's kind is registered and stamps its `allows_overdraft`
/// from the registry, then inserts the row. The `balance_apply` trigger applies
/// the delta to the materialised balance and refuses a resulting negative balance
/// unless the stamped flag permits it. A balance-change subject event and its
/// outbox row are appended in the same transaction through [`crate::events`].
///
/// IDEMPOTENCY. When the entry carries a `ref` and a row with the same `(kind,
/// ref)` (or the same `ref` across the refund kinds) already exists, the insert
/// does not create a second row: it verifies the existing row matches this
/// entry's account, amount, and quote and returns [`InsertOutcome::AlreadyApplied`].
/// A mismatch (the same `ref` used for a different account or amount) is an error,
/// because it signals a caller bug rather than a benign retry.
///
/// The executor is generic so the insert can ride the caller's transaction (the
/// quote-consume path inserts the publish debit inside the same transaction that
/// locks the quote and the balance) or run standalone against a pool.
pub async fn insert_ledger_entry<'a, A>(executor: A, entry: &LedgerEntry) -> Result<InsertOutcome>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    // A credit MUST carry a ref. Without one there is no `(kind, ref)`
    // idempotency key, so a redelivered credit (a webhook retried, a job
    // re-run) would silently apply twice. Every engine path already supplies a
    // natural key and the manual-adjustment route mints one when the caller has
    // none; this is the engine-level guard that keeps a future vendor credit
    // kind from ever double-applying. Debits are not gated here: an unkeyed
    // debit is refused by affordability/overdraft checks long before it could
    // double-charge, and no debit path omits its key today.
    if entry.amount_micros > 0 && entry.r#ref.is_none() {
        return Err(Error::Config(format!(
            "a credit ledger entry (kind {:?}) must carry a ref: an unkeyed credit \
             cannot be applied idempotently on redelivery",
            entry.kind
        )));
    }

    let mut txn = executor.begin().await?;

    // Validate the kind is registered and read its overdraft flag to stamp on the
    // row. The trigger reads only the stamped column, so the registry lookup is
    // the single point that binds an entry to its kind's overdraft policy.
    let allows_overdraft: Option<bool> = sqlx::query_scalar(
        "SELECT allows_overdraft FROM cw_core.ledger_kind_registry WHERE kind = $1",
    )
    .bind(&entry.kind)
    .fetch_optional(&mut *txn)
    .await?;
    let Some(allows_overdraft) = allows_overdraft else {
        return Err(Error::Config(format!(
            "ledger kind {:?} is not registered",
            entry.kind
        )));
    };

    // Insert the row, absorbing a conflict on either idempotency index (the
    // (kind, ref) unique or the cross-kind refund unique). `RETURNING id` yields a
    // row only when this call actually inserted; a conflict yields none.
    let inserted_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO cw_core.balance_ledger \
           (account_id, kind, amount_micros, ref, quote_id, allows_overdraft, metadata, request_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT DO NOTHING \
         RETURNING id",
    )
    .bind(entry.account_id)
    .bind(&entry.kind)
    .bind(entry.amount_micros)
    .bind(entry.r#ref.as_deref())
    .bind(entry.quote_id)
    .bind(allows_overdraft)
    .bind(&entry.metadata)
    .bind(entry.request_id)
    .fetch_optional(&mut *txn)
    .await?;

    if inserted_id.is_none() {
        // No row landed: a conflict on an idempotency index absorbed the insert.
        // A benign retry collides on (kind, ref) with a row that matches this
        // entry's account, amount, and quote; verify that and report the no-op.
        // Anything else (the same ref reused for a different account/amount, or a
        // cross-kind refund collision where no same-(kind, ref) row exists) is a
        // caller bug, surfaced as an error rather than a silent success.
        let existing: Option<ExistingEntry> = sqlx::query_as(
            "SELECT account_id, amount_micros, quote_id FROM cw_core.balance_ledger \
             WHERE kind = $1 AND ref = $2",
        )
        .bind(&entry.kind)
        .bind(entry.r#ref.as_deref())
        .fetch_optional(&mut *txn)
        .await?;

        return match existing {
            Some(row)
                if row.account_id == entry.account_id
                    && row.amount_micros == entry.amount_micros
                    && row.quote_id == entry.quote_id =>
            {
                // A faithful retry of the same logical entry: idempotent no-op.
                txn.commit().await?;
                Ok(InsertOutcome::AlreadyApplied)
            }
            Some(_) => Err(Error::Config(format!(
                "ledger entry for ({:?}, ref {:?}) already exists with different \
                 account/amount/quote",
                entry.kind, entry.r#ref
            ))),
            None => Err(Error::Config(format!(
                "ledger entry ({:?}, ref {:?}) conflicts with an existing entry of a \
                 different kind for the same ref (single-refund across refund kinds)",
                entry.kind, entry.r#ref
            ))),
        };
    }

    // The row landed and the balance_apply trigger has applied it (the AFTER
    // INSERT trigger fires before RETURNING completes). Append the balance-change
    // event and its outbox row in this same transaction, so a consumer sees the
    // event if and only if the ledger entry committed.
    crate::events::append_subject_event(
        &mut *txn,
        ACCOUNT_SUBJECT_KIND,
        &entry.account_id.to_string(),
        BALANCE_CHANGED_EVENT,
        &json!({
            "kind": entry.kind,
            "amount_micros": entry.amount_micros,
            "request_id": entry.request_id,
        }),
    )
    .await?;

    txn.commit().await?;
    Ok(InsertOutcome::Inserted)
}

/// The fields of an existing ledger row the idempotency path verifies a retry
/// against.
#[derive(sqlx::FromRow)]
struct ExistingEntry {
    account_id: Uuid,
    amount_micros: i64,
    quote_id: Option<Uuid>,
}

/// A memoized clamp result row, read back to make a same-ref retry return the
/// first call's outcome (and to detect a cross-account or revised-amount reuse).
#[derive(sqlx::FromRow)]
struct ClampLogRow {
    account_id: Uuid,
    requested_micros: i64,
    debited_micros: i64,
}

/// The outcome of a clamped debit: how much was actually taken from the balance.
///
/// `debited_micros` is the non-negative amount removed from the balance — never
/// more than the balance at the time, never more than the requested amount. The
/// caller (a vendor's clawback flow) carries `requested − debited` as its own
/// out-of-band debt (arrears); the gateway only ever moves what the balance can
/// cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClampedDebitOutcome {
    /// The amount actually removed from the balance (>= 0, <= requested).
    pub debited_micros: i64,
    /// True when this call computed and recorded the result; false when a result
    /// under the same `ref` already existed and this was an idempotent replay
    /// returning the stored amount.
    pub newly_applied: bool,
}

/// Debit an account's balance toward zero by up to `amount_micros`, clamping at
/// the available balance, idempotent on `ref`, returning the amount actually
/// debited.
///
/// This is the primitive a clawback rides: "reduce the balance toward zero by up
/// to `amount`; whatever the balance cannot cover is the caller's to carry as
/// arrears." It eliminates the stamp-time balance split a caller would otherwise
/// compute, which goes stale between read and write (the balance moves while the
/// clawback is in flight). Because the inserted entry is `-min(amount, balance)`
/// it can NEVER overdraw, so the `balance_apply` trigger never refuses it.
///
/// IDEMPOTENCY. The result is memoized per `ref` in `cw_core.clamp_debit_log`.
/// Two mechanisms together make it correct under concurrency:
///   1. The `cw_core.balance` row is locked `FOR UPDATE` — the SAME row, locked
///      the SAME way, that publish-quote consume and storage-attempt debits take.
///      The clamp therefore SERIALISES against every other balance writer: a
///      concurrent publish/storage debit cannot land between this clamp's
///      balance read and its ledger insert and make the clamp's negative entry
///      overdraw. It is the only lock taken (no separate account-anchor lock),
///      so there is no lock-order inversion with those debit paths — which take
///      an FK share-lock on `cw_api.account` while holding the balance lock, and
///      would deadlock against a clamp that held the anchor exclusively while
///      waiting for the balance row.
///   2. The `clamp_debit_log (ref)` primary key is the idempotency point for the
///      NEVER-FUNDED case, where there is no balance row to lock: two concurrent
///      zero-clamps both read no row and race the log insert, and the loser's
///      unique-violation is resolved by re-reading the committed row. A
///      never-funded account has nothing to debit (balance 0 ⇒ debited 0 ⇒ no
///      ledger row), so no balance-overdraw race exists there to begin with.
///
/// On the memoized-result path:
///   - a logged result is returned verbatim (`newly_applied = false`). The clamp
///     is computed EXACTLY ONCE; a retry never re-clamps against a balance that
///     has since moved, and a zero-debit result is recovered like a nonzero one.
///   - a DIFFERENT account, OR a DIFFERENT requested amount, under the same ref
///     is a hard invariant violation. Stripe dispute and refund amounts are
///     IMMUTABLE over the object's lifecycle — a dispute's `amount` is fixed at
///     creation and a settled refund's `amount` never changes — so the clamp ref
///     (derived from that id) can only ever be replayed with the SAME amount. A
///     differing amount is therefore a must-never-happen; erroring rather than
///     silently honouring either the first or the second amount is what prevents
///     a silent under- or over-charge.
///   - otherwise the clamp is computed under the lock, the balance_ledger debit
///     posted (only when nonzero — a zero entry is invalid), and the log row
///     inserted unconditionally (memoizing even a zero result), all before
///     COMMIT. A concurrent racer that committed its log row first is caught by
///     the unique-violation fallback, which re-reads and returns that row.
///
/// `amount_micros` must be positive (a clamped debit only ever removes money).
///
/// The `kind` must be registered and non-overdrawing (the trigger relies on the
/// stamped flag); the engine reads its flag exactly as [`insert_ledger_entry`]
/// does.
///
/// The executor is generic over [`sqlx::Acquire`] so the clamp can ride a
/// caller's transaction (the control route commits it atomically with its audit
/// row) or run standalone against a pool. Under a caller's transaction the
/// internal begins become savepoints; the unique-violation fallback still works
/// there, because rolling back to the savepoint recovers the outer transaction
/// and READ COMMITTED gives the re-read a fresh snapshot of the racer's
/// committed row.
pub async fn insert_clamped_debit<'a, A>(
    executor: A,
    account_id: Uuid,
    kind: &str,
    amount_micros: i64,
    r#ref: &str,
    reason: &str,
    request_id: Option<Uuid>,
) -> Result<ClampedDebitOutcome>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    if amount_micros <= 0 {
        return Err(Error::Config(
            "a clamped debit amount must be positive".into(),
        ));
    }

    // The outer transaction is the connection handle (a savepoint when riding a
    // caller's transaction); the main work runs on an inner transaction under it,
    // so the unique-violation fallback can roll back a half-done clamp — the
    // debit ledger row included — and still re-read the winner on this
    // connection before the outer commit.
    let mut outer = executor.begin().await?;
    let mut txn = outer.begin().await?;

    // A memoized result under this ref is returned verbatim — the clamp is
    // computed once, ever. (Read before the balance lock so a pure replay does
    // not contend on the balance row at all.)
    if let Some(out) = read_logged_clamp(&mut txn, account_id, amount_micros, r#ref).await? {
        txn.commit().await?;
        outer.commit().await?;
        return Ok(out);
    }

    // Lock the balance row (when it exists) — the SAME row, the SAME way,
    // publish-quote consume and storage-attempt debits lock it — so no concurrent
    // debit can land between this read and the ledger insert and make the clamp
    // overdraw, and there is no lock-order inversion with those paths. A missing
    // row means a never-funded account: balance 0, nothing to lock, nothing to
    // debit; the clamp_debit_log unique constraint is the idempotency point there.
    let balance_micros: i64 = sqlx::query_scalar(
        "SELECT balance_micros FROM cw_core.balance WHERE account_id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_optional(&mut *txn)
    .await?
    .unwrap_or(0);
    let available = balance_micros.max(0);
    let debited = amount_micros.min(available);

    // The balance_ledger debit lands only when nonzero (a zero entry is invalid),
    // but the clamp result is memoized in clamp_debit_log UNCONDITIONALLY — that
    // is what makes a zero-debit call idempotent (a later same-ref retry against
    // a now-funded balance returns the stored 0 instead of re-debiting).
    if debited > 0 {
        let entry = LedgerEntry {
            account_id,
            kind: kind.to_string(),
            amount_micros: -debited,
            r#ref: Some(r#ref.to_string()),
            quote_id: None,
            metadata: json!({ "reason": reason, "clamped_request_micros": amount_micros }),
            request_id,
        };
        insert_ledger_entry(&mut *txn, &entry).await?;
    }

    let log_insert = sqlx::query(
        "INSERT INTO cw_core.clamp_debit_log (ref, account_id, requested_micros, debited_micros) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(r#ref)
    .bind(account_id)
    .bind(amount_micros)
    .bind(debited)
    .execute(&mut *txn)
    .await;

    // Insert-first idempotency, belt-and-suspenders: the anchor lock already
    // serialises same-account callers, but a unique-violation here (e.g. a racer
    // that committed under a different account-lock path) is resolved by
    // re-reading the committed row rather than erroring. A debit ledger row, if
    // any, rolls back with the aborted inner transaction — so we restart a clean
    // one to read the winner; READ COMMITTED gives the re-read a fresh snapshot,
    // so the racer's committed row is visible.
    if let Err(err) = log_insert {
        if is_unique_violation(&err) {
            txn.rollback().await?;
            let mut read_txn = outer.begin().await?;
            let winner = read_logged_clamp(&mut read_txn, account_id, amount_micros, r#ref).await?;
            read_txn.commit().await?;
            outer.commit().await?;
            return winner.ok_or_else(|| {
                Error::Config(format!(
                    "clamped debit (ref {ref:?}) unique-violated but no committed row was found"
                ))
            });
        }
        return Err(err.into());
    }

    txn.commit().await?;
    outer.commit().await?;
    Ok(ClampedDebitOutcome {
        debited_micros: debited,
        newly_applied: true,
    })
}

/// Read a memoized clamp result for `ref`, returning the idempotent-replay
/// outcome (`newly_applied = false`) or `None` when no row exists.
///
/// A stored row under a DIFFERENT account, or for a DIFFERENT `requested_micros`
/// than this call's, is a hard invariant violation. The clamp ref is derived
/// from an immutable Stripe id (a dispute's amount is fixed at creation, a
/// settled refund's never changes), so a replay can only carry the SAME amount;
/// a mismatch is a must-never-happen, surfaced rather than silently resolved to
/// either amount (which would under- or over-charge).
async fn read_logged_clamp(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: Uuid,
    amount_micros: i64,
    r#ref: &str,
) -> Result<Option<ClampedDebitOutcome>> {
    let logged: Option<ClampLogRow> = sqlx::query_as(
        "SELECT account_id, requested_micros, debited_micros \
         FROM cw_core.clamp_debit_log WHERE ref = $1",
    )
    .bind(r#ref)
    .fetch_optional(&mut **txn)
    .await?;
    let Some(row) = logged else {
        return Ok(None);
    };
    if row.account_id != account_id {
        return Err(Error::Config(format!(
            "clamped debit (ref {ref:?}) already recorded for a different account"
        )));
    }
    if row.requested_micros != amount_micros {
        return Err(Error::Config(format!(
            "clamped debit (ref {ref:?}) already recorded for a different requested amount \
             (stored {}, this call {amount_micros}); Stripe clawback amounts are immutable, \
             so this must never happen",
            row.requested_micros
        )));
    }
    Ok(Some(ClampedDebitOutcome {
        debited_micros: row.debited_micros,
        newly_applied: false,
    }))
}

/// Whether a sqlx error is a Postgres unique-violation (SQLSTATE 23505).
fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")
    )
}

/// One row of an account's ledger history, as the data-plane list serves it.
///
/// A projection of `cw_core.balance_ledger` minus the engine-internal columns
/// (`allows_overdraft`, `request_id` are enforcement/tracing details, not
/// account-facing history). `amount_micros` keeps the journal's signed
/// semantics: a debit is negative, a credit positive.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LedgerHistoryRow {
    /// The ledger row id.
    pub id: Uuid,
    /// The registered kind of the entry.
    pub kind: String,
    /// Signed micro-USD delta (negative debit, positive credit).
    pub amount_micros: i64,
    /// The idempotency / cross-reference key (the `poe_record` id for a publish
    /// debit or refund, the upload attempt id for a storage charge, a vendor's
    /// own key for an adjustment), or `None`.
    pub entry_ref: Option<String>,
    /// The quote a publish debit consumed, or `None`.
    pub quote_id: Option<Uuid>,
    /// The Cardano network fee component of a publish debit, in micro-USD,
    /// LEFT JOINed from the consumed quote. `None` for any entry that is not a
    /// publish (no quote to join) — storage charges, adjustments, refunds.
    pub network_usd_micros: Option<i64>,
    /// The service-fee (margin) component of a publish debit, in micro-USD,
    /// from the consumed quote. `None` for non-publish entries. The publish
    /// debit amount equals `network_usd_micros + service_usd_micros` — the
    /// margin is parked on the publish line (the storage charge is billed at
    /// raw cost on its own line) so a storage-only upload can be refunded
    /// independently.
    pub service_usd_micros: Option<i64>,
    /// The markup the publish was priced at, as a fraction (e.g. `0.2500` =
    /// 25%), from the consumed quote. `None` for non-publish entries.
    pub margin_pct: Option<rust_decimal::Decimal>,
    /// Opaque structured context stamped at insert (never interpreted here).
    pub metadata: serde_json::Value,
    /// When the entry was journalled.
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

/// One page of an account's ledger entries, newest first.
///
/// Keyset pagination over `(occurred_at DESC, id DESC)`: `before` is the
/// `(occurred_at, id)` of the last row of the previous page, and the query
/// resumes strictly after it. The `(account_id, occurred_at DESC)` index serves
/// the walk; `id` only breaks ties within one timestamp, so the order is total
/// and a row can never be skipped or repeated across pages. Callers fetch
/// `limit + 1` rows to learn whether another page exists without a second
/// query.
pub async fn list_ledger_entries(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    before: Option<(chrono::DateTime<chrono::Utc>, Uuid)>,
    limit: i64,
) -> Result<Vec<LedgerHistoryRow>> {
    let (before_at, before_id) = match before {
        Some((at, id)) => (Some(at), Some(id)),
        None => (None, None),
    };
    // LEFT JOIN the consumed quote so a publish debit carries its own cost
    // breakdown (network fee + service fee + margin) inline; non-publish rows
    // have a NULL quote_id and so NULL breakdown columns. This is the only read
    // surface for the per-publish components — there is no read-by-quote-id
    // endpoint — so the account-facing history can decompose each publish line
    // into the figures the user can reconcile against the chain explorer.
    let rows: Vec<LedgerHistoryRow> = sqlx::query_as(
        "SELECT l.id, l.kind, l.amount_micros, l.ref AS entry_ref, l.quote_id, \
                q.network_usd_micros, q.service_usd_micros, q.margin_pct, \
                l.metadata, l.occurred_at \
         FROM cw_core.balance_ledger l \
         LEFT JOIN cw_core.publish_quote q ON q.id = l.quote_id \
         WHERE l.account_id = $1 \
           AND ($2::timestamptz IS NULL OR (l.occurred_at, l.id) < ($2, $3)) \
         ORDER BY l.occurred_at DESC, l.id DESC \
         LIMIT $4",
    )
    .bind(account_id)
    .bind(before_at)
    .bind(before_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The account's current balance in micro-USD.
///
/// A missing `cw_core.balance` row reads as zero (an account with no ledger
/// activity has no row), so this never returns `None`.
pub async fn load_balance_micros(pool: &sqlx::PgPool, account_id: Uuid) -> Result<i64> {
    let balance: Option<i64> =
        sqlx::query_scalar("SELECT balance_micros FROM cw_core.balance WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;
    Ok(balance.unwrap_or(0))
}
