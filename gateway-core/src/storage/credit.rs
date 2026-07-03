//! The operator's prepaid storage-credit (winc) ledger and the reconcile loop.
//!
//! `winc` is a remote prepaid balance the gateway holds at a storage provider
//! (Turbo by default) against a funding source's Arweave address. The gateway can
//! neither buy nor convert it: an operator funds it out of band through the
//! provider's own rails. This module owns three things over that balance.
//!
//! # The append-only winc journal
//!
//! Every believed change to the balance is one immutable row in
//! `cw_core.storage_credit_ledger`; the materialized per-source balance in
//! `cw_core.storage_credit` is maintained by the `storage_credit_apply` database
//! trigger on insert. [`insert_credit_entry`] is the only code that appends a row.
//! It is the operator-facing twin of the user's USD
//! [`crate::ledger::journal::insert_ledger_entry`]: a `charge` (negative) is
//! appended in the upload reserve transaction recording believed consumption, a
//! `reconcile` (signed) is appended by the reconcile loop after reading the
//! authoritative live balance, a `refund` (positive) records a rare
//! provider-side reversal, and a `topup` (positive) records an operator top-up
//! whose provider credit landed (appended by the register/poll step in the same
//! transaction that marks the `cw_core.storage_topup` row credited). Idempotency
//! is on `(funding_source_id, kind, ref)`, so a retried append that collides
//! with an existing row reports success without writing a second delta, the
//! same discipline the USD journal uses on `(kind, ref)`.
//!
//! # The cached-credit affordability read
//!
//! [`affords`] reads the materialized `storage_credit` row, never the provider, so
//! the request path makes zero provider calls regardless of concurrency. A missing
//! row is treated as unfunded (the first reconcile has not stamped the balance
//! yet), so the gateway never silently assumes solvency.
//!
//! # The reconcile loop
//!
//! [`CreditReconcileHandler`] is the only winc network caller in the whole engine.
//! On each tick it first absorbs the source's landed top-ups
//! ([`super::absorb_credited_topups`]: a `registered` top-up whose provider
//! credit arrived is journalled into the believed balance, so an operator's own
//! funding never reads as drift), then reads the authoritative live balance
//! through a [`WincBalanceProvider`], appends a `reconcile` delta that brings the
//! believed balance back to the live value, and surfaces two operator-facing
//! signals: `storage.credit.low` when the live balance has fallen below the safety
//! floor, and `storage.credit.drift` when the live balance moved by more than the
//! gateway's own journalled activity explains (the backstop for a provider that,
//! in a crash tail, charged twice for one upload). A provider that is unreachable
//! writes a stale-visibility marker and keeps serving the prior row, so a
//! transient outage never blanks the balance a quote reads.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde_json::json;
use uuid::Uuid;

use crate::storage::backend::StorageError;
use crate::storage::topup::{absorb_credited_topups, FundTxRegistrar};
use crate::{Error, Result};

/// The subject kind an operator-facing storage-credit event is recorded under.
///
/// Distinct from the account (USD balance) subject and the PoE-record subject:
/// these events concern an operator's funding source, not a customer, so they
/// ride their own subject and never reach a customer's balance stream.
pub const FUNDING_SOURCE_SUBJECT_KIND: &str = "storage_funding_source";

/// The event appended when the reconcile loop finds the live balance below the
/// configured safety floor, so the operator can top up before uploads start
/// refusing.
pub const CREDIT_LOW_EVENT: &str = "storage.credit.low";

/// The event appended when the live balance moved by more than the gateway's own
/// charges explain. It alerts the operator to an unexpected provider-side spend;
/// the user is never affected because the USD ledger is single-settlement, so the
/// only consequence of a crash-tail duplicate provider POST is operator winc
/// drift, which the `reconcile` row in the same tick self-corrects.
pub const CREDIT_DRIFT_EVENT: &str = "storage.credit.drift";

/// A winc-credit journal kind.
///
/// The wire spelling matches the `storage_credit_ledger.kind` CHECK constraint
/// exactly, so the enum is the single source of truth for the four kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditKind {
    /// Believed consumption appended in the upload reserve transaction (negative).
    Charge,
    /// A signed correction appended by the reconcile loop after reading the live
    /// balance.
    Reconcile,
    /// A rare provider-side reversal (positive).
    Refund,
    /// An operator top-up whose provider credit landed (positive), appended in
    /// the same transaction that marks the `storage_topup` row credited.
    Topup,
}

impl CreditKind {
    /// The persisted kind string (matching the CHECK constraint).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CreditKind::Charge => "charge",
            CreditKind::Reconcile => "reconcile",
            CreditKind::Refund => "refund",
            CreditKind::Topup => "topup",
        }
    }
}

/// A single winc-credit journal entry to append.
///
/// `winc_delta` is a signed winston-credit delta and must be nonzero (the
/// database CHECK rejects a zero delta, so an append always carries information).
/// `ref` is the idempotency / cross-reference key: the upload-attempt id for a
/// `charge`/`refund`, the reconcile tick id for a `reconcile`, the
/// `storage_topup` id for a `topup`. An entry that carries a `ref` is idempotent
/// on `(funding_source_id, kind, ref)`.
#[derive(Debug, Clone)]
pub struct CreditEntry {
    /// The funding source whose balance the entry moves.
    pub funding_source_id: Uuid,
    /// The kind of the entry.
    pub kind: CreditKind,
    /// Signed winston-credit delta; must be nonzero.
    pub winc_delta: Decimal,
    /// Idempotency / cross-reference key, or `None` for an entry with no natural
    /// key.
    pub r#ref: Option<String>,
}

/// The outcome of an [`insert_credit_entry`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditOutcome {
    /// The entry was appended as a new journal row, moving the materialized
    /// balance.
    Inserted,
    /// An entry with the same `(funding_source_id, kind, ref)` already existed; the
    /// append was an idempotent no-op and the balance was not moved twice.
    AlreadyApplied,
}

/// The materialized winc balance for a funding source, as maintained by the
/// `storage_credit_apply` trigger.
///
/// A missing row (no journal activity yet) reads as [`None`] from
/// [`load_credit`], which [`affords`] treats as unfunded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageCredit {
    /// The believed winc balance: the sum of every journal delta for the source.
    pub winc_balance: Decimal,
    /// The provider-reported bytes the current balance can fund, when the last
    /// reconcile carried it; `None` until a reconcile stamps it.
    pub fundable_bytes: Option<i64>,
    /// The believed balance at the last reconcile, for drift diagnostics.
    pub last_reconciled_winc: Option<Decimal>,
    /// When the last reconcile stamped this row.
    pub last_reconciled_at: Option<DateTime<Utc>>,
    /// A human-readable marker set when the last refresh attempt failed, so an
    /// operator sees a stale balance rather than a silent one.
    pub last_error: Option<String>,
}

/// The verdict of an affordability check against the cached credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffordVerdict {
    /// The cached balance covers the chargeable bytes and clears the safety floor.
    Affordable,
    /// No materialized balance exists yet (the first reconcile has not stamped
    /// it), so solvency is unknown and the upload is refused until it has.
    Unfunded,
    /// The believed balance is at or below the configured safety floor.
    BelowSafetyFloor,
    /// The provider-reported fundable byte ceiling cannot cover the chargeable
    /// bytes.
    InsufficientForBytes,
}

impl AffordVerdict {
    /// Whether the verdict permits the upload to proceed.
    #[must_use]
    pub fn is_affordable(self) -> bool {
        matches!(self, AffordVerdict::Affordable)
    }
}

/// Append one winc-credit journal entry, idempotently on its
/// `(funding_source_id, kind, ref)`.
///
/// The `storage_credit_apply` trigger applies the delta to the materialized
/// balance as the row lands; there is no non-negativity gate, because winc is a
/// remote balance the gateway can drive below zero in its belief (a charge raced
/// ahead of a reconcile) and the reconcile loop corrects the drift. When the entry
/// carries a `ref` and a row with the same `(funding_source_id, kind, ref)` already
/// exists, the append does not create a second row and the balance is not moved
/// twice: it reports [`CreditOutcome::AlreadyApplied`]. This is what lets a
/// reconcile tick that re-runs against the same `(source, tick_id)`, or a retried
/// upload charge against the same attempt id, be a benign no-op.
///
/// A same-ref collision whose EXISTING row carries a different delta is judged
/// per kind. For `charge`/`refund`/`topup` it is a hard error, mirroring the
/// USD journal's amount-mismatch guard: those deltas are fixed by the attempt
/// or top-up they reference, so a faithful retry can only ever carry the same
/// value and a mismatch is a caller bug, never to be silently absorbed. For
/// `reconcile` it is a benign [`CreditOutcome::AlreadyApplied`]: the delta is
/// recomputed per attempt (`live − believed`), so a retry of a partially-failed
/// tick whose live balance moved in between legitimately computes a different
/// value. The ref means "this tick already corrected this source once"; any
/// residual movement is the next tick's business, and treating the mismatch as
/// fatal would wedge the tick forever (every retry recomputes, every recompute
/// mismatches).
///
/// The executor is generic so the append can ride the caller's transaction (the
/// upload reserve transaction appends the believed `charge` inside the same
/// transaction that places the USD hold, the register/poll step appends the
/// `topup` inside the transaction that marks the top-up credited) or run
/// standalone against a pool.
pub async fn insert_credit_entry<'a, A>(executor: A, entry: &CreditEntry) -> Result<CreditOutcome>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    if entry.winc_delta.is_zero() {
        // The database CHECK rejects this too, but catch it before the round trip
        // so the caller gets a clear engine error rather than a constraint string.
        return Err(Error::Config(
            "storage credit entry winc_delta must be nonzero".into(),
        ));
    }

    let mut txn = executor.begin().await?;

    // Append the row, absorbing a conflict on the (funding_source_id, kind, ref)
    // idempotency index. RETURNING id yields a row only when this call actually
    // inserted; a conflict yields none. The kind text comes from the enum, so it
    // can never disagree with the CHECK constraint.
    let inserted_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO cw_core.storage_credit_ledger \
           (funding_source_id, kind, winc_delta, ref) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT DO NOTHING \
         RETURNING id",
    )
    .bind(entry.funding_source_id)
    .bind(entry.kind.as_str())
    .bind(entry.winc_delta)
    .bind(entry.r#ref.as_deref())
    .fetch_optional(&mut *txn)
    .await?;

    if inserted_id.is_none() {
        // No row landed: a conflict on the idempotency index absorbed the append.
        // A faithful retry collides with a row that carries the SAME delta; verify
        // that and report the no-op. A same-(source, kind, ref) row with a
        // different delta is a caller bug surfaced as an error for the kinds whose
        // delta is fixed by their referent — except `reconcile`, whose delta is
        // recomputed from a moving live balance per attempt, where the existing
        // row already proves this tick corrected this source (see the function
        // docs for the asymmetry).
        let existing: Option<Decimal> = sqlx::query_scalar(
            "SELECT winc_delta FROM cw_core.storage_credit_ledger \
             WHERE funding_source_id = $1 AND kind = $2 AND ref = $3",
        )
        .bind(entry.funding_source_id)
        .bind(entry.kind.as_str())
        .bind(entry.r#ref.as_deref())
        .fetch_optional(&mut *txn)
        .await?;

        return match existing {
            Some(delta) if delta == entry.winc_delta || entry.kind == CreditKind::Reconcile => {
                txn.commit().await?;
                Ok(CreditOutcome::AlreadyApplied)
            }
            Some(_) => Err(Error::Config(format!(
                "storage credit entry for source {} ({}, ref {:?}) already exists with a \
                 different winc_delta",
                entry.funding_source_id,
                entry.kind.as_str(),
                entry.r#ref
            ))),
            None => Err(Error::Config(format!(
                "storage credit entry for source {} ({}, ref {:?}) conflicted on insert but no \
                 matching row was found",
                entry.funding_source_id,
                entry.kind.as_str(),
                entry.r#ref
            ))),
        };
    }

    txn.commit().await?;
    Ok(CreditOutcome::Inserted)
}

/// Read the materialized winc balance for a source, or `None` when no journal
/// activity has stamped it yet.
pub async fn load_credit(
    pool: &sqlx::PgPool,
    funding_source_id: Uuid,
) -> Result<Option<StorageCredit>> {
    let row: Option<CreditRow> = sqlx::query_as(
        "SELECT winc_balance, fundable_bytes, last_reconciled_winc, last_reconciled_at, last_error \
         FROM cw_core.storage_credit WHERE funding_source_id = $1",
    )
    .bind(funding_source_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// Decide whether the cached credit for a source can afford `chargeable_bytes`.
///
/// `chargeable_bytes` is the size already netted of the free-storage window by the
/// caller, so a free-window upload never reaches here. The read is purely against
/// the materialized `storage_credit` row; it makes no provider call, so a thousand
/// concurrent quotes add zero provider traffic. The verdicts, in order of the
/// gate they fail:
///
///   - no materialized row at all → [`AffordVerdict::Unfunded`] (unknown is
///     unfunded; the first reconcile has not stamped a balance);
///   - believed balance at or below `winc_safety_floor` →
///     [`AffordVerdict::BelowSafetyFloor`];
///   - a provider-reported `fundable_bytes` ceiling that cannot cover the
///     chargeable bytes → [`AffordVerdict::InsufficientForBytes`];
///   - otherwise [`AffordVerdict::Affordable`].
pub async fn affords(
    pool: &sqlx::PgPool,
    funding_source_id: Uuid,
    chargeable_bytes: u64,
    winc_safety_floor: Decimal,
) -> Result<AffordVerdict> {
    let Some(credit) = load_credit(pool, funding_source_id).await? else {
        return Ok(AffordVerdict::Unfunded);
    };
    Ok(verdict(&credit, chargeable_bytes, winc_safety_floor))
}

/// The pure affordability decision over a loaded credit row, factored out so it is
/// unit-testable without a database.
#[must_use]
pub fn verdict(
    credit: &StorageCredit,
    chargeable_bytes: u64,
    winc_safety_floor: Decimal,
) -> AffordVerdict {
    if credit.winc_balance <= winc_safety_floor {
        return AffordVerdict::BelowSafetyFloor;
    }
    if let Some(fundable) = credit.fundable_bytes {
        // A negative provider-reported ceiling means it cannot fund anything; a
        // chargeable size above the ceiling cannot be covered.
        if fundable < 0 || chargeable_bytes > u64::try_from(fundable).unwrap_or(0) {
            return AffordVerdict::InsufficientForBytes;
        }
    }
    AffordVerdict::Affordable
}

/// The live authoritative winc balance a [`WincBalanceProvider`] reports for one
/// funding source's address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WincBalance {
    /// The provider's authoritative winc balance for the address.
    pub winc: Decimal,
    /// The bytes the provider says that balance can fund, when it reports them.
    pub fundable_bytes: Option<i64>,
}

/// The seam the reconcile loop reads the live winc balance through.
///
/// This is the ONLY winc network call in the engine: the request path never reads
/// the provider (it reads the cached `storage_credit` row through [`affords`]), so
/// a thousand concurrent quotes add zero provider traffic. A backend with no notion
/// of a remote balance (a dev backend, the direct stub) returns
/// [`StorageError::Misconfigured`] so the reconcile loop can skip it cleanly rather
/// than invent a balance.
pub trait WincBalanceProvider: Send + Sync {
    /// Read the authoritative live winc balance for an Arweave address.
    fn get_winc_balance<'a>(
        &'a self,
        address: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<WincBalance, StorageError>>
                + Send
                + 'a,
        >,
    >;
}

/// The Turbo winc-balance provider: a standalone HTTP client that reads a funding
/// address's authoritative balance from a Turbo payment service.
///
/// It is deliberately separate from the upload backend, the same way the Cardano
/// [`crate::chain::gateway::KoiosGateway`] is a standalone provider rather than a
/// method on a wallet: the reconcile loop reads balances, the upload backend signs
/// and POSTs content, and the two call different provider endpoints. The base URL
/// is operator config (no provider is hardcoded), matching how the upload URL is
/// supplied to the upload backend. The address is sent as a query parameter; the
/// response carries the winc balance as a decimal string, which is parsed exactly.
pub struct TurboWincProvider {
    client: reqwest::Client,
    base_url: String,
}

impl TurboWincProvider {
    /// Build a winc-balance provider over the Turbo payment-service base URL.
    ///
    /// Returns [`StorageError::Misconfigured`] if the TLS-backed client cannot be
    /// built, the same way the chain providers surface a client-build failure as a
    /// configuration error the deployment must fix before serving.
    pub fn new(base_url: impl Into<String>) -> std::result::Result<Self, StorageError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| {
                StorageError::Misconfigured(format!("building winc-balance HTTP client: {e}"))
            })?;
        Ok(Self {
            client,
            base_url: base_url.into(),
        })
    }

    /// Build a provider over a caller-supplied client and base URL, the seam a
    /// behavioural test uses to point the real provider at a local fake server.
    #[must_use]
    pub fn with_client(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: base_url.into(),
        }
    }
}

impl WincBalanceProvider for TurboWincProvider {
    fn get_winc_balance<'a>(
        &'a self,
        address: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<WincBalance, StorageError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            // The address is a base64url Arweave address (the URL-safe alphabet
            // A-Za-z0-9_-), so it embeds in the query string without escaping,
            // matching the chain providers' format!-built request URLs.
            let url = format!(
                "{}/v1/account/balance/arweave?address={address}",
                self.base_url.trim_end_matches('/')
            );
            let response = self
                .client
                .get(&url)
                .send()
                .await
                .map_err(|e| StorageError::Unavailable(format!("reading winc balance: {e}")))?;

            let status = response.status();
            // A 404 is the payment service's authoritative "this address has no
            // account yet" — a zero balance, not an outage. Mapping it to an
            // error would mark a fresh, never-funded source permanently stale
            // instead of stamping the true zero the affordability read needs.
            if status.as_u16() == 404 {
                return Ok(WincBalance {
                    winc: Decimal::ZERO,
                    fundable_bytes: None,
                });
            }
            if !status.is_success() {
                return Err(StorageError::Unavailable(format!(
                    "winc-balance service returned {status}"
                )));
            }

            let body: WincBalanceBody =
                crate::http::read_capped_json(response, crate::http::JSON_BODY_CEILING)
                    .await
                    .map_err(|e| {
                        StorageError::Unavailable(format!("decoding winc balance: {e}"))
                    })?;
            body.into_balance()
        })
    }
}

/// The winc-balance response body. The winc figure is a decimal STRING in the wire
/// form (winc can exceed a JSON-safe integer), parsed exactly into a [`Decimal`].
#[derive(serde::Deserialize)]
struct WincBalanceBody {
    winc: String,
    #[serde(default)]
    fundable_bytes: Option<i64>,
}

impl WincBalanceBody {
    fn into_balance(self) -> std::result::Result<WincBalance, StorageError> {
        let winc =
            self.winc.trim().parse::<Decimal>().map_err(|e| {
                StorageError::Unavailable(format!("winc balance is not a number: {e}"))
            })?;
        Ok(WincBalance {
            winc,
            fundable_bytes: self.fundable_bytes,
        })
    }
}

/// One active funding source the reconcile loop refreshes.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ActiveFundingSource {
    /// The source id.
    pub id: Uuid,
    /// The source's verified Arweave address (the provider balance key).
    pub arweave_address: String,
    /// The backend the source draws from.
    pub backend: String,
}

/// Read every active funding source for a backend, the set the reconcile loop
/// refreshes each tick.
pub async fn active_funding_sources(
    pool: &sqlx::PgPool,
    backend: &str,
) -> Result<Vec<ActiveFundingSource>> {
    let rows = sqlx::query_as::<_, ActiveFundingSource>(
        "SELECT id, arweave_address, backend FROM cw_core.storage_funding_source \
         WHERE backend = $1 AND status = 'active' \
         ORDER BY created_at",
    )
    .bind(backend)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// What reconciling one source resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceReconcileOutcome {
    /// The believed balance already matched the live balance; no journal row was
    /// appended.
    Unchanged,
    /// A `reconcile` delta was appended to bring the believed balance to the live
    /// value.
    Corrected,
    /// The provider was unreachable; the prior row keeps serving and a
    /// stale-visibility marker was written.
    ProviderUnavailable,
}

/// The aggregate result of one reconcile pass over every active source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconcileSummary {
    /// Sources whose believed balance already matched the live balance.
    pub unchanged: usize,
    /// Sources whose believed balance was corrected by a `reconcile` delta.
    pub corrected: usize,
    /// Sources whose provider was unreachable this pass.
    pub unavailable: usize,
    /// `storage.credit.low` events emitted this pass.
    pub low_emitted: usize,
    /// `storage.credit.drift` events emitted this pass.
    pub drift_emitted: usize,
    /// Top-ups whose provider credit landed this pass and were journalled into
    /// the believed balance before the drift comparison.
    pub topups_credited: usize,
}

/// The reconcile loop's tuning, read from config so a deployment can override the
/// thresholds without a code change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileConfig {
    /// Below this believed winc balance, `affords` refuses; the reconcile loop
    /// emits `storage.credit.low` when the live balance crosses it.
    pub winc_safety_floor: Decimal,
    /// When `|live - believed|` exceeds this, the reconcile loop emits
    /// `storage.credit.drift`: the live balance moved more than the gateway's own
    /// charges explain.
    pub winc_drift_alert_threshold: Decimal,
}

/// Stamp the stale-visibility marker on a source whose provider lookup failed,
/// WITHOUT appending a journal row, so the prior believed balance keeps serving
/// quotes and the operator sees that the refresh is stale.
///
/// The `storage_credit_apply` trigger only runs on a journal insert, so this
/// writes the materialized row directly. A source that has never had a journal row
/// has no `storage_credit` row to mark; the upsert creates a minimal one carrying
/// only the marker so the staleness is still visible.
pub async fn mark_reconcile_unavailable(
    pool: &sqlx::PgPool,
    funding_source_id: Uuid,
    detail: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO cw_core.storage_credit (funding_source_id, winc_balance, last_error) \
         VALUES ($1, 0, $2) \
         ON CONFLICT (funding_source_id) DO UPDATE \
           SET last_error = EXCLUDED.last_error, updated_at = now()",
    )
    .bind(funding_source_id)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reconcile one source's believed balance against its live provider balance.
///
/// First absorbs the source's landed top-ups ([`absorb_credited_topups`]
/// through `registrar`): a `registered` top-up whose provider credit arrived is
/// journalled into the believed balance HERE, before the comparison, so an
/// operator's own funding is explained movement rather than drift. Then reads
/// the live balance through `provider`, computes `delta = live - believed`,
/// and, when the delta is nonzero, appends a `reconcile` journal row keyed on
/// `tick_id` (so two sources reconciled in the same tick never collide, because the
/// idempotency key includes the source id) that moves the believed balance to the
/// live value. A `|delta|` beyond `config.winc_drift_alert_threshold` emits
/// `storage.credit.drift` — only when this pass actually appended the
/// correction, so a retried tick never duplicates the alert. A live balance at
/// or below `config.winc_safety_floor` emits `storage.credit.low`. A provider
/// that is unreachable writes the stale-visibility marker and keeps serving the
/// prior row.
pub async fn reconcile_source<P: WincBalanceProvider, R: FundTxRegistrar>(
    pool: &sqlx::PgPool,
    provider: &P,
    registrar: &R,
    source: &ActiveFundingSource,
    tick_id: &str,
    config: &ReconcileConfig,
    summary: &mut ReconcileSummary,
) -> Result<SourceReconcileOutcome> {
    // Settle landed top-ups into the believed balance BEFORE the drift
    // comparison: the provider credits a registered top-up minutes after
    // acceptance, and without this the credit's arrival would read as an
    // unexplained live-balance jump. A poll failure is recorded on the top-up
    // row, never propagated, so it cannot mask the balance read below.
    summary.topups_credited += absorb_credited_topups(pool, registrar, source.id).await?;

    let live = match provider.get_winc_balance(&source.arweave_address).await {
        Ok(live) => live,
        Err(e) => {
            // Unreachable / indeterminate: keep serving the prior row, record the
            // staleness, retry next tick. Never blank the balance a quote reads.
            mark_reconcile_unavailable(pool, source.id, &e.to_string()).await?;
            summary.unavailable += 1;
            return Ok(SourceReconcileOutcome::ProviderUnavailable);
        }
    };

    let believed = load_credit(pool, source.id)
        .await?
        .map(|c| c.winc_balance)
        .unwrap_or(Decimal::ZERO);
    let delta = live.winc - believed;

    let outcome = if delta.is_zero() {
        // Already in sync; refresh the provider-reported fundable bytes (and clear
        // any stale-error marker) without moving the balance.
        stamp_fundable_bytes(pool, source.id, live.fundable_bytes).await?;
        summary.unchanged += 1;
        SourceReconcileOutcome::Unchanged
    } else {
        // The believed balance is wrong: append a reconcile delta that brings it to
        // the live value. The trigger stamps the last-reconciled diagnostics; this
        // call additionally records the provider-reported fundable bytes and clears
        // any stale-error marker.
        let appended = insert_credit_entry(
            pool,
            &CreditEntry {
                funding_source_id: source.id,
                kind: CreditKind::Reconcile,
                winc_delta: delta,
                r#ref: Some(tick_id.to_string()),
            },
        )
        .await?;
        stamp_fundable_bytes(pool, source.id, live.fundable_bytes).await?;
        summary.corrected += 1;

        // Drift: the live balance moved more than the gateway's own journalled
        // activity explains. The reconcile row above already self-corrects the
        // believed balance; this only alerts the operator to an unexpected
        // provider-side spend, which is the only consequence of a crash-tail
        // duplicate provider POST (the user is never double-charged). Emitted
        // only when THIS pass appended the correction: on a retried tick the
        // append is an idempotent no-op (the first attempt's row keeps the
        // ref), so the retry neither duplicates the first attempt's alert nor
        // fabricates one from a delta the journal did not absorb.
        if appended == CreditOutcome::Inserted && delta.abs() > config.winc_drift_alert_threshold {
            emit_credit_event(
                pool,
                source.id,
                CREDIT_DRIFT_EVENT,
                &json!({
                    "funding_source_id": source.id,
                    "backend": source.backend,
                    "believed_winc": believed.to_string(),
                    "live_winc": live.winc.to_string(),
                    "delta_winc": delta.to_string(),
                }),
            )
            .await?;
            summary.drift_emitted += 1;
        }

        SourceReconcileOutcome::Corrected
    };

    // Low credit: the authoritative live balance is below the floor uploads need.
    // Emitted off the LIVE balance (not the believed one), so it fires the moment a
    // provider read shows the operator must top up, regardless of drift.
    if live.winc <= config.winc_safety_floor {
        emit_credit_event(
            pool,
            source.id,
            CREDIT_LOW_EVENT,
            &json!({
                "funding_source_id": source.id,
                "backend": source.backend,
                "live_winc": live.winc.to_string(),
                "winc_safety_floor": config.winc_safety_floor.to_string(),
            }),
        )
        .await?;
        summary.low_emitted += 1;
    }

    Ok(outcome)
}

/// Run one reconcile pass over every active source for a backend.
///
/// `tick_id` is the deterministic instant of the cron occurrence, the same id the
/// scheduler dedupes on, so a `reconcile` row's `ref` is stable per occurrence and
/// a re-run of the same tick is an idempotent no-op. A single source's provider
/// failure does not abort the pass: it is recorded as a stale-visibility marker and
/// the loop moves on, so one unreachable address never starves the rest.
pub async fn run_reconcile<P: WincBalanceProvider, R: FundTxRegistrar>(
    pool: &sqlx::PgPool,
    provider: &P,
    registrar: &R,
    backend: &str,
    tick_id: &str,
    config: &ReconcileConfig,
) -> Result<ReconcileSummary> {
    let sources = active_funding_sources(pool, backend).await?;
    let mut summary = ReconcileSummary::default();
    for source in &sources {
        reconcile_source(
            pool,
            provider,
            registrar,
            source,
            tick_id,
            config,
            &mut summary,
        )
        .await?;
    }
    Ok(summary)
}

/// Record the provider-reported fundable bytes on the materialized row and clear
/// any stale-error marker, without moving the balance.
///
/// The `storage_credit_apply` trigger maintains `winc_balance`; the
/// provider-reported `fundable_bytes` and the stale-error clearing are diagnostics
/// that live outside the journal, so they are written here directly. A source with
/// no materialized row yet (a brand-new source whose first live read matched its
/// zero believed balance) gets a minimal row so the diagnostics are visible.
async fn stamp_fundable_bytes(
    pool: &sqlx::PgPool,
    funding_source_id: Uuid,
    fundable_bytes: Option<i64>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO cw_core.storage_credit (funding_source_id, winc_balance, fundable_bytes, last_error) \
         VALUES ($1, 0, $2, NULL) \
         ON CONFLICT (funding_source_id) DO UPDATE \
           SET fundable_bytes = EXCLUDED.fundable_bytes, last_error = NULL, updated_at = now()",
    )
    .bind(funding_source_id)
    .bind(fundable_bytes)
    .execute(pool)
    .await?;
    Ok(())
}

/// Append a durable operator-facing storage-credit event on the funding-source
/// subject.
///
/// These ride the same per-subject event log + delivery outbox the rest of the
/// engine uses, so an operator integration consumes them through the existing
/// outbox machinery. They are NOT on a customer's account stream: the
/// funding-source subject has no client SSE projection, so a customer never sees an
/// operator's funding signal.
async fn emit_credit_event(
    pool: &sqlx::PgPool,
    funding_source_id: Uuid,
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<()> {
    crate::events::append_subject_event(
        pool,
        FUNDING_SOURCE_SUBJECT_KIND,
        &funding_source_id.to_string(),
        event_type,
        payload,
    )
    .await?;
    Ok(())
}

/// The materialized-credit row shape, mapped onto [`StorageCredit`].
#[derive(sqlx::FromRow)]
struct CreditRow {
    winc_balance: Decimal,
    fundable_bytes: Option<i64>,
    last_reconciled_winc: Option<Decimal>,
    last_reconciled_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}

impl From<CreditRow> for StorageCredit {
    fn from(r: CreditRow) -> Self {
        Self {
            winc_balance: r.winc_balance,
            fundable_bytes: r.fundable_bytes,
            last_reconciled_winc: r.last_reconciled_winc,
            last_reconciled_at: r.last_reconciled_at,
            last_error: r.last_error,
        }
    }
}

// ---------------------------------------------------------------------------
// The reconcile cron handler, policy, and schedule.
// ---------------------------------------------------------------------------

/// The queue the storage-credit reconcile loop runs on.
pub const CREDIT_RECONCILE_QUEUE: &str = "storage_credit_reconcile";

/// The default reconcile cadence: every five minutes. It is the only winc network
/// caller, so it stays infrequent; a deployment overrides it via the `[storage]`
/// `winc_refresh_schedule`.
pub const DEFAULT_RECONCILE_SCHEDULE: &str = "0 */5 * * * *";

/// The policy for the reconcile queue: a singleton loop so a single reconcile pass
/// is in flight across the whole deployment (it is the only winc network caller, so
/// two replicas must never both read the provider per tick). A short fixed backoff
/// and a small attempt budget ride out a transient database blip until the next
/// scheduled tick; the pass is idempotent on the tick id, so a retry is cheap.
#[must_use]
pub fn credit_reconcile_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        CREDIT_RECONCILE_QUEUE,
        3,
        crate::runtime::Backoff::Fixed { base_secs: 60 },
        // One pass reads a handful of provider balances and appends bounded rows; a
        // 10-minute lease is ample and reclaims promptly if a replica dies mid-pass.
        600,
    )
}

/// The schedule that fires the reconcile loop on the configured cadence.
///
/// The `cron` expression comes from config (`winc_refresh_schedule`), defaulting to
/// [`DEFAULT_RECONCILE_SCHEDULE`]. The scheduler's `cron_tick` gate ensures exactly
/// one replica enqueues each occurrence.
#[must_use]
pub fn credit_reconcile_schedule(
    cron: impl Into<String>,
) -> crate::runtime::scheduler::CronSchedule {
    crate::runtime::scheduler::CronSchedule::new(
        cron.into(),
        CREDIT_RECONCILE_QUEUE,
        serde_json::Value::Null,
    )
}

/// The storage-credit reconcile job handler.
///
/// Register it on the runtime against [`CREDIT_RECONCILE_QUEUE`] with
/// [`credit_reconcile_policy`] and [`credit_reconcile_schedule`]. It owns its pool,
/// the winc-balance provider it reads each active source through (the only winc
/// network call), the fund-transaction registrar it polls each source's
/// registered top-ups through (so a landed credit is journalled before the
/// drift comparison), the backend whose sources it reconciles, and the
/// floor/drift-threshold config. Every pass is idempotent on the tick id, so the
/// at-least-once delivery the runtime guarantees is harmless.
pub struct CreditReconcileHandler<P: WincBalanceProvider, R: FundTxRegistrar> {
    pool: sqlx::PgPool,
    provider: P,
    registrar: R,
    backend: String,
    config: ReconcileConfig,
}

impl<P: WincBalanceProvider, R: FundTxRegistrar> CreditReconcileHandler<P, R> {
    /// Build a reconcile handler for a backend against a pool, a winc-balance
    /// provider, and a fund-transaction registrar.
    pub fn new(
        pool: sqlx::PgPool,
        provider: P,
        registrar: R,
        backend: impl Into<String>,
        config: ReconcileConfig,
    ) -> Self {
        Self {
            pool,
            provider,
            registrar,
            backend: backend.into(),
            config,
        }
    }

    /// Run one reconcile pass and return its summary. Used by the handler and by
    /// integration tests that drive the loop directly. `tick_id` correlates the
    /// `reconcile` rows of one occurrence and makes a re-run an idempotent no-op.
    pub async fn run_once(&self, tick_id: &str) -> Result<ReconcileSummary> {
        run_reconcile(
            &self.pool,
            &self.provider,
            &self.registrar,
            &self.backend,
            tick_id,
            &self.config,
        )
        .await
    }
}

impl<P: WincBalanceProvider + 'static, R: FundTxRegistrar + 'static> crate::runtime::JobHandler
    for CreditReconcileHandler<P, R>
{
    async fn handle(&self, ctx: crate::runtime::JobContext) -> crate::runtime::JobOutcome {
        // The job id is unique per enqueued occurrence and stable across the
        // handler's retries, so it correlates the reconcile rows of one tick and
        // makes a retried pass an idempotent no-op on (source, tick_id).
        let tick_id = ctx.job_id.to_string();
        match self.run_once(&tick_id).await {
            Ok(summary) => {
                tracing::info!(
                    backend = %self.backend,
                    unchanged = summary.unchanged,
                    corrected = summary.corrected,
                    unavailable = summary.unavailable,
                    low_emitted = summary.low_emitted,
                    drift_emitted = summary.drift_emitted,
                    topups_credited = summary.topups_credited,
                    "storage credit reconcile pass complete"
                );
                crate::runtime::JobOutcome::Complete
            }
            Err(e) => {
                tracing::warn!(backend = %self.backend, error = %e, "storage credit reconcile pass failed");
                crate::runtime::JobOutcome::Fail {
                    error: crate::runtime::JobError::new(
                        "storage_credit_reconcile_failed",
                        e.to_string(),
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credit(balance: i64, fundable: Option<i64>) -> StorageCredit {
        StorageCredit {
            winc_balance: Decimal::from(balance),
            fundable_bytes: fundable,
            last_reconciled_winc: None,
            last_reconciled_at: None,
            last_error: None,
        }
    }

    #[test]
    fn affordable_when_above_floor_and_within_fundable_bytes() {
        let c = credit(10_000, Some(1_000_000));
        assert_eq!(
            verdict(&c, 500_000, Decimal::from(1_000)),
            AffordVerdict::Affordable
        );
    }

    #[test]
    fn below_or_at_the_floor_is_refused() {
        let at_floor = credit(1_000, Some(1_000_000));
        assert_eq!(
            verdict(&at_floor, 1, Decimal::from(1_000)),
            AffordVerdict::BelowSafetyFloor,
            "a balance exactly at the floor does not afford"
        );
        let below = credit(500, Some(1_000_000));
        assert_eq!(
            verdict(&below, 1, Decimal::from(1_000)),
            AffordVerdict::BelowSafetyFloor
        );
    }

    #[test]
    fn chargeable_bytes_over_the_fundable_ceiling_is_refused() {
        let c = credit(10_000, Some(100));
        assert_eq!(
            verdict(&c, 101, Decimal::from(1_000)),
            AffordVerdict::InsufficientForBytes
        );
        // Exactly at the ceiling affords.
        assert_eq!(
            verdict(&c, 100, Decimal::from(1_000)),
            AffordVerdict::Affordable
        );
    }

    #[test]
    fn an_unknown_fundable_ceiling_does_not_block() {
        // fundable_bytes is None until a reconcile stamps it; the floor still
        // guards, but the byte ceiling does not refuse what it has not measured.
        let c = credit(10_000, None);
        assert_eq!(
            verdict(&c, u64::MAX, Decimal::from(1_000)),
            AffordVerdict::Affordable
        );
    }

    #[test]
    fn a_negative_provider_ceiling_refuses() {
        let c = credit(10_000, Some(-1));
        assert_eq!(
            verdict(&c, 0, Decimal::from(1_000)),
            AffordVerdict::InsufficientForBytes
        );
    }

    #[test]
    fn credit_kind_strings_match_the_check_constraint() {
        assert_eq!(CreditKind::Charge.as_str(), "charge");
        assert_eq!(CreditKind::Reconcile.as_str(), "reconcile");
        assert_eq!(CreditKind::Refund.as_str(), "refund");
        assert_eq!(CreditKind::Topup.as_str(), "topup");
    }

    #[test]
    fn reconcile_policy_is_a_single_in_flight_singleton_loop() {
        let policy = credit_reconcile_policy();
        assert_eq!(policy.queue, CREDIT_RECONCILE_QUEUE);
    }
}
