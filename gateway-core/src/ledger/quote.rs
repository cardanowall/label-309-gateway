//! The two-phase publish-cost protocol: quote, then consume.
//!
//! A publish is priced in two phases so the cost a user sees is the cost they
//! pay, even across a 15-minute composing session:
//!
//! 1. **Quote.** [`create_quote`] computes the engine-owned resource cost (the
//!    exact network fee from the canonical-shape build, plus the storage cost of
//!    the content bytes), asks a [`PricingHook`] for the markup, derives the
//!    total, and writes it all into one durable `cw_core.publish_quote` row. The
//!    row is the single snapshot: every input that determined the price is on it,
//!    so the price is reproducible from the row alone.
//! 2. **Consume.** [`consume_quote`] is one transaction that locks the quote and
//!    the balance, checks affordability, inserts the signed-negative publish
//!    debit (idempotent on the record id), and flips the quote `consumed` bound
//!    to the record. Two retries of the same publish converge on one debit. The
//!    publish debit is the network plus service components only: storage is
//!    reserved and charged at upload against the funding source, so a quote's
//!    `storage_usd_micros` is a forecast publish never consumes.
//!
//! A quote that is never consumed expires: [`expire_stale_quotes`] is a scheduled
//! maintenance pass that flips pending quotes past their TTL to `expired`.
//!
//! # Where the numbers come from
//!
//! The engine owns the COGS computation and nothing else. The network fee is the
//! exact canonical-shape fee ([`crate::wallet::quote`]); the storage cost is the
//! content bytes priced at a per-byte rate. The per-byte rate and the lovelace
//! conversion rate are FX VALUES the engine does not source: they arrive as a
//! [`FxSnapshot`] input (a vendor reads its own oracle and passes the values in),
//! and the engine persists the snapshot verbatim so the cost stays reproducible.
//! The markup likewise comes from the hook. The engine computes the arithmetic
//! and owns the durable, idempotent, replay-safe row.

use chrono::{DateTime, Utc};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::ledger::journal::{self, InsertOutcome, LedgerEntry};
use crate::{Error, Result};

/// The default time-to-live of a quote: the window a user has to consume a quote
/// before it must be re-priced. Fifteen minutes matches the composer's quote
/// refresh cadence.
pub const QUOTE_TTL_SECONDS: i64 = 15 * 60;

/// The maintenance queue the stale-quote expiry job runs on.
pub const EXPIRE_QUOTES_QUEUE: &str = "expire_quotes";

/// How often the expiry pass runs. Quotes carry an exact `expires_at`, so the
/// pass only needs to run often enough to keep the `pending` set from
/// accumulating lapsed rows; once a minute is ample.
pub const EXPIRE_QUOTES_SCHEDULE: &str = "0 * * * * *";

/// The FX inputs a quote is priced from. Vendor-supplied: the engine reads no
/// oracle, it persists this verbatim and computes the cost from it.
///
/// `ada_usd_micros` converts the network fee (lovelace) to micro-USD;
/// `ar_usd_per_byte_femto` prices the content bytes for storage. Both are carried
/// as integers in the smallest unit the vendor's oracle reports, so the snapshot
/// round-trips exactly through JSON with no float in the path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FxSnapshot {
    /// USD per ADA, in micro-USD per ADA.
    pub ada_usd_micros: i64,
    /// USD per stored byte, in femto-USD per byte.
    pub ar_usd_per_byte_femto: i64,
    /// An opaque identifier the vendor attaches to the FX reading it used, so a
    /// quote can be traced back to the oracle snapshot that priced it.
    pub source: String,
}

/// The markup a [`PricingHook`] resolved for a quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarginResolution {
    /// The markup as a fraction (e.g. `0.2500` = 25%). Stored as the quote's
    /// `numeric(6,4)` margin.
    pub margin_pct: Decimal,
    /// Where the markup came from, a free-text attribution for audit (the engine
    /// does not interpret it).
    pub margin_source: String,
}

/// The default free-storage byte window: content up to this size stores for free
/// (Merkle trees, manifests, identity envelopes), and only bytes beyond it are
/// priced. Operator-configurable; this is the default the wire contract assumes.
pub const DEFAULT_FREE_STORAGE_BYTES: u64 = 102_400;

/// The largest Label 309 record, in bytes, a quote may be created for.
///
/// A record crosses the chain as transaction metadata under label 309, and the
/// Cardano ledger caps the whole serialised transaction at 16,384 bytes. The
/// record bytes are not the only thing in that budget: the transaction also
/// carries its body (inputs, change output, fee, auxiliary-data hash), the
/// witness set, and per-chunk CBOR framing (the record is sliced into 64-byte
/// metadata byte strings, each adding two framing bytes), so the assembled
/// transaction is always larger than the record itself. A 14,000-byte record,
/// for instance, assembles to a ~14,684-byte transaction.
///
/// This bound is the record-payload ceiling that keeps the assembled transaction
/// comfortably under the 16,384-byte protocol maximum with headroom for the
/// variable change-output and witness overhead. Rejecting an over-cap record at
/// quote creation stops a quote being issued — and content being uploaded against
/// it — for a record that could only ever fail to submit. It is a deliberately
/// conservative pre-flight gate, not the authoritative ledger limit: the submit
/// path still meters the fully assembled transaction against the live protocol
/// maximum and is the final word on what fits.
pub const MAX_QUOTE_RECORD_BYTES: u32 = 14_500;

/// The cost inputs a quote is created from.
///
/// The engine computes the resource cost from these plus the canonical-shape
/// network fee; the markup comes from the [`PricingHook`], not from here.
#[derive(Debug, Clone)]
pub struct QuoteRequest {
    /// The account the quote is for.
    pub account_id: Uuid,
    /// The canonical Label 309 record length the network fee is metered over.
    pub record_bytes: u32,
    /// The number of sealed-PoE recipients the record addresses. Carried so the
    /// quote snapshot records the envelope shape it was priced for; the network
    /// fee already reflects the on-chain slot bytes via `record_bytes`.
    pub recipient_count: u32,
    /// The total content bytes the storage cost is computed over.
    pub file_bytes_total: u64,
    /// The free-storage byte window for this quote: bytes up to here are not
    /// charged. Operator-configurable; defaults to [`DEFAULT_FREE_STORAGE_BYTES`].
    pub free_storage_bytes: u64,
    /// The exact network fee (lovelace) the canonical-shape build priced for a
    /// record of `record_bytes`. The caller obtains it from
    /// [`crate::wallet::quote::quote_fee`].
    pub network_lovelace: u64,
    /// The FX inputs the cost is priced from, persisted verbatim on the quote.
    pub fx: FxSnapshot,
    /// The age of the FX snapshot in seconds when the quote was priced, surfaced
    /// on the wire so a caller can see how fresh the conversion was.
    pub fx_age_seconds: i64,
    /// The request id that issued the quote, for tracing.
    pub request_id: Option<Uuid>,
}

/// A created quote: the durable row's identity plus the priced total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    /// The quote's id (its durable row PK and the idempotency handle a consume
    /// references).
    pub id: Uuid,
    /// The account the quote is for.
    pub account_id: Uuid,
    /// The locked total a consume charges, in micro-USD.
    pub total_usd_micros: i64,
    /// The network cost component, in micro-USD.
    pub network_usd_micros: i64,
    /// The storage cost component, in micro-USD.
    pub storage_usd_micros: i64,
    /// The service (markup) cost component, in micro-USD.
    pub service_usd_micros: i64,
    /// The markup fraction the hook resolved (e.g. `0.25` = 25%), surfaced on the
    /// wire breakdown.
    pub margin_pct: Decimal,
    /// The age of the FX snapshot in seconds when the quote was priced. Carried
    /// from the request onto the wire; not a persisted column.
    pub fx_age_seconds: i64,
    /// When the quote was issued.
    pub issued_at: DateTime<Utc>,
    /// When the quote expires.
    pub expires_at: DateTime<Utc>,
}

impl Quote {
    /// The locked total as the decimal-string `amount` the wire carries.
    ///
    /// The wire `amount` is the USD micro-cents total rendered as a decimal
    /// string, matching the SDK's `QuoteResponse.amount` (which it promotes to an
    /// arbitrary-precision integer at the application boundary). The currency is
    /// always `USD`.
    #[must_use]
    pub fn wire_amount(&self) -> String {
        self.total_usd_micros.to_string()
    }

    /// The ISO 4217 currency the `amount` is denominated in. Always `USD`.
    #[must_use]
    pub fn wire_currency(&self) -> &'static str {
        "USD"
    }
}

/// The cost-of-goods breakdown the engine computes before the markup is applied.
///
/// Split out so the markup can be resolved by the hook OUTSIDE any transaction
/// from the COGS total, then folded back in. `total_cogs_usd_micros` is the
/// affordability base the hook prices its markup against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostOfGoods {
    /// The network fee converted to micro-USD.
    pub network_usd_micros: i64,
    /// The content bytes priced to micro-USD.
    pub storage_usd_micros: i64,
    /// `network_usd_micros + storage_usd_micros`.
    pub total_cogs_usd_micros: i64,
}

/// The pricing-policy seam: resolve the markup for a quote.
///
/// Called at quote time, OUTSIDE any database transaction, with the account and
/// the engine-computed cost-of-goods total. The implementation is free to do its
/// own I/O (read a margin ladder, query a delegation tier); a failure surfaces as
/// an [`crate::Error`] and aborts the quote. The engine ships a trivial
/// [`FixedMarginHook`]; a vendor supplies its own.
pub trait PricingHook: Send + Sync {
    /// Resolve the markup for an account given the cost-of-goods it will be
    /// applied to.
    fn resolve_margin(
        &self,
        account_id: Uuid,
        cogs_usd_micros: i64,
    ) -> impl std::future::Future<Output = Result<MarginResolution>> + Send;
}

/// The reference [`PricingHook`]: a single configured markup for every account.
///
/// Useful as a default and in tests. A real deployment supplies a hook that
/// resolves a per-account markup; this one ignores the account and returns its
/// configured percentage with a fixed `margin_source`.
#[derive(Debug, Clone)]
pub struct FixedMarginHook {
    margin_pct: Decimal,
}

impl FixedMarginHook {
    /// A hook that applies `margin_pct` (a fraction, e.g. `0.25` for 25%) to
    /// every quote.
    #[must_use]
    pub fn new(margin_pct: Decimal) -> Self {
        Self { margin_pct }
    }
}

impl PricingHook for FixedMarginHook {
    async fn resolve_margin(
        &self,
        _account_id: Uuid,
        _cogs_usd_micros: i64,
    ) -> Result<MarginResolution> {
        Ok(MarginResolution {
            margin_pct: self.margin_pct,
            margin_source: "fixed".to_string(),
        })
    }
}

/// A [`PricingHook`] that echoes a fully-resolved [`MarginResolution`] verbatim.
///
/// The DB-backed pricing seam already resolves both the markup fraction AND its
/// attribution (a pushed per-account override, or the operator-default) before
/// the quote is built. This hook carries that resolution straight onto the
/// durable row, so the persisted `margin_source` and the wire `margin_source`
/// agree with what the seam actually used, rather than collapsing to a fabricated
/// literal. Unlike [`FixedMarginHook`] it preserves the source string.
#[derive(Debug, Clone)]
pub struct EchoMarginHook {
    resolution: MarginResolution,
}

impl EchoMarginHook {
    /// A hook that returns `resolution` for every account.
    #[must_use]
    pub fn new(resolution: MarginResolution) -> Self {
        Self { resolution }
    }
}

impl PricingHook for EchoMarginHook {
    async fn resolve_margin(
        &self,
        _account_id: Uuid,
        _cogs_usd_micros: i64,
    ) -> Result<MarginResolution> {
        Ok(self.resolution.clone())
    }
}

/// The reason a [`consume_quote`] could not proceed, distinct from an
/// infrastructure error so a caller can map each to the right user-facing outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeRejection {
    /// The quote does not exist for this account.
    NotFound,
    /// The quote is not `pending` (already consumed or already expired).
    NotPending,
    /// The quote's TTL has lapsed.
    Expired,
    /// The record being published is larger than the quote was priced for. A
    /// quote is a fixed-price contract for a specific record size; publishing a
    /// larger record would meter a larger on-chain fee than the quote charged for,
    /// so it is refused before any debit. Carries the actual and quoted sizes.
    RecordTooLarge {
        /// The actual decoded record length, in bytes.
        actual_bytes: u32,
        /// The record size, in bytes, the quote was priced for.
        quoted_bytes: u32,
    },
    /// The account's balance is below the publish charge (network plus service;
    /// storage is settled separately at upload). Carries the balance read under
    /// the lock and the charge it could not cover, so the caller's 402 problem
    /// can tell the payer exactly how short the account is.
    InsufficientFunds {
        /// The account's balance at rejection time, in micro-USD.
        balance_micros: i64,
        /// The publish charge the balance could not cover, in micro-USD.
        required_micros: i64,
    },
}

/// The result of a [`consume_quote`] attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// The quote was consumed: the publish debit was applied and the quote bound
    /// to the record. Carries the post-debit balance in micro-USD.
    Consumed {
        /// The account's balance after the publish debit.
        balance_micros: i64,
    },
    /// The quote was already consumed for THIS record (the idempotent retry path);
    /// no second debit was applied.
    AlreadyConsumed,
    /// The consume could not proceed; carries the reason.
    Rejected(ConsumeRejection),
}

/// Compute the engine-owned cost of goods for a quote from its network fee and
/// content bytes, priced through the FX snapshot.
///
/// Pure arithmetic, no I/O: the network lovelace is converted to micro-USD via
/// `ada_usd_micros`, and the content bytes are priced via
/// `ar_usd_per_byte_femto`. Split out so the markup can be resolved against the
/// COGS total before the durable row is written.
pub fn compute_cost_of_goods(request: &QuoteRequest) -> Result<CostOfGoods> {
    if request.fx.ada_usd_micros < 0 || request.fx.ar_usd_per_byte_femto < 0 {
        return Err(Error::Config(
            "FX snapshot prices must be non-negative".into(),
        ));
    }

    // network: lovelace (1e-6 ADA) priced at micro-USD per ADA, rounded up to the
    // micro-USD so the engine never undercharges the network fee. Done in i128 so
    // the intermediate product cannot overflow before the divide.
    let network = i128::from(request.network_lovelace) * i128::from(request.fx.ada_usd_micros);
    let network_usd_micros = div_ceil_i128(network, 1_000_000)?;

    // storage: only the bytes BEYOND the free-storage window are charged. Content
    // up to `free_storage_bytes` (Merkle trees, manifests, identity envelopes)
    // stores for free; the excess is priced at femto-USD (1e-15) per byte, scaled
    // to micro-USD (divide by 1e9), rounded up so the engine never undercharges.
    let chargeable_bytes = request
        .file_bytes_total
        .saturating_sub(request.free_storage_bytes);
    let storage = i128::from(chargeable_bytes) * i128::from(request.fx.ar_usd_per_byte_femto);
    let storage_usd_micros = div_ceil_i128(storage, 1_000_000_000)?;

    let total_cogs_usd_micros = network_usd_micros
        .checked_add(storage_usd_micros)
        .ok_or_else(|| Error::Config("cost-of-goods total overflows i64".into()))?;

    Ok(CostOfGoods {
        network_usd_micros,
        storage_usd_micros,
        total_cogs_usd_micros,
    })
}

/// Divide a non-negative i128 by a positive divisor, rounding up, and narrow the
/// quotient to i64. Errors when the quotient does not fit i64, so an absurd FX
/// reading surfaces as a quote failure rather than a silently truncated charge.
fn div_ceil_i128(numerator: i128, divisor: i128) -> Result<i64> {
    debug_assert!(divisor > 0 && numerator >= 0);
    // Ceiling division on non-negative operands without an intermediate
    // `numerator + divisor` that could overflow: add one only when there is a
    // remainder. (i128's signed `div_ceil` is still unstable, so this is spelled
    // out.)
    let mut quotient = numerator / divisor;
    if numerator % divisor != 0 {
        quotient += 1;
    }
    i64::try_from(quotient).map_err(|_| Error::Config("micro-USD cost overflows i64".into()))
}

/// Create a publish quote: compute the COGS, resolve the markup through the hook
/// (outside any transaction), derive the total, and persist the durable row.
///
/// The hook is called once, with the COGS total, BEFORE the row is written, so a
/// hook failure aborts the quote without leaving a half-written row. The returned
/// [`Quote`] mirrors the persisted row's identity and priced totals.
pub async fn create_quote<H: PricingHook>(
    pool: &sqlx::PgPool,
    hook: &H,
    request: &QuoteRequest,
) -> Result<Quote> {
    // Refuse a quote for a record larger than what could ever fit a Cardano
    // transaction's metadata budget. Issuing such a quote would let content be
    // uploaded against a publish that can only fail at submit, sinking the upload
    // and stranding the user; rejecting here closes that cycle before any work.
    if request.record_bytes > MAX_QUOTE_RECORD_BYTES {
        return Err(Error::QuoteRecordTooLarge {
            record_bytes: request.record_bytes,
            max: MAX_QUOTE_RECORD_BYTES,
        });
    }

    let cogs = compute_cost_of_goods(request)?;

    // Resolve the markup OUTSIDE any transaction: the hook is free to do its own
    // I/O, and a failure here aborts the quote before a row is written.
    let margin = hook
        .resolve_margin(request.account_id, cogs.total_cogs_usd_micros)
        .await?;
    if margin.margin_pct.is_sign_negative() {
        return Err(Error::Config("resolved margin must be non-negative".into()));
    }

    let service_usd_micros = apply_margin(cogs.total_cogs_usd_micros, margin.margin_pct)?;
    let total_usd_micros = cogs
        .total_cogs_usd_micros
        .checked_add(service_usd_micros)
        .ok_or_else(|| Error::Config("quote total overflows i64".into()))?;

    let id = Uuid::now_v7();
    let record_bytes = i32::try_from(request.record_bytes)
        .map_err(|_| Error::Config("record_bytes overflows i32".into()))?;
    let recipient_count = i32::try_from(request.recipient_count)
        .map_err(|_| Error::Config("recipient_count overflows i32".into()))?;
    let file_bytes_total = i64::try_from(request.file_bytes_total)
        .map_err(|_| Error::Config("file_bytes_total overflows i64".into()))?;
    let network_lovelace = i64::try_from(request.network_lovelace)
        .map_err(|_| Error::Config("network_lovelace overflows i64".into()))?;
    if request.fx_age_seconds < 0 {
        return Err(Error::Config("fx_age_seconds must be non-negative".into()));
    }
    let fx_snapshot = serde_json::to_value(&request.fx)?;

    let row: QuoteRow = sqlx::query_as(
        "INSERT INTO cw_core.publish_quote \
           (id, account_id, expires_at, record_bytes, recipient_count, file_bytes_total, \
            network_lovelace, network_usd_micros, storage_usd_micros, margin_pct, margin_source, \
            service_usd_micros, total_usd_micros, fx_snapshot, fx_age_seconds, status, request_id) \
         VALUES ($1, $2, now() + make_interval(secs => $3), $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                 $13, $14, $15, 'pending', $16) \
         RETURNING id, account_id, total_usd_micros, network_usd_micros, storage_usd_micros, \
                   service_usd_micros, margin_pct, fx_age_seconds, issued_at, expires_at",
    )
    .bind(id)
    .bind(request.account_id)
    .bind(QUOTE_TTL_SECONDS as f64)
    .bind(record_bytes)
    .bind(recipient_count)
    .bind(file_bytes_total)
    .bind(network_lovelace)
    .bind(cogs.network_usd_micros)
    .bind(cogs.storage_usd_micros)
    .bind(margin.margin_pct)
    .bind(&margin.margin_source)
    .bind(service_usd_micros)
    .bind(total_usd_micros)
    .bind(&fx_snapshot)
    .bind(request.fx_age_seconds)
    .bind(request.request_id)
    .fetch_one(pool)
    .await?;

    Ok(row.into())
}

/// Apply a markup fraction to a cost-of-goods total, rounding the service charge
/// up to the micro-USD. Errors when the result does not fit i64.
fn apply_margin(cogs_usd_micros: i64, margin_pct: Decimal) -> Result<i64> {
    let service = Decimal::from(cogs_usd_micros)
        .checked_mul(margin_pct)
        .ok_or_else(|| Error::Config("service cost overflows the decimal range".into()))?
        .ceil();
    service
        .to_i64()
        .ok_or_else(|| Error::Config("service cost overflows i64".into()))
}

/// The columns [`create_quote`] reads back from the inserted row.
#[derive(sqlx::FromRow)]
struct QuoteRow {
    id: Uuid,
    account_id: Uuid,
    total_usd_micros: i64,
    network_usd_micros: i64,
    storage_usd_micros: i64,
    service_usd_micros: i64,
    margin_pct: Decimal,
    fx_age_seconds: i64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<QuoteRow> for Quote {
    fn from(r: QuoteRow) -> Self {
        Self {
            id: r.id,
            account_id: r.account_id,
            total_usd_micros: r.total_usd_micros,
            network_usd_micros: r.network_usd_micros,
            storage_usd_micros: r.storage_usd_micros,
            service_usd_micros: r.service_usd_micros,
            margin_pct: r.margin_pct,
            fx_age_seconds: r.fx_age_seconds,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
        }
    }
}

/// Consume a quote for a record, charging the account in one transaction.
///
/// The single transaction: `SELECT ... FOR UPDATE` the quote (validate it is
/// pending, unexpired, belongs to the account, and was priced for at least
/// `actual_record_bytes`), `SELECT ... FOR UPDATE` the balance, check the balance
/// covers the publish charge, insert the signed-negative `poe_publish` ledger
/// entry (ref = `poe_record_id`, `quote_id` stamped) which is idempotent on the
/// record id, then flip the quote `consumed` and bind `poe_record_id`.
/// All-or-nothing: a rejection rolls back with no debit.
///
/// `actual_record_bytes` is the decoded length of the record actually being
/// published. A quote is a fixed-price contract for a specific record size, and
/// the on-chain fee scales with the record bytes, so a record larger than the
/// quote was priced for is refused ([`ConsumeRejection::RecordTooLarge`]) before
/// any debit — otherwise an account could quote one byte and publish a full
/// record at the one-byte price while the operator's wallet funds the real fee.
/// A record smaller than quoted is accepted: the quote's price stands and the
/// account simply does not get a refund of the difference.
///
/// The publish charge is network plus service only. Storage is reserved and
/// charged at upload against the funding source, so the quote's
/// `storage_usd_micros` is never debited here even though the wire total includes
/// it. A publish-then-permanent-fail therefore refunds network+service only,
/// because the refund mirrors this debit; the storage charge is sunk once the
/// bytes are written.
///
/// IDEMPOTENCY. A retry that finds the quote already consumed for THIS record
/// returns [`ConsumeOutcome::AlreadyConsumed`] without a second debit; the ledger
/// entry's `(kind, ref)` uniqueness backs the guarantee even under a concurrent
/// double-submit.
pub async fn consume_quote(
    pool: &sqlx::PgPool,
    quote_id: Uuid,
    account_id: Uuid,
    poe_record_id: Uuid,
    actual_record_bytes: u32,
    request_id: Option<Uuid>,
) -> Result<ConsumeOutcome> {
    let mut txn = pool.begin().await?;
    let outcome = consume_quote_in_tx(
        &mut txn,
        quote_id,
        account_id,
        poe_record_id,
        actual_record_bytes,
        request_id,
    )
    .await?;
    // Only a Consumed outcome made writes worth committing; a rejection left the
    // transaction with no debit and is rolled back by dropping it. AlreadyConsumed
    // made no write either, but committing an empty transaction is harmless.
    match &outcome {
        ConsumeOutcome::Consumed { .. } | ConsumeOutcome::AlreadyConsumed => {
            txn.commit().await?;
        }
        ConsumeOutcome::Rejected(_) => {
            txn.rollback().await?;
        }
    }
    Ok(outcome)
}

/// Consume a quote inside the CALLER's transaction, composing the debit with the
/// caller's other writes (the `poe_record` insert, the submit-job enqueue, and
/// the subject event) so the whole publish commits or rolls back as one unit.
///
/// This is the data-plane publish path's primitive: the route opens one
/// transaction, inserts the record, calls this to lock the quote and apply the
/// debit, enqueues the submit job and appends the `submitting` subject event on
/// the SAME transaction, and commits. Because everything is one transaction the
/// debit and the enqueued submit can never diverge: a publish is charged exactly
/// once and its submit job is enqueued exactly once (invariant: exactly-once
/// publish). The debit is network plus service only; storage is charged at upload
/// against the funding source, so it is never part of this transaction.
///
/// Unlike [`consume_quote`] this does NOT commit or roll back: the caller owns
/// the transaction's fate. A [`ConsumeOutcome::Rejected`] leaves the caller's
/// transaction in a state the caller must roll back (this function performed no
/// debit, but the caller may have already inserted the record row).
///
/// `actual_record_bytes` is the decoded length of the record actually being
/// published. The quote's stored `record_bytes` is the size it was priced for,
/// and the on-chain fee scales with the record bytes, so a record larger than the
/// quote was priced for is refused ([`ConsumeRejection::RecordTooLarge`]) under
/// the row lock, before the affordability check and before any write. This is the
/// single chokepoint every publish path passes through, so no caller can pay a
/// small-record price for a large record.
///
/// IDEMPOTENCY. A retry that finds the quote already consumed for THIS record
/// returns [`ConsumeOutcome::AlreadyConsumed`] without a second debit; the ledger
/// entry's `(kind, ref)` uniqueness backs the guarantee even under a concurrent
/// double-submit. The size check sits AFTER the idempotent-retry branch, so a
/// retry of an already-consumed quote is honoured without re-deciding the size.
pub async fn consume_quote_in_tx(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    quote_id: Uuid,
    account_id: Uuid,
    poe_record_id: Uuid,
    actual_record_bytes: u32,
    request_id: Option<Uuid>,
) -> Result<ConsumeOutcome> {
    // Lock the quote for the duration of the transaction. Two consumers of the
    // same quote serialise here: the first to acquire the lock flips it consumed,
    // and the second wakes to find it no longer pending. The quoted record_bytes
    // is read under the lock too, so the size contract is enforced atomically with
    // the debit.
    let locked: Option<LockedQuote> = sqlx::query_as(
        "SELECT status, record_bytes, network_usd_micros, service_usd_micros, \
                expires_at <= now() AS expired, poe_record_id \
         FROM cw_core.publish_quote WHERE id = $1 AND account_id = $2 FOR UPDATE",
    )
    .bind(quote_id)
    .bind(account_id)
    .fetch_optional(&mut **txn)
    .await?;

    let Some(quote) = locked else {
        return Ok(ConsumeOutcome::Rejected(ConsumeRejection::NotFound));
    };

    if quote.status != "pending" {
        // A consumed quote bound to THIS record is the idempotent retry; any other
        // non-pending state (consumed for another record, or already expired) is a
        // plain rejection.
        if quote.status == "consumed" && quote.poe_record_id == Some(poe_record_id) {
            return Ok(ConsumeOutcome::AlreadyConsumed);
        }
        return Ok(ConsumeOutcome::Rejected(ConsumeRejection::NotPending));
    }

    if quote.expired {
        return Ok(ConsumeOutcome::Rejected(ConsumeRejection::Expired));
    }

    // Enforce the fixed-price contract: the record actually being published must
    // be no larger than the size the quote was priced for. A larger record would
    // meter a larger on-chain fee than the quote charged, so the operator's wallet
    // would silently fund the difference. Refuse it before the affordability check
    // and before any write; a smaller record is fine (the quoted price stands).
    let quoted_bytes = quote.quoted_record_bytes()?;
    if actual_record_bytes > quoted_bytes {
        return Ok(ConsumeOutcome::Rejected(ConsumeRejection::RecordTooLarge {
            actual_bytes: actual_record_bytes,
            quoted_bytes,
        }));
    }

    // Publish charges network plus service only. Storage is reserved and charged
    // at upload against the funding source, so it never lands on this debit even
    // though the quote's wire total still includes it.
    let publish_charge_micros = quote.publish_charge_micros()?;

    // Lock the balance row (when one exists) so a concurrent consume of a
    // DIFFERENT quote for the same account cannot interleave between this
    // affordability check and the debit. A missing row reads as a zero balance.
    let balance_micros: i64 = sqlx::query_scalar(
        "SELECT balance_micros FROM cw_core.balance WHERE account_id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_optional(&mut **txn)
    .await?
    .unwrap_or(0);

    if balance_micros < publish_charge_micros {
        // Affordability fails: the caller must roll back, leaving NOTHING (no
        // ledger row, quote still pending). The gate is against the publish
        // charge (network+service), not the wire total, since storage is settled
        // separately at upload. The observed balance and the uncovered charge
        // ride the rejection so the 402 problem can report the shortfall.
        return Ok(ConsumeOutcome::Rejected(
            ConsumeRejection::InsufficientFunds {
                balance_micros,
                required_micros: publish_charge_micros,
            },
        ));
    }

    // Insert the signed-negative publish debit on the SAME transaction, idempotent
    // on the record id and stamped with the quote it consumed. The balance_apply
    // trigger applies it and enforces non-negativity; the affordability check
    // above guarantees the entry will not overdraw.
    let entry = LedgerEntry {
        account_id,
        kind: "poe_publish".to_string(),
        amount_micros: -publish_charge_micros,
        r#ref: Some(poe_record_id.to_string()),
        quote_id: Some(quote_id),
        metadata: serde_json::json!({}),
        request_id,
    };
    let outcome = journal::insert_ledger_entry(&mut **txn, &entry).await?;
    debug_assert_eq!(
        outcome,
        InsertOutcome::Inserted,
        "a pending quote's debit is the first for its record"
    );

    // Flip the quote consumed and bind it to the record, still inside the lock.
    sqlx::query(
        "UPDATE cw_core.publish_quote \
         SET status = 'consumed', consumed_at = now(), poe_record_id = $2 \
         WHERE id = $1",
    )
    .bind(quote_id)
    .bind(poe_record_id)
    .execute(&mut **txn)
    .await?;

    let new_balance = balance_micros - publish_charge_micros;
    Ok(ConsumeOutcome::Consumed {
        balance_micros: new_balance,
    })
}

/// The quote fields locked for a consume.
///
/// `network_usd_micros + service_usd_micros` is what publish actually charges:
/// storage is charged separately at upload, against the funding source, so the
/// quote's `storage_usd_micros` is a forecast that publish never debits. The
/// `total_usd_micros` on the row stays network+storage+service (the wire total
/// the breakdown sums to) but is not the publish charge. `record_bytes` is the
/// size the quote was priced for, enforced against the record actually published.
#[derive(sqlx::FromRow)]
struct LockedQuote {
    status: String,
    record_bytes: i32,
    network_usd_micros: i64,
    service_usd_micros: i64,
    expired: bool,
    poe_record_id: Option<Uuid>,
}

impl LockedQuote {
    /// The amount publish debits: network plus service only. Storage is settled at
    /// upload time against the funding source, so it is never part of the publish
    /// charge even though the quote's wire total still includes it.
    fn publish_charge_micros(&self) -> Result<i64> {
        self.network_usd_micros
            .checked_add(self.service_usd_micros)
            .ok_or_else(|| Error::Config("publish charge overflows i64".into()))
    }

    /// The record size, in bytes, the quote was priced for. The column is a
    /// non-negative `int4` (it was written from a `u32`), so it narrows to `u32`;
    /// a negative value would mean a corrupt row and surfaces as a config error
    /// rather than a silent wraparound.
    fn quoted_record_bytes(&self) -> Result<u32> {
        u32::try_from(self.record_bytes)
            .map_err(|_| Error::Config("quote record_bytes is negative".into()))
    }
}

/// Expire every pending quote whose TTL has lapsed, returning how many were
/// expired. The scheduled maintenance pass; safe to run concurrently with quote
/// creation and consumption because it only touches rows that are both `pending`
/// and past `expires_at`, and a consume re-checks expiry under the row lock.
pub async fn expire_stale_quotes(pool: &sqlx::PgPool) -> Result<u64> {
    let affected = sqlx::query(
        "UPDATE cw_core.publish_quote SET status = 'expired' \
         WHERE status = 'pending' AND expires_at <= now()",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A snapshot pricing 1 ADA at $0.50 and 1 stored byte at 2 femto-USD.
    fn fx() -> FxSnapshot {
        FxSnapshot {
            // $0.50 per ADA = 500_000 micro-USD per ADA.
            ada_usd_micros: 500_000,
            // 2 femto-USD per byte.
            ar_usd_per_byte_femto: 2,
            source: "test".to_string(),
        }
    }

    fn request(network_lovelace: u64, file_bytes_total: u64) -> QuoteRequest {
        QuoteRequest {
            account_id: Uuid::nil(),
            record_bytes: 100,
            recipient_count: 0,
            file_bytes_total,
            // The legacy COGS tests price every byte, so the helper uses a
            // zero-byte free window; the free-window behaviour has its own tests.
            free_storage_bytes: 0,
            network_lovelace,
            fx: fx(),
            fx_age_seconds: 0,
            request_id: None,
        }
    }

    #[test]
    fn cost_of_goods_converts_lovelace_and_bytes_through_the_snapshot() {
        // 2 ADA fee at $0.50/ADA = $1.00 = 1_000_000 micro-USD.
        // 1_000_000 bytes at 2 femto-USD/byte = 2_000_000 femto-USD = 0.002 micro-USD,
        // rounded UP to 1 micro-USD.
        let cogs = compute_cost_of_goods(&request(2_000_000, 1_000_000)).expect("cogs");
        assert_eq!(cogs.network_usd_micros, 1_000_000);
        assert_eq!(cogs.storage_usd_micros, 1);
        assert_eq!(cogs.total_cogs_usd_micros, 1_000_001);
    }

    #[test]
    fn cost_of_goods_rounds_partial_micros_up_so_the_engine_never_undercharges() {
        // A network fee that lands on a fractional micro-USD must round up: 1
        // lovelace at 500_000 micro-USD/ADA = 0.5 micro-USD -> 1.
        let cogs = compute_cost_of_goods(&request(1, 0)).expect("cogs");
        assert_eq!(cogs.network_usd_micros, 1);
        assert_eq!(cogs.storage_usd_micros, 0);
    }

    #[test]
    fn cost_of_goods_rejects_a_negative_fx_price() {
        let mut req = request(1, 1);
        req.fx.ada_usd_micros = -1;
        assert!(compute_cost_of_goods(&req).is_err());
    }

    #[test]
    fn apply_margin_rounds_the_service_charge_up() {
        // 25% of 1_000_001 = 250_000.25, rounded up to 250_001.
        let service = apply_margin(1_000_001, Decimal::new(25, 2)).expect("margin");
        assert_eq!(service, 250_001);
    }

    #[test]
    fn apply_margin_of_zero_charges_no_service() {
        let service = apply_margin(1_000_000, Decimal::ZERO).expect("margin");
        assert_eq!(service, 0);
    }

    #[test]
    fn free_storage_window_charges_nothing_at_or_below_the_window() {
        let mut req = request(0, DEFAULT_FREE_STORAGE_BYTES);
        req.free_storage_bytes = DEFAULT_FREE_STORAGE_BYTES;
        // A 1 femto-USD/byte price over exactly the free window costs nothing.
        req.fx.ar_usd_per_byte_femto = 1_000_000_000;
        let cogs = compute_cost_of_goods(&req).expect("cogs");
        assert_eq!(
            cogs.storage_usd_micros, 0,
            "content at or below the free window is not charged"
        );
    }

    #[test]
    fn free_storage_window_charges_only_the_excess() {
        // 1 byte over the free window, priced at 1e9 femto-USD/byte = 1 micro-USD.
        let mut req = request(0, DEFAULT_FREE_STORAGE_BYTES + 1);
        req.free_storage_bytes = DEFAULT_FREE_STORAGE_BYTES;
        req.fx.ar_usd_per_byte_femto = 1_000_000_000;
        let cogs = compute_cost_of_goods(&req).expect("cogs");
        assert_eq!(
            cogs.storage_usd_micros, 1,
            "only the single byte beyond the free window is charged"
        );
    }

    #[test]
    fn wire_amount_is_the_total_as_a_decimal_string() {
        let quote = Quote {
            id: Uuid::nil(),
            account_id: Uuid::nil(),
            total_usd_micros: 1_500_000,
            network_usd_micros: 1_000_000,
            storage_usd_micros: 0,
            service_usd_micros: 500_000,
            margin_pct: Decimal::new(50, 2),
            fx_age_seconds: 42,
            issued_at: Utc::now(),
            expires_at: Utc::now(),
        };
        assert_eq!(quote.wire_amount(), "1500000");
        assert_eq!(quote.wire_currency(), "USD");
    }

    #[test]
    fn max_quotable_record_stays_under_the_cardano_tx_size_cap() {
        // The quote-time record ceiling is a payload bound, and the assembled
        // transaction (body + witness set + per-chunk metadata framing) is always
        // larger than the record. The cap must leave room for that overhead under
        // the 16,384-byte protocol maximum a Cardano transaction is metered
        // against, so a quotable record always has headroom to assemble and submit.
        // Checked at compile time so a future cap bump that breaches the budget
        // fails the build, not just a test run.
        const CARDANO_MAX_TX_SIZE: u32 = 16_384;
        // The overhead is dominated by ~2 framing bytes per 64-byte metadata chunk
        // plus a fixed body/witness cost; require the cap to leave at least that
        // much headroom so the assembled transaction cannot breach the maximum.
        const CHUNK_FRAMING: u32 = MAX_QUOTE_RECORD_BYTES.div_ceil(64) * 2;
        const _: () = assert!(
            MAX_QUOTE_RECORD_BYTES + CHUNK_FRAMING < CARDANO_MAX_TX_SIZE,
            "the cap plus per-chunk metadata framing must stay under the tx maximum"
        );
    }
}
