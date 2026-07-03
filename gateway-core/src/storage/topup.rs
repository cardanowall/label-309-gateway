//! Operator storage top-up: convert AR tokens into provider upload credits.
//!
//! A Turbo-style storage provider sells upload capacity as a prepaid `winc`
//! balance keyed on the funding wallet's address. The provider's token rail funds
//! that balance with an ON-CHAIN AR transfer: send winston from the funding
//! wallet to the provider's deposit wallet, then register the transfer's
//! transaction id with the provider's payment service, which credits the winc
//! once the transfer reaches its confirmation depth. The conversion is ONE-WAY —
//! credits can never be turned back into AR — so every top-up leaves a permanent
//! `cw_core.storage_topup` row and the control surface demands an explicit,
//! typed-confirmation request before issuing one.
//!
//! # Crash-deterministic, forward-only recovery
//!
//! The transfer is signed once; its id (`SHA-256(signature)`) and complete
//! broadcastable JSON are persisted BEFORE any byte reaches the network. From
//! then on every step is forward-recoverable against that row: a broadcast or
//! registration that fails (or a process that dies between steps) is retried by
//! re-broadcasting the byte-identical persisted transaction and re-registering
//! the same id — never by re-signing, which would mint a second transaction and
//! move the funds twice ([`register_topup`] is that retry).
//!
//! # The credit lands minutes later, and must be journalled
//!
//! `registered` is an ACCEPTANCE, not the credit: the payment service credits
//! the winc only once the transfer reaches its confirmation depth. The
//! register/poll step therefore keeps re-registering a `registered` row (the
//! registration is idempotent on the tx id) until the verdict reports the
//! credit landed, and at that moment atomically marks the row `credited` and
//! appends the positive `topup` entry to the believed-balance winc journal.
//! Without that journal row every legitimate top-up would surface as
//! unexplained drift when the reconcile loop next compared the live balance
//! against the believed one. [`absorb_credited_topups`] is the reconcile
//! loop's hook: it polls a source's `registered` rows so a landed credit is
//! absorbed into the believed balance BEFORE the drift comparison runs.
//!
//! # Idempotent create
//!
//! The journal row alone cannot protect the CREATE from a lost response: the
//! PSS signature is randomised, so a client that retries the same logical
//! top-up would mint a fresh transaction under a fresh id and the funds would
//! move twice. Every create therefore carries a caller-supplied idempotency
//! key, unique per initiating operator. [`execute_topup`] looks the key up
//! BEFORE signing and replays the existing conversion (converging it forward,
//! exactly as [`register_topup`] would) when one exists; a concurrent
//! duplicate loses the `(operator, key)` unique-insert race and replays the
//! winner. Reusing a key with different parameters is refused — that signals a
//! caller bug, not a benign retry.
//!
//! # Who may top up
//!
//! Only the funding source's OWNER ([`super::authorize_owner_topup`]): a top-up
//! spends the wallet behind the source, which no draw grant entitles. The signer
//! is resolved through the same unforgeable capability the upload path uses, so
//! a bare address can never reach the key.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::storage::backend::StorageError;
use crate::storage::credit::{insert_credit_entry, CreditEntry, CreditKind};
use crate::storage::funding::AuthorizedFunding;
use crate::storage::node::ArweaveNodeClient;
use crate::wallet::keyring::UnlockedKeyring;
use crate::{Error, Result};

/// The provider token rail a gateway top-up funds with. The deposit-address
/// lookup and the fund-transaction registration are both keyed on it.
const TOKEN: &str = "arweave";

/// A top-up's lifecycle status. The wire spelling matches the
/// `storage_topup.status` CHECK constraint exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopUpStatus {
    /// Signed and durably recorded; broadcast not yet confirmed.
    Signed,
    /// Accepted by the Arweave node; payment-service registration outstanding.
    Submitted,
    /// The broadcast was refused or failed in transit (possibly indeterminate);
    /// retryable by re-broadcasting the persisted transaction.
    SubmitFailed,
    /// The payment service accepted the fund-transaction; the winc credits once
    /// the transfer reaches its confirmation depth, so the register/poll step
    /// keeps advancing this row until the credit lands.
    Registered,
    /// Terminal: the payment service reported the credit landed and the
    /// believed-balance `topup` journal row was appended.
    Credited,
}

impl TopUpStatus {
    /// The persisted status string (matching the CHECK constraint).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TopUpStatus::Signed => "signed",
            TopUpStatus::Submitted => "submitted",
            TopUpStatus::SubmitFailed => "submit_failed",
            TopUpStatus::Registered => "registered",
            TopUpStatus::Credited => "credited",
        }
    }

    /// Parse a persisted status string.
    fn parse(value: &str) -> Result<Self> {
        match value {
            "signed" => Ok(TopUpStatus::Signed),
            "submitted" => Ok(TopUpStatus::Submitted),
            "submit_failed" => Ok(TopUpStatus::SubmitFailed),
            "registered" => Ok(TopUpStatus::Registered),
            "credited" => Ok(TopUpStatus::Credited),
            other => Err(Error::Config(format!("unknown top-up status {other:?}"))),
        }
    }
}

/// One persisted top-up, as the control surface projects it.
#[derive(Debug, Clone)]
pub struct TopUpRecord {
    /// The top-up id.
    pub id: Uuid,
    /// The funding source whose provider balance the transfer funds.
    pub funding_source_id: Uuid,
    /// The transferred amount, in winston.
    pub ar_amount_winston: Decimal,
    /// The node-quoted transfer fee, in winston.
    pub fee_winston: Decimal,
    /// The provider deposit wallet the transfer pays.
    pub target_address: String,
    /// The Arweave transfer transaction id (fixed at signing).
    pub tx_id: String,
    /// The caller-supplied create idempotency key, unique per initiating
    /// operator. `None` only on rows journalled before the key existed.
    pub idempotency_key: Option<String>,
    /// How far the operation provably progressed.
    pub status: TopUpStatus,
    /// The most recent failure detail, cleared on a later success.
    pub last_error: Option<String>,
    /// The winc the payment service reported it will credit, when known.
    pub registered_winc: Option<Decimal>,
    /// When the payment service reported the credit landed and the winc
    /// journal row was appended; `None` while the credit is still pending.
    pub credited_at: Option<DateTime<Utc>>,
    /// When the top-up was signed and recorded.
    pub created_at: DateTime<Utc>,
    /// When the row last advanced.
    pub updated_at: DateTime<Utc>,
}

/// The outcome of one execute/retry pass, carrying the row's final projection.
///
/// The pass itself never returns `Err` for a provider-side failure — the failure
/// is recorded ON the row (that is the whole point of the journal) and the
/// caller reports the row's real state. An `Err` means the engine itself failed
/// (the database was unreachable, the keyring holds no signer).
#[derive(Debug, Clone)]
pub struct TopUpExecuteOutcome {
    /// The row after the pass.
    pub record: TopUpRecord,
    /// Whether this pass signed the transfer. `false` on an idempotent replay
    /// (the key matched an existing conversion) and on a register retry, both
    /// of which only converge an existing row forward.
    pub created: bool,
}

/// The Turbo payment-service client for the token-funding rail: deposit-address
/// discovery and fund-transaction registration.
///
/// Deliberately separate from the winc-balance provider
/// ([`super::TurboWincProvider`]) the reconcile loop reads through: that one is a
/// recurring background reader, this one acts only on an explicit operator
/// top-up. Both are plain HTTP clients over the operator-configured payment-
/// service base URL; neither holds key material.
pub struct TurboPaymentClient {
    client: reqwest::Client,
    base_url: String,
}

impl TurboPaymentClient {
    /// Build a payment-service client over the configured base URL.
    pub fn new(base_url: impl Into<String>) -> std::result::Result<Self, StorageError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| {
                StorageError::Misconfigured(format!("building payment-service HTTP client: {e}"))
            })?;
        Ok(Self {
            client,
            base_url: base_url.into(),
        })
    }

    /// Build a client over a caller-supplied client and base URL, the seam a
    /// behavioural test uses to point the real client at a local fake server.
    #[must_use]
    pub fn with_client(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: base_url.into(),
        }
    }

    fn base(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    /// Resolve the provider's deposit wallet for the AR token rail
    /// (`GET /v1/info`, whose `addresses` map carries one deposit wallet per
    /// supported token).
    pub async fn deposit_address(&self) -> std::result::Result<String, StorageError> {
        let url = format!("{}/v1/info", self.base());
        let response =
            self.client.get(&url).send().await.map_err(|e| {
                StorageError::Unavailable(format!("reading payment-service info: {e}"))
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(StorageError::Unavailable(format!(
                "payment-service info returned {status}"
            )));
        }
        let body: serde_json::Value =
            crate::http::read_capped_json(response, crate::http::JSON_BODY_CEILING)
                .await
                .map_err(|e| {
                    StorageError::Unavailable(format!("decoding payment-service info: {e}"))
                })?;
        body.get("addresses")
            .and_then(|a| a.get(TOKEN))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| {
                StorageError::Unavailable(format!(
                    "payment-service info carries no {TOKEN} deposit address"
                ))
            })
    }

    /// Register a broadcast fund transaction with the payment service
    /// (`POST /v1/account/balance/{token}` with `{ "tx_id": ... }`), so the
    /// provider credits the winc once the transfer confirms.
    ///
    /// Safe to retry with the same id: the payment service keys the credit on
    /// the transaction, so a re-registration converges on the same credit. The
    /// 200 body carries the verdict under ONE of three nested keys —
    /// `creditedTransaction` (already credited), `pendingTransaction` (accepted,
    /// credits at confirmation depth), or `failedTransaction` (examined and
    /// rejected) — each with a `winstonCreditAmount`. A freshly broadcast
    /// transfer the service cannot see yet typically comes back as a non-2xx,
    /// which surfaces as [`StorageError::Unavailable`] and is retried later.
    pub async fn submit_fund_transaction(
        &self,
        tx_id: &str,
    ) -> std::result::Result<FundTxAck, StorageError> {
        let url = format!("{}/v1/account/balance/{TOKEN}", self.base());
        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "tx_id": tx_id }))
            .send()
            .await
            .map_err(|e| {
                StorageError::Unavailable(format!("registering the fund transaction: {e}"))
            })?;
        let status = response.status();
        // Bounded read: a hostile or misbehaving payment service cannot OOM us with
        // a huge body. A cap/decode failure falls back to a null verdict (the
        // tolerant behaviour a non-2xx retry expects), never the whole body.
        let body: serde_json::Value =
            crate::http::read_capped_json(response, crate::http::JSON_BODY_CEILING)
                .await
                .unwrap_or(serde_json::Value::Null);
        if !status.is_success() {
            return Err(StorageError::Unavailable(format!(
                "fund-transaction registration returned {status}: {}",
                body.to_string().chars().take(512).collect::<String>()
            )));
        }
        if let Some(t) = body.get("creditedTransaction") {
            return Ok(FundTxAck::Accepted {
                winc: winc_of(t),
                credited: true,
            });
        }
        if let Some(t) = body.get("pendingTransaction") {
            return Ok(FundTxAck::Accepted {
                winc: winc_of(t),
                credited: false,
            });
        }
        if body.get("failedTransaction").is_some() {
            return Ok(FundTxAck::Failed {
                detail: "the payment service examined the transaction and reports it failed"
                    .to_string(),
            });
        }
        Err(StorageError::Unavailable(format!(
            "fund-transaction registration returned an unrecognised body: {}",
            body.to_string().chars().take(512).collect::<String>()
        )))
    }
}

/// The payment service's verdict on a registered fund transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundTxAck {
    /// The registration was accepted: the transfer is credited already
    /// (`credited: true`) or will credit once it reaches confirmation depth.
    Accepted {
        /// The winc the service reported for this transfer, when present.
        winc: Option<Decimal>,
        /// Whether the credit has already landed (vs pending confirmation).
        credited: bool,
    },
    /// The service examined the transaction and reports it failed. Not an
    /// acceptance; retryable (a later look may resolve differently only if the
    /// verdict was premature, so the failure detail is recorded on the row).
    Failed {
        /// The human-readable verdict recorded on the journal row.
        detail: String,
    },
}

/// The seam the register/poll step registers a fund transaction through.
///
/// The reconcile loop's [`absorb_credited_topups`] polls `registered` rows on
/// every pass, so — like the winc-balance read behind
/// [`super::WincBalanceProvider`] — the call must be stubbable without a live
/// payment service. [`TurboPaymentClient`] is the production implementation;
/// the registration is idempotent on the tx id at the provider, so a repeated
/// poll converges on the same verdict.
pub trait FundTxRegistrar: Send + Sync {
    /// Register (or re-poll) a broadcast fund transaction with the payment
    /// service, returning its verdict.
    fn submit_fund_transaction<'a>(
        &'a self,
        tx_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<FundTxAck, StorageError>>
                + Send
                + 'a,
        >,
    >;
}

impl FundTxRegistrar for TurboPaymentClient {
    fn submit_fund_transaction<'a>(
        &'a self,
        tx_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<FundTxAck, StorageError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(TurboPaymentClient::submit_fund_transaction(self, tx_id))
    }
}

/// Pull the `winstonCreditAmount` decimal string off a verdict object.
fn winc_of(verdict: &serde_json::Value) -> Option<Decimal> {
    verdict.get("winstonCreditAmount").and_then(|v| match v {
        serde_json::Value::String(s) => s.trim().parse::<Decimal>().ok(),
        serde_json::Value::Number(n) => n.to_string().parse::<Decimal>().ok(),
        _ => None,
    })
}

/// The largest idempotency key the create path accepts, in bytes. Generous for
/// any reasonable reference scheme while keeping the unique index cheap; the
/// schema CHECK mirrors it.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 200;

/// Execute a top-up end to end, idempotently on `(operator, idempotency_key)`:
/// quote, sign, persist, broadcast, register — or replay the conversion the
/// same key already created.
///
/// `funding` is the owner-minted capability for the source being funded;
/// `ar_amount_winston` the winston to convert; `idempotency_key` the caller's
/// name for this logical conversion (required: the transfer is irreversible,
/// so an unnamed create could never be retried safely). The pass:
///
///   1. replays an existing `(operator, key)` conversion when one exists:
///      verifies the request names the same source and amount (a mismatch is
///      an [`Error::Config`] — the key was reused for a DIFFERENT top-up),
///      converges a not-yet-registered row forward exactly as
///      [`register_topup`] would, and returns it with `created: false` —
///      never signing a second transfer,
///   2. resolves the signer through the capability (the physical key gate),
///   3. resolves the provider deposit wallet, the transfer anchor, and the
///      node-quoted fee,
///   4. refuses (an [`Error::Config`], surfaced as a validation problem) when
///      the wallet's live AR balance cannot cover `amount + fee`, BEFORE
///      signing, so an unaffordable conversion never leaves a journal row,
///   5. signs the transfer and persists the row in `signed` state — from here
///      the operation is durable and forward-recoverable. A concurrent
///      same-key duplicate loses the unique-insert race here; the loser's
///      signed-but-never-persisted transaction is discarded unbroadcast (no
///      funds moved) and the winner is replayed instead,
///   6. broadcasts and registers, advancing the row through
///      `submitted`/`registered` (and to `credited` when the provider already
///      reports the credit landed) and recording any failure on the row.
///
/// Provider failures after step 5 are NOT an `Err`: the returned record carries
/// the real state and the failure detail, and [`register_topup`] retries it.
#[allow(clippy::too_many_arguments)]
pub async fn execute_topup(
    pool: &sqlx::PgPool,
    keyring: &UnlockedKeyring,
    node: &ArweaveNodeClient,
    payment: &TurboPaymentClient,
    funding: &AuthorizedFunding,
    operator_id: Uuid,
    ar_amount_winston: u128,
    idempotency_key: &str,
) -> Result<TopUpExecuteOutcome> {
    if ar_amount_winston == 0 {
        return Err(Error::Config("the top-up amount must be nonzero".into()));
    }
    if idempotency_key.trim().is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_LEN {
        return Err(Error::Config(format!(
            "the idempotency key must be a non-empty string of at most \
             {MAX_IDEMPOTENCY_KEY_LEN} characters"
        )));
    }
    let amount = winston_decimal(ar_amount_winston)?;

    // Replay before any external effect: a retry of an already-journalled
    // conversion must return that conversion, not sign a new one.
    if let Some(existing) = load_topup_by_key(pool, operator_id, idempotency_key).await? {
        return replay_topup(pool, node, payment, funding, existing, amount).await;
    }

    let signer = keyring.arweave_signer_for(funding).ok_or_else(|| {
        Error::Config(
            "this instance does not hold the Arweave key for the funding source".to_string(),
        )
    })?;

    // Quote the transfer: the deposit wallet, a fresh anchor, and the fee. These
    // are pre-sign reads; a failure here aborts cleanly with nothing persisted
    // and no funds at risk.
    let target = payment
        .deposit_address()
        .await
        .map_err(|e| Error::Config(format!("resolving the deposit wallet: {e}")))?;
    let anchor = node
        .tx_anchor()
        .await
        .map_err(|e| Error::Config(format!("fetching the transaction anchor: {e}")))?;
    let fee = node
        .transfer_price_winston(&target)
        .await
        .map_err(|e| Error::Config(format!("quoting the transfer fee: {e}")))?;

    // Affordability gate, against the LIVE wallet balance, before signing: an
    // operator typo (one digit too many) must fail the request, not strand a
    // journal row for a transfer the node will refuse.
    let balance = node
        .wallet_balance_winston(signer.address())
        .await
        .map_err(|e| Error::Config(format!("reading the funding wallet balance: {e}")))?;
    let total = ar_amount_winston
        .checked_add(u128::from(fee))
        .ok_or_else(|| Error::Config("the top-up amount overflows".into()))?;
    if balance < total {
        return Err(Error::Config(format!(
            "the funding wallet holds {balance} winston, which cannot cover the \
             {ar_amount_winston} winston transfer plus the {fee} winston fee"
        )));
    }

    // Sign once. The id and the broadcastable JSON are now fixed; persist them
    // BEFORE broadcasting so a crash at any later point recovers forward.
    let tx = signer.sign_transfer_tx_v2(&target, ar_amount_winston, &anchor, fee)?;
    let tx_id = tx.id_b64url();
    let tx_json = tx.to_json();

    let topup_id = Uuid::now_v7();
    let fee_decimal = winston_decimal(u128::from(fee))?;
    let inserted = sqlx::query(
        "INSERT INTO cw_core.storage_topup \
           (id, funding_source_id, initiated_by_operator, ar_amount_winston, fee_winston, \
            target_address, tx_id, tx_json, status, idempotency_key) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'signed', $9)",
    )
    .bind(topup_id)
    .bind(funding.funding_source_id())
    .bind(operator_id)
    .bind(amount)
    .bind(fee_decimal)
    .bind(&target)
    .bind(&tx_id)
    .bind(&tx_json)
    .bind(idempotency_key)
    .execute(pool)
    .await;
    if let Err(e) = inserted {
        // A concurrent same-key duplicate persisted its row between the replay
        // lookup and this insert. The transaction signed above was never
        // persisted or broadcast, so no funds moved; discard it and replay the
        // winner rather than journalling a second transfer.
        if unique_violation_on(&e, "storage_topup_operator_idempotency_key") {
            let winner = load_topup_by_key(pool, operator_id, idempotency_key)
                .await?
                .ok_or_else(|| {
                    Error::Config("the duplicate top-up row vanished after its insert won".into())
                })?;
            return replay_topup(pool, node, payment, funding, winner, amount).await;
        }
        return Err(e.into());
    }

    // Broadcast + register, advancing the durable row. Failures land on the row.
    advance_topup(pool, node, payment, topup_id).await?;

    let record = load_topup(pool, topup_id)
        .await?
        .ok_or_else(|| Error::Config("the top-up row vanished after insert".into()))?;
    Ok(TopUpExecuteOutcome {
        record,
        created: true,
    })
}

/// Return an existing conversion as the outcome of a same-key create retry:
/// verify the retry names the same source and amount, converge the row forward
/// when its credit has not yet landed (the same no-re-sign advance
/// [`register_topup`] runs), and return its current state.
///
/// A parameter mismatch is refused rather than replayed: the same key naming a
/// different source or amount is a caller bug, and silently returning the old
/// conversion would hide it.
async fn replay_topup(
    pool: &sqlx::PgPool,
    node: &ArweaveNodeClient,
    payment: &TurboPaymentClient,
    funding: &AuthorizedFunding,
    existing: TopUpRecord,
    amount: Decimal,
) -> Result<TopUpExecuteOutcome> {
    if existing.funding_source_id != funding.funding_source_id()
        || existing.ar_amount_winston != amount
    {
        return Err(Error::Config(format!(
            "this idempotency key already names a different conversion \
             ({} winston from source {}); use a new key for a new top-up",
            existing.ar_amount_winston, existing.funding_source_id
        )));
    }
    if existing.status != TopUpStatus::Credited {
        advance_topup(pool, node, payment, existing.id).await?;
    }
    let record = load_topup(pool, existing.id)
        .await?
        .ok_or_else(|| Error::Config("the top-up row vanished during replay".into()))?;
    Ok(TopUpExecuteOutcome {
        record,
        created: false,
    })
}

/// Whether an insert failed on the named unique constraint (vs any other
/// database error, which the caller propagates).
fn unique_violation_on(e: &sqlx::Error, constraint: &str) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.constraint() == Some(constraint))
}

/// Retry an unfinished top-up: re-broadcast the persisted transaction when its
/// broadcast is not yet confirmed, then re-register/poll the id with the
/// payment service. A `registered` row is still advanced — its credit lands at
/// confirmation depth, so the poll is what discovers the transition to
/// `credited`. A no-op only for an already-`credited` (terminal) row.
///
/// Owner-scoped: the row must belong to a source `operator_id` owns. Returns
/// `Ok(None)` for a missing or foreign top-up (no cross-tenant existence
/// oracle).
pub async fn register_topup(
    pool: &sqlx::PgPool,
    node: &ArweaveNodeClient,
    payment: &TurboPaymentClient,
    operator_id: Uuid,
    topup_id: Uuid,
) -> Result<Option<TopUpExecuteOutcome>> {
    let Some(record) = load_topup_for_operator(pool, operator_id, topup_id).await? else {
        return Ok(None);
    };
    if record.status != TopUpStatus::Credited {
        advance_topup(pool, node, payment, topup_id).await?;
    }
    let record = load_topup(pool, topup_id)
        .await?
        .ok_or_else(|| Error::Config("the top-up row vanished during retry".into()))?;
    Ok(Some(TopUpExecuteOutcome {
        record,
        created: false,
    }))
}

/// Drive one persisted top-up as far forward as the providers allow: broadcast
/// the persisted transaction unless already `submitted`, then run the
/// register/poll step. Provider failures are recorded on the row, never
/// returned as `Err`. A `credited` row is terminal and left untouched.
async fn advance_topup<R: FundTxRegistrar>(
    pool: &sqlx::PgPool,
    node: &ArweaveNodeClient,
    registrar: &R,
    topup_id: Uuid,
) -> Result<()> {
    let (status_raw, funding_source_id, tx_id, tx_json): (String, Uuid, String, serde_json::Value) =
        sqlx::query_as(
            "SELECT status, funding_source_id, tx_id, tx_json \
         FROM cw_core.storage_topup WHERE id = $1",
        )
        .bind(topup_id)
        .fetch_one(pool)
        .await?;
    let status = TopUpStatus::parse(&status_raw)?;
    if status == TopUpStatus::Credited {
        return Ok(());
    }

    // Broadcast (or re-broadcast) the byte-identical persisted transaction. A
    // node that already holds it accepts the duplicate under the same id, so the
    // retry is idempotent; only a definite refusal records a failure.
    if matches!(status, TopUpStatus::Signed | TopUpStatus::SubmitFailed) {
        match node.submit_tx(&tx_json).await {
            Ok(()) => set_status(pool, topup_id, TopUpStatus::Submitted, None).await?,
            Err(e) => {
                set_status(
                    pool,
                    topup_id,
                    TopUpStatus::SubmitFailed,
                    Some(&e.to_string()),
                )
                .await?;
                return Ok(());
            }
        }
    }

    register_step(pool, registrar, topup_id, funding_source_id, &tx_id).await?;
    Ok(())
}

/// What one register/poll step resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegisterStepOutcome {
    /// The provider reported the credit landed: the row is `credited` and the
    /// believed-balance `topup` journal row was appended.
    Credited,
    /// The provider accepted the registration; the credit is still pending
    /// confirmation depth, so the row is (or stays) `registered`.
    Registered,
    /// A failed verdict or an unreachable/unaware service: the detail is
    /// recorded on the row and a later poll retries.
    Unresolved,
}

/// Register (or re-poll) one top-up's fund transaction with the payment
/// service and settle the verdict onto the row. Idempotent: the registration
/// converges on the same verdict at the provider, every row write is guarded
/// against regressing the terminal `credited` state, and the journal append is
/// keyed on the top-up id.
///
/// A pending acceptance sets `registered`; a landed credit transitions the row
/// to `credited` AND appends the positive `topup` journal row to the believed
/// winc balance in ONE transaction, so the top-up row and the journal can
/// never disagree about whether the credit was absorbed. A failed verdict or
/// an unreachable service records the detail and leaves the status alone,
/// retryable — a freshly broadcast transfer is often not yet visible to the
/// payment service.
async fn register_step<R: FundTxRegistrar>(
    pool: &sqlx::PgPool,
    registrar: &R,
    topup_id: Uuid,
    funding_source_id: Uuid,
    tx_id: &str,
) -> Result<RegisterStepOutcome> {
    match registrar.submit_fund_transaction(tx_id).await {
        Ok(FundTxAck::Accepted {
            winc,
            credited: true,
        }) => {
            // One transaction marks the row credited and journals the credit
            // into the believed balance: a crash between the two would leave
            // either a landed credit the drift alert misreads as unexplained
            // (journal row missing) or a journal row no top-up corroborates.
            let mut txn = pool.begin().await?;
            // Guarded transition: only the poll that moves the row INTO
            // `credited` journals; a replayed poll affects zero rows and
            // appends nothing.
            let credited_winc: Option<Option<Decimal>> = sqlx::query_scalar(
                "UPDATE cw_core.storage_topup \
                 SET status = 'credited', \
                     registered_winc = COALESCE($2, registered_winc), \
                     credited_at = now(), last_error = NULL, updated_at = now() \
                 WHERE id = $1 AND status <> 'credited' \
                 RETURNING registered_winc",
            )
            .bind(topup_id)
            .bind(winc)
            .fetch_optional(&mut *txn)
            .await?;
            if let Some(credited_winc) = credited_winc {
                // The journalled delta is the credited winstonCreditAmount,
                // falling back to the amount an earlier acceptance recorded.
                // When neither is known the row is still marked credited but
                // no journal row is appended: inventing a delta would corrupt
                // the believed balance, while the missing movement is exactly
                // what the next `reconcile` row absorbs.
                if let Some(delta) = credited_winc.filter(|w| *w > Decimal::ZERO) {
                    insert_credit_entry(
                        &mut *txn,
                        &CreditEntry {
                            funding_source_id,
                            kind: CreditKind::Topup,
                            winc_delta: delta,
                            r#ref: Some(topup_id.to_string()),
                        },
                    )
                    .await?;
                }
            }
            txn.commit().await?;
            Ok(RegisterStepOutcome::Credited)
        }
        Ok(FundTxAck::Accepted {
            winc,
            credited: false,
        }) => {
            sqlx::query(
                "UPDATE cw_core.storage_topup \
                 SET status = 'registered', registered_winc = $2, last_error = NULL, \
                     updated_at = now() \
                 WHERE id = $1 AND status <> 'credited'",
            )
            .bind(topup_id)
            .bind(winc)
            .execute(pool)
            .await?;
            Ok(RegisterStepOutcome::Registered)
        }
        Ok(FundTxAck::Failed { detail }) => {
            record_register_failure(pool, topup_id, &detail).await?;
            Ok(RegisterStepOutcome::Unresolved)
        }
        Err(e) => {
            record_register_failure(pool, topup_id, &e.to_string()).await?;
            Ok(RegisterStepOutcome::Unresolved)
        }
    }
}

/// Record a registration failure detail on the row without touching its
/// status (a `credited` row is terminal and keeps its clean state).
async fn record_register_failure(pool: &sqlx::PgPool, topup_id: Uuid, detail: &str) -> Result<()> {
    sqlx::query(
        "UPDATE cw_core.storage_topup \
         SET last_error = $2, updated_at = now() \
         WHERE id = $1 AND status <> 'credited'",
    )
    .bind(topup_id)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

/// Poll every `registered` top-up for one funding source and settle any whose
/// provider credit has landed, returning how many became `credited` (each
/// appending its believed-balance `topup` journal row as it transitioned).
///
/// The reconcile loop calls this BEFORE comparing the live balance against the
/// believed one, so a landed top-up is absorbed into the believed balance
/// instead of surfacing as unexplained drift. Poll failures follow the
/// [`register_topup`] discipline — recorded on the row's `last_error`, never
/// returned as `Err` — so one flaky poll cannot abort a reconcile pass.
pub async fn absorb_credited_topups<R: FundTxRegistrar>(
    pool: &sqlx::PgPool,
    registrar: &R,
    funding_source_id: Uuid,
) -> Result<usize> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, tx_id FROM cw_core.storage_topup \
         WHERE funding_source_id = $1 AND status = 'registered' \
         ORDER BY id",
    )
    .bind(funding_source_id)
    .fetch_all(pool)
    .await?;

    let mut credited = 0;
    for (topup_id, tx_id) in rows {
        if register_step(pool, registrar, topup_id, funding_source_id, &tx_id).await?
            == RegisterStepOutcome::Credited
        {
            credited += 1;
        }
    }
    Ok(credited)
}

/// Stamp a top-up's status and failure detail.
async fn set_status(
    pool: &sqlx::PgPool,
    topup_id: Uuid,
    status: TopUpStatus,
    error: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE cw_core.storage_topup \
         SET status = $2, last_error = $3, updated_at = now() \
         WHERE id = $1",
    )
    .bind(topup_id)
    .bind(status.as_str())
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// Load one top-up by id.
async fn load_topup(pool: &sqlx::PgPool, topup_id: Uuid) -> Result<Option<TopUpRecord>> {
    let row: Option<TopUpRow> = sqlx::query_as(
        "SELECT t.id, t.funding_source_id, t.ar_amount_winston, t.fee_winston, \
                t.target_address, t.tx_id, t.idempotency_key, t.status, t.last_error, \
                t.registered_winc, t.credited_at, t.created_at, t.updated_at \
         FROM cw_core.storage_topup t WHERE t.id = $1",
    )
    .bind(topup_id)
    .fetch_optional(pool)
    .await?;
    row.map(TopUpRow::into_record).transpose()
}

/// Load the top-up an operator's idempotency key names, when one exists.
async fn load_topup_by_key(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    idempotency_key: &str,
) -> Result<Option<TopUpRecord>> {
    let row: Option<TopUpRow> = sqlx::query_as(
        "SELECT t.id, t.funding_source_id, t.ar_amount_winston, t.fee_winston, \
                t.target_address, t.tx_id, t.idempotency_key, t.status, t.last_error, \
                t.registered_winc, t.credited_at, t.created_at, t.updated_at \
         FROM cw_core.storage_topup t \
         WHERE t.initiated_by_operator = $1 AND t.idempotency_key = $2",
    )
    .bind(operator_id)
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await?;
    row.map(TopUpRow::into_record).transpose()
}

/// Load one top-up by id, scoped to the sources `operator_id` owns. A missing or
/// foreign row reads as `None`.
pub async fn load_topup_for_operator(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    topup_id: Uuid,
) -> Result<Option<TopUpRecord>> {
    let row: Option<TopUpRow> = sqlx::query_as(
        "SELECT t.id, t.funding_source_id, t.ar_amount_winston, t.fee_winston, \
                t.target_address, t.tx_id, t.idempotency_key, t.status, t.last_error, \
                t.registered_winc, t.credited_at, t.created_at, t.updated_at \
         FROM cw_core.storage_topup t \
         JOIN cw_core.storage_funding_source s ON s.id = t.funding_source_id \
         WHERE t.id = $1 AND s.owner_operator_id = $2",
    )
    .bind(topup_id)
    .bind(operator_id)
    .fetch_optional(pool)
    .await?;
    row.map(TopUpRow::into_record).transpose()
}

/// List the top-ups against sources `operator_id` owns, newest-first up to
/// `limit`.
pub async fn list_operator_topups(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    limit: i64,
) -> Result<Vec<TopUpRecord>> {
    let rows: Vec<TopUpRow> = sqlx::query_as(
        "SELECT t.id, t.funding_source_id, t.ar_amount_winston, t.fee_winston, \
                t.target_address, t.tx_id, t.idempotency_key, t.status, t.last_error, \
                t.registered_winc, t.credited_at, t.created_at, t.updated_at \
         FROM cw_core.storage_topup t \
         JOIN cw_core.storage_funding_source s ON s.id = t.funding_source_id \
         WHERE s.owner_operator_id = $1 \
         ORDER BY t.id DESC \
         LIMIT $2",
    )
    .bind(operator_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(TopUpRow::into_record).collect()
}

/// Render a winston amount as the `numeric` value the journal stores. Winston
/// amounts inside the AR supply (about 20 decimal digits) fit a [`Decimal`]
/// exactly; an amount that does not is non-physical and refused.
fn winston_decimal(winston: u128) -> Result<Decimal> {
    winston
        .to_string()
        .parse::<Decimal>()
        .map_err(|_| Error::Config(format!("winston amount {winston} is out of range")))
}

/// The row shape the top-up reads share.
#[derive(sqlx::FromRow)]
struct TopUpRow {
    id: Uuid,
    funding_source_id: Uuid,
    ar_amount_winston: Decimal,
    fee_winston: Decimal,
    target_address: String,
    tx_id: String,
    idempotency_key: Option<String>,
    status: String,
    last_error: Option<String>,
    registered_winc: Option<Decimal>,
    credited_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TopUpRow {
    fn into_record(self) -> Result<TopUpRecord> {
        Ok(TopUpRecord {
            id: self.id,
            funding_source_id: self.funding_source_id,
            ar_amount_winston: self.ar_amount_winston,
            fee_winston: self.fee_winston,
            target_address: self.target_address,
            tx_id: self.tx_id,
            idempotency_key: self.idempotency_key,
            status: TopUpStatus::parse(&self.status)?,
            last_error: self.last_error,
            registered_winc: self.registered_winc,
            credited_at: self.credited_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_strings_match_the_check_constraint() {
        for status in [
            TopUpStatus::Signed,
            TopUpStatus::Submitted,
            TopUpStatus::SubmitFailed,
            TopUpStatus::Registered,
            TopUpStatus::Credited,
        ] {
            assert_eq!(
                TopUpStatus::parse(status.as_str()).expect("round-trips"),
                status
            );
        }
        assert!(TopUpStatus::parse("bogus").is_err());
    }

    #[test]
    fn winston_decimal_handles_supply_scale_amounts() {
        // 66M AR in winston: beyond u64, well within Decimal.
        let v = winston_decimal(66_000_000u128 * 1_000_000_000_000u128).expect("fits");
        assert_eq!(v.to_string(), "66000000000000000000");
        assert_eq!(winston_decimal(0).expect("zero fits"), Decimal::ZERO);
    }
}
