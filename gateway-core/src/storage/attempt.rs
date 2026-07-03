//! The upload-attempt state machine: the durable reservation that makes a paid
//! storage upload crash-deterministic and exactly-once-charged.
//!
//! A paid upload is a three-phase saga. The route signs the ANS-104 data item once
//! (the randomised RSA-PSS signature, and therefore the item id, is fixed from
//! here), then:
//!
//!   1. [`reserve_attempt`] writes the `reserved` attempt row AND the user's USD
//!      hold AND the operator's believed winc charge in one transaction, BEFORE the
//!      provider is paid. A second concurrent request for the same logical upload
//!      (`account_id, backend, sha256`) loses the partial-unique insert and instead
//!      ATTACHES to the existing live attempt: no second hold, signature, or charge.
//!   2. [`claim_post_lease`] fences the external POST: among the many contenders
//!      that may legitimately settle one `reserved` attempt (the live handler, an
//!      attached retry, a recovery sweep), exactly one holds the POST window at a
//!      time.
//!   3. [`commit_attempt`] (provider 2xx) or [`release_attempt`] (definite failure)
//!      settles the attempt with a compare-and-set on `state`, so the live handler
//!      and the recovery sweep can never both settle one attempt: the CAS has one
//!      winner, and the loser performs no ledger side effect.
//!
//! Every ledger row the saga writes keys its `ref` on the attempt id, so the hold,
//! its release, the final charge, and any refund all correlate on one stable key
//! and a retried settlement is an idempotent no-op rather than a double charge.
//!
//! The content payload is NEVER stored here. The recovery artifact is the bounded
//! signed envelope on the row plus the durable staged file `staged_path` points at;
//! the route promotes that file off the auto-delete guard before [`reserve_attempt`]
//! and deletes it on settlement.

use rust_decimal::Decimal;
use serde_json::json;
use uuid::Uuid;

use crate::ledger::journal::{insert_ledger_entry, LedgerEntry, ACCOUNT_SUBJECT_KIND};
use crate::storage::backend::StorageReceipt;
use crate::storage::credit::{insert_credit_entry, CreditEntry, CreditKind};
use crate::storage::persist::{lookup_receipt, PersistedUpload};
use crate::{Error, Result};

/// A test-only interleaving gate for the lost-slot window of [`reserve_attempt`].
///
/// The window under test — the loser's insert conflicts against a live winner,
/// then the winner settles BEFORE the loser's attach read — spans microseconds,
/// so a test that merely races two tasks and hopes the scheduler produces it is
/// a timing lottery (it reliably misses on a loaded few-core CI runner). A test
/// arms the gate for one content digest instead; the reserve loop then parks in
/// the window and hands control to the test, which settles the winner and
/// releases the loser, making the interleaving a certainty rather than a hope.
///
/// Armed gates are keyed by digest so concurrent tests in one process cannot
/// interfere, and each gate fires exactly once. The module is compiled out of
/// production builds.
#[cfg(any(test, feature = "testsupport"))]
pub mod race_window {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use tokio::sync::oneshot;

    struct Gate {
        entered_tx: oneshot::Sender<()>,
        release_rx: oneshot::Receiver<()>,
    }

    fn gates() -> &'static Mutex<HashMap<[u8; 32], Gate>> {
        static GATES: OnceLock<Mutex<HashMap<[u8; 32], Gate>>> = OnceLock::new();
        GATES.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// The test's side of an armed gate.
    pub struct WindowHandle {
        entered_rx: oneshot::Receiver<()>,
        release_tx: oneshot::Sender<()>,
    }

    impl WindowHandle {
        /// Wait until a loser reserve for the armed digest is parked inside the
        /// lost-slot window (its insert conflicted; its attach read has not run).
        pub async fn entered(&mut self) {
            (&mut self.entered_rx)
                .await
                .expect("the armed reserve dropped before reaching the window");
        }

        /// Release the parked reserve to run its attach read.
        pub fn release(self) {
            let _ = self.release_tx.send(());
        }
    }

    /// Arm the window for one content digest. The next lost-slot reserve for
    /// that digest parks in the window until [`WindowHandle::release`].
    pub fn arm(sha256: [u8; 32]) -> WindowHandle {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let prior = gates().lock().expect("race-window registry").insert(
            sha256,
            Gate {
                entered_tx,
                release_rx,
            },
        );
        assert!(prior.is_none(), "digest already armed");
        WindowHandle {
            entered_rx,
            release_tx,
        }
    }

    /// Called by the reserve loop inside the lost-slot window. A no-op unless a
    /// test armed this digest; an armed gate is consumed by its first hit.
    pub(super) async fn pause_if_armed(sha256: &[u8; 32]) {
        let gate = gates().lock().expect("race-window registry").remove(sha256);
        if let Some(gate) = gate {
            let _ = gate.entered_tx.send(());
            let _ = gate.release_rx.await;
        }
    }
}

/// The terminal, client-facing event a recovery sweep emits when an attempt is
/// unrecoverable: the provider confirms the bytes never landed AND the durable
/// staged content did not survive, so the body cannot be reconstructed. It rides
/// the owning account's subject (the failing upload predates any PoE record, so
/// there is no record subject to hang it on, and the account is the identity that
/// must re-upload). Its SSE projection is a distinct wire name so a client tells a
/// retryable upload failure apart from an ordinary balance change.
pub const STORAGE_UPLOAD_FAILED_EVENT: &str = "storage.upload.failed";

/// The state an attempt is in. `reserved` is the only mutable state; `committed`
/// and `released` are terminal and have no outgoing transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptState {
    /// The hold is placed; the provider write may or may not have happened.
    Reserved,
    /// The provider accepted the bytes; the receipt and the final debit landed.
    Committed,
    /// The provider write was never confirmed; the hold was released, no charge.
    Released,
}

impl AttemptState {
    /// The stable string stored in `storage_upload_attempt.state`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AttemptState::Reserved => "reserved",
            AttemptState::Committed => "committed",
            AttemptState::Released => "released",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "reserved" => Ok(AttemptState::Reserved),
            "committed" => Ok(AttemptState::Committed),
            "released" => Ok(AttemptState::Released),
            other => Err(Error::Config(format!("unknown attempt state {other:?}"))),
        }
    }
}

/// Why a `released` attempt failed, the cause the poll route and the terminal
/// upload-failed event both report. The wire spelling matches the
/// `storage_upload_attempt.release_reason` CHECK exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseReason {
    /// The upload reached the provider and was definitively refused (a 402, or a
    /// build/transport fault before any bytes were sent). The bytes never landed
    /// and the client may retry the same content.
    ProviderRejected,
    /// The recovery sweep found the provider does not hold the data item AND the
    /// durable staged content did not survive, so the body cannot be reconstructed.
    /// The client MUST re-upload the original bytes.
    UnrecoverableStagedContentLost,
}

impl ReleaseReason {
    /// The stable string stored in `storage_upload_attempt.release_reason`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ReleaseReason::ProviderRejected => "provider_rejected",
            ReleaseReason::UnrecoverableStagedContentLost => "unrecoverable_staged_content_lost",
        }
    }
}

/// The attempt row as the poll route and the recovery sweep read it.
///
/// The envelope columns (`data_item_signature`/`_anchor`/`_tag_bytes`) and the
/// `staged_path` are not carried here: a reader that needs them (the recovery
/// sweep) reads them separately, and the poll route does not. This shape is exactly
/// the poll contract plus the keys a settler needs.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// The attempt id (the ledger correlation key and the poll path segment).
    pub id: Uuid,
    /// The owning account.
    pub account_id: Uuid,
    /// The funding source the charge drew.
    pub funding_source_id: Uuid,
    /// The persisted backend identifier.
    pub backend: String,
    /// The content digest.
    pub sha256: [u8; 32],
    /// The content byte count.
    pub bytes: u64,
    /// The chargeable bytes (netted of the free window).
    pub chargeable_bytes: u64,
    /// The user-facing USD charge held for this upload at reserve time (the estimate
    /// the hold covers). This is what the attempt MIGHT cost, not what it cost.
    pub charged_usd_micros: i64,
    /// The USD the settlement ACTUALLY debited: `Some(charged_usd_micros)` for a
    /// fresh committed receipt, `Some(0)` for a deduped commit or a release, and
    /// `None` while the attempt is still `reserved` (no settlement has run). The poll
    /// route reports this so a deduped upload never claims a charge it did not make.
    pub settled_charge_usd_micros: Option<i64>,
    /// The data-item id stamped from the one signing.
    pub data_item_id: String,
    /// The lifecycle state.
    pub state: AttemptState,
    /// Why the attempt was released, set only in the `released` state.
    pub release_reason: Option<ReleaseReason>,
}

impl Attempt {
    /// The content digest as lowercase hex.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }
}

/// The columns an attempt row reads back.
#[derive(sqlx::FromRow)]
struct AttemptRow {
    id: Uuid,
    account_id: Uuid,
    funding_source_id: Uuid,
    backend: String,
    sha256: Vec<u8>,
    bytes: i64,
    chargeable_bytes: i64,
    charged_usd_micros: i64,
    settled_charge_usd_micros: Option<i64>,
    data_item_id: String,
    state: String,
    release_reason: Option<String>,
}

impl AttemptRow {
    fn into_attempt(self) -> Result<Attempt> {
        let sha256: [u8; 32] = self
            .sha256
            .as_slice()
            .try_into()
            .map_err(|_| Error::Config("attempt sha256 is not 32 bytes".into()))?;
        let bytes = u64::try_from(self.bytes)
            .map_err(|_| Error::Config("attempt byte count is negative".into()))?;
        let chargeable_bytes = u64::try_from(self.chargeable_bytes)
            .map_err(|_| Error::Config("attempt chargeable bytes is negative".into()))?;
        let release_reason = match self.release_reason.as_deref() {
            None => None,
            Some("provider_rejected") => Some(ReleaseReason::ProviderRejected),
            Some("unrecoverable_staged_content_lost") => {
                Some(ReleaseReason::UnrecoverableStagedContentLost)
            }
            Some(other) => {
                return Err(Error::Config(format!(
                    "unknown attempt release reason {other:?}"
                )))
            }
        };
        Ok(Attempt {
            id: self.id,
            account_id: self.account_id,
            funding_source_id: self.funding_source_id,
            backend: self.backend,
            sha256,
            bytes,
            chargeable_bytes,
            charged_usd_micros: self.charged_usd_micros,
            settled_charge_usd_micros: self.settled_charge_usd_micros,
            data_item_id: self.data_item_id,
            state: AttemptState::from_str(&self.state)?,
            release_reason,
        })
    }
}

/// Everything the route stamps onto a fresh reservation: the identity, the priced
/// charge, and the bounded signed envelope it produced from the single signing.
pub struct ReserveSpec<'a> {
    /// The attempt id. Minted by the route BEFORE promotion so the durable staged
    /// file is named by the same id the attempt row carries: the recovery sweep, the
    /// orphan janitor, and operator debugging all read one id, never two. On a lost
    /// live-slot race this row is never inserted (the caller attaches to the winner),
    /// so the id is simply discarded along with the wasted signature and staged file.
    pub id: Uuid,
    /// The owning account.
    pub account_id: Uuid,
    /// The account's owning operator.
    pub operator_id: Uuid,
    /// The funding source the charge draws.
    pub funding_source_id: Uuid,
    /// The persisted backend identifier.
    pub backend: &'a str,
    /// The content digest.
    pub sha256: [u8; 32],
    /// The content byte count.
    pub bytes: u64,
    /// The chargeable bytes (netted of the free window).
    pub chargeable_bytes: u64,
    /// The deterministic user-facing USD storage charge (`> 0`, the free path takes
    /// no attempt).
    pub charged_usd_micros: i64,
    /// The operator's believed winc consumption, held against the funding source
    /// until the reconcile cron corrects it. Nonzero (the credit-ledger CHECK
    /// rejects a zero delta).
    pub estimated_winc: Decimal,
    /// The data-item id (SHA-256 of the signature).
    pub data_item_id: &'a str,
    /// The signature bytes (RSA-4096 = 512 bytes).
    pub data_item_signature: &'a [u8],
    /// The optional 32-byte anchor.
    pub data_item_anchor: Option<&'a [u8]>,
    /// The serialised tag block (<= 4096 bytes).
    pub data_item_tag_bytes: &'a [u8],
    /// The durable staged content path the recovery sweep re-POSTs from.
    pub staged_path: &'a str,
    /// The originating request id, stamped on the ledger entries for tracing.
    pub request_id: Option<Uuid>,
}

/// The result of trying to reserve the live slot for a logical upload.
#[derive(Debug, Clone)]
pub enum ReserveOutcome {
    /// This request won the live-slot race: it owns the attempt and must proceed to
    /// claim the POST window and upload.
    Claimed(Attempt),
    /// A concurrent request already owns the live slot for this logical upload; this
    /// request ATTACHED to it. The carried attempt is the winner's: a `reserved`
    /// one is still in flight (the caller returns the `accepted` disposition). No
    /// second hold, signature, or charge was taken.
    Attached(Attempt),
    /// The live slot was lost to a concurrent request that has since committed: the
    /// winner already stored these exact bytes for this account on this backend, so
    /// the prior receipt satisfies the upload. The caller returns it as a dedup hit;
    /// no second hold, signature, or charge was taken.
    Deduplicated(PersistedUpload),
    /// Affordability failed under the locked balance: the reservation was rolled
    /// back, nothing was held, the provider is never paid. The caller returns 402.
    InsufficientFunds,
}

/// Reserve the live slot for a logical upload, placing the USD hold and the
/// believed winc charge in one transaction, before the provider is paid.
///
/// The insert is the authoritative claim: `ON CONFLICT (account_id, backend,
/// sha256) WHERE state='reserved' DO NOTHING`, so a concurrent contender that
/// already minted the live attempt makes this insert return no row, and the caller
/// ATTACHES to the winner instead of taking a second hold. When the insert wins, the
/// same transaction locks the account balance `FOR UPDATE`, refuses if the hold
/// would overdraw (rolling back so nothing is reserved), then writes the
/// `storage_hold` USD debit and the `storage_credit_ledger` `charge`. The lock order
/// is attempt insert -> balance `FOR UPDATE` -> `balance_ledger` -> the winc journal,
/// matching the wallet side's discipline so two storage transactions never deadlock.
///
/// The lost-slot case converges rather than erroring: when the conflicting winner
/// has already left `reserved` (it committed or was released between this insert's
/// conflict and the attach read), the slot is now free, so this re-reads
/// `storage_upload` for a committed receipt — a hit is a [`ReserveOutcome::Deduplicated`]
/// success — and otherwise retries the claim from the top against the freed slot.
pub async fn reserve_attempt(
    pool: &sqlx::PgPool,
    spec: &ReserveSpec<'_>,
) -> Result<ReserveOutcome> {
    // The route minted the id and named the durable staged file by it, so the row
    // and its content file share one id. A lost live-slot race discards this id.
    let id = spec.id;
    let bytes_i64 = i64::try_from(spec.bytes)
        .map_err(|_| Error::Config("upload byte count overflows i64".into()))?;
    let chargeable_i64 = i64::try_from(spec.chargeable_bytes)
        .map_err(|_| Error::Config("chargeable byte count overflows i64".into()))?;

    loop {
        let mut txn = pool.begin().await?;

        // The authoritative live-slot claim. A losing insert (a concurrent contender
        // already holds the live slot) returns no row; the winner gets its id back.
        let inserted: Option<(Uuid,)> = sqlx::query_as(
            "INSERT INTO cw_core.storage_upload_attempt \
               (id, account_id, operator_id, funding_source_id, backend, sha256, bytes, \
                chargeable_bytes, charged_usd_micros, estimated_winc, data_item_id, \
                data_item_signature, data_item_anchor, data_item_tag_bytes, staged_path, state) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'reserved') \
             ON CONFLICT (account_id, backend, sha256) WHERE state = 'reserved' DO NOTHING \
             RETURNING id",
        )
        .bind(id)
        .bind(spec.account_id)
        .bind(spec.operator_id)
        .bind(spec.funding_source_id)
        .bind(spec.backend)
        .bind(spec.sha256.as_slice())
        .bind(bytes_i64)
        .bind(chargeable_i64)
        .bind(spec.charged_usd_micros)
        .bind(spec.estimated_winc)
        .bind(spec.data_item_id)
        .bind(spec.data_item_signature)
        .bind(spec.data_item_anchor)
        .bind(spec.data_item_tag_bytes)
        .bind(spec.staged_path)
        .fetch_optional(&mut *txn)
        .await?;

        let Some((attempt_id,)) = inserted else {
            // Lost the race: a contender already holds the live slot. Roll back this
            // empty transaction and attach to the winner's attempt by the
            // logical-upload key.
            txn.rollback().await?;
            #[cfg(any(test, feature = "testsupport"))]
            race_window::pause_if_armed(&spec.sha256).await;
            if let Some(winner) =
                load_live_attempt(pool, spec.account_id, spec.backend, &spec.sha256).await?
            {
                return Ok(ReserveOutcome::Attached(winner));
            }

            // The winner settled (committed or released) between our conflict and
            // this read, freeing the live slot. A committed winner already stored
            // these exact bytes, so the upload deduplicates against its receipt; a
            // released winner stored nothing, so the slot is free and we retry the
            // claim from the top.
            if let Some(receipt) =
                lookup_receipt(pool, spec.account_id, spec.backend, &spec.sha256).await?
            {
                return Ok(ReserveOutcome::Deduplicated(receipt));
            }
            continue;
        };

        // Won the slot. Lock the account balance so a concurrent consume/charge
        // cannot interleave between this affordability check and the hold debit.
        let balance_micros: i64 = sqlx::query_scalar(
            "SELECT balance_micros FROM cw_core.balance WHERE account_id = $1 FOR UPDATE",
        )
        .bind(spec.account_id)
        .fetch_optional(&mut *txn)
        .await?
        .unwrap_or(0);

        if balance_micros < spec.charged_usd_micros {
            // The hold would overdraw. Roll back so the claimed live slot is freed,
            // the staged file is dropped by the caller, and the provider is never
            // paid.
            txn.rollback().await?;
            return Ok(ReserveOutcome::InsufficientFunds);
        }

        // The USD hold: a signed-negative, non-overdrawing reservation keyed on the
        // attempt id. Its later release carries the same magnitude, so the
        // hold/release pair nets to zero and a retry is an idempotent no-op.
        let hold = LedgerEntry {
            account_id: spec.account_id,
            kind: "storage_hold".to_string(),
            amount_micros: -spec.charged_usd_micros,
            r#ref: Some(attempt_id.to_string()),
            quote_id: None,
            metadata: json!({ "chargeable_bytes": chargeable_i64 }),
            request_id: spec.request_id,
        };
        insert_ledger_entry(&mut *txn, &hold).await?;

        // The operator's believed winc charge, in the same transaction. The
        // reconcile cron corrects any drift against the actual provider balance.
        let winc_charge = CreditEntry {
            funding_source_id: spec.funding_source_id,
            kind: CreditKind::Charge,
            winc_delta: -spec.estimated_winc,
            r#ref: Some(attempt_id.to_string()),
        };
        insert_credit_entry(&mut *txn, &winc_charge).await?;

        txn.commit().await?;

        let attempt = load_attempt(pool, attempt_id)
            .await?
            .ok_or_else(|| Error::Config("reserved attempt vanished after commit".into()))?;
        return Ok(ReserveOutcome::Claimed(attempt));
    }
}

/// Acquire the external-POST claim-lease on a `reserved` attempt, returning the new
/// claim token when granted.
///
/// The atomic claim-CAS grants the lease only when the attempt is still `reserved`
/// and the lease is unheld or lapsed (the prior owner died mid-POST), so among many
/// contenders exactly one owns the POST window. A caller that does not get the token
/// must NOT POST. `lease_ttl_secs` is the lease lifetime; it exceeds the upload
/// timeout, so a healthy owner's timeout-abort always fires before the lease lapses.
pub async fn claim_post_lease(
    pool: &sqlx::PgPool,
    attempt_id: Uuid,
    lease_ttl_secs: i64,
) -> Result<Option<Uuid>> {
    let token = Uuid::now_v7();
    let granted: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE cw_core.storage_upload_attempt \
            SET upload_claim_token = $2, \
                upload_claim_expires_at = now() + make_interval(secs => $3) \
          WHERE id = $1 AND state = 'reserved' \
            AND (upload_claim_token IS NULL OR upload_claim_expires_at < now()) \
          RETURNING upload_claim_token",
    )
    .bind(attempt_id)
    .bind(token)
    .bind(lease_ttl_secs as f64)
    .fetch_optional(pool)
    .await?;
    Ok(granted.map(|(t,)| t))
}

/// Release the external-POST claim-lease without settling the attempt.
///
/// Called on the ambiguous-`Unavailable` return: the attempt stays `reserved` (the
/// bytes may have landed), but the POST window is freed so the recovery sweep can
/// reclaim it. Forward-looking and idempotent.
///
/// The release is fenced on `claim_token`: only the worker that still holds the
/// lease it POSTed under clears it. A worker whose lease lapsed (and was re-granted
/// to a recovery sweep that minted a fresh token) matches no row and clears nothing,
/// so a lost-ownership release is a benign no-op rather than wiping the new owner's
/// active lease.
pub async fn release_post_lease(
    pool: &sqlx::PgPool,
    attempt_id: Uuid,
    claim_token: Uuid,
) -> Result<()> {
    sqlx::query(
        "UPDATE cw_core.storage_upload_attempt \
            SET upload_claim_token = NULL, upload_claim_expires_at = NULL \
          WHERE id = $1 AND state = 'reserved' AND upload_claim_token = $2",
    )
    .bind(attempt_id)
    .bind(claim_token)
    .execute(pool)
    .await?;
    Ok(())
}

/// The outcome of a settlement compare-and-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleOutcome {
    /// This caller won the CAS and performed the settlement side effects. Carries
    /// the USD ACTUALLY debited by this settlement, so the route and poll responses
    /// report the real charge rather than the reserve-time estimate: the held amount
    /// for a fresh committed receipt, and `0` for a deduped commit (the bytes were
    /// already stored) or a release (the bytes never landed).
    Settled { charged_usd_micros: i64 },
    /// The attempt was no longer `reserved` (another settler won the CAS first);
    /// this caller did nothing.
    AlreadySettled,
}

/// Commit a `reserved` attempt on a provider 2xx: flip it `committed`, write the
/// receipt, release the hold, and — only when the receipt actually inserts — charge
/// the final storage debit, all in one transaction guarded by the compare-and-set on
/// `state`.
///
/// The CAS (`WHERE state='reserved' RETURNING`) is the serialization point: only one
/// contender (the live handler or the recovery sweep) wins it, and the loser returns
/// [`SettleOutcome::AlreadySettled`] without touching the ledger.
///
/// The final `storage_upload` debit is CONTINGENT on the receipt insert: the receipt
/// shares the committed dedup identity `(account_id, backend, sha256)` with the
/// live-attempt guard, so a settled attempt whose bytes another receipt already holds
/// for this account+backend deduplicates to no receipt row. In that case the user is
/// not charged again — the hold is released and the believed winc charge is refunded
/// (a dedup-no-rebill). This makes "no charge without a receipt row" a structural
/// invariant rather than a hoped-for coincidence. When the receipt does insert, the
/// hold-release and the `storage_upload` debit key their `ref` on the attempt id, so
/// the hold/release pair nets to zero and the net effect is exactly one storage
/// charge; a retried commit collides on every `(kind, ref)` and is an idempotent
/// no-op.
pub async fn commit_attempt(
    pool: &sqlx::PgPool,
    attempt_id: Uuid,
    receipt: &StorageReceipt,
    request_id: Option<Uuid>,
) -> Result<SettleOutcome> {
    let mut txn = pool.begin().await?;

    // The compare-and-set. Nulls the envelope and the lease so the recovery
    // artifact is held only while genuinely in flight; returns the row only to the
    // single winner. The realized charge is stamped in THIS statement (the state
    // CHECK requires a non-null `settled_charge_usd_micros` the moment the attempt
    // leaves 'reserved'), provisionally to the held estimate for the common
    // fresh-receipt case; the dedup branch below overrides it to 0 if the receipt
    // deduplicated.
    let won: Option<SettleRow> = sqlx::query_as(
        "UPDATE cw_core.storage_upload_attempt \
            SET state = 'committed', \
                data_item_signature = NULL, data_item_anchor = NULL, \
                data_item_tag_bytes = NULL, staged_path = NULL, \
                upload_claim_token = NULL, upload_claim_expires_at = NULL, \
                settled_charge_usd_micros = charged_usd_micros, \
                settled_at = now() \
          WHERE id = $1 AND state = 'reserved' \
          RETURNING account_id, operator_id, funding_source_id, sha256, bytes, \
                    chargeable_bytes, charged_usd_micros, backend",
    )
    .bind(attempt_id)
    .fetch_optional(&mut *txn)
    .await?;

    let Some(row) = won else {
        // The sweep (or the live handler) already settled this attempt: the caller
        // reads back the receipt and returns ok. No ledger side effect.
        txn.rollback().await?;
        return Ok(SettleOutcome::AlreadySettled);
    };

    let sha256: [u8; 32] = row
        .sha256
        .as_slice()
        .try_into()
        .map_err(|_| Error::Config("committed attempt sha256 is not 32 bytes".into()))?;
    let bytes_i64 = row.bytes;

    // The receipt row, linked back to the attempt that paid for the bytes. The
    // RETURNING tells us whether this insert created the receipt or deduplicated
    // against an existing one for the same account+backend+content: a present id is a
    // fresh receipt to be charged, an absent id is a dedup that must NOT be charged.
    let receipt_inserted: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO cw_core.storage_upload \
           (id, account_id, sha256, bytes, uri, data_item_id, raw_receipt, root_tx_id, backend, \
            attempt_id, funding_source_id, charged_operator_id, chargeable_bytes, charged_usd_micros) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         ON CONFLICT (account_id, backend, sha256) WHERE account_id IS NOT NULL DO NOTHING \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(row.account_id)
    .bind(sha256.as_slice())
    .bind(bytes_i64)
    .bind(&receipt.uri)
    .bind(&receipt.data_item_id)
    .bind(&receipt.raw_receipt)
    .bind(&receipt.root_tx_id)
    .bind(&row.backend)
    .bind(attempt_id)
    .bind(row.funding_source_id)
    .bind(row.operator_id)
    .bind(row.chargeable_bytes)
    .bind(row.charged_usd_micros)
    .fetch_optional(&mut *txn)
    .await?;

    // The hold is always released (the reservation is over either way). Whether the
    // user is charged is contingent on the receipt: a fresh receipt charges once, a
    // dedup-no-rebill refunds the believed winc instead so the attempt nets to zero.
    let release = LedgerEntry {
        account_id: row.account_id,
        kind: "storage_hold_release".to_string(),
        amount_micros: row.charged_usd_micros,
        r#ref: Some(attempt_id.to_string()),
        quote_id: None,
        metadata: json!({}),
        request_id,
    };
    insert_ledger_entry(&mut *txn, &release).await?;

    let settled_charge = if receipt_inserted.is_some() {
        // Fresh receipt: apply the final storage debit. With the hold-release above
        // it nets to exactly one charge, both keyed on the attempt id. The CAS above
        // already stamped the realized charge as the held estimate, which is correct
        // for this branch, so no second stamp is needed.
        let charge = LedgerEntry {
            account_id: row.account_id,
            kind: "storage_upload".to_string(),
            amount_micros: -row.charged_usd_micros,
            r#ref: Some(attempt_id.to_string()),
            quote_id: None,
            metadata: json!({ "chargeable_bytes": row.chargeable_bytes }),
            request_id,
        };
        insert_ledger_entry(&mut *txn, &charge).await?;
        row.charged_usd_micros
    } else {
        // Dedup-no-rebill: another receipt already holds these bytes for this
        // account+backend, so no new artifact was stored and no charge is owed. The
        // hold is released above; compensate the believed winc charge appended at
        // reserve time so the operator's credit is also made whole. Override the
        // provisional realized charge the CAS stamped down to 0, so the poll route
        // and the live response report no charge.
        refund_estimated_winc(&mut txn, attempt_id, row.funding_source_id).await?;
        stamp_settled_charge(&mut txn, attempt_id, 0).await?;
        0
    };

    txn.commit().await?;
    Ok(SettleOutcome::Settled {
        charged_usd_micros: settled_charge,
    })
}

/// Override the realized debit recorded on a settled attempt row. Used by the
/// dedup-no-rebill branch to correct the provisional estimate the settle CAS
/// stamped down to 0. Run inside the settling transaction so it commits with the
/// CAS, and only on an attempt that has already left 'reserved' (so the state CHECK
/// that requires a non-null realized charge is never momentarily violated).
async fn stamp_settled_charge(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    attempt_id: Uuid,
    settled_charge_usd_micros: i64,
) -> Result<()> {
    sqlx::query(
        "UPDATE cw_core.storage_upload_attempt \
            SET settled_charge_usd_micros = $2 \
          WHERE id = $1",
    )
    .bind(attempt_id)
    .bind(settled_charge_usd_micros)
    .execute(&mut **txn)
    .await?;
    Ok(())
}

/// Compensate the believed winc charge appended at reserve time, reading its exact
/// magnitude off the attempt row so the refund cancels the charge precisely.
///
/// Used by every settlement that does NOT bill the operator's credit: a released
/// attempt (the bytes never landed) and a committed-but-deduped attempt (the bytes
/// were already stored, so no new credit was consumed). The reconcile cron remains
/// the authority on the real provider balance; this only undoes the believed hold.
async fn refund_estimated_winc(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    attempt_id: Uuid,
    funding_source_id: Uuid,
) -> Result<()> {
    let estimated_winc: Decimal = sqlx::query_scalar(
        "SELECT estimated_winc FROM cw_core.storage_upload_attempt WHERE id = $1",
    )
    .bind(attempt_id)
    .fetch_one(&mut **txn)
    .await?;
    if !estimated_winc.is_zero() {
        let winc_refund = CreditEntry {
            funding_source_id,
            kind: CreditKind::Refund,
            winc_delta: estimated_winc,
            r#ref: Some(attempt_id.to_string()),
        };
        insert_credit_entry(&mut **txn, &winc_refund).await?;
    }
    Ok(())
}

/// Release a `reserved` attempt on a definite provider failure: flip it `released`,
/// stamp the reason, return the hold, and compensate the believed winc charge, all
/// in one transaction guarded by the compare-and-set on `state`.
///
/// As with [`commit_attempt`] the CAS is single-winner. The `storage_hold_release`
/// credit returns the held USD (the user is not charged), and the winc `refund`
/// compensates the believed `charge` appended at reserve time, both keyed on the
/// attempt id so a retry is an idempotent no-op.
pub async fn release_attempt(
    pool: &sqlx::PgPool,
    attempt_id: Uuid,
    reason: ReleaseReason,
    request_id: Option<Uuid>,
) -> Result<SettleOutcome> {
    let mut txn = pool.begin().await?;

    // The CAS stamps the realized charge as 0 in the SAME statement that leaves
    // 'reserved' (a release never bills the user), so the state CHECK requiring a
    // non-null realized charge holds at the statement boundary.
    let won: Option<SettleRow> = sqlx::query_as(
        "UPDATE cw_core.storage_upload_attempt \
            SET state = 'released', release_reason = $2, \
                data_item_signature = NULL, data_item_anchor = NULL, \
                data_item_tag_bytes = NULL, staged_path = NULL, \
                upload_claim_token = NULL, upload_claim_expires_at = NULL, \
                settled_charge_usd_micros = 0, \
                settled_at = now() \
          WHERE id = $1 AND state = 'reserved' \
          RETURNING account_id, operator_id, funding_source_id, sha256, bytes, \
                    chargeable_bytes, charged_usd_micros, backend",
    )
    .bind(attempt_id)
    .bind(reason.as_str())
    .fetch_optional(&mut *txn)
    .await?;

    let Some(row) = won else {
        txn.rollback().await?;
        return Ok(SettleOutcome::AlreadySettled);
    };

    // Return the held USD: the upload failed, so the user is not charged. The
    // release magnitude equals the original hold, so the pair nets to zero.
    let release = LedgerEntry {
        account_id: row.account_id,
        kind: "storage_hold_release".to_string(),
        amount_micros: row.charged_usd_micros,
        r#ref: Some(attempt_id.to_string()),
        quote_id: None,
        metadata: json!({ "release_reason": reason.as_str() }),
        request_id,
    };
    insert_ledger_entry(&mut *txn, &release).await?;

    // Compensate the believed winc charge appended at reserve time; the reconcile
    // cron remains the authority on the real provider balance.
    refund_estimated_winc(&mut txn, attempt_id, row.funding_source_id).await?;

    txn.commit().await?;
    Ok(SettleOutcome::Settled {
        charged_usd_micros: 0,
    })
}

/// Release a `reserved` attempt the recovery sweep proved unrecoverable, and emit
/// the terminal client-facing upload-failed event, all in one compare-and-set
/// transaction.
///
/// This is the [`release_attempt`] twin for the one release cause the live handler
/// never produces: the sweep found the provider does not hold the data item AND the
/// durable staged content did not survive, so the body cannot be reconstructed. The
/// reason is fixed to [`ReleaseReason::UnrecoverableStagedContentLost`]. Beyond the
/// hold-release + winc-refund the ordinary release writes, this appends
/// [`STORAGE_UPLOAD_FAILED_EVENT`] on the owning account's subject INSIDE the same
/// transaction as the release CAS, so the event commits if and only if this settler
/// won the CAS: a redundant settler whose CAS returns no row appends nothing, and
/// the single-winner CAS makes the terminal event exactly-once. The payload carries
/// the attempt id + the content digest so the client can correlate the failure to
/// the file it uploaded and re-upload exactly those bytes.
pub async fn release_unrecoverable(
    pool: &sqlx::PgPool,
    attempt_id: Uuid,
    request_id: Option<Uuid>,
) -> Result<SettleOutcome> {
    let reason = ReleaseReason::UnrecoverableStagedContentLost;
    let mut txn = pool.begin().await?;

    // The CAS stamps the realized charge as 0 in the SAME statement that leaves
    // 'reserved' (a release never bills the user), so the state CHECK requiring a
    // non-null realized charge holds at the statement boundary.
    let won: Option<SettleRow> = sqlx::query_as(
        "UPDATE cw_core.storage_upload_attempt \
            SET state = 'released', release_reason = $2, \
                data_item_signature = NULL, data_item_anchor = NULL, \
                data_item_tag_bytes = NULL, staged_path = NULL, \
                upload_claim_token = NULL, upload_claim_expires_at = NULL, \
                settled_charge_usd_micros = 0, \
                settled_at = now() \
          WHERE id = $1 AND state = 'reserved' \
          RETURNING account_id, operator_id, funding_source_id, sha256, bytes, \
                    chargeable_bytes, charged_usd_micros, backend",
    )
    .bind(attempt_id)
    .bind(reason.as_str())
    .fetch_optional(&mut *txn)
    .await?;

    let Some(row) = won else {
        txn.rollback().await?;
        return Ok(SettleOutcome::AlreadySettled);
    };

    let sha256: [u8; 32] = row
        .sha256
        .as_slice()
        .try_into()
        .map_err(|_| Error::Config("released attempt sha256 is not 32 bytes".into()))?;
    let bytes = u64::try_from(row.bytes)
        .map_err(|_| Error::Config("released attempt byte count is negative".into()))?;

    // Return the held USD: the bytes never landed, so the user is not charged. The
    // release magnitude equals the original hold, so the pair nets to zero.
    let release = LedgerEntry {
        account_id: row.account_id,
        kind: "storage_hold_release".to_string(),
        amount_micros: row.charged_usd_micros,
        r#ref: Some(attempt_id.to_string()),
        quote_id: None,
        metadata: json!({ "release_reason": reason.as_str() }),
        request_id,
    };
    insert_ledger_entry(&mut *txn, &release).await?;

    // Compensate the believed winc charge appended at reserve time.
    refund_estimated_winc(&mut txn, attempt_id, row.funding_source_id).await?;

    // The terminal client-facing event, appended in the same transaction as the CAS
    // so it commits exactly when the attempt transitioned to released. It rides the
    // owning account's subject and carries the keys the client needs to re-upload.
    crate::events::append_subject_event(
        &mut txn,
        ACCOUNT_SUBJECT_KIND,
        &row.account_id.to_string(),
        STORAGE_UPLOAD_FAILED_EVENT,
        &json!({
            "attempt_id": attempt_id,
            "sha256": hex::encode(sha256),
            "bytes": bytes,
            "backend": row.backend,
            "reason": reason.as_str(),
        }),
    )
    .await?;

    txn.commit().await?;
    Ok(SettleOutcome::Settled {
        charged_usd_micros: 0,
    })
}

/// The columns a settlement CAS returns to drive its ledger side effects.
#[derive(sqlx::FromRow)]
struct SettleRow {
    account_id: Uuid,
    operator_id: Uuid,
    funding_source_id: Uuid,
    sha256: Vec<u8>,
    #[allow(dead_code)]
    bytes: i64,
    chargeable_bytes: i64,
    charged_usd_micros: i64,
    backend: String,
}

/// Load an attempt by id (the poll route's read).
pub async fn load_attempt(pool: &sqlx::PgPool, attempt_id: Uuid) -> Result<Option<Attempt>> {
    let row: Option<AttemptRow> = sqlx::query_as(
        "SELECT id, account_id, funding_source_id, backend, sha256, bytes, chargeable_bytes, \
                charged_usd_micros, settled_charge_usd_micros, data_item_id, state, release_reason \
         FROM cw_core.storage_upload_attempt WHERE id = $1",
    )
    .bind(attempt_id)
    .fetch_optional(pool)
    .await?;
    row.map(AttemptRow::into_attempt).transpose()
}

/// Load the live (`reserved`) attempt for a logical upload, if one exists.
///
/// The fast-path attach check the route runs before signing, and the attach reload
/// after a lost insert race. A `committed`/`released` attempt is not live (its slot
/// is freed), so this never returns one.
pub async fn load_live_attempt(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    backend: &str,
    sha256: &[u8; 32],
) -> Result<Option<Attempt>> {
    let row: Option<AttemptRow> = sqlx::query_as(
        "SELECT id, account_id, funding_source_id, backend, sha256, bytes, chargeable_bytes, \
                charged_usd_micros, settled_charge_usd_micros, data_item_id, state, release_reason \
         FROM cw_core.storage_upload_attempt \
         WHERE account_id = $1 AND backend = $2 AND sha256 = $3 AND state = 'reserved' \
         LIMIT 1",
    )
    .bind(account_id)
    .bind(backend)
    .bind(sha256.as_slice())
    .fetch_optional(pool)
    .await?;
    row.map(AttemptRow::into_attempt).transpose()
}

/// The bounded signed envelope a `reserved` attempt persists, read by the recovery
/// sweep to reconstruct the byte-identical data item for a re-POST.
#[derive(Debug, Clone)]
pub struct PersistedEnvelope {
    /// The signature bytes (RSA-4096 = 512 bytes).
    pub signature: Vec<u8>,
    /// The optional 32-byte anchor.
    pub anchor: Option<Vec<u8>>,
    /// The serialised tag block.
    pub tag_bytes: Vec<u8>,
    /// The durable staged content path.
    pub staged_path: Option<String>,
    /// The data-item id.
    pub data_item_id: String,
}

/// Read the persisted signed envelope for a `reserved` attempt (the recovery
/// sweep's reconstruction inputs), or `None` when the attempt is not reserved (its
/// envelope was nulled on settlement).
pub async fn load_envelope(
    pool: &sqlx::PgPool,
    attempt_id: Uuid,
) -> Result<Option<PersistedEnvelope>> {
    let row: Option<EnvelopeRow> = sqlx::query_as(
        "SELECT data_item_signature, data_item_anchor, data_item_tag_bytes, staged_path, \
                data_item_id \
         FROM cw_core.storage_upload_attempt \
         WHERE id = $1 AND state = 'reserved'",
    )
    .bind(attempt_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| {
        // A reserved attempt always carries its signature + tag block; if they are
        // somehow absent the envelope is unusable, so report none.
        let signature = r.data_item_signature?;
        Some(PersistedEnvelope {
            signature,
            anchor: r.data_item_anchor,
            tag_bytes: r.data_item_tag_bytes.unwrap_or_default(),
            staged_path: r.staged_path,
            data_item_id: r.data_item_id,
        })
    }))
}

/// The envelope columns the recovery reconstruction reads.
#[derive(sqlx::FromRow)]
struct EnvelopeRow {
    data_item_signature: Option<Vec<u8>>,
    data_item_anchor: Option<Vec<u8>>,
    data_item_tag_bytes: Option<Vec<u8>>,
    staged_path: Option<String>,
    data_item_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_state_round_trips() {
        for s in [
            AttemptState::Reserved,
            AttemptState::Committed,
            AttemptState::Released,
        ] {
            assert_eq!(AttemptState::from_str(s.as_str()).unwrap(), s);
        }
        assert!(AttemptState::from_str("nonsense").is_err());
    }

    #[test]
    fn release_reason_strings_match_the_check_constraint() {
        assert_eq!(
            ReleaseReason::ProviderRejected.as_str(),
            "provider_rejected"
        );
        assert_eq!(
            ReleaseReason::UnrecoverableStagedContentLost.as_str(),
            "unrecoverable_staged_content_lost"
        );
    }
}
