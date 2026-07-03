//! The durable, per-UTxO state machine.
//!
//! Each tracked output is one `cw_core.wallet_utxo` row moving through
//! `available -> in_flight -> pending_spent -> confirmed_spent`, with a fenced
//! `in_flight -> available` release/expiry. Replacing the old single-JSONB
//! snapshot, a per-row state machine lets concurrent submits lease distinct
//! outputs without clobbering each other.
//!
//! # Leasing and fencing
//!
//! [`claim`] flips one `available` canonical row to `in_flight`, stamping a fresh
//! `lease_token` and a short expiry. Every later transition ([`release`],
//! [`apply_submit_in_tx`]) fences on that token: a stale builder whose lease was
//! reaped cannot move a UTxO a fresh claimant now owns. [`reap_expired_leases`]
//! returns
//! `in_flight` rows past their expiry to `available`, but only for wallets whose
//! advisory lock it can take: a held lock means a live (possibly just slow) submit
//! still owns the wallet, so the reaper skips it and its lease survives. The lock,
//! not the expiry clock alone, is the authority on whether a builder is still live.
//!
//! # Apply-change-locally
//!
//! On an accepted submit, [`apply_submit_in_tx`] marks each spent input
//! `pending_spent` and inserts the expected change output as a new `available` row sourced from
//! the change, in the same transaction. The change is not canonical-eligible nor
//! spendable-unconfirmed by default; [`apply_confirmed`] (driven by the chain
//! confirmation path) promotes the spend to `confirmed_spent` and lets the change
//! become canonical-eligible once it is confirmed on chain.
//!
//! # Cancelling replacement
//!
//! When a reorg rolls a confirmed-or-pending transaction back, the confirm path
//! resubmits a *cancelling replacement* that must spend at least one input of the
//! rolled-back transaction so the old metadata-only transaction can never land
//! afterwards. [`claim_replacement`] re-leases those specific inputs (currently
//! `pending_spent` or `confirmed_spent` from the rolled-back transaction) back to
//! `in_flight` under a fresh lease token, so the replacement's build owns them and
//! no concurrent submit can also pick them. [`apply_submit_in_tx`] then advances
//! all of the replacement's inputs together.
//!
//! Crucially, re-leasing an input does NOT terminalise the original: the original
//! stays a live, reconcilable broadcaster whose inputs remain ITS reservation until
//! the replacement re-confirms to settlement depth. So a rollback of an
//! unrecorded/lost replacement lease must return the borrowed input to the spent
//! state it came from, NOT to `available` — returning it to `available` would hand
//! an input the live original still holds back to the free pool, where a fresh
//! claim could double-spend it. The `restore_state` column carries that rollback
//! target: `claim_replacement` records the prior spent state into it, and [`release`]
//! and [`reap_expired_leases`] roll a lease back to `COALESCE(restore_state,
//! 'available')`. An ordinary [`claim`]/[`claim_source`] lease has no
//! `restore_state` and so rolls back to `available` as before. Only the
//! chain-truth-proven [`restore_inputs_in_tx`] returns a spent input to `available`,
//! and [`apply_submit_in_tx`] clears `restore_state` on a recorded spend.

use uuid::Uuid;
use zeroize::Zeroizing;

use super::config::{LovelaceBand, WalletConfig, MAX_CANONICAL_OUTPUT_INDEX};
use crate::{Error, Result};

/// A UTxO's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum UtxoState {
    /// Unspent and free to be leased by a submit.
    Available,
    /// Leased by an in-flight build/submit, holding a fencing token + expiry.
    InFlight,
    /// The accepted submit's input: spent on chain but not yet confirmed.
    PendingSpent,
    /// The spend confirmed; the row is terminal.
    ConfirmedSpent,
}

/// Where a tracked UTxO came from (the row's `source` column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum UtxoOrigin {
    /// Observed on chain by a snapshot ingest.
    Snapshot,
    /// The expected change output recorded locally on an accepted submit.
    Change,
}

/// An on-chain UTxO reference: the origin transaction id and output index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtxoRef {
    /// 32-byte origin transaction id.
    pub tx_hash: [u8; 32],
    /// Output index within that transaction.
    pub output_index: u32,
}

/// A tracked UTxO row as read back from Postgres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletUtxo {
    /// The wallet that owns the output.
    pub wallet_id: Uuid,
    /// The on-chain reference.
    pub utxo: UtxoRef,
    /// Lovelace the output holds.
    pub lovelace: u64,
    /// Lifecycle state.
    pub state: UtxoState,
    /// Whether the output is canonical (pure-ADA, low index, value in band).
    pub canonical: bool,
    /// Whether unconfirmed change may be chained on (false unless policy opts in).
    pub spendable_unconfirmed: bool,
    /// The fencing token while `in_flight`; `None` otherwise.
    pub lease_token: Option<Uuid>,
    /// When the lease expires while `in_flight`; `None` otherwise.
    pub lease_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Where the row came from.
    pub source: UtxoOrigin,
}

/// An output observed on chain during a snapshot ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedUtxo {
    /// The on-chain reference.
    pub utxo: UtxoRef,
    /// Lovelace the output holds.
    pub lovelace: u64,
    /// Whether the output is pure ADA (no native tokens). A token-bearing output
    /// is never canonical regardless of its index or value.
    pub pure_ada: bool,
}

/// A successful lease over one canonical UTxO.
///
/// Carries the leased reference plus the fencing token every subsequent
/// transition must present. Holding this does not keep the lease alive on its
/// own; the durable expiry and the per-wallet advisory lock do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoLease {
    /// The wallet the UTxO belongs to.
    pub wallet_id: Uuid,
    /// The leased reference.
    pub utxo: UtxoRef,
    /// The lovelace the leased output holds.
    pub lovelace: u64,
    /// The fencing token to present on release / apply_submit_in_tx.
    pub lease_token: Uuid,
    /// When the lease expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Whether an observed output is canonical under a band: pure ADA, output index
/// below the cap, and value inside the band.
///
/// Canonicality is computed once at ingest and stored, because it is the
/// predicate the quote depends on: a canonical UTxO has a fixed CBOR width, so a
/// one-input transaction over any canonical UTxO charges the same fee.
#[must_use]
pub fn is_canonical(observed: &ObservedUtxo, band: &LovelaceBand) -> bool {
    observed.pure_ada
        && observed.utxo.output_index < MAX_CANONICAL_OUTPUT_INDEX
        && band.contains(observed.lovelace)
}

/// Ingest a chain snapshot for a wallet, reconciling it with local state.
///
/// Inserts newly observed outputs (computing `canonical` per [`is_canonical`])
/// and marks `available` rows that were known to be on chain but have vanished
/// from it as `confirmed_spent`. It MUST NOT resurrect a `pending_spent` row from
/// a stale chain read that still lists the input (the local pending state is
/// authoritative until a confirmation supersedes it), it leaves a live in-flight
/// lease untouched, and it MUST NOT tombstone a locally recorded change/minted
/// output that has not confirmed yet: such a row was never on chain, so its
/// absence from a snapshot is expected, not evidence of a spend. Returns how
/// many rows were inserted.
pub async fn ingest_snapshot(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    observed: &[ObservedUtxo],
    config: &WalletConfig,
) -> Result<u64> {
    let mut tx = pool.begin().await?;

    let mut inserted = 0u64;
    for output in observed {
        // A pure-ADA output that vanished and reappeared, or that the chain still
        // lists, must never overwrite a local row that has already advanced past
        // `available`: the local pending/in-flight/confirmed state is
        // authoritative. ON CONFLICT DO NOTHING keeps the row untouched, so a
        // stale snapshot that still lists a `pending_spent` input cannot resurrect
        // it to `available`.
        let canonical = is_canonical(output, &config.band);
        let rows = sqlx::query(
            "INSERT INTO cw_core.wallet_utxo \
               (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
             VALUES ($1, $2, $3, $4, 'available', $5, 'snapshot') \
             ON CONFLICT (wallet_id, tx_hash, output_index) DO NOTHING",
        )
        .bind(wallet_id)
        .bind(output.utxo.tx_hash.as_slice())
        .bind(output_index_to_i32(output.utxo.output_index)?)
        .bind(lovelace_to_i64(output.lovelace)?)
        .bind(canonical)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        inserted += rows;
    }

    // Reconcile vanished outputs. An `available` row the chain listed before but
    // no longer lists was spent out of band (by another deployment or a manual
    // spend) and is confirmed gone; mark it `confirmed_spent` so the scheduler
    // stops offering it. Two deliberate scope limits:
    //
    // - ONLY `available` rows: an `in_flight` row is held by a live lease and a
    //   `pending_spent` row is the authoritative record of a spend this engine
    //   made, neither of which a snapshot may override. A `pending_spent` input
    //   the chain still lists (the spend has not confirmed yet) is left exactly
    //   as it is.
    // - ONLY rows known to have been on chain: a `snapshot`-sourced row was
    //   observed on chain at insert, and a `change`-sourced row qualifies once
    //   confirmation has promoted it (apply_confirmed_in_tx sets
    //   `spendable_unconfirmed` unconditionally then, unlike `canonical`, which
    //   stays false for out-of-band change — so `spendable_unconfirmed` is the
    //   exact "has confirmed on chain" marker for local change). A change/minted
    //   output recorded at submit but not yet confirmed was NEVER on chain, so a
    //   snapshot taken in the broadcast->confirmation window is expected not to
    //   list it; tombstoning it there would strand the wallet's own change and
    //   starve replenish of the band-mid outputs it just minted. Such a row is
    //   skipped until confirmation makes its absence meaningful (and if its
    //   transaction is abandoned instead, tombstone_outputs_in_tx deletes it, so
    //   nothing stays unreconcilable forever).
    let present: Vec<(Vec<u8>, i32)> = observed
        .iter()
        .map(|o| {
            Ok((
                o.utxo.tx_hash.to_vec(),
                output_index_to_i32(o.utxo.output_index)?,
            ))
        })
        .collect::<Result<_>>()?;
    let present_hashes: Vec<Vec<u8>> = present.iter().map(|(h, _)| h.clone()).collect();
    let present_indexes: Vec<i32> = present.iter().map(|(_, i)| *i).collect();

    sqlx::query(
        "UPDATE cw_core.wallet_utxo \
         SET state = 'confirmed_spent', updated_at = now() \
         WHERE wallet_id = $1 \
           AND state = 'available' \
           AND (source = 'snapshot' OR spendable_unconfirmed) \
           AND NOT EXISTS ( \
             SELECT 1 FROM unnest($2::bytea[], $3::int[]) AS o(tx_hash, output_index) \
             WHERE o.tx_hash = cw_core.wallet_utxo.tx_hash \
               AND o.output_index = cw_core.wallet_utxo.output_index \
           )",
    )
    .bind(wallet_id)
    .bind(&present_hashes)
    .bind(&present_indexes)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(inserted)
}

/// Claim one canonical, available UTxO for a wallet, flipping it to `in_flight`
/// with the given fencing token and the configured lease duration.
///
/// Returns `Ok(Some(lease))` on success or `Ok(None)` when the wallet has no
/// canonical available UTxO to lease (the caller routes to another wallet or
/// triggers a replenish). The `FOR UPDATE SKIP LOCKED` row pick means two
/// concurrent claims on the same wallet take different rows.
pub async fn claim(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    lease_token: Uuid,
    config: &WalletConfig,
) -> Result<Option<UtxoLease>> {
    let lease_secs = duration_to_secs(config.lease)?;
    let mut tx = pool.begin().await?;

    // Lock one canonical available row so a concurrent claim on the same wallet
    // skips it (SKIP LOCKED) and takes the next one, then flip the locked row to
    // in_flight inside the same transaction. The CTE keeps the pick and the flip
    // atomic: the row stays row-locked from SELECT through UPDATE, so no other
    // transaction can claim it in the gap.
    let row = sqlx::query_as::<_, ClaimedRow>(
        "WITH picked AS ( \
            SELECT tx_hash, output_index \
            FROM cw_core.wallet_utxo \
            WHERE wallet_id = $1 AND state = 'available' AND canonical \
            ORDER BY tx_hash, output_index \
            FOR UPDATE SKIP LOCKED \
            LIMIT 1 \
         ) \
         UPDATE cw_core.wallet_utxo u \
         SET state = 'in_flight', \
             restore_state = NULL, \
             lease_token = $2, \
             lease_expires_at = now() + make_interval(secs => $3), \
             updated_at = now() \
         FROM picked \
         WHERE u.wallet_id = $1 \
           AND u.tx_hash = picked.tx_hash \
           AND u.output_index = picked.output_index \
         RETURNING u.tx_hash, u.output_index, u.lovelace, u.lease_expires_at",
    )
    .bind(wallet_id)
    .bind(lease_token)
    .bind(lease_secs)
    .fetch_optional(&mut *tx)
    .await?;

    tx.commit().await?;

    let Some(row) = row else {
        return Ok(None);
    };

    Ok(Some(UtxoLease {
        wallet_id,
        utxo: UtxoRef {
            tx_hash: tx_hash_from_bytes(&row.tx_hash)?,
            output_index: i32_to_output_index(row.output_index)?,
        },
        lovelace: i64_to_lovelace(row.lovelace)?,
        lease_token,
        expires_at: row.lease_expires_at.ok_or_else(|| {
            Error::Config("a claimed in_flight row must carry a lease expiry".to_string())
        })?,
    }))
}

/// Re-lease the specific inputs of a rolled-back transaction to a cancelling
/// replacement, flipping each from `pending_spent`/`confirmed_spent` back to
/// `in_flight` under a fresh `lease_token` with the configured expiry.
///
/// A reorg returns the rolled-back transaction's inputs to the chain, but the
/// wallet's view still has them as spent. The replacement must consume at least
/// one of them so the rolled-back transaction can never re-enter and double-
/// publish; re-leasing them here hands them to the replacement's build exclusively
/// (a fresh `in_flight` lease no concurrent submit can also claim), in one
/// transaction. Returns the leases for the inputs that were re-acquired; an input
/// already advanced past spent by another path (so not re-leasable) is omitted,
/// and the caller decides whether the inputs it did acquire suffice to cancel.
///
/// Unlike [`claim`], which picks any canonical available row, this targets named
/// references: the replacement is defined by the exact inputs it must cancel, so
/// the function leases those and only those.
pub async fn claim_replacement(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    inputs: &[UtxoRef],
    lease_token: Uuid,
    config: &WalletConfig,
) -> Result<Vec<UtxoLease>> {
    if inputs.is_empty() {
        return Ok(Vec::new());
    }

    let lease_secs = duration_to_secs(config.lease)?;
    let mut tx = pool.begin().await?;
    let mut leases = Vec::with_capacity(inputs.len());

    // Each input is re-leased under one transaction so the replacement's whole
    // input set is acquired atomically: either every input that is still
    // re-leasable flips to in_flight together, or the transaction rolls back and
    // none do. An input that has already advanced past spent by another path (so
    // is neither pending_spent nor confirmed_spent) simply does not flip and is
    // omitted from the returned leases; the caller decides whether the inputs it
    // did acquire suffice to cancel the rolled-back transaction.
    for input in inputs {
        let row = sqlx::query_as::<_, ClaimedRow>(
            // Capture the input's prior spent state into `restore_state` IN THE SAME
            // update that flips it to `in_flight`: a Postgres `SET` expression reads
            // the OLD row value, so `restore_state = state` records the
            // pending_spent/confirmed_spent the input came from. A later rollback of
            // this replacement lease (release, lease-reaper, or a lost-generation
            // record failure) then returns the input to that reserved spent state
            // rather than to `available`, so the still-live original keeps exclusive
            // hold of an input the replacement only borrowed.
            "UPDATE cw_core.wallet_utxo \
             SET restore_state = state, \
                 state = 'in_flight', \
                 lease_token = $4, \
                 lease_expires_at = now() + make_interval(secs => $5), \
                 updated_at = now() \
             WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3 \
               AND state IN ('pending_spent', 'confirmed_spent') \
             RETURNING tx_hash, output_index, lovelace, lease_expires_at",
        )
        .bind(wallet_id)
        .bind(input.tx_hash.as_slice())
        .bind(output_index_to_i32(input.output_index)?)
        .bind(lease_token)
        .bind(lease_secs)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            continue;
        };

        leases.push(UtxoLease {
            wallet_id,
            utxo: UtxoRef {
                tx_hash: tx_hash_from_bytes(&row.tx_hash)?,
                output_index: i32_to_output_index(row.output_index)?,
            },
            lovelace: i64_to_lovelace(row.lovelace)?,
            lease_token,
            expires_at: row.lease_expires_at.ok_or_else(|| {
                Error::Config("a re-leased in_flight row must carry a lease expiry".to_string())
            })?,
        });
    }

    tx.commit().await?;
    Ok(leases)
}

/// Lease one specific named, `available` UTxO to `in_flight` under a fresh
/// fencing token and the configured expiry.
///
/// Unlike [`claim`], which picks any canonical available row, this leases a UTxO
/// the caller names by reference and does not require it to be canonical: the
/// replenisher leases an oversized (non-canonical) source it is about to split,
/// so the source moves through the same `available -> in_flight -> pending_spent`
/// state machine every other spend does. The row must be tracked and `available`;
/// returns `Ok(None)` when it is absent or already past `available` (leased by
/// another path, already spent), so a concurrent replenish cannot lease the same
/// source twice.
pub async fn claim_source(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    source: UtxoRef,
    lease_token: Uuid,
    config: &WalletConfig,
) -> Result<Option<UtxoLease>> {
    let lease_secs = duration_to_secs(config.lease)?;
    let row = sqlx::query_as::<_, ClaimedRow>(
        "UPDATE cw_core.wallet_utxo \
         SET state = 'in_flight', \
             restore_state = NULL, \
             lease_token = $4, \
             lease_expires_at = now() + make_interval(secs => $5), \
             updated_at = now() \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3 \
           AND state = 'available' \
         RETURNING tx_hash, output_index, lovelace, lease_expires_at",
    )
    .bind(wallet_id)
    .bind(source.tx_hash.as_slice())
    .bind(output_index_to_i32(source.output_index)?)
    .bind(lease_token)
    .bind(lease_secs)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    Ok(Some(UtxoLease {
        wallet_id,
        utxo: UtxoRef {
            tx_hash: tx_hash_from_bytes(&row.tx_hash)?,
            output_index: i32_to_output_index(row.output_index)?,
        },
        lovelace: i64_to_lovelace(row.lovelace)?,
        lease_token,
        expires_at: row.lease_expires_at.ok_or_else(|| {
            Error::Config("a claimed in_flight source must carry a lease expiry".to_string())
        })?,
    }))
}

/// Release a leased UTxO back to the state its lease must roll back to, fenced on
/// the lease token.
///
/// The lease holder calls this after an unambiguous submit failure once it has
/// confirmed the input is still unspent. An ordinary claim/claim_source lease has
/// no `restore_state`, so it returns to `available`; a cancelling replacement's
/// re-leased input (`restore_state` recorded its prior spent state) returns to that
/// reserved spent state, so a released replacement input never re-enters the free
/// pool while the original it was borrowed from is still live. Returns `true` if
/// the row was the caller's lease (token matched and it was `in_flight`) and was
/// rolled back, `false` if the lease no longer matched (already reaped or
/// transitioned).
pub async fn release(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    utxo: UtxoRef,
    lease_token: Uuid,
) -> Result<bool> {
    let affected = sqlx::query(
        "UPDATE cw_core.wallet_utxo \
         SET state = COALESCE(restore_state, 'available'), \
             restore_state = NULL, lease_token = NULL, lease_expires_at = NULL, \
             updated_at = now() \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3 \
           AND state = 'in_flight' AND lease_token = $4",
    )
    .bind(wallet_id)
    .bind(utxo.tx_hash.as_slice())
    .bind(output_index_to_i32(utxo.output_index)?)
    .bind(lease_token)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected == 1)
}

/// The expected change output an accepted submit produces, recorded locally so
/// the wallet's balance is not understated between submit and confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeOutput {
    /// The change output's on-chain reference (the submit tx id + its index).
    pub utxo: UtxoRef,
    /// Lovelace returned to the wallet as change.
    pub lovelace: u64,
}

/// One input an accepted submit spent, with the fencing token its lease carried.
///
/// A submit spends one input in the common case and several when it is a
/// cancelling replacement (the freshly claimed canonical input plus the
/// rolled-back inputs it is forced to consume). Each input was leased
/// independently, so each carries its own token and is advanced under its own
/// fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpentInput {
    /// The leased input the submit consumed.
    pub utxo: UtxoRef,
    /// The fencing token from the lease that claimed it.
    pub lease_token: Uuid,
}

/// Apply an accepted submit's wallet-state effects within a caller-owned
/// transaction: mark each leased input `pending_spent` (fenced on its own lease
/// token) and insert the expected change output as an `available`,
/// `source = 'change'` row.
///
/// Every spent input is advanced atomically: only if ALL of them were still the
/// caller's lease does the call report success. The DML runs on the caller's
/// transaction so the wallet writes commit atomically with the rows the caller
/// wrote before them. The record-before-broadcast path uses this to advance the
/// leases and insert the change as the LAST writes of the one transaction that
/// already wrote the attempt and the record (the lock order is attempt -> record
/// -> wallet), so a crash can never leave the spend on chain but unrecorded. The
/// inserted change is NOT canonical and NOT spendable-unconfirmed, so the
/// scheduler and replenisher never build on it until a confirmation promotes it.
///
/// Returns `true` when every fenced input update applied; `false` when any lease
/// no longer matched, in which case the caller MUST roll the whole transaction
/// back (this helper does not roll back the caller's transaction, since it does
/// not own it). All-or-nothing is the safe rule for a multi-input replacement: a
/// partial apply (some inputs advanced, one stale) would leave the wallet's view
/// inconsistent with the transaction that landed. The fenced UPDATEs that did
/// apply before the stale one are reverted by the caller's rollback.
pub async fn apply_submit_in_tx(
    tx: &mut sqlx::PgConnection,
    wallet_id: Uuid,
    spent: &[SpentInput],
    change: Option<ChangeOutput>,
) -> Result<bool> {
    if spent.is_empty() {
        return Err(Error::Config(
            "apply_submit_in_tx requires at least one spent input".to_string(),
        ));
    }

    // Fence every spend on its own lease token: only the lease holder may advance
    // its input. If any input is no longer ours (a reaped/re-claimed lease) the
    // caller rolls the whole transaction back, so a replacement never lands a
    // half-recorded spend.
    for input in spent {
        // The spend is now durably recorded by the attempt this transaction writes,
        // so the lease's rollback target is no longer meaningful: clear
        // `restore_state`. A replacement's borrowed input becomes a plain
        // `pending_spent` row exactly like a first-submit input; if THIS attempt
        // later dies, only the chain-truth-proven restore_inputs_in_tx path (gated on
        // a settlement-deep conflict or a deterministic reject) returns it to
        // `available`, and the replacement-reject arm restores only the replacement's
        // EXCLUSIVE inputs, leaving a shared original input reserved.
        let advanced = sqlx::query(
            "UPDATE cw_core.wallet_utxo \
             SET state = 'pending_spent', restore_state = NULL, \
                 lease_token = NULL, lease_expires_at = NULL, updated_at = now() \
             WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3 \
               AND state = 'in_flight' AND lease_token = $4",
        )
        .bind(wallet_id)
        .bind(input.utxo.tx_hash.as_slice())
        .bind(output_index_to_i32(input.utxo.output_index)?)
        .bind(input.lease_token)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;

        if !advanced {
            // A lease was no longer ours; signal the caller to roll back rather
            // than record a partial submit.
            return Ok(false);
        }
    }

    if let Some(change) = change {
        // The change is spendable only after the spend confirms: it lands
        // non-canonical and not spendable-unconfirmed, so neither the scheduler
        // nor the replenisher builds on it before confirmation.
        sqlx::query(
            "INSERT INTO cw_core.wallet_utxo \
               (wallet_id, tx_hash, output_index, lovelace, state, canonical, spendable_unconfirmed, source) \
             VALUES ($1, $2, $3, $4, 'available', false, false, 'change')",
        )
        .bind(wallet_id)
        .bind(change.utxo.tx_hash.as_slice())
        .bind(output_index_to_i32(change.utxo.output_index)?)
        .bind(lovelace_to_i64(change.lovelace)?)
        .execute(&mut *tx)
        .await?;
    }

    Ok(true)
}

/// Apply an accepted split's wallet-state effects within a caller-owned
/// transaction: advance the leased source input to `pending_spent` (fenced on its
/// lease token) and insert every minted band-mid output as an `available`,
/// `source = 'change'` row that confirmation later promotes to canonical.
///
/// Like [`apply_submit_in_tx`], this fences on the source's lease token and is
/// all-or-nothing. The DML runs on the caller's transaction so the wallet writes
/// commit atomically with the `chain_attempt` row the record-before-broadcast path
/// writes before them (the lock order is attempt -> wallet for a split, which has no
/// record). A crash can then never leave the split on chain but unrecorded: the
/// signed bytes are durable in the attempt before they ever reach the wire.
///
/// Returns `true` when the source was still the caller's lease (the fenced update
/// advanced exactly the one row); `false` when the lease no longer matched, in
/// which case the caller MUST roll the whole transaction back (this helper does not
/// own it). The minted outputs land non-canonical and not spendable-unconfirmed, so
/// neither the scheduler nor the replenisher builds on them until a confirmation
/// promotes them.
pub async fn apply_split_in_tx(
    tx: &mut sqlx::PgConnection,
    wallet_id: Uuid,
    spent: &SpentInput,
    minted: &[ChangeOutput],
) -> Result<bool> {
    // The source spend is now durably recorded by the split attempt; clear any
    // `restore_state` so the row is a plain `pending_spent` reservation (a split
    // source is claimed from `available`, so this is normally already NULL, but the
    // clear keeps the transition's post-state unambiguous).
    let advanced = sqlx::query(
        "UPDATE cw_core.wallet_utxo \
         SET state = 'pending_spent', restore_state = NULL, \
             lease_token = NULL, lease_expires_at = NULL, updated_at = now() \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3 \
           AND state = 'in_flight' AND lease_token = $4",
    )
    .bind(wallet_id)
    .bind(spent.utxo.tx_hash.as_slice())
    .bind(output_index_to_i32(spent.utxo.output_index)?)
    .bind(spent.lease_token)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;

    if !advanced {
        // A stale lease: signal the caller to roll the whole transaction back
        // rather than record a partial split.
        return Ok(false);
    }

    for output in minted {
        sqlx::query(
            "INSERT INTO cw_core.wallet_utxo \
               (wallet_id, tx_hash, output_index, lovelace, state, canonical, spendable_unconfirmed, source) \
             VALUES ($1, $2, $3, $4, 'available', false, false, 'change')",
        )
        .bind(wallet_id)
        .bind(output.utxo.tx_hash.as_slice())
        .bind(output_index_to_i32(output.utxo.output_index)?)
        .bind(lovelace_to_i64(output.lovelace)?)
        .execute(&mut *tx)
        .await?;
    }

    Ok(true)
}

/// A confirmed spending transaction: its id and the wallet inputs it consumed.
///
/// A confirmation is about a transaction, so the change it produced (recorded by
/// [`apply_submit_in_tx`] keyed on the spend tx id) can be promoted in lockstep with the
/// inputs the transaction spent. Carrying the spend tx id is what scopes the change
/// promotion to exactly this transaction's outputs rather than every pending change
/// in the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedSpend {
    /// The 32-byte id of the transaction that confirmed.
    pub spend_tx_hash: [u8; 32],
    /// The wallet inputs the transaction consumed (now terminal).
    pub inputs: Vec<UtxoRef>,
}

/// Promote confirmed spends in their own transaction.
///
/// Each transaction's `pending_spent` inputs become `confirmed_spent`, and the
/// change outputs that transaction produced (the `change`-sourced rows keyed on
/// its tx id) become canonical-eligible (re-evaluated against the band) and
/// spendable. Returns how many input rows were promoted across all the confirmed
/// transactions. Idempotent: a re-confirmation of an already-promoted transaction
/// promotes nothing and leaves its change as it is.
///
/// The chain confirmation path promotes in the SAME transaction as the record's
/// `confirmed` flip via [`apply_confirmed_in_tx`], so a record can never be
/// confirmed without its wallet spends advancing in lockstep. This own-transaction
/// wrapper exists for direct callers and tests.
pub async fn apply_confirmed(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    confirmed: &[ConfirmedSpend],
    config: &WalletConfig,
) -> Result<u64> {
    if confirmed.is_empty() {
        return Ok(0);
    }
    let mut tx = pool.begin().await?;
    let promoted = apply_confirmed_in_tx(&mut tx, wallet_id, confirmed, config).await?;
    tx.commit().await?;
    Ok(promoted)
}

/// Promote confirmed spends within a caller-owned transaction.
///
/// Same effect as [`apply_confirmed`], but the DML runs on the caller's
/// transaction so the wallet-state promotion commits atomically with whatever else
/// the caller is doing (the confirmation path flips the record to `confirmed` and
/// promotes the spends in one transaction, so neither can land without the other).
pub async fn apply_confirmed_in_tx(
    tx: &mut sqlx::PgConnection,
    wallet_id: Uuid,
    confirmed: &[ConfirmedSpend],
    config: &WalletConfig,
) -> Result<u64> {
    if confirmed.is_empty() {
        return Ok(0);
    }

    let band_min = lovelace_to_i64(config.band.min)?;
    let band_max = lovelace_to_i64(config.band.max)?;
    let index_cap = output_index_to_i32(MAX_CANONICAL_OUTPUT_INDEX)?;

    let mut promoted = 0u64;

    for spend in confirmed {
        // Promote each input the transaction consumed to terminal.
        for input in &spend.inputs {
            promoted += sqlx::query(
                "UPDATE cw_core.wallet_utxo \
                 SET state = 'confirmed_spent', updated_at = now() \
                 WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3 \
                   AND state = 'pending_spent'",
            )
            .bind(wallet_id)
            .bind(input.tx_hash.as_slice())
            .bind(output_index_to_i32(input.output_index)?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        }

        // The change this transaction produced becomes spendable; recompute its
        // canonical flag against the live band now that it is on chain. The change
        // rows are exactly the `change`-sourced rows whose tx id is the spend tx id,
        // so the promotion is scoped to this transaction's outputs only.
        sqlx::query(
            "UPDATE cw_core.wallet_utxo \
             SET spendable_unconfirmed = true, \
                 canonical = (output_index < $5 AND lovelace BETWEEN $3 AND $4), \
                 updated_at = now() \
             WHERE wallet_id = $1 \
               AND tx_hash = $2 \
               AND source = 'change' \
               AND state = 'available'",
        )
        .bind(wallet_id)
        .bind(spend.spend_tx_hash.as_slice())
        .bind(band_min)
        .bind(band_max)
        .bind(index_cap)
        .execute(&mut *tx)
        .await?;
    }

    Ok(promoted)
}

/// Restore an abandoned transaction's inputs from spent back to `available`
/// within a caller-owned transaction.
///
/// This is the exact inverse of [`apply_confirmed_in_tx`]'s input promotion. When
/// an attempt is provably dead (a confirmed conflicting transaction has spent one
/// of its inputs and that conflicting spend has itself reached settlement depth),
/// the inputs the dead transaction held but the winner did not consume are live
/// again on the canonical chain and must return to the spendable pool. Each named
/// reference flips from `pending_spent` or `confirmed_spent` back to `available`,
/// clearing any lease fields, so the scheduler can offer it again.
///
/// The caller passes only the dead attempt's **exclusive** inputs: a reference the
/// conflicting winner already spent stays `confirmed_spent` by the winner and must
/// never be restored, so the caller excludes it from `refs`. This function does
/// not consult any winner; it restores exactly the references it is given that are
/// still in a spent state.
///
/// Returns how many rows were actually restored. Idempotent and safe to re-run: a
/// reference already `available` (restored by a prior call, or never spent) does
/// not match the `state IN ('pending_spent','confirmed_spent')` guard and is left
/// untouched, so a second call over the same references restores nothing further.
/// A reference for a different wallet or a transaction this wallet never spent
/// matches no row and restores nothing.
pub async fn restore_inputs_in_tx(
    tx: &mut sqlx::PgConnection,
    wallet_id: Uuid,
    refs: &[UtxoRef],
) -> Result<u64> {
    let mut restored = 0u64;
    for input in refs {
        restored += sqlx::query(
            "UPDATE cw_core.wallet_utxo \
             SET state = 'available', restore_state = NULL, \
                 lease_token = NULL, lease_expires_at = NULL, updated_at = now() \
             WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3 \
               AND state IN ('pending_spent', 'confirmed_spent')",
        )
        .bind(wallet_id)
        .bind(input.tx_hash.as_slice())
        .bind(output_index_to_i32(input.output_index)?)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }
    Ok(restored)
}

/// Tombstone the change/minted outputs a reorged-out transaction produced, within
/// a caller-owned transaction.
///
/// When an attempt is abandoned its outputs never existed on the canonical chain,
/// so a `change`-sourced row keyed on the abandoned transaction's id must not stay
/// in the wallet: leaving it would let the scheduler or replenisher build on an
/// output that was rolled back. Every `change`-sourced row whose `tx_hash` is the
/// abandoned transaction's id is deleted. Snapshot-sourced rows are never touched:
/// only the locally recorded change/minted outputs this transaction produced are
/// removed, and only those keyed on its tx id.
///
/// Returns how many rows were deleted. Idempotent: a second call over the same
/// transaction id finds no remaining `change`-sourced rows and deletes nothing.
pub async fn tombstone_outputs_in_tx(
    tx: &mut sqlx::PgConnection,
    wallet_id: Uuid,
    spend_tx_hash: [u8; 32],
) -> Result<u64> {
    let deleted = sqlx::query(
        "DELETE FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND source = 'change'",
    )
    .bind(wallet_id)
    .bind(spend_tx_hash.as_slice())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    Ok(deleted)
}

/// Return `in_flight` UTxOs whose lease has expired to `available`, per wallet,
/// each under that wallet's advisory lock.
///
/// Run by the lease-reaper job. A lease expiry alone does NOT prove the builder
/// is gone: a slow build/sign/submit can outlive the lease while still holding
/// the per-wallet advisory lock and still racing to record its spend. The lock,
/// not the expiry clock, is the authority on liveness. So the reaper, per wallet
/// with an expired lease, tries to acquire that wallet's advisory lock:
///
/// - **Lock held** — a live submit is mid-flight on the wallet (it holds the lock
///   across claim -> build -> sign -> submit -> apply_submit_in_tx). The wallet is
///   alive by definition; the reaper skips it, leaving the lease intact so the live
///   submit's `apply_submit_in_tx` still fences on its own token and records the spend.
/// - **Lock free** — no builder is on the wallet, so an expired lease is genuinely
///   abandoned. The reaper takes the lock, returns the wallet's expired in-flight
///   rows to `available`, and releases.
///
/// Reaping under the same lock the submit path holds is what makes "an expired
/// lease whose builder is gone" sound: a live (merely slow) submit can never have
/// its lease reaped out from under it, so its on-wire transaction is always
/// recorded locally. Returns how many rows were reaped across all wallets.
pub async fn reap_expired_leases(pool: &sqlx::PgPool) -> Result<u64> {
    // The wallets that currently have at least one expired in-flight lease. We
    // resolve the set first, then lock-and-reap each one independently, so one
    // live (locked) wallet never blocks reaping abandoned leases on the others.
    let wallet_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT wallet_id FROM cw_core.wallet_utxo \
         WHERE state = 'in_flight' AND lease_expires_at < now()",
    )
    .fetch_all(pool)
    .await?;

    let mut reaped = 0u64;
    for wallet_id in wallet_ids {
        // A held lock means a live submit owns this wallet; skip it (it is alive
        // by definition) rather than reap a lease that is merely slow, not dead.
        let Some(lock) = super::pool::try_lock_wallet(pool, wallet_id).await? else {
            continue;
        };

        // Under the lock, re-evaluate `lease_expires_at < now()` so we never reap
        // a lease a just-finished submit replaced or a fresh claim renewed in the
        // window between the scan and the lock. An expired lease returns to its
        // rollback target, COALESCE(restore_state, 'available'): an ordinary lease to
        // `available`, a cancelling replacement's borrowed input to the reserved
        // spent state it came from, so a reaped replacement lease never frees an
        // input the still-live original holds.
        let affected = sqlx::query(
            "UPDATE cw_core.wallet_utxo \
             SET state = COALESCE(restore_state, 'available'), \
                 restore_state = NULL, lease_token = NULL, lease_expires_at = NULL, \
                 updated_at = now() \
             WHERE wallet_id = $1 AND state = 'in_flight' AND lease_expires_at < now()",
        )
        .bind(wallet_id)
        .execute(pool)
        .await?
        .rows_affected();
        reaped += affected;

        lock.release().await?;
    }
    Ok(reaped)
}

/// Count a wallet's canonical, available UTxOs.
///
/// The scheduler reads this to rank wallets and the replenisher reads it to decide
/// whether a wallet has fallen below its minimum canonical count.
pub async fn canonical_ready_count(pool: &sqlx::PgPool, wallet_id: Uuid) -> Result<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND state = 'available' AND canonical",
    )
    .bind(wallet_id)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// The queue the lease-reaper job runs on.
pub const LEASE_REAPER_QUEUE: &str = "wallet_lease_reaper";

/// The default policy for the lease-reaper queue: a singleton loop so a single
/// reaper pass runs across the deployment, on a short fixed backoff.
#[must_use]
pub fn lease_reaper_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        LEASE_REAPER_QUEUE,
        3,
        crate::runtime::Backoff::Fixed { base_secs: 15 },
        60,
    )
}

/// A source of a wallet's on-chain UTxOs, used by snapshot ingest.
///
/// Mirrors the protocol-parameter source pattern: the production case talks to a
/// keyless public provider, tests substitute an in-memory implementation so
/// ingest is exercised with no HTTP. The address it queries is the wallet's
/// stable payment address.
pub trait UtxoSource: Send + Sync {
    /// The current set of unspent outputs at `address`.
    fn address_utxos(
        &self,
        address: &str,
    ) -> impl std::future::Future<Output = Result<Vec<ObservedUtxo>>> + Send;
}

/// The Koios address-UTxO source.
///
/// Reads `/address_utxos` from a Koios gateway, decoding each output into an
/// [`ObservedUtxo`] (including whether it is pure ADA). The base URL is supplied
/// by the caller so network selection (and any operator base-URL override)
/// stays in one place; the optional API key authenticates every request as
/// `Authorization: Bearer`, matching the chain gateway and the
/// protocol-parameter source.
pub struct KoiosUtxoSource {
    client: reqwest::Client,
    base_url: String,
    /// The optional API key, a deploy-time secret wiped on drop.
    api_key: Option<Zeroizing<String>>,
}

impl KoiosUtxoSource {
    /// Build a source over a Koios base URL and an optional API key (`None`
    /// stays on the keyless public tier).
    ///
    /// Returns [`Error::ChainProvider`] if the TLS-backed client cannot be built
    /// (which only fails on a broken platform crypto backend).
    pub fn new(base_url: impl Into<String>, api_key: Option<Zeroizing<String>>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| Error::ChainProvider(format!("building HTTP client: {e}")))?;
        Ok(Self {
            client,
            base_url: base_url.into(),
            api_key,
        })
    }

    /// Build a source over a caller-provided client, base URL, and optional API
    /// key.
    #[must_use]
    pub fn with_client(
        client: reqwest::Client,
        base_url: impl Into<String>,
        api_key: Option<Zeroizing<String>>,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into(),
            api_key,
        }
    }
}

impl UtxoSource for KoiosUtxoSource {
    async fn address_utxos(&self, address: &str) -> Result<Vec<ObservedUtxo>> {
        // Koios returns one JSON row per UTxO at the address. We request only the
        // columns the state machine needs; the response carries each output's
        // origin tx id, index, lovelace value, and any native-asset list (whose
        // emptiness decides pure-ADA).
        let url = format!("{}/address_utxos", self.base_url);
        let body = serde_json::json!({ "_addresses": [address] });
        let mut request = self.client.post(&url).json(&body);
        if let Some(key) = self.api_key.as_deref() {
            request = request.bearer_auth(key);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| Error::ChainProvider(format!("POST {url}: {e}")))?
            .error_for_status()
            .map_err(|e| Error::ChainProvider(format!("POST {url}: {e}")))?;
        let rows: Vec<KoiosAddressUtxo> =
            crate::http::read_capped_json(resp, crate::http::JSON_BODY_CEILING)
                .await
                .map_err(|e| Error::ChainProvider(format!("decoding {url}: {e}")))?;
        rows.into_iter().map(ObservedUtxo::try_from).collect()
    }
}

/// One row of a Koios `/address_utxos` response, limited to the fields the state
/// machine needs.
#[derive(serde::Deserialize)]
struct KoiosAddressUtxo {
    tx_hash: String,
    tx_index: u32,
    #[serde(deserialize_with = "de_u64_lenient")]
    value: u64,
    /// The output's native assets. Koios sends an explicit JSON `null` (not an
    /// absent field) for a pure-ADA output, so the list is deserialised leniently:
    /// `null`, an absent field, and `[]` all mean no native assets.
    #[serde(default, deserialize_with = "de_vec_lenient")]
    asset_list: Vec<serde_json::Value>,
}

impl TryFrom<KoiosAddressUtxo> for ObservedUtxo {
    type Error = Error;

    fn try_from(row: KoiosAddressUtxo) -> Result<Self> {
        let raw = hex::decode(&row.tx_hash)
            .map_err(|_| Error::ChainProvider(format!("invalid utxo tx_hash: {}", row.tx_hash)))?;
        let tx_hash: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            Error::ChainProvider(format!("utxo tx_hash is not 32 bytes: {}", row.tx_hash))
        })?;
        Ok(ObservedUtxo {
            utxo: UtxoRef {
                tx_hash,
                output_index: row.tx_index,
            },
            lovelace: row.value,
            pure_ada: row.asset_list.is_empty(),
        })
    }
}

/// Deserialize a `u64` the provider may encode as a number or a quoted string.
/// Koios renders lovelace values as quoted strings to keep precision for clients
/// whose native numbers are doubles, so both forms are accepted.
fn de_u64_lenient<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    use serde::Deserialize as _;
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| D::Error::custom(format!("not a u64: {n}"))),
        serde_json::Value::String(s) => s
            .parse::<u64>()
            .map_err(|e| D::Error::custom(format!("not a u64 string: {s}: {e}"))),
        other => Err(D::Error::custom(format!(
            "expected a u64 number or string, got {other}"
        ))),
    }
}

/// Deserialize a list the provider may render as a JSON array OR as an explicit
/// `null`. Koios sends `"asset_list": null` for a pure-ADA output rather than
/// omitting the field or sending `[]`, so a plain `Vec` deserialize would fail on
/// the `null`. A `null` (and an absent field, via `#[serde(default)]`) maps to an
/// empty list; an array deserializes element-wise as usual.
fn de_vec_lenient<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    use serde::Deserialize as _;
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// The row shape `claim`'s `UPDATE ... RETURNING` reads back.
#[derive(sqlx::FromRow)]
struct ClaimedRow {
    tx_hash: Vec<u8>,
    output_index: i32,
    lovelace: i64,
    lease_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Convert a lovelace `u64` to the `i64` the `bigint` column binds expect,
/// rejecting a value too large to represent rather than wrapping it negative.
fn lovelace_to_i64(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| Error::Config(format!("lovelace value {value} does not fit in i64")))
}

/// Convert a stored `bigint` lovelace back to `u64`, rejecting a negative value
/// (the column CHECK forbids one, so this only fails on a corrupt row).
fn i64_to_lovelace(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::Config(format!("stored lovelace is negative: {value}")))
}

/// Convert an output index `u32` to the `integer` column's `i32`, rejecting a
/// value past the 32-bit signed ceiling (a real index never approaches it).
fn output_index_to_i32(index: u32) -> Result<i32> {
    i32::try_from(index)
        .map_err(|_| Error::Config(format!("output index {index} does not fit in i32")))
}

/// Convert a stored `integer` output index back to `u32`, rejecting a negative
/// value (the column CHECK forbids one).
fn i32_to_output_index(value: i32) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| Error::Config(format!("stored output index is negative: {value}")))
}

/// Convert a stored 32-byte `tx_hash` column to the fixed array, rejecting a
/// wrong length (the writers always store 32 bytes).
fn tx_hash_from_bytes(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        Error::Config(format!(
            "stored tx_hash is not 32 bytes: {} bytes",
            bytes.len()
        ))
    })
}

/// Convert a lease duration to whole seconds for `make_interval`, rejecting a
/// value past the signed-64-bit ceiling (a real lease is minutes-scale).
fn duration_to_secs(lease: std::time::Duration) -> Result<f64> {
    let secs = lease.as_secs();
    if secs == 0 {
        return Err(Error::Config(
            "the submit lease duration must be non-zero".to_string(),
        ));
    }
    // make_interval takes a double `secs`; a minutes-scale lease is far below the
    // precision boundary of f64 for whole seconds.
    Ok(secs as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::config::{LovelaceBand, Network};

    fn band() -> LovelaceBand {
        LovelaceBand {
            min: 4_000_000,
            max: 8_000_000,
            mid: 6_000_000,
        }
    }

    fn config() -> WalletConfig {
        WalletConfig {
            network: Network::Preprod,
            band: band(),
            lease: std::time::Duration::from_secs(120),
            min_canonical_count: 4,
        }
    }

    #[test]
    fn canonical_predicate_honours_band_and_index() {
        let band = band();
        let cfg = config();
        let _ = cfg;
        let at = |lovelace: u64, output_index: u32, pure_ada: bool| ObservedUtxo {
            utxo: UtxoRef {
                tx_hash: [0u8; 32],
                output_index,
            },
            lovelace,
            pure_ada,
        };
        assert!(is_canonical(&at(band.mid, 0, true), &band));
        assert!(is_canonical(&at(band.min, 23, true), &band));
        assert!(!is_canonical(
            &at(band.min, MAX_CANONICAL_OUTPUT_INDEX, true),
            &band
        ));
        assert!(!is_canonical(&at(band.min - 1, 0, true), &band));
        assert!(!is_canonical(&at(band.max + 1, 0, true), &band));
        assert!(!is_canonical(&at(band.mid, 0, false), &band));
    }

    #[test]
    fn lease_duration_rejects_zero() {
        let err =
            duration_to_secs(std::time::Duration::ZERO).expect_err("a zero lease must be rejected");
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }

    #[test]
    fn tx_hash_conversion_round_trips_and_rejects_wrong_length() {
        let bytes = [0x11u8; 32];
        assert_eq!(tx_hash_from_bytes(&bytes).unwrap(), bytes);
        assert!(tx_hash_from_bytes(&[0u8; 31]).is_err());
    }

    /// Koios renders a pure-ADA output's `asset_list` as an explicit JSON `null`
    /// (not an absent field, not `[]`) and its `value` as a quoted string. A row
    /// in that exact shape must decode, with the `null` asset list classified as
    /// pure ADA. This pins the live-response decoding the address ingest depends
    /// on: a stricter `Vec` decode would reject the `null` and the ingest would
    /// fail against the real provider.
    #[test]
    fn address_utxo_row_decodes_a_null_asset_list_as_pure_ada() {
        let json = serde_json::json!({
            "tx_hash": "55c5274ba6fe2f3317a0ad604c2f0e6e219341de8287bee2b4360124ae80eb0e",
            "tx_index": 1,
            "value": "6000000",
            "asset_list": null
        });
        let row: KoiosAddressUtxo = serde_json::from_value(json).expect("decode null asset_list");
        let observed = ObservedUtxo::try_from(row).expect("convert row");
        assert_eq!(observed.lovelace, 6_000_000, "the quoted value decodes");
        assert_eq!(observed.utxo.output_index, 1);
        assert!(
            observed.pure_ada,
            "a null asset_list is a pure-ADA output, never rejected as malformed"
        );
    }

    /// A token-bearing output (a non-empty `asset_list`) is decoded as not pure
    /// ADA, so the canonical predicate excludes it.
    #[test]
    fn address_utxo_row_with_assets_is_not_pure_ada() {
        let json = serde_json::json!({
            "tx_hash": "55c5274ba6fe2f3317a0ad604c2f0e6e219341de8287bee2b4360124ae80eb0e",
            "tx_index": 0,
            "value": 4_000_000u64,
            "asset_list": [ { "policy_id": "ab", "quantity": "1" } ]
        });
        let row: KoiosAddressUtxo = serde_json::from_value(json).expect("decode asset list");
        let observed = ObservedUtxo::try_from(row).expect("convert row");
        assert!(
            !observed.pure_ada,
            "an output carrying native assets is not pure ADA"
        );
    }

    /// An absent `asset_list` field (older provider shape) still decodes, also as
    /// pure ADA, so the lenient decode does not regress the omitted-field case.
    #[test]
    fn address_utxo_row_decodes_an_absent_asset_list_as_pure_ada() {
        let json = serde_json::json!({
            "tx_hash": "55c5274ba6fe2f3317a0ad604c2f0e6e219341de8287bee2b4360124ae80eb0e",
            "tx_index": 2,
            "value": "5000000"
        });
        let row: KoiosAddressUtxo = serde_json::from_value(json).expect("decode absent asset_list");
        let observed = ObservedUtxo::try_from(row).expect("convert row");
        assert!(
            observed.pure_ada,
            "an absent asset_list is a pure-ADA output"
        );
    }
}
