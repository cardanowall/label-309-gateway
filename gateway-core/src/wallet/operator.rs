//! Operator and operator-wallet row management.
//!
//! An operator is a tenant. A wallet is a GLOBAL on-chain identity: there is
//! exactly one row per `(network, address)`, registered and administered by one
//! operator (its `registrar_operator_id`). Registration does not confer a spend
//! scope on anyone else; who may SPEND a wallet lives in `wallet_grant` and is
//! checked through [`super::grant::authorize_spend`]. `address` is the stable
//! identity a keyring upserts against, so renaming a wallet's label never changes
//! its row identity. The lifecycle (`active -> draining -> retired`) is driven
//! through these helpers, never by ad-hoc UPDATEs, so the state transitions stay
//! in one place.
//!
//! The control-plane lifecycle transitions ([`begin_draining`], [`reactivate`])
//! carry the registrar `operator_id` and pin every UPDATE to it
//! (`operator_wallet.registrar_operator_id`), so a wallet another operator
//! registered is reported as [`ScopedTransition::NotFound`] and never touched
//! across the tenant boundary. Each transition reports the wallet's real status,
//! so a no-op on a wallet already in a terminal state is reported truthfully (a
//! `retired` wallet that is asked to drain reports `retired`, not the requested
//! target).

use pallas_addresses::{Address, Network as PallasNetwork};
use uuid::Uuid;

use super::config::Network;
use crate::ledger::account::ScopedTransition;
use crate::Result;

/// An operator (tenant) row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    /// UUIDv7 primary key.
    pub id: Uuid,
    /// Operator-facing display name.
    pub label: String,
    /// Lifecycle status.
    pub status: OperatorStatus,
}

/// An operator's lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum OperatorStatus {
    /// Eligible: its wallets may be scheduled.
    Active,
    /// Disabled: its wallets are skipped by the scheduler.
    Disabled,
}

/// An operator-wallet row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorWallet {
    /// UUIDv7 primary key.
    pub id: Uuid,
    /// The operator that registered and administers this wallet (drives the
    /// lifecycle and is always entitled to spend it). NOT the spend scope: who
    /// may spend a wallet lives in `wallet_grant`.
    pub registrar_operator_id: Uuid,
    /// Operator-facing label (renameable).
    pub label: String,
    /// Stable bech32 payment address. The wallet's global identity: exactly one
    /// row per `(network, address)`, never per operator.
    pub address: String,
    /// The network the wallet is pinned to.
    pub network: Network,
    /// Lifecycle status.
    pub status: WalletStatus,
}

/// A wallet's lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum WalletStatus {
    /// Eligible to be picked for new submits.
    Active,
    /// No new claims, but in-flight UTxOs may finish.
    Draining,
    /// Terminal: off the books for scheduling.
    Retired,
}

impl WalletStatus {
    /// The stable wire token for this status (the same lowercase string the
    /// column stores), so a route reports the row's real state rather than a
    /// hardcoded literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WalletStatus::Active => "active",
            WalletStatus::Draining => "draining",
            WalletStatus::Retired => "retired",
        }
    }
}

/// Create an operator, returning its id.
///
/// The id is a UUIDv7 minted here (time-ordered, so a B-tree index on it tracks
/// insertion order), and the row defaults to `active`. The label is free text;
/// the stable identity is the returned id. The executor is generic so the
/// insert can ride a caller's transaction (bootstrap creates the operator and
/// mints its root credential atomically) or run standalone against a pool.
pub async fn create_operator<'a, A>(executor: A, label: &str) -> Result<Uuid>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(id)
        .bind(label)
        .execute(executor)
        .await?;
    Ok(id)
}

/// Register a wallet under `registrar_operator_id`, keyed on its global
/// `(network, address)` identity.
///
/// A wallet is a global on-chain identity: there is one row per `(network,
/// address)`. A new address inserts a fresh `active` wallet registered to this
/// operator. The SAME operator re-registering its own address updates the label
/// only (a rename) and never re-activates a wallet it has drained or retired. A
/// DIFFERENT operator registering an already-registered address is rejected
/// ([`RegisterOutcome::AddressTaken`]): the address already signs one way for
/// everyone, so a second registrar cannot mint a parallel row that aliases it;
/// the right expression of a shared key is the registrar issuing an `operator`
/// grant on its wallet, not a second registration.
///
/// This is the row side of the keyring unlock and of the control-plane register
/// route; every verified keyring entry registers here.
///
/// The executor is generic over [`sqlx::Acquire`] so the register can run
/// standalone against a pool or ride a caller's transaction. The control-plane
/// register route registers the wallet, issues its spend grant, and enqueues a
/// targeted replenish on one transaction so all three commit atomically; passing
/// `&mut *tx` here makes the wallet row part of that unit.
pub async fn register_wallet<'a, A>(
    executor: A,
    registrar_operator_id: Uuid,
    label: &str,
    address: &str,
    network: Network,
) -> Result<RegisterOutcome>
where
    A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
{
    let mut txn = executor.begin().await?;

    // ON CONFLICT (network, address) keys on the wallet's global identity. The
    // DO UPDATE fires only when the conflicting row's registrar is THIS operator
    // (the `WHERE` on the conflict), so a same-operator re-register renames in
    // place while a different operator's collision updates nothing. The update
    // touches ONLY the label, never `status`, so re-running an unlock on a wallet
    // the operator has drained or retired leaves it drained/retired rather than
    // silently re-activating it.
    //
    // `xmax = 0` in the inserting transaction's snapshot distinguishes an insert
    // (no prior version, xmax 0) from a DO UPDATE (carries the updating txn's
    // xmax) in a single RETURNING. The DO UPDATE reads back the existing id, so a
    // returned id is always the wallet's persistent id. When the conflict's
    // registrar differs the `WHERE` makes the UPDATE a no-op, so the statement
    // RETURNs no row: that empty result is the "address taken" signal, which a
    // second query resolves into the registrar that holds it (for the audit).
    let candidate_id = Uuid::now_v7();
    let row = sqlx::query_as::<_, RegisteredRow>(
        "INSERT INTO cw_core.operator_wallet \
           (id, registrar_operator_id, label, address, network) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (network, address) DO UPDATE SET label = EXCLUDED.label \
         WHERE cw_core.operator_wallet.registrar_operator_id = EXCLUDED.registrar_operator_id \
         RETURNING id, (xmax = 0) AS inserted",
    )
    .bind(candidate_id)
    .bind(registrar_operator_id)
    .bind(label)
    .bind(address)
    .bind(network.as_str())
    .fetch_optional(&mut *txn)
    .await?;

    let outcome = match row {
        Some(row) => RegisterOutcome::Registered(RegisteredWallet {
            wallet_id: row.id,
            inserted: row.inserted,
        }),
        // No row returned: the address is already registered to a DIFFERENT
        // operator (the conflict's WHERE excluded the update). Read back which
        // wallet holds it so the caller can report it without a second guess.
        None => {
            let existing: Uuid = sqlx::query_scalar(
                "SELECT id FROM cw_core.operator_wallet WHERE network = $1 AND address = $2",
            )
            .bind(network.as_str())
            .bind(address)
            .fetch_one(&mut *txn)
            .await?;
            RegisterOutcome::AddressTaken {
                wallet_id: existing,
            }
        }
    };

    txn.commit().await?;
    Ok(outcome)
}

/// The row [`register_wallet`]'s `RETURNING` reads back: the persistent wallet id
/// and whether the register inserted (rather than renamed) the row.
#[derive(sqlx::FromRow)]
struct RegisteredRow {
    id: Uuid,
    inserted: bool,
}

/// A successful registration: the wallet's id and whether it is new.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredWallet {
    /// The wallet's persistent id.
    pub wallet_id: Uuid,
    /// True when this register inserted a fresh row (vs renaming an existing one).
    pub inserted: bool,
}

/// The outcome of a [`register_wallet`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// The wallet was inserted or renamed under the calling operator.
    Registered(RegisteredWallet),
    /// The address is already registered to a DIFFERENT operator; nothing was
    /// written. The caller surfaces this as a conflict, never a silent overwrite.
    AddressTaken {
        /// The id of the existing wallet that holds the address.
        wallet_id: Uuid,
    },
}

/// The outcome of a [`register_wallet_and_grant`] call: the wallet, its
/// auto-issued spend grant, and whether a targeted replenish was enqueued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterAndGrantOutcome {
    /// The wallet was registered (or renamed in place), granted the resolved scope,
    /// and a targeted replenish was enqueued so it is stocked on the next tick.
    Registered {
        /// The registered wallet's id and whether the register inserted it.
        wallet: RegisteredWallet,
        /// The id of the auto-issued (or already-live) spend grant.
        grant_id: Uuid,
    },
    /// The address is already registered to a DIFFERENT operator; nothing was
    /// written, granted, or enqueued.
    AddressTaken {
        /// The id of the existing wallet that holds the address.
        wallet_id: Uuid,
    },
    /// The wallet vanished between the register and the grant (a concurrent delete),
    /// or its account scope no longer resolves; nothing durable was committed.
    GrantUnresolved,
}

/// Register a wallet, issue its spend grant, and enqueue a targeted replenish, all
/// in one transaction so the three commit atomically (or roll back together).
///
/// Registration alone leaves a wallet with no canonical UTxOs until the periodic
/// replenish cron next ticks, so a freshly registered wallet is unspendable for up
/// to one cron interval. This makes registration TRIGGER the grooming it depends
/// on: the targeted replenish enqueued here grooms exactly the just-registered
/// wallet on the next worker tick, closing that gap.
///
/// All three writes share one transaction: the wallet row, the spend grant, and the
/// replenish enqueue commit together. If any fails the whole registration rolls back
/// rather than leaving a half-registered wallet. The enqueue is deduped on a
/// per-wallet singleton key, so a re-register or a periodic enqueue that races this
/// one is a no-op rather than a duplicate groom; the targeted pass and the periodic
/// pass are interchangeable and idempotent (the per-wallet lock and the
/// already-stocked short-circuit make a redundant pass safe).
///
/// A foreign-owned address is reported as [`RegisterAndGrantOutcome::AddressTaken`]
/// without writing anything; a grant that cannot resolve (the wallet or its scope
/// account vanished mid-transaction) is reported as
/// [`RegisterAndGrantOutcome::GrantUnresolved`] and the transaction is rolled back.
pub async fn register_wallet_and_grant(
    pool: &sqlx::PgPool,
    registrar_operator_id: Uuid,
    label: &str,
    address: &str,
    network: Network,
    scope: super::grant::GrantScope,
) -> Result<RegisterAndGrantOutcome> {
    let mut tx = pool.begin().await?;

    let registered =
        match register_wallet(&mut *tx, registrar_operator_id, label, address, network).await? {
            RegisterOutcome::Registered(r) => r,
            RegisterOutcome::AddressTaken { wallet_id } => {
                // Nothing was written; drop the transaction (rollback) and report the
                // conflict so the caller never grants or enqueues against a wallet it
                // does not administer.
                return Ok(RegisterAndGrantOutcome::AddressTaken { wallet_id });
            }
        };

    // Auto-grant the resolved scope so the common case (register and use) needs no
    // second call. Idempotent per scope subject: re-registering re-asserts the grant
    // rather than duplicating it. A None means the wallet or its scope account no
    // longer resolves under this operator, which on a just-inserted row can only be
    // a concurrent delete; roll the whole registration back rather than commit a
    // wallet with no spend authority.
    let grant_id = match super::grant::issue_grant(
        &mut *tx,
        registrar_operator_id,
        registered.wallet_id,
        scope,
    )
    .await?
    {
        Some(super::grant::IssueOutcome::Issued { grant_id })
        | Some(super::grant::IssueOutcome::AlreadyGranted { grant_id }) => grant_id,
        None => return Ok(RegisterAndGrantOutcome::GrantUnresolved),
    };

    // Enqueue the targeted replenish on the same transaction so it becomes visible
    // exactly when the wallet and grant do. The singleton key dedupes a re-register
    // or a racing periodic enqueue to a no-op; a suppressed enqueue is not an error
    // (another pass for this wallet is already in flight and will stock it).
    crate::runtime::enqueue::enqueue_dedupe(
        &mut *tx,
        super::replenish::REPLENISH_QUEUE,
        &super::replenish::TargetedReplenish {
            wallet_id: registered.wallet_id,
        },
        crate::runtime::enqueue::EnqueueOptions {
            singleton_key: Some(super::replenish::ReplenishPayload::singleton_key(
                registered.wallet_id,
            )),
            ..Default::default()
        },
    )
    .await?;

    tx.commit().await?;
    Ok(RegisterAndGrantOutcome::Registered {
        wallet: registered,
        grant_id,
    })
}

/// Begin draining a wallet registered by `operator_id`: it takes no new claims,
/// but its in-flight UTxOs may finish.
///
/// Only an `active` wallet transitions to `draining`; the call is idempotent for
/// a registered wallet already draining or retired ([`ScopedTransition::Unchanged`],
/// reporting the wallet's real status). The UPDATE is pinned to the registrar, so
/// a wallet another operator registered reports [`ScopedTransition::NotFound`]
/// and is never touched. The lifecycle is the registrar's prerogative, so it
/// keys on `registrar_operator_id`, not on any spend grant.
///
/// The executor is generic so the transition can ride the route's transaction
/// (committing atomically with its audit row) or run standalone against a pool.
pub async fn begin_draining<'a, A>(
    executor: A,
    operator_id: Uuid,
    wallet_id: Uuid,
) -> Result<ScopedTransition<WalletStatus>>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    scoped_wallet_transition(
        executor,
        operator_id,
        wallet_id,
        WalletStatus::Active,
        WalletStatus::Draining,
    )
    .await
}

/// Reactivate a draining wallet registered by `operator_id`: return it to
/// `active` so the scheduler may pick it for new submits again.
///
/// Only a `draining` wallet transitions back to `active`; a `retired` wallet is
/// terminal and is never reactivated, and an already-active wallet is an
/// idempotent no-op ([`ScopedTransition::Unchanged`], reporting the wallet's real
/// status). The UPDATE is pinned to the registrar, so a wallet another operator
/// registered reports [`ScopedTransition::NotFound`].
///
/// The executor is generic so the transition can ride the route's transaction
/// (committing atomically with its audit row) or run standalone against a pool.
pub async fn reactivate<'a, A>(
    executor: A,
    operator_id: Uuid,
    wallet_id: Uuid,
) -> Result<ScopedTransition<WalletStatus>>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    scoped_wallet_transition(
        executor,
        operator_id,
        wallet_id,
        WalletStatus::Draining,
        WalletStatus::Active,
    )
    .await
}

/// Drive a registrar-scoped `from -> to` status transition on a wallet,
/// distinguishing not-registered-by-this-operator, applied, and idempotent-no-op
/// outcomes, and reporting the wallet's real status in every owned outcome.
///
/// A single round trip: the CTE locates the operator's own (registered) wallet
/// (the existence arm, reading back its current `status`) and a conditional
/// UPDATE flips it only when it is in the `from` state. A wallet another operator
/// registered never matches the existence arm, so it is reported as absent rather
/// than acted on across the boundary. The `SELECT` returns the wallet's
/// pre-update status so an `Unchanged` outcome reports the wallet's actual state
/// (e.g. `retired`), never the requested target.
async fn scoped_wallet_transition<'a, A>(
    executor: A,
    operator_id: Uuid,
    wallet_id: Uuid,
    from: WalletStatus,
    to: WalletStatus,
) -> Result<ScopedTransition<WalletStatus>>
where
    A: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let row: Option<(bool, WalletStatus)> = sqlx::query_as(
        "WITH owned AS ( \
             SELECT id, status FROM cw_core.operator_wallet \
             WHERE id = $1 AND registrar_operator_id = $2 \
         ), \
         updated AS ( \
             UPDATE cw_core.operator_wallet w SET status = $4 \
             FROM owned \
             WHERE w.id = owned.id AND w.status = $3 \
             RETURNING w.id \
         ) \
         SELECT EXISTS (SELECT 1 FROM updated) AS changed, owned.status FROM owned",
    )
    .bind(wallet_id)
    .bind(operator_id)
    .bind(from.as_str())
    .bind(to.as_str())
    .fetch_optional(executor)
    .await?;

    Ok(match row {
        None => ScopedTransition::NotFound,
        // The UPDATE fired, so the wallet really was in `from` and now holds `to`.
        Some((true, _)) => ScopedTransition::Changed { from, to },
        // No update: report the wallet's actual current status, not the target.
        Some((false, status)) => ScopedTransition::Unchanged { status },
    })
}

/// Load a wallet by id.
pub async fn load_wallet(pool: &sqlx::PgPool, wallet_id: Uuid) -> Result<Option<OperatorWallet>> {
    let row = sqlx::query_as::<_, WalletRow>(
        "SELECT id, registrar_operator_id, label, address, network, status \
         FROM cw_core.operator_wallet WHERE id = $1",
    )
    .bind(wallet_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else { return Ok(None) };
    Ok(Some(OperatorWallet {
        id: row.id,
        registrar_operator_id: row.registrar_operator_id,
        label: row.label,
        address: row.address,
        network: Network::parse(&row.network)?,
        status: row.status,
    }))
}

/// List every active wallet whose registrar is an active operator on a network,
/// in stable id order.
///
/// This is the set the replenish job grooms: a wallet that is draining or retired,
/// or whose registrar is disabled, is off the books and never replenished.
/// Replenish is a registrar-side operation (it consolidates a wallet's own funds
/// and needs the key the registrar holds), so the active-registrar gate is the
/// right boundary; no spend grant is consulted. Ordered by id (UUIDv7, insertion
/// order) so a pass is deterministic.
pub async fn list_active_wallets(
    pool: &sqlx::PgPool,
    network: Network,
) -> Result<Vec<OperatorWallet>> {
    let rows = sqlx::query_as::<_, WalletRow>(
        "SELECT w.id, w.registrar_operator_id, w.label, w.address, w.network, w.status \
         FROM cw_core.operator_wallet w \
         JOIN cw_core.operator o ON o.id = w.registrar_operator_id \
         WHERE w.network = $1 AND w.status = 'active' AND o.status = 'active' \
         ORDER BY w.id",
    )
    .bind(network.as_str())
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(OperatorWallet {
                id: row.id,
                registrar_operator_id: row.registrar_operator_id,
                label: row.label,
                address: row.address,
                network: Network::parse(&row.network)?,
                status: row.status,
            })
        })
        .collect()
}

/// The Cardano network id a bech32 payment address encodes (1 for mainnet, 0 for
/// any test network), or `None` when the string is not a Shelley payment address.
///
/// The shared address-network check: the keyring unlock uses it to reject an
/// entry whose address belongs to a different network than the deployment's, and
/// the wallet-registration route uses it to reject a body whose address does not
/// match the requested network. The two test networks (preprod, preview) share
/// the same network id and `addr_test` HRP, so an address only distinguishes
/// mainnet from a test network; the configured network supplies the finer
/// preprod-vs-preview choice.
#[must_use]
pub fn address_network_id(address: &str) -> Option<u8> {
    let parsed = Address::from_bech32(address).ok()?;
    match parsed.network()? {
        PallasNetwork::Mainnet => Some(1),
        PallasNetwork::Testnet => Some(0),
        PallasNetwork::Other(id) => Some(id),
    }
}

/// The row [`load_wallet`] reads back. `network` is fetched as text and mapped
/// to the typed [`Network`] enum in code (the column is a CHECK-constrained text
/// rather than a Postgres enum), while `status` decodes straight through the
/// `sqlx::Type` derive on [`WalletStatus`].
#[derive(sqlx::FromRow)]
struct WalletRow {
    id: Uuid,
    registrar_operator_id: Uuid,
    label: String,
    address: String,
    network: String,
    status: WalletStatus,
}
