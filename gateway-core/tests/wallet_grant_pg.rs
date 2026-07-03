//! Integration coverage for wallet spend authority: the scope-bound signing
//! capability, the grant relation, and the pool/submit gates that consult it.
//!
//! A wallet is a global on-chain identity registered by one operator; who may
//! SPEND it is decided by `wallet_grant` (plus the always-entitled registrar and
//! the system actor). These suites drive the real `grant`, `pool`, and
//! `operator` APIs and the control router against a freshly migrated database to
//! pin the contract the rest of the engine relies on:
//!
//!   - `authorize_spend` mints a capability for the registrar, for any operator
//!     under a live service grant, and for the operator a live operator grant
//!     names; and refuses (None) an operator with no entitlement.
//!   - the signer is reachable ONLY through that capability, so a non-entitled
//!     operator gets no signer and cannot spend.
//!   - `pick_wallet` selects exactly the entitled wallets.
//!   - issuing/revoking a grant gates NEW picks; revocation does not retract a
//!     capability already minted for an in-flight settlement.
//!   - registration validates the address (bech32 + network), rejects an address
//!     already registered to another operator, and auto-grants the default scope.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Duration;
use gateway_core::api::control::credential::mint_root_credential;
use gateway_core::api::control::{
    ControlConfig, ControlState, ControlWalletKey, DefaultStorageScope, DefaultWalletScope,
};
use gateway_core::api::control_router;
use gateway_core::ledger::account::create_account;
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::Network;
use gateway_core::wallet::grant::{
    authorize_spend, issue_grant, resolve_inflight_wallet, revoke_grant, GrantScope, IssueOutcome,
    RevokeOutcome, SpendPrincipal,
};
use gateway_core::wallet::keyring::derive_enterprise_address;
use gateway_core::wallet::operator::{create_operator, register_wallet, RegisterOutcome};
use gateway_core::wallet::pool::pick_wallet;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

/// The operator-chosen secret prefix the control plane mints credentials under.
const PREFIX: &str = "ctl_";

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// A real preprod enterprise bech32 address derived from a seed, so each wallet
/// has a distinct, validly-encoded global identity.
fn preprod_address(seed: u8) -> String {
    let key = pallas_crypto::key::ed25519::SecretKey::from([seed; 32]);
    let vk = {
        let pk = key.public_key();
        let mut out = [0u8; 32];
        out.copy_from_slice(pk.as_ref());
        out
    };
    derive_enterprise_address(&vk, Network::Preprod).expect("derive preprod address")
}

/// Register a wallet under an operator and return its id, panicking on a
/// collision (each test uses distinct addresses).
async fn register(pool: &sqlx::PgPool, operator_id: Uuid, seed: u8) -> Uuid {
    match register_wallet(
        pool,
        operator_id,
        "primary",
        &preprod_address(seed),
        Network::Preprod,
    )
    .await
    .expect("register wallet")
    {
        RegisterOutcome::Registered(r) => r.wallet_id,
        RegisterOutcome::AddressTaken { .. } => panic!("a fresh address must register"),
    }
}

/// Seed one canonical, available UTxO on a wallet so `pick_wallet` finds it ready.
async fn seed_canonical_utxo(pool: &sqlx::PgPool, wallet_id: Uuid, byte: u8) {
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, 0, 6000000, 'available', true, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(vec![byte; 32])
    .execute(pool)
    .await
    .expect("seed canonical utxo");
}

// ---------------------------------------------------------------------------
// (a) Scope-bound signing: entitlement is required, and the registrar/service
//     paths grant it.
// ---------------------------------------------------------------------------

/// The registrar of a wallet is ALWAYS entitled to spend it, even with no grant
/// row at all: `authorize_spend` mints a capability carrying the wallet's id and
/// verified address.
#[tokio::test]
async fn the_registrar_is_always_entitled_without_any_grant() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x01).await;

    let authorized = authorize_spend(
        &db.pool,
        wallet_id,
        SpendPrincipal::Operator {
            operator_id: registrar,
        },
    )
    .await
    .expect("authorize")
    .expect("the registrar is entitled to its own wallet");
    assert_eq!(authorized.wallet_id(), wallet_id);
    assert_eq!(authorized.address(), preprod_address(0x01));
}

/// An operator that is NOT the registrar and holds no grant is NOT entitled:
/// `authorize_spend` returns None, so no capability (and therefore no signer) can
/// be obtained for that wallet.
#[tokio::test]
async fn a_non_entitled_operator_cannot_authorize_a_wallet() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let stranger = create_operator(&db.pool, "stranger")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x02).await;

    // No grant entitles the stranger, and it is not the registrar.
    let authorized = authorize_spend(
        &db.pool,
        wallet_id,
        SpendPrincipal::Operator {
            operator_id: stranger,
        },
    )
    .await
    .expect("authorize");
    assert!(
        authorized.is_none(),
        "an operator with no grant and not the registrar must not be authorized"
    );
}

/// A live SERVICE grant entitles ANY operator to spend the wallet: a stranger
/// becomes authorized once the service grant exists (the single-tenant default).
#[tokio::test]
async fn a_service_grant_entitles_any_operator() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let stranger = create_operator(&db.pool, "stranger")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x03).await;

    // Before the grant, the stranger is not entitled.
    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Operator {
                operator_id: stranger
            },
        )
        .await
        .expect("authorize")
        .is_none(),
        "no service grant yet, so the stranger is not entitled"
    );

    // The registrar issues a service grant.
    assert!(matches!(
        issue_grant(&db.pool, registrar, wallet_id, GrantScope::Service)
            .await
            .expect("issue"),
        Some(IssueOutcome::Issued { .. })
    ));

    // Now any operator is entitled.
    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Operator {
                operator_id: stranger
            },
        )
        .await
        .expect("authorize")
        .is_some(),
        "a live service grant entitles every operator"
    );
}

/// A live OPERATOR grant entitles only the named operator, not a third party.
#[tokio::test]
async fn an_operator_grant_entitles_only_its_named_operator() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let grantee = create_operator(&db.pool, "grantee")
        .await
        .expect("operator");
    let third = create_operator(&db.pool, "third").await.expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x04).await;

    issue_grant(
        &db.pool,
        registrar,
        wallet_id,
        GrantScope::Operator {
            operator_id: grantee,
        },
    )
    .await
    .expect("issue")
    .expect("registrar may grant on its own wallet");

    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Operator {
                operator_id: grantee
            },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the named grantee is entitled"
    );
    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Operator { operator_id: third },
        )
        .await
        .expect("authorize")
        .is_none(),
        "a third operator is not entitled by an operator grant for someone else"
    );
}

/// The SYSTEM principal is entitled to any wallet (its authority is key
/// possession, not a grant): replenish signs through this path.
#[tokio::test]
async fn the_system_principal_is_always_entitled() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x05).await;

    assert!(
        authorize_spend(&db.pool, wallet_id, SpendPrincipal::System)
            .await
            .expect("authorize")
            .is_some(),
        "the system actor is entitled to spend any wallet (key possession)"
    );

    // An unknown wallet is still None even for the system actor.
    assert!(
        authorize_spend(&db.pool, Uuid::now_v7(), SpendPrincipal::System)
            .await
            .expect("authorize")
            .is_none(),
        "a missing wallet authorizes to None even for the system actor"
    );
}

// ---------------------------------------------------------------------------
// pick_wallet honours the entitlement set.
// ---------------------------------------------------------------------------

/// `pick_wallet` returns a wallet for its registrar (no grant needed) and for an
/// operator a service grant entitles, but never for a non-entitled stranger.
#[tokio::test]
async fn pick_wallet_selects_only_entitled_wallets() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let stranger = create_operator(&db.pool, "stranger")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x06).await;
    seed_canonical_utxo(&db.pool, wallet_id, 0xA0).await;

    // The registrar picks its own wallet.
    let picked = pick_wallet(&db.pool, registrar, Network::Preprod)
        .await
        .expect("pick")
        .expect("the registrar is entitled and the wallet is ready");
    assert_eq!(picked.wallet_id, wallet_id);

    // The stranger picks nothing (no entitlement).
    assert!(
        pick_wallet(&db.pool, stranger, Network::Preprod)
            .await
            .expect("pick")
            .is_none(),
        "a non-entitled operator picks no wallet"
    );

    // A service grant makes the stranger able to pick the same wallet.
    issue_grant(&db.pool, registrar, wallet_id, GrantScope::Service)
        .await
        .expect("issue")
        .expect("registrar grants");
    let picked = pick_wallet(&db.pool, stranger, Network::Preprod)
        .await
        .expect("pick")
        .expect("a service grant entitles the stranger");
    assert_eq!(picked.wallet_id, wallet_id);
}

// ---------------------------------------------------------------------------
// (c) Grant issue/revoke; revocation gates new picks but not an in-flight
//     capability.
// ---------------------------------------------------------------------------

/// Issuing the same grant twice is idempotent, and revoking it gates a fresh
/// pick. Critically, a capability already minted (the in-flight settlement) keeps
/// working after revocation: revocation gates NEW picks only.
#[tokio::test]
async fn revocation_gates_new_picks_but_not_an_inflight_capability() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let grantee = create_operator(&db.pool, "grantee")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x07).await;
    seed_canonical_utxo(&db.pool, wallet_id, 0xB0).await;

    // Issue an operator grant; re-issuing is an idempotent no-op pointing at the
    // same row.
    let first = issue_grant(
        &db.pool,
        registrar,
        wallet_id,
        GrantScope::Operator {
            operator_id: grantee,
        },
    )
    .await
    .expect("issue")
    .expect("granted");
    let grant_id = match first {
        IssueOutcome::Issued { grant_id } => grant_id,
        IssueOutcome::AlreadyGranted { .. } => panic!("the first issue inserts"),
    };
    let again = issue_grant(
        &db.pool,
        registrar,
        wallet_id,
        GrantScope::Operator {
            operator_id: grantee,
        },
    )
    .await
    .expect("issue again")
    .expect("granted");
    assert_eq!(
        again,
        IssueOutcome::AlreadyGranted { grant_id },
        "re-issuing a live grant is idempotent, not a duplicate"
    );

    // The grantee can authorize and pick now.
    let principal = SpendPrincipal::Operator {
        operator_id: grantee,
    };
    let inflight = authorize_spend(&db.pool, wallet_id, principal)
        .await
        .expect("authorize")
        .expect("the grantee is entitled while the grant is live");
    assert!(
        pick_wallet(&db.pool, grantee, Network::Preprod)
            .await
            .expect("pick")
            .is_some(),
        "the grantee can pick the wallet while the grant is live"
    );

    // Revoke the grant.
    assert_eq!(
        revoke_grant(&db.pool, registrar, wallet_id, grant_id)
            .await
            .expect("revoke")
            .expect("the registrar may revoke its own wallet's grant"),
        RevokeOutcome::Revoked
    );
    // Revoking again is an idempotent no-op.
    assert_eq!(
        revoke_grant(&db.pool, registrar, wallet_id, grant_id)
            .await
            .expect("revoke again")
            .expect("still the registrar's grant"),
        RevokeOutcome::AlreadyRevoked
    );

    // A FRESH authorization/pick by the grantee is now refused: revocation gates
    // new picks.
    assert!(
        authorize_spend(&db.pool, wallet_id, principal)
            .await
            .expect("authorize")
            .is_none(),
        "a revoked grant no longer entitles a fresh authorization"
    );
    assert!(
        pick_wallet(&db.pool, grantee, Network::Preprod)
            .await
            .expect("pick")
            .is_none(),
        "a revoked grant no longer lets the grantee pick the wallet"
    );

    // The capability minted BEFORE revocation is still a valid token: an in-flight
    // settlement keys on the wallet id and finishes regardless. The capability
    // still resolves a signer address (the keyring lookup is not re-gated).
    assert_eq!(
        inflight.wallet_id(),
        wallet_id,
        "the in-flight capability keeps its wallet binding after revocation"
    );
    assert_eq!(inflight.address(), preprod_address(0x07));
}

/// Concurrent duplicate issues of the SAME grant subject are atomically
/// idempotent: exactly one inserts, the rest report `AlreadyGranted` pointing at
/// that one row, and at most one live grant of the subject exists. None of the
/// racers surfaces a raw unique-violation error. This pins the `ON CONFLICT`
/// idempotency boundary against the live-grant partial unique index.
#[tokio::test]
async fn concurrent_duplicate_issues_are_atomically_idempotent() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let grantee = create_operator(&db.pool, "grantee")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x09).await;

    // Fire several issues of the same operator-grant subject at once.
    const RACERS: usize = 8;
    let mut handles = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let pool = db.pool.clone();
        handles.push(tokio::spawn(async move {
            issue_grant(
                &pool,
                registrar,
                wallet_id,
                GrantScope::Operator {
                    operator_id: grantee,
                },
            )
            .await
        }));
    }

    let mut issued_ids = std::collections::HashSet::new();
    let mut already_ids = std::collections::HashSet::new();
    for handle in handles {
        // No racer errors out: a duplicate is reported, never surfaced as a raw
        // unique violation.
        let outcome = handle
            .await
            .expect("issue task joins")
            .expect("issue never errors under a duplicate race")
            .expect("the registrar may grant on its own wallet");
        match outcome {
            IssueOutcome::Issued { grant_id } => {
                issued_ids.insert(grant_id);
            }
            IssueOutcome::AlreadyGranted { grant_id } => {
                already_ids.insert(grant_id);
            }
        }
    }

    // Exactly one racer inserted; every reported id (Issued or AlreadyGranted)
    // names the same single live row.
    assert_eq!(
        issued_ids.len(),
        1,
        "exactly one concurrent issue inserts the live grant"
    );
    let winner = *issued_ids.iter().next().unwrap();
    for id in &already_ids {
        assert_eq!(
            *id, winner,
            "every AlreadyGranted points at the one inserted row"
        );
    }

    // The schema holds exactly one live grant of this subject.
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_grant \
         WHERE wallet_id = $1 AND scope_kind = 'operator' AND operator_id = $2 \
           AND revoked_at IS NULL",
    )
    .bind(wallet_id)
    .bind(grantee)
    .fetch_one(&db.pool)
    .await
    .expect("count live grants");
    assert_eq!(
        live, 1,
        "the partial unique index keeps a single live grant"
    );

    // And it actually entitles the grantee.
    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Operator {
                operator_id: grantee
            },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the single live grant entitles the named grantee"
    );
}

/// Only the wallet's registrar may issue or revoke grants on it: a stranger's
/// attempt is reported as not-found (no cross-tenant existence oracle), and a
/// grant on a foreign wallet cannot be revoked by a non-registrar.
#[tokio::test]
async fn only_the_registrar_may_administer_grants() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let stranger = create_operator(&db.pool, "stranger")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x08).await;

    // A stranger cannot issue a grant on a wallet it does not administer.
    assert!(
        issue_grant(&db.pool, stranger, wallet_id, GrantScope::Service)
            .await
            .expect("issue")
            .is_none(),
        "a non-registrar cannot grant on another operator's wallet"
    );

    // The registrar issues a service grant, then a stranger cannot revoke it.
    let issued = issue_grant(&db.pool, registrar, wallet_id, GrantScope::Service)
        .await
        .expect("issue")
        .expect("registrar grants");
    let grant_id = match issued {
        IssueOutcome::Issued { grant_id } => grant_id,
        IssueOutcome::AlreadyGranted { .. } => unreachable!(),
    };
    assert!(
        revoke_grant(&db.pool, stranger, wallet_id, grant_id)
            .await
            .expect("revoke")
            .is_none(),
        "a non-registrar cannot revoke a grant on another operator's wallet"
    );
    // The grant is still live (the stranger's revoke was a no-op): the service
    // grant still entitles an arbitrary operator.
    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Operator {
                operator_id: stranger
            },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the foreign revoke did not retract the live service grant"
    );
}

// ---------------------------------------------------------------------------
// Revocation is forward-looking; it takes no lock.
//
// A new spend re-checks entitlement with `authorize_spend` under the per-wallet
// advisory lock (in `submit_locked`) before signing; a spend that has already
// passed that check holds the wallet lock and completes. The per-wallet lock
// bounds in-flight spends to at most one per wallet. `revoke_grant` is a plain
// committed UPDATE and takes NO lock: a spend authorizing AFTER the revoke commits
// reads the stamped revocation and is refused, while an already-authorized
// in-flight capability still resolves a signer. No unentitled spend can ever sign.
// ---------------------------------------------------------------------------

/// A fresh `authorize_spend` whose entitlement query runs AFTER a committed
/// revoke is refused (`None`): read-committed visibility means the post-revoke
/// authorize observes the stamped `revoked_at`, so no spend can authorize against
/// a grant whose revocation already committed. This is the forward-looking
/// guarantee that replaces the old lock-serialized ordering.
#[tokio::test]
async fn authorize_after_a_committed_revoke_is_refused() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let grantee = create_operator(&db.pool, "grantee")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x50).await;
    let principal = SpendPrincipal::Operator {
        operator_id: grantee,
    };

    // A live operator grant entitles the grantee.
    let grant_id = match issue_grant(
        &db.pool,
        registrar,
        wallet_id,
        GrantScope::Operator {
            operator_id: grantee,
        },
    )
    .await
    .expect("issue")
    .expect("granted")
    {
        IssueOutcome::Issued { grant_id } => grant_id,
        IssueOutcome::AlreadyGranted { .. } => panic!("the first issue inserts"),
    };

    // Before the revoke the grantee authorizes.
    assert!(
        authorize_spend(&db.pool, wallet_id, principal)
            .await
            .expect("authorize")
            .is_some(),
        "the grantee is entitled while the grant is live"
    );

    // Revoke as a plain committed UPDATE (no lock taken).
    assert_eq!(
        revoke_grant(&db.pool, registrar, wallet_id, grant_id)
            .await
            .expect("revoke")
            .expect("the registrar may revoke its own wallet's grant"),
        RevokeOutcome::Revoked
    );

    // A spend whose authorize_spend runs AFTER the revoke committed is refused: the
    // entitlement query observes the revocation under read-committed visibility.
    assert!(
        authorize_spend(&db.pool, wallet_id, principal)
            .await
            .expect("authorize")
            .is_none(),
        "an authorization that runs after the revoke commits is refused"
    );
}

/// An [`AuthorizedWallet`] obtained BEFORE the revoke (already authorized) stays
/// usable: it keeps its wallet binding and verified address, so an already-checked
/// in-flight spend completes even though a concurrent revoke committed. Revocation
/// gates the NEXT authorize, never an already-minted capability.
#[tokio::test]
async fn an_authorized_capability_obtained_before_revoke_stays_usable() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let grantee = create_operator(&db.pool, "grantee")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x53).await;
    let principal = SpendPrincipal::Operator {
        operator_id: grantee,
    };

    let grant_id = match issue_grant(
        &db.pool,
        registrar,
        wallet_id,
        GrantScope::Operator {
            operator_id: grantee,
        },
    )
    .await
    .expect("issue")
    .expect("granted")
    {
        IssueOutcome::Issued { grant_id } => grant_id,
        IssueOutcome::AlreadyGranted { .. } => panic!("the first issue inserts"),
    };

    // The grantee authorizes BEFORE the revoke: this capability is the
    // already-authorized in-flight spend.
    let authorized = authorize_spend(&db.pool, wallet_id, principal)
        .await
        .expect("authorize")
        .expect("the grantee is entitled while the grant is live");

    // The registrar revokes concurrently (a plain committed UPDATE, no lock).
    assert_eq!(
        revoke_grant(&db.pool, registrar, wallet_id, grant_id)
            .await
            .expect("revoke")
            .expect("registrar revokes"),
        RevokeOutcome::Revoked
    );

    // The already-minted capability is unaffected: it still carries the wallet's
    // id and verified address, so the in-flight spend completes (it was entitled
    // when it was authorized).
    assert_eq!(
        authorized.wallet_id(),
        wallet_id,
        "the capability keeps its wallet binding after a concurrent revoke"
    );
    assert_eq!(authorized.address(), preprod_address(0x53));

    // But a FRESH authorize is now refused: revocation is forward-looking.
    assert!(
        authorize_spend(&db.pool, wallet_id, principal)
            .await
            .expect("authorize")
            .is_none(),
        "a fresh authorization after the revoke is refused"
    );
}

/// Revocation never blocks an in-flight SETTLEMENT: `resolve_inflight_wallet`
/// keys strictly on the wallet id with no entitlement check, so a wallet whose
/// only grant is revoked still settles its already-authorized in-flight
/// transaction. (The grantee was entitled solely by the now-revoked grant, so a
/// fresh `authorize_spend` is refused, proving the settlement path is the only
/// thing that still resolves.)
#[tokio::test]
async fn revocation_does_not_block_inflight_settlement() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let grantee = create_operator(&db.pool, "grantee")
        .await
        .expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x51).await;
    let principal = SpendPrincipal::Operator {
        operator_id: grantee,
    };

    let grant_id = match issue_grant(
        &db.pool,
        registrar,
        wallet_id,
        GrantScope::Operator {
            operator_id: grantee,
        },
    )
    .await
    .expect("issue")
    .expect("granted")
    {
        IssueOutcome::Issued { grant_id } => grant_id,
        IssueOutcome::AlreadyGranted { .. } => panic!("the first issue inserts"),
    };

    // Revoke the only grant entitling the grantee.
    assert_eq!(
        revoke_grant(&db.pool, registrar, wallet_id, grant_id)
            .await
            .expect("revoke")
            .expect("registrar revokes"),
        RevokeOutcome::Revoked
    );

    // A NEW spend by the grantee is refused (its grant is gone).
    assert!(
        authorize_spend(&db.pool, wallet_id, principal)
            .await
            .expect("authorize")
            .is_none(),
        "the grantee's new spend is refused after revocation"
    );

    // But the in-flight settlement path still resolves the wallet by id: a reorg
    // rollback's cancelling replacement must settle the original wallet's UTxOs
    // even though the grant is gone.
    let settled = resolve_inflight_wallet(&db.pool, wallet_id, Network::Preprod.as_str())
        .await
        .expect("resolve inflight")
        .expect("settlement resolves by wallet id regardless of grants");
    assert_eq!(settled.wallet_id(), wallet_id);
    assert_eq!(settled.address(), preprod_address(0x51));
}

// ---------------------------------------------------------------------------
// Account-scope ownership is enforced in the engine, not only the route.
// ---------------------------------------------------------------------------

/// `issue_grant` refuses an account-scope grant for an account the operator does
/// not own, at the ENGINE level: ownership lives in the function signature, so a
/// caller that reaches `issue_grant` directly (bypassing the route's own check)
/// still cannot entitle a foreign account to spend its wallet. A foreign/absent
/// account reports None (the missing-wallet shape, no cross-tenant oracle), and
/// no grant row is written.
#[tokio::test]
async fn issue_grant_engine_refuses_an_account_the_operator_does_not_own() {
    let db = TestDb::fresh().await.expect("fresh db");
    let registrar = create_operator(&db.pool, "registrar")
        .await
        .expect("operator");
    let other_operator = create_operator(&db.pool, "other").await.expect("operator");
    let wallet_id = register(&db.pool, registrar, 0x52).await;

    // An account owned by a DIFFERENT operator.
    let foreign_account = create_account(&db.pool, other_operator)
        .await
        .expect("create foreign account");

    // The registrar tries to grant its wallet to that foreign account directly
    // through the engine. It is refused (None), even though the registrar owns the
    // wallet: the account is not its own.
    let outcome = issue_grant(
        &db.pool,
        registrar,
        wallet_id,
        GrantScope::Account {
            account_id: foreign_account,
        },
    )
    .await
    .expect("issue");
    assert!(
        outcome.is_none(),
        "an account grant for an account the operator does not own is refused in the engine"
    );

    // No grant row was written for that subject.
    let written: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_grant \
         WHERE wallet_id = $1 AND scope_kind = 'account' AND account_id = $2",
    )
    .bind(wallet_id)
    .bind(foreign_account)
    .fetch_one(&db.pool)
    .await
    .expect("count account grants");
    assert_eq!(written, 0, "the refused account grant wrote no row");

    // An account the registrar DOES own is granted normally, proving the check
    // gates only the cross-tenant case.
    let own_account = create_account(&db.pool, registrar)
        .await
        .expect("create own account");
    assert!(
        matches!(
            issue_grant(
                &db.pool,
                registrar,
                wallet_id,
                GrantScope::Account {
                    account_id: own_account,
                },
            )
            .await
            .expect("issue")
            .expect("the registrar may grant its own account"),
            IssueOutcome::Issued { .. }
        ),
        "an account the operator owns is granted normally"
    );
    // And that grant entitles a record submitting under that account.
    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Account {
                operator_id: registrar,
                account_id: own_account,
            },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the account grant entitles a spend under that account"
    );
}

// ---------------------------------------------------------------------------
// (d) Registration address validation + global-identity rejection, driven
//     through the real control router.
// ---------------------------------------------------------------------------

/// Build the control router state declaring the instance holds the wallet signing
/// keys for the seeds the registration suites register, so the wallet-register
/// route can confirm possession. The register route refuses any address the
/// instance does not physically hold a signer for, so each happy-path seed is
/// declared held; a seed left out of this set models an unsignable address.
fn control_state(pool: sqlx::PgPool) -> ControlState {
    let wallet_keys = HELD_WALLET_SEEDS
        .iter()
        .map(|&seed| ControlWalletKey {
            address: preprod_address(seed),
            label: format!("held-{seed:#04x}"),
        })
        .collect();
    ControlState::with_keys(
        pool,
        ControlConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            secret_prefix: PREFIX.to_string(),
            operator_token_ttl: Duration::hours(1),
            account_token_ttl: Duration::hours(1),
            adjustment_cap_usd_micros: 10_000_000_000,
            admin_ui_enabled: false,
            default_wallet_scope: DefaultWalletScope::Service,
            default_storage_scope: DefaultStorageScope::Service,
            ..Default::default()
        },
        wallet_keys,
        Vec::new(),
    )
}

/// The seeds whose derived preprod addresses the test instance declares it holds a
/// signing key for. Every registration happy path in this file uses one of these;
/// a seed deliberately absent (see [`a_register_for_an_unheld_address_is_refused`])
/// models an address no instance signer backs.
const HELD_WALLET_SEEDS: &[u8] = &[0x10, 0x20, 0x30, 0x40, 0x50];

/// Issue a control request and return (status, body json).
async fn call(
    router: &axum::Router,
    method: &str,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {bearer}"));
    let req = if let Some(b) = body {
        req = req.header("content-type", "application/json");
        req.body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        req.body(Body::empty()).unwrap()
    };
    let resp = router.clone().oneshot(req).await.expect("router responds");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

/// One operator with the two credentials its routes need: a root secret and an
/// operator token minted from it.
struct Tenant {
    operator_id: Uuid,
    operator_token: String,
    /// The operator root credential secret. Wallet registration binds a
    /// shared-keyring key to an owner, so it is a root-only (instance-admin)
    /// action; the operator token authorizes everything else (list, drain, grant,
    /// revoke).
    root_secret: String,
}

/// Provision an operator with a root credential and an operator token minted from
/// it.
async fn provision_tenant(router: &axum::Router, pool: &sqlx::PgPool, label: &str) -> Tenant {
    // The wallet-register route enqueues a targeted replenish in the same
    // transaction as the wallet row and its grant; the enqueue resolves its
    // attempt/backoff defaults from the replenish queue policy, so that policy must
    // exist before a register can run. The supervised runtime reconciles it at
    // startup in production; this suite registers wallets without booting the
    // runtime, so it seeds the policy here (idempotent per call).
    gateway_core::runtime::policy::reconcile(
        pool,
        &gateway_core::wallet::replenish::replenish_policy(),
    )
    .await
    .expect("reconcile replenish policy");

    let operator_id = create_operator(pool, label).await.expect("operator");
    let root = mint_root_credential(pool, operator_id, PREFIX, None)
        .await
        .expect("mint root");
    let (status, body) = call(
        router,
        "POST",
        "/control/v1/operator/token",
        &root.secret,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    Tenant {
        operator_id,
        operator_token: body["token"].as_str().unwrap().to_string(),
        root_secret: root.secret,
    }
}

/// Registration rejects a malformed address and a network mismatch with 422, and
/// accepts a valid preprod address with 201.
#[tokio::test]
async fn registration_validates_the_address_and_network() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "op").await;

    // A non-bech32 address is a 422.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &a.root_secret,
        Some(json!({ "label": "w", "address": "not-an-address", "network": "preprod" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "validation-failed");

    // A mainnet address under a preprod registration is a network mismatch (422):
    // a mainnet enterprise address carries network id 1, the request asks preprod.
    let mainnet_addr = {
        let key = pallas_crypto::key::ed25519::SecretKey::from([0x77u8; 32]);
        let vk = {
            let pk = key.public_key();
            let mut out = [0u8; 32];
            out.copy_from_slice(pk.as_ref());
            out
        };
        derive_enterprise_address(&vk, Network::Mainnet).expect("derive mainnet address")
    };
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &a.root_secret,
        Some(json!({ "label": "w", "address": mainnet_addr, "network": "preprod" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "validation-failed");

    // A valid preprod address registers.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &a.root_secret,
        Some(json!({ "label": "w", "address": preprod_address(0x10), "network": "preprod" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["created"], true);
}

/// A second operator registering an already-registered address is a 409, and the
/// register auto-grants the configured default scope (service) so the wallet is
/// immediately spendable by any operator.
#[tokio::test]
async fn registration_rejects_a_taken_address_and_auto_grants_the_default_scope() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let b = provision_tenant(&router, &db.pool, "b").await;

    let address = preprod_address(0x20);

    // A registers the address under its root; the default scope is `service`, so the
    // auto-grant makes it spendable by any operator (here, B).
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &a.root_secret,
        Some(json!({ "label": "w", "address": address, "network": "preprod" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let wallet_id = Uuid::parse_str(body["wallet_id"].as_str().unwrap()).unwrap();
    // The register response carries the auto-issued grant id (mirrors the storage
    // source register response), so the caller can revoke it without a list call.
    let auto_grant_id = body["grant_id"]
        .as_str()
        .expect("the wallet register response returns the auto-issued grant id")
        .to_string();
    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Operator {
                operator_id: b.operator_id
            },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the default service auto-grant makes the wallet spendable by another operator"
    );

    // Revoking exactly the returned grant id drops the spendability, proving the id
    // the register response handed back is the live auto-grant.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{wallet_id}/grants/{auto_grant_id}/revoke"),
        &a.operator_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], true);
    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Operator {
                operator_id: b.operator_id
            },
        )
        .await
        .expect("authorize")
        .is_none(),
        "revoking the auto-issued grant the register response returned removes the entitlement"
    );

    // Re-register the same address to restore the auto-grant for the conflict check
    // below (re-registration re-asserts the grant idempotently).
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &a.root_secret,
        Some(json!({ "label": "w", "address": address, "network": "preprod" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // B re-registering the SAME address (even under B's own root) is a 409: a global
    // identity cannot be re-registered by a second tenant. Root gates WHO may
    // register a key; it does not let one operator's root claim a key another already
    // owns.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &b.root_secret,
        Some(json!({ "label": "w2", "address": address, "network": "preprod" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "address-already-registered");
}

/// Registering with `scope: operator` pins the wallet to its registrar: another
/// operator is NOT entitled (no service auto-grant), proving the
/// `default_wallet_scope` override per call works.
#[tokio::test]
async fn registration_with_operator_scope_pins_the_wallet_to_the_registrar() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let stranger = create_operator(&db.pool, "stranger")
        .await
        .expect("operator");

    // The registration pins the wallet to the registering operator (`a`), so the
    // grant scope follows `a` even though the route is reached with `a`'s root.
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &a.root_secret,
        Some(json!({
            "label": "w",
            "address": preprod_address(0x30),
            "network": "preprod",
            "scope": "operator",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let wallet_id = Uuid::parse_str(body["wallet_id"].as_str().unwrap()).unwrap();

    // The registrar is entitled; a stranger is not (operator scope, no service
    // grant).
    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Operator {
                operator_id: a.operator_id
            },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the registrar is entitled to its operator-scoped wallet"
    );
    assert!(
        authorize_spend(
            &db.pool,
            wallet_id,
            SpendPrincipal::Operator {
                operator_id: stranger
            },
        )
        .await
        .expect("authorize")
        .is_none(),
        "an operator-scoped wallet is not spendable by a stranger"
    );
}

/// The grant management routes are reachable through the control router: issuing
/// and revoking a service grant changes the spend entitlement end to end.
#[tokio::test]
async fn the_grant_routes_issue_and_revoke_end_to_end() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let stranger = create_operator(&db.pool, "stranger")
        .await
        .expect("operator");

    // A registers an operator-scoped wallet under its root (so the stranger starts
    // non-entitled).
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &a.root_secret,
        Some(json!({
            "label": "w",
            "address": preprod_address(0x40),
            "network": "preprod",
            "scope": "operator",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let wallet_id = body["wallet_id"].as_str().unwrap().to_string();
    let wallet_uuid = Uuid::parse_str(&wallet_id).unwrap();
    let stranger_principal = SpendPrincipal::Operator {
        operator_id: stranger,
    };
    assert!(
        authorize_spend(&db.pool, wallet_uuid, stranger_principal)
            .await
            .expect("authorize")
            .is_none(),
        "the stranger starts non-entitled"
    );

    // Issue a service grant through the route (grant management stays
    // operator-scoped: the owner administers grants with its operator token).
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{wallet_id}/grants"),
        &a.operator_token,
        Some(json!({ "scope": "service" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["issued"], true);
    let grant_id = body["grant_id"].as_str().unwrap().to_string();
    assert!(
        authorize_spend(&db.pool, wallet_uuid, stranger_principal)
            .await
            .expect("authorize")
            .is_some(),
        "the service grant entitles the stranger"
    );

    // Revoke it through the route.
    let (status, body) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{wallet_id}/grants/{grant_id}/revoke"),
        &a.operator_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], true);
    assert!(
        authorize_spend(&db.pool, wallet_uuid, stranger_principal)
            .await
            .expect("authorize")
            .is_none(),
        "after revoke the stranger is no longer entitled"
    );

    // A stranger token cannot issue a grant on A's wallet: it is a 404 (the wallet
    // is invisible across the registrar boundary).
    let s = provision_tenant(&router, &db.pool, "s").await;
    let (status, _) = call(
        &router,
        "POST",
        &format!("/control/v1/wallets/{wallet_id}/grants"),
        &s.operator_token,
        Some(json!({ "scope": "service" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a non-registrar cannot issue a grant on another operator's wallet"
    );
}

/// Registration is a root-only action: an ordinary operator token is refused with a
/// 403 and writes no row (it shares custody of the keyring key but may not claim
/// ownership), no credential is a 401, and the operator root succeeds.
#[tokio::test]
async fn register_requires_root() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;
    let address = preprod_address(0x50);

    // An operator token (not root) is refused: it shares custody of the shared
    // keyring but may not claim a wallet key as its own.
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &a.operator_token,
        Some(json!({ "label": "w", "address": address, "network": "preprod" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an operator token may not register a wallet"
    );

    // No wallet row was written by the refused operator-token registration.
    assert_eq!(
        count_wallets(&db.pool).await,
        0,
        "a refused registration writes no wallet row"
    );

    // No credential at all is a 401.
    let (status, _) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        "",
        Some(json!({ "label": "w", "address": address, "network": "preprod" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        count_wallets(&db.pool).await,
        0,
        "an unauthenticated registration writes no wallet row"
    );

    // The operator root succeeds at the held address (the happy path under the
    // corrected auth posture).
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &a.root_secret,
        Some(json!({ "label": "ok", "address": address, "network": "preprod" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "root may register, body = {body}"
    );
    assert_eq!(count_wallets(&db.pool).await, 1);
}

/// A register naming an address the instance does NOT hold a signing key for is a
/// 422, and no wallet row is written: a registered-but-unsignable wallet would be
/// auto-granted, ingest externally-funded UTxOs, and be pickable by the scheduler,
/// only for every submit to fail at signing. Mirrors the storage source-register
/// possession gate. The root credential passes the auth gate, so this isolates the
/// possession check from authorization.
#[tokio::test]
async fn a_register_for_an_unheld_address_is_refused() {
    let db = TestDb::fresh().await.expect("fresh db");
    let router = control_router(control_state(db.pool.clone()));
    let a = provision_tenant(&router, &db.pool, "a").await;

    // Seed 0x60 is a validly-encoded preprod address but is absent from
    // HELD_WALLET_SEEDS, so no instance signer backs it.
    let unheld = preprod_address(0x60);
    let (status, body) = call(
        &router,
        "POST",
        "/control/v1/wallets",
        &a.root_secret,
        Some(json!({ "label": "unsignable", "address": unheld, "network": "preprod" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an address the instance holds no signer for must be refused, body = {body}"
    );
    assert_eq!(body["code"], "validation-failed");
    assert_eq!(
        count_wallets(&db.pool).await,
        0,
        "a refused unheld-address registration writes no wallet row"
    );
}

/// Count the rows in `operator_wallet`.
async fn count_wallets(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.operator_wallet")
        .fetch_one(pool)
        .await
        .expect("count wallets")
}
