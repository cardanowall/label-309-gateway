//! Integration coverage for storage charge authority: the scope-bound charge
//! capability, the grant relation, and the selection resolver that consults it.
//!
//! A storage funding source is an operator-owned credit identity (one Arweave key
//! plus the prepaid winc balance at a provider); who may DRAW charges against it is
//! decided by `storage_grant`. These suites drive the real `funding` engine against
//! a freshly migrated database to pin the contract the upload path relies on:
//!
//!   - cross-operator ISOLATION: operator A cannot authorize a charge against
//!     operator B's source, and cannot issue or revoke a grant on it.
//!   - selection PRECEDENCE: the resolver picks the most specific live grant in the
//!     order account -> operator -> service, single-source per backend.
//!   - the owner is NOT a special always-entitled arm: a grant-less source draws
//!     for nobody, including its owner; the owner draws only through a grant.
//!   - issuing/revoking a grant gates NEW charges; the per-backend live-service
//!     unique keeps exactly one live service grant per backend;
//!     `resolve_committed_upload` settles by id with no entitlement re-check, so a
//!     revoked grant never strands an in-flight upload.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use gateway_core::ledger::account::create_account;
use gateway_core::ledger::account::ScopedTransition;
use gateway_core::storage::{
    authorize_charge, begin_draining_source, issue_grant, resolve_committed_upload, revoke_grant,
    IssueOutcome, RevokeOutcome, SourceStatus, StorageChargePrincipal, StorageGrantScope,
};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::operator::create_operator;
use uuid::Uuid;

/// The canonical backend the storage suites exercise (the Turbo rail).
const BACKEND: &str = "turbo";

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// Register a funding source owned by `owner` for `backend`, returning its id.
///
/// Source registration proper is a control-plane concern; these grant-engine
/// suites seed the row directly so they test the authority resolver in isolation.
/// A distinct Arweave address per `seed` keeps the `(backend, arweave_address)`
/// integrity unique satisfied.
async fn register_source(pool: &sqlx::PgPool, owner: Uuid, backend: &str, seed: u8) -> Uuid {
    let id = Uuid::now_v7();
    let address = format!("ar-address-{backend}-{seed:02x}");
    sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'primary', $3, $4, $5)",
    )
    .bind(id)
    .bind(owner)
    .bind(backend)
    .bind(&address)
    .bind(format!("key-{seed:02x}"))
    .execute(pool)
    .await
    .expect("seed funding source");
    id
}

/// The verified Arweave address `register_source` writes for a `(backend, seed)`.
fn source_address(backend: &str, seed: u8) -> String {
    format!("ar-address-{backend}-{seed:02x}")
}

// ---------------------------------------------------------------------------
// (a) Scope-bound charging: a grant is required, and only a grant entitles.
// ---------------------------------------------------------------------------

/// A funding source with NO grant draws for nobody, NOT EVEN its owner: storage has
/// no always-entitled-owner arm (unlike the wallet registrar). `authorize_charge`
/// returns None for the owning operator until a grant exists.
#[tokio::test]
async fn an_ungranted_source_draws_for_nobody_including_its_owner() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let _source = register_source(&db.pool, owner, BACKEND, 0x01).await;

    // The owner is not entitled with no grant: the owner draws only through a grant
    // the register route auto-issues, never a grant-less owner draw.
    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator { operator_id: owner },
        )
        .await
        .expect("authorize")
        .is_none(),
        "a source with no grant entitles nobody, including its owner"
    );
}

/// A live SERVICE grant entitles ANY operator to draw the source (the single-tenant
/// default). The minted capability carries the source's id and verified address.
#[tokio::test]
async fn a_service_grant_entitles_any_operator() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let stranger = create_operator(&db.pool, "stranger")
        .await
        .expect("operator");
    let source = register_source(&db.pool, owner, BACKEND, 0x02).await;

    // Before the grant, a stranger is not entitled.
    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator {
                operator_id: stranger
            },
        )
        .await
        .expect("authorize")
        .is_none(),
        "no service grant yet, so the stranger is not entitled"
    );

    // The owner issues a service grant.
    assert!(matches!(
        issue_grant(&db.pool, owner, source, StorageGrantScope::Service)
            .await
            .expect("issue"),
        Some(IssueOutcome::Issued { .. })
    ));

    // Now any operator is entitled, and the capability names the granted source.
    let authorized = authorize_charge(
        &db.pool,
        BACKEND,
        StorageChargePrincipal::Operator {
            operator_id: stranger,
        },
    )
    .await
    .expect("authorize")
    .expect("a live service grant entitles every operator");
    assert_eq!(authorized.funding_source_id(), source);
    assert_eq!(authorized.arweave_address(), source_address(BACKEND, 0x02));
}

/// A live OPERATOR grant entitles only the named operator, not a third party.
#[tokio::test]
async fn an_operator_grant_entitles_only_its_named_operator() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let grantee = create_operator(&db.pool, "grantee")
        .await
        .expect("operator");
    let third = create_operator(&db.pool, "third").await.expect("operator");
    let source = register_source(&db.pool, owner, BACKEND, 0x03).await;

    issue_grant(
        &db.pool,
        owner,
        source,
        StorageGrantScope::Operator {
            operator_id: grantee,
        },
    )
    .await
    .expect("issue")
    .expect("owner may grant on its own source");

    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator {
                operator_id: grantee
            },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the named grantee is entitled"
    );
    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator { operator_id: third },
        )
        .await
        .expect("authorize")
        .is_none(),
        "a third operator is not entitled by an operator grant for someone else"
    );
}

// ---------------------------------------------------------------------------
// (b) Cross-operator isolation: the most important deliverable. Operator A can
//     never draw, grant on, or revoke a grant on operator B's source.
// ---------------------------------------------------------------------------

/// Operator A cannot authorize a charge against operator B's source: with no grant
/// from B, A is not entitled, and A's own operator grant on its OWN source does not
/// leak across to B's source. Two operators each owning a source for the same
/// backend stay isolated.
#[tokio::test]
async fn operator_a_cannot_charge_operator_bs_source() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op_a = create_operator(&db.pool, "a").await.expect("operator");
    let op_b = create_operator(&db.pool, "b").await.expect("operator");

    // Each operator owns a source. They must be on DIFFERENT backends, because a
    // backend holds at most one live service grant; here A and B each get an
    // operator-scoped grant on their own source, so a shared backend is fine for
    // the operator-grant isolation check.
    let source_a = register_source(&db.pool, op_a, BACKEND, 0x10).await;
    let source_b = register_source(&db.pool, op_b, BACKEND, 0x11).await;

    // A grants itself an operator scope on A's source; B does likewise on B's.
    issue_grant(
        &db.pool,
        op_a,
        source_a,
        StorageGrantScope::Operator { operator_id: op_a },
    )
    .await
    .expect("issue a")
    .expect("a grants on its own source");
    issue_grant(
        &db.pool,
        op_b,
        source_b,
        StorageGrantScope::Operator { operator_id: op_b },
    )
    .await
    .expect("issue b")
    .expect("b grants on its own source");

    // A draws ITS OWN source.
    let a_cap = authorize_charge(
        &db.pool,
        BACKEND,
        StorageChargePrincipal::Operator { operator_id: op_a },
    )
    .await
    .expect("authorize a")
    .expect("a draws its own source");
    assert_eq!(
        a_cap.funding_source_id(),
        source_a,
        "operator A's charge resolves to A's own source, never B's"
    );

    // B draws ITS OWN source, not A's.
    let b_cap = authorize_charge(
        &db.pool,
        BACKEND,
        StorageChargePrincipal::Operator { operator_id: op_b },
    )
    .await
    .expect("authorize b")
    .expect("b draws its own source");
    assert_eq!(
        b_cap.funding_source_id(),
        source_b,
        "operator B's charge resolves to B's own source, never A's"
    );
    assert_ne!(
        a_cap.funding_source_id(),
        b_cap.funding_source_id(),
        "the two operators draw distinct sources"
    );
}

/// Operator A cannot ISSUE a grant on operator B's source: ownership is enforced in
/// the engine signature, so a foreign owner reports None (the missing-source shape)
/// and no grant row is written. Mirrors the wallet `only_the_registrar_may_administer`.
#[tokio::test]
async fn operator_a_cannot_issue_or_revoke_a_grant_on_bs_source() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op_a = create_operator(&db.pool, "a").await.expect("operator");
    let op_b = create_operator(&db.pool, "b").await.expect("operator");
    let source_b = register_source(&db.pool, op_b, BACKEND, 0x12).await;

    // A cannot grant on B's source.
    assert!(
        issue_grant(&db.pool, op_a, source_b, StorageGrantScope::Service)
            .await
            .expect("issue")
            .is_none(),
        "a non-owner cannot grant on another operator's source"
    );
    let written: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_grant WHERE funding_source_id = $1",
    )
    .bind(source_b)
    .fetch_one(&db.pool)
    .await
    .expect("count grants");
    assert_eq!(written, 0, "A's refused issue wrote no grant on B's source");

    // B issues a real service grant; then A cannot revoke it.
    let issued = issue_grant(&db.pool, op_b, source_b, StorageGrantScope::Service)
        .await
        .expect("issue")
        .expect("owner grants");
    let grant_id = match issued {
        IssueOutcome::Issued { grant_id } => grant_id,
        other => unreachable!("the first issue inserts, got {other:?}"),
    };
    assert!(
        revoke_grant(&db.pool, op_a, source_b, grant_id)
            .await
            .expect("revoke")
            .is_none(),
        "a non-owner cannot revoke a grant on another operator's source"
    );
    // The grant is still live (A's revoke was a no-op): it still entitles any operator.
    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator { operator_id: op_a },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the foreign revoke did not retract the live service grant"
    );
}

/// A source owned by operator B, granted ONLY at operator scope to B, is invisible
/// to operator A even though A and B share a backend (A would need a grant on B's
/// source, which only B can issue). This is the storage twin of the wallet
/// operator-scope pin.
#[tokio::test]
async fn an_operator_scoped_source_is_drawable_only_by_its_grantee() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op_a = create_operator(&db.pool, "a").await.expect("operator");
    let op_b = create_operator(&db.pool, "b").await.expect("operator");
    let source_b = register_source(&db.pool, op_b, BACKEND, 0x13).await;

    issue_grant(
        &db.pool,
        op_b,
        source_b,
        StorageGrantScope::Operator { operator_id: op_b },
    )
    .await
    .expect("issue")
    .expect("b grants to itself");

    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator { operator_id: op_b },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the grantee draws its operator-scoped source"
    );
    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator { operator_id: op_a },
        )
        .await
        .expect("authorize")
        .is_none(),
        "an operator-scoped source is not drawable by a stranger"
    );
}

// ---------------------------------------------------------------------------
// (c) Selection precedence: account -> operator -> service, single-source.
// ---------------------------------------------------------------------------

/// The resolver picks the MOST SPECIFIC live grant. With service, operator, and
/// account grants all live (on distinct backends so the per-backend cardinality
/// holds), an account principal resolves to the account-granted source, an
/// operator-only principal to the operator-granted source, and a bare operator with
/// only a service grant to the service-granted source.
#[tokio::test]
async fn selection_resolves_account_before_operator_before_service() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let account = create_account(&db.pool, owner).await.expect("account");

    // Three grant scopes targeting one backend cannot coexist on three sources at
    // the same backend only if they collide on the per-(backend, subject) unique;
    // service/operator/account name different subjects, so all three can be live on
    // the SAME backend at once. Put them on three sources to prove the resolver
    // picks the right one by specificity.
    let svc_source = register_source(&db.pool, owner, BACKEND, 0x20).await;
    let op_source = register_source(&db.pool, owner, BACKEND, 0x21).await;
    let acct_source = register_source(&db.pool, owner, BACKEND, 0x22).await;

    issue_grant(&db.pool, owner, svc_source, StorageGrantScope::Service)
        .await
        .expect("issue service")
        .expect("granted");
    issue_grant(
        &db.pool,
        owner,
        op_source,
        StorageGrantScope::Operator { operator_id: owner },
    )
    .await
    .expect("issue operator")
    .expect("granted");
    issue_grant(
        &db.pool,
        owner,
        acct_source,
        StorageGrantScope::Account {
            account_id: account,
        },
    )
    .await
    .expect("issue account")
    .expect("granted");

    // An account principal resolves to the ACCOUNT source (most specific).
    let acct_cap = authorize_charge(
        &db.pool,
        BACKEND,
        StorageChargePrincipal::Account {
            operator_id: owner,
            account_id: account,
        },
    )
    .await
    .expect("authorize account")
    .expect("the account grant resolves");
    assert_eq!(
        acct_cap.funding_source_id(),
        acct_source,
        "an account principal draws the account-granted source over operator/service"
    );

    // An operator principal (a different account, no account grant) resolves to the
    // OPERATOR source over the service source.
    let other_account = create_account(&db.pool, owner).await.expect("account");
    let op_cap = authorize_charge(
        &db.pool,
        BACKEND,
        StorageChargePrincipal::Account {
            operator_id: owner,
            account_id: other_account,
        },
    )
    .await
    .expect("authorize operator")
    .expect("the operator grant resolves");
    assert_eq!(
        op_cap.funding_source_id(),
        op_source,
        "an account with no account grant falls to the operator-granted source over service"
    );

    // A bare operator with neither account nor operator specificity for a different
    // operator falls to the service source.
    let stranger = create_operator(&db.pool, "stranger")
        .await
        .expect("operator");
    let svc_cap = authorize_charge(
        &db.pool,
        BACKEND,
        StorageChargePrincipal::Operator {
            operator_id: stranger,
        },
    )
    .await
    .expect("authorize service")
    .expect("the service grant resolves");
    assert_eq!(
        svc_cap.funding_source_id(),
        svc_source,
        "an operator with only a service grant draws the service-granted source"
    );
}

/// A charge principal whose (operator, account) pair does not actually belong
/// together is refused, even when a service grant would otherwise entitle any
/// operator. The pairing is verified in the engine signature, so a caller cannot
/// draw a source by pairing an account with an operator it does not belong to.
#[tokio::test]
async fn a_mismatched_operator_account_pair_is_refused() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op_a = create_operator(&db.pool, "a").await.expect("operator a");
    let op_b = create_operator(&db.pool, "b").await.expect("operator b");
    // The account belongs to operator B.
    let account_b = create_account(&db.pool, op_b).await.expect("account b");

    // A live SERVICE grant exists, which entitles ANY operator on its own. So if the
    // pairing were not verified, pairing B's account with operator A would resolve.
    let source = register_source(&db.pool, op_a, BACKEND, 0x30).await;
    issue_grant(&db.pool, op_a, source, StorageGrantScope::Service)
        .await
        .expect("issue service")
        .expect("granted");

    // The correctly-paired principal (account B under operator B) resolves.
    let ok = authorize_charge(
        &db.pool,
        BACKEND,
        StorageChargePrincipal::Account {
            operator_id: op_b,
            account_id: account_b,
        },
    )
    .await
    .expect("authorize correct pair");
    assert!(
        ok.is_some(),
        "the correctly-paired account draws the service source"
    );

    // The mismatched principal (account B paired with operator A) is refused, shaped
    // like a missing grant, despite the live service grant.
    let mismatched = authorize_charge(
        &db.pool,
        BACKEND,
        StorageChargePrincipal::Account {
            operator_id: op_a,
            account_id: account_b,
        },
    )
    .await
    .expect("authorize mismatched pair");
    assert!(
        mismatched.is_none(),
        "an account paired with an operator it does not belong to is refused"
    );
}

// ---------------------------------------------------------------------------
// (d) The single-source per-backend service guard, idempotency, and revocation.
// ---------------------------------------------------------------------------

/// Issuing a second SERVICE grant for the same backend (even on a different source)
/// is rejected by the per-backend live-service unique: the call reports
/// `AlreadyGranted` pointing at the existing live service grant, never a second
/// row. This is the single-source rule enforced in the database: one live service
/// grant per backend, never two, even across distinct sources.
#[tokio::test]
async fn a_second_live_service_grant_for_a_backend_is_unrepresentable() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let source_one = register_source(&db.pool, owner, BACKEND, 0x30).await;
    let source_two = register_source(&db.pool, owner, BACKEND, 0x31).await;

    let first = issue_grant(&db.pool, owner, source_one, StorageGrantScope::Service)
        .await
        .expect("issue")
        .expect("granted");
    let first_id = match first {
        IssueOutcome::Issued { grant_id } => grant_id,
        other => unreachable!("the first issue inserts, got {other:?}"),
    };

    // A service grant on a DIFFERENT source for the same backend cannot create a
    // second live service grant: it converges on the existing one.
    let second = issue_grant(&db.pool, owner, source_two, StorageGrantScope::Service)
        .await
        .expect("issue")
        .expect("granted");
    assert_eq!(
        second,
        IssueOutcome::AlreadyGranted { grant_id: first_id },
        "a backend holds exactly one live service grant; the second issue converges on it"
    );

    // Exactly one live service grant exists for the backend.
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_grant \
         WHERE backend = $1 AND scope_kind = 'service' AND revoked_at IS NULL",
    )
    .bind(BACKEND)
    .fetch_one(&db.pool)
    .await
    .expect("count live service grants");
    assert_eq!(
        live, 1,
        "the per-backend unique keeps a single live service grant"
    );
}

/// Concurrent duplicate issues of the SAME operator-grant subject are atomically
/// idempotent: exactly one inserts, the rest report `AlreadyGranted` pointing at
/// that one row, and at most one live grant of the subject exists. None of the
/// racers surfaces a raw unique-violation error.
#[tokio::test]
async fn concurrent_duplicate_issues_are_atomically_idempotent() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let grantee = create_operator(&db.pool, "grantee")
        .await
        .expect("operator");
    let source = register_source(&db.pool, owner, BACKEND, 0x32).await;

    const RACERS: usize = 8;
    let mut handles = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let pool = db.pool.clone();
        handles.push(tokio::spawn(async move {
            issue_grant(
                &pool,
                owner,
                source,
                StorageGrantScope::Operator {
                    operator_id: grantee,
                },
            )
            .await
        }));
    }

    let mut issued_ids = std::collections::HashSet::new();
    let mut already_ids = std::collections::HashSet::new();
    for handle in handles {
        let outcome = handle
            .await
            .expect("issue task joins")
            .expect("issue never errors under a duplicate race")
            .expect("the owner may grant on its own source");
        match outcome {
            IssueOutcome::Issued { grant_id } => {
                issued_ids.insert(grant_id);
            }
            IssueOutcome::AlreadyGranted { grant_id } => {
                already_ids.insert(grant_id);
            }
            // A same-owner operator-scope race only ever inserts or converges on the
            // owner's own grant; a cross-owner conflict is unreachable here.
            other => panic!(
                "a same-owner operator-scope race never conflicts cross-owner, got {other:?}"
            ),
        }
    }

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

    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_grant \
         WHERE funding_source_id = $1 AND scope_kind = 'operator' AND operator_id = $2 \
           AND revoked_at IS NULL",
    )
    .bind(source)
    .bind(grantee)
    .fetch_one(&db.pool)
    .await
    .expect("count live grants");
    assert_eq!(
        live, 1,
        "the partial unique index keeps a single live grant"
    );
}

/// Issuing the same grant twice is idempotent, and revoking it gates a fresh
/// charge while leaving in-flight settlement (by source id) unaffected.
#[tokio::test]
async fn revocation_gates_new_charges_but_not_inflight_settlement() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let grantee = create_operator(&db.pool, "grantee")
        .await
        .expect("operator");
    let source = register_source(&db.pool, owner, BACKEND, 0x33).await;
    let principal = StorageChargePrincipal::Operator {
        operator_id: grantee,
    };

    let grant_id = match issue_grant(
        &db.pool,
        owner,
        source,
        StorageGrantScope::Operator {
            operator_id: grantee,
        },
    )
    .await
    .expect("issue")
    .expect("granted")
    {
        IssueOutcome::Issued { grant_id } => grant_id,
        other => panic!("the first issue inserts, got {other:?}"),
    };
    // Re-issuing is idempotent.
    assert_eq!(
        issue_grant(
            &db.pool,
            owner,
            source,
            StorageGrantScope::Operator {
                operator_id: grantee,
            },
        )
        .await
        .expect("issue again")
        .expect("granted"),
        IssueOutcome::AlreadyGranted { grant_id },
        "re-issuing a live grant is idempotent, not a duplicate"
    );

    // The grantee can authorize a charge while the grant is live.
    assert!(
        authorize_charge(&db.pool, BACKEND, principal)
            .await
            .expect("authorize")
            .is_some(),
        "the grantee draws the source while the grant is live"
    );

    // Revoke the grant; revoking again is an idempotent no-op.
    assert_eq!(
        revoke_grant(&db.pool, owner, source, grant_id)
            .await
            .expect("revoke")
            .expect("the owner may revoke its own source's grant"),
        RevokeOutcome::Revoked
    );
    assert_eq!(
        revoke_grant(&db.pool, owner, source, grant_id)
            .await
            .expect("revoke again")
            .expect("still the owner's grant"),
        RevokeOutcome::AlreadyRevoked
    );

    // A fresh charge by the grantee is now refused: revocation gates new charges.
    assert!(
        authorize_charge(&db.pool, BACKEND, principal)
            .await
            .expect("authorize")
            .is_none(),
        "a revoked grant no longer entitles a fresh charge"
    );

    // But the committed-upload settlement path still resolves the source by id with
    // no entitlement re-check: a release/refund of an upload reserved while the
    // grant was live still draws the source even though the grant is gone.
    let settled = resolve_committed_upload(&db.pool, source, BACKEND)
        .await
        .expect("resolve committed")
        .expect("settlement resolves by source id regardless of grants");
    assert_eq!(settled.funding_source_id(), source);
    assert_eq!(settled.arweave_address(), source_address(BACKEND, 0x33));
}

/// A fresh `authorize_charge` whose entitlement query runs AFTER a committed revoke
/// is refused: read-committed visibility means the post-revoke authorize observes
/// the stamped `revoked_at`, so no charge can authorize against a revoked grant.
#[tokio::test]
async fn authorize_after_a_committed_revoke_is_refused() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let grantee = create_operator(&db.pool, "grantee")
        .await
        .expect("operator");
    let source = register_source(&db.pool, owner, BACKEND, 0x34).await;
    let principal = StorageChargePrincipal::Operator {
        operator_id: grantee,
    };

    let grant_id = match issue_grant(
        &db.pool,
        owner,
        source,
        StorageGrantScope::Operator {
            operator_id: grantee,
        },
    )
    .await
    .expect("issue")
    .expect("granted")
    {
        IssueOutcome::Issued { grant_id } => grant_id,
        other => panic!("the first issue inserts, got {other:?}"),
    };

    assert!(
        authorize_charge(&db.pool, BACKEND, principal)
            .await
            .expect("authorize")
            .is_some(),
        "the grantee is entitled while the grant is live"
    );

    assert_eq!(
        revoke_grant(&db.pool, owner, source, grant_id)
            .await
            .expect("revoke")
            .expect("the owner may revoke its own source's grant"),
        RevokeOutcome::Revoked
    );

    assert!(
        authorize_charge(&db.pool, BACKEND, principal)
            .await
            .expect("authorize")
            .is_none(),
        "an authorization that runs after the revoke commits is refused"
    );
}

// ---------------------------------------------------------------------------
// (e) Account-scope ownership is enforced in the engine, not only the route.
// ---------------------------------------------------------------------------

/// `issue_grant` refuses an account-scope grant for an account the operator does
/// not own, at the ENGINE level: ownership lives in the function signature, so a
/// caller that reaches `issue_grant` directly (bypassing any route check) still
/// cannot entitle a foreign account to draw its source. A foreign/absent account
/// reports None and writes no row; an owned account is granted normally.
#[tokio::test]
async fn issue_grant_engine_refuses_an_account_the_operator_does_not_own() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let other_operator = create_operator(&db.pool, "other").await.expect("operator");
    let source = register_source(&db.pool, owner, BACKEND, 0x35).await;

    // An account owned by a DIFFERENT operator.
    let foreign_account = create_account(&db.pool, other_operator)
        .await
        .expect("create foreign account");

    let outcome = issue_grant(
        &db.pool,
        owner,
        source,
        StorageGrantScope::Account {
            account_id: foreign_account,
        },
    )
    .await
    .expect("issue");
    assert!(
        outcome.is_none(),
        "an account grant for an account the operator does not own is refused in the engine"
    );
    let written: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_grant \
         WHERE funding_source_id = $1 AND scope_kind = 'account' AND account_id = $2",
    )
    .bind(source)
    .bind(foreign_account)
    .fetch_one(&db.pool)
    .await
    .expect("count account grants");
    assert_eq!(written, 0, "the refused account grant wrote no row");

    // An account the owner DOES own is granted normally.
    let own_account = create_account(&db.pool, owner)
        .await
        .expect("create own account");
    assert!(
        matches!(
            issue_grant(
                &db.pool,
                owner,
                source,
                StorageGrantScope::Account {
                    account_id: own_account,
                },
            )
            .await
            .expect("issue")
            .expect("the owner may grant its own account"),
            IssueOutcome::Issued { .. }
        ),
        "an account the operator owns is granted normally"
    );
    // And that grant entitles a charge under that account.
    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Account {
                operator_id: owner,
                account_id: own_account,
            },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the account grant entitles a charge under that account"
    );
}

// ---------------------------------------------------------------------------
// (f) Backend isolation + retired/missing-source resolution.
// ---------------------------------------------------------------------------

/// A grant for one backend never entitles a charge resolved for a different
/// backend: `authorize_charge` filters on the requested backend, so a service grant
/// for `turbo` does not satisfy an `arlocal` charge.
#[tokio::test]
async fn a_grant_does_not_leak_across_backends() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let source = register_source(&db.pool, owner, "turbo", 0x40).await;
    issue_grant(&db.pool, owner, source, StorageGrantScope::Service)
        .await
        .expect("issue")
        .expect("granted");

    // The turbo service grant entitles a turbo charge.
    assert!(
        authorize_charge(
            &db.pool,
            "turbo",
            StorageChargePrincipal::Operator { operator_id: owner },
        )
        .await
        .expect("authorize")
        .is_some(),
        "the turbo grant entitles a turbo charge"
    );
    // But not an arlocal charge: no arlocal grant exists.
    assert!(
        authorize_charge(
            &db.pool,
            "arlocal",
            StorageChargePrincipal::Operator { operator_id: owner },
        )
        .await
        .expect("authorize")
        .is_none(),
        "a turbo grant does not entitle an arlocal charge"
    );
}

/// A RETIRED source draws no NEW charge (`authorize_charge` excludes it) but still
/// settles an in-flight upload by id (`resolve_committed_upload` has no status
/// gate), so a wound-down source never strands an upload it was already paying for.
#[tokio::test]
async fn a_retired_source_takes_no_new_charge_but_settles_inflight() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let source = register_source(&db.pool, owner, BACKEND, 0x41).await;
    issue_grant(&db.pool, owner, source, StorageGrantScope::Service)
        .await
        .expect("issue")
        .expect("granted");

    // While active, the source draws a new charge.
    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator { operator_id: owner },
        )
        .await
        .expect("authorize")
        .is_some(),
        "an active granted source draws a new charge"
    );

    // Retire the source.
    sqlx::query(
        "UPDATE cw_core.storage_funding_source \
         SET status = 'retired', retired_at = now() WHERE id = $1",
    )
    .bind(source)
    .execute(&db.pool)
    .await
    .expect("retire source");

    // A NEW charge is refused (the retired source is excluded from selection).
    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator { operator_id: owner },
        )
        .await
        .expect("authorize")
        .is_none(),
        "a retired source takes no new charge"
    );
    // But an in-flight settlement still resolves it by id.
    assert!(
        resolve_committed_upload(&db.pool, source, BACKEND)
            .await
            .expect("resolve committed")
            .is_some(),
        "a retired source still settles an in-flight upload by id"
    );
}

/// `resolve_committed_upload` reports None for an unknown source id or a
/// backend-mismatch, so a settlement can never resolve a source bound to a
/// different backend (the defense-in-depth filter).
#[tokio::test]
async fn resolve_committed_upload_rejects_an_unknown_or_mismatched_source() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let source = register_source(&db.pool, owner, "turbo", 0x42).await;

    // An unknown id resolves to None.
    assert!(
        resolve_committed_upload(&db.pool, Uuid::now_v7(), "turbo")
            .await
            .expect("resolve")
            .is_none(),
        "an unknown source id resolves to None"
    );
    // The real source under the wrong backend resolves to None.
    assert!(
        resolve_committed_upload(&db.pool, source, "arlocal")
            .await
            .expect("resolve")
            .is_none(),
        "a backend-mismatched settlement resolves to None"
    );
    // The real source under its own backend resolves.
    assert!(
        resolve_committed_upload(&db.pool, source, "turbo")
            .await
            .expect("resolve")
            .is_some(),
        "the source resolves under its own backend"
    );
}

/// A DRAINING source takes no NEW charge (`authorize_charge` admits only `active`)
/// but still settles an in-flight upload by id (`resolve_committed_upload` has no
/// status gate), so an owner winding a source down stops new spend while never
/// stranding an upload it was already paying for. This pins the only
/// operator-reachable wind-down state, mirroring the wallet `pick_wallet`
/// active-only discipline.
#[tokio::test]
async fn a_draining_source_takes_no_new_charge_but_settles_inflight() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = create_operator(&db.pool, "owner").await.expect("operator");
    let source = register_source(&db.pool, owner, BACKEND, 0x43).await;
    issue_grant(&db.pool, owner, source, StorageGrantScope::Service)
        .await
        .expect("issue")
        .expect("granted");

    // While active, the source draws a new charge.
    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator { operator_id: owner },
        )
        .await
        .expect("authorize")
        .is_some(),
        "an active granted source draws a new charge"
    );

    // The owner drains the source through the real lifecycle transition.
    assert_eq!(
        begin_draining_source(&db.pool, owner, source)
            .await
            .expect("drain"),
        ScopedTransition::Changed {
            from: SourceStatus::Active,
            to: SourceStatus::Draining,
        },
        "the active source transitions to draining"
    );

    // A NEW charge is refused: the draining source is excluded from selection even
    // though its service grant is still live.
    assert!(
        authorize_charge(
            &db.pool,
            BACKEND,
            StorageChargePrincipal::Operator { operator_id: owner },
        )
        .await
        .expect("authorize")
        .is_none(),
        "a draining source takes no new charge"
    );

    // But an in-flight settlement still resolves it by id, with no status gate.
    let settled = resolve_committed_upload(&db.pool, source, BACKEND)
        .await
        .expect("resolve committed")
        .expect("a draining source still settles an in-flight upload by id");
    assert_eq!(settled.funding_source_id(), source);
    assert_eq!(settled.arweave_address(), source_address(BACKEND, 0x43));
}

// ---------------------------------------------------------------------------
// (g) Owner-aware service-grant read-back: a cross-owner conflict never leaks a
//     foreign operator's grant id.
// ---------------------------------------------------------------------------

/// Operator B issuing a `service` grant for a backend whose live service default is
/// already held by operator A gets the distinct non-leaking
/// `ServiceDefaultHeldByOtherOwner` outcome, NOT operator A's grant id. The
/// per-backend service unique is global (the single-source rule), so B's insert
/// conflicts with A's grant; the idempotent read-back is owner-scoped, so it never
/// discloses A's grant to B. A same-owner re-issue still reads back the owner's own
/// grant as `AlreadyGranted`.
#[tokio::test]
async fn a_service_reissue_by_a_foreign_owner_does_not_leak_the_existing_grant_id() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op_a = create_operator(&db.pool, "a").await.expect("operator a");
    let op_b = create_operator(&db.pool, "b").await.expect("operator b");

    // Each operator owns a distinct source on the SAME backend (distinct addresses).
    let source_a = register_source(&db.pool, op_a, BACKEND, 0x50).await;
    let source_b = register_source(&db.pool, op_b, BACKEND, 0x51).await;

    // A holds the backend's single live service grant.
    let a_grant = match issue_grant(&db.pool, op_a, source_a, StorageGrantScope::Service)
        .await
        .expect("issue a")
        .expect("a grants the service default")
    {
        IssueOutcome::Issued { grant_id } => grant_id,
        other => panic!("the first service issue inserts, got {other:?}"),
    };

    // B issues a service grant on B's OWN source for the same backend. The insert
    // collides with A's live service grant (one per backend), so the read-back must
    // report the cross-owner conflict WITHOUT A's grant id.
    let b_outcome = issue_grant(&db.pool, op_b, source_b, StorageGrantScope::Service)
        .await
        .expect("issue b")
        .expect("the owner of source_b is recognized");
    assert_eq!(
        b_outcome,
        IssueOutcome::ServiceDefaultHeldByOtherOwner,
        "B's service issue conflicts with A's default and discloses no foreign grant id"
    );
    assert_ne!(
        b_outcome,
        IssueOutcome::AlreadyGranted { grant_id: a_grant },
        "B never receives A's grant id"
    );

    // No second live service grant was written: A's remains the sole service grant.
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_grant \
         WHERE backend = $1 AND scope_kind = 'service' AND revoked_at IS NULL",
    )
    .bind(BACKEND)
    .fetch_one(&db.pool)
    .await
    .expect("count live service grants");
    assert_eq!(
        live, 1,
        "B's conflicting issue wrote no second service grant"
    );

    // A re-issuing its own service grant is still idempotent and reads back A's own
    // grant id (the owner-scoped read-back resolves the caller's own grant).
    assert_eq!(
        issue_grant(&db.pool, op_a, source_a, StorageGrantScope::Service)
            .await
            .expect("re-issue a")
            .expect("a still owns its source"),
        IssueOutcome::AlreadyGranted { grant_id: a_grant },
        "A's idempotent re-issue reads back its own grant"
    );
}
