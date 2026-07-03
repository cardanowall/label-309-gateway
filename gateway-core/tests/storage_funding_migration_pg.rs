//! Storage-funding migration smoke test: the funding source, the charge-authority
//! grant relation, the append-only winc credit journal, the durable upload
//! reservation, and the storage ledger kinds behave against a real Postgres.
//!
//! These suites drive raw SQL against a freshly migrated database (TestDb::fresh
//! runs the full MIGRATOR) to pin the schema invariants the storage billing model
//! relies on before the engine code that depends on them exists. They assert the
//! structural guards directly:
//!
//!   - the four storage ledger kinds are seeded;
//!   - the per-(backend, subject) partial uniques reject a second live service /
//!     operator / account grant, and re-admit one after the first is revoked;
//!   - the composite FK rejects a grant whose backend differs from its source;
//!   - the at-most-one-live-attempt partial unique rejects a second `reserved`
//!     attempt for the same (account, backend, sha256) and re-admits one once the
//!     first leaves `reserved`;
//!   - the storage_credit_apply trigger maintains the materialized winc balance on
//!     a charge and a reconcile insert, stamping the last-reconciled diagnostics;
//!   - the append-only guard rejects an UPDATE/DELETE on the winc journal;
//!   - the attempt envelope CHECKs reject an over-512-byte signature and an
//!     over-4096-byte tag block, so the persisted envelope stays bounded.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use gateway_core::testsupport::TestDb;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// Seed one operator and return its id.
async fn seed_operator(pool: &sqlx::PgPool, label: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(id)
        .bind(label)
        .execute(pool)
        .await
        .expect("insert operator");
    id
}

/// Seed one account anchor + its detail under an operator, returning the account id.
async fn seed_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("insert account anchor");
    sqlx::query(
        "INSERT INTO cw_core.account_detail (account_id, operator_id, status) \
         VALUES ($1, $2, 'active')",
    )
    .bind(account_id)
    .bind(operator_id)
    .execute(pool)
    .await
    .expect("insert account detail");
    account_id
}

/// Register one funding source for an operator on a backend and return its id.
async fn seed_funding_source(
    pool: &sqlx::PgPool,
    owner_operator_id: Uuid,
    backend: &str,
    address: &str,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'primary', $3, $4, 'kr:1')",
    )
    .bind(id)
    .bind(owner_operator_id)
    .bind(backend)
    .bind(address)
    .execute(pool)
    .await
    .expect("insert funding source");
    id
}

/// Insert one storage grant, returning the Result so a uniqueness/FK violation can
/// be asserted by the caller.
async fn insert_grant(
    pool: &sqlx::PgPool,
    funding_source_id: Uuid,
    backend: &str,
    scope_kind: &str,
    operator_id: Option<Uuid>,
    account_id: Option<Uuid>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO cw_core.storage_grant \
           (id, funding_source_id, backend, scope_kind, operator_id, account_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::now_v7())
    .bind(funding_source_id)
    .bind(backend)
    .bind(scope_kind)
    .bind(operator_id)
    .bind(account_id)
    .execute(pool)
    .await
}

/// Insert one reserved upload attempt with a fixed-shape envelope, returning the
/// Result so a uniqueness/CHECK violation can be asserted by the caller. The
/// signature/anchor/tag bytes default to in-bound lengths; callers override them to
/// probe the octet-length CHECKs.
#[allow(clippy::too_many_arguments)]
async fn insert_attempt(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    operator_id: Uuid,
    funding_source_id: Uuid,
    backend: &str,
    sha256: &[u8],
    signature: &[u8],
    tag_bytes: &[u8],
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_upload_attempt \
           (id, account_id, operator_id, funding_source_id, backend, sha256, bytes, \
            chargeable_bytes, charged_usd_micros, estimated_winc, data_item_id, \
            data_item_signature, data_item_anchor, data_item_tag_bytes, staged_path) \
         VALUES ($1, $2, $3, $4, $5, $6, 1000, 1000, 5000, 7, 'di:1', $7, NULL, $8, '/tmp/staged/1')",
    )
    .bind(id)
    .bind(account_id)
    .bind(operator_id)
    .bind(funding_source_id)
    .bind(backend)
    .bind(sha256)
    .bind(signature)
    .bind(tag_bytes)
    .execute(pool)
    .await?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// Ledger kinds.
// ---------------------------------------------------------------------------

/// The migration seeds the four non-overdrawing storage ledger kinds into the
/// registry, so a storage hold/release/charge/refund entry can be inserted.
#[tokio::test]
async fn migration_seeds_the_four_storage_ledger_kinds() {
    let db = TestDb::fresh().await.expect("fresh db");

    for kind in [
        "storage_hold",
        "storage_hold_release",
        "storage_upload",
        "storage_refund",
    ] {
        let overdraft: Option<bool> = sqlx::query_scalar(
            "SELECT allows_overdraft FROM cw_core.ledger_kind_registry \
             WHERE kind = $1 AND registered_by = 'core'",
        )
        .bind(kind)
        .fetch_optional(&db.pool)
        .await
        .expect("registry query");
        assert_eq!(
            overdraft,
            Some(false),
            "storage kind {kind} is seeded and non-overdrawing"
        );
    }
}

/// The storage-refund single-refund index keys on `ref`: a given upload's
/// `storage_refund` credit lands at most once, while two different refs coexist.
#[tokio::test]
async fn storage_refund_is_unique_per_ref() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator_id = seed_operator(&db.pool, "op").await;
    let account_id = seed_account(&db.pool, operator_id).await;

    let insert_refund = |ref_key: &'static str| {
        let pool = db.pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO cw_core.balance_ledger (account_id, kind, amount_micros, ref) \
                 VALUES ($1, 'storage_refund', 500, $2)",
            )
            .bind(account_id)
            .bind(ref_key)
            .execute(&pool)
            .await
        }
    };

    insert_refund("attempt-a")
        .await
        .expect("first refund inserts");
    assert!(
        insert_refund("attempt-a").await.is_err(),
        "a second storage_refund for the same ref hits the single-refund unique"
    );
    insert_refund("attempt-b")
        .await
        .expect("a refund for a different attempt inserts");
}

// ---------------------------------------------------------------------------
// D3 cardinality guard: per-(backend, subject) live-grant uniqueness + re-admit.
// ---------------------------------------------------------------------------

/// At most one LIVE service grant may exist per backend: a second one is rejected,
/// and revoking the first re-admits a fresh service grant.
#[tokio::test]
async fn one_live_service_grant_per_backend_and_re_admit() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator_id = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator_id, "turbo", "addr-turbo").await;

    insert_grant(&db.pool, source, "turbo", "service", None, None)
        .await
        .expect("first service grant inserts");
    assert!(
        insert_grant(&db.pool, source, "turbo", "service", None, None)
            .await
            .is_err(),
        "a second live service grant for the same backend is rejected"
    );

    // Revoke the live grant; the partial unique frees and a fresh service grant
    // for the same backend re-admits.
    sqlx::query(
        "UPDATE cw_core.storage_grant SET revoked_at = now() \
         WHERE backend = 'turbo' AND scope_kind = 'service' AND revoked_at IS NULL",
    )
    .execute(&db.pool)
    .await
    .expect("revoke the live service grant");
    insert_grant(&db.pool, source, "turbo", "service", None, None)
        .await
        .expect("a fresh service grant re-admits once the first is revoked");
}

/// A second live grant for the same (backend, operator) is rejected; the same
/// operator may hold a live grant on a DIFFERENT backend.
#[tokio::test]
async fn one_live_operator_grant_per_backend_subject() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = seed_operator(&db.pool, "owner").await;
    let grantee = seed_operator(&db.pool, "grantee").await;
    let turbo = seed_funding_source(&db.pool, owner, "turbo", "addr-t").await;
    let arlocal = seed_funding_source(&db.pool, owner, "arlocal", "addr-a").await;

    insert_grant(&db.pool, turbo, "turbo", "operator", Some(grantee), None)
        .await
        .expect("first operator grant inserts");
    assert!(
        insert_grant(&db.pool, turbo, "turbo", "operator", Some(grantee), None)
            .await
            .is_err(),
        "a second live grant for the same (backend, operator) is rejected"
    );
    // The same operator on a different backend is a distinct subject and admits.
    insert_grant(
        &db.pool,
        arlocal,
        "arlocal",
        "operator",
        Some(grantee),
        None,
    )
    .await
    .expect("the same operator on a different backend is a distinct live grant");
}

/// A second live grant for the same (backend, account) is rejected.
#[tokio::test]
async fn one_live_account_grant_per_backend_subject() {
    let db = TestDb::fresh().await.expect("fresh db");
    let owner = seed_operator(&db.pool, "owner").await;
    let account_id = seed_account(&db.pool, owner).await;
    let source = seed_funding_source(&db.pool, owner, "turbo", "addr-acct").await;

    insert_grant(&db.pool, source, "turbo", "account", None, Some(account_id))
        .await
        .expect("first account grant inserts");
    assert!(
        insert_grant(&db.pool, source, "turbo", "account", None, Some(account_id))
            .await
            .is_err(),
        "a second live grant for the same (backend, account) is rejected"
    );
}

// ---------------------------------------------------------------------------
// Composite FK: the denormalized backend must equal the source's backend.
// ---------------------------------------------------------------------------

/// A grant whose `backend` disagrees with its source's backend is unrepresentable:
/// the composite FK (funding_source_id, backend) -> source (id, backend) has no
/// matching (id, backend) pair, so the insert is rejected. A grant whose backend
/// matches inserts normally.
#[tokio::test]
async fn the_composite_fk_rejects_a_backend_source_mismatch() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator_id = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator_id, "turbo", "addr-turbo").await;

    // The source is 'turbo'; a grant that claims 'arlocal' for it references a
    // nonexistent (id, backend) pair.
    assert!(
        insert_grant(&db.pool, source, "arlocal", "service", None, None)
            .await
            .is_err(),
        "a grant whose backend differs from its source's backend is rejected by the composite FK"
    );

    // The matching backend inserts.
    insert_grant(&db.pool, source, "turbo", "service", None, None)
        .await
        .expect("a grant whose backend matches its source inserts");
}

// ---------------------------------------------------------------------------
// D5a at-most-one-live-attempt guard + re-admit after settlement.
// ---------------------------------------------------------------------------

/// A second `reserved` attempt for the same (account, backend, sha256) is rejected
/// by the live-attempt partial unique; once the first leaves `reserved` (committed
/// or released) a fresh attempt for the same logical upload re-admits.
#[tokio::test]
async fn one_live_attempt_per_logical_upload_and_re_admit() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator_id = seed_operator(&db.pool, "op").await;
    let account_id = seed_account(&db.pool, operator_id).await;
    let source = seed_funding_source(&db.pool, operator_id, "turbo", "addr-turbo").await;

    let sha = vec![0x11u8; 32];
    let sig = vec![0x22u8; 512];
    let tags = vec![0x33u8; 64];

    let first = insert_attempt(
        &db.pool,
        account_id,
        operator_id,
        source,
        "turbo",
        &sha,
        &sig,
        &tags,
    )
    .await
    .expect("first reserved attempt inserts");

    // A second reserved attempt for the same logical upload is rejected.
    assert!(
        insert_attempt(
            &db.pool,
            account_id,
            operator_id,
            source,
            "turbo",
            &sha,
            &sig,
            &tags,
        )
        .await
        .is_err(),
        "a second reserved attempt for the same (account, backend, sha256) is rejected"
    );

    // Settle the first attempt out of 'reserved'; the live slot frees. A committed
    // attempt must carry a non-null realized charge (the state CHECK), so this
    // mirrors the settle path by stamping it in the same statement.
    sqlx::query(
        "UPDATE cw_core.storage_upload_attempt \
            SET state = 'committed', data_item_signature = NULL, \
                data_item_tag_bytes = NULL, staged_path = NULL, \
                settled_charge_usd_micros = charged_usd_micros, settled_at = now() \
          WHERE id = $1 AND state = 'reserved'",
    )
    .bind(first)
    .execute(&db.pool)
    .await
    .expect("commit the first attempt");

    // A fresh reserved attempt for the same logical upload now re-admits.
    insert_attempt(
        &db.pool,
        account_id,
        operator_id,
        source,
        "turbo",
        &sha,
        &sig,
        &tags,
    )
    .await
    .expect("a fresh reserved attempt re-admits once the first leaves 'reserved'");
}

// ---------------------------------------------------------------------------
// Attempt envelope bounds: the octet-length CHECKs.
// ---------------------------------------------------------------------------

/// The signed-envelope columns reject an over-512-byte signature and an
/// over-4096-byte tag block, so the persisted envelope can never grow with content
/// size. An in-bound envelope inserts normally.
#[tokio::test]
async fn the_attempt_envelope_checks_bound_the_signature_and_tag_block() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator_id = seed_operator(&db.pool, "op").await;
    let account_id = seed_account(&db.pool, operator_id).await;
    let source = seed_funding_source(&db.pool, operator_id, "turbo", "addr-turbo").await;

    let sha = vec![0x44u8; 32];

    // A 513-byte signature exceeds the RSA-4096 length CHECK.
    assert!(
        insert_attempt(
            &db.pool,
            account_id,
            operator_id,
            source,
            "turbo",
            &sha,
            &[0x55u8; 513],
            &[0x66u8; 64],
        )
        .await
        .is_err(),
        "an over-512-byte signature is rejected by the octet-length CHECK"
    );

    // A 4097-byte tag block exceeds the MAX_TAG_BYTES CHECK.
    assert!(
        insert_attempt(
            &db.pool,
            account_id,
            operator_id,
            source,
            "turbo",
            &sha,
            &[0x55u8; 512],
            &[0x66u8; 4097],
        )
        .await
        .is_err(),
        "an over-4096-byte tag block is rejected by the octet-length CHECK"
    );

    // An in-bound envelope (exactly 512-byte signature, 4096-byte tag block)
    // inserts.
    insert_attempt(
        &db.pool,
        account_id,
        operator_id,
        source,
        "turbo",
        &sha,
        &[0x55u8; 512],
        &[0x66u8; 4096],
    )
    .await
    .expect("an in-bound envelope inserts");
}

// ---------------------------------------------------------------------------
// storage_credit_apply trigger maintains the materialized winc balance.
// ---------------------------------------------------------------------------

/// The storage_credit_apply trigger materializes the winc balance on a `charge`
/// insert (no row -> insert at the delta), then a `reconcile` insert both moves the
/// balance and stamps the last-reconciled diagnostics.
#[tokio::test]
async fn storage_credit_apply_materializes_the_winc_balance() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator_id = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator_id, "turbo", "addr-turbo").await;

    // A 'charge' (negative) creates the materialized row at the delta.
    sqlx::query(
        "INSERT INTO cw_core.storage_credit_ledger (funding_source_id, kind, winc_delta, ref) \
         VALUES ($1, 'charge', -3000, 'attempt-1')",
    )
    .bind(source)
    .execute(&db.pool)
    .await
    .expect("insert charge");

    let balance: rust_decimal::Decimal = sqlx::query_scalar(
        "SELECT winc_balance FROM cw_core.storage_credit WHERE funding_source_id = $1",
    )
    .bind(source)
    .fetch_one(&db.pool)
    .await
    .expect("read balance after charge");
    assert_eq!(
        balance,
        rust_decimal::Decimal::from(-3000),
        "the charge materializes the believed winc balance at its delta"
    );

    // A 'reconcile' (positive) moves the balance to the live value AND stamps the
    // last-reconciled diagnostics.
    sqlx::query(
        "INSERT INTO cw_core.storage_credit_ledger (funding_source_id, kind, winc_delta, ref) \
         VALUES ($1, 'reconcile', 8000, 'tick-1')",
    )
    .bind(source)
    .execute(&db.pool)
    .await
    .expect("insert reconcile");

    let (balance, reconciled, reconciled_at): (
        rust_decimal::Decimal,
        Option<rust_decimal::Decimal>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT winc_balance, last_reconciled_winc, last_reconciled_at \
         FROM cw_core.storage_credit WHERE funding_source_id = $1",
    )
    .bind(source)
    .fetch_one(&db.pool)
    .await
    .expect("read balance after reconcile");
    assert_eq!(
        balance,
        rust_decimal::Decimal::from(5000),
        "the reconcile moves the believed balance by its delta (-3000 + 8000)"
    );
    assert_eq!(
        reconciled,
        Some(rust_decimal::Decimal::from(5000)),
        "a reconcile stamps last_reconciled_winc to the post-reconcile balance"
    );
    assert!(
        reconciled_at.is_some(),
        "a reconcile stamps last_reconciled_at"
    );
}

// ---------------------------------------------------------------------------
// Append-only guard on the winc journal.
// ---------------------------------------------------------------------------

/// The append-only guard triggers reject UPDATE and DELETE on the winc journal: the
/// ledger can only grow.
#[tokio::test]
async fn the_winc_journal_is_append_only() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator_id = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator_id, "turbo", "addr-turbo").await;

    sqlx::query(
        "INSERT INTO cw_core.storage_credit_ledger (funding_source_id, kind, winc_delta, ref) \
         VALUES ($1, 'charge', -100, 'attempt-x')",
    )
    .bind(source)
    .execute(&db.pool)
    .await
    .expect("insert journal row");

    assert!(
        sqlx::query("UPDATE cw_core.storage_credit_ledger SET winc_delta = -200")
            .execute(&db.pool)
            .await
            .is_err(),
        "an UPDATE on the append-only winc journal is rejected"
    );
    assert!(
        sqlx::query("DELETE FROM cw_core.storage_credit_ledger")
            .execute(&db.pool)
            .await
            .is_err(),
        "a DELETE on the append-only winc journal is rejected"
    );
}

// ---------------------------------------------------------------------------
// Funding-source integrity guard.
// ---------------------------------------------------------------------------

/// One (backend, arweave_address) maps to one funding source: a second source for
/// the same pair is rejected, while the same address on a different backend admits.
#[tokio::test]
async fn one_funding_source_per_backend_address() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator_id = seed_operator(&db.pool, "op").await;

    seed_funding_source(&db.pool, operator_id, "turbo", "shared-addr").await;

    let dup = sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'dup', 'turbo', 'shared-addr', 'kr:2')",
    )
    .bind(Uuid::now_v7())
    .bind(operator_id)
    .execute(&db.pool)
    .await;
    assert!(
        dup.is_err(),
        "a second source for the same (backend, address) is rejected"
    );

    // The same address on a different backend is a distinct credit pool.
    seed_funding_source(&db.pool, operator_id, "arlocal", "shared-addr").await;
}
