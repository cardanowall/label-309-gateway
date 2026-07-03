//! Audit-row atomicity for the control plane's money mutations, against a real
//! Postgres. The ledger adjustment and its `ledger.adjust` audit row commit in
//! ONE route transaction, so a failing audit append rolls the balance move back
//! with it — an unaudited mutation can never land — while an idempotent replay
//! never double-writes the audit row. The audit failure is injected with a
//! BEFORE INSERT trigger on `cw_core.admin_audit`; assertions are end-state
//! (HTTP status, balance, ledger rows, audit rows), never log strings.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Duration;
use gateway_core::api::control::credential::mint_root_credential;
use gateway_core::api::control::ledger_adjust::register_manual_adjustment_kind;
use gateway_core::api::control::{ControlConfig, ControlState};
use gateway_core::api::control_router;
use gateway_core::ledger::journal::load_balance_micros;
use gateway_core::testsupport::TestDb;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

/// The operator-chosen secret prefix the control plane mints credentials under.
const PREFIX: &str = "ctl_";

/// Build the control router state. No wallet / funding keys: this suite touches
/// only the ledger-adjustment path.
fn control_state(pool: sqlx::PgPool) -> ControlState {
    ControlState::with_keys(
        pool,
        ControlConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            secret_prefix: PREFIX.to_string(),
            operator_token_ttl: Duration::hours(1),
            account_token_ttl: Duration::hours(1),
            adjustment_cap_usd_micros: 10_000_000_000,
            admin_ui_enabled: false,
            ..Default::default()
        },
        Vec::new(),
        Vec::new(),
    )
}

/// Provision an operator row and return its id.
async fn seed_operator(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'op')")
        .bind(id)
        .execute(pool)
        .await
        .expect("insert operator");
    id
}

/// Provision an account anchor + satellite under an operator and return its id.
async fn seed_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(id)
        .execute(pool)
        .await
        .expect("insert account anchor");
    sqlx::query("INSERT INTO cw_core.account_detail (account_id, operator_id) VALUES ($1, $2)")
        .bind(id)
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert account detail");
    id
}

/// Issue a control request and return (status, body json).
async fn call(
    router: &axum::Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let req = if let Some(b) = body {
        req.header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
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

/// Mint an operator token through the route (real lineage: `minted_by` is the
/// presented root's credential id), returning its secret.
async fn mint_operator_token_via_route(router: &axum::Router, root_secret: &str) -> String {
    let (status, body) = call(
        router,
        "POST",
        "/control/v1/operator/token",
        Some(root_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "operator token mint: {body}");
    body["token"].as_str().expect("token secret").to_string()
}

/// Count the account's manual-adjustment ledger rows, the end-state proof of how
/// many balance moves actually landed.
async fn manual_adjustment_rows(pool: &sqlx::PgPool, account_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.balance_ledger \
         WHERE account_id = $1 AND kind = 'manual_adjustment'",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("count manual-adjustment ledger rows")
}

/// Count the audit rows carrying an action + target id, the end-state proof a
/// mutation was journalled.
async fn audit_rows(pool: &sqlx::PgPool, action: &str, target_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.admin_audit WHERE action = $1 AND target_id = $2",
    )
    .bind(action)
    .bind(target_id)
    .fetch_one(pool)
    .await
    .expect("count audit rows")
}

/// The flagship money mutation is atomic with its audit row: an injected audit
/// failure fails the request AND rolls the balance move back; the retried call
/// (same ref) lands exactly once with exactly one audit row; a replay under the
/// same ref is the idempotent no-op and journals nothing further.
#[tokio::test]
async fn a_ledger_adjustment_and_its_audit_row_commit_or_roll_back_together() {
    let db = TestDb::fresh().await.expect("fresh db");
    let op = seed_operator(&db.pool).await;
    let account = seed_account(&db.pool, op).await;
    let root = mint_root_credential(&db.pool, op, PREFIX, None)
        .await
        .expect("mint root");
    register_manual_adjustment_kind(&db.pool)
        .await
        .expect("register the manual-adjustment kind");
    let router = control_router(control_state(db.pool.clone()));
    let op_token = mint_operator_token_via_route(&router, &root.secret).await;

    // Inject a failure into every audit append: a BEFORE INSERT trigger on the
    // audit table raises, so the route's mutation+audit transaction aborts at
    // the audit step — after the ledger row and balance move already ran.
    sqlx::query(
        "CREATE FUNCTION cw_core.refuse_audit_insert() RETURNS trigger \
         LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'injected audit failure'; END $$",
    )
    .execute(&db.pool)
    .await
    .expect("create the injected-failure function");
    sqlx::query(
        "CREATE TRIGGER refuse_audit_insert \
         BEFORE INSERT ON cw_core.admin_audit \
         FOR EACH ROW EXECUTE FUNCTION cw_core.refuse_audit_insert()",
    )
    .execute(&db.pool)
    .await
    .expect("attach the injected-failure trigger");

    let adjustment = json!({
        "amount_usd_micros": 5_000_000,
        "reason": "welcome grant",
        "ref": "grant-1",
    });
    let path = format!("/control/v1/accounts/{account}/ledger-adjustment");

    let (status, problem) = call(
        &router,
        "POST",
        &path,
        Some(&op_token),
        Some(adjustment.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a failed audit append must fail the whole request: {problem}"
    );

    // The failed audit rolled the mutation back with it: the balance never
    // moved, no ledger row exists, and (of course) no audit row either.
    assert_eq!(
        load_balance_micros(&db.pool, account)
            .await
            .expect("balance after the failed call"),
        0,
        "the balance must be untouched when the audit row could not be written"
    );
    assert_eq!(
        manual_adjustment_rows(&db.pool, account).await,
        0,
        "no ledger row may survive a failed audit append"
    );
    assert_eq!(
        audit_rows(&db.pool, "ledger.adjust", &account.to_string()).await,
        0
    );

    // Clear the injected failure; the SAME call (same ref) now lands cleanly.
    sqlx::query("DROP TRIGGER refuse_audit_insert ON cw_core.admin_audit")
        .execute(&db.pool)
        .await
        .expect("drop the injected-failure trigger");
    sqlx::query("DROP FUNCTION cw_core.refuse_audit_insert()")
        .execute(&db.pool)
        .await
        .expect("drop the injected-failure function");

    let (status, body) = call(
        &router,
        "POST",
        &path,
        Some(&op_token),
        Some(adjustment.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "retry after the rollback: {body}");
    assert_eq!(body["applied"], json!(true), "the retry is a fresh apply");
    assert_eq!(
        load_balance_micros(&db.pool, account)
            .await
            .expect("balance after the retry"),
        5_000_000
    );
    assert_eq!(manual_adjustment_rows(&db.pool, account).await, 1);
    assert_eq!(
        audit_rows(&db.pool, "ledger.adjust", &account.to_string()).await,
        1,
        "exactly one audit row for the one landed mutation"
    );

    // A replay under the same ref is the idempotent no-op: the balance moves
    // once, ever, and the replay journals no second audit row.
    let (status, body) = call(&router, "POST", &path, Some(&op_token), Some(adjustment)).await;
    assert_eq!(status, StatusCode::OK, "replay: {body}");
    assert_eq!(body["applied"], json!(false), "the replay is a no-op");
    assert_eq!(
        load_balance_micros(&db.pool, account)
            .await
            .expect("balance after the replay"),
        5_000_000
    );
    assert_eq!(manual_adjustment_rows(&db.pool, account).await, 1);
    assert_eq!(
        audit_rows(&db.pool, "ledger.adjust", &account.to_string()).await,
        1,
        "an idempotent replay must not double-write the audit row"
    );
}
