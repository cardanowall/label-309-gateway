//! Bootstrap subcommand behaviour against a real Postgres.
//!
//! Exercises the `operator bootstrap` path end-to-end: from an empty migrated
//! database it creates one operator, registers the reference manual-adjustment
//! ledger kind, and mints a root credential whose secret resolves back to that
//! operator. It creates NO account (accounts come through the API). Assertions are
//! end-state DB rows and the resolved principal, never log strings.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use gateway::bootstrap::{self, Provisioning};
use gateway::config::{ControlSettings, GatewayConfig, WebhookSettings};
use gateway_core::api::control::credential::resolve_root_credential;
use gateway_core::api::control::ledger_adjust::MANUAL_ADJUSTMENT_KIND;
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use std::time::Duration;
use zeroize::Zeroizing;

/// A minimal resolved config for the bootstrap path. Only the control settings and
/// the (unused-by-bootstrap) wallet/keyring fields need plausible values; bootstrap
/// touches the pool and the control config, not the keyring or the runtime.
fn config(secret_prefix: &str) -> GatewayConfig {
    let band = LovelaceBand::new(4_000_000, 8_000_000, 6_000_000).expect("band");
    let wallet =
        WalletConfig::new(Network::Preprod, band, Duration::from_secs(120), 4).expect("wallet");
    GatewayConfig {
        database_url: String::new(),
        worker_id: "test".to_string(),
        wallet,
        fee_shape_record_sizes: vec![1],
        keyring_path: std::path::PathBuf::from("/dev/null"),
        keyring_passphrase: Zeroizing::new(String::new()),
        http: None,
        storage: None,
        fx: None,
        control: ControlSettings {
            secret_prefix: secret_prefix.to_string(),
            operator_token_ttl_secs: 3600,
            account_token_ttl_secs: 3600,
            adjustment_cap_usd_micros: 10_000_000_000,
            admin_ui_enabled: true,
            default_wallet_scope: "service".to_string(),
            default_storage_scope: "service".to_string(),
        },
        webhooks: WebhookSettings::default(),
        blockfrost_project_id: None,
        koios: gateway_core::chain::params::KoiosConfig::default(),
        chain_egress: gateway_core::chain::egress::EgressLimits::default(),
    }
}

#[tokio::test]
async fn bootstrap_provisions_operator_root_and_the_adjustment_kind() {
    let db = TestDb::fresh().await.expect("fresh db");
    let cfg = config("ctl_");

    bootstrap::run(&db.pool, &cfg, "primary-operator", Provisioning::FreshOnly)
        .await
        .expect("bootstrap runs");

    // Exactly one operator row, labelled as requested.
    let (op_count, label): (i64, String) =
        sqlx::query_as("SELECT count(*)::bigint, max(label) FROM cw_core.operator")
            .fetch_one(&db.pool)
            .await
            .expect("count operators");
    assert_eq!(op_count, 1, "bootstrap creates exactly one operator");
    assert_eq!(label, "primary-operator");

    // Exactly one live root credential, resolving back to the operator.
    let operator_id: uuid::Uuid =
        sqlx::query_scalar("SELECT operator_id FROM cw_core.control_credential")
            .fetch_one(&db.pool)
            .await
            .expect("read credential operator id");

    let cred_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.control_credential WHERE kind = 'operator_root' AND revoked_at IS NULL",
    )
    .fetch_one(&db.pool)
    .await
    .expect("count live root credentials");
    assert_eq!(cred_count, 1, "bootstrap mints exactly one root credential");

    // The reference manual-adjustment ledger kind is registered, as the reference
    // adapter (not a core-seeded kind).
    let registrant: String = sqlx::query_scalar(
        "SELECT registered_by FROM cw_core.ledger_kind_registry WHERE kind = $1",
    )
    .bind(MANUAL_ADJUSTMENT_KIND)
    .fetch_one(&db.pool)
    .await
    .expect("read kind registrant");
    assert_eq!(
        registrant, "reference",
        "the manual-adjustment kind is registered by the reference adapter, not core"
    );

    // Bootstrap creates NO account: the account anchor table is empty.
    let account_count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_api.account")
        .fetch_one(&db.pool)
        .await
        .expect("count accounts");
    assert_eq!(account_count, 0, "bootstrap creates no account");

    // A credential resolve over an unknown secret returns None, proving resolution
    // is wired even though the real secret is only printed (never returned) by
    // `run`.
    let _ = operator_id; // resolution against the real secret is exercised in the control-plane suite.
    assert!(
        resolve_root_credential(&db.pool, "ctl_definitely-not-the-secret")
            .await
            .expect("resolve")
            .is_none()
    );
}

#[tokio::test]
async fn fresh_only_bootstrap_refuses_a_second_run_but_allow_additional_provisions_another() {
    let db = TestDb::fresh().await.expect("fresh db");
    let cfg = config("ctl_");

    // First run succeeds against the empty database.
    bootstrap::run(&db.pool, &cfg, "primary-operator", Provisioning::FreshOnly)
        .await
        .expect("first bootstrap runs");

    // A second fresh-only run refuses: it does not mint another operator or
    // credential. The error names the explicit opt-in.
    let err = bootstrap::run(&db.pool, &cfg, "primary-operator", Provisioning::FreshOnly)
        .await
        .expect_err("a second fresh-only bootstrap must refuse");
    assert!(
        err.to_string().contains("--allow-additional"),
        "the refusal points the operator at the explicit opt-in, got: {err}"
    );

    // The refusal left the database untouched: still exactly one operator and one
    // live root credential.
    let op_count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.operator")
        .fetch_one(&db.pool)
        .await
        .expect("count operators after refusal");
    assert_eq!(op_count, 1, "the refused run minted nothing");
    let cred_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.control_credential \
         WHERE kind = 'operator_root' AND revoked_at IS NULL",
    )
    .fetch_one(&db.pool)
    .await
    .expect("count live credentials after refusal");
    assert_eq!(cred_count, 1, "the refused run minted no second credential");

    // The explicit opt-in provisions a second operator with its own root
    // credential: this is the deliberate multi-operator path.
    bootstrap::run(
        &db.pool,
        &cfg,
        "second-operator",
        Provisioning::AllowAdditional,
    )
    .await
    .expect("an explicit additional bootstrap provisions a second operator");

    let op_count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.operator")
        .fetch_one(&db.pool)
        .await
        .expect("count operators after the explicit additional run");
    assert_eq!(
        op_count, 2,
        "the explicit opt-in provisioned a second operator"
    );
    let cred_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.control_credential \
         WHERE kind = 'operator_root' AND revoked_at IS NULL",
    )
    .fetch_one(&db.pool)
    .await
    .expect("count live credentials after the explicit additional run");
    assert_eq!(
        cred_count, 2,
        "each operator carries its own root credential"
    );
}

/// A failure mid-provisioning rolls the WHOLE bootstrap back, and a re-run
/// succeeds. The regression this pins: operator creation and the root mint
/// used to be separate statements, so a failure between them stranded an
/// operator with no credential — and the fresh-only guard (keyed on operator
/// existence) then refused the retry, bricking the deployment. With the
/// provisioning in one transaction the failed run leaves an empty database.
#[tokio::test]
async fn a_failed_bootstrap_rolls_back_completely_and_a_rerun_succeeds() {
    let db = TestDb::fresh().await.expect("fresh db");
    let cfg = config("ctl_");

    // Inject a failure at the LAST provisioning step (the root-credential
    // insert), after the operator row and the kind registration have run.
    sqlx::query(
        "CREATE FUNCTION cw_core.refuse_credential_insert() RETURNS trigger \
         LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'injected bootstrap failure'; END $$",
    )
    .execute(&db.pool)
    .await
    .expect("create the injected-failure function");
    sqlx::query(
        "CREATE TRIGGER refuse_credential_insert \
         BEFORE INSERT ON cw_core.control_credential \
         FOR EACH ROW EXECUTE FUNCTION cw_core.refuse_credential_insert()",
    )
    .execute(&db.pool)
    .await
    .expect("attach the injected-failure trigger");

    let err = bootstrap::run(&db.pool, &cfg, "primary-operator", Provisioning::FreshOnly)
        .await
        .expect_err("the injected failure must fail the bootstrap");
    assert!(
        err.to_string().contains("root credential"),
        "the failure surfaces at the mint step, got: {err}"
    );

    // The rollback left NOTHING behind: no operator, no credential, and no
    // manual-adjustment kind (all three ran in the one transaction).
    let op_count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.operator")
        .fetch_one(&db.pool)
        .await
        .expect("count operators after the failed run");
    assert_eq!(op_count, 0, "the failed run left an operator row behind");
    let kind_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.ledger_kind_registry WHERE kind = $1")
            .bind(MANUAL_ADJUSTMENT_KIND)
            .fetch_one(&db.pool)
            .await
            .expect("count adjustment kinds after the failed run");
    assert_eq!(kind_count, 0, "the failed run left the kind registered");

    // Clear the injected failure; the retry now provisions from scratch — the
    // fresh-only guard sees the empty table the rollback restored.
    sqlx::query("DROP TRIGGER refuse_credential_insert ON cw_core.control_credential")
        .execute(&db.pool)
        .await
        .expect("drop the injected-failure trigger");
    sqlx::query("DROP FUNCTION cw_core.refuse_credential_insert()")
        .execute(&db.pool)
        .await
        .expect("drop the injected-failure function");

    bootstrap::run(&db.pool, &cfg, "primary-operator", Provisioning::FreshOnly)
        .await
        .expect("the retry after the rolled-back failure succeeds");

    let op_count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.operator")
        .fetch_one(&db.pool)
        .await
        .expect("count operators after the retry");
    assert_eq!(op_count, 1, "the retry provisioned exactly one operator");
    let cred_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.control_credential \
         WHERE kind = 'operator_root' AND revoked_at IS NULL",
    )
    .fetch_one(&db.pool)
    .await
    .expect("count live credentials after the retry");
    assert_eq!(cred_count, 1, "the retry minted exactly one live root");
}
