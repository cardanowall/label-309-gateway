//! End-to-end proof that the admin CLI drives the control plane over HTTP and
//! that the bundled admin UI is served exactly as the binary ships it.
//!
//! This is the slice's gate. It boots the real control router (plus the `/admin`
//! route the binary mounts) against a fresh Postgres, then exercises the *actual
//! compiled binary's* `admin` subcommand as a subprocess: a working CLI over HTTP
//! is the proof the control contract works, because the CLI is just another HTTP
//! client (never a direct database connection). Assertions check observable
//! end-state, the CLI's own stdout, and HTTP status codes, never log strings.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::net::SocketAddr;
use std::process::Command;

use ans104::{Ans104Signer, ArweaveJwkSigner};
use chrono::Duration;
use gateway::bootstrap::{self, Provisioning};
use gateway::config::{ControlSettings, GatewayConfig, WebhookSettings};
use gateway_core::api::control::credential::mint_root_credential;
use gateway_core::api::{
    control_router, ControlConfig, ControlFundingKey, ControlState, ControlWalletKey,
};
use gateway_core::runtime::policy::reconcile;
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use gateway_core::wallet::keyring::{arweave_address, derive_enterprise_address};
use gateway_core::wallet::replenish::replenish_policy;
use zeroize::Zeroizing;

/// The control secret prefix the test deployment mints under.
const SECRET_PREFIX: &str = "ctl_";

/// The ed25519 seed the test instance derives its one held Cardano signing key
/// from. The wallet-register route refuses an address no instance signer backs, so
/// the harness declares it physically holds a signer for exactly this address.
const HELD_WALLET_SEED: u8 = 0x42;

/// A real 4096-bit Arweave RSA JWK fixture, shared with the ANS-104 vector suite.
/// The storage-source register route refuses an address no instance signer backs,
/// so the harness declares it holds this signer.
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// The preprod enterprise address the held Cardano seed derives to, through the
/// same keyring path the unlock uses, so the test pins no magic string.
fn held_wallet_address() -> String {
    let key = pallas_crypto::key::ed25519::SecretKey::from([HELD_WALLET_SEED; 32]);
    let mut vk = [0u8; 32];
    vk.copy_from_slice(key.public_key().as_ref());
    derive_enterprise_address(&vk, Network::Preprod).expect("derive preprod address")
}

/// The Arweave address the fixture JWK derives to, through the same keyring path
/// the unlock uses, so the test pins no magic string.
fn held_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

/// A minimal resolved config for the bootstrap path: bootstrap only touches the
/// pool and the control settings.
fn config() -> GatewayConfig {
    let band = LovelaceBand::new(4_000_000, 8_000_000, 6_000_000).expect("band");
    let wallet = WalletConfig::new(
        Network::Preprod,
        band,
        std::time::Duration::from_secs(120),
        4,
    )
    .expect("wallet");
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
            secret_prefix: SECRET_PREFIX.to_string(),
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

/// Build the control state the served router runs over, declaring the instance
/// physically holds a signer for the one wallet address and the one funding address
/// the CLI tests register (the register routes refuse an address no signer backs).
fn control_state(pool: sqlx::PgPool) -> ControlState {
    ControlState::with_keys(
        pool,
        ControlConfig {
            problem_type_base: "https://errors.example/control".to_string(),
            secret_prefix: SECRET_PREFIX.to_string(),
            operator_token_ttl: Duration::seconds(3600),
            account_token_ttl: Duration::seconds(3600),
            adjustment_cap_usd_micros: 10_000_000_000,
            admin_ui_enabled: true,
            default_wallet_scope: gateway_core::api::DefaultWalletScope::Service,
            default_storage_scope: gateway_core::api::DefaultStorageScope::Service,
            ..Default::default()
        },
        vec![ControlWalletKey {
            address: held_wallet_address(),
            label: "held-wallet".to_string(),
        }],
        vec![ControlFundingKey {
            address: held_arweave_address(),
            label: "held-storage".to_string(),
        }],
    )
}

/// Spawn the served router on an ephemeral port and return its base URL plus a
/// handle whose drop aborts the server task.
async fn serve(router: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    (format!("http://{addr}"), handle)
}

/// Run the compiled binary's `admin` subcommand against `base_url` with `token`,
/// piping the bearer through `--token-stdin` (the credential never rides argv —
/// the argv `--token` flag no longer exists).
///
/// The admin binary is a blocking, one-shot HTTP client, so it is driven through
/// [`tokio::task::spawn_blocking`]: spawning and waiting on a child process must
/// not block a runtime worker (and would otherwise interfere with the in-process
/// server task sharing the runtime).
async fn run_admin(base_url: &str, token: &str, args: &[&str]) -> (bool, String, String) {
    let exe = env!("CARGO_BIN_EXE_gateway");
    // The admin CLI is configured with the FULL control-plane base including the
    // version segment; it appends only the bare resource suffix per call.
    let control_base = format!("{base_url}/control/v1");
    let token = token.to_string();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(exe)
            .arg("admin")
            .args(&args)
            .arg("--url")
            .arg(&control_base)
            .arg("--token-stdin")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the gateway admin subprocess");
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().expect("child stdin is piped");
            writeln!(stdin, "{token}").expect("write the bearer to the child's stdin");
            // Dropping the handle closes the pipe so the child's read_to_string ends.
        }
        let output = child
            .wait_with_output()
            .expect("wait for the gateway admin subprocess");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    })
    .await
    .expect("join the admin subprocess task")
}

/// Run the `admin` subcommand sourcing the bearer from the `GATEWAY_CONTROL_TOKEN`
/// environment variable rather than a stdin pipe.
///
/// This is the credential-hygiene posture the root-gated register commands steer a
/// caller toward: a high-authority token on argv leaks into shell history and
/// process listings, so the env-var source is the recommended one and the test
/// exercises that exact path end to end.
async fn run_admin_env_token(base_url: &str, token: &str, args: &[&str]) -> (bool, String, String) {
    let exe = env!("CARGO_BIN_EXE_gateway");
    // The admin CLI is configured with the FULL control-plane base including the
    // version segment; it appends only the bare resource suffix per call.
    let control_base = format!("{base_url}/control/v1");
    let token = token.to_string();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let output = Command::new(exe)
            .arg("admin")
            .args(&args)
            .arg("--url")
            .arg(&control_base)
            .env("GATEWAY_CONTROL_TOKEN", &token)
            .output()
            .expect("spawn the gateway admin subprocess");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    })
    .await
    .expect("join the admin subprocess task")
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cli_drives_account_and_key_lifecycle_over_http() {
    let db = TestDb::fresh().await.expect("fresh db");

    // Provision the control plane exactly as the operator would: bootstrap creates
    // the operator, registers the manual-adjustment kind, and mints a root
    // credential. Bootstrap only PRINTS its secret, so to obtain a usable bearer
    // for the CLI we mint a second root credential here (test setup) and capture
    // its plaintext. The operator id is read back from the row bootstrap created.
    bootstrap::run(
        &db.pool,
        &config(),
        "primary-operator",
        Provisioning::FreshOnly,
    )
    .await
    .expect("bootstrap");
    let operator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM cw_core.operator LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .expect("operator id");
    let root = mint_root_credential(&db.pool, operator_id, SECRET_PREFIX, Some("test-root"))
        .await
        .expect("mint root credential");

    let (base_url, server) = serve(control_router(control_state(db.pool.clone()))).await;

    // The root credential mints a short-lived operator token through the CLI: this
    // is the real `token mint operator` path, authenticated by the root bearer.
    let (ok, stdout, stderr) =
        run_admin(&base_url, &root.secret, &["token", "mint", "operator"]).await;
    assert!(ok, "token mint operator failed: {stderr}");
    let operator_token = parse_secret_line(&stdout, "operator token (shown once):")
        .expect("operator token printed once on stdout");

    // From here on the CLI presents the operator token. Create an account.
    let (ok, stdout, stderr) = run_admin(&base_url, &operator_token, &["account", "create"]).await;
    assert!(ok, "account create failed: {stderr}");
    assert!(
        stdout.contains("account created:"),
        "account create prints the new id, got: {stdout}"
    );

    // The account exists in the database: exactly one, active, owned by the
    // operator. Read its id back to thread it into the key commands (the mutation
    // still went through the CLI over HTTP; this is only how the test learns the id
    // the CLI minted).
    let account_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT a.id FROM cw_api.account a \
           JOIN cw_core.account_detail d ON d.account_id = a.id \
         WHERE d.operator_id = $1 AND d.status = 'active'",
    )
    .bind(operator_id)
    .fetch_one(&db.pool)
    .await
    .expect("the CLI-created account exists");

    // Create an api key for that account through the CLI.
    let (ok, stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &[
            "key",
            "create",
            &account_id.to_string(),
            "poe:read,poe:create",
        ],
    )
    .await;
    assert!(ok, "key create failed: {stderr}");
    let key_id =
        parse_field_line(&stdout, "key created:").expect("key create prints the new key id");
    assert!(
        stdout.contains("secret (shown once):"),
        "key create surfaces the once-shown secret, got: {stdout}"
    );

    // The key is persisted with the scopes the CLI requested, un-revoked.
    let scopes: Vec<String> = sqlx::query_scalar(
        "SELECT scopes FROM cw_core.api_key WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(uuid::Uuid::parse_str(&key_id).expect("key id is a uuid"))
    .fetch_one(&db.pool)
    .await
    .expect("the CLI-created key exists and is live");
    assert_eq!(
        scopes,
        vec!["poe:read".to_string(), "poe:create".to_string()],
        "the key carries exactly the scopes the CLI requested"
    );

    // The CLI sees the key it created via `key list`: the round-trip the task
    // names. The listed row carries the same key id.
    let (ok, stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &["key", "list", &account_id.to_string()],
    )
    .await;
    assert!(ok, "key list failed: {stderr}");
    assert!(
        stdout.contains(&key_id),
        "key list shows the key the CLI just created (id {key_id}), got: {stdout}"
    );

    // An operator-level mutation also lands an audit row the CLI can tail: the
    // account.create above. `audit tail` renders it.
    let (ok, stdout, stderr) =
        run_admin(&base_url, &operator_token, &["audit", "tail", "50"]).await;
    assert!(ok, "audit tail failed: {stderr}");
    assert!(
        stdout.contains("account.create") && stdout.contains("key.create"),
        "the audit tail surfaces the mutations the CLI performed, got: {stdout}"
    );

    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cli_rejects_a_request_with_no_valid_token() {
    let db = TestDb::fresh().await.expect("fresh db");
    bootstrap::run(
        &db.pool,
        &config(),
        "primary-operator",
        Provisioning::FreshOnly,
    )
    .await
    .expect("bootstrap");
    let (base_url, server) = serve(control_router(control_state(db.pool.clone()))).await;

    // A garbage token cannot drive any operator route: the CLI exits non-zero and
    // surfaces the control plane's rejection rather than silently succeeding.
    let (ok, _stdout, stderr) =
        run_admin(&base_url, "ctl_not-a-real-token", &["account", "list"]).await;
    assert!(!ok, "an unauthenticated admin command must fail");
    assert!(
        !stderr.is_empty(),
        "the CLI surfaces the rejection on stderr, got empty"
    );

    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cli_drives_wallet_register_grant_revoke_over_http() {
    let db = TestDb::fresh().await.expect("fresh db");
    bootstrap::run(
        &db.pool,
        &config(),
        "primary-operator",
        Provisioning::FreshOnly,
    )
    .await
    .expect("bootstrap");
    // The wallet-register route enqueues a targeted replenish job inside its
    // register transaction, which resolves its attempt/backoff defaults from the
    // wallet_replenish queue_policy row. The production binary reconciles that
    // policy at boot; this harness serves only the control router (no Runtime), so
    // it must reconcile the policy itself or the enqueue fails with UnknownQueue and
    // the register route 500s before the assertions run.
    reconcile(&db.pool, &replenish_policy())
        .await
        .expect("reconcile replenish policy");
    let operator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM cw_core.operator LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .expect("operator id");
    let root = mint_root_credential(&db.pool, operator_id, SECRET_PREFIX, Some("test-root"))
        .await
        .expect("mint root credential");

    let (base_url, server) = serve(control_router(control_state(db.pool.clone()))).await;

    // Mint a non-root operator token through the CLI: it drives the operator-gated
    // grant routes but is rejected by the root-gated register route below.
    let (ok, stdout, stderr) =
        run_admin(&base_url, &root.secret, &["token", "mint", "operator"]).await;
    assert!(ok, "token mint operator failed: {stderr}");
    let operator_token = parse_secret_line(&stdout, "operator token (shown once):")
        .expect("operator token printed once on stdout");

    let address = held_wallet_address();

    // A non-root operator token cannot register a wallet: the route is root-gated
    // server-side, and the CLI carries no client-side authority logic, so it
    // forwards the non-root bearer and surfaces the route's rejection (non-zero
    // exit), never silently succeeding.
    let (ok, _stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &["wallet", "register", "primary", &address, "preprod"],
    )
    .await;
    assert!(
        !ok,
        "a non-root credential must be rejected by the root-gated register route"
    );
    assert!(
        !stderr.is_empty(),
        "the CLI surfaces the route's 403 on stderr, got empty"
    );
    let registered_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.operator_wallet WHERE address = $1")
            .bind(&address)
            .fetch_one(&db.pool)
            .await
            .expect("count wallets");
    assert_eq!(
        registered_count, 0,
        "the rejected register wrote no wallet row"
    );

    // The root credential registers the wallet, sourced through GATEWAY_CONTROL_TOKEN
    // (the credential-hygiene path the usage steers a root credential toward).
    let (ok, stdout, stderr) = run_admin_env_token(
        &base_url,
        &root.secret,
        &["wallet", "register", "primary", &address, "preprod"],
    )
    .await;
    assert!(ok, "root wallet register failed: {stderr}");
    assert!(
        stdout.contains("registered") && stdout.contains("grant"),
        "register prints the wallet id, created flag, and auto-issued grant id, got: {stdout}"
    );

    // The wallet row exists, owned by the operator, with the auto-issued service
    // grant live (the register route auto-grants the default scope).
    let wallet_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM cw_core.operator_wallet WHERE address = $1 AND registrar_operator_id = $2",
    )
    .bind(&address)
    .bind(operator_id)
    .fetch_one(&db.pool)
    .await
    .expect("the CLI-registered wallet exists under the operator");
    let live_grants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_grant WHERE wallet_id = $1 AND revoked_at IS NULL",
    )
    .bind(wallet_id)
    .fetch_one(&db.pool)
    .await
    .expect("count live grants");
    assert_eq!(
        live_grants, 1,
        "registration auto-issues exactly one live grant"
    );

    // Issue a second, account-scoped grant through the operator-gated grant route.
    // The account must belong to the registrar, so create one first via the CLI.
    let (ok, stdout, stderr) = run_admin(&base_url, &operator_token, &["account", "create"]).await;
    assert!(ok, "account create failed: {stderr}");
    let account_id =
        parse_field_line(&stdout, "account created:").expect("account create prints the new id");

    let (ok, stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &[
            "wallet",
            "grant",
            &wallet_id.to_string(),
            "account",
            &account_id,
        ],
    )
    .await;
    assert!(ok, "wallet grant failed: {stderr}");
    assert!(
        stdout.contains("issued=true"),
        "the account grant is freshly issued, got: {stdout}"
    );
    let new_grant_id = parse_grant_id(&stdout).expect("the grant line carries the issued grant id");

    // Two live grants now (the auto service grant + the account grant).
    let live_grants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_grant WHERE wallet_id = $1 AND revoked_at IS NULL",
    )
    .bind(wallet_id)
    .fetch_one(&db.pool)
    .await
    .expect("count live grants");
    assert_eq!(
        live_grants, 2,
        "the account grant is live alongside the service grant"
    );

    // Revoke the account grant through the CLI: the row's revoked_at is stamped.
    let (ok, stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &[
            "wallet",
            "grant-revoke",
            &wallet_id.to_string(),
            &new_grant_id,
        ],
    )
    .await;
    assert!(ok, "wallet grant-revoke failed: {stderr}");
    assert!(
        stdout.contains("revoked=true"),
        "the grant revoke reports the transition, got: {stdout}"
    );
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM cw_core.wallet_grant WHERE id = $1")
            .bind(uuid::Uuid::parse_str(&new_grant_id).expect("grant id is a uuid"))
            .fetch_one(&db.pool)
            .await
            .expect("the revoked grant row exists");
    assert!(
        revoked_at.is_some(),
        "grant-revoke stamps revoked_at on the grant row"
    );

    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cli_drives_storage_source_register_grant_revoke_over_http() {
    let db = TestDb::fresh().await.expect("fresh db");
    bootstrap::run(
        &db.pool,
        &config(),
        "primary-operator",
        Provisioning::FreshOnly,
    )
    .await
    .expect("bootstrap");
    let operator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM cw_core.operator LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .expect("operator id");
    let root = mint_root_credential(&db.pool, operator_id, SECRET_PREFIX, Some("test-root"))
        .await
        .expect("mint root credential");

    let (base_url, server) = serve(control_router(control_state(db.pool.clone()))).await;

    let (ok, stdout, stderr) =
        run_admin(&base_url, &root.secret, &["token", "mint", "operator"]).await;
    assert!(ok, "token mint operator failed: {stderr}");
    let operator_token = parse_secret_line(&stdout, "operator token (shown once):")
        .expect("operator token printed once on stdout");

    let address = held_arweave_address();

    // The root credential registers a funding source (root-gated, like the wallet
    // register), through GATEWAY_CONTROL_TOKEN.
    let (ok, stdout, stderr) = run_admin_env_token(
        &base_url,
        &root.secret,
        &[
            "storage", "source", "register", "primary", "arlocal", &address,
        ],
    )
    .await;
    assert!(ok, "root storage source register failed: {stderr}");
    assert!(
        stdout.contains("registered") && stdout.contains("grant"),
        "register prints the source id, created flag, and auto-issued grant id, got: {stdout}"
    );

    let source_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM cw_core.storage_funding_source \
         WHERE arweave_address = $1 AND owner_operator_id = $2",
    )
    .bind(&address)
    .bind(operator_id)
    .fetch_one(&db.pool)
    .await
    .expect("the CLI-registered source exists under the operator");

    // A non-root operator token cannot register a source: the route is root-gated.
    let (ok, _stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &[
            "storage", "source", "register", "second", "arlocal", &address,
        ],
    )
    .await;
    assert!(
        !ok,
        "a non-root credential must be rejected by the root-gated source register route"
    );
    assert!(!stderr.is_empty(), "the CLI surfaces the route's rejection");

    // Issue an operator-scoped grant on the source through the operator-gated route,
    // then revoke it; the revoked_at is stamped on the grant row.
    let (ok, stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &[
            "storage",
            "source",
            "grant",
            &source_id.to_string(),
            "operator",
        ],
    )
    .await;
    assert!(ok, "storage source grant failed: {stderr}");
    let grant_id = parse_grant_id(&stdout).expect("the grant line carries the issued grant id");

    let (ok, stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &[
            "storage",
            "source",
            "grant-revoke",
            &source_id.to_string(),
            &grant_id,
        ],
    )
    .await;
    assert!(ok, "storage source grant-revoke failed: {stderr}");
    assert!(
        stdout.contains("revoked=true"),
        "the source grant revoke reports the transition, got: {stdout}"
    );
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM cw_core.storage_grant WHERE id = $1")
            .bind(uuid::Uuid::parse_str(&grant_id).expect("grant id is a uuid"))
            .fetch_one(&db.pool)
            .await
            .expect("the revoked source grant row exists");
    assert!(
        revoked_at.is_some(),
        "grant-revoke stamps revoked_at on the source grant row"
    );

    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cli_drives_the_storage_funding_console_over_http() {
    let db = TestDb::fresh().await.expect("fresh db");
    bootstrap::run(
        &db.pool,
        &config(),
        "primary-operator",
        Provisioning::FreshOnly,
    )
    .await
    .expect("bootstrap");
    let operator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM cw_core.operator LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .expect("operator id");
    let root = mint_root_credential(&db.pool, operator_id, SECRET_PREFIX, Some("test-root"))
        .await
        .expect("mint root credential");

    let (base_url, server) = serve(control_router(control_state(db.pool.clone()))).await;

    let (ok, stdout, stderr) =
        run_admin(&base_url, &root.secret, &["token", "mint", "operator"]).await;
    assert!(ok, "token mint operator failed: {stderr}");
    let operator_token = parse_secret_line(&stdout, "operator token (shown once):")
        .expect("operator token printed once on stdout");

    // Register one funding source so the roll-up has something to aggregate.
    let address = held_arweave_address();
    let (ok, _stdout, stderr) = run_admin_env_token(
        &base_url,
        &root.secret,
        &[
            "storage", "source", "register", "primary", "arlocal", &address,
        ],
    )
    .await;
    assert!(ok, "storage source register failed: {stderr}");

    // The cached funding roll-up sees exactly the one registered source.
    let (ok, stdout, stderr) = run_admin(&base_url, &operator_token, &["storage", "funding"]).await;
    assert!(ok, "storage funding failed: {stderr}");
    assert!(
        stdout.contains("sources=1"),
        "the roll-up counts the registered source, got: {stdout}"
    );

    // The conversion journal reads fine while empty: it prints the one-line notice
    // (never a silent blank) and exits zero.
    let (ok, stdout, stderr) = run_admin(&base_url, &operator_token, &["storage", "top-ups"]).await;
    assert!(ok, "storage top-ups failed: {stderr}");
    assert_eq!(
        stdout.trim(),
        "no top-ups",
        "an empty journal prints the notice, got: {stdout:?}"
    );

    // The live balance console degrades gracefully on a deployment with no
    // [storage] configured, and says why a top-up cannot be issued.
    let (ok, stdout, stderr) =
        run_admin(&base_url, &operator_token, &["storage", "operator-balance"]).await;
    assert!(ok, "storage operator-balance failed: {stderr}");
    assert!(
        stdout.contains("storage_configured=false")
            && stdout.contains("top-up: disabled (storage-not-configured)"),
        "the console reports the unconfigured backend and the blocking reason, got: {stdout}"
    );

    // A top-up create on the unconfigured deployment fails CLEANLY: the CLI
    // exits non-zero and surfaces the API's problem detail — proof the command
    // reaches the money route with a parsed body rather than erroring locally.
    let (ok, _stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &["storage", "top-up", "1000000000", "cli-e2e-topup-1"],
    )
    .await;
    assert!(!ok, "a top-up without a storage backend must fail");
    assert!(
        !stderr.is_empty(),
        "the CLI surfaces the API's rejection on stderr, got empty"
    );
    // No conversion row was journalled by the refused create.
    let topup_count: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.storage_topup")
        .fetch_one(&db.pool)
        .await
        .expect("count top-ups");
    assert_eq!(topup_count, 0, "the refused top-up journalled nothing");

    // The idempotency key is a required argument: omitting it fails locally,
    // before any HTTP call, naming the missing argument.
    let (ok, _stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &["storage", "top-up", "1000000000"],
    )
    .await;
    assert!(!ok, "a top-up without an idempotency key must fail");
    assert!(
        stderr.contains("idempotency_key"),
        "the error names the missing argument, got: {stderr}"
    );

    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cli_drives_margin_override_and_source_drain_over_http() {
    let db = TestDb::fresh().await.expect("fresh db");
    bootstrap::run(
        &db.pool,
        &config(),
        "primary-operator",
        Provisioning::FreshOnly,
    )
    .await
    .expect("bootstrap");
    let operator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM cw_core.operator LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .expect("operator id");
    let root = mint_root_credential(&db.pool, operator_id, SECRET_PREFIX, Some("test-root"))
        .await
        .expect("mint root credential");

    let (base_url, server) = serve(control_router(control_state(db.pool.clone()))).await;

    let (ok, stdout, stderr) =
        run_admin(&base_url, &root.secret, &["token", "mint", "operator"]).await;
    assert!(ok, "token mint operator failed: {stderr}");
    let operator_token = parse_secret_line(&stdout, "operator token (shown once):")
        .expect("operator token printed once on stdout");

    // Create an account, then set a per-account margin override through the CLI.
    let (ok, stdout, stderr) = run_admin(&base_url, &operator_token, &["account", "create"]).await;
    assert!(ok, "account create failed: {stderr}");
    let account_id =
        parse_field_line(&stdout, "account created:").expect("account create prints the new id");

    let (ok, stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &["account", "margin", "set", &account_id, "0.25"],
    )
    .await;
    assert!(ok, "account margin set failed: {stderr}");
    assert!(
        stdout.contains("account-override"),
        "the set reports the override source, got: {stdout}"
    );

    // The override row is persisted at exactly the fraction the CLI sent (read as
    // text so the test needs no decimal dependency of its own).
    let stored: String = sqlx::query_scalar(
        "SELECT margin_pct::text FROM cw_core.account_margin_override WHERE account_id = $1",
    )
    .bind(uuid::Uuid::parse_str(&account_id).expect("account id is a uuid"))
    .fetch_one(&db.pool)
    .await
    .expect("the CLI-set override row exists");
    assert_eq!(
        stored.parse::<f64>().expect("margin is numeric"),
        0.25,
        "the persisted override is the fraction the CLI set"
    );

    // Clearing it through the CLI removes the row (reverting to the operator default).
    let (ok, stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &["account", "margin", "unset", &account_id],
    )
    .await;
    assert!(ok, "account margin unset failed: {stderr}");
    assert!(
        stdout.contains("cleared=true"),
        "the unset reports the clear, got: {stdout}"
    );
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.account_margin_override WHERE account_id = $1",
    )
    .bind(uuid::Uuid::parse_str(&account_id).expect("account id is a uuid"))
    .fetch_one(&db.pool)
    .await
    .expect("count overrides");
    assert_eq!(remaining, 0, "the cleared override left no row");

    // Register a funding source (root-gated), then drain it through the CLI.
    let address = held_arweave_address();
    let (ok, _stdout, stderr) = run_admin_env_token(
        &base_url,
        &root.secret,
        &[
            "storage", "source", "register", "primary", "arlocal", &address,
        ],
    )
    .await;
    assert!(ok, "storage source register failed: {stderr}");
    let source_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM cw_core.storage_funding_source \
         WHERE arweave_address = $1 AND owner_operator_id = $2",
    )
    .bind(&address)
    .bind(operator_id)
    .fetch_one(&db.pool)
    .await
    .expect("the CLI-registered source exists");

    let (ok, stdout, stderr) = run_admin(
        &base_url,
        &operator_token,
        &["storage", "source", "drain", &source_id.to_string()],
    )
    .await;
    assert!(ok, "storage source drain failed: {stderr}");
    assert!(
        stdout.contains("draining"),
        "the drain reports the transition, got: {stdout}"
    );
    let status: String =
        sqlx::query_scalar("SELECT status::text FROM cw_core.storage_funding_source WHERE id = $1")
            .bind(source_id)
            .fetch_one(&db.pool)
            .await
            .expect("the source row exists");
    assert_eq!(
        status, "draining",
        "the CLI drain moved the source to draining"
    );

    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_ui_serves_when_mounted_is_absent_when_not_and_its_api_requires_a_token() {
    let db = TestDb::fresh().await.expect("fresh db");
    bootstrap::run(
        &db.pool,
        &config(),
        "primary-operator",
        Provisioning::FreshOnly,
    )
    .await
    .expect("bootstrap");

    // The router the binary serves when the admin UI is enabled: the control plane
    // plus the mounted `/admin` route (the same `mount_admin_ui` the binary uses).
    let enabled = gateway::mount_admin_ui(control_router(control_state(db.pool.clone())));
    let (base_url, server) = serve(enabled).await;
    let client = reqwest::Client::new();

    // GET /admin serves the bundled HTML page (200, text/html), and the page is the
    // real bundled asset (it references the control API it drives).
    let res = client
        .get(format!("{base_url}/admin"))
        .send()
        .await
        .expect("GET /admin");
    assert_eq!(res.status(), reqwest::StatusCode::OK, "the UI route serves");
    let content_type = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "the UI route serves HTML, got content-type {content_type}"
    );
    let body = res.text().await.expect("read body");
    assert!(
        body.contains("/control/v1") && body.contains("Bearer"),
        "the served page is the bundled admin UI that drives the control plane with a token"
    );

    // The control endpoints the page calls require a token: an anonymous GET is
    // rejected (the page's auth is the token it presents, not the static route).
    let res = client
        .get(format!("{base_url}/control/v1/accounts"))
        .send()
        .await
        .expect("anonymous GET /control/v1/accounts");
    assert_eq!(
        res.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the control API the UI drives requires a token"
    );
    server.abort();

    // A router built WITHOUT mounting the UI does not serve `/admin`: that is the
    // disable-flag behaviour (the binary skips `mount_admin_ui` when the flag is
    // off), so the route is simply not present.
    let disabled = control_router(control_state(db.pool.clone()));
    let (base_url, server) = serve(disabled).await;
    let res = client
        .get(format!("{base_url}/admin"))
        .send()
        .await
        .expect("GET /admin on the disabled router");
    assert_eq!(
        res.status(),
        reqwest::StatusCode::NOT_FOUND,
        "with the UI disabled the /admin route is absent"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cli_rotates_the_root_and_revokes_tokens_over_http() {
    let db = TestDb::fresh().await.expect("fresh db");
    bootstrap::run(
        &db.pool,
        &config(),
        "primary-operator",
        Provisioning::FreshOnly,
    )
    .await
    .expect("bootstrap");
    let operator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM cw_core.operator LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .expect("operator id");
    // Bootstrap's own root: its secret went to bootstrap's stdout, but its ROW
    // is live — the test retires it later to reach the last-live-root refusal.
    let bootstrap_root_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM cw_core.control_credential WHERE operator_id = $1")
            .bind(operator_id)
            .fetch_one(&db.pool)
            .await
            .expect("bootstrap root id");
    // Bootstrap only prints its secret; mint a root here (test setup) to hold a
    // usable bearer, exactly as the account/key lifecycle test does.
    let root = mint_root_credential(&db.pool, operator_id, SECRET_PREFIX, Some("initial"))
        .await
        .expect("mint root credential");

    let (base_url, server) = serve(control_router(control_state(db.pool.clone()))).await;

    // A token minted from the pre-rotation root, to prove the rotation kills it.
    let (ok, stdout, stderr) =
        run_admin_env_token(&base_url, &root.secret, &["token", "mint", "operator"]).await;
    assert!(ok, "token mint operator failed: {stderr}");
    let doomed_token = parse_secret_line(&stdout, "operator token (shown once):")
        .expect("operator token printed once on stdout");

    // Rotate through the CLI, sourcing the root from the environment (the
    // credential-hygiene path the usage text mandates for root bearers).
    let (ok, stdout, stderr) = run_admin_env_token(
        &base_url,
        &root.secret,
        &["credential", "rotate-root", "vault-2"],
    )
    .await;
    assert!(ok, "credential rotate-root failed: {stderr}");
    assert!(
        stdout.contains("shown once, store it now"),
        "the rotated secret carries the bootstrap-style care framing, got: {stdout}"
    );
    let new_root = parse_framed_secret(&stdout, "new operator root secret")
        .expect("the successor secret printed once on stdout");
    assert_ne!(new_root, root.secret);
    let new_root_id: uuid::Uuid = parse_field_line(&stdout, "  credential_id")
        .and_then(|s| s.parse().ok())
        .expect("the successor credential id printed on stdout");

    // The old root is dead: it can no longer mint.
    let (ok, _, _) =
        run_admin_env_token(&base_url, &root.secret, &["token", "mint", "operator"]).await;
    assert!(!ok, "the rotated-away root must not mint tokens");
    // The token minted from the old root died with it (the mint lineage).
    let (ok, _, _) = run_admin_env_token(&base_url, &doomed_token, &["account", "list"]).await;
    assert!(
        !ok,
        "a token minted from the rotated-away root must be dead"
    );

    // The successor works: it mints a fresh operator token.
    let (ok, stdout, stderr) =
        run_admin_env_token(&base_url, &new_root, &["token", "mint", "operator"]).await;
    assert!(ok, "the successor root must mint tokens: {stderr}");
    let fresh_token = parse_secret_line(&stdout, "operator token (shown once):")
        .expect("fresh operator token printed");
    let fresh_token_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM cw_core.access_token \
         WHERE revoked_at IS NULL AND account_id IS NULL \
         ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&db.pool)
    .await
    .expect("fresh token id");

    // The roster lists it; the targeted revoke kills exactly it.
    let (ok, stdout, stderr) =
        run_admin_env_token(&base_url, &fresh_token, &["token", "list"]).await;
    assert!(ok, "token list failed: {stderr}");
    assert!(
        stdout.contains(&fresh_token_id.to_string()),
        "token list must show the freshly minted token, got: {stdout}"
    );
    let (ok, stdout, stderr) = run_admin_env_token(
        &base_url,
        &new_root,
        &["token", "revoke", &fresh_token_id.to_string()],
    )
    .await;
    assert!(ok, "token revoke failed: {stderr}");
    assert!(stdout.contains("revoked=true"), "got: {stdout}");
    let (ok, _, _) = run_admin_env_token(&base_url, &fresh_token, &["account", "list"]).await;
    assert!(!ok, "a revoked operator token must stop authenticating");

    // The credential roster shows the rotation history.
    let (ok, stdout, stderr) =
        run_admin_env_token(&base_url, &new_root, &["credential", "list"]).await;
    assert!(ok, "credential list failed: {stderr}");
    assert!(
        stdout.contains(&root.id.to_string()),
        "the revoked predecessor stays listed, got: {stdout}"
    );

    // Retire the stale bootstrap root through the CLI (a second live root, so
    // the guard permits it) ...
    let (ok, stdout, stderr) = run_admin_env_token(
        &base_url,
        &new_root,
        &["credential", "revoke", &bootstrap_root_id.to_string()],
    )
    .await;
    assert!(ok, "credential revoke failed: {stderr}");
    assert!(stdout.contains("revoked=true"), "got: {stdout}");

    // ... which leaves the successor as the operator's ONLY live root: revoking
    // it is refused with the API's problem detail.
    let (ok, _, stderr) = run_admin_env_token(
        &base_url,
        &new_root,
        &["credential", "revoke", &new_root_id.to_string()],
    )
    .await;
    assert!(!ok, "revoking the only live root must be refused");
    assert!(
        stderr.contains("only live root"),
        "the refusal surfaces the API's problem detail, got: {stderr}"
    );

    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn control_docs_ui_serves_the_vendored_renderer_offline() {
    let db = TestDb::fresh().await.expect("fresh db");
    bootstrap::run(
        &db.pool,
        &config(),
        "primary-operator",
        Provisioning::FreshOnly,
    )
    .await
    .expect("bootstrap");
    let (base_url, server) = serve(control_router(control_state(db.pool.clone()))).await;
    let client = reqwest::Client::new();

    // The control-plane docs page is public — the same posture as openapi.json — so
    // an anonymous GET serves it (the page embeds no secret; a token is only needed
    // to CALL an endpoint). The served HTML names no external origin and loads its
    // renderer from this gateway, so the page works fully offline.
    let res = client
        .get(format!("{base_url}/control/v1/docs"))
        .send()
        .await
        .expect("GET /control/v1/docs");
    assert_eq!(
        res.status(),
        reqwest::StatusCode::OK,
        "the control docs page serves without a token"
    );
    let content_type = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "the docs page is HTML, got content-type {content_type}"
    );
    let html = res.text().await.expect("read the docs page body");
    assert!(
        !html.contains("http://") && !html.contains("https://"),
        "the served HTML names no external origin, got: {html}"
    );
    assert!(
        html.contains("src=\"docs/scalar.js\""),
        "the page loads the vendored renderer bundle from this gateway"
    );

    // The renderer bundle serves at the sibling path with a caching header and is
    // the vendored artifact itself (not a redirect to a CDN).
    let res = client
        .get(format!("{base_url}/control/v1/docs/scalar.js"))
        .send()
        .await
        .expect("GET /control/v1/docs/scalar.js");
    assert_eq!(
        res.status(),
        reqwest::StatusCode::OK,
        "the renderer bundle serves"
    );
    let content_type = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.contains("javascript"),
        "the bundle is served as JavaScript, got content-type {content_type}"
    );
    assert!(
        res.headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .contains("max-age="),
        "the bundle carries a long-lived caching header"
    );
    let body = res.text().await.expect("read the bundle");
    assert!(
        body.contains("@scalar/api-reference 1.61.0"),
        "the served bundle is the vendored renderer, banner intact"
    );

    server.abort();
}

/// An empty list prints a one-line `no <things>` notice, never a silent blank, so an
/// operator can tell "nothing here" apart from a command that produced no output at
/// all. Right after bootstrap the operator holds no accounts and no registered
/// wallets, so both list commands render their empty notice on stdout.
#[tokio::test(flavor = "multi_thread")]
async fn admin_cli_empty_lists_print_a_notice_not_a_blank() {
    let db = TestDb::fresh().await.expect("fresh db");
    bootstrap::run(
        &db.pool,
        &config(),
        "primary-operator",
        Provisioning::FreshOnly,
    )
    .await
    .expect("bootstrap");
    let operator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM cw_core.operator LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .expect("operator id");
    let root = mint_root_credential(&db.pool, operator_id, SECRET_PREFIX, Some("test-root"))
        .await
        .expect("mint root credential");

    let (base_url, server) = serve(control_router(control_state(db.pool.clone()))).await;

    let (ok, stdout, stderr) =
        run_admin(&base_url, &root.secret, &["token", "mint", "operator"]).await;
    assert!(ok, "token mint operator failed: {stderr}");
    let operator_token = parse_secret_line(&stdout, "operator token (shown once):")
        .expect("operator token printed once on stdout");

    // No accounts created yet: the list renders its empty notice, not a blank line.
    let (ok, stdout, stderr) = run_admin(&base_url, &operator_token, &["account", "list"]).await;
    assert!(ok, "account list failed: {stderr}");
    assert_eq!(
        stdout.trim(),
        "no accounts",
        "an empty account list prints the notice, got: {stdout:?}"
    );

    // No wallets registered yet: same one-line notice.
    let (ok, stdout, stderr) = run_admin(&base_url, &operator_token, &["wallet", "list"]).await;
    assert!(ok, "wallet list failed: {stderr}");
    assert_eq!(
        stdout.trim(),
        "no wallets",
        "an empty wallet list prints the notice, got: {stdout:?}"
    );

    server.abort();
}

/// Extract the value after a `label:`-prefixed line, trimmed. Used to read a once-
/// shown secret or token the CLI prints on its own line.
fn parse_secret_line(stdout: &str, label: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(label).map(|rest| rest.trim().to_string()))
        .filter(|s| !s.is_empty())
}

/// Extract the value after a `label:`-prefixed line where the value is a single
/// token (e.g. `account created: <id>` or `key created: <id>`).
fn parse_field_line(stdout: &str, label: &str) -> Option<String> {
    parse_secret_line(stdout, label)
}

/// Extract a bootstrap-style framed secret: the first non-empty line after the
/// marker line (the rotate-root print frames the successor secret exactly as
/// the bootstrap print frames the initial one — on its own indented line).
fn parse_framed_secret(stdout: &str, marker: &str) -> Option<String> {
    stdout
        .lines()
        .skip_while(|l| !l.contains(marker))
        .skip(1)
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// Extract the grant id the wallet/storage grant command prints. Both render a
/// `grant <id> on …` line, so the id is the second whitespace-delimited token of
/// the `grant `-prefixed line.
fn parse_grant_id(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find(|l| l.starts_with("grant "))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(str::to_string)
}
