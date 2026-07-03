//! The gateway application binary.
//!
//! One process that boots the whole base plane: it loads its configuration, runs
//! the engine migrations, assembles the supervised job runtime with every
//! handler and schedule registered, and runs until a termination signal asks it
//! to stop. The runtime's loops are supervised together, so a single failing
//! loop brings the whole process down with a non-zero exit rather than silently
//! degrading.
//!
//! When an `[http]` section is configured the binary also serves the data-plane
//! API ([`gateway_core::api::router`]) beside the background plane: the HTTP
//! server and the runtime are driven together so a shutdown signal stops both and
//! a failure in either brings the process down. Without `[http]` it runs the
//! background plane alone.
//!
//! The binary also carries four non-serving subcommands. `keyring …` creates and
//! edits the age-encrypted operator keyring (generate or import keys, inspect,
//! remove, change the passphrase) without touching the database. `operator
//! bootstrap` provisions the control plane from an empty database (one operator,
//! its root credential, the reference adjustment kind). `storage bootstrap`
//! registers one service-scoped funding source for a backend, so a single-key
//! deployment reaches a working upload without grant choreography. `admin …` is a
//! thin, blocking HTTP client of the control plane the operator drives day to
//! day. The admin and keyring paths run synchronously outside any async runtime;
//! the serving and bootstrap paths build a multi-threaded runtime explicitly and
//! block on it.
//!
//! `--help`/`-h`/`help` prints the top-level usage and `--version`/`-V` prints the
//! version, both to stdout with a zero exit. Serving is the NO-argument behavior
//! only: an unrecognized leading argument prints the usage to stderr and exits
//! nonzero rather than falling through to serve (which would otherwise die on a
//! missing config file, masking the typo).

use std::path::PathBuf;

use anyhow::{Context, Result};
use gateway::assembly;
use gateway::config::GatewayConfig;

/// Environment variable pointing at the TOML configuration file. Defaults to
/// `gateway.toml` in the working directory.
const CONFIG_PATH_ENV: &str = "GATEWAY_CONFIG";

/// The default config file path when [`CONFIG_PATH_ENV`] is unset.
const DEFAULT_CONFIG_PATH: &str = "gateway.toml";

/// Subcommand dispatch.
///
/// `main` is intentionally NOT `#[tokio::main]`: the `admin` subcommand drives a
/// blocking `reqwest` client, and a blocking client cannot be constructed inside a
/// running tokio runtime (it builds its own). So the admin path runs fully
/// synchronously, outside any runtime, and the serve / bootstrap paths build a
/// multi-threaded runtime explicitly and block on their async work.
///
/// The leading-argument routing is a pure [`classify`] decision, so it is
/// unit-tested without a database, a config file, or a runtime; `main` only
/// performs the side effects each [`Command`] names. With no subcommand the binary
/// serves; `--help`/`--version` short-circuit; an unrecognized argument is
/// rejected rather than served.
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match classify(&args) {
        // The admin CLI installs no tracing subscriber (it prints results to
        // stdout) and connects over HTTP, so it needs neither the config file nor
        // the database. It runs synchronously, outside any tokio runtime, so its
        // blocking HTTP client can build its own.
        Command::Admin => gateway::admin::run(&args[1..]),
        Command::OperatorBootstrap => {
            let _sentry_guard = init_tracing()?;
            async_runtime()?.block_on(run_bootstrap(&args[2..]))
        }
        Command::StorageBootstrap => {
            let _sentry_guard = init_tracing()?;
            async_runtime()?.block_on(run_storage_bootstrap(&args[2..]))
        }
        // The keyring CLI is file-local: no database, no HTTP, and no tracing
        // subscriber (it prints results to stdout and must never route key material
        // through a logger). It runs synchronously, like `admin`.
        Command::Keyring => gateway::keyring::run(&args[1..]),
        // No subcommand: serve the background runtime plus, when configured, the
        // HTTP planes.
        Command::Serve => {
            let _sentry_guard = init_tracing()?;
            async_runtime()?.block_on(serve())
        }
        Command::Help => {
            println!("{}", usage());
            Ok(())
        }
        Command::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        // An unrecognized invocation must never fall through to serve — that would
        // die on a missing config file and mask the typo. Print the usage to stderr
        // and exit nonzero.
        Command::Unknown(message) => {
            eprintln!("{}", usage());
            anyhow::bail!("{message}")
        }
    }
}

/// The top-level command an argument list selects.
///
/// The variants that touch a runtime or the filesystem carry no data (`main` reads
/// the remaining arguments itself); `Unknown` carries the message that names what
/// was wrong so the reject path can surface it.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// `admin …` — the blocking HTTP client of the control plane.
    Admin,
    /// `operator bootstrap` — provision the control plane from an empty database.
    OperatorBootstrap,
    /// `storage bootstrap` — register one service-scoped storage funding source.
    StorageBootstrap,
    /// `keyring …` — create and edit the age-encrypted operator keyring.
    Keyring,
    /// No subcommand — serve the background plane plus the HTTP planes.
    Serve,
    /// `--help`/`-h`/`help` — print the usage block to stdout, exit zero.
    Help,
    /// `--version`/`-V` — print the name and version to stdout, exit zero.
    Version,
    /// An unrecognized invocation: the message names what was wrong. `main` prints
    /// the usage block to stderr and exits nonzero.
    Unknown(String),
}

/// Decide which top-level command an argument list selects, as a pure function so
/// the dispatch is unit-testable without a database, a config file, or a runtime.
///
/// The FIRST argument selects the command; `keyring` and `admin` own their own
/// sub-parsing downstream, so only their presence is decided here. `operator` and
/// `storage` each have exactly one subcommand (`bootstrap`), so a wrong or missing
/// second word is rejected here rather than silently served. With NO argument the
/// binary serves; `--help`/`-h`/`help` and `--version`/`-V` short-circuit before
/// the serve path; any other leading argument is unknown — never silently served.
fn classify(args: &[String]) -> Command {
    match args.first().map(String::as_str) {
        None => Command::Serve,
        Some("admin") => Command::Admin,
        Some("keyring") => Command::Keyring,
        Some("operator") => match args.get(1).map(String::as_str) {
            Some("bootstrap") => Command::OperatorBootstrap,
            _ => Command::Unknown(
                "unknown operator subcommand; the only one is 'operator bootstrap'".to_string(),
            ),
        },
        Some("storage") => match args.get(1).map(String::as_str) {
            Some("bootstrap") => Command::StorageBootstrap,
            _ => Command::Unknown(
                "unknown storage subcommand; the only one is 'storage bootstrap'".to_string(),
            ),
        },
        Some("--help" | "-h" | "help") => Command::Help,
        Some("--version" | "-V") => Command::Version,
        Some(other) => Command::Unknown(format!("unknown command: {other}")),
    }
}

/// The top-level usage block: every subcommand plus the no-argument = serve
/// behavior. Returned as a string so `--help` can print it to stdout and an
/// unknown-command error can print the identical block to stderr.
fn usage() -> String {
    format!(
        "{name} {version} — Label 309 Proof-of-Existence gateway.

usage: gateway [<command>] [args]

With no command the binary SERVES: the background plane plus, when an [http]
section is configured, the data and control HTTP planes.

commands:
  (none)                serve the gateway (background plane + HTTP planes)
  operator bootstrap    provision the control plane from an empty database
  storage bootstrap     register one service-scoped storage funding source
  keyring <action>      create and edit the age-encrypted operator keyring
  admin <group> <action>
                        drive the control plane over HTTP (accounts, keys, wallets, …)
  --help, -h, help      print this usage and exit
  --version, -V         print the version and exit

Run `gateway keyring` or `gateway admin` with no valid action to see that
command's own detailed usage.",
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// Build the multi-threaded tokio runtime the async serve / bootstrap paths run on.
///
/// Built explicitly (rather than via `#[tokio::main]`) so the synchronous `admin`
/// path can run with no runtime present at all.
fn async_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the async runtime")
}

/// Serve the gateway: load config, connect, migrate, assemble the supervised
/// runtime, and run the background plane (plus the HTTP planes when configured)
/// until a termination signal asks it to stop.
async fn serve() -> Result<()> {
    let config_path = std::env::var_os(CONFIG_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    let config = GatewayConfig::load(&config_path)
        .with_context(|| format!("loading configuration from {}", config_path.display()))?;

    tracing::info!(
        network = config.wallet.network.as_str(),
        worker_id = %config.worker_id,
        "gateway starting"
    );

    // Decrypt the operator keyring exactly once, before any database work: the
    // scrypt derivation is deliberately expensive, and a bad passphrase should
    // fail the boot before Postgres is even contacted. Every builder below
    // shares this one unlocked keyring.
    let keyring = std::sync::Arc::new(
        assembly::unlock_keyring(&config).context("unlocking the operator keyring")?,
    );
    tracing::info!("operator keyring unlocked");

    let pool = connect_pool(&config.database_url)
        .await
        .context("connecting to Postgres")?;

    // Apply the engine migrations into its own `cw_core` schema before any loop
    // claims work. The migrator is idempotent: an already-migrated database is a
    // no-op.
    gateway_core::MIGRATOR
        .run(&pool)
        .await
        .context("running engine migrations")?;
    tracing::info!("migrations applied");

    let runtime = std::sync::Arc::new(
        assembly::build_runtime(pool.clone(), &config, keyring.clone())
            .await
            .context("assembling the runtime")?,
    );
    tracing::info!("runtime assembled; starting background plane");

    // Translate the first termination signal into a graceful shutdown: the
    // runtime stops claiming new work, finishes in-flight jobs, and returns.
    spawn_signal_shutdown(runtime.clone());

    let result = run_planes(runtime.clone(), pool.clone(), &config, keyring).await;
    pool.close().await;

    match result {
        Ok(()) => {
            tracing::info!("gateway stopped cleanly");
            Ok(())
        }
        Err(e) => {
            tracing::error!(error = %e, "gateway runtime exited with an error");
            Err(e)
        }
    }
}

/// Run the `operator bootstrap` subcommand: load config, connect, migrate, and
/// provision the operator + root credential.
///
/// Accepts an optional `--label <name>` for the operator's display name
/// (defaulting to `operator`) and an optional `--allow-additional` flag that opts
/// into provisioning a second operator against an already-bootstrapped database.
/// Without it, a re-run refuses rather than minting an unexpected root credential.
/// The root secret is printed once to stdout by the bootstrap module; nothing
/// sensitive is logged.
async fn run_bootstrap(args: &[String]) -> Result<()> {
    let label = parse_label_flag(args).unwrap_or_else(|| "operator".to_string());
    let mode = if args.iter().any(|a| a == "--allow-additional") {
        gateway::bootstrap::Provisioning::AllowAdditional
    } else {
        gateway::bootstrap::Provisioning::FreshOnly
    };

    let config_path = std::env::var_os(CONFIG_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    let config = GatewayConfig::load(&config_path)
        .with_context(|| format!("loading configuration from {}", config_path.display()))?;

    let pool = connect_pool(&config.database_url)
        .await
        .context("connecting to Postgres")?;
    gateway_core::MIGRATOR
        .run(&pool)
        .await
        .context("running engine migrations")?;

    let result = gateway::bootstrap::run(&pool, &config, &label, mode).await;
    pool.close().await;
    result
}

/// Parse an optional `--label <name>` flag out of an argument list.
fn parse_label_flag(args: &[String]) -> Option<String> {
    parse_flag_value(args, "--label")
}

/// Run the `storage bootstrap` subcommand: load config, connect, migrate, and
/// register one service-scoped funding source so a single-key deployment reaches a
/// working upload with no grant choreography.
///
/// `--backend <name>` is required (the storage backend the source draws from).
/// `--label <name>` names the source row (defaulting to `primary`). `--key-address
/// <addr>` selects which Arweave key to register when the keyring holds more than
/// one; with a single key it is inferred. `--operator-id <uuid>` selects the owning
/// operator when more than one exists; with a single operator it is inferred. The
/// resolved source + grant ids are printed to stdout by the storage-bootstrap
/// module; nothing sensitive is logged.
async fn run_storage_bootstrap(args: &[String]) -> Result<()> {
    let backend = parse_flag_value(args, "--backend").context(
        "storage bootstrap requires --backend <turbo|direct-arweave|arlocal> to choose the \
         backend the funding source draws from",
    )?;
    let label = parse_flag_value(args, "--label").unwrap_or_else(|| "primary".to_string());
    let key_address = parse_flag_value(args, "--key-address");
    let operator_id = match parse_flag_value(args, "--operator-id") {
        Some(raw) => Some(
            raw.parse()
                .with_context(|| format!("--operator-id {raw:?} is not a valid UUID"))?,
        ),
        None => None,
    };

    let config_path = std::env::var_os(CONFIG_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    let config = GatewayConfig::load(&config_path)
        .with_context(|| format!("loading configuration from {}", config_path.display()))?;

    let pool = connect_pool(&config.database_url)
        .await
        .context("connecting to Postgres")?;
    gateway_core::MIGRATOR
        .run(&pool)
        .await
        .context("running engine migrations")?;

    let result = gateway::storage_bootstrap::run(
        &pool,
        &config,
        &backend,
        &label,
        key_address.as_deref(),
        operator_id,
    )
    .await;
    pool.close().await;
    result
}

/// Parse an optional `--flag <value>` out of an argument list, returning the value
/// that follows the flag's first occurrence.
fn parse_flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            return iter.next().cloned();
        }
    }
    None
}

/// Run the background plane and, when configured, the HTTP data plane together
/// under one supervised set.
///
/// The two planes share the runtime's shutdown signal: the HTTP server's
/// graceful-shutdown future resolves when the runtime is asked to stop, and the
/// signal handler that stops the runtime therefore stops the server too. If
/// either plane returns (cleanly or with an error) the other is asked to stop, so
/// a failed HTTP bind or a failed runtime loop brings the whole process down
/// rather than leaving a half-running gateway.
///
/// When the first plane finishes it only *initiates* shutdown; the second plane
/// is then awaited to completion (bounded by [`PLANE_DRAIN_TIMEOUT`]) so its own
/// graceful path runs. For the background plane that path is the runtime's
/// drain — in-flight jobs finish or cleanly checkpoint rather than being aborted
/// mid-work. The bound guarantees a wedged plane can delay but never block
/// shutdown indefinitely.
///
/// The keyring is the one unlocked keyring `serve` decrypted at boot; every
/// HTTP-plane seam built here derives from it rather than re-running the
/// expensive scrypt unlock.
async fn run_planes(
    runtime: std::sync::Arc<gateway_core::runtime::Runtime>,
    pool: sqlx::PgPool,
    config: &GatewayConfig,
    keyring: std::sync::Arc<gateway_core::wallet::keyring::UnlockedKeyring>,
) -> Result<()> {
    let Some(http) = config.http.clone() else {
        // No HTTP plane configured: run the background plane alone.
        return runtime.run().await.map_err(|e| anyhow::anyhow!(e));
    };

    // Wire the pricing seam so the data plane can price and persist quotes. When
    // `[fx]` is configured the live DB-backed seam prices every quote from the
    // newest snapshot the FX refresh loop writes (the live path); otherwise the
    // static seam prices from the operator-configured `[http]` rate (the offline /
    // test path). Both implement the engine's `PricingSource`, so the data plane is
    // unchanged either way.
    let pricing: std::sync::Arc<dyn gateway_core::api::state::DynPricingSource> =
        if config.fx.is_some() {
            std::sync::Arc::new(
                assembly::build_pg_pricing(pool.clone(), config, &http, &keyring)
                    .context("building the live FX pricing seam")?,
            )
        } else {
            std::sync::Arc::new(
                assembly::build_pricing(pool.clone(), config, &http, &keyring)
                    .context("building the static pricing seam")?,
            )
        };

    // The free-storage window is a property of `[storage]` (it is netted off every
    // chargeable upload), so it is sourced from the resolved storage config when the
    // deployment serves uploads, and falls back to the data-plane default when it
    // runs hash-only.
    let free_storage_bytes = config
        .storage
        .as_ref()
        .map(|s| s.free_storage_bytes)
        .unwrap_or(gateway_core::api::ApiConfig::default().free_storage_bytes);

    // The resumable-upload session tunables are a property of `[storage]` too (their
    // assembling files share the durable staging directory); a hash-only deployment
    // never serves the session routes, so the data-plane default is harmless there.
    let upload_session_limits = config
        .storage
        .as_ref()
        .map(|s| s.session_limits)
        .unwrap_or_default();

    // Wire the storage seam (the upload backend plus the funding knobs and the
    // upload-signing seam) when the deployment configures `[storage]`. A hash-only
    // deployment leaves it `None`: the uploads route reports content storage
    // unavailable and the quote route skips the storage-affordability branch.
    let storage_state = match config.storage.as_ref() {
        Some(storage_cfg) => Some(
            assembly::build_storage(pool.clone(), config, storage_cfg, keyring.clone())
                .context("building the data-plane storage seam")?,
        ),
        None => None,
    };

    let request_timeout = std::time::Duration::from_secs(http.request_timeout_secs);
    let mut app_state = gateway_core::api::AppState::new(
        pool.clone(),
        gateway_core::api::ApiConfig {
            problem_type_base: http.problem_type_base.clone(),
            free_storage_bytes,
            upload_session_limits,
            network: config.wallet.network.to_params_network(),
            request_timeout,
            anon_rate_limit_per_min: http.anon_rate_limit_per_min,
            sse_limits: gateway_core::api::SseLimits {
                max_streams: http.sse_max_streams,
                max_streams_per_account: http.sse_max_streams_per_account,
            },
            ..Default::default()
        },
    )
    .with_pricing(pricing);
    if let Some(storage_state) = storage_state {
        app_state = app_state.with_storage(storage_state);
    }

    // The webhook seam (the secret-wrap data key plus the registration URL-safety
    // knobs) is shared by both planes: the account-scoped subscription routes on the
    // data plane and the operator firehose routes on the control plane both seal a
    // minted secret under the SAME instance data key, so a stored secret opens the
    // same way regardless of which plane registered it. `None` for a keyring with no
    // webhook wrap key, in which case both planes report the feature unavailable.
    let webhook_state = assembly::build_webhook(config, &keyring);
    if let Some(webhook) = &webhook_state {
        app_state = app_state.with_webhook(webhook.clone());
    }

    // The verified Cardano wallet keys the instance physically holds, so the control
    // plane's wallet-register route can confirm possession before writing an
    // operator_wallet row the submit path could never sign. Empty for a hash-only or
    // storage-only keyring (a wallet register then has no signer to back and is
    // refused).
    let control_wallet_keys = assembly::wallet_keys(&keyring);

    // The verified Arweave funding keys the instance physically holds, so the
    // control plane's source-register route can confirm possession before writing a
    // funding-source row a signer could never back. Empty for a hash-only or
    // wallet-only keyring (a source register then has no key to back and is refused).
    let control_funding_keys = assembly::funding_keys(&keyring);

    // The control plane is a separate router mounted beside the data plane. Its
    // operator-configured knobs (secret prefix, token TTLs, adjustment cap) come
    // from the resolved `[control]` config. The operator firehose routes carry the
    // same webhook seam the data plane does, so both arms seal under one data key.
    let mut control_state = gateway_core::api::ControlState::with_keys(
        pool,
        gateway_core::api::ControlConfig {
            problem_type_base: http.problem_type_base.clone(),
            secret_prefix: config.control.secret_prefix.clone(),
            operator_token_ttl: chrono::Duration::seconds(config.control.operator_token_ttl_secs),
            account_token_ttl: chrono::Duration::seconds(config.control.account_token_ttl_secs),
            adjustment_cap_usd_micros: config.control.adjustment_cap_usd_micros,
            admin_ui_enabled: config.control.admin_ui_enabled,
            // Validated at config load, so this parse always succeeds.
            default_wallet_scope: gateway_core::api::DefaultWalletScope::parse(
                &config.control.default_wallet_scope,
            )
            .unwrap_or(gateway_core::api::DefaultWalletScope::Service),
            // Validated at config load, so this parse always succeeds.
            default_storage_scope: gateway_core::api::DefaultStorageScope::parse(
                &config.control.default_storage_scope,
            )
            .unwrap_or(gateway_core::api::DefaultStorageScope::Service),
            // The same operator-default markup the live pricing seam resolves against
            // (`[http].margin_pct`), surfaced on the FX-snapshot console. A finite
            // config float always converts; treat a non-finite value as a load-time
            // wiring error rather than inventing a margin.
            operator_default_margin_pct: rust_decimal::Decimal::try_from(http.margin_pct)
                .map_err(|e| anyhow::anyhow!("invalid margin_pct in the [http] config: {e}"))?,
            // The same freshness ceiling the live pricing seam refuses a stale snapshot
            // past, so the console flags staleness on the threshold the quote path
            // enforces. Defaults to the engine default when `[fx]` is not configured.
            fx_freshness_ceiling_seconds: config
                .fx
                .as_ref()
                .map_or(3_600, |fx| fx.max_fx_snapshot_age_seconds),
        },
        control_wallet_keys,
        control_funding_keys,
    );
    if let Some(webhook) = webhook_state {
        control_state = control_state.with_webhook(webhook);
    }

    // The storage funding console (live AR/winc balances + the AR -> credit
    // top-up) rides the control plane whenever the deployment serves uploads; a
    // hash-only deployment leaves it off and the routes report storage not
    // configured.
    if let Some(storage_cfg) = config.storage.as_ref() {
        control_state =
            control_state.with_storage(assembly::build_control_storage(storage_cfg, keyring));
    }

    // The chain seam the wallet-balance console reads live on-chain ADA balances
    // through. Every Cardano deployment configures Koios (the chain provider), so
    // this is always wired; it carries the same base-URL override + optional API
    // key the engine's other Koios clients use.
    control_state = control_state.with_chain(gateway_core::api::ControlChain {
        koios: config.koios.clone(),
    });

    // The data-plane router scopes the request timeout itself (its streaming
    // routes — SSE, content ingress — are exempt by construction). The control
    // plane has no streaming surface, so the binary wraps the whole plane in the
    // same ceiling here.
    let mut router = gateway_core::api::router(app_state).merge(
        gateway_core::api::control_router(control_state).layer(
            tower_http::timeout::TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                request_timeout,
            ),
        ),
    );

    // Serve the bundled static admin UI when enabled. It is a thin HTTP client of
    // the control plane (the operator pastes a token in the page); a deployment
    // that does not want it sets `admin_ui_enabled = false`.
    if config.control.admin_ui_enabled {
        router = gateway::mount_admin_ui(router);
    }

    let listener = tokio::net::TcpListener::bind(&http.bind)
        .await
        .with_context(|| format!("binding the HTTP data plane to {}", http.bind))?;
    tracing::info!(bind = %http.bind, "HTTP data plane listening");

    // The server shuts down gracefully when the runtime's shutdown is signalled.
    // Connect-info stamps each request with its socket peer address — the
    // trusted client identity the anonymous rate limiter meters on (never a
    // forgeable header).
    let server_runtime = runtime.clone();
    let server = async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { server_runtime.wait_for_shutdown().await })
        .await
        .map_err(|e| anyhow::anyhow!("HTTP server error: {e}"))
    };

    let run_runtime = runtime.clone();
    let background = async move { run_runtime.run().await.map_err(|e| anyhow::anyhow!(e)) };

    // Drive both planes together. Whichever finishes first only *initiates*
    // shutdown via the shared signal; we then await the other plane to
    // completion so its own graceful path runs. For the background plane that
    // path is the runtime's drain: it stops claiming new work and lets every
    // in-flight job finish (or cleanly checkpoint) before returning. Dropping
    // the losing future instead — as a bare `select!` would — aborts in-flight
    // jobs mid-work and skips the runtime's drain entirely, so we never do that.
    //
    // The await of the second plane is bounded: a stuck plane must not hang the
    // process forever on shutdown. If the drain overruns the budget we log and
    // return, letting process exit tear down whatever remained, so a wedged job
    // can delay but never block a shutdown indefinitely.
    let mut server = std::pin::pin!(server);
    let mut background = std::pin::pin!(background);

    // The first plane to finish reports its result here and names which plane is
    // still outstanding; the drain step below awaits that one to completion.
    let (first_result, drain): (Result<()>, OutstandingPlane) = tokio::select! {
        result = &mut server => {
            // The HTTP plane stopped first (clean shutdown of its graceful
            // future, or a bind/serve error). Wind the background plane down.
            runtime.shutdown();
            (result, OutstandingPlane::Background)
        }
        result = &mut background => {
            // The background plane stopped first (clean drain, or a supervised
            // loop failed). Wind the HTTP plane down; its graceful-shutdown
            // future is wired to the same signal and will resolve.
            runtime.shutdown();
            (result, OutstandingPlane::Server)
        }
    };

    // Await the outstanding plane to completion so its own graceful path runs,
    // bounded so a wedged plane can delay but never block shutdown forever.
    let drained = match drain {
        OutstandingPlane::Background => {
            tokio::time::timeout(PLANE_DRAIN_TIMEOUT, &mut background).await
        }
        OutstandingPlane::Server => tokio::time::timeout(PLANE_DRAIN_TIMEOUT, &mut server).await,
    };

    match drained {
        Ok(second_result) => {
            // Both planes have stopped. Prefer the first plane's result (it is
            // the one that triggered shutdown); only promote the second's error
            // if the first was Ok, so a drain that surfaced its own failure is
            // not lost.
            match first_result {
                Err(_) => first_result,
                Ok(()) => second_result,
            }
        }
        Err(_) => {
            tracing::warn!(
                timeout_secs = PLANE_DRAIN_TIMEOUT.as_secs(),
                "the second plane did not drain within the shutdown budget; exiting and leaving \
                 process teardown to reclaim it"
            );
            first_result
        }
    }
}

/// Which plane is still outstanding after the first one initiates shutdown, so
/// the drain step knows which pinned future to await to completion.
enum OutstandingPlane {
    /// The HTTP plane finished first; the background runtime must still drain.
    Background,
    /// The background runtime finished first; the HTTP plane must still wind down.
    Server,
}

/// How long to wait for the second plane's graceful drain after shutdown is
/// signalled before giving up and letting process exit reclaim it. Generous
/// enough for an in-flight publish/upload to finish or checkpoint, bounded so a
/// wedged job can never block shutdown forever.
const PLANE_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Install the formatting tracing subscriber and, when configured, error
/// monitoring.
///
/// The filter comes from `RUST_LOG` (falling back to `info`), and the format is
/// JSON so a log aggregator can parse the structured fields the library emits.
///
/// Error monitoring is initialised first, before the subscriber and before the
/// config file is parsed, so a panic or an `error!` during config load, keyring
/// unlock, or migration is still captured. When a DSN is configured the returned
/// guard is `Some` and a Sentry layer is added to the subscriber so ERROR events
/// become issues; when it is absent the subscriber is exactly the JSON log layer
/// it has always been and no telemetry leaves the process. The caller must hold
/// the returned guard for the lifetime of the run — dropping it flushes pending
/// events.
fn init_tracing() -> Result<Option<sentry::ClientInitGuard>> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let guard = gateway::observability::init().context("initialising error monitoring")?;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let base = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json());
    if guard.is_some() {
        base.with(gateway::observability::tracing_layer()).init();
    } else {
        base.init();
    }
    Ok(guard)
}

/// Open a connection pool sized for the background plane: one connection per
/// concurrent loop plus headroom for the NOTIFY listener and ad-hoc queries.
async fn connect_pool(url: &str) -> Result<sqlx::PgPool> {
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(32)
        .connect(url)
        .await?)
}

/// Spawn a task that signals the runtime to shut down on the first SIGTERM or
/// SIGINT. A second signal is left to the OS default (an operator who sends it
/// twice wants the process gone immediately).
///
/// The runtime is shared as an `Arc` so the signal task can call its
/// `shutdown` (a cheap watch-channel send) while the main task drives `run`.
fn spawn_signal_shutdown(runtime: std::sync::Arc<gateway_core::runtime::Runtime>) {
    tokio::spawn(async move {
        wait_for_terminate().await;
        tracing::info!("termination signal received; requesting graceful shutdown");
        runtime.shutdown();
    });
}

/// Resolve when the process receives its first SIGTERM or SIGINT (Unix), or
/// Ctrl-C (any platform).
async fn wait_for_terminate() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, usage, Command};

    /// Build an owned argument vector from string slices, the shape `classify`
    /// receives from `std::env::args`.
    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classify_routes_each_top_level_command() {
        assert_eq!(classify(&args(&[])), Command::Serve);
        assert_eq!(
            classify(&args(&["admin", "account", "list"])),
            Command::Admin
        );
        assert_eq!(classify(&args(&["keyring", "inspect"])), Command::Keyring);
        assert_eq!(
            classify(&args(&["operator", "bootstrap"])),
            Command::OperatorBootstrap
        );
        assert_eq!(
            classify(&args(&["storage", "bootstrap"])),
            Command::StorageBootstrap
        );
    }

    #[test]
    fn classify_short_circuits_help_and_version_before_serve() {
        for help in [&["--help"], &["-h"], &["help"]] {
            assert_eq!(classify(&args(help)), Command::Help, "{help:?}");
        }
        for version in [&["--version"], &["-V"]] {
            assert_eq!(classify(&args(version)), Command::Version, "{version:?}");
        }
    }

    #[test]
    fn classify_rejects_an_unknown_leading_argument_rather_than_serving() {
        // The no-args case serves; a typo'd command must NOT silently serve (which
        // would then die on a missing config file, masking the typo). Only the
        // empty argument list resolves to Serve.
        match classify(&args(&["srve"])) {
            Command::Unknown(message) => assert!(
                message.contains("srve"),
                "the reject message names the bad argument: {message}"
            ),
            other => panic!("an unknown command must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn classify_rejects_a_missing_or_wrong_operator_or_storage_subcommand() {
        // `operator`/`storage` each have exactly one subcommand; a missing or wrong
        // second word is rejected here, never served.
        for wrong in [
            &["operator"][..],
            &["operator", "nope"][..],
            &["storage"][..],
            &["storage", "nope"][..],
        ] {
            assert!(
                matches!(classify(&args(wrong)), Command::Unknown(_)),
                "{wrong:?} must be rejected"
            );
        }
    }

    #[test]
    fn usage_names_every_command_and_the_serve_default() {
        let usage = usage();
        for token in [
            "operator bootstrap",
            "storage bootstrap",
            "keyring",
            "admin",
            "--help",
            "--version",
            "SERVES",
            env!("CARGO_PKG_VERSION"),
        ] {
            assert!(usage.contains(token), "usage must mention {token:?}");
        }
    }
}
