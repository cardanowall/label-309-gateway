//! Assembling the supervised runtime from a resolved configuration.
//!
//! This is where every engine handler and schedule is registered onto one
//! [`Runtime`]: the publish path (submit, confirm, index), the indexer scan, the
//! protocol-parameter populate loop, the wallet pool's maintenance and
//! replenishment, the expired-lease reaper, and the engine's own partition /
//! archive / cron-tick maintenance. The publish and index queues are
//! event-driven (other handlers enqueue them), so they register a handler and a
//! policy but no schedule; every recurring loop registers a schedule too.
//!
//! All chain I/O goes through one Koios-primary provider (keyless public tier
//! by default; the operator's `[chain]`/`GATEWAY_KOIOS_API_KEY` settings key it
//! or point it at a self-hosted instance), shared as an `Arc` so the submit,
//! confirm, scan, and index handlers, and the replenisher's submitter adapter,
//! all use the same client and failover policy.
//!
//! The operator keyring is decrypted exactly once per boot — `serve` calls
//! [`unlock_keyring`] before touching the database and shares the unlocked
//! keyring as an `Arc` — because the scrypt key derivation is deliberately
//! expensive. Every builder here takes that shared keyring rather than
//! re-deriving it.

use std::sync::Arc;

use anyhow::{Context, Result};
use gateway_core::api::{StorageState, UploadSigning};
use gateway_core::chain::confirm::{
    confirm_policy, confirm_schedule, ConfirmConfig, ConfirmHandler,
};
use gateway_core::chain::egress::ChainEgress;
use gateway_core::chain::gateway::{
    build_failover_gateway, EitherGateway, FailoverGateway, KoiosGateway, ProviderCooldown,
};
use gateway_core::chain::params::{
    params_populate_policy, params_populate_schedule, KoiosParamsSource, ParamsPopulateHandler,
};
use gateway_core::chain::records::{index_tx_policy, IndexTxHandler, INDEX_TX_QUEUE};
use gateway_core::chain::recover::{
    chain_recover_policy, chain_recover_schedule, ChainRecoverConfig, ChainRecoverHandler,
    CHAIN_RECOVER_QUEUE, DEFAULT_CHAIN_RECOVER_SCHEDULE,
};
use gateway_core::chain::scan::{scan_policy, scan_schedule, ScanConfig, ScanHandler};
use gateway_core::chain::submit::{submit_policy, SubmitHandler, SUBMIT_QUEUE};
use gateway_core::maintenance::{
    maintenance_policy, maintenance_schedule, MaintenanceCadence, MaintenanceHandler,
};
use gateway_core::pricing::{
    ensure_fx_seeded, fx_refresh_policy, fx_refresh_schedule, CoinGeckoConfig, CoinPriceProvider,
    FxRefreshConfig, FxRefreshHandler, FX_REFRESH_QUEUE,
};
use gateway_core::runtime::Runtime;
use gateway_core::storage::{
    attempt_reconcile_policy, attempt_reconcile_schedule, credit_reconcile_policy,
    credit_reconcile_schedule, session_janitor_policy, staging_janitor_policy, ArLocalBackend,
    AttemptReconcileConfig, AttemptReconcileHandler, CreditReconcileHandler, DirectArweaveBackend,
    ReconcileConfig, SessionJanitor, StagingJanitor, StorageBackend, TurboBackend,
    TurboPaymentClient, TurboWincProvider, ATTEMPT_RECONCILE_QUEUE, CREDIT_RECONCILE_QUEUE,
    SESSION_JANITOR_QUEUE, STAGING_JANITOR_QUEUE,
};
use gateway_core::wallet::config::WalletConfig;
use gateway_core::wallet::keyring::{unlock, UnlockedKeyring};
use gateway_core::wallet::pool::{
    wallet_maintenance_policy, wallet_maintenance_schedule, WalletMaintenanceHandler,
    WALLET_MAINTENANCE_QUEUE,
};
use gateway_core::wallet::replenish::{
    replenish_policy, replenish_schedule, ReplenishHandler, REPLENISH_QUEUE,
};
use gateway_core::wallet::utxo::{lease_reaper_policy, KoiosUtxoSource};
use gateway_core::webhook::delivery::DeliveryPolicy;
use gateway_core::webhook::egress::EgressConfig;
use gateway_core::webhook::{
    delivery_policy, delivery_schedule, fanout_policy, fanout_schedule, DeliveryHandler,
    FanoutHandler, DELIVERY_QUEUE, FANOUT_QUEUE,
};

use crate::config::{GatewayConfig, StorageBackendKind, StorageConfig};
use crate::handlers::{
    lease_reaper_schedule, GatewaySubmitter, LeaseReaperHandler, LEASE_REAPER_QUEUE,
};

/// Build the fully wired, supervised runtime from a resolved config, an
/// already-migrated pool, and the shared unlocked keyring.
///
/// The keyring arrives already decrypted (the caller unlocks it once per boot);
/// the submit and replenish handlers share the same `Arc`, and the key material
/// is wiped when the last reference drops. This constructs the shared Koios
/// provider, validates the band's fee shape against the freshly loaded protocol
/// parameters, then registers every handler, policy, and schedule. The returned
/// runtime is ready to `run`; it has not started any loop yet.
pub async fn build_runtime(
    pool: sqlx::PgPool,
    config: &GatewayConfig,
    keyring: Arc<UnlockedKeyring>,
) -> Result<Runtime> {
    let wallet = config.wallet;
    let network = wallet.network;
    let params_network = network.to_params_network();

    // One failover chain provider, shared (as an Arc) by the replenisher's
    // submitter adapter; the chain handlers each take an owned gateway value, so
    // they construct their own failover pair over the same providers. The primary
    // is keyless Koios; the secondary is Blockfrost when a project id is
    // configured (so a Koios 429 fails over to it) and a second Koios instance
    // otherwise. Each pair shares the restart-survivable per-provider cooldown
    // gate, backed by Postgres, and the SAME per-provider egress budget built
    // here: one Postgres-accounted token bucket per provider for the whole
    // process, so however many handler-owned pairs exist they cannot jointly
    // exceed the configured provider request rate.
    let chain_egress = ChainEgress::new(params_network, config.chain_egress, pool.clone());
    let gateway = Arc::new(
        failover_for(&pool, params_network, config, &chain_egress)
            .context("constructing the chain gateway failover pair")?,
    );
    let split_submitter = GatewaySubmitter::new(gateway.clone());

    // Cold start: on a fresh database no protocol-parameter row exists yet, and the
    // fee-shape certification below reads one. Rather than require an out-of-band
    // seeding step, the binary populates the parameters for its own network once
    // here, before the certification, so a brand-new deployment self-bootstraps the
    // parameters its quote and fee-shape paths depend on. The recurring populate
    // schedule still keeps them fresh once the runtime is ticking; this only closes
    // the gap on the very first start, when that schedule has not run yet. An
    // already-populated database makes this a cheap no-op (the populate pass finds
    // the current epoch already cached).
    ensure_params_populated(&pool, params_network, &config.koios)
        .await
        .context("populating protocol parameters on first start")?;

    // Cold start for the live FX snapshot, the symmetric twin of the protocol-
    // parameter seed above. On a fresh database with no fx_rate row the first quote
    // would have no conversion to price from, and a fresh process never has the
    // chance to wait for the first FX cron tick. So a live-FX deployment seeds one
    // snapshot here, before serving. An already-seeded database is a cheap no-op
    // (the seed returns immediately when a row exists). A seed that cannot write a
    // row (oracle down, or a cooldown already in effect with no prior row) fails the
    // boot rather than serving FX-less quotes; the orchestrator restart loop is the
    // recovery mechanism. Only runs when `[fx]` is configured.
    if let Some(fx_config) = build_fx_refresh_config(config)? {
        ensure_fx_seeded(&pool, &fx_config)
            .await
            .context("seeding the live FX snapshot on first start")?;
    }

    // Fail fast if the configured band cannot hold the exact-quote guarantee under
    // the live protocol parameters: load them (populated just above on a cold
    // start, refreshed by the populate schedule thereafter), then certify the
    // band's fee shape.
    validate_fee_shape(&pool, config, &wallet, &keyring)
        .await
        .context("validating the configured lovelace band against protocol parameters")?;

    let mut builder = Runtime::builder(pool.clone())
        .worker_id(config.worker_id.clone())
        // --- Publish path: event-driven submit + confirm + index. ---
        .queue_policy(submit_policy())
        .handler(
            SUBMIT_QUEUE,
            SubmitHandler::new(
                pool.clone(),
                failover_for(&pool, params_network, config, &chain_egress)?,
                wallet,
                keyring.clone(),
            ),
        )
        .queue_policy(confirm_policy())
        .handler(
            gateway_core::chain::confirm::CONFIRM_QUEUE,
            ConfirmHandler::new(
                pool.clone(),
                failover_for(&pool, params_network, config, &chain_egress)?,
                network.as_str(),
                ConfirmConfig::default(),
                wallet,
            ),
        )
        .schedule(confirm_schedule())
        // The chain-attempt recovery sweep: it owns every attempt recorded before
        // broadcast whose broadcast never reached the wire (a provider storm, a
        // transport error the node never saw). Such an attempt stays `recorded` with
        // a NULL mempool entry, invisible to the confirm authority's mempool
        // reconcile, with no submit job left to retry it. The sweep re-enqueues a
        // submit past a grace (the submit path re-broadcasts the recorded bytes
        // idempotently, landing via the failover secondary when the primary is rate-
        // limited) and refunds through the single-refund hook past an absolute
        // backstop, so a stranded record always reaches a terminal state. Always
        // registered: this is the on-chain money path, not a storage feature.
        .queue_policy(chain_recover_policy())
        .handler(
            CHAIN_RECOVER_QUEUE,
            ChainRecoverHandler::new(pool.clone(), ChainRecoverConfig::default()),
        )
        .schedule(chain_recover_schedule(DEFAULT_CHAIN_RECOVER_SCHEDULE))
        .queue_policy(index_tx_policy())
        .handler(
            INDEX_TX_QUEUE,
            IndexTxHandler::new(
                pool.clone(),
                failover_for(&pool, params_network, config, &chain_egress)?,
                params_network,
            ),
        )
        // --- Indexer scan loop. ---
        .queue_policy(scan_policy())
        .handler(
            gateway_core::chain::scan::SCAN_QUEUE,
            ScanHandler::new(
                pool.clone(),
                failover_for(&pool, params_network, config, &chain_egress)?,
                params_network,
                ScanConfig::default(),
            ),
        )
        .schedule(scan_schedule())
        // --- Protocol-parameter populate loop. ---
        .queue_policy(params_populate_policy())
        .handler(
            gateway_core::chain::params::PARAMS_POPULATE_QUEUE,
            ParamsPopulateHandler::new(
                pool.clone(),
                KoiosParamsSource::new(config.koios.clone())
                    .context("constructing the Koios params source")?,
                vec![params_network],
            ),
        )
        .schedule(params_populate_schedule())
        // --- Wallet pool: maintenance + replenishment + lease reaping. ---
        .queue_policy(wallet_maintenance_policy())
        .handler(
            WALLET_MAINTENANCE_QUEUE,
            WalletMaintenanceHandler::new(pool.clone()),
        )
        .schedule(wallet_maintenance_schedule())
        .queue_policy(replenish_policy())
        .handler(
            REPLENISH_QUEUE,
            ReplenishHandler::new(
                pool.clone(),
                keyring.clone(),
                KoiosUtxoSource::new(
                    config.koios.base_url_for(params_network),
                    config.koios.api_key.clone(),
                )
                .context("constructing the replenish UTxO source")?,
                split_submitter,
                wallet,
            ),
        )
        .schedule(replenish_schedule())
        .queue_policy(lease_reaper_policy())
        .handler(LEASE_REAPER_QUEUE, LeaseReaperHandler::new(pool.clone()))
        .schedule(lease_reaper_schedule())
        // --- Engine maintenance: partitions + archive + cron-tick pruning. ---
        .queue_policy(maintenance_policy(MaintenanceCadence::Daily))
        .handler(
            MaintenanceCadence::Daily.queue(),
            MaintenanceHandler::new(pool.clone(), MaintenanceCadence::Daily),
        )
        .schedule(maintenance_schedule(MaintenanceCadence::Daily))
        .queue_policy(maintenance_policy(MaintenanceCadence::Hourly))
        .handler(
            MaintenanceCadence::Hourly.queue(),
            MaintenanceHandler::new(pool.clone(), MaintenanceCadence::Hourly),
        )
        .schedule(maintenance_schedule(MaintenanceCadence::Hourly))
        // --- Webhook delivery: the fan-out drain + the per-subscription delivery
        // worker. The fan-out drain explodes un-fanned outbox rows into
        // per-subscription delivery rows; the delivery worker signs and POSTs them
        // through the hardened egress, reusing the unlocked keyring to unwrap each
        // endpoint secret. Both run on every deployment: an instance with no
        // subscriptions drains nothing, so registering them costs only an idle loop.
        // The egress posture comes from `[webhooks]` and defaults to strict
        // (HTTPS-only, public-IP-only); it is the SAME posture the registration
        // guard uses (`build_webhook`), so a URL that passes registration also
        // passes delivery. The delivery budget uses the platform defaults. ---
        .queue_policy(fanout_policy())
        .handler(FANOUT_QUEUE, FanoutHandler::new(pool.clone()))
        .schedule(fanout_schedule())
        .queue_policy(delivery_policy())
        .handler(
            DELIVERY_QUEUE,
            DeliveryHandler::new(
                pool.clone(),
                keyring.clone(),
                EgressConfig {
                    allow_insecure_http: config.webhooks.allow_insecure_http,
                    allow_loopback: config.webhooks.egress_allow_loopback,
                },
                DeliveryPolicy::default(),
            ),
        )
        .schedule(delivery_schedule());

    // --- Storage crons: the winc-credit reconcile and the upload-attempt recovery
    // sweep, plus the durable-staging orphan janitor. Only wired when the
    // deployment configures `[storage]`; a hash-only deployment runs neither. ---
    if let Some(storage) = &config.storage {
        builder = register_storage_crons(builder, &pool, storage, network, keyring.clone())
            .context("registering the storage crons")?;
    }

    // --- Live FX refresh loop. The only oracle caller: every quote reads the
    // cached snapshot it writes. Wired only when the deployment configures `[fx]`;
    // an offline/test deployment leaves it off and prices from the static rate. The
    // symmetric twin of the protocol-parameter populate loop and the winc-credit
    // reconcile loop. ---
    if let Some(fx_config) = build_fx_refresh_config(config)? {
        let refresh_schedule = config
            .fx
            .as_ref()
            .map(|fx| fx.refresh_schedule.clone())
            .unwrap_or_else(|| gateway_core::pricing::DEFAULT_FX_REFRESH_SCHEDULE.to_string());
        builder = builder
            .queue_policy(fx_refresh_policy())
            .handler(
                FX_REFRESH_QUEUE,
                FxRefreshHandler::new(pool.clone(), fx_config),
            )
            .schedule(fx_refresh_schedule(refresh_schedule));
    }

    builder.build().await.context("building the runtime")
}

/// Register the storage background work onto the runtime builder.
///
/// Two reconcile loops and a startup janitor. The upload-attempt recovery sweep is
/// backend-agnostic: every funded backend reserves attempts the sweep must
/// converge, so it is always registered when storage is configured. The
/// winc-credit reconcile loop is the only winc network caller and is meaningful
/// only for a backend that draws a remote prepaid winc balance, so it is wired for
/// the Turbo backend; the ArLocal emulator mints free balance (nothing to
/// reconcile) and the direct-Arweave backend fails fast at boot before reaching
/// here. The durable-staging janitor reclaims orphaned promoted files left by a
/// crash; it is registered for every storage backend.
fn register_storage_crons(
    mut builder: gateway_core::runtime::RuntimeBuilder,
    pool: &sqlx::PgPool,
    storage: &StorageConfig,
    network: gateway_core::wallet::config::Network,
    keyring: Arc<UnlockedKeyring>,
) -> Result<gateway_core::runtime::RuntimeBuilder> {
    let backend = build_storage_backend(
        pool.clone(),
        storage,
        network.is_production(),
        Arc::clone(&keyring),
    )
    .context("constructing the storage backend for the recovery sweep")?;

    // The upload-attempt recovery sweep: it owns every `reserved` attempt past the
    // horizon, querying the backend for the data-item status and re-POSTing the
    // byte-identical reconstruction or releasing the hold. Backend-agnostic.
    builder = builder
        .queue_policy(attempt_reconcile_policy())
        .handler(
            ATTEMPT_RECONCILE_QUEUE,
            AttemptReconcileHandler::new(
                pool.clone(),
                backend,
                keyring,
                AttemptReconcileConfig {
                    reconcile_horizon: storage.reconcile_horizon,
                    upload_claim_lease_ttl: storage.upload_claim_lease_ttl,
                    attempt_stuck_passes: storage.attempt_stuck_passes,
                },
            ),
        )
        .schedule(attempt_reconcile_schedule(
            // The sweep cadence is fixed; the horizon (not the cadence) bounds how
            // long an interrupted attempt waits, and it is validated above the
            // upload timeout at config load.
            gateway_core::storage::DEFAULT_ATTEMPT_RECONCILE_SCHEDULE,
        ));

    // The durable-staging orphan janitor: reclaims promoted staged files no live
    // reservation still points at (a crash between promotion and commit, or between
    // nulling the row and deleting the file). Backend-agnostic, and driven by its
    // own recurring schedule so it recovers debris from a crash at any time, not
    // only the one immediately preceding a restart.
    builder = builder
        .queue_policy(staging_janitor_policy())
        .handler(
            STAGING_JANITOR_QUEUE,
            StagingJanitor::new(pool.clone(), storage.durable_staging_dir.clone()),
        )
        .schedule(staging_janitor_schedule());

    // The abandoned-session janitor: CAS-expires sessions past their TTL and
    // reclaims their `.assembling` files. The sibling of the staging janitor and the
    // clean partition's other half: it owns ONLY pre-reservation assembling files;
    // once a session reserves its attempt, the assembling file is adopted under the
    // attempt-named `.stage` path and the staging janitor + attempt reconcile own it.
    // It assembles into the same durable staging directory the attempt promotion
    // uses, so both janitors scan one directory and partition it by file suffix.
    builder = builder
        .queue_policy(session_janitor_policy())
        .handler(
            SESSION_JANITOR_QUEUE,
            SessionJanitor::new(pool.clone(), storage.durable_staging_dir.clone()),
        )
        .schedule(session_janitor_schedule());

    // The winc-credit reconcile loop: settles landed top-ups into the believed
    // balance, then reads the live provider balance and corrects the remainder,
    // emitting the low/drift alerts. The only winc network caller, so it stays
    // infrequent. Meaningful only for a backend with a remote prepaid balance —
    // the Turbo backend.
    if storage.backend == StorageBackendKind::Turbo {
        let provider = TurboWincProvider::new(storage.payment_url.clone())
            .map_err(|e| anyhow::anyhow!("constructing the winc-balance provider: {e}"))?;
        // The registrar polls registered top-ups against the same payment
        // service so a credit that lands between ticks is journalled into the
        // believed balance before the drift comparison.
        let registrar = TurboPaymentClient::new(storage.payment_url.clone())
            .map_err(|e| anyhow::anyhow!("constructing the payment-service client: {e}"))?;
        builder = builder
            .queue_policy(credit_reconcile_policy())
            .handler(
                CREDIT_RECONCILE_QUEUE,
                CreditReconcileHandler::new(
                    pool.clone(),
                    provider,
                    registrar,
                    // The backend's persisted identifier, the same value the
                    // funding-source rows carry, so the reconcile loop scopes to its
                    // own backend's sources.
                    "turbo",
                    ReconcileConfig {
                        winc_safety_floor: storage.winc_safety_floor,
                        winc_drift_alert_threshold: storage.winc_drift_alert_threshold,
                    },
                ),
            )
            .schedule(credit_reconcile_schedule(
                storage.winc_refresh_schedule.clone(),
            ));
    }

    Ok(builder)
}

/// The schedule that fires the durable-staging orphan janitor every five minutes.
///
/// Each pass reconciles the durable directory against the live reservation set and
/// reclaims orphaned promoted files, so the cadence bounds how long crash debris
/// lingers, not how promptly a single upload settles. Five minutes matches the
/// janitor's own lease window, keeps the directory scan infrequent, and still
/// recovers from a crash that happens long after the last restart. The scheduler's
/// `cron_tick` gate ensures exactly one replica enqueues each occurrence.
fn staging_janitor_schedule() -> gateway_core::runtime::scheduler::CronSchedule {
    gateway_core::runtime::scheduler::CronSchedule::new(
        "0 */5 * * * *",
        STAGING_JANITOR_QUEUE,
        serde_json::Value::Null,
    )
}

/// The schedule that fires the abandoned-session janitor every five minutes.
///
/// Each pass CAS-expires sessions past their TTL and reclaims their assembling
/// files, so the cadence bounds how long abandoned-session disk lingers, not how
/// promptly any one upload finishes. Five minutes matches the staging janitor and
/// the janitor's own lease window. The scheduler's `cron_tick` gate ensures exactly
/// one replica enqueues each occurrence.
fn session_janitor_schedule() -> gateway_core::runtime::scheduler::CronSchedule {
    gateway_core::runtime::scheduler::CronSchedule::new(
        "0 */5 * * * *",
        SESSION_JANITOR_QUEUE,
        serde_json::Value::Null,
    )
}

/// Construct a fresh chain-gateway failover pair for a network. Each chain handler
/// owns its own pair (the handlers take `G` by value, not by reference), while the
/// replenisher's submitter shares one `Arc`-wrapped pair; every pair has the same
/// Koios primary and the same secondary (Blockfrost when a project id is
/// configured, a second Koios instance otherwise) and shares the
/// restart-survivable per-provider cooldown gate over the pool AND the single
/// per-provider egress budget built once in [`build_runtime`]. Building one pair
/// per handler keeps each handler's gateway owned and independent while they all
/// agree on the provider set, the cooldown store, and the request budget.
fn failover_for(
    pool: &sqlx::PgPool,
    network: gateway_core::chain::params::Network,
    config: &GatewayConfig,
    egress: &ChainEgress,
) -> Result<FailoverGateway<KoiosGateway, EitherGateway>> {
    let cooldown = ProviderCooldown::new(pool.clone());
    build_failover_gateway(
        network,
        &config.koios,
        config.blockfrost_project_id.clone(),
        cooldown,
        egress,
    )
    .context("constructing the chain gateway failover pair")
}

/// Populate the protocol parameters for `network` once on a cold start.
///
/// If a row already exists this returns immediately (the recurring schedule owns
/// keeping it fresh). On a fresh database it runs a single populate pass from the
/// engine's Koios parameter source, so the fee-shape certification and the data
/// plane's quote path have the parameters they read without an out-of-band seeding
/// step. A populate failure is surfaced (the deployment cannot serve quotes
/// without parameters), but an already-cached database never touches the network.
async fn ensure_params_populated(
    pool: &sqlx::PgPool,
    network: gateway_core::chain::params::Network,
    koios: &gateway_core::chain::params::KoiosConfig,
) -> Result<()> {
    if gateway_core::chain::params::load_params(pool, network)
        .await
        .is_ok()
    {
        return Ok(());
    }

    let handler = ParamsPopulateHandler::new(
        pool.clone(),
        KoiosParamsSource::new(koios.clone()).context("constructing the Koios params source")?,
        vec![network],
    );
    for (net, result) in handler.run_once().await {
        result.with_context(|| format!("populating protocol parameters for {net:?}"))?;
    }
    Ok(())
}

/// Read the keyring ciphertext from its configured path and unlock it with the
/// configured passphrase, pinned to the deployment's network.
///
/// The scrypt key derivation is deliberately expensive, so each boot path calls
/// this exactly once: `serve` unlocks before any database work and shares the
/// result with every builder, and the storage-bootstrap subcommand unlocks for
/// its own one-shot run. Public so both paths open the operator keyring through
/// one helper rather than re-deriving the read/decrypt/verify sequence.
pub fn unlock_keyring(config: &GatewayConfig) -> Result<UnlockedKeyring> {
    let ciphertext = std::fs::read(&config.keyring_path).with_context(|| {
        format!(
            "reading operator keyring ciphertext from {}",
            config.keyring_path.display()
        )
    })?;
    // The passphrase is moved into a fresh zeroizing copy the unlock owns; the
    // config's own copy is wiped when the config drops.
    let passphrase = zeroize::Zeroizing::new(config.keyring_passphrase.to_string());
    let keyring = unlock(&ciphertext, passphrase, config.wallet.network)
        .map_err(|e| anyhow::anyhow!("unlock failed: {e}"))?;
    // An empty keyring is a valid file state (`gateway keyring init` writes
    // one) but not a servable one: nothing could ever be signed, so refuse the
    // boot here with a pointer at the provisioning step rather than running an
    // engine whose every signing path is dead.
    if keyring.is_empty() {
        anyhow::bail!(
            "the operator keyring at {} holds no keys; add entries with `gateway keyring \
             add-cardano`, `gateway keyring add-arweave`, or `gateway keyring add-webhook-wrap` \
             before starting the gateway",
            config.keyring_path.display()
        );
    }
    Ok(keyring)
}

/// Load the live protocol parameters and certify the configured band is
/// fee-shape-stable under them: the canonical quote fee must equal the real
/// one-input build fee across the whole band, with no fold or min-ADA boundary.
async fn validate_fee_shape(
    pool: &sqlx::PgPool,
    config: &GatewayConfig,
    wallet: &WalletConfig,
    keyring: &UnlockedKeyring,
) -> Result<()> {
    let params = gateway_core::chain::params::load_params(pool, wallet.network.to_params_network())
        .await
        .context(
            "loading protocol parameters for the band fee-shape check (the populate loop must \
             have cached at least one epoch for this network)",
        )?;
    let builder_params = cardano_poe_tx::ProtocolParams {
        min_fee_a: params.min_fee_a,
        min_fee_b: params.min_fee_b,
        coins_per_utxo_byte: params.coins_per_utxo_byte,
        max_tx_size: params.max_tx_size,
    };

    // The fee shape is independent of which canonical address the quote is priced
    // against, but a real address is needed to drive the builder. Any wallet's
    // verified address works; resolve the first one in the shared unlocked keyring.
    let wallets = keyring.wallets();
    let probe = wallets.first().context(
        "the operator keyring holds no wallet, so the band's fee shape cannot be certified",
    )?;

    wallet
        .validate_fee_shape_stable(
            &builder_params,
            &probe.address,
            FEE_SHAPE_PROBE_VERIFICATION_KEY,
            &config.fee_shape_record_sizes,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// A fixed, obviously synthetic verification key used only to size the single
/// vkey witness when probing the band's fee shape. The witness size is identical
/// for any 32-byte key, so this never needs to be a real wallet key.
const FEE_SHAPE_PROBE_VERIFICATION_KEY: [u8; 32] = [0x07; 32];

/// Construct the configured storage backend, failing fast on a misconfiguration
/// that could only surface as a broken upload later.
///
/// The fail-fast matrix is the whole point of building the backend at boot rather
/// than per request: an ArLocal backend selected on a production network, or the
/// not-yet-implemented direct-Arweave backend, is a deployment error the operator
/// must fix before serving, not a 500 the first uploader discovers. Turbo is the
/// funded default; its affordability read needs the pool and the winc safety
/// floor. The ArLocal dev backend additionally needs the unlocked keyring: it signs
/// an outer base-layer transaction with the funding key the upload names, so the
/// keyring is threaded in (it is the same `Arc` the signing seam holds). The
/// unknown-backend case cannot reach here: the config layer parses the backend to a
/// closed enum, so a typo is already a load error.
pub(crate) fn build_storage_backend(
    pool: sqlx::PgPool,
    storage: &StorageConfig,
    is_production: bool,
    keyring: Arc<UnlockedKeyring>,
) -> Result<Arc<dyn StorageBackend>> {
    match storage.backend {
        StorageBackendKind::Turbo => Ok(Arc::new(TurboBackend::new(
            pool,
            storage.upload_url.clone(),
            storage.gateway_url.clone(),
            storage.winc_safety_floor,
            storage.upload_timeout,
        ))),
        StorageBackendKind::ArLocal => {
            // The dev emulator refuses to construct on a production network, so a
            // mainnet deployment that left ArLocal wired fails at boot.
            let backend =
                ArLocalBackend::new(storage.arlocal_endpoint.clone(), is_production, keyring)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(Arc::new(backend))
        }
        StorageBackendKind::DirectArweave => {
            // The direct-Arweave backend's full-transaction signer is not
            // implemented; selecting it is a configuration error until it lands, so
            // it fails at boot rather than serving a backend that cannot store.
            let _ = DirectArweaveBackend::new(storage.gateway_url.clone());
            Err(anyhow::anyhow!(
                "the direct-arweave storage backend is not yet implemented; configure the turbo \
                 backend"
            ))
        }
    }
}

/// Build the data-plane storage seam (the backend plus the upload-signing seam)
/// from the resolved storage config and the shared unlocked keyring.
///
/// The seam carries the backend the uploads route POSTs through and the signing
/// seam (the keyring, the durable staging directory, and the two in-flight
/// deadlines) a paid account-scoped upload needs. The ArLocal dev backend signs
/// its outer carrier transaction with a funding key, so it takes the same
/// unlocked keyring the signing seam holds. Funding policy lives on the
/// backend itself: the Turbo backend is built with the winc safety floor its
/// cached-credit affordability read refuses below. A deployment whose keyring
/// holds no Arweave key still gets a quote-affordability seam; the uploads route
/// then reports the paid path unavailable rather than failing mid-sign, which the
/// keyring's empty Arweave set already enforces (the signer lookup returns
/// `None`).
pub fn build_storage(
    pool: sqlx::PgPool,
    config: &GatewayConfig,
    storage: &StorageConfig,
    keyring: Arc<UnlockedKeyring>,
) -> Result<StorageState> {
    let is_production = config.wallet.network.is_production();

    let backend = build_storage_backend(pool, storage, is_production, Arc::clone(&keyring))
        .context("constructing the storage backend")?;

    let signing = UploadSigning::new(
        keyring,
        storage.durable_staging_dir.clone(),
        storage.upload_timeout,
        storage.upload_claim_lease_ttl,
    );

    Ok(StorageState::new(backend).with_signing(signing))
}

/// Build the control plane's storage funding-console seam (live AR/winc balance
/// reads plus the AR -> credit top-up) from the resolved `[storage]` config.
///
/// The node URL is the ArLocal endpoint under the dev emulator (its base-layer
/// API serves the same wallet-balance/anchor/price/tx endpoints a public
/// gateway does) and the configured Arweave gateway otherwise. The payment
/// service exists only on the Turbo backend; the other backends leave it `None`
/// so the control routes report the Turbo features unavailable rather than
/// inventing a balance. The keyring is the shared unlocked keyring every other
/// seam holds; the top-up reaches a signer only through the owner-minted
/// funding capability.
pub fn build_control_storage(
    storage: &StorageConfig,
    keyring: Arc<UnlockedKeyring>,
) -> gateway_core::api::ControlStorage {
    let node_url = match storage.backend {
        StorageBackendKind::ArLocal => storage.arlocal_endpoint.clone(),
        StorageBackendKind::Turbo | StorageBackendKind::DirectArweave => {
            storage.gateway_url.clone()
        }
    };
    let payment_url = match storage.backend {
        StorageBackendKind::Turbo => Some(storage.payment_url.clone()),
        StorageBackendKind::ArLocal | StorageBackendKind::DirectArweave => None,
    };
    gateway_core::api::ControlStorage {
        backend: storage.backend.name().to_string(),
        node_url,
        payment_url,
        keyring,
    }
}

/// The verified Cardano wallet keys the unlocked keyring holds, as the control
/// plane sees them.
///
/// The control plane's wallet-register route consults this set to confirm the
/// instance physically holds a signer for a claimed Cardano address before it
/// writes an `operator_wallet` row the submit path could never sign. It carries no
/// key material: only the verified address and the operator label the keyring
/// exposes. An empty set (a hash-only or storage-only deployment) means a wallet
/// register has no signer to back and is refused.
pub fn wallet_keys(keyring: &UnlockedKeyring) -> Vec<gateway_core::api::ControlWalletKey> {
    keyring
        .wallets()
        .into_iter()
        .map(|k| gateway_core::api::ControlWalletKey {
            address: k.address,
            label: k.label,
        })
        .collect()
}

/// The verified Arweave funding keys the unlocked keyring holds, as the control
/// plane sees them.
///
/// The control plane's source-register route consults this set to confirm the
/// instance physically holds a signer for a claimed Arweave address before it
/// writes a funding-source row a signer could never back. It carries no key
/// material: only the verified address and the operator label the keyring exposes.
/// An empty set (a hash-only or wallet-only deployment) means a source register
/// has no key to back and is refused.
pub fn funding_keys(keyring: &UnlockedKeyring) -> Vec<gateway_core::api::ControlFundingKey> {
    keyring
        .arweave_funding_keys()
        .into_iter()
        .map(|k| gateway_core::api::ControlFundingKey {
            address: k.address,
            label: k.label,
        })
        .collect()
}

/// Build the webhook seam (the secret-wrap data key plus the registration
/// URL-safety knobs) both HTTP planes share, or `None` when the instance holds no
/// webhook wrap key.
///
/// The active wrap key is the data key a freshly minted webhook secret is sealed
/// under; the delivery worker opens stored secrets back through the same keyring.
/// A deployment that never registered a webhook wrap key (a hash-only keyring with
/// no webhook entry) returns `None`, so both planes report the webhook feature
/// unavailable rather than minting a secret with no place to seal it. The two
/// URL-safety knobs come from `[webhooks]` and default to the production-safe
/// posture: HTTPS-only delivery targets, and the SSRF range-block always on (no
/// loopback escape hatch). The SAME knobs drive the delivery worker's
/// [`gateway_core::webhook::EgressConfig`] in [`build_runtime`], so a URL that
/// passes the registration guard also passes delivery and the posture can never
/// split between the two stages.
pub fn build_webhook(
    config: &GatewayConfig,
    keyring: &UnlockedKeyring,
) -> Option<gateway_core::api::WebhookState> {
    keyring.active_webhook_wrap_key().map(|wrap_key| {
        gateway_core::api::WebhookState::new(
            Arc::new(wrap_key.secret_wrap()),
            config.webhooks.allow_insecure_http,
            config.webhooks.egress_allow_loopback,
        )
    })
}

/// Build the data-plane pricing seam from the resolved config and the HTTP
/// section's FX/markup.
///
/// The network fee is priced through the engine's canonical-fee helper against
/// any verified operator wallet address (the fee is independent of which one), so
/// this resolves that address from the shared unlocked keyring; the witness key
/// is the same synthetic probe the fee-shape check uses, since the fee depends
/// only on the record length and the protocol parameters, never on the specific
/// key. The FX rate and markup come from the operator-configured HTTP section;
/// the per-byte storage rate comes from `[storage]` when the deployment serves
/// uploads (zero for a hash-only deployment, which has no storage cost to
/// forecast).
pub fn build_pricing(
    pool: sqlx::PgPool,
    config: &GatewayConfig,
    http: &crate::config::HttpConfig,
    keyring: &UnlockedKeyring,
) -> Result<crate::pricing::BinaryPricing> {
    let wallets = keyring.wallets();
    let probe = wallets
        .first()
        .context("the operator keyring holds no wallet, so the data plane cannot price a quote")?;
    let margin = rust_decimal::Decimal::try_from(http.margin_pct)
        .map_err(|e| anyhow::anyhow!("invalid margin_pct in the [http] config: {e}"))?;

    // The quote forecasts the storage cost from this per-byte rate. A hash-only
    // deployment has no storage section, so it forecasts zero storage cost.
    let ar_usd_per_byte_femto = config
        .storage
        .as_ref()
        .map(|s| s.ar_usd_per_byte_femto)
        .unwrap_or(0);

    Ok(crate::pricing::BinaryPricing::new(
        pool,
        probe.address.clone(),
        FEE_SHAPE_PROBE_VERIFICATION_KEY,
        config.wallet,
        config.wallet.network.to_params_network(),
        crate::pricing::FxRates {
            ada_usd_micros: http.ada_usd_micros,
            ar_usd_per_byte_femto,
        },
        margin,
    ))
}

/// Build the live DB-backed pricing seam from the resolved config and the HTTP
/// section's markup.
///
/// The network fee is priced exactly the way the static seam prices it (the
/// engine's canonical-fee helper against any verified operator wallet address, the
/// synthetic probe witness key); the difference is that the two FX prices come from
/// the newest `cw_core.fx_rate` row the FX refresh loop writes, not from static
/// config, and the quote reports the snapshot's true age. This is the binary's live
/// PricingSource; it is selected whenever `[fx]` is configured. The markup still
/// comes from `[http]`.
pub fn build_pg_pricing(
    pool: sqlx::PgPool,
    config: &GatewayConfig,
    http: &crate::config::HttpConfig,
    keyring: &UnlockedKeyring,
) -> Result<gateway_core::pricing::PgFxPricing> {
    let wallets = keyring.wallets();
    let probe = wallets
        .first()
        .context("the operator keyring holds no wallet, so the data plane cannot price a quote")?;
    let margin = rust_decimal::Decimal::try_from(http.margin_pct)
        .map_err(|e| anyhow::anyhow!("invalid margin_pct in the [http] config: {e}"))?;

    // The live seam is only built when `[fx]` is configured (its caller gates on
    // `config.fx.is_some()`), so the freshness ceiling is always present here; treat
    // its absence as a wiring error rather than inventing a default.
    let fx = config.fx.as_ref().context(
        "build_pg_pricing requires the [fx] section: it is the live pricing seam, selected only \
         when live FX is configured",
    )?;

    Ok(gateway_core::pricing::PgFxPricing::new(
        pool,
        probe.address.clone(),
        FEE_SHAPE_PROBE_VERIFICATION_KEY,
        config.wallet,
        config.wallet.network.to_params_network(),
        margin,
        fx.max_fx_snapshot_age_seconds,
    ))
}

/// Build the FX refresh loop's oracle configuration from `[fx]` and `[storage]`.
///
/// Returns `None` when `[fx]` is absent (the offline/test deployment): no oracle
/// loop runs and the binary prices from the static `[http]` rate. When `[fx]` is
/// present the per-byte oracles need the storage service URLs (the Turbo payment
/// service for the primary oracle, the Arweave gateway for the fallback), so a
/// `[fx]` section without `[storage]` is a configuration error rather than a loop
/// with nowhere to read the per-byte price.
pub fn build_fx_refresh_config(config: &GatewayConfig) -> Result<Option<FxRefreshConfig>> {
    let Some(fx) = config.fx.as_ref() else {
        return Ok(None);
    };
    let storage = config.storage.as_ref().context(
        "the [fx] live-pricing section requires [storage]: the per-byte price oracles read the \
         Turbo payment-service and Arweave gateway URLs the storage subsystem configures",
    )?;
    // Build the coin-price provider chain: CoinGecko first when a key is configured
    // (validated at config load), then the keyless CoinPaprika default, which is
    // always present as the sole provider or the fallback — so the chain is never
    // empty and a self-hosted gateway prices publishes with no API key.
    let mut coin_price_providers = Vec::new();
    if let Some(coingecko) = fx.coingecko.as_ref() {
        coin_price_providers.push(CoinPriceProvider::CoinGecko(CoinGeckoConfig {
            tier: coingecko.tier,
            api_key: coingecko.api_key.clone(),
        }));
    }
    coin_price_providers.push(CoinPriceProvider::CoinPaprika);
    Ok(Some(FxRefreshConfig {
        coin_price_providers,
        turbo_payment_url: storage.payment_url.clone(),
        arweave_gateway_url: storage.gateway_url.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A storage config for a given backend, with plausible non-zero values and the
    /// timeout ordering invariants satisfied. The backend-specific URLs are filled
    /// in for every backend so a single helper drives the whole fail-fast matrix.
    fn storage_config(backend: StorageBackendKind) -> StorageConfig {
        StorageConfig {
            backend,
            upload_url: "https://upload.example".to_string(),
            payment_url: "https://payment.example".to_string(),
            gateway_url: "https://arweave.net".to_string(),
            arlocal_endpoint: "http://localhost:1984".to_string(),
            staging_dir: std::env::temp_dir(),
            durable_staging_dir: std::env::temp_dir().join("durable"),
            free_storage_bytes: 102_400,
            ar_usd_per_byte_femto: 1_500,
            winc_refresh_schedule: "0 */5 * * * *".to_string(),
            winc_safety_floor: rust_decimal::Decimal::from(5_000),
            winc_drift_alert_threshold: rust_decimal::Decimal::from(100_000),
            reconcile_horizon: Duration::from_secs(900),
            upload_timeout: Duration::from_secs(300),
            upload_claim_lease_ttl: Duration::from_secs(360),
            attempt_stuck_passes: 12,
            session_limits: gateway_core::storage::UploadSessionLimits::default(),
        }
    }

    /// A pool that never connects: `build_storage_backend` only stores the pool on
    /// the Turbo backend and never queries during construction, so a lazy pool is
    /// enough to exercise the fail-fast matrix without a database.
    fn lazy_pool() -> sqlx::PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .expect("a lazy pool needs no live connection")
    }

    /// An empty unlocked keyring for the construction tests. ArLocal's signer is
    /// only resolved at upload time, so backend construction (the fail-fast matrix
    /// these tests cover) never consults it.
    fn test_keyring() -> Arc<UnlockedKeyring> {
        Arc::new(UnlockedKeyring::empty_for_tests())
    }

    #[tokio::test]
    async fn the_turbo_backend_constructs() {
        let backend = build_storage_backend(
            lazy_pool(),
            &storage_config(StorageBackendKind::Turbo),
            false,
            test_keyring(),
        )
        .expect("the turbo backend constructs");
        assert_eq!(backend.name(), "turbo");
    }

    #[tokio::test]
    async fn the_arlocal_backend_constructs_off_production() {
        // ArLocal is a dev emulator; it constructs when the deployment is NOT on a
        // production network.
        let backend = build_storage_backend(
            lazy_pool(),
            &storage_config(StorageBackendKind::ArLocal),
            false,
            test_keyring(),
        )
        .expect("the arlocal backend constructs off production");
        assert_eq!(backend.name(), "arlocal");
    }

    #[tokio::test]
    async fn arlocal_on_a_production_network_fails_at_boot() {
        // The two config axes are independent, but ArLocal must never serve a
        // production deployment: selecting it with `is_production` is a boot error.
        // `Arc<dyn StorageBackend>` is not `Debug`, so the Ok arm is asserted by a
        // match rather than `expect_err`.
        match build_storage_backend(
            lazy_pool(),
            &storage_config(StorageBackendKind::ArLocal),
            true,
            test_keyring(),
        ) {
            Ok(_) => panic!("arlocal on a production network must fail at boot"),
            Err(err) => assert!(
                err.to_string().contains("production"),
                "the error explains the production guard, got {err}"
            ),
        }
    }

    #[tokio::test]
    async fn the_direct_arweave_backend_fails_at_boot_until_implemented() {
        // Selectable but not yet implemented: it fails fast rather than serving a
        // backend that cannot store. The production posture does not matter.
        for is_production in [false, true] {
            match build_storage_backend(
                lazy_pool(),
                &storage_config(StorageBackendKind::DirectArweave),
                is_production,
                test_keyring(),
            ) {
                Ok(_) => {
                    panic!("the direct-arweave backend must fail at boot until implemented")
                }
                Err(err) => assert!(
                    err.to_string().contains("not yet implemented"),
                    "the error explains the unimplemented backend, got {err}"
                ),
            }
        }
    }
}
