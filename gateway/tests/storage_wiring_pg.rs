//! Storage-wiring boot tests: prove the binary builds the storage seam and
//! registers the storage crons from a `[storage]` configuration, and that a
//! deployment without `[storage]` runs hash-only.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! The pure fail-fast matrix (arlocal-on-mainnet, direct-arweave, valid turbo)
//! lives in `assembly`'s own unit tests; these tests cover the database-backed
//! boot path: the data-plane storage seam the uploads route runs through, the
//! recovery-sweep cron the runtime registers, and the hash-only fallback.

#![cfg(feature = "pg-tests")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use age::secrecy::SecretString;
use ans104::{Ans104Signer, ArweaveJwkSigner};
use gateway::assembly::{build_runtime, build_storage, funding_keys, unlock_keyring};
use gateway::config::{GatewayConfig, StorageBackendKind};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::{arweave_address, derive_enterprise_address};
use pallas_crypto::key::ed25519::{PublicKey, SecretKey};

/// A deliberately low scrypt work factor so the in-test keyring envelope
/// encrypts/decrypts fast. The unlock path does not care which factor was used.
const TEST_SCRYPT_LOG_N: u8 = 4;

/// The throwaway Arweave JWK the keyring's funding entry signs with, the same
/// fixture the ANS-104 and storage suites use.
const TEST_JWK_JSON: &str = include_str!("../../ans104/tests/vectors/test-jwk.json");

/// The Arweave address derived from the fixture JWK. The keyring's unlock verifies
/// the claimed address against this derivation, so the entry must carry exactly it.
fn fixture_arweave_address() -> String {
    let signer = ArweaveJwkSigner::from_jwk_json(TEST_JWK_JSON).expect("fixture jwk parses");
    arweave_address(&signer.owner())
}

/// Build a deterministic wallet (a fixed-seed ed25519 key, its bech32 signing-key
/// string, and its derived enterprise address) on a network.
fn test_wallet(seed: [u8; 32], network: Network) -> (String, String) {
    let secret = SecretKey::from(seed);
    let public: PublicKey = secret.public_key();
    let mut vk = [0u8; 32];
    vk.copy_from_slice(public.as_ref());
    let hrp = bech32::Hrp::parse("ed25519_sk").expect("valid hrp");
    let bech32_skey = bech32::encode::<bech32::Bech32>(hrp, &seed).expect("encode skey");
    let address = derive_enterprise_address(&vk, network).expect("derive address");
    (bech32_skey, address)
}

/// Encrypt a keyring JSON document under `passphrase` as an age scrypt envelope.
fn encrypt_envelope(json: &str, passphrase: &str) -> Vec<u8> {
    let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_string()));
    recipient.set_work_factor(TEST_SCRYPT_LOG_N);
    age::encrypt(&recipient, json.as_bytes()).expect("encrypt keyring envelope")
}

/// Seed preprod protocol parameters so the band fee-shape check has live values to
/// certify against (the assembly refuses to start without them).
async fn seed_preprod_params(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO cw_core.cardano_protocol_params \
           (network, epoch, min_fee_a, min_fee_b, coins_per_utxo_byte, max_tx_size, raw) \
         VALUES ('preprod', 500, 44, 155381, 4310, 16384, $1)",
    )
    .bind(serde_json::json!({ "epoch_no": 500 }))
    .execute(pool)
    .await
    .expect("seed preprod params");
}

/// A unique scratch directory under the system temp dir, removed at the end.
fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "gateway-storage-wiring-{}",
        uuid::Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Write a keyring carrying a Cardano wallet (for the fee-shape check) plus the
/// Arweave funding entry, and return its ciphertext path under `dir`.
fn write_keyring(
    dir: &std::path::Path,
    wallet_address: &str,
    wallet_skey: &str,
    passphrase: &str,
) -> PathBuf {
    let keyring_path = dir.join("keyring.age");
    let keyring_json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "cardano-ed25519", "label": "primary", "address": wallet_address,
              "secret": wallet_skey },
            { "kind": "arweave-rsa", "label": "storage", "address": fixture_arweave_address(),
              "secret": TEST_JWK_JSON }
        ]
    })
    .to_string();
    std::fs::write(&keyring_path, encrypt_envelope(&keyring_json, passphrase))
        .expect("write keyring ciphertext");
    keyring_path
}

/// The connection URL for this test's own database.
fn db_url_for(db: &TestDb) -> String {
    let base = TestDb::database_url();
    let (prefix, _rest) = base.rsplit_once('/').expect("url has a database segment");
    format!("{prefix}/{}", db.db_name)
}

/// Serializes the env-mutation window across the tests in this binary. The deploy
/// secrets reach `GatewayConfig::load` only through process-global environment
/// variables, which every `#[tokio::test]` here writes; the tests run concurrently
/// on a shared runtime, so without this guard one test's `set_var` could race
/// another's read inside `load`. Holding the lock across the set + load + restore
/// makes the environment consistent for the duration of each load.
static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII scope over the deploy-secret environment variables, held for the set + load
/// window. On construction it locks [`ENV_GUARD`] (mutual exclusion), captures each
/// variable's PRIOR value, and sets the test values. On `Drop` it restores each
/// prior value (unsetting any that was absent) and releases the lock.
///
/// `Drop` runs on a normal return AND on unwind, so a test that panics inside the
/// window cannot leak its env values into a later test. The mutex is held for the
/// guard's whole lifetime, so the set + load + restore is atomic against siblings:
/// no concurrent test observes a half-written or half-restored environment.
struct EnvScope {
    _lock: std::sync::MutexGuard<'static, ()>,
    prior: Vec<(&'static str, Option<String>)>,
}

impl EnvScope {
    fn set(vars: &[(&'static str, String)]) -> Self {
        let lock = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prior = vars
            .iter()
            .map(|(key, value)| {
                let prior = std::env::var(key).ok();
                std::env::set_var(key, value);
                (*key, prior)
            })
            .collect();
        Self { _lock: lock, prior }
    }
}

impl Drop for EnvScope {
    fn drop(&mut self) {
        for (key, prior) in &self.prior {
            match prior {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

/// Load a `GatewayConfig` from a config TOML string written to `dir`, with the
/// deploy-time secrets supplied through the environment.
///
/// The set-then-load window runs under an [`EnvScope`] so concurrent tests in this
/// binary never observe each other's half-written environment, and the scope's
/// `Drop` restores the prior values even if `load` (or the test) panics. The config
/// captures the secrets into its own fields during `load`, so restoring the
/// environment afterwards does not affect the returned config.
fn load_config(
    dir: &std::path::Path,
    config_toml: &str,
    db: &TestDb,
    passphrase: &str,
) -> GatewayConfig {
    let config_path = dir.join("gateway.toml");
    std::fs::write(&config_path, config_toml).expect("write config");
    let _env = EnvScope::set(&[
        (gateway::config::DATABASE_URL_ENV, db_url_for(db)),
        (
            gateway::config::KEYRING_PASSPHRASE_ENV,
            passphrase.to_string(),
        ),
    ]);
    GatewayConfig::load(&config_path).expect("load config")
}

#[tokio::test]
async fn a_storage_section_builds_the_data_plane_seam_and_funding_keys() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool_with(4).await.expect("sized pool");

    let network = Network::Preprod;
    let passphrase = "correct horse battery staple";
    let (wallet_skey, wallet_address) = test_wallet([21u8; 32], network);

    let dir = scratch_dir();
    let keyring_path = write_keyring(&dir, &wallet_address, &wallet_skey, passphrase);
    let durable = dir.join("durable");

    // A valid arlocal storage section: it does not require a production posture and
    // never contacts the network at build time.
    let config_toml = format!(
        r#"
            network = "preprod"
            keyring_path = "{keyring}"
            [band]
            min = 4000000
            max = 8000000
            mid = 6000000
            [wallet]
            lease_secs = 120
            min_canonical_count = 4
            [storage]
            backend = "arlocal"
            arlocal_endpoint = "http://localhost:1984"
            durable_staging_dir = "{durable}"
            ar_usd_per_byte_femto = 1500
            upload_timeout_secs = 30
            reconcile_horizon_secs = 60
            upload_claim_lease_ttl_secs = 45
        "#,
        keyring = keyring_path.to_str().unwrap(),
        durable = durable.to_str().unwrap(),
    );
    let config = load_config(&dir, &config_toml, &db, passphrase);

    let storage_cfg = config
        .storage
        .as_ref()
        .expect("the [storage] section resolves");
    assert_eq!(storage_cfg.backend, StorageBackendKind::ArLocal);

    // Unlock the keyring once, the way the binary's serve path does, and share
    // it into every seam below.
    let keyring = Arc::new(unlock_keyring(&config).expect("unlock the operator keyring"));

    // The data-plane storage seam builds: the backend POSTs through arlocal and the
    // upload-signing seam carries the durable directory and the in-flight deadlines.
    let storage_state = build_storage(pool.clone(), &config, storage_cfg, keyring.clone())
        .expect("the data-plane storage seam builds");
    assert_eq!(storage_state.backend_name(), "arlocal");
    let signing = storage_state
        .signing()
        .expect("the keyring holds an Arweave key, so the paid-upload signing seam is wired");
    assert_eq!(signing.durable_staging_dir(), durable.as_path());
    assert_eq!(signing.upload_timeout(), Duration::from_secs(30));
    assert_eq!(signing.upload_claim_lease_ttl(), Duration::from_secs(45));

    // The control plane sees the verified Arweave funding key the instance holds,
    // so the source-register route can confirm possession.
    let keys = funding_keys(&keyring);
    assert_eq!(
        keys.len(),
        1,
        "the keyring holds exactly one Arweave funding key"
    );
    assert_eq!(keys[0].address, fixture_arweave_address());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_hash_only_deployment_wires_no_storage_seam() {
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool_with(4).await.expect("sized pool");

    let network = Network::Preprod;
    let passphrase = "correct horse battery staple";
    let (wallet_skey, wallet_address) = test_wallet([22u8; 32], network);

    let dir = scratch_dir();
    let keyring_path = write_keyring(&dir, &wallet_address, &wallet_skey, passphrase);

    // No `[storage]` section: an intentional hash-only deployment.
    let config_toml = format!(
        r#"
            network = "preprod"
            keyring_path = "{keyring}"
            [band]
            min = 4000000
            max = 8000000
            mid = 6000000
            [wallet]
            lease_secs = 120
            min_canonical_count = 4
        "#,
        keyring = keyring_path.to_str().unwrap(),
    );
    let config = load_config(&dir, &config_toml, &db, passphrase);

    assert!(
        config.storage.is_none(),
        "a deployment without a [storage] section runs hash-only"
    );
    // The build_storage seam is simply not invoked; the funding keys still resolve
    // (the keyring still holds the Arweave entry) but no source can be registered
    // without storage wired, which is the control plane's concern, not this boot's.
    let _ = pool;

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_storage_section_registers_the_recovery_sweep_cron() {
    let db = TestDb::fresh().await.expect("test database");
    // The full assembly runs many concurrent loops, each needing its own connection.
    let pool = db.pool_with(32).await.expect("sized pool");
    seed_preprod_params(&pool).await;

    let network = Network::Preprod;
    let passphrase = "correct horse battery staple";
    let (wallet_skey, wallet_address) = test_wallet([23u8; 32], network);

    let dir = scratch_dir();
    let keyring_path = write_keyring(&dir, &wallet_address, &wallet_skey, passphrase);
    let durable = dir.join("durable");

    // The arlocal backend registers the backend-agnostic recovery-sweep and staging
    // janitor without the winc-credit reconcile loop (which is Turbo-only), so the
    // boot enqueues no job that would reach out to a winc provider.
    let config_toml = format!(
        r#"
            network = "preprod"
            keyring_path = "{keyring}"
            [band]
            min = 4000000
            max = 8000000
            mid = 6000000
            [wallet]
            lease_secs = 120
            min_canonical_count = 4
            [storage]
            backend = "arlocal"
            arlocal_endpoint = "http://localhost:1984"
            durable_staging_dir = "{durable}"
            ar_usd_per_byte_femto = 1500
            upload_timeout_secs = 30
            reconcile_horizon_secs = 60
            upload_claim_lease_ttl_secs = 45
        "#,
        keyring = keyring_path.to_str().unwrap(),
        durable = durable.to_str().unwrap(),
    );
    let config = load_config(&dir, &config_toml, &db, passphrase);

    let keyring = Arc::new(unlock_keyring(&config).expect("unlock the operator keyring"));
    let runtime = Arc::new(
        build_runtime(pool.clone(), &config, keyring)
            .await
            .expect("build the full runtime assembly with storage wired"),
    );

    let run = {
        let runtime = runtime.clone();
        tokio::spawn(async move { runtime.run().await })
    };

    // Both backend-agnostic storage crons fire on the catch-up pass, so within
    // moments of boot a cron tick must exist on each queue, proving they are wired
    // onto the runtime (not merely constructed). The recovery sweep recovers
    // interrupted upload attempts; the staging janitor reclaims orphaned durable
    // staged files. A janitor registered with a policy and handler but no schedule
    // would never fire a tick here.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let (swept, janitor_scheduled) = loop {
        let swept: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM cw_core.cron_tick WHERE queue = 'storage_attempt_reconcile'",
        )
        .fetch_one(&pool)
        .await
        .expect("count storage-sweep cron ticks");
        let janitor: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM cw_core.cron_tick WHERE queue = 'storage_staging_janitor'",
        )
        .fetch_one(&pool)
        .await
        .expect("count staging-janitor cron ticks");
        if swept >= 1 && janitor >= 1 {
            break (true, true);
        }
        if std::time::Instant::now() >= deadline {
            break (swept >= 1, janitor >= 1);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    // The budget must exceed the chain client's 20-second HTTP timeout: shutdown
    // legitimately waits for one in-flight provider call, and a slow or throttled
    // provider holds the loop until that timeout fires. Only a genuine hang
    // outlives this budget.
    runtime.shutdown();
    let result = tokio::time::timeout(Duration::from_secs(30), run)
        .await
        .expect("runtime stops promptly after shutdown")
        .expect("join runtime task");
    result.expect("a clean shutdown returns Ok, not a supervised loop error");

    assert!(
        swept,
        "the recovery-sweep cron did not fire a tick, so the storage crons are not wired"
    );
    assert!(
        janitor_scheduled,
        "the staging-janitor cron did not fire a tick, so its schedule is not wired and \
         orphaned durable staged files would leak for the deployment's lifetime"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
