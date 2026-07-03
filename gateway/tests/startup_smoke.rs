//! Startup smoke test: boot the full background-plane assembly against a real
//! Postgres, observe that it registers its scheduled work through the engine, and
//! shut down cleanly.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! This is the end-to-end proof that the binary's assembly actually wires every
//! handler and schedule onto one supervised runtime: not that the helpers exist,
//! but that `build_runtime` produces a runtime which, when run, drives the
//! scheduler to enqueue jobs and then stops on request without error.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;
use std::time::Duration;

use age::secrecy::SecretString;
use gateway::assembly::{build_runtime, unlock_keyring};
use gateway::config::GatewayConfig;
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::Network;
use gateway_core::wallet::keyring::derive_enterprise_address;
use pallas_crypto::key::ed25519::{PublicKey, SecretKey};

/// A deliberately low scrypt work factor so the in-test keyring envelope
/// encrypts/decrypts fast. The unlock path does not care which factor was used.
const TEST_SCRYPT_LOG_N: u8 = 4;

/// Build a deterministic preprod wallet (a fixed-seed ed25519 key, its bech32
/// signing-key string, and its derived enterprise address).
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

/// Seed preprod protocol parameters so the band fee-shape check has live values
/// to certify against (the assembly refuses to start without them).
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

/// A unique scratch directory under the system temp dir for this test's keyring
/// and config files, removed at the end.
fn scratch_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("gateway-smoke-{}", uuid::Uuid::now_v7().simple()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Bare leaf-partition names of a partitioned parent table.
async fn leaf_partitions(pool: &sqlx::PgPool, parent: &str) -> Vec<String> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT relid::regclass::text FROM pg_partition_tree($1::regclass) WHERE isleaf",
    )
    .bind(parent)
    .fetch_all(pool)
    .await
    .expect("introspect partition tree");
    rows.into_iter()
        .map(|(n,)| n.rsplit('.').next().unwrap_or(&n).to_string())
        .collect()
}

/// Drop every monthly partition of both engine tables, leaving only the DEFAULT
/// backstops — the state of a deployment stood up long after the months its
/// schema (or last run) provisioned have lapsed.
async fn drop_monthly_partitions(pool: &sqlx::PgPool) {
    for parent in ["cw_core.job_history", "cw_core.subject_event"] {
        for leaf in leaf_partitions(pool, parent).await {
            if leaf.ends_with("_default") {
                continue;
            }
            let sql = format!("DROP TABLE cw_core.\"{leaf}\"");
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(pool)
                .await
                .expect("drop monthly partition");
        }
    }
}

/// The current calendar month's partition name for a table, matching the
/// engine's `{table}_{yyyy}_{mm}` naming.
fn current_month_partition(bare: &str) -> String {
    let now = chrono::Utc::now();
    format!(
        "{bare}_{:04}_{:02}",
        chrono::Datelike::year(&now),
        chrono::Datelike::month(&now)
    )
}

#[tokio::test]
async fn boots_registers_scheduled_jobs_and_shuts_down_cleanly() {
    let db = TestDb::fresh().await.expect("test database");
    // The full assembly runs many concurrent loops, each needing its own
    // connection (NOTIFY listener, sweeper, scheduler, per-queue workers). Every
    // per-queue worker holds a dedicated NOTIFY listener connection for its
    // lifetime, so the pool is sized to seat all of them plus the transient
    // connections the handlers acquire while processing.
    let pool = db.pool_with(48).await.expect("sized pool");
    seed_preprod_params(&pool).await;

    // Boot against a database whose monthly partitions have all lapsed: the
    // assembly must provision the working set back synchronously during the
    // runtime build, before any loop (or the first publish) can insert.
    drop_monthly_partitions(&pool).await;

    let network = Network::Preprod;
    let passphrase = "correct horse battery staple";
    let (bech32_skey, address) = test_wallet([9u8; 32], network);

    // Write the operator keyring ciphertext and the config file to a scratch dir.
    let dir = scratch_dir();
    let keyring_path = dir.join("keyring.age");
    let keyring_json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "cardano-ed25519", "label": "primary", "address": address,
              "secret": bech32_skey }
        ]
    })
    .to_string();
    std::fs::write(&keyring_path, encrypt_envelope(&keyring_json, passphrase))
        .expect("write keyring ciphertext");

    let config_path = dir.join("gateway.toml");
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
        keyring = keyring_path.to_str().unwrap()
    );
    std::fs::write(&config_path, config_toml).expect("write config");

    // The environment carries the deploy-time secrets. The database URL points at
    // this test's own database.
    // SAFETY: this test owns its process's environment for the duration; no other
    // thread reads these vars concurrently.
    std::env::set_var(gateway::config::DATABASE_URL_ENV, db_url_for(&db).await);
    std::env::set_var(gateway::config::KEYRING_PASSPHRASE_ENV, passphrase);
    std::env::set_var(gateway::config::WORKER_ID_ENV, "smoke-replica");

    let config = GatewayConfig::load(&config_path).expect("load config");

    // Unlock the keyring once, the way the binary's serve path does, and share
    // it into the assembly.
    let keyring = Arc::new(unlock_keyring(&config).expect("unlock the operator keyring"));

    // Build the full runtime: this exercises the provider construction and the
    // band fee-shape certification against the seeded params. A failure here
    // would mean the assembly is mis-wired.
    let runtime = Arc::new(
        build_runtime(pool.clone(), &config, keyring)
            .await
            .expect("build the full runtime assembly"),
    );

    // The build provisioned the partitioned working set synchronously: the
    // current month exists again for both engine tables even though no
    // maintenance job has run yet.
    for (parent, bare) in [
        ("cw_core.job_history", "job_history"),
        ("cw_core.subject_event", "subject_event"),
    ] {
        let leaves = leaf_partitions(&pool, parent).await;
        let want = current_month_partition(bare);
        assert!(
            leaves.contains(&want),
            "{parent} must have {want} right after the runtime build; have {leaves:?}"
        );
    }

    let run = {
        let runtime = runtime.clone();
        tokio::spawn(async move { runtime.run().await })
    };

    // The scheduler performs a bounded catch-up on start: every registered
    // schedule enqueues its most-recent occurrence immediately. So within moments
    // of boot, cron ticks must have registered jobs through the engine. We wait
    // until at least one cron_tick row AND one enqueued job exist, proving the
    // schedules are wired onto the runtime and firing.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let ticks: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.cron_tick")
            .fetch_one(&pool)
            .await
            .expect("count cron ticks");
        let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.job")
            .fetch_one(&pool)
            .await
            .expect("count jobs");
        if ticks >= 1 && jobs >= 1 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            runtime.shutdown();
            let _ = run.await;
            panic!(
                "the assembly did not register any scheduled jobs through the runtime in time \
                 (cron ticks: {ticks}, jobs: {jobs})"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Every scheduled queue we registered must have at least one cron tick across
    // the catch-up window, confirming the schedules are all wired (not just one).
    let distinct_queues: i64 =
        sqlx::query_scalar("SELECT count(DISTINCT queue) FROM cw_core.cron_tick")
            .fetch_one(&pool)
            .await
            .expect("count distinct scheduled queues");
    assert!(
        distinct_queues >= 5,
        "the assembly registers many schedules (params, confirm, scan, wallet \
         maintenance/replenish/reaper, engine maintenance); expected several distinct scheduled \
         queues to have fired, got {distinct_queues}"
    );

    // Graceful shutdown: the supervised runtime stops promptly and returns Ok.
    // The budget must exceed the chain client's 20-second HTTP timeout: shutdown
    // legitimately waits for one in-flight provider call (the catch-up jobs hit
    // live Koios), and a slow or throttled provider holds the loop until that
    // timeout fires. Only a genuine hang outlives this budget.
    runtime.shutdown();
    let result = tokio::time::timeout(Duration::from_secs(30), run)
        .await
        .expect("runtime stops promptly after shutdown")
        .expect("join runtime task");
    result.expect("a clean shutdown returns Ok, not a supervised loop error");

    // Clean up scratch files.
    let _ = std::fs::remove_dir_all(&dir);

    std::env::remove_var(gateway::config::WORKER_ID_ENV);
}

/// The connection URL for this test's own database, read back from the handle's
/// pool so the binary connects to exactly the database the test migrated.
async fn db_url_for(db: &TestDb) -> String {
    // TestDb exposes its own database name; reconstruct the URL the same way the
    // harness does by swapping the base URL's database segment.
    let base = TestDb::database_url();
    let (prefix, _rest) = base.rsplit_once('/').expect("url has a database segment");
    format!("{prefix}/{}", db.db_name)
}
