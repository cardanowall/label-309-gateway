//! Integration coverage for stocking a wallet the moment it is registered.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! Registration alone leaves a wallet with no canonical UTxOs until the periodic
//! replenish cron next ticks, so a freshly registered wallet is unspendable for up
//! to one cron interval. Registration must instead TRIGGER the grooming it depends
//! on: register the wallet, issue its spend grant, and enqueue a targeted replenish
//! in one transaction, so the next worker tick stocks exactly that wallet and a
//! publish can select it without waiting for the periodic pass. This suite drives
//! that end to end against a real Postgres, the real Conway split builder, a mock
//! UTxO source, and the stub submitter.

#![cfg(feature = "pg-tests")]

use std::sync::{Arc, Mutex};

use age::secrecy::SecretString;
use gateway_core::runtime::policy::reconcile;
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use gateway_core::wallet::grant::GrantScope;
use gateway_core::wallet::keyring::{derive_enterprise_address, unlock, UnlockedKeyring};
use gateway_core::wallet::operator::{
    create_operator, register_wallet_and_grant, RegisterAndGrantOutcome,
};
use gateway_core::wallet::pool::pick_wallet;
use gateway_core::wallet::replenish::{
    replenish_policy, GroomOutcome, ReplenishHandler, ReplenishPayload, REPLENISH_QUEUE,
};
use gateway_core::wallet::submitter::StubSubmitter;
use gateway_core::wallet::utxo::{self, ConfirmedSpend, ObservedUtxo, UtxoRef, UtxoSource};
use gateway_core::Result;
use uuid::Uuid;
use zeroize::Zeroizing;

use cardano_poe_tx::{ProtocolParams, SigningKey};

/// A low scrypt work factor so the test keyring encrypt/decrypt is fast.
const TEST_SCRYPT_LOG_N: u8 = 2;

fn band() -> LovelaceBand {
    LovelaceBand::new(4_000_000, 8_000_000, 6_000_000).expect("band")
}

fn config(min_canonical_count: u32) -> WalletConfig {
    WalletConfig::new(
        Network::Preprod,
        band(),
        std::time::Duration::from_secs(120),
        min_canonical_count,
    )
    .expect("config")
}

fn params() -> ProtocolParams {
    ProtocolParams {
        min_fee_a: 44,
        min_fee_b: 155_381,
        coins_per_utxo_byte: 4_310,
        max_tx_size: 16_384,
    }
}

async fn seed_params(pool: &sqlx::PgPool) {
    let p = params();
    sqlx::query(
        "INSERT INTO cw_core.cardano_protocol_params \
           (network, epoch, min_fee_a, min_fee_b, coins_per_utxo_byte, max_tx_size, raw) \
         VALUES ('preprod', 500, $1, $2, $3, $4, $5)",
    )
    .bind(p.min_fee_a as i64)
    .bind(p.min_fee_b as i64)
    .bind(p.coins_per_utxo_byte as i64)
    .bind(p.max_tx_size as i64)
    .bind(serde_json::json!({ "epoch_no": 500 }))
    .execute(pool)
    .await
    .expect("seed params");
}

/// A mock UTxO source returning a fixed set of observed outputs for any address.
struct MockUtxoSource {
    outputs: Mutex<Vec<ObservedUtxo>>,
}

impl MockUtxoSource {
    fn new(outputs: Vec<ObservedUtxo>) -> Self {
        Self {
            outputs: Mutex::new(outputs),
        }
    }
}

impl UtxoSource for MockUtxoSource {
    async fn address_utxos(&self, _address: &str) -> Result<Vec<ObservedUtxo>> {
        Ok(self.outputs.lock().expect("source lock").clone())
    }
}

/// An oversized pure-ADA source the replenisher can split into a band-mid set.
fn splittable_source(config: &WalletConfig, byte: u8) -> ObservedUtxo {
    ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [byte; 32],
            output_index: 0,
        },
        // Enough for four band-mid (6 ADA) outputs plus fee and change.
        lovelace: config.band.mid * 5 + 50_000_000,
        pure_ada: true,
    }
}

/// Build an unlocked keyring holding the signer for `seed` on preprod. This is the
/// form the replenish handler resolves a wallet's signer from.
fn unlocked_keyring(seed: [u8; 32], address: &str) -> Arc<UnlockedKeyring> {
    let hrp = bech32::Hrp::parse("ed25519_sk").expect("hrp");
    let bech32_skey = bech32::encode::<bech32::Bech32>(hrp, &seed).expect("encode skey");
    let json = serde_json::json!({
        "version": 1,
        "entries": [
            { "kind": "cardano-ed25519", "label": "primary", "address": address,
              "secret": bech32_skey }
        ]
    })
    .to_string();
    let mut recipient = age::scrypt::Recipient::new(SecretString::from("test-passphrase"));
    recipient.set_work_factor(TEST_SCRYPT_LOG_N);
    let envelope = age::encrypt(&recipient, json.as_bytes()).expect("encrypt envelope");
    let keyring = unlock(
        &envelope,
        Zeroizing::new("test-passphrase".to_string()),
        Network::Preprod,
    )
    .expect("unlock keyring");
    Arc::new(keyring)
}

/// The split tx id every minted change row shares.
async fn read_change_tx_hash(pool: &sqlx::PgPool, wallet_id: Uuid) -> [u8; 32] {
    let raw: Vec<u8> = sqlx::query_scalar(
        "SELECT tx_hash FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND source = 'change' LIMIT 1",
    )
    .bind(wallet_id)
    .fetch_one(pool)
    .await
    .expect("read change tx hash");
    raw.as_slice().try_into().expect("32-byte tx hash")
}

/// Count the in-flight (available/running) replenish jobs for a wallet's targeted
/// singleton key. A targeted enqueue lands exactly one; the singleton dedupe keeps
/// a re-register or a racing periodic enqueue from minting a second.
async fn pending_targeted_jobs(pool: &sqlx::PgPool, wallet_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.job \
         WHERE queue = $1 AND singleton_key = $2 AND state IN ('available', 'running')",
    )
    .bind(REPLENISH_QUEUE)
    .bind(ReplenishPayload::singleton_key(wallet_id))
    .fetch_one(pool)
    .await
    .expect("count targeted jobs")
}

/// Registering a wallet writes the wallet row, its spend grant, AND a targeted
/// replenish job in one transaction: all three are present after a single call,
/// and the job's payload names exactly the registered wallet. This is the atomic
/// register -> grant -> enqueue unit the spendability gap fix rests on.
#[tokio::test]
async fn register_writes_wallet_grant_and_targeted_replenish_atomically() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    // The targeted enqueue resolves its attempt/backoff defaults from the queue
    // policy row, so the policy must be reconciled before a register can enqueue.
    reconcile(&db.pool, &replenish_policy())
        .await
        .expect("reconcile replenish policy");

    let operator_id = create_operator(&db.pool, "operator")
        .await
        .expect("operator");
    let seed = [0x11; 32];
    let address = derive_enterprise_address(
        &SigningKey::from_seed(seed).verification_key(),
        config.network,
    )
    .expect("address");

    let outcome = register_wallet_and_grant(
        &db.pool,
        operator_id,
        "primary",
        &address,
        config.network,
        GrantScope::Service,
    )
    .await
    .expect("register and grant");
    let (wallet_id, grant_id) = match outcome {
        RegisterAndGrantOutcome::Registered { wallet, grant_id } => (wallet.wallet_id, grant_id),
        other => panic!("expected a fresh registration, got {other:?}"),
    };

    // The wallet row exists and is active.
    let status: String =
        sqlx::query_scalar("SELECT status FROM cw_core.operator_wallet WHERE id = $1")
            .bind(wallet_id)
            .fetch_one(&db.pool)
            .await
            .expect("wallet row");
    assert_eq!(status, "active", "the registered wallet is active");

    // The auto-issued service grant exists and is live.
    let live_grant: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM cw_core.wallet_grant \
         WHERE id = $1 AND wallet_id = $2 AND scope_kind = 'service' AND revoked_at IS NULL)",
    )
    .bind(grant_id)
    .bind(wallet_id)
    .fetch_one(&db.pool)
    .await
    .expect("grant row");
    assert!(live_grant, "the register auto-issued a live service grant");

    // Exactly one targeted replenish job is queued, and its payload names this
    // wallet (the targeted pass, not the all-wallets cron payload).
    assert_eq!(
        pending_targeted_jobs(&db.pool, wallet_id).await,
        1,
        "registration enqueued exactly one targeted replenish for this wallet"
    );
    let payload: serde_json::Value = sqlx::query_scalar(
        "SELECT payload FROM cw_core.job WHERE queue = $1 AND singleton_key = $2",
    )
    .bind(REPLENISH_QUEUE)
    .bind(ReplenishPayload::singleton_key(wallet_id))
    .fetch_one(&db.pool)
    .await
    .expect("job payload");
    assert_eq!(
        ReplenishPayload::parse(&payload).expect("payload parses"),
        ReplenishPayload::Wallet(wallet_id),
        "the queued job carries the targeted wallet_id payload"
    );
}

/// A re-register (or any racing enqueue) of the same wallet does not mint a second
/// targeted replenish job: the per-wallet singleton key dedupes the enqueue to a
/// no-op, so a re-register re-asserts the wallet and grant idempotently and leaves
/// exactly one queued job.
#[tokio::test]
async fn re_register_dedupes_the_targeted_replenish() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    reconcile(&db.pool, &replenish_policy())
        .await
        .expect("reconcile replenish policy");

    let operator_id = create_operator(&db.pool, "operator")
        .await
        .expect("operator");
    let seed = [0x22; 32];
    let address = derive_enterprise_address(
        &SigningKey::from_seed(seed).verification_key(),
        config.network,
    )
    .expect("address");

    let first = register_wallet_and_grant(
        &db.pool,
        operator_id,
        "primary",
        &address,
        config.network,
        GrantScope::Service,
    )
    .await
    .expect("first register");
    let wallet_id = match first {
        RegisterAndGrantOutcome::Registered { wallet, .. } => wallet.wallet_id,
        other => panic!("expected a fresh registration, got {other:?}"),
    };
    assert_eq!(pending_targeted_jobs(&db.pool, wallet_id).await, 1);

    // Re-register the same address under the same operator: a rename in place. The
    // grant re-asserts idempotently and the targeted enqueue is suppressed because
    // the first job is still in flight (singleton dedupe).
    let second = register_wallet_and_grant(
        &db.pool,
        operator_id,
        "renamed",
        &address,
        config.network,
        GrantScope::Service,
    )
    .await
    .expect("second register");
    match second {
        RegisterAndGrantOutcome::Registered { wallet, .. } => {
            assert_eq!(
                wallet.wallet_id, wallet_id,
                "the re-register renames the same wallet in place"
            );
            assert!(!wallet.inserted, "the re-register did not insert a new row");
        }
        other => panic!("expected an idempotent re-register, got {other:?}"),
    }

    assert_eq!(
        pending_targeted_jobs(&db.pool, wallet_id).await,
        1,
        "the singleton key dedupes a re-register to a single queued replenish"
    );
}

/// The targeted payload grooms exactly the named wallet and leaves a sibling wallet
/// untouched: running `run_once_for(wallet_id)` splits only that wallet's source,
/// so the targeted pass is a precise per-wallet groom, not an all-wallets pass.
#[tokio::test]
async fn targeted_pass_grooms_exactly_one_wallet() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    seed_params(&db.pool).await;
    reconcile(&db.pool, &replenish_policy())
        .await
        .expect("reconcile replenish policy");

    let operator_id = create_operator(&db.pool, "operator")
        .await
        .expect("operator");

    // Two wallets, each with its own derived address and signer.
    let seed_a = [0x33; 32];
    let seed_b = [0x44; 32];
    let addr_a = derive_enterprise_address(
        &SigningKey::from_seed(seed_a).verification_key(),
        config.network,
    )
    .expect("addr a");
    let addr_b = derive_enterprise_address(
        &SigningKey::from_seed(seed_b).verification_key(),
        config.network,
    )
    .expect("addr b");

    let wallet_a = match register_wallet_and_grant(
        &db.pool,
        operator_id,
        "a",
        &addr_a,
        config.network,
        GrantScope::Service,
    )
    .await
    .expect("register a")
    {
        RegisterAndGrantOutcome::Registered { wallet, .. } => wallet.wallet_id,
        other => panic!("register a: {other:?}"),
    };
    let wallet_b = match register_wallet_and_grant(
        &db.pool,
        operator_id,
        "b",
        &addr_b,
        config.network,
        GrantScope::Service,
    )
    .await
    .expect("register b")
    {
        RegisterAndGrantOutcome::Registered { wallet, .. } => wallet.wallet_id,
        other => panic!("register b: {other:?}"),
    };

    // A handler whose keyring and source serve wallet A only. Running the targeted
    // pass for A grooms A; B is never touched by this pass.
    let keyring = unlocked_keyring(seed_a, &addr_a);
    let source = splittable_source(&config, 0xA1);
    let handler = ReplenishHandler::new(
        db.pool.clone(),
        keyring,
        MockUtxoSource::new(vec![source]),
        StubSubmitter::new(config.network).expect("stub"),
        config,
    );

    let groomed = handler.run_once_for(wallet_a).await.expect("groom a");
    assert!(
        matches!(groomed, GroomOutcome::Split { minted } if minted == config.min_canonical_count),
        "the targeted pass split exactly wallet A's canonical deficit, got {groomed:?}"
    );

    // Wallet A has minted change rows; wallet B has none (it was not in this pass).
    let a_change: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_utxo WHERE wallet_id = $1 AND source = 'change'",
    )
    .bind(wallet_a)
    .fetch_one(&db.pool)
    .await
    .expect("count a change");
    let b_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cw_core.wallet_utxo WHERE wallet_id = $1")
            .bind(wallet_b)
            .fetch_one(&db.pool)
            .await
            .expect("count b rows");
    assert_eq!(
        a_change,
        i64::from(config.min_canonical_count),
        "the targeted pass minted wallet A's canonical deficit as change"
    );
    assert_eq!(
        b_rows, 0,
        "the sibling wallet B was not touched by a targeted pass for A"
    );
}

/// The exit assertion: a freshly registered, funded wallet becomes selectable for a
/// publish after its targeted replenish runs and confirms, without the periodic cron
/// ever firing. `pick_wallet` is the same selection a publish uses, so a non-None
/// pick proves the wallet is spendable within one worker tick of registration.
#[tokio::test]
async fn registered_wallet_is_pickable_after_targeted_replenish_without_the_cron() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    seed_params(&db.pool).await;
    reconcile(&db.pool, &replenish_policy())
        .await
        .expect("reconcile replenish policy");

    let operator_id = create_operator(&db.pool, "operator")
        .await
        .expect("operator");
    let seed = [0x55; 32];
    let address = derive_enterprise_address(
        &SigningKey::from_seed(seed).verification_key(),
        config.network,
    )
    .expect("address");

    let wallet_id = match register_wallet_and_grant(
        &db.pool,
        operator_id,
        "primary",
        &address,
        config.network,
        GrantScope::Service,
    )
    .await
    .expect("register")
    {
        RegisterAndGrantOutcome::Registered { wallet, .. } => wallet.wallet_id,
        other => panic!("register: {other:?}"),
    };

    // Right after registration the wallet has no canonical UTxOs, so a publish
    // cannot pick it yet: this is the spendability gap the targeted replenish closes.
    assert!(
        pick_wallet(&db.pool, operator_id, config.network)
            .await
            .expect("pick before groom")
            .is_none(),
        "a freshly registered wallet has no canonical UTxOs and is not yet pickable"
    );

    // Run ONLY the targeted replenish the registration queued (the all-wallets cron
    // never fires in this test). The handler serves this wallet's key and source.
    let keyring = unlocked_keyring(seed, &address);
    let source = splittable_source(&config, 0xB2);
    let handler = ReplenishHandler::new(
        db.pool.clone(),
        keyring,
        MockUtxoSource::new(vec![source]),
        StubSubmitter::new(config.network).expect("stub"),
        config,
    );
    let groomed = handler
        .run_once_for(wallet_id)
        .await
        .expect("targeted groom");
    assert!(
        matches!(groomed, GroomOutcome::Split { .. }),
        "the targeted pass split the source, got {groomed:?}"
    );

    // The minted band-mid outputs are pending change until they confirm; confirm
    // the split so they become canonical-available (the state a publish selects).
    let split_tx_hash = read_change_tx_hash(&db.pool, wallet_id).await;
    let confirmed = ConfirmedSpend {
        spend_tx_hash: split_tx_hash,
        inputs: vec![source.utxo],
    };
    utxo::apply_confirmed(&db.pool, wallet_id, &[confirmed], &config)
        .await
        .expect("confirm split");

    // The wallet is now publish-selectable: pick_wallet (the real publish-time
    // selection) returns it, with a positive canonical-ready count. No periodic
    // replenish cron ran; the targeted enqueue alone stocked it.
    let picked = pick_wallet(&db.pool, operator_id, config.network)
        .await
        .expect("pick after groom")
        .expect("the stocked wallet is pickable");
    assert_eq!(
        picked.wallet_id, wallet_id,
        "the stocked wallet is the one a publish selects"
    );
    assert!(
        picked.canonical_ready_count >= i64::from(config.min_canonical_count),
        "the picked wallet carries its canonical minimum: have {}, want {}",
        picked.canonical_ready_count,
        config.min_canonical_count
    );
}
