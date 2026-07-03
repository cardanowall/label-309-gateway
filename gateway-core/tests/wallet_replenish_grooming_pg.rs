//! Integration coverage for keeping a wallet's canonical band groomed.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.
//! After a burst of submits drains a wallet's canonical UTxOs, the replenish job
//! must restock it: it ingests the wallet's on-chain UTxOs, splits a large source
//! output into band-sized canonical outputs, and (once those outputs confirm)
//! lifts the wallet back to its minimum canonical count. This suite drives that
//! end to end against a real Postgres, the real Conway split builder, and a mock
//! UTxO source plus the stub submitter, asserting the canonical count is restored.

#![cfg(feature = "pg-tests")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use age::secrecy::SecretString;
use chrono::Utc;
use gateway_core::chain::confirm::{upsert_tip, ConfirmConfig, ConfirmHandler};
use gateway_core::chain::gateway::{
    BlockInfo, ChainGateway, ChainTip, Label309RecordsResult, TxCborMap, TxConfirmation,
    TxConfirmationMap,
};
use gateway_core::runtime::enqueue::{enqueue, EnqueueOptions};
use gateway_core::runtime::Runtime;
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use gateway_core::wallet::keyring::{derive_enterprise_address, unlock, UnlockedKeyring};
use gateway_core::wallet::operator::{create_operator, register_wallet, RegisterOutcome};
use gateway_core::wallet::pool::lock_wallet;
use gateway_core::wallet::replenish::{
    replenish_policy, replenish_wallet, ReplenishHandler, ReplenishOutcome, REPLENISH_QUEUE,
};
use gateway_core::wallet::submitter::StubSubmitter;
use gateway_core::wallet::utxo::{self, ObservedUtxo, UtxoRef, UtxoSource};
use gateway_core::Result;
use uuid::Uuid;
use zeroize::Zeroizing;

use cardano_poe_tx::{ProtocolParams, SigningKey};

/// A low scrypt work factor so the test keyring encrypt/decrypt is fast.
const TEST_SCRYPT_LOG_N: u8 = 2;

/// Register a wallet and return its id, panicking if the (always-fresh) address
/// is somehow already taken.
async fn register_wallet_id(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    label: &str,
    address: &str,
    network: Network,
) -> Uuid {
    match register_wallet(pool, operator_id, label, address, network)
        .await
        .expect("register wallet")
    {
        RegisterOutcome::Registered(r) => r.wallet_id,
        RegisterOutcome::AddressTaken { .. } => {
            panic!("a fresh wallet address must register, not collide")
        }
    }
}

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
/// The split test points it at a single large pure-ADA source; the stub submitter
/// simulates acceptance so the split lands locally as pending change.
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

/// A chain gateway whose `get_tx_confirmations` answers from a script, so a test can
/// drive a recorded split attempt through the real confirm authority: an unseeded
/// hash answers `not_on_chain`.
#[derive(Default)]
struct ScriptedGateway {
    confirmations: Mutex<HashMap<[u8; 32], TxConfirmation>>,
}

impl ScriptedGateway {
    fn new() -> Self {
        Self::default()
    }

    fn set_confirmation(&self, hash: [u8; 32], confirmation: TxConfirmation) {
        self.confirmations
            .lock()
            .unwrap()
            .insert(hash, confirmation);
    }
}

impl ChainGateway for ScriptedGateway {
    async fn submit_tx(&self, _signed_tx: &[u8]) -> Result<[u8; 32]> {
        Ok([0u8; 32])
    }

    async fn get_tx_confirmations(&self, tx_hashes: &[[u8; 32]]) -> Result<TxConfirmationMap> {
        let script = self.confirmations.lock().unwrap();
        let mut out = TxConfirmationMap::new();
        for hash in tx_hashes {
            out.insert(
                *hash,
                script
                    .get(hash)
                    .copied()
                    .unwrap_or_else(TxConfirmation::not_on_chain),
            );
        }
        Ok(out)
    }

    async fn get_block_info(&self, _block_height: u64) -> Result<Option<BlockInfo>> {
        Ok(None)
    }

    async fn get_tip(&self) -> Result<ChainTip> {
        Ok(ChainTip {
            block_height: 0,
            epoch: None,
        })
    }

    async fn fetch_tx_cbor_by_hashes(&self, _tx_hashes: &[[u8; 32]]) -> Result<TxCborMap> {
        Ok(TxCborMap::new())
    }

    async fn fetch_label309_records_since(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> Result<Label309RecordsResult> {
        Ok(Label309RecordsResult::default())
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> Result<Label309RecordsResult> {
        Ok(Label309RecordsResult::default())
    }
}

/// The split confirmation threshold the test confirm config settles at.
const TEST_CONFIRMATION_THRESHOLD: u64 = 5;

fn confirm_config() -> ConfirmConfig {
    ConfirmConfig {
        confirmation_threshold: TEST_CONFIRMATION_THRESHOLD,
        ..ConfirmConfig::default()
    }
}

/// The tx hash a split attempt recorded under, read back from its `chain_attempt`
/// row (the single non-terminal split attempt for the wallet).
async fn split_attempt_tx_hash(pool: &sqlx::PgPool, wallet_id: Uuid) -> [u8; 32] {
    let raw: Vec<u8> = sqlx::query_scalar(
        "SELECT tx_hash FROM cw_core.chain_attempt \
         WHERE wallet_id = $1 AND kind = 'split' LIMIT 1",
    )
    .bind(wallet_id)
    .fetch_one(pool)
    .await
    .expect("read split attempt tx hash");
    raw.as_slice().try_into().expect("32-byte tx hash")
}

/// The status of the wallet's single split attempt.
async fn split_attempt_status(pool: &sqlx::PgPool, wallet_id: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT status FROM cw_core.chain_attempt WHERE wallet_id = $1 AND kind = 'split' LIMIT 1",
    )
    .bind(wallet_id)
    .fetch_one(pool)
    .await
    .expect("read split attempt status")
}

/// After the band is drained, the replenish job records a `kind='split'` chain
/// attempt before broadcast; once the confirm authority settles that attempt, the
/// minted band-mid outputs are promoted to canonical and the source is
/// `confirmed_spent`, restoring the wallet's canonical minimum. This is the
/// grooming guarantee, and it is the regression that pins the split into the
/// attempt ledger: before the fix a split minted outputs nothing ever confirmed, so
/// the wallet drained to permanently unspendable change.
#[tokio::test]
async fn replenish_split_attempt_is_confirmed_by_the_authority_and_restores_the_minimum() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    seed_params(&db.pool).await;

    // A real wallet with a derived preprod address (the split build needs a
    // network-matching bech32 address).
    let operator_id = create_operator(&db.pool, "operator")
        .await
        .expect("operator");
    let signing_key = SigningKey::from_seed([0x55; 32]);
    let verification_key = signing_key.verification_key();
    let address = derive_enterprise_address(&verification_key, config.network).expect("address");
    let wallet_id =
        register_wallet_id(&db.pool, operator_id, "primary", &address, config.network).await;
    // A WalletSigner for the same key, the form replenish_wallet signs with.
    let signer = gateway_core::wallet::keyring::WalletSigner::new(
        "primary".to_string(),
        address.clone(),
        zeroizing_seed([0x55; 32]),
    )
    .expect("signer");

    // The wallet starts with zero canonical UTxOs (the load drained it) and one
    // large, oversized pure-ADA source the replenisher can split. The source must
    // be above the band so it is not itself groomed.
    let source = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0xA1; 32],
            output_index: 0,
        },
        // Enough for four band-mid (6 ADA) outputs plus fee and change.
        lovelace: config.band.mid * 5 + 50_000_000,
        pure_ada: true,
    };
    let source_url_outputs = MockUtxoSource::new(vec![source]);
    let submitter = StubSubmitter::new(config.network).expect("stub");

    assert_eq!(
        utxo::canonical_ready_count(&db.pool, wallet_id)
            .await
            .expect("count"),
        0,
        "the wallet starts drained of canonical UTxOs"
    );

    // Run the replenish pass: it ingests, plans a split, builds + signs it, records
    // the split as a `kind='split'` attempt BEFORE broadcast, then broadcasts.
    let outcome = replenish_wallet(
        &db.pool,
        wallet_id,
        &signer,
        &source_url_outputs,
        &submitter,
        &config,
    )
    .await
    .expect("replenish");
    let minted = match outcome {
        ReplenishOutcome::Split { minted } => minted,
        other => panic!("expected a split, got {other:?}"),
    };
    assert_eq!(
        minted, config.min_canonical_count,
        "the split mints exactly the canonical deficit"
    );

    // The split is a recorded-then-broadcast `kind='split'` attempt, not a
    // fire-and-forget mint: it is loadable by the confirm authority by its tx hash.
    assert_eq!(
        split_attempt_status(&db.pool, wallet_id).await,
        "broadcast",
        "the accepted split attempt is on the wire and reconcilable"
    );
    let split_tx_hash = split_attempt_tx_hash(&db.pool, wallet_id).await;

    // The minted outputs are pending change: present but not yet canonical (they are
    // unconfirmed), so the canonical count is still zero right after the split.
    assert_eq!(
        utxo::canonical_ready_count(&db.pool, wallet_id)
            .await
            .expect("count"),
        0,
        "freshly minted change is not canonical until the attempt confirms"
    );

    // Drive the real confirm authority over the split attempt. First the gateway
    // reports the split landed at block 100 (the mempool pass repins its
    // coordinates), then a tip past the settlement threshold confirms it via the
    // tip-derived pass. There is NO bespoke split-confirm path: the split rides the
    // exact same authority and the same wallet-promotion call as a publish.
    let gateway = ScriptedGateway::new();
    gateway.set_confirmation(split_tx_hash, TxConfirmation::on_chain(1, 100, Utc::now()));
    upsert_tip(&db.pool, "preprod", 100, None)
        .await
        .expect("tip");
    let handler = ConfirmHandler::new(
        db.pool.clone(),
        gateway,
        "preprod",
        confirm_config(),
        config,
    );
    handler.run_iteration().await.expect("discover the split");
    assert_eq!(
        split_attempt_status(&db.pool, wallet_id).await,
        "broadcast",
        "the mempool pass repins the height but the split is not yet settlement-deep"
    );

    // Tip 105: confirmations = 105 - 100 + 1 = 6 >= threshold 5, so the split
    // confirms.
    upsert_tip(&db.pool, "preprod", 105, None)
        .await
        .expect("tip");
    handler.run_iteration().await.expect("confirm the split");

    assert_eq!(
        split_attempt_status(&db.pool, wallet_id).await,
        "confirmed",
        "the confirm authority terminalises the split attempt"
    );

    // The minted outputs are promoted to canonical and the source is confirmed_spent:
    // the canonical count rose by exactly the minted count and the band is groomed.
    let ready = utxo::canonical_ready_count(&db.pool, wallet_id)
        .await
        .expect("count");
    assert_eq!(
        ready,
        i64::from(minted),
        "confirmation promotes the minted outputs to canonical: have {ready}, minted {minted}"
    );
    assert_eq!(
        state_of(&db.pool, wallet_id, source.utxo).await.as_deref(),
        Some("confirmed_spent"),
        "the split's source input is confirmed_spent after the attempt confirms"
    );

    // Re-running replenish now is a no-op: the wallet is stocked. The second pass
    // re-observes the chain, which after confirmation lists the minted band-mid
    // outputs (and no longer lists the spent source), so ingest leaves the canonical
    // set intact and the stocked check short-circuits before any split.
    let on_chain_minted: Vec<ObservedUtxo> = (0..minted)
        .map(|i| ObservedUtxo {
            utxo: UtxoRef {
                tx_hash: split_tx_hash,
                output_index: i,
            },
            lovelace: config.band.mid,
            pure_ada: true,
        })
        .collect();
    let again = replenish_wallet(
        &db.pool,
        wallet_id,
        &signer,
        &MockUtxoSource::new(on_chain_minted),
        &submitter,
        &config,
    )
    .await
    .expect("second replenish");
    assert!(
        matches!(again, ReplenishOutcome::AlreadyStocked { .. }),
        "a stocked wallet needs no further split, got {again:?}"
    );
}

/// A wallet whose largest splittable source cannot fund a split (it is oversized,
/// so a candidate, but too small once the fee and a minimum-ADA change output are
/// reserved) still replenishes off a smaller source that can. The pass must not
/// commit to the single maximal source and give up; it falls through the candidates
/// in descending order to the first one that actually funds a split. Before the fix
/// the pass picked the single `max_by_key` source and returned `NoFundableSource`,
/// stranding a wallet that had a fundable smaller source.
#[tokio::test]
async fn replenish_falls_through_to_a_smaller_fundable_source() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    seed_params(&db.pool).await;

    let operator_id = create_operator(&db.pool, "operator")
        .await
        .expect("operator");
    let signing_key = SigningKey::from_seed([0x99; 32]);
    let verification_key = signing_key.verification_key();
    let address = derive_enterprise_address(&verification_key, config.network).expect("address");
    let wallet_id =
        register_wallet_id(&db.pool, operator_id, "primary", &address, config.network).await;
    let signer = gateway_core::wallet::keyring::WalletSigner::new(
        "primary".to_string(),
        address.clone(),
        zeroizing_seed([0x99; 32]),
    )
    .expect("signer");

    // The LARGEST candidate is oversized (above the band, so it is a candidate) but
    // only just: once the worst-case fee and a minimum-ADA change output are
    // reserved it cannot fund even one band-mid output, so plan_split declines it.
    // A SMALLER candidate is comfortably large enough to fund the whole deficit.
    // The unfundable source is larger, so descending order tries it first and must
    // fall through to the fundable one.
    let params = params();
    let reserve = cardano_poe_tx::fee::linear_fee(&params, params.max_tx_size)
        + cardano_poe_tx::fee::min_ada_for_output(&params, 80);
    let unfundable_larger = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0xE5; 32],
            output_index: 0,
        },
        // Above the band (a candidate) but below band_mid + reserve, so it funds
        // zero band-mid outputs. Make it the LARGER of the two candidates.
        lovelace: config.band.max + reserve / 2,
        pure_ada: true,
    };
    let fundable_smaller = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0xE6; 32],
            output_index: 0,
        },
        // Comfortably funds all four band-mid outputs plus fee and change, but is
        // SMALLER than the unfundable source above.
        lovelace: config.band.mid * 5 + 50_000_000,
        pure_ada: true,
    };
    assert!(
        unfundable_larger.lovelace > config.band.max,
        "the unfundable source is still an oversized candidate"
    );
    assert!(
        unfundable_larger.lovelace < fundable_smaller.lovelace,
        "the unfundable source is the larger candidate, tried first in descending order"
    );

    let source_outputs = MockUtxoSource::new(vec![unfundable_larger, fundable_smaller]);
    let submitter = StubSubmitter::new(config.network).expect("stub");

    let outcome = replenish_wallet(
        &db.pool,
        wallet_id,
        &signer,
        &source_outputs,
        &submitter,
        &config,
    )
    .await
    .expect("replenish");
    assert!(
        matches!(outcome, ReplenishOutcome::Split { minted } if minted == config.min_canonical_count),
        "the pass falls through the unfundable larger source and splits the smaller fundable one, got {outcome:?}"
    );

    // The split spent the SMALLER fundable source, and the unfundable larger source
    // was never leased (it is still available, untouched).
    assert_eq!(
        state_of(&db.pool, wallet_id, fundable_smaller.utxo)
            .await
            .as_deref(),
        Some("pending_spent"),
        "the fundable smaller source was the one split"
    );
    assert_eq!(
        state_of(&db.pool, wallet_id, unfundable_larger.utxo)
            .await
            .as_deref(),
        Some("available"),
        "the unfundable larger source was never leased, only fallen through"
    );
}

/// A wallet whose every splittable candidate is already leased (held `in_flight`
/// by a concurrent pass) returns `NoFundableSource` only after the loop tries each
/// candidate in turn and `claim_source` declines every one. The pass never
/// double-leases a held source; it falls through the whole ordered set and gives up
/// without minting a partial split, proving `NoFundableSource` is returned only
/// after the set is exhausted.
#[tokio::test]
async fn replenish_exhausts_all_claimed_candidates_before_giving_up() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    seed_params(&db.pool).await;

    let operator_id = create_operator(&db.pool, "operator")
        .await
        .expect("operator");
    let signing_key = SigningKey::from_seed([0xA7; 32]);
    let verification_key = signing_key.verification_key();
    let address = derive_enterprise_address(&verification_key, config.network).expect("address");
    let wallet_id =
        register_wallet_id(&db.pool, operator_id, "primary", &address, config.network).await;
    let signer = gateway_core::wallet::keyring::WalletSigner::new(
        "primary".to_string(),
        address.clone(),
        zeroizing_seed([0xA7; 32]),
    )
    .expect("signer");

    // Two oversized, fundable candidates, but each is pre-leased `in_flight` (a
    // concurrent pass already claimed them). Ingest leaves an in_flight row untouched
    // (ON CONFLICT DO NOTHING), so each stays held when the pass tries to claim it.
    let a = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0xF1; 32],
            output_index: 0,
        },
        lovelace: config.band.mid * 5 + 50_000_000,
        pure_ada: true,
    };
    let b = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0xF2; 32],
            output_index: 0,
        },
        lovelace: config.band.mid * 6 + 50_000_000,
        pure_ada: true,
    };
    for source in [&a, &b] {
        seed_in_flight_source(&db.pool, wallet_id, source.utxo, source.lovelace).await;
    }

    let source_outputs = MockUtxoSource::new(vec![a, b]);
    let submitter = StubSubmitter::new(config.network).expect("stub");

    let outcome = replenish_wallet(
        &db.pool,
        wallet_id,
        &signer,
        &source_outputs,
        &submitter,
        &config,
    )
    .await
    .expect("replenish");
    assert!(
        matches!(outcome, ReplenishOutcome::NoFundableSource),
        "every candidate is already leased, so the whole ordered set is exhausted, got {outcome:?}"
    );
    // No split attempt was recorded and both sources stay held by their original
    // lease: the loop never double-leased a held source.
    let split_attempts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.chain_attempt WHERE wallet_id = $1 AND kind = 'split'",
    )
    .bind(wallet_id)
    .fetch_one(&db.pool)
    .await
    .expect("count split attempts");
    assert_eq!(
        split_attempts, 0,
        "an exhausted pass records no split attempt"
    );
    assert_eq!(
        state_of(&db.pool, wallet_id, a.utxo).await.as_deref(),
        Some("in_flight"),
        "the first held source stays in_flight, never re-leased"
    );
    assert_eq!(
        state_of(&db.pool, wallet_id, b.utxo).await.as_deref(),
        Some("in_flight"),
        "the second held source stays in_flight, never re-leased"
    );
}

/// Insert a source UTxO already leased `in_flight` by a concurrent pass, with a
/// fresh lease token and a far-future expiry so the reaper never reopens it during
/// the test.
async fn seed_in_flight_source(pool: &sqlx::PgPool, wallet_id: Uuid, utxo: UtxoRef, lovelace: u64) {
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source, \
            lease_token, lease_expires_at) \
         VALUES ($1, $2, $3, $4, 'in_flight', false, 'snapshot', $5, now() + interval '1 hour')",
    )
    .bind(wallet_id)
    .bind(utxo.tx_hash.as_slice())
    .bind(utxo.output_index as i32)
    .bind(lovelace as i64)
    .bind(Uuid::now_v7())
    .execute(pool)
    .await
    .expect("seed in_flight source");
}

/// Wrap a 32-byte seed in the zeroizing buffer `WalletSigner::new` expects.
fn zeroizing_seed(seed: [u8; 32]) -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(seed.to_vec())
}

/// Build an unlocked keyring holding the signer for `seed` on preprod, by
/// encrypting a one-entry keyring envelope and unlocking it. This is the form the
/// replenish handler resolves a wallet's signer from.
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

/// Count the wallet's rows in a given source category and state.
async fn count_rows(pool: &sqlx::PgPool, wallet_id: Uuid, source: &str, state: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND source = $2 AND state = $3",
    )
    .bind(wallet_id)
    .bind(source)
    .bind(state)
    .fetch_one(pool)
    .await
    .expect("count rows")
}

/// The state of a specific UTxO row, or `None` when it is not tracked.
async fn state_of(pool: &sqlx::PgPool, wallet_id: Uuid, utxo: UtxoRef) -> Option<String> {
    sqlx::query_scalar(
        "SELECT state FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3",
    )
    .bind(wallet_id)
    .bind(utxo.tx_hash.as_slice())
    .bind(utxo.output_index as i32)
    .fetch_optional(pool)
    .await
    .expect("read state")
}

/// Poll until `pred` returns true or panic after `timeout`.
async fn wait_for<F, Fut>(timeout: Duration, mut pred: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if pred().await {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("condition not met within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The replenish handler must groom a drained wallet when driven THROUGH the
/// runtime, not just by a direct call: registered against its queue with its
/// policy, an enqueued job runs the handler, which lists the active wallet,
/// resolves its signer, and splits the source. This proves production wiring grooms
/// wallets (the gap S-2 flagged: a queue policy with no handler/schedule never
/// runs). Asserts on the DB end-state the handler produced (source spent, minted
/// change rows present), not on a return value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replenish_handler_runs_through_the_runtime_and_grooms_a_wallet() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    // The runtime keeps a NOTIFY listener, sweeper, scheduler, and per-wallet
    // advisory lock in flight, so it needs more than the default connection cap.
    let pool = db.pool_with(12).await.expect("sized pool");
    seed_params(&pool).await;

    let seed = [0x66; 32];
    let signing_key = SigningKey::from_seed(seed);
    let verification_key = signing_key.verification_key();
    let address = derive_enterprise_address(&verification_key, config.network).expect("address");
    let operator_id = create_operator(&pool, "operator").await.expect("operator");
    let wallet_id =
        register_wallet_id(&pool, operator_id, "primary", &address, config.network).await;

    // One large oversized source the chain shows; the wallet is drained of
    // canonical UTxOs, so the handler must split the source.
    let source = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0xB2; 32],
            output_index: 0,
        },
        lovelace: config.band.mid * 5 + 50_000_000,
        pure_ada: true,
    };
    let utxo_source = MockUtxoSource::new(vec![source]);
    let submitter = StubSubmitter::new(config.network).expect("stub");
    let keyring = unlocked_keyring(seed, &address);

    let handler = ReplenishHandler::new(pool.clone(), keyring, utxo_source, submitter, config);

    let rt = Arc::new(
        Runtime::builder(pool.clone())
            .worker_id("replenish-smoke")
            .queue_policy(replenish_policy())
            .handler(REPLENISH_QUEUE, handler)
            .poll_interval(Duration::from_millis(25))
            .build()
            .await
            .expect("build runtime"),
    );

    // Enqueue one replenish job; the running worker loop claims and runs the
    // handler (the same path the schedule would drive).
    enqueue(
        &pool,
        REPLENISH_QUEUE,
        &serde_json::Value::Null,
        EnqueueOptions::default(),
    )
    .await
    .expect("enqueue replenish job");

    let run = {
        let rt = rt.clone();
        tokio::spawn(async move { rt.run().await })
    };

    // The handler grooms the wallet: the source ends `pending_spent` and the minted
    // band-mid change rows appear. Poll on that DB end-state.
    {
        let pool = pool.clone();
        wait_for(Duration::from_secs(20), move || {
            let pool = pool.clone();
            async move {
                state_of(&pool, wallet_id, source.utxo).await.as_deref() == Some("pending_spent")
                    && count_rows(&pool, wallet_id, "change", "available").await
                        == i64::from(config.min_canonical_count)
            }
        })
        .await;
    }

    rt.shutdown();
    let _ = run.await;

    // Final assertions on the durable end-state the handler produced.
    assert_eq!(
        state_of(&pool, wallet_id, source.utxo).await.as_deref(),
        Some("pending_spent"),
        "the runtime-driven handler spent the source"
    );
    assert_eq!(
        count_rows(&pool, wallet_id, "change", "available").await,
        i64::from(config.min_canonical_count),
        "the runtime-driven handler minted the canonical deficit as change rows"
    );
}

/// Two replenish passes racing on the same wallet must not double-spend the
/// source: the per-wallet advisory lock plus leasing the source through the state
/// machine means exactly one pass splits and the source is spent at most once. This
/// is the concurrency guarantee S-3 flagged (the old path selected and submitted a
/// source with no lease/fence and no wallet lock).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_replenish_never_double_spends_the_source() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    let pool = db.pool_with(8).await.expect("sized pool");
    seed_params(&pool).await;

    let seed = [0x77; 32];
    let signing_key = SigningKey::from_seed(seed);
    let verification_key = signing_key.verification_key();
    let address = derive_enterprise_address(&verification_key, config.network).expect("address");
    let operator_id = create_operator(&pool, "operator").await.expect("operator");
    let wallet_id =
        register_wallet_id(&pool, operator_id, "primary", &address, config.network).await;

    let source = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0xC3; 32],
            output_index: 0,
        },
        lovelace: config.band.mid * 5 + 50_000_000,
        pure_ada: true,
    };

    // Two passes started at once over the same source. The advisory lock serialises
    // them: one wins and splits; the other finds the wallet busy or the source
    // already leased and does not build a second time. Each task owns its signer,
    // source, submitter, and config copy so they share nothing but the wallet row.
    let address = Arc::new(address);
    let pass = |pool: sqlx::PgPool| {
        let address = address.clone();
        async move {
            let signer = gateway_core::wallet::keyring::WalletSigner::new(
                "primary".to_string(),
                (*address).clone(),
                zeroizing_seed(seed),
            )
            .expect("signer");
            let source_outputs = MockUtxoSource::new(vec![source]);
            let submitter = StubSubmitter::new(config.network).expect("stub");
            replenish_wallet(
                &pool,
                wallet_id,
                &signer,
                &source_outputs,
                &submitter,
                &config,
            )
            .await
        }
    };

    let a = tokio::spawn(pass(pool.clone()));
    let b = tokio::spawn(pass(pool.clone()));
    let (ra, rb) = (a.await.expect("join a"), b.await.expect("join b"));
    let ra = ra.expect("pass a result");
    let rb = rb.expect("pass b result");

    // Exactly one pass split; the other yielded without building (busy/no-source).
    let splits = [&ra, &rb]
        .iter()
        .filter(|o| matches!(o, ReplenishOutcome::Split { .. }))
        .count();
    assert_eq!(
        splits, 1,
        "exactly one of two racing replenish passes splits the source, got {ra:?} and {rb:?}"
    );

    // The source is spent at most once: exactly one `pending_spent` row for it, and
    // exactly one canonical deficit's worth of minted change (no second split's
    // outputs).
    assert_eq!(
        state_of(&pool, wallet_id, source.utxo).await.as_deref(),
        Some("pending_spent"),
        "the source is spent exactly once"
    );
    assert_eq!(
        count_rows(&pool, wallet_id, "change", "available").await,
        i64::from(config.min_canonical_count),
        "only one split's worth of minted change exists; the source was not double-spent"
    );
}

/// A replenish pass whose wallet lock is already held (a live submit or another
/// replenish) yields `WalletBusy` without touching the wallet's UTxOs, instead of
/// building against an unleased source. Pins the lock-serialisation S-3 requires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replenish_yields_when_the_wallet_lock_is_held() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    seed_params(&db.pool).await;

    let seed = [0x88; 32];
    let signing_key = SigningKey::from_seed(seed);
    let verification_key = signing_key.verification_key();
    let address = derive_enterprise_address(&verification_key, config.network).expect("address");
    let operator_id = create_operator(&db.pool, "operator")
        .await
        .expect("operator");
    let wallet_id =
        register_wallet_id(&db.pool, operator_id, "primary", &address, config.network).await;
    let signer = gateway_core::wallet::keyring::WalletSigner::new(
        "primary".to_string(),
        address.clone(),
        zeroizing_seed(seed),
    )
    .expect("signer");

    let source = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0xD4; 32],
            output_index: 0,
        },
        lovelace: config.band.mid * 5 + 50_000_000,
        pure_ada: true,
    };
    let source_outputs = MockUtxoSource::new(vec![source]);
    let submitter = StubSubmitter::new(config.network).expect("stub");

    // A live submit holds the wallet's advisory lock.
    let held = lock_wallet(&db.pool, wallet_id)
        .await
        .expect("hold the wallet lock");

    let outcome = replenish_wallet(
        &db.pool,
        wallet_id,
        &signer,
        &source_outputs,
        &submitter,
        &config,
    )
    .await
    .expect("replenish");
    assert!(
        matches!(outcome, ReplenishOutcome::WalletBusy),
        "a replenish on a locked wallet yields busy, got {outcome:?}"
    );
    // Nothing was built: the source was never even ingested/leased.
    assert!(
        state_of(&db.pool, wallet_id, source.utxo).await.is_none(),
        "a busy pass touches no UTxO state"
    );

    held.release().await.expect("release the wallet lock");
}

/// Seed a canonical, `available` wallet_utxo row directly (a snapshot-sourced
/// UTxO that the idle gate counts), so a test can construct a stale-high local
/// view independent of the chain.
async fn seed_canonical_available(
    pool: &sqlx::PgPool,
    wallet_id: Uuid,
    utxo: UtxoRef,
    lovelace: u64,
) {
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, $3, $4, 'available', true, 'snapshot')",
    )
    .bind(wallet_id)
    .bind(utxo.tx_hash.as_slice())
    .bind(utxo.output_index as i32)
    .bind(lovelace as i64)
    .execute(pool)
    .await
    .expect("seed canonical available utxo");
}

/// Make the wallet's local view look FRESH (`now()`) to the idle gate.
async fn mark_fresh(pool: &sqlx::PgPool, wallet_id: Uuid) {
    sqlx::query("UPDATE cw_core.operator_wallet SET last_ingest_at = now() WHERE id = $1")
        .bind(wallet_id)
        .execute(pool)
        .await
        .expect("mark wallet view fresh");
}

/// Make the wallet's local view look STALE (never ingested) to the idle gate.
async fn mark_never_ingested(pool: &sqlx::PgPool, wallet_id: Uuid) {
    sqlx::query("UPDATE cw_core.operator_wallet SET last_ingest_at = NULL WHERE id = $1")
        .bind(wallet_id)
        .execute(pool)
        .await
        .expect("mark wallet view never-ingested");
}

/// The idle gate must NOT trust a high canonical count when the local view is
/// STALE. A canonical `available` row spent out of band (a shared keyring across
/// replicas, or a manual operator spend) stays counted locally even though it
/// vanished on chain, so a genuinely-understocked wallet can read at/above its
/// minimum. With a stale `last_ingest_at` the gate falls through to a fresh
/// snapshot, the vanished-output reconciliation drops the row to `confirmed_spent`,
/// the real deficit surfaces, and the wallet grooms (splits) instead of being
/// wrongly skipped as AlreadyStocked. This pins the idle-gate-must-not-skip-a-
/// needed-groom invariant.
#[tokio::test]
async fn stale_canonical_view_does_not_skip_a_needed_groom() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    seed_params(&db.pool).await;

    let seed = [0x73; 32];
    let signing_key = SigningKey::from_seed(seed);
    let verification_key = signing_key.verification_key();
    let address = derive_enterprise_address(&verification_key, config.network).expect("address");
    let operator_id = create_operator(&db.pool, "operator")
        .await
        .expect("operator");
    let wallet_id =
        register_wallet_id(&db.pool, operator_id, "primary", &address, config.network).await;
    let signer = gateway_core::wallet::keyring::WalletSigner::new(
        "primary".to_string(),
        address.clone(),
        zeroizing_seed(seed),
    )
    .expect("signer");
    let submitter = StubSubmitter::new(config.network).expect("stub");

    // Seed the wallet's local view as STOCKED: four canonical, available band-mid
    // UTxOs, exactly the minimum. These were spent out of band (another replica /
    // a manual spend), so the chain no longer lists them.
    let ghost_utxos: Vec<UtxoRef> = (0..4)
        .map(|i| UtxoRef {
            tx_hash: [0xE0 + i as u8; 32],
            output_index: 0,
        })
        .collect();
    for ghost in &ghost_utxos {
        seed_canonical_available(&db.pool, wallet_id, *ghost, config.band.mid).await;
    }
    // The local count reads at the minimum, so the cached-count idle gate alone
    // would conclude "stocked".
    assert_eq!(
        utxo::canonical_ready_count(&db.pool, wallet_id)
            .await
            .expect("count"),
        4,
        "the stale local view reads at the canonical minimum"
    );

    // Mark the local view never-ingested (stale): the wallet has not been
    // reconciled against the chain, so its high count is untrustworthy.
    mark_never_ingested(&db.pool, wallet_id).await;

    // The chain snapshot the gate will fetch on fall-through: the four canonical
    // UTxOs are GONE (spent out of band) and only a large splittable source remains.
    let source = ObservedUtxo {
        utxo: UtxoRef {
            tx_hash: [0xC9; 32],
            output_index: 0,
        },
        lovelace: config.band.mid * 5 + 50_000_000,
        pure_ada: true,
    };
    let chain = MockUtxoSource::new(vec![source]);

    let outcome = replenish_wallet(&db.pool, wallet_id, &signer, &chain, &submitter, &config)
        .await
        .expect("replenish");

    // The needed groom was NOT skipped: the pass fell through the stale gate,
    // reconciled the vanished rows, found the real deficit, and split.
    assert!(
        matches!(outcome, ReplenishOutcome::Split { .. }),
        "a stale-high but genuinely-understocked wallet grooms, got {outcome:?}"
    );
    // The vanished ghost UTxOs were reconciled down to confirmed_spent by the ingest
    // the gate no longer skipped.
    for ghost in &ghost_utxos {
        assert_eq!(
            state_of(&db.pool, wallet_id, *ghost).await.as_deref(),
            Some("confirmed_spent"),
            "an out-of-band-spent canonical row is reconciled away on the forced ingest"
        );
    }
}

/// The complement: the idle efficiency win is preserved. A wallet that is stocked
/// AND freshly ingested short-circuits to AlreadyStocked WITHOUT a chain fetch, so
/// a genuinely-idle stocked wallet does not pay an /address_utxos call every tick.
#[tokio::test]
async fn fresh_stocked_wallet_short_circuits_without_a_chain_fetch() {
    let config = config(4);
    let db = TestDb::fresh().await.expect("test database");
    seed_params(&db.pool).await;

    let seed = [0x74; 32];
    let signing_key = SigningKey::from_seed(seed);
    let verification_key = signing_key.verification_key();
    let address = derive_enterprise_address(&verification_key, config.network).expect("address");
    let operator_id = create_operator(&db.pool, "operator")
        .await
        .expect("operator");
    let wallet_id =
        register_wallet_id(&db.pool, operator_id, "primary", &address, config.network).await;
    let signer = gateway_core::wallet::keyring::WalletSigner::new(
        "primary".to_string(),
        address.clone(),
        zeroizing_seed(seed),
    )
    .expect("signer");
    let submitter = StubSubmitter::new(config.network).expect("stub");

    // Four canonical available UTxOs (stocked), and a FRESH last_ingest_at.
    for i in 0..4u8 {
        seed_canonical_available(
            &db.pool,
            wallet_id,
            UtxoRef {
                tx_hash: [0xF0 + i; 32],
                output_index: 0,
            },
            config.band.mid,
        )
        .await;
    }
    mark_fresh(&db.pool, wallet_id).await;

    // A UTxO source that PANICS if consulted: a fresh stocked wallet must decide
    // from the cached count alone and never reach the chain.
    struct PanicSource;
    impl UtxoSource for PanicSource {
        async fn address_utxos(&self, _address: &str) -> Result<Vec<ObservedUtxo>> {
            panic!("a fresh stocked wallet must not fetch the chain");
        }
    }

    let outcome = replenish_wallet(
        &db.pool,
        wallet_id,
        &signer,
        &PanicSource,
        &submitter,
        &config,
    )
    .await
    .expect("replenish");
    assert!(
        matches!(
            outcome,
            ReplenishOutcome::AlreadyStocked { canonical_count: 4 }
        ),
        "a fresh, stocked wallet short-circuits without a chain fetch, got {outcome:?}"
    );
}
