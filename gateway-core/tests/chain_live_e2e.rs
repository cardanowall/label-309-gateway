//! The live end-to-end publish round-trip on Cardano preprod.
//!
//! This is the one test that submits a real transaction to a real network and
//! spends real (test) ADA. It is doubly gated and skips (passing trivially)
//! unless BOTH are set, so CI, the default `cargo test`, and the `pg-tests`
//! suite never touch the network or move funds:
//!
//! - `GATEWAY_LIVE_TESTS=1` enables the live network path.
//! - `GATEWAY_OPERATOR_KEYRING_PATH` and `GATEWAY_OPERATOR_KEYRING_PASSPHRASE_PATH`
//!   point at the age-encrypted operator keyring and its passphrase file.
//!
//! It also needs a Postgres (the harness mints an isolated database). Run it
//! deliberately, for example:
//!
//! ```text
//! GATEWAY_LIVE_TESTS=1 \
//!   GATEWAY_OPERATOR_KEYRING_PATH=/path/operator-keyring.age \
//!   GATEWAY_OPERATOR_KEYRING_PASSPHRASE_PATH=/path/operator-keyring-passphrase \
//!   cargo test -p gateway-core --features pg-tests --test chain_live_e2e -- --nocapture
//! ```
//!
//! The flow exercises every layer of the publish pipeline against the live chain:
//!
//! 1. Decrypt the operator keyring and resolve its preprod wallet.
//! 2. Populate the live protocol parameters from preprod Koios.
//! 3. Ingest the wallet's live UTxOs into the durable wallet state.
//! 4. Enqueue and run the real submit handler: claim a UTxO, build and sign a
//!    minimal Label 309 record, submit to live Koios.
//! 5. Run the confirm loop until the record flips to `confirmed` with a low
//!    threshold, refreshing the materialised tip from live Koios.
//!
//! It then asserts the determinism contract: the quoted canonical fee equals the
//! built fee equals the on-chain fee EXACTLY; the index job created exactly one
//! `chain_records` row with the right columns; and the subject-event stream shows
//! `submitted` then `confirmed` in order. Key material is never printed.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;
use std::time::Duration;

use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};
use gateway_core::chain::confirm::{upsert_tip, ConfirmConfig, ConfirmHandler};
use gateway_core::chain::gateway::{ChainGateway, KoiosGateway};
use gateway_core::chain::params::{
    KoiosParamsSource, Network as ParamsNetwork, ParamsPopulateHandler,
};
use gateway_core::chain::records::{IndexTxHandler, IndexTxJob, MetadataSource, INDEX_TX_QUEUE};
use gateway_core::chain::submit::{submit_policy, SubmitHandler, SubmitJob, SubmitOutcome};
use gateway_core::runtime::policy::reconcile;
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use gateway_core::wallet::keyring::{unlock, UnlockedKeyring};
use gateway_core::wallet::utxo::{ingest_snapshot, KoiosUtxoSource, UtxoSource};
use sqlx::Row;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The preprod confirmation threshold for the live run: a low value so the test
/// settles in a few blocks rather than the production fifteen.
const LIVE_CONFIRMATION_THRESHOLD: u64 = 2;

/// How long to wait for the submitted transaction to confirm before giving up.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(600);

/// How long to wait between confirm-loop iterations (about one preprod block).
const CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(20);

/// The lovelace band the canonical-UTxO predicate uses for the live wallet. The
/// band is deliberately NARROW (the documented 4-8 ADA canonical band): every
/// value in it minus a fee shares one CBOR integer width, so a one-input
/// transaction over ANY canonical UTxO charges byte-for-byte the same fee. That
/// is the precondition the canonical-fee exactness relies on; a wide band that
/// admitted, say, a multi-billion-lovelace output would break it, because the
/// wider change output would cost more bytes than the band-mid the quote prices.
/// The live preprod wallet is funded with 6 ADA pure-ADA outputs, which sit at
/// the band midpoint.
fn live_band() -> LovelaceBand {
    LovelaceBand {
        min: 4_000_000,
        max: 8_000_000,
        mid: 6_000_000,
    }
}

fn live_config() -> WalletConfig {
    WalletConfig {
        network: Network::Preprod,
        band: live_band(),
        lease: Duration::from_secs(120),
        min_canonical_count: 1,
    }
}

/// Read the two gating environment variables, returning the keyring ciphertext
/// and passphrase, or `None` to skip the test.
fn live_keyring() -> Option<(Vec<u8>, Zeroizing<String>)> {
    if std::env::var("GATEWAY_LIVE_TESTS").as_deref() != Ok("1") {
        eprintln!("skipping live preprod e2e: set GATEWAY_LIVE_TESTS=1 to enable");
        return None;
    }
    let keyring_path = std::env::var("GATEWAY_OPERATOR_KEYRING_PATH").ok()?;
    let passphrase_path = std::env::var("GATEWAY_OPERATOR_KEYRING_PASSPHRASE_PATH").ok()?;
    let ciphertext = std::fs::read(&keyring_path).expect("read operator keyring");
    let passphrase = Zeroizing::new(
        std::fs::read_to_string(&passphrase_path)
            .expect("read keyring passphrase")
            .trim_end()
            .to_string(),
    );
    Some((ciphertext, passphrase))
}

/// A minimal valid Label 309 record carrying one open content item, with a unique
/// hash per run so each live submit publishes a distinct record.
fn minimal_record_bytes(nonce: [u8; 32]) -> Vec<u8> {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), nonce.to_vec())],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    encode_poe_record(&record).expect("encode minimal record")
}

/// Seed the operator and the keyring's preprod wallet (its real address) so the
/// submit pipeline binds to a wallet whose key the keyring holds.
async fn seed_operator_and_keyring_wallet(pool: &sqlx::PgPool, address: &str) -> (Uuid, Uuid) {
    let operator_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'live-op')")
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert operator");
    let wallet_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet (id, registrar_operator_id, label, address, network, status) \
         VALUES ($1, $2, 'live', $3, 'preprod', 'active')",
    )
    .bind(wallet_id)
    .bind(operator_id)
    .bind(address)
    .execute(pool)
    .await
    .expect("insert wallet");
    (operator_id, wallet_id)
}

/// Read the on-chain fee a confirmed transaction paid, via live Koios.
async fn onchain_fee(gateway: &KoiosGateway, tx_hash: [u8; 32]) -> Option<u64> {
    // The confirmation lookup returns block coordinates; the fee comes from the
    // raw transaction body, which the gateway can fetch by hash.
    let cbor_map = gateway
        .fetch_tx_cbor_by_hashes(&[tx_hash])
        .await
        .expect("fetch tx cbor");
    let cbor = cbor_map.get(&tx_hash)?;
    fee_from_tx_cbor(cbor)
}

/// Decode a Conway transaction's fee field from its CBOR. The fee is map key 2 of
/// the transaction body (the first element of the top-level transaction array).
fn fee_from_tx_cbor(cbor: &[u8]) -> Option<u64> {
    use pallas_primitives::conway::Tx as ConwayTx;
    use pallas_primitives::Fragment;
    let tx = ConwayTx::decode_fragment(cbor).ok()?;
    Some(tx.transaction_body.fee)
}

#[tokio::test]
async fn live_preprod_publish_round_trip() {
    let Some((ciphertext, passphrase)) = live_keyring() else {
        return;
    };

    // --- Decrypt the operator keyring and resolve the preprod wallet. ---
    let keyring: UnlockedKeyring =
        unlock(&ciphertext, passphrase, Network::Preprod).expect("unlock operator keyring");
    let wallets = keyring.wallets();
    let wallet = wallets
        .first()
        .expect("the operator keyring holds at least one preprod wallet");
    let address = wallet.address.clone();
    eprintln!("live preprod wallet address: {address}");
    let keyring = Arc::new(keyring);

    let db = TestDb::fresh().await.expect("test database");
    for policy in [
        submit_policy(),
        gateway_core::chain::confirm::confirm_policy(),
        gateway_core::chain::records::index_tx_policy(),
    ] {
        reconcile(&db.pool, &policy)
            .await
            .expect("reconcile policy");
    }
    let (operator_id, wallet_id) = seed_operator_and_keyring_wallet(&db.pool, &address).await;

    // --- Populate the LIVE protocol parameters from preprod Koios. ---
    let params_handler = ParamsPopulateHandler::new(
        db.pool.clone(),
        KoiosParamsSource::new(Default::default()).expect("build params source"),
        vec![ParamsNetwork::Preprod],
    );
    let outcomes = params_handler.run_once().await;
    for (network, result) in &outcomes {
        result
            .as_ref()
            .unwrap_or_else(|e| panic!("populate live params for {network:?}: {e}"));
    }

    // --- Ingest the wallet's LIVE UTxOs into the durable wallet state. ---
    let utxo_source = KoiosUtxoSource::new(ParamsNetwork::Preprod.koios_base_url(), None)
        .expect("build utxo source");
    let observed = utxo_source
        .address_utxos(&address)
        .await
        .expect("fetch live utxos");
    assert!(
        !observed.is_empty(),
        "the live preprod wallet {address} has no UTxOs; fund it before running the live e2e"
    );
    let config = live_config();
    ingest_snapshot(&db.pool, wallet_id, &observed, &config)
        .await
        .expect("ingest live utxos");
    let canonical: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.wallet_utxo \
         WHERE wallet_id = $1 AND state = 'available' AND canonical = true",
    )
    .bind(wallet_id)
    .fetch_one(&db.pool)
    .await
    .expect("count canonical");
    assert!(
        canonical >= 1,
        "the live wallet has no canonical UTxO in the band {:?}; fund it with a pure-ADA output",
        config.band
    );

    // --- Submit: enqueue and run the REAL submit handler against live Koios. ---
    let nonce = *uuid::Uuid::now_v7().as_bytes();
    let mut nonce32 = [0u8; 32];
    nonce32[..16].copy_from_slice(&nonce);
    let record_bytes = minimal_record_bytes(nonce32);
    let record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, record_bytes, status, wallet_id, request_id) \
         VALUES ($1, $2, $3, 'submitting', $4, $5)",
    )
    .bind(record_id)
    .bind(operator_id)
    .bind(&record_bytes)
    .bind(wallet_id)
    .bind("live-req-1")
    .execute(&db.pool)
    .await
    .expect("insert poe_record");

    let submit_gateway =
        KoiosGateway::new(ParamsNetwork::Preprod, Default::default()).expect("submit gateway");
    let submit_handler =
        SubmitHandler::new(db.pool.clone(), submit_gateway, config, keyring.clone());
    let job = SubmitJob {
        request_id: "live-req-1".to_string(),
        record_id,
        replacement_for: None,
        forced_inputs: Vec::new(),
    };
    let outcome = submit_handler
        .submit_once(&job, 1)
        .await
        .expect("live submit");
    let SubmitOutcome::Submitted {
        tx_hash,
        fee_lovelace,
        ..
    } = outcome
    else {
        panic!("the live submit did not land: {outcome:?}");
    };
    let built_fee = fee_lovelace.expect("a landed submit records its built fee");
    eprintln!(
        "live submit accepted: tx_hash={} built_fee={built_fee}",
        hex::encode(tx_hash)
    );

    // The quoted canonical fee (the fee for a one-input canonical transaction over
    // these protocol params) must equal the fee the builder actually charged. The
    // canonical fee is address-shape invariant, so the wallet's own address and
    // verification key supply the synthetic build.
    let stored = gateway_core::chain::params::load_params(&db.pool, ParamsNetwork::Preprod)
        .await
        .expect("load stored params");
    let authorized = gateway_core::wallet::grant::AuthorizedWallet::for_tests(
        uuid::Uuid::now_v7(),
        address.clone(),
    );
    let verification_key = keyring
        .signer_for(&authorized)
        .expect("the keyring holds a signer for the wallet")
        .verification_key();
    let quote = gateway_core::wallet::quote::quote_fee(
        record_bytes.len(),
        &cardano_poe_tx::ProtocolParams {
            min_fee_a: stored.min_fee_a,
            min_fee_b: stored.min_fee_b,
            coins_per_utxo_byte: stored.coins_per_utxo_byte,
            max_tx_size: stored.max_tx_size,
        },
        &address,
        verification_key,
        &live_config(),
    )
    .expect("quote canonical fee");
    let quoted_fee = quote.fee;
    assert_eq!(
        quoted_fee, built_fee,
        "the quoted canonical fee must equal the built fee exactly"
    );

    // --- Confirm: run the loop until the record flips to confirmed. ---
    let confirm_gateway =
        KoiosGateway::new(ParamsNetwork::Preprod, Default::default()).expect("confirm gateway");
    let confirm_config = ConfirmConfig {
        confirmation_threshold: LIVE_CONFIRMATION_THRESHOLD,
        ..ConfirmConfig::default()
    };
    let confirm_handler = ConfirmHandler::new(
        db.pool.clone(),
        confirm_gateway,
        Network::Preprod.as_str(),
        confirm_config,
        live_config(),
    );

    let deadline = std::time::Instant::now() + CONFIRM_TIMEOUT;
    let mut confirmed = false;
    while std::time::Instant::now() < deadline {
        // Refresh the materialised tip from live Koios (the indexer's job in prod).
        let tip_gateway =
            KoiosGateway::new(ParamsNetwork::Preprod, Default::default()).expect("tip gateway");
        let tip = tip_gateway.get_tip().await.expect("live tip");
        upsert_tip(
            &db.pool,
            Network::Preprod.as_str(),
            tip.block_height,
            tip.epoch,
        )
        .await
        .expect("upsert tip");

        let summary = confirm_handler
            .run_iteration()
            .await
            .expect("confirm iteration");
        eprintln!(
            "confirm iteration: tip={} confirmed={} progress={} mempool={}",
            tip.block_height, summary.confirmed, summary.progress, summary.mempool
        );

        let status: String =
            sqlx::query_scalar("SELECT status FROM cw_core.poe_record WHERE id = $1")
                .bind(record_id)
                .fetch_one(&db.pool)
                .await
                .expect("read status");
        if status == "confirmed" {
            confirmed = true;
            break;
        }
        assert_ne!(
            status, "permanent_failure",
            "the live record reached a terminal failure instead of confirming"
        );
        tokio::time::sleep(CONFIRM_POLL_INTERVAL).await;
    }
    assert!(
        confirmed,
        "the live record did not confirm within {CONFIRM_TIMEOUT:?}"
    );

    // --- Determinism contract: fee exactness against the on-chain transaction. ---
    let onchain_gateway =
        KoiosGateway::new(ParamsNetwork::Preprod, Default::default()).expect("onchain gateway");
    let onchain_fee = onchain_fee(&onchain_gateway, tx_hash)
        .await
        .expect("read the on-chain fee");
    assert_eq!(
        onchain_fee, built_fee,
        "the on-chain fee must equal the built fee exactly"
    );
    assert_eq!(
        onchain_fee, quoted_fee,
        "the on-chain fee must equal the quoted canonical fee exactly"
    );

    // The block coordinates the confirm flip pinned.
    let block_height: i64 =
        sqlx::query_scalar("SELECT block_height FROM cw_core.poe_record WHERE id = $1")
            .bind(record_id)
            .fetch_one(&db.pool)
            .await
            .expect("read block height");
    eprintln!(
        "DETERMINISM OK: tx_hash={} fee={built_fee} (quoted==built==onchain) block={block_height}",
        hex::encode(tx_hash)
    );

    // --- The index job: run the single chain_records writer it enqueued. ---
    let index_payload: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM cw_core.job WHERE queue = $1")
            .bind(INDEX_TX_QUEUE)
            .fetch_one(&db.pool)
            .await
            .expect("the confirm flip enqueued exactly one index job");
    let index_job: IndexTxJob =
        serde_json::from_value(index_payload).expect("decode index job payload");
    assert_eq!(index_job.tx_hash, hex::encode(tx_hash));
    assert!(
        matches!(index_job.metadata, MetadataSource::Inline { .. }),
        "the own-submission index job carries the metadata inline"
    );

    let index_handler = IndexTxHandler::new(
        db.pool.clone(),
        KoiosGateway::new(ParamsNetwork::Preprod, Default::default()).unwrap(),
        ParamsNetwork::Preprod,
    );
    let inserted = index_handler
        .index_once(&index_job)
        .await
        .expect("index the confirmed transaction");
    assert!(
        inserted,
        "the index job inserts exactly one chain_records row"
    );

    let row = sqlx::query(
        "SELECT block_height, item_count, scheme FROM cw_core.chain_records WHERE tx_hash = $1",
    )
    .bind(tx_hash.as_slice())
    .fetch_one(&db.pool)
    .await
    .expect("the chain_records row exists");
    assert_eq!(
        row.get::<i64, _>("block_height"),
        block_height,
        "the indexed block height matches the confirmed coordinates"
    );
    assert_eq!(
        row.get::<i32, _>("item_count"),
        1,
        "the minimal record has one content item"
    );
    assert_eq!(
        row.get::<i16, _>("scheme"),
        0,
        "the open record indexes as scheme 0"
    );

    // --- The subject-event stream shows submitted -> confirmed in order. ---
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM cw_core.subject_event \
         WHERE subject_kind = 'poe_record' AND subject_id = $1 ORDER BY subject_seq",
    )
    .bind(record_id.to_string())
    .fetch_all(&db.pool)
    .await
    .expect("read event stream");
    let submitted_at = events.iter().position(|e| e == "submitted");
    let confirmed_at = events.iter().position(|e| e == "confirmed");
    assert!(
        matches!((submitted_at, confirmed_at), (Some(s), Some(c)) if s < c),
        "the event stream must show submitted before confirmed, got {events:?}"
    );
}
