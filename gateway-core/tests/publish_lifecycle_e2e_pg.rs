//! End-to-end coverage of the full billed publish lifecycle on the engine.
//!
//! This suite stitches every money and chain primitive into the single journey a
//! tenant publish travels, proving the slices compose rather than only working in
//! isolation: provision a tenant account, register a vendor credit kind, credit
//! the balance through that kind, price a publish (quote through a pricing hook),
//! consume the quote inside one transaction (the signed-negative publish debit,
//! bound to the record), submit the record through the real submission pipeline
//! against a test chain gateway, and settle it through the real confirmation loop.
//!
//! The assertions are the end-state of the whole journey, never log strings: the
//! materialised balance reflects exactly the credit minus the publish debit; the
//! ledger holds exactly one credit and one debit, the debit signed-negative,
//! keyed on the record, and stamped with the quote; the record is `confirmed`
//! with its on-chain anchor present; and the per-account balance events are
//! sequenced gap-free in commit order with a matching outbox row per event.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use age::secrecy::SecretString;
use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};
use gateway_core::chain::confirm::{
    confirm_policy, upsert_tip, ConfirmConfig, ConfirmHandler, CONFIRM_QUEUE,
};
use gateway_core::chain::gateway::{
    BlockInfo, ChainGateway, ChainTip, Label309RecordsResult, TxCborMap, TxConfirmation,
    TxConfirmationMap,
};
use gateway_core::chain::records::{index_tx_policy, IndexTxHandler, IndexTxJob, INDEX_TX_QUEUE};
use gateway_core::chain::submit::{submit_policy, SubmitHandler, SubmitJob, SubmitOutcome};
use gateway_core::ledger::account::create_account;
use gateway_core::ledger::journal::{
    insert_ledger_entry, load_balance_micros, register_kind, LedgerEntry,
};
use gateway_core::ledger::quote::{
    consume_quote, create_quote, ConsumeOutcome, FixedMarginHook, FxSnapshot, QuoteRequest,
};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::config::{LovelaceBand, Network, WalletConfig};
use gateway_core::wallet::keyring::{derive_enterprise_address, unlock, UnlockedKeyring};
use pallas_crypto::key::ed25519::{PublicKey, SecretKey};
use pallas_primitives::conway::Tx as ConwayTx;
use pallas_primitives::Fragment;
use rust_decimal::Decimal;
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

const NETWORK: &str = "preprod";
const TEST_SCRYPT_LOG_N: u8 = 4;
const PREPROD_EPOCH: i32 = 100;

/// The vendor credit kind a deployment registers to fund accounts. Not a core
/// kind: the engine seeds only publish/refund, and a vendor declares its own
/// top-up kind through the registry before crediting an account.
const VENDOR_TOPUP_KIND: &str = "topup_stripe";

// ---------------------------------------------------------------------------
// A test chain gateway that accepts a submit (echoing the builder's tx id) and
// reports nothing on chain for confirmation reads, so Pass A drives confirmation
// purely from the materialised tip and the record's stamped block height.
// ---------------------------------------------------------------------------

struct AcceptGateway {
    submits: AtomicU32,
}

impl AcceptGateway {
    fn new() -> Self {
        Self {
            submits: AtomicU32::new(0),
        }
    }
}

impl ChainGateway for AcceptGateway {
    async fn submit_tx(&self, signed_tx: &[u8]) -> gateway_core::Result<[u8; 32]> {
        self.submits.fetch_add(1, Ordering::SeqCst);
        Ok(body_hash_of(signed_tx))
    }

    async fn get_tx_confirmations(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxConfirmationMap> {
        Ok(tx_hashes
            .iter()
            .map(|h| (*h, TxConfirmation::not_on_chain()))
            .collect())
    }

    async fn get_block_info(&self, _block_height: u64) -> gateway_core::Result<Option<BlockInfo>> {
        Ok(None)
    }

    async fn get_tip(&self) -> gateway_core::Result<ChainTip> {
        Ok(ChainTip {
            block_height: 0,
            epoch: None,
        })
    }

    async fn fetch_tx_cbor_by_hashes(
        &self,
        _tx_hashes: &[[u8; 32]],
    ) -> gateway_core::Result<TxCborMap> {
        Ok(TxCborMap::new())
    }

    async fn fetch_label309_records_since(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<Label309RecordsResult> {
        Ok(Label309RecordsResult::default())
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> gateway_core::Result<Label309RecordsResult> {
        Ok(Label309RecordsResult::default())
    }
}

/// The Blake2b-256 hash of a transaction's body (its id), recomputed from the
/// signed CBOR so the gateway echoes the same id the builder produced.
fn body_hash_of(tx_bytes: &[u8]) -> [u8; 32] {
    let tx = ConwayTx::decode_fragment(tx_bytes).expect("decode submitted tx");
    *pallas_crypto::hash::Hasher::<256>::hash(tx.transaction_body.raw_cbor())
}

// ---------------------------------------------------------------------------
// Wallet + fixtures (mirrors the submit suite's deterministic-key setup).
// ---------------------------------------------------------------------------

fn band() -> LovelaceBand {
    LovelaceBand {
        min: 4_000_000,
        max: 8_000_000,
        mid: 6_000_000,
    }
}

fn wallet_config() -> WalletConfig {
    WalletConfig {
        network: Network::Preprod,
        band: band(),
        lease: Duration::from_secs(120),
        min_canonical_count: 4,
    }
}

fn confirm_config() -> ConfirmConfig {
    ConfirmConfig {
        confirmation_threshold: 5,
        ..ConfirmConfig::default()
    }
}

/// A deterministic wallet: a fixed-seed ed25519 key, its derived preprod
/// enterprise address, and an unlocked keyring holding the signer for it.
struct Wallet {
    address: String,
    keyring: Arc<UnlockedKeyring>,
}

fn wallet_from_seed(seed: [u8; 32]) -> Wallet {
    let secret = SecretKey::from(seed);
    let public: PublicKey = secret.public_key();
    let mut vk = [0u8; 32];
    vk.copy_from_slice(public.as_ref());
    let address = derive_enterprise_address(&vk, Network::Preprod).expect("derive address");

    let hrp = bech32::Hrp::parse("ed25519_sk").expect("hrp");
    let bech32_skey = bech32::encode::<bech32::Bech32>(hrp, &seed).expect("encode skey");
    let json = json!({
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

    Wallet {
        address,
        keyring: Arc::new(keyring),
    }
}

/// Insert an operator and an active wallet at `address`, returning their ids.
async fn seed_operator_and_wallet(pool: &sqlx::PgPool, address: &str) -> (Uuid, Uuid) {
    let operator_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'op')")
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("insert operator");

    let wallet_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.operator_wallet (id, registrar_operator_id, label, address, network, status) \
         VALUES ($1, $2, 'primary', $3, 'preprod', 'active')",
    )
    .bind(wallet_id)
    .bind(operator_id)
    .bind(address)
    .execute(pool)
    .await
    .expect("insert wallet");
    (operator_id, wallet_id)
}

/// Seed one canonical, available UTxO for a wallet.
async fn seed_canonical_utxo(pool: &sqlx::PgPool, wallet_id: Uuid, byte: u8) {
    sqlx::query(
        "INSERT INTO cw_core.wallet_utxo \
           (wallet_id, tx_hash, output_index, lovelace, state, canonical, source) \
         VALUES ($1, $2, 0, $3, 'available', true, 'snapshot')",
    )
    .bind(wallet_id)
    .bind([byte; 32].as_slice())
    .bind(band().mid as i64)
    .execute(pool)
    .await
    .expect("insert utxo");
}

/// Seed the cached preprod protocol parameters the build reads.
async fn seed_protocol_params(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO cw_core.cardano_protocol_params \
           (network, epoch, min_fee_a, min_fee_b, coins_per_utxo_byte, max_tx_size, raw) \
         VALUES ('preprod', $1, 44, 155381, 4310, 16384, '{}'::jsonb)",
    )
    .bind(PREPROD_EPOCH)
    .execute(pool)
    .await
    .expect("insert params");
}

/// Insert a `poe_record` bound to the tenant account, ready for submit.
async fn seed_record(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
    wallet_id: Uuid,
    record_bytes: &[u8],
) -> Uuid {
    let record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record \
           (id, operator_id, account_id, record_bytes, status, wallet_id, request_id) \
         VALUES ($1, $2, $3, $4, 'submitting', $5, 'req-publish')",
    )
    .bind(record_id)
    .bind(operator_id)
    .bind(account_id)
    .bind(record_bytes)
    .bind(wallet_id)
    .execute(pool)
    .await
    .expect("insert record");
    record_id
}

/// Register the queue policies the submit nudge and confirm enqueue resolve.
async fn register_queue_policies(pool: &sqlx::PgPool) {
    for policy in [submit_policy(), confirm_policy(), index_tx_policy()] {
        gateway_core::runtime::policy::reconcile(pool, &policy)
            .await
            .expect("reconcile policy");
    }
}

/// A minimal valid open Label 309 record's canonical bytes. The submit path
/// treats the record bytes as opaque metadata, but the single chain-records writer
/// validates them as a real record before indexing, so the lifecycle must publish
/// a structurally valid record for the confirm-driven index step to land.
fn open_record_bytes() -> Vec<u8> {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![0xab; 32])],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    encode_poe_record(&record).expect("encode record")
}

/// An FX snapshot pricing 1 ADA at $0.50 and zero storage, so the COGS is the
/// network fee alone and the lifecycle arithmetic stays exact.
fn fx() -> FxSnapshot {
    FxSnapshot {
        ada_usd_micros: 500_000,
        ar_usd_per_byte_femto: 0,
        source: "lifecycle-oracle".to_string(),
    }
}

/// The per-account balance events in `subject_seq` order, each as
/// `(subject_seq, event_type, kind)`.
async fn balance_events(pool: &sqlx::PgPool, account_id: Uuid) -> Vec<(i64, String, String)> {
    sqlx::query_as::<_, (i64, String, serde_json::Value)>(
        "SELECT subject_seq, event_type, payload FROM cw_core.subject_event \
         WHERE subject_kind = 'account' AND subject_id = $1 ORDER BY subject_seq",
    )
    .bind(account_id.to_string())
    .fetch_all(pool)
    .await
    .expect("read balance events")
    .into_iter()
    .map(|(seq, ty, payload)| {
        (
            seq,
            ty,
            payload["kind"].as_str().unwrap_or_default().to_string(),
        )
    })
    .collect()
}

/// The full billed publish lifecycle, end to end: account -> vendor kind ->
/// credit -> quote -> consume -> submit -> confirm, with the money and chain
/// end-state proven at every joint.
#[tokio::test]
async fn full_billed_publish_lifecycle() {
    let db = TestDb::fresh().await.expect("test database");
    register_queue_policies(&db.pool).await;
    seed_protocol_params(&db.pool).await;

    let wallet = wallet_from_seed([7u8; 32]);
    let (operator_id, wallet_id) = seed_operator_and_wallet(&db.pool, &wallet.address).await;
    seed_canonical_utxo(&db.pool, wallet_id, 0x77).await;

    // 1. Provision a tenant account under the operator (anchor + satellite).
    let account_id = create_account(&db.pool, operator_id)
        .await
        .expect("create account");

    // 2. A vendor registers its own credit kind (the engine seeds only
    //    publish/refund). It is non-overdrawing: a top-up only ever credits.
    register_kind(&db.pool, VENDOR_TOPUP_KIND, false, "vendor")
        .await
        .expect("register vendor credit kind");

    // 3. Credit the balance through that vendor kind. A 5_000_000 micro-USD
    //    top-up funds the publish.
    const CREDIT_MICROS: i64 = 5_000_000;
    insert_ledger_entry(
        &db.pool,
        &LedgerEntry {
            account_id,
            kind: VENDOR_TOPUP_KIND.to_string(),
            amount_micros: CREDIT_MICROS,
            r#ref: Some("invoice-1".to_string()),
            quote_id: None,
            metadata: json!({ "rail": "stripe" }),
            request_id: Some(Uuid::now_v7()),
        },
    )
    .await
    .expect("credit the account");
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        CREDIT_MICROS,
        "the credit materialised the balance"
    );

    // 4. Materialise the record the publish is for, so the quote can be priced for
    //    its exact byte length (the consume enforces the published record is no
    //    larger than the quote was priced for).
    let record_bytes = open_record_bytes();
    let record_len = u32::try_from(record_bytes.len()).expect("record length fits u32");

    // 5. Price the publish: a quote through the pricing hook. 2 ADA fee at
    //    $0.50/ADA = 1_000_000 micro-USD COGS; a flat 25% margin = 250_000
    //    service; total 1_250_000. The price tracks the network fee and storage
    //    bytes, not record_bytes, so quoting the record's exact length leaves the
    //    asserted totals unchanged.
    let quote = create_quote(
        &db.pool,
        &FixedMarginHook::new(Decimal::new(25, 2)),
        &QuoteRequest {
            account_id,
            record_bytes: record_len,
            recipient_count: 0,
            file_bytes_total: 0,
            free_storage_bytes: gateway_core::ledger::quote::DEFAULT_FREE_STORAGE_BYTES,
            network_lovelace: 2_000_000,
            fx: fx(),
            fx_age_seconds: 0,
            request_id: Some(Uuid::now_v7()),
        },
    )
    .await
    .expect("create quote");
    assert_eq!(quote.total_usd_micros, 1_250_000, "COGS + 25% margin");

    // 6. Seed the record bound to the tenant account.
    let record_id = seed_record(&db.pool, operator_id, account_id, wallet_id, &record_bytes).await;

    // 7. Consume the quote in one transaction: the signed-negative publish debit,
    //    bound to the record, charged against the balance. The published record's
    //    exact length is passed; it equals the quoted size, so the size contract
    //    holds.
    let consume = consume_quote(
        &db.pool,
        quote.id,
        account_id,
        record_id,
        record_len,
        Some(Uuid::now_v7()),
    )
    .await
    .expect("consume quote");
    assert_eq!(
        consume,
        ConsumeOutcome::Consumed {
            balance_micros: CREDIT_MICROS - 1_250_000
        },
        "consume charges the quote total exactly once"
    );
    assert_eq!(
        load_balance_micros(&db.pool, account_id).await.unwrap(),
        CREDIT_MICROS - 1_250_000,
        "the balance reflects credit minus the publish charge"
    );

    // 8. Submit the record through the real submission pipeline against the
    //    accept gateway. The submit flips the record to `submitted` and applies
    //    the spend locally.
    let submit_handler = SubmitHandler::new(
        db.pool.clone(),
        AcceptGateway::new(),
        wallet_config(),
        wallet.keyring.clone(),
    );
    let outcome = submit_handler
        .submit_once(
            &SubmitJob {
                request_id: "req-publish".to_string(),
                record_id,
                replacement_for: None,
                forced_inputs: Vec::new(),
            },
            1,
        )
        .await
        .expect("submit once");
    let SubmitOutcome::Submitted { tx_hash, .. } = outcome else {
        panic!("expected a submitted outcome, got {outcome:?}");
    };
    let (status, has_tx): (String, bool) = sqlx::query_as(
        "SELECT status, (tx_hash IS NOT NULL) FROM cw_core.poe_record WHERE id = $1",
    )
    .bind(record_id)
    .fetch_one(&db.pool)
    .await
    .expect("read record after submit");
    assert_eq!(status, "submitted");
    assert!(has_tx, "a submitted record carries its tx hash");

    // 9. The chain includes the transaction: stamp the block coordinates the
    //    confirm loop's threshold pass reads onto the ATTEMPT (the chain-effect
    //    ledger is the authority; in production Pass B discovers and stamps these,
    //    the e2e records them deterministically). Then drive the real confirmation
    //    loop. With the attempt at height 100 and the tip at 110, confirmations =
    //    11 >= the threshold of 5, so Pass A settles it.
    sqlx::query(
        "UPDATE cw_core.chain_attempt \
         SET block_height = 100, block_time = now(), first_seen_on_chain_at = now() \
         WHERE tx_hash = $1",
    )
    .bind(tx_hash.to_vec())
    .execute(&db.pool)
    .await
    .expect("stamp the attempt's on-chain coordinates");
    upsert_tip(&db.pool, NETWORK, 110, None)
        .await
        .expect("materialise the tip");

    let confirm_handler = ConfirmHandler::new(
        db.pool.clone(),
        AcceptGateway::new(),
        NETWORK,
        confirm_config(),
        wallet_config(),
    );
    let summary = confirm_handler
        .run_iteration()
        .await
        .expect("confirm iteration");
    assert_eq!(summary.confirmed, 1, "the record crossed the threshold");

    let confirmed_status: String =
        sqlx::query_scalar("SELECT status FROM cw_core.poe_record WHERE id = $1")
            .bind(record_id)
            .fetch_one(&db.pool)
            .await
            .expect("read confirmed status");
    assert_eq!(confirmed_status, "confirmed");

    // 10. The confirm flip enqueued exactly one index job; drive the single
    //    chain-records writer so the record's on-chain anchor is materialised, and
    //    assert the thin `cw_api.records` anchor and its rich `chain_records` row
    //    both exist for the transaction.
    let index_job: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM cw_core.job WHERE queue = $1")
            .bind(INDEX_TX_QUEUE)
            .fetch_one(&db.pool)
            .await
            .expect("the confirm flip enqueued an index job");
    let job: IndexTxJob = serde_json::from_value(index_job).expect("decode index job");
    assert_eq!(
        job.tx_hash,
        hex::encode(tx_hash),
        "the index job names the confirmed transaction"
    );
    let indexed = IndexTxHandler::new(
        db.pool.clone(),
        AcceptGateway::new(),
        gateway_core::chain::params::Network::Preprod,
    )
    .index_once(&job)
    .await
    .expect("index the confirmed transaction");
    assert!(indexed, "the single writer inserted the record");
    let (anchor, rich): (bool, bool) = sqlx::query_as(
        "SELECT \
           EXISTS (SELECT 1 FROM cw_api.records WHERE tx_hash = $1), \
           EXISTS (SELECT 1 FROM cw_core.chain_records WHERE tx_hash = $1)",
    )
    .bind(tx_hash.as_slice())
    .fetch_one(&db.pool)
    .await
    .expect("read anchor/rich existence");
    assert!(anchor, "the thin cw_api.records anchor exists");
    assert!(rich, "the rich cw_core.chain_records row exists");

    // 11. The money end-state: exactly one credit and one publish debit, the
    //     debit signed-negative, keyed on the record, and stamped with the quote.
    let ledger: Vec<(String, i64, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT kind, amount_micros, ref, quote_id FROM cw_core.balance_ledger \
         WHERE account_id = $1 ORDER BY occurred_at",
    )
    .bind(account_id)
    .fetch_all(&db.pool)
    .await
    .expect("read ledger");
    assert_eq!(ledger.len(), 2, "exactly a credit and a debit");
    assert_eq!(ledger[0].0, VENDOR_TOPUP_KIND);
    assert_eq!(ledger[0].1, CREDIT_MICROS);
    assert_eq!(ledger[1].0, "poe_publish");
    assert_eq!(
        ledger[1].1, -1_250_000,
        "the publish debit is signed-negative"
    );
    assert_eq!(
        ledger[1].2.as_deref(),
        Some(record_id.to_string().as_str()),
        "the debit is keyed on the record"
    );
    assert_eq!(
        ledger[1].3,
        Some(quote.id),
        "the debit is stamped with the quote it consumed"
    );

    // The quote is consumed and bound to the record.
    let (quote_status, bound): (String, Option<Uuid>) =
        sqlx::query_as("SELECT status, poe_record_id FROM cw_core.publish_quote WHERE id = $1")
            .bind(quote.id)
            .fetch_one(&db.pool)
            .await
            .expect("read quote end-state");
    assert_eq!(quote_status, "consumed");
    assert_eq!(bound, Some(record_id));

    // 12. The account's balance events are sequenced gap-free in commit order
    //     (credit then debit), with one outbox row per event. The submit/confirm
    //     status events are recorded under the `poe_record` subject, so the
    //     `account` subject sees only the two money events.
    let events = balance_events(&db.pool, account_id).await;
    assert_eq!(
        events,
        vec![
            (
                1,
                "balance.changed".to_string(),
                VENDOR_TOPUP_KIND.to_string()
            ),
            (2, "balance.changed".to_string(), "poe_publish".to_string()),
        ],
        "the account's balance events are gap-free, in commit order, credit then debit"
    );
    let outbox_for_account: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.delivery_outbox \
         WHERE subject_kind = 'account' AND subject_id = $1",
    )
    .bind(account_id.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("count account outbox rows");
    assert_eq!(
        outbox_for_account, 2,
        "every balance event has its delivery-outbox row"
    );

    // The confirm loop nudged itself (a singleton re-enqueue exists), proving the
    // lifecycle ends with the loop scheduled to keep settling.
    let confirm_jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM cw_core.job WHERE queue = $1")
        .bind(CONFIRM_QUEUE)
        .fetch_one(&db.pool)
        .await
        .expect("count confirm jobs");
    assert!(
        confirm_jobs >= 1,
        "the confirm loop is scheduled to continue settling"
    );
}
