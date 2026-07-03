//! Postgres-backed coverage for the forward-scan fetch under the failover policy.
//!
//! A transient failure on the primary's `fetch_label309_records_since` (a
//! classified 5xx, 429, or transport blip) must fail over to the secondary and
//! return the secondary's records; a non-transient failure (a deterministic 4xx)
//! must propagate without a failover attempt, because a second provider would
//! repeat the same rejection. The cooldown the failover wrapper consults is
//! database-backed, so these tests run only under `pg-tests`.
//!
//! No live HTTP: both providers are in-process scripted gateways. The forward
//! scan over a real provider's wire shape is covered, network-free, in
//! `chain_label_fetch_providers`.

#![cfg(feature = "pg-tests")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use gateway_core::chain::gateway::{
    chain_error, classify_chain_error, BlockInfo, ChainErrorClass, ChainGateway, ChainTip,
    FailoverGateway, Label309Record, Label309RecordsResult, ProviderCooldown, ProviderKind,
    ScanFrontier, TxCborMap, TxConfirmationMap,
};
use gateway_core::chain::params::Network;
use gateway_core::testsupport::TestDb;
use gateway_core::Result;

/// A scripted in-process gateway whose only interesting arm is the forward scan.
///
/// `scan_result` is the outcome the next `fetch_label309_records_since` returns;
/// `scan_calls` is a shared counter the test holds a clone of, so it can prove
/// the secondary was (or was not) reached without reaching back into the
/// failover wrapper that owns the gateway.
struct ScriptedScanGateway {
    scan_calls: Arc<AtomicU32>,
    scan_result: Mutex<Option<Result<Label309RecordsResult>>>,
}

impl ScriptedScanGateway {
    /// Build the gateway and the call-counter handle the test keeps.
    fn returning(result: Result<Label309RecordsResult>) -> (Self, Arc<AtomicU32>) {
        let scan_calls = Arc::new(AtomicU32::new(0));
        (
            Self {
                scan_calls: scan_calls.clone(),
                scan_result: Mutex::new(Some(result)),
            },
            scan_calls,
        )
    }
}

impl ChainGateway for ScriptedScanGateway {
    async fn submit_tx(&self, _signed_tx: &[u8]) -> Result<[u8; 32]> {
        Ok([0u8; 32])
    }

    async fn get_tx_confirmations(&self, tx_hashes: &[[u8; 32]]) -> Result<TxConfirmationMap> {
        Ok(tx_hashes
            .iter()
            .map(|h| {
                (
                    *h,
                    gateway_core::chain::gateway::TxConfirmation::not_on_chain(),
                )
            })
            .collect())
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
        Ok(HashMap::new())
    }

    async fn fetch_label309_records_since(
        &self,
        _after_block_height: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _tip_block_height: u64,
        _max_records: u32,
    ) -> Result<Label309RecordsResult> {
        self.scan_calls.fetch_add(1, Ordering::SeqCst);
        self.scan_result
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Ok(Label309RecordsResult::default()))
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        after_block_height: u64,
        exclude_tx_hashes: &[[u8; 32]],
        tip_block_height: u64,
        max_records: u32,
    ) -> Result<Label309RecordsResult> {
        self.fetch_label309_records_since(
            after_block_height,
            exclude_tx_hashes,
            tip_block_height,
            max_records,
        )
        .await
    }
}

/// One record the secondary returns so a successful failover is observable.
fn secondary_record() -> Label309Record {
    Label309Record {
        tx_hash: [0xab; 32],
        block_hash: [0xcd; 32],
        block_height: 500,
        block_time: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
        num_confirmations: 101,
        metadata_cbor: vec![0xa1, 0x01, 0x18, 0x2a],
    }
}

fn secondary_result() -> Label309RecordsResult {
    Label309RecordsResult {
        records: vec![secondary_record()],
        frontier: ScanFrontier::CaughtUpTo { indexed_to: 1_000 },
    }
}

#[tokio::test]
async fn a_transient_primary_scan_failure_fails_over_to_the_secondary() {
    let db = TestDb::fresh().await.expect("test database");
    let cooldown = ProviderCooldown::new(db.pool.clone());

    // The primary raises a classified 5xx (transient); the secondary answers.
    let (primary, primary_calls) = ScriptedScanGateway::returning(Err(chain_error(
        ChainErrorClass::Http { status: 503 },
        "koios scan unavailable",
    )));
    let (secondary, secondary_calls) = ScriptedScanGateway::returning(Ok(secondary_result()));

    let failover = FailoverGateway::new(
        primary,
        secondary,
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        cooldown,
        Network::Preprod,
    );

    let result = failover
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("a transient primary failure fails over rather than surfacing");

    // The secondary's records came through.
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].tx_hash, [0xab; 32]);
    assert_eq!(
        result.records[0].metadata_cbor,
        vec![0xa1, 0x01, 0x18, 0x2a]
    );

    // Both providers were asked exactly once: primary failed, secondary answered.
    assert_eq!(
        primary_calls.load(Ordering::SeqCst),
        1,
        "the primary is tried first"
    );
    assert_eq!(
        secondary_calls.load(Ordering::SeqCst),
        1,
        "a transient primary failure fails over to the secondary"
    );
}

#[tokio::test]
async fn a_transient_primary_429_engages_the_cooldown_before_failing_over() {
    let db = TestDb::fresh().await.expect("test database");
    let cooldown = ProviderCooldown::new(db.pool.clone());

    let (primary, _primary_calls) = ScriptedScanGateway::returning(Err(chain_error(
        ChainErrorClass::Http { status: 429 },
        "koios rate limited",
    )));
    let (secondary, _secondary_calls) = ScriptedScanGateway::returning(Ok(secondary_result()));

    let failover = FailoverGateway::new(
        primary,
        secondary,
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        cooldown,
        Network::Preprod,
    );

    let result = failover
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("a 429 fails over");
    assert_eq!(result.records.len(), 1);

    // The 429 armed the primary's cooldown, so a subsequent read sees it active.
    let active = failover
        .cooldown()
        .active_until(ProviderKind::Koios, Network::Preprod)
        .await
        .expect("cooldown read");
    assert!(
        active.is_some(),
        "a 429 on the primary scan engages the per-provider cooldown"
    );
}

#[tokio::test]
async fn a_primary_already_in_cooldown_skips_straight_to_the_secondary() {
    let db = TestDb::fresh().await.expect("test database");
    let cooldown = ProviderCooldown::new(db.pool.clone());
    // Pre-arm the primary's cooldown so the wrapper skips it without a call.
    cooldown
        .engage(
            ProviderKind::Koios,
            Network::Preprod,
            Utc::now() + chrono::Duration::seconds(300),
        )
        .await
        .expect("engage cooldown");

    // The primary would succeed if called, but it must not be called at all.
    let (primary, primary_calls) =
        ScriptedScanGateway::returning(Ok(Label309RecordsResult::default()));
    let (secondary, secondary_calls) = ScriptedScanGateway::returning(Ok(secondary_result()));

    let failover = FailoverGateway::new(
        primary,
        secondary,
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        cooldown,
        Network::Preprod,
    );

    let result = failover
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("the secondary answers while the primary is parked");
    assert_eq!(
        result.records.len(),
        1,
        "the secondary's records came through"
    );

    assert_eq!(
        primary_calls.load(Ordering::SeqCst),
        0,
        "a primary in cooldown is skipped without a call"
    );
    assert_eq!(secondary_calls.load(Ordering::SeqCst), 1);
}

/// A corrupt-provider failure (the primary served data that cannot exist on
/// chain, e.g. an over-cap metadata chunk) is a verdict on the PRIMARY, not on
/// the chain: the secondary is expected to serve the true bytes, so the wrapper
/// must fail over and return its records. The scan cursor then advances only
/// over correctly-served data.
#[tokio::test]
async fn a_corrupt_primary_scan_response_fails_over_to_the_secondary() {
    let db = TestDb::fresh().await.expect("test database");
    let cooldown = ProviderCooldown::new(db.pool.clone());

    let (primary, primary_calls) = ScriptedScanGateway::returning(Err(chain_error(
        ChainErrorClass::CorruptProvider,
        "koios served a 65-byte label-309 metadata chunk",
    )));
    let (secondary, secondary_calls) = ScriptedScanGateway::returning(Ok(secondary_result()));

    let failover = FailoverGateway::new(
        primary,
        secondary,
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        cooldown,
        Network::Preprod,
    );

    let result = failover
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect("a corrupt primary response fails over rather than surfacing");
    assert_eq!(
        result.records.len(),
        1,
        "the secondary's records came through"
    );
    assert_eq!(result.records[0].tx_hash, [0xab; 32]);

    assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        secondary_calls.load(Ordering::SeqCst),
        1,
        "provider corruption fails over: only the corrupt provider is distrusted"
    );

    // Corruption is not a rate limit: the per-provider cooldown stays disarmed.
    let active = failover
        .cooldown()
        .active_until(ProviderKind::Koios, Network::Preprod)
        .await
        .expect("cooldown read");
    assert!(
        active.is_none(),
        "a corrupt response does not engage the rate-limit cooldown"
    );
}

#[tokio::test]
async fn a_non_transient_primary_scan_failure_propagates_without_failover() {
    let db = TestDb::fresh().await.expect("test database");
    let cooldown = ProviderCooldown::new(db.pool.clone());

    // A malformed response body is deterministic: a second provider would not
    // decode it differently either, so the wrapper must not fail over.
    let (primary, primary_calls) = ScriptedScanGateway::returning(Err(chain_error(
        ChainErrorClass::BadResponse,
        "koios returned an undecodable body",
    )));
    let (secondary, secondary_calls) = ScriptedScanGateway::returning(Ok(secondary_result()));

    let failover = FailoverGateway::new(
        primary,
        secondary,
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        cooldown,
        Network::Preprod,
    );

    let err = failover
        .fetch_label309_records_since(0, &[], 600, 200)
        .await
        .expect_err("a malformed body must propagate, not fail over");
    assert_eq!(
        classify_chain_error(&err),
        Some(ChainErrorClass::BadResponse)
    );

    assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        secondary_calls.load(Ordering::SeqCst),
        0,
        "a deterministic failure never reaches the secondary"
    );
}

/// A provider-side HTTP 4xx that is NOT a proven ledger reject — a 401/403
/// auth/routing misconfig or a 404 routing error — is now TRANSIENT: the wrapper
/// fails over to the secondary so a single provider's misconfiguration cannot fail
/// a request the other provider can serve. This is the read side of the GC-2 fix.
#[tokio::test]
async fn a_provider_side_4xx_fails_over_to_the_secondary() {
    for status in [401u16, 403, 404] {
        let db = TestDb::fresh().await.expect("test database");
        let cooldown = ProviderCooldown::new(db.pool.clone());

        let (primary, primary_calls) = ScriptedScanGateway::returning(Err(chain_error(
            ChainErrorClass::Http { status },
            "provider misconfig",
        )));
        let (secondary, secondary_calls) = ScriptedScanGateway::returning(Ok(secondary_result()));

        let failover = FailoverGateway::new(
            primary,
            secondary,
            ProviderKind::Koios,
            ProviderKind::Blockfrost,
            cooldown,
            Network::Preprod,
        );

        let result = failover
            .fetch_label309_records_since(0, &[], 600, 200)
            .await
            .unwrap_or_else(|e| panic!("a {status} must fail over to the secondary, got {e:?}"));
        assert_eq!(
            result.records.len(),
            1,
            "the secondary's records are returned after a {status} failover"
        );
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            secondary_calls.load(Ordering::SeqCst),
            1,
            "a provider-side {status} reaches the secondary"
        );
    }
}
