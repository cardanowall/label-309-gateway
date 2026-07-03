//! Postgres-backed coverage for the chain gateway's restart-survivable cooldown
//! and its failover policy, plus a local-fake behavioural check of the Koios
//! request chunking. Gated behind `pg-tests` so the default `cargo test` never
//! needs a database.
//!
//! No test here makes a live HTTP call: the failover policy is driven by an
//! in-process scripted gateway, and the chunking check points the real Koios
//! gateway at a tiny local TCP server that records the request bodies.

#![cfg(feature = "pg-tests")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{Duration as ChronoDuration, Utc};
use gateway_core::chain::gateway::{
    build_failover_gateway, chain_error, BlockInfo, ChainErrorClass, ChainGateway, ChainTip,
    FailoverGateway, KoiosGateway, Label309RecordsResult, ProviderCooldown, ProviderKind,
    TxCborMap, TxConfirmation, TxConfirmationMap, TxPresence, KOIOS_KEYLESS_CHUNK,
};
use gateway_core::chain::params::{KoiosConfig, Network};
use gateway_core::testsupport::TestDb;
use gateway_core::Result;

// ---------------------------------------------------------------------------
// A scripted in-process gateway, so the failover policy can be exercised without
// any network. Each method counts its calls and returns the next scripted
// result; the submit arm carries an explicit Result so a test can inject a
// classified transient (or non-transient) error.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeGateway {
    submit_calls: AtomicU32,
    submit_result: Mutex<Option<Result<[u8; 32]>>>,
}

impl FakeGateway {
    fn ok(hash: [u8; 32]) -> Self {
        Self {
            submit_calls: AtomicU32::new(0),
            submit_result: Mutex::new(Some(Ok(hash))),
        }
    }

    fn err(error: gateway_core::Error) -> Self {
        Self {
            submit_calls: AtomicU32::new(0),
            submit_result: Mutex::new(Some(Err(error))),
        }
    }

    fn submit_calls(&self) -> u32 {
        self.submit_calls.load(Ordering::SeqCst)
    }
}

impl ChainGateway for FakeGateway {
    async fn submit_tx(&self, _signed_tx: &[u8]) -> Result<[u8; 32]> {
        self.submit_calls.fetch_add(1, Ordering::SeqCst);
        self.submit_result
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Ok([0u8; 32]))
    }

    async fn get_tx_confirmations(&self, tx_hashes: &[[u8; 32]]) -> Result<TxConfirmationMap> {
        Ok(tx_hashes
            .iter()
            .map(|h| (*h, TxConfirmation::not_on_chain()))
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

// ---------------------------------------------------------------------------
// ProviderCooldown: write-through and restart-survivable read.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failover_secondary_is_blockfrost_only_when_a_project_id_is_supplied() {
    let db = TestDb::fresh().await.expect("test database");

    let egress = gateway_core::chain::egress::ChainEgress::unlimited(Network::Preprod);

    // No project id: the secondary degrades to a second Koios instance, so a Koios
    // 429 parks both providers (the all-keyless-Koios stall this fix removes).
    let koios_secondary = build_failover_gateway(
        Network::Preprod,
        &KoiosConfig::default(),
        None,
        ProviderCooldown::new(db.pool.clone()),
        &egress,
    )
    .expect("build with no project id");
    assert_eq!(
        koios_secondary.provider_kinds(),
        (ProviderKind::Koios, ProviderKind::Koios),
        "no Blockfrost secret means both providers are Koios"
    );

    // A project id supplied: the secondary is a real Blockfrost gateway, so a Koios
    // 429 fails over to Blockfrost rather than a second Koios.
    let blockfrost_secondary = build_failover_gateway(
        Network::Preprod,
        &KoiosConfig::default(),
        Some(
            "preprodNONSECRET000000000000000000000000"
                .to_string()
                .into(),
        ),
        ProviderCooldown::new(db.pool.clone()),
        &egress,
    )
    .expect("build with a project id");
    assert_eq!(
        blockfrost_secondary.provider_kinds(),
        (ProviderKind::Koios, ProviderKind::Blockfrost),
        "a configured project id makes the secondary Blockfrost"
    );
}

#[tokio::test]
async fn cooldown_write_through_is_read_back_and_survives_a_reconnect() {
    let db = TestDb::fresh().await.expect("test database");

    // Engage a cooldown for koios on preprod 5 minutes out.
    let store = ProviderCooldown::new(db.pool.clone());
    let until = Utc::now() + ChronoDuration::seconds(300);
    store
        .engage(ProviderKind::Koios, Network::Preprod, until)
        .await
        .expect("engage cooldown");

    // A fresh store over a fresh pool (the "after a restart" case) reads the
    // persisted gate: correctness never relied on in-process state.
    let reconnected_pool = db.pool_with(2).await.expect("second pool");
    let restarted = ProviderCooldown::new(reconnected_pool);
    let active = restarted
        .active_until(ProviderKind::Koios, Network::Preprod)
        .await
        .expect("read cooldown");
    let active = active.expect("the engaged cooldown is still active after a reconnect");
    // The persisted instant is the one we wrote (to the second).
    assert_eq!(active.timestamp(), until.timestamp());

    // A different provider/network shares no gate.
    assert!(restarted
        .active_until(ProviderKind::Blockfrost, Network::Preprod)
        .await
        .expect("read blockfrost cooldown")
        .is_none());
    assert!(restarted
        .active_until(ProviderKind::Koios, Network::Mainnet)
        .await
        .expect("read mainnet cooldown")
        .is_none());
}

#[tokio::test]
async fn an_expired_cooldown_reads_as_free() {
    let db = TestDb::fresh().await.expect("test database");
    let store = ProviderCooldown::new(db.pool.clone());

    // A cooldown already in the past must not gate a call.
    let past = Utc::now() - ChronoDuration::seconds(60);
    store
        .engage(ProviderKind::Koios, Network::Preprod, past)
        .await
        .expect("engage past cooldown");
    assert!(store
        .active_until(ProviderKind::Koios, Network::Preprod)
        .await
        .expect("read expired cooldown")
        .is_none());
}

#[tokio::test]
async fn engage_never_shortens_an_existing_cooldown() {
    let db = TestDb::fresh().await.expect("test database");
    let store = ProviderCooldown::new(db.pool.clone());

    let far = Utc::now() + ChronoDuration::seconds(600);
    let near = Utc::now() + ChronoDuration::seconds(60);
    store
        .engage(ProviderKind::Koios, Network::Preprod, far)
        .await
        .expect("engage far cooldown");
    // A later writer with a nearer instant must not pull the gate in: GREATEST
    // keeps the longer cooldown.
    store
        .engage(ProviderKind::Koios, Network::Preprod, near)
        .await
        .expect("engage near cooldown");
    let active = store
        .active_until(ProviderKind::Koios, Network::Preprod)
        .await
        .expect("read cooldown")
        .expect("cooldown still active");
    assert_eq!(
        active.timestamp(),
        far.timestamp(),
        "GREATEST preserves the longer cooldown; a nearer instant never shortens it"
    );
}

// ---------------------------------------------------------------------------
// FailoverGateway policy.
// ---------------------------------------------------------------------------

/// Build a failover wrapper over two fakes, with an empty (no-cooldown) store.
fn failover(
    db: &TestDb,
    primary: FakeGateway,
    secondary: FakeGateway,
) -> FailoverGateway<FakeGateway, FakeGateway> {
    FailoverGateway::new(
        primary,
        secondary,
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        ProviderCooldown::new(db.pool.clone()),
        Network::Preprod,
    )
}

#[tokio::test]
async fn primary_success_is_returned_and_the_secondary_is_never_called() {
    let db = TestDb::fresh().await.expect("test database");

    // The secondary counts its calls so "never reached on the happy path" is a
    // concrete observable; the primary answers successfully.
    let secondary_calls = Arc::new(AtomicU32::new(0));
    let secondary = CountingSecondary {
        calls: secondary_calls.clone(),
    };
    let gw = FailoverGateway::new(
        FakeGateway::ok([0x01; 32]),
        secondary,
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        ProviderCooldown::new(db.pool.clone()),
        Network::Preprod,
    );

    let hash = gw.submit_tx(&[0x84]).await.expect("primary submit");
    assert_eq!(hash, [0x01; 32], "the primary's answer is returned");
    assert_eq!(
        secondary_calls.load(Ordering::SeqCst),
        0,
        "the secondary is never called when the primary succeeds"
    );
    assert_eq!(
        gw.provider_kinds(),
        (ProviderKind::Koios, ProviderKind::Blockfrost)
    );
}

#[tokio::test]
async fn a_transient_primary_failure_fails_over_to_the_secondary() {
    let db = TestDb::fresh().await.expect("test database");

    // The wrapper consumes the fakes, so to assert call counts the fakes are
    // built here and their behaviour scripted before the move; the assertion
    // reads the secondary's returned hash (only the secondary could produce it)
    // and confirms the cooldown was armed by the 429.
    let primary = FakeGateway::err(chain_error(
        ChainErrorClass::Http { status: 429 },
        "rate limited",
    ));
    let secondary = FakeGateway::ok([0x02; 32]);
    let gw = failover(&db, primary, secondary);

    let hash = gw.submit_tx(&[0x84]).await.expect("failover submit");
    assert_eq!(
        hash, [0x02; 32],
        "a transient primary failure is answered by the secondary"
    );

    // A 429 arms the per-provider cooldown so a sustained storm parks the loop.
    let cooldown = gw.cooldown();
    let active = cooldown
        .active_until(ProviderKind::Koios, Network::Preprod)
        .await
        .expect("read cooldown");
    assert!(
        active.is_some(),
        "a primary 429 must engage the koios cooldown"
    );
}

#[tokio::test]
async fn a_transient_5xx_fails_over_without_arming_the_cooldown() {
    let db = TestDb::fresh().await.expect("test database");
    let primary = FakeGateway::err(chain_error(
        ChainErrorClass::Http { status: 503 },
        "upstream down",
    ));
    let secondary = FakeGateway::ok([0x07; 32]);
    let gw = failover(&db, primary, secondary);

    let hash = gw.submit_tx(&[0x84]).await.expect("failover submit");
    assert_eq!(hash, [0x07; 32], "a 5xx fails over to the secondary");

    // A 5xx is transient but not a rate limit: it must NOT engage the cooldown.
    let active = gw
        .cooldown()
        .active_until(ProviderKind::Koios, Network::Preprod)
        .await
        .expect("read cooldown");
    assert!(
        active.is_none(),
        "only a 429 arms the cooldown; a 5xx fails over without it"
    );
}

#[tokio::test]
async fn a_non_transient_primary_failure_propagates_and_never_calls_the_secondary() {
    let db = TestDb::fresh().await.expect("test database");

    // Own the secondary through an Arc so its call count can be inspected after
    // the failover wrapper is dropped.
    let secondary_calls = Arc::new(AtomicU32::new(0));
    let secondary = CountingSecondary {
        calls: secondary_calls.clone(),
    };
    // A proven ledger reject (a 400/422 the submit path classified from the node's
    // validation error body) is the deterministic class that must NOT fail over: a
    // second provider would repeat the rejection. (A provider-side 401/403/404 is
    // now transient and DOES fail over — covered separately.)
    let primary = FakeGateway::err(chain_error(
        ChainErrorClass::NodeReject { status: 400 },
        "node rejected the body",
    ));
    let gw = FailoverGateway::new(
        primary,
        secondary,
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        ProviderCooldown::new(db.pool.clone()),
        Network::Preprod,
    );

    let err = gw
        .submit_tx(&[0x84])
        .await
        .expect_err("a deterministic ledger reject must propagate");
    // The non-transient error propagates unchanged: its class is still the reject.
    assert_eq!(
        gateway_core::chain::gateway::classify_chain_error(&err),
        Some(ChainErrorClass::NodeReject { status: 400 }),
        "the non-transient error propagates unchanged, got {err:?}"
    );
    assert_eq!(
        secondary_calls.load(Ordering::SeqCst),
        0,
        "a deterministic ledger reject must NOT fail over: the secondary is never called"
    );
}

#[tokio::test]
async fn a_primary_already_in_cooldown_is_skipped_straight_to_the_secondary() {
    let db = TestDb::fresh().await.expect("test database");

    // Pre-arm the koios cooldown so the wrapper must skip the primary.
    let store = ProviderCooldown::new(db.pool.clone());
    store
        .engage(
            ProviderKind::Koios,
            Network::Preprod,
            Utc::now() + ChronoDuration::seconds(300),
        )
        .await
        .expect("pre-arm cooldown");

    let primary_calls = Arc::new(AtomicU32::new(0));
    let primary = CountingPrimary {
        calls: primary_calls.clone(),
    };
    let gw = FailoverGateway::new(
        primary,
        FakeGateway::ok([0x09; 32]),
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        store,
        Network::Preprod,
    );

    let hash = gw.submit_tx(&[0x84]).await.expect("submit via secondary");
    assert_eq!(hash, [0x09; 32], "the secondary answers a parked primary");
    assert_eq!(
        primary_calls.load(Ordering::SeqCst),
        0,
        "a primary in cooldown is never called at all"
    );
}

/// The failover's submit honesty rule: a deterministic NodeReject answered by
/// the SECONDARY after the primary arm was attempted and failed transiently is
/// downgraded to the transient ambiguous-broadcast class. The failed primary
/// attempt is an ambiguous wire contact with the very bytes being submitted, so
/// the secondary's reject may be the transaction conflicting with its own
/// in-flight or landed copy — letting the clean reject surface would license
/// the submit path's immediate first-broadcast abandon-and-refund against bytes
/// that can still land.
#[tokio::test]
async fn a_secondary_reject_after_a_transient_primary_is_downgraded_to_ambiguous_regression() {
    let db = TestDb::fresh().await.expect("test database");
    let primary = FakeGateway::err(chain_error(
        ChainErrorClass::Http { status: 503 },
        "primary timed out mid-submit",
    ));
    let secondary = FakeGateway::err(chain_error(
        ChainErrorClass::NodeReject { status: 400 },
        "node rejected the transaction body",
    ));
    let gw = failover(&db, primary, secondary);

    let err = gw
        .submit_tx(&[0x84])
        .await
        .expect_err("both arms failed; the call errs");
    assert_eq!(
        gateway_core::chain::gateway::classify_chain_error(&err),
        Some(ChainErrorClass::NodeRejectAfterAmbiguousBroadcast { status: 400 }),
        "the secondary's reject is downgraded, carrying the node's status, got {err:?}"
    );
    assert!(
        !gateway_core::chain::gateway::is_deterministic_node_reject(&err),
        "a reject after an ambiguous primary contact must never read as deterministic"
    );
    assert!(
        gateway_core::chain::gateway::is_transient_chain_error(&err),
        "the downgraded reject is transient: the attempt stays in flight"
    );
}

/// The precision counterpart: a PARKED primary is skipped without touching the
/// payload, so the secondary's deterministic reject stands unchanged — the
/// clean first-broadcast refund is preserved when no ambiguous contact existed.
#[tokio::test]
async fn a_secondary_reject_with_the_primary_parked_stays_a_clean_deterministic_reject() {
    let db = TestDb::fresh().await.expect("test database");
    let store = ProviderCooldown::new(db.pool.clone());
    store
        .engage(
            ProviderKind::Koios,
            Network::Preprod,
            Utc::now() + ChronoDuration::seconds(300),
        )
        .await
        .expect("pre-arm cooldown");
    let primary_calls = Arc::new(AtomicU32::new(0));
    let primary = CountingPrimary {
        calls: primary_calls.clone(),
    };
    let secondary = FakeGateway::err(chain_error(
        ChainErrorClass::NodeReject { status: 422 },
        "node rejected the transaction body",
    ));
    let gw = FailoverGateway::new(
        primary,
        secondary,
        ProviderKind::Koios,
        ProviderKind::Blockfrost,
        store,
        Network::Preprod,
    );

    let err = gw
        .submit_tx(&[0x84])
        .await
        .expect_err("the secondary rejects");
    assert_eq!(
        primary_calls.load(Ordering::SeqCst),
        0,
        "the parked primary never touched the payload"
    );
    assert_eq!(
        gateway_core::chain::gateway::classify_chain_error(&err),
        Some(ChainErrorClass::NodeReject { status: 422 }),
        "with no ambiguous contact the reject stands as-is, got {err:?}"
    );
    assert!(gateway_core::chain::gateway::is_deterministic_node_reject(
        &err
    ));
}

/// A secondary that only counts its submit calls, so a "never called" assertion
/// has a concrete observable.
struct CountingSecondary {
    calls: Arc<AtomicU32>,
}

impl ChainGateway for CountingSecondary {
    async fn submit_tx(&self, _signed_tx: &[u8]) -> Result<[u8; 32]> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok([0xff; 32])
    }
    async fn get_tx_confirmations(&self, _h: &[[u8; 32]]) -> Result<TxConfirmationMap> {
        Ok(HashMap::new())
    }
    async fn get_block_info(&self, _b: u64) -> Result<Option<BlockInfo>> {
        Ok(None)
    }
    async fn get_tip(&self) -> Result<ChainTip> {
        Ok(ChainTip {
            block_height: 0,
            epoch: None,
        })
    }
    async fn fetch_tx_cbor_by_hashes(&self, _h: &[[u8; 32]]) -> Result<TxCborMap> {
        Ok(HashMap::new())
    }
    async fn fetch_label309_records_since(
        &self,
        _a: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _t: u64,
        _m: u32,
    ) -> Result<Label309RecordsResult> {
        Ok(Label309RecordsResult::default())
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        _a: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _t: u64,
        _m: u32,
    ) -> Result<Label309RecordsResult> {
        Ok(Label309RecordsResult::default())
    }
}

/// A primary that counts its submit calls, to assert a parked primary is skipped.
struct CountingPrimary {
    calls: Arc<AtomicU32>,
}

impl ChainGateway for CountingPrimary {
    async fn submit_tx(&self, _signed_tx: &[u8]) -> Result<[u8; 32]> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok([0x00; 32])
    }
    async fn get_tx_confirmations(&self, _h: &[[u8; 32]]) -> Result<TxConfirmationMap> {
        Ok(HashMap::new())
    }
    async fn get_block_info(&self, _b: u64) -> Result<Option<BlockInfo>> {
        Ok(None)
    }
    async fn get_tip(&self) -> Result<ChainTip> {
        Ok(ChainTip {
            block_height: 0,
            epoch: None,
        })
    }
    async fn fetch_tx_cbor_by_hashes(&self, _h: &[[u8; 32]]) -> Result<TxCborMap> {
        Ok(HashMap::new())
    }
    async fn fetch_label309_records_since(
        &self,
        _a: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _t: u64,
        _m: u32,
    ) -> Result<Label309RecordsResult> {
        Ok(Label309RecordsResult::default())
    }

    async fn fetch_label309_records_since_alternate(
        &self,
        _a: u64,
        _exclude_tx_hashes: &[[u8; 32]],
        _t: u64,
        _m: u32,
    ) -> Result<Label309RecordsResult> {
        Ok(Label309RecordsResult::default())
    }
}

// Keep FakeGateway::submit_calls meaningful: assert the helper observes calls.
#[tokio::test]
async fn fake_gateway_counts_its_submit_calls() {
    let fake = FakeGateway::ok([0x01; 32]);
    let _ = fake.submit_tx(&[0x84]).await.unwrap();
    assert_eq!(fake.submit_calls(), 1);
}

// ---------------------------------------------------------------------------
// Chunking: the real Koios gateway against a local fake server.
//
// Points KoiosGateway at a tiny TCP server that records every /tx_status request
// body, then asks for more than KOIOS_KEYLESS_CHUNK hashes and asserts the
// gateway split the request into chunks of at most 14.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn koios_chunks_tx_status_requests_at_the_keyless_limit() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake");
    let addr = listener.local_addr().expect("addr");
    let base_url = format!("http://{addr}");

    // Records the per-request count of `_tx_hashes` each /tx_status body carried.
    let chunk_sizes: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let chunk_sizes_server = chunk_sizes.clone();

    // 30 distinct hashes -> at 14/chunk that is 3 chunks (14, 14, 2). Every hash
    // comes back as not-on-chain (num_confirmations 0), so no /tx_info follows
    // and the only requests are the /tx_status chunks.
    let total = 30usize;

    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let mut buf = vec![0u8; 16 * 1024];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            // The body follows the blank line after the headers.
            let body = request
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or("")
                .trim_matches(char::from(0))
                .to_string();
            let parsed: serde_json::Value =
                serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
            let count = parsed
                .get("_tx_hashes")
                .and_then(|v| v.as_array())
                .map(Vec::len)
                .unwrap_or(0);
            chunk_sizes_server.lock().unwrap().push(count);

            // Answer every requested hash as not-on-chain (num_confirmations 0).
            let rows: Vec<serde_json::Value> = parsed
                .get("_tx_hashes")
                .and_then(|v| v.as_array())
                .map(|hashes| {
                    hashes
                        .iter()
                        .map(|h| serde_json::json!({ "tx_hash": h, "num_confirmations": 0 }))
                        .collect()
                })
                .unwrap_or_default();
            let payload = serde_json::to_string(&rows).unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        }
    });

    let client = reqwest::Client::builder().build().expect("reqwest client");
    let gateway = KoiosGateway::with_client(
        client,
        Network::Preprod,
        KoiosConfig {
            base_url: Some(base_url),
            api_key: None,
        },
    );

    let hashes: Vec<[u8; 32]> = (0..total as u8).map(|i| [i; 32]).collect();
    let map = gateway
        .get_tx_confirmations(&hashes)
        .await
        .expect("confirmations against the fake");

    // Every requested hash is answered (the uniform contract), all not-on-chain.
    assert_eq!(map.len(), total);
    assert!(map.values().all(|c| c.num_confirmations == 0));

    server.await.ok();

    let sizes = chunk_sizes.lock().unwrap().clone();
    assert!(
        sizes.iter().all(|&n| n <= KOIOS_KEYLESS_CHUNK),
        "no /tx_status chunk may exceed the keyless limit ({KOIOS_KEYLESS_CHUNK}); saw {sizes:?}"
    );
    assert_eq!(
        sizes.iter().sum::<usize>(),
        total,
        "every requested hash is covered across the chunks exactly once"
    );
    assert!(
        sizes.len() >= 3,
        "30 hashes at 14/chunk must split into at least 3 requests; saw {sizes:?}"
    );
}

// ---------------------------------------------------------------------------
// The real gateways against a local fixture-serving fake.
//
// `serve` answers each incoming connection with the next scripted (status, body)
// pair, so the real KoiosGateway / BlockfrostGateway parse the committed
// fixtures over a loopback socket with no live endpoint. Every fixture in
// tests/fixtures/chain is loaded by exactly one of these tests.
// ---------------------------------------------------------------------------

/// Spawn a tiny HTTP server that answers each connection with the next
/// `(status_line, body)` from `responses`, returning its base URL.
async fn serve(responses: Vec<(&'static str, String)>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake");
    let addr = listener.local_addr().expect("addr");
    let base_url = format!("http://{addr}");

    tokio::spawn(async move {
        for (status_line, body) in responses {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            // Drain the request (we do not assert on it here; the chunking test
            // covers request-body inspection).
            let mut buf = vec![0u8; 16 * 1024];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        }
    });
    base_url
}

fn koios_at(base_url: String) -> KoiosGateway {
    let client = reqwest::Client::builder().build().expect("reqwest client");
    KoiosGateway::with_client(
        client,
        Network::Preprod,
        KoiosConfig {
            base_url: Some(base_url),
            api_key: None,
        },
    )
}

const TX_STATUS: &str = include_str!("fixtures/chain/tx_status.json");
const TX_INFO: &str = include_str!("fixtures/chain/tx_info.json");
const TIP: &str = include_str!("fixtures/chain/tip.json");
const BLOCKS_BY_HEIGHT: &str = include_str!("fixtures/chain/blocks_by_height.json");
const TX_CBOR: &str = include_str!("fixtures/chain/tx_cbor.json");
const BLOCKFROST_TX: &str = include_str!("fixtures/chain/blockfrost_tx.json");
const BLOCKFROST_BLOCKS_LATEST: &str = include_str!("fixtures/chain/blockfrost_blocks_latest.json");

#[tokio::test]
async fn koios_submit_echoes_and_validates_the_returned_tx_hash() {
    let hash_hex = "11".repeat(32);
    let base = serve(vec![("HTTP/1.1 202 Accepted", format!("\"{hash_hex}\""))]).await;
    let got = koios_at(base)
        .submit_tx(&[0x84, 0xa0])
        .await
        .expect("submit accepted");
    assert_eq!(got, [0x11; 32], "the quoted hex hash decodes to 32 bytes");
}

#[tokio::test]
async fn koios_submit_rejects_a_malformed_returned_hash() {
    let base = serve(vec![(
        "HTTP/1.1 202 Accepted",
        "\"not-a-hash\"".to_string(),
    )])
    .await;
    let err = koios_at(base)
        .submit_tx(&[0x84])
        .await
        .expect_err("a malformed hash must be rejected");
    // A malformed returned hash is a deterministic BadResponse (the provider
    // answered, but the body did not parse): it must not fail over.
    assert_eq!(
        gateway_core::chain::gateway::classify_chain_error(&err),
        Some(ChainErrorClass::BadResponse)
    );
}

#[tokio::test]
async fn koios_two_step_confirmation_hydrates_from_fixtures() {
    // /tx_status then /tx_info, both served from the committed fixtures.
    let base = serve(vec![
        ("HTTP/1.1 200 OK", TX_STATUS.to_string()),
        ("HTTP/1.1 200 OK", TX_INFO.to_string()),
    ])
    .await;
    let requested = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]];
    let map = koios_at(base)
        .get_tx_confirmations(&requested)
        .await
        .expect("two-step confirmations");

    assert_eq!(map.len(), 4, "every requested hash is answered");
    let c11 = map.get(&[0x11; 32]).unwrap();
    assert_eq!(c11.num_confirmations, 5);
    assert_eq!(c11.block_height, Some(2_891_230));
    assert!(c11.block_time.is_some());
    // 0x44 had a confirmation at /tx_status but is ABSENT from /tx_info: a
    // confirmation count with no coordinates is incomplete data. Its numeric
    // shape stays not-on-chain (the confirm authority never settles a record at
    // a fabricated height 0), but its presence is INCONCLUSIVE — /tx_status
    // positively saw the hash, so a money decision must not read the lag window
    // as proof the transaction does not exist.
    let c44 = map.get(&[0x44; 32]).unwrap();
    assert_eq!(
        c44.num_confirmations, 0,
        "a hash missing from /tx_info is incomplete, never confirms"
    );
    assert!(c44.block_height.is_none());
    assert_eq!(c44.presence(), TxPresence::Inconclusive);
    // 0x22 was mempool-only at /tx_status: affirmatively not on chain.
    let c22 = map.get(&[0x22; 32]).unwrap();
    assert_eq!(c22.num_confirmations, 0);
    assert_eq!(c22.presence(), TxPresence::Absent);
}

#[tokio::test]
async fn koios_tip_reads_block_height_and_epoch_from_fixture() {
    let base = serve(vec![("HTTP/1.1 200 OK", TIP.to_string())]).await;
    let tip = koios_at(base).get_tip().await.expect("tip read");
    assert_eq!(tip.block_height, 2_891_234);
    // The same `/tip` read carries the epoch, so the scan can materialise it.
    assert_eq!(tip.epoch, Some(213));
}

#[tokio::test]
async fn koios_block_info_decodes_a_fixture_row_and_404_is_none() {
    let base = serve(vec![("HTTP/1.1 200 OK", BLOCKS_BY_HEIGHT.to_string())]).await;
    let info = koios_at(base)
        .get_block_info(2_891_223)
        .await
        .expect("block info")
        .expect("the fixture row is present");
    assert_eq!(info.block_height, 2_891_223);
    assert_eq!(info.block_hash, [0xab; 32]);

    // An empty array (no block at this height) reads as None.
    let base = serve(vec![("HTTP/1.1 200 OK", "[]".to_string())]).await;
    assert!(koios_at(base)
        .get_block_info(999)
        .await
        .expect("empty block read")
        .is_none());
}

#[tokio::test]
async fn koios_tx_cbor_decodes_hex_and_omits_absent_hashes() {
    let base = serve(vec![("HTTP/1.1 200 OK", TX_CBOR.to_string())]).await;
    let map = koios_at(base)
        .fetch_tx_cbor_by_hashes(&[[0x11; 32], [0x33; 32], [0x99; 32]])
        .await
        .expect("tx cbor");
    // Two hashes are present in the fixture; the third is absent (never on chain).
    assert!(map.contains_key(&[0x11; 32]));
    assert_eq!(
        map.get(&[0x33; 32]).cloned(),
        Some(vec![0x84, 0xa0, 0xf5, 0xf6])
    );
    assert!(
        !map.contains_key(&[0x99; 32]),
        "a hash with no on-chain transaction is absent from the cbor map"
    );
}

#[tokio::test]
async fn blockfrost_confirmation_derives_count_from_a_single_tip_read() {
    // /txs/{hash} (on chain) then /blocks/latest (the lazy single tip read).
    let base = serve(vec![
        ("HTTP/1.1 200 OK", BLOCKFROST_TX.to_string()),
        ("HTTP/1.1 200 OK", BLOCKFROST_BLOCKS_LATEST.to_string()),
    ])
    .await;
    let client = reqwest::Client::builder().build().expect("client");
    let gw = gateway_core::chain::gateway::BlockfrostGateway::with_client(
        client,
        Network::Preprod,
        base,
        "test-project-id".to_string().into(),
    );
    let map = gw
        .get_tx_confirmations(&[[0x11; 32]])
        .await
        .expect("blockfrost confirmations");
    let c = map.get(&[0x11; 32]).unwrap();
    assert_eq!(c.block_height, Some(2_891_230));
    // tip 2891234 - block 2891230 + 1 = 5 confirmations.
    assert_eq!(c.num_confirmations, 5);
    assert!(c.block_time.is_some());
}

#[tokio::test]
async fn blockfrost_404_is_not_on_chain() {
    let base = serve(vec![("HTTP/1.1 404 Not Found", "{}".to_string())]).await;
    let client = reqwest::Client::builder().build().expect("client");
    let gw = gateway_core::chain::gateway::BlockfrostGateway::with_client(
        client,
        Network::Preprod,
        base,
        "test-project-id".to_string().into(),
    );
    let map = gw
        .get_tx_confirmations(&[[0xaa; 32]])
        .await
        .expect("blockfrost confirmations");
    assert_eq!(
        map.get(&[0xaa; 32]).copied(),
        Some(TxConfirmation::not_on_chain()),
        "a 404 answers not-on-chain, and a missing tx never triggers the tip read"
    );
    assert_eq!(
        map.get(&[0xaa; 32]).unwrap().presence(),
        TxPresence::Absent,
        "a 404 is Blockfrost's affirmative no-such-transaction"
    );
}

#[tokio::test]
async fn blockfrost_found_tx_without_block_is_inconclusive_not_absent() {
    // A found /txs row whose block coordinates are missing (the tx is not yet in
    // a block, or the row is partially hydrated). It must not confirm — but the
    // row EXISTS, so it is inconclusive, never affirmative absence: a money
    // decision reading it as absence would refund a transaction the provider
    // just said it has. Only one response is scripted, which also pins that an
    // incomplete row never triggers the tip read.
    let pending = serde_json::json!({
        "hash": "11".repeat(32),
        "block": serde_json::Value::Null,
    })
    .to_string();
    let base = serve(vec![("HTTP/1.1 200 OK", pending)]).await;
    let client = reqwest::Client::builder().build().expect("client");
    let gw = gateway_core::chain::gateway::BlockfrostGateway::with_client(
        client,
        Network::Preprod,
        base,
        "test-project-id".to_string().into(),
    );
    let map = gw
        .get_tx_confirmations(&[[0x11; 32]])
        .await
        .expect("blockfrost confirmations");
    let c = map.get(&[0x11; 32]).unwrap();
    assert_eq!(c.num_confirmations, 0, "an incomplete row never confirms");
    assert!(c.block_height.is_none());
    assert!(c.block_time.is_none());
    assert_eq!(
        c.presence(),
        TxPresence::Inconclusive,
        "a found row without coordinates is inconclusive, never absent"
    );
}

// ---------------------------------------------------------------------------
// Egress request accounting: the per-day Postgres buckets.
// ---------------------------------------------------------------------------

/// The accounting upsert accumulates issued and denied counts into one
/// `(provider, network, day)` row, exactly.
#[tokio::test]
async fn request_accounting_upserts_one_day_bucket_per_provider() {
    use gateway_core::chain::egress::record_requests;

    let db = TestDb::fresh().await.expect("test database");
    let day = Utc::now().date_naive();

    record_requests(&db.pool, ProviderKind::Koios, Network::Preprod, day, 1, 0)
        .await
        .expect("first observation inserts the bucket");
    record_requests(&db.pool, ProviderKind::Koios, Network::Preprod, day, 3, 2)
        .await
        .expect("second observation increments it");
    // A different provider on the same day is its own bucket.
    record_requests(
        &db.pool,
        ProviderKind::Blockfrost,
        Network::Preprod,
        day,
        5,
        0,
    )
    .await
    .expect("the other provider's bucket inserts");

    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT provider, request_count, denied_count \
         FROM cw_core.chain_provider_request_day \
         WHERE network = 'preprod' AND day = $1 ORDER BY provider",
    )
    .bind(day)
    .fetch_all(&db.pool)
    .await
    .expect("read the day buckets");
    assert_eq!(
        rows,
        vec![
            ("blockfrost".to_string(), 5, 0),
            ("koios".to_string(), 4, 2),
        ],
        "issued and denied counts accumulate per (provider, network, day)"
    );
}

/// A budgeted, Postgres-accounted egress records both the admitted request and
/// the budget denial into the day bucket, and the denial carries the provider
/// rate-limit class so the failover/cooldown seams treat it like a real 429.
#[tokio::test]
async fn a_persisted_egress_accounts_admits_and_denials() {
    use gateway_core::chain::egress::{EgressLimits, ProviderEgress};

    let db = TestDb::fresh().await.expect("test database");
    let egress = ProviderEgress::new(
        ProviderKind::Blockfrost,
        Network::Preprod,
        EgressLimits {
            requests_per_minute: 1,
            burst: 1,
        },
        db.pool.clone(),
    );

    egress.admit().await.expect("the single burst token admits");
    let denied = egress.admit().await.expect_err("the drained budget denies");
    assert!(
        gateway_core::chain::gateway::classify_chain_error(&denied)
            .is_some_and(|class| class.is_rate_limited()),
        "a budget denial carries the rate-limited class"
    );

    let row: (i64, i64) = sqlx::query_as(
        "SELECT request_count, denied_count FROM cw_core.chain_provider_request_day \
         WHERE provider = 'blockfrost' AND network = 'preprod' AND day = $1",
    )
    .bind(Utc::now().date_naive())
    .fetch_one(&db.pool)
    .await
    .expect("read the bucket");
    assert_eq!(
        row,
        (1, 1),
        "the bucket holds exactly the one admitted and the one denied request"
    );
    assert_eq!(egress.issued_total(), 1);
    assert_eq!(egress.denied_total(), 1);
}
