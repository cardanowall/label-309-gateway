//! Conformance: drive the PUBLISHED Rust SDK against a booted gateway.
//!
//! Gated behind the `live` feature. The suite BOOTS the in-repo gateway over a
//! fresh database ([`BootedGateway::start`]) and drives it with the exact
//! PUBLISHED `cardanowall` client (a registry dependency pinned to `=0.8.0`), so
//! any drift in the gateway's wire shape surfaces as a deserialize failure in the
//! real client a third party would install.
//!
//! The deep flow proves the wire guarantees the published Rust SDK can observe:
//!
//! - The quote `amount`/`currency` decode (the defect this server fixes: the SDK's
//!   `QuoteResponse` requires both, and the gateway now emits them additively).
//! - Exactly-once publish: a fresh publish is 202 (`dedup_hit == false`) and a
//!   re-publish of the identical record bytes is 200 (`dedup_hit == true`), with
//!   the balance debited exactly once.
//! - The records list envelope and the single-record read after a stub
//!   confirmation, including the owner-only `account_id` projection.
//! - The balance read as a decimal string.
//!
//! The chain side is stubbed ([`BootedGateway::stub_confirm`]); the one live
//! preprod leg lives in the gate, not here.

#![cfg(feature = "live")]

use cardanowall::client::types::{PublishInput, QuoteInput, RecordsListInput};
use cardanowall::client::{Label309Client, Label309ClientConfig};
use cardanowall::poe_standard::{encode_poe_record, ItemEntry, PoeRecord};
use conformance::BootedGateway;

/// Build a published client pointed at the gateway under test with a seeded key.
///
/// The published client holds a non-`Send` transport, so it must be constructed
/// and used inside the same blocking thread; callers build it within the
/// `spawn_blocking` closure rather than moving it across an await.
fn client(base_url: String, api_key: String) -> Label309Client {
    Label309Client::new(Label309ClientConfig {
        base_url: Some(base_url),
        api_key: Some(api_key),
    })
    .expect("published client constructs with a base_url")
}

/// A minimal valid open Label 309 record with a per-seed unique hash, so two
/// calls produce distinct record bytes (and distinct dedup keys).
fn open_record(seed: u8) -> Vec<u8> {
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), vec![seed; 32])],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    };
    encode_poe_record(&record).expect("encode record")
}

/// Run one published-client call on a blocking thread (the transport is not
/// `Send`), returning its result.
///
/// The client is configured with the gateway's data-plane base URL (the served
/// host plus the `/api/v1` version segment): the published SDK carries the API
/// version in the configured base URL and appends only bare resource suffixes.
async fn on_client<T, F>(gw: &BootedGateway, api_key: &str, f: F) -> T
where
    F: FnOnce(Label309Client) -> T + Send + 'static,
    T: Send + 'static,
{
    let base = gw.data_plane_base_url();
    let key = api_key.to_string();
    tokio::task::spawn_blocking(move || f(client(base, key)))
        .await
        .expect("join the blocking client task")
}

/// The published SDK reads the balance as a decimal string; a wire regression
/// breaks the decode here.
#[tokio::test(flavor = "multi_thread")]
async fn published_client_reads_the_balance() {
    let gw = BootedGateway::start().await.expect("boot the gateway");
    let tenant = gw
        .seed_tenant("ck_live_", &["account:read"], 5_000_000)
        .await
        .expect("seed a tenant");

    let balance = on_client(&gw, &tenant.api_key, |c| c.account().balance())
        .await
        .expect("balance request");
    assert_eq!(
        balance.balance_usd_micros, "5000000",
        "the seeded opening balance round-trips through the published decoder"
    );

    gw.shutdown().await;
}

/// The published SDK requires the `{ object, data, has_more, next_cursor, url }`
/// list envelope; a wire regression in the envelope breaks the decode here.
#[tokio::test(flavor = "multi_thread")]
async fn published_client_lists_records() {
    let gw = BootedGateway::start().await.expect("boot the gateway");
    let tenant = gw
        .seed_tenant("ck_live_", &["poe:read"], 0)
        .await
        .expect("seed a tenant");

    let page = on_client(&gw, &tenant.api_key, |c| c.records().list(None))
        .await
        .expect("records list request");
    assert_eq!(page.object, "list", "the list envelope decodes");

    gw.shutdown().await;
}

/// The full quote -> publish -> dedup -> confirm -> read -> balance flow, every
/// step driven by the PUBLISHED Rust SDK.
///
/// This is the heart of the conformance gate: it proves the quote
/// `amount`/`currency` decode against the published deserializer, the 202-vs-200
/// dedup signal (exactly-once publish), and the records read surface after a stub
/// confirmation, all through the real published deserializers.
#[tokio::test(flavor = "multi_thread")]
async fn published_client_quote_publish_records_balance_flow() {
    let gw = BootedGateway::start().await.expect("boot the gateway");
    let tenant = gw
        .seed_tenant(
            "ck_live_",
            &["poe:create", "poe:read", "account:read"],
            50_000_000,
        )
        .await
        .expect("seed a tenant");

    let record = open_record(0xa1);

    // --- Quote. The published QuoteResponse requires amount + currency, the
    // exact additive fields. A missing field would fail this decode. ---
    let quote = on_client(&gw, &tenant.api_key, {
        let record_len = record.len() as u64;
        move |c| {
            c.poe().quote(&QuoteInput {
                record_bytes: record_len,
                recipient_count: 0,
                file_bytes_total: 0,
            })
        }
    })
    .await
    .expect("quote request");
    assert!(!quote.quote_id.is_empty(), "the quote carries an id");
    assert_eq!(quote.currency, "USD", "the quote currency decodes as USD");
    // The amount is a decimal string the SDK can promote to a big integer; the
    // conformance pricing yields COGS 1_000_000 + 25% margin = 1_250_000.
    assert_eq!(
        quote.amount, "1250000",
        "the quote amount decodes as the priced total"
    );

    // --- Publish (fresh): 202, dedup_hit == false, one debit. ---
    let publish = on_client(&gw, &tenant.api_key, {
        let record = record.clone();
        let quote_id = quote.quote_id.clone();
        move |c| {
            c.poe().publish(&PublishInput {
                record,
                quote_id,
                signatures: None,
                idempotency_key: None,
            })
        }
    })
    .await
    .expect("fresh publish request");
    assert!(
        !publish.dedup_hit,
        "a fresh publish is 202 (dedup_hit == false)"
    );
    assert!(
        publish.id.starts_with("poe_"),
        "the publish returns a wire id"
    );
    assert_eq!(publish.items_count, 1, "one content item");
    assert_eq!(
        publish.conformance_profile, "core",
        "an open unsigned record is the core profile"
    );
    assert_eq!(
        publish.balance_after_usd_micros, "48750000",
        "the balance is debited exactly once (50_000_000 - 1_250_000)"
    );
    let fresh_id = publish.id.clone();

    // --- Publish again (identical bytes, a NEW quote): 200, dedup_hit == true,
    // NO second debit. ---
    let quote2 = on_client(&gw, &tenant.api_key, {
        let record_len = record.len() as u64;
        move |c| {
            c.poe().quote(&QuoteInput {
                record_bytes: record_len,
                recipient_count: 0,
                file_bytes_total: 0,
            })
        }
    })
    .await
    .expect("second quote");
    let republish = on_client(&gw, &tenant.api_key, {
        let record = record.clone();
        let quote_id = quote2.quote_id.clone();
        move |c| {
            c.poe().publish(&PublishInput {
                record,
                quote_id,
                signatures: None,
                idempotency_key: None,
            })
        }
    })
    .await
    .expect("re-publish request");
    assert!(
        republish.dedup_hit,
        "re-publishing identical bytes is 200 (dedup_hit == true)"
    );
    assert_eq!(
        republish.id, fresh_id,
        "the dedup hit returns the prior record's id"
    );
    assert_eq!(
        republish.balance_after_usd_micros, "48750000",
        "the dedup hit charges nothing more (one debit total)"
    );

    // --- Stub-confirm the published record, then read it back through the SDK. ---
    let record_uuid = decode_poe_id(&fresh_id).expect("decode the wire id");
    let tx_hex = gw
        .stub_confirm(record_uuid, 4_793_566)
        .await
        .expect("stub confirm");

    // records.list returns the anchored record in the list envelope.
    let page = on_client(&gw, &tenant.api_key, |c| {
        c.records().list(Some(&RecordsListInput::default()))
    })
    .await
    .expect("list after confirm");
    assert_eq!(page.object, "list");
    assert!(
        page.data.iter().any(|r| r.tx_hash == tx_hex),
        "the confirmed record appears in the owner's list"
    );

    // records.get returns the single record with the owner-only account_id.
    let resource = on_client(&gw, &tenant.api_key, {
        let tx = tx_hex.clone();
        move |c| c.records().get(&tx)
    })
    .await
    .expect("get after confirm");
    assert_eq!(resource.tx_hash, tx_hex);
    assert_eq!(resource.item_count, 1);
    assert!(
        resource.block_height.is_some(),
        "the anchored record carries a block height"
    );
    assert!(
        resource.account_id.is_some(),
        "the owner sees the owner-only account_id"
    );

    // --- Balance read confirms the single debit through the published decoder. ---
    let balance = on_client(&gw, &tenant.api_key, |c| c.account().balance())
        .await
        .expect("balance after publish");
    assert_eq!(
        balance.balance_usd_micros, "48750000",
        "the published balance decoder agrees with the publish response"
    );

    gw.shutdown().await;
}

/// An anonymous reader (no bearer) never sees a record's owner account id, and
/// only sees chain-anchored rows.
#[tokio::test(flavor = "multi_thread")]
async fn anonymous_reader_sees_no_owner_account() {
    let gw = BootedGateway::start().await.expect("boot the gateway");
    let tenant = gw
        .seed_tenant("ck_live_", &["poe:create", "poe:read"], 50_000_000)
        .await
        .expect("seed a tenant");

    let record = open_record(0xb2);
    let record_id = gw.seed_record(&tenant, &record).await.expect("seed record");
    let tx_hex = gw
        .stub_confirm(record_id, 4_793_500)
        .await
        .expect("stub confirm");

    // An anonymous client (no api key) reads the public record but never its
    // owner. The client holds a non-`Send` transport, so it is constructed inside
    // the blocking thread rather than moved across the await.
    let base = gw.data_plane_base_url();
    let tx = tx_hex.clone();
    let resource = tokio::task::spawn_blocking(move || {
        let anon = Label309Client::new(Label309ClientConfig {
            base_url: Some(base),
            api_key: None,
        })
        .expect("anon client");
        anon.records().get(&tx)
    })
    .await
    .expect("join")
    .expect("anon get");
    assert_eq!(resource.tx_hash, tx_hex);
    assert!(
        resource.account_id.is_none(),
        "an anonymous reader never sees the owner account id"
    );

    gw.shutdown().await;
}

/// Decode a `poe_<crockford>` wire id back to its UUID (the same codec the
/// gateway uses), so the harness can address the record by its durable id for the
/// stub confirmation.
fn decode_poe_id(wire: &str) -> Option<uuid::Uuid> {
    let body = wire.strip_prefix("poe_")?;
    if body.len() != 26 {
        return None;
    }
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("0123456789abcdefghjkmnpqrstvwxyz");
    let encoding = spec.encoding().ok()?;
    let bytes = encoding.decode(body.as_bytes()).ok()?;
    let arr: [u8; 16] = bytes.try_into().ok()?;
    Some(uuid::Uuid::from_bytes(arr))
}
