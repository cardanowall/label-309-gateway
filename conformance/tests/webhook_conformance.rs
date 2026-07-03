//! Webhook conformance: the published webhook surface driven against a booted
//! gateway and a harness-local receiver sink.
//!
//! These scenarios (W1-W13) drive the account-scoped webhook routes and the
//! operator firehose over real HTTP, inject events through the harness seam, drain
//! the fan-out and delivery workers in-process, and assert on what a controllable
//! loopback receiver actually received. They prove the delivery contract a third
//! party relies on end to end:
//!
//!   - registration / lifecycle (W1), happy-path signed delivery (W2), receiver
//!     signature verification (W3), retry-on-500 with the same id/body (W4),
//!     dedupe-on-replay (W5), per-subject ordering with no cross-subscription
//!     head-of-line blocking (W6);
//!   - rotation-window dual-sign and explicit commit (W7), sustained-failure
//!     auto-disable and redrive (W8), operator firehose across two accounts (W9);
//!   - the presence-based mid-stream cutoff in all four facets (W10), fan-out
//!     crash dedupe (W11), strict invalid-signature rejection (W12), and the SSRF
//!     redirect/deny guard (W13).
//!
//! Gated behind the `live` feature: the suite boots a real gateway over a real
//! Postgres. The receiver sink is inherently harness-local (the suite must observe
//! what was delivered), reached through the egress test seam without weakening the
//! production range-block.

#![cfg(feature = "live")]

use cardanowall::verifier::fetch::{
    assert_webhook_url_safe, AssertWebhookUrlSafeOptions, ResolveHost, ResolvedRecord,
};
use conformance::receiver::ReceiverSink;
use conformance::BootedGateway;
use serde_json::{json, Value};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// A small HTTP client over the booted gateway (the published SDK does not cover
// the webhook or control surface, so these routes are driven directly).
// ---------------------------------------------------------------------------

/// The response of one HTTP call: the status and the parsed JSON body (or `Null`
/// for an empty body).
struct Resp {
    status: u16,
    body: Value,
}

impl Resp {
    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// An authenticated HTTP client bound to one gateway base URL and one bearer.
struct Client {
    http: reqwest::Client,
    base: String,
    bearer: String,
}

impl Client {
    fn new(base: &str, bearer: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: base.to_string(),
            bearer: bearer.to_string(),
        }
    }

    async fn send(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Resp {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.bearer);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.expect("request sends");
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Resp { status, body }
    }

    async fn post(&self, path: &str, body: Value) -> Resp {
        self.send(reqwest::Method::POST, path, Some(body)).await
    }

    async fn get(&self, path: &str) -> Resp {
        self.send(reqwest::Method::GET, path, None).await
    }

    async fn patch(&self, path: &str, body: Value) -> Resp {
        self.send(reqwest::Method::PATCH, path, Some(body)).await
    }

    async fn delete(&self, path: &str) -> Resp {
        self.send(reqwest::Method::DELETE, path, None).await
    }
}

/// Register an account-scoped subscription against `url`, returning its
/// `(id, one-time secret)`. The secret is shown exactly once at create.
async fn register_endpoint(
    client: &Client,
    url: &str,
    enabled_events: &[&str],
) -> (String, String) {
    let resp = client
        .post(
            "/api/v1/webhooks",
            json!({ "url": url, "enabled_events": enabled_events }),
        )
        .await;
    assert_eq!(resp.status, 201, "register returns 201: {:?}", resp.body);
    let id = resp.body["id"].as_str().expect("endpoint id").to_string();
    let secret = resp.body["secret"]
        .as_str()
        .expect("the secret is shown once at create")
        .to_string();
    (id, secret)
}

/// Drain fan-out then run a delivery pass, re-arming a still-pending row to due so
/// a jittered backoff does not stall a single-pass assertion.
async fn fanout_then_deliver(gw: &BootedGateway, endpoint_id: &str) {
    gw.run_fanout().await.expect("fan-out");
    let id = Uuid::parse_str(endpoint_id).expect("endpoint uuid");
    gw.rearm_pending(id).await.expect("re-arm");
    gw.run_delivery().await.expect("deliver");
}

// ---------------------------------------------------------------------------
// W1 — registration, list (secret shown once), pause/resume, delete.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w1_registration_lifecycle() {
    let gw = BootedGateway::start().await.expect("boot");
    let tenant = gw
        .seed_tenant("cfm_", &["webhooks:read", "webhooks:write"], 0)
        .await
        .expect("tenant");
    let client = Client::new(&gw.base_url, &tenant.api_key);

    // Register: 201 with the secret shown exactly once.
    let (id, secret) = register_endpoint(&client, "https://example.com/hook", &[]).await;
    assert!(
        secret.starts_with("whsec_"),
        "the minted secret is returned"
    );

    // List: the endpoint appears, with a fingerprint but NEVER the secret.
    let list = client.get("/api/v1/webhooks").await;
    assert_eq!(list.status, 200);
    let items = list.body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "the registered endpoint is listed");
    assert!(
        items[0].get("secret").is_none(),
        "a listing never includes the plaintext secret"
    );
    assert!(
        items[0]["secret_fp"].is_string(),
        "the fingerprint is shown for audit"
    );

    // Get-one: same write-only contract.
    let one = client.get(&format!("/api/v1/webhooks/{id}")).await;
    assert_eq!(one.status, 200);
    assert!(one.body.get("secret").is_none());
    assert_eq!(one.body["status"], "active");

    // Pause: the status flips to paused.
    let paused = client
        .patch(
            &format!("/api/v1/webhooks/{id}"),
            json!({ "status": "paused" }),
        )
        .await;
    assert_eq!(paused.status, 200);
    assert_eq!(paused.body["status"], "paused");

    // Resume: back to active.
    let resumed = client
        .patch(
            &format!("/api/v1/webhooks/{id}"),
            json!({ "status": "active" }),
        )
        .await;
    assert_eq!(resumed.status, 200);
    assert_eq!(resumed.body["status"], "active");

    // Delete: soft-deletes; a follow-up read is 404.
    let deleted = client.delete(&format!("/api/v1/webhooks/{id}")).await;
    assert!(deleted.is_success(), "delete succeeds: {}", deleted.status);
    let gone = client.get(&format!("/api/v1/webhooks/{id}")).await;
    assert_eq!(gone.status, 404, "a deleted endpoint reads 404");

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W2 / W3 — happy path: one signed POST the receiver can verify.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w2_w3_happy_path_signed_delivery_verifies() {
    let gw = BootedGateway::start().await.expect("boot");
    let tenant = gw
        .seed_tenant("cfm_", &["webhooks:read", "webhooks:write"], 0)
        .await
        .expect("tenant");
    let client = Client::new(&gw.base_url, &tenant.api_key);

    let sink = ReceiverSink::scripted(vec![200]);
    let (endpoint_id, secret) = register_endpoint(&client, &sink.url(), &[]).await;

    // Inject a record event under the account and drive the workers.
    let record = gw
        .seed_record(&tenant, b"w2-record-bytes")
        .await
        .expect("record");
    gw.append_poe_event(record, "confirmed", json!({ "status": "confirmed" }))
        .await
        .expect("append");
    fanout_then_deliver(&gw, &endpoint_id).await;

    let got = sink.deliveries();
    assert_eq!(got.len(), 1, "exactly one signed delivery arrives");
    let delivered = &got[0];

    // W3: the receiver recomputes the HMAC over "{t}.{body}" and matches the v1.
    assert!(
        delivered.signature_valid_under(&[secret.as_bytes()]),
        "the delivery signature validates under the registered secret"
    );
    // The per-delivery Webhook-Id binds the endpoint, and the envelope carries the
    // projected wire type.
    let webhook_id = delivered.webhook_id().expect("webhook id header");
    assert!(
        webhook_id.contains(&endpoint_id),
        "the Webhook-Id is per-delivery (carries the endpoint id)"
    );
    assert!(
        delivered.body.contains("poe_status_changed"),
        "the envelope carries the projected wire type"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W4 — retry-on-500: the same id/body redelivered until a 2xx.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w4_retry_on_500_then_succeeds_with_same_id_and_body() {
    let gw = BootedGateway::start().await.expect("boot");
    let tenant = gw
        .seed_tenant("cfm_", &["webhooks:read", "webhooks:write"], 0)
        .await
        .expect("tenant");
    let client = Client::new(&gw.base_url, &tenant.api_key);

    // Three 500s then a 200.
    let sink = ReceiverSink::scripted(vec![500, 500, 500, 200]);
    let (endpoint_id, _secret) = register_endpoint(&client, &sink.url(), &[]).await;

    let record = gw
        .seed_record(&tenant, b"w4-record-bytes")
        .await
        .expect("record");
    gw.append_poe_event(record, "confirmed", json!({}))
        .await
        .expect("append");
    gw.run_fanout().await.expect("fan-out");

    // Drive delivery passes, re-arming the still-pending row between passes, until
    // it is delivered (full jitter means a single pass might retry, so bound it).
    let endpoint_uuid = Uuid::parse_str(&endpoint_id).unwrap();
    let mut delivered = false;
    for _ in 0..8 {
        gw.run_delivery().await.expect("deliver");
        let state = delivery_state(&gw, endpoint_uuid).await;
        if state == "delivered" {
            delivered = true;
            break;
        }
        gw.rearm_pending(endpoint_uuid).await.expect("re-arm");
    }
    assert!(delivered, "the retry after the 500s eventually succeeds");

    let got = sink.deliveries();
    assert!(
        got.len() >= 2,
        "at least one 500 attempt and the 200 attempt"
    );
    // Every attempt reused the same Webhook-Id and the same frozen body.
    let first_id = got[0].webhook_id().expect("id");
    let last = got.last().unwrap();
    assert_eq!(
        last.webhook_id().expect("id"),
        first_id,
        "a retry reuses the same Webhook-Id"
    );
    assert_eq!(last.body, got[0].body, "a retry signs the same frozen body");

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W5 — dedupe-on-replay: an at-least-once double-deliver carries one logical id.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w5_dedupe_on_replay_one_logical_id() {
    let gw = BootedGateway::start().await.expect("boot");
    let tenant = gw
        .seed_tenant("cfm_", &["webhooks:read", "webhooks:write"], 0)
        .await
        .expect("tenant");
    let client = Client::new(&gw.base_url, &tenant.api_key);

    // A receiver that answers the FIRST delivery with a 500 but RECORDS it, then
    // 200s. Our side retries (a double-deliver of the same logical event); the
    // receiver dedupes on the identical Webhook-Id.
    let sink = ReceiverSink::scripted(vec![500, 200]);
    let (endpoint_id, _secret) = register_endpoint(&client, &sink.url(), &[]).await;

    let record = gw
        .seed_record(&tenant, b"w5-record-bytes")
        .await
        .expect("record");
    gw.append_poe_event(record, "confirmed", json!({}))
        .await
        .expect("append");
    gw.run_fanout().await.expect("fan-out");

    let endpoint_uuid = Uuid::parse_str(&endpoint_id).unwrap();
    for _ in 0..6 {
        gw.run_delivery().await.expect("deliver");
        if delivery_state(&gw, endpoint_uuid).await == "delivered" {
            break;
        }
        gw.rearm_pending(endpoint_uuid).await.expect("re-arm");
    }

    let got = sink.deliveries();
    assert!(got.len() >= 2, "the event was delivered more than once");
    // Every physical delivery carries the SAME Webhook-Id: a receiver dedupes them
    // to one logical event.
    let ids: std::collections::HashSet<&str> = got.iter().filter_map(|d| d.webhook_id()).collect();
    assert_eq!(
        ids.len(),
        1,
        "every at-least-once redelivery shares one logical Webhook-Id"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W6 — per-subject ordering, no cross-subscription head-of-line blocking.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w6_per_subject_ordering_no_cross_subscription_hol() {
    let gw = BootedGateway::start().await.expect("boot");
    let tenant = gw
        .seed_tenant("cfm_", &["webhooks:read", "webhooks:write"], 0)
        .await
        .expect("tenant");
    let client = Client::new(&gw.base_url, &tenant.api_key);

    // Two receivers: the first is slow (it 500s once on the first attempt, holding
    // its own subject's frontier back for a beat), the second always 200s.
    let slow = ReceiverSink::scripted(vec![500, 200, 200, 200]);
    let fast = ReceiverSink::scripted(vec![200]);
    let (slow_id, slow_secret) = register_endpoint(&client, &slow.url(), &[]).await;
    let (fast_id, _) = register_endpoint(&client, &fast.url(), &[]).await;

    // One subject, three ordered events (seq 1,2,3).
    let record = gw
        .seed_record(&tenant, b"w6-record-bytes")
        .await
        .expect("record");
    for status in ["submitted", "confirmed", "confirmed"] {
        gw.append_poe_event(record, status, json!({}))
            .await
            .expect("append");
    }
    gw.run_fanout().await.expect("fan-out");

    // Drive both subscriptions to completion, re-arming between passes.
    let slow_uuid = Uuid::parse_str(&slow_id).unwrap();
    let fast_uuid = Uuid::parse_str(&fast_id).unwrap();
    for _ in 0..12 {
        gw.run_delivery().await.expect("deliver");
        gw.rearm_pending(slow_uuid).await.expect("re-arm slow");
        gw.rearm_pending(fast_uuid).await.expect("re-arm fast");
        if slow.count() >= 4 && fast.count() >= 3 {
            break;
        }
    }

    // The slow subscription saw all three events in subject_seq order (the seq is in
    // the Webhook-Id), even though its first attempt 500'd.
    let slow_seqs = delivered_seqs(&slow, &slow_secret);
    assert_eq!(
        slow_seqs,
        vec![1, 2, 3],
        "the slow subscription delivers in seq order despite an early 500"
    );

    // The fast subscription is unaffected by the slow one (no cross-subscription
    // head-of-line blocking): it received all three quickly.
    assert_eq!(
        fast.count(),
        3,
        "the fast subscription is not blocked by the slow one"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W7 — rotation window dual-sign and explicit commit.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w7_rotation_window_dual_sign_then_commit() {
    let gw = BootedGateway::start().await.expect("boot");
    let tenant = gw
        .seed_tenant("cfm_", &["webhooks:read", "webhooks:write"], 0)
        .await
        .expect("tenant");
    let client = Client::new(&gw.base_url, &tenant.api_key);

    let sink = ReceiverSink::scripted(vec![200]);
    let (endpoint_id, primary) = register_endpoint(&client, &sink.url(), &[]).await;

    // Open the rotation window: mint a successor secret (shown once).
    let rotate = client
        .post(
            &format!("/api/v1/webhooks/{endpoint_id}/rotate-secret"),
            json!({}),
        )
        .await;
    assert_eq!(rotate.status, 200, "rotate-secret opens the window");
    let successor = rotate.body["secret_next"]
        .as_str()
        .expect("the successor secret is shown once")
        .to_string();
    assert!(
        rotate.body["secret_next_fp"].is_string(),
        "both fingerprints listed during the window"
    );

    // A delivery during the window carries TWO v1 values, one per active secret;
    // EITHER secret validates it.
    let record = gw
        .seed_record(&tenant, b"w7-record-bytes")
        .await
        .expect("record");
    gw.append_poe_event(record, "confirmed", json!({}))
        .await
        .expect("append");
    fanout_then_deliver(&gw, &endpoint_id).await;

    let during = sink.deliveries();
    assert_eq!(during.len(), 1);
    assert_eq!(
        during[0].signature_v1s().len(),
        2,
        "dual-signed: one v1 per active secret"
    );
    assert!(
        during[0].signature_valid_under(&[primary.as_bytes()]),
        "the primary validates during the window"
    );
    assert!(
        during[0].signature_valid_under(&[successor.as_bytes()]),
        "the successor validates during the window"
    );

    // Commit: the successor is promoted; the window closes.
    let commit = client
        .post(
            &format!("/api/v1/webhooks/{endpoint_id}/rotate-secret/commit"),
            json!({}),
        )
        .await;
    assert!(commit.is_success(), "commit promotes the successor");

    // A delivery after commit carries ONE v1, validated by the successor (now
    // primary); the OLD primary no longer validates.
    let record2 = gw
        .seed_record(&tenant, b"w7-record-bytes-2")
        .await
        .expect("record");
    gw.append_poe_event(record2, "confirmed", json!({}))
        .await
        .expect("append");
    fanout_then_deliver(&gw, &endpoint_id).await;

    let after = sink.deliveries();
    let last = after.last().unwrap();
    assert_eq!(
        last.signature_v1s().len(),
        1,
        "after commit the header carries one v1"
    );
    assert!(
        last.signature_valid_under(&[successor.as_bytes()]),
        "the promoted secret validates after commit"
    );
    assert!(
        !last.signature_valid_under(&[primary.as_bytes()]),
        "the old primary no longer validates after commit"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W8 — sustained failure auto-disables, then redrive after re-enable.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w8_auto_disable_then_redrive_after_reenable() {
    let gw = BootedGateway::start().await.expect("boot");
    let tenant = gw
        .seed_tenant("cfm_", &["webhooks:read", "webhooks:write"], 0)
        .await
        .expect("tenant");
    let client = Client::new(&gw.base_url, &tenant.api_key);

    // An endpoint that always 500s. Drive deliveries to exhaustion across the
    // default budget; each delivery's attempts are capped to 1 so it exhausts in
    // one pass, and the auto-disable budget (20 consecutive) is reached over 20
    // distinct events. To keep the test fast, force the per-delivery max_attempts
    // to 1 and drive exactly the budget.
    let sink = ReceiverSink::scripted(vec![500]);
    let (endpoint_id, _secret) = register_endpoint(&client, &sink.url(), &[]).await;
    let endpoint_uuid = Uuid::parse_str(&endpoint_id).unwrap();

    // Drive 20 distinct events, each capped to one attempt, each exhausting.
    let mut last_failed_delivery = None;
    for i in 0..20 {
        let record = gw
            .seed_record(&tenant, format!("w8-{i}").as_bytes())
            .await
            .expect("record");
        gw.append_poe_event(record, "confirmed", json!({}))
            .await
            .expect("append");
        gw.run_fanout().await.expect("fan-out");
        cap_attempts_to_one(&gw, endpoint_uuid).await;
        gw.rearm_pending(endpoint_uuid).await.expect("re-arm");
        gw.run_delivery().await.expect("deliver");
        last_failed_delivery = Some(record);
    }

    // The endpoint auto-disabled after the consecutive-failure budget.
    let one = client.get(&format!("/api/v1/webhooks/{endpoint_id}")).await;
    assert_eq!(
        one.body["status"], "disabled",
        "the budget auto-disables it"
    );
    assert_eq!(one.body["disabled_reason"], "consecutive_failures");

    // A `webhook_endpoint_disabled` event was emitted on the account subject.
    let disabled_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.subject_event \
         WHERE subject_kind = 'account' AND subject_id = $1 \
           AND event_type = 'webhook.endpoint_disabled'",
    )
    .bind(tenant.account_id.to_string())
    .fetch_one(&gw.pool)
    .await
    .expect("count disable events");
    assert_eq!(
        disabled_events, 1,
        "exactly one auto-disable event is emitted"
    );

    // The deliveries list (the DLQ) shows the failed deliveries.
    let dlq = client
        .get(&format!("/api/v1/webhooks/{endpoint_id}/deliveries"))
        .await;
    let items = dlq.body["items"].as_array().expect("deliveries");
    let failed: Vec<&Value> = items.iter().filter(|d| d["state"] == "failed").collect();
    assert!(
        !failed.is_empty(),
        "the dead-letter view lists failed deliveries"
    );
    let dead_id = failed[0]["id"].as_str().expect("delivery id").to_string();

    // Re-enable resets the failure budget; the endpoint is active again.
    let reenable = client
        .patch(
            &format!("/api/v1/webhooks/{endpoint_id}"),
            json!({ "status": "active" }),
        )
        .await;
    assert_eq!(
        reenable.body["status"], "active",
        "re-enable clears disabled"
    );

    // Redrive a dead-letter: it goes back to pending without losing the attempts.
    let redrive = client
        .post(
            &format!("/api/v1/webhooks/{endpoint_id}/deliveries/{dead_id}/retry"),
            json!({}),
        )
        .await;
    assert!(redrive.is_success(), "redrive re-arms a dead-letter");
    let state: String =
        sqlx::query_scalar("SELECT state FROM cw_core.webhook_delivery WHERE id = $1")
            .bind(Uuid::parse_str(&dead_id).unwrap())
            .fetch_one(&gw.pool)
            .await
            .expect("state");
    assert_eq!(state, "pending", "the redriven delivery is pending again");

    let _ = last_failed_delivery;
    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W9 — operator firehose receives events across two accounts under it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w9_operator_firehose_across_two_accounts() {
    let gw = BootedGateway::start().await.expect("boot");

    // One operator with a root credential; mint an operator token to drive the
    // control plane.
    let (operator_id, root_secret) = gw.seed_operator_root("cfm_").await.expect("operator root");
    let root = Client::new(&gw.base_url, &root_secret);
    let token_resp = root.post("/control/v1/operator/token", json!({})).await;
    assert_eq!(token_resp.status, 201, "root mints an operator token");
    let operator_token = token_resp.body["token"]
        .as_str()
        .expect("token")
        .to_string();
    let operator = Client::new(&gw.base_url, &operator_token);

    // Two accounts under the operator, each with its own record.
    let acct_one = seed_account_under(&gw, operator_id).await;
    let acct_two = seed_account_under(&gw, operator_id).await;

    // Register an operator-scoped firehose subscription pointed at the sink.
    let sink = ReceiverSink::scripted(vec![200]);
    let create = operator
        .post("/control/v1/webhooks", json!({ "url": sink.url() }))
        .await;
    assert_eq!(
        create.status, 201,
        "operator firehose registers: {:?}",
        create.body
    );
    let firehose_id = create.body["id"].as_str().expect("firehose id").to_string();

    // An event under EACH account fans out to the single operator firehose.
    let record_one = seed_record_for(&gw, operator_id, acct_one, b"w9-one").await;
    let record_two = seed_record_for(&gw, operator_id, acct_two, b"w9-two").await;
    gw.append_poe_event(record_one, "confirmed", json!({}))
        .await
        .expect("append one");
    gw.append_poe_event(record_two, "confirmed", json!({}))
        .await
        .expect("append two");
    gw.run_fanout().await.expect("fan-out");
    let firehose_uuid = Uuid::parse_str(&firehose_id).unwrap();
    gw.rearm_pending(firehose_uuid).await.expect("re-arm");
    gw.run_delivery().await.expect("deliver");
    // A second pass in case both deliveries did not drain in one.
    gw.rearm_pending(firehose_uuid).await.expect("re-arm");
    gw.run_delivery().await.expect("deliver");

    assert_eq!(
        sink.count(),
        2,
        "the firehose receives an event from each of the two accounts"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W10 — presence-based mid-stream cutoff (four facets, no crisp-seq assertion).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w10_mid_stream_cutoff_presence_based() {
    let gw = BootedGateway::start().await.expect("boot");
    let tenant = gw
        .seed_tenant("cfm_", &["webhooks:read", "webhooks:write"], 0)
        .await
        .expect("tenant");
    let client = Client::new(&gw.base_url, &tenant.api_key);
    let record = gw
        .seed_record(&tenant, b"w10-record")
        .await
        .expect("record");

    // (a) No backlog replay: event A is fanned out BEFORE any subscription exists.
    gw.append_poe_event(record, "submitted", json!({}))
        .await
        .expect("append A");
    gw.run_fanout().await.expect("fan-out A");

    // Now register the endpoint, AFTER A was fanned out.
    let sink = ReceiverSink::scripted(vec![200]);
    let (endpoint_id, _secret) = register_endpoint(&client, &sink.url(), &[]).await;
    let endpoint_uuid = Uuid::parse_str(&endpoint_id).unwrap();
    assert_eq!(
        endpoint_delivery_count(&gw, endpoint_uuid).await,
        0,
        "(a) an event fanned out before the subscription is never delivered (no replay)"
    );

    // (b) No miss: events fanned out after the subscription are all delivered.
    for _ in 0..3 {
        gw.append_poe_event(record, "confirmed", json!({}))
            .await
            .expect("append");
    }
    gw.run_fanout().await.expect("fan-out post");
    assert_eq!(
        endpoint_delivery_count(&gw, endpoint_uuid).await,
        3,
        "(b) every event fanned out after the subscription is delivered (no miss)"
    );

    // (d) Initial per-subject offset: the FIRST delivered seq for this subject is
    // above 1 (seq 1 of the subject was fanned out before the endpoint existed),
    // and the delivered run is contiguous — a valid mid-stream start, not a gap.
    let seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT subject_seq FROM cw_core.webhook_delivery \
         WHERE endpoint_id = $1 ORDER BY subject_seq",
    )
    .bind(endpoint_uuid)
    .fetch_all(&gw.pool)
    .await
    .expect("seqs");
    assert_eq!(
        seqs,
        vec![2, 3, 4],
        "(d) the first delivered seq is a valid mid-stream start (>1), contiguous run"
    );

    // (c) Committed-but-unfanned-at-create window: insert+commit an outbox row for a
    // FRESH subject, register a second endpoint, THEN drain. The presence-based
    // cutoff is fuzzy here — the row MAY or MAY NOT reach the new endpoint — but in
    // BOTH outcomes there is no wedge, no stall, and no replay of pre-X history. We
    // model "committed but unfanned at create" by registering the endpoint AFTER the
    // outbox row commits but BEFORE the drain, exactly the fuzzy window.
    let fresh = gw.seed_record(&tenant, b"w10-fresh").await.expect("record");
    gw.append_poe_event(fresh, "submitted", json!({}))
        .await
        .expect("append X (committed, not yet fanned)");
    let sink2 = ReceiverSink::scripted(vec![200]);
    let (endpoint2_id, _s2) = register_endpoint(&client, &sink2.url(), &[]).await;
    let endpoint2_uuid = Uuid::parse_str(&endpoint2_id).unwrap();
    // Drain: no wedge, no stall.
    gw.run_fanout().await.expect("fan-out (no wedge)");
    let x_deliveries = endpoint_delivery_count(&gw, endpoint2_uuid).await;
    assert!(
        x_deliveries <= 1,
        "(c) the committed-but-unfanned row delivers at most once (0 or 1), never replays history"
    );
    // A genuinely-later event for the same fresh subject is never missed.
    gw.append_poe_event(fresh, "confirmed", json!({}))
        .await
        .expect("append genuinely-later");
    gw.run_fanout().await.expect("fan-out later");
    assert!(
        endpoint_delivery_count(&gw, endpoint2_uuid).await > x_deliveries,
        "(c) a genuinely-later event is always delivered (no miss), whatever X's outcome"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W11 — fan-out crash dedupe: exactly-once across a mid-fan-out crash.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w11_fanout_crash_dedupe_exactly_once() {
    let gw = BootedGateway::start().await.expect("boot");
    let tenant = gw
        .seed_tenant("cfm_", &["webhooks:read", "webhooks:write"], 0)
        .await
        .expect("tenant");
    let client = Client::new(&gw.base_url, &tenant.api_key);
    let sink = ReceiverSink::scripted(vec![200]);
    let (endpoint_id, _secret) = register_endpoint(&client, &sink.url(), &[]).await;
    let endpoint_uuid = Uuid::parse_str(&endpoint_id).unwrap();

    let record = gw
        .seed_record(&tenant, b"w11-record")
        .await
        .expect("record");
    gw.append_poe_event(record, "confirmed", json!({}))
        .await
        .expect("append");

    // Simulate a crash between the per-subscription inserts and the fanned_out_at
    // stamp: claim the outbox row, explode it, then ROLL BACK (no commit). The
    // row stays un-fanned and the inserts are gone.
    let row = {
        let mut tx = gw.pool.begin().await.expect("begin");
        let batch = gateway_core::webhook::fanout::claim_unfanned(&mut tx, 10)
            .await
            .expect("claim");
        tx.commit().await.expect("commit claim");
        batch.into_iter().next().expect("one outbox row")
    };
    {
        let mut tx = gw.pool.begin().await.expect("begin");
        gateway_core::webhook::delivery::explode_outbox_row(&gw.pool, &mut tx, &row)
            .await
            .expect("explode");
        tx.rollback().await.expect("rollback (simulated crash)");
    }
    assert_eq!(
        endpoint_delivery_count(&gw, endpoint_uuid).await,
        0,
        "the rolled-back explode left no rows"
    );

    // Replay: the un-fanned row is re-claimed, the same dedupe_key DO-NOTHINGs, and
    // exactly one delivery row converges — no duplicate, no unique-violation wedge.
    gw.run_fanout().await.expect("replay 1");
    gw.run_fanout().await.expect("replay 2");
    assert_eq!(
        endpoint_delivery_count(&gw, endpoint_uuid).await,
        1,
        "exactly one delivery row after the crash replay (no duplicate, no wedge)"
    );

    // And it delivers exactly once over the wire.
    fanout_then_deliver(&gw, &endpoint_id).await;
    assert_eq!(
        sink.count(),
        1,
        "exactly one delivery POST after the replay"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W12 — invalid-signature: a strict receiver rejects, the gateway retries.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w12_invalid_signature_rejected_and_retried() {
    let gw = BootedGateway::start().await.expect("boot");
    let tenant = gw
        .seed_tenant("cfm_", &["webhooks:read", "webhooks:write"], 0)
        .await
        .expect("tenant");
    let client = Client::new(&gw.base_url, &tenant.api_key);

    // A strict receiver holding the WRONG secret: it recomputes the HMAC and
    // rejects every delivery whose v1 does not match (a 400). The gateway treats
    // the non-2xx as a transient failure and retries.
    let sink = ReceiverSink::strict_verify(vec![b"whsec_a_secret_the_gateway_never_used".to_vec()]);
    let (endpoint_id, secret) = register_endpoint(&client, &sink.url(), &[]).await;
    let endpoint_uuid = Uuid::parse_str(&endpoint_id).unwrap();

    let record = gw
        .seed_record(&tenant, b"w12-record")
        .await
        .expect("record");
    gw.append_poe_event(record, "confirmed", json!({}))
        .await
        .expect("append");
    gw.run_fanout().await.expect("fan-out");

    // The receiver rejects (the signature does not validate under its wrong secret),
    // so the delivery stays pending and its attempts climb across passes.
    for _ in 0..3 {
        gw.rearm_pending(endpoint_uuid).await.expect("re-arm");
        gw.run_delivery().await.expect("deliver");
    }
    let (state, attempts): (String, i32) = sqlx::query_as(
        "SELECT state, attempts FROM cw_core.webhook_delivery WHERE endpoint_id = $1",
    )
    .bind(endpoint_uuid)
    .fetch_one(&gw.pool)
    .await
    .expect("delivery row");
    assert!(
        attempts >= 1,
        "the rejected delivery accrued failed attempts"
    );
    assert_ne!(
        state, "delivered",
        "a rejected delivery is never marked delivered"
    );

    // The gateway DID sign correctly — the rejection is the receiver's choice. A
    // receiver holding the REAL secret would have validated every delivery.
    let got = sink.deliveries();
    assert!(!got.is_empty(), "the gateway did attempt delivery");
    assert!(
        got[0].signature_valid_under(&[secret.as_bytes()]),
        "the gateway's signature is valid under the real secret; the strict \
         receiver rejected only because it held the wrong one"
    );

    gw.shutdown().await;
}

// ---------------------------------------------------------------------------
// W13 — SSRF redirect/deny: blocked-range refused; a 30x to a private IP is not
// followed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w13_ssrf_blocked_range_refused_and_redirect_not_followed() {
    // (1) A URL resolving to a blocked range is refused by the guard. Drive the
    // guard with an injectable resolver that maps a public-looking hostname to a
    // loopback/metadata IP — the DNS-rebind vector — and assert it is refused.
    struct RebindResolver;
    impl ResolveHost for RebindResolver {
        fn resolve(&self, _hostname: &str) -> Result<Vec<ResolvedRecord>, String> {
            // The hostname looks public, but it resolves to the cloud metadata IP.
            Ok(vec![ResolvedRecord {
                address: "169.254.169.254".parse().unwrap(),
                family: 4,
            }])
        }
    }
    let resolver = RebindResolver;
    let opts = AssertWebhookUrlSafeOptions {
        resolve_host: Some(&resolver),
        ..Default::default()
    };
    let refused = assert_webhook_url_safe("https://totally-public.example.com/hook", &opts);
    assert!(
        refused.is_err(),
        "a hostname resolving to a blocked range is refused (DNS-rebind defeated)"
    );

    // (2) A 30x redirect toward a private IP is NOT followed. The egress pins the
    // connection and sets Policy::none, so a redirecting receiver gets a single
    // non-2xx response (the 307 itself), never a follow-up request to the redirect
    // target. We drive the real egress against a redirecting loopback sink through
    // the test seam.
    let redirect_target = "http://127.0.0.1:1/private";
    let sink = ReceiverSink::redirect_to(redirect_target);
    let url = sink.url();
    let result = tokio::task::spawn_blocking(move || {
        gateway_core::webhook::egress::deliver(
            &url,
            b"{}",
            &[],
            gateway_core::webhook::egress::EgressConfig {
                // The redirecting sink is a local plain-HTTP receiver, so both
                // independent loosenings are opened explicitly.
                allow_insecure_http: true,
                allow_loopback: true,
            },
        )
    })
    .await
    .expect("join");

    match result {
        Ok(resp) => assert!(
            !resp.is_success(),
            "the 307 redirect is surfaced as a non-2xx, never followed to a 2xx"
        ),
        Err(_) => { /* a transport error is also an acceptable non-followed outcome */ }
    }
    // The sink saw exactly one request (the original POST); the redirect was not
    // followed (no second request to the redirect target).
    assert_eq!(
        sink.count(),
        1,
        "the redirect was not followed: exactly one request reached the sink"
    );
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

/// The state of the single delivery row for an endpoint.
async fn delivery_state(gw: &BootedGateway, endpoint_id: Uuid) -> String {
    sqlx::query_scalar("SELECT state FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
        .bind(endpoint_id)
        .fetch_one(&gw.pool)
        .await
        .expect("delivery state")
}

/// The number of delivery rows for an endpoint.
async fn endpoint_delivery_count(gw: &BootedGateway, endpoint_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cw_core.webhook_delivery WHERE endpoint_id = $1")
        .bind(endpoint_id)
        .fetch_one(&gw.pool)
        .await
        .expect("delivery count")
}

/// Cap every pending delivery for an endpoint to a single attempt, so the next
/// failed pass exhausts it (used to drive the auto-disable budget quickly).
async fn cap_attempts_to_one(gw: &BootedGateway, endpoint_id: Uuid) {
    sqlx::query(
        "UPDATE cw_core.webhook_delivery SET max_attempts = 1 \
         WHERE endpoint_id = $1 AND state = 'pending'",
    )
    .bind(endpoint_id)
    .execute(&gw.pool)
    .await
    .expect("cap attempts");
}

/// The subject_seqs delivered to a sink, in order, for deliveries that validate
/// under `secret` (so a corrupted body is excluded). The seq is parsed out of the
/// Webhook-Id (`kind:id:seq:endpoint_id`).
fn delivered_seqs(sink: &ReceiverSink, secret: &str) -> Vec<i64> {
    let mut seqs: Vec<i64> = sink
        .deliveries()
        .iter()
        .filter(|d| d.signature_valid_under(&[secret.as_bytes()]))
        .filter_map(|d| {
            let id = d.webhook_id()?;
            // kind:id:seq:endpoint_id — the seq is the second-to-last colon field.
            let parts: Vec<&str> = id.split(':').collect();
            parts.get(parts.len().wrapping_sub(2))?.parse().ok()
        })
        .collect();
    seqs.sort_unstable();
    seqs.dedup();
    seqs
}

/// Seed an account under an existing operator, returning the account id.
async fn seed_account_under(gw: &BootedGateway, operator_id: Uuid) -> Uuid {
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(&gw.pool)
        .await
        .expect("account anchor");
    sqlx::query("INSERT INTO cw_core.account_detail (account_id, operator_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(operator_id)
        .execute(&gw.pool)
        .await
        .expect("account detail");
    account_id
}

/// Seed a poe_record owned by an operator/account, returning its id (the subject).
async fn seed_record_for(
    gw: &BootedGateway,
    operator_id: Uuid,
    account_id: Uuid,
    bytes: &[u8],
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.poe_record (id, operator_id, account_id, record_bytes) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(operator_id)
    .bind(account_id)
    .bind(bytes)
    .execute(&gw.pool)
    .await
    .expect("seed poe_record");
    id
}
