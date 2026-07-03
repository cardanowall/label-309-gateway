//! The webhook operator surface: the deliveries list / dead-letter view, manual
//! redrive, the dual-signed secret rotation window, and the health summary.
//!
//! These pin the operator-facing contract of a subscription beyond registration:
//!
//!   - **Deliveries list (the dead-letter view).** Every state (`pending`,
//!     `delivered`, `failed`) is listed newest-first, scoped to the owning account;
//!     another tenant's endpoint is reported absent.
//!   - **Manual redrive resets the schedule, not the history.** A `failed`
//!     dead-letter is re-armed `pending` with an immediate `next_attempt_at`, but
//!     `attempts` is left intact (the prior failures stand). A non-failed delivery
//!     is left untouched, and a foreign delivery is reported absent.
//!   - **Secret rotation is a dual-signed window.** Opening a rotation mints a
//!     successor secret (shown once) and makes the delivery dual-signed: the header
//!     carries two `v1`, and a receiver validates with EITHER the current or the
//!     successor secret. Committing promotes the successor and drops back to a
//!     single `v1`, after which only the promoted secret validates and the old one
//!     is rejected.
//!   - **Health view counts.** The `webhook_health` aggregate reports each
//!     endpoint's dead/pending population and the oldest pending instants, scoped to
//!     the operator that owns the endpoints.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use tower::ServiceExt;
use uuid::Uuid;

use gateway_core::api::control::queries::webhook_health;
use gateway_core::api::state::{ApiConfig, AppState, WebhookState};
use gateway_core::testsupport::TestDb;
use gateway_core::wallet::keyring::{UnlockedKeyring, WebhookWrapKey};
use gateway_core::webhook::secret::SecretWrap;
use gateway_core::webhook::signer::sign_delivery;
use gateway_core::webhook::{
    commit_rotation, create_endpoint, get_endpoint, list_deliveries, retry_delivery, rotate_secret,
    EndpointScope, NewEndpoint, RedriveOutcome,
};

type HmacSha256 = Hmac<Sha256>;

/// A deterministic wrap key for the suite (production mints it at bootstrap).
fn wrap() -> SecretWrap {
    SecretWrap::new("whk_test", [0x5au8; 32])
}

async fn seed_operator(pool: &sqlx::PgPool, label: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(id)
        .bind(label)
        .execute(pool)
        .await
        .expect("seed operator");
    id
}

async fn seed_account(pool: &sqlx::PgPool, operator_id: Uuid) -> Uuid {
    let account_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("seed account anchor");
    sqlx::query("INSERT INTO cw_core.account_detail (account_id, operator_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(operator_id)
        .execute(pool)
        .await
        .expect("seed account detail");
    account_id
}

fn new_endpoint(account_id: Uuid) -> NewEndpoint {
    NewEndpoint {
        scope: EndpointScope::Account(account_id),
        url: "https://hooks.example.test/ingest".to_string(),
        enabled_events: Vec::new(),
        label: Some("primary".to_string()),
    }
}

/// Insert a `webhook_delivery` row in a given state for an endpoint. Returns the id.
/// The outbox row a real delivery FK-references is not needed for the list/redrive/
/// health reads, so a synthetic delivery is anchored to a freshly-seeded outbox row
/// (the FK is NOT NULL).
async fn seed_delivery(
    pool: &sqlx::PgPool,
    endpoint_id: Uuid,
    subject_seq: i64,
    state: &str,
    attempts: i32,
    next_attempt_at: chrono::DateTime<Utc>,
) -> Uuid {
    // A minimal outbox row so the delivery FK resolves. The fan-out marker is set so
    // it is never re-fanned by a stray drain in another test path.
    let outbox_id = Uuid::now_v7();
    let subject_id = Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO cw_core.delivery_outbox \
           (id, subject_kind, subject_id, subject_seq, event_type, payload, dedupe_key, \
            fanned_out_at) \
         VALUES ($1, 'account', $2, $3, 'balance.changed', '{}'::jsonb, $4, now())",
    )
    .bind(outbox_id)
    .bind(&subject_id)
    .bind(subject_seq)
    .bind(format!("account:{subject_id}:{subject_seq}"))
    .execute(pool)
    .await
    .expect("seed outbox");

    let id = Uuid::now_v7();
    let dedupe_key = format!("account:{subject_id}:{subject_seq}:{endpoint_id}");
    sqlx::query(
        "INSERT INTO cw_core.webhook_delivery \
           (id, endpoint_id, subject_kind, subject_id, subject_seq, event_type, body, \
            dedupe_key, outbox_id, state, attempts, next_attempt_at) \
         VALUES ($1, $2, 'account', $3, $4, 'balance.changed', '{}'::jsonb, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(endpoint_id)
    .bind(&subject_id)
    .bind(subject_seq)
    .bind(&dedupe_key)
    .bind(outbox_id)
    .bind(state)
    .bind(attempts)
    .bind(next_attempt_at)
    .execute(pool)
    .await
    .expect("seed delivery");
    id
}

// ---------------------------------------------------------------------------
// Deliveries list (the dead-letter view).
// ---------------------------------------------------------------------------

/// The deliveries list returns every state newest-first and is owner-scoped: a
/// foreign account's endpoint reads as absent (no cross-tenant deliveries oracle).
#[tokio::test]
async fn deliveries_list_carries_every_state_and_is_owner_scoped() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let other_account = seed_account(&pool, operator_id).await;

    let endpoint = create_endpoint(&pool, &w, &new_endpoint(account_id))
        .await
        .expect("create endpoint")
        .id;

    let now = Utc::now();
    seed_delivery(&pool, endpoint, 1, "delivered", 1, now).await;
    seed_delivery(&pool, endpoint, 2, "failed", 12, now).await;
    seed_delivery(&pool, endpoint, 3, "pending", 0, now).await;

    let views = list_deliveries(&pool, EndpointScope::Account(account_id), endpoint, 50)
        .await
        .expect("list")
        .expect("endpoint owned by account");
    assert_eq!(views.len(), 3, "all three deliveries are listed");
    // Newest-first: the most recently inserted (seq 3) is first.
    assert_eq!(views[0].subject_seq, 3);
    let states: Vec<&str> = views.iter().map(|v| v.state.as_str()).collect();
    assert!(states.contains(&"delivered"));
    assert!(states.contains(&"failed"));
    assert!(states.contains(&"pending"));

    // Another account never sees this endpoint's deliveries: it reads as absent,
    // identical to a non-existent endpoint.
    assert!(
        list_deliveries(&pool, EndpointScope::Account(other_account), endpoint, 50)
            .await
            .expect("list other")
            .is_none(),
        "a foreign account's endpoint deliveries read as absent"
    );
    // A genuinely absent endpoint id is also None.
    assert!(
        list_deliveries(
            &pool,
            EndpointScope::Account(account_id),
            Uuid::now_v7(),
            50
        )
        .await
        .expect("list missing")
        .is_none(),
        "an absent endpoint reads as None"
    );
}

// ---------------------------------------------------------------------------
// Manual redrive.
// ---------------------------------------------------------------------------

/// Redrive resets the schedule, not the attempt history: a `failed` row flips back
/// to `pending` and becomes immediately due, while `attempts` is left intact.
#[tokio::test]
async fn redrive_resets_schedule_but_preserves_attempts() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let endpoint = create_endpoint(&pool, &w, &new_endpoint(account_id))
        .await
        .expect("create endpoint")
        .id;

    // A failed dead-letter with a future next_attempt_at and a consumed attempt
    // budget.
    let far_future = Utc::now() + Duration::hours(6);
    let delivery = seed_delivery(&pool, endpoint, 1, "failed", 12, far_future).await;

    let outcome = retry_delivery(
        &pool,
        EndpointScope::Account(account_id),
        endpoint,
        delivery,
    )
    .await
    .expect("redrive");
    assert_eq!(outcome, RedriveOutcome::Redriven);

    // The row is re-armed: pending, immediately due, attempts UNCHANGED (history
    // stands), last_error cleared.
    let (state, attempts, next_attempt_at, last_error): (
        String,
        i32,
        chrono::DateTime<Utc>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT state, attempts, next_attempt_at, last_error \
         FROM cw_core.webhook_delivery WHERE id = $1",
    )
    .bind(delivery)
    .fetch_one(&pool)
    .await
    .expect("read redriven row");
    assert_eq!(state, "pending", "the redrive re-arms the delivery");
    assert_eq!(
        attempts, 12,
        "redrive preserves the attempt history (resets schedule, not attempts)"
    );
    assert!(
        next_attempt_at <= Utc::now() + Duration::seconds(2),
        "the delivery is now immediately due"
    );
    assert!(
        last_error.is_none(),
        "the prior error is cleared on redrive"
    );
}

/// Redrive only acts on a `failed` row: a still-pending or already-delivered row is
/// reported NotFailed and left untouched; a foreign/absent delivery is NotFound.
#[tokio::test]
async fn redrive_only_acts_on_a_failed_delivery() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let other_account = seed_account(&pool, operator_id).await;
    let endpoint = create_endpoint(&pool, &w, &new_endpoint(account_id))
        .await
        .expect("create endpoint")
        .id;

    let now = Utc::now();
    let pending = seed_delivery(&pool, endpoint, 1, "pending", 0, now).await;
    let delivered = seed_delivery(&pool, endpoint, 2, "delivered", 1, now).await;
    let failed = seed_delivery(&pool, endpoint, 3, "failed", 12, now).await;

    // A pending delivery is not redrivable.
    assert_eq!(
        retry_delivery(&pool, EndpointScope::Account(account_id), endpoint, pending)
            .await
            .expect("redrive pending"),
        RedriveOutcome::NotFailed
    );
    // A delivered delivery is not redrivable.
    assert_eq!(
        retry_delivery(
            &pool,
            EndpointScope::Account(account_id),
            endpoint,
            delivered
        )
        .await
        .expect("redrive delivered"),
        RedriveOutcome::NotFailed
    );
    // A foreign account cannot redrive this endpoint's delivery: NotFound (no
    // cross-tenant oracle), and the failed row is untouched.
    assert_eq!(
        retry_delivery(
            &pool,
            EndpointScope::Account(other_account),
            endpoint,
            failed
        )
        .await
        .expect("redrive foreign"),
        RedriveOutcome::NotFound
    );
    let still_failed: String =
        sqlx::query_scalar("SELECT state FROM cw_core.webhook_delivery WHERE id = $1")
            .bind(failed)
            .fetch_one(&pool)
            .await
            .expect("read failed row");
    assert_eq!(
        still_failed, "failed",
        "a foreign redrive does not touch the delivery"
    );
    // An absent delivery id is NotFound.
    assert_eq!(
        retry_delivery(
            &pool,
            EndpointScope::Account(account_id),
            endpoint,
            Uuid::now_v7()
        )
        .await
        .expect("redrive absent"),
        RedriveOutcome::NotFound
    );
}

// ---------------------------------------------------------------------------
// Secret rotation (dual-signed window + commit).
// ---------------------------------------------------------------------------

/// Recompute the v1 MAC a receiver would, over `"{id}.{t}.{body}"`.
fn receiver_v1(id: &str, secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Whether a `Webhook-Signature` header value carries a `v1` a receiver holding
/// `secret` would accept for `(id, timestamp, body)`.
fn signature_validates(
    signature: &str,
    id: &str,
    secret: &[u8],
    timestamp: i64,
    body: &[u8],
) -> bool {
    let expected = receiver_v1(id, secret, timestamp, body);
    signature
        .split(',')
        .filter_map(|part| part.strip_prefix("v1="))
        .any(|v1| v1 == expected)
}

/// The full rotation lifecycle: open a window (the successor secret is shown once,
/// both fingerprints appear in GET), the delivery is dual-signed so EITHER secret
/// validates, then commit promotes the successor (one `v1`, only the promoted
/// secret validates, the old one is rejected).
#[tokio::test]
async fn rotation_window_dual_signs_then_commit_promotes_the_successor() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let created = create_endpoint(&pool, &w, &new_endpoint(account_id))
        .await
        .expect("create endpoint");
    let primary = created.secret.clone().into_bytes();

    // Before any rotation: one fingerprint, no successor.
    let view = get_endpoint(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("get")
        .expect("present");
    assert!(
        view.secret_next_fp.is_none(),
        "no rotation window before rotate"
    );

    // Open the rotation window: the successor is returned once, both fingerprints
    // now appear.
    let rotated = rotate_secret(&pool, &w, EndpointScope::Account(account_id), created.id)
        .await
        .expect("rotate")
        .expect("endpoint present");
    let successor = rotated.secret_next.clone().into_bytes();
    assert!(rotated.secret_next.starts_with("whsec_"));
    assert_ne!(
        rotated.secret_next, created.secret,
        "the successor is a fresh secret"
    );
    let view = get_endpoint(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("get")
        .expect("present");
    assert!(
        view.secret_next_fp.is_some(),
        "both fingerprints appear during the rotation window"
    );

    // The stored row now carries BOTH ciphertexts; the worker would dual-sign. Read
    // them back and build the delivery signature exactly as the worker does.
    let (secret_enc, secret_next_enc): (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT secret_enc, secret_next_enc FROM cw_core.webhook_endpoint WHERE id = $1",
    )
    .bind(created.id)
    .fetch_one(&pool)
    .await
    .expect("read secret columns");
    let opened_primary = w.open(&secret_enc).expect("open primary").to_vec();
    let opened_next = w
        .open(&secret_next_enc.expect("successor present"))
        .expect("open successor")
        .to_vec();

    let body =
        br#"{"id":"x","type":"balance_changed","created_at":"2026-06-07T00:00:00Z","data":{}}"#;
    let timestamp = 1_733_600_000i64;
    let webhook_id = "account:x:1:endpoint";
    let headers = sign_delivery(webhook_id, timestamp, body, &[opened_primary, opened_next]);

    // The header carries two v1, and a receiver holding EITHER the current or the
    // successor secret validates the delivery.
    assert_eq!(
        headers.signature.matches("v1=").count(),
        2,
        "the rotation window dual-signs"
    );
    assert!(
        signature_validates(&headers.signature, webhook_id, &primary, timestamp, body),
        "the current secret validates during the window"
    );
    assert!(
        signature_validates(&headers.signature, webhook_id, &successor, timestamp, body),
        "the successor secret validates during the window"
    );

    // Commit the rotation: the successor is promoted, the window closes.
    let outcome = commit_rotation(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("commit");
    assert_eq!(
        outcome,
        gateway_core::webhook::EndpointChange::Changed,
        "the commit promotes the successor"
    );
    let view = get_endpoint(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("get")
        .expect("present");
    assert!(
        view.secret_next_fp.is_none(),
        "the window is closed after commit (one fingerprint)"
    );

    // After commit: a single v1 signed with the promoted (formerly successor)
    // secret. The old primary no longer validates; the promoted secret does.
    let (secret_enc, secret_next_enc): (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT secret_enc, secret_next_enc FROM cw_core.webhook_endpoint WHERE id = $1",
    )
    .bind(created.id)
    .fetch_one(&pool)
    .await
    .expect("read secret columns post-commit");
    assert!(
        secret_next_enc.is_none(),
        "the successor column is cleared on commit"
    );
    let promoted = w.open(&secret_enc).expect("open promoted").to_vec();
    let webhook_id = "account:x:2:endpoint";
    let headers = sign_delivery(webhook_id, timestamp, body, &[promoted]);
    assert_eq!(
        headers.signature.matches("v1=").count(),
        1,
        "back to a single v1 after commit"
    );
    assert!(
        signature_validates(&headers.signature, webhook_id, &successor, timestamp, body),
        "the promoted (formerly successor) secret validates after commit"
    );
    assert!(
        !signature_validates(&headers.signature, webhook_id, &primary, timestamp, body),
        "the old primary secret is rejected after commit"
    );
}

/// A commit with no open rotation window is a no-op NotFound, so a redundant commit
/// never clears the only secret.
#[tokio::test]
async fn commit_without_an_open_window_is_a_noop() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let created = create_endpoint(&pool, &w, &new_endpoint(account_id))
        .await
        .expect("create endpoint");
    let original_secret = created.secret.clone().into_bytes();

    // No rotation is open: commit reports NotFound and leaves the secret intact, so a
    // redundant commit never clears the only secret.
    let outcome = commit_rotation(&pool, EndpointScope::Account(account_id), created.id)
        .await
        .expect("commit no window");
    assert_eq!(outcome, gateway_core::webhook::EndpointChange::NotFound);

    let (secret_enc, secret_next_enc): (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT secret_enc, secret_next_enc FROM cw_core.webhook_endpoint WHERE id = $1",
    )
    .bind(created.id)
    .fetch_one(&pool)
    .await
    .expect("read secret");
    assert!(
        secret_next_enc.is_none(),
        "no successor existed and none was created"
    );
    assert_eq!(
        w.open(&secret_enc).expect("open").to_vec(),
        original_secret,
        "the active secret still decrypts to the original (the commit did not clear it)"
    );

    // A foreign account also cannot commit a rotation it does not own.
    let other_account = seed_account(&pool, operator_id).await;
    assert_eq!(
        commit_rotation(&pool, EndpointScope::Account(other_account), created.id)
            .await
            .expect("foreign commit"),
        gateway_core::webhook::EndpointChange::NotFound
    );
}

/// Rotating an endpoint whose row was sealed under a now-superseded wrap key
/// succeeds (it is not reported absent), and the successor is sealed under the
/// ROW's recorded key, not the process-active one.
///
/// A deployment that holds more than one webhook-wrap key has a newest (active) key
/// and older keys still referenced by rows created before the newest was added. The
/// rotation must seal the successor under the row's own key so both ciphertexts on a
/// row keep sharing one key (the delivery worker opens both by the row's recorded
/// `wrap_key_id`). Resolving the row's key through the full keyring lets the rotation
/// succeed for such a row instead of reporting the live endpoint as absent.
#[tokio::test]
async fn rotate_under_a_superseded_wrap_key_succeeds_and_seals_under_the_rows_key() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();

    // Two webhook-wrap keys, K2 added after K1 so K2 is the active (newest) key and K1
    // is superseded. The keyring still holds K1, the same custody the delivery worker
    // relies on to open a K1 row.
    let k1 = WebhookWrapKey::generate("wrap-1".to_string(), "whk_k1".to_string()).expect("gen k1");
    let k2 = WebhookWrapKey::generate("wrap-2".to_string(), "whk_k2".to_string()).expect("gen k2");
    let keyring = UnlockedKeyring::for_webhook_tests(vec![k1, k2]);
    let active_wrap = keyring
        .active_webhook_wrap_key()
        .expect("active key")
        .secret_wrap();
    assert_eq!(
        active_wrap.wrap_key_id(),
        "whk_k2",
        "K2 is the active key after being added last"
    );

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;

    // Create the endpoint under the SUPERSEDED key K1, so its row references whk_k1
    // while the active key is whk_k2 (the exact stale-wrap-key state).
    let k1_wrap = keyring
        .webhook_wrap_key("whk_k1")
        .expect("k1 held")
        .secret_wrap();
    let created = create_endpoint(&pool, &k1_wrap, &new_endpoint(account_id))
        .await
        .expect("create endpoint under K1");
    let row_key: String =
        sqlx::query_scalar("SELECT wrap_key_id FROM cw_core.webhook_endpoint WHERE id = $1")
            .bind(created.id)
            .fetch_one(&pool)
            .await
            .expect("read row wrap_key_id");
    assert_eq!(
        row_key, "whk_k1",
        "the row is recorded under the superseded key"
    );

    // Rotate through the full keyring (the resolver that holds every wrap key). The
    // row sits under K1, the active key is K2; the rotation must still succeed.
    let rotated = rotate_secret(
        &pool,
        &keyring,
        EndpointScope::Account(account_id),
        created.id,
    )
    .await
    .expect("rotate succeeds (no service error)")
    .expect("a live owned endpoint is NOT reported absent under a superseded key");
    let successor = rotated.secret_next.clone();
    assert!(successor.starts_with("whsec_"));

    // The row's wrap_key_id is unchanged, and the successor ciphertext opens under the
    // ROW's key (K1), not the active key (K2). That is what lets the delivery worker,
    // which resolves the single key by the row's recorded id, dual-sign with both.
    let (row_key_after, secret_next_enc): (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT wrap_key_id, secret_next_enc FROM cw_core.webhook_endpoint WHERE id = $1",
    )
    .bind(created.id)
    .fetch_one(&pool)
    .await
    .expect("read row after rotate");
    assert_eq!(
        row_key_after, "whk_k1",
        "rotation keeps the row under its own recorded key"
    );
    let next_enc = secret_next_enc.expect("the successor ciphertext is stored");
    let opened_under_k1 = k1_wrap
        .open(&next_enc)
        .expect("successor opens under the row's key");
    assert_eq!(
        opened_under_k1.as_slice(),
        successor.as_bytes(),
        "the stored successor decrypts under the row's key to the plaintext shown once"
    );
    assert!(
        active_wrap.open(&next_enc).is_err(),
        "the successor is sealed under the row's key, not the process-active key"
    );
}

// ---------------------------------------------------------------------------
// Health summary.
// ---------------------------------------------------------------------------

/// The health view counts dead and pending deliveries per endpoint and reports the
/// oldest pending instants, scoped to the operator that owns the endpoints. An
/// endpoint under another operator never appears.
#[tokio::test]
async fn health_summary_counts_dead_pending_and_oldest_pending_scoped_to_the_operator() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let w = wrap();

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let endpoint = create_endpoint(&pool, &w, &new_endpoint(account_id))
        .await
        .expect("create endpoint")
        .id;

    // Two failed (dead) and three pending deliveries; one delivered (counts toward
    // neither). The pending deliveries are due at distinct future instants so the
    // oldest-pending aggregates are well-defined.
    let base = Utc::now();
    seed_delivery(&pool, endpoint, 1, "failed", 12, base).await;
    seed_delivery(&pool, endpoint, 2, "failed", 12, base).await;
    seed_delivery(&pool, endpoint, 3, "delivered", 1, base).await;
    let due_soon = base + Duration::minutes(5);
    let due_later = base + Duration::minutes(30);
    let due_latest = base + Duration::hours(2);
    seed_delivery(&pool, endpoint, 4, "pending", 0, due_soon).await;
    seed_delivery(&pool, endpoint, 5, "pending", 1, due_later).await;
    seed_delivery(&pool, endpoint, 6, "pending", 2, due_latest).await;

    let summaries = webhook_health(&pool, operator_id, 100)
        .await
        .expect("health summary");
    let row = summaries
        .iter()
        .find(|s| s.endpoint_id == endpoint)
        .expect("the operator's endpoint is in the summary");

    assert_eq!(
        row.dead_deliveries, 2,
        "two failed deliveries are counted dead"
    );
    assert_eq!(
        row.pending_deliveries, 3,
        "three pending deliveries are counted"
    );
    assert_eq!(row.scope_kind, "account");
    assert_eq!(row.status, "active");
    // The oldest pending due instant is the soonest of the pending next_attempt_at.
    let oldest_due = row.oldest_pending_due.expect("a pending delivery exists");
    assert!(
        (oldest_due - due_soon).num_seconds().abs() <= 1,
        "oldest_pending_due is the soonest pending next_attempt_at"
    );
    assert!(
        row.oldest_pending_at.is_some(),
        "the oldest pending created_at is reported"
    );

    // An endpoint owned by another operator is never in this operator's summary.
    let other_operator = seed_operator(&pool, "other").await;
    let other_account = seed_account(&pool, other_operator).await;
    let other_endpoint = create_endpoint(&pool, &w, &new_endpoint(other_account))
        .await
        .expect("create other endpoint")
        .id;
    seed_delivery(&pool, other_endpoint, 1, "failed", 12, base).await;

    let summaries = webhook_health(&pool, operator_id, 100)
        .await
        .expect("health summary after foreign endpoint");
    assert!(
        summaries.iter().all(|s| s.endpoint_id != other_endpoint),
        "another operator's endpoint never leaks into this operator's health summary"
    );
    // The other operator sees only its own endpoint.
    let other_summaries = webhook_health(&pool, other_operator, 100)
        .await
        .expect("other operator health summary");
    assert_eq!(other_summaries.len(), 1);
    assert_eq!(other_summaries[0].endpoint_id, other_endpoint);
    assert_eq!(other_summaries[0].dead_deliveries, 1);
}

// ---------------------------------------------------------------------------
// HTTP route-level tests: drive the actual axum routers.
// ---------------------------------------------------------------------------

/// Build data-plane state with the webhook seam wired (loopback allowed so a test
/// URL passes the SSRF guard at create/rotate).
fn data_state(pool: sqlx::PgPool) -> AppState {
    AppState::new(
        pool,
        ApiConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            ..Default::default()
        },
    )
    .with_webhook(WebhookState::new(
        Arc::new(SecretWrap::new("whk_test", [0x5au8; 32])),
        false, // allow_insecure_http
        true,  // egress_allow_loopback: the test URL resolves to loopback
    ))
}

/// Issue an api key for an account carrying `scopes`, returning the bearer secret.
async fn issue_key(pool: &sqlx::PgPool, account_id: Uuid, scopes: &[&str]) -> String {
    use sha2::Digest;
    let secret = format!("wh_test_{}", Uuid::now_v7().simple());
    let full = Sha256::digest(secret.as_bytes());
    let lookup = full[..8].to_vec();
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "INSERT INTO cw_core.api_key \
           (id, account_id, prefix, key_lookup, key_hash_sha256, scopes, rate_limit_per_min) \
         VALUES ($1, $2, 'wh_test_', $3, $4, $5, 1000)",
    )
    .bind(Uuid::now_v7())
    .bind(account_id)
    .bind(lookup)
    .bind(full.to_vec())
    .bind(&scopes)
    .execute(pool)
    .await
    .expect("insert api key");
    secret
}

/// Drive one request through a router and return (status, json body).
async fn call(router: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

fn get_auth(path: &str, secret: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", format!("Bearer {secret}"))
        .body(Body::empty())
        .expect("build request")
}

fn post_auth(path: &str, secret: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {secret}"))
        .body(Body::empty())
        .expect("build request")
}

/// The full operator surface over the data-plane router: list deliveries (the DLQ
/// view), redrive a failed one, rotate the secret (successor shown once, window
/// open), then commit (window closed).
#[tokio::test]
async fn http_deliveries_redrive_and_rotation_lifecycle() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let st = data_state(pool.clone());
    let router = gateway_core::api::router(st);

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    // The wrap key the router uses to seal must match the one a delivery seed reads,
    // so create the endpoint through the same wrap key the state carries.
    let endpoint = create_endpoint(&pool, &wrap(), &new_endpoint(account_id))
        .await
        .expect("create endpoint")
        .id;
    let secret = issue_key(&pool, account_id, &["webhooks:read", "webhooks:write"]).await;

    // Seed one failed and one pending delivery.
    let now = Utc::now();
    let failed = seed_delivery(&pool, endpoint, 1, "failed", 12, now + Duration::hours(6)).await;
    seed_delivery(&pool, endpoint, 2, "pending", 0, now).await;

    // List deliveries: 200, both states present, the failed row is the dead-letter.
    let (status, body) = call(
        &router,
        get_auth(&format!("/api/v1/webhooks/{endpoint}/deliveries"), &secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
    assert!(items.iter().any(|d| d["state"] == "failed"));
    assert!(items.iter().any(|d| d["state"] == "pending"));
    // The frozen body is not echoed; the webhook_id (the receiver's dedupe key) is.
    assert!(items[0].get("body").is_none());
    assert!(items.iter().all(|d| d["webhook_id"].as_str().is_some()));

    // The per-account subscription list carries the dead-delivery count inline, so a
    // subscriber sees the failure population without scanning the deliveries list.
    let (status, list) = call(&router, get_auth("/api/v1/webhooks", &secret)).await;
    assert_eq!(status, StatusCode::OK);
    let endpoint_view = list["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|e| e["id"] == endpoint.to_string())
        .expect("the endpoint is listed");
    assert_eq!(
        endpoint_view["dead_deliveries"], 1,
        "the account list carries dead_deliveries inline"
    );

    // Redrive the failed delivery: 200, re-armed to pending.
    let (status, body) = call(
        &router,
        post_auth(
            &format!("/api/v1/webhooks/{endpoint}/deliveries/{failed}/retry"),
            &secret,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "pending");
    // The redrive preserved the attempt count.
    let attempts: i32 =
        sqlx::query_scalar("SELECT attempts FROM cw_core.webhook_delivery WHERE id = $1")
            .bind(failed)
            .fetch_one(&pool)
            .await
            .expect("read attempts");
    assert_eq!(attempts, 12, "redrive resets schedule, not attempts");

    // Redriving an already-pending delivery is 422 (only a failed row is
    // redrivable).
    let (status, body) = call(
        &router,
        post_auth(
            &format!("/api/v1/webhooks/{endpoint}/deliveries/{failed}/retry"),
            &secret,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "validation-failed");

    // Rotate the secret: 200, successor shown once, both fingerprints in GET.
    let (status, body) = call(
        &router,
        post_auth(
            &format!("/api/v1/webhooks/{endpoint}/rotate-secret"),
            &secret,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["secret_next"]
        .as_str()
        .expect("successor shown once")
        .starts_with("whsec_"));
    assert!(body["secret_fp"].as_str().is_some());
    assert!(body["secret_next_fp"].as_str().is_some());
    let (status, view) = call(
        &router,
        get_auth(&format!("/api/v1/webhooks/{endpoint}"), &secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        view["secret_next_fp"].as_str().is_some(),
        "the rotation window is open: both fingerprints appear"
    );

    // Commit the rotation: 200, the window closes (one fingerprint).
    let (status, _body) = call(
        &router,
        post_auth(
            &format!("/api/v1/webhooks/{endpoint}/rotate-secret/commit"),
            &secret,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, view) = call(
        &router,
        get_auth(&format!("/api/v1/webhooks/{endpoint}"), &secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        view.get("secret_next_fp").is_none() || view["secret_next_fp"].is_null(),
        "the rotation window is closed after commit"
    );

    // A second commit with no open window is 404 (nothing to promote).
    let (status, _body) = call(
        &router,
        post_auth(
            &format!("/api/v1/webhooks/{endpoint}/rotate-secret/commit"),
            &secret,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The deliveries list requires `webhooks:read` and the redrive/rotate routes
/// require `webhooks:write`; a key missing the scope is rejected 403.
#[tokio::test]
async fn http_operator_routes_enforce_scopes() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let router = gateway_core::api::router(data_state(pool.clone()));

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let endpoint = create_endpoint(&pool, &wrap(), &new_endpoint(account_id))
        .await
        .expect("create endpoint")
        .id;

    // A write-only key cannot list deliveries (needs read).
    let write_only = issue_key(&pool, account_id, &["webhooks:write"]).await;
    let (status, body) = call(
        &router,
        get_auth(
            &format!("/api/v1/webhooks/{endpoint}/deliveries"),
            &write_only,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "insufficient-scope");

    // A read-only key cannot rotate the secret (needs write).
    let read_only = issue_key(&pool, account_id, &["webhooks:read"]).await;
    let (status, body) = call(
        &router,
        post_auth(
            &format!("/api/v1/webhooks/{endpoint}/rotate-secret"),
            &read_only,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "insufficient-scope");
}

/// Build control state for the health route (no held keys are needed for a read).
fn control_state(pool: sqlx::PgPool) -> gateway_core::api::ControlState {
    gateway_core::api::ControlState::new(
        pool,
        gateway_core::api::ControlConfig {
            problem_type_base: "https://errors.example/v1".to_string(),
            secret_prefix: "ctl_test_".to_string(),
            ..Default::default()
        },
    )
}

/// The control-plane health route returns the operator's endpoint health under an
/// operator token, and rejects an account bearer (plane isolation).
#[tokio::test]
async fn http_control_health_is_operator_scoped() {
    let db = TestDb::fresh().await.expect("db");
    let pool = db.pool.clone();
    let control = gateway_core::api::control_router(control_state(pool.clone()));

    let operator_id = seed_operator(&pool, "op").await;
    let account_id = seed_account(&pool, operator_id).await;
    let endpoint = create_endpoint(&pool, &wrap(), &new_endpoint(account_id))
        .await
        .expect("create endpoint")
        .id;
    let now = Utc::now();
    seed_delivery(&pool, endpoint, 1, "failed", 12, now).await;
    seed_delivery(&pool, endpoint, 2, "pending", 0, now).await;

    // An operator token sees the health row with the dead/pending counts. The
    // mint is anchored on a real root: the engine refuses a fabricated
    // `minted_by` lineage id.
    let root = gateway_core::api::control::credential::mint_root_credential(
        &pool,
        operator_id,
        "ctl_test_",
        None,
    )
    .await
    .expect("mint lineage root");
    let op_token = gateway_core::api::control::credential::mint_operator_token(
        &pool,
        operator_id,
        "ctl_test_",
        Duration::hours(1),
        root.id,
    )
    .await
    .expect("mint operator token");
    let (status, body) = call(
        &control,
        get_auth("/control/v1/webhooks/health", &op_token.minted.secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let data = body["data"].as_array().expect("data array");
    let row = data
        .iter()
        .find(|h| h["endpoint_id"] == endpoint.to_string())
        .expect("the operator's endpoint health is in the summary");
    assert_eq!(row["dead_deliveries"], 1);
    assert_eq!(row["pending_deliveries"], 1);
    assert_eq!(row["scope_kind"], "account");

    // An account bearer is rejected on the control plane (plane isolation).
    let account_bearer = issue_key(&pool, account_id, &["webhooks:read"]).await;
    let (status, _body) = call(
        &control,
        get_auth("/control/v1/webhooks/health", &account_bearer),
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "an account bearer may not read the operator health summary, got {status}"
    );
}
