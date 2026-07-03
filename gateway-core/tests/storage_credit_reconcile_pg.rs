//! The operator winc-credit reconcile loop against a real Postgres.
//!
//! These suites drive the reconcile pass through a stubbed winc-balance provider
//! (no live HTTP) and assert the converged ledger/cache state and the emitted
//! operator-facing events:
//!
//!   - two sources reconciled in one tick each append their own `reconcile` row
//!     (the idempotency key includes `funding_source_id`, so they never collide);
//!   - a provider that is unreachable for one source keeps the prior believed
//!     balance serving and records a stale-visibility marker, without blanking the
//!     row a quote reads;
//!   - a live balance that moved more than the gateway's own journalled activity
//!     explains emits `storage.credit.drift` AND the `reconcile` row self-corrects
//!     the believed balance to the live value;
//!   - a landed operator top-up is absorbed into the believed balance BEFORE the
//!     drift comparison, so a legitimate top-up never trips the drift alert;
//!   - a live balance at or below the safety floor emits `storage.credit.low`;
//!   - the cached-credit `affords` read refuses an unfunded source, a source below
//!     the floor, and a chargeable size over the provider's fundable ceiling, and
//!     admits an affordable one, all without any provider call;
//!   - the winc journal append is idempotent on `(funding_source_id, kind, ref)`,
//!     including the reconcile-only tolerance for a retried tick whose recomputed
//!     delta moved.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use std::collections::HashMap;
use std::sync::Mutex;

use gateway_core::storage::{
    active_funding_sources, affords, insert_credit_entry, load_credit, run_reconcile,
    AffordVerdict, CreditEntry, CreditKind, CreditOutcome, FundTxAck, FundTxRegistrar,
    ReconcileConfig, StorageError, WincBalance, WincBalanceProvider, CREDIT_DRIFT_EVENT,
    CREDIT_LOW_EVENT, FUNDING_SOURCE_SUBJECT_KIND,
};
use gateway_core::testsupport::TestDb;
use rust_decimal::Decimal;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

async fn seed_operator(pool: &sqlx::PgPool, label: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(id)
        .bind(label)
        .execute(pool)
        .await
        .expect("insert operator");
    id
}

async fn seed_funding_source(
    pool: &sqlx::PgPool,
    owner_operator_id: Uuid,
    backend: &str,
    address: &str,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_funding_source \
           (id, owner_operator_id, label, backend, arweave_address, key_ref) \
         VALUES ($1, $2, 'primary', $3, $4, 'kr:1')",
    )
    .bind(id)
    .bind(owner_operator_id)
    .bind(backend)
    .bind(address)
    .execute(pool)
    .await
    .expect("insert funding source");
    id
}

/// A scripted winc-balance provider: a map from Arweave address to either a live
/// balance or an unreachable error, so a test fully controls what each source's
/// provider read resolves to without any network.
#[derive(Default)]
struct StubWincProvider {
    /// Address -> Ok(balance) or Err(unavailable detail).
    answers: Mutex<HashMap<String, Result<WincBalance, String>>>,
}

impl StubWincProvider {
    fn with_balance(self, address: &str, winc: i64, fundable_bytes: Option<i64>) -> Self {
        self.answers.lock().unwrap().insert(
            address.to_string(),
            Ok(WincBalance {
                winc: Decimal::from(winc),
                fundable_bytes,
            }),
        );
        self
    }

    fn with_unavailable(self, address: &str, detail: &str) -> Self {
        self.answers
            .lock()
            .unwrap()
            .insert(address.to_string(), Err(detail.to_string()));
        self
    }
}

impl WincBalanceProvider for StubWincProvider {
    fn get_winc_balance<'a>(
        &'a self,
        address: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<WincBalance, StorageError>> + Send + 'a>,
    > {
        let answer = self.answers.lock().unwrap().get(address).cloned();
        Box::pin(async move {
            match answer {
                Some(Ok(balance)) => Ok(balance),
                Some(Err(detail)) => Err(StorageError::Unavailable(detail)),
                None => Err(StorageError::Unavailable(format!(
                    "no scripted balance for {address}"
                ))),
            }
        })
    }
}

/// A scripted fund-transaction registrar: a map from tx id to a verdict. An
/// unscripted id reports the payment service unreachable, so the default
/// (empty) registrar doubles as the stub for suites whose sources hold no
/// registered top-ups — the reconcile pass never polls it there.
#[derive(Default)]
struct StubRegistrar {
    answers: Mutex<HashMap<String, FundTxAck>>,
}

impl StubRegistrar {
    fn with_credited(self, tx_id: &str, winc: i64) -> Self {
        self.answers.lock().unwrap().insert(
            tx_id.to_string(),
            FundTxAck::Accepted {
                winc: Some(Decimal::from(winc)),
                credited: true,
            },
        );
        self
    }
}

impl FundTxRegistrar for StubRegistrar {
    fn submit_fund_transaction<'a>(
        &'a self,
        tx_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<FundTxAck, StorageError>> + Send + 'a>,
    > {
        let answer = self.answers.lock().unwrap().get(tx_id).cloned();
        Box::pin(async move {
            answer.ok_or_else(|| {
                StorageError::Unavailable(format!("no scripted verdict for {tx_id}"))
            })
        })
    }
}

/// Insert a `registered` top-up for a source: the payment service accepted the
/// fund transaction and reported it will credit `registered_winc` at
/// confirmation depth. The persisted transaction JSON is irrelevant here — the
/// reconcile pass only re-registers the tx id, never re-broadcasts.
async fn seed_registered_topup(
    pool: &sqlx::PgPool,
    operator: Uuid,
    source: Uuid,
    tx_id: &str,
    registered_winc: i64,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cw_core.storage_topup \
           (id, funding_source_id, initiated_by_operator, ar_amount_winston, fee_winston, \
            target_address, tx_id, tx_json, status, registered_winc) \
         VALUES ($1, $2, $3, $4, 1000, 'deposit-wallet', $5, '{}'::jsonb, 'registered', $4)",
    )
    .bind(id)
    .bind(source)
    .bind(operator)
    .bind(Decimal::from(registered_winc))
    .bind(tx_id)
    .execute(pool)
    .await
    .expect("insert registered top-up");
    id
}

async fn credit_events(pool: &sqlx::PgPool, funding_source_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_type FROM cw_core.subject_event \
         WHERE subject_kind = $1 AND subject_id = $2 ORDER BY subject_seq",
    )
    .bind(FUNDING_SOURCE_SUBJECT_KIND)
    .bind(funding_source_id.to_string())
    .fetch_all(pool)
    .await
    .expect("read credit events")
}

fn config(floor: i64, drift: i64) -> ReconcileConfig {
    ReconcileConfig {
        winc_safety_floor: Decimal::from(floor),
        winc_drift_alert_threshold: Decimal::from(drift),
    }
}

// ---------------------------------------------------------------------------
// Two sources in one tick: the reconcile rows never collide.
// ---------------------------------------------------------------------------

/// Two sources reconciled in the SAME tick each get their own `reconcile` row,
/// because the journal idempotency key is (funding_source_id, kind, ref): the same
/// tick id never makes one source's reconcile suppress the other's.
#[tokio::test]
async fn two_sources_reconciled_in_one_tick_do_not_collide() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let source_a = seed_funding_source(&db.pool, operator, "turbo", "addr-a").await;
    let source_b = seed_funding_source(&db.pool, operator, "turbo", "addr-b").await;

    let provider = StubWincProvider::default()
        .with_balance("addr-a", 50_000, Some(1_000_000))
        .with_balance("addr-b", 70_000, Some(2_000_000));

    let summary = run_reconcile(
        &db.pool,
        &provider,
        &StubRegistrar::default(),
        "turbo",
        "tick-shared",
        &config(1_000, 10_000),
    )
    .await
    .expect("reconcile pass");

    assert_eq!(
        summary.corrected, 2,
        "both sources moved off their zero belief"
    );

    // Each source carries exactly one reconcile row keyed on the shared tick id;
    // they coexist because the idempotency key includes the source id.
    for (source, expected) in [(source_a, 50_000), (source_b, 70_000)] {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM cw_core.storage_credit_ledger \
             WHERE funding_source_id = $1 AND kind = 'reconcile' AND ref = 'tick-shared'",
        )
        .bind(source)
        .fetch_one(&db.pool)
        .await
        .expect("count reconcile rows");
        assert_eq!(
            count, 1,
            "exactly one reconcile row for this source in the tick"
        );

        let credit = load_credit(&db.pool, source)
            .await
            .expect("load credit")
            .expect("source has a materialized balance");
        assert_eq!(
            credit.winc_balance,
            Decimal::from(expected),
            "the reconcile moved the believed balance to the live value"
        );
    }
}

/// Re-running the SAME tick is an idempotent no-op: the reconcile row is keyed on
/// the tick id, so a retried pass does not append a second delta or move the
/// balance again.
#[tokio::test]
async fn re_running_the_same_tick_is_idempotent() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator, "turbo", "addr-a").await;

    let provider = StubWincProvider::default().with_balance("addr-a", 50_000, Some(1_000_000));

    run_reconcile(
        &db.pool,
        &provider,
        &StubRegistrar::default(),
        "turbo",
        "tick-1",
        &config(1_000, 10_000),
    )
    .await
    .expect("first pass");
    let summary = run_reconcile(
        &db.pool,
        &provider,
        &StubRegistrar::default(),
        "turbo",
        "tick-1",
        &config(1_000, 10_000),
    )
    .await
    .expect("second pass, same tick");

    // The second pass sees the believed balance already equal to live, so it
    // appends nothing.
    assert_eq!(summary.unchanged, 1);
    assert_eq!(summary.corrected, 0);

    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_credit_ledger \
         WHERE funding_source_id = $1 AND kind = 'reconcile'",
    )
    .bind(source)
    .fetch_one(&db.pool)
    .await
    .expect("count reconcile rows");
    assert_eq!(
        rows, 1,
        "the same tick re-run does not append a second reconcile"
    );
}

// ---------------------------------------------------------------------------
// Provider unavailable: the prior row keeps serving.
// ---------------------------------------------------------------------------

/// A provider that is unreachable for one source keeps the prior believed balance
/// serving (it is not blanked) and records a stale-visibility marker; a sibling
/// source whose provider answers still reconciles, so one outage does not starve
/// the pass.
#[tokio::test]
async fn provider_unavailable_keeps_the_prior_row_serving() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let stale = seed_funding_source(&db.pool, operator, "turbo", "addr-stale").await;
    let healthy = seed_funding_source(&db.pool, operator, "turbo", "addr-ok").await;

    // First tick: both providers answer, both balances stamped.
    let up = StubWincProvider::default()
        .with_balance("addr-stale", 40_000, Some(800_000))
        .with_balance("addr-ok", 60_000, Some(900_000));
    run_reconcile(
        &db.pool,
        &up,
        &StubRegistrar::default(),
        "turbo",
        "tick-1",
        &config(1_000, 100_000),
    )
    .await
    .expect("first pass");

    // Second tick: the stale source's provider is down; the healthy one answers
    // with a moved balance.
    let down = StubWincProvider::default()
        .with_unavailable("addr-stale", "connection reset")
        .with_balance("addr-ok", 65_000, Some(900_000));
    let summary = run_reconcile(
        &db.pool,
        &down,
        &StubRegistrar::default(),
        "turbo",
        "tick-2",
        &config(1_000, 100_000),
    )
    .await
    .expect("second pass");

    assert_eq!(
        summary.unavailable, 1,
        "the down source is counted unavailable"
    );

    // The stale source keeps its prior balance (40_000) and gains a stale-error
    // marker; it is NOT blanked.
    let stale_credit = load_credit(&db.pool, stale)
        .await
        .expect("load stale credit")
        .expect("the prior row still exists");
    assert_eq!(
        stale_credit.winc_balance,
        Decimal::from(40_000),
        "the prior believed balance keeps serving when the provider is down"
    );
    assert!(
        stale_credit.last_error.is_some(),
        "the down source records a stale-visibility marker"
    );

    // No reconcile row was appended for the down source on tick-2.
    let stale_reconciles: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_credit_ledger \
         WHERE funding_source_id = $1 AND kind = 'reconcile' AND ref = 'tick-2'",
    )
    .bind(stale)
    .fetch_one(&db.pool)
    .await
    .expect("count down-source reconciles");
    assert_eq!(
        stale_reconciles, 0,
        "a down provider appends no reconcile delta"
    );

    // The healthy source still reconciled to its moved value.
    let ok_credit = load_credit(&db.pool, healthy)
        .await
        .expect("load healthy credit")
        .expect("healthy source row");
    assert_eq!(
        ok_credit.winc_balance,
        Decimal::from(65_000),
        "the sibling source still reconciles despite the other's outage"
    );
    assert!(
        ok_credit.last_error.is_none(),
        "a successful reconcile clears any prior stale-error marker"
    );
}

// ---------------------------------------------------------------------------
// Drift: live moved more than the gateway's charges explain -> alert + self-correct.
// ---------------------------------------------------------------------------

/// The gateway's believed balance reflects only its own charges; when the live
/// provider balance is BELOW the believed one by more than the drift threshold (a
/// provider-side spend the gateway did not bill for, e.g. a crash-tail duplicate
/// POST), the reconcile loop emits `storage.credit.drift` AND the `reconcile` row
/// self-corrects the believed balance back to the live value.
#[tokio::test]
async fn a_drift_beyond_the_threshold_alerts_and_self_corrects() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator, "turbo", "addr-drift").await;

    // The gateway believes it has spent down to 100_000 (a charge it appended for
    // an upload it billed).
    insert_credit_entry(
        &db.pool,
        &CreditEntry {
            funding_source_id: source,
            kind: CreditKind::Charge,
            winc_delta: Decimal::from(100_000),
            r#ref: Some("attempt-1".into()),
        },
    )
    .await
    .expect("seed believed charge");

    // The provider's ACTUAL balance is 70_000: 30_000 lower than believed, more
    // than the 10_000 drift threshold. (A second, unbilled provider-side spend.)
    let provider = StubWincProvider::default().with_balance("addr-drift", 70_000, Some(700_000));
    let summary = run_reconcile(
        &db.pool,
        &provider,
        &StubRegistrar::default(),
        "turbo",
        "tick-drift",
        &config(1_000, 10_000),
    )
    .await
    .expect("reconcile pass");

    assert_eq!(summary.drift_emitted, 1, "the drift exceeds the threshold");
    assert_eq!(summary.corrected, 1, "the believed balance is corrected");

    let events = credit_events(&db.pool, source).await;
    assert!(
        events.contains(&CREDIT_DRIFT_EVENT.to_string()),
        "a storage.credit.drift event fires, got {events:?}"
    );

    // The reconcile row brought the believed balance to the live value.
    let credit = load_credit(&db.pool, source)
        .await
        .expect("load credit")
        .expect("materialized row")
        .winc_balance;
    assert_eq!(
        credit,
        Decimal::from(70_000),
        "the reconcile self-corrects the believed balance to the live value"
    );
}

/// A live balance that moved within the drift threshold reconciles WITHOUT a drift
/// alert: ordinary believed-vs-live skew is not an anomaly.
#[tokio::test]
async fn a_small_drift_reconciles_without_an_alert() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator, "turbo", "addr-small").await;

    insert_credit_entry(
        &db.pool,
        &CreditEntry {
            funding_source_id: source,
            kind: CreditKind::Charge,
            winc_delta: Decimal::from(100_000),
            r#ref: Some("attempt-1".into()),
        },
    )
    .await
    .expect("seed believed charge");

    // Live is 95_000: a 5_000 delta, under the 10_000 threshold.
    let provider = StubWincProvider::default().with_balance("addr-small", 95_000, Some(950_000));
    let summary = run_reconcile(
        &db.pool,
        &provider,
        &StubRegistrar::default(),
        "turbo",
        "tick-small",
        &config(1_000, 10_000),
    )
    .await
    .expect("reconcile pass");

    assert_eq!(
        summary.corrected, 1,
        "the believed balance is still corrected"
    );
    assert_eq!(
        summary.drift_emitted, 0,
        "a within-threshold delta is not an alert"
    );

    let events = credit_events(&db.pool, source).await;
    assert!(
        !events.contains(&CREDIT_DRIFT_EVENT.to_string()),
        "no drift event for a within-threshold delta, got {events:?}"
    );
}

// ---------------------------------------------------------------------------
// Top-up absorption: an operator's own funding is explained movement, not drift.
// ---------------------------------------------------------------------------

/// A registered top-up whose provider credit landed between ticks is settled
/// BEFORE the drift comparison: the reconcile pass polls it to `credited`,
/// journals the winc into the believed balance exactly once, and the live
/// jump the credit caused reads as fully explained — no `storage.credit.drift`
/// fires even though the movement dwarfs the alert threshold.
#[tokio::test]
async fn a_landed_top_up_is_absorbed_instead_of_alerting_drift() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator, "turbo", "addr-fund").await;

    // The accepted conversion: 500_000 winc, well above the 10_000 drift
    // threshold, pending at the provider until confirmation depth.
    let winc = 500_000_i64;
    let topup = seed_registered_topup(&db.pool, operator, source, "fund-tx-1", winc).await;

    // Between ticks the credit landed: the live balance jumped by the full
    // top-up and the registration poll now reports it credited.
    let provider = StubWincProvider::default().with_balance("addr-fund", winc, Some(1_000_000));
    let registrar = StubRegistrar::default().with_credited("fund-tx-1", winc);

    let summary = run_reconcile(
        &db.pool,
        &provider,
        &registrar,
        "turbo",
        "tick-fund",
        &config(1_000, 10_000),
    )
    .await
    .expect("reconcile pass");

    assert_eq!(summary.topups_credited, 1, "the landed top-up was settled");
    assert_eq!(
        summary.drift_emitted, 0,
        "an operator's own top-up is not drift"
    );
    assert_eq!(
        summary.unchanged, 1,
        "after absorption the believed balance already matched the live one"
    );
    assert_eq!(summary.corrected, 0, "no reconcile delta was needed");

    let events = credit_events(&db.pool, source).await;
    assert!(
        !events.contains(&CREDIT_DRIFT_EVENT.to_string()),
        "no storage.credit.drift for a journalled top-up, got {events:?}"
    );

    // The top-up row is terminal with its credit instant stamped.
    let (status, credited_at_set): (String, bool) = sqlx::query_as(
        "SELECT status, credited_at IS NOT NULL FROM cw_core.storage_topup WHERE id = $1",
    )
    .bind(topup)
    .fetch_one(&db.pool)
    .await
    .expect("top-up row");
    assert_eq!(status, "credited");
    assert!(
        credited_at_set,
        "credited_at is stamped alongside the journal row"
    );

    // Exactly one `topup` journal row, keyed on the top-up id, carrying the
    // credited amount; the believed balance absorbed it.
    let (rows, journalled): (i64, Decimal) = sqlx::query_as(
        "SELECT count(*), COALESCE(sum(winc_delta), 0) FROM cw_core.storage_credit_ledger \
         WHERE funding_source_id = $1 AND kind = 'topup' AND ref = $2",
    )
    .bind(source)
    .bind(topup.to_string())
    .fetch_one(&db.pool)
    .await
    .expect("count topup journal rows");
    assert_eq!(rows, 1);
    assert_eq!(journalled, Decimal::from(winc));

    let balance = load_credit(&db.pool, source)
        .await
        .expect("load credit")
        .expect("materialized row")
        .winc_balance;
    assert_eq!(
        balance,
        Decimal::from(winc),
        "the believed balance absorbed exactly the credited amount"
    );

    // A second pass with the same scripted answers is a no-op: the top-up is
    // terminal, so it is neither re-polled nor journalled twice.
    let second = run_reconcile(
        &db.pool,
        &provider,
        &registrar,
        "turbo",
        "tick-fund-2",
        &config(1_000, 10_000),
    )
    .await
    .expect("second pass");
    assert_eq!(second.topups_credited, 0);
    assert_eq!(second.unchanged, 1);
    assert_eq!(second.drift_emitted, 0);

    let topup_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_credit_ledger \
         WHERE funding_source_id = $1 AND kind = 'topup'",
    )
    .bind(source)
    .fetch_one(&db.pool)
    .await
    .expect("count topup journal rows");
    assert_eq!(topup_rows, 1, "the credit is journalled exactly once");
}

// ---------------------------------------------------------------------------
// Low credit: a live balance below the floor alerts the operator.
// ---------------------------------------------------------------------------

/// A live balance at or below the safety floor emits `storage.credit.low`, off the
/// LIVE balance, so an operator is warned the moment a provider read shows they must
/// top up.
#[tokio::test]
async fn a_live_balance_below_the_floor_emits_credit_low() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator, "turbo", "addr-low").await;

    let provider = StubWincProvider::default().with_balance("addr-low", 500, Some(0));
    let summary = run_reconcile(
        &db.pool,
        &provider,
        &StubRegistrar::default(),
        "turbo",
        "tick-low",
        &config(1_000, 10_000),
    )
    .await
    .expect("reconcile pass");

    assert_eq!(
        summary.low_emitted, 1,
        "the live balance is below the floor"
    );

    let events = credit_events(&db.pool, source).await;
    assert!(
        events.contains(&CREDIT_LOW_EVENT.to_string()),
        "a storage.credit.low event fires, got {events:?}"
    );
}

// ---------------------------------------------------------------------------
// Cached-credit affordability: no provider call on the request path.
// ---------------------------------------------------------------------------

/// The cached-credit `affords` read refuses an unfunded source, a source at/below
/// the floor, and a chargeable size over the provider's fundable ceiling, and
/// admits an affordable one, reading only the materialized row.
#[tokio::test]
async fn affords_reads_the_cached_credit_only() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator, "turbo", "addr-aff").await;

    let floor = Decimal::from(1_000);

    // No materialized row yet: unknown is unfunded.
    assert_eq!(
        affords(&db.pool, source, 100, floor)
            .await
            .expect("affords unfunded"),
        AffordVerdict::Unfunded
    );

    // Stamp a funded balance (above the floor) with a fundable-byte ceiling.
    let provider = StubWincProvider::default().with_balance("addr-aff", 50_000, Some(1_000));
    run_reconcile(
        &db.pool,
        &provider,
        &StubRegistrar::default(),
        "turbo",
        "tick-aff",
        &config(1_000, 100_000),
    )
    .await
    .expect("reconcile to stamp the balance");

    // Within the ceiling and above the floor: affordable.
    assert_eq!(
        affords(&db.pool, source, 500, floor)
            .await
            .expect("affords ok"),
        AffordVerdict::Affordable
    );
    // Over the fundable-byte ceiling: refused.
    assert_eq!(
        affords(&db.pool, source, 1_001, floor)
            .await
            .expect("affords over-ceiling"),
        AffordVerdict::InsufficientForBytes
    );
    // Raise the floor above the balance: refused.
    assert_eq!(
        affords(&db.pool, source, 1, Decimal::from(60_000))
            .await
            .expect("affords below floor"),
        AffordVerdict::BelowSafetyFloor
    );
}

// ---------------------------------------------------------------------------
// Journal append idempotency.
// ---------------------------------------------------------------------------

/// The winc journal append is idempotent on (funding_source_id, kind, ref): a
/// retried append of the same charge reports AlreadyApplied and does not move the
/// balance twice; a same-(source, kind, ref) append with a DIFFERENT delta is a
/// caller-bug error, not a silent overwrite.
#[tokio::test]
async fn the_winc_journal_append_is_idempotent_on_source_kind_ref() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator, "turbo", "addr-idem").await;

    let entry = CreditEntry {
        funding_source_id: source,
        kind: CreditKind::Charge,
        winc_delta: Decimal::from(-3_000),
        r#ref: Some("attempt-1".into()),
    };

    assert_eq!(
        insert_credit_entry(&db.pool, &entry)
            .await
            .expect("first append"),
        CreditOutcome::Inserted
    );
    assert_eq!(
        insert_credit_entry(&db.pool, &entry)
            .await
            .expect("retried append"),
        CreditOutcome::AlreadyApplied,
        "a faithful retry is an idempotent no-op"
    );

    // The balance moved exactly once.
    let balance = load_credit(&db.pool, source)
        .await
        .expect("load credit")
        .expect("row")
        .winc_balance;
    assert_eq!(
        balance,
        Decimal::from(-3_000),
        "the retry did not move the balance a second time"
    );

    // A same-(source, kind, ref) append with a different delta is a caller bug.
    let conflicting = CreditEntry {
        winc_delta: Decimal::from(-9_999),
        ..entry.clone()
    };
    assert!(
        insert_credit_entry(&db.pool, &conflicting).await.is_err(),
        "a different delta on the same (source, kind, ref) is rejected, not silently overwritten"
    );

    // A zero delta is rejected before the round trip.
    let zero = CreditEntry {
        winc_delta: Decimal::ZERO,
        r#ref: Some("attempt-zero".into()),
        ..entry.clone()
    };
    assert!(
        insert_credit_entry(&db.pool, &zero).await.is_err(),
        "a zero winc_delta is rejected"
    );
}

/// A retried reconcile tick recomputes its delta from a moving live balance,
/// so the same `(source, reconcile, tick)` ref can legitimately carry a
/// DIFFERENT value on the retry. That conflict is a benign no-op — the
/// existing row already proves this tick corrected this source — and the
/// balance moves exactly once; any residual movement is the next tick's
/// business. (A hard error here would wedge the tick forever: every retry
/// recomputes, every recompute mismatches.)
#[tokio::test]
async fn a_reconcile_retry_whose_live_balance_moved_is_a_benign_no_op() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let source = seed_funding_source(&db.pool, operator, "turbo", "addr-retick").await;

    let first = CreditEntry {
        funding_source_id: source,
        kind: CreditKind::Reconcile,
        winc_delta: Decimal::from(40_000),
        r#ref: Some("tick-r".into()),
    };
    assert_eq!(
        insert_credit_entry(&db.pool, &first)
            .await
            .expect("first append"),
        CreditOutcome::Inserted
    );

    // The retry of the same tick, recomputed after the live balance moved.
    let moved = CreditEntry {
        winc_delta: Decimal::from(55_000),
        ..first.clone()
    };
    assert_eq!(
        insert_credit_entry(&db.pool, &moved)
            .await
            .expect("retried append with a moved delta"),
        CreditOutcome::AlreadyApplied,
        "a recomputed reconcile delta on the same tick ref is a no-op, not a hard error"
    );

    // The balance moved exactly once, by the first attempt's delta.
    let balance = load_credit(&db.pool, source)
        .await
        .expect("load credit")
        .expect("materialized row")
        .winc_balance;
    assert_eq!(balance, Decimal::from(40_000));

    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_credit_ledger \
         WHERE funding_source_id = $1 AND kind = 'reconcile' AND ref = 'tick-r'",
    )
    .bind(source)
    .fetch_one(&db.pool)
    .await
    .expect("count reconcile rows");
    assert_eq!(rows, 1, "one correction per (source, tick)");
}

// ---------------------------------------------------------------------------
// active_funding_sources scoping.
// ---------------------------------------------------------------------------

/// The reconcile loop refreshes only ACTIVE sources for the backend: a draining or
/// retired source, and a source on another backend, are excluded.
#[tokio::test]
async fn active_funding_sources_scopes_to_active_rows_for_the_backend() {
    let db = TestDb::fresh().await.expect("fresh db");
    let operator = seed_operator(&db.pool, "op").await;
    let active = seed_funding_source(&db.pool, operator, "turbo", "addr-active").await;
    let draining = seed_funding_source(&db.pool, operator, "turbo", "addr-draining").await;
    let other_backend = seed_funding_source(&db.pool, operator, "arlocal", "addr-other").await;

    sqlx::query("UPDATE cw_core.storage_funding_source SET status = 'draining' WHERE id = $1")
        .bind(draining)
        .execute(&db.pool)
        .await
        .expect("drain a source");

    let sources = active_funding_sources(&db.pool, "turbo")
        .await
        .expect("list active turbo sources");
    let ids: Vec<Uuid> = sources.iter().map(|s| s.id).collect();

    assert!(ids.contains(&active), "the active turbo source is listed");
    assert!(!ids.contains(&draining), "a draining source is excluded");
    assert!(
        !ids.contains(&other_backend),
        "a source on another backend is excluded"
    );
}
