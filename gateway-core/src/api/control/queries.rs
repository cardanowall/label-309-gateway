//! Read-side queries the control surface projects onto its list/usage responses.
//!
//! These are the operator-facing reads the control routes return: the account
//! roster under an operator, an account's usage counters, the api keys on an
//! account, and the wallet roster with per-wallet UTxO statistics. They are kept
//! here, beside the control routes, so the control surface's read shapes never
//! leak into the engine's internal modules.
//!
//! Every read is tenancy-scoped by the owning `operator_id`: the roster reads
//! filter on it directly, and the per-account reads (`account_usage`,
//! `list_account_keys`) confirm the account belongs to the operator and return
//! `None` for an account that is absent or owned by another operator (the route
//! renders that as a 404, with no cross-tenant existence oracle).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::wallet::config::Network;
use crate::wallet::operator::WalletStatus;
use crate::Result;

/// One account row in the operator's account roster.
#[derive(Debug, Clone)]
pub struct AccountSummary {
    /// The account id.
    pub account_id: Uuid,
    /// The owning operator.
    pub operator_id: Uuid,
    /// The account's lifecycle status (`active` / `disabled`).
    pub status: String,
    /// The account's current balance in micro-USD (zero when no ledger activity).
    pub balance_micros: i64,
    /// When the account was created.
    pub created_at: DateTime<Utc>,
}

/// List the accounts under an operator, newest-first, up to `limit`.
///
/// Joins the account anchor, its satellite (for the status), and the materialised
/// balance (a missing balance row reads as zero). Soft-deleted accounts are
/// excluded.
pub async fn list_accounts(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    limit: i64,
) -> Result<Vec<AccountSummary>> {
    let rows: Vec<AccountRow> = sqlx::query_as(
        "SELECT a.id, d.operator_id, d.status, \
                COALESCE(b.balance_micros, 0) AS balance_micros, a.created_at \
         FROM cw_api.account a \
         JOIN cw_core.account_detail d ON d.account_id = a.id \
         LEFT JOIN cw_core.balance b ON b.account_id = a.id \
         WHERE d.operator_id = $1 AND a.deleted_at IS NULL \
         ORDER BY a.id DESC \
         LIMIT $2",
    )
    .bind(operator_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| AccountSummary {
            account_id: r.id,
            operator_id: r.operator_id,
            status: r.status,
            balance_micros: r.balance_micros,
            created_at: r.created_at,
        })
        .collect())
}

/// The usage counters for one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUsage {
    /// The account's lifecycle status (`active` / `disabled`). A caller about to
    /// move money toward this account (e.g. posting a credit) reads it here to
    /// refuse a credit to a disabled account rather than orphaning funds on one.
    pub status: String,
    /// The account's current balance in micro-USD.
    pub balance_micros: i64,
    /// The number of ledger entries on the account.
    pub ledger_entry_count: i64,
    /// The number of quotes the account has issued.
    pub quote_count: i64,
    /// The number of quotes the account has consumed (a publish each).
    pub publish_count: i64,
}

/// Read an account's usage counters in one round trip, scoped to `operator_id`.
///
/// The query is gated on the account belonging to the operator: an `account_detail`
/// row for the pair must exist, so an account that is absent or owned by another
/// operator returns `None` (the route renders a 404). For an owned account the
/// balance is the materialised running sum and the ledger / quote / publish counts
/// come from aggregate scans over the account's rows (zeroed for no activity).
pub async fn account_usage(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
) -> Result<Option<AccountUsage>> {
    let row: Option<UsageRow> = sqlx::query_as(
        "SELECT \
           d.status AS status, \
           COALESCE((SELECT balance_micros FROM cw_core.balance WHERE account_id = d.account_id), 0) \
             AS balance_micros, \
           (SELECT count(*) FROM cw_core.balance_ledger WHERE account_id = d.account_id) \
             AS ledger_entry_count, \
           (SELECT count(*) FROM cw_core.publish_quote WHERE account_id = d.account_id) \
             AS quote_count, \
           (SELECT count(*) FROM cw_core.publish_quote \
              WHERE account_id = d.account_id AND status = 'consumed') AS publish_count \
         FROM cw_core.account_detail d \
         WHERE d.account_id = $1 AND d.operator_id = $2",
    )
    .bind(account_id)
    .bind(operator_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| AccountUsage {
        status: row.status,
        balance_micros: row.balance_micros,
        ledger_entry_count: row.ledger_entry_count,
        quote_count: row.quote_count,
        publish_count: row.publish_count,
    }))
}

/// One api-key row in an account's key listing. The secret is never returned by a
/// listing (it is shown once at creation only); a listing carries metadata only.
#[derive(Debug, Clone)]
pub struct ApiKeySummary {
    /// The key id.
    pub key_id: Uuid,
    /// The operator-chosen secret prefix the key was issued under.
    pub prefix: String,
    /// The scopes the key carries.
    pub scopes: Vec<String>,
    /// The key's custom per-minute request budget, or `None` when it meters
    /// against the data-plane default.
    pub rate_limit_per_min: Option<i32>,
    /// The operator label, when set.
    pub label: Option<String>,
    /// When the key was created.
    pub created_at: DateTime<Utc>,
    /// When the key was last used, when ever.
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the key was revoked, when revoked (a listing shows revoked keys too).
    pub revoked_at: Option<DateTime<Utc>>,
}

/// List an account's api keys under `operator_id`, newest-first, up to `limit`.
///
/// Gated on the account belonging to the operator: an account that is absent or
/// owned by another operator returns `None` (the route renders a 404), never an
/// empty list, so a cross-tenant probe cannot distinguish "no keys" from "not
/// yours". For an owned account the listing includes revoked keys (it is the audit
/// view of every key the account has held). The keys themselves are joined back to
/// the operator so only keys on the owned account are returned.
pub async fn list_account_keys(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    account_id: Uuid,
    limit: i64,
) -> Result<Option<Vec<ApiKeySummary>>> {
    // Confirm ownership first: a separate, cheap existence check so a missing
    // account is reported as absent rather than as an empty key list.
    if !crate::ledger::account::account_belongs_to_operator(pool, operator_id, account_id).await? {
        return Ok(None);
    }

    let rows: Vec<KeyRow> = sqlx::query_as(
        "SELECT k.id, k.prefix, k.scopes, k.rate_limit_per_min, k.label, \
                k.created_at, k.last_used_at, k.revoked_at \
         FROM cw_core.api_key k \
         JOIN cw_core.account_detail d ON d.account_id = k.account_id \
         WHERE k.account_id = $1 AND d.operator_id = $2 \
         ORDER BY k.id DESC \
         LIMIT $3",
    )
    .bind(account_id)
    .bind(operator_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(Some(
        rows.into_iter()
            .map(|r| ApiKeySummary {
                key_id: r.id,
                prefix: r.prefix,
                scopes: r.scopes,
                rate_limit_per_min: r.rate_limit_per_min,
                label: r.label,
                created_at: r.created_at,
                last_used_at: r.last_used_at,
                revoked_at: r.revoked_at,
            })
            .collect(),
    ))
}

/// One wallet row in the operator's wallet roster, with its UTxO statistics.
#[derive(Debug, Clone)]
pub struct WalletSummary {
    /// The wallet id.
    pub wallet_id: Uuid,
    /// The operator that registered (administers) the wallet.
    pub registrar_operator_id: Uuid,
    /// The operator label.
    pub label: String,
    /// The stable payment address.
    pub address: String,
    /// The network the wallet is pinned to.
    pub network: Network,
    /// The wallet's lifecycle status.
    pub status: WalletStatus,
    /// The number of tracked UTxOs currently `available` for spend.
    pub available_utxos: i64,
    /// The number of `available` UTxOs that are also `canonical` (the band-shaped
    /// outputs the quote prices and the scheduler counts).
    pub canonical_utxos: i64,
    /// When the wallet was registered.
    pub created_at: DateTime<Utc>,
}

/// List the wallets an operator registered, with per-wallet UTxO statistics, in
/// stable id order up to `limit`.
///
/// Scoped to the wallets this operator administers (its `registrar_operator_id`),
/// so the roster is the operator's own wallets, not every wallet a grant may let
/// it spend. The two UTxO counts come from a correlated aggregate over
/// `cw_core.wallet_utxo`: `available_utxos` counts spendable outputs,
/// `canonical_utxos` the band-shaped subset the quote relies on. A wallet with no
/// tracked UTxOs reports zero for both.
pub async fn list_wallets(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    limit: i64,
) -> Result<Vec<WalletSummary>> {
    let rows: Vec<WalletRow> = sqlx::query_as(
        "SELECT w.id, w.registrar_operator_id, w.label, w.address, w.network, w.status, \
                w.created_at, \
                COALESCE(u.available_utxos, 0) AS available_utxos, \
                COALESCE(u.canonical_utxos, 0) AS canonical_utxos \
         FROM cw_core.operator_wallet w \
         LEFT JOIN ( \
             SELECT wallet_id, \
                    count(*) FILTER (WHERE state = 'available') AS available_utxos, \
                    count(*) FILTER (WHERE state = 'available' AND canonical) AS canonical_utxos \
             FROM cw_core.wallet_utxo \
             GROUP BY wallet_id \
         ) u ON u.wallet_id = w.id \
         WHERE w.registrar_operator_id = $1 \
         ORDER BY w.id \
         LIMIT $2",
    )
    .bind(operator_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|r| {
            Ok(WalletSummary {
                wallet_id: r.id,
                registrar_operator_id: r.registrar_operator_id,
                label: r.label,
                address: r.address,
                network: Network::parse(&r.network)?,
                status: r.status,
                available_utxos: r.available_utxos,
                canonical_utxos: r.canonical_utxos,
                created_at: r.created_at,
            })
        })
        .collect()
}

/// One control credential in the operator's credential roster. Ids and
/// lifecycle only — a stored credential's secret is unrecoverable by design, so
/// there is nothing sensitive to project.
#[derive(Debug, Clone)]
pub struct CredentialSummary {
    /// The credential row id (the rotate / revoke handle).
    pub credential_id: Uuid,
    /// The credential class (`operator_root`).
    pub kind: String,
    /// The operator's free-text label, when one was set.
    pub label: Option<String>,
    /// When the credential was minted.
    pub created_at: DateTime<Utc>,
    /// When the credential was revoked, or `None` while live.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// List an operator's control credentials, newest-first up to `limit`.
///
/// The enumeration half of the credential lifecycle: an operator responding to
/// an incident reads this roster to find the credential id to rotate or revoke.
/// Revoked credentials stay listed (revocation is a timestamp, not a delete), so
/// the roster doubles as rotation history.
pub async fn list_credentials(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    limit: i64,
) -> Result<Vec<CredentialSummary>> {
    let rows: Vec<CredentialRow> = sqlx::query_as(
        "SELECT id, kind, label, created_at, revoked_at \
         FROM cw_core.control_credential \
         WHERE operator_id = $1 \
         ORDER BY id DESC \
         LIMIT $2",
    )
    .bind(operator_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| CredentialSummary {
            credential_id: r.id,
            kind: r.kind,
            label: r.label,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
        })
        .collect())
}

/// One access token in the operator's token roster. Ids and lifecycle only —
/// the token secret is unrecoverable by design.
#[derive(Debug, Clone)]
pub struct AccessTokenSummary {
    /// The token row id (the revoke handle).
    pub token_id: Uuid,
    /// The account the token is scoped to, or `None` for an operator token.
    pub account_id: Option<Uuid>,
    /// The data-plane scopes an account-scoped token carries.
    pub scopes: Vec<String>,
    /// The row id of the credential that minted the token, when lineage is
    /// recorded (the chain a credential revocation cascades through).
    pub minted_by: Option<Uuid>,
    /// When the token stops authenticating by expiry.
    pub expires_at: DateTime<Utc>,
    /// When the token was minted.
    pub created_at: DateTime<Utc>,
    /// When the token was revoked, or `None` while un-revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// List an operator's access tokens, newest-first up to `limit`.
///
/// The enumeration half of the targeted token kill switch: an operator hunting
/// a leaked token reads this roster (mint time, account binding, lineage) to
/// pick the id to revoke. Expired and revoked tokens stay listed within the
/// page so the roster shows recent history, not just the live set.
pub async fn list_access_tokens(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    limit: i64,
) -> Result<Vec<AccessTokenSummary>> {
    let rows: Vec<AccessTokenRow> = sqlx::query_as(
        "SELECT id, account_id, scopes, minted_by, expires_at, created_at, revoked_at \
         FROM cw_core.access_token \
         WHERE operator_id = $1 \
         ORDER BY id DESC \
         LIMIT $2",
    )
    .bind(operator_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| AccessTokenSummary {
            token_id: r.id,
            account_id: r.account_id,
            scopes: r.scopes,
            minted_by: r.minted_by,
            expires_at: r.expires_at,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
        })
        .collect())
}

/// The columns the account-roster query reads back.
#[derive(sqlx::FromRow)]
struct AccountRow {
    id: Uuid,
    operator_id: Uuid,
    status: String,
    balance_micros: i64,
    created_at: DateTime<Utc>,
}

/// The columns the usage query reads back.
#[derive(sqlx::FromRow)]
struct UsageRow {
    status: String,
    balance_micros: i64,
    ledger_entry_count: i64,
    quote_count: i64,
    publish_count: i64,
}

/// The columns the key-listing query reads back.
#[derive(sqlx::FromRow)]
struct KeyRow {
    id: Uuid,
    prefix: String,
    scopes: Vec<String>,
    rate_limit_per_min: Option<i32>,
    label: Option<String>,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

/// The columns the credential-roster query reads back.
#[derive(sqlx::FromRow)]
struct CredentialRow {
    id: Uuid,
    kind: String,
    label: Option<String>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

/// The columns the token-roster query reads back.
#[derive(sqlx::FromRow)]
struct AccessTokenRow {
    id: Uuid,
    account_id: Option<Uuid>,
    scopes: Vec<String>,
    minted_by: Option<Uuid>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

/// The columns the wallet-roster query reads back.
#[derive(sqlx::FromRow)]
struct WalletRow {
    id: Uuid,
    registrar_operator_id: Uuid,
    label: String,
    address: String,
    network: String,
    status: WalletStatus,
    created_at: DateTime<Utc>,
    available_utxos: i64,
    canonical_utxos: i64,
}

/// One endpoint's webhook health row in the operator's health summary.
///
/// Surfaces a degrading or dead endpoint without scanning its deliveries list: the
/// failure population (`dead_deliveries`), the in-flight backlog
/// (`pending_deliveries`), the auto-disable accumulator (`consecutive_failures`),
/// and the oldest pending instants so a stuck backlog is visible at a glance.
#[derive(Debug, Clone)]
pub struct WebhookHealthSummary {
    /// The endpoint id.
    pub endpoint_id: Uuid,
    /// Whether the endpoint is the operator's own firehose (`operator`) or an
    /// account-scoped subscription under the operator (`account`).
    pub scope_kind: String,
    /// The endpoint's lifecycle status (`active` / `paused` / `disabled`).
    pub status: String,
    /// Consecutive fully-exhausted deliveries (the auto-disable accumulator).
    pub consecutive_failures: i32,
    /// The last instant a delivery to this endpoint succeeded.
    pub last_success_at: Option<DateTime<Utc>>,
    /// The count of `failed` (dead-letter) deliveries.
    pub dead_deliveries: i64,
    /// The count of `pending` (in-flight) deliveries.
    pub pending_deliveries: i64,
    /// The soonest a pending delivery becomes due, or `None` when none is pending.
    pub oldest_pending_due: Option<DateTime<Utc>>,
    /// When the oldest pending delivery was fanned out, or `None` when none is
    /// pending (so an old, stuck backlog is visible).
    pub oldest_pending_at: Option<DateTime<Utc>>,
}

/// The columns the webhook-health query reads back from the `webhook_health` view.
#[derive(sqlx::FromRow)]
struct WebhookHealthRow {
    endpoint_id: Uuid,
    scope_kind: String,
    status: String,
    consecutive_failures: i32,
    last_success_at: Option<DateTime<Utc>>,
    dead_deliveries: i64,
    pending_deliveries: i64,
    oldest_pending_due: Option<DateTime<Utc>>,
    oldest_pending_at: Option<DateTime<Utc>>,
}

/// The webhook-health summary for every endpoint under an operator.
///
/// Reads the live `cw_core.webhook_health` view (an aggregate that always reflects
/// the current delivery population, with no write path of its own) and scopes it to
/// the operator: an account-scoped endpoint counts when its account belongs to the
/// operator (joined through `account_detail`), and an operator-scoped firehose
/// counts when its `operator_id` is the operator's. A degrading endpoint owned by
/// another operator is never visible, so the summary cannot leak another tenant's
/// failure population. Ordered worst-first by the dead-then-pending population so
/// the endpoints that need attention sort to the top, up to `limit`.
pub async fn webhook_health(
    pool: &sqlx::PgPool,
    operator_id: Uuid,
    limit: i64,
) -> Result<Vec<WebhookHealthSummary>> {
    let rows: Vec<WebhookHealthRow> = sqlx::query_as(
        "SELECT h.endpoint_id, h.scope_kind, h.status, h.consecutive_failures, \
                h.last_success_at, h.dead_deliveries, h.pending_deliveries, \
                h.oldest_pending_due, h.oldest_pending_at \
         FROM cw_core.webhook_health h \
         JOIN cw_core.webhook_endpoint e ON e.id = h.endpoint_id \
         LEFT JOIN cw_core.account_detail ad ON ad.account_id = e.account_id \
         WHERE (e.scope_kind = 'operator' AND e.operator_id = $1) \
            OR (e.scope_kind = 'account'  AND ad.operator_id = $1) \
         ORDER BY h.dead_deliveries DESC, h.pending_deliveries DESC, h.endpoint_id \
         LIMIT $2",
    )
    .bind(operator_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| WebhookHealthSummary {
            endpoint_id: r.endpoint_id,
            scope_kind: r.scope_kind,
            status: r.status,
            consecutive_failures: r.consecutive_failures,
            last_success_at: r.last_success_at,
            dead_deliveries: r.dead_deliveries,
            pending_deliveries: r.pending_deliveries,
            oldest_pending_due: r.oldest_pending_due,
            oldest_pending_at: r.oldest_pending_at,
        })
        .collect())
}
