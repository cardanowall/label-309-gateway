//! Conformance harness for the Label 309 gateway.
//!
//! Boots the in-repo gateway engine (its `/api/v1/*` router over a fresh
//! database, with the pricing and storage seams a deployment supplies) and drives
//! it with the PUBLISHED SDK/CLI artifacts (pinned to exact released versions, as
//! registry dependencies rather than in-repo paths). The point is byte stability:
//! a regression in the gateway's wire shape surfaces as a deserialize failure in
//! the real published client a third party would install.
//!
//! Two ways to point the harness at a gateway:
//!
//! - **Boot one in-process.** [`BootedGateway::start`] creates an isolated
//!   database, runs the migrator, wires a conformance pricing seam, serves the
//!   engine router on an ephemeral port, and seeds an operator/account/api-key
//!   directly (there is no public key-issuance API yet, so the harness writes the
//!   credential into the database). The published clients drive it over real HTTP.
//!   This is what the default live suite uses.
//! - **Target an external one.** [`base_url`] and [`database_url`] read
//!   `GATEWAY_BASE_URL` and `GATEWAY_CONFORMANCE_DATABASE_URL`, so the same flows
//!   can run against a separately booted binary (for the live preprod leg).
//!
//! The chain side is stubbed for every flow except the live preprod leg in the
//! gate: [`BootedGateway::stub_confirm`] anchors a published record into the
//! indexer exactly as the confirm loop's threshold flip would, so the records
//! read surface returns it without a real submission.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use sqlx::Connection;
use uuid::Uuid;

use gateway_core::wallet::keyring::{UnlockedKeyring, WebhookWrapKey};
use gateway_core::webhook::egress::EgressConfig;
use gateway_core::webhook::{DeliveryHandler, FanoutHandler};

pub mod receiver;

/// The environment variable carrying the base URL of an externally booted gateway.
pub const GATEWAY_BASE_URL_ENV: &str = "GATEWAY_BASE_URL";

/// The environment variable carrying the database URL the harness seeds into when
/// targeting an external gateway.
pub const DATABASE_URL_ENV: &str = "GATEWAY_CONFORMANCE_DATABASE_URL";

/// The admin database URL the boot path creates per-run databases through.
///
/// Points at the server's `postgres` database; the final path segment of
/// [`DEFAULT_BASE_DATABASE_URL`] is the base name per-run databases derive from.
pub const ADMIN_DATABASE_URL_ENV: &str = "GATEWAY_CONFORMANCE_ADMIN_DATABASE_URL";

/// The default base database URL the boot path derives per-run database names
/// from when [`DATABASE_URL_ENV`] is unset. Matches the engine test harness's
/// default server and credentials.
pub const DEFAULT_BASE_DATABASE_URL: &str =
    "postgres://cardanowall:cardanowall_dev@localhost:5432/cardanowall_gateway_conformance";

/// The number of leading SHA-256 bytes the gateway uses as the key lookup prefix.
const KEY_LOOKUP_BYTES: usize = 8;

/// A seeded tenant: the account id and the plaintext API key the harness drives
/// the published clients with.
#[derive(Debug, Clone)]
pub struct SeededTenant {
    /// The account id the published flows act under.
    pub account_id: Uuid,
    /// The operator that owns the account (its wallet pool publishes).
    pub operator_id: Uuid,
    /// The plaintext Bearer secret to pass as the published client's `api_key`.
    pub api_key: String,
}

/// The knobs the boot path accepts. Defaults reproduce the byte-stable quote/publish
/// flows (no storage, default config, no per-byte storage price); the storage and
/// resumable-upload scenarios override the relevant fields.
#[derive(Default)]
struct StartOptions {
    /// The storage seam to wire (the uploads and session routes are only served when
    /// this is present).
    storage: Option<gateway_core::api::state::StorageState>,
    /// The held wallet keys the control-plane wallet-register route resolves against.
    control_wallet_keys: Vec<gateway_core::api::ControlWalletKey>,
    /// An explicit data-plane config (small chunk grid, free window) for the
    /// resumable-upload scenarios; `None` uses the engine default.
    api_config: Option<gateway_core::api::ApiConfig>,
    /// The per-byte storage price the pricing seam reports. Zero (the default) keeps
    /// a free-window file free; a non-zero value makes an over-the-window file incur a
    /// real charge.
    ar_usd_per_byte_femto: i64,
}

impl StartOptions {
    /// Boot options carrying only a storage seam, with the default config and no
    /// per-byte price (the byte-stable free-window upload flows).
    fn with_storage(storage: gateway_core::api::state::StorageState) -> Self {
        Self {
            storage: Some(storage),
            ..Self::default()
        }
    }
}

/// A booted gateway under test: a served HTTP base URL plus the database the
/// harness seeds tenants and stubs confirmations into.
///
/// The server task and the per-run database live for the handle's lifetime; both
/// are torn down on [`BootedGateway::shutdown`]. A dropped handle leaves the
/// database (the OS reaps the server task), so callers shut down explicitly to
/// keep the conformance database clean.
pub struct BootedGateway {
    /// The base URL the published clients point at (e.g. `http://127.0.0.1:PORT`).
    pub base_url: String,
    /// The pool the harness seeds tenants and stubs confirmations through.
    pub pool: sqlx::PgPool,
    /// The unlocked keyring holding the webhook secret-wrap data key the booted
    /// gateway seals delivery secrets under. The data plane's and control plane's
    /// registration routes seal a minted secret with this key's wrap accessor, and
    /// the delivery worker (driven via [`BootedGateway::run_delivery`]) opens a
    /// stored ciphertext back through it — exactly one data key serves both, so a
    /// secret registered on either plane opens the same way.
    keyring: Arc<UnlockedKeyring>,
    /// The egress config the delivery worker reaches the harness sink through:
    /// a local plain-HTTP listener, so both independent loosenings are opened
    /// explicitly — `allow_insecure_http` for the scheme, `allow_loopback` for
    /// the SDK guard's test-only `allow_private_for_tests` range seam.
    loopback_egress: EgressConfig,
    /// The per-run database name (dropped on shutdown).
    db_name: String,
    /// The URL of the per-run database (for the admin drop).
    url: String,
    /// The admin URL used to drop the per-run database on shutdown.
    admin_url: String,
    /// The server task handle, aborted on shutdown.
    server: tokio::task::JoinHandle<()>,
}

impl BootedGateway {
    /// Boot a gateway over a fresh, isolated database and serve it on an ephemeral
    /// port.
    ///
    /// Creates a uniquely named database, runs the engine migrator, wires the
    /// conformance pricing seam (a fixed FX/fee/margin so the quote is
    /// deterministic), serves the router, and returns once the listener is bound.
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_internal(StartOptions::default()).await
    }

    /// Boot a gateway with content storage wired, for the upload-conformance leg.
    ///
    /// Identical to [`Self::start`] but additionally attaches the supplied storage
    /// seam (a stub backend plus the upload-signing keyring), so the `/api/v1/poe/
    /// uploads` route and the attempt-poll route are served. The caller owns the
    /// storage stack (it constructs the backend, the funding keyring, and the
    /// signing seam) and hands it in, keeping this module free of the ANS-104 / age
    /// machinery the storage leg needs.
    pub async fn start_with_storage(
        storage: gateway_core::api::state::StorageState,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_internal(StartOptions::with_storage(storage)).await
    }

    /// Boot a gateway with content storage wired and an explicit upload config plus a
    /// per-byte storage price, for the resumable-upload conformance scenarios that
    /// need a small chunk grid and a real charge.
    ///
    /// The chunked scenarios assemble multi-chunk files, so they pass a small
    /// `chunk_bytes` ceiling (a real upload chunks at tens of megabytes; a test
    /// chunks at tens of bytes to keep the bodies small). A non-zero
    /// `ar_usd_per_byte_femto` makes a file above the free window incur a genuine
    /// storage charge, so the "charged exactly once" invariant is asserted on real
    /// ledger rows rather than a zero. Both single-shot and chunked ingress read the
    /// same config and price, so the charge for the same bytes is identical across
    /// the two paths.
    pub async fn start_with_storage_config(
        storage: gateway_core::api::state::StorageState,
        api_config: gateway_core::api::ApiConfig,
        ar_usd_per_byte_femto: i64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_internal(StartOptions {
            storage: Some(storage),
            control_wallet_keys: Vec::new(),
            api_config: Some(api_config),
            ar_usd_per_byte_femto,
        })
        .await
    }

    /// Boot a gateway whose control plane holds the supplied verified Cardano wallet
    /// keys, for the wallet-register conformance step (C2).
    ///
    /// The wallet-register route refuses an address the instance holds no signer
    /// for, so the harness wires the held-key metadata exactly as the running binary
    /// resolves it from the unlocked keyring. The keys are public address/label
    /// metadata only; no signing key material is involved.
    pub async fn start_with_control_wallet_keys(
        wallet_keys: Vec<gateway_core::api::ControlWalletKey>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_internal(StartOptions {
            control_wallet_keys: wallet_keys,
            ..StartOptions::default()
        })
        .await
    }

    async fn start_internal(opts: StartOptions) -> Result<Self, Box<dyn std::error::Error>> {
        let StartOptions {
            storage,
            control_wallet_keys,
            api_config,
            ar_usd_per_byte_femto,
        } = opts;
        let base_url = base_database_url();
        let base_name = database_name(&base_url)?;
        let db_name = format!("{base_name}_{}", Uuid::now_v7().simple());
        let url = with_database_name(&base_url, &db_name)?;
        let admin_url = admin_url(&base_url)?;

        create_database(&admin_url, &db_name).await?;
        // A pool sized for the data plane: SSE streams hold a connection while open
        // (the durable-log poll loop) and each also attaches a separate NOTIFY
        // listener, so a handful of concurrent streams plus the seeding/stub
        // queries need more than the default ten connections.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(32)
            .connect(&url)
            .await?;
        gateway_core::MIGRATOR.run(&pool).await?;

        // The publish path enqueues onto the cardano_submit queue, whose policy the
        // runtime assembly registers in production; the booted router has no
        // runtime, so register it directly. Reconcile is idempotent.
        gateway_core::runtime::policy::reconcile(
            &pool,
            &gateway_core::chain::submit::submit_policy(),
        )
        .await?;
        // The wallet-register route enqueues a targeted replenish in its transaction,
        // so its queue policy must exist; the manual-adjustment ledger kind backs the
        // control-plane balance adjustment. Both are registered by the runtime
        // assembly in production and reconciled here for the routerless boot.
        gateway_core::runtime::policy::reconcile(
            &pool,
            &gateway_core::wallet::replenish::replenish_policy(),
        )
        .await?;
        gateway_core::api::control::ledger_adjust::register_manual_adjustment_kind(&pool).await?;

        // The webhook seam both planes seal a minted delivery secret under. A fresh
        // wrap key per booted gateway, held in an unlocked keyring exactly as the
        // running binary holds it; the data key never reaches the database. The
        // delivery worker (driven in-process by the harness) opens a stored secret
        // back through this same key.
        let wrap_key = WebhookWrapKey::generate(
            "conformance-webhook-wrap".to_string(),
            format!("whk_conformance_{}", Uuid::now_v7().simple()),
        )
        .map_err(|e| format!("mint webhook wrap key: {e}"))?;
        let secret_wrap = Arc::new(wrap_key.secret_wrap());
        let keyring = Arc::new(UnlockedKeyring::for_webhook_tests(vec![wrap_key]));
        // The harness reaches its loopback plain-HTTP receiver sink, so both
        // independent loosenings are opened: the `http://` scheme and the
        // range-block (the SDK guard's test-only `allow_private_for_tests` seam).
        // A production deployment leaves both knobs off (HTTPS-only, public IP
        // only); the suite's blocked-range scenarios still assert the default.
        let webhook_state = gateway_core::api::WebhookState::new(secret_wrap, true, true);

        // The deployment's data-plane config: a caller-supplied override (the
        // resumable-upload scenarios pass a small chunk grid and free window) or the
        // default, but always with the conformance problem-type base stamped on it so
        // the problem `type` is a real URL.
        let api_config = gateway_core::api::ApiConfig {
            problem_type_base: "https://errors.conformance.invalid/v1".to_string(),
            ..api_config.unwrap_or_default()
        };

        let mut state = gateway_core::api::AppState::new(pool.clone(), api_config)
            .with_pricing(Arc::new(ConformancePricing {
                ar_usd_per_byte_femto,
            })
                as Arc<dyn gateway_core::api::state::DynPricingSource>)
            .with_webhook(webhook_state.clone());
        if let Some(storage) = storage {
            state = state.with_storage(storage);
        }

        // The control plane is the operator surface the C1-C4 and operator-firehose
        // (W9) scenarios drive. It is merged beside the data plane exactly as the
        // binary mounts it, carrying the SAME webhook seam so an account-scoped
        // subscription and an operator firehose seal under one instance data key.
        // The held wallet keys back the wallet-register route (empty unless the
        // caller wired them via `start_with_control_wallet_keys`).
        let control_state = gateway_core::api::ControlState::with_keys(
            pool.clone(),
            gateway_core::api::ControlConfig {
                problem_type_base: "https://errors.conformance.invalid/v1".to_string(),
                secret_prefix: "cfm_".to_string(),
                ..Default::default()
            },
            control_wallet_keys,
            Vec::new(),
        )
        .with_webhook(webhook_state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let router = gateway_core::api::router(state)
            .merge(gateway_core::api::control_router(control_state));
        let server = tokio::spawn(async move {
            // The server runs until the task is aborted on shutdown.
            let _ = axum::serve(listener, router).await;
        });

        Ok(Self {
            base_url: format!("http://{addr}"),
            pool,
            keyring,
            loopback_egress: EgressConfig {
                // The harness receiver is a local plain-HTTP listener, so both
                // independent loosenings are opened explicitly: the scheme and
                // the range-block.
                allow_insecure_http: true,
                allow_loopback: true,
            },
            db_name,
            url,
            admin_url,
            server,
        })
    }

    /// The data-plane base URL a published SDK/CLI client is configured with: the
    /// served host plus the `/api/v1` version segment.
    ///
    /// The published clients carry the API version in the configured base URL and
    /// append only bare resource suffixes (`/poe/quote`, `/records`, …), so a
    /// client is handed the full versioned base, never the bare host. The direct
    /// HTTP clients in the webhook/control/storage legs compose both the `/api/v1`
    /// data plane and the `/control/v1` control plane from [`Self::base_url`], so
    /// that field stays the bare host and this accessor derives the data-plane
    /// base on top of it.
    pub fn data_plane_base_url(&self) -> String {
        format!("{}/api/v1", self.base_url)
    }

    /// Seed an operator, an account (with a starting balance), and an API key,
    /// returning the credential the published clients authenticate with.
    pub async fn seed_tenant(
        &self,
        prefix: &str,
        scopes: &[&str],
        starting_balance_micros: i64,
    ) -> Result<SeededTenant, sqlx::Error> {
        seed_tenant(&self.pool, prefix, scopes, starting_balance_micros).await
    }

    /// Stub a confirmation for a published record: write its `chain_records` index
    /// row and advance its `poe_record` to a confirmed, on-chain state.
    ///
    /// This is the offline Stub-gateway path: it does for one record exactly what
    /// the confirm loop's threshold flip and the index writer do on a real
    /// settlement, so the records read surface (list, get, the owner projection)
    /// returns the record without a real Cardano submission. Returns the synthetic
    /// transaction hash (64-char lowercase hex) the record was anchored under.
    pub async fn stub_confirm(
        &self,
        record_uuid: Uuid,
        block_height: i64,
    ) -> Result<String, sqlx::Error> {
        // Load the record bytes the publish path stored, so the indexed columns are
        // derived from the same bytes a real index pass would read.
        let record_bytes: Vec<u8> =
            sqlx::query_scalar("SELECT record_bytes FROM cw_core.poe_record WHERE id = $1")
                .bind(record_uuid)
                .fetch_one(&self.pool)
                .await?;

        // A deterministic synthetic tx hash derived from the record id, so two runs
        // never collide and the hash is reproducible from the row.
        let tx_hash: [u8; 32] = Sha256::digest(record_uuid.as_bytes()).into();
        let tx_hex = hex::encode(tx_hash);
        let block_time = chrono::Utc::now();
        let block_height_u64 = u64::try_from(block_height).unwrap_or(0);

        let mut txn = self.pool.begin().await?;

        // The issuer-agnostic index row, written through the engine's OWN single
        // chain-records writer so the thin `cw_api.records` anchor and the rich row
        // are created together (the writer's leading CTE), exactly as a real
        // confirm/index pass does. The derived columns come from the same record
        // bytes the publish path stored. The harness has no chain, so the signer
        // verification runs under the engine default network (mainnet); the
        // conformance corpus signs records with in-record keys, whose
        // verification is network-independent — only wallet-path stake-address
        // binding reads the network byte.
        let columns = gateway_core::chain::records::derive_chain_record_columns(
            &record_bytes,
            gateway_core::chain::params::Network::Mainnet,
        )
        .map_err(|e| sqlx::Error::Protocol(format!("derive index columns: {e}")))?;
        gateway_core::chain::records::insert_chain_record_in_tx(
            &mut txn,
            tx_hash,
            block_height_u64,
            block_time,
            &record_bytes,
            // No full transaction CBOR in the stub path; the read surface serves
            // the canonical record metadata, which the row already carries.
            None,
            &columns,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("insert chain record: {e}")))?;

        // Advance the record to confirmed with its on-chain coordinates, the same
        // transition the confirm loop applies once the threshold is crossed.
        sqlx::query(
            "UPDATE cw_core.poe_record \
             SET status = 'confirmed', tx_hash = $2, block_height = $3, block_time = $4 \
             WHERE id = $1",
        )
        .bind(record_uuid)
        .bind(tx_hash.to_vec())
        .bind(block_height)
        .bind(block_time)
        .execute(&mut *txn)
        .await?;

        // Append the confirmed subject event so an SSE consumer sees the flip, just
        // as the confirm path does.
        gateway_core::events::append_subject_event(
            &mut txn,
            "poe_record",
            &record_uuid.to_string(),
            "confirmed",
            &serde_json::json!({ "status": "confirmed" }),
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("append confirmed event: {e}")))?;

        txn.commit().await?;

        // Materialise a tip well past the record so the confirmation depth the read
        // surface derives is positive.
        upsert_conformance_tip(&self.pool, block_height + 10).await?;

        Ok(tx_hex)
    }

    /// Append a subject event for a record, returning its allocated sequence.
    ///
    /// Drives the SSE resume assertion: the harness appends events while an SSE
    /// client is connected (and after a disconnect), then a reconnect with
    /// `Last-Event-ID` must replay exactly the events past the resume point.
    pub async fn append_poe_event(
        &self,
        record_uuid: Uuid,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        let ev = gateway_core::events::append_subject_event(
            &self.pool,
            "poe_record",
            &record_uuid.to_string(),
            event_type,
            &payload,
        )
        .await?;
        Ok(ev.subject_seq)
    }

    /// Insert a draft PoE record for an account directly (bypassing publish), for
    /// flows that need a record subject without a quote/debit. Returns its id.
    pub async fn seed_record(
        &self,
        tenant: &SeededTenant,
        record_bytes: &[u8],
    ) -> Result<Uuid, sqlx::Error> {
        let record_id = Uuid::now_v7();
        let record_sha256 = Sha256::digest(record_bytes).to_vec();
        sqlx::query(
            "INSERT INTO cw_core.poe_record \
               (id, operator_id, account_id, record_bytes, record_sha256, status) \
             VALUES ($1, $2, $3, $4, $5, 'submitting')",
        )
        .bind(record_id)
        .bind(tenant.operator_id)
        .bind(tenant.account_id)
        .bind(record_bytes)
        .bind(&record_sha256)
        .execute(&self.pool)
        .await?;
        Ok(record_id)
    }

    /// Seed an operator and mint its root credential, returning the operator id and
    /// the plaintext root bearer the control plane authenticates the bootstrap step
    /// with.
    ///
    /// Mirrors the binary's bootstrap subcommand: a fresh operator plus the single
    /// long-lived root credential that may mint operator tokens. The control-plane
    /// conformance flow (C1-C4) presents this root to mint an operator token, then
    /// drives the operator surface with that token.
    pub async fn seed_operator_root(&self, prefix: &str) -> Result<(Uuid, String), sqlx::Error> {
        let operator_id = Uuid::now_v7();
        sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, 'conformance')")
            .bind(operator_id)
            .execute(&self.pool)
            .await?;
        let minted = gateway_core::api::control::credential::mint_root_credential(
            &self.pool,
            operator_id,
            prefix,
            Some("conformance-root"),
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(format!("mint root credential: {e}")))?;
        Ok((operator_id, minted.secret))
    }

    /// Append a subject event on an arbitrary subject (an account, a funding source),
    /// returning its allocated per-subject sequence.
    ///
    /// The webhook fan-out scenarios inject events on whichever subject the matcher
    /// resolves an owner from: a `poe_record` (via [`Self::append_poe_event`]), an
    /// `account` (balance / storage-upload-failed), or a `storage_funding_source`
    /// (storage refund-intent). This is the general seam those scenarios use.
    pub async fn append_subject_event(
        &self,
        subject_kind: &str,
        subject_id: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        let ev = gateway_core::events::append_subject_event(
            &self.pool,
            subject_kind,
            subject_id,
            event_type,
            &payload,
        )
        .await?;
        Ok(ev.subject_seq)
    }

    /// Drain the webhook fan-out once: explode every un-fanned outbox row into one
    /// `webhook_delivery` row per matching live subscription, stamping each outbox
    /// row fanned-out. Returns how many outbox rows were processed.
    ///
    /// The booted gateway has no background runtime, so the harness drives the
    /// fan-out drain explicitly between injecting an event and asserting on the
    /// delivery rows it produced — the same `run_once` the singleton-loop handler
    /// runs under the runtime in production.
    pub async fn run_fanout(&self) -> Result<u64, Box<dyn std::error::Error>> {
        Ok(FanoutHandler::new(self.pool.clone()).run_once().await?)
    }

    /// Run one webhook delivery pass: claim every due delivery row with the frontier
    /// query, sign it (dual-signing inside a rotation window), and POST it through
    /// the hardened egress to its endpoint, recording each outcome.
    ///
    /// Reaches a loopback receiver through the egress test seam (the production
    /// range-block is otherwise intact). The harness re-arms a still-pending row to
    /// due between passes when it wants to drive a retry without waiting on the
    /// jittered backoff, exactly as the engine's own delivery-worker integration
    /// tests do.
    pub async fn run_delivery(&self) -> Result<(), Box<dyn std::error::Error>> {
        let handler = DeliveryHandler::new(
            self.pool.clone(),
            Arc::clone(&self.keyring),
            self.loopback_egress,
            gateway_core::webhook::DeliveryPolicy::default(),
        );
        handler.run_once().await?;
        Ok(())
    }

    /// Re-arm every still-`pending` delivery row for an endpoint to due now, so the
    /// next [`Self::run_delivery`] pass retries it without waiting on the
    /// (possibly multi-second) jittered backoff. Returns how many rows were re-armed.
    pub async fn rearm_pending(&self, endpoint_id: Uuid) -> Result<u64, sqlx::Error> {
        let affected = sqlx::query(
            "UPDATE cw_core.webhook_delivery SET next_attempt_at = now() \
             WHERE endpoint_id = $1 AND state = 'pending'",
        )
        .bind(endpoint_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(affected)
    }

    /// Shut the server down and drop the per-run database.
    pub async fn shutdown(self) {
        self.server.abort();
        // Close the pool so no backend keeps the database busy. Bound the wait: an
        // open SSE stream attaches its own NOTIFY listener connection that is not
        // pool-managed, so `close()` (which drains pool connections) can otherwise
        // wait on a detached stream task. The admin DROP below uses FORCE and first
        // terminates any lingering backend, so a bounded close is sufficient.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), self.pool.close()).await;
        if let Ok(mut admin) = sqlx::PgConnection::connect(&self.admin_url).await {
            // Terminate any lingering backends, then drop the database.
            let _ = sqlx::query(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
            )
            .bind(&self.db_name)
            .execute(&mut admin)
            .await;
            // CREATE/DROP DATABASE take no bind parameters; the name is a UUIDv7
            // suffix the harness minted, so it is interpolated under AssertSqlSafe
            // (double-quoted, and structurally not user-controlled).
            let drop_sql = format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", self.db_name);
            let _ = sqlx::query(sqlx::AssertSqlSafe(drop_sql))
                .execute(&mut admin)
                .await;
        }
        let _ = self.url; // retained for diagnostics; the drop uses db_name.
    }
}

/// The conformance pricing seam: a fixed network fee, FX snapshot, and margin.
///
/// The engine computes the cost-of-goods and persists the quote; this only
/// supplies the vendor inputs a deployment's oracle would. Deterministic so the
/// quote `amount` the published SDK decodes is reproducible.
///
/// The per-byte storage price is configurable so the storage suite can drive both
/// the free-only path (price zero, as the byte-stable quote flows use) and the
/// billed path (a non-zero price that produces a real storage charge over the
/// chargeable bytes). Everything else stays fixed and deterministic.
struct ConformancePricing {
    ar_usd_per_byte_femto: i64,
}

impl gateway_core::api::state::PricingSource for ConformancePricing {
    async fn resolve(
        &self,
        _account_id: Uuid,
        _record_bytes: u32,
        _recipient_count: u32,
        _file_bytes_total: u64,
    ) -> gateway_core::Result<gateway_core::api::state::PricingInputs> {
        Ok(gateway_core::api::state::PricingInputs {
            network_lovelace: 2_000_000,
            fx: gateway_core::ledger::quote::FxSnapshot {
                ada_usd_micros: 500_000,
                ar_usd_per_byte_femto: self.ar_usd_per_byte_femto,
                source: "conformance-oracle".to_string(),
            },
            fx_age_seconds: 5,
            margin: gateway_core::ledger::quote::MarginResolution {
                margin_pct: rust_decimal::Decimal::new(25, 2),
                margin_source: "conformance".to_string(),
            },
        })
    }
}

/// Seed an operator, an account (with a starting balance), and an API key
/// directly in a gateway database, returning the credential the published clients
/// authenticate with.
///
/// Mirrors what a public key-issuance API would expose: it writes the operator,
/// the account anchor + detail, an opening balance through the ledger, and an
/// api-key row whose `key_lookup`/`key_hash_sha256` are derived from the plaintext
/// secret exactly the way the gateway's auth path expects. The plaintext secret is
/// returned for the harness to use and is never logged.
pub async fn seed_tenant(
    pool: &sqlx::PgPool,
    prefix: &str,
    scopes: &[&str],
    starting_balance_micros: i64,
) -> Result<SeededTenant, sqlx::Error> {
    let operator_id = Uuid::now_v7();
    let account_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();

    let api_key = format!("{prefix}{}", Uuid::now_v7().simple());
    let full = Sha256::digest(api_key.as_bytes());
    let lookup = full[..KEY_LOOKUP_BYTES].to_vec();
    let hash = full.to_vec();

    let mut txn = pool.begin().await?;

    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES ($1, $2)")
        .bind(operator_id)
        .bind("conformance")
        .execute(&mut *txn)
        .await?;

    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(&mut *txn)
        .await?;

    sqlx::query(
        "INSERT INTO cw_core.account_detail (account_id, operator_id, status) \
         VALUES ($1, $2, 'active')",
    )
    .bind(account_id)
    .bind(operator_id)
    .execute(&mut *txn)
    .await?;

    if starting_balance_micros != 0 {
        sqlx::query(
            "INSERT INTO cw_core.ledger_kind_registry (kind, allows_overdraft, registered_by) \
             VALUES ('conformance_topup', false, 'conformance') ON CONFLICT (kind) DO NOTHING",
        )
        .execute(&mut *txn)
        .await?;
        sqlx::query(
            "INSERT INTO cw_core.balance_ledger (account_id, kind, amount_micros, ref) \
             VALUES ($1, 'conformance_topup', $2, $3)",
        )
        .bind(account_id)
        .bind(starting_balance_micros)
        .bind(format!("seed-{key_id}"))
        .execute(&mut *txn)
        .await?;
    }

    let scope_vec: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "INSERT INTO cw_core.api_key \
           (id, account_id, prefix, key_lookup, key_hash_sha256, scopes, rate_limit_per_min, label) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(key_id)
    .bind(account_id)
    .bind(prefix)
    .bind(&lookup)
    .bind(&hash)
    .bind(&scope_vec)
    .bind(6000_i32)
    .bind("conformance")
    .execute(&mut *txn)
    .await?;

    txn.commit().await?;

    Ok(SeededTenant {
        account_id,
        operator_id,
        api_key,
    })
}

/// Materialise the conformance chain tip so the read surface derives a positive
/// confirmation depth.
async fn upsert_conformance_tip(
    pool: &sqlx::PgPool,
    tip_block_height: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO cw_core.cardano_tip (network, tip_block_height) VALUES ('conformance', $1) \
         ON CONFLICT (network) DO UPDATE SET tip_block_height = GREATEST(cw_core.cardano_tip.tip_block_height, EXCLUDED.tip_block_height), tip_observed_at = now()",
    )
    .bind(tip_block_height)
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Database URL helpers (self-contained so the harness owns its own databases).
// ---------------------------------------------------------------------------

/// The base database URL the boot path derives per-run names from.
fn base_database_url() -> String {
    std::env::var(DATABASE_URL_ENV).unwrap_or_else(|_| DEFAULT_BASE_DATABASE_URL.to_string())
}

/// Extract the final path segment (the database name) from a connection URL.
fn database_name(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    url.rsplit('/')
        .next()
        .map(|s| s.split('?').next().unwrap_or(s).to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "database URL carries no database name".into())
}

/// Replace the database name in a connection URL.
fn with_database_name(url: &str, name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let idx = url
        .rfind('/')
        .ok_or("database URL carries no path separator")?;
    Ok(format!("{}/{name}", &url[..idx]))
}

/// Derive the admin URL (pointing at the server's `postgres` database) from the
/// base URL, honouring an explicit override.
fn admin_url(base_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(explicit) = std::env::var(ADMIN_DATABASE_URL_ENV) {
        return Ok(explicit);
    }
    with_database_name(base_url, "postgres")
}

/// Create a database through an admin connection, dropping any stale leftover of
/// the same name first.
async fn create_database(admin_url: &str, db_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut admin = sqlx::PgConnection::connect(admin_url).await?;
    // CREATE/DROP DATABASE take no bind parameters; the name is a UUIDv7-suffixed
    // identifier the harness minted, interpolated under AssertSqlSafe (double-
    // quoted, structurally not user-controlled).
    let drop_sql = format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)");
    let _ = sqlx::query(sqlx::AssertSqlSafe(drop_sql))
        .execute(&mut admin)
        .await;
    let create_sql = format!("CREATE DATABASE \"{db_name}\"");
    sqlx::query(sqlx::AssertSqlSafe(create_sql))
        .execute(&mut admin)
        .await?;
    Ok(())
}

/// The base URL of an externally booted gateway, from the environment.
#[must_use]
pub fn base_url() -> Option<String> {
    std::env::var(GATEWAY_BASE_URL_ENV).ok()
}

/// The database URL the harness seeds into for an external gateway, from the
/// environment.
#[must_use]
pub fn database_url() -> Option<String> {
    std::env::var(DATABASE_URL_ENV).ok()
}
