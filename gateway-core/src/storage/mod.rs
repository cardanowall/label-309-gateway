//! Content storage backends for the data plane.
//!
//! A publish that carries content bytes uploads them to a storage backend before
//! the record is anchored. This module defines the backend-neutral
//! [`StorageBackend`] trait and the receipt it returns, plus the concrete
//! backends: Turbo (the default, an ANS-104 data item signed with the operator
//! JWK and POSTed to a Turbo upload service), direct Arweave (a fallback), and
//! ArLocal (a dev backend that refuses to run in production).
//!
//! The trait and its types are the stable seam; the backends are selected by the
//! deployment's configuration. The uploads route streams each part to a tmpfs
//! staging file with a rolling hash and a byte ceiling ([`stage_stream`]), hands
//! the staged file to the configured backend, and writes the resulting receipt to
//! the `cw_core.storage_upload` ledger ([`persist_receipt`]).
//!
//! Who may draw charges against a funding source is a scope-bound capability
//! ([`AuthorizedFunding`]); the keyring's Arweave signer is reachable only through
//! it, the storage twin of the wallet spend capability.
//!
//! A funding source carries a prepaid remote credit balance (`winc`) at the
//! provider. The operator's append-only winc ledger, the cached-balance
//! affordability read the request path uses ([`affords`]), and the reconcile loop
//! that keeps the cached balance in step with the provider
//! ([`CreditReconcileHandler`]) live in the `credit` module. That ledger is the
//! operator's, distinct from the user's USD balance ledger; the two never share a
//! row.

mod arlocal;
mod attempt;
mod backend;
mod body;
mod bootstrap;
mod credit;
mod direct;
mod funding;
mod limits;
mod node;
mod persist;
mod reconcile;
mod refund;
mod session;
mod source;
mod staging;
mod topup;
mod turbo;

pub use arlocal::ArLocalBackend;
#[cfg(any(test, feature = "testsupport"))]
pub use attempt::race_window;
pub use attempt::{
    claim_post_lease, commit_attempt, load_attempt, load_envelope, load_live_attempt,
    release_attempt, release_post_lease, release_unrecoverable, reserve_attempt, Attempt,
    AttemptState, PersistedEnvelope, ReleaseReason, ReserveOutcome, ReserveSpec, SettleOutcome,
    STORAGE_UPLOAD_FAILED_EVENT,
};
pub use backend::{
    DataItemStatus, StorageBackend, StorageBackendExt, StorageError, StorageReceipt,
};
pub use body::streamed_data_item_body;
pub use bootstrap::{bootstrap_service_source, BootstrapOutcome};
pub use credit::{
    active_funding_sources, affords, credit_reconcile_policy, credit_reconcile_schedule,
    insert_credit_entry, load_credit, mark_reconcile_unavailable, reconcile_source, run_reconcile,
    verdict, ActiveFundingSource, AffordVerdict, CreditEntry, CreditKind, CreditOutcome,
    CreditReconcileHandler, ReconcileConfig, ReconcileSummary, SourceReconcileOutcome,
    StorageCredit, TurboWincProvider, WincBalance, WincBalanceProvider, CREDIT_DRIFT_EVENT,
    CREDIT_LOW_EVENT, CREDIT_RECONCILE_QUEUE, DEFAULT_RECONCILE_SCHEDULE,
    FUNDING_SOURCE_SUBJECT_KIND,
};
pub use direct::DirectArweaveBackend;
pub use funding::{
    authorize_charge, authorize_owner_topup, issue_grant, resolve_committed_upload, revoke_grant,
    AuthorizedFunding, IssueOutcome, RevokeOutcome, StorageChargePrincipal, StorageGrantScope,
};
pub use limits::{
    UploadLimits, UploadSessionLimits, DEFAULT_CHUNK_BYTES, DEFAULT_MAX_BATCH_BYTES,
    DEFAULT_MAX_CHUNK_BYTES, DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_OPEN_SESSIONS_PER_ACCOUNT, DEFAULT_MIN_CHUNK_BYTES, DEFAULT_SESSION_TTL_SECS,
    MAX_SESSION_CHUNKS,
};
pub use node::ArweaveNodeClient;
pub use persist::{lookup_receipt, persist_receipt, PersistedUpload};
pub use reconcile::{
    attempt_reconcile_policy, attempt_reconcile_schedule, AttemptReconcileConfig,
    AttemptReconcileHandler, AttemptReconcileSummary, ATTEMPT_RECONCILE_QUEUE, ATTEMPT_STUCK_EVENT,
    DEFAULT_ATTEMPT_RECONCILE_SCHEDULE,
};
pub use refund::{
    record_storage_refund_intent, refund_orphaned_uploads, OrphanRefundSweep, StorageRefundOutcome,
    StorageRefundReason, MAX_ORPHAN_SWEEP_PASSES, STORAGE_REFUND_INTENT_EVENT_TYPE,
};
pub use session::{
    assembled_sha256, assembling_path, begin_assembling, bitmap_get, bitmap_len, chunk_count_for,
    create_assembling_file, create_session, delete_session, ingest_chunk, load_session,
    load_session_for_account, mark_completed, mark_failed, record_chunk, recorded_chunk_digest,
    revert_to_open, session_janitor_policy, sweep_abandoned_sessions, ChunkIngestError,
    CreateSessionOutcome, CreateSessionSpec, RecordOutcome, SessionDisposition, SessionJanitor,
    SessionJanitorSummary, SessionState, UploadSession, SESSION_JANITOR_QUEUE,
};
pub use source::{
    begin_draining_source, list_sources, register_source, RegisterSourceOutcome, RegisteredSource,
    SourceStatus, SourceSummary,
};
pub use topup::{
    absorb_credited_topups, execute_topup, list_operator_topups, load_topup_for_operator,
    register_topup, FundTxAck, FundTxRegistrar, TopUpExecuteOutcome, TopUpRecord, TopUpStatus,
    TurboPaymentClient, MAX_IDEMPOTENCY_KEY_LEN,
};

pub use staging::{
    default_staging_dir, delete_durable, durable_staged_path, promote_to_durable, stage_stream,
    staging_janitor_policy, sweep_orphan_durable_files, StagedFile, StagingError, StagingJanitor,
    StagingJanitorSummary, STAGING_JANITOR_QUEUE,
};
pub use turbo::TurboBackend;
