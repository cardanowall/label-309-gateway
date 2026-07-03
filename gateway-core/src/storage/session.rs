//! The resumable / chunked upload session: the ingress precursor that assembles a
//! large file from client-sent chunks before it enters the existing paid-upload
//! pipeline.
//!
//! A session is content-addressed: the client declares the whole-file SHA-256 and
//! `total_bytes` at create. The gateway preallocates one durable assembling file
//! and accepts each chunk as a raw body at its deterministic offset
//! (`offset = index * chunk_bytes`), so chunks may arrive in any order and in
//! parallel. The received-chunk set is a bitmap; a reconnecting client re-PUTs only
//! the missing indices. At completion the assembled file's whole-file hash is
//! checked against the declaration and the file is handed, unchanged, into the
//! existing `store_one` -> `reserve_attempt` path.
//!
//! # Crash-safe ordering (durable write before receipt bit)
//!
//! A chunk PUT has two effects: the positional byte write to the assembling file
//! and the received-bit flip. They are STRICTLY ordered. [`write_chunk_bytes`]
//! writes the bytes at the chunk's offset and `fsync`s the file FIRST; only then
//! does [`record_chunk`] flip the received bit (a bitmap CAS) and record the chunk
//! digest. So the bitmap can never claim an index whose bytes are not durably on
//! disk. A crash in the gap (bytes written, bit not yet flipped) leaves the bit
//! UNSET, so the resume `missing` set still lists that index and the client re-PUTs
//! it, an idempotent positional re-write of the same bytes at the same offset. The
//! inverse hazard (bit set, bytes absent) is structurally impossible because the
//! flip never runs before the durable write. The complete-time whole-file hash
//! check is the final backstop: any torn or missing range fails it before a byte is
//! signed or charged.
//!
//! # No ledger state
//!
//! A session carries no money. The bitmap CAS owns chunk-level idempotency; the
//! existing attempt machinery owns logical-upload idempotency and billing. The
//! first and only billing event is the attempt reserve at completion.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Error, Result};

/// The on-disk suffix marking a session's assembling file. The file name IS the
/// session id, mirroring the `<attempt_id>.stage` convention so the janitor's
/// reconcile reasoning is the same: an `.assembling` file's name names the session
/// it belongs to.
const ASSEMBLING_SUFFIX: &str = "assembling";

/// The lifecycle state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Accepting chunks.
    Open,
    /// `complete` is verifying the assembled file (a transient state).
    Assembling,
    /// The assembled file entered the attempt pipeline; terminal.
    Completed,
    /// The session failed (e.g. the assembled hash did not match the declaration);
    /// terminal.
    Failed,
    /// The session passed its TTL with no completion; terminal.
    Expired,
}

impl SessionState {
    /// The stable string stored in `storage_upload_session.state`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SessionState::Open => "open",
            SessionState::Assembling => "assembling",
            SessionState::Completed => "completed",
            SessionState::Failed => "failed",
            SessionState::Expired => "expired",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "open" => Ok(SessionState::Open),
            "assembling" => Ok(SessionState::Assembling),
            "completed" => Ok(SessionState::Completed),
            "failed" => Ok(SessionState::Failed),
            "expired" => Ok(SessionState::Expired),
            other => Err(Error::Config(format!("unknown session state {other:?}"))),
        }
    }

    /// Whether a session in this state is still live (accepting work and owning its
    /// assembling file). A live session's file is the session janitor's to keep; any
    /// non-live session's file is reclaimable.
    #[must_use]
    pub fn is_live(self) -> bool {
        matches!(self, SessionState::Open | SessionState::Assembling)
    }
}

/// The terminal disposition a completed session replays on a re-`complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDisposition {
    /// Committed (or free-window): the upload landed, with a `uri` and a charge.
    Committed,
    /// Attached to an in-flight attempt: the caller polls `attempt_id`.
    Accepted,
    /// Deduped: the bytes were already stored, with the prior `uri` and no charge.
    Deduplicated,
}

impl SessionDisposition {
    /// The stable string stored in `storage_upload_session.settled_disposition`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SessionDisposition::Committed => "committed",
            SessionDisposition::Accepted => "accepted",
            SessionDisposition::Deduplicated => "deduplicated",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "committed" => Some(SessionDisposition::Committed),
            "accepted" => Some(SessionDisposition::Accepted),
            "deduplicated" => Some(SessionDisposition::Deduplicated),
            _ => None,
        }
    }
}

/// A session row as the routes read it.
#[derive(Debug, Clone)]
pub struct UploadSession {
    pub id: Uuid,
    pub account_id: Uuid,
    pub operator_id: Uuid,
    pub backend: String,
    pub sha256: [u8; 32],
    pub total_bytes: u64,
    pub chunk_bytes: u64,
    pub chunk_count: u32,
    pub content_type: String,
    pub received_bitmap: Vec<u8>,
    pub received_count: u32,
    pub assembling_path: Option<String>,
    pub state: SessionState,
    pub attempt_id: Option<Uuid>,
    pub uri: Option<String>,
    pub settled_disposition: Option<SessionDisposition>,
    pub charged_usd_micros: Option<i64>,
    pub failure_reason: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl UploadSession {
    /// The content digest as lowercase hex (the wire `sha256`).
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }

    /// The byte range a chunk index covers: `[index*chunk_bytes,
    /// min((index+1)*chunk_bytes, total_bytes))`. The length is `chunk_bytes` for
    /// every chunk except the last (the remainder). Returns `None` for an
    /// out-of-range index.
    #[must_use]
    pub fn chunk_range(&self, index: u32) -> Option<(u64, u64)> {
        if index >= self.chunk_count {
            return None;
        }
        let start = u64::from(index) * self.chunk_bytes;
        let end = start.saturating_add(self.chunk_bytes).min(self.total_bytes);
        Some((start, end))
    }

    /// The expected byte length of a chunk index.
    #[must_use]
    pub fn chunk_len(&self, index: u32) -> Option<u64> {
        self.chunk_range(index).map(|(s, e)| e - s)
    }

    /// Whether the index's received bit is set.
    #[must_use]
    pub fn is_received(&self, index: u32) -> bool {
        bitmap_get(&self.received_bitmap, index)
    }

    /// The received indices, ascending.
    #[must_use]
    pub fn received_indices(&self) -> Vec<u32> {
        (0..self.chunk_count)
            .filter(|&i| self.is_received(i))
            .collect()
    }

    /// The missing indices, ascending (the resume set).
    #[must_use]
    pub fn missing_indices(&self) -> Vec<u32> {
        (0..self.chunk_count)
            .filter(|&i| !self.is_received(i))
            .collect()
    }

    /// Whether every chunk index is received.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received_count == self.chunk_count
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    account_id: Uuid,
    operator_id: Uuid,
    backend: String,
    sha256: Vec<u8>,
    total_bytes: i64,
    chunk_bytes: i64,
    chunk_count: i32,
    content_type: String,
    received_bitmap: Vec<u8>,
    received_count: i32,
    assembling_path: Option<String>,
    state: String,
    attempt_id: Option<Uuid>,
    uri: Option<String>,
    settled_disposition: Option<String>,
    charged_usd_micros: Option<i64>,
    failure_reason: Option<String>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl SessionRow {
    fn into_session(self) -> Result<UploadSession> {
        let sha256: [u8; 32] = self
            .sha256
            .as_slice()
            .try_into()
            .map_err(|_| Error::Config("session sha256 is not 32 bytes".into()))?;
        Ok(UploadSession {
            id: self.id,
            account_id: self.account_id,
            operator_id: self.operator_id,
            backend: self.backend,
            sha256,
            total_bytes: u64::try_from(self.total_bytes)
                .map_err(|_| Error::Config("session total_bytes is negative".into()))?,
            chunk_bytes: u64::try_from(self.chunk_bytes)
                .map_err(|_| Error::Config("session chunk_bytes is non-positive".into()))?,
            chunk_count: u32::try_from(self.chunk_count)
                .map_err(|_| Error::Config("session chunk_count is negative".into()))?,
            content_type: self.content_type,
            received_bitmap: self.received_bitmap,
            received_count: u32::try_from(self.received_count)
                .map_err(|_| Error::Config("session received_count is negative".into()))?,
            assembling_path: self.assembling_path,
            state: SessionState::from_str(&self.state)?,
            attempt_id: self.attempt_id,
            uri: self.uri,
            settled_disposition: self
                .settled_disposition
                .as_deref()
                .and_then(SessionDisposition::from_str),
            charged_usd_micros: self.charged_usd_micros,
            failure_reason: self.failure_reason,
            expires_at: self.expires_at,
        })
    }
}

/// The full column list a [`SessionRow`] reads, inlined into the two load queries
/// (sqlx requires a `'static` query string, so this cannot be interpolated).
const SESSION_SELECT_FOR_ACCOUNT: &str =
    "SELECT id, account_id, operator_id, backend, sha256, total_bytes, chunk_bytes, chunk_count, \
            content_type, received_bitmap, received_count, assembling_path, state, attempt_id, \
            uri, settled_disposition, charged_usd_micros, failure_reason, expires_at \
     FROM cw_core.storage_upload_session WHERE id = $1 AND account_id = $2";

const SESSION_SELECT_BY_ID: &str =
    "SELECT id, account_id, operator_id, backend, sha256, total_bytes, chunk_bytes, chunk_count, \
            content_type, received_bitmap, received_count, assembling_path, state, attempt_id, \
            uri, settled_disposition, charged_usd_micros, failure_reason, expires_at \
     FROM cw_core.storage_upload_session WHERE id = $1";

/// The number of `total_bytes / chunk_bytes` chunks, rounded up (0 for an empty
/// file), or `None` when the grid would exceed [`crate::storage::MAX_SESSION_CHUNKS`].
///
/// Checked, never saturating: every per-session structure (the received bitmap,
/// the per-chunk digest rows, the resume `received`/`missing` sets) scales with
/// this count, so an over-bound grid must be REJECTED by the caller before any of
/// them exists — a saturated count would instead size a ~512 MiB bitmap and hand
/// an attacker a repeatable allocation. A zero `chunk_bytes` is likewise `None`
/// (an unanswerable grid), not a fabricated count.
#[must_use]
pub fn chunk_count_for(total_bytes: u64, chunk_bytes: u64) -> Option<u32> {
    if total_bytes == 0 {
        return Some(0);
    }
    if chunk_bytes == 0 {
        return None;
    }
    let count = total_bytes.div_ceil(chunk_bytes);
    u32::try_from(count)
        .ok()
        .filter(|&c| c <= crate::storage::MAX_SESSION_CHUNKS)
}

/// The number of bytes a bitmap needs to hold `chunk_count` bits.
#[must_use]
pub fn bitmap_len(chunk_count: u32) -> usize {
    chunk_count.div_ceil(8) as usize
}

/// Whether bit `index` is set in `bitmap` (little-endian within each byte).
#[must_use]
pub fn bitmap_get(bitmap: &[u8], index: u32) -> bool {
    let byte = (index / 8) as usize;
    let bit = index % 8;
    bitmap.get(byte).is_some_and(|b| (b >> bit) & 1 == 1)
}

/// The durable assembling path for a session id, under `assembling_dir`. The path
/// is reproducible from the id alone, so the janitor derives it without a lookup.
#[must_use]
pub fn assembling_path(assembling_dir: &Path, session_id: Uuid) -> PathBuf {
    assembling_dir.join(format!("{}.{ASSEMBLING_SUFFIX}", session_id.simple()))
}

/// The spec for a fresh session row.
pub struct CreateSessionSpec<'a> {
    pub id: Uuid,
    pub account_id: Uuid,
    pub operator_id: Uuid,
    pub backend: &'a str,
    pub sha256: [u8; 32],
    pub total_bytes: u64,
    pub chunk_bytes: u64,
    pub chunk_count: u32,
    pub content_type: &'a str,
    pub assembling_path: &'a str,
    pub ttl_secs: u64,
    /// The per-account cap on concurrently open/assembling sessions, enforced
    /// ATOMICALLY in the same transaction that inserts this row so two concurrent
    /// creates cannot both pass a count check and overshoot the cap.
    pub max_open_sessions: u32,
}

/// The outcome of an atomic session create: either the row landed, or the account
/// already held the cap of open/assembling sessions (the backpressure refusal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateSessionOutcome {
    /// The session row was inserted.
    Created,
    /// The account already holds `open` open/assembling sessions, at or over the
    /// cap; no row was inserted.
    CapExceeded {
        /// The open/assembling-session count observed under the serialising lock.
        open: u32,
    },
}

/// Insert a fresh `open` session with an empty received bitmap, enforcing the
/// per-account open-session cap atomically.
///
/// The count and the insert are one transaction serialised on a per-account
/// transaction-scoped advisory lock, so two concurrent creates for the same account
/// cannot both observe `open < cap` and both insert (the read-then-insert TOCTOU a
/// separate count check would leave open). The lock is keyed on the account id, so
/// creates for different accounts never contend; it releases when the transaction
/// commits or rolls back. This mirrors the read-modify-write serialisation the
/// chunk-receipt CAS and the reserve balance check use, applied to the cap check.
pub async fn create_session(
    pool: &sqlx::PgPool,
    spec: &CreateSessionSpec<'_>,
) -> Result<CreateSessionOutcome> {
    // The engine-level grid bound, enforced BEFORE the bitmap is sized: the route
    // already rejects an over-bound grid at validation, but no caller may reach a
    // bitmap allocation proportional to an unbounded chunk count, so the invariant
    // is re-checked where the allocation happens.
    if spec.chunk_count > crate::storage::MAX_SESSION_CHUNKS {
        return Err(Error::Config(format!(
            "session chunk_count {} exceeds the {} chunk ceiling",
            spec.chunk_count,
            crate::storage::MAX_SESSION_CHUNKS
        )));
    }
    let empty_bitmap = vec![0u8; bitmap_len(spec.chunk_count)];
    let total_bytes = i64::try_from(spec.total_bytes)
        .map_err(|_| Error::Config("total_bytes overflow".into()))?;
    let chunk_bytes = i64::try_from(spec.chunk_bytes)
        .map_err(|_| Error::Config("chunk_bytes overflow".into()))?;
    let chunk_count = i32::try_from(spec.chunk_count)
        .map_err(|_| Error::Config("chunk_count overflow".into()))?;
    let cap = i64::from(spec.max_open_sessions);

    let mut txn = pool.begin().await?;

    // Serialise concurrent creates for THIS account so the count below and the
    // insert that follows are one atomic read-modify-write. A transaction-scoped
    // advisory lock keyed on the account id contends only with another create for
    // the same account; it releases on commit/rollback. The key is derived in SQL
    // with `hashtext`, the same idiom the FX cold-start seed and the event-sequence
    // allocator use (`pg_advisory_xact_lock(hashtext(name)::bigint)`): `hashtext`
    // runs the full namespaced account string through Postgres' Jenkins hash, so two
    // distinct accounts do not alias (unlike a reversible XOR fold of the uuid halves,
    // where `hi,lo` and `lo,hi` would collide). The `storage_upload_session:` prefix
    // namespaces the key away from other advisory-lock users on the same instance.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(format!("storage_upload_session:{}", spec.account_id))
        .execute(&mut *txn)
        .await?;

    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cw_core.storage_upload_session \
         WHERE account_id = $1 AND state IN ('open', 'assembling')",
    )
    .bind(spec.account_id)
    .fetch_one(&mut *txn)
    .await?;

    if open >= cap {
        txn.rollback().await?;
        return Ok(CreateSessionOutcome::CapExceeded {
            open: u32::try_from(open).unwrap_or(u32::MAX),
        });
    }

    sqlx::query(
        "INSERT INTO cw_core.storage_upload_session \
           (id, account_id, operator_id, backend, sha256, total_bytes, chunk_bytes, chunk_count, \
            content_type, received_bitmap, received_count, assembling_path, state, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, $11, 'open', \
                 now() + make_interval(secs => $12))",
    )
    .bind(spec.id)
    .bind(spec.account_id)
    .bind(spec.operator_id)
    .bind(spec.backend)
    .bind(spec.sha256.as_slice())
    .bind(total_bytes)
    .bind(chunk_bytes)
    .bind(chunk_count)
    .bind(spec.content_type)
    .bind(empty_bitmap)
    .bind(spec.assembling_path)
    .bind(spec.ttl_secs as f64)
    .execute(&mut *txn)
    .await?;

    txn.commit().await?;
    Ok(CreateSessionOutcome::Created)
}

/// Load a session owned by `account_id`, or `None` (a non-owned or non-existent
/// session is indistinguishable, the same non-oracle rule as the attempt poll).
pub async fn load_session_for_account(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    account_id: Uuid,
) -> Result<Option<UploadSession>> {
    let row: Option<SessionRow> = sqlx::query_as(SESSION_SELECT_FOR_ACCOUNT)
        .bind(session_id)
        .bind(account_id)
        .fetch_optional(pool)
        .await?;
    row.map(SessionRow::into_session).transpose()
}

/// Load a session by id alone (the janitor and reload-after-CAS read).
pub async fn load_session(pool: &sqlx::PgPool, session_id: Uuid) -> Result<Option<UploadSession>> {
    let row: Option<SessionRow> = sqlx::query_as(SESSION_SELECT_BY_ID)
        .bind(session_id)
        .fetch_optional(pool)
        .await?;
    row.map(SessionRow::into_session).transpose()
}

/// The outcome of recording a received chunk under the received-bitmap CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// This PUT flipped the received bit and recorded the digest (the first arrival).
    Recorded,
    /// The bit was already set with a MATCHING digest: an idempotent no-op re-PUT.
    AlreadyMatches,
    /// The bit was already set with a DIFFERING digest: the client contradicts
    /// itself for a fixed offset (`409 chunk-conflict`).
    Conflict,
    /// The session is no longer `open` (settled, expired, or assembling); the chunk
    /// cannot be accepted.
    NotOpen,
}

/// Why ingesting one chunk's bytes failed (before any received bit is flipped).
#[derive(Debug)]
pub enum ChunkIngestError {
    /// The streamed body length did not equal the implied range length.
    LengthMismatch {
        /// The implied range length the body was expected to carry.
        expected: u64,
        /// The length actually streamed.
        actual: u64,
    },
    /// The streamed bytes' SHA-256 did not equal the declared per-chunk digest.
    DigestMismatch,
    /// The source body stream yielded an error (a truncated or malformed body).
    Stream(String),
    /// An I/O error writing or fsyncing the assembling file.
    Io(String),
}

/// Stream a chunk's bytes to its deterministic offset in the assembling file,
/// computing the rolling SHA-256 as it goes, and `fsync` the file BEFORE the
/// caller is allowed to flip the received bit.
///
/// This is the durable-write half of the crash-safe ordering. Peak memory is one
/// read buffer (the `stage_stream` discipline): each yielded sub-chunk is written
/// at its running positional offset and folded into the rolling hash before the next
/// is read, so a 64 MiB chunk never lands in memory whole. The write is positional
/// (`seek` then write at `offset + run`), so two PUTs for different indices touch
/// disjoint ranges and are independent, and a re-PUT of the same index overwrites
/// the identical bytes at the identical offset (idempotent). After the stream the
/// length and the declared digest are verified, then the file is `fsync`ed: only
/// then may [`record_chunk`] claim the index, so the bitmap can never name an index
/// whose bytes are not durably on disk. On a digest or length mismatch the bytes may
/// already be on disk, but the bit is NOT flipped, so the index stays in the resume
/// `missing` set and a corrected re-PUT overwrites them at the same offset.
pub async fn ingest_chunk<S, B, E>(
    assembling_path: &Path,
    offset: u64,
    expected_len: u64,
    expected_digest: &[u8; 32],
    mut source: S,
) -> std::result::Result<(), ChunkIngestError>
where
    S: futures_util::Stream<Item = std::result::Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
    E: std::fmt::Display,
{
    use futures_util::StreamExt;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(assembling_path)
        .await
        .map_err(|e| ChunkIngestError::Io(format!("opening assembling file for a chunk: {e}")))?;
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| ChunkIngestError::Io(format!("seeking the assembling file: {e}")))?;

    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    while let Some(chunk) = source.next().await {
        let chunk = chunk.map_err(|e| ChunkIngestError::Stream(e.to_string()))?;
        let bytes = chunk.as_ref();
        written = written.saturating_add(bytes.len() as u64);
        // Bound the write: a body that over-runs the implied range is rejected the
        // instant it crosses, so a lying Content-Length cannot scribble past the
        // chunk's region into the next chunk's bytes.
        if written > expected_len {
            return Err(ChunkIngestError::LengthMismatch {
                expected: expected_len,
                actual: written,
            });
        }
        file.write_all(bytes)
            .await
            .map_err(|e| ChunkIngestError::Io(format!("writing the chunk: {e}")))?;
        hasher.update(bytes);
    }

    if written != expected_len {
        return Err(ChunkIngestError::LengthMismatch {
            expected: expected_len,
            actual: written,
        });
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest.as_slice() != expected_digest.as_slice() {
        return Err(ChunkIngestError::DigestMismatch);
    }

    // fsync the data before the receipt bit is flipped: the bitmap must never claim
    // an index whose bytes are not durably on disk (a crash in the gap leaves the
    // bit UNSET, so resume re-PUTs the index).
    file.sync_all()
        .await
        .map_err(|e| ChunkIngestError::Io(format!("fsyncing the chunk: {e}")))?;
    Ok(())
}

/// Create (truncate) the durable assembling file for a session, sized to
/// `total_bytes` so positional chunk writes land in a preallocated file. A zero-byte
/// file is created empty.
pub async fn create_assembling_file(
    path: &Path,
    total_bytes: u64,
) -> std::result::Result<(), crate::storage::StagingError> {
    use crate::storage::StagingError;

    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| StagingError::Io(format!("creating the assembling dir: {e}")))?;
    }
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .await
        .map_err(|e| StagingError::Io(format!("creating the assembling file: {e}")))?;
    // Size the sparse file so every chunk's positional offset is in-bounds; the
    // bytes between unwritten offsets read as zero until their chunk lands, and the
    // complete-time whole-file hash gate rejects any range never filled.
    file.set_len(total_bytes)
        .await
        .map_err(|e| StagingError::Io(format!("sizing the assembling file: {e}")))?;
    file.sync_all()
        .await
        .map_err(|e| StagingError::Io(format!("fsyncing the assembling file: {e}")))?;
    // fsync the PARENT DIRECTORY too: `sync_all` makes the file's CONTENTS durable,
    // but on Linux the new directory entry (the file's very existence under its name)
    // is only guaranteed to survive a power loss after the directory itself is
    // fsynced. The crash-safety contract is durable-write-before-receipt-bit, and the
    // assembling file's existence is the floor that contract stands on, so its
    // directory entry must be durable before the first chunk bit can ever be flipped.
    if let Some(dir) = path.parent() {
        fsync_dir(dir).await?;
    }
    Ok(())
}

/// fsync a directory so a newly created (or renamed) entry within it survives a
/// power loss, not just the file's own contents.
///
/// `File::sync_all` persists a file's data and metadata, but the directory entry
/// that names the file is a property of the PARENT directory's own on-disk
/// structure; only fsyncing the directory guarantees the entry is durable. Opening a
/// directory read-only and fsyncing its handle is the portable way to do this on
/// Unix. A platform that rejects fsync on a directory handle (some non-Linux
/// filesystems) is treated as success, since the file contents were already synced.
async fn fsync_dir(dir: &Path) -> std::result::Result<(), crate::storage::StagingError> {
    use crate::storage::StagingError;

    match tokio::fs::File::open(dir).await {
        Ok(handle) => match handle.sync_all().await {
            Ok(()) => Ok(()),
            // Some filesystems reject fsync on a directory handle (EINVAL, which Rust
            // maps to InvalidInput); the file contents are already durable, so this is
            // not a hard failure of the write.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
            Err(e) => Err(StagingError::Io(format!(
                "fsyncing the assembling directory {}: {e}",
                dir.display()
            ))),
        },
        Err(e) => Err(StagingError::Io(format!(
            "opening the assembling directory {} for fsync: {e}",
            dir.display()
        ))),
    }
}

/// Flip the received bit for `index` under a CAS and record the chunk digest, in one
/// transaction, AFTER the bytes are durably written by `write_chunk_bytes`.
///
/// The CAS sets the bit only on a session still `open` and only when the bit is not
/// already set, ORing it into the bitmap and bumping `received_count`; the chunk row
/// records the digest and byte length. A second PUT for the same index finds the bit
/// already set and compares the supplied digest against the recorded one:
/// [`RecordOutcome::AlreadyMatches`] (idempotent no-op) or [`RecordOutcome::Conflict`]
/// (a self-contradicting client). This is the chunk-level idempotency layer; it
/// never touches money.
pub async fn record_chunk(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    index: u32,
    chunk_sha256: &[u8; 32],
    bytes: u64,
) -> Result<RecordOutcome> {
    // The byte offset into the bitmap, as an i32: get_byte/set_byte are defined for
    // (bytea, integer) only, never (bytea, bigint). The chunk index is bounded by
    // chunk_count (an i32 column), so index/8 always fits an i32.
    let byte_pos = (index / 8) as i32;
    let bit_mask = 1u8 << (index % 8);
    let bytes_i32 = i32::try_from(bytes)
        .map_err(|_| Error::Config("chunk byte length overflows i32".into()))?;

    let mut txn = pool.begin().await?;

    // Lock the session row so the read-modify-write of the bitmap byte and the
    // received_count are serialized against a concurrent same-index PUT.
    let row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT state, received_bitmap FROM cw_core.storage_upload_session \
         WHERE id = $1 FOR UPDATE",
    )
    .bind(session_id)
    .fetch_optional(&mut *txn)
    .await?;

    let Some((state, bitmap)) = row else {
        txn.rollback().await?;
        return Ok(RecordOutcome::NotOpen);
    };
    if state != "open" {
        txn.rollback().await?;
        return Ok(RecordOutcome::NotOpen);
    }

    // Already received? Compare digests for idempotency / conflict.
    if bitmap_get(&bitmap, index) {
        let recorded: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT chunk_sha256 FROM cw_core.storage_upload_session_chunk \
             WHERE session_id = $1 AND index = $2",
        )
        .bind(session_id)
        .bind(index as i32)
        .fetch_optional(&mut *txn)
        .await?;
        txn.rollback().await?;
        return Ok(match recorded {
            Some(d) if d.as_slice() == chunk_sha256.as_slice() => RecordOutcome::AlreadyMatches,
            _ => RecordOutcome::Conflict,
        });
    }

    // Flip the bit: OR the index's byte (set_byte grows the bytea if needed), and
    // bump received_count in the same statement.
    sqlx::query(
        "UPDATE cw_core.storage_upload_session \
            SET received_bitmap = set_byte( \
                    received_bitmap, $2, \
                    get_byte(received_bitmap, $2) | $3), \
                received_count = received_count + 1 \
          WHERE id = $1",
    )
    .bind(session_id)
    .bind(byte_pos)
    .bind(i32::from(bit_mask))
    .execute(&mut *txn)
    .await?;

    sqlx::query(
        "INSERT INTO cw_core.storage_upload_session_chunk \
           (session_id, index, chunk_sha256, bytes) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(session_id)
    .bind(index as i32)
    .bind(chunk_sha256.as_slice())
    .bind(bytes_i32)
    .execute(&mut *txn)
    .await?;

    txn.commit().await?;
    Ok(RecordOutcome::Recorded)
}

/// The recorded per-chunk digest for an index, if the chunk has been received.
///
/// A re-PUT of an already-received index is resolved against this WITHOUT rewriting
/// the durable bytes: a matching digest is an idempotent no-op, a differing one is a
/// conflict. Reading it before the positional write is what keeps a contradicting
/// re-PUT from overwriting the good bytes already on disk for that offset.
pub async fn recorded_chunk_digest(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    index: u32,
) -> Result<Option<[u8; 32]>> {
    let recorded: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT chunk_sha256 FROM cw_core.storage_upload_session_chunk \
         WHERE session_id = $1 AND index = $2",
    )
    .bind(session_id)
    .bind(index as i32)
    .fetch_optional(pool)
    .await?;
    match recorded {
        Some(d) => Ok(Some(d.as_slice().try_into().map_err(|_| {
            Error::Config("recorded chunk digest is not 32 bytes".into())
        })?)),
        None => Ok(None),
    }
}

/// Transition an `open` session to `assembling` under a CAS, returning whether this
/// caller won. Only the winner proceeds to verify + store; a racing re-`complete`
/// loses and reads back the recorded outcome.
///
/// Winning the CAS also pushes `expires_at` forward by a fresh `ttl_secs` window, so
/// an in-flight `complete` (which may run a slow whole-file hash and a slow backend
/// POST) is never CAS-expired by the session janitor mid-store and its assembling
/// file is never reclaimed out from under the running store. The bound store deadline
/// (`upload_timeout`) is far below the TTL, so the store always settles inside the
/// refreshed window; a process that genuinely crashes mid-`complete` still reaches
/// the refreshed TTL eventually and is reclaimed then. This is the structural
/// guarantee that the working `assembling` state is not mistaken for an abandoned
/// one; the create TTL alone would race a slow store that straddles it.
pub async fn begin_assembling(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    ttl_secs: u64,
) -> Result<bool> {
    let won: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE cw_core.storage_upload_session \
            SET state = 'assembling', expires_at = now() + make_interval(secs => $2) \
          WHERE id = $1 AND state = 'open' RETURNING id",
    )
    .bind(session_id)
    .bind(ttl_secs as f64)
    .fetch_optional(pool)
    .await?;
    Ok(won.is_some())
}

/// Transition an `assembling` session back to `open` under a CAS, returning whether
/// this caller reverted it.
///
/// `complete` wins the `open -> assembling` CAS before it verifies and stores the
/// assembled file. A NON-TERMINAL store failure (a transient backend outage, an
/// unfunded account, a slow dependency) must not strand the session in `assembling`
/// forever: there is no path out of `assembling` except a winning store or the TTL
/// janitor, so a stranded session would force a full chunk re-upload after the TTL.
/// Reverting to `open` makes `/complete` genuinely retryable WITHOUT re-uploading a
/// byte, because the assembling file and the received bitmap are untouched by a
/// pre-store failure. The CAS is bound to `assembling` so it only ever undoes THIS
/// caller's transition, never a concurrent winner's. A terminal failure
/// (sha256-mismatch) uses [`mark_failed`] instead and stays terminal.
pub async fn revert_to_open(pool: &sqlx::PgPool, session_id: Uuid) -> Result<bool> {
    let reverted: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE cw_core.storage_upload_session SET state = 'open' \
         WHERE id = $1 AND state = 'assembling' RETURNING id",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;
    Ok(reverted.is_some())
}

/// Mark a session `failed` with a reason and clear its assembling path (the caller
/// deletes the file). Used when the assembled hash does not match the declaration.
pub async fn mark_failed(pool: &sqlx::PgPool, session_id: Uuid, reason: &str) -> Result<()> {
    sqlx::query(
        "UPDATE cw_core.storage_upload_session \
            SET state = 'failed', failure_reason = $2, assembling_path = NULL, settled_at = now() \
          WHERE id = $1",
    )
    .bind(session_id)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(())
}

/// Stamp a session `completed` with its terminal outcome (the bridge attempt id, the
/// resolved uri, the disposition, and the realized charge) and clear its assembling
/// path: from reservation on, the attempt lifecycle owns the durable file. A
/// re-`complete` reads these back instead of re-reserving.
pub async fn mark_completed(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    attempt_id: Option<Uuid>,
    uri: Option<&str>,
    disposition: SessionDisposition,
    charged_usd_micros: Option<i64>,
) -> Result<()> {
    sqlx::query(
        "UPDATE cw_core.storage_upload_session \
            SET state = 'completed', attempt_id = $2, uri = $3, settled_disposition = $4, \
                charged_usd_micros = $5, assembling_path = NULL, settled_at = now() \
          WHERE id = $1",
    )
    .bind(session_id)
    .bind(attempt_id)
    .bind(uri)
    .bind(disposition.as_str())
    .bind(charged_usd_micros)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete a session (the explicit abandon path). The chunk rows CASCADE; the caller
/// deletes the assembling file.
pub async fn delete_session(pool: &sqlx::PgPool, session_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM cw_core.storage_upload_session WHERE id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Compute the whole-file SHA-256 of the assembled file in one bounded streaming
/// pass (the integrity gate). SHA-256 is not composable across out-of-order chunks,
/// so the authoritative whole-file digest is a single ordered pass over the
/// assembled bytes; the per-chunk digests were the cheap early rejection.
pub async fn assembled_sha256(path: &Path) -> Result<[u8; 32]> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| Error::Config(format!("opening the assembled file for hashing: {e}")))?;
    let mut hasher = Sha256::new();
    // The same bounded read size the streamed POST body uses, so a multi-GB file is
    // hashed with a fixed working set.
    let mut buf = vec![0u8; crate::storage::body::STREAM_CHUNK_BYTES];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| Error::Config(format!("reading the assembled file: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

// ---------------------------------------------------------------------------
// The abandoned-session janitor.
// ---------------------------------------------------------------------------

/// What one session-janitor sweep reclaimed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionJanitorSummary {
    /// Sessions CAS-marked `expired` this pass (past their TTL, still live).
    pub sessions_expired: u64,
    /// Engine-owned `.assembling` files inspected this pass.
    pub files_seen: u64,
    /// Files deleted because no live session still pointed at them.
    pub files_reclaimed: u64,
}

/// Reconcile abandoned sessions and their assembling files.
///
/// Mirrors the staging-orphan janitor exactly: (a) CAS-mark sessions past
/// `expires_at` that are still `open`/`assembling` as `expired` (a racing winning
/// `complete` already left the live set, so it loses nothing); (b) delete the
/// `<id>.assembling` file for any non-live session, the same way the staging janitor
/// deletes `.stage` files no live `reserved` attempt points at. The live set (still
/// `open`/`assembling` after the expiry CAS) is read FIRST, then the directory is
/// scanned and only files absent from the live set are deleted, so the window only
/// ever spares a file (the next pass reclaims it), never deletes a live one. An
/// already-gone file is success.
///
/// CLEAN PARTITION: this janitor owns ONLY pre-reservation assembling files. Once a
/// session reserves its attempt at `complete`, its `assembling_path` is cleared (the
/// file is adopted under the attempt-named `.stage` path), so it is no longer in the
/// session live set NOR an `.assembling` file, and the existing staging janitor +
/// attempt reconcile own it. No file is owned by both, none by neither.
pub async fn sweep_abandoned_sessions(
    pool: &sqlx::PgPool,
    assembling_dir: &Path,
) -> Result<SessionJanitorSummary> {
    let mut summary = SessionJanitorSummary::default();

    // Expire sessions past their TTL. A CAS bound to the live states, so a session
    // that a winning complete just moved out of the live set is untouched. A session
    // that has already bridged to an attempt (`attempt_id` set) is excluded: from the
    // reserve on, the attempt lifecycle owns the durable file (renamed to its
    // `.stage` path), so the session janitor must not expire it out from under the
    // attempt. An in-flight `complete` is protected by the refreshed `expires_at`
    // that `begin_assembling` stamped, so a slow store is never expired mid-flight.
    let expired: u64 = sqlx::query(
        "UPDATE cw_core.storage_upload_session \
            SET state = 'expired', assembling_path = NULL, settled_at = now() \
          WHERE expires_at < now() AND state IN ('open', 'assembling') \
            AND attempt_id IS NULL",
    )
    .execute(pool)
    .await?
    .rows_affected();
    summary.sessions_expired = expired;

    // The set of assembling files a live session still points at. Read AFTER the
    // expiry CAS and BEFORE the directory scan, so the scan only ever encounters a
    // file that was already live (kept) or abandoned (reclaimed); a file created
    // after this read is simply not seen this pass.
    let live: std::collections::HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT assembling_path FROM cw_core.storage_upload_session \
         WHERE state IN ('open', 'assembling') AND assembling_path IS NOT NULL",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    let mut entries = match tokio::fs::read_dir(assembling_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(summary),
        Err(e) => {
            return Err(Error::Config(format!(
                "reading the assembling dir {}: {e}",
                assembling_dir.display()
            )))
        }
    };

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| Error::Config(format!("scanning the assembling dir: {e}")))?
    {
        let path = entry.path();
        // Only engine-owned `.assembling` files are candidates; the attempt
        // lifecycle's `.stage` files (and any unrelated operator file in the shared
        // durable dir) are left alone, which is what keeps the two janitors'
        // ownership disjoint.
        if path.extension().and_then(|e| e.to_str()) != Some(ASSEMBLING_SUFFIX) {
            continue;
        }
        summary.files_seen += 1;
        let path_str = path.to_string_lossy().into_owned();
        if live.contains(&path_str) {
            continue;
        }
        crate::storage::delete_durable(&path)
            .await
            .map_err(|e| Error::Config(e.to_string()))?;
        summary.files_reclaimed += 1;
    }

    Ok(summary)
}

/// The queue the session janitor runs on.
pub const SESSION_JANITOR_QUEUE: &str = "storage_session_janitor";

/// The janitor that expires abandoned sessions and reclaims their assembling files.
///
/// The sibling of the staging-orphan janitor, driven by its own recurring schedule
/// so it reclaims debris from a crash at any time. Every pass is idempotent.
pub struct SessionJanitor {
    pool: sqlx::PgPool,
    assembling_dir: PathBuf,
}

impl SessionJanitor {
    /// Build a janitor over a pool and the assembling directory (the durable staging
    /// directory the attempt promotion also uses).
    #[must_use]
    pub fn new(pool: sqlx::PgPool, assembling_dir: PathBuf) -> Self {
        Self {
            pool,
            assembling_dir,
        }
    }

    /// The directory this janitor reconciles against the live session set.
    #[must_use]
    pub fn assembling_dir(&self) -> &Path {
        &self.assembling_dir
    }

    /// Run one expire-and-reclaim pass. Idempotent.
    pub async fn run_once(&self) -> Result<SessionJanitorSummary> {
        sweep_abandoned_sessions(&self.pool, &self.assembling_dir).await
    }
}

/// The default policy for the session-janitor queue: a singleton loop, the same
/// shape the staging janitor uses, so at most one pass runs across the deployment.
#[must_use]
pub fn session_janitor_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        SESSION_JANITOR_QUEUE,
        3,
        crate::runtime::Backoff::Fixed { base_secs: 60 },
        300,
    )
}

impl crate::runtime::JobHandler for SessionJanitor {
    async fn handle(&self, _ctx: crate::runtime::JobContext) -> crate::runtime::JobOutcome {
        match self.run_once().await {
            Ok(summary) => {
                tracing::info!(
                    sessions_expired = summary.sessions_expired,
                    files_seen = summary.files_seen,
                    files_reclaimed = summary.files_reclaimed,
                    "abandoned-session janitor pass complete"
                );
                crate::runtime::JobOutcome::Complete
            }
            Err(e) => {
                tracing::warn!(error = %e, "abandoned-session janitor pass failed");
                crate::runtime::JobOutcome::Fail {
                    error: crate::runtime::JobError::new("session_janitor_failed", e.to_string()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_count_rounds_up_and_handles_empty() {
        assert_eq!(chunk_count_for(0, 100), Some(0));
        assert_eq!(chunk_count_for(100, 100), Some(1));
        assert_eq!(chunk_count_for(101, 100), Some(2));
        assert_eq!(chunk_count_for(250, 100), Some(3));
    }

    #[test]
    fn chunk_count_rejects_an_over_bound_grid_instead_of_saturating() {
        let max = u64::from(crate::storage::MAX_SESSION_CHUNKS);
        // Exactly at the ceiling is admitted; one chunk past it is rejected.
        assert_eq!(
            chunk_count_for(max * 100, 100),
            Some(crate::storage::MAX_SESSION_CHUNKS)
        );
        assert_eq!(chunk_count_for(max * 100 + 1, 100), None);
        // The historical hazard: a huge total at 1-byte chunks must be None,
        // never a saturated u32::MAX that sizes a ~512 MiB bitmap.
        assert_eq!(chunk_count_for(10 * 1024 * 1024 * 1024, 1), None);
        // A zero chunk size over a non-empty total is unanswerable, not zero.
        assert_eq!(chunk_count_for(10, 0), None);
    }

    #[test]
    fn bitmap_len_rounds_up_to_whole_bytes() {
        assert_eq!(bitmap_len(0), 0);
        assert_eq!(bitmap_len(1), 1);
        assert_eq!(bitmap_len(8), 1);
        assert_eq!(bitmap_len(9), 2);
        assert_eq!(bitmap_len(17), 3);
    }

    #[test]
    fn bitmap_get_reads_the_right_bit() {
        // byte 0 = 0b0000_0101 -> bits 0 and 2 set; byte 1 = 0b0000_0010 -> bit 9.
        let bitmap = [0b0000_0101u8, 0b0000_0010u8];
        assert!(bitmap_get(&bitmap, 0));
        assert!(!bitmap_get(&bitmap, 1));
        assert!(bitmap_get(&bitmap, 2));
        assert!(bitmap_get(&bitmap, 9));
        assert!(!bitmap_get(&bitmap, 8));
        // Out of range is false, never a panic.
        assert!(!bitmap_get(&bitmap, 100));
    }

    fn session_with(total_bytes: u64, chunk_bytes: u64) -> UploadSession {
        let chunk_count = chunk_count_for(total_bytes, chunk_bytes).expect("test grid in bounds");
        UploadSession {
            id: Uuid::now_v7(),
            account_id: Uuid::now_v7(),
            operator_id: Uuid::now_v7(),
            backend: "turbo".into(),
            sha256: [0u8; 32],
            total_bytes,
            chunk_bytes,
            chunk_count,
            content_type: "application/octet-stream".into(),
            received_bitmap: vec![0u8; bitmap_len(chunk_count)],
            received_count: 0,
            assembling_path: None,
            state: SessionState::Open,
            attempt_id: None,
            uri: None,
            settled_disposition: None,
            charged_usd_micros: None,
            failure_reason: None,
            expires_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn chunk_ranges_cover_the_file_with_a_remainder_tail() {
        let s = session_with(250, 100);
        assert_eq!(s.chunk_count, 3);
        assert_eq!(s.chunk_range(0), Some((0, 100)));
        assert_eq!(s.chunk_range(1), Some((100, 200)));
        // The last chunk is the 50-byte remainder, not a full chunk.
        assert_eq!(s.chunk_range(2), Some((200, 250)));
        assert_eq!(s.chunk_len(2), Some(50));
        // Out of range.
        assert_eq!(s.chunk_range(3), None);
    }

    #[test]
    fn missing_and_received_partition_the_indices() {
        let mut s = session_with(300, 100); // 3 chunks
        s.received_bitmap = vec![0b0000_0101u8]; // 0 and 2 received
        s.received_count = 2;
        assert_eq!(s.received_indices(), vec![0, 2]);
        assert_eq!(s.missing_indices(), vec![1]);
        assert!(!s.is_complete());
        s.received_bitmap = vec![0b0000_0111u8];
        s.received_count = 3;
        assert!(s.is_complete());
        assert!(s.missing_indices().is_empty());
    }

    #[test]
    fn state_round_trips() {
        for st in [
            SessionState::Open,
            SessionState::Assembling,
            SessionState::Completed,
            SessionState::Failed,
            SessionState::Expired,
        ] {
            assert_eq!(SessionState::from_str(st.as_str()).unwrap(), st);
            assert_eq!(
                st.is_live(),
                matches!(st, SessionState::Open | SessionState::Assembling)
            );
        }
        assert!(SessionState::from_str("nope").is_err());
    }
}
