//! Bounded, hash-as-you-go staging of an upload stream, and the durable
//! promotion that lets an in-flight upload survive a crash.
//!
//! A content upload may be many gigabytes, so it is never buffered in memory:
//! [`stage_stream`] reads a byte stream chunk by chunk, writes each chunk to a
//! named temporary file, folds it into a rolling SHA-256, and enforces a byte
//! ceiling that aborts the write the instant the limit is crossed. The result is
//! a [`StagedFile`] carrying the file handle, its content digest, and its exact
//! size; the file is removed when the handle drops, even on an error path.
//!
//! That tmpfs-style auto-delete is the right default for a request that
//! succeeds or fails within one handler. It is the WRONG behaviour once an
//! upload becomes a durable reservation: the data item is signed once with a
//! randomized signature, so its content must survive a crash to be re-POSTed
//! with the identical bytes. [`promote_to_durable`] therefore moves a staged
//! file off the [`TempPath`] guard to a durable directory at a deterministic
//! path keyed on the attempt, defusing the auto-delete; [`delete_durable`]
//! removes it when the attempt settles. Both are idempotent, so a crash partway
//! through either is recoverable. [`sweep_orphan_durable_files`] reclaims durable
//! files that no live reservation still points at, and [`StagingJanitor`] is the
//! startup pass that runs it.
//!
//! The stream is generic over its chunk and error types so the same primitive
//! serves an axum multipart field, a test fixture, or any other byte source.

use std::path::{Path, PathBuf};

use futures_util::{Stream, StreamExt};
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempPath};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::Result;

/// The backing of a staged file's on-disk content.
///
/// A staged file may come from either ingress: the single-shot multipart loop
/// streams to a tmpfs scratch file that must auto-delete if the handler returns
/// early, while the resumable-upload path assembles its chunks into an
/// already-durable file that the session (and later the attempt lifecycle) owns,
/// which must NOT auto-delete. The source of the staged file is an ingress detail
/// the consuming pipeline ([`super::StagedFile`] -> `store_one`) does not need to
/// know, so both are carried behind one type.
#[derive(Debug)]
enum StagedBacking {
    /// A tmpfs scratch file that deletes itself when this value drops (the
    /// single-shot multipart loop's ingress).
    Scratch(TempPath),
    /// An already-durable file owned by an outer lifecycle (the resumable-upload
    /// assembling file). No auto-delete guard: the owner reclaims it.
    Durable(PathBuf),
}

impl StagedBacking {
    fn path(&self) -> &Path {
        match self {
            StagedBacking::Scratch(p) => p,
            StagedBacking::Durable(p) => p,
        }
    }
}

/// A staged upload: the on-disk content, its SHA-256, and its byte count.
///
/// A scratch-backed staged file (the single-shot ingress) is deleted when this
/// value drops, so it never leaks whether the upload succeeded, failed, or the
/// handler returned early. A durable-backed staged file (the resumable-upload
/// ingress, built via [`StagedFile::adopt_durable`]) carries no auto-delete guard:
/// an outer lifecycle owns the file. Either way [`promote_to_durable`] moves the
/// content under the attempt-named durable path, and from `store_one` onward the
/// two ingress sources are indistinguishable.
#[derive(Debug)]
pub struct StagedFile {
    /// The staged content's on-disk backing (auto-deleting scratch, or an
    /// already-durable file an outer lifecycle owns).
    backing: StagedBacking,
    /// The SHA-256 of the staged bytes (the content identity).
    pub sha256: [u8; 32],
    /// The number of staged bytes.
    pub bytes: u64,
}

impl StagedFile {
    /// Adopt an ALREADY-DURABLE file as a staged file with a known, verified digest
    /// and byte count.
    ///
    /// The resumable-upload path assembles its chunks into one durable file and
    /// verifies its whole-file SHA-256 against the client's declared hash; it then
    /// hands that file into the SAME `store_one` the single-shot loop uses. Unlike a
    /// scratch-backed staged file there is no [`TempPath`] auto-delete guard: the
    /// session (and, once the attempt reserves, the attempt lifecycle) owns the
    /// file, so dropping this handle must NOT remove it. [`promote_to_durable`]
    /// remains idempotent for an already-durable file, so promoting an adopted file
    /// to its attempt-named path moves it once and a re-promotion is a no-op.
    #[must_use]
    pub fn adopt_durable(path: PathBuf, sha256: [u8; 32], bytes: u64) -> Self {
        Self {
            backing: StagedBacking::Durable(path),
            sha256,
            bytes,
        }
    }

    /// The path to the staged content. For a scratch-backed file, valid until this
    /// handle drops; for an adopted durable file, valid for the file's lifetime.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.backing.path()
    }

    /// The staged content digest as lowercase hex (the wire `sha256`).
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }
}

/// Why staging a single upload stream failed.
///
/// Distinct from the storage-backend error: staging happens before any backend
/// is touched, and the route maps each variant to its own RFC 7807 problem
/// (`envelope-too-large` for the ceiling, `invalid-body` for a stream/IO fault).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StagingError {
    /// The stream exceeded the per-file byte ceiling; the write was aborted the
    /// instant the limit was crossed, so no more than `ceiling + one chunk` ever
    /// reached the disk.
    #[error("upload exceeds the per-file ceiling of {ceiling} bytes")]
    TooLarge {
        /// The ceiling that was crossed.
        ceiling: u64,
    },
    /// The source stream yielded an error (a truncated or malformed body).
    #[error("upload stream error: {0}")]
    Stream(String),
    /// Writing the staged file or creating the staging temp file failed.
    #[error("staging I/O error: {0}")]
    Io(String),
}

/// Stream `source` to a fresh temporary file under `staging_dir`, hashing as it
/// goes and aborting if the total crosses `ceiling`.
///
/// Each yielded chunk is written and folded into the rolling SHA-256 before the
/// next is read, so peak memory is one chunk regardless of the total size. The
/// instant the running total would exceed `ceiling` the function returns
/// [`StagingError::TooLarge`] and the partially written file is removed (the
/// [`TempPath`] guard drops on the early return). A source error or any IO
/// failure aborts the same way.
///
/// `staging_dir` is the tmpfs (or any) directory the temp file is created in, so
/// the operator controls where staged content lands; passing the system temp dir
/// is fine for a deployment that mounts it on tmpfs.
pub async fn stage_stream<S, B, E>(
    staging_dir: &Path,
    ceiling: u64,
    mut source: S,
) -> std::result::Result<StagedFile, StagingError>
where
    S: Stream<Item = std::result::Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
    E: std::fmt::Display,
{
    // Create the temp file synchronously (cheap), then drive the writes async.
    // `into_temp_path` hands back a guard that removes the file on drop while
    // keeping the std file handle, which we wrap for async writes.
    let temp = NamedTempFile::new_in(staging_dir)
        .map_err(|e| StagingError::Io(format!("creating staging file: {e}")))?;
    let std_file = temp
        .reopen()
        .map_err(|e| StagingError::Io(format!("reopening staging file for writing: {e}")))?;
    let path: TempPath = temp.into_temp_path();
    let mut file = tokio::fs::File::from_std(std_file);

    let mut hasher = Sha256::new();
    let mut total: u64 = 0;

    while let Some(chunk) = source.next().await {
        let chunk = chunk.map_err(|e| StagingError::Stream(e.to_string()))?;
        let bytes = chunk.as_ref();
        // Check the ceiling against the running total BEFORE committing the chunk
        // to disk so a crossing aborts deterministically; the partial file is
        // removed by the guard on the early return.
        total = total.saturating_add(bytes.len() as u64);
        if total > ceiling {
            return Err(StagingError::TooLarge { ceiling });
        }
        file.write_all(bytes)
            .await
            .map_err(|e| StagingError::Io(format!("writing staged chunk: {e}")))?;
        hasher.update(bytes);
    }

    file.flush()
        .await
        .map_err(|e| StagingError::Io(format!("flushing staged file: {e}")))?;

    let sha256: [u8; 32] = hasher.finalize().into();
    Ok(StagedFile {
        backing: StagedBacking::Scratch(path),
        sha256,
        bytes: total,
    })
}

/// The default staging directory: the system temporary directory.
///
/// A deployment that wants staged content on a tmpfs mount points the system
/// temp dir there (or passes an explicit dir to [`stage_stream`]); the engine
/// does not bake a path in.
#[must_use]
pub fn default_staging_dir() -> PathBuf {
    std::env::temp_dir()
}

/// The durable on-disk path a promoted attempt's content lives at.
///
/// The naming contract: a promoted file is named `<attempt_id>.stage`. The route
/// mints the attempt id BEFORE promotion and carries the same id into the
/// reservation, so the file name equals the attempt row's id. This makes the path
/// reproducible from the attempt row alone (a retry or the reconcile sweep derives
/// it without a second lookup) and makes orphan reasoning and operator debugging
/// direct: a `.stage` file's name IS the attempt it belongs to. The orphan janitor
/// reconciles the directory against the set of `staged_path` values on `reserved`
/// rows; because the path is keyed on the attempt id, an orphaned file's name
/// names the dead attempt directly. The `.stage` suffix marks the file as
/// engine-owned so a janitor never touches an unrelated file an operator placed
/// in the directory.
#[must_use]
pub fn durable_staged_path(durable_dir: &Path, attempt_id: Uuid) -> PathBuf {
    durable_dir.join(format!("{}.stage", attempt_id.simple()))
}

/// Promote a staged file off the auto-delete guard to its durable path.
///
/// A [`StagedFile`] deletes itself when its handle drops, which is correct for a
/// request that resolves in one handler but loses the content the instant a
/// reservation's handler returns or the process dies. This moves the file to the
/// deterministic [`durable_staged_path`] and defuses the [`TempPath`] guard, so
/// the content outlives the handler and a crash. The returned path is what the
/// attempt row's `staged_path` records.
///
/// Idempotent by construction: if the durable path already holds content (a
/// re-promotion of an attempt already promoted, e.g. an at-least-once retry of
/// the reserve step), the source staged file is simply discarded and the
/// existing durable file is kept. The rename is attempted first because it is
/// atomic on one filesystem; a cross-device move falls back to a copy followed
/// by removing the source, so a `durable_dir` on a different mount than the
/// tmpfs scratch dir still works.
pub async fn promote_to_durable(
    staged: StagedFile,
    durable_dir: &Path,
    attempt_id: Uuid,
) -> std::result::Result<PathBuf, StagingError> {
    let durable = durable_staged_path(durable_dir, attempt_id);

    // A file already at the durable path is the byte-identical content of an
    // earlier promotion of the same attempt (the path is keyed on the attempt
    // id, and the once-signed envelope pins these bytes). Re-promoting is a
    // no-op: keep the durable copy, drop the fresh staged file via its guard.
    if tokio::fs::try_exists(&durable)
        .await
        .map_err(|e| StagingError::Io(format!("checking durable path: {e}")))?
    {
        return Ok(durable);
    }

    tokio::fs::create_dir_all(durable_dir)
        .await
        .map_err(|e| StagingError::Io(format!("creating durable staging dir: {e}")))?;

    // Take ownership of the source path. A scratch-backed file calls `keep`, which
    // defuses the auto-delete and returns the current path; from here the bytes are
    // ours to move, and a failure must NOT leave them at a path nothing will ever
    // clean up. An adopted durable file already owns its path (no guard to defuse),
    // so it is moved straight to the attempt-named durable path.
    let source: PathBuf = match staged.backing {
        StagedBacking::Scratch(temp) => temp
            .keep()
            .map_err(|e| StagingError::Io(format!("releasing the staging guard: {e}")))?,
        StagedBacking::Durable(path) => path,
    };

    match tokio::fs::rename(&source, &durable).await {
        Ok(()) => Ok(durable),
        Err(rename_err) => {
            // Cross-device or otherwise un-renamable: copy then remove the
            // source so neither path is left holding a half-written or orphaned
            // file. A copy failure removes the source we just un-guarded so the
            // scratch file is not leaked.
            match tokio::fs::copy(&source, &durable).await {
                Ok(_) => {
                    let _ = tokio::fs::remove_file(&source).await;
                    Ok(durable)
                }
                Err(copy_err) => {
                    let _ = tokio::fs::remove_file(&source).await;
                    let _ = tokio::fs::remove_file(&durable).await;
                    Err(StagingError::Io(format!(
                        "promoting staged file to durable storage (rename: {rename_err}; \
                         copy: {copy_err})"
                    )))
                }
            }
        }
    }
}

/// Delete a durable staged file, treating an already-absent file as success.
///
/// Called by the same code path that nulls the attempt's signed envelope on
/// commit or release, so the content and the recovery envelope are cleared
/// together. Idempotent: a file that a previous (possibly crashed) settlement
/// already removed is not an error, so a settlement retry is safe.
pub async fn delete_durable(staged_path: &Path) -> std::result::Result<(), StagingError> {
    match tokio::fs::remove_file(staged_path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StagingError::Io(format!(
            "deleting durable staged file {}: {e}",
            staged_path.display()
        ))),
    }
}

/// What one orphan-staging sweep reclaimed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StagingJanitorSummary {
    /// Engine-owned durable files inspected this pass.
    pub files_seen: u64,
    /// Files deleted because no `reserved` attempt still pointed at them.
    pub files_reclaimed: u64,
}

/// Delete durable staged files that no live reservation still points at.
///
/// A durable file is live exactly while a `reserved` `storage_upload_attempt`
/// row names it: that attempt may still re-POST the content. Every other
/// engine-owned `.stage` file in `durable_dir` is an orphan, left by a crash
/// between writing the durable file and committing the attempt row, or by a
/// settlement that nulled the row but died before [`delete_durable`] ran. This
/// reconciles the directory against the live set and removes the orphans.
///
/// Idempotent and crash-safe: it reads the live set, then deletes only files
/// absent from it, and an already-gone file is not an error. A file that races a
/// concurrently-promoting attempt is kept, because the live set is read before
/// the directory is scanned, so the window only ever spares an orphan (which the
/// next pass reclaims), never deletes a live file.
pub async fn sweep_orphan_durable_files(
    pool: &sqlx::PgPool,
    durable_dir: &Path,
) -> Result<StagingJanitorSummary> {
    // The set of paths a live reservation still points at. Read FIRST so the
    // scan below can only ever encounter a file that was already live (kept) or
    // an orphan (reclaimed); a file promoted after this read is simply not seen
    // this pass.
    let live: std::collections::HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT staged_path \
         FROM cw_core.storage_upload_attempt \
         WHERE state = 'reserved' AND staged_path IS NOT NULL",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    let mut summary = StagingJanitorSummary::default();

    let mut entries = match tokio::fs::read_dir(durable_dir).await {
        Ok(entries) => entries,
        // No durable directory yet means nothing has been promoted; there is
        // nothing to reclaim.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(summary),
        Err(e) => {
            return Err(crate::Error::Config(format!(
                "reading durable staging dir {}: {e}",
                durable_dir.display()
            )))
        }
    };

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| crate::Error::Config(format!("scanning durable staging dir: {e}")))?
    {
        let path = entry.path();
        // Only engine-owned promoted files are candidates; anything else in the
        // directory is left alone so the janitor cannot delete an unrelated
        // operator file.
        if path.extension().and_then(|e| e.to_str()) != Some("stage") {
            continue;
        }
        summary.files_seen += 1;

        let path_str = path.to_string_lossy().into_owned();
        if live.contains(&path_str) {
            continue;
        }

        delete_durable(&path)
            .await
            .map_err(|e| crate::Error::Config(e.to_string()))?;
        summary.files_reclaimed += 1;
    }

    Ok(summary)
}

/// The queue the staging-orphan janitor runs on.
pub const STAGING_JANITOR_QUEUE: &str = "storage_staging_janitor";

/// The startup janitor that reclaims orphaned durable staged files.
///
/// A promoted staged file outlives its handler, so a crash between writing it
/// and committing the attempt row, or between nulling the row and deleting the
/// file, leaves content on disk that no reservation points at. This handler runs
/// [`sweep_orphan_durable_files`] to reclaim those orphans. It is meant to run
/// once at startup (so a restart cleans up its predecessor's debris) and is
/// registered like the other engine maintenance jobs; every pass is idempotent,
/// so an at-least-once re-run is a harmless no-op.
pub struct StagingJanitor {
    pool: sqlx::PgPool,
    durable_dir: PathBuf,
}

impl StagingJanitor {
    /// Build a janitor over a pool and the durable staging directory.
    #[must_use]
    pub fn new(pool: sqlx::PgPool, durable_dir: PathBuf) -> Self {
        Self { pool, durable_dir }
    }

    /// The durable directory this janitor reconciles against the live set.
    #[must_use]
    pub fn durable_dir(&self) -> &Path {
        &self.durable_dir
    }

    /// Run one orphan-reclaim pass. Idempotent: a pass with nothing orphaned is
    /// a no-op.
    pub async fn run_once(&self) -> Result<StagingJanitorSummary> {
        sweep_orphan_durable_files(&self.pool, &self.durable_dir).await
    }
}

/// The default policy for the staging-janitor queue: a singleton loop so at most
/// one orphan-reclaim pass runs across the deployment at a time. A short fixed
/// backoff and a small attempt budget ride out a transient database blip; the
/// pass is idempotent, so a retry of an already-done pass is cheap.
#[must_use]
pub fn staging_janitor_policy() -> crate::runtime::policy::QueuePolicy {
    crate::runtime::policy::QueuePolicy::singleton_loop(
        STAGING_JANITOR_QUEUE,
        3,
        crate::runtime::Backoff::Fixed { base_secs: 60 },
        // A pass scans one directory and deletes a bounded set of files; a
        // 5-minute lease is ample and reclaims promptly if a replica dies.
        300,
    )
}

impl crate::runtime::JobHandler for StagingJanitor {
    async fn handle(&self, _ctx: crate::runtime::JobContext) -> crate::runtime::JobOutcome {
        match self.run_once().await {
            Ok(summary) => {
                tracing::info!(
                    files_seen = summary.files_seen,
                    files_reclaimed = summary.files_reclaimed,
                    "staging-orphan janitor pass complete"
                );
                crate::runtime::JobOutcome::Complete
            }
            Err(e) => {
                tracing::warn!(error = %e, "staging-orphan janitor pass failed");
                crate::runtime::JobOutcome::Fail {
                    error: crate::runtime::JobError::new("staging_janitor_failed", e.to_string()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    /// A stream of owned byte chunks that never errors, for the happy paths.
    fn ok_stream(
        chunks: Vec<Vec<u8>>,
    ) -> impl Stream<Item = std::result::Result<Vec<u8>, Infallible>> + Unpin {
        futures_util::stream::iter(chunks.into_iter().map(Ok))
    }

    #[tokio::test]
    async fn stages_the_stream_and_computes_the_sha_and_byte_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Split the payload across chunks to prove the rolling hash spans them.
        let staged = stage_stream(
            dir.path(),
            1024,
            ok_stream(vec![b"hello, ".to_vec(), b"world".to_vec()]),
        )
        .await
        .expect("staging succeeds");

        assert_eq!(staged.bytes, 12, "byte count is the sum of every chunk");

        // The digest matches a one-shot hash of the concatenated payload, proving
        // the rolling update spanned the chunk boundary correctly.
        let expected: [u8; 32] = Sha256::digest(b"hello, world").into();
        assert_eq!(staged.sha256, expected);
        assert_eq!(staged.sha256_hex(), hex::encode(expected));

        // The bytes really landed on disk.
        let on_disk = tokio::fs::read(staged.path()).await.expect("read staged");
        assert_eq!(on_disk, b"hello, world");
    }

    #[tokio::test]
    async fn empty_stream_stages_the_empty_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = stage_stream(dir.path(), 1024, ok_stream(vec![]))
            .await
            .expect("empty stream stages");
        assert_eq!(staged.bytes, 0);
        let expected: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(staged.sha256, expected);
    }

    #[tokio::test]
    async fn aborts_the_instant_the_ceiling_is_crossed() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Ceiling of 8; the second chunk crosses it.
        let err = stage_stream(dir.path(), 8, ok_stream(vec![vec![0u8; 5], vec![1u8; 5]]))
            .await
            .expect_err("crossing the ceiling aborts");
        assert!(matches!(err, StagingError::TooLarge { ceiling: 8 }));
    }

    #[tokio::test]
    async fn a_single_chunk_over_the_ceiling_aborts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = stage_stream(dir.path(), 4, ok_stream(vec![vec![0u8; 100]]))
            .await
            .expect_err("a single oversized chunk aborts");
        assert!(matches!(err, StagingError::TooLarge { ceiling: 4 }));
    }

    #[tokio::test]
    async fn exactly_at_the_ceiling_is_allowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = stage_stream(dir.path(), 4, ok_stream(vec![vec![9u8; 4]]))
            .await
            .expect("exactly at the ceiling stages");
        assert_eq!(staged.bytes, 4);
    }

    #[tokio::test]
    async fn a_stream_error_aborts_staging() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = futures_util::stream::iter(vec![
            Ok::<Vec<u8>, String>(b"partial".to_vec()),
            Err("truncated body".to_string()),
        ]);
        let err = stage_stream(dir.path(), 1024, source)
            .await
            .expect_err("a stream error aborts staging");
        match err {
            StagingError::Stream(detail) => assert!(detail.contains("truncated body")),
            other => panic!("expected a stream error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_staged_file_is_removed_when_the_handle_drops() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = stage_stream(dir.path(), 1024, ok_stream(vec![b"x".to_vec()]))
            .await
            .expect("staging succeeds");
        let path = staged.path().to_path_buf();
        assert!(
            path.exists(),
            "the staged file exists while the handle lives"
        );
        drop(staged);
        assert!(
            !path.exists(),
            "the staged file is removed when its handle drops"
        );
    }

    // ----------------------------------------------------------------------
    // Durable promotion + deletion.
    // ----------------------------------------------------------------------

    /// Stage a small payload to `scratch` and return the handle.
    async fn stage_small(scratch: &Path, payload: &[u8]) -> StagedFile {
        stage_stream(scratch, 1024, ok_stream(vec![payload.to_vec()]))
            .await
            .expect("staging succeeds")
    }

    #[tokio::test]
    async fn promotion_moves_the_content_off_the_auto_delete_guard() {
        let scratch = tempfile::tempdir().expect("scratch");
        let durable = tempfile::tempdir().expect("durable");
        let attempt = Uuid::now_v7();

        let staged = stage_small(scratch.path(), b"durable payload").await;
        let scratch_path = staged.path().to_path_buf();

        let promoted = promote_to_durable(staged, durable.path(), attempt)
            .await
            .expect("promotion succeeds");

        // The content is at the deterministic durable path, the scratch file is
        // gone, and the bytes survived the move intact.
        assert_eq!(promoted, durable_staged_path(durable.path(), attempt));
        assert!(promoted.exists(), "the promoted file exists");
        assert!(
            !scratch_path.exists(),
            "the scratch file is moved off, not left behind"
        );
        let on_disk = tokio::fs::read(&promoted).await.expect("read promoted");
        assert_eq!(on_disk, b"durable payload");
    }

    #[tokio::test]
    async fn the_promoted_file_outlives_a_dropped_staged_handle() {
        // The whole point of promotion: the durable copy survives even after the
        // original StagedFile guard would have fired. Promotion consumes the
        // handle, so once promoted there is no guard left to delete it.
        let scratch = tempfile::tempdir().expect("scratch");
        let durable = tempfile::tempdir().expect("durable");
        let attempt = Uuid::now_v7();

        let staged = stage_small(scratch.path(), b"survives a crash").await;
        let promoted = promote_to_durable(staged, durable.path(), attempt)
            .await
            .expect("promotion succeeds");

        // Simulate "the handler returned / the process restarted": nothing holds
        // the file, yet it is still readable for a re-POST.
        assert!(promoted.exists());
        let on_disk = tokio::fs::read(&promoted).await.expect("still readable");
        assert_eq!(on_disk, b"survives a crash");
    }

    #[tokio::test]
    async fn re_promoting_an_already_durable_attempt_is_a_no_op() {
        // A second promotion for the same attempt id (an at-least-once retry of
        // the reserve step) must not clobber the durable file or error; it keeps
        // the existing content and discards the fresh staged file.
        let scratch = tempfile::tempdir().expect("scratch");
        let durable = tempfile::tempdir().expect("durable");
        let attempt = Uuid::now_v7();

        let first = stage_small(scratch.path(), b"original bytes").await;
        let promoted = promote_to_durable(first, durable.path(), attempt)
            .await
            .expect("first promotion");

        // A second staged file with DIFFERENT bytes, promoted under the same
        // attempt id: the durable copy is keyed on the id and already exists, so
        // the original is kept and the new staged file is discarded.
        let second = stage_small(scratch.path(), b"different bytes").await;
        let second_scratch = second.path().to_path_buf();
        let again = promote_to_durable(second, durable.path(), attempt)
            .await
            .expect("second promotion is a no-op");

        assert_eq!(again, promoted, "the durable path is unchanged");
        let on_disk = tokio::fs::read(&promoted).await.expect("read durable");
        assert_eq!(
            on_disk, b"original bytes",
            "the first promotion's content is preserved"
        );
        assert!(
            !second_scratch.exists(),
            "the discarded staged file is cleaned up by its guard"
        );
    }

    #[tokio::test]
    async fn deleting_a_durable_file_then_deleting_again_is_idempotent() {
        let durable = tempfile::tempdir().expect("durable");
        let attempt = Uuid::now_v7();
        let scratch = tempfile::tempdir().expect("scratch");

        let staged = stage_small(scratch.path(), b"to be deleted").await;
        let promoted = promote_to_durable(staged, durable.path(), attempt)
            .await
            .expect("promotion");

        delete_durable(&promoted).await.expect("first delete");
        assert!(!promoted.exists(), "the file is gone after the delete");
        // A settlement retry calls delete again on an already-gone file.
        delete_durable(&promoted)
            .await
            .expect("deleting an absent file is a no-op");
    }

    #[tokio::test]
    async fn the_durable_path_is_deterministic_per_attempt() {
        let dir = Path::new("/var/lib/gateway/staging");
        let attempt = Uuid::now_v7();
        // The path is reproducible from the attempt id alone, so a sweep or a
        // retry derives it without a lookup.
        assert_eq!(
            durable_staged_path(dir, attempt),
            durable_staged_path(dir, attempt)
        );
        assert_ne!(
            durable_staged_path(dir, attempt),
            durable_staged_path(dir, Uuid::now_v7())
        );
    }
}
