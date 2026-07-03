//! Upload ceilings for the multipart staging path.
//!
//! These are DoS backstops, not a product limit: content is billed per byte and
//! a deployment is expected to accept multi-gigabyte blobs. The ceilings exist
//! only to bound a single request's resource use (disk staged, parts parsed) so
//! a malicious caller cannot exhaust the host with one unbounded request. A
//! deployment tunes them via [`UploadLimits`]; the defaults match the wire
//! contract.

/// The default per-file ceiling: 10 GiB. A single staged content blob may not
/// exceed this; the staging stream aborts the instant it is crossed.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// The default per-request batch ceiling: 10 GiB across all files in one call.
pub const DEFAULT_MAX_BATCH_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// The default maximum number of files one upload call may carry.
pub const DEFAULT_MAX_FILES: usize = 32;

/// The default suggested chunk size for a resumable upload: 48 MiB. The server
/// returns this when the client declares none, and clamps a larger request down to
/// [`DEFAULT_MAX_CHUNK_BYTES`]. Held well under a ~100 MB CDN body cap with margin
/// for transport overhead and for stricter intermediate proxy caps that can sit
/// below the CDN's.
pub const DEFAULT_CHUNK_BYTES: u64 = 50_331_648;

/// The default hard per-chunk ceiling: 64 MiB. A chunk PUT whose `Content-Length`
/// exceeds this is rejected before the body is read. Set safely under a ~100 MB CDN
/// body cap; an operator behind a tighter proxy lowers it, one with more headroom
/// raises it.
pub const DEFAULT_MAX_CHUNK_BYTES: u64 = 67_108_864;

/// The default minimum chunk size: 1 MiB. A session's per-connection state (the
/// received bitmap, the resume `received`/`missing` sets) is proportional to its
/// chunk COUNT, so a tiny chunk size is a memory-amplification lever: a 10 GiB
/// declaration at 1-byte chunks would imply ~10^10 chunks. The floor keeps the
/// grid dense enough that the count stays small (10 GiB / 1 MiB = 10,240 chunks,
/// a 1.25 KiB bitmap) while any real resumable-upload client comfortably clears
/// it (the suggested chunk is 48 MiB).
pub const DEFAULT_MIN_CHUNK_BYTES: u64 = 1_048_576;

/// The hard ceiling on a session's chunk count, enforced BEFORE any bitmap or
/// assembling file exists. This is an engine invariant, not an operator knob: every
/// per-session structure that scales with the grid (the bitmap row, the status
/// read's `received`/`missing` sets, the per-chunk digest rows) is bounded by it,
/// so no configuration can reintroduce the amplification.
///
/// 16,384 chunks covers the default 10 GiB per-file ceiling at the default 1 MiB
/// minimum chunk (10,240 chunks) and reaches 1 TiB at the default 64 MiB per-chunk
/// ceiling, while capping the bitmap at 2 KiB and the resume sets at 16,384
/// indices. A deployment that raises `max_file_bytes` far beyond that must also
/// raise its chunk sizes so the grid still fits — the create route's rejection
/// names the minimum workable `chunk_bytes` for the declared total.
pub const MAX_SESSION_CHUNKS: u32 = 16_384;

/// The framing slack added on top of [`UploadLimits::max_batch_bytes`] when the
/// batch ceiling is projected onto an HTTP request-body limit: multipart
/// boundaries, per-part headers, and the small metadata fields (`target`) ride
/// alongside the file bytes in the same body. 1 MiB covers the framing of a
/// maximum-files batch many times over while staying negligible against the
/// multi-GiB ceilings it pads.
pub const MULTIPART_FRAMING_SLACK_BYTES: u64 = 1024 * 1024;

/// The default abandoned-session horizon: 24 hours. A session past this with no
/// completion is reclaimable by the janitor.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 86_400;

/// The default cap on concurrently open sessions per account: backpressure against
/// a client opening unbounded sessions to exhaust assembling-file disk.
pub const DEFAULT_MAX_OPEN_SESSIONS_PER_ACCOUNT: u32 = 64;

/// The configurable tunables for the resumable / chunked upload sessions.
///
/// These bound a session's chunk grid and lifetime. There is deliberately NO total
/// upload-size cap here: a session's `total_bytes` reuses the per-file DoS ceiling
/// ([`UploadLimits::max_file_bytes`]) as its one backstop, so a large-content
/// deployment tunes a single knob, not two. The assembling directory is not here
/// either: it reuses the durable staging directory the attempt promotion already
/// uses, so a session's pre-reservation file and the attempt's post-reservation
/// file live in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadSessionLimits {
    /// The hard per-chunk ceiling. A chunk `Content-Length` over this is `413` before
    /// the body is read; a create request's `chunk_bytes` is clamped down to it.
    pub max_chunk_bytes: u64,
    /// The chunk-size floor. A create request declaring a smaller `chunk_bytes` is
    /// clamped UP to it (the response's chunk grid is authoritative, exactly as an
    /// over-ceiling request is clamped down), so a degenerate chunk size can never
    /// inflate the session's chunk count. See [`DEFAULT_MIN_CHUNK_BYTES`] for why
    /// the floor exists.
    pub min_chunk_bytes: u64,
    /// The chunk size the server suggests when a create request declares none, and
    /// the value it clamps a larger request to (never above `max_chunk_bytes`).
    pub default_chunk_bytes: u64,
    /// The abandoned-session horizon in seconds; a session's `expires_at` is
    /// `created_at + this`.
    pub session_ttl_secs: u64,
    /// The cap on concurrently open sessions per account (backpressure).
    pub max_open_sessions_per_account: u32,
}

impl Default for UploadSessionLimits {
    fn default() -> Self {
        Self {
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            min_chunk_bytes: DEFAULT_MIN_CHUNK_BYTES,
            default_chunk_bytes: DEFAULT_CHUNK_BYTES,
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            max_open_sessions_per_account: DEFAULT_MAX_OPEN_SESSIONS_PER_ACCOUNT,
        }
    }
}

impl UploadSessionLimits {
    /// The chunk size the server will enforce for a session: the client's request
    /// clamped to `[min_chunk_bytes, max_chunk_bytes]`, falling back to
    /// `default_chunk_bytes` when the client declares none or a non-positive value.
    /// Clamping is symmetric — an over-ceiling request comes down, an under-floor
    /// request comes up — because the create response's chunk grid is authoritative
    /// either way, and a floor-less resolve would let `chunk_bytes: 1` explode the
    /// chunk count. The returned size is fixed for the session, which is what makes
    /// `offset = index * chunk_bytes` a pure function and the received set a
    /// compact bitmap.
    #[must_use]
    pub fn resolve_chunk_bytes(&self, requested: Option<u64>) -> u64 {
        let ceiling = self.max_chunk_bytes.max(1);
        let floor = self.min_chunk_bytes.clamp(1, ceiling);
        let default = self.default_chunk_bytes.clamp(floor, ceiling);
        match requested {
            Some(r) if r > 0 => r.clamp(floor, ceiling),
            _ => default,
        }
    }

    /// The HTTP request-body limit for the chunk-PUT route: exactly the per-chunk
    /// ceiling (a chunk body is raw octets, no framing).
    ///
    /// The chunk handler streams the raw body and enforces this ceiling itself (a
    /// declared `Content-Length` over it is `413` before the body is read, and the
    /// streaming ingest bounds the actual bytes against the chunk grid), but the
    /// router still installs the limit explicitly so the route's wire cap is
    /// stated where the routes are wired — and so a future change to a buffering
    /// body extractor cannot silently fall back to the HTTP framework's built-in
    /// default (axum: 2 MiB), which would cap every chunk far below the
    /// gateway's own ceiling.
    #[must_use]
    pub fn chunk_request_body_limit(&self) -> usize {
        usize::try_from(self.max_chunk_bytes).unwrap_or(usize::MAX)
    }
}

/// The configurable upload ceilings for one `/poe/uploads` call.
///
/// Each is a DoS backstop the operator may tune; the defaults match the wire
/// contract (10 GiB per file, 10 GiB per batch, 32 files).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadLimits {
    /// The maximum size of any single staged file, in bytes.
    pub max_file_bytes: u64,
    /// The maximum cumulative size across all files in one call, in bytes.
    pub max_batch_bytes: u64,
    /// The maximum number of files one call may carry.
    pub max_files: usize,
}

impl Default for UploadLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            max_files: DEFAULT_MAX_FILES,
        }
    }
}

impl UploadLimits {
    /// Whether a declared `Content-Length` exceeds the batch ceiling, so the
    /// route can reject an over-large request cheaply before streaming a byte.
    ///
    /// A request that under-declares its length (or omits it) is not rejected
    /// here; the per-file and per-batch streaming ceilings catch the real size as
    /// it lands. This is purely the cheap early-out for an honestly-declared
    /// over-large request.
    #[must_use]
    pub fn rejects_declared_length(&self, content_length: u64) -> bool {
        content_length > self.max_batch_bytes
    }

    /// The remaining batch budget given how many bytes have already been staged,
    /// so the next file is staged against the smaller of its own ceiling and what
    /// is left of the batch.
    #[must_use]
    pub fn remaining_batch_budget(&self, staged_so_far: u64) -> u64 {
        self.max_batch_bytes.saturating_sub(staged_so_far)
    }

    /// The HTTP request-body limit for the single-shot multipart route: the batch
    /// ceiling plus `MULTIPART_FRAMING_SLACK_BYTES` of framing.
    ///
    /// The router must install this explicitly, because the HTTP framework ships
    /// its own built-in default body limit (axum: 2 MiB) that would otherwise
    /// silently override the gateway's documented ceilings — the streaming
    /// per-file/per-batch enforcement in the route never sees the bytes the
    /// framework already refused. This limit is the outer wire backstop; the
    /// route's own streaming ceilings remain the precise per-file/per-batch
    /// arbiters inside it.
    #[must_use]
    pub fn request_body_limit(&self) -> usize {
        usize::try_from(
            self.max_batch_bytes
                .saturating_add(MULTIPART_FRAMING_SLACK_BYTES),
        )
        .unwrap_or(usize::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_wire_contract() {
        let limits = UploadLimits::default();
        assert_eq!(limits.max_file_bytes, 10 * 1024 * 1024 * 1024);
        assert_eq!(limits.max_batch_bytes, 10 * 1024 * 1024 * 1024);
        assert_eq!(limits.max_files, 32);
    }

    #[test]
    fn declared_length_over_the_batch_ceiling_is_rejected_early() {
        let limits = UploadLimits {
            max_batch_bytes: 1000,
            ..UploadLimits::default()
        };
        assert!(limits.rejects_declared_length(1001));
        assert!(!limits.rejects_declared_length(1000));
        assert!(!limits.rejects_declared_length(0));
    }

    #[test]
    fn session_chunk_defaults_sit_under_a_100_mb_cap() {
        let limits = UploadSessionLimits::default();
        // 64 MiB ceiling / 48 MiB default / 1 MiB floor, the ceiling well under a
        // ~100 MB CDN body cap.
        assert_eq!(limits.max_chunk_bytes, 67_108_864);
        assert_eq!(limits.min_chunk_bytes, 1_048_576);
        assert_eq!(limits.default_chunk_bytes, 50_331_648);
        assert!(limits.max_chunk_bytes < 100_000_000);
        assert_eq!(limits.session_ttl_secs, 86_400);
        assert_eq!(limits.max_open_sessions_per_account, 64);
    }

    #[test]
    fn the_default_grid_bound_covers_the_default_file_ceiling() {
        // The engine invariant: a maximum-size file at the minimum chunk still fits
        // the hard chunk-count ceiling, so the defaults can never reject a grid the
        // per-file ceiling admits.
        let session = UploadSessionLimits::default();
        let upload = UploadLimits::default();
        assert!(
            upload.max_file_bytes.div_ceil(session.min_chunk_bytes)
                <= u64::from(MAX_SESSION_CHUNKS)
        );
    }

    #[test]
    fn resolve_chunk_bytes_clamps_into_the_floor_ceiling_band() {
        let limits = UploadSessionLimits {
            max_chunk_bytes: 1000,
            min_chunk_bytes: 100,
            default_chunk_bytes: 400,
            ..UploadSessionLimits::default()
        };
        // A declared size within the band is honoured.
        assert_eq!(limits.resolve_chunk_bytes(Some(600)), 600);
        // A declared size over the ceiling is clamped down.
        assert_eq!(limits.resolve_chunk_bytes(Some(5000)), 1000);
        // A declared size under the floor is clamped UP — the degenerate
        // `chunk_bytes: 1` can never inflate the chunk count.
        assert_eq!(limits.resolve_chunk_bytes(Some(1)), 100);
        assert_eq!(limits.resolve_chunk_bytes(Some(99)), 100);
        // No declared size (or a non-positive one) falls back to the default.
        assert_eq!(limits.resolve_chunk_bytes(None), 400);
        assert_eq!(limits.resolve_chunk_bytes(Some(0)), 400);
    }

    #[test]
    fn request_body_limit_is_the_batch_ceiling_plus_framing_slack() {
        let limits = UploadLimits::default();
        assert_eq!(
            limits.request_body_limit() as u64,
            limits.max_batch_bytes + MULTIPART_FRAMING_SLACK_BYTES
        );
        // The default wire cap must clear the largest valid batch with framing,
        // and in particular sit far above the 2 MiB built-in default of the HTTP
        // framework that this limit exists to override.
        assert!(limits.request_body_limit() > 2 * 1024 * 1024);

        // A u64 ceiling near the top saturates instead of overflowing.
        let huge = UploadLimits {
            max_batch_bytes: u64::MAX,
            ..UploadLimits::default()
        };
        assert_eq!(huge.request_body_limit(), usize::MAX);
    }

    #[test]
    fn chunk_request_body_limit_matches_the_chunk_ceiling() {
        let limits = UploadSessionLimits::default();
        assert_eq!(
            limits.chunk_request_body_limit() as u64,
            limits.max_chunk_bytes
        );
        // The default chunk ceiling (64 MiB) must itself exceed the framework's
        // 2 MiB built-in default, or every default-sized chunk PUT would be
        // refused at the wire before the route's own enforcement runs.
        assert!(limits.chunk_request_body_limit() > 2 * 1024 * 1024);
    }

    #[test]
    fn remaining_batch_budget_shrinks_and_saturates_at_zero() {
        let limits = UploadLimits {
            max_batch_bytes: 100,
            ..UploadLimits::default()
        };
        assert_eq!(limits.remaining_batch_budget(0), 100);
        assert_eq!(limits.remaining_batch_budget(60), 40);
        assert_eq!(
            limits.remaining_batch_budget(200),
            0,
            "an over-budget staged total saturates rather than underflowing"
        );
    }
}
