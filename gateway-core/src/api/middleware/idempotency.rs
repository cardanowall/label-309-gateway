//! Idempotent replay of mutating responses.
//!
//! A mutating request may carry an `Idempotency-Key`. The first time a
//! `(account, key)` pair commits, its response is persisted; a later request with
//! the same pair replays the stored status and body byte-for-byte (the caller
//! stamps an `Idempotent-Replayed` header). A same-key request whose payload hash
//! differs is a conflict.
//!
//! A NON-COMMITTING outcome (a 402 that charged nothing) is deliberately NOT
//! persisted, so a retry after a top-up runs fresh against the new balance. That
//! is enforced by the writing path passing only committing responses to
//! [`store`].

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::Result;

/// How long a stored idempotency response is replayable before its key may be
/// reused. 24 hours matches the published contract.
pub const IDEMPOTENCY_TTL_SECONDS: i64 = 24 * 60 * 60;

/// A stored idempotent response, ready to replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredResponse {
    /// The HTTP status to replay.
    pub status: u16,
    /// The response body to replay verbatim.
    pub body: Vec<u8>,
    /// The response content type to replay.
    pub content_type: String,
}

/// The outcome of looking up an idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// No stored response: run the handler.
    Miss,
    /// A stored response whose request hash matches: replay it.
    Hit(StoredResponse),
    /// A stored response whose request hash differs: the key was reused for a
    /// different request (the caller returns 409 `idempotency-key-conflict`).
    Conflict,
}

/// Compute the canonical request hash over `(method, path, body)`.
///
/// The conflict discriminator: two requests with the same key but different
/// canonical content hash to different values, which is what surfaces a reused
/// key. The hash binds the method and path too so the same key on two endpoints
/// never aliases.
#[must_use]
pub fn request_hash(method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\n");
    hasher.update(path.as_bytes());
    hasher.update(b"\n");
    hasher.update(body);
    hasher.finalize().to_vec()
}

/// Look up an idempotency key for an account, comparing the request hash.
///
/// An expired row reads as a [`Lookup::Miss`] so the key may be reused after its
/// TTL. A live row with a matching hash is a [`Lookup::Hit`]; a live row with a
/// differing hash is a [`Lookup::Conflict`].
pub async fn lookup(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    key: &str,
    req_hash: &[u8],
    now: DateTime<Utc>,
) -> Result<Lookup> {
    let row: Option<StoredRow> = sqlx::query_as(
        "SELECT request_hash, response_status, response_body, response_content_type, expires_at \
         FROM cw_core.idempotency_keys \
         WHERE account_id = $1 AND idempotency_key = $2",
    )
    .bind(account_id)
    .bind(key)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(Lookup::Miss);
    };

    if row.expires_at <= now {
        return Ok(Lookup::Miss);
    }

    if row.request_hash != req_hash {
        return Ok(Lookup::Conflict);
    }

    Ok(Lookup::Hit(StoredResponse {
        status: u16::try_from(row.response_status).unwrap_or(500),
        body: row.response_body,
        content_type: row.response_content_type,
    }))
}

/// Store a committed response for replay.
///
/// Called ONLY for a committing response (the writing path never passes a
/// non-committing 402 here), so a row exists exactly when a replay should occur.
/// The upsert replaces an expired row in place, which is what lets a key be
/// reused after its TTL.
pub async fn store(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    key: &str,
    req_hash: &[u8],
    response: &StoredResponse,
    now: DateTime<Utc>,
) -> Result<()> {
    let expires_at = now + Duration::seconds(IDEMPOTENCY_TTL_SECONDS);
    sqlx::query(
        "INSERT INTO cw_core.idempotency_keys \
           (account_id, idempotency_key, request_hash, response_status, response_body, \
            response_content_type, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (account_id, idempotency_key) \
         DO UPDATE SET request_hash = EXCLUDED.request_hash, \
                       response_status = EXCLUDED.response_status, \
                       response_body = EXCLUDED.response_body, \
                       response_content_type = EXCLUDED.response_content_type, \
                       created_at = EXCLUDED.created_at, \
                       expires_at = EXCLUDED.expires_at \
         WHERE cw_core.idempotency_keys.expires_at <= EXCLUDED.created_at",
    )
    .bind(account_id)
    .bind(key)
    .bind(req_hash)
    .bind(i16::try_from(response.status).unwrap_or(500))
    .bind(&response.body)
    .bind(&response.content_type)
    .bind(now)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Prune expired idempotency rows. The scheduled maintenance pass.
pub async fn prune_expired(pool: &sqlx::PgPool, now: DateTime<Utc>) -> Result<u64> {
    let affected = sqlx::query("DELETE FROM cw_core.idempotency_keys WHERE expires_at <= $1")
        .bind(now)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(affected)
}

/// Whether an HTTP status is non-committing and therefore must NOT be persisted.
///
/// A 402 charged nothing, so a same-key retry after a top-up must run fresh. The
/// set is deliberately narrow: only the affordability failure is non-committing.
/// This is the single-shot / publish policy, where a partial-batch failure is a
/// per-item error inside a committing 2xx envelope rather than a top-level status.
#[must_use]
pub fn is_non_committing(status: u16) -> bool {
    status == 402
}

/// Whether a `/complete` outcome is TERMINAL and therefore safe to persist under an
/// idempotency key.
///
/// A `/complete` request, unlike single-shot uploads or publish, can legitimately
/// return a NON-FINAL status that a later retry of the SAME key resolves: a
/// precondition-not-yet-met (the client called `/complete` before every chunk
/// arrived), or a transient dependency failure (the session reverted to open, or
/// bridged to a live attempt). Persisting any of those under the key would poison it,
/// replaying a non-final outcome forever even after the client uploads the remaining
/// chunks or the dependency recovers. Only an outcome that the session can never move
/// off is committing:
///
///   * `200` — committed / deduped / accepted-and-bridged (the session is settled).
///   * `400` — the assembled bytes did not match the declared hash; the session is
///     permanently `failed`, so replaying the rejection is correct.
///   * `410` — the session passed its TTL; terminal and never retryable.
///
/// Everything else is non-final and must run fresh on retry: `409`
/// (incomplete-upload, or a still-finalising race), `422` (a validation failure),
/// `402` (affordability, top up and retry), `503` (a transient dependency outage),
/// and `500` (a transient internal fault, e.g. a read of the just-assembled file).
#[must_use]
pub fn complete_outcome_is_committing(status: u16) -> bool {
    matches!(status, 200 | 400 | 410)
}

/// The columns a lookup reads back.
#[derive(sqlx::FromRow)]
struct StoredRow {
    request_hash: Vec<u8>,
    response_status: i16,
    response_body: Vec<u8>,
    response_content_type: String,
    expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_hash_distinguishes_method_path_and_body() {
        let a = request_hash("POST", "/api/v1/poe/publish", b"{}");
        let b = request_hash("POST", "/api/v1/poe/publish", b"{\"x\":1}");
        let c = request_hash("POST", "/api/v1/poe/quote", b"{}");
        let d = request_hash("GET", "/api/v1/poe/publish", b"{}");
        assert_ne!(a, b, "different body hashes differently");
        assert_ne!(a, c, "different path hashes differently");
        assert_ne!(a, d, "different method hashes differently");
        assert_eq!(a, request_hash("POST", "/api/v1/poe/publish", b"{}"));
    }

    #[test]
    fn only_402_is_non_committing() {
        assert!(is_non_committing(402));
        assert!(!is_non_committing(200));
        assert!(!is_non_committing(202));
        assert!(!is_non_committing(409));
        assert!(!is_non_committing(500));
    }

    #[test]
    fn complete_persists_only_terminal_outcomes() {
        // Terminal: a settled session, a permanent hash failure, or an expired TTL is
        // safe to replay under the key.
        assert!(complete_outcome_is_committing(200));
        assert!(complete_outcome_is_committing(400));
        assert!(complete_outcome_is_committing(410));
        // Non-final: each of these is resolvable by a same-key retry (more chunks, a
        // top-up, a recovered dependency), so it must NOT poison the key.
        assert!(!complete_outcome_is_committing(409)); // incomplete-upload
        assert!(!complete_outcome_is_committing(422)); // validation
        assert!(!complete_outcome_is_committing(402)); // affordability
        assert!(!complete_outcome_is_committing(503)); // transient
        assert!(!complete_outcome_is_committing(500)); // transient internal
    }
}
