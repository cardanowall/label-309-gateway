//! Bearer credential resolution and authorization.
//!
//! A request authenticates with `Authorization: Bearer <secret>`. The secret is
//! hashed with SHA-256; its first 8 bytes are the lookup prefix the auth query
//! indexes on, and the full 32-byte hash is compared in constant time against the
//! candidate row's stored hash. The secret's operator-configured human prefix is
//! validated against the stored prefix. A successful resolve yields a [`Viewer`]
//! carrying the account and granted scopes the handler authorizes against.
//!
//! The engine stores no key prefix of its own: the prefix is an operator choice
//! per key, so there is no hardcoded `sk-…` brand string anywhere in this path.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::Result;

/// The number of leading SHA-256 bytes used as the key lookup prefix.
const KEY_LOOKUP_BYTES: usize = 8;

/// An authenticated caller resolved from a Bearer credential.
#[derive(Debug, Clone)]
pub struct Viewer {
    /// The api-key row id (the rate-limit subject and audit handle).
    pub key_id: Uuid,
    /// The account the key belongs to.
    pub account_id: Uuid,
    /// The scopes the key was granted.
    pub scopes: Vec<String>,
    /// The key's custom per-minute budget, or `None` to meter against the
    /// data-plane default.
    pub rate_limit_per_min: Option<i32>,
}

/// Why a Bearer credential failed to resolve.
///
/// Format failure and an unknown key collapse to the same outcome at the HTTP
/// boundary (a 401 `unauthorized`) so a scanner cannot tell a malformed key from
/// a well-formed but unknown one; the distinction is kept here only for logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// No `Authorization: Bearer` header, or an empty token.
    Missing,
    /// The presented secret did not match any live key.
    Unknown,
}

/// Resolve a Bearer secret to a [`Viewer`], or report why it failed.
///
/// Hashes the secret, narrows to live candidate rows by the 8-byte lookup
/// prefix, and constant-time-compares the full hash against each candidate. The
/// stored operator prefix is verified too, so a secret whose prefix does not
/// match the row it hashes to is rejected. A best-effort `last_used_at` bump is
/// left to the caller (it is not on the authentication critical path).
pub async fn resolve_bearer(
    pool: &sqlx::PgPool,
    secret: &str,
) -> Result<std::result::Result<Viewer, AuthFailure>> {
    if secret.is_empty() {
        return Ok(Err(AuthFailure::Missing));
    }

    let full_hash = Sha256::digest(secret.as_bytes());
    let lookup = &full_hash[..KEY_LOOKUP_BYTES];

    // Narrow to live candidates by the lookup prefix. The 8-byte prefix can
    // collide, so several rows may come back; the full-hash compare below picks
    // the one (if any) whose secret actually matches.
    let candidates: Vec<KeyRow> = sqlx::query_as(
        "SELECT id, account_id, prefix, key_hash_sha256, scopes, rate_limit_per_min \
         FROM cw_core.api_key \
         WHERE key_lookup = $1 AND revoked_at IS NULL",
    )
    .bind(lookup)
    .fetch_all(pool)
    .await?;

    for row in candidates {
        // Constant-time compare the full 32-byte hash so the number of matching
        // leading bytes never leaks through timing.
        let stored: &[u8] = &row.key_hash_sha256;
        if full_hash.as_slice().ct_eq(stored).into() {
            // Defensive: the presented secret must carry the row's operator prefix.
            // (The hash already proves identity; this guards a row whose prefix was
            // edited out of band.)
            if secret.starts_with(&row.prefix) {
                return Ok(Ok(Viewer {
                    key_id: row.id,
                    account_id: row.account_id,
                    scopes: row.scopes,
                    rate_limit_per_min: row.rate_limit_per_min,
                }));
            }
        }
    }

    Ok(Err(AuthFailure::Unknown))
}

/// Best-effort bump of a key's `last_used_at`. Fire-and-forget: a failure here
/// never affects the request, so the caller may ignore the result.
pub async fn touch_last_used(pool: &sqlx::PgPool, key_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE cw_core.api_key SET last_used_at = now() WHERE id = $1")
        .bind(key_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Extract the Bearer token from an `Authorization` header value.
///
/// Returns `None` when the scheme is not `Bearer` (case-insensitive) or the
/// token is empty, so a malformed header maps to [`AuthFailure::Missing`].
#[must_use]
pub fn bearer_token(authorization: &str) -> Option<&str> {
    let (scheme, token) = authorization.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// The columns the auth query reads back from a candidate key row.
#[derive(sqlx::FromRow)]
struct KeyRow {
    id: Uuid,
    account_id: Uuid,
    prefix: String,
    key_hash_sha256: Vec<u8>,
    scopes: Vec<String>,
    rate_limit_per_min: Option<i32>,
}

/// Compute the `(lookup_prefix, full_hash)` an issuer stores for a secret.
///
/// Exposed for key-issuance and the conformance harness's direct seeding: the
/// lookup is the first 8 bytes of SHA-256(secret), the hash is the full 32. The
/// stored values must be produced exactly this way for [`resolve_bearer`] to
/// find the row.
#[must_use]
pub fn hash_secret(secret: &str) -> (Vec<u8>, Vec<u8>) {
    let full = Sha256::digest(secret.as_bytes());
    (full[..KEY_LOOKUP_BYTES].to_vec(), full.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_extracts_a_bearer_secret() {
        assert_eq!(bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(bearer_token("bearer abc123"), Some("abc123"));
        assert_eq!(bearer_token("BEARER  abc123  "), Some("abc123"));
    }

    #[test]
    fn bearer_token_rejects_other_schemes_and_empties() {
        assert_eq!(bearer_token("Basic abc123"), None);
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token("abc123"), None);
    }

    #[test]
    fn hash_secret_lookup_is_the_first_eight_hash_bytes() {
        let (lookup, full) = hash_secret("a-secret");
        assert_eq!(lookup.len(), KEY_LOOKUP_BYTES);
        assert_eq!(full.len(), 32);
        assert_eq!(&full[..KEY_LOOKUP_BYTES], lookup.as_slice());
    }

    #[test]
    fn hash_secret_is_deterministic_and_distinct() {
        assert_eq!(hash_secret("x"), hash_secret("x"));
        assert_ne!(hash_secret("x").1, hash_secret("y").1);
    }
}
