//! Session-scoped advisory locks held on a detached connection.
//!
//! A Postgres *session* advisory lock lives for the lifetime of the connection
//! that took it, independent of any transaction. To hold one safely from a pool
//! we acquire a connection and detach it from the pool
//! (`PoolConnection::detach`): a pooled connection returned to the pool could be
//! handed to another task while the lock is still held, and pool recycling
//! could silently drop the lock. A detached connection is owned outright by the
//! guard, so the lock's lifetime is exactly the guard's lifetime.
//!
//! Queues whose work must not overlap across replicas (a `singleton_loop`
//! policy, a non-overlapping cron job) take one of these inside the handler:
//! whichever replica holds the lock runs; the others fail to acquire and skip.

use sha2::{Digest, Sha256};
use sqlx::Connection;

use crate::Result;

/// The domain prefix every runtime advisory-lock key is derived under.
///
/// It separates this family of keys from every other advisory-lock user on the
/// same database (the SQL-side `pg_advisory_xact_lock(hashtext(...))` idiom the
/// event sequencer, the session-create serializer, and the FX cold-start seed
/// use, whose keys all sign-extend a 32-bit value and so occupy a sliver of the
/// 64-bit space these keys spread across). The `v1` tag versions the
/// derivation: it must never change silently, because two replicas on either
/// side of a rolling deploy have to contend on the same key for the same name.
const LOCK_KEY_DOMAIN: &[u8] = b"cw-gateway:advisory-lock:v1:";

/// Derive a stable 64-bit advisory-lock key from a textual lock name.
///
/// The key is the first eight bytes, big-endian, of SHA-256 over
/// `LOCK_KEY_DOMAIN` plus the name, read as a signed 64-bit integer. Using
/// the full `bigint` key space makes a collision between two distinct names —
/// two wallets spuriously serializing on one key, say — cryptographically
/// negligible, where a 32-bit derivation (the historical `hashtext` one) makes
/// cross-name collisions a realistic birthday event once enough wallets and
/// queues coexist. The derivation is deterministic and pure, so every replica
/// computes the same key for the same name with no database round trip.
pub fn lock_key(name: &str) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(LOCK_KEY_DOMAIN);
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    i64::from_be_bytes(digest[..8].try_into().expect("SHA-256 yields 32 bytes"))
}

/// A held session advisory lock.
///
/// Owns the detached connection the lock lives on. [`release`](Self::release)
/// runs `pg_advisory_unlock` and closes the connection; if the guard is dropped
/// without `release`, dropping the connection ends the session and the server
/// releases the lock regardless.
pub struct AdvisoryLock {
    key: i64,
    // The connection is detached from the pool (it is a plain `PgConnection`,
    // not a `PoolConnection`), so it is never returned to the pool while the
    // lock is held and the lock cannot leak onto another task's checkout.
    conn: Option<sqlx::PgConnection>,
}

impl AdvisoryLock {
    /// Block until the advisory lock for `name` is acquired on a detached
    /// connection from `pool`.
    pub async fn acquire(pool: &sqlx::PgPool, name: &str) -> Result<Self> {
        let key = lock_key(name);
        let mut conn = pool.acquire().await?.detach();
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(key)
            .execute(&mut conn)
            .await?;
        Ok(Self {
            key,
            conn: Some(conn),
        })
    }

    /// Acquire the advisory lock for `name`, blocking up to `deadline` before
    /// giving up.
    ///
    /// Returns `Ok(Some(guard))` when the lock was acquired within the deadline,
    /// or `Ok(None)` when the wait timed out (the lock was held by another session
    /// the whole time). The bound is enforced with a session `lock_timeout`, so a
    /// blocked `pg_advisory_lock` aborts with a timeout error rather than waiting
    /// indefinitely. This is the bounded-fair escalation a confirm/abandon mutation
    /// uses after it has yielded too many times: a `try_acquire` that keeps losing
    /// the race to fresh submit acquisitions escalates to this bounded wait, which
    /// still takes the wallet advisory lock before any row lock (the lock-order
    /// invariant holds), so a persistently-contended record acquires the lock in
    /// bounded time rather than only eventually.
    pub async fn acquire_with_deadline(
        pool: &sqlx::PgPool,
        name: &str,
        deadline: std::time::Duration,
    ) -> Result<Option<Self>> {
        let key = lock_key(name);
        let mut conn = pool.acquire().await?.detach();
        let timeout_ms = i64::try_from(deadline.as_millis())
            .map_err(|_| crate::Error::Config("lock deadline overflow".into()))?
            .max(1);
        // A session lock_timeout bounds the blocking pg_advisory_lock: if the lock
        // is not granted within the deadline the statement aborts with SQLSTATE
        // 55P03 (lock_not_available), which we map to Ok(None). Set it on this
        // detached connection only; it is closed on either outcome.
        sqlx::query("SET lock_timeout = $1")
            .bind(format!("{timeout_ms}ms"))
            .execute(&mut conn)
            .await?;
        let acquired = sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(key)
            .execute(&mut conn)
            .await;
        match acquired {
            Ok(_) => {
                // Clear the timeout so the held session does not carry it onto any
                // later statement the guard runs.
                let _ = sqlx::query("SET lock_timeout = 0").execute(&mut conn).await;
                Ok(Some(Self {
                    key,
                    conn: Some(conn),
                }))
            }
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("55P03") => {
                // The bounded wait elapsed with the lock still held. Close this
                // detached session so it does not consume pool capacity.
                conn.close().await?;
                Ok(None)
            }
            Err(err) => {
                let _ = conn.close().await;
                Err(err.into())
            }
        }
    }

    /// Try to acquire the advisory lock for `name` without blocking.
    ///
    /// Returns `Ok(Some(guard))` if the lock was free and is now held, or
    /// `Ok(None)` if another session holds it. The non-overlapping primitive:
    /// the replica that gets `Some` runs; the others get `None` and skip. A
    /// connection that fails to take the lock is closed rather than leaked, so a
    /// losing replica does not permanently consume a pool slot.
    pub async fn try_acquire(pool: &sqlx::PgPool, name: &str) -> Result<Option<Self>> {
        let key = lock_key(name);
        let mut conn = pool.acquire().await?.detach();
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut conn)
            .await?;
        if acquired {
            Ok(Some(Self {
                key,
                conn: Some(conn),
            }))
        } else {
            // Did not take the lock: end this detached session so it does not
            // count against the pool's capacity forever.
            conn.close().await?;
            Ok(None)
        }
    }

    /// The 64-bit key this lock was taken on.
    pub fn key(&self) -> i64 {
        self.key
    }

    /// Explicitly release the lock and close the detached connection.
    pub async fn release(mut self) -> Result<()> {
        // Take the connection out so the `Drop` impl does not also try to end a
        // session we are closing cleanly here.
        if let Some(mut conn) = self.conn.take() {
            let key = self.key;
            sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(key)
                .execute(&mut conn)
                .await?;
            conn.close().await?;
        }
        Ok(())
    }
}

impl Drop for AdvisoryLock {
    fn drop(&mut self) {
        // If the guard is dropped without an explicit `release`, ending the
        // session releases the lock. Closing a connection is async, so we hand
        // the owned connection to a detached task that runs the clean shutdown;
        // even if that task never gets to run, dropping the connection still
        // tears down the session and the server releases the lock.
        if let Some(conn) = self.conn.take() {
            tokio::spawn(async move {
                let _ = conn.close().await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden keys pin the derivation: it must be stable across releases, or
    /// two replicas on either side of a rolling deploy would stop contending
    /// on the same lock for the same name.
    #[test]
    fn lock_keys_are_pinned_and_deterministic() {
        for (name, expected) in [
            ("cw_core_chain_scan", -3_852_523_968_382_213_052_i64),
            ("cw_core:partition_maintenance", 9_126_968_571_152_581_247),
            (
                "wallet:0197c9a0-0000-7000-8000-000000000001",
                3_905_563_414_987_871_156,
            ),
            ("", 7_842_178_380_053_309_147),
        ] {
            assert_eq!(lock_key(name), expected, "key drifted for {name:?}");
        }
    }

    /// The keys occupy the full 64-bit space, not a sign-extended 32-bit
    /// sliver: a 32-bit derivation would make two distinct wallet locks
    /// colliding onto one key a realistic birthday event.
    #[test]
    fn lock_keys_use_the_full_64_bit_space() {
        let spread = ["cw_core_chain_scan", "cw_core:partition_maintenance", ""]
            .iter()
            .any(|name| {
                let key = lock_key(name);
                key > i64::from(i32::MAX) || key < i64::from(i32::MIN)
            });
        assert!(spread, "every sampled key fits in 32 bits");
    }

    #[test]
    fn distinct_names_derive_distinct_keys() {
        let names = [
            "wallet:0197c9a0-0000-7000-8000-000000000001",
            "wallet:0197c9a0-0000-7000-8000-000000000002",
            "cw_core_chain_scan",
            "cw_core:partition_maintenance",
        ];
        for (i, a) in names.iter().enumerate() {
            for b in &names[i + 1..] {
                assert_ne!(lock_key(a), lock_key(b), "{a:?} and {b:?} collide");
            }
        }
    }
}
