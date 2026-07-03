//! Integration-test harness (compiled only under the `pg-tests` feature).
//!
//! Brings up isolated Postgres databases for the engine's integration suites and
//! applies the embedded migrations to them. The harness never touches a shared
//! application database: it owns the databases it creates, whose names are
//! derived from `GATEWAY_TEST_DATABASE_URL` (default
//! `cardanowall_gateway_test`).
//!
//! # Isolation model
//!
//! [`TestDb::fresh`] mints a *uniquely named* database per call (the configured
//! base name plus a UUIDv7 suffix), creates it, runs [`crate::MIGRATOR`], and
//! drops it again when the returned handle is dropped. Because each call owns a
//! distinct database, an arbitrary number of `#[tokio::test]`s can call `fresh`
//! at the same time without racing on `CREATE DATABASE`/`DROP DATABASE` for a
//! single shared name, and one test's writes can never be seen by another. This
//! is the harness's correctness boundary: there is no shared mutable state
//! between tests, so cargo's default test concurrency is safe.
//!
//! [`reset_and_migrate`] is the lower-level primitive for the few suites that
//! deliberately *share* one database across the tests in a binary (resetting it
//! exactly once and isolating tests by row scope). It drops and recreates the
//! named database in place. It is not safe to call concurrently against the same
//! name, which is why concurrent per-test callers use [`TestDb::fresh`] instead.

use sqlx::Connection;
use tokio::sync::Semaphore;

use crate::{Error, Result};

/// The environment variable carrying the engine test database URL.
pub const TEST_DATABASE_URL_ENV: &str = "GATEWAY_TEST_DATABASE_URL";

/// How many [`TestDb::fresh`] setups (CREATE DATABASE plus the migration run)
/// may be in flight at once, process-wide.
///
/// The migration corpus is DDL-heavy: one migration transaction holds on the
/// order of 500 relation/object locks at commit, and Postgres sizes its shared
/// lock table at `max_locks_per_transaction x max_connections` (64 x 100 =
/// 6400 slots on a stock server). An unbounded parallel suite runs one
/// migration per test thread simultaneously; on a many-core machine that
/// brushes the lock-table ceiling and fails arbitrary sibling tests with
/// SQLSTATE 53200 ("out of shared memory"). Four in flight keeps peak lock
/// demand near a third of the stock capacity, while adding negligible
/// wall-clock (a create+migrate takes well under a second).
const MAX_CONCURRENT_SETUPS: usize = 4;

/// The concurrency gate for the create+migrate phase of [`TestDb::fresh`].
/// Never closed, so acquiring can only wait, not fail.
static SETUP_GATE: Semaphore = Semaphore::const_new(MAX_CONCURRENT_SETUPS);

/// The connection cap for the pool a [`TestDb::fresh`] handle carries.
///
/// A pg integration test drives a handful of concurrent queries at most (the
/// test body, a few request handlers, one NOTIFY listener), so five
/// connections cost it nothing — while sqlx's default of ten per pool lets a
/// parallel suite demand more backends than a stock server's
/// `max_connections` (100) and fail arbitrary tests with SQLSTATE 53300
/// ("sorry, too many clients already"). A test that genuinely needs a wider
/// pool sizes one explicitly via [`TestDb::pool_with`].
const FRESH_POOL_MAX_CONNECTIONS: u32 = 5;

/// The URL used when [`TEST_DATABASE_URL_ENV`] is unset.
pub const DEFAULT_TEST_DATABASE_URL: &str =
    "postgres://cardanowall:cardanowall_dev@localhost:5432/cardanowall_gateway_test";

/// A connected, migrated, *uniquely named* test database.
///
/// The database is created on [`TestDb::fresh`] and dropped when this handle is
/// dropped, so each test owns an isolated database for its lifetime. Holds the
/// pool the test uses plus the admin URL needed to drop the database on cleanup.
pub struct TestDb {
    /// Pool connected to this test's own database, capped at
    /// `FRESH_POOL_MAX_CONNECTIONS`; size a wider one via [`Self::pool_with`].
    pub pool: sqlx::PgPool,
    /// The unique database name the harness created for this handle.
    pub db_name: String,
    /// The connection URL for this handle's own database.
    url: String,
    /// Admin URL (pointing at the server's `postgres` database) used to drop the
    /// per-test database on cleanup.
    admin_url: String,
}

impl TestDb {
    /// Create a fresh, uniquely named database, migrate it, and return a
    /// connected pool.
    ///
    /// The name is the configured base name with a UUIDv7 suffix, so concurrent
    /// callers never collide on the same database and never see each other's
    /// rows. The database is dropped when the returned handle is dropped.
    pub async fn fresh() -> Result<Self> {
        let base_url = Self::database_url();
        let base_name = database_name(&base_url)?;
        let db_name = format!("{base_name}_{}", uuid::Uuid::now_v7().simple());
        let url = with_database_name(&base_url, &db_name)?;
        let admin_url = admin_url(&base_url, "postgres")?;

        // The permit bounds only the setup phase: it is released before the
        // test body runs, so steady-state test concurrency is unaffected. See
        // MAX_CONCURRENT_SETUPS for why the phase must be bounded at all.
        let pool = {
            let _permit = SETUP_GATE
                .acquire()
                .await
                .expect("the setup gate is never closed");
            create_and_migrate(&admin_url, &db_name, &url).await?
        };

        Ok(Self {
            pool,
            db_name,
            url,
            admin_url,
        })
    }

    /// The configured test database URL (env override or default). The final
    /// path segment is the *base* name; per-test databases append a suffix.
    pub fn database_url() -> String {
        std::env::var(TEST_DATABASE_URL_ENV)
            .unwrap_or_else(|_| DEFAULT_TEST_DATABASE_URL.to_string())
    }

    /// Open an additional pool against this handle's own database with an explicit
    /// connection cap. Tests that run a full [`crate::runtime::Runtime`] (a
    /// persistent NOTIFY listener plus sweeper, scheduler, and per-handler
    /// advisory locks) need more connections than the default pool provides. The
    /// pool shares this handle's database, so it is torn down with the rest when
    /// the handle drops.
    pub async fn pool_with(&self, max_connections: u32) -> Result<sqlx::PgPool> {
        Ok(sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(&self.url)
            .await?)
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Drop the per-test database so a test run does not leak one database per
        // test. Cleanup runs on a short-lived runtime on a dedicated OS thread,
        // independent of the (possibly already shutting-down) runtime the test
        // ran on, so it happens deterministically when the handle goes out of
        // scope.
        //
        // We deliberately do NOT call `pool.close().await` here: a pool's
        // graceful close waits on the background reaper task, which is bound to
        // the *test's* runtime. By the time Drop runs that runtime may be
        // tearing down, so awaiting the reaper would hang forever. Instead we
        // drop the database with FORCE, which terminates the pool's server-side
        // backends directly; the client-side pool handle is being dropped anyway.
        let admin_url = self.admin_url.clone();
        let db_name = self.db_name.clone();
        let _ = std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async move {
                if let Ok(mut admin) = sqlx::PgConnection::connect(&admin_url).await {
                    // FORCE evicts any lingering session (including this pool's
                    // own backends) so the drop cannot be blocked by a connection
                    // that outlived the handle.
                    let sql = format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)");
                    let _ = sqlx::query(sqlx::AssertSqlSafe(sql))
                        .execute(&mut admin)
                        .await;
                    let _ = admin.close().await;
                }
            });
        })
        .join();
    }
}

/// Drop and recreate the database named in `url` using an admin connection to
/// the server's `postgres` database, then apply migrations.
///
/// This resets a *named* database in place, so the same name reused across runs
/// always starts clean. It is the primitive for suites that share one database
/// across a binary's tests (reset once, isolate by row scope). It is not safe to
/// call concurrently against the same name; concurrent per-test callers use
/// [`TestDb::fresh`], which mints a unique name per call. Because
/// `CREATE DATABASE` cannot run with `IF NOT EXISTS`, the function drops first,
/// achieving the same create-if-absent effect while guaranteeing a clean slate.
pub async fn reset_and_migrate(url: &str) -> Result<sqlx::PgPool> {
    let db_name = database_name(url)?;
    let admin_url = admin_url(url, "postgres")?;

    {
        let mut admin = sqlx::PgConnection::connect(&admin_url).await?;

        // CREATE/DROP DATABASE take no bind parameters, so the database name is
        // interpolated as a quoted identifier. database_name has already
        // rejected any name containing a double quote, so the identifier cannot
        // be broken out of; AssertSqlSafe records that this string is
        // deliberately, audited-ly dynamic. FORCE evicts sessions still
        // connected to the test database so a leaked pool from a previous run
        // cannot block the reset.
        let drop_sql = format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)");
        sqlx::query(sqlx::AssertSqlSafe(drop_sql))
            .execute(&mut admin)
            .await?;

        let create_sql = format!("CREATE DATABASE \"{db_name}\"");
        sqlx::query(sqlx::AssertSqlSafe(create_sql))
            .execute(&mut admin)
            .await?;

        admin.close().await?;
    }

    let pool = sqlx::PgPool::connect(url).await?;
    crate::MIGRATOR.run(&pool).await?;
    Ok(pool)
}

/// Create the (assumed-absent, uniquely named) database, apply migrations, and
/// return the capped pool the [`TestDb`] handle then carries — one pool serves
/// both the migration run and the test, so setup never opens a second pool's
/// worth of connections.
///
/// Unlike [`reset_and_migrate`] this does not drop first: the name is freshly
/// generated per call so it cannot pre-exist, which is what makes concurrent
/// callers collision-free.
async fn create_and_migrate(admin_url: &str, db_name: &str, url: &str) -> Result<sqlx::PgPool> {
    {
        let mut admin = sqlx::PgConnection::connect(admin_url).await?;
        // db_name is engine-generated (base name validated free of double quotes,
        // plus a hex UUID suffix), never user input.
        let create_sql = format!("CREATE DATABASE \"{db_name}\"");
        sqlx::query(sqlx::AssertSqlSafe(create_sql))
            .execute(&mut admin)
            .await?;
        admin.close().await?;
    }

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(FRESH_POOL_MAX_CONNECTIONS)
        .connect(url)
        .await?;
    crate::MIGRATOR.run(&pool).await?;
    Ok(pool)
}

/// The configured base test URL rewritten to point at `db_name` on the same
/// server (preserving any query string). Used by suites that manage their own
/// databases (for example the migration-privilege role tests).
pub fn database_url_with_name(db_name: &str) -> String {
    let base = TestDb::database_url();
    // The base URL is well-formed (it carries a database path segment), so the
    // rewrite cannot fail in practice; fall back to the base on the impossible
    // malformed case rather than panicking in a helper.
    with_database_name(&base, db_name).unwrap_or(base)
}

/// Run a single admin (superuser) statement against `db_name` on the configured
/// server. The connection authenticates with the credentials from the base test
/// URL, which the harness assumes belong to a role able to manage databases and
/// roles (the dev/CI Postgres superuser).
///
/// Used by suites that provision their own databases and roles. The statement is
/// engine-controlled test setup, never user input, so it is wrapped as SQL-safe.
pub async fn run_as_admin(db_name: &str, sql: &str) -> Result<()> {
    let url = database_url_with_name(db_name);
    let mut conn = sqlx::PgConnection::connect(&url).await?;
    let outcome = sqlx::query(sqlx::AssertSqlSafe(sql.to_string()))
        .execute(&mut conn)
        .await;
    // Close regardless of the statement's result so a failing statement does not
    // leak the admin connection.
    let _ = conn.close().await;
    outcome?;
    Ok(())
}

/// Extract the database name (final path segment) from a Postgres URL.
///
/// Rejects a name containing a double quote so it is safe to splice into a
/// quoted SQL identifier.
fn database_name(url: &str) -> Result<String> {
    let name = url
        .rsplit('/')
        .next()
        .and_then(|tail| tail.split('?').next())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Config(format!("no database name in URL: {url}")))?;
    if name.contains('"') {
        return Err(Error::Config(format!(
            "database name must not contain a double quote: {name}"
        )));
    }
    Ok(name.to_string())
}

/// Rewrite a Postgres URL to point at a different database on the same server.
fn admin_url(url: &str, admin_db: &str) -> Result<String> {
    with_database_name(url, admin_db)
}

/// Replace the database-name path segment of a Postgres URL, preserving any
/// query string.
fn with_database_name(url: &str, db_name: &str) -> Result<String> {
    let (prefix, rest) = url
        .rsplit_once('/')
        .ok_or_else(|| Error::Config(format!("malformed Postgres URL: {url}")))?;
    let query = rest.split_once('?').map(|(_, q)| q);
    Ok(match query {
        Some(q) => format!("{prefix}/{db_name}?{q}"),
        None => format!("{prefix}/{db_name}"),
    })
}
