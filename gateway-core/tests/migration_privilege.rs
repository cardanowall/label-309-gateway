//! Migration namespace-scoping enforcement.
//!
//! The engine's migrations are required to create objects only in `cw_core`,
//! never in `public` (or any other host schema). This suite proves that property
//! is *enforced by Postgres*, not merely by convention: it runs the migrator
//! under a restricted role that has `CREATE` on `cw_core` but NOT on `public`,
//! and asserts that
//!
//!   - the real embedded corpus applies cleanly under that role, and
//!   - a throwaway migration that creates an object in `public` is rejected.
//!
//! Together these show a future migration cannot silently start writing to the
//! host's `public` schema: such a migration would fail this gate before it could
//! ship.
//!
//! Gated behind `pg-tests` so the default `cargo test` never needs a database.

#![cfg(feature = "pg-tests")]

use sqlx::migrate::Migrator;
use sqlx::Connection;

use gateway_core::testsupport::{database_url_with_name, run_as_admin};

/// The cw_core-scoped tracking-table name the embedded migrator uses. The
/// runtime migrators built here mirror it so the only thing that differs between
/// the positive and negative cases is the migration *content*, not where the
/// tracking table lives.
const TRACKING_TABLE: &str = "cw_core._sqlx_migrations";

/// Build a runtime migrator from a directory, configured to track its state in
/// `cw_core` (matching the embedded `migrate!()` macro via `sqlx.toml`).
///
/// The migrator deliberately does NOT create the `cw_core` schema: the test
/// harness pre-creates it as the superuser and grants the restricted role
/// `CREATE` on it. The restricted role has no database-level `CREATE`, so a
/// migrator that tried to `CREATE SCHEMA` would fail on the schema step rather
/// than on the migration content. Leaving schema creation out isolates the
/// privilege check to the migration's own DDL, which is exactly what this gate
/// is testing.
async fn cw_core_scoped_migrator(dir: &std::path::Path) -> Migrator {
    let mut m = Migrator::new(dir).await.expect("load migrations from dir");
    m.dangerous_set_table_name(TRACKING_TABLE);
    m
}

/// Build a migrator carrying the *real embedded corpus* but tracking its state
/// in `cw_core` without a schema-creation step, so it can run under the
/// restricted (cw_core-only, no database CREATE) role exactly as shipped.
fn embedded_corpus_scoped_migrator() -> Migrator {
    let mut m = Migrator::with_migrations(gateway_core::MIGRATOR.iter().cloned().collect());
    m.dangerous_set_table_name(TRACKING_TABLE);
    m
}

/// A scratch directory holding one throwaway migration, removed on drop.
struct ScratchMigrations {
    dir: std::path::PathBuf,
}

impl ScratchMigrations {
    /// Create a temp directory containing a single migration file with the given
    /// SQL body.
    fn with_single_migration(sql: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "gateway_core_priv_{}",
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch migration dir");
        // sqlx requires `{version}_{description}.sql`.
        std::fs::write(dir.join("0001_scratch.sql"), sql).expect("write scratch migration");
        Self { dir }
    }
}

impl Drop for ScratchMigrations {
    fn drop(&mut self) {
        // Remove only the unique directory this handle created.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Stand up a fresh database with a restricted migration role.
///
/// The role has `CREATE` revoked on schema `public` (so it cannot create there)
/// while `cw_core` is created up front with `CREATE` granted on it. The handle
/// then exposes a URL that connects *as the restricted role*.
///
/// All admin DDL runs as the superuser; the returned URL is what the migrator
/// under test uses, so the migrator only ever holds the restricted privileges.
struct RestrictedDb {
    role_url: String,
    admin_db_url: String,
    db_name: String,
    role: String,
}

impl RestrictedDb {
    async fn create() -> Self {
        let suffix = uuid::Uuid::now_v7().simple().to_string();
        let db_name = format!("cardanowall_gateway_priv_{suffix}");
        let role = format!("gw_migrator_{suffix}");
        let role_pw = "restricted_migrator_pw";

        // 1) Create the role and the database as the superuser.
        run_as_admin(
            "postgres",
            &format!("CREATE ROLE \"{role}\" LOGIN PASSWORD '{role_pw}'"),
        )
        .await
        .expect("create restricted role");
        run_as_admin("postgres", &format!("CREATE DATABASE \"{db_name}\""))
            .await
            .expect("create privilege-test database");

        // 2) Inside the new database, set up the exact privilege surface a
        //    namespace-scoped migration role is expected to run with:
        //      - it can connect and use public, but cannot create in it,
        //      - it can create in cw_core and cw_api (both exist up front),
        //        the engine's two owned schemas.
        for stmt in [
            // PG15+ already drops the default PUBLIC CREATE grant on public, but
            // revoke explicitly so the test does not depend on the server's
            // default and the role demonstrably lacks CREATE on public.
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC".to_string(),
            format!("REVOKE ALL ON SCHEMA public FROM \"{role}\""),
            format!("GRANT USAGE ON SCHEMA public TO \"{role}\""),
            "CREATE SCHEMA IF NOT EXISTS cw_core".to_string(),
            format!("GRANT USAGE, CREATE ON SCHEMA cw_core TO \"{role}\""),
            "CREATE SCHEMA IF NOT EXISTS cw_api".to_string(),
            format!("GRANT USAGE, CREATE ON SCHEMA cw_api TO \"{role}\""),
        ] {
            run_as_admin(&db_name, &stmt)
                .await
                .unwrap_or_else(|e| panic!("admin setup `{stmt}` failed: {e:?}"));
        }

        let role_url = role_url(&db_name, &role, role_pw);
        let admin_db_url = database_url_with_name(&db_name);

        Self {
            role_url,
            admin_db_url,
            db_name,
            role,
        }
    }

    /// Open a connection authenticated as the restricted role.
    async fn connect_restricted(&self) -> sqlx::PgConnection {
        sqlx::PgConnection::connect(&self.role_url)
            .await
            .expect("connect as the restricted migration role")
    }

    /// Does an object exist in a given schema, checked with superuser visibility?
    async fn object_exists(&self, schema: &str, table: &str) -> bool {
        let mut admin = sqlx::PgConnection::connect(&self.admin_db_url)
            .await
            .expect("admin connect for verification");
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
             WHERE table_schema = $1 AND table_name = $2)",
        )
        .bind(schema)
        .bind(table)
        .fetch_one(&mut admin)
        .await
        .expect("existence query");
        let _ = admin.close().await;
        exists
    }

    /// Apply the real embedded corpus under the restricted migrator role.
    ///
    /// This is the engine's own deployment path: the migrator role owns `cw_core`
    /// and `cw_api` and runs every engine migration. The exit-criterion tests
    /// start from a fully migrated database so the anchor tables a vendor FKs
    /// against exist.
    async fn apply_corpus(&self) {
        let mut conn = self.connect_restricted().await;
        embedded_corpus_scoped_migrator()
            .run(&mut conn)
            .await
            .expect("the embedded corpus must apply under the migrator role");
        let _ = conn.close().await;
    }

    /// Run one statement as the restricted migrator role, returning the result so
    /// a test can assert it succeeded or was rejected.
    async fn run_as_migrator(&self, sql: &str) -> Result<(), sqlx::Error> {
        let mut conn = self.connect_restricted().await;
        let outcome = sqlx::query(sqlx::AssertSqlSafe(sql.to_string()))
            .execute(&mut conn)
            .await
            .map(|_| ());
        let _ = conn.close().await;
        outcome
    }

    /// Provision a separate VENDOR role that owns its own schema and is granted
    /// the exact extension-contract privileges on `cw_api`: USAGE + SELECT +
    /// REFERENCES, and nothing else (no INSERT/UPDATE/DELETE). This is the
    /// privilege surface an embedding application runs its own migrations under.
    /// Returns a handle that runs statements as the vendor role.
    async fn provision_vendor(&self, schema: &str) -> VendorRole {
        let suffix = uuid::Uuid::now_v7().simple().to_string();
        let role = format!("gw_vendor_{suffix}");
        let role_pw = "vendor_role_pw";

        run_as_admin(
            "postgres",
            &format!("CREATE ROLE \"{role}\" LOGIN PASSWORD '{role_pw}'"),
        )
        .await
        .expect("create vendor role");

        for stmt in [
            // The vendor owns its own schema: it can create tables there.
            format!("CREATE SCHEMA \"{schema}\" AUTHORIZATION \"{role}\""),
            // The exact privileges a foreign key into the contract needs: USAGE to
            // reach the schema, SELECT to read anchor rows, and REFERENCES to point
            // a FK at them. Deliberately NO write grant: the vendor can reference
            // the anchor but can neither insert anchor rows nor mutate them.
            format!("GRANT USAGE ON SCHEMA cw_api TO \"{role}\""),
            format!("GRANT SELECT, REFERENCES ON ALL TABLES IN SCHEMA cw_api TO \"{role}\""),
            // The vendor cannot reach the engine's private schema at all.
            format!("REVOKE ALL ON SCHEMA cw_core FROM \"{role}\""),
        ] {
            run_as_admin(&self.db_name, &stmt)
                .await
                .unwrap_or_else(|e| panic!("vendor setup `{stmt}` failed: {e:?}"));
        }

        let role_url = role_url(&self.db_name, &role, role_pw);
        VendorRole { role_url, role }
    }
}

/// A vendor role: owns its own schema, holds only USAGE + SELECT + REFERENCES on
/// `cw_api`, and cannot reach `cw_core`.
struct VendorRole {
    role_url: String,
    role: String,
}

impl VendorRole {
    /// Run one statement as the vendor role, returning the result so a test can
    /// assert success or a specific rejection.
    async fn run(&self, sql: &str) -> Result<(), sqlx::Error> {
        let mut conn = sqlx::PgConnection::connect(&self.role_url)
            .await
            .expect("connect as the vendor role");
        let outcome = sqlx::query(sqlx::AssertSqlSafe(sql.to_string()))
            .execute(&mut conn)
            .await
            .map(|_| ());
        let _ = conn.close().await;
        outcome
    }
}

impl Drop for VendorRole {
    fn drop(&mut self) {
        let role = self.role.clone();
        let _ = std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async move {
                // The owning database is dropped by RestrictedDb's own Drop, which
                // takes its objects (including this role's schema) with it; only
                // the role itself must be cleaned up here.
                let _ = run_as_admin("postgres", &format!("DROP ROLE IF EXISTS \"{role}\"")).await;
            });
        })
        .join();
    }
}

/// The SQLSTATE Postgres reports for an insufficient-privilege failure.
const INSUFFICIENT_PRIVILEGE: &str = "42501";
/// The SQLSTATE Postgres reports when an explicit ON DELETE RESTRICT foreign key
/// blocks a delete (distinct from the 23503 a default NO ACTION defers).
const RESTRICT_VIOLATION: &str = "23001";

/// Extract the SQLSTATE of a database error, or `None` for a non-database error.
fn sqlstate(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

impl Drop for RestrictedDb {
    fn drop(&mut self) {
        let db_name = self.db_name.clone();
        let role = self.role.clone();
        let _ = std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async move {
                // Drop the database (FORCE evicts the restricted role's sessions),
                // then the now-unused role.
                let _ = run_as_admin(
                    "postgres",
                    &format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"),
                )
                .await;
                let _ = run_as_admin("postgres", &format!("DROP ROLE IF EXISTS \"{role}\"")).await;
            });
        })
        .join();
    }
}

/// Build a connection URL for a named role/password against a named database on
/// the configured server.
fn role_url(db_name: &str, role: &str, password: &str) -> String {
    let base = database_url_with_name(db_name);
    // Replace the `user:pass@` authority while keeping host/port/db/query.
    let (scheme, rest) = base.split_once("://").expect("url has a scheme");
    let after_authority = rest.split_once('@').map(|(_, a)| a).unwrap_or(rest);
    format!("{scheme}://{role}:{password}@{after_authority}")
}

/// The real embedded corpus applies cleanly under a role that can create in
/// `cw_core` but not in `public`, and lands its objects in `cw_core` (never in
/// `public`). This is the property the namespace scoping guarantees.
#[tokio::test]
async fn real_corpus_applies_under_restricted_role() {
    let db = RestrictedDb::create().await;

    {
        let mut conn = db.connect_restricted().await;
        embedded_corpus_scoped_migrator()
            .run(&mut conn)
            .await
            .expect("the real corpus must apply under the restricted (cw_core-only) role");
        let _ = conn.close().await;
    }

    // The corpus's objects exist in cw_core...
    assert!(
        db.object_exists("cw_core", "job").await,
        "cw_core.job must exist after the corpus applied"
    );
    assert!(
        db.object_exists("cw_core", "_sqlx_migrations").await,
        "the tracking table must live in cw_core, not public"
    );
    // ...and the corpus created nothing in public.
    assert!(
        !db.object_exists("public", "_sqlx_migrations").await,
        "no migration-tracking table may be created in public"
    );
}

/// A migration that creates an object in `public` is rejected under the
/// restricted role: the role lacks CREATE on public, so the DDL fails and the
/// object never appears. This is what makes a stray public-DDL migration
/// unshippable.
#[tokio::test]
async fn migration_touching_public_is_rejected_under_restricted_role() {
    let db = RestrictedDb::create().await;
    let scratch = ScratchMigrations::with_single_migration(
        "CREATE TABLE public.illegal_escape (id integer PRIMARY KEY);",
    );
    let migrator = cw_core_scoped_migrator(&scratch.dir).await;

    let mut conn = db.connect_restricted().await;
    let result = migrator.run(&mut conn).await;
    let _ = conn.close().await;

    let err = result.expect_err(
        "a migration creating an object in public must fail under a role lacking CREATE on public",
    );
    // The failure is the migration's own DDL being rejected by Postgres, not a
    // loader/version bookkeeping error: applying a migration surfaces the SQL
    // error as `ExecuteMigration(_, version)`.
    let inner = match &err {
        sqlx::migrate::MigrateError::ExecuteMigration(e, version) => {
            assert_eq!(*version, 1, "the scratch migration is version 1");
            e
        }
        other => panic!("expected ExecuteMigration from the public DDL, got {other:?}"),
    };
    // Postgres reports an insufficient-privilege failure (SQLSTATE 42501) when a
    // role without CREATE on the schema attempts DDL there.
    let sqlstate = inner
        .as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned());
    assert_eq!(
        sqlstate.as_deref(),
        Some("42501"),
        "expected insufficient_privilege (42501), got {sqlstate:?}"
    );

    // The forbidden object never came into being.
    assert!(
        !db.object_exists("public", "illegal_escape").await,
        "the public-schema table must not exist after the rejected migration"
    );
}

/// Control: a throwaway migration that creates an object in `cw_core` *succeeds*
/// under the same restricted role. This proves the negative case above fails for
/// the right reason (public is off-limits), not because the role cannot run
/// migrations at all.
#[tokio::test]
async fn migration_touching_cw_core_succeeds_under_restricted_role() {
    let db = RestrictedDb::create().await;
    let scratch = ScratchMigrations::with_single_migration(
        "CREATE TABLE cw_core.allowed_object (id integer PRIMARY KEY);",
    );
    let migrator = cw_core_scoped_migrator(&scratch.dir).await;

    let mut conn = db.connect_restricted().await;
    migrator
        .run(&mut conn)
        .await
        .expect("a cw_core-only migration must succeed under the restricted role");
    let _ = conn.close().await;

    assert!(
        db.object_exists("cw_core", "allowed_object").await,
        "the cw_core object must exist after the allowed migration"
    );
}

/// The corpus lands the extension-contract anchors in `cw_api` and keeps the
/// engine's private tables in `cw_core`, with nothing in `public`. This pins the
/// two-schema split the rest of the privilege model depends on.
#[tokio::test]
async fn corpus_lands_anchors_in_cw_api_and_internals_in_cw_core() {
    let db = RestrictedDb::create().await;
    db.apply_corpus().await;

    // The stable extension contract lives in cw_api.
    assert!(
        db.object_exists("cw_api", "account").await,
        "cw_api.account anchor must exist"
    );
    assert!(
        db.object_exists("cw_api", "records").await,
        "cw_api.records anchor must exist"
    );

    // The volatile internals live in cw_core.
    for table in [
        "account_detail",
        "balance",
        "balance_ledger",
        "publish_quote",
    ] {
        assert!(
            db.object_exists("cw_core", table).await,
            "cw_core.{table} must exist"
        );
    }

    // Nothing escaped into public.
    for table in ["account", "balance", "balance_ledger", "publish_quote"] {
        assert!(
            !db.object_exists("public", table).await,
            "no ledger/quote object may be created in public ({table})"
        );
    }
}

/// A vendor that holds only USAGE + SELECT + REFERENCES on `cw_api` can create
/// its own schema and FK-reference `cw_api.account`. This is the extension
/// contract working as designed: a downstream application binds to the anchor
/// without any write privilege on it.
#[tokio::test]
async fn vendor_can_reference_cw_api_account_with_only_references_grant() {
    let db = RestrictedDb::create().await;
    db.apply_corpus().await;

    let vendor = db.provision_vendor("vendor_app").await;

    // The vendor creates its own table with a foreign key into the anchor, using
    // nothing more than the REFERENCES grant.
    vendor
        .run(
            "CREATE TABLE vendor_app.account_profile ( \
               account_id uuid NOT NULL REFERENCES cw_api.account (id), \
               display_name text NOT NULL \
             )",
        )
        .await
        .expect("a vendor with REFERENCES on cw_api.account may FK it");

    assert!(
        db.object_exists("vendor_app", "account_profile").await,
        "the vendor table must exist after creation"
    );

    // The same vendor cannot WRITE the anchor: it has no INSERT grant. This proves
    // REFERENCES alone does not leak write access to the contract.
    let write = vendor
        .run("INSERT INTO cw_api.account (id) VALUES (gen_random_uuid())")
        .await
        .expect_err("a vendor without INSERT on cw_api.account must be refused");
    assert_eq!(
        sqlstate(&write).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "expected insufficient_privilege writing the anchor, got {write:?}"
    );
}

/// The engine's migrator role owns `cw_core`/`cw_api` but holds NO privilege on a
/// vendor schema, so a stray engine migration cannot create, alter, or drop
/// anything inside vendor-owned space. Each attempt is rejected for insufficient
/// privilege.
#[tokio::test]
async fn migrator_role_cannot_touch_a_vendor_schema() {
    let db = RestrictedDb::create().await;
    db.apply_corpus().await;

    let vendor = db.provision_vendor("vendor_app").await;
    vendor
        .run("CREATE TABLE vendor_app.thing (id integer PRIMARY KEY)")
        .await
        .expect("vendor creates its own table");

    // CREATE in the vendor schema: refused.
    let create = db
        .run_as_migrator("CREATE TABLE vendor_app.intruder (id integer PRIMARY KEY)")
        .await
        .expect_err("the migrator must not create in a vendor schema");
    assert_eq!(
        sqlstate(&create).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "expected insufficient_privilege on CREATE in vendor schema, got {create:?}"
    );

    // ALTER a vendor table: refused.
    let alter = db
        .run_as_migrator("ALTER TABLE vendor_app.thing ADD COLUMN extra text")
        .await
        .expect_err("the migrator must not alter a vendor table");
    assert_eq!(
        sqlstate(&alter).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "expected insufficient_privilege on ALTER of a vendor table, got {alter:?}"
    );

    // DROP a vendor table: refused.
    let drop = db
        .run_as_migrator("DROP TABLE vendor_app.thing")
        .await
        .expect_err("the migrator must not drop a vendor table");
    assert_eq!(
        sqlstate(&drop).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "expected insufficient_privilege on DROP of a vendor table, got {drop:?}"
    );

    // The vendor table survived every attempt intact.
    assert!(
        db.object_exists("vendor_app", "thing").await,
        "the vendor table must be untouched by the rejected engine DDL"
    );
}

/// A `DROP TABLE cw_api.account CASCADE` issued by the engine migrator CANNOT
/// remove a vendor table or its data. Postgres lets the anchor's owner cascade
/// away the dependent FK CONSTRAINT (the migrator owns the anchor, and CASCADE
/// follows the dependency to the constraint, not to the vendor table), but the
/// vendor table and every row in it survive: a CASCADE drop only ever removes a
/// dependent table when the issuer also owns that table, which the migrator never
/// does for a vendor schema. So the worst an engine cascade can do is detach a
/// vendor's foreign key; it can never erase vendor data, which is the guarantee
/// the two-schema split exists to provide.
#[tokio::test]
async fn dropping_an_anchor_cascade_cannot_remove_vendor_data() {
    let db = RestrictedDb::create().await;
    db.apply_corpus().await;

    // Seed a real account anchor as the superuser (the vendor cannot write it);
    // the vendor's row references this id, so the FK is satisfied before the drop.
    let account_id = uuid::Uuid::now_v7();
    {
        let mut admin = sqlx::PgConnection::connect(&db.admin_db_url)
            .await
            .expect("admin connect");
        sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
            .bind(account_id)
            .execute(&mut admin)
            .await
            .expect("seed anchor row");
        let _ = admin.close().await;
    }

    let vendor = db.provision_vendor("vendor_app").await;
    vendor
        .run(
            "CREATE TABLE vendor_app.account_profile ( \
               id uuid PRIMARY KEY, \
               account_id uuid NOT NULL REFERENCES cw_api.account (id), \
               note text \
             )",
        )
        .await
        .expect("vendor FKs the anchor");
    // The vendor seeds a row referencing the real anchor, so we can prove its DATA
    // survives the cascade, not just the table.
    vendor
        .run(&format!(
            "INSERT INTO vendor_app.account_profile (id, account_id, note) \
             VALUES (gen_random_uuid(), '{account_id}', 'keep me')",
        ))
        .await
        .expect("vendor seeds a row");

    // The migrator cascade-drops the anchor it owns. This succeeds and removes the
    // vendor's FK constraint, but cannot reach the vendor table itself.
    db.run_as_migrator("DROP TABLE cw_api.account CASCADE")
        .await
        .expect("the migrator owns the anchor, so the cascade drop runs");

    // The vendor table and its row survived; only the FK constraint is gone.
    assert!(
        db.object_exists("vendor_app", "account_profile").await,
        "the vendor table must survive a cascade drop of the anchor"
    );
    let rows: i64 = {
        let mut admin = sqlx::PgConnection::connect(&db.admin_db_url)
            .await
            .expect("admin connect");
        let n = sqlx::query_scalar("SELECT count(*) FROM vendor_app.account_profile")
            .fetch_one(&mut admin)
            .await
            .expect("count vendor rows");
        let _ = admin.close().await;
        n
    };
    assert_eq!(rows, 1, "the vendor's data must survive the cascade");
    assert!(
        !db.object_exists("cw_api", "account").await,
        "the anchor itself, which the migrator owns, was dropped"
    );
}

/// An account anchor cannot be hard-DELETEd while its satellite (and any other
/// dependent) references it ON DELETE RESTRICT. Removal is soft-delete only; the
/// RESTRICT foreign keys make a row delete impossible. Run as the superuser so
/// the failure is the RESTRICT dependency itself, not a missing privilege.
#[tokio::test]
async fn anchor_hard_delete_is_blocked_by_restrict_foreign_keys() {
    let db = RestrictedDb::create().await;
    db.apply_corpus().await;

    let mut admin = sqlx::PgConnection::connect(&db.admin_db_url)
        .await
        .expect("admin connect");

    // Seed an operator, an account anchor, and its satellite (the 1:1 RESTRICT
    // dependency every account carries).
    sqlx::query("INSERT INTO cw_core.operator (id, label) VALUES (gen_random_uuid(), 'op')")
        .execute(&mut admin)
        .await
        .expect("seed operator");
    let operator_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM cw_core.operator LIMIT 1")
        .fetch_one(&mut admin)
        .await
        .expect("read operator id");

    let account_id = uuid::Uuid::now_v7();
    sqlx::query("INSERT INTO cw_api.account (id) VALUES ($1)")
        .bind(account_id)
        .execute(&mut admin)
        .await
        .expect("seed account anchor");
    sqlx::query("INSERT INTO cw_core.account_detail (account_id, operator_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(operator_id)
        .execute(&mut admin)
        .await
        .expect("seed account satellite");

    // A hard DELETE of the anchor is refused: the satellite references it RESTRICT.
    let del = sqlx::query("DELETE FROM cw_api.account WHERE id = $1")
        .bind(account_id)
        .execute(&mut admin)
        .await
        .expect_err("the satellite RESTRICT FK must block the anchor delete");
    assert_eq!(
        sqlstate(&del).as_deref(),
        Some(RESTRICT_VIOLATION),
        "expected a RESTRICT dependency error, got {del:?}"
    );

    // Soft-delete is the supported removal path and succeeds.
    let soft = sqlx::query("UPDATE cw_api.account SET deleted_at = now() WHERE id = $1")
        .bind(account_id)
        .execute(&mut admin)
        .await
        .expect("soft-delete must succeed")
        .rows_affected();
    assert_eq!(soft, 1, "soft-delete stamps deleted_at on the anchor");

    let _ = admin.close().await;
}
