//! Separate database roles for the audit guard (#84).
//!
//! An *owner* role (`DATABASE_MIGRATION_URL`) owns every schema object, runs
//! the migrations and grants the *application* role (`DATABASE_URL`) only DML.
//! The application role therefore cannot drop, disable or replace the audit
//! guard (migrations 040/043), drop or alter the audit tables, or set the
//! `stig.audit_allow_test_mode` flag. A superuser can always bypass this.
//!
//! The grants are applied by [`apply_app_grants`] after every migration run;
//! it is the single authority (no `ALTER DEFAULT PRIVILEGES`), so the state
//! converges even after new tables appear. Neither URL is ever logged.

use std::str::FromStr;

use anyhow::{bail, Context, Result};
use sqlx::migrate::Migrate;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, PgPool};

/// Append-only tables guarded by the triggers from migration 040.
pub const AUDIT_TABLES: [&str; 2] = ["rule_audit", "audit_events"];

/// The role name a connection URL logs in as.
pub fn app_role_from_url(database_url: &str) -> Result<String> {
    let opts = PgConnectOptions::from_str(database_url)
        .map_err(|_| anyhow::anyhow!("DATABASE_URL is not a valid PostgreSQL URL"))?;
    Ok(opts.get_username().to_string())
}

/// The application role named in the connection URL does not exist (yet). The
/// owner step cannot proceed, but this is retryable: the role may be created
/// by a concurrent bootstrap.
#[derive(Debug)]
pub struct AppRoleMissing(pub String);

impl std::fmt::Display for AppRoleMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "application role {:?} does not exist; create it before migrating",
            self.0
        )
    }
}

impl std::error::Error for AppRoleMissing {}

/// Exit code of `migrate` for a retryable failure (EX_TEMPFAIL).
pub const MIGRATE_EXIT_TRANSIENT: i32 = 75;

/// True when retrying the owner step later can succeed: the database is not
/// reachable yet or the application role is not created yet.
pub fn is_transient(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if cause.is::<AppRoleMissing>() || cause.is::<OwnerStepLockHeld>() {
            return true;
        }
        match cause.downcast_ref::<sqlx::Error>() {
            Some(sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut) => true,
            Some(sqlx::Error::Database(d)) => d.code().is_some_and(|c| {
                matches!(
                    &*c,
                    "57P03" | "08000" | "08001" | "08003" | "08004" | "08006"
                )
            }),
            _ => false,
        }
    })
}

/// Process exit code for a failed `migrate`: 75 if transient, else 1.
pub fn migrate_exit_code(err: &anyhow::Error) -> i32 {
    if is_transient(err) {
        MIGRATE_EXIT_TRANSIENT
    } else {
        1
    }
}

/// Reject an owner step whose owner and application roles are the same.
fn check_distinct_roles(owner: &str, app: &str) -> Result<()> {
    if owner == app {
        bail!(
            "DATABASE_MIGRATION_URL and DATABASE_URL use the same role ({app:?}); \
             the application role must differ from the owner role"
        );
    }
    Ok(())
}

/// What the process was asked to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Serve,
    Migrate,
}

/// Parse the arguments after the program name: none serves, `migrate` runs the
/// owner step, anything else (including extra arguments) is an error.
pub fn parse_command(args: &[String]) -> Result<Command> {
    match args {
        [] => Ok(Command::Serve),
        [cmd] if cmd == "migrate" => Ok(Command::Migrate),
        _ => bail!("unknown argument; the only subcommand is `migrate`"),
    }
}

/// Preconditions of `migrate`: the test-hook production refusal applies (the
/// owner step would otherwise grant test-only privileges and set the audit
/// test flag), and `DATABASE_MIGRATION_URL` must be set. Returns that URL.
pub fn migrate_preconditions<'a>(
    hooks: &crate::config::TestHooks,
    migration_url: Option<&'a str>,
) -> Result<&'a str> {
    hooks.validate()?;
    migration_url.ok_or_else(|| anyhow::anyhow!("`migrate` needs DATABASE_MIGRATION_URL"))
}

/// How the server gets a current schema at startup.
#[derive(Debug, PartialEq, Eq)]
pub enum StartupPath {
    /// `DATABASE_MIGRATION_URL` set: the owner migrates, the app verifies.
    OwnerMigrates,
    /// The app role owns the schema (single-role, development only).
    SelfMigrate,
    /// Migrated externally: only verify.
    VerifyOnly,
}

/// `can_migrate` is only consulted when there is no owner URL.
pub fn startup_path(has_owner_url: bool, can_migrate: impl FnOnce() -> bool) -> StartupPath {
    if has_owner_url {
        StartupPath::OwnerMigrates
    } else if can_migrate() {
        StartupPath::SelfMigrate
    } else {
        StartupPath::VerifyOnly
    }
}

/// Run pending migrations as the owner role, then (re)apply the application
/// role's grants. With `test_routes` on, also flags the database for audit
/// `test` maintenance mode (the owner must be a superuser or hold
/// `GRANT SET ON PARAMETER stig.audit_allow_test_mode`). Test-only privileges
/// are never granted, nor the flag set, when `production` is true.
pub async fn migrate_as_owner(
    owner_url: &str,
    app_database_url: &str,
    test_routes: bool,
    production: bool,
) -> Result<()> {
    if production && test_routes {
        bail!("refusing to grant test-only audit privileges in production");
    }
    let app_role = app_role_from_url(app_database_url)?;
    let owner_opts = PgConnectOptions::from_str(owner_url)
        .map_err(|_| anyhow::anyhow!("DATABASE_MIGRATION_URL is not a valid PostgreSQL URL"))?;
    migrate_with(owner_opts, &app_role, test_routes).await
}

/// [`migrate_as_owner`] with parsed options (the tests pass their own). The
/// whole step runs under the [`crate::db_audit::OWNER_STEP_LOCK`] advisory lock.
async fn migrate_with(
    owner_opts: PgConnectOptions,
    app_role: &str,
    test_routes: bool,
) -> Result<()> {
    check_distinct_roles(owner_opts.get_username(), app_role)?;
    let owner_pool = PgPoolOptions::new()
        .max_connections(2)
        // One connection holds the session-level advisory lock for the whole
        // step, so never recycle it; `close()` at the end releases it.
        .idle_timeout(None)
        .max_lifetime(None)
        // Do not let a role- or database-level search_path setting decide
        // which schema the migrations and grants act on. `pg_catalog` is then
        // searched first implicitly, so nothing in `public` can shadow a
        // built-in that the migrator or this module calls unqualified.
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET search_path = public")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with(owner_opts)
        .await
        .context("connecting with DATABASE_MIGRATION_URL")?;
    let mut lock_conn: Option<sqlx::pool::PoolConnection<sqlx::Postgres>> = None;
    let result = async {
        // Serialise the whole owner step across replicas: the grants, the
        // REVOKE and the test-mode flag all update shared catalog rows and
        // fail with "tuple concurrently updated" when run concurrently. The
        // session-level lock lives on a connection held out of the pool for
        // the whole step (the pool has a second one for the work), so it can
        // never be swapped for another session.
        lock_conn = Some(owner_pool.acquire().await?);
        if let Some(c) = lock_conn.as_mut() {
            lock_owner_step(c, OWNER_LOCK_WAIT).await?;
        }
        // Close the schema to the application role and refuse pre-planted
        // objects before anything unqualified runs as the owner.
        let mut conn = owner_pool.acquire().await?;
        prepare_owner_schema(&mut conn, app_role).await?;
        drop(conn);
        sqlx::migrate!("./migrations").run(&owner_pool).await?;
        let mut conn = owner_pool.acquire().await?;
        apply_app_grants(&mut conn, app_role, test_routes).await?;
        drop(conn);
        if test_routes {
            crate::db_audit::allow_test_maintenance(&owner_pool).await?;
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    // Return the lock connection first so `close()` ends the session, which
    // releases the lock.
    drop(lock_conn);
    owner_pool.close().await;
    result
}

/// How long an owner step waits for another one before giving up (retryable).
const OWNER_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Another session holds the owner-step lock. Retryable.
#[derive(Debug)]
pub struct OwnerStepLockHeld;

impl std::fmt::Display for OwnerStepLockHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "owner step lock held by another session")
    }
}

impl std::error::Error for OwnerStepLockHeld {}

/// Take the owner-step advisory lock on `conn`, waiting up to `wait`. The
/// timeout (55P03) becomes [`OwnerStepLockHeld`]. `pg_catalog`-qualified so
/// nothing planted in `public` can run. `lock_timeout` is session-scoped to
/// this connection and reset afterwards; the migrations use another one.
async fn lock_owner_step(conn: &mut PgConnection, wait: std::time::Duration) -> Result<()> {
    // SET cannot take bind parameters; the value is an integer we format.
    let ms = wait.as_millis().max(1);
    sqlx::query(&format!("SET lock_timeout = {ms}"))
        .execute(&mut *conn)
        .await?;
    tracing::info!("waiting for owner step lock");
    if let Err(e) = sqlx::query("SELECT pg_catalog.pg_advisory_lock($1)")
        .bind(crate::db_audit::OWNER_STEP_LOCK)
        .execute(&mut *conn)
        .await
    {
        if e.as_database_error()
            .and_then(|d| d.code())
            .is_some_and(|c| c == "55P03")
        {
            return Err(OwnerStepLockHeld.into());
        }
        return Err(e.into());
    }
    sqlx::query("SET lock_timeout = 0")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// A schema as `(raw name, server-quoted identifier)`.
struct Schema {
    raw: String,
    quoted: String,
}

/// Before migrating: check the application role exists, that the owner may
/// revoke on the schema, revoke `CREATE` on it from PUBLIC and the application
/// role, and refuse to continue if the schema already holds a function,
/// operator, type or relation owned by a role other than the schema owner, the
/// owner role or a superuser (an object planted while the application role
/// could still `CREATE`). Only `pg_catalog`-qualified names are used.
async fn prepare_owner_schema(conn: &mut PgConnection, app_role: &str) -> Result<Schema> {
    let owner: String = sqlx::query_scalar("SELECT current_user::pg_catalog.text")
        .fetch_one(&mut *conn)
        .await?;
    check_distinct_roles(&owner, app_role)?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)")
            .bind(app_role)
            .fetch_one(&mut *conn)
            .await?;
    if !exists {
        return Err(AppRoleMissing(app_role.to_string()).into());
    }

    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT pg_catalog.current_schema()::pg_catalog.text, \
                pg_catalog.quote_ident(pg_catalog.current_schema())",
    )
    .fetch_optional(&mut *conn)
    .await?;
    let (Some(raw), Some(quoted)) = row.unwrap_or_default() else {
        bail!("the owner connection has no current schema (is the `public` schema missing?)");
    };
    let schema = Schema { raw, quoted };
    let role: String = sqlx::query_scalar("SELECT pg_catalog.quote_ident($1)")
        .bind(app_role)
        .fetch_one(&mut *conn)
        .await?;

    // REVOKE by a role that does not own the schema is a silent no-op, so
    // check. USAGE (not MEMBER): a NOINHERIT member cannot revoke.
    let may_revoke: bool = sqlx::query_scalar(
        "SELECT r.rolsuper OR pg_catalog.pg_has_role(current_user, n.nspowner, 'USAGE') \
         FROM pg_catalog.pg_namespace n, pg_catalog.pg_roles r \
         WHERE n.nspname = $1 AND r.rolname = current_user",
    )
    .bind(&schema.raw)
    .fetch_one(&mut *conn)
    .await?;
    if !may_revoke {
        bail!(
            "the owner role must own schema {} (or be a superuser) to revoke CREATE \
             on it from PUBLIC and the application role",
            schema.quoted
        );
    }
    for target in ["PUBLIC", role.as_str()] {
        sqlx::query(&format!(
            "REVOKE CREATE ON SCHEMA {} FROM {target}",
            schema.quoted
        ))
        .execute(&mut *conn)
        .await?;
    }

    let planted: Vec<String> = sqlx::query_scalar(
        "WITH s AS (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = $1), \
         objs AS ( \
           SELECT 'function ' || p.proname::pg_catalog.text AS what, p.proowner AS o \
             FROM pg_catalog.pg_proc p WHERE p.pronamespace = (SELECT oid FROM s) \
           UNION ALL \
           SELECT 'operator ' || x.oprname::pg_catalog.text, x.oprowner \
             FROM pg_catalog.pg_operator x WHERE x.oprnamespace = (SELECT oid FROM s) \
           UNION ALL \
           SELECT 'type ' || t.typname::pg_catalog.text, t.typowner \
             FROM pg_catalog.pg_type t WHERE t.typnamespace = (SELECT oid FROM s) \
           UNION ALL \
           SELECT 'relation ' || c.relname::pg_catalog.text, c.relowner \
             FROM pg_catalog.pg_class c WHERE c.relnamespace = (SELECT oid FROM s)) \
         SELECT objs.what || ' (owner ' || r.rolname::pg_catalog.text || ')' \
         FROM objs JOIN pg_catalog.pg_roles r ON r.oid = objs.o \
         WHERE NOT r.rolsuper \
           AND r.rolname <> current_user \
           AND objs.o <> (SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname = $1) \
         ORDER BY 1 LIMIT 10",
    )
    .bind(&schema.raw)
    .fetch_all(&mut *conn)
    .await?;
    if !planted.is_empty() {
        bail!(
            "schema {} holds objects owned by other roles (pre-planted?): {}; inspect them, \
             then drop them or reassign ownership before migrating",
            schema.quoted,
            planted.join(", ")
        );
    }
    Ok(schema)
}

/// Grant `app_role` the DML it needs and nothing more, in one transaction.
/// Never `GRANT ALL`, never `TRIGGER` or `REFERENCES`. Idempotent: the audit
/// tables and `_sqlx_migrations` are revoked first, so the state converges.
/// `test_routes` adds table-level `UPDATE` on the audit tables (the E2E
/// backdate hook updates `rule_audit.occurred_at`); with it off, it is revoked.
/// The schema the grants act on is the one that holds `rule_audit`.
pub async fn apply_app_grants(
    conn: &mut PgConnection,
    app_role: &str,
    test_routes: bool,
) -> Result<()> {
    let prepared = prepare_owner_schema(conn, app_role).await?;

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT n.nspname::pg_catalog.text, pg_catalog.quote_ident(n.nspname) \
         FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.oid = pg_catalog.to_regclass('rule_audit')",
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some((raw, quoted)) = row else {
        bail!("table rule_audit not found; run the migrations first");
    };
    if raw != prepared.raw {
        bail!(
            "rule_audit lives in schema {quoted}, not in the owner step's schema {}",
            prepared.quoted
        );
    }
    let schema = quoted;
    // Identifiers are quoted by the server, never concatenated raw.
    let role: String = sqlx::query_scalar("SELECT pg_catalog.quote_ident($1)")
        .bind(app_role)
        .fetch_one(&mut *conn)
        .await?;
    let audit = AUDIT_TABLES.map(|t| format!("{schema}.{t}")).join(", ");
    let migrations = format!("{schema}._sqlx_migrations");

    let mut stmts = vec![
        format!("GRANT USAGE ON SCHEMA {schema} TO {role}"),
        format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA {schema} TO {role}"
        ),
        format!("GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA {schema} TO {role}"),
        format!("REVOKE ALL ON {audit} FROM {role}"),
        format!("GRANT SELECT, INSERT, DELETE, TRUNCATE ON {audit} TO {role}"),
        format!(
            "GRANT UPDATE (repeat_count, last_occurred_at) ON {schema}.audit_events TO {role}"
        ),
    ];
    if test_routes {
        stmts.push(format!("GRANT UPDATE ON {audit} TO {role}"));
    }
    stmts.push(format!("REVOKE ALL ON {migrations} FROM {role}"));
    stmts.push(format!("GRANT SELECT ON {migrations} TO {role}"));

    let mut tx = conn.begin().await?;
    for stmt in &stmts {
        sqlx::query(stmt).execute(&mut *tx).await?;
    }
    tx.commit().await?;

    let can_create: bool =
        sqlx::query_scalar("SELECT pg_catalog.has_schema_privilege($1, $2, 'CREATE')")
            .bind(app_role)
            .bind(&raw)
            .fetch_one(&mut *conn)
            .await?;
    if can_create {
        bail!("application role {app_role:?} can still CREATE in schema {schema} (inherited from another role?)");
    }
    Ok(())
}

/// The embedded migrations as `(version, checksum)`, up migrations only.
fn expected_migrations() -> Vec<(i64, Vec<u8>)> {
    sqlx::migrate!("./migrations")
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
        .map(|m| (m.version, m.checksum.to_vec()))
        .collect()
}

/// Pure comparison of the embedded migrations against the applied ones.
fn check_applied(expected: &[(i64, Vec<u8>)], applied: &[(i64, Vec<u8>)]) -> Result<()> {
    for (version, checksum) in applied {
        match expected.iter().find(|(v, _)| v == version) {
            None => bail!("database has migration {version} that this build does not know"),
            Some((_, c)) if c != checksum => {
                bail!("migration {version} was modified after it was applied (checksum mismatch)")
            }
            Some(_) => {}
        }
    }
    let pending: Vec<String> = expected
        .iter()
        .filter(|(v, _)| !applied.iter().any(|(a, _)| a == v))
        .map(|(v, _)| v.to_string())
        .collect();
    if !pending.is_empty() {
        bail!(
            "pending migrations ({}); run `stig-viewer-backend migrate` with DATABASE_MIGRATION_URL first",
            pending.join(", ")
        );
    }
    Ok(())
}

/// Read-only check that every embedded migration is applied with a matching
/// checksum. Used when the application role cannot migrate.
pub async fn verify_migrations(pool: &PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    if let Some(v) = conn.dirty_version().await? {
        bail!("migration {v} is marked dirty (a previous run failed part-way)");
    }
    let applied: Vec<(i64, Vec<u8>)> = conn
        .list_applied_migrations()
        .await
        .context("reading applied migrations")?
        .into_iter()
        .map(|m| (m.version, m.checksum.to_vec()))
        .collect();
    check_applied(&expected_migrations(), &applied)
}

/// True when the current role may run migrations itself: it owns
/// `_sqlx_migrations`, or the table does not exist yet (fresh database).
pub async fn can_migrate(pool: &PgPool) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE((SELECT pg_has_role(current_user, c.relowner, 'MEMBER') \
         FROM pg_class c \
         WHERE c.relname = '_sqlx_migrations' \
           AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema())), \
         true)",
    )
    .fetch_one(pool)
    .await?)
}

/// The guard triggers migration 040 creates: `(table, trigger, tgtype)`.
/// `tgtype`: ROW=1, BEFORE=2, DELETE=8, UPDATE=16, TRUNCATE=32. A migration
/// that changes the guard updates this one place.
const GUARD_TRIGGERS: [(&str, &str, i16); 4] = [
    ("rule_audit", "rule_audit_guard_row", 1 | 2 | 8 | 16),
    ("rule_audit", "rule_audit_guard_truncate", 2 | 32),
    ("audit_events", "audit_events_guard_row", 1 | 2 | 8 | 16),
    ("audit_events", "audit_events_guard_truncate", 2 | 32),
];

/// Ways in which `current_user` can still tamper with the audit guard.
/// Empty means the boundary holds. Every schema-scoped check uses the schema
/// that holds `rule_audit`.
pub async fn boundary_violations(pool: &PgPool, test_routes: bool) -> Result<Vec<String>> {
    let mut rows: Vec<String> = sqlx::query_scalar(
        "WITH s AS (SELECT c.relnamespace AS ns FROM pg_catalog.pg_class c \
                    WHERE c.oid = pg_catalog.to_regclass('rule_audit')) \
         SELECT 'role is a superuser' FROM pg_catalog.pg_roles \
           WHERE rolname = current_user AND rolsuper \
         UNION ALL \
         SELECT 'role has CREATEROLE' FROM pg_catalog.pg_roles \
           WHERE rolname = current_user AND rolcreaterole \
         UNION ALL \
         SELECT 'role is a member of ' || r.rolname FROM pg_catalog.pg_roles r \
         WHERE r.rolname IN ('pg_execute_server_program', 'pg_write_server_files', \
                             'pg_read_server_files') \
           AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER') \
         UNION ALL \
         SELECT 'role is a member of the owner of ' || c.relname \
         FROM pg_catalog.pg_class c \
         WHERE c.relnamespace = (SELECT ns FROM s) \
           AND c.relname IN ('rule_audit', 'audit_events', '_sqlx_migrations') \
           AND pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER') \
         UNION ALL \
         SELECT 'role is a member of the owner of ' || count(*) || ' other relations in the schema' \
         FROM pg_catalog.pg_class c \
         WHERE c.relnamespace = (SELECT ns FROM s) \
           AND c.relkind IN ('r', 'p', 'S', 'v', 'm') \
           AND c.relname NOT IN ('rule_audit', 'audit_events', '_sqlx_migrations') \
           AND pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER') \
         HAVING count(*) > 0 \
         UNION ALL \
         SELECT 'role is a member of the owner of ' || count(*) || ' functions in the schema' \
         FROM pg_catalog.pg_proc p \
         WHERE p.pronamespace = (SELECT ns FROM s) \
           AND pg_catalog.pg_has_role(current_user, p.proowner, 'MEMBER') \
         HAVING count(*) > 0 \
         UNION ALL \
         SELECT 'role is a member of the owner of schema ' || n.nspname \
         FROM pg_catalog.pg_namespace n \
         WHERE n.oid = (SELECT ns FROM s) \
           AND pg_catalog.pg_has_role(current_user, n.nspowner, 'MEMBER') \
         UNION ALL \
         SELECT 'role is a member of the owner of database ' || d.datname \
         FROM pg_catalog.pg_database d \
         WHERE d.datname = pg_catalog.current_database() \
           AND pg_catalog.pg_has_role(current_user, d.datdba, 'MEMBER') \
         UNION ALL \
         SELECT 'role can CREATE in schema ' || n.nspname \
         FROM pg_catalog.pg_namespace n \
         WHERE n.oid = (SELECT ns FROM s) \
           AND pg_catalog.has_schema_privilege(current_user, n.oid, 'CREATE') \
         UNION ALL \
         SELECT 'role can CREATE in database ' || pg_catalog.current_database() \
         WHERE pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'CREATE') \
         UNION ALL \
         SELECT 'role holds TRIGGER on ' || t \
         FROM unnest(ARRAY['rule_audit', 'audit_events']) AS t \
         WHERE pg_catalog.has_table_privilege(current_user, t, 'TRIGGER') \
         UNION ALL \
         SELECT 'role holds table-level UPDATE on ' || t || ' with test routes off' \
         FROM unnest(ARRAY['rule_audit', 'audit_events']) AS t \
         WHERE NOT $1 AND pg_catalog.has_table_privilege(current_user, t, 'UPDATE') \
         UNION ALL \
         SELECT 'audit_tables_guard() does not pin search_path to pg_catalog, pg_temp' \
         FROM pg_catalog.pg_proc p \
         WHERE p.oid = 'audit_tables_guard()'::pg_catalog.regprocedure \
           AND NOT ('search_path=pg_catalog, pg_temp' = ANY (COALESCE(p.proconfig, '{}')))",
    )
    .bind(test_routes)
    .fetch_all(pool)
    .await
    .context("checking the audit guard boundary (is the schema migrated?)")?;

    // The trigger set must be exactly the expected one: per table, the
    // expected triggers, bound to the guard function, enabled ALWAYS.
    let actual: Vec<(String, String, i16, String, bool)> = sqlx::query_as(
        "SELECT c.relname::pg_catalog.text, t.tgname::pg_catalog.text, t.tgtype, \
                t.tgenabled::pg_catalog.text, \
                t.tgfoid = 'audit_tables_guard()'::pg_catalog.regprocedure \
         FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid \
         WHERE t.tgrelid IN ('rule_audit'::pg_catalog.regclass, 'audit_events'::pg_catalog.regclass) \
           AND NOT t.tgisinternal \
         ORDER BY 1, 2",
    )
    .fetch_all(pool)
    .await?;
    for table in AUDIT_TABLES {
        let mut want: Vec<(&str, i16)> = GUARD_TRIGGERS
            .iter()
            .filter(|(t, _, _)| *t == table)
            .map(|(_, name, ty)| (*name, *ty))
            .collect();
        want.sort_unstable();
        let mut got: Vec<(&str, i16)> = actual
            .iter()
            .filter(|(t, _, _, enabled, guard)| t == table && enabled == "A" && *guard)
            .map(|(_, name, ty, _, _)| (name.as_str(), *ty))
            .collect();
        got.sort_unstable();
        let total = actual.iter().filter(|(t, ..)| t == table).count();
        if got != want || total != want.len() {
            rows.push(format!(
                "audit guard triggers on {table} are missing, altered, disabled or extra \
                 (expected {} bound to audit_tables_guard(), enabled ALWAYS)",
                want.len()
            ));
        }
    }

    // PostgreSQL 15+ only: SET privilege on the audit test flag parameter.
    // Skipped on older servers; on 15+ a failing query fails closed.
    let pg15: bool = sqlx::query_scalar(
        "SELECT pg_catalog.current_setting('server_version_num')::pg_catalog.int4 >= 150000",
    )
    .fetch_one(pool)
    .await?;
    if pg15 {
        let can_set: bool = sqlx::query_scalar(
            "SELECT pg_catalog.has_parameter_privilege(current_user, 'stig.audit_allow_test_mode', 'SET')",
        )
        .fetch_one(pool)
        .await
        .context("checking SET privilege on stig.audit_allow_test_mode")?;
        if can_set {
            rows.push("role can SET stig.audit_allow_test_mode".to_string());
        }
    }
    Ok(rows)
}

/// Startup policy for [`boundary_violations`]: refuse in production, warn
/// everywhere else.
pub fn boundary_policy(production: bool, violations: &[String]) -> Result<()> {
    if violations.is_empty() {
        return Ok(());
    }
    let list = violations.join("; ");
    if production {
        bail!(
            "refusing to start: the database role can tamper with the audit guard ({list}); \
             run migrations as a separate owner role (DATABASE_MIGRATION_URL) and connect \
             the server as a restricted role, see README"
        );
    }
    tracing::warn!(
        "the database role can tamper with the audit guard ({list}); production refuses to \
         start in this state"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{allow_audit_test_mode, app_role_pool, seed_user};
    use sqlx::PgPool;

    fn code(e: &sqlx::Error) -> Option<String> {
        e.as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.to_string())
    }

    #[test]
    fn boundary_policy_truth_table() {
        let v = vec!["role is a superuser".to_string()];
        assert!(boundary_policy(true, &[]).is_ok());
        assert!(boundary_policy(false, &[]).is_ok());
        assert!(boundary_policy(false, &v).is_ok());
        let err = boundary_policy(true, &v).unwrap_err().to_string();
        assert!(err.contains("role is a superuser"));
    }

    #[test]
    fn app_role_is_the_url_username() {
        assert_eq!(
            app_role_from_url("postgres://stig_app:pw@db:5432/x").unwrap(),
            "stig_app"
        );
        assert!(app_role_from_url("not a url").is_err());
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn command_parsing() {
        assert_eq!(parse_command(&[]).unwrap(), Command::Serve);
        assert_eq!(
            parse_command(&args(&["migrate"])).unwrap(),
            Command::Migrate
        );
        assert!(parse_command(&args(&["bogus"])).is_err());
        assert!(parse_command(&args(&["migrate", "extra"])).is_err());
        assert!(parse_command(&args(&["--migrate"])).is_err());
    }

    #[test]
    fn migrate_preconditions_need_the_url_and_refuse_test_hooks_in_production() {
        use crate::config::TestHooks;
        let dev = TestHooks::from_vars(None, Some("true"), None);
        assert_eq!(migrate_preconditions(&dev, Some("u")).unwrap(), "u");
        assert!(migrate_preconditions(&dev, None).is_err());
        let prod_routes = TestHooks::from_vars(Some("production"), Some("true"), None);
        assert!(migrate_preconditions(&prod_routes, Some("u")).is_err());
        let prod_header = TestHooks::from_vars(Some("production"), None, Some("1"));
        assert!(migrate_preconditions(&prod_header, Some("u")).is_err());
        let prod = TestHooks::from_vars(Some("production"), None, None);
        assert_eq!(migrate_preconditions(&prod, Some("u")).unwrap(), "u");
    }

    #[tokio::test]
    async fn migrate_as_owner_refuses_test_routes_in_production_before_connecting() {
        let err = migrate_as_owner(
            "postgres://o@127.0.0.1:1/d",
            "postgres://a@127.0.0.1:1/d",
            true,
            true,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("production"), "{err}");
    }

    #[test]
    fn startup_path_choice() {
        assert_eq!(
            startup_path(true, || panic!("not consulted")),
            StartupPath::OwnerMigrates
        );
        assert_eq!(startup_path(false, || true), StartupPath::SelfMigrate);
        assert_eq!(startup_path(false, || false), StartupPath::VerifyOnly);
    }

    #[test]
    fn same_role_is_rejected() {
        assert!(check_distinct_roles("stig", "stig").is_err());
        assert!(check_distinct_roles("stig", "stig_app").is_ok());
    }

    #[test]
    fn check_applied_detects_pending_mismatch_and_unknown() {
        let exp = expected_migrations();
        assert!(!exp.is_empty());
        assert!(check_applied(&exp, &exp).is_ok());
        assert!(check_applied(&exp, &exp[..exp.len() - 1]).is_err());
        let mut bad = exp.clone();
        bad[0].1 = vec![0];
        assert!(check_applied(&exp, &bad).is_err());
        let mut extra = exp.clone();
        extra.push((i64::MAX, vec![]));
        assert!(check_applied(&exp, &extra).is_err());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn app_role_cannot_tamper_with_the_guard(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        let triggers_before: Vec<(String, String)> = sqlx::query_as(
            "SELECT tgname::text, tgenabled::text FROM pg_trigger \
             WHERE tgrelid IN ('rule_audit'::regclass, 'audit_events'::regclass) \
               AND NOT tgisinternal ORDER BY tgname",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(triggers_before.len(), 4);
        assert!(triggers_before.iter().all(|(_, e)| e == "A"));
        let src_before: String =
            sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE proname = 'audit_tables_guard'")
                .fetch_one(&pool)
                .await
                .unwrap();

        let stmts = [
            "DROP TRIGGER rule_audit_guard_row ON rule_audit",
            "DROP TRIGGER rule_audit_guard_truncate ON rule_audit",
            "DROP TRIGGER audit_events_guard_row ON audit_events",
            "DROP TRIGGER audit_events_guard_truncate ON audit_events",
            "ALTER TABLE rule_audit DISABLE TRIGGER rule_audit_guard_row",
            "ALTER TABLE audit_events DISABLE TRIGGER ALL",
            "ALTER TABLE audit_events DISABLE TRIGGER USER",
            "ALTER TABLE rule_audit ENABLE REPLICA TRIGGER rule_audit_guard_row",
            "CREATE OR REPLACE FUNCTION audit_tables_guard() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
            "ALTER FUNCTION audit_tables_guard() RENAME TO audit_tables_guard_x",
            "ALTER FUNCTION audit_tables_guard() OWNER TO CURRENT_USER",
            "DROP FUNCTION audit_tables_guard() CASCADE",
            "DROP TABLE audit_events",
            "ALTER TABLE rule_audit OWNER TO CURRENT_USER",
            "ALTER TABLE rule_audit ADD COLUMN x int",
            "CREATE TRIGGER sneaky BEFORE INSERT ON rule_audit \
             FOR EACH ROW EXECUTE FUNCTION audit_tables_guard()",
            "SET session_replication_role = replica",
            "DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET stig.audit_allow_test_mode = %L', \
             current_database(), 'on'); END $$",
            "UPDATE _sqlx_migrations SET success = false",
            "DELETE FROM _sqlx_migrations",
        ];
        for stmt in stmts {
            let err = sqlx::query(stmt).execute(&app.pool).await.expect_err(stmt);
            assert_eq!(code(&err).as_deref(), Some("42501"), "{stmt}: {err}");
        }

        let triggers_after: Vec<(String, String)> = sqlx::query_as(
            "SELECT tgname::text, tgenabled::text FROM pg_trigger \
             WHERE tgrelid IN ('rule_audit'::regclass, 'audit_events'::regclass) \
               AND NOT tgisinternal ORDER BY tgname",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(triggers_after, triggers_before);
        let src_after: String =
            sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE proname = 'audit_tables_guard'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(src_after, src_before);
        assert!(!crate::db_audit::test_maintenance_allowed(&pool)
            .await
            .unwrap());
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn app_role_cannot_mutate_audit_rows_outside_maintenance(pool: PgPool) {
        seed_user(&pool, "u1").await;
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r1','status')")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO audit_events (user_id, action, outcome) VALUES ('u1','checklist.save','ok')")
            .execute(&pool).await.unwrap();
        let app = app_role_pool(&pool, false).await;
        for stmt in [
            "UPDATE rule_audit SET field = 'x'",
            "DELETE FROM rule_audit",
            "TRUNCATE rule_audit",
            "UPDATE audit_events SET repeat_count = repeat_count + 1",
            "DELETE FROM audit_events",
            "TRUNCATE audit_events",
            "TRUNCATE users CASCADE",
        ] {
            let err = sqlx::query(stmt).execute(&app.pool).await.expect_err(stmt);
            assert_eq!(code(&err).as_deref(), Some("42501"), "{stmt}: {err}");
        }
        // `migration` mode (UPDATE) is no longer usable by the app role.
        let mut tx = app.pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "migration")
            .await
            .unwrap();
        let err = sqlx::query("UPDATE audit_events SET outcome = 'denied'")
            .execute(&mut *tx)
            .await
            .expect_err("migration-mode update");
        assert_eq!(code(&err).as_deref(), Some("42501"), "{err}");
        drop(tx);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn app_role_can_do_its_normal_audit_work(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let app = app_role_pool(&pool, false).await;
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r1','status')")
            .execute(&app.pool).await.unwrap();
        sqlx::query("INSERT INTO audit_events (user_id, action, outcome) VALUES ('u1','checklist.save','denied')")
            .execute(&app.pool).await.unwrap();
        // The collapse UPDATE of a repeated denial.
        let n = sqlx::query(
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = now()",
        )
        .execute(&app.pool)
        .await
        .unwrap()
        .rows_affected();
        assert_eq!(n, 1);
        // Retention DELETE.
        let mut tx = app.pool.begin().await.unwrap();
        crate::audit_retention::declare_retention_delete(&mut tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM rule_audit")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        // Restore TRUNCATE.
        let mut tx = app.pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "restore")
            .await
            .unwrap();
        sqlx::query("TRUNCATE audit_events, rule_audit")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn test_route_grants_follow_the_flag_and_converge(pool: PgPool) {
        use crate::api::test_support::{backdate_audit, reset_db};
        seed_user(&pool, "u1").await;
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r1','status')")
            .execute(&pool).await.unwrap();
        allow_audit_test_mode(&pool).await;
        let app = app_role_pool(&pool, true).await;
        backdate_audit(&app.pool, "r1", 60).await.unwrap();
        reset_db(&app.pool).await.unwrap();

        let mut conn = pool.acquire().await.unwrap();
        // Idempotent.
        apply_app_grants(&mut conn, &app.name, true).await.unwrap();
        apply_app_grants(&mut conn, &app.name, false).await.unwrap();
        apply_app_grants(&mut conn, &app.name, false).await.unwrap();
        drop(conn);
        let has_update: bool =
            sqlx::query_scalar("SELECT has_table_privilege($1, 'rule_audit', 'UPDATE')")
                .bind(&app.name)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!has_update);
        let err = backdate_audit(&app.pool, "r1", 60).await.unwrap_err();
        let db_err = err.downcast_ref::<sqlx::Error>().expect("sqlx error");
        assert_eq!(code(db_err).as_deref(), Some("42501"), "{err}");
        for sql in [
            "SELECT has_column_privilege($1, 'audit_events', 'repeat_count', 'UPDATE')",
            "SELECT has_column_privilege($1, 'audit_events', 'last_occurred_at', 'UPDATE')",
        ] {
            let ok: bool = sqlx::query_scalar(sql)
                .bind(&app.name)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert!(ok, "{sql}");
        }
        let no_col: bool = sqlx::query_scalar(
            "SELECT has_column_privilege($1, 'audit_events', 'outcome', 'UPDATE')",
        )
        .bind(&app.name)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!no_col);
        let trig: bool =
            sqlx::query_scalar("SELECT has_table_privilege($1, 'rule_audit', 'TRIGGER')")
                .bind(&app.name)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!trig);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn grants_reject_unknown_and_same_roles(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        assert!(apply_app_grants(&mut conn, "stig_no_such_role_x", false)
            .await
            .is_err());
        let me: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert!(apply_app_grants(&mut conn, &me, false).await.is_err());
    }

    fn has(v: &[String], needle: &str) -> bool {
        v.iter().any(|m| m.contains(needle))
    }

    async fn exec(pool: &PgPool, sql: &str) {
        sqlx::query(sql).execute(pool).await.expect(sql);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn boundary_violations_for_a_superuser_name_each_reason(pool: PgPool) {
        let v = boundary_violations(&pool, false).await.unwrap();
        for needle in [
            "role is a superuser",
            "role has CREATEROLE",
            "role is a member of pg_execute_server_program",
            "role is a member of the owner of rule_audit",
            "role is a member of the owner of audit_events",
            "role is a member of the owner of _sqlx_migrations",
            "other relations in the schema",
            "functions in the schema",
            "role is a member of the owner of schema",
            "role is a member of the owner of database",
            "role can CREATE in schema",
            "role holds TRIGGER on rule_audit",
            "table-level UPDATE on audit_events with test routes off",
        ] {
            assert!(has(&v, needle), "{needle}: {v:?}");
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn boundary_violations_are_empty_for_the_app_role_and_each_escalation_is_named(
        pool: PgPool,
    ) {
        let app = app_role_pool(&pool, false).await;
        let q = format!("\"{}\"", app.name);
        let none = boundary_violations(&app.pool, false).await.unwrap();
        assert!(none.is_empty(), "{none:?}");

        // TRIGGER on an audit table.
        exec(&pool, &format!("GRANT TRIGGER ON rule_audit TO {q}")).await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert_eq!(v, ["role holds TRIGGER on rule_audit"]);
        exec(&pool, &format!("REVOKE TRIGGER ON rule_audit FROM {q}")).await;

        // CREATEROLE.
        exec(&pool, &format!("ALTER ROLE {q} CREATEROLE")).await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(has(&v, "role has CREATEROLE"), "{v:?}");
        exec(&pool, &format!("ALTER ROLE {q} NOCREATEROLE")).await;

        // CREATE on the schema and on the database.
        exec(&pool, &format!("GRANT CREATE ON SCHEMA public TO {q}")).await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert_eq!(v, ["role can CREATE in schema public"]);
        exec(&pool, &format!("REVOKE CREATE ON SCHEMA public FROM {q}")).await;
        exec(
            &pool,
            &format!(
                "GRANT CREATE ON DATABASE \"{}\" TO {q}",
                db_name(&pool).await
            ),
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(has(&v, "role can CREATE in database"), "{v:?}");
        exec(
            &pool,
            &format!(
                "REVOKE CREATE ON DATABASE \"{}\" FROM {q}",
                db_name(&pool).await
            ),
        )
        .await;

        // Membership in the role that owns the audit tables.
        let owner: String = sqlx::query_scalar(
            "SELECT pg_get_userbyid(relowner)::text FROM pg_class WHERE relname = 'rule_audit'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        exec(&pool, &format!("GRANT \"{owner}\" TO {q}")).await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(
            has(&v, "role is a member of the owner of rule_audit"),
            "{v:?}"
        );
        assert!(has(&v, "functions in the schema"), "{v:?}");
        exec(&pool, &format!("REVOKE \"{owner}\" FROM {q}")).await;

        // Escalation roles.
        exec(&pool, &format!("GRANT pg_write_server_files TO {q}")).await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert_eq!(v, ["role is a member of pg_write_server_files"]);
        exec(&pool, &format!("REVOKE pg_write_server_files FROM {q}")).await;

        // Table-level UPDATE on the audit tables with test routes off.
        let test_app = app_role_pool(&pool, true).await;
        assert!(boundary_violations(&test_app.pool, true)
            .await
            .unwrap()
            .is_empty());
        let v = boundary_violations(&test_app.pool, false).await.unwrap();
        assert!(
            has(&v, "table-level UPDATE on rule_audit with test routes off"),
            "{v:?}"
        );
        test_app.cleanup(&pool).await;
        app.cleanup(&pool).await;
    }

    async fn db_name(pool: &PgPool) -> String {
        sqlx::query_scalar("SELECT current_database()::text")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn database_ownership_is_a_violation(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        let q = format!("\"{}\"", app.name);
        let db = db_name(&pool).await;
        let dbo = format!("stig_t_dbo_{}", app.name.trim_start_matches("stig_t_"));
        exec(&pool, &format!("CREATE ROLE \"{dbo}\" NOLOGIN")).await;
        exec(
            &pool,
            &format!("ALTER DATABASE \"{db}\" OWNER TO \"{dbo}\""),
        )
        .await;
        exec(&pool, &format!("GRANT \"{dbo}\" TO {q}")).await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(
            has(&v, "role is a member of the owner of database"),
            "{v:?}"
        );
        assert!(has(&v, "role is a member of the owner of schema"), "{v:?}");
        exec(&pool, &format!("REVOKE \"{dbo}\" FROM {q}")).await;
        exec(
            &pool,
            &format!("ALTER DATABASE \"{db}\" OWNER TO CURRENT_USER"),
        )
        .await;
        exec(&pool, &format!("DROP ROLE \"{dbo}\"")).await;
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_disabled_guard_trigger_is_a_violation(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        exec(
            &pool,
            "ALTER TABLE rule_audit DISABLE TRIGGER rule_audit_guard_row",
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(
            v[0].starts_with("audit guard triggers on rule_audit are missing"),
            "{v:?}"
        );
        exec(
            &pool,
            "ALTER TABLE rule_audit ENABLE ALWAYS TRIGGER rule_audit_guard_row",
        )
        .await;
        assert!(boundary_violations(&app.pool, false)
            .await
            .unwrap()
            .is_empty());
        exec(&pool, "DROP TRIGGER audit_events_guard_row ON audit_events").await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(
            has(&v, "audit guard triggers on audit_events are missing"),
            "{v:?}"
        );
        // An extra trigger on an audit table is also a deviation.
        exec(
            &pool,
            "CREATE TRIGGER audit_events_guard_row BEFORE UPDATE OR DELETE ON audit_events \
             FOR EACH ROW EXECUTE FUNCTION audit_tables_guard()",
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(has(&v, "audit guard triggers on audit_events"), "{v:?}"); // not ENABLE ALWAYS
        exec(
            &pool,
            "ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_guard_row",
        )
        .await;
        assert!(boundary_violations(&app.pool, false)
            .await
            .unwrap()
            .is_empty());
        exec(
            &pool,
            "CREATE TRIGGER extra BEFORE INSERT ON audit_events \
             FOR EACH ROW EXECUTE FUNCTION audit_tables_guard()",
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(has(&v, "audit guard triggers on audit_events"), "{v:?}");
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn set_privilege_on_the_test_flag_parameter_is_a_violation(pool: PgPool) {
        let ver: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
            .fetch_one(&pool)
            .await
            .unwrap();
        if ver < 150000 {
            return; // GRANT ... ON PARAMETER does not exist before PostgreSQL 15
        }
        let app = app_role_pool(&pool, false).await;
        let q = format!("\"{}\"", app.name);
        exec(
            &pool,
            &format!("GRANT SET ON PARAMETER stig.audit_allow_test_mode TO {q}"),
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert_eq!(v, ["role can SET stig.audit_allow_test_mode"]);
        exec(
            &pool,
            &format!("REVOKE SET ON PARAMETER stig.audit_allow_test_mode FROM {q}"),
        )
        .await;
        assert!(boundary_violations(&app.pool, false)
            .await
            .unwrap()
            .is_empty());
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_owner_step_refuses_objects_planted_by_the_app_role(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        // An old ACL: PUBLIC may create in public. The app role plants built-in
        // look-alikes that the migrator and this module would otherwise call.
        exec(&pool, "GRANT CREATE ON SCHEMA public TO PUBLIC").await;
        exec(&pool, "CREATE TABLE planted_log (called text)").await;
        exec(&pool, "GRANT INSERT ON planted_log TO PUBLIC").await;
        exec(
            &app.pool,
            "CREATE FUNCTION public.quote_ident(text) RETURNS text LANGUAGE sql \
             AS 'INSERT INTO public.planted_log VALUES (''quote_ident''); SELECT $1' ",
        )
        .await;
        let _ = sqlx::query(
            "CREATE FUNCTION public.pg_advisory_lock(bigint) RETURNS void LANGUAGE sql \
             AS 'INSERT INTO public.planted_log VALUES (''advisory''); SELECT NULL::void'",
        )
        .execute(&app.pool)
        .await;

        let err = migrate_with((*pool.connect_options()).clone(), &app.name, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("owned by other roles"), "{err}");
        assert!(err.contains("quote_ident"), "{err}");
        let calls: i64 = sqlx::query_scalar("SELECT count(*) FROM planted_log")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(calls, 0, "a planted function ran");
        // The schema was closed before the check.
        let create: bool =
            sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
                .bind(&app.name)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!create);
        exec(&pool, "DROP FUNCTION public.quote_ident(text)").await;
        let _ = sqlx::query("DROP FUNCTION public.pg_advisory_lock(bigint)")
            .execute(&pool)
            .await;
        exec(&pool, "DROP TABLE planted_log").await;
        // With the plants gone the owner step succeeds.
        migrate_with((*pool.connect_options()).clone(), &app.name, false)
            .await
            .unwrap();
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_owner_step_removes_schema_create_even_when_public_had_it(pool: PgPool) {
        exec(&pool, "GRANT CREATE ON SCHEMA public TO PUBLIC").await;
        let app = app_role_pool(&pool, false).await;
        let create: bool =
            sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
                .bind(&app.name)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!create);
        let err = sqlx::query("CREATE TABLE sneaky (x int)")
            .execute(&app.pool)
            .await
            .unwrap_err();
        assert_eq!(code(&err).as_deref(), Some("42501"), "{err}");
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn verify_migrations_detects_pending(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        assert!(!can_migrate(&app.pool).await.unwrap());
        assert!(can_migrate(&pool).await.unwrap());
        verify_migrations(&app.pool).await.unwrap();
        sqlx::query(
            "DELETE FROM _sqlx_migrations WHERE version = (SELECT MAX(version) FROM _sqlx_migrations)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let err = verify_migrations(&app.pool).await.unwrap_err().to_string();
        assert!(err.contains("pending migrations"), "{err}");
        app.cleanup(&pool).await;
    }

    #[test]
    fn transient_errors_exit_75_and_the_rest_exit_1() {
        let missing = anyhow::Error::new(AppRoleMissing("x".into()));
        assert!(is_transient(&missing));
        assert_eq!(migrate_exit_code(&missing), MIGRATE_EXIT_TRANSIENT);
        let wrapped = missing.context("owner step");
        assert!(is_transient(&wrapped));
        let io = anyhow::Error::new(sqlx::Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        )))
        .context("connecting with DATABASE_MIGRATION_URL");
        assert_eq!(migrate_exit_code(&io), 75);
        let timeout = anyhow::Error::new(sqlx::Error::PoolTimedOut);
        assert_eq!(migrate_exit_code(&timeout), 75);
        let mismatch = anyhow::Error::new(sqlx::migrate::MigrateError::VersionMismatch(1));
        assert!(!is_transient(&mismatch));
        assert_eq!(migrate_exit_code(&mismatch), 1);
        assert_eq!(migrate_exit_code(&anyhow::anyhow!("boom")), 1);
        let held = anyhow::Error::new(OwnerStepLockHeld);
        assert_eq!(migrate_exit_code(&held), 75);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_missing_app_role_is_transient_and_a_planted_object_is_not(pool: PgPool) {
        let err = migrate_with(
            (*pool.connect_options()).clone(),
            "stig_no_such_role_x",
            false,
        )
        .await
        .unwrap_err();
        assert!(is_transient(&err), "{err:#}");

        let app = app_role_pool(&pool, false).await;
        exec(&pool, "GRANT CREATE ON SCHEMA public TO PUBLIC").await;
        exec(
            &app.pool,
            "CREATE FUNCTION public.quote_ident(text) RETURNS text LANGUAGE sql AS 'SELECT $1'",
        )
        .await;
        let err = migrate_with((*pool.connect_options()).clone(), &app.name, false)
            .await
            .unwrap_err();
        assert!(!is_transient(&err), "{err:#}");
        exec(&pool, "DROP FUNCTION public.quote_ident(text)").await;
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_held_owner_lock_times_out_as_a_transient_error(pool: PgPool) {
        let mut holder = pool.acquire().await.unwrap();
        lock_owner_step(&mut holder, std::time::Duration::from_secs(5))
            .await
            .unwrap();
        let mut waiter = pool.acquire().await.unwrap();
        let err = lock_owner_step(&mut waiter, std::time::Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(err.is::<OwnerStepLockHeld>(), "{err:#}");
        assert!(is_transient(&err));
        assert_eq!(migrate_exit_code(&err), 75);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn concurrent_owner_steps_all_succeed(pool: PgPool) {
        let app = app_role_pool(&pool, true).await;
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let opts = (*pool.connect_options()).clone();
            let name = app.name.clone();
            set.spawn(async move { migrate_with(opts, &name, true).await });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap().unwrap();
        }
        assert!(crate::db_audit::test_maintenance_allowed(&pool)
            .await
            .unwrap());
        app.cleanup(&pool).await;
    }
}
