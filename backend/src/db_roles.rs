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
    check_distinct_roles(owner_opts.get_username(), &app_role)?;

    let owner_pool = PgPoolOptions::new()
        .max_connections(1)
        // Do not let a role- or database-level search_path setting decide
        // which schema the migrations and grants act on.
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET search_path = public, pg_catalog")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with(owner_opts)
        .await
        .context("connecting with DATABASE_MIGRATION_URL")?;
    let result = async {
        sqlx::migrate!("./migrations").run(&owner_pool).await?;
        let mut conn = owner_pool.acquire().await?;
        apply_app_grants(&mut conn, &app_role, test_routes).await?;
        drop(conn);
        if test_routes {
            crate::db_audit::allow_test_maintenance(&owner_pool).await?;
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    owner_pool.close().await;
    result
}

/// Grant `app_role` the DML it needs and nothing more, in one transaction.
/// Never `GRANT ALL`, never `TRIGGER` or `REFERENCES`. Idempotent: the audit
/// tables and `_sqlx_migrations` are revoked first, so the state converges.
/// `test_routes` adds table-level `UPDATE` on the audit tables (the E2E
/// backdate hook updates `rule_audit.occurred_at`); with it off, it is revoked.
pub async fn apply_app_grants(
    conn: &mut PgConnection,
    app_role: &str,
    test_routes: bool,
) -> Result<()> {
    let owner: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut *conn)
        .await?;
    check_distinct_roles(&owner, app_role)?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(app_role)
            .fetch_one(&mut *conn)
            .await?;
    if !exists {
        bail!("application role {app_role:?} does not exist; create it before migrating");
    }

    // Identifiers are quoted by the server, never concatenated raw.
    let role: String = sqlx::query_scalar("SELECT quote_ident($1)")
        .bind(app_role)
        .fetch_one(&mut *conn)
        .await?;
    let schema: String = sqlx::query_scalar("SELECT quote_ident(current_schema())")
        .fetch_one(&mut *conn)
        .await?;
    let audit = AUDIT_TABLES.map(|t| format!("{schema}.{t}")).join(", ");
    let migrations = format!("{schema}._sqlx_migrations");

    // REVOKE by a role that does not own the schema is a silent no-op, so check.
    let may_revoke: bool = sqlx::query_scalar(
        "SELECT r.rolsuper OR pg_has_role(current_user, n.nspowner, 'MEMBER') \
         FROM pg_namespace n, pg_roles r \
         WHERE n.nspname = current_schema() AND r.rolname = current_user",
    )
    .fetch_one(&mut *conn)
    .await?;
    if !may_revoke {
        bail!(
            "the owner role must own schema {schema} (or be a superuser) to revoke CREATE \
             on it from PUBLIC and the application role"
        );
    }

    let mut stmts = vec![
        format!("REVOKE CREATE ON SCHEMA {schema} FROM PUBLIC"),
        format!("REVOKE CREATE ON SCHEMA {schema} FROM {role}"),
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

/// Ways in which `current_user` can still tamper with the audit guard.
/// Empty means the boundary holds.
pub async fn boundary_violations(pool: &PgPool, test_routes: bool) -> Result<Vec<String>> {
    let mut rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'role is a superuser' FROM pg_roles WHERE rolname = current_user AND rolsuper \
         UNION ALL \
         SELECT 'role has CREATEROLE' FROM pg_roles WHERE rolname = current_user AND rolcreaterole \
         UNION ALL \
         SELECT 'role is a member of ' || r.rolname FROM pg_roles r \
         WHERE r.rolname IN ('pg_execute_server_program', 'pg_write_server_files', \
                             'pg_read_server_files') \
           AND pg_has_role(current_user, r.oid, 'MEMBER') \
         UNION ALL \
         SELECT 'role is a member of the owner of ' || c.relname \
         FROM pg_class c \
         WHERE c.oid = ANY (ARRAY['rule_audit'::regclass, 'audit_events'::regclass, \
                                  '_sqlx_migrations'::regclass]) \
           AND pg_has_role(current_user, c.relowner, 'MEMBER') \
         UNION ALL \
         SELECT 'role is a member of the owner of ' || count(*) || ' other relations in the schema' \
         FROM pg_class c \
         WHERE c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema()) \
           AND c.relkind IN ('r', 'p', 'S', 'v', 'm') \
           AND c.relname NOT IN ('rule_audit', 'audit_events', '_sqlx_migrations') \
           AND pg_has_role(current_user, c.relowner, 'MEMBER') \
         HAVING count(*) > 0 \
         UNION ALL \
         SELECT 'role is a member of the owner of ' || count(*) || ' functions in the schema' \
         FROM pg_proc p \
         WHERE p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema()) \
           AND pg_has_role(current_user, p.proowner, 'MEMBER') \
         HAVING count(*) > 0 \
         UNION ALL \
         SELECT 'role is a member of the owner of schema ' || n.nspname \
         FROM pg_namespace n \
         WHERE n.nspname = current_schema() AND pg_has_role(current_user, n.nspowner, 'MEMBER') \
         UNION ALL \
         SELECT 'role is a member of the owner of database ' || d.datname \
         FROM pg_database d \
         WHERE d.datname = current_database() AND pg_has_role(current_user, d.datdba, 'MEMBER') \
         UNION ALL \
         SELECT 'role can CREATE in schema ' || current_schema() \
         WHERE has_schema_privilege(current_user, current_schema(), 'CREATE') \
         UNION ALL \
         SELECT 'role can CREATE in database ' || current_database() \
         WHERE has_database_privilege(current_user, current_database(), 'CREATE') \
         UNION ALL \
         SELECT 'role holds TRIGGER on ' || t \
         FROM unnest(ARRAY['rule_audit', 'audit_events']) AS t \
         WHERE has_table_privilege(current_user, t, 'TRIGGER') \
         UNION ALL \
         SELECT 'role holds table-level UPDATE on ' || t || ' with test routes off' \
         FROM unnest(ARRAY['rule_audit', 'audit_events']) AS t \
         WHERE NOT $1 AND has_table_privilege(current_user, t, 'UPDATE') \
         UNION ALL \
         SELECT 'audit guard triggers are missing or not enabled (found ' || n || ' of 4)' \
         FROM (SELECT count(*) AS n FROM pg_trigger \
               WHERE tgrelid IN ('rule_audit'::regclass, 'audit_events'::regclass) \
                 AND tgfoid = 'audit_tables_guard()'::regprocedure \
                 AND tgenabled = 'A' AND NOT tgisinternal) g \
         WHERE n <> 4",
    )
    .bind(test_routes)
    .fetch_all(pool)
    .await?;

    // PostgreSQL 15+ only: SET privilege on the audit test flag parameter.
    // Skipped on older servers, and if the check itself errors.
    let pg15: bool =
        sqlx::query_scalar("SELECT current_setting('server_version_num')::int >= 150000")
            .fetch_one(pool)
            .await?;
    if pg15 {
        let can_set: Option<bool> = sqlx::query_scalar(
            "SELECT has_parameter_privilege(current_user, 'stig.audit_allow_test_mode', 'SET')",
        )
        .fetch_one(pool)
        .await
        .ok();
        if can_set == Some(true) {
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
        crate::db_audit::set_maintenance(&mut tx, "retention")
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
        assert!(
            has(&v, "role is a member of the owner of audit_tables_guard()")
                || has(&v, "functions in the schema"),
            "{v:?}"
        );
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
        assert_eq!(
            v,
            ["audit guard triggers are missing or not enabled (found 3 of 4)"]
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
        assert!(has(&v, "found 3 of 4"), "{v:?}");
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
}
