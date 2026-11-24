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
//!
//! On the two audit tables the application role can read, insert (column-level,
//! never `id` or `occurred_at`) and collapse repeats, but not delete, truncate
//! or move the id sequences (#109). Pruning and restoring audit rows run
//! through the owner-owned `SECURITY DEFINER` functions of migration 050
//! ([`AUDIT_FUNCTIONS`]), which enforce the retention floor and the
//! owner-opened restore window kept in `audit_policy`. The owner step and the
//! startup boundary check also write system audit events (#110).

use std::str::FromStr;

use anyhow::{bail, Context, Result};
use sqlx::migrate::Migrate;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, PgPool};

/// Append-only tables guarded by the triggers from migration 040.
pub const AUDIT_TABLES: [&str; 2] = ["rule_audit", "audit_events"];

/// The owner-owned `SECURITY DEFINER` functions of migration 050 that prune
/// and restore audit rows. The application role holds only `EXECUTE` on them.
pub const AUDIT_FUNCTIONS: [&str; 4] = [
    "audit_prune_rule_audit(bigint[])",
    "audit_prune_events(bigint[])",
    "audit_restore_truncate(text[], text)",
    "audit_restore_load(text, jsonb, text)",
];

/// Tables the application role may read but never write.
const OWNER_ONLY_TABLES: [&str; 3] = ["_sqlx_migrations", "audit_policy", "audit_restore_log"];

/// Columns the application role may set on INSERT, per audit table. `id` and
/// `occurred_at` come from the defaults, so a row cannot be placed in the past
/// or collide with a pruned id. A future migration that adds an app-written
/// column extends these lists.
const RULE_AUDIT_INSERT_COLUMNS: &str =
    "user_id, checklist_id, rule_id, field, from_value, to_value";
const AUDIT_EVENTS_INSERT_COLUMNS: &str = "user_id, action, outcome, asset_id, checklist_id, \
     stig_id, detail, source_ip, request_id, user_role";

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

/// Connection-class SQLSTATEs worth retrying. 08P01 (protocol violation) is permanent.
fn sqlstate_is_transient(code: &str) -> bool {
    matches!(
        code,
        "57P03" | "08000" | "08001" | "08003" | "08004" | "08006"
    )
}

/// True when retrying the owner step later can succeed: the database is not
/// reachable yet or the application role is not created yet.
pub fn is_transient(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if cause.is::<AppRoleMissing>() || cause.is::<OwnerStepLockHeld>() {
            return true;
        }
        match cause.downcast_ref::<sqlx::Error>() {
            Some(sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut) => true,
            Some(sqlx::Error::Database(d)) => d.code().is_some_and(|c| sqlstate_is_transient(&c)),
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

/// Inputs of one owner step.
#[derive(Debug, Clone)]
pub struct OwnerStep {
    /// Grant the test-only privileges, flag the database for `test` mode and
    /// open the restore window.
    pub test_routes: bool,
    /// Production refuses test routes.
    pub production: bool,
    /// `AUDIT_RETENTION_DAYS` as seen by this step; becomes the database's
    /// retention floor (0 with test routes).
    pub retention_floor_days: i64,
    /// `migrate_command`, `server_startup` or `server_self_migrate`.
    pub source: &'static str,
}

/// Run pending migrations as the owner role, then set the audit policy and
/// (re)apply the application role's grants. With `test_routes` on, also flags
/// the database for audit `test` maintenance mode (the owner must be a
/// superuser or hold `GRANT SET ON PARAMETER stig.audit_allow_test_mode`).
/// Test-only privileges are never granted, nor the flag set, when
/// `production` is true. A completed step writes a `db.migrate` system audit
/// event; a failure after the connection exists writes a failure event (#110).
pub async fn migrate_as_owner(
    owner_url: &str,
    app_database_url: &str,
    step: &OwnerStep,
) -> Result<()> {
    if step.production && step.test_routes {
        bail!("refusing to grant test-only audit privileges in production");
    }
    let app_role = app_role_from_url(app_database_url)?;
    let owner_opts = PgConnectOptions::from_str(owner_url)
        .map_err(|_| anyhow::anyhow!("DATABASE_MIGRATION_URL is not a valid PostgreSQL URL"))?;
    migrate_with(owner_opts, &app_role, step).await
}

/// Versions of the successfully applied migrations, empty before the first one.
pub async fn applied_versions(conn: &mut PgConnection) -> Result<Vec<i64>> {
    let present: bool =
        sqlx::query_scalar("SELECT pg_catalog.to_regclass('_sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    if !present {
        return Ok(Vec::new());
    }
    Ok(
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
            .fetch_all(&mut *conn)
            .await?,
    )
}

/// [`migrate_as_owner`] with parsed options (the tests pass their own). The
/// whole step runs under the [`crate::db_audit::OWNER_STEP_LOCK`] advisory lock.
async fn migrate_with(
    owner_opts: PgConnectOptions,
    app_role: &str,
    step: &OwnerStep,
) -> Result<()> {
    check_distinct_roles(owner_opts.get_username(), app_role)?;
    let stage = Stage::new("connect");
    let owner_pool = match PgPoolOptions::new()
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
        .context("connecting with DATABASE_MIGRATION_URL")
    {
        Ok(pool) => pool,
        Err(e) => {
            // No connection: there is nowhere to write an audit event.
            log_migrate_failure_fallback(stage.get(), &e, step.source);
            return Err(e);
        }
    };
    let mut lock_conn: Option<sqlx::pool::PoolConnection<sqlx::Postgres>> = None;
    let result = async {
        // Serialise the whole owner step across replicas: the grants, the
        // REVOKE and the test-mode flag all update shared catalog rows and
        // fail with "tuple concurrently updated" when run concurrently. The
        // session-level lock lives on a connection held out of the pool for
        // the whole step (the pool has a second one for the work), so it can
        // never be swapped for another session.
        stage.set("lock");
        lock_conn = Some(owner_pool.acquire().await?);
        if let Some(c) = lock_conn.as_mut() {
            lock_owner_step(c, OWNER_LOCK_WAIT).await?;
        }
        // Close the schema to the application role and refuse pre-planted
        // objects before anything unqualified runs as the owner.
        stage.set("prepare_schema");
        let mut conn = owner_pool.acquire().await?;
        prepare_owner_schema(&mut conn, app_role).await?;
        let before = applied_versions(&mut conn).await?;
        drop(conn);
        stage.set("migrations");
        sqlx::migrate!("./migrations").run(&owner_pool).await?;
        // The policy goes in before the grants so EXECUTE on the audit
        // functions is never granted while the floor is unset.
        stage.set("audit_policy");
        let mut conn = owner_pool.acquire().await?;
        let floor_previous =
            apply_audit_policy(&mut conn, step.retention_floor_days, step.test_routes).await?;
        drop(conn);
        stage.set("grants");
        let mut conn = owner_pool.acquire().await?;
        apply_app_grants(&mut conn, app_role, step.test_routes).await?;
        drop(conn);
        if step.test_routes {
            stage.set("test_flag");
            crate::db_audit::allow_test_maintenance(&owner_pool).await?;
        }
        stage.set("audit_record");
        let mut conn = owner_pool.acquire().await?;
        let after = applied_versions(&mut conn).await?;
        drop(conn);
        let applied: Vec<i64> = after
            .iter()
            .copied()
            .filter(|v| !before.contains(v))
            .collect();
        record_migrate_event(
            &owner_pool,
            "ok",
            migrate_detail(
                step.source,
                &applied,
                after.last().copied(),
                step.test_routes,
                effective_floor(step.retention_floor_days, step.test_routes),
                floor_previous,
            ),
        )
        .await
        .context("migrations applied but the db.migrate audit record could not be written")?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(e) = &result {
        // Before the lock is released; best effort, never replaces `e`.
        record_migrate_failure(&owner_pool, stage.get(), e, step.source).await;
    }
    // Return the lock connection first so `close()` ends the session, which
    // releases the lock.
    drop(lock_conn);
    owner_pool.close().await;
    result
}

/// The owner step's current stage, shared with the failure record. A mutex
/// (not a `Cell`) so the step's future stays `Send`.
struct Stage(std::sync::Mutex<&'static str>);

impl Stage {
    fn new(initial: &'static str) -> Self {
        Self(std::sync::Mutex::new(initial))
    }

    fn set(&self, stage: &'static str) {
        if let Ok(mut g) = self.0.lock() {
            *g = stage;
        }
    }

    fn get(&self) -> &'static str {
        self.0.lock().map_or("unknown", |g| *g)
    }
}

/// The floor the owner step stores: 0 with test routes, else the configured
/// number of days clamped to the column's range.
fn effective_floor(retention_floor_days: i64, test_routes: bool) -> i64 {
    if test_routes {
        0
    } else {
        retention_floor_days.clamp(0, 36500)
    }
}

/// Store the audit policy for this owner step: the retention floor
/// ([`effective_floor`]) and the restore window (open forever with test routes,
/// otherwise an `infinity` window left by a test-routes run is closed again;
/// an operator's finite window is left alone). Returns the previous floor when
/// it changed. Runs as the owner, the only role that can write `audit_policy`.
pub async fn apply_audit_policy(
    conn: &mut PgConnection,
    retention_floor_days: i64,
    test_routes: bool,
) -> Result<Option<i64>> {
    let floor = effective_floor(retention_floor_days, test_routes);
    let previous: i32 = sqlx::query_scalar("SELECT min_retain_days FROM public.audit_policy")
        .fetch_one(&mut *conn)
        .await
        .context("reading audit_policy")?;
    let changed = i64::from(previous) != floor;
    if changed {
        sqlx::query(
            "UPDATE public.audit_policy SET min_retain_days = $1, updated_at = pg_catalog.now()",
        )
        .bind(floor as i32)
        .execute(&mut *conn)
        .await?;
    }
    if test_routes {
        sqlx::query(
            "UPDATE public.audit_policy SET restore_allowed_until = 'infinity', \
                    updated_at = pg_catalog.now() \
             WHERE restore_allowed_until IS DISTINCT FROM 'infinity'",
        )
        .execute(&mut *conn)
        .await?;
    } else {
        sqlx::query(
            "UPDATE public.audit_policy SET restore_allowed_until = NULL, \
                    updated_at = pg_catalog.now() \
             WHERE restore_allowed_until = 'infinity'",
        )
        .execute(&mut *conn)
        .await?;
    }
    Ok(changed.then_some(i64::from(previous)))
}

/// Most violations listed in an event; each is cut to [`MAX_VIOLATION_CHARS`].
const MAX_VIOLATIONS_LISTED: usize = 20;
const MAX_VIOLATION_CHARS: usize = 200;
/// Longest wait for the `db.migrate` write and for a boundary event write.
const MIGRATE_EVENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const BOUNDARY_EVENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Detail of a completed `db.migrate` event. Identifiers and counts only.
pub(crate) fn migrate_detail(
    source: &str,
    applied: &[i64],
    schema_version: Option<i64>,
    test_routes: bool,
    floor_days: i64,
    floor_previous: Option<i64>,
) -> serde_json::Value {
    let mut d = serde_json::json!({
        "source": source,
        "appliedVersions": applied,
        "schemaVersion": schema_version,
        "testRoutes": test_routes,
        "retentionFloorDays": floor_days,
    });
    if let (Some(prev), Some(obj)) = (floor_previous, d.as_object_mut()) {
        obj.insert("retentionFloorPrevious".into(), prev.into());
    }
    d
}

/// The SQLSTATE of the first database error in the chain, if any.
fn sqlstate_of(err: &anyhow::Error) -> Option<String> {
    err.chain().find_map(|c| {
        c.downcast_ref::<sqlx::Error>()
            .and_then(|e| e.as_database_error())
            .and_then(|d| d.code())
            .map(|c| c.to_string())
    })
}

/// Detail of a failed `db.migrate` event. Never carries the error text, which
/// can quote object names or connection details.
pub(crate) fn migrate_failure_detail(
    source: &str,
    stage: &str,
    transient: bool,
    sqlstate: Option<&str>,
) -> serde_json::Value {
    let mut d = serde_json::json!({
        "source": source,
        "stage": stage,
        "errorClass": if transient { "transient" } else { "permanent" },
    });
    if let (Some(code), Some(obj)) = (sqlstate, d.as_object_mut()) {
        obj.insert("sqlstate".into(), code.into());
    }
    d
}

/// Detail of a boundary event: the capped violation list plus one flag
/// (`testRoutes` for a degraded start, `production` for a refusal).
pub(crate) fn boundary_detail(
    reason: &str,
    violations: &[String],
    flag: (&str, bool),
) -> serde_json::Value {
    let listed: Vec<String> = violations
        .iter()
        .take(MAX_VIOLATIONS_LISTED)
        .map(|v| v.chars().take(MAX_VIOLATION_CHARS).collect())
        .collect();
    serde_json::json!({
        "reason": reason,
        "violations": listed,
        "count": violations.len(),
        flag.0: flag.1,
    })
}

/// Write a system event synchronously with a timeout. The caller decides what
/// a failure means.
async fn record_event(
    pool: &PgPool,
    action: &'static str,
    outcome: &'static str,
    detail: serde_json::Value,
    wait: std::time::Duration,
) -> Result<()> {
    let write = crate::db_audit::record_system_now(
        pool,
        crate::db_audit::NewSystemEvent {
            action,
            outcome,
            stig_id: None,
            detail,
        },
    );
    match tokio::time::timeout(wait, write).await {
        Ok(r) => r,
        Err(_) => bail!("timed out writing the {action} audit event"),
    }
}

/// Write a `db.migrate` event now, returning a failure.
pub async fn record_migrate_event(
    pool: &PgPool,
    outcome: &'static str,
    detail: serde_json::Value,
) -> Result<()> {
    record_event(pool, "db.migrate", outcome, detail, MIGRATE_EVENT_TIMEOUT).await
}

/// Structured log line used when no audit row can be written.
fn log_migrate_failure_fallback(stage: &str, err: &anyhow::Error, source: &str) {
    tracing::error!(
        target: "audit",
        action = "db.migrate",
        outcome = "failure",
        source,
        stage,
        error_class = if is_transient(err) { "transient" } else { "permanent" },
        sqlstate = sqlstate_of(err).as_deref().unwrap_or(""),
        "owner step failed (no audit row written)"
    );
}

/// Record a failed owner step. Best effort: never returns an error and never
/// replaces the original one. Without a writable `audit_events` (missing, or
/// older than migration 045) the structured log line is the record.
pub async fn record_migrate_failure(
    pool: &PgPool,
    stage: &str,
    err: &anyhow::Error,
    source: &'static str,
) {
    let detail = migrate_failure_detail(
        source,
        stage,
        is_transient(err),
        sqlstate_of(err).as_deref(),
    );
    if record_migrate_event(pool, "failure", detail).await.is_err() {
        log_migrate_failure_fallback(stage, err, source);
    }
}

/// Startup policy for [`boundary_violations`] that first records a degraded
/// start. Production with violations is refused (and recorded) by the caller's
/// `refuse` path: the refusal event is written here too.
pub async fn enforce_boundary(
    pool: &PgPool,
    production: bool,
    test_routes: bool,
    violations: &[String],
) -> Result<()> {
    if !violations.is_empty() {
        if production {
            record_boundary_refusal_with(pool, "violations", production, violations).await;
        } else if let Err(e) = record_event(
            pool,
            "db.boundary_degraded",
            "partial",
            boundary_detail("violations", violations, ("testRoutes", test_routes)),
            BOUNDARY_EVENT_TIMEOUT,
        )
        .await
        {
            tracing::error!(
                target: "audit",
                action = "db.boundary_degraded",
                outcome = "partial",
                count = violations.len(),
                "audit write failed: {e:#}"
            );
        }
    }
    boundary_policy(production, violations)
}

/// Record that startup is refused for `reason`. Best effort; the refusal
/// stands whether or not the write succeeds.
pub async fn record_boundary_refusal(pool: &PgPool, reason: &'static str, production: bool) {
    record_boundary_refusal_with(pool, reason, production, &[]).await;
}

async fn record_boundary_refusal_with(
    pool: &PgPool,
    reason: &'static str,
    production: bool,
    violations: &[String],
) {
    if let Err(e) = record_event(
        pool,
        "db.boundary_refused",
        "rejected",
        boundary_detail(reason, violations, ("production", production)),
        BOUNDARY_EVENT_TIMEOUT,
    )
    .await
    {
        tracing::error!(
            target: "audit",
            action = "db.boundary_refused",
            outcome = "rejected",
            reason,
            count = violations.len(),
            "audit write failed: {e:#}"
        );
    }
}

/// Record a degraded start: a production start that still carries the owner
/// URL. Best effort.
pub async fn record_owner_url_on_server(pool: &PgPool, test_routes: bool) {
    if let Err(e) = record_event(
        pool,
        "db.boundary_degraded",
        "partial",
        boundary_detail("owner_url_on_server", &[], ("testRoutes", test_routes)),
        BOUNDARY_EVENT_TIMEOUT,
    )
    .await
    {
        tracing::error!(
            target: "audit",
            action = "db.boundary_degraded",
            outcome = "partial",
            reason = "owner_url_on_server",
            "audit write failed: {e:#}"
        );
    }
}

/// Finish a single-role self-migrate (development only): store the audit
/// policy and write the `db.migrate` event. `before` is [`applied_versions`]
/// taken ahead of the migrations.
pub async fn finish_self_migrate(pool: &PgPool, step: &OwnerStep, before: &[i64]) -> Result<()> {
    let mut conn = pool.acquire().await?;
    let floor_previous =
        apply_audit_policy(&mut conn, step.retention_floor_days, step.test_routes).await?;
    let after = applied_versions(&mut conn).await?;
    drop(conn);
    let applied: Vec<i64> = after
        .iter()
        .copied()
        .filter(|v| !before.contains(v))
        .collect();
    record_migrate_event(
        pool,
        "ok",
        migrate_detail(
            step.source,
            &applied,
            after.last().copied(),
            step.test_routes,
            effective_floor(step.retention_floor_days, step.test_routes),
            floor_previous,
        ),
    )
    .await
    .context("migrations applied but the db.migrate audit record could not be written")
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

/// Refuse when the application role, or any role it is a member of (even a
/// NOINHERIT membership, which `SET ROLE` can still assume), can `CREATE` in
/// the schema.
async fn ensure_no_schema_create(
    conn: &mut PgConnection,
    app_role: &str,
    schema: &Schema,
) -> Result<()> {
    let can_create: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r \
         WHERE pg_catalog.pg_has_role($1, r.oid, 'MEMBER') \
           AND pg_catalog.has_schema_privilege(r.oid, $2, 'CREATE'))",
    )
    .bind(app_role)
    .bind(&schema.raw)
    .fetch_one(&mut *conn)
    .await?;
    if can_create {
        bail!(
            "application role {app_role:?} can still CREATE in schema {} (it, or a role it is \
             a member of, holds CREATE: superuser, or a group membership?); revoke it from \
             that role before migrating",
            schema.quoted
        );
    }
    Ok(())
}

/// Before migrating: check the application role exists, that the owner may
/// revoke on the schema, revoke `CREATE` on it from PUBLIC and the application
/// role, and refuse to continue if the schema already holds a function,
/// operator, type or relation owned by a role other than the schema owner, the
/// owner role or a superuser (an object planted while the application role
/// could still `CREATE`). Refuses (after the revokes) when the application
/// role is a member of the schema owner, or can still `CREATE` through another
/// role. Only `pg_catalog`-qualified names are used.
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

    let app_is_superuser: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = $1")
            .bind(app_role)
            .fetch_one(&mut *conn)
            .await?;
    if app_is_superuser {
        bail!("application role {app_role:?} is a superuser; it must be a restricted role");
    }
    let member_of_owner: bool = sqlx::query_scalar(
        "SELECT pg_catalog.pg_has_role($1, n.nspowner, 'MEMBER') \
         FROM pg_catalog.pg_namespace n WHERE n.nspname = $2",
    )
    .bind(app_role)
    .bind(&schema.raw)
    .fetch_one(&mut *conn)
    .await?;
    if member_of_owner {
        bail!(
            "application role {app_role:?} is a member of the role that owns schema {}; it \
             could re-grant itself CREATE. Revoke that membership before migrating",
            schema.quoted
        );
    }
    // Objects owned by the owner login are exempt below, so the application
    // role must not be able to act as it either.
    let member_of_login: bool =
        sqlx::query_scalar("SELECT pg_catalog.pg_has_role($1, current_user, 'MEMBER')")
            .bind(app_role)
            .fetch_one(&mut *conn)
            .await?;
    if member_of_login {
        bail!(
            "application role {app_role:?} is a member of the owner role ({owner:?}); revoke \
             that membership before migrating"
        );
    }
    ensure_no_schema_create(conn, app_role, &schema).await?;

    // Deliberately not listed: pg_opclass, pg_opfamily (creating them needs a
    // superuser) and pg_ts_parser, pg_ts_template (no owner, superuser-only).
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
             FROM pg_catalog.pg_class c WHERE c.relnamespace = (SELECT oid FROM s) \
           UNION ALL \
           SELECT 'collation ' || k.collname::pg_catalog.text, k.collowner \
             FROM pg_catalog.pg_collation k WHERE k.collnamespace = (SELECT oid FROM s) \
           UNION ALL \
           SELECT 'conversion ' || v.conname::pg_catalog.text, v.conowner \
             FROM pg_catalog.pg_conversion v WHERE v.connamespace = (SELECT oid FROM s) \
           UNION ALL \
           SELECT 'text search configuration ' || tc.cfgname::pg_catalog.text, tc.cfgowner \
             FROM pg_catalog.pg_ts_config tc WHERE tc.cfgnamespace = (SELECT oid FROM s) \
           UNION ALL \
           SELECT 'text search dictionary ' || td.dictname::pg_catalog.text, td.dictowner \
             FROM pg_catalog.pg_ts_dict td WHERE td.dictnamespace = (SELECT oid FROM s) \
           UNION ALL \
           SELECT 'statistics ' || st.stxname::pg_catalog.text, st.stxowner \
             FROM pg_catalog.pg_statistic_ext st WHERE st.stxnamespace = (SELECT oid FROM s)) \
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
/// tables and the owner-only tables are revoked first, so the state converges.
/// On the audit tables the role gets `SELECT`, column-level `INSERT` and
/// `UPDATE (repeat_count, last_occurred_at)`, `USAGE, SELECT` on their
/// sequences and `EXECUTE` on [`AUDIT_FUNCTIONS`]; no `DELETE`, `TRUNCATE` or
/// sequence `UPDATE`. `test_routes` adds table-level `UPDATE` and `TRUNCATE` on
/// the audit tables (the E2E backdate and reset hooks); with it off, both are
/// revoked. The schema the grants act on is the one that holds `rule_audit`.
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

    let mut stmts = vec![
        format!("GRANT USAGE ON SCHEMA {schema} TO {role}"),
        format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA {schema} TO {role}"
        ),
        format!("GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA {schema} TO {role}"),
        // A table-level REVOKE also drops column-level privileges.
        format!("REVOKE ALL ON {audit} FROM {role}"),
        format!("GRANT SELECT ON {audit} TO {role}"),
        format!("GRANT INSERT ({RULE_AUDIT_INSERT_COLUMNS}) ON {schema}.rule_audit TO {role}"),
        format!("GRANT INSERT ({AUDIT_EVENTS_INSERT_COLUMNS}) ON {schema}.audit_events TO {role}"),
        format!(
            "GRANT UPDATE (repeat_count, last_occurred_at) ON {schema}.audit_events TO {role}"
        ),
    ];
    if test_routes {
        stmts.push(format!("GRANT UPDATE, TRUNCATE ON {audit} TO {role}"));
    }
    stmts.push(format!(
        "REVOKE ALL ON SEQUENCE {schema}.rule_audit_id_seq, {schema}.audit_events_id_seq, \
         {schema}.audit_restore_log_id_seq FROM {role}"
    ));
    stmts.push(format!(
        "GRANT USAGE, SELECT ON SEQUENCE {schema}.rule_audit_id_seq, \
         {schema}.audit_events_id_seq TO {role}"
    ));
    for table in OWNER_ONLY_TABLES {
        stmts.push(format!("REVOKE ALL ON {schema}.{table} FROM {role}"));
        stmts.push(format!("GRANT SELECT ON {schema}.{table} TO {role}"));
    }
    for function in AUDIT_FUNCTIONS {
        stmts.push(format!(
            "REVOKE ALL ON FUNCTION {schema}.{function} FROM PUBLIC"
        ));
        stmts.push(format!(
            "GRANT EXECUTE ON FUNCTION {schema}.{function} TO {role}"
        ));
    }

    let mut tx = conn.begin().await?;
    for stmt in &stmts {
        sqlx::query(stmt).execute(&mut *tx).await?;
    }
    tx.commit().await?;

    ensure_no_schema_create(conn, app_role, &prepared).await?;
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
                    WHERE c.oid = pg_catalog.to_regclass('rule_audit')), \
              fn AS (SELECT pg_catalog.to_regprocedure( \
                         pg_catalog.quote_ident((SELECT nspname FROM pg_catalog.pg_namespace \
                                                 WHERE oid = (SELECT ns FROM s))) || '.' || f.sig)::pg_catalog.oid \
                         AS oid \
                     FROM unnest($2::pg_catalog.text[]) AS f(sig) \
                     WHERE pg_catalog.to_regprocedure( \
                         pg_catalog.quote_ident((SELECT nspname FROM pg_catalog.pg_namespace \
                                                 WHERE oid = (SELECT ns FROM s))) || '.' || f.sig) \
                           IS NOT NULL) \
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
           AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles gr \
                       WHERE pg_catalog.pg_has_role(current_user, gr.oid, 'MEMBER') \
                         AND pg_catalog.has_schema_privilege(gr.oid, n.oid, 'CREATE')) \
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
         SELECT 'role holds DELETE on ' || t \
         FROM unnest(ARRAY['rule_audit', 'audit_events']) AS t \
         WHERE pg_catalog.has_table_privilege(current_user, t, 'DELETE') \
         UNION ALL \
         SELECT 'role holds TRUNCATE on ' || t || ' with test routes off' \
         FROM unnest(ARRAY['rule_audit', 'audit_events']) AS t \
         WHERE NOT $1 AND pg_catalog.has_table_privilege(current_user, t, 'TRUNCATE') \
         UNION ALL \
         SELECT 'role holds table-level INSERT on ' || t \
         FROM unnest(ARRAY['rule_audit', 'audit_events']) AS t \
         WHERE pg_catalog.has_table_privilege(current_user, t, 'INSERT') \
         UNION ALL \
         SELECT 'role holds UPDATE on sequence ' || pg_catalog.pg_get_serial_sequence(t, 'id') \
         FROM unnest(ARRAY['rule_audit', 'audit_events']) AS t \
         WHERE pg_catalog.has_sequence_privilege(current_user, \
                   pg_catalog.pg_get_serial_sequence(t, 'id'), 'UPDATE') \
         UNION ALL \
         SELECT 'role can write ' || t \
         FROM unnest(ARRAY['audit_policy', 'audit_restore_log']) AS t \
         WHERE pg_catalog.has_table_privilege(current_user, t, 'INSERT') \
            OR pg_catalog.has_table_privilege(current_user, t, 'UPDATE') \
            OR pg_catalog.has_table_privilege(current_user, t, 'DELETE') \
            OR pg_catalog.has_table_privilege(current_user, t, 'TRUNCATE') \
         UNION ALL \
         SELECT 'audit function ' || f.sig || ' is missing' \
         FROM unnest($2::pg_catalog.text[]) AS f(sig) \
         WHERE pg_catalog.to_regprocedure( \
                   pg_catalog.quote_ident((SELECT nspname FROM pg_catalog.pg_namespace \
                                           WHERE oid = (SELECT ns FROM s))) || '.' || f.sig) IS NULL \
         UNION ALL \
         SELECT 'audit function ' || p.proname || ' is not SECURITY DEFINER' \
         FROM pg_catalog.pg_proc p WHERE p.oid = ANY (SELECT oid FROM fn) AND NOT p.prosecdef \
         UNION ALL \
         SELECT 'audit function ' || p.proname || ' does not pin search_path to pg_catalog, pg_temp' \
         FROM pg_catalog.pg_proc p WHERE p.oid = ANY (SELECT oid FROM fn) \
           AND NOT ('search_path=pg_catalog, pg_temp' = ANY (COALESCE(p.proconfig, '{}'))) \
         UNION ALL \
         SELECT 'audit function ' || p.proname || ' is not owned by the owner of rule_audit' \
         FROM pg_catalog.pg_proc p WHERE p.oid = ANY (SELECT oid FROM fn) \
           AND p.proowner <> (SELECT c.relowner FROM pg_catalog.pg_class c \
                              WHERE c.oid = pg_catalog.to_regclass('rule_audit')) \
         UNION ALL \
         SELECT 'audit function ' || p.proname || ' is executable by PUBLIC' \
         FROM pg_catalog.pg_proc p WHERE p.oid = ANY (SELECT oid FROM fn) \
           AND pg_catalog.has_function_privilege('public', p.oid, 'EXECUTE') \
         UNION ALL \
         SELECT 'role can INSERT the ' || col || ' column of ' || t \
         FROM unnest(ARRAY['rule_audit', 'audit_events']) AS t, \
              unnest(ARRAY['id', 'occurred_at']) AS col \
         WHERE pg_catalog.has_column_privilege(current_user, t, col, 'INSERT') \
         UNION ALL \
         SELECT 'audit restore window is held open (infinity) with test routes off' \
         FROM audit_policy WHERE NOT $1 AND restore_allowed_until = 'infinity' \
         UNION ALL \
         SELECT 'audit restore window is open for more than 24 hours' \
         FROM audit_policy WHERE NOT $1 AND restore_allowed_until <> 'infinity' \
           AND restore_allowed_until > pg_catalog.now() + interval '24 hours' \
         UNION ALL \
         SELECT 'audit retention floor is 0 with test routes off' \
         FROM audit_policy WHERE NOT $1 AND min_retain_days = 0 \
         UNION ALL \
         SELECT 'audit_tables_guard() is not revision 4 (owner-gated maintenance modes)' \
         FROM pg_catalog.pg_proc p \
         WHERE p.oid = 'audit_tables_guard()'::pg_catalog.regprocedure \
           AND position('as_owner' IN p.prosrc) = 0 \
         UNION ALL \
         SELECT 'audit_tables_guard() does not pin search_path to pg_catalog, pg_temp' \
         FROM pg_catalog.pg_proc p \
         WHERE p.oid = 'audit_tables_guard()'::pg_catalog.regprocedure \
           AND NOT ('search_path=pg_catalog, pg_temp' = ANY (COALESCE(p.proconfig, '{}')))",
    )
    .bind(test_routes)
    .bind(
        AUDIT_FUNCTIONS.to_vec(),
    )
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

/// [`verify_migrations`], recording a `db.boundary_refused` event (reason
/// `migrations_unverified`, best effort) before returning its error.
pub async fn verify_or_record_refusal(pool: &PgPool, production: bool) -> Result<()> {
    if let Err(e) = verify_migrations(pool).await {
        record_boundary_refusal(pool, "migrations_unverified", production).await;
        return Err(e);
    }
    Ok(())
}

/// Warning for an owner credential present on the serving process in production.
pub fn owner_url_on_server_warning(production: bool, has_owner_url: bool) -> Option<&'static str> {
    (production && has_owner_url).then_some(
        "DATABASE_MIGRATION_URL is set on the serving process: code execution in the server \
         could read the owner credential. Prefer running `migrate` as a separate job.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{
        allow_audit_test_mode, app_role_pool, open_audit_restore_window, seed_user,
        set_audit_retention_floor, temp_role,
    };
    use sqlx::PgPool;

    fn step(test_routes: bool) -> OwnerStep {
        OwnerStep {
            test_routes,
            production: false,
            retention_floor_days: 365,
            source: "migrate_command",
        }
    }

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

    const TRANSIENT_CODES: [&str; 6] = ["57P03", "08000", "08001", "08003", "08004", "08006"];
    const PERMANENT_CODES: [&str; 6] = ["08P01", "55P03", "42501", "28P01", "3D000", ""];

    #[test]
    fn sqlstate_classification() {
        for c in TRANSIENT_CODES {
            assert!(sqlstate_is_transient(c), "{c}");
        }
        for c in PERMANENT_CODES {
            assert!(!sqlstate_is_transient(c), "{c:?}");
        }
    }

    #[test]
    fn owner_url_on_server_warning_truth_table() {
        for (p, o) in [(false, false), (false, true), (true, false)] {
            assert!(owner_url_on_server_warning(p, o).is_none());
        }
        let w = owner_url_on_server_warning(true, true).unwrap();
        assert!(w.contains("DATABASE_MIGRATION_URL") && w.contains("migrate"));
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
            &OwnerStep {
                production: true,
                ..step(true)
            },
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
        // `migration` mode is honoured only for the owner: the app role cannot
        // use it to rewrite a collapsed denial (null or lower its counters).
        sqlx::query(
            "INSERT INTO audit_events (user_id, action, outcome, repeat_count, last_occurred_at) \
             VALUES ('u1', 'checklist.save', 'denied', 3, now())",
        )
        .execute(&pool)
        .await
        .unwrap();
        for stmt in [
            "UPDATE audit_events SET last_occurred_at = NULL, repeat_count = 1 WHERE outcome = 'denied'",
            "UPDATE audit_events SET repeat_count = repeat_count + 5 WHERE outcome = 'denied'",
            "UPDATE audit_events SET last_occurred_at = occurred_at WHERE outcome = 'denied'",
            "UPDATE audit_events SET outcome = 'denied'",
        ] {
            let mut tx = app.pool.begin().await.unwrap();
            crate::db_audit::set_maintenance(&mut tx, "migration")
                .await
                .unwrap();
            let err = sqlx::query(stmt).execute(&mut *tx).await.expect_err(stmt);
            assert_eq!(code(&err).as_deref(), Some("42501"), "{stmt}: {err}");
        }
        // With the mode still set, the legitimate collapse goes through.
        let mut tx = app.pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "migration")
            .await
            .unwrap();
        let n = sqlx::query(
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = now() \
             WHERE outcome = 'denied'",
        )
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
        assert_eq!(n, 1);
        tx.commit().await.unwrap();
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_app_role_cannot_age_a_collapsed_row_to_prune_it(pool: PgPool) {
        seed_user(&pool, "u1").await;
        set_audit_retention_floor(&pool, 30).await;
        sqlx::query(
            "INSERT INTO audit_events (occurred_at, last_occurred_at, user_id, action, outcome, repeat_count) \
             VALUES (now() - interval '40 days', now() - interval '1 day', 'u1', 'a', 'denied', 3)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let id: i64 = sqlx::query_scalar("SELECT id FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        let app = app_role_pool(&pool, false).await;
        let mut tx = app.pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "migration")
            .await
            .unwrap();
        let err = sqlx::query("UPDATE audit_events SET last_occurred_at = NULL")
            .execute(&mut *tx)
            .await
            .expect_err("aging update");
        assert_eq!(code(&err).as_deref(), Some("42501"), "{err}");
        drop(tx);
        let r = sqlx::query_scalar::<_, i64>("SELECT audit_prune_events($1::bigint[])")
            .bind(vec![id])
            .fetch_one(&app.pool)
            .await;
        assert_eq!(code_of(r).as_deref(), Some("42501"));
        let (repeat, young): (i32, bool) = sqlx::query_as(
            "SELECT repeat_count, last_occurred_at > now() - interval '2 days' FROM audit_events",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((repeat, young), (3, true));
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn maintenance_modes_are_refused_for_a_non_owner_even_with_the_privilege(pool: PgPool) {
        seed_user(&pool, "u1").await;
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r1','status')")
            .execute(&pool).await.unwrap();
        let app = app_role_pool(&pool, false).await;
        exec(
            &pool,
            &format!(
                "GRANT DELETE, TRUNCATE, UPDATE ON rule_audit, audit_events TO \"{}\"",
                app.name
            ),
        )
        .await;
        for (mode, stmt) in [
            ("retention", "DELETE FROM rule_audit"),
            ("restore", "TRUNCATE rule_audit, audit_events"),
            ("migration", "UPDATE rule_audit SET field = 'x'"),
        ] {
            let mut tx = app.pool.begin().await.unwrap();
            match mode {
                "retention" => crate::audit_retention::declare_retention_delete(&mut tx)
                    .await
                    .unwrap(),
                m => crate::db_audit::set_maintenance(&mut tx, m).await.unwrap(),
            }
            let err = sqlx::query(stmt).execute(&mut *tx).await.expect_err(stmt);
            assert_eq!(code(&err).as_deref(), Some("42501"), "{stmt}: {err}");
            assert!(
                err.to_string().contains("honoured only for the owner"),
                "{stmt}: {err}"
            );
        }
        // In a flagged database `restore` still fails for the app role, while
        // the DB-flag-gated `test` mode works for any role.
        allow_audit_test_mode(&pool).await;
        let mut tx = app.pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "restore")
            .await
            .unwrap();
        let err = sqlx::query("TRUNCATE rule_audit, audit_events")
            .execute(&mut *tx)
            .await
            .expect_err("restore truncate");
        assert_eq!(code(&err).as_deref(), Some("42501"), "{err}");
        drop(tx);
        let mut tx = app.pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "test")
            .await
            .unwrap();
        sqlx::query("TRUNCATE rule_audit, audit_events")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn restore_load_rejects_out_of_range_ids_and_closes_a_finite_window(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let app = app_role_pool(&pool, false).await;
        exec(
            &pool,
            "UPDATE audit_policy SET restore_allowed_until = now() + interval '1 hour'",
        )
        .await;
        let row = |id: i64| {
            serde_json::json!([{
                "id": id, "occurred_at": "2025-01-01T00:00:00Z", "user_id": "u1",
                "action": "a", "outcome": "ok", "asset_id": null, "checklist_id": null,
                "stig_id": null, "detail": {}, "source_ip": null, "request_id": null,
                "user_role": null, "repeat_count": 1, "last_occurred_at": null
            }])
        };
        for bad in [0_i64, -5, i64::MAX - 10] {
            let r = sqlx::query("SELECT audit_restore_load('audit_events', $1, 't')")
                .bind(row(bad))
                .execute(&app.pool)
                .await;
            assert_eq!(code_of(r).as_deref(), Some("22023"), "id {bad}");
        }
        // A rolled-back load leaves the window and the table untouched.
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        let n: i64 = sqlx::query_scalar("SELECT audit_restore_load('audit_events', $1, 't')")
            .bind(row(7))
            .fetch_one(&app.pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
        let open: bool =
            sqlx::query_scalar("SELECT restore_allowed_until IS NOT NULL FROM audit_policy")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!open, "a finite window closes after the audit_events load");
        // An infinity window (test routes) stays open.
        let mut tx = pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "restore")
            .await
            .unwrap();
        exec_tx(&mut tx, "TRUNCATE audit_events").await;
        tx.commit().await.unwrap();
        open_audit_restore_window(&pool).await;
        sqlx::query("SELECT audit_restore_load('audit_events', $1, 't')")
            .bind(row(8))
            .execute(&app.pool)
            .await
            .unwrap();
        let open: bool =
            sqlx::query_scalar("SELECT restore_allowed_until = 'infinity' FROM audit_policy")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(open);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_window_cap_applies_at_set_time_and_at_use_time(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        let call = "SELECT audit_restore_truncate(ARRAY['rule_audit', 'audit_events'], 't')";
        // Set time: the owner cannot set more than 24 hours ahead.
        let r = sqlx::query(
            "UPDATE audit_policy SET restore_allowed_until = now() + interval '30 days'",
        )
        .execute(&pool)
        .await;
        assert_eq!(code_of(r).as_deref(), Some("22023"));
        exec(
            &pool,
            "UPDATE audit_policy SET restore_allowed_until = now() + interval '1 hour'",
        )
        .await;
        // Use time: just under 24h opens, just over (set around the trigger) refuses.
        set_window_unchecked(&pool, "23 hours").await;
        sqlx::query(call).execute(&app.pool).await.unwrap();
        set_window_unchecked(&pool, "25 hours").await;
        let r = sqlx::query(call).execute(&app.pool).await;
        assert_eq!(code_of(r).as_deref(), Some("SV001"));
        // updated_at is stamped by the trigger.
        let fresh: bool =
            sqlx::query_scalar("SELECT updated_at > now() - interval '1 minute' FROM audit_policy")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(fresh);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn restore_truncate_refuses_an_inheriting_child_outside_the_list(pool: PgPool) {
        seed_user(&pool, "u1").await;
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r1','status')")
            .execute(&pool)
            .await
            .unwrap();
        exec(
            &pool,
            "CREATE TABLE public.child_t () INHERITS (rule_audit)",
        )
        .await;
        open_audit_restore_window(&pool).await;
        let app = app_role_pool(&pool, false).await;
        let r =
            sqlx::query("SELECT audit_restore_truncate(ARRAY['rule_audit', 'audit_events'], 't')")
                .execute(&app.pool)
                .await;
        assert_eq!(code_of(r).as_deref(), Some("42501"));
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "nothing was truncated");
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn restore_truncate_refuses_a_cascade_into_an_unlisted_table(pool: PgPool) {
        seed_user(&pool, "u1").await;
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r1','status')")
            .execute(&pool)
            .await
            .unwrap();
        exec(
            &pool,
            "CREATE TABLE public.refs_audit (r bigint REFERENCES rule_audit(id))",
        )
        .await;
        open_audit_restore_window(&pool).await;
        let app = app_role_pool(&pool, false).await;
        let r =
            sqlx::query("SELECT audit_restore_truncate(ARRAY['rule_audit', 'audit_events'], 't')")
                .execute(&app.pool)
                .await;
        assert_eq!(code_of(r).as_deref(), Some("42501"));
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "nothing was truncated");
        // Listing the referencing table makes the call acceptable.
        sqlx::query(
            "SELECT audit_restore_truncate(ARRAY['rule_audit', 'audit_events', 'refs_audit'], 't')",
        )
        .execute(&app.pool)
        .await
        .unwrap();
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn restore_truncate_never_truncates_what_the_caller_could_not(pool: PgPool) {
        open_audit_restore_window(&pool).await;
        let app = app_role_pool(&pool, false).await;
        // Created after the grants, so the app role has no privilege on it.
        exec(&pool, "CREATE TABLE public.owner_only_t (x int)").await;
        exec(&pool, "INSERT INTO public.owner_only_t VALUES (1)").await;
        // A real login: SET SESSION AUTHORIZATION makes session_user the app role.
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query(&format!("SET SESSION AUTHORIZATION \"{}\"", app.name))
            .execute(&mut *conn)
            .await
            .unwrap();
        let r = sqlx::query(
            "SELECT audit_restore_truncate(ARRAY['rule_audit', 'audit_events', 'owner_only_t'], 't')",
        )
        .execute(&mut *conn)
        .await;
        assert_eq!(code_of(r).as_deref(), Some("42501"));
        // With the privilege the same call works.
        exec(
            &pool,
            &format!("GRANT TRUNCATE ON public.owner_only_t TO \"{}\"", app.name),
        )
        .await;
        sqlx::query(
            "SELECT audit_restore_truncate(ARRAY['rule_audit', 'audit_events', 'owner_only_t'], 't')",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query("RESET SESSION AUTHORIZATION")
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn app_role_can_do_its_normal_audit_work(pool: PgPool) {
        seed_user(&pool, "u1").await;
        set_audit_retention_floor(&pool, 0).await;
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
        // Retention through the owner function: a row past the floor goes.
        sqlx::query(
            "INSERT INTO rule_audit (occurred_at, user_id, checklist_id, rule_id, field) \
             VALUES (now() - interval '10 days', 'u1', 'c', 'old', 'status')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let old: i64 = sqlx::query_scalar("SELECT id FROM rule_audit WHERE rule_id = 'old'")
            .fetch_one(&pool)
            .await
            .unwrap();
        let pruned: i64 = sqlx::query_scalar("SELECT audit_prune_rule_audit($1::bigint[])")
            .bind(vec![old])
            .fetch_one(&app.pool)
            .await
            .unwrap();
        assert_eq!(pruned, 1);
        // Restore through the owner functions, inside an open window.
        open_audit_restore_window(&pool).await;
        sqlx::query("SELECT audit_restore_truncate(ARRAY['rule_audit', 'audit_events'], 'tester')")
            .execute(&app.pool)
            .await
            .unwrap();
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn app_role_can_use_the_saml_replay_cache(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        let id = "a".repeat(64);
        let ins = "INSERT INTO saml_seen_ids (id_sha256, kind, expires_at) \
                   VALUES ($1, 'assertion', now() + interval '5 minutes') ON CONFLICT DO NOTHING";
        let n = sqlx::query(ins).bind(&id).execute(&app.pool).await.unwrap();
        assert_eq!(n.rows_affected(), 1);
        let n = sqlx::query(ins).bind(&id).execute(&app.pool).await.unwrap();
        assert_eq!(n.rows_affected(), 0);
        sqlx::query("DELETE FROM saml_seen_ids WHERE expires_at < now()")
            .execute(&app.pool)
            .await
            .unwrap();
        app.cleanup(&pool).await;
    }

    /// Run `stmts` (each in its own transaction, in the given maintenance mode
    /// where one is named) as the app role and expect 42501 for every one.
    async fn expect_denied(app: &PgPool, stmts: &[(&str, &str)]) {
        for (mode, stmt) in stmts {
            let mut tx = app.begin().await.unwrap();
            match *mode {
                "retention" => crate::audit_retention::declare_retention_delete(&mut tx)
                    .await
                    .unwrap(),
                "" => {}
                m => crate::db_audit::set_maintenance(&mut tx, m).await.unwrap(),
            }
            let err = sqlx::query(stmt).execute(&mut *tx).await.expect_err(stmt);
            assert_eq!(code(&err).as_deref(), Some("42501"), "{stmt}: {err}");
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn app_role_cannot_delete_truncate_reinsert_or_setval(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let app = app_role_pool(&pool, false).await;
        expect_denied(
            &app.pool,
            &[
                ("retention", "DELETE FROM rule_audit"),
                ("retention", "DELETE FROM audit_events"),
                ("restore", "TRUNCATE rule_audit, audit_events"),
                ("restore", "TRUNCATE users CASCADE"),
                (
                    "",
                    "INSERT INTO rule_audit (id, user_id, checklist_id, rule_id, field) \
                     VALUES (1, 'u1', 'c', 'r', 'f')",
                ),
                (
                    "",
                    "INSERT INTO rule_audit (occurred_at, user_id, checklist_id, rule_id, field) \
                     VALUES (now() - interval '1 year', 'u1', 'c', 'r', 'f')",
                ),
                (
                    "",
                    "INSERT INTO audit_events (id, user_id, action, outcome) \
                     VALUES (1, 'u1', 'a', 'ok')",
                ),
                (
                    "",
                    "INSERT INTO audit_events (occurred_at, user_id, action, outcome) \
                     VALUES (now() - interval '1 year', 'u1', 'a', 'ok')",
                ),
                ("", "SELECT setval('rule_audit_id_seq', 1)"),
                ("", "SELECT setval('audit_events_id_seq', 1)"),
                ("", "ALTER SEQUENCE rule_audit_id_seq RESTART"),
                ("", "ALTER SEQUENCE audit_events_id_seq RESTART"),
                ("", "UPDATE audit_policy SET min_retain_days = 0"),
                (
                    "",
                    "UPDATE audit_policy SET restore_allowed_until = 'infinity'",
                ),
                (
                    "",
                    "INSERT INTO audit_restore_log (step, target_table, caller, row_count) \
                     VALUES ('load', 'rule_audit', 'x', 0)",
                ),
                ("", "DELETE FROM audit_restore_log"),
                (
                    "",
                    "CREATE OR REPLACE FUNCTION public.audit_prune_rule_audit(p_ids bigint[]) \
                     RETURNS bigint LANGUAGE sql AS 'SELECT 0::bigint'",
                ),
                (
                    "",
                    "CREATE OR REPLACE FUNCTION public.audit_restore_truncate(p_tables text[]) \
                     RETURNS void LANGUAGE sql AS 'SELECT'",
                ),
            ],
        )
        .await;
        // Normal inserts still draw from the sequences.
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r1','status')")
            .execute(&app.pool).await.unwrap();
        sqlx::query("INSERT INTO audit_events (user_id, action, outcome) VALUES ('u1','checklist.save','ok')")
            .execute(&app.pool).await.unwrap();
        app.cleanup(&pool).await;
    }

    fn code_of(r: Result<impl std::fmt::Debug, sqlx::Error>) -> Option<String> {
        code(&r.expect_err("expected a database error"))
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_function_refuses_rows_younger_than_the_floor(pool: PgPool) {
        seed_user(&pool, "u1").await;
        set_audit_retention_floor(&pool, 30).await;
        let app = app_role_pool(&pool, false).await;
        for (rule, days) in [("old", 40), ("young", 10)] {
            sqlx::query(
                "INSERT INTO rule_audit (occurred_at, user_id, checklist_id, rule_id, field) \
                 VALUES (now() - ($1 || ' days')::interval, 'u1', 'c', $2, 'status')",
            )
            .bind(days.to_string())
            .bind(rule)
            .execute(&pool)
            .await
            .unwrap();
        }
        let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM rule_audit ORDER BY occurred_at")
            .fetch_all(&pool)
            .await
            .unwrap();
        let (old, young) = (ids[0], ids[1]);
        let r = sqlx::query_scalar::<_, i64>("SELECT audit_prune_rule_audit($1::bigint[])")
            .bind(vec![old, young])
            .fetch_one(&app.pool)
            .await;
        assert_eq!(code_of(r).as_deref(), Some("42501"));
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 2);
        let n: i64 = sqlx::query_scalar("SELECT audit_prune_rule_audit($1::bigint[])")
            .bind(vec![old])
            .fetch_one(&app.pool)
            .await
            .unwrap();
        assert_eq!(n, 1);

        // audit_events: the age is the later of occurred_at and last_occurred_at.
        sqlx::query(
            "INSERT INTO audit_events (occurred_at, last_occurred_at, user_id, action, outcome) \
             VALUES (now() - interval '40 days', now() - interval '5 days', 'u1', 'a', 'denied')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let ev: i64 = sqlx::query_scalar("SELECT id FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        let r = sqlx::query_scalar::<_, i64>("SELECT audit_prune_events($1::bigint[])")
            .bind(vec![ev])
            .fetch_one(&app.pool)
            .await;
        assert_eq!(code_of(r).as_deref(), Some("42501"));
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn restore_functions_need_the_owner_window_and_an_empty_table(pool: PgPool) {
        const TRUNCATE: &str = "SELECT audit_restore_truncate($1::text[], 'tester')";
        seed_user(&pool, "u1").await;
        let app = app_role_pool(&pool, false).await;
        let both = vec!["rule_audit".to_string(), "audit_events".to_string()];
        let truncate = |tables: Vec<String>| {
            let pool = app.pool.clone();
            async move { sqlx::query(TRUNCATE).bind(tables).execute(&pool).await }
        };

        // Closed (NULL) and expired windows refuse with SV001.
        let r = truncate(both.clone()).await;
        assert_eq!(code_of(r).as_deref(), Some("SV001"));
        exec(
            &pool,
            "UPDATE audit_policy SET restore_allowed_until = now() - interval '1 minute'",
        )
        .await;
        let r = truncate(both.clone()).await;
        assert_eq!(code_of(r).as_deref(), Some("SV001"));
        let r = sqlx::query("SELECT audit_restore_load('rule_audit', '[]'::jsonb, 't')")
            .execute(&app.pool)
            .await;
        assert_eq!(code_of(r).as_deref(), Some("SV001"));

        // A finite window beyond 24 hours counts as closed.
        set_window_unchecked(&pool, "48 hours").await;
        let r = truncate(both.clone()).await;
        assert_eq!(code_of(r).as_deref(), Some("SV001"));

        // Open window.
        exec(
            &pool,
            "UPDATE audit_policy SET restore_allowed_until = now() + interval '1 hour'",
        )
        .await;
        for _ in 0..3 {
            sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r1','status')")
                .execute(&pool).await.unwrap();
        }
        let rows: serde_json::Value =
            sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM rule_audit a")
                .fetch_one(&pool)
                .await
                .unwrap();
        // A list with a table outside the allowed set is refused.
        let mut bad = both.clone();
        bad.push("_sqlx_migrations".to_string());
        let r = truncate(bad).await;
        assert_eq!(code_of(r).as_deref(), Some("42501"));
        let r = truncate(vec!["rule_audit".to_string()]).await;
        assert_eq!(code_of(r).as_deref(), Some("22023"));
        exec(&pool, "SELECT setval('rule_audit_id_seq', 500)").await;
        truncate(both.clone()).await.unwrap();
        let ledger: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit_restore_log WHERE step = 'truncate'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(ledger, 2);
        let removed: i64 = sqlx::query_scalar(
            "SELECT row_count FROM audit_restore_log \
             WHERE step = 'truncate' AND target_table = 'rule_audit'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(removed, 3);
        let actors: Vec<Option<String>> =
            sqlx::query_scalar("SELECT DISTINCT actor FROM audit_restore_log")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(actors, [Some("tester".to_string())]);

        let n: i64 = sqlx::query_scalar("SELECT audit_restore_load('rule_audit', $1, 'tester')")
            .bind(&rows)
            .fetch_one(&app.pool)
            .await
            .unwrap();
        assert_eq!(n, 3);
        // The sequence never moves backwards: ids were 1..3, it stood at 500.
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r2','status')")
            .execute(&app.pool).await.unwrap();
        let next: i64 = sqlx::query_scalar("SELECT max(id) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(next, 501);
        // Audit rows load only into an empty table.
        let r = sqlx::query("SELECT audit_restore_load('rule_audit', $1, 'tester')")
            .bind(&rows)
            .execute(&app.pool)
            .await;
        assert_eq!(code_of(r).as_deref(), Some("SV002"));
        let r = sqlx::query("SELECT audit_restore_load('users', '[]'::jsonb, 't')")
            .execute(&app.pool)
            .await;
        assert_eq!(code_of(r).as_deref(), Some("22023"));
        let loads: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_restore_log WHERE step = 'load' AND sequence_after = 500",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(loads, 1);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn execute_on_audit_functions_is_not_public(pool: PgPool) {
        // Another role, never granted by the owner step.
        let other = temp_role(&pool, "np_").await;
        for call in [
            "SELECT audit_prune_rule_audit(ARRAY[]::bigint[])",
            "SELECT audit_prune_events(ARRAY[]::bigint[])",
            "SELECT audit_restore_truncate(ARRAY['rule_audit', 'audit_events'], 't')",
            "SELECT audit_restore_load('rule_audit', '[]'::jsonb, 't')",
        ] {
            let mut tx = pool.begin().await.unwrap();
            exec_tx(&mut tx, &format!("SET LOCAL ROLE \"{}\"", other.name)).await;
            let err = sqlx::query(call).execute(&mut *tx).await.expect_err(call);
            assert_eq!(code(&err).as_deref(), Some("42501"), "{call}: {err}");
        }
    }

    /// Set the restore window to now() + `interval` bypassing the policy
    /// trigger's 24-hour cap (disabled for this transaction only).
    async fn set_window_unchecked(pool: &PgPool, interval: &str) {
        let mut tx = pool.begin().await.unwrap();
        exec_tx(
            &mut tx,
            "ALTER TABLE audit_policy DISABLE TRIGGER audit_policy_guard",
        )
        .await;
        exec_tx(
            &mut tx,
            &format!(
                "UPDATE audit_policy SET restore_allowed_until = now() + interval '{interval}'"
            ),
        )
        .await;
        exec_tx(
            &mut tx,
            "ALTER TABLE audit_policy ENABLE TRIGGER audit_policy_guard",
        )
        .await;
        tx.commit().await.unwrap();
    }

    async fn exec_tx(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, sql: &str) {
        sqlx::query(sql).execute(&mut **tx).await.expect(sql);
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
        // TRUNCATE follows the flag too; column-level INSERT survives it.
        let priv_of = |sql: &'static str| {
            let pool = pool.clone();
            let name = app.name.clone();
            async move {
                sqlx::query_scalar::<_, bool>(sql)
                    .bind(name)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }
        };
        assert!(!priv_of("SELECT has_table_privilege($1, 'rule_audit', 'TRUNCATE')").await);
        assert!(!priv_of("SELECT has_table_privilege($1, 'audit_events', 'DELETE')").await);
        assert!(!priv_of("SELECT has_table_privilege($1, 'rule_audit', 'INSERT')").await);
        assert!(
            priv_of("SELECT has_column_privilege($1, 'rule_audit', 'rule_id', 'INSERT')").await
        );
        assert!(!priv_of("SELECT has_column_privilege($1, 'rule_audit', 'id', 'INSERT')").await);
        assert!(
            !priv_of("SELECT has_column_privilege($1, 'audit_events', 'occurred_at', 'INSERT')")
                .await
        );
        let mut conn = pool.acquire().await.unwrap();
        apply_app_grants(&mut conn, &app.name, true).await.unwrap();
        drop(conn);
        assert!(priv_of("SELECT has_table_privilege($1, 'rule_audit', 'TRUNCATE')").await);
        assert!(priv_of("SELECT has_table_privilege($1, 'audit_events', 'TRUNCATE')").await);
        assert!(
            priv_of("SELECT has_column_privilege($1, 'rule_audit', 'rule_id', 'INSERT')").await
        );
        let mut conn = pool.acquire().await.unwrap();
        apply_app_grants(&mut conn, &app.name, false).await.unwrap();
        drop(conn);
        assert!(!priv_of("SELECT has_table_privilege($1, 'rule_audit', 'TRUNCATE')").await);
        assert!(
            priv_of("SELECT has_column_privilege($1, 'rule_audit', 'rule_id', 'INSERT')").await
        );
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_audit_policy_converges(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let read = |sql: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, String>(sql)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }
        };
        const FLOOR: &str = "SELECT min_retain_days::text FROM audit_policy";
        const WINDOW: &str =
            "SELECT COALESCE(restore_allowed_until::text, 'closed') FROM audit_policy";
        // Defaults: floor 365, window closed. Lowering reports the previous value.
        assert_eq!(read(FLOOR).await, "365");
        assert_eq!(
            apply_audit_policy(&mut conn, 365, false).await.unwrap(),
            None
        );
        assert_eq!(
            apply_audit_policy(&mut conn, 30, false).await.unwrap(),
            Some(365)
        );
        assert_eq!(
            apply_audit_policy(&mut conn, 30, false).await.unwrap(),
            None
        );
        assert_eq!(read(FLOOR).await, "30");
        assert_eq!(read(WINDOW).await, "closed");
        // Out-of-range values are clamped.
        apply_audit_policy(&mut conn, -5, false).await.unwrap();
        assert_eq!(read(FLOOR).await, "0");
        apply_audit_policy(&mut conn, 10_000_000, false)
            .await
            .unwrap();
        assert_eq!(read(FLOOR).await, "36500");
        // Test routes: floor 0 and an open window.
        assert_eq!(
            apply_audit_policy(&mut conn, 365, true).await.unwrap(),
            Some(36500)
        );
        assert_eq!(read(FLOOR).await, "0");
        assert_eq!(read(WINDOW).await, "infinity");
        // Back to production: the infinity window closes again.
        apply_audit_policy(&mut conn, 365, false).await.unwrap();
        assert_eq!(read(FLOOR).await, "365");
        assert_eq!(read(WINDOW).await, "closed");
        // An operator's finite window is left alone.
        sqlx::query("UPDATE audit_policy SET restore_allowed_until = now() + interval '1 hour'")
            .execute(&pool)
            .await
            .unwrap();
        apply_audit_policy(&mut conn, 365, false).await.unwrap();
        assert_ne!(read(WINDOW).await, "closed");
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
            "role holds DELETE on rule_audit",
            "role holds TRUNCATE on audit_events with test routes off",
            "role holds table-level INSERT on rule_audit",
            "role holds UPDATE on sequence",
            "role can write audit_policy",
            "role can write audit_restore_log",
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

        // New privileges on the audit tables, sequences and functions.
        for (grant, revoke, needle) in [
            (
                "GRANT DELETE ON rule_audit TO {q}",
                "REVOKE DELETE ON rule_audit FROM {q}",
                "role holds DELETE on rule_audit",
            ),
            (
                "GRANT INSERT ON audit_events TO {q}",
                "REVOKE INSERT ON audit_events FROM {q}",
                "role holds table-level INSERT on audit_events",
            ),
            (
                "GRANT UPDATE ON SEQUENCE audit_events_id_seq TO {q}",
                "REVOKE UPDATE ON SEQUENCE audit_events_id_seq FROM {q}",
                "role holds UPDATE on sequence public.audit_events_id_seq",
            ),
            (
                "GRANT UPDATE ON audit_policy TO {q}",
                "REVOKE UPDATE ON audit_policy FROM {q}",
                "role can write audit_policy",
            ),
            (
                "GRANT TRUNCATE ON audit_restore_log TO {q}",
                "REVOKE TRUNCATE ON audit_restore_log FROM {q}",
                "role can write audit_restore_log",
            ),
            (
                "ALTER FUNCTION audit_prune_events(bigint[]) SECURITY INVOKER",
                "ALTER FUNCTION audit_prune_events(bigint[]) SECURITY DEFINER",
                "audit function audit_prune_events is not SECURITY DEFINER",
            ),
            (
                "ALTER FUNCTION audit_restore_load(text, jsonb, text) RESET search_path",
                "ALTER FUNCTION audit_restore_load(text, jsonb, text) SET search_path = pg_catalog, pg_temp",
                "audit function audit_restore_load does not pin search_path",
            ),
            (
                "GRANT EXECUTE ON FUNCTION audit_restore_truncate(text[], text) TO PUBLIC",
                "REVOKE EXECUTE ON FUNCTION audit_restore_truncate(text[], text) FROM PUBLIC",
                "audit function audit_restore_truncate is executable by PUBLIC",
            ),
        ] {
            exec(&pool, &grant.replace("{q}", &q)).await;
            let v = boundary_violations(&app.pool, false).await.unwrap();
            assert!(has(&v, needle), "{needle}: {v:?}");
            exec(&pool, &revoke.replace("{q}", &q)).await;
            let v = boundary_violations(&app.pool, false).await.unwrap();
            assert!(v.is_empty(), "after {revoke}: {v:?}");
        }
        // Column-level INSERT of id / occurred_at.
        exec(&pool, &format!("GRANT INSERT (id) ON rule_audit TO {q}")).await;
        exec(
            &pool,
            &format!("GRANT INSERT (occurred_at) ON audit_events TO {q}"),
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(
            has(&v, "role can INSERT the id column of rule_audit"),
            "{v:?}"
        );
        assert!(
            has(&v, "role can INSERT the occurred_at column of audit_events"),
            "{v:?}"
        );
        exec(&pool, &format!("REVOKE INSERT (id) ON rule_audit FROM {q}")).await;
        exec(
            &pool,
            &format!("REVOKE INSERT (occurred_at) ON audit_events FROM {q}"),
        )
        .await;

        // A held-open restore window and a zero floor with test routes off.
        exec(
            &pool,
            "UPDATE audit_policy SET restore_allowed_until = 'infinity', min_retain_days = 0",
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(has(&v, "restore window is held open"), "{v:?}");
        assert!(has(&v, "retention floor is 0"), "{v:?}");
        let v = boundary_violations(&app.pool, true).await.unwrap();
        assert!(v.is_empty(), "test routes on: {v:?}");
        set_window_unchecked(&pool, "48 hours").await;
        exec(&pool, "UPDATE audit_policy SET min_retain_days = 365").await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(has(&v, "open for more than 24 hours"), "{v:?}");
        exec(
            &pool,
            "UPDATE audit_policy SET restore_allowed_until = now() + interval '1 hour'",
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(v.is_empty(), "a short finite window is fine: {v:?}");
        exec(
            &pool,
            "UPDATE audit_policy SET restore_allowed_until = NULL",
        )
        .await;

        // A guard that is not revision 4 (047's body) is named; revision 4 is put back.
        let migration = include_str!("../migrations/050_audit_owner_functions.sql");
        let rev4 = &migration[migration
            .find("CREATE OR REPLACE FUNCTION public.audit_tables_guard()")
            .unwrap()..];
        let rev3 = include_str!("../migrations/047_audit_retention_protocol_gate.sql");
        exec(&pool, rev3).await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(has(&v, "is not revision 4"), "{v:?}");
        exec(&pool, rev4).await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(v.is_empty(), "{v:?}");

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

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_missing_or_foreign_owned_audit_function_is_a_violation(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        let other = temp_role(&pool, "fo_").await;
        exec(
            &pool,
            &format!(
                "ALTER FUNCTION audit_prune_rule_audit(bigint[]) OWNER TO \"{}\"",
                other.name
            ),
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(
            has(
                &v,
                "audit function audit_prune_rule_audit is not owned by the owner of rule_audit"
            ),
            "{v:?}"
        );
        exec(
            &pool,
            "ALTER FUNCTION audit_prune_rule_audit(bigint[]) OWNER TO CURRENT_USER",
        )
        .await;
        exec(&pool, "DROP FUNCTION audit_prune_rule_audit(bigint[])").await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(
            has(
                &v,
                "audit function audit_prune_rule_audit(bigint[]) is missing"
            ),
            "{v:?}"
        );
        // A same-name overload with other argument types is not the function.
        exec(
            &pool,
            "CREATE FUNCTION public.audit_prune_rule_audit(p text) RETURNS bigint \
             LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp \
             AS 'SELECT 0::bigint'",
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(
            has(
                &v,
                "audit function audit_prune_rule_audit(bigint[]) is missing"
            ),
            "{v:?}"
        );
        exec(&pool, "DROP FUNCTION public.audit_prune_rule_audit(text)").await;
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
        let dbo_role = temp_role(&pool, "dbo_").await;
        let dbo = dbo_role.name.clone();
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
            eprintln!("SKIPPED (PostgreSQL {ver} < 15): GRANT SET ON PARAMETER does not exist");
            let app = app_role_pool(&pool, false).await;
            let v = boundary_violations(&app.pool, false).await.unwrap();
            assert!(!has(&v, "can SET"), "{v:?}");
            app.cleanup(&pool).await;
            return;
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
        exec(
            &app.pool,
            "CREATE FUNCTION public.pg_advisory_lock(bigint) RETURNS void LANGUAGE sql \
             AS 'INSERT INTO public.planted_log VALUES (''advisory'')'",
        )
        .await;

        let err = migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("owned by other roles"), "{err}");
        assert!(err.contains("quote_ident"), "{err}");
        assert!(err.contains("pg_advisory_lock"), "{err}");
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
        exec(&pool, "DROP FUNCTION public.pg_advisory_lock(bigint)").await;
        exec(&pool, "DROP TABLE planted_log").await;
        // With the plants gone the owner step succeeds.
        migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
            .await
            .unwrap();
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn real_database_errors_are_classified_by_sqlstate(pool: PgPool) {
        for (codes, want) in [(TRANSIENT_CODES, 75), (PERMANENT_CODES, 1)] {
            for c in codes.into_iter().filter(|c| !c.is_empty()) {
                let e = sqlx::query(&format!(
                    "DO $$ BEGIN RAISE EXCEPTION 'x' USING ERRCODE = '{c}'; END $$"
                ))
                .execute(&pool)
                .await
                .unwrap_err();
                assert_eq!(code(&e).as_deref(), Some(c));
                let err = anyhow::Error::new(e).context("owner step");
                assert_eq!(is_transient(&err), want == 75, "{c}");
                assert_eq!(migrate_exit_code(&err), want, "{c}");
            }
        }
    }

    async fn migration_rows(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_owner_step_refuses_create_inherited_from_a_group_role_before_migrating(
        pool: PgPool,
    ) {
        let app = app_role_pool(&pool, false).await;
        let grp = temp_role(&pool, "grp_").await;
        exec(
            &pool,
            &format!("GRANT CREATE ON SCHEMA public TO \"{}\"", grp.name),
        )
        .await;
        exec(
            &pool,
            &format!("GRANT \"{}\" TO \"{}\"", grp.name, app.name),
        )
        .await;
        let mut conn = pool.acquire().await.unwrap();
        let err = prepare_owner_schema(&mut conn, &app.name)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("can still CREATE"), "{err}");
        drop(conn);

        exec(
            &pool,
            "DELETE FROM _sqlx_migrations WHERE version = \
             (SELECT max(version) FROM _sqlx_migrations)",
        )
        .await;
        let before = migration_rows(&pool).await;
        let err = migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("can still CREATE"), "{err}");
        assert_eq!(migration_rows(&pool).await, before, "migrations ran");

        exec(
            &pool,
            &format!("REVOKE CREATE ON SCHEMA public FROM \"{}\"", grp.name),
        )
        .await;
        let mut conn = pool.acquire().await.unwrap();
        prepare_owner_schema(&mut conn, &app.name).await.unwrap();
        drop(conn);
        exec(
            &pool,
            &format!("REVOKE \"{}\" FROM \"{}\"", grp.name, app.name),
        )
        .await;
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_owner_step_refuses_an_app_role_that_is_a_member_of_the_schema_owner(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        let own = temp_role(&pool, "own_").await;
        exec(
            &pool,
            &format!("ALTER SCHEMA public OWNER TO \"{}\"", own.name),
        )
        .await;
        exec(&pool, &format!("ALTER ROLE \"{}\" NOINHERIT", app.name)).await;
        exec(
            &pool,
            &format!("GRANT \"{}\" TO \"{}\"", own.name, app.name),
        )
        .await;
        let create: bool =
            sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
                .bind(&app.name)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!create, "the CREATE check alone would miss this");

        let mut conn = pool.acquire().await.unwrap();
        let err = prepare_owner_schema(&mut conn, &app.name)
            .await
            .err()
            .unwrap();
        assert!(!is_transient(&err));
        assert!(
            err.to_string()
                .contains("is a member of the role that owns schema"),
            "{err}"
        );
        drop(conn);
        let err = migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
            .await
            .unwrap_err();
        assert!(!is_transient(&err));
        assert!(
            err.to_string()
                .contains("is a member of the role that owns schema"),
            "{err}"
        );

        exec(
            &pool,
            &format!("REVOKE \"{}\" FROM \"{}\"", own.name, app.name),
        )
        .await;
        let mut conn = pool.acquire().await.unwrap();
        prepare_owner_schema(&mut conn, &app.name).await.unwrap();
        drop(conn);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_owner_step_refuses_planted_collations_conversions_and_text_search_objects(
        pool: PgPool,
    ) {
        let app = app_role_pool(&pool, false).await;
        let cases = [
            (
                "CREATE COLLATION public.planted_coll FROM \"C\"",
                "DROP COLLATION public.planted_coll",
                "collation planted_coll",
            ),
            (
                "CREATE CONVERSION public.planted_conv FOR 'LATIN1' TO 'UTF8' \
                 FROM iso8859_1_to_utf8",
                "DROP CONVERSION public.planted_conv",
                "conversion planted_conv",
            ),
            (
                "CREATE TEXT SEARCH CONFIGURATION public.planted_cfg (COPY = pg_catalog.simple)",
                "DROP TEXT SEARCH CONFIGURATION public.planted_cfg",
                "text search configuration planted_cfg",
            ),
            (
                "CREATE STATISTICS public.planted_stat ON a, b FROM public.planted_tbl",
                "DROP TABLE public.planted_tbl CASCADE",
                "statistics planted_stat",
            ),
            (
                "CREATE TEXT SEARCH DICTIONARY public.planted_dict (TEMPLATE = pg_catalog.simple)",
                "DROP TEXT SEARCH DICTIONARY public.planted_dict",
                "text search dictionary planted_dict",
            ),
        ];
        for (create, drop_sql, label) in cases {
            exec(&pool, "GRANT CREATE ON SCHEMA public TO PUBLIC").await;
            if label.starts_with("statistics") {
                exec(&app.pool, "CREATE TABLE public.planted_tbl (a int, b int)").await;
            }
            exec(&app.pool, create).await;
            let mut conn = pool.acquire().await.unwrap();
            let err = prepare_owner_schema(&mut conn, &app.name)
                .await
                .err()
                .unwrap()
                .to_string();
            drop(conn);
            assert!(err.contains("owned by other roles"), "{err}");
            assert!(err.contains(label), "{label}: {err}");
            exec(&pool, drop_sql).await;
        }
        let mut conn = pool.acquire().await.unwrap();
        prepare_owner_schema(&mut conn, &app.name).await.unwrap();
        drop(conn);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_owner_step_refuses_create_held_by_a_noinherit_group_membership(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        let grp = temp_role(&pool, "grp_").await;
        exec(&pool, &format!("ALTER ROLE \"{}\" NOINHERIT", app.name)).await;
        exec(
            &pool,
            &format!("GRANT CREATE ON SCHEMA public TO \"{}\"", grp.name),
        )
        .await;
        exec(
            &pool,
            &format!("GRANT \"{}\" TO \"{}\"", grp.name, app.name),
        )
        .await;
        let direct: bool =
            sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
                .bind(&app.name)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            !direct,
            "NOINHERIT hides the privilege from has_schema_privilege"
        );

        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(has(&v, "role can CREATE in schema"), "{v:?}");

        exec(
            &pool,
            "DELETE FROM _sqlx_migrations WHERE version = \
             (SELECT max(version) FROM _sqlx_migrations)",
        )
        .await;
        let before = migration_rows(&pool).await;
        let mut conn = pool.acquire().await.unwrap();
        let err = prepare_owner_schema(&mut conn, &app.name)
            .await
            .err()
            .unwrap()
            .to_string();
        drop(conn);
        assert!(err.contains("can still CREATE"), "{err}");
        let err = migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("can still CREATE"), "{err}");
        assert_eq!(migration_rows(&pool).await, before, "migrations ran");

        exec(
            &pool,
            &format!("REVOKE \"{}\" FROM \"{}\"", grp.name, app.name),
        )
        .await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(!has(&v, "role can CREATE in schema"), "{v:?}");
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_owner_step_refuses_a_superuser_app_role(pool: PgPool) {
        let su = temp_role(&pool, "su_").await;
        exec(&pool, &format!("ALTER ROLE \"{}\" SUPERUSER", su.name)).await;
        let mut conn = pool.acquire().await.unwrap();
        let result = prepare_owner_schema(&mut conn, &su.name).await;
        drop(conn);
        // Demote first so a failing assertion never leaves a superuser behind.
        exec(&pool, &format!("ALTER ROLE \"{}\" NOSUPERUSER", su.name)).await;
        let err = result.err().unwrap().to_string();
        assert!(err.contains("is a superuser"), "{err}");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_owner_step_refuses_an_app_role_that_is_a_member_of_the_owner_login(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        let own = temp_role(&pool, "own_").await;
        // A schema owner the app role is not a member of, so only the login
        // membership check can fire.
        exec(
            &pool,
            &format!("ALTER SCHEMA public OWNER TO \"{}\"", own.name),
        )
        .await;
        let login: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&pool)
            .await
            .unwrap();
        exec(&pool, &format!("GRANT \"{login}\" TO \"{}\"", app.name)).await;
        let mut conn = pool.acquire().await.unwrap();
        let err = prepare_owner_schema(&mut conn, &app.name)
            .await
            .err()
            .unwrap()
            .to_string();
        drop(conn);
        assert!(err.contains("member of the owner role"), "{err}");
        exec(&pool, &format!("REVOKE \"{login}\" FROM \"{}\"", app.name)).await;
        let mut conn = pool.acquire().await.unwrap();
        prepare_owner_schema(&mut conn, &app.name).await.unwrap();
        drop(conn);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_temp_role_is_removed_when_its_test_task_panics(pool: PgPool) {
        let role = temp_role(&pool, "panic_").await;
        let name = role.name.clone();
        let handle = tokio::spawn(async move {
            let role = role;
            panic!("simulated test failure holding {}", role.name);
        });
        let err = handle.await.unwrap_err();
        assert!(err.is_panic());
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
                .bind(&name)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!exists);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn dropping_an_app_role_without_cleanup_removes_the_cluster_role(pool: PgPool) {
        async fn exists(pool: &PgPool, name: &str) -> bool {
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
                .bind(name)
                .fetch_one(pool)
                .await
                .unwrap()
        }
        let app = app_role_pool(&pool, false).await;
        let name = app.name.clone();
        assert!(exists(&pool, &name).await);
        drop(app);
        assert!(!exists(&pool, &name).await);

        let own = temp_role(&pool, "own_").await;
        let name = own.name.clone();
        exec(&pool, &format!("ALTER SCHEMA public OWNER TO \"{name}\"")).await;
        drop(own);
        assert!(!exists(&pool, &name).await);
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
            &step(false),
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
        let err = migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
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
            set.spawn(async move { migrate_with(opts, &name, &step(true)).await });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap().unwrap();
        }
        assert!(crate::db_audit::test_maintenance_allowed(&pool)
            .await
            .unwrap());
        app.cleanup(&pool).await;
    }

    // ── #110: audit of the owner step and the boundary check ──

    #[test]
    fn migrate_detail_has_identifiers_and_counts_only() {
        let d = migrate_detail("migrate_command", &[50], Some(50), false, 365, None);
        assert_eq!(d["source"], "migrate_command");
        assert_eq!(d["appliedVersions"], serde_json::json!([50]));
        assert_eq!(d["schemaVersion"], 50);
        assert_eq!(d["testRoutes"], false);
        assert_eq!(d["retentionFloorDays"], 365);
        assert!(d.get("retentionFloorPrevious").is_none());
        let d = migrate_detail("server_startup", &[], Some(50), true, 0, Some(365));
        assert_eq!(d["retentionFloorPrevious"], 365);
        assert_eq!(d["appliedVersions"], serde_json::json!([]));
    }

    #[test]
    fn migrate_failure_detail_never_carries_error_text() {
        let d = migrate_failure_detail("migrate_command", "grants", true, Some("08006"));
        assert_eq!(d["stage"], "grants");
        assert_eq!(d["errorClass"], "transient");
        assert_eq!(d["sqlstate"], "08006");
        let keys: Vec<&String> = d.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 4, "{keys:?}");
        let d = migrate_failure_detail("migrate_command", "connect", false, None);
        assert_eq!(d["errorClass"], "permanent");
        assert!(d.get("sqlstate").is_none());
    }

    #[test]
    fn boundary_detail_caps_the_list_and_each_entry() {
        let many: Vec<String> = (0..30).map(|i| format!("v{i}")).collect();
        let d = boundary_detail("violations", &many, ("testRoutes", true));
        assert_eq!(d["violations"].as_array().unwrap().len(), 20);
        assert_eq!(d["count"], 30);
        assert_eq!(d["testRoutes"], true);
        let long = vec!["x".repeat(500)];
        let d = boundary_detail("violations", &long, ("production", true));
        assert_eq!(d["violations"][0].as_str().unwrap().len(), 200);
        assert_eq!(d["production"], true);
    }

    /// `(outcome, detail)` of the system events with this action, oldest first.
    async fn events(pool: &PgPool, action: &str) -> Vec<(String, serde_json::Value)> {
        sqlx::query_as(
            "SELECT outcome, detail FROM audit_events \
             WHERE action = $1 AND user_role = 'system' AND user_id IS NULL ORDER BY id",
        )
        .bind(action)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_owner_step_records_db_migrate_ok(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
            .await
            .unwrap();
        let ev = events(&pool, "db.migrate").await;
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].0, "ok");
        assert_eq!(ev[0].1["source"], "migrate_command");
        // The harness had already applied every migration, so this run applied none.
        assert_eq!(ev[0].1["appliedVersions"], serde_json::json!([]));
        assert_eq!(ev[0].1["testRoutes"], false);
        assert_eq!(ev[0].1["retentionFloorDays"], 365);
        assert!(ev[0].1["schemaVersion"].as_i64().unwrap() >= 50);
        // A rerun is idempotent and writes another record.
        migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
            .await
            .unwrap();
        assert_eq!(events(&pool, "db.migrate").await.len(), 2);
        // Lowering the floor is recorded with the previous value.
        let lower = OwnerStep {
            retention_floor_days: 30,
            ..step(false)
        };
        migrate_with((*pool.connect_options()).clone(), &app.name, &lower)
            .await
            .unwrap();
        let ev = events(&pool, "db.migrate").await;
        assert_eq!(ev[2].1["retentionFloorDays"], 30);
        assert_eq!(ev[2].1["retentionFloorPrevious"], 365);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_owner_step_records_db_migrate_failure(pool: PgPool) {
        // Missing application role: transient.
        migrate_with(
            (*pool.connect_options()).clone(),
            "stig_no_such_role_x",
            &step(false),
        )
        .await
        .unwrap_err();
        let ev = events(&pool, "db.migrate").await;
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].0, "failure");
        assert_eq!(ev[0].1["stage"], "prepare_schema");
        assert_eq!(ev[0].1["errorClass"], "transient");

        // A planted look-alike object: permanent.
        let app = app_role_pool(&pool, false).await;
        exec(&pool, "GRANT CREATE ON SCHEMA public TO PUBLIC").await;
        exec(
            &app.pool,
            "CREATE FUNCTION public.quote_ident(text) RETURNS text LANGUAGE sql AS 'SELECT $1'",
        )
        .await;
        migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
            .await
            .unwrap_err();
        let ev = events(&pool, "db.migrate").await;
        assert_eq!(ev.len(), 2, "{ev:?}");
        assert_eq!(ev[1].1["stage"], "prepare_schema");
        assert_eq!(ev[1].1["errorClass"], "permanent");
        // No error text, no object names.
        assert!(!ev[1].1.to_string().contains("quote_ident"));
        exec(&pool, "DROP FUNCTION public.quote_ident(text)").await;
        app.cleanup(&pool).await;
    }

    async fn closed_pool(pool: &PgPool) -> PgPool {
        let p = PgPoolOptions::new()
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        p.close().await;
        p
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_audit_write_does_not_mask_the_migrate_error(pool: PgPool) {
        let closed = closed_pool(&pool).await;
        // Best effort and infallible: returns (after logging) instead of failing.
        record_migrate_failure(
            &closed,
            "grants",
            &anyhow::anyhow!("boom"),
            "migrate_command",
        )
        .await;
        assert!(record_migrate_event(&closed, "ok", serde_json::json!({}))
            .await
            .is_err());
        assert!(events(&pool, "db.migrate").await.is_empty());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn boundary_degraded_is_recorded_outside_production(pool: PgPool) {
        let v = boundary_violations(&pool, false).await.unwrap();
        assert!(has(&v, "role is a superuser"));
        enforce_boundary(&pool, false, true, &v).await.unwrap();
        let ev = events(&pool, "db.boundary_degraded").await;
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].0, "partial");
        assert_eq!(ev[0].1["reason"], "violations");
        assert_eq!(ev[0].1["testRoutes"], true);
        assert!(ev[0].1["violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "role is a superuser"));
        record_owner_url_on_server(&pool, false).await;
        let ev = events(&pool, "db.boundary_degraded").await;
        assert_eq!(ev[1].1["reason"], "owner_url_on_server");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn boundary_refused_is_recorded_in_production(pool: PgPool) {
        let v = boundary_violations(&pool, false).await.unwrap();
        let err = enforce_boundary(&pool, true, false, &v).await.unwrap_err();
        assert!(err.to_string().contains("refusing to start"), "{err:#}");
        let ev = events(&pool, "db.boundary_refused").await;
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].0, "rejected");
        assert_eq!(ev[0].1["reason"], "violations");
        assert_eq!(ev[0].1["production"], true);
        record_boundary_refusal(&pool, "migrations_unverified", true).await;
        let ev = events(&pool, "db.boundary_refused").await;
        assert_eq!(ev[1].1["reason"], "migrations_unverified");
        assert_eq!(ev[1].1["count"], 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_clean_boundary_writes_no_event(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        let v = boundary_violations(&app.pool, false).await.unwrap();
        assert!(v.is_empty(), "{v:?}");
        enforce_boundary(&app.pool, true, false, &v).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events WHERE action LIKE 'db.boundary_%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 0);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_boundary_refusal_still_refuses_when_the_write_fails(pool: PgPool) {
        let v = boundary_violations(&pool, false).await.unwrap();
        let closed = closed_pool(&pool).await;
        let err = enforce_boundary(&closed, true, false, &v)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("refusing to start"), "{err:#}");
        // And a degraded start still starts.
        enforce_boundary(&closed, false, false, &v).await.unwrap();
    }

    /// A trigger that blocks every `db.migrate` audit row, as a planted fault.
    async fn block_migrate_events(pool: &PgPool) {
        exec(
            pool,
            "CREATE FUNCTION public.t_block_migrate() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'blocked'; END $$",
        )
        .await;
        exec(
            pool,
            "CREATE TRIGGER t_block_migrate BEFORE INSERT ON audit_events \
             FOR EACH ROW WHEN (NEW.action = 'db.migrate') EXECUTE FUNCTION public.t_block_migrate()",
        )
        .await;
    }

    async fn unblock_migrate_events(pool: &PgPool) {
        exec(pool, "DROP TRIGGER t_block_migrate ON audit_events").await;
        exec(pool, "DROP FUNCTION public.t_block_migrate()").await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failing_db_migrate_ok_write_fails_the_step_and_a_rerun_succeeds(pool: PgPool) {
        let app = app_role_pool(&pool, false).await;
        block_migrate_events(&pool).await;
        let err = migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("could not be written"),
            "{err:#}"
        );
        assert!(events(&pool, "db.migrate").await.is_empty());
        unblock_migrate_events(&pool).await;
        migrate_with((*pool.connect_options()).clone(), &app.name, &step(false))
            .await
            .unwrap();
        let ev = events(&pool, "db.migrate").await;
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].0, "ok");
        assert_eq!(ev[0].1["appliedVersions"], serde_json::json!([]));
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_failure_record_returns_the_original_step_error(pool: PgPool) {
        // The step fails (no such role) and the failure record fails too.
        block_migrate_events(&pool).await;
        let err = migrate_with(
            (*pool.connect_options()).clone(),
            "stig_no_such_role_x",
            &step(false),
        )
        .await
        .unwrap_err();
        assert!(err.chain().any(|c| c.is::<AppRoleMissing>()), "{err:#}");
        assert!(!format!("{err:#}").contains("blocked"), "{err:#}");
        assert!(is_transient(&err));
        unblock_migrate_events(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn unverified_migrations_record_a_refusal_and_still_refuse(pool: PgPool) {
        exec(&pool, "DELETE FROM _sqlx_migrations WHERE version = 49").await;
        let err = verify_or_record_refusal(&pool, true).await.unwrap_err();
        assert!(format!("{err:#}").contains("pending migrations"), "{err:#}");
        let ev = events(&pool, "db.boundary_refused").await;
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].1["reason"], "migrations_unverified");
        assert_eq!(ev[0].1["production"], true);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_self_migrate_records_db_migrate(pool: PgPool) {
        let step = OwnerStep {
            source: "server_self_migrate",
            ..step(false)
        };
        finish_self_migrate(&pool, &step, &[]).await.unwrap();
        let ev = events(&pool, "db.migrate").await;
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].1["source"], "server_self_migrate");
        // `before` was empty, so every applied migration counts as new.
        assert!(ev[0].1["appliedVersions"].as_array().unwrap().len() > 10);
    }
}
