use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{CookieJar, SameSite};
use serde::Deserialize;
use serde_json::json;

use crate::api::asset_email_cc::run_asset_email_schedules;
use crate::api::auth::{
    client_ip, cookie_secure, session_cookie, user_agent, SESSION_COOKIE, SESSION_LIFETIME_HOURS,
};
use crate::api::catalog_diff::seed_archive_handler;
use crate::api::compliance_report;
use crate::api::dashboard::{snapshot_handler, take_snapshot};
use crate::api::rate_limit;
use crate::api::saml::saml_login_user;
use crate::api::webhooks::run_overdue_digest;
use crate::audit_retention;
use crate::config::load_sources;
use crate::scheduler_log;
use crate::sync;
use crate::AppState;

/// Roles the system understands. Kept in sync with the allowlist in
/// `api::admin::update_user_role_handler` so the test-bypass set-role
/// endpoint can't be used to sneak in an unrecognized value.
const VALID_ROLES: &[&str] = &["author", "reviewer", "admin", "viewer"];

/// The five known background schedulers wired up in `main.rs`. Kept in
/// sync with the match arms in `run_scheduler_handler` so the
/// inject-error endpoint can't arm a failure for a name nothing will
/// ever consume.
const VALID_SCHEDULERS: &[&str] = &[
    "sync",
    "snapshot",
    "overdue_digest",
    "audit_retention",
    "compliance_report",
];

/// The reset transaction: `TRUNCATE ... CASCADE` in audit `test` mode. Requires the
/// database flag `stig.audit_allow_test_mode=on` (set at startup when test routes are on).
pub(crate) async fn reset_db(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    crate::db_audit::set_maintenance(&mut tx, "test").await?;
    sqlx::query(
        "TRUNCATE draft_comments, stig_drafts, users, catalog_archive, \
                  email_deliveries, login_notice_acks CASCADE",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The backdate transaction: shift matching `rule_audit` rows into the past. Requires the
/// database flag `stig.audit_allow_test_mode=on` (set at startup when test routes are on).
pub(crate) async fn backdate_audit(
    pool: &sqlx::PgPool,
    rule_id: &str,
    days: i64,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    crate::db_audit::set_maintenance(&mut tx, "test").await?;
    sqlx::query(
        "UPDATE rule_audit \
         SET occurred_at = occurred_at - ($1 || ' days')::INTERVAL \
         WHERE rule_id = $2",
    )
    .bind(days.to_string())
    .bind(rule_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// POST /api/test/reset — truncate all user-generated data for E2E test isolation.
/// Only registered when `STIG_ENABLE_TEST_ROUTES=true` (which startup refuses
/// under `STIG_ENV=production`).
pub async fn reset_handler(State(state): State<AppState>) -> StatusCode {
    // catalog_archive has no FK linkage to user tables, so CASCADE doesn't
    // reach it from `users`. List it explicitly so per-test archive seeds
    // don't leak between specs.
    // CASCADE from `users` reaches the audit tables, whose guard triggers need
    // the `test` maintenance mode.
    let result = reset_db(state.pool.as_ref()).await;

    match result {
        Ok(_) => {
            // Also clear the pre-auth rate-limit buckets so specs start fresh.
            crate::api::rate_limit::reset();
            StatusCode::NO_CONTENT
        }
        Err(e) => {
            tracing::error!("Test reset failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub user_id: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct BackdateRequest {
    pub checklist_id: String,
    pub rule_id: String,
    pub days: i64,
}

#[derive(Deserialize)]
pub struct BumpStigRequest {
    pub stig_id: String,
    pub version: String,
    pub release_info: String,
}

#[derive(Deserialize)]
pub struct BackdateBaselineRequest {
    pub baseline_id: String,
    pub days: i64,
}

/// POST /api/test/set-role — update a user's role for E2E workflow testing.
pub async fn set_role_handler(
    State(state): State<AppState>,
    Json(req): Json<SetRoleRequest>,
) -> StatusCode {
    if !VALID_ROLES.contains(&req.role.as_str()) {
        return StatusCode::BAD_REQUEST;
    }
    // Test-bypass users are inserted with provider='test' and sub=<X-User-Id>.
    // E2E specs pass the same X-User-Id string here, so match on (provider, sub).
    let result = sqlx::query("UPDATE users SET role = $1 WHERE provider = 'test' AND sub = $2")
        .bind(&req.role)
        .bind(&req.user_id)
        .execute(state.pool.as_ref())
        .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Test set-role failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// POST /api/test/backdate-rule — shift a checklist_rule's updated_at into
/// the past so the "stale" filter can be exercised without sleeping. Used
/// by E2E only.
pub async fn backdate_handler(
    State(state): State<AppState>,
    Json(req): Json<BackdateRequest>,
) -> StatusCode {
    let result = sqlx::query(
        "UPDATE checklist_rules \
         SET updated_at = NOW() - ($1 || ' days')::INTERVAL \
         WHERE checklist_id = $2 AND rule_id = $3",
    )
    .bind(req.days.to_string())
    .bind(&req.checklist_id)
    .bind(&req.rule_id)
    .execute(state.pool.as_ref())
    .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Test backdate failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// POST /api/test/backdate-baseline — shift a baseline's `created_at`
/// into the past so the "stale baseline" reminder can be exercised
/// without sleeping for 90 days. Used by E2E only.
pub async fn backdate_baseline_handler(
    State(state): State<AppState>,
    Json(req): Json<BackdateBaselineRequest>,
) -> StatusCode {
    let result = sqlx::query(
        "UPDATE baselines \
         SET created_at = NOW() - ($1 || ' days')::INTERVAL \
         WHERE id = $2",
    )
    .bind(req.days.to_string())
    .bind(&req.baseline_id)
    .execute(state.pool.as_ref())
    .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Test backdate-baseline failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// POST /api/test/run-digest — synchronously run the overdue-digest
/// sweep once and return the number of webhooks attempted. Used by E2E
/// to drive the digest path without waiting for the 24h scheduler.
pub async fn run_digest_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match run_overdue_digest(state.pool.as_ref()).await {
        Ok(count) => Ok(Json(json!({ "count": count }))),
        Err(e) => {
            tracing::error!("Test run-digest failed: {e:#}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize, Default)]
pub struct RunReportRequest {
    #[serde(default = "default_report_days")]
    pub range_days: i32,
}

fn default_report_days() -> i32 {
    7
}

/// POST /api/test/run-report — synchronously generate a compliance
/// report once and return its id. Used by E2E to drive the report
/// path without waiting for the weekly scheduler.
pub async fn run_report_handler(
    State(state): State<AppState>,
    body: Option<Json<RunReportRequest>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    match compliance_report::run_report(state.pool.as_ref(), &state.config.data_dir, req.range_days)
        .await
    {
        Ok(row) => Ok(Json(json!({
            "id": row.id,
            "generatedAt": row.generated_at,
            "pdfPath": row.pdf_path,
        }))),
        Err(e) => {
            tracing::error!("Test run-report failed: {e:#}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
pub struct RunRetentionRequest {
    pub retain_days: i64,
    pub archive: bool,
}

/// POST /api/test/run-retention — synchronously run the audit-retention
/// prune once and return the row count deleted. Used by E2E to drive
/// the housekeeping path without waiting for the 24h scheduler.
pub async fn run_retention_handler(
    State(state): State<AppState>,
    Json(req): Json<RunRetentionRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Independent prunes: an error in one must not skip the other.
    let rules = audit_retention::run_prune(
        state.pool.as_ref(),
        &state.config.data_dir,
        req.retain_days,
        req.archive,
        state.signing.as_ref(),
    )
    .await;
    let events = audit_retention::run_prune_events(
        state.pool.as_ref(),
        &state.config.data_dir,
        req.retain_days,
        req.archive,
        state.signing.as_ref(),
    )
    .await;
    match (rules, events) {
        (Ok(pruned), Ok(pruned_events)) => Ok(Json(
            json!({ "pruned": pruned, "prunedEvents": pruned_events }),
        )),
        (r, e) => {
            tracing::error!("Test run-retention failed: rule_audit={r:?} audit_events={e:?}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
pub struct BackdateAuditRequest {
    pub rule_id: String,
    pub days: i64,
}

/// POST /api/test/backdate-audit — shift every `rule_audit` row whose
/// `rule_id` matches into the past by N days. Used by the retention
/// E2E spec to fabricate "old" audit rows without waiting a year.
pub async fn backdate_audit_handler(
    State(state): State<AppState>,
    Json(req): Json<BackdateAuditRequest>,
) -> StatusCode {
    let result = backdate_audit(state.pool.as_ref(), &req.rule_id, req.days).await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Test backdate-audit failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlLoginRequest {
    pub name_id: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub display_name: String,
}

/// POST /api/test/saml-login — exercise the SAML "find or create user +
/// mint session" path without a real IdP. Returns the session cookie via
/// `Set-Cookie` so subsequent requests with the same cookie jar are
/// authenticated. Only registered when `STIG_ENABLE_TEST_ROUTES=true`, like
/// the other test helpers.
pub async fn saml_login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<SamlLoginRequest>,
) -> Result<(CookieJar, Json<serde_json::Value>), StatusCode> {
    if req.name_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let display = if req.display_name.is_empty() {
        if !req.email.is_empty() {
            req.email.clone()
        } else {
            req.name_id.clone()
        }
    } else {
        req.display_name.clone()
    };

    let ip = client_ip(&headers);
    let ua = user_agent(&headers);
    let (user_id, session_id) = saml_login_user(
        state.pool.as_ref(),
        &req.name_id,
        &req.email,
        &display,
        &ip,
        &ua,
    )
    .await
    .map_err(|e| {
        tracing::error!("test saml-login failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let cookie = session_cookie(
        SESSION_COOKIE,
        session_id.clone(),
        "/",
        SameSite::Lax,
        time::Duration::hours(SESSION_LIFETIME_HOURS),
        cookie_secure(),
    );

    Ok((
        jar.add(cookie),
        Json(json!({
            "userId": user_id,
            "sessionId": session_id,
        })),
    ))
}

/// POST /api/test/bump-stig — change a `stigs_catalog` row's version +
/// release_info to simulate a newer revision landing from DISA. Used by
/// the drift E2E spec to flip a checklist's `outdated` flag without
/// running a real sync.
pub async fn bump_stig_handler(
    State(state): State<AppState>,
    Json(req): Json<BumpStigRequest>,
) -> StatusCode {
    let result = sqlx::query(
        "UPDATE stigs_catalog \
         SET version = $1, release_info = $2, last_updated = NOW() \
         WHERE id = $3",
    )
    .bind(&req.version)
    .bind(&req.release_info)
    .bind(&req.stig_id)
    .execute(state.pool.as_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() == 0 => StatusCode::NOT_FOUND,
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Test bump-stig failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Deserialize)]
pub struct RunSchedulerRequest {
    pub name: String,
}

/// POST /api/test/run-scheduler — synchronously execute one tick of the
/// named background scheduler via the same `scheduler_log::record`
/// helper used by the production loops. The tick records a
/// `scheduler_runs` row exactly as it would on a real interval — E2E
/// asserts against that surface.
///
/// Body: `{ "name": "sync" | "snapshot" | "overdue_digest" | "audit_retention" | "compliance_report" }`.
pub async fn run_scheduler_handler(
    State(state): State<AppState>,
    Json(req): Json<RunSchedulerRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pool = state.pool.as_ref();
    let data_dir = state.config.data_dir.clone();

    let result: anyhow::Result<String> = match req.name.as_str() {
        "sync" => {
            // `sync::run_sync` needs a parsed sources manifest. We
            // re-read it on demand here so the test endpoint doesn't
            // require threading it through AppState.
            let sources = load_sources().map_err(|e| {
                tracing::error!("run-scheduler: load_sources failed: {e:#}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            scheduler_log::record(pool, "sync", || async {
                sync::run_sync(&state.config, &std::sync::Arc::new(sources.clone()), pool).await?;
                Ok::<String, anyhow::Error>(format!("synced {} source(s)", sources.len()))
            })
            .await
        }
        "snapshot" => {
            scheduler_log::record(pool, "snapshot", || async {
                let n = take_snapshot(pool).await.map_err(anyhow::Error::from)?;
                Ok::<String, anyhow::Error>(format!("captured {n} checklists"))
            })
            .await
        }
        "overdue_digest" => {
            scheduler_log::record(pool, "overdue_digest", || async {
                let n = run_overdue_digest(pool).await?;
                Ok::<String, anyhow::Error>(format!("attempted {n} webhook(s)"))
            })
            .await
        }
        "audit_retention" => {
            scheduler_log::record(pool, "audit_retention", || async {
                audit_retention::run_scheduled(pool, &data_dir, 365, false, None).await
            })
            .await
        }
        "compliance_report" => {
            scheduler_log::record(pool, "compliance_report", || async {
                let row = compliance_report::run_report(pool, &data_dir, 7).await?;
                Ok::<String, anyhow::Error>(format!("generated id={} pdf={}", row.id, row.pdf_path))
            })
            .await
        }
        other => {
            tracing::warn!("run-scheduler: unknown name {other:?}");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    match result {
        Ok(msg) => Ok(Json(json!({ "ok": true, "message": msg }))),
        Err(e) => {
            tracing::error!("run-scheduler failed: {e:#}");
            // We don't return 500 here — the row was already written
            // with status='error', and E2E wants to inspect the failure
            // via /api/admin/scheduler-runs. Surface the error string
            // in the body but with a 200 so the dashboard fetch path
            // is the source of truth.
            Ok(Json(json!({ "ok": false, "error": format!("{e:#}") })))
        }
    }
}

/// POST /api/test/run-asset-email-schedules — synchronously run one
/// tick of the per-asset scheduled-email loop and return the number of
/// assets that were emailed. Used by E2E to drive the cadence path
/// without waiting on the hourly scheduler. Only registered
/// when `STIG_ENABLE_TEST_ROUTES=true`.
pub async fn run_asset_email_schedules_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match run_asset_email_schedules(state.pool.as_ref(), &state.config.data_dir).await {
        Ok(count) => Ok(Json(json!({ "count": count }))),
        Err(e) => {
            tracing::error!("Test run-asset-email-schedules failed: {e:#}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /api/test/reset-ratelimit — flush the in-memory token-bucket map
/// used by the rate-limit middleware. The rate-limit E2E spec calls this
/// in `beforeEach` so prior runs (and earlier mutation-heavy specs in the
/// same process) don't contaminate alice's bucket. Only registered
/// when `STIG_ENABLE_TEST_ROUTES=true`.
pub async fn reset_ratelimit_handler() -> StatusCode {
    rate_limit::reset();
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
pub struct InjectSchedulerErrorRequest {
    pub name: String,
}

/// POST /api/test/inject-scheduler-error — arm a one-shot failure for
/// the named scheduler. The next call to `scheduler_log::record` for
/// that name short-circuits with `status='error'` /
/// `message='injected test failure'`. The flag is consumed after one
/// tick, so subsequent ticks return to normal behaviour.
///
/// Exists so the admin job dashboard's error path is reachable from
/// E2E — nothing in the real system errors reliably on demand. Body:
/// `{ "name": "sync" | "snapshot" | "overdue_digest" | "audit_retention" | "compliance_report" }`.
pub async fn inject_scheduler_error_handler(
    Json(req): Json<InjectSchedulerErrorRequest>,
) -> StatusCode {
    if !VALID_SCHEDULERS.contains(&req.name.as_str()) {
        tracing::warn!("inject-scheduler-error: unknown name {:?}", req.name);
        return StatusCode::BAD_REQUEST;
    }
    scheduler_log::inject_failure(&req.name);
    StatusCode::NO_CONTENT
}

/// GET /api/test/login-acks — read-only metadata of the AC-8 acknowledgement
/// rows (id digests, timestamps, method, state digest, whether nonce/verifier are
/// set). Deliberately omits the nonce and PKCE verifier values.
pub async fn login_acks_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::db_notice::AckProbe>>, StatusCode> {
    crate::db_notice::list_ack_probes(state.pool.as_ref())
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Test login-acks read failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// POST /api/test/system-audit-event — write one fixed system audit event
/// (the DISA download-cap shape, `stig_id = "e2e-system-event"`) through the
/// production writer, so specs can see a real NULL-user `system` row.
/// Takes no body and no query: the event is not caller-influenced. Only
/// registered through [`mount`]; the row is removed by `/api/test/reset`. The
/// writer is detached, so this returns 204 before the row is necessarily visible.
pub async fn system_audit_event_handler(State(state): State<AppState>) -> StatusCode {
    crate::db_audit::record_system_or_log(
        state.pool.as_ref(),
        crate::sync::disa::download_too_large_event("e2e-system-event", 1024, Some(2048)),
    )
    .await;
    StatusCode::NO_CONTENT
}

/// Every path [`mount`] registers. Keep in step with `mount`: the router tests
/// use it to prove each one is absent when the flag is off and present when on.
#[cfg(test)]
pub(crate) const ROUTE_PATHS: &[&str] = &[
    "/api/test/reset",
    "/api/test/set-role",
    "/api/test/snapshot",
    "/api/test/backdate-rule",
    "/api/test/backdate-baseline",
    "/api/test/bump-stig",
    "/api/test/run-digest",
    "/api/test/run-report",
    "/api/test/run-retention",
    "/api/test/run-asset-email-schedules",
    "/api/test/backdate-audit",
    "/api/test/run-scheduler",
    "/api/test/inject-scheduler-error",
    "/api/test/saml-login",
    "/api/test/seed-archive",
    "/api/test/reset-ratelimit",
    "/api/test/login-acks",
    "/api/test/system-audit-event",
];

/// Merge the unauthenticated test-only routes into `app` when `enabled`
/// (`STIG_ENABLE_TEST_ROUTES=true`); otherwise return `app` unchanged.
/// `TestHooks::validate` already refused that flag under `STIG_ENV=production`.
pub fn mount(app: Router, enabled: bool, state: AppState) -> Router {
    if !enabled {
        return app;
    }
    let test_router: Router = Router::new()
        .route("/api/test/reset", post(reset_handler))
        .route("/api/test/set-role", post(set_role_handler))
        .route("/api/test/snapshot", post(snapshot_handler))
        .route("/api/test/backdate-rule", post(backdate_handler))
        .route(
            "/api/test/backdate-baseline",
            post(backdate_baseline_handler),
        )
        .route("/api/test/bump-stig", post(bump_stig_handler))
        .route("/api/test/run-digest", post(run_digest_handler))
        .route("/api/test/run-report", post(run_report_handler))
        .route("/api/test/run-retention", post(run_retention_handler))
        .route(
            "/api/test/run-asset-email-schedules",
            post(run_asset_email_schedules_handler),
        )
        .route("/api/test/backdate-audit", post(backdate_audit_handler))
        .route("/api/test/run-scheduler", post(run_scheduler_handler))
        .route(
            "/api/test/inject-scheduler-error",
            post(inject_scheduler_error_handler),
        )
        .route("/api/test/saml-login", post(saml_login_handler))
        .route("/api/test/seed-archive", post(seed_archive_handler))
        .route("/api/test/reset-ratelimit", post(reset_ratelimit_handler))
        .route("/api/test/login-acks", get(login_acks_handler))
        .route(
            "/api/test/system-audit-event",
            post(system_audit_event_handler),
        )
        .with_state(state);
    app.merge(test_router)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::seed_user;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn login_acks_route_is_404_when_test_routes_disabled() {
        let (state, _dir) = crate::test_fixtures::lazy_state();
        let app = mount(Router::new(), false, state);
        for uri in ROUTE_PATHS {
            for method in ["GET", "POST", "DELETE"] {
                let req = Request::builder()
                    .method(method)
                    .uri(*uri)
                    .body(Body::empty())
                    .unwrap();
                let resp = app.clone().oneshot(req).await.unwrap();
                assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{method} {uri}");
            }
        }
    }

    /// `ROUTE_PATHS` must list exactly the paths `mount` registers: read the
    /// path literals out of `mount`'s own source.
    #[test]
    fn route_paths_match_the_routes_mount_registers() {
        let src = include_str!("test_support.rs");
        let start = src.find("pub fn mount(").unwrap();
        let end = src.find("#[cfg(test)]\nmod tests").unwrap();
        let mut found: Vec<&str> = src[start..end]
            .split('"')
            .skip(1)
            .step_by(2)
            .filter(|s| s.starts_with("/api/test/"))
            .collect();
        found.sort_unstable();
        let mut listed = ROUTE_PATHS.to_vec();
        listed.sort_unstable();
        assert_eq!(found, listed);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn login_acks_handler_returns_digests_not_ids(pool: sqlx::PgPool) {
        use crate::db_notice::{ack_id_digest, consume_ack, insert_ack, LoginBinding};
        let (state, _dir) = crate::test_fixtures::app_state(pool.clone());
        let id = "distinct-ack-id-value";
        insert_ack(&pool, id, "v1", "", "", 300).await.unwrap();
        let b = LoginBinding::Oidc {
            state: "distinct-state-value",
            nonce: "distinct-nonce-value",
            pkce_verifier: "distinct-verifier-value",
        };
        consume_ack(&pool, id, "v1", &b).await.unwrap();
        let saml_id = "distinct-saml-ack-id";
        let saml_req = "distinct-saml-request-id";
        insert_ack(&pool, saml_id, "v1", "", "", 300).await.unwrap();
        let sb = LoginBinding::Saml {
            request_id: saml_req,
        };
        consume_ack(&pool, saml_id, "v1", &sb).await.unwrap();

        let app = mount(Router::new(), true, state);
        let other = Request::builder()
            .method("POST")
            .uri("/api/test/reset-ratelimit")
            .body(Body::empty())
            .unwrap();
        let other_resp = app.clone().oneshot(other).await.unwrap();
        assert_ne!(other_resp.status(), StatusCode::NOT_FOUND);
        let req = Request::builder()
            .uri("/api/test/login-acks")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        let rows: serde_json::Value = serde_json::from_str(&body).unwrap();
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let oidc = rows
            .iter()
            .find(|r| r["idSha256"] == ack_id_digest(id))
            .unwrap();
        assert!(oidc.get("id").is_none());
        assert_eq!(oidc["hasNonce"], true);
        let saml = rows
            .iter()
            .find(|r| r["idSha256"] == ack_id_digest(saml_id))
            .unwrap();
        assert_eq!(
            saml["samlRequestIdSha256"],
            crate::db_notice::state_digest(saml_req)
        );
        assert!(saml.get("samlRequestId").is_none());
        for v in [
            id,
            saml_id,
            saml_req,
            "distinct-state-value",
            "distinct-nonce-value",
            "distinct-verifier-value",
        ] {
            assert!(!body.contains(v), "the probe leaked {v}");
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn backdate_and_reset_work_under_the_audit_guard(pool: sqlx::PgPool) {
        crate::test_fixtures::allow_audit_test_mode(&pool).await;
        seed_user(&pool, "u1").await;
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r1','status')")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO audit_events (user_id, action, outcome) VALUES ('u1','checklist.save','ok')")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO audit_events (user_id, user_role, action, outcome) VALUES (NULL,'system','catalog.sync','rejected')")
            .execute(&pool).await.unwrap();
        backdate_audit(&pool, "r1", 60).await.unwrap();
        let old: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM rule_audit WHERE occurred_at < NOW() - INTERVAL '59 days'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(old, 1);
        reset_db(&pool).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM users) + (SELECT COUNT(*) FROM rule_audit) + (SELECT COUNT(*) FROM audit_events)")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(left, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn reset_and_backdate_fail_without_the_database_flag(pool: sqlx::PgPool) {
        seed_user(&pool, "u1").await;
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r1','status')")
            .execute(&pool).await.unwrap();
        assert!(backdate_audit(&pool, "r1", 60).await.is_err());
        assert!(reset_db(&pool).await.is_err());
        let left: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM users) + (SELECT COUNT(*) FROM rule_audit)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(left, 2);
        let old: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM rule_audit WHERE occurred_at < NOW() - INTERVAL '59 days'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(old, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn system_audit_event_route_writes_a_system_row(pool: sqlx::PgPool) {
        let (state, _dir) = crate::test_fixtures::app_state(pool.clone());
        let app = mount(Router::new(), true, state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/test/system-audit-event")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"action":"x"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        crate::db_audit::drain().await;
        type Row = (Option<String>, String, String, String, Option<String>);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT user_id, user_role, action, outcome, detail->>'reasonCode' FROM audit_events",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![(
                None,
                "system".to_string(),
                "catalog.sync".to_string(),
                "rejected".to_string(),
                Some("download_too_large".to_string())
            )]
        );
    }
}
