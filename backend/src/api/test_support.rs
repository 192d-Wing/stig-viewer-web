use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use serde_json::json;

use crate::api::asset_email_cc::run_asset_email_schedules;
use crate::api::auth::{client_ip, user_agent};
use crate::api::compliance_report;
use crate::api::dashboard::take_snapshot;
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

/// POST /api/test/reset — truncate all user-generated data for E2E test isolation.
/// Only registered when STIG_ENV != "production".
pub async fn reset_handler(State(state): State<AppState>) -> StatusCode {
    // catalog_archive has no FK linkage to user tables, so CASCADE doesn't
    // reach it from `users`. List it explicitly so per-test archive seeds
    // don't leak between specs.
    let result = sqlx::query(
        "TRUNCATE draft_comments, stig_drafts, users, catalog_archive CASCADE",
    )
        .execute(state.pool.as_ref())
        .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT,
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
    match compliance_report::run_report(
        state.pool.as_ref(),
        &state.config.data_dir,
        req.range_days,
    )
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
    match audit_retention::run_prune(
        state.pool.as_ref(),
        &state.config.data_dir,
        req.retain_days,
        req.archive,
    )
    .await
    {
        Ok(pruned) => Ok(Json(json!({ "pruned": pruned }))),
        Err(e) => {
            tracing::error!("Test run-retention failed: {e:#}");
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
    let result = sqlx::query(
        "UPDATE rule_audit \
         SET occurred_at = occurred_at - ($1 || ' days')::INTERVAL \
         WHERE rule_id = $2",
    )
    .bind(req.days.to_string())
    .bind(&req.rule_id)
    .execute(state.pool.as_ref())
    .await;

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
/// authenticated. Gated by STIG_ENV != "production" like the other test
/// helpers.
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

    let cookie = Cookie::build(("stig_session", session_id.clone()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::hours(8))
        .build();

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
                let n = audit_retention::run_prune(pool, &data_dir, 365, false).await?;
                Ok::<String, anyhow::Error>(format!("pruned {n} rows"))
            })
            .await
        }
        "compliance_report" => {
            scheduler_log::record(pool, "compliance_report", || async {
                let row = compliance_report::run_report(pool, &data_dir, 7).await?;
                Ok::<String, anyhow::Error>(format!(
                    "generated id={} pdf={}",
                    row.id, row.pdf_path
                ))
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
/// without waiting on the hourly scheduler. Gated by
/// `STIG_ENV != "production"` at registration time.
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
/// same process) don't contaminate alice's bucket. Gated by
/// `STIG_ENV != "production"` at registration time.
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
