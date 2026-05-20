use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::json;

use crate::api::webhooks::run_overdue_digest;
use crate::AppState;

/// POST /api/test/reset — truncate all user-generated data for E2E test isolation.
/// Only registered when STIG_ENV != "production".
pub async fn reset_handler(State(state): State<AppState>) -> StatusCode {
    let result = sqlx::query("TRUNCATE draft_comments, stig_drafts, users CASCADE")
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
