use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;

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

/// POST /api/test/set-role — update a user's role for E2E workflow testing.
pub async fn set_role_handler(
    State(state): State<AppState>,
    Json(req): Json<SetRoleRequest>,
) -> StatusCode {
    let result = sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
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
