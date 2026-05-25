//! Admin-only endpoints powering the "Active sessions" panel in the
//! admin console. The data lives in the same `sessions` table that
//! `auth::resolve_session_user` uses; migration 028 added the audit
//! columns (`ip`, `user_agent`, `revoked_at`) that this surface joins
//! against `users` to render.
//!
//! Revocation is soft — DELETE stamps `revoked_at` instead of removing
//! the row. The lookup path in `auth.rs` treats `revoked_at IS NOT
//! NULL` as "no session", so a revoked user is forced back through the
//! login flow on their next request without needing to drop the audit
//! trail.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::api::auth::AuthUser;
use crate::AppState;

fn ensure_admin(user: &AuthUser) -> Result<(), StatusCode> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("sessions sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ActiveSessionRow {
    pub id: String,
    pub user_id: String,
    pub user_name: String,
    pub ip: String,
    pub user_agent: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// GET /api/admin/sessions — newest 100 active (non-revoked,
/// non-expired) sessions across every user. Admin-only; everyone else
/// gets 403.
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<ActiveSessionRow>>, StatusCode> {
    ensure_admin(&user)?;
    let rows = sqlx::query_as::<_, ActiveSessionRow>(
        r#"
        SELECT s.id,
               s.user_id            AS user_id,
               u.display_name       AS user_name,
               s.ip,
               s.user_agent,
               s.created_at,
               s.expires_at
          FROM sessions s
          JOIN users    u ON u.id = s.user_id
         WHERE s.revoked_at IS NULL
           AND s.expires_at > NOW()
         ORDER BY s.created_at DESC
         LIMIT 100
        "#,
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    Ok(Json(rows))
}

/// DELETE /api/admin/sessions/:id — soft-revoke a session by stamping
/// `revoked_at = NOW()`. Returns 204 on success, 404 if no row exists.
/// Idempotent for already-revoked rows (still 204) — the UPDATE
/// touches the timestamp again but the row stays out of the active
/// list either way.
pub async fn revoke_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;
    let result = sqlx::query(
        "UPDATE sessions \
         SET revoked_at = COALESCE(revoked_at, NOW()) \
         WHERE id = $1",
    )
    .bind(&id)
    .execute(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}
