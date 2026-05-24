use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::api::auth::AuthUser;
use crate::AppState;

const VALID_ROLES: &[&str] = &["author", "reviewer", "admin", "viewer"];

fn ensure_admin(user: &AuthUser) -> Result<(), StatusCode> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("admin sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

// ── GET /api/admin/users ────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserRow {
    pub id: String,
    pub display_name: String,
    pub email: String,
    pub role: String,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub async fn list_users_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<AdminUserRow>>, StatusCode> {
    ensure_admin(&user)?;
    let rows = sqlx::query_as::<_, AdminUserRow>(
        r#"
        SELECT id, display_name, email, role, last_login, created_at
          FROM users
         ORDER BY display_name
        "#,
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    Ok(Json(rows))
}

// ── PATCH /api/admin/users/:id/role ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub role: String,
}

pub async fn update_user_role_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;
    if !VALID_ROLES.contains(&req.role.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let result = sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
        .bind(&req.role)
        .bind(&id)
        .execute(state.pool.as_ref())
        .await
        .map_err(map_sqlx)?;
    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── PATCH /api/admin/assets/:id/owner ───────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOwnerRequest {
    pub owner_id: String,
}

pub async fn update_asset_owner_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateOwnerRequest>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;
    let pool = state.pool.as_ref();

    // Verify the asset exists.
    let asset_exists: Option<String> = sqlx::query_scalar("SELECT id FROM assets WHERE id = $1")
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)?;
    if asset_exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Verify the new owner exists.
    let owner_exists: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
        .bind(&req.owner_id)
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)?;
    if owner_exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    sqlx::query("UPDATE assets SET owner_id = $1, updated_at = NOW() WHERE id = $2")
        .bind(&req.owner_id)
        .bind(&id)
        .execute(pool)
        .await
        .map_err(map_sqlx)?;

    // The asset audit table doesn't exist yet (see TODO in db_assets.rs);
    // intentionally skip audit logging until a shared pattern lands.
    Ok(StatusCode::NO_CONTENT)
}
