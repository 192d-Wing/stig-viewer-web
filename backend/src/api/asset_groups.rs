//! Asset groups — first-class, named collections of assets.
//!
//! Distinct from `asset_tags` (free-form string labels). A group has a
//! single owner plus an explicit, mutable membership list. An asset can
//! belong to any number of groups (many-to-many via the
//! `asset_group_members` table).
//!
//! Authorization
//! -------------
//! Listing groups and viewing membership is open to any authenticated
//! user — groups are organizational metadata, not a security boundary.
//! Mutating a group (name/description/membership/delete) requires the
//! caller to be the group's owner OR a global admin (`role == "admin"`).
//!
//! v1 deliberately ships without a per-group ACL. If we need shared
//! ownership later we can mirror the `asset_acl` pattern.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::api::auth::AuthUser;
use crate::AppState;

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct GroupSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub owner_id: String,
    pub owner_name: String,
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub asset_id: String,
    pub name: String,
    pub hostname: String,
    pub classification: String,
    pub added_at: DateTime<Utc>,
    pub added_by: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMemberRequest {
    pub asset_id: String,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("asset_groups sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// Fetch a group's owner_id, returning `None` if the group doesn't exist.
async fn fetch_owner(pool: &PgPool, group_id: &str) -> Result<Option<String>, StatusCode> {
    sqlx::query_scalar::<_, String>("SELECT owner_id FROM asset_groups WHERE id = $1")
        .bind(group_id)
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)
}

/// Require the caller to be the group owner OR a global admin.
/// Returns 404 if the group is missing, 403 if it exists but the caller
/// is not allowed to mutate it.
async fn require_owner_or_admin(
    pool: &PgPool,
    group_id: &str,
    user: &AuthUser,
) -> Result<(), StatusCode> {
    let owner = fetch_owner(pool, group_id).await?.ok_or(StatusCode::NOT_FOUND)?;
    if user.role == "admin" || owner == user.id {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

// ── Group CRUD ──────────────────────────────────────────────────────────────

/// GET /api/asset-groups
///
/// Lists every group, newest-first, with the owner's display name and a
/// member count. Visible to every authenticated user — groups are
/// organizational metadata, not a security boundary.
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(_user): Extension<AuthUser>,
) -> Result<Json<Vec<GroupSummary>>, StatusCode> {
    let rows = sqlx::query_as::<_, GroupSummary>(
        r#"
        SELECT g.id,
               g.name,
               g.description,
               g.owner_id,
               u.display_name AS owner_name,
               COALESCE(m.cnt, 0)::bigint AS member_count,
               g.created_at
          FROM asset_groups g
          JOIN users u ON u.id = g.owner_id
          LEFT JOIN (
              SELECT group_id, COUNT(*) AS cnt
                FROM asset_group_members
               GROUP BY group_id
          ) m ON m.group_id = g.id
         ORDER BY g.created_at DESC
        "#,
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    Ok(Json(rows))
}

/// POST /api/asset-groups
///
/// Body: `{ "name": "...", "description"?: "..." }`.
/// Caller becomes the owner. Duplicate `name` returns 409 (we surface the
/// unique-violation explicitly so the UI can show a clean error).
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<GroupSummary>), StatusCode> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let description = req.description.unwrap_or_default();

    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO asset_groups (id, name, description, owner_id)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(&id)
    .bind(name)
    .bind(&description)
    .bind(&user.id)
    .execute(state.pool.as_ref())
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.is_unique_violation() {
                return StatusCode::CONFLICT;
            }
        }
        tracing::error!("asset_groups insert failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let row = sqlx::query_as::<_, GroupSummary>(
        r#"
        SELECT g.id,
               g.name,
               g.description,
               g.owner_id,
               u.display_name AS owner_name,
               0::bigint AS member_count,
               g.created_at
          FROM asset_groups g
          JOIN users u ON u.id = g.owner_id
         WHERE g.id = $1
        "#,
    )
    .bind(&id)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    Ok((StatusCode::CREATED, Json(row)))
}

/// PATCH /api/asset-groups/:id
///
/// Body: `{ "name"?: "...", "description"?: "..." }`. Owner or admin
/// only. Empty body is a no-op success. Renaming to a colliding name
/// yields 409.
pub async fn update_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<GroupSummary>, StatusCode> {
    require_owner_or_admin(state.pool.as_ref(), &id, &user).await?;

    if let Some(name) = req.name.as_ref() {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        sqlx::query("UPDATE asset_groups SET name = $1 WHERE id = $2")
            .bind(trimmed)
            .bind(&id)
            .execute(state.pool.as_ref())
            .await
            .map_err(|e| {
                if let sqlx::Error::Database(db_err) = &e {
                    if db_err.is_unique_violation() {
                        return StatusCode::CONFLICT;
                    }
                }
                tracing::error!("asset_groups rename failed: {e:#}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }
    if let Some(description) = req.description.as_ref() {
        sqlx::query("UPDATE asset_groups SET description = $1 WHERE id = $2")
            .bind(description)
            .bind(&id)
            .execute(state.pool.as_ref())
            .await
            .map_err(map_sqlx)?;
    }

    let row = sqlx::query_as::<_, GroupSummary>(
        r#"
        SELECT g.id,
               g.name,
               g.description,
               g.owner_id,
               u.display_name AS owner_name,
               COALESCE((SELECT COUNT(*) FROM asset_group_members m WHERE m.group_id = g.id), 0)::bigint AS member_count,
               g.created_at
          FROM asset_groups g
          JOIN users u ON u.id = g.owner_id
         WHERE g.id = $1
        "#,
    )
    .bind(&id)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    Ok(Json(row))
}

/// DELETE /api/asset-groups/:id
///
/// Owner or admin only. CASCADE drops `asset_group_members` rows.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    require_owner_or_admin(state.pool.as_ref(), &id, &user).await?;

    let res = sqlx::query("DELETE FROM asset_groups WHERE id = $1")
        .bind(&id)
        .execute(state.pool.as_ref())
        .await
        .map_err(map_sqlx)?;
    if res.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── Membership ──────────────────────────────────────────────────────────────

/// GET /api/asset-groups/:id/members
///
/// Lists the assets in this group. Open to any authenticated user.
/// Returns 404 if the group itself doesn't exist (so the UI can tell
/// "empty group" apart from "stale link").
pub async fn list_members_handler(
    State(state): State<AppState>,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<Vec<GroupMember>>, StatusCode> {
    if fetch_owner(state.pool.as_ref(), &id).await?.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let rows = sqlx::query_as::<_, GroupMember>(
        r#"
        SELECT a.id AS asset_id,
               a.name,
               a.hostname,
               a.classification,
               m.added_at,
               m.added_by
          FROM asset_group_members m
          JOIN assets a ON a.id = m.asset_id
         WHERE m.group_id = $1
         ORDER BY a.name
        "#,
    )
    .bind(&id)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    Ok(Json(rows))
}

/// POST /api/asset-groups/:id/members
///
/// Body: `{ "assetId": "..." }`. Owner or admin only. Idempotent — a
/// repeat add is a no-op success (200). Returns 404 if either the group
/// or the asset doesn't exist.
pub async fn add_member_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<StatusCode, StatusCode> {
    require_owner_or_admin(state.pool.as_ref(), &id, &user).await?;

    if req.asset_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify the asset exists — otherwise the FK insert returns a 500
    // and the UI can't distinguish "stale" from "broken".
    let asset_exists: Option<String> = sqlx::query_scalar("SELECT id FROM assets WHERE id = $1")
        .bind(&req.asset_id)
        .fetch_optional(state.pool.as_ref())
        .await
        .map_err(map_sqlx)?;
    if asset_exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    sqlx::query(
        r#"
        INSERT INTO asset_group_members (group_id, asset_id, added_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (group_id, asset_id) DO NOTHING
        "#,
    )
    .bind(&id)
    .bind(&req.asset_id)
    .bind(&user.id)
    .execute(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/asset-groups/:id/members/:asset_id
///
/// Owner or admin only. 204 on delete, 404 if the asset was not actually
/// a member (or the group is missing — `require_owner_or_admin` handles
/// the group-missing branch first).
pub async fn remove_member_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((id, asset_id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    require_owner_or_admin(state.pool.as_ref(), &id, &user).await?;

    let res = sqlx::query(
        "DELETE FROM asset_group_members WHERE group_id = $1 AND asset_id = $2",
    )
    .bind(&id)
    .bind(&asset_id)
    .execute(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    if res.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}
