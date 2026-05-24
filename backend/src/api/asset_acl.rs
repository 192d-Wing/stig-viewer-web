//! Per-asset Access Control List (ACL).
//!
//! Today's mutation handlers gate on `asset.owner_id == user.id`. This
//! module generalises that single rule into "owner OR has the required
//! ACL level OR is a global admin" via a single helper, [`user_can`].
//!
//! Levels are ordered `admin > write > read`. A grant of `admin` implies
//! `write`, which implies `read`. The asset owner and any user with the
//! global `admin` role always satisfy every level.
//!
//! Default behavior (no ACL rows) MUST match today's behavior — only the
//! asset owner can mutate — so existing E2E coverage passes untouched.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::api::auth::AuthUser;
use crate::db_assets;
use crate::AppState;

/// Valid permission levels, low → high.
const VALID_PERMISSIONS: &[&str] = &["read", "write", "admin"];

/// Numeric ranking so a higher granted level satisfies a lower required
/// one (admin satisfies write satisfies read). Unknown values rank 0.
fn rank(level: &str) -> u8 {
    match level {
        "admin" => 3,
        "write" => 2,
        "read" => 1,
        _ => 0,
    }
}

/// Resolve whether `user` is permitted to act on `asset_id` at the given
/// `level` (`"read" | "write" | "admin"`).
///
/// Allowed when ANY of:
///   - `user.role == "admin"` (global admin role bypasses ACL),
///   - `user.id == assets.owner_id` for the asset,
///   - there is an `asset_acl` row with `permission >= level`.
///
/// Returns `false` when the asset does not exist so callers can map that
/// to a 404 separately (the typical pattern is to fetch the asset first
/// to distinguish 404 from 403 — see e.g. checklists::delete_handler).
pub async fn user_can(
    pool: &PgPool,
    asset_id: &str,
    user: &AuthUser,
    level: &str,
) -> bool {
    if user.role == "admin" {
        return true;
    }

    // Owner short-circuit. We don't need the full AssetRow — just the
    // owner_id — and we want to keep the call cheap for the hot path.
    let owner_id: Option<String> =
        match sqlx::query_scalar("SELECT owner_id FROM assets WHERE id = $1")
            .bind(asset_id)
            .fetch_optional(pool)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("user_can owner lookup failed: {e:#}");
                return false;
            }
        };
    let Some(owner_id) = owner_id else {
        return false;
    };
    if owner_id == user.id {
        return true;
    }

    let needed = rank(level);
    if needed == 0 {
        // Defensive — caller passed an unknown level. Treat as deny.
        return false;
    }

    let granted: Option<String> = match sqlx::query_scalar(
        "SELECT permission FROM asset_acl WHERE asset_id = $1 AND user_id = $2",
    )
    .bind(asset_id)
    .bind(&user.id)
    .fetch_optional(pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("user_can acl lookup failed: {e:#}");
            return false;
        }
    };

    matches!(granted.as_deref().map(rank), Some(g) if g >= needed)
}

// ── Handlers ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AclRow {
    pub user_id: String,
    pub display_name: String,
    pub permission: String,
    pub granted_at: DateTime<Utc>,
    pub granted_by: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRequest {
    pub user_id: String,
    pub permission: String,
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("asset_acl db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("asset_acl sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// Gate that lets only the asset's *owner*, a global admin, or someone
/// holding the `admin` ACL on the asset manage ACL entries. This is
/// stricter than the regular "write" gate the mutation handlers use.
async fn require_acl_admin(
    pool: &PgPool,
    asset_id: &str,
    user: &AuthUser,
) -> Result<(), StatusCode> {
    if user_can(pool, asset_id, user, "admin").await {
        Ok(())
    } else {
        // Distinguish missing asset from forbidden to match the rest of
        // the codebase (e.g. checklists::delete_handler).
        let exists: Option<String> = sqlx::query_scalar("SELECT id FROM assets WHERE id = $1")
            .bind(asset_id)
            .fetch_optional(pool)
            .await
            .map_err(map_sqlx)?;
        if exists.is_none() {
            Err(StatusCode::NOT_FOUND)
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// GET /api/assets/:id/acl — list ACL rows for the asset.
///
/// Visible to the owner, a global admin, or anyone holding the `admin`
/// ACL on the asset. Holding plain `write` does NOT let you read the
/// roster — that mirrors the typical "managers see who else is shared"
/// pattern.
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(asset_id): Path<String>,
) -> Result<Json<Vec<AclRow>>, StatusCode> {
    require_acl_admin(state.pool.as_ref(), &asset_id, &user).await?;

    let rows = sqlx::query_as::<_, AclRow>(
        r#"
        SELECT acl.user_id,
               u.display_name,
               acl.permission,
               acl.granted_at,
               acl.granted_by
          FROM asset_acl acl
          JOIN users u ON u.id = acl.user_id
         WHERE acl.asset_id = $1
         ORDER BY u.display_name
        "#,
    )
    .bind(&asset_id)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    Ok(Json(rows))
}

/// POST /api/assets/:id/acl — grant (upsert) a permission to a user.
///
/// Body: `{ "userId": "...", "permission": "read" | "write" | "admin" }`.
/// Only the asset owner, a global admin, or an existing acl-admin may
/// call this. The owner cannot be re-granted (the owner is always above
/// any ACL entry) — we return 400 instead of silently no-op so the
/// caller learns about the mismatch.
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(asset_id): Path<String>,
    Json(req): Json<GrantRequest>,
) -> Result<(StatusCode, Json<AclRow>), StatusCode> {
    require_acl_admin(state.pool.as_ref(), &asset_id, &user).await?;

    if !VALID_PERMISSIONS.contains(&req.permission.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.user_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify the target user exists; surfaces 404 instead of a foreign
    // key violation 500.
    let target_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
            .bind(&req.user_id)
            .fetch_optional(state.pool.as_ref())
            .await
            .map_err(map_sqlx)?;
    if target_exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Refuse to ACL the owner — semantically meaningless and would
    // confuse the listing UI.
    let asset = db_assets::get_asset(state.pool.as_ref(), &asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if asset.owner_id == req.user_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    sqlx::query(
        r#"
        INSERT INTO asset_acl (asset_id, user_id, permission, granted_by)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (asset_id, user_id)
        DO UPDATE SET permission = EXCLUDED.permission,
                      granted_at = NOW(),
                      granted_by = EXCLUDED.granted_by
        "#,
    )
    .bind(&asset_id)
    .bind(&req.user_id)
    .bind(&req.permission)
    .bind(&user.id)
    .execute(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    let row = sqlx::query_as::<_, AclRow>(
        r#"
        SELECT acl.user_id,
               u.display_name,
               acl.permission,
               acl.granted_at,
               acl.granted_by
          FROM asset_acl acl
          JOIN users u ON u.id = acl.user_id
         WHERE acl.asset_id = $1 AND acl.user_id = $2
        "#,
    )
    .bind(&asset_id)
    .bind(&req.user_id)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    Ok((StatusCode::CREATED, Json(row)))
}

/// DELETE /api/assets/:id/acl/:user_id — revoke a user's ACL row.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((asset_id, target_user_id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    require_acl_admin(state.pool.as_ref(), &asset_id, &user).await?;

    let result = sqlx::query(
        "DELETE FROM asset_acl WHERE asset_id = $1 AND user_id = $2",
    )
    .bind(&asset_id)
    .bind(&target_user_id)
    .execute(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}
