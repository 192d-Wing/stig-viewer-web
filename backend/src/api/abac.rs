//! Attribute-based access control (ABAC) policies.
//!
//! Layered behind `asset_acl::user_can`. After the owner / per-asset
//! ACL / global-admin checks all decline, the gating helper consults
//! every enabled policy whose `level` equals the requested level and
//! whose role/classification/tag predicates (NULL = wildcard) match
//! the caller and the target asset.
//!
//! Decision semantics — order matters:
//!   1. If *any* matching policy has `effect='deny'`, return `Deny`.
//!   2. Otherwise if *any* matching policy has `effect='allow'`,
//!      return `Allow`.
//!   3. Otherwise return `NoOpinion` — the caller (`user_can`) keeps
//!      its current "false" fallback so default behaviour with zero
//!      rows in the table is identical to before this feature shipped.
//!
//! Admin-only CRUD lives in this module too; routes are wired up
//! inside the auth-gated draft router in `main.rs`.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::api::auth::AuthUser;
use crate::db_assets::AssetRow;
use crate::AppState;

const VALID_EFFECTS: &[&str] = &["allow", "deny"];
const VALID_LEVELS: &[&str] = &["read", "write", "admin"];

/// Tri-state outcome of ABAC evaluation. `NoOpinion` exists so
/// callers can distinguish "no matching policy" from an explicit
/// deny and fall through to whatever the legacy gate would have
/// returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    NoOpinion,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRow {
    pub id: String,
    pub name: String,
    pub effect: String,
    pub level: String,
    pub role_match: Option<String>,
    pub classification_match: Option<String>,
    pub tag_match: Option<String>,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePolicyRequest {
    pub name: String,
    pub effect: String,
    pub level: String,
    #[serde(default)]
    pub role_match: Option<String>,
    #[serde(default)]
    pub classification_match: Option<String>,
    #[serde(default)]
    pub tag_match: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePolicyRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub effect: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    // `Option<Option<String>>` would let callers clear back to NULL,
    // but our PATCH semantics are "any field left out is untouched"
    // — explicit-null clears stay as a follow-up. Today, sending the
    // field at all overrides the current value (including with an
    // empty string, which we treat as NULL).
    #[serde(default)]
    pub role_match: Option<String>,
    #[serde(default)]
    pub classification_match: Option<String>,
    #[serde(default)]
    pub tag_match: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

fn ensure_admin(user: &AuthUser) -> Result<(), StatusCode> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("abac sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// True when the policy's three match predicates each accept the
/// (user, asset) pair. A NULL column matches anything; a non-NULL
/// column must equal the corresponding user.role / asset.classification
/// / be present in asset.tags.
fn policy_matches(policy: &PolicyRow, user: &AuthUser, asset: &AssetRow) -> bool {
    if let Some(r) = &policy.role_match {
        if r != &user.role {
            return false;
        }
    }
    if let Some(c) = &policy.classification_match {
        if c != &asset.classification {
            return false;
        }
    }
    if let Some(t) = &policy.tag_match {
        if !asset.tags.iter().any(|tag| tag == t) {
            return false;
        }
    }
    true
}

/// Evaluate every enabled policy targeting `requested_level` against the
/// given user + asset. Deny wins over Allow when multiple rows match.
///
/// Returns `NoOpinion` when nothing matches so the caller can keep its
/// pre-ABAC fallback (today: deny). DB errors are logged and treated
/// as `NoOpinion` so a transient lookup failure can't accidentally
/// elevate privileges.
pub async fn evaluate(
    pool: &PgPool,
    user: &AuthUser,
    asset: &AssetRow,
    requested_level: &str,
) -> Decision {
    let rows = sqlx::query_as::<_, PolicyRow>(
        r#"
        SELECT id, name, effect, level,
               role_match, classification_match, tag_match,
               enabled, created_by, created_at
          FROM abac_policies
         WHERE enabled = TRUE
           AND level = $1
        "#,
    )
    .bind(requested_level)
    .fetch_all(pool)
    .await;
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("abac::evaluate lookup failed: {e:#}");
            return Decision::NoOpinion;
        }
    };

    let mut allow_seen = false;
    for p in &rows {
        if !policy_matches(p, user, asset) {
            continue;
        }
        if p.effect == "deny" {
            // Single deny short-circuits the entire decision.
            return Decision::Deny;
        }
        if p.effect == "allow" {
            allow_seen = true;
        }
    }
    if allow_seen {
        Decision::Allow
    } else {
        Decision::NoOpinion
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// GET /api/admin/policies — admin-only list, newest first.
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<PolicyRow>>, StatusCode> {
    ensure_admin(&user)?;
    let rows = sqlx::query_as::<_, PolicyRow>(
        r#"
        SELECT id, name, effect, level,
               role_match, classification_match, tag_match,
               enabled, created_by, created_at
          FROM abac_policies
         ORDER BY created_at DESC
        "#,
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    Ok(Json(rows))
}

/// Convert an empty-string optional match value to NULL. Callers
/// pass "" via JSON when they mean "wildcard"; storing NULL keeps
/// the match logic simple (Option::is_none == wildcard).
fn nullify_empty(opt: Option<String>) -> Option<String> {
    opt.and_then(|s| {
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}

/// POST /api/admin/policies — create a new policy. Admin only.
/// 400 on invalid effect/level. 409 on duplicate name.
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<PolicyRow>), StatusCode> {
    ensure_admin(&user)?;

    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !VALID_EFFECTS.contains(&req.effect.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !VALID_LEVELS.contains(&req.level.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let role_match = nullify_empty(req.role_match);
    let classification_match = nullify_empty(req.classification_match);
    let tag_match = nullify_empty(req.tag_match);

    let id = uuid::Uuid::new_v4().to_string();
    let row = sqlx::query_as::<_, PolicyRow>(
        r#"
        INSERT INTO abac_policies
            (id, name, effect, level, role_match, classification_match,
             tag_match, enabled, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, name, effect, level,
                  role_match, classification_match, tag_match,
                  enabled, created_by, created_at
        "#,
    )
    .bind(&id)
    .bind(&name)
    .bind(&req.effect)
    .bind(&req.level)
    .bind(&role_match)
    .bind(&classification_match)
    .bind(&tag_match)
    .bind(req.enabled)
    .bind(&user.id)
    .fetch_one(state.pool.as_ref())
    .await;

    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(StatusCode::CONFLICT);
        }
        Err(e) => return Err(map_sqlx(e)),
    };
    Ok((StatusCode::CREATED, Json(row)))
}

/// PATCH /api/admin/policies/:id — partial update. Admin only.
/// Any field left out is untouched. Empty string clears the
/// corresponding optional match column to NULL.
pub async fn update_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<Json<PolicyRow>, StatusCode> {
    ensure_admin(&user)?;

    let existing = sqlx::query_as::<_, PolicyRow>(
        r#"
        SELECT id, name, effect, level,
               role_match, classification_match, tag_match,
               enabled, created_by, created_at
          FROM abac_policies WHERE id = $1
        "#,
    )
    .bind(&id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let name = match req.name {
        Some(n) => {
            let n = n.trim().to_string();
            if n.is_empty() {
                return Err(StatusCode::BAD_REQUEST);
            }
            n
        }
        None => existing.name,
    };
    let effect = match req.effect {
        Some(e) => {
            if !VALID_EFFECTS.contains(&e.as_str()) {
                return Err(StatusCode::BAD_REQUEST);
            }
            e
        }
        None => existing.effect,
    };
    let level = match req.level {
        Some(l) => {
            if !VALID_LEVELS.contains(&l.as_str()) {
                return Err(StatusCode::BAD_REQUEST);
            }
            l
        }
        None => existing.level,
    };
    let role_match = match req.role_match {
        Some(v) => nullify_empty(Some(v)),
        None => existing.role_match,
    };
    let classification_match = match req.classification_match {
        Some(v) => nullify_empty(Some(v)),
        None => existing.classification_match,
    };
    let tag_match = match req.tag_match {
        Some(v) => nullify_empty(Some(v)),
        None => existing.tag_match,
    };
    let enabled = req.enabled.unwrap_or(existing.enabled);

    let row = sqlx::query_as::<_, PolicyRow>(
        r#"
        UPDATE abac_policies
           SET name = $1, effect = $2, level = $3,
               role_match = $4, classification_match = $5,
               tag_match = $6, enabled = $7
         WHERE id = $8
        RETURNING id, name, effect, level,
                  role_match, classification_match, tag_match,
                  enabled, created_by, created_at
        "#,
    )
    .bind(&name)
    .bind(&effect)
    .bind(&level)
    .bind(&role_match)
    .bind(&classification_match)
    .bind(&tag_match)
    .bind(enabled)
    .bind(&id)
    .fetch_one(state.pool.as_ref())
    .await;
    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(StatusCode::CONFLICT);
        }
        Err(e) => return Err(map_sqlx(e)),
    };
    Ok(Json(row))
}

/// DELETE /api/admin/policies/:id — admin only. 404 when missing.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;
    let res = sqlx::query("DELETE FROM abac_policies WHERE id = $1")
        .bind(&id)
        .execute(state.pool.as_ref())
        .await
        .map_err(map_sqlx)?;
    if res.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}
