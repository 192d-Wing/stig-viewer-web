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
use sqlx::{PgConnection, PgPool};
use std::collections::HashSet;

use crate::api::abac::{self, Decision};
use crate::api::auth::AuthUser;
use crate::db_assets::{self, AssetSummary};
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
///
/// NOTE: [`writable_asset_ids`] re-implements the `"write"` decision in bulk.
/// Change the two together; the control is the parity test
/// `writable_asset_ids_matches_user_can_write`.
///
/// `user_can_on` reports a database failure as `Err` so a caller on a bounded
/// transaction can tell a timeout (503) from a denial; [`user_can`] maps `Err`
/// to deny. `abac::evaluate` likewise returns its lookup errors.
pub async fn user_can_on(
    conn: &mut PgConnection,
    asset_id: &str,
    user: &AuthUser,
    level: &str,
) -> anyhow::Result<bool> {
    if user.role == "admin" {
        return Ok(true);
    }

    // Owner short-circuit. We don't need the full AssetRow — just the
    // owner_id — and we want to keep the call cheap for the hot path.
    let owner_id: Option<String> = sqlx::query_scalar("SELECT owner_id FROM assets WHERE id = $1")
        .bind(asset_id)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(owner_id) = owner_id else {
        return Ok(false);
    };
    if owner_id == user.id {
        return Ok(true);
    }

    let needed = rank(level);
    if needed == 0 {
        // Defensive — caller passed an unknown level. Treat as deny.
        return Ok(false);
    }

    let granted: Option<String> =
        sqlx::query_scalar("SELECT permission FROM asset_acl WHERE asset_id = $1 AND user_id = $2")
            .bind(asset_id)
            .bind(&user.id)
            .fetch_optional(&mut *conn)
            .await?;
    if matches!(granted.as_deref().map(rank), Some(g) if g >= needed) {
        return Ok(true);
    }

    // All three legacy paths (admin role, owner, ACL row) declined.
    // Fall through to attribute-based access control: load the full
    // asset row (with tags) once and evaluate the policy set.
    //
    // With zero rows in `abac_policies` there is no opinion and we keep
    // today's `false` — preserving the contract that default behaviour is
    // unchanged.
    let Some(asset) = db_assets::get_asset_on(&mut *conn, asset_id).await? else {
        return Ok(false);
    };
    let decision = abac::evaluate(&mut *conn, user, &asset, level).await?;
    Ok(matches!(decision, Decision::Allow))
}

/// [`user_can_on`] on a connection acquired from `pool`. A failed acquire or
/// any database error is logged and denies.
pub async fn user_can(pool: &PgPool, asset_id: &str, user: &AuthUser, level: &str) -> bool {
    if user.role == "admin" {
        return true;
    }
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("user_can connection acquire failed: {e:#}");
            return false;
        }
    };
    match user_can_on(&mut conn, asset_id, user, level).await {
        Ok(allowed) => allowed,
        Err(e) => {
            tracing::error!("user_can lookup failed: {e:#}");
            false
        }
    }
}

/// The ids in `assets` for which `user_can(.., "write")` is true, computed in
/// bulk: a global admin gets everything; otherwise owners and `write`/`admin`
/// ACL grants come from one query, and ABAC (`write` policies, loaded once) is
/// consulted only for the rest. Same order as `user_can`: legacy grants win,
/// ABAC (deny beats allow) only decides the remainder. Advisory only (it
/// filters a picker); the mutation handlers still call `user_can`.
///
/// NOTE: this duplicates `user_can(.., "write")`; change them together. The
/// control is the parity test `writable_asset_ids_matches_user_can_write`.
pub async fn writable_asset_ids(
    pool: &PgPool,
    user: &AuthUser,
    assets: &[AssetSummary],
) -> HashSet<String> {
    if user.role == "admin" {
        return assets.iter().map(|a| a.id.clone()).collect();
    }
    let mut out: HashSet<String> = assets
        .iter()
        .filter(|a| a.owner_id == user.id)
        .map(|a| a.id.clone())
        .collect();

    // Every level ranked at or above write, as `user_can` compares them.
    let levels: Vec<&str> = VALID_PERMISSIONS
        .iter()
        .copied()
        .filter(|p| rank(p) >= rank("write"))
        .collect();
    let granted: Vec<String> = match sqlx::query_scalar(
        "SELECT asset_id FROM asset_acl WHERE user_id = $1 AND permission = ANY($2)",
    )
    .bind(&user.id)
    .bind(&levels)
    .fetch_all(pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            // `user_can` denies non-owners on a lookup failure, ABAC included.
            tracing::error!("writable_asset_ids acl lookup failed: {e:#}");
            return out;
        }
    };
    out.extend(granted);

    let policies = match abac::load_policies(pool, "write").await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("writable_asset_ids abac lookup failed: {e:#}");
            return out;
        }
    };
    if !policies.is_empty() {
        for a in assets {
            if !out.contains(&a.id)
                && abac::decide(&policies, user, &a.classification, &a.tags) == Decision::Allow
            {
                out.insert(a.id.clone());
            }
        }
    }
    // ACL rows for assets outside `assets` are irrelevant to callers.
    let listed: HashSet<&str> = assets.iter().map(|a| a.id.as_str()).collect();
    out.retain(|id| listed.contains(id.as_str()));
    out
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
    let target_exists: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
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

    let result = sqlx::query("DELETE FROM asset_acl WHERE asset_id = $1 AND user_id = $2")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::*;

    /// `writable_asset_ids` is a batched second implementation of
    /// `user_can(.., "write")`; this keeps them identical across every branch.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn writable_asset_ids_matches_user_can_write(pool: PgPool) {
        for u in ["own", "wr", "ad", "rd", "nobody", "root", "vic"] {
            seed_user(&pool, u).await;
        }
        // Owned by "own": plain, write-ACL, admin-ACL, read-ACL.
        for id in ["a_own", "a_wr", "a_ad", "a_rd", "a_plain"] {
            seed_asset(&pool, id, "own", false).await;
        }
        seed_acl(&pool, "a_wr", "wr", "write").await;
        seed_acl(&pool, "a_ad", "ad", "admin").await;
        seed_acl(&pool, "a_rd", "rd", "read").await;
        // Owned by a viewer-role user: owner branch for the read-only role.
        seed_asset(&pool, "a_vic", "vic", false).await;
        // ABAC fixtures.
        for (id, tag) in [
            ("a_tag", "shared"),
            ("a_secret", "shared"),
            ("a_disabled", "off"),
            ("a_adminlvl", "adminlvl"),
            ("a_readlvl", "readlvl"),
            ("a_vrole", "vrole"),
            ("a_deny_only", "denyonly"),
        ] {
            seed_asset(&pool, id, "own", false).await;
            seed_tag(&pool, id, tag).await;
        }
        set_classification(&pool, "a_secret", "secret").await;
        // M4: classification-only ABAC allow, and a read ACL covered by an ABAC allow.
        seed_asset(&pool, "a_cls", "own", false).await;
        set_classification(&pool, "a_cls", "cui").await;
        seed_asset(&pool, "a_rd_abac", "own", false).await;
        seed_tag(&pool, "a_rd_abac", "shared").await;
        seed_acl(&pool, "a_rd_abac", "rd", "read").await;
        // wr holds a write ACL on a denied asset: legacy grants beat ABAC deny.
        seed_acl(&pool, "a_secret", "wr", "write").await;
        seed_policy(
            &pool,
            "allow-shared",
            "allow",
            "write",
            None,
            None,
            Some("shared"),
            true,
            "own",
        )
        .await;
        seed_policy(
            &pool,
            "deny-secret",
            "deny",
            "write",
            None,
            Some("secret"),
            None,
            true,
            "own",
        )
        .await;
        seed_policy(
            &pool,
            "disabled-allow",
            "allow",
            "write",
            None,
            None,
            Some("off"),
            false,
            "own",
        )
        .await;
        seed_policy(
            &pool,
            "admin-level",
            "allow",
            "admin",
            None,
            None,
            Some("adminlvl"),
            true,
            "own",
        )
        .await;
        seed_policy(
            &pool,
            "read-level",
            "allow",
            "read",
            None,
            None,
            Some("readlvl"),
            true,
            "own",
        )
        .await;
        seed_policy(
            &pool,
            "viewer-role",
            "allow",
            "write",
            Some("viewer"),
            None,
            Some("vrole"),
            true,
            "own",
        )
        .await;
        seed_policy(
            &pool,
            "deny-tag",
            "deny",
            "write",
            None,
            None,
            Some("denyonly"),
            true,
            "own",
        )
        .await;
        seed_policy(
            &pool,
            "allow-cui",
            "allow",
            "write",
            None,
            Some("cui"),
            None,
            true,
            "own",
        )
        .await;
        // a_secret matches both allow-shared and deny-secret: deny wins.

        let assets = db_assets::list_assets(&pool).await.unwrap();
        assert_eq!(assets.len(), 15);
        let users = [
            auth("own", "author"),
            auth("wr", "author"),
            auth("ad", "author"),
            auth("rd", "author"),
            auth("nobody", "author"),
            auth("root", "admin"),
            auth("vic", "viewer"),
        ];
        for u in &users {
            let got = writable_asset_ids(&pool, u, &assets).await;
            let mut want = HashSet::new();
            for a in &assets {
                if user_can(&pool, &a.id, u, "write").await {
                    want.insert(a.id.clone());
                }
            }
            assert_eq!(got, want, "mismatch for user {}", u.id);
        }

        // Guard against a vacuous pass: pin the interesting expectations.
        let ids = |u: &AuthUser| {
            let (pool, assets, u) = (pool.clone(), assets.clone(), u.clone());
            async move { writable_asset_ids(&pool, &u, &assets).await }
        };
        let nobody = ids(&users[4]).await;
        assert!(nobody.contains("a_tag"), "ABAC allow");
        assert!(!nobody.contains("a_secret"), "ABAC deny beats allow");
        assert!(!nobody.contains("a_disabled"), "disabled policy ignored");
        assert!(
            !nobody.contains("a_adminlvl") && !nobody.contains("a_readlvl"),
            "other levels ignored"
        );
        assert!(!nobody.contains("a_vrole"), "role_match must match");
        assert!(!nobody.contains("a_plain") && !nobody.contains("a_deny_only"));
        assert!(nobody.contains("a_cls"), "classification-only ABAC allow");
        assert!(
            nobody.contains("a_rd_abac"),
            "ABAC allow covers an unrelated user"
        );
        let wr = ids(&users[1]).await;
        assert!(
            wr.contains("a_wr") && wr.contains("a_secret"),
            "write ACL, incl. over an ABAC deny"
        );
        assert!(!wr.contains("a_rd"));
        assert!(
            ids(&users[2]).await.contains("a_ad"),
            "admin ACL implies write"
        );
        let rd = ids(&users[3]).await;
        assert!(!rd.contains("a_rd"), "read ACL is below write");
        assert!(
            rd.contains("a_rd_abac"),
            "read ACL plus ABAC allow is writable via ABAC"
        );
        assert_eq!(ids(&users[5]).await.len(), assets.len(), "global admin");
        let vic = ids(&users[6]).await;
        assert!(
            vic.contains("a_vic") && vic.contains("a_vrole"),
            "viewer role has no special case"
        );
        assert!(
            ids(&users[0]).await.contains("a_deny_only"),
            "owner beats ABAC deny"
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn writable_asset_ids_without_policies_is_owner_plus_acl(pool: PgPool) {
        for u in ["own", "wr", "rd"] {
            seed_user(&pool, u).await;
        }
        for id in ["a1", "a2", "a3"] {
            seed_asset(&pool, id, "own", false).await;
        }
        seed_acl(&pool, "a1", "wr", "write").await;
        seed_acl(&pool, "a2", "wr", "read").await;
        seed_acl(&pool, "a1", "rd", "read").await;
        let assets = db_assets::list_assets(&pool).await.unwrap();
        let wr = writable_asset_ids(&pool, &auth("wr", "author"), &assets).await;
        assert_eq!(wr, HashSet::from(["a1".to_string()]));
        assert!(writable_asset_ids(&pool, &auth("rd", "author"), &assets)
            .await
            .is_empty());
        assert!(writable_asset_ids(&pool, &auth("own", "author"), &[])
            .await
            .is_empty());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_database_error_denies_in_user_can_but_is_an_error_in_user_can_on(pool: PgPool) {
        seed_user(&pool, "own").await;
        seed_user(&pool, "other").await;
        seed_asset(&pool, "a1", "own", false).await;
        seed_acl(&pool, "a1", "other", "read").await;
        let other = auth("other", "author");
        assert!(user_can(&pool, "a1", &other, "read").await);
        // The ACL lookup now fails: a non-admin is denied, an admin is not.
        sqlx::query("DROP TABLE asset_acl CASCADE")
            .execute(&pool)
            .await
            .unwrap();
        assert!(!user_can(&pool, "a1", &other, "read").await);
        assert!(user_can(&pool, "a1", &auth("root", "admin"), "read").await);
        let mut conn = pool.acquire().await.unwrap();
        assert!(user_can_on(&mut conn, "a1", &other, "read").await.is_err());
        drop(conn);
        // A failed acquire denies too.
        pool.close().await;
        assert!(!user_can(&pool, "a1", &auth("own", "author"), "write").await);
    }
}
