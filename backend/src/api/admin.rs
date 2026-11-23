use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::audit_tx;
use crate::api::auth::AuthUser;
use crate::api::request_ctx::RequestCtx;
use crate::db_audit;
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
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;
    if !VALID_ROLES.contains(&req.role.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    // The change and its `user.role_change` row commit together.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    let from: Option<String> =
        sqlx::query_scalar("SELECT role FROM users WHERE id = $1 FOR NO KEY UPDATE")
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx)?;
    let Some(from) = from else {
        return Err(StatusCode::NOT_FOUND);
    };
    sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
        .bind(&req.role)
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    let ev = audit_tx::ok_event(
        &user,
        &ctx,
        "user.role_change",
        json!({
            "targetUserId": db_audit::audit_safe_id(&id),
            "fromRole": from,
            "toRole": req.role,
        }),
    );
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;
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
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
    Json(req): Json<UpdateOwnerRequest>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;

    // The reassignment and its `asset.owner_change` row commit together.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;

    // Verify the asset exists (and lock it, so the recorded previous owner is
    // the one replaced).
    let from: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM assets WHERE id = $1 FOR NO KEY UPDATE")
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx)?;
    let Some(from) = from else {
        return Err(StatusCode::NOT_FOUND);
    };

    // Verify the new owner exists.
    let owner_exists: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
        .bind(&req.owner_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    if owner_exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    sqlx::query("UPDATE assets SET owner_id = $1, updated_at = NOW() WHERE id = $2")
        .bind(&req.owner_id)
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;

    let mut ev = audit_tx::ok_event(
        &user,
        &ctx,
        "asset.owner_change",
        json!({
            "fromOwnerId": db_audit::audit_safe_id(&from),
            "toOwnerId": db_audit::audit_safe_id(&req.owner_id),
        }),
    );
    ev.asset_id = Some(&id);
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{
        app_state, audit_rows, auth, ctx, fail_audit_inserts, seed_asset, seed_user,
    };
    use sqlx::PgPool;

    async fn set_role(pool: &PgPool, target: &str, role: &str) -> Result<StatusCode, StatusCode> {
        let (state, _dir) = app_state(pool.clone());
        update_user_role_handler(
            State(state),
            Extension(auth("root", "admin")),
            Extension(ctx()),
            Path(target.into()),
            Json(UpdateRoleRequest { role: role.into() }),
        )
        .await
    }

    async fn set_owner(pool: &PgPool, asset: &str, owner: &str) -> Result<StatusCode, StatusCode> {
        let (state, _dir) = app_state(pool.clone());
        update_asset_owner_handler(
            State(state),
            Extension(auth("root", "admin")),
            Extension(ctx()),
            Path(asset.into()),
            Json(UpdateOwnerRequest {
                owner_id: owner.into(),
            }),
        )
        .await
    }

    async fn base(pool: &PgPool) {
        for u in ["root", "u1", "u2"] {
            seed_user(pool, u).await;
        }
        seed_asset(pool, "a1", "u1", false).await;
    }

    async fn role_of(pool: &PgPool, id: &str) -> String {
        sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn user_role_change_is_recorded_with_from_and_to(pool: PgPool) {
        base(&pool).await;
        assert_eq!(
            set_role(&pool, "u1", "reviewer").await,
            Ok(StatusCode::NO_CONTENT)
        );
        let rows = audit_rows(&pool, "user.role_change").await;
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.user_id.as_deref(), Some("root"));
        assert_eq!(r.asset_id, None);
        assert_eq!(r.detail_keys(), ["fromRole", "targetUserId", "toRole"]);
        assert_eq!(r.detail["fromRole"], "author");
        assert_eq!(r.detail["toRole"], "reviewer");
        assert_eq!(r.detail["targetUserId"], "u1");
        assert_eq!(r.request_id.as_deref(), Some("test-request"));
        assert_eq!(r.source_ip.as_deref(), Some("198.51.100.4"));
        // An unknown user is a 404 and writes no row.
        assert_eq!(
            set_role(&pool, "nobody", "admin").await,
            Err(StatusCode::NOT_FOUND)
        );
        assert_eq!(audit_rows(&pool, "user.role_change").await.len(), 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn user_role_change_fails_closed_when_the_audit_row_cannot_be_written(pool: PgPool) {
        base(&pool).await;
        fail_audit_inserts(&pool, &["user.role_change"]).await;
        assert_eq!(
            set_role(&pool, "u1", "admin").await,
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert_eq!(role_of(&pool, "u1").await, "author");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_owner_change_is_recorded_with_from_and_to(pool: PgPool) {
        base(&pool).await;
        assert_eq!(
            set_owner(&pool, "a1", "u2").await,
            Ok(StatusCode::NO_CONTENT)
        );
        let rows = audit_rows(&pool, "asset.owner_change").await;
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.asset_id.as_deref(), Some("a1"));
        assert_eq!(r.detail_keys(), ["fromOwnerId", "toOwnerId"]);
        assert_eq!(r.detail["fromOwnerId"], "u1");
        assert_eq!(r.detail["toOwnerId"], "u2");
        assert_eq!(r.request_id.as_deref(), Some("test-request"));
        assert_eq!(
            set_owner(&pool, "nope", "u2").await,
            Err(StatusCode::NOT_FOUND)
        );
        assert_eq!(
            set_owner(&pool, "a1", "nobody").await,
            Err(StatusCode::NOT_FOUND)
        );
        assert_eq!(audit_rows(&pool, "asset.owner_change").await.len(), 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_owner_change_fails_closed_when_the_audit_row_cannot_be_written(pool: PgPool) {
        base(&pool).await;
        fail_audit_inserts(&pool, &["asset.owner_change"]).await;
        assert_eq!(
            set_owner(&pool, "a1", "u2").await,
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        );
        let owner: String = sqlx::query_scalar("SELECT owner_id FROM assets WHERE id = 'a1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(owner, "u1");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn refused_admin_requests_write_no_audit_row(pool: PgPool) {
        base(&pool).await;
        let (state, _dir) = app_state(pool.clone());
        let denied = update_user_role_handler(
            State(state.clone()),
            Extension(auth("u1", "author")),
            Extension(ctx()),
            Path("u2".into()),
            Json(UpdateRoleRequest {
                role: "admin".into(),
            }),
        )
        .await;
        assert_eq!(denied, Err(StatusCode::FORBIDDEN));
        assert_eq!(
            set_role(&pool, "u1", "godking").await,
            Err(StatusCode::BAD_REQUEST)
        );
        let denied = update_asset_owner_handler(
            State(state),
            Extension(auth("u1", "author")),
            Extension(ctx()),
            Path("a1".into()),
            Json(UpdateOwnerRequest {
                owner_id: "u2".into(),
            }),
        )
        .await;
        assert_eq!(denied, Err(StatusCode::FORBIDDEN));
        for a in ["user.role_change", "asset.owner_change"] {
            assert!(audit_rows(&pool, a).await.is_empty(), "{a}");
        }
    }
}
