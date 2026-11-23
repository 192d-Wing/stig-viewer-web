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
use serde_json::json;

use crate::api::audit_tx;
use crate::api::auth::AuthUser;
use crate::api::request_ctx::RequestCtx;
use crate::db_audit;
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
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;
    // The revoke and its `session.revoke` row commit together. The session id
    // is the cookie value: it is never put in the event or in a log line.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    let row: Option<(String, bool)> = sqlx::query_as(
        "WITH old AS (SELECT user_id, revoked_at FROM sessions WHERE id = $1 FOR UPDATE) \
         UPDATE sessions s SET revoked_at = COALESCE(s.revoked_at, NOW()) \
           FROM old WHERE s.id = $1 \
         RETURNING old.user_id, (old.revoked_at IS NOT NULL)",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_sqlx)?;
    let Some((target_user_id, already_revoked)) = row else {
        return Err(StatusCode::NOT_FOUND);
    };
    let ev = audit_tx::ok_event(
        &user,
        &ctx,
        "session.revoke",
        json!({
            "targetUserId": db_audit::audit_safe_id(&target_user_id),
            "alreadyRevoked": already_revoked,
        }),
    );
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{app_state, audit_rows, auth, ctx, fail_audit_inserts, seed_user};
    use sqlx::PgPool;

    async fn base(pool: &PgPool) -> String {
        seed_user(pool, "root").await;
        seed_user(pool, "u1").await;
        let sid = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, 'u1', NOW() + INTERVAL '1 day')",
        )
        .bind(&sid)
        .execute(pool)
        .await
        .unwrap();
        sid
    }

    async fn revoke(pool: &PgPool, sid: &str) -> Result<StatusCode, StatusCode> {
        let (state, _dir) = app_state(pool.clone());
        revoke_handler(
            State(state),
            Extension(auth("root", "admin")),
            Extension(ctx()),
            Path(sid.into()),
        )
        .await
    }

    async fn revoked(pool: &PgPool, sid: &str) -> bool {
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1")
            .bind(sid)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn session_revoke_is_recorded_without_the_session_id(pool: PgPool) {
        let sid = base(&pool).await;
        assert_eq!(revoke(&pool, &sid).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(revoke(&pool, &sid).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(revoke(&pool, "missing").await, Err(StatusCode::NOT_FOUND));
        let rows = audit_rows(&pool, "session.revoke").await;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].outcome, "ok");
        assert_eq!(rows[0].user_id.as_deref(), Some("root"));
        assert_eq!(rows[0].detail_keys(), ["alreadyRevoked", "targetUserId"]);
        assert_eq!(rows[0].detail["targetUserId"], "u1");
        assert_eq!(rows[0].detail["alreadyRevoked"], false);
        assert_eq!(rows[1].detail["alreadyRevoked"], true);
        assert_eq!(rows[0].request_id.as_deref(), Some("test-request"));
        let text: String = sqlx::query_scalar(
            "SELECT string_agg(detail::text || COALESCE(request_id, ''), ' ') FROM audit_events WHERE action = 'session.revoke'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!text.contains(&sid), "{text}");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn session_revoke_fails_closed_when_the_audit_row_cannot_be_written(pool: PgPool) {
        let sid = base(&pool).await;
        fail_audit_inserts(&pool, &["session.revoke"]).await;
        assert_eq!(
            revoke(&pool, &sid).await,
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert!(!revoked(&pool, &sid).await);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn refused_session_revokes_write_no_audit_row(pool: PgPool) {
        let sid = base(&pool).await;
        let (state, _dir) = app_state(pool.clone());
        let denied = revoke_handler(
            State(state),
            Extension(auth("u1", "author")),
            Extension(ctx()),
            Path(sid.clone()),
        )
        .await;
        assert_eq!(denied, Err(StatusCode::FORBIDDEN));
        assert_eq!(revoke(&pool, "missing").await, Err(StatusCode::NOT_FOUND));
        assert!(!revoked(&pool, &sid).await);
        assert!(audit_rows(&pool, "session.revoke").await.is_empty());
    }
}
