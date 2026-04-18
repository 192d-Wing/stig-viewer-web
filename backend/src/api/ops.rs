//! Operational endpoints: liveness, readiness, and manual DISA sync.
//!
//! - `GET /api/livez` — 200 as long as the process is answering requests.
//! - `GET /api/readyz` — 200 once we can round-trip the database; 503
//!   otherwise. Load balancers should use this.
//! - `POST /api/sync` — admin-only; triggers a DISA sync in the background
//!   and returns 202 immediately.
//!
//! `/api/health` is retained as an alias for `/api/readyz` so existing
//! probes keep working.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};

use crate::{
    api::error::ApiError,
    audit::{self, AuditEntry},
    auth::{session::SessionData, Role},
    AppState,
};

pub async fn livez() -> StatusCode {
    StatusCode::OK
}

pub async fn readyz(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(state.pool.as_ref())
        .await
    {
        Ok(_) => Ok(Json(serde_json::json!({"status": "ready"}))),
        Err(e) => {
            tracing::warn!("readyz: db probe failed: {e}");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "not_ready",
                    "reason": "database unreachable",
                })),
            ))
        }
    }
}

pub async fn trigger_sync(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if session.role != Role::Admin {
        return Err(ApiError::Forbidden);
    }
    let Some(sources) = state.sources.clone() else {
        return Err(ApiError::Internal(
            "stig-sources.toml not loaded — sync disabled".into(),
        ));
    };
    let config = state.config.clone();
    let pool = state.pool.clone();
    let sources_count = sources.len();

    // Fire-and-forget. Errors land in tracing; the caller just sees 202.
    tokio::spawn(async move {
        if let Err(e) = crate::sync::run_sync(&config, &sources, &pool).await {
            tracing::error!("Manual sync failed: {e:#}");
        }
    });

    audit::log(
        &state.pool,
        AuditEntry {
            session: &session,
            action: "ops.sync",
            resource: None,
            remote_ip: None,
            status_code: 202,
            metadata: Some(serde_json::json!({ "sources": sources_count })),
        },
    )
    .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "accepted": true,
            "sources": sources_count,
        })),
    ))
}
