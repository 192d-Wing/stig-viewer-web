//! `GET /api/audit` — admin-only paginated audit log reader.

use axum::{
    extract::{Extension, Query, State},
    Json,
};
use serde::Deserialize;

use crate::{
    api::error::ApiError,
    audit::{self, AuditEvent},
    auth::{session::SessionData, Role},
    AppState,
};

#[derive(Deserialize)]
pub struct ListQuery {
    /// Max rows to return (1..=500). Default 100.
    limit: Option<i64>,
    /// Cursor: return rows with id < this value. Combine with the last id
    /// from the previous page for keyset pagination.
    before_id: Option<i64>,
}

pub async fn list_audit(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<AuditEvent>>, ApiError> {
    if session.role != Role::Admin {
        return Err(ApiError::Forbidden);
    }
    let rows = audit::list(
        &state.pool,
        session.active_org_id,
        q.limit.unwrap_or(100),
        q.before_id,
    )
    .await?;
    Ok(Json(rows))
}
