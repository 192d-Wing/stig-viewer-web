use axum::{
    extract::{Extension, Query, State},
    Json,
};
use serde::Deserialize;

use crate::api::error::ApiError;
use crate::auth::session::SessionData;
use crate::db::{count_catalog, list_catalog};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct CatalogQuery {
    pub category: Option<String>,
}

/// GET /api/catalog[?category=Windows]
pub async fn get_catalog(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    Query(params): Query<CatalogQuery>,
) -> Result<Json<Vec<crate::db::CatalogEntry>>, ApiError> {
    let entries = list_catalog(
        &state.pool,
        session.active_org_id,
        params.category.as_deref(),
    )
    .await?;
    Ok(Json(entries))
}

/// GET /api/health — public, so not per-org scoped; reports the default org.
pub async fn get_health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let count = count_catalog(&state.pool, state.default_org.id)
        .await
        .unwrap_or(0);
    Json(serde_json::json!({
        "status": "ok",
        "stig_count": count,
    }))
}
