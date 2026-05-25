use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

use crate::db::list_catalog;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct CatalogQuery {
    pub category: Option<String>,
}

/// GET /api/catalog[?category=Windows]
pub async fn get_catalog(
    State(state): State<AppState>,
    Query(params): Query<CatalogQuery>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let entries = list_catalog(&state.pool, params.category.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("catalog query failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(entries))
}
