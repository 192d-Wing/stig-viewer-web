use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;

use crate::api::auth::AuthUser;
use crate::db_assets;
use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAssetRequest {
    pub name: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_classification")]
    pub classification: String,
}

fn default_classification() -> String {
    "unclassified".into()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAssetRequest {
    pub name: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub description: String,
    pub classification: String,
}

pub async fn list_assets_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<db_assets::AssetSummary>>, StatusCode> {
    let rows = db_assets::list_assets(state.pool.as_ref())
        .await
        .map_err(map_db)?;
    Ok(Json(rows))
}

pub async fn create_asset_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateAssetRequest>,
) -> Result<(StatusCode, Json<db_assets::AssetRow>), StatusCode> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = chrono::Utc::now();
    let asset = db_assets::AssetRow {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.into(),
        hostname: req.hostname,
        description: req.description,
        classification: req.classification,
        owner_id: user.id.clone(),
        created_at: now,
        updated_at: now,
    };
    db_assets::insert_asset(state.pool.as_ref(), &asset)
        .await
        .map_err(map_db)?;
    Ok((StatusCode::CREATED, Json(asset)))
}

pub async fn get_asset_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<db_assets::AssetRow>, StatusCode> {
    db_assets::get_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)
        .map(Json)
}

pub async fn update_asset_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAssetRequest>,
) -> Result<Json<db_assets::AssetRow>, StatusCode> {
    let existing = db_assets::get_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if existing.owner_id != user.id {
        return Err(StatusCode::FORBIDDEN);
    }

    let name = req.name.trim();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    db_assets::update_asset(
        state.pool.as_ref(),
        &id,
        name,
        &req.hostname,
        &req.description,
        &req.classification,
    )
    .await
    .map_err(map_db)?;

    db_assets::get_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)
        .map(Json)
}

pub async fn delete_asset_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let existing = db_assets::get_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if existing.owner_id != user.id {
        return Err(StatusCode::FORBIDDEN);
    }

    db_assets::delete_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?;
    Ok(StatusCode::NO_CONTENT)
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("assets db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}
