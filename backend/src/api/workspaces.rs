//! `GET/PUT /api/workspaces/:stig_id` — per-user review state.
//!
//! The workspace stores the user's asset metadata (hostname/IP/MAC/FQDN)
//! and a map of per-rule overrides keyed by rule id: status, finding
//! details, comments. The STIG rules themselves live in the catalog; this
//! table only holds the user-supplied deltas.
//!
//! Isolation: every row is keyed by `(user_sub, stig_id)`. A user can only
//! see or mutate their own row. We never expose `user_sub` in responses.

use axum::{
    extract::{Extension, Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    api::error::ApiError,
    auth::session::SessionData,
    db::{get_workspace, upsert_workspace, Workspace},
    AppState,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceBody {
    #[serde(default = "default_object")]
    pub asset_info: serde_json::Value,
    #[serde(default = "default_object")]
    pub rule_overrides: serde_json::Value,
}

fn default_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceResponse {
    pub stig_id: String,
    pub asset_info: serde_json::Value,
    pub rule_overrides: serde_json::Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<Workspace> for WorkspaceResponse {
    fn from(w: Workspace) -> Self {
        Self {
            stig_id: w.stig_id,
            asset_info: w.asset_info,
            rule_overrides: w.rule_overrides,
            updated_at: w.updated_at,
        }
    }
}

fn validate_stig_id(id: &str) -> Result<(), ApiError> {
    if id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "stig id must be alphanumeric with hyphens only".into(),
        ))
    }
}

pub async fn get(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    Path(stig_id): Path<String>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    validate_stig_id(&stig_id)?;
    let ws = get_workspace(&state.pool, &session.sub, &stig_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no workspace for '{stig_id}'")))?;
    Ok(Json(ws.into()))
}

pub async fn put(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    Path(stig_id): Path<String>,
    Json(body): Json<WorkspaceBody>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    validate_stig_id(&stig_id)?;
    // JSONB columns want objects; reject anything else rather than silently
    // storing scalars or arrays that the frontend can't deserialize.
    if !body.asset_info.is_object() || !body.rule_overrides.is_object() {
        return Err(ApiError::BadRequest(
            "assetInfo and ruleOverrides must both be JSON objects".into(),
        ));
    }
    let ws = upsert_workspace(
        &state.pool,
        &session.sub,
        &stig_id,
        &body.asset_info,
        &body.rule_overrides,
    )
    .await?;
    Ok(Json(ws.into()))
}
