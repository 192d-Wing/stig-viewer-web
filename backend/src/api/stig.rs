use axum::{
    extract::{Path, State},
    Json,
};

use crate::api::error::ApiError;
use crate::AppState;

/// GET /api/stigs/:id
///
/// Reads the pre-parsed JSON file for the given STIG ID and returns it as-is.
/// The JSON on disk matches the frontend's internal STIG data model exactly.
pub async fn get_stig(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Sanitise the id — only allow alphanumeric + hyphens to prevent path traversal.
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(ApiError::BadRequest(
            "id must be alphanumeric with hyphens only".into(),
        ));
    }

    let path = state
        .config
        .data_dir
        .join("stigs")
        .join(format!("{id}.json"));

    let contents = match tokio::fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiError::NotFound(format!("stig '{id}' not found")));
        }
        Err(e) => return Err(ApiError::Internal(format!("read {}: {e}", path.display()))),
    };

    let value: serde_json::Value = serde_json::from_str(&contents)?;
    Ok(Json(value))
}
