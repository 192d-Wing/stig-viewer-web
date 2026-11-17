use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use crate::AppState;

/// GET /api/stigs/:id
///
/// Reads the pre-parsed JSON file for the given STIG ID and returns it as-is.
/// The JSON on disk matches the frontend's internal STIG data model exactly.
pub async fn get_stig(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    // Shared id rule; also prevents path traversal
    if !crate::stig_id::is_valid(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let path = state.config.data_dir.join("stigs").join(format!("{id}.json"));

    let contents = tokio::fs::read_to_string(&path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StatusCode::NOT_FOUND
        } else {
            tracing::error!("Failed to read {}: {e:#}", path.display());
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;

    // Parse to Value so axum re-serialises with correct Content-Type
    let value: serde_json::Value = serde_json::from_str(&contents).map_err(|e| {
        tracing::error!("Failed to deserialise {}: {e:#}", path.display());
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(value))
}

#[cfg(test)]
mod id_tests {
    use super::*;
    use crate::test_fixtures::{bad_ids, lazy_state};

    #[tokio::test]
    async fn invalid_ids_are_rejected_before_any_file_access() {
        let (state, _dir) = lazy_state();
        for id in bad_ids() {
            let r = get_stig(State(state.clone()), Path(id.clone())).await;
            assert!(matches!(r, Err(StatusCode::BAD_REQUEST)), "{id:?}");
        }
    }
}
