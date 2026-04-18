use axum::{
    extract::{Extension, Path, State},
    Json,
};

use crate::api::error::ApiError;
use crate::auth::session::SessionData;
use crate::AppState;

/// GET /api/stigs/:id
///
/// Reads the pre-parsed JSON file for the given STIG ID and returns it as-is.
/// The JSON on disk matches the frontend's internal STIG data model exactly.
/// The row must be owned by the session's active org; otherwise 404 so we
/// don't leak cross-tenant existence.
pub async fn get_stig(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Sanitise the id — only allow alphanumeric + hyphens to prevent path traversal.
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(ApiError::BadRequest(
            "id must be alphanumeric with hyphens only".into(),
        ));
    }

    // Tenant gate: the id must belong to the caller's active org. We query
    // by (org_id, id) so leaking a STIG id from another tenant still yields
    // a 404 rather than the parsed JSON on disk.
    let (exists,): (bool,) =
        sqlx::query_as("SELECT EXISTS (SELECT 1 FROM stigs_catalog WHERE org_id = $1 AND id = $2)")
            .bind(session.active_org_id)
            .bind(&id)
            .fetch_one(state.pool.as_ref())
            .await?;
    if !exists {
        return Err(ApiError::NotFound(format!("stig '{id}' not found")));
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
