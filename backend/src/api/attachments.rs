use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::db_assets;
use crate::db_attachments::{self, AttachmentRow};
use crate::db_checklists;
use crate::AppState;

// 25 MB per-file cap.
const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("attachments db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn attachments_dir(state: &AppState) -> std::path::PathBuf {
    state.config.data_dir.join("attachments")
}

fn blob_path(state: &AppState, id: &str) -> std::path::PathBuf {
    attachments_dir(state).join(id)
}

/// Resolve a checklist + its owning asset, returning 404 if missing.
async fn load_checklist_and_asset(
    state: &AppState,
    checklist_id: &str,
) -> Result<(db_checklists::ChecklistRow, db_assets::AssetRow), StatusCode> {
    let checklist = db_checklists::get_checklist(state.pool.as_ref(), checklist_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let asset = db_assets::get_asset(state.pool.as_ref(), &checklist.asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok((checklist, asset))
}

/// POST /api/checklists/:id/rules/:rule_id/attachments
///
/// Multipart upload. Owner-only.
pub async fn upload_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((checklist_id, rule_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<AttachmentRow>), StatusCode> {
    let (_checklist, asset) = load_checklist_and_asset(&state, &checklist_id).await?;
    if !asset_acl::user_can(state.pool.as_ref(), &asset.id, &user, "write").await {
        return Err(StatusCode::FORBIDDEN);
    }

    // Ensure attachments dir exists. Cheap idempotent op.
    if let Err(e) = tokio::fs::create_dir_all(attachments_dir(&state)).await {
        tracing::error!("Failed to create attachments dir: {e:#}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let attachment_id = uuid::Uuid::new_v4().to_string();
    let dest = blob_path(&state, &attachment_id);

    let mut filename: Option<String> = None;
    let mut mime_type: Option<String> = None;
    let mut size_bytes: i64 = 0;
    let mut hasher = Sha256::new();
    let mut wrote_file = false;

    while let Some(mut field) = multipart.next_field().await.map_err(|e| {
        tracing::warn!("multipart error: {e:#}");
        StatusCode::BAD_REQUEST
    })? {
        if field.name() != Some("file") {
            continue;
        }
        // Capture filename + mime before streaming the body, since
        // those getters borrow from the field's header view.
        let fname = field
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "attachment".to_string());
        let mime = field
            .content_type()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "application/octet-stream".to_string());

        let mut out = tokio::fs::File::create(&dest).await.map_err(|e| {
            tracing::error!("Failed to create attachment file: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // Stream chunks into the file while tracking size + sha256.
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    let new_total = size_bytes as usize + chunk.len();
                    if new_total > MAX_ATTACHMENT_BYTES {
                        let _ = tokio::fs::remove_file(&dest).await;
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    hasher.update(&chunk);
                    if let Err(e) = out.write_all(&chunk).await {
                        tracing::error!("Failed to write chunk: {e:#}");
                        let _ = tokio::fs::remove_file(&dest).await;
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                    size_bytes = new_total as i64;
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!("multipart chunk error: {e:#}");
                    let _ = tokio::fs::remove_file(&dest).await;
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }

        if let Err(e) = out.flush().await {
            tracing::error!("Failed to flush attachment: {e:#}");
            let _ = tokio::fs::remove_file(&dest).await;
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        filename = Some(fname);
        mime_type = Some(mime);
        wrote_file = true;
        break;
    }

    if !wrote_file {
        return Err(StatusCode::BAD_REQUEST);
    }

    let row = AttachmentRow {
        id: attachment_id.clone(),
        checklist_id: checklist_id.clone(),
        rule_id: rule_id.clone(),
        filename: filename.unwrap_or_else(|| "attachment".into()),
        mime_type: mime_type.unwrap_or_else(|| "application/octet-stream".into()),
        size_bytes,
        sha256: hex::encode(hasher.finalize()),
        uploaded_by: user.id.clone(),
        uploaded_at: chrono::Utc::now(),
    };

    if let Err(e) = db_attachments::insert(state.pool.as_ref(), &row).await {
        tracing::error!("Failed to insert attachment row: {e:#}");
        let _ = tokio::fs::remove_file(&dest).await;
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok((StatusCode::CREATED, Json(row)))
}

/// GET /api/checklists/:id/rules/:rule_id/attachments — list rows for a rule.
pub async fn list_for_rule_handler(
    State(state): State<AppState>,
    Path((checklist_id, rule_id)): Path<(String, String)>,
) -> Result<Json<Vec<AttachmentRow>>, StatusCode> {
    // Confirm the checklist exists so non-existent ids 404 rather than
    // silently returning an empty list.
    let _ = load_checklist_and_asset(&state, &checklist_id).await?;
    let rows = db_attachments::list_for_rule(state.pool.as_ref(), &checklist_id, &rule_id)
        .await
        .map_err(map_db)?;
    Ok(Json(rows))
}

/// GET /api/checklists/:id/attachments — counts per rule for one checklist.
/// Lets the rule list show a paperclip indicator without N round-trips.
pub async fn counts_for_checklist_handler(
    State(state): State<AppState>,
    Path(checklist_id): Path<String>,
) -> Result<Json<Vec<db_attachments::AttachmentCountRow>>, StatusCode> {
    let _ = load_checklist_and_asset(&state, &checklist_id).await?;
    let rows = db_attachments::counts_for_checklist(state.pool.as_ref(), &checklist_id)
        .await
        .map_err(map_db)?;
    Ok(Json(rows))
}

/// GET /api/attachments/:id — stream blob with correct content-type +
/// content-disposition.
pub async fn download_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    let row = db_attachments::get_by_id(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let path = blob_path(&state, &row.id);
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to read attachment blob {}: {e:#}", row.id);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&row.mime_type) {
        headers.insert(header::CONTENT_TYPE, v);
    } else {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
    }
    let safe_name = sanitize_filename(&row.filename);
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=\"{safe_name}\""
    )) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }

    Ok((headers, Body::from(bytes)).into_response())
}

/// DELETE /api/attachments/:id — owner-only. Removes row + blob.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let row = db_attachments::get_by_id(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let (_checklist, asset) = load_checklist_and_asset(&state, &row.checklist_id).await?;
    if !asset_acl::user_can(state.pool.as_ref(), &asset.id, &user, "write").await {
        return Err(StatusCode::FORBIDDEN);
    }

    db_attachments::delete(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?;

    let _ = tokio::fs::remove_file(blob_path(&state, &id)).await;

    Ok(StatusCode::NO_CONTENT)
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect()
}
