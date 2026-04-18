use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Extension, Multipart, State},
    Json,
};
use chrono::Utc;

use crate::{
    api::error::ApiError,
    audit::{self, AuditEntry},
    auth::session::SessionData,
    db::{upsert_catalog, CatalogEntry},
    parser::{extract_all_from_library, extract_xccdf_from_zip, parse_xccdf},
    AppState,
};

/// POST /api/upload
///
/// Multipart form fields (order-independent):
///   file     — DISA STIG ZIP (required)
///   id       — machine-readable slug, e.g. "windows-11" (required)
///   category — Windows / Linux / Browser / Network (required)
pub async fn upload_stig(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut zip_bytes: Option<Vec<u8>> = None;
    let mut id: Option<String> = None;
    let mut category: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("multipart error: {e}")))?
    {
        match field.name() {
            Some("file") => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("reading file field: {e}")))?;
                zip_bytes = Some(bytes.to_vec());
            }
            Some("id") => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("reading id field: {e}")))?;
                if !text.chars().all(|c| c.is_alphanumeric() || c == '-') {
                    return Err(ApiError::BadRequest(
                        "id must be alphanumeric with hyphens only".into(),
                    ));
                }
                id = Some(text);
            }
            Some("category") => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("reading category field: {e}")))?;
                category = Some(text);
            }
            _ => {}
        }
    }

    let zip_bytes = zip_bytes.ok_or_else(|| ApiError::BadRequest("missing 'file' field".into()))?;
    let id = id.ok_or_else(|| ApiError::BadRequest("missing 'id' field".into()))?;
    let category =
        category.ok_or_else(|| ApiError::BadRequest("missing 'category' field".into()))?;

    let limit = state.config.max_upload_bytes;
    if zip_bytes.len() > limit {
        return Err(ApiError::PayloadTooLarge {
            message: format!(
                "file exceeds MAX_UPLOAD_BYTES ({} > {})",
                zip_bytes.len(),
                limit
            ),
            limit_bytes: limit,
            actual_bytes: zip_bytes.len(),
        });
    }

    let xccdf = extract_xccdf_from_zip(&zip_bytes)
        .map_err(|e| ApiError::Unprocessable(format!("ZIP extraction failed: {e}")))?;

    let stig = parse_xccdf(&xccdf)
        .map_err(|e| ApiError::Unprocessable(format!("XCCDF parse failed: {e}")))?;

    let stigs_dir = state.config.data_dir.join("stigs");
    tokio::fs::create_dir_all(&stigs_dir).await?;

    let json_path = stigs_dir.join(format!("{id}.json"));
    let json_str = serde_json::to_string(&stig)?;
    tokio::fs::write(&json_path, &json_str).await?;

    let rule_count = stig.rules.len() as i32;
    let title = if stig.title.is_empty() {
        id.clone()
    } else {
        stig.title.clone()
    };
    let entry = CatalogEntry {
        id: id.clone(),
        title: title.clone(),
        category: category.clone(),
        version: stig.version.clone(),
        release_info: stig.release_info.clone(),
        rule_count,
        json_path: json_path.to_string_lossy().into_owned(),
        last_updated: Utc::now(),
    };
    upsert_catalog(&state.pool, &entry)
        .await
        .map_err(|e| ApiError::Internal(format!("catalog upsert: {e}")))?;

    tracing::info!("Uploaded STIG '{id}' ({title}): {rule_count} rules");

    audit::log(
        &state.pool,
        AuditEntry {
            session: &session,
            action: "upload.stig",
            resource: Some(&id),
            remote_ip: Some(addr.ip().to_string()),
            status_code: 200,
            metadata: Some(serde_json::json!({
                "title": title,
                "category": category,
                "ruleCount": rule_count,
                "version": stig.version,
            })),
        },
    )
    .await;

    Ok(Json(serde_json::json!({
        "id": id,
        "title": title,
        "category": category,
        "version": stig.version,
        "ruleCount": rule_count,
    })))
}

/// POST /api/upload/library
///
/// Accepts a DISA SRG/STIG Library bundle ZIP. Iterates every `*_STIG.zip`
/// inside, parses each XCCDF, writes JSON files, and upserts catalog rows.
pub async fn upload_library(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut zip_bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("multipart error: {e}")))?
    {
        if field.name() == Some("file") {
            let bytes = field
                .bytes()
                .await
                .map_err(|e| ApiError::BadRequest(format!("reading file field: {e}")))?;
            zip_bytes = Some(bytes.to_vec());
        }
    }
    let zip_bytes = zip_bytes.ok_or_else(|| ApiError::BadRequest("missing 'file' field".into()))?;

    let limit = state.config.max_library_bytes;
    if zip_bytes.len() > limit {
        return Err(ApiError::PayloadTooLarge {
            message: format!(
                "library bundle exceeds MAX_LIBRARY_BYTES ({} > {})",
                zip_bytes.len(),
                limit
            ),
            limit_bytes: limit,
            actual_bytes: zip_bytes.len(),
        });
    }

    tracing::info!(
        "Library bundle received ({} MB), processing…",
        zip_bytes.len() / 1_048_576
    );

    let (lib_entries, parse_errors) =
        tokio::task::spawn_blocking(move || extract_all_from_library(&zip_bytes))
            .await
            .map_err(|e| ApiError::Internal(format!("task panic: {e}")))?;

    let stigs_dir = state.config.data_dir.join("stigs");
    tokio::fs::create_dir_all(&stigs_dir).await?;

    let mut imported = 0usize;
    let mut db_errors: Vec<serde_json::Value> = Vec::new();

    for entry in lib_entries {
        let json_path = stigs_dir.join(format!("{}.json", entry.id));

        let json_str = match serde_json::to_string(&entry.stig) {
            Ok(s) => s,
            Err(e) => {
                db_errors.push(serde_json::json!({"id": entry.id, "error": e.to_string()}));
                continue;
            }
        };
        if let Err(e) = tokio::fs::write(&json_path, &json_str).await {
            db_errors.push(serde_json::json!({"id": entry.id, "error": e.to_string()}));
            continue;
        }

        let rule_count = entry.stig.rules.len() as i32;
        let title = if entry.stig.title.is_empty() {
            entry.id.clone()
        } else {
            entry.stig.title.clone()
        };

        let catalog_entry = CatalogEntry {
            id: entry.id.clone(),
            title: title.clone(),
            category: entry.category,
            version: entry.stig.version,
            release_info: entry.stig.release_info,
            rule_count,
            json_path: json_path.to_string_lossy().into_owned(),
            last_updated: Utc::now(),
        };

        match upsert_catalog(&state.pool, &catalog_entry).await {
            Ok(_) => {
                tracing::info!("  Imported '{}' ({title}): {rule_count} rules", entry.id);
                imported += 1;
            }
            Err(e) => {
                db_errors.push(serde_json::json!({"id": entry.id, "error": e.to_string()}));
            }
        }
    }

    let mut all_errors: Vec<serde_json::Value> = parse_errors
        .iter()
        .map(|(id, e)| serde_json::json!({"id": id, "error": e}))
        .collect();
    all_errors.extend(db_errors);

    let total_errors = all_errors.len();
    tracing::info!("Library import complete: {imported} imported, {total_errors} errors");

    audit::log(
        &state.pool,
        AuditEntry {
            session: &session,
            action: "upload.library",
            resource: None,
            remote_ip: Some(addr.ip().to_string()),
            status_code: 200,
            metadata: Some(serde_json::json!({
                "imported": imported,
                "errors": total_errors,
            })),
        },
    )
    .await;

    Ok(Json(serde_json::json!({
        "imported": imported,
        "errors": total_errors,
        "errorDetail": all_errors,
    })))
}
