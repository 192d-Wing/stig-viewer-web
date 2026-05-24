use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;

use crate::{
    db::{upsert_catalog, CatalogEntry},
    parser::{extract_all_from_library, extract_xccdf_from_zip, parse_xccdf},
    AppState,
};

/// POST /api/upload
///
/// Accepts a multipart form upload with the following fields (order-independent):
///   file     — the DISA STIG ZIP (required)
///   id       — machine-readable slug, e.g. "windows-11" (required)
///   category — one of Windows / Linux / Browser / Network (required)
///
/// Example:
///   curl -X POST http://localhost:8080/api/upload \
///        -F "file=@U_MS_Windows_11_V2R3_STIG.zip" \
///        -F "id=windows-11" \
///        -F "category=Windows"
pub async fn upload_stig(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut zip_bytes: Option<Vec<u8>> = None;
    let mut id: Option<String> = None;
    let mut category: Option<String> = None;

    // Collect all multipart fields
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Multipart error: {e}"))
    })? {
        match field.name() {
            Some("file") => {
                let bytes = field.bytes().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Failed to read file field: {e}"))
                })?;
                zip_bytes = Some(bytes.to_vec());
            }
            Some("id") => {
                let text = field.text().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Failed to read id field: {e}"))
                })?;
                // Validate id — alphanumeric + hyphens only
                if !text.chars().all(|c| c.is_alphanumeric() || c == '-') {
                    return Err((StatusCode::BAD_REQUEST, "id must be alphanumeric with hyphens only".into()));
                }
                id = Some(text);
            }
            Some("category") => {
                let text = field.text().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, format!("Failed to read category field: {e}"))
                })?;
                category = Some(text);
            }
            _ => {} // ignore unknown fields
        }
    }

    let zip_bytes = zip_bytes.ok_or((StatusCode::BAD_REQUEST, "Missing 'file' field".into()))?;
    let id = id.ok_or((StatusCode::BAD_REQUEST, "Missing 'id' field".into()))?;
    let category = category.ok_or((StatusCode::BAD_REQUEST, "Missing 'category' field".into()))?;

    // Extract and parse XCCDF
    let xccdf = extract_xccdf_from_zip(&zip_bytes).map_err(|e| {
        (StatusCode::UNPROCESSABLE_ENTITY, format!("ZIP extraction failed: {e}"))
    })?;

    let stig = parse_xccdf(&xccdf).map_err(|e| {
        (StatusCode::UNPROCESSABLE_ENTITY, format!("XCCDF parse failed: {e}"))
    })?;

    // Write JSON file
    let stigs_dir = state.config.data_dir.join("stigs");
    tokio::fs::create_dir_all(&stigs_dir).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create data dir: {e}"))
    })?;

    let json_path = stigs_dir.join(format!("{id}.json"));
    let json_str = serde_json::to_string(&stig).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialisation failed: {e}"))
    })?;
    tokio::fs::write(&json_path, &json_str).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write JSON: {e}"))
    })?;

    // Upsert catalog row
    let rule_count = stig.rules.len() as i32;
    let title = if stig.title.is_empty() { id.clone() } else { stig.title.clone() };
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
    upsert_catalog(&state.pool, &entry).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database upsert failed: {e}"))
    })?;

    tracing::info!("Uploaded STIG '{id}' ({title}): {rule_count} rules");

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
/// Accepts a DISA SRG/STIG Library bundle ZIP (the big all-in-one download).
/// Iterates every `*_STIG.zip` inside, parses each XCCDF, auto-assigns an ID
/// from the inner filename and a category from the XCCDF title, then writes
/// JSON files and upserts all catalog rows in one pass.
///
/// Body limit: 500 MB (set on the route in main.rs).
///
/// Example:
///   curl -X POST http://localhost:8080/api/upload/library \
///        -F "file=@U_SRG-STIG_Library_January_2026.zip"
pub async fn upload_library(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Read the single 'file' field
    let mut zip_bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Multipart error: {e}"))
    })? {
        if field.name() == Some("file") {
            let bytes = field.bytes().await.map_err(|e| {
                (StatusCode::BAD_REQUEST, format!("Failed to read file field: {e}"))
            })?;
            zip_bytes = Some(bytes.to_vec());
        }
    }
    let zip_bytes = zip_bytes.ok_or((StatusCode::BAD_REQUEST, "Missing 'file' field".into()))?;

    tracing::info!("Library bundle received ({} MB), processing…", zip_bytes.len() / 1_048_576);

    // Parsing is CPU-bound — run on blocking thread pool
    let (lib_entries, parse_errors) =
        tokio::task::spawn_blocking(move || extract_all_from_library(&zip_bytes))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Task panic: {e}")))?;

    // Write JSON files and upsert catalog rows
    let stigs_dir = state.config.data_dir.join("stigs");
    tokio::fs::create_dir_all(&stigs_dir).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create data dir: {e}"))
    })?;

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

    Ok(Json(serde_json::json!({
        "imported": imported,
        "errors": total_errors,
        "errorDetail": all_errors,
    })))
}
