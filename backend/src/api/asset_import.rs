use axum::{
    extract::{Multipart, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::api::assets::{normalize_tags, MAX_TAG_LEN};
use crate::api::auth::AuthUser;
use crate::AppState;

/// Allowed asset classifications. Mirrors the frontend Select options.
const VALID_CLASSIFICATIONS: &[&str] = &["unclassified", "cui", "secret", "top-secret"];

#[derive(Debug, Deserialize)]
pub struct ImportQuery {
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportRowResult {
    pub row_number: usize,
    pub name: String,
    pub hostname: String,
    pub classification: String,
    pub tags: Vec<String>,
    /// "ok" | "skipped" | "error"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResponse {
    pub total_rows: usize,
    pub rows: Vec<ImportRowResult>,
    pub created_count: usize,
    pub skipped_count: usize,
}

/// Internal staging row produced from CSV parsing.
struct ParsedRow {
    row_number: usize,
    name: String,
    hostname: String,
    description: String,
    classification: String,
    tags: Vec<String>,
}

/// POST /api/assets/import?dry_run=true|false
///
/// Multipart upload with one `file` field containing a CSV with columns:
/// `name, hostname, description, classification, tags` (tags semicolon-
/// separated inside the cell). When `dry_run=true` no rows are persisted;
/// otherwise valid rows are inserted inside a single transaction so a
/// mid-batch DB failure rolls back the whole import.
pub async fn import_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(query): Query<ImportQuery>,
    mut multipart: Multipart,
) -> Result<Json<ImportResponse>, StatusCode> {
    // Slurp the first 'file' field into a buffer. CSVs are small so we
    // accept the memory cost in exchange for simpler parsing.
    let mut csv_bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::warn!("import multipart error: {e:#}");
        StatusCode::BAD_REQUEST
    })? {
        if field.name() != Some("file") {
            continue;
        }
        let bytes = field.bytes().await.map_err(|e| {
            tracing::warn!("import body read error: {e:#}");
            StatusCode::BAD_REQUEST
        })?;
        csv_bytes = Some(bytes.to_vec());
        break;
    }
    let csv_bytes = csv_bytes.ok_or(StatusCode::BAD_REQUEST)?;

    // Existing names for the current user — used to flag duplicates as
    // "skipped" without performing a DB write per row.
    let existing_names: std::collections::HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT name FROM assets WHERE owner_id = $1",
    )
    .bind(&user.id)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("import: existing-names query failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .into_iter()
    .collect();

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(csv_bytes.as_slice());

    let headers = rdr
        .headers()
        .map_err(|e| {
            tracing::warn!("import: bad CSV headers: {e:#}");
            StatusCode::BAD_REQUEST
        })?
        .clone();

    let col = |name: &str| -> Option<usize> {
        headers
            .iter()
            .position(|h| h.trim().eq_ignore_ascii_case(name))
    };
    let name_idx = col("name");
    let hostname_idx = col("hostname");
    let description_idx = col("description");
    let classification_idx = col("classification");
    let tags_idx = col("tags");

    // 'name' is the only required column. Other columns are optional and
    // default to empty / 'unclassified'.
    if name_idx.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut results: Vec<ImportRowResult> = Vec::new();
    // Track names introduced earlier in the same batch so a CSV with two
    // identical rows reports the second as a duplicate too.
    let mut seen_in_batch: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut to_insert: Vec<ParsedRow> = Vec::new();

    for (i, record) in rdr.records().enumerate() {
        // CSV row number to surface in the UI. Row 1 = headers, data starts at 2.
        let row_number = i + 2;
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                results.push(ImportRowResult {
                    row_number,
                    name: String::new(),
                    hostname: String::new(),
                    classification: String::new(),
                    tags: Vec::new(),
                    status: "error".into(),
                    error: Some(format!("malformed row: {e}")),
                });
                continue;
            }
        };

        let cell = |idx: Option<usize>| -> String {
            idx.and_then(|i| record.get(i))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };

        let name = cell(name_idx);
        let hostname = cell(hostname_idx);
        let description = cell(description_idx);
        let classification_raw = cell(classification_idx);
        let tags_raw = cell(tags_idx);

        if name.is_empty() {
            results.push(ImportRowResult {
                row_number,
                name,
                hostname,
                classification: classification_raw,
                tags: Vec::new(),
                status: "error".into(),
                error: Some("name required".into()),
            });
            continue;
        }

        let classification = if classification_raw.is_empty() {
            "unclassified".to_string()
        } else {
            classification_raw.clone()
        };
        if !VALID_CLASSIFICATIONS.iter().any(|c| *c == classification) {
            results.push(ImportRowResult {
                row_number,
                name,
                hostname,
                classification: classification_raw,
                tags: Vec::new(),
                status: "error".into(),
                error: Some("invalid classification".into()),
            });
            continue;
        }

        // Split semicolons, then run through the same normalizer used by
        // single-asset POST so length/dedup rules stay consistent.
        let raw_tags: Vec<String> = tags_raw
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        // Pre-check long tags so we can attach the offending tag in the message.
        if let Some(bad) = raw_tags
            .iter()
            .find(|t| t.chars().count() > MAX_TAG_LEN)
        {
            results.push(ImportRowResult {
                row_number,
                name,
                hostname,
                classification,
                tags: Vec::new(),
                status: "error".into(),
                error: Some(format!("tag too long: {bad}")),
            });
            continue;
        }
        let tags = match normalize_tags(&raw_tags) {
            Ok(t) => t,
            Err(_) => {
                results.push(ImportRowResult {
                    row_number,
                    name,
                    hostname,
                    classification,
                    tags: Vec::new(),
                    status: "error".into(),
                    error: Some("invalid tags".into()),
                });
                continue;
            }
        };

        if existing_names.contains(&name) || !seen_in_batch.insert(name.clone()) {
            results.push(ImportRowResult {
                row_number,
                name,
                hostname,
                classification,
                tags,
                status: "skipped".into(),
                error: Some("duplicate".into()),
            });
            continue;
        }

        results.push(ImportRowResult {
            row_number,
            name: name.clone(),
            hostname: hostname.clone(),
            classification: classification.clone(),
            tags: tags.clone(),
            status: "ok".into(),
            error: None,
        });
        to_insert.push(ParsedRow {
            row_number,
            name,
            hostname,
            description,
            classification,
            tags,
        });
    }

    let total_rows = results.len();
    let skipped_count = results.iter().filter(|r| r.status == "skipped").count();

    let created_count = if query.dry_run || to_insert.is_empty() {
        0
    } else {
        // All-or-nothing on DB writes: any unexpected insert failure
        // rolls the whole batch back, leaving callers free to retry.
        let mut tx = state.pool.begin().await.map_err(|e| {
            tracing::error!("import: begin tx failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let now = chrono::Utc::now();
        for row in &to_insert {
            let id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO assets
                    (id, name, hostname, description, classification, owner_id, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
                "#,
            )
            .bind(&id)
            .bind(&row.name)
            .bind(&row.hostname)
            .bind(&row.description)
            .bind(&row.classification)
            .bind(&user.id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("import: insert asset failed (row {}): {e:#}", row.row_number);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            for tag in &row.tags {
                sqlx::query("INSERT INTO asset_tags (asset_id, tag) VALUES ($1, $2)")
                    .bind(&id)
                    .bind(tag)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            "import: insert tag failed (row {}, tag {tag}): {e:#}",
                            row.row_number,
                        );
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
            }
        }
        tx.commit().await.map_err(|e| {
            tracing::error!("import: commit failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        to_insert.len()
    };

    Ok(Json(ImportResponse {
        total_rows,
        rows: results,
        created_count,
        skipped_count,
    }))
}
