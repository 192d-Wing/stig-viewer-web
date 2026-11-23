use axum::{
    extract::{Multipart, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::api::assets::{normalize_tags, MAX_TAG_LEN};
use crate::api::audit_tx;
use crate::api::auth::AuthUser;
use crate::api::request_ctx::RequestCtx;
use crate::AppState;

/// Most created asset ids listed in the `asset.import` audit row.
const MAX_AUDITED_IDS: usize = 200;

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
    Extension(ctx): Extension<RequestCtx>,
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
    let existing_names: std::collections::HashSet<String> =
        sqlx::query_scalar::<_, String>("SELECT name FROM assets WHERE owner_id = $1")
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
        if let Some(bad) = raw_tags.iter().find(|t| t.chars().count() > MAX_TAG_LEN) {
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
        let mut created_ids: Vec<String> = Vec::with_capacity(to_insert.len());
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
            created_ids.push(id);
        }
        // One summary row in the import's transaction, so a bulk import is not
        // an unaudited way to create assets; a failed row rolls the batch back.
        // The import has no row cap (only the request body limit), so the id
        // list is capped; `assetIdsTruncated` says when it was.
        let listed = &created_ids[..created_ids.len().min(MAX_AUDITED_IDS)];
        let ev = audit_tx::ok_event(
            &user,
            &ctx,
            "asset.import",
            serde_json::json!({
                "created": to_insert.len(),
                "assetIds": listed,
                "assetIdsTruncated": created_ids.len() > listed.len(),
            }),
        );
        audit_tx::record(&mut tx, &ev)
            .await
            .map_err(audit_tx::failed)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{app_state, audit_rows, auth, ctx, fail_audit_inserts, seed_user};
    use axum::extract::FromRequest;
    use sqlx::PgPool;

    const CSV: &str = "name,hostname,classification,tags\nweb1,h1,unclassified,a;b\nweb2,h2,cui,\n";

    async fn run(pool: &PgPool, dry_run: bool) -> Result<Json<ImportResponse>, StatusCode> {
        run_csv(pool, dry_run, CSV).await
    }

    async fn run_csv(
        pool: &PgPool,
        dry_run: bool,
        csv: &str,
    ) -> Result<Json<ImportResponse>, StatusCode> {
        let (state, _dir) = app_state(pool.clone());
        let payload = format!(
            "--XB\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.csv\"\r\n\
             Content-Type: text/csv\r\n\r\n{csv}\r\n--XB--\r\n"
        );
        let req = axum::http::Request::builder()
            .header(
                axum::http::header::CONTENT_TYPE,
                "multipart/form-data; boundary=XB",
            )
            .body(axum::body::Body::from(payload))
            .unwrap();
        let multipart = Multipart::from_request(req, &()).await.unwrap();
        import_handler(
            State(state),
            Extension(auth("owner", "author")),
            Extension(ctx()),
            Query(ImportQuery { dry_run }),
            multipart,
        )
        .await
    }

    async fn assets(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM assets")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_import_records_one_summary_row_and_none_on_a_dry_run(pool: PgPool) {
        seed_user(&pool, "owner").await;
        let Json(dry) = run(&pool, true).await.unwrap();
        assert_eq!(dry.created_count, 0);
        assert!(audit_rows(&pool, "asset.import").await.is_empty());

        let Json(done) = run(&pool, false).await.unwrap();
        assert_eq!(done.created_count, 2);
        let rows = audit_rows(&pool, "asset.import").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome, "ok");
        assert_eq!(rows[0].user_id.as_deref(), Some("owner"));
        assert_eq!(
            rows[0].detail_keys(),
            ["assetIds", "assetIdsTruncated", "created"]
        );
        assert_eq!(rows[0].detail["created"], 2);
        assert_eq!(rows[0].detail["assetIdsTruncated"], false);
        let mut listed: Vec<String> = rows[0].detail["assetIds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let mut stored: Vec<String> = sqlx::query_scalar("SELECT id FROM assets")
            .fetch_all(&pool)
            .await
            .unwrap();
        listed.sort();
        stored.sort();
        assert_eq!(listed, stored);
        assert_eq!(rows[0].request_id.as_deref(), Some("test-request"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_import_fails_closed_when_the_audit_row_cannot_be_written(pool: PgPool) {
        seed_user(&pool, "owner").await;
        fail_audit_inserts(&pool, &["asset.import"]).await;
        assert_eq!(
            run(&pool, false).await.err(),
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert_eq!(assets(&pool).await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_refused_or_empty_import_writes_no_audit_row(pool: PgPool) {
        seed_user(&pool, "owner").await;
        // Everything is a duplicate of an existing asset: nothing is created.
        let _ = run(&pool, false).await.unwrap();
        let Json(again) = run(&pool, false).await.unwrap();
        assert_eq!(again.created_count, 0);
        assert_eq!(audit_rows(&pool, "asset.import").await.len(), 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_large_import_lists_at_most_200_asset_ids(pool: PgPool) {
        seed_user(&pool, "owner").await;
        let mut csv = String::from("name\n");
        for i in 0..201 {
            csv.push_str(&format!("host{i}\n"));
        }
        let Json(done) = run_csv(&pool, false, &csv).await.unwrap();
        assert_eq!(done.created_count, 201);
        let rows = audit_rows(&pool, "asset.import").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].detail["created"], 201);
        assert_eq!(rows[0].detail["assetIds"].as_array().unwrap().len(), 200);
        assert_eq!(rows[0].detail["assetIdsTruncated"], true);
    }
}
