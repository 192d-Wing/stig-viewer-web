//! Admin backup + restore.
//!
//! GET  /api/admin/backup  — streams a ZIP of all user-generated tables
//!                           as JSONL plus the attachment blobs from
//!                           `${data_dir}/attachments/`.
//! POST /api/admin/restore — multipart upload of the same ZIP. Optionally
//!                           force-truncates the existing data first.
//!
//! The STIG catalog itself is intentionally NOT included — those JSON
//! files are sourced externally and live under `${data_dir}/stigs/`. The
//! same goes for transient runtime tables (sessions, scheduler_runs,
//! email_deliveries, dashboard_snapshots, compliance_reports,
//! catalog_archive).
//!
//! Restore uses `jsonb_populate_recordset` to map JSON rows back into
//! their target row type — that's how we avoid hand-writing N column
//! lists per table. For BIGSERIAL-keyed tables (rule_audit,
//! webhook_deliveries) we explicitly `setval()` after the bulk insert so
//! a subsequent INSERT doesn't collide with restored ids.

use axum::{
    body::Bytes,
    extract::{Multipart, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::api::auth::AuthUser;
use crate::AppState;

const BACKUP_VERSION: &str = "1";

/// Ordered so foreign keys insert cleanly: parents before children.
/// `users` first, then everything that references users, then deeper
/// joins (e.g. asset_acl needs assets, comment_mentions needs
/// rule_comments).
const TABLES: &[&str] = &[
    "users",
    "assets",
    "asset_tags",
    "asset_acl",
    "asset_groups",
    "asset_group_members",
    "checklists",
    "checklist_rules",
    "rule_audit",
    "rule_comments",
    "comment_mentions",
    "attachments",
    "stig_drafts",
    "draft_comments",
    "baselines",
    "webhooks",
    "webhook_deliveries",
    "finding_approvals",
    "saved_searches",
];

/// Tables with a BIGSERIAL pk where we need to bump the sequence after
/// restore so subsequent INSERTs don't collide with restored ids.
const SERIAL_TABLES: &[(&str, &str)] = &[
    ("rule_audit", "id"),
    ("webhook_deliveries", "id"),
];

fn ensure_admin(user: &AuthUser) -> Result<(), StatusCode> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("backup sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

// ── Manifest ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    version: String,
    #[serde(rename = "takenAt")]
    taken_at: String,
    #[serde(rename = "schemaMigration")]
    schema_migration: i64,
    counts: HashMap<String, i64>,
}

// ── GET /api/admin/backup ───────────────────────────────────────────────────

pub async fn download_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<impl IntoResponse, StatusCode> {
    ensure_admin(&user)?;
    let pool = state.pool.as_ref();

    let schema_migration = current_schema_version(pool).await?;

    // Pull each table as `jsonb_agg(to_jsonb(t))` so we can serialize
    // straight from postgres-native types (timestamps as ISO strings,
    // arrays as JSON arrays, etc.) without re-mapping per column.
    let mut table_rows: HashMap<String, Vec<Value>> = HashMap::new();
    let mut counts: HashMap<String, i64> = HashMap::new();
    for &t in TABLES {
        let rows = load_table_rows(pool, t).await?;
        counts.insert(t.to_string(), rows.len() as i64);
        table_rows.insert(t.to_string(), rows);
    }

    // Resolve every attachment blob path up-front so the spawn_blocking
    // body doesn't need access to AppState.
    let attachment_ids: Vec<String> = table_rows
        .get("attachments")
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let attachments_dir = state.config.data_dir.join("attachments");

    let taken_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let manifest = Manifest {
        version: BACKUP_VERSION.into(),
        taken_at,
        schema_migration,
        counts,
    };

    let zip_bytes = tokio::task::spawn_blocking(move || {
        build_backup_zip(manifest, table_rows, attachment_ids, attachments_dir)
    })
    .await
    .map_err(|e| {
        tracing::error!("backup join error: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .map_err(|e| {
        tracing::error!("backup build failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let filename = format!("stig-backup-{date}.zip");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok((headers, zip_bytes))
}

async fn current_schema_version(pool: &PgPool) -> Result<i64, StatusCode> {
    // sqlx's migration table tracks each applied migration's `version`
    // (i64, parsed from the leading numeric in the filename). MAX gives
    // the highest version actually applied, which is what we compare
    // against on restore.
    let row = sqlx::query("SELECT MAX(version) AS v FROM _sqlx_migrations")
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)?;
    let v: Option<i64> = row.and_then(|r| r.try_get::<Option<i64>, _>("v").ok().flatten());
    Ok(v.unwrap_or(0))
}

async fn load_table_rows(pool: &PgPool, table: &str) -> Result<Vec<Value>, StatusCode> {
    // Pulling whole-table snapshots is fine here — the backup is admin-
    // only and intended to run rarely. If a table grows pathological we
    // can stream row-by-row, but the JSONL files in the zip already
    // assume "fits in memory" at restore time anyway.
    let sql = format!(
        "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) AS rows FROM \"{table}\" t"
    );
    let row = sqlx::query(&sql)
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)?;
    let v: Value = row.try_get("rows").map_err(|e| {
        tracing::error!("backup decode {table} rows: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(match v {
        Value::Array(a) => a,
        _ => Vec::new(),
    })
}

fn build_backup_zip(
    manifest: Manifest,
    table_rows: HashMap<String, Vec<Value>>,
    attachment_ids: Vec<String>,
    attachments_dir: std::path::PathBuf,
) -> anyhow::Result<Vec<u8>> {
    let buf: Vec<u8> = Vec::new();
    let cursor = Cursor::new(buf);
    let mut zip = ZipWriter::new(cursor);
    let options: SimpleFileOptions = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    // manifest.json at the root.
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    zip.start_file("manifest.json", options)?;
    zip.write_all(&manifest_bytes)?;

    // One JSONL per table, ordered by TABLES.
    for &t in TABLES {
        let rows = table_rows.get(t).cloned().unwrap_or_default();
        let mut body: Vec<u8> = Vec::new();
        for row in rows {
            let line = serde_json::to_string(&row)?;
            body.extend_from_slice(line.as_bytes());
            body.push(b'\n');
        }
        zip.start_file(format!("tables/{t}.jsonl"), options)?;
        zip.write_all(&body)?;
    }

    // Attachment blobs, basename = attachment id.
    for id in attachment_ids {
        // Defense in depth — ids are UUIDs but never trust user input.
        if id.contains('/') || id.contains('\\') || id.contains("..") {
            continue;
        }
        let path = attachments_dir.join(&id);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                // Row exists without an on-disk file — log and continue
                // so the rest of the backup still succeeds.
                tracing::warn!("backup: missing attachment blob {} ({e:#})", path.display());
                continue;
            }
        };
        zip.start_file(format!("attachments/{id}"), options)?;
        zip.write_all(&bytes)?;
    }

    let cursor = zip.finish()?;
    Ok(cursor.into_inner())
}

// ── POST /api/admin/restore ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RestoreQuery {
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResponse {
    pub restored: HashMap<String, i64>,
    pub attachments_written: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forced: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RestoreError {
    pub error: String,
}

fn err_response(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<RestoreError>) {
    (status, Json(RestoreError { error: msg.into() }))
}

pub async fn restore_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(q): Query<RestoreQuery>,
    mut multipart: Multipart,
) -> Result<Json<RestoreResponse>, (StatusCode, Json<RestoreError>)> {
    if user.role != "admin" {
        return Err(err_response(StatusCode::FORBIDDEN, "admin role required"));
    }
    let pool = state.pool.as_ref();

    // Pull the first `file` field. Multipart libraries differ on what
    // "next_field" returns when the client uploads the body as raw
    // bytes, so we tolerate either a named `file` field or the first
    // field we find.
    let mut zip_bytes: Option<Bytes> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::warn!("restore multipart parse: {e:#}");
        err_response(StatusCode::BAD_REQUEST, "invalid multipart body")
    })? {
        let name = field.name().unwrap_or("").to_string();
        let bytes = field.bytes().await.map_err(|e| {
            tracing::warn!("restore multipart read: {e:#}");
            err_response(StatusCode::BAD_REQUEST, "failed to read upload")
        })?;
        if name == "file" || zip_bytes.is_none() {
            zip_bytes = Some(bytes);
        }
        if name == "file" {
            break;
        }
    }
    let zip_bytes = zip_bytes
        .ok_or_else(|| err_response(StatusCode::BAD_REQUEST, "missing file in upload"))?;

    // Parse the zip on a blocking pool — the central directory walk is
    // sync and could be large.
    let (manifest, tables, attachments) =
        tokio::task::spawn_blocking(move || parse_backup_zip(&zip_bytes))
            .await
            .map_err(|e| {
                tracing::error!("restore join error: {e:#}");
                err_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            })?
            .map_err(|e| {
                tracing::warn!("restore zip parse: {e:#}");
                err_response(StatusCode::BAD_REQUEST, format!("invalid backup: {e}"))
            })?;

    // Schema version gate — refuse to load a backup taken against a
    // different migration set. Reduces the blast radius if someone
    // tries to restore last year's backup onto today's schema.
    let live_version = current_schema_version(pool).await.map_err(|s| {
        err_response(s, "failed to read schema version")
    })?;
    if manifest.schema_migration != live_version {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            format!(
                "schema version mismatch: backup={} live={}",
                manifest.schema_migration, live_version
            ),
        ));
    }

    // Precondition for non-forced restore: target db must be empty of
    // user-generated data. We check assets + checklists since they're
    // the primary parents most other rows hang off.
    if !q.force {
        let asset_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assets")
            .fetch_one(pool)
            .await
            .map_err(|e| {
                tracing::error!("restore precondition assets: {e:#}");
                err_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            })?;
        let checklist_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklists")
            .fetch_one(pool)
            .await
            .map_err(|e| {
                tracing::error!("restore precondition checklists: {e:#}");
                err_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            })?;
        if asset_count > 0 || checklist_count > 0 {
            return Err(err_response(
                StatusCode::BAD_REQUEST,
                "target database is not empty (assets and/or checklists exist). Re-run with force=true to overwrite.",
            ));
        }
    }

    // ── Transactional insert ────────────────────────────────────────────
    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!("restore tx begin: {e:#}");
        err_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    })?;

    if q.force {
        // CASCADE so children get cleared too. Quoted to keep the
        // identifier list safe even if a name ever collides with a
        // reserved word.
        let list = TABLES
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("TRUNCATE {list} RESTART IDENTITY CASCADE");
        sqlx::query(&sql).execute(&mut *tx).await.map_err(|e| {
            tracing::error!("restore truncate: {e:#}");
            err_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to truncate")
        })?;
    }

    let mut restored: HashMap<String, i64> = HashMap::new();
    for &t in TABLES {
        let rows = tables.get(t).cloned().unwrap_or_default();
        if rows.is_empty() {
            restored.insert(t.to_string(), 0);
            continue;
        }
        let arr = Value::Array(rows);
        let sql = format!(
            "INSERT INTO \"{t}\" SELECT * FROM jsonb_populate_recordset(NULL::\"{t}\", $1)"
        );
        let res = sqlx::query(&sql).bind(&arr).execute(&mut *tx).await.map_err(|e| {
            tracing::error!("restore insert {t}: {e:#}");
            err_response(StatusCode::BAD_REQUEST, format!("failed to insert {t}: {e}"))
        })?;
        restored.insert(t.to_string(), res.rows_affected() as i64);
    }

    // Bump BIGSERIAL sequences so future inserts don't collide.
    for (table, col) in SERIAL_TABLES {
        let sql = format!(
            "SELECT setval(pg_get_serial_sequence('{table}', '{col}'), \
             COALESCE((SELECT MAX({col}) FROM \"{table}\"), 1))"
        );
        if let Err(e) = sqlx::query(&sql).execute(&mut *tx).await {
            tracing::warn!("restore setval {table}.{col}: {e:#}");
        }
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("restore commit: {e:#}");
        err_response(StatusCode::INTERNAL_SERVER_ERROR, "commit failed")
    })?;

    // ── Attachment blobs ────────────────────────────────────────────────
    let dest_dir = state.config.data_dir.join("attachments");
    if let Err(e) = tokio::fs::create_dir_all(&dest_dir).await {
        tracing::error!("restore mkdir attachments: {e:#}");
        return Err(err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to create attachments dir",
        ));
    }
    let mut written: i64 = 0;
    for (id, bytes) in attachments {
        // Reject anything that tries to escape the attachments dir.
        if id.contains('/') || id.contains('\\') || id.contains("..") || id.is_empty() {
            continue;
        }
        let path = dest_dir.join(&id);
        if let Err(e) = tokio::fs::write(&path, &bytes).await {
            tracing::warn!("restore write blob {id}: {e:#}");
            continue;
        }
        written += 1;
    }

    Ok(Json(RestoreResponse {
        restored,
        attachments_written: written,
        forced: if q.force { Some(true) } else { None },
    }))
}

/// Walk the ZIP once, returning `(manifest, table->rows, attachment_id->bytes)`.
/// Sync — call from inside `spawn_blocking`.
type ParsedBackup = (Manifest, HashMap<String, Vec<Value>>, Vec<(String, Vec<u8>)>);

fn parse_backup_zip(bytes: &[u8]) -> anyhow::Result<ParsedBackup> {
    let cursor = Cursor::new(bytes);
    let mut zip = ZipArchive::new(cursor)?;

    let mut manifest: Option<Manifest> = None;
    let mut tables: HashMap<String, Vec<Value>> = HashMap::new();
    let mut attachments: Vec<(String, Vec<u8>)> = Vec::new();

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        if name.ends_with('/') {
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;

        if name == "manifest.json" {
            manifest = Some(serde_json::from_slice(&buf)?);
        } else if let Some(rest) = name.strip_prefix("tables/") {
            if let Some(tname) = rest.strip_suffix(".jsonl") {
                let mut rows = Vec::new();
                for line in buf.split(|&b| b == b'\n') {
                    if line.is_empty() {
                        continue;
                    }
                    let v: Value = serde_json::from_slice(line)?;
                    rows.push(v);
                }
                tables.insert(tname.to_string(), rows);
            }
        } else if let Some(att_id) = name.strip_prefix("attachments/") {
            // Skip subdirs / traversal attempts.
            if att_id.contains('/') || att_id.contains('\\') || att_id.is_empty() {
                continue;
            }
            attachments.push((att_id.to_string(), buf));
        }
    }

    let manifest =
        manifest.ok_or_else(|| anyhow::anyhow!("manifest.json missing from backup"))?;
    if manifest.version != BACKUP_VERSION {
        anyhow::bail!(
            "unsupported backup version: {} (expected {})",
            manifest.version,
            BACKUP_VERSION
        );
    }
    Ok((manifest, tables, attachments))
}

// Silence the unused-import lint when the `json!` macro isn't reached
// (used in tests later).
#[allow(dead_code)]
fn _json_macro_sentinel() -> Value {
    json!({})
}
