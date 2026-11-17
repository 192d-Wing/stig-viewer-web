//! Admin backup + restore.
//!
//! GET  /api/admin/backup  — streams a ZIP of all user-generated tables
//!                           as JSONL plus the attachment blobs from
//!                           `${data_dir}/attachments/`.
//! POST /api/admin/restore — multipart upload of the same ZIP. Optionally
//!                           force-truncates the existing data first.
//!
//! Integrity (format version 2): `manifest.json` lists a SHA-512 digest for
//! every other entry and, when `SIGNING_KEY_HEX` is set, names its signers;
//! `manifest.sig.json` is an envelope (see `crate::integrity`) carrying the
//! exact manifest bytes and the Ed25519 signature over
//! `b"stig-viewer/backup/v1\0" || manifest`. Restore checks both before it
//! touches the database. Version 1 backups (no digests) are still accepted.
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
use std::collections::{BTreeMap, HashMap};
use std::io::{Cursor, Read, Write};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::api::auth::AuthUser;
use crate::api::signing::SigningState;
use crate::integrity::{self, SignatureStatus, SignerId};
use crate::AppState;

const BACKUP_VERSION: &str = "2";
/// Versions restore accepts. "1" has no digests and no signature.
const ACCEPTED_VERSIONS: &[&str] = &["1", "2"];
const MANIFEST_NAME: &str = "manifest.json";
const MANIFEST_SIG_NAME: &str = "manifest.sig.json";

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
    "audit_events",
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
    ("audit_events", "id"),
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
    /// `stig-viewer/backup` (absent in version 1 manifests).
    #[serde(rename = "type", default)]
    kind: String,
    version: String,
    #[serde(rename = "takenAt")]
    taken_at: String,
    #[serde(rename = "schemaMigration")]
    schema_migration: i64,
    counts: HashMap<String, i64>,
    /// Entry name -> lowercase hex SHA-512 (version 2). Every entry except the
    /// two manifest files.
    #[serde(default)]
    entries: BTreeMap<String, String>,
    /// Signers that must have signed these exact bytes (empty: digests only).
    #[serde(default)]
    signers: Vec<SignerId>,
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
        kind: integrity::BACKUP_TYPE.into(),
        version: BACKUP_VERSION.into(),
        taken_at,
        schema_migration,
        counts,
        entries: BTreeMap::new(),
        signers: Vec::new(),
    };
    let signing = state.signing.clone();

    let zip_bytes = tokio::task::spawn_blocking(move || {
        build_backup_zip(manifest, table_rows, attachment_ids, attachments_dir, signing.as_ref())
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
    mut manifest: Manifest,
    table_rows: HashMap<String, Vec<Value>>,
    attachment_ids: Vec<String>,
    attachments_dir: std::path::PathBuf,
    signing: Option<&SigningState>,
) -> anyhow::Result<Vec<u8>> {
    let buf: Vec<u8> = Vec::new();
    let cursor = Cursor::new(buf);
    let mut zip = ZipWriter::new(cursor);
    let options: SimpleFileOptions = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    // Every data entry is digested as it is written; the manifest (which lists
    // the digests) is written last.
    let mut entries: BTreeMap<String, String> = BTreeMap::new();

    // One JSONL per table, ordered by TABLES.
    for &t in TABLES {
        let rows = table_rows.get(t).cloned().unwrap_or_default();
        let mut body: Vec<u8> = Vec::new();
        for row in rows {
            let line = serde_json::to_string(&row)?;
            body.extend_from_slice(line.as_bytes());
            body.push(b'\n');
        }
        let name = format!("tables/{t}.jsonl");
        entries.insert(name.clone(), integrity::sha512_hex(&body));
        zip.start_file(name, options)?;
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
        let name = format!("attachments/{id}");
        entries.insert(name.clone(), integrity::sha512_hex(&bytes));
        zip.start_file(name, options)?;
        zip.write_all(&bytes)?;
    }

    manifest.entries = entries;
    manifest.signers = integrity::signers_for(signing);
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    zip.start_file(MANIFEST_NAME, options)?;
    zip.write_all(&manifest_bytes)?;
    if signing.is_some() {
        let envelope = integrity::seal(
            integrity::BACKUP_DOMAIN,
            integrity::BACKUP_TYPE,
            &manifest_bytes,
            signing,
            None,
        );
        zip.start_file(MANIFEST_SIG_NAME, options)?;
        zip.write_all(&serde_json::to_vec_pretty(&envelope)?)?;
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
    /// `verified`, `unsigned` or `unknown_key`.
    pub signature_status: &'static str,
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
    Extension(ctx): Extension<crate::api::request_ctx::RequestCtx>,
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
    // Integrity is verified here, before anything touches the database.
    let signing = state.signing.clone();
    let require_signature = require_signature_from_env();
    let (manifest, tables, attachments, signature_status) =
        tokio::task::spawn_blocking(move || {
            parse_and_verify_backup(&zip_bytes, signing.as_ref(), require_signature)
        })
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
    // Structured record before anything is changed, so the external log has it
    // even if the database write below fails.
    // Only counts for known tables: the manifest comes from the uploaded ZIP.
    let backup_counts: Vec<(&str, i64)> = TABLES
        .iter()
        .filter_map(|t| manifest.counts.get(*t).map(|n| (*t, *n)))
        .collect();
    let backup_rows: i64 = backup_counts.iter().map(|(_, n)| n).sum();
    tracing::warn!(
        target: "audit",
        actor = %user.id,
        source_ip = ctx.source_ip.as_deref(),
        request_id = %ctx.request_id,
        forced = q.force,
        signature_status = signature_status.as_str(),
        backup_rows = backup_rows,
        backup_counts = ?backup_counts,
        "backup restore starting"
    );
    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!("restore tx begin: {e:#}");
        err_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    })?;
    // The acting admin's row, so it can be put back if the backup lacks it
    // (the restore event references it by foreign key).
    let actor_row: Option<Value> = sqlx::query_scalar("SELECT to_jsonb(u) FROM users u WHERE id = $1")
        .bind(&user.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("restore actor lookup: {e:#}");
            err_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        })?;

    if q.force {
        // The truncate reaches the audit tables, whose guard triggers need the
        // `restore` maintenance mode (transaction-local).
        crate::db_audit::set_maintenance(&mut tx, "restore").await.map_err(|e| {
            tracing::error!("restore maintenance mode: {e:#}");
            err_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        })?;
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

    // Record the restore inside the transaction: if the record cannot be
    // written, the restore is rolled back rather than committed unrecorded.
    let restored_rows: i64 = restored.values().sum();
    record_restore(&mut tx, &user.id, &ctx, q.force, restored_rows, actor_row.as_ref(), signature_status)
        .await
        .map_err(|e| match e {
            RecordRestoreError::NoActor => {
                tracing::error!(target: "audit", actor = %user.id, "restore rolled back: acting user not in restored data");
                err_response(
                    StatusCode::CONFLICT,
                    "restore rolled back: the acting admin is not present in the backup (matched neither by id nor by identity provider subject); nothing was changed",
                )
            }
            RecordRestoreError::Db(e) => {
                tracing::error!(target: "audit", "restore audit record failed, rolling back: {e:#}");
                err_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to record restore")
            }
        })?;

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

    tracing::warn!(
        target: "audit",
        actor = %user.id,
        request_id = %ctx.request_id,
        forced = q.force,
        attachments_written = written,
        "backup restore committed"
    );
    Ok(Json(RestoreResponse {
        restored,
        attachments_written: written,
        signature_status: signature_status.as_str(),
        forced: if q.force { Some(true) } else { None },
    }))
}

#[derive(Debug)]
enum RecordRestoreError {
    /// The acting user is in the restored data neither by id nor by (provider, sub).
    NoActor,
    Db(anyhow::Error),
}

impl From<sqlx::Error> for RecordRestoreError {
    fn from(e: sqlx::Error) -> Self {
        RecordRestoreError::Db(e.into())
    }
}

/// Put the acting user's row back if the restored data lacks it, resolve the
/// user the event is attributed to (the same id, else the same IdP identity
/// under the id the restored data uses), then record `backup.restore` on the
/// same transaction.
async fn record_restore(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &str,
    ctx: &crate::api::request_ctx::RequestCtx,
    forced: bool,
    restored_rows: i64,
    actor_row: Option<&Value>,
    signature_status: SignatureStatus,
) -> Result<(), RecordRestoreError> {
    if let Some(row) = actor_row {
        sqlx::query("INSERT INTO users SELECT * FROM jsonb_populate_record(NULL::users, $1) ON CONFLICT DO NOTHING")
            .bind(row)
            .execute(&mut **tx)
            .await?;
    }
    let mut attributed: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
        .bind(actor)
        .fetch_optional(&mut **tx)
        .await?;
    if attributed.is_none() {
        let provider = actor_row.and_then(|r| r.get("provider")).and_then(Value::as_str);
        let sub = actor_row.and_then(|r| r.get("sub")).and_then(Value::as_str);
        if let (Some(provider), Some(sub)) = (provider, sub) {
            attributed = sqlx::query_scalar("SELECT id FROM users WHERE provider = $1 AND sub = $2")
                .bind(provider)
                .bind(sub)
                .fetch_optional(&mut **tx)
                .await?;
        }
    }
    let Some(attributed) = attributed else {
        return Err(RecordRestoreError::NoActor);
    };
    let mut detail = json!({
        "forced": forced,
        "restoredRows": restored_rows,
        "signatureStatus": signature_status.as_str(),
    });
    if attributed != actor {
        detail["actorIdBeforeRestore"] = json!(actor);
    }
    crate::db_audit::record_in_tx(
        tx,
        &crate::db_audit::NewAuditEvent {
            user_id: &attributed,
            ctx: Some(ctx),
            action: "backup.restore",
            outcome: "ok",
            asset_id: None,
            checklist_id: None,
            stig_id: None,
            detail,
        },
    )
    .await
    .map_err(RecordRestoreError::Db)
}

/// Walk the ZIP once, returning the manifest, its raw bytes, the
/// `manifest.sig.json` bytes if present, the digest of every other entry,
/// the table rows and the attachment blobs. Sync — call from inside
/// `spawn_blocking`.
struct ParsedBackup {
    manifest: Manifest,
    manifest_bytes: Vec<u8>,
    sig_bytes: Option<Vec<u8>>,
    digests: BTreeMap<String, String>,
    tables: HashMap<String, Vec<Value>>,
    attachments: Vec<(String, Vec<u8>)>,
}

fn parse_backup_zip(bytes: &[u8]) -> anyhow::Result<ParsedBackup> {
    let cursor = Cursor::new(bytes);
    let mut zip = ZipArchive::new(cursor)?;

    let mut manifest: Option<(Manifest, Vec<u8>)> = None;
    let mut sig_bytes: Option<Vec<u8>> = None;
    let mut digests: BTreeMap<String, String> = BTreeMap::new();
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

        if name == MANIFEST_NAME {
            if manifest.is_some() {
                anyhow::bail!("duplicate {MANIFEST_NAME}");
            }
            manifest = Some((serde_json::from_slice(&buf)?, buf));
            continue;
        }
        if name == MANIFEST_SIG_NAME {
            if sig_bytes.is_some() {
                anyhow::bail!("duplicate {MANIFEST_SIG_NAME}");
            }
            sig_bytes = Some(buf);
            continue;
        }
        if digests.insert(name.clone(), integrity::sha512_hex(&buf)).is_some() {
            anyhow::bail!("duplicate entry {name}");
        }
        if let Some(rest) = name.strip_prefix("tables/") {
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

    let (manifest, manifest_bytes) =
        manifest.ok_or_else(|| anyhow::anyhow!("{MANIFEST_NAME} missing from backup"))?;
    if !ACCEPTED_VERSIONS.contains(&manifest.version.as_str()) {
        anyhow::bail!(
            "unsupported backup version: {} (expected one of {:?})",
            manifest.version,
            ACCEPTED_VERSIONS
        );
    }
    Ok(ParsedBackup { manifest, manifest_bytes, sig_bytes, digests, tables, attachments })
}

/// `BACKUP_REQUIRE_SIGNATURE=true` makes restore reject anything that is not
/// signature-verified.
fn require_signature_from_env() -> bool {
    std::env::var("BACKUP_REQUIRE_SIGNATURE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}

/// Check the digests and the signature of a parsed backup. Policy: a
/// signature that is present and wrong is always rejected; unsigned or
/// unknown-key backups are accepted (with a warning) unless `require`.
fn verify_backup(
    p: &ParsedBackup,
    signing: Option<&SigningState>,
    require: bool,
) -> anyhow::Result<SignatureStatus> {
    let m = &p.manifest;
    if m.version == "1" {
        // No digests, no signature possible: only the policy applies.
        if require {
            anyhow::bail!("unsigned backup rejected: BACKUP_REQUIRE_SIGNATURE is set");
        }
        tracing::warn!(target: "audit", "restoring a version 1 backup: no integrity data to verify");
        return Ok(SignatureStatus::Unsigned);
    }
    if m.kind != integrity::BACKUP_TYPE {
        anyhow::bail!("manifest type is not {}", integrity::BACKUP_TYPE);
    }
    // Digests: both directions, so an added or removed entry is caught.
    for (name, digest) in &p.digests {
        match m.entries.get(name) {
            Some(expected) if expected == digest => {}
            Some(_) => anyhow::bail!("integrity check failed: entry {name} does not match its digest"),
            None => anyhow::bail!("integrity check failed: entry {name} is not listed in the manifest"),
        }
    }
    if let Some(missing) = m.entries.keys().find(|n| !p.digests.contains_key(*n)) {
        anyhow::bail!("integrity check failed: entry {missing} is listed but missing");
    }
    // Signature.
    let status = match (&p.sig_bytes, m.signers.is_empty()) {
        (None, true) => SignatureStatus::Unsigned,
        (None, false) => {
            anyhow::bail!("manifest names signers but {MANIFEST_SIG_NAME} is missing")
        }
        (Some(sig), _) => {
            integrity::verify_envelope(
                integrity::BACKUP_DOMAIN,
                integrity::BACKUP_TYPE,
                sig,
                Some(&p.manifest_bytes),
                signing,
            )?
            .status
        }
    };
    if status != SignatureStatus::Verified {
        if require {
            anyhow::bail!(
                "backup signature is {} and BACKUP_REQUIRE_SIGNATURE is set",
                status.as_str()
            );
        }
        tracing::warn!(
            target: "audit",
            signature_status = status.as_str(),
            "restoring a backup whose signature could not be verified"
        );
    }
    Ok(status)
}

type ParsedTables = HashMap<String, Vec<Value>>;
type ParsedAttachments = Vec<(String, Vec<u8>)>;

fn parse_and_verify_backup(
    bytes: &[u8],
    signing: Option<&SigningState>,
    require: bool,
) -> anyhow::Result<(Manifest, ParsedTables, ParsedAttachments, SignatureStatus)> {
    let p = parse_backup_zip(bytes)?;
    let status = verify_backup(&p, signing, require)?;
    Ok((p.manifest, p.tables, p.attachments, status))
}

// Silence the unused-import lint when the `json!` macro isn't reached
// (used in tests later).
#[allow(dead_code)]
fn _json_macro_sentinel() -> Value {
    json!({})
}

#[cfg(test)]
mod restore_record_tests {
    use super::*;
    use crate::api::request_ctx::RequestCtx;
    use crate::test_fixtures::seed_user;

    fn ctx() -> RequestCtx {
        RequestCtx::new(&axum::http::HeaderMap::new(), None, "admin")
    }

    async fn actor_row(pool: &PgPool) -> Value {
        sqlx::query_scalar("SELECT to_jsonb(u) FROM users u WHERE id = 'admin1'")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn forced_restore_omitting_the_actor_keeps_the_actor_and_one_event(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        let row = actor_row(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "restore").await.unwrap();
        // The backup contains no users at all.
        sqlx::query("TRUNCATE users CASCADE").execute(&mut *tx).await.unwrap();
        record_restore(&mut tx, "admin1", &ctx(), true, 0, Some(&row), SignatureStatus::Unsigned).await.unwrap();
        tx.commit().await.unwrap();
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = 'admin1'").fetch_one(&pool).await.unwrap();
        assert_eq!(users, 1);
        let events: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_events").fetch_all(&pool).await.unwrap();
        assert_eq!(events, ["backup.restore"]);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failing_event_insert_rolls_the_restore_back(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("INSERT INTO audit_events (user_id, action, outcome) VALUES ('admin1','checklist.save','ok')")
            .execute(&pool).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "restore").await.unwrap();
        sqlx::query("TRUNCATE users CASCADE").execute(&mut *tx).await.unwrap();
        // No actor row to restore: the event's user FK fails.
        assert!(matches!(
            record_restore(&mut tx, "admin1", &ctx(), true, 0, None, SignatureStatus::Unsigned).await,
            Err(RecordRestoreError::NoActor)
        ));
        drop(tx);
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(&pool).await.unwrap();
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events").fetch_one(&pool).await.unwrap();
        assert_eq!((users, events), (1, 1));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn restore_attributes_to_the_restored_id_of_the_same_idp_identity(pool: PgPool) {
        seed_user(&pool, "admin1").await; // provider 'test', sub 'admin1'
        let row = actor_row(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "restore").await.unwrap();
        sqlx::query("TRUNCATE users CASCADE").execute(&mut *tx).await.unwrap();
        // The backup holds the same (provider, sub) under another id.
        sqlx::query("INSERT INTO users (id, display_name, email, role, sub, provider) VALUES ('old-id', 'x', '', 'admin', 'admin1', 'test')")
            .execute(&mut *tx).await.unwrap();
        record_restore(&mut tx, "admin1", &ctx(), true, 0, Some(&row), SignatureStatus::Unsigned).await.unwrap();
        tx.commit().await.unwrap();
        let rows: Vec<(String, Value)> = sqlx::query_as("SELECT user_id, detail FROM audit_events WHERE action = 'backup.restore'")
            .fetch_all(&pool).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "old-id");
        assert_eq!(rows[0].1["actorIdBeforeRestore"], "admin1");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn restore_with_no_matching_actor_is_a_conflict_and_changes_nothing(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        let mut row = actor_row(&pool).await;
        // Only an identity that the restored data does not contain.
        row["id"] = json!("ghost");
        row["sub"] = json!("ghost-sub");
        let mut tx = pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "restore").await.unwrap();
        sqlx::query("TRUNCATE users CASCADE").execute(&mut *tx).await.unwrap();
        // Re-inserting the captured row would restore it, so omit the row.
        assert!(matches!(
            record_restore(&mut tx, "ghost", &ctx(), true, 0, None, SignatureStatus::Unsigned).await,
            Err(RecordRestoreError::NoActor)
        ));
        drop(tx);
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(&pool).await.unwrap();
        assert_eq!(users, 1);
    }
}

#[cfg(test)]
mod integrity_tests {
    use super::*;
    use crate::integrity::test_key;

    fn manifest() -> Manifest {
        Manifest {
            kind: integrity::BACKUP_TYPE.into(),
            version: BACKUP_VERSION.into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            schema_migration: 1,
            counts: HashMap::new(),
            entries: BTreeMap::new(),
            signers: Vec::new(),
        }
    }

    fn build(key: Option<&SigningState>) -> Vec<u8> {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("att-1"), b"blob").unwrap();
        let mut rows = HashMap::new();
        rows.insert("users".to_string(), vec![json!({"id": "u1"})]);
        let zip = build_backup_zip(manifest(), rows, vec!["att-1".into()], dir.clone(), key).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        zip
    }

    /// Rewrite every entry through `f`; `None` drops it.
    fn rewrite(zip: &[u8], mut f: impl FnMut(&str, Vec<u8>) -> Option<Vec<u8>>) -> Vec<u8> {
        let mut src = ZipArchive::new(Cursor::new(zip)).unwrap();
        let mut out = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        for i in 0..src.len() {
            let mut e = src.by_index(i).unwrap();
            let name = e.name().to_string();
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).unwrap();
            if let Some(b) = f(&name, buf) {
                out.start_file(name, opts).unwrap();
                out.write_all(&b).unwrap();
            }
        }
        out.finish().unwrap().into_inner()
    }

    fn check(zip: &[u8], key: Option<&SigningState>, require: bool) -> anyhow::Result<SignatureStatus> {
        parse_and_verify_backup(zip, key, require).map(|r| r.3)
    }

    #[test]
    fn signed_backup_round_trips_and_lists_every_entry() {
        let k = test_key(1);
        let zip = build(Some(&k));
        let p = parse_backup_zip(&zip).unwrap();
        assert_eq!(p.manifest.version, "2");
        assert!(p.manifest.entries.contains_key("tables/users.jsonl"));
        assert!(p.manifest.entries.contains_key("attachments/att-1"));
        assert_eq!(p.manifest.signers.len(), 1);
        assert!(p.sig_bytes.is_some());
        assert_eq!(check(&zip, Some(&k), true).unwrap(), SignatureStatus::Verified);
    }

    #[test]
    fn without_a_key_only_digests_are_written() {
        let zip = build(None);
        let p = parse_backup_zip(&zip).unwrap();
        assert!(p.sig_bytes.is_none() && p.manifest.signers.is_empty());
        assert!(!p.manifest.entries.is_empty());
        assert_eq!(check(&zip, None, false).unwrap(), SignatureStatus::Unsigned);
        // A tampered entry is still caught by the digests.
        let bad = rewrite(&zip, |n, b| Some(if n == "tables/users.jsonl" { b"{}\n".to_vec() } else { b }));
        assert!(check(&bad, None, false).is_err());
    }

    #[test]
    fn tampered_added_or_removed_entries_are_rejected() {
        let k = test_key(1);
        let zip = build(Some(&k));
        let tampered = rewrite(&zip, |n, mut b| {
            if n == "attachments/att-1" {
                b[0] ^= 1;
            }
            Some(b)
        });
        assert!(check(&tampered, Some(&k), false).unwrap_err().to_string().contains("attachments/att-1"));
        let removed = rewrite(&zip, |n, b| (n != "attachments/att-1").then_some(b));
        assert!(check(&removed, Some(&k), false).unwrap_err().to_string().contains("missing"));
        let with_extra = {
            let mut w = ZipWriter::new(Cursor::new(Vec::new()));
            let mut src = ZipArchive::new(Cursor::new(&zip)).unwrap();
            for i in 0..src.len() {
                let mut e = src.by_index(i).unwrap();
                let mut b = Vec::new();
                e.read_to_end(&mut b).unwrap();
                w.start_file(e.name().to_string(), SimpleFileOptions::default()).unwrap();
                w.write_all(&b).unwrap();
            }
            w.start_file("attachments/extra", SimpleFileOptions::default()).unwrap();
            w.write_all(b"x").unwrap();
            w.finish().unwrap().into_inner()
        };
        assert!(check(&with_extra, Some(&k), false).unwrap_err().to_string().contains("not listed"));
    }

    #[test]
    fn a_rewritten_manifest_breaks_the_signature_even_with_matching_digests() {
        let k = test_key(1);
        let zip = build(Some(&k));
        let bad = rewrite(&zip, |n, b| {
            Some(if n == MANIFEST_NAME {
                String::from_utf8(b).unwrap().replace("2026-01-01", "2027-01-01").into_bytes()
            } else {
                b
            })
        });
        assert!(check(&bad, Some(&k), false).unwrap_err().to_string().contains("PayloadMismatch"));
    }

    #[test]
    fn stripping_the_signature_entry_is_rejected_when_signers_are_named() {
        let k = test_key(1);
        let zip = build(Some(&k));
        let bad = rewrite(&zip, |n, b| (n != MANIFEST_SIG_NAME).then_some(b));
        assert!(check(&bad, Some(&k), false).is_err());
    }

    #[test]
    fn an_archive_manifest_signature_replayed_as_a_backup_signature_fails() {
        let k = test_key(1);
        let zip = build(Some(&k));
        let manifest_bytes = parse_backup_zip(&zip).unwrap().manifest_bytes;
        let replay = integrity::seal(
            integrity::ARCHIVE_DOMAIN,
            integrity::BACKUP_TYPE,
            &manifest_bytes,
            Some(&k),
            None,
        );
        let bad = rewrite(&zip, |n, b| {
            Some(if n == MANIFEST_SIG_NAME { serde_json::to_vec(&replay).unwrap() } else { b })
        });
        assert!(check(&bad, Some(&k), false).unwrap_err().to_string().contains("SignatureInvalid"));
    }

    #[test]
    fn version_1_backups_are_accepted_unless_a_signature_is_required() {
        let zip = rewrite(&build(None), |n, b| {
            if n == MANIFEST_NAME {
                let mut m: Manifest = serde_json::from_slice(&b).unwrap();
                m.version = "1".into();
                m.kind = String::new();
                m.entries.clear();
                Some(serde_json::to_vec(&m).unwrap())
            } else {
                Some(b)
            }
        });
        assert_eq!(check(&zip, None, false).unwrap(), SignatureStatus::Unsigned);
        assert!(check(&zip, None, true).is_err());
    }

    #[test]
    fn unsupported_versions_are_rejected() {
        let zip = rewrite(&build(None), |n, b| {
            Some(if n == MANIFEST_NAME {
                String::from_utf8(b).unwrap().replace("\"version\": \"2\"", "\"version\": \"9\"").into_bytes()
            } else {
                b
            })
        });
        assert!(check(&zip, None, false).is_err());
    }

    #[test]
    fn requiring_a_signature_rejects_unsigned_and_unknown_key_backups() {
        let k = test_key(1);
        let unsigned = build(None);
        assert!(check(&unsigned, Some(&k), true).unwrap_err().to_string().contains("BACKUP_REQUIRE_SIGNATURE"));
        assert_eq!(check(&unsigned, Some(&k), false).unwrap(), SignatureStatus::Unsigned);
        let signed = build(Some(&k));
        let other = test_key(2);
        assert!(check(&signed, Some(&other), true).is_err());
        assert_eq!(check(&signed, Some(&other), false).unwrap(), SignatureStatus::UnknownKey);
        assert_eq!(check(&signed, None, false).unwrap(), SignatureStatus::UnknownKey);
    }
}

#[cfg(test)]
mod restore_integrity_db_tests {
    use super::*;
    use crate::integrity::test_key;
    use crate::test_fixtures::{app_state, auth, ctx, seed_asset, seed_user};
    use axum::{extract::Request, middleware::{self, Next}, routing::post, Router};

    async fn serve(state: AppState) -> String {
        let app = Router::new()
            .route("/api/admin/restore", post(restore_handler))
            .route_layer(middleware::from_fn(|mut req: Request, next: Next| async move {
                req.extensions_mut().insert(auth("admin1", "admin"));
                req.extensions_mut().insert(ctx());
                next.run(req).await
            }))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        format!("http://{addr}")
    }

    async fn backup_of(state: &AppState) -> Vec<u8> {
        let user = auth("admin1", "admin");
        let resp = download_handler(State(state.clone()), Extension(user)).await.unwrap().into_response();
        axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()
    }

    async fn post_restore(base: &str, zip: &[u8]) -> (u16, Value) {
        let boundary = "XBOUNDARYX";
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"b.zip\"\r\nContent-Type: application/zip\r\n\r\n"
        )
        .into_bytes();
        body.extend_from_slice(zip);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = reqwest::Client::new()
            .post(format!("{base}/api/admin/restore?force=true"))
            .header("content-type", format!("multipart/form-data; boundary={boundary}"))
            .body(body)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let text = r.text().await.unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn signed_restore_is_recorded_as_verified_and_a_tampered_one_changes_nothing(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'").execute(&pool).await.unwrap();
        seed_asset(&pool, "a1", "admin1", false).await;
        let (mut state, _dir) = app_state(pool.clone());
        state.signing = Some(test_key(7));
        let base = serve(state.clone()).await;
        let zip = backup_of(&state).await;

        // Tamper with one table: the data it restores would differ.
        let mut src = ZipArchive::new(Cursor::new(&zip)).unwrap();
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for i in 0..src.len() {
            let mut e = src.by_index(i).unwrap();
            let name = e.name().to_string();
            let mut b = Vec::new();
            e.read_to_end(&mut b).unwrap();
            if name == "tables/assets.jsonl" {
                b = String::from_utf8(b).unwrap().replace("\"a1\"", "\"evil\"").into_bytes();
            }
            w.start_file(name, SimpleFileOptions::default()).unwrap();
            w.write_all(&b).unwrap();
        }
        let tampered = w.finish().unwrap().into_inner();
        let (status, body) = post_restore(&base, &tampered).await;
        assert_eq!(status, 400, "{body}");
        assert!(body["error"].as_str().unwrap().contains("tables/assets.jsonl"));
        // Rejected before the TRUNCATE: the data and the audit trail are untouched.
        let assets: Vec<String> = sqlx::query_scalar("SELECT id FROM assets").fetch_all(&pool).await.unwrap();
        assert_eq!(assets, ["a1"]);
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events").fetch_one(&pool).await.unwrap();
        assert_eq!(events, 0);

        // The genuine backup restores and records the status.
        let (status, body) = post_restore(&base, &zip).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["signatureStatus"], "verified");
        let detail: Value = sqlx::query_scalar("SELECT detail FROM audit_events WHERE action = 'backup.restore'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(detail["signatureStatus"], "verified");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn unsigned_backup_restores_with_the_unsigned_status(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'").execute(&pool).await.unwrap();
        let (state, _dir) = app_state(pool.clone());
        let base = serve(state.clone()).await;
        let zip = backup_of(&state).await;
        let (status, body) = post_restore(&base, &zip).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["signatureStatus"], "unsigned");
        let detail: Value = sqlx::query_scalar("SELECT detail FROM audit_events WHERE action = 'backup.restore'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(detail["signatureStatus"], "unsigned");
    }
}
