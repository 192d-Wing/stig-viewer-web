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
use std::io::{Cursor, Write};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::zip_safe::{read_entry, ReadBudget, ZipReadError};

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
    "checklist_sets",
    "checklist_set_stigs",
    "checklist_set_rules",
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

/// Every serial/identity column of the [`TABLES`], as `(table, column)`.
/// Found from the catalog so a new BIGSERIAL table cannot be forgotten.
async fn serial_columns(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let tables: Vec<String> = TABLES.iter().map(ToString::to_string).collect();
    sqlx::query_as(
        "SELECT t.name, a.attname::text \
         FROM unnest($1::text[]) AS t(name) \
         JOIN pg_attribute a ON a.attrelid = to_regclass(quote_ident(t.name)) \
         WHERE a.attnum > 0 AND NOT a.attisdropped \
           AND pg_get_serial_sequence(quote_ident(t.name), a.attname::text) IS NOT NULL \
         ORDER BY t.name, a.attnum",
    )
    .bind(&tables)
    .fetch_all(&mut **tx)
    .await
}

/// Point every serial sequence at the restored data so future inserts don't
/// collide: next id is MAX + 1, or 1 for an empty table. Uses `setval` only
/// (needs UPDATE on the sequence), not `TRUNCATE ... RESTART IDENTITY`, which
/// requires owning the sequences.
async fn reset_serial_sequences(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    for (table, col) in serial_columns(tx).await? {
        let sql = format!(
            "SELECT setval(pg_get_serial_sequence(quote_ident($1), $2), \
             COALESCE(MAX(\"{col}\"), 1), MAX(\"{col}\") IS NOT NULL) FROM \"{table}\""
        );
        sqlx::query(&sql)
            .bind(&table)
            .bind(&col)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

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
    /// Algorithm of the `entries` digests: `sha-512`.
    #[serde(rename = "entriesDigest", default)]
    entries_digest: String,
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
        entries_digest: String::new(),
        signers: Vec::new(),
    };
    let signing = state.signing.clone();

    let zip_bytes = tokio::task::spawn_blocking(move || {
        build_backup_zip(
            manifest,
            table_rows,
            attachment_ids,
            attachments_dir,
            signing.as_ref(),
        )
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
    let sql =
        format!("SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) AS rows FROM \"{table}\" t");
    let row = sqlx::query(&sql).fetch_one(pool).await.map_err(map_sqlx)?;
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
    manifest.entries_digest = "sha-512".into();
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
    let zip_bytes =
        zip_bytes.ok_or_else(|| err_response(StatusCode::BAD_REQUEST, "missing file in upload"))?;

    // Parse the zip on a blocking pool — the central directory walk is
    // sync and could be large.
    // Integrity is verified here, before anything touches the database.
    let signing = state.signing.clone();
    // Required by default when a signing key is configured; the operator can
    // opt out explicitly with BACKUP_REQUIRE_SIGNATURE=false.
    let require_signature = state
        .config
        .backup_require_signature
        .unwrap_or(state.signing.is_some());
    let verified = tokio::task::spawn_blocking(move || {
        parse_and_verify_backup(&zip_bytes, signing.as_ref(), require_signature)
    })
    .await
    .map_err(|e| {
        tracing::error!("restore join error: {e:#}");
        err_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    })?;
    let (manifest, tables, attachments, signature_status) = match verified {
        Ok(v) => v,
        Err(f) => {
            tracing::warn!(target: "audit", actor = %user.id, signature_status = f.status, reason_code = f.code, "restore rejected: {}", f.message);
            // Recorded outside any transaction: nothing was changed.
            let reason: String = f.message.chars().take(300).collect();
            crate::db_audit::record_or_log(
                pool,
                crate::db_audit::NewAuditEvent {
                    user_id: &user.id,
                    ctx: Some(&ctx),
                    action: "backup.restore",
                    outcome: "failure",
                    asset_id: None,
                    checklist_id: None,
                    stig_id: None,
                    detail: json!({
                        "reason": reason,
                        "reasonCode": f.code,
                        "signatureStatus": f.status,
                        "requireSignature": require_signature,
                    }),
                },
            )
            .await;
            let status = if f.too_large {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            return Err(err_response(
                status,
                format!("invalid backup: {}", f.message),
            ));
        }
    };

    // Schema version gate — refuse to load a backup taken against a
    // different migration set. Reduces the blast radius if someone
    // tries to restore last year's backup onto today's schema.
    let live_version = current_schema_version(pool)
        .await
        .map_err(|s| err_response(s, "failed to read schema version"))?;
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
        require_signature = require_signature,
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
    let actor_row: Option<Value> =
        sqlx::query_scalar("SELECT to_jsonb(u) FROM users u WHERE id = $1")
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
        crate::db_audit::set_maintenance(&mut tx, "restore")
            .await
            .map_err(|e| {
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
        let sql = format!("TRUNCATE {list} CASCADE");
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
        let res = sqlx::query(&sql)
            .bind(&arr)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("restore insert {t}: {e:#}");
                err_response(
                    StatusCode::BAD_REQUEST,
                    format!("failed to insert {t}: {e}"),
                )
            })?;
        restored.insert(t.to_string(), res.rows_affected() as i64);
    }

    // Reset the serial sequences so future inserts don't collide.
    reset_serial_sequences(&mut tx).await.map_err(|e| {
        tracing::error!("restore sequence reset: {e:#}");
        err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to reset sequences",
        )
    })?;

    // Record the restore inside the transaction: if the record cannot be
    // written, the restore is rolled back rather than committed unrecorded.
    let restored_rows: i64 = restored.values().sum();
    record_restore(&mut tx, &user.id, &ctx, q.force, restored_rows, actor_row.as_ref(), (signature_status, require_signature))
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
    (signature_status, require_signature): (SignatureStatus, bool),
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
        let provider = actor_row
            .and_then(|r| r.get("provider"))
            .and_then(Value::as_str);
        let sub = actor_row.and_then(|r| r.get("sub")).and_then(Value::as_str);
        if let (Some(provider), Some(sub)) = (provider, sub) {
            attributed =
                sqlx::query_scalar("SELECT id FROM users WHERE provider = $1 AND sub = $2")
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
        "requireSignature": require_signature,
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

/// A restore rejected before it touched the database.
#[derive(Debug)]
struct VerifyFailure {
    message: String,
    /// `verified`, `unsigned`, `unknown_key` once known; `invalid` for a bad
    /// signature; `not_evaluated` when the backup was refused before its
    /// signature was evaluated.
    status: &'static str,
    /// Machine-readable reason, recorded in the audit event.
    code: &'static str,
    /// The archive exceeded a size cap (HTTP 413 rather than 400).
    too_large: bool,
}

impl VerifyFailure {
    fn new(status: &'static str, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status,
            code: "invalid_backup",
            too_large: false,
        }
    }
}

impl From<anyhow::Error> for VerifyFailure {
    fn from(e: anyhow::Error) -> Self {
        Self {
            code: "malformed",
            ..Self::new("not_evaluated", format!("{e:#}"))
        }
    }
}

impl From<ZipReadError> for VerifyFailure {
    fn from(e: ZipReadError) -> Self {
        Self {
            code: e.code(),
            too_large: e.is_limit(),
            ..Self::new("not_evaluated", e.to_string())
        }
    }
}

/// Largest single decompressed entry, and the largest total. Reading is
/// bounded with `take`, never sized from the entry header.
const MAX_ENTRY_BYTES: u64 = 1 << 30;
const MAX_TOTAL_BYTES: u64 = 4 << 30;
/// `manifest.json` and `manifest.sig.json` are small; read them under a tight cap.
const MAX_MANIFEST_BYTES: u64 = 16 << 20;

type ParsedTables = HashMap<String, Vec<Value>>;
type ParsedAttachments = Vec<(String, Vec<u8>)>;

/// Parse and verify a backup ZIP. Sync — call from inside `spawn_blocking`.
///
/// Order: the manifest and signature are read and checked first (version,
/// downgrade, signature, policy); only then are the remaining entries read,
/// digested and compared with the manifest. Nothing here touches the database.
fn parse_and_verify_backup(
    bytes: &[u8],
    signing: Option<&SigningState>,
    require: bool,
) -> Result<(Manifest, ParsedTables, ParsedAttachments, SignatureStatus), VerifyFailure> {
    let mut zip = ZipArchive::new(Cursor::new(bytes)).map_err(ZipReadError::from)?;
    let mut budget = ReadBudget::new(MAX_TOTAL_BYTES);

    // Duplicate names are refused outright: which copy a reader sees must not
    // be a matter of choice.
    let mut seen = std::collections::HashSet::new();
    for i in 0..zip.len() {
        let name = zip
            .by_index_raw(i)
            .map_err(anyhow::Error::from)?
            .name()
            .map_err(anyhow::Error::from)?
            .into_owned();
        if !seen.insert(name.clone()) {
            return Err(VerifyFailure::new(
                "not_evaluated",
                format!("duplicate entry {name:?}"),
            ));
        }
    }
    // Local headers must agree with the central directory, before any entry
    // (including the manifest) is read.
    zip.validate_header_consistency()
        .map_err(|e| ZipReadError::Inconsistent(e.to_string()))?;

    let (manifest, manifest_bytes) = {
        let mut e = zip
            .by_name(MANIFEST_NAME)
            .map_err(|_| anyhow::anyhow!("{MANIFEST_NAME} missing from backup"))?;
        let buf = read_entry(&mut e, MAX_MANIFEST_BYTES, &mut budget)?;
        let m: Manifest = serde_json::from_slice(&buf).map_err(anyhow::Error::from)?;
        (m, buf)
    };
    if !ACCEPTED_VERSIONS.contains(&manifest.version.as_str()) {
        return Err(VerifyFailure::new(
            "not_evaluated",
            format!(
                "unsupported backup version: {:?} (expected one of {:?})",
                manifest.version, ACCEPTED_VERSIONS
            ),
        ));
    }
    let sig_bytes = match zip.by_name(MANIFEST_SIG_NAME) {
        Ok(mut e) => Some(read_entry(&mut e, MAX_MANIFEST_BYTES, &mut budget)?),
        Err(_) => None,
    };
    let status = verify_signature(
        &manifest,
        &manifest_bytes,
        sig_bytes.as_deref(),
        signing,
        require,
    )?;
    let fail = |msg: String| VerifyFailure::new(status.as_str(), msg);

    let mut digests: BTreeMap<String, String> = BTreeMap::new();
    let mut tables: ParsedTables = HashMap::new();
    let mut attachments: ParsedAttachments = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(anyhow::Error::from)?;
        let name = entry.name().map_err(anyhow::Error::from)?.into_owned();
        if name.ends_with('/') || name == MANIFEST_NAME || name == MANIFEST_SIG_NAME {
            continue;
        }
        let buf = read_entry(&mut entry, MAX_ENTRY_BYTES, &mut budget)?;
        digests.insert(name.clone(), integrity::sha512_hex(&buf));
        if let Some(rest) = name.strip_prefix("tables/") {
            if let Some(tname) = rest.strip_suffix(".jsonl") {
                let mut rows = Vec::new();
                for line in buf.split(|&b| b == b'\n') {
                    if line.is_empty() {
                        continue;
                    }
                    rows.push(serde_json::from_slice::<Value>(line).map_err(anyhow::Error::from)?);
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

    if manifest.version == "2" {
        for (name, digest) in &digests {
            match manifest.entries.get(name) {
                Some(expected) if expected == digest => {}
                Some(_) => {
                    return Err(fail(format!(
                        "integrity check failed: entry {name:?} does not match its digest"
                    )))
                }
                None => {
                    return Err(fail(format!(
                        "integrity check failed: entry {name:?} is not listed in the manifest"
                    )))
                }
            }
        }
        if let Some(missing) = manifest.entries.keys().find(|n| !digests.contains_key(*n)) {
            return Err(fail(format!(
                "integrity check failed: entry {missing:?} is listed but missing"
            )));
        }
    }
    Ok((manifest, tables, attachments, status))
}

/// Check version consistency, the signature and the policy. A signature that
/// is present and wrong is always rejected; unsigned or unknown-key backups
/// are rejected only when `require`.
fn verify_signature(
    m: &Manifest,
    manifest_bytes: &[u8],
    sig: Option<&[u8]>,
    signing: Option<&SigningState>,
    require: bool,
) -> Result<SignatureStatus, VerifyFailure> {
    let policy = |status: SignatureStatus| -> Result<SignatureStatus, VerifyFailure> {
        if status != SignatureStatus::Verified {
            if require {
                return Err(VerifyFailure::new(
                    status.as_str(),
                    format!(
                        "backup signature is {} and a verified signature is required (set BACKUP_REQUIRE_SIGNATURE=false to restore unsigned backups)",
                        status.as_str()
                    ),
                ));
            }
            tracing::warn!(
                target: "audit",
                signature_status = status.as_str(),
                "restoring a backup whose signature could not be verified"
            );
        }
        Ok(status)
    };
    if m.version == "1" {
        // A version 1 backup has no digests or signature. Refuse anything that
        // looks like a downgraded version 2 backup.
        if sig.is_some()
            || !m.entries.is_empty()
            || !m.signers.is_empty()
            || !m.kind.is_empty()
            || !m.entries_digest.is_empty()
        {
            return Err(VerifyFailure::new(
                "invalid",
                "version 1 manifest carries version 2 integrity fields (downgrade)",
            ));
        }
        return policy(SignatureStatus::Unsigned);
    }
    if m.kind != integrity::BACKUP_TYPE {
        return Err(VerifyFailure::new(
            "invalid",
            format!("manifest type is not {}", integrity::BACKUP_TYPE),
        ));
    }
    if m.entries_digest != "sha-512" {
        return Err(VerifyFailure::new(
            "invalid",
            format!("unsupported entries digest {:?}", m.entries_digest),
        ));
    }
    let status = match (sig, m.signers.is_empty()) {
        (None, true) => SignatureStatus::Unsigned,
        (None, false) => {
            return Err(VerifyFailure::new(
                "invalid",
                format!("manifest names signers but {MANIFEST_SIG_NAME} is missing"),
            ))
        }
        (Some(sig), _) => {
            integrity::verify_envelope(
                integrity::BACKUP_DOMAIN,
                integrity::BACKUP_TYPE,
                sig,
                Some(manifest_bytes),
                signing,
            )
            .map_err(|e| VerifyFailure::new("invalid", e.to_string()))?
            .status
        }
    };
    policy(status)
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
        crate::db_audit::set_maintenance(&mut tx, "restore")
            .await
            .unwrap();
        // The backup contains no users at all.
        sqlx::query("TRUNCATE users CASCADE")
            .execute(&mut *tx)
            .await
            .unwrap();
        record_restore(
            &mut tx,
            "admin1",
            &ctx(),
            true,
            0,
            Some(&row),
            (SignatureStatus::Unsigned, false),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = 'admin1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(users, 1);
        let events: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_events")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(events, ["backup.restore"]);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failing_event_insert_rolls_the_restore_back(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("INSERT INTO audit_events (user_id, action, outcome) VALUES ('admin1','checklist.save','ok')")
            .execute(&pool).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "restore")
            .await
            .unwrap();
        sqlx::query("TRUNCATE users CASCADE")
            .execute(&mut *tx)
            .await
            .unwrap();
        // No actor row to restore: the event's user FK fails.
        assert!(matches!(
            record_restore(
                &mut tx,
                "admin1",
                &ctx(),
                true,
                0,
                None,
                (SignatureStatus::Unsigned, false)
            )
            .await,
            Err(RecordRestoreError::NoActor)
        ));
        drop(tx);
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!((users, events), (1, 1));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn restore_attributes_to_the_restored_id_of_the_same_idp_identity(pool: PgPool) {
        seed_user(&pool, "admin1").await; // provider 'test', sub 'admin1'
        let row = actor_row(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "restore")
            .await
            .unwrap();
        sqlx::query("TRUNCATE users CASCADE")
            .execute(&mut *tx)
            .await
            .unwrap();
        // The backup holds the same (provider, sub) under another id.
        sqlx::query("INSERT INTO users (id, display_name, email, role, sub, provider) VALUES ('old-id', 'x', '', 'admin', 'admin1', 'test')")
            .execute(&mut *tx).await.unwrap();
        record_restore(
            &mut tx,
            "admin1",
            &ctx(),
            true,
            0,
            Some(&row),
            (SignatureStatus::Unsigned, false),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let rows: Vec<(String, Value)> = sqlx::query_as(
            "SELECT user_id, detail FROM audit_events WHERE action = 'backup.restore'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
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
        crate::db_audit::set_maintenance(&mut tx, "restore")
            .await
            .unwrap();
        sqlx::query("TRUNCATE users CASCADE")
            .execute(&mut *tx)
            .await
            .unwrap();
        // Re-inserting the captured row would restore it, so omit the row.
        assert!(matches!(
            record_restore(
                &mut tx,
                "ghost",
                &ctx(),
                true,
                0,
                None,
                (SignatureStatus::Unsigned, false)
            )
            .await,
            Err(RecordRestoreError::NoActor)
        ));
        drop(tx);
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(users, 1);
    }
}

#[cfg(test)]
mod integrity_tests {
    use super::*;
    use crate::integrity::test_key;
    use std::io::Read;

    fn manifest() -> Manifest {
        Manifest {
            kind: integrity::BACKUP_TYPE.into(),
            version: BACKUP_VERSION.into(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            schema_migration: 1,
            counts: HashMap::new(),
            entries: BTreeMap::new(),
            entries_digest: String::new(),
            signers: Vec::new(),
        }
    }

    pub(super) fn build(key: Option<&SigningState>) -> Vec<u8> {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("att-1"), b"blob").unwrap();
        let mut rows = HashMap::new();
        rows.insert("users".to_string(), vec![json!({"id": "u1"})]);
        let zip =
            build_backup_zip(manifest(), rows, vec!["att-1".into()], dir.clone(), key).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        zip
    }

    /// Rewrite every entry through `f`; `None` drops it.
    pub(super) fn rewrite(
        zip: &[u8],
        mut f: impl FnMut(&str, Vec<u8>) -> Option<Vec<u8>>,
    ) -> Vec<u8> {
        let mut src = ZipArchive::new(Cursor::new(zip)).unwrap();
        let mut out = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        for i in 0..src.len() {
            let mut e = src.by_index(i).unwrap();
            let name = e.name().unwrap().into_owned();
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).unwrap();
            if let Some(b) = f(&name, buf) {
                out.start_file(name, opts).unwrap();
                out.write_all(&b).unwrap();
            }
        }
        out.finish().unwrap().into_inner()
    }

    fn manifest_of(zip: &[u8]) -> (Manifest, Vec<u8>) {
        let mut z = ZipArchive::new(Cursor::new(zip)).unwrap();
        let mut b = Vec::new();
        z.by_name(MANIFEST_NAME)
            .unwrap()
            .read_to_end(&mut b)
            .unwrap();
        (serde_json::from_slice(&b).unwrap(), b)
    }

    fn has_entry(zip: &[u8], name: &str) -> bool {
        ZipArchive::new(Cursor::new(zip))
            .unwrap()
            .by_name(name)
            .is_ok()
    }

    fn check(
        zip: &[u8],
        key: Option<&SigningState>,
        require: bool,
    ) -> Result<SignatureStatus, String> {
        parse_and_verify_backup(zip, key, require)
            .map(|r| r.3)
            .map_err(|f| f.message)
    }

    #[test]
    fn signed_backup_round_trips_and_lists_every_entry() {
        let k = test_key(1);
        let zip = build(Some(&k));
        let (m, _) = manifest_of(&zip);
        assert_eq!(m.version, "2");
        assert_eq!(m.entries_digest, "sha-512");
        assert!(m.entries.contains_key("tables/users.jsonl"));
        assert!(m.entries.contains_key("attachments/att-1"));
        assert_eq!(m.signers.len(), 1);
        assert!(has_entry(&zip, MANIFEST_SIG_NAME));
        assert_eq!(
            check(&zip, Some(&k), true).unwrap(),
            SignatureStatus::Verified
        );
    }

    #[test]
    fn without_a_key_only_digests_are_written() {
        let zip = build(None);
        let (m, _) = manifest_of(&zip);
        assert!(!has_entry(&zip, MANIFEST_SIG_NAME) && m.signers.is_empty());
        assert!(!m.entries.is_empty());
        assert_eq!(check(&zip, None, false).unwrap(), SignatureStatus::Unsigned);
        let bad = rewrite(&zip, |n, b| {
            Some(if n == "tables/users.jsonl" {
                b"{}\n".to_vec()
            } else {
                b
            })
        });
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
        assert!(check(&tampered, Some(&k), false)
            .unwrap_err()
            .contains("attachments/att-1"));
        let removed = rewrite(&zip, |n, b| (n != "attachments/att-1").then_some(b));
        assert!(check(&removed, Some(&k), false)
            .unwrap_err()
            .contains("missing"));
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let mut src = ZipArchive::new(Cursor::new(&zip)).unwrap();
        for i in 0..src.len() {
            let mut e = src.by_index(i).unwrap();
            let mut b = Vec::new();
            e.read_to_end(&mut b).unwrap();
            w.start_file(e.name().unwrap().into_owned(), SimpleFileOptions::default())
                .unwrap();
            w.write_all(&b).unwrap();
        }
        w.start_file("attachments/extra", SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"x").unwrap();
        let with_extra = w.finish().unwrap().into_inner();
        assert!(check(&with_extra, Some(&k), false)
            .unwrap_err()
            .contains("not listed"));
    }

    #[test]
    fn a_rewritten_manifest_breaks_the_signature_even_with_matching_digests() {
        let k = test_key(1);
        let bad = rewrite(&build(Some(&k)), |n, b| {
            Some(if n == MANIFEST_NAME {
                String::from_utf8(b)
                    .unwrap()
                    .replace("2026-01-01", "2027-01-01")
                    .into_bytes()
            } else {
                b
            })
        });
        assert!(check(&bad, Some(&k), false)
            .unwrap_err()
            .contains("PayloadMismatch"));
    }

    #[test]
    fn stripping_the_signature_entry_is_rejected_when_signers_are_named() {
        let k = test_key(1);
        let bad = rewrite(&build(Some(&k)), |n, b| {
            (n != MANIFEST_SIG_NAME).then_some(b)
        });
        assert!(check(&bad, Some(&k), false).is_err());
    }

    #[test]
    fn an_archive_manifest_signature_replayed_as_a_backup_signature_fails() {
        let k = test_key(1);
        let zip = build(Some(&k));
        let (_, manifest_bytes) = manifest_of(&zip);
        let replay = integrity::seal(
            integrity::ARCHIVE_DOMAIN,
            integrity::BACKUP_TYPE,
            &manifest_bytes,
            Some(&k),
        );
        let bad = rewrite(&zip, |n, b| {
            Some(if n == MANIFEST_SIG_NAME {
                serde_json::to_vec(&replay).unwrap()
            } else {
                b
            })
        });
        assert!(check(&bad, Some(&k), false)
            .unwrap_err()
            .contains("SignatureInvalid"));
    }

    fn as_v1(zip: &[u8], keep_v2_fields: bool) -> Vec<u8> {
        rewrite(zip, |n, b| {
            if n == MANIFEST_NAME {
                let mut m: Manifest = serde_json::from_slice(&b).unwrap();
                m.version = "1".into();
                if !keep_v2_fields {
                    m.kind = String::new();
                    m.entries.clear();
                    m.entries_digest = String::new();
                    m.signers.clear();
                }
                Some(serde_json::to_vec(&m).unwrap())
            } else {
                Some(b)
            }
        })
    }

    #[test]
    fn version_1_backups_are_accepted_unless_a_signature_is_required() {
        let zip = as_v1(&build(None), false);
        assert_eq!(check(&zip, None, false).unwrap(), SignatureStatus::Unsigned);
        assert!(check(&zip, None, true).is_err());
    }

    #[test]
    fn downgrading_a_signed_backup_to_version_1_is_rejected() {
        let k = test_key(1);
        let signed = build(Some(&k));
        // Version flipped, everything else left: v2 fields present.
        let err = check(&as_v1(&signed, true), Some(&k), false).unwrap_err();
        assert!(err.contains("downgrade"), "{err}");
        // Fields stripped from the manifest but the signature entry left behind.
        let err = check(&as_v1(&signed, false), Some(&k), false).unwrap_err();
        assert!(err.contains("downgrade"), "{err}");
        // Fully stripped (no signature entry): only the policy stops it.
        let stripped = rewrite(&as_v1(&signed, false), |n, b| {
            (n != MANIFEST_SIG_NAME).then_some(b)
        });
        assert!(check(&stripped, Some(&k), false).is_ok());
        assert!(check(&stripped, Some(&k), true).is_err());
    }

    #[test]
    fn unsupported_versions_are_rejected() {
        let zip = rewrite(&build(None), |n, b| {
            Some(if n == MANIFEST_NAME {
                String::from_utf8(b)
                    .unwrap()
                    .replace("\"version\": \"2\"", "\"version\": \"9\"")
                    .into_bytes()
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
        assert!(check(&unsigned, Some(&k), true)
            .unwrap_err()
            .contains("required"));
        assert_eq!(
            check(&unsigned, Some(&k), false).unwrap(),
            SignatureStatus::Unsigned
        );
        let signed = build(Some(&k));
        let other = test_key(2);
        assert!(check(&signed, Some(&other), true).is_err());
        assert_eq!(
            check(&signed, Some(&other), false).unwrap(),
            SignatureStatus::UnknownKey
        );
        assert_eq!(
            check(&signed, None, false).unwrap(),
            SignatureStatus::UnknownKey
        );
        let f = parse_and_verify_backup(&signed, Some(&other), true).unwrap_err();
        assert_eq!(f.status, "unknown_key");
    }

    /// Two entries of the same name. The writer refuses them, so the second is
    /// written under a same-length name and renamed in the raw bytes.
    fn with_duplicate(zip: &[u8], name: &str) -> Vec<u8> {
        let mut decoy = name.to_string();
        decoy.pop();
        decoy.push('#');
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let mut src = ZipArchive::new(Cursor::new(zip)).unwrap();
        for i in 0..src.len() {
            let mut e = src.by_index(i).unwrap();
            let mut b = Vec::new();
            e.read_to_end(&mut b).unwrap();
            let n = e.name().unwrap().into_owned();
            w.start_file(n.clone(), SimpleFileOptions::default())
                .unwrap();
            w.write_all(&b).unwrap();
            if n == name {
                w.start_file(decoy.clone(), SimpleFileOptions::default())
                    .unwrap();
                w.write_all(b"{\"id\":\"evil\"}\n").unwrap();
            }
        }
        let mut bytes = w.finish().unwrap().into_inner();
        let (from, to) = (decoy.as_bytes().to_vec(), name.as_bytes().to_vec());
        let mut i = 0;
        while i + from.len() <= bytes.len() {
            if bytes[i..i + from.len()] == from[..] {
                bytes[i..i + from.len()].copy_from_slice(&to);
                i += from.len();
            } else {
                i += 1;
            }
        }
        bytes
    }

    #[test]
    fn refused_before_evaluation_is_not_confused_with_unknown_key() {
        let f = parse_and_verify_backup(b"not a zip", None, false).unwrap_err();
        assert_eq!(f.status, "not_evaluated");
    }

    #[test]
    fn duplicate_entries_are_rejected() {
        let k = test_key(1);
        let zip = build(Some(&k));
        for name in ["tables/users.jsonl", MANIFEST_NAME, MANIFEST_SIG_NAME] {
            let dup = with_duplicate(&zip, name);
            // The zip crate does not reject exact duplicate names: it keeps one
            // copy (the decoy), which the signed manifest / digests then refuse.
            assert!(
                parse_and_verify_backup(&dup, Some(&k), false).is_err(),
                "{name}"
            );
        }
    }
}

#[cfg(test)]
mod restore_integrity_db_tests {
    use super::*;
    use crate::integrity::test_key;
    use crate::test_fixtures::{app_state, auth, ctx, seed_asset, seed_user};
    use axum::{
        extract::Request,
        middleware::{self, Next},
        routing::post,
        Router,
    };
    use std::io::Read;

    async fn serve(state: AppState) -> String {
        let app = Router::new()
            .route("/api/admin/restore", post(restore_handler))
            .route_layer(middleware::from_fn(
                |mut req: Request, next: Next| async move {
                    req.extensions_mut().insert(auth("admin1", "admin"));
                    req.extensions_mut().insert(ctx());
                    next.run(req).await
                },
            ))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        format!("http://{addr}")
    }

    async fn backup_of(state: &AppState) -> Vec<u8> {
        let user = auth("admin1", "admin");
        let resp = download_handler(State(state.clone()), Extension(user))
            .await
            .unwrap()
            .into_response();
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
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
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
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
    async fn signed_restore_is_recorded_as_verified_and_a_tampered_one_changes_nothing(
        pool: PgPool,
    ) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
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
            let name = e.name().unwrap().into_owned();
            let mut b = Vec::new();
            e.read_to_end(&mut b).unwrap();
            if name == "tables/assets.jsonl" {
                b = String::from_utf8(b)
                    .unwrap()
                    .replace("\"a1\"", "\"evil\"")
                    .into_bytes();
            }
            w.start_file(name, SimpleFileOptions::default()).unwrap();
            w.write_all(&b).unwrap();
        }
        let tampered = w.finish().unwrap().into_inner();
        let (status, body) = post_restore(&base, &tampered).await;
        assert_eq!(status, 400, "{body}");
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("tables/assets.jsonl"));
        // Rejected before the TRUNCATE: the data and the audit trail are untouched.
        let assets: Vec<String> = sqlx::query_scalar("SELECT id FROM assets")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(assets, ["a1"]);
        // The rejection is recorded, outside any restore transaction.
        let (outcome, d): (String, Value) = sqlx::query_as(
            "SELECT outcome, detail FROM audit_events WHERE action = 'backup.restore'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(outcome, "failure");
        // The manifest signature itself verified; an entry then failed its digest.
        assert_eq!(d["signatureStatus"], "verified");
        assert_eq!(d["requireSignature"], true);
        assert!(d["reason"]
            .as_str()
            .unwrap()
            .contains("tables/assets.jsonl"));

        // The genuine backup restores and records the status.
        let (status, body) = post_restore(&base, &zip).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["signatureStatus"], "verified");
        let detail: Value =
            sqlx::query_scalar("SELECT detail FROM audit_events WHERE action = 'backup.restore'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(detail["signatureStatus"], "verified");
        assert_eq!(detail["requireSignature"], true);
    }

    async fn failure_rows(pool: &PgPool) -> Vec<Value> {
        sqlx::query_scalar("SELECT detail FROM audit_events WHERE action = 'backup.restore' AND outcome = 'failure'")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn an_oversized_manifest_is_413_and_recorded_and_changes_nothing(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
        seed_asset(&pool, "a1", "admin1", false).await;
        let (state, _dir) = app_state(pool.clone());
        let base = serve(state).await;

        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file(MANIFEST_NAME, SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"{}").unwrap();
        w.write_all(&vec![b' '; MAX_MANIFEST_BYTES as usize + 1])
            .unwrap();
        let zip = w.finish().unwrap().into_inner();

        let (status, body) = post_restore(&base, &zip).await;
        assert_eq!(status, 413, "{body}");
        let rows = failure_rows(&pool).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reasonCode"], "entry_too_large");
        assert_eq!(rows[0]["signatureStatus"], "not_evaluated");
        let assets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assets")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(assets, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_header_mismatch_is_400_and_recorded_and_changes_nothing(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
        seed_asset(&pool, "a1", "admin1", false).await;
        let (state, _dir) = app_state(pool.clone());
        let base = serve(state.clone()).await;
        let mut zip = backup_of(&state).await;
        // Rename the first central-directory entry; its local header keeps the old name.
        let cd = zip.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        zip[cd + 46] ^= 0x01;

        let (status, body) = post_restore(&base, &zip).await;
        assert_eq!(status, 400, "{body}");
        let rows = failure_rows(&pool).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reasonCode"], "header_inconsistency");
        assert_eq!(rows[0]["signatureStatus"], "not_evaluated");
        let assets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assets")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(assets, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn unsigned_backup_restores_with_the_unsigned_status(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
        let (state, _dir) = app_state(pool.clone());
        let base = serve(state.clone()).await;
        let zip = backup_of(&state).await;
        let (status, body) = post_restore(&base, &zip).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["signatureStatus"], "unsigned");
        let detail: Value =
            sqlx::query_scalar("SELECT detail FROM audit_events WHERE action = 'backup.restore'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(detail["signatureStatus"], "unsigned");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn forced_restore_works_as_the_restricted_app_role(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('admin1','c','r1','status')")
            .execute(&pool)
            .await
            .unwrap();
        let app = crate::test_fixtures::app_role_pool(&pool, false).await;
        let (state, _dir) = app_state(app.pool.clone());
        let base = serve(state.clone()).await;
        let zip = backup_of(&state).await;
        let (status, body) = post_restore(&base, &zip).await;
        assert_eq!(status, 200, "{body}");
        // The sequence continues after the restored row.
        let next: i64 = sqlx::query_scalar(
            "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) \
             VALUES ('admin1','c','r2','status') RETURNING id",
        )
        .fetch_one(&app.pool)
        .await
        .unwrap();
        let max_before: i64 =
            sqlx::query_scalar("SELECT MAX(id) FROM rule_audit WHERE rule_id = 'r1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(next, max_before + 1);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn every_serial_column_is_found_and_reset_to_the_next_free_id(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        let cols = serial_columns(&mut tx).await.unwrap();
        let expected = ["audit_events", "rule_audit", "webhook_deliveries"];
        let tables: Vec<&str> = cols.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(tables, expected, "{cols:?}");
        // Advance every sequence, then reset: empty tables restart at 1.
        for (t, c) in &cols {
            sqlx::query("SELECT setval(pg_get_serial_sequence(quote_ident($1), $2), 500)")
                .bind(t)
                .bind(c)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        reset_serial_sequences(&mut tx).await.unwrap();
        for (t, c) in &cols {
            let next: i64 =
                sqlx::query_scalar("SELECT nextval(pg_get_serial_sequence(quote_ident($1), $2))")
                    .bind(t)
                    .bind(c)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert_eq!(next, 1, "{t}.{c}");
        }
        tx.rollback().await.unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn with_a_key_an_unsigned_backup_is_refused_unless_explicitly_allowed(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
        seed_asset(&pool, "a1", "admin1", false).await;
        let (plain, _dir) = app_state(pool.clone());
        let unsigned = backup_of(&plain).await;

        let mut keyed = plain.clone();
        keyed.signing = Some(test_key(7));
        let base = serve(keyed.clone()).await;
        let (status, body) = post_restore(&base, &unsigned).await;
        assert_eq!(status, 400, "{body}");
        assert!(body["error"].as_str().unwrap().contains("required"));
        let d: Value = sqlx::query_scalar("SELECT detail FROM audit_events WHERE action = 'backup.restore' AND outcome = 'failure'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(d["signatureStatus"], "unsigned");
        let assets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assets")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(assets, 1);

        // Explicit opt-out (BACKUP_REQUIRE_SIGNATURE=false).
        let mut cfg = (*keyed.config).clone();
        cfg.backup_require_signature = Some(false);
        keyed.config = std::sync::Arc::new(cfg);
        let base = serve(keyed).await;
        let (status, body) = post_restore(&base, &unsigned).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["signatureStatus"], "unsigned");
        let d: Value =
            sqlx::query_scalar("SELECT detail FROM audit_events WHERE action = 'backup.restore'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(d["requireSignature"], false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests below predate integrity checking; they go through the full
    /// parse-and-verify path with an unsigned, digest-free version 2 manifest.
    fn parse_backup_zip(
        bytes: &[u8],
    ) -> anyhow::Result<(Manifest, ParsedTables, ParsedAttachments)> {
        parse_and_verify_backup(bytes, None, false)
            .map(|(m, t, a, _)| (m, t, a))
            .map_err(|f| anyhow::anyhow!(f.message))
    }

    fn manifest() -> Manifest {
        Manifest {
            kind: integrity::BACKUP_TYPE.into(),
            entries: BTreeMap::new(),
            entries_digest: "sha-512".into(),
            signers: Vec::new(),
            version: BACKUP_VERSION.to_string(),
            taken_at: "2026-01-01T00:00:00Z".into(),
            schema_migration: 7,
            counts: HashMap::from([("users".to_string(), 1)]),
        }
    }

    fn zip_with(name: &str, data: &[u8]) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file(name, SimpleFileOptions::default()).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn backup_round_trips_rows_and_attachment_blobs() {
        let dir = std::env::temp_dir().join(format!("stig-backup-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        std::fs::write(dir.join(&id), b"blob bytes \x00\x01\x02").unwrap();

        let row = json!({"id": 1, "name": "alice"});
        let built = build_backup_zip(
            manifest(),
            HashMap::from([("users".to_string(), vec![row.clone()])]),
            vec![id.clone()],
            dir.clone(),
            None,
        );
        let _ = std::fs::remove_dir_all(&dir);
        let (m, tables, atts) = parse_backup_zip(&built.unwrap()).unwrap();

        assert_eq!(m.version, BACKUP_VERSION);
        assert_eq!(m.taken_at, "2026-01-01T00:00:00Z");
        assert_eq!(m.schema_migration, 7);
        assert_eq!(m.counts.get("users"), Some(&1));
        assert_eq!(tables.get("users"), Some(&vec![row]));
        assert_eq!(atts, vec![(id, b"blob bytes \x00\x01\x02".to_vec())]);
    }

    #[test]
    fn restore_rejects_an_archive_without_a_manifest() {
        assert!(parse_backup_zip(&zip_with("tables/users.jsonl", b"{}\n")).is_err());
    }

    fn failure_of(bytes: &[u8]) -> VerifyFailure {
        parse_and_verify_backup(bytes, None, false).unwrap_err()
    }

    #[test]
    fn restore_rejects_an_entry_whose_size_disagrees_with_its_data() {
        let data = serde_json::to_vec(&manifest()).unwrap();
        let mut bytes = zip_with("manifest.json", &data);
        // Patch both headers so they agree with each other but not the data.
        // Central directory header: uncompressed size at offset 24; local
        // header: offset 22.
        let smaller = (data.len() as u32 - 5).to_le_bytes();
        let cd = bytes.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        bytes[cd + 24..cd + 28].copy_from_slice(&smaller);
        let lh = bytes.windows(4).position(|w| w == b"PK\x03\x04").unwrap();
        bytes[lh + 22..lh + 26].copy_from_slice(&smaller);
        let err = parse_backup_zip(&bytes)
            .unwrap_err()
            .to_string()
            .to_lowercase();
        assert!(
            err.contains("larger than its declared uncompressed size"),
            "{err}"
        );
    }

    #[test]
    fn restore_rejects_a_central_only_size_mismatch_as_header_inconsistency() {
        let data = serde_json::to_vec(&manifest()).unwrap();
        let mut bytes = zip_with("manifest.json", &data);
        let cd = bytes.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        let smaller = (data.len() as u32 - 5).to_le_bytes();
        bytes[cd + 24..cd + 28].copy_from_slice(&smaller);
        let f = failure_of(&bytes);
        assert_eq!(f.code, "header_inconsistency", "{}", f.message);
        assert_eq!(f.status, "not_evaluated");
        assert!(!f.too_large);
    }

    #[test]
    fn restore_rejects_a_renamed_central_entry_before_reading_anything() {
        let mut bytes = zip_with("tables/users.jsonl", b"{}\n");
        let cd = bytes.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        bytes[cd + 46] = b'x'; // central name no longer matches the local header
        let f = failure_of(&bytes);
        assert_eq!(f.code, "header_inconsistency", "{}", f.message);
        assert_eq!(f.status, "not_evaluated");
    }

    #[test]
    fn restore_rejects_an_unsupported_compression_method() {
        let data = serde_json::to_vec(&manifest()).unwrap();
        let mut bytes = zip_with("manifest.json", &data);
        for pos in 0..bytes.len() - 12 {
            if &bytes[pos..pos + 4] == b"PK\x03\x04" {
                bytes[pos + 8..pos + 10].copy_from_slice(&12u16.to_le_bytes());
            } else if &bytes[pos..pos + 4] == b"PK\x01\x02" {
                bytes[pos + 10..pos + 12].copy_from_slice(&12u16.to_le_bytes());
            }
        }
        let err = parse_backup_zip(&bytes).unwrap_err().to_string();
        assert!(
            err.contains("compression method not supported: 12"),
            "{err}"
        );
    }

    #[test]
    fn restore_refuses_an_entry_with_an_enormous_declared_size() {
        let data = serde_json::to_vec(&manifest()).unwrap();
        let mut bytes = zip_with("manifest.json", &data);
        let huge = u32::MAX.to_le_bytes();
        let cd = bytes.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        bytes[cd + 24..cd + 28].copy_from_slice(&huge);
        let lh = bytes.windows(4).position(|w| w == b"PK\x03\x04").unwrap();
        bytes[lh + 22..lh + 26].copy_from_slice(&huge);
        // Declared size over the manifest cap: refused without decompressing.
        let f = failure_of(&bytes);
        assert_eq!(f.code, "entry_too_large", "{}", f.message);
        assert!(f.too_large);
    }

    #[test]
    fn restore_refuses_a_manifest_over_the_manifest_cap() {
        let mut m = serde_json::to_vec(&manifest()).unwrap();
        m.extend(std::iter::repeat_n(b' ', MAX_MANIFEST_BYTES as usize + 1));
        let f = failure_of(&zip_with("manifest.json", &m));
        assert_eq!(f.code, "entry_too_large", "{}", f.message);
        assert!(f.too_large);
    }

    #[test]
    fn built_backups_pass_header_validation_signed_and_unsigned() {
        let dir = std::env::temp_dir().join(format!("stig-backup-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let tables = || HashMap::from([("users".to_string(), vec![json!({"id": 1})])]);
        let unsigned = build_backup_zip(manifest(), tables(), vec![], dir.clone(), None).unwrap();
        let (_, t, _, status) = parse_and_verify_backup(&unsigned, None, false).unwrap();
        assert_eq!(t.get("users").map(Vec::len), Some(1));
        assert_eq!(status.as_str(), "unsigned");

        let key = crate::integrity::test_key(1);
        let signed =
            build_backup_zip(manifest(), tables(), vec![], dir.clone(), Some(&key)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let (_, _, _, status) = parse_and_verify_backup(&signed, Some(&key), true).unwrap();
        assert_eq!(status.as_str(), "verified");
    }
}
