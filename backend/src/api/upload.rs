use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::Utc;

use crate::{
    api::{auth::AuthUser, request_ctx::RequestCtx, stig_validator::lint_stig},
    db::{upsert_catalog_tx, CatalogEntry},
    parser::{
        extract_all_from_library, extract_xccdf_from_zip, parse_xccdf, LibraryAbort, LibrarySkip,
    },
    zip_safe::ZipReadError,
    AppState,
};

/// Body cap for the two catalog upload routes (DISA library ZIPs are large).
/// Applied per-route in `main.rs`; every other route gets the small default.
pub const MAX_UPLOAD_BYTES: usize = 500 * 1024 * 1024;

/// Catalog uploads replace shared STIG content for every user, so they are
/// admin-only. Checked before the multipart body is read.
fn ensure_admin(user: &AuthUser) -> Result<(), (StatusCode, String)> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "admin role required".into()))
    }
}

/// Why a ZIP was refused, with optional skip counts gathered before the abort.
struct Rejection<'a> {
    reason_code: &'static str,
    reason: &'a str,
    bytes_compressed: usize,
    /// Skip counts for a library aborted part-way.
    tally: Option<SkipTally>,
}

/// Skip counts gathered before a library import was aborted.
struct SkipTally {
    skipped: usize,
    by_reason: std::collections::BTreeMap<&'static str, usize>,
    parsed: usize,
    /// Entry audit rows queued for the skips.
    audited: usize,
}

impl<'a> Rejection<'a> {
    fn new(reason: (&'static str, &'a str), bytes_compressed: usize) -> Self {
        Self {
            reason_code: reason.0,
            reason: reason.1,
            bytes_compressed,
            tally: None,
        }
    }
}

/// Audit a ZIP that was refused (too large, inconsistent headers, malformed).
/// Recorded outside any transaction: nothing was changed.
async fn record_zip_rejection(
    state: &AppState,
    user: &AuthUser,
    ctx: &RequestCtx,
    action: &'static str,
    stig_id: Option<&str>,
    rejection: Rejection<'_>,
) {
    let Rejection {
        reason_code,
        reason,
        bytes_compressed,
        tally,
    } = rejection;
    let reason: String = reason.chars().take(300).collect();
    tracing::warn!(
        target: "audit",
        actor = %user.id,
        action,
        reason_code,
        "catalog upload rejected: {reason}"
    );
    let mut detail = serde_json::json!({
        "reasonCode": reason_code,
        "reason": reason,
        "bytesCompressed": bytes_compressed,
    });
    if let (Some(t), Some(map)) = (tally, detail.as_object_mut()) {
        map.insert("skipped".into(), t.skipped.into());
        map.insert("byReason".into(), serde_json::json!(t.by_reason));
        map.insert("parsed".into(), t.parsed.into());
        map.insert("skippedAudited".into(), t.audited.into());
        map.insert(
            "skippedTruncated".into(),
            (t.skipped > MAX_SKIPPED_ENTRIES_AUDITED).into(),
        );
    }
    crate::db_audit::record_or_log(
        state.pool.as_ref(),
        crate::db_audit::NewAuditEvent {
            user_id: &user.id,
            ctx: Some(ctx),
            action,
            outcome: "rejected",
            asset_id: None,
            checklist_id: None,
            stig_id,
            detail,
        },
    )
    .await;
}

fn zip_status(err: &ZipReadError) -> StatusCode {
    if err.is_limit() {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    }
}

/// Status and fixed client message for a refused ZIP. The error's `Display`
/// (entry names, limits, library text) goes to logs and the audit `reason`
/// only, never to the client.
fn zip_rejection(e: &ZipReadError) -> (StatusCode, String) {
    (zip_status(e), e.client_message().into())
}

/// At most this many skipped library entries get their own audit row per
/// import; the request-level summary row records the true count.
pub const MAX_SKIPPED_ENTRIES_AUDITED: usize = 100;

/// One overall deadline for the per-entry audit writes of a request, so a
/// stalled pool cannot hold the response for 100 x the per-write timeout.
/// Past it no more entry rows are written; the summary row is still tried.
const ENTRY_AUDIT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

/// A skip's free-text detail for a log line: truncated and Debug-escaped (with
/// its quotes), so untrusted text cannot add log lines.
fn escaped_detail(detail: &str) -> String {
    format!("{:?}", detail.chars().take(300).collect::<String>())
}

/// The closing log line when more skips happened than were logged one by one.
fn more_skips_line(total: usize) -> Option<String> {
    (total > MAX_SKIPPED_ENTRIES_AUDITED).then(|| {
        format!(
            "{} more skipped entries not logged individually",
            total - MAX_SKIPPED_ENTRIES_AUDITED
        )
    })
}

/// Log each skip (up to the cap) and count them by reason code.
fn log_and_tally_skips(
    user: &AuthUser,
    skips: &[&LibrarySkip],
) -> std::collections::BTreeMap<&'static str, usize> {
    let mut by_reason: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for (i, skip) in skips.iter().enumerate() {
        *by_reason.entry(skip.code).or_default() += 1;
        if i < MAX_SKIPPED_ENTRIES_AUDITED {
            // `?` (Debug) keeps any newline in untrusted text escaped.
            tracing::warn!(
                target: "audit",
                actor = %user.id,
                action = "catalog.import_library_entry",
                reason_code = skip.code,
                entry = %crate::db_audit::audit_safe_id(&skip.id),
                detail = %escaped_detail(&skip.detail),
                "library entry skipped"
            );
        }
    }
    if let Some(line) = more_skips_line(skips.len()) {
        tracing::warn!(target: "audit", actor = %user.id, "{line}");
    }
    by_reason
}

/// How the entry and summary audit rows are written: the overall deadline and
/// the queue. Production uses the process-wide queue; a test passes its own so
/// it does not share caps with other tests.
#[derive(Clone, Copy)]
struct AuditVia {
    deadline: std::time::Duration,
    queue: Option<&'static crate::db_audit::WriteQueue>,
}

const PRODUCTION_AUDIT: AuditVia = AuditVia {
    deadline: ENTRY_AUDIT_DEADLINE,
    queue: None,
};

async fn write_reporting(
    via: AuditVia,
    pool: &sqlx::PgPool,
    ev: crate::db_audit::NewAuditEvent<'_>,
) -> crate::db_audit::Submission {
    match via.queue {
        Some(q) => crate::db_audit::record_reporting_on(q, pool, ev).await,
        None => crate::db_audit::record_or_log_reporting(pool, ev).await,
    }
}

/// Write one `catalog.import_library_entry` row per skip, up to the cap and the
/// overall deadline, and return how many writes were queued (not shed).
///
/// Entry rows go through the queue, which collapses identical denied or
/// rejected rows (same user, entry id, reason code) seen within 300 s into one
/// row with a larger `repeat_count`. Writes are detached: when the deadline
/// passes, the write in flight is not cancelled (it finishes and is counted on
/// its own) and no further entry rows are submitted. A skip of the outer
/// archive is not handled here.
async fn audit_skip_entries(
    state: &AppState,
    user: &AuthUser,
    ctx: &RequestCtx,
    skips: &[&LibrarySkip],
    via: AuditVia,
) -> usize {
    let deadline = tokio::time::Instant::now() + via.deadline;
    let mut attempted = 0usize;
    for skip in skips.iter().take(MAX_SKIPPED_ENTRIES_AUDITED) {
        let write = write_reporting(
            via,
            state.pool.as_ref(),
            crate::db_audit::NewAuditEvent {
                user_id: &user.id,
                ctx: Some(ctx),
                action: "catalog.import_library_entry",
                outcome: "rejected",
                asset_id: None,
                checklist_id: None,
                stig_id: Some(&skip.id),
                detail: serde_json::json!({
                    "reasonCode": skip.code,
                    "entry": crate::db_audit::audit_safe_id(&skip.id),
                }),
            },
        );
        // `write` submits on its first poll, so a queued row is in flight
        // even when the deadline has already passed.
        let Ok(submission) = tokio::time::timeout_at(deadline, write).await else {
            // Elapsed, so the write was queued and is still running.
            attempted += 1;
            tracing::error!(target: "audit", "entry audit deadline reached; stopping entry rows");
            break;
        };
        // A shed write (queue over a cap) wrote no row and is not counted.
        if submission == crate::db_audit::Submission::Submitted {
            attempted += 1;
        }
    }
    attempted
}

/// Counts for one import's `catalog.import_library` summary row.
struct ImportCounts<'a> {
    skipped: usize,
    by_reason: &'a std::collections::BTreeMap<&'static str, usize>,
    audited: usize,
    parsed: usize,
    /// Rows committed to the catalog.
    imported: usize,
    /// Entries that were parsed but could not be written.
    failed: usize,
    commit_failed: bool,
    bytes_compressed: usize,
}

/// Outcome and detail of the summary row: `ok` with nothing skipped or failed,
/// `partial` when something was imported alongside skips or failures, and
/// `rejected` when nothing was imported.
fn import_summary(c: &ImportCounts<'_>) -> (&'static str, serde_json::Value) {
    let empty = c.skipped == 0 && c.failed == 0 && c.parsed == 0 && !c.commit_failed;
    let outcome = if empty {
        "rejected"
    } else if c.skipped == 0 && c.failed == 0 {
        "ok"
    } else if c.imported > 0 {
        "partial"
    } else {
        "rejected"
    };
    let reason_code = if c.commit_failed {
        Some("commit_failed")
    } else if empty {
        Some("no_entries")
    } else if c.skipped > 0 {
        Some("entries_skipped")
    } else if c.failed > 0 {
        Some("write_failed")
    } else {
        None
    };
    let mut detail = serde_json::json!({
        "skipped": c.skipped,
        "skippedAudited": c.audited,
        "skippedTruncated": c.skipped > MAX_SKIPPED_ENTRIES_AUDITED,
        "byReason": c.by_reason,
        "parsed": c.parsed,
        "imported": c.imported,
        "failed": c.failed,
        "bytesCompressed": c.bytes_compressed,
    });
    if let (Some(code), Some(map)) = (reason_code, detail.as_object_mut()) {
        map.insert("reasonCode".into(), code.into());
    }
    (outcome, detail)
}

/// Write the summary row through the queue (no transaction).
async fn record_summary(
    state: &AppState,
    user: &AuthUser,
    ctx: &RequestCtx,
    outcome: &'static str,
    detail: serde_json::Value,
    via: AuditVia,
) {
    write_reporting(
        via,
        state.pool.as_ref(),
        crate::db_audit::NewAuditEvent {
            user_id: &user.id,
            ctx: Some(ctx),
            action: "catalog.import_library",
            outcome,
            asset_id: None,
            checklist_id: None,
            stig_id: None,
            detail,
        },
    )
    .await;
}

/// Log a failed join of a blocking or detached task; the client gets a fixed
/// message, never the error text.
fn join_failed(what: &str, e: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::error!("{what} task failed: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}

fn internal_error() -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}

/// Longest a catalog-commit statement may run or wait for a lock.
const COMMIT_TIMEOUT_MS: i64 = 8_000;

/// Commit catalog rows and the audit row in one transaction.
async fn commit_catalog(
    pool: &sqlx::PgPool,
    entries: &[CatalogEntry],
    ev: &crate::db_audit::NewAuditEvent<'_>,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    // Bound every statement so a stuck commit fails (and its caller discards
    // its temps) instead of holding the publish lock indefinitely.
    sqlx::query(
        "SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', $1, true)",
    )
    .bind(COMMIT_TIMEOUT_MS.to_string())
    .execute(&mut *tx)
    .await?;
    for e in entries {
        upsert_catalog_tx(&mut tx, e).await?;
    }
    crate::db_audit::record_in_tx(&mut tx, ev).await?;
    tx.commit().await?;
    Ok(())
}

/// The validated fields of a single-STIG upload.
pub(crate) struct StigUpload {
    pub(crate) id: String,
    pub(crate) category: String,
    pub(crate) zip_bytes: Vec<u8>,
}

/// POST /api/upload
///
/// Requires an authenticated session with the `admin` role.
///
/// Accepts a multipart form upload with the following fields (order-independent):
///   file     — the DISA STIG ZIP (required)
///   id       — machine-readable slug, e.g. "windows-11" (required)
///   category — one of Windows / Linux / Browser / Network (required)
///
/// Example:
///   curl -X POST http://localhost:8080/api/upload \
///        -b "stig_session=<admin session cookie>" \
///        -F "file=@U_MS_Windows_11_V2R3_STIG.zip" \
///        -F "id=windows-11" \
///        -F "category=Windows"
pub async fn upload_stig(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_admin(&user)?;

    let mut zip_bytes: Option<Vec<u8>> = None;
    let mut id: Option<String> = None;
    let mut category: Option<String> = None;

    // Collect all multipart fields
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {e}")))?
    {
        match field.name() {
            Some("file") => {
                let bytes = field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read file field: {e}"),
                    )
                })?;
                zip_bytes = Some(bytes.to_vec());
            }
            Some("id") => {
                let text = field.text().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read id field: {e}"),
                    )
                })?;
                if !crate::stig_id::is_valid_new(&text) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!(
                            "id must be 1-{} lower-case ASCII letters, digits or hyphens",
                            crate::stig_id::MAX_BYTES
                        ),
                    ));
                }
                id = Some(text);
            }
            Some("category") => {
                let text = field.text().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read category field: {e}"),
                    )
                })?;
                category = Some(text);
            }
            _ => {} // ignore unknown fields
        }
    }

    let zip_bytes = zip_bytes.ok_or((StatusCode::BAD_REQUEST, "Missing 'file' field".into()))?;
    let id = id.ok_or((StatusCode::BAD_REQUEST, "Missing 'id' field".into()))?;
    let category = category.ok_or((StatusCode::BAD_REQUEST, "Missing 'category' field".into()))?;
    publish_stig(
        state,
        user,
        ctx,
        StigUpload {
            id,
            category,
            zip_bytes,
        },
    )
    .await
}

/// Run the upload as a detached task; no await before the spawn, so a client
/// disconnect cannot split the file, catalog row and audit row.
pub(crate) async fn publish_stig(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    up: StigUpload,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tasks = state.tasks.clone();
    crate::detached::run(
        &tasks,
        "stig upload",
        upload_stig_work(state, user, ctx, up),
    )
    .await
    .map_err(|code| (code, "internal error".to_string()))?
}

async fn upload_stig_work(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    up: StigUpload,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let StigUpload {
        id,
        category,
        zip_bytes,
    } = up;
    let stigs_dir = state.config.data_dir.join("stigs");
    crate::api::catalog_store::sweep_stale(
        &stigs_dir,
        &state.pool,
        crate::api::catalog_store::STALE_AFTER,
    )
    .await;

    // Extract and parse XCCDF
    // Both steps are CPU-bound (decompression and XML parsing).
    let compressed = zip_bytes.len();
    let extracted = tokio::task::spawn_blocking(move || {
        extract_xccdf_from_zip(&zip_bytes).map(|xccdf| parse_xccdf(&xccdf))
    })
    .await
    .map_err(|e| join_failed("stig parse", e))?;
    let stig = match extracted {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(e)) => {
            // The parser's text is untrusted; the audit row gets a fixed reason.
            tracing::warn!(target: "audit", actor = %user.id, "XCCDF parse failed: {e}");
            record_zip_rejection(
                &state,
                &user,
                &ctx,
                "catalog.upload",
                Some(&id),
                Rejection::new(
                    ("parse_failed", "The XCCDF document could not be parsed."),
                    compressed,
                ),
            )
            .await;
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("XCCDF parse failed: {e}"),
            ));
        }
        Err(e) => {
            record_zip_rejection(
                &state,
                &user,
                &ctx,
                "catalog.upload",
                Some(&id),
                Rejection::new((e.code(), &e.to_string()), compressed),
            )
            .await;
            return Err(zip_rejection(&e));
        }
    };

    // Lint the JSON shape *before* we write anything. We feed in the
    // multipart-supplied `id` + `category` alongside the parsed STIG so the
    // lint pass sees the full top-level shape it expects.
    let mut lint_value = serde_json::to_value(&stig).map_err(|e| {
        tracing::error!("lint pre-serialise failed: {e}");
        internal_error()
    })?;
    if let Some(obj) = lint_value.as_object_mut() {
        obj.insert("id".into(), serde_json::Value::String(id.clone()));
        obj.insert(
            "category".into(),
            serde_json::Value::String(category.clone()),
        );
    }
    let lint_report = lint_stig(&lint_value);
    if !lint_report.errors.is_empty() {
        let body = serde_json::to_string(&lint_report).unwrap_or_else(|_| "{}".into());
        return Err((StatusCode::BAD_REQUEST, body));
    }

    let json_str = serde_json::to_string(&stig).map_err(|e| {
        tracing::error!("stig serialisation failed: {e}");
        internal_error()
    })?;
    tokio::fs::create_dir_all(&stigs_dir).await.map_err(|e| {
        tracing::error!("could not create the stigs dir: {e}");
        internal_error()
    })?;
    // Stage the file; it is published only after the catalog commit.
    let staged = crate::api::catalog_store::stage(&stigs_dir, &id, &json_str)
        .await
        .map_err(|e| {
            tracing::error!("could not stage the STIG file: {e}");
            internal_error()
        })?;

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
        json_path: staged.dest.to_string_lossy().into_owned(),
        last_updated: Utc::now(),
    };
    let publish_guard = crate::api::catalog_store::publish_lock().await;
    let ev = crate::db_audit::NewAuditEvent {
        user_id: &user.id,
        ctx: Some(&ctx),
        action: "catalog.upload",
        outcome: "ok",
        asset_id: None,
        checklist_id: None,
        stig_id: Some(&id),
        detail: serde_json::json!({
            "ruleCount": rule_count,
            "bytesCompressed": compressed,
        }),
    };
    if let Err(e) = commit_catalog(&state.pool, std::slice::from_ref(&entry), &ev).await {
        tracing::error!("stig upload commit failed: {e:#}");
        staged.discard().await;
        return Err(internal_error());
    }
    if let Err(e) = staged.publish().await {
        // The catalog row and its `ok` audit row are already committed, yet the
        // request answers 500: the file is not in place. The temp stays, so the
        // next upload's sweep rolls it forward. A follow-up row records the failure.
        tracing::error!(target: "audit", stig_id = %id, "could not publish the STIG file: {e}");
        drop(publish_guard);
        write_reporting(
            PRODUCTION_AUDIT,
            state.pool.as_ref(),
            crate::db_audit::NewAuditEvent {
                user_id: &user.id,
                ctx: Some(&ctx),
                action: "catalog.upload_publish",
                outcome: "error",
                asset_id: None,
                checklist_id: None,
                stig_id: Some(&id),
                detail: serde_json::json!({"reasonCode": "publish_failed"}),
            },
        )
        .await;
        return Err(internal_error());
    }

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
/// from the inner filename and a category from the XCCDF title, then stages the
/// JSON files, upserts all catalog rows and the summary audit row in one
/// transaction, and publishes the files after the commit.
///
/// Requires an authenticated session with the `admin` role.
/// Body limit: `MAX_UPLOAD_BYTES` (set on the route in main.rs).
///
/// Runs in a spawned task so a client disconnect cannot split file writes,
/// catalog rows and audit rows.
///
/// Example:
///   curl -X POST http://localhost:8080/api/upload/library \
///        -b "stig_session=<admin session cookie>" \
///        -F "file=@U_SRG-STIG_Library_January_2026.zip"
pub async fn upload_library(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_admin(&user)?;

    // Read the single 'file' field
    let mut zip_bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {e}")))?
    {
        if field.name() == Some("file") {
            let bytes = field.bytes().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read file field: {e}"),
                )
            })?;
            zip_bytes = Some(bytes.to_vec());
        }
    }
    let zip_bytes = zip_bytes.ok_or((StatusCode::BAD_REQUEST, "Missing 'file' field".into()))?;
    import_library(state, user, ctx, zip_bytes).await
}

/// Run the import as a detached task; no await before the spawn.
pub(crate) async fn import_library(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    zip_bytes: Vec<u8>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tasks = state.tasks.clone();
    crate::detached::run(
        &tasks,
        "library import",
        import_library_work(state, user, ctx, zip_bytes),
    )
    .await
    .map_err(|code| (code, "internal error".to_string()))?
}

async fn import_library_work(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    zip_bytes: Vec<u8>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!(
        "Library bundle received ({} MB), processing…",
        zip_bytes.len() / 1_048_576
    );

    // Parsing is CPU-bound — run on blocking thread pool
    let compressed = zip_bytes.len();
    let (lib_entries, parse_errors) =
        match tokio::task::spawn_blocking(move || extract_all_from_library(&zip_bytes))
            .await
            .map_err(|e| join_failed("library parse", e))?
        {
            Ok(v) => v,
            Err(LibraryAbort {
                error: e,
                skips,
                parsed,
            }) => {
                let entry_skips: Vec<&LibrarySkip> =
                    skips.iter().filter(|s| !s.is_outer()).collect();
                let by_reason = log_and_tally_skips(&user, &entry_skips);
                // Entry rows first, so the rejection row can say how many landed.
                let audited =
                    audit_skip_entries(&state, &user, &ctx, &entry_skips, PRODUCTION_AUDIT).await;
                let reason = e.to_string();
                let mut rejection = Rejection::new((e.code(), &reason), compressed);
                rejection.tally = Some(SkipTally {
                    skipped: entry_skips.len(),
                    by_reason,
                    parsed,
                    audited,
                });
                record_zip_rejection(
                    &state,
                    &user,
                    &ctx,
                    "catalog.import_library",
                    None,
                    rejection,
                )
                .await;
                return Err(zip_rejection(&e));
            }
        };

    // An unreadable outer archive is answered with 200 + errorDetail (below);
    // it is still recorded as a rejection.
    let outer = parse_errors.first().filter(|s| s.is_outer());
    if let Some(outer) = outer {
        record_zip_rejection(
            &state,
            &user,
            &ctx,
            "catalog.import_library",
            None,
            Rejection::new((outer.code, &outer.detail), compressed),
        )
        .await;
    }
    let entry_skips: Vec<&LibrarySkip> = parse_errors.iter().filter(|s| !s.is_outer()).collect();
    let by_reason = log_and_tally_skips(&user, &entry_skips);
    let attempted = audit_skip_entries(&state, &user, &ctx, &entry_skips, PRODUCTION_AUDIT).await;

    // Stage every entry; nothing is published until the catalog commit.
    let stigs_dir = state.config.data_dir.join("stigs");
    tokio::fs::create_dir_all(&stigs_dir).await.map_err(|e| {
        tracing::error!("could not create the stigs dir: {e}");
        internal_error()
    })?;
    crate::api::catalog_store::sweep_stale(
        &stigs_dir,
        &state.pool,
        crate::api::catalog_store::STALE_AFTER,
    )
    .await;

    let parsed = lib_entries.len();
    let mut failures: Vec<serde_json::Value> = Vec::new();
    let mut staged: Vec<(crate::api::catalog_store::Staged, CatalogEntry)> = Vec::new();
    for entry in lib_entries {
        let json_str = match serde_json::to_string(&entry.stig) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("library entry '{}' serialisation failed: {e}", entry.id);
                failures.push(write_failure(&entry.id, "write_failed"));
                continue;
            }
        };
        let s = match crate::api::catalog_store::stage(&stigs_dir, &entry.id, &json_str).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("library entry '{}' could not be staged: {e}", entry.id);
                failures.push(write_failure(&entry.id, "write_failed"));
                continue;
            }
        };
        let title = if entry.stig.title.is_empty() {
            entry.id.clone()
        } else {
            entry.stig.title.clone()
        };
        let catalog_entry = CatalogEntry {
            id: entry.id.clone(),
            title,
            category: entry.category,
            version: entry.stig.version,
            release_info: entry.stig.release_info,
            rule_count: entry.stig.rules.len() as i32,
            json_path: s.dest.to_string_lossy().into_owned(),
            last_updated: Utc::now(),
        };
        staged.push((s, catalog_entry));
    }

    let skipped = entry_skips.len();
    let mut publish_failures: Vec<serde_json::Value> = Vec::new();
    let mut imported = 0usize;
    if staged.is_empty() {
        // The header-mismatch case already has its one (rejection) row.
        if !(outer.is_some() && entry_skips.is_empty()) {
            let (outcome, detail) = import_summary(&ImportCounts {
                skipped,
                by_reason: &by_reason,
                audited: attempted,
                parsed,
                imported: 0,
                failed: failures.len(),
                commit_failed: false,
                bytes_compressed: compressed,
            });
            record_summary(&state, &user, &ctx, outcome, detail, PRODUCTION_AUDIT).await;
        }
    } else {
        let publish_guard = crate::api::catalog_store::publish_lock().await;
        let entries: Vec<CatalogEntry> = staged.iter().map(|(_, e)| e.clone()).collect();
        let (outcome, detail) = import_summary(&ImportCounts {
            skipped,
            by_reason: &by_reason,
            audited: attempted,
            parsed,
            imported: entries.len(),
            failed: failures.len(),
            commit_failed: false,
            bytes_compressed: compressed,
        });
        let ev = crate::db_audit::NewAuditEvent {
            user_id: &user.id,
            ctx: Some(&ctx),
            action: "catalog.import_library",
            outcome,
            asset_id: None,
            checklist_id: None,
            stig_id: None,
            detail,
        };
        if let Err(e) = commit_catalog(&state.pool, &entries, &ev).await {
            tracing::error!("library import commit failed: {e:#}");
            for (s, _) in &staged {
                s.discard().await;
            }
            let (outcome, detail) = import_summary(&ImportCounts {
                skipped,
                by_reason: &by_reason,
                audited: attempted,
                parsed,
                imported: 0,
                failed: failures.len() + staged.len(),
                commit_failed: true,
                bytes_compressed: compressed,
            });
            record_summary(&state, &user, &ctx, outcome, detail, PRODUCTION_AUDIT).await;
            return Err(internal_error());
        }
        let mut failed_ids: Vec<String> = Vec::new();
        for (s, e) in &staged {
            match s.publish().await {
                Ok(()) => {
                    tracing::info!(
                        "  Imported '{}' ({}): {} rules",
                        e.id,
                        e.title,
                        e.rule_count
                    );
                    imported += 1;
                }
                Err(err) => {
                    // The row is committed; the temp stays for the next sweep.
                    tracing::error!(target: "audit", stig_id = %e.id, "could not publish the STIG file: {err}");
                    publish_failures.push(write_failure(&e.id, "publish_failed"));
                    failed_ids.push(crate::db_audit::audit_safe_id(&e.id));
                }
            }
        }
        drop(publish_guard);
        if !failed_ids.is_empty() {
            // The summary row (written in the commit) counted these as imported;
            // this follow-up records which files never reached `{id}.json`.
            // Their temps stay, so the next sweep rolls them forward.
            let n = failed_ids.len();
            failed_ids.truncate(MAX_SKIPPED_ENTRIES_AUDITED);
            write_reporting(
                PRODUCTION_AUDIT,
                state.pool.as_ref(),
                crate::db_audit::NewAuditEvent {
                    user_id: &user.id,
                    ctx: Some(&ctx),
                    action: "catalog.import_library_publish",
                    outcome: "error",
                    asset_id: None,
                    checklist_id: None,
                    stig_id: None,
                    detail: serde_json::json!({
                        "reasonCode": "publish_failed",
                        "publishFailed": n,
                        "ids": failed_ids,
                        "idsTruncated": n > MAX_SKIPPED_ENTRIES_AUDITED,
                    }),
                },
            )
            .await;
        }
    }

    let mut all_errors: Vec<serde_json::Value> = parse_errors
        .iter()
        .map(|s| serde_json::json!({"id": s.id, "reasonCode": s.code, "error": s.message}))
        .collect();
    all_errors.extend(failures);
    all_errors.extend(publish_failures);

    let total_errors = all_errors.len();
    tracing::info!("Library import complete: {imported} imported, {total_errors} errors");

    Ok(Json(serde_json::json!({
        "imported": imported,
        "errors": total_errors,
        "errorDetail": all_errors,
    })))
}

/// An `errorDetail` item for an entry that could not be written; the real
/// error is logged, not returned.
fn write_failure(id: &str, code: &'static str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "reasonCode": code,
        "error": "The entry could not be written.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(role: &str) -> AuthUser {
        AuthUser {
            id: "u1".into(),
            display_name: "U".into(),
            email: String::new(),
            role: role.into(),
        }
    }

    #[test]
    fn skip_log_helpers_escape_and_cap() {
        let d = escaped_detail("a\nFORGED\r\"q\"");
        assert!(!d.contains('\n') && !d.contains('\r'), "{d}");
        assert!(d.contains("FORGED"));
        assert_eq!(escaped_detail(&"x".repeat(500)).len(), 302);
        assert_eq!(more_skips_line(MAX_SKIPPED_ENTRIES_AUDITED), None);
        assert_eq!(
            more_skips_line(MAX_SKIPPED_ENTRIES_AUDITED + 5).as_deref(),
            Some("5 more skipped entries not logged individually")
        );
    }

    #[test]
    fn only_admins_may_upload() {
        assert!(ensure_admin(&user("admin")).is_ok());
        for role in ["author", "reviewer", "viewer", "", "Admin"] {
            let (status, _) = ensure_admin(&user(role)).unwrap_err();
            assert_eq!(status, StatusCode::FORBIDDEN, "{role:?}");
        }
    }

    // ── Database-backed: rejected archives change nothing and are audited ──

    use crate::test_fixtures::{app_state, auth, ctx, seed_user};
    use axum::{
        extract::{DefaultBodyLimit, Request},
        middleware::{self, Next},
        routing::post,
        Router,
    };
    use sqlx::PgPool;
    use std::io::Write;

    async fn serve(state: AppState) -> String {
        serve_as(state, "admin").await
    }

    async fn serve_as(state: AppState, role: &'static str) -> String {
        let app = Router::new()
            .route("/api/upload", post(upload_stig))
            .route("/api/upload/library", post(upload_library))
            .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES))
            .route_layer(middleware::from_fn(
                move |mut req: Request, next: Next| async move {
                    req.extensions_mut().insert(auth("admin1", role));
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

    fn zip_of(name: &str, data: &[u8]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        w.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap().into_inner()
    }

    async fn post_zip(base: &str, path: &str, zip: &[u8]) -> (u16, String) {
        let b = "XBOUNDARYX";
        let mut body = Vec::new();
        for (k, v) in [("id", "bomb-test"), ("category", "Linux")] {
            body.extend_from_slice(
                format!("--{b}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!("--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.zip\"\r\nContent-Type: application/zip\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(zip);
        body.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
        let r = crate::crypto::tls::http_client_builder()
            .build()
            .unwrap()
            .post(format!("{base}{path}"))
            .header("content-type", format!("multipart/form-data; boundary={b}"))
            .body(body)
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.text().await.unwrap_or_default())
    }

    async fn rejected_rows(pool: &PgPool, action: &str) -> Vec<serde_json::Value> {
        sqlx::query_scalar(
            "SELECT detail FROM audit_events WHERE action = $1 AND outcome = 'rejected'",
        )
        .bind(action)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_decompression_bomb_is_413_audited_and_writes_nothing(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
        let (state, _dir) = app_state(pool.clone());
        let data_dir = state.config.data_dir.clone();
        let base = serve(state).await;

        let mut xml = b"<Benchmark/>".to_vec();
        xml.resize(64 * 1024 * 1024 + 1, b' ');
        let zip = zip_of("a-xccdf.xml", &xml);
        assert!(zip.len() < 1 << 20);
        let (status, body) = post_zip(&base, "/api/upload", &zip).await;
        assert_eq!(status, 413, "{body}");
        assert_eq!(
            body,
            "An entry in the archive is larger than the allowed uncompressed size."
        );

        let rows = rejected_rows(&pool, "catalog.upload").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reasonCode"], "entry_too_large");
        assert_eq!(rows[0]["bytesCompressed"], zip.len());
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stigs_catalog")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(!data_dir.join("stigs/bomb-test.json").exists());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_library_over_the_budget_is_413_audited_and_writes_nothing(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
        let (state, _dir) = app_state(pool.clone());
        let data_dir = state.config.data_dir.clone();
        let base = serve(state).await;

        // One 64 MiB (the per-entry cap) whitespace XCCDF, deflated to ~64 KiB,
        // shared by 33 library entries: 33 x 64 MiB > the 2 GiB budget.
        let inner = zip_of("a-xccdf.xml", &vec![b' '; 64 * 1024 * 1024]);
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        // Two junk entries come first: their skips must reach the rejection row.
        for name in ["U_JunkA_V1R1_STIG.zip", "U_JunkB_V1R1_STIG.zip"] {
            w.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(b"not a zip").unwrap();
        }
        for i in 0..33 {
            w.start_file(
                format!("U_Big{i}_V1R1_STIG.zip"),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
            w.write_all(&inner).unwrap();
        }
        let lib = w.finish().unwrap().into_inner();

        let (status, body) = post_zip(&base, "/api/upload/library", &lib).await;
        assert_eq!(status, 413, "{body}");
        assert_eq!(
            body,
            "The archive is larger than the allowed total uncompressed size."
        );
        let rows = rejected_rows(&pool, "catalog.import_library").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reasonCode"], "budget_exceeded");
        assert_eq!(rows[0]["skipped"], 2, "{:?}", rows[0]);
        assert_eq!(rows[0]["byReason"]["malformed"], 2, "{:?}", rows[0]);
        // Entries parsed before the budget ran out; none of them is written.
        assert!(
            rows[0]["parsed"].as_u64().is_some_and(|n| n > 0 && n < 33),
            "{:?}",
            rows[0]
        );
        assert_eq!(rows[0]["skippedAudited"], 2, "{:?}", rows[0]);
        assert_eq!(rows[0]["skippedTruncated"], false, "{:?}", rows[0]);
        crate::db_audit::drain().await;
        let entries = rows_of(&pool, "catalog.import_library_entry").await;
        let mut ids: Vec<_> = entries
            .iter()
            .map(|(o, stig, d)| {
                assert_eq!(o, "rejected");
                assert_eq!(d["reasonCode"], "malformed");
                stig.clone().unwrap()
            })
            .collect();
        ids.sort();
        assert_eq!(ids, ["junka", "junkb"]);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stigs_catalog")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        // Nothing was written beyond the fixture STIG that `app_state` seeds.
        let written: std::collections::BTreeSet<String> = std::fs::read_dir(data_dir.join("stigs"))
            .expect("the stigs dir exists")
            .map(|e| {
                e.expect("readable dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        let expected: std::collections::BTreeSet<String> =
            [format!("{}.json", crate::test_fixtures::STIG_ID)].into();
        assert_eq!(written, expected);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_header_mismatch_is_422_and_audited(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
        let (state, _dir) = app_state(pool.clone());
        let base = serve(state).await;

        let mut zip = zip_of("a-xccdf.xml", b"<Benchmark/>");
        let cd = zip.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        zip[cd + 46] = b'b';
        let (status, body) = post_zip(&base, "/api/upload", &zip).await;
        assert_eq!(status, 422, "{body}");
        assert_eq!(body, "The archive's ZIP headers are inconsistent.");
        let rows = rejected_rows(&pool, "catalog.upload").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reasonCode"], "header_inconsistency");

        // The library route answers 200 with errorDetail but still audits.
        let (status, body) = post_zip(&base, "/api/upload/library", &zip).await;
        assert_eq!(status, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["errorDetail"][0]["id"], "(outer zip)");
        assert_eq!(v["errorDetail"][0]["reasonCode"], "header_inconsistency");
        assert_eq!(
            v["errorDetail"][0]["error"],
            "The archive's ZIP headers are inconsistent."
        );
        let rows = rejected_rows(&pool, "catalog.import_library").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reasonCode"], "header_inconsistency");
    }

    fn lib_of(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (n, d) in entries {
            w.start_file(n, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(d).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    async fn admin_server(pool: &PgPool) -> String {
        seed_user(pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(pool)
            .await
            .unwrap();
        let (state, dir) = app_state(pool.clone());
        // Keep the data dir for the whole test process.
        std::mem::forget(dir);
        serve(state).await
    }

    async fn rows_of(
        pool: &PgPool,
        action: &str,
    ) -> Vec<(String, Option<String>, serde_json::Value)> {
        sqlx::query_as(
            "SELECT outcome, stig_id, detail FROM audit_events WHERE action = $1 ORDER BY id",
        )
        .bind(action)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn each_skipped_library_entry_gets_an_audit_row_and_a_summary(pool: PgPool) {
        let base = admin_server(&pool).await;
        let good = zip_of(
            "a-xccdf.xml",
            br#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><title>Good</title>
            <Group id="V-1"><Rule id="SV-1_rule" severity="low"><title>r</title></Rule></Group></Benchmark>"#,
        );
        let no_xccdf = zip_of("readme.txt", b"hello");
        let bad_id = zip_of(
            "x-xccdf.xml",
            br#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><title>T</title></Benchmark>"#,
        );
        let lib = lib_of(&[
            ("U_Good_V1R1_STIG.zip".into(), good),
            ("U_Bad_One_V1R1_STIG.zip".into(), b"not a zip".to_vec()),
            ("U_Bad_Two_V1R1_STIG.zip".into(), no_xccdf),
            ("U_\u{e9}\u{e9}_V1R1_STIG.zip".into(), bad_id),
        ]);
        let (status, body) = post_zip(&base, "/api/upload/library", &lib).await;
        assert_eq!(status, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["imported"], 1, "{body}");
        for item in v["errorDetail"].as_array().unwrap() {
            assert!(item["reasonCode"].is_string(), "{item}");
            assert!(!item["error"].as_str().unwrap().contains("zip::"), "{item}");
        }

        let entries = rows_of(&pool, "catalog.import_library_entry").await;
        let mut got: Vec<(String, String)> = entries
            .iter()
            .map(|(o, stig, d)| {
                assert_eq!(o, "rejected");
                assert!(d["entry"].is_string());
                assert_eq!(d.as_object().unwrap().len(), 2, "no free text: {d}");
                (
                    stig.clone().unwrap(),
                    d["reasonCode"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("bad-one".to_string(), "malformed".to_string()),
                ("bad-two".to_string(), "no_xccdf".to_string()),
                ("x-xccdf.xml".to_string(), "invalid_id".to_string()),
            ]
        );

        let summary = rows_of(&pool, "catalog.import_library").await;
        assert_eq!(summary.len(), 1, "{summary:?}");
        let (outcome, _, d) = &summary[0];
        assert_eq!(outcome, "partial");
        assert_eq!(d["reasonCode"], "entries_skipped");
        assert_eq!(d["skipped"], 3);
        assert_eq!(d["skippedAudited"], 3);
        assert_eq!(d["skippedTruncated"], false);
        assert_eq!(d["parsed"], 1);
        assert_eq!(d["byReason"]["malformed"], 1);
        assert_eq!(d["byReason"]["no_xccdf"], 1);
        assert_eq!(d["byReason"]["invalid_id"], 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_malformed_xccdf_is_reported_with_a_fixed_message(pool: PgPool) {
        let base = admin_server(&pool).await;
        let broken = zip_of(
            "x-xccdf.xml",
            b"<Benchmark><title>SECRETPARSERTEXT</Benchmark>",
        );
        let lib = lib_of(&[("U_Broken_V1R1_STIG.zip".into(), broken)]);
        let (status, body) = post_zip(&base, "/api/upload/library", &lib).await;
        assert_eq!(status, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["errorDetail"][0]["id"], "broken");
        assert_eq!(v["errorDetail"][0]["reasonCode"], "xccdf_parse_failed");
        assert_eq!(
            v["errorDetail"][0]["error"],
            "The XCCDF document could not be parsed."
        );
        assert!(
            !body.contains("SECRETPARSERTEXT") && !body.contains("expected"),
            "{body}"
        );
        let rows = rows_of(&pool, "catalog.import_library_entry").await;
        assert_eq!(rows[0].2["reasonCode"], "xccdf_parse_failed");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_entry_audit_deadline_stops_entry_rows_but_not_the_summary(pool: PgPool) {
        seed_user(&pool, "deadline-user").await;
        let (state, _dir) = app_state(pool.clone());
        let user = auth("deadline-user", "admin");
        let (cap, _g) = crate::api::audit_capture::capture();
        let skips: Vec<LibrarySkip> = (0..5)
            .map(|i| LibrarySkip {
                id: format!("junk{i}"),
                code: "malformed",
                message: "m",
                detail: String::new(),
                outer: false,
            })
            .collect();
        let refs: Vec<&LibrarySkip> = skips.iter().collect();
        static C: crate::failure_counters::FailureCounter =
            crate::failure_counters::FailureCounter::new();
        static Q: crate::db_audit::WriteQueue = crate::db_audit::WriteQueue::new(&C, 64, 16, 4);
        let via = AuditVia {
            deadline: std::time::Duration::ZERO,
            queue: Some(&Q),
        };
        let by_reason = log_and_tally_skips(&user, &refs);
        let attempted = audit_skip_entries(&state, &user, &ctx(), &refs, via).await;
        let (outcome, detail) = import_summary(&ImportCounts {
            skipped: refs.len(),
            by_reason: &by_reason,
            audited: attempted,
            parsed: 0,
            imported: 0,
            failed: 0,
            commit_failed: false,
            bytes_compressed: 10,
        });
        record_summary(&state, &user, &ctx(), outcome, detail, via).await;
        let deadline_lines = cap
            .lines()
            .iter()
            .filter(|l| {
                l.values()
                    .any(|v| v.contains("entry audit deadline reached"))
            })
            .count();
        assert_eq!(deadline_lines, 1);

        let summary = rows_of(&pool, "catalog.import_library").await;
        assert_eq!(summary.len(), 1, "{summary:?}");
        let d = &summary[0].2;
        assert_eq!(d["skipped"], 5);
        let audited = d["skippedAudited"].as_u64().unwrap();
        assert_eq!(audited, 1, "{d}");

        // The write in flight at the deadline is detached; this test's own
        // queue says when it has finished.
        Q.drain().await;
        assert_eq!(Q.shed_writes(), 0);
        let entries = rows_of(&pool, "catalog.import_library_entry").await;
        assert_eq!(entries.len() as u64, audited);
        let repeats: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(repeat_count), 0)::BIGINT FROM audit_events WHERE action = 'catalog.import_library_entry'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(repeats as u64, audited);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_non_admin_library_upload_is_403_and_changes_nothing(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        let (state, _dir) = app_state(pool.clone());
        let data_dir = state.config.data_dir.clone();
        let base = serve_as(state, "user").await;
        let good = zip_of(
            "a-xccdf.xml",
            br#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><title>G</title>
            <Group id="V-1"><Rule id="SV-1_rule" severity="low"><title>r</title></Rule></Group></Benchmark>"#,
        );
        let lib = lib_of(&[("U_Good_V1R1_STIG.zip".into(), good)]);
        let (status, body) = post_zip(&base, "/api/upload/library", &lib).await;
        assert_eq!(status, 403, "{body}");
        crate::db_audit::drain().await;
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stigs_catalog")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        let files: Vec<String> = std::fs::read_dir(data_dir.join("stigs"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(files, [format!("{}.json", crate::test_fixtures::STIG_ID)]);
        assert!(rows_of(&pool, "catalog.import_library").await.is_empty());
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE user_id = 'admin1' AND action LIKE 'catalog.%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn library_import_and_its_audit_rows_survive_the_handler_future_being_dropped(
        pool: PgPool,
    ) {
        seed_user(&pool, "admin1").await;
        let (state, _dir) = app_state(pool.clone());
        let data_dir = state.config.data_dir.clone();
        let tasks = state.tasks.clone();
        let good = |t: &str| {
            zip_of(
                "a-xccdf.xml",
                format!(
                    r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><title>{t}</title>
            <Group id="V-1"><Rule id="SV-1_rule" severity="low"><title>r</title></Rule></Group></Benchmark>"#
                )
                .as_bytes(),
            )
        };
        let lib = lib_of(&[
            ("U_GoodA_V1R1_STIG.zip".into(), good("A")),
            ("U_GoodB_V1R1_STIG.zip".into(), good("B")),
            ("U_Junk_V1R1_STIG.zip".into(), b"not a zip".to_vec()),
        ]);
        {
            let call = import_library(state, auth("admin1", "admin"), ctx(), lib);
            let mut call = std::pin::pin!(call);
            let pending = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(std::future::Future::poll(call.as_mut(), cx).is_pending())
            })
            .await;
            assert!(pending, "the handler must still be waiting on its task");
            assert_eq!(tasks.in_flight(), 1);
        } // caller dropped
        tasks.idle().await;
        crate::db_audit::drain().await;

        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM stigs_catalog ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(ids, ["gooda", "goodb"]);
        for id in &ids {
            assert!(data_dir.join(format!("stigs/{id}.json")).exists(), "{id}");
        }
        assert_eq!(
            rows_of(&pool, "catalog.import_library_entry").await.len(),
            1
        );
        let summary = rows_of(&pool, "catalog.import_library").await;
        assert_eq!(summary.len(), 1, "{summary:?}");
        assert_eq!(summary[0].0, "partial");
        assert_eq!(summary[0].2["skipped"], 1);
        assert_eq!(summary[0].2["parsed"], 2);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn per_entry_audit_rows_are_capped_and_the_summary_keeps_the_true_count(pool: PgPool) {
        let base = admin_server(&pool).await;
        let total = MAX_SKIPPED_ENTRIES_AUDITED + 5;
        let entries: Vec<(String, Vec<u8>)> = (0..total)
            .map(|i| (format!("U_Junk{i}_V1R1_STIG.zip"), b"junk".to_vec()))
            .collect();
        let (status, body) = post_zip(&base, "/api/upload/library", &lib_of(&entries)).await;
        assert_eq!(status, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["errors"], total, "every skip stays in the response");

        let rows = rows_of(&pool, "catalog.import_library_entry").await;
        assert_eq!(rows.len(), MAX_SKIPPED_ENTRIES_AUDITED);
        let summary = rows_of(&pool, "catalog.import_library").await;
        assert_eq!(summary.len(), 1, "{summary:?}");
        let (outcome, _, d) = &summary[0];
        assert_eq!(outcome, "rejected");
        assert_eq!(d["skipped"], total);
        assert_eq!(d["skippedAudited"], MAX_SKIPPED_ENTRIES_AUDITED);
        assert_eq!(d["skippedTruncated"], true);
        assert_eq!(d["parsed"], 0);
    }

    const GOOD_XML: &str = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><title>G</title>
            <Group id="V-1"><Rule id="SV-1_rule" severity="low"><title>r</title></Rule></Group></Benchmark>"#;

    #[tokio::test]
    async fn a_join_failure_is_logged_and_answered_with_a_fixed_message() {
        let e = tokio::task::spawn_blocking(|| -> () { panic!("SECRET") })
            .await
            .unwrap_err();
        let (status, body) = join_failed("test", e);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, "internal error");
        assert!(!body.contains("SECRET"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn single_stig_upload_survives_the_handler_future_being_dropped(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        let (state, _dir) = app_state(pool.clone());
        let data_dir = state.config.data_dir.clone();
        let tasks = state.tasks.clone();
        let call = publish_stig(
            state,
            auth("admin1", "admin"),
            ctx(),
            StigUpload {
                id: "single-one".into(),
                category: "Linux".into(),
                zip_bytes: zip_of("a-xccdf.xml", GOOD_XML.as_bytes()),
            },
        );
        crate::detached::abort_once_spawned(&tasks, call).await;
        tasks.idle().await;
        crate::db_audit::drain().await;

        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM stigs_catalog WHERE id = 'single-one'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(n, 1);
        assert!(data_dir.join("stigs/single-one.json").exists());
        let names: Vec<String> = std::fs::read_dir(data_dir.join("stigs"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|n| !n.starts_with(".upload-")),
            "{names:?}"
        );
        let rows = rows_of(&pool, "catalog.upload").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].0, "ok");
        assert_eq!(rows[0].1.as_deref(), Some("single-one"));
        assert_eq!(rows[0].2["ruleCount"], 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_clean_library_import_writes_one_ok_summary_row(pool: PgPool) {
        let base = admin_server(&pool).await;
        let good = zip_of("a-xccdf.xml", GOOD_XML.as_bytes());
        let lib = lib_of(&[
            ("U_GoodA_V1R1_STIG.zip".into(), good.clone()),
            ("U_GoodB_V1R1_STIG.zip".into(), good),
        ]);
        let (status, body) = post_zip(&base, "/api/upload/library", &lib).await;
        assert_eq!(status, 200, "{body}");
        let summary = sqlx::query_as::<_, (String, String, serde_json::Value)>(
            "SELECT outcome, user_id, detail FROM audit_events WHERE action = 'catalog.import_library'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(summary.len(), 1, "{summary:?}");
        let (outcome, user_id, d) = &summary[0];
        assert_eq!(outcome, "ok");
        assert_eq!(user_id, "admin1");
        assert_eq!(d["parsed"], 2);
        assert_eq!(d["imported"], 2);
        assert_eq!(d["skipped"], 0);
        assert_eq!(d["failed"], 0);
        assert!(rows_of(&pool, "catalog.import_library_entry")
            .await
            .is_empty());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_catalog_commit_leaves_the_old_file_no_temp_and_no_ok_row(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE stigs_catalog ADD CONSTRAINT refuse_goodb CHECK (id <> 'goodb')")
            .execute(&pool)
            .await
            .unwrap();
        let (state, _dir) = app_state(pool.clone());
        let stigs = state.config.data_dir.join("stigs");
        std::fs::write(stigs.join("goodb.json"), "MARKER").unwrap();
        let base = serve(state).await;
        let good = zip_of("a-xccdf.xml", GOOD_XML.as_bytes());
        let lib = lib_of(&[
            ("U_GoodA_V1R1_STIG.zip".into(), good.clone()),
            ("U_GoodB_V1R1_STIG.zip".into(), good),
        ]);
        let (status, body) = post_zip(&base, "/api/upload/library", &lib).await;
        assert_eq!(status, 500, "{body}");
        assert_eq!(body, "internal error");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stigs_catalog")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert_eq!(
            std::fs::read_to_string(stigs.join("goodb.json")).unwrap(),
            "MARKER"
        );
        assert!(!stigs.join("gooda.json").exists());
        let names: Vec<String> = std::fs::read_dir(&stigs)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|n| !n.starts_with(".upload-")),
            "{names:?}"
        );
        let summary = rows_of(&pool, "catalog.import_library").await;
        assert_eq!(summary.len(), 1, "{summary:?}");
        assert_eq!(summary[0].0, "rejected");
        assert_eq!(summary[0].2["reasonCode"], "commit_failed");
    }

    fn temps_in(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".upload-"))
            .collect()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_single_upload_whose_rename_fails_keeps_the_row_and_temp_and_audits_it(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        let (state, _dir) = app_state(pool.clone());
        let stigs = state.config.data_dir.join("stigs");
        // A directory at the destination makes the rename fail after the commit.
        std::fs::create_dir(stigs.join("pub-fail.json")).unwrap();
        let r = publish_stig(
            state,
            auth("admin1", "admin"),
            ctx(),
            StigUpload {
                id: "pub-fail".into(),
                category: "Linux".into(),
                zip_bytes: zip_of("a-xccdf.xml", GOOD_XML.as_bytes()),
            },
        )
        .await;
        let Err((status, body)) = r else {
            panic!("expected a 500");
        };
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, "internal error");
        crate::db_audit::drain().await;
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stigs_catalog WHERE id = 'pub-fail'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(temps_in(&stigs).len(), 1);
        let rows = rows_of(&pool, "catalog.upload").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].0, "ok");
        let follow = rows_of(&pool, "catalog.upload_publish").await;
        assert_eq!(follow.len(), 1, "{follow:?}");
        assert_eq!(follow[0].0, "error");
        assert_eq!(follow[0].2["reasonCode"], "publish_failed");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_library_import_whose_rename_fails_reports_publish_failed_and_audits_it(
        pool: PgPool,
    ) {
        seed_user(&pool, "admin1").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'admin1'")
            .execute(&pool)
            .await
            .unwrap();
        let (state, _dir) = app_state(pool.clone());
        let stigs = state.config.data_dir.join("stigs");
        std::fs::create_dir(stigs.join("gooda.json")).unwrap();
        let base = serve(state).await;
        let good = zip_of("a-xccdf.xml", GOOD_XML.as_bytes());
        let lib = lib_of(&[
            ("U_GoodA_V1R1_STIG.zip".into(), good.clone()),
            ("U_GoodB_V1R1_STIG.zip".into(), good),
        ]);
        let (status, body) = post_zip(&base, "/api/upload/library", &lib).await;
        assert_eq!(status, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["imported"], 1, "{body}");
        assert_eq!(v["errorDetail"][0]["id"], "gooda");
        assert_eq!(v["errorDetail"][0]["reasonCode"], "publish_failed");
        crate::db_audit::drain().await;
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stigs_catalog")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(temps_in(&stigs).len(), 1);
        assert!(stigs.join("goodb.json").is_file());
        let rows = rows_of(&pool, "catalog.import_library").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].0, "ok");
        let follow = rows_of(&pool, "catalog.import_library_publish").await;
        assert_eq!(follow.len(), 1, "{follow:?}");
        assert_eq!(follow[0].0, "error");
        assert_eq!(follow[0].2["reasonCode"], "publish_failed");
        assert_eq!(follow[0].2["publishFailed"], 1);
        assert_eq!(follow[0].2["ids"][0], "gooda");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn an_unparseable_single_upload_is_422_and_audited(pool: PgPool) {
        let base = admin_server(&pool).await;
        let zip = zip_of("a-xccdf.xml", b"<Benchmark><title>SECRET</Benchmark>");
        let (status, _) = post_zip(&base, "/api/upload", &zip).await;
        assert_eq!(status, 422);
        let rows = rejected_rows(&pool, "catalog.upload").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reasonCode"], "parse_failed");
        assert!(!rows[0].to_string().contains("SECRET"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn an_empty_library_is_one_rejected_no_entries_row(pool: PgPool) {
        let base = admin_server(&pool).await;
        let lib = lib_of(&[("readme.txt".into(), b"hi".to_vec())]);
        let (status, body) = post_zip(&base, "/api/upload/library", &lib).await;
        assert_eq!(status, 200, "{body}");
        let rows = rows_of(&pool, "catalog.import_library").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].0, "rejected");
        assert_eq!(rows[0].2["reasonCode"], "no_entries");
        assert_eq!(rows[0].2["imported"], 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_blocked_catalog_commit_times_out_and_changes_nothing(pool: PgPool) {
        seed_user(&pool, "admin1").await;
        let entry = CatalogEntry {
            id: "blocked".into(),
            title: "T".into(),
            category: "Linux".into(),
            version: "1".into(),
            release_info: String::new(),
            rule_count: 1,
            json_path: "x".into(),
            last_updated: Utc::now(),
        };
        // A second connection holds a conflicting table lock.
        let mut holder = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE stigs_catalog IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *holder)
            .await
            .unwrap();
        let c = ctx();
        let ev = crate::db_audit::NewAuditEvent {
            user_id: "admin1",
            ctx: Some(&c),
            action: "catalog.upload",
            outcome: "ok",
            asset_id: None,
            checklist_id: None,
            stig_id: Some("blocked"),
            detail: serde_json::json!({}),
        };
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(25),
            commit_catalog(&pool, std::slice::from_ref(&entry), &ev),
        )
        .await
        .expect("the commit must fail by itself, not hang");
        assert!(r.is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(15));
        holder.rollback().await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stigs_catalog")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(rows_of(&pool, "catalog.upload").await.is_empty());
    }
}
