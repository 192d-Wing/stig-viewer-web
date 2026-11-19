use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::Utc;

use crate::{
    api::{auth::AuthUser, request_ctx::RequestCtx, stig_validator::lint_stig},
    db::{upsert_catalog, CatalogEntry},
    parser::{extract_all_from_library, extract_xccdf_from_zip, parse_xccdf, LibrarySkip},
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

/// Audit a ZIP that was refused (too large, inconsistent headers, malformed).
/// Recorded outside any transaction: nothing was changed.
async fn record_zip_rejection(
    state: &AppState,
    user: &AuthUser,
    ctx: &RequestCtx,
    action: &'static str,
    stig_id: Option<&str>,
    (reason_code, reason): (&'static str, &str),
    bytes_compressed: usize,
) {
    let reason: String = reason.chars().take(300).collect();
    tracing::warn!(
        target: "audit",
        actor = %user.id,
        action,
        reason_code,
        "catalog upload rejected: {reason}"
    );
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
            detail: serde_json::json!({
                "reasonCode": reason_code,
                "reason": reason,
                "bytesCompressed": bytes_compressed,
            }),
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

/// Audit the skipped entries of an imported library: one
/// `catalog.import_library_entry` row per skip up to the cap, plus one
/// `catalog.import_library` summary row. Every skip is also logged. A skip of
/// the outer archive is not handled here (it is recorded as a rejection).
///
/// Entry rows go through `record_or_log`, which collapses identical denied or
/// rejected rows (same user, entry id, reason code) seen within 300 s into one
/// row with a larger `repeat_count`. The summary row's `skipped` is the true
/// count; `skippedAudited` is the number of entry writes attempted before the
/// cap or `deadline` stopped them (so it may be below the cap). A write
/// cancelled by the deadline is not counted there; it is counted as a failed
/// audit write in `AUDIT_WRITES`.
async fn audit_library_skips(
    state: &AppState,
    user: &AuthUser,
    ctx: &RequestCtx,
    skips: &[&LibrarySkip],
    parsed: usize,
    bytes_compressed: usize,
    deadline: std::time::Duration,
) {
    if skips.is_empty() {
        return;
    }
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
    let deadline = tokio::time::Instant::now() + deadline;
    let mut attempted = 0usize;
    for skip in skips.iter().take(MAX_SKIPPED_ENTRIES_AUDITED) {
        let write = crate::db_audit::record_or_log(
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
        if tokio::time::timeout_at(deadline, write).await.is_err() {
            tracing::error!(target: "audit", "entry audit deadline reached; stopping entry rows");
            crate::failure_counters::AUDIT_WRITES.record_failure();
            break;
        }
        attempted += 1;
    }
    let n = skips.len();
    crate::db_audit::record_or_log(
        state.pool.as_ref(),
        crate::db_audit::NewAuditEvent {
            user_id: &user.id,
            ctx: Some(ctx),
            action: "catalog.import_library",
            outcome: if parsed > 0 { "partial" } else { "rejected" },
            asset_id: None,
            checklist_id: None,
            stig_id: None,
            detail: serde_json::json!({
                "reasonCode": "entries_skipped",
                "skipped": n,
                "skippedAudited": attempted,
                "skippedTruncated": n > MAX_SKIPPED_ENTRIES_AUDITED,
                "byReason": by_reason,
                "parsed": parsed,
                "bytesCompressed": bytes_compressed,
            }),
        },
    )
    .await;
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

    // Extract and parse XCCDF
    // Both steps are CPU-bound (decompression and XML parsing).
    let compressed = zip_bytes.len();
    let extracted = tokio::task::spawn_blocking(move || {
        extract_xccdf_from_zip(&zip_bytes).map(|xccdf| parse_xccdf(&xccdf))
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Task panic: {e}"),
        )
    })?;
    let stig = match extracted {
        Ok(parsed) => parsed.map_err(|e| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("XCCDF parse failed: {e}"),
            )
        })?,
        Err(e) => {
            record_zip_rejection(
                &state,
                &user,
                &ctx,
                "catalog.upload",
                Some(&id),
                (e.code(), &e.to_string()),
                compressed,
            )
            .await;
            return Err(zip_rejection(&e));
        }
    };

    // Lint the JSON shape *before* we write anything. We feed in the
    // multipart-supplied `id` + `category` alongside the parsed STIG so the
    // lint pass sees the full top-level shape it expects.
    let mut lint_value = serde_json::to_value(&stig).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Lint pre-serialise failed: {e}"),
        )
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

    // Write JSON file
    let stigs_dir = state.config.data_dir.join("stigs");
    tokio::fs::create_dir_all(&stigs_dir).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create data dir: {e}"),
        )
    })?;

    let json_path = stigs_dir.join(format!("{id}.json"));
    let json_str = serde_json::to_string(&stig).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Serialisation failed: {e}"),
        )
    })?;
    tokio::fs::write(&json_path, &json_str).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to write JSON: {e}"),
        )
    })?;

    // Upsert catalog row
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
    upsert_catalog(&state.pool, &entry).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database upsert failed: {e}"),
        )
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
/// Requires an authenticated session with the `admin` role.
/// Body limit: `MAX_UPLOAD_BYTES` (set on the route in main.rs).
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

    tracing::info!(
        "Library bundle received ({} MB), processing…",
        zip_bytes.len() / 1_048_576
    );

    // Parsing is CPU-bound — run on blocking thread pool
    let compressed = zip_bytes.len();
    let (lib_entries, parse_errors) =
        match tokio::task::spawn_blocking(move || extract_all_from_library(&zip_bytes))
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Task panic: {e}"),
                )
            })? {
            Ok(v) => v,
            Err(e) => {
                record_zip_rejection(
                    &state,
                    &user,
                    &ctx,
                    "catalog.import_library",
                    None,
                    (e.code(), &e.to_string()),
                    compressed,
                )
                .await;
                return Err(zip_rejection(&e));
            }
        };

    // An unreadable outer archive is answered with 200 + errorDetail (below);
    // it is still recorded as a rejection.
    if let Some(outer) = parse_errors.first().filter(|s| s.is_outer()) {
        record_zip_rejection(
            &state,
            &user,
            &ctx,
            "catalog.import_library",
            None,
            (outer.code, &outer.detail),
            compressed,
        )
        .await;
    }
    let entry_skips: Vec<&LibrarySkip> = parse_errors.iter().filter(|s| !s.is_outer()).collect();
    audit_library_skips(
        &state,
        &user,
        &ctx,
        &entry_skips,
        lib_entries.len(),
        compressed,
        ENTRY_AUDIT_DEADLINE,
    )
    .await;

    // Write JSON files and upsert catalog rows
    let stigs_dir = state.config.data_dir.join("stigs");
    tokio::fs::create_dir_all(&stigs_dir).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create data dir: {e}"),
        )
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
        .map(|s| serde_json::json!({"id": s.id, "reasonCode": s.code, "error": s.message}))
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
        let app = Router::new()
            .route("/api/upload", post(upload_stig))
            .route("/api/upload/library", post(upload_library))
            .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES))
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
        let r = reqwest::Client::new()
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
        seed_user(&pool, "admin1").await;
        let (state, _dir) = app_state(pool.clone());
        let user = auth("admin1", "admin");
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
        let before = crate::failure_counters::AUDIT_WRITES.snapshot().total;
        audit_library_skips(
            &state,
            &user,
            &ctx(),
            &refs,
            0,
            10,
            std::time::Duration::ZERO,
        )
        .await;
        let entries = rows_of(&pool, "catalog.import_library_entry").await;
        assert!(entries.len() < 5, "{}", entries.len());
        let summary = rows_of(&pool, "catalog.import_library").await;
        assert_eq!(summary.len(), 1, "{summary:?}");
        let d = &summary[0].2;
        assert_eq!(d["skipped"], 5);
        assert!(d["skippedAudited"].as_u64().unwrap() < 5, "{d}");
        assert!(crate::failure_counters::AUDIT_WRITES.snapshot().total > before);
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
}
