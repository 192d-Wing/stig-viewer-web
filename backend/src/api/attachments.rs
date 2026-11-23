use crate::crypto;
use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use tokio::io::AsyncWriteExt;

use crate::api::asset_acl;
use crate::api::audit_tx;
use crate::api::auth::AuthUser;
use crate::api::request_ctx::RequestCtx;
use crate::db_assets;
use crate::db_attachments::{self, AttachmentRow};
use crate::db_audit;
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

/// Like `load_checklist_and_asset`, but also requires `read` on the owning
/// asset. A missing checklist is 404; an existing but unreadable one is 403
/// (same split as the rest of the codebase; `authz_audit` records the 403).
async fn require_read(
    state: &AppState,
    user: &AuthUser,
    checklist_id: &str,
) -> Result<(db_checklists::ChecklistRow, db_assets::AssetRow), StatusCode> {
    let (checklist, asset) = load_checklist_and_asset(state, checklist_id).await?;
    if !asset_acl::user_can(state.pool.as_ref(), &asset.id, user, "read").await {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok((checklist, asset))
}

/// POST /api/checklists/:id/rules/:rule_id/attachments
///
/// Multipart upload. Owner-only.
pub async fn upload_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
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

    let attachment_id = crate::crypto::rand::uuid_v4().to_string();
    let dest = blob_path(&state, &attachment_id);

    let mut filename: Option<String> = None;
    let mut mime_type: Option<String> = None;
    let mut size_bytes: i64 = 0;
    let mut hasher = crypto::digest::Sha256Stream::new();
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
        sha256: hex::encode(hasher.finish()),
        uploaded_by: user.id.clone(),
        uploaded_at: chrono::Utc::now(),
    };

    // The row and its `attachment.upload` event commit together; any failure
    // removes the blob. The filename and MIME type are client text and are
    // not recorded.
    let rule_label = db_audit::audit_safe_id(&rule_id);
    let mut ev = audit_tx::ok_event(
        &user,
        &ctx,
        "attachment.upload",
        serde_json::json!({
            "attachmentId": row.id,
            "ruleId": rule_label,
            "sizeBytes": row.size_bytes,
            "sha256": row.sha256,
        }),
    );
    ev.asset_id = Some(&asset.id);
    ev.checklist_id = Some(&checklist_id);
    if let Err(code) = insert_audited(state.pool.as_ref(), &row, &ev).await {
        let _ = tokio::fs::remove_file(&dest).await;
        return Err(code);
    }

    Ok((StatusCode::CREATED, Json(row)))
}

/// Insert the attachment row and its audit event in one transaction.
async fn insert_audited(
    pool: &sqlx::PgPool,
    row: &AttachmentRow,
    ev: &db_audit::NewAuditEvent<'_>,
) -> Result<(), StatusCode> {
    let mut tx = crate::db::begin_bounded(pool)
        .await
        .map_err(audit_tx::failed)?;
    db_attachments::insert_on(&mut tx, row).await.map_err(|e| {
        tracing::error!("Failed to insert attachment row: {e:#}");
        audit_tx::failed(e)
    })?;
    audit_tx::record(&mut tx, ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))
}

/// GET /api/checklists/:id/rules/:rule_id/attachments — list rows for a rule.
/// Requires `read` on the owning asset (403 otherwise). Metadata listings are
/// not audited; denials are recorded by `authz_audit`.
pub async fn list_for_rule_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((checklist_id, rule_id)): Path<(String, String)>,
) -> Result<Json<Vec<AttachmentRow>>, StatusCode> {
    // 404 for a missing checklist, 403 when the caller cannot read its asset.
    let _ = require_read(&state, &user, &checklist_id).await?;
    let rows = db_attachments::list_for_rule(state.pool.as_ref(), &checklist_id, &rule_id)
        .await
        .map_err(map_db)?;
    Ok(Json(rows))
}

/// GET /api/checklists/:id/attachments — counts per rule for one checklist.
/// Lets the rule list show a paperclip indicator without N round-trips.
/// Requires `read` on the owning asset (403 otherwise); not audited.
pub async fn counts_for_checklist_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(checklist_id): Path<String>,
) -> Result<Json<Vec<db_attachments::AttachmentCountRow>>, StatusCode> {
    let _ = require_read(&state, &user, &checklist_id).await?;
    let rows = db_attachments::counts_for_checklist(state.pool.as_ref(), &checklist_id)
        .await
        .map_err(map_db)?;
    Ok(Json(rows))
}

/// GET /api/attachments/:id — stream blob with correct content-type +
/// content-disposition. Requires `read` on the owning asset (403 otherwise)
/// and records an `attachment.download` audit event (fail-open). The event
/// means the bytes were served, not necessarily received by the client.
pub async fn download_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    let row = db_attachments::get_by_id(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let (_checklist, asset) = require_read(&state, &user, &row.checklist_id).await?;

    let path = blob_path(&state, &row.id);
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to read attachment blob {}: {e:#}", row.id);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Evidence reads are recorded (AU-2) after the blob is in hand. The
    // filename and MIME type are client text and are not recorded.
    db_audit::record_or_log(
        state.pool.as_ref(),
        db_audit::NewAuditEvent {
            user_id: &user.id,
            action: "attachment.download",
            outcome: "ok",
            asset_id: Some(&asset.id),
            checklist_id: Some(&row.checklist_id),
            stig_id: None,
            detail: serde_json::json!({
                "attachmentId": row.id,
                "ruleId": db_audit::audit_safe_id(&row.rule_id),
                "sizeBytes": row.size_bytes,
                "sha256": row.sha256,
            }),
            ctx: Some(&ctx),
        },
    )
    .await;

    let mut headers = HeaderMap::new();
    // Evidence is user-supplied content: never let a browser sniff it into
    // an executable type.
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(v) = HeaderValue::from_str(&row.mime_type) {
        headers.insert(header::CONTENT_TYPE, v);
    } else {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
    }
    let safe_name = sanitize_filename(&row.filename);
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{safe_name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }

    Ok((headers, Body::from(bytes)).into_response())
}

/// DELETE /api/attachments/:id — owner-only. Removes row + blob.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
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

    // The row removal and its `attachment.delete` event commit together; the
    // blob is removed after the commit.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    if !db_attachments::delete_on(&mut tx, &id)
        .await
        .map_err(audit_tx::failed)?
    {
        return Err(StatusCode::NOT_FOUND);
    }
    let mut ev = audit_tx::ok_event(
        &user,
        &ctx,
        "attachment.delete",
        serde_json::json!({
            "attachmentId": row.id,
            "ruleId": db_audit::audit_safe_id(&row.rule_id),
            "sizeBytes": row.size_bytes,
            "sha256": row.sha256,
            "uploadedBy": db_audit::audit_safe_id(&row.uploaded_by),
        }),
    );
    ev.asset_id = Some(&asset.id);
    ev.checklist_id = Some(&row.checklist_id);
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;

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

#[cfg(test)]
mod audit_tests {
    use super::*;
    use crate::test_fixtures::{
        app_state, audit_rows, auth, ctx, fail_audit_inserts, seed_acl, seed_asset, seed_checklist,
        seed_user, STIG_ID,
    };
    use axum::extract::FromRequest;
    use sqlx::PgPool;

    const RULE: &str = "SV-1r1_rule";

    async fn base(pool: &PgPool) -> (AppState, crate::test_fixtures::StigDir) {
        seed_user(pool, "owner").await;
        seed_asset(pool, "a1", "owner", false).await;
        seed_checklist(pool, "c1", "a1", STIG_ID).await;
        app_state(pool.clone())
    }

    async fn multipart(filename: &str, body: &[u8]) -> Multipart {
        let mut payload = format!(
            "--XB\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\
             Content-Type: text/plain\r\n\r\n"
        )
        .into_bytes();
        payload.extend_from_slice(body);
        payload.extend_from_slice(b"\r\n--XB--\r\n");
        let req = axum::http::Request::builder()
            .header(header::CONTENT_TYPE, "multipart/form-data; boundary=XB")
            .body(Body::from(payload))
            .unwrap();
        Multipart::from_request(req, &()).await.unwrap()
    }

    async fn upload(
        state: &AppState,
        filename: &str,
    ) -> Result<(StatusCode, Json<AttachmentRow>), StatusCode> {
        upload_handler(
            State(state.clone()),
            Extension(auth("owner", "author")),
            Extension(ctx()),
            Path(("c1".into(), RULE.into())),
            multipart(filename, b"evidence bytes").await,
        )
        .await
    }

    fn blobs(state: &AppState) -> usize {
        std::fs::read_dir(attachments_dir(state))
            .map(|d| d.count())
            .unwrap_or(0)
    }

    async fn rows(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM attachments")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn attachment_upload_and_delete_are_recorded(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let filename = "private-evidence-name.txt";
        let (_, Json(row)) = upload(&state, filename).await.unwrap();
        let up = audit_rows(&pool, "attachment.upload").await;
        assert_eq!(up.len(), 1);
        let u = &up[0];
        assert_eq!(u.outcome, "ok");
        assert_eq!(u.user_id.as_deref(), Some("owner"));
        assert_eq!(u.asset_id.as_deref(), Some("a1"));
        assert_eq!(u.checklist_id.as_deref(), Some("c1"));
        assert_eq!(
            u.detail_keys(),
            ["attachmentId", "ruleId", "sha256", "sizeBytes"]
        );
        assert_eq!(u.detail["attachmentId"], row.id.as_str());
        assert_eq!(u.detail["ruleId"], RULE);
        assert_eq!(u.detail["sha256"], row.sha256.as_str());
        assert_eq!(u.detail["sizeBytes"], 14);
        assert_eq!(u.request_id.as_deref(), Some("test-request"));
        assert_eq!(u.source_ip.as_deref(), Some("198.51.100.4"));
        let text = u.detail.to_string();
        assert!(!text.contains(filename) && !text.contains("text/plain"));

        let res = delete_handler(
            State(state.clone()),
            Extension(auth("owner", "author")),
            Extension(ctx()),
            Path(row.id.clone()),
        )
        .await;
        assert_eq!(res, Ok(StatusCode::NO_CONTENT));
        let del = audit_rows(&pool, "attachment.delete").await;
        assert_eq!(del.len(), 1);
        let d = &del[0];
        assert_eq!(d.asset_id.as_deref(), Some("a1"));
        assert_eq!(d.checklist_id.as_deref(), Some("c1"));
        assert_eq!(
            d.detail_keys(),
            [
                "attachmentId",
                "ruleId",
                "sha256",
                "sizeBytes",
                "uploadedBy"
            ]
        );
        assert_eq!(d.detail["sha256"], row.sha256.as_str());
        assert_eq!(d.detail["uploadedBy"], "owner");
        assert_eq!(rows(&pool).await, 0);
        assert_eq!(blobs(&state), 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn attachment_upload_fails_closed_and_leaves_no_row_or_blob(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        fail_audit_inserts(&pool, &["attachment.upload"]).await;
        let res = upload(&state, "e.txt").await;
        assert_eq!(res.err(), Some(StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(rows(&pool).await, 0);
        assert_eq!(blobs(&state), 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn attachment_delete_fails_closed_and_keeps_row_and_blob(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let (_, Json(row)) = upload(&state, "e.txt").await.unwrap();
        fail_audit_inserts(&pool, &["attachment.delete"]).await;
        let res = delete_handler(
            State(state.clone()),
            Extension(auth("owner", "author")),
            Extension(ctx()),
            Path(row.id.clone()),
        )
        .await;
        assert_eq!(res, Err(StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(rows(&pool).await, 1);
        assert_eq!(blobs(&state), 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn refused_attachment_requests_write_no_audit_row(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        seed_user(&pool, "nosy").await;
        let (_, Json(row)) = upload(&state, "e.txt").await.unwrap();
        let denied = upload_handler(
            State(state.clone()),
            Extension(auth("nosy", "author")),
            Extension(ctx()),
            Path(("c1".into(), RULE.into())),
            multipart("e.txt", b"x").await,
        )
        .await;
        assert_eq!(denied.err(), Some(StatusCode::FORBIDDEN));
        let denied = delete_handler(
            State(state.clone()),
            Extension(auth("nosy", "author")),
            Extension(ctx()),
            Path(row.id.clone()),
        )
        .await;
        assert_eq!(denied, Err(StatusCode::FORBIDDEN));
        let missing = delete_handler(
            State(state.clone()),
            Extension(auth("owner", "author")),
            Extension(ctx()),
            Path("missing".into()),
        )
        .await;
        assert_eq!(missing, Err(StatusCode::NOT_FOUND));
        assert_eq!(audit_rows(&pool, "attachment.upload").await.len(), 1);
        assert!(audit_rows(&pool, "attachment.delete").await.is_empty());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn attachment_reads_require_asset_read_acl(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        seed_user(&pool, "nosy").await;
        let (_, Json(row)) = upload(&state, "e.txt").await.unwrap();

        async fn all(
            state: &AppState,
            who: crate::api::auth::AuthUser,
            id: &str,
        ) -> [Result<(), StatusCode>; 3] {
            let l = list_for_rule_handler(
                State(state.clone()),
                Extension(who.clone()),
                Path(("c1".into(), RULE.into())),
            )
            .await
            .map(|_| ());
            let c = counts_for_checklist_handler(
                State(state.clone()),
                Extension(who.clone()),
                Path("c1".into()),
            )
            .await
            .map(|_| ());
            let d = download_handler(
                State(state.clone()),
                Extension(who),
                Extension(ctx()),
                Path(id.into()),
            )
            .await
            .map(|_| ());
            [l, c, d]
        }

        for role in ["author", "viewer"] {
            let r = all(&state, auth("nosy", role), &row.id).await;
            assert_eq!(r, [Err(StatusCode::FORBIDDEN); 3], "role {role}");
        }
        assert!(audit_rows(&pool, "attachment.download").await.is_empty());

        seed_acl(&pool, "a1", "nosy", "read").await;
        assert_eq!(
            all(&state, auth("nosy", "viewer"), &row.id).await,
            [Ok(()); 3]
        );
        assert_eq!(
            all(&state, auth("admin1", "admin"), &row.id).await,
            [Ok(()); 3]
        );

        let missing = download_handler(
            State(state.clone()),
            Extension(auth("owner", "author")),
            Extension(ctx()),
            Path("missing".into()),
        )
        .await;
        assert_eq!(missing.err(), Some(StatusCode::NOT_FOUND));
        let missing = counts_for_checklist_handler(
            State(state.clone()),
            Extension(auth("owner", "author")),
            Path("nope".into()),
        )
        .await;
        assert_eq!(missing.err(), Some(StatusCode::NOT_FOUND));
    }

    async fn download(state: &AppState, id: &str) -> Result<Response, StatusCode> {
        download_handler(
            State(state.clone()),
            Extension(auth("owner", "author")),
            Extension(ctx()),
            Path(id.into()),
        )
        .await
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn attachment_download_is_recorded(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let (_, Json(row)) = upload(&state, "private-evidence-name.txt").await.unwrap();
        download(&state, &row.id).await.unwrap();
        let ev = audit_rows(&pool, "attachment.download").await;
        assert_eq!(ev.len(), 1);
        assert_eq!(
            ev[0].detail_keys(),
            ["attachmentId", "ruleId", "sha256", "sizeBytes"]
        );
        assert!(!ev[0].detail.to_string().contains("private-evidence-name"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn attachment_download_fails_open_when_audit_insert_fails(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let (_, Json(row)) = upload(&state, "e.txt").await.unwrap();
        fail_audit_inserts(&pool, &["attachment.download"]).await;
        assert!(download(&state, &row.id).await.is_ok());
    }
}
