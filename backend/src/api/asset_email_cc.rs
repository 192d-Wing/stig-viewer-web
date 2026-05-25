//! Per-asset email CC list + on-demand "email this asset's compliance
//! report" handler.
//!
//! The asset owner curates a small list of extra email addresses that
//! should receive the per-asset compliance PDF whenever they hit
//! "Email report now" on the asset detail page. Recipients are the
//! union of (owner.email if non-empty) and every row in
//! `asset_email_cc`.
//!
//! Access control mirrors the rest of the mutation surface — owner,
//! global admin, or anyone with the `write` (or higher) ACL on the
//! asset can manage the list and trigger a send.
//!
//! The send path reuses `report::build_asset_report` so the PDF the
//! recipients receive is byte-identical to what they'd download from
//! `GET /api/assets/:id/report.pdf`. We never round-trip through HTTP.
//! When SMTP isn't configured we still write a `mode='dryrun'` row to
//! `email_deliveries` so the e2e tests + operators can confirm the
//! handler fired without needing a real mail server.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use lettre::{
    message::{header::ContentType, Attachment, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::api::asset_acl::user_can;
use crate::api::auth::AuthUser;
use crate::api::email::EmailConfig;
use crate::api::report::build_asset_report;
use crate::db_assets;
use crate::AppState;

// ── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct EmailCcRow {
    pub email: String,
    pub added_at: DateTime<Utc>,
    pub added_by: String,
}

#[derive(Debug, Deserialize)]
pub struct AddCcRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailReportResult {
    pub recipients: Vec<String>,
    /// `"sent"` when the SMTP path completed, `"dryrun"` when SMTP wasn't
    /// configured. Mirrors the `email_deliveries.mode` column.
    pub mode: String,
    /// Populated only when the send attempt failed but the handler still
    /// returned 200 — e.g. SMTP timeout. The handler itself only returns
    /// non-200 for auth / validation problems.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── Validation ──────────────────────────────────────────────────────────────

/// Loose email shape check — must contain an `@` with at least one
/// character on either side and at least one `.` after the `@`. Full
/// RFC 5322 parsing is intentionally avoided; this is for the UI's
/// benefit only, and the SMTP transport is the real authority.
fn is_email_shape(s: &str) -> bool {
    let trimmed = s.trim();
    let Some(at) = trimmed.find('@') else {
        return false;
    };
    if at == 0 || at == trimmed.len() - 1 {
        return false;
    }
    let domain = &trimmed[at + 1..];
    domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("asset_email_cc sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn map_anyhow(e: anyhow::Error) -> StatusCode {
    tracing::error!("asset_email_cc db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// Owner / write-ACL / global-admin gate. Returns 404 when the asset
/// doesn't exist so the caller can distinguish from 403, matching the
/// rest of the codebase (see `checklists::delete_handler`).
async fn require_asset_write(
    pool: &PgPool,
    asset_id: &str,
    user: &AuthUser,
) -> Result<(), StatusCode> {
    if user_can(pool, asset_id, user, "write").await {
        return Ok(());
    }
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM assets WHERE id = $1")
        .bind(asset_id)
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)?;
    if exists.is_none() {
        Err(StatusCode::NOT_FOUND)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

async fn fetch_cc_rows(pool: &PgPool, asset_id: &str) -> Result<Vec<EmailCcRow>, StatusCode> {
    sqlx::query_as::<_, EmailCcRow>(
        "SELECT email, added_at, added_by \
           FROM asset_email_cc \
          WHERE asset_id = $1 \
          ORDER BY email",
    )
    .bind(asset_id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)
}

async fn fetch_owner_email(pool: &PgPool, owner_id: &str) -> Result<String, StatusCode> {
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(owner_id)
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)?;
    Ok(email.unwrap_or_default())
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// GET /api/assets/:id/email-cc — list configured CC entries.
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(asset_id): Path<String>,
) -> Result<Json<Vec<EmailCcRow>>, StatusCode> {
    require_asset_write(state.pool.as_ref(), &asset_id, &user).await?;
    let rows = fetch_cc_rows(state.pool.as_ref(), &asset_id).await?;
    Ok(Json(rows))
}

/// POST /api/assets/:id/email-cc — append one address (idempotent).
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(asset_id): Path<String>,
    Json(req): Json<AddCcRequest>,
) -> Result<Json<Vec<EmailCcRow>>, StatusCode> {
    require_asset_write(state.pool.as_ref(), &asset_id, &user).await?;

    let email = req.email.trim().to_string();
    if email.is_empty() || !is_email_shape(&email) {
        return Err(StatusCode::BAD_REQUEST);
    }

    sqlx::query(
        "INSERT INTO asset_email_cc (asset_id, email, added_by) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (asset_id, email) DO NOTHING",
    )
    .bind(&asset_id)
    .bind(&email)
    .bind(&user.id)
    .execute(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    let rows = fetch_cc_rows(state.pool.as_ref(), &asset_id).await?;
    Ok(Json(rows))
}

/// DELETE /api/assets/:id/email-cc/:email — remove one address.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((asset_id, email)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    require_asset_write(state.pool.as_ref(), &asset_id, &user).await?;

    let result = sqlx::query(
        "DELETE FROM asset_email_cc WHERE asset_id = $1 AND email = $2",
    )
    .bind(&asset_id)
    .bind(&email)
    .execute(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/assets/:id/email-report — generate the per-asset PDF and
/// mail it to the owner + every CC. Synchronous; returns the resolved
/// recipient list + send mode.
pub async fn send_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(asset_id): Path<String>,
) -> Result<Json<EmailReportResult>, StatusCode> {
    require_asset_write(state.pool.as_ref(), &asset_id, &user).await?;

    let pool = state.pool.as_ref();
    let asset = db_assets::get_asset(pool, &asset_id)
        .await
        .map_err(map_anyhow)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let owner_email = fetch_owner_email(pool, &asset.owner_id).await?;
    let cc_rows = fetch_cc_rows(pool, &asset_id).await?;

    // Dedup while preserving insertion order so the audit row + response
    // stay deterministic for the e2e tests.
    let mut recipients: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    if !owner_email.trim().is_empty() {
        let lower = owner_email.trim().to_lowercase();
        if seen.insert(lower) {
            recipients.push(owner_email.trim().to_string());
        }
    }
    for r in &cc_rows {
        let lower = r.email.trim().to_lowercase();
        if seen.insert(lower) {
            recipients.push(r.email.trim().to_string());
        }
    }

    if recipients.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Build the PDF directly — no HTTP loopback. Reuses the exact code
    // path that backs `GET /api/assets/:id/report.pdf`.
    let built = build_asset_report(pool, &state.config.data_dir, &asset_id)
        .await
        .map_err(map_anyhow)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let subject = format!("Compliance report — {}", built.asset_name);
    let body = format!(
        "Attached: latest compliance report for {}.\n\
         Generated: {}\n\
         Recipients: {}\n",
        built.asset_name,
        Utc::now().format("%Y-%m-%d %H:%M UTC"),
        recipients.join(", "),
    );
    let snippet: String = body.chars().take(500).collect();
    let to_joined = recipients.join(",");
    let pdf_size = built.pdf_bytes.len();
    let attached_note = format!("(in-memory PDF, {pdf_size} bytes)");

    let cfg = EmailConfig::from_env();

    // Dry-run when SMTP isn't configured. The audit row still gets
    // written so the e2e suite (and operators) can verify the path
    // fired without needing a real mail server.
    if cfg.host.is_empty() {
        insert_delivery(
            pool,
            "asset_report",
            &to_joined,
            &subject,
            &snippet,
            Some(&attached_note),
            "dryrun",
            None,
        )
        .await;
        return Ok(Json(EmailReportResult {
            recipients,
            mode: "dryrun".into(),
            error: None,
        }));
    }

    // ── Real SMTP path ──────────────────────────────────────────────────────
    let from_addr = if cfg.from.is_empty() {
        cfg.user.clone()
    } else {
        cfg.from.clone()
    };

    let send_result = (|| -> anyhow::Result<()> {
        let mut builder = Message::builder().subject(subject.clone());
        let from_parsed = from_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("parse from-address {from_addr:?}: {e}"))?;
        builder = builder.from(from_parsed);
        for r in &recipients {
            match r.parse() {
                Ok(p) => builder = builder.to(p),
                Err(e) => tracing::warn!("asset email: skipping bad recipient {r:?}: {e}"),
            }
        }
        let multipart = MultiPart::mixed()
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(body.clone()),
            )
            .singlepart(
                Attachment::new(format!(
                    "{}-stig-report.pdf",
                    crate::api::report::sanitize_report_filename(&built.asset_name)
                ))
                .body(built.pdf_bytes.clone(), ContentType::parse("application/pdf").unwrap()),
            );
        let message = builder
            .multipart(multipart)
            .map_err(|e| anyhow::anyhow!("build message: {e}"))?;
        let transport_builder = SmtpTransport::starttls_relay(&cfg.host)
            .map_err(|e| anyhow::anyhow!("build transport: {e}"))?;
        let transport_builder = transport_builder.port(cfg.port);
        let transport = if !cfg.user.is_empty() {
            transport_builder
                .credentials(Credentials::new(cfg.user.clone(), cfg.pass.clone()))
                .build()
        } else {
            transport_builder.build()
        };
        transport
            .send(&message)
            .map_err(|e| anyhow::anyhow!("smtp send: {e}"))?;
        Ok(())
    })();

    match send_result {
        Ok(()) => {
            insert_delivery(
                pool,
                "asset_report",
                &to_joined,
                &subject,
                &snippet,
                Some(&attached_note),
                "sent",
                None,
            )
            .await;
            Ok(Json(EmailReportResult {
                recipients,
                mode: "sent".into(),
                error: None,
            }))
        }
        Err(e) => {
            let err_msg = format!("{e:#}");
            tracing::error!("asset_report email send failed: {err_msg}");
            insert_delivery(
                pool,
                "asset_report",
                &to_joined,
                &subject,
                &snippet,
                Some(&attached_note),
                "sent",
                Some(&err_msg),
            )
            .await;
            Ok(Json(EmailReportResult {
                recipients,
                mode: "sent".into(),
                error: Some(err_msg),
            }))
        }
    }
}

/// Same audit-row insert helper that `email.rs` uses; duplicated rather
/// than re-exported to keep `email.rs` private to its module-level
/// concerns (the fleet report).
async fn insert_delivery(
    pool: &PgPool,
    kind: &str,
    to_addresses: &str,
    subject: &str,
    body_snippet: &str,
    attached: Option<&str>,
    mode: &str,
    error: Option<&str>,
) {
    let res = sqlx::query(
        "INSERT INTO email_deliveries \
            (kind, to_addresses, subject, body_snippet, attached, mode, error) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(kind)
    .bind(to_addresses)
    .bind(subject)
    .bind(body_snippet)
    .bind(attached)
    .bind(mode)
    .bind(error)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::error!("email_deliveries insert failed: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_shape_accepts_normal_addresses() {
        assert!(is_email_shape("ops@example.gov"));
        assert!(is_email_shape("a@b.co"));
        assert!(is_email_shape("first.last+tag@sub.example.com"));
    }

    #[test]
    fn email_shape_rejects_malformed() {
        assert!(!is_email_shape(""));
        assert!(!is_email_shape("plain"));
        assert!(!is_email_shape("@no-local.com"));
        assert!(!is_email_shape("no-domain@"));
        assert!(!is_email_shape("no-dot@localhost"));
        assert!(!is_email_shape("trailing-dot@x."));
    }
}
