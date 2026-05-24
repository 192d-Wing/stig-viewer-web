//! Outbound email delivery.
//!
//! Right now we only send one kind of email: the fleet-wide compliance
//! report PDF, fired immediately after `compliance_report::run_report`
//! finishes a new generation. The webhook fan-out and email send are
//! independent best-effort paths — both fire per generation, neither
//! propagates errors back to the caller.
//!
//! Configuration is purely env-based (no database knob). We re-read
//! `EmailConfig::from_env()` inside `send_compliance_report` rather
//! than threading it through `AppState`. Two reasons:
//!   1. Email is best-effort and lives at the edge — keeping it out of
//!      AppState avoids polluting every handler signature with a config
//!      it'll never use.
//!   2. Operators can change SMTP credentials with a restart instead of
//!      a redeploy of code. The scheduler picks them up on the next tick.
//!
//! When SMTP is not configured (no `SMTP_HOST` or empty
//! `COMPLIANCE_REPORT_RECIPIENTS`), we still write a `mode='dryrun'`
//! row to `email_deliveries` so ops can confirm the path fired and see
//! exactly what would have been sent.

use anyhow::Result;
use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::{DateTime, Utc};
use lettre::{
    message::{header::ContentType, Attachment, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use serde::Serialize;
use sqlx::PgPool;

use crate::api::auth::AuthUser;
use crate::api::compliance_report::ComplianceReportRow;
use crate::AppState;

/// SMTP + recipient configuration. All fields are optional in the sense
/// that an empty `host` or empty `recipients` toggles dry-run mode.
#[derive(Debug, Clone, Default)]
pub struct EmailConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
    pub from: String,
    /// Parsed from comma-separated `COMPLIANCE_REPORT_RECIPIENTS`.
    pub recipients: Vec<String>,
}

impl EmailConfig {
    pub fn from_env() -> EmailConfig {
        let host = std::env::var("SMTP_HOST").unwrap_or_default();
        let port: u16 = std::env::var("SMTP_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(587);
        let user = std::env::var("SMTP_USER").unwrap_or_default();
        let pass = std::env::var("SMTP_PASS").unwrap_or_default();
        let from = std::env::var("SMTP_FROM").unwrap_or_default();
        let recipients = std::env::var("COMPLIANCE_REPORT_RECIPIENTS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        EmailConfig {
            host,
            port,
            user,
            pass,
            from,
            recipients,
        }
    }

    /// Comma-joined recipient list for the `to_addresses` audit column.
    pub fn recipients_joined(&self) -> String {
        self.recipients.join(",")
    }
}

/// Insert an `email_deliveries` row. Errors are logged, never returned —
/// the audit log is best-effort.
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

fn body_for_report(row: &ComplianceReportRow) -> String {
    let s = &row.summary;
    format!(
        "Fleet compliance report\n\
         Generated: {}\n\
         Window: last {} days\n\
         \n\
         Assets:           {}\n\
         Applied STIGs:    {}\n\
         Compliance:       {:.1}%\n\
         Open findings:    {}\n\
         Overdue findings: {}\n\
         Top-risk system:  {}\n\
         \n\
         The full PDF is attached. Direct download URL (auth required):\n\
         /api/reports/{}/report.pdf\n",
        row.generated_at.format("%Y-%m-%d %H:%M UTC"),
        row.range_days,
        s.assets,
        s.checklists,
        s.compliance_score,
        s.open_findings,
        s.overdue_findings,
        s.top_asset_name.as_deref().unwrap_or("(none)"),
        row.id,
    )
}

fn subject_for_report(row: &ComplianceReportRow) -> String {
    format!(
        "Fleet compliance report — {:.1}% compliant",
        row.summary.compliance_score,
    )
}

/// Send (or dry-run) the compliance-report email. Best-effort: errors
/// are logged + recorded into `email_deliveries`, never returned.
pub async fn send_compliance_report(
    pool: &PgPool,
    data_dir: &std::path::Path,
    cfg: EmailConfig,
    row: &ComplianceReportRow,
) -> Result<()> {
    let subject = subject_for_report(row);
    let body = body_for_report(row);
    let snippet: String = body.chars().take(500).collect();
    let to_joined = cfg.recipients_joined();

    // Dry-run when SMTP isn't configured or no recipients are set. This
    // is the default for local dev — still write a row so the operator
    // can confirm the path fired.
    if cfg.host.is_empty() || cfg.recipients.is_empty() {
        insert_delivery(
            pool,
            "compliance_report",
            &to_joined,
            &subject,
            &snippet,
            Some(&row.pdf_path),
            "dryrun",
            None,
        )
        .await;
        tracing::info!(
            "compliance email: dryrun (host_configured={}, recipients={})",
            !cfg.host.is_empty(),
            cfg.recipients.len(),
        );
        return Ok(());
    }

    // Build the multipart message: plain-text body + PDF attachment.
    let pdf_abs = data_dir.join(&row.pdf_path);
    let pdf_bytes = match tokio::fs::read(&pdf_abs).await {
        Ok(b) => b,
        Err(e) => {
            let err_msg = format!("read pdf at {}: {e}", pdf_abs.display());
            tracing::error!("compliance email: {err_msg}");
            insert_delivery(
                pool,
                "compliance_report",
                &to_joined,
                &subject,
                &snippet,
                Some(&row.pdf_path),
                "sent",
                Some(&err_msg),
            )
            .await;
            return Ok(());
        }
    };

    let from_addr = if cfg.from.is_empty() {
        cfg.user.clone()
    } else {
        cfg.from.clone()
    };

    let mut builder = Message::builder()
        .subject(subject.clone());

    let from_parsed = match from_addr.parse() {
        Ok(p) => p,
        Err(e) => {
            let err_msg = format!("parse from-address {from_addr:?}: {e}");
            tracing::error!("compliance email: {err_msg}");
            insert_delivery(
                pool,
                "compliance_report",
                &to_joined,
                &subject,
                &snippet,
                Some(&row.pdf_path),
                "sent",
                Some(&err_msg),
            )
            .await;
            return Ok(());
        }
    };
    builder = builder.from(from_parsed);

    for r in &cfg.recipients {
        match r.parse() {
            Ok(p) => builder = builder.to(p),
            Err(e) => {
                tracing::warn!("compliance email: skipping bad recipient {r:?}: {e}");
            }
        }
    }

    let multipart = MultiPart::mixed()
        .singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_PLAIN)
                .body(body.clone()),
        )
        .singlepart(
            Attachment::new(format!("compliance-{}.pdf", row.id))
                .body(pdf_bytes, ContentType::parse("application/pdf").unwrap()),
        );

    let email = match builder.multipart(multipart) {
        Ok(m) => m,
        Err(e) => {
            let err_msg = format!("build message: {e}");
            tracing::error!("compliance email: {err_msg}");
            insert_delivery(
                pool,
                "compliance_report",
                &to_joined,
                &subject,
                &snippet,
                Some(&row.pdf_path),
                "sent",
                Some(&err_msg),
            )
            .await;
            return Ok(());
        }
    };

    // Build the SMTP transport. Use plain SMTP+STARTTLS on the
    // submission port; rustls is wired through tokio1-rustls-tls.
    let transport_result = SmtpTransport::starttls_relay(&cfg.host)
        .map(|b| {
            let b = b.port(cfg.port);
            if !cfg.user.is_empty() {
                b.credentials(Credentials::new(cfg.user.clone(), cfg.pass.clone()))
            } else {
                b
            }
        });

    let transport = match transport_result {
        Ok(b) => b.build(),
        Err(e) => {
            let err_msg = format!("build transport: {e}");
            tracing::error!("compliance email: {err_msg}");
            insert_delivery(
                pool,
                "compliance_report",
                &to_joined,
                &subject,
                &snippet,
                Some(&row.pdf_path),
                "sent",
                Some(&err_msg),
            )
            .await;
            return Ok(());
        }
    };

    match transport.send(&email) {
        Ok(_) => {
            insert_delivery(
                pool,
                "compliance_report",
                &to_joined,
                &subject,
                &snippet,
                Some(&row.pdf_path),
                "sent",
                None,
            )
            .await;
            tracing::info!(
                "compliance email: sent to {} recipient(s) for report {}",
                cfg.recipients.len(),
                row.id,
            );
        }
        Err(e) => {
            let err_msg = format!("{e}");
            tracing::error!("compliance email: send failed: {err_msg}");
            insert_delivery(
                pool,
                "compliance_report",
                &to_joined,
                &subject,
                &snippet,
                Some(&row.pdf_path),
                "sent",
                Some(&err_msg),
            )
            .await;
        }
    }

    Ok(())
}

// ── Admin HTTP surface ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct EmailDeliveryRow {
    pub id: i64,
    pub kind: String,
    pub to_addresses: String,
    pub subject: String,
    pub body_snippet: String,
    pub attached: Option<String>,
    pub mode: String,
    pub error: Option<String>,
    pub attempted_at: DateTime<Utc>,
}

/// GET /api/admin/email-deliveries — latest 50 rows. Admin-only.
pub async fn list_deliveries_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<EmailDeliveryRow>>, StatusCode> {
    if user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }
    let rows = sqlx::query_as::<_, EmailDeliveryRow>(
        "SELECT id, kind, to_addresses, subject, body_snippet, attached, mode, error, attempted_at \
           FROM email_deliveries \
          ORDER BY attempted_at DESC \
          LIMIT 50",
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("email_deliveries list failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(rows))
}
