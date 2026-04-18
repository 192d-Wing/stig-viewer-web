//! Audit log — append-only record of user-initiated actions.
//!
//! Every write goes through [`log`]; reads are admin-only and served by
//! [`list`]. Actions are free-form strings; convention is `domain.verb`,
//! e.g. `upload.stig`, `upload.library`, `auth.login`, `auth.logout`.
//!
//! Failures to insert audit rows are logged and swallowed — they never
//! propagate into user-facing errors.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

use crate::auth::session::SessionData;

/// A single audit event, as stored and returned by the list endpoint.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub actor_sub: String,
    pub actor_email: Option<String>,
    pub actor_role: String,
    pub action: String,
    pub resource: Option<String>,
    pub remote_ip: Option<String>,
    pub status_code: i32,
    pub metadata: Option<serde_json::Value>,
}

/// Shape of one row to append. Construct via `AuditEntry::new` for brevity.
#[derive(Debug, Clone)]
pub struct AuditEntry<'a> {
    pub session: &'a SessionData,
    pub action: &'a str,
    pub resource: Option<&'a str>,
    pub remote_ip: Option<String>,
    pub status_code: u16,
    pub metadata: Option<serde_json::Value>,
}

/// Append an audit row. Errors are logged and swallowed — audit writes must
/// never break the user request they're describing.
pub async fn log(pool: &PgPool, entry: AuditEntry<'_>) {
    let role = match entry.session.role {
        crate::auth::Role::Admin => "admin",
        crate::auth::Role::Editor => "editor",
        crate::auth::Role::Viewer => "viewer",
    };

    let res = sqlx::query(
        r#"
        INSERT INTO audit_log
            (actor_sub, actor_email, actor_role, action, resource, remote_ip, status_code, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(&entry.session.sub)
    .bind(entry.session.email.as_deref())
    .bind(role)
    .bind(entry.action)
    .bind(entry.resource)
    .bind(entry.remote_ip.as_deref())
    .bind(i32::from(entry.status_code))
    .bind(entry.metadata)
    .execute(pool)
    .await;

    if let Err(e) = res {
        tracing::warn!("audit log insert failed: {e}");
        return;
    }
    crate::api::metrics::record_event("audit_events_total", entry.action);
}

/// Paginated read of recent events. Caller is responsible for the admin check.
pub async fn list(pool: &PgPool, limit: i64, before_id: Option<i64>) -> Result<Vec<AuditEvent>> {
    let limit = limit.clamp(1, 500);
    let rows = match before_id {
        Some(id) => {
            sqlx::query_as::<_, AuditEvent>(
                "SELECT * FROM audit_log WHERE id < $1 ORDER BY id DESC LIMIT $2",
            )
            .bind(id)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, AuditEvent>("SELECT * FROM audit_log ORDER BY id DESC LIMIT $1")
                .bind(limit)
                .fetch_all(pool)
                .await?
        }
    };
    Ok(rows)
}
