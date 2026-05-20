use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use sqlx::Row;

use crate::api::auth::AuthUser;
use crate::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignedItem {
    pub occurred_at: DateTime<Utc>,
    pub actor_id: String,
    pub checklist_id: String,
    pub rule_id: String,
    pub asset_name: String,
    pub stig_title: String,
    pub unread: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverdueItem {
    pub checklist_id: String,
    pub rule_id: String,
    pub asset_name: String,
    pub stig_title: String,
    pub due_date: Option<NaiveDate>,
    pub severity: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationsResponse {
    pub assigned: Vec<AssignedItem>,
    pub overdue: Vec<OverdueItem>,
    pub unread_count: i64,
    pub last_seen: Option<DateTime<Utc>>,
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("notifications db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("notifications sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// GET /api/notifications — assignment + overdue items for the current
/// user, plus an unread counter driven by `users.notifications_last_seen`.
pub async fn get_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<NotificationsResponse>, StatusCode> {
    let pool = state.pool.as_ref();

    // Read the watermark once; null = nothing has ever been read.
    let last_seen: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT notifications_last_seen FROM users WHERE id = $1")
            .bind(&user.id)
            .fetch_optional(pool)
            .await
            .map_err(map_sqlx)?
            .flatten();

    // Recent assignment events: audit rows where the assignee_id field
    // transitioned to the current user. Joined with asset/stig metadata
    // so the frontend has enough to render a clickable row.
    let assigned_rows = sqlx::query(
        r#"
        SELECT
            ra.occurred_at,
            ra.user_id     AS actor_id,
            ra.checklist_id,
            ra.rule_id,
            a.name         AS asset_name,
            COALESCE(sc.title, c.stig_id) AS stig_title
          FROM rule_audit ra
          JOIN checklists c     ON c.id = ra.checklist_id
          JOIN assets a         ON a.id = c.asset_id
          LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
         WHERE ra.field = 'assignee_id'
           AND ra.to_value = $1
         ORDER BY ra.occurred_at DESC
         LIMIT 25
        "#,
    )
    .bind(&user.id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;

    let mut assigned: Vec<AssignedItem> = Vec::with_capacity(assigned_rows.len());
    let mut unread_count: i64 = 0;
    for row in assigned_rows {
        let occurred_at: DateTime<Utc> = row.try_get("occurred_at").map_err(map_sqlx)?;
        let unread = last_seen.is_none_or(|t| occurred_at > t);
        if unread {
            unread_count += 1;
        }
        assigned.push(AssignedItem {
            occurred_at,
            actor_id: row.try_get("actor_id").map_err(map_sqlx)?,
            checklist_id: row.try_get("checklist_id").map_err(map_sqlx)?,
            rule_id: row.try_get("rule_id").map_err(map_sqlx)?,
            asset_name: row.try_get("asset_name").map_err(map_sqlx)?,
            stig_title: row.try_get("stig_title").map_err(map_sqlx)?,
            unread,
        });
    }

    // Currently-open findings assigned to me whose due date has passed.
    // No timestamp/watermark — this is live state, always shown.
    let overdue_rows = sqlx::query(
        r#"
        SELECT
            cr.checklist_id,
            cr.rule_id,
            cr.due_date,
            a.name         AS asset_name,
            COALESCE(sc.title, c.stig_id) AS stig_title
          FROM checklist_rules cr
          JOIN checklists c     ON c.id = cr.checklist_id
          JOIN assets a         ON a.id = c.asset_id
          LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
         WHERE cr.status = 'open'
           AND cr.assignee_id = $1
           AND cr.due_date IS NOT NULL
           AND cr.due_date < CURRENT_DATE
         ORDER BY cr.due_date ASC
        "#,
    )
    .bind(&user.id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;

    let overdue: Vec<OverdueItem> = overdue_rows
        .into_iter()
        .map(|row| -> Result<OverdueItem, sqlx::Error> {
            Ok(OverdueItem {
                checklist_id: row.try_get("checklist_id")?,
                rule_id: row.try_get("rule_id")?,
                asset_name: row.try_get("asset_name")?,
                stig_title: row.try_get("stig_title")?,
                due_date: row.try_get("due_date")?,
                severity: None, // severity lives in STIG JSON; omitted for now
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sqlx)?;

    Ok(Json(NotificationsResponse {
        assigned,
        overdue,
        unread_count,
        last_seen,
    }))
}

/// POST /api/notifications/mark-read — stamp `last_seen = NOW()` on the
/// current user so subsequent assignment events count as unread again.
pub async fn mark_read_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("UPDATE users SET notifications_last_seen = NOW() WHERE id = $1")
        .bind(&user.id)
        .execute(state.pool.as_ref())
        .await
        .map_err(|e| map_db(anyhow::anyhow!(e)))?;
    Ok(StatusCode::NO_CONTENT)
}
