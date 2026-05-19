use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
    pub user_name: String,
    pub checklist_id: String,
    pub rule_id: String,
    /// Optional asset/STIG context (NULL for entries whose checklist was deleted).
    pub asset_id: Option<String>,
    pub asset_name: Option<String>,
    pub stig_id: Option<String>,
    pub field: String,
    pub from_value: Option<String>,
    pub to_value: Option<String>,
}

/// GET /api/checklists/:id/rules/:rule_id/history — full audit timeline
/// for one rule, newest first.
pub async fn rule_history_handler(
    State(state): State<AppState>,
    Path((checklist_id, rule_id)): Path<(String, String)>,
) -> Result<Json<Vec<AuditEntry>>, StatusCode> {
    let rows = sqlx::query_as::<_, AuditEntry>(
        r#"
        SELECT
            a.id,
            a.occurred_at,
            a.user_id,
            COALESCE(u.display_name, a.user_id) AS user_name,
            a.checklist_id,
            a.rule_id,
            c.asset_id,
            ast.name AS asset_name,
            c.stig_id,
            a.field,
            a.from_value,
            a.to_value
        FROM rule_audit a
        LEFT JOIN users u ON u.id = a.user_id
        LEFT JOIN checklists c ON c.id = a.checklist_id
        LEFT JOIN assets ast ON ast.id = c.asset_id
        WHERE a.checklist_id = $1 AND a.rule_id = $2
        ORDER BY a.occurred_at DESC, a.id DESC
        "#,
    )
    .bind(&checklist_id)
    .bind(&rule_id)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("rule history query failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(rows))
}

#[derive(Debug, Deserialize)]
pub struct ActivityQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    50
}

/// GET /api/activity?limit=N — recent audit entries across everything,
/// newest first. Used by the dashboard "Recent activity" widget.
pub async fn activity_handler(
    State(state): State<AppState>,
    Query(params): Query<ActivityQuery>,
) -> Result<Json<Vec<AuditEntry>>, StatusCode> {
    let limit = params.limit.clamp(1, 500);
    let rows = sqlx::query_as::<_, AuditEntry>(
        r#"
        SELECT
            a.id,
            a.occurred_at,
            a.user_id,
            COALESCE(u.display_name, a.user_id) AS user_name,
            a.checklist_id,
            a.rule_id,
            c.asset_id,
            ast.name AS asset_name,
            c.stig_id,
            a.field,
            a.from_value,
            a.to_value
        FROM rule_audit a
        LEFT JOIN users u ON u.id = a.user_id
        LEFT JOIN checklists c ON c.id = a.checklist_id
        LEFT JOIN assets ast ON ast.id = c.asset_id
        ORDER BY a.occurred_at DESC, a.id DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("activity query failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(rows))
}
