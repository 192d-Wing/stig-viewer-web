use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::api::auth::AuthUser;
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

// ── GET /api/audit/search ───────────────────────────────────────────────────
//
// Cross-cutting search over `rule_audit`, joined to checklists / assets /
// users / stigs_catalog for human-readable display fields. Admin-only.
// Every filter is optional; the handler builds the WHERE clause dynamically
// so unset params are simply skipped.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSearchQuery {
    pub user_id: Option<String>,
    pub asset_id: Option<String>,
    pub checklist_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AuditSearchRow {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub by_name: String,
    pub asset_name: Option<String>,
    pub stig_title: Option<String>,
    pub rule_id: String,
    pub field: String,
    pub from_value: Option<String>,
    pub to_value: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSearchResponse {
    pub total_count: i64,
    pub page: i64,
    pub page_size: i64,
    pub rows: Vec<AuditSearchRow>,
}

/// Parse a `YYYY-MM-DD` query param into a UTC instant. The `end` flag
/// shifts the time-of-day to the end of the day so an inclusive `to=`
/// bound covers the whole calendar day the user picked.
fn parse_date_param(raw: &str, end: bool) -> Result<DateTime<Utc>, StatusCode> {
    let nd = NaiveDate::parse_from_str(raw, "%Y-%m-%d").map_err(|_| StatusCode::BAD_REQUEST)?;
    let ndt = if end {
        nd.and_hms_opt(23, 59, 59).ok_or(StatusCode::BAD_REQUEST)?
    } else {
        nd.and_hms_opt(0, 0, 0).ok_or(StatusCode::BAD_REQUEST)?
    };
    Ok(Utc.from_utc_datetime(&ndt))
}

pub async fn search_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(params): Query<AuditSearchQuery>,
) -> Result<Json<AuditSearchResponse>, StatusCode> {
    if user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }

    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * page_size;

    let from_ts = match params.from.as_deref() {
        Some(s) if !s.is_empty() => Some(parse_date_param(s, false)?),
        _ => None,
    };
    let to_ts = match params.to.as_deref() {
        Some(s) if !s.is_empty() => Some(parse_date_param(s, true)?),
        _ => None,
    };

    // Build the dynamic WHERE / arg list. The same parts power both the
    // COUNT(*) and the paginated SELECT below — keep them in lockstep so
    // totalCount matches what the user actually sees.
    let mut wheres: Vec<String> = Vec::new();
    let mut next_idx = 1;
    let mut user_id_val: Option<String> = None;
    let mut asset_id_val: Option<String> = None;
    let mut checklist_id_val: Option<String> = None;
    let mut from_val: Option<DateTime<Utc>> = None;
    let mut to_val: Option<DateTime<Utc>> = None;

    if let Some(uid) = params.user_id.as_deref().filter(|s| !s.is_empty()) {
        wheres.push(format!("a.user_id = ${next_idx}"));
        user_id_val = Some(uid.to_string());
        next_idx += 1;
    }
    if let Some(aid) = params.asset_id.as_deref().filter(|s| !s.is_empty()) {
        wheres.push(format!("c.asset_id = ${next_idx}"));
        asset_id_val = Some(aid.to_string());
        next_idx += 1;
    }
    if let Some(cid) = params.checklist_id.as_deref().filter(|s| !s.is_empty()) {
        wheres.push(format!("a.checklist_id = ${next_idx}"));
        checklist_id_val = Some(cid.to_string());
        next_idx += 1;
    }
    if let Some(ts) = from_ts {
        wheres.push(format!("a.occurred_at >= ${next_idx}"));
        from_val = Some(ts);
        next_idx += 1;
    }
    if let Some(ts) = to_ts {
        wheres.push(format!("a.occurred_at <= ${next_idx}"));
        to_val = Some(ts);
        next_idx += 1;
    }

    let where_clause = if wheres.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", wheres.join(" AND "))
    };

    let count_sql = format!(
        r#"
        SELECT COUNT(*)
          FROM rule_audit a
          LEFT JOIN checklists c ON c.id = a.checklist_id
          {where_clause}
        "#
    );
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(v) = &user_id_val {
        count_q = count_q.bind(v.clone());
    }
    if let Some(v) = &asset_id_val {
        count_q = count_q.bind(v.clone());
    }
    if let Some(v) = &checklist_id_val {
        count_q = count_q.bind(v.clone());
    }
    if let Some(v) = from_val {
        count_q = count_q.bind(v);
    }
    if let Some(v) = to_val {
        count_q = count_q.bind(v);
    }
    let total_count: i64 = count_q
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("audit search count failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let limit_idx = next_idx;
    let offset_idx = next_idx + 1;
    let rows_sql = format!(
        r#"
        SELECT
            a.id,
            a.occurred_at,
            COALESCE(u.display_name, a.user_id) AS by_name,
            ast.name AS asset_name,
            COALESCE(sc.title, c.stig_id) AS stig_title,
            a.rule_id,
            a.field,
            a.from_value,
            a.to_value
          FROM rule_audit a
          LEFT JOIN users u ON u.id = a.user_id
          LEFT JOIN checklists c ON c.id = a.checklist_id
          LEFT JOIN assets ast ON ast.id = c.asset_id
          LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
          {where_clause}
         ORDER BY a.occurred_at DESC, a.id DESC
         LIMIT ${limit_idx} OFFSET ${offset_idx}
        "#
    );
    let mut rows_q = sqlx::query_as::<_, AuditSearchRow>(&rows_sql);
    if let Some(v) = &user_id_val {
        rows_q = rows_q.bind(v.clone());
    }
    if let Some(v) = &asset_id_val {
        rows_q = rows_q.bind(v.clone());
    }
    if let Some(v) = &checklist_id_val {
        rows_q = rows_q.bind(v.clone());
    }
    if let Some(v) = from_val {
        rows_q = rows_q.bind(v);
    }
    if let Some(v) = to_val {
        rows_q = rows_q.bind(v);
    }
    let rows = rows_q
        .bind(page_size)
        .bind(offset)
        .fetch_all(state.pool.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("audit search query failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(AuditSearchResponse {
        total_count,
        page,
        page_size,
        rows,
    }))
}
