use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::api::auth::AuthUser;
use crate::api::request_ctx::RequestCtx;
use crate::db_audit::{self, audit_safe_id, NewAuditEvent};
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

/// What one audit read returned, for its `audit.read` event.
struct AuditRead<'a> {
    view: &'static str,
    filters: &'a [(&'static str, &'a Option<String>)],
    page: i64,
    page_size: i64,
    returned: usize,
}

/// Record that an admin read an audit view. Fails open like every audit event.
/// Filter values are bounded and sanitised; nothing else from the request is kept.
async fn record_audit_read(
    state: &AppState,
    user: &AuthUser,
    ctx: &RequestCtx,
    read: AuditRead<'_>,
) {
    let AuditRead {
        view,
        filters,
        page,
        page_size,
        returned,
    } = read;
    let mut f = serde_json::Map::new();
    for (k, v) in filters {
        if let Some(v) = v.as_deref().filter(|s| !s.is_empty()) {
            f.insert(
                (*k).to_string(),
                serde_json::Value::String(audit_safe_id(v)),
            );
        }
    }
    db_audit::record_or_log(
        state.pool.as_ref(),
        NewAuditEvent {
            user_id: &user.id,
            action: "audit.read",
            outcome: "ok",
            asset_id: None,
            checklist_id: None,
            stig_id: None,
            detail: serde_json::json!({
                "view": view,
                "filters": f,
                "page": page,
                "pageSize": page_size,
                "returned": returned,
            }),
            ctx: Some(ctx),
        },
    )
    .await;
}

pub async fn search_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Query(params): Query<AuditSearchQuery>,
) -> Result<Json<AuditSearchResponse>, StatusCode> {
    if user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }

    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1).saturating_mul(page_size);

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
    let total_count: i64 = count_q.fetch_one(state.pool.as_ref()).await.map_err(|e| {
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

    record_audit_read(
        &state,
        &user,
        &ctx,
        AuditRead {
            view: "rules",
            filters: &[
                ("userId", &params.user_id),
                ("assetId", &params.asset_id),
                ("checklistId", &params.checklist_id),
                ("from", &params.from),
                ("to", &params.to),
            ],
            page,
            page_size,
            returned: rows.len(),
        },
    )
    .await;

    Ok(Json(AuditSearchResponse {
        total_count,
        page,
        page_size,
        rows,
    }))
}

// ── GET /api/audit/events ───────────────────────────────────────────────────
//
// Request-level events from `audit_events` (bulk status, save to system,
// checklist creation, including rejected and denied requests). Admin-only,
// like `/api/audit/search`; all filters optional.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventsQuery {
    pub user_id: Option<String>,
    pub asset_id: Option<String>,
    pub checklist_id: Option<String>,
    pub action: Option<String>,
    pub outcome: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct AuditEventDbRow {
    id: i64,
    occurred_at: DateTime<Utc>,
    by_name: String,
    asset_name: Option<String>,
    stig_title: Option<String>,
    action: String,
    outcome: String,
    /// `detail::text`; sqlx's json feature is not enabled.
    detail: String,
    source_ip: Option<String>,
    request_id: Option<String>,
    user_role: Option<String>,
    repeat_count: i32,
    last_occurred_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventRow {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub by_name: String,
    pub asset_name: Option<String>,
    pub stig_title: Option<String>,
    pub action: String,
    pub outcome: String,
    pub detail: serde_json::Value,
    pub source_ip: Option<String>,
    pub request_id: Option<String>,
    pub user_role: Option<String>,
    pub repeat_count: i32,
    pub last_occurred_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventsResponse {
    pub total_count: i64,
    pub page: i64,
    pub page_size: i64,
    pub rows: Vec<AuditEventRow>,
}

/// Push the optional filters as a WHERE clause (all values bound).
fn push_event_filters<'a>(
    qb: &mut sqlx::QueryBuilder<'a, sqlx::Postgres>,
    p: &'a AuditEventsQuery,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) {
    let mut sep = " WHERE ";
    let texts: [(&str, &'a Option<String>); 5] = [
        ("e.user_id", &p.user_id),
        ("e.asset_id", &p.asset_id),
        ("e.checklist_id", &p.checklist_id),
        ("e.action", &p.action),
        ("e.outcome", &p.outcome),
    ];
    for (col, v) in texts {
        if let Some(v) = v.as_deref().filter(|s| !s.is_empty()) {
            qb.push(sep).push(col).push(" = ").push_bind(v);
            sep = " AND ";
        }
    }
    if let Some(ts) = from {
        qb.push(sep).push("e.occurred_at >= ").push_bind(ts);
        sep = " AND ";
    }
    if let Some(ts) = to {
        qb.push(sep).push("e.occurred_at <= ").push_bind(ts);
    }
}

pub async fn events_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Query(params): Query<AuditEventsQuery>,
) -> Result<Json<AuditEventsResponse>, StatusCode> {
    if user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }

    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1).saturating_mul(page_size);

    let from_ts = match params.from.as_deref() {
        Some(s) if !s.is_empty() => Some(parse_date_param(s, false)?),
        _ => None,
    };
    let to_ts = match params.to.as_deref() {
        Some(s) if !s.is_empty() => Some(parse_date_param(s, true)?),
        _ => None,
    };

    let mut count_qb = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM audit_events e");
    push_event_filters(&mut count_qb, &params, from_ts, to_ts);
    let total_count: i64 = count_qb
        .build_query_scalar()
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("audit events count failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut qb = sqlx::QueryBuilder::new(
        "SELECT e.id, e.occurred_at, \
                COALESCE(u.display_name, e.user_id) AS by_name, \
                ast.name AS asset_name, \
                COALESCE(sc.title, e.stig_id) AS stig_title, \
                e.action, e.outcome, e.detail::text AS detail, \
                e.source_ip, e.request_id, e.user_role, \
                e.repeat_count, e.last_occurred_at \
           FROM audit_events e \
           LEFT JOIN users u ON u.id = e.user_id \
           LEFT JOIN assets ast ON ast.id = e.asset_id \
           LEFT JOIN stigs_catalog sc ON sc.id = e.stig_id",
    );
    push_event_filters(&mut qb, &params, from_ts, to_ts);
    qb.push(" ORDER BY e.occurred_at DESC, e.id DESC LIMIT ")
        .push_bind(page_size)
        .push(" OFFSET ")
        .push_bind(offset);
    let db_rows: Vec<AuditEventDbRow> = qb
        .build_query_as()
        .fetch_all(state.pool.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("audit events query failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let rows: Vec<AuditEventRow> = db_rows
        .into_iter()
        .map(|r| AuditEventRow {
            id: r.id,
            occurred_at: r.occurred_at,
            by_name: r.by_name,
            asset_name: r.asset_name,
            stig_title: r.stig_title,
            action: r.action,
            outcome: r.outcome,
            detail: serde_json::from_str(&r.detail).unwrap_or(serde_json::Value::Null),
            source_ip: r.source_ip,
            request_id: r.request_id,
            user_role: r.user_role,
            repeat_count: r.repeat_count,
            last_occurred_at: r.last_occurred_at,
        })
        .collect();

    record_audit_read(
        &state,
        &user,
        &ctx,
        AuditRead {
            view: "events",
            filters: &[
                ("userId", &params.user_id),
                ("assetId", &params.asset_id),
                ("checklistId", &params.checklist_id),
                ("action", &params.action),
                ("outcome", &params.outcome),
                ("from", &params.from),
                ("to", &params.to),
            ],
            page,
            page_size,
            returned: rows.len(),
        },
    )
    .await;

    Ok(Json(AuditEventsResponse {
        total_count,
        page,
        page_size,
        rows,
    }))
}

#[cfg(test)]
mod events_tests {
    use super::*;
    use crate::test_fixtures::{app_state, auth, seed_user};
    use sqlx::PgPool;

    fn query(action: Option<&str>) -> AuditEventsQuery {
        AuditEventsQuery {
            user_id: None,
            asset_id: None,
            checklist_id: None,
            action: action.map(str::to_string),
            outcome: None,
            from: None,
            to: None,
            page: None,
            page_size: None,
        }
    }

    async fn call(
        state: &AppState,
        role: &str,
        q: AuditEventsQuery,
    ) -> Result<Json<AuditEventsResponse>, StatusCode> {
        events_handler(
            State(state.clone()),
            Extension(auth("u1", role)),
            Extension(crate::test_fixtures::ctx()),
            Query(q),
        )
        .await
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn events_are_admin_only_left_joined_and_filterable(pool: PgPool) {
        seed_user(&pool, "u1").await;
        // The asset ids refer to nothing: the record outlives deletion.
        for (action, outcome) in [("checklist.save", "ok"), ("checklist.create", "denied")] {
            sqlx::query(
                "INSERT INTO audit_events (user_id, action, outcome, asset_id, detail) \
                 VALUES ('u1', $1, $2, 'deleted-asset', '{\"k\":1}')",
            )
            .bind(action)
            .bind(outcome)
            .execute(&pool)
            .await
            .unwrap();
        }
        let (state, _dir) = app_state(pool.clone());
        for role in ["author", "reviewer", "viewer"] {
            assert_eq!(
                call(&state, role, query(None)).await.err(),
                Some(StatusCode::FORBIDDEN),
                "{role}"
            );
        }

        let Json(all) = call(&state, "admin", query(None)).await.unwrap();
        assert_eq!(all.total_count, 2);
        assert!(all
            .rows
            .iter()
            .all(|r| r.asset_name.is_none() && r.detail["k"] == 1));

        let Json(some) = call(&state, "admin", query(Some("checklist.create")))
            .await
            .unwrap();
        assert_eq!(some.total_count, 1);
        assert_eq!(some.rows[0].repeat_count, 1);
        assert!(some.rows[0].last_occurred_at.is_none());
        assert_eq!(some.rows[0].outcome, "denied");

        // A huge page does not overflow the offset.
        let mut q = query(None);
        q.page = Some(i64::MAX);
        let Json(far) = call(&state, "admin", q).await.unwrap();
        assert!(far.rows.is_empty());
    }

    fn search_query() -> AuditSearchQuery {
        AuditSearchQuery {
            user_id: Some("who\"ever".repeat(40)),
            asset_id: None,
            checklist_id: None,
            from: Some("2024-01-02".into()),
            to: None,
            page: Some(2),
            page_size: Some(500),
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn both_audit_reads_are_recorded_with_bounded_filters_and_context(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let (state, _dir) = app_state(pool.clone());
        let ctx = crate::test_fixtures::ctx();
        let _ = search_handler(
            State(state.clone()),
            Extension(auth("u1", "admin")),
            Extension(ctx.clone()),
            Query(search_query()),
        )
        .await
        .unwrap();
        let mut q = query(Some("checklist.save"));
        q.outcome = Some("denied".into());
        let _ = events_handler(
            State(state.clone()),
            Extension(auth("u1", "admin")),
            Extension(ctx.clone()),
            Query(q),
        )
        .await
        .unwrap();

        type Row = (String, String, String, Option<String>, Option<String>);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT action, outcome, detail::text, source_ip, request_id FROM audit_events ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.0 == "audit.read" && r.1 == "ok"));
        assert!(rows
            .iter()
            .all(|r| r.3.as_deref() == Some("198.51.100.4")
                && r.4.as_deref() == Some("test-request")));
        let a: serde_json::Value = serde_json::from_str(&rows[0].2).unwrap();
        assert_eq!(a["view"], "rules");
        assert_eq!(
            (
                a["page"].as_i64(),
                a["pageSize"].as_i64(),
                a["returned"].as_i64()
            ),
            (Some(2), Some(200), Some(0))
        );
        assert_eq!(a["filters"]["from"], "2024-01-02");
        let uid = a["filters"]["userId"].as_str().unwrap();
        assert_eq!(uid.len(), 64);
        assert!(!uid.contains('"'));
        let b: serde_json::Value = serde_json::from_str(&rows[1].2).unwrap();
        assert_eq!(b["view"], "events");
        assert_eq!(b["filters"]["action"], "checklist.save");
        assert_eq!(b["filters"]["outcome"], "denied");
        // The first audit read is itself in the events view's `returned` only
        // if it was committed before the query ran: it was, but the filter excluded it.
        assert_eq!(b["returned"].as_i64(), Some(0));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_forbidden_audit_read_handler_writes_no_event_itself(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let (state, _dir) = app_state(pool.clone());
        let ctx = crate::test_fixtures::ctx();
        for role in ["author", "reviewer", "viewer"] {
            let s = search_handler(
                State(state.clone()),
                Extension(auth("u1", role)),
                Extension(ctx.clone()),
                Query(search_query()),
            )
            .await;
            assert_eq!(s.err(), Some(StatusCode::FORBIDDEN));
            assert_eq!(
                call(&state, role, query(None)).await.err(),
                Some(StatusCode::FORBIDDEN)
            );
        }
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_bad_request_writes_no_audit_read(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let (state, _dir) = app_state(pool.clone());
        let ctx = crate::test_fixtures::ctx();
        let mut sq = search_query();
        sq.from = Some("not-a-date".into());
        let s = search_handler(
            State(state.clone()),
            Extension(auth("u1", "admin")),
            Extension(ctx.clone()),
            Query(sq),
        )
        .await;
        assert_eq!(s.err(), Some(StatusCode::BAD_REQUEST));
        let mut eq = query(None);
        eq.to = Some("nope".into());
        assert_eq!(
            call(&state, "admin", eq).await.err(),
            Some(StatusCode::BAD_REQUEST)
        );
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }
}
