//! Per-asset approval workflow for closing findings.
//!
//! When `assets.requires_approval = TRUE`, transitions to a closing status
//! (`not_a_finding` / `not_applicable`) made via
//! `PATCH /api/checklists/:id/rules/:rule_id` are diverted into the
//! `finding_approvals` queue. A reviewer or admin must explicitly
//! approve/reject the row before the rule's status actually changes.
//!
//! Default `requires_approval = FALSE` preserves the legacy direct-close
//! behavior that the bulk of the existing E2E suite depends on.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use crate::api::auth::AuthUser;
use crate::db_assets;
use crate::db_checklists;
use crate::AppState;

// ── Row + DTO types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct FindingApprovalRow {
    pub id: String,
    pub checklist_id: String,
    pub rule_id: String,
    pub requested_by: String,
    pub requested_at: DateTime<Utc>,
    pub proposed_status: String,
    pub finding_details: String,
    pub status: String,
    pub decided_by: Option<String>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decision_reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingApprovalView {
    #[serde(flatten)]
    pub row: FindingApprovalRow,
    pub asset_name: String,
    pub asset_id: String,
    pub stig_title: String,
    pub requested_by_name: String,
}

// ── Listing ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub status: Option<String>,
}

/// GET /api/approvals?status=pending — list approvals visible to the
/// caller. Admin/reviewer sees all rows; everyone else sees only their
/// own (rows they requested).
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<FindingApprovalView>>, StatusCode> {
    let pool = state.pool.as_ref();
    let status = q.status.unwrap_or_else(|| "pending".to_string());
    if !matches!(status.as_str(), "pending" | "approved" | "rejected" | "all") {
        return Err(StatusCode::BAD_REQUEST);
    }

    let is_reviewer = user.role == "reviewer" || user.role == "admin";

    // Reviewer/admin: every row. Otherwise restrict to rows the caller filed.
    let rows = if is_reviewer {
        sqlx::query_as::<_, FindingApprovalView>(
            r#"
            SELECT fa.id, fa.checklist_id, fa.rule_id,
                   fa.requested_by, fa.requested_at,
                   fa.proposed_status, fa.finding_details,
                   fa.status, fa.decided_by, fa.decided_at, fa.decision_reason,
                   a.id AS asset_id,
                   a.name AS asset_name,
                   COALESCE(sc.title, c.stig_id) AS stig_title,
                   u.display_name AS requested_by_name
              FROM finding_approvals fa
              JOIN checklists c ON c.id = fa.checklist_id
              JOIN assets a     ON a.id = c.asset_id
              LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
              JOIN users u      ON u.id = fa.requested_by
             WHERE ($1 = 'all' OR fa.status = $1)
             ORDER BY fa.requested_at DESC
             LIMIT 200
            "#,
        )
        .bind(&status)
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?
    } else {
        sqlx::query_as::<_, FindingApprovalView>(
            r#"
            SELECT fa.id, fa.checklist_id, fa.rule_id,
                   fa.requested_by, fa.requested_at,
                   fa.proposed_status, fa.finding_details,
                   fa.status, fa.decided_by, fa.decided_at, fa.decision_reason,
                   a.id AS asset_id,
                   a.name AS asset_name,
                   COALESCE(sc.title, c.stig_id) AS stig_title,
                   u.display_name AS requested_by_name
              FROM finding_approvals fa
              JOIN checklists c ON c.id = fa.checklist_id
              JOIN assets a     ON a.id = c.asset_id
              LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
              JOIN users u      ON u.id = fa.requested_by
             WHERE fa.requested_by = $2
               AND ($1 = 'all' OR fa.status = $1)
             ORDER BY fa.requested_at DESC
             LIMIT 200
            "#,
        )
        .bind(&status)
        .bind(&user.id)
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?
    };

    Ok(Json(rows))
}

// Manual FromRow for FindingApprovalView since #[serde(flatten)] doesn't
// play with sqlx::FromRow's derive — write it by hand.
impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for FindingApprovalView {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(FindingApprovalView {
            row: FindingApprovalRow {
                id: row.try_get("id")?,
                checklist_id: row.try_get("checklist_id")?,
                rule_id: row.try_get("rule_id")?,
                requested_by: row.try_get("requested_by")?,
                requested_at: row.try_get("requested_at")?,
                proposed_status: row.try_get("proposed_status")?,
                finding_details: row.try_get("finding_details")?,
                status: row.try_get("status")?,
                decided_by: row.try_get("decided_by")?,
                decided_at: row.try_get("decided_at")?,
                decision_reason: row.try_get("decision_reason")?,
            },
            asset_id: row.try_get("asset_id")?,
            asset_name: row.try_get("asset_name")?,
            stig_title: row.try_get("stig_title")?,
            requested_by_name: row.try_get("requested_by_name")?,
        })
    }
}

// ── Approve ────────────────────────────────────────────────────────────────

/// POST /api/approvals/:id/approve — reviewer/admin only. Applies the
/// proposed status to the rule via the existing upsert path (preserving
/// any concurrent comments/assignee/due_date the requester left intact)
/// and stamps the decision metadata.
pub async fn approve_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<FindingApprovalRow>, Response> {
    if !is_reviewer(&user) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    let pool = state.pool.as_ref();

    let approval = get_pending(pool, &id)
        .await
        .map_err(|s| s.into_response())?
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    // Preserve the current comments/assignee/due_date on the rule so we
    // don't accidentally clobber concurrent edits while we apply only the
    // status + finding_details from the approval row.
    let current: Option<db_checklists::ChecklistRuleRow> = sqlx::query_as(
        "SELECT * FROM checklist_rules WHERE checklist_id = $1 AND rule_id = $2",
    )
    .bind(&approval.checklist_id)
    .bind(&approval.rule_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!("approve current-rule lookup: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;
    let comments = current.as_ref().map(|r| r.comments.clone()).unwrap_or_default();
    let assignee = current.as_ref().and_then(|r| r.assignee_id.clone());
    let due = current.as_ref().and_then(|r| r.due_date);

    db_checklists::upsert_rule(
        pool,
        &approval.checklist_id,
        &approval.rule_id,
        &approval.proposed_status,
        &approval.finding_details,
        &comments,
        &user.id,
        assignee.as_deref(),
        due,
    )
    .await
    .map_err(|e| {
        tracing::error!("approve upsert_rule failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let row = stamp_decision(pool, &id, "approved", &user.id, None)
        .await
        .map_err(|s| s.into_response())?;

    Ok(Json(row))
}

// ── Reject ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RejectRequest {
    #[serde(default)]
    pub reason: String,
}

/// POST /api/approvals/:id/reject — reviewer/admin only. Stamps the
/// decision metadata + decision_reason; does NOT change the rule's
/// status (it stays whatever the upstream value was, typically 'open').
pub async fn reject_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<RejectRequest>,
) -> Result<Json<FindingApprovalRow>, Response> {
    if !is_reviewer(&user) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    let pool = state.pool.as_ref();

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "reason required to reject" })),
        )
            .into_response());
    }

    let _approval = get_pending(pool, &id)
        .await
        .map_err(|s| s.into_response())?
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    let row = stamp_decision(pool, &id, "rejected", &user.id, Some(&reason))
        .await
        .map_err(|s| s.into_response())?;
    Ok(Json(row))
}

// ── Asset policy toggle ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalPolicyRequest {
    pub requires_approval: bool,
}

/// PATCH /api/assets/:id/approval-policy — owner-only. Flips the
/// per-asset `requires_approval` flag.
pub async fn update_policy_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<ApprovalPolicyRequest>,
) -> Result<Json<db_assets::AssetRow>, StatusCode> {
    let pool = state.pool.as_ref();
    let existing = db_assets::get_asset(pool, &id)
        .await
        .map_err(|e| {
            tracing::error!("approval-policy lookup: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    if existing.owner_id != user.id {
        return Err(StatusCode::FORBIDDEN);
    }
    db_assets::set_requires_approval(pool, &id, req.requires_approval)
        .await
        .map_err(|e| {
            tracing::error!("approval-policy update: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    db_assets::get_asset(pool, &id)
        .await
        .map_err(|e| {
            tracing::error!("approval-policy re-read: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)
        .map(Json)
}

// ── Shared helpers reused by checklists.rs::update_rule_handler ────────────

/// Create a `pending` `finding_approvals` row. Called from
/// `checklists.rs::update_rule_handler` when an asset has
/// `requires_approval = TRUE` and the proposed status is a closing one.
#[allow(clippy::too_many_arguments)]
pub async fn create_pending(
    pool: &PgPool,
    checklist_id: &str,
    rule_id: &str,
    requested_by: &str,
    proposed_status: &str,
    finding_details: &str,
) -> anyhow::Result<FindingApprovalRow> {
    let id = uuid::Uuid::new_v4().to_string();
    let row = sqlx::query_as::<_, FindingApprovalRow>(
        r#"
        INSERT INTO finding_approvals
            (id, checklist_id, rule_id, requested_by,
             proposed_status, finding_details, status)
        VALUES ($1, $2, $3, $4, $5, $6, 'pending')
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(checklist_id)
    .bind(rule_id)
    .bind(requested_by)
    .bind(proposed_status)
    .bind(finding_details)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// True if a rule already has an outstanding pending approval. Used to
/// avoid duplicate-row spam when a user re-submits the same close.
pub async fn has_pending(
    pool: &PgPool,
    checklist_id: &str,
    rule_id: &str,
) -> anyhow::Result<bool> {
    let row: Option<String> = sqlx::query_scalar(
        "SELECT id FROM finding_approvals \
         WHERE checklist_id = $1 AND rule_id = $2 AND status = 'pending' \
         LIMIT 1",
    )
    .bind(checklist_id)
    .bind(rule_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

// ── Internal helpers ───────────────────────────────────────────────────────

fn is_reviewer(user: &AuthUser) -> bool {
    matches!(user.role.as_str(), "reviewer" | "admin")
}

async fn get_pending(pool: &PgPool, id: &str) -> Result<Option<FindingApprovalRow>, StatusCode> {
    sqlx::query_as::<_, FindingApprovalRow>(
        "SELECT * FROM finding_approvals WHERE id = $1 AND status = 'pending'",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(map_sqlx)
}

async fn stamp_decision(
    pool: &PgPool,
    id: &str,
    new_status: &str,
    decided_by: &str,
    reason: Option<&str>,
) -> Result<FindingApprovalRow, StatusCode> {
    sqlx::query_as::<_, FindingApprovalRow>(
        r#"
        UPDATE finding_approvals
           SET status = $1,
               decided_by = $2,
               decided_at = NOW(),
               decision_reason = $3
         WHERE id = $4
        RETURNING *
        "#,
    )
    .bind(new_status)
    .bind(decided_by)
    .bind(reason)
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(map_sqlx)
}

/// Mirrors the closing-status set from checklists.rs.
pub fn is_closing_status(s: &str) -> bool {
    matches!(s, "not_a_finding" | "not_applicable")
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("finding_approvals sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// Optional helper for tests / future filters.
#[allow(dead_code)]
pub async fn get_by_id(pool: &PgPool, id: &str) -> anyhow::Result<Option<FindingApprovalRow>> {
    let row = sqlx::query_as::<_, FindingApprovalRow>(
        "SELECT * FROM finding_approvals WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Date conversion helper available to tests.
#[allow(dead_code)]
pub fn parse_date(s: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}
