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

use std::collections::HashSet;

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
#[allow(clippy::result_large_err)] // axum handler: Response is the error type
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
    let current: Option<db_checklists::ChecklistRuleRow> =
        sqlx::query_as("SELECT * FROM checklist_rules WHERE checklist_id = $1 AND rule_id = $2")
            .bind(&approval.checklist_id)
            .bind(&approval.rule_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                tracing::error!("approve current-rule lookup: {e:#}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
    let comments = current
        .as_ref()
        .map(|r| r.comments.clone())
        .unwrap_or_default();
    let assignee = current.as_ref().and_then(|r| r.assignee_id.clone());
    let due = current.as_ref().and_then(|r| r.due_date);

    db_checklists::upsert_rule(
        pool,
        db_checklists::RuleWrite {
            checklist_id: &approval.checklist_id,
            rule_id: &approval.rule_id,
            status: &approval.proposed_status,
            finding_details: &approval.finding_details,
            comments: &comments,
            updated_by: &user.id,
            assignee_id: assignee.as_deref(),
            due_date: due,
        },
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
#[allow(clippy::result_large_err)] // axum handler: Response is the error type
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

// ── Batch approval requests (also used by the single-rule PATCH) ───────────

/// One approval request for [`request_many`].
#[derive(Debug, Clone, Copy)]
pub struct ApprovalRequest<'a> {
    pub rule_id: &'a str,
    pub proposed_status: &'a str,
    pub finding_details: &'a str,
}

/// Result of one item of [`request_many`].
#[derive(Debug, PartialEq)]
pub enum ApprovalOutcome {
    /// A new pending row was filed.
    Queued { id: String },
    /// The rule already had a pending request (or an earlier item of this
    /// call filed one); nothing was inserted.
    AlreadyPending,
    /// A database error rolled back the whole chunk this item was in.
    Failed,
}

/// File approval requests for many rules of one checklist, skipping rules
/// that already have a pending request. One transaction per
/// `db_checklists::RULE_CHUNK` items; each takes the checklist lock, which is
/// what makes the check-then-insert atomic against other writers. A database
/// error rolls back and fails its chunk; after two failed chunks in a row
/// the rest are failed without being tried. One entry per item, in order.
pub async fn request_many(
    pool: &PgPool,
    checklist_id: &str,
    requested_by: &str,
    items: &[ApprovalRequest<'_>],
) -> Vec<ApprovalOutcome> {
    request_many_with(
        pool,
        checklist_id,
        requested_by,
        items,
        db_checklists::CHUNK_LOCK_TIMEOUT,
    )
    .await
}

/// Rule ids of `checklist_id` that currently have a pending approval request.
/// A read-only preview helper; the queueing path re-checks under the lock.
pub async fn pending_rule_ids(
    pool: &PgPool,
    checklist_id: &str,
) -> anyhow::Result<HashSet<String>> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT rule_id FROM finding_approvals \
         WHERE checklist_id = $1 AND status = 'pending'",
    )
    .bind(checklist_id)
    .fetch_all(pool)
    .await?;
    Ok(ids.into_iter().collect())
}

async fn request_many_with(
    pool: &PgPool,
    checklist_id: &str,
    requested_by: &str,
    items: &[ApprovalRequest<'_>],
    lock_timeout: &str,
) -> Vec<ApprovalOutcome> {
    let mut out = Vec::with_capacity(items.len());
    let mut consecutive_failures = 0u8;
    for (i, chunk) in items.chunks(db_checklists::RULE_CHUNK).enumerate() {
        if consecutive_failures >= 2 {
            out.extend(chunk.iter().map(|_| ApprovalOutcome::Failed));
            continue;
        }
        match request_chunk(pool, checklist_id, requested_by, chunk, lock_timeout).await {
            Ok(results) => {
                consecutive_failures = 0;
                out.extend(results);
            }
            Err(e) => {
                consecutive_failures += 1;
                tracing::error!(
                    "approval batch failed (checklist {checklist_id}, chunk {i}): {}",
                    db_checklists::error_summary(&e)
                );
                out.extend(chunk.iter().map(|_| ApprovalOutcome::Failed));
            }
        }
    }
    out
}

async fn request_chunk(
    pool: &PgPool,
    checklist_id: &str,
    requested_by: &str,
    chunk: &[ApprovalRequest<'_>],
    lock_timeout: &str,
) -> anyhow::Result<Vec<ApprovalOutcome>> {
    let mut tx = pool.begin().await?;
    db_checklists::set_lock_timeout(&mut tx, lock_timeout).await?;
    db_checklists::lock_checklist(&mut tx, checklist_id).await?;
    let wanted: Vec<&str> = chunk.iter().map(|r| r.rule_id).collect();
    let pending: HashSet<String> = sqlx::query_scalar(
        "SELECT DISTINCT rule_id FROM finding_approvals \
         WHERE checklist_id = $1 AND status = 'pending' AND rule_id = ANY($2)",
    )
    .bind(checklist_id)
    .bind(&wanted)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .collect();

    let mut filed: HashSet<&str> = HashSet::new();
    let mut results = Vec::with_capacity(chunk.len());
    let (mut ids, mut rules, mut statuses, mut details) = (vec![], vec![], vec![], vec![]);
    for item in chunk {
        if pending.contains(item.rule_id) || !filed.insert(item.rule_id) {
            results.push(ApprovalOutcome::AlreadyPending);
            continue;
        }
        let id = uuid::Uuid::new_v4().to_string();
        results.push(ApprovalOutcome::Queued { id: id.clone() });
        ids.push(id);
        rules.push(item.rule_id);
        statuses.push(item.proposed_status);
        details.push(item.finding_details);
    }
    if !ids.is_empty() {
        sqlx::query(
            "INSERT INTO finding_approvals \
                 (id, checklist_id, rule_id, requested_by, proposed_status, finding_details, status) \
             SELECT u.id, $1, u.rule_id, $2, u.proposed_status, u.finding_details, 'pending' \
             FROM UNNEST($3::text[], $4::text[], $5::text[], $6::text[]) \
                  AS u(id, rule_id, proposed_status, finding_details)",
        )
        .bind(checklist_id)
        .bind(requested_by)
        .bind(&ids)
        .bind(&rules)
        .bind(&statuses)
        .bind(&details)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(results)
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
    let row =
        sqlx::query_as::<_, FindingApprovalRow>("SELECT * FROM finding_approvals WHERE id = $1")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{seed_asset, seed_checklist, seed_user};

    async fn setup(pool: &PgPool) {
        seed_user(pool, "u1").await;
        seed_asset(pool, "a1", "u1", true).await;
        seed_checklist(pool, "c1", "a1", "S").await;
    }

    fn reqs(ids: &[String]) -> Vec<ApprovalRequest<'_>> {
        ids.iter()
            .map(|id| ApprovalRequest {
                rule_id: id,
                proposed_status: "not_a_finding",
                finding_details: "why",
            })
            .collect()
    }

    fn names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("r{i:03}")).collect()
    }

    async fn pending_rows(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM finding_approvals WHERE status = 'pending'")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn request_many_queues_missing_and_reports_already_pending(pool: PgPool) {
        setup(&pool).await;
        let ids = names(3);
        let first = request_many(&pool, "c1", "u1", &reqs(&ids[..1])).await;
        let ApprovalOutcome::Queued { id: first_id } = &first[0] else {
            panic!("{first:?}")
        };

        // r000 is pending; r001 is new; the second r001 repeats within the call.
        let batch = [
            ids[0].clone(),
            ids[1].clone(),
            ids[1].clone(),
            ids[2].clone(),
        ];
        let out = request_many(&pool, "c1", "u1", &reqs(&batch)).await;
        assert_eq!(out.len(), 4);
        assert_eq!(out[0], ApprovalOutcome::AlreadyPending);
        assert!(matches!(out[1], ApprovalOutcome::Queued { .. }));
        assert_eq!(out[2], ApprovalOutcome::AlreadyPending);
        assert!(matches!(out[3], ApprovalOutcome::Queued { .. }));
        assert_eq!(pending_rows(&pool).await, 3);

        let (rule, status, details, by, state): (String, String, String, String, String) = sqlx::query_as(
            "SELECT rule_id, proposed_status, finding_details, requested_by, status FROM finding_approvals WHERE id = $1",
        )
        .bind(first_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (
                rule.as_str(),
                status.as_str(),
                details.as_str(),
                by.as_str(),
                state.as_str()
            ),
            ("r000", "not_a_finding", "why", "u1", "pending")
        );

        // A decided request no longer blocks a new one.
        sqlx::query("UPDATE finding_approvals SET status = 'rejected' WHERE rule_id = 'r000'")
            .execute(&pool)
            .await
            .unwrap();
        let out = request_many(&pool, "c1", "u1", &reqs(&ids[..1])).await;
        assert!(matches!(out[0], ApprovalOutcome::Queued { .. }));
    }

    // Probabilistic: without the checklist lock both callers can pass the
    // pending check before either inserts.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn concurrent_request_many_leaves_one_pending_row_per_rule(pool: PgPool) {
        setup(&pool).await;
        let ids = names(30);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let (p, ids) = (pool.clone(), ids.clone());
            tasks.spawn(async move { request_many(&p, "c1", "u1", &reqs(&ids)).await });
        }
        let mut queued = 0;
        while let Some(res) = tasks.join_next().await {
            queued += res
                .unwrap()
                .iter()
                .filter(|o| matches!(o, ApprovalOutcome::Queued { .. }))
                .count();
        }
        assert_eq!(queued, 30);
        assert_eq!(pending_rows(&pool).await, 30);
        let distinct: i64 =
            sqlx::query_scalar("SELECT COUNT(DISTINCT rule_id) FROM finding_approvals")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(distinct, 30);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn request_many_failed_chunk_inserts_nothing(pool: PgPool) {
        setup(&pool).await;
        crate::test_fixtures::fail_writes_of(&pool, "finding_approvals", &["r150"]).await;
        let ids = names(250);
        let out = request_many(&pool, "c1", "u1", &reqs(&ids)).await;
        for (i, o) in out.iter().enumerate() {
            if (100..200).contains(&i) {
                assert_eq!(*o, ApprovalOutcome::Failed, "item {i}");
            } else {
                assert!(matches!(o, ApprovalOutcome::Queued { .. }), "item {i}");
            }
        }
        assert_eq!(pending_rows(&pool).await, 150);
        let in_failed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM finding_approvals WHERE rule_id >= 'r100' AND rule_id < 'r200'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(in_failed, 0);

        // A missing checklist fails the chunk through the foreign key.
        let out = request_many(&pool, "nope", "u1", &reqs(&ids[..2])).await;
        assert_eq!(out, [ApprovalOutcome::Failed, ApprovalOutcome::Failed]);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn request_many_handles_a_chunk_boundary(pool: PgPool) {
        setup(&pool).await;
        let n = db_checklists::RULE_CHUNK + 1;
        let mut ids = names(n);
        ids.push(ids[0].clone()); // repeat of a rule filed by the previous chunk
        let out = request_many(&pool, "c1", "u1", &reqs(&ids)).await;
        assert_eq!(out.len(), n + 1);
        assert!(out[..n]
            .iter()
            .all(|o| matches!(o, ApprovalOutcome::Queued { .. })));
        assert_eq!(out[n], ApprovalOutcome::AlreadyPending);
        assert_eq!(pending_rows(&pool).await as usize, n);
    }

    // Timing-dependent: see the twin in `db_checklists`.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn request_many_chunk_fails_promptly_when_the_checklist_lock_is_held(pool: PgPool) {
        setup(&pool).await;
        let mut holder = pool.begin().await.unwrap();
        db_checklists::lock_checklist(&mut holder, "c1")
            .await
            .unwrap();
        let ids = names(3);
        let t = std::time::Instant::now();
        let out = request_many_with(&pool, "c1", "u1", &reqs(&ids), "300ms").await;
        assert!(
            t.elapsed() < std::time::Duration::from_secs(4),
            "took {:?}",
            t.elapsed()
        );
        assert!(out.iter().all(|o| *o == ApprovalOutcome::Failed));
        holder.rollback().await.unwrap();
        assert_eq!(pending_rows(&pool).await, 0);
        let out = request_many_with(&pool, "c1", "u1", &reqs(&ids), "300ms").await;
        assert!(out
            .iter()
            .all(|o| matches!(o, ApprovalOutcome::Queued { .. })));
    }

    // Timing-dependent (about 5s): the public entry point must bound the lock
    // wait by CHUNK_LOCK_TIMEOUT.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn request_many_passes_the_chunk_lock_timeout(pool: PgPool) {
        setup(&pool).await;
        let mut holder = pool.begin().await.unwrap();
        db_checklists::lock_checklist(&mut holder, "c1")
            .await
            .unwrap();
        let ids = names(2);
        let t = std::time::Instant::now();
        let out = request_many(&pool, "c1", "u1", &reqs(&ids)).await;
        let took = t.elapsed();
        assert!(out.iter().all(|o| *o == ApprovalOutcome::Failed));
        assert!(
            took >= std::time::Duration::from_secs(4) && took < std::time::Duration::from_secs(15),
            "took {took:?}"
        );
        holder.rollback().await.unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_batched_request_can_be_approved_or_rejected(pool: PgPool) {
        use crate::test_fixtures::{app_state, auth};
        setup(&pool).await;
        seed_user(&pool, "rev").await;
        let (state, _dir) = app_state(pool.clone());
        let ids = names(2);
        let items = [
            ApprovalRequest {
                rule_id: &ids[0],
                proposed_status: "not_a_finding",
                finding_details: "fixed it",
            },
            ApprovalRequest {
                rule_id: &ids[1],
                proposed_status: "not_applicable",
                finding_details: "n/a here",
            },
        ];
        let out = request_many(&pool, "c1", "u1", &items).await;
        let (ApprovalOutcome::Queued { id: first }, ApprovalOutcome::Queued { id: second }) =
            (&out[0], &out[1])
        else {
            panic!("{out:?}")
        };

        let _ = approve_handler(
            State(state.clone()),
            Extension(auth("rev", "reviewer")),
            Path(first.clone()),
        )
        .await
        .map_err(|r| r.status())
        .unwrap();
        let (status, details): (String, String) = sqlx::query_as(
            "SELECT status, finding_details FROM checklist_rules WHERE rule_id = 'r000'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (status.as_str(), details.as_str()),
            ("not_a_finding", "fixed it")
        );
        let st: String = sqlx::query_scalar("SELECT status FROM finding_approvals WHERE id = $1")
            .bind(first)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(st, "approved");

        let _ = reject_handler(
            State(state.clone()),
            Extension(auth("rev", "reviewer")),
            Path(second.clone()),
            Json(RejectRequest {
                reason: "not enough".into(),
            }),
        )
        .await
        .map_err(|r| r.status())
        .unwrap();
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM checklist_rules WHERE rule_id = 'r001'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rows, 0);
        let (st, reason): (String, Option<String>) =
            sqlx::query_as("SELECT status, decision_reason FROM finding_approvals WHERE id = $1")
                .bind(second)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            (st.as_str(), reason.as_deref()),
            ("rejected", Some("not enough"))
        );
        assert_eq!(pending_rows(&pool).await, 0);
    }
}
