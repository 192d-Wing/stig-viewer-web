use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::api::finding_approvals;
use crate::api::webhooks;
use crate::db_assets;
use crate::db_audit;
use crate::db_checklists;
use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateChecklistRequest {
    pub stig_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRuleRequest {
    pub status: String,
    #[serde(default)]
    pub finding_details: String,
    #[serde(default)]
    pub comments: String,
    #[serde(default)]
    pub assignee_id: Option<String>,
    #[serde(default)]
    pub due_date: Option<chrono::NaiveDate>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistDetail {
    pub checklist: db_checklists::ChecklistRow,
    pub asset: db_assets::AssetRow,
    pub stig: Value,
    pub rules: Vec<Value>,
}

/// POST /api/assets/:asset_id/checklists — apply a STIG to this asset.
///
/// The work runs in a spawned task so a client disconnect cannot separate the
/// committed insert from its audit event.
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(asset_id): Path<String>,
    Json(req): Json<CreateChecklistRequest>,
) -> Result<(StatusCode, Json<db_checklists::ChecklistRow>), StatusCode> {
    tokio::spawn(create_work(state, user, asset_id, req))
        .await
        .map_err(|e| {
            tracing::error!("create checklist task failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
}

async fn create_work(
    state: AppState,
    user: AuthUser,
    asset_id: String,
    req: CreateChecklistRequest,
) -> Result<(StatusCode, Json<db_checklists::ChecklistRow>), StatusCode> {
    // 404 if the asset itself is missing — keep that distinct from the
    // 403 the ACL check below produces.
    let _asset = db_assets::get_asset(state.pool.as_ref(), &asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // The request's STIG id is recorded only once it has the expected shape.
    let event_stig = is_valid_stig_id(&req.stig_id).then_some(req.stig_id.as_str());
    let refused = |outcome: &'static str, reason: &'static str| {
        db_audit::record_or_log(
            state.pool.as_ref(),
            db_audit::NewAuditEvent {
                user_id: &user.id,
                action: "checklist.create",
                outcome,
                asset_id: Some(&asset_id),
                checklist_id: None,
                stig_id: event_stig,
                detail: serde_json::json!({ "reason": reason }),
            },
        )
    };
    if !asset_acl::user_can(state.pool.as_ref(), &asset_id, &user, "write").await {
        refused("denied", "forbidden").await;
        return Err(StatusCode::FORBIDDEN);
    }

    if !is_valid_stig_id(&req.stig_id) {
        refused("rejected", "invalid_stig_id").await;
        return Err(StatusCode::BAD_REQUEST);
    }

    let row = match create_checklist(state.pool.as_ref(), &asset_id, &req.stig_id, &user.id).await {
        Ok(row) => row,
        Err(e) => {
            let status = map_unique_conflict(e);
            if status == StatusCode::CONFLICT {
                refused("rejected", "exists").await;
            }
            return Err(status);
        }
    };
    db_audit::record_or_log(
        state.pool.as_ref(),
        db_audit::NewAuditEvent {
            user_id: &user.id,
            action: "checklist.create",
            outcome: "ok",
            asset_id: Some(&asset_id),
            checklist_id: Some(&row.id),
            stig_id: Some(&row.stig_id),
            detail: serde_json::json!({ "via": "create" }),
        },
    )
    .await;

    Ok((StatusCode::CREATED, Json(row)))
}

/// Stamp the catalog version and insert a new `in_progress` checklist.
pub(crate) async fn create_checklist(
    pool: &sqlx::PgPool,
    asset_id: &str,
    stig_id: &str,
    created_by: &str,
) -> anyhow::Result<db_checklists::ChecklistRow> {
    let (applied_version, applied_release) = db_checklists::catalog_version(pool, stig_id).await?;
    let now = chrono::Utc::now();
    let row = db_checklists::ChecklistRow {
        id: uuid::Uuid::new_v4().to_string(),
        asset_id: asset_id.to_string(),
        stig_id: stig_id.to_string(),
        status: "in_progress".into(),
        created_at: now,
        updated_at: now,
        applied_version,
        applied_release,
        created_by: Some(created_by.to_string()),
    };
    db_checklists::insert_checklist(pool, &row).await?;
    Ok(row)
}

/// GET /api/assets/:asset_id/checklists — list checklists for an asset.
pub async fn list_for_asset_handler(
    State(state): State<AppState>,
    Path(asset_id): Path<String>,
) -> Result<Json<Vec<db_checklists::ChecklistRow>>, StatusCode> {
    let rows = db_checklists::list_checklists_for_asset(state.pool.as_ref(), &asset_id)
        .await
        .map_err(map_db)?;
    Ok(Json(rows))
}

/// GET /api/checklists/:id — full checklist with merged rule states.
pub async fn get_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ChecklistDetail>, StatusCode> {
    let checklist = db_checklists::get_checklist(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let asset = db_assets::get_asset(state.pool.as_ref(), &checklist.asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut stig = load_stig_json(&state, &checklist.stig_id).await?;
    let rules = take_rules(&mut stig);

    let overrides = db_checklists::list_rule_overrides(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?;
    let override_by_rule: HashMap<String, db_checklists::ChecklistRuleRow> = overrides
        .into_iter()
        .map(|r| (r.rule_id.clone(), r))
        .collect();

    let merged: Vec<Value> = rules
        .into_iter()
        .map(|rule| merge_rule(rule, &override_by_rule))
        .collect();

    Ok(Json(ChecklistDetail {
        checklist,
        asset,
        stig,
        rules: merged,
    }))
}

/// DELETE /api/checklists/:id — remove a checklist (owner of the asset only).
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let checklist = db_checklists::get_checklist(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let asset = db_assets::get_asset(state.pool.as_ref(), &checklist.asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if !asset_acl::user_can(state.pool.as_ref(), &asset.id, &user, "write").await {
        return Err(StatusCode::FORBIDDEN);
    }

    db_checklists::delete_checklist(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReapplyResponse {
    pub checklist: db_checklists::ChecklistRow,
    pub pruned_rules: u64,
}

/// POST /api/checklists/:id/reapply — refresh a checklist against the
/// current catalog. Stamps the live `(version, release)` onto the row
/// and prunes any rule overrides whose rule_id no longer exists in the
/// new STIG JSON. Existing overrides for rules that still exist are
/// preserved unchanged.
pub async fn reapply_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<ReapplyResponse>, StatusCode> {
    let checklist = db_checklists::get_checklist(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let asset = db_assets::get_asset(state.pool.as_ref(), &checklist.asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if !asset_acl::user_can(state.pool.as_ref(), &asset.id, &user, "write").await {
        return Err(StatusCode::FORBIDDEN);
    }

    let (version, release) =
        db_checklists::catalog_version(state.pool.as_ref(), &checklist.stig_id)
            .await
            .map_err(map_db)?;

    // Pull the new STIG's rule IDs so we know which overrides to keep.
    let mut stig = load_stig_json(&state, &checklist.stig_id).await?;
    let rules = take_rules(&mut stig);
    let keep: Vec<String> = rules
        .iter()
        .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();

    let pruned = db_checklists::prune_orphan_rule_overrides(state.pool.as_ref(), &id, &keep)
        .await
        .map_err(map_db)?;
    db_checklists::set_applied_version(state.pool.as_ref(), &id, &version, &release)
        .await
        .map_err(map_db)?;

    let updated = db_checklists::get_checklist(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(ReapplyResponse {
        checklist: updated,
        pruned_rules: pruned,
    }))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkReapplyResult {
    pub checklist_id: String,
    pub asset_name: String,
    pub stig_title: String,
    pub from_version: String,
    pub to_version: String,
    pub pruned_rules: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkReapplyResponse {
    pub results: Vec<BulkReapplyResult>,
}

/// POST /api/checklists/bulk-reapply — re-apply the current catalog
/// version onto every outdated checklist owned by the calling user.
/// Per-row failures are collected and reported instead of aborting the
/// whole batch.
pub async fn bulk_reapply_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<BulkReapplyResponse>, StatusCode> {
    // Mirrors the dashboard's drift predicate, scoped to checklists the
    // calling user is allowed to mutate. The scope includes:
    //   - assets they own
    //   - assets where they have a write|admin ACL grant
    //   - everything (when their global role is `admin`)
    // The per-row `user_can(..., "write")` check below is the source of
    // truth; the SQL `WHERE` is a coarse filter to avoid loading rows we
    // would only discard.
    let is_admin = user.role == "admin";
    let rows = sqlx::query(
        r#"
        SELECT c.id              AS checklist_id,
               c.asset_id        AS asset_id,
               c.stig_id         AS stig_id,
               c.applied_version AS from_version,
               c.applied_release AS from_release,
               a.name            AS asset_name,
               COALESCE(sc.title, c.stig_id) AS stig_title
          FROM checklists c
          JOIN assets a ON a.id = c.asset_id
          JOIN stigs_catalog sc ON sc.id = c.stig_id
         WHERE (
                $2
                OR a.owner_id = $1
                OR EXISTS (
                    SELECT 1 FROM asset_acl acl
                     WHERE acl.asset_id = a.id
                       AND acl.user_id  = $1
                       AND acl.permission IN ('write','admin')
                )
               )
           AND c.applied_version <> ''
           AND (c.applied_version <> sc.version
                OR c.applied_release <> sc.release_info)
         ORDER BY a.name, sc.title
        "#,
    )
    .bind(&user.id)
    .bind(is_admin)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("bulk-reapply query failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut results: Vec<BulkReapplyResult> = Vec::with_capacity(rows.len());
    for row in rows {
        use sqlx::Row;
        let checklist_id: String = row.try_get("checklist_id").unwrap_or_default();
        let asset_id: String = row.try_get("asset_id").unwrap_or_default();
        let stig_id: String = row.try_get("stig_id").unwrap_or_default();
        let from_version: String = row.try_get("from_version").unwrap_or_default();
        let asset_name: String = row.try_get("asset_name").unwrap_or_default();
        let stig_title: String = row.try_get("stig_title").unwrap_or_default();

        // Per-row authorization gate — keeps the handler safe even if the
        // outer SQL is loosened later, and gives a single source of
        // truth in `asset_acl::user_can`.
        if !asset_acl::user_can(state.pool.as_ref(), &asset_id, &user, "write").await {
            continue;
        }

        match reapply_one(&state, &checklist_id, &stig_id).await {
            Ok((to_version, pruned)) => {
                results.push(BulkReapplyResult {
                    checklist_id,
                    asset_name,
                    stig_title,
                    from_version,
                    to_version,
                    pruned_rules: pruned,
                    status: "reapplied".into(),
                    error: None,
                });
            }
            Err(BulkReapplyErr::Skipped) => {
                results.push(BulkReapplyResult {
                    checklist_id,
                    asset_name,
                    stig_title,
                    from_version,
                    to_version: String::new(),
                    pruned_rules: 0,
                    status: "skipped".into(),
                    error: Some("catalog version is empty".into()),
                });
            }
            Err(BulkReapplyErr::Failed(msg)) => {
                results.push(BulkReapplyResult {
                    checklist_id,
                    asset_name,
                    stig_title,
                    from_version,
                    to_version: String::new(),
                    pruned_rules: 0,
                    status: "error".into(),
                    error: Some(msg),
                });
            }
        }
    }

    Ok(Json(BulkReapplyResponse { results }))
}

enum BulkReapplyErr {
    Skipped,
    Failed(String),
}

/// Inner per-row helper for `bulk_reapply_handler`. Performs the same
/// catalog-stamp + prune steps as `reapply_handler` but reports
/// recoverable failures so the batch can continue.
async fn reapply_one(
    state: &AppState,
    checklist_id: &str,
    stig_id: &str,
) -> Result<(String, u64), BulkReapplyErr> {
    let (version, release) = db_checklists::catalog_version(state.pool.as_ref(), stig_id)
        .await
        .map_err(|e| BulkReapplyErr::Failed(format!("catalog lookup failed: {e}")))?;

    if version.is_empty() {
        return Err(BulkReapplyErr::Skipped);
    }

    let mut stig = load_stig_json(state, stig_id)
        .await
        .map_err(|s| BulkReapplyErr::Failed(format!("load_stig_json: {s}")))?;
    let rules = take_rules(&mut stig);
    let keep: Vec<String> = rules
        .iter()
        .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();

    let pruned =
        db_checklists::prune_orphan_rule_overrides(state.pool.as_ref(), checklist_id, &keep)
            .await
            .map_err(|e| BulkReapplyErr::Failed(format!("prune failed: {e}")))?;
    db_checklists::set_applied_version(state.pool.as_ref(), checklist_id, &version, &release)
        .await
        .map_err(|e| BulkReapplyErr::Failed(format!("stamp failed: {e}")))?;

    Ok((version, pruned))
}

/// PATCH /api/checklists/:id/rules/:rule_id — update one rule's state.
///
/// Returns the upserted rule on the direct-write path. When the asset
/// has `requires_approval = TRUE` and the proposed status is a closing
/// one, returns 202 Accepted with the new approval row's id (the rule
/// row itself is NOT modified). When the rule was already at that closing
/// status the write goes through directly, guarded by the status read
/// under the checklist lock: a concurrent reopen yields 409 Conflict
/// instead of silently re-closing the rule without review.
#[allow(clippy::result_large_err)] // axum handler: Response is the error type
pub async fn update_rule_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((id, rule_id)): Path<(String, String)>,
    Json(req): Json<UpdateRuleRequest>,
) -> Result<Response, Response> {
    let checklist = db_checklists::get_checklist(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)
        .map_err(|s| s.into_response())?
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    let asset = db_assets::get_asset(state.pool.as_ref(), &checklist.asset_id)
        .await
        .map_err(map_db)
        .map_err(|s| s.into_response())?
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    if !asset_acl::user_can(state.pool.as_ref(), &asset.id, &user, "write").await {
        return Err(StatusCode::FORBIDDEN.into_response());
    }

    if !is_valid_status(&req.status) {
        return Err(StatusCode::BAD_REQUEST.into_response());
    }

    // Compliance gate: closing a finding (not_a_finding / not_applicable)
    // requires a written justification in finding_details.
    if requires_finding_details(&req.status) && req.finding_details.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("finding_details required for status {}", req.status)
            })),
        )
            .into_response());
    }

    // Per-asset approval workflow. When asset.requires_approval = TRUE
    // and the proposed status is a closing one AND the rule's current
    // status is NOT already that target value, divert into the
    // finding_approvals queue instead of writing the rule row. The
    // rule's status stays untouched (typically 'open') until a reviewer
    // or admin approves. requires_approval defaults to FALSE so the
    // existing direct-close behavior the bulk of the E2E suite depends
    // on is unaffected.
    let mut expect_status: Option<&str> = None;
    if asset.requires_approval && finding_approvals::is_closing_status(&req.status) {
        let current_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM checklist_rules \
             WHERE checklist_id = $1 AND rule_id = $2",
        )
        .bind(&id)
        .bind(&rule_id)
        .fetch_optional(state.pool.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("approval current-status lookup: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
        let already_closed = current_status.as_deref() == Some(req.status.as_str());
        if already_closed {
            expect_status = Some(req.status.as_str());
        } else {
            // Idempotency: if a pending request already exists for this
            // rule, return 202 without filing a duplicate row. `request_many`
            // does the check and the insert under the checklist lock.
            let request = finding_approvals::ApprovalRequest {
                rule_id: &rule_id,
                proposed_status: &req.status,
                finding_details: &req.finding_details,
            };
            let outcome = finding_approvals::request_many(
                state.pool.as_ref(),
                &id,
                &user.id,
                std::slice::from_ref(&request),
            )
            .await
            .pop();
            return match outcome {
                Some(finding_approvals::ApprovalOutcome::AlreadyPending) => Ok((
                    StatusCode::ACCEPTED,
                    Json(json!({
                        "status": "pending_approval",
                        "message": "an approval request is already pending for this rule",
                    })),
                )
                    .into_response()),
                Some(finding_approvals::ApprovalOutcome::Queued { id: approval_id }) => Ok((
                    StatusCode::ACCEPTED,
                    Json(json!({
                        "status": "pending_approval",
                        "approvalId": approval_id,
                        "proposedStatus": req.status,
                    })),
                )
                    .into_response()),
                Some(finding_approvals::ApprovalOutcome::Failed) | None => {
                    Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
            };
        }
    }

    // Snapshot the prior assignee so we can detect a transition for the
    // outbound 'assigned' webhook event after the upsert succeeds.
    let prev_assignee: Option<String> = sqlx::query_scalar(
        "SELECT assignee_id FROM checklist_rules \
         WHERE checklist_id = $1 AND rule_id = $2",
    )
    .bind(&id)
    .bind(&rule_id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("checklists prev-assignee lookup: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?
    .flatten();

    let row = match db_checklists::upsert_rule_expecting(
        state.pool.as_ref(),
        db_checklists::RuleWrite {
            checklist_id: &id,
            rule_id: &rule_id,
            status: &req.status,
            finding_details: &req.finding_details,
            comments: &req.comments,
            updated_by: &user.id,
            assignee_id: req.assignee_id.as_deref(),
            due_date: req.due_date,
        },
        expect_status,
    )
    .await
    .map_err(map_db)
    .map_err(|s| s.into_response())?
    {
        Ok(row) => row,
        Err(rejected) => {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({ "error": rejected.to_string() })),
            )
                .into_response());
        }
    };

    // Fire the webhook only when the assignee actually changed and the
    // new value is non-null — null means "unassigned", which we treat
    // as a no-op for outbound notifications.
    let new_assignee = req.assignee_id.clone();
    let changed = new_assignee != prev_assignee;
    if changed {
        if let Some(assignee_id) = new_assignee {
            let pool = state.pool.clone();
            let state_clone = state.clone();
            let checklist_id = id.clone();
            let rule_id_clone = rule_id.clone();
            let due_date = req.due_date;
            tokio::spawn(async move {
                fire_assigned_event(
                    &state_clone,
                    pool.as_ref(),
                    &checklist_id,
                    &rule_id_clone,
                    &assignee_id,
                    due_date,
                )
                .await;
            });
        }
    }

    Ok(Json(row).into_response())
}

/// Resolve event metadata + dispatch an `assigned` webhook event for a
/// single rule. Runs inside `tokio::spawn` from `update_rule_handler`;
/// any failure here is logged but never bubbles back to the caller.
async fn fire_assigned_event(
    state: &AppState,
    pool: &sqlx::PgPool,
    checklist_id: &str,
    rule_id: &str,
    assignee_id: &str,
    due_date: Option<chrono::NaiveDate>,
) {
    // Asset name + stig_id + stig title in one round-trip.
    let meta: Option<(String, String, Option<String>)> = match sqlx::query_as(
        r#"
        SELECT a.name, c.stig_id, sc.title
          FROM checklists c
          JOIN assets a         ON a.id = c.asset_id
          LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
         WHERE c.id = $1
        "#,
    )
    .bind(checklist_id)
    .fetch_optional(pool)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!("webhook meta lookup failed: {e:#}");
            return;
        }
    };
    let (asset_name, stig_id, stig_title) = match meta {
        Some((a, sid, t)) => (a, sid.clone(), t.unwrap_or(sid)),
        None => return,
    };

    // Assignee display name — fall back to id if missing.
    let assignee_name: String =
        sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1")
            .bind(assignee_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| assignee_id.to_string());

    // Severity lives in the STIG JSON. Best-effort lookup — if the file
    // is missing or the rule doesn't carry one we just send "unknown".
    let severity = match load_stig_json(state, &stig_id).await {
        Ok(stig) => stig
            .get("rules")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find(|r| {
                    r.get("id").and_then(|i| i.as_str()) == Some(rule_id)
                })
            })
            .and_then(|r| r.get("severity").and_then(|v| v.as_str()))
            .unwrap_or("unknown")
            .to_string(),
        Err(_) => "unknown".to_string(),
    };

    let assigned = webhooks::AssignedEvent {
        rule_id: rule_id.to_string(),
        assignee_name,
        asset_name,
        stig_title,
        severity,
        due_date: due_date.map(|d| d.to_string()),
    };
    // Flavor-agnostic event — per-webhook wire schema is selected
    // inside `dispatch_event` based on each subscriber's `flavor`.
    let event = webhooks::assigned_event(&assigned);
    webhooks::dispatch_event(pool, event).await;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Longest accepted STIG id (bytes). Catalog ids come from file names
/// (the longest checked in is 39 characters); this only stops absurd input
/// from being stored, logged or echoed.
pub(crate) const MAX_STIG_ID_BYTES: usize = 128;

pub(crate) fn is_valid_stig_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_STIG_ID_BYTES && id.chars().all(|c| c.is_alphanumeric() || c == '-')
}

fn is_valid_status(status: &str) -> bool {
    matches!(
        status,
        "not_reviewed" | "open" | "not_a_finding" | "not_applicable"
    )
}

/// Closing-status transitions (`not_a_finding`, `not_applicable`) require a
/// written justification in `finding_details`. Other statuses are unrestricted.
fn requires_finding_details(status: &str) -> bool {
    matches!(status, "not_a_finding" | "not_applicable")
}

pub(crate) async fn load_stig_json(state: &AppState, stig_id: &str) -> Result<Value, StatusCode> {
    if !is_valid_stig_id(stig_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let path = state
        .config
        .data_dir
        .join("stigs")
        .join(format!("{stig_id}.json"));
    let contents = tokio::fs::read_to_string(&path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StatusCode::NOT_FOUND
        } else {
            tracing::error!("Failed to read STIG {stig_id}: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;
    serde_json::from_str(&contents).map_err(|e| {
        tracing::error!("Failed to parse STIG {stig_id}: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

pub(crate) fn take_rules(stig: &mut Value) -> Vec<Value> {
    let obj = match stig.as_object_mut() {
        Some(o) => o,
        None => return Vec::new(),
    };
    match obj.remove("rules") {
        Some(Value::Array(arr)) => arr,
        _ => Vec::new(),
    }
}

fn merge_rule(
    mut rule: Value,
    overrides: &HashMap<String, db_checklists::ChecklistRuleRow>,
) -> Value {
    let obj = match rule.as_object_mut() {
        Some(o) => o,
        None => return rule,
    };
    let rule_id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut state_obj = Map::new();
    if let Some(rule_id) = rule_id.as_deref() {
        if let Some(o) = overrides.get(rule_id) {
            state_obj.insert("status".into(), Value::String(o.status.clone()));
            state_obj.insert(
                "findingDetails".into(),
                Value::String(o.finding_details.clone()),
            );
            state_obj.insert("comments".into(), Value::String(o.comments.clone()));
            state_obj.insert(
                "updatedAt".into(),
                Value::String(o.updated_at.to_rfc3339()),
            );
            state_obj.insert(
                "updatedBy".into(),
                o.updated_by
                    .as_ref()
                    .map(|s| Value::String(s.clone()))
                    .unwrap_or(Value::Null),
            );
            state_obj.insert(
                "assigneeId".into(),
                o.assignee_id
                    .as_ref()
                    .map(|s| Value::String(s.clone()))
                    .unwrap_or(Value::Null),
            );
            state_obj.insert(
                "dueDate".into(),
                o.due_date
                    .map(|d| Value::String(d.to_string()))
                    .unwrap_or(Value::Null),
            );
        } else {
            state_obj.insert("status".into(), Value::String("not_reviewed".into()));
            state_obj.insert("findingDetails".into(), Value::String("".into()));
            state_obj.insert("comments".into(), Value::String("".into()));
            state_obj.insert("updatedAt".into(), Value::Null);
            state_obj.insert("updatedBy".into(), Value::Null);
            state_obj.insert("assigneeId".into(), Value::Null);
            state_obj.insert("dueDate".into(), Value::Null);
        }
    }
    obj.insert("state".into(), Value::Object(state_obj));
    rule
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("checklists db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn map_unique_conflict(e: anyhow::Error) -> StatusCode {
    let msg = format!("{e:#}");
    if msg.contains("duplicate key") || msg.contains("unique") {
        StatusCode::CONFLICT
    } else {
        map_db(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{app_state, auth, seed_asset, seed_checklist, seed_rule, seed_user, RULES, STIG_ID};
    use sqlx::PgPool;

    async fn create(state: &AppState, user: &str, stig_id: &str) -> Result<StatusCode, StatusCode> {
        create_handler(
            State(state.clone()),
            Extension(auth(user, "author")),
            Path("a1".into()),
            Json(CreateChecklistRequest { stig_id: stig_id.into() }),
        )
        .await
        .map(|(code, _)| code)
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn create_handler_keeps_its_403_400_and_409_paths(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_user(&pool, "other").await;
        seed_asset(&pool, "a1", "owner", false).await;
        let (state, _dir) = app_state(pool.clone());
        assert_eq!(create(&state, "other", STIG_ID).await, Err(StatusCode::FORBIDDEN));
        assert_eq!(create(&state, "owner", "../x").await, Err(StatusCode::BAD_REQUEST));
        assert_eq!(create(&state, "owner", STIG_ID).await, Ok(StatusCode::CREATED));
        assert_eq!(create(&state, "owner", STIG_ID).await, Err(StatusCode::CONFLICT));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn create_handler_records_the_creator_and_a_create_event(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_asset(&pool, "a1", "owner", false).await;
        let (state, _dir) = app_state(pool.clone());
        let (code, Json(row)) = create_handler(
            State(state.clone()),
            Extension(auth("owner", "author")),
            Path("a1".into()),
            Json(CreateChecklistRequest { stig_id: STIG_ID.into() }),
        )
        .await
        .unwrap();
        assert_eq!(code, StatusCode::CREATED);
        assert_eq!(row.created_by.as_deref(), Some("owner"));
        let stored: Option<String> = sqlx::query_scalar("SELECT created_by FROM checklists WHERE id = $1")
            .bind(&row.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored.as_deref(), Some("owner"));
        let ev: Vec<(String, String, Option<String>, Option<String>)> =
            sqlx::query_as("SELECT action, outcome, checklist_id, asset_id FROM audit_events")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            ev,
            [("checklist.create".to_string(), "ok".to_string(), Some(row.id.clone()), Some("a1".to_string()))]
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn create_handler_records_denied_rejected_and_exists_events(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_user(&pool, "other").await;
        seed_asset(&pool, "a1", "owner", false).await;
        let (state, _dir) = app_state(pool.clone());
        assert_eq!(create(&state, "other", STIG_ID).await, Err(StatusCode::FORBIDDEN));
        assert_eq!(create(&state, "owner", "../etc").await, Err(StatusCode::BAD_REQUEST));
        assert_eq!(create(&state, "owner", STIG_ID).await, Ok(StatusCode::CREATED));
        assert_eq!(create(&state, "owner", STIG_ID).await, Err(StatusCode::CONFLICT));
        let ev: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT outcome, COALESCE(detail->>'reason', detail->>'via'), COALESCE(stig_id, '') FROM audit_events ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let s = |a: &str, b: &str, c: &str| (a.to_string(), b.to_string(), c.to_string());
        assert_eq!(
            ev,
            [
                s("denied", "forbidden", STIG_ID),
                s("rejected", "invalid_stig_id", ""),
                s("ok", "create", STIG_ID),
                s("rejected", "exists", STIG_ID),
            ]
        );
    }

    /// Long STIG ids are refused before anything is stored: a denied or
    /// rejected event for one carries a NULL `stig_id` (the id fails the shape
    /// check, so it is never recorded), and a valid-length id is stored.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_huge_stig_id_leaves_events_without_the_value(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_user(&pool, "other").await;
        seed_asset(&pool, "a1", "owner", false).await;
        let (state, _dir) = app_state(pool.clone());
        let huge = "A".repeat(100_000);
        assert_eq!(create(&state, "other", &huge).await, Err(StatusCode::FORBIDDEN));
        assert_eq!(create(&state, "owner", &huge).await, Err(StatusCode::BAD_REQUEST));
        let ev: Vec<(String, Option<String>)> =
            sqlx::query_as("SELECT outcome, stig_id FROM audit_events ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(ev, [("denied".to_string(), None), ("rejected".to_string(), None)]);
        assert!(is_valid_stig_id(&"a".repeat(MAX_STIG_ID_BYTES)));
        assert!(!is_valid_stig_id(&"a".repeat(MAX_STIG_ID_BYTES + 1)));
    }

    /// Relies on the current-thread runtime `#[sqlx::test]` uses: after one
    /// `yield_now` the spawned handler task has been polled once and so has
    /// spawned its inner task, which only runs once this test awaits again.
    /// If the runtime ever becomes multi-threaded the abort may land later; the
    /// test still passes but proves less.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn create_work_and_event_survive_the_handler_future_being_dropped(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_asset(&pool, "a1", "owner", false).await;
        let (state, _dir) = app_state(pool.clone());
        let st = state.clone();
        let h = tokio::spawn(async move {
            let _ = create(&st, "owner", STIG_ID).await;
        });
        tokio::task::yield_now().await;
        h.abort();
        let mut seen = 0i64;
        for _ in 0..200 {
            seen = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events").fetch_one(&pool).await.unwrap();
            if seen > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(seen, 1);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklists").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 1);
    }

    async fn patch(
        state: &AppState,
        rule: &str,
        status: &str,
        details: &str,
    ) -> (StatusCode, serde_json::Value) {
        let res = update_rule_handler(
            State(state.clone()),
            Extension(auth("owner", "author")),
            Path(("c1".to_string(), rule.to_string())),
            Json(UpdateRuleRequest {
                status: status.into(),
                finding_details: details.into(),
                comments: String::new(),
                assignee_id: None,
                due_date: None,
            }),
        )
        .await
        .unwrap_or_else(|r| r);
        let code = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (code, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn gated_close_is_queued_once_and_a_repeat_reports_already_pending(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_asset(&pool, "a1", "owner", true).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        seed_rule(&pool, "c1", RULES[0], "open", "", "", "owner").await;
        let (state, _dir) = app_state(pool.clone());

        let (code, body) = patch(&state, RULES[0], "not_a_finding", "because").await;
        assert_eq!(code, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "pending_approval");
        assert_eq!(body["proposedStatus"], "not_a_finding");
        let approval_id = body["approvalId"].as_str().expect("approvalId").to_string();
        let (stored_id, details): (String, String) =
            sqlx::query_as("SELECT id, finding_details FROM finding_approvals")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((stored_id, details.as_str()), (approval_id, "because"));
        let live: String = sqlx::query_scalar("SELECT status FROM checklist_rules").fetch_one(&pool).await.unwrap();
        assert_eq!(live, "open");

        let (code, body) = patch(&state, RULES[0], "not_a_finding", "because").await;
        assert_eq!(code, StatusCode::ACCEPTED);
        assert_eq!(
            body,
            serde_json::json!({
                "status": "pending_approval",
                "message": "an approval request is already pending for this rule",
            })
        );
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM finding_approvals").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn gated_non_closing_status_still_writes_directly(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_asset(&pool, "a1", "owner", true).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        let (state, _dir) = app_state(pool.clone());
        let (code, body) = patch(&state, RULES[0], "open", "").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "open");
        let live: String = sqlx::query_scalar("SELECT status FROM checklist_rules").fetch_one(&pool).await.unwrap();
        assert_eq!(live, "open");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM finding_approvals").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn gated_close_without_details_is_a_400_and_files_nothing(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_asset(&pool, "a1", "owner", true).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        let (state, _dir) = app_state(pool.clone());
        let (code, body) = patch(&state, RULES[0], "not_a_finding", "  ").await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "finding_details required for status not_a_finding");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM finding_approvals").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 0);
    }

    /// Deterministic race: the rule is closed when the handler reads it, then
    /// a concurrent transaction (holding the checklist lock) reopens it before
    /// the handler's write gets the lock.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn gated_already_closed_patch_conflicts_when_the_rule_is_reopened_before_the_write(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_asset(&pool, "a1", "owner", true).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        seed_rule(&pool, "c1", RULES[0], "not_a_finding", "because", "", "owner").await;
        let audit_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_audit").fetch_one(&pool).await.unwrap();

        let mut holder = pool.begin().await.unwrap();
        db_checklists::lock_checklist(&mut holder, "c1").await.unwrap();
        sqlx::query("UPDATE checklist_rules SET status = 'open' WHERE rule_id = $1")
            .bind(RULES[0])
            .execute(&mut *holder)
            .await
            .unwrap();

        let (state, _dir) = app_state(pool.clone());
        let h = tokio::spawn(async move { patch(&state, RULES[0], "not_a_finding", "because").await });
        let mut waiting = false;
        for _ in 0..400 {
            let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_locks WHERE NOT granted")
                .fetch_one(&pool)
                .await
                .unwrap();
            if n > 0 {
                waiting = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(waiting, "the handler never blocked on the checklist lock");
        holder.commit().await.unwrap();

        let (code, body) = h.await.unwrap();
        assert_eq!(code, StatusCode::CONFLICT);
        assert_eq!(body["error"], "rule changed while saving; try again");
        let live: String = sqlx::query_scalar("SELECT status FROM checklist_rules").fetch_one(&pool).await.unwrap();
        assert_eq!(live, "open");
        let audit_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_audit").fetch_one(&pool).await.unwrap();
        assert_eq!(audit_after, audit_before);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM finding_approvals").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn gated_already_closed_patch_still_writes_directly(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_asset(&pool, "a1", "owner", true).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        seed_rule(&pool, "c1", RULES[0], "not_a_finding", "because", "", "owner").await;
        let (state, _dir) = app_state(pool.clone());
        let (code, body) = patch(&state, RULES[0], "not_a_finding", "updated reason").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["findingDetails"], "updated reason");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM finding_approvals").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn ungated_patch_is_unchanged(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_asset(&pool, "a1", "owner", false).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        seed_rule(&pool, "c1", RULES[0], "not_a_finding", "because", "", "owner").await;
        let (state, _dir) = app_state(pool.clone());
        let (code, _) = patch(&state, RULES[0], "open", "").await;
        assert_eq!(code, StatusCode::OK);
        let (code, body) = patch(&state, RULES[0], "not_applicable", "n/a here").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "not_applicable");
    }
}
