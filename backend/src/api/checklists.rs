use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;

use crate::api::auth::AuthUser;
use crate::api::webhooks;
use crate::db_assets;
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
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(asset_id): Path<String>,
    Json(req): Json<CreateChecklistRequest>,
) -> Result<(StatusCode, Json<db_checklists::ChecklistRow>), StatusCode> {
    let asset = db_assets::get_asset(state.pool.as_ref(), &asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if asset.owner_id != user.id {
        return Err(StatusCode::FORBIDDEN);
    }

    if !is_valid_stig_id(&req.stig_id) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let (applied_version, applied_release) =
        db_checklists::catalog_version(state.pool.as_ref(), &req.stig_id)
            .await
            .map_err(map_db)?;
    let now = chrono::Utc::now();
    let row = db_checklists::ChecklistRow {
        id: uuid::Uuid::new_v4().to_string(),
        asset_id: asset_id.clone(),
        stig_id: req.stig_id,
        status: "in_progress".into(),
        created_at: now,
        updated_at: now,
        applied_version,
        applied_release,
    };
    db_checklists::insert_checklist(state.pool.as_ref(), &row)
        .await
        .map_err(map_unique_conflict)?;

    Ok((StatusCode::CREATED, Json(row)))
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

    if asset.owner_id != user.id {
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

    if asset.owner_id != user.id {
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
    // Mirrors the dashboard's drift predicate, scoped to this user's assets.
    let rows = sqlx::query(
        r#"
        SELECT c.id              AS checklist_id,
               c.stig_id         AS stig_id,
               c.applied_version AS from_version,
               c.applied_release AS from_release,
               a.name            AS asset_name,
               COALESCE(sc.title, c.stig_id) AS stig_title
          FROM checklists c
          JOIN assets a ON a.id = c.asset_id
          JOIN stigs_catalog sc ON sc.id = c.stig_id
         WHERE a.owner_id = $1
           AND c.applied_version <> ''
           AND (c.applied_version <> sc.version
                OR c.applied_release <> sc.release_info)
         ORDER BY a.name, sc.title
        "#,
    )
    .bind(&user.id)
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
        let stig_id: String = row.try_get("stig_id").unwrap_or_default();
        let from_version: String = row.try_get("from_version").unwrap_or_default();
        let asset_name: String = row.try_get("asset_name").unwrap_or_default();
        let stig_title: String = row.try_get("stig_title").unwrap_or_default();

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
pub async fn update_rule_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((id, rule_id)): Path<(String, String)>,
    Json(req): Json<UpdateRuleRequest>,
) -> Result<Json<db_checklists::ChecklistRuleRow>, StatusCode> {
    let checklist = db_checklists::get_checklist(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let asset = db_assets::get_asset(state.pool.as_ref(), &checklist.asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if asset.owner_id != user.id {
        return Err(StatusCode::FORBIDDEN);
    }

    if !is_valid_status(&req.status) {
        return Err(StatusCode::BAD_REQUEST);
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
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .flatten();

    let row = db_checklists::upsert_rule(
        state.pool.as_ref(),
        &id,
        &rule_id,
        &req.status,
        &req.finding_details,
        &req.comments,
        &user.id,
        req.assignee_id.as_deref(),
        req.due_date,
    )
    .await
    .map_err(map_db)?;

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

    Ok(Json(row))
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

    let event = webhooks::AssignedEvent {
        rule_id: rule_id.to_string(),
        assignee_name,
        asset_name,
        stig_title,
        severity,
        due_date: due_date.map(|d| d.to_string()),
    };
    let payload = webhooks::build_assigned_payload(&event);
    webhooks::dispatch_event(pool, "assigned", payload).await;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn is_valid_stig_id(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_alphanumeric() || c == '-')
}

fn is_valid_status(status: &str) -> bool {
    matches!(
        status,
        "not_reviewed" | "open" | "not_a_finding" | "not_applicable"
    )
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
