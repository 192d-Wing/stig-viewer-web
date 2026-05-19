use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;

use crate::api::auth::AuthUser;
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

    let now = chrono::Utc::now();
    let row = db_checklists::ChecklistRow {
        id: uuid::Uuid::new_v4().to_string(),
        asset_id: asset_id.clone(),
        stig_id: req.stig_id,
        status: "in_progress".into(),
        created_at: now,
        updated_at: now,
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
    Ok(Json(row))
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

async fn load_stig_json(state: &AppState, stig_id: &str) -> Result<Value, StatusCode> {
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

fn take_rules(stig: &mut Value) -> Vec<Value> {
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
