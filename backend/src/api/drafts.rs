use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    Extension,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::auth::AuthUser;
use crate::db_drafts::*;
use crate::AppState;

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

fn err_500(e: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::error!("{e:#}");
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn err_400(msg: &str) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.to_string())
}

fn err_403(msg: &str) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, msg.to_string())
}

/// 403 with a structured JSON body — used for reviewer-assignment guards
/// so the frontend can render a specific message.
fn err_403_json(msg: &str) -> (StatusCode, String) {
    (
        StatusCode::FORBIDDEN,
        serde_json::json!({ "error": msg }).to_string(),
    )
}

/// 400 with a structured JSON body for client-supplied validation errors.
fn err_400_json(msg: &str) -> (StatusCode, String) {
    (
        StatusCode::BAD_REQUEST,
        serde_json::json!({ "error": msg }).to_string(),
    )
}

fn err_404() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "Not found".to_string())
}

// ── List drafts ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
    pub author_id: Option<String>,
}

pub async fn list_drafts_handler(
    State(state): State<AppState>,
    Extension(_user): Extension<AuthUser>,
    Query(params): Query<ListQuery>,
) -> Result<Json<Vec<DraftSummary>>, (StatusCode, String)> {
    let rows = list_drafts(
        &state.pool,
        params.status.as_deref(),
        params.author_id.as_deref(),
    )
    .await
    .map_err(err_500)?;
    Ok(Json(rows))
}

/// GET /api/drafts/pending-for-me — drafts in 'submitted' state where
/// the caller is the assigned reviewer. Newest first.
pub async fn pending_for_me_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<DraftSummary>>, (StatusCode, String)> {
    let rows = list_pending_for_reviewer(&state.pool, &user.id)
        .await
        .map_err(err_500)?;
    Ok(Json(rows))
}

// ── Create draft ────────────────────────────────────────────────────────────

pub async fn create_draft_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<DraftRow>, (StatusCode, String)> {
    let id = new_id();
    let json_path = state
        .config
        .data_dir
        .join("drafts")
        .join(format!("{id}.json"));
    let json_path_str = json_path.to_string_lossy().to_string();

    // Ensure drafts directory
    tokio::fs::create_dir_all(state.config.data_dir.join("drafts"))
        .await
        .map_err(|e| err_500(e))?;

    // Write empty rules JSON
    tokio::fs::write(&json_path, "[]")
        .await
        .map_err(|e| err_500(e))?;

    let draft = DraftRow {
        id: id.clone(),
        title: String::new(),
        author_id: user.id,
        based_on_stig: None,
        status: "draft".to_string(),
        version: "1".to_string(),
        release_info: String::new(),
        description: String::new(),
        next_vuln_id: 100001,
        json_path: json_path_str,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        assigned_reviewer_id: None,
    };

    insert_draft(&state.pool, &draft).await.map_err(err_500)?;
    Ok(Json(draft))
}

// ── Fork from library STIG ─────────────────────────────────────────────────

pub async fn fork_from_stig_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(stig_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Read the library STIG JSON
    let stig_path = state
        .config
        .data_dir
        .join("stigs")
        .join(format!("{stig_id}.json"));
    let stig_json = tokio::fs::read_to_string(&stig_path)
        .await
        .map_err(|_| err_404())?;
    let stig_value: serde_json::Value =
        serde_json::from_str(&stig_json).map_err(|e| err_500(e))?;

    let draft_id = new_id();
    let json_path = state
        .config
        .data_dir
        .join("drafts")
        .join(format!("{draft_id}.json"));
    let json_path_str = json_path.to_string_lossy().to_string();

    tokio::fs::create_dir_all(state.config.data_dir.join("drafts"))
        .await
        .map_err(|e| err_500(e))?;

    // Copy rules to draft JSON
    let rules = stig_value.get("rules").cloned().unwrap_or(serde_json::json!([]));
    let rule_count = rules.as_array().map(|a| a.len()).unwrap_or(0) as i32;
    tokio::fs::write(&json_path, serde_json::to_string_pretty(&rules).unwrap_or_default())
        .await
        .map_err(|e| err_500(e))?;

    let title = stig_value.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let description = stig_value.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let version = stig_value.get("version").and_then(|v| v.as_str()).unwrap_or("1").to_string();
    let release_info = stig_value.get("releaseInfo").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // next_vuln_id: find max existing V-ID and add 1
    let next_id = rules
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    r.get("stigId")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.strip_prefix("V-"))
                        .and_then(|n| n.parse::<i32>().ok())
                })
                .max()
                .unwrap_or(100000)
                + 1
        })
        .unwrap_or(100001);

    let draft = DraftRow {
        id: draft_id.clone(),
        title,
        author_id: user.id,
        based_on_stig: Some(stig_id),
        status: "draft".to_string(),
        version,
        release_info,
        description,
        next_vuln_id: next_id,
        json_path: json_path_str,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        assigned_reviewer_id: None,
    };

    insert_draft(&state.pool, &draft).await.map_err(err_500)?;

    Ok(Json(serde_json::json!({
        "id": draft_id,
        "title": draft.title,
        "ruleCount": rule_count,
    })))
}

// ── Get draft ───────────────────────────────────────────────────────────────

pub async fn get_draft_handler(
    State(state): State<AppState>,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let draft = get_draft(&state.pool, &id)
        .await
        .map_err(err_500)?
        .ok_or_else(err_404)?;

    let rules_json = tokio::fs::read_to_string(&draft.json_path)
        .await
        .unwrap_or_else(|_| "[]".to_string());
    let rules: serde_json::Value =
        serde_json::from_str(&rules_json).unwrap_or(serde_json::json!([]));

    Ok(Json(serde_json::json!({
        "id": draft.id,
        "title": draft.title,
        "authorId": draft.author_id,
        "basedOnStig": draft.based_on_stig,
        "status": draft.status,
        "version": draft.version,
        "releaseInfo": draft.release_info,
        "description": draft.description,
        "nextVulnId": draft.next_vuln_id,
        "rules": rules,
        "createdAt": draft.created_at,
        "updatedAt": draft.updated_at,
        "assignedReviewerId": draft.assigned_reviewer_id,
    })))
}

// ── Update draft ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDraftBody {
    pub title: Option<String>,
    pub description: Option<String>,
    pub version: Option<String>,
    pub release_info: Option<String>,
    pub rules: Option<serde_json::Value>,
}

pub async fn update_draft_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<UpdateDraftBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let draft = get_draft(&state.pool, &id)
        .await
        .map_err(err_500)?
        .ok_or_else(err_404)?;

    if draft.author_id != user.id && user.role != "admin" {
        return Err(err_403("Only the author or admin can edit this draft"));
    }
    if draft.status != "draft" && draft.status != "rejected" {
        return Err(err_400("Draft can only be edited in 'draft' or 'rejected' status"));
    }

    let title = body.title.as_deref().unwrap_or(&draft.title);
    let description = body.description.as_deref().unwrap_or(&draft.description);
    let version = body.version.as_deref().unwrap_or(&draft.version);
    let release_info = body.release_info.as_deref().unwrap_or(&draft.release_info);

    // Write rules to disk if provided
    if let Some(rules) = &body.rules {
        tokio::fs::write(
            &draft.json_path,
            serde_json::to_string_pretty(rules).unwrap_or_default(),
        )
        .await
        .map_err(|e| err_500(e))?;
    }

    update_draft_content(
        &state.pool,
        &id,
        title,
        description,
        version,
        release_info,
        draft.next_vuln_id,
    )
    .await
    .map_err(err_500)?;

    Ok(Json(serde_json::json!({"ok": true})))
}

// ── Delete draft ────────────────────────────────────────────────────────────

pub async fn delete_draft_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let draft = get_draft(&state.pool, &id)
        .await
        .map_err(err_500)?
        .ok_or_else(err_404)?;

    if draft.author_id != user.id && user.role != "admin" {
        return Err(err_403("Only the author or admin can delete this draft"));
    }

    // Remove JSON file
    let _ = tokio::fs::remove_file(&draft.json_path).await;
    delete_draft(&state.pool, &id).await.map_err(err_500)?;

    Ok(Json(serde_json::json!({"ok": true})))
}

// ── Next V-ID ───────────────────────────────────────────────────────────────

pub async fn next_vuln_id_handler(
    State(state): State<AppState>,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let num = next_vuln_id(&state.pool, &id).await.map_err(err_500)?;
    Ok(Json(serde_json::json!({
        "vulnId": format!("V-{num}"),
        "ruleId": format!("SV-{num}r1_rule"),
        "groupId": format!("SRG-APP-{:06}", num - 100000),
    })))
}

// ── Workflow transitions ────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SubmitBody {
    /// Optional explicit reviewer. If null/missing the draft remains
    /// open for any reviewer to claim.
    pub assigned_reviewer_id: Option<String>,
}

pub async fn submit_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    body: Option<Json<SubmitBody>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let draft = get_draft(&state.pool, &id)
        .await
        .map_err(err_500)?
        .ok_or_else(err_404)?;
    if draft.author_id != user.id {
        return Err(err_403("Only the author can submit"));
    }

    // Optional `assignedReviewerId` — validate it points at a real user
    // whose role is `reviewer` or `admin`. Anything else is a 400.
    let assigned: Option<String> = body.and_then(|Json(b)| b.assigned_reviewer_id);
    if let Some(reviewer_id) = &assigned {
        let role: Option<String> =
            sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
                .bind(reviewer_id)
                .fetch_optional(state.pool.as_ref())
                .await
                .map_err(err_500)?;
        match role.as_deref() {
            Some("reviewer") | Some("admin") => {}
            _ => {
                return Err(err_400_json(
                    "assignedReviewerId must reference a user with role reviewer or admin",
                ));
            }
        }
    }

    transition_status(&state.pool, &id, &draft.status, "submitted")
        .await
        .map_err(|e| err_400(&e.to_string()))?;

    // Persist (or clear) the assignee regardless of whether one was
    // supplied — re-submission after a rejection may legitimately want
    // to unset the prior assignment.
    set_assigned_reviewer(&state.pool, &id, assigned.as_deref())
        .await
        .map_err(err_500)?;

    Ok(Json(serde_json::json!({
        "status": "submitted",
        "assignedReviewerId": assigned,
    })))
}

/// Common guard: if the draft has an `assigned_reviewer_id` set, only
/// that user (or an admin) may act on it. Returns Ok if the caller is
/// allowed, Err(403 JSON) otherwise.
fn check_assignment_guard(
    draft: &DraftRow,
    user: &AuthUser,
) -> Result<(), (StatusCode, String)> {
    if let Some(target) = &draft.assigned_reviewer_id {
        if user.id != *target && user.role != "admin" {
            return Err(err_403_json(
                "this draft is assigned to a specific reviewer",
            ));
        }
    }
    Ok(())
}

pub async fn review_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if user.role != "reviewer" && user.role != "admin" {
        return Err(err_403("Only reviewers can pick up reviews"));
    }
    let draft = get_draft(&state.pool, &id)
        .await
        .map_err(err_500)?
        .ok_or_else(err_404)?;
    check_assignment_guard(&draft, &user)?;
    transition_status(&state.pool, &id, "submitted", "in_review")
        .await
        .map_err(|e| err_400(&e.to_string()))?;
    Ok(Json(serde_json::json!({"status": "in_review"})))
}

#[derive(Debug, Deserialize)]
pub struct ActionBody {
    pub comment: Option<String>,
}

pub async fn approve_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<ActionBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if user.role != "reviewer" && user.role != "admin" {
        return Err(err_403("Only reviewers can approve"));
    }
    let draft = get_draft(&state.pool, &id)
        .await
        .map_err(err_500)?
        .ok_or_else(err_404)?;
    check_assignment_guard(&draft, &user)?;
    // If the draft is still 'submitted' (i.e. the assignee did not bother
    // claiming it via review_handler first) allow approval directly. Both
    // 'submitted' and 'in_review' are valid origin states.
    let from = if draft.status == "submitted" {
        "submitted"
    } else {
        "in_review"
    };
    // For 'submitted' → 'approved' we need a two-step transition since
    // TRANSITIONS doesn't allow that jump. Step via in_review.
    if from == "submitted" {
        transition_status(&state.pool, &id, "submitted", "in_review")
            .await
            .map_err(|e| err_400(&e.to_string()))?;
    }
    transition_status(&state.pool, &id, "in_review", "approved")
        .await
        .map_err(|e| err_400(&e.to_string()))?;

    if let Some(comment) = &body.comment {
        insert_comment(&state.pool, &new_id(), &id, &user.id, comment, Some("approve"))
            .await
            .map_err(err_500)?;
    }
    Ok(Json(serde_json::json!({"status": "approved"})))
}

pub async fn reject_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<ActionBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if user.role != "reviewer" && user.role != "admin" {
        return Err(err_403("Only reviewers can reject"));
    }
    let draft = get_draft(&state.pool, &id)
        .await
        .map_err(err_500)?
        .ok_or_else(err_404)?;
    check_assignment_guard(&draft, &user)?;
    if draft.status == "submitted" {
        transition_status(&state.pool, &id, "submitted", "in_review")
            .await
            .map_err(|e| err_400(&e.to_string()))?;
    }
    transition_status(&state.pool, &id, "in_review", "rejected")
        .await
        .map_err(|e| err_400(&e.to_string()))?;

    let comment = body.comment.as_deref().unwrap_or("Rejected");
    insert_comment(&state.pool, &new_id(), &id, &user.id, comment, Some("reject"))
        .await
        .map_err(err_500)?;
    Ok(Json(serde_json::json!({"status": "rejected"})))
}

pub async fn revise_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let draft = get_draft(&state.pool, &id)
        .await
        .map_err(err_500)?
        .ok_or_else(err_404)?;
    if draft.author_id != user.id {
        return Err(err_403("Only the author can revise"));
    }
    transition_status(&state.pool, &id, "rejected", "draft")
        .await
        .map_err(|e| err_400(&e.to_string()))?;
    Ok(Json(serde_json::json!({"status": "draft"})))
}

// ── Comments ────────────────────────────────────────────────────────────────

pub async fn list_comments_handler(
    State(state): State<AppState>,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<Vec<CommentRow>>, (StatusCode, String)> {
    let rows = list_comments(&state.pool, &id).await.map_err(err_500)?;
    Ok(Json(rows))
}

#[derive(Debug, Deserialize)]
pub struct AddCommentBody {
    pub body: String,
}

pub async fn add_comment_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<AddCommentBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    insert_comment(&state.pool, &new_id(), &id, &user.id, &body.body, None)
        .await
        .map_err(err_500)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

