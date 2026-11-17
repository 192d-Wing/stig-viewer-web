//! "Save to system": push a Viewer tab's per-rule status, finding details and
//! comments into an asset's checklist for a catalog STIG, creating the
//! checklist when it does not exist yet.
//!
//! Every rule goes through the same gates as the single-rule PATCH (via
//! `rule_bulk_status::plan_rule` / `apply_plan`): known-rule check, the
//! finding-details compliance gate and the per-asset approval workflow.
//! Failures are reported per rule; one bad rule does not abort the batch.
//!
//! Merge policy (see [`merge_entry`]): untouched rules never downgrade the
//! server, a `not_reviewed` status never changes the server status, blank
//! text never erases server text, and a no-op write is skipped.

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::api::checklists::{create_checklist, is_valid_stig_id, load_stig_json, take_rules};
use crate::api::rule_bulk_status::{
    apply_plan, expected_status, plan_rule, short_id, Plan, MAX_RULES, MAX_RULE_ID_BYTES, VALID_STATUSES,
};
use crate::db_assets;
use crate::db_checklists::{self, ChecklistRuleRow, RulePatch};
use crate::AppState;

/// Per-field cap (bytes) on each rule's finding details and comments. A rule
/// over the cap gets a per-rule error and is not written.
const MAX_TEXT_BYTES: usize = 32 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveRule {
    pub rule_id: String,
    pub status: String,
    #[serde(default)]
    pub finding_details: String,
    #[serde(default)]
    pub comments: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveRequest {
    pub stig_id: String,
    #[serde(default)]
    pub rules: Vec<SaveRule>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SaveRowResult {
    pub rule_id: String,
    /// "applied" | "pending_approval" | "unchanged" | "error"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Extra information on a non-error row (e.g. approval already pending).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveResponse {
    pub checklist_id: String,
    pub created: bool,
    pub results: Vec<SaveRowResult>,
    pub applied_count: usize,
    pub pending_count: usize,
    pub unchanged_count: usize,
    pub error_count: usize,
}

/// The write resolved from the Viewer entry and the server row.
#[derive(Debug, PartialEq)]
struct Merged {
    /// Target status; for a `not_reviewed` entry this is the server's current
    /// status and `write_status` is false.
    status: String,
    /// False when only text is written and the stored status is left alone.
    write_status: bool,
    /// `Some` only when non-blank and different from the server value.
    finding_details: Option<String>,
    comments: Option<String>,
}

/// Decide what one entry changes. `None` means nothing to write.
fn merge_entry(existing: Option<&ChecklistRuleRow>, e: &SaveRule) -> Option<Merged> {
    let has_details = !e.finding_details.trim().is_empty();
    let has_comments = !e.comments.trim().is_empty();
    if e.status == "not_reviewed" && !has_details && !has_comments {
        return None; // untouched
    }
    let cur_status = existing.map(|x| x.status.as_str()).unwrap_or("not_reviewed");
    let cur_details = existing.map(|x| x.finding_details.as_str()).unwrap_or("");
    let cur_comments = existing.map(|x| x.comments.as_str()).unwrap_or("");
    let write_status = e.status != "not_reviewed";
    let status = if write_status { e.status.as_str() } else { cur_status };
    let finding_details = (has_details && e.finding_details != cur_details).then(|| e.finding_details.clone());
    let comments = (has_comments && e.comments != cur_comments).then(|| e.comments.clone());
    if status == cur_status && finding_details.is_none() && comments.is_none() {
        return None;
    }
    Some(Merged { status: status.to_string(), write_status, finding_details, comments })
}

/// POST /api/assets/:id/checklists/save
pub async fn save_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(asset_id): Path<String>,
    Json(req): Json<SaveRequest>,
) -> Result<Json<SaveResponse>, StatusCode> {
    let pool = state.pool.as_ref();
    let asset = db_assets::get_asset(pool, &asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if !asset_acl::user_can(pool, &asset.id, &user, "write").await {
        return Err(StatusCode::FORBIDDEN);
    }
    if !is_valid_stig_id(&req.stig_id) || req.rules.len() > MAX_RULES {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Load the catalog STIG before creating anything so a bad id never
    // leaves an empty checklist behind.
    let mut stig = load_stig_json(&state, &req.stig_id).await?;
    let known: HashSet<String> = take_rules(&mut stig)
        .iter()
        .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(str::to_string))
        .collect();

    let distinct: HashSet<&str> = req.rules.iter().map(|r| r.rule_id.as_str()).collect();
    if distinct.len() > known.len() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut created = false;
    let checklist = match db_checklists::find_checklist(pool, &asset.id, &req.stig_id)
        .await
        .map_err(map_db)?
    {
        Some(c) => c,
        None => match create_checklist(pool, &asset.id, &req.stig_id).await {
            Ok(c) => {
                created = true;
                c
            }
            Err(e) => {
                // A concurrent save may have created it first.
                match db_checklists::find_checklist(pool, &asset.id, &req.stig_id)
                    .await
                    .map_err(map_db)?
                {
                    Some(c) => c,
                    None => return Err(map_db(e)),
                }
            }
        },
    };

    let existing: HashMap<String, ChecklistRuleRow> =
        db_checklists::list_rule_overrides(pool, &checklist.id)
            .await
            .map_err(map_db)?
            .into_iter()
            .map(|r| (r.rule_id.clone(), r))
            .collect();

    let mut results = Vec::with_capacity(req.rules.len());
    let mut seen: HashSet<&str> = HashSet::new();
    for entry in &req.rules {
        if !seen.insert(entry.rule_id.as_str()) {
            continue; // duplicate rule id: first one wins
        }
        let outcome = save_one(
            pool,
            &checklist.id,
            &user.id,
            asset.requires_approval,
            known.contains(&entry.rule_id),
            existing.get(&entry.rule_id),
            entry,
        )
        .await;
        let rule_id = short_id(&entry.rule_id);
        results.push(match outcome {
            Ok((status, note)) => SaveRowResult { rule_id, status: status.into(), error: None, note },
            Err(error) => SaveRowResult { rule_id, status: "error".into(), error: Some(error), note: None },
        });
    }

    let count = |s: &str| results.iter().filter(|r| r.status == s).count();
    let rejected: Vec<String> = results
        .iter()
        .filter(|r| r.status == "error")
        .take(100)
        .map(|r| r.rule_id.clone())
        .collect();
    // No general-purpose audit table exists; record the request as one line.
    tracing::info!(
        target: "audit",
        user_id = %user.id,
        asset_id = %asset.id,
        stig_id = %req.stig_id,
        checklist_id = %checklist.id,
        created,
        already_pending = results.iter().filter(|r| r.note.is_some()).count(),
        applied = count("applied"),
        pending = count("pending_approval"),
        unchanged = count("unchanged"),
        errors = count("error"),
        rejected_rule_ids = ?rejected,
        "save to system"
    );
    Ok(Json(SaveResponse {
        checklist_id: checklist.id,
        created,
        applied_count: count("applied"),
        pending_count: count("pending_approval"),
        unchanged_count: count("unchanged"),
        error_count: count("error"),
        results,
    }))
}

/// Process one entry; returns the result status or a per-rule error message.
async fn save_one(
    pool: &sqlx::PgPool,
    checklist_id: &str,
    user_id: &str,
    requires_approval: bool,
    known: bool,
    prev: Option<&ChecklistRuleRow>,
    e: &SaveRule,
) -> Result<(&'static str, Option<String>), String> {
    if e.rule_id.len() > MAX_RULE_ID_BYTES {
        return Err("rule id too long".into());
    }
    if !VALID_STATUSES.contains(&e.status.as_str()) {
        return Err("invalid status".into());
    }
    if e.finding_details.len() > MAX_TEXT_BYTES || e.comments.len() > MAX_TEXT_BYTES {
        return Err("finding details or comments too long".into());
    }
    if !known {
        // Report unknown rules even when there is nothing to write.
        return Err("rule is not part of this checklist's STIG".into());
    }
    let Some(merged) = merge_entry(prev, e) else {
        return Ok(("unchanged", None));
    };
    // A text-only update leaves the status alone, so the status gates do not apply.
    let plan = if merged.write_status {
        plan_rule(true, prev, &merged.status, &e.finding_details, requires_approval)
    } else {
        Plan::Apply { finding_details: e.finding_details.clone() }
    };
    let expect = expected_status(requires_approval, &merged.status, prev);
    let applied = apply_plan(
        pool,
        checklist_id,
        &e.rule_id,
        user_id,
        &merged.status,
        merged.write_status,
        expect.as_deref(),
        merged.finding_details.as_deref(),
        merged.comments.as_deref(),
        plan,
    )
    .await?;
    if applied.status == "pending_approval" {
        if let Some(comments) = merged.comments.as_deref() {
            // Status and finding details wait for approval; the comments are
            // not gated, so keep them rather than dropping user input.
            db_checklists::patch_rule(
                pool,
                checklist_id,
                &e.rule_id,
                RulePatch { comments: Some(comments), ..RulePatch::default() },
                user_id,
            )
            .await
            .map_err(|err| {
                tracing::error!("save comments failed for {}: {err:#}", short_id(&e.rule_id));
                "failed to save comments".to_string()
            })?;
        }
    }
    Ok((applied.status, applied.note.map(str::to_string)))
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("checklist save DB error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(status: &str, details: &str, comments: &str) -> ChecklistRuleRow {
        ChecklistRuleRow {
            checklist_id: "c".into(),
            rule_id: "r".into(),
            status: status.into(),
            finding_details: details.into(),
            comments: comments.into(),
            updated_at: chrono::Utc::now(),
            updated_by: None,
            assignee_id: None,
            due_date: None,
        }
    }

    fn entry(status: &str, details: &str, comments: &str) -> SaveRule {
        SaveRule {
            rule_id: "r".into(),
            status: status.into(),
            finding_details: details.into(),
            comments: comments.into(),
        }
    }

    #[test]
    fn untouched_entry_is_skipped() {
        assert_eq!(merge_entry(None, &entry("not_reviewed", "  ", "")), None);
    }

    #[test]
    fn untouched_entry_never_downgrades() {
        let open = row("open", "d", "c");
        assert_eq!(merge_entry(Some(&open), &entry("not_reviewed", "", "")), None);
    }

    #[test]
    fn not_reviewed_with_notes_keeps_status_and_takes_comments() {
        let open = row("open", "d", "old");
        assert_eq!(
            merge_entry(Some(&open), &entry("not_reviewed", "", "new")),
            Some(Merged { status: "open".into(), write_status: false, finding_details: None, comments: Some("new".into()) })
        );
    }

    #[test]
    fn blank_text_keeps_server_text() {
        let r = row("open", "d", "c");
        assert_eq!(
            merge_entry(Some(&r), &entry("not_a_finding", "", "")),
            Some(Merged { status: "not_a_finding".into(), write_status: true, finding_details: None, comments: None })
        );
    }

    #[test]
    fn non_blank_text_replaces() {
        let r = row("open", "d", "c");
        assert_eq!(
            merge_entry(Some(&r), &entry("open", "d2", "c2")),
            Some(Merged {
                status: "open".into(),
                write_status: true,
                finding_details: Some("d2".into()),
                comments: Some("c2".into())
            })
        );
    }

    #[test]
    fn identical_entry_is_a_noop() {
        let r = row("open", "d", "c");
        assert_eq!(merge_entry(Some(&r), &entry("open", "d", "c")), None);
        assert_eq!(merge_entry(Some(&r), &entry("open", "", "")), None);
    }

    #[test]
    fn closing_status_without_details_is_rejected_by_the_gate() {
        let e = entry("not_a_finding", "", "");
        let merged = merge_entry(None, &e).expect("status change");
        assert!(matches!(
            plan_rule(true, None, &merged.status, &e.finding_details, false),
            Plan::Reject(_)
        ));
    }
}
