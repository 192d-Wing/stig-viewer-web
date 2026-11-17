//! Set one status on many rules of a checklist in a single request.
//!
//! Backs the multi-select "Set status" action in the checklist view. Each
//! rule goes through the same gates as the single-rule PATCH
//! (`checklists::update_rule_handler`): write access to the asset, the
//! finding-details compliance gate, and the per-asset approval workflow.
//! Failures are reported per rule; one bad rule does not abort the batch.

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::api::checklists::{load_stig_json, take_rules};
use crate::api::finding_approvals;
use crate::db_assets;
use crate::db_checklists::{self, ChecklistRuleRow};
use crate::AppState;

/// Upper bound on rules per request. The largest DISA STIGs have well under
/// a thousand rules; this only stops absurd payloads.
pub(crate) const MAX_RULES: usize = 2000;

/// Cap on the shared finding details (bytes). The text is copied onto every
/// selected rule and into the audit trail, so it must stay small.
/// Longest accepted rule id (bytes); longer ids get a per-rule error.
pub(crate) const MAX_RULE_ID_BYTES: usize = 256;

/// Note on a `pending_approval` row when a request was already queued.
pub(crate) const ALREADY_PENDING: &str = "an approval request is already pending";

/// A rule id safe to echo in responses and log lines.
pub(crate) fn short_id(id: &str) -> String {
    id.chars().take(64).collect()
}

/// Outcome of [`apply_plan`] for one rule.
pub(crate) struct Applied {
    /// "applied" | "pending_approval"
    pub status: &'static str,
    pub note: Option<&'static str>,
}

const MAX_FINDING_DETAILS_BYTES: usize = 32 * 1024;

pub(crate) const VALID_STATUSES: &[&str] = &["not_reviewed", "open", "not_a_finding", "not_applicable"];

fn requires_finding_details(status: &str) -> bool {
    matches!(status, "not_a_finding" | "not_applicable")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkStatusRequest {
    pub rule_ids: Vec<String>,
    pub status: String,
    /// Applied to every selected rule when non-blank. When blank, each rule
    /// keeps the finding details it already has.
    #[serde(default)]
    pub finding_details: String,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BulkStatusRowResult {
    pub rule_id: String,
    /// "applied" | "pending_approval" | "error"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Extra information on a non-error row (e.g. approval already pending).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkStatusResponse {
    pub results: Vec<BulkStatusRowResult>,
    pub applied_count: usize,
    pub pending_count: usize,
    pub error_count: usize,
}

/// What to do with one rule, decided without touching the database.
#[derive(Debug, PartialEq)]
pub(crate) enum Plan {
    /// Write the rule row with these finding details.
    Apply { finding_details: String },
    /// Divert into the approval queue with these finding details.
    RequestApproval { finding_details: String },
    Reject(&'static str),
}

/// Decide how one rule is handled. `existing` is the rule's current override
/// row, if any; `shared_details` is the request-level justification.
pub(crate) fn plan_rule(
    known_rule: bool,
    existing: Option<&ChecklistRuleRow>,
    status: &str,
    shared_details: &str,
    asset_requires_approval: bool,
) -> Plan {
    if !known_rule {
        return Plan::Reject("rule is not part of this checklist's STIG");
    }
    // Stored verbatim like the single-rule PATCH; trim only to test blankness.
    let finding_details = if shared_details.trim().is_empty() {
        existing.map(|e| e.finding_details.clone()).unwrap_or_default()
    } else {
        shared_details.to_string()
    };
    if requires_finding_details(status) && finding_details.trim().is_empty() {
        return Plan::Reject("finding details required for this status");
    }
    let already_at_target = existing.map(|e| e.status.as_str()) == Some(status);
    if asset_requires_approval && finding_approvals::is_closing_status(status) && !already_at_target {
        return Plan::RequestApproval { finding_details };
    }
    Plan::Apply { finding_details }
}

/// POST /api/checklists/:id/rules/bulk-status
pub async fn bulk_status_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(checklist_id): Path<String>,
    Json(req): Json<BulkStatusRequest>,
) -> Result<Json<BulkStatusResponse>, StatusCode> {
    let pool = state.pool.as_ref();
    let checklist = db_checklists::get_checklist(pool, &checklist_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let asset = db_assets::get_asset(pool, &checklist.asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if !asset_acl::user_can(pool, &asset.id, &user, "write").await {
        return Err(StatusCode::FORBIDDEN);
    }
    if !VALID_STATUSES.contains(&req.status.as_str())
        || req.rule_ids.is_empty()
        || req.rule_ids.len() > MAX_RULES
        || req.finding_details.len() > MAX_FINDING_DETAILS_BYTES
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut stig = load_stig_json(&state, &checklist.stig_id).await?;
    let known: HashSet<String> = take_rules(&mut stig)
        .iter()
        .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    let distinct: HashSet<&str> = req.rule_ids.iter().map(String::as_str).collect();
    if distinct.len() > known.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let existing: HashMap<String, ChecklistRuleRow> =
        db_checklists::list_rule_overrides(pool, &checklist_id)
            .await
            .map_err(map_db)?
            .into_iter()
            .map(|r| (r.rule_id.clone(), r))
            .collect();

    let mut results = Vec::with_capacity(req.rule_ids.len());
    let mut seen: HashSet<&str> = HashSet::new();
    for rule_id in &req.rule_ids {
        if !seen.insert(rule_id.as_str()) {
            continue; // duplicate id in the request
        }
        if rule_id.len() > MAX_RULE_ID_BYTES {
            results.push(BulkStatusRowResult {
                rule_id: short_id(rule_id),
                status: "error".into(),
                error: Some("rule id too long".into()),
                note: None,
            });
            continue;
        }
        let prev = existing.get(rule_id);
        let plan = plan_rule(
            known.contains(rule_id),
            prev,
            &req.status,
            &req.finding_details,
            asset.requires_approval,
        );
        // Only a non-blank shared text overwrites; otherwise the write keeps
        // whatever the row holds at write time.
        let details = (!req.finding_details.trim().is_empty()).then_some(req.finding_details.as_str());
        let expect = expected_status(asset.requires_approval, &req.status, prev);
        let outcome = apply_plan(
            pool,
            &checklist_id,
            rule_id,
            &user.id,
            &req.status,
            true,
            expect.as_deref(),
            details,
            None,
            plan,
        )
        .await;
        results.push(match outcome {
            Ok(a) => BulkStatusRowResult {
                rule_id: rule_id.clone(),
                status: a.status.into(),
                error: None,
                note: a.note.map(str::to_string),
            },
            Err(error) => BulkStatusRowResult {
                rule_id: rule_id.clone(),
                status: "error".into(),
                error: Some(error),
                note: None,
            },
        });
    }

    let count = |s: &str| results.iter().filter(|r| r.status == s).count();
    let rejected: Vec<String> = results
        .iter()
        .filter(|r| r.status == "error")
        .take(100)
        .map(|r| short_id(&r.rule_id))
        .collect();
    // No general-purpose audit table exists (rule_audit is per rule/field),
    // so the request as a whole is recorded as one structured log line.
    tracing::info!(
        target: "audit",
        user_id = %user.id,
        asset_id = %asset.id,
        stig_id = %checklist.stig_id,
        checklist_id = %checklist_id,
        target_status = %req.status,
        applied = count("applied"),
        pending = count("pending_approval"),
        already_pending = results.iter().filter(|r| r.note.is_some()).count(),
        errors = count("error"),
        rejected_rule_ids = ?rejected,
        "bulk status change"
    );
    Ok(Json(BulkStatusResponse {
        applied_count: count("applied"),
        pending_count: count("pending_approval"),
        error_count: count("error"),
        results,
    }))
}

/// The status the locked row must still have for an approval-asset write that
/// relied on "already at the target status" (so it skipped the approval queue).
pub(crate) fn expected_status(
    requires_approval: bool,
    status: &str,
    existing: Option<&ChecklistRuleRow>,
) -> Option<String> {
    (requires_approval
        && finding_approvals::is_closing_status(status)
        && existing.map(|e| e.status.as_str()) == Some(status))
    .then(|| status.to_string())
}

/// The write for a `Plan::Apply`: which columns change and which guards the
/// locked row must pass.
fn build_patch<'a>(
    status: &'a str,
    write_status: bool,
    expect_status: Option<&'a str>,
    finding_details: Option<&'a str>,
    comments: Option<&'a str>,
) -> db_checklists::RulePatch<'a> {
    db_checklists::RulePatch {
        status: write_status.then_some(status),
        finding_details,
        comments,
        require_details: write_status && requires_finding_details(status),
        expect_status: if write_status { expect_status } else { None },
    }
}

/// Carry out a [`Plan`] for one rule. `finding_details` / `comments` are
/// `Some` only when the caller wants to overwrite that column; `None` keeps
/// the value stored at write time. `write_status` false leaves the stored
/// status alone (text-only update). A closing status is re-checked for
/// finding details against the locked row at write time.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_plan(
    pool: &sqlx::PgPool,
    checklist_id: &str,
    rule_id: &str,
    user_id: &str,
    status: &str,
    write_status: bool,
    expect_status: Option<&str>,
    finding_details: Option<&str>,
    comments: Option<&str>,
    plan: Plan,
) -> Result<Applied, String> {
    match plan {
        Plan::Reject(msg) => Err(msg.to_string()),
        Plan::RequestApproval { finding_details } => {
            let already = request_approval(pool, checklist_id, rule_id, user_id, status, &finding_details).await?;
            Ok(Applied { status: "pending_approval", note: already.then_some(ALREADY_PENDING) })
        }
        Plan::Apply { .. } => db_checklists::patch_rule(
            pool,
            checklist_id,
            rule_id,
            build_patch(status, write_status, expect_status, finding_details, comments),
            user_id,
        )
        .await
        .map(|_| Applied { status: "applied", note: None })
        .map_err(|e| {
            if let Some(rejected) = e.downcast_ref::<db_checklists::PatchRejected>() {
                return rejected.to_string();
            }
            tracing::error!("rule write failed for {rule_id}: {e:#}");
            "failed to save".to_string()
        }),
    }
}

/// File an approval request unless one is already pending for the rule.
async fn request_approval(
    pool: &sqlx::PgPool,
    checklist_id: &str,
    rule_id: &str,
    user_id: &str,
    status: &str,
    finding_details: &str,
) -> Result<bool, String> {
    let fail = |e: anyhow::Error| {
        tracing::error!("bulk-status approval request failed for {rule_id}: {e:#}");
        "failed to request approval".to_string()
    };
    if finding_approvals::has_pending(pool, checklist_id, rule_id).await.map_err(fail)? {
        return Ok(true);
    }
    finding_approvals::create_pending(pool, checklist_id, rule_id, user_id, status, finding_details)
        .await
        .map(|_| false)
        .map_err(fail)
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("bulk-status DB error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(status: &str, finding_details: &str) -> ChecklistRuleRow {
        ChecklistRuleRow {
            checklist_id: "c".into(),
            rule_id: "r".into(),
            status: status.into(),
            finding_details: finding_details.into(),
            comments: String::new(),
            updated_at: chrono::Utc::now(),
            updated_by: None,
            assignee_id: None,
            due_date: None,
        }
    }

    #[test]
    fn unknown_rule_is_rejected() {
        assert!(matches!(plan_rule(false, None, "open", "", false), Plan::Reject(_)));
    }

    #[test]
    fn closing_status_needs_finding_details_from_request_or_rule() {
        assert!(matches!(plan_rule(true, None, "not_a_finding", "  ", false), Plan::Reject(_)));
        assert_eq!(
            plan_rule(true, None, "not_a_finding", " patched ", false),
            Plan::Apply { finding_details: " patched ".into() }
        );
        let existing = row("open", "already documented");
        assert_eq!(
            plan_rule(true, Some(&existing), "not_applicable", "", false),
            Plan::Apply { finding_details: "already documented".into() }
        );
    }

    #[test]
    fn open_and_not_reviewed_need_no_details() {
        for status in ["open", "not_reviewed"] {
            assert_eq!(plan_rule(true, None, status, "", true), Plan::Apply { finding_details: String::new() });
        }
    }

    #[test]
    fn expected_status_pins_the_reopen_race_guard() {
        let at = |st: &str| row(st, "d");
        // (requires_approval, status, existing, expected)
        let cases: Vec<(bool, &str, Option<ChecklistRuleRow>, Option<&str>)> = vec![
            (true, "not_a_finding", Some(at("not_a_finding")), Some("not_a_finding")),
            (true, "not_applicable", Some(at("not_applicable")), Some("not_applicable")),
            (false, "not_a_finding", Some(at("not_a_finding")), None),
            (true, "open", Some(at("open")), None),
            (true, "not_reviewed", Some(at("not_reviewed")), None),
            (true, "not_a_finding", Some(at("open")), None),
            (true, "not_a_finding", None, None),
        ];
        for (approval, status, existing, want) in cases {
            assert_eq!(
                expected_status(approval, status, existing.as_ref()).as_deref(),
                want,
                "approval={approval} status={status}"
            );
        }
    }

    #[test]
    fn build_patch_carries_expect_status_only_when_status_is_written() {
        let p = build_patch("not_a_finding", true, Some("not_a_finding"), None, None);
        assert_eq!(p.expect_status, Some("not_a_finding"));
        assert_eq!(p.status, Some("not_a_finding"));
        assert!(p.require_details);
        let text_only = build_patch("open", false, Some("open"), None, Some("c"));
        assert_eq!(text_only.expect_status, None);
        assert_eq!(text_only.status, None);
        assert!(!text_only.require_details);
    }

    #[test]
    fn approval_assets_divert_closing_statuses_unless_already_there() {
        let open = row("open", "");
        assert_eq!(
            plan_rule(true, Some(&open), "not_a_finding", "fixed", true),
            Plan::RequestApproval { finding_details: "fixed".into() }
        );
        let closed = row("not_a_finding", "fixed");
        assert_eq!(
            plan_rule(true, Some(&closed), "not_a_finding", "", true),
            Plan::Apply { finding_details: "fixed".into() }
        );
    }
}
