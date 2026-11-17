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
use serde_json::json;

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::api::checklists::{load_stig_json, take_rules};
use crate::api::finding_approvals;
use crate::db_assets;
use crate::db_audit::{self, NewAuditEvent};
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
///
/// The work (access check through the final audit event) runs in a spawned
/// task: each rule is committed on its own, so a client disconnect that drops
/// this future must not leave committed writes without their audit event.
pub async fn bulk_status_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(checklist_id): Path<String>,
    Json(req): Json<BulkStatusRequest>,
) -> Result<Json<BulkStatusResponse>, StatusCode> {
    tokio::spawn(bulk_status_work(state, user, checklist_id, req))
        .await
        .map_err(|e| {
            tracing::error!("bulk status task failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
}

async fn bulk_status_work(
    state: AppState,
    user: AuthUser,
    checklist_id: String,
    req: BulkStatusRequest,
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

    let request_event = |outcome: &'static str, detail: serde_json::Value| {
        db_audit::record_or_log(
            pool,
            NewAuditEvent {
                user_id: &user.id,
                action: "rules.bulk_status",
                outcome,
                asset_id: Some(&asset.id),
                checklist_id: Some(&checklist_id),
                stig_id: Some(&checklist.stig_id),
                detail,
            },
        )
    };
    if !asset_acl::user_can(pool, &asset.id, &user, "write").await {
        request_event("denied", json!({ "reason": "forbidden" })).await;
        return Err(StatusCode::FORBIDDEN);
    }
    let bad_request = if !VALID_STATUSES.contains(&req.status.as_str()) {
        Some("invalid_status")
    } else if req.rule_ids.is_empty() {
        Some("no_rules")
    } else if req.rule_ids.len() > MAX_RULES {
        Some("too_many_rules")
    } else if req.finding_details.len() > MAX_FINDING_DETAILS_BYTES {
        Some("finding_details_too_long")
    } else {
        None
    };
    if let Some(reason) = bad_request {
        // The submitted status text is not echoed: it is not a known value here.
        request_event("rejected", json!({ "reason": reason, "requested": req.rule_ids.len() })).await;
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut stig = match load_stig_json(&state, &checklist.stig_id).await
    {
        Ok(v) => v,
        Err(code) => {
            if code == StatusCode::BAD_REQUEST || code == StatusCode::NOT_FOUND {
                request_event("rejected", json!({ "reason": "stig_unavailable" })).await;
            }
            return Err(code);
        }
    };
    let known: HashSet<String> = take_rules(&mut stig)
        .iter()
        .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    let distinct: HashSet<&str> = req.rule_ids.iter().map(String::as_str).collect();
    if distinct.len() > known.len() {
        request_event(
            "rejected",
            json!({
                "reason": "more_rules_than_stig",
                "targetStatus": req.status,
                "requested": req.rule_ids.len(),
                "distinct": distinct.len(),
            }),
        )
        .await;
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
    let all_rejected: Vec<(String, String)> = results
        .iter()
        .filter(|r| r.status == "error")
        .map(|r| (short_id(&r.rule_id), r.error.clone().unwrap_or_default()))
        .collect();
    let rejected: Vec<&str> = all_rejected.iter().take(100).map(|(id, _)| id.as_str()).collect();
    // The durable record is written below; this line stays as the fallback
    // when that write fails.
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
    let (rejected_list, rejected_truncated) = db_audit::rejected_detail(&all_rejected);
    request_event(
        if count("error") > 0 { "partial" } else { "ok" },
        json!({
            "targetStatus": req.status,
            "requested": req.rule_ids.len(),
            "applied": count("applied"),
            "pending": count("pending_approval"),
            "alreadyPending": results.iter().filter(|r| r.note.is_some()).count(),
            "errors": count("error"),
            "rejected": rejected_list,
            "rejectedTruncated": rejected_truncated,
        }),
    )
    .await;
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

    // ── Database-backed tests ──────────────────────────────────────────────

    use crate::test_fixtures::{app_state, StigDir, seed_asset, seed_checklist, seed_user, RULES, STIG_ID};
    use sqlx::PgPool;

    async fn setup(pool: &PgPool) -> (AppState, StigDir) {
        seed_user(pool, "owner").await;
        seed_user(pool, "other").await;
        seed_asset(pool, "a1", "owner", false).await;
        seed_checklist(pool, "c1", "a1", STIG_ID).await;
        app_state(pool.clone())
    }

    async fn call(
        state: &AppState,
        user: &str,
        checklist: &str,
        rule_ids: &[&str],
        status: &str,
        details: &str,
    ) -> Result<Json<BulkStatusResponse>, StatusCode> {
        bulk_status_handler(
            State(state.clone()),
            Extension(crate::test_fixtures::auth(user, "author")),
            Path(checklist.into()),
            Json(BulkStatusRequest {
                rule_ids: rule_ids.iter().map(|s| s.to_string()).collect(),
                status: status.into(),
                finding_details: details.into(),
            }),
        )
        .await
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_forbids_a_non_writer_and_404s_a_missing_checklist(pool: PgPool) {
        let (state, _dir) = setup(&pool).await;
        let err = call(&state, "other", "c1", &RULES, "open", "").await.err();
        assert_eq!(err, Some(StatusCode::FORBIDDEN));
        let err = call(&state, "owner", "nope", &RULES, "open", "").await.err();
        assert_eq!(err, Some(StatusCode::NOT_FOUND));
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklist_rules").fetch_one(&pool).await.unwrap();
        assert_eq!(rows, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_rejects_each_bad_request_shape(pool: PgPool) {
        let (state, _dir) = setup(&pool).await;
        let bad = |r: Result<Json<BulkStatusResponse>, StatusCode>| r.err();
        assert_eq!(bad(call(&state, "owner", "c1", &RULES, "bogus", "").await), Some(StatusCode::BAD_REQUEST));
        assert_eq!(bad(call(&state, "owner", "c1", &[], "open", "").await), Some(StatusCode::BAD_REQUEST));
        let many: Vec<String> = (0..=MAX_RULES).map(|i| format!("r{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(bad(call(&state, "owner", "c1", &many, "open", "").await), Some(StatusCode::BAD_REQUEST));
        let long = "x".repeat(MAX_FINDING_DETAILS_BYTES + 1);
        assert_eq!(bad(call(&state, "owner", "c1", &RULES, "open", &long).await), Some(StatusCode::BAD_REQUEST));
        let extra = ["x1", "x2", "x3", "x4"];
        assert_eq!(bad(call(&state, "owner", "c1", &extra, "open", "").await), Some(StatusCode::BAD_REQUEST));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_counts_match_the_rows_and_duplicates_collapse(pool: PgPool) {
        let (state, _dir) = setup(&pool).await;
        let ids = [RULES[0], RULES[0], RULES[1], "SV-unknown"];
        let Json(out) = call(&state, "owner", "c1", &ids, "open", "").await.unwrap();
        assert_eq!(out.results.len(), 3);
        assert_eq!((out.applied_count, out.pending_count, out.error_count), (2, 0, 1));
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklist_rules").fetch_one(&pool).await.unwrap();
        assert_eq!(rows as usize, out.applied_count);
        // Closing without any finding details is a per-rule error and writes nothing new.
        let Json(out) = call(&state, "owner", "c1", &[RULES[2]], "not_a_finding", "").await.unwrap();
        assert_eq!((out.applied_count, out.error_count), (0, 1));
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklist_rules").fetch_one(&pool).await.unwrap();
        assert_eq!(rows, 2);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_queues_closing_on_gated_assets_once(pool: PgPool) {
        seed_user(&pool, "owner").await;
        seed_asset(&pool, "a1", "owner", true).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        let (state, _dir) = app_state(pool.clone());
        let Json(out) = call(&state, "owner", "c1", &[RULES[0]], "not_a_finding", "why").await.unwrap();
        assert_eq!((out.applied_count, out.pending_count), (0, 1));
        let Json(out) = call(&state, "owner", "c1", &[RULES[0]], "not_a_finding", "why").await.unwrap();
        assert_eq!(out.results[0].note.as_deref(), Some(ALREADY_PENDING));
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM finding_approvals").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn apply_plan_rejects_a_stale_closed_snapshot(pool: PgPool) {
        // The handler cannot be driven to this from one direct call (the row
        // must change between its snapshot read and its write), so this is
        // the equivalent check one level down with a stale `expect_status`.
        let (_state, _dir) = setup(&pool).await;
        db_checklists::upsert_rule(&pool, "c1", RULES[0], "open", "d", "", "owner", None, None)
            .await
            .unwrap();
        let audit_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_audit").fetch_one(&pool).await.unwrap();
        let out = apply_plan(
            &pool,
            "c1",
            RULES[0],
            "owner",
            "not_a_finding",
            true,
            Some("not_a_finding"),
            None,
            None,
            Plan::Apply { finding_details: "d".into() },
        )
        .await;
        assert_eq!(out.err().as_deref(), Some("rule changed while saving; try again"));
        let status: String = sqlx::query_scalar("SELECT status FROM checklist_rules").fetch_one(&pool).await.unwrap();
        assert_eq!(status, "open");
        let audit_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_audit").fetch_one(&pool).await.unwrap();
        assert_eq!(audit_after, audit_before);
    }

    /// `(action, outcome, asset_id, checklist_id, detail text)` of every event, oldest first.
    async fn events(pool: &PgPool) -> Vec<(String, String, Option<String>, Option<String>, String)> {
        sqlx::query_as(
            "SELECT action, outcome, asset_id, checklist_id, detail::text FROM audit_events ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_records_ok_partial_denied_and_rejected_events(pool: PgPool) {
        let (state, _dir) = setup(&pool).await;
        let _ = call(&state, "owner", "c1", &[RULES[0], RULES[1]], "open", "").await.unwrap();
        let _ = call(&state, "owner", "c1", &[RULES[2], "SV-unknown"], "open", "").await.unwrap();
        call(&state, "other", "c1", &RULES, "open", "").await.err();
        call(&state, "owner", "c1", &RULES, "bogus", "").await.err();
        call(&state, "owner", "c1", &["x1", "x2", "x3", "x4"], "open", "").await.err();
        // A missing checklist has no asset to attach to and is not recorded.
        call(&state, "owner", "nope", &RULES, "open", "").await.err();

        let ev = events(&pool).await;
        let kinds: Vec<(&str, &str)> = ev.iter().map(|e| (e.0.as_str(), e.1.as_str())).collect();
        assert_eq!(
            kinds,
            [
                ("rules.bulk_status", "ok"),
                ("rules.bulk_status", "partial"),
                ("rules.bulk_status", "denied"),
                ("rules.bulk_status", "rejected"),
                ("rules.bulk_status", "rejected"),
            ]
        );
        assert!(ev.iter().all(|e| e.2.as_deref() == Some("a1") && e.3.as_deref() == Some("c1")));
        let d = |i: usize| serde_json::from_str::<serde_json::Value>(&ev[i].4).unwrap();
        assert_eq!((d(0)["applied"].as_i64(), d(0)["requested"].as_i64(), d(0)["errors"].as_i64()), (Some(2), Some(2), Some(0)));
        assert_eq!(d(0)["targetStatus"], "open");
        assert_eq!((d(1)["applied"].as_i64(), d(1)["errors"].as_i64()), (Some(1), Some(1)));
        assert_eq!(d(1)["rejected"][0]["ruleId"], "SV-unknown");
        assert_eq!(d(1)["rejected"][0]["reason"], "rule is not part of this checklist's STIG");
        assert_eq!(d(1)["rejectedTruncated"], false);
        assert_eq!(d(2)["reason"], "forbidden");
        assert_eq!(d(3)["reason"], "invalid_status");
        assert_eq!(d(4)["reason"], "more_rules_than_stig");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_event_detail_never_holds_request_text(pool: PgPool) {
        let (state, _dir) = setup(&pool).await;
        let text = "ZZ-RECOGNISABLE-FINDING-TEXT";
        let _ = call(&state, "owner", "c1", &[RULES[0], "SV-unknown"], "not_a_finding", text).await.unwrap();
        // A rejected request echoing the text in the status field.
        call(&state, "owner", "c1", &RULES, text, text).await.err();
        let ev = events(&pool).await;
        assert_eq!(ev.len(), 2);
        for e in &ev {
            assert!(!e.4.contains("ZZ-RECOGNISABLE"), "detail leaked request text: {}", e.4);
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_still_succeeds_when_the_audit_event_cannot_be_written(pool: PgPool) {
        let (state, _dir) = setup(&pool).await;
        sqlx::query("DROP TABLE audit_events").execute(&pool).await.unwrap();
        let Json(out) = call(&state, "owner", "c1", &[RULES[0]], "open", "").await.unwrap();
        assert_eq!(out.applied_count, 1);
        let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklist_rules").fetch_one(&pool).await.unwrap();
        assert_eq!(stored, 1);
        // Denials and rejections keep their status codes too.
        assert_eq!(call(&state, "other", "c1", &RULES, "open", "").await.err(), Some(StatusCode::FORBIDDEN));
        assert_eq!(call(&state, "owner", "c1", &RULES, "bogus", "").await.err(), Some(StatusCode::BAD_REQUEST));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_hostile_rule_ids_still_leave_exactly_one_event(pool: PgPool) {
        let (state, _dir) = setup(&pool).await;
        let long = "x".repeat(300);
        // NUL, quote + backslash + control chars, and an over-long id. (A lone
        // surrogate cannot be represented in a Rust String.)
        let ids = ["\u{0}", "q\"b\\\n\t\u{7f}", long.as_str()];
        let Json(out) = call(&state, "owner", "c1", &ids, "open", "").await.unwrap();
        assert_eq!(out.error_count, 3);
        let ev = events(&pool).await;
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].1, "partial");
        let d: serde_json::Value = serde_json::from_str(&ev[0].4).unwrap();
        assert_ne!(d, serde_json::json!({ "detailDropped": true }));
        let listed: Vec<&str> = d["rejected"].as_array().unwrap().iter().map(|r| r["ruleId"].as_str().unwrap()).collect();
        assert_eq!(listed, ["?", "q?b????", "x".repeat(64).as_str()]);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_records_a_rejected_event_for_each_validation_failure(pool: PgPool) {
        let (state, _dir) = setup(&pool).await;
        call(&state, "owner", "c1", &[], "open", "").await.err();
        let many: Vec<String> = (0..=MAX_RULES).map(|i| format!("r{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        call(&state, "owner", "c1", &many, "open", "").await.err();
        let long = "x".repeat(MAX_FINDING_DETAILS_BYTES + 1);
        call(&state, "owner", "c1", &RULES, "open", &long).await.err();
        let got: Vec<(String, String)> = events(&pool)
            .await
            .into_iter()
            .map(|e| {
                let d: serde_json::Value = serde_json::from_str(&e.4).unwrap();
                (e.1, d["reason"].as_str().unwrap().to_string())
            })
            .collect();
        let want: Vec<(String, String)> = [
            ("rejected", "no_rules"),
            ("rejected", "too_many_rules"),
            ("rejected", "finding_details_too_long"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        assert_eq!(got, want);
    }

    /// Relies on the current-thread runtime `#[sqlx::test]` uses (one `yield_now`
    /// lets the handler task reach its `tokio::spawn` before `abort()`).
    /// Drops the handler future right after its first poll, as hyper does on a
    /// client disconnect. The spawned work must still commit the rule write
    /// and the audit event. (Without the spawn, the abort would cancel the
    /// request before either happened.) This proves the work survives the
    /// handler future being dropped; it does not exercise hyper itself.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_work_and_event_survive_the_handler_future_being_dropped(pool: PgPool) {
        let (state, _dir) = setup(&pool).await;
        let st = state.clone();
        let h = tokio::spawn(async move { let _ = call(&st, "owner", "c1", &[RULES[0]], "open", "").await; });
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
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklist_rules").fetch_one(&pool).await.unwrap();
        assert_eq!(rows, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn bulk_on_a_checklist_whose_stig_file_is_missing_is_404_and_recorded(pool: PgPool) {
        let (state, _dir) = setup(&pool).await;
        seed_checklist(&pool, "c2", "a1", "GONE-STIG").await;
        assert_eq!(call(&state, "owner", "c2", &RULES, "open", "").await.err(), Some(StatusCode::NOT_FOUND));
        let ev = events(&pool).await;
        assert_eq!(ev.len(), 1);
        assert_eq!((ev[0].0.as_str(), ev[0].1.as_str()), ("rules.bulk_status", "rejected"));
        let d: serde_json::Value = serde_json::from_str(&ev[0].4).unwrap();
        assert_eq!(d["reason"], "stig_unavailable");
    }
}
