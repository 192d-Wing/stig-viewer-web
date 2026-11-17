//! "Save to system": push a Viewer tab's per-rule status, finding details and
//! comments into an asset's checklist for a catalog STIG, creating the
//! checklist when it does not exist yet.
//!
//! Every rule goes through the same gates as the single-rule PATCH (via
//! `rule_bulk_status::plan_rule` / `apply_plans`): known-rule check, the
//! finding-details compliance gate and the per-asset approval workflow.
//! Entries are planned without touching the database ([`plan_entry`]), then
//! written in chunks of `db_checklists::RULE_CHUNK` per transaction. A gate
//! failure is reported per rule and does not abort the batch; a database
//! error fails the chunk it hit.
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
use serde_json::json;

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::api::checklists::{is_valid_stig_id, load_stig_json, take_rules};
use crate::api::rule_bulk_status::{
    apply_plans, expected_status, plan_rule, short_id, Plan, RuleOp, MAX_RULES, MAX_RULE_ID_BYTES, VALID_STATUSES,
};
use crate::db_assets;
use crate::db_audit::{self, NewAuditEvent};
use crate::db_checklists::{self, ChecklistRuleRow};
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
///
/// The work (access check through the final audit events) runs in a spawned
/// task: each chunk is committed on its own, so a client disconnect that drops
/// this future must not leave committed writes without their audit events.
pub async fn save_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(asset_id): Path<String>,
    Json(req): Json<SaveRequest>,
) -> Result<Json<SaveResponse>, StatusCode> {
    tokio::spawn(save_work(state, user, asset_id, req))
        .await
        .map_err(|e| {
            tracing::error!("save task failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
}

async fn save_work(
    state: AppState,
    user: AuthUser,
    asset_id: String,
    req: SaveRequest,
) -> Result<Json<SaveResponse>, StatusCode> {
    let pool = state.pool.as_ref();
    let asset = db_assets::get_asset(pool, &asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    // The request's STIG id is recorded only once it has the expected shape.
    let event_stig = is_valid_stig_id(&req.stig_id).then_some(req.stig_id.as_str());
    let request_event = |outcome: &'static str, detail: serde_json::Value| {
        db_audit::record_or_log(
            pool,
            NewAuditEvent {
                user_id: &user.id,
                action: "checklist.save",
                outcome,
                asset_id: Some(&asset.id),
                checklist_id: None,
                stig_id: event_stig,
                detail,
            },
        )
    };
    if !asset_acl::user_can(pool, &asset.id, &user, "write").await {
        request_event("denied", json!({ "reason": "forbidden" })).await;
        return Err(StatusCode::FORBIDDEN);
    }
    if !is_valid_stig_id(&req.stig_id) {
        request_event("rejected", json!({ "reason": "invalid_stig_id", "requested": req.rules.len() })).await;
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.rules.len() > MAX_RULES {
        request_event("rejected", json!({ "reason": "too_many_rules", "requested": req.rules.len() })).await;
        return Err(StatusCode::BAD_REQUEST);
    }

    // Load the catalog STIG before creating anything so a bad id never
    // leaves an empty checklist behind.
    let mut stig = match load_stig_json(&state, &req.stig_id).await
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

    let distinct: HashSet<&str> = req.rules.iter().map(|r| r.rule_id.as_str()).collect();
    if distinct.len() > known.len() {
        request_event(
            "rejected",
            json!({ "reason": "more_rules_than_stig", "requested": req.rules.len(), "distinct": distinct.len() }),
        )
        .await;
        return Err(StatusCode::BAD_REQUEST);
    }

    let (checklist, created) = find_or_create(pool, &asset.id, &req.stig_id, &user.id)
        .await
        .map_err(map_db)?;
    if created {
        // Separate event so every checklist creation is searchable by action,
        // whichever endpoint made it (also noted as `created` in the save event).
        db_audit::record_or_log(
            pool,
            NewAuditEvent {
                user_id: &user.id,
                action: "checklist.create",
                outcome: "ok",
                asset_id: Some(&asset.id),
                checklist_id: Some(&checklist.id),
                stig_id: Some(&req.stig_id),
                detail: json!({ "via": "save" }),
            },
        )
        .await;
    }

    let existing: HashMap<String, ChecklistRuleRow> =
        db_checklists::list_rule_overrides(pool, &checklist.id)
            .await
            .map_err(map_db)?
            .into_iter()
            .map(|r| (r.rule_id.clone(), r))
            .collect();

    let results =
        apply_entries(pool, &checklist.id, &user.id, asset.requires_approval, &known, &existing, &req.rules).await;

    let count = |s: &str| results.iter().filter(|r| r.status == s).count();
    let all_rejected: Vec<(String, String)> = results
        .iter()
        .filter(|r| r.status == "error")
        .map(|r| (r.rule_id.clone(), r.error.clone().unwrap_or_default()))
        .collect();
    let rejected: Vec<&str> = all_rejected.iter().take(100).map(|(id, _)| id.as_str()).collect();
    // The durable record is written below; this line stays as the fallback
    // when that write fails.
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
    let (rejected_list, rejected_truncated) = db_audit::rejected_detail(&all_rejected);
    db_audit::record_or_log(
        pool,
        NewAuditEvent {
            user_id: &user.id,
            action: "checklist.save",
            outcome: if count("error") > 0 { "partial" } else { "ok" },
            asset_id: Some(&asset.id),
            checklist_id: Some(&checklist.id),
            stig_id: Some(&req.stig_id),
            detail: json!({
                "created": created,
                "requested": req.rules.len(),
                "applied": count("applied"),
                "pending": count("pending_approval"),
                "unchanged": count("unchanged"),
                "errors": count("error"),
                "alreadyPending": results.iter().filter(|r| r.note.is_some()).count(),
                "rejected": rejected_list,
                "rejectedTruncated": rejected_truncated,
            }),
        },
    )
    .await;
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

/// Find the asset's checklist for a STIG, creating it when absent. A
/// concurrent creator is handled by the insert-if-absent plus a re-read, so
/// only a genuine failure surfaces as an error. The flag is true when this
/// call created the checklist.
async fn find_or_create(
    pool: &sqlx::PgPool,
    asset_id: &str,
    stig_id: &str,
    created_by: &str,
) -> anyhow::Result<(db_checklists::ChecklistRow, bool)> {
    if let Some(c) = db_checklists::find_checklist(pool, asset_id, stig_id).await? {
        return Ok((c, false));
    }
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
    let inserted = db_checklists::insert_checklist_if_absent(pool, &row).await?;
    if inserted {
        return Ok((row, true));
    }
    // Lost the race: the winner's row is the checklist.
    db_checklists::find_checklist(pool, asset_id, stig_id)
        .await?
        .map(|c| (c, false))
        .ok_or_else(|| anyhow::anyhow!("checklist vanished after concurrent create"))
}

/// An entry that has something to write: the merge, the revision guard and
/// the gate decision.
struct Planned {
    merged: Merged,
    /// Status the locked row must still have (see `expected_status`).
    expect: Option<String>,
    plan: Plan,
}

/// Validate and plan one entry without touching the database. `Ok(None)`
/// means unchanged; `Err` is the per-rule error message.
fn plan_entry(
    requires_approval: bool,
    known: bool,
    prev: Option<&ChecklistRuleRow>,
    e: &SaveRule,
) -> Result<Option<Planned>, String> {
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
        return Ok(None);
    };
    // A text-only update leaves the status alone, so the status gates do not apply.
    let plan = if merged.write_status {
        plan_rule(true, prev, &merged.status, &e.finding_details, requires_approval)
    } else {
        Plan::Apply { finding_details: e.finding_details.clone() }
    };
    let expect = expected_status(requires_approval, &merged.status, prev);
    Ok(Some(Planned { merged, expect, plan }))
}

/// Plan every entry (first occurrence of a rule id wins), write them through
/// `apply_plans`, and return the results in request order. `existing` is the
/// caller's snapshot; the writes re-check against the locked rows.
async fn apply_entries(
    pool: &sqlx::PgPool,
    checklist_id: &str,
    user_id: &str,
    requires_approval: bool,
    known: &HashSet<String>,
    existing: &HashMap<String, ChecklistRuleRow>,
    rules: &[SaveRule],
) -> Vec<SaveRowResult> {
    enum Slot {
        Done(SaveRowResult),
        Op(usize),
    }
    let mut slots = Vec::with_capacity(rules.len());
    let mut entries: Vec<&SaveRule> = Vec::new();
    let mut planned: Vec<Planned> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for entry in rules {
        if !seen.insert(entry.rule_id.as_str()) {
            continue; // duplicate rule id: first one wins
        }
        let rule_id = short_id(&entry.rule_id);
        match plan_entry(requires_approval, known.contains(&entry.rule_id), existing.get(&entry.rule_id), entry) {
            Err(error) => slots.push(Slot::Done(SaveRowResult { rule_id, status: "error".into(), error: Some(error), note: None })),
            Ok(None) => slots.push(Slot::Done(SaveRowResult { rule_id, status: "unchanged".into(), error: None, note: None })),
            Ok(Some(p)) => {
                slots.push(Slot::Op(planned.len()));
                entries.push(entry);
                planned.push(p);
            }
        }
    }
    let (plans, rest): (Vec<Plan>, Vec<(Merged, Option<String>)>) =
        planned.into_iter().map(|p| (p.plan, (p.merged, p.expect))).unzip();
    let ops: Vec<RuleOp<'_>> = entries
        .iter()
        .zip(plans)
        .zip(&rest)
        .map(|((e, plan), (merged, expect))| RuleOp {
            rule_id: &e.rule_id,
            status: &merged.status,
            write_status: merged.write_status,
            expect_status: expect.as_deref(),
            finding_details: merged.finding_details.as_deref(),
            comments: merged.comments.as_deref(),
            plan,
        })
        .collect();
    let mut applied = apply_plans(pool, checklist_id, user_id, &ops).await.into_iter();
    slots
        .into_iter()
        .map(|slot| match slot {
            Slot::Done(r) => r,
            Slot::Op(i) => {
                let rule_id = short_id(&entries[i].rule_id);
                match applied.next() {
                    Some(Ok(a)) => SaveRowResult { rule_id, status: a.status.into(), error: None, note: a.note.map(str::to_string) },
                    Some(Err(error)) => SaveRowResult { rule_id, status: "error".into(), error: Some(error), note: None },
                    None => SaveRowResult { rule_id, status: "error".into(), error: Some("failed to save".into()), note: None },
                }
            }
        })
        .collect()
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

    fn plan(requires_approval: bool, known: bool, prev: Option<&ChecklistRuleRow>, e: &SaveRule) -> Result<Option<Planned>, String> {
        plan_entry(requires_approval, known, prev, e)
    }

    #[test]
    fn plan_entry_reports_each_validation_in_order() {
        let long_id = "x".repeat(MAX_RULE_ID_BYTES + 1);
        let long_text = "y".repeat(MAX_TEXT_BYTES + 1);
        let mut e = entry("bogus", &long_text, "");
        e.rule_id = long_id;
        // Every check fails at once: the id length is reported first.
        assert_eq!(plan(false, false, None, &e).err().as_deref(), Some("rule id too long"));
        e.rule_id = "r".into();
        assert_eq!(plan(false, false, None, &e).err().as_deref(), Some("invalid status"));
        e.status = "open".into();
        assert_eq!(
            plan(false, false, None, &e).err().as_deref(),
            Some("finding details or comments too long")
        );
        let e = entry("open", "", &long_text);
        assert_eq!(
            plan(false, false, None, &e).err().as_deref(),
            Some("finding details or comments too long")
        );
        // Unknown rules are reported even when there is nothing to write.
        let e = entry("not_reviewed", "", "");
        assert_eq!(
            plan(false, false, None, &e).err().as_deref(),
            Some("rule is not part of this checklist's STIG")
        );
    }

    #[test]
    fn plan_entry_unchanged_and_planned() {
        assert!(matches!(plan(false, true, None, &entry("not_reviewed", "", "")), Ok(None)));
        let open = row("open", "d", "c");
        assert!(matches!(plan(false, true, Some(&open), &entry("open", "d", "c")), Ok(None)));

        let p = plan(false, true, None, &entry("open", "", "")).unwrap().unwrap();
        assert_eq!(p.plan, Plan::Apply { finding_details: String::new() });
        assert_eq!((p.merged.status.as_str(), p.merged.write_status, p.expect), ("open", true, None));

        // Text only: the status gates do not apply.
        let p = plan(true, true, Some(&open), &entry("not_reviewed", "", "note")).unwrap().unwrap();
        assert!(!p.merged.write_status);
        assert_eq!(p.plan, Plan::Apply { finding_details: String::new() });
        assert_eq!(p.expect, None);
    }

    #[test]
    fn plan_entry_applies_the_approval_and_details_gates() {
        let p = plan(true, true, None, &entry("not_a_finding", "why", "")).unwrap().unwrap();
        assert_eq!(p.plan, Plan::RequestApproval { finding_details: "why".into() });
        let p = plan(false, true, None, &entry("not_a_finding", "", "")).unwrap().unwrap();
        assert!(matches!(p.plan, Plan::Reject(_)));
        // Already at the target on a gated asset: write, guarded by the snapshot status.
        let closed = row("not_a_finding", "why", "");
        let p = plan(true, true, Some(&closed), &entry("not_a_finding", "why2", "")).unwrap().unwrap();
        assert_eq!(p.plan, Plan::Apply { finding_details: "why2".into() });
        assert_eq!(p.expect.as_deref(), Some("not_a_finding"));
    }

    // ── Database-backed tests ──────────────────────────────────────────────

    use crate::test_fixtures::{app_state, app_state_with_rules, auth, fail_writes_of, rule_ids, seed_asset, seed_checklist, seed_rule, seed_user, RULES, STIG_ID};
    use sqlx::PgPool;

    async fn count(pool: &PgPool, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
    }

    async fn call(
        state: &AppState,
        user: &str,
        role: &str,
        stig_id: &str,
        rules: Vec<SaveRule>,
    ) -> Result<Json<SaveResponse>, StatusCode> {
        save_handler(
            State(state.clone()),
            Extension(auth(user, role)),
            Path("a1".into()),
            Json(SaveRequest { stig_id: stig_id.into(), rules }),
        )
        .await
    }

    fn rule(id: &str, status: &str, details: &str, comments: &str) -> SaveRule {
        SaveRule {
            rule_id: id.into(),
            status: status.into(),
            finding_details: details.into(),
            comments: comments.into(),
        }
    }

    async fn base(pool: &PgPool, requires_approval: bool) {
        seed_user(pool, "owner").await;
        seed_user(pool, "other").await;
        seed_asset(pool, "a1", "owner", requires_approval).await;
    }

    fn known() -> HashSet<String> {
        RULES.iter().map(|s| s.to_string()).collect()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn apply_entries_rejects_when_the_live_row_was_reopened(pool: PgPool) {
        base(&pool, true).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        seed_rule(&pool, "c1", RULES[0], "not_a_finding", "d", "", "owner").await;
        // The caller read the rule as closed...
        let prev = db_checklists::list_rule_overrides(&pool, "c1").await.unwrap().remove(0);
        let snapshot = HashMap::from([(RULES[0].to_string(), prev)]);
        // ...then someone reopened it before the save wrote.
        seed_rule(&pool, "c1", RULES[0], "open", "d", "", "owner").await;
        let audit_before = count(&pool, "SELECT COUNT(*) FROM rule_audit").await;

        let out = apply_entries(
            &pool,
            "c1",
            "owner",
            true,
            &known(),
            &snapshot,
            &[rule(RULES[0], "not_a_finding", "d", "new comment")],
        )
        .await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].error.as_deref(), Some("rule changed while saving; try again"));

        let live = db_checklists::list_rule_overrides(&pool, "c1").await.unwrap().remove(0);
        assert_eq!((live.status.as_str(), live.comments.as_str()), ("open", ""));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM rule_audit").await, audit_before);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_approvals").await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn pending_path_keeps_comments_with_a_single_audit_row(pool: PgPool) {
        base(&pool, true).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        let out = apply_entries(
            &pool,
            "c1",
            "owner",
            true,
            &known(),
            &HashMap::new(),
            &[rule(RULES[0], "not_a_finding", "because", "reviewer note")],
        )
        .await;
        assert_eq!(out[0].status, "pending_approval");
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_approvals WHERE status = 'pending'").await, 1);
        let live = db_checklists::list_rule_overrides(&pool, "c1").await.unwrap().remove(0);
        assert_eq!(live.status, "not_reviewed");
        assert_eq!(live.comments, "reviewer note");
        let fields: Vec<String> = sqlx::query_scalar("SELECT field FROM rule_audit")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(fields, ["comments"]);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_text_only_entries_keep_the_locked_status_in_a_batch(pool: PgPool) {
        base(&pool, false).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        seed_rule(&pool, "c1", RULES[0], "open", "d", "", "owner").await;
        let snapshot = HashMap::from([(
            RULES[0].to_string(),
            db_checklists::list_rule_overrides(&pool, "c1").await.unwrap().remove(0),
        )]);
        // The status moves on after the snapshot; a text-only save must not revert it.
        seed_rule(&pool, "c1", RULES[0], "not_a_finding", "d", "", "owner").await;
        let out = apply_entries(
            &pool,
            "c1",
            "owner",
            false,
            &known(),
            &snapshot,
            &[
                rule(RULES[0], "not_reviewed", "", "reviewer note"),
                rule(RULES[1], "open", "", ""),
                rule(RULES[2], "not_reviewed", "", "note only"),
            ],
        )
        .await;
        let statuses: Vec<&str> = out.iter().map(|r| r.status.as_str()).collect();
        assert_eq!(statuses, ["applied", "applied", "applied"]);
        let rows = db_checklists::list_rule_overrides(&pool, "c1").await.unwrap();
        let by = |id: &str| rows.iter().find(|r| r.rule_id == id).unwrap();
        assert_eq!((by(RULES[0]).status.as_str(), by(RULES[0]).comments.as_str()), ("not_a_finding", "reviewer note"));
        assert_eq!(by(RULES[1]).status, "open");
        assert_eq!((by(RULES[2]).status.as_str(), by(RULES[2]).comments.as_str()), ("not_reviewed", "note only"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_event_counts_survive_a_failed_chunk(pool: PgPool) {
        base(&pool, false).await;
        let ids = rule_ids(250);
        let (state, _dir) = app_state_with_rules(pool.clone(), &ids);
        fail_writes_of(&pool, "checklist_rules", &[ids[150].as_str()]).await;
        let rules: Vec<SaveRule> = ids.iter().map(|id| rule(id, "open", "", "")).collect();
        let Json(out) = call(&state, "owner", "author", STIG_ID, rules).await.unwrap();
        assert_eq!((out.applied_count, out.error_count, out.unchanged_count), (150, 100, 0));
        assert!(out.results[100..200].iter().all(|r| r.error.as_deref() == Some("failed to save")));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_rules").await, 150);
        let saves: Vec<_> = events(&pool).await.into_iter().filter(|e| e.0 == "checklist.save").collect();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].1, "partial");
        let d: serde_json::Value = serde_json::from_str(&saves[0].4).unwrap();
        assert_eq!((d["applied"].as_i64(), d["errors"].as_i64()), (Some(150), Some(100)));
        assert_eq!(d["rejected"].as_array().unwrap().len(), 100);
        assert_eq!(d["rejected"][0]["reason"], "failed to save");
        assert_eq!(d["rejectedTruncated"], false);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn find_or_create_returns_the_existing_checklist(pool: PgPool) {
        base(&pool, false).await;
        seed_checklist(&pool, "orig", "a1", STIG_ID).await;
        let (c, created) = find_or_create(&pool, "a1", STIG_ID, "owner").await.unwrap();
        assert_eq!((c.id.as_str(), created), ("orig", false));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn find_or_create_creates_once_then_finds(pool: PgPool) {
        base(&pool, false).await;
        let (first, created) = find_or_create(&pool, "a1", STIG_ID, "owner").await.unwrap();
        assert!(created);
        let (again, created) = find_or_create(&pool, "a1", STIG_ID, "owner").await.unwrap();
        assert_eq!((again.id, created), (first.id, false));
    }

    // Probabilistic: the race window is only hit when tasks interleave between the find and
    // the insert. A regression to a plain INSERT would surface as a unique-violation error or
    // two "created" results, not necessarily on every run.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn concurrent_find_or_create_yields_one_checklist(pool: PgPool) {
        base(&pool, false).await;
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let pool = pool.clone();
            tasks.spawn(async move { find_or_create(&pool, "a1", STIG_ID, "owner").await });
        }
        let mut ids = HashSet::new();
        let mut created = 0;
        while let Some(res) = tasks.join_next().await {
            let (c, was_created) = res.unwrap().unwrap();
            ids.insert(c.id);
            created += usize::from(was_created);
        }
        assert_eq!((ids.len(), created), (1, 1));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_handler_forbids_a_non_writer(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        let err = call(&state, "other", "author", STIG_ID, vec![]).await.err();
        assert_eq!(err, Some(StatusCode::FORBIDDEN));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_handler_rejects_bad_requests_without_creating_a_checklist(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        let bad_id = call(&state, "owner", "author", "../etc", vec![]).await.err();
        assert_eq!(bad_id, Some(StatusCode::BAD_REQUEST));
        let too_many: Vec<SaveRule> = (0..=MAX_RULES).map(|i| rule(&format!("r{i}"), "open", "", "")).collect();
        let err = call(&state, "owner", "author", STIG_ID, too_many).await.err();
        assert_eq!(err, Some(StatusCode::BAD_REQUEST));
        // More distinct ids than the STIG has rules.
        let extra: Vec<SaveRule> = (0..=RULES.len()).map(|i| rule(&format!("x{i}"), "open", "", "")).collect();
        let err = call(&state, "owner", "author", STIG_ID, extra).await.err();
        assert_eq!(err, Some(StatusCode::BAD_REQUEST));
        let err = call(&state, "owner", "author", "NO-SUCH-STIG", vec![]).await.err();
        assert_eq!(err, Some(StatusCode::NOT_FOUND));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_handler_counts_match_the_rows(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        let rules = vec![
            rule(RULES[0], "open", "", ""),
            rule(RULES[0], "not_applicable", "dup ignored", ""), // duplicate id: first wins
            rule(RULES[1], "bogus", "", ""),                     // invalid status
            rule(RULES[2], "not_reviewed", "", ""),              // untouched
        ];
        let Json(out) = call(&state, "owner", "author", STIG_ID, rules).await.unwrap();
        assert!(out.created);
        assert_eq!(out.results.len(), 3);
        assert_eq!(
            (out.applied_count, out.pending_count, out.unchanged_count, out.error_count),
            (1, 0, 1, 1)
        );
        let stored = db_checklists::list_rule_overrides(&pool, &out.checklist_id).await.unwrap();
        assert_eq!(stored.len(), out.applied_count);
        assert_eq!(stored[0].status, "open");

        // A second save reuses the checklist and finds nothing to change.
        let again = vec![rule(RULES[0], "open", "", "")];
        let Json(out2) = call(&state, "owner", "author", STIG_ID, again).await.unwrap();
        assert_eq!((out2.created, out2.checklist_id.as_str()), (false, out.checklist_id.as_str()));
        assert_eq!(out2.unchanged_count, 1);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_handler_routes_closing_through_approval_on_gated_assets(pool: PgPool) {
        base(&pool, true).await;
        let (state, _dir) = app_state(pool.clone());
        let rules = vec![rule(RULES[0], "not_a_finding", "why", "note")];
        let Json(out) = call(&state, "owner", "author", STIG_ID, rules).await.unwrap();
        assert_eq!((out.applied_count, out.pending_count, out.error_count), (0, 1, 0));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_approvals").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_handler_reports_per_rule_errors_and_writes_nothing_for_them(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        let long_id = "x".repeat(MAX_RULE_ID_BYTES + 1);
        let long_text = "y".repeat(MAX_TEXT_BYTES + 1);
        let rules = vec![
            rule("SV-unknown", "open", "", ""),
            rule(&long_id, "open", "", ""),
            rule(RULES[0], "open", &long_text, ""),
        ];
        let Json(out) = call(&state, "owner", "author", STIG_ID, rules).await.unwrap();
        assert_eq!((out.applied_count, out.error_count), (0, 3));
        let msgs: Vec<&str> = out.results.iter().map(|r| r.error.as_deref().unwrap()).collect();
        assert_eq!(
            msgs,
            [
                "rule is not part of this checklist's STIG",
                "rule id too long",
                "finding details or comments too long"
            ]
        );
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_rules").await, 0);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM rule_audit").await, 0);
    }

    async fn events(pool: &PgPool) -> Vec<(String, String, Option<String>, Option<String>, String)> {
        sqlx::query_as(
            "SELECT action, outcome, checklist_id, stig_id, detail::text FROM audit_events ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_records_create_and_save_events_and_the_creator(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        let rules = vec![rule(RULES[0], "open", "", ""), rule("SV-unknown", "open", "", "")];
        let Json(out) = call(&state, "owner", "author", STIG_ID, rules).await.unwrap();
        assert!(out.created);
        let by: Option<String> = sqlx::query_scalar("SELECT created_by FROM checklists WHERE id = $1")
            .bind(&out.checklist_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(by.as_deref(), Some("owner"));

        // A second save reuses the checklist: a save event, no second create event.
        let _ = call(&state, "owner", "author", STIG_ID, vec![rule(RULES[1], "open", "", "")]).await.unwrap();

        let ev = events(&pool).await;
        let kinds: Vec<(&str, &str)> = ev.iter().map(|e| (e.0.as_str(), e.1.as_str())).collect();
        assert_eq!(
            kinds,
            [("checklist.create", "ok"), ("checklist.save", "partial"), ("checklist.save", "ok")]
        );
        assert!(ev.iter().all(|e| e.2.as_deref() == Some(out.checklist_id.as_str())));
        assert!(ev.iter().all(|e| e.3.as_deref() == Some(STIG_ID)));
        let d = |i: usize| serde_json::from_str::<serde_json::Value>(&ev[i].4).unwrap();
        assert_eq!(d(0)["via"], "save");
        assert_eq!(d(1)["created"], true);
        assert_eq!((d(1)["applied"].as_i64(), d(1)["errors"].as_i64()), (Some(1), Some(1)));
        assert_eq!(d(1)["rejected"][0]["ruleId"], "SV-unknown");
        assert_eq!(d(2)["created"], false);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_records_denied_and_rejected_requests(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        call(&state, "other", "author", STIG_ID, vec![]).await.err();
        call(&state, "owner", "author", "../etc", vec![]).await.err();
        let too_many: Vec<SaveRule> = (0..=MAX_RULES).map(|i| rule(&format!("r{i}"), "open", "", "")).collect();
        call(&state, "owner", "author", STIG_ID, too_many).await.err();
        let extra: Vec<SaveRule> = (0..=RULES.len()).map(|i| rule(&format!("x{i}"), "open", "", "")).collect();
        call(&state, "owner", "author", STIG_ID, extra).await.err();
        // An unknown STIG is a 404 to the client, recorded as stig_unavailable.
        call(&state, "owner", "author", "NO-SUCH-STIG", vec![]).await.err();

        let ev = events(&pool).await;
        let got: Vec<(String, String)> = ev
            .iter()
            .map(|e| {
                let d: serde_json::Value = serde_json::from_str(&e.4).unwrap();
                (e.1.clone(), d["reason"].as_str().unwrap().to_string())
            })
            .collect();
        let want: Vec<(String, String)> = [
            ("denied", "forbidden"),
            ("rejected", "invalid_stig_id"),
            ("rejected", "too_many_rules"),
            ("rejected", "more_rules_than_stig"),
            ("rejected", "stig_unavailable"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        assert_eq!(got, want);
        // The malformed STIG id is not stored; valid ones are.
        assert_eq!(ev[1].3, None);
        assert_eq!(ev[2].3.as_deref(), Some(STIG_ID));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_event_detail_never_holds_request_text(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        let rules = vec![
            rule(RULES[0], "not_a_finding", "ZZ-RECOGNISABLE-DETAILS", "ZZ-RECOGNISABLE-COMMENT"),
            rule(RULES[1], "bogus", "ZZ-RECOGNISABLE-DETAILS", "ZZ-RECOGNISABLE-COMMENT"),
        ];
        let _ = call(&state, "owner", "author", STIG_ID, rules).await.unwrap();
        let ev = events(&pool).await;
        assert!(!ev.is_empty());
        for e in &ev {
            assert!(!e.4.contains("ZZ-RECOGNISABLE"), "detail leaked request text: {}", e.4);
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_still_succeeds_when_the_audit_event_cannot_be_written(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        sqlx::query("DROP TABLE audit_events").execute(&pool).await.unwrap();
        let Json(out) = call(&state, "owner", "author", STIG_ID, vec![rule(RULES[0], "open", "", "")])
            .await
            .unwrap();
        assert!(out.created);
        assert_eq!(out.applied_count, 1);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_rules").await, 1);
        assert_eq!(call(&state, "other", "author", STIG_ID, vec![]).await.err(), Some(StatusCode::FORBIDDEN));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_hostile_rule_ids_still_leave_save_event(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        let long = "x".repeat(300);
        let rules = vec![
            rule("\u{0}", "open", "", ""),
            rule("q\"b\\\n\t\u{7f}", "open", "", ""),
            rule(&long, "open", "", ""),
        ];
        let Json(out) = call(&state, "owner", "author", STIG_ID, rules).await.unwrap();
        assert_eq!(out.error_count, 3);
        let saves: Vec<_> = events(&pool).await.into_iter().filter(|e| e.0 == "checklist.save").collect();
        assert_eq!(saves.len(), 1);
        assert_eq!(saves[0].1, "partial");
        let d: serde_json::Value = serde_json::from_str(&saves[0].4).unwrap();
        assert_ne!(d, serde_json::json!({ "detailDropped": true }));
        let listed: Vec<&str> = d["rejected"].as_array().unwrap().iter().map(|r| r["ruleId"].as_str().unwrap()).collect();
        assert_eq!(listed, ["?", "q?b????", "x".repeat(64).as_str()]);
    }

    /// Relies on the current-thread runtime `#[sqlx::test]` uses (one `yield_now`
    /// lets the handler task reach its `tokio::spawn` before `abort()`).
    /// See the bulk-status twin: the future is dropped after its first poll;
    /// the checklist, the rule write, the create event and the save event must
    /// all still land.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_work_and_events_survive_the_handler_future_being_dropped(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        let st = state.clone();
        let h = tokio::spawn(async move {
            let _ = call(&st, "owner", "author", STIG_ID, vec![rule(RULES[0], "open", "", "")]).await;
        });
        tokio::task::yield_now().await;
        h.abort();
        let mut seen = 0i64;
        for _ in 0..200 {
            seen = count(&pool, "SELECT COUNT(*) FROM audit_events").await;
            if seen >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(seen, 2);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_rules").await, 1);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_with_a_huge_stig_id_leaves_events_without_the_value(pool: PgPool) {
        base(&pool, false).await;
        let (state, _dir) = app_state(pool.clone());
        let huge = "A".repeat(100_000);
        assert_eq!(call(&state, "other", "author", &huge, vec![]).await.err(), Some(StatusCode::FORBIDDEN));
        assert_eq!(call(&state, "owner", "author", &huge, vec![]).await.err(), Some(StatusCode::BAD_REQUEST));
        let ev: Vec<(String, Option<String>, String)> =
            sqlx::query_as("SELECT outcome, stig_id, detail->>'reason' FROM audit_events ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            ev,
            [
                ("denied".to_string(), None, "forbidden".to_string()),
                ("rejected".to_string(), None, "invalid_stig_id".to_string()),
            ]
        );
    }
}
