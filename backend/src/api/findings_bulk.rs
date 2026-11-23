//! `PATCH /api/findings/bulk`: apply one patch to many (checklist, rule)
//! targets, possibly across checklists.
//!
//! Authorisation is all-or-nothing: the caller needs write access (the same
//! `asset_acl::user_can` decision as the single-rule PATCH) on the asset of
//! every target, or nothing is written. After that every target goes through
//! the same gates as the single-rule PATCH and bulk-status
//! (`rule_bulk_status::plan_rule` / `apply_plans`): known-rule check,
//! finding-details gate, the approval workflow and the write-time
//! `expect_status` guard. Outcomes are reported per target.

use std::collections::{HashMap, HashSet};

use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sqlx::PgPool;

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::api::checklists::{load_stig_json, take_rules};
use crate::api::request_ctx::RequestCtx;
use crate::api::rule_bulk_status::{
    apply_plans, expected_status, has_nul, plan_rule, short_id, Plan, RuleOp,
    MAX_FINDING_DETAILS_BYTES, MAX_RULES, STATUS_PENDING_APPROVAL, VALID_STATUSES,
};
use crate::db_audit::{self, NewAuditEvent};
use crate::db_checklists::{self, ChecklistRuleRow};
use crate::AppState;

/// Tri-state for PATCH-style fields: absent (leave alone), null (clear), or
/// some new value. Encoded as `Option<Option<T>>`; serde's `default` makes a
/// missing field deserialize to `None`, while an explicit `null` lands as
/// `Some(None)` thanks to this helper.
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Longest checklist id looked up; anything else cannot exist.
const MAX_CHECKLIST_ID_BYTES: usize = 128;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkTarget {
    pub checklist_id: String,
    pub rule_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkPatch {
    pub status: Option<String>,
    /// Blank (or whitespace) is treated as absent: each target keeps its
    /// stored details.
    pub finding_details: Option<String>,
    pub comments: Option<String>,
    /// Tri-state: absent = leave each target's existing assignee alone,
    /// `Some(Some(uuid))` = reassign to that user, `Some(None)` = unassign
    /// (clear) the field.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub assignee_id: Option<Option<String>>,
    /// Tri-state with the same semantics as `assignee_id`.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub due_date: Option<Option<chrono::NaiveDate>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkRequest {
    pub targets: Vec<BulkTarget>,
    pub patch: BulkPatch,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BulkTargetError {
    pub checklist_id: String,
    pub rule_id: String,
    pub error: String,
}

/// Outcome counts are disjoint: `updated + pending_approval + already_pending
/// + error_count` is the number of distinct targets.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkResponse {
    /// Targets written directly.
    pub updated: usize,
    /// Targets newly submitted for approval.
    pub pending_approval: usize,
    /// Targets that already had a request pending.
    pub already_pending: usize,
    pub error_count: usize,
    pub errors: Vec<BulkTargetError>,
}

/// How one target is handled, decided without touching the database.
/// `prev` is the target's current override row, if any.
pub(crate) fn plan_target(
    known_rule: bool,
    prev: Option<&ChecklistRuleRow>,
    patch: &BulkPatch,
    requires_approval: bool,
) -> (Plan, Option<String>) {
    // Blank details mean "keep what is stored".
    let details = patch
        .finding_details
        .as_deref()
        .filter(|d| !d.trim().is_empty());
    match patch.status.as_deref() {
        Some(status) => (
            plan_rule(
                known_rule,
                prev,
                status,
                details.unwrap_or(""),
                requires_approval,
            ),
            expected_status(requires_approval, status, prev),
        ),
        None if !known_rule => (
            Plan::Reject("rule is not part of this checklist's STIG"),
            None,
        ),
        None => {
            let finding_details = details
                .map(str::to_string)
                .or_else(|| prev.map(|p| p.finding_details.clone()))
                .unwrap_or_default();
            (Plan::Apply { finding_details }, None)
        }
    }
}

/// PATCH /api/findings/bulk
///
/// The work (authorisation through the audit events) runs in a spawned task:
/// each chunk of each checklist commits on its own, so a client disconnect
/// that drops this future must not leave committed writes without their
/// audit events.
pub async fn bulk_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Json(req): Json<BulkRequest>,
) -> Result<Json<BulkResponse>, StatusCode> {
    let tasks = state.tasks.clone();
    crate::detached::run(&tasks, "findings bulk", bulk_work(state, user, ctx, req)).await?
}

/// Which patch keys the request carried (values are never recorded).
fn patch_fields(p: &BulkPatch) -> Vec<&'static str> {
    let mut f = Vec::new();
    if p.status.is_some() {
        f.push("status");
    }
    if p.finding_details.is_some() {
        f.push("findingDetails");
    }
    if p.comments.is_some() {
        f.push("comments");
    }
    if p.assignee_id.is_some() {
        f.push("assigneeId");
    }
    if p.due_date.is_some() {
        f.push("dueDate");
    }
    f
}

/// A checklist of the request resolved to its asset.
struct Resolved {
    asset_id: String,
    stig_id: String,
    requires_approval: bool,
}

/// The caller and request context, borrowed by the phase helpers so each
/// can emit the same audit events as the handler.
struct Actor<'a> {
    pool: &'a PgPool,
    user: &'a AuthUser,
    ctx: &'a RequestCtx,
    requested: usize,
}

impl Actor<'_> {
    async fn rejected(&self, reason: &'static str) {
        db_audit::record_or_log(
            self.pool,
            NewAuditEvent {
                user_id: &self.user.id,
                ctx: Some(self.ctx),
                action: "findings.bulk_update",
                outcome: "rejected",
                asset_id: None,
                checklist_id: None,
                stig_id: None,
                detail: json!({ "reason": reason, "requested": self.requested }),
            },
        )
        .await;
    }
}

/// First request-shape problem, in precedence order, if any.
fn bad_request_reason(req: &BulkRequest) -> Option<&'static str> {
    let patch = &req.patch;
    if req.targets.is_empty() {
        Some("no_targets")
    } else if patch
        .status
        .as_deref()
        .is_some_and(|s| !VALID_STATUSES.contains(&s))
    {
        // The submitted status text is not echoed: it is not a known value.
        Some("invalid_status")
    } else if req.targets.len() > MAX_RULES {
        Some("too_many_targets")
    } else if patch
        .finding_details
        .as_deref()
        .is_some_and(|t| t.len() > MAX_FINDING_DETAILS_BYTES)
    {
        Some("finding_details_too_long")
    } else if patch.finding_details.as_deref().is_some_and(has_nul) {
        Some("finding_details_invalid")
    } else if patch
        .comments
        .as_deref()
        .is_some_and(|t| t.len() > MAX_FINDING_DETAILS_BYTES)
    {
        Some("comments_too_long")
    } else if patch.comments.as_deref().is_some_and(has_nul) {
        Some("comments_invalid")
    } else {
        None
    }
}

/// Resolve every target's checklist to its asset in one query. Ids that
/// cannot exist (NUL, over-long) are never sent to the database.
async fn resolve_checklists(
    pool: &PgPool,
    targets: &[BulkTarget],
) -> Result<HashMap<String, Resolved>, StatusCode> {
    let lookup_ids: Vec<&str> = targets
        .iter()
        .map(|t| t.checklist_id.as_str())
        .filter(|id| id.len() <= MAX_CHECKLIST_ID_BYTES && !has_nul(id))
        .collect();
    let rows: Vec<(String, String, String, bool)> = sqlx::query_as(
        "SELECT c.id, c.asset_id, c.stig_id, a.requires_approval \
         FROM checklists c JOIN assets a ON a.id = c.asset_id \
         WHERE c.id = ANY($1)",
    )
    .bind(&lookup_ids)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!("findings bulk checklist lookup failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(rows
        .into_iter()
        .map(|(id, asset_id, stig_id, requires_approval)| {
            (
                id,
                Resolved {
                    asset_id,
                    stig_id,
                    requires_approval,
                },
            )
        })
        .collect())
}

/// Request-order walk; the write check runs lazily, once per distinct
/// asset, and the first unknown or forbidden target ends the request.
async fn authorize_targets(
    actor: &Actor<'_>,
    targets: &[BulkTarget],
    resolved: &HashMap<String, Resolved>,
) -> Result<(), StatusCode> {
    let mut can_write: HashMap<&str, bool> = HashMap::new();
    for t in targets {
        let Some(r) = resolved.get(&t.checklist_id) else {
            actor.rejected("unknown_checklist").await;
            return Err(StatusCode::NOT_FOUND);
        };
        let ok = match can_write.get(r.asset_id.as_str()) {
            Some(v) => *v,
            None => {
                let v = asset_acl::user_can(actor.pool, &r.asset_id, actor.user, "write").await;
                can_write.insert(r.asset_id.as_str(), v);
                v
            }
        };
        if !ok {
            db_audit::record_or_log(
                actor.pool,
                NewAuditEvent {
                    user_id: &actor.user.id,
                    ctx: Some(actor.ctx),
                    action: "findings.bulk_update",
                    outcome: "denied",
                    asset_id: Some(&r.asset_id),
                    checklist_id: Some(&t.checklist_id),
                    stig_id: Some(&r.stig_id),
                    detail: json!({ "reason": "forbidden", "requested": actor.requested }),
                },
            )
            .await;
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(())
}

/// An unknown assignee would fail every chunk on the foreign key.
async fn check_assignee(actor: &Actor<'_>, patch: &BulkPatch) -> Result<(), StatusCode> {
    if let Some(Some(assignee)) = &patch.assignee_id {
        let exists = if assignee.len() > MAX_CHECKLIST_ID_BYTES || has_nul(assignee) {
            false
        } else {
            sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
                .bind(assignee)
                .fetch_one(actor.pool)
                .await
                .map_err(|e| {
                    tracing::error!("findings bulk assignee lookup failed: {e:#}");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
        };
        if !exists {
            actor.rejected("unknown_assignee").await;
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    Ok(())
}

/// Group the distinct targets by checklist, in first-seen order.
fn group_targets(targets: &[BulkTarget]) -> Vec<(&str, Vec<&str>)> {
    let mut groups: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut group_of: HashMap<&str, usize> = HashMap::new();
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for t in targets {
        if !seen.insert((t.checklist_id.as_str(), t.rule_id.as_str())) {
            continue;
        }
        let i = *group_of.entry(t.checklist_id.as_str()).or_insert_with(|| {
            groups.push((t.checklist_id.as_str(), Vec::new()));
            groups.len() - 1
        });
        groups[i].1.push(t.rule_id.as_str());
    }
    groups
}

/// The rule ids of a STIG, or `None` when the STIG cannot be loaded.
async fn known_rule_ids(
    state: &AppState,
    stig_id: &str,
    checklist_id: &str,
) -> Option<HashSet<String>> {
    match load_stig_json(state, stig_id).await {
        Ok(mut v) => Some(
            take_rules(&mut v)
                .iter()
                .filter_map(|x| x.get("id").and_then(|v| v.as_str()).map(str::to_string))
                .collect::<HashSet<String>>(),
        ),
        Err(code) => {
            tracing::warn!(
                "findings bulk: STIG {stig_id} unavailable ({code}) for checklist {checklist_id}"
            );
            None
        }
    }
}

/// Per-target result of one checklist: Ok(applied status, note) or Err(reason).
type TargetResult = Result<(&'static str, bool), String>;

async fn apply_group(
    pool: &PgPool,
    user_id: &str,
    checklist_id: &str,
    rule_ids: &[&str],
    known: Option<&HashSet<String>>,
    requires_approval: bool,
    patch: &BulkPatch,
) -> Vec<TargetResult> {
    let Some(known) = known else {
        return rule_ids
            .iter()
            .map(|_| Err("STIG unavailable for this checklist".to_string()))
            .collect();
    };
    let existing = match db_checklists::list_rule_overrides(pool, checklist_id).await {
        Err(e) => {
            tracing::error!("findings bulk rule snapshot failed: {e:#}");
            return rule_ids
                .iter()
                .map(|_| Err("failed to read checklist state".to_string()))
                .collect();
        }
        Ok(existing) => existing,
    };
    let existing: HashMap<String, ChecklistRuleRow> = existing
        .into_iter()
        .map(|r| (r.rule_id.clone(), r))
        .collect();
    let planned: Vec<(Plan, Option<String>)> = rule_ids
        .iter()
        .map(|id| {
            plan_target(
                known.contains(*id),
                existing.get(*id),
                patch,
                requires_approval,
            )
        })
        .collect();
    let (plans, expects): (Vec<Plan>, Vec<Option<String>>) = planned.into_iter().unzip();
    let ops: Vec<RuleOp<'_>> = rule_ids
        .iter()
        .zip(plans)
        .zip(&expects)
        .map(|((&rule_id, plan), expect)| RuleOp {
            rule_id,
            status: patch.status.as_deref().unwrap_or(""),
            write_status: patch.status.is_some(),
            expect_status: expect.as_deref(),
            finding_details: patch
                .finding_details
                .as_deref()
                .filter(|d| !d.trim().is_empty()),
            comments: patch.comments.as_deref(),
            assignee_id: patch.assignee_id.as_ref().map(|o| o.as_deref()),
            due_date: patch.due_date,
            plan,
        })
        .collect();
    apply_plans(pool, checklist_id, user_id, &ops)
        .await
        .into_iter()
        .map(|o| o.map(|a| (a.status, a.note.is_some())))
        .collect()
}

/// Counts and rejected targets of one checklist.
struct GroupTally {
    requested: usize,
    applied: usize,
    queued: usize,
    already: usize,
    errors: usize,
    rejected: Vec<(String, String)>,
}

/// Fold per-target results into counts, pushing each error onto `errors_out`.
fn tally_group(
    checklist_id: &str,
    rule_ids: &[&str],
    results: Vec<TargetResult>,
    errors_out: &mut Vec<BulkTargetError>,
) -> GroupTally {
    let mut t = GroupTally {
        requested: rule_ids.len(),
        applied: 0,
        queued: 0,
        already: 0,
        errors: 0,
        rejected: Vec::new(),
    };
    for (rule_id, res) in rule_ids.iter().zip(results) {
        match res {
            Ok((STATUS_PENDING_APPROVAL, true)) => t.already += 1,
            Ok((STATUS_PENDING_APPROVAL, false)) => t.queued += 1,
            Ok(_) => t.applied += 1,
            Err(error) => {
                t.errors += 1;
                t.rejected.push((short_id(rule_id), error.clone()));
                errors_out.push(BulkTargetError {
                    checklist_id: checklist_id.to_string(),
                    rule_id: short_id(rule_id),
                    error,
                });
            }
        }
    }
    t
}

/// Audit one checklist's outcome: the log line is the fallback when the
/// durable write fails.
async fn record_group(
    actor: &Actor<'_>,
    r: &Resolved,
    checklist_id: &str,
    patch: &BulkPatch,
    fields: &[&'static str],
    tally: &GroupTally,
    checklists_in_request: usize,
) {
    let GroupTally {
        requested,
        applied,
        queued,
        already,
        errors,
        rejected,
    } = tally;
    tracing::info!(
        target: "audit",
        user_id = %actor.user.id,
        asset_id = %r.asset_id,
        stig_id = %r.stig_id,
        checklist_id = %checklist_id,
        applied,
        pending = queued + already,
        already_pending = already,
        errors,
        "findings bulk update"
    );
    let (rejected_list, rejected_truncated) = db_audit::rejected_detail(rejected);
    db_audit::record_or_log(
        actor.pool,
        NewAuditEvent {
            user_id: &actor.user.id,
            ctx: Some(actor.ctx),
            action: "findings.bulk_update",
            outcome: if *errors > 0 { "partial" } else { "ok" },
            asset_id: Some(&r.asset_id),
            checklist_id: Some(checklist_id),
            stig_id: Some(&r.stig_id),
            detail: json!({
                "targetStatus": patch.status,
                "fields": fields,
                "requested": requested,
                "applied": applied,
                // As in bulk-status, `pending` includes `alreadyPending`;
                // the response counts are disjoint.
                "pending": queued + already,
                "alreadyPending": already,
                "errors": errors,
                "rejected": rejected_list,
                "rejectedTruncated": rejected_truncated,
                "checklistsInRequest": checklists_in_request,
            }),
        },
    )
    .await;
}

async fn bulk_work(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    req: BulkRequest,
) -> Result<Json<BulkResponse>, StatusCode> {
    let pool = state.pool.as_ref();
    let actor = Actor {
        pool,
        user: &user,
        ctx: &ctx,
        requested: req.targets.len(),
    };
    let patch = &req.patch;
    if let Some(reason) = bad_request_reason(&req) {
        actor.rejected(reason).await;
        return Err(StatusCode::BAD_REQUEST);
    }
    let resolved = resolve_checklists(pool, &req.targets).await?;
    authorize_targets(&actor, &req.targets, &resolved).await?;
    check_assignee(&actor, patch).await?;

    let groups = group_targets(&req.targets);
    let fields = patch_fields(patch);
    let mut response = BulkResponse {
        updated: 0,
        pending_approval: 0,
        already_pending: 0,
        error_count: 0,
        errors: Vec::new(),
    };
    let mut stigs: HashMap<String, Option<HashSet<String>>> = HashMap::new();
    for (checklist_id, rule_ids) in &groups {
        let Some(r) = resolved.get(*checklist_id) else {
            continue;
        };
        if !stigs.contains_key(&r.stig_id) {
            let known = known_rule_ids(&state, &r.stig_id, checklist_id).await;
            stigs.insert(r.stig_id.clone(), known);
        }
        let known = stigs.get(&r.stig_id).and_then(Option::as_ref);
        let results = apply_group(
            pool,
            &user.id,
            checklist_id,
            rule_ids,
            known,
            r.requires_approval,
            patch,
        )
        .await;
        let tally = tally_group(checklist_id, rule_ids, results, &mut response.errors);
        response.updated += tally.applied;
        response.pending_approval += tally.queued;
        response.already_pending += tally.already;
        response.error_count += tally.errors;
        record_group(
            &actor,
            r,
            checklist_id,
            patch,
            &fields,
            &tally,
            groups.len(),
        )
        .await;
    }

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{
        app_state, auth, fail_writes_of, seed_acl, seed_asset, seed_checklist, seed_rule,
        seed_user, RULES, STIG_ID,
    };
    use sqlx::PgPool;

    fn row(status: &str, details: &str) -> ChecklistRuleRow {
        ChecklistRuleRow {
            checklist_id: "c".into(),
            rule_id: "r".into(),
            status: status.into(),
            finding_details: details.into(),
            comments: String::new(),
            updated_at: chrono::Utc::now(),
            updated_by: None,
            assignee_id: None,
            due_date: None,
        }
    }

    fn patch(v: serde_json::Value) -> BulkPatch {
        serde_json::from_value(v).unwrap()
    }

    // ── phase helpers ───────────────────────────────────────────────────────

    fn request(v: serde_json::Value) -> BulkRequest {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn bad_request_reason_follows_precedence() {
        let t = json!([{ "checklistId": "c", "ruleId": "r" }]);
        assert_eq!(
            bad_request_reason(&request(
                json!({ "targets": [], "patch": { "status": "bogus" } })
            )),
            Some("no_targets")
        );
        assert_eq!(
            bad_request_reason(&request(
                json!({ "targets": t, "patch": { "status": "bogus" } })
            )),
            Some("invalid_status")
        );
        let many: Vec<_> = (0..=MAX_RULES)
            .map(|i| json!({ "checklistId": "c", "ruleId": format!("r{i}") }))
            .collect();
        assert_eq!(
            bad_request_reason(&request(
                json!({ "targets": many, "patch": { "status": "bogus" } })
            )),
            Some("invalid_status")
        );
        assert_eq!(
            bad_request_reason(&request(json!({ "targets": many, "patch": {} }))),
            Some("too_many_targets")
        );
        assert_eq!(
            bad_request_reason(&request(
                json!({ "targets": t, "patch": { "comments": "a\u{0}b" } })
            )),
            Some("comments_invalid")
        );
        assert_eq!(
            bad_request_reason(&request(
                json!({ "targets": t, "patch": { "comments": "ok" } })
            )),
            None
        );
    }

    #[test]
    fn group_targets_drops_duplicates_and_keeps_first_seen_order() {
        let r = request(json!({ "targets": [
            { "checklistId": "b", "ruleId": "r1" },
            { "checklistId": "a", "ruleId": "r1" },
            { "checklistId": "b", "ruleId": "r2" },
            { "checklistId": "b", "ruleId": "r1" },
        ], "patch": {} }));
        assert_eq!(
            group_targets(&r.targets),
            vec![("b", vec!["r1", "r2"]), ("a", vec!["r1"])]
        );
    }

    #[test]
    fn tally_group_counts_are_disjoint_and_errors_are_shortened() {
        let long = "x".repeat(100);
        let rule_ids = ["a", "b", "c", "d", long.as_str()];
        let results: Vec<TargetResult> = vec![
            Ok((STATUS_PENDING_APPROVAL, true)),
            Ok((STATUS_PENDING_APPROVAL, false)),
            Ok(("applied", false)),
            Ok(("applied", true)),
            Err("nope".into()),
        ];
        let mut errors = Vec::new();
        let t = tally_group("c1", &rule_ids, results, &mut errors);
        assert_eq!(
            (t.requested, t.applied, t.queued, t.already, t.errors),
            (5, 2, 1, 1, 1)
        );
        assert_eq!(t.rejected, vec![("x".repeat(64), "nope".to_string())]);
        assert_eq!(
            errors,
            vec![BulkTargetError {
                checklist_id: "c1".into(),
                rule_id: "x".repeat(64),
                error: "nope".into(),
            }]
        );
    }

    // ── plan_target ─────────────────────────────────────────────────────────

    #[test]
    fn plan_target_with_status_uses_the_shared_gates() {
        let p = patch(json!({ "status": "not_a_finding", "findingDetails": "why" }));
        assert_eq!(
            plan_target(true, None, &p, false),
            (
                Plan::Apply {
                    finding_details: "why".into()
                },
                None
            )
        );
        assert_eq!(
            plan_target(true, None, &p, true),
            (
                Plan::RequestApproval {
                    finding_details: "why".into()
                },
                None
            )
        );
        let closed = row("not_a_finding", "old");
        assert_eq!(
            plan_target(true, Some(&closed), &p, true),
            (
                Plan::Apply {
                    finding_details: "why".into()
                },
                Some("not_a_finding".into())
            )
        );
        assert!(matches!(
            plan_target(false, None, &p, false).0,
            Plan::Reject(_)
        ));
        let blank = patch(json!({ "status": "not_a_finding", "findingDetails": "  " }));
        assert!(matches!(
            plan_target(true, None, &blank, false).0,
            Plan::Reject(_)
        ));
    }

    #[test]
    fn plan_target_without_status_keeps_stored_details_and_rejects_unknown_rules() {
        let stored = row("not_a_finding", "kept");
        let blank = patch(json!({ "findingDetails": "   ", "comments": "c" }));
        assert_eq!(
            plan_target(true, Some(&stored), &blank, true),
            (
                Plan::Apply {
                    finding_details: "kept".into()
                },
                None
            )
        );
        let set = patch(json!({ "findingDetails": "new" }));
        assert_eq!(
            plan_target(true, Some(&stored), &set, true).0,
            Plan::Apply {
                finding_details: "new".into()
            }
        );
        assert!(matches!(
            plan_target(false, None, &set, false).0,
            Plan::Reject(_)
        ));
        assert_eq!(
            plan_target(true, None, &patch(json!({})), false).0,
            Plan::Apply {
                finding_details: String::new()
            }
        );
    }

    // ── Database-backed tests ───────────────────────────────────────────────

    /// Users owner/other/root, asset a1 (owner, `gated`) with checklist c1,
    /// asset a2 (owner, ungated) with checklist c2.
    async fn setup(pool: &PgPool, gated: bool) -> (AppState, crate::test_fixtures::StigDir) {
        for u in ["owner", "other", "root"] {
            seed_user(pool, u).await;
        }
        seed_asset(pool, "a1", "owner", gated).await;
        seed_checklist(pool, "c1", "a1", STIG_ID).await;
        seed_asset(pool, "a2", "owner", false).await;
        seed_checklist(pool, "c2", "a2", STIG_ID).await;
        app_state(pool.clone())
    }

    fn targets(list: &[(&str, &str)]) -> serde_json::Value {
        json!(list
            .iter()
            .map(|(c, r)| json!({ "checklistId": c, "ruleId": r }))
            .collect::<Vec<_>>())
    }

    async fn call_as(
        state: &AppState,
        user: &str,
        role: &str,
        targets: serde_json::Value,
        patch: serde_json::Value,
    ) -> Result<BulkResponse, StatusCode> {
        let req: BulkRequest =
            serde_json::from_value(json!({ "targets": targets, "patch": patch })).unwrap();
        bulk_handler(
            State(state.clone()),
            Extension(auth(user, role)),
            Extension(crate::test_fixtures::ctx()),
            Json(req),
        )
        .await
        .map(|j| j.0)
    }

    async fn call(
        state: &AppState,
        targets: serde_json::Value,
        patch: serde_json::Value,
    ) -> Result<BulkResponse, StatusCode> {
        call_as(state, "owner", "author", targets, patch).await
    }

    async fn count(pool: &PgPool, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
    }

    async fn rule(
        pool: &PgPool,
        checklist: &str,
        rule_id: &str,
    ) -> Option<(String, String, String)> {
        sqlx::query_as(
            "SELECT status, finding_details, comments FROM checklist_rules WHERE checklist_id = $1 AND rule_id = $2",
        )
        .bind(checklist)
        .bind(rule_id)
        .fetch_optional(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_keeps_its_400_403_and_404_paths(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let t = targets(&[("c1", RULES[0])]);
        assert_eq!(
            call(&state, json!([]), json!({ "status": "open" }))
                .await
                .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&state, t.clone(), json!({ "status": "bogus" }))
                .await
                .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &state,
                targets(&[("nope", RULES[0])]),
                json!({ "status": "open" })
            )
            .await
            .unwrap_err(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(
                &state,
                targets(&[("bad\u{0}id", RULES[0])]),
                json!({ "status": "open" })
            )
            .await
            .unwrap_err(),
            StatusCode::NOT_FOUND
        );
        let long = "c".repeat(MAX_CHECKLIST_ID_BYTES + 1);
        assert_eq!(
            call(
                &state,
                targets(&[(long.as_str(), RULES[0])]),
                json!({ "status": "open" })
            )
            .await
            .unwrap_err(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call_as(
                &state,
                "other",
                "author",
                t.clone(),
                json!({ "status": "open" })
            )
            .await
            .unwrap_err(),
            StatusCode::FORBIDDEN
        );
        // New shared-value 400s.
        let many: Vec<(&str, &str)> = (0..MAX_RULES + 1).map(|_| ("c1", RULES[0])).collect();
        assert_eq!(
            call(&state, targets(&many), json!({ "status": "open" }))
                .await
                .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&state, t.clone(), json!({ "comments": "a\u{0}b" }))
                .await
                .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&state, t.clone(), json!({ "findingDetails": "a\u{0}b" }))
                .await
                .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        let big_comments = "x".repeat(MAX_FINDING_DETAILS_BYTES + 1);
        assert_eq!(
            call(&state, t.clone(), json!({ "comments": big_comments }))
                .await
                .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        let big = "x".repeat(MAX_FINDING_DETAILS_BYTES + 1);
        assert_eq!(
            call(&state, t.clone(), json!({ "findingDetails": big }))
                .await
                .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_rules").await,
            0
        );
        assert_eq!(
            call(&state, t, json!({ "status": "open" }))
                .await
                .unwrap()
                .updated,
            1
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_writes_nothing_when_one_target_is_forbidden(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        seed_asset(&pool, "a3", "other", false).await;
        seed_checklist(&pool, "c3", "a3", STIG_ID).await;
        let t = targets(&[("c1", RULES[0]), ("c3", RULES[0]), ("c2", RULES[0])]);
        assert_eq!(
            call(&state, t, json!({ "status": "open" }))
                .await
                .unwrap_err(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_rules").await,
            0
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_allows_an_acl_writer_and_an_admin_and_forbids_read_acl(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let t = targets(&[("c1", RULES[0])]);
        let p = json!({ "status": "open" });
        seed_acl(&pool, "a1", "other", "read").await;
        assert_eq!(
            call_as(&state, "other", "author", t.clone(), p.clone())
                .await
                .unwrap_err(),
            StatusCode::FORBIDDEN
        );
        sqlx::query("UPDATE asset_acl SET permission = 'write' WHERE user_id = 'other'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            call_as(&state, "other", "author", t.clone(), p.clone())
                .await
                .unwrap()
                .updated,
            1
        );
        assert_eq!(
            call_as(&state, "root", "admin", targets(&[("c2", RULES[0])]), p)
                .await
                .unwrap()
                .updated,
            1
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_queues_closing_on_gated_assets_and_counts_separately(pool: PgPool) {
        let (state, _d) = setup(&pool, true).await;
        let t = targets(&[("c1", RULES[0]), ("c1", RULES[1]), ("c2", RULES[0])]);
        let p = json!({ "status": "not_a_finding", "findingDetails": "why" });
        let r = call(&state, t.clone(), p.clone()).await.unwrap();
        assert_eq!(
            (
                r.updated,
                r.pending_approval,
                r.already_pending,
                r.error_count
            ),
            (1, 2, 0, 0)
        );
        assert_eq!(rule(&pool, "c1", RULES[0]).await, None);
        assert_eq!(
            rule(&pool, "c2", RULES[0]).await.unwrap().0,
            "not_a_finding"
        );
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM finding_approvals WHERE status = 'pending'"
            )
            .await,
            2
        );
        let r = call(&state, t, p).await.unwrap();
        assert_eq!(
            (
                r.updated,
                r.pending_approval,
                r.already_pending,
                r.error_count
            ),
            (1, 0, 2, 0)
        );
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM finding_approvals").await,
            2
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_applies_assignee_due_and_comments_to_queued_rules(pool: PgPool) {
        let (state, _d) = setup(&pool, true).await;
        let r = call(
            &state,
            targets(&[("c1", RULES[0])]),
            json!({
                "status": "not_a_finding", "findingDetails": "why", "comments": "cc",
                "assigneeId": "other", "dueDate": "2031-05-06"
            }),
        )
        .await
        .unwrap();
        assert_eq!(r.pending_approval, 1);
        let row: (
            String,
            String,
            String,
            Option<String>,
            Option<chrono::NaiveDate>,
        ) = sqlx::query_as(
            "SELECT status, finding_details, comments, assignee_id, due_date FROM checklist_rules",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "not_reviewed");
        assert_eq!(row.1, "");
        assert_eq!(row.2, "cc");
        assert_eq!(row.3.as_deref(), Some("other"));
        assert_eq!(row.4.map(|d| d.to_string()).as_deref(), Some("2031-05-06"));
        let audit: Vec<(String, Option<String>, Option<String>)> =
            sqlx::query_as("SELECT field, from_value, to_value FROM rule_audit ORDER BY field")
                .fetch_all(&pool)
                .await
                .unwrap();
        let norm = |v: &Option<String>| v.clone().unwrap_or_default();
        assert_eq!(audit.len(), 3);
        assert_eq!(
            (
                audit[0].0.as_str(),
                norm(&audit[0].1).as_str(),
                norm(&audit[0].2).as_str()
            ),
            ("assignee_id", "", "other")
        );
        assert_eq!(
            (
                audit[1].0.as_str(),
                norm(&audit[1].1).as_str(),
                norm(&audit[1].2).as_str()
            ),
            ("comments", "", "cc")
        );
        assert_eq!(
            (
                audit[2].0.as_str(),
                norm(&audit[2].1).as_str(),
                norm(&audit[2].2).as_str()
            ),
            ("due_date", "", "2031-05-06")
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_assignee_and_due_date_are_tri_state(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let t = targets(&[("c1", RULES[0])]);
        let get = || async {
            sqlx::query_as::<_, (Option<String>, Option<chrono::NaiveDate>)>(
                "SELECT assignee_id, due_date FROM checklist_rules",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        call(
            &state,
            t.clone(),
            json!({ "assigneeId": "other", "dueDate": "2031-05-06" }),
        )
        .await
        .unwrap();
        assert!(get().await.0.is_some() && get().await.1.is_some());
        // Absent keeps both.
        call(&state, t.clone(), json!({ "comments": "x" }))
            .await
            .unwrap();
        assert!(get().await.0.is_some() && get().await.1.is_some());
        // Explicit null clears.
        call(&state, t.clone(), json!({ "assigneeId": null }))
            .await
            .unwrap();
        let (a, d) = get().await;
        assert!(a.is_none() && d.is_some());
        call(&state, t, json!({ "dueDate": null })).await.unwrap();
        assert_eq!(get().await, (None, None));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_closing_without_details_is_a_per_target_error(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        seed_rule(&pool, "c1", RULES[1], "open", "documented", "", "owner").await;
        let t = targets(&[("c1", RULES[0]), ("c1", RULES[1])]);
        let r = call(&state, t, json!({ "status": "not_a_finding" }))
            .await
            .unwrap();
        assert_eq!((r.updated, r.error_count), (1, 1));
        assert_eq!(
            r.errors,
            [BulkTargetError {
                checklist_id: "c1".into(),
                rule_id: RULES[0].into(),
                error: "finding details required for this status".into()
            }]
        );
        assert_eq!(rule(&pool, "c1", RULES[0]).await, None);
        assert_eq!(
            rule(&pool, "c1", RULES[1]).await.unwrap().0,
            "not_a_finding"
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_blank_finding_details_keeps_stored_text(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        seed_rule(
            &pool,
            "c1",
            RULES[0],
            "not_a_finding",
            "justification",
            "",
            "owner",
        )
        .await;
        let t = targets(&[("c1", RULES[0])]);
        call(
            &state,
            t.clone(),
            json!({ "findingDetails": "   ", "comments": "note" }),
        )
        .await
        .unwrap();
        let row = rule(&pool, "c1", RULES[0]).await.unwrap();
        assert_eq!((row.1.as_str(), row.2.as_str()), ("justification", "note"));
        call(
            &state,
            t,
            json!({ "status": "not_applicable", "findingDetails": "" }),
        )
        .await
        .unwrap();
        assert_eq!(
            rule(&pool, "c1", RULES[0]).await.unwrap().1,
            "justification"
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_unknown_rule_is_an_error_and_inserts_nothing(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let r = call(
            &state,
            targets(&[("c1", "SV-bogus"), ("c1", RULES[0])]),
            json!({ "status": "open" }),
        )
        .await
        .unwrap();
        assert_eq!((r.updated, r.error_count), (1, 1));
        assert_eq!(
            r.errors[0].error,
            "rule is not part of this checklist's STIG"
        );
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_rules").await,
            1
        );
        // A text-only patch is checked too.
        let r = call(
            &state,
            targets(&[("c1", "SV-bogus2")]),
            json!({ "comments": "x" }),
        )
        .await
        .unwrap();
        assert_eq!(r.error_count, 1);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_rules").await,
            1
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_unknown_assignee_is_400_and_writes_nothing(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let r = call(
            &state,
            targets(&[("c1", RULES[0])]),
            json!({ "assigneeId": "ghost" }),
        )
        .await;
        assert_eq!(r.unwrap_err(), StatusCode::BAD_REQUEST);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_rules").await,
            0
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_failed_chunk_is_reported_not_500(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        fail_writes_of(&pool, "checklist_rules", &[RULES[0]]).await;
        let t = targets(&[("c1", RULES[0]), ("c2", RULES[1])]);
        let r = call(&state, t, json!({ "status": "open" })).await.unwrap();
        assert_eq!((r.updated, r.error_count), (1, 1));
        assert_eq!(r.errors[0].checklist_id, "c1");
        assert_eq!(r.errors[0].error, "failed to save");
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM audit_events WHERE outcome = 'partial'"
            )
            .await,
            1
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_records_one_event_per_checklist(pool: PgPool) {
        let (state, _d) = setup(&pool, true).await;
        let t = targets(&[
            ("c1", RULES[0]),
            ("c2", RULES[0]),
            ("c2", RULES[1]),
            ("c1", RULES[0]),
        ]);
        call(
            &state,
            t,
            json!({ "status": "not_a_finding", "findingDetails": "why", "comments": "c" }),
        )
        .await
        .unwrap();
        let ev: Vec<(String, String, String, String, serde_json::Value)> = sqlx::query_as(
            "SELECT action, outcome, asset_id, checklist_id, detail FROM audit_events ORDER BY checklist_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(
            (
                ev[0].0.as_str(),
                ev[0].1.as_str(),
                ev[0].2.as_str(),
                ev[0].3.as_str()
            ),
            ("findings.bulk_update", "ok", "a1", "c1")
        );
        assert_eq!(ev[0].4["pending"], 1);
        assert_eq!(ev[0].4["requested"], 1);
        assert_eq!(ev[0].4["checklistsInRequest"], 2);
        assert_eq!(ev[0].4["targetStatus"], "not_a_finding");
        assert_eq!(
            ev[0].4["fields"],
            json!(["status", "findingDetails", "comments"])
        );
        assert_eq!((ev[1].2.as_str(), ev[1].3.as_str()), ("a2", "c2"));
        assert_eq!(ev[1].4["applied"], 2);
        let stig: Vec<Option<String>> = sqlx::query_scalar("SELECT stig_id FROM audit_events")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert!(stig.iter().all(|s| s.as_deref() == Some(STIG_ID)));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_records_denied_and_rejected_events(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let t = targets(&[("c1", RULES[0])]);
        let _ = call_as(
            &state,
            "other",
            "author",
            t.clone(),
            json!({ "status": "open" }),
        )
        .await;
        let _ = call(&state, t.clone(), json!({ "status": "BOGUSSTATUS" })).await;
        let _ = call(&state, t.clone(), json!({ "assigneeId": "ghost" })).await;
        let _ = call(
            &state,
            targets(&[("nope", RULES[0])]),
            json!({ "status": "open" }),
        )
        .await;
        let ev: Vec<(String, Option<String>, serde_json::Value)> =
            sqlx::query_as("SELECT outcome, checklist_id, detail FROM audit_events ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(ev.len(), 4);
        assert!(!ev
            .iter()
            .any(|e| e.2.to_string().contains("BOGUSSTATUS") || e.2.to_string().contains("nope")));
        assert_eq!(ev[3].2["reason"], "unknown_checklist");
        assert_eq!(
            (
                ev[0].0.as_str(),
                ev[0].1.as_deref(),
                ev[0].2["reason"].as_str()
            ),
            ("denied", Some("c1"), Some("forbidden"))
        );
        assert_eq!(
            (
                ev[1].0.as_str(),
                ev[1].1.as_deref(),
                ev[1].2["reason"].as_str()
            ),
            ("rejected", None, Some("invalid_status"))
        );
        assert_eq!(ev[2].2["reason"], "unknown_assignee");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_event_detail_never_holds_request_text(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let r = call(
            &state,
            targets(&[("c1", "SECRETRULE"), ("c1", RULES[0])]),
            json!({ "status": "not_a_finding", "findingDetails": "SECRETDETAIL", "comments": "SECRETCOMMENT" }),
        )
        .await
        .unwrap();
        assert_eq!(r.error_count, 1);
        let detail: String = sqlx::query_scalar("SELECT detail::text FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        for leak in ["SECRETDETAIL", "SECRETCOMMENT"] {
            assert!(!detail.contains(leak), "detail leaks {leak}: {detail}");
        }
    }

    /// Drops the handler future once its task is spawned.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_work_and_events_survive_the_handler_future_being_dropped(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        crate::detached::abort_once_spawned(
            &state.tasks,
            call(
                &state,
                targets(&[("c1", RULES[0]), ("c2", RULES[0])]),
                json!({ "status": "open" }),
            ),
        )
        .await;
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM audit_events").await, 2);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_rules").await,
            2
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn findings_bulk_unavailable_stig_fails_only_that_checklist(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        // A second STIG id that has no file; c3 on a2 uses it.
        sqlx::query(
            "INSERT INTO checklists (id, asset_id, stig_id) VALUES ('c3', 'a2', 'MISSING-STIG')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let t = targets(&[
            ("c3", RULES[0]),
            ("c3", RULES[1]),
            ("c3", RULES[0]),
            ("c1", RULES[0]),
        ]);
        let r = call(&state, t, json!({ "status": "open" })).await.unwrap();
        assert_eq!((r.updated, r.error_count), (1, 2));
        assert!(r
            .errors
            .iter()
            .all(|e| e.checklist_id == "c3" && e.error == "STIG unavailable for this checklist"));
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_rules WHERE checklist_id = 'c3'"
            )
            .await,
            0
        );
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_rules WHERE checklist_id = 'c1'"
            )
            .await,
            1
        );
    }
}
