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
use crate::api::checklists::{is_valid_stig_id, load_stig_json, take_rules};
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

    let (checklist, created) = find_or_create(pool, &asset.id, &req.stig_id)
        .await
        .map_err(map_db)?;

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

/// Find the asset's checklist for a STIG, creating it when absent. A
/// concurrent creator is handled by the insert-if-absent plus a re-read, so
/// only a genuine failure surfaces as an error. The flag is true when this
/// call created the checklist.
async fn find_or_create(
    pool: &sqlx::PgPool,
    asset_id: &str,
    stig_id: &str,
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

    // ── Database-backed tests ──────────────────────────────────────────────

    use crate::test_fixtures::{app_state, auth, seed_asset, seed_checklist, seed_user, RULES, STIG_ID};
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

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_one_rejects_when_the_live_row_was_reopened(pool: PgPool) {
        base(&pool, true).await;
        seed_checklist(&pool, "c1", "a1", STIG_ID).await;
        db_checklists::upsert_rule(&pool, "c1", RULES[0], "not_a_finding", "d", "", "owner", None, None)
            .await
            .unwrap();
        // The caller read the rule as closed...
        let prev = db_checklists::list_rule_overrides(&pool, "c1").await.unwrap().remove(0);
        // ...then someone reopened it before the save wrote.
        db_checklists::upsert_rule(&pool, "c1", RULES[0], "open", "d", "", "owner", None, None)
            .await
            .unwrap();
        let audit_before = count(&pool, "SELECT COUNT(*) FROM rule_audit").await;

        let out = save_one(
            &pool,
            "c1",
            "owner",
            true,
            true,
            Some(&prev),
            &rule(RULES[0], "not_a_finding", "d", "new comment"),
        )
        .await;
        assert_eq!(out, Err("rule changed while saving; try again".to_string()));

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
        let out = save_one(
            &pool,
            "c1",
            "owner",
            true,
            true,
            None,
            &rule(RULES[0], "not_a_finding", "because", "reviewer note"),
        )
        .await
        .unwrap();
        assert_eq!(out.0, "pending_approval");
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
    async fn find_or_create_returns_the_existing_checklist(pool: PgPool) {
        base(&pool, false).await;
        seed_checklist(&pool, "orig", "a1", STIG_ID).await;
        let (c, created) = find_or_create(&pool, "a1", STIG_ID).await.unwrap();
        assert_eq!((c.id.as_str(), created), ("orig", false));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn find_or_create_creates_once_then_finds(pool: PgPool) {
        base(&pool, false).await;
        let (first, created) = find_or_create(&pool, "a1", STIG_ID).await.unwrap();
        assert!(created);
        let (again, created) = find_or_create(&pool, "a1", STIG_ID).await.unwrap();
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
            tasks.spawn(async move { find_or_create(&pool, "a1", STIG_ID).await });
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
}
