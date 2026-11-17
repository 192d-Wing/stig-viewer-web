//! Bulk rule update from a CSV upload.
//!
//! Every row goes through the same gates as the single-rule PATCH and
//! bulk-status (`rule_bulk_status::plan_rule` / `apply_plans`): the known-rule
//! check, the finding-details gate, the per-asset approval workflow and the
//! write-time `expect_status` guard. Failures are reported per row.

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::api::checklists::{load_stig_json, take_rules};
use crate::api::finding_approvals;
use crate::api::rule_bulk_status::{
    apply_plans, expected_status, has_nul, plan_rule, requires_finding_details, short_id, Plan, RuleOp,
    ALREADY_PENDING, MAX_FINDING_DETAILS_BYTES, MAX_RULES, MAX_RULE_ID_BYTES, VALID_STATUSES,
};
use crate::db_assets::{self, AssetRow};
use crate::db_audit::{self, NewAuditEvent};
use crate::db_checklists::{self, ChecklistRow, ChecklistRuleRow};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct BulkImportQuery {
    #[serde(default)]
    pub dry_run: bool,
}

/// One row of the bulk-import response.
///
/// Note on field naming: the CSV's `status` column carries the rule's new
/// status (open / not_a_finding / etc), but the response also needs a
/// row-level result status (ok / pending_approval / error). We surface the
/// rule's status as `ruleStatus` and reserve `status` for the row-level
/// result so the shape stays consistent with `asset_import`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkImportRowResult {
    pub row_number: usize,
    pub rule_id: String,
    /// Status value from the CSV (the value being applied to the rule).
    pub rule_status: String,
    pub finding_details: String,
    /// Row-level result: "ok" | "pending_approval" | "error". In a dry run
    /// "ok" means the row would be applied and "pending_approval" that it
    /// would be submitted for review.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Extra information on a non-error row (an approval already pending).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkImportResponse {
    pub total_rows: usize,
    pub rows: Vec<BulkImportRowResult>,
    /// Rows written directly. Always 0 in a dry run.
    pub applied_count: usize,
    /// Rows newly sent for approval or already awaiting it. 0 in a dry run.
    pub pending_count: usize,
    pub error_count: usize,
}

/// One CSV data record, before validation.
#[derive(Debug, PartialEq)]
enum RawRow {
    Malformed { row_number: usize, error: String },
    Row { row_number: usize, rule_id: String, status: String, finding_details: String },
}

/// Why the upload as a whole is refused (HTTP 400).
#[derive(Debug, PartialEq)]
enum CsvReject {
    BadHeader,
    MissingColumns,
    TooManyRows,
}

impl CsvReject {
    fn reason(&self) -> &'static str {
        match self {
            Self::BadHeader => "bad_csv_header",
            Self::MissingColumns => "missing_columns",
            Self::TooManyRows => "too_many_rows",
        }
    }
}

/// Read the CSV. `rule_id` and `status` are required columns;
/// `finding_details` is optional. More than [`MAX_RULES`] data rows is
/// refused. Row 1 is the header, so data rows are numbered from 2.
fn parse_csv(bytes: &[u8]) -> Result<Vec<RawRow>, CsvReject> {
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(true).from_reader(bytes);
    let headers = rdr.headers().map_err(|e| {
        tracing::warn!("rule bulk-import: bad CSV headers: {e:#}");
        CsvReject::BadHeader
    })?;
    let col = |name: &str| headers.iter().position(|h| h.trim().eq_ignore_ascii_case(name));
    let (Some(rule_id_idx), Some(status_idx)) = (col("rule_id"), col("status")) else {
        return Err(CsvReject::MissingColumns);
    };
    let details_idx = col("finding_details");

    let mut rows = Vec::new();
    for (i, record) in rdr.records().enumerate() {
        if i >= MAX_RULES {
            return Err(CsvReject::TooManyRows);
        }
        let row_number = i + 2;
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                rows.push(RawRow::Malformed { row_number, error: format!("malformed row: {e}") });
                continue;
            }
        };
        let cell = |idx: Option<usize>| -> String {
            idx.and_then(|i| record.get(i)).map(|s| s.trim().to_string()).unwrap_or_default()
        };
        rows.push(RawRow::Row {
            row_number,
            rule_id: cell(Some(rule_id_idx)),
            status: cell(Some(status_idx)),
            finding_details: cell(details_idx),
        });
    }
    Ok(rows)
}

/// A row that failed validation: the text shown to the user and the fixed
/// reason that may go into the audit trail (never CSV content).
struct RowError {
    shown: String,
    audit: &'static str,
}

impl RowError {
    fn fixed(msg: &'static str) -> Self {
        Self { shown: msg.to_string(), audit: msg }
    }
}

/// A valid row waiting to be applied (or previewed).
struct Planned {
    /// Index into the result rows.
    slot: usize,
    rule_id: String,
    status: String,
    /// `Some` only for a non-blank cell; blank keeps the stored text.
    details: Option<String>,
    expect: Option<String>,
    plan: Plan,
}

fn record_event<'a>(
    user: &'a AuthUser,
    asset: &'a AssetRow,
    checklist: &'a ChecklistRow,
    outcome: &'static str,
    detail: serde_json::Value,
) -> NewAuditEvent<'a> {
    NewAuditEvent {
        user_id: &user.id,
        action: "rules.bulk_import",
        outcome,
        asset_id: Some(&asset.id),
        checklist_id: Some(&checklist.id),
        stig_id: Some(&checklist.stig_id),
        detail,
    }
}

/// Record a refused upload. A preview fires on every file pick, so only a
/// commit is recorded.
async fn reject_event(
    pool: &sqlx::PgPool,
    user: &AuthUser,
    asset: &AssetRow,
    checklist: &ChecklistRow,
    dry_run: bool,
    reason: &'static str,
) {
    if !dry_run {
        db_audit::record_or_log(pool, record_event(user, asset, checklist, "rejected", json!({ "reason": reason })))
            .await;
    }
}

/// Look up the checklist and asset and check write access. 404 and 403 come
/// before any upload is read. A denied attempt is recorded (both modes).
pub(crate) async fn authorise(
    state: AppState,
    user: AuthUser,
    checklist_id: String,
    dry_run: bool,
) -> Result<(ChecklistRow, AssetRow), StatusCode> {
    let pool = state.pool.as_ref();
    let checklist = db_checklists::get_checklist(pool, &checklist_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let asset = db_assets::get_asset(pool, &checklist.asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    // Must hold write (owner / write-ACL / admin role / acl-admin) on the
    // underlying asset to bulk-patch its checklist.
    if !asset_acl::user_can(pool, &asset.id, &user, "write").await {
        db_audit::record_or_log(
            pool,
            record_event(&user, &asset, &checklist, "denied", json!({ "reason": "forbidden", "dryRun": dry_run })),
        )
        .await;
        return Err(StatusCode::FORBIDDEN);
    }
    Ok((checklist, asset))
}

/// POST /api/checklists/:id/rules/bulk-import?dry_run=true|false
///
/// Multipart upload with one `file` field containing a CSV with columns:
/// `rule_id, status, finding_details` (other columns ignored). For each row:
///   - rule_id non-empty, part of the checklist's STIG, not repeated
///   - status ∈ {not_reviewed, open, not_a_finding, not_applicable}
///   - a closing status needs finding details, from the cell or already
///     stored; a blank cell keeps the stored text
///
/// In dry_run nothing is persisted and the rows report what would happen.
/// On commit, rows are applied through `apply_plans`: on an asset that
/// requires approval a closing row is queued for review instead of written.
/// Comments, assignee and due date are never touched.
///
/// The access check and the work run in spawned tasks: rows commit in
/// independent chunks, so a dropped client connection must not leave
/// committed writes without their audit event.
pub async fn bulk_import_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(checklist_id): Path<String>,
    Query(query): Query<BulkImportQuery>,
    mut multipart: Multipart,
) -> Result<Json<BulkImportResponse>, StatusCode> {
    let (checklist, asset) =
        tokio::spawn(authorise(state.clone(), user.clone(), checklist_id, query.dry_run))
            .await
            .map_err(join_failed)??;

    // Slurp the first 'file' field into a buffer. CSVs for a checklist are
    // bounded by the rule count so we accept the memory cost.
    let mut csv_bytes: Option<Vec<u8>> = None;
    let mut read_error: Option<&'static str> = None;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                if field.name() != Some("file") {
                    continue;
                }
                match field.bytes().await {
                    Ok(bytes) => csv_bytes = Some(bytes.to_vec()),
                    Err(e) => {
                        tracing::warn!("rule bulk-import body read error: {e:#}");
                        read_error = Some("multipart_error");
                    }
                }
                break;
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("rule bulk-import multipart error: {e:#}");
                read_error = Some("multipart_error");
                break;
            }
        }
    }
    let Some(csv_bytes) = csv_bytes else {
        let reason = read_error.unwrap_or("no_file");
        let st = state.clone();
        let dry_run = query.dry_run;
        let (u, a, c) = (user.clone(), asset.clone(), checklist.clone());
        let _ = tokio::spawn(async move {
            reject_event(st.pool.as_ref(), &u, &a, &c, dry_run, reason).await;
        })
        .await;
        return Err(StatusCode::BAD_REQUEST);
    };

    run_import(state, user, checklist, asset, csv_bytes, query.dry_run).await
}

/// Run [`import_work`] in its own task so it finishes (events included) even
/// if the caller's future is dropped.
pub(crate) async fn run_import(
    state: AppState,
    user: AuthUser,
    checklist: ChecklistRow,
    asset: AssetRow,
    csv_bytes: Vec<u8>,
    dry_run: bool,
) -> Result<Json<BulkImportResponse>, StatusCode> {
    tokio::spawn(import_work(state, user, checklist, asset, csv_bytes, dry_run))
        .await
        .map_err(join_failed)?
}

pub(crate) async fn import_work(
    state: AppState,
    user: AuthUser,
    checklist: ChecklistRow,
    asset: AssetRow,
    csv_bytes: Vec<u8>,
    dry_run: bool,
) -> Result<Json<BulkImportResponse>, StatusCode> {
    let pool = state.pool.as_ref();
    let raw = match parse_csv(&csv_bytes) {
        Ok(r) => r,
        Err(rej) => {
            reject_event(pool, &user, &asset, &checklist, dry_run, rej.reason()).await;
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let mut stig = match load_stig_json(&state, &checklist.stig_id).await {
        Ok(v) => v,
        Err(code) => {
            if code == StatusCode::BAD_REQUEST || code == StatusCode::NOT_FOUND {
                reject_event(pool, &user, &asset, &checklist, dry_run, "stig_unavailable").await;
            }
            return Err(code);
        }
    };
    let known: HashSet<String> = take_rules(&mut stig)
        .iter()
        .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    let existing: HashMap<String, ChecklistRuleRow> = db_checklists::list_rule_overrides(pool, &checklist.id)
        .await
        .map_err(map_db)?
        .into_iter()
        .map(|r| (r.rule_id.clone(), r))
        .collect();

    // Validate and plan every row, in both modes.
    let mut rows: Vec<BulkImportRowResult> = Vec::with_capacity(raw.len());
    // Fixed reason per errored row, parallel to `rows` (audit only).
    let mut reasons: Vec<Option<String>> = Vec::with_capacity(raw.len());
    let mut planned: Vec<Planned> = Vec::new();
    let mut first_seen: HashMap<String, usize> = HashMap::new();
    for r in raw {
        let (row_number, rule_id, status, details) = match r {
            RawRow::Malformed { row_number, error } => {
                rows.push(BulkImportRowResult {
                    row_number,
                    rule_id: String::new(),
                    rule_status: String::new(),
                    finding_details: String::new(),
                    status: "error".into(),
                    error: Some(error),
                    note: None,
                });
                reasons.push(Some("malformed row".into()));
                continue;
            }
            RawRow::Row { row_number, rule_id, status, finding_details } => {
                (row_number, rule_id, status, finding_details)
            }
        };
        let slot = rows.len();
        let echo_details = if details.len() > MAX_FINDING_DETAILS_BYTES { String::new() } else { details.clone() };
        rows.push(BulkImportRowResult {
            row_number,
            rule_id: short_id(&rule_id),
            rule_status: short_id(&status),
            finding_details: echo_details,
            status: "ok".into(),
            error: None,
            note: None,
        });
        reasons.push(None);

        let prev = existing.get(&rule_id);
        let invalid: Option<RowError> = if rule_id.is_empty() {
            Some(RowError::fixed("rule_id required"))
        } else if rule_id.len() > MAX_RULE_ID_BYTES {
            Some(RowError::fixed("rule id too long"))
        } else if has_nul(&rule_id) || has_nul(&status) || has_nul(&details) {
            Some(RowError::fixed("text contains a NUL character"))
        } else if details.len() > MAX_FINDING_DETAILS_BYTES {
            Some(RowError::fixed("finding_details too long"))
        } else if !VALID_STATUSES.contains(&status.as_str()) {
            Some(RowError { shown: format!("invalid status: {}", short_id(&status)), audit: "invalid status" })
        } else if requires_finding_details(&status)
            && details.is_empty()
            && prev.map(|p| p.finding_details.trim().is_empty()).unwrap_or(true)
        {
            Some(RowError { shown: format!("finding_details required for status {status}"), audit: "finding_details required" })
        } else {
            first_seen.get(&rule_id).map(|first| RowError {
                shown: format!("duplicate rule_id (first on row {first})"),
                audit: "duplicate rule_id",
            })
        };
        if let Some(e) = invalid {
            rows[slot].status = "error".into();
            rows[slot].error = Some(e.shown);
            reasons[slot] = Some(e.audit.to_string());
            continue;
        }
        first_seen.insert(rule_id.clone(), row_number);

        let plan = plan_rule(known.contains(&rule_id), prev, &status, &details, asset.requires_approval);
        if let Plan::Reject(msg) = plan {
            rows[slot].status = "error".into();
            rows[slot].error = Some(msg.to_string());
            reasons[slot] = Some(msg.to_string());
            continue;
        }
        let expect = expected_status(asset.requires_approval, &status, prev);
        planned.push(Planned {
            slot,
            rule_id,
            status,
            details: (!details.trim().is_empty()).then_some(details),
            expect,
            plan,
        });
    }

    let total_rows = rows.len();
    let mut applied_count = 0usize;
    let mut pending_count = 0usize;
    let mut already_pending = 0usize;

    if dry_run {
        let pending_ids = if planned.iter().any(|p| matches!(p.plan, Plan::RequestApproval { .. })) {
            finding_approvals::pending_rule_ids(pool, &checklist.id).await.map_err(map_db)?
        } else {
            HashSet::new()
        };
        for p in &planned {
            if matches!(p.plan, Plan::RequestApproval { .. }) {
                rows[p.slot].status = "pending_approval".into();
                if pending_ids.contains(&p.rule_id) {
                    rows[p.slot].note = Some(ALREADY_PENDING.to_string());
                }
            }
        }
    } else {
        let ops: Vec<RuleOp<'_>> = planned
            .iter()
            .map(|p| RuleOp {
                rule_id: &p.rule_id,
                status: &p.status,
                write_status: true,
                expect_status: p.expect.as_deref(),
                finding_details: p.details.as_deref(),
                comments: None,
                plan: match &p.plan {
                    Plan::Apply { finding_details } => Plan::Apply { finding_details: finding_details.clone() },
                    Plan::RequestApproval { finding_details } => {
                        Plan::RequestApproval { finding_details: finding_details.clone() }
                    }
                    Plan::Reject(m) => Plan::Reject(m),
                },
            })
            .collect();
        let outcomes = apply_plans(pool, &checklist.id, &user.id, &ops).await;
        for (p, outcome) in planned.iter().zip(outcomes) {
            let row = &mut rows[p.slot];
            match outcome {
                Ok(a) if a.status == "pending_approval" => {
                    row.status = "pending_approval".into();
                    row.note = a.note.map(str::to_string);
                    pending_count += 1;
                    if row.note.is_some() {
                        already_pending += 1;
                    }
                }
                Ok(_) => applied_count += 1,
                Err(msg) => {
                    row.status = "error".into();
                    // Fixed texts from the write layer, never user input.
                    reasons[p.slot] = Some(msg.clone());
                    row.error = Some(msg);
                }
            }
        }
    }
    let error_count = rows.iter().filter(|r| r.status == "error").count();

    if !dry_run {
        let all_rejected: Vec<(String, String)> = rows
            .iter()
            .zip(&reasons)
            .filter(|(r, _)| r.status == "error")
            .map(|(r, reason)| {
                let id = if r.rule_id.is_empty() { format!("row:{}", r.row_number) } else { r.rule_id.clone() };
                (id, reason.clone().unwrap_or_default())
            })
            .collect();
        let rejected: Vec<&str> = all_rejected.iter().take(100).map(|(id, _)| id.as_str()).collect();
        // The durable record is written below; this line stays as the
        // fallback when that write fails.
        tracing::info!(
            target: "audit",
            user_id = %user.id,
            asset_id = %asset.id,
            stig_id = %checklist.stig_id,
            checklist_id = %checklist.id,
            applied = applied_count,
            pending = pending_count,
            already_pending = already_pending,
            errors = error_count,
            rejected_rule_ids = ?rejected,
            "bulk rule import"
        );
        let (rejected_list, rejected_truncated) = db_audit::rejected_detail(&all_rejected);
        db_audit::record_or_log(
            pool,
            record_event(
                &user,
                &asset,
                &checklist,
                if error_count > 0 { "partial" } else { "ok" },
                json!({
                    "requested": total_rows,
                    "applied": applied_count,
                    // As in bulk-status, `pending` includes `alreadyPending`;
                    // the response's `pendingCount` is the same sum.
                    "pending": pending_count,
                    "alreadyPending": already_pending,
                    "errors": error_count,
                    "rejected": rejected_list,
                    "rejectedTruncated": rejected_truncated,
                }),
            ),
        )
        .await;
    }

    Ok(Json(BulkImportResponse { total_rows, rows, applied_count, pending_count, error_count }))
}

fn join_failed(e: tokio::task::JoinError) -> StatusCode {
    tracing::error!("rule bulk-import task failed: {e}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("rule bulk-import db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{
        app_state, auth, fail_writes_of, seed_asset, seed_checklist, seed_rule, seed_user, RULES, STIG_ID,
    };
    use sqlx::PgPool;

    // ── CSV parsing ─────────────────────────────────────────────────────────

    #[test]
    fn parse_requires_rule_id_and_status_columns() {
        assert_eq!(parse_csv(b"rule_id,finding_details\nr1,x\n"), Err(CsvReject::MissingColumns));
        assert_eq!(parse_csv(b"status\nopen\n"), Err(CsvReject::MissingColumns));
        assert!(parse_csv(b"Rule_ID , STATUS\nr1,open\n").is_ok());
    }

    #[test]
    fn parse_numbers_rows_from_two_and_trims_cells() {
        let rows = parse_csv(b"rule_id,status,finding_details\n r1 , open , why \nr2,open\n").unwrap();
        assert_eq!(
            rows,
            [
                RawRow::Row { row_number: 2, rule_id: "r1".into(), status: "open".into(), finding_details: "why".into() },
                RawRow::Row { row_number: 3, rule_id: "r2".into(), status: "open".into(), finding_details: String::new() },
            ]
        );
    }

    #[test]
    fn parse_reports_a_malformed_row_in_place() {
        let rows = parse_csv(b"rule_id,status\nr1,open\n\xff\xfe,open\nr3,open\n").unwrap();
        assert_eq!(rows.len(), 3);
        assert!(matches!(&rows[1], RawRow::Malformed { row_number: 3, .. }));
        assert!(matches!(&rows[2], RawRow::Row { row_number: 4, .. }));
    }

    #[test]
    fn parse_refuses_more_than_max_rules_rows() {
        let mut csv = String::from("rule_id,status\n");
        for i in 0..MAX_RULES {
            csv.push_str(&format!("r{i},open\n"));
        }
        assert_eq!(parse_csv(csv.as_bytes()).unwrap().len(), MAX_RULES);
        csv.push_str("extra,open\n");
        assert_eq!(parse_csv(csv.as_bytes()), Err(CsvReject::TooManyRows));
    }

    // ── Database-backed tests ───────────────────────────────────────────────

    async fn setup(pool: &PgPool, gated: bool) -> (AppState, crate::test_fixtures::StigDir) {
        seed_user(pool, "owner").await;
        seed_user(pool, "other").await;
        seed_asset(pool, "a1", "owner", gated).await;
        seed_checklist(pool, "c1", "a1", STIG_ID).await;
        app_state(pool.clone())
    }

    async fn run(state: &AppState, user: &str, csv: &str, dry: bool) -> Result<BulkImportResponse, StatusCode> {
        run_bytes(state, user, csv.as_bytes(), dry).await
    }

    async fn run_bytes(state: &AppState, user: &str, csv: &[u8], dry: bool) -> Result<BulkImportResponse, StatusCode> {
        let u = auth(user, "author");
        let (c, a) = authorise(state.clone(), u.clone(), "c1".into(), dry).await?;
        run_import(state.clone(), u, c, a, csv.to_vec(), dry).await.map(|j| j.0)
    }

    async fn rule(pool: &PgPool, rule_id: &str) -> Option<(String, String, String)> {
        sqlx::query_as("SELECT status, finding_details, comments FROM checklist_rules WHERE rule_id = $1")
            .bind(rule_id)
            .fetch_optional(pool)
            .await
            .unwrap()
    }

    async fn count(pool: &PgPool, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
    }

    fn statuses(r: &BulkImportResponse) -> Vec<&str> {
        r.rows.iter().map(|x| x.status.as_str()).collect()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_dry_run_writes_nothing_and_reports_would_be_outcomes(pool: PgPool) {
        let (state, _d) = setup(&pool, true).await;
        seed_rule(&pool, "c1", RULES[2], "not_a_finding", "done", "", "owner").await;
        let csv = format!(
            "rule_id,status,finding_details\n{},open,\n{},not_a_finding,why\n{},not_a_finding,\nnope,open,\n{},not_a_finding,x\n",
            RULES[0], RULES[1], RULES[2], RULES[1]
        );
        let before = count(&pool, "SELECT COUNT(*) FROM rule_audit").await;
        let r = run(&state, "owner", &csv, true).await.unwrap();
        assert_eq!(statuses(&r), ["ok", "pending_approval", "ok", "error", "error"]);
        assert_eq!((r.applied_count, r.pending_count, r.error_count), (0, 0, 2));
        assert_eq!(r.rows[3].error.as_deref(), Some("rule is not part of this checklist's STIG"));
        assert_eq!(r.rows[4].error.as_deref(), Some("duplicate rule_id (first on row 3)"));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_rules").await, 1);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_approvals").await, 0);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM rule_audit").await, before);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM audit_events").await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_dry_run_flags_already_pending(pool: PgPool) {
        let (state, _d) = setup(&pool, true).await;
        let csv = format!("rule_id,status,finding_details\n{},not_a_finding,why\n", RULES[0]);
        let first = run(&state, "owner", &csv, false).await.unwrap();
        assert_eq!(first.rows[0].note, None);
        let r = run(&state, "owner", &csv, true).await.unwrap();
        assert_eq!(r.rows[0].status, "pending_approval");
        assert_eq!(r.rows[0].note.as_deref(), Some(ALREADY_PENDING));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_approvals").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_commit_queues_closing_rows_on_a_gated_asset_once(pool: PgPool) {
        let (state, _d) = setup(&pool, true).await;
        let csv = format!("rule_id,status,finding_details\n{},not_a_finding,why\n{},open,\n", RULES[0], RULES[1]);
        let r = run(&state, "owner", &csv, false).await.unwrap();
        assert_eq!(statuses(&r), ["pending_approval", "ok"]);
        assert_eq!((r.applied_count, r.pending_count, r.error_count), (1, 1, 0));
        // The rule itself is untouched; only the queue grew.
        assert_eq!(rule(&pool, RULES[0]).await, None);
        assert_eq!(rule(&pool, RULES[1]).await.unwrap().0, "open");
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_approvals WHERE status = 'pending'").await, 1);
        let again = run(&state, "owner", &csv, false).await.unwrap();
        assert_eq!(again.rows[0].status, "pending_approval");
        assert_eq!(again.rows[0].note.as_deref(), Some(ALREADY_PENDING));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_approvals").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_already_closed_row_on_a_gated_asset_applies_directly(pool: PgPool) {
        let (state, _d) = setup(&pool, true).await;
        seed_rule(&pool, "c1", RULES[0], "not_a_finding", "old", "", "owner").await;
        let csv = format!("rule_id,status,finding_details\n{},not_a_finding,new text\n", RULES[0]);
        let r = run(&state, "owner", &csv, false).await.unwrap();
        assert_eq!(statuses(&r), ["ok"]);
        assert_eq!(rule(&pool, RULES[0]).await.unwrap().1, "new text");
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_approvals").await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_unknown_rule_is_a_row_error_and_inserts_nothing(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let r = run(&state, "owner", "rule_id,status,finding_details\nSV-not-in-stig,open,\n", false).await.unwrap();
        assert_eq!(statuses(&r), ["error"]);
        assert_eq!((r.applied_count, r.error_count), (0, 1));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_rules").await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_blank_details_keeps_stored_text(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        seed_rule(&pool, "c1", RULES[0], "open", "kept justification", "", "owner").await;
        let csv = format!("rule_id,status,finding_details\n{},not_applicable,\n", RULES[0]);
        let r = run(&state, "owner", &csv, false).await.unwrap();
        assert_eq!(statuses(&r), ["ok"]);
        let (st, details, _) = rule(&pool, RULES[0]).await.unwrap();
        assert_eq!((st.as_str(), details.as_str()), ("not_applicable", "kept justification"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_closing_without_any_details_is_a_row_error(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let csv = format!("rule_id,status\n{},not_a_finding\n", RULES[0]);
        let r = run(&state, "owner", &csv, false).await.unwrap();
        assert_eq!(r.rows[0].error.as_deref(), Some("finding_details required for status not_a_finding"));
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_rules").await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_duplicate_rule_ids_error_after_the_first(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let csv = format!("rule_id,status,finding_details\n{0},open,\n{0},not_a_finding,x\n", RULES[0]);
        let r = run(&state, "owner", &csv, false).await.unwrap();
        assert_eq!(statuses(&r), ["ok", "error"]);
        assert_eq!(r.rows[1].error.as_deref(), Some("duplicate rule_id (first on row 2)"));
        assert_eq!(rule(&pool, RULES[0]).await.unwrap().0, "open");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_preserves_comments_assignee_and_due_date(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        seed_rule(&pool, "c1", RULES[0], "open", "", "my comment", "owner").await;
        sqlx::query("UPDATE checklist_rules SET assignee_id = 'other', due_date = '2031-02-03' WHERE rule_id = $1")
            .bind(RULES[0])
            .execute(&pool)
            .await
            .unwrap();
        let csv = format!("rule_id,status,finding_details\n{},not_a_finding,why\n", RULES[0]);
        run(&state, "owner", &csv, false).await.unwrap();
        let row: (String, Option<String>, Option<chrono::NaiveDate>) =
            sqlx::query_as("SELECT comments, assignee_id, due_date FROM checklist_rules WHERE rule_id = $1")
                .bind(RULES[0])
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, "my comment");
        assert_eq!(row.1.as_deref(), Some("other"));
        assert_eq!(row.2.map(|d| d.to_string()).as_deref(), Some("2031-02-03"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_failed_chunk_becomes_row_errors(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        fail_writes_of(&pool, "checklist_rules", &[RULES[0]]).await;
        let csv = format!("rule_id,status,finding_details\n{},open,\n{},open,\n", RULES[0], RULES[1]);
        let r = run(&state, "owner", &csv, false).await.unwrap();
        assert_eq!(r.rows[0].status, "error");
        assert_eq!(r.rows[0].error.as_deref(), Some("failed to save"));
        assert_eq!(r.applied_count + r.error_count, 2);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM audit_events WHERE outcome = 'partial'").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_records_ok_partial_denied_and_rejected_events(pool: PgPool) {
        let (state, _d) = setup(&pool, true).await;
        let ok = format!("rule_id,status\n{},open\n", RULES[0]);
        run(&state, "owner", &ok, false).await.unwrap();
        let partial = format!("rule_id,status,finding_details\n{},not_a_finding,why\nnope,open,\n", RULES[1]);
        run(&state, "owner", &partial, false).await.unwrap();
        assert_eq!(run(&state, "other", &ok, false).await.unwrap_err(), StatusCode::FORBIDDEN);
        assert_eq!(run(&state, "other", &ok, true).await.unwrap_err(), StatusCode::FORBIDDEN);
        assert_eq!(run(&state, "owner", "a,b\n1,2\n", false).await.unwrap_err(), StatusCode::BAD_REQUEST);
        // A dry run records nothing, whatever its outcome.
        run(&state, "owner", &ok, true).await.unwrap();
        assert_eq!(run(&state, "owner", "a,b\n1,2\n", true).await.unwrap_err(), StatusCode::BAD_REQUEST);

        let ev: Vec<(String, String, Option<String>, serde_json::Value)> = sqlx::query_as(
            "SELECT action, outcome, stig_id, detail FROM audit_events ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let shape: Vec<(&str, &str)> = ev.iter().map(|e| (e.0.as_str(), e.1.as_str())).collect();
        assert_eq!(
            shape,
            [
                ("rules.bulk_import", "ok"),
                ("rules.bulk_import", "partial"),
                ("rules.bulk_import", "denied"),
                ("rules.bulk_import", "denied"),
                ("rules.bulk_import", "rejected"),
            ]
        );
        assert!(ev.iter().all(|e| e.2.as_deref() == Some(STIG_ID)));
        assert_eq!(ev[1].3["applied"], 0);
        assert_eq!(ev[1].3["pending"], 1);
        assert_eq!(ev[1].3["errors"], 1);
        assert_eq!(ev[2].3["dryRun"], false);
        assert_eq!(ev[3].3["dryRun"], true);
        assert_eq!(ev[4].3["reason"], "missing_columns");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_event_detail_never_holds_csv_text(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let mut csv = b"rule_id,status,finding_details\nZZRULE,QQSTATUS,SECRETDETAILS\n".to_vec();
        csv.extend_from_slice(format!("{},not_a_finding,\n", RULES[0]).as_bytes());
        csv.extend_from_slice(b"\xff\xfe,open,\n");
        csv.extend_from_slice(b",open,\n");
        let r = run_bytes(&state, "owner", &csv, false).await.unwrap();
        assert_eq!(r.error_count, 4);
        let detail: String = sqlx::query_scalar("SELECT detail::text FROM audit_events").fetch_one(&pool).await.unwrap();
        for leak in ["QQSTATUS", "SECRETDETAILS", "utf", "UTF"] {
            assert!(!detail.contains(leak), "detail leaks {leak}: {detail}");
        }
        assert!(detail.contains("row:"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn import_work_and_event_survive_the_future_being_dropped(pool: PgPool) {
        let (state, _d) = setup(&pool, false).await;
        let u = auth("owner", "author");
        let (c, a) = authorise(state.clone(), u.clone(), "c1".into(), false).await.unwrap();
        let csv = format!("rule_id,status\n{},open\n", RULES[0]).into_bytes();
        let st = state.clone();
        let h = tokio::spawn(async move {
            let _ = run_import(st, u, c, a, csv, false).await;
        });
        tokio::task::yield_now().await;
        h.abort();
        let mut seen = 0i64;
        for _ in 0..200 {
            seen = count(&pool, "SELECT COUNT(*) FROM audit_events").await;
            if seen > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(seen, 1);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_rules").await, 1);
    }
}
