use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::api::auth::AuthUser;
use crate::db_assets;
use crate::db_checklists;
use crate::AppState;

/// Allowed rule statuses. Mirrors `is_valid_status` in `checklists.rs`.
const VALID_STATUSES: &[&str] = &[
    "not_reviewed",
    "open",
    "not_a_finding",
    "not_applicable",
];

/// Closing-status transitions (`not_a_finding`, `not_applicable`) require a
/// written justification in `finding_details`. Kept in sync with
/// `requires_finding_details` in `checklists.rs`.
fn requires_finding_details(status: &str) -> bool {
    matches!(status, "not_a_finding" | "not_applicable")
}

#[derive(Debug, Deserialize)]
pub struct BulkImportQuery {
    #[serde(default)]
    pub dry_run: bool,
}

/// One row of the bulk-import response.
///
/// Note on field naming: the CSV's `status` column carries the rule's new
/// status (open / not_a_finding / etc), but the response also needs a
/// row-level result status (ok / error). We surface the rule's status as
/// `ruleStatus` and reserve `status` for the row-level result so the shape
/// stays consistent with `asset_import`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkImportRowResult {
    pub row_number: usize,
    pub rule_id: String,
    /// Status value from the CSV (the value being applied to the rule).
    pub rule_status: String,
    pub finding_details: String,
    /// Row-level result: "ok" | "error".
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkImportResponse {
    pub total_rows: usize,
    pub rows: Vec<BulkImportRowResult>,
    pub applied_count: usize,
    pub error_count: usize,
}

/// Internal staging row for valid rows that will be applied on commit.
struct ParsedRow {
    rule_id: String,
    status: String,
    finding_details: String,
}

/// POST /api/checklists/:id/rules/bulk-import?dry_run=true|false
///
/// Multipart upload with one `file` field containing a CSV with columns:
/// `rule_id, status, finding_details` (other columns ignored). For each row:
///   - rule_id non-empty
///   - status ∈ {not_reviewed, open, not_a_finding, not_applicable}
///   - if status is a closing one, finding_details must be non-empty
///
/// In dry_run, no rows are persisted. On commit, "ok" rows are applied via
/// `db_checklists::upsert_rule`; "error" rows are skipped. Existing rule
/// state (comments, assignee, due date) is preserved for applied rows.
pub async fn bulk_import_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(checklist_id): Path<String>,
    Query(query): Query<BulkImportQuery>,
    mut multipart: Multipart,
) -> Result<Json<BulkImportResponse>, StatusCode> {
    // Owner-only — only the asset owner can bulk-patch its checklist.
    let checklist = db_checklists::get_checklist(state.pool.as_ref(), &checklist_id)
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

    // Slurp the first 'file' field into a buffer. CSVs for a checklist are
    // bounded by the rule count so we accept the memory cost.
    let mut csv_bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::warn!("rule bulk-import multipart error: {e:#}");
        StatusCode::BAD_REQUEST
    })? {
        if field.name() != Some("file") {
            continue;
        }
        let bytes = field.bytes().await.map_err(|e| {
            tracing::warn!("rule bulk-import body read error: {e:#}");
            StatusCode::BAD_REQUEST
        })?;
        csv_bytes = Some(bytes.to_vec());
        break;
    }
    let csv_bytes = csv_bytes.ok_or(StatusCode::BAD_REQUEST)?;

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(csv_bytes.as_slice());

    let headers = rdr
        .headers()
        .map_err(|e| {
            tracing::warn!("rule bulk-import: bad CSV headers: {e:#}");
            StatusCode::BAD_REQUEST
        })?
        .clone();

    let col = |name: &str| -> Option<usize> {
        headers
            .iter()
            .position(|h| h.trim().eq_ignore_ascii_case(name))
    };
    let rule_id_idx = col("rule_id");
    let status_idx = col("status");
    let finding_details_idx = col("finding_details");

    // rule_id and status are both required columns; finding_details is
    // optional (gate-violating rows surface a per-row error).
    if rule_id_idx.is_none() || status_idx.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut results: Vec<BulkImportRowResult> = Vec::new();
    let mut to_apply: Vec<ParsedRow> = Vec::new();

    for (i, record) in rdr.records().enumerate() {
        // CSV row number to surface in the UI. Row 1 = headers, data starts at 2.
        let row_number = i + 2;
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                results.push(BulkImportRowResult {
                    row_number,
                    rule_id: String::new(),
                    rule_status: String::new(),
                    finding_details: String::new(),
                    status: "error".into(),
                    error: Some(format!("malformed row: {e}")),
                });
                continue;
            }
        };

        let cell = |idx: Option<usize>| -> String {
            idx.and_then(|i| record.get(i))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };

        let rule_id = cell(rule_id_idx);
        let status = cell(status_idx);
        let finding_details = cell(finding_details_idx);

        if rule_id.is_empty() {
            results.push(BulkImportRowResult {
                row_number,
                rule_id,
                rule_status: status,
                finding_details,
                status: "error".into(),
                error: Some("rule_id required".into()),
            });
            continue;
        }

        if !VALID_STATUSES.iter().any(|s| *s == status) {
            results.push(BulkImportRowResult {
                row_number,
                rule_id,
                rule_status: status.clone(),
                finding_details,
                status: "error".into(),
                error: Some(format!("invalid status: {status}")),
            });
            continue;
        }

        if requires_finding_details(&status) && finding_details.is_empty() {
            results.push(BulkImportRowResult {
                row_number,
                rule_id,
                rule_status: status.clone(),
                finding_details,
                status: "error".into(),
                error: Some(format!(
                    "finding_details required for status {status}"
                )),
            });
            continue;
        }

        results.push(BulkImportRowResult {
            row_number,
            rule_id: rule_id.clone(),
            rule_status: status.clone(),
            finding_details: finding_details.clone(),
            status: "ok".into(),
            error: None,
        });
        to_apply.push(ParsedRow {
            rule_id,
            status,
            finding_details,
        });
    }

    let total_rows = results.len();
    let error_count = results
        .iter()
        .filter(|r| r.status == "error")
        .count();

    // On commit, walk the "ok" rows and apply each via upsert_rule.
    // upsert_rule overwrites every column on conflict, so we first read
    // the existing overrides and pass through any comments/assignee/due
    // values so bulk-patching status+finding_details doesn't blow away
    // other per-rule state.
    let applied_count = if query.dry_run || to_apply.is_empty() {
        0
    } else {
        let existing = db_checklists::list_rule_overrides(state.pool.as_ref(), &checklist_id)
            .await
            .map_err(map_db)?;
        let existing_by_rule: std::collections::HashMap<String, db_checklists::ChecklistRuleRow> =
            existing.into_iter().map(|r| (r.rule_id.clone(), r)).collect();

        let mut applied = 0usize;
        for row in &to_apply {
            let prev = existing_by_rule.get(&row.rule_id);
            let comments = prev.map(|p| p.comments.clone()).unwrap_or_default();
            let assignee_id = prev.and_then(|p| p.assignee_id.clone());
            let due_date = prev.and_then(|p| p.due_date);

            db_checklists::upsert_rule(
                state.pool.as_ref(),
                &checklist_id,
                &row.rule_id,
                &row.status,
                &row.finding_details,
                &comments,
                &user.id,
                assignee_id.as_deref(),
                due_date,
            )
            .await
            .map_err(|e| {
                tracing::error!(
                    "rule bulk-import: upsert_rule failed (rule {}): {e:#}",
                    row.rule_id,
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            applied += 1;
        }
        applied
    };

    Ok(Json(BulkImportResponse {
        total_rows,
        rows: results,
        applied_count,
        error_count,
    }))
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("rule bulk-import db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}
