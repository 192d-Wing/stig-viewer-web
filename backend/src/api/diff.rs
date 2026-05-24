//! GET /api/diff — given an ISO date, return every rule that had any
//! field change since then, with a per-field collapsed (first-from →
//! latest-to) view. Backed entirely by the existing `rule_audit` table.
//!
//! A rule that bounced `open → not_a_finding → not_applicable` inside
//! the window collapses to one entry: `{from: "open", to: "not_applicable"}`.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    pub since: Option<String>,
    #[serde(rename = "assetId")]
    pub asset_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldChange {
    pub field: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub by: String,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleDiff {
    pub asset_id: String,
    pub asset_name: String,
    pub checklist_id: String,
    pub stig_title: String,
    pub rule_id: String,
    pub changes: Vec<FieldChange>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffResponse {
    pub since: String,
    pub rules: Vec<RuleDiff>,
}

/// GET /api/diff?since=YYYY-MM-DD[&assetId=...]
pub async fn diff_handler(
    State(state): State<AppState>,
    Query(q): Query<DiffQuery>,
) -> Result<Json<DiffResponse>, StatusCode> {
    let since_str = q.since.ok_or(StatusCode::BAD_REQUEST)?;
    let _since: NaiveDate =
        NaiveDate::parse_from_str(&since_str, "%Y-%m-%d").map_err(|_| StatusCode::BAD_REQUEST)?;

    // Build SQL. The asset filter is optional; parameter binding handles
    // both shapes via a NULL sentinel so we keep one prepared statement.
    let rows = sqlx::query(
        r#"
        SELECT
            ra.checklist_id,
            ra.rule_id,
            ra.field,
            ra.from_value,
            ra.to_value,
            ra.occurred_at,
            u.display_name        AS by_name,
            a.id                  AS asset_id,
            a.name                AS asset_name,
            COALESCE(sc.title, c.stig_id) AS stig_title
          FROM rule_audit ra
          JOIN checklists c     ON c.id = ra.checklist_id
          JOIN assets a         ON a.id = c.asset_id
          JOIN users u          ON u.id = ra.user_id
          LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
         WHERE ra.occurred_at >= $1::date
           AND ($2::text IS NULL OR a.id = $2)
         ORDER BY ra.checklist_id, ra.rule_id, ra.field, ra.occurred_at ASC
        "#,
    )
    .bind(&since_str)
    .bind(&q.asset_id)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("diff query failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Group into per-rule entries. For each (rule, field) keep:
    //   first `from_value` chronologically + latest `to_value`,
    //   plus the latest `by`/`at` so the UI can show who did the
    //   final transition.
    use std::collections::BTreeMap;
    type RuleKey = (String, String); // (checklist_id, rule_id)
    // Per-rule metadata + per-field collapsed change.
    struct Acc {
        asset_id: String,
        asset_name: String,
        stig_title: String,
        // field → (from_first, to_latest, by_latest, at_latest)
        fields: BTreeMap<String, (Option<String>, Option<String>, String, DateTime<Utc>)>,
    }

    let mut by_rule: BTreeMap<RuleKey, Acc> = BTreeMap::new();
    for row in rows {
        let checklist_id: String = row.try_get("checklist_id").map_err(internal)?;
        let rule_id: String = row.try_get("rule_id").map_err(internal)?;
        let field: String = row.try_get("field").map_err(internal)?;
        let from_value: Option<String> = row.try_get("from_value").map_err(internal)?;
        let to_value: Option<String> = row.try_get("to_value").map_err(internal)?;
        let occurred_at: DateTime<Utc> = row.try_get("occurred_at").map_err(internal)?;
        let by_name: String = row.try_get("by_name").map_err(internal)?;
        let asset_id: String = row.try_get("asset_id").map_err(internal)?;
        let asset_name: String = row.try_get("asset_name").map_err(internal)?;
        let stig_title: String = row.try_get("stig_title").map_err(internal)?;

        let entry = by_rule
            .entry((checklist_id.clone(), rule_id.clone()))
            .or_insert_with(|| Acc {
                asset_id,
                asset_name,
                stig_title,
                fields: BTreeMap::new(),
            });

        entry
            .fields
            .entry(field)
            .and_modify(|(_, to, by, at)| {
                // First row already set the from; subsequent rows update
                // to/by/at to the latest.
                *to = to_value.clone();
                *by = by_name.clone();
                *at = occurred_at;
            })
            .or_insert_with(|| (from_value, to_value, by_name, occurred_at));
    }

    // Filter out rules whose collapsed from == to per field (no net change).
    // That happens when a rule was flipped and then flipped back inside the
    // window — surfacing those in the diff is noise.
    let rules: Vec<RuleDiff> = by_rule
        .into_iter()
        .filter_map(|((checklist_id, rule_id), acc)| {
            let changes: Vec<FieldChange> = acc
                .fields
                .into_iter()
                .filter_map(|(field, (from, to, by, at))| {
                    if from == to {
                        None
                    } else {
                        Some(FieldChange { field, from, to, by, at })
                    }
                })
                .collect();
            if changes.is_empty() {
                None
            } else {
                Some(RuleDiff {
                    asset_id: acc.asset_id,
                    asset_name: acc.asset_name,
                    checklist_id,
                    stig_title: acc.stig_title,
                    rule_id,
                    changes,
                })
            }
        })
        .collect();

    Ok(Json(DiffResponse {
        since: since_str,
        rules,
    }))
}

fn internal(e: sqlx::Error) -> StatusCode {
    tracing::error!("diff row decode failed: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[allow(dead_code)]
fn _utc_today() -> NaiveDate {
    Utc::now().date_naive()
}
