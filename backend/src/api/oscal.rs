//! OSCAL assessment-results export per asset.
//!
//! Emits a minimal but spec-shaped OSCAL 1.1.2 `assessment-results` JSON
//! document for a single asset. Each applied checklist becomes one entry
//! in `results[]`, with one `findings[]` entry per rule that maps STIG
//! status (`open` / `not_a_finding` / `not_applicable` / `not_reviewed`)
//! to the OSCAL objective-status state (`not-satisfied` / `satisfied` /
//! `other` / `other`).
//!
//! NOTE: OSCAL uses **kebab-case** field names, not camelCase, so the
//! structs here intentionally drop the project-wide `rename_all =
//! "camelCase"` convention and use explicit per-field `rename`.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use std::path::Path as StdPath;
use uuid::Uuid;

use crate::db_assets;
use crate::db_checklists;
use crate::AppState;

/// GET /api/assets/:id/oscal.json — OSCAL assessment-results JSON.
///
/// Auth posture matches the per-asset PDF report and bundle exporters:
/// any authenticated user can fetch.
pub async fn export_handler(
    State(state): State<AppState>,
    Path(asset_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let pool = state.pool.as_ref();
    let data_dir = state.config.data_dir.as_path();

    let doc = match build_oscal_document(pool, data_dir, &asset_id).await {
        Ok(Some(d)) => d,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("build_oscal_document failed: {e:#}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let json_bytes = serde_json::to_vec_pretty(&doc).map_err(|e| {
        tracing::error!("oscal serialize failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let date = Utc::now().format("%Y-%m-%d").to_string();
    let filename = sanitize_filename(&format!("oscal-{}-{}.json", doc.asset_name_for_file, date));

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok((headers, json_bytes))
}

// ── Build pipeline ──────────────────────────────────────────────────────────

/// Assemble the full OSCAL document for an asset. Returns `Ok(None)`
/// when the asset doesn't exist so the handler can map to a clean 404.
async fn build_oscal_document(
    pool: &PgPool,
    data_dir: &StdPath,
    asset_id: &str,
) -> anyhow::Result<Option<OscalDocument>> {
    let asset = match db_assets::get_asset(pool, asset_id).await? {
        Some(a) => a,
        None => return Ok(None),
    };

    let owner_name: String = sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1")
        .bind(&asset.owner_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or_else(|| asset.owner_id.clone());

    let checklists = db_checklists::list_checklists_for_asset(pool, asset_id).await?;

    let now_iso = Utc::now().to_rfc3339();

    let mut results: Vec<OscalResult> = Vec::with_capacity(checklists.len());
    for c in &checklists {
        let stig = load_stig_json(data_dir, &c.stig_id).await;
        let stig_title = stig
            .as_ref()
            .and_then(|v| v.get("title"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| c.stig_id.clone());
        let rules = stig
            .as_ref()
            .and_then(|v| v.get("rules"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let overrides = db_checklists::list_rule_overrides(pool, &c.id).await?;
        let over_by_id: HashMap<String, db_checklists::ChecklistRuleRow> = overrides
            .into_iter()
            .map(|r| (r.rule_id.clone(), r))
            .collect();

        let mut findings: Vec<OscalFinding> = Vec::with_capacity(rules.len());
        for rule in &rules {
            let rid = rule
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if rid.is_empty() {
                continue;
            }
            let status = over_by_id
                .get(&rid)
                .map(|r| r.status.as_str())
                .unwrap_or("not_reviewed");
            let state = status_to_oscal(status);

            // CCI tags: a parallel agent is adding a `cci` array on each
            // rule. We treat it as best-effort — if it's missing or
            // empty we omit `props` entirely.
            let props = extract_cci_props(rule);

            findings.push(OscalFinding {
                uuid: deterministic_rule_uuid(&c.id, &rid),
                title: rid.clone(),
                target: OscalTarget {
                    target_type: "objective-id".to_string(),
                    target_id: rid,
                    status: OscalTargetStatus {
                        state: state.to_string(),
                    },
                },
                implementation_statement_uuid: String::new(),
                related_observations: Vec::new(),
                props,
            });
        }

        results.push(OscalResult {
            uuid: c.id.clone(),
            title: stig_title,
            description: "STIG checklist results".to_string(),
            start: now_iso.clone(),
            end: now_iso.clone(),
            reviewed_controls: OscalReviewedControls {
                control_selections: vec![OscalControlSelection {}],
            },
            findings,
        });
    }

    let doc = OscalDocument {
        asset_name_for_file: asset.name.clone(),
        assessment_results: OscalAssessmentResults {
            uuid: asset.id.clone(),
            metadata: OscalMetadata {
                title: format!("STIG assessment for {}", asset.name),
                last_modified: now_iso.clone(),
                version: "1.0".to_string(),
                oscal_version: "1.1.2".to_string(),
                parties: vec![OscalParty {
                    uuid: asset.owner_id.clone(),
                    party_type: "person".to_string(),
                    name: owner_name,
                }],
            },
            import_ap: OscalImportAp {
                href: String::new(),
            },
            results,
        },
    };

    Ok(Some(doc))
}

// ── OSCAL data shapes ───────────────────────────────────────────────────────
//
// NOTE: these structs intentionally do NOT use `rename_all = "camelCase"`
// because OSCAL fields are kebab-case. Each field that needs a different
// JSON key carries an explicit `rename`.

/// Wrapper passed to the handler. The top-level OSCAL JSON only contains
/// `assessment-results`; `asset_name_for_file` is internal bookkeeping
/// for the Content-Disposition header and is excluded from the body.
#[derive(Debug, Serialize)]
struct OscalDocument {
    #[serde(skip)]
    asset_name_for_file: String,
    #[serde(rename = "assessment-results")]
    assessment_results: OscalAssessmentResults,
}

#[derive(Debug, Serialize)]
struct OscalAssessmentResults {
    uuid: String,
    metadata: OscalMetadata,
    #[serde(rename = "import-ap")]
    import_ap: OscalImportAp,
    results: Vec<OscalResult>,
}

#[derive(Debug, Serialize)]
struct OscalMetadata {
    title: String,
    #[serde(rename = "last-modified")]
    last_modified: String,
    version: String,
    #[serde(rename = "oscal-version")]
    oscal_version: String,
    parties: Vec<OscalParty>,
}

#[derive(Debug, Serialize)]
struct OscalParty {
    uuid: String,
    #[serde(rename = "type")]
    party_type: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct OscalImportAp {
    href: String,
}

#[derive(Debug, Serialize)]
struct OscalResult {
    uuid: String,
    title: String,
    description: String,
    start: String,
    end: String,
    #[serde(rename = "reviewed-controls")]
    reviewed_controls: OscalReviewedControls,
    findings: Vec<OscalFinding>,
}

#[derive(Debug, Serialize)]
struct OscalReviewedControls {
    #[serde(rename = "control-selections")]
    control_selections: Vec<OscalControlSelection>,
}

#[derive(Debug, Serialize)]
struct OscalControlSelection {}

#[derive(Debug, Serialize)]
struct OscalFinding {
    uuid: String,
    title: String,
    target: OscalTarget,
    #[serde(rename = "implementation-statement-uuid")]
    implementation_statement_uuid: String,
    #[serde(rename = "related-observations")]
    related_observations: Vec<Value>,
    /// Optional CCI references rolled up onto the finding. Omitted from
    /// the JSON entirely when the rule has no `cci` array.
    #[serde(skip_serializing_if = "Option::is_none")]
    props: Option<Vec<OscalProp>>,
}

#[derive(Debug, Serialize)]
struct OscalTarget {
    #[serde(rename = "type")]
    target_type: String,
    #[serde(rename = "target-id")]
    target_id: String,
    status: OscalTargetStatus,
}

#[derive(Debug, Serialize)]
struct OscalTargetStatus {
    state: String,
}

#[derive(Debug, Serialize)]
struct OscalProp {
    name: String,
    value: String,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Map internal rule status to the OSCAL objective-status `state` token.
/// `not_reviewed` and `not_applicable` both collapse to `other` since
/// OSCAL only defines satisfied / not-satisfied / other for objective
/// status.
fn status_to_oscal(status: &str) -> &'static str {
    match status {
        "not_a_finding" => "satisfied",
        "open" => "not-satisfied",
        "not_applicable" => "other",
        "not_reviewed" => "other",
        _ => "other",
    }
}

/// Deterministic UUID for a finding so re-exports of the same data
/// produce stable IDs. Uses v5 with the DNS namespace and a
/// `<checklist_id>:<rule_id>` payload — uniqueness across checklists
/// (the same rule_id can appear in multiple STIGs / asset applications).
fn deterministic_rule_uuid(checklist_id: &str, rule_id: &str) -> String {
    let key = format!("{checklist_id}:{rule_id}");
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, key.as_bytes()).to_string()
}

/// Pull a `cci` array off a rule JSON value and convert each entry into
/// an OSCAL `prop` with `name = "cci"`. Returns `None` if the rule has
/// no `cci` field or the field is empty / not an array — callers should
/// skip serializing `props` entirely in that case so the JSON stays
/// clean for the common (no-CCI) shape.
fn extract_cci_props(rule: &Value) -> Option<Vec<OscalProp>> {
    let arr = rule.get("cci").and_then(|v| v.as_array())?;
    let props: Vec<OscalProp> = arr
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| OscalProp {
            name: "cci".to_string(),
            value: s.to_string(),
        })
        .collect();
    if props.is_empty() {
        None
    } else {
        Some(props)
    }
}

/// Read a STIG's parsed JSON from the on-disk catalog. Returns `None`
/// for unknown/invalid IDs or read errors — callers degrade gracefully
/// (no rules → empty findings) rather than 500ing the whole export.
async fn load_stig_json(data_dir: &StdPath, stig_id: &str) -> Option<Value> {
    if !stig_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return None;
    }
    let path = data_dir.join("stigs").join(format!("{stig_id}.json"));
    let contents = tokio::fs::read_to_string(&path).await.ok()?;
    serde_json::from_str(&contents).ok()
}

/// Strip anything that isn't a safe filename character. Mirrors the
/// helper in `report.rs` / `bundle.rs` so downloads stay consistent.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_covers_all_known_states() {
        assert_eq!(status_to_oscal("not_a_finding"), "satisfied");
        assert_eq!(status_to_oscal("open"), "not-satisfied");
        assert_eq!(status_to_oscal("not_applicable"), "other");
        assert_eq!(status_to_oscal("not_reviewed"), "other");
        assert_eq!(status_to_oscal("anything-else"), "other");
    }

    #[test]
    fn deterministic_uuid_is_stable() {
        let a = deterministic_rule_uuid("checklist-1", "SV-12345_rule");
        let b = deterministic_rule_uuid("checklist-1", "SV-12345_rule");
        assert_eq!(a, b);
        // Different checklist with the same rule_id → different UUID.
        let c = deterministic_rule_uuid("checklist-2", "SV-12345_rule");
        assert_ne!(a, c);
    }

    #[test]
    fn cci_props_omitted_when_missing_or_empty() {
        let no_cci = serde_json::json!({ "id": "r1" });
        assert!(extract_cci_props(&no_cci).is_none());

        let empty_cci = serde_json::json!({ "id": "r1", "cci": [] });
        assert!(extract_cci_props(&empty_cci).is_none());

        let with_cci = serde_json::json!({ "id": "r1", "cci": ["CCI-001", "CCI-002"] });
        let props = extract_cci_props(&with_cci).expect("two props");
        assert_eq!(props.len(), 2);
        assert_eq!(props[0].name, "cci");
        assert_eq!(props[0].value, "CCI-001");
    }
}
