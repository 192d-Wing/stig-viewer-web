//! Per-STIG catalog version diff.
//!
//! After a DISA sync replaces `${data_dir}/stigs/{id}.json`, the sync
//! hook (`sync::disa::archive_previous_catalog`) copies the old JSON
//! aside and records a row in `catalog_archive`. This module exposes
//! that history to the UI:
//!
//! - `GET /api/stigs/:id/diff` — diff CURRENT live STIG JSON against
//!   the most recent archive row for that STIG. Returns
//!   added / removed / changed rule lists.
//! - `GET /api/stigs/:id/archive` — every archive entry for the STIG,
//!   newest first, so the UI can show "this is the n-th revision".
//!
//! Both endpoints return 404 when there is no archive for the STIG —
//! the typical case before the first sync after this feature ships.
use std::collections::{BTreeMap, HashMap};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Subset of the on-disk STIG JSON we need to diff. The full shape is
/// defined in `parser::StigData` but we only touch fields the diff
/// emits, so we redeclare a narrow struct here to keep the dependency
/// surface small and tolerate forward-compatible JSON additions.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiffStig {
    #[serde(default)]
    version: String,
    #[serde(default)]
    release_info: String,
    #[serde(default)]
    rules: Vec<DiffRule>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DiffRule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    fix_text: String,
    #[serde(default)]
    check_text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddedRule {
    pub id: String,
    pub title: String,
    pub severity: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovedRule {
    pub id: String,
    pub title: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangedField {
    pub id: String,
    pub field: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffResponse {
    pub stig_id: String,
    pub from_version: String,
    pub from_release_info: String,
    pub to_version: String,
    pub to_release_info: String,
    pub added: Vec<AddedRule>,
    pub removed: Vec<RemovedRule>,
    pub changed: Vec<ChangedField>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveRow {
    pub id: i64,
    pub stig_id: String,
    pub version: String,
    pub release_info: String,
    pub archived_at: DateTime<Utc>,
    pub json_path: String,
}

/// GET /api/stigs/:id/diff
///
/// 404 when no archive exists yet, or the current live JSON is missing
/// (catalog row without a file — shouldn't happen, but bail rather
/// than panic). 500 on read/parse failures.
pub async fn diff_handler(
    State(state): State<AppState>,
    Path(stig_id): Path<String>,
) -> Result<Json<DiffResponse>, StatusCode> {
    // Same id sanitization as `api::stig::get_stig` — alphanumerics +
    // hyphens. Prevents path traversal via crafted ids.
    if !stig_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Most recent archive entry for this STIG.
    let prev: Option<(String, String, String)> =
        sqlx::query_as::<_, (String, String, String)>(
            r#"
            SELECT version, release_info, json_path
              FROM catalog_archive
             WHERE stig_id = $1
             ORDER BY archived_at DESC
             LIMIT 1
            "#,
        )
        .bind(&stig_id)
        .fetch_optional(state.pool.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("catalog_archive lookup failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let Some((from_version, from_release_info, from_rel_path)) = prev else {
        return Err(StatusCode::NOT_FOUND);
    };

    // Load the previous version JSON.
    let from_abs = state.config.data_dir.join(&from_rel_path);
    let from_stig: DiffStig = load_json(&from_abs)?;

    // Load the current live JSON.
    let to_abs = state
        .config
        .data_dir
        .join("stigs")
        .join(format!("{stig_id}.json"));
    let to_stig: DiffStig = load_json(&to_abs)?;

    let (added, removed, changed) = compute_diff(&from_stig, &to_stig);

    Ok(Json(DiffResponse {
        stig_id,
        from_version,
        from_release_info,
        to_version: to_stig.version,
        to_release_info: to_stig.release_info,
        added,
        removed,
        changed,
    }))
}

/// GET /api/stigs/:id/archive — all archive rows for this STIG,
/// newest first. Returns 200 with an empty array when the STIG exists
/// in the catalog but has no archive yet.
pub async fn list_archive_handler(
    State(state): State<AppState>,
    Path(stig_id): Path<String>,
) -> Result<Json<Vec<ArchiveRow>>, StatusCode> {
    if !stig_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(StatusCode::BAD_REQUEST);
    }
    let rows = sqlx::query_as::<_, (i64, String, String, String, DateTime<Utc>, String)>(
        r#"
        SELECT id, stig_id, version, release_info, archived_at, json_path
          FROM catalog_archive
         WHERE stig_id = $1
         ORDER BY archived_at DESC
        "#,
    )
    .bind(&stig_id)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("catalog_archive list failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, stig_id, version, release_info, archived_at, json_path)| ArchiveRow {
                id,
                stig_id,
                version,
                release_info,
                archived_at,
                json_path,
            })
            .collect(),
    ))
}

/// Body for `POST /api/test/seed-archive` — synchronously fabricates
/// a "previous version" archive entry for E2E so we don't have to run
/// a real DISA sync to populate `catalog_archive`. Gated by the
/// STIG_ENV != "production" block, same as the rest of `test_support`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedArchiveRequest {
    pub stig_id: String,
    pub version: String,
    pub release_info: String,
    #[serde(default)]
    pub rules: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedArchiveResponse {
    pub id: i64,
    pub json_path: String,
}

/// POST /api/test/seed-archive
///
/// Writes `${data_dir}/stigs/archive/<safe>.json` containing a STIG
/// payload built from the request body (just enough fields for the
/// diff endpoint to consume) and inserts a corresponding
/// `catalog_archive` row. Returns the row id + relative json_path.
pub async fn seed_archive_handler(
    State(state): State<AppState>,
    Json(req): Json<SeedArchiveRequest>,
) -> Result<Json<SeedArchiveResponse>, StatusCode> {
    if !req.stig_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(StatusCode::BAD_REQUEST);
    }
    let release_safe = sanitize_release(&req.release_info);
    let filename = format!(
        "{}-v{}-r{}.json",
        req.stig_id, req.version, release_safe
    );
    let rel_path = format!("stigs/archive/{filename}");
    let abs_path = state.config.data_dir.join(&rel_path);

    let parent = abs_path.parent().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    tokio::fs::create_dir_all(parent).await.map_err(|e| {
        tracing::error!("seed-archive mkdir failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let payload = serde_json::json!({
        "title": "",
        "description": "",
        "version": req.version,
        "releaseInfo": req.release_info,
        "rules": req.rules,
    });
    let bytes = serde_json::to_vec(&payload).map_err(|e| {
        tracing::error!("seed-archive serialise failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    tokio::fs::write(&abs_path, &bytes).await.map_err(|e| {
        tracing::error!("seed-archive write failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let row: (i64,) = sqlx::query_as(
        r#"
        INSERT INTO catalog_archive (stig_id, version, release_info, json_path)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (stig_id, version, release_info) DO UPDATE
          SET json_path = EXCLUDED.json_path,
              archived_at = NOW()
        RETURNING id
        "#,
    )
    .bind(&req.stig_id)
    .bind(&req.version)
    .bind(&req.release_info)
    .bind(&rel_path)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("seed-archive insert failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(SeedArchiveResponse {
        id: row.0,
        json_path: rel_path,
    }))
}

// ── helpers ─────────────────────────────────────────────────────────

fn load_json(path: &std::path::Path) -> Result<DiffStig, StatusCode> {
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            tracing::warn!("catalog_diff: missing file {}", path.display());
            StatusCode::NOT_FOUND
        } else {
            tracing::error!("catalog_diff: read {} failed: {e:#}", path.display());
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|e| {
        tracing::error!("catalog_diff: parse {} failed: {e:#}", path.display());
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Compute (added, removed, changed) for two rule sets keyed by `id`.
/// Field comparisons cover the user-visible columns: title, severity,
/// description, fixText, check (alias for checkText). Long-text fields
/// are compared verbatim — a single trailing-whitespace difference is
/// surfaced as a change, which is fine for an ops review surface.
fn compute_diff(
    from: &DiffStig,
    to: &DiffStig,
) -> (Vec<AddedRule>, Vec<RemovedRule>, Vec<ChangedField>) {
    let from_map: HashMap<&str, &DiffRule> =
        from.rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let to_map: HashMap<&str, &DiffRule> =
        to.rules.iter().map(|r| (r.id.as_str(), r)).collect();

    // Sorted output so diffs are stable across runs even though the
    // upstream JSON ordering is whatever DISA shipped.
    let mut added_b: BTreeMap<&str, AddedRule> = BTreeMap::new();
    let mut removed_b: BTreeMap<&str, RemovedRule> = BTreeMap::new();
    let mut changed_b: BTreeMap<(String, String), ChangedField> = BTreeMap::new();

    for (id, r) in &to_map {
        if !from_map.contains_key(id) {
            added_b.insert(
                id,
                AddedRule {
                    id: r.id.clone(),
                    title: r.title.clone(),
                    severity: r.severity.clone(),
                },
            );
        }
    }
    for (id, r) in &from_map {
        if !to_map.contains_key(id) {
            removed_b.insert(
                id,
                RemovedRule {
                    id: r.id.clone(),
                    title: r.title.clone(),
                },
            );
        }
    }
    for (id, from_rule) in &from_map {
        let Some(to_rule) = to_map.get(id) else {
            continue;
        };
        for (field, a, b) in [
            ("title", &from_rule.title, &to_rule.title),
            ("severity", &from_rule.severity, &to_rule.severity),
            ("description", &from_rule.description, &to_rule.description),
            ("fixText", &from_rule.fix_text, &to_rule.fix_text),
            ("check", &from_rule.check_text, &to_rule.check_text),
        ] {
            if a != b {
                changed_b.insert(
                    (id.to_string(), field.to_string()),
                    ChangedField {
                        id: id.to_string(),
                        field: field.to_string(),
                        from: a.clone(),
                        to: b.clone(),
                    },
                );
            }
        }
    }

    (
        added_b.into_values().collect(),
        removed_b.into_values().collect(),
        changed_b.into_values().collect(),
    )
}

/// Mirrors the sanitiser in `sync::disa` so test-seeded archive
/// filenames look the same as real ones. Whitespace + punctuation →
/// hyphen, collapse repeats, trim trailing hyphens.
fn sanitize_release(release_info: &str) -> String {
    let mut out = String::with_capacity(release_info.len());
    let mut prev_dash = false;
    for c in release_info.chars() {
        if c.is_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}
