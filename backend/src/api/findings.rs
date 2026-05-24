use axum::{
    extract::{Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

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

use crate::api::auth::AuthUser;
use crate::severity::weighted_score;
use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingsQuery {
    #[serde(default = "default_status")]
    pub status: String,
    pub rule_id: Option<String>,
    pub asset_id: Option<String>,
    /// Filter by severity string (e.g. "CAT I", "CAT II", "CAT III").
    /// Case-insensitive exact match against the STIG JSON's rule.severity.
    pub severity: Option<String>,
    /// Filter by assignee. The literal value "me" resolves to the
    /// authenticated user's id; any other value is treated as a user id.
    pub assignee: Option<String>,
    /// When true, only return findings whose due_date is before today.
    #[serde(default)]
    pub past_due: bool,
    /// When set, only return findings with no activity (updated_at) in
    /// the last N days.
    pub older_than_days: Option<i64>,
}

fn default_status() -> String {
    "open".into()
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub checklist_id: String,
    pub rule_id: String,
    pub status: String,
    pub finding_details: String,
    pub comments: String,
    pub updated_at: DateTime<Utc>,
    pub stig_id: String,
    pub stig_title: String,
    pub asset_id: String,
    pub asset_name: String,
    /// Owning asset's classification. Pulled into the row so we can
    /// compute `weighted_score` without an extra round-trip and so the
    /// frontend can colour-by-classification if it wants to.
    pub classification: String,
    pub owner_name: String,
    pub assignee_id: Option<String>,
    pub assignee_name: Option<String>,
    pub due_date: Option<NaiveDate>,
    // The following fields are populated from the STIG JSON after the SQL
    // query. None if the JSON can't be read or the rule isn't found there.
    #[sqlx(default)]
    pub severity: Option<String>,
    #[sqlx(default)]
    pub title: Option<String>,
    #[sqlx(default)]
    pub description: Option<String>,
    #[sqlx(default)]
    pub check_text: Option<String>,
    #[sqlx(default)]
    pub fix_text: Option<String>,
    /// SCAP-style score for this finding. Filled in alongside `severity`
    /// after the rule meta lookup; 0.0 when severity is unknown.
    #[sqlx(default)]
    pub weighted_score: f64,
}

#[derive(Debug, Default, Clone)]
struct RuleMeta {
    severity: Option<String>,
    title: Option<String>,
    description: Option<String>,
    check_text: Option<String>,
    fix_text: Option<String>,
}

/// GET /api/findings?status=open[&ruleId=...][&assetId=...][&severity=...][&assignee=me|<id>]
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(params): Query<FindingsQuery>,
) -> Result<Json<Vec<Finding>>, StatusCode> {
    if !is_valid_status(&params.status) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Resolve the assignee filter: "me" → current user's id, anything else
    // passed through as a user id.
    let assignee_filter: Option<String> = params.assignee.as_deref().map(|s| {
        if s.eq_ignore_ascii_case("me") {
            user.id.clone()
        } else {
            s.to_string()
        }
    });

    let mut rows = sqlx::query_as::<_, Finding>(
        r#"
        SELECT
            cr.checklist_id,
            cr.rule_id,
            cr.status,
            cr.finding_details,
            cr.comments,
            cr.updated_at,
            c.stig_id,
            COALESCE(sc.title, c.stig_id) AS stig_title,
            c.asset_id,
            a.name           AS asset_name,
            a.classification AS classification,
            u.display_name   AS owner_name,
            cr.assignee_id,
            au.display_name  AS assignee_name,
            cr.due_date
        FROM checklist_rules cr
        JOIN checklists c ON c.id = cr.checklist_id
        JOIN assets a     ON a.id = c.asset_id
        JOIN users u      ON u.id = a.owner_id
        LEFT JOIN users au         ON au.id = cr.assignee_id
        LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
        WHERE cr.status = $1
          AND ($2::text IS NULL OR cr.rule_id     = $2)
          AND ($3::text IS NULL OR c.asset_id     = $3)
          AND ($4::text IS NULL OR cr.assignee_id = $4)
          AND ($5::bool = false OR (cr.due_date IS NOT NULL AND cr.due_date < CURRENT_DATE))
          AND ($6::text IS NULL OR cr.updated_at < NOW() - ($6 || ' days')::INTERVAL)
        ORDER BY a.name, c.stig_id, cr.rule_id
        "#,
    )
    .bind(&params.status)
    .bind(params.rule_id.as_deref())
    .bind(params.asset_id.as_deref())
    .bind(assignee_filter.as_deref())
    .bind(params.past_due)
    .bind(params.older_than_days.map(|n| n.to_string()))
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("findings query failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Attach rule metadata from the STIG JSON files. One read per unique
    // stig_id. Failures (missing file, parse error) leave fields as None —
    // the frontend treats those as "Unknown".
    let mut meta_by_stig: HashMap<String, HashMap<String, RuleMeta>> = HashMap::new();
    for f in &rows {
        if meta_by_stig.contains_key(&f.stig_id) {
            continue;
        }
        let map = load_rule_meta_map(&state, &f.stig_id).await;
        meta_by_stig.insert(f.stig_id.clone(), map);
    }
    let today: NaiveDate = Utc::now().date_naive();
    for f in &mut rows {
        if let Some(map) = meta_by_stig.get(&f.stig_id) {
            if let Some(m) = map.get(&f.rule_id) {
                f.severity = m.severity.clone();
                f.title = m.title.clone();
                f.description = m.description.clone();
                f.check_text = m.check_text.clone();
                f.fix_text = m.fix_text.clone();
            }
        }
        // SCAP-style score per finding. Severity strings of "" (unknown)
        // fall through to a weight of 1, which keeps the value non-zero
        // even when the STIG JSON is missing — matches the dashboard's
        // legacy behaviour.
        let sev = f.severity.as_deref().unwrap_or("");
        f.weighted_score = weighted_score(
            sev,
            &f.classification,
            &f.status,
            f.due_date,
            today,
        );
    }

    if let Some(sev) = params.severity.as_deref() {
        let want = sev.to_ascii_lowercase();
        rows.retain(|f| {
            f.severity
                .as_deref()
                .map(|s| s.to_ascii_lowercase() == want)
                .unwrap_or(false)
        });
    }

    Ok(Json(rows))
}

/// Read a STIG JSON file from disk and build a {rule_id -> RuleMeta} map.
/// Returns an empty map on any read/parse failure (logged).
async fn load_rule_meta_map(
    state: &AppState,
    stig_id: &str,
) -> HashMap<String, RuleMeta> {
    if !stig_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return HashMap::new();
    }
    let path = state
        .config
        .data_dir
        .join("stigs")
        .join(format!("{stig_id}.json"));
    let contents = match tokio::fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("rule-meta lookup: cannot read {stig_id}.json: {e}");
            return HashMap::new();
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("rule-meta lookup: cannot parse {stig_id}.json: {e}");
            return HashMap::new();
        }
    };
    let rules = match value.get("rules").and_then(|v| v.as_array()) {
        Some(r) => r,
        None => return HashMap::new(),
    };
    let s = |r: &serde_json::Value, k: &str| {
        r.get(k).and_then(|v| v.as_str()).map(|x| x.to_string())
    };
    rules
        .iter()
        .filter_map(|r| {
            let id = r.get("id")?.as_str()?.to_string();
            Some((
                id,
                RuleMeta {
                    severity: s(r, "severity"),
                    title: s(r, "title"),
                    description: s(r, "description"),
                    check_text: s(r, "checkText"),
                    fix_text: s(r, "fixText"),
                },
            ))
        })
        .collect()
}

fn is_valid_status(s: &str) -> bool {
    matches!(s, "open" | "not_a_finding" | "not_applicable" | "not_reviewed")
}

// ── Bulk patch ──────────────────────────────────────────────────────────────

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
    pub finding_details: Option<String>,
    pub comments: Option<String>,
    /// Tri-state: absent = leave each target's existing assignee alone,
    /// `Some(Some(uuid))` = reassign to that user, `Some(None)` = unassign
    /// (clear) the field. The `deserialize_some` helper preserves the
    /// null-vs-missing distinction that vanilla `Option<String>` collapses.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub assignee_id: Option<Option<String>>,
    /// Tri-state with the same semantics as `assignee_id`.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub due_date: Option<Option<NaiveDate>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkRequest {
    pub targets: Vec<BulkTarget>,
    pub patch: BulkPatch,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkResponse {
    pub updated: usize,
}

/// PATCH /api/findings/bulk
/// Apply the same patch to a list of (checklistId, ruleId) targets.
/// Caller must own the asset for every target; otherwise the entire
/// request is rejected with 403 (no partial application).
pub async fn bulk_handler(
    State(state): State<crate::AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<BulkRequest>,
) -> Result<Json<BulkResponse>, StatusCode> {
    if req.targets.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some(s) = &req.patch.status {
        if !is_valid_status(s) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let pool = state.pool.as_ref();

    // Owner check: every target's checklist must belong to an asset owned
    // by the caller. One IN-list query suffices.
    let checklist_ids: Vec<&str> = req.targets.iter().map(|t| t.checklist_id.as_str()).collect();
    let owner_rows = sqlx::query_as::<_, (String, String)>(
        "SELECT c.id, a.owner_id \
         FROM checklists c \
         JOIN assets a ON a.id = c.asset_id \
         WHERE c.id = ANY($1)",
    )
    .bind(&checklist_ids)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!("bulk owner-check failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let owners: std::collections::HashMap<String, String> = owner_rows.into_iter().collect();
    for t in &req.targets {
        match owners.get(&t.checklist_id) {
            Some(owner) if owner == &user.id => {}
            Some(_) => return Err(StatusCode::FORBIDDEN),
            None => return Err(StatusCode::NOT_FOUND),
        }
    }

    // Apply each patch using the existing upsert_rule path so audit log
    // entries are written per-field-changed, just like a single PATCH.
    let mut updated = 0usize;
    for t in &req.targets {
        // Fetch existing row to fill in untouched fields.
        let existing = sqlx::query_as::<_, crate::db_checklists::ChecklistRuleRow>(
            "SELECT * FROM checklist_rules WHERE checklist_id = $1 AND rule_id = $2",
        )
        .bind(&t.checklist_id)
        .bind(&t.rule_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            tracing::error!("bulk existing fetch failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let status = req
            .patch
            .status
            .clone()
            .or_else(|| existing.as_ref().map(|e| e.status.clone()))
            .unwrap_or_else(|| "not_reviewed".into());
        let finding_details = req
            .patch
            .finding_details
            .clone()
            .or_else(|| existing.as_ref().map(|e| e.finding_details.clone()))
            .unwrap_or_default();
        let comments = req
            .patch
            .comments
            .clone()
            .or_else(|| existing.as_ref().map(|e| e.comments.clone()))
            .unwrap_or_default();
        // Tri-state: None = field absent from request (keep existing),
        // Some(None) = explicit null (clear it), Some(Some(v)) = set it.
        let assignee_id = match &req.patch.assignee_id {
            None => existing.as_ref().and_then(|e| e.assignee_id.clone()),
            Some(None) => None,
            Some(Some(v)) => Some(v.clone()),
        };
        let due_date = match &req.patch.due_date {
            None => existing.as_ref().and_then(|e| e.due_date),
            Some(None) => None,
            Some(Some(d)) => Some(*d),
        };

        crate::db_checklists::upsert_rule(
            pool,
            &t.checklist_id,
            &t.rule_id,
            &status,
            &finding_details,
            &comments,
            &user.id,
            assignee_id.as_deref(),
            due_date,
        )
        .await
        .map_err(|e| {
            tracing::error!("bulk upsert_rule failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        updated += 1;
    }

    Ok(Json(BulkResponse { updated }))
}
