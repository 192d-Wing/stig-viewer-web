use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::api::auth::AuthUser;
use crate::AppState;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct BaselineRow {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub created_by_name: String,
    pub created_at: DateTime<Utc>,
    pub rule_count: i64,
    /// True when `created_at` is older than the `STALE_BASELINE_DAYS`
    /// threshold (default 90 days). Computed in SQL via the same predicate
    /// the dashboard uses to count stale baselines.
    pub is_stale: bool,
}

fn stale_baseline_days() -> i64 {
    std::env::var("STALE_BASELINE_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &i64| n > 0)
        .unwrap_or(90)
}

#[derive(Debug, Deserialize)]
pub struct CreateBaselineRequest {
    pub name: String,
}

/// POST /api/baselines { name } — snapshot the current touched rule states.
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateBaselineRequest>,
) -> Result<(StatusCode, Json<BaselineRow>), StatusCode> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let id = uuid::Uuid::new_v4().to_string();
    let pool = state.pool.as_ref();

    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!("baselines db error: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        "INSERT INTO baselines (id, name, created_by) VALUES ($1, $2, $3)",
    )
    .bind(&id)
    .bind(name)
    .bind(&user.id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        let msg = format!("{e:#}");
        if msg.contains("duplicate key") {
            StatusCode::CONFLICT
        } else {
            tracing::error!("create baseline failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;

    sqlx::query(
        r#"
        INSERT INTO baseline_rules (baseline_id, checklist_id, rule_id, status)
        SELECT $1, checklist_id, rule_id, status
          FROM checklist_rules
        "#,
    )
    .bind(&id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("snapshot baseline rules failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("baselines db error: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let row = fetch_one(pool, &id).await?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// GET /api/baselines — list all baselines.
pub async fn list_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<BaselineRow>>, StatusCode> {
    let threshold = stale_baseline_days();
    let rows = sqlx::query_as::<_, BaselineRow>(
        r#"
        SELECT
            b.id,
            b.name,
            b.created_by,
            u.display_name AS created_by_name,
            b.created_at,
            COALESCE((SELECT COUNT(*) FROM baseline_rules br WHERE br.baseline_id = b.id), 0)
                ::BIGINT AS rule_count,
            (b.created_at < NOW() - ($1 || ' days')::INTERVAL) AS is_stale
          FROM baselines b
          JOIN users u ON u.id = b.created_by
         ORDER BY b.created_at DESC
        "#,
    )
    .bind(threshold.to_string())
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("list baselines failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(rows))
}

/// DELETE /api/baselines/:id — creator-only.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let owner: Option<String> = sqlx::query_scalar("SELECT created_by FROM baselines WHERE id = $1")
        .bind(&id)
        .fetch_optional(state.pool.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("delete baseline lookup failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let owner = owner.ok_or(StatusCode::NOT_FOUND)?;
    if owner != user.id {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query("DELETE FROM baselines WHERE id = $1")
        .bind(&id)
        .execute(state.pool.as_ref())
        .await
        .map_err(|e| {
            tracing::error!("delete baseline failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Diff ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct DiffEntry {
    pub checklist_id: String,
    pub rule_id: String,
    pub from_status: String,
    pub to_status: String,
    pub asset_id: String,
    pub asset_name: String,
    pub stig_id: String,
    pub stig_title: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffResponse {
    pub baseline: BaselineRow,
    pub regressed: Vec<DiffEntry>,
    pub improved: Vec<DiffEntry>,
    pub unchanged: i64,
}

fn is_better(s: &str) -> bool {
    matches!(s, "not_a_finding" | "not_applicable")
}

/// GET /api/baselines/:id/diff
///
/// Compares baseline_rules.status to the current checklist_rules.status.
/// - regressed: baseline was "better" (NaF/NA) but current is Open
/// - improved:  baseline was Open but current is "better" (NaF/NA)
/// - unchanged: count of rows where statuses match
///
/// Rules with no current row default to "not_reviewed" (treated as neither
/// better nor worse — usually unchanged-relative or "improved" depending on
/// the baseline status; included in regressed only if baseline was "better").
pub async fn diff_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<DiffResponse>, StatusCode> {
    let pool = state.pool.as_ref();
    let baseline = fetch_one(pool, &id).await?;

    let rows = sqlx::query_as::<_, DiffEntry>(
        r#"
        SELECT
            br.checklist_id,
            br.rule_id,
            br.status AS from_status,
            COALESCE(cr.status, 'not_reviewed') AS to_status,
            c.asset_id,
            a.name AS asset_name,
            c.stig_id,
            COALESCE(sc.title, c.stig_id) AS stig_title
        FROM baseline_rules br
        LEFT JOIN checklist_rules cr
            ON cr.checklist_id = br.checklist_id AND cr.rule_id = br.rule_id
        LEFT JOIN checklists c     ON c.id = br.checklist_id
        LEFT JOIN assets a         ON a.id = c.asset_id
        LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
        WHERE br.baseline_id = $1
          AND br.status != COALESCE(cr.status, 'not_reviewed')
          -- Drop orphan rows from deleted checklists.
          AND c.id IS NOT NULL
        ORDER BY a.name, c.stig_id, br.rule_id
        "#,
    )
    .bind(&id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!("baseline diff failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let unchanged: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
          FROM baseline_rules br
          LEFT JOIN checklist_rules cr
            ON cr.checklist_id = br.checklist_id AND cr.rule_id = br.rule_id
         WHERE br.baseline_id = $1
           AND br.status = COALESCE(cr.status, 'not_reviewed')
        "#,
    )
    .bind(&id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("baseline unchanged count failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut regressed = Vec::new();
    let mut improved = Vec::new();
    for row in rows {
        let to_open = row.to_status == "open";
        let to_better = is_better(&row.to_status);
        let from_open = row.from_status == "open";
        let from_better = is_better(&row.from_status);

        if (from_better || row.from_status == "not_reviewed") && to_open {
            // Was reviewed-good or untouched; now Open → regression.
            regressed.push(row);
        } else if from_better && row.to_status == "not_reviewed" {
            // Lost a previously-reviewed-good status → regression.
            regressed.push(row);
        } else if from_open && to_better {
            // Was Open; now reviewed-good → improvement.
            improved.push(row);
        }
        // Anything else (NaF↔NA, etc.) is neither regressed nor improved.
    }

    Ok(Json(DiffResponse {
        baseline,
        regressed,
        improved,
        unchanged,
    }))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn fetch_one(pool: &sqlx::PgPool, id: &str) -> Result<BaselineRow, StatusCode> {
    let threshold = stale_baseline_days();
    sqlx::query_as::<_, BaselineRow>(
        r#"
        SELECT
            b.id,
            b.name,
            b.created_by,
            u.display_name AS created_by_name,
            b.created_at,
            COALESCE((SELECT COUNT(*) FROM baseline_rules br WHERE br.baseline_id = b.id), 0)
                ::BIGINT AS rule_count,
            (b.created_at < NOW() - ($2 || ' days')::INTERVAL) AS is_stale
          FROM baselines b
          JOIN users u ON u.id = b.created_by
         WHERE b.id = $1
        "#,
    )
    .bind(id)
    .bind(threshold.to_string())
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!("baseline fetch_one failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)
}

