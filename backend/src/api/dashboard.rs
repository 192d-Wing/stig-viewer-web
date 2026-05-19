use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardResponse {
    pub totals: Totals,
    pub by_asset: Vec<AssetSummary>,
    pub top_open_rules: Vec<TopRule>,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Totals {
    pub assets: i64,
    pub checklists: i64,
    pub open_findings: i64,
    pub overdue_findings: i64, // Open with due_date < CURRENT_DATE
    pub stale_findings: i64,   // Open with no activity in N days (default 30)
    pub stale_threshold_days: i64,
    pub reviewed_rules: i64,   // count of rule rows that have been touched
    pub total_rules: i64,      // sum of stig.rule_count across all checklists
}

fn stale_threshold_days() -> i64 {
    std::env::var("STALE_FINDING_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &i64| n > 0)
        .unwrap_or(30)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetSummary {
    pub id: String,
    pub name: String,
    pub owner_name: String,
    pub checklists: Vec<ChecklistSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistSummary {
    pub id: String,
    pub stig_id: String,
    pub stig_title: String,
    pub rule_count: i64,
    pub open_count: i64,
    pub overdue_count: i64,
    pub naf_count: i64,
    pub na_count: i64,
    pub reviewed_count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TopRule {
    pub rule_id: String,
    pub affected_systems: i64,
}

/// GET /api/dashboard
pub async fn get_handler(
    State(state): State<AppState>,
) -> Result<Json<DashboardResponse>, StatusCode> {
    let pool = state.pool.as_ref();

    let stale_days = stale_threshold_days();

    // Totals — independent, can run in parallel.
    let (
        assets_count,
        checklists_count,
        open_count,
        overdue_count,
        stale_count,
        reviewed_count,
        total_rules,
    ) = tokio::join!(
        count_one(pool, "SELECT COUNT(*) FROM assets"),
        count_one(pool, "SELECT COUNT(*) FROM checklists"),
        count_one(
            pool,
            "SELECT COUNT(*) FROM checklist_rules WHERE status = 'open'",
        ),
        count_one(
            pool,
            "SELECT COUNT(*) FROM checklist_rules \
             WHERE status = 'open' AND due_date IS NOT NULL AND due_date < CURRENT_DATE",
        ),
        count_one_with(
            pool,
            // No activity in N days. Uses updated_at as proxy; revisit if a
            // dedicated status_changed_at column is added later.
            "SELECT COUNT(*) FROM checklist_rules \
             WHERE status = 'open' AND updated_at < NOW() - ($1 || ' days')::INTERVAL",
            stale_days.to_string(),
        ),
        count_one(pool, "SELECT COUNT(*) FROM checklist_rules"),
        count_one(
            pool,
            r#"
            SELECT COALESCE(SUM(sc.rule_count), 0)
              FROM checklists c
              LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
            "#,
        ),
    );

    let totals = Totals {
        assets: assets_count.map_err(map_db)?,
        checklists: checklists_count.map_err(map_db)?,
        open_findings: open_count.map_err(map_db)?,
        overdue_findings: overdue_count.map_err(map_db)?,
        stale_findings: stale_count.map_err(map_db)?,
        stale_threshold_days: stale_days,
        reviewed_rules: reviewed_count.map_err(map_db)?,
        total_rules: total_rules.map_err(map_db)?,
    };

    // Per-asset / per-checklist breakdown. One row per (asset, checklist);
    // assets with no checklists show up with NULL checklist columns and are
    // included in by_asset with an empty checklists array.
    let rows = sqlx::query(
        r#"
        SELECT
            a.id              AS asset_id,
            a.name            AS asset_name,
            u.display_name    AS owner_name,
            c.id              AS checklist_id,
            c.stig_id         AS stig_id,
            COALESCE(sc.title, c.stig_id) AS stig_title,
            COALESCE(sc.rule_count, 0)::BIGINT AS rule_count,
            COALESCE(SUM(CASE WHEN cr.status = 'open' THEN 1 ELSE 0 END), 0)           AS open_count,
            COALESCE(SUM(CASE WHEN cr.status = 'open' AND cr.due_date IS NOT NULL
                                 AND cr.due_date < CURRENT_DATE THEN 1 ELSE 0 END), 0) AS overdue_count,
            COALESCE(SUM(CASE WHEN cr.status = 'not_a_finding' THEN 1 ELSE 0 END), 0)  AS naf_count,
            COALESCE(SUM(CASE WHEN cr.status = 'not_applicable' THEN 1 ELSE 0 END), 0) AS na_count,
            COUNT(cr.rule_id) AS reviewed_count
        FROM assets a
        JOIN users u ON u.id = a.owner_id
        LEFT JOIN checklists c ON c.asset_id = a.id
        LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
        LEFT JOIN checklist_rules cr ON cr.checklist_id = c.id
        GROUP BY a.id, a.name, u.display_name, c.id, c.stig_id, sc.title, sc.rule_count
        ORDER BY a.name, c.stig_id
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!("dashboard query failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut by_asset: Vec<AssetSummary> = Vec::new();
    for row in rows {
        let asset_id: String = row.try_get("asset_id").map_err(map_sqlx)?;
        let asset_name: String = row.try_get("asset_name").map_err(map_sqlx)?;
        let owner_name: String = row.try_get("owner_name").map_err(map_sqlx)?;
        let checklist_id: Option<String> = row.try_get("checklist_id").map_err(map_sqlx)?;

        let entry = match by_asset.last_mut() {
            Some(e) if e.id == asset_id => e,
            _ => {
                by_asset.push(AssetSummary {
                    id: asset_id.clone(),
                    name: asset_name,
                    owner_name,
                    checklists: Vec::new(),
                });
                by_asset.last_mut().unwrap()
            }
        };

        if let Some(cid) = checklist_id {
            entry.checklists.push(ChecklistSummary {
                id: cid,
                stig_id: row.try_get("stig_id").map_err(map_sqlx)?,
                stig_title: row.try_get("stig_title").map_err(map_sqlx)?,
                rule_count: row.try_get("rule_count").map_err(map_sqlx)?,
                open_count: row.try_get("open_count").map_err(map_sqlx)?,
                overdue_count: row.try_get("overdue_count").map_err(map_sqlx)?,
                naf_count: row.try_get("naf_count").map_err(map_sqlx)?,
                na_count: row.try_get("na_count").map_err(map_sqlx)?,
                reviewed_count: row.try_get("reviewed_count").map_err(map_sqlx)?,
            });
        }
    }

    // Top open rules across all checklists.
    let top_rows = sqlx::query(
        r#"
        SELECT rule_id, COUNT(DISTINCT checklist_id) AS affected
          FROM checklist_rules
         WHERE status = 'open'
         GROUP BY rule_id
         ORDER BY affected DESC, rule_id ASC
         LIMIT 10
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!("dashboard top-rules query failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let top_open_rules = top_rows
        .into_iter()
        .map(|r| -> Result<TopRule, sqlx::Error> {
            Ok(TopRule {
                rule_id: r.try_get("rule_id")?,
                affected_systems: r.try_get("affected")?,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sqlx)?;

    Ok(Json(DashboardResponse {
        totals,
        by_asset,
        top_open_rules,
    }))
}

async fn count_one(pool: &sqlx::PgPool, sql: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(sql).fetch_one(pool).await
}

async fn count_one_with(
    pool: &sqlx::PgPool,
    sql: &str,
    arg: String,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(sql)
        .bind(arg)
        .fetch_one(pool)
        .await
}

// ── Snapshots ───────────────────────────────────────────────────────────────

/// Capture one snapshot row per current checklist. Idempotent at second
/// resolution but the (captured_at, checklist_id) PK means two snapshots
/// within the same second would collide; for the daily scheduler that's
/// not a concern, and the test-only manual trigger sleeps to dodge it.
pub async fn take_snapshot(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        r#"
        INSERT INTO checklist_snapshots
            (checklist_id, asset_id, stig_id, rule_count,
             open_count, naf_count, na_count, reviewed_count)
        SELECT
            c.id,
            c.asset_id,
            c.stig_id,
            COALESCE(sc.rule_count, 0),
            COALESCE(SUM(CASE WHEN cr.status = 'open' THEN 1 ELSE 0 END), 0)::INT,
            COALESCE(SUM(CASE WHEN cr.status = 'not_a_finding' THEN 1 ELSE 0 END), 0)::INT,
            COALESCE(SUM(CASE WHEN cr.status = 'not_applicable' THEN 1 ELSE 0 END), 0)::INT,
            COUNT(cr.rule_id)::INT
        FROM checklists c
        LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
        LEFT JOIN checklist_rules cr ON cr.checklist_id = c.id
        GROUP BY c.id, c.asset_id, c.stig_id, sc.rule_count
        "#,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// POST /api/test/snapshot — manually take a snapshot. Only registered
/// when STIG_ENV != "production"; used by E2E to populate trend data.
pub async fn snapshot_handler(State(state): State<AppState>) -> Result<StatusCode, StatusCode> {
    take_snapshot(state.pool.as_ref()).await.map_err(map_db)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct TrendQuery {
    #[serde(default = "default_days")]
    pub days: i64,
}

fn default_days() -> i64 {
    30
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrendResponse {
    pub overall: Vec<TrendPoint>,
    pub by_asset: Vec<AssetTrend>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrendPoint {
    pub captured_at: DateTime<Utc>,
    pub open: i64,
    pub naf: i64,
    pub na: i64,
    pub reviewed: i64,
    pub total: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetTrend {
    pub asset_id: String,
    pub asset_name: String,
    pub series: Vec<TrendPoint>,
}

/// GET /api/dashboard/trend?days=N — aggregated trend over the last N days.
///
/// Buckets by `captured_at` (one bucket per snapshot run) and sums counts
/// across checklists. Per-asset series sums across an asset's checklists.
pub async fn trend_handler(
    State(state): State<AppState>,
    Query(params): Query<TrendQuery>,
) -> Result<Json<TrendResponse>, StatusCode> {
    let pool = state.pool.as_ref();
    let days = params.days.clamp(1, 365);

    // Overall: one row per captured_at, summed across all checklists.
    let overall_rows = sqlx::query(
        r#"
        SELECT
            captured_at,
            SUM(open_count)::BIGINT     AS open,
            SUM(naf_count)::BIGINT      AS naf,
            SUM(na_count)::BIGINT       AS na,
            SUM(reviewed_count)::BIGINT AS reviewed,
            SUM(rule_count)::BIGINT     AS total
        FROM checklist_snapshots
        WHERE captured_at >= NOW() - ($1 || ' days')::INTERVAL
        GROUP BY captured_at
        ORDER BY captured_at ASC
        "#,
    )
    .bind(days.to_string())
    .fetch_all(pool)
    .await
    .map_err(map_db)?;

    let overall = overall_rows
        .into_iter()
        .map(|r| -> Result<TrendPoint, sqlx::Error> {
            Ok(TrendPoint {
                captured_at: r.try_get("captured_at")?,
                open: r.try_get("open")?,
                naf: r.try_get("naf")?,
                na: r.try_get("na")?,
                reviewed: r.try_get("reviewed")?,
                total: r.try_get("total")?,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_db)?;

    // Per-asset: rows are sorted by asset, then by captured_at, so we can
    // fold them into AssetTrend entries in a single pass.
    let asset_rows = sqlx::query(
        r#"
        SELECT
            s.asset_id,
            a.name AS asset_name,
            s.captured_at,
            SUM(s.open_count)::BIGINT     AS open,
            SUM(s.naf_count)::BIGINT      AS naf,
            SUM(s.na_count)::BIGINT       AS na,
            SUM(s.reviewed_count)::BIGINT AS reviewed,
            SUM(s.rule_count)::BIGINT     AS total
        FROM checklist_snapshots s
        JOIN assets a ON a.id = s.asset_id
        WHERE s.captured_at >= NOW() - ($1 || ' days')::INTERVAL
        GROUP BY s.asset_id, a.name, s.captured_at
        ORDER BY s.asset_id, s.captured_at ASC
        "#,
    )
    .bind(days.to_string())
    .fetch_all(pool)
    .await
    .map_err(map_db)?;

    let mut by_asset: Vec<AssetTrend> = Vec::new();
    for r in asset_rows {
        let asset_id: String = r.try_get("asset_id").map_err(map_db)?;
        let asset_name: String = r.try_get("asset_name").map_err(map_db)?;
        let point = TrendPoint {
            captured_at: r.try_get("captured_at").map_err(map_db)?,
            open: r.try_get("open").map_err(map_db)?,
            naf: r.try_get("naf").map_err(map_db)?,
            na: r.try_get("na").map_err(map_db)?,
            reviewed: r.try_get("reviewed").map_err(map_db)?,
            total: r.try_get("total").map_err(map_db)?,
        };
        match by_asset.last_mut() {
            Some(t) if t.asset_id == asset_id => t.series.push(point),
            _ => by_asset.push(AssetTrend {
                asset_id,
                asset_name,
                series: vec![point],
            }),
        }
    }

    Ok(Json(TrendResponse { overall, by_asset }))
}

fn map_db(e: sqlx::Error) -> StatusCode {
    tracing::error!("dashboard db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    map_db(e)
}
