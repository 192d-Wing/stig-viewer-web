use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
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
    pub reviewed_rules: i64,   // count of rule rows that have been touched
    pub total_rules: i64,      // sum of stig.rule_count across all checklists
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

    // Totals — independent, can run in parallel.
    let (assets_count, checklists_count, open_count, reviewed_count, total_rules) = tokio::join!(
        count_one(pool, "SELECT COUNT(*) FROM assets"),
        count_one(pool, "SELECT COUNT(*) FROM checklists"),
        count_one(
            pool,
            "SELECT COUNT(*) FROM checklist_rules WHERE status = 'open'"
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

fn map_db(e: sqlx::Error) -> StatusCode {
    tracing::error!("dashboard db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    map_db(e)
}
