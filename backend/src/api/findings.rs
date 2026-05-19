use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingsQuery {
    #[serde(default = "default_status")]
    pub status: String,
    pub rule_id: Option<String>,
    pub asset_id: Option<String>,
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
    pub owner_name: String,
}

/// GET /api/findings?status=open[&ruleId=...][&assetId=...]
pub async fn list_handler(
    State(state): State<AppState>,
    Query(params): Query<FindingsQuery>,
) -> Result<Json<Vec<Finding>>, StatusCode> {
    if !is_valid_status(&params.status) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let rows = sqlx::query_as::<_, Finding>(
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
            u.display_name   AS owner_name
        FROM checklist_rules cr
        JOIN checklists c ON c.id = cr.checklist_id
        JOIN assets a     ON a.id = c.asset_id
        JOIN users u      ON u.id = a.owner_id
        LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
        WHERE cr.status = $1
          AND ($2::text IS NULL OR cr.rule_id  = $2)
          AND ($3::text IS NULL OR c.asset_id  = $3)
        ORDER BY a.name, c.stig_id, cr.rule_id
        "#,
    )
    .bind(&params.status)
    .bind(params.rule_id.as_deref())
    .bind(params.asset_id.as_deref())
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("findings query failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(rows))
}

fn is_valid_status(s: &str) -> bool {
    matches!(s, "open" | "not_a_finding" | "not_applicable" | "not_reviewed")
}
