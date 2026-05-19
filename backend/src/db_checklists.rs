use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistRow {
    pub id: String,
    pub asset_id: String,
    pub stig_id: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistRuleRow {
    pub checklist_id: String,
    pub rule_id: String,
    pub status: String,
    pub finding_details: String,
    pub comments: String,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<String>,
}

pub async fn list_checklists_for_asset(
    pool: &PgPool,
    asset_id: &str,
) -> Result<Vec<ChecklistRow>> {
    let rows = sqlx::query_as::<_, ChecklistRow>(
        "SELECT * FROM checklists WHERE asset_id = $1 ORDER BY created_at DESC",
    )
    .bind(asset_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_checklist(pool: &PgPool, id: &str) -> Result<Option<ChecklistRow>> {
    let row = sqlx::query_as::<_, ChecklistRow>("SELECT * FROM checklists WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

pub async fn insert_checklist(pool: &PgPool, row: &ChecklistRow) -> Result<()> {
    sqlx::query(
        "INSERT INTO checklists (id, asset_id, stig_id, status) VALUES ($1, $2, $3, $4)",
    )
    .bind(&row.id)
    .bind(&row.asset_id)
    .bind(&row.stig_id)
    .bind(&row.status)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_checklist(pool: &PgPool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM checklists WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_rule_overrides(
    pool: &PgPool,
    checklist_id: &str,
) -> Result<Vec<ChecklistRuleRow>> {
    let rows = sqlx::query_as::<_, ChecklistRuleRow>(
        "SELECT * FROM checklist_rules WHERE checklist_id = $1",
    )
    .bind(checklist_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn upsert_rule(
    pool: &PgPool,
    checklist_id: &str,
    rule_id: &str,
    status: &str,
    finding_details: &str,
    comments: &str,
    updated_by: &str,
) -> Result<ChecklistRuleRow> {
    let row = sqlx::query_as::<_, ChecklistRuleRow>(
        r#"
        INSERT INTO checklist_rules
            (checklist_id, rule_id, status, finding_details, comments, updated_by, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (checklist_id, rule_id) DO UPDATE
           SET status = EXCLUDED.status,
               finding_details = EXCLUDED.finding_details,
               comments = EXCLUDED.comments,
               updated_by = EXCLUDED.updated_by,
               updated_at = NOW()
        RETURNING *
        "#,
    )
    .bind(checklist_id)
    .bind(rule_id)
    .bind(status)
    .bind(finding_details)
    .bind(comments)
    .bind(updated_by)
    .fetch_one(pool)
    .await?;

    // Bump the parent checklist's updated_at so the asset list reflects activity.
    sqlx::query("UPDATE checklists SET updated_at = NOW() WHERE id = $1")
        .bind(checklist_id)
        .execute(pool)
        .await?;

    Ok(row)
}
