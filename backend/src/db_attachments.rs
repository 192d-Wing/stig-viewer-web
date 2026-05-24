use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRow {
    pub id: String,
    pub checklist_id: String,
    pub rule_id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub uploaded_by: String,
    pub uploaded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentCountRow {
    pub rule_id: String,
    pub count: i64,
}

pub async fn insert(pool: &PgPool, row: &AttachmentRow) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO attachments
            (id, checklist_id, rule_id, filename, mime_type,
             size_bytes, sha256, uploaded_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(&row.id)
    .bind(&row.checklist_id)
    .bind(&row.rule_id)
    .bind(&row.filename)
    .bind(&row.mime_type)
    .bind(row.size_bytes)
    .bind(&row.sha256)
    .bind(&row.uploaded_by)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_for_rule(
    pool: &PgPool,
    checklist_id: &str,
    rule_id: &str,
) -> Result<Vec<AttachmentRow>> {
    let rows = sqlx::query_as::<_, AttachmentRow>(
        "SELECT * FROM attachments \
         WHERE checklist_id = $1 AND rule_id = $2 \
         ORDER BY uploaded_at DESC",
    )
    .bind(checklist_id)
    .bind(rule_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

#[allow(dead_code)]
pub async fn list_for_checklist(
    pool: &PgPool,
    checklist_id: &str,
) -> Result<Vec<AttachmentRow>> {
    let rows = sqlx::query_as::<_, AttachmentRow>(
        "SELECT * FROM attachments \
         WHERE checklist_id = $1 \
         ORDER BY uploaded_at DESC",
    )
    .bind(checklist_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Count attachments per rule for one checklist. Used by the UI to
/// decorate the rule list with a paperclip indicator without
/// requiring N per-rule queries.
pub async fn counts_for_checklist(
    pool: &PgPool,
    checklist_id: &str,
) -> Result<Vec<AttachmentCountRow>> {
    let rows = sqlx::query_as::<_, AttachmentCountRow>(
        "SELECT rule_id, COUNT(*)::BIGINT AS count \
         FROM attachments \
         WHERE checklist_id = $1 \
         GROUP BY rule_id",
    )
    .bind(checklist_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_by_id(pool: &PgPool, id: &str) -> Result<Option<AttachmentRow>> {
    let row = sqlx::query_as::<_, AttachmentRow>(
        "SELECT * FROM attachments WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn delete(pool: &PgPool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM attachments WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
