use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AssetRow {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub description: String,
    pub classification: String,
    pub owner_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AssetSummary {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub classification: String,
    pub owner_id: String,
    pub owner_name: String,
    pub updated_at: DateTime<Utc>,
}

pub async fn list_assets(pool: &PgPool) -> Result<Vec<AssetSummary>> {
    let rows = sqlx::query_as::<_, AssetSummary>(
        r#"
        SELECT a.id, a.name, a.hostname, a.classification,
               a.owner_id, u.display_name AS owner_name, a.updated_at
          FROM assets a
          JOIN users u ON u.id = a.owner_id
         ORDER BY a.updated_at DESC
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_asset(pool: &PgPool, id: &str) -> Result<Option<AssetRow>> {
    let row = sqlx::query_as::<_, AssetRow>("SELECT * FROM assets WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

pub async fn insert_asset(pool: &PgPool, asset: &AssetRow) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO assets
            (id, name, hostname, description, classification, owner_id)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(&asset.id)
    .bind(&asset.name)
    .bind(&asset.hostname)
    .bind(&asset.description)
    .bind(&asset.classification)
    .bind(&asset.owner_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_asset(
    pool: &PgPool,
    id: &str,
    name: &str,
    hostname: &str,
    description: &str,
    classification: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE assets
           SET name = $1, hostname = $2, description = $3,
               classification = $4, updated_at = NOW()
         WHERE id = $5
        "#,
    )
    .bind(name)
    .bind(hostname)
    .bind(description)
    .bind(classification)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_asset(pool: &PgPool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM assets WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
