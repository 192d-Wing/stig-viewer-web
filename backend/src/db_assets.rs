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
    #[sqlx(default)]
    pub tags: Vec<String>,
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
    #[sqlx(default)]
    pub tags: Vec<String>,
}

pub async fn list_assets(pool: &PgPool) -> Result<Vec<AssetSummary>> {
    let mut rows = sqlx::query_as::<_, AssetSummary>(
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

    // Attach tags in a single grouped query.
    let tag_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT asset_id, tag FROM asset_tags ORDER BY asset_id, tag",
    )
    .fetch_all(pool)
    .await?;
    let mut by_asset: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for (asset_id, tag) in tag_rows {
        by_asset.entry(asset_id).or_default().push(tag);
    }
    for r in &mut rows {
        if let Some(tags) = by_asset.remove(&r.id) {
            r.tags = tags;
        }
    }
    Ok(rows)
}

pub async fn get_asset(pool: &PgPool, id: &str) -> Result<Option<AssetRow>> {
    let row = sqlx::query_as::<_, AssetRow>("SELECT * FROM assets WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let mut row = match row {
        Some(r) => r,
        None => return Ok(None),
    };
    let tags: Vec<String> =
        sqlx::query_scalar("SELECT tag FROM asset_tags WHERE asset_id = $1 ORDER BY tag")
            .bind(id)
            .fetch_all(pool)
            .await?;
    row.tags = tags;
    Ok(Some(row))
}

/// Replace the asset's tag set. Inserts/deletes in a single transaction.
pub async fn replace_tags(pool: &PgPool, asset_id: &str, tags: &[String]) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM asset_tags WHERE asset_id = $1")
        .bind(asset_id)
        .execute(&mut *tx)
        .await?;
    for tag in tags {
        sqlx::query("INSERT INTO asset_tags (asset_id, tag) VALUES ($1, $2)")
            .bind(asset_id)
            .bind(tag)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
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
