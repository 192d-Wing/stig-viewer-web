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
    /// When true, transitions to a closing finding status
    /// (`not_a_finding` / `not_applicable`) on this asset's checklists do
    /// NOT apply directly. They instead create a `finding_approvals` row
    /// that a reviewer/admin must approve before the rule's status
    /// actually changes. Default FALSE preserves legacy behavior.
    #[sqlx(default)]
    pub requires_approval: bool,
    /// Per-asset scheduled compliance-report email cadence.
    /// One of `"off"` | `"daily"` | `"weekly"` | `"monthly"`. Default
    /// `"off"` preserves legacy behavior — only the on-demand "Email
    /// report now" path fires. See migration 032_asset_email_schedule.
    #[sqlx(default)]
    pub email_cadence: String,
    /// Timestamp of the last scheduled (or attempted) per-asset email
    /// send. NULL when no scheduled tick has ever fired for this asset.
    /// Used by the scheduler to gate the cadence interval — see
    /// `run_asset_email_schedules` in `asset_email_cc.rs`.
    #[sqlx(default)]
    pub email_last_sent_at: Option<DateTime<Utc>>,
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

/// Update the per-asset approval-policy flag.
pub async fn set_requires_approval(
    pool: &PgPool,
    id: &str,
    requires_approval: bool,
) -> Result<()> {
    sqlx::query(
        "UPDATE assets \
         SET requires_approval = $1, updated_at = NOW() \
         WHERE id = $2",
    )
    .bind(requires_approval)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update the per-asset scheduled email cadence. Caller is responsible
/// for validating the value against the allowlist (see
/// `api::assets::VALID_EMAIL_CADENCES`).
pub async fn set_email_cadence(pool: &PgPool, id: &str, cadence: &str) -> Result<()> {
    sqlx::query(
        "UPDATE assets \
         SET email_cadence = $1, updated_at = NOW() \
         WHERE id = $2",
    )
    .bind(cadence)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Stamp `email_last_sent_at = NOW()` after a scheduled (or attempted)
/// per-asset email send. Called from `run_asset_email_schedules` after
/// each tick — whether the send fell into dryrun mode or actually
/// reached SMTP — so the cadence-interval gate is monotonic.
pub async fn stamp_email_last_sent_at(pool: &PgPool, id: &str) -> Result<()> {
    sqlx::query("UPDATE assets SET email_last_sent_at = NOW() WHERE id = $1")
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
