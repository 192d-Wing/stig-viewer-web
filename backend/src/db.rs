use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, PgPool};

/// Catalog entry as stored in PostgreSQL and returned by GET /api/catalog.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    pub id: String,
    pub title: String,
    pub category: String,
    pub version: String,
    pub release_info: String,
    pub rule_count: i32,
    pub json_path: String,
    pub last_updated: DateTime<Utc>,
}

/// Create a connection pool and run pending migrations.
pub async fn init_pool(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}

/// Return all catalog entries in the given org, optionally filtered by category.
pub async fn list_catalog(
    pool: &PgPool,
    org_id: i64,
    category: Option<&str>,
) -> Result<Vec<CatalogEntry>> {
    let rows = match category {
        Some(cat) => {
            sqlx::query_as::<_, CatalogEntry>(
                "SELECT id, title, category, version, release_info, rule_count, \
                        json_path, last_updated \
                 FROM stigs_catalog WHERE org_id = $1 AND category = $2 ORDER BY title",
            )
            .bind(org_id)
            .bind(cat)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, CatalogEntry>(
                "SELECT id, title, category, version, release_info, rule_count, \
                        json_path, last_updated \
                 FROM stigs_catalog WHERE org_id = $1 ORDER BY category, title",
            )
            .bind(org_id)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows)
}

/// Count rows in the catalog for an org (used by /api/health & /api/readyz).
pub async fn count_catalog(pool: &PgPool, org_id: i64) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM stigs_catalog WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Per-user review state for one STIG. `asset_info` and `rule_overrides` are
/// opaque JSON blobs serialized from / deserialized by the frontend; the
/// backend never interprets their shape.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub stig_id: String,
    pub asset_info: serde_json::Value,
    pub rule_overrides: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

/// Fetch a user's workspace for a STIG within an org. `Ok(None)` means the
/// user has never touched it in this tenant.
pub async fn get_workspace(
    pool: &PgPool,
    org_id: i64,
    user_sub: &str,
    stig_id: &str,
) -> Result<Option<Workspace>> {
    let row = sqlx::query_as::<_, Workspace>(
        "SELECT stig_id, asset_info, rule_overrides, updated_at \
         FROM workspaces WHERE org_id = $1 AND user_sub = $2 AND stig_id = $3",
    )
    .bind(org_id)
    .bind(user_sub)
    .bind(stig_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Upsert a user's workspace for a STIG within an org.
pub async fn upsert_workspace(
    pool: &PgPool,
    org_id: i64,
    user_sub: &str,
    stig_id: &str,
    asset_info: &serde_json::Value,
    rule_overrides: &serde_json::Value,
) -> Result<Workspace> {
    let row = sqlx::query_as::<_, Workspace>(
        r#"
        INSERT INTO workspaces
            (org_id, user_sub, stig_id, asset_info, rule_overrides, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (org_id, user_sub, stig_id) DO UPDATE SET
            asset_info     = EXCLUDED.asset_info,
            rule_overrides = EXCLUDED.rule_overrides,
            updated_at     = NOW()
        RETURNING stig_id, asset_info, rule_overrides, updated_at
        "#,
    )
    .bind(org_id)
    .bind(user_sub)
    .bind(stig_id)
    .bind(asset_info)
    .bind(rule_overrides)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Upsert a catalog entry in an org — inserts or updates on (org_id, id).
pub async fn upsert_catalog(pool: &PgPool, org_id: i64, entry: &CatalogEntry) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO stigs_catalog
            (org_id, id, title, category, version, release_info, rule_count, json_path, last_updated)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        ON CONFLICT (id) DO UPDATE SET
            org_id       = EXCLUDED.org_id,
            title        = EXCLUDED.title,
            category     = EXCLUDED.category,
            version      = EXCLUDED.version,
            release_info = EXCLUDED.release_info,
            rule_count   = EXCLUDED.rule_count,
            json_path    = EXCLUDED.json_path,
            last_updated = NOW()
        "#,
    )
    .bind(org_id)
    .bind(&entry.id)
    .bind(&entry.title)
    .bind(&entry.category)
    .bind(&entry.version)
    .bind(&entry.release_info)
    .bind(entry.rule_count)
    .bind(&entry.json_path)
    .execute(pool)
    .await?;
    Ok(())
}
