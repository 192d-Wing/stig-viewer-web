use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};

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

/// Return all catalog entries, optionally filtered by category.
pub async fn list_catalog(pool: &PgPool, category: Option<&str>) -> Result<Vec<CatalogEntry>> {
    let rows = match category {
        Some(cat) => {
            sqlx::query_as::<_, CatalogEntry>(
                "SELECT * FROM stigs_catalog WHERE category = $1 ORDER BY title",
            )
            .bind(cat)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, CatalogEntry>(
                "SELECT * FROM stigs_catalog ORDER BY category, title",
            )
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows)
}

/// Count rows in the catalog (used by /api/health).
pub async fn count_catalog(pool: &PgPool) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM stigs_catalog")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Upsert a catalog entry — inserts or updates on conflict.
pub async fn upsert_catalog(pool: &PgPool, entry: &CatalogEntry) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO stigs_catalog
            (id, title, category, version, release_info, rule_count, json_path, last_updated)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (id) DO UPDATE SET
            title        = EXCLUDED.title,
            category     = EXCLUDED.category,
            version      = EXCLUDED.version,
            release_info = EXCLUDED.release_info,
            rule_count   = EXCLUDED.rule_count,
            json_path    = EXCLUDED.json_path,
            last_updated = NOW()
        "#,
    )
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
