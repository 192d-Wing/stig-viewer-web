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

/// Connect the application pool without touching the schema.
pub async fn connect_pool(database_url: &str) -> Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?)
}

/// Run pending migrations on `pool` (the role must own the schema objects).
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
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

/// Upsert a catalog entry — inserts or updates on conflict.
pub async fn upsert_catalog(pool: &PgPool, entry: &CatalogEntry) -> Result<()> {
    upsert_catalog_on(pool, entry).await
}

/// [`upsert_catalog`] inside the caller's transaction.
pub async fn upsert_catalog_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entry: &CatalogEntry,
) -> Result<()> {
    upsert_catalog_on(&mut **tx, entry).await
}

async fn upsert_catalog_on<'e, E>(exec: E, entry: &CatalogEntry) -> Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
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
    .execute(exec)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn upsert_catalog_tx_rolls_back_with_its_transaction(pool: PgPool) {
        let entry = CatalogEntry {
            id: "tx-test".into(),
            title: "T".into(),
            category: "Linux".into(),
            version: "1".into(),
            release_info: String::new(),
            rule_count: 1,
            json_path: "x".into(),
            last_updated: Utc::now(),
        };
        let mut tx = pool.begin().await.unwrap();
        upsert_catalog_tx(&mut tx, &entry).await.unwrap();
        tx.rollback().await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stigs_catalog")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        let mut tx = pool.begin().await.unwrap();
        upsert_catalog_tx(&mut tx, &entry).await.unwrap();
        tx.commit().await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stigs_catalog")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }
}
