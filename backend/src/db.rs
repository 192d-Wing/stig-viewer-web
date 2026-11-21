use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};

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

/// Longest a bounded statement may run or wait for a lock, in milliseconds.
///
/// Why Postgres has to enforce this and the application cannot: in sqlx 0.8.6
/// (locked), `PgConnection::run` writes Bind/Execute/Sync and counts a pending
/// ReadyForQuery before it flushes, so dropping the query future sends
/// nothing further, and sqlx-postgres has no CancelRequest. Dropping a
/// `PoolConnection` spawns `return_to_pool`, which pings and waits for the
/// outstanding ReadyForQuery with no timeout, and the floating connection
/// keeps its pool permit meanwhile. A statement whose future was dropped
/// therefore keeps running on the server and holds one of the pool's slots
/// until Postgres finishes it. A transaction-local `statement_timeout` /
/// `lock_timeout` caps that: a dropped read pins its connection for at most
/// this long after the drop.
///
/// Rule for callers of `begin_bounded`: never call anything that takes the
/// pool (including `db_audit::record_or_log`) while the transaction is open.
/// Commit first, otherwise one request holds two connections and admitted
/// tasks can deadlock on the pool.
pub const STATEMENT_TIMEOUT_MS: i64 = 8_000;

/// Set transaction-local statement and lock timeouts of `ms` milliseconds.
pub(crate) async fn bound_ms(tx: &mut sqlx::PgConnection, ms: i64) -> Result<()> {
    sqlx::query(
        "SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', $1, true)",
    )
    .bind(ms.to_string())
    .execute(tx)
    .await?;
    Ok(())
}

/// Begin a transaction with the transaction-local timeouts already set.
pub async fn begin_bounded(pool: &PgPool) -> Result<Transaction<'static, Postgres>> {
    begin_bounded_ms(pool, STATEMENT_TIMEOUT_MS).await
}

/// [`begin_bounded`] with an explicit bound (tests use a short one).
pub(crate) async fn begin_bounded_ms(
    pool: &PgPool,
    ms: i64,
) -> Result<Transaction<'static, Postgres>> {
    let mut tx = pool.begin().await?;
    bound_ms(&mut tx, ms).await?;
    Ok(tx)
}

/// True when the error is Postgres cutting a statement (`57014`) or a lock
/// wait (`55P03`) short.
pub fn is_timeout(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        matches!(
            c.downcast_ref::<sqlx::Error>(),
            Some(sqlx::Error::Database(d)) if matches!(d.code().as_deref(), Some("57014" | "55P03"))
        )
    })
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
