//! AC-8 notice acknowledgements (`login_notice_acks`): issue, atomically
//! consume at login start, and take back at login completion for the audit link.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

/// What an acknowledgement recorded, returned once at login completion.
#[derive(Debug, sqlx::FromRow)]
pub struct AckRecord {
    pub created_at: DateTime<Utc>,
    pub ip: String,
    pub user_agent: String,
    pub notice_version: String,
    pub method: Option<String>,
}

/// Insert a fresh acknowledgement, pruning expired/stale rows first.
pub async fn insert_ack(
    pool: &PgPool,
    id: &str,
    version: &str,
    ip: &str,
    user_agent: &str,
    ttl_secs: i64,
) -> Result<()> {
    // Two index-friendly deletes (expiry partial index, created_at index).
    sqlx::query("DELETE FROM login_notice_acks WHERE consumed_at IS NULL AND expires_at < NOW()")
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM login_notice_acks WHERE created_at < NOW() - INTERVAL '1 hour'")
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO login_notice_acks (id, expires_at, notice_version, ip, user_agent) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(Utc::now() + Duration::seconds(ttl_secs))
    .bind(version)
    .bind(ip)
    .bind(user_agent)
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomically consume an unused, unexpired acknowledgement for the current
/// notice version. True exactly once per issued row.
pub async fn consume_ack(
    pool: &PgPool,
    id: &str,
    current_version: &str,
    method: &str,
    saml_request_id: Option<&str>,
) -> Result<bool> {
    let row: Option<String> = sqlx::query_scalar(
        "UPDATE login_notice_acks \
            SET consumed_at = NOW(), method = $3, saml_request_id = $4 \
          WHERE id = $1 AND consumed_at IS NULL AND expires_at > NOW() \
            AND notice_version = $2 \
        RETURNING id",
    )
    .bind(id)
    .bind(current_version)
    .bind(method)
    .bind(saml_request_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

pub async fn take_consumed_by_id(pool: &PgPool, id: &str) -> Result<Option<AckRecord>> {
    Ok(sqlx::query_as::<_, AckRecord>(
        "DELETE FROM login_notice_acks \
          WHERE id = $1 AND consumed_at IS NOT NULL \
            AND created_at > NOW() - INTERVAL '1 hour' \
        RETURNING created_at, ip, user_agent, notice_version, method",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

pub async fn take_consumed_by_saml_request(
    pool: &PgPool,
    req_id: &str,
) -> Result<Option<AckRecord>> {
    Ok(sqlx::query_as::<_, AckRecord>(
        "DELETE FROM login_notice_acks \
          WHERE saml_request_id = $1 AND consumed_at IS NOT NULL \
            AND created_at > NOW() - INTERVAL '1 hour' \
        RETURNING created_at, ip, user_agent, notice_version, method",
    )
    .bind(req_id)
    .fetch_optional(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "v1";

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn consume_succeeds_once(pool: PgPool) {
        insert_ack(&pool, "a1", V, "1.2.3.4", "ua", 300).await.unwrap();
        assert!(consume_ack(&pool, "a1", V, "oidc", None).await.unwrap());
        assert!(!consume_ack(&pool, "a1", V, "oidc", None).await.unwrap());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn expired_and_wrong_version_rejected(pool: PgPool) {
        insert_ack(&pool, "a1", V, "", "", 300).await.unwrap();
        insert_ack(&pool, "a2", V, "", "", 300).await.unwrap();
        sqlx::query("UPDATE login_notice_acks SET expires_at = NOW() - INTERVAL '1 second' WHERE id = 'a2'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(!consume_ack(&pool, "a2", V, "oidc", None).await.unwrap());
        assert!(!consume_ack(&pool, "a1", "other", "oidc", None).await.unwrap());
        assert!(consume_ack(&pool, "a1", V, "oidc", None).await.unwrap());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_removes_stale_keeps_fresh_consumed(pool: PgPool) {
        insert_ack(&pool, "old", V, "", "", 300).await.unwrap();
        insert_ack(&pool, "exp", V, "", "", 300).await.unwrap();
        insert_ack(&pool, "fresh", V, "", "", 300).await.unwrap();
        consume_ack(&pool, "fresh", V, "oidc", None).await.unwrap();
        sqlx::query("UPDATE login_notice_acks SET created_at = NOW() - INTERVAL '2 hours' WHERE id = 'old'")
            .execute(&pool).await.unwrap();
        sqlx::query("UPDATE login_notice_acks SET expires_at = NOW() - INTERVAL '1 second' WHERE id = 'exp'")
            .execute(&pool).await.unwrap();
        insert_ack(&pool, "new", V, "", "", 300).await.unwrap();
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM login_notice_acks ORDER BY id")
            .fetch_all(&pool).await.unwrap();
        assert_eq!(ids, vec!["fresh", "new"]);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn take_returns_once_and_refuses_unconsumed(pool: PgPool) {
        insert_ack(&pool, "a1", V, "9.9.9.9", "ua", 300).await.unwrap();
        assert!(take_consumed_by_id(&pool, "a1").await.unwrap().is_none());
        consume_ack(&pool, "a1", V, "saml", Some("_req1")).await.unwrap();
        let rec = take_consumed_by_saml_request(&pool, "_req1").await.unwrap().unwrap();
        assert_eq!(rec.ip, "9.9.9.9");
        assert_eq!(rec.method.as_deref(), Some("saml"));
        assert!(take_consumed_by_saml_request(&pool, "_req1").await.unwrap().is_none());
        insert_ack(&pool, "a2", V, "", "", 300).await.unwrap();
        consume_ack(&pool, "a2", V, "oidc", None).await.unwrap();
        assert!(take_consumed_by_id(&pool, "a2").await.unwrap().is_some());
        assert!(take_consumed_by_id(&pool, "a2").await.unwrap().is_none());
    }
}
