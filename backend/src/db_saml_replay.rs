//! SAML replay cache (`saml_seen_ids`, #62): a verified Assertion or Response
//! ID is accepted at most once, cluster-wide. Only a domain-separated SHA-256
//! of each ID is stored.

use crate::crypto;
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Rows are kept this long past their expiry before pruning, so a clock
/// difference between instances cannot reopen a replay window.
const PRUNE_MARGIN: &str = "10 minutes";

/// Lowercase hex SHA-256 of `"stig-viewer/saml-replay/v1\0" || kind || 0 || id`.
pub fn id_digest(kind: &str, id: &str) -> String {
    let mut m = Vec::with_capacity(32 + kind.len() + id.len());
    m.extend_from_slice(b"stig-viewer/saml-replay/v1\0");
    m.extend_from_slice(kind.as_bytes());
    m.push(0);
    m.extend_from_slice(id.as_bytes());
    crypto::digest::sha256_hex(&m)
}

/// Lowercase hex SHA-256 of `"stig-viewer/saml-nameid/v1\0" || name_id`, for
/// audit records that must identify a subject without storing it.
pub fn name_id_digest(name_id: &str) -> String {
    let mut m = Vec::with_capacity(32 + name_id.len());
    m.extend_from_slice(b"stig-viewer/saml-nameid/v1\0");
    m.extend_from_slice(name_id.as_bytes());
    crypto::digest::sha256_hex(&m)
}

/// Record every `(kind, id_digest)` in one statement. True when all were new;
/// false means at least one was already seen (a replay), in which case the
/// statement may still have recorded the new ones. Concurrent presentations
/// race on the primary key, so exactly one wins.
pub async fn record_first_use(
    pool: &PgPool,
    ids: &[(&'static str, String)],
    expires_at: DateTime<Utc>,
) -> Result<bool> {
    let kinds: Vec<&str> = ids.iter().map(|(k, _)| *k).collect();
    let digests: Vec<&str> = ids.iter().map(|(_, d)| d.as_str()).collect();
    let n = sqlx::query(
        "INSERT INTO saml_seen_ids (id_sha256, kind, expires_at) \
         SELECT d, k, $3 FROM UNNEST($1::text[], $2::text[]) AS t(d, k) \
         ON CONFLICT (id_sha256) DO NOTHING",
    )
    .bind(&digests)
    .bind(&kinds)
    .bind(expires_at)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n == ids.len() as u64)
}

/// Delete rows whose assertion can no longer be accepted.
pub async fn prune(pool: &PgPool) -> Result<u64> {
    Ok(sqlx::query(&format!(
        "DELETE FROM saml_seen_ids WHERE expires_at < NOW() - INTERVAL '{PRUNE_MARGIN}'"
    ))
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn prune_tick(pool: &PgPool) {
    if let Err(e) = prune(pool).await {
        tracing::error!("saml replay cache prune failed: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn ids(a: &str, r: Option<&str>) -> Vec<(&'static str, String)> {
        let mut v = vec![("assertion", id_digest("assertion", a))];
        if let Some(r) = r {
            v.push(("response", id_digest("response", r)));
        }
        v
    }

    #[test]
    fn digest_is_domain_separated() {
        let d = id_digest("assertion", "x");
        assert_eq!(d.len(), 64);
        assert_ne!(d, id_digest("response", "x"));
        assert_ne!(d, id_digest("assertion", "y"));
        assert_ne!(id_digest("a", "bc"), id_digest("ab", "c"));
        assert_ne!(d, crypto::digest::sha256_hex(b"x"));
        assert_eq!(name_id_digest("a").len(), 64);
        assert_ne!(name_id_digest("a"), crypto::digest::sha256_hex(b"a"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_tick_deletes_expired_rows(pool: PgPool) {
        let past = Utc::now() - Duration::hours(1);
        assert!(record_first_use(&pool, &ids("t", None), past)
            .await
            .unwrap());
        prune_tick(&pool).await;
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM saml_seen_ids")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn first_use_wins_then_replay(pool: PgPool) {
        let exp = Utc::now() + Duration::minutes(5);
        assert!(record_first_use(&pool, &ids("a1", Some("r1")), exp)
            .await
            .unwrap());
        assert!(!record_first_use(&pool, &ids("a1", Some("r1")), exp)
            .await
            .unwrap());
        // Same assertion under a new Response ID is still a replay.
        assert!(!record_first_use(&pool, &ids("a1", Some("r2")), exp)
            .await
            .unwrap());
        // A new assertion re-using only the old Response ID is a replay too.
        assert!(!record_first_use(&pool, &ids("a2", Some("r1")), exp)
            .await
            .unwrap());
        // An assertion ID and a response ID with the same text do not collide.
        assert!(record_first_use(&pool, &ids("same", None), exp)
            .await
            .unwrap());
        assert!(
            record_first_use(&pool, &[("response", id_digest("response", "same"))], exp)
                .await
                .unwrap()
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn concurrent_presentations_have_one_winner(pool: PgPool) {
        let exp = Utc::now() + Duration::minutes(5);
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let pool = pool.clone();
            set.spawn(async move {
                record_first_use(&pool, &ids("race", Some("race-r")), exp)
                    .await
                    .unwrap()
            });
        }
        let mut wins = 0;
        while let Some(r) = set.join_next().await {
            wins += usize::from(r.unwrap());
        }
        assert_eq!(wins, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_removes_only_rows_past_expiry_plus_margin(pool: PgPool) {
        let now = Utc::now();
        for (id, exp) in [
            ("old", now - Duration::minutes(11)),
            ("margin", now - Duration::minutes(5)),
            ("live", now + Duration::minutes(5)),
        ] {
            assert!(record_first_use(&pool, &ids(id, None), exp).await.unwrap());
        }
        assert_eq!(prune(&pool).await.unwrap(), 1);
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM saml_seen_ids")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 2);
        // A pruned (long expired) ID can be recorded again; a kept one cannot.
        assert!(record_first_use(&pool, &ids("old", None), now)
            .await
            .unwrap());
        assert!(!record_first_use(&pool, &ids("margin", None), now)
            .await
            .unwrap());
    }
}
