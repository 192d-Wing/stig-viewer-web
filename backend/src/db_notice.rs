//! AC-8 notice acknowledgements (`login_notice_acks`): issue, atomically
//! consume at login start (storing the protocol binding), and claim at login
//! completion. A completed login must claim the row or it gets no session.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

use crate::failure_counters::FailureCounter;

/// What an acknowledgement recorded, returned once at login completion.
#[derive(Debug, sqlx::FromRow)]
pub struct AckRecord {
    pub created_at: DateTime<Utc>,
    pub ip: String,
    pub user_agent: String,
    pub notice_version: String,
    pub method: Option<String>,
}

/// Protocol values bound to an acknowledgement at login start.
pub enum LoginBinding<'a> {
    Oidc {
        state: &'a str,
        nonce: &'a str,
        pkce_verifier: &'a str,
    },
    Saml {
        request_id: &'a str,
    },
}

impl LoginBinding<'_> {
    pub fn method(&self) -> &'static str {
        match self {
            LoginBinding::Oidc { .. } => "oidc",
            LoginBinding::Saml { .. } => "saml",
        }
    }
}

/// A login must complete within this long of login start.
pub const CLAIM_WINDOW_MINUTES: i64 = 10;

/// Insert a fresh acknowledgement, pruning expired/stale rows first.
pub async fn insert_ack(
    pool: &PgPool,
    id: &str,
    version: &str,
    ip: &str,
    user_agent: &str,
    ttl_secs: i64,
) -> Result<()> {
    prune_acks(pool).await?;
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

/// Delete unconsumed-and-expired rows, rows older than an hour and consumed rows
/// whose claim window has passed. Returns the number of rows removed.
pub async fn prune_acks(pool: &PgPool) -> Result<u64> {
    let mut n = 0;
    n += sqlx::query(
        "DELETE FROM login_notice_acks WHERE consumed_at IS NULL AND expires_at < NOW()",
    )
    .execute(pool)
    .await?
    .rows_affected();
    n += sqlx::query("DELETE FROM login_notice_acks WHERE created_at < NOW() - INTERVAL '1 hour'")
        .execute(pool)
        .await?
        .rows_affected();
    n += sqlx::query(
        "DELETE FROM login_notice_acks WHERE consumed_at < NOW() - INTERVAL '10 minutes'",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// One background prune tick: run [`prune_acks`], log a failure and record the
/// outcome on `counter` (status on `/api/health`, numbers on `/api/admin/failure-counters`).
pub async fn prune_acks_tick(pool: &PgPool, counter: &FailureCounter) {
    match prune_acks(pool).await {
        Ok(_) => {
            let streak = counter.snapshot().consecutive;
            counter.record_success();
            if streak > 0 {
                tracing::info!("login ack prune recovered after {streak} failures");
            }
        }
        Err(e) => {
            let n = counter.record_failure();
            tracing::error!(consecutive_failures = n, "login ack prune failed: {e:#}");
        }
    }
}

/// Atomically consume an unused, unexpired acknowledgement for the current
/// notice version and store the login binding on it. True exactly once per row.
pub async fn consume_ack(
    pool: &PgPool,
    id: &str,
    current_version: &str,
    binding: &LoginBinding<'_>,
) -> Result<bool> {
    let (req, state, nonce, verifier) = match binding {
        LoginBinding::Oidc {
            state,
            nonce,
            pkce_verifier,
        } => (None, Some(*state), Some(*nonce), Some(*pkce_verifier)),
        LoginBinding::Saml { request_id } => (Some(*request_id), None, None, None),
    };
    let row: Option<String> = sqlx::query_scalar(
        "UPDATE login_notice_acks \
            SET consumed_at = NOW(), method = $3, saml_request_id = $4, \
                oidc_state = $5, oidc_nonce = $6, oidc_pkce_verifier = $7 \
          WHERE id = $1 AND consumed_at IS NULL AND expires_at > NOW() \
            AND notice_version = $2 \
        RETURNING id",
    )
    .bind(id)
    .bind(current_version)
    .bind(binding.method())
    .bind(req)
    .bind(state)
    .bind(nonce)
    .bind(verifier)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// What an OIDC claim yields: the audit record plus the stored nonce and verifier.
pub struct OidcClaim {
    pub ack: AckRecord,
    pub nonce: String,
    pub pkce_verifier: String,
}

#[derive(sqlx::FromRow)]
struct OidcClaimRow {
    created_at: DateTime<Utc>,
    ip: String,
    user_agent: String,
    notice_version: String,
    method: Option<String>,
    oidc_nonce: Option<String>,
    oidc_pkce_verifier: Option<String>,
}

/// Atomically claim (delete) the OIDC login bound to this ack id and `state`.
/// None unless the id, method, state and 10-minute window all match.
pub async fn claim_oidc(pool: &PgPool, id: &str, state: &str) -> Result<Option<OidcClaim>> {
    let row = sqlx::query_as::<_, OidcClaimRow>(
        "DELETE FROM login_notice_acks \
          WHERE id = $1 AND method = 'oidc' AND oidc_state = $2 \
            AND consumed_at > NOW() - make_interval(mins => $3) \
        RETURNING created_at, ip, user_agent, notice_version, method, oidc_nonce, oidc_pkce_verifier",
    )
    .bind(id)
    .bind(state)
    .bind(CLAIM_WINDOW_MINUTES as i32)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| {
        Some(OidcClaim {
            nonce: r.oidc_nonce?,
            pkce_verifier: r.oidc_pkce_verifier?,
            ack: AckRecord {
                created_at: r.created_at,
                ip: r.ip,
                user_agent: r.user_agent,
                notice_version: r.notice_version,
                method: r.method,
            },
        })
    }))
}

/// Atomically claim (delete) the SAML login bound to this ack id and the
/// verified `InResponseTo`. None unless id, method, request id and window match.
pub async fn claim_saml(
    pool: &PgPool,
    id: &str,
    in_response_to: &str,
) -> Result<Option<AckRecord>> {
    Ok(sqlx::query_as::<_, AckRecord>(
        "DELETE FROM login_notice_acks \
          WHERE id = $1 AND method = 'saml' AND saml_request_id = $2 \
            AND consumed_at > NOW() - make_interval(mins => $3) \
        RETURNING created_at, ip, user_agent, notice_version, method",
    )
    .bind(id)
    .bind(in_response_to)
    .bind(CLAIM_WINDOW_MINUTES as i32)
    .fetch_optional(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "v1";
    const OIDC: LoginBinding<'static> = LoginBinding::Oidc {
        state: "st",
        nonce: "no",
        pkce_verifier: "pv",
    };
    const SAML: LoginBinding<'static> = LoginBinding::Saml {
        request_id: "_req1",
    };

    #[test]
    fn binding_method_names() {
        assert_eq!(OIDC.method(), "oidc");
        assert_eq!(SAML.method(), "saml");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn consume_succeeds_once_and_stores_binding(pool: PgPool) {
        insert_ack(&pool, "a1", V, "1.2.3.4", "ua", 300)
            .await
            .unwrap();
        assert!(consume_ack(&pool, "a1", V, &OIDC).await.unwrap());
        assert!(!consume_ack(&pool, "a1", V, &OIDC).await.unwrap());
        type Row5 = (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let r: Row5 =
            sqlx::query_as("SELECT method, oidc_state, oidc_nonce, oidc_pkce_verifier, saml_request_id FROM login_notice_acks WHERE id='a1'")
                .fetch_one(&pool).await.unwrap();
        assert_eq!(
            r,
            (
                Some("oidc".into()),
                Some("st".into()),
                Some("no".into()),
                Some("pv".into()),
                None
            )
        );
        insert_ack(&pool, "a2", V, "", "", 300).await.unwrap();
        assert!(consume_ack(&pool, "a2", V, &SAML).await.unwrap());
        let r: (Option<String>, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT method, saml_request_id, oidc_state FROM login_notice_acks WHERE id='a2'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(r, (Some("saml".into()), Some("_req1".into()), None));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn expired_and_wrong_version_rejected(pool: PgPool) {
        insert_ack(&pool, "a1", V, "", "", 300).await.unwrap();
        insert_ack(&pool, "a2", V, "", "", 300).await.unwrap();
        sqlx::query(
            "UPDATE login_notice_acks SET expires_at = NOW() - INTERVAL '1 second' WHERE id = 'a2'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(!consume_ack(&pool, "a2", V, &OIDC).await.unwrap());
        assert!(!consume_ack(&pool, "a1", "other", &OIDC).await.unwrap());
        assert!(consume_ack(&pool, "a1", V, &OIDC).await.unwrap());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn claim_oidc_matrix(pool: PgPool) {
        insert_ack(&pool, "a1", V, "9.9.9.9", "ua", 300)
            .await
            .unwrap();
        // Unconsumed row is not claimable.
        assert!(claim_oidc(&pool, "a1", "st").await.unwrap().is_none());
        consume_ack(&pool, "a1", V, &OIDC).await.unwrap();
        assert!(claim_oidc(&pool, "a1", "wrong").await.unwrap().is_none());
        assert!(claim_oidc(&pool, "other", "st").await.unwrap().is_none());
        // A SAML claim on an OIDC row finds nothing.
        assert!(claim_saml(&pool, "a1", "st").await.unwrap().is_none());
        let c = claim_oidc(&pool, "a1", "st").await.unwrap().unwrap();
        assert_eq!((c.nonce.as_str(), c.pkce_verifier.as_str()), ("no", "pv"));
        assert_eq!(c.ack.ip, "9.9.9.9");
        assert_eq!(c.ack.method.as_deref(), Some("oidc"));
        assert!(claim_oidc(&pool, "a1", "st").await.unwrap().is_none());
        // Stale consumed_at.
        insert_ack(&pool, "a2", V, "", "", 300).await.unwrap();
        consume_ack(&pool, "a2", V, &OIDC).await.unwrap();
        sqlx::query("UPDATE login_notice_acks SET consumed_at = NOW() - INTERVAL '11 minutes' WHERE id='a2'")
            .execute(&pool).await.unwrap();
        assert!(claim_oidc(&pool, "a2", "st").await.unwrap().is_none());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn claim_saml_matrix(pool: PgPool) {
        insert_ack(&pool, "a1", V, "9.9.9.9", "ua", 300)
            .await
            .unwrap();
        assert!(claim_saml(&pool, "a1", "_req1").await.unwrap().is_none());
        consume_ack(&pool, "a1", V, &SAML).await.unwrap();
        assert!(claim_saml(&pool, "a1", "_nope").await.unwrap().is_none());
        assert!(claim_saml(&pool, "other", "_req1").await.unwrap().is_none());
        assert!(claim_oidc(&pool, "a1", "_req1").await.unwrap().is_none());
        let rec = claim_saml(&pool, "a1", "_req1").await.unwrap().unwrap();
        assert_eq!(rec.ip, "9.9.9.9");
        assert_eq!(rec.method.as_deref(), Some("saml"));
        assert!(claim_saml(&pool, "a1", "_req1").await.unwrap().is_none());
        insert_ack(&pool, "a2", V, "", "", 300).await.unwrap();
        consume_ack(&pool, "a2", V, &SAML).await.unwrap();
        sqlx::query("UPDATE login_notice_acks SET consumed_at = NOW() - INTERVAL '11 minutes' WHERE id='a2'")
            .execute(&pool).await.unwrap();
        assert!(claim_saml(&pool, "a2", "_req1").await.unwrap().is_none());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn concurrent_claims_yield_exactly_one(pool: PgPool) {
        insert_ack(&pool, "a1", V, "", "", 300).await.unwrap();
        consume_ack(&pool, "a1", V, &OIDC).await.unwrap();
        let (a, b) = tokio::join!(claim_oidc(&pool, "a1", "st"), claim_oidc(&pool, "a1", "st"));
        let n = [a.unwrap(), b.unwrap()]
            .iter()
            .filter(|r| r.is_some())
            .count();
        assert_eq!(n, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_removes_stale_keeps_fresh_consumed(pool: PgPool) {
        insert_ack(&pool, "old", V, "", "", 300).await.unwrap();
        insert_ack(&pool, "exp", V, "", "", 300).await.unwrap();
        insert_ack(&pool, "fresh", V, "", "", 300).await.unwrap();
        insert_ack(&pool, "stale", V, "", "", 300).await.unwrap();
        consume_ack(&pool, "fresh", V, &OIDC).await.unwrap();
        consume_ack(&pool, "stale", V, &OIDC).await.unwrap();
        sqlx::query(
            "UPDATE login_notice_acks SET created_at = NOW() - INTERVAL '2 hours' WHERE id = 'old'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE login_notice_acks SET expires_at = NOW() - INTERVAL '1 second' WHERE id = 'exp'")
            .execute(&pool).await.unwrap();
        sqlx::query("UPDATE login_notice_acks SET consumed_at = NOW() - INTERVAL '11 minutes' WHERE id = 'stale'")
            .execute(&pool).await.unwrap();
        assert_eq!(prune_acks(&pool).await.unwrap(), 3);
        insert_ack(&pool, "new", V, "", "", 300).await.unwrap();
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM login_notice_acks ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(ids, vec!["fresh", "new"]);
    }

    #[tokio::test]
    async fn prune_tick_counts_failures_on_an_unreachable_database() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy(&format!("postgres://{}@127.0.0.1:1/x", "u"))
            .expect("lazy pool");
        let c = FailureCounter::new();
        for _ in 0..3 {
            prune_acks_tick(&pool, &c).await;
        }
        let s = c.snapshot();
        assert_eq!((s.total, s.consecutive), (3, 3));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_tick_records_success_then_failure(pool: PgPool) {
        let c = FailureCounter::new();
        prune_acks_tick(&pool, &c).await;
        let s = c.snapshot();
        assert!(s.last_success_at.is_some());
        assert_eq!((s.total, s.consecutive), (0, 0));
        pool.close().await;
        prune_acks_tick(&pool, &c).await;
        let s = c.snapshot();
        assert_eq!((s.total, s.consecutive), (1, 1));
    }
}
