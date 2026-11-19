//! AC-8 notice acknowledgements (`login_notice_acks`): issue, atomically
//! consume at login start (storing the protocol binding), and claim at login
//! completion. A completed login must claim the row or it gets no session.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
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

/// Lowercase hex SHA-256 of an OIDC `state`. Only this digest is stored (in
/// `oidc_state_sha256`); the state is a 128-bit random value, so an unkeyed
/// hash suffices. This relies on that entropy: never feed it a low-entropy
/// or caller-chosen state. Must match the SQL `encode(sha256(convert_to(s,'UTF8')),'hex')`
/// used by migration 046.
pub(crate) fn state_digest(state: &str) -> String {
    hex::encode(Sha256::digest(state.as_bytes()))
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
/// notice version and store the login binding on it (the OIDC state as its
/// SHA-256 digest). True exactly once per row.
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
                oidc_state_sha256 = $5, oidc_nonce = $6, oidc_pkce_verifier = $7 \
          WHERE id = $1 AND consumed_at IS NULL AND expires_at > NOW() \
            AND notice_version = $2 \
        RETURNING id",
    )
    .bind(id)
    .bind(current_version)
    .bind(binding.method())
    .bind(req)
    .bind(state.map(state_digest))
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

/// Atomically claim (delete) the OIDC login bound to this ack id and `state`
/// (compared by SHA-256 against the stored digest). None unless the id,
/// method, state and 10-minute window all match.
pub async fn claim_oidc(pool: &PgPool, id: &str, state: &str) -> Result<Option<OidcClaim>> {
    let row = sqlx::query_as::<_, OidcClaimRow>(
        "DELETE FROM login_notice_acks \
          WHERE id = $1 AND method = 'oidc' AND oidc_state_sha256 = $2 \
            AND consumed_at > NOW() - make_interval(mins => $3) \
        RETURNING created_at, ip, user_agent, notice_version, method, oidc_nonce, oidc_pkce_verifier",
    )
    .bind(id)
    .bind(state_digest(state))
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

/// Non-secret view of one acknowledgement row for the e2e test routes. Never
/// carries the nonce or PKCE verifier values, only whether they are set.
#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AckProbe {
    /// The ack id is the `stig_notice_ack` / `stig_oidc_state` cookie value,
    /// so this type must only ever be served by the gated test routes.
    pub id: String,
    pub consumed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub method: Option<String>,
    pub oidc_state_sha256: Option<String>,
    pub has_nonce: bool,
    pub has_pkce_verifier: bool,
    pub saml_request_id: Option<String>,
}

/// All acknowledgement rows ordered by id, without the secret values.
pub async fn list_ack_probes(pool: &PgPool) -> Result<Vec<AckProbe>> {
    Ok(sqlx::query_as::<_, AckProbe>(
        "SELECT id, consumed_at, expires_at, method, oidc_state_sha256, \
                oidc_nonce IS NOT NULL AS has_nonce, \
                oidc_pkce_verifier IS NOT NULL AS has_pkce_verifier, saml_request_id \
           FROM login_notice_acks ORDER BY id",
    )
    .fetch_all(pool)
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
    fn state_digest_matches_the_sha256_test_vector() {
        assert_eq!(
            state_digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

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
            sqlx::query_as("SELECT method, oidc_state_sha256, oidc_nonce, oidc_pkce_verifier, saml_request_id FROM login_notice_acks WHERE id='a1'")
                .fetch_one(&pool).await.unwrap();
        assert_eq!(
            r,
            (
                Some("oidc".into()),
                Some(state_digest("st")),
                Some("no".into()),
                Some("pv".into()),
                None
            )
        );
        insert_ack(&pool, "a2", V, "", "", 300).await.unwrap();
        assert!(consume_ack(&pool, "a2", V, &SAML).await.unwrap());
        let r: (Option<String>, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT method, saml_request_id, oidc_state_sha256 FROM login_notice_acks WHERE id='a2'",
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
    async fn claiming_with_the_stored_hash_as_state_fails(pool: PgPool) {
        insert_ack(&pool, "a1", V, "", "", 300).await.unwrap();
        consume_ack(&pool, "a1", V, &OIDC).await.unwrap();
        let stored: String =
            sqlx::query_scalar("SELECT oidc_state_sha256 FROM login_notice_acks WHERE id='a1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_ne!(stored, "st");
        assert_eq!(stored, state_digest("st"));
        assert!(claim_oidc(&pool, "a1", &stored).await.unwrap().is_none());
        assert!(claim_oidc(&pool, "a1", "st").await.unwrap().is_some());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn ack_table_is_unlogged(pool: PgPool) {
        let p: String = sqlx::query_scalar(
            "SELECT relpersistence::text FROM pg_class WHERE oid = 'login_notice_acks'::regclass",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(p, "u");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn list_ack_probes_omits_secrets(pool: PgPool) {
        insert_ack(&pool, "a1", V, "", "", 300).await.unwrap();
        let b = LoginBinding::Oidc {
            state: "distinct-state-value",
            nonce: "distinct-nonce-value",
            pkce_verifier: "distinct-verifier-value",
        };
        consume_ack(&pool, "a1", V, &b).await.unwrap();
        let probes = list_ack_probes(&pool).await.unwrap();
        assert_eq!(probes.len(), 1);
        let p = &probes[0];
        assert!(p.has_nonce && p.has_pkce_verifier && p.consumed_at.is_some());
        assert_eq!(
            p.oidc_state_sha256.as_deref(),
            Some(state_digest("distinct-state-value").as_str())
        );
        let json = serde_json::to_string(&probes).unwrap();
        for secret in [
            "distinct-state-value",
            "distinct-nonce-value",
            "distinct-verifier-value",
        ] {
            assert!(!json.contains(secret), "{secret} leaked");
        }
        assert!(json.contains("hasNonce") && json.contains("oidcStateSha256"));
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
