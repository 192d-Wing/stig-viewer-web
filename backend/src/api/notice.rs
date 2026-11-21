//! AC-8 server-side gate: `POST /auth/notice/ack` issues a short-lived,
//! single-use proof cookie; the login-start endpoints consume it via
//! [`require_ack`], binding it to the login's protocol values. Login completion
//! must claim that row (`db_notice::claim_*`) or no session is created, and the
//! claimed record is written to `audit_events` ([`record_ack_linked`]).

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Redirect,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;

use crate::api::auth::{cookie_secure, removal_cookie, session_cookie, user_agent, AppAuthState};
use crate::db_audit::{self, NewAuditEvent};
use crate::db_notice::{self, AckRecord, LoginBinding};

/// Version of the notice wording. MUST equal `USE_NOTICE_VERSION` in
/// `frontend/src/constants.rs` (a mismatch makes every acknowledgement 409).
pub const USE_NOTICE_VERSION: &str = "DoD-NCB-standard-2026-11";
pub const ACK_COOKIE: &str = "stig_notice_ack";
pub const ACK_TTL_SECS: i64 = 300;
const ACK_PATH: &str = "/auth";
const MAX_VERSION_CHARS: usize = 64;
const MAX_UA_CHARS: usize = 256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckBody {
    pub notice_version: String,
}

/// Printable ASCII only, at most [`MAX_UA_CHARS`] characters.
pub(crate) fn bound_ua(ua: &str) -> String {
    ua.chars()
        .filter(|c| (' '..='~').contains(c))
        .take(MAX_UA_CHARS)
        .collect()
}

/// Canonical text of a valid IP address, else empty (never stores free text).
pub(crate) fn canonical_ip(raw: &str) -> String {
    raw.trim()
        .parse::<std::net::IpAddr>()
        .map(|i| i.to_string())
        .unwrap_or_default()
}

/// Client IP for the notice/login-start paths. The socket peer is used unless
/// `trusted_hops > 0`, in which case the hop that many places from the RIGHT of
/// `X-Forwarded-For` (the one appended by the nearest trusted proxy; 1 =
/// rightmost) is used when it is a valid IP, else the peer. Always a canonical
/// IP or empty (at most 45 chars).
pub(crate) fn request_ip(
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    trusted_hops: usize,
) -> String {
    if trusted_hops > 0 {
        // Every header line, in order, each split on commas: a proxy may append
        // its own line instead of extending the client's.
        let hops: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .collect();
        let from_xff = hops
            .len()
            .checked_sub(trusted_hops)
            .and_then(|i| hops.get(i).copied())
            .map(canonical_ip)
            .filter(|s| !s.is_empty());
        if let Some(ip) = from_xff {
            return ip;
        }
    }
    peer.map(|p| canonical_ip(&p.ip().to_string()))
        .unwrap_or_default()
}

/// Number of trusted proxy hops: 0 unless `STIG_TRUST_PROXY_HEADERS` is on, then
/// `STIG_TRUSTED_PROXY_HOPS` (default 1).
fn trusted_hops() -> usize {
    if !crate::config::parse_flag(std::env::var("STIG_TRUST_PROXY_HEADERS").ok().as_deref()) {
        return 0;
    }
    std::env::var("STIG_TRUSTED_PROXY_HOPS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(1)
}

/// [`request_ip`] configured from the environment.
pub(crate) fn notice_ip(headers: &HeaderMap, peer: Option<std::net::SocketAddr>) -> String {
    request_ip(headers, peer, trusted_hops())
}

/// Log once at startup how client IPs are derived.
pub fn log_proxy_trust_config() {
    if trusted_hops() == 0 {
        tracing::warn!(
            "STIG_TRUST_PROXY_HEADERS is not enabled: client IPs (and the auth rate limit) use the \
             socket peer address, so all clients behind a reverse proxy share one bucket. Set it \
             (and STIG_TRUSTED_PROXY_HOPS) only behind a proxy that overwrites X-Forwarded-For."
        );
    }
}

fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    let o = u.origin();
    o.is_tuple().then(|| o.ascii_serialization())
}

/// The proof cookie: HttpOnly, SameSite=Strict, scoped to `/auth`, short-lived.
fn ack_cookie(id: String, secure: bool) -> axum_extra::extract::cookie::Cookie<'static> {
    session_cookie(
        ACK_COOKIE,
        id,
        ACK_PATH,
        axum_extra::extract::cookie::SameSite::Strict,
        time::Duration::seconds(ACK_TTL_SECS),
        secure,
    )
}

/// True when a login-start request should be turned away as rate limited. Only
/// requests carrying the proof cookie spend a token, so cross-site GETs without
/// it (for example `<img>` tags) cannot drain a victim's budget.
pub(crate) fn login_start_limited(jar: &CookieJar, ip: &str) -> bool {
    jar.get(ACK_COOKIE).is_some() && !crate::api::rate_limit::allow_pre_auth(ip)
}

/// Core of the ack endpoint (split out so tests need no OIDC context).
pub(crate) async fn issue_ack(
    pool: &PgPool,
    frontend_url: &str,
    headers: &HeaderMap,
    ip: &str,
    notice_version: &str,
    jar: CookieJar,
) -> Result<CookieJar, StatusCode> {
    let want = origin_of(frontend_url).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let got = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(origin_of);
    if got.as_deref() != Some(want.as_str()) {
        return Err(StatusCode::FORBIDDEN);
    }
    if notice_version.chars().count() > MAX_VERSION_CHARS || notice_version != USE_NOTICE_VERSION {
        return Err(StatusCode::CONFLICT);
    }
    // Security depends on this being a CSPRNG-backed UUIDv4 (122 random bits);
    // it must not become v7, a counter, or any guessable id.
    let id = uuid::Uuid::new_v4().to_string();
    db_notice::insert_ack(
        pool,
        &id,
        USE_NOTICE_VERSION,
        ip,
        &bound_ua(&user_agent(headers)),
        ACK_TTL_SECS,
    )
    .await
    .map_err(|e| {
        tracing::error!("notice ack insert failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    tracing::info!(target: "audit", action = "auth.notice_ack", outcome = "issued", ip = %ip, notice_version = USE_NOTICE_VERSION);
    Ok(jar.add(ack_cookie(id, cookie_secure())))
}

/// Rate-limit, then issue (split from the handler so tests can pass their own limiter).
pub(crate) async fn ack_with_limiter(
    limiter: &crate::api::rate_limit::PreAuthLimiter,
    pool: &PgPool,
    frontend_url: &str,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    notice_version: &str,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    let ip = notice_ip(headers, peer);
    if !limiter.allow(&crate::api::rate_limit::limiter_key(&ip)) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let jar = issue_ack(pool, frontend_url, headers, &ip, notice_version, jar).await?;
    Ok((jar, StatusCode::NO_CONTENT))
}

/// POST /auth/notice/ack — public; per-IP rate limit, strict Origin check, JSON body.
pub async fn ack_handler(
    State(state): State<AppAuthState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<std::net::SocketAddr>>,
    jar: CookieJar,
    Json(body): Json<AckBody>,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    ack_with_limiter(
        crate::api::rate_limit::global(),
        state.pool.as_ref(),
        &state.oidc.frontend_url,
        &headers,
        peer.map(|p| p.0),
        &body.notice_version,
        jar,
    )
    .await
}

/// Response for a rate-limited login start: audit log line and a redirect to the banner.
pub(crate) fn rate_limited_redirect(
    jar: CookieJar,
    frontend_url: &str,
    ip: &str,
) -> (CookieJar, Redirect) {
    tracing::warn!(target: "audit", action = "auth.login_start", outcome = "denied", reason = "rate_limited", ip = %ip);
    (jar, Redirect::to(frontend_url))
}

/// Gate for the login-start endpoints. On success returns the cleared jar and
/// the consumed acknowledgement id; on any failure (fail closed) the jar with
/// the cookie cleared and a redirect to the frontend banner.
pub(crate) async fn require_ack(
    pool: &PgPool,
    jar: CookieJar,
    frontend_url: &str,
    binding: &LoginBinding<'_>,
    ip: &str,
) -> Result<(CookieJar, String), Box<(CookieJar, Redirect)>> {
    let raw = jar.get(ACK_COOKIE).map(|c| c.value().to_string());
    let jar = jar.remove(removal_cookie(ACK_COOKIE, ACK_PATH, cookie_secure()));
    let deny = |jar: CookieJar, reason: &'static str| {
        tracing::warn!(target: "audit", action = "auth.login_start", outcome = "denied", reason, ip = %ip);
        Box::new((jar, Redirect::to(frontend_url)))
    };
    let Some(raw) = raw else {
        return Err(deny(jar, "missing"));
    };
    let Ok(id) = uuid::Uuid::parse_str(&raw) else {
        return Err(deny(jar, "malformed"));
    };
    let id = id.to_string();
    match db_notice::consume_ack(pool, &id, USE_NOTICE_VERSION, binding).await {
        Ok(true) => Ok((jar, id)),
        Ok(false) => Err(deny(jar, "invalid")),
        Err(e) => {
            tracing::error!("notice ack consume failed: {e:#}");
            Err(deny(jar, "error"))
        }
    }
}

/// Create the session and submit its `auth.notice_ack` row as one detached
/// task, so a dropped caller cannot leave a session without its ack record.
/// No await before the spawn.
///
/// Known, accepted gap: the session insert and the ack write are not one
/// transaction. If the process dies between them, no response was sent, so
/// nobody holds that session id. The residual case needs the ack write to
/// stall past `WRITE_TIMEOUT` (cookie sent) followed by a hard kill before the
/// detached write lands; a graceful shutdown drains the tracker and queue. A
/// transaction would turn audit-table trouble into a login outage (including
/// for the admin who must fix it) and bypass the write-queue accounting.
/// Writing the ack first is worse: a failed session insert would leave an `ok`
/// ack for a login that never happened. To reconcile, look for sessions with
/// no `auth.notice_ack` row whose `detail->>'sessionId'` matches the session.
pub(crate) async fn session_with_ack(
    tasks: &std::sync::Arc<crate::detached::Tracker>,
    pool: std::sync::Arc<PgPool>,
    user_id: String,
    ip: String,
    ua: String,
    ack: AckRecord,
) -> Result<String, axum::http::StatusCode> {
    let made = crate::detached::run(tasks, "login session", async move {
        let sid = crate::api::auth::create_session(&pool, &user_id, &ip, &ua).await?;
        record_ack_linked(&pool, &user_id, &sid, ack).await;
        anyhow::Ok(sid)
    })
    .await?;
    made.map_err(|e| {
        tracing::error!("create_session failed: {e:#}");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Write the durable AU-2 record for a completed login. Never fails the caller.
pub(crate) async fn record_ack_linked(
    pool: &PgPool,
    user_id: &str,
    session_id: &str,
    rec: AckRecord,
) {
    db_audit::record_or_log(
        pool,
        NewAuditEvent {
            user_id,
            action: "auth.notice_ack",
            outcome: "ok",
            asset_id: None,
            checklist_id: None,
            stig_id: None,
            ctx: None,
            detail: json!({
                "noticeVersion": rec.notice_version,
                "acknowledgedAt": rec.created_at.to_rfc3339(),
                "ip": rec.ip,
                "userAgent": rec.user_agent,
                "method": rec.method,
                "sessionId": session_id,
            }),
        },
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const FE: &str = "http://localhost:5173";
    const TEST_BINDING: LoginBinding<'static> = LoginBinding::Oidc {
        state: "s",
        nonce: "n",
        pkce_verifier: "p",
    };

    fn hdrs(origin: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(o) = origin {
            h.insert("origin", HeaderValue::from_str(o).unwrap());
        }
        h
    }

    #[test]
    fn backend_notice_version_matches_frontend_constant() {
        let fe = include_str!("../../../frontend/src/constants.rs");
        assert!(
            fe.contains(&format!(
                "USE_NOTICE_VERSION: &str = \"{USE_NOTICE_VERSION}\""
            )),
            "frontend USE_NOTICE_VERSION differs from the backend's"
        );
    }

    #[test]
    fn ip_is_canonical_or_empty_and_proxy_headers_are_opt_in() {
        use std::net::SocketAddr;
        assert_eq!(canonical_ip(" 10.0.0.1 "), "10.0.0.1");
        assert_eq!(canonical_ip("::FFFF:1.2.3.4"), "::ffff:1.2.3.4");
        assert_eq!(canonical_ip("not an ip\r\n"), "");
        assert_eq!(canonical_ip(&"1".repeat(200)), "");
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("6.6.6.6, 203.0.113.9, 10.0.0.1"),
        );
        let peer: SocketAddr = "192.0.2.7:5555".parse().unwrap();
        assert_eq!(request_ip(&h, Some(peer), 0), "192.0.2.7");
        // 1 = rightmost (appended by the trusted proxy); a forged leftmost is ignored.
        assert_eq!(request_ip(&h, Some(peer), 1), "10.0.0.1");
        assert_eq!(request_ip(&h, Some(peer), 2), "203.0.113.9");
        assert_eq!(request_ip(&h, Some(peer), 9), "192.0.2.7");
        // Separate lines: a forged client line first, the proxy's appended line last.
        let mut two = HeaderMap::new();
        two.append("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
        two.append("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        assert_eq!(request_ip(&two, Some(peer), 1), "203.0.113.9");
        // Mixed: merged first line plus a separate proxy line.
        let mut mixed = HeaderMap::new();
        mixed.append(
            "x-forwarded-for",
            HeaderValue::from_static("6.6.6.6, 198.51.100.4"),
        );
        mixed.append("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        assert_eq!(request_ip(&mixed, Some(peer), 1), "203.0.113.9");
        assert_eq!(request_ip(&mixed, Some(peer), 2), "198.51.100.4");
        h.insert("x-forwarded-for", HeaderValue::from_static("<script>"));
        assert_eq!(request_ip(&h, Some(peer), 1), "192.0.2.7");
        assert_eq!(request_ip(&h, None, 1), "");
    }

    #[test]
    fn ack_cookie_attributes_and_secure_flag() {
        let c = ack_cookie("id".into(), true);
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(
            c.same_site(),
            Some(axum_extra::extract::cookie::SameSite::Strict)
        );
        assert_eq!(ack_cookie("id".into(), false).secure(), Some(false));
        // The flag fed to it in issue_ack is `cookie_secure()`: production or https frontend.
        assert!(crate::api::auth::secure_for(Some("production"), None));
        assert!(crate::api::auth::secure_for(
            None,
            Some("https://app.example")
        ));
    }

    #[test]
    fn login_start_without_proof_cookie_spends_no_token() {
        // No cookie: never limited, regardless of the (global) bucket state.
        for _ in 0..200 {
            assert!(!login_start_limited(&CookieJar::new(), "203.0.113.200"));
        }
    }

    #[test]
    fn rate_limited_redirect_goes_to_the_banner() {
        let (_, r) = rate_limited_redirect(CookieJar::new(), FE, "1.2.3.4");
        let resp = axum::response::IntoResponse::into_response(r);
        assert_eq!(resp.headers().get("location").unwrap(), FE);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn ack_endpoint_returns_429_after_the_burst(pool: PgPool) {
        let limiter = crate::api::rate_limit::PreAuthLimiter::from_vars(Some("2"), Some("1"));
        let h = hdrs(Some(FE));
        let peer = Some("192.0.2.1:1".parse().unwrap());
        let call = |peer| {
            ack_with_limiter(
                &limiter,
                &pool,
                FE,
                &h,
                peer,
                USE_NOTICE_VERSION,
                CookieJar::new(),
            )
        };
        assert!(call(peer).await.is_ok());
        assert!(call(peer).await.is_ok());
        assert_eq!(call(peer).await.err(), Some(StatusCode::TOO_MANY_REQUESTS));
        // A different client keeps its own budget.
        assert!(call(Some("192.0.2.2:1".parse().unwrap())).await.is_ok());
    }

    #[test]
    fn bound_ua_keeps_printable_ascii_and_caps_length() {
        assert_eq!(bound_ua("Mozilla/5.0 \u{1}\r\n\u{e9}x"), "Mozilla/5.0 x");
        assert_eq!(bound_ua(&"a".repeat(1000)).len(), MAX_UA_CHARS);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn ack_rejects_bad_origin_and_version(pool: PgPool) {
        let jar = CookieJar::new();
        for h in [hdrs(None), hdrs(Some("http://evil.example"))] {
            let r = issue_ack(&pool, FE, &h, "", USE_NOTICE_VERSION, jar.clone()).await;
            assert_eq!(r.err(), Some(StatusCode::FORBIDDEN));
        }
        let r = issue_ack(&pool, FE, &hdrs(Some(FE)), "", "nope", jar).await;
        assert_eq!(r.err(), Some(StatusCode::CONFLICT));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn ack_success_sets_strict_httponly_cookie_and_require_consumes_once(pool: PgPool) {
        let jar = issue_ack(
            &pool,
            FE,
            &hdrs(Some("http://localhost:5173/")),
            "1.2.3.4",
            USE_NOTICE_VERSION,
            CookieJar::new(),
        )
        .await
        .unwrap();
        let c = jar.get(ACK_COOKIE).unwrap().clone();
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(
            c.same_site(),
            Some(axum_extra::extract::cookie::SameSite::Strict)
        );
        assert_eq!(c.path(), Some("/auth"));
        assert_eq!(c.max_age(), Some(time::Duration::seconds(300)));
        let req = CookieJar::new().add(c.clone());
        let ok = require_ack(&pool, req.clone(), FE, &TEST_BINDING, "").await;
        assert!(ok.is_ok());
        let again = require_ack(&pool, req, FE, &TEST_BINDING, "").await;
        assert!(again.is_err());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn require_ack_denies_missing_malformed_unknown(pool: PgPool) {
        // Jars as the extractor builds them: from the request's Cookie header.
        let from = |c: Option<String>| {
            let mut h = HeaderMap::new();
            if let Some(c) = c {
                h.insert(
                    "cookie",
                    HeaderValue::from_str(&format!("{ACK_COOKIE}={c}")).unwrap(),
                );
            }
            CookieJar::from_headers(&h)
        };
        let cases = [
            (from(None), false),
            (from(Some("not-a-uuid".into())), true),
            (from(Some(uuid::Uuid::new_v4().to_string())), true),
        ];
        for (jar, cleared) in cases {
            let (jar, redirect) = *require_ack(&pool, jar, FE, &TEST_BINDING, "")
                .await
                .err()
                .unwrap();
            let resp = axum::response::IntoResponse::into_response(redirect);
            assert_eq!(resp.headers().get("location").unwrap(), FE);
            // the response clears the cookie
            if cleared {
                let set = axum::response::IntoResponse::into_response((jar, ()));
                let set = set
                    .headers()
                    .get("set-cookie")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                assert!(
                    set.starts_with("stig_notice_ack=;") && set.contains("Max-Age=0"),
                    "{set}"
                );
            }
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn record_ack_linked_writes_one_audit_row(pool: PgPool) {
        sqlx::query("INSERT INTO users (id, display_name, email, sub, provider) VALUES ('u1','U','','s','test')")
            .execute(&pool).await.unwrap();
        db_notice::insert_ack(&pool, "a1", USE_NOTICE_VERSION, "1.1.1.1", "ua", 300)
            .await
            .unwrap();
        db_notice::consume_ack(&pool, "a1", USE_NOTICE_VERSION, &TEST_BINDING)
            .await
            .unwrap();
        let rec = db_notice::claim_oidc(&pool, "a1", "s")
            .await
            .unwrap()
            .unwrap()
            .ack;
        record_ack_linked(&pool, "u1", "sess1", rec).await;
        let (action, outcome, detail): (String, String, serde_json::Value) =
            sqlx::query_as("SELECT action, outcome, detail FROM audit_events")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            (action.as_str(), outcome.as_str()),
            ("auth.notice_ack", "ok")
        );
        for k in [
            "noticeVersion",
            "acknowledgedAt",
            "ip",
            "userAgent",
            "method",
            "sessionId",
        ] {
            assert!(detail.get(k).is_some(), "missing {k}");
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_session_returns_500_and_writes_no_ack_row(pool: PgPool) {
        db_notice::insert_ack(&pool, "a1", USE_NOTICE_VERSION, "1.1.1.1", "ua", 300)
            .await
            .unwrap();
        db_notice::consume_ack(&pool, "a1", USE_NOTICE_VERSION, &TEST_BINDING)
            .await
            .unwrap();
        let ack = db_notice::claim_oidc(&pool, "a1", "s")
            .await
            .unwrap()
            .unwrap()
            .ack;
        let tasks = crate::detached::Tracker::new();
        // No such user: the sessions FK refuses the insert.
        let r = session_with_ack(
            &tasks,
            std::sync::Arc::new(pool.clone()),
            "no-such-user".into(),
            "1.1.1.1".into(),
            "ua".into(),
            ack,
        )
        .await;
        assert_eq!(r, Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR));
        tasks.idle().await;
        crate::db_audit::drain().await;
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        // `claim_oidc` deletes the ack row, so "claimed" means the row is gone,
        // and a second claim finds nothing.
        let left: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM login_notice_acks WHERE id = 'a1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(left, 0);
        assert!(db_notice::claim_oidc(&pool, "a1", "s")
            .await
            .unwrap()
            .is_none());
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(sessions, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn session_and_ack_survive_a_dropped_caller(pool: PgPool) {
        sqlx::query("INSERT INTO users (id, display_name, email, sub, provider) VALUES ('u1','U','','s','test')")
            .execute(&pool).await.unwrap();
        db_notice::insert_ack(&pool, "a1", USE_NOTICE_VERSION, "1.1.1.1", "ua", 300)
            .await
            .unwrap();
        db_notice::consume_ack(&pool, "a1", USE_NOTICE_VERSION, &TEST_BINDING)
            .await
            .unwrap();
        let ack = db_notice::claim_oidc(&pool, "a1", "s")
            .await
            .unwrap()
            .unwrap()
            .ack;
        let tasks = crate::detached::Tracker::new();
        {
            let call = session_with_ack(
                &tasks,
                std::sync::Arc::new(pool.clone()),
                "u1".into(),
                "1.1.1.1".into(),
                "ua".into(),
                ack,
            );
            let mut call = std::pin::pin!(call);
            let pending = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(std::future::Future::poll(call.as_mut(), cx).is_pending())
            })
            .await;
            assert!(pending);
            assert_eq!(tasks.in_flight(), 1);
        }
        tasks.idle().await;
        crate::db_audit::drain().await;
        let sid: String = sqlx::query_scalar("SELECT id FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        let detail: serde_json::Value =
            sqlx::query_scalar("SELECT detail FROM audit_events WHERE action = 'auth.notice_ack'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(detail["sessionId"], sid);
    }
}
