use crate::db_notice::LoginBinding;
use anyhow::{Context, Result};
use axum::{
    extract::{Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{DateTime, Duration, Utc};
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreIdTokenVerifier, CoreJsonWebKeySet,
        CoreProviderMetadata,
    },
    reqwest, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

pub(crate) const SESSION_COOKIE: &str = "stig_session";
const STATE_COOKIE: &str = "stig_oidc_state";
pub(crate) const SESSION_LIFETIME_HOURS: i64 = 8;

// ── User & config types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuthUser {
    pub id: String,
    pub display_name: String,
    pub email: String,
    pub role: String,
}

/// Discovered + configured OIDC client. Built once at startup.
pub type OidcClient = CoreClient<
    EndpointSet,      // HasAuthUrl
    EndpointNotSet,   // HasDeviceAuthUrl
    EndpointNotSet,   // HasIntrospectionUrl
    EndpointNotSet,   // HasRevocationUrl
    EndpointMaybeSet, // HasTokenUrl
    EndpointMaybeSet, // HasUserInfoUrl
>;

#[derive(Clone)]
pub struct OidcContext {
    pub client: Arc<OidcClient>,
    pub http: reqwest::Client,
    pub public_auth_base: String, // e.g. http://localhost:8081  (for browser redirect rewrite)
    pub internal_issuer: String, // e.g. http://keycloak:8081/realms/stig-viewer  (used for discovery)
    pub public_issuer: String, // e.g. http://localhost:8081/realms/stig-viewer  (what tokens actually carry as iss)
    pub jwks: CoreJsonWebKeySet,
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub frontend_url: String,
    pub allow_test_auth_header: bool,
}

#[derive(Debug, Clone)]
pub struct OidcEnv {
    pub internal_issuer_url: String,
    pub public_auth_base: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub frontend_url: String,
    pub allow_test_auth_header: bool,
}

impl OidcEnv {
    /// `allow_test_auth_header` comes from the already-validated
    /// [`crate::config::TestHooks`], so it can never be on in production.
    pub fn from_env(allow_test_auth_header: bool) -> Result<Self> {
        Ok(Self {
            internal_issuer_url: std::env::var("OIDC_INTERNAL_URL")
                .unwrap_or_else(|_| "http://keycloak:8081/realms/stig-viewer".into()),
            public_auth_base: std::env::var("OIDC_PUBLIC_URL")
                .unwrap_or_else(|_| "http://localhost:8081".into()),
            client_id: std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| "stig-viewer-app".into()),
            client_secret: std::env::var("OIDC_CLIENT_SECRET")
                .unwrap_or_else(|_| "dev-only-not-a-real-secret".into()),
            redirect_uri: std::env::var("OIDC_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:8080/auth/callback".into()),
            frontend_url: std::env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:5173".into()),
            allow_test_auth_header,
        })
    }
}

pub async fn build_oidc_context(env: &OidcEnv) -> Result<OidcContext> {
    let http = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Build reqwest client for OIDC")?;

    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(env.internal_issuer_url.clone())?,
        &http,
    )
    .await
    .context("OIDC discovery failed")?;

    let jwks = provider_metadata.jwks().clone();

    let client_id = ClientId::new(env.client_id.clone());
    let client_secret = ClientSecret::new(env.client_secret.clone());
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        client_id.clone(),
        Some(client_secret.clone()),
    )
    .set_redirect_uri(RedirectUrl::new(env.redirect_uri.clone())?);

    // Public issuer = rewrite the discovery (internal) issuer's origin to the
    // browser-facing public origin. Tokens minted by an IdP that auth'd the
    // browser at the public URL will carry this issuer in their iss claim.
    let public_issuer = url::Url::parse(&env.internal_issuer_url)
        .ok()
        .and_then(|u| {
            let pub_base = url::Url::parse(&env.public_auth_base).ok()?;
            Some(rewrite_origin(u, &env.internal_issuer_url, pub_base.as_str()).to_string())
        })
        .unwrap_or_else(|| env.internal_issuer_url.clone());
    // url::Url::to_string() adds a trailing slash; strip it to match issuer string form.
    let public_issuer = public_issuer.trim_end_matches('/').to_string();

    Ok(OidcContext {
        client: Arc::new(client),
        http,
        public_auth_base: env.public_auth_base.clone(),
        internal_issuer: env.internal_issuer_url.clone(),
        public_issuer,
        jwks,
        client_id,
        client_secret,
        frontend_url: env.frontend_url.clone(),
        allow_test_auth_header: env.allow_test_auth_header,
    })
}

// ── Cookie helpers ──────────────────────────────────────────────────────────

/// `Secure` is set on auth cookies when `STIG_ENV=production` (dev/test run over http).
pub(crate) fn cookie_secure() -> bool {
    secure_for(
        std::env::var("STIG_ENV").ok().as_deref(),
        std::env::var("FRONTEND_URL").ok().as_deref(),
    )
}

/// Secure when running in production or when the frontend is served over https.
pub(crate) fn secure_for(stig_env: Option<&str>, frontend_url: Option<&str>) -> bool {
    crate::config::is_production(stig_env)
        || frontend_url.is_some_and(|u| u.trim().to_ascii_lowercase().starts_with("https://"))
}

/// HttpOnly cookie with explicit path, SameSite, lifetime and Secure attribute.
pub(crate) fn session_cookie(
    name: &'static str,
    value: String,
    path: &'static str,
    same_site: SameSite,
    max_age: time::Duration,
    secure: bool,
) -> Cookie<'static> {
    Cookie::build((name, value))
        .path(path)
        .http_only(true)
        .secure(secure)
        .same_site(same_site)
        .max_age(max_age)
        .build()
}

/// Removal cookie matching the attributes of [`session_cookie`].
pub(crate) fn removal_cookie(
    name: &'static str,
    path: &'static str,
    secure: bool,
) -> Cookie<'static> {
    Cookie::build(name).path(path).secure(secure).build()
}

/// SameSite for the SAML request cookie, which must ride the IdP's cross-site
/// top-level POST to the ACS: `None` (requires `Secure`) when secure, else `Lax`.
pub(crate) fn saml_req_same_site(secure: bool) -> SameSite {
    if secure {
        SameSite::None
    } else {
        SameSite::Lax
    }
}

/// Callback step 1-2: read the state cookie (a bare ack UUID) and claim the
/// acknowledgement bound to it and to the echoed `state`. Err is the audit reason.
pub(crate) async fn claim_from_state_cookie(
    pool: &PgPool,
    cookie_value: Option<&str>,
    state: &str,
) -> Result<crate::db_notice::OidcClaim, &'static str> {
    let raw = cookie_value.ok_or("no_state_cookie")?;
    let id = uuid::Uuid::parse_str(raw).map_err(|_| "malformed_state_cookie")?;
    match crate::db_notice::claim_oidc(pool, &id.to_string(), state).await {
        Ok(Some(c)) => Ok(c),
        Ok(None) => Err("ack_not_claimed"),
        Err(e) => {
            tracing::error!("oidc ack claim failed: {e:#}");
            Err("claim_error")
        }
    }
}

/// Audit log line for a refused OIDC callback (log only, by decision).
fn oidc_denied(reason: &'static str, ip: &str) {
    tracing::warn!(target: "audit", action = "auth.oidc_callback", outcome = "denied", reason, ip = %ip);
}

fn oidc_success(user_id: &str, ip: &str) {
    tracing::info!(target: "audit", action = "auth.oidc_callback", outcome = "success", user_id = %user_id, ip = %ip);
}

/// Callback pre-IdP step: per-IP rate limit, then clear the binding cookie and
/// claim the acknowledgement. Errors carry the jar (cookie removed) and status.
pub(crate) async fn claim_step(
    limiter: &crate::api::rate_limit::PreAuthLimiter,
    pool: &PgPool,
    jar: CookieJar,
    state: &str,
    ip: &str,
) -> Result<(CookieJar, crate::db_notice::OidcClaim), (CookieJar, StatusCode)> {
    if !limiter.allow(&crate::api::rate_limit::limiter_key(ip)) {
        oidc_denied("rate_limited", ip);
        return Err((jar, StatusCode::TOO_MANY_REQUESTS));
    }
    let cookie_val = jar.get(STATE_COOKIE).map(|c| c.value().to_string());
    let jar = jar.remove(removal_cookie(STATE_COOKIE, "/auth", cookie_secure()));
    match claim_from_state_cookie(pool, cookie_val.as_deref(), state).await {
        Ok(c) => Ok((jar, c)),
        Err(reason) => {
            oidc_denied(reason, ip);
            Err((jar, StatusCode::BAD_REQUEST))
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// GET /auth/login — start the OIDC Authorization Code + PKCE flow.
pub async fn login_handler(
    State(state): State<AppAuthState>,
    headers: HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let oidc = &state.oidc;
    let ip = crate::api::notice::notice_ip(&headers, peer.map(|p| p.0));
    if crate::api::notice::login_start_limited(&jar, &ip) {
        return Ok(crate::api::notice::rate_limited_redirect(
            jar,
            &oidc.frontend_url,
            &ip,
        ));
    }
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (mut auth_url, csrf_token, nonce) = oidc
        .client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Rewrite the auth-endpoint origin from the docker-internal hostname
    // (issuer URL) to the public URL the browser can reach.
    auth_url = rewrite_origin(auth_url, &oidc.internal_issuer, &oidc.public_auth_base);

    // AC-8 gate: consumes the acknowledgement and stores state/nonce/verifier on it.
    let (jar, ack_id) = match crate::api::notice::require_ack(
        state.pool.as_ref(),
        jar,
        &oidc.frontend_url,
        &LoginBinding::Oidc {
            state: csrf_token.secret(),
            nonce: nonce.secret(),
            pkce_verifier: pkce_verifier.secret(),
        },
        &ip,
    )
    .await
    {
        Ok(v) => v,
        Err(deny) => return Ok(*deny),
    };

    // The cookie holds only the ack id; the secrets stay server-side.
    let cookie = session_cookie(
        STATE_COOKIE,
        ack_id,
        "/auth",
        SameSite::Lax,
        time::Duration::minutes(10),
        cookie_secure(),
    );

    Ok((jar.add(cookie), Redirect::to(auth_url.as_str())))
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

/// Callback steps after the claim: code exchange, ID-token validation, user and
/// session creation, audit. Split from the handler so tests can drive it
/// against a stub token endpoint. Errors are already audit-logged.
pub(crate) async fn finish_callback(
    oidc: &OidcContext,
    pool: &Arc<PgPool>,
    tasks: &Arc<crate::detached::Tracker>,
    code: String,
    claim: crate::db_notice::OidcClaim,
    ip: &str,
    ua: &str,
) -> Result<Cookie<'static>, StatusCode> {
    let deny = |reason: &'static str| oidc_denied(reason, ip);
    // Exchange code for tokens.
    let token_response = oidc
        .client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .set_pkce_verifier(PkceCodeVerifier::new(claim.pkce_verifier))
        .request_async(&oidc.http)
        .await
        .map_err(|e| {
            tracing::error!("OIDC token exchange failed: {e:#}");
            deny("token_exchange");
            StatusCode::UNAUTHORIZED
        })?;

    // Validate ID token. Build the verifier with the PUBLIC issuer URL
    // (matching what the IdP put in the iss claim — Keycloak ties iss to
    // the hostname the browser used at auth time, not where the backend
    // exchanges the code) and reuse the JWKS fetched at discovery time.
    let id_token = token_response.id_token().ok_or_else(|| {
        deny("id_token");
        StatusCode::UNAUTHORIZED
    })?;
    let verifier_issuer = IssuerUrl::new(oidc.public_issuer.clone())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let id_token_verifier = CoreIdTokenVerifier::new_confidential_client(
        oidc.client_id.clone(),
        oidc.client_secret.clone(),
        verifier_issuer,
        oidc.jwks.clone(),
    );
    let claims = id_token
        .claims(&id_token_verifier, &Nonce::new(claim.nonce))
        .map_err(|e| {
            tracing::error!("ID token validation failed: {e:#}");
            deny("id_token");
            StatusCode::UNAUTHORIZED
        })?;

    let sub = claims.subject().to_string();
    let email = claims.email().map(|e| e.to_string()).unwrap_or_default();
    let display_name = claims
        .preferred_username()
        .map(|n| n.to_string())
        .or_else(|| {
            claims
                .name()
                .and_then(|n| n.get(None))
                .map(|s| s.to_string())
        })
        .or_else(|| {
            if email.is_empty() {
                None
            } else {
                Some(email.clone())
            }
        })
        .unwrap_or_else(|| format!("user-{}", &sub[..8.min(sub.len())]));

    // Upsert user (provider='oidc', sub from IdP).
    let user = upsert_user(pool.as_ref(), "oidc", &sub, &display_name, &email)
        .await
        .map_err(|e| {
            tracing::error!("upsert_user failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Create server-side session, set cookie.
    // Session and the durable AU-2 record of the claimed AC-8 acknowledgement
    // are written by one detached task; the ack never fails the login.
    let session_id = crate::api::notice::session_with_ack(
        tasks,
        pool.clone(),
        user.id.clone(),
        ip.to_string(),
        ua.to_string(),
        claim.ack,
    )
    .await?;

    oidc_success(&user.id, ip);

    Ok(session_cookie(
        SESSION_COOKIE,
        session_id,
        "/",
        SameSite::Lax,
        time::Duration::hours(SESSION_LIFETIME_HOURS),
        cookie_secure(),
    ))
}

/// GET /auth/callback — exchange code, validate ID token, create session,
/// set session cookie, redirect to frontend.
pub async fn callback_handler(
    State(state): State<AppAuthState>,
    Query(params): Query<CallbackParams>,
    headers: HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), (CookieJar, StatusCode)> {
    let ip = crate::api::notice::notice_ip(&headers, peer.map(|p| p.0));
    let ua = user_agent(&headers);
    let oidc = &state.oidc;

    // AC-8: claim the acknowledgement bound to this browser and `state`; no
    // claim, no session. Done before the code exchange, so a failed exchange
    // burns the acknowledgement. The binding cookie is cleared on every path.
    let (jar, claim) = claim_step(
        crate::api::rate_limit::global(),
        &state.pool,
        jar,
        &params.state,
        &ip,
    )
    .await?;

    // Everything after the claim; on error the (cookie-cleared) jar is still returned.
    let rest = finish_callback(
        oidc,
        &state.pool,
        &state.tasks,
        params.code,
        claim,
        &ip,
        &ua,
    )
    .await;

    match rest {
        Ok(c) => Ok((jar.add(c), Redirect::to(&oidc.frontend_url))),
        Err(code) => Err((jar, code)),
    }
}

/// POST /auth/logout — drop the session row and clear the cookie.
pub async fn logout_handler(
    State(state): State<AppAuthState>,
    jar: CookieJar,
) -> impl IntoResponse {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        let _ = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(c.value())
            .execute(state.pool.as_ref())
            .await;
    }
    let jar = jar.remove(removal_cookie(SESSION_COOKIE, "/", cookie_secure()));
    (jar, StatusCode::NO_CONTENT)
}

/// GET /api/users/me — return the authenticated user from request extensions.
pub async fn me_handler(req: Request) -> Result<Json<AuthUser>, StatusCode> {
    let user = req
        .extensions()
        .get::<AuthUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?
        .clone();
    Ok(Json(user))
}

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct UserSummary {
    pub id: String,
    pub display_name: String,
    pub role: String,
}

/// GET /api/users — list all users (id + display name + role) for
/// assignee/reviewer pickers. Auth-protected via the surrounding router;
/// we don't need the AuthUser here, only the DB pool, so we take
/// State<crate::AppState>.
pub async fn list_users_handler(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
) -> Result<Json<Vec<UserSummary>>, StatusCode> {
    let rows = sqlx::query_as::<_, UserSummary>(
        "SELECT id, display_name, role FROM users ORDER BY display_name",
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("list users failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(rows))
}

// ── Middleware ──────────────────────────────────────────────────────────────

/// Combined app state for handlers that need both pool and OIDC ctx.
#[derive(Clone)]
pub struct AppAuthState {
    pub pool: Arc<PgPool>,
    pub oidc: OidcContext,
    pub tasks: Arc<crate::detached::Tracker>,
}

/// Auth middleware:
/// 1. Session cookie (primary path)
/// 2. X-User-Id header, only if `ALLOW_TEST_AUTH_HEADER=true`. Startup
///    refuses that flag when `STIG_ENV=production`
///    (`config::TestHooks::validate`), so the bypass cannot be on there.
pub async fn auth_middleware(
    State(state): State<AppAuthState>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let user = resolve_session_user(&state.pool, &headers)
        .await
        .map_err(|e| {
            tracing::error!("session lookup failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let user = match user {
        Some(u) => u,
        None if state.oidc.allow_test_auth_header => {
            match test_header_user(&state.pool, &headers).await {
                Ok(Some(u)) => u,
                Ok(None) => return Err(StatusCode::UNAUTHORIZED),
                Err(e) => {
                    tracing::error!("test header auth failed: {e:#}");
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}

// ── DB helpers ──────────────────────────────────────────────────────────────

pub(crate) async fn upsert_user(
    pool: &PgPool,
    provider: &str,
    sub: &str,
    display_name: &str,
    email: &str,
) -> Result<AuthUser> {
    // Try to find existing user by (provider, sub).
    if let Some(existing) = sqlx::query_as::<_, AuthUser>(
        "SELECT id, display_name, email, role FROM users WHERE provider = $1 AND sub = $2",
    )
    .bind(provider)
    .bind(sub)
    .fetch_optional(pool)
    .await?
    {
        // Keep display name / email fresh.
        sqlx::query("UPDATE users SET display_name = $1, email = $2 WHERE id = $3")
            .bind(display_name)
            .bind(email)
            .bind(&existing.id)
            .execute(pool)
            .await?;
        return Ok(AuthUser {
            display_name: display_name.to_string(),
            email: email.to_string(),
            ..existing
        });
    }

    // Otherwise create. id = UUID for OIDC users.
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, display_name, email, sub, provider) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(display_name)
    .bind(email)
    .bind(sub)
    .bind(provider)
    .execute(pool)
    .await?;
    Ok(AuthUser {
        id,
        display_name: display_name.to_string(),
        email: email.to_string(),
        role: "author".to_string(),
    })
}

pub(crate) async fn create_session(
    pool: &PgPool,
    user_id: &str,
    ip: &str,
    user_agent: &str,
) -> Result<String> {
    let session_id = uuid::Uuid::new_v4().to_string();
    let expires_at: DateTime<Utc> = Utc::now() + Duration::hours(SESSION_LIFETIME_HOURS);
    sqlx::query(
        "INSERT INTO sessions (id, user_id, expires_at, ip, user_agent) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&session_id)
    .bind(user_id)
    .bind(expires_at)
    .bind(ip)
    .bind(user_agent)
    .execute(pool)
    .await?;
    // Track activity for the admin console. Updating on every newly minted
    // session captures real logins; the resolve path below also bumps it
    // when an existing session is reused so "last_login" tracks ongoing
    // activity rather than just first-ever auth.
    let _ = sqlx::query("UPDATE users SET last_login = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
    Ok(session_id)
}

/// Client IP from headers only (no socket peer): a validated canonical IP from
/// the trusted `X-Forwarded-For` hop when `STIG_TRUST_PROXY_HEADERS` is on,
/// else empty. Handlers that have `ConnectInfo` use `notice::notice_ip`.
pub(crate) fn client_ip(headers: &HeaderMap) -> String {
    // Validated and canonical, never the raw header text; no peer address is
    // available here, so this is empty unless proxy headers are trusted.
    crate::api::notice::notice_ip(headers, None)
}

/// Pull the `User-Agent` request header, defaulting to an empty
/// string. Used at session-creation time for the admin audit view.
pub(crate) fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

async fn resolve_session_user(pool: &PgPool, headers: &HeaderMap) -> Result<Option<AuthUser>> {
    let session_id = match cookie_value(headers, SESSION_COOKIE) {
        Some(v) => v,
        None => return Ok(None),
    };

    let row = sqlx::query_as::<_, AuthUser>(
        r#"
        SELECT u.id, u.display_name, u.email, u.role
          FROM sessions s
          JOIN users u ON u.id = s.user_id
         WHERE s.id = $1
           AND s.expires_at > NOW()
           AND s.revoked_at IS NULL
        "#,
    )
    .bind(&session_id)
    .fetch_optional(pool)
    .await?;

    // Treat an authenticated request that extends an existing session as a
    // "login" event for the admin console's last_login column. This keeps
    // the column meaningful for users who stay logged in for days.
    if let Some(u) = &row {
        let _ = sqlx::query("UPDATE users SET last_login = NOW() WHERE id = $1")
            .bind(&u.id)
            .execute(pool)
            .await;
    }
    Ok(row)
}

async fn test_header_user(pool: &PgPool, headers: &HeaderMap) -> Result<Option<AuthUser>> {
    let raw = match headers.get("X-User-Id").and_then(|v| v.to_str().ok()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return Ok(None),
    };
    let user = upsert_user(pool, "test", &raw, &raw, "").await?;
    // X-User-Id auth doesn't go through create_session organically, but
    // the admin "active sessions" panel + session-audit spec want a real
    // session row to look at. Mint a fresh one whenever the user has no
    // active (non-revoked, non-expired) session — that way after an
    // admin revoke the next request gets a brand-new session and the
    // user stays logged in (the bypass is test-only).
    let ip = client_ip(headers);
    let ua = user_agent(headers);
    let has_active: Option<String> = sqlx::query_scalar(
        "SELECT id FROM sessions \
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW() \
         LIMIT 1",
    )
    .bind(&user.id)
    .fetch_optional(pool)
    .await?;
    if has_active.is_none() {
        let _ = create_session(pool, &user.id, &ip, &ua).await?;
    } else {
        // Bypass already has a live session — just keep last_login fresh.
        let _ = sqlx::query("UPDATE users SET last_login = NOW() WHERE id = $1")
            .bind(&user.id)
            .execute(pool)
            .await;
    }
    Ok(Some(user))
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())?
        .split(';')
        .map(|c| c.trim())
        .find_map(|c| {
            let (k, v) = c.split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}

/// Replace the origin (scheme + host + port) of `url` from `from_origin`
/// to `to_origin`. Used to rewrite the docker-internal auth endpoint to
/// the browser-reachable URL.
fn rewrite_origin(url: url::Url, from_origin: &str, to_origin: &str) -> url::Url {
    let from = url::Url::parse(from_origin).ok();
    let to = url::Url::parse(to_origin).ok();
    let (from, to) = match (from, to) {
        (Some(f), Some(t)) => (f, t),
        _ => return url,
    };
    if url.scheme() != from.scheme() || url.host_str() != from.host_str() {
        return url;
    }
    let mut new = url.clone();
    let _ = new.set_scheme(to.scheme());
    let _ = new.set_host(to.host_str());
    let _ = new.set_port(to.port());
    new
}

#[cfg(test)]
mod cookie_tests {
    use super::*;

    #[test]
    fn secure_follows_production_or_https_frontend() {
        assert!(secure_for(Some("production"), None));
        assert!(secure_for(None, Some("https://stig.example")));
        assert!(secure_for(Some("dev"), Some(" HTTPS://x")));
        assert!(!secure_for(None, Some("http://localhost:5173")));
        assert!(!secure_for(None, None));
    }

    #[test]
    fn secure_attribute_follows_flag() {
        let c = session_cookie(
            "n",
            "v".into(),
            "/",
            SameSite::Lax,
            time::Duration::hours(1),
            true,
        );
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.http_only(), Some(true));
        let c = session_cookie(
            "n",
            "v".into(),
            "/",
            SameSite::Lax,
            time::Duration::hours(1),
            false,
        );
        assert_eq!(c.secure(), Some(false));
        assert_eq!(removal_cookie("n", "/auth", true).secure(), Some(true));
        assert_eq!(removal_cookie("n", "/auth", true).path(), Some("/auth"));
    }
}

#[cfg(test)]
mod claim_tests {
    use super::*;
    use crate::db_notice::{consume_ack, insert_ack, LoginBinding};

    #[test]
    fn saml_req_same_site_follows_secure() {
        assert_eq!(saml_req_same_site(true), SameSite::None);
        assert_eq!(saml_req_same_site(false), SameSite::Lax);
    }

    fn limiter(burst: &str) -> crate::api::rate_limit::PreAuthLimiter {
        crate::api::rate_limit::PreAuthLimiter::from_vars(Some(burst), Some("1"))
    }

    fn jar_with(v: Option<&str>) -> CookieJar {
        match v {
            // As the extractor builds it: from the request's Cookie header.
            Some(v) => {
                let mut h = HeaderMap::new();
                h.insert(
                    "cookie",
                    header::HeaderValue::from_str(&format!("{STATE_COOKIE}={v}")).unwrap(),
                );
                CookieJar::from_headers(&h)
            }
            None => CookieJar::new(),
        }
    }

    fn cleared(jar: CookieJar) -> bool {
        let r = jar.into_response();
        r.headers().get_all("set-cookie").iter().any(|h| {
            h.to_str()
                .is_ok_and(|v| v.starts_with("stig_oidc_state=;") && v.contains("Max-Age=0"))
        })
    }

    #[test]
    fn oidc_audit_lines_have_the_documented_fields() {
        let (cap, _g) = crate::api::audit_capture::capture();
        for r in ["token_exchange", "id_token"] {
            oidc_denied(r, "1.2.3.4");
        }
        oidc_success("u1", "1.2.3.4");
        let lines = cap.lines();
        assert_eq!(lines.len(), 3);
        for (l, reason) in lines.iter().zip(["token_exchange", "id_token"]) {
            assert_eq!(l["action"], "auth.oidc_callback");
            assert_eq!(l["outcome"], "denied");
            assert_eq!(l["reason"], reason);
            assert_eq!(l["ip"], "1.2.3.4");
        }
        assert_eq!(lines[2]["outcome"], "success");
        assert_eq!(lines[2]["user_id"], "u1");
        assert_eq!(lines[2]["ip"], "1.2.3.4");
    }

    #[tokio::test]
    async fn callback_is_rate_limited_before_touching_the_db() {
        // Lazy pool: never connected, since the limited path returns first.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://u:p@127.0.0.1:1/x")
            .unwrap();
        let (cap, _g) = crate::api::audit_capture::capture();
        let lim = limiter("1");
        let ip = "203.0.113.77";
        // First call spends the token (and fails on the missing cookie, no DB use).
        let first = claim_step(&lim, &pool, jar_with(None), "s", ip)
            .await
            .err()
            .unwrap();
        assert_eq!(first.1, StatusCode::BAD_REQUEST);
        let second = claim_step(&lim, &pool, jar_with(None), "s", ip)
            .await
            .err()
            .unwrap();
        assert_eq!(second.1, StatusCode::TOO_MANY_REQUESTS);
        let reasons: Vec<String> = cap.summary().into_iter().map(|s| s.2).collect();
        assert_eq!(reasons, ["no_state_cookie", "rate_limited"]);
    }

    #[tokio::test]
    async fn callback_refusal_without_a_db_clears_the_cookie_and_logs_the_reason() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(500))
            .connect_lazy("postgres://u:p@127.0.0.1:1/x")
            .unwrap();
        let (cap, _g) = crate::api::audit_capture::capture();
        let lim = limiter("100");
        let (_, code) = claim_step(&lim, &pool, jar_with(None), "s", "198.51.100.1")
            .await
            .err()
            .unwrap();
        assert_eq!(code, StatusCode::BAD_REQUEST);
        let (jar, code) = claim_step(&lim, &pool, jar_with(Some("junk")), "s", "198.51.100.1")
            .await
            .err()
            .unwrap();
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(cleared(jar));
        // Valid UUID against an unreachable DB: a distinct reason from a plain refusal.
        let id = uuid::Uuid::new_v4().to_string();
        let (jar, code) = claim_step(&lim, &pool, jar_with(Some(&id)), "s", "198.51.100.1")
            .await
            .err()
            .unwrap();
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(cleared(jar));
        let got = cap.summary();
        let want: Vec<_> = ["no_state_cookie", "malformed_state_cookie", "claim_error"]
            .iter()
            .map(|r| {
                (
                    "auth.oidc_callback".to_string(),
                    "denied".to_string(),
                    r.to_string(),
                )
            })
            .collect();
        assert_eq!(got, want);
        assert!(cap.lines().iter().all(|l| l["ip"] == "198.51.100.1"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn wrong_state_logs_ack_not_claimed(pool: PgPool) {
        let (cap, _g) = crate::api::audit_capture::capture();
        let id = uuid::Uuid::new_v4().to_string();
        insert_ack(&pool, &id, "v1", "", "", 300).await.unwrap();
        consume_ack(
            &pool,
            &id,
            "v1",
            &LoginBinding::Oidc {
                state: "st",
                nonce: "n",
                pkce_verifier: "p",
            },
        )
        .await
        .unwrap();
        let lim = limiter("100");
        let (jar, code) = claim_step(&lim, &pool, jar_with(Some(&id)), "wrong", "192.0.2.9")
            .await
            .err()
            .unwrap();
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(cleared(jar));
        assert_eq!(cap.summary()[0].2, "ack_not_claimed");
        // The forged navigation did not burn the in-flight login.
        assert!(
            claim_step(&lim, &pool, jar_with(Some(&id)), "st", "192.0.2.9")
                .await
                .is_ok()
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn state_cookie_claim_requires_matching_ack_and_state(pool: PgPool) {
        let id = uuid::Uuid::new_v4().to_string();
        insert_ack(&pool, &id, "v1", "", "", 300).await.unwrap();
        consume_ack(
            &pool,
            &id,
            "v1",
            &LoginBinding::Oidc {
                state: "st",
                nonce: "no",
                pkce_verifier: "pv",
            },
        )
        .await
        .unwrap();
        let other = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            claim_from_state_cookie(&pool, None, "st").await.err(),
            Some("no_state_cookie")
        );
        for junk in ["{\"ack_id\":\"x\"}", "junk"] {
            assert_eq!(
                claim_from_state_cookie(&pool, Some(junk), "st").await.err(),
                Some("malformed_state_cookie")
            );
        }
        assert_eq!(
            claim_from_state_cookie(&pool, Some(&other), "st")
                .await
                .err(),
            Some("ack_not_claimed")
        );
        assert_eq!(
            claim_from_state_cookie(&pool, Some(&id), "wrong")
                .await
                .err(),
            Some("ack_not_claimed")
        );
        let c = claim_from_state_cookie(&pool, Some(&id), "st")
            .await
            .unwrap();
        assert_eq!((c.nonce.as_str(), c.pkce_verifier.as_str()), ("no", "pv"));
        assert_eq!(
            claim_from_state_cookie(&pool, Some(&id), "st").await.err(),
            Some("ack_not_claimed")
        );
    }
}

#[cfg(test)]
mod callback_flow_tests {
    //! Drives `finish_callback` against a stub token endpoint, so the audit
    //! call sites (token_exchange, id_token, success) live in tested code.
    use super::*;
    use crate::api::saml_verify::fixtures::key;
    use crate::db_notice::{claim_oidc, consume_ack, insert_ack, OidcClaim};
    use axum::routing::post;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64U, Engine as _};
    use openidconnect::core::{
        CoreJwsSigningAlgorithm, CoreResponseType, CoreSubjectIdentifierType,
    };
    use openidconnect::{AuthUrl, JsonWebKeySetUrl, ResponseTypes, TokenUrl};
    use rsa::{
        pkcs1v15::SigningKey,
        sha2::Sha256,
        signature::{SignatureEncoding, Signer},
        traits::PublicKeyParts,
    };

    const ISS: &str = "https://idp.test/realms/x";
    /// Per-run random nonce, so no fixed value stands in for one.
    static NONCE: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| uuid::Uuid::new_v4().to_string());

    fn jwks() -> CoreJsonWebKeySet {
        let pk = key().1.to_public_key();
        serde_json::from_value(serde_json::json!({"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
            "n": B64U.encode(pk.n().to_bytes_be()),
            "e": B64U.encode(pk.e().to_bytes_be()),
        }]}))
        .unwrap()
    }

    fn id_token(nonce: &str, tamper: bool) -> String {
        let head = B64U.encode(r#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#);
        let now = Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": ISS, "sub": "sub-alice-0001", "aud": "cid", "exp": now + 600, "iat": now,
            "nonce": nonce, "email": "alice@example.com", "preferred_username": "alice",
        });
        let signing_input = format!("{head}.{}", B64U.encode(claims.to_string()));
        let sig = SigningKey::<Sha256>::new(key().1.clone()).sign(signing_input.as_bytes());
        let mut sig = sig.to_bytes().to_vec();
        if tamper {
            sig[0] ^= 0xff;
        }
        format!("{signing_input}.{}", B64U.encode(sig))
    }

    /// Stub token endpoint answering every POST with `status` and `body`.
    async fn stub(status: u16, body: String) -> std::net::SocketAddr {
        let app = axum::Router::new().route(
            "/token",
            post(move || {
                let body = body.clone();
                async move {
                    (
                        StatusCode::from_u16(status).unwrap(),
                        [("content-type", "application/json")],
                        body,
                    )
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        addr
    }

    fn ctx(token_addr: std::net::SocketAddr) -> OidcContext {
        let meta = CoreProviderMetadata::new(
            IssuerUrl::new(ISS.into()).unwrap(),
            AuthUrl::new("https://idp.test/auth".into()).unwrap(),
            JsonWebKeySetUrl::new("https://idp.test/jwks".into()).unwrap(),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Public],
            vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
            Default::default(),
        )
        .set_token_endpoint(Some(
            TokenUrl::new(format!("http://{token_addr}/token")).unwrap(),
        ));
        let client_id = ClientId::new("cid".into());
        let client_secret = ClientSecret::new("secret".into());
        let client = CoreClient::from_provider_metadata(
            meta,
            client_id.clone(),
            Some(client_secret.clone()),
        );
        OidcContext {
            client: Arc::new(client),
            http: reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            public_auth_base: "https://idp.test".into(),
            internal_issuer: ISS.into(),
            public_issuer: ISS.into(),
            jwks: jwks(),
            client_id,
            client_secret,
            frontend_url: "http://localhost:5173".into(),
            allow_test_auth_header: false,
        }
    }

    async fn claim(pool: &PgPool) -> OidcClaim {
        let id = uuid::Uuid::new_v4().to_string();
        insert_ack(pool, &id, "v1", "", "", 300).await.unwrap();
        let b = LoginBinding::Oidc {
            state: "st",
            nonce: &NONCE,
            pkce_verifier: "pv",
        };
        assert!(consume_ack(pool, &id, "v1", &b).await.unwrap());
        claim_oidc(pool, &id, "st").await.unwrap().unwrap()
    }

    fn token_resp(id_token: Option<String>) -> String {
        let mut v = serde_json::json!({"access_token": "at", "token_type": "bearer"});
        if let Some(t) = id_token {
            v["id_token"] = t.into();
        }
        v.to_string()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn callback_audit_lines_for_exchange_idtoken_and_success(pool: PgPool) {
        let (cap, _g) = crate::api::audit_capture::capture();
        let ip = "192.0.2.50";
        let run = |addr, c| {
            let (pool, ctx) = (Arc::new(pool.clone()), ctx(addr));
            let tasks = crate::detached::Tracker::new();
            async move { finish_callback(&ctx, &pool, &tasks, "code".into(), c, ip, "ua").await }
        };
        // Each step starts from an empty capture and must add exactly one line.
        let step = |expect: &str| {
            let l = cap.take_one();
            assert_eq!(l["action"], "auth.oidc_callback");
            assert_eq!(
                (
                    l["outcome"].as_str(),
                    l["reason"].as_str(),
                    l["ip"].as_str()
                ),
                ("denied", expect, ip)
            );
        };

        // Token endpoint refuses the exchange.
        let a = stub(400, r#"{"error":"invalid_grant"}"#.into()).await;
        let c = claim(&pool).await;
        cap.clear();
        assert_eq!(run(a, c).await.err(), Some(StatusCode::UNAUTHORIZED));
        step("token_exchange");

        // Token response without an ID token.
        let a = stub(200, token_resp(None)).await;
        let c = claim(&pool).await;
        cap.clear();
        assert_eq!(run(a, c).await.err(), Some(StatusCode::UNAUTHORIZED));
        step("id_token");

        // Bad signature, then wrong nonce (the claims-validation site).
        let other = uuid::Uuid::new_v4().to_string();
        for tok in [id_token(&NONCE, true), id_token(&other, false)] {
            let a = stub(200, token_resp(Some(tok))).await;
            let c = claim(&pool).await;
            cap.clear();
            assert_eq!(run(a, c).await.err(), Some(StatusCode::UNAUTHORIZED));
            step("id_token");
        }
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);

        // Valid, signed token: session, success line with the user id, audit row.
        let a = stub(200, token_resp(Some(id_token(&NONCE, false)))).await;
        let c = claim(&pool).await;
        cap.clear();
        let cookie = run(a, c).await.unwrap();
        assert_eq!(cookie.name(), SESSION_COOKIE);
        let l = cap.take_one();
        assert_eq!(
            (
                l["action"].as_str(),
                l["outcome"].as_str(),
                l["ip"].as_str()
            ),
            ("auth.oidc_callback", "success", ip)
        );
        let uid: String = sqlx::query_scalar("SELECT id FROM users WHERE provider='oidc'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!uid.is_empty());
        assert_eq!(l["user_id"], uid);
        let ok: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE action='auth.notice_ack' AND outcome='ok' AND user_id=$1")
            .bind(&uid).fetch_one(&pool).await.unwrap();
        assert_eq!(ok, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn notice_ack_survives_the_callback_future_being_dropped(pool: PgPool) {
        let a = stub(200, token_resp(Some(id_token(&NONCE, false)))).await;
        let c = claim(&pool).await;
        let ctx = ctx(a);
        let pool_arc = Arc::new(pool.clone());
        let tasks = crate::detached::Tracker::new();
        crate::detached::abort_once_spawned(
            &tasks,
            finish_callback(
                &ctx,
                &pool_arc,
                &tasks,
                "code".into(),
                c,
                "192.0.2.50",
                "ua",
            ),
        )
        .await;
        tasks.idle().await;
        crate::db_audit::drain().await;
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(sessions, 1);
        let acks: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE action='auth.notice_ack' AND outcome='ok'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(acks, 1);
    }
}
