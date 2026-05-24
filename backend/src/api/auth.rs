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
    reqwest, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
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
    pub internal_issuer: String,  // e.g. http://keycloak:8081/realms/stig-viewer  (used for discovery)
    pub public_issuer: String,    // e.g. http://localhost:8081/realms/stig-viewer  (what tokens actually carry as iss)
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
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            internal_issuer_url: std::env::var("OIDC_INTERNAL_URL")
                .unwrap_or_else(|_| "http://keycloak:8081/realms/stig-viewer".into()),
            public_auth_base: std::env::var("OIDC_PUBLIC_URL")
                .unwrap_or_else(|_| "http://localhost:8081".into()),
            client_id: std::env::var("OIDC_CLIENT_ID")
                .unwrap_or_else(|_| "stig-viewer-app".into()),
            client_secret: std::env::var("OIDC_CLIENT_SECRET")
                .unwrap_or_else(|_| "dev-only-not-a-real-secret".into()),
            redirect_uri: std::env::var("OIDC_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:8080/auth/callback".into()),
            frontend_url: std::env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:5173".into()),
            allow_test_auth_header: std::env::var("ALLOW_TEST_AUTH_HEADER")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
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

// ── State cookie payload (PKCE verifier + nonce + CSRF) ────────────────────

#[derive(Serialize, Deserialize)]
struct AuthState {
    pkce_verifier: String,
    csrf_token: String,
    nonce: String,
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// GET /auth/login — start the OIDC Authorization Code + PKCE flow.
pub async fn login_handler(
    State(state): State<AppAuthState>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let oidc = &state.oidc;
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

    let state = AuthState {
        pkce_verifier: pkce_verifier.secret().clone(),
        csrf_token: csrf_token.secret().clone(),
        nonce: nonce.secret().clone(),
    };
    let state_json = serde_json::to_string(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let cookie = Cookie::build((STATE_COOKIE, state_json))
        .path("/auth")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::minutes(10))
        .build();

    Ok((jar.add(cookie), Redirect::to(auth_url.as_str())))
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

/// GET /auth/callback — exchange code, validate ID token, create session,
/// set session cookie, redirect to frontend.
pub async fn callback_handler(
    State(state): State<AppAuthState>,
    Query(params): Query<CallbackParams>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let oidc = &state.oidc;

    // Pull AuthState from the state cookie and clear it.
    let state_cookie = jar
        .get(STATE_COOKIE)
        .ok_or(StatusCode::BAD_REQUEST)?
        .value()
        .to_string();
    let auth_state: AuthState =
        serde_json::from_str(&state_cookie).map_err(|_| StatusCode::BAD_REQUEST)?;
    let jar = jar.remove(Cookie::build(STATE_COOKIE).path("/auth").build());

    // CSRF check (defense in depth — PKCE already binds the flow).
    if auth_state.csrf_token != params.state {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Exchange code for tokens.
    let token_response = oidc
        .client
        .exchange_code(AuthorizationCode::new(params.code))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .set_pkce_verifier(PkceCodeVerifier::new(auth_state.pkce_verifier))
        .request_async(&oidc.http)
        .await
        .map_err(|e| {
            tracing::error!("OIDC token exchange failed: {e:#}");
            StatusCode::UNAUTHORIZED
        })?;

    // Validate ID token. Build the verifier with the PUBLIC issuer URL
    // (matching what the IdP put in the iss claim — Keycloak ties iss to
    // the hostname the browser used at auth time, not where the backend
    // exchanges the code) and reuse the JWKS fetched at discovery time.
    let id_token = token_response
        .id_token()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let verifier_issuer = IssuerUrl::new(oidc.public_issuer.clone())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let id_token_verifier = CoreIdTokenVerifier::new_confidential_client(
        oidc.client_id.clone(),
        oidc.client_secret.clone(),
        verifier_issuer,
        oidc.jwks.clone(),
    );
    let claims = id_token
        .claims(&id_token_verifier, &Nonce::new(auth_state.nonce))
        .map_err(|e| {
            tracing::error!("ID token validation failed: {e:#}");
            StatusCode::UNAUTHORIZED
        })?;

    let sub = claims.subject().to_string();
    let email = claims
        .email()
        .map(|e| e.to_string())
        .unwrap_or_default();
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
    let user = upsert_user(&state.pool, "oidc", &sub, &display_name, &email)
        .await
        .map_err(|e| {
            tracing::error!("upsert_user failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Create server-side session, set cookie.
    let session_id = create_session(&state.pool, &user.id)
        .await
        .map_err(|e| {
            tracing::error!("create_session failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let session_cookie = Cookie::build((SESSION_COOKIE, session_id))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::hours(SESSION_LIFETIME_HOURS))
        .build();

    Ok((jar.add(session_cookie), Redirect::to(&oidc.frontend_url)))
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
    let jar = jar.remove(Cookie::build(SESSION_COOKIE).path("/").build());
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
}

/// GET /api/users — list all users (id + display name) for assignee pickers.
/// Auth-protected via the surrounding router; we don't need the AuthUser
/// here, only the DB pool, so we take State<crate::AppState>.
pub async fn list_users_handler(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
) -> Result<Json<Vec<UserSummary>>, StatusCode> {
    let rows = sqlx::query_as::<_, UserSummary>(
        "SELECT id, display_name FROM users ORDER BY display_name",
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
}

/// Auth middleware:
/// 1. Session cookie (primary path)
/// 2. X-User-Id header (only if `ALLOW_TEST_AUTH_HEADER=true` AND not production)
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

pub(crate) async fn create_session(pool: &PgPool, user_id: &str) -> Result<String> {
    let session_id = uuid::Uuid::new_v4().to_string();
    let expires_at: DateTime<Utc> = Utc::now() + Duration::hours(SESSION_LIFETIME_HOURS);
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(&session_id)
        .bind(user_id)
        .bind(expires_at)
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
         WHERE s.id = $1 AND s.expires_at > NOW()
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
    // X-User-Id auth doesn't go through create_session, so stamp the
    // last_login here so E2E + admin-console scenarios still see activity.
    let _ = sqlx::query("UPDATE users SET last_login = NOW() WHERE id = $1")
        .bind(&user.id)
        .execute(pool)
        .await;
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

