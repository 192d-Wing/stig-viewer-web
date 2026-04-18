//! OIDC HTTP handlers: /login, /callback, /logout, /me.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use openidconnect::{
    core::CoreAuthenticationFlow, reqwest::async_http_client, AuthorizationCode, CsrfToken, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use time::Duration as TimeDuration;
use tracing::{debug, error, warn};

use super::session::{
    OAuthState, SessionData, OAUTH_STATE_COOKIE, OAUTH_STATE_TTL_SECS, SESSION_COOKIE,
};
use super::Role;
use crate::AppState;

/// Mount the auth routes at their public paths.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/login", get(login))
        .route("/api/auth/callback", get(callback))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
}

// ── /me ──────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct MeResponse {
    sub: String,
    email: Option<String>,
    role: Role,
    exp: i64,
}

async fn me(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
) -> Result<Json<MeResponse>, StatusCode> {
    // 204 when auth is disabled: frontend should treat the user as anonymous
    // and not prompt for login.
    state.auth.as_ref().ok_or(StatusCode::NO_CONTENT)?;
    let session = read_session(&jar).ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(MeResponse {
        sub: session.sub,
        email: session.email,
        role: session.role,
        exp: session.exp,
    }))
}

// ── /login ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct LoginQuery {
    /// Where to return the user after successful login. Must be an absolute
    /// URL on the configured `post_login_redirect` origin (validated below).
    return_to: Option<String>,
}

async fn login(
    State(state): State<AppState>,
    Query(q): Query<LoginQuery>,
    jar: PrivateCookieJar,
) -> Response {
    let Some(auth) = state.auth.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Authentication is not configured on this server",
        )
            .into_response();
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token, nonce) = auth
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

    let return_to = validate_return_to(q.return_to.as_deref(), &auth.config.post_login_redirect)
        .unwrap_or_else(|| auth.config.post_login_redirect.clone());

    let oauth_state = OAuthState {
        csrf: csrf_token.secret().to_string(),
        nonce: nonce.secret().to_string(),
        pkce_verifier: pkce_verifier.secret().to_string(),
        return_to,
    };

    let jar = match serde_json::to_string(&oauth_state) {
        Ok(s) => jar.add(build_state_cookie(s)),
        Err(e) => {
            error!("failed to serialize oauth state: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "login failed").into_response();
        }
    };

    (jar, Redirect::temporary(auth_url.as_str())).into_response()
}

// ── /callback ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Extra claims we pull out of the ID token payload — openidconnect doesn't
/// typed-parse non-standard claims like `groups` so we do it manually.
#[derive(Deserialize, Default)]
struct IdTokenExtraClaims {
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    email: Option<String>,
}

async fn callback(
    State(state): State<AppState>,
    Query(q): Query<CallbackQuery>,
    jar: PrivateCookieJar,
) -> Response {
    let Some(auth) = state.auth.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "auth not configured").into_response();
    };

    // Surface IdP-reported errors early.
    if let Some(err) = q.error.as_deref() {
        let desc = q.error_description.as_deref().unwrap_or("");
        warn!("IdP returned error at callback: {err} ({desc})");
        return (StatusCode::UNAUTHORIZED, format!("login failed: {err}")).into_response();
    }

    let code = match q.code {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "missing `code`").into_response(),
    };
    let state_param = match q.state {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "missing `state`").into_response(),
    };

    // Read and drop the OAuth state cookie (single-use).
    let Some(oauth_state_raw) = jar.get(OAUTH_STATE_COOKIE).map(|c| c.value().to_string()) else {
        return (
            StatusCode::BAD_REQUEST,
            "login session expired, please retry",
        )
            .into_response();
    };
    let jar = jar.remove(Cookie::from(OAUTH_STATE_COOKIE));

    let oauth_state: OAuthState = match serde_json::from_str(&oauth_state_raw) {
        Ok(s) => s,
        Err(e) => {
            warn!("corrupt oauth state cookie: {e}");
            return (StatusCode::BAD_REQUEST, "bad login state").into_response();
        }
    };

    if oauth_state.csrf != state_param {
        warn!("CSRF mismatch at callback");
        return (StatusCode::BAD_REQUEST, "CSRF state mismatch").into_response();
    }

    // Exchange the authorization code for tokens.
    let token_response = match auth
        .client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(oauth_state.pkce_verifier))
        .request_async(async_http_client)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("token exchange failed: {e}");
            return (StatusCode::UNAUTHORIZED, "token exchange failed").into_response();
        }
    };

    let id_token = match token_response.id_token() {
        Some(t) => t,
        None => {
            error!("no id_token in token response");
            return (StatusCode::UNAUTHORIZED, "missing id_token").into_response();
        }
    };

    // openidconnect verifies signature, issuer, audience, and our nonce.
    let verifier = auth.client.id_token_verifier();
    let expected_nonce = Nonce::new(oauth_state.nonce);
    let claims = match id_token.claims(&verifier, &expected_nonce) {
        Ok(c) => c,
        Err(e) => {
            warn!("id_token verification failed: {e}");
            return (StatusCode::UNAUTHORIZED, "id_token invalid").into_response();
        }
    };

    // Parse custom claims (groups, email) from the raw ID token payload.
    let extra = match parse_extra_claims(&id_token.to_string()) {
        Ok(e) => e,
        Err(e) => {
            warn!("failed to decode id_token payload: {e}");
            IdTokenExtraClaims::default()
        }
    };

    // Role derivation.
    let role = match Role::from_groups(&auth.config, &extra.groups) {
        Some(r) => r,
        None => {
            // If ALLOWED_GROUPS is set and none matched, reject; otherwise
            // default to Viewer so non-group-managed IdPs still work.
            if !auth.config.allowed_groups.is_empty() {
                warn!(
                    "user {} has no matching group (has: {:?})",
                    claims.subject().as_str(),
                    extra.groups
                );
                return (StatusCode::FORBIDDEN, "no access").into_response();
            }
            Role::Viewer
        }
    };

    let sub = claims.subject().to_string();
    let email = extra
        .email
        .or_else(|| claims.email().map(|e| e.as_str().to_string()));
    let exp = claims.expiration().timestamp();

    debug!("login: sub={sub} role={role:?} exp={exp}");

    let session = SessionData {
        sub,
        email,
        role,
        exp,
    };

    let jar = match serde_json::to_string(&session) {
        Ok(s) => jar.add(build_session_cookie(s, exp)),
        Err(e) => {
            error!("failed to serialize session: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "login failed").into_response();
        }
    };

    (jar, Redirect::temporary(&oauth_state.return_to)).into_response()
}

// ── /logout ──────────────────────────────────────────────────────────────────

async fn logout(State(_state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let jar = jar.remove(Cookie::from(SESSION_COOKIE));
    (jar, StatusCode::NO_CONTENT).into_response()
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Decode the middle (payload) segment of a JWT and pull our extra claims.
fn parse_extra_claims(jwt: &str) -> anyhow::Result<IdTokenExtraClaims> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let segment = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("id_token does not look like a JWT (no `.` separators)"))?;
    let bytes = URL_SAFE_NO_PAD.decode(segment.as_bytes())?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_session(jar: &PrivateCookieJar) -> Option<SessionData> {
    let raw = jar.get(SESSION_COOKIE)?;
    let s: SessionData = serde_json::from_str(raw.value()).ok()?;
    if s.is_expired() {
        return None;
    }
    Some(s)
}

fn build_session_cookie(value: String, exp_unix: i64) -> Cookie<'static> {
    // PrivateCookieJar handles encryption; we only set transport flags.
    let now = chrono::Utc::now().timestamp();
    let secs = (exp_unix - now).max(60);
    let mut c = Cookie::new(SESSION_COOKIE, value);
    c.set_http_only(true);
    c.set_secure(is_secure_transport());
    c.set_same_site(SameSite::Lax);
    c.set_path("/");
    c.set_max_age(TimeDuration::seconds(secs));
    c
}

fn build_state_cookie(value: String) -> Cookie<'static> {
    let mut c = Cookie::new(OAUTH_STATE_COOKIE, value);
    c.set_http_only(true);
    c.set_secure(is_secure_transport());
    c.set_same_site(SameSite::Lax);
    c.set_path("/api/auth");
    c.set_max_age(TimeDuration::seconds(OAUTH_STATE_TTL_SECS));
    c
}

fn is_secure_transport() -> bool {
    // Cookies marked Secure won't be sent to http:// URLs. In dev we want
    // them on plain http://localhost, so opt in only when explicitly asked.
    std::env::var("COOKIE_SECURE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Accept a `return_to` URL only if it shares an origin with `allowed_origin`.
/// Prevents open-redirect via the login endpoint.
fn validate_return_to(return_to: Option<&str>, allowed_origin: &str) -> Option<String> {
    let candidate = return_to?;
    let parsed = url::Url::parse(candidate).ok()?;
    let allowed = url::Url::parse(allowed_origin).ok()?;
    if parsed.scheme() == allowed.scheme()
        && parsed.host_str() == allowed.host_str()
        && parsed.port_or_known_default() == allowed.port_or_known_default()
    {
        Some(candidate.to_string())
    } else {
        None
    }
}
