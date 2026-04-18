//! `require_auth` middleware.
//!
//! When OIDC is configured, the middleware reads the encrypted session cookie
//! and inserts a [`SessionData`] into request extensions. Handlers pull it
//! out via `Extension<SessionData>`. When OIDC isn't configured (dev open
//! mode), a synthetic admin session is injected instead, so handlers can be
//! written without branching.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::PrivateCookieJar;
use tracing::debug;

use super::session::{SessionData, SESSION_COOKIE};
use super::Role;
use crate::AppState;

pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if state.auth.is_none() {
        req.extensions_mut().insert(dev_synthetic_user(&state));
        return Ok(next.run(req).await);
    }

    let session = read_session_from_headers(&state, &req).ok_or(StatusCode::UNAUTHORIZED)?;
    // Paranoia: any path that accepts an unbound org_id is a tenant leak.
    if session.active_org_id == 0 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    req.extensions_mut().insert(session);
    Ok(next.run(req).await)
}

fn read_session_from_headers(state: &AppState, req: &Request) -> Option<SessionData> {
    let auth = state.auth.as_ref()?;
    let jar = PrivateCookieJar::from_headers(req.headers(), auth.cookie_key.clone());
    let cookie = jar.get(SESSION_COOKIE)?;
    let session: SessionData = serde_json::from_str(cookie.value())
        .inspect_err(|e| debug!("bad session cookie: {e}"))
        .ok()?;
    if session.is_expired() {
        debug!("expired session for sub={}", session.sub);
        return None;
    }
    Some(session)
}

fn dev_synthetic_user(state: &AppState) -> SessionData {
    SessionData {
        sub: "dev-open-mode".into(),
        email: Some("dev@local".into()),
        role: Role::Admin,
        exp: chrono::Utc::now().timestamp() + 86_400,
        active_org_id: state.default_org.id,
        active_org_slug: state.default_org.slug.clone(),
    }
}
