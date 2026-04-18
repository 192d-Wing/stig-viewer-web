//! OIDC authentication — relying-party side.
//!
//! # Flow
//!
//! 1. `GET /api/auth/login` — start auth: store state + nonce + PKCE verifier
//!    in a short-lived signed cookie and 302 to the IdP authorization endpoint.
//! 2. `GET /api/auth/callback` — exchange code for tokens, verify ID token +
//!    nonce, map IdP groups to an internal role, write an encrypted session
//!    cookie, and redirect back to the frontend.
//! 3. `GET /api/auth/me` — return the current session's user + role.
//! 4. `POST /api/auth/logout` — clear the session cookie.
//!
//! # Dev bypass
//!
//! When `OIDC_ISSUER_URL` (and the other required vars) aren't configured,
//! [`AuthState::try_from_env`] returns `None` and the router falls back to an
//! open mode — every protected handler sees a synthetic admin user. A warning
//! is logged at startup; production must set `REQUIRE_AUTH=1` to make this
//! startup condition fatal.

pub mod client;
pub mod extractor;
pub mod handlers;
pub mod session;

use anyhow::Result;
use axum_extra::extract::cookie::Key;
use openidconnect::core::CoreClient;
use std::sync::Arc;

use crate::config::Config;

/// OIDC relying-party configuration, loaded from env.
#[derive(Debug, Clone, Default)]
pub struct OidcConfig {
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub session_secret: Option<String>,
    pub post_login_redirect: String,
    pub allowed_groups: Vec<String>,
    pub admin_group: Option<String>,
    pub editor_group: Option<String>,
    pub viewer_group: Option<String>,
}

impl OidcConfig {
    pub fn from_env() -> Self {
        let read = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
        let allowed_groups = read("ALLOWED_GROUPS")
            .map(|s| s.split(',').map(|g| g.trim().to_string()).collect())
            .unwrap_or_default();

        Self {
            issuer_url: read("OIDC_ISSUER_URL"),
            client_id: read("OIDC_CLIENT_ID"),
            client_secret: read("OIDC_CLIENT_SECRET"),
            redirect_uri: read("OIDC_REDIRECT_URI"),
            session_secret: read("SESSION_SECRET"),
            // Where the IdP-returned callback redirects the browser after
            // a successful login. Defaults to the frontend dev server.
            post_login_redirect: read("OIDC_POST_LOGIN_REDIRECT")
                .unwrap_or_else(|| "http://localhost:5173".into()),
            allowed_groups,
            admin_group: read("OIDC_ADMIN_GROUP"),
            editor_group: read("OIDC_EDITOR_GROUP"),
            viewer_group: read("OIDC_VIEWER_GROUP"),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.issuer_url.is_some()
            && self.client_id.is_some()
            && self.client_secret.is_some()
            && self.redirect_uri.is_some()
            && self.session_secret.is_some()
    }
}

/// Role assigned to an authenticated session, derived from IdP group claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Editor,
    Admin,
}

impl Role {
    pub fn from_groups(cfg: &OidcConfig, groups: &[String]) -> Option<Self> {
        let has =
            |name: &Option<String>| name.as_ref().is_some_and(|n| groups.iter().any(|g| g == n));
        if has(&cfg.admin_group) {
            Some(Role::Admin)
        } else if has(&cfg.editor_group) {
            Some(Role::Editor)
        } else if has(&cfg.viewer_group) {
            Some(Role::Viewer)
        } else {
            None
        }
    }
}

/// Fully-initialised auth subsystem: discovery done, cookie key derived.
#[derive(Clone)]
pub struct AuthState {
    pub config: Arc<OidcConfig>,
    pub client: Arc<CoreClient>,
    pub cookie_key: Key,
}

impl AuthState {
    /// Attempt to bring OIDC up. Returns `Ok(None)` if not configured (dev-open
    /// mode); `Err` if configured but discovery or key derivation fails.
    pub async fn try_from_env(_cfg: &Config) -> Result<Option<Self>> {
        let oidc = OidcConfig::from_env();
        if !oidc.is_enabled() {
            return Ok(None);
        }
        let key = session::derive_key(oidc.session_secret.as_deref().unwrap_or_default())?;
        let client = client::build(&oidc).await?;
        Ok(Some(Self {
            config: Arc::new(oidc),
            client: Arc::new(client),
            cookie_key: key,
        }))
    }
}

pub use handlers::routes;
