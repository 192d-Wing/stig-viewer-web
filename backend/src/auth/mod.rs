//! OIDC authentication — relying-party side.
//!
//! # Plan
//!
//! This module is a scaffold. Implementation lands in a follow-up PR.
//!
//! ## Flow
//!
//! 1. `GET /api/auth/login` — redirect to IdP authorization endpoint, state +
//!    PKCE verifier stored in a signed cookie.
//! 2. `GET /api/auth/callback` — exchange code for tokens, verify ID token,
//!    look up / create a user row, write session cookie, redirect to frontend.
//! 3. `GET /api/auth/me` — return the current session's user + role.
//! 4. `POST /api/auth/logout` — clear session cookie, optionally RP-initiated
//!    logout at the IdP.
//!
//! ## Middleware
//!
//! An Axum extractor (`AuthUser`) parses the session cookie on every request to
//! a protected route and injects the user + role. A second extractor
//! (`RequireRole(Role::Admin)`) gates admin endpoints.
//!
//! ## Role mapping
//!
//! The IdP's `groups` claim is compared against `OIDC_ADMIN_GROUP`,
//! `OIDC_EDITOR_GROUP`, `OIDC_VIEWER_GROUP`. Highest-privilege match wins.
//! Users with no matching group are rejected at callback if `ALLOWED_GROUPS`
//! is non-empty.
//!
//! ## Libraries (proposed)
//!
//! - `openidconnect` — discovery, token verification, userinfo
//! - `tower-cookies` or `axum-extra::extract::cookie` — signed cookies
//! - `rand` + `base64` — state + PKCE
//!
//! ## Session storage
//!
//! Encrypted cookie holding `{user_id, role, exp}`. No server-side session
//! table in the first cut; revoke on logout by setting an expired cookie.
//! Revisit if we need forced logout across devices.

// Scaffold: every item below is wired up in the follow-up PR that implements
// the OIDC flow. Silence the dead-code warning at module scope until then.
#![allow(dead_code)]

use anyhow::Result;

/// OIDC relying-party configuration, loaded from env.
///
/// All fields are optional at the type level so the server can boot without
/// OIDC configured during local development. Production startup should call
/// [`OidcConfig::require`] to fail fast.
#[derive(Debug, Clone, Default)]
pub struct OidcConfig {
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub session_secret: Option<String>,
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
            allowed_groups,
            admin_group: read("OIDC_ADMIN_GROUP"),
            editor_group: read("OIDC_EDITOR_GROUP"),
            viewer_group: read("OIDC_VIEWER_GROUP"),
        }
    }

    /// True once all required OIDC env vars are populated.
    pub fn is_enabled(&self) -> bool {
        self.issuer_url.is_some()
            && self.client_id.is_some()
            && self.client_secret.is_some()
            && self.redirect_uri.is_some()
            && self.session_secret.is_some()
    }

    /// For production: returns Err if auth is not fully configured.
    pub fn require(&self) -> Result<()> {
        if self.is_enabled() {
            Ok(())
        } else {
            anyhow::bail!(
                "OIDC is not fully configured. Required env vars: \
                 OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, \
                 OIDC_REDIRECT_URI, SESSION_SECRET. See .env.example."
            )
        }
    }
}

/// Role assigned to an authenticated session, derived from IdP group claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Editor,
    Admin,
}

impl Role {
    /// Pick the highest-privilege role matching the user's IdP groups.
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
