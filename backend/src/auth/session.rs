//! Session cookie helpers: key derivation and payload types.

use anyhow::{Context, Result};
use axum_extra::extract::cookie::Key;
use serde::{Deserialize, Serialize};

use super::Role;

/// Name of the encrypted session cookie set after successful login.
pub const SESSION_COOKIE: &str = "stig_session";

/// Name of the short-lived cookie that carries OAuth state + nonce + PKCE
/// verifier between `/login` and `/callback`.
pub const OAUTH_STATE_COOKIE: &str = "stig_oauth_state";

/// Seconds the OAuth-state cookie is valid. 10 minutes is generous for a
/// user to finish authenticating at the IdP.
pub const OAUTH_STATE_TTL_SECS: i64 = 600;

/// Session cookie payload. Stored encrypted via `PrivateCookieJar`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub sub: String,
    pub email: Option<String>,
    pub role: Role,
    /// Unix timestamp (seconds) at which the session expires.
    pub exp: i64,
}

impl SessionData {
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() >= self.exp
    }
}

/// OAuth state cookie payload. Written at `/login`, read at `/callback`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    pub csrf: String,
    pub nonce: String,
    pub pkce_verifier: String,
    /// Absolute URL to redirect the browser to after login completes.
    pub return_to: String,
}

/// Derive a `cookie::Key` from the hex-encoded `SESSION_SECRET` env var.
///
/// We require at least 32 bytes (= 64 hex chars) since the underlying
/// `Key::from` needs a >= 64-byte buffer for HMAC-SHA-512; we stretch a
/// 32-byte input by concatenating with its SHA-256 hash.
pub fn derive_key(hex_secret: &str) -> Result<Key> {
    use sha2::{Digest, Sha256, Sha512};

    let raw = hex::decode(hex_secret.trim())
        .context("SESSION_SECRET must be hex-encoded (e.g. `openssl rand -hex 32`)")?;
    anyhow::ensure!(
        raw.len() >= 32,
        "SESSION_SECRET must be at least 32 bytes (64 hex chars)"
    );

    // Expand to 64 bytes deterministically so Key::from always has enough
    // material regardless of input length >= 32.
    let mut expanded = Vec::with_capacity(64);
    expanded.extend_from_slice(&Sha512::digest(&raw));
    // Mix in the original bytes for key separation vs. plain SHA-512.
    for (i, b) in Sha256::digest(&raw).iter().enumerate() {
        expanded[i] ^= *b;
    }
    Ok(Key::from(&expanded))
}
