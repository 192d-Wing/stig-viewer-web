//! Ed25519 detached signing endpoints.
//!
//! The server holds one Ed25519 key pair (configured via `SIGNING_KEY_HEX`).
//! `POST /api/sign` takes an arbitrary blob of bytes, hashes it, wraps the
//! hash plus metadata in a small JSON "signing document", and returns a
//! detached signature over that document. The content itself never has to
//! leave the client if they prefer to sign the hash — include the content
//! in the request only so the server can audit what was signed.
//!
//! `GET /api/signing/pubkey` returns the verifying key in raw base64 plus
//! a short `key_id` fingerprint so verifiers can check signatures offline
//! against a trusted copy of the public key.
//!
//! Threat model: the signature attests that the server saw exactly these
//! bytes, at this time, under this authenticated user's session. Replay is
//! prevented by the `signedAt` timestamp embedded in the signing document.

use axum::{
    extract::{ConnectInfo, Extension, State},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

use crate::{
    api::error::ApiError,
    audit::{self, AuditEntry},
    auth::session::SessionData,
    AppState,
};

/// Server-side signing state. Cloned into `AppState` at startup; `None` when
/// `SIGNING_KEY_HEX` isn't set, which makes all endpoints 503.
#[derive(Clone)]
pub struct SigningState {
    pub signing_key: std::sync::Arc<Ed25519SigningKey>,
    /// Short fingerprint of the public key — first 8 bytes of the SHA-256
    /// of the raw verifying-key bytes, hex-encoded. Lets clients recognise
    /// when a signature was produced with a rotated key.
    pub key_id: String,
}

impl SigningState {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let Some(hex_str) = std::env::var("SIGNING_KEY_HEX")
            .ok()
            .filter(|s| !s.trim().is_empty())
        else {
            return Ok(None);
        };
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| anyhow::anyhow!("SIGNING_KEY_HEX is not valid hex: {e}"))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "SIGNING_KEY_HEX must decode to exactly 32 bytes (got {})",
                bytes.len()
            );
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        let signing_key = Ed25519SigningKey::from_bytes(&seed);
        let key_id = compute_key_id(&signing_key.verifying_key());
        Ok(Some(Self {
            signing_key: std::sync::Arc::new(signing_key),
            key_id,
        }))
    }
}

fn compute_key_id(vk: &VerifyingKey) -> String {
    let digest = Sha256::digest(vk.as_bytes());
    hex::encode(&digest[..8])
}

// ── Handlers ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct PubkeyResponse {
    pub algorithm: &'static str,
    pub key_id: String,
    /// Raw public key bytes, base64-standard (not URL-safe) encoded.
    pub public_key: String,
}

pub async fn pubkey(State(state): State<AppState>) -> Result<Json<PubkeyResponse>, ApiError> {
    let sk = state
        .signing
        .as_ref()
        .ok_or_else(|| ApiError::Unavailable("signing is not configured".into()))?;
    Ok(Json(PubkeyResponse {
        algorithm: "ed25519",
        key_id: sk.key_id.clone(),
        public_key: BASE64.encode(sk.signing_key.verifying_key().as_bytes()),
    }))
}

#[derive(Deserialize)]
pub struct SignRequest {
    /// Base64-standard encoded bytes to be signed. The server hashes these
    /// and signs the hash along with metadata.
    pub content: String,
    /// Optional free-text identifier baked into the signing document — the
    /// frontend typically fills this with the STIG id so auditors can trace
    /// a signature back to its source resource.
    #[serde(default)]
    pub resource: Option<String>,
}

/// Canonical signing document. Field order is stable because serde honors
/// the struct declaration order, so two servers with the same code produce
/// byte-identical JSON for identical inputs. Verifiers reconstruct this
/// struct from the response and verify `signature` against its bytes.
#[derive(Serialize)]
pub struct SigningDocument {
    pub algorithm: &'static str,
    pub sha256: String,
    pub signed_at: String,
    pub signed_by: String,
    pub signed_org: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

#[derive(Serialize)]
pub struct SignedBundle {
    pub document: SigningDocument,
    /// Base64-standard encoded 64-byte Ed25519 signature.
    pub signature: String,
    pub key_id: String,
}

pub async fn sign(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<SignRequest>,
) -> Result<Json<SignedBundle>, ApiError> {
    let sk = state
        .signing
        .as_ref()
        .ok_or_else(|| ApiError::Unavailable("signing is not configured".into()))?;

    let content = BASE64
        .decode(body.content.trim())
        .map_err(|e| ApiError::BadRequest(format!("content must be base64: {e}")))?;
    if content.is_empty() {
        return Err(ApiError::BadRequest("content must not be empty".into()));
    }
    // Cap by library upload limit — anyone legitimately signing larger than
    // this should be signing the hash client-side, not sending bytes.
    if content.len() > state.config.max_library_bytes {
        return Err(ApiError::PayloadTooLarge {
            message: format!(
                "content exceeds MAX_LIBRARY_BYTES ({} > {})",
                content.len(),
                state.config.max_library_bytes
            ),
            limit_bytes: state.config.max_library_bytes,
            actual_bytes: content.len(),
        });
    }

    let sha = Sha256::digest(&content);
    let document = SigningDocument {
        algorithm: "ed25519",
        sha256: hex::encode(sha),
        signed_at: chrono::Utc::now().to_rfc3339(),
        signed_by: session.sub.clone(),
        signed_org: session.active_org_slug.clone(),
        resource: body.resource.clone().filter(|s| !s.is_empty()),
    };

    let doc_bytes = serde_json::to_vec(&document)
        .map_err(|e| ApiError::Internal(format!("canonicalise document: {e}")))?;
    let signature = sk.signing_key.sign(&doc_bytes);

    audit::log(
        &state.pool,
        AuditEntry {
            session: &session,
            action: "signing.sign",
            resource: document.resource.as_deref(),
            remote_ip: Some(addr.ip().to_string()),
            status_code: 200,
            metadata: Some(serde_json::json!({
                "sha256": document.sha256,
                "keyId": sk.key_id,
                "bytes": content.len(),
            })),
        },
    )
    .await;

    Ok(Json(SignedBundle {
        document,
        signature: BASE64.encode(signature.to_bytes()),
        key_id: sk.key_id.clone(),
    }))
}
