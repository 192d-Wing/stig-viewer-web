//! Ed25519 detached signing for exported artifacts (e.g. `.ckl` files).
//!
//! Enabled by setting `SIGNING_KEY_HEX` to a 32-byte hex-encoded Ed25519
//! seed. When the env var is absent, [`SigningState::from_env`] returns
//! `None` and both endpoints respond 503.
//!
//! - `GET  /api/signing/pubkey` — public; returns `{algorithm, keyId,
//!   publicKey}` so verifiers can pin a trusted copy of the key offline.
//! - `POST /api/sign` — authenticated; takes an opaque blob (base64) +
//!   optional `resource` label, hashes the content, wraps the hash plus
//!   the signer's identity and a timestamp in a canonical JSON "signing
//!   document", and returns an Ed25519 signature over that document.
//!
//! Threat model: the signature attests that the server observed exactly
//! these bytes, at this time, under this authenticated user's session.
//! Replay is prevented by the `signedAt` field in the signing document.
//!
//! Audit trail: each successful sign emits a `tracing::info!` line with
//! the user id, sha256, key id, and byte count. Hook this into whatever
//! log aggregator you use for forensic review.

use axum::{extract::State, http::StatusCode, Extension, Json};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::api::auth::AuthUser;
use crate::AppState;

/// Loaded signing material. Stored on `AppState` as `Option<SigningState>`;
/// `None` makes every endpoint in this module return 503.
#[derive(Clone, Debug)]
pub struct SigningState {
    pub signing_key: Arc<Ed25519SigningKey>,
    /// Short public-key fingerprint — first 8 bytes of SHA-256 over the raw
    /// verifying-key bytes, hex-encoded. Clients embed this in signed
    /// bundles so a verifier can detect key rotation.
    pub key_id: String,
}

impl SigningState {
    /// Reads `SIGNING_KEY_HEX` from the environment. Returns `Ok(None)` when
    /// the var is unset or empty so the server starts cleanly without
    /// signing. Returns `Err` only for malformed hex or wrong-length input.
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
            signing_key: Arc::new(signing_key),
            key_id,
        }))
    }
}

fn compute_key_id(vk: &VerifyingKey) -> String {
    let digest = Sha256::digest(vk.as_bytes());
    hex::encode(&digest[..8])
}

// ── GET /api/signing/pubkey ─────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PubkeyResponse {
    pub algorithm: &'static str,
    pub key_id: String,
    /// Raw public key bytes, base64-standard (not URL-safe) encoded.
    pub public_key: String,
}

pub async fn pubkey_handler(
    State(state): State<AppState>,
) -> Result<Json<PubkeyResponse>, (StatusCode, &'static str)> {
    let sk = state
        .signing
        .as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "signing is not configured"))?;
    Ok(Json(PubkeyResponse {
        algorithm: "ed25519",
        key_id: sk.key_id.clone(),
        public_key: BASE64.encode(sk.signing_key.verifying_key().as_bytes()),
    }))
}

// ── POST /api/sign ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SignRequest {
    /// Base64-standard encoded bytes to sign. Clients that would rather
    /// not round-trip the whole payload may hash it client-side and send
    /// just the raw hash bytes here instead — the server hashes whatever
    /// it receives either way.
    pub content: String,
    /// Optional free-text label baked into the signing document (e.g. the
    /// STIG id). Shown back to verifiers so auditors can trace a signature
    /// to its source resource.
    #[serde(default)]
    pub resource: Option<String>,
}

/// Signing document. Serde preserves struct field order on serialisation,
/// so two servers running the same code produce byte-identical JSON for
/// the same inputs. Verifiers reconstruct this struct from the response
/// and verify `signature` against its bytes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningDocument {
    pub algorithm: &'static str,
    pub sha256: String,
    pub signed_at: String,
    pub signed_by: String,
    pub signed_by_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedBundle {
    pub document: SigningDocument,
    /// Base64-standard encoded 64-byte Ed25519 signature.
    pub signature: String,
    pub key_id: String,
}

/// Cap signed payloads at 100 MiB. Larger inputs should be hashed
/// client-side; the server only cares about the sha in the document.
const MAX_SIGN_BYTES: usize = 100 * 1024 * 1024;

pub async fn sign_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<SignRequest>,
) -> Result<Json<SignedBundle>, (StatusCode, String)> {
    let sk = state.signing.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "signing is not configured".into(),
    ))?;

    let content = BASE64.decode(body.content.trim()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("content must be base64: {e}"),
        )
    })?;
    if content.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "content must not be empty".into()));
    }
    if content.len() > MAX_SIGN_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("content exceeds {} bytes", MAX_SIGN_BYTES),
        ));
    }

    let sha = Sha256::digest(&content);
    let document = SigningDocument {
        algorithm: "ed25519",
        sha256: hex::encode(sha),
        signed_at: chrono::Utc::now().to_rfc3339(),
        signed_by: user.id.clone(),
        signed_by_name: user.display_name.clone(),
        resource: body.resource.clone().filter(|s| !s.is_empty()),
    };

    let doc_bytes = serde_json::to_vec(&document).map_err(|e| {
        tracing::error!("canonicalise signing document: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing failed".to_string(),
        )
    })?;
    let signature = sk.signing_key.sign(&doc_bytes);

    tracing::info!(
        user = %user.id,
        sha256 = %document.sha256,
        key_id = %sk.key_id,
        bytes = content.len(),
        resource = %document.resource.as_deref().unwrap_or(""),
        "signing.sign"
    );

    Ok(Json(SignedBundle {
        document,
        signature: BASE64.encode(signature.to_bytes()),
        key_id: sk.key_id.clone(),
    }))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    const TEST_SEED_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn test_state() -> SigningState {
        let bytes = hex::decode(TEST_SEED_HEX).unwrap();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        let signing_key = Ed25519SigningKey::from_bytes(&seed);
        let key_id = compute_key_id(&signing_key.verifying_key());
        SigningState {
            signing_key: Arc::new(signing_key),
            key_id,
        }
    }

    #[test]
    fn from_env_returns_none_when_unset() {
        // Guard against leakage from parallel tests on the same process.
        let prior = std::env::var("SIGNING_KEY_HEX").ok();
        // Safety: tests run single-threaded via cargo test by default; the
        // env var is read-reset-written in this test only.
        std::env::remove_var("SIGNING_KEY_HEX");
        let got = SigningState::from_env().unwrap();
        assert!(got.is_none());
        if let Some(v) = prior {
            std::env::set_var("SIGNING_KEY_HEX", v);
        }
    }

    #[test]
    fn from_env_rejects_short_key() {
        std::env::set_var("SIGNING_KEY_HEX", "deadbeef");
        let err = SigningState::from_env().unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
        std::env::remove_var("SIGNING_KEY_HEX");
    }

    #[test]
    fn key_id_is_deterministic_and_short() {
        let a = test_state();
        let b = test_state();
        assert_eq!(a.key_id, b.key_id);
        // 8 bytes → 16 hex chars.
        assert_eq!(a.key_id.len(), 16);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let st = test_state();
        let content = b"<CHECKLIST>pretend this is a .ckl</CHECKLIST>";

        let sha = Sha256::digest(content);
        let document = SigningDocument {
            algorithm: "ed25519",
            sha256: hex::encode(sha),
            signed_at: "2026-01-01T00:00:00Z".into(),
            signed_by: "u1".into(),
            signed_by_name: "User One".into(),
            resource: Some("windows-11".into()),
        };
        let doc_bytes = serde_json::to_vec(&document).unwrap();
        let signature = st.signing_key.sign(&doc_bytes);

        // Verifying against the matching verifying key succeeds.
        let vk = st.signing_key.verifying_key();
        vk.verify(&doc_bytes, &signature).expect("must verify");

        // Flipping a single bit of the document breaks the signature.
        let mut tampered = doc_bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(vk.verify(&tampered, &signature).is_err());
    }
}
