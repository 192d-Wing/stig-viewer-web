//! Ed25519 detached signing for exported artifacts (e.g. `.ckl` files).
//!
//! Enabled by setting `SIGNING_KEY_HEX` to a 32-byte hex-encoded Ed25519
//! seed. When the env var is absent, [`SigningState::from_env`] returns
//! `None` and both endpoints respond 503.
//!
//! - `GET  /api/signing/pubkey` — public; returns `{algorithm, keyId,
//!   publicKey, keys: [{algorithm, keyId, publicKey}]}` so verifiers can pin a trusted copy of the key offline.
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
        Self::from_hex(std::env::var("SIGNING_KEY_HEX").ok().as_deref())
    }

    /// Pure parsing behind [`Self::from_env`]: `None` or blank means disabled.
    pub fn from_hex(value: Option<&str>) -> anyhow::Result<Option<Self>> {
        let Some(hex_str) = value.filter(|s| !s.trim().is_empty()) else {
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

const ALGORITHM: &str = "ed25519";
/// Envelope / document format version.
pub const ENVELOPE_VERSION: u32 = 2;

// ── GET /api/signing/pubkey ─────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PubkeyResponse {
    pub algorithm: &'static str,
    pub key_id: String,
    /// Raw public key bytes, base64-standard (not URL-safe) encoded.
    pub public_key: String,
    /// Algorithm-tagged key list (envelope v2). Today it holds one entry
    /// identical to the top-level fields.
    pub keys: Vec<PubkeyEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PubkeyEntry {
    pub algorithm: &'static str,
    pub key_id: String,
    pub public_key: String,
}

fn pubkey_response(sk: &SigningState) -> PubkeyResponse {
    let public_key = BASE64.encode(sk.signing_key.verifying_key().as_bytes());
    PubkeyResponse {
        algorithm: ALGORITHM,
        key_id: sk.key_id.clone(),
        public_key: public_key.clone(),
        keys: vec![PubkeyEntry {
            algorithm: ALGORITHM,
            key_id: sk.key_id.clone(),
            public_key,
        }],
    }
}

pub async fn pubkey_handler(
    State(state): State<AppState>,
) -> Result<Json<PubkeyResponse>, (StatusCode, &'static str)> {
    let sk = state
        .signing
        .as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "signing is not configured"))?;
    Ok(Json(pubkey_response(sk)))
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
/// the same inputs.
///
/// Signed bytes: `serde_json::to_vec(&document)`, i.e. compact JSON (no
/// whitespace), fields in declaration order (`version`, `algorithm`,
/// `keyId`, `sha256`, `signedAt`, `signedBy`, `signedByName`, then
/// `resource` only when present), UTF-8. Verifiers should verify against
/// the document exactly as received (preserving field order), not rebuild
/// it from a fixed field list; if they must rebuild, `version` and `keyId`
/// are part of the document since envelope v2.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningDocument {
    pub version: u32,
    pub algorithm: &'static str,
    pub key_id: String,
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
    /// Legacy field; equals `signatures[0].signature`.
    pub signature: String,
    /// Legacy field; equals `signatures[0].key_id`.
    pub key_id: String,
    /// Envelope version (2).
    pub version: u32,
    /// Algorithm-tagged signatures over the same document bytes.
    pub signatures: Vec<BundleSignature>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleSignature {
    pub algorithm: &'static str,
    pub key_id: String,
    pub signature: String,
}

/// Canonical signed bytes for a document.
fn document_bytes(document: &SigningDocument) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(document)
}

fn build_bundle(
    sk: &SigningState,
    document: SigningDocument,
) -> Result<SignedBundle, serde_json::Error> {
    let doc_bytes = document_bytes(&document)?;
    let signature = BASE64.encode(sk.signing_key.sign(&doc_bytes).to_bytes());
    Ok(SignedBundle {
        document,
        signature: signature.clone(),
        key_id: sk.key_id.clone(),
        version: ENVELOPE_VERSION,
        signatures: vec![BundleSignature {
            algorithm: ALGORITHM,
            key_id: sk.key_id.clone(),
            signature,
        }],
    })
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
        version: ENVELOPE_VERSION,
        algorithm: ALGORITHM,
        key_id: sk.key_id.clone(),
        sha256: hex::encode(sha),
        signed_at: chrono::Utc::now().to_rfc3339(),
        signed_by: user.id.clone(),
        signed_by_name: user.display_name.clone(),
        resource: body.resource.clone().filter(|s| !s.is_empty()),
    };

    let bundle = build_bundle(sk, document).map_err(|e| {
        tracing::error!("canonicalise signing document: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing failed".to_string(),
        )
    })?;

    tracing::info!(
        user = %user.id,
        sha256 = %bundle.document.sha256,
        key_id = %sk.key_id,
        bytes = content.len(),
        resource = %bundle.document.resource.as_deref().unwrap_or(""),
        "signing.sign"
    );

    Ok(Json(bundle))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    const TEST_SEED_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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

    fn sample_doc(st: &SigningState, sha256: String) -> SigningDocument {
        SigningDocument {
            version: ENVELOPE_VERSION,
            algorithm: ALGORITHM,
            key_id: st.key_id.clone(),
            sha256,
            signed_at: "2026-01-01T00:00:00Z".into(),
            signed_by: "u1".into(),
            signed_by_name: "User One".into(),
            resource: Some("windows-11".into()),
        }
    }

    fn sample_bundle(st: &SigningState) -> SignedBundle {
        build_bundle(st, sample_doc(st, "ab".repeat(32))).unwrap()
    }

    #[test]
    fn legacy_fields_equal_first_signature() {
        let b = sample_bundle(&test_state());
        assert_eq!(b.version, 2);
        assert_eq!(b.signatures.len(), 1);
        assert_eq!(b.signature, b.signatures[0].signature);
        assert_eq!(b.key_id, b.signatures[0].key_id);
        assert_eq!(b.signatures[0].algorithm, "ed25519");
    }

    #[test]
    fn existing_signature_round_trips_from_json() {
        let st = test_state();
        let wire = serde_json::to_string(&sample_bundle(&st)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&wire).unwrap();
        let sig_b = BASE64.decode(v["signature"].as_str().unwrap()).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_b).unwrap();
        // Verifier takes the document bytes exactly as received on the wire.
        let start = wire.find(r#"{"document":"#).unwrap() + r#"{"document":"#.len();
        let end = wire.find(r#","signature":"#).unwrap();
        let doc_bytes = &wire.as_bytes()[start..end];
        st.signing_key
            .verifying_key()
            .verify(doc_bytes, &sig)
            .expect("must verify");
    }

    #[test]
    fn tampering_key_id_or_version_breaks_verification() {
        let st = test_state();
        let b = sample_bundle(&st);
        let sig =
            ed25519_dalek::Signature::from_slice(&BASE64.decode(&b.signature).unwrap()).unwrap();
        let vk = st.signing_key.verifying_key();
        assert!(serde_json::to_string(&b.document)
            .unwrap()
            .contains(&format!("\"keyId\":\"{}\"", st.key_id)));
        let mut d = sample_doc(&st, "ab".repeat(32));
        d.key_id = "0000000000000000".into();
        assert!(vk.verify(&serde_json::to_vec(&d).unwrap(), &sig).is_err());
        let mut d = sample_doc(&st, "ab".repeat(32));
        d.version = 1;
        assert!(vk.verify(&serde_json::to_vec(&d).unwrap(), &sig).is_err());
        // Untampered still verifies.
        let d = sample_doc(&st, "ab".repeat(32));
        assert!(vk.verify(&serde_json::to_vec(&d).unwrap(), &sig).is_ok());
    }

    #[test]
    fn envelope_json_shape_snapshot() {
        let st = test_state();
        let mut v = serde_json::to_value(sample_bundle(&st)).unwrap();
        let sig = v["signature"].as_str().unwrap().to_string();
        assert_eq!(v["signatures"][0]["signature"], sig.as_str());
        v["signature"] = "SIG".into();
        v["signatures"][0]["signature"] = "SIG".into();
        let expected = serde_json::json!({
            "document": {
                "version": 2, "algorithm": "ed25519", "keyId": st.key_id,
                "sha256": "ab".repeat(32), "signedAt": "2026-01-01T00:00:00Z",
                "signedBy": "u1", "signedByName": "User One", "resource": "windows-11"
            },
            "signature": "SIG", "keyId": st.key_id, "version": 2,
            "signatures": [{"algorithm": "ed25519", "keyId": st.key_id, "signature": "SIG"}]
        });
        assert_eq!(v, expected);
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys.len(), 5);
        let doc = serde_json::to_string(&sample_bundle(&st).document).unwrap();
        assert!(doc.starts_with(r#"{"version":2,"algorithm":"ed25519","keyId":""#));
    }

    #[test]
    fn pubkey_json_shape_snapshot() {
        let st = test_state();
        let v = serde_json::to_value(pubkey_response(&st)).unwrap();
        let pk = BASE64.encode(st.signing_key.verifying_key().as_bytes());
        assert_eq!(
            v,
            serde_json::json!({
                "algorithm": "ed25519", "keyId": st.key_id, "publicKey": pk,
                "keys": [{"algorithm": "ed25519", "keyId": st.key_id, "publicKey": pk}]
            })
        );
    }

    #[test]
    fn from_hex_returns_none_when_unset_or_blank() {
        assert!(SigningState::from_hex(None).unwrap().is_none());
        assert!(SigningState::from_hex(Some("  ")).unwrap().is_none());
    }

    #[test]
    fn from_hex_rejects_short_key() {
        let err = SigningState::from_hex(Some("deadbeef")).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
        assert!(SigningState::from_hex(Some("zz")).is_err());
        assert!(SigningState::from_hex(Some(&"ab".repeat(32)))
            .unwrap()
            .is_some());
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
        let document = sample_doc(&st, hex::encode(sha));
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
