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
use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
    Engine as _,
};
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
/// Domain-separation prefix. The Ed25519 signature input is
/// `SIGN_DOMAIN || payload_bytes`, so a signature made here can never be
/// replayed as a signature over some other protocol's message.
pub const SIGN_DOMAIN: &[u8] = b"stig-viewer/sign/v2\0";

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

/// 503 unless a signing key is configured.
fn require_signing(
    signing: &Option<SigningState>,
) -> Result<&SigningState, (StatusCode, &'static str)> {
    signing
        .as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "signing is not configured"))
}

pub async fn pubkey_handler(
    State(state): State<AppState>,
) -> Result<Json<PubkeyResponse>, (StatusCode, &'static str)> {
    let sk = require_signing(&state.signing)?;
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

/// One entry of the signed signer list.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignerId {
    pub algorithm: String,
    pub key_id: String,
}

/// Signing document. Serde preserves struct field order on serialisation.
///
/// The signed bytes (the envelope's `payload`) are `serde_json::to_vec` of
/// this struct: compact JSON, fields in declaration order (`version`,
/// `algorithm`, `keyId`, `signers`, `sha256`, `signedAt`, `signedBy`,
/// `signedByName`, then `resource` only when present), UTF-8. Verifiers never
/// rebuild these bytes: they decode `payload`, verify, then parse it.
///
/// `algorithm` and `keyId` are kept for compatibility and equal `signers[0]`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningDocument {
    pub version: u32,
    pub algorithm: &'static str,
    pub key_id: String,
    /// Every signer that must have signed these bytes.
    pub signers: Vec<SignerId>,
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
    /// Convenience copy of the signed document. NOT authenticated: only
    /// `payload` is. Verifiers must read fields from the verified payload.
    pub document: SigningDocument,
    /// base64url (no padding) of the exact bytes that were signed
    /// (before the domain prefix).
    pub payload: String,
    /// Base64-standard encoded 64-byte Ed25519 signature.
    /// Legacy field; equals `signatures[0].signature`.
    pub signature: String,
    /// Legacy field; equals `signatures[0].key_id`.
    pub key_id: String,
    /// Envelope version (2).
    pub version: u32,
    /// Algorithm-tagged signatures over `SIGN_DOMAIN || payload`.
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

fn signing_input(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGN_DOMAIN.len() + payload.len());
    input.extend_from_slice(SIGN_DOMAIN);
    input.extend_from_slice(payload);
    input
}

fn build_bundle(
    sk: &SigningState,
    document: SigningDocument,
) -> Result<SignedBundle, serde_json::Error> {
    let payload = document_bytes(&document)?;
    let signature = BASE64.encode(sk.signing_key.sign(&signing_input(&payload)).to_bytes());
    Ok(SignedBundle {
        document,
        payload: URL_SAFE_NO_PAD.encode(&payload),
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

// ── Reference verifier ──────────────────────────────────────────────────────

/// Fields of the signed document, parsed from the verified payload.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
pub struct VerifiedDocument {
    pub version: Option<u32>,
    pub algorithm: String,
    pub key_id: String,
    pub signers: Vec<SignerId>,
    pub sha256: String,
    pub signed_at: String,
    pub signed_by: String,
    pub signed_by_name: String,
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
pub enum VerifyError {
    /// Envelope is not JSON of the expected shape, or has no `payload`/`signatures` (e.g. v1).
    MalformedEnvelope,
    BadPayloadEncoding,
    /// Payload is not a signing document.
    MalformedDocument,
    /// Signed document has no `version`, or it is not 2 (v1 documents).
    UnsupportedVersion,
    /// A signer uses an algorithm this verifier cannot check.
    UnsupportedAlgorithm(String),
    /// `signers` is empty or contains duplicates, or `algorithm`/`keyId` disagree with `signers[0]`.
    BadSignerSet,
    /// A signer has no matching entry in `signatures`.
    MissingSignature,
    /// `signatures` has an entry that is not in the signed `signers`, or a duplicate.
    UnexpectedSignature,
    BadSignatureEncoding,
    SignatureInvalid,
    /// A signer's keyId is not the pinned key's fingerprint.
    KeyIdMismatch,
    ArtifactHashMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bundle verification failed: {self:?}")
    }
}

impl std::error::Error for VerifyError {}

#[derive(Deserialize)]
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
struct EnvelopeIn {
    payload: String,
    signatures: Vec<SignatureIn>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
struct SignatureIn {
    algorithm: String,
    key_id: String,
    signature: String,
}

/// Maximum number of entries accepted in `signers`.
const MAX_SIGNERS: usize = 8;

/// Reference verifier for the v2 envelope. Only `payload` and `signatures`
/// are read from the envelope; `document`, `signature`, `keyId` and `version`
/// at the top level are unauthenticated and ignored.
///
/// Steps: decode `payload` (strict base64url, no padding); parse it (duplicate
/// keys and trailing bytes are errors); require signed `version == 2`; require
/// a non-empty `signers` list of at most 8 entries whose first entry equals the
/// signed `algorithm`/`keyId`; reject any unsupported signer algorithm; require
/// every signer's keyId to be the pinned key's fingerprint; reject duplicate
/// signers; require the `signatures` set to equal the `signers` set; verify
/// every signature over `SIGN_DOMAIN || payload`; and require the signed
/// `sha256` to equal `artifact_sha256`. The hash comparison is
/// case-insensitive (hex), and the hash is mandatory so a valid bundle for a
/// different artifact cannot be accepted.
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
pub fn verify_bundle(
    bundle_json: &[u8],
    pinned: &VerifyingKey,
    artifact_sha256: &str,
) -> Result<VerifiedDocument, VerifyError> {
    verify_inner(bundle_json, pinned, Some(artifact_sha256))
}

/// Same checks as [`verify_bundle`] but without an artifact hash: it proves
/// the pinned key signed the document and does NOT bind any artifact. Callers
/// must compare `sha256` against their artifact themselves.
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
pub fn verify_bundle_document_only(
    bundle_json: &[u8],
    pinned: &VerifyingKey,
) -> Result<VerifiedDocument, VerifyError> {
    verify_inner(bundle_json, pinned, None)
}

fn verify_inner(
    bundle_json: &[u8],
    pinned: &VerifyingKey,
    artifact_sha256: Option<&str>,
) -> Result<VerifiedDocument, VerifyError> {
    let env: EnvelopeIn =
        serde_json::from_slice(bundle_json).map_err(|_| VerifyError::MalformedEnvelope)?;
    let payload = URL_SAFE_NO_PAD
        .decode(env.payload.as_bytes())
        .map_err(|_| VerifyError::BadPayloadEncoding)?;
    let doc: VerifiedDocument =
        serde_json::from_slice(&payload).map_err(|_| VerifyError::MalformedDocument)?;

    if doc.version != Some(ENVELOPE_VERSION) {
        return Err(VerifyError::UnsupportedVersion);
    }
    let first = doc.signers.first().ok_or(VerifyError::BadSignerSet)?;
    if first.algorithm != doc.algorithm || first.key_id != doc.key_id {
        return Err(VerifyError::BadSignerSet);
    }
    if doc.signers.len() > MAX_SIGNERS {
        return Err(VerifyError::BadSignerSet);
    }
    let pinned_id = compute_key_id(pinned);
    for s in &doc.signers {
        if s.algorithm != ALGORITHM {
            return Err(VerifyError::UnsupportedAlgorithm(s.algorithm.clone()));
        }
        if s.key_id != pinned_id {
            return Err(VerifyError::KeyIdMismatch);
        }
    }
    for (i, s) in doc.signers.iter().enumerate() {
        if doc.signers[..i].contains(s) {
            return Err(VerifyError::BadSignerSet);
        }
    }

    for (i, sig) in env.signatures.iter().enumerate() {
        let known = doc
            .signers
            .iter()
            .any(|s| s.algorithm == sig.algorithm && s.key_id == sig.key_id);
        let duplicate = env.signatures[..i]
            .iter()
            .any(|o| o.algorithm == sig.algorithm && o.key_id == sig.key_id);
        if !known || duplicate {
            return Err(VerifyError::UnexpectedSignature);
        }
    }
    let input = signing_input(&payload);
    for signer in &doc.signers {
        let sig = env
            .signatures
            .iter()
            .find(|s| s.algorithm == signer.algorithm && s.key_id == signer.key_id)
            .ok_or(VerifyError::MissingSignature)?;
        let raw = BASE64
            .decode(sig.signature.as_bytes())
            .map_err(|_| VerifyError::BadSignatureEncoding)?;
        let parsed = ed25519_dalek::Signature::from_slice(&raw)
            .map_err(|_| VerifyError::BadSignatureEncoding)?;
        pinned
            .verify_strict(&input, &parsed)
            .map_err(|_| VerifyError::SignatureInvalid)?;
    }

    if let Some(expected) = artifact_sha256 {
        if !expected.eq_ignore_ascii_case(&doc.sha256) {
            return Err(VerifyError::ArtifactHashMismatch);
        }
    }
    Ok(doc)
}

/// Cap signed payloads at 100 MiB. Larger inputs should be hashed
/// client-side; the server only cares about the sha in the document.
const MAX_SIGN_BYTES: usize = 100 * 1024 * 1024;

/// Validates the request and builds the signed bundle. Returns the bundle and
/// the content length.
fn sign_request(
    sk: &SigningState,
    user: &AuthUser,
    body: &SignRequest,
) -> Result<(SignedBundle, usize), (StatusCode, String)> {
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
        signers: vec![SignerId {
            algorithm: ALGORITHM.into(),
            key_id: sk.key_id.clone(),
        }],
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
    Ok((bundle, content.len()))
}

pub async fn sign_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<SignRequest>,
) -> Result<Json<SignedBundle>, (StatusCode, String)> {
    let sk = require_signing(&state.signing).map_err(|(c, m)| (c, m.to_string()))?;

    let (bundle, bytes) = sign_request(sk, &user, &body)?;

    let algorithms = bundle
        .signatures
        .iter()
        .map(|s| s.algorithm)
        .collect::<Vec<_>>()
        .join(",");
    tracing::info!(
        user = %user.id,
        sha256 = %bundle.document.sha256,
        key_id = %sk.key_id,
        version = bundle.version,
        algorithms = %algorithms,
        bytes,
        resource = %bundle.document.resource.as_deref().unwrap_or(""),
        "signing.sign"
    );

    Ok(Json(bundle))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

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

    fn other_key() -> VerifyingKey {
        Ed25519SigningKey::from_bytes(&[7u8; 32]).verifying_key()
    }

    fn sample_doc(st: &SigningState, sha256: String) -> SigningDocument {
        SigningDocument {
            version: ENVELOPE_VERSION,
            algorithm: ALGORITHM,
            key_id: st.key_id.clone(),
            signers: vec![SignerId {
                algorithm: ALGORITHM.into(),
                key_id: st.key_id.clone(),
            }],
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

    fn wire(st: &SigningState) -> Value {
        serde_json::to_value(sample_bundle(st)).unwrap()
    }

    fn verify(
        v: &Value,
        st: &SigningState,
        hash: Option<&str>,
    ) -> Result<VerifiedDocument, VerifyError> {
        let bytes = serde_json::to_vec(v).unwrap();
        let vk = st.signing_key.verifying_key();
        match hash {
            Some(h) => verify_bundle(&bytes, &vk, h),
            None => verify_bundle_document_only(&bytes, &vk),
        }
    }

    /// Re-signs an arbitrary payload value with the test key, returning a wire envelope.
    fn resign(st: &SigningState, payload: &Value) -> Value {
        let bytes = serde_json::to_vec(payload).unwrap();
        let sig = BASE64.encode(st.signing_key.sign(&signing_input(&bytes)).to_bytes());
        json!({
            "payload": URL_SAFE_NO_PAD.encode(&bytes),
            "signatures": [{"algorithm": "ed25519", "keyId": st.key_id, "signature": sig}]
        })
    }

    fn payload_value(v: &Value) -> Value {
        let b = URL_SAFE_NO_PAD
            .decode(v["payload"].as_str().unwrap())
            .unwrap();
        serde_json::from_slice(&b).unwrap()
    }

    #[test]
    fn legacy_fields_equal_first_signature() {
        let b = sample_bundle(&test_state());
        assert_eq!(b.version, 2);
        assert_eq!(b.signatures.len(), 1);
        assert_eq!(b.signature, b.signatures[0].signature);
        assert_eq!(b.key_id, b.signatures[0].key_id);
        assert_eq!(b.signatures[0].algorithm, "ed25519");
        assert_eq!(b.document.signers[0].key_id, b.document.key_id);
    }

    #[test]
    fn payload_is_exactly_the_signed_document_bytes() {
        let st = test_state();
        let b = sample_bundle(&st);
        let bytes = URL_SAFE_NO_PAD.decode(&b.payload).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&b.document).unwrap());
        assert!(!b.payload.contains('=') && !b.payload.contains('+') && !b.payload.contains('/'));
        assert!(bytes.starts_with(br#"{"version":2,"algorithm":"ed25519","keyId":""#));
    }

    #[test]
    fn happy_path_verifies_via_payload() {
        let st = test_state();
        let doc = verify(&wire(&st), &st, Some(&"AB".repeat(32))).unwrap();
        assert_eq!(doc.version, Some(2));
        assert_eq!(doc.sha256, "ab".repeat(32));
        assert_eq!(doc.signed_by, "u1");
        assert_eq!(doc.resource.as_deref(), Some("windows-11"));
        assert!(verify(&wire(&st), &st, None).is_ok());
    }

    #[test]
    fn tampered_payload_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        let mut b = URL_SAFE_NO_PAD
            .decode(v["payload"].as_str().unwrap())
            .unwrap();
        let n = b.len() - 3;
        b[n] ^= 1;
        v["payload"] = URL_SAFE_NO_PAD.encode(&b).into();
        assert!(verify(&v, &st, None).is_err());
        v["payload"] = "!!!not base64".into();
        assert_eq!(verify(&v, &st, None), Err(VerifyError::BadPayloadEncoding));
    }

    #[test]
    fn unsigned_envelope_document_and_legacy_fields_are_ignored() {
        let st = test_state();
        let mut v = wire(&st);
        v["document"]["sha256"] = "00".repeat(32).into();
        v["document"]["signedBy"] = "attacker".into();
        v["signature"] = "garbage".into();
        v["keyId"] = "ffffffffffffffff".into();
        v["version"] = 1.into();
        let doc = verify(&v, &st, None).unwrap();
        assert_eq!(doc.sha256, "ab".repeat(32));
        assert_eq!(doc.signed_by, "u1");
    }

    #[test]
    fn stripped_signature_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        v["signatures"] = json!([]);
        assert_eq!(verify(&v, &st, None), Err(VerifyError::MissingSignature));
    }

    #[test]
    fn extra_unsigned_signature_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        let first = v["signatures"][0].clone();
        v["signatures"].as_array_mut().unwrap().push(json!({
            "algorithm": "ml-dsa-65", "keyId": st.key_id, "signature": first["signature"]
        }));
        assert_eq!(verify(&v, &st, None), Err(VerifyError::UnexpectedSignature));
        let mut v = wire(&st);
        v["signatures"].as_array_mut().unwrap().push(first);
        assert_eq!(verify(&v, &st, None), Err(VerifyError::UnexpectedSignature));
    }

    #[test]
    fn unknown_algorithm_in_signers_rejected_not_skipped() {
        let st = test_state();
        let mut p = payload_value(&wire(&st));
        p["signers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"algorithm": "ml-dsa-65", "keyId": "0011223344556677"}));
        let mut v = resign(&st, &p);
        assert_eq!(
            verify(&v, &st, None),
            Err(VerifyError::UnsupportedAlgorithm("ml-dsa-65".into()))
        );
        v["signatures"].as_array_mut().unwrap().push(json!({
            "algorithm": "ml-dsa-65", "keyId": "0011223344556677", "signature": "AAAA"
        }));
        assert!(matches!(
            verify(&v, &st, None),
            Err(VerifyError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn wrong_pinned_key_rejected() {
        let st = test_state();
        let r = verify_bundle_document_only(&serde_json::to_vec(&wire(&st)).unwrap(), &other_key());
        assert_eq!(r, Err(VerifyError::KeyIdMismatch));
    }

    #[test]
    fn wrong_artifact_hash_rejected() {
        let st = test_state();
        let r = verify(&wire(&st), &st, Some(&"cd".repeat(32)));
        assert_eq!(r, Err(VerifyError::ArtifactHashMismatch));
    }

    #[test]
    fn missing_version_v1_rejected() {
        let st = test_state();
        // v1 envelope: no payload at all.
        let v1 =
            json!({"document": {"algorithm": "ed25519"}, "signature": "x", "keyId": st.key_id});
        assert_eq!(verify(&v1, &st, None), Err(VerifyError::MalformedEnvelope));
        // Signed payload without `version`.
        let mut p = payload_value(&wire(&st));
        p.as_object_mut().unwrap().remove("version");
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::UnsupportedVersion)
        );
        p["version"] = 1.into();
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::UnsupportedVersion)
        );
    }

    #[test]
    fn signature_without_domain_prefix_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        let bytes = URL_SAFE_NO_PAD
            .decode(v["payload"].as_str().unwrap())
            .unwrap();
        let bare = BASE64.encode(st.signing_key.sign(&bytes).to_bytes());
        v["signatures"][0]["signature"] = bare.into();
        assert_eq!(verify(&v, &st, None), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn signer_list_must_match_signed_algorithm_and_key_id() {
        let st = test_state();
        let mut p = payload_value(&wire(&st));
        p["signers"][0]["keyId"] = "0000000000000000".into();
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::BadSignerSet)
        );
        p["signers"] = json!([]);
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::BadSignerSet)
        );
    }

    fn resign_raw(st: &SigningState, bytes: &[u8]) -> Value {
        let sig = BASE64.encode(st.signing_key.sign(&signing_input(bytes)).to_bytes());
        json!({
            "payload": URL_SAFE_NO_PAD.encode(bytes),
            "signatures": [{"algorithm": "ed25519", "keyId": st.key_id, "signature": sig}]
        })
    }

    #[test]
    fn duplicate_signers_rejected() {
        let st = test_state();
        let mut p = payload_value(&wire(&st));
        let a = p["signers"][0].clone();
        p["signers"] = json!([a, a]);
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::BadSignerSet)
        );
    }

    #[test]
    fn too_many_signers_rejected() {
        let st = test_state();
        let mut p = payload_value(&wire(&st));
        let a = p["signers"][0].clone();
        p["signers"] = json!(vec![a; MAX_SIGNERS + 1]);
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::BadSignerSet)
        );
    }

    #[test]
    fn wrong_pinned_key_is_reported_before_duplicates() {
        let st = test_state();
        let mut p = payload_value(&wire(&st));
        let a = p["signers"][0].clone();
        p["signers"] = json!([a, a]);
        let bytes = serde_json::to_vec(&resign(&st, &p)).unwrap();
        assert_eq!(
            verify_bundle_document_only(&bytes, &other_key()),
            Err(VerifyError::KeyIdMismatch)
        );
    }

    #[test]
    fn duplicate_signatures_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        let first = v["signatures"][0].clone();
        v["signatures"].as_array_mut().unwrap().push(first);
        assert_eq!(verify(&v, &st, None), Err(VerifyError::UnexpectedSignature));
    }

    #[test]
    fn padded_standard_alphabet_and_noncanonical_payload_rejected() {
        let st = test_state();
        // Padded: try three resource lengths so every padding amount is covered.
        let mut padded_cases = 0;
        let mut bits_cases = 0;
        for extra in ["", "a", "aa"] {
            let mut p = payload_value(&wire(&st));
            p["resource"] = format!("windows-11{extra}").into();
            let raw = serde_json::to_vec(&p).unwrap();
            let v = resign_raw(&st, &raw);
            assert!(verify(&v, &st, None).is_ok());
            let good = v["payload"].as_str().unwrap().to_string();
            let mut padded = good.clone();
            while !padded.len().is_multiple_of(4) {
                padded.push('=');
            }
            if padded != good {
                padded_cases += 1;
                let mut bad = v.clone();
                bad["payload"] = padded.into();
                assert_eq!(
                    verify(&bad, &st, None),
                    Err(VerifyError::BadPayloadEncoding)
                );
                // Non-canonical trailing bits: same length, last char differs in the
                // unused low bits.
                let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let mut chars: Vec<char> = good.chars().collect();
                let last = chars.len() - 1;
                let idx = alphabet.find(chars[last]).unwrap();
                chars[last] = alphabet.chars().nth(idx ^ 1).unwrap();
                let mut bad = v.clone();
                bad["payload"] = chars.into_iter().collect::<String>().into();
                assert_eq!(
                    verify(&bad, &st, None),
                    Err(VerifyError::BadPayloadEncoding)
                );
                bits_cases += 1;
            }
        }
        assert!(padded_cases >= 1 && bits_cases >= 1);
        // Standard alphabet: find bytes whose encoding uses '-' or '_'.
        let mut payload = payload_value(&wire(&st));
        payload["resource"] = "???>>>~~~".into();
        let raw = serde_json::to_vec(&payload).unwrap();
        let url = URL_SAFE_NO_PAD.encode(&raw);
        let std_alpha = BASE64.encode(&raw).trim_end_matches('=').to_string();
        assert_ne!(url, std_alpha, "fixture must exercise - and _");
        let mut v = resign_raw(&st, &raw);
        assert!(verify(&v, &st, None).is_ok());
        v["payload"] = std_alpha.into();
        assert_eq!(verify(&v, &st, None), Err(VerifyError::BadPayloadEncoding));
    }

    #[test]
    fn trailing_bytes_after_payload_json_rejected() {
        let st = test_state();
        let mut raw = serde_json::to_vec(&payload_value(&wire(&st))).unwrap();
        raw.extend_from_slice(b" ");
        assert!(verify(&resign_raw(&st, &raw), &st, None).is_ok());
        raw.extend_from_slice(b"x");
        assert_eq!(
            verify(&resign_raw(&st, &raw), &st, None),
            Err(VerifyError::MalformedDocument)
        );
    }

    #[test]
    fn duplicate_key_in_payload_json_rejected() {
        let st = test_state();
        let mut raw = serde_json::to_vec(&payload_value(&wire(&st))).unwrap();
        raw.pop();
        raw.extend_from_slice(br#","sha256":"00"}"#);
        assert_eq!(
            verify(&resign_raw(&st, &raw), &st, None),
            Err(VerifyError::MalformedDocument)
        );
    }

    #[test]
    fn invalid_signature_encoding_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        let sig = v["signatures"][0]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        v["signatures"][0]["signature"] = format!("!{}", &sig[1..]).into();
        assert_eq!(
            verify(&v, &st, None),
            Err(VerifyError::BadSignatureEncoding)
        );
        v["signatures"][0]["signature"] = sig[..10].into();
        assert_eq!(
            verify(&v, &st, None),
            Err(VerifyError::BadSignatureEncoding)
        );
    }

    #[test]
    fn artifact_hash_is_mandatory_in_verify_bundle() {
        let st = test_state();
        let bytes = serde_json::to_vec(&wire(&st)).unwrap();
        let vk = st.signing_key.verifying_key();
        assert!(verify_bundle(&bytes, &vk, &"AB".repeat(32)).is_ok());
        assert_eq!(
            verify_bundle(&bytes, &vk, ""),
            Err(VerifyError::ArtifactHashMismatch)
        );
    }

    #[test]
    fn missing_signing_key_is_503() {
        let err = require_signing(&None).err().unwrap();
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(require_signing(&Some(test_state())).is_ok());
    }

    #[test]
    fn envelope_json_shape_snapshot() {
        let st = test_state();
        let mut v = wire(&st);
        let sig = v["signature"].as_str().unwrap().to_string();
        assert_eq!(v["signatures"][0]["signature"], sig.as_str());
        let payload = v["payload"].as_str().unwrap().to_string();
        v["signature"] = "SIG".into();
        v["signatures"][0]["signature"] = "SIG".into();
        v["payload"] = "PAYLOAD".into();
        let signer = json!({"algorithm": "ed25519", "keyId": st.key_id});
        let expected = json!({
            "document": {
                "version": 2, "algorithm": "ed25519", "keyId": st.key_id,
                "signers": [signer],
                "sha256": "ab".repeat(32), "signedAt": "2026-01-01T00:00:00Z",
                "signedBy": "u1", "signedByName": "User One", "resource": "windows-11"
            },
            "payload": "PAYLOAD",
            "signature": "SIG", "keyId": st.key_id, "version": 2,
            "signatures": [{"algorithm": "ed25519", "keyId": st.key_id, "signature": "SIG"}]
        });
        assert_eq!(v, expected);
        assert_eq!(v.as_object().unwrap().len(), 6);
        assert_eq!(
            payload_value(&json!({"payload": payload}))["signers"][0],
            signer
        );
    }

    #[test]
    fn pubkey_json_shape_snapshot() {
        let st = test_state();
        let v = serde_json::to_value(pubkey_response(&st)).unwrap();
        let pk = BASE64.encode(st.signing_key.verifying_key().as_bytes());
        assert_eq!(
            v,
            json!({
                "algorithm": "ed25519", "keyId": st.key_id, "publicKey": pk,
                "keys": [{"algorithm": "ed25519", "keyId": st.key_id, "publicKey": pk}]
            })
        );
    }

    fn user() -> AuthUser {
        AuthUser {
            id: "u1".into(),
            display_name: "User One".into(),
            email: "u1@example.test".into(),
            role: "user".into(),
        }
    }

    fn request(content: &str, resource: Option<&str>) -> SignRequest {
        SignRequest {
            content: content.into(),
            resource: resource.map(String::from),
        }
    }

    #[test]
    fn resource_none_is_absent_and_empty_becomes_none() {
        let st = test_state();
        let content = BASE64.encode(b"hello");
        for res in [None, Some("")] {
            let (b, n) = sign_request(&st, &user(), &request(&content, res)).unwrap();
            assert_eq!(n, 5);
            assert!(b.document.resource.is_none());
            let bytes = URL_SAFE_NO_PAD.decode(&b.payload).unwrap();
            assert!(!String::from_utf8(bytes).unwrap().contains("resource"));
        }
        let (b, _) = sign_request(&st, &user(), &request(&content, Some("r1"))).unwrap();
        assert_eq!(b.document.resource.as_deref(), Some("r1"));
        let wire = serde_json::to_vec(&b).unwrap();
        let doc = verify_bundle(
            &wire,
            &st.signing_key.verifying_key(),
            &hex::encode(Sha256::digest(b"hello")),
        )
        .unwrap();
        assert_eq!(doc.signed_by, "u1");
    }

    #[test]
    fn sign_request_rejects_bad_input() {
        let st = test_state();
        let bad = sign_request(&st, &user(), &request("***", None))
            .err()
            .unwrap();
        assert_eq!(bad.0, StatusCode::BAD_REQUEST);
        let empty = sign_request(&st, &user(), &request("", None))
            .err()
            .unwrap();
        assert_eq!(empty.0, StatusCode::BAD_REQUEST);
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
}
