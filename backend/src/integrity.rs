//! Integrity envelopes for system-produced artifacts (audit archive segments
//! and backups).
//!
//! The design mirrors the signed-bundle envelope in `api::signing`:
//!
//! - the envelope carries `payload`, the base64url (no padding) exact bytes
//!   that were signed, and `signatures: [{algorithm, keyId, signature}]`;
//! - the payload names its own `signers: [{algorithm, keyId}]`, so the signer
//!   list is inside the signed bytes, and EVERY listed signer must verify;
//! - the Ed25519 input is `DOMAIN || payload`, with a different domain per
//!   artifact type, so a signature made for one purpose can never be replayed
//!   as another (nor as a `/api/sign` export, whose domain is
//!   `stig-viewer/sign/v2\0`).
//!
//! The same `SIGNING_KEY_HEX` key signs all of them. The payload also carries
//! a `type` string, checked on verification.

use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signature as EdSignature, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::api::signing::SigningState;

pub const ALGORITHM: &str = "ed25519";
/// Domain-separation prefix for audit archive segment manifests.
pub const ARCHIVE_DOMAIN: &[u8] = b"stig-viewer/audit-archive/v1\0";
/// Domain-separation prefix for backup manifests.
pub const BACKUP_DOMAIN: &[u8] = b"stig-viewer/backup/v1\0";
pub const ARCHIVE_TYPE: &str = "stig-viewer/audit-archive";
pub const BACKUP_TYPE: &str = "stig-viewer/backup";
pub const ENVELOPE_VERSION: u32 = 1;

/// One entry of the signed signer list.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct SignerId {
    pub algorithm: String,
    pub key_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeSignature {
    pub algorithm: String,
    pub key_id: String,
    /// Base64-standard 64-byte Ed25519 signature over `DOMAIN || payload`.
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Envelope {
    pub version: u32,
    #[serde(rename = "type")]
    pub kind: String,
    /// base64url (no padding) of the exact signed bytes.
    pub payload: String,
    pub signatures: Vec<EnvelopeSignature>,
}

/// Lowercase hex SHA-512.
pub fn sha512_hex(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}

/// The signer list to embed in a manifest: one entry per configured key, or
/// empty when signing is disabled.
pub fn signers_for(key: Option<&SigningState>) -> Vec<SignerId> {
    key.map(|k| {
        vec![SignerId {
            algorithm: ALGORITHM.into(),
            key_id: k.key_id.clone(),
        }]
    })
    .unwrap_or_default()
}

fn signing_input(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + payload.len());
    v.extend_from_slice(domain);
    v.extend_from_slice(payload);
    v
}

/// Wrap `payload` (which must already contain `signers_for(key)` and `type`)
/// in an envelope, signing it when a key is configured.
pub fn seal(domain: &[u8], kind: &str, payload: &[u8], key: Option<&SigningState>) -> Envelope {
    let signatures = key
        .map(|k| {
            vec![EnvelopeSignature {
                algorithm: ALGORITHM.into(),
                key_id: k.key_id.clone(),
                signature: BASE64.encode(
                    k.signing_key
                        .sign(&signing_input(domain, payload))
                        .to_bytes(),
                ),
            }]
        })
        .unwrap_or_default();
    Envelope {
        version: ENVELOPE_VERSION,
        kind: kind.into(),
        payload: URL_SAFE_NO_PAD.encode(payload),
        signatures,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Every signer verified against the configured key.
    Verified,
    /// No signature (digest-only).
    Unsigned,
    /// Signed, but by a key this server does not hold (or no key configured).
    UnknownKey,
}

impl SignatureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unsigned => "unsigned",
            Self::UnknownKey => "unknown_key",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum IntegrityError {
    MalformedEnvelope,
    BadPayloadEncoding,
    /// The envelope's payload is not the bytes it was expected to carry.
    PayloadMismatch,
    MalformedPayload,
    /// The signed `type` is not the expected artifact type.
    WrongType,
    UnsupportedAlgorithm(String),
    /// `signers` contains duplicates.
    BadSignerSet,
    MissingSignature,
    UnexpectedSignature,
    BadSignatureEncoding,
    SignatureInvalid,
}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signature verification failed: {self:?}")
    }
}

impl std::error::Error for IntegrityError {}

pub struct Verification {
    pub status: SignatureStatus,
    /// The verified payload bytes.
    pub payload: Vec<u8>,
}

#[derive(Deserialize)]
struct PayloadHead {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    signers: Vec<SignerId>,
}

/// Verify an envelope. `expected_payload`, when given, must equal the decoded
/// payload exactly (a backup's `manifest.json`). A signature by a key the
/// server holds that does not verify is an error; signers whose key the
/// server does not hold give [`SignatureStatus::UnknownKey`].
pub fn verify_envelope(
    domain: &[u8],
    expected_type: &str,
    envelope_json: &[u8],
    expected_payload: Option<&[u8]>,
    key: Option<&SigningState>,
) -> Result<Verification, IntegrityError> {
    let env: Envelope =
        serde_json::from_slice(envelope_json).map_err(|_| IntegrityError::MalformedEnvelope)?;
    let payload = URL_SAFE_NO_PAD
        .decode(env.payload.as_bytes())
        .map_err(|_| IntegrityError::BadPayloadEncoding)?;
    if let Some(expected) = expected_payload {
        if expected != payload.as_slice() {
            return Err(IntegrityError::PayloadMismatch);
        }
    }
    let head: PayloadHead =
        serde_json::from_slice(&payload).map_err(|_| IntegrityError::MalformedPayload)?;
    if head.kind != expected_type {
        return Err(IntegrityError::WrongType);
    }
    if head.signers.is_empty() {
        return if env.signatures.is_empty() {
            Ok(Verification {
                status: SignatureStatus::Unsigned,
                payload,
            })
        } else {
            Err(IntegrityError::UnexpectedSignature)
        };
    }
    let mut seen = std::collections::HashSet::new();
    for s in &head.signers {
        if s.algorithm != ALGORITHM {
            return Err(IntegrityError::UnsupportedAlgorithm(s.algorithm.clone()));
        }
        if !seen.insert(s.clone()) {
            return Err(IntegrityError::BadSignerSet);
        }
    }
    let mut sig_seen = std::collections::HashSet::new();
    for sig in &env.signatures {
        let id = SignerId {
            algorithm: sig.algorithm.clone(),
            key_id: sig.key_id.clone(),
        };
        if !seen.contains(&id) || !sig_seen.insert(id) {
            return Err(IntegrityError::UnexpectedSignature);
        }
    }
    let input = signing_input(domain, &payload);
    let mut unknown = false;
    for signer in &head.signers {
        let sig = env
            .signatures
            .iter()
            .find(|s| s.algorithm == signer.algorithm && s.key_id == signer.key_id)
            .ok_or(IntegrityError::MissingSignature)?;
        match key.filter(|k| k.key_id == signer.key_id) {
            None => unknown = true,
            Some(k) => {
                let raw = BASE64
                    .decode(sig.signature.as_bytes())
                    .map_err(|_| IntegrityError::BadSignatureEncoding)?;
                let ed = EdSignature::from_slice(&raw)
                    .map_err(|_| IntegrityError::BadSignatureEncoding)?;
                k.signing_key
                    .verifying_key()
                    .verify_strict(&input, &ed)
                    .map_err(|_| IntegrityError::SignatureInvalid)?;
            }
        }
    }
    Ok(Verification {
        status: if unknown {
            SignatureStatus::UnknownKey
        } else {
            SignatureStatus::Verified
        },
        payload,
    })
}

#[cfg(test)]
pub fn test_key(seed: u8) -> SigningState {
    SigningState::from_hex(Some(&hex::encode([seed; 32])))
        .unwrap()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(kind: &str, key: Option<&SigningState>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": kind, "version": 1, "signers": signers_for(key)
        }))
        .unwrap()
    }

    fn sealed(domain: &[u8], kind: &str, key: Option<&SigningState>) -> Vec<u8> {
        serde_json::to_vec(&seal(domain, kind, &payload(kind, key), key)).unwrap()
    }

    #[test]
    fn signed_envelope_verifies() {
        let k = test_key(1);
        let env = sealed(ARCHIVE_DOMAIN, ARCHIVE_TYPE, Some(&k));
        let v = verify_envelope(ARCHIVE_DOMAIN, ARCHIVE_TYPE, &env, None, Some(&k)).unwrap();
        assert_eq!(v.status, SignatureStatus::Verified);
    }

    #[test]
    fn archive_signature_replayed_as_backup_fails() {
        let k = test_key(1);
        // Same key, same payload bytes shape; only the domain differs.
        let p = payload(BACKUP_TYPE, Some(&k));
        let env = serde_json::to_vec(&seal(ARCHIVE_DOMAIN, BACKUP_TYPE, &p, Some(&k))).unwrap();
        assert_eq!(
            verify_envelope(BACKUP_DOMAIN, BACKUP_TYPE, &env, None, Some(&k)).err(),
            Some(IntegrityError::SignatureInvalid)
        );
        // And an honest archive envelope is refused on its type.
        let env = sealed(ARCHIVE_DOMAIN, ARCHIVE_TYPE, Some(&k));
        assert_eq!(
            verify_envelope(BACKUP_DOMAIN, BACKUP_TYPE, &env, None, Some(&k)).err(),
            Some(IntegrityError::WrongType)
        );
    }

    #[test]
    fn export_domain_signature_is_not_accepted() {
        let k = test_key(1);
        let p = payload(BACKUP_TYPE, Some(&k));
        let env =
            serde_json::to_vec(&seal(b"stig-viewer/sign/v2\0", BACKUP_TYPE, &p, Some(&k))).unwrap();
        assert_eq!(
            verify_envelope(BACKUP_DOMAIN, BACKUP_TYPE, &env, None, Some(&k)).err(),
            Some(IntegrityError::SignatureInvalid)
        );
    }

    #[test]
    fn tampered_payload_or_signature_fails() {
        let k = test_key(1);
        let mut env: Envelope =
            serde_json::from_slice(&sealed(BACKUP_DOMAIN, BACKUP_TYPE, Some(&k))).unwrap();
        let mut p = URL_SAFE_NO_PAD.decode(&env.payload).unwrap();
        p.push(b' ');
        env.payload = URL_SAFE_NO_PAD.encode(&p);
        let bytes = serde_json::to_vec(&env).unwrap();
        assert_eq!(
            verify_envelope(BACKUP_DOMAIN, BACKUP_TYPE, &bytes, None, Some(&k)).err(),
            Some(IntegrityError::SignatureInvalid)
        );
        // Expected-payload binding.
        let good = sealed(BACKUP_DOMAIN, BACKUP_TYPE, Some(&k));
        assert_eq!(
            verify_envelope(BACKUP_DOMAIN, BACKUP_TYPE, &good, Some(b"other"), Some(&k)).err(),
            Some(IntegrityError::PayloadMismatch)
        );
    }

    #[test]
    fn every_signer_must_have_a_signature_and_extras_are_refused() {
        let k = test_key(1);
        let mut env: Envelope =
            serde_json::from_slice(&sealed(BACKUP_DOMAIN, BACKUP_TYPE, Some(&k))).unwrap();
        let mut extra = env.signatures[0].clone();
        extra.key_id = "other".into();
        env.signatures.push(extra);
        assert_eq!(
            verify_envelope(
                BACKUP_DOMAIN,
                BACKUP_TYPE,
                &serde_json::to_vec(&env).unwrap(),
                None,
                Some(&k)
            )
            .err(),
            Some(IntegrityError::UnexpectedSignature)
        );
        env.signatures.clear();
        assert_eq!(
            verify_envelope(
                BACKUP_DOMAIN,
                BACKUP_TYPE,
                &serde_json::to_vec(&env).unwrap(),
                None,
                Some(&k)
            )
            .err(),
            Some(IntegrityError::MissingSignature)
        );
    }

    #[test]
    fn unsigned_and_unknown_key_statuses() {
        let k = test_key(1);
        let unsigned = sealed(BACKUP_DOMAIN, BACKUP_TYPE, None);
        assert_eq!(
            verify_envelope(BACKUP_DOMAIN, BACKUP_TYPE, &unsigned, None, Some(&k))
                .unwrap()
                .status,
            SignatureStatus::Unsigned
        );
        let signed = sealed(BACKUP_DOMAIN, BACKUP_TYPE, Some(&k));
        let other = test_key(2);
        assert_eq!(
            verify_envelope(BACKUP_DOMAIN, BACKUP_TYPE, &signed, None, Some(&other))
                .unwrap()
                .status,
            SignatureStatus::UnknownKey
        );
        assert_eq!(
            verify_envelope(BACKUP_DOMAIN, BACKUP_TYPE, &signed, None, None)
                .unwrap()
                .status,
            SignatureStatus::UnknownKey
        );
    }

    #[test]
    fn sha512_is_hex_of_64_bytes() {
        assert_eq!(sha512_hex(b"").len(), 128);
    }
}
