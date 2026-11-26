//! Integrity envelopes for system-produced artifacts (audit archive segments
//! and backups).
//!
//! The design mirrors the signed-bundle envelope in `api::signing`:
//!
//! - the envelope carries `payload`, the base64url (no padding) exact bytes
//!   that were signed, and `signatures: [{algorithm, keyId, signature}]`;
//! - the payload names its own `signers: [{algorithm, keyId}]`, so the signer
//!   list is inside the signed bytes, and EVERY listed signer must verify. The
//!   accepted signer sets are `[ed25519]` (classical) and
//!   `[ed25519, ml-dsa-87]` (hybrid), see [`crate::signers`];
//! - every signature's input is `DOMAIN || payload`, with a different domain
//!   per artifact type, so a signature made for one purpose can never be
//!   replayed as another (nor as a `/api/sign` export, whose domain is
//!   `stig-viewer/sign/v2\0`).
//!
//! The same signing keys (`SIGNING_KEY_HEX`, and `SIGNING_MLDSA87_KEY_B64`
//! when set) sign all of them. The payload also carries a `type` string,
//! checked on verification. The outer `version` stays 1: it is never checked
//! by [`verify_envelope`]; the signed signer set is the profile.

use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{Deserialize, Serialize};

use crate::api::signing::SigningState;
use crate::crypto;
use crate::signers::{self, Algorithm};
pub use crate::signers::{Profile, SignerId};

/// Domain-separation prefix for audit archive segment manifests.
pub const ARCHIVE_DOMAIN: &[u8] = b"stig-viewer/audit-archive/v1\0";
/// Domain-separation prefix for backup manifests.
pub const BACKUP_DOMAIN: &[u8] = b"stig-viewer/backup/v1\0";
pub const ARCHIVE_TYPE: &str = "stig-viewer/audit-archive";
pub const BACKUP_TYPE: &str = "stig-viewer/backup";
pub const ENVELOPE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeSignature {
    pub algorithm: String,
    pub key_id: String,
    /// Base64-standard signature over `DOMAIN || payload`: 64 bytes for
    /// Ed25519, 4627 for ML-DSA-87.
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
    crypto::digest::sha512_hex(bytes)
}

/// The signer list to embed in a manifest: one entry per configured key
/// (Ed25519, then ML-DSA-87 when configured), or empty when signing is
/// disabled.
pub fn signers_for(key: Option<&SigningState>) -> Vec<SignerId> {
    key.map(SigningState::signers).unwrap_or_default()
}

fn signing_input(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + payload.len());
    v.extend_from_slice(domain);
    v.extend_from_slice(payload);
    v
}

/// Wrap `payload` (which must already contain `signers_for(key)` and `type`)
/// in an envelope, signing it with every configured key when one is. A signing
/// failure is an error; the caller must not write an unsigned artifact instead.
pub fn seal(
    domain: &[u8],
    kind: &str,
    payload: &[u8],
    key: Option<&SigningState>,
) -> anyhow::Result<Envelope> {
    let signatures = match key {
        Some(k) => k
            .sign_all(&signing_input(domain, payload))?
            .into_iter()
            .map(|p| EnvelopeSignature {
                algorithm: p.algorithm.wire().into(),
                key_id: p.key_id,
                signature: BASE64.encode(p.signature),
            })
            .collect(),
        None => Vec::new(),
    };
    Ok(Envelope {
        version: ENVELOPE_VERSION,
        kind: kind.into(),
        payload: URL_SAFE_NO_PAD.encode(payload),
        signatures,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Every signer verified against the configured keys.
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
    /// `signers` is not `[ed25519]` or `[ed25519, ml-dsa-87]`.
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
    /// The signed signer set's profile; `None` when unsigned.
    pub profile: Option<Profile>,
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
/// server does not hold give [`SignatureStatus::UnknownKey`]. The returned
/// profile is the signed signer set's, whatever the status.
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
                profile: None,
            })
        } else {
            Err(IntegrityError::UnexpectedSignature)
        };
    }
    let profile = signers::classify(head.signers.iter().map(|s| s.algorithm.as_str())).map_err(
        |e| match e {
            signers::ClassifyError::UnsupportedAlgorithm(a) => {
                IntegrityError::UnsupportedAlgorithm(a)
            }
            signers::ClassifyError::BadSet => IntegrityError::BadSignerSet,
        },
    )?;
    let seen: std::collections::HashSet<&SignerId> = head.signers.iter().collect();
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
    let trusted = key.map(SigningState::trusted).unwrap_or_default();
    let mut unknown = false;
    for signer in &head.signers {
        let sig = env
            .signatures
            .iter()
            .find(|s| s.algorithm == signer.algorithm && s.key_id == signer.key_id)
            .ok_or(IntegrityError::MissingSignature)?;
        let known = Algorithm::from_wire(&signer.algorithm)
            .and_then(|alg| trusted.find(alg, &signer.key_id).map(|k| (alg, k)));
        match known {
            None => unknown = true,
            Some((alg, k)) => {
                let raw = BASE64
                    .decode(sig.signature.as_bytes())
                    .map_err(|_| IntegrityError::BadSignatureEncoding)?;
                signers::verify_sig(alg, &k.public_key, &input, &raw).map_err(|e| match e {
                    signers::SigError::BadLength => IntegrityError::BadSignatureEncoding,
                    signers::SigError::Invalid => IntegrityError::SignatureInvalid,
                })?;
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
        profile: Some(profile),
    })
}

/// Per-process random Ed25519 seed for `n`, so tests never carry key material
/// in source and `test_key(1) != test_key(2)`.
#[cfg(test)]
fn test_seed(n: u8) -> [u8; 32] {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static SEEDS: OnceLock<Mutex<HashMap<u8, [u8; 32]>>> = OnceLock::new();
    let mut m = SEEDS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *m.entry(n).or_insert_with(|| {
        let mut s = [0u8; 32];
        crypto::rand::fill(&mut s).expect("rng");
        s
    })
}

/// Classical (Ed25519-only) state with a per-process random key.
#[cfg(test)]
pub fn test_key(n: u8) -> SigningState {
    SigningState::from_hex(Some(&hex::encode(test_seed(n))))
        .unwrap()
        .unwrap()
}

/// Hybrid state: the same Ed25519 key as [`test_key`]`(n)` plus a per-process
/// random ML-DSA-87 key.
#[cfg(test)]
pub fn test_hybrid_key(n: u8) -> SigningState {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static KEYS: OnceLock<Mutex<HashMap<u8, Vec<u8>>>> = OnceLock::new();
    let der = KEYS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(n)
        .or_insert_with(|| {
            crypto::mldsa::SigningKey::generate()
                .and_then(|k| k.to_pkcs8())
                .expect("ml-dsa key")
        })
        .clone();
    let mut st = test_key(n);
    st.mldsa = Some(std::sync::Arc::new(crate::api::signing::MlDsaSigner::new(
        crypto::mldsa::SigningKey::from_pkcs8(&der).expect("ml-dsa key"),
    )));
    st
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
        serde_json::to_vec(&seal(domain, kind, &payload(kind, key), key).unwrap()).unwrap()
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
        let env =
            serde_json::to_vec(&seal(ARCHIVE_DOMAIN, BACKUP_TYPE, &p, Some(&k)).unwrap()).unwrap();
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
            serde_json::to_vec(&seal(b"stig-viewer/sign/v2\0", BACKUP_TYPE, &p, Some(&k)).unwrap())
                .unwrap();
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

    // ── Hybrid (#66, #68) ──────────────────────────────────────────────────

    fn verified(
        domain: &[u8],
        kind: &str,
        env: &[u8],
        key: &SigningState,
    ) -> Result<Verification, IntegrityError> {
        verify_envelope(domain, kind, env, None, Some(key))
    }

    fn envelope_of(bytes: &[u8]) -> Envelope {
        serde_json::from_slice(bytes).unwrap()
    }

    fn to_bytes(env: &Envelope) -> Vec<u8> {
        serde_json::to_vec(env).unwrap()
    }

    #[test]
    fn hybrid_envelopes_verify_in_both_artifact_domains() {
        let k = test_hybrid_key(1);
        for (domain, kind) in [(ARCHIVE_DOMAIN, ARCHIVE_TYPE), (BACKUP_DOMAIN, BACKUP_TYPE)] {
            let bytes = sealed(domain, kind, Some(&k));
            let env = envelope_of(&bytes);
            assert_eq!(env.version, 1);
            assert_eq!(env.signatures.len(), 2);
            assert_eq!(env.signatures[0].algorithm, "ed25519");
            assert_eq!(env.signatures[1].algorithm, "ml-dsa-87");
            let v = verified(domain, kind, &bytes, &k).unwrap();
            assert_eq!(v.status, SignatureStatus::Verified);
            assert_eq!(v.profile, Some(Profile::Hybrid));
        }
        let classical = sealed(BACKUP_DOMAIN, BACKUP_TYPE, Some(&test_key(1)));
        let v = verified(BACKUP_DOMAIN, BACKUP_TYPE, &classical, &test_key(1)).unwrap();
        assert_eq!(v.profile, Some(Profile::Classical));
        let unsigned = sealed(BACKUP_DOMAIN, BACKUP_TYPE, None);
        let v = verified(BACKUP_DOMAIN, BACKUP_TYPE, &unsigned, &test_key(1)).unwrap();
        assert_eq!(v.profile, None);
    }

    #[test]
    fn hybrid_missing_swapped_or_duplicated_signatures_fail() {
        let k = test_hybrid_key(1);
        let good = envelope_of(&sealed(BACKUP_DOMAIN, BACKUP_TYPE, Some(&k)));
        let check = |env: &Envelope| verified(BACKUP_DOMAIN, BACKUP_TYPE, &to_bytes(env), &k).err();

        let mut e = envelope_of(&to_bytes(&good));
        e.signatures.remove(1);
        assert_eq!(check(&e), Some(IntegrityError::MissingSignature));
        let mut e = envelope_of(&to_bytes(&good));
        e.signatures.remove(0);
        assert_eq!(check(&e), Some(IntegrityError::MissingSignature));
        let mut e = envelope_of(&to_bytes(&good));
        e.signatures.push(good.signatures[1].clone());
        assert_eq!(check(&e), Some(IntegrityError::UnexpectedSignature));
        // Swapped signature bytes.
        let mut e = envelope_of(&to_bytes(&good));
        let (a, b) = (
            good.signatures[0].signature.clone(),
            good.signatures[1].signature.clone(),
        );
        e.signatures[0].signature = b;
        e.signatures[1].signature = a;
        assert_eq!(check(&e), Some(IntegrityError::BadSignatureEncoding));
        // Flipped ML-DSA byte.
        let mut e = envelope_of(&to_bytes(&good));
        let mut raw = BASE64.decode(&good.signatures[1].signature).unwrap();
        raw[9] ^= 1;
        e.signatures[1].signature = BASE64.encode(raw);
        assert_eq!(check(&e), Some(IntegrityError::SignatureInvalid));
    }

    #[test]
    fn cross_domain_replay_fails_for_both_algorithms() {
        let k = test_hybrid_key(1);
        let p = payload(BACKUP_TYPE, Some(&k));
        for wrong in [ARCHIVE_DOMAIN, b"stig-viewer/sign/v2\0".as_slice()] {
            let env = to_bytes(&seal(wrong, BACKUP_TYPE, &p, Some(&k)).unwrap());
            assert_eq!(
                verified(BACKUP_DOMAIN, BACKUP_TYPE, &env, &k).err(),
                Some(IntegrityError::SignatureInvalid)
            );
            // The ML-DSA signature alone is wrong-domain too: swap in the right
            // Ed25519 signature and it must still fail.
            let right = envelope_of(&sealed(BACKUP_DOMAIN, BACKUP_TYPE, Some(&k)));
            let mut mixed = envelope_of(&env);
            mixed.payload = right.payload.clone();
            mixed.signatures[0] = right.signatures[0].clone();
            assert_eq!(
                verified(BACKUP_DOMAIN, BACKUP_TYPE, &to_bytes(&mixed), &k).err(),
                Some(IntegrityError::SignatureInvalid)
            );
        }
    }

    #[test]
    fn only_the_two_signer_profiles_are_accepted() {
        let k = test_hybrid_key(1);
        let ed = k.signers()[0].clone();
        let ml = k.signers()[1].clone();
        let unknown = SignerId {
            algorithm: "ml-dsa-65".into(),
            key_id: "00".into(),
        };
        let cases: Vec<(Vec<SignerId>, IntegrityError)> = vec![
            (vec![ml.clone(), ed.clone()], IntegrityError::BadSignerSet),
            (vec![ml.clone()], IntegrityError::BadSignerSet),
            (vec![ed.clone(), ed.clone()], IntegrityError::BadSignerSet),
            (
                vec![ed.clone(), ml.clone(), ml.clone()],
                IntegrityError::BadSignerSet,
            ),
            (
                vec![ed.clone(), unknown],
                IntegrityError::UnsupportedAlgorithm("ml-dsa-65".into()),
            ),
        ];
        for (signers, want) in cases {
            let p = serde_json::to_vec(&serde_json::json!({
                "type": BACKUP_TYPE, "version": 1, "signers": signers
            }))
            .unwrap();
            let env = to_bytes(&seal(BACKUP_DOMAIN, BACKUP_TYPE, &p, Some(&k)).unwrap());
            assert_eq!(
                verified(BACKUP_DOMAIN, BACKUP_TYPE, &env, &k).err(),
                Some(want),
                "{signers:?}"
            );
        }
    }

    #[test]
    fn stripping_the_ml_dsa_half_and_its_signer_needs_a_forgery() {
        let k = test_hybrid_key(1);
        let good = envelope_of(&sealed(ARCHIVE_DOMAIN, ARCHIVE_TYPE, Some(&k)));
        // Remove the ML-DSA signer from the payload and the signature: the
        // Ed25519 signature covered the old bytes.
        let mut p: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&good.payload).unwrap()).unwrap();
        p["signers"].as_array_mut().unwrap().pop();
        let mut e = envelope_of(&to_bytes(&good));
        e.payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&p).unwrap());
        e.signatures.pop();
        assert_eq!(
            verified(ARCHIVE_DOMAIN, ARCHIVE_TYPE, &to_bytes(&e), &k).err(),
            Some(IntegrityError::SignatureInvalid)
        );
    }

    #[test]
    fn classical_and_hybrid_artifacts_across_server_configurations() {
        let (classical, hybrid) = (test_key(1), test_hybrid_key(1));
        // A classical artifact still verifies on a hybrid server.
        let c = sealed(BACKUP_DOMAIN, BACKUP_TYPE, Some(&classical));
        let v = verified(BACKUP_DOMAIN, BACKUP_TYPE, &c, &hybrid).unwrap();
        assert_eq!(
            (v.status, v.profile),
            (SignatureStatus::Verified, Some(Profile::Classical))
        );
        // A hybrid artifact on a classical server: Ed25519 verifies, the
        // ML-DSA key is not held, so the status is unknown_key (never verified).
        let h = sealed(BACKUP_DOMAIN, BACKUP_TYPE, Some(&hybrid));
        let v = verified(BACKUP_DOMAIN, BACKUP_TYPE, &h, &classical).unwrap();
        assert_eq!(
            (v.status, v.profile),
            (SignatureStatus::UnknownKey, Some(Profile::Hybrid))
        );
        // ... and a bad Ed25519 half is still an error there.
        let mut e = envelope_of(&h);
        let mut raw = BASE64.decode(&e.signatures[0].signature).unwrap();
        raw[0] ^= 1;
        e.signatures[0].signature = BASE64.encode(raw);
        assert_eq!(
            verified(BACKUP_DOMAIN, BACKUP_TYPE, &to_bytes(&e), &classical).err(),
            Some(IntegrityError::SignatureInvalid)
        );
    }

    #[test]
    fn sha512_is_hex_of_64_bytes() {
        assert_eq!(sha512_hex(b"").len(), 128);
    }
}
