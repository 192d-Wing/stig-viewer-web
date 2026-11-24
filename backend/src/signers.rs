//! Signer identities, key ids and the accepted signer profiles, shared by the
//! `/api/sign` bundle verifier (`api::signing`) and the archive/backup
//! verifier (`integrity`).
//!
//! A signed signer set is a *profile*: `[ed25519]` (classical) or
//! `[ed25519, ml-dsa-87]` (hybrid, in that order). Any other set is rejected,
//! and every listed signer must verify (AND semantics), so stripping the
//! ML-DSA signature from a hybrid artifact cannot downgrade it unless the
//! signed signer list is also rewritten (which needs an Ed25519 forgery).

use serde::{Deserialize, Serialize};

use crate::crypto;

/// Wire name of the Ed25519 algorithm.
pub const ED25519: &str = "ed25519";
/// Wire name of the ML-DSA-87 algorithm.
pub const ML_DSA_87: &str = "ml-dsa-87";

/// One entry of a signed signer list.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct SignerId {
    pub algorithm: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    MlDsa87,
}

impl Algorithm {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519,
            Self::MlDsa87 => ML_DSA_87,
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            ED25519 => Some(Self::Ed25519),
            ML_DSA_87 => Some(Self::MlDsa87),
            _ => None,
        }
    }
}

/// Key id: Ed25519 is the first 8 bytes of SHA-256 over the raw public key
/// (16 hex); ML-DSA-87 is the first 16 bytes of
/// SHA-384(`"ml-dsa-87" || 0x00 || raw public key`) (32 hex).
pub fn key_id(alg: Algorithm, public: &[u8]) -> String {
    match alg {
        Algorithm::Ed25519 => hex::encode(&crypto::digest::sha256(public)[..8]),
        Algorithm::MlDsa87 => {
            let mut input = Vec::with_capacity(ML_DSA_87.len() + 1 + public.len());
            input.extend_from_slice(ML_DSA_87.as_bytes());
            input.push(0);
            input.extend_from_slice(public);
            hex::encode(&crypto::digest::sha384(&input)[..16])
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Ed25519 only.
    Classical,
    /// Ed25519 and ML-DSA-87.
    Hybrid,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classical => "classical",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassifyError {
    /// A signer names an algorithm this build cannot verify.
    UnsupportedAlgorithm(String),
    /// Not exactly `[ed25519]` or `[ed25519, ml-dsa-87]`.
    BadSet,
}

/// Map a signed signer list's algorithms to a profile.
///
/// The accepted sets are deliberately fixed. A future profile (ML-DSA only,
/// SLH-DSA, key rotation with several keys per algorithm for #68) must be
/// added here explicitly, together with its tests. Relaxing this to "any set of
/// supported algorithms" would open a downgrade path: an attacker who can
/// forge one supported signature could drop the others from the signer list. Unknown algorithms are
/// rejected, never skipped.
pub fn classify<'a>(
    algorithms: impl IntoIterator<Item = &'a str>,
) -> Result<Profile, ClassifyError> {
    let mut algs = Vec::new();
    for a in algorithms {
        match Algorithm::from_wire(a) {
            Some(alg) => algs.push(alg),
            None => return Err(ClassifyError::UnsupportedAlgorithm(a.to_string())),
        }
    }
    match algs.as_slice() {
        [Algorithm::Ed25519] => Ok(Profile::Classical),
        [Algorithm::Ed25519, Algorithm::MlDsa87] => Ok(Profile::Hybrid),
        _ => Err(ClassifyError::BadSet),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub algorithm: Algorithm,
    pub key_id: String,
    /// Raw public key bytes.
    pub public_key: Vec<u8>,
}

/// Keys a verifier trusts, looked up by (algorithm, keyId). Today it holds the
/// server's current keys; a key-history list can extend it without touching
/// the verifiers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedKeys(Vec<TrustedKey>);

impl TrustedKeys {
    pub fn new(keys: Vec<TrustedKey>) -> Self {
        Self(keys)
    }

    pub fn from_ed25519(public: &[u8; 32]) -> Self {
        Self(vec![TrustedKey {
            algorithm: Algorithm::Ed25519,
            key_id: key_id(Algorithm::Ed25519, public),
            public_key: public.to_vec(),
        }])
    }

    pub fn find(&self, alg: Algorithm, key_id: &str) -> Option<&TrustedKey> {
        self.0
            .iter()
            .find(|k| k.algorithm == alg && k.key_id == key_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    BadLength,
    Invalid,
}

/// Verify one signature of either algorithm over `input` (domain || payload).
pub fn verify_sig(alg: Algorithm, public: &[u8], input: &[u8], sig: &[u8]) -> Result<(), SigError> {
    match alg {
        Algorithm::Ed25519 => {
            let pk: &[u8; 32] = public.try_into().map_err(|_| SigError::Invalid)?;
            crypto::ed25519::verify(pk, input, sig).map_err(|e| match e {
                crypto::ed25519::VerifyError::BadLength => SigError::BadLength,
                crypto::ed25519::VerifyError::Invalid => SigError::Invalid,
            })
        }
        Algorithm::MlDsa87 => crypto::mldsa::verify(public, input, sig).map_err(|e| match e {
            crypto::mldsa::VerifyError::BadLength => SigError::BadLength,
            crypto::mldsa::VerifyError::Invalid => SigError::Invalid,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_accepts_only_the_two_profiles() {
        assert_eq!(classify([ED25519]), Ok(Profile::Classical));
        assert_eq!(classify([ED25519, ML_DSA_87]), Ok(Profile::Hybrid));
        for bad in [
            vec![],
            vec![ML_DSA_87],
            vec![ML_DSA_87, ED25519],
            vec![ED25519, ED25519],
            vec![ED25519, ML_DSA_87, ML_DSA_87],
            vec![ED25519, ML_DSA_87, ED25519],
        ] {
            assert_eq!(classify(bad.clone()), Err(ClassifyError::BadSet), "{bad:?}");
        }
        assert_eq!(
            classify([ED25519, "ml-dsa-65"]),
            Err(ClassifyError::UnsupportedAlgorithm("ml-dsa-65".into()))
        );
    }

    #[test]
    fn key_ids_have_the_documented_shape_and_differ_by_algorithm() {
        let pk = [7u8; 32];
        let ed = key_id(Algorithm::Ed25519, &pk);
        assert_eq!(ed.len(), 16);
        assert_eq!(ed, hex::encode(&crypto::digest::sha256(&pk)[..8]));
        let ml = key_id(Algorithm::MlDsa87, &pk);
        assert_eq!(ml.len(), 32);
        let mut input = b"ml-dsa-87\0".to_vec();
        input.extend_from_slice(&pk);
        assert_eq!(ml, hex::encode(&crypto::digest::sha384(&input)[..16]));
    }

    #[test]
    fn trusted_lookup_is_by_algorithm_and_key_id() {
        let pk = [9u8; 32];
        let t = TrustedKeys::from_ed25519(&pk);
        let id = key_id(Algorithm::Ed25519, &pk);
        assert!(t.find(Algorithm::Ed25519, &id).is_some());
        assert!(t.find(Algorithm::MlDsa87, &id).is_none());
        assert!(t.find(Algorithm::Ed25519, "nope").is_none());
    }
}
