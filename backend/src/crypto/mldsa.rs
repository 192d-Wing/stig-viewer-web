//! ML-DSA-87 (FIPS 204) signing and verification, pure mode with the empty
//! context string, on AWS-LC (`aws_lc_rs::signature::PqdsaKeyPair`).
//!
//! Signing is hedged (randomised), so there are no signing known-answer
//! tests; the tests round-trip and check cross-implementation vectors
//! elsewhere (`scripts/verify-bundle.mjs`).

use aws_lc_rs::signature::{
    KeyPair, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_87, ML_DSA_87_SIGNING,
};
use std::fmt;

/// FIPS 204 ML-DSA-87 encoded public key length.
pub const PUBLIC_KEY_LEN: usize = 2592;
/// FIPS 204 ML-DSA-87 signature length.
pub const SIGNATURE_LEN: usize = 4627;

pub struct SigningKey(PqdsaKeyPair);

impl SigningKey {
    /// A fresh key from the module's RNG.
    pub fn generate() -> anyhow::Result<Self> {
        PqdsaKeyPair::generate(&ML_DSA_87_SIGNING)
            .map(Self)
            .map_err(|_| anyhow::anyhow!("ML-DSA-87 key generation failed"))
    }

    /// Load from PKCS#8 DER. The error never echoes the input.
    pub fn from_pkcs8(der: &[u8]) -> anyhow::Result<Self> {
        PqdsaKeyPair::from_pkcs8(&ML_DSA_87_SIGNING, der)
            .map(Self)
            .map_err(|_| anyhow::anyhow!("ML-DSA-87 PKCS#8 private key rejected"))
    }

    /// PKCS#8 DER (seed form). Only the `gen-mldsa-key` subcommand calls this.
    pub fn to_pkcs8(&self) -> anyhow::Result<Vec<u8>> {
        self.0
            .to_pkcs8v1()
            .map(|d| d.as_ref().to_vec())
            .map_err(|_| anyhow::anyhow!("ML-DSA-87 private key export failed"))
    }

    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = vec![0u8; ML_DSA_87_SIGNING.signature_len()];
        let n = self
            .0
            .sign(msg, &mut out)
            .map_err(|_| anyhow::anyhow!("ML-DSA-87 signing failed"))?;
        out.truncate(n);
        Ok(out)
    }

    /// Raw FIPS 204 public key bytes.
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key().as_ref().to_vec()
    }
}

/// Never prints key material.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsaSigningKey(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Public key or signature has the wrong length.
    BadLength,
    /// Signature does not verify.
    Invalid,
}

/// Verify `sig` over `msg` (empty context) against a raw public key. Lengths
/// are checked before the call into the module.
pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
    if public.len() != PUBLIC_KEY_LEN || sig.len() != SIGNATURE_LEN {
        return Err(VerifyError::BadLength);
    }
    UnparsedPublicKey::new(&ML_DSA_87, public)
        .verify(msg, sig)
        .map_err(|_| VerifyError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_sizes() {
        let k = SigningKey::generate().unwrap();
        let pk = k.public_key();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);
        let sig = k.sign(b"message").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify(&pk, b"message", &sig).is_ok());
        assert_eq!(verify(&pk, b"other", &sig), Err(VerifyError::Invalid));
    }

    #[test]
    fn flipped_byte_and_wrong_key_rejected() {
        let k = SigningKey::generate().unwrap();
        let pk = k.public_key();
        let mut sig = k.sign(b"m").unwrap();
        sig[100] ^= 1;
        assert_eq!(verify(&pk, b"m", &sig), Err(VerifyError::Invalid));
        let sig = k.sign(b"m").unwrap();
        let other = SigningKey::generate().unwrap();
        assert_eq!(
            verify(&other.public_key(), b"m", &sig),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn wrong_lengths_rejected_before_the_module() {
        let k = SigningKey::generate().unwrap();
        let pk = k.public_key();
        let sig = k.sign(b"m").unwrap();
        assert_eq!(verify(&pk, b"m", &sig[..100]), Err(VerifyError::BadLength));
        let mut long = sig.clone();
        long.push(0);
        assert_eq!(verify(&pk, b"m", &long), Err(VerifyError::BadLength));
        assert_eq!(verify(&pk[..32], b"m", &sig), Err(VerifyError::BadLength));
        assert_eq!(verify(&[], b"m", &[]), Err(VerifyError::BadLength));
    }

    #[test]
    fn pkcs8_round_trip_and_garbage() {
        let k = SigningKey::generate().unwrap();
        let der = k.to_pkcs8().unwrap();
        let k2 = SigningKey::from_pkcs8(&der).unwrap();
        assert_eq!(k.public_key(), k2.public_key());
        let sig = k2.sign(b"m").unwrap();
        assert!(verify(&k.public_key(), b"m", &sig).is_ok());
        assert!(SigningKey::from_pkcs8(b"not pkcs8").is_err());
        assert!(SigningKey::from_pkcs8(&[]).is_err());
        assert!(SigningKey::from_pkcs8(&der[..der.len() - 1]).is_err());
    }

    #[test]
    fn debug_does_not_leak() {
        let k = SigningKey::generate().unwrap();
        assert_eq!(format!("{k:?}"), "MlDsaSigningKey(<redacted>)");
    }
}
