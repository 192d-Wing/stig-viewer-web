//! Ed25519 signing and verification.

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use std::fmt;

pub struct SigningKey(Ed25519KeyPair);

impl SigningKey {
    /// Load from a raw 32-byte seed (RFC 8032 private key).
    pub fn from_seed(seed: &[u8; 32]) -> anyhow::Result<Self> {
        Ed25519KeyPair::from_seed_unchecked(seed)
            .map(Self)
            .map_err(|_| anyhow::anyhow!("signing key seed rejected"))
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.0.sign(msg).as_ref());
        out
    }

    pub fn public_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.public_key().as_ref());
        out
    }
}

/// Never prints key material.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Signature is not 64 bytes.
    BadLength,
    /// Signature does not verify.
    Invalid,
}

/// Verify `sig` over `msg` against a raw 32-byte public key. Only for the
/// server's own pinned key, never an attacker-supplied one: aws-lc rejects
/// non-canonical S but is not dalek's `verify_strict` (no small-order or
/// mixed-order key rejection).
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
    if sig.len() != 64 {
        return Err(VerifyError::BadLength);
    }
    UnparsedPublicKey::new(&ED25519, public)
        .verify(msg, sig)
        .map_err(|_| VerifyError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey as Dalek};

    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        crate::crypto::rand::fill(&mut s).unwrap();
        s
    }

    #[test]
    fn matches_dalek_byte_for_byte_and_cross_verifies() {
        let seed = seed();
        let ours = SigningKey::from_seed(&seed).unwrap();
        let theirs = Dalek::from_bytes(&seed);
        assert_eq!(ours.public_key(), theirs.verifying_key().to_bytes());
        for len in [0usize, 1, 64, 1 << 20] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let sig = ours.sign(&msg);
            assert_eq!(sig, theirs.sign(&msg).to_bytes());
            assert!(verify(&ours.public_key(), &msg, &sig).is_ok());
            let ed = ed25519_dalek::Signature::from_slice(&sig).unwrap();
            assert!(theirs.verifying_key().verify_strict(&msg, &ed).is_ok());
            let dsig = theirs.sign(&msg).to_bytes();
            assert!(verify(&ours.public_key(), &msg, &dsig).is_ok());
        }
    }

    #[test]
    fn negatives() {
        let k = SigningKey::from_seed(&seed()).unwrap();
        let pk = k.public_key();
        let msg = b"message";
        let sig = k.sign(msg);
        assert!(verify(&pk, msg, &sig).is_ok());

        let mut flipped = sig;
        flipped[10] ^= 1;
        assert_eq!(verify(&pk, msg, &flipped), Err(VerifyError::Invalid));
        assert_eq!(verify(&pk, b"other", &sig), Err(VerifyError::Invalid));
        assert_eq!(verify(&pk, msg, &sig[..63]), Err(VerifyError::BadLength));
        let mut long = sig.to_vec();
        long.push(0);
        assert_eq!(verify(&pk, msg, &long), Err(VerifyError::BadLength));

        let other = SigningKey::from_seed(&seed()).unwrap();
        assert_eq!(
            verify(&other.public_key(), msg, &sig),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn non_canonical_s_is_rejected() {
        // Group order L, little-endian; S + L encodes the same scalar mod L.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let k = SigningKey::from_seed(&seed()).unwrap();
        let sig = k.sign(b"m");
        let mut carry = 0u16;
        let mut bad = sig;
        for i in 0..32 {
            let v = sig[32 + i] as u16 + L[i] as u16 + carry;
            bad[32 + i] = v as u8;
            carry = v >> 8;
        }
        // S < 2^253 so S + L < 2^254 and fits without overflow.
        assert_eq!(carry, 0);
        assert!(verify(&k.public_key(), b"m", &bad).is_err());
    }

    #[test]
    fn debug_does_not_leak() {
        let k = SigningKey::from_seed(&seed()).unwrap();
        assert_eq!(format!("{k:?}"), "SigningKey(<redacted>)");
    }
}
