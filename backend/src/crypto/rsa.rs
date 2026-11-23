//! RSA PKCS#1 v1.5 / SHA-256 signature verification for SAML.

use anyhow::{anyhow, Result};
use aws_lc_rs::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo};
use x509_parser::public_key::PublicKey;

/// Exact bit length of a DER INTEGER modulus. Rejects empty, negative and
/// non-minimal (zero-padded beyond the single sign byte) encodings, so a padded
/// small modulus cannot pass a size gate. (x509-parser's `key_size()` is a
/// byte-based estimate, not a bit count.)
fn true_modulus_bits(der_int: &[u8]) -> Result<usize> {
    let mag = match der_int {
        [] => return Err(anyhow!("empty RSA modulus")),
        [0, rest @ ..] => {
            if rest.first().is_none_or(|b| b & 0x80 == 0) {
                return Err(anyhow!("non-minimal RSA modulus encoding"));
            }
            rest
        }
        [b, ..] if b & 0x80 != 0 => return Err(anyhow!("negative RSA modulus")),
        all => all,
    };
    Ok(mag.len() * 8 - mag[0].leading_zeros() as usize)
}

/// An RSA public key held as PKCS#1 `RSAPublicKey` DER, plus its modulus size.
#[derive(Debug, Clone)]
pub struct RsaVerifyKey {
    pkcs1_der: Vec<u8>,
    modulus_bits: usize,
}

impl RsaVerifyKey {
    /// Parse a DER `SubjectPublicKeyInfo`; fails unless it is an RSA key.
    pub fn from_spki_der(spki_der: &[u8]) -> Result<Self> {
        let (rest, spki) = SubjectPublicKeyInfo::from_der(spki_der)
            .map_err(|_| anyhow!("public key is not a valid SubjectPublicKeyInfo"))?;
        if !rest.is_empty() {
            return Err(anyhow!("trailing data after SubjectPublicKeyInfo"));
        }
        let modulus = match spki.parsed() {
            Ok(PublicKey::RSA(k)) => k.modulus,
            _ => return Err(anyhow!("not an RSA public key")),
        };
        let modulus_bits = true_modulus_bits(modulus)?;
        Ok(Self {
            pkcs1_der: spki.subject_public_key.data.to_vec(),
            modulus_bits,
        })
    }

    pub fn modulus_bits(&self) -> usize {
        self.modulus_bits
    }

    /// Modulus length in bytes (the required signature length).
    pub fn modulus_len(&self) -> usize {
        self.modulus_bits.div_ceil(8)
    }

    /// Verify an RSASSA-PKCS1-v1_5 SHA-256 signature (2048..=8192-bit keys).
    pub fn verify_pkcs1_sha256(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.pkcs1_der)
            .verify(msg, sig)
            .map_err(|_| anyhow!("RSA signature does not verify"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{
        pkcs1v15::SigningKey,
        pkcs8::EncodePublicKey,
        sha2::Sha256,
        signature::{SignatureEncoding, Signer},
        RsaPrivateKey,
    };

    fn pair(bits: usize) -> (RsaPrivateKey, RsaVerifyKey) {
        let sk = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).unwrap();
        let der = sk.to_public_key().to_public_key_der().unwrap();
        let k = RsaVerifyKey::from_spki_der(der.as_bytes()).unwrap();
        (sk, k)
    }

    fn sign(sk: &RsaPrivateKey, msg: &[u8]) -> Vec<u8> {
        SigningKey::<Sha256>::new(sk.clone()).sign(msg).to_vec()
    }

    #[test]
    fn verifies_2048_and_3072() {
        for bits in [2048usize, 3072] {
            let (sk, k) = pair(bits);
            assert_eq!(k.modulus_bits(), bits);
            assert_eq!(k.modulus_len(), bits / 8);
            let sig = sign(&sk, b"signed info");
            assert!(k.verify_pkcs1_sha256(b"signed info", &sig).is_ok());
            assert!(k.verify_pkcs1_sha256(b"tampered", &sig).is_err());
            assert!(k.verify_pkcs1_sha256(b"signed info", &sig[1..]).is_err());
        }
    }

    #[test]
    fn rejects_1024_bit_keys() {
        let (sk, k) = pair(1024);
        assert_eq!(k.modulus_bits(), 1024);
        assert!(k.verify_pkcs1_sha256(b"m", &sign(&sk, b"m")).is_err());
    }

    #[test]
    fn non_multiple_of_eight_moduli_verify_end_to_end() {
        for bits in [2049usize, 2055, 2056] {
            let (sk, k) = pair(bits);
            assert_eq!(k.modulus_bits(), bits);
            assert_eq!(k.modulus_len(), bits.div_ceil(8));
            let sig = sign(&sk, b"m");
            assert_eq!(sig.len(), k.modulus_len());
            assert!(k.verify_pkcs1_sha256(b"m", &sig).is_ok(), "{bits}");
        }
    }

    #[test]
    fn modulus_bit_counting_and_padding() {
        assert_eq!(
            true_modulus_bits(&[0x80, 1]).unwrap_err().to_string(),
            "negative RSA modulus"
        );
        assert_eq!(true_modulus_bits(&[0, 0x80, 1]).unwrap(), 16);
        assert_eq!(true_modulus_bits(&[0x01, 0xff]).unwrap(), 9);
        assert!(true_modulus_bits(&[0, 0x7f, 1]).is_err());
        assert!(true_modulus_bits(&[0, 0, 0x80]).is_err());
        assert!(true_modulus_bits(&[]).is_err());
        assert!(true_modulus_bits(&[0]).is_err());
    }

    #[test]
    fn padded_modulus_in_spki_is_rejected() {
        let (_, k) = pair(2048);
        // RSAPublicKey ::= SEQUENCE { INTEGER n, INTEGER e }; rebuild with an
        // extra leading zero on n and wrap in an rsaEncryption SPKI.
        let wrapped = spki_of(&k.pkcs1_der);
        let (_, spki) = SubjectPublicKeyInfo::from_der(&wrapped).unwrap();
        let PublicKey::RSA(r) = spki.parsed().unwrap() else {
            panic!()
        };
        let mut n = vec![0u8];
        n.extend_from_slice(r.modulus);
        let padded = spki_of(&pkcs1(&n, r.exponent));
        assert!(RsaVerifyKey::from_spki_der(&padded).is_err());
        assert!(RsaVerifyKey::from_spki_der(&spki_of(&pkcs1(r.modulus, r.exponent))).is_ok());
    }

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        match body.len() {
            n if n < 128 => v.push(n as u8),
            n if n < 256 => v.extend([0x81, n as u8]),
            n => v.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        v.extend_from_slice(body);
        v
    }

    fn pkcs1(n: &[u8], e: &[u8]) -> Vec<u8> {
        der(0x30, &[der(0x02, n), der(0x02, e)].concat())
    }

    fn spki_of(pkcs1_der: &[u8]) -> Vec<u8> {
        // AlgorithmIdentifier { rsaEncryption 1.2.840.113549.1.1.1, NULL }
        let alg = [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        let mut bits = vec![0u8];
        bits.extend_from_slice(pkcs1_der);
        der(0x30, &[alg.to_vec(), der(0x03, &bits)].concat())
    }

    #[test]
    fn rejects_non_rsa_and_garbage() {
        assert!(RsaVerifyKey::from_spki_der(b"garbage").is_err());
        let kp = rcgen::KeyPair::generate().unwrap(); // ECDSA P-256
        assert!(RsaVerifyKey::from_spki_der(&kp.public_key_der()).is_err());
    }
}
