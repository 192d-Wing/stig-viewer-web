//! HMAC-SHA-256 and HMAC-SHA-384.

use aws_lc_rs::hmac::{self, HMAC_SHA256, HMAC_SHA384};

/// HMAC-SHA-256 of `msg` under `key`. Any key length is accepted.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(HMAC_SHA256, key);
    let mut out = [0u8; 32];
    out.copy_from_slice(hmac::sign(&key, msg).as_ref());
    out
}

/// HMAC-SHA-384 of `msg` under `key`. Any key length is accepted.
pub fn hmac_sha384(key: &[u8], msg: &[u8]) -> [u8; 48] {
    let key = hmac::Key::new(HMAC_SHA384, key);
    let mut out = [0u8; 48];
    out.copy_from_slice(hmac::sign(&key, msg).as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384};

    // RFC 4231 test case 2 (published vector).
    #[test]
    fn rfc4231_case_2() {
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn matches_rustcrypto_for_varied_key_lengths() {
        for klen in [0usize, 1, 14, 32, 64, 65, 200] {
            let key: Vec<u8> = (0..klen).map(|i| (i * 13 + 5) as u8).collect();
            for msg in [&b""[..], b"x", &[7u8; 5000][..]] {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
                m.update(msg);
                assert_eq!(
                    hmac_sha256(&key, msg).as_slice(),
                    m.finalize().into_bytes().as_slice()
                );
            }
        }
    }

    // RFC 4231 test case 2 (published vector), HMAC-SHA-384.
    #[test]
    fn rfc4231_case_2_sha384() {
        assert_eq!(
            hex::encode(hmac_sha384(b"Jefe", b"what do ya want for nothing?")),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        );
    }

    // RFC 4231 test case 1 (published vector), HMAC-SHA-384.
    #[test]
    fn rfc4231_case_1_sha384() {
        assert_eq!(
            hex::encode(hmac_sha384(&[0x0b; 20], b"Hi There")),
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
        );
    }

    #[test]
    fn sha384_matches_rustcrypto_for_varied_key_lengths() {
        for klen in [0usize, 1, 14, 48, 128, 129, 200] {
            let key: Vec<u8> = (0..klen).map(|i| (i * 13 + 5) as u8).collect();
            for msg in [&b""[..], b"x", &[7u8; 5000][..]] {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(&key).unwrap();
                m.update(msg);
                assert_eq!(
                    hmac_sha384(&key, msg).as_slice(),
                    m.finalize().into_bytes().as_slice()
                );
            }
        }
    }
}
