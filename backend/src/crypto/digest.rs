//! SHA-2 digests (SHA-256, SHA-384, SHA-512).

use aws_lc_rs::digest::{self, Context, SHA256, SHA384, SHA512};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&SHA256, data).as_ref());
    out
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(digest::digest(&SHA384, data).as_ref());
    out
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(digest::digest(&SHA512, data).as_ref());
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

pub fn sha512_hex(data: &[u8]) -> String {
    hex::encode(sha512(data))
}

/// Incremental SHA-256.
pub struct Sha256Stream(Context);

impl Sha256Stream {
    pub fn new() -> Self {
        Self(Context::new(&SHA256))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finish(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.finish().as_ref());
        out
    }
}

impl Default for Sha256Stream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    // Published FIPS 180-4 vectors for "abc".
    #[test]
    fn known_answers() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha512_hex(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn matches_rustcrypto_on_varied_lengths() {
        for len in [0usize, 1, 55, 56, 64, 111, 112, 128, 1000, 1 << 20] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            assert_eq!(sha256(&data).as_slice(), Sha256::digest(&data).as_slice());
            assert_eq!(sha512(&data).as_slice(), Sha512::digest(&data).as_slice());
            assert_eq!(sha384(&data).as_slice(), Sha384::digest(&data).as_slice());
        }
    }

    #[test]
    fn stream_matches_one_shot() {
        let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let mut s = Sha256Stream::new();
        for c in data.chunks(777) {
            s.update(c);
        }
        assert_eq!(s.finish(), sha256(&data));
        assert_eq!(Sha256Stream::default().finish(), sha256(b""));
    }
}
