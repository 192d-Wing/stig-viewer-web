//! Random values from the AWS-LC DRBG (the module DRBG under `fips`). A
//! failure is an error; there is no fallback source.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

#[derive(Debug)]
pub struct RandError;

impl std::fmt::Display for RandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("random number generator failure")
    }
}

impl std::error::Error for RandError {}

pub fn fill(buf: &mut [u8]) -> Result<(), RandError> {
    SystemRandom::new().fill(buf).map_err(|_| RandError)
}

/// Fallible v4 UUID (version and variant bits set by `uuid`).
pub fn try_uuid_v4() -> Result<uuid::Uuid, RandError> {
    let mut b = [0u8; 16];
    fill(&mut b)?;
    Ok(uuid::Builder::from_random_bytes(b).into_uuid())
}

/// v4 UUID from the module DRBG. A DRBG failure is unrecoverable (the process
/// cannot mint an unpredictable identifier), so this panics rather than fall
/// back to a weaker source; the router's `CatchPanicLayer` turns a panic in
/// a request into a 500.
pub fn uuid_v4() -> uuid::Uuid {
    match try_uuid_v4() {
        Ok(u) => u,
        Err(e) => panic!("{e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v4_has_version_and_variant() {
        let u = uuid_v4();
        assert_eq!(u.get_version_num(), 4);
        assert_eq!(u.get_variant(), uuid::Variant::RFC4122);
        assert_ne!(u, uuid_v4());
    }

    #[test]
    fn fill_overwrites_the_buffer() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }
}
