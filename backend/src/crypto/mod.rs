//! Application-level cryptography (#65).
//!
//! The only module (besides the `fips.rs` probe) that names `aws_lc_rs`. Every
//! Ed25519 sign/verify, HMAC-SHA-256, SHA-256/512 digest, SAML RSA PKCS#1 v1.5
//! verification and security-relevant random value in this crate goes through
//! here, so a `--no-default-features --features fips` binary runs them inside the AWS-LC FIPS module.
//! Without `fips` the same code runs on the non-FIPS `aws-lc-sys` and makes no
//! FIPS claim.

pub mod digest;
pub mod ed25519;
pub mod hmac;
pub mod rand;
pub mod rsa;

/// True when the primitives *this application calls directly* (Ed25519, HMAC,
/// SHA-2, SAML RSA verify, RNG) run inside the AWS-LC FIPS module, i.e. the
/// binary was built with `--no-default-features --features fips`. It does not cover crypto done by
/// dependencies: TLS (rustls on ring), OIDC ID-token verification and
/// state/nonce generation (openidconnect, RustCrypto) and Postgres SCRAM
/// (sqlx); see [`crate::fips::OUTSIDE_MODULE`].
pub const fn app_primitives_in_module() -> bool {
    cfg!(feature = "fips")
}
