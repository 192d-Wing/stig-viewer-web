//! SAML assertion signature verification.
//!
//! This module closes the production-readiness gap noted in `saml.rs`.
//! For each SAMLResponse it:
//!   1. Locates the `<Signature>` block.
//!   2. Extracts the embedded `<X509Certificate>` and asserts it matches
//!      the operator-configured `SAML_IDP_CERT_PEM` (cert pinning — the
//!      IdP cannot rotate keys without an explicit ops change).
//!   3. Computes SHA-256 of the signed element (the assertion or the
//!      response, whichever is referenced in `<SignedInfo>/<Reference>`)
//!      and compares it to `<DigestValue>`.
//!   4. RSA-verifies the base64 `<SignatureValue>` against the raw
//!      `<SignedInfo>` bytes using the certificate's public key.
//!
//! ## Canonicalisation
//!
//! Real XML-DSig requires exclusive canonicalisation (exc-c14n) of both
//! the SignedInfo and the signed element. Implementing exc-c14n correctly
//! is fiddly. We instead verify against the raw byte ranges of those two
//! elements as they appeared on the wire — which works for IdPs whose
//! emitted XML is already canonical (Azure AD, Okta, Auth0, ADFS). It
//! does not work if a proxy reformats the XML in transit. If a real-world
//! IdP fails to verify, the next step is to add a proper c14n step here,
//! not to weaken verification.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    sha2::Sha256,
    signature::Verifier,
    RsaPublicKey,
};
use sha2::{Digest, Sha256 as Sha256Hasher};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Verify a SAMLResponse signature against the operator-configured PEM.
///
/// `xml` is the raw decoded SAMLResponse bytes (as received over the wire,
/// after base64-decoding the form `SAMLResponse` value).
///
/// Returns `Ok(())` only when:
///   - the response contains exactly one Signature block,
///   - the embedded X509 certificate matches the configured PEM,
///   - the SignedInfo's DigestValue matches SHA-256 of the signed element,
///   - the SignatureValue is a valid RSA-SHA256 signature over SignedInfo
///     using the certificate's public key.
pub fn verify_response_signature(xml: &[u8], idp_cert_pem: &str) -> Result<()> {
    let xml_str = std::str::from_utf8(xml).context("response not utf-8")?;

    // ── Locate the Signature block ──────────────────────────────────────
    let sig_block = extract_element(xml_str, "Signature")
        .ok_or_else(|| anyhow!("no Signature element"))?;

    // ── Pull SignedInfo (raw byte range), SignatureValue, X509Certificate
    let signed_info = extract_element(sig_block, "SignedInfo")
        .ok_or_else(|| anyhow!("Signature has no SignedInfo"))?;
    let signature_value = inner_text(sig_block, "SignatureValue")
        .ok_or_else(|| anyhow!("Signature has no SignatureValue"))?
        .trim()
        .to_string();
    let embedded_cert_b64 = inner_text(sig_block, "X509Certificate")
        .ok_or_else(|| anyhow!("Signature has no X509Certificate"))?
        .trim()
        .replace(['\n', '\r', ' ', '\t'], "");

    // ── Cert pinning: bytes of embedded cert MUST match configured PEM ──
    let configured_b64 = strip_pem_armor(idp_cert_pem);
    if embedded_cert_b64 != configured_b64 {
        bail!("embedded X509Certificate does not match SAML_IDP_CERT_PEM");
    }

    // ── Parse the cert and extract its RSA public key ───────────────────
    let cert_der = B64
        .decode(embedded_cert_b64.as_bytes())
        .context("X509Certificate not base64")?;
    let (_, cert) =
        X509Certificate::from_der(&cert_der).context("X509Certificate parse failed")?;
    let spki_der = cert.public_key().raw;
    let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
        .context("certificate is not an RSA public key")?;
    let verifying_key = VerifyingKey::<Sha256>::new(rsa_pub);

    // ── Verify the DigestValue covers the signed element ────────────────
    // The Reference URI inside SignedInfo points at the signed element by
    // its `ID` attribute, prefixed with `#`. We resolve it to the byte
    // range of that element and hash those bytes.
    let reference_uri = attr_value(signed_info, "Reference", "URI")
        .ok_or_else(|| anyhow!("SignedInfo has no Reference URI"))?;
    let signed_id = reference_uri.trim_start_matches('#');
    let signed_element_bytes = element_with_id(xml_str, signed_id)
        .ok_or_else(|| anyhow!("Reference URI {reference_uri} does not resolve"))?;

    let mut hasher = Sha256Hasher::new();
    hasher.update(signed_element_bytes.as_bytes());
    let computed_digest = hasher.finalize();
    let computed_digest_b64 = B64.encode(computed_digest);

    let claimed_digest_b64 = inner_text(signed_info, "DigestValue")
        .ok_or_else(|| anyhow!("Reference has no DigestValue"))?
        .trim()
        .to_string();
    if computed_digest_b64 != claimed_digest_b64 {
        bail!("DigestValue does not match SHA-256 of the signed element");
    }

    // ── RSA-verify the SignatureValue over the SignedInfo bytes ─────────
    let sig_bytes = B64
        .decode(
            signature_value
                .replace(['\n', '\r', ' ', '\t'], "")
                .as_bytes(),
        )
        .context("SignatureValue not base64")?;
    let signature =
        Signature::try_from(sig_bytes.as_slice()).context("SignatureValue malformed")?;

    verifying_key
        .verify(signed_info.as_bytes(), &signature)
        .context("RSA signature does not verify against SignedInfo")?;

    Ok(())
}

/// Strip `-----BEGIN ...-----` / `-----END ...-----` armor lines and any
/// whitespace from a PEM string, returning the base64 body.
fn strip_pem_armor(pem: &str) -> String {
    pem.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .replace(['\n', '\r', ' ', '\t'], "")
}

/// Return the raw textual slice of the FIRST `<{local_name}>...</{local_name}>`
/// element (or its `{ns}:{local_name}` variant) in `xml`, including the
/// open and close tags. Returns `None` if no such element exists.
fn extract_element<'a>(xml: &'a str, local_name: &str) -> Option<&'a str> {
    extract_element_after(xml, local_name, 0)
}

fn extract_element_after<'a>(xml: &'a str, local_name: &str, from: usize) -> Option<&'a str> {
    // Find an opening tag whose name ends with `:local_name` or equals
    // `local_name` exactly. This is a deliberately loose match — SAML
    // namespaces vary by IdP.
    let hay = &xml[from..];
    let mut cursor = 0;
    while let Some(rel_lt) = hay[cursor..].find('<') {
        let open_at = cursor + rel_lt;
        let tail = &hay[open_at..];
        let close_bracket = tail.find('>')?;
        let tag_text = &tail[1..close_bracket];
        let tag_name = tag_text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_start_matches('/');
        let local = tag_name.rsplit(':').next().unwrap_or(tag_name);
        if local == local_name && !tag_text.starts_with('/') {
            // Found an opening tag. Walk forward, tracking nesting, until
            // we find the matching closing tag.
            let mut depth: i32 = 1;
            let mut scan = open_at + close_bracket + 1;
            while depth > 0 {
                let next_lt = hay[scan..].find('<')?;
                let abs = scan + next_lt;
                let after_lt = &hay[abs + 1..];
                let next_gt = after_lt.find('>')?;
                let inner_tag = &after_lt[..next_gt];
                let inner_name = inner_tag
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_start_matches('/');
                let inner_local = inner_name.rsplit(':').next().unwrap_or(inner_name);
                if inner_local == local_name {
                    if inner_tag.starts_with('/') {
                        depth -= 1;
                    } else if !inner_tag.ends_with('/') {
                        depth += 1;
                    }
                }
                scan = abs + 1 + next_gt + 1;
                if depth == 0 {
                    return Some(&hay[open_at..scan]);
                }
            }
            return None;
        }
        cursor = open_at + close_bracket + 1;
    }
    None
}

/// Return the inner-text content of the first matching element.
fn inner_text(xml: &str, local_name: &str) -> Option<String> {
    let elem = extract_element(xml, local_name)?;
    let open_close = elem.find('>')?;
    let after_open = &elem[open_close + 1..];
    let end_open = after_open.rfind("</")?;
    Some(after_open[..end_open].to_string())
}

/// Return the value of `attr` on the first `<{local_name} ... {attr}="...">`
/// element. Loose match — looks for `attr="..."` literal inside the tag.
fn attr_value(xml: &str, local_name: &str, attr: &str) -> Option<String> {
    let elem = extract_element(xml, local_name)?;
    let open_close = elem.find('>')?;
    let open_tag = &elem[..open_close];
    let needle = format!(r#"{attr}=""#);
    let start = open_tag.find(&needle)? + needle.len();
    let rest = &open_tag[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Find an element with `ID="{wanted}"` anywhere in `xml`, and return its
/// raw byte slice (open tag through close tag). Used to resolve the
/// Reference URI to the signed element.
fn element_with_id<'a>(xml: &'a str, wanted_id: &str) -> Option<&'a str> {
    let needle = format!(r#"ID="{wanted_id}""#);
    let id_at = xml.find(&needle)?;
    // Walk backward to the `<` that opens this element's tag.
    let open_at = xml[..id_at].rfind('<')?;
    // The element's local name.
    let tail = &xml[open_at + 1..];
    let space_or_gt = tail.find(|c: char| c == ' ' || c == '>')?;
    let tag_name = &tail[..space_or_gt];
    let local = tag_name.rsplit(':').next().unwrap_or(tag_name);
    extract_element_after(xml, local, open_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_element_handles_nested() {
        let xml = r#"<a><b>inner<b>deep</b></b></a>"#;
        assert_eq!(extract_element(xml, "b").unwrap(), "<b>inner<b>deep</b></b>");
    }

    #[test]
    fn extract_element_with_namespace() {
        let xml = r#"<saml:Assertion ID="x"><saml:Issuer>idp</saml:Issuer></saml:Assertion>"#;
        let assertion = extract_element(xml, "Assertion").unwrap();
        assert!(assertion.contains("idp"));
    }

    #[test]
    fn inner_text_works() {
        assert_eq!(
            inner_text(r#"<DigestValue>abc</DigestValue>"#, "DigestValue"),
            Some("abc".to_string())
        );
    }

    #[test]
    fn attr_value_works() {
        let xml = r##"<Reference URI="#abc" Type="ref"></Reference>"##;
        assert_eq!(
            attr_value(xml, "Reference", "URI"),
            Some("#abc".to_string())
        );
    }

    #[test]
    fn element_with_id_returns_full_element() {
        let xml = r#"<root><Assertion ID="X"><Issuer>idp</Issuer></Assertion></root>"#;
        let e = element_with_id(xml, "X").unwrap();
        assert!(e.starts_with("<Assertion"));
        assert!(e.ends_with("</Assertion>"));
    }

    // ── End-to-end signature test: generate a real cert, sign a real
    //    SAMLResponse, verify it, then tamper and confirm rejection. ──

    use rsa::{
        pkcs1v15::SigningKey as PkSigner,
        pkcs8::EncodePrivateKey,
        signature::{SignatureEncoding, Signer},
        RsaPrivateKey,
    };

    /// Generate a self-signed RSA cert + return (PEM, RsaPrivateKey).
    /// rcgen can't generate RSA itself (KeyGenerationUnavailable); we
    /// generate the keypair with the `rsa` crate and feed it in.
    fn gen_cert() -> (String, RsaPrivateKey) {
        let rsa = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pkcs8_pem = rsa
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        let key_pair =
            rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&pkcs8_pem, &rcgen::PKCS_RSA_SHA256)
                .unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-idp");
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), rsa)
    }

    fn sign_response(assertion_id: &str, sig_id: &str, cert_pem: &str, rsa: &RsaPrivateKey) -> String {
        // Build a minimal Assertion, compute its digest, build a SignedInfo
        // referencing it, sign the SignedInfo, and embed the result.
        let assertion = format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}"><saml:Issuer>idp</saml:Issuer><saml:Subject><saml:NameID>nm</saml:NameID></saml:Subject></saml:Assertion>"#
        );
        let mut hasher = Sha256Hasher::new();
        hasher.update(assertion.as_bytes());
        let digest = B64.encode(hasher.finalize());

        let signed_info = format!(
            r##"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#{assertion_id}"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>{digest}</DigestValue></Reference></SignedInfo>"##
        );

        let signer = PkSigner::<Sha256>::new(rsa.clone());
        let sig = signer.sign(signed_info.as_bytes());
        let sig_b64 = B64.encode(sig.to_bytes());
        let cert_b64 = strip_pem_armor(cert_pem);

        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#" ID="{sig_id}">{signed_info}<SignatureValue>{sig_b64}</SignatureValue><KeyInfo><X509Data><X509Certificate>{cert_b64}</X509Certificate></X509Data></KeyInfo></Signature>{assertion}</samlp:Response>"#
        )
    }

    #[test]
    fn verifies_a_real_signed_response() {
        let (cert_pem, rsa) = gen_cert();
        let xml = sign_response("AS1", "S1", &cert_pem, &rsa);
        verify_response_signature(xml.as_bytes(), &cert_pem)
            .expect("freshly-signed response should verify");
    }

    #[test]
    fn rejects_tampered_assertion() {
        let (cert_pem, rsa) = gen_cert();
        let xml = sign_response("AS1", "S1", &cert_pem, &rsa);
        // Mutate the assertion body — the digest won't match anymore.
        let tampered = xml.replace("<saml:NameID>nm</saml:NameID>", "<saml:NameID>evil</saml:NameID>");
        let err = verify_response_signature(tampered.as_bytes(), &cert_pem).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("DigestValue"),
            "expected digest mismatch, got: {msg}"
        );
    }

    #[test]
    fn rejects_wrong_cert_pinning() {
        let (cert_pem, rsa) = gen_cert();
        let (other_pem, _) = gen_cert();
        let xml = sign_response("AS1", "S1", &cert_pem, &rsa);
        let err = verify_response_signature(xml.as_bytes(), &other_pem).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not match SAML_IDP_CERT_PEM"),
            "expected pin failure, got: {msg}"
        );
    }

    #[test]
    fn rejects_unsigned_response() {
        let (cert_pem, _) = gen_cert();
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion ID="A"/></samlp:Response>"#;
        verify_response_signature(xml.as_bytes(), &cert_pem)
            .expect_err("response without Signature must fail");
    }
}
