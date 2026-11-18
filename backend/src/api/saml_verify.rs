//! SAML signature verification over the parsed [`SamlDoc`] tree.
//!
//! Verification and identity extraction share one parse (`saml_xml`), and
//! verification returns a [`VerifiedScope`] saying *which* element was
//! covered, so extraction can never read outside it.
//!
//! Policy:
//!   - A `ds:Signature` may appear only as a direct child of the root
//!     `samlp:Response` or of the single `saml:Assertion`; at most one under
//!     each; at least one overall. Every Signature present must verify.
//!   - Each Signature has exactly one `Reference`, whose URI is `#` plus the
//!     ID of the Signature's parent element.
//!   - Only exc-c14n (declared), RSA-SHA256 and SHA-256 are accepted; the
//!     only Transforms allowed are enveloped-signature and exc-c14n.
//!   - The key comes from the configured `SAML_IDP_CERT_PEM`; an embedded
//!     `X509Certificate`, if present, must equal it (cert pinning).
//!
//! ## Canonicalisation limitation
//!
//! Exclusive canonicalisation is NOT implemented (follow-up work). Digest
//! and signature are computed over the bytes exactly as they appeared on
//! the wire (with the enveloped Signature excised for the digest), so only
//! IdPs whose output is already canonical will verify; others fail closed.
//! Do not weaken verification to work around this; add a c14n step.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    sha2::Sha256,
    signature::Verifier,
    traits::PublicKeyParts,
    RsaPublicKey,
};
use sha2::{Digest, Sha256 as Sha256Hasher};
use std::collections::HashSet;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::api::saml_xml::{reject, tag, SamlDoc, NS_DSIG};

const ALG_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ALG_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ALG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// Smallest RSA modulus accepted for the IdP key.
const MIN_RSA_BITS: usize = 2048;

/// Supported SignatureMethod URIs: the single dispatch point for signing algorithms.
#[derive(Clone, Copy)]
enum SigAlg {
    RsaSha256,
}

impl SigAlg {
    fn from_uri(u: &str) -> Option<Self> {
        (u == ALG_RSA_SHA256).then_some(SigAlg::RsaSha256)
    }

    fn verify(self, key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> Result<()> {
        if sig.len() != key.size() {
            bail!("SignatureValue length does not match the key modulus");
        }
        let signature = Signature::try_from(sig).context("SignatureValue malformed")?;
        match self {
            SigAlg::RsaSha256 => VerifyingKey::<Sha256>::new(key.clone())
                .verify(msg, &signature)
                .context("RSA signature does not verify against SignedInfo"),
        }
    }
}

/// Supported DigestMethod URIs.
#[derive(Clone, Copy)]
enum DigestAlg {
    Sha256,
}

impl DigestAlg {
    fn from_uri(u: &str) -> Option<Self> {
        (u == ALG_SHA256).then_some(DigestAlg::Sha256)
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestAlg::Sha256 => Sha256Hasher::digest(data).to_vec(),
        }
    }
}

/// Which element a verified signature covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScopeKind {
    /// The whole `Response` (and so the Assertion inside it).
    #[default]
    Response,
    /// Only the `Assertion`; Response-level attributes are unauthenticated.
    Assertion,
}

/// Proof that the document was verified. Only this module can construct it.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedScope {
    pub kind: ScopeKind,
    _private: (),
}

/// Dev-only bypass: refuses in production under every configuration.
pub fn insecure_unverified_scope(is_production: bool) -> Result<VerifiedScope> {
    if is_production {
        bail!("signature verification cannot be skipped in production");
    }
    Ok(VerifiedScope {
        kind: ScopeKind::Response,
        _private: (),
    })
}

/// Verify every Signature in `doc` against the configured PEM.
pub fn verify_response(doc: &SamlDoc, idp_cert_pem: &str) -> Result<VerifiedScope> {
    let root = doc.root();
    let assertion = doc.assertion()?;
    let sigs: Vec<usize> = (0..doc.len())
        .filter(|&i| doc.is(i, NS_DSIG, "Signature"))
        .collect();
    if sigs.is_empty() {
        bail!("no Signature element");
    }
    let configured_b64 = strip_pem_armor(idp_cert_pem);
    let key = pinned_key(&configured_b64).map_err(|e| tag("cert", e))?;

    // Structural checks for every Signature before any verification.
    let mut parents = HashSet::new();
    let mut placed = Vec::new();
    for s in sigs {
        let parent = doc
            .node(s)
            .parent
            .filter(|&p| p == root || p == assertion)
            .ok_or_else(|| anyhow!("Signature is not a direct child of Response or Assertion"))?;
        if !parents.insert(parent) {
            bail!("more than one Signature under the same element");
        }
        placed.push((s, parent));
    }
    let mut response_signed = false;
    for (s, parent) in placed {
        verify_one(doc, s, parent, &key, &configured_b64)?;
        response_signed |= parent == root;
    }
    let kind = if response_signed {
        ScopeKind::Response
    } else {
        ScopeKind::Assertion
    };
    Ok(VerifiedScope { kind, _private: () })
}

/// Startup check for `SAML_IDP_CERT_PEM`: parses and enforces the key size.
pub fn validate_idp_cert(pem: &str) -> Result<()> {
    pinned_key(&strip_pem_armor(pem))
        .map(|_| ())
        .map_err(|e| tag("cert", e))
}

fn pinned_key(configured_b64: &str) -> Result<RsaPublicKey> {
    let der = B64
        .decode(configured_b64.as_bytes())
        .context("SAML_IDP_CERT_PEM not base64")?;
    let (_, cert) = X509Certificate::from_der(&der).context("SAML_IDP_CERT_PEM parse failed")?;
    let rsa_pub = RsaPublicKey::from_public_key_der(cert.public_key().raw)
        .context("certificate is not an RSA public key")?;
    check_key_size(&rsa_pub)?;
    Ok(rsa_pub)
}

fn check_key_size(key: &RsaPublicKey) -> Result<()> {
    if key.n().bits() < MIN_RSA_BITS {
        return Err(reject(
            "cert",
            format!("IdP RSA key is smaller than {MIN_RSA_BITS} bits"),
        ));
    }
    Ok(())
}

fn verify_one(
    doc: &SamlDoc,
    sig: usize,
    parent: usize,
    key: &RsaPublicKey,
    configured_b64: &str,
) -> Result<()> {
    let parent_id = doc
        .attr(parent, "ID")
        .ok_or_else(|| anyhow!("signed element has no ID"))?;
    let signed_info = doc.child_one(sig, NS_DSIG, "SignedInfo")?;
    let sig_value = doc.child_one(sig, NS_DSIG, "SignatureValue")?;

    let alg_uri = |i: usize, name: &str| -> Result<&str> {
        let m = doc.child_one(i, NS_DSIG, name)?;
        doc.attr(m, "Algorithm")
            .ok_or_else(|| anyhow!("{name} has no Algorithm"))
    };
    if alg_uri(signed_info, "CanonicalizationMethod")? != ALG_EXC_C14N {
        return Err(reject(
            "algorithm",
            "unsupported CanonicalizationMethod algorithm",
        ));
    }
    let sig_alg = SigAlg::from_uri(alg_uri(signed_info, "SignatureMethod")?)
        .ok_or_else(|| reject("algorithm", "unsupported SignatureMethod algorithm"))?;

    let reference = doc.child_one(signed_info, NS_DSIG, "Reference")?;
    if doc.attr(reference, "URI") != Some(format!("#{parent_id}").as_str()) {
        bail!("Reference URI does not point at the Signature's parent element");
    }
    let digest_alg = DigestAlg::from_uri(alg_uri(reference, "DigestMethod")?)
        .ok_or_else(|| reject("algorithm", "unsupported DigestMethod algorithm"))?;
    if let Some(transforms) = doc.child_opt(reference, NS_DSIG, "Transforms")? {
        for t in doc.children(transforms, NS_DSIG, "Transform") {
            match doc.attr(t, "Algorithm") {
                Some(ALG_ENVELOPED) | Some(ALG_EXC_C14N) => {}
                _ => return Err(reject("algorithm", "unsupported Transform algorithm")),
            }
        }
    }
    let digest_value = doc.child_one(reference, NS_DSIG, "DigestValue")?;

    // Cert pinning: an embedded certificate, if any, must be the configured one.
    let certs: Vec<usize> = doc
        .descendants(sig)
        .into_iter()
        .filter(|&i| doc.is(i, NS_DSIG, "X509Certificate"))
        .collect();
    if certs.len() > 1 {
        return Err(reject("cert", "more than one X509Certificate"));
    }
    if let Some(&c) = certs.first() {
        let embedded: String = doc.leaf_text(c)?.split_whitespace().collect();
        if embedded != configured_b64 {
            return Err(reject(
                "cert",
                "embedded X509Certificate does not match SAML_IDP_CERT_PEM",
            ));
        }
    }

    // Without c14n the signed bytes must carry every namespace binding they use.
    if !doc.namespaces_closed(parent, Some(sig)) || !doc.namespaces_closed(signed_info, None) {
        bail!("namespace declarations used by signed content are declared outside it");
    }

    // Digest over the parent with the enveloped Signature excised.
    let enveloped = doc.span_without(parent, sig);
    let computed = B64.encode(digest_alg.digest(enveloped.as_bytes()));
    let claimed: String = doc.leaf_text(digest_value)?.split_whitespace().collect();
    if computed != claimed {
        bail!("DigestValue does not match SHA-256 of the signed element");
    }

    let sig_b64: String = doc.leaf_text(sig_value)?.split_whitespace().collect();
    let sig_bytes = B64
        .decode(sig_b64.as_bytes())
        .context("SignatureValue not base64")?;
    sig_alg.verify(key, doc.span(signed_info).as_bytes(), &sig_bytes)?;
    Ok(())
}

/// Strip PEM armor lines and whitespace, returning the base64 body.
fn strip_pem_armor(pem: &str) -> String {
    pem.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .replace(['\n', '\r', ' ', '\t'], "")
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Signed-response builder shared by the verifier and ACS tests. Output
    //! is canonical-on-the-wire, which is all this module can verify.
    use super::*;
    use rsa::{
        pkcs1v15::SigningKey,
        pkcs8::EncodePrivateKey,
        signature::{SignatureEncoding, Signer},
        RsaPrivateKey,
    };
    use std::sync::OnceLock;

    pub const ACS: &str = "http://localhost:8080/auth/saml/acs";
    pub const SP: &str = "http://localhost:5173/saml/sp";

    pub fn key() -> &'static (String, RsaPrivateKey) {
        static K: OnceLock<(String, RsaPrivateKey)> = OnceLock::new();
        K.get_or_init(gen_cert)
    }

    pub fn gen_cert() -> (String, RsaPrivateKey) {
        gen_cert_bits(2048)
    }

    pub fn gen_rsa(bits: usize) -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).unwrap()
    }

    pub fn gen_cert_bits(bits: usize) -> (String, RsaPrivateKey) {
        let rsa = gen_rsa(bits);
        let pem = rsa
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        let kp =
            rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &rcgen::PKCS_RSA_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-idp");
        (params.self_signed(&kp).unwrap().pem(), rsa)
    }

    #[derive(Clone, Copy, PartialEq)]
    pub enum Layout {
        Assertion,
        Response,
        Both,
        Unsigned,
    }

    #[derive(Clone)]
    pub struct Fx {
        pub layout: Layout,
        pub issuer: String,
        pub name_id: String,
        pub audience: String,
        pub recipient: String,
        pub destination: Option<String>,
        pub status: String,
        pub cond_nb: String,
        pub cond_nooa: String,
        pub bearer_nooa: String,
        pub resp_irt: Option<String>,
        pub sub_irt: Option<String>,
    }

    impl Fx {
        pub fn new(layout: Layout) -> Self {
            Fx {
                layout,
                issuer: "idp".into(),
                name_id: "alice@example.com".into(),
                audience: SP.into(),
                recipient: ACS.into(),
                destination: Some(ACS.into()),
                status: "urn:oasis:names:tc:SAML:2.0:status:Success".into(),
                cond_nb: "2029-12-31T23:59:00Z".into(),
                cond_nooa: "2030-01-01T00:05:00Z".into(),
                bearer_nooa: "2030-01-01T00:05:00Z".into(),
                resp_irt: Some("_req1".into()),
                sub_irt: Some("_req1".into()),
            }
        }

        fn assertion(&self, sig: &str) -> String {
            let irt = self
                .sub_irt
                .as_ref()
                .map(|v| format!(r#" InResponseTo="{v}""#))
                .unwrap_or_default();
            format!(
                r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="AS1" Version="2.0" IssueInstant="2029-12-31T23:59:30Z"><saml:Issuer>{iss}</saml:Issuer>{sig}<saml:Subject><saml:NameID>{nm}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="{rcp}" NotOnOrAfter="{bn}"{irt}/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="mail"><saml:AttributeValue>{nm}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="displayName"><saml:AttributeValue>Alice Example</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#,
                iss = self.issuer,
                nm = self.name_id,
                rcp = self.recipient,
                bn = self.bearer_nooa,
                nb = self.cond_nb,
                na = self.cond_nooa,
                aud = self.audience,
            )
        }

        fn response(&self, sig: &str, assertion: &str) -> String {
            let dest = self
                .destination
                .as_ref()
                .map(|v| format!(r#" Destination="{v}""#))
                .unwrap_or_default();
            let irt = self
                .resp_irt
                .as_ref()
                .map(|v| format!(r#" InResponseTo="{v}""#))
                .unwrap_or_default();
            format!(
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="RS1" Version="2.0"{dest}{irt}>{sig}<samlp:Status><samlp:StatusCode Value="{st}"/></samlp:Status>{assertion}</samlp:Response>"#,
                st = self.status,
            )
        }

        pub fn build(&self) -> String {
            let (pem, rsa) = key();
            let assertion = match self.layout {
                Layout::Assertion | Layout::Both => {
                    let sig = signature("AS1", &self.assertion(""), pem, rsa);
                    self.assertion(&sig)
                }
                _ => self.assertion(""),
            };
            match self.layout {
                Layout::Response | Layout::Both => {
                    let sig = signature("RS1", &self.response("", &assertion), pem, rsa);
                    self.response(&sig, &assertion)
                }
                _ => self.response("", &assertion),
            }
        }
    }

    /// Enveloped Signature over `unsigned` (the parent with no Signature).
    pub fn signature(id: &str, unsigned: &str, cert_pem: &str, rsa: &RsaPrivateKey) -> String {
        let digest = B64.encode(Sha256Hasher::digest(unsigned.as_bytes()));
        let si = format!(
            r##"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#{id}"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>{digest}</DigestValue></Reference></SignedInfo>"##
        );
        let sv = B64.encode(
            SigningKey::<Sha256>::new(rsa.clone())
                .sign(si.as_bytes())
                .to_bytes(),
        );
        let cert = strip_pem_armor(cert_pem);
        format!(
            r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">{si}<SignatureValue>{sv}</SignatureValue><KeyInfo><X509Data><X509Certificate>{cert}</X509Certificate></X509Data></KeyInfo></Signature>"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn verify(xml: &str) -> Result<VerifiedScope> {
        verify_response(&SamlDoc::parse(xml)?, &key().0)
    }
    fn err(xml: &str) -> String {
        format!("{:#}", verify(xml).expect_err("must be rejected"))
    }
    fn built(l: Layout) -> String {
        Fx::new(l).build()
    }

    #[test]
    fn verifies_each_layout_with_right_scope() {
        assert_eq!(
            verify(&built(Layout::Assertion)).unwrap().kind,
            ScopeKind::Assertion
        );
        assert_eq!(
            verify(&built(Layout::Response)).unwrap().kind,
            ScopeKind::Response
        );
        assert_eq!(
            verify(&built(Layout::Both)).unwrap().kind,
            ScopeKind::Response
        );
    }

    #[test]
    fn poc_extra_unsigned_assertion_is_rejected() {
        let xml = built(Layout::Response).replace(
            "</samlp:Response>",
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="EVIL"><saml:Subject><saml:NameID>admin@victim.example</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#,
        );
        assert!(SamlDoc::parse(&xml).is_err());
        // Also when placed before the signed assertion and with Assertion-only signing.
        let xml = built(Layout::Assertion).replace(
            "<samlp:Status>",
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="EVIL"/><samlp:Status>"#,
        );
        assert!(SamlDoc::parse(&xml).is_err());
    }

    #[test]
    fn bare_identity_elements_outside_assertion_are_rejected() {
        for l in [Layout::Assertion, Layout::Response] {
            let xml = built(l).replace(
                "</samlp:Response>",
                r#"<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">admin@victim.example</saml:NameID></samlp:Response>"#,
            );
            assert!(SamlDoc::parse(&xml).is_err());
        }
    }

    #[test]
    fn signed_assertion_moved_into_wrapper_is_rejected() {
        let good = built(Layout::Assertion);
        let a0 = good.find("<saml:Assertion").unwrap();
        let a1 = good.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
        let signed = &good[a0..a1];
        let forged = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="EVIL"><saml:Subject><saml:NameID>admin@victim.example</saml:NameID></saml:Subject></saml:Assertion>"#;
        for wrap in ["Extensions", "Object", "Advice"] {
            let xml = format!(
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="RS1" Version="2.0"><{wrap}>{signed}</{wrap}>{forged}</samlp:Response>"#
            );
            // Count/placement rules reject it at parse; even if parse allowed it, verify would.
            assert!(SamlDoc::parse(&xml).is_err(), "{wrap}");
        }
        // Signed assertion under Advice inside the real (unsigned) one: parse rejects (2 Assertions).
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="RS1" Version="2.0"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="EVIL"><saml:Advice>{signed}</saml:Advice></saml:Assertion></samlp:Response>"#
        );
        assert!(SamlDoc::parse(&xml).is_err());
    }

    #[test]
    fn signature_not_direct_child_is_rejected() {
        let xml = built(Layout::Assertion).replace("<samlp:Status>", "<samlp:Extensions><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"/></samlp:Extensions><samlp:Status>");
        assert!(err(&xml).contains("not a direct child"));
        // Signature of the Response placed inside Status.
        let good = built(Layout::Response);
        let s0 = good.find("<Signature").unwrap();
        let s1 = good.find("</Signature>").unwrap() + "</Signature>".len();
        let sig = good[s0..s1].to_string();
        let moved = good
            .replace(&sig, "")
            .replace("<samlp:Status>", &format!("<samlp:Status>{sig}"));
        assert!(err(&moved).contains("not a direct child"));
    }

    #[test]
    fn reference_problems_are_rejected() {
        for (from, to) in [
            (r##"URI="#AS1""##, r##"URI="""##),
            (r##"URI="#AS1""##, r##"URI="#RS1""##),
            (r##"URI="#AS1""##, r##"URI="#nope""##),
        ] {
            assert!(err(&built(Layout::Assertion).replace(from, to)).contains("Reference URI"));
        }
        // Second Reference.
        let xml = built(Layout::Assertion)
            .replace("</SignedInfo>", r##"<Reference URI="#AS1"/></SignedInfo>"##);
        assert!(err(&xml).contains("duplicate Reference"));
    }

    #[test]
    fn duplicate_ids_and_two_signatures_are_rejected() {
        assert!(
            SamlDoc::parse(&built(Layout::Assertion).replace(r#"ID="RS1""#, r#"ID="AS1""#))
                .is_err()
        );
        let good = built(Layout::Assertion);
        let s0 = good.find("<Signature").unwrap();
        let s1 = good.find("</Signature>").unwrap() + "</Signature>".len();
        let sig = good[s0..s1].to_string();
        let dup = good.replace(&sig, &format!("{sig}{sig}"));
        assert!(err(&dup).contains("more than one Signature"));
    }

    #[test]
    fn unsupported_algorithms_are_rejected() {
        for (from, to, want) in [
            ("xmlenc#sha256", "xmlenc#sha512", "DigestMethod"),
            ("rsa-sha256", "rsa-sha1", "SignatureMethod"),
            (
                "xml-exc-c14n#\"",
                "REC-xml-c14n-20010315\"",
                "CanonicalizationMethod",
            ),
            ("xmldsig#enveloped-signature", "xmldsig#base64", "Transform"),
        ] {
            assert!(
                err(&built(Layout::Assertion).replace(from, to)).contains(want),
                "{from}"
            );
        }
    }

    #[test]
    fn tampering_and_pinning_are_rejected() {
        let xml = built(Layout::Assertion).replace(
            ">alice@example.com</saml:NameID>",
            ">evil@example.com</saml:NameID>",
        );
        assert!(err(&xml).contains("DigestValue"));
        let (other, _) = gen_cert();
        let e = format!(
            "{:#}",
            verify_response(&SamlDoc::parse(&built(Layout::Assertion)).unwrap(), &other)
                .unwrap_err()
        );
        assert!(e.contains("does not match SAML_IDP_CERT_PEM"), "{e}");
        assert!(err(&built(Layout::Unsigned)).contains("no Signature"));
    }

    #[test]
    fn comment_inside_nameid_is_rejected() {
        let xml = built(Layout::Assertion).replace(
            "alice@example.com</saml:NameID>",
            "a@b<!-- -->.evil</saml:NameID>",
        );
        assert!(SamlDoc::parse(&xml).is_err());
    }

    #[test]
    fn dev_bypass_refuses_in_production() {
        assert!(insecure_unverified_scope(true).is_err());
        assert_eq!(
            insecure_unverified_scope(false).unwrap().kind,
            ScopeKind::Response
        );
    }

    const P: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
    const A: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

    /// Assertion signed with the given unsigned/signed-body split; namespaces
    /// are declared by the caller on the Response only.
    fn ns_outside(root_decls: &str, open: &str, body: &str, close: &str) -> String {
        let (pem, rsa) = key();
        let unsigned = format!("{open}{body}{close}");
        let sig = signature("AS1", &unsigned, pem, rsa);
        format!(
            r#"<samlp:Response xmlns:samlp="{P}" {root_decls} ID="RS1">{open}{sig}{body}{close}</samlp:Response>"#
        )
    }

    #[test]
    fn namespaces_declared_outside_signed_span_are_rejected() {
        // Prefix declared on the Response only (so it could be rebound without changing the digest).
        let xml = ns_outside(
            &format!(r#"xmlns:saml="{A}""#),
            r#"<saml:Assertion ID="AS1">"#,
            "<saml:Subject><saml:NameID>admin@victim.example</saml:NameID></saml:Subject>",
            "</saml:Assertion>",
        );
        assert!(err(&xml).contains("declared outside"));
        // Default namespace on the Response turning bare elements into SAML elements.
        let xml = ns_outside(
            &format!(r#"xmlns="{A}""#),
            r#"<Assertion ID="AS1">"#,
            "<Subject><NameID>admin@victim.example</NameID></Subject>",
            "</Assertion>",
        );
        assert!(err(&xml).contains("declared outside"));
        // Same shape with the declaration inside the signed element verifies.
        let (pem, rsa) = key();
        let open = format!(r#"<saml:Assertion xmlns:saml="{A}" ID="AS1">"#);
        let body = "<saml:Subject><saml:NameID>a@b.c</saml:NameID></saml:Subject>";
        let unsigned = format!("{open}{body}</saml:Assertion>");
        let sig = signature("AS1", &unsigned, pem, rsa);
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="{P}" ID="RS1">{open}{sig}{body}</saml:Assertion></samlp:Response>"#
        );
        assert!(verify(&xml).is_ok());
    }

    #[test]
    fn signed_assertion_alone_inside_wrappers_is_rejected() {
        let good = built(Layout::Assertion);
        let a0 = good.find("<saml:Assertion").unwrap();
        let a1 = good.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
        let signed = &good[a0..a1];
        for wrap in [
            r#"<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            "<samlp:Extensions>",
            "<saml:Advice xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">",
        ] {
            let close = format!("</{}>", wrap[1..].split([' ', '>']).next().unwrap());
            let xml = format!(
                r#"<samlp:Response xmlns:samlp="{P}" ID="RS1" Version="2.0">{wrap}{signed}{close}</samlp:Response>"#
            );
            // Rejected at parse (Assertion not a direct child of Response) before any verification.
            let e = SamlDoc::parse(&xml)
                .and_then(|d| verify_response(&d, &key().0))
                .unwrap_err();
            assert!(
                format!("{e:#}").contains("not a direct child of Response"),
                "{wrap}: {e:#}"
            );
        }
    }

    #[test]
    fn weak_rsa_key_is_rejected() {
        // rcgen cannot issue a certificate for a 1024-bit key, so test the size gate directly.
        let weak = gen_rsa(1024);
        let e = format!("{:#}", check_key_size(&weak.to_public_key()).unwrap_err());
        assert!(e.contains("smaller than 2048"), "{e}");
        assert!(check_key_size(&key().1.to_public_key()).is_ok());
        assert!(validate_idp_cert(&key().0).is_ok());
    }
}
