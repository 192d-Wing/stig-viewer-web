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
//!   - Accepted algorithms: exclusive canonicalisation (`xml-exc-c14n#` and
//!     `#WithComments`, which are identical because the parser rejects
//!     comments), RSA PKCS#1 v1.5 with SHA-256/384/512 (any pairing with
//!     the SHA-256/384/512 digest). SHA-1, PSS and ECDSA are rejected.
//!   - Each Reference must carry exactly two Transforms, in order: the
//!     enveloped-signature transform, then exclusive canonicalisation
//!     (XML-DSig would otherwise default to inclusive C14N 1.0, which is not
//!     implemented). An `InclusiveNamespaces` `PrefixList` (at most 16
//!     prefixes) is honoured on the CanonicalizationMethod and the Transform.
//!   - The key comes from the configured `SAML_IDP_CERT_PEM`; an embedded
//!     `X509Certificate`, if present, must equal it (cert pinning).
//!
//! ## Canonicalisation
//!
//! Digest and signature are computed over the exclusive canonical form
//! (`saml_c14n`) of the parsed tree, so IdP output that is not already
//! canonical on the wire (indentation, quote style, attribute order,
//! `<x/>` versus `<x></x>`, CDATA, CRLF) verifies. The canonical bytes are
//! serialised from the same nodes that `saml::extract` reads, so a namespace
//! rebinding on an ancestor changes the digest rather than being ignored.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::HashSet;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::api::saml_c14n::{canonicalize, NS_EXC_C14N};
use crate::api::saml_xml::{reject, tag, SamlDoc, NS_DSIG};
use crate::crypto::{self, rsa::RsaVerifyKey};

const ALG_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ALG_EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const ALG_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ALG_RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
const ALG_RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const ALG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const ALG_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const ALG_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

/// Most prefixes accepted in an `InclusiveNamespaces` `PrefixList`.
const MAX_PREFIX_LIST: usize = 16;

/// Smallest RSA modulus accepted for the IdP key.
const MIN_RSA_BITS: usize = 2048;

/// Supported SignatureMethod URIs: the single dispatch point for signing algorithms.
#[derive(Clone, Copy)]
enum SigAlg {
    RsaSha256,
    RsaSha384,
    RsaSha512,
}

impl SigAlg {
    fn from_uri(u: &str) -> Option<Self> {
        match u {
            ALG_RSA_SHA256 => Some(SigAlg::RsaSha256),
            ALG_RSA_SHA384 => Some(SigAlg::RsaSha384),
            ALG_RSA_SHA512 => Some(SigAlg::RsaSha512),
            _ => None,
        }
    }

    fn verify(self, key: &RsaVerifyKey, msg: &[u8], sig: &[u8]) -> Result<()> {
        if sig.len() != key.modulus_len() {
            bail!("SignatureValue length does not match the key modulus");
        }
        match self {
            SigAlg::RsaSha256 => key
                .verify_pkcs1_sha256(msg, sig)
                .context("RSA signature does not verify against SignedInfo"),
            SigAlg::RsaSha384 => key
                .verify_pkcs1_sha384(msg, sig)
                .context("RSA signature does not verify against SignedInfo"),
            SigAlg::RsaSha512 => key
                .verify_pkcs1_sha512(msg, sig)
                .context("RSA signature does not verify against SignedInfo"),
        }
    }
}

/// Supported DigestMethod URIs.
#[derive(Clone, Copy)]
enum DigestAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlg {
    fn from_uri(u: &str) -> Option<Self> {
        match u {
            ALG_SHA256 => Some(DigestAlg::Sha256),
            ALG_SHA384 => Some(DigestAlg::Sha384),
            ALG_SHA512 => Some(DigestAlg::Sha512),
            _ => None,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestAlg::Sha256 => crypto::digest::sha256(data).to_vec(),
            DigestAlg::Sha384 => crypto::digest::sha384(data).to_vec(),
            DigestAlg::Sha512 => crypto::digest::sha512(data).to_vec(),
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

fn pinned_key(configured_b64: &str) -> Result<RsaVerifyKey> {
    let der = B64
        .decode(configured_b64.as_bytes())
        .context("SAML_IDP_CERT_PEM not base64")?;
    let (_, cert) = X509Certificate::from_der(&der).context("SAML_IDP_CERT_PEM parse failed")?;
    let rsa_pub = RsaVerifyKey::from_spki_der(cert.public_key().raw)
        .context("certificate is not an RSA public key")?;
    check_key_size(&rsa_pub)?;
    Ok(rsa_pub)
}

fn check_key_size(key: &RsaVerifyKey) -> Result<()> {
    if key.modulus_bits() < MIN_RSA_BITS {
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
    key: &RsaVerifyKey,
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
    if !is_exc_c14n(alg_uri(signed_info, "CanonicalizationMethod")?) {
        return Err(reject(
            "algorithm",
            "unsupported CanonicalizationMethod algorithm",
        ));
    }
    let si_prefixes = c14n_params(
        doc,
        doc.child_one(signed_info, NS_DSIG, "CanonicalizationMethod")?,
    )?;
    let sig_alg = SigAlg::from_uri(alg_uri(signed_info, "SignatureMethod")?)
        .ok_or_else(|| reject("algorithm", "unsupported SignatureMethod algorithm"))?;

    let reference = doc.child_one(signed_info, NS_DSIG, "Reference")?;
    if doc.attr(reference, "URI") != Some(format!("#{parent_id}").as_str()) {
        bail!("Reference URI does not point at the Signature's parent element");
    }
    let digest_alg = DigestAlg::from_uri(alg_uri(reference, "DigestMethod")?)
        .ok_or_else(|| reject("algorithm", "unsupported DigestMethod algorithm"))?;
    // Exactly [enveloped-signature, exc-c14n], in that order. XML-DSig
    // defaults to inclusive C14N 1.0 when no canonicalisation transform is
    // listed, which is not implemented, so that must not be accepted.
    let transforms = doc
        .child_opt(reference, NS_DSIG, "Transforms")?
        .ok_or_else(|| reject("algorithm", "Reference has no Transforms"))?;
    let tkids = &doc.node(transforms).children;
    if tkids.len() != 2 || tkids.iter().any(|&t| !doc.is(t, NS_DSIG, "Transform")) {
        return Err(reject(
            "algorithm",
            "Transforms must be enveloped-signature then exc-c14n",
        ));
    }
    if doc.attr(tkids[0], "Algorithm") != Some(ALG_ENVELOPED)
        || !doc.node(tkids[0]).children.is_empty()
        || !doc.attr(tkids[1], "Algorithm").is_some_and(is_exc_c14n)
    {
        return Err(reject(
            "algorithm",
            "Transforms must be enveloped-signature then exc-c14n",
        ));
    }
    let ref_prefixes = c14n_params(doc, tkids[1])?;
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

    // Digest over the canonical parent with the enveloped Signature omitted.
    let canon = canonicalize(doc, parent, Some(sig), &ref_prefixes)?;
    let computed = digest_alg.digest(&canon);
    let claimed = B64
        .decode(
            doc.leaf_text(digest_value)?
                .split_whitespace()
                .collect::<String>()
                .as_bytes(),
        )
        .context("DigestValue not base64")?;
    if computed != claimed {
        bail!("DigestValue does not match the canonical signed element");
    }

    let sig_b64: String = doc.leaf_text(sig_value)?.split_whitespace().collect();
    let sig_bytes = B64
        .decode(sig_b64.as_bytes())
        .context("SignatureValue not base64")?;
    let canon_si = canonicalize(doc, signed_info, None, &si_prefixes)?;
    sig_alg.verify(key, &canon_si, &sig_bytes)?;
    Ok(())
}

fn is_exc_c14n(uri: &str) -> bool {
    uri == ALG_EXC_C14N || uri == ALG_EXC_C14N_COMMENTS
}

/// The `PrefixList` of a CanonicalizationMethod / exc-c14n Transform: the
/// element may have no children or exactly one childless `InclusiveNamespaces`.
fn c14n_params(doc: &SamlDoc, el: usize) -> Result<Vec<String>> {
    let kids = &doc.node(el).children;
    let bad = || reject("algorithm", "unsupported canonicalisation parameters");
    let list = match kids.as_slice() {
        [] => return Ok(Vec::new()),
        [k] if doc.is(*k, NS_EXC_C14N, "InclusiveNamespaces")
            && doc.node(*k).children.is_empty() =>
        {
            doc.attr(*k, "PrefixList").unwrap_or("")
        }
        _ => return Err(bad()),
    };
    let prefixes: Vec<String> = list.split_whitespace().map(str::to_string).collect();
    if prefixes.len() > MAX_PREFIX_LIST {
        return Err(bad());
    }
    Ok(prefixes)
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
    //! Signed-response builder shared by the verifier and ACS tests. Digests
    //! and signatures are computed over `saml_c14n` output; use
    //! [`signed_from_literals`] for vectors that must not depend on it.
    use super::*;
    use rsa::{
        pkcs1v15::SigningKey,
        pkcs8::EncodePrivateKey,
        sha2::{Digest, Sha256, Sha384, Sha512},
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

    /// Hash choice for both the signature and digest algorithms.
    #[derive(Clone, Copy, PartialEq, Debug)]
    pub enum Hash {
        S256,
        S384,
        S512,
    }

    impl Hash {
        fn sig_uri(self) -> &'static str {
            match self {
                Hash::S256 => ALG_RSA_SHA256,
                Hash::S384 => ALG_RSA_SHA384,
                Hash::S512 => ALG_RSA_SHA512,
            }
        }

        fn digest_uri(self) -> &'static str {
            match self {
                Hash::S256 => ALG_SHA256,
                Hash::S384 => ALG_SHA384,
                Hash::S512 => ALG_SHA512,
            }
        }

        fn digest(self, data: &[u8]) -> Vec<u8> {
            match self {
                Hash::S256 => Sha256::digest(data).to_vec(),
                Hash::S384 => Sha384::digest(data).to_vec(),
                Hash::S512 => Sha512::digest(data).to_vec(),
            }
        }

        fn sign(self, rsa: &RsaPrivateKey, msg: &[u8]) -> Vec<u8> {
            match self {
                Hash::S256 => SigningKey::<Sha256>::new(rsa.clone()).sign(msg).to_vec(),
                Hash::S384 => SigningKey::<Sha384>::new(rsa.clone()).sign(msg).to_vec(),
                Hash::S512 => SigningKey::<Sha512>::new(rsa.clone()).sign(msg).to_vec(),
            }
        }
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
        pub assertion_id: String,
        pub response_id: String,
        pub sig_alg: Hash,
        pub digest_alg: Hash,
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
                assertion_id: "AS1".into(),
                response_id: "RS1".into(),
                sig_alg: Hash::S256,
                digest_alg: Hash::S256,
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
                r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}" Version="2.0" IssueInstant="2029-12-31T23:59:30Z"><saml:Issuer>{iss}</saml:Issuer>{sig}<saml:Subject><saml:NameID>{nm}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="{rcp}" NotOnOrAfter="{bn}"{irt}/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="mail"><saml:AttributeValue>{nm}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="displayName"><saml:AttributeValue>Alice Example</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#,
                aid = self.assertion_id,
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
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{rid}" Version="2.0"{dest}{irt}>{sig}<samlp:Status><samlp:StatusCode Value="{st}"/></samlp:Status>{assertion}</samlp:Response>"#,
                rid = self.response_id,
                st = self.status,
            )
        }

        pub fn build(&self) -> String {
            let (pem, rsa) = key();
            let sign = |id: &str, unsigned: &str| {
                signature_with(id, unsigned, pem, rsa, self.sig_alg, self.digest_alg)
            };
            let assertion = match self.layout {
                Layout::Assertion | Layout::Both => {
                    let sig = sign(&self.assertion_id, &self.assertion(""));
                    self.assertion(&sig)
                }
                _ => self.assertion(""),
            };
            match self.layout {
                Layout::Response | Layout::Both => {
                    let sig = sign(&self.response_id, &self.response("", &assertion));
                    self.response(&sig, &assertion)
                }
                _ => self.response("", &assertion),
            }
        }
    }

    /// Canonical form of a standalone fragment, for digest and signature input.
    fn canon_of(xml: &str) -> Vec<u8> {
        let doc = SamlDoc::parse_tree(xml).expect("fixture XML parses");
        canonicalize(&doc, 0, None, &[]).expect("fixture XML canonicalises")
    }

    fn inclusive_xml(prefixes: &[&str]) -> String {
        if prefixes.is_empty() {
            String::new()
        } else {
            format!(
                r#"<ec:InclusiveNamespaces xmlns:ec="{NS_EXC_C14N}" PrefixList="{}"/>"#,
                prefixes.join(" ")
            )
        }
    }

    /// `SignedInfo` for a Reference to `id`, with optional `PrefixList`s on
    /// the CanonicalizationMethod (`si_pl`) and on the Transform (`ref_pl`).
    fn signed_info_xml(
        id: &str,
        digest: &str,
        sig_alg: Hash,
        digest_alg: Hash,
        ref_pl: &[&str],
        si_pl: &[&str],
    ) -> String {
        let close = |name: &str, inc: String| {
            if inc.is_empty() {
                "/>".to_string()
            } else {
                format!(">{inc}</{name}>")
            }
        };
        let (si_end, ref_end) = (
            close("CanonicalizationMethod", inclusive_xml(si_pl)),
            close("Transform", inclusive_xml(ref_pl)),
        );
        format!(
            r##"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"{si_end}<SignatureMethod Algorithm="{sa}"/><Reference URI="#{id}"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"{ref_end}</Transforms><DigestMethod Algorithm="{da}"/><DigestValue>{digest}</DigestValue></Reference></SignedInfo>"##,
            sa = sig_alg.sig_uri(),
            da = digest_alg.digest_uri(),
        )
    }

    fn signature_xml(si: &str, sv: &str, cert_pem: &str) -> String {
        let cert = strip_pem_armor(cert_pem);
        format!(
            r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">{si}<SignatureValue>{sv}</SignatureValue><KeyInfo><X509Data><X509Certificate>{cert}</X509Certificate></X509Data></KeyInfo></Signature>"#
        )
    }

    pub fn signature_with(
        id: &str,
        unsigned: &str,
        cert_pem: &str,
        rsa: &RsaPrivateKey,
        sig_alg: Hash,
        digest_alg: Hash,
    ) -> String {
        let digest = B64.encode(digest_alg.digest(&canon_of(unsigned)));
        let si = signed_info_xml(id, &digest, sig_alg, digest_alg, &[], &[]);
        let sv = B64.encode(sig_alg.sign(rsa, &canon_of(&si)));
        signature_xml(&si, &sv, cert_pem)
    }

    /// Sign the element with ID `id` of the full document `unsigned` (SHA-256),
    /// canonicalising in document context so ancestor namespace declarations
    /// count. The Signature is inserted right after the element's start tag.
    /// `ref_pl` / `si_pl` are `PrefixList`s for the Transform / CanonicalizationMethod.
    pub fn sign_in_context(unsigned: &str, id: &str, ref_pl: &[&str], si_pl: &[&str]) -> String {
        let (pem, rsa) = key();
        let doc = SamlDoc::parse_tree(unsigned).expect("fixture XML parses");
        let i = (0..doc.len())
            .find(|&i| doc.attr(i, "ID") == Some(id))
            .expect("element with ID");
        let owned = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let canon = canonicalize(&doc, i, None, &owned(ref_pl)).expect("canonicalises");
        let digest = B64.encode(Sha256::digest(&canon));
        let start = doc.node(i).start;
        let ins = start + unsigned[start..].find('>').expect("start tag") + 1;
        let si = signed_info_xml(id, &digest, Hash::S256, Hash::S256, ref_pl, si_pl);
        let sig = signature_xml(&si, "@SIGVALUE@", pem);
        let full = format!("{}{}{}", &unsigned[..ins], sig, &unsigned[ins..]);
        let doc = SamlDoc::parse_tree(&full).expect("signed fixture parses");
        let sii = (0..doc.len())
            .find(|&i| doc.is(i, NS_DSIG, "SignedInfo"))
            .expect("SignedInfo");
        let canon_si = canonicalize(&doc, sii, None, &owned(si_pl)).expect("canonicalises");
        full.replace("@SIGVALUE@", &B64.encode(Hash::S256.sign(rsa, &canon_si)))
    }

    /// Sign hand-written canonical literals, independent of `saml_c14n`.
    /// `wire` is the document to emit; it may contain `@DIGEST@`, `@SIGVALUE@`
    /// and `@CERT@`. `canon_parent` is the exclusive canonical form of the
    /// signed element (Signature omitted); `canon_signed_info` is that of
    /// `SignedInfo` and may contain `@DIGEST@`. Always SHA-256.
    pub fn signed_from_literals(wire: &str, canon_parent: &str, canon_signed_info: &str) -> String {
        let (pem, rsa) = key();
        let digest = B64.encode(Sha256::digest(canon_parent.as_bytes()));
        let si = canon_signed_info.replace("@DIGEST@", &digest);
        let sv = B64.encode(Hash::S256.sign(rsa, si.as_bytes()));
        wire.replace("@DIGEST@", &digest)
            .replace("@SIGVALUE@", &sv)
            .replace("@CERT@", &strip_pem_armor(pem))
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::api::saml_xml::code_of;

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
            (
                "http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "DigestMethod",
            ),
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
    const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

    /// Response with the given root declarations whose Assertion (ID AS1) is
    /// signed in document context.
    fn ctx_signed(root_decls: &str, assertion: &str, ref_pl: &[&str], si_pl: &[&str]) -> String {
        let unsigned = format!(
            r#"<samlp:Response xmlns:samlp="{P}" {root_decls} ID="RS1">{assertion}</samlp:Response>"#
        );
        sign_in_context(&unsigned, "AS1", ref_pl, si_pl)
    }

    #[test]
    fn namespaces_declared_only_on_the_response_verify() {
        // Prefix declared on the Response only: the canonical form renders it
        // into the signed bytes.
        let xml = ctx_signed(
            &format!(r#"xmlns:saml="{A}""#),
            r#"<saml:Assertion ID="AS1"><saml:Subject><saml:NameID>a@b.c</saml:NameID></saml:Subject></saml:Assertion>"#,
            &[],
            &[],
        );
        assert_eq!(verify(&xml).unwrap().kind, ScopeKind::Assertion);
        // Default namespace on the Response.
        let xml = ctx_signed(
            &format!(r#"xmlns="{A}""#),
            r#"<Assertion ID="AS1"><Subject><NameID>a@b.c</NameID></Subject></Assertion>"#,
            &[],
            &[],
        );
        assert!(verify(&xml).is_ok());
    }

    #[test]
    fn rebinding_an_outer_prefix_after_signing_is_rejected() {
        // A non-SAML element inside the Assertion uses a prefix bound on the
        // Response; rebinding it must change the digest.
        let xml = ctx_signed(
            &format!(r#"xmlns:saml="{A}" xmlns:x="urn:x1""#),
            r#"<saml:Assertion ID="AS1"><x:Ext>v</x:Ext></saml:Assertion>"#,
            &[],
            &[],
        );
        assert!(verify(&xml).is_ok());
        let tampered = xml.replace(r#"xmlns:x="urn:x1""#, r#"xmlns:x="urn:x2""#);
        assert!(err(&tampered).contains("DigestValue"));
        // Rebinding the default namespace the same way.
        let xml = ctx_signed(
            &format!(r#"xmlns:saml="{A}" xmlns="urn:d1""#),
            r#"<saml:Assertion ID="AS1"><Ext>v</Ext></saml:Assertion>"#,
            &[],
            &[],
        );
        assert!(verify(&xml).is_ok());
        let tampered = xml.replace(r#"xmlns="urn:d1""#, r#"xmlns="urn:d2""#);
        assert!(err(&tampered).contains("DigestValue"));
    }

    #[test]
    fn inclusive_prefix_lists_are_honoured() {
        let a = r#"<saml:Assertion ID="AS1"><saml:Issuer>idp</saml:Issuer></saml:Assertion>"#;
        let decls = format!(r#"xmlns:saml="{A}" xmlns:xs="urn:xs1""#);
        // PrefixList on the Reference's Transform.
        let xml = ctx_signed(&decls, a, &["xs"], &[]);
        assert!(verify(&xml).is_ok());
        assert!(err(&xml.replace("urn:xs1", "urn:xs2")).contains("DigestValue"));
        // PrefixList on the CanonicalizationMethod (covers SignedInfo).
        let xml = ctx_signed(&decls, a, &[], &["xs"]);
        assert!(verify(&xml).is_ok());
        assert!(err(&xml.replace("urn:xs1", "urn:xs2")).contains("does not verify"));
        // Without a PrefixList the unused binding is not signed.
        let xml = ctx_signed(&decls, a, &[], &[]);
        assert!(verify(&xml.replace("urn:xs1", "urn:xs2")).is_ok());
    }

    #[test]
    fn prefix_list_limits_are_enforced() {
        let many = (0..17)
            .map(|i| format!("p{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let xml = built(Layout::Assertion).replacen(
            r#"xml-exc-c14n#"/>"#,
            &format!(
                r#"xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="{many}"/></CanonicalizationMethod>"#
            ),
            1,
        );
        assert_eq!(code_of(&verify(&xml).unwrap_err()), "algorithm");
    }

    /// Non-canonical wire form of a signed Assertion plus its hand-written
    /// canonical forms (independent of `saml_c14n`): single quotes, reordered
    /// attributes, ds: prefix, CDATA, `<x/>`, CRLF and indentation.
    fn literal_signed(cm: &str, tr: &str) -> String {
        let (env, r256, s256) = (ALG_ENVELOPED, ALG_RSA_SHA256, ALG_SHA256);
        let si_wire = format!(
            "<ds:SignedInfo xmlns:ds='{DS}'>\r\n<ds:CanonicalizationMethod Algorithm='{cm}'/>\r\n<ds:SignatureMethod Algorithm='{r256}'/><ds:Reference URI='#AS1'><ds:Transforms><ds:Transform Algorithm='{env}'/><ds:Transform Algorithm='{tr}'/></ds:Transforms><ds:DigestMethod Algorithm='{s256}'/><ds:DigestValue>@DIGEST@</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        );
        let si_canon = format!(
            "<ds:SignedInfo xmlns:ds=\"{DS}\">\n<ds:CanonicalizationMethod Algorithm=\"{cm}\"></ds:CanonicalizationMethod>\n<ds:SignatureMethod Algorithm=\"{r256}\"></ds:SignatureMethod><ds:Reference URI=\"#AS1\"><ds:Transforms><ds:Transform Algorithm=\"{env}\"></ds:Transform><ds:Transform Algorithm=\"{tr}\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"{s256}\"></ds:DigestMethod><ds:DigestValue>@DIGEST@</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        );
        let wire = format!(
            "<?xml version=\"1.0\"?>\r\n<samlp:Response xmlns:samlp='{P}' ID='RS1'>\r\n<saml:Assertion ID='AS1' xmlns:saml='{A}'>\r\n  <saml:Issuer><![CDATA[idp]]></saml:Issuer>\r\n  <ds:Signature xmlns:ds='{DS}'>{si_wire}<ds:SignatureValue>@SIGVALUE@</ds:SignatureValue></ds:Signature>\r\n  <saml:Empty/>\r\n</saml:Assertion>\r\n</samlp:Response>\r\n"
        );
        let canon_parent = format!(
            "<saml:Assertion xmlns:saml=\"{A}\" ID=\"AS1\">\n  <saml:Issuer>idp</saml:Issuer>\n  \n  <saml:Empty></saml:Empty>\n</saml:Assertion>"
        );
        signed_from_literals(&wire, &canon_parent, &si_canon)
    }

    #[test]
    fn non_canonical_wire_forms_verify() {
        let xml = literal_signed(ALG_EXC_C14N, ALG_EXC_C14N);
        assert_eq!(verify(&xml).unwrap().kind, ScopeKind::Assertion);
        // Any change inside the signed element is still caught.
        assert!(err(&xml.replace("idp", "evil")).contains("DigestValue"));
    }

    #[test]
    fn with_comments_uris_are_accepted() {
        let xml = literal_signed(ALG_EXC_C14N_COMMENTS, ALG_EXC_C14N_COMMENTS);
        assert!(verify(&xml).is_ok());
        let xml = literal_signed(ALG_EXC_C14N, ALG_EXC_C14N_COMMENTS);
        assert!(verify(&xml).is_ok());
    }

    #[test]
    fn insignificant_changes_outside_the_signed_element_verify() {
        let good = built(Layout::Assertion);
        // Whitespace between Response children (Assertion-only signature).
        let ws = good
            .replace("<samlp:Status>", "\n  <samlp:Status>")
            .replace("</samlp:Response>", "\n</samlp:Response>");
        assert!(verify(&ws).is_ok());
        // Unused namespace declaration added to the Response after signing.
        let ns = good.replacen(
            "<samlp:Response ",
            r#"<samlp:Response xmlns:foo="urn:foo" "#,
            1,
        );
        assert!(verify(&ns).is_ok());
        // Response attribute order and quote style.
        let q = good.replacen(r#"ID="RS1" Version="2.0""#, "Version='2.0' ID='RS1'", 1);
        assert!(verify(&q).is_ok());
    }

    #[test]
    fn changes_inside_the_signed_element_are_rejected() {
        let good = built(Layout::Assertion);
        for (from, to) in [
            ("<saml:Issuer>idp", "<saml:Issuer> idp"),
            ("<saml:Subject>", " <saml:Subject>"),
            ("<saml:Subject>", "<saml:Subject>x"),
            ("</saml:Issuer>", "</saml:Issuer>\n"),
        ] {
            assert!(
                err(&good.replacen(from, to, 1)).contains("DigestValue"),
                "{from}"
            );
        }
    }

    #[test]
    fn rsa_sha384_and_sha512_verify_with_any_digest() {
        for sig in [Hash::S256, Hash::S384, Hash::S512] {
            for dig in [Hash::S256, Hash::S384, Hash::S512] {
                for l in [Layout::Assertion, Layout::Response, Layout::Both] {
                    let mut fx = Fx::new(l);
                    fx.sig_alg = sig;
                    fx.digest_alg = dig;
                    assert!(verify(&fx.build()).is_ok(), "{sig:?}/{dig:?}");
                }
            }
        }
    }

    #[test]
    fn signature_algorithm_must_match_the_signed_info() {
        let mut fx = Fx::new(Layout::Assertion);
        fx.sig_alg = Hash::S384;
        let xml = fx.build();
        for other in ["rsa-sha256", "rsa-sha512"] {
            assert!(verify(&xml.replace("rsa-sha384", other)).is_err());
        }
        // Digest method swapped without re-signing.
        let mut fx = Fx::new(Layout::Assertion);
        fx.digest_alg = Hash::S384;
        let xml = fx.build();
        assert!(verify(&xml.replace("xmldsig-more#sha384", "xmlenc#sha512")).is_err());
    }

    #[test]
    fn transforms_must_be_enveloped_then_exc_c14n() {
        const ENV: &str =
            r#"<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#;
        const EXC: &str = r#"<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#;
        let good = built(Layout::Assertion);
        let both = format!("{ENV}{EXC}");
        assert!(good.contains(&both));
        let cases = [
            good.replace(&both, ENV),
            good.replace(&both, EXC),
            good.replace(&both, &format!("{EXC}{ENV}")),
            good.replace(&both, &format!("{ENV}{EXC}{EXC}")),
            good.replace(&both, &format!("{ENV}{ENV}")),
            good.replace(&both, &format!("{ENV}<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><Foo/></Transform>")),
            good.replace(&both, &format!("{ENV}<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><ec:InclusiveNamespaces xmlns:ec=\"urn:other\" PrefixList=\"a\"/></Transform>")),
            good.replace(&format!("<Transforms>{both}</Transforms>"), ""),
            good.replace(ENV, r#"<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"><Foo/></Transform>"#),
        ];
        for (n, c) in cases.iter().enumerate() {
            assert_eq!(code_of(&verify(c).unwrap_err()), "algorithm", "case {n}");
        }
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
        use rsa::pkcs8::EncodePublicKey;
        let spki = |k: &rsa::RsaPrivateKey| {
            RsaVerifyKey::from_spki_der(k.to_public_key().to_public_key_der().unwrap().as_bytes())
                .unwrap()
        };
        let e = format!("{:#}", check_key_size(&spki(&weak)).unwrap_err());
        assert!(e.contains("smaller than 2048"), "{e}");
        assert!(check_key_size(&spki(&key().1)).is_ok());
        assert!(validate_idp_cert(&key().0).is_ok());
    }
}
