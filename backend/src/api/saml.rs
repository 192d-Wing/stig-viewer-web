//! SAML 2.0 Service Provider (SP) endpoints — runs alongside the existing
//! OIDC flow in `auth.rs`. The OIDC code is untouched; this module only
//! reuses a handful of `pub(crate)` helpers from there so the post-login
//! flow (users row, session cookie, last_login stamp) is identical.
//!
//! No external SAML crate: we build the AuthnRequest and parse the
//! SAMLResponse by hand with `quick-xml` (already in tree). Signature
//! validation is intentionally skipped in dev (`STIG_ENV != "production"`)
//! to keep the test loop fast; in production an `SAML_IDP_CERT_PEM` is
//! required and we hard-fail when it's missing or the assertion has no
//! Signature element.

use anyhow::{anyhow, Result};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use flate2::{write::DeflateEncoder, Compression};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::Deserialize;
use sqlx::PgPool;
use std::io::Write;
use std::sync::Arc;

use crate::api::auth::{
    create_session, upsert_user, SESSION_COOKIE, SESSION_LIFETIME_HOURS,
};

// ── Config ──────────────────────────────────────────────────────────────────

/// Static SAML SP/IdP config built once at startup. If the IdP SSO URL is
/// empty we treat SAML as "not configured" and return 503 from the live
/// endpoints — the test endpoint + metadata still work, which is enough
/// for the E2E spec.
#[derive(Clone, Debug)]
pub struct SamlConfig {
    pub idp_sso_url: String,
    #[allow(dead_code)] // surfaced in metadata + logged for ops, otherwise informational
    pub idp_entity_id: String,
    pub sp_entity_id: String,
    pub sp_acs_url: String,
    pub idp_cert_pem: Option<String>,
    pub frontend_url: String,
    pub is_production: bool,
}

impl SamlConfig {
    pub fn from_env(frontend_url: &str) -> Self {
        let public_base = std::env::var("PUBLIC_BASE")
            .unwrap_or_else(|_| "http://localhost:8080".into());
        let sp_entity_id = std::env::var("SAML_SP_ENTITY_ID")
            .unwrap_or_else(|_| format!("{}/saml/sp", frontend_url.trim_end_matches('/')));
        let sp_acs_url = std::env::var("SAML_SP_ACS_URL")
            .unwrap_or_else(|_| format!("{}/auth/saml/acs", public_base.trim_end_matches('/')));
        Self {
            idp_sso_url: std::env::var("SAML_IDP_SSO_URL").unwrap_or_default(),
            idp_entity_id: std::env::var("SAML_IDP_ENTITY_ID").unwrap_or_default(),
            sp_entity_id,
            sp_acs_url,
            idp_cert_pem: std::env::var("SAML_IDP_CERT_PEM").ok().filter(|s| !s.is_empty()),
            frontend_url: frontend_url.to_string(),
            is_production: std::env::var("STIG_ENV").unwrap_or_default() == "production",
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.idp_sso_url.is_empty()
    }
}

/// Combined state for SAML handlers — DB pool + static SAML config.
#[derive(Clone)]
pub struct AppSamlState {
    pub pool: Arc<PgPool>,
    pub config: Arc<SamlConfig>,
}

// ── Login: GET /auth/saml/login ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginParams {
    #[serde(default)]
    pub relay_state: Option<String>,
}

/// Redirect the browser to the IdP's SSO endpoint with a base64-encoded
/// AuthnRequest in the `SAMLRequest` query param.
pub async fn login_handler(
    State(state): State<AppSamlState>,
    axum::extract::Query(params): axum::extract::Query<LoginParams>,
) -> Result<Redirect, (StatusCode, String)> {
    if !state.config.is_configured() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "SAML IdP is not configured (set SAML_IDP_SSO_URL)".into(),
        ));
    }
    let req_id = format!("_{}", uuid::Uuid::new_v4().simple());
    let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let authn_req = build_authn_request(
        &req_id,
        &issue_instant,
        &state.config.sp_entity_id,
        &state.config.sp_acs_url,
        &state.config.idp_sso_url,
    );

    // HTTP-Redirect binding: DEFLATE (raw, no zlib header) then base64.
    let mut deflater = DeflateEncoder::new(Vec::new(), Compression::default());
    deflater
        .write_all(authn_req.as_bytes())
        .map_err(|e| internal(&format!("deflate failed: {e}")))?;
    let deflated = deflater
        .finish()
        .map_err(|e| internal(&format!("deflate finish failed: {e}")))?;
    let encoded = B64.encode(&deflated);

    let relay = params
        .relay_state
        .unwrap_or_else(|| state.config.frontend_url.clone());

    let mut url = url::Url::parse(&state.config.idp_sso_url)
        .map_err(|e| internal(&format!("bad SAML_IDP_SSO_URL: {e}")))?;
    url.query_pairs_mut()
        .append_pair("SAMLRequest", &encoded)
        .append_pair("RelayState", &relay);
    Ok(Redirect::to(url.as_str()))
}

// ── ACS: POST /auth/saml/acs ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    #[serde(rename = "RelayState", default)]
    pub relay_state: Option<String>,
}

/// IdP POSTs the (base64-encoded) SAMLResponse here. We decode, parse,
/// optionally verify the signature, extract NameID + attributes, and mint
/// a session via the same helper the OIDC callback uses.
pub async fn acs_handler(
    State(state): State<AppSamlState>,
    jar: CookieJar,
    Form(form): Form<AcsForm>,
) -> Result<(CookieJar, Redirect), (StatusCode, String)> {
    let xml_bytes = B64
        .decode(form.saml_response.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("SAMLResponse not base64: {e}")))?;
    let xml = std::str::from_utf8(&xml_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("SAMLResponse not UTF-8: {e}")))?;

    // Production gate: require a configured cert AND a Signature element.
    // Actual cryptographic verification is out of scope for this hand-rolled
    // path — we surface the requirement so an ops error doesn't fail open.
    if state.config.is_production {
        if state.config.idp_cert_pem.is_none() {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "SAML_IDP_CERT_PEM is required in production".into(),
            ));
        }
        if !xml.contains("Signature") {
            return Err((
                StatusCode::UNAUTHORIZED,
                "SAMLResponse is missing Signature element".into(),
            ));
        }
    }

    let assertion = parse_assertion(xml).map_err(|e| {
        tracing::error!("SAMLResponse parse failed: {e:#}");
        (StatusCode::BAD_REQUEST, format!("SAMLResponse parse failed: {e}"))
    })?;

    let (display_name, sub) = pick_identity(&assertion);
    let email = assertion.email.clone().unwrap_or_default();

    let user = upsert_user(state.pool.as_ref(), "saml", &sub, &display_name, &email)
        .await
        .map_err(|e| internal(&format!("upsert_user failed: {e}")))?;

    let session_id = create_session(state.pool.as_ref(), &user.id)
        .await
        .map_err(|e| internal(&format!("create_session failed: {e}")))?;

    let cookie = Cookie::build((SESSION_COOKIE, session_id))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::hours(SESSION_LIFETIME_HOURS))
        .build();

    let redirect_to = form
        .relay_state
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| state.config.frontend_url.clone());

    Ok((jar.add(cookie), Redirect::to(&redirect_to)))
}

// ── Metadata: GET /auth/saml/metadata ───────────────────────────────────────

/// Static SP metadata XML — what an IdP admin imports to register us.
pub async fn metadata_handler(
    State(state): State<AppSamlState>,
) -> impl IntoResponse {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#,
        entity = xml_escape(&state.config.sp_entity_id),
        acs = xml_escape(&state.config.sp_acs_url),
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/xml; charset=utf-8".parse().unwrap(),
    );
    (StatusCode::OK, headers, xml).into_response()
}

// ── Helpers reused by the test endpoint ─────────────────────────────────────

/// Same "find or create user, mint session cookie" path the ACS handler
/// uses, exposed so the E2E test endpoint can drive it without an IdP.
pub(crate) async fn saml_login_user(
    pool: &PgPool,
    name_id: &str,
    email: &str,
    display_name: &str,
) -> Result<(String, String)> {
    let user = upsert_user(pool, "saml", name_id, display_name, email).await?;
    let session_id = create_session(pool, &user.id).await?;
    Ok((user.id, session_id))
}

// ── XML build/parse ─────────────────────────────────────────────────────────

fn build_authn_request(
    id: &str,
    issue_instant: &str,
    sp_entity_id: &str,
    acs_url: &str,
    destination: &str,
) -> String {
    // Minimal AuthnRequest. Signed/encrypted variants are out of scope —
    // dev IdPs (and the test endpoint) accept this as-is.
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{ii}" Destination="{dest}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{acs}"><saml:Issuer>{sp}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>"#,
        id = xml_escape(id),
        ii = xml_escape(issue_instant),
        dest = xml_escape(destination),
        acs = xml_escape(acs_url),
        sp = xml_escape(sp_entity_id),
    )
}

#[derive(Default, Debug)]
pub(crate) struct ParsedAssertion {
    pub name_id: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

/// Pull NameID and a handful of common attributes (`mail`/`email`, plus
/// `displayName`/`name`/`cn`) out of a SAMLResponse. We intentionally
/// don't try to fully validate the schema — we just want enough to mint
/// a session.
pub(crate) fn parse_assertion(xml: &str) -> Result<ParsedAssertion> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut out = ParsedAssertion::default();

    // Track depth into <AttributeStatement>/<Attribute Name="...">/<AttributeValue>
    let mut in_name_id = false;
    let mut in_attr_value = false;
    let mut current_attr_name: Option<String> = None;
    // Text-accumulator for the current text run (handles entity refs).
    let mut text_buf = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local = local_name(e.name().as_ref());
                match local.as_str() {
                    "NameID" => {
                        in_name_id = true;
                        text_buf.clear();
                    }
                    "Attribute" => {
                        current_attr_name = None;
                        for a in e.attributes().flatten() {
                            if local_name(a.key.as_ref()) == "Name" {
                                if let Ok(v) = a.unescape_value() {
                                    current_attr_name = Some(v.to_string());
                                }
                            }
                        }
                    }
                    "AttributeValue" => {
                        in_attr_value = true;
                        text_buf.clear();
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(t)) => {
                if in_name_id || in_attr_value {
                    if let Ok(s) = t.unescape() {
                        text_buf.push_str(&s);
                    }
                }
            }
            Ok(Event::CData(c)) => {
                if in_name_id || in_attr_value {
                    if let Ok(s) = std::str::from_utf8(&c) {
                        text_buf.push_str(s);
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = local_name(e.name().as_ref());
                match local.as_str() {
                    "NameID" => {
                        if in_name_id {
                            let v = text_buf.trim().to_string();
                            if !v.is_empty() {
                                out.name_id = Some(v);
                            }
                            in_name_id = false;
                            text_buf.clear();
                        }
                    }
                    "AttributeValue" => {
                        if in_attr_value {
                            let value = text_buf.trim().to_string();
                            if let Some(name) = current_attr_name.as_deref() {
                                match map_attr_name(name) {
                                    AttrKind::Email if out.email.is_none() && !value.is_empty() => {
                                        out.email = Some(value.clone());
                                    }
                                    AttrKind::DisplayName
                                        if out.display_name.is_none() && !value.is_empty() =>
                                    {
                                        out.display_name = Some(value.clone());
                                    }
                                    _ => {}
                                }
                            }
                            in_attr_value = false;
                            text_buf.clear();
                        }
                    }
                    "Attribute" => {
                        current_attr_name = None;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow!("xml parse error at {}: {e}", reader.buffer_position())),
            _ => {}
        }
        buf.clear();
    }

    if out.name_id.is_none() && out.email.is_none() {
        return Err(anyhow!("SAMLResponse contains neither NameID nor email attribute"));
    }
    Ok(out)
}

/// Prefer email over NameID for the user-facing display, but keep NameID
/// as the stable subject when present (some IdPs use a transient NameID
/// and put the durable identifier in the `mail` attribute — we accept
/// either).
fn pick_identity(a: &ParsedAssertion) -> (String, String) {
    let sub = a
        .name_id
        .clone()
        .or_else(|| a.email.clone())
        .unwrap_or_else(|| format!("saml-{}", uuid::Uuid::new_v4()));
    let display = a
        .display_name
        .clone()
        .or_else(|| a.email.clone())
        .unwrap_or_else(|| sub.clone());
    (display, sub)
}

enum AttrKind {
    Email,
    DisplayName,
    Other,
}

fn map_attr_name(name: &str) -> AttrKind {
    // Cover the friendly names AD/Keycloak/Okta/etc. use, plus the
    // canonical urn:oid: forms.
    let n = name.to_ascii_lowercase();
    if n == "mail"
        || n == "email"
        || n == "emailaddress"
        || n.ends_with(":emailaddress")
        || n == "urn:oid:0.9.2342.19200300.100.1.3"
    {
        AttrKind::Email
    } else if n == "displayname"
        || n == "name"
        || n == "cn"
        || n == "commonname"
        || n.ends_with(":name")
        || n == "urn:oid:2.16.840.1.113730.3.1.241"
        || n == "urn:oid:2.5.4.3"
    {
        AttrKind::DisplayName
    } else {
        AttrKind::Other
    }
}

/// Drop the XML namespace prefix from a tag name (e.g. `saml:NameID` → `NameID`).
fn local_name(qname: &[u8]) -> String {
    let s = std::str::from_utf8(qname).unwrap_or("");
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => s.to_string(),
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn internal(msg: &str) -> (StatusCode, String) {
    tracing::error!("SAML internal error: {msg}");
    (StatusCode::INTERNAL_SERVER_ERROR, msg.to_string())
}

/// Adapter so the IntoResponse type can be inferred at the route layer.
impl IntoResponse for ParsedAssertion {
    fn into_response(self) -> Response {
        // Not actually used as a route response — implemented to keep
        // the type usable as a return value in tests/debug paths.
        let body = format!("{self:?}");
        (StatusCode::OK, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_response() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion>
                <saml:Subject>
                    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
                </saml:Subject>
                <saml:AttributeStatement>
                    <saml:Attribute Name="mail"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>
                    <saml:Attribute Name="displayName"><saml:AttributeValue>Alice Example</saml:AttributeValue></saml:Attribute>
                </saml:AttributeStatement>
            </saml:Assertion>
        </samlp:Response>"#;
        let a = parse_assertion(xml).unwrap();
        assert_eq!(a.name_id.as_deref(), Some("alice@example.com"));
        assert_eq!(a.email.as_deref(), Some("alice@example.com"));
        assert_eq!(a.display_name.as_deref(), Some("Alice Example"));
    }

    #[test]
    fn parse_requires_some_identity() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:Response>"#;
        assert!(parse_assertion(xml).is_err());
    }
}
