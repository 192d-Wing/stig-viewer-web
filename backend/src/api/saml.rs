//! SAML 2.0 Service Provider (SP) endpoints — runs alongside the existing
//! OIDC flow in `auth.rs`. The OIDC code is untouched; this module only
//! reuses a handful of `pub(crate)` helpers from there so the post-login
//! flow (users row, session cookie, last_login stamp) is identical.
//!
//! No external SAML crate: we build the AuthnRequest and parse the
//! SAMLResponse by hand with `quick-xml` (see `saml_xml`). Signature
//! validation is skipped only with `SAML_INSECURE_SKIP_VERIFY=true` outside
//! production (startup refuses that combination in production); otherwise
//! `SAML_IDP_CERT_PEM` is required and the response must verify. Identity is
//! read only from the verified scope (see `saml_verify`).

use anyhow::{anyhow, bail, Result};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::{CookieJar, SameSite};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use flate2::{write::DeflateEncoder, Compression};
use serde::Deserialize;
use sqlx::PgPool;
use std::io::Write;
use std::sync::Arc;

use crate::api::auth::{
    cookie_secure, create_session, removal_cookie, saml_req_same_site, session_cookie, upsert_user,
    user_agent, SESSION_COOKIE, SESSION_LIFETIME_HOURS,
};
use crate::api::notice::require_ack;
use crate::api::saml_verify::ScopeKind;
use crate::api::saml_xml::{code_of, reject, tag, SamlDoc, NS_ASSERT, NS_PROTO};
use crate::db_notice::LoginBinding;

/// Cookie carrying the ack id from login start to the ACS (proves this browser began the login).
const SAML_REQ_COOKIE: &str = "stig_saml_req";
const SAML_REQ_PATH: &str = "/auth/saml";

/// Longest RelayState accepted as a redirect target.
const MAX_RELAY_STATE_CHARS: usize = 512;

/// A RelayState reduced to a same-origin relative path: starts with a single
/// `/` (not `//`), no backslash or control characters, at most
/// [`MAX_RELAY_STATE_CHARS`] characters.
pub(crate) fn safe_relay_path(raw: &str) -> Option<&str> {
    let mut chars = raw.chars();
    if chars.next() != Some('/')
        || matches!(chars.next(), Some('/') | Some('\\'))
        || raw.chars().count() > MAX_RELAY_STATE_CHARS
        || raw.chars().any(|c| c == '\\' || c.is_control())
    {
        return None;
    }
    Some(raw)
}

/// RelayState sent to the IdP: the validated relative path (ACS validates it
/// again and resolves it), or `/`.
pub(crate) fn relay_for_idp(raw: &str) -> String {
    safe_relay_path(raw).unwrap_or("/").to_string()
}

/// Redirect target for a RelayState: only a same-origin relative path is
/// resolved against `frontend_url` (and must stay on its origin); anything
/// else yields `frontend_url`.
pub(crate) fn safe_relay_target(raw: &str, frontend_url: &str) -> String {
    let fallback = || frontend_url.to_string();
    let Some(path) = safe_relay_path(raw) else {
        return fallback();
    };
    let Ok(base) = url::Url::parse(frontend_url) else {
        return fallback();
    };
    match base.join(path) {
        Ok(u) if u.origin() == base.origin() => u.to_string(),
        _ => fallback(),
    }
}

/// Where the ACS redirects after login for the IdP-supplied RelayState.
pub(crate) fn acs_redirect_target(relay_state: Option<&str>, frontend_url: &str) -> String {
    safe_relay_target(relay_state.unwrap_or(""), frontend_url)
}

// ── Config ──────────────────────────────────────────────────────────────────

/// Static SAML SP/IdP config built once at startup. If the IdP SSO URL is
/// empty we treat SAML as "not configured" and return 503 from the live
/// endpoints — the test endpoint + metadata still work, which is enough
/// for the E2E spec.
#[derive(Clone, Debug)]
pub struct SamlConfig {
    pub idp_sso_url: String,
    pub idp_entity_id: String,
    pub sp_entity_id: String,
    pub sp_acs_url: String,
    pub idp_cert_pem: Option<String>,
    pub frontend_url: String,
    pub is_production: bool,
    /// Dev-only: skip signature verification (never true in production).
    pub insecure_skip_verify: bool,
    /// Tolerated clock difference for NotBefore/NotOnOrAfter, in seconds.
    pub clock_skew_secs: i64,
}

const DEFAULT_SKEW_SECS: i64 = 120;
const MAX_SKEW_SECS: i64 = 300;

/// `SAML_INSECURE_SKIP_VERIFY` resolution. Refuses (startup error) when the
/// flag is on in production, as `TestHooks::validate` does for test hooks.
fn resolve_skip_verify(stig_env: Option<&str>, flag: Option<&str>) -> Result<bool> {
    let on = crate::config::parse_flag(flag);
    if on && crate::config::is_production(stig_env) {
        return Err(anyhow!(
            "refusing to start: SAML_INSECURE_SKIP_VERIFY must not be set when STIG_ENV=production"
        ));
    }
    Ok(on)
}

/// `SAML_CLOCK_SKEW_SECS`: default 120, clamped to 0..=300.
fn resolve_skew(raw: Option<&str>) -> i64 {
    raw.and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(DEFAULT_SKEW_SECS)
        .clamp(0, MAX_SKEW_SECS)
}

impl SamlConfig {
    pub fn from_env(frontend_url: &str) -> Result<Self> {
        Self::from_lookup(frontend_url, |k| std::env::var(k).ok())
    }

    /// `from_env` over an injectable variable lookup (tests need no global env).
    fn from_lookup(frontend_url: &str, var: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let stig_env = var("STIG_ENV");
        let insecure_skip_verify = resolve_skip_verify(
            stig_env.as_deref(),
            var("SAML_INSECURE_SKIP_VERIFY").as_deref(),
        )?;
        if insecure_skip_verify {
            tracing::warn!("SAML_INSECURE_SKIP_VERIFY is active: SAML signatures are NOT verified");
        }
        let public_base =
            std::env::var("PUBLIC_BASE").unwrap_or_else(|_| "http://localhost:8080".into());
        let sp_entity_id = std::env::var("SAML_SP_ENTITY_ID")
            .unwrap_or_else(|_| format!("{}/saml/sp", frontend_url.trim_end_matches('/')));
        let sp_acs_url = std::env::var("SAML_SP_ACS_URL")
            .unwrap_or_else(|_| format!("{}/auth/saml/acs", public_base.trim_end_matches('/')));
        let cfg = Self {
            idp_sso_url: var("SAML_IDP_SSO_URL").unwrap_or_default(),
            idp_entity_id: var("SAML_IDP_ENTITY_ID").unwrap_or_default(),
            sp_entity_id,
            sp_acs_url,
            idp_cert_pem: var("SAML_IDP_CERT_PEM").filter(|s| !s.is_empty()),
            frontend_url: frontend_url.to_string(),
            is_production: crate::config::is_production(stig_env.as_deref()),
            insecure_skip_verify,
            clock_skew_secs: resolve_skew(var("SAML_CLOCK_SKEW_SECS").as_deref()),
        };
        if cfg.is_configured() {
            if let Some(pem) = cfg.idp_cert_pem.as_deref() {
                crate::api::saml_verify::validate_idp_cert(pem)
                    .map_err(|e| anyhow!("refusing to start: SAML_IDP_CERT_PEM rejected: {e:#}"))?;
            }
            if cfg.is_production && cfg.idp_entity_id.is_empty() {
                tracing::warn!(
                    "SAML_IDP_ENTITY_ID is not set: the assertion Issuer is not being checked"
                );
            }
        }
        Ok(cfg)
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
    pub tasks: Arc<crate::detached::Tracker>,
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
    headers: HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    jar: CookieJar,
    axum::extract::Query(params): axum::extract::Query<LoginParams>,
) -> Result<(CookieJar, Redirect), (StatusCode, String)> {
    if !state.config.is_configured() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "SAML IdP is not configured (set SAML_IDP_SSO_URL)".into(),
        ));
    }
    let req_id = format!("_{}", crate::crypto::rand::uuid_v4().simple());
    let ip = crate::api::notice::notice_ip(&headers, peer.map(|p| p.0));
    if crate::api::notice::login_start_limited(&jar, &ip) {
        return Ok(crate::api::notice::rate_limited_redirect(
            jar,
            &state.config.frontend_url,
            &ip,
        ));
    }
    // AC-8 gate: consumes the acknowledgement and binds it to this request id.
    let (jar, ack_id) = match require_ack(
        state.pool.as_ref(),
        jar,
        &state.config.frontend_url,
        &LoginBinding::Saml {
            request_id: &req_id,
        },
        &ip,
    )
    .await
    {
        Ok(v) => v,
        Err(deny) => return Ok(*deny),
    };
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

    let relay = relay_for_idp(params.relay_state.as_deref().unwrap_or(""));

    let mut url = url::Url::parse(&state.config.idp_sso_url)
        .map_err(|e| internal(&format!("bad SAML_IDP_SSO_URL: {e}")))?;
    url.query_pairs_mut()
        .append_pair("SAMLRequest", &encoded)
        .append_pair("RelayState", &relay);
    let req_cookie = session_cookie(
        SAML_REQ_COOKIE,
        ack_id,
        SAML_REQ_PATH,
        saml_req_same_site(cookie_secure()),
        time::Duration::minutes(10),
        cookie_secure(),
    );
    Ok((jar.add(req_cookie), Redirect::to(url.as_str())))
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
#[allow(clippy::result_large_err)] // the Err carries the cookie jar so refusals clear the binding cookie
pub async fn acs_handler(
    State(state): State<AppSamlState>,
    headers: HeaderMap,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    jar: CookieJar,
    Form(form): Form<AcsForm>,
) -> Result<(CookieJar, Redirect), (StatusCode, CookieJar, String)> {
    acs_with_limiter(
        crate::api::rate_limit::global(),
        &state,
        &headers,
        peer.map(|p| p.0),
        jar,
        form,
    )
    .await
}

/// Audit detail for an oversized `SAMLResponse` field; kept stable.
const FIELD_TOO_LONG: &str = "SAMLResponse field too long";
/// Longest base64 SAMLResponse accepted (checked before any decoding).
const MAX_RESPONSE_B64: usize = (crate::api::saml_xml::MAX_DOC_BYTES / 3 + 1) * 4 + 1024;
/// Request body cap for the ACS route.
pub const ACS_BODY_LIMIT: usize = 512 * 1024;

/// ACS core, split from the handler so tests can pass their own limiter. A
/// refusal returns the jar with the request cookie removed (except for 429).
#[allow(clippy::result_large_err)] // see acs_handler
pub(crate) async fn acs_with_limiter(
    limiter: &crate::api::rate_limit::PreAuthLimiter,
    state: &AppSamlState,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    jar: CookieJar,
    form: AcsForm,
) -> Result<(CookieJar, Redirect), (StatusCode, CookieJar, String)> {
    let cleared = jar.clone().remove(removal_cookie(
        SAML_REQ_COOKIE,
        SAML_REQ_PATH,
        cookie_secure(),
    ));
    acs_core(limiter, state, headers, peer, jar, form)
        .await
        .map_err(|(code, msg)| {
            let jar = if code == StatusCode::TOO_MANY_REQUESTS {
                CookieJar::new()
            } else {
                cleared
            };
            (code, jar, msg)
        })
}

async fn acs_core(
    limiter: &crate::api::rate_limit::PreAuthLimiter,
    state: &AppSamlState,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    jar: CookieJar,
    form: AcsForm,
) -> Result<(CookieJar, Redirect), (StatusCode, String)> {
    let ip = crate::api::notice::notice_ip(headers, peer);
    let ua = user_agent(headers);
    if !limiter.allow(&crate::api::rate_limit::limiter_key(&ip)) {
        tracing::warn!(target: "audit", action = "auth.saml_acs", outcome = "denied", reason = "rate_limited", ip = %ip);
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests".to_string(),
        ));
    }
    let deny = |reason: &'static str, detail: &str| {
        tracing::warn!(target: "audit", action = "auth.saml_acs", outcome = "denied", reason, ip = %ip);
        tracing::debug!(reason, detail = ?sanitize_detail(detail), "SAML ACS denial detail");
        (
            StatusCode::UNAUTHORIZED,
            "SAML authentication failed".to_string(),
        )
    };
    let xml =
        decode_saml_response(&form.saml_response).map_err(|e| deny("decode", &format!("{e:#}")))?;

    let assertion = process_saml_response(&xml, &state.config, Utc::now())
        .map_err(|e| deny(code_of(&e), &format!("{e:#}")))?;

    // AC-8: the verified InResponseTo plus this browser's request cookie must claim
    // the acknowledgement consumed at login start. IdP-initiated responses are refused.
    let Some(irt) = assertion.in_response_to.as_deref() else {
        return Err(deny("unsolicited", "no InResponseTo"));
    };
    let Some(ack_id) = jar
        .get(SAML_REQ_COOKIE)
        .and_then(|c| uuid::Uuid::parse_str(c.value()).ok())
        .map(|u| u.to_string())
    else {
        return Err(deny(
            "no_request_cookie",
            "missing or malformed request cookie",
        ));
    };
    let ack = match crate::db_notice::claim_saml(state.pool.as_ref(), &ack_id, irt).await {
        Ok(Some(rec)) => rec,
        Ok(None) => return Err(deny("ack_not_claimed", "no matching acknowledgement")),
        Err(e) => {
            tracing::error!("saml ack claim failed: {e:#}");
            return Err(deny("claim_error", "claim query failed"));
        }
    };

    let (display_name, sub) = pick_identity(&assertion);
    let email = assertion.email.clone().unwrap_or_default();

    let user = upsert_user(state.pool.as_ref(), "saml", &sub, &display_name, &email)
        .await
        .map_err(|e| internal(&format!("upsert_user failed: {e}")))?;

    // Session and the durable AU-2 ack record: one detached task.
    let session_id = crate::api::notice::session_with_ack(
        &state.tasks,
        state.pool.clone(),
        user.id.clone(),
        ip.to_string(),
        ua.to_string(),
        ack,
    )
    .await
    .map_err(|c| internal(&format!("login session failed: {c}")))?;

    tracing::info!(target: "audit", action = "auth.saml_acs", outcome = "success", user_id = %user.id, assertion_id = assertion.assertion_id.as_deref().unwrap_or(""), ip = %ip);

    let jar = jar.remove(removal_cookie(
        SAML_REQ_COOKIE,
        SAML_REQ_PATH,
        cookie_secure(),
    ));

    let cookie = session_cookie(
        SESSION_COOKIE,
        session_id,
        "/",
        SameSite::Lax,
        time::Duration::hours(SESSION_LIFETIME_HOURS),
        cookie_secure(),
    );

    let redirect_to = acs_redirect_target(form.relay_state.as_deref(), &state.config.frontend_url);

    Ok((jar.add(cookie), Redirect::to(&redirect_to)))
}

/// Base64-decode the form value (ASCII whitespace from line wrapping is
/// ignored) into UTF-8.
fn decode_saml_response(raw: &str) -> Result<String> {
    if raw.len() > MAX_RESPONSE_B64 {
        bail!(FIELD_TOO_LONG);
    }
    let compact: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let bytes = B64
        .decode(compact.as_bytes())
        .map_err(|e| anyhow!("not base64: {e}"))?;
    String::from_utf8(bytes).map_err(|_| anyhow!("not UTF-8"))
}

/// Printable, bounded form of an error detail for the (non-audit) debug line.
fn sanitize_detail(detail: &str) -> String {
    detail
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect()
}

// ── Metadata: GET /auth/saml/metadata ───────────────────────────────────────

/// Static SP metadata XML — what an IdP admin imports to register us.
pub async fn metadata_handler(State(state): State<AppSamlState>) -> impl IntoResponse {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
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
    ip: &str,
    user_agent: &str,
) -> Result<(String, String)> {
    let user = upsert_user(pool, "saml", name_id, display_name, email).await?;
    let session_id = create_session(pool, &user.id, ip, user_agent).await?;
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
    /// The AuthnRequest id this response answers, taken only from the
    /// verified scope (see [`extract`]); at most 128 chars.
    pub in_response_to: Option<String>,
    /// `ID` of the Assertion the identity was read from.
    #[allow(dead_code)] // carried for the replay-cache follow-up
    pub assertion_id: Option<String>,
    /// Expiry of the accepted bearer SubjectConfirmation.
    #[allow(dead_code)] // carried for the replay-cache follow-up
    pub not_on_or_after: Option<DateTime<Utc>>,
    #[allow(dead_code)] // informational; asserted in tests
    pub scope: ScopeKind,
}

const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const MAX_IRT_CHARS: usize = 128;

/// Parse, verify, and validate a SAMLResponse; returns identity read only
/// from the verified element. The single entry point used by the ACS.
pub(crate) fn process_saml_response(
    xml: &str,
    cfg: &SamlConfig,
    now: DateTime<Utc>,
) -> Result<ParsedAssertion> {
    let doc = SamlDoc::parse(xml).map_err(|e| tag("xml_structure", e))?;
    let scope = if cfg.insecure_skip_verify {
        crate::api::saml_verify::insecure_unverified_scope(cfg.is_production)?
    } else {
        let pem = cfg.idp_cert_pem.as_deref().ok_or_else(|| {
            reject(
                "cert",
                "SAML_IDP_CERT_PEM is required for signature verification",
            )
        })?;
        crate::api::saml_verify::verify_response(&doc, pem).map_err(|e| tag("signature", e))?
    };
    extract(&doc, cfg, now, scope.kind).map_err(|e| tag("xml_structure", e))
}

fn parse_time(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s.trim())
        .map_err(|e| reject("time_window", format!("bad timestamp {s:?}: {e}")))?
        .with_timezone(&Utc))
}

/// Reject when `now` is outside `[not_before - skew, not_on_or_after + skew)`.
fn check_window(
    now: DateTime<Utc>,
    skew: chrono::Duration,
    not_before: Option<&str>,
    not_on_or_after: Option<&str>,
    what: &str,
) -> Result<()> {
    if let Some(nb) = not_before {
        if now + skew < parse_time(nb)? {
            return Err(reject("time_window", format!("{what} not yet valid")));
        }
    }
    if let Some(na) = not_on_or_after {
        if now >= parse_time(na)? + skew {
            return Err(reject("time_window", format!("{what} expired")));
        }
    }
    Ok(())
}

/// Validate the response and read identity strictly from named paths under
/// the Assertion (never descending into a Signature).
fn extract(
    doc: &SamlDoc,
    cfg: &SamlConfig,
    now: DateTime<Utc>,
    scope: ScopeKind,
) -> Result<ParsedAssertion> {
    let root = doc.root();
    let assertion = doc.assertion()?;
    let a = NS_ASSERT;
    if doc.attr(root, "Version") != Some("2.0") || doc.attr(assertion, "Version") != Some("2.0") {
        return Err(reject("xml_structure", "unsupported SAML Version"));
    }
    let assertion_id = doc
        .attr(assertion, "ID")
        .ok_or_else(|| reject("xml_structure", "Assertion has no ID"))?
        .to_string();

    let status = doc.child_one(root, NS_PROTO, "Status")?;
    let code = doc.child_one(status, NS_PROTO, "StatusCode")?;
    if doc.attr(code, "Value") != Some(STATUS_SUCCESS) {
        return Err(reject("status", "SAML status is not Success"));
    }
    if let Some(d) = doc.attr(root, "Destination") {
        if d != cfg.sp_acs_url {
            return Err(reject(
                "destination",
                "Destination does not match the ACS URL",
            ));
        }
    }
    if !cfg.idp_entity_id.is_empty() {
        let issuer = doc.child_one(assertion, a, "Issuer")?;
        if doc.leaf_text(issuer)? != cfg.idp_entity_id {
            return Err(reject("issuer", "Issuer does not match SAML_IDP_ENTITY_ID"));
        }
    }
    let skew = chrono::Duration::seconds(cfg.clock_skew_secs);

    // Subject: NameID (at most one), bearer confirmation for this ACS.
    let subject = doc.child_one(assertion, a, "Subject")?;
    if !doc.children(subject, a, "EncryptedID").is_empty() {
        return Err(reject("nameid", "EncryptedID is not supported"));
    }
    let name_id = match doc.child_opt(subject, a, "NameID")? {
        Some(n) => Some(doc.leaf_text(n)?.to_string()).filter(|t| !t.is_empty()),
        None => None,
    };
    let mut bearer = None;
    for sc in doc.children(subject, a, "SubjectConfirmation") {
        if doc.attr(sc, "Method") != Some(CM_BEARER) {
            continue;
        }
        let Some(d) = doc.child_opt(sc, a, "SubjectConfirmationData")? else {
            continue;
        };
        if doc.attr(d, "Recipient") != Some(cfg.sp_acs_url.as_str()) {
            continue;
        }
        let Some(na) = doc.attr(d, "NotOnOrAfter") else {
            continue;
        };
        if check_window(
            now,
            skew,
            doc.attr(d, "NotBefore"),
            Some(na),
            "bearer confirmation",
        )
        .is_err()
        {
            continue;
        }
        bearer = Some((d, parse_time(na)?));
        break;
    }
    let (conf_data, not_on_or_after) = bearer.ok_or_else(|| {
        reject(
            "recipient",
            "no valid bearer SubjectConfirmation for this ACS",
        )
    })?;

    // Conditions: validity window and audience.
    let cond = doc.child_one(assertion, a, "Conditions")?;
    check_window(
        now,
        skew,
        doc.attr(cond, "NotBefore"),
        doc.attr(cond, "NotOnOrAfter"),
        "Conditions",
    )?;
    let restrictions = doc.children(cond, a, "AudienceRestriction");
    if restrictions.is_empty() {
        return Err(reject("audience", "no AudienceRestriction"));
    }
    for r in restrictions {
        let mut ok = false;
        for aud in doc.children(r, a, "Audience") {
            ok |= doc.leaf_text(aud)? == cfg.sp_entity_id;
        }
        if !ok {
            return Err(reject(
                "audience",
                "AudienceRestriction does not include this SP",
            ));
        }
    }

    // InResponseTo: bearer data wins; Response-level only if the Response is signed.
    let in_response_to = match (
        doc.attr(conf_data, "InResponseTo"),
        doc.attr(root, "InResponseTo"),
    ) {
        (Some(s), Some(r)) if s != r => {
            return Err(reject(
                "in_response_to",
                "InResponseTo mismatch between Response and confirmation",
            ))
        }
        (Some(s), _) => Some(s),
        (None, Some(r)) if scope == ScopeKind::Response => Some(r),
        _ => None,
    };
    if in_response_to.is_some_and(|v| v.chars().count() > MAX_IRT_CHARS) {
        return Err(reject("in_response_to", "InResponseTo too long"));
    }

    // Attributes, only Assertion/AttributeStatement/Attribute/AttributeValue.
    let (mut email, mut display_name) = (None, None);
    for stmt in doc.children(assertion, a, "AttributeStatement") {
        for attr in doc.children(stmt, a, "Attribute") {
            let kind = map_attr_name(doc.attr(attr, "Name").unwrap_or(""));
            for v in doc.children(attr, a, "AttributeValue") {
                let slot = match kind {
                    AttrKind::Email => &mut email,
                    AttrKind::DisplayName => &mut display_name,
                    AttrKind::Other => continue,
                };
                let t = doc.leaf_text(v)?;
                if slot.is_none() && !t.is_empty() {
                    *slot = Some(t.to_string());
                }
            }
        }
    }

    if name_id.is_none() && email.is_none() {
        return Err(reject(
            "nameid",
            "SAMLResponse contains neither NameID nor email attribute",
        ));
    }
    Ok(ParsedAssertion {
        name_id,
        email,
        display_name,
        in_response_to: in_response_to.map(String::from),
        assertion_id: Some(assertion_id),
        not_on_or_after: Some(not_on_or_after),
        scope,
    })
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
        .unwrap_or_else(|| format!("saml-{}", crate::crypto::rand::uuid_v4()));
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

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn internal(msg: &str) -> (StatusCode, String) {
    tracing::error!("SAML internal error: {msg}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error".to_string(),
    )
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
    use axum_extra::extract::cookie::Cookie;

    const FE: &str = "http://localhost:5173";

    #[test]
    fn relay_state_accepts_only_same_origin_paths() {
        assert_eq!(safe_relay_target("/", FE), "http://localhost:5173/");
        assert_eq!(
            safe_relay_target("/checklists?x=1", FE),
            "http://localhost:5173/checklists?x=1"
        );
        for bad in [
            "",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com",
            "javascript:alert(1)",
            "%2F%2Fevil.com",
            "/a\r\nSet-Cookie: x=1",
            "/a\nb",
            "/a\\b",
        ] {
            assert_eq!(safe_relay_target(bad, FE), FE, "{bad:?}");
        }
        let long = format!("/{}", "a".repeat(MAX_RELAY_STATE_CHARS));
        assert_eq!(safe_relay_target(&long, FE), FE);
        let ok_len = format!("/{}", "a".repeat(MAX_RELAY_STATE_CHARS - 1));
        assert_ne!(safe_relay_target(&ok_len, FE), FE);
    }

    #[test]
    fn relay_round_trip_sends_a_relative_path_and_acs_resolves_it() {
        let sent = relay_for_idp("/checklists?x=1");
        assert_eq!(sent, "/checklists?x=1");
        assert_eq!(
            acs_redirect_target(Some(&sent), FE),
            "http://localhost:5173/checklists?x=1"
        );
        assert_eq!(relay_for_idp(""), "/");
        assert_eq!(relay_for_idp("https://evil.example"), "/");
        assert_eq!(acs_redirect_target(None, FE), FE);
    }

    #[test]
    fn acs_redirect_falls_back_for_hostile_relay_state() {
        for bad in [
            "//evil.example",
            "https://evil.example",
            "/\\evil.example",
            "javascript:alert(1)",
        ] {
            assert_eq!(acs_redirect_target(Some(bad), FE), FE, "{bad}");
        }
    }

    fn st(pool: PgPool, sso: &str) -> AppSamlState {
        AppSamlState {
            pool: Arc::new(pool),
            tasks: crate::detached::Tracker::new(),
            config: Arc::new(SamlConfig {
                idp_sso_url: sso.into(),
                idp_entity_id: String::new(),
                sp_entity_id: "sp".into(),
                sp_acs_url: "http://localhost:8080/auth/saml/acs".into(),
                idp_cert_pem: None,
                frontend_url: FE.into(),
                is_production: false,
                insecure_skip_verify: false,
                clock_skew_secs: 120,
            }),
        }
    }

    fn location(r: Redirect) -> String {
        let resp = IntoResponse::into_response(r);
        resp.headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn saml_login_requires_ack_then_single_use(pool: PgPool) {
        let state = st(pool.clone(), "https://idp.example/sso");
        let q = || axum::extract::Query(LoginParams { relay_state: None });
        let (_, r) = login_handler(
            State(state.clone()),
            HeaderMap::new(),
            None,
            CookieJar::new(),
            q(),
        )
        .await
        .unwrap();
        assert_eq!(location(r), FE);

        crate::db_notice::insert_ack(
            &pool,
            "00000000-0000-4000-8000-000000000001",
            crate::api::notice::USE_NOTICE_VERSION,
            "",
            "",
            300,
        )
        .await
        .unwrap();
        let jar = CookieJar::new().add(Cookie::new(
            crate::api::notice::ACK_COOKIE,
            "00000000-0000-4000-8000-000000000001",
        ));
        let (out, r) = login_handler(
            State(state.clone()),
            HeaderMap::new(),
            None,
            jar.clone(),
            q(),
        )
        .await
        .unwrap();
        let rc = out.get(SAML_REQ_COOKIE).unwrap();
        assert_eq!(rc.value(), "00000000-0000-4000-8000-000000000001");
        assert_eq!(rc.path(), Some("/auth/saml"));
        assert_eq!(rc.http_only(), Some(true));
        let loc = location(r);
        assert!(loc.starts_with("https://idp.example/sso"));
        assert!(loc.contains("SAMLRequest="));
        let (req, consumed): (Option<String>, bool) = sqlx::query_as(
            "SELECT saml_request_id, consumed_at IS NOT NULL FROM login_notice_acks",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(req.is_some() && consumed);
        let (_, r) = login_handler(State(state), HeaderMap::new(), None, jar, q())
            .await
            .unwrap();
        assert_eq!(location(r), FE);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn saml_login_unconfigured_is_503_and_keeps_proof(pool: PgPool) {
        crate::db_notice::insert_ack(
            &pool,
            "00000000-0000-4000-8000-000000000002",
            crate::api::notice::USE_NOTICE_VERSION,
            "",
            "",
            300,
        )
        .await
        .unwrap();
        let jar = CookieJar::new().add(Cookie::new(
            crate::api::notice::ACK_COOKIE,
            "00000000-0000-4000-8000-000000000002",
        ));
        let r = login_handler(
            State(st(pool.clone(), "")),
            HeaderMap::new(),
            None,
            jar,
            axum::extract::Query(LoginParams { relay_state: None }),
        )
        .await;
        assert_eq!(r.err().map(|e| e.0), Some(StatusCode::SERVICE_UNAVAILABLE));
        let consumed: bool =
            sqlx::query_scalar("SELECT consumed_at IS NOT NULL FROM login_notice_acks")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!consumed);
    }

    // ── process_saml_response: signed-scope, structure and validity ──

    use crate::api::saml_verify::fixtures::{key, Fx, Layout, ACS, SP};

    fn now() -> DateTime<Utc> {
        "2030-01-01T00:00:00Z".parse().unwrap()
    }
    fn cfg() -> SamlConfig {
        SamlConfig {
            idp_sso_url: "https://idp.example/sso".into(),
            idp_entity_id: String::new(),
            sp_entity_id: SP.into(),
            sp_acs_url: ACS.into(),
            idp_cert_pem: Some(key().0.clone()),
            frontend_url: FE.into(),
            is_production: false,
            insecure_skip_verify: false,
            clock_skew_secs: 120,
        }
    }
    fn dev_cfg() -> SamlConfig {
        SamlConfig {
            insecure_skip_verify: true,
            idp_cert_pem: None,
            ..cfg()
        }
    }
    fn ok(fx: &Fx) -> ParsedAssertion {
        process_saml_response(&fx.build(), &cfg(), now()).unwrap()
    }
    fn bad(fx: &Fx) -> String {
        format!(
            "{:#}",
            process_saml_response(&fx.build(), &cfg(), now()).expect_err("rejected")
        )
    }

    #[test]
    fn each_signed_layout_yields_identity() {
        for l in [Layout::Assertion, Layout::Response, Layout::Both] {
            let p = ok(&Fx::new(l));
            assert_eq!(p.name_id.as_deref(), Some("alice@example.com"));
            assert_eq!(p.email.as_deref(), Some("alice@example.com"));
            assert_eq!(p.display_name.as_deref(), Some("Alice Example"));
            assert_eq!(p.in_response_to.as_deref(), Some("_req1"));
            assert_eq!(p.assertion_id.as_deref(), Some("AS1"));
        }
    }

    #[test]
    fn poc_forged_assertion_is_rejected_end_to_end() {
        let xml = Fx::new(Layout::Response).build().replace(
            "</samlp:Response>",
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="EVIL"><saml:Subject><saml:NameID>admin@victim.example</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#,
        );
        assert!(process_saml_response(&xml, &cfg(), now()).is_err());
        let xml = Fx::new(Layout::Assertion).build().replace(
            "</samlp:Response>",
            r#"<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">admin@victim.example</saml:NameID></samlp:Response>"#,
        );
        assert!(process_saml_response(&xml, &cfg(), now()).is_err());
    }

    #[test]
    fn unsigned_response_is_rejected_without_dev_flag() {
        assert!(bad(&Fx::new(Layout::Unsigned)).contains("no Signature"));
        let mut c = cfg();
        c.idp_cert_pem = None;
        assert!(process_saml_response(&Fx::new(Layout::Assertion).build(), &c, now()).is_err());
        // Dev flag accepts the unsigned document but still runs all checks.
        assert!(
            process_saml_response(&Fx::new(Layout::Unsigned).build(), &dev_cfg(), now()).is_ok()
        );
        let mut fx = Fx::new(Layout::Unsigned);
        fx.audience = "other".into();
        assert!(process_saml_response(&fx.build(), &dev_cfg(), now()).is_err());
        let mut prod = dev_cfg();
        prod.is_production = true;
        assert!(process_saml_response(&Fx::new(Layout::Unsigned).build(), &prod, now()).is_err());
    }

    #[test]
    fn conditions_window_boundaries_with_skew() {
        let mut fx = Fx::new(Layout::Assertion);
        fx.cond_nooa = "2029-12-31T23:58:01Z".into(); // + 120s skew is just after now
        ok(&fx);
        fx.cond_nooa = "2029-12-31T23:58:00Z".into(); // exactly now: expired
        assert!(bad(&fx).contains("expired"));
        let mut fx = Fx::new(Layout::Assertion);
        fx.cond_nb = "2030-01-01T00:02:00Z".into(); // now + skew == nb: ok
        ok(&fx);
        fx.cond_nb = "2030-01-01T00:02:01Z".into();
        assert!(bad(&fx).contains("not yet valid"));
        let mut fx = Fx::new(Layout::Assertion);
        fx.cond_nb = "garbage".into();
        assert!(process_saml_response(&fx.build(), &cfg(), now()).is_err());
    }

    #[test]
    fn bearer_confirmation_is_required_and_checked() {
        let mut fx = Fx::new(Layout::Assertion);
        fx.bearer_nooa = "2029-12-31T23:58:00Z".into();
        assert!(bad(&fx).contains("bearer"));
        let mut fx = Fx::new(Layout::Assertion);
        fx.recipient = "http://evil.example/acs".into();
        assert!(bad(&fx).contains("bearer"));
    }

    #[test]
    fn audience_destination_status_issuer_are_enforced() {
        let mut fx = Fx::new(Layout::Assertion);
        fx.audience = "http://other/sp".into();
        assert!(bad(&fx).contains("Audience"));
        let xml = Fx::new(Layout::Unsigned).build().replace(
            "<saml:AudienceRestriction><saml:Audience>http://localhost:5173/saml/sp</saml:Audience></saml:AudienceRestriction>", "");
        assert!(process_saml_response(&xml, &dev_cfg(), now()).is_err());
        let mut fx = Fx::new(Layout::Response);
        fx.destination = Some("http://evil.example/acs".into());
        assert!(bad(&fx).contains("Destination"));
        let mut fx = Fx::new(Layout::Assertion);
        fx.status = "urn:oasis:names:tc:SAML:2.0:status:Responder".into();
        assert!(bad(&fx).contains("status"));
        let mut c = cfg();
        c.idp_entity_id = "idp".into();
        assert!(process_saml_response(&Fx::new(Layout::Assertion).build(), &c, now()).is_ok());
        c.idp_entity_id = "someone-else".into();
        assert!(process_saml_response(&Fx::new(Layout::Assertion).build(), &c, now()).is_err());
    }

    #[test]
    fn duplicate_nameid_and_encrypted_assertion_are_rejected() {
        let xml = Fx::new(Layout::Unsigned).build().replace(
            "<saml:NameID>alice@example.com</saml:NameID>",
            "<saml:NameID>alice@example.com</saml:NameID><saml:NameID>admin@x</saml:NameID>",
        );
        assert!(process_saml_response(&xml, &dev_cfg(), now()).is_err());
        let xml = Fx::new(Layout::Unsigned).build().replace(
            "</samlp:Response>", "<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/></samlp:Response>");
        assert!(process_saml_response(&xml, &dev_cfg(), now()).is_err());
    }

    #[test]
    fn email_fallback_when_nameid_absent() {
        let xml = Fx::new(Layout::Unsigned)
            .build()
            .replace("<saml:NameID>alice@example.com</saml:NameID>", "");
        let p = process_saml_response(&xml, &dev_cfg(), now()).unwrap();
        assert_eq!(p.name_id, None);
        assert_eq!(pick_identity(&p).1, "alice@example.com");
    }

    #[test]
    fn in_response_to_follows_verified_scope() {
        let mut fx = Fx::new(Layout::Assertion);
        fx.resp_irt = Some("_evil".into());
        fx.sub_irt = None;
        assert_eq!(ok(&fx).in_response_to, None);
        fx.layout = Layout::Response;
        assert_eq!(ok(&fx).in_response_to.as_deref(), Some("_evil"));
        let mut fx = Fx::new(Layout::Both);
        fx.sub_irt = Some("_a".into());
        fx.resp_irt = Some("_b".into());
        assert!(bad(&fx).contains("mismatch"));
        let mut fx = Fx::new(Layout::Assertion);
        fx.sub_irt = Some("x".repeat(129));
        fx.resp_irt = None;
        assert!(bad(&fx).contains("too long"));
    }

    #[test]
    fn skip_verify_refuses_to_start_in_production() {
        for env in ["production", " Production ", "PRODUCTION"] {
            assert!(
                resolve_skip_verify(Some(env), Some("true")).is_err(),
                "{env}"
            );
        }
        assert!(!resolve_skip_verify(Some("production"), None).unwrap());
        assert!(resolve_skip_verify(Some("development"), Some("true")).unwrap());
        assert!(!resolve_skip_verify(None, Some("nope")).unwrap());
    }

    #[test]
    fn skew_is_clamped() {
        assert_eq!(resolve_skew(None), 120);
        assert_eq!(resolve_skew(Some("9999")), 300);
        assert_eq!(resolve_skew(Some("-5")), 0);
        assert_eq!(resolve_skew(Some("x")), 120);
        assert_eq!(resolve_skew(Some(" 30 ")), 30);
    }

    fn code(xml: &str) -> &'static str {
        code_of(&process_saml_response(xml, &cfg(), now()).expect_err("rejected"))
    }

    #[test]
    fn reason_codes_are_typed_not_text_derived() {
        // Every parse failure is xml_structure, even when the echoed text looks like another class.
        let dup = Fx::new(Layout::Unsigned)
            .build()
            .replace(r#"ID="RS1""#, r#"ID="unsupported SignatureMethod""#)
            .replace(r#"ID="AS1""#, r#"ID="unsupported SignatureMethod""#);
        assert_eq!(code(&dup), "xml_structure");
        let e = SamlDoc::parse("<samlp:Response\x1b\nFAKE/>").unwrap_err();
        assert_eq!(code_of(&tag("xml_structure", e)), "xml_structure");
        assert_eq!(code(&Fx::new(Layout::Unsigned).build()), "signature");
        let mut fx = Fx::new(Layout::Assertion);
        fx.audience = "x".into();
        assert_eq!(code(&fx.build()), "audience");
        fx = Fx::new(Layout::Assertion);
        fx.cond_nooa = "2020-01-01T00:00:00Z".into();
        assert_eq!(code(&fx.build()), "time_window");
        fx = Fx::new(Layout::Assertion);
        fx.recipient = "x".into();
        assert_eq!(code(&fx.build()), "recipient");
        assert_eq!(code_of(&anyhow!("anything")), "invalid_response");
        let d = sanitize_detail(&format!("a\nb\x1b[2J{}", "z".repeat(500)));
        assert!(!d.chars().any(|c| c.is_control()) && d.chars().count() <= 200);
    }

    fn acs_state() -> AppSamlState {
        // Lazy pool: never connected, since the limited path returns before any DB use.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://u:p@127.0.0.1:1/x")
            .unwrap();
        AppSamlState {
            pool: Arc::new(pool),
            tasks: crate::detached::Tracker::new(),
            config: Arc::new(cfg()),
        }
    }
    fn form(b64: &str) -> AcsForm {
        AcsForm {
            saml_response: b64.into(),
            relay_state: None,
        }
    }

    #[tokio::test]
    async fn acs_is_rate_limited_per_ip_without_a_session() {
        let limiter = crate::api::rate_limit::PreAuthLimiter::from_vars(Some("2"), Some("1"));
        let state = acs_state();
        let peer = |o: u8| Some(std::net::SocketAddr::from(([203, 0, 113, o], 4000)));
        let headers = HeaderMap::new();
        let call = |o: u8| {
            acs_with_limiter(
                &limiter,
                &state,
                &headers,
                peer(o),
                CookieJar::new(),
                form("!!bad!!"),
            )
        };
        for _ in 0..2 {
            assert_eq!(
                call(1).await.err().map(|e| e.0),
                Some(StatusCode::UNAUTHORIZED)
            );
        }
        let r = call(1).await;
        assert_eq!(
            r.as_ref().err().map(|e| e.0),
            Some(StatusCode::TOO_MANY_REQUESTS)
        );
        assert!(r.is_err()); // Err carries no CookieJar, so no stig_session is set
                             // A different IP has its own budget.
        assert_eq!(
            call(2).await.err().map(|e| e.0),
            Some(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn acs_rejects_oversized_field_before_decoding() {
        let limiter = crate::api::rate_limit::PreAuthLimiter::from_vars(Some("100"), Some("100"));
        let big = "!".repeat(MAX_RESPONSE_B64 + 1);
        let jar = CookieJar::new().add(axum_extra::extract::cookie::Cookie::new(
            SAML_REQ_COOKIE,
            "x",
        ));
        let r = acs_with_limiter(
            &limiter,
            &acs_state(),
            &HeaderMap::new(),
            None,
            jar,
            form(&big),
        )
        .await;
        let (code, jar, msg) = r.err().unwrap();
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert_eq!(msg, "SAML authentication failed");
        assert!(jar.get(SAML_REQ_COOKIE).is_none(), "request cookie cleared");
    }

    #[test]
    fn oversized_field_is_refused_before_base64_is_attempted() {
        let e = decode_saml_response(&"!".repeat(MAX_RESPONSE_B64 + 1)).unwrap_err();
        assert_eq!(format!("{e:#}"), FIELD_TOO_LONG);
        let e = decode_saml_response(&"!".repeat(MAX_RESPONSE_B64)).unwrap_err();
        assert!(format!("{e:#}").contains("not base64"));
        let n = (MAX_RESPONSE_B64 / 4 + 2) * 4;
        let e = decode_saml_response(&"A".repeat(n)).unwrap_err();
        assert_eq!(format!("{e:#}"), FIELD_TOO_LONG);
    }

    #[test]
    fn decode_accepts_wrapped_base64_and_rejects_garbage() {
        let wrapped = format!(
            "{}\r\n{}",
            B64.encode("<a/>").get(..4).unwrap(),
            B64.encode("<a/>").get(4..).unwrap()
        );
        assert_eq!(decode_saml_response(&wrapped).unwrap(), "<a/>");
        assert!(decode_saml_response("!!not-base64!!").is_err());
        assert!(decode_saml_response(&B64.encode([0xffu8, 0xfe])).is_err());
    }

    #[test]
    fn from_env_refuses_skip_verify_in_production_and_bad_certs() {
        let lk = |pairs: Vec<(&'static str, String)>| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())
        };
        let prod_skip = vec![
            ("STIG_ENV", " Production".to_string()),
            ("SAML_INSECURE_SKIP_VERIFY", "true".to_string()),
        ];
        assert!(SamlConfig::from_lookup(FE, lk(prod_skip)).is_err());
        let bad = vec![
            ("SAML_IDP_SSO_URL", "https://idp.example/sso".to_string()),
            (
                "SAML_IDP_CERT_PEM",
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----".to_string(),
            ),
        ];
        assert!(SamlConfig::from_lookup(FE, lk(bad)).is_err());
        let good = vec![
            ("SAML_IDP_SSO_URL", "https://idp.example/sso".to_string()),
            ("SAML_IDP_CERT_PEM", key().0.clone()),
        ];
        assert!(SamlConfig::from_lookup(FE, lk(good)).is_ok());
    }

    #[test]
    fn missing_recipient_audience_and_optional_destination() {
        let mut fx = Fx::new(Layout::Assertion);
        fx.destination = None;
        ok(&fx); // Destination is optional
                 // Layout::Both signs the Response too; remove Audience from the signed Assertion.
        let fx = Fx::new(Layout::Unsigned);
        let no_aud = fx.build().replace(
            "<saml:Audience>http://localhost:5173/saml/sp</saml:Audience>",
            "",
        );
        let e = process_saml_response(&no_aud, &dev_cfg(), now()).unwrap_err();
        assert_eq!(code_of(&e), "audience");
        let no_rcp = fx.build().replace(&format!(" Recipient=\"{ACS}\""), "");
        let e = process_saml_response(&no_rcp, &dev_cfg(), now()).unwrap_err();
        assert_eq!(code_of(&e), "recipient");
    }

    // ── ACS AC-8 binding ──

    fn signed_b64(irt: Option<&str>) -> String {
        let mut fx = Fx::new(Layout::Both);
        fx.cond_nb = "2020-01-01T00:00:00Z".into();
        fx.cond_nooa = "2099-01-01T00:00:00Z".into();
        fx.bearer_nooa = "2099-01-01T00:00:00Z".into();
        fx.resp_irt = irt.map(String::from);
        fx.sub_irt = irt.map(String::from);
        B64.encode(fx.build())
    }

    fn acs_ready(pool: PgPool) -> AppSamlState {
        AppSamlState {
            pool: Arc::new(pool),
            tasks: crate::detached::Tracker::new(),
            config: Arc::new(cfg()),
        }
    }

    #[allow(clippy::result_large_err)]
    async fn acs(
        state: &AppSamlState,
        jar: CookieJar,
        b64: &str,
    ) -> Result<(CookieJar, Redirect), (StatusCode, CookieJar, String)> {
        let limiter = crate::api::rate_limit::PreAuthLimiter::from_vars(Some("100"), Some("100"));
        acs_with_limiter(&limiter, state, &HeaderMap::new(), None, jar, form(b64)).await
    }

    async fn counts(pool: &PgPool) -> (i64, i64, i64) {
        let s: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(pool)
            .await
            .unwrap();
        let a: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE action='auth.notice_ack' AND outcome='ok'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        let k: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM login_notice_acks")
            .fetch_one(pool)
            .await
            .unwrap();
        (s, a, k)
    }

    async fn started_login(pool: &PgPool, id: &str, req: &str) {
        crate::db_notice::insert_ack(
            pool,
            id,
            crate::api::notice::USE_NOTICE_VERSION,
            "",
            "",
            300,
        )
        .await
        .unwrap();
        crate::db_notice::consume_ack(
            pool,
            id,
            crate::api::notice::USE_NOTICE_VERSION,
            &LoginBinding::Saml { request_id: req },
        )
        .await
        .unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn acs_requires_bound_ack_and_is_single_use(pool: PgPool) {
        let (cap, _g) = crate::api::audit_capture::capture();
        let state = acs_ready(pool.clone());
        let id = "00000000-0000-4000-8000-0000000000f1";
        let other = "00000000-0000-4000-8000-0000000000f2";
        started_login(&pool, id, "_req1").await;
        // As the extractor builds it: from the request's Cookie header.
        let cookie = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(
                "cookie",
                axum::http::HeaderValue::from_str(&format!("{SAML_REQ_COOKIE}={v}")).unwrap(),
            );
            CookieJar::from_headers(&h)
        };
        let cleared = |jar: CookieJar| {
            IntoResponse::into_response((jar, ()))
                .headers()
                .get_all("set-cookie")
                .iter()
                .any(|h| {
                    h.to_str()
                        .is_ok_and(|v| v.starts_with("stig_saml_req=;") && v.contains("Max-Age=0"))
                })
        };
        // Exactly one new audit line since the last clear: (action, outcome, reason).
        let one = || {
            let l = cap.take_one();
            let g = |k: &str| l.get(k).cloned().unwrap_or_default();
            (g("action"), g("outcome"), g("reason"))
        };
        let denied = |reason: &str| {
            (
                "auth.saml_acs".to_string(),
                "denied".to_string(),
                reason.to_string(),
            )
        };

        // IdP-initiated (no InResponseTo), even with a cookie.
        cap.clear();
        let r = acs(&state, cookie(id), &signed_b64(None))
            .await
            .err()
            .unwrap();
        assert_eq!(r.0, StatusCode::UNAUTHORIZED);
        assert!(cleared(r.1));
        assert_eq!(one(), denied("unsolicited"));
        // Valid response, no cookie / junk cookie / cookie for a different ack.
        for (jar, reason, clears) in [
            (CookieJar::new(), "no_request_cookie", false),
            (cookie("junk"), "no_request_cookie", true),
            (cookie(other), "ack_not_claimed", true),
        ] {
            cap.clear();
            let r = acs(&state, jar, &signed_b64(Some("_req1")))
                .await
                .err()
                .unwrap();
            assert_eq!(r.0, StatusCode::UNAUTHORIZED);
            assert_eq!(cleared(r.1), clears, "{reason}");
            assert_eq!(one(), denied(reason));
        }
        // Wrong InResponseTo for the right cookie.
        cap.clear();
        let r = acs(&state, cookie(id), &signed_b64(Some("_zzz")))
            .await
            .err()
            .unwrap();
        assert_eq!(r.0, StatusCode::UNAUTHORIZED);
        assert_eq!(one(), denied("ack_not_claimed"));
        assert_eq!(counts(&pool).await, (0, 0, 1));

        // Matching cookie + InResponseTo: session, audit row, ack gone, cookie cleared.
        cap.clear();
        let (jar, _) = acs(&state, cookie(id), &signed_b64(Some("_req1")))
            .await
            .unwrap();
        assert!(jar.get(SESSION_COOKIE).is_some());
        assert_eq!(counts(&pool).await, (1, 1, 0));
        let last = cap.take_one();
        assert_eq!(
            (last["action"].as_str(), last["outcome"].as_str()),
            ("auth.saml_acs", "success")
        );
        assert!(!last["user_id"].is_empty());
        // Replay.
        cap.clear();
        let r = acs(&state, cookie(id), &signed_b64(Some("_req1")))
            .await
            .err()
            .unwrap();
        assert_eq!(r.0, StatusCode::UNAUTHORIZED);
        assert_eq!(one(), denied("ack_not_claimed"));
        assert_eq!(counts(&pool).await, (1, 1, 0));
    }

    #[tokio::test]
    async fn acs_claim_db_error_is_logged_as_claim_error() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(500))
            .connect_lazy("postgres://u:p@127.0.0.1:1/x")
            .unwrap();
        let state = AppSamlState {
            pool: Arc::new(pool),
            tasks: crate::detached::Tracker::new(),
            config: Arc::new(cfg()),
        };
        let (cap, _g) = crate::api::audit_capture::capture();
        let mut h = HeaderMap::new();
        let id = crate::crypto::rand::uuid_v4();
        h.insert(
            "cookie",
            axum::http::HeaderValue::from_str(&format!("{SAML_REQ_COOKIE}={id}")).unwrap(),
        );
        cap.clear();
        let r = acs(
            &state,
            CookieJar::from_headers(&h),
            &signed_b64(Some("_req1")),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(r.0, StatusCode::UNAUTHORIZED);
        assert_eq!(cap.take_one()["reason"], "claim_error");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn notice_ack_survives_the_acs_future_being_dropped(pool: PgPool) {
        let state = acs_ready(pool.clone());
        let id = "00000000-0000-4000-8000-0000000000f3";
        started_login(&pool, id, "_req1").await;
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            axum::http::HeaderValue::from_str(&format!("{SAML_REQ_COOKIE}={id}")).unwrap(),
        );
        crate::detached::abort_once_spawned(
            &state.tasks,
            acs(
                &state,
                CookieJar::from_headers(&h),
                &signed_b64(Some("_req1")),
            ),
        )
        .await;
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        let (sessions, acks, _) = counts(&pool).await;
        assert_eq!((sessions, acks), (1, 1));
    }
}
