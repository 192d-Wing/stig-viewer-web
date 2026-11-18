//! Per-request context for audit events.
//!
//! Sits inside the auth layer (so `AuthUser` is populated). It builds a
//! [`RequestCtx`] request extension and echoes the generated id in the
//! `X-Request-Id` response header. An inbound `X-Request-Id` is never trusted:
//! the id is always a fresh UUID v4.

use std::sync::{atomic::AtomicBool, Arc};

use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
    Extension,
};

use std::net::SocketAddr;

use crate::api::auth::AuthUser;
use crate::api::notice::notice_ip;

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Debug, Clone)]
pub struct RequestCtx {
    pub request_id: String,
    /// Canonical client IP from `notice::notice_ip`: the socket peer, or the
    /// trusted `X-Forwarded-For` hop when `STIG_TRUST_PROXY_HEADERS` is on.
    /// `None` when neither yields a valid IP.
    pub source_ip: Option<String>,
    pub role: String,
    /// Set by `db_audit::record_or_log` when a handler has recorded its own
    /// event for this request, so a central recorder does not add a second.
    pub audited: Arc<AtomicBool>,
}

impl RequestCtx {
    pub fn new(headers: &axum::http::HeaderMap, peer: Option<SocketAddr>, role: &str) -> Self {
        RequestCtx {
            request_id: uuid::Uuid::new_v4().to_string(),
            source_ip: Some(notice_ip(headers, peer)).filter(|ip| !ip.is_empty()),
            role: role.to_string(),
            audited: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub async fn request_ctx(
    Extension(user): Extension<AuthUser>,
    peer: Option<ConnectInfo<SocketAddr>>,
    mut req: Request,
    next: Next,
) -> Response {
    let ctx = RequestCtx::new(req.headers(), peer.map(|p| p.0), &user.role);
    let id = ctx.request_id.clone();
    req.extensions_mut().insert(ctx);
    let mut resp = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn id_is_generated_and_ignores_inbound_header() {
        let mut h = HeaderMap::new();
        h.insert("x-request-id", HeaderValue::from_static("attacker-chosen"));
        let a = RequestCtx::new(&h, None, "admin");
        let b = RequestCtx::new(&h, None, "admin");
        assert_ne!(a.request_id, "attacker-chosen");
        assert_ne!(a.request_id, b.request_id);
        assert!(uuid::Uuid::parse_str(&a.request_id).is_ok());
    }

    #[test]
    fn source_ip_is_a_canonical_ip_and_never_header_text_by_default() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("evil\"; DROP TABLE x"),
        );
        h.insert("x-real-ip", HeaderValue::from_static("10.0.0.9"));
        // Without STIG_TRUST_PROXY_HEADERS the headers are not used at all.
        let c = RequestCtx::new(&h, None, "viewer");
        assert_eq!(c.source_ip, None);
        let peer: SocketAddr = "[2001:db8::1]:4433".parse().unwrap();
        let c = RequestCtx::new(&h, Some(peer), "viewer");
        assert_eq!(c.source_ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(c.role, "viewer");
    }
}
