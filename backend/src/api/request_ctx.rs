//! Per-request context for audit events.
//!
//! Sits inside the auth layer (so `AuthUser` is populated). It builds a
//! [`RequestCtx`] request extension and echoes the generated id in the
//! `X-Request-Id` response header. An inbound `X-Request-Id` is never trusted:
//! the id is always a fresh UUID v4.

use std::sync::{atomic::AtomicBool, Arc};

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
    Extension,
};

use crate::api::auth::{client_ip, AuthUser};

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Debug, Clone)]
pub struct RequestCtx {
    pub request_id: String,
    /// First `X-Forwarded-For` / `X-Real-IP` value, sanitised and bounded.
    /// Client-asserted unless a trusted proxy overwrites the headers.
    pub source_ip: Option<String>,
    pub role: String,
    /// Set by `db_audit::record_or_log` when a handler has recorded its own
    /// event for this request, so a central recorder does not add a second.
    pub audited: Arc<AtomicBool>,
}

impl RequestCtx {
    pub fn new(headers: &axum::http::HeaderMap, role: &str) -> Self {
        let ip = crate::db_audit::sanitize_source_ip(&client_ip(headers));
        RequestCtx {
            request_id: uuid::Uuid::new_v4().to_string(),
            source_ip: if ip.is_empty() { None } else { Some(ip) },
            role: role.to_string(),
            audited: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub async fn request_ctx(Extension(user): Extension<AuthUser>, mut req: Request, next: Next) -> Response {
    let ctx = RequestCtx::new(req.headers(), &user.role);
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
    use crate::db_audit::MAX_SOURCE_IP_CHARS;
    use axum::http::HeaderMap;

    #[test]
    fn id_is_generated_and_ignores_inbound_header() {
        let mut h = HeaderMap::new();
        h.insert("x-request-id", HeaderValue::from_static("attacker-chosen"));
        let a = RequestCtx::new(&h, "admin");
        let b = RequestCtx::new(&h, "admin");
        assert_ne!(a.request_id, "attacker-chosen");
        assert_ne!(a.request_id, b.request_id);
        assert!(uuid::Uuid::parse_str(&a.request_id).is_ok());
    }

    #[test]
    fn source_ip_comes_from_forwarding_headers_and_is_bounded() {
        let mut h = HeaderMap::new();
        assert_eq!(RequestCtx::new(&h, "viewer").source_ip, None);
        h.insert("x-real-ip", HeaderValue::from_static("10.0.0.9"));
        assert_eq!(RequestCtx::new(&h, "viewer").source_ip.as_deref(), Some("10.0.0.9"));
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7, 10.0.0.1"));
        let c = RequestCtx::new(&h, "viewer");
        assert_eq!(c.source_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(c.role, "viewer");
        h.insert("x-forwarded-for", HeaderValue::from_str(&"9".repeat(500)).unwrap());
        assert_eq!(RequestCtx::new(&h, "viewer").source_ip.unwrap().len(), MAX_SOURCE_IP_CHARS);
    }
}
