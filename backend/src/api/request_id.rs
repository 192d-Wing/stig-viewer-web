//! `X-Request-Id` middleware + the `RequestId` extension.
//!
//! Reads an inbound `X-Request-Id` header if the client supplied one
//! (callers, load balancers, correlated tracing), otherwise generates a
//! fresh v4 UUID. Wraps the request in a tracing span so downstream log
//! lines inherit the id, and echoes the id back on the response so the
//! client can correlate.

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use tracing::Instrument;
use uuid::Uuid;

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone, Copy, Debug)]
pub struct RequestId(pub Uuid);

impl RequestId {
    pub fn as_string(&self) -> String {
        self.0.to_string()
    }
}

pub async fn with_request_id(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);

    req.extensions_mut().insert(RequestId(id));

    let span = tracing::info_span!("http", request_id = %id);
    let fut = async move { next.run(req).await };
    let mut res = fut.instrument(span).await;

    if let Ok(hv) = HeaderValue::from_str(&id.to_string()) {
        res.headers_mut().insert(&REQUEST_ID_HEADER, hv);
    }
    res
}
