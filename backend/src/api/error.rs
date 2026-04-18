//! Typed HTTP errors with a structured JSON response body.
//!
//! Every error returned from an API handler should be an [`ApiError`]. The
//! [`IntoResponse`] impl converts it into a body of shape:
//!
//! ```json
//! { "error": { "code": "payload_too_large", "message": "…", "details": {…} } }
//! ```
//!
//! `code` is a stable string the frontend can branch on; `message` is
//! human-readable; `details` is an optional JSON blob for things like
//! validation specifics.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

// Some variants aren't constructed yet but define the stable error surface;
// allow dead-code until more handlers use them.
#[allow(dead_code)]
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden,
    NotFound(String),
    Conflict(String),
    PayloadTooLarge {
        message: String,
        limit_bytes: usize,
        actual_bytes: usize,
    },
    Unprocessable(String),
    TooManyRequests,
    Internal(String),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized => "unauthorized",
            ApiError::Forbidden => "forbidden",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::PayloadTooLarge { .. } => "payload_too_large",
            ApiError::Unprocessable(_) => "unprocessable_entity",
            ApiError::TooManyRequests => "too_many_requests",
            ApiError::Internal(_) => "internal_error",
        }
    }

    fn message(&self) -> String {
        match self {
            ApiError::BadRequest(m)
            | ApiError::NotFound(m)
            | ApiError::Conflict(m)
            | ApiError::Unprocessable(m) => m.clone(),
            ApiError::PayloadTooLarge { message, .. } => message.clone(),
            ApiError::Unauthorized => "authentication required".into(),
            ApiError::Forbidden => "insufficient permissions".into(),
            ApiError::TooManyRequests => "rate limit exceeded".into(),
            // Internal messages are kept server-side only; the client gets
            // a generic string so we don't leak implementation details.
            ApiError::Internal(_) => "internal server error".into(),
        }
    }

    fn details(&self) -> Option<serde_json::Value> {
        match self {
            ApiError::PayloadTooLarge {
                limit_bytes,
                actual_bytes,
                ..
            } => Some(serde_json::json!({
                "limitBytes": limit_bytes,
                "actualBytes": actual_bytes,
            })),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorInner,
}

#[derive(Serialize)]
struct ErrorInner {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Log server-side errors at error level; leave client errors at debug.
        if matches!(self, ApiError::Internal(_)) {
            tracing::error!("{:?}", self);
        } else {
            tracing::debug!("{:?}", self);
        }

        let body = ErrorBody {
            error: ErrorInner {
                code: self.code(),
                message: self.message(),
                details: self.details(),
            },
        };
        (self.status(), Json(body)).into_response()
    }
}

// ── From conversions ─────────────────────────────────────────────────────────

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(format!("{e:#}"))
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::Internal(format!("database: {e}"))
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::Internal(format!("io: {e}"))
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::Internal(format!("serde: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn response_body_contains_code_and_message() {
        let err = ApiError::BadRequest("missing field".into());
        let res = err.into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(res.into_body(), 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["code"], "bad_request");
        assert_eq!(body["error"]["message"], "missing field");
    }

    #[tokio::test]
    async fn payload_too_large_includes_size_details() {
        let err = ApiError::PayloadTooLarge {
            message: "too big".into(),
            limit_bytes: 100,
            actual_bytes: 200,
        };
        let res = err.into_response();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let bytes = to_bytes(res.into_body(), 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["details"]["limitBytes"], 100);
        assert_eq!(body["error"]["details"]["actualBytes"], 200);
    }

    #[tokio::test]
    async fn internal_message_is_not_leaked_to_client() {
        let err = ApiError::Internal("secret db schema path".into());
        let res = err.into_response();
        let bytes = to_bytes(res.into_body(), 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["message"], "internal server error");
        assert!(!body.to_string().contains("secret"));
    }
}
