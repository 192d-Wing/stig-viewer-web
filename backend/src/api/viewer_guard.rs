use axum::{
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::json;

use crate::api::auth::AuthUser;

/// Paths whose mutations are still allowed for a `viewer`.
///
/// The notifications bell calls POST `/api/notifications/mark-read` even when
/// the user is read-only — clearing the unread counter isn't a real write to
/// any audited resource, just a per-user marker. Add more entries here as
/// similar passive endpoints come up.
const VIEWER_MUTATION_ALLOWLIST: &[&str] = &["/api/notifications/mark-read"];

/// Read-only role gate.
///
/// Sits behind `auth_middleware` on the protected router so `AuthUser` is
/// already populated. Lets every GET / HEAD through. For non-GET methods,
/// short-circuits with a 403 + JSON body when the caller has the `viewer`
/// role, unless the request path is in the small allowlist above.
pub async fn viewer_guard(
    Extension(user): Extension<AuthUser>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method();
    let path = req.uri().path();

    let is_read = matches!(*method, Method::GET | Method::HEAD);
    let is_allowlisted = VIEWER_MUTATION_ALLOWLIST.iter().any(|p| path.starts_with(p));

    if user.role == "viewer" && !is_read && !is_allowlisted {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "viewer role is read-only" })),
        )
            .into_response();
    }

    next.run(req).await
}
