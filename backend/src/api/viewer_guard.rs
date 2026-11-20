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

/// Whether [`viewer_guard`] refuses this request: a `viewer` using a
/// non-read method on a path outside the allowlist. `admission` uses the same
/// predicate (and the same `uri().path()` input) so that such a request takes
/// no permit and reaches the guard's 403 and its `authz.denied` record.
pub(crate) fn denies(role: &str, method: &Method, path: &str) -> bool {
    let is_read = matches!(*method, Method::GET | Method::HEAD);
    let is_allowlisted = VIEWER_MUTATION_ALLOWLIST
        .iter()
        .any(|p| path.starts_with(p));
    role == "viewer" && !is_read && !is_allowlisted
}

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
    if denies(&user.role, req.method(), req.uri().path()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "viewer role is read-only" })),
        )
            .into_response();
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_only_viewer_mutations_outside_the_allowlist() {
        let mark = "/api/notifications/mark-read";
        let other = "/api/checklist-sets";
        let cases: &[(&str, Method, &str, bool)] = &[
            ("viewer", Method::POST, other, true),
            ("viewer", Method::PUT, other, true),
            ("viewer", Method::PATCH, other, true),
            ("viewer", Method::DELETE, other, true),
            ("viewer", Method::GET, other, false),
            ("viewer", Method::HEAD, other, false),
            // OPTIONS is not a read here: the guard's behaviour is unchanged.
            ("viewer", Method::OPTIONS, other, true),
            ("viewer", Method::POST, mark, false),
            ("viewer", Method::DELETE, mark, false),
            ("author", Method::POST, other, false),
            ("admin", Method::DELETE, other, false),
            ("admin", Method::POST, mark, false),
        ];
        for (role, method, path, want) in cases {
            assert_eq!(denies(role, method, path), *want, "{role} {method} {path}");
        }
    }
}
