//! Central `authz.denied` audit events.
//!
//! A response-observing middleware on the protected router: after the handler
//! (or `viewer_guard`) has answered, a 403 for which nothing was recorded
//! (`RequestCtx::audited` is still false) is written as `authz.denied` with
//! `detail = {method, route}`. `route` is the `MatchedPath` template, never the
//! raw URI, so it carries no ids or free text. 401 and 429 are not recorded.
//! Sits inside `request_ctx` and outside `viewer_guard`.

use axum::{
    extract::{MatchedPath, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    Extension, Router,
};
use serde_json::json;

use crate::api::auth::AuthUser;
use crate::api::request_ctx::RequestCtx;
use crate::db_audit::{record_or_log, NewAuditEvent};
use crate::AppState;

const MAX_ROUTE_CHARS: usize = 128;

/// Apply the protected router's inner layers, innermost first, so the
/// request order is `rate_limit -> request_ctx -> authz_audit -> viewer_guard
/// -> handler`. `auth_middleware` (which needs the auth state) is added by the
/// caller as the outermost layer. Shared by `main` and the tests.
pub fn protected_stack(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    router
        .route_layer(middleware::from_fn(crate::api::viewer_guard::viewer_guard))
        .route_layer(middleware::from_fn_with_state(state.clone(), authz_audit))
        .route_layer(middleware::from_fn(crate::api::request_ctx::request_ctx))
        .route_layer(middleware::from_fn(crate::api::rate_limit::rate_limit))
}

/// The method as recorded: the standard ones, else `OTHER`, so a client-chosen
/// extension method cannot mint unlimited distinct audit keys.
fn normalized_method(m: &axum::http::Method) -> &'static str {
    use axum::http::Method;
    match *m {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    }
}

pub async fn authz_audit(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    req: Request,
    next: Next,
) -> Response {
    let method = normalized_method(req.method());
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().chars().take(MAX_ROUTE_CHARS).collect::<String>())
        .unwrap_or_else(|| "unmatched".to_string());
    let resp = next.run(req).await;
    if resp.status() == StatusCode::FORBIDDEN
        && !ctx.audited.load(std::sync::atomic::Ordering::Relaxed)
    {
        // Detached from the connection: a client that hangs up must not
        // cancel the write. The handle is awaited so the response still
        // waits for it (bounded by `WRITE_TIMEOUT` inside `record_or_log`).
        let pool = state.pool.clone();
        let (user_id, ctx) = (user.id.clone(), ctx.clone());
        let detail = json!({ "method": method, "route": route });
        let _ = tokio::spawn(async move {
            record_or_log(
                pool.as_ref(),
                NewAuditEvent {
                    user_id: &user_id,
                    action: "authz.denied",
                    outcome: "denied",
                    asset_id: None,
                    checklist_id: None,
                    stig_id: None,
                    detail,
                    ctx: Some(&ctx),
                },
            )
            .await
        })
        .await;
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{app_state, auth, seed_user};
    use axum::{
        middleware,
        routing::{get, post},
        Router,
    };
    use sqlx::PgPool;

    async fn own_denial(
        State(state): State<AppState>,
        Extension(ctx): Extension<RequestCtx>,
    ) -> StatusCode {
        record_or_log(
            state.pool.as_ref(),
            NewAuditEvent {
                user_id: "u1",
                action: "checklist.save",
                outcome: "denied",
                asset_id: None,
                checklist_id: None,
                stig_id: None,
                detail: json!({ "reason": "x" }),
                ctx: Some(&ctx),
            },
        )
        .await;
        StatusCode::FORBIDDEN
    }

    /// The production inner layer stack (`protected_stack`) around test
    /// handlers, with the caller's `AuthUser` injected outermost.
    fn app(state: AppState, user_id: &str, role: &str) -> Router {
        let user = auth(user_id, role);
        protected_stack(
            Router::new()
                .route("/api/things/:id", post(|| async { StatusCode::OK }))
                .route("/api/own", post(own_denial))
                .route("/api/unauth", get(|| async { StatusCode::UNAUTHORIZED }))
                .route("/api/ok", get(|| async { StatusCode::OK })),
            &state,
        )
        .route_layer(middleware::from_fn(move |mut req: Request, next: Next| {
            let user = user.clone();
            async move {
                req.extensions_mut().insert(user);
                next.run(req).await
            }
        }))
        .with_state(state)
    }

    /// Serve the router on an ephemeral loopback port.
    struct Server(String);

    async fn serve(app: Router) -> Server {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        Server(format!("http://{addr}"))
    }

    async fn send(app: &Server, method: &str, uri: &str) -> StatusCode {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let status = reqwest::Client::new()
            .request(m, format!("{}{uri}", app.0))
            .send()
            .await
            .unwrap()
            .status();
        StatusCode::from_u16(status.as_u16()).unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_403_is_recorded_once_with_the_route_template(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let (state, _dir) = app_state(pool.clone());
        let app = serve(app(state, "u1", "viewer")).await;
        assert_eq!(
            send(&app, "POST", "/api/things/secret-id-123?q=free%20text").await,
            StatusCode::FORBIDDEN
        );
        let got: Vec<(String, String, String, Option<String>)> =
            sqlx::query_as("SELECT action, outcome, detail::text, user_role FROM audit_events")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].0.as_str(), got[0].1.as_str()),
            ("authz.denied", "denied")
        );
        let d: serde_json::Value = serde_json::from_str(&got[0].2).unwrap();
        assert_eq!(d, json!({ "method": "POST", "route": "/api/things/:id" }));
        assert!(!got[0].2.contains("secret-id-123"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_handler_that_recorded_its_own_denial_is_not_recorded_twice(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let (state, _dir) = app_state(pool.clone());
        let app = serve(app(state, "u1", "author")).await;
        assert_eq!(send(&app, "POST", "/api/own").await, StatusCode::FORBIDDEN);
        let got: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_events")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(got, ["checklist.save"]);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn other_statuses_are_not_recorded_and_repeats_collapse(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let (state, _dir) = app_state(pool.clone());
        let app = serve(app(state, "u1", "viewer")).await;
        assert_eq!(
            send(&app, "GET", "/api/unauth").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(send(&app, "GET", "/api/ok").await, StatusCode::OK);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        for _ in 0..3 {
            send(&app, "POST", "/api/things/a").await;
            send(&app, "POST", "/api/things/b").await;
        }
        let got: Vec<i32> = sqlx::query_scalar("SELECT repeat_count FROM audit_events")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(got, [6]);
    }

    #[test]
    fn methods_are_normalised() {
        use axum::http::Method;
        assert_eq!(normalized_method(&Method::PATCH), "PATCH");
        assert_eq!(
            normalized_method(&Method::from_bytes(b"BREW").unwrap()),
            "OTHER"
        );
        assert_eq!(normalized_method(&Method::TRACE), "OTHER");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn extension_methods_share_one_key_and_a_429_is_not_recorded(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let (state, _dir) = app_state(pool.clone());
        // viewer_guard answers 403 for any non-GET method, extension ones included.
        let viewer = serve(app(state.clone(), "u1", "viewer")).await;
        for m in ["BREW", "PROPFIND", "X-ONE", "X-TWO"] {
            assert_eq!(
                send(&viewer, m, "/api/things/a").await,
                StatusCode::FORBIDDEN
            );
        }
        let got: Vec<(String, i32)> =
            sqlx::query_as("SELECT detail->>'method', repeat_count FROM audit_events")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(got, [("OTHER".to_string(), 4)]);

        // An author past the burst gets 429 from rate_limit, which is not recorded.
        seed_user(&pool, "rl-author-pkg6").await;
        let author = serve(app(state, "rl-author-pkg6", "author")).await;
        let mut limited = 0;
        for _ in 0..60 {
            if send(&author, "POST", "/api/things/a").await == StatusCode::TOO_MANY_REQUESTS {
                limited += 1;
            }
        }
        assert!(limited > 0, "never rate limited");
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE user_id = 'rl-author-pkg6'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 0);
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(total, 1);
    }
}
