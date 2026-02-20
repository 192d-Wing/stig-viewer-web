use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;

/// User record stored in request extensions after auth.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuthUser {
    pub id: String,
    pub display_name: String,
    pub email: String,
    pub role: String,
}

/// Middleware: reads `X-User-Id` header, looks up or auto-creates the user,
/// and injects `AuthUser` into request extensions.
///
/// Placeholder for OIDC/CAC — swap header check for bearer token validation later.
pub async fn auth_middleware(
    State(pool): State<Arc<PgPool>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let user_id = req
        .headers()
        .get("X-User-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if user_id.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Look up user; if not found, auto-create with 'author' role
    let user = sqlx::query_as::<_, AuthUser>("SELECT id, display_name, email, role FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = match user {
        Some(u) => u,
        None => {
            // Auto-create: use the header value as both id and display name
            sqlx::query(
                "INSERT INTO users (id, display_name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING",
            )
            .bind(&user_id)
            .bind(&user_id)
            .execute(pool.as_ref())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            AuthUser {
                id: user_id.clone(),
                display_name: user_id,
                email: String::new(),
                role: "author".to_string(),
            }
        }
    };

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}
