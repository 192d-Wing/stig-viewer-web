use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::api::auth::AuthUser;
use crate::AppState;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct SavedSearch {
    pub id: String,
    pub user_id: String,
    pub page: String,
    pub name: String,
    pub params: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    /// Restrict results to a single page (e.g. "myfindings"). Omit to
    /// return every saved search the caller owns.
    pub page: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    pub page: String,
    pub name: String,
    pub params: String,
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("saved_searches sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// GET /api/saved-searches?page=<page>
///
/// Returns the current user's saved searches, ordered newest first.
/// If `page` is omitted, all of the user's searches are returned.
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(params): Query<ListQuery>,
) -> Result<Json<Vec<SavedSearch>>, StatusCode> {
    let rows = sqlx::query_as::<_, SavedSearch>(
        r#"
        SELECT id, user_id, page, name, params, created_at
          FROM saved_searches
         WHERE user_id = $1
           AND ($2::text IS NULL OR page = $2)
         ORDER BY created_at DESC
        "#,
    )
    .bind(&user.id)
    .bind(params.page.as_deref())
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    Ok(Json(rows))
}

/// POST /api/saved-searches { page, name, params }
///
/// Inserts a new saved search for the current user. 400 if name or page
/// are empty after trimming. 409 if the (user, page, name) tuple is
/// already taken.
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateRequest>,
) -> Result<(StatusCode, Json<SavedSearch>), StatusCode> {
    let page = req.page.trim();
    let name = req.name.trim();
    if page.is_empty() || name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Strip a stray leading '?' so callers can pass either form.
    let params = req.params.trim().trim_start_matches('?').to_string();

    let id = uuid::Uuid::new_v4().to_string();

    let row = sqlx::query_as::<_, SavedSearch>(
        r#"
        INSERT INTO saved_searches (id, user_id, page, name, params)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, user_id, page, name, params, created_at
        "#,
    )
    .bind(&id)
    .bind(&user.id)
    .bind(page)
    .bind(name)
    .bind(&params)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.is_unique_violation() {
                return StatusCode::CONFLICT;
            }
        }
        tracing::error!("saved_searches insert failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok((StatusCode::CREATED, Json(row)))
}

/// DELETE /api/saved-searches/:id
///
/// Owner-only. Returns 204 on success, 404 if the row doesn't exist or
/// belongs to another user (we don't leak existence to non-owners).
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let res = sqlx::query("DELETE FROM saved_searches WHERE id = $1 AND user_id = $2")
        .bind(&id)
        .bind(&user.id)
        .execute(state.pool.as_ref())
        .await
        .map_err(map_sqlx)?;

    if res.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}
