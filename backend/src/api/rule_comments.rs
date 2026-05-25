//! Per-rule threaded discussion.
//!
//! Auth-middleware-gated. Any authed user can read; only the comment's
//! author can edit or delete it.

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    Extension,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::auth::AuthUser;
use crate::AppState;

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// Scan a comment body for `@handle` tokens and return the unique handles
/// (lowercased) in order of first appearance. The handle alphabet matches
/// `[a-zA-Z0-9_.-]+` and must be preceded by start-of-string or a non-
/// alphanumeric character so we don't pick up `foo@bar.com` style strings.
fn extract_mention_handles(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let prev_ok = if i == 0 {
                true
            } else {
                let p = bytes[i - 1];
                !p.is_ascii_alphanumeric() && p != b'_'
            };
            if prev_ok {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() {
                    let c = bytes[j];
                    if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-' {
                        j += 1;
                    } else {
                        break;
                    }
                }
                if j > start {
                    let handle = body[start..j].to_ascii_lowercase();
                    if !out.contains(&handle) {
                        out.push(handle);
                    }
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Best-effort insert of `comment_mentions` rows for every distinct
/// `@handle` token in `body`. A handle matches a user whose lowercased
/// display name (with spaces stripped) equals the handle. Self-mentions
/// (mentioned_user_id == author_id) are skipped. All DB errors are
/// swallowed with a tracing warning — mentions are a notification
/// nice-to-have, not part of the comment-create contract.
async fn record_mentions(
    pool: &sqlx::PgPool,
    comment_id: &str,
    author_id: &str,
    body: &str,
) {
    let handles = extract_mention_handles(body);
    if handles.is_empty() {
        return;
    }
    for handle in handles {
        let target: Result<Option<(String,)>, _> = sqlx::query_as(
            r#"
            SELECT id FROM users
             WHERE LOWER(REPLACE(display_name, ' ', '')) = $1
             LIMIT 1
            "#,
        )
        .bind(&handle)
        .fetch_optional(pool)
        .await;
        let user_id = match target {
            Ok(Some((id,))) => id,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!("mention lookup for @{handle} failed: {e:#}");
                continue;
            }
        };
        if user_id == author_id {
            continue;
        }
        let mention_id = new_id();
        let res = sqlx::query(
            r#"
            INSERT INTO comment_mentions (id, comment_id, mentioned_user_id)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(&mention_id)
        .bind(comment_id)
        .bind(&user_id)
        .execute(pool)
        .await;
        if let Err(e) = res {
            tracing::warn!("mention insert for @{handle} failed: {e:#}");
        }
    }
}

fn err_500(e: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::error!("{e:#}");
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn err_400(msg: &str) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.to_string())
}

fn err_403(msg: &str) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, msg.to_string())
}

fn err_404() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "Not found".to_string())
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct RuleCommentRow {
    pub id: String,
    pub checklist_id: String,
    pub rule_id: String,
    pub user_id: String,
    pub user_name: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub edited_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionSummary {
    pub count: i64,
    pub mine: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionsBlock {
    pub thumbs_up: ReactionSummary,
    pub check: ReactionSummary,
    pub question: ReactionSummary,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleCommentWithReactions {
    pub id: String,
    pub checklist_id: String,
    pub rule_id: String,
    pub user_id: String,
    pub user_name: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub edited_at: Option<DateTime<Utc>>,
    pub reactions: ReactionsBlock,
}

#[derive(Debug, Deserialize)]
pub struct CommentBody {
    pub body: String,
}

#[derive(Debug, Deserialize)]
pub struct ReactionBody {
    pub reaction: String,
}

/// Allowed reaction-type values. The schema is open (TEXT) but the API
/// is the gatekeeper so that adding a new reaction type doesn't need a
/// migration.
const ALLOWED_REACTIONS: &[&str] = &["thumbs_up", "check", "question"];

fn is_allowed_reaction(value: &str) -> bool {
    ALLOWED_REACTIONS.iter().any(|r| *r == value)
}

// ── List ───────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct ListCommentRow {
    id: String,
    checklist_id: String,
    rule_id: String,
    user_id: String,
    user_name: String,
    body: String,
    created_at: DateTime<Utc>,
    edited_at: Option<DateTime<Utc>>,
    thumbs_up_count: Option<i64>,
    thumbs_up_mine: Option<bool>,
    check_count: Option<i64>,
    check_mine: Option<bool>,
    question_count: Option<i64>,
    question_mine: Option<bool>,
}

pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((checklist_id, rule_id)): Path<(String, String)>,
) -> Result<Json<Vec<RuleCommentWithReactions>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, ListCommentRow>(
        r#"
        SELECT c.id, c.checklist_id, c.rule_id, c.user_id,
               u.display_name AS user_name,
               c.body, c.created_at, c.edited_at,
               COUNT(r.*) FILTER (WHERE r.reaction = 'thumbs_up') AS thumbs_up_count,
               COALESCE(BOOL_OR(r.reaction = 'thumbs_up' AND r.user_id = $3), false) AS thumbs_up_mine,
               COUNT(r.*) FILTER (WHERE r.reaction = 'check') AS check_count,
               COALESCE(BOOL_OR(r.reaction = 'check' AND r.user_id = $3), false) AS check_mine,
               COUNT(r.*) FILTER (WHERE r.reaction = 'question') AS question_count,
               COALESCE(BOOL_OR(r.reaction = 'question' AND r.user_id = $3), false) AS question_mine
        FROM rule_comments c
        JOIN users u ON u.id = c.user_id
        LEFT JOIN comment_reactions r ON r.comment_id = c.id
        WHERE c.checklist_id = $1 AND c.rule_id = $2
        GROUP BY c.id, u.display_name
        ORDER BY c.created_at DESC
        "#,
    )
    .bind(&checklist_id)
    .bind(&rule_id)
    .bind(&user.id)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(err_500)?;

    let out: Vec<RuleCommentWithReactions> = rows
        .into_iter()
        .map(|r| RuleCommentWithReactions {
            id: r.id,
            checklist_id: r.checklist_id,
            rule_id: r.rule_id,
            user_id: r.user_id,
            user_name: r.user_name,
            body: r.body,
            created_at: r.created_at,
            edited_at: r.edited_at,
            reactions: ReactionsBlock {
                thumbs_up: ReactionSummary {
                    count: r.thumbs_up_count.unwrap_or(0),
                    mine: r.thumbs_up_mine.unwrap_or(false),
                },
                check: ReactionSummary {
                    count: r.check_count.unwrap_or(0),
                    mine: r.check_mine.unwrap_or(false),
                },
                question: ReactionSummary {
                    count: r.question_count.unwrap_or(0),
                    mine: r.question_mine.unwrap_or(false),
                },
            },
        })
        .collect();

    Ok(Json(out))
}

// ── Create ─────────────────────────────────────────────────────────────────

pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((checklist_id, rule_id)): Path<(String, String)>,
    Json(body): Json<CommentBody>,
) -> Result<(StatusCode, Json<RuleCommentRow>), (StatusCode, String)> {
    let trimmed = body.body.trim();
    if trimmed.is_empty() {
        return Err(err_400("Comment body cannot be empty"));
    }

    let id = new_id();
    sqlx::query(
        r#"
        INSERT INTO rule_comments (id, checklist_id, rule_id, user_id, body)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&id)
    .bind(&checklist_id)
    .bind(&rule_id)
    .bind(&user.id)
    .bind(trimmed)
    .execute(state.pool.as_ref())
    .await
    .map_err(err_500)?;

    // Best-effort: scan the body for @handles and record mention rows so
    // mentioned users see them in their Notifications bell. Failures here
    // are logged but do not surface to the caller.
    record_mentions(state.pool.as_ref(), &id, &user.id, trimmed).await;

    let row = sqlx::query_as::<_, RuleCommentRow>(
        r#"
        SELECT c.id, c.checklist_id, c.rule_id, c.user_id,
               u.display_name AS user_name,
               c.body, c.created_at, c.edited_at
        FROM rule_comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.id = $1
        "#,
    )
    .bind(&id)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(err_500)?;

    Ok((StatusCode::CREATED, Json(row)))
}

// ── Update ─────────────────────────────────────────────────────────────────

pub async fn update_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<CommentBody>,
) -> Result<Json<RuleCommentRow>, (StatusCode, String)> {
    let trimmed = body.body.trim();
    if trimmed.is_empty() {
        return Err(err_400("Comment body cannot be empty"));
    }

    let owner: Option<(String,)> =
        sqlx::query_as("SELECT user_id FROM rule_comments WHERE id = $1")
            .bind(&id)
            .fetch_optional(state.pool.as_ref())
            .await
            .map_err(err_500)?;

    let owner_id = owner.ok_or_else(err_404)?.0;
    if owner_id != user.id {
        return Err(err_403("Only the author can edit this comment"));
    }

    sqlx::query(
        r#"
        UPDATE rule_comments
        SET body = $2, edited_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&id)
    .bind(trimmed)
    .execute(state.pool.as_ref())
    .await
    .map_err(err_500)?;

    let row = sqlx::query_as::<_, RuleCommentRow>(
        r#"
        SELECT c.id, c.checklist_id, c.rule_id, c.user_id,
               u.display_name AS user_name,
               c.body, c.created_at, c.edited_at
        FROM rule_comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.id = $1
        "#,
    )
    .bind(&id)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(err_500)?;

    Ok(Json(row))
}

// ── Delete ─────────────────────────────────────────────────────────────────

pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner: Option<(String,)> =
        sqlx::query_as("SELECT user_id FROM rule_comments WHERE id = $1")
            .bind(&id)
            .fetch_optional(state.pool.as_ref())
            .await
            .map_err(err_500)?;

    let owner_id = owner.ok_or_else(err_404)?.0;
    if owner_id != user.id {
        return Err(err_403("Only the author can delete this comment"));
    }

    sqlx::query("DELETE FROM rule_comments WHERE id = $1")
        .bind(&id)
        .execute(state.pool.as_ref())
        .await
        .map_err(err_500)?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Reactions ──────────────────────────────────────────────────────────────

/// POST /api/comments/:id/reactions — add the caller's reaction to a
/// comment. Idempotent (`ON CONFLICT DO NOTHING`). 400 on unknown
/// reaction type, 404 if the comment doesn't exist.
pub async fn add_reaction_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(comment_id): Path<String>,
    Json(body): Json<ReactionBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !is_allowed_reaction(&body.reaction) {
        return Err(err_400("Unknown reaction type"));
    }

    // Confirm the comment exists so we return 404 cleanly instead of
    // letting the FK insert fail with a 500.
    let exists: Option<(String,)> =
        sqlx::query_as("SELECT id FROM rule_comments WHERE id = $1")
            .bind(&comment_id)
            .fetch_optional(state.pool.as_ref())
            .await
            .map_err(err_500)?;
    if exists.is_none() {
        return Err(err_404());
    }

    sqlx::query(
        r#"
        INSERT INTO comment_reactions (comment_id, user_id, reaction)
        VALUES ($1, $2, $3)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(&comment_id)
    .bind(&user.id)
    .bind(&body.reaction)
    .execute(state.pool.as_ref())
    .await
    .map_err(err_500)?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/comments/:id/reactions/:reaction — remove the caller's
/// reaction. Idempotent (returns 204 even if no row matched).
pub async fn remove_reaction_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((comment_id, reaction)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !is_allowed_reaction(&reaction) {
        return Err(err_400("Unknown reaction type"));
    }

    sqlx::query(
        r#"
        DELETE FROM comment_reactions
        WHERE comment_id = $1 AND user_id = $2 AND reaction = $3
        "#,
    )
    .bind(&comment_id)
    .bind(&user.id)
    .bind(&reaction)
    .execute(state.pool.as_ref())
    .await
    .map_err(err_500)?;

    Ok(StatusCode::NO_CONTENT)
}
