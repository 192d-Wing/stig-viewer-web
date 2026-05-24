use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

// ── Draft row ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct DraftRow {
    pub id: String,
    pub title: String,
    pub author_id: String,
    pub based_on_stig: Option<String>,
    pub status: String,
    pub version: String,
    pub release_info: String,
    pub description: String,
    pub next_vuln_id: i32,
    pub json_path: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Summary row for the drafts list (joins author display name).
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct DraftSummary {
    pub id: String,
    pub title: String,
    pub author_id: String,
    pub author_name: String,
    pub based_on_stig: Option<String>,
    pub status: String,
    pub version: String,
    pub updated_at: DateTime<Utc>,
}

// ── Comment row ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct CommentRow {
    pub id: String,
    pub draft_id: String,
    pub user_id: String,
    pub user_name: String,
    pub user_role: String,
    pub body: String,
    pub action: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ── Draft CRUD ──────────────────────────────────────────────────────────────

pub async fn list_drafts(
    pool: &PgPool,
    status: Option<&str>,
    author_id: Option<&str>,
) -> Result<Vec<DraftSummary>> {
    let rows = sqlx::query_as::<_, DraftSummary>(
        r#"
        SELECT d.id, d.title, d.author_id, u.display_name AS author_name,
               d.based_on_stig, d.status, d.version, d.updated_at
        FROM stig_drafts d
        JOIN users u ON u.id = d.author_id
        WHERE ($1::text IS NULL OR d.status = $1)
          AND ($2::text IS NULL OR d.author_id = $2)
        ORDER BY d.updated_at DESC
        "#,
    )
    .bind(status)
    .bind(author_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_draft(pool: &PgPool, id: &str) -> Result<Option<DraftRow>> {
    let row = sqlx::query_as::<_, DraftRow>("SELECT * FROM stig_drafts WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

pub async fn insert_draft(pool: &PgPool, draft: &DraftRow) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO stig_drafts
            (id, title, author_id, based_on_stig, status, version, release_info,
             description, next_vuln_id, json_path)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(&draft.id)
    .bind(&draft.title)
    .bind(&draft.author_id)
    .bind(&draft.based_on_stig)
    .bind(&draft.status)
    .bind(&draft.version)
    .bind(&draft.release_info)
    .bind(&draft.description)
    .bind(draft.next_vuln_id)
    .bind(&draft.json_path)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_draft_content(
    pool: &PgPool,
    id: &str,
    title: &str,
    description: &str,
    version: &str,
    release_info: &str,
    next_vuln_id: i32,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE stig_drafts
        SET title = $2, description = $3, version = $4, release_info = $5,
            next_vuln_id = $6, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(title)
    .bind(description)
    .bind(version)
    .bind(release_info)
    .bind(next_vuln_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_draft(pool: &PgPool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM stig_drafts WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ── Status transitions ──────────────────────────────────────────────────────

const TRANSITIONS: &[(&str, &str)] = &[
    ("draft", "submitted"),
    ("submitted", "in_review"),
    ("in_review", "approved"),
    ("in_review", "rejected"),
    ("rejected", "draft"),
    ("submitted", "draft"), // withdraw
];

pub async fn transition_status(pool: &PgPool, id: &str, from: &str, to: &str) -> Result<()> {
    if !TRANSITIONS.iter().any(|(f, t)| *f == from && *t == to) {
        bail!("Invalid transition: {from} → {to}");
    }
    let result = sqlx::query(
        "UPDATE stig_drafts SET status = $2, updated_at = NOW() WHERE id = $1 AND status = $3",
    )
    .bind(id)
    .bind(to)
    .bind(from)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        bail!("Draft not found or not in expected status '{from}'");
    }
    Ok(())
}

// ── V-ID generation ─────────────────────────────────────────────────────────

pub async fn next_vuln_id(pool: &PgPool, draft_id: &str) -> Result<i32> {
    let row: (i32,) = sqlx::query_as(
        r#"
        UPDATE stig_drafts SET next_vuln_id = next_vuln_id + 1, updated_at = NOW()
        WHERE id = $1
        RETURNING next_vuln_id - 1
        "#,
    )
    .bind(draft_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

// ── Comments ────────────────────────────────────────────────────────────────

pub async fn list_comments(pool: &PgPool, draft_id: &str) -> Result<Vec<CommentRow>> {
    let rows = sqlx::query_as::<_, CommentRow>(
        r#"
        SELECT c.id, c.draft_id, c.user_id, u.display_name AS user_name,
               u.role AS user_role, c.body, c.action, c.created_at
        FROM draft_comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.draft_id = $1
        ORDER BY c.created_at ASC
        "#,
    )
    .bind(draft_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn insert_comment(
    pool: &PgPool,
    id: &str,
    draft_id: &str,
    user_id: &str,
    body: &str,
    action: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO draft_comments (id, draft_id, user_id, body, action) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(draft_id)
    .bind(user_id)
    .bind(body)
    .bind(action)
    .execute(pool)
    .await?;
    Ok(())
}
