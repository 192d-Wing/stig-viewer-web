//! Organisation (tenant) data access.
//!
//! Session cookies carry the active org. Data tables (`stigs_catalog`,
//! `workspaces`, `audit_log`) are all scoped by `org_id` so two tenants
//! on the same instance can't see each other's rows. Memberships live
//! in the `org_memberships` table; `ensure_membership` upserts a row
//! the first time an OIDC user logs in so a fresh deployment doesn't
//! strand its first users.

use anyhow::Result;
use serde::Serialize;
use sqlx::PgPool;

pub const DEFAULT_ORG_SLUG: &str = "default";

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub id: i64,
    pub slug: String,
    pub name: String,
}

/// Fetch an organisation by slug. Returns `Ok(None)` when the slug doesn't
/// exist — distinguish from "exists but user can't see it" at the handler.
pub async fn lookup_by_slug(pool: &PgPool, slug: &str) -> Result<Option<Organization>> {
    let row = sqlx::query_as::<_, Organization>(
        "SELECT id, slug, name FROM organizations WHERE slug = $1",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List every organisation the user is a member of, ordered by slug.
pub async fn list_for_user(pool: &PgPool, user_sub: &str) -> Result<Vec<Organization>> {
    let rows = sqlx::query_as::<_, Organization>(
        "SELECT o.id, o.slug, o.name \
         FROM organizations o \
         JOIN org_memberships m ON m.org_id = o.id \
         WHERE m.user_sub = $1 \
         ORDER BY o.slug",
    )
    .bind(user_sub)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Idempotent membership upsert. Safe to call on every OIDC login callback.
pub async fn ensure_membership(pool: &PgPool, org_id: i64, user_sub: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO org_memberships (org_id, user_sub) VALUES ($1, $2) \
         ON CONFLICT (org_id, user_sub) DO NOTHING",
    )
    .bind(org_id)
    .bind(user_sub)
    .execute(pool)
    .await?;
    Ok(())
}

/// Returns true if a new row was deleted, false if no membership existed.
pub async fn remove_membership(pool: &PgPool, org_id: i64, user_sub: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM org_memberships WHERE org_id = $1 AND user_sub = $2")
        .bind(org_id)
        .bind(user_sub)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// List every organisation known to the instance. Admin-only use.
pub async fn list_all(pool: &PgPool) -> Result<Vec<Organization>> {
    let rows =
        sqlx::query_as::<_, Organization>("SELECT id, slug, name FROM organizations ORDER BY slug")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Create a new organisation. Returns the fresh row; `None` when the slug
/// already exists (the caller maps this to 409 Conflict).
pub async fn create(pool: &PgPool, slug: &str, name: &str) -> Result<Option<Organization>> {
    let row = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (slug, name) VALUES ($1, $2) \
         ON CONFLICT (slug) DO NOTHING \
         RETURNING id, slug, name",
    )
    .bind(slug)
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Members of one org. Only `user_sub` and `created_at` are known; the IdP
/// owns display name / email lookups.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub user_sub: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_members(pool: &PgPool, org_id: i64) -> Result<Vec<Member>> {
    let rows = sqlx::query_as::<_, Member>(
        "SELECT user_sub, created_at FROM org_memberships \
         WHERE org_id = $1 ORDER BY created_at",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Does this user have a row in `org_memberships` for this org? Handlers use
/// it to gate cross-org access — no membership ⇒ 403.
pub async fn is_member(pool: &PgPool, org_id: i64, user_sub: &str) -> Result<bool> {
    let (exists,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM org_memberships WHERE org_id = $1 AND user_sub = $2)",
    )
    .bind(org_id)
    .bind(user_sub)
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

/// Resolve the default org row. Migration 004 guarantees it exists; if it's
/// missing we treat that as a fatal DB state problem.
pub async fn default_org(pool: &PgPool) -> Result<Organization> {
    lookup_by_slug(pool, DEFAULT_ORG_SLUG)
        .await?
        .ok_or_else(|| anyhow::anyhow!("default organisation missing — migration 004 regressed"))
}
