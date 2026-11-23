//! Attribute-based access control (ABAC) policies.
//!
//! Layered behind `asset_acl::user_can`. After the owner / per-asset
//! ACL / global-admin checks all decline, the gating helper consults
//! every enabled policy whose `level` equals the requested level and
//! whose role/classification/tag predicates (NULL = wildcard) match
//! the caller and the target asset.
//!
//! Decision semantics — order matters:
//!   1. If *any* matching policy has `effect='deny'`, return `Deny`.
//!   2. Otherwise if *any* matching policy has `effect='allow'`,
//!      return `Allow`.
//!   3. Otherwise return `NoOpinion` — the caller (`user_can`) keeps
//!      its current "false" fallback so default behaviour with zero
//!      rows in the table is identical to before this feature shipped.
//!
//! Admin-only CRUD lives in this module too; routes are wired up
//! inside the auth-gated draft router in `main.rs`.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::audit_tx;
use crate::api::auth::AuthUser;
use crate::api::request_ctx::RequestCtx;
use crate::db_assets::AssetRow;
use crate::db_audit;
use crate::AppState;

const VALID_EFFECTS: &[&str] = &["allow", "deny"];
const VALID_LEVELS: &[&str] = &["read", "write", "admin"];

/// Tri-state outcome of ABAC evaluation. `NoOpinion` exists so
/// callers can distinguish "no matching policy" from an explicit
/// deny and fall through to whatever the legacy gate would have
/// returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    NoOpinion,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRow {
    pub id: String,
    pub name: String,
    pub effect: String,
    pub level: String,
    pub role_match: Option<String>,
    pub classification_match: Option<String>,
    pub tag_match: Option<String>,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePolicyRequest {
    pub name: String,
    pub effect: String,
    pub level: String,
    #[serde(default)]
    pub role_match: Option<String>,
    #[serde(default)]
    pub classification_match: Option<String>,
    #[serde(default)]
    pub tag_match: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePolicyRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub effect: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    // `Option<Option<String>>` would let callers clear back to NULL,
    // but our PATCH semantics are "any field left out is untouched"
    // — explicit-null clears stay as a follow-up. Today, sending the
    // field at all overrides the current value (including with an
    // empty string, which we treat as NULL).
    #[serde(default)]
    pub role_match: Option<String>,
    #[serde(default)]
    pub classification_match: Option<String>,
    #[serde(default)]
    pub tag_match: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

fn ensure_admin(user: &AuthUser) -> Result<(), StatusCode> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("abac sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// True when the policy's three match predicates each accept the
/// (user, asset) pair. A NULL column matches anything; a non-NULL
/// column must equal the corresponding user.role / asset.classification
/// / be present in asset.tags.
fn policy_matches(
    policy: &PolicyRow,
    user: &AuthUser,
    classification: &str,
    tags: &[String],
) -> bool {
    if let Some(r) = &policy.role_match {
        if r != &user.role {
            return false;
        }
    }
    if let Some(c) = &policy.classification_match {
        if c != classification {
            return false;
        }
    }
    if let Some(t) = &policy.tag_match {
        if !tags.iter().any(|tag| tag == t) {
            return false;
        }
    }
    true
}

/// Evaluate every enabled policy targeting `requested_level` against the
/// given user + asset. Deny wins over Allow when multiple rows match.
///
/// Returns `NoOpinion` when nothing matches so the caller can keep its
/// pre-ABAC fallback (today: deny). A DB error is returned, not folded into
/// `NoOpinion`, so a caller on a bounded transaction can tell a timeout from
/// a denial; callers that only need allow/deny must treat `Err` as deny.
pub async fn evaluate(
    pool: impl sqlx::PgExecutor<'_>,
    user: &AuthUser,
    asset: &AssetRow,
    requested_level: &str,
) -> Result<Decision, sqlx::Error> {
    let rows = load_policies(pool, requested_level).await?;
    Ok(decide(&rows, user, &asset.classification, &asset.tags))
}

/// Every enabled policy targeting `level`.
pub async fn load_policies(
    pool: impl sqlx::PgExecutor<'_>,
    level: &str,
) -> Result<Vec<PolicyRow>, sqlx::Error> {
    sqlx::query_as::<_, PolicyRow>(
        r#"
        SELECT id, name, effect, level,
               role_match, classification_match, tag_match,
               enabled, created_by, created_at
          FROM abac_policies
         WHERE enabled = TRUE
           AND level = $1
        "#,
    )
    .bind(level)
    .fetch_all(pool)
    .await
}

/// The pure half of [`evaluate`]: Deny wins over Allow over NoOpinion across
/// the already-loaded `policies` for an asset with this classification/tags.
pub fn decide(
    policies: &[PolicyRow],
    user: &AuthUser,
    classification: &str,
    tags: &[String],
) -> Decision {
    let mut allow_seen = false;
    for p in policies {
        if !policy_matches(p, user, classification, tags) {
            continue;
        }
        if p.effect == "deny" {
            // Single deny short-circuits the entire decision.
            return Decision::Deny;
        }
        if p.effect == "allow" {
            allow_seen = true;
        }
    }
    if allow_seen {
        Decision::Allow
    } else {
        Decision::NoOpinion
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// GET /api/admin/policies — admin-only list, newest first.
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<PolicyRow>>, StatusCode> {
    ensure_admin(&user)?;
    let rows = sqlx::query_as::<_, PolicyRow>(
        r#"
        SELECT id, name, effect, level,
               role_match, classification_match, tag_match,
               enabled, created_by, created_at
          FROM abac_policies
         ORDER BY created_at DESC
        "#,
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    Ok(Json(rows))
}

/// Convert an empty-string optional match value to NULL. Callers
/// pass "" via JSON when they mean "wildcard"; storing NULL keeps
/// the match logic simple (Option::is_none == wildcard).
fn nullify_empty(opt: Option<String>) -> Option<String> {
    opt.and_then(|s| {
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}

/// Audit detail for a policy: ids, enums and the match predicates (through
/// `audit_safe_id`); never the policy name.
fn policy_detail(p: &PolicyRow) -> Value {
    let safe = |v: &Option<String>| v.as_deref().map(db_audit::audit_safe_id);
    json!({
        "policyId": p.id,
        "effect": p.effect,
        "level": p.level,
        "enabled": p.enabled,
        "roleMatch": safe(&p.role_match),
        "classificationMatch": safe(&p.classification_match),
        "tagMatch": safe(&p.tag_match),
    })
}

/// Names (never values) of the fields an update replaced.
fn changed_fields(before: &PolicyRow, after: &PolicyRow) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if before.name != after.name {
        changed.push("name");
    }
    if before.effect != after.effect {
        changed.push("effect");
    }
    if before.level != after.level {
        changed.push("level");
    }
    if before.role_match != after.role_match {
        changed.push("roleMatch");
    }
    if before.classification_match != after.classification_match {
        changed.push("classificationMatch");
    }
    if before.tag_match != after.tag_match {
        changed.push("tagMatch");
    }
    if before.enabled != after.enabled {
        changed.push("enabled");
    }
    changed
}

/// POST /api/admin/policies — create a new policy. Admin only.
/// 400 on invalid effect/level. 409 on duplicate name.
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<PolicyRow>), StatusCode> {
    ensure_admin(&user)?;

    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !VALID_EFFECTS.contains(&req.effect.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !VALID_LEVELS.contains(&req.level.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let role_match = nullify_empty(req.role_match);
    let classification_match = nullify_empty(req.classification_match);
    let tag_match = nullify_empty(req.tag_match);

    let id = uuid::Uuid::new_v4().to_string();
    // The policy and its `abac_policy.create` row commit together.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    let row = sqlx::query_as::<_, PolicyRow>(
        r#"
        INSERT INTO abac_policies
            (id, name, effect, level, role_match, classification_match,
             tag_match, enabled, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, name, effect, level,
                  role_match, classification_match, tag_match,
                  enabled, created_by, created_at
        "#,
    )
    .bind(&id)
    .bind(&name)
    .bind(&req.effect)
    .bind(&req.level)
    .bind(&role_match)
    .bind(&classification_match)
    .bind(&tag_match)
    .bind(req.enabled)
    .bind(&user.id)
    .fetch_one(&mut *tx)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(StatusCode::CONFLICT);
        }
        Err(e) => return Err(map_sqlx(e)),
    };
    let ev = audit_tx::ok_event(&user, &ctx, "abac_policy.create", policy_detail(&row));
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// PATCH /api/admin/policies/:id — partial update. Admin only.
/// Any field left out is untouched. Empty string clears the
/// corresponding optional match column to NULL.
pub async fn update_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<Json<PolicyRow>, StatusCode> {
    ensure_admin(&user)?;

    // The update and its `abac_policy.update` row commit together; the
    // existing row is read under a lock so `changed` names what was replaced.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    let existing = sqlx::query_as::<_, PolicyRow>(
        r#"
        SELECT id, name, effect, level,
               role_match, classification_match, tag_match,
               enabled, created_by, created_at
          FROM abac_policies WHERE id = $1 FOR NO KEY UPDATE
        "#,
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_sqlx)?
    .ok_or(StatusCode::NOT_FOUND)?;
    let before = existing.clone();

    let name = match req.name {
        Some(n) => {
            let n = n.trim().to_string();
            if n.is_empty() {
                return Err(StatusCode::BAD_REQUEST);
            }
            n
        }
        None => existing.name,
    };
    let effect = match req.effect {
        Some(e) => {
            if !VALID_EFFECTS.contains(&e.as_str()) {
                return Err(StatusCode::BAD_REQUEST);
            }
            e
        }
        None => existing.effect,
    };
    let level = match req.level {
        Some(l) => {
            if !VALID_LEVELS.contains(&l.as_str()) {
                return Err(StatusCode::BAD_REQUEST);
            }
            l
        }
        None => existing.level,
    };
    let role_match = match req.role_match {
        Some(v) => nullify_empty(Some(v)),
        None => existing.role_match,
    };
    let classification_match = match req.classification_match {
        Some(v) => nullify_empty(Some(v)),
        None => existing.classification_match,
    };
    let tag_match = match req.tag_match {
        Some(v) => nullify_empty(Some(v)),
        None => existing.tag_match,
    };
    let enabled = req.enabled.unwrap_or(existing.enabled);

    let row = sqlx::query_as::<_, PolicyRow>(
        r#"
        UPDATE abac_policies
           SET name = $1, effect = $2, level = $3,
               role_match = $4, classification_match = $5,
               tag_match = $6, enabled = $7
         WHERE id = $8
        RETURNING id, name, effect, level,
                  role_match, classification_match, tag_match,
                  enabled, created_by, created_at
        "#,
    )
    .bind(&name)
    .bind(&effect)
    .bind(&level)
    .bind(&role_match)
    .bind(&classification_match)
    .bind(&tag_match)
    .bind(enabled)
    .bind(&id)
    .fetch_one(&mut *tx)
    .await;
    let row = match row {
        Ok(r) => r,
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(StatusCode::CONFLICT);
        }
        Err(e) => return Err(map_sqlx(e)),
    };
    let mut detail = policy_detail(&row);
    if let Some(obj) = detail.as_object_mut() {
        obj.insert("changed".into(), json!(changed_fields(&before, &row)));
    }
    let ev = audit_tx::ok_event(&user, &ctx, "abac_policy.update", detail);
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;
    Ok(Json(row))
}

/// DELETE /api/admin/policies/:id — admin only. 404 when missing.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;
    // The delete and its `abac_policy.delete` row commit together.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    let row = sqlx::query_as::<_, PolicyRow>(
        r#"
        DELETE FROM abac_policies WHERE id = $1
        RETURNING id, name, effect, level,
                  role_match, classification_match, tag_match,
                  enabled, created_by, created_at
        "#,
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_sqlx)?
    .ok_or(StatusCode::NOT_FOUND)?;
    let ev = audit_tx::ok_event(&user, &ctx, "abac_policy.delete", policy_detail(&row));
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use crate::test_fixtures::{app_state, audit_rows, auth, ctx, fail_audit_inserts, seed_user};
    use sqlx::PgPool;

    const NAME: &str = "deny-contractors-secret";

    fn admin() -> Extension<AuthUser> {
        Extension(auth("root", "admin"))
    }

    async fn create(pool: &PgPool) -> Result<PolicyRow, StatusCode> {
        let (state, _dir) = app_state(pool.clone());
        create_handler(
            State(state),
            admin(),
            Extension(ctx()),
            Json(CreatePolicyRequest {
                name: NAME.into(),
                effect: "deny".into(),
                level: "write".into(),
                role_match: Some("viewer".into()),
                classification_match: Some("secret".into()),
                tag_match: None,
                enabled: true,
            }),
        )
        .await
        .map(|(_, Json(p))| p)
    }

    async fn update(pool: &PgPool, id: &str, enabled: bool) -> Result<PolicyRow, StatusCode> {
        let (state, _dir) = app_state(pool.clone());
        update_handler(
            State(state),
            admin(),
            Extension(ctx()),
            Path(id.into()),
            Json(UpdatePolicyRequest {
                name: None,
                effect: None,
                level: None,
                role_match: None,
                classification_match: None,
                tag_match: None,
                enabled: Some(enabled),
            }),
        )
        .await
        .map(|Json(p)| p)
    }

    async fn delete(pool: &PgPool, id: &str) -> Result<StatusCode, StatusCode> {
        let (state, _dir) = app_state(pool.clone());
        delete_handler(State(state), admin(), Extension(ctx()), Path(id.into())).await
    }

    async fn policies(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM abac_policies")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn abac_policy_changes_are_recorded_without_the_policy_name(pool: PgPool) {
        seed_user(&pool, "root").await;
        let p = create(&pool).await.unwrap();
        update(&pool, &p.id, false).await.unwrap();
        assert_eq!(delete(&pool, &p.id).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(delete(&pool, &p.id).await, Err(StatusCode::NOT_FOUND));

        let keys = [
            "classificationMatch",
            "effect",
            "enabled",
            "level",
            "policyId",
            "roleMatch",
            "tagMatch",
        ];
        let created = audit_rows(&pool, "abac_policy.create").await;
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].outcome, "ok");
        assert_eq!(created[0].user_id.as_deref(), Some("root"));
        assert_eq!(created[0].detail_keys(), keys);
        assert_eq!(created[0].detail["policyId"], p.id.as_str());
        assert_eq!(created[0].detail["effect"], "deny");
        assert_eq!(created[0].detail["roleMatch"], "viewer");
        assert!(created[0].detail["tagMatch"].is_null());
        assert_eq!(created[0].request_id.as_deref(), Some("test-request"));

        let updated = audit_rows(&pool, "abac_policy.update").await;
        assert_eq!(updated.len(), 1);
        let mut with_changed = keys.to_vec();
        with_changed.insert(0, "changed");
        assert_eq!(updated[0].detail_keys(), with_changed);
        assert_eq!(updated[0].detail["changed"], serde_json::json!(["enabled"]));
        assert_eq!(updated[0].detail["enabled"], false);

        let deleted = audit_rows(&pool, "abac_policy.delete").await;
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].detail_keys(), keys);

        let text: String = sqlx::query_scalar(
            "SELECT string_agg(detail::text, ' ') FROM audit_events WHERE action LIKE 'abac_policy.%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!text.contains(NAME), "{text}");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn abac_policy_changes_fail_closed_when_the_audit_row_cannot_be_written(pool: PgPool) {
        seed_user(&pool, "root").await;
        fail_audit_inserts(
            &pool,
            &[
                "abac_policy.create",
                "abac_policy.update",
                "abac_policy.delete",
            ],
        )
        .await;
        assert_eq!(
            create(&pool).await.err(),
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert_eq!(policies(&pool).await, 0);

        crate::test_fixtures::seed_policy(
            &pool, "p1", "deny", "write", None, None, None, true, "root",
        )
        .await;
        assert_eq!(
            update(&pool, "p1", false).await.err(),
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        let enabled: bool = sqlx::query_scalar("SELECT enabled FROM abac_policies WHERE id = 'p1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(enabled);
        assert_eq!(
            delete(&pool, "p1").await,
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert_eq!(policies(&pool).await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn refused_policy_requests_write_no_audit_row(pool: PgPool) {
        seed_user(&pool, "root").await;
        let (state, _dir) = app_state(pool.clone());
        let denied = create_handler(
            State(state.clone()),
            Extension(auth("u1", "author")),
            Extension(ctx()),
            Json(CreatePolicyRequest {
                name: "n".into(),
                effect: "deny".into(),
                level: "write".into(),
                role_match: None,
                classification_match: None,
                tag_match: None,
                enabled: true,
            }),
        )
        .await;
        assert_eq!(denied.err(), Some(StatusCode::FORBIDDEN));
        let invalid = create_handler(
            State(state),
            admin(),
            Extension(ctx()),
            Json(CreatePolicyRequest {
                name: "n".into(),
                effect: "maybe".into(),
                level: "write".into(),
                role_match: None,
                classification_match: None,
                tag_match: None,
                enabled: true,
            }),
        )
        .await;
        assert_eq!(invalid.err(), Some(StatusCode::BAD_REQUEST));
        assert_eq!(
            update(&pool, "nope", true).await.err(),
            Some(StatusCode::NOT_FOUND)
        );
        assert_eq!(delete(&pool, "nope").await, Err(StatusCode::NOT_FOUND));
        for a in [
            "abac_policy.create",
            "abac_policy.update",
            "abac_policy.delete",
        ] {
            assert!(audit_rows(&pool, a).await.is_empty(), "{a}");
        }
    }
}
