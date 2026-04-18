//! `/api/orgs/*` — list memberships and switch the active organisation.
//!
//! The session cookie already carries the active org id/slug. These
//! endpoints let the frontend render an org picker without having to
//! trust the cookie contents blindly (the membership check runs on every
//! switch).

use axum::{
    extract::{Extension, State},
    Json,
};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use serde::{Deserialize, Serialize};
use time::Duration as TimeDuration;

use crate::{
    api::error::ApiError,
    audit::{self, AuditEntry},
    auth::{
        session::{SessionData, SESSION_COOKIE},
        Role,
    },
    orgs, AppState,
};

/// Slug contract — lowercase alphanumerics + hyphens, 3..=32 chars. Keeps the
/// slug addressable in URLs and in human conversation. Matches the seed slug
/// "default" in the migration.
fn is_valid_slug(slug: &str) -> bool {
    let len = slug.len();
    if !(3..=32).contains(&len) {
        return false;
    }
    slug.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
}

fn require_admin(session: &SessionData) -> Result<(), ApiError> {
    if session.role == Role::Admin {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

#[derive(Serialize)]
pub struct MeResponse {
    pub active: orgs::Organization,
    pub memberships: Vec<orgs::Organization>,
}

pub async fn me(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
) -> Result<Json<MeResponse>, ApiError> {
    let memberships = orgs::list_for_user(&state.pool, &session.sub).await?;
    let active = orgs::Organization {
        id: session.active_org_id,
        slug: session.active_org_slug.clone(),
        name: memberships
            .iter()
            .find(|o| o.id == session.active_org_id)
            .map(|o| o.name.clone())
            .unwrap_or_else(|| session.active_org_slug.clone()),
    };
    Ok(Json(MeResponse {
        active,
        memberships,
    }))
}

#[derive(Deserialize)]
pub struct SwitchBody {
    pub slug: String,
}

pub async fn switch_org(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    jar: PrivateCookieJar,
    Json(body): Json<SwitchBody>,
) -> Result<(PrivateCookieJar, Json<orgs::Organization>), ApiError> {
    // In dev-open mode there's no real cookie to mutate — the extractor
    // always hands out the synthetic admin. Reject the switch so callers
    // know the dev server is single-tenant by design.
    if state.auth.is_none() {
        return Err(ApiError::BadRequest(
            "dev-open mode runs in a single organisation".into(),
        ));
    }

    let target = orgs::lookup_by_slug(&state.pool, &body.slug)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("organisation '{}' not found", body.slug)))?;

    if !orgs::is_member(&state.pool, target.id, &session.sub).await? {
        // 403, not 404 — keep existence explicit once the caller has named a
        // real org; cross-tenant discovery was already possible via list_for_user
        // for orgs they DO belong to.
        return Err(ApiError::Forbidden);
    }

    let new_session = SessionData {
        active_org_id: target.id,
        active_org_slug: target.slug.clone(),
        ..session
    };

    let exp = new_session.exp;
    let serialized = serde_json::to_string(&new_session)?;
    let mut cookie = Cookie::new(SESSION_COOKIE, serialized);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    let secs = (exp - chrono::Utc::now().timestamp()).max(60);
    cookie.set_max_age(TimeDuration::seconds(secs));
    cookie.set_secure(
        std::env::var("COOKIE_SECURE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
    );

    Ok((jar.add(cookie), Json(target)))
}

// ── Admin endpoints ──────────────────────────────────────────────────────────

pub async fn list_all(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
) -> Result<Json<Vec<orgs::Organization>>, ApiError> {
    require_admin(&session)?;
    let rows = orgs::list_all(&state.pool).await?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct CreateBody {
    pub slug: String,
    pub name: String,
}

pub async fn create(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<CreateBody>,
) -> Result<(axum::http::StatusCode, Json<orgs::Organization>), ApiError> {
    require_admin(&session)?;

    let slug = body.slug.trim();
    if !is_valid_slug(slug) {
        return Err(ApiError::BadRequest(
            "slug must be 3..=32 lowercase alphanumerics or hyphens".into(),
        ));
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err(ApiError::BadRequest(
            "name must be 1..=120 characters".into(),
        ));
    }

    let created = orgs::create(&state.pool, slug, name)
        .await?
        .ok_or_else(|| ApiError::Conflict(format!("organisation '{slug}' already exists")))?;

    audit::log(
        &state.pool,
        AuditEntry {
            session: &session,
            action: "orgs.create",
            resource: Some(&created.slug),
            remote_ip: Some(addr.ip().to_string()),
            status_code: 201,
            metadata: Some(serde_json::json!({ "name": created.name })),
        },
    )
    .await;

    Ok((axum::http::StatusCode::CREATED, Json(created)))
}

pub async fn members_list(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    axum::extract::Path(slug): axum::extract::Path<String>,
) -> Result<Json<Vec<orgs::Member>>, ApiError> {
    require_admin(&session)?;
    let org = orgs::lookup_by_slug(&state.pool, &slug)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("organisation '{slug}' not found")))?;
    let members = orgs::list_members(&state.pool, org.id).await?;
    Ok(Json(members))
}

#[derive(Deserialize)]
pub struct AddMemberBody {
    pub user_sub: String,
}

pub async fn members_add(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    axum::extract::Path(slug): axum::extract::Path<String>,
    Json(body): Json<AddMemberBody>,
) -> Result<axum::http::StatusCode, ApiError> {
    require_admin(&session)?;
    let user_sub = body.user_sub.trim();
    if user_sub.is_empty() || user_sub.len() > 256 {
        return Err(ApiError::BadRequest(
            "user_sub must be 1..=256 characters".into(),
        ));
    }

    let org = orgs::lookup_by_slug(&state.pool, &slug)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("organisation '{slug}' not found")))?;
    orgs::ensure_membership(&state.pool, org.id, user_sub).await?;

    audit::log(
        &state.pool,
        AuditEntry {
            session: &session,
            action: "orgs.member.add",
            resource: Some(&org.slug),
            remote_ip: Some(addr.ip().to_string()),
            status_code: 204,
            metadata: Some(serde_json::json!({ "userSub": user_sub })),
        },
    )
    .await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn members_remove(
    State(state): State<AppState>,
    Extension(session): Extension<SessionData>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    axum::extract::Path((slug, user_sub)): axum::extract::Path<(String, String)>,
) -> Result<axum::http::StatusCode, ApiError> {
    require_admin(&session)?;

    let org = orgs::lookup_by_slug(&state.pool, &slug)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("organisation '{slug}' not found")))?;

    // Guardrail: don't let an admin strand their own session by removing
    // themselves from the org they're currently scoped to. They can switch
    // first and then have another admin remove them.
    if org.id == session.active_org_id && user_sub == session.sub {
        return Err(ApiError::BadRequest(
            "cannot remove yourself from your active organisation; switch orgs first".into(),
        ));
    }

    let removed = orgs::remove_membership(&state.pool, org.id, &user_sub).await?;
    if !removed {
        return Err(ApiError::NotFound(format!(
            "user '{user_sub}' is not a member of '{slug}'"
        )));
    }

    audit::log(
        &state.pool,
        AuditEntry {
            session: &session,
            action: "orgs.member.remove",
            resource: Some(&org.slug),
            remote_ip: Some(addr.ip().to_string()),
            status_code: 204,
            metadata: Some(serde_json::json!({ "userSub": user_sub })),
        },
    )
    .await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}
