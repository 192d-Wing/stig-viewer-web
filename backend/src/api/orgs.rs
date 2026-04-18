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
    auth::session::{SessionData, SESSION_COOKIE},
    orgs, AppState,
};

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
