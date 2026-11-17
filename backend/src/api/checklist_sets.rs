//! Checklist sets: named, owner-private working checklists holding one or
//! more catalog STIGs. The Viewer autosaves rule edits into a set and can
//! push the whole set to a system repeatedly ("save to system").
//!
//! Sets are owner-only. A set that belongs to someone else (admins included)
//! is reported as 404, and every storage function filters on the owner in
//! SQL. Autosave validates shape and caps sizes only; catalog rule
//! membership, the finding-details gate and the approval workflow are
//! enforced at save-to-system by [`save_to_asset`].

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::api::checklist_save::{
    save_to_asset, SaveOrigin, SaveRequest, SaveResponse, SaveRule, MAX_TEXT_BYTES,
};
use crate::api::checklists::is_valid_stig_id;
use crate::api::rule_bulk_status::{has_nul, MAX_RULES, MAX_RULE_ID_BYTES, VALID_STATUSES};
use crate::db_assets;
use crate::db_audit::{self, NewAuditEvent};
use crate::db_checklist_sets::{self as db, AddStig, RuleChange, SetBudget, WriteOutcome};
use crate::AppState;

const MAX_SETS_PER_USER: i64 = 50;
const MAX_STIGS_PER_SET: usize = 20;
const MAX_NAME_CHARS: usize = 120;
/// Most stored rules per set: room for 20 STIGs of 500 touched rules each.
const MAX_SET_ROWS: i64 = 10_000;
/// Most stored text per set (rule ids, finding details, comments).
const MAX_SET_BYTES: i64 = 16 * 1024 * 1024;

/// Handler error: a bare status, or a prepared JSON response.
pub struct ApiError(Box<Response>);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        *self.0
    }
}

impl From<StatusCode> for ApiError {
    fn from(c: StatusCode) -> Self {
        ApiError(Box::new(c.into_response()))
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn map_db(e: anyhow::Error) -> ApiError {
    tracing::error!("checklist set DB error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR.into()
}

fn conflict(revision: i64) -> ApiError {
    ApiError(Box::new(
        (
            StatusCode::CONFLICT,
            Json(json!({ "error": "revision_conflict", "revision": revision })),
        )
            .into_response(),
    ))
}

// ── Wire types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistSetSummary {
    pub id: String,
    pub name: String,
    pub revision: i64,
    pub stig_count: i64,
    pub touched_count: i64,
    pub asset_id: Option<String>,
    pub asset_name: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRuleState {
    pub rule_id: String,
    pub status: String,
    pub finding_details: String,
    pub comments: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetStigDetail {
    pub stig_id: String,
    pub applied_version: String,
    pub applied_release: String,
    pub rules: Vec<SetRuleState>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistSetDetail {
    pub id: String,
    pub name: String,
    pub revision: i64,
    pub asset_id: Option<String>,
    pub asset_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_attached_at: Option<DateTime<Utc>>,
    pub stigs: Vec<SetStigDetail>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub stig_ids: Vec<String>,
}

/// `Some(None)` is an explicit JSON null; an absent field is `None`.
fn explicit_null<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "explicit_null")]
    pub asset_id: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddStigRequest {
    pub stig_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRuleChange {
    pub stig_id: String,
    pub rule_id: String,
    pub status: String,
    #[serde(default)]
    pub finding_details: String,
    #[serde(default)]
    pub comments: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutosaveRequest {
    pub revision: i64,
    #[serde(default)]
    pub changes: Vec<SetRuleChange>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutosaveResponse {
    pub revision: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveToSystemRequest {
    pub revision: i64,
    #[serde(default)]
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetStigResult {
    pub stig_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub save: Option<SaveResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetSaveResponse {
    pub asset_id: String,
    pub asset_name: String,
    pub results: Vec<SetStigResult>,
}

// ── Validation ──────────────────────────────────────────────────────────────

/// Trimmed, 1 to 120 characters, no control characters (NUL included).
fn clean_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    let n = name.chars().count();
    (1..=MAX_NAME_CHARS).contains(&n).then_some(())?;
    (!name.chars().any(char::is_control)).then(|| name.to_string())
}

fn event<'a>(
    user: &'a AuthUser,
    action: &'static str,
    outcome: &'static str,
    stig_id: Option<&'a str>,
    detail: serde_json::Value,
) -> NewAuditEvent<'a> {
    NewAuditEvent {
        user_id: &user.id,
        action,
        outcome,
        asset_id: None,
        checklist_id: None,
        stig_id,
        detail,
    }
}

/// The asset's name, only when the caller can still read it.
async fn visible_asset_name(
    state: &AppState,
    user: &AuthUser,
    asset_id: Option<&str>,
    name: Option<String>,
) -> Option<String> {
    let id = asset_id?;
    let name = name?;
    asset_acl::user_can(state.pool.as_ref(), id, user, "read")
        .await
        .then_some(name)
}

async fn detail_of(state: &AppState, user: &AuthUser, id: &str) -> ApiResult<ChecklistSetDetail> {
    let pool = state.pool.as_ref();
    let set = db::get_set(pool, &user.id, id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let stigs = db::list_stigs(pool, &user.id, id).await.map_err(map_db)?;
    let rules = db::list_rules(pool, &user.id, id).await.map_err(map_db)?;
    let mut by_stig: HashMap<String, Vec<SetRuleState>> = HashMap::new();
    for r in rules {
        by_stig.entry(r.stig_id).or_default().push(SetRuleState {
            rule_id: r.rule_id,
            status: r.status,
            finding_details: r.finding_details,
            comments: r.comments,
        });
    }
    let asset_name = match set.asset_id.as_deref() {
        Some(a) => {
            let name = db_assets::get_asset(pool, a)
                .await
                .map_err(map_db)?
                .map(|x| x.name);
            visible_asset_name(state, user, Some(a), name).await
        }
        None => None,
    };
    Ok(ChecklistSetDetail {
        id: set.id,
        name: set.name,
        revision: set.revision,
        asset_id: set.asset_id,
        asset_name,
        created_at: set.created_at,
        updated_at: set.updated_at,
        last_attached_at: set.last_attached_at,
        stigs: stigs
            .into_iter()
            .map(|s| SetStigDetail {
                rules: by_stig.remove(&s.stig_id).unwrap_or_default(),
                stig_id: s.stig_id,
                applied_version: s.applied_version,
                applied_release: s.applied_release,
            })
            .collect(),
    })
}

/// A catalog STIG's `(version, release)`; 400 for a bad or unknown id.
async fn catalog_stig(state: &AppState, stig_id: &str) -> ApiResult<(String, String)> {
    if !is_valid_stig_id(stig_id) {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    db::catalog_entry(state.pool.as_ref(), stig_id)
        .await
        .map_err(map_db)?
        .ok_or_else(|| StatusCode::BAD_REQUEST.into())
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// GET /api/checklist-sets
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> ApiResult<Json<Vec<ChecklistSetSummary>>> {
    let rows = db::list_sets(state.pool.as_ref(), &user.id)
        .await
        .map_err(map_db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let asset_name =
            visible_asset_name(&state, &user, r.asset_id.as_deref(), r.asset_name).await;
        out.push(ChecklistSetSummary {
            id: r.id,
            name: r.name,
            revision: r.revision,
            stig_count: r.stig_count,
            touched_count: r.touched_count,
            asset_id: r.asset_id,
            asset_name,
            updated_at: r.updated_at,
        });
    }
    Ok(Json(out))
}

/// POST /api/checklist-sets
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<ChecklistSetDetail>)> {
    let pool = state.pool.as_ref();
    let mut seen = HashSet::new();
    let ids: Vec<&String> = req
        .stig_ids
        .iter()
        .filter(|s| seen.insert(s.as_str()))
        .collect();
    if ids.is_empty() || ids.len() > MAX_STIGS_PER_SET {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let mut stigs = Vec::with_capacity(ids.len());
    for id in &ids {
        let (version, release) = catalog_stig(&state, id).await?;
        stigs.push(((*id).clone(), version, release));
    }
    let name = match req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => clean_name(n).ok_or(StatusCode::BAD_REQUEST)?,
        None => {
            let default = format!("{} {}", stigs[0].0, Utc::now().format("%Y-%m-%d"));
            default.chars().take(MAX_NAME_CHARS).collect()
        }
    };
    let id = uuid::Uuid::new_v4().to_string();
    if !db::insert_set(pool, &user.id, &id, &name, &stigs, MAX_SETS_PER_USER)
        .await
        .map_err(map_db)?
    {
        return Err(ApiError(Box::new(
            (StatusCode::CONFLICT, Json(json!({ "error": "set_limit" }))).into_response(),
        )));
    }
    db_audit::record_or_log(
        pool,
        event(
            &user,
            "checklist_set.create",
            "ok",
            None,
            json!({ "setId": id, "stigs": stigs.len() }),
        ),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(detail_of(&state, &user, &id).await?),
    ))
}

/// GET /api/checklist-sets/:id
pub async fn get_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult<Json<ChecklistSetDetail>> {
    Ok(Json(detail_of(&state, &user, &id).await?))
}

/// PATCH /api/checklist-sets/:id — rename, or unlink (`assetId: null`).
/// Linking happens only through save-to-system.
pub async fn patch_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<PatchRequest>,
) -> ApiResult<Json<ChecklistSetDetail>> {
    let pool = state.pool.as_ref();
    if matches!(req.asset_id, Some(Some(_))) {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let name = match req.name.as_deref() {
        Some(n) => Some(clean_name(n).ok_or(StatusCode::BAD_REQUEST)?),
        None => None,
    };
    if db::get_set(pool, &user.id, &id)
        .await
        .map_err(map_db)?
        .is_none()
    {
        return Err(StatusCode::NOT_FOUND.into());
    }
    if let Some(n) = &name {
        if !db::rename_set(pool, &user.id, &id, n)
            .await
            .map_err(map_db)?
        {
            return Err(StatusCode::NOT_FOUND.into());
        }
        db_audit::record_or_log(
            pool,
            event(
                &user,
                "checklist_set.rename",
                "ok",
                None,
                json!({ "setId": id }),
            ),
        )
        .await;
    }
    if req.asset_id == Some(None) {
        let prev = db::unlink_asset(pool, &user.id, &id)
            .await
            .map_err(map_db)?
            .ok_or(StatusCode::NOT_FOUND)?;
        if let Some(prev) = prev {
            let mut ev = event(
                &user,
                "checklist_set.unlink",
                "ok",
                None,
                json!({ "setId": id }),
            );
            ev.asset_id = Some(&prev);
            db_audit::record_or_log(pool, ev).await;
        }
    }
    Ok(Json(detail_of(&state, &user, &id).await?))
}

/// DELETE /api/checklist-sets/:id
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let pool = state.pool.as_ref();
    if !db::delete_set(pool, &user.id, &id).await.map_err(map_db)? {
        return Err(StatusCode::NOT_FOUND.into());
    }
    db_audit::record_or_log(
        pool,
        event(
            &user,
            "checklist_set.delete",
            "ok",
            None,
            json!({ "setId": id }),
        ),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/checklist-sets/:id/stigs — idempotent.
pub async fn add_stig_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<AddStigRequest>,
) -> ApiResult<Json<ChecklistSetDetail>> {
    let pool = state.pool.as_ref();
    if db::get_set(pool, &user.id, &id)
        .await
        .map_err(map_db)?
        .is_none()
    {
        return Err(StatusCode::NOT_FOUND.into());
    }
    let (version, release) = catalog_stig(&state, &req.stig_id).await?;
    match db::add_stig(
        pool,
        &user.id,
        &id,
        &req.stig_id,
        &version,
        &release,
        MAX_STIGS_PER_SET as i64,
    )
    .await
    .map_err(map_db)?
    {
        AddStig::NotFound => return Err(StatusCode::NOT_FOUND.into()),
        AddStig::Limit => return Err(StatusCode::BAD_REQUEST.into()),
        AddStig::Exists => {}
        AddStig::Added => {
            db_audit::record_or_log(
                pool,
                event(
                    &user,
                    "checklist_set.stig_add",
                    "ok",
                    Some(&req.stig_id),
                    json!({ "setId": id }),
                ),
            )
            .await;
        }
    }
    Ok(Json(detail_of(&state, &user, &id).await?))
}

/// DELETE /api/checklist-sets/:id/stigs/:stig_id
pub async fn remove_stig_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((id, stig_id)): Path<(String, String)>,
) -> ApiResult<Json<ChecklistSetDetail>> {
    let pool = state.pool.as_ref();
    let removed = db::remove_stig(pool, &user.id, &id, &stig_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if removed {
        let sid = is_valid_stig_id(&stig_id).then_some(stig_id.as_str());
        db_audit::record_or_log(
            pool,
            event(
                &user,
                "checklist_set.stig_remove",
                "ok",
                sid,
                json!({ "setId": id }),
            ),
        )
        .await;
    }
    Ok(Json(detail_of(&state, &user, &id).await?))
}

/// PATCH /api/checklist-sets/:id/rules — autosave.
pub async fn autosave_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<AutosaveRequest>,
) -> ApiResult<Json<AutosaveResponse>> {
    let budget = SetBudget {
        max_rows_per_stig: MAX_RULES as i64,
        max_rows: MAX_SET_ROWS,
        max_bytes: MAX_SET_BYTES,
    };
    autosave_with_budget(state, user, id, req, budget).await
}

/// Autosave with explicit size bounds (tests pass small ones).
async fn autosave_with_budget(
    state: AppState,
    user: AuthUser,
    id: String,
    req: AutosaveRequest,
    budget: SetBudget,
) -> ApiResult<Json<AutosaveResponse>> {
    let pool = state.pool.as_ref();
    if req.changes.len() > MAX_RULES {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let set = db::get_set(pool, &user.id, &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let members: HashSet<String> = db::list_stigs(pool, &user.id, &id)
        .await
        .map_err(map_db)?
        .into_iter()
        .map(|s| s.stig_id)
        .collect();
    for c in &req.changes {
        let ok = members.contains(&c.stig_id)
            && !c.rule_id.is_empty()
            && c.rule_id.len() <= MAX_RULE_ID_BYTES
            && VALID_STATUSES.contains(&c.status.as_str())
            && c.finding_details.len() <= MAX_TEXT_BYTES
            && c.comments.len() <= MAX_TEXT_BYTES
            && !has_nul(&c.rule_id)
            && !has_nul(&c.finding_details)
            && !has_nul(&c.comments);
        if !ok {
            return Err(StatusCode::BAD_REQUEST.into());
        }
    }
    if req.revision != set.revision {
        return Err(conflict(set.revision));
    }
    // Last write wins for a repeated (stig, rule).
    let mut order: Vec<(String, String)> = Vec::new();
    let mut latest: HashMap<(String, String), RuleChange> = HashMap::new();
    for c in req.changes {
        let key = (c.stig_id.clone(), c.rule_id.clone());
        if latest
            .insert(
                key.clone(),
                RuleChange {
                    stig_id: c.stig_id,
                    rule_id: c.rule_id,
                    status: c.status,
                    finding_details: c.finding_details,
                    comments: c.comments,
                },
            )
            .is_none()
        {
            order.push(key);
        }
    }
    let changes: Vec<RuleChange> = order
        .into_iter()
        .filter_map(|k| latest.remove(&k))
        .collect();
    let stig_ids: Vec<&str> = {
        let mut v: Vec<&str> = changes.iter().map(|c| c.stig_id.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    match db::write_rules(pool, &user.id, &id, req.revision, &changes, budget)
        .await
        .map_err(map_db)?
    {
        WriteOutcome::Written {
            revision,
            updated_at,
            edit_event_due,
        } => {
            if edit_event_due {
                db_audit::record_or_log(
                    pool,
                    event(
                        &user,
                        "checklist_set.edit",
                        "ok",
                        None,
                        json!({ "setId": id, "changes": changes.len(), "stigIds": stig_ids }),
                    ),
                )
                .await;
            }
            Ok(Json(AutosaveResponse {
                revision,
                updated_at,
            }))
        }
        WriteOutcome::NotFound => Err(StatusCode::NOT_FOUND.into()),
        WriteOutcome::Conflict { revision } => Err(conflict(revision)),
        WriteOutcome::SetTooLarge => Err(ApiError(Box::new(
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({ "error": "set_too_large" })),
            )
                .into_response(),
        ))),
        WriteOutcome::TooManyRules | WriteOutcome::UnknownStig => {
            Err(StatusCode::BAD_REQUEST.into())
        }
    }
}

/// POST /api/checklist-sets/:id/save-to-system
///
/// Runs in a spawned task: each STIG's chunks commit on their own, so a
/// client disconnect must not leave committed writes without audit events.
pub async fn save_to_system_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<SaveToSystemRequest>,
) -> ApiResult<Json<SetSaveResponse>> {
    tokio::spawn(save_to_system_work(state, user, id, req))
        .await
        .map_err(|e| {
            tracing::error!("set save task failed: {e}");
            ApiError(Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()))
        })?
}

async fn save_to_system_work(
    state: AppState,
    user: AuthUser,
    id: String,
    req: SaveToSystemRequest,
) -> ApiResult<Json<SetSaveResponse>> {
    let pool = state.pool.as_ref();
    let set = db::get_set(pool, &user.id, &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    // Early refusals leave a record too; no asset id until it is known to exist.
    let reject = |reason: &'static str| {
        db_audit::record_or_log(
            pool,
            event(
                &user,
                "checklist_set.save_to_system",
                "rejected",
                None,
                json!({ "setId": id, "reason": reason }),
            ),
        )
    };
    if set.revision != req.revision {
        reject("revision_conflict").await;
        return Err(conflict(set.revision));
    }
    let target = match (set.asset_id.as_deref(), req.asset_id.as_deref()) {
        (Some(linked), Some(asked)) if linked != asked => {
            reject("asset_mismatch").await;
            return Err(StatusCode::BAD_REQUEST.into());
        }
        (Some(linked), _) => linked.to_string(),
        (None, Some(asked)) => asked.to_string(),
        (None, None) => {
            reject("no_asset").await;
            return Err(StatusCode::BAD_REQUEST.into());
        }
    };
    let Some(asset) = db_assets::get_asset(pool, &target).await.map_err(map_db)? else {
        reject("asset_not_found").await;
        return Err(StatusCode::NOT_FOUND.into());
    };
    let record = |outcome: &'static str, detail: serde_json::Value| {
        let mut ev = event(&user, "checklist_set.save_to_system", outcome, None, detail);
        ev.asset_id = Some(&asset.id);
        db_audit::record_or_log(pool, ev)
    };
    if !asset_acl::user_can(pool, &asset.id, &user, "write").await {
        record("denied", json!({ "setId": id, "reason": "forbidden" })).await;
        return Err(StatusCode::FORBIDDEN.into());
    }
    let stigs = db::list_stigs(pool, &user.id, &id).await.map_err(map_db)?;
    let rules = db::list_rules(pool, &user.id, &id).await.map_err(map_db)?;
    // What is pushed must be what the user last saw saved: re-check after the reads.
    let after = db::get_set(pool, &user.id, &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if after.revision != req.revision {
        reject("revision_conflict").await;
        return Err(conflict(after.revision));
    }
    let mut by_stig: HashMap<String, Vec<SaveRule>> = HashMap::new();
    for r in rules {
        by_stig.entry(r.stig_id).or_default().push(SaveRule {
            rule_id: r.rule_id,
            status: r.status,
            finding_details: r.finding_details,
            comments: r.comments,
        });
    }
    let mut results = Vec::with_capacity(stigs.len());
    for s in stigs {
        let save_req = SaveRequest {
            stig_id: s.stig_id.clone(),
            rules: by_stig.remove(&s.stig_id).unwrap_or_default(),
        };
        let origin = SaveOrigin::Set { set_id: &id };
        results.push(
            match save_to_asset(&state, &user, &asset, &save_req, origin).await {
                Ok(save) => SetStigResult {
                    stig_id: s.stig_id,
                    ok: true,
                    status: None,
                    save: Some(save),
                },
                Err(code) => SetStigResult {
                    stig_id: s.stig_id,
                    ok: false,
                    status: Some(code.as_u16()),
                    save: None,
                },
            },
        );
    }
    let ok_count = results.iter().filter(|r| r.ok).count();
    let row_errors: usize = results
        .iter()
        .filter_map(|r| r.save.as_ref())
        .map(|s| s.error_count)
        .sum();
    if ok_count > 0 {
        // The writes above are committed; a failed link (asset deleted in
        // between) must not hide their results.
        if let Err(e) = db::link_asset(pool, &user.id, &id, &asset.id).await {
            tracing::error!("linking set {id} to asset {} failed: {e:#}", asset.id);
        }
    }
    record(
        if ok_count == results.len() && row_errors == 0 { "ok" } else { "partial" },
        json!({
            "setId": id,
            "stigs": results.len(),
            "stigsOk": ok_count,
            "stigsFailed": results.len() - ok_count,
            "applied": results.iter().filter_map(|r| r.save.as_ref()).map(|s| s.applied_count).sum::<usize>(),
            "pending": results.iter().filter_map(|r| r.save.as_ref()).map(|s| s.pending_count).sum::<usize>(),
            "unchanged": results.iter().filter_map(|r| r.save.as_ref()).map(|s| s.unchanged_count).sum::<usize>(),
            "errors": row_errors,
        }),
    )
    .await;
    Ok(Json(SetSaveResponse {
        asset_id: asset.id.clone(),
        asset_name: asset.name.clone(),
        results,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{app_state, auth, seed_acl, seed_asset, seed_user, RULES, STIG_ID};
    use sqlx::PgPool;

    const STIG2: &str = "TEST-STIG-2";
    const GHOST: &str = "GHOST-STIG";

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(clean_name("  ok  ").as_deref(), Some("ok"));
        assert_eq!(clean_name("   "), None);
        assert_eq!(clean_name("a\u{0}b"), None);
        assert_eq!(clean_name("a\nb"), None);
        assert_eq!(clean_name(&"x".repeat(120)).map(|n| n.len()), Some(120));
        assert_eq!(clean_name(&"x".repeat(121)), None);
    }

    #[test]
    fn patch_distinguishes_null_from_absent() {
        let a: PatchRequest = serde_json::from_str(r#"{"assetId":null}"#).unwrap();
        assert_eq!(a.asset_id, Some(None));
        let b: PatchRequest = serde_json::from_str(r#"{"name":"n"}"#).unwrap();
        assert_eq!(b.asset_id, None);
    }

    // ── Database-backed tests ──────────────────────────────────────────────

    async fn count(pool: &PgPool, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
    }

    async fn seed_catalog(pool: &PgPool, id: &str) {
        sqlx::query("INSERT INTO stigs_catalog (id, title, category, version, release_info, json_path) VALUES ($1, $1, 'x', '2', 'R3', '')")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }

    fn write_stig2(state: &AppState) {
        let rules: Vec<_> = RULES
            .iter()
            .map(|id| json!({ "id": id, "title": id }))
            .collect();
        std::fs::write(
            state
                .config
                .data_dir
                .join("stigs")
                .join(format!("{STIG2}.json")),
            json!({ "id": STIG2, "rules": rules }).to_string(),
        )
        .unwrap();
    }

    /// Users `owner`, `other`, admin `root`; asset `a1` owned by `owner`;
    /// catalog rows for the fixture STIGs and a ghost STIG with no file.
    async fn base(pool: &PgPool) -> (AppState, crate::test_fixtures::StigDir) {
        seed_user(pool, "owner").await;
        seed_user(pool, "other").await;
        seed_user(pool, "root").await;
        seed_asset(pool, "a1", "owner", false).await;
        for id in [STIG_ID, STIG2, GHOST] {
            seed_catalog(pool, id).await;
        }
        let (state, dir) = app_state(pool.clone());
        write_stig2(&state);
        (state, dir)
    }

    fn st(state: &AppState) -> State<AppState> {
        State(state.clone())
    }

    async fn make(state: &AppState, who: &str, ids: &[&str]) -> ChecklistSetDetail {
        let req = CreateRequest {
            name: None,
            stig_ids: ids.iter().map(|s| s.to_string()).collect(),
        };
        let Ok((code, Json(d))) =
            create_handler(st(state), Extension(auth(who, "author")), Json(req)).await
        else {
            panic!("create failed");
        };
        assert_eq!(code, StatusCode::CREATED);
        d
    }

    fn change(
        stig: &str,
        rule: &str,
        status: &str,
        details: &str,
        comments: &str,
    ) -> SetRuleChange {
        SetRuleChange {
            stig_id: stig.into(),
            rule_id: rule.into(),
            status: status.into(),
            finding_details: details.into(),
            comments: comments.into(),
        }
    }

    async fn autosave(
        state: &AppState,
        who: &str,
        id: &str,
        revision: i64,
        changes: Vec<SetRuleChange>,
    ) -> Result<AutosaveResponse, StatusCode> {
        autosave_handler(
            st(state),
            Extension(auth(who, "author")),
            Path(id.into()),
            Json(AutosaveRequest { revision, changes }),
        )
        .await
        .map(|Json(r)| r)
        .map_err(|e| e.into_response().status())
    }

    async fn push(
        state: &AppState,
        who: &str,
        id: &str,
        revision: i64,
        asset: Option<&str>,
    ) -> Result<SetSaveResponse, StatusCode> {
        save_to_system_handler(
            st(state),
            Extension(auth(who, "author")),
            Path(id.into()),
            Json(SaveToSystemRequest {
                revision,
                asset_id: asset.map(str::to_string),
            }),
        )
        .await
        .map(|Json(r)| r)
        .map_err(|e| e.into_response().status())
    }

    fn code<T>(r: ApiResult<T>) -> Option<StatusCode> {
        r.err().map(|e| e.into_response().status())
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn other_users_and_admins_get_404_on_every_route(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        for (who, role) in [("other", "author"), ("root", "admin")] {
            let u = || Extension(auth(who, role));
            let id = || Path(set.id.clone());
            assert_eq!(
                code(get_handler(st(&state), u(), id()).await),
                Some(StatusCode::NOT_FOUND)
            );
            let p = PatchRequest {
                name: Some("x".into()),
                asset_id: None,
            };
            assert_eq!(
                code(patch_handler(st(&state), u(), id(), Json(p)).await),
                Some(StatusCode::NOT_FOUND)
            );
            let add = AddStigRequest {
                stig_id: STIG2.into(),
            };
            assert_eq!(
                code(add_stig_handler(st(&state), u(), id(), Json(add)).await),
                Some(StatusCode::NOT_FOUND)
            );
            let rm = Path((set.id.clone(), STIG_ID.to_string()));
            assert_eq!(
                code(remove_stig_handler(st(&state), u(), rm).await),
                Some(StatusCode::NOT_FOUND)
            );
            let a = AutosaveRequest {
                revision: 0,
                changes: vec![],
            };
            assert_eq!(
                code(autosave_handler(st(&state), u(), id(), Json(a)).await),
                Some(StatusCode::NOT_FOUND)
            );
            let s = SaveToSystemRequest {
                revision: 0,
                asset_id: Some("a1".into()),
            };
            assert_eq!(
                code(save_to_system_handler(st(&state), u(), id(), Json(s)).await),
                Some(StatusCode::NOT_FOUND)
            );
            assert_eq!(
                code(delete_handler(st(&state), u(), id()).await),
                Some(StatusCode::NOT_FOUND)
            );
            let Json(list) = list_handler(st(&state), u()).await.ok().unwrap();
            assert!(list.is_empty());
        }
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_sets").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn create_defaults_the_name_and_validates_input(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let d = make(&state, "owner", &[STIG_ID, STIG2, STIG_ID]).await;
        assert!(d.name.starts_with(&format!("{STIG_ID} 20")), "{}", d.name);
        assert_eq!(d.stigs.len(), 2);
        assert_eq!(d.stigs[0].applied_version, "2");
        assert_eq!(d.stigs[0].applied_release, "R3");
        let u = || Extension(auth("owner", "author"));
        let bad = |ids: Vec<String>| CreateRequest {
            name: None,
            stig_ids: ids,
        };
        for ids in [
            vec![],
            vec!["../x".to_string()],
            vec!["NOPE".to_string()],
            (0..21).map(|i| format!("S{i}")).collect(),
        ] {
            assert_eq!(
                code(create_handler(st(&state), u(), Json(bad(ids))).await),
                Some(StatusCode::BAD_REQUEST)
            );
        }
        let named = CreateRequest {
            name: Some("a\u{0}b".into()),
            stig_ids: vec![STIG_ID.into()],
        };
        assert_eq!(
            code(create_handler(st(&state), u(), Json(named)).await),
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_sets").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_fifty_first_set_is_refused(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        for _ in 0..50 {
            make(&state, "owner", &[STIG_ID]).await;
        }
        let req = CreateRequest {
            name: None,
            stig_ids: vec![STIG_ID.into()],
        };
        let r = create_handler(st(&state), Extension(auth("owner", "author")), Json(req)).await;
        assert_eq!(code(r), Some(StatusCode::CONFLICT));
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_sets").await,
            50
        );
        // Another user is unaffected.
        make(&state, "other", &[STIG_ID]).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn autosave_replaces_state_exactly_and_untouched_deletes_the_row(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let r = autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![
                change(STIG_ID, RULES[0], "open", "d", "c"),
                change(STIG_ID, RULES[1], "not_reviewed", "", "note"),
                change(STIG_ID, RULES[0], "not_a_finding", "d2", ""),
            ],
        )
        .await
        .unwrap();
        assert_eq!(r.revision, 1);
        let Json(d) = get_handler(
            st(&state),
            Extension(auth("owner", "author")),
            Path(set.id.clone()),
        )
        .await
        .ok()
        .unwrap();
        let rules = &d.stigs[0].rules;
        assert_eq!(rules.len(), 2);
        assert_eq!(
            (
                rules[0].status.as_str(),
                rules[0].finding_details.as_str(),
                rules[0].comments.as_str()
            ),
            ("not_a_finding", "d2", "")
        );
        assert_eq!(rules[1].comments, "note");
        autosave(
            &state,
            "owner",
            &set.id,
            1,
            vec![change(STIG_ID, RULES[0], "not_reviewed", " ", "")],
        )
        .await
        .unwrap();
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            1
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn autosave_stale_revision_conflicts_and_writes_nothing(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![change(STIG_ID, RULES[0], "open", "", "")],
        )
        .await
        .unwrap();
        let r = autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![change(STIG_ID, RULES[1], "open", "", "")],
        )
        .await;
        assert_eq!(r.err(), Some(StatusCode::CONFLICT));
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            1
        );
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn autosave_rejects_bad_requests_whole(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let good = || change(STIG_ID, RULES[0], "open", "", "");
        let bad: Vec<SetRuleChange> = vec![
            change(STIG_ID2_NOT_IN_SET, RULES[0], "open", "", ""),
            change(STIG_ID, RULES[0], "bogus", "", ""),
            change(
                STIG_ID,
                RULES[0],
                "open",
                &"x".repeat(MAX_TEXT_BYTES + 1),
                "",
            ),
            change(STIG_ID, RULES[0], "open", "a\u{0}b", ""),
            change(STIG_ID, &"r".repeat(MAX_RULE_ID_BYTES + 1), "open", "", ""),
        ];
        for b in bad {
            let r = autosave(&state, "owner", &set.id, 0, vec![good(), b]).await;
            assert_eq!(r.err(), Some(StatusCode::BAD_REQUEST));
        }
        let many: Vec<SetRuleChange> = (0..=MAX_RULES)
            .map(|i| change(STIG_ID, &format!("r{i}"), "open", "", ""))
            .collect();
        assert_eq!(
            autosave(&state, "owner", &set.id, 0, many).await.err(),
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            0
        );
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 0);
    }
    const STIG_ID2_NOT_IN_SET: &str = STIG2;

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn set_budget_rolls_back_and_empty_rule_ids_are_refused(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let budget = |max_rows, max_bytes| SetBudget {
            max_rows_per_stig: MAX_RULES as i64,
            max_rows,
            max_bytes,
        };
        let run = |revision: i64, changes: Vec<SetRuleChange>, b: SetBudget| {
            autosave_with_budget(
                state.clone(),
                auth("owner", "author"),
                set.id.clone(),
                AutosaveRequest { revision, changes },
                b,
            )
        };
        let too_large = |e: ApiError| async move {
            let res = e.into_response();
            let status = res.status();
            let body = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        };
        let expect = (
            StatusCode::PAYLOAD_TOO_LARGE,
            r#"{"error":"set_too_large"}"#.to_string(),
        );

        // Row budget: three rows fit, a fourth is refused with 413.
        let three = (0..3)
            .map(|i| change(STIG_ID, &format!("r{i}"), "open", "", ""))
            .collect();
        assert_eq!(
            run(0, three, budget(3, 1 << 20))
                .await
                .ok()
                .unwrap()
                .0
                .revision,
            1
        );
        let over = vec![change(STIG_ID, "one-more", "open", "", "")];
        assert_eq!(
            too_large(run(1, over, budget(3, 1 << 20)).await.err().unwrap()).await,
            expect
        );
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            3
        );
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 1);

        // Byte budget: rewriting a row with more text than fits is refused.
        let fat = vec![change(STIG_ID, "r0", "open", &"x".repeat(100), "")];
        assert_eq!(
            too_large(run(1, fat, budget(10, 50)).await.err().unwrap()).await,
            expect
        );
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 1);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_set_rules WHERE finding_details <> ''"
            )
            .await,
            0
        );

        // An empty rule id is a 400 and changes nothing.
        let empty = vec![change(STIG_ID, "", "open", "", "")];
        let err = run(1, empty, budget(10, 1 << 20)).await.err().unwrap();
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            3
        );
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn autosave_row_cap_rolls_back(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let full: Vec<SetRuleChange> = (0..MAX_RULES)
            .map(|i| change(STIG_ID, &format!("r{i}"), "open", "", ""))
            .collect();
        assert_eq!(
            autosave(&state, "owner", &set.id, 0, full)
                .await
                .unwrap()
                .revision,
            1
        );
        let over = vec![change(STIG_ID, "one-more", "open", "", "")];
        assert_eq!(
            autosave(&state, "owner", &set.id, 1, over).await.err(),
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            MAX_RULES as i64
        );
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn edit_audit_is_coalesced_per_window(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let edits = |pool: PgPool| async move {
            count(
                &pool,
                "SELECT COUNT(*) FROM audit_events WHERE action = 'checklist_set.edit'",
            )
            .await
        };
        autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![change(STIG_ID, RULES[0], "open", "", "")],
        )
        .await
        .unwrap();
        autosave(
            &state,
            "owner",
            &set.id,
            1,
            vec![change(STIG_ID, RULES[1], "open", "", "")],
        )
        .await
        .unwrap();
        assert_eq!(edits(pool.clone()).await, 1);
        sqlx::query("UPDATE checklist_sets SET last_edit_event_at = NOW() - INTERVAL '16 minutes'")
            .execute(&pool)
            .await
            .unwrap();
        autosave(
            &state,
            "owner",
            &set.id,
            2,
            vec![change(STIG_ID, RULES[2], "open", "", "")],
        )
        .await
        .unwrap();
        assert_eq!(edits(pool.clone()).await, 2);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn stig_add_remove_and_cascades(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let u = || Extension(auth("owner", "author"));
        let add = |id: &str| Json(AddStigRequest { stig_id: id.into() });
        let Json(d) = add_stig_handler(st(&state), u(), Path(set.id.clone()), add(STIG2))
            .await
            .ok()
            .unwrap();
        assert_eq!(d.stigs.len(), 2);
        let Json(d) = add_stig_handler(st(&state), u(), Path(set.id.clone()), add(STIG2))
            .await
            .ok()
            .unwrap();
        assert_eq!(d.stigs.len(), 2, "idempotent");
        assert_eq!(
            code(add_stig_handler(st(&state), u(), Path(set.id.clone()), add("NOPE")).await),
            Some(StatusCode::BAD_REQUEST)
        );
        autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![change(STIG2, RULES[0], "open", "", "")],
        )
        .await
        .unwrap();
        let Json(d) = remove_stig_handler(st(&state), u(), Path((set.id.clone(), STIG2.into())))
            .await
            .ok()
            .unwrap();
        assert_eq!((d.stigs.len(), d.revision), (1, 2));
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            0
        );
        // 20-STIG cap.
        for i in 0..19 {
            let id = format!("EXTRA-{i}");
            seed_catalog(&pool, &id).await;
            assert!(
                add_stig_handler(st(&state), u(), Path(set.id.clone()), add(&id))
                    .await
                    .is_ok()
            );
        }
        seed_catalog(&pool, "EXTRA-X").await;
        assert_eq!(
            code(add_stig_handler(st(&state), u(), Path(set.id.clone()), add("EXTRA-X")).await),
            Some(StatusCode::BAD_REQUEST)
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_delete_unlinks_and_user_delete_cascades(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![change(STIG_ID, RULES[0], "open", "", "")],
        )
        .await
        .unwrap();
        push(&state, "owner", &set.id, 1, Some("a1")).await.unwrap();
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_sets WHERE asset_id = 'a1'"
            )
            .await,
            1
        );
        sqlx::query("DELETE FROM assets WHERE id = 'a1'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_sets WHERE asset_id IS NULL"
            )
            .await,
            1
        );
        for t in ["rule_audit", "audit_events", "checklists"] {
            sqlx::query(&format!("DELETE FROM {t}"))
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM users WHERE id = 'owner'")
            .execute(&pool)
            .await
            .unwrap();
        for t in [
            "checklist_sets",
            "checklist_set_stigs",
            "checklist_set_rules",
        ] {
            assert_eq!(
                count(&pool, &format!("SELECT COUNT(*) FROM {t}")).await,
                0,
                "{t}"
            );
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_to_system_fans_out_per_stig_and_can_repeat(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID, STIG2]).await;
        autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![
                change(STIG_ID, RULES[0], "open", "", ""),
                change(STIG_ID, RULES[1], "not_a_finding", "why", ""),
                change(STIG2, RULES[0], "not_reviewed", "", "note"),
            ],
        )
        .await
        .unwrap();
        let r = push(&state, "owner", &set.id, 1, Some("a1")).await.unwrap();
        assert_eq!(r.asset_id, "a1");
        assert_eq!(r.results.len(), 2);
        let counts: Vec<(usize, usize)> = r
            .results
            .iter()
            .map(|x| {
                x.save
                    .as_ref()
                    .map(|s| (s.applied_count, s.error_count))
                    .unwrap()
            })
            .collect();
        assert_eq!(counts, vec![(2, 0), (1, 0)]);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 2);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM audit_events WHERE action = 'checklist_set.save_to_system' AND outcome = 'ok'").await, 1);
        let tagged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE action IN ('checklist.save','checklist.create') AND detail->>'via' = 'checklist_set' AND detail->>'setId' = $1")
            .bind(&set.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(tagged, 4);
        // The set stays linked and can be saved again; nothing changes.
        let Json(d) = get_handler(
            st(&state),
            Extension(auth("owner", "author")),
            Path(set.id.clone()),
        )
        .await
        .ok()
        .unwrap();
        assert_eq!(d.asset_id.as_deref(), Some("a1"));
        assert_eq!(d.asset_name.as_deref(), Some("a1"));
        let again = push(&state, "owner", &set.id, 1, None).await.unwrap();
        assert!(again.results.iter().all(|x| x
            .save
            .as_ref()
            .is_some_and(|s| s.applied_count == 0 && s.unchanged_count > 0)));
        // Linked to a1: a different asset needs an unlink first.
        seed_asset(&pool, "a2", "owner", false).await;
        assert_eq!(
            push(&state, "owner", &set.id, 1, Some("a2")).await.err(),
            Some(StatusCode::BAD_REQUEST)
        );
        let p = PatchRequest {
            name: None,
            asset_id: Some(None),
        };
        let Json(d) = patch_handler(
            st(&state),
            Extension(auth("owner", "author")),
            Path(set.id.clone()),
            Json(p),
        )
        .await
        .ok()
        .unwrap();
        assert_eq!(d.asset_id, None);
        assert!(push(&state, "owner", &set.id, 1, Some("a2")).await.is_ok());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_to_system_needs_write_access_and_a_fresh_revision(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "other", &[STIG_ID]).await;
        autosave(
            &state,
            "other",
            &set.id,
            0,
            vec![change(STIG_ID, RULES[0], "open", "", "")],
        )
        .await
        .unwrap();
        assert_eq!(
            push(&state, "other", &set.id, 1, Some("a1")).await.err(),
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 0);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM audit_events WHERE action = 'checklist_set.save_to_system' AND outcome = 'denied' AND asset_id = 'a1'").await, 1);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_sets WHERE asset_id IS NOT NULL"
            )
            .await,
            0
        );
        // Read access is not enough.
        seed_acl(&pool, "a1", "other", "read").await;
        assert_eq!(
            push(&state, "other", &set.id, 1, Some("a1")).await.err(),
            Some(StatusCode::FORBIDDEN)
        );
        seed_acl(&pool, "a1", "owner", "write").await;
        assert_eq!(
            push(&state, "other", &set.id, 0, Some("a1")).await.err(),
            Some(StatusCode::CONFLICT)
        );
        assert_eq!(
            push(&state, "other", &set.id, 1, None).await.err(),
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM audit_events WHERE action = 'checklist_set.save_to_system' AND outcome = 'rejected' AND asset_id IS NULL").await, 2);
        assert_eq!(
            push(&state, "other", &set.id, 1, Some("nope")).await.err(),
            Some(StatusCode::NOT_FOUND)
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn save_to_system_keeps_the_gates(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        sqlx::query("UPDATE assets SET requires_approval = TRUE WHERE id = 'a1'")
            .execute(&pool)
            .await
            .unwrap();
        let set = make(&state, "owner", &[STIG_ID]).await;
        autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![
                change(STIG_ID, RULES[0], "not_a_finding", "why", ""),
                change(STIG_ID, RULES[1], "not_a_finding", "", ""),
                change(STIG_ID, "SV-unknown", "open", "", ""),
            ],
        )
        .await
        .unwrap();
        let r = push(&state, "owner", &set.id, 1, Some("a1")).await.unwrap();
        let s = r.results[0].save.as_ref().unwrap();
        assert_eq!((s.pending_count, s.error_count, s.applied_count), (1, 2, 0));
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM finding_approvals").await,
            1
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn one_stig_failing_does_not_stop_the_others(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[GHOST, STIG_ID]).await;
        autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![change(STIG_ID, RULES[0], "open", "", "")],
        )
        .await
        .unwrap();
        let r = push(&state, "owner", &set.id, 1, Some("a1")).await.unwrap();
        assert_eq!((r.results[0].ok, r.results[0].status), (false, Some(404)));
        assert!(r.results[1].ok);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklists").await, 1);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_sets WHERE asset_id = 'a1'"
            )
            .await,
            1
        );
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM audit_events WHERE action = 'checklist_set.save_to_system' AND outcome = 'partial'").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn set_save_survives_the_handler_future_being_dropped(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![change(STIG_ID, RULES[0], "open", "", "")],
        )
        .await
        .unwrap();
        let (st2, id) = (state.clone(), set.id.clone());
        let h = tokio::spawn(async move {
            let _ = push(&st2, "owner", &id, 1, Some("a1")).await;
        });
        tokio::task::yield_now().await;
        h.abort();
        let mut done = 0;
        for _ in 0..200 {
            done = count(
                &pool,
                "SELECT COUNT(*) FROM audit_events WHERE action = 'checklist_set.save_to_system'",
            )
            .await;
            if done >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(done, 1);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_rules").await,
            1
        );
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_sets WHERE asset_id = 'a1'"
            )
            .await,
            1
        );
    }
}
