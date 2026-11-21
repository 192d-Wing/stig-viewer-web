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
use std::future::Future;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::api::checklist_save::{
    save_to_asset, SaveOrigin, SaveRequest, SaveResponse, SaveRule, MAX_TEXT_BYTES,
};
use crate::api::checklists::is_valid_stig_id;
use crate::api::request_ctx::RequestCtx;
use crate::api::rule_bulk_status::{has_nul, MAX_RULES, MAX_RULE_ID_BYTES, VALID_STATUSES};
use crate::db_assets;
use crate::db_audit::{self, NewAuditEvent};
use crate::db_checklist_sets::{
    self as db, AddStig, CreateOutcome, RuleChange, SetBudget, WriteOutcome,
};
use crate::detached::{self, Limits, Origin, Shield, Stopped};
use crate::AppState;

const MAX_SETS_PER_USER: i64 = 50;
const MAX_STIGS_PER_SET: usize = 20;
const MAX_NAME_CHARS: usize = 120;
/// Most stored rules per set: room for 20 STIGs of 500 touched rules each.
const MAX_SET_ROWS: i64 = 10_000;
/// Most stored text per set (rule ids, finding details, comments). A set
/// already over this (the limit was lowered) stays readable, deletable and
/// editable as long as a save does not grow it.
const MAX_SET_BYTES: i64 = 4 * 1024 * 1024;

/// Server deadlines. The client gives up at 15 s (writes) and 60 s (save to
/// system), so the server answers first and the client's retry with the same
/// token resolves as a replay or a plain retry. Postgres cuts a stalled write
/// at 8 s (`db_checklist_sets::STATEMENT_TIMEOUT_MS`), inside the deadline.
const SET_LIMITS: Limits = Limits {
    deadline: Duration::from_secs(10),
    write_grace: Duration::from_secs(10),
};
const SAVE_TO_SYSTEM_LIMITS: Limits = Limits {
    deadline: Duration::from_secs(45),
    write_grace: Duration::from_secs(10),
};
/// Bound on the plain GET routes (not spawned).
const READ_DEADLINE: Duration = Duration::from_secs(10);

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

/// 503 with `Retry-After: 1` and a plain-text body, like admission's.
fn deadline_exceeded() -> ApiError {
    ApiError(Box::new(
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "1")],
            "server deadline exceeded",
        )
            .into_response(),
    ))
}

impl From<Stopped> for ApiError {
    fn from(s: Stopped) -> Self {
        match s {
            Stopped::Panicked => StatusCode::INTERNAL_SERVER_ERROR.into(),
            Stopped::Deadline => deadline_exceeded(),
        }
    }
}

fn map_db(e: anyhow::Error) -> ApiError {
    if db::is_timeout(&e) {
        tracing::warn!("checklist set DB statement timed out: {e:#}");
        return deadline_exceeded();
    }
    tracing::error!("checklist set DB error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR.into()
}

/// Bound a read handler's work to `limit`.
async fn within<T>(limit: Duration, fut: impl Future<Output = ApiResult<T>>) -> ApiResult<T> {
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => {
            tracing::warn!("checklist set read exceeded its deadline");
            Err(deadline_exceeded())
        }
    }
}

fn request_conflict() -> ApiError {
    ApiError(Box::new(
        (
            StatusCode::CONFLICT,
            Json(json!({ "error": "request_id_conflict" })),
        )
            .into_response(),
    ))
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
    /// Optional UUID chosen by the client, reused when it retries a create.
    #[serde(default)]
    pub client_request_id: Option<String>,
}

/// A client-supplied token must be a UUID; stored in its canonical form.
fn canonical_token(raw: Option<&str>) -> Result<Option<String>, StatusCode> {
    match raw {
        None => Ok(None),
        Some(t) if t.len() > 36 => Err(StatusCode::BAD_REQUEST),
        Some(t) => uuid::Uuid::parse_str(t)
            .map(|u| Some(u.hyphenated().to_string()))
            .map_err(|_| StatusCode::BAD_REQUEST),
    }
}

/// Log form of a replay token: its first 8 characters.
fn short(t: &Option<String>) -> String {
    t.as_deref()
        .map(|t| t.chars().take(8).collect())
        .unwrap_or_default()
}

/// Algorithm tag stored in front of every replay digest (`<alg>:<hex>`).
/// Changing it makes in-flight tokens fail closed (409 / not a replay, since
/// the stored and the new digests no longer compare equal), never accepted by
/// mistake.
const DIGEST_ALG: &str = "sha256";

/// Tagged digest (`sha256:<hex>`) of the canonical JSON of `v`. This binds a
/// retry token to the request content it was first used with (idempotency);
/// it is not a MAC or an integrity control, and the tokens are not secrets.
fn body_digest(v: &impl Serialize) -> ApiResult<String> {
    let bytes = serde_json::to_vec(v).map_err(|e| {
        tracing::error!("checklist set fingerprint failed: {e}");
        ApiError::from(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    Ok(format!(
        "{DIGEST_ALG}:{}",
        hex::encode(Sha256::digest(bytes))
    ))
}

/// Digest of what a create request asks for, as sent (the token is excluded).
/// Idempotency binding only.
fn create_fingerprint(req: &CreateRequest) -> ApiResult<String> {
    body_digest(&("checklist-set.create.v1", &req.name, &req.stig_ids))
}

/// Digest of what an autosave asks for, as sent and before dedupe (the token
/// is excluded). Idempotency binding only.
fn autosave_fingerprint(req: &AutosaveRequest) -> ApiResult<String> {
    let changes: Vec<(&str, &str, &str, &str, &str)> = req
        .changes
        .iter()
        .map(|c| {
            (
                c.stig_id.as_str(),
                c.rule_id.as_str(),
                c.status.as_str(),
                c.finding_details.as_str(),
                c.comments.as_str(),
            )
        })
        .collect();
    body_digest(&("checklist-set.autosave.v1", req.revision, changes))
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
    /// Optional UUID naming this request, so an exact retry is recognised.
    #[serde(default)]
    pub save_id: Option<String>,
}

#[derive(Debug, PartialEq, Serialize)]
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
    ctx: &'a RequestCtx,
    action: &'static str,
    outcome: &'static str,
    stig_id: Option<&'a str>,
    detail: serde_json::Value,
) -> NewAuditEvent<'a> {
    NewAuditEvent {
        user_id: &user.id,
        ctx: Some(ctx),
        action,
        outcome,
        asset_id: None,
        checklist_id: None,
        stig_id,
        detail,
    }
}

/// The asset's name, only when the caller can still read it. Runs on the
/// caller's (bounded) connection.
async fn visible_asset_name(
    conn: &mut PgConnection,
    user: &AuthUser,
    asset_id: Option<&str>,
    name: Option<String>,
) -> ApiResult<Option<String>> {
    let (Some(id), Some(name)) = (asset_id, name) else {
        return Ok(None);
    };
    // A database error (a timeout included) is a 503, not a hidden name.
    let ok = asset_acl::user_can_on(conn, id, user, "read")
        .await
        .map_err(map_db)?;
    Ok(ok.then_some(name))
}

async fn detail_of(state: &AppState, user: &AuthUser, id: &str) -> ApiResult<ChecklistSetDetail> {
    detail_within(state, user, id, crate::db::STATEMENT_TIMEOUT_MS).await
}

/// [`detail_of`] with an explicit database bound in milliseconds.
async fn detail_within(
    state: &AppState,
    user: &AuthUser,
    id: &str,
    bound_ms: i64,
) -> ApiResult<ChecklistSetDetail> {
    // One short bounded transaction for every read, committed at the end.
    let mut tx = crate::db::begin_bounded_ms(state.pool.as_ref(), bound_ms)
        .await
        .map_err(map_db)?;
    let set = db::get_set(&mut *tx, &user.id, id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let stigs = db::list_stigs(&mut *tx, &user.id, id)
        .await
        .map_err(map_db)?;
    let rules = db::list_rules(&mut *tx, &user.id, id)
        .await
        .map_err(map_db)?;
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
            let name = db_assets::get_asset_on(&mut tx, a)
                .await
                .map_err(map_db)?
                .map(|x| x.name);
            visible_asset_name(&mut tx, user, Some(a), name).await?
        }
        None => None,
    };
    tx.commit().await.map_err(|e| map_db(e.into()))?;
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
async fn catalog_stig(conn: &mut PgConnection, stig_id: &str) -> ApiResult<(String, String)> {
    if !is_valid_stig_id(stig_id) {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    db::catalog_entry(&mut *conn, stig_id)
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
    within(
        READ_DEADLINE,
        list_within(&state, &user, crate::db::STATEMENT_TIMEOUT_MS),
    )
    .await
}

/// The list read with an explicit database bound in milliseconds.
async fn list_within(
    state: &AppState,
    user: &AuthUser,
    bound_ms: i64,
) -> ApiResult<Json<Vec<ChecklistSetSummary>>> {
    {
        let mut tx = crate::db::begin_bounded_ms(state.pool.as_ref(), bound_ms)
            .await
            .map_err(map_db)?;
        let rows = db::list_sets(&mut *tx, &user.id).await.map_err(map_db)?;
        let mut out = Vec::with_capacity(rows.len());
        // One ACL answer per distinct asset.
        let mut readable: HashMap<String, bool> = HashMap::new();
        for r in rows {
            let asset_name = match r.asset_id.as_deref() {
                Some(a) if r.asset_name.is_some() => {
                    let ok = match readable.get(a) {
                        Some(ok) => *ok,
                        None => {
                            let ok = asset_acl::user_can_on(&mut tx, a, user, "read")
                                .await
                                .map_err(map_db)?;
                            readable.insert(a.to_string(), ok);
                            ok
                        }
                    };
                    r.asset_name.filter(|_| ok)
                }
                _ => None,
            };
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
        tx.commit().await.map_err(|e| map_db(e.into()))?;
        Ok(Json(out))
    }
}

/// POST /api/checklist-sets
///
/// Runs in a spawned task so a client disconnect cannot land between the
/// commit and its audit event (a replay writes no second event).
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Json(req): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<ChecklistSetDetail>)> {
    let origin = Origin {
        what: "set create",
        user_id: user.id.clone(),
        request_id: ctx.request_id.clone(),
    };
    let tasks = state.tasks.clone();
    detached::run_bounded(&tasks, origin, SET_LIMITS, move |shield| {
        create_work(state, user, ctx, req, shield)
    })
    .await
    .map_err(ApiError::from)?
}

async fn create_work(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    req: CreateRequest,
    shield: Shield,
) -> ApiResult<(StatusCode, Json<ChecklistSetDetail>)> {
    let pool = state.pool.as_ref();
    let create_key = canonical_token(req.client_request_id.as_deref())?;
    let fingerprint = match create_key {
        Some(_) => Some(create_fingerprint(&req)?),
        None => None,
    };
    let token = match (create_key.as_deref(), fingerprint.as_deref()) {
        (Some(id), Some(body_digest)) => Some(db::Token { id, body_digest }),
        _ => None,
    };
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
    let mut tx = crate::db::begin_bounded(pool).await.map_err(map_db)?;
    for id in &ids {
        let (version, release) = catalog_stig(&mut tx, id).await?;
        stigs.push(((*id).clone(), version, release));
    }
    tx.commit().await.map_err(|e| map_db(e.into()))?;
    let name = match req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => clean_name(n).ok_or(StatusCode::BAD_REQUEST)?,
        None => {
            let default = format!("{} {}", stigs[0].0, Utc::now().format("%Y-%m-%d"));
            default.chars().take(MAX_NAME_CHARS).collect()
        }
    };
    let id = uuid::Uuid::new_v4().to_string();
    let hold = shield.hold();
    match db::insert_set(pool, &user.id, &id, &name, &stigs, MAX_SETS_PER_USER, token)
        .await
        .map_err(map_db)?
    {
        CreateOutcome::Created => {}
        CreateOutcome::Existing(existing) => {
            drop(hold);
            tracing::info!(user = %user.id, set = %existing, token = %short(&create_key), "checklist set create replayed");
            return Ok((
                StatusCode::OK,
                Json(detail_of(&state, &user, &existing).await?),
            ));
        }
        CreateOutcome::KeyConflict {
            set_id,
            stored_digest,
        } => {
            tracing::warn!(user = %user.id, token = %short(&create_key), "checklist set create token reused with different content");
            // Recorded while the shield is held, like the ok events. An exact
            // repeat within `db_audit::collapse`'s window is folded into the
            // first row's `repeat_count` / `last_occurred_at`; this is intended.
            db_audit::record_or_log(
                pool,
                event(
                    &user,
                    &ctx,
                    "checklist_set.create",
                    "denied",
                    None,
                    json!({
                        "setId": set_id,
                        "reason": "request_id_conflict",
                        "token": short(&create_key),
                        "storedDigest": stored_digest,
                    }),
                ),
            )
            .await;
            drop(hold);
            return Err(request_conflict());
        }
        CreateOutcome::Limit => {
            return Err(ApiError(Box::new(
                (StatusCode::CONFLICT, Json(json!({ "error": "set_limit" }))).into_response(),
            )));
        }
    }
    db_audit::record_or_log(
        pool,
        event(
            &user,
            &ctx,
            "checklist_set.create",
            "ok",
            None,
            json!({ "setId": id, "stigs": stigs.len() }),
        ),
    )
    .await;
    drop(hold);
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
    within(READ_DEADLINE, async {
        Ok(Json(detail_of(&state, &user, &id).await?))
    })
    .await
}

/// PATCH /api/checklist-sets/:id — rename, or unlink (`assetId: null`).
/// Linking happens only through save-to-system.
///
/// Runs in a spawned task so a client disconnect cannot land between a
/// commit and its audit event.
pub async fn patch_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
    Json(req): Json<PatchRequest>,
) -> ApiResult<Json<ChecklistSetDetail>> {
    let origin = Origin {
        what: "set patch",
        user_id: user.id.clone(),
        request_id: ctx.request_id.clone(),
    };
    let tasks = state.tasks.clone();
    detached::run_bounded(&tasks, origin, SET_LIMITS, move |shield| {
        patch_work(state, user, ctx, id, req, shield)
    })
    .await
    .map_err(ApiError::from)?
}

async fn patch_work(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    id: String,
    req: PatchRequest,
    shield: Shield,
) -> ApiResult<Json<ChecklistSetDetail>> {
    let pool = state.pool.as_ref();
    if matches!(req.asset_id, Some(Some(_))) {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let name = match req.name.as_deref() {
        Some(n) => Some(clean_name(n).ok_or(StatusCode::BAD_REQUEST)?),
        None => None,
    };
    let mut tx = crate::db::begin_bounded(pool).await.map_err(map_db)?;
    let found = db::get_set(&mut *tx, &user.id, &id)
        .await
        .map_err(map_db)?
        .is_some();
    tx.commit().await.map_err(|e| map_db(e.into()))?;
    if !found {
        return Err(StatusCode::NOT_FOUND.into());
    }
    let hold = shield.hold();
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
                &ctx,
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
                &ctx,
                "checklist_set.unlink",
                "ok",
                None,
                json!({ "setId": id }),
            );
            ev.asset_id = Some(&prev);
            db_audit::record_or_log(pool, ev).await;
        }
    }
    drop(hold);
    Ok(Json(detail_of(&state, &user, &id).await?))
}

/// DELETE /api/checklist-sets/:id
///
/// Runs in a spawned task so a client disconnect cannot land between the
/// commit and its audit event.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let origin = Origin {
        what: "set delete",
        user_id: user.id.clone(),
        request_id: ctx.request_id.clone(),
    };
    let tasks = state.tasks.clone();
    detached::run_bounded(&tasks, origin, SET_LIMITS, move |shield| {
        delete_work(state, user, ctx, id, shield)
    })
    .await
    .map_err(ApiError::from)?
}

async fn delete_work(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    id: String,
    shield: Shield,
) -> ApiResult<StatusCode> {
    let pool = state.pool.as_ref();
    let _hold = shield.hold();
    if !db::delete_set(pool, &user.id, &id).await.map_err(map_db)? {
        return Err(StatusCode::NOT_FOUND.into());
    }
    db_audit::record_or_log(
        pool,
        event(
            &user,
            &ctx,
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
///
/// Runs in a spawned task so a client disconnect cannot land between the
/// commit and its audit event.
pub async fn add_stig_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
    Json(req): Json<AddStigRequest>,
) -> ApiResult<Json<ChecklistSetDetail>> {
    let origin = Origin {
        what: "set stig add",
        user_id: user.id.clone(),
        request_id: ctx.request_id.clone(),
    };
    let tasks = state.tasks.clone();
    detached::run_bounded(&tasks, origin, SET_LIMITS, move |shield| {
        add_stig_work(state, user, ctx, id, req, shield)
    })
    .await
    .map_err(ApiError::from)?
}

async fn add_stig_work(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    id: String,
    req: AddStigRequest,
    shield: Shield,
) -> ApiResult<Json<ChecklistSetDetail>> {
    let pool = state.pool.as_ref();
    let mut tx = crate::db::begin_bounded(pool).await.map_err(map_db)?;
    if db::get_set(&mut *tx, &user.id, &id)
        .await
        .map_err(map_db)?
        .is_none()
    {
        return Err(StatusCode::NOT_FOUND.into());
    }
    let (version, release) = catalog_stig(&mut tx, &req.stig_id).await?;
    tx.commit().await.map_err(|e| map_db(e.into()))?;
    let hold = shield.hold();
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
                    &ctx,
                    "checklist_set.stig_add",
                    "ok",
                    Some(&req.stig_id),
                    json!({ "setId": id }),
                ),
            )
            .await;
        }
    }
    drop(hold);
    Ok(Json(detail_of(&state, &user, &id).await?))
}

/// DELETE /api/checklist-sets/:id/stigs/:stig_id
///
/// Runs in a spawned task so a client disconnect cannot land between the
/// commit and its audit event.
pub async fn remove_stig_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path((id, stig_id)): Path<(String, String)>,
) -> ApiResult<Json<ChecklistSetDetail>> {
    let origin = Origin {
        what: "set stig remove",
        user_id: user.id.clone(),
        request_id: ctx.request_id.clone(),
    };
    let tasks = state.tasks.clone();
    detached::run_bounded(&tasks, origin, SET_LIMITS, move |shield| {
        remove_stig_work(state, user, ctx, id, stig_id, shield)
    })
    .await
    .map_err(ApiError::from)?
}

async fn remove_stig_work(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    id: String,
    stig_id: String,
    shield: Shield,
) -> ApiResult<Json<ChecklistSetDetail>> {
    let pool = state.pool.as_ref();
    let hold = shield.hold();
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
                &ctx,
                "checklist_set.stig_remove",
                "ok",
                sid,
                json!({ "setId": id }),
            ),
        )
        .await;
    }
    drop(hold);
    Ok(Json(detail_of(&state, &user, &id).await?))
}

/// PATCH /api/checklist-sets/:id/rules — autosave.
pub async fn autosave_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
    Json(req): Json<AutosaveRequest>,
) -> ApiResult<Json<AutosaveResponse>> {
    let budget = SetBudget {
        max_rows_per_stig: MAX_RULES as i64,
        max_rows: MAX_SET_ROWS,
        max_bytes: MAX_SET_BYTES,
    };
    autosave_run(state, user, ctx, id, req, budget, SET_LIMITS).await
}

/// Spawned so a client disconnect cannot land between the commit and the
/// audit event (a retry is acknowledged without a second event).
async fn autosave_run(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    id: String,
    req: AutosaveRequest,
    budget: SetBudget,
    limits: Limits,
) -> ApiResult<Json<AutosaveResponse>> {
    let origin = Origin {
        what: "set autosave",
        user_id: user.id.clone(),
        request_id: ctx.request_id.clone(),
    };
    let tasks = state.tasks.clone();
    detached::run_bounded(&tasks, origin, limits, move |shield| {
        autosave_with_budget(state, user, ctx, id, req, budget, shield)
    })
    .await
    .map_err(ApiError::from)?
}

/// Audit a refused reuse of an autosave token (`save_id_conflict`). Callers
/// hold the shield, like the ok events. `db_audit::collapse` folds an exact
/// repeat within its window into the first row's `repeat_count` /
/// `last_occurred_at`; this is intended.
#[allow(clippy::too_many_arguments)]
async fn record_save_id_conflict(
    pool: &sqlx::PgPool,
    user: &AuthUser,
    ctx: &RequestCtx,
    set_id: &str,
    save_id: &Option<String>,
    base_revision: i64,
    revision: i64,
    stored_digest: bool,
) {
    db_audit::record_or_log(
        pool,
        event(
            user,
            ctx,
            "checklist_set.edit",
            "denied",
            None,
            json!({
                "setId": set_id,
                "reason": "save_id_conflict",
                "token": short(save_id),
                "baseRevision": base_revision,
                "revision": revision,
                "storedDigest": stored_digest,
            }),
        ),
    )
    .await;
}

/// Autosave with explicit size bounds (tests pass small ones).
async fn autosave_with_budget(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    id: String,
    req: AutosaveRequest,
    budget: SetBudget,
    shield: Shield,
) -> ApiResult<Json<AutosaveResponse>> {
    let pool = state.pool.as_ref();
    if req.changes.len() > MAX_RULES {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let mut tx = crate::db::begin_bounded(pool).await.map_err(map_db)?;
    let set = db::get_set(&mut *tx, &user.id, &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let members: HashSet<String> = db::list_stigs(&mut *tx, &user.id, &id)
        .await
        .map_err(map_db)?
        .into_iter()
        .map(|s| s.stig_id)
        .collect();
    tx.commit().await.map_err(|e| map_db(e.into()))?;
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
    let save_id = canonical_token(req.save_id.as_deref())?;
    let fingerprint = match save_id {
        Some(_) => Some(autosave_fingerprint(&req)?),
        None => None,
    };
    let token = match (save_id.as_deref(), fingerprint.as_deref()) {
        (Some(id), Some(body_digest)) => Some(db::Token { id, body_digest }),
        _ => None,
    };
    if req.revision != set.revision {
        if db::is_replay(&set, req.revision, token.as_ref()) {
            tracing::info!(user = %user.id, set = %id, token = %short(&save_id), "checklist set autosave replayed");
            return Ok(Json(AutosaveResponse {
                revision: set.revision,
                updated_at: set.updated_at,
            }));
        }
        if db::is_token_reuse(&set, req.revision, token.as_ref()) {
            tracing::warn!(user = %user.id, set = %id, token = %short(&save_id), "checklist set autosave token reused with different content");
            let _hold = shield.hold();
            record_save_id_conflict(
                pool,
                &user,
                &ctx,
                &id,
                &save_id,
                req.revision,
                set.revision,
                set.last_save_body_digest.is_some(),
            )
            .await;
        }
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
    let hold = shield.hold();
    let outcome = db::write_rules(pool, &user.id, &id, req.revision, &changes, budget, token)
        .await
        .map_err(map_db)?;
    match outcome {
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
                        &ctx,
                        "checklist_set.edit",
                        "ok",
                        None,
                        json!({ "setId": id, "changes": changes.len(), "stigIds": stig_ids }),
                    ),
                )
                .await;
            }
            drop(hold);
            Ok(Json(AutosaveResponse {
                revision,
                updated_at,
            }))
        }
        WriteOutcome::Replayed {
            revision,
            updated_at,
        } => {
            tracing::info!(user = %user.id, set = %id, token = %short(&save_id), "checklist set autosave replayed");
            Ok(Json(AutosaveResponse {
                revision,
                updated_at,
            }))
        }
        WriteOutcome::NotFound => Err(StatusCode::NOT_FOUND.into()),
        WriteOutcome::Conflict {
            revision,
            token_reused,
            stored_digest,
        } => {
            if token_reused {
                tracing::warn!(user = %user.id, set = %id, token = %short(&save_id), "checklist set autosave token reused with different content");
                record_save_id_conflict(
                    pool,
                    &user,
                    &ctx,
                    &id,
                    &save_id,
                    req.revision,
                    revision,
                    stored_digest,
                )
                .await;
            }
            drop(hold);
            Err(conflict(revision))
        }
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
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
    Json(req): Json<SaveToSystemRequest>,
) -> ApiResult<Json<SetSaveResponse>> {
    let origin = Origin {
        what: "set save",
        user_id: user.id.clone(),
        request_id: ctx.request_id.clone(),
    };
    let tasks = state.tasks.clone();
    detached::run_bounded(&tasks, origin, SAVE_TO_SYSTEM_LIMITS, move |shield| {
        save_to_system_work(state, user, ctx, id, req, shield)
    })
    .await
    .map_err(ApiError::from)?
}

async fn save_to_system_work(
    state: AppState,
    user: AuthUser,
    ctx: RequestCtx,
    id: String,
    req: SaveToSystemRequest,
    shield: Shield,
) -> ApiResult<Json<SetSaveResponse>> {
    let pool = state.pool.as_ref();
    // Three short bounded transactions; every reject and audit record runs
    // after the commit of the one before it, never inside one.
    let mut tx = crate::db::begin_bounded(pool).await.map_err(map_db)?;
    let set = db::get_set(&mut *tx, &user.id, &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    tx.commit().await.map_err(|e| map_db(e.into()))?;
    // Every later exit records an event, so hold from here on.
    let _hold = shield.hold();
    // Early refusals leave a record too; no asset id until it is known to exist.
    let reject = |reason: &'static str| {
        db_audit::record_or_log(
            pool,
            event(
                &user,
                &ctx,
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
    let mut tx = crate::db::begin_bounded(pool).await.map_err(map_db)?;
    let found = db_assets::get_asset_on(&mut tx, &target)
        .await
        .map_err(map_db)?;
    let can_write = match &found {
        Some(a) => Some(
            asset_acl::user_can_on(&mut tx, &a.id, &user, "write")
                .await
                .map_err(map_db)?,
        ),
        None => None,
    };
    tx.commit().await.map_err(|e| map_db(e.into()))?;
    let Some(asset) = found else {
        reject("asset_not_found").await;
        return Err(StatusCode::NOT_FOUND.into());
    };
    let record = |outcome: &'static str, detail: serde_json::Value| {
        let mut ev = event(
            &user,
            &ctx,
            "checklist_set.save_to_system",
            outcome,
            None,
            detail,
        );
        ev.asset_id = Some(&asset.id);
        db_audit::record_or_log(pool, ev)
    };
    if can_write != Some(true) {
        record("denied", json!({ "setId": id, "reason": "forbidden" })).await;
        return Err(StatusCode::FORBIDDEN.into());
    }
    let mut tx = crate::db::begin_bounded(pool).await.map_err(map_db)?;
    let stigs = db::list_stigs(&mut *tx, &user.id, &id)
        .await
        .map_err(map_db)?;
    let rules = db::list_rules(&mut *tx, &user.id, &id)
        .await
        .map_err(map_db)?;
    // What is pushed must be what the user last saw saved: re-check after the reads.
    let after = db::get_set(&mut *tx, &user.id, &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    tx.commit().await.map_err(|e| map_db(e.into()))?;
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
            match save_to_asset(&state, &user, &ctx, &asset, &save_req, origin).await {
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

    fn cx() -> Extension<RequestCtx> {
        Extension(crate::test_fixtures::ctx())
    }

    fn st(state: &AppState) -> State<AppState> {
        State(state.clone())
    }

    async fn make(state: &AppState, who: &str, ids: &[&str]) -> ChecklistSetDetail {
        let req = CreateRequest {
            name: None,
            stig_ids: ids.iter().map(|s| s.to_string()).collect(),
            client_request_id: None,
        };
        let Ok((code, Json(d))) =
            create_handler(st(state), Extension(auth(who, "author")), cx(), Json(req)).await
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
            cx(),
            Path(id.into()),
            Json(AutosaveRequest {
                revision,
                changes,
                save_id: None,
            }),
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
            cx(),
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
                code(patch_handler(st(&state), u(), cx(), id(), Json(p)).await),
                Some(StatusCode::NOT_FOUND)
            );
            let add = AddStigRequest {
                stig_id: STIG2.into(),
            };
            assert_eq!(
                code(add_stig_handler(st(&state), u(), cx(), id(), Json(add)).await),
                Some(StatusCode::NOT_FOUND)
            );
            let rm = Path((set.id.clone(), STIG_ID.to_string()));
            assert_eq!(
                code(remove_stig_handler(st(&state), u(), cx(), rm).await),
                Some(StatusCode::NOT_FOUND)
            );
            let a = AutosaveRequest {
                revision: 0,
                changes: vec![],
                save_id: None,
            };
            assert_eq!(
                code(autosave_handler(st(&state), u(), cx(), id(), Json(a)).await),
                Some(StatusCode::NOT_FOUND)
            );
            let s = SaveToSystemRequest {
                revision: 0,
                asset_id: Some("a1".into()),
            };
            assert_eq!(
                code(save_to_system_handler(st(&state), u(), cx(), id(), Json(s)).await),
                Some(StatusCode::NOT_FOUND)
            );
            assert_eq!(
                code(delete_handler(st(&state), u(), cx(), id()).await),
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
            client_request_id: None,
        };
        for ids in [
            vec![],
            vec!["../x".to_string()],
            vec!["NOPE".to_string()],
            (0..21).map(|i| format!("S{i}")).collect(),
        ] {
            assert_eq!(
                code(create_handler(st(&state), u(), cx(), Json(bad(ids))).await),
                Some(StatusCode::BAD_REQUEST)
            );
        }
        let named = CreateRequest {
            name: Some("a\u{0}b".into()),
            stig_ids: vec![STIG_ID.into()],
            client_request_id: None,
        };
        assert_eq!(
            code(create_handler(st(&state), u(), cx(), Json(named)).await),
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
            client_request_id: None,
        };
        let r = create_handler(
            st(&state),
            Extension(auth("owner", "author")),
            cx(),
            Json(req),
        )
        .await;
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
                crate::test_fixtures::ctx(),
                set.id.clone(),
                AutosaveRequest {
                    revision,
                    changes,
                    save_id: None,
                },
                b,
                Shield::default(),
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

    const KEY_A: &str = "0b9d6f0e-39a4-4d7a-9a0e-5d6a1c2b3e4f";
    const KEY_B: &str = "7c1e2f3a-4b5c-4d6e-8f70-91a2b3c4d5e6";

    async fn create_keyed(
        state: &AppState,
        who: &str,
        key: &str,
    ) -> Result<(StatusCode, ChecklistSetDetail), StatusCode> {
        let req = CreateRequest {
            name: None,
            stig_ids: vec![STIG_ID.into()],
            client_request_id: Some(key.into()),
        };
        create_handler(st(state), Extension(auth(who, "author")), cx(), Json(req))
            .await
            .map(|(c, Json(d))| (c, d))
            .map_err(|e| e.into_response().status())
    }

    async fn autosave_keyed(
        state: &AppState,
        id: &str,
        revision: i64,
        save_id: &str,
        changes: Vec<SetRuleChange>,
    ) -> Result<AutosaveResponse, StatusCode> {
        autosave_handler(
            st(state),
            Extension(auth("owner", "author")),
            cx(),
            Path(id.into()),
            Json(AutosaveRequest {
                revision,
                changes,
                save_id: Some(save_id.into()),
            }),
        )
        .await
        .map(|Json(r)| r)
        .map_err(|e| e.into_response().status())
    }

    #[test]
    fn tokens_must_be_uuids_and_are_canonicalised() {
        assert_eq!(canonical_token(None), Ok(None));
        assert_eq!(
            canonical_token(Some("0B9D6F0E-39A4-4D7A-9A0E-5D6A1C2B3E4F")),
            Ok(Some(KEY_A.to_string()))
        );
        for bad in ["", "abc", "not-a-uuid-at-all", &"a".repeat(500)] {
            assert_eq!(canonical_token(Some(bad)), Err(StatusCode::BAD_REQUEST));
        }
    }

    #[test]
    fn replay_needs_a_matching_id_one_revision_behind() {
        let at = |revision, last: Option<&str>, hash: Option<&str>| db::SetRow {
            id: "s".into(),
            name: "n".into(),
            asset_id: None,
            revision,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_attached_at: None,
            last_save_id: last.map(str::to_string),
            last_save_body_digest: hash.map(str::to_string),
        };
        let h1 = "a".repeat(64);
        let h2 = "b".repeat(64);
        let tok = |id, h| db::Token { id, body_digest: h };
        let stored = Some(h1.as_str());
        assert!(db::is_replay(
            &at(1, Some(KEY_A), stored),
            0,
            Some(&tok(KEY_A, &h1))
        ));
        assert!(!db::is_replay(
            &at(2, Some(KEY_A), stored),
            0,
            Some(&tok(KEY_A, &h1))
        ));
        assert!(!db::is_replay(
            &at(1, Some(KEY_A), stored),
            0,
            Some(&tok(KEY_B, &h1))
        ));
        assert!(!db::is_replay(&at(1, Some(KEY_A), stored), 0, None));
        assert!(!db::is_replay(
            &at(1, None, None),
            0,
            Some(&tok(KEY_A, &h1))
        ));
        // Same token, different content: not a replay.
        assert!(!db::is_replay(
            &at(1, Some(KEY_A), stored),
            0,
            Some(&tok(KEY_A, &h2))
        ));
        // A row with no stored digest (written before it existed) is not a replay.
        assert!(!db::is_replay(
            &at(1, Some(KEY_A), None),
            0,
            Some(&tok(KEY_A, &h2))
        ));
    }

    #[test]
    fn body_digest_is_tagged_with_its_algorithm() {
        let d = body_digest(&("x", 1)).ok().unwrap();
        let hex = d.strip_prefix("sha256:").unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(DIGEST_ALG == "sha256");
    }

    #[test]
    fn token_reuse_is_the_refused_case_of_the_replay_window() {
        let at = |revision, last: Option<&str>, hash: Option<&str>| db::SetRow {
            id: "s".into(),
            name: "n".into(),
            asset_id: None,
            revision,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_attached_at: None,
            last_save_id: last.map(str::to_string),
            last_save_body_digest: hash.map(str::to_string),
        };
        let h1 = "sha256:".to_string() + &"a".repeat(64);
        let h2 = "sha256:".to_string() + &"b".repeat(64);
        let tok = |id, h| db::Token { id, body_digest: h };
        let stored = Some(h1.as_str());
        // Same id, one revision behind, different content: refused reuse.
        assert!(db::is_token_reuse(
            &at(1, Some(KEY_A), stored),
            0,
            Some(&tok(KEY_A, &h2))
        ));
        // An exact retry is a replay, not a reuse.
        assert!(!db::is_token_reuse(
            &at(1, Some(KEY_A), stored),
            0,
            Some(&tok(KEY_A, &h1))
        ));
        // A later write, another token, or no token is not a reuse.
        assert!(!db::is_token_reuse(
            &at(2, Some(KEY_A), stored),
            0,
            Some(&tok(KEY_A, &h2))
        ));
        assert!(!db::is_token_reuse(
            &at(1, Some(KEY_A), stored),
            0,
            Some(&tok(KEY_B, &h2))
        ));
        assert!(!db::is_token_reuse(&at(1, Some(KEY_A), stored), 0, None));
        // No stored digest: the token is refused, so it counts as a reuse.
        assert!(db::is_token_reuse(
            &at(1, Some(KEY_A), None),
            0,
            Some(&tok(KEY_A, &h1))
        ));
        assert!(!db::is_token_reuse(
            &at(1, None, None),
            0,
            Some(&tok(KEY_A, &h2))
        ));
    }

    fn create_req(name: Option<&str>, ids: &[&str]) -> CreateRequest {
        CreateRequest {
            name: name.map(str::to_string),
            stig_ids: ids.iter().map(|s| s.to_string()).collect(),
            client_request_id: Some(KEY_A.into()),
        }
    }

    fn save_req(revision: i64, changes: Vec<SetRuleChange>) -> AutosaveRequest {
        AutosaveRequest {
            revision,
            changes,
            save_id: Some(KEY_A.into()),
        }
    }

    fn cfp(r: &CreateRequest) -> String {
        create_fingerprint(r).ok().unwrap()
    }

    fn afp(r: &AutosaveRequest) -> String {
        autosave_fingerprint(r).ok().unwrap()
    }

    #[test]
    fn create_fingerprint_binds_content_but_not_the_token() {
        let base = create_req(Some("n"), &["A", "B"]);
        let f = cfp(&base);
        assert_eq!(f.len(), "sha256:".len() + 64);
        assert_eq!(f, cfp(&create_req(Some("n"), &["A", "B"])));
        let mut other_token = create_req(Some("n"), &["A", "B"]);
        other_token.client_request_id = Some(KEY_B.into());
        assert_eq!(f, cfp(&other_token));
        assert_ne!(f, cfp(&create_req(Some("m"), &["A", "B"])));
        assert_ne!(f, cfp(&create_req(None, &["A", "B"])));
        assert_ne!(f, cfp(&create_req(Some("n"), &["B", "A"])));
        assert_ne!(f, cfp(&create_req(Some("n"), &["A"])));
    }

    #[test]
    fn autosave_fingerprint_binds_content_but_not_the_token() {
        let one = || change("S", "r1", "open", "d", "c");
        let f = afp(&save_req(3, vec![one()]));
        assert_eq!(f.len(), "sha256:".len() + 64);
        assert_eq!(f, afp(&save_req(3, vec![one()])));
        let mut other_token = save_req(3, vec![one()]);
        other_token.save_id = Some(KEY_B.into());
        assert_eq!(f, afp(&other_token));
        assert_ne!(f, afp(&save_req(4, vec![one()])));
        for tweaked in [
            change("T", "r1", "open", "d", "c"),
            change("S", "r2", "open", "d", "c"),
            change("S", "r1", "not_a_finding", "d", "c"),
            change("S", "r1", "open", "e", "c"),
            change("S", "r1", "open", "d", "x"),
        ] {
            assert_ne!(f, afp(&save_req(3, vec![tweaked])));
        }
        // Order and repeats count: the hash covers the request as sent.
        let two = || change("S", "r2", "open", "", "");
        assert_ne!(
            afp(&save_req(3, vec![one(), two()])),
            afp(&save_req(3, vec![two(), one()]))
        );
        assert_ne!(
            afp(&save_req(3, vec![one()])),
            afp(&save_req(3, vec![one(), one()]))
        );
    }

    #[test]
    fn server_deadlines_sit_inside_the_client_ones() {
        // Client: 15 s for set requests, 60 s for save to system.
        assert_eq!(SET_LIMITS.deadline, Duration::from_secs(10));
        assert_eq!(SET_LIMITS.write_grace, Duration::from_secs(10));
        assert_eq!(SAVE_TO_SYSTEM_LIMITS.deadline, Duration::from_secs(45));
        assert_eq!(SAVE_TO_SYSTEM_LIMITS.write_grace, Duration::from_secs(10));
        assert_eq!(READ_DEADLINE, Duration::from_secs(10));
        assert!(SET_LIMITS.deadline < Duration::from_secs(15));
        assert!(SAVE_TO_SYSTEM_LIMITS.deadline < Duration::from_secs(60));
        assert!(READ_DEADLINE < Duration::from_secs(15));
    }

    #[test]
    fn a_server_deadline_answers_503_with_retry_after() {
        let res = ApiError::from(Stopped::Deadline).into_response();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(res.headers().get(header::RETRY_AFTER).unwrap(), "1");
        assert_eq!(
            ApiError::from(Stopped::Panicked).into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn the_per_set_byte_budget_is_four_mib() {
        assert_eq!(MAX_SET_BYTES, 4 * 1024 * 1024);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn create_with_same_request_id_returns_the_original(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let (c1, a) = create_keyed(&state, "owner", KEY_A).await.unwrap();
        assert_eq!(c1, StatusCode::CREATED);
        let (c2, b) = create_keyed(&state, "owner", &KEY_A.to_uppercase())
            .await
            .unwrap();
        assert_eq!(c2, StatusCode::OK);
        assert_eq!(a.id, b.id);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_sets").await, 1);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM audit_events WHERE action = 'checklist_set.create'"
            )
            .await,
            1
        );
        // Another owner's identical key is a different set.
        let (c3, other) = create_keyed(&state, "other", KEY_A).await.unwrap();
        assert_eq!(c3, StatusCode::CREATED);
        assert_ne!(other.id, a.id);
        assert_eq!(
            create_keyed(&state, "owner", "nope").await.err(),
            Some(StatusCode::BAD_REQUEST)
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn create_replay_at_the_set_limit_returns_the_original_not_409(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let (_, first) = create_keyed(&state, "owner", KEY_A).await.unwrap();
        for _ in 1..50 {
            make(&state, "owner", &[STIG_ID]).await;
        }
        let (code, again) = create_keyed(&state, "owner", KEY_A).await.unwrap();
        assert_eq!(code, StatusCode::OK);
        assert_eq!(again.id, first.id);
        assert_eq!(
            create_keyed(&state, "owner", KEY_B).await.err(),
            Some(StatusCode::CONFLICT)
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn concurrent_creates_with_one_key_make_one_set(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let (a, b) = tokio::join!(
            create_keyed(&state, "owner", KEY_A),
            create_keyed(&state, "owner", KEY_A)
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.1.id, b.1.id);
        let mut codes = [a.0, b.0];
        codes.sort();
        assert_eq!(codes, [StatusCode::OK, StatusCode::CREATED]);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_sets").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn autosave_replay_with_same_save_id_is_ok_and_writes_nothing(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let edits = || {
            count(
                &pool,
                "SELECT COUNT(*) FROM audit_events WHERE action = 'checklist_set.edit'",
            )
        };
        let body = || vec![change(STIG_ID, RULES[0], "open", "d", "c")];
        let first = autosave_keyed(&state, &set.id, 0, KEY_A, body())
            .await
            .unwrap();
        assert_eq!(first.revision, 1);
        let before = edits().await;
        let again = autosave_keyed(&state, &set.id, 0, KEY_A, body())
            .await
            .unwrap();
        assert_eq!(again.revision, 1);
        assert_eq!(edits().await, before);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            1
        );
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn autosave_replay_is_a_conflict_after_another_write(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let body = || vec![change(STIG_ID, RULES[0], "open", "", "")];
        autosave_keyed(&state, &set.id, 0, KEY_A, body())
            .await
            .unwrap();
        autosave_keyed(&state, &set.id, 1, KEY_B, body())
            .await
            .unwrap();
        assert_eq!(
            autosave_keyed(&state, &set.id, 0, KEY_A, body()).await,
            Err(StatusCode::CONFLICT)
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_stig_removal_clears_the_replay_token(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID, STIG2]).await;
        let body = || vec![change(STIG_ID, RULES[0], "open", "", "")];
        autosave_keyed(&state, &set.id, 0, KEY_A, body())
            .await
            .unwrap();
        let rm = Path((set.id.clone(), STIG2.to_string()));
        assert!(
            remove_stig_handler(st(&state), Extension(auth("owner", "author")), cx(), rm)
                .await
                .is_ok()
        );
        // Revision is now 2; without the clear this would look like a replay.
        assert_eq!(
            autosave_keyed(&state, &set.id, 1, KEY_A, body()).await,
            Err(StatusCode::CONFLICT)
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_keyed_create_after_the_original_was_deleted_makes_a_new_set(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let (_, first) = create_keyed(&state, "owner", KEY_A).await.unwrap();
        let del = delete_handler(
            st(&state),
            Extension(auth("owner", "author")),
            cx(),
            Path(first.id.clone()),
        )
        .await;
        assert_eq!(code(del), None);
        let (c, second) = create_keyed(&state, "owner", KEY_A).await.unwrap();
        assert_eq!(c, StatusCode::CREATED);
        assert_ne!(second.id, first.id);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn autosave_stale_revision_with_unknown_save_id_is_409(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        autosave_keyed(&state, &set.id, 0, KEY_A, vec![])
            .await
            .unwrap();
        assert_eq!(
            autosave_keyed(&state, &set.id, 0, KEY_B, vec![]).await,
            Err(StatusCode::CONFLICT)
        );
        assert_eq!(
            autosave(&state, "owner", &set.id, 0, vec![]).await,
            Err(StatusCode::CONFLICT)
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn over_budget_set_can_shrink_but_not_grow(pool: PgPool) {
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
                crate::test_fixtures::ctx(),
                set.id.clone(),
                AutosaveRequest {
                    revision,
                    changes,
                    save_id: None,
                },
                b,
                Shield::default(),
            )
        };
        // Seed under a roomy budget: 3 rows holding about 300 bytes of text.
        let seed = vec![
            change(STIG_ID, "r0", "open", &"x".repeat(100), ""),
            change(STIG_ID, "r1", "open", &"y".repeat(100), ""),
            change(STIG_ID, "r2", "open", "", &"z".repeat(100)),
        ];
        assert_eq!(code(run(0, seed, budget(100, 1 << 20)).await), None);
        // Now the limits are far below what is stored (2 rows, 100 bytes).
        let tiny = budget(2, 100);
        let status = |r: ApiResult<Json<AutosaveResponse>>| code(r);
        // Shorter text, a same-size status change, and a delete are accepted.
        let shrink = vec![change(STIG_ID, "r0", "open", &"x".repeat(10), "")];
        assert_eq!(status(run(1, shrink, tiny).await), None);
        let flip = vec![change(STIG_ID, "r1", "not_a_finding", &"y".repeat(100), "")];
        assert_eq!(status(run(2, flip, tiny).await), None);
        let delete = vec![change(STIG_ID, "r2", "not_reviewed", "", "")];
        assert_eq!(status(run(3, delete, tiny).await), None);
        // Growing the text or adding a row is refused.
        let grow = vec![change(STIG_ID, "r0", "open", &"x".repeat(50), "")];
        assert_eq!(
            status(run(4, grow, tiny).await),
            Some(StatusCode::PAYLOAD_TOO_LARGE)
        );
        let add = vec![change(STIG_ID, "r9", "open", "", "")];
        assert_eq!(
            status(run(4, add, tiny).await),
            Some(StatusCode::PAYLOAD_TOO_LARGE)
        );
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 4);
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
        let Json(d) = add_stig_handler(st(&state), u(), cx(), Path(set.id.clone()), add(STIG2))
            .await
            .ok()
            .unwrap();
        assert_eq!(d.stigs.len(), 2);
        let Json(d) = add_stig_handler(st(&state), u(), cx(), Path(set.id.clone()), add(STIG2))
            .await
            .ok()
            .unwrap();
        assert_eq!(d.stigs.len(), 2, "idempotent");
        assert_eq!(
            code(add_stig_handler(st(&state), u(), cx(), Path(set.id.clone()), add("NOPE")).await),
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
        let Json(d) =
            remove_stig_handler(st(&state), u(), cx(), Path((set.id.clone(), STIG2.into())))
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
                add_stig_handler(st(&state), u(), cx(), Path(set.id.clone()), add(&id))
                    .await
                    .is_ok()
            );
        }
        seed_catalog(&pool, "EXTRA-X").await;
        assert_eq!(
            code(
                add_stig_handler(st(&state), u(), cx(), Path(set.id.clone()), add("EXTRA-X")).await
            ),
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
        crate::test_fixtures::allow_audit_test_mode(&pool).await;
        // The audit guard (migration 040) allows clearing the audit tables
        // only by TRUNCATE in `test` maintenance mode.
        let mut tx = pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "test")
            .await
            .unwrap();
        sqlx::query("TRUNCATE rule_audit, audit_events")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM checklists")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = 'owner'")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
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
            cx(),
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

    /// Poll `f` once, which submits its detached work, assert it is still
    /// waiting, then drop it: a client abort. The spawned task cannot run
    /// before the caller yields, which holds on the current-thread runtime
    /// `#[sqlx::test]` uses.
    async fn start_then_abort<F: std::future::Future>(tasks: &detached::Tracker, f: F) {
        let mut f = std::pin::pin!(f);
        let pending =
            std::future::poll_fn(|cx| std::task::Poll::Ready(f.as_mut().poll(cx).is_pending()))
                .await;
        assert!(pending, "the handler must still be waiting on its task");
        // The work runs detached: still counted after the caller is gone.
        assert_eq!(tasks.in_flight(), 1);
    }

    async fn audit_count(pool: &PgPool, action: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE action = $1")
            .bind(action)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn audit_count_ok(pool: &PgPool, action: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE action = $1 AND outcome = 'ok'")
            .bind(action)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// `(detail, request_id)` of every `denied` event for `action`.
    async fn denied_events(
        pool: &PgPool,
        action: &str,
    ) -> Vec<(serde_json::Value, Option<String>)> {
        sqlx::query_as(
            "SELECT detail, request_id FROM audit_events
             WHERE action = $1 AND outcome = 'denied' ORDER BY id",
        )
        .bind(action)
        .fetch_all(pool)
        .await
        .unwrap()
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
        start_then_abort(&state.tasks, push(&state, "owner", &set.id, 1, Some("a1"))).await;
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(audit_count(&pool, "checklist_set.save_to_system").await, 1);
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

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_admission_permit_outlives_an_aborted_handler_until_its_task_ends(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let mut c = crate::test_fixtures::ctx();
        c.permit = Some(state.admission.try_admit("owner").unwrap());
        start_then_abort(
            &state.tasks,
            autosave_handler(
                st(&state),
                Extension(auth("owner", "author")),
                Extension(c),
                Path(set.id.clone()),
                Json(AutosaveRequest {
                    revision: 0,
                    changes: vec![change(STIG_ID, RULES[0], "open", "", "")],
                    save_id: None,
                }),
            ),
        )
        .await;
        // The handler is gone; the detached task still holds the permit.
        assert_eq!(state.admission.in_flight(), 1);
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        state.admission.idle().await;
        assert_eq!(state.admission.in_flight(), 0);
        assert_eq!(audit_count(&pool, "checklist_set.edit").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn autosave_and_its_audit_event_survive_the_handler_future_being_dropped(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        start_then_abort(
            &state.tasks,
            autosave(
                &state,
                "owner",
                &set.id,
                0,
                vec![change(STIG_ID, RULES[0], "open", "", "")],
            ),
        )
        .await;
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(audit_count(&pool, "checklist_set.edit").await, 1);
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn rename_and_its_audit_event_survive_the_handler_future_being_dropped(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let p = PatchRequest {
            name: Some("renamed".into()),
            asset_id: None,
        };
        start_then_abort(
            &state.tasks,
            patch_handler(
                st(&state),
                Extension(auth("owner", "author")),
                cx(),
                Path(set.id.clone()),
                Json(p),
            ),
        )
        .await;
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_sets WHERE name = 'renamed'"
            )
            .await,
            1
        );
        assert_eq!(audit_count(&pool, "checklist_set.rename").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn unlink_and_its_audit_event_survive_the_handler_future_being_dropped(pool: PgPool) {
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
        let p = PatchRequest {
            name: None,
            asset_id: Some(None),
        };
        start_then_abort(
            &state.tasks,
            patch_handler(
                st(&state),
                Extension(auth("owner", "author")),
                cx(),
                Path(set.id.clone()),
                Json(p),
            ),
        )
        .await;
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_sets WHERE asset_id IS NOT NULL"
            )
            .await,
            0
        );
        assert_eq!(audit_count(&pool, "checklist_set.unlink").await, 1);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM audit_events WHERE action = 'checklist_set.unlink' AND asset_id = 'a1'"
            )
            .await,
            1
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn delete_and_its_audit_event_survive_the_handler_future_being_dropped(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        start_then_abort(
            &state.tasks,
            delete_handler(
                st(&state),
                Extension(auth("owner", "author")),
                cx(),
                Path(set.id.clone()),
            ),
        )
        .await;
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_sets").await, 0);
        assert_eq!(audit_count(&pool, "checklist_set.delete").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn stig_add_and_its_audit_event_survive_the_handler_future_being_dropped(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        start_then_abort(
            &state.tasks,
            add_stig_handler(
                st(&state),
                Extension(auth("owner", "author")),
                cx(),
                Path(set.id.clone()),
                Json(AddStigRequest {
                    stig_id: STIG2.into(),
                }),
            ),
        )
        .await;
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_stigs").await,
            2
        );
        assert_eq!(audit_count(&pool, "checklist_set.stig_add").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn stig_remove_and_its_audit_event_survive_the_handler_future_being_dropped(
        pool: PgPool,
    ) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID, STIG2]).await;
        start_then_abort(
            &state.tasks,
            remove_stig_handler(
                st(&state),
                Extension(auth("owner", "author")),
                cx(),
                Path((set.id.clone(), STIG2.to_string())),
            ),
        )
        .await;
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_stigs").await,
            1
        );
        assert_eq!(audit_count(&pool, "checklist_set.stig_remove").await, 1);
    }

    // ── Deadlines, content-bound tokens, delete-only saves ─────────────────

    const ROOMY: SetBudget = SetBudget {
        max_rows_per_stig: MAX_RULES as i64,
        max_rows: MAX_SET_ROWS,
        max_bytes: MAX_SET_BYTES,
    };

    async fn body_text(e: ApiError) -> (StatusCode, String) {
        let res = e.into_response();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_request_past_the_server_deadline_is_a_503_and_leaves_no_trace(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let req = || AutosaveRequest {
            revision: 0,
            changes: vec![change(STIG_ID, RULES[0], "open", "", "")],
            save_id: Some(KEY_A.into()),
        };
        let mut lock = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE checklist_sets IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();
        let limits = Limits {
            deadline: Duration::from_millis(200),
            write_grace: Duration::from_secs(30),
        };
        let res = autosave_run(
            state.clone(),
            auth("owner", "author"),
            crate::test_fixtures::ctx(),
            set.id.clone(),
            req(),
            ROOMY,
            limits,
        )
        .await;
        let Err(e) = res else {
            panic!("expected the deadline to cut the request");
        };
        let res = e.into_response();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(res.headers().get(header::RETRY_AFTER).unwrap(), "1");
        lock.rollback().await.unwrap();
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 0);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            0
        );
        assert_eq!(audit_count(&pool, "checklist_set.edit").await, 0);
        // The same request, retried with the same token, succeeds.
        let ok = autosave_run(
            state.clone(),
            auth("owner", "author"),
            crate::test_fixtures::ctx(),
            set.id.clone(),
            req(),
            ROOMY,
            SET_LIMITS,
        )
        .await;
        assert_eq!(ok.ok().map(|Json(r)| r.revision), Some(1));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_read_past_its_deadline_is_a_503(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let mut lock = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE checklist_sets IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();
        let user = auth("owner", "author");
        let r = within(
            Duration::from_millis(200),
            detail_of(&state, &user, &set.id),
        )
        .await;
        assert_eq!(code(r), Some(StatusCode::SERVICE_UNAVAILABLE));
        lock.rollback().await.unwrap();
        // The dropped read's statement finishes once the lock is gone and its
        // connection returns to the pool: a query succeeds promptly.
        let n: i64 = tokio::time::timeout(
            Duration::from_secs(5),
            sqlx::query_scalar("SELECT COUNT(*) FROM checklist_sets").fetch_one(&pool),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(n, 1);
    }

    /// Reads under an ACCESS EXCLUSIVE lock, with a short database bound: the
    /// 503 comes from Postgres cutting the statement (the outer deadline is
    /// ten seconds), and the connection is back in the pool at once.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn read_paths_are_cut_by_the_database_bound_and_release_the_connection(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let user = auth("owner", "author");
        let mut lock = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE checklist_sets IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();
        let t = std::time::Instant::now();
        let r = detail_within(&state, &user, &set.id, 150).await;
        assert_eq!(code(r), Some(StatusCode::SERVICE_UNAVAILABLE));
        let r = list_within(&state, &user, 150).await;
        assert_eq!(code(r), Some(StatusCode::SERVICE_UNAVAILABLE));
        assert!(t.elapsed() < Duration::from_secs(5));
        lock.rollback().await.unwrap();
        // Both connections went back to the pool: a query succeeds promptly.
        let t = std::time::Instant::now();
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_sets").await, 1);
        assert!(t.elapsed() < Duration::from_secs(2));
        assert!(detail_within(&state, &user, &set.id, 150).await.is_ok());
    }

    /// A timeout in the ACL check of a read path is a 503, not a 403 (hidden
    /// name) or a 200.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_timeout_in_the_acl_check_of_a_read_is_a_503(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "other", &[STIG_ID]).await;
        // "other" owns the set but only has a read ACL on owner's asset a1.
        sqlx::query("UPDATE checklist_sets SET asset_id = 'a1'")
            .execute(&pool)
            .await
            .unwrap();
        let user = auth("other", "author");
        assert!(detail_within(&state, &user, &set.id, 150).await.is_ok());
        let mut lock = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE asset_acl IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();
        let r = detail_within(&state, &user, &set.id, 150).await;
        assert_eq!(code(r), Some(StatusCode::SERVICE_UNAVAILABLE));
        let r = list_within(&state, &user, 150).await;
        assert_eq!(code(r), Some(StatusCode::SERVICE_UNAVAILABLE));
        lock.rollback().await.unwrap();
    }

    /// The autosave race arm audits a refused reuse once, with a stored digest.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_save_id_conflict_event_carries_the_stored_digest_flag(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let user = auth("owner", "author");
        let id = Some(KEY_A.to_string());
        for _ in 0..2 {
            // The race arm and the early check share this helper.
            record_save_id_conflict(
                state.pool.as_ref(),
                &user,
                &crate::test_fixtures::ctx(),
                &set.id,
                &id,
                0,
                1,
                true,
            )
            .await;
        }
        crate::db_audit::drain().await;
        let denied = denied_events(&pool, "checklist_set.edit").await;
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].0["reason"], "save_id_conflict");
        assert_eq!(denied[0].0["storedDigest"], true);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_changed_autosave_under_a_used_save_id_is_a_409_and_writes_nothing(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let a = || vec![change(STIG_ID, RULES[0], "open", "d", "c")];
        let b = || vec![change(STIG_ID, RULES[0], "not_a_finding", "other", "c")];
        assert_eq!(
            autosave_keyed(&state, &set.id, 0, KEY_A, a())
                .await
                .unwrap()
                .revision,
            1
        );
        crate::db_audit::drain().await;
        assert_eq!(
            autosave_keyed(&state, &set.id, 0, KEY_A, b()).await,
            Err(StatusCode::CONFLICT)
        );
        crate::db_audit::drain().await;
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 1);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM checklist_set_rules WHERE status = 'open' AND finding_details = 'd'"
            )
            .await,
            1
        );
        assert_eq!(audit_count_ok(&pool, "checklist_set.edit").await, 1);
        // The refusal is audited once, with the token prefix and no content.
        let denied = denied_events(&pool, "checklist_set.edit").await;
        assert_eq!(denied.len(), 1);
        let (detail, request_id) = &denied[0];
        assert_eq!(detail["setId"], set.id.as_str());
        assert_eq!(detail["reason"], "save_id_conflict");
        assert_eq!(detail["token"], &KEY_A[..8]);
        assert_eq!(detail["baseRevision"], 0);
        assert_eq!(detail["revision"], 1);
        assert_eq!(detail["storedDigest"], true);
        assert_eq!(request_id.as_deref(), Some("test-request"));
        // The identical request is still a replay.
        assert_eq!(
            autosave_keyed(&state, &set.id, 0, KEY_A, a())
                .await
                .unwrap()
                .revision,
            1
        );
    }

    async fn create_with(
        state: &AppState,
        key: &str,
        name: Option<&str>,
        ids: &[&str],
    ) -> Result<StatusCode, (StatusCode, String)> {
        let req = CreateRequest {
            name: name.map(str::to_string),
            stig_ids: ids.iter().map(|s| s.to_string()).collect(),
            client_request_id: Some(key.into()),
        };
        match create_handler(
            st(state),
            Extension(auth("owner", "author")),
            cx(),
            Json(req),
        )
        .await
        {
            Ok((c, _)) => Ok(c),
            Err(e) => Err(body_text(e).await),
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_create_key_reused_with_different_content_is_a_409(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        assert_eq!(
            create_with(&state, KEY_A, Some("one"), &[STIG_ID]).await,
            Ok(StatusCode::CREATED)
        );
        for (name, ids) in [(Some("one"), vec![STIG2]), (Some("two"), vec![STIG_ID])] {
            let (c, body) = create_with(&state, KEY_A, name, &ids).await.unwrap_err();
            assert_eq!(c, StatusCode::CONFLICT);
            assert!(body.contains("request_id_conflict"), "{body}");
        }
        crate::db_audit::drain().await;
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_sets").await, 1);
        assert_eq!(audit_count_ok(&pool, "checklist_set.create").await, 1);
        // Each refused reuse is audited; the audit layer's usual collapse of
        // an exact repeat denied event turns the second into a repeat count.
        let denied = denied_events(&pool, "checklist_set.create").await;
        assert_eq!(denied.len(), 1);
        assert_eq!(
            count(
                &pool,
                "SELECT repeat_count::bigint FROM audit_events WHERE outcome = 'denied'"
            )
            .await,
            2
        );
        let set_id: String = sqlx::query_scalar("SELECT id FROM checklist_sets")
            .fetch_one(&pool)
            .await
            .unwrap();
        for (detail, request_id) in &denied {
            assert_eq!(detail["setId"], set_id.as_str());
            assert_eq!(detail["reason"], "request_id_conflict");
            assert_eq!(detail["token"], &KEY_A[..8]);
            assert_eq!(detail["storedDigest"], true);
            assert_eq!(request_id.as_deref(), Some("test-request"));
        }
        assert_eq!(
            create_with(&state, KEY_A, Some("one"), &[STIG_ID]).await,
            Ok(StatusCode::OK)
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn an_autosave_token_with_no_stored_digest_is_not_a_replay(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let a = || vec![change(STIG_ID, RULES[0], "open", "d", "c")];
        assert_eq!(
            autosave_keyed(&state, &set.id, 0, KEY_A, a())
                .await
                .unwrap()
                .revision,
            1
        );
        sqlx::query("UPDATE checklist_sets SET last_save_body_digest = NULL")
            .execute(&pool)
            .await
            .unwrap();
        // The identical retry is refused, not acknowledged.
        let r = autosave_handler(
            st(&state),
            Extension(auth("owner", "author")),
            cx(),
            Path(set.id.clone()),
            Json(AutosaveRequest {
                revision: 0,
                changes: a(),
                save_id: Some(KEY_A.into()),
            }),
        )
        .await;
        let Err(e) = r else {
            panic!("expected a conflict");
        };
        let (code, body) = body_text(e).await;
        assert_eq!(code, StatusCode::CONFLICT);
        assert!(body.contains("\"revision\":1"), "{body}");
        crate::db_audit::drain().await;
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 1);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            1
        );
        assert_eq!(audit_count_ok(&pool, "checklist_set.edit").await, 1);
        let denied = denied_events(&pool, "checklist_set.edit").await;
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].0["reason"], "save_id_conflict");
        assert_eq!(denied[0].0["storedDigest"], false);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_create_key_with_no_stored_digest_is_a_409_and_makes_no_set(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        assert_eq!(
            create_with(&state, KEY_A, Some("one"), &[STIG_ID]).await,
            Ok(StatusCode::CREATED)
        );
        sqlx::query("UPDATE checklist_sets SET create_body_digest = NULL")
            .execute(&pool)
            .await
            .unwrap();
        let (c, body) = create_with(&state, KEY_A, Some("one"), &[STIG_ID])
            .await
            .unwrap_err();
        assert_eq!(c, StatusCode::CONFLICT);
        assert!(body.contains("request_id_conflict"), "{body}");
        crate::db_audit::drain().await;
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_sets").await, 1);
        let denied = denied_events(&pool, "checklist_set.create").await;
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].0["reason"], "request_id_conflict");
        assert_eq!(denied[0].0["storedDigest"], false);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_stig_removal_clears_the_stored_save_hash(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID, STIG2]).await;
        autosave_keyed(
            &state,
            &set.id,
            0,
            KEY_A,
            vec![change(STIG_ID, RULES[0], "open", "", "")],
        )
        .await
        .unwrap();
        let stored = "SELECT COUNT(*) FROM checklist_sets WHERE last_save_body_digest IS NOT NULL";
        assert_eq!(count(&pool, stored).await, 1);
        let rm = Path((set.id.clone(), STIG2.to_string()));
        assert!(
            remove_stig_handler(st(&state), Extension(auth("owner", "author")), cx(), rm)
                .await
                .is_ok()
        );
        assert_eq!(count(&pool, stored).await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn delete_two_add_one_is_accepted_on_an_over_budget_set(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let run = |revision: i64, changes: Vec<SetRuleChange>, b: SetBudget| {
            autosave_with_budget(
                state.clone(),
                auth("owner", "author"),
                crate::test_fixtures::ctx(),
                set.id.clone(),
                AutosaveRequest {
                    revision,
                    changes,
                    save_id: None,
                },
                b,
                Shield::default(),
            )
        };
        let seed = vec![
            change(STIG_ID, "r0", "open", "x", ""),
            change(STIG_ID, "r1", "open", "y", ""),
            change(STIG_ID, "r2", "open", "z", ""),
        ];
        assert_eq!(code(run(0, seed, ROOMY).await), None);
        // One row allowed, three stored: shrinking by one net is fine.
        let tiny = SetBudget {
            max_rows: 1,
            ..ROOMY
        };
        let mixed = vec![
            change(STIG_ID, "r1", "not_reviewed", "", ""),
            change(STIG_ID, "r2", "not_reviewed", "", ""),
            change(STIG_ID, "r9", "open", "n", ""),
        ];
        assert_eq!(code(run(1, mixed, tiny).await), None);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            2
        );
        // A pure add on the still over-budget set is refused.
        let grow = vec![change(STIG_ID, "r10", "open", "", "")];
        assert_eq!(
            code(run(2, grow, tiny).await),
            Some(StatusCode::PAYLOAD_TOO_LARGE)
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_delete_only_save_of_an_unstored_rule_only_bumps_the_revision(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        let r = autosave(
            &state,
            "owner",
            &set.id,
            0,
            vec![change(STIG_ID, RULES[0], "not_reviewed", "", "")],
        )
        .await
        .unwrap();
        assert_eq!(r.revision, 1);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            0
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_lock_timeout_maps_to_a_503(pool: PgPool) {
        let mut lock = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE checklist_sets IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SELECT set_config('lock_timeout', '100', true)")
            .execute(&mut *tx)
            .await
            .unwrap();
        let err = sqlx::query("SELECT id FROM checklist_sets")
            .execute(&mut *tx)
            .await
            .unwrap_err();
        let err = anyhow::Error::from(err);
        assert!(db::is_timeout(&err));
        assert_eq!(
            map_db(err).into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        lock.rollback().await.unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_tokened_autosave_with_no_changes_replays(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        for _ in 0..2 {
            assert_eq!(
                autosave_keyed(&state, &set.id, 0, KEY_A, vec![])
                    .await
                    .unwrap()
                    .revision,
                1
            );
        }
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_tokened_create_with_no_stigs_is_refused_every_time(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        for _ in 0..2 {
            let (c, _) = create_with(&state, KEY_A, None, &[]).await.unwrap_err();
            assert_eq!(c, StatusCode::BAD_REQUEST);
        }
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_sets").await, 0);
        // The refused token was never stored, so a real create may use it.
        assert_eq!(
            create_with(&state, KEY_A, None, &[STIG_ID]).await,
            Ok(StatusCode::CREATED)
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_blocked_writer_is_cut_by_the_lock_timeout_and_commits_nothing(pool: PgPool) {
        let (state, _dir) = base(&pool).await;
        let set = make(&state, "owner", &[STIG_ID]).await;
        // SHARE blocks writers but not the reads that come first.
        let mut lock = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE checklist_sets IN SHARE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();
        // The deadline is generous so Postgres' own 8 s lock_timeout fires first.
        let limits = Limits {
            deadline: Duration::from_secs(30),
            write_grace: Duration::from_secs(5),
        };
        let res = autosave_run(
            state.clone(),
            auth("owner", "author"),
            crate::test_fixtures::ctx(),
            set.id.clone(),
            AutosaveRequest {
                revision: 0,
                changes: vec![change(STIG_ID, RULES[0], "open", "", "")],
                save_id: None,
            },
            ROOMY,
            limits,
        )
        .await;
        let Err(e) = res else {
            panic!("expected the lock timeout to cut the write");
        };
        let res = e.into_response();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(res.headers().get(header::RETRY_AFTER).unwrap(), "1");
        lock.rollback().await.unwrap();
        state.tasks.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(count(&pool, "SELECT revision FROM checklist_sets").await, 0);
        assert_eq!(
            count(&pool, "SELECT COUNT(*) FROM checklist_set_rules").await,
            0
        );
        assert_eq!(audit_count(&pool, "checklist_set.edit").await, 0);
    }
}
