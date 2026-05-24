use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::api::asset_acl;
use crate::api::auth::AuthUser;
use crate::db_assets;
use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAssetRequest {
    pub name: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_classification")]
    pub classification: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_classification() -> String {
    "unclassified".into()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAssetRequest {
    pub name: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub description: String,
    pub classification: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

pub const MAX_TAG_LEN: usize = 50;

/// Trim, dedup, and validate-length a user-supplied tag list. Returns
/// 400 if any tag is too long after trimming. Empty strings dropped.
pub fn normalize_tags(input: &[String]) -> Result<Vec<String>, StatusCode> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for raw in input {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        if t.chars().count() > MAX_TAG_LEN {
            return Err(StatusCode::BAD_REQUEST);
        }
        if seen.insert(t.to_string()) {
            out.push(t.to_string());
        }
    }
    Ok(out)
}

pub async fn list_assets_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<db_assets::AssetSummary>>, StatusCode> {
    let rows = db_assets::list_assets(state.pool.as_ref())
        .await
        .map_err(map_db)?;
    Ok(Json(rows))
}

pub async fn create_asset_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateAssetRequest>,
) -> Result<(StatusCode, Json<db_assets::AssetRow>), StatusCode> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let tags = normalize_tags(&req.tags)?;
    let now = chrono::Utc::now();
    let asset = db_assets::AssetRow {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.into(),
        hostname: req.hostname,
        description: req.description,
        classification: req.classification,
        owner_id: user.id.clone(),
        created_at: now,
        updated_at: now,
        tags: tags.clone(),
        requires_approval: false,
    };
    db_assets::insert_asset(state.pool.as_ref(), &asset)
        .await
        .map_err(map_db)?;
    if !tags.is_empty() {
        db_assets::replace_tags(state.pool.as_ref(), &asset.id, &tags)
            .await
            .map_err(map_db)?;
    }
    Ok((StatusCode::CREATED, Json(asset)))
}

pub async fn get_asset_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<db_assets::AssetRow>, StatusCode> {
    db_assets::get_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)
        .map(Json)
}

pub async fn update_asset_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAssetRequest>,
) -> Result<Json<db_assets::AssetRow>, StatusCode> {
    let _existing = db_assets::get_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Renaming / reclassifying / retagging the asset row itself is a
    // structural change — require ACL `admin` (which the owner and any
    // global admin role automatically satisfy).
    if !asset_acl::user_can(state.pool.as_ref(), &id, &user, "admin").await {
        return Err(StatusCode::FORBIDDEN);
    }

    let name = req.name.trim();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let tags = normalize_tags(&req.tags)?;

    db_assets::update_asset(
        state.pool.as_ref(),
        &id,
        name,
        &req.hostname,
        &req.description,
        &req.classification,
    )
    .await
    .map_err(map_db)?;
    db_assets::replace_tags(state.pool.as_ref(), &id, &tags)
        .await
        .map_err(map_db)?;

    db_assets::get_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)
        .map(Json)
}

pub async fn delete_asset_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let _existing = db_assets::get_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Destroying the asset is the most destructive op — require ACL
    // `admin` level (owner + global admin role still satisfy this).
    if !asset_acl::user_can(state.pool.as_ref(), &id, &user, "admin").await {
        return Err(StatusCode::FORBIDDEN);
    }

    db_assets::delete_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?;
    Ok(StatusCode::NO_CONTENT)
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("assets db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

// ── Compare two assets ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetRef {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DivergedRule {
    pub rule_id: String,
    pub left_status: String,
    pub right_status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedStigDiff {
    pub stig_id: String,
    pub stig_title: String,
    pub diverged: Vec<DivergedRule>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetCompareResponse {
    pub left: AssetRef,
    pub right: AssetRef,
    pub shared: Vec<SharedStigDiff>,
}

/// GET /api/assets/:left/diff/:right — compare two assets' compliance state
/// across STIGs they both have applied. Only diverged rules are returned;
/// rules where both sides have the same status (after defaulting absent
/// rows to 'not_reviewed') are omitted.
pub async fn compare_handler(
    State(state): State<AppState>,
    Path((left_id, right_id)): Path<(String, String)>,
) -> Result<Json<AssetCompareResponse>, StatusCode> {
    if left_id == right_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    let pool = state.pool.as_ref();

    let left = db_assets::get_asset(pool, &left_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let right = db_assets::get_asset(pool, &right_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Pairs of (left_checklist_id, right_checklist_id, stig_id, stig_title)
    // for STIGs both assets have applied.
    let shared_rows = sqlx::query(
        r#"
        SELECT
            cl_l.id  AS left_cl,
            cl_r.id  AS right_cl,
            cl_l.stig_id,
            COALESCE(sc.title, cl_l.stig_id) AS stig_title
        FROM checklists cl_l
        JOIN checklists cl_r ON cl_r.stig_id = cl_l.stig_id
                            AND cl_r.asset_id = $2
        LEFT JOIN stigs_catalog sc ON sc.id = cl_l.stig_id
        WHERE cl_l.asset_id = $1
        ORDER BY stig_title
        "#,
    )
    .bind(&left_id)
    .bind(&right_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!("compare shared-stigs query failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut shared: Vec<SharedStigDiff> = Vec::new();
    for row in shared_rows {
        let left_cl: String = row.try_get("left_cl").map_err(|e| {
            tracing::error!("compare row decode failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let right_cl: String = row.try_get("right_cl").map_err(|e| {
            tracing::error!("compare row decode failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let stig_id: String = row.try_get("stig_id").map_err(|e| {
            tracing::error!("compare row decode failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let stig_title: String = row.try_get("stig_title").map_err(|e| {
            tracing::error!("compare row decode failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // Find rules that diverge. Union of touched rule_ids on either side;
        // LEFT JOIN both sides to get each status with default 'not_reviewed';
        // keep only rows where the statuses differ.
        let diff_rows = sqlx::query(
            r#"
            WITH all_rules AS (
                SELECT rule_id FROM checklist_rules WHERE checklist_id = $1
                UNION
                SELECT rule_id FROM checklist_rules WHERE checklist_id = $2
            )
            SELECT
                ar.rule_id,
                COALESCE(l.status, 'not_reviewed') AS left_status,
                COALESCE(r.status, 'not_reviewed') AS right_status
            FROM all_rules ar
            LEFT JOIN checklist_rules l ON l.checklist_id = $1 AND l.rule_id = ar.rule_id
            LEFT JOIN checklist_rules r ON r.checklist_id = $2 AND r.rule_id = ar.rule_id
            WHERE COALESCE(l.status, 'not_reviewed') != COALESCE(r.status, 'not_reviewed')
            ORDER BY ar.rule_id
            "#,
        )
        .bind(&left_cl)
        .bind(&right_cl)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            tracing::error!("compare diff query failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let diverged: Vec<DivergedRule> = diff_rows
            .into_iter()
            .map(|r| -> Result<DivergedRule, sqlx::Error> {
                Ok(DivergedRule {
                    rule_id: r.try_get("rule_id")?,
                    left_status: r.try_get("left_status")?,
                    right_status: r.try_get("right_status")?,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                tracing::error!("compare diff decode failed: {e:#}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        shared.push(SharedStigDiff {
            stig_id,
            stig_title,
            diverged,
        });
    }

    Ok(Json(AssetCompareResponse {
        left: AssetRef {
            id: left.id,
            name: left.name,
        },
        right: AssetRef {
            id: right.id,
            name: right.name,
        },
        shared,
    }))
}
