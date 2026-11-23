use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

use crate::api::asset_acl;
use crate::api::audit_tx;
use crate::api::auth::AuthUser;
use crate::api::request_ctx::RequestCtx;
use crate::db_assets;
use crate::db_audit;
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
    /// Optional free-form markdown runbook. Omitted ⇒ leave existing
    /// content untouched. Sending an empty string explicitly clears
    /// it. See `db_assets::set_runbook` / migration 033.
    #[serde(default)]
    pub runbook: Option<String>,
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

#[derive(Debug, Deserialize)]
pub struct ListAssetsQuery {
    /// `true` narrows the list to systems the caller can write to (the
    /// "Save to system" picker). Advisory: write handlers re-check.
    #[serde(default)]
    pub writable: Option<bool>,
}

pub async fn list_assets_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(q): Query<ListAssetsQuery>,
) -> Result<Json<Vec<db_assets::AssetSummary>>, StatusCode> {
    let mut rows = db_assets::list_assets(state.pool.as_ref())
        .await
        .map_err(map_db)?;
    if q.writable == Some(true) {
        let ids = asset_acl::writable_asset_ids(state.pool.as_ref(), &user, &rows).await;
        rows.retain(|a| ids.contains(&a.id));
    }
    Ok(Json(rows))
}

pub async fn create_asset_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
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
        email_cadence: "off".into(),
        email_last_sent_at: None,
        runbook: String::new(),
    };
    // The asset, its tags and its `asset.create` row commit together. Neither
    // the name, hostname, description nor the tag values are recorded.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    db_assets::insert_asset_on(&mut tx, &asset)
        .await
        .map_err(map_db)?;
    if !tags.is_empty() {
        db_assets::replace_tags_on(&mut tx, &asset.id, &tags)
            .await
            .map_err(map_db)?;
    }
    let mut ev = audit_tx::ok_event(
        &user,
        &ctx,
        "asset.create",
        json!({
            "classification": db_audit::audit_safe_id(&asset.classification),
            "tags": tags.len(),
        }),
    );
    ev.asset_id = Some(&asset.id);
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;
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
    Extension(ctx): Extension<RequestCtx>,
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

    // The update, the tags, the runbook and the `asset.update` row commit together.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    let existing = lock_and_load(&mut tx, &id).await?;

    // Field names that differ from the locked row; never their values
    // (the classification is the one enum-like exception, recorded sanitised).
    let mut changed: Vec<&str> = Vec::new();
    if name != existing.name {
        changed.push("name");
    }
    if req.hostname != existing.hostname {
        changed.push("hostname");
    }
    if req.description != existing.description {
        changed.push("description");
    }
    let classification_changed = req.classification != existing.classification;
    if classification_changed {
        changed.push("classification");
    }
    let (mut old_tags, mut new_tags) = (existing.tags.clone(), tags.clone());
    old_tags.sort();
    new_tags.sort();
    if old_tags != new_tags {
        changed.push("tags");
    }
    if req
        .runbook
        .as_deref()
        .is_some_and(|r| r != existing.runbook)
    {
        changed.push("runbook");
    }

    db_assets::update_asset_on(
        &mut tx,
        &id,
        name,
        &req.hostname,
        &req.description,
        &req.classification,
    )
    .await
    .map_err(map_db)?;
    db_assets::replace_tags_on(&mut tx, &id, &tags)
        .await
        .map_err(map_db)?;
    // Runbook is opt-in on PUT — omitting the field preserves what's
    // already on the row. Sending "" explicitly clears it.
    if let Some(runbook) = req.runbook.as_deref() {
        db_assets::set_runbook_on(&mut tx, &id, runbook)
            .await
            .map_err(map_db)?;
    }
    let mut detail = json!({ "changed": &changed });
    if let (true, Some(obj)) = (classification_changed, detail.as_object_mut()) {
        obj.insert(
            "classificationFrom".into(),
            json!(db_audit::audit_safe_id(&existing.classification)),
        );
        obj.insert(
            "classificationTo".into(),
            json!(db_audit::audit_safe_id(&req.classification)),
        );
    }
    // A request that changes nothing leaves no row.
    if !changed.is_empty() {
        let mut ev = audit_tx::ok_event(&user, &ctx, "asset.update", detail);
        ev.asset_id = Some(&id);
        audit_tx::record(&mut tx, &ev)
            .await
            .map_err(audit_tx::failed)?;
    }
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;

    db_assets::get_asset(state.pool.as_ref(), &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)
        .map(Json)
}

// ── Partial update (PATCH) ─────────────────────────────────────────────────

/// Legal `emailCadence` values. Kept in sync with the CHECK-style
/// validation in migration 032 — the column itself is a free-form
/// TEXT, but the handler is the only writer.
pub const VALID_EMAIL_CADENCES: &[&str] = &["off", "daily", "weekly", "monthly"];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchAssetRequest {
    /// When set, switches the per-asset scheduled email cadence. Must
    /// be one of `VALID_EMAIL_CADENCES`. Anything else → 400.
    #[serde(default)]
    pub email_cadence: Option<String>,
    /// When set, replaces the asset's runbook content. Empty string is
    /// the explicit "clear" signal. No write-side cap — the read path
    /// applies `MAX_RUNBOOK_BYTES` truncation defensively.
    #[serde(default)]
    pub runbook: Option<String>,
}

/// PATCH /api/assets/:id — partial update. Today the only field is
/// `emailCadence`. Owner or anyone with `write` ACL (or global admin)
/// can call this. The wider PUT handler still owns name/classification
/// /tags and gates on `admin` ACL.
pub async fn patch_asset_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
    Json(req): Json<PatchAssetRequest>,
) -> Result<Json<db_assets::AssetRow>, StatusCode> {
    let pool = state.pool.as_ref();
    let _existing = db_assets::get_asset(pool, &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Owner / write-ACL / global-admin. Scheduling is operational, not
    // structural — write is enough.
    if !asset_acl::user_can(pool, &id, &user, "write").await {
        return Err(StatusCode::FORBIDDEN);
    }

    if let Some(cad) = req.email_cadence.as_deref() {
        if !VALID_EMAIL_CADENCES.contains(&cad) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // The changes and the `asset.update` row commit together.
    let mut tx = crate::db::begin_bounded(pool)
        .await
        .map_err(audit_tx::failed)?;
    let existing = lock_and_load(&mut tx, &id).await?;
    let mut changed: Vec<&str> = Vec::new();
    let mut detail = json!({});
    if let Some(cad) = req.email_cadence.as_deref() {
        db_assets::set_email_cadence_on(&mut tx, &id, cad)
            .await
            .map_err(map_db)?;
        if cad != existing.email_cadence {
            changed.push("emailCadence");
        }
        if let Some(obj) = detail.as_object_mut() {
            obj.insert("emailCadence".into(), json!(cad));
        }
    }
    if let Some(runbook) = req.runbook.as_deref() {
        db_assets::set_runbook_on(&mut tx, &id, runbook)
            .await
            .map_err(map_db)?;
        if runbook != existing.runbook {
            changed.push("runbook");
        }
    }
    if let Some(obj) = detail.as_object_mut() {
        obj.insert("changed".into(), json!(changed));
    }
    // A request that changes nothing leaves no row.
    if !changed.is_empty() {
        let mut ev = audit_tx::ok_event(&user, &ctx, "asset.update", detail);
        ev.asset_id = Some(&id);
        audit_tx::record(&mut tx, &ev)
            .await
            .map_err(audit_tx::failed)?;
    }
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;

    db_assets::get_asset(pool, &id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)
        .map(Json)
}

pub async fn delete_asset_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
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

    // The delete and its `asset.delete` row commit together; the row is all
    // that survives of the asset.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    let existing = lock_and_load(&mut tx, &id).await?;
    db_assets::delete_asset_on(&mut tx, &id)
        .await
        .map_err(map_db)?;
    let mut ev = audit_tx::ok_event(
        &user,
        &ctx,
        "asset.delete",
        json!({ "ownerId": db_audit::audit_safe_id(&existing.owner_id) }),
    );
    ev.asset_id = Some(&id);
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Lock the asset row (`FOR NO KEY UPDATE`, which does not conflict with the
/// key-share locks FK inserts take) and read it on the transaction, so the
/// before-values an audit row records are the ones this write replaces.
async fn lock_and_load(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
) -> Result<db_assets::AssetRow, StatusCode> {
    let locked: Option<String> =
        sqlx::query_scalar("SELECT id FROM assets WHERE id = $1 FOR NO KEY UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_db(e.into()))?;
    if locked.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    db_assets::get_asset_on(tx, id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)
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

#[cfg(test)]
mod audit_tests {
    use super::*;
    use crate::test_fixtures::{
        app_state, audit_rows, auth, ctx, fail_audit_inserts, seed_asset, seed_tag, seed_user,
    };
    use sqlx::PgPool;

    const NAME: &str = "payroll-database-prod";
    const HOST: &str = "db01.internal.example";

    fn owner() -> Extension<AuthUser> {
        Extension(auth("owner", "author"))
    }

    async fn create(pool: &PgPool, tags: &[&str]) -> Result<db_assets::AssetRow, StatusCode> {
        let (state, _dir) = app_state(pool.clone());
        create_asset_handler(
            State(state),
            owner(),
            Extension(ctx()),
            Json(CreateAssetRequest {
                name: NAME.into(),
                hostname: HOST.into(),
                description: String::new(),
                classification: "cui".into(),
                tags: tags.iter().map(|t| t.to_string()).collect(),
            }),
        )
        .await
        .map(|(_, Json(a))| a)
    }

    async fn put(
        pool: &PgPool,
        classification: &str,
        tags: &[&str],
        runbook: Option<&str>,
    ) -> Result<db_assets::AssetRow, StatusCode> {
        let (state, _dir) = app_state(pool.clone());
        update_asset_handler(
            State(state),
            owner(),
            Extension(ctx()),
            Path("a1".into()),
            Json(UpdateAssetRequest {
                name: NAME.into(),
                hostname: HOST.into(),
                description: String::new(),
                classification: classification.into(),
                tags: tags.iter().map(|t| t.to_string()).collect(),
                runbook: runbook.map(str::to_string),
            }),
        )
        .await
        .map(|Json(a)| a)
    }

    /// Asset `a1` owned by `owner` with the PUT fixture's name and tag `t1`.
    async fn base(pool: &PgPool) {
        seed_user(pool, "owner").await;
        seed_asset(pool, "a1", "owner", false).await;
        sqlx::query(
            "UPDATE assets SET name = $1, hostname = $2, classification = 'cui' WHERE id = 'a1'",
        )
        .bind(NAME)
        .bind(HOST)
        .execute(pool)
        .await
        .unwrap();
        seed_tag(pool, "a1", "t1").await;
    }

    async fn counts(pool: &PgPool) -> (i64, i64) {
        (
            sqlx::query_scalar("SELECT COUNT(*) FROM assets")
                .fetch_one(pool)
                .await
                .unwrap(),
            sqlx::query_scalar("SELECT COUNT(*) FROM asset_tags")
                .fetch_one(pool)
                .await
                .unwrap(),
        )
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_create_is_recorded_without_names_or_tag_values(pool: PgPool) {
        seed_user(&pool, "owner").await;
        let asset = create(&pool, &["pci", "prod"]).await.unwrap();
        let rows = audit_rows(&pool, "asset.create").await;
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.user_id.as_deref(), Some("owner"));
        assert_eq!(r.asset_id.as_deref(), Some(asset.id.as_str()));
        assert_eq!(r.detail_keys(), ["classification", "tags"]);
        assert_eq!(r.detail["classification"], "cui");
        assert_eq!(r.detail["tags"], 2);
        assert_eq!(r.request_id.as_deref(), Some("test-request"));
        assert_eq!(r.source_ip.as_deref(), Some("198.51.100.4"));
        let text = r.detail.to_string();
        for leaked in [NAME, HOST, "pci", "prod"] {
            assert!(!text.contains(leaked), "{leaked}: {text}");
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_create_is_atomic_with_its_audit_row_and_tags(pool: PgPool) {
        seed_user(&pool, "owner").await;
        fail_audit_inserts(&pool, &["asset.create"]).await;
        assert_eq!(
            create(&pool, &["pci"]).await.err(),
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert_eq!(counts(&pool).await, (0, 0));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_update_records_exactly_the_changed_fields(pool: PgPool) {
        base(&pool).await;
        // Classification only.
        put(&pool, "secret", &["t1"], None).await.unwrap();
        // Tags only.
        put(&pool, "secret", &["t1", "t2"], None).await.unwrap();
        // Runbook only.
        put(&pool, "secret", &["t1", "t2"], Some("steps"))
            .await
            .unwrap();
        let rows = audit_rows(&pool, "asset.update").await;
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].asset_id.as_deref(), Some("a1"));
        assert_eq!(
            rows[0].detail_keys(),
            ["changed", "classificationFrom", "classificationTo"]
        );
        assert_eq!(
            rows[0].detail["changed"],
            serde_json::json!(["classification"])
        );
        assert_eq!(rows[0].detail["classificationFrom"], "cui");
        assert_eq!(rows[0].detail["classificationTo"], "secret");
        assert_eq!(rows[1].detail_keys(), ["changed"]);
        assert_eq!(rows[1].detail["changed"], serde_json::json!(["tags"]));
        assert_eq!(rows[2].detail["changed"], serde_json::json!(["runbook"]));
        assert_eq!(rows[2].request_id.as_deref(), Some("test-request"));
        let all: String = sqlx::query_scalar(
            "SELECT string_agg(detail::text, ' ') FROM audit_events WHERE action = 'asset.update'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        for leaked in [NAME, HOST, "t2", "steps"] {
            assert!(!all.contains(leaked), "{leaked}: {all}");
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_patch_is_recorded_as_an_update(pool: PgPool) {
        base(&pool).await;
        let (state, _dir) = app_state(pool.clone());
        let _ = patch_asset_handler(
            State(state),
            owner(),
            Extension(ctx()),
            Path("a1".into()),
            Json(PatchAssetRequest {
                email_cadence: Some("weekly".into()),
                runbook: None,
            }),
        )
        .await
        .unwrap();
        let rows = audit_rows(&pool, "asset.update").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].detail_keys(), ["changed", "emailCadence"]);
        assert_eq!(
            rows[0].detail["changed"],
            serde_json::json!(["emailCadence"])
        );
        assert_eq!(rows[0].detail["emailCadence"], "weekly");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_update_and_patch_fail_closed_when_the_audit_row_cannot_be_written(pool: PgPool) {
        base(&pool).await;
        fail_audit_inserts(&pool, &["asset.update"]).await;
        assert_eq!(
            put(&pool, "secret", &["t9"], Some("steps")).await.err(),
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        let (class, runbook): (String, String) =
            sqlx::query_as("SELECT classification, runbook FROM assets WHERE id = 'a1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((class.as_str(), runbook.as_str()), ("cui", ""));
        let tags: Vec<String> = sqlx::query_scalar("SELECT tag FROM asset_tags")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(tags, ["t1"]);

        let (state, _dir) = app_state(pool.clone());
        let res = patch_asset_handler(
            State(state),
            owner(),
            Extension(ctx()),
            Path("a1".into()),
            Json(PatchAssetRequest {
                email_cadence: Some("daily".into()),
                runbook: None,
            }),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::INTERNAL_SERVER_ERROR));
        let cadence: String =
            sqlx::query_scalar("SELECT email_cadence FROM assets WHERE id = 'a1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(cadence, "off");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn asset_delete_is_recorded_and_fails_closed(pool: PgPool) {
        base(&pool).await;
        let (state, _dir) = app_state(pool.clone());
        fail_audit_inserts(&pool, &["asset.delete"]).await;
        let res = delete_asset_handler(
            State(state.clone()),
            owner(),
            Extension(ctx()),
            Path("a1".into()),
        )
        .await;
        assert_eq!(res, Err(StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(counts(&pool).await.0, 1);

        sqlx::query("DROP TRIGGER test_fail_audit ON audit_events")
            .execute(&pool)
            .await
            .unwrap();
        let res =
            delete_asset_handler(State(state), owner(), Extension(ctx()), Path("a1".into())).await;
        assert_eq!(res, Ok(StatusCode::NO_CONTENT));
        let rows = audit_rows(&pool, "asset.delete").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].asset_id.as_deref(), Some("a1"));
        assert_eq!(rows[0].detail_keys(), ["ownerId"]);
        assert_eq!(rows[0].detail["ownerId"], "owner");
        assert_eq!(counts(&pool).await.0, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn refused_and_no_op_asset_requests_write_no_audit_row(pool: PgPool) {
        base(&pool).await;
        seed_user(&pool, "nosy").await;
        let (state, _dir) = app_state(pool.clone());
        let nosy = || Extension(auth("nosy", "author"));
        let denied = update_asset_handler(
            State(state.clone()),
            nosy(),
            Extension(ctx()),
            Path("a1".into()),
            Json(UpdateAssetRequest {
                name: NAME.into(),
                hostname: HOST.into(),
                description: String::new(),
                classification: "cui".into(),
                tags: vec![],
                runbook: None,
            }),
        )
        .await;
        assert_eq!(denied.err(), Some(StatusCode::FORBIDDEN));
        let denied = delete_asset_handler(
            State(state.clone()),
            nosy(),
            Extension(ctx()),
            Path("a1".into()),
        )
        .await;
        assert_eq!(denied, Err(StatusCode::FORBIDDEN));
        let bad = patch_asset_handler(
            State(state.clone()),
            owner(),
            Extension(ctx()),
            Path("a1".into()),
            Json(PatchAssetRequest {
                email_cadence: Some("hourly".into()),
                runbook: None,
            }),
        )
        .await;
        assert_eq!(bad.err(), Some(StatusCode::BAD_REQUEST));
        // A PATCH and a PUT that change nothing leave no row either.
        let _ = patch_asset_handler(
            State(state),
            owner(),
            Extension(ctx()),
            Path("a1".into()),
            Json(PatchAssetRequest {
                email_cadence: Some("off".into()),
                runbook: None,
            }),
        )
        .await
        .unwrap();
        put(&pool, "cui", &["t1"], None).await.unwrap();
        for a in ["asset.update", "asset.delete", "asset.create"] {
            assert!(audit_rows(&pool, a).await.is_empty(), "{a}");
        }
    }
}
