//! Outbound webhook delivery + admin CRUD.
//!
//! ## Payload signing (HMAC-SHA256, HMAC-SHA384 and timestamped V3)
//!
//! Every delivery whose `webhooks.secret` is non-empty carries these headers,
//! keyed by the configured secret:
//!
//! - `X-Webhook-Signature: sha256=<hex>`, the lower-case hexadecimal
//!   HMAC-SHA256 over the raw body. It matches GitHub's webhook convention,
//!   so any receiver that already validates GitHub webhooks can reuse the
//!   same code path.
//! - `X-Webhook-Signature-V2: sha384=<hex>`, the HMAC-SHA384 (the CNSA 2.0
//!   hash size) over the raw body. Receivers that must meet CNSA 2.0 should
//!   use a secret of at least 48 bytes.
//! - `X-Webhook-Timestamp: <ts>`, the send time, and
//!   `X-Webhook-Signature-V3: sha384=<hex>`, an HMAC-SHA384 that binds that
//!   time to the body. This is the replay-protected signature.
//!
//! Webhooks with an empty secret are sent **unsigned**: no signature or
//! timestamp header at all, preserving the original opt-in behaviour for
//! users who do not need to authenticate the sender (e.g. internal-only Slack
//! incoming webhooks behind a VPN). The pre-HMAC `X-Webhook-Secret`
//! literal-value header was removed; secrets are never transmitted on the
//! wire.
//!
//! V1 and V2 cover the body only. They carry no timestamp or nonce, so a
//! captured delivery can be replayed with them indefinitely. Only V3 binds
//! the send time. Replay protection therefore holds only for receivers that
//! **require V3 and ignore V1/V2**: an attacker who can strip V3 can
//! otherwise replay with the body-only headers.
//!
//! ### V3 wire contract
//!
//! - `X-Webhook-Timestamp: <ts>`: Unix time in whole seconds, UTC, ASCII
//!   decimal digits only, no sign, no leading zeros, no whitespace. Example:
//!   `1700000000`.
//! - `X-Webhook-Signature-V3: sha384=<96 lowercase hex>`: HMAC-SHA-384 keyed
//!   with the secret's UTF-8 bytes (the same key as V1/V2).
//! - Signed string: the bytes of `<ts>` exactly as they appear in the
//!   timestamp header, one byte `0x2E` (`.`), then the raw request body
//!   bytes. No trailing newline, no re-serialisation.
//! - The timestamp is taken from the server clock for each send attempt, so
//!   a resend is re-signed with a fresh timestamp.
//!
//! ### V3 receiver algorithm
//!
//! 1. Read `X-Webhook-Timestamp` and `X-Webhook-Signature-V3`. If either is
//!    missing, reject.
//! 2. The timestamp must match `^[1-9][0-9]{0,11}$`. Reject anything else.
//! 3. The signature must be `sha384=` followed by exactly 96 lowercase hex
//!    characters.
//! 4. Compute `"sha384=" + hex(HMAC-SHA-384(secret, ts_header_bytes + "." +
//!    raw_body))`, using the received header string (not a re-formatted
//!    integer) and the raw body before any JSON parsing.
//! 5. Compare in constant time.
//! 6. Only after the MAC verifies, check `abs(now - ts) <= 300` (both
//!    directions, boundary inclusive).
//! 7. Return the same 401 for every failure.
//! 8. Recommended: remember each accepted `(timestamp, signature)` pair for
//!    at least 600 s and reject repeats. Identical bodies sent in the same
//!    second share a signature, so treat deliveries as idempotent. The
//!    sender's clock must be NTP-synced.
//!
//! ### Verification recipe: Python
//! ```python
//! import hmac, hashlib, re, time
//! # `secret` must be non-empty (an empty key is forgeable).
//! def verify_v3(secret: bytes, raw_body: bytes, ts: str, sig: str) -> bool:
//!     if not re.fullmatch(r"[1-9][0-9]{0,11}", ts or ""):
//!         return False
//!     if not re.fullmatch(r"sha384=[0-9a-f]{96}", sig or ""):
//!         return False
//!     mac = hmac.new(secret, ts.encode() + b"." + raw_body, hashlib.sha384)
//!     if not hmac.compare_digest("sha384=" + mac.hexdigest(), sig):
//!         return False
//!     return abs(time.time() - int(ts)) <= 300
//! ```
//!
//! ### Verification recipe: Node.js
//! ```js
//! const crypto = require("crypto");
//! function verifyV3(secret, rawBody, ts, sig) {
//!   if (!/^[1-9][0-9]{0,11}$/.test(ts || "")) return false;
//!   if (!/^sha384=[0-9a-f]{96}$/.test(sig || "")) return false;
//!   const mac = crypto.createHmac("sha384", secret)
//!     .update(ts).update(".").update(rawBody).digest("hex");
//!   const a = Buffer.from("sha384=" + mac), b = Buffer.from(sig);
//!   if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
//!   return Math.abs(Date.now() / 1000 - Number(ts)) <= 300;
//! }
//! ```

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::time::Duration;

use crate::api::audit_tx;
use crate::api::auth::AuthUser;
use crate::api::request_ctx::RequestCtx;
use crate::crypto;
use crate::AppState;

/// Header carrying the HMAC-SHA256 signature (`sha256=<hex>`).
const SIG_HEADER: &str = "X-Webhook-Signature";
/// Header carrying the HMAC-SHA384 signature (`sha384=<hex>`).
const SIG_HEADER_V2: &str = "X-Webhook-Signature-V2";
/// Signature scheme labels: the digest name and the header-value prefix
/// (`<name>=<hex>`). The signers and the verify recipes both derive from them.
const SIG_ALGO: &str = "sha256";
const SIG_ALGO_V2: &str = "sha384";
/// Header carrying the timestamp-bound HMAC-SHA384 (`sha384=<hex>`).
const SIG_HEADER_V3: &str = "X-Webhook-Signature-V3";
/// Header carrying the send time (Unix seconds) that V3 signs.
const TIMESTAMP_HEADER: &str = "X-Webhook-Timestamp";
const SIG_ALGO_V3: &str = "sha384";
/// Receivers accept |now - timestamp| <= this many seconds.
const SIG_V3_TOLERANCE_SECS: u64 = 300;

/// Compute the `sha256=<hex>` signature for `body` keyed by `secret`.
/// Returns `None` when `secret` is empty so callers can branch on
/// "unsigned webhook" without inspecting the string twice.
fn sign_body(secret: &str, body: &[u8]) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    Some(format!(
        "{SIG_ALGO}={}",
        hex::encode(crypto::hmac::hmac_sha256(secret.as_bytes(), body))
    ))
}

/// Compute the `sha384=<hex>` signature for `body` keyed by `secret`
/// (`X-Webhook-Signature-V2`). `None` for an empty secret.
fn sign_body_v2(secret: &str, body: &[u8]) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    Some(format!(
        "{SIG_ALGO_V2}={}",
        hex::encode(crypto::hmac::hmac_sha384(secret.as_bytes(), body))
    ))
}

/// `<ts>.<body>`: ASCII decimal seconds, one '.', raw body bytes.
fn signed_payload_v3(timestamp: u64, body: &[u8]) -> Vec<u8> {
    let ts = timestamp.to_string();
    let mut out = Vec::with_capacity(ts.len() + 1 + body.len());
    out.extend_from_slice(ts.as_bytes());
    out.push(b'.');
    out.extend_from_slice(body);
    out
}

/// `sha384=<hex>` over `signed_payload_v3` keyed by `secret`
/// (`X-Webhook-Signature-V3`). `None` for an empty secret.
fn sign_body_v3(secret: &str, timestamp: u64, body: &[u8]) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    Some(format!(
        "{SIG_ALGO_V3}={}",
        hex::encode(crypto::hmac::hmac_sha384(
            secret.as_bytes(),
            &signed_payload_v3(timestamp, body)
        ))
    ))
}

/// Server clock in Unix seconds; 0 if the clock is before the epoch (which
/// every receiver rejects, so it fails closed).
fn unix_now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or_else(|_| {
        // 0 is intentionally fail-closed: every receiver rejects it as far
        // outside the tolerance window.
        tracing::warn!("system clock is before the Unix epoch; webhook timestamp set to 0");
        0
    })
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_SNIPPET_LIMIT: usize = 500;

/// Allowed values for the `kinds` column. Anything outside this set is
/// rejected with 400 by create/update so we don't end up with a webhook
/// silently subscribed to a typo'd event name.
const ALLOWED_KINDS: &[&str] = &["assigned", "overdue_digest", "compliance_report"];

/// Allowed values for the `flavor` column — i.e. which wire schema the
/// dispatcher serialises outbound events into. Same rejected-on-400
/// pattern as `kinds`.
///
/// - `slack`: legacy `{ text, attachments: [{ title, text, color }] }`
///   shape that incoming Slack webhooks consume directly. This is the
///   default for backwards-compat with every existing webhook row.
/// - `teams`: Microsoft Teams "MessageCard" legacy schema (the format
///   Teams "Incoming Webhook" connectors accept). Rendered as a single
///   card with `summary`, `title`, `themeColor`, and one section
///   containing `text` + a `facts` list keyed off the event fields.
/// - `generic`: flat `{ kind, title, body, color, fields }` shape with
///   no platform-specific framing. Useful for custom integrations that
///   want to re-render however they like (PagerDuty, in-house bots,
///   webhook-to-DB sinks, etc.).
const ALLOWED_FLAVORS: &[&str] = &["slack", "teams", "generic"];

/// Maximum number of overdue findings included in a single digest
/// payload. Slack incoming webhooks cap attachment size, and operators
/// only care about the top of the list anyway.
const DIGEST_LIMIT: i64 = 50;

fn validate_kinds(kinds: &[String]) -> Result<(), StatusCode> {
    for k in kinds {
        if !ALLOWED_KINDS.contains(&k.as_str()) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    Ok(())
}

fn validate_flavor(flavor: &str) -> Result<(), StatusCode> {
    if ALLOWED_FLAVORS.contains(&flavor) {
        Ok(())
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

// ── Types ──────────────────────────────────────────────────────────────────

/// Internal row, including the stored secret. Never serialized: API
/// responses use `WebhookView`, which omits the secret.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebhookRow {
    pub id: String,
    pub name: String,
    pub url: String,
    pub secret: String,
    pub kinds: Vec<String>,
    pub enabled: bool,
    pub flavor: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

/// API representation of a webhook. The secret is write-only: it is never
/// echoed back, only whether one is set (`signed`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookView {
    pub id: String,
    pub name: String,
    pub url: String,
    pub signed: bool,
    pub kinds: Vec<String>,
    pub enabled: bool,
    pub flavor: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

impl From<WebhookRow> for WebhookView {
    fn from(r: WebhookRow) -> Self {
        Self {
            signed: !r.secret.is_empty(),
            id: r.id,
            name: r.name,
            url: r.url,
            kinds: r.kinds,
            enabled: r.enabled,
            flavor: r.flavor,
            created_by: r.created_by,
            created_at: r.created_at,
        }
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryRow {
    pub id: i64,
    pub webhook_id: String,
    pub kind: String,
    pub payload: String,
    pub http_status: Option<i32>,
    pub response: Option<String>,
    pub error: Option<String>,
    pub attempted_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub kinds: Option<Vec<String>>,
    #[serde(default)]
    pub flavor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub kinds: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub flavor: Option<String>,
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn ensure_admin(user: &AuthUser) -> Result<(), StatusCode> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("webhooks sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn valid_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

// ── Handlers ───────────────────────────────────────────────────────────────

/// GET /api/webhooks — admin-only list of every configured webhook.
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<WebhookView>>, StatusCode> {
    ensure_admin(&user)?;
    let rows = sqlx::query_as::<_, WebhookRow>(
        r#"
        SELECT id, name, url, secret, kinds, enabled, flavor, created_by, created_at
          FROM webhooks
         ORDER BY created_at DESC
        "#,
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    Ok(Json(rows.into_iter().map(WebhookView::from).collect()))
}

/// POST /api/webhooks — admin-only create. 400 on empty name/url or a
/// non-http(s) url. Default `kinds` is ['assigned'] when omitted.
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Json(req): Json<CreateRequest>,
) -> Result<(StatusCode, Json<WebhookView>), StatusCode> {
    ensure_admin(&user)?;

    let name = req.name.trim().to_string();
    let url = req.url.trim().to_string();
    if name.is_empty() || url.is_empty() || !valid_url(&url) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let secret = req.secret.unwrap_or_default();
    let kinds = req
        .kinds
        .filter(|k| !k.is_empty())
        .unwrap_or_else(|| vec!["assigned".to_string()]);
    validate_kinds(&kinds)?;
    // Default to the legacy Slack shape so omitting `flavor` matches the
    // pre-flavor behaviour every existing integration relies on.
    let flavor = req.flavor.unwrap_or_else(|| "slack".to_string());
    validate_flavor(&flavor)?;

    let id = crate::crypto::rand::uuid_v4().to_string();

    // The webhook and its `webhook.create` row commit together. The detail
    // never carries the URL, name or secret (Slack/Teams URLs embed a
    // credential in the path).
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    let row = sqlx::query_as::<_, WebhookRow>(
        r#"
        INSERT INTO webhooks (id, name, url, secret, kinds, enabled, flavor, created_by)
        VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7)
        RETURNING id, name, url, secret, kinds, enabled, flavor, created_by, created_at
        "#,
    )
    .bind(&id)
    .bind(&name)
    .bind(&url)
    .bind(&secret)
    .bind(&kinds)
    .bind(&flavor)
    .bind(&user.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_sqlx)?;
    let ev = audit_tx::ok_event(
        &user,
        &ctx,
        "webhook.create",
        json!({
            "webhookId": row.id,
            "kinds": row.kinds,
            "flavor": row.flavor,
            "enabled": row.enabled,
            "signed": !row.secret.is_empty(),
        }),
    );
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;

    Ok((StatusCode::CREATED, Json(row.into())))
}

/// PATCH /api/webhooks/:id — admin-only partial update. Any field left
/// out is left untouched. 404 if the row doesn't exist.
pub async fn update_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
    Json(req): Json<UpdateRequest>,
) -> Result<Json<WebhookView>, StatusCode> {
    ensure_admin(&user)?;

    // The update and its `webhook.update` row commit together; the existing
    // row is read under a lock so `changed` names the fields really replaced.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    let existing = sqlx::query_as::<_, WebhookRow>(
        "SELECT id, name, url, secret, kinds, enabled, flavor, created_by, created_at \
         FROM webhooks WHERE id = $1 FOR NO KEY UPDATE",
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
    let url = match req.url {
        Some(u) => {
            let u = u.trim().to_string();
            if u.is_empty() || !valid_url(&u) {
                return Err(StatusCode::BAD_REQUEST);
            }
            u
        }
        None => existing.url,
    };
    let secret = req.secret.unwrap_or(existing.secret);
    let kinds = req.kinds.unwrap_or(existing.kinds);
    validate_kinds(&kinds)?;
    let enabled = req.enabled.unwrap_or(existing.enabled);
    let flavor = req.flavor.unwrap_or(existing.flavor);
    validate_flavor(&flavor)?;

    let row = sqlx::query_as::<_, WebhookRow>(
        r#"
        UPDATE webhooks
           SET name = $1, url = $2, secret = $3,
               kinds = $4, enabled = $5, flavor = $6
         WHERE id = $7
        RETURNING id, name, url, secret, kinds, enabled, flavor, created_by, created_at
        "#,
    )
    .bind(&name)
    .bind(&url)
    .bind(&secret)
    .bind(&kinds)
    .bind(enabled)
    .bind(&flavor)
    .bind(&id)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_sqlx)?;

    let changed = changed_fields(&before, &row);
    let ev = audit_tx::ok_event(
        &user,
        &ctx,
        "webhook.update",
        json!({
            "webhookId": row.id,
            "changed": changed,
            "kinds": row.kinds,
            "flavor": row.flavor,
            "enabled": row.enabled,
            "signed": !row.secret.is_empty(),
        }),
    );
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;

    Ok(Json(row.into()))
}

/// Names (never values) of the fields an update replaced. The URL, name and
/// secret are compared but only their field names are recorded.
fn changed_fields(before: &WebhookRow, after: &WebhookRow) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if before.name != after.name {
        changed.push("name");
    }
    if before.url != after.url {
        changed.push("url");
    }
    if before.secret != after.secret {
        changed.push("secret");
    }
    if before.kinds != after.kinds {
        changed.push("kinds");
    }
    if before.enabled != after.enabled {
        changed.push("enabled");
    }
    if before.flavor != after.flavor {
        changed.push("flavor");
    }
    changed
}

/// DELETE /api/webhooks/:id — admin-only. Deliveries cascade away.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;
    // The delete and its `webhook.delete` row commit together.
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    let deleted: Option<String> =
        sqlx::query_scalar("DELETE FROM webhooks WHERE id = $1 RETURNING id")
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx)?;
    let Some(deleted) = deleted else {
        return Err(StatusCode::NOT_FOUND);
    };
    let ev = audit_tx::ok_event(
        &user,
        &ctx,
        "webhook.delete",
        json!({ "webhookId": deleted }),
    );
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/webhooks/:id/deliveries — most recent 50 attempts, newest first.
pub async fn list_deliveries_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<Vec<DeliveryRow>>, StatusCode> {
    ensure_admin(&user)?;

    // Surface a 404 if the webhook itself is gone so the UI doesn't
    // silently render an empty table for a typo'd id.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM webhooks WHERE id = $1")
        .bind(&id)
        .fetch_optional(state.pool.as_ref())
        .await
        .map_err(map_sqlx)?;
    if exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let rows = sqlx::query_as::<_, DeliveryRow>(
        r#"
        SELECT id, webhook_id, kind, payload, http_status, response, error, attempted_at
          FROM webhook_deliveries
         WHERE webhook_id = $1
         ORDER BY attempted_at DESC
         LIMIT 50
        "#,
    )
    .bind(&id)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;
    Ok(Json(rows))
}

/// POST /api/webhooks/:id/test — fire a synthetic 'assigned' event so an
/// operator can verify the webhook is wired up without waiting for a
/// real assignment. Records a delivery row just like the live path.
pub async fn test_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;

    let webhook = sqlx::query_as::<_, WebhookRow>(
        "SELECT id, name, url, secret, kinds, enabled, flavor, created_by, created_at \
         FROM webhooks WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let event = assigned_event(&AssignedEvent {
        rule_id: "SV-TEST".to_string(),
        assignee_name: user.display_name.clone(),
        asset_name: "test-asset".to_string(),
        stig_title: "Test STIG".to_string(),
        severity: "CAT II".to_string(),
        due_date: None,
    });

    // Nothing is mutated here (the send writes its own `webhook_deliveries`
    // row), so the record is its own one-statement transaction, committed
    // before the send is spawned (as `signing.sign`): when it cannot be
    // written the request fails and nothing is sent.
    let ev = audit_tx::ok_event(
        &user,
        &ctx,
        "webhook.test",
        json!({ "webhookId": webhook.id }),
    );
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(audit_tx::failed)?;
    audit_tx::record(&mut tx, &ev)
        .await
        .map_err(audit_tx::failed)?;
    tx.commit().await.map_err(|e| audit_tx::failed(e.into()))?;

    let pool = state.pool.clone();
    tokio::spawn(async move {
        // Per-webhook flavor formatting happens inside deliver_one.
        deliver_one(pool.as_ref(), &webhook, &event).await;
    });
    Ok(StatusCode::ACCEPTED)
}

// ── Verify recipe (copy/paste receiver snippets) ───────────────────────────

/// Response payload for `GET /api/webhooks/:id/verify-recipe`.
///
/// Renders the same HMAC verification logic documented at the top of
/// this module as ready-to-paste curl / Python / Node snippets, with the
/// webhook's actual URL + a canned sample payload pre-filled so an operator
/// can validate a receiver end-to-end. The secret itself is never included:
/// the Python/Node snippets read it from `WEBHOOK_SECRET`; only the curl
/// snippet carries a signature precomputed over the sample payload. When the webhook's secret is empty we emit
/// "unsigned" snippets instead of fabricating a meaningless signature.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRecipe {
    pub id: String,
    pub name: String,
    pub url: String,
    /// The literal HTTP header name receivers should validate. Kept in
    /// the response so a future header rename doesn't silently break
    /// every existing copy/paste recipe out in the wild.
    #[serde(rename = "headerName")]
    pub header_name: String,
    /// Header carrying the HMAC-SHA384 signature (CNSA 2.0 receivers).
    #[serde(rename = "headerNameV2")]
    pub header_name_v2: String,
    /// Header carrying the timestamp-bound HMAC-SHA384 (replay-protected).
    #[serde(rename = "headerNameV3")]
    pub header_name_v3: String,
    /// Header carrying the Unix-seconds send time that V3 signs.
    #[serde(rename = "timestampHeaderName")]
    pub timestamp_header_name: String,
    /// Receivers accept |now - timestamp| <= this many seconds.
    #[serde(rename = "toleranceSeconds")]
    pub tolerance_seconds: u64,
    /// Pretty-printed canonical sample body — matches what the Slack
    /// formatter produces for the synthetic /test (`assigned`) event.
    #[serde(rename = "samplePayload")]
    pub sample_payload: String,
    pub snippets: VerifyRecipeSnippets,
}

#[derive(Debug, Serialize)]
pub struct VerifyRecipeSnippets {
    pub curl: String,
    pub python: String,
    pub node: String,
}

/// Build the curl, Python and Node snippets for one webhook. Kept apart from
/// the HTTP layer so it can be unit-tested; the secret never appears in the
/// output (only the curl signature over the fixed sample payload does).
fn build_verify_recipe(webhook: &WebhookRow) -> VerifyRecipe {
    build_verify_recipe_at(webhook, unix_now())
}

/// `build_verify_recipe` with the clock injected, for tests.
fn build_verify_recipe_at(webhook: &WebhookRow, now_unix: u64) -> VerifyRecipe {
    // Canonical sample event — kept compact on purpose so the snippets
    // fit in a Slack/Discord message without scrolling.
    let sample = json!({
        "text": "Finding SV-SAMPLE assigned to Demo User",
        "attachments": [{
            "title": "Asset: demo-host · STIG: Sample STIG",
            "text": "Severity: CAT II",
            "color": "#df8b08",
        }]
    });
    // Compact serialization keeps the body identical to what the
    // outbound dispatcher actually signs, so the precomputed HMAC below
    // is byte-accurate against the wire format.
    let sample_payload = serde_json::to_string(&sample).expect("sample payload serialises");

    let header_name = SIG_HEADER;
    let header_name_v2 = SIG_HEADER_V2;
    let sigs = (
        sign_body(&webhook.secret, sample_payload.as_bytes()),
        sign_body_v2(&webhook.secret, sample_payload.as_bytes()),
        sign_body_v3(&webhook.secret, now_unix, sample_payload.as_bytes()),
    );
    // All three are `None` exactly when the secret is empty (unsigned).
    let snippets = if let (Some(sig), Some(sig_v2), Some(sig_v3)) = sigs {
        let now_str = now_unix.to_string();
        let hdrs = RecipeHeaders {
            v1: header_name,
            v2: header_name_v2,
            v3: SIG_HEADER_V3,
            ts: TIMESTAMP_HEADER,
        };
        VerifyRecipeSnippets {
            curl: signed_curl_snippet(
                &webhook.url,
                &sample_payload,
                &[
                    (header_name, &sig),
                    (header_name_v2, &sig_v2),
                    (TIMESTAMP_HEADER, &now_str),
                    (SIG_HEADER_V3, &sig_v3),
                ],
            ),
            python: signed_python_snippet(&hdrs),
            node: signed_node_snippet(&hdrs),
        }
    } else {
        VerifyRecipeSnippets {
            curl: unsigned_curl_snippet(&webhook.url, &sample_payload),
            python: unsigned_python_snippet(),
            node: unsigned_node_snippet(),
        }
    };

    VerifyRecipe {
        id: webhook.id.clone(),
        name: webhook.name.clone(),
        url: webhook.url.clone(),
        header_name: header_name.to_string(),
        header_name_v2: header_name_v2.to_string(),
        header_name_v3: SIG_HEADER_V3.to_string(),
        timestamp_header_name: TIMESTAMP_HEADER.to_string(),
        tolerance_seconds: SIG_V3_TOLERANCE_SECS,
        sample_payload,
        snippets,
    }
}

fn signed_curl_snippet(url: &str, body: &str, sigs: &[(&str, &str)]) -> String {
    // Single-line curl that demonstrates exactly what the dispatcher
    // emits on the wire. The signature is pre-computed for the literal
    // sample body so a paste-and-run actually validates downstream.
    let minutes = SIG_V3_TOLERANCE_SECS / 60;
    let headers: String = sigs
        .iter()
        .map(|(h, v)| format!("  -H '{h}: {v}' \\\n"))
        .collect();
    format!(
        "# {TIMESTAMP_HEADER} / {SIG_HEADER_V3} below are a live signed sample delivery, valid for {minutes} minutes from when this recipe was generated.\n# Use it only against a test receiver and do not paste it into shared channels; reload to refresh.\ncurl -X POST '{url}' \\\n  -H 'Content-Type: application/json' \\\n{headers}  -d '{body}'"
    )
}

fn unsigned_curl_snippet(url: &str, body: &str) -> String {
    format!(
        "# This webhook is configured as unsigned (no secret set) — no signature header is sent.\ncurl -X POST '{url}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{body}'"
    )
}

/// Header names the signed receiver snippets refer to.
struct RecipeHeaders<'a> {
    v1: &'a str,
    v2: &'a str,
    v3: &'a str,
    ts: &'a str,
}

fn signed_python_snippet(h: &RecipeHeaders) -> String {
    // Receiver-side verification recipe. The secret is write-only, so the
    // snippet reads it from the environment instead of embedding it.
    format!(
        "# Python receiver — verify the {v3} header (replay-protected: HMAC-SHA384 over '<{ts}>.<body>').\n# {v1} (HMAC-SHA256) and {v2} (HMAC-SHA384) cover the body only and can be replayed; require V3 and ignore them for replay protection.\nimport hmac, hashlib, os, re, time\n\n# Set WEBHOOK_SECRET to this webhook's signing secret; it is not shown here.\nSECRET = os.environ.get('WEBHOOK_SECRET', '').encode()\nif not SECRET:\n    raise SystemExit('WEBHOOK_SECRET must be set to a non-empty value')\nHEADER = {v1_lit}\nHEADER_V2 = {v2_lit}\nHEADER_V3 = {v3_lit}\nHEADER_TS = {ts_lit}\nTOLERANCE = {tol}\n\ndef verify(raw_body: bytes, received_sig: str) -> bool:\n    expected = '{algo}=' + hmac.new(SECRET, raw_body, hashlib.{algo}).hexdigest()\n    return hmac.compare_digest(expected, received_sig)\n\ndef verify_v2(raw_body: bytes, received_sig: str) -> bool:\n    expected = '{algo_v2}=' + hmac.new(SECRET, raw_body, hashlib.{algo_v2}).hexdigest()\n    return hmac.compare_digest(expected, received_sig)\n\ndef verify_v3(raw_body: bytes, received_ts: str, received_sig: str, now=None) -> bool:\n    if not re.fullmatch(r'[1-9][0-9]{{0,11}}', received_ts or ''):\n        return False\n    if not re.fullmatch(r'{algo_v3}=[0-9a-f]{{96}}', received_sig or ''):\n        return False\n    signed = received_ts.encode() + b'.' + raw_body\n    expected = '{algo_v3}=' + hmac.new(SECRET, signed, hashlib.{algo_v3}).hexdigest()\n    if not hmac.compare_digest(expected, received_sig):\n        return False\n    # Check the clock only after the MAC verifies.\n    return abs((time.time() if now is None else now) - int(received_ts)) <= TOLERANCE\n\n# In Flask / FastAPI / Django (return the same 401 for every failure):\n#   ok = verify_v3(request.get_data(), request.headers.get(HEADER_TS), request.headers.get(HEADER_V3))\n# Recommended: remember each accepted (timestamp, signature) pair for at least\n# 600 seconds and reject repeats; treat deliveries as idempotent.\n",
        v1 = h.v1,
        v2 = h.v2,
        v3 = h.v3,
        ts = h.ts,
        v1_lit = python_string_literal(h.v1),
        v2_lit = python_string_literal(h.v2),
        v3_lit = python_string_literal(h.v3),
        ts_lit = python_string_literal(h.ts),
        tol = SIG_V3_TOLERANCE_SECS,
        algo = SIG_ALGO,
        algo_v2 = SIG_ALGO_V2,
        algo_v3 = SIG_ALGO_V3,
    )
}

fn unsigned_python_snippet() -> String {
    // Explicit signal that the body is unauthenticated — anyone who can
    // reach the URL can forge events. Operators should add a secret if
    // they want to authenticate deliveries.
    "# This webhook is configured as unsigned (no secret set).\n# Receivers cannot verify the body's authenticity — there is no signature header.\n# Set a secret on the webhook in the Admin Console to enable HMAC verification.\n".to_string()
}

fn signed_node_snippet(h: &RecipeHeaders) -> String {
    format!(
        "// Node.js receiver — verify the {v3} header (replay-protected: HMAC-SHA384 over '<{ts}>.<body>').\n// {v1} (HMAC-SHA256) and {v2} (HMAC-SHA384) cover the body only and can be replayed; require V3 and ignore them for replay protection.\nconst crypto = require('crypto');\n\n// Set WEBHOOK_SECRET to this webhook's signing secret; it is not shown here.\nconst SECRET = process.env.WEBHOOK_SECRET;\nif (!SECRET) throw new Error('WEBHOOK_SECRET must be set to a non-empty value');\nconst HEADER = {v1_lit};\nconst HEADER_V2 = {v2_lit};\nconst HEADER_V3 = {v3_lit};\nconst HEADER_TS = {ts_lit};\nconst TOLERANCE = {tol};\n\nfunction safeEqual(expected, receivedSig) {{\n  const a = Buffer.from(expected);\n  const b = Buffer.from(receivedSig || '');\n  return a.length === b.length && crypto.timingSafeEqual(a, b);\n}}\n\nfunction verify(rawBody, receivedSig) {{\n  const expected = '{algo}=' + crypto.createHmac('{algo}', SECRET).update(rawBody).digest('hex');\n  return safeEqual(expected, receivedSig);\n}}\n\nfunction verifyV2(rawBody, receivedSig) {{\n  const expected = '{algo_v2}=' + crypto.createHmac('{algo_v2}', SECRET).update(rawBody).digest('hex');\n  return safeEqual(expected, receivedSig);\n}}\n\nfunction verifyV3(rawBody, receivedTs, receivedSig, now = Date.now() / 1000) {{\n  if (!/^[1-9][0-9]{{0,11}}$/.test(receivedTs || '')) return false;\n  if (!/^{algo_v3}=[0-9a-f]{{96}}$/.test(receivedSig || '')) return false;\n  const mac = crypto.createHmac('{algo_v3}', SECRET).update(receivedTs).update('.').update(rawBody).digest('hex');\n  if (!safeEqual('{algo_v3}=' + mac, receivedSig)) return false;\n  // Check the clock only after the MAC verifies.\n  return Math.abs(now - Number(receivedTs)) <= TOLERANCE;\n}}\n\n// In Express (return the same 401 for every failure):\n//   app.post('/hook', express.raw({{ type: 'application/json' }}), (req, res) => {{\n//     if (!verifyV3(req.body, req.get(HEADER_TS), req.get(HEADER_V3))) return res.sendStatus(401);\n//     res.sendStatus(200);\n//   }});\n// Recommended: remember each accepted (timestamp, signature) pair for at least\n// 600 seconds and reject repeats; treat deliveries as idempotent.\n",
        v1 = h.v1,
        v2 = h.v2,
        v3 = h.v3,
        ts = h.ts,
        v1_lit = js_string_literal(h.v1),
        v2_lit = js_string_literal(h.v2),
        v3_lit = js_string_literal(h.v3),
        ts_lit = js_string_literal(h.ts),
        tol = SIG_V3_TOLERANCE_SECS,
        algo = SIG_ALGO,
        algo_v2 = SIG_ALGO_V2,
        algo_v3 = SIG_ALGO_V3,
    )
}

fn unsigned_node_snippet() -> String {
    "// This webhook is configured as unsigned (no secret set).\n// Receivers cannot verify the body's authenticity — there is no signature header.\n// Set a secret on the webhook in the Admin Console to enable HMAC verification.\n".to_string()
}

/// Escape a string for safe inclusion in a Python single-quoted literal.
/// We use single quotes throughout the snippet so we only need to deal
/// with backslashes and the quote character itself.
fn python_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

/// Same idea as `python_string_literal` but for JavaScript single-quoted
/// literals. Forward slashes and control chars don't need escaping for
/// the values we feed in (URLs, hex header names, opaque secrets).
fn js_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

/// GET /api/webhooks/:id/verify-recipe — admin-only. Returns the curl /
/// Python / Node receiver-verification snippets for one webhook, with
/// the actual URL and sample body pre-filled (never the secret). 404 if the webhook is
/// gone (so a typo'd id in the Admin UI surfaces as an error toast
/// rather than a blank modal).
pub async fn verify_recipe_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<VerifyRecipe>, StatusCode> {
    ensure_admin(&user)?;

    let webhook = sqlx::query_as::<_, WebhookRow>(
        "SELECT id, name, url, secret, kinds, enabled, flavor, created_by, created_at \
         FROM webhooks WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(build_verify_recipe(&webhook)))
}

// ── Event payload + dispatch ───────────────────────────────────────────────

/// Snapshot of just enough state to render an assigned-event Slack body.
/// Built synchronously inside the request handler so the spawned task can
/// own all of its data and not borrow from the DB transaction.
#[derive(Debug, Clone)]
pub struct AssignedEvent {
    pub rule_id: String,
    pub assignee_name: String,
    pub asset_name: String,
    pub stig_title: String,
    pub severity: String,
    pub due_date: Option<String>,
}

/// Flavor-agnostic representation of one outbound webhook event. Each
/// event-source helper (assigned, overdue_digest, compliance_report)
/// builds a `WebhookEvent`; the dispatcher then asks
/// `format_for_flavor` to translate it into the wire JSON for each
/// subscribed webhook's configured `flavor`.
///
/// `fields` is an ordered `(name, value)` list rather than a `HashMap`
/// because (a) Teams MessageCard "facts" are rendered in array order
/// and operators want stable ordering, and (b) it keeps the
/// Slack-attachment rendering deterministic for the round-trip
/// backwards-compat snapshot tests.
#[derive(Debug, Clone)]
pub struct WebhookEvent {
    pub kind: String,
    pub title: String,
    pub body: String,
    /// `#RRGGBB` for the slack/teams shapes (Teams strips the `#`).
    /// Passed through verbatim for the generic shape so receivers can
    /// re-interpret. Slack also accepts the named tokens `good`,
    /// `warning`, `danger` — we preserve any string the caller hands us.
    pub color: String,
    pub fields: Vec<(String, String)>,
    /// Optional per-row "attachments" — used by the overdue digest to
    /// render each overdue finding as its own Slack attachment / Teams
    /// section. Empty when the event is a single-card style.
    pub items: Vec<WebhookEventItem>,
}

/// One row inside `WebhookEvent::items`. Lets the digest payload carry
/// per-finding cards without forcing every event shape to pre-render
/// them into the `body` string.
#[derive(Debug, Clone)]
pub struct WebhookEventItem {
    pub title: String,
    pub text: String,
    pub color: String,
}

fn severity_color(sev: &str) -> &'static str {
    // Slack-style attachment colors keyed to CAT level. Anything we
    // don't recognise gets neutral grey.
    match sev {
        "CAT I" | "high" => "#d13212",
        "CAT II" | "medium" => "#df8b08",
        "CAT III" | "low" => "#2a9d8f",
        _ => "#878787",
    }
}

/// Build the flavor-agnostic event for a single rule assignment. The
/// `body` matches the human-readable text the legacy Slack `attachments[0].text`
/// field carried, and `fields` mirrors the same data in a structured
/// form so Teams "facts" and the generic flat shape don't need a second
/// rendering pass.
pub fn assigned_event(ev: &AssignedEvent) -> WebhookEvent {
    let due_part = ev
        .due_date
        .as_ref()
        .map(|d| format!(" · Due: {}", d))
        .unwrap_or_default();
    let mut fields = vec![
        ("Rule".to_string(), ev.rule_id.clone()),
        ("Assignee".to_string(), ev.assignee_name.clone()),
        ("Asset".to_string(), ev.asset_name.clone()),
        ("STIG".to_string(), ev.stig_title.clone()),
        ("Severity".to_string(), ev.severity.clone()),
    ];
    if let Some(d) = &ev.due_date {
        fields.push(("Due".to_string(), d.clone()));
    }
    WebhookEvent {
        kind: "assigned".to_string(),
        title: format!("Asset: {} · STIG: {}", ev.asset_name, ev.stig_title),
        body: format!("Severity: {}{}", ev.severity, due_part),
        color: severity_color(&ev.severity).to_string(),
        fields,
        items: vec![],
    }
}

/// Flavor-agnostic compliance-report event. The summary text mirrors
/// what the previous hard-coded Slack payload emitted bit-for-bit so
/// `flavor='slack'` subscribers don't see a wording change.
pub fn compliance_report_event(
    row: &crate::api::compliance_report::ComplianceReportRow,
) -> WebhookEvent {
    let s = &row.summary;
    // The legacy Slack payload used the named tokens here; keep them so
    // backwards compat is exact for slack webhooks. For teams/generic
    // these are passed through as-is (teams will render with its own
    // theme color when it doesn't parse the value as hex).
    let color = if s.compliance_score >= 80.0 {
        "good"
    } else if s.compliance_score >= 50.0 {
        "warning"
    } else {
        "danger"
    };
    let top = s
        .top_asset_name
        .clone()
        .unwrap_or_else(|| "(none)".to_string());
    let download = format!("/api/reports/{}/report.pdf", row.id);
    let body = format!("Top-risk system: {} — download at {}", top, download,);
    let fields = vec![
        (
            "Compliance score".to_string(),
            format!("{:.1}%", s.compliance_score),
        ),
        ("Assets".to_string(), s.assets.to_string()),
        ("Open findings".to_string(), s.open_findings.to_string()),
        (
            "Overdue findings".to_string(),
            s.overdue_findings.to_string(),
        ),
        ("Top-risk system".to_string(), top),
        ("Download".to_string(), download),
    ];
    WebhookEvent {
        kind: "compliance_report".to_string(),
        title: format!("Compliance report for {} assets", s.assets),
        // The Slack `text` field (top-of-card summary) is rebuilt from
        // these numbers inside the slack formatter below. We park the
        // long-form details in `body` instead.
        body,
        color: color.to_string(),
        fields,
        items: vec![],
    }
}

/// Render `event` into the wire JSON for a given `flavor`. Switching on
/// the flavor here — and using the resulting bytes as both the request
/// body AND the HMAC input — guarantees the signature matches whatever
/// the receiver actually parses.
pub fn format_for_flavor(event: &WebhookEvent, flavor: &str) -> Value {
    match flavor {
        "teams" => format_teams(event),
        "generic" => format_generic(event),
        // Default + explicit "slack" → legacy Slack incoming-webhook shape.
        _ => format_slack(event),
    }
}

/// Compose the Slack `text` summary line for a given event. Keeps the
/// human-readable wording each `kind` produced before the refactor so
/// the slack flavor stays byte-identical for existing subscribers.
fn slack_summary(event: &WebhookEvent) -> String {
    match event.kind.as_str() {
        "assigned" => {
            // Legacy: "Finding {rule_id} assigned to {assignee_name}".
            let rule = field(event, "Rule").unwrap_or_default();
            let who = field(event, "Assignee").unwrap_or_default();
            format!("Finding {} assigned to {}", rule, who)
        }
        "overdue_digest" => {
            // Legacy: "{N} overdue findings across the fleet". `items`
            // length matches the row count the digest collector found.
            format!("{} overdue findings across the fleet", event.items.len())
        }
        "compliance_report" => {
            let score = field(event, "Compliance score").unwrap_or_default();
            let open = field(event, "Open findings").unwrap_or_default();
            let overdue = field(event, "Overdue findings").unwrap_or_default();
            // Strip the trailing '%' from the score and reformat to one
            // decimal so the legacy wording survives unchanged.
            let score_num = score.trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
            format!(
                "Fleet compliance report ready — {:.1}% compliant, {} open, {} overdue",
                score_num, open, overdue,
            )
        }
        _ => event.title.clone(),
    }
}

fn field<'a>(event: &'a WebhookEvent, name: &str) -> Option<&'a str> {
    event
        .fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn format_slack(event: &WebhookEvent) -> Value {
    // Multi-item events (overdue digest) render one attachment per item.
    // Single-card events render a single attachment, mirroring the
    // legacy shape `{ text, attachments: [{ title, text, color }] }`.
    let attachments: Vec<Value> = if event.items.is_empty() {
        vec![json!({
            "title": event.title,
            "text": event.body,
            "color": event.color,
        })]
    } else {
        event
            .items
            .iter()
            .map(|i| {
                json!({
                    "title": i.title,
                    "text": i.text,
                    "color": i.color,
                })
            })
            .collect()
    };
    json!({
        "text": slack_summary(event),
        "attachments": attachments,
    })
}

fn format_teams(event: &WebhookEvent) -> Value {
    // Microsoft Teams "MessageCard" legacy schema. Teams strips the
    // leading '#' from theme colors and treats named tokens
    // (good/warning/danger) as invalid → we map the legacy tokens onto
    // 6-char hex equivalents.
    let theme_color = teams_theme_color(&event.color);
    let facts: Vec<Value> = event
        .fields
        .iter()
        .map(|(k, v)| json!({ "name": k, "value": v }))
        .collect();
    // For multi-item events (overdue digest), emit one section per item
    // — each with its own title + text — plus a leading summary section.
    let mut sections: Vec<Value> = Vec::with_capacity(1 + event.items.len());
    sections.push(json!({
        "text": event.body,
        "facts": facts,
    }));
    for i in &event.items {
        sections.push(json!({
            "title": i.title,
            "text": i.text,
        }));
    }
    let summary = slack_summary(event);
    json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": summary,
        "themeColor": theme_color,
        "title": event.title,
        "sections": sections,
    })
}

/// Map an event color into a 6-char hex without `#`, suitable for
/// Teams' `themeColor`. Slack-style named tokens are translated to
/// reasonable defaults; anything we don't recognise falls back to grey.
fn teams_theme_color(color: &str) -> String {
    let trimmed = color.trim_start_matches('#');
    if trimmed.len() == 6 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return trimmed.to_ascii_lowercase();
    }
    match color {
        "good" => "2a9d8f".to_string(),
        "warning" => "df8b08".to_string(),
        "danger" => "d13212".to_string(),
        _ => "878787".to_string(),
    }
}

fn format_generic(event: &WebhookEvent) -> Value {
    // Flat shape for custom integrations. No platform-specific framing
    // — receivers re-render however they like.
    let fields: Vec<Value> = event
        .fields
        .iter()
        .map(|(k, v)| json!({ "name": k, "value": v }))
        .collect();
    let items: Vec<Value> = event
        .items
        .iter()
        .map(|i| {
            json!({
                "title": i.title,
                "text": i.text,
                "color": i.color,
            })
        })
        .collect();
    json!({
        "kind": event.kind,
        "title": event.title,
        "body": event.body,
        "color": event.color,
        "fields": fields,
        "items": items,
    })
}

/// Fire a "compliance_report" event. Best-effort — errors are logged
/// but do not block the surrounding generate call.
pub async fn fire_compliance_report(
    pool: &PgPool,
    row: &crate::api::compliance_report::ComplianceReportRow,
) -> anyhow::Result<()> {
    dispatch_event(pool, compliance_report_event(row)).await;
    Ok(())
}

/// Fan an event out to every enabled webhook subscribed to `event.kind`.
/// Intended to be called from inside a `tokio::spawn` so the originating
/// request can return immediately. Each subscribed webhook gets the
/// payload formatted into its own configured `flavor` BEFORE signing —
/// so the HMAC always covers the exact bytes the receiver parses.
pub async fn dispatch_event(pool: &PgPool, event: WebhookEvent) {
    // Postgres array containment: kinds @> ARRAY[$2]
    let webhooks = match sqlx::query_as::<_, WebhookRow>(
        r#"
        SELECT id, name, url, secret, kinds, enabled, flavor, created_by, created_at
          FROM webhooks
         WHERE enabled = TRUE
           AND $1 = ANY(kinds)
        "#,
    )
    .bind(&event.kind)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("webhook dispatch: failed to load subscribers: {e:#}");
            return;
        }
    };

    for w in webhooks {
        deliver_one(pool, &w, &event).await;
    }
}

/// POST the formatted payload to one webhook and log the outcome.
/// Failures (bad DNS, connection refused, non-2xx) are still recorded
/// so the operator can debug from the Admin UI.
///
/// The flavor switch happens here, on a per-webhook basis, BEFORE we
/// serialise the body bytes and sign them — so the HMAC always matches
/// the exact wire payload the receiver sees, regardless of which schema
/// the operator picked.
/// The outgoing POST: JSON body plus the signature headers.
/// HMAC-SHA256(body, secret) → `X-Webhook-Signature: sha256=<hex>`,
/// HMAC-SHA384(body, secret) → `X-Webhook-Signature-V2: sha384=<hex>`, and
/// HMAC-SHA384(`<ts>.<body>`, secret) → `X-Webhook-Signature-V3: sha384=<hex>`
/// alongside `X-Webhook-Timestamp: <ts>`.
/// Webhooks with an empty secret remain unsigned (no headers) so the
/// "no sender authentication needed" path keeps working.
///
/// Call this once per send attempt and never clone or reuse a
/// `RequestBuilder` for a resend: each call reads the clock, so a retry gets
/// a fresh timestamp and V3 signature while V1/V2 stay identical.
fn build_request(
    client: &reqwest::Client,
    webhook: &WebhookRow,
    body: &str,
) -> reqwest::RequestBuilder {
    build_request_at(client, webhook, body, unix_now())
}

/// `build_request` with the clock injected, for tests.
fn build_request_at(
    client: &reqwest::Client,
    webhook: &WebhookRow,
    body: &str,
    now_unix: u64,
) -> reqwest::RequestBuilder {
    let mut req = client
        .post(&webhook.url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_owned());
    if let Some(sig) = sign_body(&webhook.secret, body.as_bytes()) {
        req = req.header(SIG_HEADER, sig);
    }
    if let Some(sig) = sign_body_v2(&webhook.secret, body.as_bytes()) {
        req = req.header(SIG_HEADER_V2, sig);
    }
    if let Some(sig) = sign_body_v3(&webhook.secret, now_unix, body.as_bytes()) {
        req = req
            .header(TIMESTAMP_HEADER, now_unix.to_string())
            .header(SIG_HEADER_V3, sig);
    }
    req
}

async fn deliver_one(pool: &PgPool, webhook: &WebhookRow, event: &WebhookEvent) {
    let payload = format_for_flavor(event, &webhook.flavor);
    let kind = event.kind.as_str();
    let body = match serde_json::to_string(&payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("webhook payload serialisation failed: {e:#}");
            return;
        }
    };

    let client = crate::crypto::tls::http_client_builder()
        .timeout(REQUEST_TIMEOUT)
        .build();
    let client = match client {
        Ok(c) => c,
        Err(e) => {
            // Couldn't even build the client — still record so the UI shows
            // *something* rather than silently dropping the event.
            record_delivery(
                pool,
                &webhook.id,
                kind,
                &body,
                None,
                None,
                Some(&e.to_string()),
            )
            .await;
            return;
        }
    };

    let req = build_request(&client, webhook, &body);

    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16() as i32;
            let text = resp.text().await.unwrap_or_default();
            let snippet = truncate(&text, RESPONSE_SNIPPET_LIMIT);
            record_delivery(
                pool,
                &webhook.id,
                kind,
                &body,
                Some(status),
                Some(snippet.as_str()),
                None,
            )
            .await;
        }
        Err(e) => {
            record_delivery(
                pool,
                &webhook.id,
                kind,
                &body,
                None,
                None,
                Some(&e.to_string()),
            )
            .await;
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    // Truncate at char boundaries so we never panic on multi-byte UTF-8.
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// ── Overdue digest ─────────────────────────────────────────────────────────

/// One overdue row pulled from the fleet-wide query. Kept private — the
/// shape only matters when building the Slack payload below.
#[derive(Debug, sqlx::FromRow)]
struct OverdueDigestRow {
    rule_id: String,
    asset_name: String,
    stig_title: String,
    due_date: Option<chrono::NaiveDate>,
    days_overdue: Option<i32>,
    assignee_name: Option<String>,
}

/// Build the flavor-agnostic event for the overdue digest. Public so
/// the test support endpoint and the scheduler can share the exact same
/// code path. The `slack` formatter renders each item as an attachment
/// (byte-identical to the legacy payload); `teams` renders one
/// MessageCard section per item; `generic` exposes the raw item list.
fn build_digest_event(rows: &[OverdueDigestRow]) -> WebhookEvent {
    let total = rows.len();
    let items: Vec<WebhookEventItem> = rows
        .iter()
        .map(|r| {
            let due_part = r
                .due_date
                .as_ref()
                .map(|d| format!(" · Due: {}", d))
                .unwrap_or_default();
            let overdue_part = r
                .days_overdue
                .map(|d| format!(" · {} day(s) overdue", d))
                .unwrap_or_default();
            let who = r
                .assignee_name
                .clone()
                .unwrap_or_else(|| "unassigned".to_string());
            WebhookEventItem {
                title: format!("{} · {}", r.rule_id, r.asset_name),
                text: format!(
                    "STIG: {} · Assignee: {}{}{}",
                    r.stig_title, who, due_part, overdue_part
                ),
                color: "#d13212".to_string(),
            }
        })
        .collect();
    WebhookEvent {
        kind: "overdue_digest".to_string(),
        title: format!("{} overdue findings across the fleet", total),
        body: format!("{} overdue findings across the fleet", total),
        color: "#d13212".to_string(),
        fields: vec![("Total overdue".to_string(), total.to_string())],
        items,
    }
}

/// Sweep enabled `overdue_digest` webhooks that haven't fired in the
/// last ~24h and deliver one digest each. Called by the background
/// scheduler in main.rs and the test-only `/api/test/run-digest` route.
///
/// Returns the count of webhooks the sweep attempted. A webhook with no
/// overdue findings to report is skipped (no delivery row written), but
/// `last_digest_at` is still bumped so we don't re-check on every tick.
pub async fn run_overdue_digest(pool: &PgPool) -> anyhow::Result<usize> {
    // 23h fudge factor: when the scheduler ticks slightly under 24h the
    // strict `> 24h` check would skip every other tick. 23h keeps the
    // cadence honest while still preventing same-tick spam.
    let webhooks = sqlx::query_as::<_, WebhookRow>(
        r#"
        SELECT id, name, url, secret, kinds, enabled, flavor, created_by, created_at
          FROM webhooks
         WHERE enabled = TRUE
           AND 'overdue_digest' = ANY(kinds)
           AND (last_digest_at IS NULL
                OR last_digest_at < NOW() - INTERVAL '23 hours')
        "#,
    )
    .fetch_all(pool)
    .await?;

    if webhooks.is_empty() {
        return Ok(0);
    }

    // Fleet-wide overdue snapshot. Built once and reused across every
    // subscribed webhook so we hit the DB once per sweep, not N times.
    let rows = sqlx::query_as::<_, OverdueDigestRow>(
        r#"
        SELECT
            cr.rule_id                                AS rule_id,
            a.name                                    AS asset_name,
            COALESCE(sc.title, c.stig_id)             AS stig_title,
            cr.due_date                               AS due_date,
            (CURRENT_DATE - cr.due_date)::INT         AS days_overdue,
            u.display_name                            AS assignee_name
          FROM checklist_rules cr
          JOIN checklists c     ON c.id = cr.checklist_id
          JOIN assets a         ON a.id = c.asset_id
          LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
          LEFT JOIN users u          ON u.id = cr.assignee_id
         WHERE cr.status = 'open'
           AND cr.due_date IS NOT NULL
           AND cr.due_date < CURRENT_DATE
         ORDER BY cr.due_date ASC
         LIMIT $1
        "#,
    )
    .bind(DIGEST_LIMIT)
    .fetch_all(pool)
    .await?;

    let event = build_digest_event(&rows);
    let attempted = webhooks.len();

    for w in webhooks {
        // Skip the POST entirely when there is nothing to report, but
        // still stamp `last_digest_at` — the cron semantics are "we
        // checked, nothing to do" rather than "we never ran."
        if !rows.is_empty() {
            deliver_one(pool, &w, &event).await;
        }
        let stamp = sqlx::query("UPDATE webhooks SET last_digest_at = NOW() WHERE id = $1")
            .bind(&w.id)
            .execute(pool)
            .await;
        if let Err(e) = stamp {
            tracing::error!("digest last_digest_at update failed for {}: {e:#}", w.id);
        }
    }

    Ok(attempted)
}

async fn record_delivery(
    pool: &PgPool,
    webhook_id: &str,
    kind: &str,
    payload: &str,
    http_status: Option<i32>,
    response: Option<&str>,
    error: Option<&str>,
) {
    let res = sqlx::query(
        r#"
        INSERT INTO webhook_deliveries
            (webhook_id, kind, payload, http_status, response, error)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(webhook_id)
    .bind(kind)
    .bind(payload)
    .bind(http_status)
    .bind(response)
    .bind(error)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::error!("webhook delivery insert failed: {e:#}");
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use crate::test_fixtures::{app_state, audit_rows, auth, ctx, fail_audit_inserts, seed_user};

    const HOOK_NAME: &str = "pager-integration";

    fn admin() -> Extension<AuthUser> {
        Extension(auth("root", "admin"))
    }

    /// A URL with a path credential and a secret, both random per test.
    fn creds() -> (String, String) {
        (
            format!(
                "https://hooks.example.test/{}",
                crate::crypto::rand::uuid_v4()
            ),
            crate::crypto::rand::uuid_v4().to_string(),
        )
    }

    async fn make(state: &AppState, url: &str, secret: &str) -> Result<WebhookView, StatusCode> {
        create_handler(
            State(state.clone()),
            admin(),
            Extension(ctx()),
            Json(CreateRequest {
                name: HOOK_NAME.into(),
                url: url.into(),
                secret: Some(secret.into()),
                kinds: None,
                flavor: None,
            }),
        )
        .await
        .map(|(_, Json(r))| r)
    }

    async fn patch(
        state: &AppState,
        id: &str,
        req: UpdateRequest,
    ) -> Result<WebhookView, StatusCode> {
        update_handler(
            State(state.clone()),
            admin(),
            Extension(ctx()),
            Path(id.into()),
            Json(req),
        )
        .await
        .map(|Json(r)| r)
    }

    fn no_change() -> UpdateRequest {
        UpdateRequest {
            name: None,
            url: None,
            secret: None,
            kinds: None,
            enabled: None,
            flavor: None,
        }
    }

    async fn all_detail_text(pool: &sqlx::PgPool) -> String {
        sqlx::query_scalar::<_, String>(
            "SELECT COALESCE(string_agg(detail::text, ' '), '') FROM audit_events WHERE action LIKE 'webhook.%'",
        )
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn webhook_create_update_delete_are_recorded_without_the_url_or_secret(
        pool: sqlx::PgPool,
    ) {
        seed_user(&pool, "root").await;
        let (state, _dir) = app_state(pool.clone());
        let (url, secret) = creds();
        let hook = make(&state, &url, &secret).await.unwrap();

        let rows = audit_rows(&pool, "webhook.create").await;
        assert_eq!(rows.len(), 1);
        let c = &rows[0];
        assert_eq!(c.outcome, "ok");
        assert_eq!(c.user_id.as_deref(), Some("root"));
        assert_eq!(c.asset_id, None);
        assert_eq!(
            c.detail_keys(),
            ["enabled", "flavor", "kinds", "signed", "webhookId"]
        );
        assert_eq!(c.detail["webhookId"], hook.id.as_str());
        assert_eq!(c.detail["signed"], true);
        assert_eq!(c.request_id.as_deref(), Some("test-request"));
        assert_eq!(c.source_ip.as_deref(), Some("198.51.100.4"));

        // `changed` lists exactly the fields that differ.
        let new_secret = crate::crypto::rand::uuid_v4().to_string();
        patch(
            &state,
            &hook.id,
            UpdateRequest {
                enabled: Some(false),
                secret: Some(new_secret.clone()),
                name: Some(HOOK_NAME.into()),
                ..no_change()
            },
        )
        .await
        .unwrap();
        let rows = audit_rows(&pool, "webhook.update").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].detail_keys(),
            [
                "changed",
                "enabled",
                "flavor",
                "kinds",
                "signed",
                "webhookId"
            ]
        );
        assert_eq!(
            rows[0].detail["changed"],
            serde_json::json!(["secret", "enabled"])
        );
        assert_eq!(rows[0].detail["enabled"], false);
        // Unknown id: 404, no row.
        assert_eq!(
            patch(&state, "missing", no_change()).await.err(),
            Some(StatusCode::NOT_FOUND)
        );

        let res = delete_handler(
            State(state.clone()),
            admin(),
            Extension(ctx()),
            Path(hook.id.clone()),
        )
        .await;
        assert_eq!(res, Ok(StatusCode::NO_CONTENT));
        let rows = audit_rows(&pool, "webhook.delete").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].detail_keys(), ["webhookId"]);
        assert_eq!(audit_rows(&pool, "webhook.update").await.len(), 1);

        let text = all_detail_text(&pool).await;
        for forbidden in [
            url.as_str(),
            secret.as_str(),
            new_secret.as_str(),
            HOOK_NAME,
        ] {
            assert!(!text.contains(forbidden), "{forbidden} leaked: {text}");
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn webhook_changes_fail_closed_when_the_audit_row_cannot_be_written(pool: sqlx::PgPool) {
        seed_user(&pool, "root").await;
        let (state, _dir) = app_state(pool.clone());
        let (url, secret) = creds();
        fail_audit_inserts(
            &pool,
            &["webhook.create", "webhook.update", "webhook.delete"],
        )
        .await;
        assert_eq!(
            make(&state, &url, &secret).await.err(),
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhooks")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);

        sqlx::query("INSERT INTO webhooks (id, name, url, secret, kinds, enabled, flavor, created_by) VALUES ('w1', 'n', $1, '', ARRAY['assigned'], TRUE, 'slack', 'root')")
            .bind(&url)
            .execute(&pool)
            .await
            .unwrap();
        let res = patch(
            &state,
            "w1",
            UpdateRequest {
                enabled: Some(false),
                ..no_change()
            },
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::INTERNAL_SERVER_ERROR));
        let enabled: bool = sqlx::query_scalar("SELECT enabled FROM webhooks WHERE id = 'w1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(enabled);
        let res = delete_handler(
            State(state.clone()),
            admin(),
            Extension(ctx()),
            Path("w1".into()),
        )
        .await;
        assert_eq!(res, Err(StatusCode::INTERNAL_SERVER_ERROR));
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhooks")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn webhook_test_send_is_recorded(pool: sqlx::PgPool) {
        seed_user(&pool, "root").await;
        let (state, _dir) = app_state(pool.clone());
        // Nothing listens here: the delivery fails fast and is only logged.
        let hook = make(&state, "http://127.0.0.1:1/hook", "").await.unwrap();
        let res = test_handler(
            State(state.clone()),
            admin(),
            Extension(ctx()),
            Path(hook.id.clone()),
        )
        .await;
        assert_eq!(res, Ok(StatusCode::ACCEPTED));
        let rows = audit_rows(&pool, "webhook.test").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome, "ok");
        assert_eq!(rows[0].detail_keys(), ["webhookId"]);
        assert_eq!(rows[0].detail["webhookId"], hook.id.as_str());
        assert_eq!(rows[0].request_id.as_deref(), Some("test-request"));
        // Let the spawned delivery finish before the database goes away.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn webhook_test_fails_closed_and_sends_nothing_when_the_row_cannot_be_written(
        pool: sqlx::PgPool,
    ) {
        seed_user(&pool, "root").await;
        let (state, _dir) = app_state(pool.clone());
        let hook = make(&state, "http://127.0.0.1:1/hook", "").await.unwrap();
        fail_audit_inserts(&pool, &["webhook.test"]).await;
        let res = test_handler(
            State(state.clone()),
            admin(),
            Extension(ctx()),
            Path(hook.id.clone()),
        )
        .await;
        assert_eq!(res, Err(StatusCode::INTERNAL_SERVER_ERROR));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let sent: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(sent, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn refused_webhook_requests_write_no_audit_row(pool: sqlx::PgPool) {
        seed_user(&pool, "root").await;
        let (state, _dir) = app_state(pool.clone());
        let denied = create_handler(
            State(state.clone()),
            Extension(auth("u1", "author")),
            Extension(ctx()),
            Json(CreateRequest {
                name: "n".into(),
                url: "https://example.test/h".into(),
                secret: None,
                kinds: None,
                flavor: None,
            }),
        )
        .await;
        assert_eq!(denied.err(), Some(StatusCode::FORBIDDEN));
        assert_eq!(
            make(&state, "ftp://nope", "").await.err(),
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            patch(&state, "missing", no_change()).await.err(),
            Some(StatusCode::NOT_FOUND)
        );
        let gone = delete_handler(
            State(state.clone()),
            admin(),
            Extension(ctx()),
            Path("missing".into()),
        )
        .await;
        assert_eq!(gone, Err(StatusCode::NOT_FOUND));
        let test_denied = test_handler(
            State(state.clone()),
            Extension(auth("u1", "author")),
            Extension(ctx()),
            Path("missing".into()),
        )
        .await;
        assert_eq!(test_denied, Err(StatusCode::FORBIDDEN));
        let test_missing = test_handler(
            State(state),
            admin(),
            Extension(ctx()),
            Path("missing".into()),
        )
        .await;
        assert_eq!(test_missing, Err(StatusCode::NOT_FOUND));
        for a in [
            "webhook.create",
            "webhook.update",
            "webhook.delete",
            "webhook.test",
        ] {
            assert!(audit_rows(&pool, a).await.is_empty(), "{a}");
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn webhook_responses_never_carry_the_secret(pool: sqlx::PgPool) {
        seed_user(&pool, "root").await;
        let (state, _dir) = app_state(pool.clone());
        let (url, secret) = creds();
        let hook = make(&state, &url, &secret).await.unwrap();
        assert!(hook.signed);
        let Json(list) = list_handler(State(state.clone()), admin()).await.unwrap();
        let listed = serde_json::to_string(&list).unwrap();
        let created = serde_json::to_string(&hook).unwrap();
        let kept = patch(
            &state,
            &hook.id,
            UpdateRequest {
                enabled: Some(false),
                ..no_change()
            },
        )
        .await
        .unwrap();
        assert!(kept.signed);
        let rotated = patch(
            &state,
            &hook.id,
            UpdateRequest {
                secret: Some(crate::crypto::rand::uuid_v4().to_string()),
                ..no_change()
            },
        )
        .await
        .unwrap();
        let cleared = patch(
            &state,
            &hook.id,
            UpdateRequest {
                secret: Some(String::new()),
                ..no_change()
            },
        )
        .await
        .unwrap();
        assert!(!cleared.signed);
        for body in [
            listed,
            created,
            serde_json::to_string(&kept).unwrap(),
            serde_json::to_string(&rotated).unwrap(),
        ] {
            assert!(!body.contains(&secret), "secret leaked: {body}");
            assert!(!body.contains("\"secret\""), "secret key present: {body}");
        }
    }
}

#[cfg(test)]
mod recipe_tests {
    use super::*;

    fn row(secret: &str) -> WebhookRow {
        WebhookRow {
            id: "w1".into(),
            name: "n".into(),
            url: "https://hooks.example.test/x".into(),
            secret: secret.into(),
            kinds: vec!["assigned".into()],
            enabled: true,
            flavor: "slack".into(),
            created_by: "root".into(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn signed_recipe_omits_the_secret_but_keeps_the_curl_signature() {
        let secret = crate::crypto::rand::uuid_v4().to_string();
        let r = build_verify_recipe(&row(&secret));
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains(&secret));
        assert!(r.snippets.python.contains("WEBHOOK_SECRET"));
        assert!(r.snippets.node.contains("WEBHOOK_SECRET"));
        let sig = sign_body(&secret, r.sample_payload.as_bytes()).unwrap();
        assert!(r.snippets.curl.contains(&sig));
        let sig_v2 = sign_body_v2(&secret, r.sample_payload.as_bytes()).unwrap();
        assert!(r
            .snippets
            .curl
            .contains(&format!("-H 'X-Webhook-Signature-V2: {sig_v2}'")));
        assert_eq!(r.header_name_v2, "X-Webhook-Signature-V2");
        assert!(r.snippets.python.contains("verify_v2"));
        assert!(r.snippets.node.contains("verifyV2"));
        // Existing receivers copy the v1 verifier; every snippet must keep
        // the literal `sha256=` prefix (e2e 74 asserts the same).
        for s in [&r.snippets.curl, &r.snippets.python, &r.snippets.node] {
            assert!(s.contains("sha256="), "missing sha256= prefix: {s}");
        }
        assert!(r.snippets.node.contains("'sha384='"));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["headerNameV2"], "X-Webhook-Signature-V2");
        assert_eq!(v["headerName"], "X-Webhook-Signature");
        assert_eq!(v["headerNameV3"], "X-Webhook-Signature-V3");
        assert_eq!(v["timestampHeaderName"], "X-Webhook-Timestamp");
        assert_eq!(v["toleranceSeconds"], 300);
        assert!(r.snippets.python.contains("verify_v3"));
        assert!(r.snippets.node.contains("verifyV3"));
        assert!(r.snippets.python.contains("300"));
        assert!(r.snippets.node.contains("300"));

        let at = build_verify_recipe_at(&row(&secret), 1_700_000_000);
        let sig_v3 = sign_body_v3(&secret, 1_700_000_000, at.sample_payload.as_bytes()).unwrap();
        assert!(at
            .snippets
            .curl
            .contains("-H 'X-Webhook-Timestamp: 1700000000'"));
        assert!(at
            .snippets
            .curl
            .contains(&format!("-H 'X-Webhook-Signature-V3: {sig_v3}'")));
        assert!(at.snippets.curl.starts_with("# X-Webhook-Timestamp"));
        assert!(!serde_json::to_string(&at).unwrap().contains(&secret));
    }

    #[test]
    fn both_signatures_cover_the_same_body_and_v1_is_unchanged() {
        let secret = crate::crypto::rand::uuid_v4().to_string();
        let body = br#"{"text":"x"}"#;
        let v1 = sign_body(&secret, body).unwrap();
        let v2 = sign_body_v2(&secret, body).unwrap();
        assert_eq!(
            v1,
            format!(
                "sha256={}",
                hex::encode(crypto::hmac::hmac_sha256(secret.as_bytes(), body))
            )
        );
        assert!(v1.starts_with("sha256=") && v1.len() == 7 + 64);
        assert!(v2.starts_with("sha384=") && v2.len() == 7 + 96);
        assert_eq!(
            v2,
            format!(
                "sha384={}",
                hex::encode(crypto::hmac::hmac_sha384(secret.as_bytes(), body))
            )
        );
        assert_ne!(sign_body_v2(&secret, b"other"), Some(v2));
    }

    /// Send the request `build_request` makes to a local listener and return
    /// the raw request head as seen on the wire.
    async fn wire_head(secret: &str) -> (String, String) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut c, _) = l.accept().unwrap();
            let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            // The headers are all that is asserted on; stop at the blank line.
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = c.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let _ =
                c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            String::from_utf8_lossy(&buf).into_owned()
        });
        let mut w = row(secret);
        w.url = format!("http://{addr}/hook");
        let body = r#"{"text":"hi"}"#;
        let client = crate::crypto::tls::http_client_builder().build().unwrap();
        let resp = build_request(&client, &w, body).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let head = tokio::task::spawn_blocking(move || h.join().unwrap())
            .await
            .unwrap();
        (head.to_ascii_lowercase(), body.to_string())
    }

    #[tokio::test]
    async fn the_wire_request_carries_all_signatures_when_signed() {
        let secret = crate::crypto::rand::uuid_v4().to_string();
        let (head, body) = wire_head(&secret).await;
        let v1 = sign_body(&secret, body.as_bytes()).unwrap();
        let v2 = sign_body_v2(&secret, body.as_bytes()).unwrap();
        assert!(
            head.contains(&format!("x-webhook-signature: {v1}")),
            "{head}"
        );
        assert!(
            head.contains(&format!("x-webhook-signature-v2: {v2}")),
            "{head}"
        );
        let ts_hdr = head
            .lines()
            .find_map(|l| l.strip_prefix("x-webhook-timestamp: "))
            .expect("timestamp header present");
        assert!(ts_hdr.bytes().all(|b| b.is_ascii_digit()), "{head}");
        let ts: u64 = ts_hdr.parse().unwrap();
        assert!(unix_now().abs_diff(ts) <= 10, "{head}");
        let v3 = sign_body_v3(&secret, ts, body.as_bytes()).unwrap();
        assert!(
            head.contains(&format!("x-webhook-signature-v3: {v3}")),
            "{head}"
        );
        assert_eq!(
            reference_verify_v3(&secret, ts_hdr, &v3, body.as_bytes(), unix_now()),
            Ok(())
        );
    }

    #[tokio::test]
    async fn the_wire_request_carries_no_signature_when_unsigned() {
        let (head, _) = wire_head("").await;
        assert!(!head.contains("x-webhook-signature"), "{head}");
        assert!(!head.contains("x-webhook-timestamp"), "{head}");
    }

    // Published RFC 4231 test case 2 key (precedent: crypto/hmac.rs).
    const RFC4231_TC2_KEY: &str = "Jefe";

    #[test]
    fn v3_known_answer_matches_an_independent_openssl_computation() {
        // printf '1700000000.{"text":"hi"}' | openssl dgst -sha384 -hmac Jefe
        assert_eq!(
            sign_body_v3(RFC4231_TC2_KEY, 1_700_000_000, br#"{"text":"hi"}"#).unwrap(),
            "sha384=291e40e6a2f6715a9394ecd5c496d8a72421f1dada85d8a3e2634990c66f606ba7d44b63633eab8851ef598ae4046bec"
        );
    }

    #[test]
    fn v1_and_v2_known_answers_are_unchanged() {
        let body = br#"{"text":"hi"}"#;
        assert_eq!(
            sign_body(RFC4231_TC2_KEY, body).unwrap(),
            "sha256=1a3b1739466fd28c7f1a00b811474407a63e8b12063ffb04af366faeb58d4ab3"
        );
        assert_eq!(
            sign_body_v2(RFC4231_TC2_KEY, body).unwrap(),
            "sha384=c165efa8e85c0b1a55c4b77d0b8fc05f358314025b8838d4dfb7abbbe37794f7ca937734b0cc55747a3edb652347b76b"
        );
    }

    #[test]
    fn v3_matches_rustcrypto_over_timestamp_dot_body() {
        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        let secret = crate::crypto::rand::uuid_v4().to_string();
        let utf8 = "h\u{e9}llo \u{4e16}\u{754c}".as_bytes();
        for ts in [1u64, 1_700_000_000, u64::MAX] {
            for body in [&b""[..], &b"."[..], utf8] {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
                m.update(ts.to_string().as_bytes());
                m.update(b".");
                m.update(body);
                assert_eq!(
                    sign_body_v3(&secret, ts, body).unwrap(),
                    format!("sha384={}", hex::encode(m.finalize().into_bytes()))
                );
            }
        }
    }

    #[test]
    fn signed_payload_v3_is_decimal_seconds_dot_raw_body() {
        assert_eq!(signed_payload_v3(1_700_000_000, b"x"), b"1700000000.x");
        assert_eq!(signed_payload_v3(0, b""), b"0.");
    }

    #[test]
    fn v3_changes_with_the_timestamp_and_with_the_body() {
        let secret = crate::crypto::rand::uuid_v4().to_string();
        let base = sign_body_v3(&secret, 100, b"a").unwrap();
        assert!(base.starts_with("sha384=") && base.len() == 7 + 96);
        assert_ne!(sign_body_v3(&secret, 101, b"a").unwrap(), base);
        assert_ne!(sign_body_v3(&secret, 100, b"b").unwrap(), base);
    }

    #[test]
    fn a_retry_is_resigned_with_a_fresh_timestamp_and_v1_v2_do_not_change() {
        let secret = crate::crypto::rand::uuid_v4().to_string();
        let w = row(&secret);
        let body = r#"{"text":"hi"}"#;
        let client = crate::crypto::tls::http_client_builder().build().unwrap();
        let t = 1_700_000_000u64;
        let a = build_request_at(&client, &w, body, t).build().unwrap();
        let b = build_request_at(&client, &w, body, t + 7).build().unwrap();
        let h = |r: &reqwest::Request, n: &str| {
            r.headers().get(n).unwrap().to_str().unwrap().to_string()
        };
        assert_eq!(h(&a, TIMESTAMP_HEADER), t.to_string());
        assert_eq!(h(&b, TIMESTAMP_HEADER), (t + 7).to_string());
        assert_ne!(h(&a, SIG_HEADER_V3), h(&b, SIG_HEADER_V3));
        assert_eq!(
            h(&a, SIG_HEADER_V3),
            sign_body_v3(&secret, t, body.as_bytes()).unwrap()
        );
        assert_eq!(
            h(&b, SIG_HEADER_V3),
            sign_body_v3(&secret, t + 7, body.as_bytes()).unwrap()
        );
        assert_eq!(h(&a, SIG_HEADER), h(&b, SIG_HEADER));
        assert_eq!(h(&a, SIG_HEADER_V2), h(&b, SIG_HEADER_V2));
        assert_eq!(
            a.body().and_then(|x| x.as_bytes()),
            b.body().and_then(|x| x.as_bytes())
        );
    }

    /// Test-only receiver following the documented algorithm. The server
    /// never verifies webhook signatures; this exists to pin the contract.
    /// It is a cross-check for the shipped Python/Node snippets, which are
    /// executed by `shipped_snippets_verify_v3_correctly`.
    fn reference_verify_v3(
        secret: &str,
        ts_header: &str,
        sig_header: &str,
        body: &[u8],
        now: u64,
    ) -> Result<(), &'static str> {
        let tb = ts_header.as_bytes();
        let ts_ok =
            (1..=12).contains(&tb.len()) && tb[0] != b'0' && tb.iter().all(|b| b.is_ascii_digit());
        if !ts_ok {
            return Err("bad timestamp");
        }
        let hex_part = sig_header.strip_prefix("sha384=").ok_or("bad prefix")?;
        if hex_part.len() != 96
            || !hex_part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("bad signature format");
        }
        let mut signed = ts_header.as_bytes().to_vec();
        signed.push(b'.');
        signed.extend_from_slice(body);
        let expected = format!(
            "sha384={}",
            hex::encode(crypto::hmac::hmac_sha384(secret.as_bytes(), &signed))
        );
        if expected.len() != sig_header.len() {
            return Err("mismatch");
        }
        let diff = expected
            .bytes()
            .zip(sig_header.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return Err("mismatch");
        }
        let ts: u64 = ts_header.parse().map_err(|_| "bad timestamp")?;
        if now.abs_diff(ts) > SIG_V3_TOLERANCE_SECS {
            return Err("outside window");
        }
        Ok(())
    }

    #[test]
    fn reference_verifier_enforces_the_300_second_window_both_ways() {
        let secret = crate::crypto::rand::uuid_v4().to_string();
        let ts = 1_700_000_000u64;
        let body = b"{}";
        let sig = sign_body_v3(&secret, ts, body).unwrap();
        let tsh = ts.to_string();
        for now in [ts, ts + 300, ts - 300] {
            assert_eq!(reference_verify_v3(&secret, &tsh, &sig, body, now), Ok(()));
        }
        for now in [ts + 301, ts - 301] {
            assert_eq!(
                reference_verify_v3(&secret, &tsh, &sig, body, now),
                Err("outside window")
            );
        }
    }

    #[test]
    fn reference_verifier_rejects_malformed_or_mismatched_input() {
        let secret = crate::crypto::rand::uuid_v4().to_string();
        let other = crate::crypto::rand::uuid_v4().to_string();
        let ts = 1_700_000_000u64;
        let tsh = ts.to_string();
        let body = br#"{"a":1}"#;
        let sig = sign_body_v3(&secret, ts, body).unwrap();
        let v = |t: &str, s: &str, b: &[u8], k: &str| reference_verify_v3(k, t, s, b, ts);
        assert_eq!(v(&tsh, &sig, body, &secret), Ok(()));
        for bad in [
            "",
            "0123",
            "+1700000000",
            " 1700000000",
            "1700000000.0",
            "-1",
        ] {
            assert!(v(bad, &sig, body, &secret).is_err(), "{bad:?}");
        }
        let hex_only = sig.trim_start_matches("sha384=");
        assert!(v(&tsh, hex_only, body, &secret).is_err());
        assert!(v(&tsh, &sig.to_uppercase(), body, &secret).is_err());
        assert!(v(
            &tsh,
            &format!("sha384={}", hex_only.to_uppercase()),
            body,
            &secret
        )
        .is_err());
        assert!(v(&tsh, &sig[..sig.len() - 2], body, &secret).is_err());
        let v2 = sign_body_v2(&secret, body).unwrap();
        assert!(v(&tsh, &v2, body, &secret).is_err());
        assert!(v(&tsh, &sig, br#"{"a":2}"#, &secret).is_err());
        assert!(v(&(ts + 1).to_string(), &sig, body, &secret).is_err());
        assert!(v(&tsh, &sig, body, &other).is_err());
    }

    #[test]
    fn curl_comment_minutes_match_the_tolerance_constant() {
        let r = build_verify_recipe_at(&row("k"), 1_700_000_000);
        assert!(r
            .snippets
            .curl
            .contains(&format!("valid for {} minutes", SIG_V3_TOLERANCE_SECS / 60)));
        assert!(r.snippets.curl.contains("test receiver"));
    }

    #[tokio::test]
    async fn the_default_clock_request_is_stamped_now_and_signed() {
        let secret = crate::crypto::rand::uuid_v4().to_string();
        let client = crate::crypto::tls::http_client_builder().build().unwrap();
        let body = r#"{"text":"hi"}"#;
        let req = build_request(&client, &row(&secret), body).build().unwrap();
        let ts: u64 = req
            .headers()
            .get(TIMESTAMP_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(unix_now().abs_diff(ts) <= 5);
        assert_eq!(
            req.headers().get(SIG_HEADER_V3).unwrap().to_str().unwrap(),
            sign_body_v3(&secret, ts, body.as_bytes()).unwrap()
        );
    }

    /// Run `prog args` with WEBHOOK_SECRET in the environment; Ok(None) when
    /// the interpreter is missing and `CI` is unset (skip), Err when missing in CI.
    fn run_interp(
        prog: &str,
        file: &std::path::Path,
        secret: &str,
    ) -> Result<Option<std::process::Output>, String> {
        let mut cmd = std::process::Command::new(prog);
        if prog.starts_with("python") {
            cmd.arg("-I");
        }
        cmd.arg(file).env("WEBHOOK_SECRET", secret);
        match cmd.output() {
            Ok(o) => Ok(Some(o)),
            Err(e) if std::env::var_os("CI").is_none() => {
                eprintln!("skipping: {prog} not runnable: {e}");
                Ok(None)
            }
            Err(e) => Err(format!("{prog} required in CI: {e}")),
        }
    }

    #[test]
    fn shipped_snippets_verify_v3_correctly() {
        let secret = crate::crypto::rand::uuid_v4().to_string();
        let other = crate::crypto::rand::uuid_v4().to_string();
        let ts = 1_700_000_000u64;
        let body = r#"{"a":1,"b":"\u00e9"}"#;
        let r = build_verify_recipe_at(&row(&secret), ts);
        let sig = |k: &str, t: u64, b: &str| sign_body_v3(k, t, b.as_bytes()).unwrap();
        let up = sig(&secret, ts, body)
            .to_uppercase()
            .replace("SHA384=", "sha384=");
        // (body, ts header, sig header, now, expected)
        let cases: Vec<(String, Option<String>, String, u64, bool)> = vec![
            (
                body.into(),
                Some(ts.to_string()),
                sig(&secret, ts, body),
                ts,
                true,
            ),
            (
                body.into(),
                Some(ts.to_string()),
                sig(&secret, ts, body),
                ts + 300,
                true,
            ),
            (
                body.into(),
                Some(ts.to_string()),
                sig(&secret, ts, body),
                ts - 300,
                true,
            ),
            (
                body.into(),
                Some(ts.to_string()),
                sig(&secret, ts, body),
                ts + 301,
                false,
            ),
            (
                body.into(),
                Some(ts.to_string()),
                sig(&secret, ts, body),
                ts - 301,
                false,
            ),
            (
                "{}".into(),
                Some(ts.to_string()),
                sig(&secret, ts, body),
                ts,
                false,
            ),
            (
                body.into(),
                Some((ts + 1).to_string()),
                sig(&secret, ts, body),
                ts,
                false,
            ),
            (
                body.into(),
                Some(ts.to_string()),
                sign_body_v2(&secret, body.as_bytes()).unwrap(),
                ts,
                false,
            ),
            (
                body.into(),
                Some(format!("0{ts}")),
                sig(&secret, ts, body),
                ts,
                false,
            ),
            (body.into(), None, sig(&secret, ts, body), ts, false),
            (body.into(), Some(ts.to_string()), up, ts, false),
            (
                body.into(),
                Some(ts.to_string()),
                sig(&other, ts, body),
                ts,
                false,
            ),
        ];
        let dir = std::env::temp_dir().join(format!("wh-v3-{}", crate::crypto::rand::uuid_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cases_json: Vec<_> = cases
            .iter()
            .map(|(b, t, s, n, _)| json!({"body": b, "ts": t, "sig": s, "now": n}))
            .collect();
        let cj = dir.join("cases.json");
        std::fs::write(&cj, serde_json::to_string(&cases_json).unwrap()).unwrap();
        let cj_s = cj.to_string_lossy().replace('\\', "/");
        let py = dir.join("v.py");
        std::fs::write(
            &py,
            format!(
                "{}\nimport json\nfor c in json.load(open({cj_s:?})):\n    print(int(verify_v3(c['body'].encode(), c['ts'], c['sig'], c['now'])))\n",
                r.snippets.python
            ),
        )
        .unwrap();
        let js = dir.join("v.js");
        std::fs::write(
            &js,
            format!(
                "{}\nfor (const c of JSON.parse(require('fs').readFileSync({}, 'utf8'))) console.log(verifyV3(Buffer.from(c.body), c.ts, c.sig, c.now) ? 1 : 0);\n",
                r.snippets.node,
                serde_json::to_string(&cj_s).unwrap()
            ),
        )
        .unwrap();
        let want: Vec<String> = cases.iter().map(|c| (c.4 as u8).to_string()).collect();
        let mut result = Ok(());
        for (prog, file) in [("python3", &py), ("node", &js)] {
            match run_interp(prog, file, &secret) {
                Err(e) => result = Err(e),
                Ok(None) => {}
                Ok(Some(o)) => {
                    let got: Vec<String> = String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .map(str::to_string)
                        .collect();
                    if !o.status.success() || got != want {
                        result = Err(format!(
                            "{prog}: got {got:?} want {want:?}: {}",
                            String::from_utf8_lossy(&o.stderr)
                        ));
                    }
                    // An empty secret must make the snippet refuse to start.
                    if let Ok(Some(e)) = run_interp(prog, file, "") {
                        if e.status.success() {
                            result = Err(format!("{prog}: empty secret was accepted"));
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap();
    }

    #[test]
    fn empty_secret_sends_no_signature_of_either_kind() {
        assert_eq!(sign_body("", b"x"), None);
        assert_eq!(sign_body_v2("", b"x"), None);
        assert_eq!(sign_body_v3("", 1_700_000_000, b"x"), None);
    }

    #[test]
    fn empty_secret_gives_unsigned_snippets() {
        let r = build_verify_recipe(&row(""));
        assert!(r.snippets.python.contains("unsigned"));
        assert!(r.snippets.node.contains("unsigned"));
        assert!(!r.snippets.curl.contains("X-Webhook-Signature"));
        assert!(!r.snippets.curl.contains("X-Webhook-Timestamp"));
    }

    #[test]
    fn view_reports_signed_without_a_secret_field() {
        let v = serde_json::to_value(WebhookView::from(row("s"))).unwrap();
        assert_eq!(v["signed"], true);
        assert!(v.get("secret").is_none());
    }
}
