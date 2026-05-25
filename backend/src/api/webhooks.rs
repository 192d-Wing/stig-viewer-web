//! Outbound webhook delivery + admin CRUD.
//!
//! ## Payload signing (HMAC-SHA256)
//!
//! Every delivery whose `webhooks.secret` is non-empty carries an
//! `X-Webhook-Signature` header of the form `sha256=<hex>` where `<hex>`
//! is the lower-case hexadecimal HMAC-SHA256 of the raw request body
//! keyed by the configured secret. The scheme matches GitHub's webhook
//! convention, so any receiver that already validates GitHub webhooks
//! can reuse the same code path verbatim.
//!
//! Webhooks with an empty secret are sent **unsigned** — no header at
//! all — preserving the original opt-in behaviour for users who do not
//! care about replay protection (e.g. internal-only Slack incoming
//! webhooks behind a VPN). The pre-HMAC `X-Webhook-Secret` literal-value
//! header was removed; secrets are never transmitted on the wire.
//!
//! ### Verification recipe — Python
//! ```python
//! import hmac, hashlib
//! sig = "sha256=" + hmac.new(
//!     secret.encode(), body_bytes, hashlib.sha256
//! ).hexdigest()
//! # constant-time compare against request.headers["X-Webhook-Signature"]
//! hmac.compare_digest(sig, received_header)
//! ```
//!
//! ### Verification recipe — Node.js
//! ```js
//! const crypto = require("crypto");
//! const sig = "sha256=" + crypto
//!   .createHmac("sha256", secret)
//!   .update(rawBody)
//!   .digest("hex");
//! crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(receivedHeader));
//! ```

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::PgPool;
use std::time::Duration;

use crate::api::auth::AuthUser;
use crate::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Compute the `sha256=<hex>` signature for `body` keyed by `secret`.
/// Returns `None` when `secret` is empty so callers can branch on
/// "unsigned webhook" without inspecting the string twice.
fn sign_body(secret: &str, body: &[u8]) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    // Hmac::new_from_slice is infallible for HMAC-SHA256 — any byte
    // length is valid as a key — so the unwrap can never fire.
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(body);
    Some(format!("sha256={}", hex::encode(mac.finalize().into_bytes())))
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

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
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
) -> Result<Json<Vec<WebhookRow>>, StatusCode> {
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
    Ok(Json(rows))
}

/// POST /api/webhooks — admin-only create. 400 on empty name/url or a
/// non-http(s) url. Default `kinds` is ['assigned'] when omitted.
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateRequest>,
) -> Result<(StatusCode, Json<WebhookRow>), StatusCode> {
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

    let id = uuid::Uuid::new_v4().to_string();

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
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    Ok((StatusCode::CREATED, Json(row)))
}

/// PATCH /api/webhooks/:id — admin-only partial update. Any field left
/// out is left untouched. 404 if the row doesn't exist.
pub async fn update_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateRequest>,
) -> Result<Json<WebhookRow>, StatusCode> {
    ensure_admin(&user)?;

    let existing = sqlx::query_as::<_, WebhookRow>(
        "SELECT id, name, url, secret, kinds, enabled, flavor, created_by, created_at \
         FROM webhooks WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?
    .ok_or(StatusCode::NOT_FOUND)?;

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
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?;

    Ok(Json(row))
}

/// DELETE /api/webhooks/:id — admin-only. Deliveries cascade away.
pub async fn delete_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    ensure_admin(&user)?;
    let res = sqlx::query("DELETE FROM webhooks WHERE id = $1")
        .bind(&id)
        .execute(state.pool.as_ref())
        .await
        .map_err(map_sqlx)?;
    if res.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
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
/// webhook's actual URL + secret + a canned sample payload pre-filled so
/// an operator can validate a receiver end-to-end without having to copy
/// individual values around. When the webhook's secret is empty we emit
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

/// Build the curl/Python/Node snippets for one webhook. Pulled out so
/// it's unit-testable in isolation from the HTTP layer.
fn build_verify_recipe(webhook: &WebhookRow) -> VerifyRecipe {
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

    let header_name = "X-Webhook-Signature";
    let snippets = if webhook.secret.is_empty() {
        VerifyRecipeSnippets {
            curl: unsigned_curl_snippet(&webhook.url, &sample_payload),
            python: unsigned_python_snippet(),
            node: unsigned_node_snippet(),
        }
    } else {
        let sig = sign_body(&webhook.secret, sample_payload.as_bytes())
            .expect("non-empty secret always signs");
        VerifyRecipeSnippets {
            curl: signed_curl_snippet(&webhook.url, &sample_payload, &sig, header_name),
            python: signed_python_snippet(&webhook.secret, header_name),
            node: signed_node_snippet(&webhook.secret, header_name),
        }
    };

    VerifyRecipe {
        id: webhook.id.clone(),
        name: webhook.name.clone(),
        url: webhook.url.clone(),
        header_name: header_name.to_string(),
        sample_payload,
        snippets,
    }
}

fn signed_curl_snippet(url: &str, body: &str, sig: &str, header: &str) -> String {
    // Single-line curl that demonstrates exactly what the dispatcher
    // emits on the wire. The signature is pre-computed for the literal
    // sample body so a paste-and-run actually validates downstream.
    format!(
        "curl -X POST '{url}' \\\n  -H 'Content-Type: application/json' \\\n  -H '{header}: {sig}' \\\n  -d '{body}'"
    )
}

fn unsigned_curl_snippet(url: &str, body: &str) -> String {
    format!(
        "# This webhook is configured as unsigned (no secret set) — no signature header is sent.\ncurl -X POST '{url}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{body}'"
    )
}

fn signed_python_snippet(secret: &str, header: &str) -> String {
    // Receiver-side verification recipe. The secret is embedded so the
    // operator can paste-and-run; in production they'd load it from a
    // secrets manager.
    format!(
        "# Python receiver — verify the X-Webhook-Signature header.\nimport hmac, hashlib\n\nSECRET = {secret_lit}.encode()\nHEADER = {header_lit}\n\ndef verify(raw_body: bytes, received_sig: str) -> bool:\n    expected = 'sha256=' + hmac.new(SECRET, raw_body, hashlib.sha256).hexdigest()\n    return hmac.compare_digest(expected, received_sig)\n\n# In Flask / FastAPI / Django:\n#   ok = verify(request.get_data(), request.headers[HEADER])\n",
        secret_lit = python_string_literal(secret),
        header_lit = python_string_literal(header),
    )
}

fn unsigned_python_snippet() -> String {
    // Explicit signal that the body is unauthenticated — anyone who can
    // reach the URL can forge events. Operators should add a secret if
    // they want replay protection.
    "# This webhook is configured as unsigned (no secret set).\n# Receivers cannot verify the body's authenticity — there is no signature header.\n# Set a secret on the webhook in the Admin Console to enable HMAC verification.\n".to_string()
}

fn signed_node_snippet(secret: &str, header: &str) -> String {
    format!(
        "// Node.js receiver — verify the X-Webhook-Signature header.\nconst crypto = require('crypto');\n\nconst SECRET = {secret_lit};\nconst HEADER = {header_lit};\n\nfunction verify(rawBody, receivedSig) {{\n  const expected = 'sha256=' + crypto.createHmac('sha256', SECRET).update(rawBody).digest('hex');\n  const a = Buffer.from(expected);\n  const b = Buffer.from(receivedSig || '');\n  return a.length === b.length && crypto.timingSafeEqual(a, b);\n}}\n\n// In Express:\n//   app.post('/hook', express.raw({{ type: 'application/json' }}), (req, res) => {{\n//     if (!verify(req.body, req.get(HEADER))) return res.sendStatus(401);\n//     res.sendStatus(200);\n//   }});\n",
        secret_lit = js_string_literal(secret),
        header_lit = js_string_literal(header),
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
/// the actual URL/secret/sample-body pre-filled. 404 if the webhook is
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
    let top = s.top_asset_name.clone().unwrap_or_else(|| "(none)".to_string());
    let download = format!("/api/reports/{}/report.pdf", row.id);
    let body = format!(
        "Top-risk system: {} — download at {}",
        top, download,
    );
    let fields = vec![
        ("Compliance score".to_string(), format!("{:.1}%", s.compliance_score)),
        ("Assets".to_string(), s.assets.to_string()),
        ("Open findings".to_string(), s.open_findings.to_string()),
        ("Overdue findings".to_string(), s.overdue_findings.to_string()),
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
            .map(|i| json!({
                "title": i.title,
                "text": i.text,
                "color": i.color,
            }))
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
        .map(|i| json!({
            "title": i.title,
            "text": i.text,
            "color": i.color,
        }))
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

    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build();
    let client = match client {
        Ok(c) => c,
        Err(e) => {
            // Couldn't even build the client — still record so the UI shows
            // *something* rather than silently dropping the event.
            record_delivery(pool, &webhook.id, kind, &body, None, None, Some(&e.to_string())).await;
            return;
        }
    };

    let mut req = client
        .post(&webhook.url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.clone());
    // HMAC-SHA256(body, secret) → `X-Webhook-Signature: sha256=<hex>`.
    // Webhooks with an empty secret remain unsigned (no header) so the
    // "I don't care about replay protection" path keeps working.
    if let Some(sig) = sign_body(&webhook.secret, body.as_bytes()) {
        req = req.header("X-Webhook-Signature", sig);
    }

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
            record_delivery(pool, &webhook.id, kind, &body, None, None, Some(&e.to_string()))
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
