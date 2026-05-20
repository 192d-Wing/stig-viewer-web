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

use crate::api::auth::AuthUser;
use crate::AppState;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_SNIPPET_LIMIT: usize = 500;

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
        SELECT id, name, url, secret, kinds, enabled, created_by, created_at
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

    let id = uuid::Uuid::new_v4().to_string();

    let row = sqlx::query_as::<_, WebhookRow>(
        r#"
        INSERT INTO webhooks (id, name, url, secret, kinds, enabled, created_by)
        VALUES ($1, $2, $3, $4, $5, TRUE, $6)
        RETURNING id, name, url, secret, kinds, enabled, created_by, created_at
        "#,
    )
    .bind(&id)
    .bind(&name)
    .bind(&url)
    .bind(&secret)
    .bind(&kinds)
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
        "SELECT id, name, url, secret, kinds, enabled, created_by, created_at \
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
    let enabled = req.enabled.unwrap_or(existing.enabled);

    let row = sqlx::query_as::<_, WebhookRow>(
        r#"
        UPDATE webhooks
           SET name = $1, url = $2, secret = $3,
               kinds = $4, enabled = $5
         WHERE id = $6
        RETURNING id, name, url, secret, kinds, enabled, created_by, created_at
        "#,
    )
    .bind(&name)
    .bind(&url)
    .bind(&secret)
    .bind(&kinds)
    .bind(enabled)
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
        "SELECT id, name, url, secret, kinds, enabled, created_by, created_at \
         FROM webhooks WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(map_sqlx)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let payload = build_assigned_payload(&AssignedEvent {
        rule_id: "SV-TEST".to_string(),
        assignee_name: user.display_name.clone(),
        asset_name: "test-asset".to_string(),
        stig_title: "Test STIG".to_string(),
        severity: "CAT II".to_string(),
        due_date: None,
    });

    let pool = state.pool.clone();
    tokio::spawn(async move {
        deliver_one(pool.as_ref(), &webhook, "assigned", &payload).await;
    });
    Ok(StatusCode::ACCEPTED)
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

pub fn build_assigned_payload(ev: &AssignedEvent) -> Value {
    let due_part = ev
        .due_date
        .as_ref()
        .map(|d| format!(" · Due: {}", d))
        .unwrap_or_default();
    json!({
        "text": format!("Finding {} assigned to {}", ev.rule_id, ev.assignee_name),
        "attachments": [{
            "title": format!("Asset: {} · STIG: {}", ev.asset_name, ev.stig_title),
            "text": format!("Severity: {}{}", ev.severity, due_part),
            "color": severity_color(&ev.severity),
        }]
    })
}

/// Fan an event out to every enabled webhook subscribed to `kind`.
/// Intended to be called from inside a `tokio::spawn` so the originating
/// request can return immediately.
pub async fn dispatch_event(pool: &PgPool, kind: &str, payload: Value) {
    // Postgres array containment: kinds @> ARRAY[$2]
    let webhooks = match sqlx::query_as::<_, WebhookRow>(
        r#"
        SELECT id, name, url, secret, kinds, enabled, created_by, created_at
          FROM webhooks
         WHERE enabled = TRUE
           AND $1 = ANY(kinds)
        "#,
    )
    .bind(kind)
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
        deliver_one(pool, &w, kind, &payload).await;
    }
}

/// POST the payload to one webhook and log the outcome. Failures (bad
/// DNS, connection refused, non-2xx) are still recorded so the operator
/// can debug from the Admin UI.
async fn deliver_one(pool: &PgPool, webhook: &WebhookRow, kind: &str, payload: &Value) {
    let body = match serde_json::to_string(payload) {
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
    if !webhook.secret.is_empty() {
        req = req.header("X-Webhook-Secret", webhook.secret.as_str());
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
