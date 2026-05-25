//! Deep-health endpoint used by load balancers and uptime monitors.
//!
//! `GET /api/health` is intentionally unauthenticated and lives outside
//! the auth-middleware stack (see `main.rs`). It does three lightweight
//! checks against the database and reports a per-component status plus
//! an aggregated top-level status.
//!
//! Status semantics:
//! * `ok` — everything looks healthy; HTTP 200
//! * `degraded` — at least one non-fatal issue (stale scheduler, some
//!   webhook delivery errors); HTTP 200 so the LB keeps the node in
//!   rotation
//! * `error` — the DB is unreachable or every recent webhook delivery
//!   failed; HTTP 503 so the LB pulls the node
//!
//! All queries have a 200ms timeout and the handler aims for ~250ms
//! end-to-end. The endpoint must stay fast — uptime monitors hit it
//! every few seconds and it must not become a hotspot.

use std::time::Duration;

use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::AppState;

/// All six background schedulers wired up in `main.rs`. Five of them
/// are surfaced by `/api/test/run-scheduler`; `asset_email_schedule`
/// is the sixth (driven by SQL interval, no run-scheduler arm).
///
/// Keeping the list inline here means the health endpoint reports a
/// `null` entry the first time the backend starts (before any tick has
/// fired), which is exactly what we want for the "be lenient" rule —
/// missing rows surface as `degraded`, never `error`.
const KNOWN_SCHEDULERS: &[&str] = &[
    "sync",
    "snapshot",
    "overdue_digest",
    "audit_retention",
    "compliance_report",
    "asset_email_schedule",
];

/// How fresh a scheduler's last finished tick must be before we flag
/// the schedulers check as degraded.
const SCHEDULER_FRESHNESS_HOURS: i64 = 48;

/// Per-query timeout. The three checks are independent and serially
/// executed; a single hung query must not block the whole endpoint.
const QUERY_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Degraded,
    Error,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Degraded => "degraded",
            Status::Error => "error",
        }
    }

    /// Merge two component statuses into the strictest of the two.
    fn merge(self, other: Status) -> Status {
        match (self, other) {
            (Status::Error, _) | (_, Status::Error) => Status::Error,
            (Status::Degraded, _) | (_, Status::Degraded) => Status::Degraded,
            _ => Status::Ok,
        }
    }
}

/// GET /api/health — deep health check.
///
/// The handler always returns a JSON body (never 500), even when the
/// DB is down. A 503 is only used when the top-level status is `error`
/// so an upstream LB can pull the node out of rotation; everything
/// else returns 200.
pub async fn get_health(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let pool = state.pool.as_ref();

    let (db_status, db_value) = check_db(pool).await;
    let (sched_status, sched_value) = check_schedulers(pool).await;
    let (hook_status, hook_value) = check_webhooks(pool).await;

    let top = db_status.merge(sched_status).merge(hook_status);

    let http = if top == Status::Error {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    let body = json!({
        "status": top.as_str(),
        "version": env!("CARGO_PKG_VERSION"),
        "checks": {
            "db":         db_value,
            "schedulers": sched_value,
            "webhooks":   hook_value,
        }
    });

    (http, Json(body))
}

/// `SELECT 1` with a 200ms timeout. Anything other than a clean reply
/// flips the component (and top-level) status to `error`.
async fn check_db(pool: &sqlx::PgPool) -> (Status, Value) {
    let q = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool);
    match tokio::time::timeout(QUERY_TIMEOUT, q).await {
        Ok(Ok(_)) => (
            Status::Ok,
            json!({ "status": "ok", "message": "select 1 ok" }),
        ),
        Ok(Err(e)) => {
            tracing::warn!("health: db query failed: {e:#}");
            (
                Status::Error,
                json!({ "status": "error", "message": format!("query failed: {e}") }),
            )
        }
        Err(_) => {
            tracing::warn!("health: db query timed out");
            (
                Status::Error,
                json!({ "status": "error", "message": "query timed out" }),
            )
        }
    }
}

/// For each known scheduler, look up the most recent row's
/// `finished_at`. Rules:
/// * Any scheduler with a most-recent row whose `status='error'`
///   degrades the check.
/// * Any scheduler whose last `finished_at` is older than
///   `SCHEDULER_FRESHNESS_HOURS` degrades the check.
/// * A scheduler with no row at all (fresh dev env) is also `degraded`
///   but never escalates to `error`.
/// * Everything fresh + ok → `ok`.
async fn check_schedulers(pool: &sqlx::PgPool) -> (Status, Value) {
    // Pull the most recent row per scheduler name in a single query.
    // DISTINCT ON walks the (name, started_at DESC) index and bounds
    // the cost to the number of distinct names.
    let q = sqlx::query_as::<_, (String, Option<DateTime<Utc>>, String)>(
        r#"
        SELECT DISTINCT ON (name) name, finished_at, status
          FROM scheduler_runs
         ORDER BY name, started_at DESC
        "#,
    )
    .fetch_all(pool);

    let rows = match tokio::time::timeout(QUERY_TIMEOUT, q).await {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => {
            tracing::warn!("health: scheduler query failed: {e:#}");
            return (
                Status::Degraded,
                json!({
                    "status": "degraded",
                    "lastRuns": {},
                    "message": format!("scheduler query failed: {e}"),
                }),
            );
        }
        Err(_) => {
            tracing::warn!("health: scheduler query timed out");
            return (
                Status::Degraded,
                json!({
                    "status": "degraded",
                    "lastRuns": {},
                    "message": "scheduler query timed out",
                }),
            );
        }
    };

    let now = Utc::now();
    let mut last_runs = serde_json::Map::new();
    let mut overall = Status::Ok;

    for name in KNOWN_SCHEDULERS {
        let row = rows.iter().find(|(n, _, _)| n == name);
        match row {
            Some((_, Some(finished), status)) => {
                last_runs.insert((*name).to_string(), Value::String(finished.to_rfc3339()));
                let age = now.signed_duration_since(*finished);
                if status == "error" || age.num_hours() >= SCHEDULER_FRESHNESS_HOURS {
                    overall = overall.merge(Status::Degraded);
                }
            }
            Some((_, None, status)) => {
                // Row exists but `finished_at` is NULL — either the
                // tick is in-flight (`running`) or finished without a
                // timestamp. Surface `null` and mark degraded unless
                // it's currently running.
                last_runs.insert((*name).to_string(), Value::Null);
                if status != "running" {
                    overall = overall.merge(Status::Degraded);
                }
            }
            None => {
                // Never ran. Lenient: degraded, not error.
                last_runs.insert((*name).to_string(), Value::Null);
                overall = overall.merge(Status::Degraded);
            }
        }
    }

    (
        overall,
        json!({
            "status": overall.as_str(),
            "lastRuns": Value::Object(last_runs),
        }),
    )
}

/// Count `webhook_deliveries` rows over the last 24h plus how many had
/// a non-null `error`. Rules:
/// * 0 deliveries → `ok`. No traffic is not an error.
/// * All deliveries failed → `error`.
/// * Some failed → `degraded`.
/// * None failed → `ok`.
async fn check_webhooks(pool: &sqlx::PgPool) -> (Status, Value) {
    let q = sqlx::query_as::<_, (i64, i64)>(
        r#"
        SELECT COUNT(*)::BIGINT,
               COUNT(*) FILTER (WHERE error IS NOT NULL)::BIGINT
          FROM webhook_deliveries
         WHERE attempted_at >= NOW() - INTERVAL '24 hours'
        "#,
    )
    .fetch_one(pool);

    let (total, errors) = match tokio::time::timeout(QUERY_TIMEOUT, q).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            tracing::warn!("health: webhook query failed: {e:#}");
            return (
                Status::Degraded,
                json!({
                    "status": "degraded",
                    "deliveries24h": 0,
                    "errors24h": 0,
                    "message": format!("webhook query failed: {e}"),
                }),
            );
        }
        Err(_) => {
            tracing::warn!("health: webhook query timed out");
            return (
                Status::Degraded,
                json!({
                    "status": "degraded",
                    "deliveries24h": 0,
                    "errors24h": 0,
                    "message": "webhook query timed out",
                }),
            );
        }
    };

    let status = if total == 0 {
        Status::Ok
    } else if errors >= total {
        Status::Error
    } else if errors > 0 {
        Status::Degraded
    } else {
        Status::Ok
    };

    (
        status,
        json!({
            "status": status.as_str(),
            "deliveries24h": total,
            "errors24h": errors,
        }),
    )
}
