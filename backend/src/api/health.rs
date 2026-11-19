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
//! Two further checks read in-process counters (no DB query, so they answer
//! even when the DB is down), see `failure_counters`:
//! * `audit` — `degraded` if a swallowed audit-write failure happened in the
//!   last `AUDIT_FAILURE_WINDOW_MINUTES`.
//! * `loginAckPrune` — `degraded` after `ACK_PRUNE_DEGRADED_AFTER` consecutive
//!   failed `prune_acks` ticks; clears on the next successful tick.
//!
//! On this unauthenticated endpoint both carry only `{ "status" }`: public
//! counts and timestamps would confirm to an unauthenticated caller whether
//! an attempt to suppress audit writes worked. The numbers are on the
//! admin-only `GET /api/admin/failure-counters` (counts and timestamps only,
//! never error text, ids or actions; 403 for non-admins like every other
//! `/api/admin/*` route; not audited, like `scheduler-runs`, since it exposes
//! operational counters rather than audit records).
//!
//! The counters are per replica and since process start, and only ever
//! report `ok` or `degraded`, never `error`. Alert on the rate of change of
//! `writeFailures` from the admin endpoint, not only on status (which
//! self-clears); the authoritative AU-5 signal across replicas and restarts is
//! the `failed to write audit event` error log line, which needs a log-based
//! alert. This is not AU-5(1)/(2).
//!
//! Audit writes are detached tasks (`db_audit`): a write that finishes after
//! the caller's 5 s wait still counts as a success and adds to `lateWrites`;
//! a failure is a confirmed error, the 30 s hard cap, or a write shed with 64
//! already pending. A shed
//! means a missing row: `shedWrites` (admin endpoint only) counts them
//! separately. A shed is also a failure (reasons: 64 pending in all, or the 16
//! shared denied/rejected slots full), except one caused by a single user's
//! own denied/rejected sub-cap (4) (a user can trigger those at will, so they must
//! not be able to degrade this status); that one counts only in `shedWrites`
//! and logs at most once a minute per user. Alert on the `shedWrites` rate and
//! on `writeFailures`, not only on the public status. `lateWrites` and `pendingWrites`
//! are early warnings of a slow pool; they do not degrade the public status.
//!
//! All queries have a 200ms timeout and the handler aims for ~250ms
//! end-to-end. The endpoint must stay fast — uptime monitors hit it
//! every few seconds and it must not become a hotspot.

use std::time::Duration;

use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::api::auth::AuthUser;
use crate::failure_counters::{FailureSnapshot, ACK_PRUNE, AUDIT_WRITES};
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

/// A swallowed audit-write failure this recent degrades the `audit` check.
const AUDIT_FAILURE_WINDOW_MINUTES: i64 = 15;

/// Consecutive failed ack-prune ticks (one per minute) before `degraded`.
const ACK_PRUNE_DEGRADED_AFTER: u64 = 3;

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

    let (top, checks) = build_checks(
        (db_status, db_value),
        (sched_status, sched_value),
        (hook_status, hook_value),
        &AUDIT_WRITES.snapshot(),
        &ACK_PRUNE.snapshot(),
        Utc::now(),
    );

    let http = http_status(top);

    let body = json!({
        "status": top.as_str(),
        "version": env!("CARGO_PKG_VERSION"),
        "checks": checks,
    });

    (http, Json(body))
}

fn http_status(top: Status) -> StatusCode {
    if top == Status::Error {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    }
}

/// Assemble the `checks` object and the merged top-level status. The audit
/// and ack-prune checks are in-process only and public, so they expose
/// `status` and nothing else.
fn build_checks(
    db: (Status, Value),
    schedulers: (Status, Value),
    webhooks: (Status, Value),
    audit: &FailureSnapshot,
    prune: &FailureSnapshot,
    now: DateTime<Utc>,
) -> (Status, Value) {
    let (audit_status, _) = audit_check(audit, now);
    let (prune_status, _) = ack_prune_check(prune);
    let top =
        db.0.merge(schedulers.0)
            .merge(webhooks.0)
            .merge(audit_status)
            .merge(prune_status);
    let checks = json!({
        "db": db.1,
        "schedulers": schedulers.1,
        "webhooks": webhooks.1,
        "audit": { "status": audit_status.as_str() },
        "loginAckPrune": { "status": prune_status.as_str() },
    });
    (top, checks)
}

/// Body of `GET /api/admin/failure-counters`: counts and timestamps only.
fn counters_body(
    audit: &FailureSnapshot,
    audit_queue: (u64, u64, u64),
    prune: &FailureSnapshot,
) -> Value {
    json!({
        "audit": {
            "writeFailures": audit.total,
            "lastWriteFailureAt": rfc3339(audit.last_failure_at),
            "lateWrites": audit_queue.0,
            "pendingWrites": audit_queue.1,
            "shedWrites": audit_queue.2,
        },
        "loginAckPrune": {
            "failures": prune.total,
            "consecutiveFailures": prune.consecutive,
            "lastFailureAt": rfc3339(prune.last_failure_at),
            "lastSuccessAt": rfc3339(prune.last_success_at),
        },
    })
}

/// GET /api/admin/failure-counters — admin-only in-process failure counters.
pub async fn failure_counters_handler(
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    if user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(counters_body(
        &AUDIT_WRITES.snapshot(),
        crate::db_audit::write_stats(),
        &ACK_PRUNE.snapshot(),
    )))
}

fn rfc3339(t: Option<DateTime<Utc>>) -> Value {
    t.map_or(Value::Null, |t| Value::String(t.to_rfc3339()))
}

/// `degraded` when the last audit-write failure is within the window.
fn audit_check(s: &FailureSnapshot, now: DateTime<Utc>) -> (Status, Value) {
    let recent = s.last_failure_at.is_some_and(|t| {
        now.signed_duration_since(t) < chrono::Duration::minutes(AUDIT_FAILURE_WINDOW_MINUTES)
    });
    let status = if recent { Status::Degraded } else { Status::Ok };
    (status, json!({ "status": status.as_str() }))
}

/// `degraded` after `ACK_PRUNE_DEGRADED_AFTER` consecutive failed ticks.
fn ack_prune_check(s: &FailureSnapshot) -> (Status, Value) {
    let status = if s.consecutive >= ACK_PRUNE_DEGRADED_AFTER {
        Status::Degraded
    } else {
        Status::Ok
    };
    (status, json!({ "status": status.as_str() }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure_counters::FailureCounter;
    use chrono::Duration as D;

    fn snap(total: u64, consecutive: u64, failed_ago: Option<D>) -> FailureSnapshot {
        let now = Utc::now();
        FailureSnapshot {
            total,
            consecutive,
            last_failure_at: failed_ago.map(|d| now - d),
            last_success_at: None,
        }
    }

    #[test]
    fn audit_ok_without_failures() {
        assert_eq!(audit_check(&snap(0, 0, None), Utc::now()).0, Status::Ok);
    }

    #[test]
    fn audit_degraded_for_a_recent_failure_and_recovers() {
        let now = Utc::now();
        let recent = FailureSnapshot {
            last_failure_at: Some(now - D::minutes(1)),
            ..snap(1, 1, None)
        };
        assert_eq!(audit_check(&recent, now).0, Status::Degraded);
        let old = FailureSnapshot {
            last_failure_at: Some(now - D::minutes(16)),
            ..snap(1, 1, None)
        };
        assert_eq!(audit_check(&old, now).0, Status::Ok);
    }

    #[test]
    fn ack_prune_degrades_at_three_and_clears_on_success() {
        assert_eq!(ack_prune_check(&snap(2, 2, Some(D::zero()))).0, Status::Ok);
        assert_eq!(
            ack_prune_check(&snap(3, 3, Some(D::zero()))).0,
            Status::Degraded
        );
        let c = FailureCounter::new();
        for _ in 0..3 {
            c.record_failure();
        }
        c.record_success();
        assert_eq!(ack_prune_check(&c.snapshot()).0, Status::Ok);
    }

    fn keys(v: &Value) -> Vec<String> {
        let mut k: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    }

    fn ok() -> (Status, Value) {
        (Status::Ok, json!({ "status": "ok" }))
    }

    #[test]
    fn public_checks_carry_status_only_and_a_recent_failure_degrades_the_top_level() {
        let now = Utc::now();
        let (top, checks) =
            build_checks(ok(), ok(), ok(), &snap(0, 0, None), &snap(0, 0, None), now);
        assert_eq!(top, Status::Ok);
        assert_eq!(checks["audit"], json!({ "status": "ok" }));
        assert_eq!(checks["loginAckPrune"], json!({ "status": "ok" }));

        let (top, checks) = build_checks(
            ok(),
            ok(),
            ok(),
            &snap(1, 1, Some(D::minutes(1))),
            &snap(0, 0, None),
            now,
        );
        assert_eq!(top, Status::Degraded);
        assert_eq!(checks["audit"], json!({ "status": "degraded" }));
        assert_eq!(keys(&checks["audit"]), ["status"]);
        assert_eq!(keys(&checks["loginAckPrune"]), ["status"]);
    }

    #[tokio::test]
    async fn health_checks_with_a_recent_audit_failure_are_degraded_with_http_200() {
        // The handler itself needs a database; this exercises the same
        // assembly and status mapping it uses.
        let (top, _) = build_checks(
            ok(),
            ok(),
            ok(),
            &snap(1, 1, Some(D::zero())),
            &snap(0, 0, None),
            Utc::now(),
        );
        assert_eq!((top, http_status(top)), (Status::Degraded, StatusCode::OK));
    }

    #[test]
    fn counters_body_holds_exactly_the_documented_keys() {
        let s = snap(1, 1, Some(D::zero()));
        let b = counters_body(&s, (3, 2, 4), &s);
        assert_eq!(keys(&b), ["audit", "loginAckPrune"]);
        assert_eq!(
            keys(&b["audit"]),
            [
                "lastWriteFailureAt",
                "lateWrites",
                "pendingWrites",
                "shedWrites",
                "writeFailures"
            ]
        );
        assert_eq!(b["audit"]["lateWrites"], 3);
        assert_eq!(b["audit"]["pendingWrites"], 2);
        assert_eq!(b["audit"]["shedWrites"], 4);
        assert_eq!(
            keys(&b["loginAckPrune"]),
            [
                "consecutiveFailures",
                "failures",
                "lastFailureAt",
                "lastSuccessAt"
            ]
        );
        assert_eq!(b["audit"]["writeFailures"], 1);
        assert!(b["loginAckPrune"]["lastSuccessAt"].is_null());
    }

    #[tokio::test]
    async fn failure_counters_endpoint_refuses_non_admins_and_serves_admins() {
        for role in ["viewer", "author", "reviewer"] {
            let r =
                failure_counters_handler(Extension(crate::test_fixtures::auth("u", role))).await;
            assert_eq!(r.err(), Some(StatusCode::FORBIDDEN), "{role}");
        }
        let Json(v) = failure_counters_handler(Extension(crate::test_fixtures::auth("a", "admin")))
            .await
            .unwrap();
        assert_eq!(keys(&v), ["audit", "loginAckPrune"]);
    }
}
