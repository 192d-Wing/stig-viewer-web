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
//!   last `AUDIT_FAILURE_WINDOW_MINUTES`; `sustained` is also true when the
//!   failures span at least `AUDIT_SUSTAINED_FAILURE_MINUTES` distinct clock
//!   minutes of that window (an outage rather than a blip). `sustained` never
//!   changes the top-level status or HTTP code, is per replica, resets on
//!   restart, and a replica with little audit traffic may never reach it.
//! * `loginAckPrune` — `degraded` after `ACK_PRUNE_DEGRADED_AFTER` consecutive
//!   failed `prune_acks` ticks; clears on the next successful tick.
//!
//! On this unauthenticated endpoint `loginAckPrune` carries only
//! `{ "status" }` and `audit` carries `{ "status", "sustained" }`: the single
//! extra boolean lets monitors tell an outage from an isolated failure, while
//! public counts and timestamps would confirm to an unauthenticated caller
//! whether an attempt to suppress audit writes worked. Page on
//! `sustained == true`, after checking `shedWrites` and the "beyond the
//! tracked set" collusion log line: colluding authenticated accounts flooding
//! denied events until a shared-slot shed, or filling the queue, can also
//! raise it. Open a ticket on `degraded`. The numbers are on the
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
//! and logs at most once a minute per user (the shared-slot shed uses the
//! same per-user limit; users beyond 32 tracked ones share one overflow bucket, whose summary line
//! signals more than 32 distinct accounts shed in a minute (alert on it);
//! held-back counts are logged in a later summary line). Alert on the `shedWrites` rate and
//! on `writeFailures`, not only on the public status. `lateWrites` and `pendingWrites`
//! are early warnings of a slow pool; they do not degrade the public status.
//!
//! The admin endpoint also reports `admission` (`inFlight`, `refusedUser`,
//! `refusedGlobal`, `refusedBacklog`, `bodyDeadline`, `slowBody`): requests
//! refused by the audited-request cap or the audit-backlog mark, and bodies
//! cut off or slow (`api::admission`). Refusals never touch the public status.
//!
//! All queries have a 200ms timeout and the handler aims for ~250ms
//! end-to-end. The endpoint must stay fast — uptime monitors hit it
//! every few seconds and it must not become a hotspot.

use std::time::Duration;

use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::api::admission::AdmissionStats;
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

/// Distinct failure minutes within the window that make the `audit` check
/// `sustained`.
const AUDIT_SUSTAINED_FAILURE_MINUTES: u32 = 3;

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
    let (audit_status, audit_sustained) = audit_check(audit, now);
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
        "audit": { "status": audit_status.as_str(), "sustained": audit_sustained },
        "loginAckPrune": { "status": prune_status.as_str() },
    });
    (top, checks)
}

/// Body of `GET /api/admin/failure-counters`: counts and timestamps only.
fn counters_body(
    audit: &FailureSnapshot,
    audit_queue: (u64, u64, u64),
    prune: &FailureSnapshot,
    admission: AdmissionStats,
    now: DateTime<Utc>,
) -> Value {
    let (_, sustained) = audit_check(audit, now);
    json!({
        "audit": {
            "sustained": sustained,
            "failureMinutes": audit.recent.minutes_within(now, AUDIT_FAILURE_WINDOW_MINUTES as u32),
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
        "admission": {
            "inFlight": admission.in_flight,
            "refusedUser": admission.refused_user,
            "refusedGlobal": admission.refused_global,
            "refusedBacklog": admission.refused_backlog,
            "bodyDeadline": admission.body_deadline,
            "slowBody": admission.slow_body,
        },
    })
}

/// GET /api/admin/failure-counters — admin-only in-process failure counters.
pub async fn failure_counters_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    if user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(counters_body(
        &AUDIT_WRITES.snapshot(),
        crate::db_audit::write_stats(),
        &ACK_PRUNE.snapshot(),
        state.admission.stats(),
        Utc::now(),
    )))
}

fn rfc3339(t: Option<DateTime<Utc>>) -> Value {
    t.map_or(Value::Null, |t| Value::String(t.to_rfc3339()))
}

/// `degraded` when the last audit-write failure is within the window; the
/// bool is `sustained` (failures in enough distinct minutes of the window).
/// `status` uses an exact-seconds window and `sustained` minute buckets, so
/// near the edge a result can be `degraded` with `sustained == false`;
/// `sustained` implies `degraded` by construction.
fn audit_check(s: &FailureSnapshot, now: DateTime<Utc>) -> (Status, bool) {
    let recent = s.last_failure_at.is_some_and(|t| {
        now.signed_duration_since(t) < chrono::Duration::minutes(AUDIT_FAILURE_WINDOW_MINUTES)
    });
    let status = if recent { Status::Degraded } else { Status::Ok };
    let sustained = recent
        && s.recent
            .minutes_within(now, AUDIT_FAILURE_WINDOW_MINUTES as u32)
            >= AUDIT_SUSTAINED_FAILURE_MINUTES;
    (status, sustained)
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
            recent: crate::failure_counters::RecentFailures::default(),
        }
    }

    fn snap_minutes(now: DateTime<Utc>, ago: &[u32]) -> FailureSnapshot {
        let newest = i64::from(ago.iter().copied().min().unwrap_or(0));
        FailureSnapshot {
            total: ago.len() as u64,
            consecutive: ago.len() as u64,
            last_failure_at: Some(now - D::minutes(newest)),
            last_success_at: None,
            recent: crate::failure_counters::RecentFailures::from_minutes_ago(now, ago),
        }
    }

    #[test]
    fn audit_sustained_needs_three_distinct_recent_minutes() {
        let now = Utc::now();
        assert_eq!(audit_check(&snap(0, 0, None), now), (Status::Ok, false));
        assert_eq!(
            audit_check(&snap_minutes(now, &[1]), now),
            (Status::Degraded, false)
        );
        assert_eq!(
            audit_check(&snap_minutes(now, &[0, 1, 4]), now),
            (Status::Degraded, true)
        );
        assert_eq!(
            audit_check(&snap_minutes(now, &[16, 17, 20]), now),
            (Status::Ok, false)
        );
    }

    #[test]
    fn sustained_implies_degraded_at_the_window_edge() {
        let now = Utc::now();
        // Three distinct failure minutes all inside the window; only the
        // seconds-based `last_failure_at` moves across the 15-minute edge.
        for secs in [14 * 60, 14 * 60 + 59] {
            let mut s = snap_minutes(now, &[11, 12, 13]);
            s.last_failure_at = Some(now - D::seconds(secs));
            assert_eq!(audit_check(&s, now), (Status::Degraded, true), "{secs}s");
        }
        for secs in [15 * 60, 15 * 60 + 1] {
            let mut s = snap_minutes(now, &[11, 12, 13]);
            s.last_failure_at = Some(now - D::seconds(secs));
            assert_eq!(audit_check(&s, now), (Status::Ok, false), "{secs}s");
        }
    }

    #[test]
    fn counters_body_reports_failure_minutes_and_sustained() {
        let now = Utc::now();
        let s = snap_minutes(now, &[0, 3, 7]);
        let adm = AdmissionStats {
            in_flight: 0,
            refused_user: 0,
            refused_global: 0,
            refused_backlog: 0,
            body_deadline: 0,
            slow_body: 0,
        };
        let b = counters_body(&s, (0, 0, 0), &s, adm, now);
        assert_eq!(b["audit"]["failureMinutes"], 3);
        assert_eq!(b["audit"]["sustained"], true);
    }

    #[test]
    fn public_audit_check_has_status_and_sustained_only() {
        let now = Utc::now();
        let (top, checks) = build_checks(
            ok(),
            ok(),
            ok(),
            &snap_minutes(now, &[0, 1, 2]),
            &snap(0, 0, None),
            now,
        );
        assert_eq!(top, Status::Degraded);
        assert_eq!(
            checks["audit"],
            json!({ "status": "degraded", "sustained": true })
        );
        assert_eq!(keys(&checks["loginAckPrune"]), ["status"]);
    }

    #[tokio::test]
    async fn health_reports_a_recorded_audit_failure_without_a_database() {
        // Mutates the process-global counter and never resets it: other tests
        // may only assert one-directional facts (e.g. total rose) on it.
        AUDIT_WRITES.record_failure();
        let (state, _dir) = crate::test_fixtures::lazy_state();
        let (code, Json(v)) = get_health(State(state)).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["checks"]["audit"]["status"], "degraded");
        assert!(v["checks"]["audit"]["sustained"].is_boolean());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn health_degrades_after_a_real_swallowed_audit_write(pool: sqlx::PgPool) {
        let before = AUDIT_WRITES.snapshot().total;
        // Unseeded user: the FK rejects the insert through the production writer.
        crate::db_audit::record_or_log(
            &pool,
            crate::db_audit::NewAuditEvent {
                user_id: "ghost",
                action: "checklist.save",
                outcome: "ok",
                asset_id: None,
                checklist_id: None,
                stig_id: None,
                detail: json!({}),
                ctx: None,
            },
        )
        .await;
        assert!(AUDIT_WRITES.snapshot().total > before);
        let (state, _dir) = crate::test_fixtures::app_state(pool);
        let (code, Json(v)) = get_health(State(state)).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["checks"]["audit"]["status"], "degraded");
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
        assert_eq!(
            checks["audit"],
            json!({ "status": "ok", "sustained": false })
        );
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
        assert_eq!(
            checks["audit"],
            json!({ "status": "degraded", "sustained": false })
        );
        assert_eq!(keys(&checks["audit"]), ["status", "sustained"]);
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
        let adm = AdmissionStats {
            in_flight: 5,
            refused_user: 6,
            refused_global: 7,
            refused_backlog: 9,
            body_deadline: 8,
            slow_body: 10,
        };
        let b = counters_body(&s, (3, 2, 4), &s, adm, Utc::now());
        assert_eq!(keys(&b), ["admission", "audit", "loginAckPrune"]);
        assert_eq!(
            keys(&b["admission"]),
            [
                "bodyDeadline",
                "inFlight",
                "refusedBacklog",
                "refusedGlobal",
                "refusedUser",
                "slowBody"
            ]
        );
        assert_eq!(b["admission"]["refusedUser"], 6);
        assert_eq!(b["admission"]["refusedBacklog"], 9);
        assert_eq!(b["admission"]["slowBody"], 10);
        assert_eq!(
            keys(&b["audit"]),
            [
                "failureMinutes",
                "lastWriteFailureAt",
                "lateWrites",
                "pendingWrites",
                "shedWrites",
                "sustained",
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
        let (state, _dir) = crate::test_fixtures::lazy_state();
        for role in ["viewer", "author", "reviewer"] {
            let r = failure_counters_handler(
                State(state.clone()),
                Extension(crate::test_fixtures::auth("u", role)),
            )
            .await;
            assert_eq!(r.err(), Some(StatusCode::FORBIDDEN), "{role}");
        }
        let _permit = state.admission.try_admit("a").unwrap();
        let Json(v) = failure_counters_handler(
            State(state.clone()),
            Extension(crate::test_fixtures::auth("a", "admin")),
        )
        .await
        .unwrap();
        assert_eq!(keys(&v), ["admission", "audit", "loginAckPrune"]);
        assert_eq!(v["admission"]["inFlight"], 1);
    }
}
