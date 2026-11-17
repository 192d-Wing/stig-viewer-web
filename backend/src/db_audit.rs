//! Durable request-level audit events (`audit_events`).
//!
//! `rule_audit` records one row per rule field change; this table records the
//! request that caused them, including requests that were rejected (400) or
//! denied (403). `detail` holds only counts, status values, reason codes and
//! (truncated) rule ids; never finding details, comments or other free text
//! from the request. The one exception is `auth.notice_ack`, whose `detail`
//! carries the sanitized, truncated User-Agent and client IP of the acknowledgement.

use anyhow::Result;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::api::request_ctx::RequestCtx;

/// At most this many rejected rules are listed in an event's `detail`.
pub const MAX_REJECTED_LISTED: usize = 100;

pub struct NewAuditEvent<'a> {
    pub user_id: &'a str,
    /// "rules.bulk_status" | "rules.bulk_import" | "checklist.save" | "checklist.create" | "auth.notice_ack"
    pub action: &'static str,
    /// "ok" | "partial" | "denied" | "rejected"
    pub outcome: &'static str,
    pub asset_id: Option<&'a str>,
    pub checklist_id: Option<&'a str>,
    pub stig_id: Option<&'a str>,
    pub detail: Value,
    /// Request context (source IP, request id, role). `None` outside a request.
    pub ctx: Option<&'a RequestCtx>,
}

/// Declare an audit maintenance mode (`retention`, `restore`, `migration` or `test`) for the
/// rest of this transaction; the guard triggers from migration 040 permit the
/// matching mutation of `rule_audit` / `audit_events` only while it is set.
pub(crate) async fn set_maintenance(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mode: &str,
) -> Result<()> {
    sqlx::query("SELECT set_config('stig.audit_maintenance', $1, true)")
        .bind(mode)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Upper bound on one audit write (both attempts of [`record_or_log`]), so a
/// busy pool cannot hold the response for the pool's acquire timeout.
pub const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Longest id kept in an id column (and its log lines).
pub const MAX_ID_CHARS: usize = 128;

/// An id column value made safe to store and log: at most [`MAX_ID_CHARS`]
/// characters, anything outside ASCII alphanumerics and `._:-` replaced by `?`.
pub fn bound_id(id: &str) -> String {
    sanitize(id, MAX_ID_CHARS)
}

fn sanitize(id: &str, max: usize) -> String {
    id.chars()
        .take(max)
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-') { c } else { '?' })
        .collect()
}

/// The three id columns, bounded once and used for both insert attempts and
/// the log lines so no caller can store or print an unbounded value.
struct BoundedIds {
    asset_id: Option<String>,
    checklist_id: Option<String>,
    stig_id: Option<String>,
}

fn bounded(ev: &NewAuditEvent<'_>) -> BoundedIds {
    BoundedIds {
        asset_id: ev.asset_id.map(bound_id),
        checklist_id: ev.checklist_id.map(bound_id),
        stig_id: ev.stig_id.map(bound_id),
    }
}

async fn insert<'e, E: sqlx::PgExecutor<'e>>(pool: E, ev: &NewAuditEvent<'_>, ids: &BoundedIds, detail: &Value) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_events (user_id, action, outcome, asset_id, checklist_id, stig_id, detail, \
                                  source_ip, request_id, user_role) \
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)",
    )
    .bind(ev.user_id)
    .bind(ev.action)
    .bind(ev.outcome)
    .bind(&ids.asset_id)
    .bind(&ids.checklist_id)
    .bind(&ids.stig_id)
    .bind(detail.to_string())
    .bind(ev.ctx.and_then(|c| c.source_ip.as_deref()))
    .bind(ev.ctx.map(|c| c.request_id.as_str()))
    .bind(ev.ctx.map(|c| bound_id(&c.role)))
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert an event on an open transaction, so it commits or rolls back with
/// the caller's work. Unlike [`record_or_log`] a failure is returned.
pub(crate) async fn record_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ev: &NewAuditEvent<'_>,
) -> Result<()> {
    if let Some(ctx) = ev.ctx {
        ctx.audited.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    insert(&mut **tx, ev, &bounded(ev), &ev.detail).await
}

/// Identical `denied`/`rejected` events from the same user within this many
/// seconds of the first one are collapsed into it (see [`collapse`]).
pub const COLLAPSE_WINDOW_SECS: i64 = 300;

/// Collapse a repeated denied/rejected event into the newest matching row
/// (same user, action, outcome, the three id columns, the `detail` without its client-derived counters (`requested`, `distinct`),
/// `source_ip` and `user_role`) whose first occurrence is within [`COLLAPSE_WINDOW_SECS`]. Only
/// `repeat_count` and `last_occurred_at` change; the row keeps the first
/// request's `request_id`, `source_ip` and `detail`. Returns whether a row was
/// updated. Not atomic with the insert that follows a miss: a race yields at
/// worst two rows.
async fn collapse(pool: &PgPool, ev: &NewAuditEvent<'_>, ids: &BoundedIds, detail: &Value) -> Result<bool> {
    if !matches!(ev.outcome, "denied" | "rejected") {
        return Ok(false);
    }
    let n = sqlx::query(
        "UPDATE audit_events SET repeat_count = repeat_count + 1, \
             last_occurred_at = GREATEST(NOW(), COALESCE(last_occurred_at, occurred_at)) \
         WHERE id = (SELECT id FROM audit_events \
                      WHERE user_id = $1 AND action = $2 AND outcome = $3 \
                        AND asset_id IS NOT DISTINCT FROM $4::text \
                        AND checklist_id IS NOT DISTINCT FROM $5::text \
                        AND stig_id IS NOT DISTINCT FROM $6::text \
                        AND (detail - 'requested' - 'distinct') IS NOT DISTINCT FROM ($7::jsonb - 'requested' - 'distinct') \
                        AND source_ip IS NOT DISTINCT FROM $9::text \
                        AND user_role IS NOT DISTINCT FROM $10::text \
                        AND occurred_at > NOW() - make_interval(secs => $8) \
                      ORDER BY id DESC LIMIT 1)",
    )
    .bind(ev.user_id)
    .bind(ev.action)
    .bind(ev.outcome)
    .bind(&ids.asset_id)
    .bind(&ids.checklist_id)
    .bind(&ids.stig_id)
    .bind(detail.to_string())
    .bind(COLLAPSE_WINDOW_SECS as f64)
    .bind(ev.ctx.and_then(|c| c.source_ip.as_deref()))
    .bind(ev.ctx.map(|c| bound_id(&c.role)))
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

#[cfg(test)]
async fn record_event(pool: &PgPool, ev: &NewAuditEvent<'_>) -> Result<()> {
    insert(pool, ev, &bounded(ev), &ev.detail).await
}

/// Record an event without ever failing the caller. The request has already
/// been (or is about to be) answered, so a failure is logged at error level
/// and otherwise ignored; the structured `tracing` line stays as the fallback
/// record. If the insert fails, it is retried once with the same columns and a
/// constant `detail`, so no content-dependent failure (for example text that
/// jsonb rejects) can suppress the row. Both attempts share [`WRITE_TIMEOUT`].
pub async fn record_or_log(pool: &PgPool, ev: NewAuditEvent<'_>) {
    debug_assert!(ev.action.len() <= 64 && ev.outcome.len() <= 64);
    if let Some(ctx) = ev.ctx {
        ctx.audited.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let ids = bounded(&ev);
    let attempt = async {
        match collapse(pool, &ev, &ids, &ev.detail).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => tracing::warn!(target: "audit", action = ev.action, "audit event collapse failed, inserting: {e:#}"),
        }
        if let Err(first) = insert(pool, &ev, &ids, &ev.detail).await {
            tracing::warn!(target: "audit", action = ev.action, "audit event insert failed, retrying without detail: {first:#}");
            insert(pool, &ev, &ids, &json!({ "detailDropped": true })).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let failure = match tokio::time::timeout(WRITE_TIMEOUT, attempt).await {
        Ok(Ok(())) => return,
        Ok(Err(e)) => format!("{e:#}"),
        Err(_) => format!("timed out after {WRITE_TIMEOUT:?}"),
    };
    // Ids only: enough to reconstruct the record, no detail content.
    tracing::error!(
        target: "audit",
        user_id = ev.user_id,
        action = ev.action,
        outcome = ev.outcome,
        request_id = ev.ctx.map(|c| c.request_id.as_str()),
        asset_id = ids.asset_id.as_deref(),
        checklist_id = ids.checklist_id.as_deref(),
        stig_id = ids.stig_id.as_deref(),
        "failed to write audit event: {failure}"
    );
}

/// A rule id made safe for an audit `detail`: truncated to 64 characters and
/// every character outside ASCII alphanumerics and `._:-` replaced by `?`
/// (so NUL, quotes, backslashes and control characters never reach jsonb).
pub fn audit_safe_id(id: &str) -> String {
    sanitize(id, 64)
}

/// `rejected` / `rejectedTruncated` detail fields from per-rule `(rule id,
/// reason)` pairs. Rule ids are passed through [`audit_safe_id`].
pub fn rejected_detail(rejected: &[(String, String)]) -> (Value, bool) {
    let listed: Vec<Value> = rejected
        .iter()
        .take(MAX_REJECTED_LISTED)
        .map(|(rule_id, reason)| json!({ "ruleId": audit_safe_id(rule_id), "reason": reason }))
        .collect();
    (Value::Array(listed), rejected.len() > MAX_REJECTED_LISTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::seed_user;

    /// Run one statement in a transaction with the given audit maintenance mode.
    async fn in_mode(pool: &PgPool, mode: &str, sql: &str) -> Result<()> {
        let mut tx = pool.begin().await?;
        set_maintenance(&mut tx, mode).await?;
        sqlx::query(sql).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    fn is_guard_error(e: &anyhow::Error) -> bool {
        e.downcast_ref::<sqlx::Error>()
            .and_then(|e| e.as_database_error())
            .and_then(|d| d.code())
            .is_some_and(|c| c == "42501")
    }

    async fn seed_both(pool: &PgPool) {
        sqlx::query("INSERT INTO users (id, display_name, email, role, sub, provider) VALUES ('u1', 'u1', '', 'author', 'u1', 'test') ON CONFLICT DO NOTHING")
            .execute(pool).await.unwrap();
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r','status')")
            .execute(pool).await.unwrap();
        sqlx::query("INSERT INTO audit_events (user_id, action, outcome) VALUES ('u1','checklist.save','ok')")
            .execute(pool).await.unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn guard_rejects_plain_mutation_of_both_tables(pool: PgPool) {
        seed_both(&pool).await;
        for t in ["rule_audit", "audit_events"] {
            for sql in [
                format!("UPDATE {t} SET user_id = user_id"),
                format!("DELETE FROM {t}"),
                format!("TRUNCATE {t}"),
            ] {
                let e = sqlx::query(&sql).execute(&pool).await.unwrap_err();
                assert_eq!(e.as_database_error().and_then(|d| d.code()).as_deref(), Some("42501"), "{sql}");
            }
        }
        let e = sqlx::query("TRUNCATE users CASCADE").execute(&pool).await.unwrap_err();
        assert_eq!(e.as_database_error().and_then(|d| d.code()).as_deref(), Some("42501"));
        let n: i64 = sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM rule_audit) + (SELECT COUNT(*) FROM audit_events)")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(n, 2);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn guard_modes_allow_only_their_operations(pool: PgPool) {
        seed_both(&pool).await;
        // retention: DELETE only.
        assert!(is_guard_error(&in_mode(&pool, "retention", "UPDATE rule_audit SET field = 'x'").await.unwrap_err()));
        assert!(is_guard_error(&in_mode(&pool, "retention", "TRUNCATE rule_audit").await.unwrap_err()));
        // test: UPDATE and TRUNCATE, not DELETE.
        in_mode(&pool, "test", "UPDATE rule_audit SET field = 'x'").await.unwrap();
        assert!(is_guard_error(&in_mode(&pool, "test", "DELETE FROM rule_audit").await.unwrap_err()));
        // An unknown mode permits nothing.
        assert!(is_guard_error(&in_mode(&pool, "bogus", "DELETE FROM audit_events").await.unwrap_err()));
        in_mode(&pool, "retention", "DELETE FROM rule_audit").await.unwrap();
        in_mode(&pool, "retention", "DELETE FROM audit_events").await.unwrap();
        // The mode is transaction-local: it does not leak to the next statement.
        let e = sqlx::query("DELETE FROM audit_events").execute(&pool).await;
        assert!(e.is_ok(), "no rows left, so nothing to guard");
        seed_both(&pool).await;
        let e = sqlx::query("DELETE FROM audit_events").execute(&pool).await.unwrap_err();
        assert!(e.as_database_error().is_some());
        // restore: TRUNCATE (cascading from users) only; DELETE is rejected.
        seed_both(&pool).await;
        assert!(is_guard_error(&in_mode(&pool, "restore", "DELETE FROM rule_audit").await.unwrap_err()));
        in_mode(&pool, "restore", "TRUNCATE users CASCADE").await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM rule_audit) + (SELECT COUNT(*) FROM audit_events)")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(n, 0);
        seed_both(&pool).await;
        in_mode(&pool, "test", "TRUNCATE users CASCADE").await.unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn guard_allows_only_the_collapse_update_without_a_mode(pool: PgPool) {
        seed_both(&pool).await;
        let code = |e: sqlx::Error| e.as_database_error().and_then(|d| d.code().map(|c| c.to_string()));
        // An `ok` row has no collapse shape.
        let e = sqlx::query("UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NOW()")
            .execute(&pool).await.unwrap_err();
        assert_eq!(code(e).as_deref(), Some("42501"));
        in_mode(&pool, "test", "UPDATE audit_events SET outcome = 'denied'").await.unwrap();
        // The collapse shape on a denied row passes without any mode.
        sqlx::query("UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NOW()")
            .execute(&pool).await.unwrap();
        // Rejected: another column too, an outcome change, a jump over 1, a
        // decrease, no change, a past or future or infinite timestamp.
        for sql in [
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NOW(), action = 'x'",
            "UPDATE audit_events SET outcome = 'ok'",
            "UPDATE audit_events SET repeat_count = repeat_count + 2, last_occurred_at = NOW()",
            "UPDATE audit_events SET repeat_count = 1, last_occurred_at = NOW()",
            "UPDATE audit_events SET repeat_count = repeat_count, last_occurred_at = NOW()",
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NOW() - INTERVAL '1 day'",
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NOW() + INTERVAL '1 day'",
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = 'infinity'",
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NULL",
        ] {
            let e = sqlx::query(sql).execute(&pool).await.unwrap_err();
            assert_eq!(code(e).as_deref(), Some("42501"), "{sql}");
        }
        // rule_audit has no collapse shape.
        let e = sqlx::query("UPDATE rule_audit SET field = 'x'").execute(&pool).await.unwrap_err();
        assert_eq!(code(e).as_deref(), Some("42501"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn guard_triggers_are_always_enabled_and_migration_mode_allows_update_only(pool: PgPool) {
        seed_both(&pool).await;
        let enabled: Vec<(String, String)> = sqlx::query_as(
            "SELECT tgname::text, tgenabled::text FROM pg_trigger WHERE tgname LIKE '%\\_guard\\_%' ORDER BY tgname",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(enabled.len(), 4);
        assert!(enabled.iter().all(|(_, e)| e == "A"), "{enabled:?}");
        in_mode(&pool, "migration", "UPDATE rule_audit SET field = 'y'").await.unwrap();
        assert!(is_guard_error(&in_mode(&pool, "migration", "DELETE FROM rule_audit").await.unwrap_err()));
        assert!(is_guard_error(&in_mode(&pool, "migration", "TRUNCATE rule_audit").await.unwrap_err()));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn collapse_onto_a_row_whose_last_occurrence_is_slightly_in_the_future_still_collapses(pool: PgPool) {
        seed_user(&pool, "u1").await;
        record_or_log(&pool, ev("denied", json!({ "reason": "a" }))).await;
        in_mode(&pool, "test", "UPDATE audit_events SET last_occurred_at = NOW() + INTERVAL '30 seconds'").await.unwrap();
        record_or_log(&pool, ev("denied", json!({ "reason": "a" }))).await;
        let got = rows(&pool).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, 2);
    }

    fn ev(outcome: &'static str, detail: Value) -> NewAuditEvent<'static> {
        NewAuditEvent {
            user_id: "u1",
            action: "checklist.save",
            outcome,
            asset_id: Some("a1"),
            checklist_id: None,
            stig_id: None,
            detail,
            ctx: None,
        }
    }

    #[test]
    fn rejected_detail_caps_the_list() {
        let many: Vec<(String, String)> =
            (0..150).map(|i| (format!("r{i}"), "why".to_string())).collect();
        let (listed, truncated) = rejected_detail(&many);
        assert_eq!(listed.as_array().unwrap().len(), MAX_REJECTED_LISTED);
        assert!(truncated);
        let (listed, truncated) = rejected_detail(&many[..100]);
        assert_eq!(listed.as_array().unwrap().len(), 100);
        assert!(!truncated);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn records_one_row_per_outcome(pool: PgPool) {
        seed_user(&pool, "u1").await;
        for outcome in ["ok", "partial", "denied", "rejected"] {
            record_event(&pool, &ev(outcome, json!({ "n": 1 }))).await.unwrap();
        }
        let got: Vec<(String, String, Option<String>)> =
            sqlx::query_as("SELECT outcome, detail->>'n', asset_id FROM audit_events ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        let outcomes: Vec<&str> = got.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(outcomes, ["ok", "partial", "denied", "rejected"]);
        assert!(got.iter().all(|r| r.1 == "1" && r.2.as_deref() == Some("a1")));
    }

    async fn rows(pool: &PgPool) -> Vec<(String, i32, bool, Option<String>)> {
        sqlx::query_as(
            "SELECT outcome, repeat_count, last_occurred_at IS NOT NULL, request_id FROM audit_events ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn identical_denials_collapse_and_keep_the_first_context(pool: PgPool) {
        seed_user(&pool, "u1").await;
        for i in 0..5 {
            let mut c = ctx();
            c.request_id = format!("req-{i}");
            let mut e = ev("denied", json!({ "reason": "not_owner" }));
            e.ctx = Some(&c);
            record_or_log(&pool, e).await;
        }
        let got = rows(&pool).await;
        assert_eq!(got, vec![("denied".to_string(), 5, true, Some("req-0".to_string()))]);
        // Only repeat_count and last_occurred_at move: detail is untouched.
        let d: String = sqlx::query_scalar("SELECT detail::text FROM audit_events").fetch_one(&pool).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&d).unwrap(), json!({ "reason": "not_owner" }));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_different_reason_asset_user_or_a_late_repeat_is_a_new_row(pool: PgPool) {
        seed_user(&pool, "u1").await;
        seed_user(&pool, "u2").await;
        record_or_log(&pool, ev("rejected", json!({ "reason": "a" }))).await;
        record_or_log(&pool, ev("rejected", json!({ "reason": "b" }))).await;
        let mut other_asset = ev("rejected", json!({ "reason": "a" }));
        other_asset.asset_id = Some("a2");
        record_or_log(&pool, other_asset).await;
        let mut other_user = ev("rejected", json!({ "reason": "a" }));
        other_user.user_id = "u2";
        record_or_log(&pool, other_user).await;
        let mut other_action = ev("rejected", json!({ "reason": "a" }));
        other_action.action = "checklist.create";
        record_or_log(&pool, other_action).await;
        assert_eq!(rows(&pool).await.len(), 5);

        // Age the first row past the window: the next identical event inserts.
        in_mode(&pool, "test", "UPDATE audit_events SET occurred_at = NOW() - INTERVAL '6 minutes' WHERE id = (SELECT MIN(id) FROM audit_events)")
            .await
            .unwrap();
        record_or_log(&pool, ev("rejected", json!({ "reason": "a" }))).await;
        let got = rows(&pool).await;
        assert_eq!(got.len(), 6);
        assert!(got.iter().all(|r| r.1 == 1));
    }

    fn ctx_with(ip: &str, role: &str) -> RequestCtx {
        RequestCtx { source_ip: Some(ip.into()), role: role.into(), ..ctx() }
    }

    async fn denied_authz(pool: &PgPool, c: &RequestCtx, method: &str, route: &str) {
        let mut e = ev("denied", json!({ "method": method, "route": route }));
        e.action = "authz.denied";
        e.asset_id = None;
        e.ctx = Some(c);
        record_or_log(pool, e).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn only_exact_repeats_collapse(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let c = ctx_with("203.0.113.7", "author");
        denied_authz(&pool, &c, "POST", "/api/a").await;
        denied_authz(&pool, &c, "POST", "/api/b").await; // other route
        denied_authz(&pool, &c, "PUT", "/api/a").await; // other method
        denied_authz(&pool, &ctx_with("203.0.113.8", "author"), "POST", "/api/a").await; // other ip
        denied_authz(&pool, &ctx_with("203.0.113.7", "viewer"), "POST", "/api/a").await; // other role
        assert_eq!(rows(&pool).await.len(), 5);
        // An exact repeat with a different request id collapses; the first id is kept.
        let mut again = ctx_with("203.0.113.7", "author");
        again.request_id = "req-other".into();
        denied_authz(&pool, &again, "POST", "/api/a").await;
        let got = rows(&pool).await;
        assert_eq!(got.len(), 5);
        assert_eq!(got[0], ("denied".to_string(), 2, true, Some("req-1".to_string())));
        assert!(got[1..].iter().all(|r| r.1 == 1));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn client_derived_counters_do_not_split_the_key_but_reason_and_dry_run_do(pool: PgPool) {
        seed_user(&pool, "u1").await;
        for n in [1, 50, 9000] {
            record_or_log(&pool, ev("rejected", json!({ "reason": "too_many_rules", "requested": n }))).await;
        }
        assert_eq!(rows(&pool).await.len(), 1);
        record_or_log(&pool, ev("rejected", json!({ "reason": "other", "requested": 1 }))).await;
        record_or_log(&pool, ev("rejected", json!({ "reason": "too_many_rules", "dryRun": true, "requested": 1 }))).await;
        record_or_log(&pool, ev("rejected", json!({ "reason": "too_many_rules", "dryRun": false, "requested": 1 }))).await;
        let got = rows(&pool).await;
        assert_eq!(got.len(), 4);
        assert_eq!(got[0].1, 3);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_window_boundary_is_five_minutes(pool: PgPool) {
        seed_user(&pool, "u1").await;
        record_or_log(&pool, ev("denied", json!({ "reason": "a" }))).await;
        let age = |secs: i32| {
            let pool = pool.clone();
            async move {
                in_mode(&pool, "test", &format!("UPDATE audit_events SET occurred_at = NOW() - make_interval(secs => {secs})")).await
            }
        };
        age(299).await.unwrap(); // 4m59s: still inside
        record_or_log(&pool, ev("denied", json!({ "reason": "a" }))).await;
        assert_eq!(rows(&pool).await.len(), 1);
        age(301).await.unwrap(); // 5m01s: outside
        record_or_log(&pool, ev("denied", json!({ "reason": "a" }))).await;
        assert_eq!(rows(&pool).await.len(), 2);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn ok_and_partial_events_are_never_collapsed(pool: PgPool) {
        seed_user(&pool, "u1").await;
        for outcome in ["ok", "ok", "partial", "partial"] {
            record_or_log(&pool, ev(outcome, json!({ "n": 1 }))).await;
        }
        let got = rows(&pool).await;
        assert_eq!(got.len(), 4);
        assert!(got.iter().all(|r| r.1 == 1 && !r.2));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn record_or_log_swallows_an_insert_failure(pool: PgPool) {
        // No such user: the FK rejects the insert. The helper must not panic
        // or propagate, and nothing is written.
        record_or_log(&pool, ev("ok", json!({}))).await;
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(record_event(&pool, &ev("ok", json!({}))).await.is_err());
    }

    #[test]
    fn audit_safe_id_replaces_unsafe_characters_and_truncates() {
        assert_eq!(audit_safe_id("SV-1r1_rule.x:y"), "SV-1r1_rule.x:y");
        assert_eq!(audit_safe_id("a\u{0}b\"c\\d é"), "a?b?c?d??");
        assert_eq!(audit_safe_id(&"x".repeat(300)).len(), 64);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_detail_jsonb_rejects_is_retried_as_detail_dropped(pool: PgPool) {
        seed_user(&pool, "u1").await;
        // A NUL escape makes the jsonb cast fail on the first attempt.
        record_or_log(&pool, ev("ok", json!({ "ruleId": "a\u{0}b" }))).await;
        let got: Vec<(String, String)> =
            sqlx::query_as("SELECT outcome, detail::text FROM audit_events")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "ok");
        let d: Value = serde_json::from_str(&got[0].1).unwrap();
        assert_eq!(d, json!({ "detailDropped": true }));
    }

    #[test]
    fn bound_id_caps_and_sanitises() {
        assert_eq!(bound_id("abc-1.2_3:4"), "abc-1.2_3:4");
        assert_eq!(bound_id(&"a".repeat(100_000)).len(), MAX_ID_CHARS);
        assert_eq!(bound_id("a\u{0}b\"c"), "a?b?c");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn id_columns_are_bounded_on_insert(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let mut e = ev("denied", json!({}));
        let huge = "z".repeat(100_000);
        e.stig_id = Some(&huge);
        e.checklist_id = Some(&huge);
        record_or_log(&pool, e).await;
        let (a, b): (i32, i32) =
            sqlx::query_as("SELECT LENGTH(stig_id), LENGTH(checklist_id) FROM audit_events")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((a as usize, b as usize), (MAX_ID_CHARS, MAX_ID_CHARS));
    }

    fn ctx() -> RequestCtx {
        RequestCtx {
            request_id: "req-1".into(),
            source_ip: Some("203.0.113.7".into()),
            role: "author".into(),
            audited: Default::default(),
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn request_context_columns_are_written_and_audited_is_set(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let c = ctx();
        let mut e = ev("ok", json!({}));
        e.ctx = Some(&c);
        record_or_log(&pool, e).await;
        assert!(c.audited.load(std::sync::atomic::Ordering::Relaxed));
        let got: (Option<String>, Option<String>, Option<String>) =
            sqlx::query_as("SELECT source_ip, request_id, user_role FROM audit_events")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(got, (Some("203.0.113.7".into()), Some("req-1".into()), Some("author".into())));

        // No context: the columns stay NULL.
        record_or_log(&pool, ev("ok", json!({}))).await;
        let nulls: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE source_ip IS NULL AND request_id IS NULL AND user_role IS NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(nulls, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_detail_dropped_retry_keeps_the_context(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let c = ctx();
        let mut e = ev("ok", json!({ "ruleId": "a\u{0}b" }));
        e.ctx = Some(&c);
        record_or_log(&pool, e).await;
        let got: (String, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT detail::text, source_ip, request_id, user_role FROM audit_events",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&got.0).unwrap(), json!({ "detailDropped": true }));
        assert_eq!((got.1.as_deref(), got.2.as_deref(), got.3.as_deref()), (Some("203.0.113.7"), Some("req-1"), Some("author")));
    }
}
