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

async fn insert(pool: &PgPool, ev: &NewAuditEvent<'_>, ids: &BoundedIds, detail: &Value) -> Result<()> {
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
