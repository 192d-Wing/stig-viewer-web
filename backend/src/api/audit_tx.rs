//! Audit rows committed in the same transaction as the change they describe.
//!
//! Handlers open a bounded transaction (`crate::db::begin_bounded`), mutate on
//! it, call [`record`] and commit. A failed audit insert returns an error, the
//! caller drops the transaction, and the change rolls back: the request fails
//! closed instead of leaving a change with no record. `denied` / `rejected`
//! events (nothing to bind to) stay on `db_audit::record_or_log`.
//!
//! A failure here is not counted in `failure_counters::AUDIT_WRITES`: that
//! counter is defined as swallowed failures of `record_or_log`, and nothing is
//! swallowed when the request itself fails. It is logged on the `audit` target
//! with the phrase the AU-5 log alert keys on.

use axum::http::StatusCode;
use serde_json::Value;
use sqlx::{Postgres, Transaction};

use crate::api::auth::AuthUser;
use crate::api::request_ctx::RequestCtx;
use crate::db_audit::{self, NewAuditEvent};

/// An `ok` event for `user`; callers set the id columns they need.
pub(crate) fn ok_event<'a>(
    user: &'a AuthUser,
    ctx: &'a RequestCtx,
    action: &'static str,
    detail: Value,
) -> NewAuditEvent<'a> {
    NewAuditEvent {
        user_id: &user.id,
        action,
        outcome: "ok",
        asset_id: None,
        checklist_id: None,
        stig_id: None,
        detail,
        ctx: Some(ctx),
    }
}

/// Insert `ev` on the caller's transaction. On failure the error is logged
/// and returned; the caller must drop the transaction without committing.
pub(crate) async fn record(
    tx: &mut Transaction<'_, Postgres>,
    ev: &NewAuditEvent<'_>,
) -> anyhow::Result<()> {
    if let Err(e) = db_audit::record_in_tx(tx, ev).await {
        tracing::error!(
            target: "audit",
            action = ev.action,
            user_id = ev.user_id,
            request_id = ev.ctx.map(|c| c.request_id.as_str()),
            "failed to write audit event: the change was rolled back: {e:#}"
        );
        return Err(e);
    }
    Ok(())
}

/// Status for a failed transactional write: 503 when Postgres cut it short
/// (statement or lock timeout), else 500.
pub(crate) fn failed(e: anyhow::Error) -> StatusCode {
    if crate::db::is_timeout(&e) {
        tracing::warn!("audited write timed out: {e:#}");
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        tracing::error!("audited write failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{auth, ctx, fail_audit_inserts, seed_user};
    use sqlx::PgPool;

    async fn count(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE action = 'test.audit_tx'")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn record_writes_the_row_on_the_callers_transaction_and_rolls_back_with_it(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let (user, ctx) = (auth("u1", "author"), ctx());
        let ev = ok_event(&user, &ctx, "test.audit_tx", serde_json::json!({ "n": 1 }));

        let mut tx = crate::db::begin_bounded(&pool).await.unwrap();
        record(&mut tx, &ev).await.unwrap();
        assert_eq!(count(&pool).await, 0, "invisible before commit");
        tx.rollback().await.unwrap();
        assert_eq!(count(&pool).await, 0);

        let mut tx = crate::db::begin_bounded(&pool).await.unwrap();
        record(&mut tx, &ev).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(count(&pool).await, 1);
        let (outcome, request_id): (String, Option<String>) = sqlx::query_as(
            "SELECT outcome, request_id FROM audit_events WHERE action = 'test.audit_tx'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(outcome, "ok");
        assert_eq!(request_id.as_deref(), Some("test-request"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_insert_is_returned_and_logged_on_the_audit_target(pool: PgPool) {
        seed_user(&pool, "u1").await;
        fail_audit_inserts(&pool, &["test.audit_tx"]).await;
        let (user, ctx) = (auth("u1", "author"), ctx());
        let ev = ok_event(&user, &ctx, "test.audit_tx", serde_json::json!({}));
        let (cap, _g) = crate::api::audit_capture::capture();
        let mut tx = crate::db::begin_bounded(&pool).await.unwrap();
        assert!(record(&mut tx, &ev).await.is_err());
        drop(tx);
        let line = cap.take_one();
        assert_eq!(
            line.get("action").map(String::as_str),
            Some("test.audit_tx")
        );
        assert_eq!(line.get("user_id").map(String::as_str), Some("u1"));
        assert_eq!(
            line.get("request_id").map(String::as_str),
            Some("test-request")
        );
        assert!(
            line["message"].starts_with("failed to write audit event"),
            "{line:?}"
        );
    }

    #[test]
    fn a_plain_error_maps_to_500() {
        assert_eq!(
            failed(anyhow::anyhow!("boom")),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
