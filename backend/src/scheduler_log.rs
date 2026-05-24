//! Wrap a scheduler tick so its run state is persisted in
//! `scheduler_runs`.
//!
//! Each periodic background task in `main.rs` (DISA sync, dashboard
//! snapshot, overdue digest, audit retention, compliance report) used
//! to log its outcome via `tracing` and nothing else. `record()` lets
//! the call site keep the same closure body, while transparently
//! inserting a `status='running'` row at the start and updating it to
//! `ok` or `error` (with a message) when the closure returns.
//!
//! The closure's `Result` is returned unchanged so existing tracing
//! and metrics in the call site keep working.

use std::fmt::Display;
use std::future::Future;

use anyhow::Result;
use sqlx::PgPool;

/// Wrap an async closure with start/finish bookkeeping in
/// `scheduler_runs`. The returned `Result` is the closure's, unchanged.
///
/// * `ok` rows carry the closure's success value formatted via
///   `Display` so callers can include a count (e.g. "pruned 42 rows").
/// * `error` rows carry the full error chain (`{e:#}`) so ops can
///   diagnose without scraping logs.
///
/// If we can't insert the initial row (DB hiccup), we still run the
/// closure — the scheduler is more important than its bookkeeping. The
/// failure is logged at WARN.
pub async fn record<F, Fut, T>(pool: &PgPool, name: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
    T: Display,
{
    // Insert the running marker. On insert failure we proceed without
    // an id — the closure still runs and the operator just won't see
    // this tick in the dashboard.
    let row_id: Option<i64> = match sqlx::query_scalar::<_, i64>(
        "INSERT INTO scheduler_runs (name, status) VALUES ($1, 'running') RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::warn!("scheduler_log: failed to insert running row for {name}: {e:#}");
            None
        }
    };

    let result = f().await;

    if let Some(id) = row_id {
        let (status, message) = match &result {
            Ok(value) => ("ok", value.to_string()),
            Err(err) => ("error", format!("{err:#}")),
        };
        let update = sqlx::query(
            "UPDATE scheduler_runs SET status = $1, message = $2, finished_at = NOW() WHERE id = $3",
        )
        .bind(status)
        .bind(&message)
        .bind(id)
        .execute(pool)
        .await;
        if let Err(e) = update {
            tracing::warn!("scheduler_log: failed to update row {id} for {name}: {e:#}");
        }
    }

    result
}
