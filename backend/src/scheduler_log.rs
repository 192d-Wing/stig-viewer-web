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
//!
//! # Test-only failure injection
//!
//! `inject_failure(name)` arms a one-shot flag for a specific scheduler
//! name. The next `record()` call for that name short-circuits before
//! invoking the closure: it stamps `status='error'`,
//! `message='injected test failure'` on the row and returns an
//! `Err`. The flag is consumed atomically, so a subsequent tick for
//! the same name behaves normally. This exists so the admin job
//! dashboard's error path can be exercised by E2E — nothing in the
//! real system errors on demand. The endpoint that arms the flag is
//! gated by `STIG_ENV != "production"` at registration time in
//! `main.rs`.

use std::collections::HashSet;
use std::fmt::Display;
use std::future::Future;
use std::sync::{LazyLock, Mutex};

use anyhow::{anyhow, Result};
use sqlx::PgPool;

/// Names of schedulers with a pending one-shot failure injection.
/// Populated by `inject_failure`, drained by `consume_failure`.
static INJECTED_FAILURES: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Arm a one-shot failure for `name`. The next `record()` call with
/// the same name will short-circuit with an error before invoking the
/// closure. Idempotent — calling twice is the same as calling once.
pub fn inject_failure(name: &str) {
    let mut guard = INJECTED_FAILURES
        .lock()
        .expect("INJECTED_FAILURES mutex poisoned");
    guard.insert(name.to_string());
}

/// Atomically check + remove `name` from the pending-failure set.
/// Returns `true` if a failure was armed for this name (and is now
/// consumed).
pub fn consume_failure(name: &str) -> bool {
    let mut guard = INJECTED_FAILURES
        .lock()
        .expect("INJECTED_FAILURES mutex poisoned");
    guard.remove(name)
}

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
///
/// If a test-only failure has been armed for this scheduler name via
/// `inject_failure`, the closure is NOT invoked: the row is stamped
/// `error`/`injected test failure` and an `Err` is returned.
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

    // Test-only short-circuit. Drains the flag before invoking the
    // closure so a re-run for the same name behaves normally.
    if consume_failure(name) {
        let message = "injected test failure";
        if let Some(id) = row_id {
            let update = sqlx::query(
                "UPDATE scheduler_runs SET status = 'error', message = $1, finished_at = NOW() WHERE id = $2",
            )
            .bind(message)
            .bind(id)
            .execute(pool)
            .await;
            if let Err(e) = update {
                tracing::warn!(
                    "scheduler_log: failed to update row {id} for {name} (injected): {e:#}"
                );
            }
        }
        return Err(anyhow!(message));
    }

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
