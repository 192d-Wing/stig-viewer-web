//! Background prune of the `rule_audit` table.
//!
//! `rule_audit` is append-only (one row per per-rule field change), so
//! left unattended it grows unbounded. This module trims rows older
//! than `retain_days` and, optionally, archives them as JSONL on disk
//! before deletion. Mirrors the scheduler pattern used elsewhere
//! (`sync`, dashboard snapshots, overdue digest) — a 4th `tokio::spawn`
//! loop in `main.rs` drives it on a configurable interval.
//!
//! The archive layout is one file per UTC day of `occurred_at`, written
//! in append mode at `${data_dir}/audit_archive/YYYY-MM-DD.jsonl`. This
//! keeps individual files small enough to grep and lets ops compress /
//! ship the directory wholesale without coordinating with the app.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use tokio::{
    fs,
    io::AsyncWriteExt,
};

/// One `rule_audit` row, shaped for JSONL archival. Matches the table
/// columns 1:1 — we deliberately do not denormalize user/asset names
/// here because the live view (`/api/activity`, rule history) already
/// joins those in, and the archive should be a faithful raw record.
#[derive(Debug, Serialize, sqlx::FromRow)]
struct AuditRow {
    id: i64,
    occurred_at: DateTime<Utc>,
    user_id: String,
    checklist_id: String,
    rule_id: String,
    field: String,
    from_value: Option<String>,
    to_value: Option<String>,
}

/// Prune `rule_audit` rows older than `retain_days`. When `archive` is
/// true, each pruned row is appended as a JSON line to a per-UTC-day
/// file under `${data_dir}/audit_archive/`. Returns the number of rows
/// deleted from the database.
///
/// The fetch + delete pair is not strictly transactional — between
/// SELECT and DELETE a concurrent writer could insert a new row that
/// also happens to fall before the cutoff. That's fine: such a row
/// will be archived on the next sweep. We intentionally pin the
/// DELETE to the exact id set we just read so we never delete a row
/// we didn't archive.
pub async fn run_prune(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
) -> Result<usize> {
    // Build the cutoff in Rust rather than embedding `retain_days` in
    // SQL — Postgres rejects negative INTERVAL composed via string
    // concat in some setups, and this is easier to reason about.
    let rows: Vec<AuditRow> = sqlx::query_as::<_, AuditRow>(
        r#"
        SELECT id, occurred_at, user_id, checklist_id, rule_id, field, from_value, to_value
        FROM rule_audit
        WHERE occurred_at < NOW() - ($1 || ' days')::INTERVAL
        ORDER BY id ASC
        "#,
    )
    .bind(retain_days.to_string())
    .fetch_all(pool)
    .await
    .context("select expired rule_audit rows")?;

    if rows.is_empty() {
        return Ok(0);
    }

    if archive {
        write_archive(data_dir, &rows)
            .await
            .context("write audit archive jsonl")?;
    }

    let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
    let deleted = sqlx::query("DELETE FROM rule_audit WHERE id = ANY($1::bigint[])")
        .bind(&ids)
        .execute(pool)
        .await
        .context("delete pruned rule_audit rows")?
        .rows_affected();

    Ok(deleted as usize)
}

/// One `audit_events` row, shaped for JSONL archival (raw columns).
#[derive(Debug, Serialize, sqlx::FromRow)]
struct EventRow {
    id: i64,
    occurred_at: DateTime<Utc>,
    user_id: String,
    action: String,
    outcome: String,
    asset_id: Option<String>,
    checklist_id: Option<String>,
    stig_id: Option<String>,
    source_ip: Option<String>,
    request_id: Option<String>,
    user_role: Option<String>,
    repeat_count: i32,
    last_occurred_at: Option<DateTime<Utc>>,
    /// `detail::text`, re-parsed into JSON when archived.
    detail: String,
}

/// Rows per select/archive/delete round of [`run_prune_events`].
const EVENT_PRUNE_BATCH: i64 = 5_000;

/// Same as [`run_prune`] for `audit_events` (same cutoff, same id-pinned
/// delete), but in bounded batches: any user with write access can create
/// rows, so a sweep must not load them all at once. Each batch is archived
/// before it is deleted. Archived to
/// `${data_dir}/audit_archive/events-YYYY-MM-DD.jsonl`.
pub async fn run_prune_events(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
) -> Result<usize> {
    run_prune_events_batched(pool, data_dir, retain_days, archive, EVENT_PRUNE_BATCH).await
}

async fn run_prune_events_batched(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    batch: i64,
) -> Result<usize> {
    let mut total = 0usize;
    loop {
        let rows: Vec<EventRow> = sqlx::query_as::<_, EventRow>(
            r#"
            SELECT id, occurred_at, user_id, action, outcome, asset_id, checklist_id, stig_id,
                   source_ip, request_id, user_role, repeat_count, last_occurred_at,
                   detail::text AS detail
            FROM audit_events
            WHERE occurred_at < NOW() - ($1 || ' days')::INTERVAL
              AND (last_occurred_at IS NULL OR last_occurred_at < NOW() - ($1 || ' days')::INTERVAL)
            ORDER BY id ASC
            LIMIT $2
            "#,
        )
        .bind(retain_days.to_string())
        .bind(batch)
        .fetch_all(pool)
        .await
        .context("select expired audit_events rows")?;

        if rows.is_empty() {
            return Ok(total);
        }

        if archive {
            write_event_archive(data_dir, &rows)
                .await
                .context("write audit events archive jsonl")?;
        }

        let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
        let deleted = sqlx::query("DELETE FROM audit_events WHERE id = ANY($1::bigint[])")
            .bind(&ids)
            .execute(pool)
            .await
            .context("delete pruned audit_events rows")?
            .rows_affected() as usize;
        total += deleted;
        if deleted == 0 || (rows.len() as i64) < batch {
            return Ok(total);
        }
    }
}

/// The scheduled audit retention body: prune `rule_audit` and `audit_events`
/// independently, so a failure in one never skips the other. Returns the
/// summary line; an error (naming both results) if either prune failed.
pub async fn run_scheduled(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
) -> Result<String> {
    let rules = run_prune(pool, data_dir, retain_days, archive).await;
    let events = run_prune_events(pool, data_dir, retain_days, archive).await;
    match (rules, events) {
        (Ok(n), Ok(e)) => Ok(format!(
            "pruned {n} rows and {e} events (retain_days={retain_days}, archive={archive})"
        )),
        (r, e) => {
            let show = |x: Result<usize>| match x {
                Ok(n) => format!("pruned {n}"),
                Err(err) => format!("failed: {err:#}"),
            };
            anyhow::bail!("audit retention: rule_audit {}; audit_events {}", show(r), show(e))
        }
    }
}

async fn write_event_archive(data_dir: &Path, rows: &[EventRow]) -> Result<()> {
    let dir = data_dir.join("audit_archive");
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create archive dir {}", dir.display()))?;

    use std::collections::BTreeMap;
    let mut by_date: BTreeMap<String, Vec<&EventRow>> = BTreeMap::new();
    for row in rows {
        by_date
            .entry(row.occurred_at.format("%Y-%m-%d").to_string())
            .or_default()
            .push(row);
    }

    for (date, group) in by_date {
        let path = dir.join(format!("events-{date}.jsonl"));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("open archive file {}", path.display()))?;
        for row in group {
            let detail: serde_json::Value =
                serde_json::from_str(&row.detail).unwrap_or(serde_json::Value::Null);
            let line = serde_json::to_string(&serde_json::json!({
                "id": row.id,
                "occurred_at": row.occurred_at,
                "user_id": row.user_id,
                "action": row.action,
                "outcome": row.outcome,
                "asset_id": row.asset_id,
                "checklist_id": row.checklist_id,
                "stig_id": row.stig_id,
                "source_ip": row.source_ip,
                "request_id": row.request_id,
                "user_role": row.user_role,
                "repeat_count": row.repeat_count,
                "last_occurred_at": row.last_occurred_at,
                "detail": detail,
            }))
            .context("serialize audit event")?;
            file.write_all(line.as_bytes()).await?;
            file.write_all(b"\n").await?;
        }
        file.flush().await?;
    }

    Ok(())
}

/// Append each row to `${data_dir}/audit_archive/<UTC-date>.jsonl`.
/// One file is opened per distinct date to keep handle count bounded
/// even on a big sweep. Files are opened with create+append so reruns
/// (or concurrent prunes for distinct date sets) append cleanly.
async fn write_archive(data_dir: &Path, rows: &[AuditRow]) -> Result<()> {
    let dir = data_dir.join("audit_archive");
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create archive dir {}", dir.display()))?;

    // Group by UTC date so we open each file at most once per sweep.
    // Rows are already ordered by id ASC, but `occurred_at` can be
    // out-of-order vs id (backdate test endpoints, clock skew), so
    // we group explicitly rather than rely on input ordering.
    use std::collections::BTreeMap;
    let mut by_date: BTreeMap<String, Vec<&AuditRow>> = BTreeMap::new();
    for row in rows {
        let date = row.occurred_at.format("%Y-%m-%d").to_string();
        by_date.entry(date).or_default().push(row);
    }

    for (date, group) in by_date {
        let path = dir.join(format!("{date}.jsonl"));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("open archive file {}", path.display()))?;
        for row in group {
            let line = serde_json::to_string(row).context("serialize audit row")?;
            file.write_all(line.as_bytes()).await?;
            file.write_all(b"\n").await?;
        }
        file.flush().await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::seed_user;

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_events_keys_on_the_last_repeat_and_archives_the_counter(pool: PgPool) {
        seed_user(&pool, "u1").await;
        // Both rows were first seen 10 days ago; only one was repeated recently.
        for (reason, last) in [("stale", "NOW() - INTERVAL '10 days'"), ("fresh", "NOW()")] {
            sqlx::query(&format!(
                "INSERT INTO audit_events (user_id, action, outcome, occurred_at, last_occurred_at, repeat_count, detail) \
                 VALUES ('u1', 'checklist.save', 'denied', NOW() - INTERVAL '10 days', {last}, 4, $1::jsonb)"
            ))
            .bind(format!("{{\"reason\":\"{reason}\"}}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let n = run_prune_events(&pool, &dir, 5, true).await.unwrap();
        assert_eq!(n, 1);
        let left: Vec<String> = sqlx::query_scalar("SELECT detail->>'reason' FROM audit_events")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(left, ["fresh"]);
        let mut archived = String::new();
        for entry in std::fs::read_dir(dir.join("audit_archive")).unwrap() {
            archived.push_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap());
        }
        let line: serde_json::Value = serde_json::from_str(archived.trim()).unwrap();
        assert_eq!(line["repeat_count"], 4);
        assert!(line["last_occurred_at"].is_string());
        assert_eq!(line["detail"]["reason"], "stale");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_events_deletes_and_archives_only_expired_rows(pool: PgPool) {
        seed_user(&pool, "u1").await;
        for (outcome, days) in [("ok", 400), ("denied", 10)] {
            sqlx::query(
                "INSERT INTO audit_events (user_id, action, outcome, occurred_at, detail) \
                 VALUES ('u1', 'checklist.save', $1, NOW() - ($2 || ' days')::INTERVAL, '{\"k\":1}')",
            )
            .bind(outcome)
            .bind(days.to_string())
            .execute(&pool)
            .await
            .unwrap();
        }
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let n = run_prune_events(&pool, &dir, 365, true).await.unwrap();
        assert_eq!(n, 1);
        let left: Vec<String> = sqlx::query_scalar("SELECT outcome FROM audit_events")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(left, ["denied"]);
        let mut archived = String::new();
        for entry in std::fs::read_dir(dir.join("audit_archive")).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_name().to_string_lossy().starts_with("events-"));
            archived.push_str(&std::fs::read_to_string(entry.path()).unwrap());
        }
        let line: serde_json::Value = serde_json::from_str(archived.trim()).unwrap();
        assert_eq!(line["outcome"], "ok");
        assert_eq!(line["detail"]["k"], 1);
        // Without the archive switch nothing is written.
        let dir2 = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        assert_eq!(run_prune_events(&pool, &dir2, 5, false).await.unwrap(), 1);
        assert!(!dir2.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn seed_expired_event(pool: &PgPool, days: i64) {
        sqlx::query(
            "INSERT INTO audit_events (user_id, action, outcome, occurred_at) \
             VALUES ('u1', 'checklist.save', 'ok', NOW() - ($1 || ' days')::INTERVAL)",
        )
        .bind(days.to_string())
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_events_runs_in_batches_until_none_remain(pool: PgPool) {
        seed_user(&pool, "u1").await;
        for _ in 0..5 {
            seed_expired_event(&pool, 400).await;
        }
        seed_expired_event(&pool, 1).await;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let n = run_prune_events_batched(&pool, &dir, 365, true, 2).await.unwrap();
        assert_eq!(n, 5);
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events").fetch_one(&pool).await.unwrap();
        assert_eq!(left, 1);
        let mut lines = 0;
        for entry in std::fs::read_dir(dir.join("audit_archive")).unwrap() {
            lines += std::fs::read_to_string(entry.unwrap().path()).unwrap().lines().count();
        }
        assert_eq!(lines, 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn scheduled_run_prunes_expired_events_and_reports_them(pool: PgPool) {
        seed_user(&pool, "u1").await;
        seed_expired_event(&pool, 400).await;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let msg = run_scheduled(&pool, &dir, 365, false).await.unwrap();
        assert!(msg.contains("1 events"), "{msg}");
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events").fetch_one(&pool).await.unwrap();
        assert_eq!(left, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failing_rule_audit_prune_does_not_skip_the_event_prune(pool: PgPool) {
        seed_user(&pool, "u1").await;
        seed_expired_event(&pool, 400).await;
        sqlx::query("DROP TABLE rule_audit").execute(&pool).await.unwrap();
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let err = run_scheduled(&pool, &dir, 365, false).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("rule_audit failed") && msg.contains("audit_events pruned 1"), "{msg}");
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events").fetch_one(&pool).await.unwrap();
        assert_eq!(left, 0);
    }
}
