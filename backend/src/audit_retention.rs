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
