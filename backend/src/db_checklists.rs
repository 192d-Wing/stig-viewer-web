use anyhow::Result;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistRow {
    pub id: String,
    pub asset_id: String,
    pub stig_id: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Version + release that were current in the catalog when this
    /// checklist was created. Compared against the live catalog row to
    /// detect drift. Empty strings mean "unknown" (legacy rows) and the
    /// drift check skips them.
    #[serde(default)]
    pub applied_version: String,
    #[serde(default)]
    pub applied_release: String,
    /// Who created the checklist. `None` = unknown (rows that predate the
    /// column are not backfilled).
    #[serde(default)]
    pub created_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistRuleRow {
    pub checklist_id: String,
    pub rule_id: String,
    pub status: String,
    pub finding_details: String,
    pub comments: String,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<String>,
    pub assignee_id: Option<String>,
    pub due_date: Option<NaiveDate>,
}

pub async fn list_checklists_for_asset(
    pool: &PgPool,
    asset_id: &str,
) -> Result<Vec<ChecklistRow>> {
    let rows = sqlx::query_as::<_, ChecklistRow>(
        "SELECT * FROM checklists WHERE asset_id = $1 ORDER BY created_at DESC",
    )
    .bind(asset_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_checklist(pool: &PgPool, id: &str) -> Result<Option<ChecklistRow>> {
    let row = sqlx::query_as::<_, ChecklistRow>("SELECT * FROM checklists WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

pub async fn find_checklist(
    pool: &PgPool,
    asset_id: &str,
    stig_id: &str,
) -> Result<Option<ChecklistRow>> {
    let row = sqlx::query_as::<_, ChecklistRow>(
        "SELECT * FROM checklists WHERE asset_id = $1 AND stig_id = $2",
    )
    .bind(asset_id)
    .bind(stig_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn insert_checklist(pool: &PgPool, row: &ChecklistRow) -> Result<()> {
    sqlx::query(
        "INSERT INTO checklists \
            (id, asset_id, stig_id, status, applied_version, applied_release, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&row.id)
    .bind(&row.asset_id)
    .bind(&row.stig_id)
    .bind(&row.status)
    .bind(&row.applied_version)
    .bind(&row.applied_release)
    .bind(&row.created_by)
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a checklist unless one already exists for `(asset_id, stig_id)`.
/// Returns true when this call inserted the row, false when the pair was
/// already present (for example a concurrent save created it first).
pub async fn insert_checklist_if_absent(pool: &PgPool, row: &ChecklistRow) -> Result<bool> {
    let res = sqlx::query(
        "INSERT INTO checklists \
            (id, asset_id, stig_id, status, applied_version, applied_release, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (asset_id, stig_id) DO NOTHING",
    )
    .bind(&row.id)
    .bind(&row.asset_id)
    .bind(&row.stig_id)
    .bind(&row.status)
    .bind(&row.applied_version)
    .bind(&row.applied_release)
    .bind(&row.created_by)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Stamp a checklist with a new applied_version + applied_release.
/// Used by re-apply to clear the drift flag once the user has acked
/// that the catalog has moved forward.
pub async fn set_applied_version(
    pool: &PgPool,
    id: &str,
    version: &str,
    release: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE checklists \
         SET applied_version = $1, applied_release = $2, updated_at = NOW() \
         WHERE id = $3",
    )
    .bind(version)
    .bind(release)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete rule overrides whose `rule_id` is not in `keep`. Used by
/// re-apply to drop overrides for rules that no longer exist in the
/// new STIG revision. Returns the count deleted.
pub async fn prune_orphan_rule_overrides(
    pool: &PgPool,
    checklist_id: &str,
    keep: &[String],
) -> Result<u64> {
    // Takes the checklist lock like every other rule writer, so this
    // multi-row delete cannot interleave with a batch holding row locks.
    let mut tx = pool.begin().await?;
    lock_checklist(&mut tx, checklist_id).await?;
    let res = sqlx::query(
        "DELETE FROM checklist_rules \
         WHERE checklist_id = $1 AND rule_id <> ALL($2)",
    )
    .bind(checklist_id)
    .bind(keep)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected())
}

/// Look up the current (version, release_info) for a STIG in the catalog.
/// Returns ("", "") if not in the catalog so create_handler can still
/// proceed for user-uploaded STIGs that don't sit in stigs_catalog.
pub async fn catalog_version(pool: &PgPool, stig_id: &str) -> Result<(String, String)> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT version, release_info FROM stigs_catalog WHERE id = $1",
    )
    .bind(stig_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.unwrap_or_default())
}

pub async fn delete_checklist(pool: &PgPool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM checklists WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_rule_overrides(
    pool: &PgPool,
    checklist_id: &str,
) -> Result<Vec<ChecklistRuleRow>> {
    let rows = sqlx::query_as::<_, ChecklistRuleRow>(
        "SELECT * FROM checklist_rules WHERE checklist_id = $1",
    )
    .bind(checklist_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Every column `write_rule` stores for one rule.
#[derive(Debug, Clone, Copy)]
pub struct RuleWrite<'a> {
    pub checklist_id: &'a str,
    pub rule_id: &'a str,
    pub status: &'a str,
    pub finding_details: &'a str,
    pub comments: &'a str,
    pub updated_by: &'a str,
    pub assignee_id: Option<&'a str>,
    pub due_date: Option<NaiveDate>,
}

pub async fn upsert_rule(pool: &PgPool, w: RuleWrite<'_>) -> Result<ChecklistRuleRow> {
    // With no expectation the guarded write cannot be rejected.
    match upsert_rule_expecting(pool, w, None).await? {
        Ok(row) => Ok(row),
        Err(rejected) => Err(rejected.into()),
    }
}

/// `upsert_rule` with a write-time status guard: when `expect_status` is
/// `Some(s)` and the row, read under the checklist lock, holds a different
/// status (`not_reviewed` when there is no row), nothing is written and
/// `PatchRejected::StatusChanged` comes back.
pub async fn upsert_rule_expecting(
    pool: &PgPool,
    w: RuleWrite<'_>,
    expect_status: Option<&str>,
) -> Result<Result<ChecklistRuleRow, PatchRejected>> {
    let mut tx = pool.begin().await?;
    lock_checklist(&mut tx, w.checklist_id).await?;

    // Snapshot existing state (if any) so we can emit audit diffs.
    let existing: Option<ChecklistRuleRow> = sqlx::query_as::<_, ChecklistRuleRow>(
        "SELECT * FROM checklist_rules WHERE checklist_id = $1 AND rule_id = $2",
    )
    .bind(w.checklist_id)
    .bind(w.rule_id)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(expected) = expect_status {
        let cur = existing.as_ref().map(|e| e.status.as_str()).unwrap_or("not_reviewed");
        if cur != expected {
            tx.rollback().await?;
            return Ok(Err(PatchRejected::StatusChanged));
        }
    }

    let row = write_rule(&mut tx, existing.as_ref(), &w).await?;
    touch_checklist(&mut tx, w.checklist_id).await?;
    tx.commit().await?;
    Ok(Ok(row))
}

/// Columns a caller wants to change on one rule; `None` keeps whatever the
/// row holds at write time.
#[derive(Debug, Default, Clone, Copy)]
pub struct RulePatch<'a> {
    pub status: Option<&'a str>,
    pub finding_details: Option<&'a str>,
    pub comments: Option<&'a str>,
    /// `None` keeps the stored assignee, `Some(None)` clears it.
    pub assignee_id: Option<Option<&'a str>>,
    /// `None` keeps the stored due date, `Some(None)` clears it.
    pub due_date: Option<Option<NaiveDate>>,
    /// Abort ([`PatchRejected::DetailsRequired`]) when the finding details
    /// that would be stored are blank, judged against the locked row.
    pub require_details: bool,
    /// Abort ([`PatchRejected::StatusChanged`]) unless the locked row's
    /// status equals this.
    pub expect_status: Option<&'a str>,
}

/// Why `patch_rule` refused to write.
#[derive(Debug, PartialEq)]
pub enum PatchRejected {
    /// A closing status would be stored with blank finding details.
    DetailsRequired,
    /// The stored status is not the one the caller relied on.
    StatusChanged,
}

impl std::fmt::Display for PatchRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DetailsRequired => "finding details required for this status",
            Self::StatusChanged => "rule changed while saving; try again",
        })
    }
}

impl std::error::Error for PatchRejected {}

/// Column values a patch resolves to against the locked row.
#[derive(Debug, PartialEq)]
struct Resolved {
    status: String,
    finding_details: String,
    comments: String,
    assignee_id: Option<String>,
    due_date: Option<NaiveDate>,
}

/// Pure decision for `patch_rule`: merge the patch over the stored row and
/// apply the write-time guards.
fn resolve_patch(
    existing: Option<&ChecklistRuleRow>,
    patch: &RulePatch<'_>,
) -> Result<Resolved, PatchRejected> {
    let cur_status = existing.map(|e| e.status.as_str()).unwrap_or("not_reviewed");
    if let Some(expected) = patch.expect_status {
        if expected != cur_status {
            return Err(PatchRejected::StatusChanged);
        }
    }
    let status = patch.status.unwrap_or(cur_status).to_string();
    let finding_details = patch
        .finding_details
        .or(existing.map(|e| e.finding_details.as_str()))
        .unwrap_or("")
        .to_string();
    let comments = patch
        .comments
        .or(existing.map(|e| e.comments.as_str()))
        .unwrap_or("")
        .to_string();
    if patch.require_details && finding_details.trim().is_empty() {
        return Err(PatchRejected::DetailsRequired);
    }
    Ok(Resolved {
        status,
        finding_details,
        comments,
        assignee_id: match patch.assignee_id {
            Some(v) => v.map(str::to_string),
            None => existing.and_then(|e| e.assignee_id.clone()),
        },
        due_date: match patch.due_date {
            Some(v) => v,
            None => existing.and_then(|e| e.due_date),
        },
    })
}

/// Take the parent checklist row lock. Every rule writer calls this first so
/// locks are always taken checklist-then-rule (no deadlock between writers),
/// and it serialises first writes to a rule row that does not exist yet.
/// `FOR NO KEY UPDATE` is enough to conflict with other writers without
/// blocking foreign-key `KEY SHARE` checks.
pub(crate) async fn lock_checklist(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    checklist_id: &str,
) -> Result<()> {
    sqlx::query("SELECT id FROM checklists WHERE id = $1 FOR NO KEY UPDATE")
        .bind(checklist_id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(())
}

/// Change some columns of a rule while preserving the rest. The existing row
/// is read inside the write transaction with `FOR UPDATE`, so a concurrent
/// edit of a column this call does not touch (comments, assignee, due date,
/// ...) is never reverted by a stale snapshot. Audit rows and the checklist
/// `updated_at` bump match `upsert_rule`.
///
/// Single-rule reference implementation, used by tests to compare against
/// `patch_rules`; the endpoints batch through `patch_rules`.
#[cfg(test)]
pub async fn patch_rule(
    pool: &PgPool,
    checklist_id: &str,
    rule_id: &str,
    patch: RulePatch<'_>,
    updated_by: &str,
) -> Result<ChecklistRuleRow> {
    let mut tx = pool.begin().await?;
    lock_checklist(&mut tx, checklist_id).await?;
    let existing: Option<ChecklistRuleRow> = sqlx::query_as::<_, ChecklistRuleRow>(
        "SELECT * FROM checklist_rules WHERE checklist_id = $1 AND rule_id = $2 FOR UPDATE",
    )
    .bind(checklist_id)
    .bind(rule_id)
    .fetch_optional(&mut *tx)
    .await?;
    let r = resolve_patch(existing.as_ref(), &patch)?;

    let w = RuleWrite {
        checklist_id,
        rule_id,
        status: &r.status,
        finding_details: &r.finding_details,
        comments: &r.comments,
        updated_by,
        assignee_id: r.assignee_id.as_deref(),
        due_date: r.due_date,
    };
    let row = write_rule(&mut tx, existing.as_ref(), &w).await?;
    touch_checklist(&mut tx, checklist_id).await?;
    tx.commit().await?;
    Ok(row)
}

/// Rules written per transaction by the batch writers.
pub const RULE_CHUNK: usize = 100;

/// How long a batch chunk waits for the checklist lock before failing.
pub(crate) const CHUNK_LOCK_TIMEOUT: &str = "5s";

/// Bound lock waits for the rest of the transaction (chunk transactions only).
pub(crate) async fn set_lock_timeout(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    timeout: &str,
) -> Result<()> {
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(timeout)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// One-line description of a failed chunk's error for logs: SQLSTATE and
/// constraint only, since database error text can carry column values.
pub(crate) fn error_summary(e: &anyhow::Error) -> String {
    match e.downcast_ref::<sqlx::Error>() {
        Some(sqlx::Error::Database(d)) => format!(
            "sqlstate {} constraint {}",
            d.code().as_deref().unwrap_or("?"),
            d.constraint().unwrap_or("-")
        ),
        Some(_) => "non-database error".to_string(),
        None => "unexpected error".to_string(),
    }
}

/// Result of one item of [`patch_rules`].
#[derive(Debug, PartialEq)]
pub enum PatchOutcome {
    Written,
    /// A write-time gate refused this rule; nothing was written for it.
    Rejected(PatchRejected),
    /// A database error rolled back the whole chunk this rule was in.
    Failed,
}

/// [`patch_rule`] for many rules of one checklist, one transaction per
/// [`RULE_CHUNK`] items. Each chunk locks the checklist, locks and reads its
/// rule rows, applies every patch through `resolve_patch` against the locked
/// row, and writes through `write_rule` (so the audit rows are the same). A
/// gate rejection skips only that rule. A database error rolls back and fails
/// its whole chunk; after two failed chunks in a row the rest are failed
/// without being tried. The result has one entry per item, in order.
pub async fn patch_rules(
    pool: &PgPool,
    checklist_id: &str,
    updated_by: &str,
    items: &[(&str, RulePatch<'_>)],
) -> Vec<PatchOutcome> {
    patch_rules_with(pool, checklist_id, updated_by, items, CHUNK_LOCK_TIMEOUT).await
}

async fn patch_rules_with(
    pool: &PgPool,
    checklist_id: &str,
    updated_by: &str,
    items: &[(&str, RulePatch<'_>)],
    lock_timeout: &str,
) -> Vec<PatchOutcome> {
    let mut out = Vec::with_capacity(items.len());
    let mut consecutive_failures = 0u8;
    for (i, chunk) in items.chunks(RULE_CHUNK).enumerate() {
        if consecutive_failures >= 2 {
            out.extend(chunk.iter().map(|_| PatchOutcome::Failed));
            continue;
        }
        match patch_chunk(pool, checklist_id, updated_by, chunk, lock_timeout).await {
            Ok(results) => {
                consecutive_failures = 0;
                out.extend(results.into_iter().map(|r| match r {
                    Ok(()) => PatchOutcome::Written,
                    Err(rejected) => PatchOutcome::Rejected(rejected),
                }));
            }
            Err(e) => {
                consecutive_failures += 1;
                tracing::error!(
                    "rule batch write failed (checklist {checklist_id}, chunk {i}): {}",
                    error_summary(&e)
                );
                out.extend(chunk.iter().map(|_| PatchOutcome::Failed));
            }
        }
    }
    out
}

async fn patch_chunk(
    pool: &PgPool,
    checklist_id: &str,
    updated_by: &str,
    chunk: &[(&str, RulePatch<'_>)],
    lock_timeout: &str,
) -> Result<Vec<Result<(), PatchRejected>>> {
    let mut tx = pool.begin().await?;
    set_lock_timeout(&mut tx, lock_timeout).await?;
    lock_checklist(&mut tx, checklist_id).await?;
    let ids: Vec<&str> = chunk.iter().map(|(id, _)| *id).collect();
    let mut rows: std::collections::HashMap<String, ChecklistRuleRow> = sqlx::query_as::<_, ChecklistRuleRow>(
        "SELECT * FROM checklist_rules WHERE checklist_id = $1 AND rule_id = ANY($2) \
         ORDER BY rule_id FOR UPDATE",
    )
    .bind(checklist_id)
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(|r| (r.rule_id.clone(), r))
    .collect();

    let mut results = Vec::with_capacity(chunk.len());
    let mut wrote = false;
    for (rule_id, patch) in chunk {
        let existing = rows.get(*rule_id);
        let r = match resolve_patch(existing, patch) {
            Ok(r) => r,
            Err(rejected) => {
                results.push(Err(rejected));
                continue;
            }
        };
        let w = RuleWrite {
            checklist_id,
            rule_id,
            status: &r.status,
            finding_details: &r.finding_details,
            comments: &r.comments,
            updated_by,
            assignee_id: r.assignee_id.as_deref(),
            due_date: r.due_date,
        };
        let row = write_rule(&mut tx, existing, &w).await?;
        // A later item for the same rule must see this write.
        rows.insert((*rule_id).to_string(), row);
        wrote = true;
        results.push(Ok(()));
    }
    if wrote {
        touch_checklist(&mut tx, checklist_id).await?;
    }
    tx.commit().await?;
    Ok(results)
}

/// Upsert one rule and write its `rule_audit` rows inside the caller's
/// transaction. The only place audit rows are produced.
async fn write_rule(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    existing: Option<&ChecklistRuleRow>,
    w: &RuleWrite<'_>,
) -> Result<ChecklistRuleRow> {
    let RuleWrite {
        checklist_id,
        rule_id,
        status,
        finding_details,
        comments,
        updated_by,
        assignee_id,
        due_date,
    } = *w;
    let row = sqlx::query_as::<_, ChecklistRuleRow>(
        r#"
        INSERT INTO checklist_rules
            (checklist_id, rule_id, status, finding_details, comments,
             updated_by, assignee_id, due_date, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        ON CONFLICT (checklist_id, rule_id) DO UPDATE
           SET status = EXCLUDED.status,
               finding_details = EXCLUDED.finding_details,
               comments = EXCLUDED.comments,
               updated_by = EXCLUDED.updated_by,
               assignee_id = EXCLUDED.assignee_id,
               due_date = EXCLUDED.due_date,
               updated_at = NOW()
        RETURNING *
        "#,
    )
    .bind(checklist_id)
    .bind(rule_id)
    .bind(status)
    .bind(finding_details)
    .bind(comments)
    .bind(updated_by)
    .bind(assignee_id)
    .bind(due_date)
    .fetch_one(&mut **tx)
    .await?;

    // Audit: write one row per field that actually changed. For a brand-new
    // row, treat "from" as the implicit defaults (status='not_reviewed',
    // empty strings, NULLs) so the audit log shows the initial assignment.
    let prev_status = existing.map(|e| e.status.as_str()).unwrap_or("not_reviewed");
    let prev_finding = existing.map(|e| e.finding_details.as_str()).unwrap_or("");
    let prev_comments = existing.map(|e| e.comments.as_str()).unwrap_or("");
    let prev_assignee: Option<&str> = existing.and_then(|e| e.assignee_id.as_deref());
    let prev_due: Option<NaiveDate> = existing.and_then(|e| e.due_date);

    let due_str = due_date.map(|d| d.to_string());
    let prev_due_str = prev_due.map(|d| d.to_string());

    let diffs: Vec<(&str, Option<String>, Option<String>)> = vec![
        ("status", Some(prev_status.into()), Some(status.into())),
        (
            "finding_details",
            Some(prev_finding.into()),
            Some(finding_details.into()),
        ),
        ("comments", Some(prev_comments.into()), Some(comments.into())),
        (
            "assignee_id",
            prev_assignee.map(|s| s.into()),
            assignee_id.map(|s| s.into()),
        ),
        ("due_date", prev_due_str, due_str),
    ];
    for (field, from, to) in diffs {
        if from == to {
            continue;
        }
        sqlx::query(
            "INSERT INTO rule_audit \
             (user_id, checklist_id, rule_id, field, from_value, to_value) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(updated_by)
        .bind(checklist_id)
        .bind(rule_id)
        .bind(field)
        .bind(from)
        .bind(to)
        .execute(&mut **tx)
        .await?;
    }

    Ok(row)
}

/// Bump the parent checklist's updated_at so the asset list reflects activity.
async fn touch_checklist(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    checklist_id: &str,
) -> Result<()> {
    sqlx::query("UPDATE checklists SET updated_at = NOW() WHERE id = $1")
        .bind(checklist_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(status: &str, details: &str) -> ChecklistRuleRow {
        ChecklistRuleRow {
            checklist_id: "c".into(),
            rule_id: "r".into(),
            status: status.into(),
            finding_details: details.into(),
            comments: "stored comments".into(),
            updated_at: Utc::now(),
            updated_by: None,
            assignee_id: Some("u".into()),
            due_date: NaiveDate::from_ymd_opt(2026, 12, 31),
        }
    }

    fn closing<'a>() -> RulePatch<'a> {
        RulePatch { status: Some("not_a_finding"), require_details: true, ..RulePatch::default() }
    }

    #[test]
    fn closing_with_blank_stored_details_is_rejected() {
        let existing = row("open", "  ");
        assert_eq!(resolve_patch(Some(&existing), &closing()), Err(PatchRejected::DetailsRequired));
        assert_eq!(resolve_patch(None, &closing()), Err(PatchRejected::DetailsRequired));
    }

    #[test]
    fn closing_is_accepted_with_details_in_patch_or_stored() {
        let existing = row("open", "");
        let patch = RulePatch { finding_details: Some("because"), ..closing() };
        assert_eq!(resolve_patch(Some(&existing), &patch).unwrap().finding_details, "because");
        let documented = row("open", "already");
        assert_eq!(resolve_patch(Some(&documented), &closing()).unwrap().finding_details, "already");
    }

    #[test]
    fn assignee_and_due_date_are_tri_state() {
        let existing = row("open", "");
        let keep = resolve_patch(Some(&existing), &RulePatch::default()).unwrap();
        assert_eq!((keep.assignee_id.as_deref(), keep.due_date), (Some("u"), existing.due_date));
        let clear = resolve_patch(
            Some(&existing),
            &RulePatch { assignee_id: Some(None), due_date: Some(None), ..RulePatch::default() },
        )
        .unwrap();
        assert_eq!((clear.assignee_id, clear.due_date), (None, None));
        let d = NaiveDate::from_ymd_opt(2031, 5, 6);
        let set = resolve_patch(
            Some(&existing),
            &RulePatch { assignee_id: Some(Some("new")), due_date: Some(d), ..RulePatch::default() },
        )
        .unwrap();
        assert_eq!((set.assignee_id.as_deref(), set.due_date), (Some("new"), d));
        // No row yet: keep means none.
        let fresh = resolve_patch(None, &RulePatch::default()).unwrap();
        assert_eq!((fresh.assignee_id, fresh.due_date), (None, None));
    }

    #[test]
    fn guard_is_off_when_not_required() {
        let existing = row("open", "");
        let patch = RulePatch { require_details: false, ..closing() };
        assert!(resolve_patch(Some(&existing), &patch).is_ok());
    }

    #[test]
    fn none_fields_keep_stored_values() {
        let existing = row("open", "details");
        let r = resolve_patch(Some(&existing), &RulePatch::default()).unwrap();
        assert_eq!(r.status, "open");
        assert_eq!(r.finding_details, "details");
        assert_eq!(r.comments, "stored comments");
        assert_eq!(r.assignee_id.as_deref(), Some("u"));
        assert_eq!(r.due_date, NaiveDate::from_ymd_opt(2026, 12, 31));
        let fresh = resolve_patch(None, &RulePatch::default()).unwrap();
        assert_eq!((fresh.status.as_str(), fresh.finding_details.as_str()), ("not_reviewed", ""));
    }

    #[test]
    fn expect_status_must_match_the_locked_row() {
        let closed = row("not_a_finding", "d");
        let patch = RulePatch { expect_status: Some("not_a_finding"), ..closing() };
        assert!(resolve_patch(Some(&closed), &patch).is_ok());
        let reopened = row("open", "d");
        assert_eq!(resolve_patch(Some(&reopened), &patch), Err(PatchRejected::StatusChanged));
        assert_eq!(resolve_patch(None, &patch), Err(PatchRejected::StatusChanged));
    }

    // ── Database-backed tests ──────────────────────────────────────────────

    use crate::test_fixtures::{fail_writes_of, seed_asset, seed_checklist, seed_rule, seed_user};

    async fn setup(pool: &PgPool) {
        seed_user(pool, "u1").await;
        seed_asset(pool, "a1", "u1", false).await;
        seed_checklist(pool, "c1", "a1", "S").await;
    }

    async fn audit_fields(pool: &PgPool) -> Vec<String> {
        sqlx::query_scalar("SELECT field FROM rule_audit ORDER BY id")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    async fn checklist_updated_at(pool: &PgPool) -> DateTime<Utc> {
        sqlx::query_scalar("SELECT updated_at FROM checklists WHERE id = 'c1'")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_keeps_untouched_columns(pool: PgPool) {
        setup(&pool).await;
        let due = NaiveDate::from_ymd_opt(2026, 12, 31);
        upsert_rule(
            &pool,
            RuleWrite {
                checklist_id: "c1",
                rule_id: "r1",
                status: "open",
                finding_details: "details",
                comments: "notes",
                updated_by: "u1",
                assignee_id: Some("u1"),
                due_date: due,
            },
        )
            .await
            .unwrap();
        let out = patch_rule(
            &pool,
            "c1",
            "r1",
            RulePatch { status: Some("not_a_finding"), ..RulePatch::default() },
            "u1",
        )
        .await
        .unwrap();
        assert_eq!(out.status, "not_a_finding");
        assert_eq!(out.finding_details, "details");
        assert_eq!(out.comments, "notes");
        assert_eq!(out.assignee_id.as_deref(), Some("u1"));
        assert_eq!(out.due_date, due);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_writes_one_audit_row_per_changed_field(pool: PgPool) {
        setup(&pool).await;
        patch_rule(
            &pool,
            "c1",
            "r1",
            RulePatch {
                status: Some("open"),
                finding_details: Some("d"),
                comments: Some("c"),
                ..RulePatch::default()
            },
            "u1",
        )
        .await
        .unwrap();
        assert_eq!(audit_fields(&pool).await, ["status", "finding_details", "comments"]);
        // Re-applying the same values changes nothing, so adds no audit rows.
        patch_rule(
            &pool,
            "c1",
            "r1",
            RulePatch { status: Some("open"), ..RulePatch::default() },
            "u1",
        )
        .await
        .unwrap();
        assert_eq!(audit_fields(&pool).await.len(), 3);
    }

    async fn assert_rejected_writes_nothing(pool: &PgPool, patch: RulePatch<'_>, want: PatchRejected) {
        let before = checklist_updated_at(pool).await;
        let err = patch_rule(pool, "c1", "r1", patch, "u1").await.unwrap_err();
        assert_eq!(err.downcast_ref::<PatchRejected>(), Some(&want));
        let rules: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklist_rules").fetch_one(pool).await.unwrap();
        assert_eq!(rules, 0);
        assert!(audit_fields(pool).await.is_empty());
        assert_eq!(checklist_updated_at(pool).await, before);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn details_required_rejection_leaves_no_trace(pool: PgPool) {
        setup(&pool).await;
        assert_rejected_writes_nothing(&pool, closing(), PatchRejected::DetailsRequired).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn status_changed_rejection_leaves_no_trace(pool: PgPool) {
        setup(&pool).await;
        // No row exists, so the live status is not_reviewed.
        let patch = RulePatch { status: Some("open"), expect_status: Some("not_a_finding"), ..RulePatch::default() };
        assert_rejected_writes_nothing(&pool, patch, PatchRejected::StatusChanged).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn expect_status_is_checked_against_the_live_row(pool: PgPool) {
        setup(&pool).await;
        seed_rule(&pool, "c1", "r1", "not_a_finding", "d", "", "u1").await;
        let patch = RulePatch { comments: Some("x"), expect_status: Some("not_a_finding"), ..RulePatch::default() };
        assert!(patch_rule(&pool, "c1", "r1", patch, "u1").await.is_ok());
        // The row is reopened behind the caller's back.
        seed_rule(&pool, "c1", "r1", "open", "d", "x", "u1").await;
        let err = patch_rule(&pool, "c1", "r1", patch, "u1").await.unwrap_err();
        assert_eq!(err.downcast_ref::<PatchRejected>(), Some(&PatchRejected::StatusChanged));
    }

    // Probabilistic: tasks interleave only at I/O awaits on the default runtime. A lost
    // update (stale snapshot overwriting a sibling column) would show up as a flaky failure.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn concurrent_patches_on_different_columns_both_survive(pool: PgPool) {
        setup(&pool).await;
        seed_rule(&pool, "c1", "r1", "open", "", "", "u1").await;
        let (a, b) = tokio::join!(
            patch_rule(&pool, "c1", "r1", RulePatch { comments: Some("c"), ..RulePatch::default() }, "u1"),
            patch_rule(&pool, "c1", "r1", RulePatch { finding_details: Some("d"), ..RulePatch::default() }, "u1"),
        );
        a.unwrap();
        b.unwrap();
        let rows = list_rule_overrides(&pool, "c1").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].comments.as_str(), rows[0].finding_details.as_str()), ("c", "d"));
    }

    // Probabilistic: interleaving is not forced. A lock-order regression (rule row
    // locked before the checklist row) would surface as a deadlock error, but not on every run.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn twenty_concurrent_writers_do_not_deadlock(pool: PgPool) {
        setup(&pool).await;
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..20 {
            let pool = pool.clone();
            tasks.spawn(async move {
                let rule = format!("r{}", i % 4);
                if i % 2 == 0 {
                    patch_rule(
                        &pool,
                        "c1",
                        &rule,
                        RulePatch { comments: Some("p"), ..RulePatch::default() },
                        "u1",
                    )
                    .await
                    .map(|_| ())
                } else {
                    upsert_rule(
                        &pool,
                        RuleWrite {
                            checklist_id: "c1",
                            rule_id: &rule,
                            status: "open",
                            finding_details: "d",
                            comments: "u",
                            updated_by: "u1",
                            assignee_id: None,
                            due_date: None,
                        },
                    )
                    .await
                    .map(|_| ())
                }
            });
        }
        while let Some(res) = tasks.join_next().await {
            res.unwrap().unwrap();
        }
        assert_eq!(list_rule_overrides(&pool, "c1").await.unwrap().len(), 4);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn insert_if_absent_reports_whether_it_inserted(pool: PgPool) {
        seed_user(&pool, "u1").await;
        seed_asset(&pool, "a1", "u1", false).await;
        let mk = |id: &str| ChecklistRow {
            id: id.into(),
            asset_id: "a1".into(),
            stig_id: "S".into(),
            status: "in_progress".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            applied_version: String::new(),
            applied_release: String::new(),
            created_by: Some("u1".into()),
        };
        assert!(insert_checklist_if_absent(&pool, &mk("first")).await.unwrap());
        assert!(!insert_checklist_if_absent(&pool, &mk("second")).await.unwrap());
        let found = find_checklist(&pool, "a1", "S").await.unwrap().unwrap();
        assert_eq!(found.id, "first");
        assert_eq!(found.created_by.as_deref(), Some("u1"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_row_without_created_by_reads_back_as_none_and_serialises_null(pool: PgPool) {
        seed_user(&pool, "u1").await;
        seed_asset(&pool, "a1", "u1", false).await;
        // Same shape as a row from before migration 036: the column is left unset.
        crate::test_fixtures::seed_checklist(&pool, "c1", "a1", "S").await;
        let by_id = get_checklist(&pool, "c1").await.unwrap().unwrap();
        let by_pair = find_checklist(&pool, "a1", "S").await.unwrap().unwrap();
        assert_eq!(by_id.created_by, None);
        assert_eq!(by_pair.created_by, None);
        let json = serde_json::to_value(&by_id).unwrap();
        assert_eq!(json["createdBy"], serde_json::Value::Null);
    }

    // ── patch_rules ────────────────────────────────────────────────────────

    fn names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("r{i:03}")).collect()
    }

    fn open_patch<'a>() -> RulePatch<'a> {
        RulePatch { status: Some("open"), finding_details: Some("d"), ..RulePatch::default() }
    }

    fn items<'a>(ids: &'a [String], patch: RulePatch<'a>) -> Vec<(&'a str, RulePatch<'a>)> {
        ids.iter().map(|id| (id.as_str(), patch)).collect()
    }

    async fn count(pool: &PgPool, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_rules_writes_across_a_chunk_boundary(pool: PgPool) {
        setup(&pool).await;
        let ids = names(RULE_CHUNK + 1);
        let out = patch_rules(&pool, "c1", "u1", &items(&ids, open_patch())).await;
        assert_eq!(out.len(), ids.len());
        assert!(out.iter().all(|o| *o == PatchOutcome::Written));
        assert_eq!(list_rule_overrides(&pool, "c1").await.unwrap().len(), RULE_CHUNK + 1);
        // status + finding_details per rule.
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM rule_audit").await as usize, 2 * (RULE_CHUNK + 1));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_rules_mixed_chunk_writes_the_good_and_rejects_the_rest(pool: PgPool) {
        setup(&pool).await;
        seed_rule(&pool, "c1", "r-closed", "not_a_finding", "d", "", "u1").await;
        seed_rule(&pool, "c1", "r-open", "open", "", "", "u1").await;
        let mark = count(&pool, "SELECT COALESCE(MAX(id), 0) FROM rule_audit").await;
        let close = RulePatch { status: Some("not_a_finding"), require_details: true, ..RulePatch::default() };
        let guarded = RulePatch { expect_status: Some("not_a_finding"), comments: Some("x"), ..RulePatch::default() };
        let batch = [
            ("r-good", open_patch()),
            ("r-open", close),     // stored details are blank
            ("r-closed", RulePatch { expect_status: Some("open"), ..guarded }),
            ("r-good2", RulePatch { status: Some("open"), ..RulePatch::default() }),
        ];
        let out = patch_rules(&pool, "c1", "u1", &batch).await;
        assert_eq!(
            out,
            [
                PatchOutcome::Written,
                PatchOutcome::Rejected(PatchRejected::DetailsRequired),
                PatchOutcome::Rejected(PatchRejected::StatusChanged),
                PatchOutcome::Written,
            ]
        );
        let rows = list_rule_overrides(&pool, "c1").await.unwrap();
        assert_eq!(rows.len(), 4);
        let open = rows.iter().find(|r| r.rule_id == "r-open").unwrap();
        assert_eq!(open.status, "open");
        let closed = rows.iter().find(|r| r.rule_id == "r-closed").unwrap();
        assert_eq!(closed.comments, "");
        // Only the two written rules added audit rows.
        let touched: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT rule_id FROM rule_audit WHERE id > $1 ORDER BY 1")
                .bind(mark)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(touched, ["r-good", "r-good2"]);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_rules_bumps_updated_at_once_per_chunk_and_not_for_all_rejected(pool: PgPool) {
        setup(&pool).await;
        let t0 = checklist_updated_at(&pool).await;
        let closing = RulePatch { status: Some("not_a_finding"), require_details: true, ..RulePatch::default() };
        let ids = names(3);
        let out = patch_rules(&pool, "c1", "u1", &items(&ids, closing)).await;
        assert!(out.iter().all(|o| matches!(o, PatchOutcome::Rejected(_))));
        assert_eq!(checklist_updated_at(&pool).await, t0);

        // Two chunks: every rule row in a chunk shares one timestamp, the
        // checklist ends at the last chunk's.
        let ids = names(RULE_CHUNK + 1);
        patch_rules(&pool, "c1", "u1", &items(&ids, open_patch())).await;
        let stamps: Vec<(String, DateTime<Utc>)> =
            sqlx::query_as("SELECT rule_id, updated_at FROM checklist_rules ORDER BY rule_id")
                .fetch_all(&pool)
                .await
                .unwrap();
        let distinct: std::collections::HashSet<_> = stamps.iter().map(|(_, t)| *t).collect();
        assert_eq!(distinct.len(), 2);
        assert_eq!(stamps[0].1, stamps[RULE_CHUNK - 1].1);
        assert_eq!(checklist_updated_at(&pool).await, stamps[RULE_CHUNK].1);
        assert!(checklist_updated_at(&pool).await > t0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_rules_audit_rows_match_single_rule_writes(pool: PgPool) {
        setup(&pool).await;
        seed_rule(&pool, "c1", "r1", "open", "old", "oc", "u1").await;
        seed_rule(&pool, "c1", "r2", "open", "old", "oc", "u1").await;
        let patches = [
            ("r1", RulePatch { status: Some("not_a_finding"), finding_details: Some("new"), ..RulePatch::default() }),
            ("r2", RulePatch { comments: Some("nc"), ..RulePatch::default() }),
            ("r3", open_patch()),
        ];
        type Audit = Vec<(String, String, Option<String>, Option<String>)>;
        let audit = |pool: PgPool, from: i64| async move {
            let a: Audit = sqlx::query_as(
                "SELECT rule_id, field, from_value, to_value FROM rule_audit WHERE id > $1 ORDER BY rule_id, field",
            )
            .bind(from)
            .fetch_all(&pool)
            .await
            .unwrap();
            a
        };
        let mark = count(&pool, "SELECT COALESCE(MAX(id), 0) FROM rule_audit").await;
        for (id, patch) in patches {
            patch_rule(&pool, "c1", id, patch, "u1").await.unwrap();
        }
        let single = audit(pool.clone(), mark).await;

        // Reset to the same starting state and replay through the batch path.
        sqlx::query("DELETE FROM checklist_rules").execute(&pool).await.unwrap();
        seed_rule(&pool, "c1", "r1", "open", "old", "oc", "u1").await;
        seed_rule(&pool, "c1", "r2", "open", "old", "oc", "u1").await;
        let mark = count(&pool, "SELECT COALESCE(MAX(id), 0) FROM rule_audit").await;
        let out = patch_rules(&pool, "c1", "u1", &patches).await;
        assert!(out.iter().all(|o| *o == PatchOutcome::Written));
        let batch = audit(pool.clone(), mark).await;
        assert!(!single.is_empty());
        assert_eq!(single, batch);
        let users: Vec<String> = sqlx::query_scalar("SELECT DISTINCT user_id FROM rule_audit")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(users, ["u1"]);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_rules_failed_chunk_writes_nothing_and_other_chunks_commit(pool: PgPool) {
        setup(&pool).await;
        fail_writes_of(&pool, "checklist_rules", &["r150"]).await;
        let ids = names(250);
        let out = patch_rules(&pool, "c1", "u1", &items(&ids, open_patch())).await;
        for (i, o) in out.iter().enumerate() {
            let want = if (100..200).contains(&i) { PatchOutcome::Failed } else { PatchOutcome::Written };
            assert_eq!(*o, want, "item {i}");
        }
        let written: Vec<String> = sqlx::query_scalar("SELECT rule_id FROM checklist_rules ORDER BY rule_id")
            .fetch_all(&pool)
            .await
            .unwrap();
        let want: Vec<String> = ids.iter().enumerate().filter(|(i, _)| !(100..200).contains(i)).map(|(_, r)| r.clone()).collect();
        assert_eq!(written, want);
        let audited: i64 = count(&pool, "SELECT COUNT(DISTINCT rule_id) FROM rule_audit").await;
        assert_eq!(audited, 150);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_rules_stops_after_two_failed_chunks(pool: PgPool) {
        setup(&pool).await;
        fail_writes_of(&pool, "checklist_rules", &["r050", "r150"]).await;
        let ids = names(400);
        let out = patch_rules(&pool, "c1", "u1", &items(&ids, open_patch())).await;
        assert_eq!(out.len(), 400);
        assert!(out.iter().all(|o| *o == PatchOutcome::Failed));
        // Chunks 2 and 3 would have succeeded had they been tried.
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_rules").await, 0);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM rule_audit").await, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_rules_duplicate_rule_id_sees_the_earlier_write(pool: PgPool) {
        setup(&pool).await;
        let batch = [
            ("r1", open_patch()),
            // Passes only if the first item's write is visible.
            ("r1", RulePatch { expect_status: Some("open"), comments: Some("x"), ..RulePatch::default() }),
        ];
        let out = patch_rules(&pool, "c1", "u1", &batch).await;
        assert_eq!(out, [PatchOutcome::Written, PatchOutcome::Written]);
        let row = list_rule_overrides(&pool, "c1").await.unwrap().remove(0);
        assert_eq!((row.status.as_str(), row.finding_details.as_str(), row.comments.as_str()), ("open", "d", "x"));
        // Second write diffed against the first: comments only.
        let fields = audit_fields(&pool).await;
        assert_eq!(fields, ["status", "finding_details", "comments"]);
    }

    // Probabilistic, like the twenty-writers test: a writer that took rule locks before the
    // checklist lock (the old prune, or a batch) would surface as a deadlock error.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn batch_and_single_writers_do_not_deadlock(pool: PgPool) {
        setup(&pool).await;
        let ids = names(150);
        let mut tasks = tokio::task::JoinSet::new();
        for round in 0..4 {
            let (p, mine) = (pool.clone(), ids.clone());
            tasks.spawn(async move {
                let out = patch_rules(&p, "c1", "u1", &items(&mine, open_patch())).await;
                assert!(out.iter().all(|o| *o == PatchOutcome::Written), "round {round}");
                Ok(())
            });
            let p = pool.clone();
            tasks.spawn(async move {
                patch_rule(&p, "c1", "r010", RulePatch { comments: Some("p"), ..RulePatch::default() }, "u1")
                    .await
                    .map(|_| ())
            });
            let p = pool.clone();
            tasks.spawn(async move {
                upsert_rule(
                    &p,
                    RuleWrite {
                        checklist_id: "c1",
                        rule_id: "r120",
                        status: "open",
                        finding_details: "d",
                        comments: "u",
                        updated_by: "u1",
                        assignee_id: None,
                        due_date: None,
                    },
                )
                .await
                .map(|_| ())
            });
            let (p, keep) = (pool.clone(), ids[..100].to_vec());
            tasks.spawn(async move { prune_orphan_rule_overrides(&p, "c1", &keep).await.map(|_| ()) });
        }
        while let Some(res) = tasks.join_next().await {
            res.unwrap().unwrap();
        }
    }

    // Timing-dependent: a second transaction holds the checklist lock while
    // the batch call runs with a short lock timeout.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_rules_chunk_fails_promptly_when_the_checklist_lock_is_held(pool: PgPool) {
        setup(&pool).await;
        let mut holder = pool.begin().await.unwrap();
        lock_checklist(&mut holder, "c1").await.unwrap();
        let ids = names(3);
        let t = std::time::Instant::now();
        let out = patch_rules_with(&pool, "c1", "u1", &items(&ids, open_patch()), "300ms").await;
        assert!(t.elapsed() < std::time::Duration::from_secs(4), "took {:?}", t.elapsed());
        assert!(out.iter().all(|o| *o == PatchOutcome::Failed));
        holder.rollback().await.unwrap();
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM checklist_rules").await, 0);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM rule_audit").await, 0);
        let out = patch_rules_with(&pool, "c1", "u1", &items(&ids, open_patch()), "300ms").await;
        assert!(out.iter().all(|o| *o == PatchOutcome::Written));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn upsert_rule_expecting_rejects_a_changed_status_and_leaves_no_trace(pool: PgPool) {
        setup(&pool).await;
        let w = |status| RuleWrite {
            checklist_id: "c1",
            rule_id: "r1",
            status,
            finding_details: "why",
            comments: "",
            updated_by: "u1",
            assignee_id: None,
            due_date: None,
        };
        upsert_rule(&pool, w("open")).await.unwrap();
        let audit = count(&pool, "SELECT COUNT(*) FROM rule_audit").await;
        let out = upsert_rule_expecting(&pool, w("not_a_finding"), Some("not_a_finding"))
            .await
            .unwrap();
        assert_eq!(out.unwrap_err(), PatchRejected::StatusChanged);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM rule_audit").await, audit);
        let st: String = sqlx::query_scalar("SELECT status FROM checklist_rules WHERE rule_id = 'r1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(st, "open");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn upsert_rule_expecting_none_matches_upsert_rule(pool: PgPool) {
        setup(&pool).await;
        let w = |rule_id| RuleWrite {
            checklist_id: "c1",
            rule_id,
            status: "open",
            finding_details: "d",
            comments: "c",
            updated_by: "u1",
            assignee_id: None,
            due_date: None,
        };
        let a = upsert_rule(&pool, w("r1")).await.unwrap();
        let b = upsert_rule_expecting(&pool, w("r2"), None).await.unwrap().unwrap();
        assert_eq!((a.status, a.finding_details, a.comments), (b.status, b.finding_details, b.comments));
        // An expectation that holds writes through.
        let c = upsert_rule_expecting(&pool, w("r2"), Some("open")).await.unwrap();
        assert!(c.is_ok());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn patch_rules_assignee_and_due_audit_rows_match_upsert_rule(pool: PgPool) {
        setup(&pool).await;
        seed_user(&pool, "u2").await;
        let due = NaiveDate::from_ymd_opt(2031, 5, 6);
        type Audit = Vec<(String, Option<String>, Option<String>)>;
        let audit = |pool: PgPool, from: i64| async move {
            let a: Audit = sqlx::query_as(
                "SELECT field, from_value, to_value FROM rule_audit WHERE id > $1 ORDER BY field",
            )
            .bind(from)
            .fetch_all(&pool)
            .await
            .unwrap();
            a
        };
        seed_rule(&pool, "c1", "r1", "open", "d", "c", "u1").await;
        let mark = count(&pool, "SELECT COALESCE(MAX(id), 0) FROM rule_audit").await;
        upsert_rule(
            &pool,
            RuleWrite {
                checklist_id: "c1",
                rule_id: "r1",
                status: "open",
                finding_details: "d",
                comments: "c",
                updated_by: "u1",
                assignee_id: Some("u2"),
                due_date: due,
            },
        )
        .await
        .unwrap();
        let single = audit(pool.clone(), mark).await;

        sqlx::query("DELETE FROM checklist_rules").execute(&pool).await.unwrap();
        seed_rule(&pool, "c1", "r1", "open", "d", "c", "u1").await;
        let mark = count(&pool, "SELECT COALESCE(MAX(id), 0) FROM rule_audit").await;
        let patch = RulePatch { assignee_id: Some(Some("u2")), due_date: Some(due), ..RulePatch::default() };
        let out = patch_rules(&pool, "c1", "u1", &[("r1", patch)]).await;
        assert_eq!(out, [PatchOutcome::Written]);
        let batch = audit(pool.clone(), mark).await;
        assert_eq!(single.len(), 2);
        assert_eq!(single, batch);
    }
}
