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
            (id, asset_id, stig_id, status, applied_version, applied_release) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&row.id)
    .bind(&row.asset_id)
    .bind(&row.stig_id)
    .bind(&row.status)
    .bind(&row.applied_version)
    .bind(&row.applied_release)
    .execute(pool)
    .await?;
    Ok(())
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
    let res = sqlx::query(
        "DELETE FROM checklist_rules \
         WHERE checklist_id = $1 AND rule_id <> ALL($2)",
    )
    .bind(checklist_id)
    .bind(keep)
    .execute(pool)
    .await?;
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

#[allow(clippy::too_many_arguments)]
pub async fn upsert_rule(
    pool: &PgPool,
    checklist_id: &str,
    rule_id: &str,
    status: &str,
    finding_details: &str,
    comments: &str,
    updated_by: &str,
    assignee_id: Option<&str>,
    due_date: Option<NaiveDate>,
) -> Result<ChecklistRuleRow> {
    let mut tx = pool.begin().await?;
    lock_checklist(&mut tx, checklist_id).await?;

    // Snapshot existing state (if any) so we can emit audit diffs.
    let existing: Option<ChecklistRuleRow> = sqlx::query_as::<_, ChecklistRuleRow>(
        "SELECT * FROM checklist_rules WHERE checklist_id = $1 AND rule_id = $2",
    )
    .bind(checklist_id)
    .bind(rule_id)
    .fetch_optional(&mut *tx)
    .await?;

    write_rule_tx(
        tx,
        existing,
        checklist_id,
        rule_id,
        status,
        finding_details,
        comments,
        updated_by,
        assignee_id,
        due_date,
    )
    .await
}

/// Columns a caller wants to change on one rule; `None` keeps whatever the
/// row holds at write time.
#[derive(Debug, Default, Clone, Copy)]
pub struct RulePatch<'a> {
    pub status: Option<&'a str>,
    pub finding_details: Option<&'a str>,
    pub comments: Option<&'a str>,
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
        assignee_id: existing.and_then(|e| e.assignee_id.clone()),
        due_date: existing.and_then(|e| e.due_date),
    })
}

/// Take the parent checklist row lock. Every rule writer calls this first so
/// locks are always taken checklist-then-rule (no deadlock between writers),
/// and it serialises first writes to a rule row that does not exist yet.
/// `FOR NO KEY UPDATE` is enough to conflict with other writers without
/// blocking foreign-key `KEY SHARE` checks.
async fn lock_checklist(
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

    write_rule_tx(
        tx,
        existing,
        checklist_id,
        rule_id,
        &r.status,
        &r.finding_details,
        &r.comments,
        updated_by,
        r.assignee_id.as_deref(),
        r.due_date,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn write_rule_tx(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    existing: Option<ChecklistRuleRow>,
    checklist_id: &str,
    rule_id: &str,
    status: &str,
    finding_details: &str,
    comments: &str,
    updated_by: &str,
    assignee_id: Option<&str>,
    due_date: Option<NaiveDate>,
) -> Result<ChecklistRuleRow> {
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
    .fetch_one(&mut *tx)
    .await?;

    // Audit: write one row per field that actually changed. For a brand-new
    // row, treat "from" as the implicit defaults (status='not_reviewed',
    // empty strings, NULLs) so the audit log shows the initial assignment.
    let prev_status = existing.as_ref().map(|e| e.status.as_str()).unwrap_or("not_reviewed");
    let prev_finding = existing.as_ref().map(|e| e.finding_details.as_str()).unwrap_or("");
    let prev_comments = existing.as_ref().map(|e| e.comments.as_str()).unwrap_or("");
    let prev_assignee: Option<&str> = existing.as_ref().and_then(|e| e.assignee_id.as_deref());
    let prev_due: Option<NaiveDate> = existing.as_ref().and_then(|e| e.due_date);

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
        .execute(&mut *tx)
        .await?;
    }

    // Bump the parent checklist's updated_at so the asset list reflects activity.
    sqlx::query("UPDATE checklists SET updated_at = NOW() WHERE id = $1")
        .bind(checklist_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(row)
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
}
