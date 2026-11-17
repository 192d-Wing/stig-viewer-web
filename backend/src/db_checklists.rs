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

    // ── Database-backed tests ──────────────────────────────────────────────

    use crate::test_fixtures::{seed_asset, seed_checklist, seed_user};

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
        upsert_rule(&pool, "c1", "r1", "open", "details", "notes", "u1", Some("u1"), due)
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
        upsert_rule(&pool, "c1", "r1", "not_a_finding", "d", "", "u1", None, None).await.unwrap();
        let patch = RulePatch { comments: Some("x"), expect_status: Some("not_a_finding"), ..RulePatch::default() };
        assert!(patch_rule(&pool, "c1", "r1", patch, "u1").await.is_ok());
        // The row is reopened behind the caller's back.
        upsert_rule(&pool, "c1", "r1", "open", "d", "x", "u1", None, None).await.unwrap();
        let err = patch_rule(&pool, "c1", "r1", patch, "u1").await.unwrap_err();
        assert_eq!(err.downcast_ref::<PatchRejected>(), Some(&PatchRejected::StatusChanged));
    }

    // Probabilistic: tasks interleave only at I/O awaits on the default runtime. A lost
    // update (stale snapshot overwriting a sibling column) would show up as a flaky failure.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn concurrent_patches_on_different_columns_both_survive(pool: PgPool) {
        setup(&pool).await;
        upsert_rule(&pool, "c1", "r1", "open", "", "", "u1", None, None).await.unwrap();
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
                    upsert_rule(&pool, "c1", &rule, "open", "d", "u", "u1", None, None).await.map(|_| ())
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
}
