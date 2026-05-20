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

    // Snapshot existing state (if any) so we can emit audit diffs.
    let existing: Option<ChecklistRuleRow> = sqlx::query_as::<_, ChecklistRuleRow>(
        "SELECT * FROM checklist_rules WHERE checklist_id = $1 AND rule_id = $2",
    )
    .bind(checklist_id)
    .bind(rule_id)
    .fetch_optional(&mut *tx)
    .await?;

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
