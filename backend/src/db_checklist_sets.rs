//! Storage for checklist sets: named, owner-private working checklists.
//!
//! Every function takes `owner_id` and filters on it in SQL, so a set that
//! belongs to someone else is indistinguishable from a missing one.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Minimum gap between two `checklist_set.edit` audit events for one set.
const EDIT_EVENT_WINDOW: &str = "15 minutes";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SetRow {
    pub id: String,
    pub name: String,
    pub asset_id: Option<String>,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_attached_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SetSummaryRow {
    pub id: String,
    pub name: String,
    pub asset_id: Option<String>,
    pub asset_name: Option<String>,
    pub revision: i64,
    pub stig_count: i64,
    pub touched_count: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SetStigRow {
    pub stig_id: String,
    pub applied_version: String,
    pub applied_release: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SetRuleRow {
    pub stig_id: String,
    pub rule_id: String,
    pub status: String,
    pub finding_details: String,
    pub comments: String,
}

/// One rule's full state as sent by autosave.
#[derive(Debug, Clone)]
pub struct RuleChange {
    pub stig_id: String,
    pub rule_id: String,
    pub status: String,
    pub finding_details: String,
    pub comments: String,
}

impl RuleChange {
    /// A rule back at its untouched state has no stored row.
    fn is_untouched(&self) -> bool {
        self.status == "not_reviewed"
            && self.finding_details.trim().is_empty()
            && self.comments.trim().is_empty()
    }
}

#[derive(Debug, PartialEq)]
pub enum WriteOutcome {
    Written {
        revision: i64,
        updated_at: DateTime<Utc>,
        edit_event_due: bool,
    },
    NotFound,
    Conflict {
        revision: i64,
    },
    TooManyRules,
    /// The set as a whole would exceed its row or byte budget.
    SetTooLarge,
    UnknownStig,
}

/// Size bounds a set's stored rules must stay within.
#[derive(Clone, Copy, Debug)]
pub struct SetBudget {
    pub max_rows_per_stig: i64,
    pub max_rows: i64,
    pub max_bytes: i64,
}

#[derive(Debug, PartialEq)]
pub enum AddStig {
    NotFound,
    Limit,
    Added,
    Exists,
}

pub async fn list_sets(pool: &PgPool, owner_id: &str) -> Result<Vec<SetSummaryRow>> {
    Ok(sqlx::query_as::<_, SetSummaryRow>(
        "SELECT c.id, c.name, c.asset_id, a.name AS asset_name, c.revision, c.updated_at,
                (SELECT COUNT(*) FROM checklist_set_stigs s WHERE s.set_id = c.id) AS stig_count,
                (SELECT COUNT(*) FROM checklist_set_rules r WHERE r.set_id = c.id) AS touched_count
         FROM checklist_sets c LEFT JOIN assets a ON a.id = c.asset_id
         WHERE c.owner_id = $1
         ORDER BY c.updated_at DESC, c.id",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await?)
}

pub async fn get_set(pool: &PgPool, owner_id: &str, id: &str) -> Result<Option<SetRow>> {
    Ok(sqlx::query_as::<_, SetRow>(
        "SELECT id, name, asset_id, revision, created_at, updated_at, last_attached_at
         FROM checklist_sets WHERE id = $1 AND owner_id = $2",
    )
    .bind(id)
    .bind(owner_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn list_stigs(pool: &PgPool, owner_id: &str, set_id: &str) -> Result<Vec<SetStigRow>> {
    Ok(sqlx::query_as::<_, SetStigRow>(
        "SELECT s.stig_id, s.applied_version, s.applied_release
         FROM checklist_set_stigs s JOIN checklist_sets c ON c.id = s.set_id
         WHERE c.id = $1 AND c.owner_id = $2
         ORDER BY s.position, s.stig_id",
    )
    .bind(set_id)
    .bind(owner_id)
    .fetch_all(pool)
    .await?)
}

pub async fn list_rules(pool: &PgPool, owner_id: &str, set_id: &str) -> Result<Vec<SetRuleRow>> {
    Ok(sqlx::query_as::<_, SetRuleRow>(
        "SELECT r.stig_id, r.rule_id, r.status, r.finding_details, r.comments
         FROM checklist_set_rules r JOIN checklist_sets c ON c.id = r.set_id
         WHERE c.id = $1 AND c.owner_id = $2
         ORDER BY r.stig_id, r.rule_id",
    )
    .bind(set_id)
    .bind(owner_id)
    .fetch_all(pool)
    .await?)
}

/// Create a set with its STIGs (`(stig_id, version, release)`) in one
/// transaction. Returns false, creating nothing, when the owner already has
/// `max_sets`. The owner's user row is locked so concurrent creates cannot
/// both pass the limit.
pub async fn insert_set(
    pool: &PgPool,
    owner_id: &str,
    id: &str,
    name: &str,
    stigs: &[(String, String, String)],
    max_sets: i64,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklist_sets WHERE owner_id = $1")
        .bind(owner_id)
        .fetch_one(&mut *tx)
        .await?;
    if n >= max_sets {
        return Ok(false);
    }
    sqlx::query("INSERT INTO checklist_sets (id, owner_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(owner_id)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    for (i, (stig_id, version, release)) in stigs.iter().enumerate() {
        sqlx::query(
            "INSERT INTO checklist_set_stigs (set_id, stig_id, position, applied_version, applied_release)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(stig_id)
        .bind(i as i32)
        .bind(version)
        .bind(release)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

pub async fn rename_set(pool: &PgPool, owner_id: &str, id: &str, name: &str) -> Result<bool> {
    let r = sqlx::query(
        "UPDATE checklist_sets SET name = $3, updated_at = NOW() WHERE id = $1 AND owner_id = $2",
    )
    .bind(id)
    .bind(owner_id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Clears the system link. Returns the previous link: `None` when the set is
/// not the owner's, `Some(None)` when it was not linked.
pub async fn unlink_asset(
    pool: &PgPool,
    owner_id: &str,
    id: &str,
) -> Result<Option<Option<String>>> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "WITH old AS (SELECT asset_id FROM checklist_sets WHERE id = $1 AND owner_id = $2 FOR UPDATE)
         UPDATE checklist_sets c SET asset_id = NULL, updated_at = NOW()
         FROM old WHERE c.id = $1 AND c.owner_id = $2
         RETURNING old.asset_id",
    )
    .bind(id)
    .bind(owner_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

/// Record that the set was saved to `asset_id`.
pub async fn link_asset(pool: &PgPool, owner_id: &str, id: &str, asset_id: &str) -> Result<bool> {
    let r = sqlx::query(
        "UPDATE checklist_sets SET asset_id = $3, last_attached_at = NOW() WHERE id = $1 AND owner_id = $2",
    )
    .bind(id)
    .bind(owner_id)
    .bind(asset_id)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn delete_set(pool: &PgPool, owner_id: &str, id: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM checklist_sets WHERE id = $1 AND owner_id = $2")
        .bind(id)
        .bind(owner_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Idempotent add of a STIG at the end of the set, up to `max_stigs`.
pub async fn add_stig(
    pool: &PgPool,
    owner_id: &str,
    id: &str,
    stig_id: &str,
    version: &str,
    release: &str,
    max_stigs: i64,
) -> Result<AddStig> {
    let mut tx = pool.begin().await?;
    let locked: Option<(String,)> =
        sqlx::query_as("SELECT id FROM checklist_sets WHERE id = $1 AND owner_id = $2 FOR UPDATE")
            .bind(id)
            .bind(owner_id)
            .fetch_optional(&mut *tx)
            .await?;
    if locked.is_none() {
        return Ok(AddStig::NotFound);
    }
    let (n, next): (i64, i32) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(MAX(position) + 1, 0) FROM checklist_set_stigs WHERE set_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let exists: Option<(i32,)> = sqlx::query_as(
        "SELECT position FROM checklist_set_stigs WHERE set_id = $1 AND stig_id = $2",
    )
    .bind(id)
    .bind(stig_id)
    .fetch_optional(&mut *tx)
    .await?;
    if exists.is_some() {
        return Ok(AddStig::Exists);
    }
    if n >= max_stigs {
        return Ok(AddStig::Limit);
    }
    sqlx::query(
        "INSERT INTO checklist_set_stigs (set_id, stig_id, position, applied_version, applied_release)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(stig_id)
    .bind(next)
    .bind(version)
    .bind(release)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE checklist_sets SET updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(AddStig::Added)
}

/// Remove a STIG (its rules cascade) and bump the revision. `None` when the
/// set is not the owner's; otherwise whether the STIG was in the set.
pub async fn remove_stig(
    pool: &PgPool,
    owner_id: &str,
    id: &str,
    stig_id: &str,
) -> Result<Option<bool>> {
    let mut tx = pool.begin().await?;
    let locked: Option<(String,)> =
        sqlx::query_as("SELECT id FROM checklist_sets WHERE id = $1 AND owner_id = $2 FOR UPDATE")
            .bind(id)
            .bind(owner_id)
            .fetch_optional(&mut *tx)
            .await?;
    if locked.is_none() {
        return Ok(None);
    }
    let r = sqlx::query("DELETE FROM checklist_set_stigs WHERE set_id = $1 AND stig_id = $2")
        .bind(id)
        .bind(stig_id)
        .execute(&mut *tx)
        .await?;
    let removed = r.rows_affected() > 0;
    if removed {
        sqlx::query(
            "UPDATE checklist_sets SET revision = revision + 1, updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Some(removed))
}

/// Autosave: replace each sent rule's state exactly, in one transaction,
/// guarded by `base_revision`. Callers dedupe `changes` by (stig, rule).
pub async fn write_rules(
    pool: &PgPool,
    owner_id: &str,
    id: &str,
    base_revision: i64,
    changes: &[RuleChange],
    budget: SetBudget,
) -> Result<WriteOutcome> {
    let mut tx = pool.begin().await?;
    let bumped: Option<(i64, DateTime<Utc>, bool)> = sqlx::query_as(&format!(
        "WITH old AS (
             SELECT last_edit_event_at FROM checklist_sets
             WHERE id = $1 AND owner_id = $2 AND revision = $3 FOR UPDATE
         )
         UPDATE checklist_sets c SET
             revision = c.revision + 1,
             updated_at = NOW(),
             last_edit_event_at = CASE
                 WHEN old.last_edit_event_at IS NULL OR old.last_edit_event_at < NOW() - INTERVAL '{EDIT_EVENT_WINDOW}'
                 THEN NOW() ELSE old.last_edit_event_at END
         FROM old
         WHERE c.id = $1 AND c.owner_id = $2
         RETURNING c.revision, c.updated_at,
             (old.last_edit_event_at IS NULL OR old.last_edit_event_at < NOW() - INTERVAL '{EDIT_EVENT_WINDOW}')"
    ))
    .bind(id)
    .bind(owner_id)
    .bind(base_revision)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((revision, updated_at, edit_event_due)) = bumped else {
        drop(tx);
        return Ok(match get_set(pool, owner_id, id).await? {
            Some(s) => WriteOutcome::Conflict {
                revision: s.revision,
            },
            None => WriteOutcome::NotFound,
        });
    };

    let (mut up, mut del): (Vec<&RuleChange>, Vec<&RuleChange>) = (Vec::new(), Vec::new());
    for c in changes {
        if c.is_untouched() {
            del.push(c);
        } else {
            up.push(c);
        }
    }
    if !del.is_empty() {
        let stigs: Vec<&str> = del.iter().map(|c| c.stig_id.as_str()).collect();
        let rules: Vec<&str> = del.iter().map(|c| c.rule_id.as_str()).collect();
        sqlx::query(
            "DELETE FROM checklist_set_rules
             WHERE set_id = $1 AND (stig_id, rule_id) IN (SELECT * FROM UNNEST($2::text[], $3::text[]))",
        )
        .bind(id)
        .bind(&stigs)
        .bind(&rules)
        .execute(&mut *tx)
        .await?;
    }
    if !up.is_empty() {
        let stigs: Vec<&str> = up.iter().map(|c| c.stig_id.as_str()).collect();
        let rules: Vec<&str> = up.iter().map(|c| c.rule_id.as_str()).collect();
        let statuses: Vec<&str> = up.iter().map(|c| c.status.as_str()).collect();
        let details: Vec<&str> = up.iter().map(|c| c.finding_details.as_str()).collect();
        let comments: Vec<&str> = up.iter().map(|c| c.comments.as_str()).collect();
        let res = sqlx::query(
            "INSERT INTO checklist_set_rules (set_id, stig_id, rule_id, status, finding_details, comments)
             SELECT $1, * FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[])
             ON CONFLICT (set_id, stig_id, rule_id) DO UPDATE SET
                 status = EXCLUDED.status,
                 finding_details = EXCLUDED.finding_details,
                 comments = EXCLUDED.comments,
                 updated_at = NOW()",
        )
        .bind(id)
        .bind(&stigs)
        .bind(&rules)
        .bind(&statuses)
        .bind(&details)
        .bind(&comments)
        .execute(&mut *tx)
        .await;
        match res {
            Ok(_) => {}
            Err(sqlx::Error::Database(d)) if d.is_foreign_key_violation() => {
                return Ok(WriteOutcome::UnknownStig)
            }
            Err(e) => return Err(e.into()),
        }
        let touched: Vec<&str> = up.iter().map(|c| c.stig_id.as_str()).collect();
        let over: Option<(String,)> = sqlx::query_as(
            "SELECT stig_id FROM checklist_set_rules WHERE set_id = $1 AND stig_id = ANY($2)
             GROUP BY stig_id HAVING COUNT(*) > $3 LIMIT 1",
        )
        .bind(id)
        .bind(&touched)
        .bind(budget.max_rows_per_stig)
        .fetch_optional(&mut *tx)
        .await?;
        if over.is_some() {
            return Ok(WriteOutcome::TooManyRules);
        }
        // Whole-set budget, so a set's stored state (and every read of it)
        // stays bounded however many rule ids are sent.
        let (rows, bytes): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(octet_length(rule_id) + octet_length(finding_details)
                                           + octet_length(comments)), 0)::bigint
             FROM checklist_set_rules WHERE set_id = $1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if rows > budget.max_rows || bytes > budget.max_bytes {
            return Ok(WriteOutcome::SetTooLarge);
        }
    }
    tx.commit().await?;
    Ok(WriteOutcome::Written {
        revision,
        updated_at,
        edit_event_due,
    })
}

/// `(version, release)` of a catalog STIG, or `None` when it is not in the
/// catalog.
pub async fn catalog_entry(pool: &PgPool, stig_id: &str) -> Result<Option<(String, String)>> {
    Ok(
        sqlx::query_as("SELECT version, release_info FROM stigs_catalog WHERE id = $1")
            .bind(stig_id)
            .fetch_optional(pool)
            .await?,
    )
}
