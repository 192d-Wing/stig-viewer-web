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
    /// Client token of the most recent autosave that bumped the revision.
    pub last_save_id: Option<String>,
    /// Hash of the request content that stored `last_save_id`; `None` for
    /// rows written before the hash existed.
    pub last_save_body_sha256: Option<String>,
}

/// A client retry token with the hash of the request content it arrived with.
#[derive(Debug, Clone, Copy)]
pub struct Token<'a> {
    pub id: &'a str,
    pub body_sha256: &'a str,
}

/// True when a request is a retry of the autosave that produced the set's
/// current revision: same token, the set sits exactly one revision past the
/// request's base, and the content hash matches (a row with no stored hash
/// predates it and matches any). Any later write breaks the condition.
pub fn is_replay(set: &SetRow, base_revision: i64, token: Option<&Token>) -> bool {
    match (token, set.last_save_id.as_deref()) {
        (Some(req), Some(stored)) => {
            req.id == stored
                && set.revision == base_revision + 1
                && set
                    .last_save_body_sha256
                    .as_deref()
                    .is_none_or(|h| h == req.body_sha256)
        }
        _ => false,
    }
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
    /// The request repeats the autosave that already produced the current
    /// revision; nothing was written.
    Replayed {
        revision: i64,
        updated_at: DateTime<Utc>,
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

/// Result of `insert_set`.
#[derive(Debug, PartialEq)]
pub enum CreateOutcome {
    Created,
    /// The owner already created a set with this key; its id.
    Existing(String),
    /// The key was used before with different request content.
    KeyConflict,
    Limit,
}

#[derive(Debug, PartialEq)]
pub enum AddStig {
    NotFound,
    Limit,
    Added,
    Exists,
}

/// Longest a write statement may run or wait for a lock, in milliseconds.
/// Postgres cuts a stalled write and rolls it back before the server
/// deadline in `detached` has to abandon it.
const STATEMENT_TIMEOUT_MS: i64 = 8_000;

async fn bound_ms(tx: &mut sqlx::PgConnection, ms: i64) -> Result<()> {
    sqlx::query(
        "SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', $1, true)",
    )
    .bind(ms.to_string())
    .execute(tx)
    .await?;
    Ok(())
}

/// Transaction-local statement and lock timeouts; the first call in a writer.
async fn bound(tx: &mut sqlx::PgConnection) -> Result<()> {
    bound_ms(tx, STATEMENT_TIMEOUT_MS).await
}

/// True when the error is Postgres cutting a statement (`57014`) or a lock
/// wait (`55P03`) short.
pub fn is_timeout(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        matches!(
            c.downcast_ref::<sqlx::Error>(),
            Some(sqlx::Error::Database(d)) if matches!(d.code().as_deref(), Some("57014" | "55P03"))
        )
    })
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
        "SELECT id, name, asset_id, revision, created_at, updated_at, last_attached_at, last_save_id,
                last_save_body_sha256
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
/// transaction. Creates nothing and returns `Limit` when the owner already has
/// `max_sets`. The owner's user row is locked so concurrent creates cannot
/// both pass the limit, and so a `create_key` lookup cannot race. When
/// `create_key` matches one of the owner's sets, that set's id is returned if
/// the content hash also matches (or none was stored), else `KeyConflict`.
pub async fn insert_set(
    pool: &PgPool,
    owner_id: &str,
    id: &str,
    name: &str,
    stigs: &[(String, String, String)],
    max_sets: i64,
    create_key: Option<Token<'_>>,
) -> Result<CreateOutcome> {
    let mut tx = pool.begin().await?;
    bound(&mut tx).await?;
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;
    if let Some(key) = create_key {
        let existing: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT id, create_body_sha256 FROM checklist_sets WHERE owner_id = $1 AND create_key = $2",
        )
        .bind(owner_id)
        .bind(key.id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((existing_id, stored)) = existing {
            return Ok(match stored {
                Some(h) if h != key.body_sha256 => CreateOutcome::KeyConflict,
                _ => CreateOutcome::Existing(existing_id),
            });
        }
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklist_sets WHERE owner_id = $1")
        .bind(owner_id)
        .fetch_one(&mut *tx)
        .await?;
    if n >= max_sets {
        return Ok(CreateOutcome::Limit);
    }
    sqlx::query(
        "INSERT INTO checklist_sets (id, owner_id, name, create_key, create_body_sha256)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(owner_id)
    .bind(name)
    .bind(create_key.map(|t| t.id))
    .bind(create_key.map(|t| t.body_sha256))
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
    Ok(CreateOutcome::Created)
}

pub async fn rename_set(pool: &PgPool, owner_id: &str, id: &str, name: &str) -> Result<bool> {
    let mut tx = pool.begin().await?;
    bound(&mut tx).await?;
    let r = sqlx::query(
        "UPDATE checklist_sets SET name = $3, updated_at = NOW() WHERE id = $1 AND owner_id = $2",
    )
    .bind(id)
    .bind(owner_id)
    .bind(name)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(r.rows_affected() > 0)
}

/// Clears the system link. Returns the previous link: `None` when the set is
/// not the owner's, `Some(None)` when it was not linked.
pub async fn unlink_asset(
    pool: &PgPool,
    owner_id: &str,
    id: &str,
) -> Result<Option<Option<String>>> {
    let mut tx = pool.begin().await?;
    bound(&mut tx).await?;
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "WITH old AS (SELECT asset_id FROM checklist_sets WHERE id = $1 AND owner_id = $2 FOR UPDATE)
         UPDATE checklist_sets c SET asset_id = NULL, updated_at = NOW()
         FROM old WHERE c.id = $1 AND c.owner_id = $2
         RETURNING old.asset_id",
    )
    .bind(id)
    .bind(owner_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
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
    let mut tx = pool.begin().await?;
    bound(&mut tx).await?;
    let r = sqlx::query("DELETE FROM checklist_sets WHERE id = $1 AND owner_id = $2")
        .bind(id)
        .bind(owner_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
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
    bound(&mut tx).await?;
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
    bound(&mut tx).await?;
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
            "UPDATE checklist_sets SET revision = revision + 1, last_save_id = NULL,
                last_save_body_sha256 = NULL, updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Some(removed))
}

/// `(rows, bytes, touched rows, touched bytes)` of the set's stored rules,
/// where "touched" means named by `changes`.
async fn totals(
    tx: &mut sqlx::PgConnection,
    id: &str,
    changes: &[RuleChange],
) -> Result<(i64, i64, i64, i64)> {
    let stigs: Vec<&str> = changes.iter().map(|c| c.stig_id.as_str()).collect();
    let rules: Vec<&str> = changes.iter().map(|c| c.rule_id.as_str()).collect();
    Ok(sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "WITH sz AS (
             SELECT r.rule_id, (t.rule_id IS NOT NULL) AS touched,
                    octet_length(r.rule_id) + octet_length(r.finding_details)
                      + octet_length(r.comments) AS n
             FROM checklist_set_rules r
             LEFT JOIN (SELECT DISTINCT * FROM UNNEST($2::text[], $3::text[]) AS u(stig_id, rule_id)) t
               ON t.stig_id = r.stig_id AND t.rule_id = r.rule_id
             WHERE r.set_id = $1
         )
         SELECT COUNT(*), COALESCE(SUM(n), 0)::bigint,
                COUNT(*) FILTER (WHERE touched),
                COALESCE(SUM(n) FILTER (WHERE touched), 0)::bigint
         FROM sz",
    )
    .bind(id)
    .bind(&stigs)
    .bind(&rules)
    .fetch_one(tx)
    .await?)
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
    save: Option<Token<'_>>,
) -> Result<WriteOutcome> {
    let mut tx = pool.begin().await?;
    bound(&mut tx).await?;
    let bumped: Option<(i64, DateTime<Utc>, bool)> = sqlx::query_as(&format!(
        "WITH old AS (
             SELECT last_edit_event_at FROM checklist_sets
             WHERE id = $1 AND owner_id = $2 AND revision = $3 FOR UPDATE
         )
         UPDATE checklist_sets c SET
             revision = c.revision + 1,
             updated_at = NOW(),
             last_save_id = $4,
             last_save_body_sha256 = $5,
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
    .bind(save.map(|t| t.id))
    .bind(save.map(|t| t.body_sha256))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((revision, updated_at, edit_event_due)) = bumped else {
        drop(tx);
        return Ok(match get_set(pool, owner_id, id).await? {
            Some(s) if is_replay(&s, base_revision, save.as_ref()) => WriteOutcome::Replayed {
                revision: s.revision,
                updated_at: s.updated_at,
            },
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
    // Totals for the whole set and for the rows this request touches, taken
    // before the writes (one scan): the set's size afterwards follows by
    // arithmetic, and a save that only shrinks or rewrites an over-budget set
    // is told apart from one that grows it. They must be read before the
    // DELETE: the touched rows include the ones about to be deleted, and
    // reading afterwards would refuse "delete 2, add 1" on an over-budget
    // set. A save with nothing to write has no growth to check, so it skips
    // the scan.
    let sizes = if up.is_empty() {
        None
    } else {
        Some(totals(&mut tx, id, changes).await?)
    };
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
        // A set already over budget (the limit was lowered) stays usable: only
        // a save that grows it in that dimension is refused.
        let (total_rows, total_bytes, old_rows, old_bytes) = sizes.unwrap_or_default();
        let new_rows = up.len() as i64;
        let new_bytes: i64 = up
            .iter()
            .map(|c| (c.rule_id.len() + c.finding_details.len() + c.comments.len()) as i64)
            .sum();
        let rows = total_rows - old_rows + new_rows;
        let bytes = total_bytes - old_bytes + new_bytes;
        if (rows > budget.max_rows && new_rows > old_rows)
            || (bytes > budget.max_bytes && new_bytes > old_bytes)
        {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_statement_bound_cuts_a_slow_statement_and_is_recognised(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        bound_ms(&mut tx, 100).await.unwrap();
        let err = sqlx::query("SELECT pg_sleep(1)")
            .execute(&mut *tx)
            .await
            .unwrap_err();
        assert!(is_timeout(&anyhow::Error::from(err)));
        assert!(!is_timeout(&anyhow::anyhow!("something else")));
    }
}
