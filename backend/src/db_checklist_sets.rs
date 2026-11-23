//! Storage for checklist sets: named, owner-private working checklists.
//!
//! Every function takes `owner_id` and filters on it in SQL, so a set that
//! belongs to someone else is indistinguishable from a missing one.
//!
//! The mutators run on the caller's connection and never begin or commit a
//! transaction: the handler opens a bounded one (`crate::db::begin_bounded`),
//! records the audit row on it (`api::audit_tx::record`) and commits, so a
//! failed audit insert rolls the change back. An early `Ok` return (not found,
//! conflict, limit) leaves the transaction for the caller to drop.

use anyhow::Result;
use chrono::{DateTime, Utc};

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
    /// Tagged digest (`<alg>:<hex>`) of the request content that stored
    /// `last_save_id`; `None` for rows written before the digest existed.
    pub last_save_body_digest: Option<String>,
}

/// A client retry token with the digest of the request content it arrived with.
#[derive(Debug, Clone, Copy)]
pub struct Token<'a> {
    pub id: &'a str,
    pub body_digest: &'a str,
}

/// Bare hex of a `sha256:` digest, for the superseded 048 columns that are
/// still written (for rollback) until a later migration drops them. `None`
/// for any other algorithm.
fn legacy_sha256(digest: &str) -> Option<&str> {
    digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// True when a request is a retry of the autosave that produced the set's
/// current revision: same token, the set sits exactly one revision past the
/// request's base, and the stored digest is present and equal to the
/// request's (a row with no stored digest predates it and is not a replay).
/// Any later write breaks the condition.
pub fn is_replay(set: &SetRow, base_revision: i64, token: Option<&Token>) -> bool {
    match (token, set.last_save_id.as_deref()) {
        (Some(req), Some(stored)) => {
            req.id == stored
                && set.revision == base_revision + 1
                && set.last_save_body_digest.as_deref() == Some(req.body_digest)
        }
        _ => false,
    }
}

/// True when a request reuses the token of the autosave that produced the
/// set's current revision (same id, one revision past the base) without being
/// a replay: the token is being refused, which is worth an audit event.
pub fn is_token_reuse(set: &SetRow, base_revision: i64, token: Option<&Token>) -> bool {
    match (token, set.last_save_id.as_deref()) {
        (Some(req), Some(stored)) => {
            req.id == stored
                && set.revision == base_revision + 1
                && !is_replay(set, base_revision, token)
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
        /// The request's token is the one that produced the current revision
        /// but its content differs (a refused reuse, not a plain stale write).
        token_reused: bool,
        /// Whether the stored row carries a digest to compare against.
        stored_digest: bool,
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
    /// The key was used before with different request content (or with no
    /// stored digest to compare). `set_id` is the set that holds the key.
    KeyConflict {
        set_id: String,
        stored_digest: bool,
    },
    Limit,
}

#[derive(Debug, PartialEq)]
pub enum AddStig {
    NotFound,
    Limit,
    Added,
    Exists,
}

pub use crate::db::is_timeout;

pub async fn list_sets(
    db: impl sqlx::PgExecutor<'_>,
    owner_id: &str,
) -> Result<Vec<SetSummaryRow>> {
    Ok(sqlx::query_as::<_, SetSummaryRow>(
        "SELECT c.id, c.name, c.asset_id, a.name AS asset_name, c.revision, c.updated_at,
                (SELECT COUNT(*) FROM checklist_set_stigs s WHERE s.set_id = c.id) AS stig_count,
                (SELECT COUNT(*) FROM checklist_set_rules r WHERE r.set_id = c.id) AS touched_count
         FROM checklist_sets c LEFT JOIN assets a ON a.id = c.asset_id
         WHERE c.owner_id = $1
         ORDER BY c.updated_at DESC, c.id",
    )
    .bind(owner_id)
    .fetch_all(db)
    .await?)
}

pub async fn get_set(
    db: impl sqlx::PgExecutor<'_>,
    owner_id: &str,
    id: &str,
) -> Result<Option<SetRow>> {
    Ok(sqlx::query_as::<_, SetRow>(
        "SELECT id, name, asset_id, revision, created_at, updated_at, last_attached_at, last_save_id,
                last_save_body_digest
         FROM checklist_sets WHERE id = $1 AND owner_id = $2",
    )
    .bind(id)
    .bind(owner_id)
    .fetch_optional(db)
    .await?)
}

pub async fn list_stigs(
    db: impl sqlx::PgExecutor<'_>,
    owner_id: &str,
    set_id: &str,
) -> Result<Vec<SetStigRow>> {
    Ok(sqlx::query_as::<_, SetStigRow>(
        "SELECT s.stig_id, s.applied_version, s.applied_release
         FROM checklist_set_stigs s JOIN checklist_sets c ON c.id = s.set_id
         WHERE c.id = $1 AND c.owner_id = $2
         ORDER BY s.position, s.stig_id",
    )
    .bind(set_id)
    .bind(owner_id)
    .fetch_all(db)
    .await?)
}

pub async fn list_rules(
    db: impl sqlx::PgExecutor<'_>,
    owner_id: &str,
    set_id: &str,
) -> Result<Vec<SetRuleRow>> {
    Ok(sqlx::query_as::<_, SetRuleRow>(
        "SELECT r.stig_id, r.rule_id, r.status, r.finding_details, r.comments
         FROM checklist_set_rules r JOIN checklist_sets c ON c.id = r.set_id
         WHERE c.id = $1 AND c.owner_id = $2
         ORDER BY r.stig_id, r.rule_id",
    )
    .bind(set_id)
    .bind(owner_id)
    .fetch_all(db)
    .await?)
}

/// Create a set with its STIGs (`(stig_id, version, release)`) in one
/// transaction. Creates nothing and returns `Limit` when the owner already has
/// `max_sets`. The owner's user row is locked so concurrent creates cannot
/// both pass the limit, and so a `create_key` lookup cannot race. When
/// `create_key` matches one of the owner's sets, that set's id is returned if
/// the stored digest is present and equal, else `KeyConflict`.
pub async fn insert_set(
    conn: &mut sqlx::PgConnection,
    owner_id: &str,
    id: &str,
    name: &str,
    stigs: &[(String, String, String)],
    max_sets: i64,
    create_key: Option<Token<'_>>,
) -> Result<CreateOutcome> {
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(owner_id)
        .fetch_optional(&mut *conn)
        .await?;
    if let Some(key) = create_key {
        let existing: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT id, create_body_digest FROM checklist_sets WHERE owner_id = $1 AND create_key = $2",
        )
        .bind(owner_id)
        .bind(key.id)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some((existing_id, stored)) = existing {
            return Ok(match stored {
                Some(ref h) if h == key.body_digest => CreateOutcome::Existing(existing_id),
                _ => CreateOutcome::KeyConflict {
                    set_id: existing_id,
                    stored_digest: stored.is_some(),
                },
            });
        }
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checklist_sets WHERE owner_id = $1")
        .bind(owner_id)
        .fetch_one(&mut *conn)
        .await?;
    if n >= max_sets {
        return Ok(CreateOutcome::Limit);
    }
    sqlx::query(
        "INSERT INTO checklist_sets
             (id, owner_id, name, create_key, create_body_digest, create_body_sha256)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(owner_id)
    .bind(name)
    .bind(create_key.map(|t| t.id))
    .bind(create_key.map(|t| t.body_digest))
    .bind(create_key.and_then(|t| legacy_sha256(t.body_digest)))
    .execute(&mut *conn)
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
        .execute(&mut *conn)
        .await?;
    }
    Ok(CreateOutcome::Created)
}

pub async fn rename_set(
    conn: &mut sqlx::PgConnection,
    owner_id: &str,
    id: &str,
    name: &str,
) -> Result<bool> {
    let r = sqlx::query(
        "UPDATE checklist_sets SET name = $3, updated_at = NOW() WHERE id = $1 AND owner_id = $2",
    )
    .bind(id)
    .bind(owner_id)
    .bind(name)
    .execute(&mut *conn)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Clears the system link. Returns the previous link: `None` when the set is
/// not the owner's, `Some(None)` when it was not linked.
pub async fn unlink_asset(
    conn: &mut sqlx::PgConnection,
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
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|r| r.0))
}

/// Record that the set was saved to `asset_id`.
pub async fn link_asset(
    conn: &mut sqlx::PgConnection,
    owner_id: &str,
    id: &str,
    asset_id: &str,
) -> Result<bool> {
    let r = sqlx::query(
        "UPDATE checklist_sets SET asset_id = $3, last_attached_at = NOW() WHERE id = $1 AND owner_id = $2",
    )
    .bind(id)
    .bind(owner_id)
    .bind(asset_id)
    .execute(&mut *conn)
    .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn delete_set(conn: &mut sqlx::PgConnection, owner_id: &str, id: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM checklist_sets WHERE id = $1 AND owner_id = $2")
        .bind(id)
        .bind(owner_id)
        .execute(&mut *conn)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Idempotent add of a STIG at the end of the set, up to `max_stigs`.
pub async fn add_stig(
    conn: &mut sqlx::PgConnection,
    owner_id: &str,
    id: &str,
    stig_id: &str,
    version: &str,
    release: &str,
    max_stigs: i64,
) -> Result<AddStig> {
    let locked: Option<(String,)> =
        sqlx::query_as("SELECT id FROM checklist_sets WHERE id = $1 AND owner_id = $2 FOR UPDATE")
            .bind(id)
            .bind(owner_id)
            .fetch_optional(&mut *conn)
            .await?;
    if locked.is_none() {
        return Ok(AddStig::NotFound);
    }
    let (n, next): (i64, i32) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(MAX(position) + 1, 0) FROM checklist_set_stigs WHERE set_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    let exists: Option<(i32,)> = sqlx::query_as(
        "SELECT position FROM checklist_set_stigs WHERE set_id = $1 AND stig_id = $2",
    )
    .bind(id)
    .bind(stig_id)
    .fetch_optional(&mut *conn)
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
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE checklist_sets SET updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    Ok(AddStig::Added)
}

/// Remove a STIG (its rules cascade) and bump the revision. `None` when the
/// set is not the owner's; otherwise whether the STIG was in the set.
pub async fn remove_stig(
    conn: &mut sqlx::PgConnection,
    owner_id: &str,
    id: &str,
    stig_id: &str,
) -> Result<Option<bool>> {
    let locked: Option<(String,)> =
        sqlx::query_as("SELECT id FROM checklist_sets WHERE id = $1 AND owner_id = $2 FOR UPDATE")
            .bind(id)
            .bind(owner_id)
            .fetch_optional(&mut *conn)
            .await?;
    if locked.is_none() {
        return Ok(None);
    }
    let r = sqlx::query("DELETE FROM checklist_set_stigs WHERE set_id = $1 AND stig_id = $2")
        .bind(id)
        .bind(stig_id)
        .execute(&mut *conn)
        .await?;
    let removed = r.rows_affected() > 0;
    if removed {
        sqlx::query(
            "UPDATE checklist_sets SET revision = revision + 1, last_save_id = NULL,
                last_save_body_digest = NULL, last_save_body_sha256 = NULL,
                updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *conn)
        .await?;
    }
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
    conn: &mut sqlx::PgConnection,
    owner_id: &str,
    id: &str,
    base_revision: i64,
    changes: &[RuleChange],
    budget: SetBudget,
    save: Option<Token<'_>>,
) -> Result<WriteOutcome> {
    let bumped: Option<(i64, DateTime<Utc>, bool)> = sqlx::query_as(&format!(
        "WITH old AS (
             SELECT last_edit_event_at FROM checklist_sets
             WHERE id = $1 AND owner_id = $2 AND revision = $3 FOR UPDATE
         )
         UPDATE checklist_sets c SET
             revision = c.revision + 1,
             updated_at = NOW(),
             last_save_id = $4,
             last_save_body_digest = $5,
             last_save_body_sha256 = $6,
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
    .bind(save.map(|t| t.body_digest))
    .bind(save.and_then(|t| legacy_sha256(t.body_digest)))
    .fetch_optional(&mut *conn)
    .await?;
    let Some((revision, updated_at, edit_event_due)) = bumped else {
        return Ok(match get_set(&mut *conn, owner_id, id).await? {
            Some(s) if is_replay(&s, base_revision, save.as_ref()) => WriteOutcome::Replayed {
                revision: s.revision,
                updated_at: s.updated_at,
            },
            Some(s) => WriteOutcome::Conflict {
                revision: s.revision,
                token_reused: is_token_reuse(&s, base_revision, save.as_ref()),
                stored_digest: s.last_save_body_digest.is_some(),
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
        Some(totals(&mut *conn, id, changes).await?)
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
        .execute(&mut *conn)
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
        .execute(&mut *conn)
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
        .fetch_optional(&mut *conn)
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
    Ok(WriteOutcome::Written {
        revision,
        updated_at,
        edit_event_due,
    })
}

/// `(version, release)` of a catalog STIG, or `None` when it is not in the
/// catalog.
pub async fn catalog_entry(
    db: impl sqlx::PgExecutor<'_>,
    stig_id: &str,
) -> Result<Option<(String, String)>> {
    Ok(
        sqlx::query_as("SELECT version, release_info FROM stigs_catalog WHERE id = $1")
            .bind(stig_id)
            .fetch_optional(db)
            .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::bound_ms;
    use sqlx::PgPool;

    /// `write_rules` on its own bounded transaction, committed.
    async fn write_rules_committed(
        pool: &PgPool,
        owner_id: &str,
        id: &str,
        base_revision: i64,
        changes: &[RuleChange],
        budget: SetBudget,
        save: Option<Token<'_>>,
    ) -> Result<WriteOutcome> {
        let mut tx = crate::db::begin_bounded(pool).await?;
        let out = write_rules(&mut tx, owner_id, id, base_revision, changes, budget, save).await?;
        tx.commit().await?;
        Ok(out)
    }

    /// `insert_set` on its own bounded transaction, committed.
    async fn insert_set_committed(
        pool: &PgPool,
        owner_id: &str,
        id: &str,
        name: &str,
        stigs: &[(String, String, String)],
        max_sets: i64,
        create_key: Option<Token<'_>>,
    ) -> Result<CreateOutcome> {
        let mut tx = crate::db::begin_bounded(pool).await?;
        let out = insert_set(&mut tx, owner_id, id, name, stigs, max_sets, create_key).await?;
        tx.commit().await?;
        Ok(out)
    }

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

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_read_on_a_bounded_transaction_is_cut_by_a_lock(pool: PgPool) {
        let mut lock = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE checklist_sets IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        bound_ms(&mut tx, 100).await.unwrap();
        let err = list_sets(&mut *tx, "u1").await.unwrap_err();
        assert!(is_timeout(&err));
        drop(tx);
        lock.rollback().await.unwrap();
        // The connection went back to the pool; a query succeeds promptly.
        let n: i64 = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sqlx::query_scalar("SELECT 1::bigint").fetch_one(&pool),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(n, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn link_asset_is_bounded_by_the_statement_timeout(pool: PgPool) {
        crate::test_fixtures::seed_user(&pool, "u1").await;
        sqlx::query("INSERT INTO checklist_sets (id, owner_id, name) VALUES ('s1', 'u1', 'n')")
            .execute(&pool)
            .await
            .unwrap();
        let mut lock = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE checklist_sets IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();
        let mut tx = crate::db::begin_bounded_ms(&pool, 100).await.unwrap();
        let err = link_asset(&mut tx, "u1", "s1", "a1").await.unwrap_err();
        assert!(is_timeout(&err));
        drop(tx);
        lock.rollback().await.unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn digests_are_tagged_and_the_check_refuses_a_bare_hash(pool: PgPool) {
        crate::test_fixtures::seed_user(&pool, "u1").await;
        let tagged = format!("sha256:{}", "ab".repeat(32));
        sqlx::query(
            "INSERT INTO checklist_sets (id, owner_id, name, create_key, create_body_digest)
             VALUES ('s1', 'u1', 'n', 'k', $1)",
        )
        .bind(&tagged)
        .execute(&pool)
        .await
        .unwrap();
        let got = get_set(&pool, "u1", "s1").await.unwrap().unwrap();
        assert_eq!(got.last_save_body_digest, None);
        let stored: String =
            sqlx::query_scalar("SELECT create_body_digest FROM checklist_sets WHERE id = 's1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored, tagged);
        for bad in ["ab".repeat(32), "SHA256:abab".to_string(), String::new()] {
            let err = sqlx::query(
                "INSERT INTO checklist_sets (id, owner_id, name, last_save_body_digest)
                 VALUES ('s2', 'u1', 'n', $1)",
            )
            .bind(&bad)
            .execute(&pool)
            .await
            .unwrap_err();
            assert!(
                matches!(&err, sqlx::Error::Database(d) if d.is_check_violation()),
                "{bad}: {err}"
            );
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn begin_bounded_sets_both_timeouts_to_eight_seconds(pool: PgPool) {
        let mut tx = crate::db::begin_bounded(&pool).await.unwrap();
        let (st, lt): (String, String) = sqlx::query_as(
            "SELECT current_setting('statement_timeout'), current_setting('lock_timeout')",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!((st.as_str(), lt.as_str()), ("8s", "8s"));
        tx.commit().await.unwrap();
        // Transaction-local: a plain pooled connection is unbounded again.
        let st: String = sqlx::query_scalar("SELECT current_setting('statement_timeout')")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(st, "0");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_refused_token_reuse_in_write_rules_reports_token_reused(pool: PgPool) {
        crate::test_fixtures::seed_user(&pool, "u1").await;
        sqlx::query("INSERT INTO checklist_sets (id, owner_id, name) VALUES ('s1', 'u1', 'n')")
            .execute(&pool)
            .await
            .unwrap();
        let budget = SetBudget {
            max_rows_per_stig: 500,
            max_rows: 10_000,
            max_bytes: 4 << 20,
        };
        let d1 = format!("sha256:{}", "a".repeat(64));
        let d2 = format!("sha256:{}", "b".repeat(64));
        let tok = |digest: &'static str| Token {
            id: "11111111-1111-4111-8111-111111111111",
            body_digest: digest,
        };
        let d1: &'static str = Box::leak(d1.into_boxed_str());
        let d2: &'static str = Box::leak(d2.into_boxed_str());
        let first = write_rules_committed(&pool, "u1", "s1", 0, &[], budget, Some(tok(d1)))
            .await
            .unwrap();
        assert!(matches!(first, WriteOutcome::Written { revision: 1, .. }));
        // Same token, other content, stale base: refused, and flagged as a reuse.
        let out = write_rules_committed(&pool, "u1", "s1", 0, &[], budget, Some(tok(d2)))
            .await
            .unwrap();
        assert_eq!(
            out,
            WriteOutcome::Conflict {
                revision: 1,
                token_reused: true,
                stored_digest: true
            }
        );
        // The identical retry is a replay; another token is a plain conflict.
        let out = write_rules_committed(&pool, "u1", "s1", 0, &[], budget, Some(tok(d1)))
            .await
            .unwrap();
        assert!(matches!(out, WriteOutcome::Replayed { revision: 1, .. }));
        let other = Token {
            id: "22222222-2222-4222-8222-222222222222",
            body_digest: d1,
        };
        let out = write_rules_committed(&pool, "u1", "s1", 0, &[], budget, Some(other))
            .await
            .unwrap();
        assert!(matches!(
            out,
            WriteOutcome::Conflict {
                token_reused: false,
                ..
            }
        ));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_superseded_sha256_columns_are_dual_written_for_rollback(pool: PgPool) {
        crate::test_fixtures::seed_user(&pool, "u1").await;
        let hex = "ab".repeat(32);
        let digest = format!("sha256:{hex}");
        let key = Token {
            id: "11111111-1111-4111-8111-111111111111",
            body_digest: &digest,
        };
        let out = insert_set_committed(&pool, "u1", "s1", "n", &[], 50, Some(key))
            .await
            .unwrap();
        assert_eq!(out, CreateOutcome::Created);
        let budget = SetBudget {
            max_rows_per_stig: 500,
            max_rows: 10_000,
            max_bytes: 4 << 20,
        };
        write_rules_committed(&pool, "u1", "s1", 0, &[], budget, Some(key))
            .await
            .unwrap();
        let q =
            "SELECT create_body_sha256, last_save_body_sha256 FROM checklist_sets WHERE id = 's1'";
        let (c, l): (Option<String>, Option<String>) =
            sqlx::query_as(q).fetch_one(&pool).await.unwrap();
        assert_eq!(
            (c.as_deref(), l.as_deref()),
            (Some(hex.as_str()), Some(hex.as_str()))
        );
        // Another algorithm leaves the old columns empty (no tagged value fits them).
        let other = Token {
            id: "22222222-2222-4222-8222-222222222222",
            body_digest: &format!("blake3:{hex}"),
        };
        insert_set_committed(&pool, "u1", "s2", "n", &[], 50, Some(other))
            .await
            .unwrap();
        let c: Option<String> =
            sqlx::query_scalar("SELECT create_body_sha256 FROM checklist_sets WHERE id = 's2'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(c, None);
    }
}
