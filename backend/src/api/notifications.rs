use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use sqlx::Row;

use crate::api::auth::AuthUser;
use crate::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignedItem {
    pub occurred_at: DateTime<Utc>,
    pub actor_id: String,
    pub checklist_id: String,
    pub rule_id: String,
    pub asset_name: String,
    pub stig_title: String,
    pub unread: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverdueItem {
    pub checklist_id: String,
    pub rule_id: String,
    pub asset_name: String,
    pub stig_title: String,
    pub due_date: Option<NaiveDate>,
    pub severity: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MentionItem {
    pub comment_id: String,
    pub checklist_id: String,
    pub rule_id: String,
    pub body: String,
    pub by_name: String,
    pub at: DateTime<Utc>,
    pub unread: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalItem {
    pub approval_id: String,
    pub checklist_id: String,
    pub rule_id: String,
    pub asset_name: String,
    pub stig_title: String,
    pub requested_by_name: String,
    pub proposed_status: String,
    pub requested_at: DateTime<Utc>,
    pub unread: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionItem {
    pub approval_id: String,
    pub checklist_id: String,
    pub rule_id: String,
    pub asset_name: String,
    pub stig_title: String,
    pub status: String,
    pub proposed_status: String,
    pub decided_at: DateTime<Utc>,
    pub decision_reason: Option<String>,
    pub unread: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignedDraftItem {
    pub draft_id: String,
    pub title: String,
    pub by_name: String,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationsResponse {
    pub assigned: Vec<AssignedItem>,
    pub overdue: Vec<OverdueItem>,
    pub mentions: Vec<MentionItem>,
    pub approvals: Vec<ApprovalItem>,
    pub decisions: Vec<DecisionItem>,
    pub assigned_drafts: Vec<AssignedDraftItem>,
    pub unread_count: i64,
    pub last_seen: Option<DateTime<Utc>>,
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push_str("…");
    out
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("notifications db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("notifications sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// GET /api/notifications — assignment + overdue items for the current
/// user, plus an unread counter driven by `users.notifications_last_seen`.
pub async fn get_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<NotificationsResponse>, StatusCode> {
    let pool = state.pool.as_ref();

    // Read the watermark once; null = nothing has ever been read.
    let last_seen: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT notifications_last_seen FROM users WHERE id = $1")
            .bind(&user.id)
            .fetch_optional(pool)
            .await
            .map_err(map_sqlx)?
            .flatten();

    // Recent assignment events: audit rows where the assignee_id field
    // transitioned to the current user. Joined with asset/stig metadata
    // so the frontend has enough to render a clickable row.
    let assigned_rows = sqlx::query(
        r#"
        SELECT
            ra.occurred_at,
            ra.user_id     AS actor_id,
            ra.checklist_id,
            ra.rule_id,
            a.name         AS asset_name,
            COALESCE(sc.title, c.stig_id) AS stig_title
          FROM rule_audit ra
          JOIN checklists c     ON c.id = ra.checklist_id
          JOIN assets a         ON a.id = c.asset_id
          LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
         WHERE ra.field = 'assignee_id'
           AND ra.to_value = $1
         ORDER BY ra.occurred_at DESC
         LIMIT 25
        "#,
    )
    .bind(&user.id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;

    let mut assigned: Vec<AssignedItem> = Vec::with_capacity(assigned_rows.len());
    let mut unread_count: i64 = 0;
    for row in assigned_rows {
        let occurred_at: DateTime<Utc> = row.try_get("occurred_at").map_err(map_sqlx)?;
        let unread = last_seen.is_none_or(|t| occurred_at > t);
        if unread {
            unread_count += 1;
        }
        assigned.push(AssignedItem {
            occurred_at,
            actor_id: row.try_get("actor_id").map_err(map_sqlx)?,
            checklist_id: row.try_get("checklist_id").map_err(map_sqlx)?,
            rule_id: row.try_get("rule_id").map_err(map_sqlx)?,
            asset_name: row.try_get("asset_name").map_err(map_sqlx)?,
            stig_title: row.try_get("stig_title").map_err(map_sqlx)?,
            unread,
        });
    }

    // Currently-open findings assigned to me whose due date has passed.
    // No timestamp/watermark — this is live state, always shown.
    let overdue_rows = sqlx::query(
        r#"
        SELECT
            cr.checklist_id,
            cr.rule_id,
            cr.due_date,
            a.name         AS asset_name,
            COALESCE(sc.title, c.stig_id) AS stig_title
          FROM checklist_rules cr
          JOIN checklists c     ON c.id = cr.checklist_id
          JOIN assets a         ON a.id = c.asset_id
          LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
         WHERE cr.status = 'open'
           AND cr.assignee_id = $1
           AND cr.due_date IS NOT NULL
           AND cr.due_date < CURRENT_DATE
         ORDER BY cr.due_date ASC
        "#,
    )
    .bind(&user.id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;

    let overdue: Vec<OverdueItem> = overdue_rows
        .into_iter()
        .map(|row| -> Result<OverdueItem, sqlx::Error> {
            Ok(OverdueItem {
                checklist_id: row.try_get("checklist_id")?,
                rule_id: row.try_get("rule_id")?,
                asset_name: row.try_get("asset_name")?,
                stig_title: row.try_get("stig_title")?,
                due_date: row.try_get("due_date")?,
                severity: None, // severity lives in STIG JSON; omitted for now
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sqlx)?;

    // @-mentions for the current user. Mentions are "unread" until the
    // user calls mark-read; once stamped, they still appear in the bucket
    // (so users can scroll history) but no longer count toward the badge.
    let mention_rows = sqlx::query(
        r#"
        SELECT
            m.id              AS mention_id,
            m.read_at         AS read_at,
            rc.id             AS comment_id,
            rc.checklist_id   AS checklist_id,
            rc.rule_id        AS rule_id,
            rc.body           AS body,
            rc.created_at     AS at,
            u.display_name    AS by_name
          FROM comment_mentions m
          JOIN rule_comments rc ON rc.id = m.comment_id
          JOIN users u ON u.id = rc.user_id
         WHERE m.mentioned_user_id = $1
         ORDER BY rc.created_at DESC
         LIMIT 50
        "#,
    )
    .bind(&user.id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;

    let mut mentions: Vec<MentionItem> = Vec::with_capacity(mention_rows.len());
    for row in mention_rows {
        let read_at: Option<DateTime<Utc>> = row.try_get("read_at").map_err(map_sqlx)?;
        let unread = read_at.is_none();
        if unread {
            unread_count += 1;
        }
        let body: String = row.try_get("body").map_err(map_sqlx)?;
        mentions.push(MentionItem {
            comment_id: row.try_get("comment_id").map_err(map_sqlx)?,
            checklist_id: row.try_get("checklist_id").map_err(map_sqlx)?,
            rule_id: row.try_get("rule_id").map_err(map_sqlx)?,
            body: truncate_chars(&body, 120),
            by_name: row.try_get("by_name").map_err(map_sqlx)?,
            at: row.try_get("at").map_err(map_sqlx)?,
            unread,
        });
    }

    // Pending approvals visible to reviewers/admins. For other roles
    // this bucket stays empty — only the decisions bucket below applies.
    let is_reviewer = user.role == "reviewer" || user.role == "admin";
    let approvals: Vec<ApprovalItem> = if is_reviewer {
        let rows = sqlx::query(
            r#"
            SELECT
                fa.id              AS approval_id,
                fa.checklist_id,
                fa.rule_id,
                fa.proposed_status,
                fa.requested_at,
                a.name             AS asset_name,
                COALESCE(sc.title, c.stig_id) AS stig_title,
                u.display_name     AS requested_by_name
              FROM finding_approvals fa
              JOIN checklists c     ON c.id = fa.checklist_id
              JOIN assets a         ON a.id = c.asset_id
              LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
              JOIN users u          ON u.id = fa.requested_by
             WHERE fa.status = 'pending'
             ORDER BY fa.requested_at DESC
             LIMIT 50
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?;

        let mut out: Vec<ApprovalItem> = Vec::with_capacity(rows.len());
        for row in rows {
            let requested_at: DateTime<Utc> = row.try_get("requested_at").map_err(map_sqlx)?;
            let unread = last_seen.is_none_or(|t| requested_at > t);
            if unread {
                unread_count += 1;
            }
            out.push(ApprovalItem {
                approval_id: row.try_get("approval_id").map_err(map_sqlx)?,
                checklist_id: row.try_get("checklist_id").map_err(map_sqlx)?,
                rule_id: row.try_get("rule_id").map_err(map_sqlx)?,
                asset_name: row.try_get("asset_name").map_err(map_sqlx)?,
                stig_title: row.try_get("stig_title").map_err(map_sqlx)?,
                requested_by_name: row.try_get("requested_by_name").map_err(map_sqlx)?,
                proposed_status: row.try_get("proposed_status").map_err(map_sqlx)?,
                requested_at,
                unread,
            });
        }
        out
    } else {
        Vec::new()
    };

    // Decisions on rows the caller requested. Always shown to the
    // requester regardless of role; they need to know an approval was
    // approved or rejected.
    let decision_rows = sqlx::query(
        r#"
        SELECT
            fa.id              AS approval_id,
            fa.checklist_id,
            fa.rule_id,
            fa.proposed_status,
            fa.status          AS status,
            fa.decided_at      AS decided_at,
            fa.decision_reason AS decision_reason,
            a.name             AS asset_name,
            COALESCE(sc.title, c.stig_id) AS stig_title
          FROM finding_approvals fa
          JOIN checklists c     ON c.id = fa.checklist_id
          JOIN assets a         ON a.id = c.asset_id
          LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
         WHERE fa.requested_by = $1
           AND fa.status IN ('approved', 'rejected')
           AND fa.decided_at IS NOT NULL
         ORDER BY fa.decided_at DESC
         LIMIT 50
        "#,
    )
    .bind(&user.id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;

    let mut decisions: Vec<DecisionItem> = Vec::with_capacity(decision_rows.len());
    for row in decision_rows {
        let decided_at: DateTime<Utc> = row.try_get("decided_at").map_err(map_sqlx)?;
        let unread = last_seen.is_none_or(|t| decided_at > t);
        if unread {
            unread_count += 1;
        }
        decisions.push(DecisionItem {
            approval_id: row.try_get("approval_id").map_err(map_sqlx)?,
            checklist_id: row.try_get("checklist_id").map_err(map_sqlx)?,
            rule_id: row.try_get("rule_id").map_err(map_sqlx)?,
            asset_name: row.try_get("asset_name").map_err(map_sqlx)?,
            stig_title: row.try_get("stig_title").map_err(map_sqlx)?,
            status: row.try_get("status").map_err(map_sqlx)?,
            proposed_status: row.try_get("proposed_status").map_err(map_sqlx)?,
            decided_at,
            decision_reason: row.try_get("decision_reason").map_err(map_sqlx)?,
            unread,
        });
    }

    // Drafts in 'submitted' state explicitly assigned to the caller.
    // These are inherently transient — once the reviewer acts (approve,
    // reject, claim) they leave the bucket. No separate notifications
    // table needed; the draft row IS the notification.
    let assigned_draft_rows = sqlx::query(
        r#"
        SELECT
            d.id            AS draft_id,
            d.title         AS title,
            d.updated_at    AS at,
            u.display_name  AS by_name
          FROM stig_drafts d
          JOIN users u ON u.id = d.author_id
         WHERE d.assigned_reviewer_id = $1
           AND d.status = 'submitted'
         ORDER BY d.updated_at DESC
         LIMIT 50
        "#,
    )
    .bind(&user.id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;

    let mut assigned_drafts: Vec<AssignedDraftItem> =
        Vec::with_capacity(assigned_draft_rows.len());
    for row in assigned_draft_rows {
        let at: DateTime<Utc> = row.try_get("at").map_err(map_sqlx)?;
        // Treat any submitted-and-still-assigned draft as unread — there
        // is no per-row read state, so the bell badge mirrors the live
        // queue. mark-read clears `last_seen` but the bucket itself is
        // self-clearing when the reviewer acts on the draft.
        let unread = last_seen.is_none_or(|t| at > t);
        if unread {
            unread_count += 1;
        }
        assigned_drafts.push(AssignedDraftItem {
            draft_id: row.try_get("draft_id").map_err(map_sqlx)?,
            title: row.try_get("title").map_err(map_sqlx)?,
            by_name: row.try_get("by_name").map_err(map_sqlx)?,
            at,
        });
    }

    Ok(Json(NotificationsResponse {
        assigned,
        overdue,
        mentions,
        approvals,
        decisions,
        assigned_drafts,
        unread_count,
        last_seen,
    }))
}

/// POST /api/notifications/mark-read — stamp `last_seen = NOW()` on the
/// current user so subsequent assignment events count as unread again.
pub async fn mark_read_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<StatusCode, StatusCode> {
    let pool = state.pool.as_ref();
    sqlx::query("UPDATE users SET notifications_last_seen = NOW() WHERE id = $1")
        .bind(&user.id)
        .execute(pool)
        .await
        .map_err(|e| map_db(anyhow::anyhow!(e)))?;
    // Stamp read_at on any outstanding @-mentions for this user. Mirrors
    // the assigned-row "watermark" behavior so the bell badge clears.
    sqlx::query(
        r#"
        UPDATE comment_mentions
           SET read_at = NOW()
         WHERE mentioned_user_id = $1
           AND read_at IS NULL
        "#,
    )
    .bind(&user.id)
    .execute(pool)
    .await
    .map_err(|e| map_db(anyhow::anyhow!(e)))?;
    Ok(StatusCode::NO_CONTENT)
}
