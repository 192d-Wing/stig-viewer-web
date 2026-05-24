//! Admin-facing scheduler dashboard.
//!
//! `GET /api/admin/scheduler-runs` returns:
//!   * `latest` — a map of `name -> most recent row` so the UI can show
//!     a single line per scheduler (sync, snapshot, overdue_digest,
//!     audit_retention, compliance_report).
//!   * `history` — the 10 most recent rows across all schedulers,
//!     newest first.
//!
//! Admin-only. Non-admins get 403 like every other `/api/admin/*` path.

use std::collections::HashMap;

use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::api::auth::AuthUser;
use crate::AppState;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerRunRow {
    pub id: i64,
    pub name: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: String,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerRunsResponse {
    pub latest: HashMap<String, SchedulerRunRow>,
    pub history: Vec<SchedulerRunRow>,
}

fn map_sqlx(e: sqlx::Error) -> StatusCode {
    tracing::error!("scheduler_status sqlx error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

pub async fn list_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<SchedulerRunsResponse>, StatusCode> {
    if user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }
    let pool = state.pool.as_ref();

    // Latest row per name. Postgres `DISTINCT ON` against the
    // `(name, started_at DESC)` index keeps this O(distinct names).
    let latest_rows: Vec<SchedulerRunRow> = sqlx::query_as::<_, SchedulerRunRow>(
        r#"
        SELECT DISTINCT ON (name)
               id, name, started_at, finished_at, status, message
          FROM scheduler_runs
         ORDER BY name, started_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;

    let mut latest: HashMap<String, SchedulerRunRow> = HashMap::new();
    for row in latest_rows {
        latest.insert(row.name.clone(), row);
    }

    let history: Vec<SchedulerRunRow> = sqlx::query_as::<_, SchedulerRunRow>(
        r#"
        SELECT id, name, started_at, finished_at, status, message
          FROM scheduler_runs
         ORDER BY started_at DESC
         LIMIT 10
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;

    Ok(Json(SchedulerRunsResponse { latest, history }))
}
