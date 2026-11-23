//! Scheduled fleet-wide compliance report.
//!
//! On each tick of the 5th background scheduler (or via the
//! `/api/test/run-report` test endpoint), this module:
//!   1. Pulls a snapshot of fleet KPIs + per-asset summary + top open rules.
//!   2. Renders them into a single PDF.
//!   3. Writes the PDF to `${data_dir}/compliance_reports/<id>.pdf`.
//!   4. Inserts a row in `compliance_reports` so the admin console can
//!      list and link to each generated report.
//!   5. Optionally fires a `compliance_report` webhook event so Slack /
//!      receivers can pick up the link.
//!   6. Optionally emails the freshly-generated PDF to the configured
//!      recipient list (`COMPLIANCE_REPORT_RECIPIENTS`). The email path
//!      is independent of webhooks — both fire per generation. We
//!      re-read `EmailConfig::from_env()` here rather than threading
//!      SMTP credentials through `AppState`, because (a) email is
//!      best-effort and lives at the edge, and (b) operators can swap
//!      SMTP credentials with just a restart.

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::Response,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::path::PathBuf;

use crate::pdf::{Face, TextDoc};
use crate::AppState;

// ── Page geometry (mirrors backend/src/api/report.rs) ───────────────────────
const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const MARGIN_L: f32 = 18.0;
const MARGIN_T: f32 = 18.0;
const MARGIN_B: f32 = 18.0;
const SIZE_TITLE: f32 = 22.0;
const SIZE_H2: f32 = 14.0;
const SIZE_BODY: f32 = 10.0;
const SIZE_SMALL: f32 = 8.5;
const LH: f32 = 5.0;

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReportRow {
    pub id: String,
    pub generated_at: DateTime<Utc>,
    pub range_days: i32,
    pub summary: sqlx::types::Json<ReportSummary>,
    pub pdf_path: String,
}

#[derive(Debug, Default, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportSummary {
    pub assets: i64,
    pub checklists: i64,
    pub compliance_score: f64,
    pub open_findings: i64,
    pub overdue_findings: i64,
    pub top_asset_name: Option<String>,
    pub top_asset_score: Option<i64>,
}

/// Generate a report once, write the PDF, insert the row. Returns the row.
pub async fn run_report(
    pool: &PgPool,
    data_dir: &std::path::Path,
    range_days: i32,
) -> Result<ComplianceReportRow> {
    // Pull all the data we need with a few parallel queries.
    let counts = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM assets)                                AS assets,
            (SELECT COUNT(*) FROM checklists)                            AS checklists,
            (SELECT COUNT(*) FROM checklist_rules WHERE status = 'open') AS open_findings,
            (SELECT COUNT(*) FROM checklist_rules
              WHERE status = 'open' AND due_date IS NOT NULL
                AND due_date < CURRENT_DATE)                             AS overdue_findings,
            COALESCE((SELECT SUM(CASE WHEN cr.status IN ('not_a_finding','not_applicable')
                                       THEN 1 ELSE 0 END)::FLOAT
                        / NULLIF(SUM(COALESCE(sc.rule_count, 0)), 0) * 100
                        FROM checklists c
                        LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
                        LEFT JOIN checklist_rules cr ON cr.checklist_id = c.id), 0)
                                                                         AS compliance_score
        "#,
    )
    .fetch_one(pool)
    .await?;

    let summary = ReportSummary {
        assets: counts.try_get("assets")?,
        checklists: counts.try_get("checklists")?,
        open_findings: counts.try_get("open_findings")?,
        overdue_findings: counts.try_get("overdue_findings")?,
        compliance_score: round1(counts.try_get::<f64, _>("compliance_score").unwrap_or(0.0)),
        top_asset_name: None,
        top_asset_score: None,
    };

    // Per-asset summary, ordered by open count desc (proxy for "worst").
    let asset_rows = sqlx::query(
        r#"
        SELECT
            a.id,
            a.name,
            a.classification,
            u.display_name AS owner_name,
            COALESCE(SUM(CASE WHEN cr.status = 'open' THEN 1 ELSE 0 END), 0) AS open_count,
            COALESCE(SUM(CASE WHEN cr.status IN ('not_a_finding','not_applicable')
                              THEN 1 ELSE 0 END)::FLOAT
                       / NULLIF(SUM(COALESCE(sc.rule_count, 0)), 0) * 100, 0) AS compliance_score
          FROM assets a
          JOIN users u ON u.id = a.owner_id
          LEFT JOIN checklists c ON c.asset_id = a.id
          LEFT JOIN stigs_catalog sc ON sc.id = c.stig_id
          LEFT JOIN checklist_rules cr ON cr.checklist_id = c.id
         GROUP BY a.id, a.name, a.classification, u.display_name
         ORDER BY open_count DESC, a.name
         LIMIT 20
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut asset_rows: Vec<AssetLine> = asset_rows
        .into_iter()
        .map(|row| -> Result<AssetLine> {
            Ok(AssetLine {
                name: row.try_get("name")?,
                classification: row.try_get("classification")?,
                owner_name: row.try_get("owner_name")?,
                open_count: row.try_get("open_count")?,
                compliance_score: round1(row.try_get::<f64, _>("compliance_score").unwrap_or(0.0)),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Top open rules across the fleet.
    let top_rules = sqlx::query(
        r#"
        SELECT rule_id, COUNT(DISTINCT checklist_id) AS affected
          FROM checklist_rules
         WHERE status = 'open'
         GROUP BY rule_id
         ORDER BY affected DESC, rule_id ASC
         LIMIT 10
        "#,
    )
    .fetch_all(pool)
    .await?;

    let top_rules: Vec<TopRuleLine> = top_rules
        .into_iter()
        .map(|row| -> Result<TopRuleLine> {
            Ok(TopRuleLine {
                rule_id: row.try_get("rule_id")?,
                affected: row.try_get("affected")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Stamp top asset into the summary blob — useful list-row metadata.
    let mut summary = summary;
    if let Some(top) = asset_rows.first() {
        summary.top_asset_name = Some(top.name.clone());
        summary.top_asset_score = Some(top.open_count);
    }

    // ── Render PDF ──────────────────────────────────────────────────────────
    let pdf_bytes = render_pdf(&summary, &asset_rows, &top_rules, range_days)?;

    // ── Persist ─────────────────────────────────────────────────────────────
    let id = crate::crypto::rand::uuid_v4().to_string();
    let dir = data_dir.join("compliance_reports");
    tokio::fs::create_dir_all(&dir).await?;
    let pdf_path_rel = format!("compliance_reports/{id}.pdf");
    let pdf_path_abs = data_dir.join(&pdf_path_rel);
    tokio::fs::write(&pdf_path_abs, &pdf_bytes).await?;

    let summary_json = sqlx::types::Json(summary);
    sqlx::query(
        "INSERT INTO compliance_reports (id, range_days, summary, pdf_path) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&id)
    .bind(range_days)
    .bind(&summary_json)
    .bind(&pdf_path_rel)
    .execute(pool)
    .await?;

    // Sort asset_rows for later use (no-op, just to silence unused mut warning)
    asset_rows.shrink_to_fit();

    // Fetch the row back so callers get the generated_at default.
    let row = sqlx::query_as::<_, ComplianceReportRow>(
        "SELECT id, generated_at, range_days, summary, pdf_path \
         FROM compliance_reports WHERE id = $1",
    )
    .bind(&id)
    .fetch_one(pool)
    .await?;

    // Fire a webhook event for downstream Slack/etc. integrations.
    let _ = crate::api::webhooks::fire_compliance_report(pool, &row).await;

    // Email path is independent of the webhook fan-out. Best-effort —
    // any SMTP failure is recorded into `email_deliveries` with the
    // error column populated and never propagated to the caller.
    let _ = crate::api::email::send_compliance_report(
        pool,
        data_dir,
        crate::api::email::EmailConfig::from_env(),
        &row,
    )
    .await;

    Ok(row)
}

#[derive(Debug)]
struct AssetLine {
    name: String,
    classification: String,
    owner_name: String,
    open_count: i64,
    compliance_score: f64,
}

#[derive(Debug)]
struct TopRuleLine {
    rule_id: String,
    affected: i64,
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn render_pdf(
    summary: &ReportSummary,
    assets: &[AssetLine],
    top_rules: &[TopRuleLine],
    range_days: i32,
) -> Result<Vec<u8>> {
    Ok(layout_report(summary, assets, top_rules, range_days, Utc::now()).finish())
}

fn layout_report(
    summary: &ReportSummary,
    assets: &[AssetLine],
    top_rules: &[TopRuleLine],
    range_days: i32,
    generated_at: DateTime<Utc>,
) -> TextDoc {
    let mut doc = TextDoc::new("Fleet Compliance Report", PAGE_W, PAGE_H);
    let mut y = PAGE_H - MARGIN_T;

    // Cover
    doc.text(
        "Fleet Compliance Report",
        SIZE_TITLE,
        MARGIN_L,
        y,
        Face::Bold,
    );
    y -= LH * 1.6;
    doc.text(
        generated_at
            .format("Generated %Y-%m-%d %H:%M UTC")
            .to_string(),
        SIZE_BODY,
        MARGIN_L,
        y,
        Face::Italic,
    );
    y -= LH * 0.8;
    doc.text(
        format!("Window: last {range_days} days"),
        SIZE_SMALL,
        MARGIN_L,
        y,
        Face::Italic,
    );
    y -= LH * 2.0;

    // Fleet KPIs
    doc.text("Fleet snapshot", SIZE_H2, MARGIN_L, y, Face::Bold);
    y -= LH * 1.4;
    let kpis = [
        ("Assets", summary.assets.to_string()),
        ("Applied STIGs", summary.checklists.to_string()),
        ("Compliance", format!("{:.1}%", summary.compliance_score)),
        ("Open findings", summary.open_findings.to_string()),
        ("Overdue findings", summary.overdue_findings.to_string()),
        (
            "Top-risk system",
            match (&summary.top_asset_name, summary.top_asset_score) {
                (Some(n), Some(s)) => format!("{n} ({s} open)"),
                _ => "—".to_string(),
            },
        ),
    ];
    for (k, v) in &kpis {
        doc.text(format!("{k}:"), SIZE_BODY, MARGIN_L, y, Face::Bold);
        doc.text(v, SIZE_BODY, MARGIN_L + 32.0, y, Face::Regular);
        y -= LH;
    }
    y -= LH;

    // Per-asset table
    doc.text(
        "Per-system summary (top 20 by open count)",
        SIZE_H2,
        MARGIN_L,
        y,
        Face::Bold,
    );
    y -= LH * 1.4;
    doc.text("System", SIZE_SMALL, MARGIN_L, y, Face::Bold);
    doc.text("Classification", SIZE_SMALL, MARGIN_L + 55.0, y, Face::Bold);
    doc.text("Owner", SIZE_SMALL, MARGIN_L + 95.0, y, Face::Bold);
    doc.text("Compl.", SIZE_SMALL, MARGIN_L + 130.0, y, Face::Bold);
    doc.text("Open", SIZE_SMALL, MARGIN_L + 160.0, y, Face::Bold);
    y -= LH;

    if assets.is_empty() {
        doc.text("No systems yet.", SIZE_BODY, MARGIN_L, y, Face::Italic);
        y -= LH;
    } else {
        for a in assets {
            if y < MARGIN_B + LH * 4.0 {
                doc.add_page();
                y = PAGE_H - MARGIN_T;
            }
            doc.text(truncate(&a.name, 28), SIZE_BODY, MARGIN_L, y, Face::Regular);
            doc.text(
                &a.classification,
                SIZE_BODY,
                MARGIN_L + 55.0,
                y,
                Face::Regular,
            );
            doc.text(
                truncate(&a.owner_name, 16),
                SIZE_BODY,
                MARGIN_L + 95.0,
                y,
                Face::Regular,
            );
            doc.text(
                format!("{:.1}%", a.compliance_score),
                SIZE_BODY,
                MARGIN_L + 130.0,
                y,
                Face::Regular,
            );
            doc.text(
                a.open_count.to_string(),
                SIZE_BODY,
                MARGIN_L + 160.0,
                y,
                Face::Regular,
            );
            y -= LH;
        }
    }
    y -= LH;

    // Top open rules
    if y < MARGIN_B + LH * 6.0 {
        doc.add_page();
        y = PAGE_H - MARGIN_T;
    }
    doc.text(
        "Top open rules across the fleet",
        SIZE_H2,
        MARGIN_L,
        y,
        Face::Bold,
    );
    y -= LH * 1.4;
    if top_rules.is_empty() {
        doc.text("No open findings.", SIZE_BODY, MARGIN_L, y, Face::Italic);
    } else {
        for r in top_rules {
            doc.text(&r.rule_id, SIZE_BODY, MARGIN_L, y, Face::Regular);
            doc.text(
                format!("{} affected", r.affected),
                SIZE_BODY,
                MARGIN_L + 80.0,
                y,
                Face::Regular,
            );
            y -= LH;
        }
    }

    doc
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// GET /api/reports — list recent reports.
pub async fn list_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<ComplianceReportRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, ComplianceReportRow>(
        "SELECT id, generated_at, range_days, summary, pdf_path \
         FROM compliance_reports ORDER BY generated_at DESC LIMIT 50",
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        tracing::error!("compliance reports list failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(rows))
}

/// GET /api/reports/:id/report.pdf — stream the PDF bytes.
pub async fn download_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT pdf_path FROM compliance_reports WHERE id = $1")
            .bind(&id)
            .fetch_optional(state.pool.as_ref())
            .await
            .map_err(|e| {
                tracing::error!("compliance report download lookup failed: {e:#}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    let pdf_path = match row {
        Some((p,)) => p,
        None => return Err(StatusCode::NOT_FOUND),
    };
    let abs: PathBuf = state.config.data_dir.join(&pdf_path);
    let bytes = tokio::fs::read(&abs).await.map_err(|e| {
        tracing::error!("compliance report file read failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/pdf"),
        )
        .header(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("inline; filename=\"compliance-{id}.pdf\""))
                .unwrap_or_else(|_| HeaderValue::from_static("inline")),
        )
        .body(bytes.into())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::td_operator;

    fn summary() -> ReportSummary {
        ReportSummary {
            assets: 0,
            checklists: 0,
            compliance_score: 0.0,
            open_findings: 0,
            overdue_findings: 0,
            top_asset_name: None,
            top_asset_score: None,
        }
    }

    fn all_text(doc: &TextDoc) -> Vec<String> {
        (0..doc.page_count())
            .flat_map(|p| doc.page_runs(p).iter().map(|r| r.text.clone()))
            .collect()
    }

    #[test]
    fn empty_fleet_layout() {
        let doc = layout_report(&summary(), &[], &[], 30, Utc::now());
        let t = all_text(&doc);
        assert!(t.iter().any(|s| s == "No systems yet."));
        assert!(t.iter().any(|s| s == "No open findings."));
        assert_eq!(doc.page_count(), 1);
        let runs = doc.page_runs(0);
        let k = runs.iter().find(|r| r.text == "Assets:").unwrap();
        assert_eq!((k.face, k.x_mm), (Face::Bold, MARGIN_L));
        let v = runs.iter().find(|r| r.text == "0").unwrap();
        assert_eq!((v.face, v.x_mm), (Face::Regular, MARGIN_L + 32.0));
    }

    #[test]
    fn many_assets_overflow_to_second_page() {
        let assets: Vec<AssetLine> = (0..80)
            .map(|i| AssetLine {
                name: format!("asset-{i}"),
                classification: "U".into(),
                owner_name: "Owner".into(),
                open_count: i,
                compliance_score: 50.0,
            })
            .collect();
        let doc = layout_report(&summary(), &assets, &[], 30, Utc::now());
        assert!(doc.page_count() >= 2);
        assert!(all_text(&doc).iter().any(|s| s == "Classification"));
    }

    /// Sample generator for the real-viewer checks (#98).
    ///
    /// Always builds and asserts on the bytes; writes `fleet-compliance-sample.pdf` only when
    /// `PDF_SAMPLE_DIR` is set. From `backend/`:
    /// `PDF_SAMPLE_DIR=/some/dir cargo test --locked pdf_sample`
    ///
    /// Look for: em dash, middle dot and ellipsis render as glyphs; CJK and
    /// emoji show as `?`; the Title metadata keeps Unicode.
    ///
    /// The fixture passes 45 rows straight to `layout_report`, more than the
    /// production top-20 cap, so the 2-page layout is exercised. The heading
    /// saying "top 20" above 45 rows is expected.
    #[test]
    fn pdf_sample_fleet_report() {
        let mut sum = summary();
        sum.assets = 45;
        sum.top_asset_name = Some("db-01 — 漢 😀".into());
        sum.top_asset_score = Some(7);
        let assets: Vec<AssetLine> = (0..45)
            .map(|i| AssetLine {
                name: if i == 3 {
                    "a-very-long-system-name-that-needs-truncation".into()
                } else {
                    format!("asset-{i}")
                },
                classification: "U".into(),
                owner_name: match i {
                    4 => "Owner With A Very Long Name".into(),
                    5 => "漢字 😀 owner".into(),
                    _ => "Owner".into(),
                },
                open_count: i,
                compliance_score: 50.0,
            })
            .collect();
        let rules = [
            TopRuleLine {
                rule_id: "SV-1r1_rule".into(),
                affected: 12,
            },
            TopRuleLine {
                rule_id: "SV-2r1_rule".into(),
                affected: 3,
            },
        ];
        let ts = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mut doc = layout_report(&sum, &assets, &rules, 30, ts);
        assert!(doc.page_count() >= 2);
        assert!(all_text(&doc).iter().any(|s| s.contains('…')));
        doc.text("—·…漢😀", SIZE_SMALL, MARGIN_L, 10.0, Face::Regular);
        let bytes = doc.finish();
        assert!(bytes.starts_with(b"%PDF-"));
        let s = String::from_utf8_lossy(&bytes);
        let kpi_y = PAGE_H - MARGIN_T - LH * 1.6 - LH * 0.8 - LH * 2.0 - LH * 1.4;
        assert!(s.contains(&td_operator(MARGIN_L + 32.0, kpi_y)));
        let lower = s.to_lowercase();
        assert!(lower.contains("<97b7853f3f> tj"));
        if let Some(dir) = std::env::var_os("PDF_SAMPLE_DIR") {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                std::path::Path::new(&dir).join("fleet-compliance-sample.pdf"),
                &bytes,
            )
            .unwrap();
        }
    }
}
