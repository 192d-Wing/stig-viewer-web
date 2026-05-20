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

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::Response,
    Json,
};
use chrono::{DateTime, Utc};
use printpdf::{BuiltinFont, Mm, PdfDocument};
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::path::PathBuf;
use uuid::Uuid;

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
    let id = Uuid::new_v4().to_string();
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
    let (doc, page, layer) = PdfDocument::new(
        "Fleet Compliance Report",
        Mm(PAGE_W),
        Mm(PAGE_H),
        "Layer 1",
    );
    let f_reg = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let f_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let f_italic = doc.add_builtin_font(BuiltinFont::HelveticaOblique)?;

    let mut layer_ref = doc.get_page(page).get_layer(layer);
    let mut y = PAGE_H - MARGIN_T;

    // Cover
    layer_ref.use_text("Fleet Compliance Report", SIZE_TITLE, Mm(MARGIN_L), Mm(y), &f_bold);
    y -= LH * 1.6;
    layer_ref.use_text(
        &Utc::now().format("Generated %Y-%m-%d %H:%M UTC").to_string(),
        SIZE_BODY,
        Mm(MARGIN_L),
        Mm(y),
        &f_italic,
    );
    y -= LH * 0.8;
    layer_ref.use_text(
        &format!("Window: last {range_days} days"),
        SIZE_SMALL,
        Mm(MARGIN_L),
        Mm(y),
        &f_italic,
    );
    y -= LH * 2.0;

    // Fleet KPIs
    layer_ref.use_text("Fleet snapshot", SIZE_H2, Mm(MARGIN_L), Mm(y), &f_bold);
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
        layer_ref.use_text(&format!("{k}:"), SIZE_BODY, Mm(MARGIN_L), Mm(y), &f_bold);
        layer_ref.use_text(v, SIZE_BODY, Mm(MARGIN_L + 32.0), Mm(y), &f_reg);
        y -= LH;
    }
    y -= LH;

    // Per-asset table
    layer_ref.use_text(
        "Per-system summary (top 20 by open count)",
        SIZE_H2,
        Mm(MARGIN_L),
        Mm(y),
        &f_bold,
    );
    y -= LH * 1.4;
    layer_ref.use_text("System", SIZE_SMALL, Mm(MARGIN_L), Mm(y), &f_bold);
    layer_ref.use_text("Classification", SIZE_SMALL, Mm(MARGIN_L + 55.0), Mm(y), &f_bold);
    layer_ref.use_text("Owner", SIZE_SMALL, Mm(MARGIN_L + 95.0), Mm(y), &f_bold);
    layer_ref.use_text("Compl.", SIZE_SMALL, Mm(MARGIN_L + 130.0), Mm(y), &f_bold);
    layer_ref.use_text("Open", SIZE_SMALL, Mm(MARGIN_L + 160.0), Mm(y), &f_bold);
    y -= LH;

    if assets.is_empty() {
        layer_ref.use_text("No systems yet.", SIZE_BODY, Mm(MARGIN_L), Mm(y), &f_italic);
        y -= LH;
    } else {
        for a in assets {
            if y < MARGIN_B + LH * 4.0 {
                let (np, nl) = doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "Layer");
                layer_ref = doc.get_page(np).get_layer(nl);
                y = PAGE_H - MARGIN_T;
            }
            layer_ref.use_text(&truncate(&a.name, 28), SIZE_BODY, Mm(MARGIN_L), Mm(y), &f_reg);
            layer_ref.use_text(
                &a.classification,
                SIZE_BODY,
                Mm(MARGIN_L + 55.0),
                Mm(y),
                &f_reg,
            );
            layer_ref.use_text(
                &truncate(&a.owner_name, 16),
                SIZE_BODY,
                Mm(MARGIN_L + 95.0),
                Mm(y),
                &f_reg,
            );
            layer_ref.use_text(
                &format!("{:.1}%", a.compliance_score),
                SIZE_BODY,
                Mm(MARGIN_L + 130.0),
                Mm(y),
                &f_reg,
            );
            layer_ref.use_text(
                &a.open_count.to_string(),
                SIZE_BODY,
                Mm(MARGIN_L + 160.0),
                Mm(y),
                &f_reg,
            );
            y -= LH;
        }
    }
    y -= LH;

    // Top open rules
    if y < MARGIN_B + LH * 6.0 {
        let (np, nl) = doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "Layer");
        layer_ref = doc.get_page(np).get_layer(nl);
        y = PAGE_H - MARGIN_T;
    }
    layer_ref.use_text(
        "Top open rules across the fleet",
        SIZE_H2,
        Mm(MARGIN_L),
        Mm(y),
        &f_bold,
    );
    y -= LH * 1.4;
    if top_rules.is_empty() {
        layer_ref.use_text("No open findings.", SIZE_BODY, Mm(MARGIN_L), Mm(y), &f_italic);
    } else {
        for r in top_rules {
            layer_ref.use_text(&r.rule_id, SIZE_BODY, Mm(MARGIN_L), Mm(y), &f_reg);
            layer_ref.use_text(
                &format!("{} affected", r.affected),
                SIZE_BODY,
                Mm(MARGIN_L + 80.0),
                Mm(y),
                &f_reg,
            );
            y -= LH;
        }
    }

    Ok(doc.save_to_bytes()?)
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
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT pdf_path FROM compliance_reports WHERE id = $1",
    )
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
        .header(header::CONTENT_TYPE, HeaderValue::from_static("application/pdf"))
        .header(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("inline; filename=\"compliance-{id}.pdf\""))
                .unwrap_or_else(|_| HeaderValue::from_static("inline")),
        )
        .body(bytes.into())
        .unwrap())
}
