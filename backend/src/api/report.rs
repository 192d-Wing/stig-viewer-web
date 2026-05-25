use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use printpdf::{BuiltinFont, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use std::path::Path as StdPath;

use crate::config::Config;
use crate::db_assets;
use crate::db_attachments;
use crate::db_checklists;
use crate::severity::weighted_score;
use crate::AppState;

/// Result of a successful per-asset PDF build — the rendered bytes plus
/// the asset name (callers want it for filenames, email subjects, etc.).
pub(crate) struct BuiltAssetReport {
    pub asset_name: String,
    pub pdf_bytes: Vec<u8>,
}

// ── Layout constants ────────────────────────────────────────────────────────
const PAGE_W: f32 = 210.0; // A4 mm
const PAGE_H: f32 = 297.0;
const MARGIN_L: f32 = 18.0;
#[allow(dead_code)]
const MARGIN_R: f32 = 18.0;
const MARGIN_T: f32 = 18.0;
const MARGIN_B: f32 = 22.0; // leaves room for footer

const SIZE_TITLE: f32 = 18.0;
const SIZE_H2: f32 = 13.0;
const SIZE_BODY: f32 = 9.5;
const SIZE_SMALL: f32 = 8.0;

const LH_BODY: f32 = 4.8; // line height in mm

const STATUS_LABEL: &[(&str, &str)] = &[
    ("open", "Open"),
    ("not_a_finding", "Not a finding"),
    ("not_applicable", "Not applicable"),
    ("not_reviewed", "Not reviewed"),
];

fn status_label(status: &str) -> &'static str {
    STATUS_LABEL
        .iter()
        .find(|(v, _)| *v == status)
        .map(|(_, l)| *l)
        .unwrap_or("—")
}

/// GET /api/assets/:id/report.pdf — auditor-ready PDF for one asset.
pub async fn report_handler(
    State(state): State<AppState>,
    Path(asset_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let built = build_asset_report(state.pool.as_ref(), &state.config.data_dir, &asset_id)
        .await
        .map_err(|e| {
            tracing::error!("build_asset_report failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    let filename = sanitize_filename(&format!("{}-stig-report.pdf", built.asset_name));
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/pdf"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok((headers, built.pdf_bytes))
}

/// Build the per-asset compliance PDF without going through HTTP. Used by
/// both the `GET /api/assets/:id/report.pdf` handler and the on-demand
/// email-send path. Returns `Ok(None)` when the asset doesn't exist so
/// callers can map that to a 404 cleanly.
pub(crate) async fn build_asset_report(
    pool: &PgPool,
    data_dir: &StdPath,
    asset_id: &str,
) -> anyhow::Result<Option<BuiltAssetReport>> {
    let asset = match db_assets::get_asset(pool, asset_id).await? {
        Some(a) => a,
        None => return Ok(None),
    };

    let owner_name: String = sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1")
        .bind(&asset.owner_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or_else(|| asset.owner_id.clone());

    let checklists = db_checklists::list_checklists_for_asset(pool, asset_id).await?;

    // For each checklist, read its STIG JSON + overrides, build summary +
    // rule rows.
    let mut sections: Vec<ChecklistSection> = Vec::new();
    for c in &checklists {
        let stig = load_stig_json_from_dir(data_dir, &c.stig_id).await;
        let rules = stig
            .as_ref()
            .and_then(|v| v.get("rules"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let stig_title = stig
            .as_ref()
            .and_then(|v| v.get("title"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| c.stig_id.clone());

        let overrides = db_checklists::list_rule_overrides(pool, &c.id).await?;
        let over_by_id: HashMap<String, db_checklists::ChecklistRuleRow> = overrides
            .into_iter()
            .map(|r| (r.rule_id.clone(), r))
            .collect();

        // Attachment counts per rule. Findings with N>0 get an
        // "Attachments: N" line in the PDF body.
        let attachment_counts = db_attachments::counts_for_checklist(pool, &c.id).await?;
        let attachments_by_rule: HashMap<String, i64> = attachment_counts
            .into_iter()
            .map(|r| (r.rule_id, r.count))
            .collect();

        let today = Utc::now().date_naive();
        let mut rule_rows: Vec<RuleSummary> = Vec::new();
        let (mut open, mut naf, mut na, mut not_reviewed) = (0, 0, 0, 0);
        for rule in &rules {
            let rid = rule
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let title = rule
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let severity = rule
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("—")
                .to_string();
            let (status, finding_details, due_date) = match over_by_id.get(&rid) {
                Some(o) => (o.status.clone(), o.finding_details.clone(), o.due_date),
                None => ("not_reviewed".to_string(), String::new(), None),
            };
            match status.as_str() {
                "open" => open += 1,
                "not_a_finding" => naf += 1,
                "not_applicable" => na += 1,
                _ => not_reviewed += 1,
            }
            let attachments = attachments_by_rule.get(&rid).copied().unwrap_or(0);
            let weighted = weighted_score(
                &severity,
                &asset.classification,
                &status,
                due_date,
                today,
            );
            rule_rows.push(RuleSummary {
                id: rid,
                title,
                severity,
                status,
                finding_details,
                attachments,
                weighted_score: weighted,
            });
        }

        sections.push(ChecklistSection {
            stig_id: c.stig_id.clone(),
            stig_title,
            total: rules.len(),
            open,
            naf,
            na,
            not_reviewed,
            rules: rule_rows,
        });
    }

    let pdf_bytes = render_pdf(&asset, &owner_name, &sections)?;
    Ok(Some(BuiltAssetReport {
        asset_name: asset.name,
        pdf_bytes,
    }))
}

/// Convenience that drops the `Config` borrow for callers that already
/// have one — keeps the public surface narrow.
#[allow(dead_code)]
pub(crate) async fn build_asset_report_with_config(
    pool: &PgPool,
    config: &Config,
    asset_id: &str,
) -> anyhow::Result<Option<BuiltAssetReport>> {
    build_asset_report(pool, &config.data_dir, asset_id).await
}

// ── Data shapes ─────────────────────────────────────────────────────────────

struct ChecklistSection {
    #[allow(dead_code)]
    stig_id: String,
    stig_title: String,
    total: usize,
    open: usize,
    naf: usize,
    na: usize,
    not_reviewed: usize,
    rules: Vec<RuleSummary>,
}

struct RuleSummary {
    id: String,
    title: String,
    severity: String,
    status: String,
    finding_details: String,
    attachments: i64,
    /// SCAP-style weighted score (see `crate::severity::weighted_score`).
    /// Rendered as a "weight: N.N" annotation in the body.
    weighted_score: f64,
}

// ── PDF rendering ───────────────────────────────────────────────────────────

fn render_pdf(
    asset: &db_assets::AssetRow,
    owner_name: &str,
    sections: &[ChecklistSection],
) -> anyhow::Result<Vec<u8>> {
    let (doc, page, layer) = PdfDocument::new(
        format!("STIG report — {}", asset.name),
        Mm(PAGE_W),
        Mm(PAGE_H),
        "Layer 1",
    );
    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_italic = doc.add_builtin_font(BuiltinFont::HelveticaOblique)?;

    let fonts = Fonts {
        regular: font_regular,
        bold: font_bold,
        italic: font_italic,
    };

    // Inner scope so `state` drops (releasing the borrow on `doc`) before
    // we call save_to_bytes(self).
    {
        let mut state = PageState {
            layer: doc.get_page(page).get_layer(layer),
            y: PAGE_H - MARGIN_T,
            doc: &doc,
        };

        // ── Cover ───────────────────────────────────────────────────────────
        state.text("STIG Compliance Report", SIZE_TITLE, &fonts.bold);
        state.advance(8.0);
        state.text(&asset.name, SIZE_H2, &fonts.bold);
        state.advance(LH_BODY);

        state.kv("Hostname", if asset.hostname.is_empty() { "—" } else { &asset.hostname }, &fonts);
        state.kv("Classification", &asset.classification, &fonts);
        state.kv("Owner", owner_name, &fonts);
        state.kv(
            "Generated",
            &Utc::now().format("%Y-%m-%d %H:%M UTC").to_string(),
            &fonts,
        );
        if !asset.description.is_empty() {
            state.advance(LH_BODY);
            state.text("Description", SIZE_SMALL, &fonts.bold);
            state.advance(LH_BODY * 0.6);
            state.wrapped(&asset.description, SIZE_BODY, &fonts.regular, 95);
        }

        if sections.is_empty() {
            state.advance(8.0);
            state.text("No STIGs applied to this system.", SIZE_BODY, &fonts.italic);
        } else {
            for section in sections {
                state.ensure_room(20.0, &fonts);
                state.advance(8.0);
                state.text(&section.stig_title, SIZE_H2, &fonts.bold);
                state.advance(LH_BODY * 0.6);
                state.text(
                    &format!(
                        "{} rules · {} open · {} not a finding · {} N/A · {} not reviewed",
                        section.total, section.open, section.naf, section.na, section.not_reviewed,
                    ),
                    SIZE_SMALL,
                    &fonts.italic,
                );
                state.advance(LH_BODY);

                for rule in &section.rules {
                    // Estimate space needed: 3 lines body + optional
                    // finding-details wrap. ensure_room paginates if we'd
                    // overflow.
                    let needed = LH_BODY * 3.0
                        + if rule.finding_details.is_empty() {
                            0.0
                        } else {
                            LH_BODY * 2.0
                        };
                    state.ensure_room(needed, &fonts);

                    state.text(
                        &format!("{} — {}", rule.id, status_label(&rule.status)),
                        SIZE_BODY,
                        &fonts.bold,
                    );
                    state.advance(LH_BODY * 0.7);
                    state.text(
                        &format!(
                            "Severity: {} · weight: {:.1}",
                            rule.severity, rule.weighted_score
                        ),
                        SIZE_SMALL,
                        &fonts.regular,
                    );
                    state.advance(LH_BODY * 0.7);
                    if rule.attachments > 0 {
                        state.text(
                            &format!("Attachments: {}", rule.attachments),
                            SIZE_SMALL,
                            &fonts.regular,
                        );
                        state.advance(LH_BODY * 0.7);
                    }
                    if !rule.title.is_empty() {
                        state.wrapped(&rule.title, SIZE_BODY, &fonts.regular, 95);
                    }
                    if !rule.finding_details.is_empty() {
                        state.advance(LH_BODY * 0.4);
                        state.text("Finding details:", SIZE_SMALL, &fonts.bold);
                        state.advance(LH_BODY * 0.5);
                        let truncated = truncate(&rule.finding_details, 200);
                        state.wrapped(&truncated, SIZE_SMALL, &fonts.italic, 100);
                    }
                    state.advance(LH_BODY * 0.6);
                }
            }
        }
    }

    Ok(doc.save_to_bytes()?)
}

struct Fonts {
    regular: printpdf::IndirectFontRef,
    bold: printpdf::IndirectFontRef,
    italic: printpdf::IndirectFontRef,
}

struct PageState<'a> {
    layer: PdfLayerReference,
    y: f32,
    doc: &'a PdfDocumentReference,
}

impl<'a> PageState<'a> {
    fn text(&self, s: &str, size: f32, font: &printpdf::IndirectFontRef) {
        self.layer.use_text(s, size, Mm(MARGIN_L), Mm(self.y), font);
    }

    fn advance(&mut self, dy: f32) {
        self.y -= dy;
    }

    fn kv(&mut self, key: &str, value: &str, fonts: &Fonts) {
        self.layer.use_text(
            &format!("{key}: "),
            SIZE_BODY,
            Mm(MARGIN_L),
            Mm(self.y),
            &fonts.bold,
        );
        self.layer.use_text(
            value,
            SIZE_BODY,
            Mm(MARGIN_L + 28.0),
            Mm(self.y),
            &fonts.regular,
        );
        self.advance(LH_BODY);
    }

    /// Wrap text at approximately `max_chars` characters per line.
    /// Imperfect (Helvetica is proportional) but adequate for body text.
    fn wrapped(
        &mut self,
        text: &str,
        size: f32,
        font: &printpdf::IndirectFontRef,
        max_chars: usize,
    ) {
        let mut line = String::new();
        for word in text.split_whitespace() {
            if line.is_empty() {
                line.push_str(word);
            } else if line.len() + 1 + word.len() <= max_chars {
                line.push(' ');
                line.push_str(word);
            } else {
                self.layer
                    .use_text(&line, size, Mm(MARGIN_L), Mm(self.y), font);
                self.advance(LH_BODY * 0.85);
                line.clear();
                line.push_str(word);
            }
        }
        if !line.is_empty() {
            self.layer
                .use_text(&line, size, Mm(MARGIN_L), Mm(self.y), font);
            self.advance(LH_BODY * 0.85);
        }
    }

    fn ensure_room(&mut self, needed: f32, _fonts: &Fonts) {
        if self.y - needed < MARGIN_B {
            let (page, layer) = self
                .doc
                .add_page(Mm(PAGE_W), Mm(PAGE_H), "Layer");
            self.layer = self.doc.get_page(page).get_layer(layer);
            self.y = PAGE_H - MARGIN_T;
        }
    }
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

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '-' })
        .collect()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn load_stig_json_from_dir(data_dir: &StdPath, stig_id: &str) -> Option<Value> {
    if !stig_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return None;
    }
    let path = data_dir.join("stigs").join(format!("{stig_id}.json"));
    let contents = tokio::fs::read_to_string(&path).await.ok()?;
    serde_json::from_str(&contents).ok()
}

pub(crate) fn sanitize_report_filename(s: &str) -> String {
    sanitize_filename(s)
}
