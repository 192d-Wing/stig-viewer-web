use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Cursor, Write};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

use crate::db_assets;
use crate::db_attachments;
use crate::db_checklists;
use crate::AppState;

/// GET /api/assets/:id/bundle.zip — streams a ZIP bundle of a single
/// asset's CKL files (one per applied STIG) plus all evidence
/// attachments. Auth posture matches `report.rs`: any authenticated
/// user can fetch.
pub async fn bundle_handler(
    State(state): State<AppState>,
    Path(asset_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let pool = state.pool.as_ref();

    let asset = db_assets::get_asset(pool, &asset_id)
        .await
        .map_err(map_db)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let checklists = db_checklists::list_checklists_for_asset(pool, &asset_id)
        .await
        .map_err(map_db)?;

    // Build a section per checklist: STIG metadata + rule data + overrides.
    // We do this up front so the zip-writing loop is pure CPU/IO without
    // further awaits inside.
    let mut sections: Vec<ChecklistSection> = Vec::new();
    for c in &checklists {
        let stig = load_stig_json(&state, &c.stig_id).await;

        let overrides = db_checklists::list_rule_overrides(pool, &c.id)
            .await
            .map_err(map_db)?;
        let over_by_id: HashMap<String, db_checklists::ChecklistRuleRow> = overrides
            .into_iter()
            .map(|r| (r.rule_id.clone(), r))
            .collect();

        sections.push(ChecklistSection {
            stig_id: c.stig_id.clone(),
            stig_json: stig,
            overrides: over_by_id,
        });
    }

    // Attachments for all checklists on this asset, with disk paths
    // resolved up-front.
    let mut attachment_entries: Vec<AttachmentEntry> = Vec::new();
    for c in &checklists {
        let rows = db_attachments::list_for_checklist(pool, &c.id)
            .await
            .map_err(map_db)?;
        for row in rows {
            let blob_path = state.config.data_dir.join("attachments").join(&row.id);
            attachment_entries.push(AttachmentEntry {
                checklist_id: row.checklist_id.clone(),
                rule_id: row.rule_id.clone(),
                filename: row.filename.clone(),
                sha256: row.sha256.clone(),
                size_bytes: row.size_bytes,
                blob_path,
            });
        }
    }

    let host = if asset.hostname.is_empty() {
        asset.name.clone()
    } else {
        asset.hostname.clone()
    };

    let zip_bytes = tokio::task::spawn_blocking(move || build_zip(host, sections, attachment_entries))
        .await
        .map_err(|e| {
            tracing::error!("bundle join error: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map_err(|e| {
            tracing::error!("bundle build failed: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let filename = sanitize_filename(&format!("{}-bundle.zip", asset.name));
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/zip"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok((headers, zip_bytes))
}

// ── Data shapes ─────────────────────────────────────────────────────────────

struct ChecklistSection {
    stig_id: String,
    stig_json: Option<Value>,
    overrides: HashMap<String, db_checklists::ChecklistRuleRow>,
}

struct AttachmentEntry {
    checklist_id: String,
    rule_id: String,
    filename: String,
    sha256: String,
    size_bytes: i64,
    blob_path: std::path::PathBuf,
}

// ── ZIP assembly ────────────────────────────────────────────────────────────

struct ManifestEntry {
    path: String,
    size: u64,
    sha256: Option<String>,
}

fn build_zip(
    host: String,
    sections: Vec<ChecklistSection>,
    attachments: Vec<AttachmentEntry>,
) -> anyhow::Result<Vec<u8>> {
    let buf: Vec<u8> = Vec::new();
    let cursor = Cursor::new(buf);
    let mut zip = ZipWriter::new(cursor);
    // Use Deflated by default. STIG XML compresses well; small attachments
    // (already compressed: PDFs/PNGs) are fine since deflate falls through.
    let options: SimpleFileOptions = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    let mut manifest: Vec<ManifestEntry> = Vec::new();

    // CKL files — one per applied STIG.
    for section in &sections {
        let ckl_xml = render_ckl(&host, section);
        let path = format!("checklists/{}.ckl", sanitize_segment(&section.stig_id));
        zip.start_file(&path, options)?;
        zip.write_all(ckl_xml.as_bytes())?;
        manifest.push(ManifestEntry {
            path: path.clone(),
            size: ckl_xml.len() as u64,
            sha256: None,
        });
    }

    // Attachments — packed as attachments/<checklist_id>/<rule_id>/<filename>.
    for att in &attachments {
        let path = format!(
            "attachments/{}/{}/{}",
            sanitize_segment(&att.checklist_id),
            sanitize_segment(&att.rule_id),
            sanitize_segment(&att.filename),
        );
        // Read the blob synchronously since we're inside spawn_blocking.
        let bytes = match std::fs::read(&att.blob_path) {
            Ok(b) => b,
            Err(e) => {
                // Skip missing blobs but log; row exists without on-disk file.
                tracing::warn!(
                    "bundle: missing attachment blob {} ({e:#})",
                    att.blob_path.display()
                );
                continue;
            }
        };
        zip.start_file(&path, options)?;
        zip.write_all(&bytes)?;
        manifest.push(ManifestEntry {
            path,
            size: att.size_bytes.max(0) as u64,
            sha256: Some(att.sha256.clone()),
        });
    }

    // MANIFEST.txt at the root — one line per file (path, size, sha256?).
    let mut manifest_txt = String::new();
    manifest_txt.push_str("# STIG bundle manifest\n");
    manifest_txt.push_str("# path\tsize_bytes\tsha256\n");
    for e in &manifest {
        manifest_txt.push_str(&e.path);
        manifest_txt.push('\t');
        manifest_txt.push_str(&e.size.to_string());
        manifest_txt.push('\t');
        manifest_txt.push_str(e.sha256.as_deref().unwrap_or("-"));
        manifest_txt.push('\n');
    }
    zip.start_file("MANIFEST.txt", options)?;
    zip.write_all(manifest_txt.as_bytes())?;

    let cursor = zip.finish()?;
    Ok(cursor.into_inner())
}

// ── CKL rendering ──────────────────────────────────────────────────────────
//
// Ported from `src/utils/exportCKL.js`. Keep field order + casing
// faithful so DISA STIG Viewer can ingest the output.

fn render_ckl(hostname: &str, section: &ChecklistSection) -> String {
    let stig_obj = section.stig_json.as_ref();
    let title = stig_obj
        .and_then(|v| v.get("title"))
        .and_then(|v| v.as_str())
        .unwrap_or(&section.stig_id);
    let version = stig_obj
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let release_info = stig_obj
        .and_then(|v| v.get("releaseInfo"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let rules = stig_obj
        .and_then(|v| v.get("rules"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<!--DISA STIG Viewer :: Web STIG Tools Export-->\n");
    out.push_str("<CHECKLIST>\n");
    out.push_str("  <ASSET>\n");
    out.push_str("    <ROLE>None</ROLE>\n");
    out.push_str("    <ASSET_TYPE>Computing</ASSET_TYPE>\n");
    out.push_str(&format!(
        "    <HOST_NAME>{}</HOST_NAME>\n",
        esc_xml(hostname)
    ));
    out.push_str("    <HOST_IP></HOST_IP>\n");
    out.push_str("    <HOST_MAC></HOST_MAC>\n");
    out.push_str("    <HOST_FQDN></HOST_FQDN>\n");
    out.push_str("    <TARGET_COMMENT></TARGET_COMMENT>\n");
    out.push_str("    <TECH_AREA></TECH_AREA>\n");
    out.push_str("    <TARGET_KEY></TARGET_KEY>\n");
    out.push_str("    <WEB_OR_DATABASE>false</WEB_OR_DATABASE>\n");
    out.push_str("    <WEB_DB_SITE></WEB_DB_SITE>\n");
    out.push_str("    <WEB_DB_INSTANCE></WEB_DB_INSTANCE>\n");
    out.push_str("  </ASSET>\n");
    out.push_str("  <STIGS>\n");
    out.push_str("    <iSTIG>\n");
    out.push_str("      <STIG_INFO>\n");
    out.push_str(&si_data("title", title));
    out.push_str(&si_data("version", version));
    out.push_str(&si_data("releaseinfo", release_info));
    out.push_str("      </STIG_INFO>\n");

    for rule in &rules {
        out.push_str("      <VULN>\n");
        let get = |k: &str| -> String {
            rule.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let rid = get("id");
        let stig_id_field = get("stigId");
        let severity = get("severity");
        let group_id = get("groupId");
        let rule_title = get("title");
        let description = get("description");
        let check_text = get("checkText");
        let fix_text = get("fixText");

        out.push_str(&stig_data("Vuln_Num", &stig_id_field));
        out.push_str(&stig_data("Severity", sev_to_ckl(&severity)));
        out.push_str(&stig_data("Group_Title", &group_id));
        out.push_str(&stig_data("Rule_ID", &rid));
        out.push_str(&stig_data("Rule_Title", &rule_title));
        out.push_str(&stig_data("Vuln_Discuss", &description));
        out.push_str(&stig_data("Check_Content", &check_text));
        out.push_str(&stig_data("Fix_Text", &fix_text));

        // CCI refs: rule.cciIds is an array of strings.
        if let Some(arr) = rule.get("cciIds").and_then(|v| v.as_array()) {
            for cci in arr {
                if let Some(s) = cci.as_str() {
                    out.push_str(&stig_data("CCI_REF", s));
                }
            }
        }

        let (status, finding_details, comments) = match section.overrides.get(&rid) {
            Some(o) => (
                status_to_ckl(&o.status),
                o.finding_details.clone(),
                o.comments.clone(),
            ),
            None => ("Not_Reviewed", String::new(), String::new()),
        };
        out.push_str(&format!("        <STATUS>{}</STATUS>\n", status));
        out.push_str(&format!(
            "        <FINDING_DETAILS>{}</FINDING_DETAILS>\n",
            esc_xml(&finding_details)
        ));
        out.push_str(&format!(
            "        <COMMENTS>{}</COMMENTS>\n",
            esc_xml(&comments)
        ));
        out.push_str("        <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>\n");
        out.push_str("        <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>\n");
        out.push_str("      </VULN>\n");
    }

    out.push_str("    </iSTIG>\n");
    out.push_str("  </STIGS>\n");
    out.push_str("</CHECKLIST>\n");
    out
}

fn si_data(name: &str, val: &str) -> String {
    format!(
        "        <SI_DATA><SID_NAME>{}</SID_NAME><SID_DATA>{}</SID_DATA></SI_DATA>\n",
        esc_xml(name),
        esc_xml(val),
    )
}

fn stig_data(name: &str, val: &str) -> String {
    format!(
        "        <STIG_DATA><VULN_ATTRIBUTE>{}</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{}</ATTRIBUTE_DATA></STIG_DATA>\n",
        esc_xml(name),
        esc_xml(val),
    )
}

/// Map our `severity` ("CAT I"/"CAT II"/"CAT III") to CKL low/medium/high.
fn sev_to_ckl(sev: &str) -> &'static str {
    match sev {
        "CAT I" => "high",
        "CAT II" => "medium",
        "CAT III" => "low",
        _ => "medium",
    }
}

/// Map our internal status string to CKL status.
fn status_to_ckl(status: &str) -> &'static str {
    match status {
        "open" => "Open",
        "not_a_finding" => "NotAFinding",
        "not_applicable" => "Not_Applicable",
        "not_reviewed" => "Not_Reviewed",
        _ => "Not_Reviewed",
    }
}

fn esc_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn load_stig_json(state: &AppState, stig_id: &str) -> Option<Value> {
    if !stig_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return None;
    }
    let path = state
        .config
        .data_dir
        .join("stigs")
        .join(format!("{stig_id}.json"));
    let contents = tokio::fs::read_to_string(&path).await.ok()?;
    serde_json::from_str(&contents).ok()
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Sanitize a path segment going INTO the zip. Keep dots/dashes/spaces;
/// strip path separators + control chars to prevent traversal.
fn sanitize_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '/' || c == '\\' || c.is_control() {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    if out.is_empty() {
        "_".into()
    } else {
        out
    }
}

fn map_db(e: anyhow::Error) -> StatusCode {
    tracing::error!("bundle db error: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}
