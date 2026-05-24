use anyhow::{bail, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};

/// Maps XCCDF severity strings to the CAT labels the frontend uses.
fn map_severity(s: &str) -> &'static str {
    match s.to_lowercase().as_str() {
        "high" => "CAT I",
        "low" => "CAT III",
        _ => "CAT II",
    }
}

/// A single STIG rule — matches the shape produced by the frontend's parseXCCDF.js.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub stig_id: String,
    pub group_id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub fix_text: String,
    pub check_text: String,
    pub cci_ids: Vec<String>,
    pub status: String,
    pub finding_details: String,
    pub comments: String,
}

/// The top-level STIG object returned by /api/stigs/:id.
/// Shape must match the frontend's internal STIG model exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StigData {
    pub title: String,
    pub description: String,
    pub version: String,
    pub release_info: String,
    pub rules: Vec<Rule>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Strip known XCCDF XML tags from description text (mirrors cleanDescription in parseXCCDF.js).
fn clean_description(raw: &str) -> String {
    // Tags to strip completely (with their contents)
    const STRIP_TAGS: &[&str] = &[
        "FalsePositives", "FalseNegatives", "Documentable", "Mitigations",
        "SeverityOverrideGuidance", "PotentialImpacts", "ThirdPartyTools",
        "MitigationControl", "Responsibility", "IAControls",
    ];

    let mut s = raw.to_string();
    for tag in STRIP_TAGS {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        while let (Some(start), Some(end)) = (s.find(&open), s.find(&close)) {
            if start <= end {
                s.replace_range(start..end + close.len(), "");
            } else {
                break;
            }
        }
    }

    // Strip VulnDiscussion wrapper tags (keep the content)
    s = s
        .replace("<VulnDiscussion>", "")
        .replace("</VulnDiscussion>", "");

    // Strip remaining XML tags
    let mut result = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                result.push(' ');
            }
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }

    // Collapse whitespace
    result.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Extract text content of the first child element with the given local name.
fn child_text<'a>(parent_bytes: &'a [u8], tag: &str) -> Option<String> {
    // We use a simple substring search since quick-xml events are finer-grained;
    // this helper is used on already-extracted text buffers.
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let start = parent_bytes
        .windows(open.len())
        .position(|w| w == open.as_bytes())?;
    let after_open = &parent_bytes[start..];
    let content_start = after_open.iter().position(|&b| b == b'>')? + 1;
    let content = &after_open[content_start..];
    let end = content
        .windows(close.len())
        .position(|w| w == close.as_bytes())?;
    Some(String::from_utf8_lossy(&content[..end]).trim().to_string())
}

/// Read an XML attribute value from a start element's raw bytes.
fn attr_value(tag_bytes: &[u8], attr_name: &str) -> Option<String> {
    let needle = format!("{attr_name}=\"");
    let start = tag_bytes
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())?
        + needle.len();
    let rest = &tag_bytes[start..];
    let end = rest.iter().position(|&b| b == b'"')?;
    Some(String::from_utf8_lossy(&rest[..end]).to_string())
}

// ── Main parser ───────────────────────────────────────────────────────────────

/// Parse an XCCDF XML string into a `StigData` value.
pub fn parse_xccdf(xml: &str) -> Result<StigData> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut title = String::new();
    let mut description = String::new();
    let mut version = String::new();
    let mut release_info = String::new();
    let mut rules: Vec<Rule> = Vec::new();

    // State machine
    let mut in_benchmark = false;
    let mut in_group = false;
    let mut in_rule = false;
    let mut current_group_id = String::new();
    let mut current_rule: Option<Rule> = None;
    let mut current_tag = String::new();
    let mut depth: usize = 0;
    let mut rule_depth: usize = 0;

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                depth += 1;
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();

                match local.as_str() {
                    "Benchmark" => {
                        in_benchmark = true;
                    }
                    "Group" if in_benchmark => {
                        in_group = true;
                        current_group_id =
                            attr_value(e.as_ref(), "id").unwrap_or_default();
                    }
                    "Rule" if in_group => {
                        in_rule = true;
                        rule_depth = depth;
                        let rule_id = attr_value(e.as_ref(), "id").unwrap_or_default();
                        let severity_raw =
                            attr_value(e.as_ref(), "severity").unwrap_or_default();
                        current_rule = Some(Rule {
                            id: rule_id,
                            stig_id: current_group_id.clone(),
                            group_id: current_group_id.clone(),
                            title: String::new(),
                            severity: map_severity(&severity_raw).to_string(),
                            description: String::new(),
                            fix_text: String::new(),
                            check_text: String::new(),
                            cci_ids: Vec::new(),
                            status: "not_reviewed".to_string(),
                            finding_details: String::new(),
                            comments: String::new(),
                        });
                    }
                    _ => {}
                }
                current_tag = local;
            }
            Ok(Event::End(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if local == "Rule" && in_rule && depth == rule_depth {
                    if let Some(rule) = current_rule.take() {
                        rules.push(rule);
                    }
                    in_rule = false;
                }
                if local == "Group" {
                    in_group = false;
                }
                depth = depth.saturating_sub(1);
                current_tag.clear();
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().trim().to_string();
                if text.is_empty() {
                    continue;
                }
                if in_rule {
                    if let Some(ref mut rule) = current_rule {
                        match current_tag.as_str() {
                            "title" => rule.title = text,
                            "description" => {
                                rule.description = clean_description(&text)
                            }
                            "fixtext" | "fix-text" => rule.fix_text = text,
                            "check-content" => rule.check_text = text,
                            "ident" => rule.cci_ids.push(text),
                            _ => {}
                        }
                    }
                } else if in_benchmark {
                    match current_tag.as_str() {
                        "title" if title.is_empty() => title = text,
                        "description" if description.is_empty() => {
                            description = clean_description(&text)
                        }
                        "version" if version.is_empty() => version = text,
                        "plain-text" | "release-info" if release_info.is_empty() => {
                            release_info = text
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("XML parse error: {e}"),
            _ => {}
        }
        buf.clear();
    }

    if title.is_empty() {
        title = "Unknown STIG".to_string();
    } else if let Some(rest) = title.strip_prefix("DPMS Target ") {
        title = rest.to_string();
    }

    Ok(StigData {
        title,
        description,
        version,
        release_info,
        rules,
    })
}

/// Find and return the text content of the XCCDF file within a ZIP archive.
pub fn extract_xccdf_from_zip(zip_bytes: &[u8]) -> Result<String> {
    use std::io::Read;
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;

    // STIGs may be double-zipped; handle one level of nesting
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_lowercase();

        // Direct XCCDF XML inside the outer ZIP
        if name.ends_with("_xccdf.xml") || name.ends_with("-xccdf.xml") {
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            return Ok(content);
        }

        // Inner ZIP — extract it and recurse one level
        if name.ends_with(".zip") {
            let mut inner_bytes = Vec::new();
            file.read_to_end(&mut inner_bytes)?;
            if let Ok(xccdf) = extract_xccdf_from_zip(&inner_bytes) {
                return Ok(xccdf);
            }
        }
    }

    bail!("No *_xccdf.xml found in ZIP archive")
}

// ── Helpers re-used by child_text (kept for future use) ─────────────────────
#[allow(dead_code)]
pub fn child_text_pub(parent_bytes: &[u8], tag: &str) -> Option<String> {
    child_text(parent_bytes, tag)
}

// ── Library bulk extraction ───────────────────────────────────────────────────

/// One successfully parsed STIG from a library bundle.
pub struct LibraryEntry {
    pub id: String,
    pub category: String,
    pub stig: StigData,
}

/// Derive a stable slug ID from a DISA ZIP filename.
///
/// `U_MS_Windows_11_V2R3_STIG.zip` → `ms-windows-11`
/// `U_RHEL_9_V2R2_STIG.zip`        → `rhel-9`
pub fn filename_to_id(zip_name: &str) -> String {
    // Use just the basename (strip any directory prefix from ZIP entry paths)
    let base = zip_name.rsplit('/').next().unwrap_or(zip_name);

    // Strip extension, U_ prefix, _STIG suffix
    let base = base.strip_suffix(".zip").unwrap_or(base);
    let base = base.strip_suffix(".ZIP").unwrap_or(base);
    let base = base.strip_prefix("U_").unwrap_or(base);
    let base = base.strip_suffix("_STIG").unwrap_or(base);

    // Strip trailing version marker _V<n>R<n>
    let base = {
        let bytes = base.as_bytes();
        let mut cut = base.len();
        for i in (0..bytes.len().saturating_sub(3)).rev() {
            if bytes[i] == b'_'
                && bytes[i + 1] == b'V'
                && bytes[i + 2].is_ascii_digit()
            {
                cut = i;
                break;
            }
        }
        &base[..cut]
    };

    // Slugify: lowercase, non-alphanum → hyphen, collapse repeated hyphens
    let raw: String = base
        .chars()
        .map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();

    let mut slug = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for c in raw.chars() {
        if c == '-' {
            if !prev_dash && !slug.is_empty() {
                slug.push('-');
            }
            prev_dash = true;
        } else {
            slug.push(c);
            prev_dash = false;
        }
    }
    slug.trim_end_matches('-').to_string()
}

/// Infer the catalog category from an XCCDF benchmark title.
pub fn infer_category(title: &str) -> &'static str {
    let t = title.to_lowercase();
    if t.contains("windows") {
        "Windows"
    } else if t.contains("red hat")
        || t.contains("rhel")
        || t.contains("ubuntu")
        || t.contains("linux")
        || t.contains("debian")
        || t.contains("suse")
        || t.contains("alma")
        || t.contains("rocky")
    {
        "Linux"
    } else if t.contains("chrome")
        || t.contains("firefox")
        || t.contains("edge")
        || t.contains("safari")
        || t.contains("browser")
    {
        "Browser"
    } else {
        "Network"
    }
}

/// Process every STIG ZIP inside a DISA SRG/STIG library bundle.
///
/// Returns `(entries, errors)` where entries are ready to write to disk and
/// upsert into the catalog.  Only ZIP entries whose filename ends with
/// `_STIG.zip` (case-insensitive) are processed; SRG ZIPs and other files
/// are silently skipped.
///
/// **Note:** this function is CPU-bound and should be called from
/// `tokio::task::spawn_blocking`.
pub fn extract_all_from_library(
    library_bytes: &[u8],
) -> (Vec<LibraryEntry>, Vec<(String, String)>) {
    use std::io::Read;

    let cursor = std::io::Cursor::new(library_bytes);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(e) => return (vec![], vec![("(outer zip)".into(), e.to_string())]),
    };

    let mut entries: Vec<LibraryEntry> = Vec::new();
    let mut errors: Vec<(String, String)> = Vec::new();

    for i in 0..archive.len() {
        // Read each ZIP entry name + bytes (separate scope to appease borrow checker)
        let (raw_name, inner_bytes) = {
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let raw_name = file.name().to_string();

            // Only process STIG ZIPs; skip SRGs, READMEs, manifests, etc.
            if !raw_name.to_lowercase().ends_with("_stig.zip") {
                continue;
            }

            let mut bytes = Vec::new();
            if file.read_to_end(&mut bytes).is_err() {
                errors.push((filename_to_id(&raw_name), "failed to read ZIP entry".into()));
                continue;
            }
            (raw_name, bytes)
        };

        let id = filename_to_id(&raw_name);

        let xccdf = match extract_xccdf_from_zip(&inner_bytes) {
            Ok(x) => x,
            Err(e) => {
                errors.push((id, format!("ZIP extraction failed: {e}")));
                continue;
            }
        };

        let stig = match parse_xccdf(&xccdf) {
            Ok(s) => s,
            Err(e) => {
                errors.push((id, format!("XCCDF parse failed: {e}")));
                continue;
            }
        };

        let category = infer_category(&stig.title).to_string();
        entries.push(LibraryEntry { id, category, stig });
    }

    (entries, errors)
}
