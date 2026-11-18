use crate::zip_safe::{open_validated, read_entry, ReadBudget, ZipReadError};
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

/// A single STIG rule — matches the shape produced by the frontend's parse_xccdf.rs.
///
/// Note on CCI fields: `cci_ids` (serialized as `cciIds`) is the long-standing
/// field name used throughout the frontend and exporters. `cci` (serialized
/// verbatim) is a parallel field that exposes the same data under the shorter
/// name used by the per-rule CCI tag display. Both are populated together —
/// always trimmed, filtered to `ident` children whose system attribute
/// contains "cci" (case-insensitive), and deduplicated while preserving the
/// first-seen order.
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
    /// Short-name mirror of `cci_ids` used by the per-rule CCI tag UI.
    /// Always present (empty array when the rule has no CCIs).
    #[serde(default, rename = "cci")]
    pub cci: Vec<String>,
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

/// Strip known XCCDF XML tags from description text (mirrors clean_description in the frontend's parse_xccdf.rs).
fn clean_description(raw: &str) -> String {
    // Tags to strip completely (with their contents)
    const STRIP_TAGS: &[&str] = &[
        "FalsePositives",
        "FalseNegatives",
        "Documentable",
        "Mitigations",
        "SeverityOverrideGuidance",
        "PotentialImpacts",
        "ThirdPartyTools",
        "MitigationControl",
        "Responsibility",
        "IAControls",
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
fn child_text(parent_bytes: &[u8], tag: &str) -> Option<String> {
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
    // The XCCDF `<ident system="...">` attribute on the element we're
    // currently inside. Tracked separately so we can filter ident text
    // children to CCI systems only (per spec, anything whose system URI
    // contains the substring "cci", case-insensitive).
    let mut current_ident_system = String::new();
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
                        current_group_id = attr_value(e.as_ref(), "id").unwrap_or_default();
                    }
                    "Rule" if in_group => {
                        in_rule = true;
                        rule_depth = depth;
                        let rule_id = attr_value(e.as_ref(), "id").unwrap_or_default();
                        let severity_raw = attr_value(e.as_ref(), "severity").unwrap_or_default();
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
                            cci: Vec::new(),
                            status: "not_reviewed".to_string(),
                            finding_details: String::new(),
                            comments: String::new(),
                        });
                    }
                    _ => {}
                }
                // Capture the `system` attribute when entering an <ident>
                // so the text-event handler can decide whether to keep it.
                if local == "ident" {
                    current_ident_system = attr_value(e.as_ref(), "system").unwrap_or_default();
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
                if local == "ident" {
                    current_ident_system.clear();
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
                            // Only the Rule's own <title> (a direct child).
                            // DISA rules also carry <reference><dc:title>,
                            // whose local name is "title" too; matching it
                            // here used to overwrite every rule title with
                            // "DPMS Target …".
                            "title" if depth == rule_depth + 1 => rule.title = text,
                            // First non-empty value wins, like the title: a
                            // later duplicate or nested element of the same
                            // name must not overwrite the Rule's own text.
                            "description" if rule.description.is_empty() => {
                                rule.description = clean_description(&text)
                            }
                            "fixtext" | "fix-text" if rule.fix_text.is_empty() => {
                                rule.fix_text = text
                            }
                            "check-content" if rule.check_text.is_empty() => rule.check_text = text,
                            "ident" => {
                                // Only retain idents whose `system` URI
                                // names a CCI source — DISA, NIST, and
                                // newer XCCDF bundles all spell this
                                // differently but every variant contains
                                // the substring "cci". Trim + dedupe so
                                // the JSON shape is stable regardless of
                                // upstream whitespace quirks.
                                if current_ident_system.to_lowercase().contains("cci") {
                                    let value = text.trim().to_string();
                                    if !value.is_empty() && !rule.cci.iter().any(|c| c == &value) {
                                        rule.cci.push(value.clone());
                                        rule.cci_ids.push(value);
                                    }
                                }
                            }
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

/// Decompression limits for one ZIP read. Production values are
/// `ZIP_LIMITS`; tests use tiny ones.
pub struct ZipLimits {
    /// Cap on each `*xccdf.xml` entry.
    pub xccdf: u64,
    /// Cap on each inner `.zip` entry.
    pub nested_zip: u64,
}

pub const ZIP_LIMITS: ZipLimits = ZipLimits {
    xccdf: 64 << 20,
    nested_zip: 128 << 20,
};
/// Cumulative decompressed bytes for one single-STIG upload or sync source.
pub const SINGLE_STIG_BUDGET: u64 = 256 << 20;
/// Cumulative decompressed bytes for one library import.
pub const LIBRARY_BUDGET: u64 = 2 << 30;

fn utf8_entry(bytes: Vec<u8>) -> Result<String, ZipReadError> {
    String::from_utf8(bytes).map_err(|e| {
        ZipReadError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.utf8_error(),
        ))
    })
}

/// Find and return the text content of the XCCDF file within a ZIP archive.
pub fn extract_xccdf_from_zip(zip_bytes: &[u8]) -> Result<String, ZipReadError> {
    extract_xccdf_with(zip_bytes, &ZIP_LIMITS, SINGLE_STIG_BUDGET)
}

fn extract_xccdf_with(
    zip_bytes: &[u8],
    limits: &ZipLimits,
    budget: u64,
) -> Result<String, ZipReadError> {
    let mut budget = ReadBudget::new(budget);
    extract_xccdf_nested(zip_bytes, MAX_ZIP_DEPTH, limits, &mut budget)
}

fn extract_xccdf_nested(
    zip_bytes: &[u8],
    depth_left: u8,
    limits: &ZipLimits,
    budget: &mut ReadBudget,
) -> Result<String, ZipReadError> {
    let mut archive = open_validated(zip_bytes)?;
    // First non-limit failure inside an inner ZIP; reported instead of
    // "not found" when nothing else turns up. Limit errors are always fatal.
    let mut first_err: Option<ZipReadError> = None;

    // STIGs may be double-zipped; follow nested ZIPs up to MAX_ZIP_DEPTH levels.
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name()?.to_lowercase();

        // Direct XCCDF XML inside the outer ZIP
        if name.ends_with("_xccdf.xml") || name.ends_with("-xccdf.xml") {
            return utf8_entry(read_entry(&mut file, limits.xccdf, budget)?);
        }

        // Inner ZIP: extract it and recurse one level. A too-deep inner ZIP
        // is skipped and the caller reports "No *_xccdf.xml found".
        if name.ends_with(".zip") && depth_left > 0 {
            let inner_bytes = read_entry(&mut file, limits.nested_zip, budget)?;
            match extract_xccdf_nested(&inner_bytes, depth_left - 1, limits, budget) {
                Ok(xccdf) => return Ok(xccdf),
                Err(e) if e.is_limit() => return Err(e),
                Err(ZipReadError::NoXccdf) => {}
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
    }

    Err(first_err.unwrap_or(ZipReadError::NoXccdf))
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
            if bytes[i] == b'_' && bytes[i + 1] == b'V' && bytes[i + 2].is_ascii_digit() {
                cut = i;
                break;
            }
        }
        &base[..cut]
    };

    // Slugify: lowercase, non-alphanum → hyphen, collapse repeated hyphens
    let raw: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
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

/// Derive a slug ID from an XCCDF file name inside a multi-STIG bundle.
///
/// `U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml` → `cisco-ios-xe-router-rtr`
pub fn xccdf_name_to_id(xccdf_name: &str) -> String {
    let id = filename_to_id(xccdf_name);
    id.strip_suffix("-stig").map(str::to_string).unwrap_or(id)
}

/// How deep `extract_all_xccdf_from_zip` follows ZIPs nested inside ZIPs.
/// DISA bundles nest two levels (product bundle → per-STIG ZIP → XCCDF).
const MAX_ZIP_DEPTH: u8 = 3;

/// Return every XCCDF document in a ZIP archive as `(entry name, content)`,
/// following nested ZIPs. Unlike `extract_xccdf_from_zip` this does not stop
/// at the first hit: DISA product bundles (`U_Cisco_IOS-XE_Router_Y26M04_STIG.zip`)
/// carry several STIGs (NDM, RTR, ...) as sibling inner ZIPs.
///
/// Entries that cannot be read (over their cap, bad headers, bad data) are
/// skipped and reported in `skipped` as `(label, reason)`. Only an exhausted
/// budget is an `Err`: it aborts the whole request.
fn extract_all_xccdf_from_zip(
    zip_bytes: &[u8],
    limits: &ZipLimits,
    budget: &mut ReadBudget,
    skipped: &mut Vec<(String, String)>,
) -> Result<Vec<(String, String)>, ZipReadError> {
    let mut out = Vec::new();
    collect_xccdf(
        zip_bytes,
        MAX_ZIP_DEPTH,
        "(inner zip)",
        limits,
        budget,
        &mut out,
        skipped,
    )?;
    Ok(out)
}

fn short_label(name: &str) -> String {
    name.chars().take(64).collect()
}

/// Skip a failed entry, or abort when the failure is an exhausted budget.
fn skip_or_abort(
    e: ZipReadError,
    label: &str,
    skipped: &mut Vec<(String, String)>,
) -> Result<(), ZipReadError> {
    if matches!(e, ZipReadError::BudgetExceeded { .. }) {
        return Err(e);
    }
    skipped.push((label.to_string(), e.to_string()));
    Ok(())
}

fn collect_xccdf(
    zip_bytes: &[u8],
    depth_left: u8,
    label: &str,
    limits: &ZipLimits,
    budget: &mut ReadBudget,
    out: &mut Vec<(String, String)>,
    skipped: &mut Vec<(String, String)>,
) -> Result<(), ZipReadError> {
    let mut archive = match open_validated(zip_bytes) {
        Ok(a) => a,
        Err(e) => return skip_or_abort(e, label, skipped),
    };
    for i in 0..archive.len() {
        let Ok(mut file) = archive.by_index(i) else {
            skipped.push((label.to_string(), "failed to read ZIP entry".into()));
            continue;
        };
        let Ok(name) = file.name().map(|n| n.into_owned()) else {
            continue;
        };
        let lower = name.to_lowercase();
        if lower.ends_with("_xccdf.xml") || lower.ends_with("-xccdf.xml") {
            match read_entry(&mut file, limits.xccdf, budget).and_then(utf8_entry) {
                Ok(content) => out.push((name, content)),
                Err(e) => skip_or_abort(e, &short_label(&name), skipped)?,
            }
        } else if lower.ends_with(".zip") && depth_left > 0 {
            match read_entry(&mut file, limits.nested_zip, budget) {
                Ok(inner) => collect_xccdf(
                    &inner,
                    depth_left - 1,
                    &short_label(&name),
                    limits,
                    budget,
                    out,
                    skipped,
                )?,
                Err(e) => skip_or_abort(e, &short_label(&name), skipped)?,
            }
        }
    }
    Ok(())
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
///
/// An `Err` means the request-wide decompression budget was exhausted; nothing
/// has been written at that point, so the caller can refuse the whole import.
#[cfg(test)]
pub fn extract_all_from_library(library_bytes: &[u8]) -> LibraryResult {
    extract_all_from_library_with(library_bytes, &ZIP_LIMITS, LIBRARY_BUDGET)
        .map(|(entries, errors, _)| (entries, errors))
}

/// Like `extract_all_from_library`, also returning the `code()` of the failure
/// when the outer archive itself was refused (its message is then the single
/// `"(outer zip)"` entry in the error list).
pub fn extract_all_from_library_full(library_bytes: &[u8]) -> LibraryFullResult {
    extract_all_from_library_with(library_bytes, &ZIP_LIMITS, LIBRARY_BUDGET)
}

pub type LibraryFullResult = Result<
    (
        Vec<LibraryEntry>,
        Vec<(String, String)>,
        Option<&'static str>,
    ),
    ZipReadError,
>;

#[cfg(test)]
pub type LibraryResult = Result<(Vec<LibraryEntry>, Vec<(String, String)>), ZipReadError>;

fn extract_all_from_library_with(
    library_bytes: &[u8],
    limits: &ZipLimits,
    budget: u64,
) -> LibraryFullResult {
    let mut budget = ReadBudget::new(budget);
    let mut archive = match open_validated(library_bytes) {
        Ok(a) => a,
        Err(e) => {
            return Ok((
                vec![],
                vec![("(outer zip)".into(), e.to_string())],
                Some(e.code()),
            ))
        }
    };

    let mut entries: Vec<LibraryEntry> = Vec::new();
    let mut errors: Vec<(String, String)> = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for i in 0..archive.len() {
        let Some((raw_name, inner_bytes)) =
            read_library_stig_zip(&mut archive, i, limits, &mut budget, &mut errors)?
        else {
            continue;
        };

        let outer_id = filename_to_id(&raw_name);

        let mut skipped = Vec::new();
        let docs = extract_all_xccdf_from_zip(&inner_bytes, limits, &mut budget, &mut skipped)?;
        let nothing_found = docs.is_empty();
        let nothing_skipped = skipped.is_empty();
        // Report under the library entry's id; the reason names the culprit.
        errors.extend(
            skipped
                .into_iter()
                .map(|(label, why)| (outer_id.clone(), format!("skipped {label}: {why}"))),
        );
        if nothing_found {
            if nothing_skipped {
                errors.push((
                    outer_id,
                    "ZIP extraction failed: No *_xccdf.xml found in ZIP archive".into(),
                ));
            }
            continue;
        }

        // A ZIP holding one STIG keeps the ID derived from the ZIP's own name.
        // A product bundle holding several gets one ID per STIG, derived from
        // each XCCDF file name, so they no longer overwrite each other.
        let multi = docs.len() > 1;
        for (xccdf_name, xccdf) in docs {
            if let Some(entry) = library_entry(
                &xccdf_name,
                &xccdf,
                &outer_id,
                multi,
                &mut seen_ids,
                &mut errors,
            ) {
                entries.push(entry);
            }
        }
    }

    Ok((entries, errors, None))
}

/// Read the library's entry `i` when it is a `_STIG.zip`. `Ok(None)` skips it
/// (not a STIG ZIP, unreadable, or over its cap, recorded in `errors`); only an
/// exhausted budget is an `Err`.
fn read_library_stig_zip(
    archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    i: usize,
    limits: &ZipLimits,
    budget: &mut ReadBudget,
    errors: &mut Vec<(String, String)>,
) -> Result<Option<(String, Vec<u8>)>, ZipReadError> {
    let Ok(mut file) = archive.by_index(i) else {
        return Ok(None);
    };
    let Ok(raw_name) = file.name().map(|n| n.into_owned()) else {
        return Ok(None);
    };
    // Only process STIG ZIPs; skip SRGs, READMEs, manifests, etc.
    if !raw_name.to_lowercase().ends_with("_stig.zip") {
        return Ok(None);
    }
    match read_entry(&mut file, limits.nested_zip, budget) {
        Ok(bytes) => Ok(Some((raw_name, bytes))),
        Err(e @ ZipReadError::BudgetExceeded { .. }) => Err(e),
        Err(e) => {
            errors.push((
                filename_to_id(&raw_name),
                format!("failed to read ZIP entry: {e}"),
            ));
            Ok(None)
        }
    }
}

/// Turn one XCCDF from a library entry into a [`LibraryEntry`], giving it a
/// unique, valid id. Problems are recorded in `errors` and yield `None`.
fn library_entry(
    xccdf_name: &str,
    xccdf: &str,
    outer_id: &str,
    multi: bool,
    seen_ids: &mut std::collections::HashSet<String>,
    errors: &mut Vec<(String, String)>,
) -> Option<LibraryEntry> {
    let mut id = if multi {
        xccdf_name_to_id(xccdf_name)
    } else {
        outer_id.to_string()
    };
    if id.is_empty() {
        id = outer_id.to_string();
    }
    if id.is_empty() {
        errors.push((
            xccdf_name.chars().take(64).collect(),
            "could not derive a valid id from the file name; skipped".into(),
        ));
        return None;
    }
    if !seen_ids.insert(id.clone()) {
        let base = id.clone();
        let mut n = 2;
        while !seen_ids.insert(format!("{base}-{n}")) {
            n += 1;
        }
        id = format!("{base}-{n}");
    }

    // Defensive: `filename_to_id` already yields lower-case ASCII, so
    // in practice this only fires for an over-long id.
    if !crate::stig_id::is_valid_new(&id) {
        errors.push((
            id.chars().take(64).collect(),
            format!(
                "derived id is not a valid STIG id (max {} bytes); skipped",
                crate::stig_id::MAX_BYTES
            ),
        ));
        return None;
    }

    let stig = match parse_xccdf(xccdf) {
        Ok(s) => s,
        Err(e) => {
            errors.push((id, format!("XCCDF parse failed: {e}")));
            return None;
        }
    };

    let category = infer_category(&stig.title).to_string();
    Some(LibraryEntry { id, category, stig })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_to_id_is_ascii_lower_only() {
        assert_eq!(
            filename_to_id("U_Caf\u{e9}_Server_V1R1_STIG.zip"),
            "caf-server"
        );
        assert_eq!(filename_to_id("U_\u{e9}\u{e9}_STIG.zip"), "");
        assert_eq!(filename_to_id("!!!.zip"), "");
        assert!(crate::stig_id::is_valid_new(&filename_to_id(
            "U_MS_Windows_11_V2R3_STIG.zip"
        )));
    }

    #[test]
    fn library_import_skips_and_reports_empty_id() {
        let inner = zip_of(&[("x_xccdf.xml", &benchmark("T"))]);
        let outer = zip_of(&[("U_\u{e9}\u{e9}_V1R1_STIG.zip", &inner)]);
        let (entries, errors) = extract_all_from_library(&outer).unwrap();
        assert!(entries.is_empty());
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn description_fixtext_and_check_content_are_first_wins() {
        let xml = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><title>B</title>
            <Group id="V-1"><Rule id="SV-1_rule" severity="low"><title>r</title>
              <description>first desc</description>
              <reference><description>later desc</description></reference>
              <fixtext>first fix</fixtext>
              <reference><fixtext>later fix</fixtext></reference>
              <check><check-content>first check</check-content></check>
              <check><check-content>later check</check-content></check>
            </Rule></Group></Benchmark>"#;
        let stig = parse_xccdf(xml).unwrap();
        let r = &stig.rules[0];
        assert_eq!(r.description, "first desc");
        assert_eq!(r.fix_text, "first fix");
        assert_eq!(r.check_text, "first check");
    }

    /// The seeded catalog is data, not code, so it can rot silently: files
    /// written by an older parser carried "DPMS Target ..." as rule titles and
    /// non-CCI idents in `cciIds`. Every tracked file must parse as `StigData`
    /// and hold real titles and CCI ids.
    #[test]
    fn seeded_catalog_has_real_titles_and_cci_ids() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seed/stigs");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("read seed/stigs") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let name = path.display().to_string();
            let bytes = std::fs::read(&path).expect("read catalog file");
            let stig: StigData = serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("{name} does not parse as StigData: {e}"));
            for r in &stig.rules {
                assert!(
                    !r.title.starts_with("DPMS Target"),
                    "{name}: rule {} has the DPMS Target title {:?}",
                    r.id,
                    r.title
                );
                for c in &r.cci_ids {
                    assert!(
                        c.starts_with("CCI-"),
                        "{name}: rule {} has non-CCI id {c:?}",
                        r.id
                    );
                }
            }
            checked += 1;
        }
        assert!(checked > 0, "no catalog files found in {}", dir.display());
    }

    /// The seed is committed to a public repository, so it must not hold CUI:
    /// no marking in any string, none of the withheld `CUI_` products, and no
    /// repeated rule ids. `seed/stigs.allowlist` pins the exact set of ids, so
    /// every added or dropped file is a deliberate, reviewable change.
    #[test]
    fn seeded_catalog_holds_no_cui_and_has_unique_rule_ids() {
        fn strings<'a>(v: &'a serde_json::Value, out: &mut Vec<&'a str>) {
            match v {
                serde_json::Value::String(s) => out.push(s),
                serde_json::Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
                serde_json::Value::Object(o) => o.values().for_each(|x| strings(x, out)),
                _ => {}
            }
        }
        // Title patterns for the withheld products (lower-case).
        const CUI_TITLES: &[&str] = &[
            "trellix ens",
            "ens 10",
            "ess agent handler",
            "ess epo",
            "epo 5",
            "policy auditor",
            "ess remote console",
            "rogue sensor",
            "ess staging server",
            "ess trellix agent",
            "tie-dxl",
            "tie dxl",
            "joint regional security stack",
        ];
        // Exact hyphen-separated id sequences of the withheld products.
        const CUI_ID_SEQUENCES: &[&[&str]] = &[
            &["policy", "auditor"],
            &["rogue", "sensor"],
            &["staging", "server"],
            &["mcafee", "ens"],
            &["trellix", "agent"],
        ];
        let seed = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seed");
        let dir = seed.join("stigs");
        let allow: std::collections::BTreeSet<String> =
            std::fs::read_to_string(seed.join("stigs.allowlist"))
                .expect("read seed/stigs.allowlist")
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect();
        let mut present = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(&dir).expect("read seed/stigs") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let name = path.display().to_string();
            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_lowercase();
            let bytes = std::fs::read(&path).expect("read catalog file");
            let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
            let stig: StigData = serde_json::from_value(value.clone())
                .unwrap_or_else(|e| panic!("{name} does not parse as StigData: {e}"));

            let mut all = Vec::new();
            strings(&value, &mut all);
            for s in all {
                let l = s.to_lowercase();
                let t = l.trim();
                assert!(
                    !l.contains("cui//")
                        && !l.contains("controlled unclassified")
                        && t != "cui"
                        && t != "(cui)",
                    "{name}: a string carries a CUI marking"
                );
            }

            let title = stig.title.to_lowercase();
            let id_words: Vec<&str> = id.split('-').collect();
            assert!(
                !CUI_TITLES.iter().any(|p| title.contains(p))
                    && !id.contains("trellix-ens")
                    && !id.contains("tie-dxl")
                    && !id.contains("joint-regional")
                    && !id_words
                        .iter()
                        .any(|w| { ["ess", "epo", "jrss", "staging-server"].contains(w) })
                    && !CUI_ID_SEQUENCES.iter().any(|seq| {
                        let n = seq.len();
                        id_words.windows(n).any(|win| win == *seq)
                    }),
                "{name}: id or title matches a withheld CUI product ({:?})",
                stig.title
            );

            let mut seen = std::collections::HashSet::new();
            for r in &stig.rules {
                assert!(
                    seen.insert(r.id.as_str()),
                    "{name}: duplicate rule id {}",
                    r.id
                );
            }
            present.insert(id);
        }
        let unlisted: Vec<_> = present.difference(&allow).collect();
        let missing: Vec<_> = allow.difference(&present).collect();
        assert!(
            unlisted.is_empty(),
            "seed files not on seed/stigs.allowlist: {unlisted:?}"
        );
        assert!(
            missing.is_empty(),
            "allowlisted ids with no seed file: {missing:?}"
        );
    }

    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes) in files {
            w.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(bytes).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn benchmark(title: &str) -> Vec<u8> {
        format!(
            r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><title>{title}</title>
            <Group id="V-1"><Rule id="SV-1_rule" severity="low"><title>r</title></Rule></Group></Benchmark>"#
        )
        .into_bytes()
    }

    /// A product bundle with several inner STIG ZIPs must yield one catalog
    /// entry per STIG; a single-STIG ZIP keeps its ZIP-name ID.
    #[test]
    fn library_import_keeps_every_stig_in_a_product_bundle() {
        let ndm = zip_of(&[(
            "U_Cisco_IOS-XE_Router_NDM_V3R7_Manual_STIG/U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml",
            &benchmark("Cisco IOS XE Router NDM"),
        )]);
        let rtr = zip_of(&[(
            "U_Cisco_IOS-XE_Router_RTR_V3R5_Manual_STIG/U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml",
            &benchmark("Cisco IOS XE Router RTR"),
        )]);
        let bundle = zip_of(&[
            ("U_Cisco_IOS-XE_Router_NDM_V3R7_Manual_STIG.zip", &ndm),
            ("U_Cisco_IOS-XE_Router_RTR_V3R5_Manual_STIG.zip", &rtr),
        ]);
        let single = zip_of(&[(
            "U_MS_Windows_11_V2R3_Manual_STIG/U_MS_Windows_11_STIG_V2R3_Manual-xccdf.xml",
            &benchmark("Microsoft Windows 11"),
        )]);
        let library = zip_of(&[
            ("U_Cisco_IOS-XE_Router_Y26M04_STIG.zip", &bundle),
            ("U_MS_Windows_11_V2R3_STIG.zip", &single),
        ]);

        let (entries, errors) = extract_all_from_library(&library).unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        let mut got: Vec<(String, String)> =
            entries.into_iter().map(|e| (e.id, e.stig.title)).collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                (
                    "cisco-ios-xe-router-ndm".to_string(),
                    "Cisco IOS XE Router NDM".to_string()
                ),
                (
                    "cisco-ios-xe-router-rtr".to_string(),
                    "Cisco IOS XE Router RTR".to_string()
                ),
                (
                    "ms-windows-11".to_string(),
                    "Microsoft Windows 11".to_string()
                ),
            ]
        );
    }

    #[test]
    fn library_import_skips_and_reports_an_over_long_derived_id() {
        let long_name = format!("U_{}_V1R1_STIG.zip", "A".repeat(200));
        let inner = zip_of(&[("x-xccdf.xml", &benchmark("Long"))]);
        let ok_inner = zip_of(&[("y-xccdf.xml", &benchmark("Short"))]);
        let library = zip_of(&[
            (long_name.as_str(), &inner),
            ("U_Short_V1R1_STIG.zip", &ok_inner),
        ]);
        let (entries, errors) = extract_all_from_library(&library).unwrap();
        let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["short"]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].1.contains("not a valid STIG id"), "{errors:?}");
        assert!(errors[0].0.len() <= 64);
    }

    /// Offsets of every local (`PK\x03\x04`) and central (`PK\x01\x02`) header
    /// whose entry name equals `name`, as `(name_offset, method_offset)`.
    fn header_offsets(bytes: &[u8], name: &str) -> Vec<(usize, usize)> {
        let n = name.as_bytes();
        let mut out = Vec::new();
        for pos in 0..bytes.len().saturating_sub(46) {
            let (name_off, method_off) = match &bytes[pos..pos + 4] {
                b"PK\x03\x04" => (30, 8),
                b"PK\x01\x02" => (46, 10),
                _ => continue,
            };
            if bytes.get(pos + name_off..pos + name_off + n.len()) == Some(n) {
                out.push((pos + name_off, pos + method_off));
            }
        }
        out
    }

    #[test]
    fn extract_xccdf_finds_direct_nested_and_rejects_bad_input() {
        let xml = benchmark("Direct");
        let direct = zip_of(&[("dir/U_X-xccdf.xml", &xml)]);
        assert_eq!(
            extract_xccdf_from_zip(&direct).unwrap().as_bytes(),
            &xml[..]
        );

        let nested = zip_of(&[("inner.zip", &direct)]);
        assert_eq!(
            extract_xccdf_from_zip(&nested).unwrap().as_bytes(),
            &xml[..]
        );

        let none = zip_of(&[("readme.txt", b"hi")]);
        let err = extract_xccdf_from_zip(&none).unwrap_err().to_string();
        assert!(err.contains("No *_xccdf.xml found"), "{err}");

        assert!(extract_xccdf_from_zip(b"definitely not a zip").is_err());
    }

    #[test]
    fn extract_xccdf_reads_a_stored_entry() {
        use std::io::Write;
        let xml = benchmark("Stored");
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        w.start_file("U_X-xccdf.xml", opts).unwrap();
        w.write_all(&xml).unwrap();
        let bytes = w.finish().unwrap().into_inner();
        assert_eq!(extract_xccdf_from_zip(&bytes).unwrap().as_bytes(), &xml[..]);
    }

    #[test]
    fn library_import_accepts_a_non_utf8_entry_name() {
        let mut lib = zip_of(&[(
            "U_AXB_V1R1_STIG.zip",
            &zip_of(&[("a-xccdf.xml", &benchmark("Patched"))]),
        )]);
        let hits = header_offsets(&lib, "U_AXB_V1R1_STIG.zip");
        assert_eq!(hits.len(), 2);
        for (name_off, _) in hits {
            lib[name_off + 3] = 0xFF; // the 'X'
        }
        let (entries, errors) = extract_all_from_library(&lib).unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "a-b");
    }

    #[test]
    fn unsupported_compression_method_fails_a_single_upload() {
        let mut z = zip_of(&[("U_X-xccdf.xml", &benchmark("X"))]);
        for (_, method_off) in header_offsets(&z, "U_X-xccdf.xml") {
            z[method_off..method_off + 2].copy_from_slice(&12u16.to_le_bytes());
        }
        let e = extract_xccdf_from_zip(&z).unwrap_err().to_string();
        assert!(e.contains("compression method not supported: 12"), "{e}");
    }

    #[test]
    fn self_nesting_zip_is_bounded_not_a_stack_overflow() {
        let mut z = zip_of(&[("readme.txt", b"x")]);
        for _ in 0..(MAX_ZIP_DEPTH as usize + 5) {
            z = zip_of(&[("inner.zip", &z)]);
        }
        let err = extract_xccdf_from_zip(&z).unwrap_err().to_string();
        assert!(err.contains("No *_xccdf.xml found"), "{err}");
        // Boundary: an XCCDF MAX_ZIP_DEPTH levels down is found, one more is not.
        let mut over = zip_of(&[("a-xccdf.xml", &benchmark("Deep"))]);
        for _ in 0..=MAX_ZIP_DEPTH {
            over = zip_of(&[("inner.zip", &over)]);
        }
        assert!(extract_xccdf_from_zip(&over).is_err());
        // An XCCDF within the limit is still found.
        let mut ok = zip_of(&[("a-xccdf.xml", &benchmark("Deep"))]);
        for _ in 0..MAX_ZIP_DEPTH {
            ok = zip_of(&[("inner.zip", &ok)]);
        }
        assert!(extract_xccdf_from_zip(&ok).is_ok());
    }

    #[test]
    fn library_import_skips_an_unsupported_compression_method() {
        let good = zip_of(&[("a-xccdf.xml", &benchmark("Good"))]);
        let bad = zip_of(&[("a-xccdf.xml", &benchmark("Bad"))]);
        let mut lib = zip_of(&[
            ("U_Bad_V1R1_STIG.zip", &bad),
            ("U_Good_V1R1_STIG.zip", &good),
        ]);
        let hits = header_offsets(&lib, "U_Bad_V1R1_STIG.zip");
        assert_eq!(hits.len(), 2);
        for (_, method_off) in hits {
            lib[method_off..method_off + 2].copy_from_slice(&12u16.to_le_bytes());
        }
        let (entries, errors) = extract_all_from_library(&lib).unwrap();
        let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["good"]);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].0, "bad");
        assert!(errors[0].1.contains("failed to read"), "{errors:?}");
    }

    /// XCCDF fragment with one rule carrying two CCI idents plus one
    /// non-CCI ident. After parsing, `cci` must contain exactly the two
    /// CCI values in document order; the non-CCI ident must be dropped.
    /// Also verifies that the second rule (no idents at all) still gets
    /// an empty `cci: []` array rather than a missing field.
    #[test]
    fn cci_idents_are_captured_filtered_and_deduped() {
        let xml = r#"
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <title>Test</title>
            <Group id="V-1">
                <Rule id="SV-1_rule" severity="medium">
                    <title>Rule one</title>
                    <ident system="http://iase.disa.mil/cci">CCI-000001</ident>
                    <ident system="http://iase.disa.mil/cci">  CCI-000002  </ident>
                    <ident system="http://iase.disa.mil/cci">CCI-000001</ident>
                    <ident system="http://nvd.nist.gov/cve">CVE-2020-9999</ident>
                </Rule>
            </Group>
            <Group id="V-2">
                <Rule id="SV-2_rule" severity="low">
                    <title>Rule two</title>
                </Rule>
            </Group>
        </Benchmark>
        "#;

        let stig = parse_xccdf(xml).expect("parse");
        assert_eq!(stig.rules.len(), 2);

        let r1 = &stig.rules[0];
        assert_eq!(
            r1.cci,
            vec!["CCI-000001".to_string(), "CCI-000002".to_string()],
            "CCI idents kept in order, trimmed, deduped; non-CCI dropped",
        );
        // cci_ids mirrors cci so legacy consumers see the same set.
        assert_eq!(r1.cci_ids, r1.cci);

        let r2 = &stig.rules[1];
        assert!(r2.cci.is_empty(), "rules with no idents must emit []");
        // Serialization sanity check — `cci` must appear as a key even
        // when empty so the API contract is "always present".
        let json = serde_json::to_value(r2).expect("serialize");
        assert!(json.get("cci").is_some(), "cci key must be present");
        assert!(json.get("cci").unwrap().is_array());
    }

    /// DISA rules carry a Dublin Core title inside `<reference>` after the
    /// rule's own `<title>`. It must not replace the rule title, and it must
    /// not leak into a rule that has no title of its own.
    #[test]
    fn reference_dc_title_does_not_override_rule_title() {
        let xml = r#"
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"
                   xmlns:dc="http://purl.org/dc/elements/1.1/">
            <title>Test</title>
            <Group id="V-1">
                <title>SRG-APP-000001</title>
                <Rule id="SV-1_rule" severity="high">
                    <title>The real rule title</title>
                    <reference>
                        <dc:title>DPMS Target Some Product</dc:title>
                        <dc:publisher>DISA</dc:publisher>
                    </reference>
                </Rule>
            </Group>
            <Group id="V-2">
                <Rule id="SV-2_rule" severity="low">
                    <reference>
                        <dc:title>DPMS Target Some Product</dc:title>
                    </reference>
                </Rule>
            </Group>
        </Benchmark>
        "#;

        let stig = parse_xccdf(xml).expect("parse");
        assert_eq!(stig.title, "Test");
        assert_eq!(stig.rules[0].title, "The real rule title");
        assert_eq!(
            stig.rules[1].title, "",
            "dc:title must not stand in for a missing rule title"
        );
    }

    // ── Parity with the frontend parser ──────────────────────────────────────
    //
    // Shared fixture also exercised by
    // the tests in frontend/src/utils/parse_xccdf.rs on the frontend side. Any assertion
    // that drifts between these two tests indicates a real parser
    // divergence.
    const PARITY_FIXTURE: &str = include_str!("../../../testdata/fixtures/minimal.xccdf.xml");

    #[test]
    fn parity_fixture_parses_three_rules_with_expected_severities() {
        let stig = parse_xccdf(PARITY_FIXTURE).expect("fixture parses");
        assert_eq!(stig.title, "Parity Fixture STIG");
        assert_eq!(stig.version, "2");
        assert_eq!(stig.rules.len(), 3);

        let by_stig_id: std::collections::HashMap<_, _> =
            stig.rules.iter().map(|r| (r.stig_id.as_str(), r)).collect();
        assert_eq!(by_stig_id["V-1001"].severity, "CAT I");
        assert_eq!(by_stig_id["V-1001"].id, "SV-1001r1_rule");
        assert_eq!(by_stig_id["V-1002"].severity, "CAT II");
        assert_eq!(by_stig_id["V-1003"].severity, "CAT III");

        // Each rule in the fixture also has <reference><dc:title>DPMS Target …
        // The rule's own <title> must win.
        assert_eq!(by_stig_id["V-1001"].title, "Critical rule under test");
        assert_eq!(by_stig_id["V-1002"].title, "Medium-severity rule");
        assert_eq!(by_stig_id["V-1003"].title, "Informational finding");
    }

    #[test]
    fn parity_fixture_strips_vulndiscussion_and_falsepositives() {
        let stig = parse_xccdf(PARITY_FIXTURE).expect("fixture parses");
        let critical = stig
            .rules
            .iter()
            .find(|r| r.id == "SV-1001r1_rule")
            .unwrap();
        assert_eq!(critical.description, "Why this critical finding matters.");
        assert!(!critical.description.contains("FalsePositives"));
        assert!(!critical.description.contains('<'));
    }

    #[test]
    fn parity_fixture_initialises_override_fields() {
        let stig = parse_xccdf(PARITY_FIXTURE).expect("fixture parses");
        for r in &stig.rules {
            assert_eq!(r.status, "not_reviewed");
            assert_eq!(r.finding_details, "");
            assert_eq!(r.comments, "");
        }
    }

    // ── Decompression caps and header validation ──────────────────────────

    const TINY: ZipLimits = ZipLimits {
        xccdf: 1024,
        nested_zip: 4096,
    };

    fn big_xccdf(n: usize) -> Vec<u8> {
        let mut v = benchmark("Big");
        v.extend(std::iter::repeat_n(b' ', n));
        v
    }

    #[test]
    fn single_upload_refuses_an_over_cap_xccdf() {
        let z = zip_of(&[("a-xccdf.xml", &big_xccdf(2000))]);
        let e = extract_xccdf_with(&z, &TINY, 1 << 20).unwrap_err();
        assert!(matches!(e, ZipReadError::EntryTooLarge { .. }), "{e}");
        assert!(e.is_limit());
    }

    #[test]
    fn a_deflated_bomb_over_the_production_cap_is_refused() {
        // 64 MiB + 1 bytes of whitespace deflates to ~64 KiB.
        let z = zip_of(&[("a-xccdf.xml", &big_xccdf((ZIP_LIMITS.xccdf + 1) as usize))]);
        assert!(z.len() < 1 << 20, "bomb should compress well: {}", z.len());
        let e = extract_xccdf_from_zip(&z).unwrap_err();
        assert!(matches!(e, ZipReadError::EntryTooLarge { .. }), "{e}");
    }

    fn nest(inner: Vec<u8>, levels: usize) -> Vec<u8> {
        let mut z = inner;
        for _ in 0..levels {
            z = zip_of(&[("inner.zip", &z)]);
        }
        z
    }

    #[test]
    fn single_upload_budget_is_cumulative_across_nested_levels() {
        // Each level charges its inner zip; the XCCDF is charged last.
        let z = nest(zip_of(&[("a-xccdf.xml", &big_xccdf(800))]), 3);
        // Generous budget: found.
        assert!(extract_xccdf_with(&z, &TINY, 1 << 20).is_ok());
        // Each part is under its own cap, but together they exceed the budget.
        let e = extract_xccdf_with(&z, &TINY, 1500).unwrap_err();
        assert!(
            matches!(e, ZipReadError::BudgetExceeded { limit: 1500 }),
            "{e}"
        );
    }

    #[test]
    fn library_budget_exhaustion_aborts_the_whole_import() {
        let good = zip_of(&[("a-xccdf.xml", &benchmark("Good"))]);
        let lib = zip_of(&[("U_Good_V1R1_STIG.zip", &nest(good, 2))]);
        assert!(extract_all_from_library_with(&lib, &TINY, 1 << 20).is_ok());
        let e = extract_all_from_library_with(&lib, &TINY, 400)
            .err()
            .unwrap();
        assert!(matches!(e, ZipReadError::BudgetExceeded { .. }), "{e}");
    }

    #[test]
    fn library_skips_an_over_cap_stig_zip_and_reports_it() {
        let good = zip_of(&[("g-xccdf.xml", &benchmark("Good"))]);
        let bad = zip_of(&[("b-xccdf.xml", &big_xccdf(2000))]);
        let lib = zip_of(&[
            ("U_Bad_V1R1_STIG.zip", &bad),
            ("U_Good_V1R1_STIG.zip", &good),
        ]);
        let (entries, errors) = extract_all_from_library_with(&lib, &TINY, 1 << 20)
            .map(|(a, b, _)| (a, b))
            .unwrap();
        let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["good"]);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].0, "bad");
        assert!(errors[0].1.contains("larger than"), "{errors:?}");
    }

    /// Rename the entry `from` to `to` (same length) in the central directory
    /// only, leaving the local header alone.
    fn patch_central_name(z: &mut [u8], from: &str, to: &str) {
        assert_eq!(from.len(), to.len());
        let mut hit = false;
        for pos in 0..z.len().saturating_sub(46) {
            if &z[pos..pos + 4] == b"PK\x01\x02"
                && z.get(pos + 46..pos + 46 + from.len()) == Some(from.as_bytes())
            {
                z[pos + 46..pos + 46 + from.len()].copy_from_slice(to.as_bytes());
                hit = true;
            }
        }
        assert!(hit);
    }

    #[test]
    fn library_skips_an_inconsistent_inner_archive_and_reports_it() {
        let mut bad = zip_of(&[("b-xccdf.xml", &benchmark("Bad"))]);
        patch_central_name(&mut bad, "b-xccdf.xml", "c-xccdf.xml");
        let good = zip_of(&[("g-xccdf.xml", &benchmark("Good"))]);
        let lib = zip_of(&[
            ("U_Bad_V1R1_STIG.zip", &bad),
            ("U_Good_V1R1_STIG.zip", &good),
        ]);
        let (entries, errors) = extract_all_from_library(&lib).unwrap();
        let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["good"]);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].0, "bad");
        assert!(
            errors[0].1.contains("inconsistent ZIP headers"),
            "{errors:?}"
        );
    }

    #[test]
    fn library_reports_an_inconsistent_outer_archive() {
        let inner = zip_of(&[("g-xccdf.xml", &benchmark("Good"))]);
        let mut lib = zip_of(&[("U_Good_V1R1_STIG.zip", &inner)]);
        patch_central_name(&mut lib, "U_Good_V1R1_STIG.zip", "U_Gold_V1R1_STIG.zip");
        let (entries, errors) = extract_all_from_library(&lib).unwrap();
        assert!(entries.is_empty());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, "(outer zip)");
        assert!(
            errors[0].1.contains("inconsistent ZIP headers"),
            "{errors:?}"
        );
        let (_, _, code) = extract_all_from_library_full(&lib).unwrap();
        assert_eq!(code, Some("header_inconsistency"));
    }

    /// Rewrite the CRC-32 in both headers of the entry named `name` so it is
    /// wrong identically in each: header validation passes, and the zip
    /// crate only reports it at the end of the entry's data.
    fn break_crc(z: &mut [u8], name: &str) {
        let n = name.as_bytes();
        for pos in 0..z.len().saturating_sub(46) {
            let off = match &z[pos..pos + 4] {
                b"PK\x03\x04" => (30, 14),
                b"PK\x01\x02" => (46, 16),
                _ => continue,
            };
            if z.get(pos + off.0..pos + off.0 + n.len()) == Some(n) {
                z[pos + off.1] ^= 0xFF;
            }
        }
    }

    #[test]
    fn bad_crc_entries_still_exhaust_the_budget() {
        // Each entry reads fully (1500 bytes) and then fails its CRC check;
        // the failures must still be charged to the shared budget.
        let mut entries = Vec::new();
        for i in 0..6 {
            let name = format!("U_Bad{i}_V1R1_STIG.zip");
            let mut inner = zip_of(&[("b-xccdf.xml", &big_xccdf(1500))]);
            break_crc(&mut inner, "b-xccdf.xml");
            entries.push((name, inner));
        }
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let lib = zip_of(&refs);
        // Without the charge nothing would add up and every entry would be skipped.
        let e = extract_all_from_library_with(
            &lib,
            &ZipLimits {
                xccdf: 4096,
                nested_zip: 4096,
            },
            3000,
        )
        .err()
        .expect("budget must be exhausted");
        assert!(matches!(e, ZipReadError::BudgetExceeded { .. }), "{e}");

        // Single-STIG path: bad-CRC XCCDFs in sibling inner zips are skipped
        // one by one, so the budget has to stop them.
        let outer: Vec<(String, Vec<u8>)> = (0..6)
            .map(|i| {
                let mut inner = zip_of(&[("b-xccdf.xml", &big_xccdf(1500))]);
                break_crc(&mut inner, "b-xccdf.xml");
                (format!("i{i}.zip"), inner)
            })
            .collect();
        let refs: Vec<(&str, &[u8])> = outer
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let single = zip_of(&refs);
        let e = extract_xccdf_with(
            &single,
            &ZipLimits {
                xccdf: 4096,
                nested_zip: 8192,
            },
            5000,
        )
        .unwrap_err();
        assert!(matches!(e, ZipReadError::BudgetExceeded { .. }), "{e}");
    }

    #[test]
    fn single_upload_reports_an_inconsistent_inner_archive_not_not_found() {
        let mut bad = zip_of(&[("b-xccdf.xml", &benchmark("Bad"))]);
        patch_central_name(&mut bad, "b-xccdf.xml", "c-xccdf.xml");
        let z = zip_of(&[("inner.zip", &bad)]);
        let e = extract_xccdf_from_zip(&z).unwrap_err();
        assert!(matches!(e, ZipReadError::Inconsistent(_)), "{e}");
        assert!(!e.is_limit());
    }

    #[test]
    fn single_upload_refuses_an_inconsistent_outer_archive() {
        let mut z = zip_of(&[("b-xccdf.xml", &benchmark("Bad"))]);
        patch_central_name(&mut z, "b-xccdf.xml", "c-xccdf.xml");
        assert!(matches!(
            extract_xccdf_from_zip(&z).unwrap_err(),
            ZipReadError::Inconsistent(_)
        ));
    }

    /// Reads every `*.zip` in `STIG_REAL_BUNDLES_DIR` with production limits.
    /// Run: `STIG_REAL_BUNDLES_DIR=/path cargo test --locked -- --ignored real_bundles`
    #[test]
    #[ignore = "needs real DISA bundles (STIG_REAL_BUNDLES_DIR)"]
    fn real_bundles_pass_production_limits_and_header_validation() {
        let Ok(dir) = std::env::var("STIG_REAL_BUNDLES_DIR") else {
            eprintln!("STIG_REAL_BUNDLES_DIR not set; skipping the real-bundle check");
            return;
        };
        let mut seen = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("zip") {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            let name = path.display();
            let is_library = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains("Library"));
            if is_library {
                let (entries, errors) =
                    extract_all_from_library(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(errors.is_empty(), "{name}: {errors:?}");
                assert!(!entries.is_empty(), "{name}");
                assert!(entries.iter().all(|e| !e.stig.rules.is_empty()), "{name}");
            } else {
                let xccdf =
                    extract_xccdf_from_zip(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
                let stig = parse_xccdf(&xccdf).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(!stig.rules.is_empty(), "{name}");
                // Multi-STIG bundles must also pass the library path.
                let mut budget = ReadBudget::new(LIBRARY_BUDGET);
                let mut skipped = Vec::new();
                let docs =
                    extract_all_xccdf_from_zip(&bytes, &ZIP_LIMITS, &mut budget, &mut skipped)
                        .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(
                    !docs.is_empty() && skipped.is_empty(),
                    "{name}: {skipped:?}"
                );
            }
            seen += 1;
        }
        assert!(seen > 0, "no *.zip in {dir}");
    }
}
