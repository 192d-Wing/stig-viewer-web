//! STIG JSON lint pass — surfaces specific, line-pointable errors so users
//! can fix their STIG JSON before it lands in the catalog.
//!
//! Two surfaces use this module:
//!   1. `POST /api/stigs/lint` — read-only validator that takes a multipart
//!      upload of a STIG JSON file and returns a `LintReport`.
//!   2. The existing `/api/upload` runs the same linter on the parsed STIG
//!      and rejects with 400 + the lint report when any errors are present.

use axum::{extract::Multipart, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single lint finding. Paths use JSON Pointer syntax (RFC 6901) so the
/// UI can render them inline with the source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LintIssue {
    /// "error" | "warning"
    pub severity: String,
    /// JSON pointer, e.g. "/rules/3/id"
    pub path: String,
    /// Human-readable message
    pub message: String,
}

impl LintIssue {
    fn error(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: "error".into(),
            path: path.into(),
            message: message.into(),
        }
    }
    fn warning(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: "warning".into(),
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Lint result. `rules_count` is best-effort — if `rules` isn't an array we
/// return 0 so the UI can still say "0 rules · 4 errors".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LintReport {
    pub rules_count: i64,
    pub errors: Vec<LintIssue>,
    pub warnings: Vec<LintIssue>,
}

/// Allowed severity strings per DISA CAT mapping.
const VALID_SEVERITIES: &[&str] = &["CAT I", "CAT II", "CAT III"];

/// Required top-level fields. `releaseInfo` and `category` are warnings,
/// not errors — see `lint_stig`.
const REQUIRED_TOP_LEVEL: &[&str] = &["id", "title", "version", "rules"];

/// `rule.id` is used as a URL path segment, so the character set is locked
/// down. Mirrors `is_safe_rule_id` callers elsewhere.
fn is_safe_rule_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'
}

fn str_or_empty(v: &Value) -> Option<&str> {
    v.as_str()
}

/// Run the lint pass over a parsed JSON value. Pure function — no I/O.
pub fn lint_stig(value: &Value) -> LintReport {
    let mut errors: Vec<LintIssue> = Vec::new();
    let mut warnings: Vec<LintIssue> = Vec::new();
    let mut rules_count: i64 = 0;

    // 1. Root must be a JSON object.
    let obj = match value.as_object() {
        Some(o) => o,
        None => {
            errors.push(LintIssue::error(
                "",
                "Root JSON value must be an object.",
            ));
            return LintReport {
                rules_count: 0,
                errors,
                warnings,
            };
        }
    };

    // 2. Required top-level fields.
    for field in REQUIRED_TOP_LEVEL {
        if !obj.contains_key(*field) {
            errors.push(LintIssue::error(
                format!("/{field}"),
                format!("Missing required top-level field '{field}'."),
            ));
        }
    }

    // 11. releaseInfo / 12. category warnings (separate from required fields).
    match obj.get("releaseInfo").and_then(str_or_empty) {
        Some(s) if !s.trim().is_empty() => {}
        _ => warnings.push(LintIssue::warning(
            "/releaseInfo",
            "Top-level 'releaseInfo' is empty — drift detection relies on this field.",
        )),
    }
    match obj.get("category").and_then(str_or_empty) {
        Some(s) if !s.trim().is_empty() => {}
        _ => warnings.push(LintIssue::warning(
            "/category",
            "Top-level 'category' is empty.",
        )),
    }

    // 3. rules must be an array.
    let rules = match obj.get("rules") {
        Some(Value::Array(arr)) => arr,
        Some(_) => {
            errors.push(LintIssue::error(
                "/rules",
                "Field 'rules' must be an array.",
            ));
            return LintReport {
                rules_count,
                errors,
                warnings,
            };
        }
        None => {
            // already reported as a missing-required-field error.
            return LintReport {
                rules_count,
                errors,
                warnings,
            };
        }
    };

    rules_count = rules.len() as i64;

    // Track rule.id positions so we can flag duplicates with both indices.
    let mut seen_ids: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for (idx, rule) in rules.iter().enumerate() {
        let base = format!("/rules/{idx}");

        let rule_obj = match rule.as_object() {
            Some(o) => o,
            None => {
                errors.push(LintIssue::error(
                    &base,
                    format!("Rule at index {idx} must be an object."),
                ));
                continue;
            }
        };

        // 5 & 13. rule.id
        match rule_obj.get("id") {
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    errors.push(LintIssue::error(
                        format!("{base}/id"),
                        "Rule id is empty.",
                    ));
                } else {
                    // 13. character set
                    if !s.chars().all(is_safe_rule_id_char) {
                        errors.push(LintIssue::error(
                            format!("{base}/id"),
                            format!(
                                "Rule id '{s}' contains characters outside [A-Za-z0-9_.-]. \
                                 The id is used as a URL path segment."
                            ),
                        ));
                    }
                    // 4. dup detection (use the literal id string)
                    if let Some(prev_idx) = seen_ids.get(s) {
                        errors.push(LintIssue::error(
                            format!("{base}/id"),
                            format!(
                                "Duplicate rule id '{s}' — also seen at rules[{prev_idx}] and rules[{idx}]."
                            ),
                        ));
                    } else {
                        seen_ids.insert(s.clone(), idx);
                    }
                }
            }
            Some(_) => {
                errors.push(LintIssue::error(
                    format!("{base}/id"),
                    "Rule id must be a string.",
                ));
            }
            None => {
                errors.push(LintIssue::error(
                    format!("{base}/id"),
                    "Rule id is missing.",
                ));
            }
        }

        // 6. severity
        match rule_obj.get("severity").and_then(str_or_empty) {
            Some(s) if VALID_SEVERITIES.contains(&s) => {}
            Some(s) => errors.push(LintIssue::error(
                format!("{base}/severity"),
                format!(
                    "Rule severity '{s}' is invalid. Expected one of: CAT I, CAT II, CAT III."
                ),
            )),
            None => errors.push(LintIssue::error(
                format!("{base}/severity"),
                "Rule severity is missing or not a string. Expected one of: CAT I, CAT II, CAT III.",
            )),
        }

        // 7-10. empty-string warnings on title / description / fixText / check
        for (field, label) in [
            ("title", "title"),
            ("description", "description"),
            ("fixText", "fixText"),
            ("check", "check"),
        ] {
            let empty = match rule_obj.get(field) {
                Some(Value::String(s)) => s.trim().is_empty(),
                Some(_) => true, // non-string is still effectively empty
                None => true,
            };
            if empty {
                warnings.push(LintIssue::warning(
                    format!("{base}/{field}"),
                    format!("Rule {label} is empty."),
                ));
            }
        }
    }

    LintReport {
        rules_count,
        errors,
        warnings,
    }
}

/// POST /api/stigs/lint
///
/// Multipart upload, single field `file` carrying the STIG JSON. Returns
/// the lint report — never writes to disk, never touches the catalog.
pub async fn lint_handler(
    mut multipart: Multipart,
) -> Result<Json<LintReport>, (StatusCode, String)> {
    let mut file_bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Multipart error: {e}"))
    })? {
        if field.name() == Some("file") {
            let bytes = field.bytes().await.map_err(|e| {
                (StatusCode::BAD_REQUEST, format!("Failed to read file field: {e}"))
            })?;
            file_bytes = Some(bytes.to_vec());
        }
    }
    let bytes = file_bytes
        .ok_or((StatusCode::BAD_REQUEST, "Missing 'file' field".into()))?;

    // We deliberately treat a JSON parse failure as a single top-level error
    // rather than a 400 — the lint endpoint's job is to *report* problems,
    // and "malformed JSON" is the most basic one.
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return Ok(Json(LintReport {
                rules_count: 0,
                errors: vec![LintIssue::error(
                    "",
                    format!("Could not parse JSON: {e}"),
                )],
                warnings: vec![],
            }));
        }
    };

    Ok(Json(lint_stig(&value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn paths(issues: &[LintIssue]) -> Vec<&str> {
        issues.iter().map(|i| i.path.as_str()).collect()
    }

    #[test]
    fn root_must_be_object() {
        let report = lint_stig(&json!([1, 2, 3]));
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].path, "");
        assert_eq!(report.rules_count, 0);
    }

    #[test]
    fn missing_required_fields() {
        let report = lint_stig(&json!({}));
        let ps = paths(&report.errors);
        for p in ["/id", "/title", "/version", "/rules"] {
            assert!(ps.contains(&p), "expected {p} in {ps:?}");
        }
    }

    #[test]
    fn rules_not_array_is_error() {
        let report = lint_stig(&json!({
            "id": "x", "title": "T", "version": "1", "rules": {}
        }));
        assert!(report.errors.iter().any(|e| e.path == "/rules"));
    }

    #[test]
    fn duplicate_rule_ids_reported_with_both_indices() {
        let report = lint_stig(&json!({
            "id": "x", "title": "T", "version": "1",
            "rules": [
                {"id": "R-1", "severity": "CAT II", "title": "t", "description": "d", "fixText": "f", "check": "c"},
                {"id": "R-1", "severity": "CAT II", "title": "t", "description": "d", "fixText": "f", "check": "c"}
            ]
        }));
        let dup = report.errors.iter().find(|e| e.path == "/rules/1/id").expect("dup error");
        assert!(dup.message.contains("rules[0]"));
        assert!(dup.message.contains("rules[1]"));
    }

    #[test]
    fn invalid_severity_is_error() {
        let report = lint_stig(&json!({
            "id": "x", "title": "T", "version": "1",
            "rules": [{"id": "R-1", "severity": "Critical", "title": "t", "description": "d", "fixText": "f", "check": "c"}]
        }));
        assert!(report.errors.iter().any(|e| e.path == "/rules/0/severity"));
    }

    #[test]
    fn rule_id_bad_char_is_error() {
        let report = lint_stig(&json!({
            "id": "x", "title": "T", "version": "1", "releaseInfo": "r", "category": "c",
            "rules": [{"id": "R/1", "severity": "CAT II", "title": "t", "description": "d", "fixText": "f", "check": "c"}]
        }));
        assert!(report.errors.iter().any(|e| e.path == "/rules/0/id"));
    }

    #[test]
    fn empty_text_fields_are_warnings() {
        let report = lint_stig(&json!({
            "id": "x", "title": "T", "version": "1", "releaseInfo": "r", "category": "c",
            "rules": [{"id": "R-1", "severity": "CAT II", "title": "", "description": "", "fixText": "", "check": ""}]
        }));
        let ws = paths(&report.warnings);
        for p in ["/rules/0/title", "/rules/0/description", "/rules/0/fixText", "/rules/0/check"] {
            assert!(ws.contains(&p), "expected {p} in {ws:?}");
        }
        assert!(report.errors.is_empty(), "no errors expected, got {:?}", report.errors);
    }

    #[test]
    fn missing_release_info_and_category_are_warnings() {
        let report = lint_stig(&json!({
            "id": "x", "title": "T", "version": "1",
            "rules": [{"id": "R-1", "severity": "CAT II", "title": "t", "description": "d", "fixText": "f", "check": "c"}]
        }));
        let ws = paths(&report.warnings);
        assert!(ws.contains(&"/releaseInfo"));
        assert!(ws.contains(&"/category"));
    }

    #[test]
    fn valid_minimal_stig_clean_lint() {
        let report = lint_stig(&json!({
            "id": "edge", "title": "Edge", "version": "2",
            "releaseInfo": "Release: 2", "category": "Browser",
            "rules": [{"id": "R-1", "severity": "CAT III", "title": "t", "description": "d", "fixText": "f", "check": "c"}]
        }));
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.rules_count, 1);
    }
}
