//! Severity / status vocabularies shared by the viewer, exports and badges.

/// XCCDF severity attribute → DISA category label.
pub fn severity_label(xccdf_severity: &str) -> Option<&'static str> {
    match xccdf_severity {
        "high" => Some("CAT I"),
        "medium" => Some("CAT II"),
        "low" => Some("CAT III"),
        _ => None,
    }
}

pub const SEVERITY_ORDER: [&str; 3] = ["CAT I", "CAT II", "CAT III"];

/// Severity → Badge colour.
pub fn severity_badge_color(cat: &str) -> &'static str {
    match cat {
        "CAT I" => "severity-high",
        "CAT II" => "severity-medium",
        "CAT III" => "severity-low",
        _ => "grey",
    }
}

pub struct StatusOption {
    pub value: &'static str,
    pub label: &'static str,
}

pub const STATUS_OPTIONS: [StatusOption; 4] = [
    StatusOption { value: "not_reviewed", label: "Not Reviewed" },
    StatusOption { value: "not_a_finding", label: "Not a Finding" },
    StatusOption { value: "open", label: "Open" },
    StatusOption { value: "not_applicable", label: "Not Applicable" },
];

/// Status value → CKL `<STATUS>` text.
pub fn status_ckl(status: &str) -> &'static str {
    match status {
        "not_a_finding" => "NotAFinding",
        "open" => "Open",
        "not_applicable" => "Not_Applicable",
        _ => "Not_Reviewed",
    }
}

/// Status value → display label (falls back to the raw value).
pub fn status_label(status: &str) -> &str {
    match status {
        "not_reviewed" => "Not Reviewed",
        "not_a_finding" => "Not a Finding",
        "open" => "Open",
        "not_applicable" => "Not Applicable",
        other => other,
    }
}

/// Status value → StatusIndicator kind.
pub fn status_indicator_kind(status: &str) -> &'static str {
    match status {
        "not_a_finding" => "success",
        "open" => "error",
        "not_applicable" => "stopped",
        _ => "pending",
    }
}

/// (rule field key, label) pairs for the free-text finding fields.
pub const FINDING_DETAILS_FIELDS: [(&str, &str); 2] =
    [("findingDetails", "Finding Details"), ("comments", "Comments")];

#[cfg(test)]
mod severity_badge_tests {
    use super::*;

    #[test]
    fn maps_cat_levels_to_severity_classes() {
        assert_eq!(severity_badge_color("CAT I"), "severity-high");
        assert_eq!(severity_badge_color("CAT II"), "severity-medium");
        assert_eq!(severity_badge_color("CAT III"), "severity-low");
        assert_eq!(severity_badge_color("bogus"), "grey");
    }
}
