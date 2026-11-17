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

/// AC-8 system use notification shown before sign-in (NIST SP 800-53 Rev. 5 AC-8;
/// DoDI 8500.01 and the DoD CIO standard Notice and Consent Banner).
/// The short-form banner is intentionally not used here: it is only permitted
/// where a severe character limit prevents showing the full text.
/// Version of the notice wording. Bump it whenever any notice text changes; a
/// future AU-2 acknowledgement record should cite it. The pinned hash test in
/// this file fails when the wording changes without a version bump.
pub const USE_NOTICE_VERSION: &str = "DoD-NCB-standard-2026-11";
pub const USE_NOTICE_TITLE: &str = "Notice and Consent";
pub const USE_NOTICE_INTRO: &str = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.";
pub const USE_NOTICE_LEAD: &str = "By using this IS (which includes any device attached to this IS), you consent to the following conditions:";
pub const USE_NOTICE_CONDITIONS: [&str; 5] = [
    "The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.",
    "At any time, the USG may inspect and seize data stored on this IS.",
    "Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.",
    "This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.",
    "Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.",
];
pub const USE_NOTICE_ACK_LABEL: &str = "I Agree";

#[cfg(test)]
mod use_notice_tests {
    use super::*;

    /// FNV-1a 64 over intro, lead and conditions (each followed by `\n`).
    /// If this fails, the wording changed: update `USE_NOTICE_VERSION` and these pins.
    #[test]
    fn notice_wording_is_pinned_to_version() {
        let mut text = String::new();
        for t in [USE_NOTICE_INTRO, USE_NOTICE_LEAD].into_iter().chain(USE_NOTICE_CONDITIONS) {
            text.push_str(t);
            text.push('\n');
        }
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in text.bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        assert_eq!(text.len(), 1294);
        assert_eq!(h, 0x13bc09f5dc6f0b50);
        assert_eq!(USE_NOTICE_VERSION, "DoD-NCB-standard-2026-11");
    }

    #[test]
    fn notice_text_is_complete_and_clean() {
        assert_eq!(USE_NOTICE_CONDITIONS.len(), 5);
        assert!(USE_NOTICE_INTRO
            .starts_with("You are accessing a U.S. Government (USG) Information System (IS)"));
        assert!(USE_NOTICE_CONDITIONS[4].ends_with("See User Agreement for details."));
        let all = [USE_NOTICE_TITLE, USE_NOTICE_INTRO, USE_NOTICE_LEAD, USE_NOTICE_ACK_LABEL]
            .into_iter()
            .chain(USE_NOTICE_CONDITIONS);
        for t in all {
            assert!(!t.is_empty());
            assert_eq!(t, t.trim());
        }
    }
}

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
