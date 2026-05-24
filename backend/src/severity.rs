//! Severity weighting helpers shared by the dashboard and findings APIs.
//!
//! Two scoring schemes live here:
//!   * `severity_weight` — integer weights used by the legacy
//!     `risk_score` aggregate (CAT I = 10, CAT II = 3, CAT III = 1).
//!   * SCAP-style weighted scoring built on top, multiplying severity by
//!     asset classification and an overdue bonus. See `weighted_score`.
//!
//! Both modules used to inline their own copies of `severity_weight` and a
//! `load_severity_map` reader; pulling them here keeps the math in one
//! place so a future tweak (e.g. CAT IV) only needs to land once.
//!
//! `weighted_score` is intentionally a *separate* metric from `risk_score`
//! — the existing dashboard contract is unchanged, and the new field is
//! additive on `AssetSummary` / `Totals` / `Finding`.

use chrono::NaiveDate;
use std::collections::HashMap;

use crate::AppState;

/// Integer severity weight used by `risk_score` (legacy) and the
/// numerator of `weighted_score`. Unknown severities fall through to 1
/// so they never inflate the score artificially.
pub fn severity_weight(sev: &str) -> i64 {
    let s = sev.to_ascii_uppercase();
    if s.contains("CAT I") && !s.contains("CAT II") {
        10
    } else if s.contains("CAT II") && !s.contains("CAT III") {
        3
    } else if s.contains("CAT III") {
        1
    } else {
        1
    }
}

/// Per-asset classification multiplier for SCAP-style scoring. Matches
/// the four classification levels assets can hold today; anything else
/// (empty / future value) maps to 1.0 so the formula degrades cleanly.
pub fn classification_multiplier(classification: &str) -> f64 {
    match classification.to_ascii_lowercase().as_str() {
        "top-secret" => 2.0,
        "secret" => 1.5,
        "cui" => 1.2,
        _ => 1.0, // unclassified / unknown
    }
}

/// 2.0 when the finding is still open AND has a due_date in the past
/// (relative to `today`). 1.0 otherwise — i.e. the bonus never *reduces*
/// the score.
pub fn overdue_bonus(status: &str, due_date: Option<NaiveDate>, today: NaiveDate) -> f64 {
    if status == "open" {
        if let Some(d) = due_date {
            if d < today {
                return 2.0;
            }
        }
    }
    1.0
}

/// SCAP-style weighted score for a single finding. Result is rounded to
/// one decimal so JSON payloads stay tidy and the badge / KPI tile can
/// render the number directly without further formatting on the
/// frontend.
pub fn weighted_score(
    severity: &str,
    classification: &str,
    status: &str,
    due_date: Option<NaiveDate>,
    today: NaiveDate,
) -> f64 {
    let raw = severity_weight(severity) as f64
        * classification_multiplier(classification)
        * overdue_bonus(status, due_date, today);
    (raw * 10.0).round() / 10.0
}

/// Read the STIG JSON for `stig_id` from disk and return a
/// `{rule_id -> severity}` map. Returns an empty map on any read/parse
/// failure (callers treat "unknown" as the lowest weight).
///
/// This is the consolidated version of the previously-duplicated reader
/// in dashboard.rs.
pub async fn load_severity_map(state: &AppState, stig_id: &str) -> HashMap<String, String> {
    if !stig_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return HashMap::new();
    }
    let path = state
        .config
        .data_dir
        .join("stigs")
        .join(format!("{stig_id}.json"));
    let contents = match tokio::fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(_) => return HashMap::new(),
    };
    let value: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };
    let rules = match value.get("rules").and_then(|v| v.as_array()) {
        Some(r) => r,
        None => return HashMap::new(),
    };
    rules
        .iter()
        .filter_map(|r| {
            let id = r.get("id")?.as_str()?.to_string();
            let sev = r.get("severity")?.as_str()?.to_string();
            Some((id, sev))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn severity_weights() {
        assert_eq!(severity_weight("CAT I"), 10);
        assert_eq!(severity_weight("cat i"), 10);
        assert_eq!(severity_weight("CAT II"), 3);
        assert_eq!(severity_weight("CAT III"), 1);
        assert_eq!(severity_weight(""), 1);
        assert_eq!(severity_weight("bogus"), 1);
    }

    #[test]
    fn classification_multipliers() {
        assert_eq!(classification_multiplier("top-secret"), 2.0);
        assert_eq!(classification_multiplier("secret"), 1.5);
        assert_eq!(classification_multiplier("cui"), 1.2);
        assert_eq!(classification_multiplier("unclassified"), 1.0);
        assert_eq!(classification_multiplier(""), 1.0);
        assert_eq!(classification_multiplier("anything-else"), 1.0);
    }

    #[test]
    fn overdue_bonus_only_for_open_with_past_due_date() {
        let today = NaiveDate::from_ymd_opt(2026, 5, 20).unwrap();
        let past = NaiveDate::from_ymd_opt(2020, 1, 1).unwrap();
        let future = NaiveDate::from_ymd_opt(2099, 1, 1).unwrap();

        assert_eq!(overdue_bonus("open", Some(past), today), 2.0);
        assert_eq!(overdue_bonus("open", Some(future), today), 1.0);
        assert_eq!(overdue_bonus("open", None, today), 1.0);
        // Closed (any non-"open" status) doesn't get the bonus even
        // when past-due.
        assert_eq!(overdue_bonus("not_a_finding", Some(past), today), 1.0);
    }

    #[test]
    fn weighted_score_examples() {
        let today = NaiveDate::from_ymd_opt(2026, 5, 20).unwrap();
        let past = NaiveDate::from_ymd_opt(2020, 1, 1).unwrap();

        // CAT I on top-secret, not past-due: 10 × 2.0 × 1.0 = 20.0
        assert_eq!(
            weighted_score("CAT I", "top-secret", "open", None, today),
            20.0
        );
        // CAT I on unclassified, not past-due: 10 × 1.0 × 1.0 = 10.0
        assert_eq!(
            weighted_score("CAT I", "unclassified", "open", None, today),
            10.0
        );
        // CAT I on top-secret, past-due: 10 × 2.0 × 2.0 = 40.0
        assert_eq!(
            weighted_score("CAT I", "top-secret", "open", Some(past), today),
            40.0
        );
        // CAT II on cui, not past-due: 3 × 1.2 × 1.0 = 3.6
        assert_eq!(
            weighted_score("CAT II", "cui", "open", None, today),
            3.6
        );
        // CAT III on secret: 1 × 1.5 × 1.0 = 1.5
        assert_eq!(
            weighted_score("CAT III", "secret", "open", None, today),
            1.5
        );
    }
}
