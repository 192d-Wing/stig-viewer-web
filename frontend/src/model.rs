//! Shared data model for parsed STIGs (viewer tabs, library loads, exports).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::rc::Rc;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Rule {
    pub id: String,
    pub stig_id: String,
    pub group_id: String,
    pub title: String,
    /// "CAT I" | "CAT II" | "CAT III"
    pub severity: String,
    pub description: String,
    pub fix_text: String,
    pub check_text: String,
    pub cci_ids: Vec<String>,
    /// "not_reviewed" | "not_a_finding" | "open" | "not_applicable"
    #[serde(default = "default_status")]
    pub status: String,
    pub finding_details: String,
    pub comments: String,
    /// Any other keys on the rule JSON (drafts, catalog payloads). Carried
    /// through untouched so a load → edit → save round trip doesn't drop them.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn default_status() -> String {
    "not_reviewed".to_string()
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Stig {
    pub title: String,
    pub description: String,
    pub version: String,
    pub release_info: String,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AssetInfo {
    pub hostname: String,
    pub ip: String,
    pub mac: String,
    pub fqdn: String,
}

/// One open checklist in the viewer.
#[derive(Clone, Debug, PartialEq)]
pub struct StigTab {
    pub id: String,
    pub stig: Rc<Stig>,
    pub asset_info: AssetInfo,
    pub selected_rule_id: Option<String>,
    /// Catalog id when the tab was opened from the library; `None` for local
    /// files and the demo STIG. Needed to save the tab to a system.
    pub catalog_id: Option<String>,
}

impl Rule {
    /// True when the user has evaluated the rule: a status other than
    /// `not_reviewed`, or non-blank finding details or comments.
    pub fn is_touched(&self) -> bool {
        self.status != "not_reviewed"
            || !self.finding_details.trim().is_empty()
            || !self.comments.trim().is_empty()
    }
}

impl Stig {
    /// Rules worth sending to "Save to system".
    pub fn rules_to_save(&self) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.is_touched()).collect()
    }

    /// Set `status` on every rule whose id is in `rule_ids`. Returns how many
    /// rules were changed to a different status.
    pub fn set_status_for(&mut self, rule_ids: &[String], status: &str) -> usize {
        let wanted: HashSet<&str> = rule_ids.iter().map(String::as_str).collect();
        let mut changed = 0;
        for r in self.rules.iter_mut().filter(|r| wanted.contains(r.id.as_str())) {
            if r.status != status {
                r.status = status.to_string();
                changed += 1;
            }
        }
        changed
    }
}

/// Rule ids covered by a shift-click from `anchor` to `target` within the
/// visible `ids` (inclusive, either direction). Falls back to just `target`
/// when the anchor is no longer visible.
pub fn id_range(ids: &[String], anchor: Option<&str>, target: &str) -> Vec<String> {
    let pos = |id: &str| ids.iter().position(|x| x == id);
    match (anchor.and_then(pos), pos(target)) {
        (Some(a), Some(t)) => ids[a.min(t)..=a.max(t)].to_vec(),
        _ => vec![target.to_string()],
    }
}

/// Partial update applied to a rule from the detail panel.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RuleUpdate {
    pub status: Option<String>,
    pub finding_details: Option<String>,
    pub comments: Option<String>,
}

impl RuleUpdate {
    pub fn apply(&self, r: &mut Rule) {
        if let Some(v) = &self.status {
            r.status = v.clone();
        }
        if let Some(v) = &self.finding_details {
            r.finding_details = v.clone();
        }
        if let Some(v) = &self.comments {
            r.comments = v.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stig(ids: &[&str]) -> Stig {
        Stig { rules: ids.iter().map(|id| Rule { id: id.to_string(), status: default_status(), ..Rule::default() }).collect(), ..Stig::default() }
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn set_status_for_only_touches_the_given_rules() {
        let mut s = stig(&["a", "b", "c"]);
        assert_eq!(s.set_status_for(&ids(&["a", "c", "missing"]), "open"), 2);
        let statuses: Vec<&str> = s.rules.iter().map(|r| r.status.as_str()).collect();
        assert_eq!(statuses, ["open", "not_reviewed", "open"]);
        // Re-applying the same status changes nothing.
        assert_eq!(s.set_status_for(&ids(&["a"]), "open"), 0);
    }

    #[test]
    fn is_touched_and_rules_to_save() {
        let mut s = stig(&["a", "b", "c", "d"]);
        s.rules[0].status = "open".into();
        s.rules[1].comments = "note".into();
        s.rules[2].finding_details = "   ".into();
        assert!(s.rules[0].is_touched());
        assert!(s.rules[1].is_touched());
        assert!(!s.rules[2].is_touched());
        let saved: Vec<&str> = s.rules_to_save().iter().map(|r| r.id.as_str()).collect();
        assert_eq!(saved, ["a", "b"]);
    }

    #[test]
    fn id_range_is_inclusive_in_either_direction() {
        let all = ids(&["a", "b", "c", "d"]);
        assert_eq!(id_range(&all, Some("b"), "d"), ids(&["b", "c", "d"]));
        assert_eq!(id_range(&all, Some("d"), "b"), ids(&["b", "c", "d"]));
        assert_eq!(id_range(&all, Some("c"), "c"), ids(&["c"]));
        assert_eq!(id_range(&all, None, "c"), ids(&["c"]));
        assert_eq!(id_range(&all, Some("gone"), "c"), ids(&["c"]));
    }
}
