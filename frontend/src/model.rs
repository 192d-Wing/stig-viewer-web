//! Shared data model for parsed STIGs (viewer tabs, library loads, exports).

use serde::{Deserialize, Serialize};
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
