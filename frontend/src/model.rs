//! Shared data model for parsed STIGs (viewer tabs, library loads, exports).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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
    /// The checklist set this tab autosaves into. `None` until the first edit
    /// of a catalog tab creates one, and always `None` for local files.
    pub set_id: Option<String>,
}

/// A server-side checklist set as the viewer tracks it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChecklistSet {
    pub id: String,
    pub name: String,
    pub revision: i64,
    /// `(asset id, asset name)` of the system the set was last saved to.
    pub asset: Option<(String, String)>,
}

/// One rule's stored state in a set (the server only keeps touched rules).
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerRule {
    pub rule_id: String,
    pub status: String,
    pub finding_details: String,
    pub comments: String,
}

/// One rule's full state as sent by autosave.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRuleChange {
    pub stig_id: String,
    pub rule_id: String,
    pub status: String,
    pub finding_details: String,
    pub comments: String,
}

/// Most changes per autosave request (the server accepts 2000).
pub const BATCH_MAX_CHANGES: usize = 500;
/// Rough serialized size cap per autosave request (the server limit is 1 MiB).
pub const BATCH_MAX_BYTES: usize = 768 * 1024;

/// Split changes into requests of at most `max_count` changes and roughly
/// `max_bytes` of JSON. A single change over the byte cap goes alone.
pub fn split_batches(changes: Vec<SetRuleChange>, max_count: usize, max_bytes: usize) -> Vec<Vec<SetRuleChange>> {
    let mut out: Vec<Vec<SetRuleChange>> = Vec::new();
    let mut cur: Vec<SetRuleChange> = Vec::new();
    let mut cur_bytes = 0usize;
    for c in changes {
        let n = serde_json::to_string(&c).map(|s| s.len() + 1).unwrap_or(0);
        if !cur.is_empty() && (cur.len() >= max_count || cur_bytes + n > max_bytes) {
            out.push(std::mem::take(&mut cur));
            cur_bytes = 0;
        }
        cur_bytes += n;
        cur.push(c);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Tracks which rules were edited since they were last autosaved. Each mark
/// takes a fresh sequence number so an edit made while a request is in flight
/// is not cleared when that request is acknowledged.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DirtyTracker {
    seq: u64,
    entries: HashMap<(String, String), u64>,
}

impl DirtyTracker {
    pub fn mark(&mut self, tab_id: &str, rule_id: &str) {
        self.seq += 1;
        self.entries.insert((tab_id.to_string(), rule_id.to_string()), self.seq);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn is_dirty(&self, tab_id: &str, rule_id: &str) -> bool {
        self.entries.contains_key(&(tab_id.to_string(), rule_id.to_string()))
    }

    /// Tab ids that have at least one dirty rule.
    pub fn dirty_tabs(&self) -> Vec<String> {
        let mut tabs: Vec<String> = self.entries.keys().map(|(t, _)| t.clone()).collect();
        tabs.sort();
        tabs.dedup();
        tabs
    }

    /// Dirty `(tab id, rule id)` pairs of the given tabs (oldest edit first)
    /// and the highest sequence number among them.
    pub fn take_batch(&self, tab_ids: &[&str]) -> (Vec<(String, String)>, u64) {
        let mut hits: Vec<(&(String, String), &u64)> =
            self.entries.iter().filter(|((t, _), _)| tab_ids.contains(&t.as_str())).collect();
        hits.sort_by_key(|(k, seq)| (**seq, (*k).clone()));
        let high_water = hits.iter().map(|(_, s)| **s).max().unwrap_or(0);
        (hits.into_iter().map(|(k, _)| k.clone()).collect(), high_water)
    }

    /// Clear the given tabs' entries not edited again since `high_water`.
    pub fn ack(&mut self, tab_ids: &[&str], high_water: u64) {
        self.entries.retain(|(t, _), seq| !(tab_ids.contains(&t.as_str()) && *seq <= high_water));
    }

    /// Forget everything about a tab (closed, or replaced from the server).
    pub fn forget_tab(&mut self, tab_id: &str) {
        self.entries.retain(|(t, _), _| t != tab_id);
    }
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

    /// Put server-stored rule state onto this (catalog) STIG: every rule not
    /// in `keep` is reset to untouched, then the server's rules are applied.
    /// Returns how many server rules match no rule in this STIG.
    pub fn overlay_server_state(&mut self, server: &[ServerRule], keep: &HashSet<String>) -> usize {
        for r in self.rules.iter_mut().filter(|r| !keep.contains(&r.id)) {
            r.status = default_status();
            r.finding_details.clear();
            r.comments.clear();
        }
        let index: HashMap<String, usize> = self.rules.iter().enumerate().map(|(i, r)| (r.id.clone(), i)).collect();
        let mut unknown = 0;
        for s in server {
            match index.get(&s.rule_id) {
                Some(&i) if !keep.contains(&s.rule_id) => {
                    let r = &mut self.rules[i];
                    r.status = if s.status.is_empty() { default_status() } else { s.status.clone() };
                    r.finding_details = s.finding_details.clone();
                    r.comments = s.comments.clone();
                }
                Some(_) => {}
                None => unknown += 1,
            }
        }
        unknown
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

/// Ids from `selected` that are still in `filtered_ids`, in filtered order.
pub fn visible_selection(filtered_ids: &[&str], selected: &[String]) -> Vec<String> {
    let sel: HashSet<&str> = selected.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    filtered_ids.iter().copied().filter(|id| sel.contains(id) && seen.insert(*id)).map(str::to_string).collect()
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

    fn change(rule: &str, details: &str) -> SetRuleChange {
        SetRuleChange {
            stig_id: "S".into(),
            rule_id: rule.into(),
            status: "open".into(),
            finding_details: details.into(),
            comments: String::new(),
        }
    }

    #[test]
    fn ack_keeps_rules_edited_while_the_request_was_in_flight() {
        let mut t = DirtyTracker::default();
        t.mark("t1", "a");
        t.mark("t1", "b");
        t.mark("t2", "z");
        let (keys, hw) = t.take_batch(&["t1"]);
        assert_eq!(keys, vec![("t1".to_string(), "a".to_string()), ("t1".to_string(), "b".to_string())]);
        // "a" is edited again before the response arrives.
        t.mark("t1", "a");
        t.ack(&["t1"], hw);
        assert!(t.is_dirty("t1", "a"));
        assert!(!t.is_dirty("t1", "b"));
        // Another tab's entries are untouched by the ack.
        assert!(t.is_dirty("t2", "z"));
        assert_eq!(t.len(), 2);
        assert_eq!(t.dirty_tabs(), vec!["t1".to_string(), "t2".to_string()]);
    }

    #[test]
    fn batch_holds_only_the_requested_tabs_changed_rules() {
        let mut t = DirtyTracker::default();
        t.mark("t1", "a");
        t.mark("t1", "a");
        t.mark("t2", "b");
        let (keys, _) = t.take_batch(&["t1"]);
        assert_eq!(keys, vec![("t1".to_string(), "a".to_string())]);
        t.forget_tab("t1");
        assert_eq!(t.dirty_tabs(), vec!["t2".to_string()]);
        assert_eq!(t.take_batch(&["t1"]).0.len(), 0);
    }

    #[test]
    fn batches_split_by_count_and_by_bytes() {
        let many: Vec<SetRuleChange> = (0..7).map(|i| change(&format!("r{i}"), "")).collect();
        let sizes: Vec<usize> = split_batches(many, 3, usize::MAX).iter().map(Vec::len).collect();
        assert_eq!(sizes, [3, 3, 1]);
        let big: Vec<SetRuleChange> = (0..4).map(|i| change(&format!("r{i}"), &"x".repeat(1000))).collect();
        let sizes: Vec<usize> = split_batches(big, 500, 2500).iter().map(Vec::len).collect();
        assert_eq!(sizes, [2, 2]);
        // An oversize single change still goes out, alone.
        let one = vec![change("r", &"x".repeat(5000)), change("s", "")];
        let sizes: Vec<usize> = split_batches(one, 500, 100).iter().map(Vec::len).collect();
        assert_eq!(sizes, [1, 1]);
        assert!(split_batches(Vec::new(), 3, 10).is_empty());
    }

    #[test]
    fn overlay_applies_sparse_rules_resets_the_rest_and_counts_unknown() {
        let mut s = stig(&["a", "b", "c"]);
        s.rules[2].status = "open".into();
        let server = vec![
            ServerRule { rule_id: "a".into(), status: "open".into(), finding_details: "d".into(), comments: "c".into() },
            ServerRule { rule_id: "gone".into(), status: "open".into(), ..ServerRule::default() },
            ServerRule { rule_id: "x".into(), status: "open".into(), ..ServerRule::default() },
        ];
        assert_eq!(s.overlay_server_state(&server, &HashSet::new()), 2);
        let st: Vec<&str> = s.rules.iter().map(|r| r.status.as_str()).collect();
        assert_eq!(st, ["open", "not_reviewed", "not_reviewed"]);
        assert_eq!((s.rules[0].finding_details.as_str(), s.rules[0].comments.as_str()), ("d", "c"));
    }

    #[test]
    fn overlay_leaves_kept_rules_alone() {
        let mut s = stig(&["a", "b"]);
        s.rules[0].status = "open".into();
        s.rules[0].comments = "mine".into();
        let server = vec![
            ServerRule { rule_id: "a".into(), status: "not_applicable".into(), ..ServerRule::default() },
            ServerRule { rule_id: "b".into(), status: "open".into(), ..ServerRule::default() },
        ];
        let keep: HashSet<String> = ["a".to_string()].into();
        assert_eq!(s.overlay_server_state(&server, &keep), 0);
        assert_eq!((s.rules[0].status.as_str(), s.rules[0].comments.as_str()), ("open", "mine"));
        assert_eq!(s.rules[1].status, "open");
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

    #[test]
    fn visible_selection_is_in_filtered_order_and_drops_hidden() {
        let selected = ids(&["c", "gone", "a", "hidden"]);
        assert_eq!(visible_selection(&["a", "b", "c"], &selected), ids(&["a", "c"]));
        assert!(visible_selection(&[], &selected).is_empty());
        assert!(visible_selection(&["a"], &[]).is_empty());
        // Duplicate ids in the filtered rows are acted on once.
        assert_eq!(visible_selection(&["a", "b", "a"], &ids(&["a", "b"])), ids(&["a", "b"]));
    }
}
