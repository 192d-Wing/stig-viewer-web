//! Rule-level comparison of two STIGs (used by the version diff view).

use crate::model::{Rule, Stig};
use std::collections::HashMap;

/// Rule fields compared by [`diff_stigs`], in display order. The names are the
/// JSON (camelCase) field names, matching what the diff view labels.
pub const DIFF_FIELDS: [&str; 5] = ["title", "severity", "description", "checkText", "fixText"];

/// One rule present in both STIGs whose compared fields differ.
#[derive(Clone, Debug, PartialEq)]
pub struct ChangedEntry {
    pub stig_id: String,
    /// Rule id on the baseline (A) side.
    pub rule_id: String,
    /// Names of the fields that differ (a subset of [`DIFF_FIELDS`], same order).
    pub fields: Vec<&'static str>,
    /// Baseline values, parallel to `fields`.
    pub a: Vec<String>,
    /// Comparison values, parallel to `fields`.
    pub b: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StigDiff {
    /// Rules in B that are not in A.
    pub added: Vec<Rule>,
    /// Rules in A that are not in B.
    pub removed: Vec<Rule>,
    pub changed: Vec<ChangedEntry>,
}

fn field<'a>(rule: &'a Rule, name: &str) -> &'a str {
    match name {
        "title" => &rule.title,
        "severity" => &rule.severity,
        "description" => &rule.description,
        "checkText" => &rule.check_text,
        "fixText" => &rule.fix_text,
        _ => "",
    }
}

/// Rules keyed by STIG id, iterable in first-seen order. When a STIG id occurs
/// more than once the last rule wins but keeps the first one's position (the
/// semantics of building a JS `Map` from entries).
struct RuleIndex<'a> {
    order: Vec<&'a str>,
    by_id: HashMap<&'a str, &'a Rule>,
}

impl<'a> RuleIndex<'a> {
    fn new(rules: &'a [Rule]) -> Self {
        let mut order = Vec::with_capacity(rules.len());
        let mut by_id = HashMap::with_capacity(rules.len());
        for rule in rules {
            if by_id.insert(rule.stig_id.as_str(), rule).is_none() {
                order.push(rule.stig_id.as_str());
            }
        }
        Self { order, by_id }
    }

    fn iter(&self) -> impl Iterator<Item = (&'a str, &'a Rule)> + '_ {
        self.order.iter().map(|id| (*id, self.by_id[id]))
    }
}

/// Compares two STIGs by STIG id.
///
/// `a` is the baseline (older) STIG, `b` the comparison (newer) one.
pub fn diff_stigs(a: &Stig, b: &Stig) -> StigDiff {
    let index_a = RuleIndex::new(&a.rules);
    let index_b = RuleIndex::new(&b.rules);
    let mut diff = StigDiff::default();

    // Rules in B not in A (added)
    for (id, rule_b) in index_b.iter() {
        if !index_a.by_id.contains_key(id) {
            diff.added.push(rule_b.clone());
        }
    }

    // Rules in A — either removed or potentially changed
    for (id, rule_a) in index_a.iter() {
        let Some(rule_b) = index_b.by_id.get(id) else {
            diff.removed.push(rule_a.clone());
            continue;
        };
        let fields: Vec<&'static str> = DIFF_FIELDS
            .into_iter()
            .filter(|f| field(rule_a, f) != field(rule_b, f))
            .collect();
        if !fields.is_empty() {
            diff.changed.push(ChangedEntry {
                stig_id: id.to_string(),
                rule_id: rule_a.id.clone(),
                a: fields.iter().map(|f| field(rule_a, f).to_string()).collect(),
                b: fields.iter().map(|f| field(rule_b, f).to_string()).collect(),
                fields,
            });
        }
    }

    diff
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(stig_id: &str, title: &str) -> Rule {
        Rule {
            id: format!("S{stig_id}r1_rule"),
            stig_id: stig_id.to_string(),
            title: title.to_string(),
            severity: "CAT II".to_string(),
            description: "desc".to_string(),
            check_text: "check".to_string(),
            fix_text: "fix".to_string(),
            status: "not_reviewed".to_string(),
            ..Rule::default()
        }
    }

    fn stig(rules: Vec<Rule>) -> Stig {
        Stig { title: "T".to_string(), rules, ..Stig::default() }
    }

    #[test]
    fn identical_stigs_have_no_differences() {
        let a = stig(vec![rule("V-1", "one"), rule("V-2", "two")]);
        assert_eq!(diff_stigs(&a, &a.clone()), StigDiff::default());
    }

    #[test]
    fn detects_added_and_removed_rules() {
        let a = stig(vec![rule("V-1", "one"), rule("V-2", "two")]);
        let b = stig(vec![rule("V-2", "two"), rule("V-3", "three"), rule("V-4", "four")]);
        let d = diff_stigs(&a, &b);
        assert_eq!(d.added.iter().map(|r| r.stig_id.as_str()).collect::<Vec<_>>(), ["V-3", "V-4"]);
        assert_eq!(d.removed.iter().map(|r| r.stig_id.as_str()).collect::<Vec<_>>(), ["V-1"]);
        assert!(d.changed.is_empty());
    }

    #[test]
    fn reports_changed_fields_in_declared_order_with_both_values() {
        let a = stig(vec![rule("V-1", "old title")]);
        let mut changed = rule("V-1", "new title");
        changed.id = "SV-1r2_rule".to_string();
        changed.fix_text = "new fix".to_string();
        changed.severity = "CAT I".to_string();
        let d = diff_stigs(&a, &stig(vec![changed]));
        assert!(d.added.is_empty() && d.removed.is_empty());
        assert_eq!(
            d.changed,
            vec![ChangedEntry {
                stig_id: "V-1".to_string(),
                rule_id: "SV-1r1_rule".to_string(),
                fields: vec!["title", "severity", "fixText"],
                a: vec!["old title".to_string(), "CAT II".to_string(), "fix".to_string()],
                b: vec!["new title".to_string(), "CAT I".to_string(), "new fix".to_string()],
            }]
        );
    }

    #[test]
    fn ignores_fields_outside_the_diff_set() {
        let a = stig(vec![rule("V-1", "one")]);
        let mut other = rule("V-1", "one");
        other.status = "open".to_string();
        other.comments = "reviewed".to_string();
        other.finding_details = "details".to_string();
        other.cci_ids = vec!["CCI-000366".to_string()];
        assert_eq!(diff_stigs(&a, &stig(vec![other])), StigDiff::default());
    }

    #[test]
    fn duplicate_stig_ids_keep_the_last_rule() {
        let a = stig(vec![rule("V-1", "first"), rule("V-2", "two"), rule("V-1", "last")]);
        let b = stig(vec![rule("V-1", "last"), rule("V-2", "two")]);
        assert_eq!(diff_stigs(&a, &b), StigDiff::default());

        let d = diff_stigs(&a, &stig(vec![]));
        assert_eq!(d.removed.iter().map(|r| r.title.as_str()).collect::<Vec<_>>(), ["last", "two"]);
    }

    #[test]
    fn empty_stigs() {
        let empty = stig(vec![]);
        let one = stig(vec![rule("V-1", "one")]);
        assert_eq!(diff_stigs(&empty, &empty), StigDiff::default());
        assert_eq!(diff_stigs(&empty, &one).added.len(), 1);
        assert_eq!(diff_stigs(&one, &empty).removed.len(), 1);
    }
}
