//! Host tests for the `TabsState` reducer methods that do not touch js_sys.

use std::collections::HashSet;
use std::rc::Rc;

use super::*;
use crate::model::Rule;

fn rule(id: &str) -> Rule {
    Rule {
        id: id.into(),
        ..Rule::default()
    }
}

fn tab(id: &str, set_id: Option<&str>, catalog_id: Option<&str>, rules: &[&str]) -> StigTab {
    StigTab {
        id: id.into(),
        stig: Rc::new(Stig {
            rules: rules.iter().map(|r| rule(r)).collect(),
            ..Stig::default()
        }),
        asset_info: AssetInfo::default(),
        selected_rule_id: None,
        catalog_id: catalog_id.map(Into::into),
        set_id: set_id.map(Into::into),
    }
}

fn set(id: &str) -> ChecklistSet {
    ChecklistSet {
        id: id.into(),
        name: id.into(),
        revision: 1,
        asset: None,
    }
}

fn state(tabs: Vec<StigTab>, active: Option<&str>) -> TabsState {
    TabsState {
        tabs,
        active_tab_id: active.map(Into::into),
        diff_pair: None,
        sets: Vec::new(),
    }
}

#[test]
fn remove_tab_focuses_the_neighbour_at_the_same_index() {
    let mut s = state(
        vec![
            tab("a", None, None, &[]),
            tab("b", None, None, &[]),
            tab("c", None, None, &[]),
        ],
        Some("b"),
    );
    s.remove_tab("b");
    assert_eq!(s.active_tab_id.as_deref(), Some("c"));
    s.remove_tab("c");
    assert_eq!(s.active_tab_id.as_deref(), Some("a"));
    s.remove_tab("a");
    assert_eq!(s.active_tab_id, None);
    assert!(s.tabs.is_empty());
}

#[test]
fn remove_tab_keeps_focus_when_another_tab_closes_and_clears_diff() {
    let mut s = state(
        vec![tab("a", None, None, &[]), tab("b", None, None, &[])],
        Some("a"),
    );
    s.diff_pair = Some((Some("a".into()), Some("b".into())));
    s.remove_tab("b");
    assert_eq!(s.active_tab_id.as_deref(), Some("a"));
    assert_eq!(s.diff_pair, None);
}

#[test]
fn set_deleted_drops_its_tabs_set_focus_and_diff() {
    let mut s = state(
        vec![
            tab("a", Some("s1"), Some("x"), &[]),
            tab("b", None, None, &[]),
            tab("c", Some("s1"), Some("y"), &[]),
        ],
        Some("c"),
    );
    s.sets = vec![set("s1"), set("s2")];
    s.diff_pair = Some((Some("a".into()), Some("b".into())));
    s.set_deleted("s1");
    assert_eq!(s.tabs.len(), 1);
    assert_eq!(s.tabs[0].id, "b");
    assert_eq!(s.sets.len(), 1);
    assert_eq!(s.sets[0].id, "s2");
    assert_eq!(s.active_tab_id.as_deref(), Some("b"));
    assert_eq!(s.diff_pair, None);
}

#[test]
fn replace_from_server_overlays_rules_except_kept_ones() {
    let mut s = state(
        vec![tab("t1", Some("s1"), Some("stig-1"), &["r1", "r2"])],
        Some("t1"),
    );
    s.sets = vec![set("s1")];
    for r in Rc::make_mut(&mut s.tabs[0].stig).rules.iter_mut() {
        r.status = "open".into();
    }
    let server = vec![(
        "stig-1".to_string(),
        vec![
            ServerRule {
                rule_id: "r1".into(),
                status: "not_a_finding".into(),
                finding_details: "d".into(),
                comments: String::new(),
            },
            ServerRule {
                rule_id: "r2".into(),
                status: "not_a_finding".into(),
                finding_details: String::new(),
                comments: String::new(),
            },
        ],
    )];
    let keep: HashSet<(String, String)> = [("t1".to_string(), "r2".to_string())].into();
    s.replace_from_server("s1", 7, &server, &keep);
    let rules = &s.tabs[0].stig.rules;
    assert_eq!(rules[0].status, "not_a_finding");
    assert_eq!(rules[0].finding_details, "d");
    assert_eq!(rules[1].status, "open");
    assert_eq!(s.sets[0].revision, 7);
}

#[test]
fn reduce_dispatches_simple_actions() {
    let s = Rc::new(state(
        vec![tab("a", None, None, &[]), tab("b", None, None, &[])],
        None,
    ));
    let s = s.reduce(TabsAction::SetActive("b".into()));
    assert_eq!(s.active_tab_id.as_deref(), Some("b"));
    let mut with_set = (*s).clone();
    with_set.sets = vec![set("s1")];
    let s = Rc::new(with_set).reduce(TabsAction::SetSaved {
        set_id: "s1".into(),
        revision: 9,
    });
    assert_eq!(s.sets[0].revision, 9);
    let s = s.reduce(TabsAction::SetRenamed {
        set_id: "s1".into(),
        name: "New".into(),
    });
    assert_eq!(s.sets[0].name, "New");
}
