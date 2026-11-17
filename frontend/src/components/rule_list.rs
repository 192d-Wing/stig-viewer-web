use crate::components::badges::{SeverityBadge, StatusBadge};
use crate::constants::STATUS_OPTIONS;
use crate::model::{id_range, Rule};
use crate::ui::*;
use std::collections::HashSet;
use std::rc::Rc;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct RuleListProps {
    /// Rules that pass the current filters.
    pub rules: Rc<Vec<Rule>>,
    pub all_rules_count: usize,
    #[prop_or_default]
    pub selected_rule_id: Option<String>,
    pub search_term: AttrValue,
    pub on_search_change: Callback<String>,
    pub on_select_rule: Callback<Rule>,
    /// New status for every rule.
    pub on_set_all_status: Callback<String>,
    /// Ids of the listed rules that are ticked for a multi-rule status change.
    #[prop_or_default]
    pub checked_ids: Vec<String>,
    /// (rule ids, ticked) — tick or untick the given rules.
    #[prop_or_default]
    pub on_check: Callback<(Vec<String>, bool)>,
    /// New status for the ticked rules.
    #[prop_or_default]
    pub on_set_checked_status: Callback<String>,
}

#[function_component]
pub fn RuleList(p: &RuleListProps) -> Html {
    let set_all = |status: &'static str| p.on_set_all_status.reform(move |_: MouseEvent| status.to_string());

    // Last rule ticked or unticked; the anchor for shift-click ranges.
    let anchor = use_state(|| None::<String>);
    let visible_ids: Rc<Vec<String>> = Rc::new(p.rules.iter().map(|r| r.id.clone()).collect());
    let checked_set: HashSet<&str> = p.checked_ids.iter().map(String::as_str).collect();
    let checked_count = p.checked_ids.len();
    let all_checked = !p.rules.is_empty() && checked_count == p.rules.len();

    let toggle_all = {
        let (ids, on_check) = (visible_ids.clone(), p.on_check.clone());
        Callback::from(move |_: Event| on_check.emit(((*ids).clone(), !all_checked)))
    };
    let clear = {
        let (ids, on_check) = (visible_ids.clone(), p.on_check.clone());
        Callback::from(move |_: MouseEvent| on_check.emit(((*ids).clone(), false)))
    };

    html! {
        <div style="display:flex;flex-direction:column;height:100%;overflow:hidden;">
            // Search bar
            <div style="padding:10px 12px;border-bottom:1px solid var(--border);flex-shrink:0;">
                <TextFilter
                    filtering_text={p.search_term.clone()}
                    on_change={p.on_search_change.clone()}
                    filtering_placeholder="Search by ID, title, or content…"
                    count_text={format!("{} of {} rules", p.rules.len(), p.all_rules_count)}
                />
                <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:6px;flex-wrap:wrap;">
                    <label class="ui-checkbox-label">
                        <input type="checkbox" checked={all_checked} disabled={p.rules.is_empty()}
                               onchange={toggle_all} data-testid="rule-check-all" />
                        <span>{"Select all"}</span>
                    </label>
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button variant="inline-link" onclick={set_all("not_a_finding")}>{"All NaF"}</Button>
                        <Button variant="inline-link" onclick={set_all("not_reviewed")}>{"Reset All"}</Button>
                    </SpaceBetween>
                </div>
                if checked_count > 0 {
                    <div role="toolbar" aria-label="Set status for selected rules" data-testid="rule-bulk-bar"
                         style="display:flex;align-items:center;gap:6px 10px;flex-wrap:wrap;margin-top:8px;\
                                padding:6px 10px;border-radius:var(--radius);background:var(--bg-selected);">
                        <strong data-testid="rule-bulk-count">{format!("{checked_count} selected")}</strong>
                        <span style="color:var(--text-secondary);">{"Set status:"}</span>
                        { for STATUS_OPTIONS.iter().map(|opt| {
                            let onclick = p.on_set_checked_status.reform(move |_: MouseEvent| opt.value.to_string());
                            html! {
                                <Button key={opt.value} variant="inline-link" {onclick}
                                        testid={format!("rule-bulk-set-{}", opt.value)}>
                                    {opt.label}
                                </Button>
                            }
                        }) }
                        <span style="margin-left:auto;">
                            <Button variant="inline-link" onclick={clear} testid="rule-bulk-clear">{"Clear"}</Button>
                        </span>
                    </div>
                }
            </div>

            // Rule list
            <div role="listbox" aria-label="Rules" style="flex:1;overflow-y:auto;">
                if p.rules.is_empty() {
                    <UiBox text_align="center" padding_vertical="l" color="text-status-inactive">
                        {"No rules match the current filters"}
                    </UiBox>
                } else {
                    { for p.rules.iter().map(|rule| {
                        let is_selected = p.selected_rule_id.as_deref() == Some(rule.id.as_str());
                        let is_checked = checked_set.contains(rule.id.as_str());
                        let onclick = {
                            let (rule, on_select_rule) = (rule.clone(), p.on_select_rule.clone());
                            Callback::from(move |_: MouseEvent| on_select_rule.emit(rule.clone()))
                        };
                        // Click toggles one rule; shift-click applies the new
                        // state to every rule between the last toggle and this one.
                        let on_check_click = {
                            let (id, ids, anchor, on_check) =
                                (rule.id.clone(), visible_ids.clone(), anchor.clone(), p.on_check.clone());
                            Callback::from(move |e: MouseEvent| {
                                let targets = if e.shift_key() {
                                    id_range(&ids, anchor.as_deref(), &id)
                                } else {
                                    vec![id.clone()]
                                };
                                anchor.set(Some(id.clone()));
                                on_check.emit((targets, !is_checked));
                            })
                        };
                        let row_style = format!(
                            "display:flex;align-items:stretch;border-bottom:1px solid var(--border);\
                             border-left:3px solid {};background:{};",
                            if is_selected { "var(--primary)" } else { "transparent" },
                            if is_selected || is_checked { "var(--bg-selected)" } else { "transparent" },
                        );
                        html! {
                            <div key={rule.id.clone()} style={row_style}>
                                <label style="display:flex;align-items:flex-start;padding:12px 0 0 12px;cursor:pointer;">
                                    <input type="checkbox" checked={is_checked} onclick={on_check_click}
                                           aria-label={format!("Select {}", rule.stig_id)} data-testid="rule-check" />
                                </label>
                                <button type="button" role="option"
                                        aria-selected={is_selected.to_string()} {onclick}
                                        style="display:block;flex:1;min-width:0;padding:10px 14px 10px 10px;border:none;\
                                               background:transparent;text-align:left;cursor:pointer;">
                                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
                                        <span style="font-family:var(--mono);font-size:12px;font-weight:700;\
                                                     color:var(--primary);min-width:65px;flex-shrink:0;">
                                            {rule.stig_id.clone()}
                                        </span>
                                        <SeverityBadge severity={rule.severity.clone()} />
                                        <StatusBadge status={rule.status.clone()} />
                                    </div>
                                    <p style="font-size:13px;color:var(--text);line-height:1.4;display:-webkit-box;\
                                              -webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;\
                                              text-align:left;margin:0;">
                                        {rule.title.clone()}
                                    </p>
                                </button>
                            </div>
                        }
                    }) }
                }
            </div>
        </div>
    }
}
