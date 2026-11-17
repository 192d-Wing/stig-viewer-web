use crate::components::badges::{SeverityBadge, StatusBadge};
use crate::model::Rule;
use crate::ui::*;
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
}

#[function_component]
pub fn RuleList(p: &RuleListProps) -> Html {
    let set_all = |status: &'static str| p.on_set_all_status.reform(move |_: MouseEvent| status.to_string());

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
                <div style="display:flex;justify-content:flex-end;margin-top:6px;">
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button variant="inline-link" onclick={set_all("not_a_finding")}>{"All NaF"}</Button>
                        <Button variant="inline-link" onclick={set_all("not_reviewed")}>{"Reset All"}</Button>
                    </SpaceBetween>
                </div>
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
                        let onclick = {
                            let (rule, on_select_rule) = (rule.clone(), p.on_select_rule.clone());
                            Callback::from(move |_: MouseEvent| on_select_rule.emit(rule.clone()))
                        };
                        let style = format!(
                            "display:block;width:100%;padding:10px 14px;border:none;\
                             border-bottom:1px solid var(--border);border-left:3px solid {};\
                             background:{};text-align:left;cursor:pointer;",
                            if is_selected { "var(--primary)" } else { "transparent" },
                            if is_selected { "var(--bg-selected)" } else { "transparent" },
                        );
                        html! {
                            <button key={rule.id.clone()} type="button" role="option"
                                    aria-selected={is_selected.to_string()} {onclick} {style}>
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
                        }
                    }) }
                }
            </div>
        </div>
    }
}
