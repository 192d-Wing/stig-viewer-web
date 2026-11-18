use crate::components::badges::SeverityBadge;
use crate::components::cci_mapping_panel::CciMappingPanel;
use crate::constants::{FINDING_DETAILS_FIELDS, STATUS_OPTIONS};
use crate::model::*;
use crate::ui::*;
use yew::prelude::*;

/// (label, monospace, value) for each read-only content section.
fn content_sections(rule: &Rule) -> [(&'static str, bool, &str); 3] {
    [
        ("Description", false, &rule.description),
        ("Check Text", true, &rule.check_text),
        ("Fix Text", false, &rule.fix_text),
    ]
}

#[derive(Properties, PartialEq)]
pub struct RuleDetailProps {
    pub rule: Rule,
    pub on_update_rule: Callback<RuleUpdate>,
    pub on_close: Callback<()>,
}

#[function_component]
pub fn RuleDetail(p: &RuleDetailProps) -> Html {
    let rule = &p.rule;
    let panel_ref = use_node_ref();

    // Jump back to the top when a different rule is shown.
    {
        let panel_ref = panel_ref.clone();
        use_effect_with(rule.id.clone(), move |_| {
            if let Some(el) = panel_ref.cast::<web_sys::Element>() {
                el.set_scroll_top(0);
            }
        });
    }

    let on_status = p.on_update_rule.reform(|id: AttrValue| RuleUpdate {
        status: Some(id.to_string()),
        ..RuleUpdate::default()
    });
    let close = p.on_close.reform(|_: MouseEvent| ());

    html! {
        <div ref={panel_ref} style="flex:1;overflow-y:auto;display:flex;flex-direction:column;min-width:0;">
            // Header
            <div style="padding:16px 20px;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10;\
                        background:var(--bg);flex-shrink:0;">
                <Header
                    variant="h2"
                    actions={html! {
                        <Button variant="icon" icon_name="close" onclick={close} aria_label="Close detail panel" />
                    }}
                    description={html! {
                        <SpaceBetween direction="horizontal" size="xs">
                            <span>{format!("Rule ID: {}", rule.id)}</span>
                            if !rule.cci_ids.is_empty() {
                                <span>{format!("CCI: {}", rule.cci_ids.join(", "))}</span>
                            }
                        </SpaceBetween>
                    }}
                >
                    <SpaceBetween direction="horizontal" size="xs" align_items="center">
                        <span>{rule.stig_id.clone()}</span>
                        <SeverityBadge severity={rule.severity.clone()} />
                    </SpaceBetween>
                </Header>
                <UiBox margin_top="xs" font_size="body-m" font_weight="bold" color="text-body-secondary">
                    {rule.title.clone()}
                </UiBox>
                if !rule.cci_ids.is_empty() {
                    <CciMappingPanel cci_ids={rule.cci_ids.clone()} />
                }
            </div>

            // Status selector
            <div style="padding:16px 20px;border-bottom:1px solid var(--border);flex-shrink:0;">
                <UiBox margin_bottom="xs" font_size="body-s" font_weight="bold" color="text-label">
                    {"Compliance Status"}
                </UiBox>
                <SegmentedControl
                    selected_id={rule.status.clone()}
                    on_change={on_status}
                    options={STATUS_OPTIONS.iter().map(|o| SegmentOption::new(o.value, o.label)).collect::<Vec<_>>()}
                />
            </div>

            // Content sections
            <div style="padding:0 20px 24px;flex:1;">
                <SpaceBetween size="m">
                    { for content_sections(rule).into_iter().filter(|(_, _, text)| !text.is_empty()).map(|(label, mono, text)| {
                        let style = format!(
                            "font-size:{}px;line-height:1.65;color:var(--text-secondary);background:var(--bg-input);\
                             border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;\
                             white-space:pre-wrap;word-break:break-word;font-family:{};margin:0;",
                            if mono { 12 } else { 13 },
                            if mono { "var(--mono)" } else { "inherit" },
                        );
                        html! {
                            <ExpandableSection key={label} header_text={label} default_expanded=true>
                                <pre {style}>{text.to_string()}</pre>
                            </ExpandableSection>
                        }
                    }) }

                    // Finding details & comments
                    { for FINDING_DETAILS_FIELDS.iter().map(|&(key, label)| {
                        let value = match key {
                            "findingDetails" => rule.finding_details.clone(),
                            _ => rule.comments.clone(),
                        };
                        let on_change = p.on_update_rule.reform(move |text: String| match key {
                            "findingDetails" => RuleUpdate { finding_details: Some(text), ..RuleUpdate::default() },
                            _ => RuleUpdate { comments: Some(text), ..RuleUpdate::default() },
                        });
                        html! {
                            <FormField {key} {label}>
                                <Textarea
                                    {value}
                                    {on_change}
                                    placeholder={format!("Enter {}…", label.to_lowercase())}
                                    rows={4}
                                />
                            </FormField>
                        }
                    }) }
                </SpaceBetween>
            </div>
        </div>
    }
}
