use crate::components::badges::SeverityBadge;
use crate::model::*;
use crate::ui::*;
use crate::utils::diff_stig::{diff_stigs, ChangedEntry};
use yew::prelude::*;

fn field_label(field: &str) -> &str {
    match field {
        "title" => "Title",
        "severity" => "Severity",
        "description" => "Description",
        "checkText" => "Check Text",
        "fixText" => "Fix Text",
        other => other,
    }
}

const STIG_ID_STYLE: &str =
    "font-family:'JetBrains Mono', monospace;font-size:12px;font-weight:700;color:#539fe5;";
const DIFF_TEXT_STYLE: &str =
    "font-size:12px;color:#d1d5db;white-space:pre-wrap;word-break:break-word;margin:0;line-height:1.5;";

/// One side of a changed field; `color` is the accent for that side.
fn diff_side(side: &'static str, color: &str, text: &str) -> Html {
    html! {
        <div style={format!("padding:6px 10px;border-radius:4px;border-left:3px solid {color};background:{color}14;")}>
            <UiBox font_size="body-s" color="text-status-inactive">{side}</UiBox>
            <pre style={DIFF_TEXT_STYLE}>{text.to_string()}</pre>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct ChangedEntryViewProps {
    entry: ChangedEntry,
}

#[function_component]
fn ChangedEntryView(p: &ChangedEntryViewProps) -> Html {
    let entry = &p.entry;
    html! {
        <ExpandableSection
            header_text={html! {
                <SpaceBetween direction="horizontal" size="xs" align_items="center">
                    <span style={STIG_ID_STYLE}>{entry.stig_id.clone()}</span>
                    <span style="font-size:11px;color:#f59e0b;">{entry.fields.join(", ")}</span>
                </SpaceBetween>
            }}
        >
            <SpaceBetween size="m">
                { for entry.fields.iter().enumerate().map(|(i, field)| html! {
                    <div key={*field}>
                        <UiBox font_size="body-s" font_weight="bold" color="text-label" margin_bottom="xxs">
                            {field_label(field).to_string()}
                        </UiBox>
                        <ColumnLayout columns={2}>
                            {diff_side("A", "#ff4444", &entry.a[i])}
                            {diff_side("B", "#22c55e", &entry.b[i])}
                        </ColumnLayout>
                    </div>
                }) }
            </SpaceBetween>
        </ExpandableSection>
    }
}

/// Added / removed rule rows; `color` is the accent for the section.
fn rule_rows(rules: &[Rule], color: &str) -> Html {
    html! {
        <SpaceBetween size="xs">
            { for rules.iter().map(|rule| html! {
                <div key={rule.stig_id.clone()}
                     style={format!("display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:6px;\
                                     border-left:3px solid {color};background:{color}14;")}>
                    <span style={format!("{STIG_ID_STYLE}min-width:65px;")}>{rule.stig_id.clone()}</span>
                    <SeverityBadge severity={rule.severity.clone()} />
                    <span style="font-size:13px;color:#d1d5db;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                        {rule.title.clone()}
                    </span>
                </div>
            }) }
        </SpaceBetween>
    }
}

#[derive(Properties, PartialEq)]
pub struct DiffViewProps {
    pub tabs: Vec<StigTab>,
    /// (tab id A, tab id B)
    pub diff_pair: (Option<String>, Option<String>),
    pub on_set_diff_pair: Callback<(Option<String>, Option<String>)>,
    pub on_exit_diff: Callback<()>,
}

#[function_component]
pub fn DiffView(p: &DiffViewProps) -> Html {
    let (tab_a_id, tab_b_id) = &p.diff_pair;
    let find_stig = |id: &Option<String>| {
        id.as_ref()
            .and_then(|id| p.tabs.iter().find(|t| &t.id == id))
            .map(|t| t.stig.clone())
    };

    let result = use_memo((find_stig(tab_a_id), find_stig(tab_b_id)), |pair| match pair {
        (Some(a), Some(b)) => Some(diff_stigs(a, b)),
        _ => None,
    });

    let handle_set_a = {
        let (b, cb) = (tab_b_id.clone(), p.on_set_diff_pair.clone());
        Callback::from(move |o: SelectOption| cb.emit((Some(o.value.to_string()), b.clone())))
    };
    let handle_set_b = {
        let (a, cb) = (tab_a_id.clone(), p.on_set_diff_pair.clone());
        Callback::from(move |o: SelectOption| cb.emit((a.clone(), Some(o.value.to_string()))))
    };

    let tab_options: Vec<SelectOption> =
        p.tabs.iter().map(|t| SelectOption::new(t.id.clone(), t.stig.title.clone())).collect();
    // Only ids of open tabs count as a selection.
    let selected = |id: &Option<String>| {
        id.as_ref().filter(|id| p.tabs.iter().any(|t| &t.id == *id)).map(|id| AttrValue::from(id.clone()))
    };
    let exit_diff = p.on_exit_diff.reform(|_: MouseEvent| ());

    html! {
        <div style="display:flex;flex-direction:column;flex:1;overflow:hidden;min-height:0;">
            // Selector row
            <div style="padding:16px 20px;border-bottom:1px solid #354150;flex-shrink:0;">
                <Header variant="h2" actions={html! { <Button onclick={exit_diff}>{"Exit Diff"}</Button> }}>
                    {"STIG Version Diff"}
                </Header>
                <div style="margin-top:12px;display:flex;gap:16px;align-items:flex-end;flex-wrap:wrap;">
                    <FormField label="Baseline (A)">
                        <Select
                            selected={selected(tab_a_id)}
                            on_change={handle_set_a}
                            options={tab_options.clone()}
                            placeholder="Select baseline"
                        />
                    </FormField>
                    <UiBox padding_bottom="xs" color="text-status-inactive" font_weight="bold">{"vs"}</UiBox>
                    <FormField label="Compare (B)">
                        <Select
                            selected={selected(tab_b_id)}
                            on_change={handle_set_b}
                            options={tab_options}
                            placeholder="Select comparison"
                        />
                    </FormField>
                </div>
            </div>

            // Results
            if let Some(result) = result.as_ref() {
                <div style="flex:1;overflow-y:auto;padding:16px 20px;">
                    <SpaceBetween size="xl">
                        // Added
                        <ExpandableSection variant="container" default_expanded=true
                            header_text={format!("Added in B ({})", result.added.len())}>
                            if result.added.is_empty() {
                                <UiBox color="text-status-inactive">{"No rules added"}</UiBox>
                            } else {
                                {rule_rows(&result.added, "#22c55e")}
                            }
                        </ExpandableSection>

                        // Removed
                        <ExpandableSection variant="container" default_expanded=true
                            header_text={format!("Removed from A ({})", result.removed.len())}>
                            if result.removed.is_empty() {
                                <UiBox color="text-status-inactive">{"No rules removed"}</UiBox>
                            } else {
                                {rule_rows(&result.removed, "#ff4444")}
                            }
                        </ExpandableSection>

                        // Changed
                        <ExpandableSection variant="container" default_expanded=true
                            header_text={format!("Changed ({})", result.changed.len())}>
                            if result.changed.is_empty() {
                                <UiBox color="text-status-inactive">{"No rules changed"}</UiBox>
                            } else {
                                <SpaceBetween size="s">
                                    { for result.changed.iter().map(|entry| html! {
                                        <ChangedEntryView key={entry.stig_id.clone()} entry={entry.clone()} />
                                    }) }
                                </SpaceBetween>
                            }
                        </ExpandableSection>
                    </SpaceBetween>
                </div>
            } else {
                <UiBox text_align="center" padding_vertical="xxl" color="text-status-inactive" font_size="heading-s">
                    {"Select a Baseline and Compare STIG above to begin."}
                </UiBox>
            }
        </div>
    }
}
