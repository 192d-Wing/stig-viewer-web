use crate::components::asset_modal::{asset_field, with_asset_field, ASSET_FIELDS};
use crate::auth::use_current_user;
use std::collections::HashSet;
use crate::components::save_to_system_modal::SaveToSystemModal;
use crate::components::poam_export_modal::{export_base_name, PoamExportModal};
use crate::components::rule_list::RuleList;
use crate::constants::{severity_badge_color, status_indicator_kind, SEVERITY_ORDER, STATUS_OPTIONS};
use crate::model::*;
use crate::ui::*;
use crate::util::{download_text, file_list_to_vec};
use crate::utils::export_ckl::export_ckl;
use std::rc::Rc;
use wasm_bindgen::JsCast;
use yew::prelude::*;

/// First capture of `/<marker>\s*(\d+)/i` (when `digits_only`) or
/// `/<marker>\s*(.+)/i` in `text`. `marker` must be lowercase ASCII.
fn capture_after(text: &str, marker: &str, digits_only: bool) -> Option<String> {
    // ASCII lowercasing keeps byte offsets aligned with `text`.
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find(marker) {
        let start = from + pos + marker.len();
        let rest = &text[start..];
        let trimmed = rest.trim_start();
        let capture: &str = if digits_only {
            let end = trimmed.find(|c: char| !c.is_ascii_digit()).unwrap_or(trimmed.len());
            &trimmed[..end]
        } else {
            // `.` stops at a line terminator. If nothing follows the
            // whitespace, the regex backtracks and lets `.+` take trailing
            // whitespace instead.
            let line = |s: &'_ str| -> usize { s.find(['\n', '\r', '\u{2028}', '\u{2029}']).unwrap_or(s.len()) };
            let mut candidate = &trimmed[..line(trimmed)];
            if candidate.is_empty() {
                let ws_len = rest.len() - trimmed.len();
                for (i, _) in rest[..ws_len].char_indices().rev() {
                    let tail = &rest[i..];
                    let end = line(tail);
                    if end > 0 {
                        candidate = &tail[..end];
                        break;
                    }
                }
            }
            candidate
        };
        if !capture.is_empty() {
            return Some(capture.to_string());
        }
        from = start;
    }
    None
}

fn or_dash(value: Option<String>) -> String {
    value.filter(|v| !v.is_empty()).unwrap_or_else(|| "—".to_string())
}

fn key_value(label: &'static str, value: Html) -> Html {
    html! {
        <div>
            <UiBox variant="awsui-key-label">{label}</UiBox>
            {value}
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct StigViewProps {
    pub tab: StigTab,
    /// (rule id, changes)
    pub on_update_rule: Callback<(String, RuleUpdate)>,
    pub on_set_asset_info: Callback<AssetInfo>,
    pub on_set_selected_rule: Callback<Option<String>>,
    /// New status for every rule in the tab.
    pub on_set_all_status: Callback<String>,
    /// (rule ids, new status) for the rules ticked in the list.
    pub on_set_status_for: Callback<(Vec<String>, String)>,
    pub on_add_files: Callback<Vec<web_sys::File>>,
}

#[function_component]
pub fn StigView(p: &StigViewProps) -> Html {
    let stig = &p.tab.stig;
    let asset_info = &p.tab.asset_info;

    let search_term = use_state(String::new);
    // "" = no filter
    let severity_filter = use_state(String::new);
    let status_filter = use_state(String::new);
    let show_poam_modal = use_state(|| false);
    let show_save_modal = use_state(|| false);
    let can_save = use_current_user().is_some_and(|u| u.role != "viewer");
    // Rule ids ticked for a multi-rule status change, tagged with the tab
    // they were ticked in; ticks from another open STIG read as empty.
    let checked = use_state(|| (String::new(), Vec::<String>::new()));
    let checked_ids: &[String] = if checked.0 == p.tab.id { &checked.1 } else { &[] };
    // Switching tabs discards the old tab's ticks. The read above is already
    // empty on the switching render; this only drops the stash so the ticks
    // do not come back when the viewer returns. No state is set on mount.
    {
        let checked = checked.clone();
        use_effect_with(p.tab.id.clone(), move |tab_id| {
            if checked.0 != *tab_id && !checked.1.is_empty() {
                checked.set((tab_id.clone(), Vec::new()));
            }
        });
    }
    let file_input_ref = use_node_ref();

    let filtered_rules = use_memo(
        (stig.clone(), (*search_term).clone(), (*severity_filter).clone(), (*status_filter).clone()),
        |(stig, search, severity, status)| {
            let term = search.to_lowercase();
            stig.rules
                .iter()
                .filter(|r| {
                    if !severity.is_empty() && &r.severity != severity {
                        return false;
                    }
                    if !status.is_empty() && &r.status != status {
                        return false;
                    }
                    if term.is_empty() {
                        return true;
                    }
                    [&r.title, &r.stig_id, &r.id, &r.description, &r.check_text, &r.fix_text]
                        .iter()
                        .any(|field| field.to_lowercase().contains(&term))
                })
                .cloned()
                .collect::<Vec<Rule>>()
        },
    );

    // Summary statistics
    let total = stig.rules.len();
    let count_severity = |sev: &str| stig.rules.iter().filter(|r| r.severity == sev).count();
    let count_status = |status: &str| stig.rules.iter().filter(|r| r.status == status).count();
    let evaluated = total - count_status("not_reviewed");
    let pct = if total > 0 { (evaluated as f64 / total as f64 * 100.0).round() } else { 0.0 };

    let handle_export_ckl = {
        let (stig, asset) = (stig.clone(), asset_info.clone());
        Callback::from(move |_: MouseEvent| {
            let xml = export_ckl(&stig, &asset.hostname, &asset.ip, &asset.mac, &asset.fqdn);
            download_text(&xml, "application/xml", &format!("{}.ckl", export_base_name(&stig.title)));
        })
    };

    let description = [
        (!stig.version.is_empty()).then(|| format!("v{}", stig.version)),
        (!stig.release_info.is_empty()).then(|| stig.release_info.clone()),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" · ");

    let open_file = {
        let file_input_ref = file_input_ref.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(input) = file_input_ref.cast::<web_sys::HtmlElement>() {
                input.click();
            }
        })
    };
    let on_files_picked = {
        let on_add_files = p.on_add_files.clone();
        Callback::from(move |e: Event| {
            let input = e.target().and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok());
            let files = file_list_to_vec(input.and_then(|i| i.files()));
            if !files.is_empty() {
                on_add_files.emit(files);
            }
        })
    };
    let set_poam_modal = |open: bool| {
        let show_poam_modal = show_poam_modal.clone();
        move || show_poam_modal.set(open)
    };
    let (open_poam, close_poam) = (set_poam_modal(true), set_poam_modal(false));

    // ── Rules tab ───────────────────────────────────────────────────────────
    let severity_options: Vec<SelectOption> = std::iter::once(SelectOption::new("", "All severities"))
        .chain(SEVERITY_ORDER.iter().map(|s| SelectOption::new(*s, *s)))
        .collect();
    let status_options: Vec<SelectOption> = std::iter::once(SelectOption::new("", "All statuses"))
        .chain(STATUS_OPTIONS.iter().map(|o| SelectOption::new(o.value, o.label)))
        .collect();
    let set_filter = |state: &UseStateHandle<String>| {
        let state = state.clone();
        Callback::from(move |o: SelectOption| state.set(o.value.to_string()))
    };
    let on_search_change = {
        let search_term = search_term.clone();
        Callback::from(move |text: String| search_term.set(text))
    };

    // Only ticked rules that pass the current filters are acted on, so a
    // status change never touches rules the user cannot see.
    let filtered_ids: Vec<&str> = filtered_rules.iter().map(|r| r.id.as_str()).collect();
    let checked_visible: Vec<String> = visible_selection(&filtered_ids, checked_ids);
    let on_check = {
        let (checked, tab_id) = (checked.clone(), p.tab.id.clone());
        Callback::from(move |(ids, on): (Vec<String>, bool)| {
            let changed: HashSet<&str> = ids.iter().map(String::as_str).collect();
            let current: &[String] = if checked.0 == tab_id { &checked.1 } else { &[] };
            let mut next: Vec<String> = current.iter().filter(|id| !changed.contains(id.as_str())).cloned().collect();
            if on {
                next.extend(ids);
            }
            checked.set((tab_id.clone(), next));
        })
    };
    let on_set_checked_status = {
        let (ids, on_set_status_for) = (checked_visible.clone(), p.on_set_status_for.clone());
        Callback::from(move |status: String| on_set_status_for.emit((ids.clone(), status)))
    };

    let rules_tab = html! {
        <SpaceBetween size="m">
            <SpaceBetween direction="horizontal" size="m" align_items="end">
                <FormField label="Severity">
                    <Select
                        selected={(*severity_filter).clone()}
                        on_change={set_filter(&severity_filter)}
                        options={severity_options}
                    />
                </FormField>
                <FormField label="Status">
                    <Select
                        selected={(*status_filter).clone()}
                        on_change={set_filter(&status_filter)}
                        options={status_options}
                    />
                </FormField>
            </SpaceBetween>
            <div style="height:calc(100vh - 420px);min-height:300px;">
                <RuleList
                    rules={filtered_rules}
                    all_rules_count={total}
                    selected_rule_id={p.tab.selected_rule_id.clone()}
                    search_term={(*search_term).clone()}
                    {on_search_change}
                    on_select_rule={p.on_set_selected_rule.reform(|rule: Rule| Some(rule.id))}
                    on_set_all_status={p.on_set_all_status.clone()}
                    checked_ids={checked_visible}
                    {on_check}
                    {on_set_checked_status}
                />
            </div>
        </SpaceBetween>
    };

    // ── Details tab ─────────────────────────────────────────────────────────
    let text = |s: String| html! { <div>{s}</div> };
    let details_tab = html! {
        <Container header={html! { <Header variant="h2">{"STIG Information"}</Header> }}>
            <ColumnLayout columns={2} variant="text-grid">
                {key_value("Title", text(stig.title.clone()))}
                {key_value("Version", text(or_dash(Some(stig.version.clone()))))}
                {key_value("Release", text(or_dash(capture_after(&stig.release_info, "release:", true))))}
                {key_value("Benchmark Date", text(or_dash(capture_after(&stig.release_info, "benchmark date:", false))))}
                {key_value("Total Rules", text(total.to_string()))}
                {key_value("DISA STIG Support", html! {
                    <Link href="mailto:disa.stig_spt@mail.mil" external=true>
                        {"disa.stig_spt@mail.mil"}
                    </Link>
                })}
            </ColumnLayout>
            if !stig.description.is_empty() {
                <UiBox margin_top="l">
                    <ExpandableSection header_text="Description" default_expanded=true>
                        <UiBox variant="p" color="text-body-secondary">
                            {stig.description.clone()}
                        </UiBox>
                    </ExpandableSection>
                </UiBox>
            }
        </Container>
    };

    // ── Asset tab ───────────────────────────────────────────────────────────
    let asset_tab = html! {
        <Container header={html! { <Header variant="h2">{"Asset Information"}</Header> }}>
            <ColumnLayout columns={2}>
                { for ASSET_FIELDS.iter().map(|&(key, label)| {
                    let on_change = {
                        let (info, on_set_asset_info) = (asset_info.clone(), p.on_set_asset_info.clone());
                        Callback::from(move |value: String| on_set_asset_info.emit(with_asset_field(&info, key, value)))
                    };
                    html! {
                        <FormField {key} {label}>
                            <Input value={asset_field(asset_info, key).to_string()} {on_change} />
                        </FormField>
                    }
                }) }
            </ColumnLayout>
        </Container>
    };

    html! {
        <SpaceBetween size="m">
            // Page header
            <Header
                variant="h2"
                description={if description.is_empty() { Html::default() } else { html! { {description} } }}
                actions={html! {
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button onclick={open_file}>{"Open File"}</Button>
                        <input
                            ref={file_input_ref}
                            type="file"
                            accept=".xml,.ckl"
                            multiple=true
                            style="display:none;"
                            aria-hidden="true"
                            tabindex="-1"
                            onchange={on_files_picked}
                        />
                        if can_save {
                            <Button
                                onclick={{ let m = show_save_modal.clone(); move |_| m.set(true) }}
                                disabled={p.tab.catalog_id.is_none()}
                                title={p.tab.catalog_id.is_none().then_some("Only STIGs opened from the library can be saved to a system.")}
                                testid="save-to-system"
                            >{"Save to system"}</Button>
                        }
                        <Button onclick={move |_| open_poam()}>{"Export POAM"}</Button>
                        <Button variant="primary" onclick={handle_export_ckl}>{"Export .ckl"}</Button>
                    </SpaceBetween>
                }}
            >
                {stig.title.clone()}
            </Header>

            // Summary container
            <Container>
                <ColumnLayout columns={4} variant="text-grid">
                    <div>
                        <UiBox variant="awsui-key-label">{"Total Rules"}</UiBox>
                        <UiBox variant="awsui-value-large">{total}</UiBox>
                    </div>
                    <div>
                        <UiBox variant="awsui-key-label">{"Evaluated"}</UiBox>
                        <ProgressBar
                            value={pct}
                            result_text={format!("{evaluated} of {total}")}
                            status={if pct == 100.0 { "success" } else { "in-progress" }}
                        />
                    </div>
                    <div>
                        <UiBox variant="awsui-key-label">{"Severity"}</UiBox>
                        <SpaceBetween direction="horizontal" size="xs">
                            { for SEVERITY_ORDER.iter().map(|sev| html! {
                                <Badge key={*sev} color={severity_badge_color(sev)}>
                                    {format!("{sev}: {}", count_severity(sev))}
                                </Badge>
                            }) }
                        </SpaceBetween>
                    </div>
                    <div>
                        <UiBox variant="awsui-key-label">{"Status"}</UiBox>
                        <SpaceBetween size="xxs">
                            { for STATUS_OPTIONS.iter().map(|opt| html! {
                                <StatusIndicator key={opt.value} kind={status_indicator_kind(opt.value)}>
                                    {format!("{}: {}", opt.label, count_status(opt.value))}
                                </StatusIndicator>
                            }) }
                        </SpaceBetween>
                    </div>
                </ColumnLayout>
            </Container>

            // Tabs
            <Tabs tabs={vec![
                TabItem::new("rules", "Rules", rules_tab),
                TabItem::new("details", "Details", details_tab),
                TabItem::new("asset", "Asset", asset_tab),
            ]} />

            if *show_save_modal {
                if let Some(catalog_id) = p.tab.catalog_id.clone() {
                    <SaveToSystemModal
                        show=true
                        on_close={{ let m = show_save_modal.clone(); move |_| m.set(false) }}
                        stig={Rc::clone(stig)}
                        {catalog_id}
                    />
                }
            }
            <PoamExportModal
                show={*show_poam_modal}
                on_close={move |_| close_poam()}
                stig={Rc::clone(stig)}
                asset_info={asset_info.clone()}
            />
        </SpaceBetween>
    }
}
