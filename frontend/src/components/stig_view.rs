use crate::api::{api_get, api_send};
use crate::auth::use_current_user;
use crate::autosave::{Autosave, SaveStatus};
use crate::components::asset_modal::{asset_field, with_asset_field, ASSET_FIELDS};
use crate::components::poam_export_modal::{export_base_name, PoamExportModal};
use crate::components::rule_list::RuleList;
use crate::components::save_to_system_modal::SaveToSystemModal;
use crate::constants::{
    severity_badge_color, status_indicator_kind, SEVERITY_ORDER, STATUS_OPTIONS,
};
use crate::model::*;
use crate::ui::*;
use crate::util::{download_text, file_list_to_vec, spawn_local};
use crate::utils::export_ckl::export_ckl;
use gloo_timers::future::TimeoutFuture;
use std::collections::HashSet;
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
            let end = trimmed
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(trimmed.len());
            &trimmed[..end]
        } else {
            // `.` stops at a line terminator. If nothing follows the
            // whitespace, the regex backtracks and lets `.+` take trailing
            // whitespace instead.
            let line = |s: &'_ str| -> usize {
                s.find(['\n', '\r', '\u{2028}', '\u{2029}'])
                    .unwrap_or(s.len())
            };
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
    value
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "—".to_string())
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
    /// The tab's checklist set, once its first edit has created one.
    #[prop_or_default]
    pub set: Option<ChecklistSet>,
    /// Open tabs that belong to the same set.
    #[prop_or_default]
    pub set_tabs: Vec<StigTab>,
    /// `None` for viewers, who have no autosave.
    #[prop_or_default]
    pub autosave: Option<Autosave>,
    #[prop_or_default]
    pub on_rename_set: Callback<String>,
    /// A catalog STIG was added to the set on the server; open it as a tab.
    #[prop_or_default]
    pub on_add_stig: Callback<String>,
    #[prop_or_default]
    pub on_set_linked: Callback<Option<(String, String)>>,
}

#[derive(Clone, PartialEq, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct CatalogItem {
    id: String,
    title: String,
}

/// Checklist-set strip above the STIG: name (renamable), Add STIG, autosave
/// status, and the conflict prompt.
#[derive(Properties, PartialEq)]
struct SetBarProps {
    set: Option<ChecklistSet>,
    local_file: bool,
    autosave: Autosave,
    on_rename_set: Callback<String>,
    on_add_stig: Callback<String>,
    can_add: bool,
}

#[function_component]
fn SetBar(p: &SetBarProps) -> Html {
    let renaming = use_state(|| None::<String>);
    let adding = use_state(|| false);
    let catalog = use_state(Vec::<CatalogItem>::new);
    let picked = use_state(Vec::<AttrValue>::new);
    let error = use_state(|| None::<String>);
    let status = p.autosave.status();

    if p.local_file {
        return html! { <UiBox color="text-status-inactive" testid="local-file-note">{"Not saved to your account (local file)"}</UiBox> };
    }

    let name_part = match (&*renaming, &p.set) {
        (Some(text), Some(set)) => {
            let on_change = {
                let renaming = renaming.clone();
                Callback::from(move |v: String| renaming.set(Some(v)))
            };
            let save = {
                let (renaming, error, on_rename, id, text) = (
                    renaming.clone(),
                    error.clone(),
                    p.on_rename_set.clone(),
                    set.id.clone(),
                    text.clone(),
                );
                Callback::from(move |_: MouseEvent| {
                    let (renaming, error, on_rename, id, text) = (
                        renaming.clone(),
                        error.clone(),
                        on_rename.clone(),
                        id.clone(),
                        text.clone(),
                    );
                    spawn_local(async move {
                        let body = serde_json::json!({ "name": text });
                        match api_send(&format!("/api/checklist-sets/{id}"), "PATCH", Some(&body))
                            .await
                        {
                            Ok(()) => {
                                on_rename.emit(text.trim().to_string());
                                renaming.set(None);
                            }
                            Err(e) => error.set(Some(format!("Could not rename: {e}"))),
                        }
                    });
                })
            };
            let cancel = {
                let renaming = renaming.clone();
                Callback::from(move |_: MouseEvent| renaming.set(None))
            };
            html! {
                <SpaceBetween direction="horizontal" size="xs">
                    <Input value={text.clone()} {on_change} aria_label="Checklist name" testid="set-name-input" />
                    <Button onclick={save} testid="set-name-save">{"Save"}</Button>
                    <Button variant="link" onclick={cancel}>{"Cancel"}</Button>
                </SpaceBetween>
            }
        }
        (_, Some(set)) => {
            let start = {
                let (renaming, name) = (renaming.clone(), set.name.clone());
                Callback::from(move |_: MouseEvent| renaming.set(Some(name.clone())))
            };
            html! {
                <SpaceBetween direction="horizontal" size="xs">
                    <strong data-testid="set-name">{set.name.clone()}</strong>
                    <Button variant="inline-link" onclick={start} testid="set-rename">{"Rename"}</Button>
                </SpaceBetween>
            }
        }
        _ => {
            html! { <UiBox color="text-status-inactive">{"Your edits are saved to My checklists automatically."}</UiBox> }
        }
    };

    let toggle_add = {
        let (adding, catalog) = (adding.clone(), catalog.clone());
        Callback::from(move |_: MouseEvent| {
            adding.set(!*adding);
            if catalog.is_empty() {
                let catalog = catalog.clone();
                spawn_local(async move {
                    if let Ok(list) = api_get::<Vec<CatalogItem>>("/api/catalog").await {
                        catalog.set(list);
                    }
                });
            }
        })
    };
    let options: Vec<SelectOption> = catalog
        .iter()
        .map(|c| SelectOption::new(c.id.clone(), c.title.clone()))
        .collect();
    let on_pick = {
        let picked = picked.clone();
        Callback::from(move |v: Vec<SelectOption>| {
            picked.set(v.into_iter().map(|o| o.value).collect())
        })
    };
    let add = {
        let (picked, adding, error, set, on_add) = (
            picked.clone(),
            adding.clone(),
            error.clone(),
            p.set.clone(),
            p.on_add_stig.clone(),
        );
        Callback::from(move |_: MouseEvent| {
            let Some(set) = set.clone() else { return };
            let ids: Vec<String> = picked.iter().map(|s| s.to_string()).collect();
            let (picked, adding, error, on_add) = (
                picked.clone(),
                adding.clone(),
                error.clone(),
                on_add.clone(),
            );
            spawn_local(async move {
                for id in ids {
                    let body = serde_json::json!({ "stigId": id });
                    let path = format!("/api/checklist-sets/{}/stigs", set.id);
                    match api_send(&path, "POST", Some(&body)).await {
                        Ok(()) => on_add.emit(id),
                        Err(e) => {
                            error.set(Some(format!("Could not add {id}: {e}")));
                            return;
                        }
                    }
                }
                picked.set(Vec::new());
                adding.set(false);
            });
        })
    };

    let indicator = status.indicator().map(|(kind, text)| {
        let retry = {
            let a = p.autosave.clone();
            Callback::from(move |_: MouseEvent| a.flush_soon())
        };
        let retryable = matches!(status, SaveStatus::Error(_) | SaveStatus::Offline);
        html! {
            <span onclick={retryable.then_some(retry)} style={retryable.then_some("cursor:pointer;")}>
                <StatusIndicator kind={kind} testid="autosave-status">{text}</StatusIndicator>
            </span>
        }
    });

    let conflict = match (&status, &p.set) {
        (SaveStatus::Conflict, Some(set)) => {
            let (a1, a2, id1, id2, err1, err2) = (
                p.autosave.clone(),
                p.autosave.clone(),
                set.id.clone(),
                set.id.clone(),
                error.clone(),
                error.clone(),
            );
            let reload = Callback::from(move |_: MouseEvent| {
                let (a, id, err) = (a1.clone(), id1.clone(), err1.clone());
                spawn_local(async move {
                    if let Err(e) = a.reload_latest(&id).await {
                        err.set(Some(e));
                    }
                });
            });
            let keep = Callback::from(move |_: MouseEvent| {
                let (a, id, err) = (a2.clone(), id2.clone(), err2.clone());
                spawn_local(async move {
                    if let Err(e) = a.keep_my_edits(&id).await {
                        err.set(Some(e));
                    }
                });
            });
            html! {
                <Alert kind="warning" header={html! { {"Changed in another tab or device"} }} testid="set-conflict">
                    <SpaceBetween size="xs">
                        <div>{"This checklist was saved from somewhere else. Your edits are not saved yet."}</div>
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button onclick={reload} testid="set-conflict-reload">{"Reload latest"}</Button>
                            <Button variant="primary" onclick={keep} testid="set-conflict-keep">{"Keep my edits"}</Button>
                        </SpaceBetween>
                        <div>{"Reload latest discards your unsaved edits. Keep my edits takes the other changes for rules you have not touched and saves yours on top."}</div>
                    </SpaceBetween>
                </Alert>
            }
        }
        _ => html! {},
    };

    html! {
        <SpaceBetween size="xs">
            <SpaceBetween direction="horizontal" size="m">
                {name_part}
                if p.can_add && p.set.is_some() {
                    <Button onclick={toggle_add} testid="set-add-stig">{"Add STIG"}</Button>
                }
                {for indicator}
            </SpaceBetween>
            if *adding {
                <SpaceBetween direction="horizontal" size="xs">
                    <Multiselect options={options} selected={(*picked).clone()} on_change={on_pick}
                                 placeholder="Choose STIGs to add" filtering=true testid="set-add-stig-select" />
                    <Button variant="primary" onclick={add} disabled={picked.is_empty()} testid="set-add-stig-apply">{"Add"}</Button>
                </SpaceBetween>
            }
            if let Some(e) = &*error {
                <Alert kind="error" dismissible=true on_dismiss={{ let error = error.clone(); move |_| error.set(None) }}>{e.clone()}</Alert>
            }
            {conflict}
        </SpaceBetween>
    }
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
    let checked_ids: &[String] = if checked.0 == p.tab.id {
        &checked.1
    } else {
        &[]
    };
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
        (
            stig.clone(),
            (*search_term).clone(),
            (*severity_filter).clone(),
            (*status_filter).clone(),
        ),
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
                    [
                        &r.title,
                        &r.stig_id,
                        &r.id,
                        &r.description,
                        &r.check_text,
                        &r.fix_text,
                    ]
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
    let pct = if total > 0 {
        (evaluated as f64 / total as f64 * 100.0).round()
    } else {
        0.0
    };

    let handle_export_ckl = {
        let (stig, asset) = (stig.clone(), asset_info.clone());
        Callback::from(move |_: MouseEvent| {
            let xml = export_ckl(&stig, &asset.hostname, &asset.ip, &asset.mac, &asset.fqdn);
            download_text(
                &xml,
                "application/xml",
                &format!("{}.ckl", export_base_name(&stig.title)),
            );
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
            let input = e
                .target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok());
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
    let severity_options: Vec<SelectOption> =
        std::iter::once(SelectOption::new("", "All severities"))
            .chain(SEVERITY_ORDER.iter().map(|s| SelectOption::new(*s, *s)))
            .collect();
    let status_options: Vec<SelectOption> = std::iter::once(SelectOption::new("", "All statuses"))
        .chain(
            STATUS_OPTIONS
                .iter()
                .map(|o| SelectOption::new(o.value, o.label)),
        )
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
            let mut next: Vec<String> = current
                .iter()
                .filter(|id| !changed.contains(id.as_str()))
                .cloned()
                .collect();
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

    let on_focus_out = {
        let a = p.autosave.clone();
        Callback::from(move |_: FocusEvent| {
            if let Some(a) = &a {
                a.flush_soon();
            }
        })
    };
    html! {
        <div onfocusout={on_focus_out}>
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
                                onclick={{
                                    let (m, a) = (show_save_modal.clone(), p.autosave.clone());
                                    move |_| {
                                        let (m, a) = (m.clone(), a.clone());
                                        // Pending edits create/update the set first, so the
                                        // dialog sees the set the edits belong to.
                                        spawn_local(async move {
                                            if let Some(a) = &a {
                                                let _ = a.flush().await;
                                                TimeoutFuture::new(0).await;
                                            }
                                            m.set(true);
                                        });
                                    }
                                }}
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

            if let Some(a) = &p.autosave {
                <SetBar set={p.set.clone()} local_file={p.tab.catalog_id.is_none()} autosave={a.clone()}
                        on_rename_set={p.on_rename_set.clone()} on_add_stig={p.on_add_stig.clone()}
                        can_add={p.tab.catalog_id.is_some()} />
            }

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
                        set={p.set.clone()}
                        autosave={p.autosave.clone()}
                        set_tabs={p.set_tabs.clone()}
                        on_linked={p.on_set_linked.clone()}
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
        </div>
    }
}
