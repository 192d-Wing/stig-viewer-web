//! Markup and small callbacks for the application shell, as plain functions
//! over [`Shell`] so they render in `App`'s own pass.

use std::collections::HashSet;

use wasm_bindgen::JsCast;
use yew::prelude::*;

use super::notifications::{bell_text, Notifications};
use super::{AccountMenu, NavButton, Shell, TabsAction, TabsState, LOGO_SVG};
use crate::api::{api_fetch, api_get};
use crate::auth::User;
use crate::autosave::Autosave;
use crate::components::admin_console::AdminConsole;
use crate::components::asset_groups_page::AssetGroupsPage;
use crate::components::assets_library::AssetsLibrary;
use crate::components::dashboard::Dashboard;
use crate::components::diff_view::DiffView;
use crate::components::drop_zone::DropZone;
use crate::components::my_checklists::{MyChecklists, OpenedSet};
use crate::components::my_findings::MyFindings;
use crate::components::rule_detail::RuleDetail;
use crate::components::stig_library::StigLibrary;
use crate::components::stig_view::StigView;
use crate::components::stig_writer::StigWriter;
use crate::data::sample_stig::generate_sample_stig;
use crate::model::{ChecklistSet, Rule, RuleUpdate, Stig, StigTab};
use crate::ui::*;
use crate::util::{console_error, download_text, file_list_to_vec, spawn_local, window};
use crate::utils::export_ckl::export_ckl;

/// The URL for a top-level view: the viewer is the bare path.
pub(super) fn view_url(path: &str, mode: &str) -> String {
    if mode == "viewer" {
        path.to_string()
    } else {
        format!("{path}?view={mode}")
    }
}

// ── Top navigation ──────────────────────────────────────────────────────────

fn account_name(u: &User) -> String {
    if u.display_name.is_empty() {
        "Account".to_string()
    } else {
        u.display_name.clone()
    }
}

fn sign_out_callback(autosave: &Autosave) -> Callback<()> {
    let autosave = autosave.clone();
    Callback::from(move |_: ()| {
        let autosave = autosave.clone();
        spawn_local(async move {
            // Save pending edits first; if that fails the reload below
            // still asks before discarding them.
            let _ = autosave.flush().await;
            let _ = api_fetch("POST", "/auth/logout").await;
            let _ = window().location().reload();
        });
    })
}

pub(super) fn file_input_handler(on_add_files: Callback<Vec<web_sys::File>>) -> Callback<Event> {
    Callback::from(move |e: Event| {
        if let Some(input) = e
            .target()
            .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        {
            let files = file_list_to_vec(input.files());
            if !files.is_empty() {
                on_add_files.emit(files);
            }
        }
    })
}

/// My checklists / Open File / Diff buttons.
fn viewer_utilities(sh: &Shell, file_input: &NodeRef) -> Html {
    let tabs = &sh.state.tabs;
    let is_library_mode = sh.is_library_mode();
    let has_tabs = sh.has_tabs();
    let is_diff_mode = sh.is_diff_mode();
    let handle_diff_toggle = {
        let dispatch = sh.dispatch();
        let first = tabs.first().map(|t| t.id.clone());
        let second = tabs.get(1).map(|t| t.id.clone());
        Callback::from(move |_: MouseEvent| {
            dispatch.dispatch(TabsAction::SetDiffPair(if is_diff_mode {
                None
            } else {
                Some((first.clone(), second.clone()))
            }));
        })
    };
    let open_file = {
        let file_input = file_input.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(el) = file_input.cast::<web_sys::HtmlElement>() {
                el.click();
            }
        })
    };
    html! {
        <>
            if is_library_mode && sh.autosave_enabled {
                <NavButton text="My checklists" onclick={{ let m = sh.show_my_checklists.clone(); Callback::from(move |_| m.set(true)) }} />
            }
            if is_library_mode && has_tabs {
                <NavButton text="Open File" icon_name="upload" onclick={open_file} />
                if tabs.len() >= 2 {
                    <NavButton text={if is_diff_mode { "Exit Diff" } else { "Diff" }} active={is_diff_mode} onclick={handle_diff_toggle} />
                }
            }
        </>
    }
}

pub(super) fn top_nav(
    sh: &Shell,
    user: Option<&User>,
    n: &Notifications,
    file_input: &NodeRef,
) -> Html {
    let nav_btn = |text: &'static str, target: &'static str| {
        let navigate_to = sh.navigate_to.clone();
        html! { <NavButton {text} active={sh.mode == target} onclick={Callback::from(move |_| navigate_to.emit(target))} /> }
    };
    let is_admin_user = user.map(|u| u.role == "admin").unwrap_or(false);
    let is_viewer_user = user.map(|u| u.role == "viewer").unwrap_or(false);
    html! {
        <div id="h">
            <header class="ui-topnav">
                <a class="ui-topnav-identity" href="#">
                    <img src={format!("data:image/svg+xml,{}", crate::util::encode_uri_component(LOGO_SVG))} alt="STIG Tools" />
                    <span class="ui-topnav-title">{"STIG Tools"}</span>
                </a>
                <nav class="ui-topnav-primary" aria-label="Primary">
                    {nav_btn("Viewer", "viewer")}
                    {nav_btn("Writer", "writer")}
                    {nav_btn("Systems", "systems")}
                    {nav_btn("Groups", "groups")}
                    {nav_btn("Dashboard", "dashboard")}
                    {nav_btn("My findings", "myfindings")}
                    if is_admin_user { {nav_btn("Admin", "admin")} }
                </nav>
                <div class="ui-topnav-utilities">
                    {viewer_utilities(sh, file_input)}
                    if is_viewer_user {
                        <span data-testid="viewer-badge" class="ui-topnav-badge"><Badge color="grey">{"Read-only"}</Badge></span>
                    }
                    if let Some(user) = user {
                        <NavButton text={bell_text(n.unread_count())} icon_name="notification" aria_label="Notifications" onclick={n.on_open()} />
                        <AccountMenu name={account_name(user)}
                                     on_sign_out={sign_out_callback(&sh.autosave)} />
                    }
                </div>
            </header>
        </div>
    }
}

// ── Side navigation ─────────────────────────────────────────────────────────

/// Set-backed tabs (or tabs with edits not yet saved) are flushed to the
/// server and closed without the prompt.
fn closes_without_prompt(
    autosave_enabled: bool,
    tab: &StigTab,
    dirty: impl FnOnce() -> bool,
) -> bool {
    autosave_enabled && tab.catalog_id.is_some() && (tab.set_id.is_some() || dirty())
}

fn tab_label(set_name: Option<&str>, title: &str) -> String {
    match set_name {
        Some(n) => format!("{n} · {title}"),
        None => title.to_string(),
    }
}

fn close_tab_callback(sh: &Shell, tab: &StigTab) -> Callback<MouseEvent> {
    let (closing_tab_id, id) = (sh.closing_tab_id.clone(), tab.id.clone());
    let (autosave, dispatch) = (sh.autosave.clone(), sh.dispatch());
    let autosaved =
        closes_without_prompt(sh.autosave_enabled, tab, || autosave.tab_is_dirty(&tab.id));
    Callback::from(move |e: MouseEvent| {
        e.prevent_default();
        e.stop_propagation();
        if !autosaved {
            closing_tab_id.set(Some(id.clone()));
            return;
        }
        let (closing_tab_id, id, autosave, dispatch) = (
            closing_tab_id.clone(),
            id.clone(),
            autosave.clone(),
            dispatch.clone(),
        );
        spawn_local(async move {
            match autosave.flush().await {
                Ok(()) => dispatch.dispatch(TabsAction::Remove(id)),
                // Could not save: keep the tab and ask.
                Err(_) => closing_tab_id.set(Some(id)),
            }
        });
    })
}

fn side_nav_item(sh: &Shell, tab: &StigTab, is_active: bool) -> Html {
    let follow = {
        let (dispatch, show_library, id) = (sh.dispatch(), sh.show_library.clone(), tab.id.clone());
        Callback::from(move |e: MouseEvent| {
            e.prevent_default();
            show_library.set(false);
            dispatch.dispatch(TabsAction::SetActive(id.clone()));
        })
    };
    let close = close_tab_callback(sh, tab);
    let set_name = tab
        .set_id
        .as_ref()
        .and_then(|sid| sh.state.sets.iter().find(|s| &s.id == sid))
        .map(|s| s.name.clone());
    let label = tab_label(set_name.as_deref(), &tab.stig.title);
    html! {
        <li key={tab.id.clone()} class="ui-sidenav-item">
            <a href={format!("#{}", tab.id)} class={classes!("ui-sidenav-link", is_active.then_some("ui-sidenav-active"))}
               aria-current={is_active.then_some("page")} onclick={follow}>
                {label}
            </a>
            <Button variant="icon" icon_name="close" aria_label={format!("Close {}", tab.stig.title)} onclick={close} />
        </li>
    }
}

pub(super) fn side_nav(sh: &Shell, navigation_open: bool) -> Html {
    let active_href = if *sh.show_library {
        None
    } else {
        sh.state.active_tab_id.clone()
    };
    html! {
        if navigation_open {
            <nav class="ui-app-nav" aria-label="Open STIGs">
                <div class="ui-sidenav-header">
                    <a href="#" class="ui-sidenav-title" onclick={|e: MouseEvent| e.prevent_default()}>{"Open STIGs"}</a>
                    <button type="button" class="ui-btn ui-btn-icon ui-nav-toggle"
                            onclick={{ let nav_open = sh.nav_open.clone(); move |_| nav_open.set(false) }}>
                        {icon("angle-left")}
                    </button>
                </div>
                <ul class="ui-sidenav-list">
                    <li>
                        <a href="#library" class={classes!("ui-sidenav-link", (*sh.show_library).then_some("ui-sidenav-active"))}
                           aria-current={(*sh.show_library).then_some("page")}
                           onclick={{ let show_library = sh.show_library.clone(); move |e: MouseEvent| { e.prevent_default(); show_library.set(true); } }}>
                            {icon("add-plus")}{"Browse Library"}
                        </a>
                    </li>
                    <li class="ui-sidenav-divider" role="separator" />
                    { for sh.state.tabs.iter().map(|tab| {
                        let is_active = Some(&tab.id) == active_href.as_ref();
                        side_nav_item(sh, tab, is_active)
                    }) }
                </ul>
            </nav>
        } else {
            <div class="ui-app-nav-collapsed">
                <button type="button" class="ui-btn ui-btn-icon ui-nav-toggle"
                        onclick={{ let nav_open = sh.nav_open.clone(); move |_| nav_open.set(true) }}>
                    {icon("menu")}
                </button>
            </div>
        }
    }
}

// ── Split panel ─────────────────────────────────────────────────────────────

pub(super) fn split_panel(sh: &Shell, rule: &Rule, tab_id: &str) -> Html {
    let (dispatch, autosave) = (sh.dispatch(), &sh.autosave);
    let tab_id = tab_id.to_string();
    html! {
        <aside class="ui-split-panel" aria-label="Rule detail">
            <div class="ui-split-panel-header">
                <h2 class="ui-split-panel-title">{rule.stig_id.clone()}</h2>
                <button type="button" class="ui-btn ui-btn-icon ui-split-panel-close"
                        onclick={{
                            // Closing the split panel deselects the rule.
                            let (dispatch, split_panel_open, tab_id) = (dispatch.clone(), sh.split_panel_open.clone(), tab_id.clone());
                            move |_| {
                                dispatch.dispatch(TabsAction::SetSelectedRule(tab_id.clone(), None));
                                split_panel_open.set(false);
                            }
                        }}>
                    {icon("close")}
                </button>
            </div>
            <div class="ui-split-panel-body" onfocusout={{ let a = autosave.clone(); move |_: FocusEvent| a.flush_soon() }}>
                <RuleDetail rule={rule.clone()}
                    on_update_rule={{
                        let (dispatch, tab_id, rule_id, autosave) = (dispatch.clone(), tab_id.clone(), rule.id.clone(), autosave.clone());
                        Callback::from(move |update| {
                            autosave.mark(&tab_id, std::slice::from_ref(&rule_id));
                            dispatch.dispatch(TabsAction::UpdateRule { tab_id: tab_id.clone(), rule_id: rule_id.clone(), update })
                        })
                    }}
                    on_close={{
                        let (dispatch, tab_id) = (dispatch.clone(), tab_id.clone());
                        Callback::from(move |_| dispatch.dispatch(TabsAction::SetSelectedRule(tab_id.clone(), None)))
                    }} />
            </div>
        </aside>
    }
}

// ── Content ─────────────────────────────────────────────────────────────────

pub(super) fn content(sh: &Shell) -> Html {
    match sh.mode {
        "admin" => html! { <AdminConsole /> },
        "dashboard" => html! { <Dashboard /> },
        "myfindings" => html! { <MyFindings /> },
        "systems" => html! { <AssetsLibrary /> },
        "groups" => html! { <AssetGroupsPage /> },
        "writer" => writer_view(sh),
        _ if !sh.has_tabs() || *sh.show_library => library_view(sh),
        _ if sh.is_diff_mode() => diff_view(sh),
        _ => sh
            .active_tab()
            .map(|t| stig_view(sh, t))
            .unwrap_or_else(|| html! {}),
    }
}

fn writer_view(sh: &Shell) -> Html {
    let writer_draft_id = sh.writer_draft_id.clone();
    let writer_draft_id_c = writer_draft_id.clone();
    html! {
        <StigWriter initial_draft_id={(*writer_draft_id).clone()}
                    on_clear_draft_id={Callback::from(move |_| writer_draft_id_c.set(None))} />
    }
}

fn library_view(sh: &Shell) -> Html {
    let on_load_sample = {
        let dispatch = sh.dispatch();
        Callback::from(move |_| {
            dispatch.dispatch(TabsAction::Add(vec![(None, generate_sample_stig())]))
        })
    };
    let handle_load_from_library = {
        let dispatch = sh.dispatch();
        let show_library = sh.show_library.clone();
        Callback::from(move |(id, stig): (String, Stig)| {
            dispatch.dispatch(TabsAction::Add(vec![(Some(id), stig)]));
            show_library.set(false);
        })
    };
    let handle_start_draft = {
        let writer_draft_id = sh.writer_draft_id.clone();
        let navigate_to = sh.navigate_to.clone();
        Callback::from(move |draft_id: String| {
            writer_draft_id.set(Some(draft_id));
            navigate_to.emit("writer");
        })
    };
    html! {
        <StigLibrary on_load={handle_load_from_library} on_start_draft={handle_start_draft}
            upload_tab={html! { <DropZone on_files_load={sh.on_add_files.clone()} on_load_sample={on_load_sample} /> }} />
    }
}

fn diff_view(sh: &Shell) -> Html {
    let d1 = sh.dispatch();
    let d2 = sh.dispatch();
    html! {
        <DiffView tabs={sh.state.tabs.clone()} diff_pair={sh.state.diff_pair.clone().unwrap_or_default()}
            on_set_diff_pair={Callback::from(move |pair| d1.dispatch(TabsAction::SetDiffPair(Some(pair))))}
            on_exit_diff={Callback::from(move |_| d2.dispatch(TabsAction::SetDiffPair(None)))} />
    }
}

/// The tabs that share `set_id`; empty when the tab is not in a set.
fn set_tabs_of(tabs: &[StigTab], set_id: Option<&String>) -> Vec<StigTab> {
    match set_id {
        Some(sid) => tabs
            .iter()
            .filter(|t| t.set_id.as_ref() == Some(sid))
            .cloned()
            .collect(),
        None => Vec::new(),
    }
}

fn add_stig_to_set(
    dispatch: UseReducerDispatcher<TabsState>,
    set: Option<ChecklistSet>,
    stig_id: String,
) {
    spawn_local(async move {
        let Some(set) = set else { return };
        let path = format!("/api/stigs/{}", crate::util::encode_uri_component(&stig_id));
        match api_get::<Stig>(&path).await {
            Ok(stig) => dispatch.dispatch(TabsAction::OpenSet {
                set,
                stigs: vec![(stig_id, stig)],
            }),
            Err(e) => console_error(&format!("Failed to load {stig_id}: {e}")),
        }
    });
}

fn stig_view(sh: &Shell, tab: &StigTab) -> Html {
    let dispatch = sh.dispatch();
    let autosave = &sh.autosave;
    let active_set = sh.active_set();
    let id = tab.id.clone();
    let (d1, d2, d3, d4, d5) = (
        dispatch.clone(),
        dispatch.clone(),
        dispatch.clone(),
        dispatch.clone(),
        dispatch.clone(),
    );
    let (i1, i2, i3, i4, i5) = (id.clone(), id.clone(), id.clone(), id.clone(), id.clone());
    let (a1, a4, a5) = (autosave.clone(), autosave.clone(), autosave.clone());
    let all_stig = tab.stig.clone();
    let set_tabs = set_tabs_of(&sh.state.tabs, tab.set_id.as_ref());
    let (rename_dispatch, link_dispatch, add_dispatch) =
        (dispatch.clone(), dispatch.clone(), dispatch.clone());
    let (rename_id, link_id, add_set) = (
        active_set.as_ref().map(|s| s.id.clone()),
        active_set.as_ref().map(|s| s.id.clone()),
        active_set.clone(),
    );
    html! {
        <StigView tab={tab.clone()}
            set={active_set.clone()}
            {set_tabs}
            autosave={sh.autosave_enabled.then(|| autosave.clone())}
            on_rename_set={Callback::from(move |name: String| {
                if let Some(set_id) = rename_id.clone() {
                    rename_dispatch.dispatch(TabsAction::SetRenamed { set_id, name });
                }
            })}
            on_set_linked={Callback::from(move |asset: Option<(String, String)>| {
                if let Some(set_id) = link_id.clone() {
                    link_dispatch.dispatch(TabsAction::SetLinked { set_id, asset });
                }
            })}
            on_add_stig={Callback::from(move |stig_id: String| {
                add_stig_to_set(add_dispatch.clone(), add_set.clone(), stig_id)
            })}
            on_update_rule={Callback::from(move |(rule_id, update): (String, RuleUpdate)| {
                a1.mark(&i1, std::slice::from_ref(&rule_id));
                d1.dispatch(TabsAction::UpdateRule { tab_id: i1.clone(), rule_id, update })
            })}
            on_set_asset_info={Callback::from(move |info| d2.dispatch(TabsAction::SetAssetInfo(i2.clone(), info)))}
            on_set_selected_rule={Callback::from(move |rule_id| d3.dispatch(TabsAction::SetSelectedRule(i3.clone(), rule_id)))}
            on_set_all_status={Callback::from(move |status| {
                let all_ids: Vec<String> = all_stig.rules.iter().map(|r| r.id.clone()).collect();
                a4.mark(&i4, &all_ids);
                d4.dispatch(TabsAction::SetAllStatus(i4.clone(), status))
            })}
            on_set_status_for={Callback::from(move |(rule_ids, status): (Vec<String>, String)| {
                a5.mark(&i5, &rule_ids);
                d5.dispatch(TabsAction::SetStatusFor(i5.clone(), rule_ids, status))
            })}
            on_add_files={sh.on_add_files.clone()} />
    }
}

// ── Modals ──────────────────────────────────────────────────────────────────

fn unknown_rules_note(unknown: usize) -> Option<String> {
    (unknown > 0).then(|| {
        format!(
            "{unknown} saved rule{} no longer match this STIG version and will not be saved to a system.",
            if unknown == 1 { "" } else { "s" }
        )
    })
}

pub(super) fn my_checklists_modal(sh: &Shell) -> Html {
    let (dispatch, autosave) = (sh.dispatch(), &sh.autosave);
    html! {
        <MyChecklists show={*sh.show_my_checklists}
            on_close={{ let m = sh.show_my_checklists.clone(); Callback::from(move |_| m.set(false)) }}
            on_open={{
                let (dispatch, autosave, m, note) = (dispatch.clone(), autosave.clone(), sh.show_my_checklists.clone(), sh.open_note.clone());
                let already_open: HashSet<String> = sh.state.tabs.iter().filter_map(|t| t.set_id.clone()).collect();
                let navigate_to = sh.navigate_to.clone();
                let show_library = sh.show_library.clone();
                Callback::from(move |(set, stigs, unknown): OpenedSet| {
                    // An open set keeps its own revision: its unsaved edits are saved against it.
                    if !already_open.contains(&set.id) {
                        autosave.register_set(&set);
                    }
                    note.set(unknown_rules_note(unknown));
                    dispatch.dispatch(TabsAction::OpenSet { set, stigs });
                    show_library.set(false);
                    navigate_to.emit("viewer");
                    m.set(false);
                })
            }}
            on_renamed={{
                let dispatch = dispatch.clone();
                Callback::from(move |(set_id, name): (String, String)| dispatch.dispatch(TabsAction::SetRenamed { set_id, name }))
            }}
            on_deleted={{
                let (dispatch, autosave) = (dispatch.clone(), autosave.clone());
                Callback::from(move |set_id: String| {
                    autosave.forget_set(&set_id);
                    dispatch.dispatch(TabsAction::SetDeleted(set_id));
                })
            }} />
    }
}

/// Download file name for an exported checklist: non-alphanumerics become `_`.
fn ckl_file_name(title: &str) -> String {
    let name: String = title
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{name}.ckl")
}

fn export_tab_ckl(tab: &StigTab) {
    let a = &tab.asset_info;
    let xml = export_ckl(&tab.stig, &a.hostname, &a.ip, &a.mac, &a.fqdn);
    download_text(&xml, "application/xml", &ckl_file_name(&tab.stig.title));
}

pub(super) fn close_tab_modal(sh: &Shell) -> Html {
    let closing_tab_id = &sh.closing_tab_id;
    let closing_tab = closing_tab_id
        .as_ref()
        .and_then(|id| sh.state.tabs.iter().find(|t| &t.id == id).cloned());
    let dismiss_close = {
        let closing_tab_id = closing_tab_id.clone();
        Callback::from(move |_: ()| closing_tab_id.set(None))
    };
    let close_without_saving = {
        let closing_tab_id = closing_tab_id.clone();
        let dispatch = sh.dispatch();
        Callback::from(move |_: MouseEvent| {
            if let Some(id) = (*closing_tab_id).clone() {
                dispatch.dispatch(TabsAction::Remove(id));
            }
            closing_tab_id.set(None);
        })
    };
    let export_and_close = {
        let closing_tab_id = closing_tab_id.clone();
        let dispatch = sh.dispatch();
        Callback::from(move |_: MouseEvent| {
            if let Some(tab) = &closing_tab {
                export_tab_ckl(tab);
                dispatch.dispatch(TabsAction::Remove(tab.id.clone()));
            }
            closing_tab_id.set(None);
        })
    };
    html! {
        <Modal visible={closing_tab_id.is_some()} on_dismiss={dismiss_close.clone()} header="Close checklist"
            footer={html! {
                <UiBox float="right">
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button variant="link" onclick={dismiss_close.reform(|_: MouseEvent| ())}>{"Cancel"}</Button>
                        <Button onclick={export_and_close}>{"Export .ckl & Close"}</Button>
                        <Button variant="primary" onclick={close_without_saving}>{"Close without saving"}</Button>
                    </SpaceBetween>
                </UiBox>
            }}>
            <Alert kind="warning">
                {"Any unsaved progress on this checklist will be lost. Export your work first if you need to keep it."}
            </Alert>
        </Modal>
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::model::{AssetInfo, Stig};

    fn tab(catalog_id: Option<&str>, set_id: Option<&str>) -> StigTab {
        StigTab {
            id: "t".into(),
            stig: Rc::new(Stig::default()),
            asset_info: AssetInfo::default(),
            selected_rule_id: None,
            catalog_id: catalog_id.map(Into::into),
            set_id: set_id.map(Into::into),
        }
    }

    #[test]
    fn closes_without_prompt_needs_autosave_and_a_catalog_tab() {
        let never = || -> bool { panic!("dirty must not be consulted") };
        assert!(!closes_without_prompt(
            false,
            &tab(Some("c"), Some("s")),
            never
        ));
        assert!(!closes_without_prompt(true, &tab(None, Some("s")), never));
        assert!(closes_without_prompt(
            true,
            &tab(Some("c"), Some("s")),
            never
        ));
        assert!(closes_without_prompt(true, &tab(Some("c"), None), || true));
        assert!(!closes_without_prompt(true, &tab(Some("c"), None), || {
            false
        }));
    }

    #[test]
    fn view_url_omits_the_query_for_the_viewer() {
        assert_eq!(view_url("/app", "viewer"), "/app");
        assert_eq!(view_url("/app", "admin"), "/app?view=admin");
    }

    #[test]
    fn tab_label_prefixes_the_set_name() {
        assert_eq!(tab_label(Some("Set"), "Title"), "Set · Title");
        assert_eq!(tab_label(None, "Title"), "Title");
    }

    #[test]
    fn ckl_file_name_replaces_non_alphanumerics() {
        assert_eq!(ckl_file_name("RHEL 9 STIG v1.2"), "RHEL_9_STIG_v1_2.ckl");
        assert_eq!(ckl_file_name(""), ".ckl");
    }

    #[test]
    fn unknown_rules_note_pluralises() {
        assert_eq!(unknown_rules_note(0), None);
        assert!(unknown_rules_note(1).is_some_and(|n| n.starts_with("1 saved rule no longer")));
        assert!(unknown_rules_note(2).is_some_and(|n| n.starts_with("2 saved rules no longer")));
    }

    #[test]
    fn account_name_falls_back_when_blank() {
        let mut u = User {
            id: "1".into(),
            display_name: String::new(),
            role: "user".into(),
        };
        assert_eq!(account_name(&u), "Account");
        u.display_name = "Ada".into();
        assert_eq!(account_name(&u), "Ada");
    }
}
