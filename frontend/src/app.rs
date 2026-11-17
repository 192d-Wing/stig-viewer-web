//! Application shell: top navigation, viewer tabs, side navigation, split
//! panel, and the notification bell.

use std::rc::Rc;

use gloo_events::EventListener;
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast, JsValue};
use yew::prelude::*;

use crate::api::{api_fetch, api_get, api_send};
use crate::auth::use_current_user;
use crate::components::admin_console::AdminConsole;
use crate::components::asset_groups_page::AssetGroupsPage;
use crate::components::assets_library::AssetsLibrary;
use crate::components::dashboard::Dashboard;
use crate::components::diff_view::DiffView;
use crate::components::drop_zone::DropZone;
use crate::components::my_findings::MyFindings;
use crate::components::rule_detail::RuleDetail;
use crate::components::stig_library::StigLibrary;
use crate::components::stig_view::StigView;
use crate::components::stig_writer::StigWriter;
use crate::data::sample_stig::generate_sample_stig;
use crate::hooks::{use_interval, use_online};
use crate::model::{AssetInfo, RuleUpdate, Stig, StigTab};
use crate::ui::*;
use crate::util::{
    console_error, download_text, file_list_to_vec, file_text, now_ms, spawn_local, to_locale_string,
    url_param, window,
};
use crate::utils::export_ckl::export_ckl;
use crate::utils::parse_ckl::parse_ckl;
use crate::utils::parse_xccdf::parse_xccdf;

// ── Viewer tab state ────────────────────────────────────────────────────────

type DiffPair = (Option<String>, Option<String>);

#[derive(Clone, PartialEq, Default)]
struct TabsState {
    tabs: Vec<StigTab>,
    active_tab_id: Option<String>,
    diff_pair: Option<DiffPair>,
}

enum TabsAction {
    /// Add tabs and focus the first new one.
    Add(Vec<Stig>),
    /// Close a tab and move focus to the nearest remaining tab.
    Remove(String),
    SetActive(String),
    UpdateRule { tab_id: String, rule_id: String, update: RuleUpdate },
    SetAssetInfo(String, AssetInfo),
    SetSelectedRule(String, Option<String>),
    SetAllStatus(String, String),
    SetDiffPair(Option<DiffPair>),
}

fn generate_tab_id() -> String {
    let rand = js_sys::Math::random().to_string();
    let suffix: String = rand.chars().skip(2).take(5).collect();
    format!("tab-{}-{suffix}", now_ms() as u64)
}

impl Reducible for TabsState {
    type Action = TabsAction;

    fn reduce(self: Rc<Self>, action: TabsAction) -> Rc<Self> {
        let mut s = (*self).clone();
        match action {
            TabsAction::Add(stigs) => {
                let new_tabs: Vec<StigTab> = stigs
                    .into_iter()
                    .map(|stig| StigTab {
                        id: generate_tab_id(),
                        stig: Rc::new(stig),
                        asset_info: AssetInfo::default(),
                        selected_rule_id: None,
                    })
                    .collect();
                if let Some(first) = new_tabs.first() {
                    s.active_tab_id = Some(first.id.clone());
                }
                s.tabs.extend(new_tabs);
            }
            TabsAction::Remove(id) => {
                let closed_idx = s.tabs.iter().position(|t| t.id == id);
                s.tabs.retain(|t| t.id != id);
                if s.active_tab_id.as_deref() == Some(id.as_str()) {
                    s.active_tab_id = match closed_idx {
                        Some(i) if !s.tabs.is_empty() => Some(s.tabs[i.min(s.tabs.len() - 1)].id.clone()),
                        _ => None,
                    };
                }
                if let Some((a, b)) = &s.diff_pair {
                    if a.as_deref() == Some(id.as_str()) || b.as_deref() == Some(id.as_str()) {
                        s.diff_pair = None;
                    }
                }
            }
            TabsAction::SetActive(id) => s.active_tab_id = Some(id),
            TabsAction::UpdateRule { tab_id, rule_id, update } => {
                if let Some(t) = s.tabs.iter_mut().find(|t| t.id == tab_id) {
                    let stig = Rc::make_mut(&mut t.stig);
                    if let Some(r) = stig.rules.iter_mut().find(|r| r.id == rule_id) {
                        update.apply(r);
                    }
                }
            }
            TabsAction::SetAssetInfo(tab_id, info) => {
                if let Some(t) = s.tabs.iter_mut().find(|t| t.id == tab_id) {
                    t.asset_info = info;
                }
            }
            TabsAction::SetSelectedRule(tab_id, rule_id) => {
                if let Some(t) = s.tabs.iter_mut().find(|t| t.id == tab_id) {
                    t.selected_rule_id = rule_id;
                }
            }
            TabsAction::SetAllStatus(tab_id, status) => {
                if let Some(t) = s.tabs.iter_mut().find(|t| t.id == tab_id) {
                    for r in Rc::make_mut(&mut t.stig).rules.iter_mut() {
                        r.status = status.clone();
                    }
                }
            }
            TabsAction::SetDiffPair(pair) => s.diff_pair = pair,
        }
        Rc::new(s)
    }
}

/// Parse dropped/picked files (.ckl or XCCDF .xml) and open each as a tab.
fn add_files(tabs: UseReducerDispatcher<TabsState>, files: Vec<web_sys::File>) {
    spawn_local(async move {
        let mut stigs = Vec::new();
        for file in files {
            let name = file.name();
            let parsed = match file_text(&file).await {
                Ok(text) if name.ends_with(".ckl") => parse_ckl(&text),
                Ok(text) => parse_xccdf(&text),
                Err(e) => Err(e),
            };
            match parsed {
                Ok(stig) => stigs.push(stig),
                // Surface parsing errors without crashing.
                Err(e) => console_error(&format!("Failed to parse {name}: {e}")),
            }
        }
        if !stigs.is_empty() {
            tabs.dispatch(TabsAction::Add(stigs));
        }
    });
}

// ── Top-level view routing (`?view=`) ───────────────────────────────────────

const VIEWS: [&str; 7] = ["viewer", "writer", "systems", "groups", "dashboard", "myfindings", "admin"];

fn view_from_url() -> &'static str {
    let v = url_param("view").unwrap_or_default();
    VIEWS.iter().copied().find(|k| *k == v).unwrap_or("viewer")
}

// ── Notifications ───────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NotifFinding {
    checklist_id: String,
    rule_id: String,
    asset_name: String,
    stig_title: String,
    occurred_at: String,
    due_date: Option<String>,
    unread: bool,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NotifMention {
    comment_id: String,
    rule_id: String,
    by_name: String,
    body: String,
    at: String,
    unread: bool,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NotifDraft {
    draft_id: String,
    title: String,
    by_name: String,
    at: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NotifData {
    assigned: Vec<NotifFinding>,
    overdue: Vec<NotifFinding>,
    mentions: Vec<NotifMention>,
    assigned_drafts: Vec<NotifDraft>,
    unread_count: u32,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NotifPrefs {
    assigned: bool,
    overdue: bool,
    mentions: bool,
    approvals: bool,
    decisions: bool,
    assigned_drafts: bool,
}

impl Default for NotifPrefs {
    /// The backend treats missing rows as enabled, so first-open shows
    /// every toggle on.
    fn default() -> Self {
        Self { assigned: true, overdue: true, mentions: true, approvals: true, decisions: true, assigned_drafts: true }
    }
}

fn count_suffix(n: usize) -> String {
    if n > 0 {
        format!(" ({n})")
    } else {
        String::new()
    }
}

const LOGO_SVG: &str = concat!(
    r##"<svg width="40" height="40" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">"##,
    r##"<path d="M20 3l14 5v10c0 9-5.6 15.6-14 19C11.600 33.600 6 27 6 18V8z" fill="#3ec6b3"/>"##,
    r##"<path d="M13 20l5 5 9-10" stroke="#04211d" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>"##,
    "</svg>"
);

// ── Small shell pieces ──────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
struct NavButtonProps {
    text: AttrValue,
    #[prop_or_default]
    active: bool,
    #[prop_or_default]
    icon_name: Option<AttrValue>,
    #[prop_or_default]
    aria_label: Option<AttrValue>,
    onclick: Callback<MouseEvent>,
}

#[function_component]
fn NavButton(p: &NavButtonProps) -> Html {
    html! {
        <button type="button" class={classes!("ui-topnav-btn", p.active.then_some("ui-topnav-btn-active"))}
                aria-label={p.aria_label.clone()} aria-current={p.active.then_some("page")} onclick={p.onclick.clone()}>
            if let Some(i) = &p.icon_name { {icon(i)} }
            <span>{p.text.clone()}</span>
        </button>
    }
}

#[derive(Properties, PartialEq)]
struct AccountMenuProps {
    name: AttrValue,
    on_sign_out: Callback<()>,
}

#[function_component]
fn AccountMenu(p: &AccountMenuProps) -> Html {
    let open = use_state(|| false);
    let root = use_node_ref();
    {
        let open = open.clone();
        let root = root.clone();
        use_effect_with(*open, move |is_open| {
            let listener = is_open.then(|| {
                EventListener::new(&crate::util::document(), "mousedown", move |e| {
                    let inside = e
                        .target()
                        .and_then(|t| t.dyn_into::<web_sys::Node>().ok())
                        .zip(root.get())
                        .map(|(t, r)| r.contains(Some(&t)))
                        .unwrap_or(false);
                    if !inside {
                        open.set(false);
                    }
                })
            });
            move || drop(listener)
        });
    }
    let toggle = {
        let open = open.clone();
        Callback::from(move |_: MouseEvent| open.set(!*open))
    };
    let sign_out = {
        let open = open.clone();
        let cb = p.on_sign_out.clone();
        Callback::from(move |_: MouseEvent| {
            open.set(false);
            cb.emit(());
        })
    };
    html! {
        <div class="ui-topnav-menu" ref={root}>
            <button type="button" class="ui-topnav-btn" aria-haspopup="menu" aria-expanded={open.to_string()} onclick={toggle}>
                {icon("user-profile")}
                <span>{p.name.clone()}</span>
                {icon("caret-down")}
            </button>
            if *open {
                <ul class="ui-menu" role="menu">
                    <li role="none">
                        <button type="button" class="ui-menu-item" role="menuitem" onclick={sign_out}>{"Sign out"}</button>
                    </li>
                </ul>
            }
        </div>
    }
}

// ── App ─────────────────────────────────────────────────────────────────────

#[function_component]
pub fn App() -> Html {
    let current_user = use_current_user();
    let online = use_online();
    let tabs_state = use_reducer(TabsState::default);
    let dispatch = tabs_state.dispatcher();

    // Top-level "view" is encoded in `?view=` so the URL is shareable. On
    // initial load we honour the param; `navigate_to` pushes a new history
    // entry and clears stale page-specific params from the previous view.
    let app_mode = use_state(view_from_url);
    let navigate_to = {
        let app_mode = app_mode.clone();
        Callback::from(move |mode: &'static str| {
            app_mode.set(mode);
            let path = window().location().pathname().unwrap_or_default();
            let url = if mode == "viewer" { path } else { format!("{path}?view={mode}") };
            if let Ok(h) = window().history() {
                let _ = h.push_state_with_url(&JsValue::NULL, "", Some(&url));
            }
        })
    };
    {
        // Pick up browser back/forward.
        let app_mode = app_mode.clone();
        use_effect_with((), move |_| {
            let l = EventListener::new(&window(), "popstate", move |_| app_mode.set(view_from_url()));
            move || drop(l)
        });
    }

    let nav_open = use_state(|| true);
    let split_panel_open = use_state(|| true);
    let show_library = use_state(|| false);
    let closing_tab_id = use_state(|| None::<String>);
    let writer_draft_id = use_state(|| None::<String>);
    let file_input = use_node_ref();

    let mode = *app_mode;
    let is_library_mode = mode == "viewer";

    let tabs = &tabs_state.tabs;
    let active_tab_id = tabs_state.active_tab_id.clone();
    let active_tab = tabs.iter().find(|t| Some(&t.id) == active_tab_id.as_ref()).cloned();
    let diff_pair = tabs_state.diff_pair.clone();
    let is_diff_mode = diff_pair.is_some();
    let has_tabs = !tabs.is_empty();

    let selected_rule = active_tab.as_ref().and_then(|t| {
        t.stig.rules.iter().find(|r| Some(&r.id) == t.selected_rule_id.as_ref()).cloned()
    });

    let on_add_files = {
        let dispatch = dispatch.clone();
        Callback::from(move |files: Vec<web_sys::File>| add_files(dispatch.clone(), files))
    };
    let on_load_sample = {
        let dispatch = dispatch.clone();
        Callback::from(move |_| dispatch.dispatch(TabsAction::Add(vec![generate_sample_stig()])))
    };

    let handle_diff_toggle = {
        let dispatch = dispatch.clone();
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

    let handle_file_input = {
        let on_add_files = on_add_files.clone();
        Callback::from(move |e: Event| {
            if let Some(input) = e.target().and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok()) {
                let files = file_list_to_vec(input.files());
                if !files.is_empty() {
                    on_add_files.emit(files);
                }
            }
        })
    };

    // ── Notifications ───────────────────────────────────────────────────────
    // Poll the bell endpoint every 30s so the badge stays roughly fresh.
    // Opening the panel calls /mark-read, which clears the unread counter
    // server-side and lets future events count as unread again.
    let notif_data = use_state(NotifData::default);
    let notif_open = use_state(|| false);
    let notif_prefs_open = use_state(|| false);
    let notif_prefs = use_state(NotifPrefs::default);
    let notif_prefs_saving = use_state(|| false);

    let refresh_notifications = {
        let notif_data = notif_data.clone();
        Callback::from(move |_: ()| {
            let notif_data = notif_data.clone();
            spawn_local(async move {
                // Non-fatal on failure; the bell stays as it was.
                if let Ok(d) = api_get::<NotifData>("/api/notifications").await {
                    notif_data.set(d);
                }
            });
        })
    };
    {
        let refresh = refresh_notifications.clone();
        let user_id = current_user.as_ref().map(|u| u.id.clone());
        use_effect_with(user_id, move |uid| {
            if uid.is_some() {
                refresh.emit(());
            }
        });
    }
    {
        let refresh = refresh_notifications.clone();
        let signed_in = current_user.is_some();
        let tick = Callback::from(move |_| {
            if signed_in {
                refresh.emit(());
            }
        });
        use_interval(signed_in, 30_000, tick);
    }

    let open_notif_prefs = {
        let notif_prefs_open = notif_prefs_open.clone();
        let notif_prefs = notif_prefs.clone();
        Callback::from(move |_: MouseEvent| {
            notif_prefs_open.set(true);
            let notif_prefs = notif_prefs.clone();
            spawn_local(async move {
                // Non-fatal — leave defaults in place so the toggles still render.
                if let Ok(p) = api_get::<NotifPrefs>("/api/notifications/prefs").await {
                    notif_prefs.set(p);
                }
            });
        })
    };

    let save_notif_prefs = {
        let notif_prefs = notif_prefs.clone();
        let saving = notif_prefs_saving.clone();
        let notif_prefs_open = notif_prefs_open.clone();
        let refresh = refresh_notifications.clone();
        Callback::from(move |_: MouseEvent| {
            let prefs = (*notif_prefs).clone();
            let saving = saving.clone();
            let notif_prefs_open = notif_prefs_open.clone();
            let refresh = refresh.clone();
            saving.set(true);
            spawn_local(async move {
                // On failure the toggles stay where the user left them and
                // the modal stays open so they can retry.
                if api_send("/api/notifications/prefs", "PUT", Some(&prefs)).await.is_ok() {
                    notif_prefs_open.set(false);
                    // Refresh the bell so disabled buckets clear immediately.
                    refresh.emit(());
                }
                saving.set(false);
            });
        })
    };

    let open_notifications = {
        let notif_open = notif_open.clone();
        let notif_data = notif_data.clone();
        Callback::from(move |_: MouseEvent| {
            notif_open.set(true);
            let notif_data = notif_data.clone();
            spawn_local(async move {
                // mark-read answers 204; failures are non-fatal and the
                // local clear below still runs.
                let _ = api_fetch("POST", "/api/notifications/mark-read").await;
                let mut d = (*notif_data).clone();
                d.unread_count = 0;
                d.assigned.iter_mut().for_each(|a| a.unread = false);
                d.mentions.iter_mut().for_each(|m| m.unread = false);
                notif_data.set(d);
            });
        })
    };

    let handle_sign_out = Callback::from(|_: ()| {
        spawn_local(async {
            let _ = api_fetch("POST", "/auth/logout").await;
            let _ = window().location().reload();
        });
    });

    let handle_load_from_library = {
        let dispatch = dispatch.clone();
        let show_library = show_library.clone();
        Callback::from(move |stig: Stig| {
            dispatch.dispatch(TabsAction::Add(vec![stig]));
            show_library.set(false);
        })
    };
    let handle_start_draft = {
        let writer_draft_id = writer_draft_id.clone();
        let navigate_to = navigate_to.clone();
        Callback::from(move |draft_id: String| {
            writer_draft_id.set(Some(draft_id));
            navigate_to.emit("writer");
        })
    };

    // ── Content ─────────────────────────────────────────────────────────────
    let content = match mode {
        "admin" => html! { <AdminConsole /> },
        "dashboard" => html! { <Dashboard /> },
        "myfindings" => html! { <MyFindings /> },
        "systems" => html! { <AssetsLibrary /> },
        "groups" => html! { <AssetGroupsPage /> },
        "writer" => {
            let writer_draft_id_c = writer_draft_id.clone();
            html! {
                <StigWriter initial_draft_id={(*writer_draft_id).clone()}
                            on_clear_draft_id={Callback::from(move |_| writer_draft_id_c.set(None))} />
            }
        }
        _ if !has_tabs || *show_library => html! {
            <StigLibrary on_load={handle_load_from_library} on_start_draft={handle_start_draft}
                upload_tab={html! { <DropZone on_files_load={on_add_files.clone()} on_load_sample={on_load_sample} /> }} />
        },
        _ if is_diff_mode => {
            let d1 = dispatch.clone();
            let d2 = dispatch.clone();
            html! {
                <DiffView tabs={tabs.clone()} diff_pair={diff_pair.clone().unwrap_or_default()}
                    on_set_diff_pair={Callback::from(move |pair| d1.dispatch(TabsAction::SetDiffPair(Some(pair))))}
                    on_exit_diff={Callback::from(move |_| d2.dispatch(TabsAction::SetDiffPair(None)))} />
            }
        }
        _ => match &active_tab {
            Some(tab) => {
                let id = tab.id.clone();
                let (d1, d2, d3, d4) = (dispatch.clone(), dispatch.clone(), dispatch.clone(), dispatch.clone());
                let (i1, i2, i3, i4) = (id.clone(), id.clone(), id.clone(), id.clone());
                html! {
                    <StigView tab={tab.clone()}
                        on_update_rule={Callback::from(move |(rule_id, update)| d1.dispatch(TabsAction::UpdateRule { tab_id: i1.clone(), rule_id, update }))}
                        on_set_asset_info={Callback::from(move |info| d2.dispatch(TabsAction::SetAssetInfo(i2.clone(), info)))}
                        on_set_selected_rule={Callback::from(move |rule_id| d3.dispatch(TabsAction::SetSelectedRule(i3.clone(), rule_id)))}
                        on_set_all_status={Callback::from(move |status| d4.dispatch(TabsAction::SetAllStatus(i4.clone(), status)))}
                        on_add_files={on_add_files.clone()} />
                }
            }
            None => html! {},
        },
    };

    // ── Top navigation ──────────────────────────────────────────────────────
    let nav_btn = |text: &'static str, target: &'static str| {
        let navigate_to = navigate_to.clone();
        html! { <NavButton {text} active={mode == target} onclick={Callback::from(move |_| navigate_to.emit(target))} /> }
    };
    let is_admin_user = current_user.as_ref().map(|u| u.role == "admin").unwrap_or(false);
    let is_viewer_user = current_user.as_ref().map(|u| u.role == "viewer").unwrap_or(false);
    let open_file = {
        let file_input = file_input.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(el) = file_input.cast::<web_sys::HtmlElement>() {
                el.click();
            }
        })
    };
    let notif_text = if notif_data.unread_count > 0 {
        format!("Notifications ({})", notif_data.unread_count)
    } else {
        "Notifications".to_string()
    };

    // ── Side navigation / split panel ───────────────────────────────────────
    let navigation_hide = !is_library_mode || !has_tabs || is_diff_mode;
    let navigation_open = *nav_open && !navigation_hide;
    let active_href = if *show_library { None } else { active_tab_id.clone() };
    let split_panel = match (&selected_rule, &active_tab) {
        (Some(rule), Some(tab)) if !is_diff_mode && is_library_mode && !*show_library && *split_panel_open => Some((rule.clone(), tab.id.clone())),
        _ => None,
    };
    {
        // Selecting a rule re-opens a split panel the user had closed.
        let split_panel_open = split_panel_open.clone();
        let key = active_tab.as_ref().and_then(|t| t.selected_rule_id.clone());
        use_effect_with(key, move |k| {
            if k.is_some() {
                split_panel_open.set(true);
            }
        });
    }

    let closing_tab = closing_tab_id.as_ref().and_then(|id| tabs.iter().find(|t| &t.id == id).cloned());
    let dismiss_close = {
        let closing_tab_id = closing_tab_id.clone();
        Callback::from(move |_: ()| closing_tab_id.set(None))
    };
    let close_without_saving = {
        let closing_tab_id = closing_tab_id.clone();
        let dispatch = dispatch.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(id) = (*closing_tab_id).clone() {
                dispatch.dispatch(TabsAction::Remove(id));
            }
            closing_tab_id.set(None);
        })
    };
    let export_and_close = {
        let closing_tab_id = closing_tab_id.clone();
        let dispatch = dispatch.clone();
        let tab = closing_tab.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(tab) = &tab {
                let a = &tab.asset_info;
                let xml = export_ckl(&tab.stig, &a.hostname, &a.ip, &a.mac, &a.fqdn);
                let name: String = tab
                    .stig
                    .title
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                    .collect();
                download_text(&xml, "application/xml", &format!("{name}.ckl"));
                dispatch.dispatch(TabsAction::Remove(tab.id.clone()));
            }
            closing_tab_id.set(None);
        })
    };

    let inactive = |text: &'static str| html! {
        <UiBox color="text-status-inactive" padding_top="xs">{text}</UiBox>
    };
    let when = |s: String| html! { <UiBox variant="span" color="text-status-inactive">{s}</UiBox> };
    let pref_toggle = |label: &'static str, testid: &'static str, checked: bool, set: fn(&mut NotifPrefs, bool)| {
        let notif_prefs = notif_prefs.clone();
        let on_change = Callback::from(move |v: bool| {
            let mut p = (*notif_prefs).clone();
            set(&mut p, v);
            notif_prefs.set(p);
        });
        html! { <Toggle {checked} {testid} {on_change}>{label}</Toggle> }
    };

    html! {
        <>
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
                        if is_library_mode && has_tabs {
                            <NavButton text="Open File" icon_name="upload" onclick={open_file} />
                            if tabs.len() >= 2 {
                                <NavButton text={if is_diff_mode { "Exit Diff" } else { "Diff" }} active={is_diff_mode} onclick={handle_diff_toggle} />
                            }
                        }
                        if is_viewer_user {
                            <span data-testid="viewer-badge" class="ui-topnav-badge"><Badge color="grey">{"Read-only"}</Badge></span>
                        }
                        if let Some(user) = &current_user {
                            <NavButton text={notif_text} icon_name="notification" aria_label="Notifications" onclick={open_notifications} />
                            <AccountMenu name={if user.display_name.is_empty() { "Account".to_string() } else { user.display_name.clone() }}
                                         on_sign_out={handle_sign_out} />
                        }
                    </div>
                </header>
            </div>

            // Hidden file input for the Open File utility
            <input ref={file_input} type="file" accept=".xml,.ckl" multiple=true style="display:none"
                   aria-hidden="true" tabindex="-1" onchange={handle_file_input} />

            <div class={classes!("ui-app-layout", navigation_open.then_some("ui-app-nav-open"), split_panel.is_some().then_some("ui-app-split-open"))}>
                if !navigation_hide {
                    if navigation_open {
                        <nav class="ui-app-nav" aria-label="Open STIGs">
                            <div class="ui-sidenav-header">
                                <a href="#" class="ui-sidenav-title" onclick={|e: MouseEvent| e.prevent_default()}>{"Open STIGs"}</a>
                                <button type="button" class="ui-btn ui-btn-icon ui-nav-toggle"
                                        onclick={{ let nav_open = nav_open.clone(); move |_| nav_open.set(false) }}>
                                    {icon("angle-left")}
                                </button>
                            </div>
                            <ul class="ui-sidenav-list">
                                <li>
                                    <a href="#library" class={classes!("ui-sidenav-link", (*show_library).then_some("ui-sidenav-active"))}
                                       aria-current={(*show_library).then_some("page")}
                                       onclick={{ let show_library = show_library.clone(); move |e: MouseEvent| { e.prevent_default(); show_library.set(true); } }}>
                                        {icon("add-plus")}{"Browse Library"}
                                    </a>
                                </li>
                                <li class="ui-sidenav-divider" role="separator" />
                                { for tabs.iter().map(|tab| {
                                    let is_active = Some(&tab.id) == active_href.as_ref();
                                    let follow = {
                                        let (dispatch, show_library, id) = (dispatch.clone(), show_library.clone(), tab.id.clone());
                                        Callback::from(move |e: MouseEvent| {
                                            e.prevent_default();
                                            show_library.set(false);
                                            dispatch.dispatch(TabsAction::SetActive(id.clone()));
                                        })
                                    };
                                    let close = {
                                        let (closing_tab_id, id) = (closing_tab_id.clone(), tab.id.clone());
                                        Callback::from(move |e: MouseEvent| {
                                            e.prevent_default();
                                            e.stop_propagation();
                                            closing_tab_id.set(Some(id.clone()));
                                        })
                                    };
                                    html! {
                                        <li key={tab.id.clone()} class="ui-sidenav-item">
                                            <a href={format!("#{}", tab.id)} class={classes!("ui-sidenav-link", is_active.then_some("ui-sidenav-active"))}
                                               aria-current={is_active.then_some("page")} onclick={follow}>
                                                {tab.stig.title.clone()}
                                            </a>
                                            <Button variant="icon" icon_name="close" aria_label={format!("Close {}", tab.stig.title)} onclick={close} />
                                        </li>
                                    }
                                }) }
                            </ul>
                        </nav>
                    } else {
                        <div class="ui-app-nav-collapsed">
                            <button type="button" class="ui-btn ui-btn-icon ui-nav-toggle"
                                    onclick={{ let nav_open = nav_open.clone(); move |_| nav_open.set(true) }}>
                                {icon("menu")}
                            </button>
                        </div>
                    }
                }
                <div class="ui-app-main">
                    if !online {
                        <Flash kind="warning" header="Offline">
                            {"No network connection. Cached STIGs remain viewable; uploads and saves will resume when the connection returns."}
                        </Flash>
                    }
                    <main class="ui-app-content">{content}</main>
                </div>
                if let Some((rule, tab_id)) = split_panel {
                    <aside class="ui-split-panel" aria-label="Rule detail">
                        <div class="ui-split-panel-header">
                            <h2 class="ui-split-panel-title">{rule.stig_id.clone()}</h2>
                            <button type="button" class="ui-btn ui-btn-icon ui-split-panel-close"
                                    onclick={{
                                        // Closing the split panel deselects the rule.
                                        let (dispatch, split_panel_open, tab_id) = (dispatch.clone(), split_panel_open.clone(), tab_id.clone());
                                        move |_| {
                                            dispatch.dispatch(TabsAction::SetSelectedRule(tab_id.clone(), None));
                                            split_panel_open.set(false);
                                        }
                                    }}>
                                {icon("close")}
                            </button>
                        </div>
                        <div class="ui-split-panel-body">
                            <RuleDetail rule={rule.clone()}
                                on_update_rule={{
                                    let (dispatch, tab_id, rule_id) = (dispatch.clone(), tab_id.clone(), rule.id.clone());
                                    Callback::from(move |update| dispatch.dispatch(TabsAction::UpdateRule { tab_id: tab_id.clone(), rule_id: rule_id.clone(), update }))
                                }}
                                on_close={{
                                    let (dispatch, tab_id) = (dispatch.clone(), tab_id.clone());
                                    Callback::from(move |_| dispatch.dispatch(TabsAction::SetSelectedRule(tab_id.clone(), None)))
                                }} />
                        </div>
                    </aside>
                }
            </div>

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

            <Modal visible={*notif_open} size="medium"
                on_dismiss={{ let notif_open = notif_open.clone(); Callback::from(move |_| notif_open.set(false)) }}
                header={html! {
                    <SpaceBetween direction="horizontal" size="s">
                        <UiBox variant="h2" padding="n">{"Notifications"}</UiBox>
                        <Button variant="link" testid="notif-prefs-open" onclick={open_notif_prefs}>{"Preferences"}</Button>
                    </SpaceBetween>
                }}>
                <SpaceBetween direction="vertical" size="l">
                    <UiBox>
                        <UiBox variant="h4">{"Newly assigned"}</UiBox>
                        if notif_data.assigned.is_empty() {
                            {inactive("Nothing assigned to you recently.")}
                        } else {
                            <ul class="ui-notif-list">
                                { for notif_data.assigned.iter().map(|a| html! {
                                    <li key={format!("{}:{}:{}", a.checklist_id, a.rule_id, a.occurred_at)}>
                                        <strong>{a.rule_id.clone()}</strong>{" on "}<em>{a.asset_name.clone()}</em>{" · "}{a.stig_title.clone()}
                                        {when(format!(" — {}", to_locale_string(&a.occurred_at)))}
                                    </li>
                                }) }
                            </ul>
                        }
                    </UiBox>
                    <UiBox>
                        <UiBox variant="h4">{"Overdue"}{count_suffix(notif_data.overdue.len())}</UiBox>
                        if notif_data.overdue.is_empty() {
                            {inactive("Nothing assigned to you is past due.")}
                        } else {
                            <ul class="ui-notif-list">
                                { for notif_data.overdue.iter().map(|o| html! {
                                    <li key={format!("{}:{}", o.checklist_id, o.rule_id)}>
                                        <strong>{o.rule_id.clone()}</strong>{" on "}<em>{o.asset_name.clone()}</em>{" · "}{o.stig_title.clone()}
                                        {when(format!(" — due {}", o.due_date.clone().unwrap_or_default()))}
                                    </li>
                                }) }
                            </ul>
                        }
                    </UiBox>
                    <UiBox>
                        <UiBox variant="h4">{"Drafts waiting on you"}{count_suffix(notif_data.assigned_drafts.len())}</UiBox>
                        if notif_data.assigned_drafts.is_empty() {
                            {inactive("No drafts are awaiting your review.")}
                        } else {
                            <ul class="ui-notif-list" data-testid="assigned-drafts-list">
                                { for notif_data.assigned_drafts.iter().map(|d| {
                                    let onclick = {
                                        let (notif_open, writer_draft_id, navigate_to, id) =
                                            (notif_open.clone(), writer_draft_id.clone(), navigate_to.clone(), d.draft_id.clone());
                                        Callback::from(move |_: MouseEvent| {
                                            notif_open.set(false);
                                            writer_draft_id.set(Some(id.clone()));
                                            navigate_to.emit("writer");
                                        })
                                    };
                                    html! {
                                        <li key={d.draft_id.clone()} data-testid="assigned-draft-item" class="ui-clickable" {onclick}>
                                            <strong>{if d.title.is_empty() { "(untitled draft)".to_string() } else { d.title.clone() }}</strong>
                                            {" from "}<em>{d.by_name.clone()}</em>
                                            {when(format!(" — {}", to_locale_string(&d.at)))}
                                        </li>
                                    }
                                }) }
                            </ul>
                        }
                    </UiBox>
                    <UiBox>
                        <UiBox variant="h4">{"Mentions"}{count_suffix(notif_data.mentions.len())}</UiBox>
                        if notif_data.mentions.is_empty() {
                            {inactive("No one has @-mentioned you in a comment.")}
                        } else {
                            <ul class="ui-notif-list" data-testid="mentions-list">
                                { for notif_data.mentions.iter().map(|m| {
                                    let onclick = {
                                        let (notif_open, navigate_to) = (notif_open.clone(), navigate_to.clone());
                                        Callback::from(move |_: MouseEvent| {
                                            notif_open.set(false);
                                            navigate_to.emit("systems");
                                        })
                                    };
                                    html! {
                                        <li key={m.comment_id.clone()} data-testid="mention-item" class="ui-clickable" {onclick}>
                                            <strong>{m.by_name.clone()}</strong>{" mentioned you on "}<em>{m.rule_id.clone()}</em>
                                            {format!(": \"{}\"", m.body)}
                                            {when(format!(" — {}", to_locale_string(&m.at)))}
                                        </li>
                                    }
                                }) }
                            </ul>
                        }
                    </UiBox>
                </SpaceBetween>
            </Modal>

            <Modal visible={*notif_prefs_open} size="small" header="Notification preferences" testid="notif-prefs-modal"
                on_dismiss={{ let o = notif_prefs_open.clone(); Callback::from(move |_| o.set(false)) }}
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={{ let o = notif_prefs_open.clone(); move |_| o.set(false) }}>{"Cancel"}</Button>
                            <Button variant="primary" loading={*notif_prefs_saving} testid="notif-prefs-save" onclick={save_notif_prefs}>{"Save"}</Button>
                        </SpaceBetween>
                    </UiBox>
                }}>
                <SpaceBetween direction="vertical" size="s">
                    <UiBox color="text-status-inactive">
                        {"Disable an event type to hide its bucket and exclude it from the bell badge."}
                    </UiBox>
                    {pref_toggle("Newly assigned", "notif-pref-assigned", notif_prefs.assigned, |p, v| p.assigned = v)}
                    {pref_toggle("Overdue", "notif-pref-overdue", notif_prefs.overdue, |p, v| p.overdue = v)}
                    {pref_toggle("Mentions", "notif-pref-mentions", notif_prefs.mentions, |p, v| p.mentions = v)}
                    {pref_toggle("Approvals (pending)", "notif-pref-approvals", notif_prefs.approvals, |p, v| p.approvals = v)}
                    {pref_toggle("Decisions", "notif-pref-decisions", notif_prefs.decisions, |p, v| p.decisions = v)}
                    {pref_toggle("Drafts waiting on you", "notif-pref-assigned_drafts", notif_prefs.assigned_drafts, |p, v| p.assigned_drafts = v)}
                </SpaceBetween>
            </Modal>
        </>
    }
}
