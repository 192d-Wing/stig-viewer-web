//! Application shell: top navigation, viewer tabs, side navigation, split
//! panel, and the notification bell.

mod notifications;
#[cfg(test)]
mod reducer_tests;
mod views;

use std::collections::HashSet;
use std::rc::Rc;

use gloo_events::EventListener;
use wasm_bindgen::{JsCast, JsValue};
use yew::prelude::*;

use crate::auth::use_current_user;
use crate::autosave::{use_autosave, Autosave, SetEvent};
use crate::hooks::use_online;
use crate::model::{AssetInfo, ChecklistSet, Rule, RuleUpdate, ServerRule, Stig, StigTab};
use crate::ui::*;
use crate::util::{console_error, file_text, now_ms, spawn_local, url_param, window};
use crate::utils::parse_ckl::parse_ckl;
use crate::utils::parse_xccdf::parse_xccdf;
use notifications::{notif_prefs_modal, notifications_modal, use_notifications};
use views::{
    close_tab_modal, content, file_input_handler, my_checklists_modal, side_nav, split_panel,
    top_nav, view_url,
};

// ── Viewer tab state ────────────────────────────────────────────────────────

type DiffPair = (Option<String>, Option<String>);

#[derive(Clone, PartialEq, Default)]
struct TabsState {
    tabs: Vec<StigTab>,
    active_tab_id: Option<String>,
    diff_pair: Option<DiffPair>,
    /// Checklist sets the open tabs belong to.
    sets: Vec<ChecklistSet>,
}

enum TabsAction {
    /// Add tabs and focus the first new one.
    Add(Vec<(Option<String>, Stig)>),
    /// Close a tab and move focus to the nearest remaining tab.
    Remove(String),
    SetActive(String),
    UpdateRule {
        tab_id: String,
        rule_id: String,
        update: RuleUpdate,
    },
    SetAssetInfo(String, AssetInfo),
    SetSelectedRule(String, Option<String>),
    SetAllStatus(String, String),
    /// (tab id, rule ids, status)
    SetStatusFor(String, Vec<String>, String),
    SetDiffPair(Option<DiffPair>),
    /// The first edit of a catalog tab created its set.
    SetCreated {
        tab_id: String,
        set: ChecklistSet,
    },
    SetSaved {
        set_id: String,
        revision: i64,
    },
    /// Open a set's STIGs as tabs (a tab already open for a STIG is only focused).
    OpenSet {
        set: ChecklistSet,
        stigs: Vec<(String, Stig)>,
    },
    SetRenamed {
        set_id: String,
        name: String,
    },
    SetLinked {
        set_id: String,
        asset: Option<(String, String)>,
    },
    SetDeleted(String),
    /// Server state for a set; rules in `keep` (tab id, rule id) stay as the user has them.
    ReplaceFromServer {
        set_id: String,
        revision: i64,
        stigs: Vec<(String, Vec<ServerRule>)>,
        keep: HashSet<(String, String)>,
    },
}

fn generate_tab_id() -> String {
    let rand = js_sys::Math::random().to_string();
    let suffix: String = rand.chars().skip(2).take(5).collect();
    format!("tab-{}-{suffix}", now_ms() as u64)
}

impl TabsState {
    fn tab_mut(&mut self, id: &str) -> Option<&mut StigTab> {
        self.tabs.iter_mut().find(|t| t.id == id)
    }

    fn set_mut(&mut self, id: &str) -> Option<&mut ChecklistSet> {
        self.sets.iter_mut().find(|x| x.id == id)
    }

    fn add_tabs(&mut self, stigs: Vec<(Option<String>, Stig)>) {
        let new_tabs: Vec<StigTab> = stigs
            .into_iter()
            .map(|(catalog_id, stig)| StigTab {
                catalog_id,
                id: generate_tab_id(),
                stig: Rc::new(stig),
                asset_info: AssetInfo::default(),
                selected_rule_id: None,
                set_id: None,
            })
            .collect();
        if let Some(first) = new_tabs.first() {
            self.active_tab_id = Some(first.id.clone());
        }
        self.tabs.extend(new_tabs);
    }

    fn remove_tab(&mut self, id: &str) {
        let closed_idx = self.tabs.iter().position(|t| t.id == id);
        self.tabs.retain(|t| t.id != id);
        if self.active_tab_id.as_deref() == Some(id) {
            self.active_tab_id = match closed_idx {
                Some(i) if !self.tabs.is_empty() => {
                    Some(self.tabs[i.min(self.tabs.len() - 1)].id.clone())
                }
                _ => None,
            };
        }
        if let Some((a, b)) = &self.diff_pair {
            if a.as_deref() == Some(id) || b.as_deref() == Some(id) {
                self.diff_pair = None;
            }
        }
    }

    fn update_rule(&mut self, tab_id: &str, rule_id: &str, update: RuleUpdate) {
        if let Some(t) = self.tab_mut(tab_id) {
            let stig = Rc::make_mut(&mut t.stig);
            if let Some(r) = stig.rules.iter_mut().find(|r| r.id == rule_id) {
                update.apply(r);
            }
        }
    }

    fn set_all_status(&mut self, tab_id: &str, status: &str) {
        if let Some(t) = self.tab_mut(tab_id) {
            for r in Rc::make_mut(&mut t.stig).rules.iter_mut() {
                r.status = status.to_string();
            }
        }
    }

    fn set_created(&mut self, tab_id: &str, set: ChecklistSet) {
        if let Some(t) = self.tab_mut(tab_id) {
            t.set_id = Some(set.id.clone());
        }
        if !self.sets.iter().any(|x| x.id == set.id) {
            self.sets.push(set);
        }
    }

    fn open_set(&mut self, set: ChecklistSet, stigs: Vec<(String, Stig)>) {
        let mut first = None;
        for (catalog_id, stig) in stigs {
            let open = self.tabs.iter().find(|t| {
                t.set_id.as_deref() == Some(set.id.as_str())
                    && t.catalog_id.as_deref() == Some(catalog_id.as_str())
            });
            if let Some(t) = open {
                first.get_or_insert_with(|| t.id.clone());
                continue;
            }
            let tab = StigTab {
                id: generate_tab_id(),
                stig: Rc::new(stig),
                asset_info: AssetInfo::default(),
                selected_rule_id: None,
                catalog_id: Some(catalog_id),
                set_id: Some(set.id.clone()),
            };
            first.get_or_insert_with(|| tab.id.clone());
            self.tabs.push(tab);
        }
        match self.set_mut(&set.id) {
            Some(x) => {
                x.name = set.name;
                x.asset = set.asset;
            }
            None => self.sets.push(set),
        }
        if first.is_some() {
            self.active_tab_id = first;
        }
    }

    fn set_deleted(&mut self, set_id: &str) {
        let gone: Vec<String> = self
            .tabs
            .iter()
            .filter(|t| t.set_id.as_deref() == Some(set_id))
            .map(|t| t.id.clone())
            .collect();
        self.tabs.retain(|t| !gone.contains(&t.id));
        self.sets.retain(|x| x.id != set_id);
        if self
            .active_tab_id
            .as_ref()
            .is_some_and(|a| gone.contains(a))
        {
            self.active_tab_id = self.tabs.last().map(|t| t.id.clone());
        }
        if self.diff_pair.as_ref().is_some_and(|(a, b)| {
            [a, b]
                .iter()
                .any(|x| x.as_ref().is_some_and(|x| gone.contains(x)))
        }) {
            self.diff_pair = None;
        }
    }

    fn replace_from_server(
        &mut self,
        set_id: &str,
        revision: i64,
        stigs: &[(String, Vec<ServerRule>)],
        keep: &HashSet<(String, String)>,
    ) {
        for t in self
            .tabs
            .iter_mut()
            .filter(|t| t.set_id.as_deref() == Some(set_id))
        {
            let Some((_, rules)) = stigs
                .iter()
                .find(|(id, _)| Some(id) == t.catalog_id.as_ref())
            else {
                continue;
            };
            let keep_ids: HashSet<String> = keep
                .iter()
                .filter(|(tab, _)| *tab == t.id)
                .map(|(_, rule)| rule.clone())
                .collect();
            Rc::make_mut(&mut t.stig).overlay_server_state(rules, &keep_ids);
        }
        if let Some(x) = self.set_mut(set_id) {
            x.revision = revision;
        }
    }
}

impl Reducible for TabsState {
    type Action = TabsAction;

    fn reduce(self: Rc<Self>, action: TabsAction) -> Rc<Self> {
        let mut s = (*self).clone();
        match action {
            TabsAction::Add(stigs) => s.add_tabs(stigs),
            TabsAction::Remove(id) => s.remove_tab(&id),
            TabsAction::SetActive(id) => s.active_tab_id = Some(id),
            TabsAction::UpdateRule {
                tab_id,
                rule_id,
                update,
            } => s.update_rule(&tab_id, &rule_id, update),
            TabsAction::SetAssetInfo(tab_id, info) => {
                if let Some(t) = s.tab_mut(&tab_id) {
                    t.asset_info = info;
                }
            }
            TabsAction::SetSelectedRule(tab_id, rule_id) => {
                if let Some(t) = s.tab_mut(&tab_id) {
                    t.selected_rule_id = rule_id;
                }
            }
            TabsAction::SetAllStatus(tab_id, status) => s.set_all_status(&tab_id, &status),
            TabsAction::SetStatusFor(tab_id, rule_ids, status) => {
                if let Some(t) = s.tab_mut(&tab_id) {
                    Rc::make_mut(&mut t.stig).set_status_for(&rule_ids, &status);
                }
            }
            TabsAction::SetDiffPair(pair) => s.diff_pair = pair,
            TabsAction::SetCreated { tab_id, set } => s.set_created(&tab_id, set),
            TabsAction::SetSaved { set_id, revision } => {
                if let Some(x) = s.set_mut(&set_id) {
                    x.revision = revision;
                }
            }
            TabsAction::OpenSet { set, stigs } => s.open_set(set, stigs),
            TabsAction::SetRenamed { set_id, name } => {
                if let Some(x) = s.set_mut(&set_id) {
                    x.name = name;
                }
            }
            TabsAction::SetLinked { set_id, asset } => {
                if let Some(x) = s.set_mut(&set_id) {
                    x.asset = asset;
                }
            }
            TabsAction::SetDeleted(set_id) => s.set_deleted(&set_id),
            TabsAction::ReplaceFromServer {
                set_id,
                revision,
                stigs,
                keep,
            } => s.replace_from_server(&set_id, revision, &stigs, &keep),
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
                Ok(stig) => stigs.push((None, stig)),
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

const VIEWS: [&str; 7] = [
    "viewer",
    "writer",
    "systems",
    "groups",
    "dashboard",
    "myfindings",
    "admin",
];

fn view_from_url() -> &'static str {
    let v = url_param("view").unwrap_or_default();
    VIEWS.iter().copied().find(|k| *k == v).unwrap_or("viewer")
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

fn set_event_action(e: SetEvent) -> TabsAction {
    match e {
        SetEvent::Created { tab_id, set } => TabsAction::SetCreated { tab_id, set },
        SetEvent::Saved { set_id, revision } => TabsAction::SetSaved { set_id, revision },
        SetEvent::Replace {
            set_id,
            revision,
            stigs,
            keep,
        } => TabsAction::ReplaceFromServer {
            set_id,
            revision,
            stigs,
            keep,
        },
    }
}

/// Top-level "view" is encoded in `?view=` so the URL is shareable. On
/// initial load we honour the param; `navigate_to` pushes a new history
/// entry and clears stale page-specific params from the previous view.
#[hook]
fn use_view_route() -> (&'static str, Callback<&'static str>) {
    let app_mode = use_state(view_from_url);
    let navigate_to = {
        let app_mode = app_mode.clone();
        Callback::from(move |mode: &'static str| {
            app_mode.set(mode);
            let path = window().location().pathname().unwrap_or_default();
            let url = view_url(&path, mode);
            if let Ok(h) = window().history() {
                let _ = h.push_state_with_url(&JsValue::NULL, "", Some(&url));
            }
        })
    };
    {
        // Pick up browser back/forward.
        let app_mode = app_mode.clone();
        use_effect_with((), move |_| {
            let l = EventListener::new(&window(), "popstate", move |_| {
                app_mode.set(view_from_url())
            });
            move || drop(l)
        });
    }
    (*app_mode, navigate_to)
}

/// Everything the view functions in `views` read: the tab state plus the
/// shell's own UI state handles.
#[derive(Clone)]
struct Shell {
    state: UseReducerHandle<TabsState>,
    autosave: Autosave,
    autosave_enabled: bool,
    mode: &'static str,
    navigate_to: Callback<&'static str>,
    show_library: UseStateHandle<bool>,
    show_my_checklists: UseStateHandle<bool>,
    nav_open: UseStateHandle<bool>,
    split_panel_open: UseStateHandle<bool>,
    open_note: UseStateHandle<Option<String>>,
    closing_tab_id: UseStateHandle<Option<String>>,
    writer_draft_id: UseStateHandle<Option<String>>,
    on_add_files: Callback<Vec<web_sys::File>>,
}

impl Shell {
    fn dispatch(&self) -> UseReducerDispatcher<TabsState> {
        self.state.dispatcher()
    }

    fn is_library_mode(&self) -> bool {
        self.mode == "viewer"
    }

    fn has_tabs(&self) -> bool {
        !self.state.tabs.is_empty()
    }

    fn is_diff_mode(&self) -> bool {
        self.state.diff_pair.is_some()
    }

    fn active_tab(&self) -> Option<&StigTab> {
        self.state
            .tabs
            .iter()
            .find(|t| Some(&t.id) == self.state.active_tab_id.as_ref())
    }

    fn active_set(&self) -> Option<ChecklistSet> {
        self.active_tab()
            .and_then(|t| t.set_id.as_ref())
            .and_then(|id| self.state.sets.iter().find(|s| &s.id == id))
            .cloned()
    }

    fn selected_rule(&self) -> Option<Rule> {
        self.active_tab().and_then(|t| {
            t.stig
                .rules
                .iter()
                .find(|r| Some(&r.id) == t.selected_rule_id.as_ref())
                .cloned()
        })
    }

    fn navigation_hide(&self) -> bool {
        !self.is_library_mode() || !self.has_tabs() || self.is_diff_mode()
    }

    /// The selected rule and its tab, when the split panel is showing.
    fn split_panel_target(&self) -> Option<(Rule, String)> {
        match (self.selected_rule(), self.active_tab()) {
            (Some(rule), Some(tab))
                if !self.is_diff_mode()
                    && self.is_library_mode()
                    && !*self.show_library
                    && *self.split_panel_open =>
            {
                Some((rule, tab.id.clone()))
            }
            _ => None,
        }
    }
}

#[function_component]
pub fn App() -> Html {
    let current_user = use_current_user();
    let online = use_online();
    let tabs_state = use_reducer(TabsState::default);
    let dispatch = tabs_state.dispatcher();
    let autosave_enabled = current_user.as_ref().is_some_and(|u| u.role != "viewer");
    let autosave = use_autosave({
        let dispatch = dispatch.clone();
        Callback::from(move |e: SetEvent| dispatch.dispatch(set_event_action(e)))
    });
    let show_my_checklists = use_state(|| false);
    let open_note = use_state(|| None::<String>);
    let (mode, navigate_to) = use_view_route();
    let nav_open = use_state(|| true);
    let split_panel_open = use_state(|| true);
    let show_library = use_state(|| false);
    let closing_tab_id = use_state(|| None::<String>);
    let writer_draft_id = use_state(|| None::<String>);
    let file_input = use_node_ref();
    let notifications = use_notifications(current_user.as_ref().map(|u| u.id.clone()));

    let on_add_files = {
        let dispatch = dispatch.clone();
        Callback::from(move |files: Vec<web_sys::File>| add_files(dispatch.clone(), files))
    };
    let sh = Shell {
        state: tabs_state,
        autosave,
        autosave_enabled,
        mode,
        navigate_to,
        show_library,
        show_my_checklists,
        nav_open,
        split_panel_open,
        open_note,
        closing_tab_id,
        writer_draft_id,
        on_add_files,
    };
    sh.autosave
        .sync(&sh.state.tabs, &sh.state.sets, autosave_enabled);

    {
        // Selecting a rule re-opens a split panel the user had closed.
        let split_panel_open = sh.split_panel_open.clone();
        let key = sh.active_tab().and_then(|t| t.selected_rule_id.clone());
        use_effect_with(key, move |k| {
            if k.is_some() {
                split_panel_open.set(true);
            }
        });
    }

    let navigation_hide = sh.navigation_hide();
    let navigation_open = *sh.nav_open && !navigation_hide;
    let split_target = sh.split_panel_target();

    html! {
        <>
            {top_nav(&sh, current_user.as_ref(), &notifications, &file_input)}

            // Hidden file input for the Open File utility
            <input ref={file_input} type="file" accept=".xml,.ckl" multiple=true style="display:none"
                   aria-hidden="true" tabindex="-1" onchange={file_input_handler(sh.on_add_files.clone())} />

            <div class={classes!("ui-app-layout", navigation_open.then_some("ui-app-nav-open"), split_target.is_some().then_some("ui-app-split-open"))}>
                if !navigation_hide {
                    {side_nav(&sh, navigation_open)}
                }
                <div class="ui-app-main">
                    if let Some(n) = &*sh.open_note {
                        <Alert kind="warning" dismissible=true on_dismiss={{ let note = sh.open_note.clone(); move |_| note.set(None) }}>{n.clone()}</Alert>
                    }
                    if !online {
                        <Flash kind="warning" header="Offline">
                            {"No network connection. Cached STIGs remain viewable; uploads and saves will resume when the connection returns."}
                        </Flash>
                    }
                    <main class="ui-app-content">{content(&sh)}</main>
                </div>
                if let Some((rule, tab_id)) = split_target {
                    {split_panel(&sh, &rule, &tab_id)}
                }
            </div>

            if autosave_enabled {
                {my_checklists_modal(&sh)}
            }
            {close_tab_modal(&sh)}
            {notifications_modal(&notifications, &sh.writer_draft_id, &sh.navigate_to)}
            {notif_prefs_modal(&notifications)}
        </>
    }
}
