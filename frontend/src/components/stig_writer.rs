//! STIG Writer: the drafts list, the draft editor and the review workflow.

use std::cell::RefCell;
use std::rc::Rc;

use gloo_timers::callback::Timeout;
use serde::Deserialize;
use serde_json::{json, Value};
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::api::{api_get, api_json};
use crate::model::{Rule, Stig};
use crate::ui::*;
use crate::util::{
    copy_to_clipboard, download_text, encode_uri_component, file_text, spawn_local, to_locale_date_string,
    to_locale_string,
};
use crate::utils::export_xccdf::export_xccdf;
use crate::utils::parse_ckl::parse_ckl;
use crate::utils::parse_xccdf::parse_xccdf;

const SEVERITIES: [(&str, &str); 3] =
    [("CAT I", "CAT I (High)"), ("CAT II", "CAT II (Medium)"), ("CAT III", "CAT III (Low)")];

fn severity_badge_color(severity: &str) -> &'static str {
    match severity {
        "CAT I" => "red",
        "CAT II" => "blue",
        _ => "grey",
    }
}

/// Badge (colour, label) for a draft workflow status.
fn status_badge(status: &str) -> (&'static str, &'static str) {
    match status {
        "submitted" => ("blue", "Submitted"),
        "in_review" => ("blue", "In Review"),
        "approved" => ("green", "Approved"),
        "rejected" => ("red", "Rejected"),
        _ => ("grey", "Draft"),
    }
}

fn draft_path(id: &str) -> String {
    format!("/api/drafts/{}", encode_uri_component(id))
}

fn or_untitled(title: &str, fallback: &'static str) -> String {
    if title.is_empty() { fallback.to_string() } else { title.to_string() }
}

// ── API payloads ─────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DraftSummary {
    id: String,
    title: String,
    author_name: String,
    status: String,
    version: String,
    updated_at: String,
    assigned_reviewer_id: Option<String>,
    assigned_reviewer_name: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct CreatedDraft {
    id: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DraftDetail {
    title: String,
    status: String,
    version: String,
    release_info: String,
    description: String,
    rules: Option<Vec<Rule>>,
}

/// The editable draft metadata (rules are tracked separately).
#[derive(Clone, PartialEq, Default)]
struct Draft {
    title: String,
    status: String,
    version: String,
    release_info: String,
    description: String,
}

impl Draft {
    fn is_editable(&self) -> bool {
        self.status == "draft" || self.status == "rejected"
    }
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DraftComment {
    id: String,
    user_name: String,
    user_role: String,
    body: String,
    action: Option<String>,
    created_at: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NextVulnId {
    vuln_id: String,
    rule_id: String,
    group_id: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct TransitionResult {
    status: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct UserSummary {
    id: String,
    display_name: String,
    role: String,
}

// ── Drafts Table (landing page) ──────────────────────────────────────────────

#[derive(Properties, PartialEq)]
struct DraftsTableProps {
    on_open_draft: Callback<String>,
}

#[function_component]
fn DraftsTable(props: &DraftsTableProps) -> Html {
    let drafts = use_state(Vec::<DraftSummary>::new);
    let loading = use_state(|| true);
    let creating = use_state(|| false);

    // Errors are not surfaced on this page (the list simply stays as it was).
    let fetch_drafts = {
        let (drafts, loading) = (drafts.setter(), loading.setter());
        Callback::from(move |_: ()| {
            let (drafts, loading) = (drafts.clone(), loading.clone());
            loading.set(true);
            spawn_local(async move {
                if let Ok(data) = api_get::<Vec<DraftSummary>>("/api/drafts").await {
                    drafts.set(data);
                }
                loading.set(false);
            });
        })
    };

    {
        let fetch_drafts = fetch_drafts.clone();
        use_effect_with((), move |_| fetch_drafts.emit(()));
    }

    let handle_create = {
        let creating = creating.setter();
        let on_open_draft = props.on_open_draft.clone();
        Callback::from(move |_: MouseEvent| {
            let (creating, on_open_draft) = (creating.clone(), on_open_draft.clone());
            creating.set(true);
            spawn_local(async move {
                let created = api_json::<CreatedDraft, ()>("/api/drafts", "POST", None).await;
                creating.set(false);
                if let Ok(draft) = created {
                    on_open_draft.emit(draft.id);
                }
            });
        })
    };

    let actions_cell = {
        let on_open_draft = props.on_open_draft.clone();
        let fetch_drafts = fetch_drafts.clone();
        move |item: &DraftSummary| {
            let open = {
                let (on_open_draft, id) = (on_open_draft.clone(), item.id.clone());
                Callback::from(move |_: MouseEvent| on_open_draft.emit(id.clone()))
            };
            let delete = {
                let (fetch_drafts, id) = (fetch_drafts.clone(), item.id.clone());
                Callback::from(move |_: MouseEvent| {
                    let (fetch_drafts, path) = (fetch_drafts.clone(), draft_path(&id));
                    spawn_local(async move {
                        if api_json::<Value, ()>(&path, "DELETE", None).await.is_ok() {
                            fetch_drafts.emit(());
                        }
                    });
                })
            };
            html! {
                <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="inline-link" onclick={open}>{"Open"}</Button>
                    if item.status == "draft" || item.status == "rejected" {
                        <Button variant="inline-link" onclick={delete}>{"Delete"}</Button>
                    }
                </SpaceBetween>
            }
        }
    };

    let columns = vec![
        Column::new("title", "Title", |d: &DraftSummary| html! { {or_untitled(&d.title, "(untitled)")} }),
        Column::new("status", "Status", |d: &DraftSummary| {
            let (color, label) = status_badge(&d.status);
            html! { <Badge {color}>{label}</Badge> }
        })
        .width("130px"),
        Column::new("author", "Author", |d: &DraftSummary| html! { {d.author_name.clone()} }).width("160px"),
        Column::new("assignedReviewer", "Reviewer", |d: &DraftSummary| {
            if d.assigned_reviewer_id.as_deref().is_some_and(|id| !id.is_empty()) {
                let name = d.assigned_reviewer_name.clone().filter(|n| !n.is_empty());
                html! { <Badge color="blue">{"Assigned to "}{name.unwrap_or_else(|| "reviewer".into())}</Badge> }
            } else {
                html! { <Badge color="grey">{"Open for review"}</Badge> }
            }
        })
        .width("220px"),
        Column::new("version", "Version", |d: &DraftSummary| {
            html! { {if d.version.is_empty() { "—".to_string() } else { d.version.clone() }} }
        })
        .width("100px"),
        Column::new("updatedAt", "Last Updated", |d: &DraftSummary| html! { {to_locale_date_string(&d.updated_at)} })
            .width("150px"),
        Column::new("actions", "Actions", actions_cell).width("160px"),
    ];

    html! {
        <Table<DraftSummary>
            variant="full-page"
            sticky_header=true
            striped_rows=true
            loading={*loading}
            loading_text="Loading drafts"
            items={(*drafts).clone()}
            {columns}
            track_by={Callback::from(|d: DraftSummary| d.id)}
            header={html! {
                <Header
                    variant="awsui-h1-sticky"
                    counter={format!("({})", drafts.len())}
                    actions={html! {
                        <Button variant="primary" loading={*creating} onclick={handle_create.clone()}>{"New Draft"}</Button>
                    }}
                    description={html! { {"Author new STIGs or modify existing ones for submission to DISA"} }}
                >
                    {"STIG Writer"}
                </Header>
            }}
            empty={html! {
                <UiBox text_align="center" padding_vertical="l">
                    <SpaceBetween size="xs">
                        <b>{"No drafts yet"}</b>
                        <Button onclick={handle_create.clone()} loading={*creating}>{"Create your first draft"}</Button>
                    </SpaceBetween>
                </UiBox>
            }}
        />
    }
}

// ── Draft Editor ─────────────────────────────────────────────────────────────

/// Mutable editor document. Kept behind a `RefCell` (not `use_state`) so that
/// async work and the debounced save always see the latest edits.
#[derive(Default)]
struct EditorData {
    draft: Option<Draft>,
    rules: Vec<Rule>,
    /// Working copy of the rule open in the editor modal.
    editing: Option<Rule>,
}

impl EditorData {
    fn to_stig(&self) -> Option<Stig> {
        let draft = self.draft.as_ref()?;
        Some(Stig {
            title: draft.title.clone(),
            description: draft.description.clone(),
            version: draft.version.clone(),
            release_info: draft.release_info.clone(),
            rules: self.rules.clone(),
        })
    }
}

/// The PUT body for the current document, or `None` for drafts that are out
/// of the author's hands (submitted / in review / approved), which are never
/// written.
fn save_body(data: &Rc<RefCell<EditorData>>) -> Option<Value> {
    let data = data.borrow();
    let draft = data.draft.as_ref()?;
    if matches!(draft.status.as_str(), "approved" | "submitted" | "in_review") {
        return None;
    }
    Some(json!({
        "title": draft.title,
        "description": draft.description,
        "version": draft.version,
        "releaseInfo": draft.release_info,
        "rules": data.rules,
    }))
}

/// PUT the current document, then run `then` (whether or not it succeeded).
fn save_draft_then(
    draft_id: &str,
    data: &Rc<RefCell<EditorData>>,
    saving: &UseStateSetter<bool>,
    then: impl FnOnce() + 'static,
) {
    let Some(body) = save_body(data) else {
        then();
        return;
    };
    let path = draft_path(draft_id);
    let saving = saving.clone();
    saving.set(true);
    spawn_local(async move {
        // Silent save failure — user can retry manually
        let _ = api_json::<Value, _>(&path, "PUT", Some(&body)).await;
        saving.set(false);
        then();
    });
}

fn save_draft(draft_id: &str, data: &Rc<RefCell<EditorData>>, saving: &UseStateSetter<bool>) {
    save_draft_then(draft_id, data, saving, || {});
}

/// Handle on the editor document plus its debounced-save machinery.
#[derive(Clone)]
struct Editor {
    draft_id: Rc<str>,
    data: Rc<RefCell<EditorData>>,
    timer: Rc<RefCell<Option<Timeout>>>,
    /// True while an edit is waiting on the debounce timer.
    dirty: Rc<RefCell<bool>>,
    saving: UseStateSetter<bool>,
    redraw: UseForceUpdateHandle,
}

impl Editor {
    /// Save 1.5s after the last edit.
    fn schedule_save(&self) {
        *self.dirty.borrow_mut() = true;
        let (draft_id, data, dirty, saving) =
            (self.draft_id.clone(), self.data.clone(), self.dirty.clone(), self.saving.clone());
        let timer = Timeout::new(1500, move || {
            *dirty.borrow_mut() = false;
            save_draft(&draft_id, &data, &saving);
        });
        // Replacing the previous Timeout cancels it.
        *self.timer.borrow_mut() = Some(timer);
    }

    /// Flush a pending save immediately.
    fn flush_save(&self) {
        self.timer.borrow_mut().take();
        if self.dirty.replace(false) {
            save_draft(&self.draft_id, &self.data, &self.saving);
        }
    }

    /// Flush a pending save and run `then` once it has reached the server
    /// (immediately when nothing is pending). Leaving the editor goes through
    /// this so the drafts list is not fetched while the last edit is in flight.
    fn flush_save_then(&self, then: impl FnOnce() + 'static) {
        self.timer.borrow_mut().take();
        if self.dirty.replace(false) {
            save_draft_then(&self.draft_id, &self.data, &self.saving, then);
        } else {
            then();
        }
    }

    /// Apply an edit, queue a save and re-render.
    fn mutate(&self, f: impl FnOnce(&mut EditorData)) {
        f(&mut self.data.borrow_mut());
        self.schedule_save();
        self.redraw.force_update();
    }

    /// Apply a change that must not trigger a save (loads, status changes).
    fn set(&self, f: impl FnOnce(&mut EditorData)) {
        f(&mut self.data.borrow_mut());
        self.redraw.force_update();
    }

    /// `on_change` for a draft metadata field.
    fn draft_field(&self, apply: fn(&mut Draft, String)) -> Callback<String> {
        let ed = self.clone();
        Callback::from(move |v: String| {
            ed.mutate(|d| {
                if let Some(draft) = d.draft.as_mut() {
                    apply(draft, v);
                }
            })
        })
    }

    /// `on_change` for a field of the rule open in the editor modal: updates
    /// both the stored rule and the modal's working copy.
    fn rule_field(&self, apply: fn(&mut Rule, String)) -> Callback<String> {
        let ed = self.clone();
        Callback::from(move |v: String| {
            ed.mutate(|d| {
                let Some(editing) = d.editing.as_mut() else { return };
                let id = editing.id.clone();
                for rule in d.rules.iter_mut().filter(|r| r.id == id) {
                    apply(rule, v.clone());
                }
                apply(editing, v);
            })
        })
    }
}

/// `releaseInfo.match(/Release:\s*(\d+)/i)`
fn parse_release_num(info: &str) -> Option<String> {
    const KEY: &str = "release:";
    let lower = info.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find(KEY) {
        let after = from + pos + KEY.len();
        let digits: String = info[after..].trim_start().chars().take_while(char::is_ascii_digit).collect();
        if !digits.is_empty() {
            return Some(digits);
        }
        from = after;
    }
    None
}

/// `releaseInfo.match(/Benchmark Date:\s*(.+)/i)`
fn parse_benchmark_date(info: &str) -> Option<String> {
    const KEY: &str = "benchmark date:";
    let is_newline = |c: char| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}');
    let lower = info.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find(KEY) {
        let after = from + pos + KEY.len();
        let rest = &info[after..];
        let trimmed = rest.trim_start();
        let line: String = trimmed.chars().take_while(|c| !is_newline(*c)).collect();
        if !line.is_empty() {
            return Some(line);
        }
        // Only whitespace follows: the regex backtracks so that `.+` takes the
        // last non-newline whitespace character.
        let skipped = &rest[..rest.len() - trimmed.len()];
        if let Some(c) = skipped.chars().rev().find(|c| !is_newline(*c)) {
            return Some(c.to_string());
        }
        from = after;
    }
    None
}

fn join_release_info(release: &str, date: &str) -> String {
    let mut parts = Vec::new();
    if !release.is_empty() {
        parts.push(format!("Release: {release}"));
    }
    if !date.is_empty() {
        parts.push(format!("Benchmark Date: {date}"));
    }
    parts.join(" ")
}

async fn load_comments(draft_id: Rc<str>, comments: UseStateSetter<Vec<DraftComment>>) {
    // Silently fail for comments
    if let Ok(data) = api_get::<Vec<DraftComment>>(&format!("{}/comments", draft_path(&draft_id))).await {
        comments.set(data);
    }
}

/// Everything a workflow transition touches.
#[derive(Clone)]
struct Workflow {
    ed: Editor,
    error: UseStateSetter<Option<String>>,
    success: UseStateSetter<Option<String>>,
    comments: UseStateSetter<Vec<DraftComment>>,
}

impl Workflow {
    /// POST `/api/drafts/{id}/{action}` and adopt the resulting status.
    async fn transition(&self, action: &str, body: Option<Value>) {
        self.error.set(None);
        self.success.set(None);
        let path = format!("{}/{action}", draft_path(&self.ed.draft_id));
        match api_json::<TransitionResult, Value>(&path, "POST", body.as_ref()).await {
            Ok(result) => {
                self.success.set(Some(format!("Draft {}", result.status.replacen('_', " ", 1))));
                self.ed.set(|d| {
                    if let Some(draft) = d.draft.as_mut() {
                        draft.status = result.status;
                    }
                });
                load_comments(self.ed.draft_id.clone(), self.comments.clone()).await;
            }
            Err(e) => self.error.set(Some(e)),
        }
    }

    /// Click handler that runs a body-less transition.
    fn action(&self, action: &'static str) -> Callback<MouseEvent> {
        let wf = self.clone();
        Callback::from(move |_: MouseEvent| {
            let wf = wf.clone();
            spawn_local(async move { wf.transition(action, None).await });
        })
    }
}

const PREVIEW_STYLE: &str = "font-size:12px;line-height:1.6;color:#8d99a8;background:#0f1b2e80;\
    border:1px solid #354150;border-radius:6px;padding:16px;white-space:pre-wrap;word-break:break-word;\
    font-family:'JetBrains Mono', monospace;margin:0;max-height:70vh;overflow:auto;";

#[derive(Properties, PartialEq)]
struct DraftEditorProps {
    draft_id: String,
    on_back: Callback<()>,
}

#[function_component]
fn DraftEditor(props: &DraftEditorProps) -> Html {
    let data = use_mut_ref(EditorData::default);
    let timer = use_mut_ref(|| None::<Timeout>);
    let dirty = use_mut_ref(|| false);
    let redraw = use_force_update();
    let loading = use_state(|| true);
    let saving = use_state(|| false);
    let error = use_state(|| None::<String>);
    let success = use_state(|| None::<String>);
    let import_error = use_state(|| None::<String>);
    let selected_rules = use_state(Vec::<String>::new);
    let active_tab_id = use_state(|| AttrValue::from("metadata"));
    let comments = use_state(Vec::<DraftComment>::new);
    let new_comment = use_state(String::new);
    let file_input_ref = use_node_ref();

    // Submit-with-reviewer modal state. Reviewer options are fetched lazily
    // each time the modal opens to avoid an extra API call on every draft view.
    let show_submit_modal = use_state(|| false);
    let reviewer_options = use_state(Vec::<SelectOption>::new);
    let selected_reviewer = use_state(|| None::<SelectOption>);

    let show_approve_modal = use_state(|| false);
    let show_reject_modal = use_state(|| false);
    let action_comment = use_state(String::new);

    let ed = Editor {
        draft_id: Rc::from(props.draft_id.as_str()),
        data,
        timer,
        dirty,
        saving: saving.setter(),
        redraw,
    };
    let workflow =
        Workflow { ed: ed.clone(), error: error.setter(), success: success.setter(), comments: comments.setter() };

    // Load the draft and its comments; flush any pending save on unmount.
    {
        let ed = ed.clone();
        let (loading, error, comments) = (loading.setter(), error.setter(), comments.setter());
        use_effect_with((), move |_| {
            {
                let ed = ed.clone();
                spawn_local(async move {
                    match api_get::<DraftDetail>(&draft_path(&ed.draft_id)).await {
                        Ok(detail) => ed.set(|d| {
                            d.draft = Some(Draft {
                                title: detail.title,
                                status: detail.status,
                                version: detail.version,
                                release_info: detail.release_info,
                                description: detail.description,
                            });
                            d.rules = detail.rules.unwrap_or_default();
                        }),
                        Err(e) => error.set(Some(e)),
                    }
                    loading.set(false);
                });
            }
            spawn_local(load_comments(ed.draft_id.clone(), comments));
            move || ed.flush_save()
        });
    }

    let back = {
        let on_back = props.on_back.clone();
        let ed = ed.clone();
        Callback::from(move |_: MouseEvent| {
            let on_back = on_back.clone();
            ed.flush_save_then(move || on_back.emit(()));
        })
    };
    let back_button = html! { <Button variant="link" icon_name="arrow-left" onclick={back}>{"Back to Drafts"}</Button> };

    if *loading {
        return html! {
            <SpaceBetween size="m">
                {back_button}
                <StatusIndicator kind="loading">{"Loading draft"}</StatusIndicator>
            </SpaceBetween>
        };
    }

    let Some(draft) = ed.data.borrow().draft.clone() else {
        return html! {
            <SpaceBetween size="m">
                {back_button}
                <Alert kind="error">{"Draft not found"}</Alert>
            </SpaceBetween>
        };
    };
    let rule_count = ed.data.borrow().rules.len();
    let editing_rule = ed.data.borrow().editing.clone();
    let is_editable = draft.is_editable();
    let active_tab = (*active_tab_id).clone();

    // ── Rules ────────────────────────────────────────────────────────────────

    let add_rule = {
        let (ed, error) = (ed.clone(), error.setter());
        Callback::from(move |_: MouseEvent| {
            let (ed, error) = (ed.clone(), error.clone());
            spawn_local(async move {
                let path = format!("{}/next-vuln-id", draft_path(&ed.draft_id));
                match api_json::<NextVulnId, ()>(&path, "POST", None).await {
                    Ok(next) => ed.mutate(|d| {
                        d.rules.push(Rule {
                            id: next.rule_id,
                            stig_id: next.vuln_id,
                            group_id: next.group_id,
                            severity: "CAT II".into(),
                            status: "not_reviewed".into(),
                            ..Rule::default()
                        })
                    }),
                    Err(e) => error.set(Some(format!("Failed to add rule: {e}"))),
                }
            });
        })
    };

    let delete_selected_rules = {
        let (ed, selected_rules) = (ed.clone(), selected_rules.clone());
        Callback::from(move |_: MouseEvent| {
            let ids = (*selected_rules).clone();
            ed.mutate(|d| {
                d.rules.retain(|r| !ids.contains(&r.id));
                if d.editing.as_ref().is_some_and(|r| ids.contains(&r.id)) {
                    d.editing = None;
                }
            });
            selected_rules.set(Vec::new());
        })
    };

    let close_rule_editor = {
        let ed = ed.clone();
        Callback::from(move |_: ()| ed.set(|d| d.editing = None))
    };

    // ── Import / export ──────────────────────────────────────────────────────

    let handle_import = {
        let ed = ed.clone();
        let (import_error, selected_rules, active_tab_id) =
            (import_error.setter(), selected_rules.setter(), active_tab_id.setter());
        Callback::from(move |e: Event| {
            let Some(input) = e.target_dyn_into::<HtmlInputElement>() else { return };
            let Some(file) = input.files().and_then(|files| files.get(0)) else { return };
            let ed = ed.clone();
            let (import_error, selected_rules, active_tab_id) =
                (import_error.clone(), selected_rules.clone(), active_tab_id.clone());
            import_error.set(None);
            spawn_local(async move {
                let parsed = match file_text(&file).await {
                    Ok(text) if file.name().ends_with(".ckl") => parse_ckl(&text),
                    Ok(text) => parse_xccdf(&text),
                    Err(e) => Err(e),
                };
                match parsed {
                    Ok(stig) => {
                        ed.mutate(|d| {
                            if let Some(draft) = d.draft.as_mut() {
                                draft.title = stig.title;
                                draft.description = stig.description;
                                draft.version = stig.version;
                                draft.release_info = stig.release_info;
                            }
                            d.rules = stig.rules;
                            d.editing = None;
                        });
                        selected_rules.set(Vec::new());
                        active_tab_id.set(AttrValue::from("metadata"));
                        // Force immediate save
                        ed.flush_save();
                    }
                    Err(e) => import_error.set(Some(e)),
                }
                input.set_value("");
            });
        })
    };

    let open_file_picker = {
        let file_input_ref = file_input_ref.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(input) = file_input_ref.cast::<HtmlInputElement>() {
                input.click();
            }
        })
    };

    let handle_export = {
        let ed = ed.clone();
        Callback::from(move |_: MouseEvent| {
            let Some(stig) = ed.data.borrow().to_stig() else { return };
            let base = if stig.title.is_empty() { "draft_stig" } else { stig.title.as_str() };
            // JS `/[^a-zA-Z0-9]/g` works on UTF-16 code units, hence one `_` per unit.
            let name: String = base
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c.to_string() } else { "_".repeat(c.len_utf16()) })
                .collect();
            download_text(&export_xccdf(&stig), "application/xml", &format!("{name}.xml"));
        })
    };

    let handle_copy_preview = {
        let ed = ed.clone();
        Callback::from(move |_: MouseEvent| {
            let Some(stig) = ed.data.borrow().to_stig() else { return };
            spawn_local(async move {
                copy_to_clipboard(&export_xccdf(&stig)).await;
            });
        })
    };

    // ── Workflow actions ─────────────────────────────────────────────────────

    let open_submit_modal = {
        let (show_submit_modal, reviewer_options, selected_reviewer) =
            (show_submit_modal.setter(), reviewer_options.setter(), selected_reviewer.setter());
        Callback::from(move |_: MouseEvent| {
            show_submit_modal.set(true);
            selected_reviewer.set(None);
            let reviewer_options = reviewer_options.clone();
            spawn_local(async move {
                let mut options = vec![SelectOption::new("", "Any reviewer")];
                if let Ok(users) = api_get::<Vec<UserSummary>>("/api/users").await {
                    options.extend(
                        users
                            .into_iter()
                            .filter(|u| u.role == "reviewer" || u.role == "admin")
                            .map(|u| SelectOption::new(u.id, u.display_name)),
                    );
                }
                reviewer_options.set(options);
            });
        })
    };

    let handle_submit = {
        let workflow = workflow.clone();
        let (show_submit_modal, selected_reviewer) = (show_submit_modal.setter(), selected_reviewer.clone());
        Callback::from(move |_: MouseEvent| {
            let body = (*selected_reviewer)
                .as_ref()
                .filter(|o| !o.value.is_empty())
                .map(|o| json!({ "assignedReviewerId": o.value.as_str() }));
            let workflow = workflow.clone();
            let (show_submit_modal, selected_reviewer) = (show_submit_modal.clone(), selected_reviewer.setter());
            spawn_local(async move {
                workflow.transition("submit", body).await;
                show_submit_modal.set(false);
                selected_reviewer.set(None);
            });
        })
    };

    let handle_approve = {
        let workflow = workflow.clone();
        let (show_approve_modal, action_comment) = (show_approve_modal.setter(), action_comment.clone());
        Callback::from(move |_: MouseEvent| {
            let body = if action_comment.is_empty() { json!({}) } else { json!({ "comment": *action_comment }) };
            let workflow = workflow.clone();
            spawn_local(async move { workflow.transition("approve", Some(body)).await });
            show_approve_modal.set(false);
            action_comment.set(String::new());
        })
    };

    let handle_reject = {
        let workflow = workflow.clone();
        let (show_reject_modal, action_comment) = (show_reject_modal.setter(), action_comment.clone());
        Callback::from(move |_: MouseEvent| {
            let comment = if action_comment.is_empty() { "Rejected".to_string() } else { (*action_comment).clone() };
            let workflow = workflow.clone();
            spawn_local(async move { workflow.transition("reject", Some(json!({ "comment": comment }))).await });
            show_reject_modal.set(false);
            action_comment.set(String::new());
        })
    };

    let handle_add_comment = {
        let draft_id = ed.draft_id.clone();
        let (new_comment, error, comments) = (new_comment.clone(), error.setter(), comments.setter());
        Callback::from(move |_: MouseEvent| {
            let body = new_comment.trim().to_string();
            if body.is_empty() {
                return;
            }
            let draft_id = draft_id.clone();
            let (new_comment, error, comments) = (new_comment.setter(), error.clone(), comments.clone());
            spawn_local(async move {
                let path = format!("{}/comments", draft_path(&draft_id));
                match api_json::<Value, _>(&path, "POST", Some(&json!({ "body": body }))).await {
                    Ok(_) => {
                        new_comment.set(String::new());
                        load_comments(draft_id, comments).await;
                    }
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    // Release info parsing
    let release_num = parse_release_num(&draft.release_info).unwrap_or_else(|| "1".to_string());
    let benchmark_date = parse_benchmark_date(&draft.release_info).unwrap_or_default();
    let on_release_num = {
        let (ed, date) = (ed.clone(), benchmark_date.clone());
        Callback::from(move |v: String| {
            ed.mutate(|d| {
                if let Some(draft) = d.draft.as_mut() {
                    draft.release_info = join_release_info(&v, &date);
                }
            })
        })
    };
    let on_benchmark_date = {
        let (ed, release) = (ed.clone(), release_num.clone());
        Callback::from(move |v: String| {
            ed.mutate(|d| {
                if let Some(draft) = d.draft.as_mut() {
                    draft.release_info = join_release_info(&release, &v);
                }
            })
        })
    };

    // Workflow action buttons
    let status = draft.status.as_str();
    let show = |handle: &UseStateHandle<bool>, visible: bool| {
        let handle = handle.setter();
        Callback::from(move |_: MouseEvent| handle.set(visible))
    };
    let dismiss = |handle: &UseStateHandle<bool>| {
        let handle = handle.setter();
        Callback::from(move |_: ()| handle.set(false))
    };
    let mut workflow_actions: Vec<Html> = Vec::new();
    if is_editable {
        workflow_actions.push(html! { <Button key="import" onclick={open_file_picker}>{"Import File"}</Button> });
    }
    match status {
        "draft" => workflow_actions.push(html! {
            <Button key="submit" variant="primary" onclick={open_submit_modal}>{"Submit for Review"}</Button>
        }),
        "submitted" => {
            workflow_actions
                .push(html! { <Button key="withdraw" onclick={workflow.action("revise")}>{"Withdraw"}</Button> });
            workflow_actions.push(html! {
                <Button key="review" variant="primary" onclick={workflow.action("review")}>{"Pick Up Review"}</Button>
            });
        }
        "in_review" => {
            workflow_actions.push(html! {
                <Button key="approve" variant="primary" onclick={show(&show_approve_modal, true)}>{"Approve"}</Button>
            });
            workflow_actions
                .push(html! { <Button key="reject" onclick={show(&show_reject_modal, true)}>{"Reject"}</Button> });
        }
        "rejected" => workflow_actions.push(html! {
            <Button key="revise" variant="primary" onclick={workflow.action("revise")}>{"Revise"}</Button>
        }),
        _ => {}
    }
    if !draft.title.is_empty() {
        workflow_actions.push(html! { <Button key="export" onclick={handle_export.clone()}>{"Export XCCDF"}</Button> });
    }

    let (status_color, status_label) = status_badge(status);

    // ── Tab contents (only the active tab is built) ──────────────────────────

    let metadata_tab = || {
        html! {
            <Container header={html! { <Header variant="h2">{"STIG Metadata"}</Header> }}>
                <SpaceBetween size="l">
                    <FormField label="Title" description="Name of the STIG">
                        <Input
                            value={draft.title.clone()}
                            on_change={ed.draft_field(|d, v| d.title = v)}
                            placeholder="e.g. My Application Security"
                            disabled={!is_editable}
                        />
                    </FormField>
                    <FormField label="Description">
                        <Textarea
                            value={draft.description.clone()}
                            on_change={ed.draft_field(|d, v| d.description = v)}
                            placeholder="Overview of what this STIG covers"
                            rows={4}
                            disabled={!is_editable}
                        />
                    </FormField>
                    <ColumnLayout columns={3}>
                        <FormField label="Version">
                            <Input
                                value={draft.version.clone()}
                                on_change={ed.draft_field(|d, v| d.version = v)}
                                placeholder="1"
                                disabled={!is_editable}
                            />
                        </FormField>
                        <FormField label="Release Number">
                            <Input
                                value={release_num.clone()}
                                on_change={on_release_num.clone()}
                                placeholder="1"
                                disabled={!is_editable}
                            />
                        </FormField>
                        <FormField label="Benchmark Date">
                            <Input
                                value={benchmark_date.clone()}
                                on_change={on_benchmark_date.clone()}
                                placeholder="e.g. 20 Feb 2026"
                                disabled={!is_editable}
                            />
                        </FormField>
                    </ColumnLayout>
                </SpaceBetween>
            </Container>
        }
    };

    let rule_editor_form = |rule: &Rule| {
        let severity =
            SEVERITIES.iter().map(|(value, _)| *value).find(|value| *value == rule.severity).unwrap_or("CAT II");
        let on_severity = {
            let set = ed.rule_field(|r, v| r.severity = v);
            Callback::from(move |o: SelectOption| set.emit(o.value.to_string()))
        };
        let on_cci_ids = ed.rule_field(|r, v| {
            r.cci_ids = v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
        });
        html! {
            <SpaceBetween size="l">
                <ColumnLayout columns={3}>
                    <FormField label="Vuln ID (stigId)">
                        <Input
                            value={rule.stig_id.clone()}
                            on_change={ed.rule_field(|r, v| r.stig_id = v)}
                            disabled={!is_editable}
                        />
                    </FormField>
                    <FormField label="Rule ID">
                        <Input
                            value={rule.id.clone()}
                            on_change={ed.rule_field(|r, v| r.id = v)}
                            disabled={!is_editable}
                        />
                    </FormField>
                    <FormField label="Group ID">
                        <Input
                            value={rule.group_id.clone()}
                            on_change={ed.rule_field(|r, v| r.group_id = v)}
                            disabled={!is_editable}
                        />
                    </FormField>
                </ColumnLayout>
                <ColumnLayout columns={2}>
                    <FormField label="Severity">
                        <Select
                            selected={AttrValue::from(severity)}
                            on_change={on_severity}
                            options={SEVERITIES.iter().map(|(v, l)| SelectOption::new(*v, *l)).collect::<Vec<_>>()}
                            disabled={!is_editable}
                        />
                    </FormField>
                    <FormField label="CCI IDs" description="Comma-separated">
                        <Input
                            value={rule.cci_ids.join(", ")}
                            on_change={on_cci_ids}
                            placeholder="CCI-000213, CCI-000366"
                            disabled={!is_editable}
                        />
                    </FormField>
                </ColumnLayout>
                <FormField label="Title">
                    <Input
                        value={rule.title.clone()}
                        on_change={ed.rule_field(|r, v| r.title = v)}
                        disabled={!is_editable}
                    />
                </FormField>
                <FormField label="Vulnerability Discussion">
                    <Textarea
                        value={rule.description.clone()}
                        on_change={ed.rule_field(|r, v| r.description = v)}
                        rows={4}
                        disabled={!is_editable}
                    />
                </FormField>
                <FormField label="Check Text">
                    <Textarea
                        value={rule.check_text.clone()}
                        on_change={ed.rule_field(|r, v| r.check_text = v)}
                        rows={4}
                        disabled={!is_editable}
                    />
                </FormField>
                <FormField label="Fix Text">
                    <Textarea
                        value={rule.fix_text.clone()}
                        on_change={ed.rule_field(|r, v| r.fix_text = v)}
                        rows={4}
                        disabled={!is_editable}
                    />
                </FormField>
            </SpaceBetween>
        }
    };

    let rules_tab = || {
        let columns = vec![
            Column::new("stigId", "Vuln ID", |r: &Rule| html! { {r.stig_id.clone()} }).width("120px"),
            Column::new("severity", "Severity", |r: &Rule| {
                html! { <Badge color={severity_badge_color(&r.severity)}>{r.severity.clone()}</Badge> }
            })
            .width("120px"),
            Column::new("title", "Title", |r: &Rule| html! { {or_untitled(&r.title, "(untitled)")} }),
            Column::new("cciIds", "CCI", |r: &Rule| {
                let ids = r.cci_ids.join(", ");
                html! { {if ids.is_empty() { "—".to_string() } else { ids }} }
            })
            .width("150px"),
        ];
        let on_selection_change = {
            let selected_rules = selected_rules.setter();
            Callback::from(move |items: Vec<Rule>| selected_rules.set(items.into_iter().map(|r| r.id).collect()))
        };
        let on_row_click = {
            let ed = ed.clone();
            Callback::from(move |rule: Rule| ed.set(|d| d.editing = Some(rule)))
        };
        let done = {
            let close = close_rule_editor.clone();
            Callback::from(move |_: MouseEvent| close.emit(()))
        };
        let modal_header =
            editing_rule.as_ref().map(|r| format!("Edit {}", r.stig_id)).unwrap_or_else(|| "Edit Rule".to_string());
        html! {
            <SpaceBetween size="m">
                <Table<Rule>
                    items={ed.data.borrow().rules.clone()}
                    {columns}
                    track_by={Callback::from(|r: Rule| r.id)}
                    selection_type={is_editable.then_some(AttrValue::from("multi"))}
                    selected_keys={(*selected_rules).clone()}
                    {on_selection_change}
                    {on_row_click}
                    striped_rows=true
                    header={html! {
                        <Header
                            counter={format!("({rule_count})")}
                            actions={html! {
                                if is_editable {
                                    <SpaceBetween direction="horizontal" size="xs">
                                        <Button disabled={selected_rules.is_empty()} onclick={delete_selected_rules.clone()}>
                                            {"Delete Selected"}
                                        </Button>
                                        <Button variant="primary" onclick={add_rule.clone()}>{"Add Rule"}</Button>
                                    </SpaceBetween>
                                }
                            }}
                        >
                            {"Rules"}
                        </Header>
                    }}
                    empty={html! {
                        <UiBox text_align="center" padding_vertical="l">
                            <SpaceBetween size="xs">
                                <b>{"No rules yet"}</b>
                                if is_editable {
                                    <Button onclick={add_rule.clone()}>{"Add your first rule"}</Button>
                                }
                            </SpaceBetween>
                        </UiBox>
                    }}
                />

                // Rule editor modal
                <Modal
                    visible={editing_rule.is_some()}
                    on_dismiss={close_rule_editor.clone()}
                    header={modal_header}
                    size="large"
                    footer={html! {
                        <UiBox float="right">
                            <Button variant="primary" onclick={done}>{"Done"}</Button>
                        </UiBox>
                    }}
                >
                    if let Some(rule) = editing_rule.as_ref() {
                        {rule_editor_form(rule)}
                    }
                </Modal>
            </SpaceBetween>
        }
    };

    let comments_tab = || {
        let on_new_comment = {
            let new_comment = new_comment.setter();
            Callback::from(move |v: String| new_comment.set(v))
        };
        html! {
            <Container header={html! { <Header variant="h2">{"Review Comments"}</Header> }}>
                <SpaceBetween size="m">
                    if comments.is_empty() {
                        <UiBox color="text-body-secondary">{"No comments yet."}</UiBox>
                    }
                    { for comments.iter().map(|c| html! {
                        <Container
                            key={c.id.clone()}
                            header={html! {
                                <SpaceBetween direction="horizontal" size="xs" align_items="center">
                                    <UiBox font_weight="bold">{c.user_name.clone()}</UiBox>
                                    <Badge color="grey">{c.user_role.clone()}</Badge>
                                    if let Some(action) = c.action.as_ref().filter(|a| !a.is_empty()) {
                                        <Badge color={if action == "approve" { "green" } else { "red" }}>
                                            {action.clone()}
                                        </Badge>
                                    }
                                    <UiBox color="text-body-secondary">{to_locale_string(&c.created_at)}</UiBox>
                                </SpaceBetween>
                            }}
                        >
                            {c.body.clone()}
                        </Container>
                    }) }
                    <FormField label="Add a comment">
                        <SpaceBetween size="xs">
                            <Textarea
                                value={(*new_comment).clone()}
                                on_change={on_new_comment}
                                placeholder="Write a comment..."
                                rows={3}
                            />
                            <UiBox>
                                <Button onclick={handle_add_comment.clone()} disabled={new_comment.trim().is_empty()}>
                                    {"Post Comment"}
                                </Button>
                            </UiBox>
                        </SpaceBetween>
                    </FormField>
                </SpaceBetween>
            </Container>
        }
    };

    let preview_tab = || {
        let xccdf_preview = ed.data.borrow().to_stig().map(|stig| export_xccdf(&stig)).unwrap_or_default();
        html! {
            <Container
                header={html! {
                    <Header
                        variant="h2"
                        actions={html! {
                            <SpaceBetween direction="horizontal" size="xs">
                                <Button icon_name="copy" onclick={handle_copy_preview.clone()}>
                                    {"Copy to Clipboard"}
                                </Button>
                                <Button variant="primary" disabled={draft.title.is_empty()} onclick={handle_export.clone()}>
                                    {"Export XCCDF"}
                                </Button>
                            </SpaceBetween>
                        }}
                    >
                        {"XCCDF Preview"}
                    </Header>
                }}
            >
                <pre style={PREVIEW_STYLE}>{xccdf_preview}</pre>
            </Container>
        }
    };

    let tab = |id: &'static str, label: String, content: &dyn Fn() -> Html| {
        TabItem::new(id, label, if active_tab == id { content() } else { Html::default() })
    };
    let tabs = vec![
        tab("metadata", "Metadata".to_string(), &metadata_tab),
        tab("rules", format!("Rules ({rule_count})"), &rules_tab),
        tab("comments", format!("Comments ({})", comments.len()), &comments_tab),
        tab("preview", "Preview".to_string(), &preview_tab),
    ];

    let on_tab_change = {
        let active_tab_id = active_tab_id.setter();
        Callback::from(move |id: AttrValue| active_tab_id.set(id))
    };
    let clear = |handle: &UseStateHandle<Option<String>>| {
        let handle = handle.setter();
        Callback::from(move |_: ()| handle.set(None))
    };
    let on_action_comment = {
        let action_comment = action_comment.setter();
        Callback::from(move |v: String| action_comment.set(v))
    };
    let on_reviewer_change = {
        let selected_reviewer = selected_reviewer.setter();
        Callback::from(move |o: SelectOption| selected_reviewer.set(Some(o)))
    };
    let reviewer_value = (*selected_reviewer).as_ref().map(|o| o.value.clone()).unwrap_or_default();
    let reviewer_label =
        (*selected_reviewer).as_ref().map(|o| o.label.clone()).unwrap_or(AttrValue::Static("Any reviewer"));

    html! {
        <SpaceBetween size="m">
            // Back + header
            {back_button}

            <Header
                variant="h2"
                description={html! {
                    <SpaceBetween direction="horizontal" size="xs" align_items="center">
                        <Badge color={status_color}>{status_label}</Badge>
                        if *saving {
                            <StatusIndicator kind="loading">{"Saving"}</StatusIndicator>
                        }
                    </SpaceBetween>
                }}
                actions={html! {
                    <SpaceBetween direction="horizontal" size="xs">
                        { for workflow_actions }
                    </SpaceBetween>
                }}
            >
                {or_untitled(&draft.title, "(untitled draft)")}
            </Header>

            <input
                ref={file_input_ref}
                type="file"
                accept=".xml,.ckl"
                style="display:none"
                aria-hidden="true"
                tabindex="-1"
                onchange={handle_import}
            />

            if let Some(message) = (*error).clone() {
                <Alert kind="error" dismissible=true on_dismiss={clear(&error)}>{message}</Alert>
            }
            if let Some(message) = (*success).clone() {
                <Alert kind="success" dismissible=true on_dismiss={clear(&success)}>{message}</Alert>
            }
            if let Some(message) = (*import_error).clone() {
                <Alert kind="error" dismissible=true on_dismiss={clear(&import_error)}>
                    {"Failed to import: "}{message}
                </Alert>
            }

            <Tabs active_tab_id={active_tab.clone()} on_change={on_tab_change} {tabs} />

            // Submit modal — optional reviewer selection
            <Modal
                visible={*show_submit_modal}
                on_dismiss={dismiss(&show_submit_modal)}
                header="Submit Draft for Review"
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button onclick={show(&show_submit_modal, false)}>{"Cancel"}</Button>
                            <Button variant="primary" onclick={handle_submit} testid="confirm-submit">{"Submit"}</Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <FormField
                    label="Send to reviewer"
                    description="Leave on 'Any reviewer' to let any reviewer claim this draft."
                >
                    <Select
                        testid="reviewer-select"
                        selected={reviewer_value}
                        selected_label={reviewer_label}
                        on_change={on_reviewer_change}
                        options={(*reviewer_options).clone()}
                        placeholder="Any reviewer"
                    />
                </FormField>
            </Modal>

            // Approve modal
            <Modal
                visible={*show_approve_modal}
                on_dismiss={dismiss(&show_approve_modal)}
                header="Approve Draft"
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button onclick={show(&show_approve_modal, false)}>{"Cancel"}</Button>
                            <Button variant="primary" onclick={handle_approve}>{"Approve"}</Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <FormField label="Comment (optional)">
                    <Textarea
                        value={(*action_comment).clone()}
                        on_change={on_action_comment.clone()}
                        placeholder="Add a comment..."
                        rows={3}
                    />
                </FormField>
            </Modal>

            // Reject modal
            <Modal
                visible={*show_reject_modal}
                on_dismiss={dismiss(&show_reject_modal)}
                header="Reject Draft"
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button onclick={show(&show_reject_modal, false)}>{"Cancel"}</Button>
                            <Button variant="primary" onclick={handle_reject}>{"Reject"}</Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <FormField label="Reason for rejection">
                    <Textarea
                        value={(*action_comment).clone()}
                        on_change={on_action_comment}
                        placeholder="Explain why this draft is being rejected..."
                        rows={3}
                    />
                </FormField>
            </Modal>
        </SpaceBetween>
    }
}

// ── Main STIGWriter component ────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct StigWriterProps {
    #[prop_or_default]
    pub initial_draft_id: Option<String>,
    #[prop_or_default]
    pub on_clear_draft_id: Callback<()>,
}

#[function_component]
pub fn StigWriter(props: &StigWriterProps) -> Html {
    let initial = props.initial_draft_id.clone().filter(|id| !id.is_empty());
    let active_draft_id = use_state(|| initial.clone());

    // Open a draft from the table or external trigger
    {
        let active_draft_id = active_draft_id.setter();
        use_effect_with(initial, move |initial| {
            if initial.is_some() {
                active_draft_id.set(initial.clone());
            }
        });
    }

    // Returning remounts the drafts table, which reloads the list.
    let handle_back = {
        let active_draft_id = active_draft_id.setter();
        let on_clear_draft_id = props.on_clear_draft_id.clone();
        Callback::from(move |_: ()| {
            active_draft_id.set(None);
            on_clear_draft_id.emit(());
        })
    };

    if let Some(draft_id) = (*active_draft_id).clone() {
        return html! { <DraftEditor key={draft_id.clone()} draft_id={draft_id.clone()} on_back={handle_back} /> };
    }

    let on_open_draft = {
        let active_draft_id = active_draft_id.setter();
        Callback::from(move |id: String| active_draft_id.set(Some(id)))
    };
    html! { <DraftsTable {on_open_draft} /> }
}
