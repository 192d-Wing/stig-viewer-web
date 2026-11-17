//! Server-backed checklist view: the rules table for one applied STIG, the
//! rule editor modal (status, assignee, evidence attachments, threaded
//! comments with reactions), the bulk CSV status import and the multi-select
//! "Set status" action.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use gloo_timers::callback::Timeout;
use serde::Deserialize;
use serde_json::{json, Value};
use wasm_bindgen::JsCast;
use yew::prelude::*;

use crate::api::{api_fetch, api_fetch_json, api_get, api_json, api_upload, api_upload_raw, BACKEND};
use crate::auth::use_current_user;
use crate::model::visible_selection;
use crate::ui::*;
use crate::util::{encode_uri_component, event_value, issue_lines, spawn_local, to_locale_string};

fn format_bytes(n: Option<f64>) -> String {
    match n {
        None => "—".to_string(),
        Some(n) if n < 1024.0 => format!("{n} B"),
        Some(n) if n < 1024.0 * 1024.0 => format!("{:.1} KB", n / 1024.0),
        Some(n) => format!("{:.1} MB", n / (1024.0 * 1024.0)),
    }
}

/// (value, label, badge colour)
const STATUSES: [(&str, &str, &str); 4] = [
    ("not_reviewed", "Not reviewed", "grey"),
    ("open", "Open", "red"),
    ("not_a_finding", "Not a finding", "green"),
    ("not_applicable", "Not applicable", "blue"),
];

// Emoji-style reactions surfaced under each rule comment. Keep the
// keys in sync with the allowlist in
// backend/src/api/rule_comments.rs (ALLOWED_REACTIONS).
const REACTION_TYPES: [(&str, &str); 3] = [("thumbs_up", "\u{1F44D}"), ("check", "✅"), ("question", "❓")];

// Closing statuses require a written justification in `findingDetails`.
// Keep in sync with `requires_finding_details` in
// backend/src/api/checklists.rs.
const CLOSING_STATUSES: [&str; 2] = ["not_a_finding", "not_applicable"];

fn finding_details_required(status: &str, finding_details: &str) -> bool {
    CLOSING_STATUSES.contains(&status) && finding_details.trim().is_empty()
}

/// Try to parse the JSON error body returned by `api_json`; fall back to the
/// raw message if the server didn't return JSON.
fn parse_save_error(message: String) -> Option<String> {
    if message.is_empty() {
        return None;
    }
    if let Ok(obj) = serde_json::from_str::<Value>(&message) {
        if let Some(e) = obj.get("error").and_then(Value::as_str) {
            return Some(e.to_string());
        }
    }
    Some(message)
}

fn severity_label(sev: &str) -> String {
    if sev.is_empty() {
        "—".to_string()
    } else {
        sev.to_uppercase()
    }
}

fn severity_color(sev: &str) -> &'static str {
    let s = sev.to_lowercase();
    if s.contains('i') && !s.contains("ii") {
        return "severity-high"; // CAT I
    }
    if s.contains("ii") && !s.contains("iii") {
        return "severity-medium"; // CAT II
    }
    if s.contains("iii") {
        return "severity-low"; // CAT III
    }
    "grey"
}

// ── API payloads ────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RuleState {
    status: String,
    finding_details: String,
    comments: String,
    assignee_id: Option<String>,
    due_date: Option<String>,
}

/// One STIG rule merged with this checklist's per-rule state. The rule part
/// comes straight from the STIG JSON, so everything is optional.
#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RuleRow {
    id: Option<String>,
    title: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    cci: Value,
    cci_ids: Value,
    state: RuleState,
}

impl RuleRow {
    fn id(&self) -> &str {
        self.id.as_deref().unwrap_or_default()
    }

    /// Backend emits `cci` as the canonical short-name field; legacy
    /// `cciIds` is the fallback so the CCI column keeps working against
    /// older STIG JSONs that haven't been re-parsed yet.
    fn cci_list(&self) -> Vec<String> {
        let to_strings = |v: &Value| -> Option<Vec<String>> {
            v.as_array().map(|a| {
                a.iter()
                    .map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string()))
                    .collect()
            })
        };
        to_strings(&self.cci).or_else(|| to_strings(&self.cci_ids)).unwrap_or_default()
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ChecklistInfo {
    stig_id: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AssetInfo {
    name: String,
    owner_id: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DetailPayload {
    checklist: ChecklistInfo,
    asset: AssetInfo,
    stig: Value,
    rules: Vec<RuleRow>,
}

/// What the view keeps of `GET /api/checklists/:id`.
#[derive(PartialEq)]
struct Detail {
    /// STIG title, falling back to the STIG id.
    title: String,
    asset_name: String,
    owner_id: String,
    rules: Vec<Rc<RuleRow>>,
}

impl From<DetailPayload> for Detail {
    fn from(d: DetailPayload) -> Self {
        let title = d
            .stig
            .get("title")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .unwrap_or(d.checklist.stig_id);
        Self {
            title,
            asset_name: d.asset.name,
            owner_id: d.asset.owner_id,
            rules: d.rules.into_iter().map(Rc::new).collect(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ApprovalRow {
    checklist_id: String,
    rule_id: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AttachmentCount {
    rule_id: String,
    count: u32,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Attachment {
    id: String,
    filename: String,
    size_bytes: Option<f64>,
    uploaded_at: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct UserSummary {
    id: String,
    display_name: String,
}

#[derive(Clone, Copy, PartialEq, Default, Deserialize)]
#[serde(default)]
struct ReactionSummary {
    count: i64,
    mine: bool,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Comment {
    id: String,
    user_id: String,
    user_name: String,
    body: String,
    created_at: String,
    edited_at: Option<String>,
    /// Keyed by reaction type (snake_case keys, e.g. `thumbs_up`).
    reactions: HashMap<String, ReactionSummary>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BulkRow {
    row_number: u64,
    rule_id: String,
    /// Status value from the CSV (the value being applied to the rule).
    rule_status: String,
    finding_details: String,
    /// Row-level result: "ok" | "error".
    status: String,
    error: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BulkResponse {
    rows: Vec<BulkRow>,
    applied_count: u64,
}

/// One rule's outcome from `POST …/rules/bulk-status`.
#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BulkStatusRow {
    rule_id: String,
    /// "applied" | "pending_approval" | "error"
    status: String,
    error: Option<String>,
    note: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BulkStatusResponse {
    results: Vec<BulkStatusRow>,
    applied_count: u64,
    pending_count: u64,
    error_count: u64,
}

/// Summary line shown after a multi-select status change.
fn bulk_status_summary(status_label: &str, r: &BulkStatusResponse) -> String {
    let plural = |n: u64| if n == 1 { "" } else { "s" };
    let mut parts = vec![format!("Set {} rule{} to {status_label}.", r.applied_count, plural(r.applied_count))];
    if r.pending_count > 0 {
        parts.push(format!("{} submitted for review.", r.pending_count));
    }
    if r.error_count > 0 {
        parts.push(format!("{} not changed.", r.error_count));
    }
    parts.join(" ")
}

// ── Editor draft ────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
struct Draft {
    status: String,
    finding_details: String,
    comments: String,
    assignee_id: Option<String>,
    due_date: String,
}

impl Default for Draft {
    fn default() -> Self {
        Self {
            status: "not_reviewed".into(),
            finding_details: String::new(),
            comments: String::new(),
            assignee_id: None,
            due_date: String::new(),
        }
    }
}

enum DraftAction {
    Reset(Draft),
    Status(String),
    FindingDetails(String),
    Comments(String),
    Assignee(Option<String>),
    DueDate(String),
}

impl Reducible for Draft {
    type Action = DraftAction;

    fn reduce(self: Rc<Self>, action: DraftAction) -> Rc<Self> {
        let mut d = (*self).clone();
        match action {
            DraftAction::Reset(next) => d = next,
            DraftAction::Status(v) => d.status = v,
            DraftAction::FindingDetails(v) => d.finding_details = v,
            DraftAction::Comments(v) => d.comments = v,
            DraftAction::Assignee(v) => d.assignee_id = v,
            DraftAction::DueDate(v) => d.due_date = v,
        }
        Rc::new(d)
    }
}

// ── State + actions ─────────────────────────────────────────────────────────

/// Bulk CSV import modal step: choose a file (+ dry-run), then review the
/// parsed rows and commit.
#[derive(Clone, Copy, PartialEq)]
enum BulkStep {
    Pick,
    Preview,
}

/// Every state handle of the view, bundled so async actions can be plain
/// methods. Cloned into callbacks each render.
#[derive(Clone)]
struct ViewState {
    checklist_id: String,

    detail: UseStateHandle<Option<Rc<Detail>>>,
    loading: UseStateHandle<bool>,
    error: UseStateHandle<Option<String>>,

    /// The rule being edited.
    editing: UseStateHandle<Option<Rc<RuleRow>>>,
    draft: UseReducerHandle<Draft>,
    saving: UseStateHandle<bool>,
    save_error: UseStateHandle<Option<String>>,
    pending_approval: UseStateHandle<bool>,

    // Attachment state — both the per-rule list shown in the Evidence
    // section of the editor modal, and a checklist-wide count map used
    // to decorate the rule list with a paperclip indicator.
    attachments: UseStateHandle<Vec<Attachment>>,
    attachments_loading: UseStateHandle<bool>,
    uploading: UseStateHandle<bool>,
    upload_error: UseStateHandle<Option<String>>,
    /// ruleId -> attachment count
    attachment_counts: UseStateHandle<Rc<HashMap<String, u32>>>,

    // Per-rule comment thread state — keyed off (checklistId, ruleId).
    // `comments` lives independently of the status-note `comments` field on
    // checklist_rules; this is the threaded discussion.
    comments: UseStateHandle<Vec<Comment>>,
    comments_loading: UseStateHandle<bool>,
    comment_draft: UseStateHandle<String>,
    posting_comment: UseStateHandle<bool>,
    comment_error: UseStateHandle<Option<String>>,
    editing_comment_id: UseStateHandle<Option<String>>,
    editing_comment_body: UseStateHandle<String>,

    bulk_open: UseStateHandle<bool>,
    bulk_step: UseStateHandle<BulkStep>,
    bulk_file: UseStateHandle<Option<web_sys::File>>,
    bulk_preview: UseStateHandle<Option<BulkResponse>>,
    bulk_busy: UseStateHandle<bool>,
    bulk_error: UseStateHandle<Option<String>>,
    bulk_success: UseStateHandle<Option<BulkResponse>>,

    /// Rule IDs in this checklist that currently have an open approval
    /// request. Used to render a "Pending review" pill in the rule list.
    pending_approval_ids: UseStateHandle<Rc<HashSet<String>>>,
}

impl ViewState {
    fn rule_path(&self, rule_id: &str, suffix: &str) -> String {
        format!(
            "/api/checklists/{}/rules/{}{suffix}",
            self.checklist_id,
            encode_uri_component(rule_id)
        )
    }

    async fn refresh(&self) {
        self.loading.set(true);
        self.error.set(None);
        match api_get::<DetailPayload>(&format!("/api/checklists/{}", self.checklist_id)).await {
            Ok(d) => {
                self.detail.set(Some(Rc::new(d.into())));
                // Best-effort fetch of pending approvals scoped to this checklist.
                // Non-fatal — the rule list still renders without the pill.
                let ids: HashSet<String> = api_get::<Vec<ApprovalRow>>("/api/approvals?status=pending")
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|r| r.checklist_id == self.checklist_id)
                    .map(|r| r.rule_id)
                    .collect();
                self.pending_approval_ids.set(Rc::new(ids));
            }
            Err(e) => self.error.set(Some(e)),
        }
        self.loading.set(false);
    }

    async fn refresh_counts(&self) {
        let path = format!("/api/checklists/{}/attachments", self.checklist_id);
        // Non-fatal on error — just leave counts as they are.
        if let Ok(rows) = api_get::<Vec<AttachmentCount>>(&path).await {
            let map = rows.into_iter().map(|r| (r.rule_id, r.count)).collect();
            self.attachment_counts.set(Rc::new(map));
        }
    }

    async fn refresh_attachments(&self, rule_id: &str) {
        if rule_id.is_empty() {
            return;
        }
        self.attachments_loading.set(true);
        match api_get::<Vec<Attachment>>(&self.rule_path(rule_id, "/attachments")).await {
            Ok(rows) => self.attachments.set(rows),
            Err(e) => {
                self.attachments.set(Vec::new());
                self.upload_error.set(Some(e));
            }
        }
        self.attachments_loading.set(false);
    }

    async fn refresh_comments(&self, rule_id: &str) {
        if rule_id.is_empty() {
            return;
        }
        self.comments_loading.set(true);
        match api_get::<Vec<Comment>>(&self.rule_path(rule_id, "/comments")).await {
            Ok(rows) => self.comments.set(rows),
            Err(e) => {
                self.comments.set(Vec::new());
                self.comment_error.set(Some(e));
            }
        }
        self.comments_loading.set(false);
    }

    fn start_edit(&self, rule: Rc<RuleRow>) {
        self.draft.dispatch(DraftAction::Reset(Draft {
            status: rule.state.status.clone(),
            finding_details: rule.state.finding_details.clone(),
            comments: rule.state.comments.clone(),
            assignee_id: rule.state.assignee_id.clone(),
            due_date: rule.state.due_date.clone().unwrap_or_default(),
        }));
        self.save_error.set(None);
        self.upload_error.set(None);
        self.attachments.set(Vec::new());
        self.comments.set(Vec::new());
        self.comment_draft.set(String::new());
        self.comment_error.set(None);
        self.editing_comment_id.set(None);
        self.editing_comment_body.set(String::new());
        self.editing.set(Some(rule.clone()));
        let (s, r) = (self.clone(), rule.clone());
        spawn_local(async move { s.refresh_attachments(r.id()).await });
        let s = self.clone();
        spawn_local(async move { s.refresh_comments(rule.id()).await });
    }

    async fn post_comment(&self, rule_id: String, body: String) {
        let trimmed = body.trim();
        if trimmed.is_empty() {
            return;
        }
        self.posting_comment.set(true);
        self.comment_error.set(None);
        let path = self.rule_path(&rule_id, "/comments");
        match api_json::<Value, _>(&path, "POST", Some(&json!({ "body": trimmed }))).await {
            Ok(_) => {
                self.comment_draft.set(String::new());
                self.refresh_comments(&rule_id).await;
            }
            Err(e) => self.comment_error.set(parse_save_error(e)),
        }
        self.posting_comment.set(false);
    }

    async fn save_edit_comment(&self, rule_id: String, comment_id: String, body: String) {
        let trimmed = body.trim();
        if trimmed.is_empty() {
            return;
        }
        self.comment_error.set(None);
        let path = format!("/api/comments/{comment_id}");
        match api_json::<Value, _>(&path, "PATCH", Some(&json!({ "body": trimmed }))).await {
            Ok(_) => {
                self.editing_comment_id.set(None);
                self.editing_comment_body.set(String::new());
                self.refresh_comments(&rule_id).await;
            }
            Err(e) => self.comment_error.set(parse_save_error(e)),
        }
    }

    async fn delete_comment(&self, rule_id: String, comment_id: String) {
        self.comment_error.set(None);
        match api_fetch("DELETE", &format!("/api/comments/{comment_id}")).await {
            Ok(res) if res.ok() => self.refresh_comments(&rule_id).await,
            Ok(res) => self.comment_error.set(Some(res.status().to_string())),
            Err(e) => self.comment_error.set(Some(e)),
        }
    }

    /// Toggle one of the three emoji reactions on a comment. If `mine` is
    /// true we DELETE; otherwise we POST. After the request we refresh the
    /// comment list so the new count/mine flag are reflected.
    async fn toggle_reaction(&self, rule_id: String, comment_id: String, reaction: &'static str, mine: bool) {
        self.comment_error.set(None);
        // Both endpoints return 204 No Content, so use the raw fetch helpers
        // rather than `api_json`, which expects a JSON body.
        let res = if mine {
            api_fetch("DELETE", &format!("/api/comments/{comment_id}/reactions/{reaction}")).await
        } else {
            let path = format!("/api/comments/{comment_id}/reactions");
            api_fetch_json("POST", &path, &json!({ "reaction": reaction })).await
        };
        match res {
            Ok(res) if res.ok() => self.refresh_comments(&rule_id).await,
            Ok(res) => self.comment_error.set(Some(res.status().to_string())),
            Err(e) => self.comment_error.set(parse_save_error(e)),
        }
    }

    async fn upload_attachment(&self, rule_id: String, file: web_sys::File) {
        self.uploading.set(true);
        self.upload_error.set(None);
        match api_upload::<Value>(&self.rule_path(&rule_id, "/attachments"), &file).await {
            Ok(_) => {
                self.refresh_attachments(&rule_id).await;
                self.refresh_counts().await;
            }
            Err(e) => {
                // The backend returns 413 for files over the size cap; surface a
                // friendlier message in that case.
                let msg = if e.contains("413") { "File too large (max 25 MB).".to_string() } else { e };
                self.upload_error.set(Some(msg));
            }
        }
        self.uploading.set(false);
    }

    async fn delete_attachment(&self, rule_id: String, attachment_id: String) {
        match api_fetch("DELETE", &format!("/api/attachments/{attachment_id}")).await {
            Ok(res) if res.ok() => {
                self.refresh_attachments(&rule_id).await;
                self.refresh_counts().await;
            }
            Ok(res) => self.upload_error.set(Some(res.status().to_string())),
            Err(e) => self.upload_error.set(Some(e)),
        }
    }

    /// Reset the bulk-import modal state.
    fn close_bulk(&self) {
        self.bulk_open.set(false);
        self.bulk_step.set(BulkStep::Pick);
        self.bulk_file.set(None);
        self.bulk_preview.set(None);
        self.bulk_error.set(None);
        self.bulk_success.set(None);
        self.bulk_busy.set(false);
    }

    fn open_bulk(&self) {
        self.close_bulk();
        self.bulk_open.set(true);
    }

    /// POST the CSV to the bulk-import endpoint and parse the JSON answer.
    async fn bulk_request(&self, file: &web_sys::File, dry_run: bool) -> Result<BulkResponse, String> {
        let path = format!("/api/checklists/{}/rules/bulk-import?dry_run={dry_run}", self.checklist_id);
        let res = api_upload_raw(&path, file).await?;
        if !res.ok() {
            let status = res.status();
            let text = res.text().await.unwrap_or_else(|_| res.status_text());
            return Err(if text.is_empty() { status.to_string() } else { text });
        }
        res.json::<BulkResponse>().await.map_err(|e| e.to_string())
    }

    /// Upload + parse the chosen CSV via a dry-run POST. The response drives
    /// the preview table; commit re-uploads the same file with dry_run=false.
    async fn bulk_file_chosen(&self, file: web_sys::File) {
        self.bulk_file.set(Some(file.clone()));
        self.bulk_preview.set(None);
        self.bulk_error.set(None);
        self.bulk_success.set(None);
        self.bulk_busy.set(true);
        match self.bulk_request(&file, true).await {
            Ok(data) => {
                self.bulk_preview.set(Some(data));
                self.bulk_step.set(BulkStep::Preview);
            }
            Err(e) => self.bulk_error.set(Some(e)),
        }
        self.bulk_busy.set(false);
    }

    async fn commit_bulk(&self, file: web_sys::File) {
        self.bulk_busy.set(true);
        self.bulk_error.set(None);
        match self.bulk_request(&file, false).await {
            Ok(data) => {
                self.bulk_success.set(Some(data));
                self.refresh().await;
                // Auto-close shortly after success so the user sees the alert.
                let s = self.clone();
                Timeout::new(800, move || s.close_bulk()).forget();
            }
            Err(e) => self.bulk_error.set(Some(e)),
        }
        self.bulk_busy.set(false);
    }

    async fn save_edit(&self, rule_id: String, draft: Draft) {
        self.saving.set(true);
        self.save_error.set(None);
        self.pending_approval.set(false);
        // DatePicker yields YYYY/MM/DD or YYYY-MM-DD; backend wants YYYY-MM-DD,
        // and an empty string should mean "no due date" → null.
        let due_date = (!draft.due_date.is_empty()).then(|| draft.due_date.replace('/', "-"));
        let body = json!({
            "status": draft.status,
            "findingDetails": draft.finding_details,
            "comments": draft.comments,
            "assigneeId": draft.assignee_id,
            "dueDate": due_date,
        });
        match api_json::<Value, _>(&self.rule_path(&rule_id, ""), "PATCH", Some(&body)).await {
            Ok(result) => {
                // The server returns 202 + { status: 'pending_approval', ... } when
                // the asset has requires_approval = TRUE and the proposed status is
                // a closing one. Keep the editor open and surface a banner instead
                // of closing it like a normal save.
                if result.get("status").and_then(Value::as_str) == Some("pending_approval") {
                    self.pending_approval.set(true);
                } else {
                    self.editing.set(None);
                }
                self.refresh().await;
            }
            Err(e) => self.save_error.set(parse_save_error(e)),
        }
        self.saving.set(false);
    }
}

/// First file of the `<input type="file">` a change event fired on.
fn picked_file(e: &Event) -> Option<(web_sys::HtmlInputElement, web_sys::File)> {
    let input = e.target()?.dyn_into::<web_sys::HtmlInputElement>().ok()?;
    let file = input.files()?.get(0)?;
    Some((input, file))
}

fn secondary_note(text: &'static str) -> Html {
    html! { <UiBox variant="small" color="text-body-secondary">{text}</UiBox> }
}

fn error_alert(message: &Option<String>) -> Html {
    match message {
        Some(m) => html! { <Alert kind="error">{m.clone()}</Alert> },
        None => Html::default(),
    }
}

// ── Component ───────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct ChecklistViewProps {
    pub checklist_id: String,
    pub on_back: Callback<()>,
}

#[function_component]
pub fn ChecklistView(props: &ChecklistViewProps) -> Html {
    let current_user = use_current_user();
    let users = use_state(Vec::<UserSummary>::new);
    let filter = use_state(String::new);

    // Multi-select "Set status" state.
    let selected = use_state(Vec::<String>::new);
    let set_status_open = use_state(|| false);
    let set_status_value = use_state(|| "not_a_finding".to_string());
    let set_status_details = use_state(String::new);
    let set_status_busy = use_state(|| false);
    let set_status_error = use_state(|| None::<String>);
    let set_status_result = use_state(|| None::<(String, BulkStatusResponse)>);

    let s = ViewState {
        checklist_id: props.checklist_id.clone(),
        detail: use_state(|| None),
        loading: use_state(|| true),
        error: use_state(|| None),
        editing: use_state(|| None),
        draft: use_reducer(Draft::default),
        saving: use_state(|| false),
        save_error: use_state(|| None),
        pending_approval: use_state(|| false),
        attachments: use_state(Vec::new),
        attachments_loading: use_state(|| false),
        uploading: use_state(|| false),
        upload_error: use_state(|| None),
        attachment_counts: use_state(Rc::default),
        comments: use_state(Vec::new),
        comments_loading: use_state(|| false),
        comment_draft: use_state(String::new),
        posting_comment: use_state(|| false),
        comment_error: use_state(|| None),
        editing_comment_id: use_state(|| None),
        editing_comment_body: use_state(String::new),
        bulk_open: use_state(|| false),
        bulk_step: use_state(|| BulkStep::Pick),
        bulk_file: use_state(|| None),
        bulk_preview: use_state(|| None),
        bulk_busy: use_state(|| false),
        bulk_error: use_state(|| None),
        bulk_success: use_state(|| None),
        pending_approval_ids: use_state(Rc::default),
    };

    // Load the checklist, plus the attachment counts for the paperclip
    // indicator in the rule list, once per checklist.
    {
        let s = s.clone();
        use_effect_with(props.checklist_id.clone(), move |_| {
            let counts = s.clone();
            spawn_local(async move { s.refresh().await });
            spawn_local(async move { counts.refresh_counts().await });
        });
    }

    // Load the user list once for the Assignee Select.
    {
        let users = users.clone();
        use_effect_with((), move |_| {
            spawn_local(async move {
                // Non-fatal on error — the Select just won't have options.
                if let Ok(rows) = api_get::<Vec<UserSummary>>("/api/users").await {
                    users.set(rows);
                }
            });
        });
    }

    let back = props.on_back.reform(|_: MouseEvent| ());

    if *s.loading {
        return html! {
            <UiBox padding="xxl" text_align="center">
                <StatusIndicator kind="loading">{"Loading checklist"}</StatusIndicator>
            </UiBox>
        };
    }

    if let Some(error) = &*s.error {
        return html! {
            <UiBox padding="m">
                <Alert kind="error" header="Error">{error.clone()}</Alert>
                <UiBox padding_top="m">
                    <Button onclick={back}>{"Back"}</Button>
                </UiBox>
            </UiBox>
        };
    }

    let Some(detail) = (*s.detail).clone() else {
        return Html::default();
    };

    let is_owner = current_user.as_ref().map(|u| u.id.as_str()) == Some(detail.owner_id.as_str());
    let gate_violated = finding_details_required(&s.draft.status, &s.draft.finding_details);

    let count_of = |status: &str| detail.rules.iter().filter(|r| r.state.status == status).count();

    let filtered_rules: Vec<Rc<RuleRow>> = {
        let f = filter.trim().to_lowercase();
        if f.is_empty() {
            detail.rules.clone()
        } else {
            let has = |v: &Option<String>| v.as_deref().unwrap_or_default().to_lowercase().contains(&f);
            detail.rules.iter().filter(|r| has(&r.id) || has(&r.title) || has(&r.severity)).cloned().collect()
        }
    };

    // ── Rules table ─────────────────────────────────────────────────────────

    let rule_columns = {
        let start_edit = {
            let s = s.clone();
            Callback::from(move |rule: Rc<RuleRow>| s.start_edit(rule))
        };
        let attachment_counts = (*s.attachment_counts).clone();
        let pending_ids = (*s.pending_approval_ids).clone();
        vec![
            Column::new("id", "Rule", move |r: &Rc<RuleRow>| {
                let n = attachment_counts.get(r.id()).copied().unwrap_or(0);
                let rule = r.clone();
                let label = format!("{n} attachment{}", if n == 1 { "" } else { "s" });
                html! {
                    <SpaceBetween direction="horizontal" size="xxs">
                        <Button variant="inline-link" onclick={start_edit.reform(move |_| rule.clone())}>
                            {r.id().to_string()}
                        </Button>
                        if n > 0 {
                            <span title={label.clone()} aria-label={label} data-testid="attachment-indicator"
                                  style="opacity:0.7;">
                                {"\u{1F4CE}"}
                                if n > 1 { {format!(" {n}")} }
                            </span>
                        }
                    </SpaceBetween>
                }
            }),
            Column::new("severity", "Severity", |r: &Rc<RuleRow>| {
                let sev = r.severity.as_deref().unwrap_or_default();
                html! { <Badge color={severity_color(sev)}>{severity_label(sev)}</Badge> }
            }),
            Column::new("title", "Title", |r: &Rc<RuleRow>| {
                let title = r.title.as_deref().filter(|t| !t.is_empty()).unwrap_or("—");
                html! { {title.to_string()} }
            }),
            Column::new("cci", "CCI", |r: &Rc<RuleRow>| {
                let ids = r.cci_list();
                if ids.is_empty() {
                    return html! { {"—"} };
                }
                html! {
                    <span data-testid="rule-cci-cell">
                        <SpaceBetween direction="horizontal" size="xxs">
                            { for ids.into_iter().map(|id| html! { <Badge key={id.clone()} color="blue">{id.clone()}</Badge> }) }
                        </SpaceBetween>
                    </span>
                }
            }),
            Column::new("status", "Status", move |r: &Rc<RuleRow>| {
                if pending_ids.contains(r.id()) {
                    return html! { <Badge color="blue" testid="status-pending-review">{"Pending review"}</Badge> };
                }
                let (_, label, color) =
                    STATUSES.iter().find(|(v, _, _)| *v == r.state.status).copied().unwrap_or(STATUSES[0]);
                html! { <Badge {color}>{label}</Badge> }
            }),
        ]
    };

    // ── Rule editor modal ───────────────────────────────────────────────────

    let close_edit = {
        let editing = s.editing.clone();
        Callback::from(move |_: ()| editing.set(None))
    };
    let save_edit = {
        let s = s.clone();
        Callback::from(move |_: MouseEvent| {
            let Some(rule) = (*s.editing).clone() else { return };
            let draft = (*s.draft).clone();
            let s = s.clone();
            spawn_local(async move { s.save_edit(rule.id().to_string(), draft).await });
        })
    };

    let edit_body = (*s.editing).clone().map(|rule| {
        let rule_id = rule.id().to_string();
        let draft = s.draft.clone();
        let dispatch = |f: fn(String) -> DraftAction| {
            let draft = draft.clone();
            Callback::from(move |v: String| draft.dispatch(f(v)))
        };

        let assignee_options: Vec<SelectOption> = std::iter::once(SelectOption::new("", "Unassigned"))
            .chain(users.iter().map(|u| SelectOption::new(u.id.clone(), u.display_name.clone())))
            .collect();
        let on_assignee = {
            let draft = draft.clone();
            Callback::from(move |o: SelectOption| {
                draft.dispatch(DraftAction::Assignee((!o.value.is_empty()).then(|| o.value.to_string())));
            })
        };
        let on_status = {
            let draft = draft.clone();
            Callback::from(move |v: AttrValue| draft.dispatch(DraftAction::Status(v.to_string())))
        };

        let attachment_columns = {
            let s = s.clone();
            let rule_id = rule_id.clone();
            vec![
                Column::new("filename", "File", |a: &Attachment| html! { {a.filename.clone()} }),
                Column::new("size", "Size", |a: &Attachment| html! { {format_bytes(a.size_bytes)} }),
                Column::new("uploaded", "Uploaded", |a: &Attachment| html! { {to_locale_string(&a.uploaded_at)} }),
                Column::new("actions", "", move |a: &Attachment| {
                    let on_delete = {
                        let (s, rule_id, id) = (s.clone(), rule_id.clone(), a.id.clone());
                        Callback::from(move |_: MouseEvent| {
                            let (s, rule_id, id) = (s.clone(), rule_id.clone(), id.clone());
                            spawn_local(async move { s.delete_attachment(rule_id, id).await });
                        })
                    };
                    html! {
                        <SpaceBetween direction="horizontal" size="xxs">
                            <Button variant="inline-link" icon_name="download"
                                    aria_label={format!("Download {}", a.filename)}
                                    href={format!("{BACKEND}/api/attachments/{}", a.id)} target="_blank"
                                    testid="attachment-download">
                                {"Download"}
                            </Button>
                            <Button variant="inline-link" icon_name="close"
                                    aria_label={format!("Delete {}", a.filename)}
                                    disabled={!is_owner} onclick={on_delete} testid="attachment-delete">
                                {"Delete"}
                            </Button>
                        </SpaceBetween>
                    }
                }),
            ]
        };
        let on_attachment_file = {
            let (s, rule_id) = (s.clone(), rule_id.clone());
            Callback::from(move |e: Event| {
                if let Some((input, file)) = picked_file(&e) {
                    let (s, rule_id) = (s.clone(), rule_id.clone());
                    spawn_local(async move { s.upload_attachment(rule_id, file).await });
                    // Reset so the same file can be picked again.
                    input.set_value("");
                }
            })
        };

        let post_comment = {
            let (s, rule_id) = (s.clone(), rule_id.clone());
            Callback::from(move |_: MouseEvent| {
                let (s, rule_id) = (s.clone(), rule_id.clone());
                let body = (*s.comment_draft).clone();
                spawn_local(async move { s.post_comment(rule_id, body).await });
            })
        };
        let on_comment_draft = {
            let comment_draft = s.comment_draft.clone();
            Callback::from(move |v: String| comment_draft.set(v))
        };
        let current_user_id = current_user.as_ref().map(|u| u.id.clone());

        html! {
            <SpaceBetween direction="vertical" size="m">
                <UiBox variant="h3">{rule.title.clone().unwrap_or_default()}</UiBox>
                if let Some(description) = rule.description.as_ref().filter(|d| !d.is_empty()) {
                    <UiBox variant="small" color="text-body-secondary">{description.clone()}</UiBox>
                }
                if !is_owner {
                    <Alert kind="info">
                        {"Read-only — only the system owner can change rule status."}
                    </Alert>
                }
                <FormField label="Status">
                    <RadioGroup
                        value={AttrValue::from(draft.status.clone())}
                        on_change={on_status}
                        items={STATUSES.iter().map(|(v, l, _)| RadioItem::new(*v, *l)).collect::<Vec<_>>()}
                    />
                </FormField>
                <ColumnLayout columns={2}>
                    <FormField label="Assignee">
                        <Select
                            selected={AttrValue::from(draft.assignee_id.clone().unwrap_or_default())}
                            selected_label={draft.assignee_id.clone().map(AttrValue::from)}
                            on_change={on_assignee}
                            options={assignee_options}
                            disabled={!is_owner}
                        />
                    </FormField>
                    <FormField label="Due date">
                        <DatePicker
                            value={draft.due_date.clone()}
                            on_change={dispatch(DraftAction::DueDate)}
                            placeholder="YYYY/MM/DD"
                            disabled={!is_owner}
                        />
                    </FormField>
                </ColumnLayout>
                <FormField
                    label="Finding details"
                    description="What was observed?"
                    error_text={if gate_violated { html! { {"Required when closing this finding."} } } else { Html::default() }}
                >
                    <Textarea
                        value={draft.finding_details.clone()}
                        disabled={!is_owner}
                        on_change={dispatch(DraftAction::FindingDetails)}
                        rows={4}
                        invalid={gate_violated}
                    />
                </FormField>
                <FormField label="Comments" description="Notes for future reviewers">
                    <Textarea
                        value={draft.comments.clone()}
                        disabled={!is_owner}
                        on_change={dispatch(DraftAction::Comments)}
                        rows={3}
                    />
                </FormField>
                {error_alert(&s.save_error)}
                if *s.pending_approval {
                    <Alert kind="success" header="Submitted for review" testid="pending-approval-alert">
                        {"This asset requires reviewer approval before closing findings. \
                          Your request has been queued and a reviewer will see it in \
                          the approvals queue."}
                    </Alert>
                }

                <FormField
                    label="Evidence"
                    description="Attach screenshots, logs, or scan output as supporting evidence."
                >
                    <SpaceBetween direction="vertical" size="s">
                        if *s.attachments_loading {
                            <StatusIndicator kind="loading">{"Loading attachments"}</StatusIndicator>
                        } else if s.attachments.is_empty() {
                            {secondary_note("No attachments yet.")}
                        } else {
                            <Table<Attachment>
                                variant="embedded"
                                items={(*s.attachments).clone()}
                                track_by={Callback::from(|a: Attachment| a.id)}
                                columns={attachment_columns}
                            />
                        }
                        if is_owner {
                            <UiBox>
                                <input type="file" data-testid="attachment-file-input"
                                       disabled={*s.uploading} onchange={on_attachment_file} />
                                if *s.uploading {
                                    <UiBox variant="small" padding_top="xs">
                                        <StatusIndicator kind="in-progress">{"Uploading…"}</StatusIndicator>
                                    </UiBox>
                                }
                            </UiBox>
                        }
                        {error_alert(&s.upload_error)}
                    </SpaceBetween>
                </FormField>

                <FormField label="Comments" description="Threaded discussion for this rule.">
                    <SpaceBetween direction="vertical" size="s">
                        if *s.comments_loading {
                            <StatusIndicator kind="loading">{"Loading comments"}</StatusIndicator>
                        } else if s.comments.is_empty() {
                            {secondary_note("No comments yet.")}
                        } else {
                            <SpaceBetween direction="vertical" size="xs">
                                { for s.comments.iter().map(|c| comment_item(&s, &rule_id, c, current_user_id.as_deref())) }
                            </SpaceBetween>
                        }

                        <Textarea
                            value={(*s.comment_draft).clone()}
                            on_change={on_comment_draft}
                            placeholder="Add a comment…"
                            rows={3}
                            testid="rule-comment-input"
                        />
                        <UiBox>
                            <Button variant="primary" loading={*s.posting_comment}
                                    disabled={s.comment_draft.trim().is_empty()}
                                    onclick={post_comment} testid="rule-comment-add">
                                {"Add comment"}
                            </Button>
                        </UiBox>
                        {error_alert(&s.comment_error)}
                    </SpaceBetween>
                </FormField>
            </SpaceBetween>
        }
    });

    // ── Bulk import modal ───────────────────────────────────────────────────

    let open_bulk = {
        let s = s.clone();
        Callback::from(move |_: MouseEvent| s.open_bulk())
    };
    let close_bulk = {
        let s = s.clone();
        Callback::from(move |_: ()| s.close_bulk())
    };
    let commit_bulk = {
        let s = s.clone();
        Callback::from(move |_: MouseEvent| {
            let Some(file) = (*s.bulk_file).clone() else { return };
            let s = s.clone();
            spawn_local(async move { s.commit_bulk(file).await });
        })
    };
    let on_bulk_file = {
        let s = s.clone();
        Callback::from(move |e: Event| {
            if let Some((_, file)) = picked_file(&e) {
                let s = s.clone();
                spawn_local(async move { s.bulk_file_chosen(file).await });
            }
        })
    };
    // ── Multi-select "Set status" ───────────────────────────────────────────
    // Only rules that still exist in the checklist count as selected.
    // Rows hidden by the text filter are not acted on either.
    let filtered_ids: Vec<&str> = filtered_rules.iter().map(|r| r.id()).collect();
    let selected_ids: Vec<String> = visible_selection(&filtered_ids, &selected);
    let on_selection_change = {
        let selected = selected.clone();
        Callback::from(move |rows: Vec<Rc<RuleRow>>| selected.set(rows.iter().map(|r| r.id().to_string()).collect()))
    };
    let open_set_status = {
        let (open, details, error) = (set_status_open.clone(), set_status_details.clone(), set_status_error.clone());
        Callback::from(move |_: MouseEvent| {
            details.set(String::new());
            error.set(None);
            open.set(true);
        })
    };
    let close_set_status = {
        let open = set_status_open.clone();
        Callback::from(move |_: ()| open.set(false))
    };
    let apply_set_status = {
        let s = s.clone();
        let (selected, open, busy, error, result) = (
            selected.clone(),
            set_status_open.clone(),
            set_status_busy.clone(),
            set_status_error.clone(),
            set_status_result.clone(),
        );
        let (rule_ids, status, details) =
            (selected_ids.clone(), (*set_status_value).clone(), (*set_status_details).clone());
        Callback::from(move |_: MouseEvent| {
            let s = s.clone();
            let (selected, open, busy, error, result) =
                (selected.clone(), open.clone(), busy.clone(), error.clone(), result.clone());
            let status = status.clone();
            let body = json!({ "ruleIds": rule_ids, "status": status, "findingDetails": details });
            spawn_local(async move {
                busy.set(true);
                error.set(None);
                let path = format!("/api/checklists/{}/rules/bulk-status", s.checklist_id);
                match api_json::<BulkStatusResponse, _>(&path, "POST", Some(&body)).await {
                    Ok(r) => {
                        // Rules that could not be changed stay selected so
                        // they can be retried with a justification.
                        selected.set(
                            r.results.iter().filter(|x| x.status == "error").map(|x| x.rule_id.clone()).collect(),
                        );
                        result.set(Some((status, r)));
                        open.set(false);
                        s.refresh().await;
                    }
                    Err(e) => error.set(Some(e)),
                }
                busy.set(false);
            });
        })
    };
    let status_label = |value: &str| {
        STATUSES.iter().find(|(v, _, _)| *v == value).map(|(_, l, _)| *l).unwrap_or_default().to_string()
    };
    let set_status_closing = CLOSING_STATUSES.contains(&set_status_value.as_str());
    let set_status_alert = match &*set_status_result {
        Some((status, r)) => {
            let (failed, failed_more) = issue_lines(
                r.results
                    .iter()
                    .filter(|x| x.status == "error")
                    .map(|x| (x.rule_id.as_str(), Some(x.error.as_deref().unwrap_or_default()))),
                10,
            );
            let (noted, noted_more) =
                issue_lines(r.results.iter().map(|x| (x.rule_id.as_str(), x.note.as_deref())), 10);
            let dismiss = {
                let result = set_status_result.clone();
                Callback::from(move |_: ()| result.set(None))
            };
            html! {
                <Alert kind={if r.error_count > 0 { "warning" } else { "success" }} dismissible=true
                       on_dismiss={dismiss} testid="set-status-result">
                    {bulk_status_summary(&status_label(status), r)}
                    if !noted.is_empty() {
                        <ul style="margin:6px 0 0;padding-left:18px;">
                            { for noted.iter().map(|(id, text)| html! {
                                <li key={id.clone()}>
                                    <code>{id.clone()}</code>{": "}{text.clone()}
                                </li>
                            }) }
                            if noted_more > 0 {
                                <li>{format!("…and {noted_more} more.")}</li>
                            }
                        </ul>
                    }
                    if !failed.is_empty() {
                        <ul style="margin:6px 0 0;padding-left:18px;">
                            { for failed.iter().map(|(id, text)| html! {
                                <li key={id.clone()}>
                                    <code>{id.clone()}</code>{": "}{text.clone()}
                                </li>
                            }) }
                            if failed_more > 0 {
                                <li>{format!("…and {failed_more} more (still selected).")}</li>
                            }
                        </ul>
                    }
                </Alert>
            }
        }
        None => Html::default(),
    };

    // Inline data: URL for the "Download template" link. Three columns +
    // one example row keep the CSV tiny and self-documenting.
    let bulk_template_href = format!(
        "data:text/csv;charset=utf-8,{}",
        encode_uri_component("rule_id,status,finding_details\nV-12345,not_a_finding,Patched per vendor guidance.\n")
    );
    let bulk_columns = vec![
        Column::new("row", "Row", |r: &BulkRow| html! { {r.row_number} }),
        Column::new("ruleId", "Rule", |r: &BulkRow| html! { {or_dash(&r.rule_id)} }),
        Column::new("ruleStatus", "Status", |r: &BulkRow| html! { {or_dash(&r.rule_status)} }),
        Column::new("findingDetails", "Finding details", |r: &BulkRow| html! { {or_dash(&r.finding_details)} }),
        Column::new("status", "Result", |r: &BulkRow| {
            let color = if r.status == "ok" { "green" } else { "red" };
            html! { <Badge {color} testid={format!("bulk-status-{}", r.row_number)}>{r.status.clone()}</Badge> }
        }),
        Column::new("error", "Note", |r: &BulkRow| html! { {r.error.clone().unwrap_or_default()} }),
    ];
    let bulk_rows_with = |preview: &BulkResponse, status: &str| preview.rows.iter().filter(|r| r.status == status).count();

    html! {
        <UiBox padding="m">
            <SpaceBetween direction="vertical" size="l">
                <Button icon_name="arrow-left" onclick={back}>{"Back to system"}</Button>

                <Container header={html! {
                    <Header
                        variant="h1"
                        description={format!("{} · {} rules", detail.asset_name, detail.rules.len())}
                        actions={html! {
                            <SpaceBetween direction="horizontal" size="xs">
                                <Button onclick={open_set_status} disabled={!is_owner || selected_ids.is_empty()}
                                        testid="set-status-button">
                                    {if selected_ids.is_empty() { "Set status".to_string() }
                                     else { format!("Set status ({})", selected_ids.len()) }}
                                </Button>
                                <Button onclick={open_bulk} disabled={!is_owner} testid="bulk-import-button">
                                    {"Bulk import"}
                                </Button>
                            </SpaceBetween>
                        }}
                    >
                        {detail.title.clone()}
                    </Header>
                }}>
                    <ColumnLayout columns={4} variant="text-grid">
                        { for STATUSES.iter().map(|(value, label, _)| html! {
                            <div key={*value}>
                                <UiBox variant="awsui-key-label">{*label}</UiBox>
                                <UiBox variant="h2">{count_of(value)}</UiBox>
                            </div>
                        }) }
                    </ColumnLayout>
                </Container>

                {set_status_alert}

                <Table<Rc<RuleRow>>
                    variant="container"
                    items={filtered_rules.clone()}
                    track_by={Callback::from(|r: Rc<RuleRow>| r.id().to_string())}
                    selection_type={is_owner.then_some(AttrValue::Static("multi"))}
                    selected_keys={selected_ids.clone()}
                    {on_selection_change}
                    columns={rule_columns}
                    header={html! {
                        <Header counter={format!("({} of {})", filtered_rules.len(), detail.rules.len())}>
                            {"Rules"}
                        </Header>
                    }}
                    filter={html! {
                        <TextFilter
                            filtering_text={(*filter).clone()}
                            filtering_placeholder="Filter rules"
                            on_change={{ let filter = filter.clone(); Callback::from(move |v: String| filter.set(v)) }}
                        />
                    }}
                />
            </SpaceBetween>

            <Modal
                visible={s.editing.is_some()}
                on_dismiss={close_edit.clone()}
                size="large"
                header={html! { {s.editing.as_ref().map(|r| r.id().to_string()).unwrap_or_default()} }}
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={close_edit.reform(|_: MouseEvent| ())}>{"Cancel"}</Button>
                            <Button variant="primary" loading={*s.saving}
                                    disabled={!is_owner || gate_violated} onclick={save_edit}>
                                {"Save"}
                            </Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                {edit_body}
            </Modal>

            <Modal
                visible={*set_status_open}
                on_dismiss={close_set_status.clone()}
                header={format!("Set status for {} rule{}", selected_ids.len(), if selected_ids.len() == 1 { "" } else { "s" })}
                testid="set-status-modal"
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={close_set_status.reform(|_: MouseEvent| ())}>{"Cancel"}</Button>
                            <Button variant="primary" loading={*set_status_busy}
                                    disabled={*set_status_busy || selected_ids.is_empty()}
                                    onclick={apply_set_status} testid="set-status-apply">
                                {"Apply"}
                            </Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <SpaceBetween direction="vertical" size="m">
                    <FormField label="Status">
                        <RadioGroup
                            value={AttrValue::from((*set_status_value).clone())}
                            on_change={{ let v = set_status_value.clone(); Callback::from(move |x: AttrValue| v.set(x.to_string())) }}
                            items={STATUSES.iter().map(|(v, l, _)| RadioItem::new(*v, *l)).collect::<Vec<_>>()}
                        />
                    </FormField>
                    <FormField
                        label="Finding details"
                        description={if set_status_closing {
                            "Applied to every selected rule. Leave blank to keep each rule's own details; \
                             rules with none cannot be closed and are left unchanged."
                        } else {
                            "Optional. Applied to every selected rule; leave blank to keep each rule's own details."
                        }}
                    >
                        <Textarea
                            value={(*set_status_details).clone()}
                            on_change={{ let d = set_status_details.clone(); Callback::from(move |x: String| d.set(x)) }}
                            rows={4}
                            testid="set-status-details"
                        />
                    </FormField>
                    {error_alert(&set_status_error)}
                </SpaceBetween>
            </Modal>

            <Modal
                visible={*s.bulk_open}
                on_dismiss={close_bulk.clone()}
                header="Bulk import rule statuses"
                size="large"
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={close_bulk.reform(|_: MouseEvent| ())}>{"Cancel"}</Button>
                            if let (BulkStep::Preview, Some(preview)) = (*s.bulk_step, &*s.bulk_preview) {
                                <Button variant="primary" loading={*s.bulk_busy}
                                        disabled={*s.bulk_busy || preview.rows.iter().all(|r| r.status == "error")}
                                        onclick={commit_bulk} testid="bulk-import-commit">
                                    {format!("Apply {} rows", bulk_rows_with(preview, "ok"))}
                                </Button>
                            }
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <SpaceBetween direction="vertical" size="m">
                    <UiBox>
                        {"CSV columns: "}<code>{"rule_id, status, finding_details"}</code>
                        {". Status must be one of "}<code>{"not_reviewed"}</code>{", "}
                        <code>{"open"}</code>{", "}<code>{"not_a_finding"}</code>{", "}
                        <code>{"not_applicable"}</code>{". "}
                        <a href={bulk_template_href} download="rule-bulk-import-template.csv"
                           data-testid="bulk-import-template">
                            {"Download template"}
                        </a>
                    </UiBox>
                    <FormField label="CSV file">
                        <input type="file" accept=".csv,text/csv" data-testid="bulk-import-input"
                               onchange={on_bulk_file} />
                    </FormField>
                    if *s.bulk_busy && *s.bulk_step == BulkStep::Pick {
                        <StatusIndicator kind="loading">{"Parsing…"}</StatusIndicator>
                    }
                    {error_alert(&s.bulk_error)}
                    if let Some(done) = &*s.bulk_success {
                        <Alert kind="success" testid="bulk-import-success">
                            {format!("Applied {} rule{}.", done.applied_count, if done.applied_count == 1 { "" } else { "s" })}
                        </Alert>
                    }
                    if let Some(preview) = &*s.bulk_preview {
                        if bulk_rows_with(preview, "error") > 0 {
                            <Alert kind="warning">
                                {format!("{} rows have errors and will be skipped.", bulk_rows_with(preview, "error"))}
                            </Alert>
                        }
                        <Table<BulkRow>
                            variant="embedded"
                            items={preview.rows.clone()}
                            track_by={Callback::from(|r: BulkRow| r.row_number.to_string())}
                            columns={bulk_columns}
                            empty={html! { <UiBox>{"No rows."}</UiBox> }}
                        />
                    }
                </SpaceBetween>
            </Modal>
        </UiBox>
    }
}

fn or_dash(s: &str) -> String {
    if s.is_empty() { "—".to_string() } else { s.to_string() }
}

/// One comment of the rule's thread: author line, then either the inline
/// editor or the body with its reaction and edit/delete buttons.
fn comment_item(s: &ViewState, rule_id: &str, c: &Comment, current_user_id: Option<&str>) -> Html {
    let is_author = current_user_id == Some(c.user_id.as_str());
    let is_editing_this = s.editing_comment_id.as_deref() == Some(c.id.as_str());

    let content = if is_editing_this {
        let on_input = {
            let body = s.editing_comment_body.clone();
            Callback::from(move |e: InputEvent| body.set(event_value(&e)))
        };
        let save = {
            let (s, rule_id, id) = (s.clone(), rule_id.to_string(), c.id.clone());
            Callback::from(move |_: MouseEvent| {
                let (s, rule_id, id) = (s.clone(), rule_id.clone(), id.clone());
                let body = (*s.editing_comment_body).clone();
                spawn_local(async move { s.save_edit_comment(rule_id, id, body).await });
            })
        };
        let cancel = {
            let s = s.clone();
            Callback::from(move |_: MouseEvent| {
                s.editing_comment_id.set(None);
                s.editing_comment_body.set(String::new());
            })
        };
        html! {
            <SpaceBetween direction="vertical" size="xs">
                // A plain textarea rather than the kit one: `defaultvalue`
                // puts the original body in the element's text content,
                // which is how the e2e suite locates the inline editor.
                <span class="ui-textarea-wrap">
                    <textarea class="ui-textarea" rows="3" value={(*s.editing_comment_body).clone()}
                              defaultvalue={c.body.clone()} oninput={on_input} />
                </span>
                <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="primary" onclick={save} testid="rule-comment-save-edit">{"Save"}</Button>
                    <Button variant="link" onclick={cancel}>{"Cancel"}</Button>
                </SpaceBetween>
            </SpaceBetween>
        }
    } else {
        let start_edit = {
            let (s, id, body) = (s.clone(), c.id.clone(), c.body.clone());
            Callback::from(move |_: MouseEvent| {
                s.editing_comment_id.set(Some(id.clone()));
                s.editing_comment_body.set(body.clone());
                s.comment_error.set(None);
            })
        };
        let delete = {
            let (s, rule_id, id) = (s.clone(), rule_id.to_string(), c.id.clone());
            Callback::from(move |_: MouseEvent| {
                let (s, rule_id, id) = (s.clone(), rule_id.clone(), id.clone());
                spawn_local(async move { s.delete_comment(rule_id, id).await });
            })
        };
        html! {
            <>
                <UiBox>{c.body.clone()}</UiBox>
                <SpaceBetween direction="horizontal" size="xxs">
                    { for REACTION_TYPES.iter().map(|&(key, emoji)| {
                        let summary = c.reactions.get(key).copied().unwrap_or_default();
                        let toggle = {
                            let (s, rule_id, id) = (s.clone(), rule_id.to_string(), c.id.clone());
                            Callback::from(move |_: MouseEvent| {
                                let (s, rule_id, id) = (s.clone(), rule_id.clone(), id.clone());
                                spawn_local(async move { s.toggle_reaction(rule_id, id, key, summary.mine).await });
                            })
                        };
                        html! {
                            <Button key={key} variant={if summary.mine { "primary" } else { "inline-link" }}
                                    aria_pressed={summary.mine} onclick={toggle}
                                    testid={format!("rule-comment-reaction-{key}")}>
                                {format!("{emoji} {}", summary.count)}
                            </Button>
                        }
                    }) }
                </SpaceBetween>
                <SpaceBetween direction="horizontal" size="xxs">
                    <Button variant="inline-link" disabled={!is_author} onclick={start_edit} testid="rule-comment-edit">
                        {"Edit"}
                    </Button>
                    <Button variant="inline-link" disabled={!is_author} onclick={delete} testid="rule-comment-delete">
                        {"Delete"}
                    </Button>
                </SpaceBetween>
            </>
        }
    };

    html! {
        <UiBox key={c.id.clone()} padding="s" testid="rule-comment">
            <SpaceBetween direction="vertical" size="xxs">
                <UiBox variant="small" color="text-body-secondary">
                    <strong>{c.user_name.clone()}</strong>
                    {" · "}
                    {to_locale_string(&c.created_at)}
                    if c.edited_at.is_some() { {" (edited)"} }
                </UiBox>
                {content}
            </SpaceBetween>
        </UiBox>
    }
}

#[cfg(test)]
mod bulk_status_summary_tests {
    use super::*;

    #[test]
    fn single_rule_wording() {
        let r = BulkStatusResponse { applied_count: 1, ..Default::default() };
        assert_eq!(bulk_status_summary("Open", &r), "Set 1 rule to Open.");
    }

    #[test]
    fn mentions_review_and_unchanged_counts() {
        let r = BulkStatusResponse { applied_count: 3, pending_count: 2, ..Default::default() };
        assert_eq!(bulk_status_summary("Open", &r), "Set 3 rules to Open. 2 submitted for review.");
        let r = BulkStatusResponse { applied_count: 0, error_count: 4, ..Default::default() };
        assert_eq!(bulk_status_summary("Open", &r), "Set 0 rules to Open. 4 not changed.");
    }
}

#[cfg(test)]
mod severity_badge_tests {
    use super::*;

    #[test]
    fn maps_cat_levels_to_severity_classes() {
        assert_eq!(severity_color("CAT I"), "severity-high");
        assert_eq!(severity_color("CAT II"), "severity-medium");
        assert_eq!(severity_color("CAT III"), "severity-low");
        assert_eq!(severity_color("unknown"), "grey");
    }
}
