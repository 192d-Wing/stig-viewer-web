//! Admin console: background jobs, sessions, users/roles, approvals, asset
//! ownership, audit search, ABAC policies, webhooks, compliance reports,
//! email deliveries and backup/restore.
//!
//! The root component owns the data every section shares (one `refresh`
//! reloads all of it); each section is a private component holding its own
//! form / modal state.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::rc::Rc;

use serde::Deserialize;
use serde_json::{json, Value};
use wasm_bindgen::JsValue;
use yew::prelude::*;

use crate::api::{api_fetch, api_get, api_json, api_upload_raw, response_blob, BACKEND};
use crate::hooks::use_interval;
use crate::ui::*;
use crate::util::{
    confirm, copy_to_clipboard, download_blob, encode_uri_component, now_iso, now_ms,
    parse_date_ms, spawn_local, to_locale_date_string, to_locale_string, window,
};

// ── Option tables ───────────────────────────────────────────────────────────

/// (label, value)
type OptionTable = &'static [(&'static str, &'static str)];

const ROLE_OPTIONS: OptionTable = &[
    ("Author", "author"),
    ("Reviewer", "reviewer"),
    ("Admin", "admin"),
    ("Viewer", "viewer"),
];

// Event kinds the backend currently knows how to fire. Keep in sync
// with ALLOWED_KINDS in backend/src/api/webhooks.rs — the create/update
// handlers reject anything outside that set with a 400.
const KIND_OPTIONS: OptionTable = &[
    ("Assigned", "assigned"),
    ("Overdue digest", "overdue_digest"),
    ("Compliance report", "compliance_report"),
];

// Wire-payload flavor a webhook is configured to receive. Keep in sync
// with ALLOWED_FLAVORS in backend/src/api/webhooks.rs.
const FLAVOR_OPTIONS: OptionTable = &[
    ("Slack", "slack"),
    ("Microsoft Teams", "teams"),
    ("Generic", "generic"),
];

// ABAC effect/level enumerations. Mirror the validation in
// backend/src/api/abac.rs — anything outside these sets is rejected
// with 400 by the create/update handlers.
const POLICY_EFFECT_OPTIONS: OptionTable = &[("Allow", "allow"), ("Deny", "deny")];
const POLICY_LEVEL_OPTIONS: OptionTable =
    &[("Read", "read"), ("Write", "write"), ("Admin", "admin")];
// Role options for the policy modal — the wildcard "Any role" row
// maps to an empty string, which the backend stores as NULL.
const POLICY_ROLE_OPTIONS: OptionTable = &[
    ("Any role", ""),
    ("Author", "author"),
    ("Reviewer", "reviewer"),
    ("Admin", "admin"),
    ("Viewer", "viewer"),
];

// Five known scheduler names, ordered the way ops scan them. We
// render a row per name even if no run has happened yet so the
// dashboard is recognizable as soon as the table loads.
const SCHEDULER_NAMES: [&str; 5] = [
    "sync",
    "snapshot",
    "overdue_digest",
    "audit_retention",
    "compliance_report",
];

const AUDIT_PAGE_SIZE: i64 = 50;

fn select_options(table: OptionTable) -> Vec<SelectOption> {
    table
        .iter()
        .map(|(label, value)| SelectOption::new(*value, *label))
        .collect()
}

/// The option matching `value`, falling back to the first one (the
/// `OPTIONS.find(...) ?? OPTIONS[0]` idiom).
fn pick(table: OptionTable, value: &str) -> Option<AttrValue> {
    table
        .iter()
        .find(|(_, v)| *v == value)
        .or(table.first())
        .map(|(_, v)| AttrValue::from(*v))
}

fn role_label(value: &str) -> String {
    ROLE_OPTIONS
        .iter()
        .find(|(_, v)| *v == value)
        .map(|(label, _)| (*label).to_string())
        .unwrap_or_else(|| value.to_string())
}

fn role_badge(role: &str) -> &'static str {
    match role {
        "author" => "blue",
        "reviewer" => "green",
        "admin" => "red",
        _ => "grey",
    }
}

/// Per-flavor Badge color for the webhooks table.
fn flavor_badge(flavor: &str) -> &'static str {
    match flavor {
        "slack" => "blue",
        "teams" => "red", // Badge has no "purple" — red is its closest accent.
        _ => "grey",
    }
}

// ── Formatting helpers ──────────────────────────────────────────────────────

/// Human-readable relative time. Falls back to absolute when older than ~30d.
fn relative_time(iso: Option<&str>) -> String {
    let Some(iso) = iso.filter(|s| !s.is_empty()) else {
        return "Never".into();
    };
    let then = parse_date_ms(iso);
    if then.is_nan() {
        return "Never".into();
    }
    let sec = ((now_ms() - then) / 1000.0).floor();
    if sec < 60.0 {
        return format!("{sec}s ago");
    }
    let min = (sec / 60.0).floor();
    if min < 60.0 {
        return format!("{min}m ago");
    }
    let hr = (min / 60.0).floor();
    if hr < 24.0 {
        return format!("{hr}h ago");
    }
    let day = (hr / 24.0).floor();
    if day < 30.0 {
        return format!("{day}d ago");
    }
    to_locale_date_string(iso)
}

fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Show a truncated value; callers put the full value in a hover title.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        format!("{}…", head(s, max - 1))
    } else {
        s.to_string()
    }
}

fn or_dash(s: &str) -> String {
    if s.is_empty() {
        "—".into()
    } else {
        s.to_string()
    }
}

fn empty_note(text: &'static str) -> Html {
    html! {
        <UiBox text_align="center" padding="l">
            <UiBox variant="p" color="text-body-secondary">{text}</UiBox>
        </UiBox>
    }
}

fn empty_plain(text: &'static str) -> Html {
    html! { <UiBox text_align="center" padding="l">{text}</UiBox> }
}

fn status_badge(status: &str) -> Html {
    let color = match status {
        "ok" => "green",
        "error" => "red",
        "running" => "blue",
        _ => "grey",
    };
    html! { <Badge {color}>{status.to_string()}</Badge> }
}

/// Click handler that emits a fixed value.
fn click<T: Clone + 'static>(cb: &Callback<T>, value: &T) -> Callback<MouseEvent> {
    let cb = cb.clone();
    let value = value.clone();
    Callback::from(move |_| cb.emit(value.clone()))
}

// ── API payloads ────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AdminUser {
    id: String,
    display_name: String,
    email: String,
    role: String,
    last_login: Option<String>,
    created_at: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AssetSummary {
    id: String,
    name: String,
    owner_name: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Webhook {
    id: String,
    name: String,
    url: String,
    /// Whether a signing secret is set. The secret itself is never returned.
    signed: bool,
    kinds: Option<Vec<String>>,
    enabled: bool,
    flavor: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Delivery {
    kind: String,
    http_status: Option<i32>,
    response: Option<String>,
    error: Option<String>,
    attempted_at: Option<String>,
}

/// Shape of the backend's `VerifyRecipe` struct (the parts the modal shows).
#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(default)]
struct VerifyRecipe {
    name: String,
    snippets: VerifySnippets,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(default)]
struct VerifySnippets {
    curl: String,
    python: String,
    node: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Report {
    id: String,
    generated_at: String,
    summary: Option<ReportSummary>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ReportSummary {
    assets: i64,
    compliance_score: f64,
    open_findings: i64,
    top_asset_name: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct EmailDelivery {
    kind: String,
    to_addresses: String,
    subject: String,
    mode: String,
    error: Option<String>,
    attempted_at: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Approval {
    id: String,
    rule_id: String,
    requested_at: Option<String>,
    proposed_status: String,
    asset_name: String,
    stig_title: String,
    requested_by_name: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SchedulerRun {
    name: String,
    started_at: Option<String>,
    finished_at: Option<String>,
    status: String,
    message: Option<String>,
}

/// Background-job dashboard payload: latest row per scheduler name plus
/// the most recent ticks across all of them.
#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(default)]
struct SchedulerRuns {
    latest: HashMap<String, SchedulerRun>,
    history: Vec<SchedulerRun>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Session {
    id: String,
    user_name: String,
    ip: String,
    user_agent: String,
    created_at: Option<String>,
    expires_at: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Policy {
    id: String,
    name: String,
    effect: String,
    level: String,
    role_match: Option<String>,
    classification_match: Option<String>,
    tag_match: Option<String>,
    enabled: bool,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AuditRow {
    occurred_at: Option<String>,
    by_name: String,
    asset_name: Option<String>,
    stig_title: Option<String>,
    rule_id: String,
    field: String,
    from_value: Option<String>,
    to_value: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AuditSearch {
    total_count: i64,
    rows: Vec<AuditRow>,
}

/// One request-level event from `/api/audit/events`.
#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AuditEventRow {
    occurred_at: Option<String>,
    /// `null` for system rows; `is_system` is authoritative.
    by_name: Option<String>,
    /// Server-computed: the event has no acting user. The UI keys on this,
    /// never on the `by_name` text.
    is_system: bool,
    asset_name: Option<String>,
    stig_title: Option<String>,
    action: String,
    outcome: String,
    detail: Value,
    source_ip: Option<String>,
    request_id: Option<String>,
    user_role: Option<String>,
    /// How many identical denied/rejected requests this row stands for.
    repeat_count: i64,
    last_occurred_at: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AuditEvents {
    total_count: i64,
    rows: Vec<AuditEventRow>,
}

/// The Count cell: "×N" for a collapsed row (with the last occurrence), else "1".
fn repeat_label(e: &AuditEventRow) -> String {
    if e.repeat_count > 1 {
        match e.last_occurred_at.as_deref().filter(|s| !s.is_empty()) {
            Some(last) => format!("\u{d7}{} (last {})", e.repeat_count, to_locale_string(last)),
            None => format!("\u{d7}{}", e.repeat_count),
        }
    } else {
        "1".into()
    }
}

/// One-line summary of an event's `detail` (counts and reason codes only).
fn event_summary(e: &AuditEventRow) -> String {
    let d = &e.detail;
    if let Some(reason) = d.get("reason").and_then(Value::as_str) {
        return reason.replace('_', " ");
    }
    let n = |k: &str| d.get(k).and_then(Value::as_i64);
    let mut parts = Vec::new();
    if let Some(s) = d.get("targetStatus").and_then(Value::as_str) {
        parts.push(format!("status {s}"));
    }
    for (key, label) in [
        ("requested", "requested"),
        ("applied", "applied"),
        ("pending", "pending"),
        ("unchanged", "unchanged"),
        ("errors", "errors"),
    ] {
        if let Some(v) = n(key) {
            parts.push(format!("{v} {label}"));
        }
    }
    if d.get("created").and_then(Value::as_bool) == Some(true) {
        parts.push("checklist created".into());
    }
    if parts.is_empty() {
        "—".into()
    } else {
        parts.join(", ")
    }
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RestoreResult {
    restored: HashMap<String, i64>,
    attachments_written: i64,
    forced: Option<bool>,
    /// `verified`, `unsigned` or `unknown_key`.
    signature_status: String,
}

impl RestoreResult {
    /// Alert kind and text for the outcome. Anything but a verified signature
    /// is a warning that the backup's integrity was not verified.
    fn summary(&self) -> (&'static str, String) {
        let base = format!(
            "Restored {} rows across {} tables and {} attachment blob(s){}.",
            self.restored.values().sum::<i64>(),
            self.restored.len(),
            self.attachments_written,
            if self.forced == Some(true) {
                " (force overwrite)"
            } else {
                ""
            },
        );
        match self.signature_status.as_str() {
            "verified" => ("success", format!("{base} Signature verified.")),
            other => (
                "warning",
                format!(
                    "{base} Warning: this backup's integrity was not verified (signature status: {}).",
                    if other.is_empty() { "not reported" } else { other }
                ),
            ),
        }
    }
}

// ── Shared console state ────────────────────────────────────────────────────

/// Data shared by every section, plus the page-level error / flash banners.
/// Handed to each section so it can read the lists and trigger a reload.
#[derive(Clone, PartialEq)]
struct Console {
    users: UseStateHandle<Vec<AdminUser>>,
    assets: UseStateHandle<Vec<AssetSummary>>,
    webhooks: UseStateHandle<Vec<Webhook>>,
    reports: UseStateHandle<Vec<Report>>,
    // Outbound email deliveries (compliance-report emails, dryrun + sent)
    emails: UseStateHandle<Vec<EmailDelivery>>,
    // Pending finding-close approval queue. Reviewer/admin only — for
    // anyone else the GET returns just their own rows (which is fine,
    // AdminConsole is gated by an admin route anyway).
    approvals: UseStateHandle<Vec<Approval>>,
    scheduler_runs: UseStateHandle<SchedulerRuns>,
    sessions: UseStateHandle<Vec<Session>>,
    policies: UseStateHandle<Vec<Policy>>,
    loading: UseStateHandle<bool>,
    error: UseStateHandle<Option<String>>,
    test_flash: UseStateHandle<Option<String>>,
}

/// Start `fut` now and park its output in a slot, so several requests can run
/// concurrently and be awaited together with `Promise.all`.
fn start<T: 'static>(
    fut: impl Future<Output = T> + 'static,
) -> (Rc<RefCell<Option<T>>>, js_sys::Promise) {
    let slot = Rc::new(RefCell::new(None));
    let out = slot.clone();
    let promise = wasm_bindgen_futures::future_to_promise(async move {
        *out.borrow_mut() = Some(fut.await);
        Ok(JsValue::UNDEFINED)
    });
    (slot, promise)
}

fn finished<T>(slot: &Rc<RefCell<Option<Result<T, String>>>>) -> Result<T, String> {
    slot.borrow_mut()
        .take()
        .unwrap_or_else(|| Err("request did not complete".to_string()))
}

impl Console {
    /// Reload everything. Users and assets are required; the other feeds
    /// fall back to empty so one broken endpoint doesn't blank the console.
    async fn refresh(&self) {
        self.loading.set(true);
        self.error.set(None);
        let (users, p1) = start(api_get::<Vec<AdminUser>>("/api/admin/users"));
        let (assets, p2) = start(api_get::<Vec<AssetSummary>>("/api/assets"));
        let (webhooks, p3) = start(api_get::<Vec<Webhook>>("/api/webhooks"));
        let (reports, p4) = start(api_get::<Vec<Report>>("/api/reports"));
        let (emails, p5) = start(api_get::<Vec<EmailDelivery>>("/api/admin/email-deliveries"));
        let (approvals, p6) = start(api_get::<Vec<Approval>>("/api/approvals?status=pending"));
        let (runs, p7) = start(api_get::<SchedulerRuns>("/api/admin/scheduler-runs"));
        let (sessions, p8) = start(api_get::<Vec<Session>>("/api/admin/sessions"));
        let (policies, p9) = start(api_get::<Vec<Policy>>("/api/admin/policies"));
        let all: js_sys::Array = [p1, p2, p3, p4, p5, p6, p7, p8, p9].iter().collect();
        let _ = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::all(&all)).await;

        match (finished(&users), finished(&assets)) {
            (Ok(u), Ok(a)) => {
                self.users.set(u);
                self.assets.set(a);
                self.webhooks.set(finished(&webhooks).unwrap_or_default());
                self.reports.set(finished(&reports).unwrap_or_default());
                self.emails.set(finished(&emails).unwrap_or_default());
                self.approvals.set(finished(&approvals).unwrap_or_default());
                self.scheduler_runs.set(finished(&runs).unwrap_or_default());
                self.sessions.set(finished(&sessions).unwrap_or_default());
                self.policies.set(finished(&policies).unwrap_or_default());
            }
            (Err(e), _) | (_, Err(e)) => self.error.set(Some(e)),
        }
        self.loading.set(false);
    }

    fn fail(&self, message: String) {
        self.error.set(Some(message));
    }

    fn asset_options(&self) -> Vec<SelectOption> {
        self.assets
            .iter()
            .map(|a| {
                SelectOption::new(a.id.clone(), a.name.clone())
                    .description(format!("Owner: {}", a.owner_name))
            })
            .collect()
    }

    fn user_options(&self) -> Vec<SelectOption> {
        self.users
            .iter()
            .map(|u| {
                let description = if u.email.is_empty() {
                    role_label(&u.role)
                } else {
                    u.email.clone()
                };
                SelectOption::new(u.id.clone(), u.display_name.clone()).description(description)
            })
            .collect()
    }
}

/// Body-less request that must come back 2xx; errors read "<what> failed: <status>".
async fn expect_ok(method: &str, path: &str, what: &str) -> Result<(), String> {
    let res = api_fetch(method, path).await?;
    if res.ok() {
        Ok(())
    } else {
        Err(format!("{what} failed: {}", res.status()))
    }
}

#[derive(Properties, PartialEq)]
struct SectionProps {
    console: Console,
}

// ── Root ────────────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct AdminConsoleProps {}

#[function_component]
pub fn AdminConsole(_props: &AdminConsoleProps) -> Html {
    let users = use_state(Vec::new);
    let assets = use_state(Vec::new);
    let webhooks = use_state(Vec::new);
    let reports = use_state(Vec::new);
    let emails = use_state(Vec::new);
    let approvals = use_state(Vec::new);
    let scheduler_runs = use_state(SchedulerRuns::default);
    let sessions = use_state(Vec::new);
    let policies = use_state(Vec::new);
    let loading = use_state(|| true);
    let error = use_state(|| None);
    let test_flash = use_state(|| None);
    let console = Console {
        users,
        assets,
        webhooks,
        reports,
        emails,
        approvals,
        scheduler_runs,
        sessions,
        policies,
        loading,
        error,
        test_flash,
    };

    {
        let console = console.clone();
        use_effect_with((), move |_| {
            spawn_local(async move { console.refresh().await });
        });
    }

    // Poll the background-job feed every 10s so the admin sees ticks
    // land without manually refreshing. We only re-fetch the scheduler
    // endpoint here (not the whole console) to keep this cheap.
    {
        let runs = console.scheduler_runs.clone();
        use_interval(
            (),
            10_000,
            Callback::from(move |_| {
                let runs = runs.clone();
                spawn_local(async move {
                    // Errors are silently ignored — the manual Refresh surfaces real ones.
                    if let Ok(sr) = api_get::<SchedulerRuns>("/api/admin/scheduler-runs").await {
                        runs.set(sr);
                    }
                });
            }),
        );
    }

    let dismiss_flash = {
        let flash = console.test_flash.clone();
        Callback::from(move |_: ()| flash.set(None))
    };

    html! {
        <SpaceBetween direction="vertical" size="l">
            if let Some(e) = &*console.error {
                <Alert kind="error">{e.clone()}</Alert>
            }
            if let Some(flash) = &*console.test_flash {
                <Alert kind="success" dismissible=true on_dismiss={dismiss_flash}>{flash.clone()}</Alert>
            }
            {scheduler_tables(&console.scheduler_runs)}
            <SessionsSection console={console.clone()} />
            <UsersSection console={console.clone()} />
            <ApprovalsSection console={console.clone()} />
            <OwnerSection console={console.clone()} />
            <AuditSection console={console.clone()} />
            <PoliciesSection console={console.clone()} />
            <WebhooksSection console={console.clone()} />
            {reports_table(&console.reports)}
            {emails_table(&console.emails)}
            <BackupSection console={console.clone()} />
        </SpaceBetween>
    }
}

// ── Background jobs ─────────────────────────────────────────────────────────

fn scheduler_columns() -> Vec<Column<SchedulerRun>> {
    vec![
        Column::new(
            "name",
            "Scheduler",
            |r: &SchedulerRun| html! { {r.name.clone()} },
        ),
        Column::new("started", "Started", |r: &SchedulerRun| {
            html! { {r.started_at.as_deref().filter(|s| !s.is_empty()).map(|s| relative_time(Some(s))).unwrap_or_else(|| "—".into())} }
        }),
        Column::new("finished", "Finished", |r: &SchedulerRun| {
            html! { {r.finished_at.as_deref().filter(|s| !s.is_empty()).map(|s| relative_time(Some(s))).unwrap_or_else(|| "—".into())} }
        }),
        Column::new("status", "Status", |r: &SchedulerRun| {
            status_badge(&r.status)
        }),
        Column::new("message", "Message", |r: &SchedulerRun| {
            let message = r.message.clone().unwrap_or_default();
            html! { <UiBox variant="code" title={message.clone()}>{head(&message, 80)}</UiBox> }
        }),
    ]
}

fn scheduler_tables(runs: &SchedulerRuns) -> Html {
    let latest_rows: Vec<SchedulerRun> = SCHEDULER_NAMES
        .iter()
        .map(|name| {
            runs.latest
                .get(*name)
                .cloned()
                .unwrap_or_else(|| SchedulerRun {
                    name: (*name).to_string(),
                    status: "—".into(),
                    ..Default::default()
                })
        })
        .collect();
    html! {
        <>
            <Table<SchedulerRun>
                variant="container"
                items={latest_rows}
                columns={scheduler_columns()}
                empty={empty_note("No scheduler runs yet.")}
                header={html! {
                    <Header counter={format!("({}/{})", runs.latest.len(), SCHEDULER_NAMES.len())}
                            description="Latest tick per background scheduler. Auto-refreshes every 10 seconds.">
                        {"Background jobs"}
                    </Header>
                }}
                testid="scheduler-latest-table"
            />
            <Table<SchedulerRun>
                variant="container"
                items={runs.history.clone()}
                columns={scheduler_columns()}
                empty={empty_note("No run history yet.")}
                header={html! {
                    <Header counter={format!("({})", runs.history.len())}
                            description="Most recent 10 scheduler ticks across every job, newest first.">
                        {"Recent scheduler history"}
                    </Header>
                }}
                testid="scheduler-history-table"
            />
        </>
    }
}

// ── Active sessions ─────────────────────────────────────────────────────────

/// Active sessions audit. Populated from /api/admin/sessions and
/// pruned when the admin clicks Revoke on a row.
#[function_component]
fn SessionsSection(props: &SectionProps) -> Html {
    let console = &props.console;
    let busy_id = use_state(|| None::<String>);

    let revoke = {
        let console = console.clone();
        let busy_id = busy_id.clone();
        Callback::from(move |id: String| {
            let console = console.clone();
            let busy_id = busy_id.clone();
            spawn_local(async move {
                busy_id.set(Some(id.clone()));
                match expect_ok("DELETE", &format!("/api/admin/sessions/{id}"), "Revoke").await {
                    Ok(()) => console.refresh().await,
                    Err(e) => console.fail(e),
                }
                busy_id.set(None);
            });
        })
    };

    let busy = (*busy_id).clone();
    let columns = vec![
        Column::new(
            "user",
            "User",
            |s: &Session| html! { {s.user_name.clone()} },
        ),
        Column::new("ip", "IP", |s: &Session| html! { {or_dash(&s.ip)} }),
        Column::new("user_agent", "User-Agent", |s: &Session| {
            let shown = if s.user_agent.is_empty() {
                "—".to_string()
            } else {
                truncate(&s.user_agent, 60)
            };
            html! { <span title={s.user_agent.clone()}>{shown}</span> }
        }),
        Column::new(
            "created",
            "Created",
            |s: &Session| html! { {relative_time(s.created_at.as_deref())} },
        ),
        Column::new("expires", "Expires", |s: &Session| {
            html! { {s.expires_at.as_deref().filter(|e| !e.is_empty()).map(to_locale_string).unwrap_or_else(|| "—".into())} }
        }),
        Column::new("actions", "", move |s: &Session| {
            html! {
                <Button variant="inline-link" loading={busy.as_ref() == Some(&s.id)}
                        onclick={click(&revoke, &s.id)} testid={format!("revoke-session-{}", s.id)}>
                    {"Revoke"}
                </Button>
            }
        }),
    ];

    html! {
        <Table<Session>
            variant="container"
            items={(*console.sessions).clone()}
            loading={*console.loading}
            loading_text="Loading active sessions"
            empty={empty_note("No active sessions.")}
            {columns}
            header={html! {
                <Header counter={format!("({})", console.sessions.len())}
                        description="Currently-active sessions across every user. Revoke forces a re-login on the next request without touching the audit row.">
                    {"Active sessions"}
                </Header>
            }}
            testid="active-sessions-table"
        />
    }
}

// ── Users + role modal ──────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
struct RoleEdit {
    user: AdminUser,
    role: String,
}

#[function_component]
fn UsersSection(props: &SectionProps) -> Html {
    let console = &props.console;
    let modal = use_state(|| None::<RoleEdit>);
    let submitting = use_state(|| false);
    let error = use_state(|| None::<String>);

    let open = {
        let modal = modal.clone();
        let error = error.clone();
        Callback::from(move |user: AdminUser| {
            let role = user.role.clone();
            modal.set(Some(RoleEdit { user, role }));
            error.set(None);
        })
    };
    let close = {
        let modal = modal.clone();
        Callback::from(move |_: ()| modal.set(None))
    };
    let submit = {
        let console = console.clone();
        let modal = modal.clone();
        let submitting = submitting.clone();
        let error = error.clone();
        Callback::from(move |_: MouseEvent| {
            let Some(edit) = (*modal).clone() else { return };
            let (console, modal, submitting, error) = (
                console.clone(),
                modal.clone(),
                submitting.clone(),
                error.clone(),
            );
            spawn_local(async move {
                submitting.set(true);
                error.set(None);
                let path = format!("/api/admin/users/{}/role", edit.user.id);
                match api_json::<Value, _>(&path, "PATCH", Some(&json!({ "role": edit.role })))
                    .await
                {
                    Ok(_) => {
                        modal.set(None);
                        console.refresh().await;
                    }
                    Err(e) => error.set(Some(e)),
                }
                submitting.set(false);
            });
        })
    };
    let set_role = {
        let modal = modal.clone();
        Callback::from(move |o: SelectOption| {
            if let Some(mut edit) = (*modal).clone() {
                edit.role = o.value.to_string();
                modal.set(Some(edit));
            }
        })
    };
    let refresh = {
        let console = console.clone();
        Callback::from(move |_: MouseEvent| {
            let console = console.clone();
            spawn_local(async move { console.refresh().await });
        })
    };

    let columns = vec![
        Column::new(
            "display_name",
            "Display name",
            |u: &AdminUser| html! { {u.display_name.clone()} },
        ),
        Column::new(
            "email",
            "Email",
            |u: &AdminUser| html! { {or_dash(&u.email)} },
        ),
        Column::new("role", "Role", |u: &AdminUser| {
            html! { <Badge color={role_badge(&u.role)}>{role_label(&u.role)}</Badge> }
        }),
        Column::new(
            "last_login",
            "Last login",
            |u: &AdminUser| html! { {relative_time(u.last_login.as_deref())} },
        ),
        Column::new("created", "Created", |u: &AdminUser| {
            html! { {u.created_at.as_deref().filter(|c| !c.is_empty()).map(to_locale_date_string).unwrap_or_else(|| "—".into())} }
        }),
        Column::new("actions", "", move |u: &AdminUser| {
            html! { <Button variant="inline-link" onclick={click(&open, u)}>{"Change role"}</Button> }
        }),
    ];

    let editing_name = modal
        .as_ref()
        .map(|m| m.user.display_name.clone())
        .unwrap_or_default();
    let editing_role = modal.as_ref().map(|m| m.role.clone()).unwrap_or_default();
    html! {
        <>
            <Table<AdminUser>
                items={(*console.users).clone()}
                {columns}
                loading={*console.loading}
                loading_text="Loading users"
                empty={empty_plain("No users yet.")}
                header={html! {
                    <Header counter={format!("({})", console.users.len())}
                            actions={html! {
                                <Button icon_name="refresh" onclick={refresh} loading={*console.loading}>{"Refresh"}</Button>
                            }}>
                        {"Users"}
                    </Header>
                }}
            />
            <Modal
                visible={modal.is_some()}
                on_dismiss={close.clone()}
                header={Html::from(format!("Change role: {editing_name}"))}
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={close.reform(|_: MouseEvent| ())}>{"Cancel"}</Button>
                            <Button variant="primary" loading={*submitting} onclick={submit}>{"Save"}</Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <SpaceBetween direction="vertical" size="m">
                    <FormField label="Role">
                        <Select selected={pick(ROLE_OPTIONS, &editing_role)} on_change={set_role}
                                options={select_options(ROLE_OPTIONS)} />
                    </FormField>
                    if let Some(e) = &*error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                </SpaceBetween>
            </Modal>
        </>
    }
}

// ── Approval queue + reject modal ───────────────────────────────────────────

#[function_component]
fn ApprovalsSection(props: &SectionProps) -> Html {
    let console = &props.console;
    let approve_busy_id = use_state(|| None::<String>);
    let reject_modal = use_state(|| None::<Approval>);
    let reject_reason = use_state(String::new);
    let reject_busy = use_state(|| false);
    let reject_error = use_state(|| None::<String>);

    let approve = {
        let console = console.clone();
        let busy_id = approve_busy_id.clone();
        Callback::from(move |id: String| {
            let console = console.clone();
            let busy_id = busy_id.clone();
            spawn_local(async move {
                busy_id.set(Some(id.clone()));
                match api_json::<Value, _>(
                    &format!("/api/approvals/{id}/approve"),
                    "POST",
                    Some(&json!({})),
                )
                .await
                {
                    Ok(_) => console.refresh().await,
                    Err(e) => console.fail(e),
                }
                busy_id.set(None);
            });
        })
    };
    let open_reject = {
        let (modal, reason, error) = (
            reject_modal.clone(),
            reject_reason.clone(),
            reject_error.clone(),
        );
        Callback::from(move |row: Approval| {
            modal.set(Some(row));
            reason.set(String::new());
            error.set(None);
        })
    };
    let close_reject = {
        let modal = reject_modal.clone();
        Callback::from(move |_: ()| modal.set(None))
    };
    let submit_reject = {
        let console = console.clone();
        let (modal, reason, busy, error) = (
            reject_modal.clone(),
            reject_reason.clone(),
            reject_busy.clone(),
            reject_error.clone(),
        );
        Callback::from(move |_: MouseEvent| {
            let Some(row) = (*modal).clone() else { return };
            let text = reason.trim().to_string();
            if text.is_empty() {
                error.set(Some("A reason is required to reject an approval.".into()));
                return;
            }
            let console = console.clone();
            let (modal, reason, busy, error) =
                (modal.clone(), reason.clone(), busy.clone(), error.clone());
            spawn_local(async move {
                busy.set(true);
                error.set(None);
                let path = format!("/api/approvals/{}/reject", row.id);
                match api_json::<Value, _>(&path, "POST", Some(&json!({ "reason": text }))).await {
                    Ok(_) => {
                        modal.set(None);
                        reason.set(String::new());
                        console.refresh().await;
                    }
                    Err(e) => error.set(Some(e)),
                }
                busy.set(false);
            });
        })
    };
    let on_reason = {
        let reason = reject_reason.clone();
        Callback::from(move |v: String| reason.set(v))
    };

    let busy = (*approve_busy_id).clone();
    let columns = vec![
        Column::new(
            "asset",
            "Asset",
            |r: &Approval| html! { {r.asset_name.clone()} },
        ),
        Column::new(
            "stig",
            "STIG",
            |r: &Approval| html! { {r.stig_title.clone()} },
        ),
        Column::new("rule", "Rule", |r: &Approval| html! { {r.rule_id.clone()} }),
        Column::new(
            "proposed",
            "Proposed status",
            |r: &Approval| html! { <Badge>{r.proposed_status.clone()}</Badge> },
        ),
        Column::new(
            "requested_by",
            "Requested by",
            |r: &Approval| html! { {r.requested_by_name.clone()} },
        ),
        Column::new(
            "requested_at",
            "Requested",
            |r: &Approval| html! { {relative_time(r.requested_at.as_deref())} },
        ),
        Column::new("actions", "", move |r: &Approval| {
            html! {
                <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="primary" loading={busy.as_ref() == Some(&r.id)}
                            onclick={click(&approve, &r.id)} testid={format!("approve-{}", r.id)}>
                        {"Approve"}
                    </Button>
                    <Button onclick={click(&open_reject, r)} testid={format!("reject-{}", r.id)}>{"Reject"}</Button>
                </SpaceBetween>
            }
        }),
    ];

    html! {
        <>
            <Table<Approval>
                items={(*console.approvals).clone()}
                loading={*console.loading}
                loading_text="Loading approvals"
                empty={empty_note("No pending approvals.")}
                {columns}
                header={html! {
                    <Header counter={format!("({})", console.approvals.len())}
                            description="Closing transitions on assets with the approval policy enabled. Approve to apply the proposed status; reject with a reason to keep the rule open.">
                        {"Pending finding-close approvals"}
                    </Header>
                }}
                testid="approvals-table"
            />
            <Modal
                visible={reject_modal.is_some()}
                on_dismiss={close_reject.clone()}
                header="Reject approval request"
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={close_reject.reform(|_: MouseEvent| ())}>{"Cancel"}</Button>
                            <Button variant="primary" loading={*reject_busy} onclick={submit_reject} testid="reject-submit">
                                {"Reject"}
                            </Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <SpaceBetween direction="vertical" size="m">
                    if let Some(row) = &*reject_modal {
                        <UiBox>{format!("{} · {} · {}", row.asset_name, row.stig_title, row.rule_id)}</UiBox>
                    }
                    <FormField label="Reason" description="The requester will see this reason in their notifications.">
                        <Textarea value={(*reject_reason).clone()} on_change={on_reason} rows={4} testid="reject-reason" />
                    </FormField>
                    if let Some(e) = &*reject_error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                </SpaceBetween>
            </Modal>
        </>
    }
}

// ── Re-assign asset owner ───────────────────────────────────────────────────

#[function_component]
fn OwnerSection(props: &SectionProps) -> Html {
    let console = &props.console;
    let asset = use_state(|| None::<SelectOption>);
    let user = use_state(|| None::<SelectOption>);
    let submitting = use_state(|| false);
    let error = use_state(|| None::<String>);
    let success = use_state(|| None::<String>);

    let submit = {
        let console = console.clone();
        let (asset, user, submitting, error, success) = (
            asset.clone(),
            user.clone(),
            submitting.clone(),
            error.clone(),
            success.clone(),
        );
        Callback::from(move |_: MouseEvent| {
            let (Some(a), Some(u)) = ((*asset).clone(), (*user).clone()) else {
                error.set(Some("Pick an asset and a new owner.".into()));
                return;
            };
            let console = console.clone();
            let (asset, user, submitting, error, success) = (
                asset.clone(),
                user.clone(),
                submitting.clone(),
                error.clone(),
                success.clone(),
            );
            spawn_local(async move {
                submitting.set(true);
                error.set(None);
                success.set(None);
                let path = format!("/api/admin/assets/{}/owner", a.value);
                match api_json::<Value, _>(
                    &path,
                    "PATCH",
                    Some(&json!({ "ownerId": u.value.as_str() })),
                )
                .await
                {
                    Ok(_) => {
                        success.set(Some(format!("Re-assigned {} to {}.", a.label, u.label)));
                        asset.set(None);
                        user.set(None);
                        console.refresh().await;
                    }
                    Err(e) => error.set(Some(e)),
                }
                submitting.set(false);
            });
        })
    };
    let on_asset = {
        let asset = asset.clone();
        Callback::from(move |o: SelectOption| asset.set(Some(o)))
    };
    let on_user = {
        let user = user.clone();
        Callback::from(move |o: SelectOption| user.set(Some(o)))
    };

    html! {
        <Container header={html! {
            <Header description="Move an asset to a different owner. Useful when a teammate leaves or hands off a system.">
                {"Re-assign asset owner"}
            </Header>
        }}>
            <SpaceBetween direction="vertical" size="m">
                <FormField label="Asset">
                    <Select placeholder="Choose an asset"
                            selected={asset.as_ref().map(|o| o.value.clone())}
                            selected_label={asset.as_ref().map(|o| o.label.clone())}
                            on_change={on_asset} options={console.asset_options()}
                            empty="No assets available" filtering=true />
                </FormField>
                <FormField label="New owner">
                    <Select placeholder="Choose a user"
                            selected={user.as_ref().map(|o| o.value.clone())}
                            selected_label={user.as_ref().map(|o| o.label.clone())}
                            on_change={on_user} options={console.user_options()}
                            empty="No users available" filtering=true />
                </FormField>
                if let Some(e) = &*error {
                    <Alert kind="error">{e.clone()}</Alert>
                }
                if let Some(s) = &*success {
                    <Alert kind="success">{s.clone()}</Alert>
                }
                <UiBox>
                    <Button variant="primary" loading={*submitting}
                            disabled={asset.is_none() || user.is_none()} onclick={submit}>
                        {"Re-assign owner"}
                    </Button>
                </UiBox>
            </SpaceBetween>
        </Container>
    }
}

// ── Audit log search ────────────────────────────────────────────────────────

/// Snapshot of the filters at the moment Search was clicked. Pagination
/// changes re-run with these values, ignoring any unsubmitted edits
/// the admin made to the filter row.
#[derive(Clone, PartialEq, Default)]
struct AuditFilters {
    user_id: String,
    /// Requests view only: select system-originated events (`actor=system`).
    actor_system: bool,
    asset_id: String,
    from: String,
    to: String,
}

/// How the "By" cell of a request event is shown. Decided only from the
/// server-computed flag, never from the name text.
#[derive(Debug, PartialEq)]
enum ActorCell<'a> {
    System,
    Name(&'a str),
}

fn actor_cell(r: &AuditEventRow) -> ActorCell<'_> {
    if r.is_system {
        ActorCell::System
    } else {
        ActorCell::Name(r.by_name.as_deref().unwrap_or("—"))
    }
}

/// Select sentinel for the "System" actor choice in the audit User filter.
const AUDIT_ACTOR_SYSTEM: &str = "__actor:system__";

/// Whether switching to `target_view` must drop a "System" actor selection:
/// the rule-changes endpoint ignores `actor`, so a lingering "System" would
/// silently list everything. Requests accepts System, so it is kept there.
fn view_switch_clears_user(selected: Option<&str>, target_view: &str) -> bool {
    target_view != "requests" && selected == Some(AUDIT_ACTOR_SYSTEM)
}

/// The audit view-switch handler: drops a lingering "System" actor selection
/// (via `clear_user`) when the target view cannot honour it, then always
/// resets the view state (via `reset`). A free function over `Callback`s so
/// it runs in native tests; the component passes thin setters.
fn view_switch_callback(
    selected_user: Option<String>,
    clear_user: Callback<()>,
    reset: Callback<AttrValue>,
) -> Callback<AttrValue> {
    Callback::from(move |id: AttrValue| {
        if view_switch_clears_user(selected_user.as_deref(), &id) {
            clear_user.emit(());
        }
        reset.emit(id);
    })
}

/// Query pairs (unencoded) for the audit endpoints. `actor=system` is sent
/// only for the requests view, and never together with `userId`.
fn audit_filter_pairs(f: &AuditFilters, requests: bool) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for (key, value) in [
        ("userId", &f.user_id),
        ("assetId", &f.asset_id),
        ("from", &f.from),
        ("to", &f.to),
    ] {
        if !value.is_empty() {
            out.push((key, value.clone()));
        }
    }
    if requests && f.actor_system {
        out.retain(|(k, _)| *k != "userId");
        out.push(("actor", "system".to_string()));
    }
    out
}

/// Audit log search. Filters are applied on Search-button click
/// rather than on every keystroke so we don't spam the backend while
/// an admin is still choosing dates / users.
#[function_component]
fn AuditSection(props: &SectionProps) -> Html {
    let console = &props.console;
    let user = use_state(|| None::<SelectOption>);
    let asset = use_state(|| None::<SelectOption>);
    let from = use_state(String::new);
    let to = use_state(String::new);
    let page = use_state(|| 1usize);
    let rows = use_state(Vec::<AuditRow>::new);
    let event_rows = use_state(Vec::<AuditEventRow>::new);
    // "rules" (rule_audit) or "requests" (audit_events).
    let view = use_state(|| "rules".to_string());
    let total = use_state(|| 0i64);
    let loading = use_state(|| false);
    let error = use_state(|| None::<String>);
    // Bumped on every Search click. The fetch effect watches it so a
    // pagination change reuses the most-recently-submitted filters.
    let search_tick = use_state(|| 0u32);
    let submitted = use_state(AuditFilters::default);

    // Re-fetch the audit page whenever the submitted filter set or page
    // changes. The Search button bumps `search_tick` (with page reset
    // to 1) so a click always lands on page 1 even if the previous run
    // was on a later page.
    {
        let (rows, event_rows, total, loading, error) = (
            rows.clone(),
            event_rows.clone(),
            total.clone(),
            loading.clone(),
            error.clone(),
        );
        use_effect_with(
            (*search_tick, *page, (*submitted).clone(), (*view).clone()),
            move |(tick, page, filters, view)| {
                let cancelled = Rc::new(Cell::new(false));
                if *tick != 0 {
                    let requests = view == "requests";
                    let mut qs: Vec<String> = audit_filter_pairs(filters, requests)
                        .into_iter()
                        .map(|(key, value)| format!("{key}={}", encode_uri_component(&value)))
                        .collect();
                    qs.push(format!("page={page}"));
                    qs.push(format!("pageSize={AUDIT_PAGE_SIZE}"));
                    let endpoint = if requests { "events" } else { "search" };
                    let path = format!("/api/audit/{endpoint}?{}", qs.join("&"));
                    let cancelled = cancelled.clone();
                    spawn_local(async move {
                        loading.set(true);
                        error.set(None);
                        // Apply a response only if this effect run is still current
                        // (cancelled is set by the cleanup on a view/page/filter change),
                        // so a late response never fills the table under the wrong view.
                        if requests {
                            let result = api_get::<AuditEvents>(&path).await;
                            if cancelled.get() {
                                return;
                            }
                            match result {
                                Ok(res) => {
                                    event_rows.set(res.rows);
                                    total.set(res.total_count);
                                }
                                Err(e) => error.set(Some(e)),
                            }
                        } else {
                            let result = api_get::<AuditSearch>(&path).await;
                            if cancelled.get() {
                                return;
                            }
                            match result {
                                Ok(res) => {
                                    rows.set(res.rows);
                                    total.set(res.total_count);
                                }
                                Err(e) => error.set(Some(e)),
                            }
                        }
                        loading.set(false);
                    });
                }
                move || cancelled.set(true)
            },
        );
    }

    let run_search = {
        let (user, asset, from, to) = (user.clone(), asset.clone(), from.clone(), to.clone());
        let (submitted, page, search_tick) = (submitted.clone(), page.clone(), search_tick.clone());
        Callback::from(move |_: MouseEvent| {
            let selected = user
                .as_ref()
                .map(|o| o.value.to_string())
                .unwrap_or_default();
            let actor_system = selected == AUDIT_ACTOR_SYSTEM;
            submitted.set(AuditFilters {
                user_id: if actor_system {
                    String::new()
                } else {
                    selected
                },
                actor_system,
                asset_id: asset
                    .as_ref()
                    .map(|o| o.value.to_string())
                    .unwrap_or_default(),
                from: (*from).clone(),
                to: (*to).clone(),
            });
            page.set(1);
            search_tick.set(*search_tick + 1);
        })
    };
    let on_page = {
        let (page, search_tick) = (page.clone(), search_tick.clone());
        Callback::from(move |n: usize| {
            page.set(n);
            // Force a re-fetch on page change. Submitted filters
            // are reused; the tick bump is what wakes the effect.
            search_tick.set(*search_tick + 1);
        })
    };
    // Switching the view drops the other view's results and waits for a new
    // Search, so a stale table never sits under the wrong columns.
    let on_view = {
        let (view, rows, event_rows, total) = (
            view.clone(),
            rows.clone(),
            event_rows.clone(),
            total.clone(),
        );
        let (page, search_tick, error, loading) = (
            page.clone(),
            search_tick.clone(),
            error.clone(),
            loading.clone(),
        );
        let reset = Callback::from(move |id: AttrValue| {
            view.set(id.to_string());
            rows.set(Vec::new());
            event_rows.set(Vec::new());
            total.set(0);
            page.set(1);
            search_tick.set(0);
            error.set(None);
            loading.set(false);
        });
        // The one-line `user.set(None)` adapter is covered only by the e2e
        // tail in `65-audit-search.spec.js`; `view_switch_callback` is
        // unit-tested natively.
        let selected = user.as_ref().map(|o| o.value.to_string());
        let clear_user = {
            let user = user.clone();
            Callback::from(move |_: ()| user.set(None))
        };
        view_switch_callback(selected, clear_user, reset)
    };
    let on_user = {
        let user = user.clone();
        Callback::from(move |o: SelectOption| user.set(Some(o)))
    };
    let on_asset = {
        let asset = asset.clone();
        Callback::from(move |o: SelectOption| asset.set(Some(o)))
    };
    let on_from = {
        let from = from.clone();
        Callback::from(move |v: String| from.set(v))
    };
    let on_to = {
        let to = to.clone();
        Callback::from(move |v: String| to.set(v))
    };

    let mut user_options = vec![SelectOption::new("", "Any user")];
    if *view == "requests" {
        user_options.push(
            SelectOption::new(AUDIT_ACTOR_SYSTEM, "System")
                .description("Automated events with no acting user"),
        );
    }
    user_options.extend(console.user_options());
    let mut asset_options = vec![SelectOption::new("", "Any asset")];
    asset_options.extend(console.asset_options());

    let clipped = |value: &Option<String>| {
        let full = value.clone().unwrap_or_default();
        html! { <span title={full.clone()}>{truncate(&full, 60)}</span> }
    };
    let columns = vec![
        Column::new("when", "When", |r: &AuditRow| {
            html! { {r.occurred_at.as_deref().filter(|s| !s.is_empty()).map(to_locale_string).unwrap_or_else(|| "—".into())} }
        }),
        Column::new("by", "By", |r: &AuditRow| html! { {r.by_name.clone()} }),
        Column::new(
            "asset",
            "Asset",
            |r: &AuditRow| html! { {r.asset_name.clone().unwrap_or_else(|| "—".into())} },
        ),
        Column::new(
            "stig",
            "STIG",
            |r: &AuditRow| html! { {r.stig_title.clone().unwrap_or_else(|| "—".into())} },
        ),
        Column::new("rule", "Rule", |r: &AuditRow| html! { {r.rule_id.clone()} }),
        Column::new("field", "Field", |r: &AuditRow| html! { {r.field.clone()} }),
        Column::new("from", "From", move |r: &AuditRow| clipped(&r.from_value)),
        Column::new("to", "To", move |r: &AuditRow| clipped(&r.to_value)),
    ];
    let event_columns = vec![
        Column::new("when", "When", |r: &AuditEventRow| {
            html! { {r.occurred_at.as_deref().filter(|s| !s.is_empty()).map(to_locale_string).unwrap_or_else(|| "—".into())} }
        }),
        Column::new("by", "By", |r: &AuditEventRow| match actor_cell(r) {
            ActorCell::System => html! { <Badge testid="audit-actor-system">{"System"}</Badge> },
            ActorCell::Name(n) => html! { {n.to_string()} },
        }),
        Column::new(
            "asset",
            "Asset",
            |r: &AuditEventRow| html! { {r.asset_name.clone().unwrap_or_else(|| "—".into())} },
        ),
        Column::new(
            "stig",
            "STIG",
            |r: &AuditEventRow| html! { {r.stig_title.clone().unwrap_or_else(|| "—".into())} },
        ),
        Column::new(
            "action",
            "Action",
            |r: &AuditEventRow| html! { {r.action.clone()} },
        ),
        Column::new(
            "outcome",
            "Outcome",
            |r: &AuditEventRow| html! { {r.outcome.clone()} },
        ),
        Column::new(
            "role",
            "Role",
            |r: &AuditEventRow| html! { {r.user_role.clone().unwrap_or_else(|| "—".into())} },
        ),
        Column::new(
            "ip",
            "Source IP",
            |r: &AuditEventRow| html! { {r.source_ip.clone().unwrap_or_else(|| "—".into())} },
        ),
        Column::new("request", "Request ID", |r: &AuditEventRow| {
            html! { <UiBox variant="code">{r.request_id.clone().unwrap_or_else(|| "—".into())}</UiBox> }
        }),
        Column::new(
            "count",
            "Count",
            |r: &AuditEventRow| html! { {repeat_label(r)} },
        ),
        Column::new(
            "summary",
            "Summary",
            |r: &AuditEventRow| html! { {event_summary(r)} },
        ),
    ];
    let requests_view = *view == "requests";
    let pages_count = usize::try_from((*total + AUDIT_PAGE_SIZE - 1) / AUDIT_PAGE_SIZE)
        .unwrap_or(1)
        .max(1);
    let empty_text = if *search_tick == 0 {
        "Click Search to query the audit log."
    } else {
        "No audit rows match the current filters."
    };

    html! {
        <Container header={html! {
            <Header description="Cross-cutting search over rule changes and request-level events. Filter by user, asset, and date range; results are paginated server-side.">
                {"Audit log"}
            </Header>
        }}>
            <SpaceBetween direction="vertical" size="m">
                <SegmentedControl
                    options={vec![SegmentOption::new("rules", "Rule changes"), SegmentOption::new("requests", "Requests")]}
                    selected_id={AttrValue::from((*view).clone())}
                    on_change={on_view}
                    label="Audit log view"
                    testid="audit-view-switch" />
                <div style="display:grid;grid-template-columns:repeat(4, minmax(0, 1fr));gap:var(--space-scaled-m, 12px);">
                    <FormField label="User">
                        <Select placeholder="Any user"
                                selected={user.as_ref().map(|o| o.value.clone())}
                                on_change={on_user} options={user_options}
                                empty="No users available" filtering=true testid="audit-user-select" />
                    </FormField>
                    <FormField label="Asset">
                        <Select placeholder="Any asset"
                                selected={asset.as_ref().map(|o| o.value.clone())}
                                on_change={on_asset} options={asset_options}
                                empty="No assets available" filtering=true testid="audit-asset-select" />
                    </FormField>
                    <FormField label="From">
                        <DatePicker value={(*from).clone()} on_change={on_from}
                                    placeholder="YYYY/MM/DD" testid="audit-from-picker" />
                    </FormField>
                    <FormField label="To">
                        <DatePicker value={(*to).clone()} on_change={on_to}
                                    placeholder="YYYY/MM/DD" testid="audit-to-picker" />
                    </FormField>
                </div>
                <UiBox>
                    <Button variant="primary" loading={*loading} onclick={run_search} testid="audit-search-button">
                        {"Search"}
                    </Button>
                </UiBox>
                if let Some(e) = &*error {
                    <Alert kind="error">{e.clone()}</Alert>
                }
                if requests_view {
                    <Table<AuditEventRow>
                        variant="embedded"
                        items={(*event_rows).clone()}
                        loading={*loading}
                        loading_text="Searching audit log"
                        empty={empty_note(empty_text)}
                        columns={event_columns}
                        pagination={html! {
                            <Pagination current_page_index={*page} {pages_count} on_change={on_page.clone()} />
                        }}
                        header={html! {
                            <Header counter={format!("({})", *total)}
                                    description="Bulk status changes, saves to a system and checklist creations, including rejected and denied requests. Newest first.">
                                {"Requests"}
                            </Header>
                        }}
                        testid="audit-events-table"
                    />
                } else {
                    <Table<AuditRow>
                        variant="embedded"
                        items={(*rows).clone()}
                        loading={*loading}
                        loading_text="Searching audit log"
                        empty={empty_note(empty_text)}
                        {columns}
                        pagination={html! {
                            <Pagination current_page_index={*page} {pages_count} on_change={on_page} />
                        }}
                        header={html! {
                            <Header counter={format!("({})", *total)}
                                    description="Newest first. Truncated values show the full text on hover.">
                                {"Results"}
                            </Header>
                        }}
                        testid="audit-search-table"
                    />
                }
            </SpaceBetween>
        </Container>
    }
}

// ── ABAC policies ───────────────────────────────────────────────────────────

/// In-flight values of the "Add policy" form.
#[derive(Clone, PartialEq)]
struct PolicyForm {
    name: String,
    effect: String,
    level: String,
    role_match: String,
    classification_match: String,
    tag_match: String,
}

impl Default for PolicyForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            effect: "allow".into(),
            level: "read".into(),
            role_match: String::new(),
            classification_match: String::new(),
            tag_match: String::new(),
        }
    }
}

#[function_component]
fn PoliciesSection(props: &SectionProps) -> Html {
    let console = &props.console;
    // Holds the form values while the create modal is open; None otherwise.
    let modal = use_state(|| None::<PolicyForm>);
    let submitting = use_state(|| false);
    let error = use_state(|| None::<String>);

    let open_create = {
        let (modal, error) = (modal.clone(), error.clone());
        Callback::from(move |_: MouseEvent| {
            modal.set(Some(PolicyForm::default()));
            error.set(None);
        })
    };
    let close = {
        let modal = modal.clone();
        Callback::from(move |_: ()| modal.set(None))
    };
    let submit = {
        let console = console.clone();
        let (modal, submitting, error) = (modal.clone(), submitting.clone(), error.clone());
        Callback::from(move |_: MouseEvent| {
            let Some(form) = (*modal).clone() else { return };
            let console = console.clone();
            let (modal, submitting, error) = (modal.clone(), submitting.clone(), error.clone());
            spawn_local(async move {
                submitting.set(true);
                error.set(None);
                let body = json!({
                    "name": form.name,
                    "effect": form.effect,
                    "level": form.level,
                    "roleMatch": form.role_match,
                    "classificationMatch": form.classification_match,
                    "tagMatch": form.tag_match,
                });
                match api_json::<Value, _>("/api/admin/policies", "POST", Some(&body)).await {
                    Ok(_) => {
                        modal.set(None);
                        console.refresh().await;
                    }
                    Err(e) => error.set(Some(e)),
                }
                submitting.set(false);
            });
        })
    };
    let toggle_enabled = {
        let console = console.clone();
        Callback::from(move |(id, next): (String, bool)| {
            let console = console.clone();
            spawn_local(async move {
                let path = format!("/api/admin/policies/{id}");
                match api_json::<Value, _>(&path, "PATCH", Some(&json!({ "enabled": next }))).await
                {
                    Ok(_) => console.refresh().await,
                    Err(e) => console.fail(e),
                }
            });
        })
    };
    let delete = {
        let console = console.clone();
        Callback::from(move |policy: Policy| {
            if !confirm(&format!(
                "Delete policy \"{}\"? This can't be undone.",
                policy.name
            )) {
                return;
            }
            let console = console.clone();
            spawn_local(async move {
                match expect_ok(
                    "DELETE",
                    &format!("/api/admin/policies/{}", policy.id),
                    "Delete",
                )
                .await
                {
                    Ok(()) => console.refresh().await,
                    Err(e) => console.fail(e),
                }
            });
        })
    };
    // Field setter for the open form.
    let edit = |apply: fn(&mut PolicyForm, String)| {
        let modal = modal.clone();
        Callback::from(move |value: String| {
            if let Some(mut form) = (*modal).clone() {
                apply(&mut form, value);
                modal.set(Some(form));
            }
        })
    };
    let chosen = |o: SelectOption| o.value.to_string();

    let any = |v: &Option<String>| v.clone().unwrap_or_else(|| "any".into());
    let columns = vec![
        Column::new("name", "Name", |p: &Policy| html! { {p.name.clone()} }),
        Column::new("effect", "Effect", |p: &Policy| {
            html! { <Badge color={if p.effect == "deny" { "red" } else { "green" }}>{p.effect.clone()}</Badge> }
        }),
        Column::new("level", "Level", |p: &Policy| html! { {p.level.clone()} }),
        Column::new(
            "role_match",
            "Role match",
            move |p: &Policy| html! { {any(&p.role_match)} },
        ),
        Column::new(
            "classification_match",
            "Classification match",
            move |p: &Policy| {
                html! { {any(&p.classification_match)} }
            },
        ),
        Column::new(
            "tag_match",
            "Tag match",
            move |p: &Policy| html! { {any(&p.tag_match)} },
        ),
        Column::new("enabled", "Enabled", move |p: &Policy| {
            let id = p.id.clone();
            let on_change = toggle_enabled.reform(move |next: bool| (id.clone(), next));
            html! {
                <div data-testid={format!("policy-enabled-{}", p.id)}>
                    <Toggle checked={p.enabled} {on_change} />
                </div>
            }
        }),
        Column::new("actions", "", move |p: &Policy| {
            html! {
                <Button variant="inline-link" onclick={click(&delete, p)} testid={format!("policy-delete-{}", p.id)}>
                    {"Delete"}
                </Button>
            }
        }),
    ];

    let form = (*modal).clone();
    let field =
        |get: fn(&PolicyForm) -> &String| form.as_ref().map(|f| get(f).clone()).unwrap_or_default();
    html! {
        <>
            <Table<Policy>
                items={(*console.policies).clone()}
                {columns}
                loading={*console.loading}
                loading_text="Loading policies"
                empty={empty_note("No ABAC policies configured. Add one to layer attribute-based rules on top of the owner / ACL / admin-role checks.")}
                header={html! {
                    <Header counter={format!("({})", console.policies.len())}
                            description="Attribute-based access control. Each policy targets a level (read/write/admin) and matches by role, classification, and tag. Deny wins over Allow when both match."
                            actions={html! {
                                <Button variant="primary" onclick={open_create} testid="add-policy-btn">{"Add policy"}</Button>
                            }}>
                        {"Policies"}
                    </Header>
                }}
                testid="policies-table"
            />
            <Modal
                visible={modal.is_some()}
                on_dismiss={close.clone()}
                header="Add policy"
                testid="policy-modal"
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={close.reform(|_: MouseEvent| ())}>{"Cancel"}</Button>
                            <Button variant="primary" loading={*submitting} onclick={submit} testid="policy-submit-btn">
                                {"Save"}
                            </Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <SpaceBetween direction="vertical" size="m">
                    <FormField label="Name">
                        <Input value={field(|f| &f.name)} on_change={edit(|f, v| f.name = v)}
                               placeholder="e.g. Reviewers can write unclassified" testid="policy-name-input" />
                    </FormField>
                    <FormField label="Effect">
                        <Select selected={pick(POLICY_EFFECT_OPTIONS, &field(|f| &f.effect))}
                                on_change={edit(|f, v| f.effect = v).reform(chosen)}
                                options={select_options(POLICY_EFFECT_OPTIONS)} testid="policy-effect-select" />
                    </FormField>
                    <FormField label="Level">
                        <Select selected={pick(POLICY_LEVEL_OPTIONS, &field(|f| &f.level))}
                                on_change={edit(|f, v| f.level = v).reform(chosen)}
                                options={select_options(POLICY_LEVEL_OPTIONS)} testid="policy-level-select" />
                    </FormField>
                    <FormField label="Role match" description="Leave as 'Any role' to match every requester.">
                        <Select selected={pick(POLICY_ROLE_OPTIONS, &field(|f| &f.role_match))}
                                on_change={edit(|f, v| f.role_match = v).reform(chosen)}
                                options={select_options(POLICY_ROLE_OPTIONS)} testid="policy-role-select" />
                    </FormField>
                    <FormField label="Classification match" description="Empty matches any classification.">
                        <Input value={field(|f| &f.classification_match)}
                               on_change={edit(|f, v| f.classification_match = v)}
                               placeholder="unclassified" testid="policy-classification-input" />
                    </FormField>
                    <FormField label="Tag match" description="Asset must carry this exact tag. Empty matches any.">
                        <Input value={field(|f| &f.tag_match)} on_change={edit(|f, v| f.tag_match = v)}
                               placeholder="prod" testid="policy-tag-input" />
                    </FormField>
                    if let Some(e) = &*error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                </SpaceBetween>
            </Modal>
        </>
    }
}

// ── Webhooks ────────────────────────────────────────────────────────────────

/// Webhook create / edit form. `id` is `Some` when editing.
#[derive(Clone, PartialEq)]
struct HookForm {
    id: Option<String>,
    name: String,
    url: String,
    /// New secret to set. Empty on edit means keep the stored one.
    secret: String,
    /// Whether the webhook being edited currently has a secret.
    signed: bool,
    /// Edit only: remove the stored secret (send unsigned).
    clear_secret: bool,
    kinds: Vec<String>,
    flavor: String,
    enabled: bool,
}

impl Default for HookForm {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            url: String::new(),
            secret: String::new(),
            signed: false,
            clear_secret: false,
            kinds: vec!["assigned".into()],
            flavor: "slack".into(),
            enabled: true,
        }
    }
}

impl HookForm {
    fn editing(w: &Webhook) -> Self {
        Self {
            id: Some(w.id.clone()),
            name: w.name.clone(),
            url: w.url.clone(),
            secret: String::new(),
            signed: w.signed,
            clear_secret: false,
            kinds: w.kinds.clone().unwrap_or_else(|| vec!["assigned".into()]),
            flavor: w.flavor.clone().unwrap_or_else(|| "slack".into()),
            enabled: w.enabled,
        }
    }
}

#[derive(Clone, PartialEq, Default)]
struct DeliveriesPanel {
    webhook_name: String,
    rows: Vec<Delivery>,
    loading: bool,
    error: Option<String>,
}

/// Verify-recipe modal state: the JSON returned by
/// GET /api/webhooks/:id/verify-recipe, or a placeholder while it loads.
#[derive(Clone, PartialEq)]
enum VerifyState {
    Loading { webhook_name: String },
    Ready(VerifyRecipe),
}

#[function_component]
fn WebhooksSection(props: &SectionProps) -> Html {
    let console = &props.console;
    let hook_modal = use_state(|| None::<HookForm>);
    let hook_submitting = use_state(|| false);
    let hook_error = use_state(|| None::<String>);
    let deliveries = use_state(|| None::<DeliveriesPanel>);
    let verify = use_state(|| None::<VerifyState>);
    let verify_error = use_state(|| None::<String>);

    let open_create = {
        let (modal, error) = (hook_modal.clone(), hook_error.clone());
        Callback::from(move |_: MouseEvent| {
            modal.set(Some(HookForm::default()));
            error.set(None);
        })
    };
    let open_edit = {
        let modal = hook_modal.clone();
        Callback::from(move |w: Webhook| modal.set(Some(HookForm::editing(&w))))
    };
    let close_hook = {
        let modal = hook_modal.clone();
        Callback::from(move |_: ()| modal.set(None))
    };
    let submit_hook = {
        let console = console.clone();
        let (modal, submitting, error) = (
            hook_modal.clone(),
            hook_submitting.clone(),
            hook_error.clone(),
        );
        Callback::from(move |_: MouseEvent| {
            let Some(form) = (*modal).clone() else { return };
            let console = console.clone();
            let (modal, submitting, error) = (modal.clone(), submitting.clone(), error.clone());
            spawn_local(async move {
                submitting.set(true);
                error.set(None);
                let mut body = json!({
                    "name": form.name,
                    "url": form.url,
                    "kinds": form.kinds,
                    "flavor": form.flavor,
                });
                let result = match &form.id {
                    None => {
                        body["secret"] = json!(form.secret);
                        api_json::<Value, _>("/api/webhooks", "POST", Some(&body)).await
                    }
                    Some(id) => {
                        body["enabled"] = json!(form.enabled);
                        // The stored secret is write-only: omit the key to
                        // keep it, send a value to rotate, "" to clear.
                        if form.clear_secret {
                            body["secret"] = json!("");
                        } else if !form.secret.is_empty() {
                            body["secret"] = json!(form.secret);
                        }
                        api_json::<Value, _>(&format!("/api/webhooks/{id}"), "PATCH", Some(&body))
                            .await
                    }
                };
                match result {
                    Ok(_) => {
                        modal.set(None);
                        console.refresh().await;
                    }
                    Err(e) => error.set(Some(e)),
                }
                submitting.set(false);
            });
        })
    };
    let toggle_enabled = {
        let console = console.clone();
        Callback::from(move |(id, next): (String, bool)| {
            let console = console.clone();
            spawn_local(async move {
                let path = format!("/api/webhooks/{id}");
                match api_json::<Value, _>(&path, "PATCH", Some(&json!({ "enabled": next }))).await
                {
                    Ok(_) => console.refresh().await,
                    Err(e) => console.fail(e),
                }
            });
        })
    };
    let delete = {
        let console = console.clone();
        Callback::from(move |hook: Webhook| {
            if !confirm(&format!(
                "Delete webhook \"{}\"? This can't be undone.",
                hook.name
            )) {
                return;
            }
            let console = console.clone();
            spawn_local(async move {
                match expect_ok("DELETE", &format!("/api/webhooks/{}", hook.id), "Delete").await {
                    Ok(()) => console.refresh().await,
                    Err(e) => console.fail(e),
                }
            });
        })
    };
    let test = {
        let console = console.clone();
        Callback::from(move |hook: Webhook| {
            let console = console.clone();
            console.test_flash.set(None);
            spawn_local(async move {
                match expect_ok("POST", &format!("/api/webhooks/{}/test", hook.id), "Test").await {
                    Ok(()) => console.test_flash.set(Some(format!(
                        "Test event dispatched to \"{}\". Open Deliveries to view the result.",
                        hook.name
                    ))),
                    Err(e) => console.fail(e),
                }
            });
        })
    };
    let open_deliveries = {
        let panel = deliveries.clone();
        Callback::from(move |hook: Webhook| {
            let panel = panel.clone();
            let webhook_name = hook.name.clone();
            panel.set(Some(DeliveriesPanel {
                webhook_name: webhook_name.clone(),
                loading: true,
                ..Default::default()
            }));
            spawn_local(async move {
                let next = match api_get::<Vec<Delivery>>(&format!(
                    "/api/webhooks/{}/deliveries",
                    hook.id
                ))
                .await
                {
                    Ok(rows) => DeliveriesPanel {
                        webhook_name,
                        rows: rows.into_iter().take(10).collect(),
                        ..Default::default()
                    },
                    Err(e) => DeliveriesPanel {
                        webhook_name,
                        error: Some(e),
                        ..Default::default()
                    },
                };
                panel.set(Some(next));
            });
        })
    };
    let close_deliveries = {
        let panel = deliveries.clone();
        Callback::from(move |_: ()| panel.set(None))
    };
    // Fetch and open the verify-recipe modal. The backend pre-fills the URL
    // and a sample HMAC; the Python/Node snippets read the secret from the
    // WEBHOOK_SECRET environment variable (it is never returned).
    let open_verify = {
        let (verify, verify_error) = (verify.clone(), verify_error.clone());
        Callback::from(move |hook: Webhook| {
            let (verify, verify_error) = (verify.clone(), verify_error.clone());
            verify_error.set(None);
            verify.set(Some(VerifyState::Loading {
                webhook_name: hook.name.clone(),
            }));
            spawn_local(async move {
                match api_get::<VerifyRecipe>(&format!("/api/webhooks/{}/verify-recipe", hook.id))
                    .await
                {
                    Ok(recipe) => verify.set(Some(VerifyState::Ready(recipe))),
                    Err(e) => {
                        verify.set(None);
                        verify_error.set(Some(e));
                    }
                }
            });
        })
    };
    let close_verify = {
        let verify = verify.clone();
        Callback::from(move |_: ()| verify.set(None))
    };
    // Field setter for the open webhook form.
    let edit = |apply: fn(&mut HookForm, String)| {
        let modal = hook_modal.clone();
        Callback::from(move |value: String| {
            if let Some(mut form) = (*modal).clone() {
                apply(&mut form, value);
                modal.set(Some(form));
            }
        })
    };
    let set_kinds = {
        let modal = hook_modal.clone();
        Callback::from(move |selected: Vec<SelectOption>| {
            if let Some(mut form) = (*modal).clone() {
                form.kinds = selected.iter().map(|o| o.value.to_string()).collect();
                modal.set(Some(form));
            }
        })
    };

    let columns = vec![
        Column::new("name", "Name", |w: &Webhook| html! { {w.name.clone()} }),
        Column::new(
            "url",
            "URL",
            |w: &Webhook| html! { <span title={w.url.clone()}>{truncate(&w.url, 50)}</span> },
        ),
        Column::new("kinds", "Events", |w: &Webhook| {
            html! {
                <SpaceBetween direction="horizontal" size="xxs">
                    { for w.kinds.iter().flatten().map(|k| html! { <Badge key={k.clone()} color="blue">{k.clone()}</Badge> }) }
                </SpaceBetween>
            }
        }),
        Column::new("flavor", "Flavor", |w: &Webhook| {
            let flavor = w.flavor.clone().unwrap_or_else(|| "slack".into());
            html! {
                <Badge color={flavor_badge(&flavor)} testid={format!("webhook-flavor-{}", w.id)}>{flavor}</Badge>
            }
        }),
        Column::new("signed", "Signing", |w: &Webhook| {
            html! {
                <Badge color={if w.signed { "green" } else { "grey" }} testid={format!("webhook-signed-{}", w.id)}>
                    {if w.signed { "Signed" } else { "Unsigned" }}
                </Badge>
            }
        }),
        Column::new("enabled", "Enabled", move |w: &Webhook| {
            let id = w.id.clone();
            let on_change = toggle_enabled.reform(move |next: bool| (id.clone(), next));
            html! { <Toggle checked={w.enabled} {on_change} /> }
        }),
        Column::new("actions", "", move |w: &Webhook| {
            html! {
                <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="inline-link" onclick={click(&test, w)}>{"Test"}</Button>
                    <Button variant="inline-link" onclick={click(&open_deliveries, w)}>{"Deliveries"}</Button>
                    <Button variant="inline-link" testid={format!("verify-recipe-{}", w.id)} onclick={click(&open_verify, w)}>
                        {"Verify recipe"}
                    </Button>
                    <Button variant="inline-link" onclick={click(&open_edit, w)}>{"Edit"}</Button>
                    <Button variant="inline-link" onclick={click(&delete, w)}>{"Delete"}</Button>
                </SpaceBetween>
            }
        }),
    ];

    let form = (*hook_modal).clone();
    let field =
        |get: fn(&HookForm) -> &String| form.as_ref().map(|f| get(f).clone()).unwrap_or_default();
    let selected_kinds: Vec<AttrValue> = form
        .as_ref()
        .map(|f| f.kinds.iter().cloned().map(AttrValue::from).collect())
        .unwrap_or_default();
    let hook_header = if form.as_ref().is_some_and(|f| f.id.is_some()) {
        "Edit webhook"
    } else {
        "Add webhook"
    };
    let editing = form.as_ref().is_some_and(|f| f.id.is_some());
    let editing_signed = editing && form.as_ref().is_some_and(|f| f.signed);
    let clear_secret = form.as_ref().is_some_and(|f| f.clear_secret);
    let secret_description = match (editing, editing_signed) {
        (true, true) => "A secret is set. Leave blank to keep it; enter a new value to rotate. It is never shown.",
        (true, false) => "No secret set (deliveries are unsigned). Enter a value to sign deliveries.",
        _ => "Used as the HMAC-SHA256 key. Verify with: hex(hmac_sha256(secret, body)) and the X-Webhook-Signature header (format sha256=<hex>). Leave blank to send unsigned.",
    };
    let on_clear_secret = {
        let modal = hook_modal.clone();
        Callback::from(move |v: bool| {
            if let Some(mut form) = (*modal).clone() {
                form.clear_secret = v;
                if v {
                    form.secret.clear();
                }
                modal.set(Some(form));
            }
        })
    };
    let flavor = form
        .as_ref()
        .map(|f| f.flavor.clone())
        .unwrap_or_else(|| "slack".into());

    let deliveries_name = deliveries
        .as_ref()
        .map(|d| d.webhook_name.clone())
        .unwrap_or_default();
    let deliveries_body = match &*deliveries {
        Some(d) if d.loading => empty_plain("Loading…"),
        Some(DeliveriesPanel { error: Some(e), .. }) => {
            html! { <Alert kind="error">{e.clone()}</Alert> }
        }
        Some(d) if !d.rows.is_empty() => html! {
            <Table<Delivery> variant="embedded" items={d.rows.clone()} columns={delivery_columns()} />
        },
        _ => empty_plain("No deliveries yet."),
    };

    let verify_name = match &*verify {
        Some(VerifyState::Ready(recipe)) => recipe.name.clone(),
        Some(VerifyState::Loading { webhook_name }) => webhook_name.clone(),
        None => String::new(),
    };
    let verify_body = match (&*verify, &*verify_error) {
        (Some(VerifyState::Loading { .. }), _) => empty_plain("Loading…"),
        (Some(VerifyState::Ready(recipe)), _) => {
            let tab = |language: &'static str, label: &'static str, text: &String| {
                TabItem::new(
                    language,
                    label,
                    html! { <SnippetBlock {language} text={text.clone()} /> },
                )
            };
            html! {
                <SpaceBetween direction="vertical" size="m">
                    <UiBox variant="p">
                        {"Drop the matching snippet into your receiver to verify incoming webhook signatures. The Python and Node snippets read the signing secret from the WEBHOOK_SECRET environment variable; it is never shown here."}
                    </UiBox>
                    <Tabs tabs={vec![
                        tab("curl", "curl", &recipe.snippets.curl),
                        tab("python", "Python", &recipe.snippets.python),
                        tab("node", "Node", &recipe.snippets.node),
                    ]} />
                </SpaceBetween>
            }
        }
        (None, Some(e)) => html! { <Alert kind="error">{e.clone()}</Alert> },
        (None, None) => html! {},
    };

    html! {
        <>
            <Table<Webhook>
                items={(*console.webhooks).clone()}
                {columns}
                loading={*console.loading}
                loading_text="Loading webhooks"
                empty={empty_plain("No webhooks configured.")}
                header={html! {
                    <Header counter={format!("({})", console.webhooks.len())}
                            description="Outbound HTTP notifications fired when a finding is assigned. Compatible with Slack incoming webhooks."
                            actions={html! {
                                <Button variant="primary" onclick={open_create}>{"Add webhook"}</Button>
                            }}>
                        {"Webhooks"}
                    </Header>
                }}
            />

            <Modal
                visible={hook_modal.is_some()}
                on_dismiss={close_hook.clone()}
                header={hook_header}
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={close_hook.reform(|_: MouseEvent| ())}>{"Cancel"}</Button>
                            <Button variant="primary" loading={*hook_submitting} onclick={submit_hook}>{"Save"}</Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <SpaceBetween direction="vertical" size="m">
                    <FormField label="Name">
                        <Input value={field(|f| &f.name)} on_change={edit(|f, v| f.name = v)} placeholder="Slack #security" />
                    </FormField>
                    <FormField label="URL" description="Slack incoming webhook URL or any HTTPS endpoint.">
                        <Input value={field(|f| &f.url)} on_change={edit(|f, v| f.url = v)}
                               placeholder="https://hooks.slack.com/services/…" />
                    </FormField>
                    <FormField label="Secret"
                               description={secret_description}>
                        <Input value={field(|f| &f.secret)} kind="password" disabled={clear_secret} on_change={edit(|f, v| f.secret = v)} />
                    </FormField>
                    if editing_signed {
                        <Toggle testid="webhook-clear-secret" checked={clear_secret} on_change={on_clear_secret}>
                            {"Remove secret (send unsigned)"}
                        </Toggle>
                    }
                    <FormField label="Events">
                        <Multiselect selected={selected_kinds} on_change={set_kinds}
                                     options={select_options(KIND_OPTIONS)} placeholder="Select event kinds" />
                    </FormField>
                    <FormField label="Flavor"
                               description="Wire payload schema. Slack = legacy {text, attachments}; Teams = MessageCard; Generic = flat {kind, title, body, color, fields}.">
                        <Select testid="webhook-flavor-select" selected={pick(FLAVOR_OPTIONS, &flavor)}
                                on_change={edit(|f, v| f.flavor = v).reform(|o: SelectOption| o.value.to_string())}
                                options={select_options(FLAVOR_OPTIONS)} />
                    </FormField>
                    if let Some(e) = &*hook_error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                </SpaceBetween>
            </Modal>

            <Modal
                visible={deliveries.is_some()}
                on_dismiss={close_deliveries.clone()}
                header={Html::from(format!("Recent deliveries: {deliveries_name}"))}
                size="large"
                footer={html! {
                    <UiBox float="right">
                        <Button variant="link" onclick={close_deliveries.reform(|_: MouseEvent| ())}>{"Close"}</Button>
                    </UiBox>
                }}
            >
                {deliveries_body}
            </Modal>

            <Modal
                visible={verify.is_some()}
                on_dismiss={close_verify.clone()}
                header={Html::from(format!("Verify recipe: {verify_name}"))}
                size="large"
                footer={html! {
                    <UiBox float="right">
                        <Button variant="link" onclick={close_verify.reform(|_: MouseEvent| ())}>{"Close"}</Button>
                    </UiBox>
                }}
            >
                {verify_body}
            </Modal>
        </>
    }
}

fn delivery_columns() -> Vec<Column<Delivery>> {
    vec![
        Column::new(
            "attempted_at",
            "When",
            |d: &Delivery| html! { {relative_time(d.attempted_at.as_deref())} },
        ),
        Column::new("kind", "Kind", |d: &Delivery| html! { {d.kind.clone()} }),
        Column::new("status", "Status", |d: &Delivery| {
            match (&d.error, d.http_status) {
                (Some(e), _) if !e.is_empty() => {
                    html! { <StatusIndicator kind="error">{"Failed"}</StatusIndicator> }
                }
                (_, Some(code)) if (200..300).contains(&code) => {
                    html! { <StatusIndicator kind="success">{code}</StatusIndicator> }
                }
                (_, code) => html! {
                    <StatusIndicator kind="warning">{code.map(|c| c.to_string()).unwrap_or_else(|| "—".into())}</StatusIndicator>
                },
            }
        }),
        Column::new("detail", "Detail", |d: &Delivery| {
            let detail = d
                .error
                .clone()
                .or_else(|| d.response.clone())
                .unwrap_or_default();
            html! { <UiBox variant="code">{head(&detail, 200)}</UiBox> }
        }),
    ]
}

#[derive(Properties, PartialEq)]
struct SnippetBlockProps {
    language: AttrValue,
    text: AttrValue,
}

/// Render one verify-recipe snippet in a monospace block with a "Copy"
/// button that pushes the raw text to the system clipboard. Each block
/// tags its Copy button with a stable `data-testid` so e2e can confirm
/// the wiring exists without depending on clipboard internals (which
/// don't work in headless Chromium without explicit permissions).
#[function_component]
fn SnippetBlock(props: &SnippetBlockProps) -> Html {
    let copied = use_state(|| false);
    let on_copy = {
        let copied = copied.clone();
        let text = props.text.clone();
        Callback::from(move |_: MouseEvent| {
            let copied = copied.clone();
            let text = text.clone();
            spawn_local(async move {
                // `navigator.clipboard` is absent outside secure contexts.
                let available =
                    js_sys::Reflect::get(&window().navigator(), &JsValue::from_str("clipboard"))
                        .map(|c| !c.is_undefined() && !c.is_null())
                        .unwrap_or(false);
                // Permission denied / unavailable is silently swallowed —
                // the button is just a convenience; the text is selectable too.
                if available && !copy_to_clipboard(&text).await {
                    return;
                }
                copied.set(true);
                // Brief flash — the user just wants visible confirmation they
                // clicked the right thing, not a permanent badge.
                gloo_timers::future::TimeoutFuture::new(1500).await;
                copied.set(false);
            });
        })
    };
    html! {
        <SpaceBetween direction="vertical" size="xs">
            <UiBox float="right">
                <Button icon_name="copy" testid={format!("verify-snippet-copy-{}", props.language)} onclick={on_copy}>
                    {if *copied { "Copied" } else { "Copy" }}
                </Button>
            </UiBox>
            <pre data-testid={format!("verify-snippet-body-{}", props.language)}
                 style="background:var(--bg-input);color:var(--text-heading);padding:12px;border-radius:4px;overflow-x:auto;font-family:var(--mono);font-size:13px;white-space:pre;margin:0;">
                {props.text.clone()}
            </pre>
        </SpaceBetween>
    }
}

// ── Compliance reports / email deliveries ───────────────────────────────────

fn reports_table(reports: &[Report]) -> Html {
    let summary = |r: &Report| r.summary.clone().unwrap_or_default();
    let columns = vec![
        Column::new(
            "generated",
            "Generated",
            |r: &Report| html! { {to_locale_string(&r.generated_at)} },
        ),
        Column::new(
            "compliance",
            "Compliance",
            move |r: &Report| html! { {format!("{}%", summary(r).compliance_score)} },
        ),
        Column::new(
            "assets",
            "Assets",
            move |r: &Report| html! { {summary(r).assets} },
        ),
        Column::new(
            "open",
            "Open findings",
            move |r: &Report| html! { {summary(r).open_findings} },
        ),
        Column::new("top", "Top-risk system", move |r: &Report| {
            html! { {summary(r).top_asset_name.unwrap_or_else(|| "—".into())} }
        }),
        Column::new("download", "", |r: &Report| {
            html! {
                <Button variant="inline-link" href={format!("{BACKEND}/api/reports/{}/report.pdf", r.id)}
                        icon_name="download" target="_blank">
                    {"PDF"}
                </Button>
            }
        }),
    ];
    html! {
        <Table<Report>
            variant="container"
            items={reports.to_vec()}
            empty={empty_note("No compliance reports yet. The scheduler runs weekly.")}
            {columns}
            header={html! {
                <Header counter={format!("({})", reports.len())}
                        description="Fleet-wide compliance snapshots. Generated on the configured cadence and emitted to compliance_report webhooks.">
                    {"Compliance reports"}
                </Header>
            }}
        />
    }
}

fn emails_table(emails: &[EmailDelivery]) -> Html {
    let columns = vec![
        Column::new(
            "when",
            "When",
            |e: &EmailDelivery| html! { {relative_time(e.attempted_at.as_deref())} },
        ),
        Column::new(
            "kind",
            "Kind",
            |e: &EmailDelivery| html! { {e.kind.clone()} },
        ),
        Column::new("to", "To", |e: &EmailDelivery| {
            let shown = if e.to_addresses.is_empty() {
                "—".to_string()
            } else {
                truncate(&e.to_addresses, 40)
            };
            html! { <span title={e.to_addresses.clone()}>{shown}</span> }
        }),
        Column::new("subject", "Subject", |e: &EmailDelivery| {
            html! { <span title={e.subject.clone()}>{truncate(&e.subject, 60)}</span> }
        }),
        Column::new("mode", "Mode", |e: &EmailDelivery| {
            if e.error.as_deref().is_some_and(|x| !x.is_empty()) {
                html! { <Badge color="red">{"error"}</Badge> }
            } else if e.mode == "sent" {
                html! { <Badge color="green">{"sent"}</Badge> }
            } else {
                html! { <Badge color="grey">{e.mode.clone()}</Badge> }
            }
        }),
        Column::new("error", "Error", |e: &EmailDelivery| {
            match e.error.as_deref().filter(|x| !x.is_empty()) {
                Some(err) => {
                    html! { <UiBox variant="code" title={err.to_string()}>{head(err, 80)}</UiBox> }
                }
                None => html! { {"—"} },
            }
        }),
    ];
    html! {
        <Table<EmailDelivery>
            variant="container"
            items={emails.to_vec()}
            empty={empty_note("No email deliveries yet. SMTP is unconfigured by default — set SMTP_HOST + COMPLIANCE_REPORT_RECIPIENTS to send for real.")}
            {columns}
            header={html! {
                <Header counter={format!("({})", emails.len())}
                        description="Outbound email audit log. Dryrun rows are recorded when SMTP isn't configured so ops can verify the path fires.">
                    {"Email deliveries"}
                </Header>
            }}
        />
    }
}

// ── Backup / restore ────────────────────────────────────────────────────────

/// Backup / restore admin tools — full DB + attachments dump and a
/// multipart upload to restore from such a dump. State here is local;
/// there's no list view, just one-shot actions.
#[function_component]
fn BackupSection(props: &SectionProps) -> Html {
    let console = &props.console;
    let backup_busy = use_state(|| false);
    let backup_error = use_state(|| None::<String>);
    let restore_files = use_state(Vec::<web_sys::File>::new);
    let restore_force = use_state(|| false);
    let restore_busy = use_state(|| false);
    let restore_result = use_state(|| None::<RestoreResult>);
    let restore_error = use_state(|| None::<String>);

    let download_backup = {
        let (busy, error) = (backup_busy.clone(), backup_error.clone());
        Callback::from(move |_: MouseEvent| {
            let (busy, error) = (busy.clone(), error.clone());
            spawn_local(async move {
                busy.set(true);
                error.set(None);
                // api_fetch wires up X-User-Id + credentials so the admin gate
                // applies. A raw <a href> would skip the header and 403 in test
                // mode, so we go through the helper and download the blob.
                let result = async {
                    let res = api_fetch("GET", "/api/admin/backup").await?;
                    if !res.ok() {
                        return Err(format!("backup failed: {}", res.status()));
                    }
                    let blob = response_blob(&res).await?;
                    let date = head(&now_iso(), 10);
                    download_blob(&blob, &format!("stig-backup-{date}.zip"));
                    Ok(())
                }
                .await;
                if let Err(e) = result {
                    error.set(Some(e));
                }
                busy.set(false);
            });
        })
    };

    let submit_restore = {
        let console = console.clone();
        let (files, force) = (restore_files.clone(), restore_force.clone());
        let (busy, result, error) = (
            restore_busy.clone(),
            restore_result.clone(),
            restore_error.clone(),
        );
        Callback::from(move |_: MouseEvent| {
            let Some(file) = files.first().cloned() else {
                error.set(Some("Pick a backup .zip first.".into()));
                return;
            };
            let console = console.clone();
            let force = *force;
            let (busy, result, error) = (busy.clone(), result.clone(), error.clone());
            spawn_local(async move {
                busy.set(true);
                error.set(None);
                result.set(None);
                let outcome = async {
                    let res =
                        api_upload_raw(&format!("/api/admin/restore?force={force}"), &file).await?;
                    let body = res.json::<Value>().await.unwrap_or_else(|_| json!({}));
                    if !res.ok() {
                        let message = body
                            .get("error")
                            .and_then(Value::as_str)
                            .filter(|m| !m.is_empty());
                        return Err(message
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("restore failed: {}", res.status())));
                    }
                    Ok(serde_json::from_value::<RestoreResult>(body).unwrap_or_default())
                }
                .await;
                match outcome {
                    Ok(restored) => {
                        result.set(Some(restored));
                        // Refresh the rest of the console so any newly-restored users /
                        // assets / webhooks show up immediately.
                        console.refresh().await;
                    }
                    Err(e) => error.set(Some(e)),
                }
                busy.set(false);
            });
        })
    };
    let on_files = {
        let (files, result, error) = (
            restore_files.clone(),
            restore_result.clone(),
            restore_error.clone(),
        );
        Callback::from(move |picked: Vec<web_sys::File>| {
            files.set(picked);
            result.set(None);
            error.set(None);
        })
    };
    let on_force = {
        let force = restore_force.clone();
        Callback::from(move |checked: bool| force.set(checked))
    };

    html! {
        <Container
            header={html! {
                <Header variant="h2"
                        description="Dump every user-generated table + attachment blob to a single ZIP, or restore from a previously-taken backup. The STIG catalog itself is sourced externally and is not included.">
                    {"Backup & restore"}
                </Header>
            }}
            testid="backup-restore-section"
        >
            <ColumnLayout columns={2}>
                <SpaceBetween direction="vertical" size="m">
                    <UiBox variant="h3">{"Backup"}</UiBox>
                    <UiBox variant="p" color="text-body-secondary">
                        {"Streams a ZIP containing one JSONL per table plus the raw attachment blobs. Safe to take at any time."}
                    </UiBox>
                    if let Some(e) = &*backup_error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                    <UiBox>
                        <Button variant="primary" icon_name="download" loading={*backup_busy}
                                onclick={download_backup} testid="backup-download-btn">
                            {"Download backup"}
                        </Button>
                    </UiBox>
                </SpaceBetween>

                <SpaceBetween direction="vertical" size="m">
                    <UiBox variant="h3">{"Restore"}</UiBox>
                    <UiBox variant="p" color="text-body-secondary">
                        {"Upload a backup .zip. Without "}<strong>{"Force overwrite"}</strong>
                        {" the target must be empty (no assets, no checklists). With force, every backed-up table is truncated first — destructive."}
                    </UiBox>
                    <FormField label="Backup file">
                        <FileUpload value={(*restore_files).clone()} on_change={on_files} accept=".zip"
                                    show_file_size=true upload_button_text="Choose backup .zip"
                                    testid="restore-file-input" />
                    </FormField>
                    <div data-testid="restore-force-toggle">
                        <Toggle checked={*restore_force} on_change={on_force}>
                            {"Force overwrite (truncates existing data)"}
                        </Toggle>
                    </div>
                    <UiBox>
                        <Button variant="primary" loading={*restore_busy} disabled={restore_files.is_empty()}
                                onclick={submit_restore} testid="restore-submit-btn">
                            {"Restore"}
                        </Button>
                    </UiBox>
                    if let Some(e) = &*restore_error {
                        <Alert kind="error" testid="restore-error">{e.clone()}</Alert>
                    }
                    if let Some(r) = &*restore_result {
                        {{
                            let (kind, text) = r.summary();
                            html! {
                                <Alert kind={kind} testid="restore-success">{text}</Alert>
                            }
                        }}
                    }
                </SpaceBetween>
            </ColumnLayout>
        </Container>
    }
}

#[cfg(test)]
mod audit_event_tests {
    use super::*;

    #[test]
    fn switching_to_rule_changes_clears_the_system_filter() {
        assert!(view_switch_clears_user(Some(AUDIT_ACTOR_SYSTEM), "rules"));
        assert!(!view_switch_clears_user(Some("some-user-id"), "rules"));
        assert!(!view_switch_clears_user(None, "rules"));
        assert!(!view_switch_clears_user(
            Some(AUDIT_ACTOR_SYSTEM),
            "requests"
        ));
    }

    #[test]
    fn restore_summary_warns_unless_the_signature_was_verified() {
        let ok: RestoreResult = serde_json::from_value(json!({
            "restored": { "users": 2 }, "attachmentsWritten": 1, "signatureStatus": "verified"
        }))
        .unwrap();
        let (kind, text) = ok.summary();
        assert_eq!(kind, "success");
        assert!(text.contains("Signature verified"), "{text}");
        for status in ["unsigned", "unknown_key"] {
            let r: RestoreResult =
                serde_json::from_value(json!({ "signatureStatus": status })).unwrap();
            let (kind, text) = r.summary();
            assert_eq!(kind, "warning");
            assert!(
                text.contains("integrity was not verified") && text.contains(status),
                "{text}"
            );
        }
        // An older backend sends no status.
        let (kind, _) = RestoreResult::default().summary();
        assert_eq!(kind, "warning");
    }

    #[test]
    fn is_system_comes_from_the_flag_not_the_name() {
        let r: AuditEventRow =
            serde_json::from_value(json!({ "byName": null, "isSystem": true })).unwrap();
        assert!(r.is_system);
        assert_eq!(r.by_name, None);
        let r: AuditEventRow = serde_json::from_value(json!({ "byName": "system" })).unwrap();
        assert!(!r.is_system);
    }

    #[test]
    fn the_by_cell_keys_on_the_flag_only() {
        let sys = AuditEventRow {
            is_system: true,
            by_name: None,
            ..AuditEventRow::default()
        };
        assert_eq!(actor_cell(&sys), ActorCell::System);
        let spoof = AuditEventRow {
            by_name: Some("system".into()),
            ..AuditEventRow::default()
        };
        assert_eq!(actor_cell(&spoof), ActorCell::Name("system"));
        // A non-system row with no name falls back to the dash.
        let nameless = AuditEventRow::default();
        assert!(!nameless.is_system && nameless.by_name.is_none());
        assert_eq!(actor_cell(&nameless), ActorCell::Name("—"));
    }

    #[test]
    fn view_switch_callback_clears_a_system_actor_then_resets() {
        use std::cell::RefCell;
        use std::rc::Rc;
        let run = |selected: Option<&str>, id: &str| {
            let log: Rc<RefCell<Vec<String>>> = Rc::default();
            let (l1, l2) = (log.clone(), log.clone());
            let cb = view_switch_callback(
                selected.map(str::to_string),
                Callback::from(move |_: ()| l1.borrow_mut().push("clear".into())),
                Callback::from(move |v: AttrValue| l2.borrow_mut().push(format!("reset:{v}"))),
            );
            cb.emit(AttrValue::from(id.to_string()));
            let out = log.borrow().clone();
            out
        };
        assert_eq!(
            run(Some(AUDIT_ACTOR_SYSTEM), "rules"),
            ["clear", "reset:rules"]
        );
        assert_eq!(
            run(Some(AUDIT_ACTOR_SYSTEM), "requests"),
            ["reset:requests"]
        );
        assert_eq!(run(Some("some-user-id"), "rules"), ["reset:rules"]);
        assert_eq!(run(None, "rules"), ["reset:rules"]);
    }

    #[test]
    fn audit_filter_pairs_pass_dates_and_gate_actor() {
        let f = AuditFilters {
            from: "2024-01-01".into(),
            to: "2024-02-01".into(),
            ..AuditFilters::default()
        };
        let p = audit_filter_pairs(&f, true);
        assert!(p.contains(&("from", "2024-01-01".to_string())));
        assert!(p.contains(&("to", "2024-02-01".to_string())));
        assert!(!p.iter().any(|(k, _)| *k == "actor"));
        let f = AuditFilters {
            actor_system: true,
            ..AuditFilters::default()
        };
        assert!(!audit_filter_pairs(&f, false)
            .iter()
            .any(|(k, _)| *k == "actor"));
    }

    #[test]
    fn audit_filter_pairs_send_actor_only_for_requests() {
        let f = AuditFilters {
            actor_system: true,
            asset_id: "a1".into(),
            ..AuditFilters::default()
        };
        let req = audit_filter_pairs(&f, true);
        assert!(req.contains(&("actor", "system".to_string())));
        assert!(req.contains(&("assetId", "a1".to_string())));
        assert!(!req.iter().any(|(k, _)| *k == "userId"));
        assert!(!audit_filter_pairs(&f, false)
            .iter()
            .any(|(k, _)| *k == "actor"));
        // Even a stray user id is dropped next to actor=system.
        let f = AuditFilters {
            user_id: "u1".into(),
            actor_system: true,
            ..AuditFilters::default()
        };
        assert!(!audit_filter_pairs(&f, true)
            .iter()
            .any(|(k, _)| *k == "userId"));
    }

    fn event(detail: Value) -> AuditEventRow {
        AuditEventRow {
            detail,
            ..AuditEventRow::default()
        }
    }

    #[test]
    fn event_rows_deserialize_the_request_context() {
        let r: AuditEventRow = serde_json::from_value(
            json!({ "sourceIp": "10.0.0.1", "requestId": "abc", "userRole": "admin" }),
        )
        .unwrap();
        assert_eq!(
            (
                r.source_ip.as_deref(),
                r.request_id.as_deref(),
                r.user_role.as_deref()
            ),
            (Some("10.0.0.1"), Some("abc"), Some("admin"))
        );
        // Rows written before the context columns existed have none.
        let old: AuditEventRow =
            serde_json::from_value(json!({ "action": "checklist.save" })).unwrap();
        assert!(old.source_ip.is_none() && old.request_id.is_none() && old.user_role.is_none());
    }

    #[test]
    fn repeat_count_deserializes_and_labels_collapsed_rows() {
        let r: AuditEventRow = serde_json::from_value(json!({ "repeatCount": 7 })).unwrap();
        assert_eq!(r.repeat_count, 7);
        assert_eq!(repeat_label(&r), "\u{d7}7");
        let old: AuditEventRow = serde_json::from_value(json!({})).unwrap();
        assert_eq!(repeat_label(&old), "1");
        assert!(old.last_occurred_at.is_none());
    }

    #[test]
    fn summary_shows_the_reason_for_denied_and_rejected_requests() {
        assert_eq!(
            event_summary(&event(json!({ "reason": "invalid_status" }))),
            "invalid status"
        );
    }

    #[test]
    fn summary_lists_counts_and_creation() {
        let e = event(
            json!({ "targetStatus": "open", "requested": 3, "applied": 2, "errors": 1, "created": true }),
        );
        assert_eq!(
            event_summary(&e),
            "status open, 3 requested, 2 applied, 1 errors, checklist created"
        );
    }

    #[test]
    fn summary_of_an_empty_detail_is_a_dash() {
        assert_eq!(event_summary(&event(json!({}))), "—");
    }
}
