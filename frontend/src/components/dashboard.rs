//! Compliance dashboard: KPI cards, posture charts, heatmap, rule-level diff,
//! per-system progress, findings drill-down with bulk actions, baselines and
//! recent activity.

use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::future::Future;
use std::rc::Rc;

use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::{future_to_promise, JsFuture};
use yew::prelude::*;
use yew::virtual_dom::VText;

use crate::api::{api_fetch, api_get, api_json};
use crate::auth::use_current_user;
use crate::hooks::{use_url_state, UrlVal};
use crate::ui::*;
use crate::util::{encode_uri_component, now_ms, parse_date_ms, spawn_local, to_locale_string};

// ── API payloads ────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DashboardData {
    totals: Totals,
    by_asset: Vec<AssetSummary>,
    top_open_rules: Vec<TopRule>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Totals {
    assets: i64,
    checklists: i64,
    open_findings: i64,
    overdue_findings: i64,
    stale_findings: i64,
    stale_threshold_days: i64,
    reviewed_rules: i64,
    total_rules: i64,
    highest_risk_score: i64,
    highest_risk_asset_name: Option<String>,
    highest_weighted_score: f64,
    highest_weighted_asset_name: Option<String>,
    highest_weighted_rule_id: Option<String>,
    outdated_checklists: i64,
    stale_baselines: i64,
    stale_baseline_days: Option<i64>,
    compliance_score: f64,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AssetSummary {
    id: String,
    name: String,
    risk_score: i64,
    weighted_risk_score: f64,
    tags: Vec<String>,
    checklists: Vec<ChecklistSummary>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ChecklistSummary {
    id: String,
    stig_id: String,
    stig_title: String,
    rule_count: i64,
    open_count: i64,
    overdue_count: i64,
    naf_count: i64,
    na_count: i64,
    reviewed_count: i64,
    outdated: bool,
    compliance_score: f64,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct TopRule {
    rule_id: String,
    affected_systems: i64,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Trend {
    overall: Vec<TrendPoint>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct TrendPoint {
    captured_at: String,
    open: f64,
    reviewed: f64,
    compliance_score: f64,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Finding {
    checklist_id: String,
    rule_id: String,
    finding_details: String,
    comments: String,
    updated_at: String,
    stig_title: String,
    asset_name: String,
    owner_name: String,
    assignee_name: Option<String>,
    due_date: Option<String>,
    severity: Option<String>,
    title: Option<String>,
    description: Option<String>,
    check_text: Option<String>,
    fix_text: Option<String>,
    weighted_score: f64,
}

impl Finding {
    fn key(&self) -> String {
        format!("{}:{}", self.checklist_id, self.rule_id)
    }
}

/// One audit-log row (`/api/activity` and per-rule history share the shape).
#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AuditEntry {
    id: i64,
    occurred_at: String,
    user_name: String,
    rule_id: String,
    asset_name: Option<String>,
    field: String,
    from_value: Option<String>,
    to_value: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Baseline {
    id: String,
    name: String,
    created_by: String,
    created_by_name: String,
    created_at: String,
    rule_count: i64,
    is_stale: bool,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BaselineDiffEntry {
    checklist_id: String,
    rule_id: String,
    from_status: String,
    to_status: String,
    asset_name: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BaselineDiff {
    regressed: Vec<BaselineDiffEntry>,
    improved: Vec<BaselineDiffEntry>,
    unchanged: i64,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct UserSummary {
    id: String,
    display_name: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BulkReapplyResponse {
    results: Vec<BulkReapplyResult>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BulkReapplyResult {
    checklist_id: String,
    asset_name: String,
    stig_title: String,
    from_version: String,
    to_version: String,
    pruned_rules: u64,
    status: String,
    error: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RuleDiffResponse {
    rules: Vec<RuleDiff>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RuleDiff {
    asset_name: String,
    checklist_id: String,
    stig_title: String,
    rule_id: String,
    changes: Vec<FieldChange>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct FieldChange {
    field: String,
    from: Option<String>,
    to: Option<String>,
    by: String,
    at: String,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const SEVERITIES: [&str; 3] = ["CAT I", "CAT II", "CAT III"];

fn severity_options() -> Vec<SelectOption> {
    std::iter::once(SelectOption::new("", "All severities"))
        .chain(SEVERITIES.iter().map(|s| SelectOption::new(*s, *s)))
        .collect()
}

fn severity_badge(sev: &str) -> &'static str {
    match sev {
        "CAT I" => "red",
        "CAT II" => "blue",
        _ => "grey",
    }
}

/// Badge colour for a status *label* ("Open", "Not a finding", …).
fn status_color(label: &str) -> &'static str {
    match label {
        "Open" => "red",
        "Not a finding" => "green",
        "Not applicable" => "blue",
        _ => "grey",
    }
}

fn status_label(status: &str) -> Option<&'static str> {
    match status {
        "open" => Some("Open"),
        "not_a_finding" => Some("Not a finding"),
        "not_applicable" => Some("Not applicable"),
        "not_reviewed" => Some("Not reviewed"),
        _ => None,
    }
}

/// Percentage with one decimal.
fn pct(numer: f64, denom: f64) -> f64 {
    if denom == 0.0 {
        return 0.0;
    }
    (numer / denom * 1000.0).round() / 10.0
}

/// Badge colour for a weighted score. Matches the formula's natural range:
///   single CAT II open finding on unclassified ≈ 3.0
///   anything ≥ 20 implies a CAT I on a classified system
fn weight_color(w: f64) -> &'static str {
    if w > 20.0 {
        "red"
    } else if w > 5.0 {
        "blue"
    } else {
        "grey"
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn audit_field_label(field: &str) -> &str {
    match field {
        "status" => "status",
        "finding_details" => "finding details",
        "comments" => "comments",
        "assignee_id" => "assignee",
        "due_date" => "due date",
        other => other,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    } else {
        s.to_string()
    }
}

/// Audit value clipped to 60 chars; `fallback` when null/empty.
fn audit_value(v: &Option<String>, fallback: &str) -> String {
    match v.as_deref() {
        None | Some("") => fallback.to_string(),
        Some(s) => truncate(s, 60),
    }
}

fn locale_compare(a: &str, b: &str) -> Ordering {
    js_sys::JsString::from(a)
        .locale_compare(b, &js_sys::Array::new(), &js_sys::Object::new())
        .cmp(&0)
}

/// A plain text node (the kit's `Modal` gives text headers a heading).
fn text(s: impl Into<AttrValue>) -> Html {
    Html::VText(VText::new(s))
}

fn inactive_dash() -> Html {
    html! { <UiBox color="text-status-inactive">{"—"}</UiBox> }
}

/// Run a future as a JS promise, parking its output in a slot, so several
/// requests can be awaited together with `Promise.all`.
fn start<T: 'static>(fut: impl Future<Output = T> + 'static) -> (js_sys::Promise, Rc<RefCell<Option<T>>>) {
    let slot = Rc::new(RefCell::new(None));
    let s = slot.clone();
    let promise = future_to_promise(async move {
        *s.borrow_mut() = Some(fut.await);
        Ok(JsValue::UNDEFINED)
    });
    (promise, slot)
}

/// What the drill-down table is showing (mirrors the `dd` URL param).
#[derive(Clone, PartialEq)]
enum Drilldown {
    /// Open instances of one rule across systems.
    Rule(String),
    /// Open findings with no activity in N days.
    Stale(i64),
    /// "open" | "overdue"
    Kind(String),
}

impl Drilldown {
    fn title(&self) -> &'static str {
        match self {
            Drilldown::Rule(_) => "Rule drill-down",
            Drilldown::Stale(_) => "Stale findings",
            Drilldown::Kind(k) if k == "overdue" => "Overdue findings",
            Drilldown::Kind(_) => "Open findings",
        }
    }

    fn describe(&self) -> String {
        match self {
            Drilldown::Rule(id) => format!("Open instances of {id} across systems."),
            Drilldown::Stale(days) => format!("Open findings with no activity in the last {days} days."),
            Drilldown::Kind(k) if k == "overdue" => "Open findings whose due date has already passed.".into(),
            Drilldown::Kind(_) => "All currently-open findings across systems.".into(),
        }
    }
}

/// One row of the "By system" table: an asset × checklist pair, or an asset
/// with no STIGs applied (`checklist: None`).
#[derive(Clone, PartialEq)]
struct ChecklistRow {
    asset_id: String,
    asset_name: String,
    risk_score: i64,
    weighted_risk_score: f64,
    checklist: Option<ChecklistSummary>,
}

#[derive(Clone, PartialEq, Default)]
struct BulkDraft {
    status: String,
    finding_details: String,
    comments: String,
}

/// Counter bumped by Refresh / bulk saves so the baseline-diff effect re-fires
/// even when the selected baseline is unchanged.
#[derive(Clone)]
struct Tick {
    state: UseStateHandle<u32>,
    latest: Rc<RefCell<u32>>,
}

impl Tick {
    fn bump(&self) {
        let mut n = self.latest.borrow_mut();
        *n += 1;
        self.state.set(*n);
    }
}

/// Everything `refresh()` touches, bundled so async flows can await it.
#[derive(Clone)]
struct Refresher {
    loading: UseStateHandle<bool>,
    error: UseStateHandle<Option<String>>,
    data: UseStateHandle<Option<DashboardData>>,
    trend: UseStateHandle<Option<Trend>>,
    activity: UseStateHandle<Vec<AuditEntry>>,
    tick: Tick,
}

impl Refresher {
    async fn run(&self) {
        self.loading.set(true);
        self.error.set(None);
        let (p_data, data) = start(api_get::<DashboardData>("/api/dashboard"));
        let (p_trend, trend) = start(api_get::<Trend>("/api/dashboard/trend?days=30"));
        let (p_activity, activity) = start(api_get::<Vec<AuditEntry>>("/api/activity?limit=25"));
        let all = js_sys::Promise::all(&js_sys::Array::of3(&p_data, &p_trend, &p_activity));
        let _ = JsFuture::from(all).await;
        let data = data.borrow_mut().take();
        let trend = trend.borrow_mut().take();
        // Activity is best-effort: a failure just leaves the section empty.
        let activity = activity.borrow_mut().take().and_then(Result::ok).unwrap_or_default();
        match (data, trend) {
            (Some(Ok(d)), Some(Ok(t))) => {
                self.data.set(Some(d));
                self.trend.set(Some(t));
                self.activity.set(activity);
                self.tick.bump();
            }
            (Some(Err(e)), _) | (_, Some(Err(e))) => self.error.set(Some(e)),
            _ => self.error.set(Some("Request failed".into())),
        }
        self.loading.set(false);
    }
}

/// Baseline list + current selection. `selected_latest` mirrors the state so
/// async code can keep the selection when it still exists after a reload.
#[derive(Clone)]
struct BaselineCtl {
    baselines: UseStateHandle<Vec<Baseline>>,
    selected: UseStateHandle<Option<String>>,
    selected_latest: Rc<RefCell<Option<String>>>,
}

impl BaselineCtl {
    fn select(&self, id: Option<String>) {
        *self.selected_latest.borrow_mut() = id.clone();
        self.selected.set(id);
    }

    async fn refresh(&self) {
        // Non-fatal on error — leave the picker as it is.
        if let Ok(rows) = api_get::<Vec<Baseline>>("/api/baselines").await {
            let curr = self.selected_latest.borrow().clone();
            let keep = curr.filter(|c| rows.iter().any(|b| &b.id == c));
            let next = keep.or_else(|| rows.first().map(|b| b.id.clone()));
            self.baselines.set(rows);
            self.select(next);
        }
    }
}

// ── Dashboard ───────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct DashboardProps {}

#[function_component]
pub fn Dashboard(_props: &DashboardProps) -> Html {
    let current_user = use_current_user();
    let data = use_state(|| None::<DashboardData>);
    let trend = use_state(|| None::<Trend>);
    let loading = use_state(|| true);
    let error = use_state(|| None::<String>);

    // Drill-down + filter state lives in `?dd=…&rule=…&stale=N&sev=…&me=true`
    // so the URL bar is a saveable, shareable view.
    // dd ∈ "" | "open" | "overdue" | "stale" | "rule"
    let (url_filters, set_url_filters) = use_url_state(vec![
        ("dd", UrlVal::from("")),
        ("rule", UrlVal::from("")),
        ("stale", UrlVal::from(0.0)),
        ("sev", UrlVal::from("")),
        ("me", UrlVal::from(false)),
    ]);
    let drilldown: Option<Drilldown> = match url_filters.str("dd").as_str() {
        "" => None,
        "rule" => Some(Drilldown::Rule(url_filters.str("rule"))),
        "stale" => {
            let days = url_filters.num("stale") as i64;
            Some(Drilldown::Stale(if days == 0 { 30 } else { days }))
        }
        kind => Some(Drilldown::Kind(kind.to_string())),
    };
    let severity_filter: Option<String> =
        Some(url_filters.str("sev")).filter(|s| SEVERITIES.contains(&s.as_str()));
    let mine_only = url_filters.bool("me");

    let set_drilldown = {
        let set = set_url_filters.clone();
        Callback::from(move |d: Option<Drilldown>| {
            let (dd, rule, stale) = match d {
                None => (String::new(), String::new(), 0.0),
                Some(Drilldown::Rule(id)) => ("rule".to_string(), id, 0.0),
                Some(Drilldown::Stale(days)) => ("stale".to_string(), String::new(), days as f64),
                Some(Drilldown::Kind(kind)) => (kind, String::new(), 0.0),
            };
            set.emit(vec![("dd", dd.into()), ("rule", rule.into()), ("stale", stale.into())]);
        })
    };

    let findings = use_state(Vec::<Finding>::new);
    let findings_loading = use_state(|| false);
    let findings_error = use_state(|| None::<String>);
    // Weight-column sort for the drill-down: `Some(descending)` when active.
    let weight_sort = use_state(|| None::<bool>);

    // Inline expanded finding shown below the drill-down table.
    let expanded_finding = use_state(|| None::<Finding>);
    let rule_history = use_state(Vec::<AuditEntry>::new);

    // Drill-down multi-select + bulk-edit
    let selected_findings = use_state(Vec::<Finding>::new);
    let bulk_open = use_state(|| false);
    let bulk_draft = use_state(BulkDraft::default);
    let bulk_saving = use_state(|| false);
    let bulk_error = use_state(|| None::<String>);

    // Streamlined "Reassign" preset modal — covers the common "just change the
    // assignee" workflow without making power-users wade through the full
    // bulk-update form. Uses the same PATCH /api/findings/bulk endpoint with
    // an assignee-only patch (null = unassign).
    let reassign_open = use_state(|| false);
    let reassign_assignee_id = use_state(|| None::<String>);
    let reassign_saving = use_state(|| false);
    let reassign_error = use_state(|| None::<String>);
    let reassign_flash = use_state(|| None::<String>);
    let users = use_state(Vec::<UserSummary>::new);

    // Recent activity (loaded with the rest of the dashboard).
    let activity = use_state(Vec::<AuditEntry>::new);

    // Bulk re-apply
    let bulk_reapply_open = use_state(|| false);
    let bulk_reapply_running = use_state(|| false);
    let bulk_reapply_error = use_state(|| None::<String>);
    let bulk_reapply_results = use_state(|| None::<Vec<BulkReapplyResult>>);

    // Baselines
    let baselines = use_state(Vec::<Baseline>::new);
    let selected_baseline_id = use_state(|| None::<String>);
    let selected_baseline_latest = use_mut_ref(|| None::<String>);
    let baseline_diff = use_state(|| None::<BaselineDiff>);
    let diff_loading = use_state(|| false);
    let refresh_tick = use_state(|| 0u32);
    let refresh_tick_latest = use_mut_ref(|| 0u32);
    let save_modal_open = use_state(|| false);
    let new_baseline_name = use_state(String::new);
    let saving_baseline = use_state(|| false);
    let save_baseline_error = use_state(|| None::<String>);

    let tick = Tick { state: refresh_tick.clone(), latest: refresh_tick_latest };
    let refresher = Refresher {
        loading: loading.clone(),
        error: error.clone(),
        data: data.clone(),
        trend: trend.clone(),
        activity: activity.clone(),
        tick: tick.clone(),
    };
    let baseline_ctl = BaselineCtl {
        baselines: baselines.clone(),
        selected: selected_baseline_id.clone(),
        selected_latest: selected_baseline_latest,
    };

    let refresh = {
        let refresher = refresher.clone();
        Callback::from(move |_: MouseEvent| {
            let refresher = refresher.clone();
            spawn_local(async move { refresher.run().await });
        })
    };

    {
        let refresher = refresher.clone();
        let baseline_ctl = baseline_ctl.clone();
        use_effect_with((), move |_| {
            spawn_local(async move { refresher.run().await });
            spawn_local(async move { baseline_ctl.refresh().await });
        });
    }

    // Load diff when a baseline is selected.
    {
        let baseline_diff = baseline_diff.clone();
        let diff_loading = diff_loading.clone();
        use_effect_with(((*selected_baseline_id).clone(), *refresh_tick), move |(id, _)| {
            let cancelled = Rc::new(Cell::new(false));
            match id.clone() {
                None => baseline_diff.set(None),
                Some(id) => {
                    let cancelled = cancelled.clone();
                    diff_loading.set(true);
                    spawn_local(async move {
                        let res = api_get::<BaselineDiff>(&format!("/api/baselines/{id}/diff")).await;
                        if !cancelled.get() {
                            baseline_diff.set(res.ok());
                            diff_loading.set(false);
                        }
                    });
                }
            }
            move || cancelled.set(true)
        });
    }

    // Load the user list for the Reassign modal's Select. One-shot — the user
    // directory is small and the dashboard is short-lived.
    {
        let users = users.clone();
        use_effect_with((), move |_| {
            let cancelled = Rc::new(Cell::new(false));
            let c = cancelled.clone();
            spawn_local(async move {
                // Non-fatal — the Select will just have an empty options list.
                if let Ok(rows) = api_get::<Vec<UserSummary>>("/api/users").await {
                    if !c.get() {
                        users.set(rows);
                    }
                }
            });
            move || cancelled.set(true)
        });
    }

    // Clear the selection and close the expanded panel whenever the
    // drill-down/filter changes, then (re)load the findings.
    {
        let selected_findings = selected_findings.clone();
        let expanded_finding = expanded_finding.clone();
        let findings = findings.clone();
        let findings_loading = findings_loading.clone();
        let findings_error = findings_error.clone();
        use_effect_with(
            (drilldown.clone(), severity_filter.clone(), mine_only),
            move |(drilldown, severity, mine_only)| {
                selected_findings.set(vec![]);
                expanded_finding.set(None);
                let cancelled = Rc::new(Cell::new(false));
                match drilldown {
                    None => {
                        findings.set(vec![]);
                        findings_error.set(None);
                    }
                    Some(d) => {
                        let mut qs: Vec<(&str, String)> = vec![("status", "open".into())];
                        if let Drilldown::Rule(id) = d {
                            if !id.is_empty() {
                                qs.push(("ruleId", id.clone()));
                            }
                        }
                        if let Some(sev) = severity {
                            qs.push(("severity", sev.clone()));
                        }
                        if *mine_only {
                            qs.push(("assignee", "me".into()));
                        }
                        match d {
                            Drilldown::Kind(k) if k == "overdue" => qs.push(("pastDue", "true".into())),
                            Drilldown::Stale(days) => qs.push(("olderThanDays", days.to_string())),
                            _ => {}
                        }
                        let qs = qs
                            .iter()
                            .map(|(k, v)| format!("{k}={}", encode_uri_component(v)))
                            .collect::<Vec<_>>()
                            .join("&");
                        findings_loading.set(true);
                        findings_error.set(None);
                        let cancelled = cancelled.clone();
                        spawn_local(async move {
                            let res = api_get::<Vec<Finding>>(&format!("/api/findings?{qs}")).await;
                            if cancelled.get() {
                                return;
                            }
                            match res {
                                Ok(rows) => findings.set(rows),
                                Err(e) => findings_error.set(Some(e)),
                            }
                            findings_loading.set(false);
                        });
                    }
                }
                move || cancelled.set(true)
            },
        );
    }

    // Load the audit history for whichever rule is expanded.
    {
        let rule_history = rule_history.clone();
        use_effect_with((*expanded_finding).clone(), move |expanded| {
            let cancelled = Rc::new(Cell::new(false));
            match expanded {
                None => rule_history.set(vec![]),
                Some(f) => {
                    let path = format!(
                        "/api/checklists/{}/rules/{}/history",
                        f.checklist_id,
                        encode_uri_component(&f.rule_id)
                    );
                    let cancelled = cancelled.clone();
                    spawn_local(async move {
                        let rows = api_get::<Vec<AuditEntry>>(&path).await.unwrap_or_default();
                        if !cancelled.get() {
                            rule_history.set(rows);
                        }
                    });
                }
            }
            move || cancelled.set(true)
        });
    }

    let save_baseline = {
        let name = (*new_baseline_name).trim().to_string();
        let new_baseline_name = new_baseline_name.clone();
        let saving = saving_baseline.clone();
        let err = save_baseline_error.clone();
        let modal = save_modal_open.clone();
        let ctl = baseline_ctl.clone();
        Callback::from(move |_: MouseEvent| {
            if name.is_empty() {
                err.set(Some("Name is required.".into()));
                return;
            }
            saving.set(true);
            err.set(None);
            let (name, new_baseline_name, saving, err, modal, ctl) =
                (name.clone(), new_baseline_name.clone(), saving.clone(), err.clone(), modal.clone(), ctl.clone());
            spawn_local(async move {
                match api_json::<Baseline, _>("/api/baselines", "POST", Some(&json!({ "name": name }))).await {
                    Ok(created) => {
                        modal.set(false);
                        new_baseline_name.set(String::new());
                        ctl.refresh().await;
                        ctl.select(Some(created.id));
                    }
                    Err(e) => err.set(Some(e)),
                }
                saving.set(false);
            });
        })
    };

    let run_bulk_reapply = {
        let running = bulk_reapply_running.clone();
        let err = bulk_reapply_error.clone();
        let results = bulk_reapply_results.clone();
        let modal = bulk_reapply_open.clone();
        let refresher = refresher.clone();
        Callback::from(move |_: MouseEvent| {
            running.set(true);
            err.set(None);
            let (running, err, results, modal, refresher) =
                (running.clone(), err.clone(), results.clone(), modal.clone(), refresher.clone());
            spawn_local(async move {
                match api_json::<BulkReapplyResponse, _>("/api/checklists/bulk-reapply", "POST", Some(&json!({}))).await
                {
                    Ok(res) => {
                        results.set(Some(res.results));
                        modal.set(false);
                        refresher.run().await;
                    }
                    Err(e) => err.set(Some(e)),
                }
                running.set(false);
            });
        })
    };

    let delete_baseline = {
        let ctl = baseline_ctl.clone();
        let id = (*selected_baseline_id).clone();
        Callback::from(move |_: MouseEvent| {
            let Some(id) = id.clone() else { return };
            let ctl = ctl.clone();
            spawn_local(async move {
                match api_fetch("DELETE", &format!("/api/baselines/{id}")).await {
                    Ok(res) if res.ok() || res.status() == 204 => ctl.refresh().await,
                    _ => {}
                }
            });
        })
    };

    let open_bulk_modal = {
        let draft = bulk_draft.clone();
        let err = bulk_error.clone();
        let open = bulk_open.clone();
        Callback::from(move |_: MouseEvent| {
            draft.set(BulkDraft::default());
            err.set(None);
            open.set(true);
        })
    };

    let bulk_targets: Vec<serde_json::Value> = selected_findings
        .iter()
        .map(|f| json!({ "checklistId": f.checklist_id, "ruleId": f.rule_id }))
        .collect();

    let save_bulk = {
        let targets = bulk_targets.clone();
        let draft = (*bulk_draft).clone();
        let saving = bulk_saving.clone();
        let err = bulk_error.clone();
        let open = bulk_open.clone();
        let selected = selected_findings.clone();
        let refresher = refresher.clone();
        Callback::from(move |_: MouseEvent| {
            if targets.is_empty() {
                return;
            }
            // Build a patch object that only includes fields the user actually set.
            let mut patch = serde_json::Map::new();
            if !draft.status.is_empty() {
                patch.insert("status".into(), draft.status.clone().into());
            }
            if !draft.finding_details.is_empty() {
                patch.insert("findingDetails".into(), draft.finding_details.clone().into());
            }
            if !draft.comments.is_empty() {
                patch.insert("comments".into(), draft.comments.clone().into());
            }
            if patch.is_empty() {
                err.set(Some("Set at least one field to apply.".into()));
                return;
            }
            saving.set(true);
            err.set(None);
            let body = json!({ "targets": targets, "patch": patch });
            let (saving, err, open, selected, refresher) =
                (saving.clone(), err.clone(), open.clone(), selected.clone(), refresher.clone());
            spawn_local(async move {
                match api_json::<serde_json::Value, _>("/api/findings/bulk", "PATCH", Some(&body)).await {
                    Ok(_) => {
                        open.set(false);
                        selected.set(vec![]);
                        // Refetch the baseline diff + the dashboard counters.
                        refresher.tick.bump();
                        refresher.run().await;
                    }
                    Err(e) => err.set(Some(e)),
                }
                saving.set(false);
            });
        })
    };

    let open_reassign_modal = {
        let assignee = reassign_assignee_id.clone();
        let err = reassign_error.clone();
        let open = reassign_open.clone();
        Callback::from(move |_: MouseEvent| {
            assignee.set(None);
            err.set(None);
            open.set(true);
        })
    };

    let save_reassign = {
        let targets = bulk_targets;
        let assignee = (*reassign_assignee_id).clone();
        let assignee_name = assignee.as_ref().map(|id| {
            users
                .iter()
                .find(|u| &u.id == id)
                .map(|u| u.display_name.clone())
                .unwrap_or_else(|| "selected user".into())
        });
        let saving = reassign_saving.clone();
        let err = reassign_error.clone();
        let open = reassign_open.clone();
        let flash = reassign_flash.clone();
        let selected = selected_findings.clone();
        let refresher = refresher.clone();
        Callback::from(move |_: MouseEvent| {
            if targets.is_empty() {
                return;
            }
            saving.set(true);
            err.set(None);
            // An explicit JSON `null` is what the bulk endpoint's tri-state
            // assignee_id treats as "unassign"; a user id reassigns.
            let body = json!({ "targets": targets, "patch": { "assigneeId": assignee } });
            let count = targets.len();
            let message = match &assignee_name {
                Some(name) => format!("Reassigned {count} finding{} to {name}.", plural(count)),
                None => format!("Unassigned {count} finding{}.", plural(count)),
            };
            let (saving, err, open, flash, selected, refresher) =
                (saving.clone(), err.clone(), open.clone(), flash.clone(), selected.clone(), refresher.clone());
            spawn_local(async move {
                match api_json::<serde_json::Value, _>("/api/findings/bulk", "PATCH", Some(&body)).await {
                    Ok(_) => {
                        flash.set(Some(message));
                        open.set(false);
                        selected.set(vec![]);
                        refresher.tick.bump();
                        refresher.run().await;
                    }
                    Err(e) => err.set(Some(e)),
                }
                saving.set(false);
            });
        })
    };

    if *loading {
        return html! {
            <UiBox padding="xxl" text_align="center">
                <StatusIndicator kind="loading">{"Loading dashboard"}</StatusIndicator>
            </UiBox>
        };
    }

    if let Some(err) = &*error {
        return html! {
            <UiBox padding="m">
                <Alert kind="error" header={text("Failed to load dashboard")}
                       action={html! { <Button onclick={refresh}>{"Retry"}</Button> }}>
                    {err.clone()}
                </Alert>
            </UiBox>
        };
    }

    let Some(data) = (*data).clone() else {
        return Html::default();
    };
    let totals = &data.totals;

    // Pre-flatten the per-asset / per-checklist rows for the table.
    // Sort assets by risk score descending so the most-at-risk system surfaces.
    let checklist_rows: Vec<ChecklistRow> = {
        let mut sorted: Vec<&AssetSummary> = data.by_asset.iter().collect();
        sorted.sort_by_key(|a| std::cmp::Reverse(a.risk_score));
        sorted
            .into_iter()
            .flat_map(|a| {
                let row = |checklist: Option<ChecklistSummary>| ChecklistRow {
                    asset_id: a.id.clone(),
                    asset_name: a.name.clone(),
                    risk_score: a.risk_score,
                    weighted_risk_score: a.weighted_risk_score,
                    checklist,
                };
                if a.checklists.is_empty() {
                    vec![row(None)]
                } else {
                    a.checklists.iter().cloned().map(|c| row(Some(c))).collect()
                }
            })
            .collect()
    };

    // Status pie chart data (only meaningful with at least some reviewed rules).
    // We don't break NaF / NA / explicit not_reviewed apart at the totals
    // level — sum to "Reviewed (compliant or N/A)" for the headline pie.
    let pie_data: Vec<PieDatum> = [
        ("Open", totals.open_findings, "red"),
        ("Reviewed", (totals.reviewed_rules - totals.open_findings).max(0), "green"),
        ("Not reviewed", (totals.total_rules - totals.reviewed_rules).max(0), "grey"),
    ]
    .into_iter()
    .filter(|(_, value, _)| *value > 0)
    .map(|(title, value, color)| PieDatum::new(title, value as f64).color(color))
    .collect();

    let compliant_pct = pct(
        (totals.reviewed_rules - totals.open_findings).max(0) as f64,
        totals.total_rules as f64,
    );
    let outdated = totals.outdated_checklists;
    let selected_count = selected_findings.len();
    let count_suffix = if selected_count > 0 { format!(" ({selected_count})") } else { String::new() };

    let kpi_drill = |d: Drilldown| {
        let set = set_drilldown.clone();
        Callback::from(move |_: MouseEvent| set.emit(Some(d.clone())))
    };

    let header_actions = {
        let open_reapply = {
            let err = bulk_reapply_error.clone();
            let open = bulk_reapply_open.clone();
            Callback::from(move |_: MouseEvent| {
                err.set(None);
                open.set(true);
            })
        };
        let open_save = {
            let name = new_baseline_name.clone();
            let err = save_baseline_error.clone();
            let open = save_modal_open.clone();
            Callback::from(move |_: MouseEvent| {
                name.set(String::new());
                err.set(None);
                open.set(true);
            })
        };
        html! {
            <SpaceBetween direction="horizontal" size="xs">
                <Button disabled={outdated == 0} onclick={open_reapply}>
                    { if outdated > 0 { format!("Re-apply all ({outdated})") } else { "Re-apply all".to_string() } }
                </Button>
                <Button onclick={open_save}>{"Save baseline"}</Button>
                <Button icon_name="refresh" onclick={refresh.clone()}>{"Refresh"}</Button>
            </SpaceBetween>
        }
    };

    let kpis = html! {
        // KPI row — 4-column grid; the cards wrap onto further rows.
        <ColumnLayout columns={4} variant="text-grid">
            <KpiCard label="Systems" value={totals.assets.to_string()} />
            <KpiCard label="Applied STIGs" value={totals.checklists.to_string()} />
            <KpiCard
                label="Open findings"
                value={totals.open_findings.to_string()}
                tone={if totals.open_findings > 0 { "warning" } else { "ok" }}
                onclick={(totals.open_findings > 0).then(|| kpi_drill(Drilldown::Kind("open".into())))}
            />
            <KpiCard
                label="Compliant"
                value={format!("{compliant_pct}%")}
                sub={format!("{} of {} rules", totals.reviewed_rules - totals.open_findings, totals.total_rules)}
                tone={(totals.open_findings == 0 && totals.reviewed_rules > 0).then_some("ok")}
            />
            <KpiCard
                label="Compliance"
                value={format!("{:.1}%", totals.compliance_score)}
                sub="NaF + N/A across all rules"
                tone={
                    if totals.compliance_score >= 80.0 { Some("ok") }
                    else if totals.compliance_score < 50.0 { Some("warning") }
                    else { None }
                }
            />
            <KpiCard
                label="Overdue"
                value={totals.overdue_findings.to_string()}
                tone={(totals.overdue_findings > 0).then_some("warning")}
                onclick={(totals.overdue_findings > 0).then(|| kpi_drill(Drilldown::Kind("overdue".into())))}
            />
            <KpiCard
                label={format!("Stale (>{}d)", totals.stale_threshold_days)}
                value={totals.stale_findings.to_string()}
                tone={(totals.stale_findings > 0).then_some("warning")}
                onclick={(totals.stale_findings > 0).then(|| {
                    // A zero threshold falls back to the default window.
                    let days = if totals.stale_threshold_days == 0 { 30 } else { totals.stale_threshold_days };
                    kpi_drill(Drilldown::Stale(days))
                })}
            />
            <KpiCard
                label="Highest risk"
                value={totals.highest_risk_score.to_string()}
                sub={totals.highest_risk_asset_name.as_ref().filter(|n| !n.is_empty()).map(|n| format!("on {n}"))}
                tone={if totals.highest_risk_score > 0 { "warning" } else { "ok" }}
            />
            <KpiCard
                label="Top weighted"
                value={format!("{:.1}", totals.highest_weighted_score)}
                sub={totals.highest_weighted_asset_name.as_ref().filter(|n| !n.is_empty()).map(|asset| {
                    match totals.highest_weighted_rule_id.as_ref().filter(|r| !r.is_empty()) {
                        Some(rule) => format!("{rule} on {asset}"),
                        None => format!("on {asset}"),
                    }
                })}
                tone={if totals.highest_weighted_score > 20.0 { "warning" } else { "ok" }}
            />
            <KpiCard
                label="STIG updates"
                value={outdated.to_string()}
                sub={if outdated > 0 { "checklists out of date" } else { "all up to date" }}
                tone={if outdated > 0 { "warning" } else { "ok" }}
            />
            <KpiCard
                label="Stale baselines"
                value={totals.stale_baselines.to_string()}
                sub={format!(">{}d", totals.stale_baseline_days.unwrap_or(90))}
                tone={if totals.stale_baselines > 0 { "warning" } else { "ok" }}
            />
        </ColumnLayout>
    };

    let trend_charts = match (*trend).as_ref().filter(|t| !t.overall.is_empty()) {
        None => Html::default(),
        Some(t) => {
            let n = t.overall.len();
            let description = format!("{n} snapshot{} in the last 30 days", plural(n));
            let series = |y: fn(&TrendPoint) -> f64| -> Vec<(f64, f64)> {
                t.overall.iter().map(|p| (parse_date_ms(&p.captured_at), y(p))).collect()
            };
            let no_snapshots = html! { <UiBox text_align="center" color="inherit">{"No snapshots yet"}</UiBox> };
            html! {
                <>
                    // Trend over time
                    <Container header={html! {
                        <Header variant="h2" description={text(description.clone())}>{"Posture over time"}</Header>
                    }}>
                        <LineChart
                            series={vec![
                                ChartSeries::line("Open", series(|p| p.open)).color("#d13212"),
                                ChartSeries::line("Reviewed", series(|p| p.reviewed)).color("#1d8102"),
                            ]}
                            x_scale_type="time"
                            x_title="Time"
                            y_title="Rules"
                            height={220}
                            aria_label="Posture trend"
                            empty={no_snapshots.clone()}
                        />
                    </Container>
                    // Compliance trend over time
                    <Container header={html! {
                        <Header variant="h2" description={text(description)}>{"Compliance trend"}</Header>
                    }}>
                        <LineChart
                            series={vec![
                                ChartSeries::line("Compliance", series(|p| p.compliance_score)).color("#1d8102"),
                            ]}
                            x_scale_type="time"
                            x_title="Time"
                            y_title="Compliance (%)"
                            y_domain={(0.0, 100.0)}
                            height={220}
                            aria_label="Compliance trend"
                            empty={no_snapshots}
                        />
                    </Container>
                </>
            }
        }
    };

    // Per-asset / per-checklist progress
    let by_system_table = {
        // Cell for a column that is blank on "no STIGs applied" rows.
        fn count_badge(
            pick: fn(&ChecklistSummary) -> i64,
            active: &'static str,
        ) -> impl Fn(&ChecklistRow) -> Html {
            move |r: &ChecklistRow| match &r.checklist {
                None => Html::default(),
                Some(c) => {
                    let n = pick(c);
                    html! { <Badge color={if n > 0 { active } else { "grey" }}>{n}</Badge> }
                }
            }
        }
        let columns = vec![
            Column::new("asset", "System", |r: &ChecklistRow| html! { {r.asset_name.clone()} }),
            Column::new("stig", "STIG", |r: &ChecklistRow| match &r.checklist {
                None => html! { {"—"} },
                Some(c) if !c.outdated => html! { {c.stig_title.clone()} },
                Some(c) => html! {
                    <SpaceBetween direction="horizontal" size="xs">
                        <span>{c.stig_title.clone()}</span>
                        <Badge color="red">{"Out of date"}</Badge>
                    </SpaceBetween>
                },
            }),
            Column::new("progress", "Review progress", |r: &ChecklistRow| match &r.checklist {
                None => html! { <UiBox color="text-status-inactive">{"No STIGs applied"}</UiBox> },
                Some(c) => html! {
                    <ProgressBar
                        value={pct(c.reviewed_count as f64, c.rule_count as f64)}
                        additional_info={text(format!("{} of {}", c.reviewed_count, c.rule_count))}
                    />
                },
            }),
            Column::new("open", "Open", count_badge(|c| c.open_count, "red")),
            Column::new("overdue", "Overdue", count_badge(|c| c.overdue_count, "red")),
            Column::new("risk", "Risk", |r: &ChecklistRow| html! {
                <Badge color={if r.risk_score > 0 { "red" } else { "grey" }}>{r.risk_score}</Badge>
            }),
            Column::new("compliance", "Compliance score", |r: &ChecklistRow| match &r.checklist {
                None => inactive_dash(),
                Some(c) => html! {
                    <ProgressBar
                        value={c.compliance_score}
                        additional_info={text(format!("{:.1}%", c.compliance_score))}
                    />
                },
            }),
            Column::new("weightedRisk", "Weighted risk", |r: &ChecklistRow| {
                let w = r.weighted_risk_score;
                html! { <Badge color={weight_color(w)}>{format!("{w:.1}")}</Badge> }
            }),
            Column::new("naf", "NaF", count_badge(|c| c.naf_count, "green")),
            Column::new("na", "N/A", count_badge(|c| c.na_count, "blue")),
        ];
        html! {
            <Table<ChecklistRow>
                variant="container"
                items={checklist_rows}
                track_by={Callback::from(|r: ChecklistRow| {
                    format!("{}:{}", r.asset_id, r.checklist.as_ref().map(|c| c.id.as_str()).unwrap_or("empty"))
                })}
                {columns}
                header={html! { <Header counter={format!("({})", data.by_asset.len())}>{"By system"}</Header> }}
                empty={html! {
                    <UiBox text_align="center" padding="l">
                        <UiBox variant="p" color="text-body-secondary">
                            {"No systems yet. Add one from the Systems page to start tracking."}
                        </UiBox>
                    </UiBox>
                }}
            />
        }
    };

    // Top open rules
    let top_rules_table = if data.top_open_rules.is_empty() {
        Html::default()
    } else {
        let set = set_drilldown.clone();
        let columns = vec![
            Column::new("rule", "Rule", move |r: &TopRule| {
                let set = set.clone();
                let id = r.rule_id.clone();
                html! {
                    <Button variant="inline-link" onclick={move |_| set.emit(Some(Drilldown::Rule(id.clone())))}>
                        {r.rule_id.clone()}
                    </Button>
                }
            }),
            Column::new("affected", "Affected systems", |r: &TopRule| html! {
                <Badge color={if r.affected_systems > 1 { "red" } else { "grey" }}>{r.affected_systems}</Badge>
            }),
        ];
        html! {
            <Table<TopRule>
                variant="container"
                items={data.top_open_rules.clone()}
                track_by={Callback::from(|r: TopRule| r.rule_id)}
                {columns}
                header={html! {
                    <Header
                        description={text("Rules currently marked Open in the most systems — likely candidates for a fleet-wide fix.")}
                        counter={format!("({})", data.top_open_rules.len())}
                    >
                        {"Top open rules"}
                    </Header>
                }}
            />
        }
    };

    // Drill-down panel
    let drilldown_table = match &drilldown {
        None => Html::default(),
        Some(d) => {
            let toggle_expanded = {
                let expanded = expanded_finding.clone();
                Callback::from(move |f: Finding| {
                    let same = expanded.as_ref().is_some_and(|curr| curr.key() == f.key());
                    expanded.set(if same { None } else { Some(f) });
                })
            };
            let columns = vec![
                Column::new("rule", "Rule", move |f: &Finding| {
                    let toggle = toggle_expanded.clone();
                    let finding = f.clone();
                    html! {
                        <Button variant="inline-link" onclick={move |_| toggle.emit(finding.clone())}>
                            {f.rule_id.clone()}
                        </Button>
                    }
                }),
                Column::new("severity", "Severity", |f: &Finding| match f.severity.as_deref() {
                    Some(sev) if !sev.is_empty() => html! { <Badge color={severity_badge(sev)}>{sev.to_string()}</Badge> },
                    _ => inactive_dash(),
                }),
                // Sortable so an auditor can pick the highest-impact
                // findings out of a large drill-down list.
                Column::new("weight", "Weight", |f: &Finding| {
                    let w = f.weighted_score;
                    html! { <Badge color={weight_color(w)}>{format!("{w:.1}")}</Badge> }
                })
                .sortable(),
                Column::new("asset", "System", |f: &Finding| html! { {f.asset_name.clone()} }),
                Column::new("stig", "STIG", |f: &Finding| html! { {f.stig_title.clone()} }),
                Column::new("owner", "Owner", |f: &Finding| html! { {f.owner_name.clone()} }),
                Column::new("assignee", "Assignee", |f: &Finding| match f.assignee_name.as_deref() {
                    Some(name) if !name.is_empty() => html! { {name.to_string()} },
                    _ => html! { <UiBox color="text-status-inactive">{"Unassigned"}</UiBox> },
                }),
                Column::new("due", "Due", |f: &Finding| match f.due_date.as_deref() {
                    Some(due) if !due.is_empty() => {
                        let overdue = parse_date_ms(due) < now_ms();
                        html! {
                            <UiBox color={if overdue { "text-status-error" } else { "inherit" }}>{due.to_string()}</UiBox>
                        }
                    }
                    _ => inactive_dash(),
                }),
                Column::new("updated", "Last update", |f: &Finding| html! { {to_locale_string(&f.updated_at)} }),
            ];
            let items = {
                let mut items = (*findings).clone();
                if let Some(desc) = *weight_sort {
                    items.sort_by(|a, b| {
                        let ord = a.weighted_score.partial_cmp(&b.weighted_score).unwrap_or(Ordering::Equal);
                        if desc { ord.reverse() } else { ord }
                    });
                }
                items
            };
            let on_sort = {
                let weight_sort = weight_sort.clone();
                Callback::from(move |(_, desc): (AttrValue, bool)| weight_sort.set(Some(desc)))
            };
            let on_selection_change = {
                let selected = selected_findings.clone();
                Callback::from(move |items: Vec<Finding>| selected.set(items))
            };
            let on_severity = {
                let set = set_url_filters.clone();
                Callback::from(move |opt: SelectOption| set.emit(vec![("sev", opt.value.to_string().into())]))
            };
            let on_mine = {
                let set = set_url_filters.clone();
                Callback::from(move |checked: bool| set.emit(vec![("me", checked.into())]))
            };
            let close = {
                let set = set_drilldown.clone();
                Callback::from(move |_: MouseEvent| set.emit(None))
            };
            html! {
                <Table<Finding>
                    variant="container"
                    {items}
                    loading={*findings_loading}
                    loading_text="Loading findings"
                    selection_type="multi"
                    selected_keys={selected_findings.iter().map(Finding::key).collect::<Vec<_>>()}
                    {on_selection_change}
                    track_by={Callback::from(|f: Finding| f.key())}
                    {columns}
                    sorting_column={weight_sort.map(|_| AttrValue::from("weight"))}
                    sorting_descending={weight_sort.unwrap_or(false)}
                    {on_sort}
                    header={html! {
                        <Header
                            description={text(d.describe())}
                            counter={format!("({})", findings.len())}
                            actions={html! {
                                <SpaceBetween direction="horizontal" size="xs">
                                    <Button disabled={selected_count == 0} onclick={open_bulk_modal}>
                                        {format!("Bulk update{count_suffix}")}
                                    </Button>
                                    <Button disabled={selected_count == 0} onclick={open_reassign_modal}
                                            testid="reassign-open">
                                        {format!("Reassign{count_suffix}")}
                                    </Button>
                                    <Button onclick={close}>{"Close"}</Button>
                                </SpaceBetween>
                            }}
                        >
                            {d.title()}
                        </Header>
                    }}
                    filter={html! {
                        <SpaceBetween direction="horizontal" size="m">
                            <Select
                                selected={AttrValue::from(severity_filter.clone().unwrap_or_default())}
                                on_change={on_severity}
                                options={severity_options()}
                                aria_label="Filter by severity"
                            />
                            <Toggle checked={mine_only} on_change={on_mine}>{"Mine only"}</Toggle>
                        </SpaceBetween>
                    }}
                    empty={html! {
                        <UiBox text_align="center" padding="l">
                            <UiBox variant="p" color="text-body-secondary">{"No matching findings."}</UiBox>
                        </UiBox>
                    }}
                />
            }
        }
    };

    let expanded_panel = match (&drilldown, &*expanded_finding) {
        (Some(_), Some(f)) => {
            let close = {
                let expanded = expanded_finding.clone();
                Callback::from(move |_: MouseEvent| expanded.set(None))
            };
            let section = |title: &'static str, body: Option<&str>| match body {
                Some(body) if !body.is_empty() => html! { <RuleSection {title} body={body.to_string()} /> },
                _ => Html::default(),
            };
            let description = f.title.clone().filter(|t| !t.is_empty()).unwrap_or_else(|| f.stig_title.clone());
            html! {
                <Container header={html! {
                    <Header
                        actions={html! { <Button onclick={close}>{"Close"}</Button> }}
                        description={text(description)}
                    >
                        {f.rule_id.clone()}
                        if let Some(sev) = f.severity.as_ref().filter(|s| !s.is_empty()) {
                            <UiBox display="inline" margin_left="s" variant="span">
                                <Badge color={severity_badge(sev)}>{sev.clone()}</Badge>
                            </UiBox>
                        }
                    </Header>
                }}>
                    <SpaceBetween direction="vertical" size="m">
                        {section("Description", f.description.as_deref())}
                        {section("Check", f.check_text.as_deref())}
                        {section("Fix", f.fix_text.as_deref())}
                        {section("Finding details (current)", Some(&f.finding_details))}
                        {section("Comments (current)", Some(&f.comments))}
                        <UiBox variant="small" color="text-body-secondary">
                            {format!("{} · {} · owner {}", f.asset_name, to_locale_string(&f.updated_at), f.owner_name)}
                        </UiBox>

                        if !rule_history.is_empty() {
                            <div>
                                <UiBox variant="awsui-key-label">{"History"}</UiBox>
                                <UiBox padding_top="xs">
                                    { for rule_history.iter().map(|h| html! {
                                        <UiBox key={h.id} padding_vertical="xxs">
                                            <UiBox variant="small" color="text-body-secondary" display="inline">
                                                {to_locale_string(&h.occurred_at)}
                                            </UiBox>
                                            {" "}<strong>{h.user_name.clone()}</strong>{" changed "}
                                            <em>{audit_field_label(&h.field).to_string()}</em>{": "}
                                            <span style="opacity:0.7">{audit_value(&h.from_value, "(empty)")}</span>
                                            {" → "}
                                            <strong>{audit_value(&h.to_value, "(empty)")}</strong>
                                        </UiBox>
                                    }) }
                                </UiBox>
                            </div>
                        }
                    </SpaceBetween>
                </Container>
            }
        }
        _ => Html::default(),
    };

    // Changes since baseline
    let baseline_panel = if baselines.is_empty() {
        Html::default()
    } else {
        let selected = (*selected_baseline_id).clone();
        let selected_row = selected.as_ref().and_then(|id| baselines.iter().find(|b| &b.id == id));
        let label = |b: &Baseline| if b.is_stale { format!("{} (stale)", b.name) } else { b.name.clone() };
        let options: Vec<SelectOption> = baselines
            .iter()
            .map(|b| {
                let mut description = format!("by {} · {} rules", b.created_by_name, b.rule_count);
                if b.is_stale {
                    description.push_str(" · STALE");
                }
                SelectOption::new(b.id.clone(), label(b)).description(description)
            })
            .collect();
        let on_select = {
            let ctl = baseline_ctl.clone();
            Callback::from(move |opt: SelectOption| ctl.select(Some(opt.value.to_string())))
        };
        let can_delete = selected_row
            .zip(current_user.as_ref())
            .is_some_and(|(b, u)| b.created_by == u.id);
        let description = match &*baseline_diff {
            Some(d) => format!(
                "{} regressed · {} improved · {} unchanged",
                d.regressed.len(),
                d.improved.len(),
                d.unchanged
            ),
            None => "Pick a baseline to see what changed since.".to_string(),
        };
        let stale_alert = selected_row.filter(|b| b.is_stale).map(|b| {
            let age_days = ((now_ms() - parse_date_ms(&b.created_at)) / (1000.0 * 60.0 * 60.0 * 24.0)).floor();
            html! {
                <Alert kind="warning" header={text("Stale baseline")}>
                    {format!("This baseline is {age_days} days old. Consider saving a fresh one.")}
                </Alert>
            }
        });
        html! {
            <Container header={html! {
                <Header
                    variant="h2"
                    description={text(description)}
                    actions={html! {
                        <SpaceBetween direction="horizontal" size="xs">
                            <Select
                                selected={selected.clone().map(AttrValue::from)}
                                selected_label={selected.clone().map(AttrValue::from)}
                                on_change={on_select}
                                {options}
                                placeholder="Choose a baseline"
                            />
                            if selected.is_some() {
                                <Button variant="normal" disabled={!can_delete} onclick={delete_baseline}>
                                    {"Delete"}
                                </Button>
                            }
                        </SpaceBetween>
                    }}
                >
                    {"Changes since baseline"}
                </Header>
            }}>
                if *diff_loading {
                    <StatusIndicator kind="loading">{"Loading…"}</StatusIndicator>
                }
                if let Some(diff) = &*baseline_diff {
                    <SpaceBetween direction="vertical" size="m">
                        {stale_alert}
                        <ColumnLayout columns={2}>
                            <DiffTable title="Regressed" tone="red" rows={diff.regressed.clone()} />
                            <DiffTable title="Improved" tone="green" rows={diff.improved.clone()} />
                        </ColumnLayout>
                    </SpaceBetween>
                }
            </Container>
        }
    };

    // Recent activity
    let activity_panel = if activity.is_empty() {
        Html::default()
    } else {
        html! {
            <Container header={html! {
                <Header
                    variant="h2"
                    counter={format!("({})", activity.len())}
                    description={text("The most recent rule-state changes across all systems.")}
                >
                    {"Recent activity"}
                </Header>
            }}>
                <SpaceBetween direction="vertical" size="xs">
                    { for activity.iter().map(|a| html! {
                        <UiBox key={a.id} variant="small">
                            <UiBox display="inline" color="text-body-secondary" variant="span">
                                {to_locale_string(&a.occurred_at)}
                            </UiBox>
                            {" "}<strong>{a.user_name.clone()}</strong>{" changed "}
                            <em>{audit_field_label(&a.field).to_string()}</em>{" on "}
                            <strong>{a.rule_id.clone()}</strong>
                            if let Some(asset) = a.asset_name.as_ref().filter(|n| !n.is_empty()) {
                                {" — "}<span style="opacity:0.7">{asset.clone()}</span>
                            }
                            {" "}
                            <span style="opacity:0.6">
                                {format!("({} → {})", audit_value(&a.from_value, "—"), audit_value(&a.to_value, "—"))}
                            </span>
                        </UiBox>
                    }) }
                </SpaceBetween>
            </Container>
        }
    };

    let modal_footer = |on_cancel: Callback<MouseEvent>, confirm: Html| {
        html! {
            <UiBox float="right">
                <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="link" onclick={on_cancel}>{"Cancel"}</Button>
                    {confirm}
                </SpaceBetween>
            </UiBox>
        }
    };
    let closer = |flag: &UseStateHandle<bool>| {
        let flag = flag.clone();
        (
            Callback::from({
                let flag = flag.clone();
                move |_: ()| flag.set(false)
            }),
            Callback::from(move |_: MouseEvent| flag.set(false)),
        )
    };

    // Bulk-edit modal
    let bulk_modal = {
        let (on_dismiss, on_cancel) = closer(&bulk_open);
        let edit = |apply: fn(&mut BulkDraft, String)| {
            let draft = bulk_draft.clone();
            Callback::from(move |value: String| {
                let mut next = (*draft).clone();
                apply(&mut next, value);
                draft.set(next);
            })
        };
        let on_status = {
            let draft = bulk_draft.clone();
            Callback::from(move |opt: SelectOption| {
                let mut next = (*draft).clone();
                next.status = opt.value.to_string();
                draft.set(next);
            })
        };
        html! {
            <Modal
                visible={*bulk_open}
                {on_dismiss}
                header={text(format!("Bulk update — {selected_count} finding{}", plural(selected_count)))}
                footer={modal_footer(on_cancel, html! {
                    <Button variant="primary" loading={*bulk_saving} onclick={save_bulk}>{"Apply"}</Button>
                })}
            >
                <SpaceBetween direction="vertical" size="m">
                    <UiBox variant="p" color="text-body-secondary">
                        {"Leave a field blank to keep each finding's current value. At least one field must be set."}
                    </UiBox>
                    <FormField label={text("Status")}>
                        <Select
                            selected={AttrValue::from(bulk_draft.status.clone())}
                            on_change={on_status}
                            options={vec![
                                SelectOption::new("", "(leave unchanged)"),
                                SelectOption::new("open", "Open"),
                                SelectOption::new("not_a_finding", "Not a finding"),
                                SelectOption::new("not_applicable", "Not applicable"),
                                SelectOption::new("not_reviewed", "Not reviewed"),
                            ]}
                        />
                    </FormField>
                    <FormField
                        label={text("Finding details")}
                        description={text("Replaces existing finding-details on every selected rule.")}
                    >
                        <Input
                            value={bulk_draft.finding_details.clone()}
                            on_change={edit(|d, v| d.finding_details = v)}
                            placeholder="e.g. closed by mitigation #42"
                        />
                    </FormField>
                    <FormField label={text("Comments")}>
                        <Input value={bulk_draft.comments.clone()} on_change={edit(|d, v| d.comments = v)} />
                    </FormField>
                    if let Some(e) = &*bulk_error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                </SpaceBetween>
            </Modal>
        }
    };

    // Reassign-only preset modal — single field, one action.
    let reassign_modal = {
        let (on_dismiss, on_cancel) = closer(&reassign_open);
        let on_change = {
            let assignee = reassign_assignee_id.clone();
            Callback::from(move |opt: SelectOption| {
                assignee.set(Some(opt.value.to_string()).filter(|v| !v.is_empty()));
            })
        };
        let options: Vec<SelectOption> = std::iter::once(SelectOption::new("", "Unassign"))
            .chain(users.iter().map(|u| SelectOption::new(u.id.clone(), u.display_name.clone())))
            .collect();
        let selected = (*reassign_assignee_id).clone().unwrap_or_default();
        html! {
            <Modal
                visible={*reassign_open}
                {on_dismiss}
                header={text(format!("Reassign {selected_count} finding{}", plural(selected_count)))}
                testid="reassign-modal"
                footer={modal_footer(on_cancel, html! {
                    <Button variant="primary" loading={*reassign_saving} onclick={save_reassign}
                            testid="reassign-submit">
                        {"Reassign"}
                    </Button>
                })}
            >
                <SpaceBetween direction="vertical" size="m">
                    <UiBox variant="p" color="text-body-secondary">
                        {"Pick a new assignee for every selected finding, or choose \"Unassign\" to clear the field."}
                    </UiBox>
                    <FormField label={text("Assignee")}>
                        <Select
                            selected={AttrValue::from(selected.clone())}
                            selected_label={AttrValue::from(selected)}
                            {on_change}
                            {options}
                            testid="reassign-select"
                        />
                    </FormField>
                    if let Some(e) = &*reassign_error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                </SpaceBetween>
            </Modal>
        }
    };

    // Save baseline modal
    let save_baseline_modal = {
        let (on_dismiss, on_cancel) = closer(&save_modal_open);
        let on_name = {
            let name = new_baseline_name.clone();
            Callback::from(move |v: String| name.set(v))
        };
        html! {
            <Modal
                visible={*save_modal_open}
                {on_dismiss}
                header={text("Save baseline")}
                footer={modal_footer(on_cancel, html! {
                    <Button variant="primary" loading={*saving_baseline} onclick={save_baseline}>{"Save"}</Button>
                })}
            >
                <SpaceBetween direction="vertical" size="m">
                    <UiBox variant="p" color="text-body-secondary">
                        {"Capture the current compliance state as a named baseline. Future dashboard sessions can show which rules regressed or improved since this baseline was taken."}
                    </UiBox>
                    <FormField label={text("Name")}>
                        <Input
                            value={(*new_baseline_name).clone()}
                            on_change={on_name}
                            placeholder="e.g. Q2 2026 audit"
                            auto_focus=true
                        />
                    </FormField>
                    if let Some(e) = &*save_baseline_error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                </SpaceBetween>
            </Modal>
        }
    };

    // Bulk re-apply confirm modal
    let bulk_reapply_modal = {
        let (on_dismiss, on_cancel) = closer(&bulk_reapply_open);
        html! {
            <Modal
                visible={*bulk_reapply_open}
                {on_dismiss}
                header={text("Re-apply all outdated STIGs")}
                footer={modal_footer(on_cancel, html! {
                    <Button variant="primary" loading={*bulk_reapply_running} onclick={run_bulk_reapply}
                            testid="bulk-reapply-confirm">
                        {"Re-apply"}
                    </Button>
                })}
            >
                <SpaceBetween direction="vertical" size="m">
                    <UiBox variant="p">
                        {"This will re-apply the current catalog version onto "}
                        <strong>{format!("{outdated} checklist{}", if outdated == 1 { "" } else { "s" })}</strong>
                        {" you own. Rule overrides for rules that still exist are preserved; overrides for rules removed in the new revision are pruned."}
                    </UiBox>
                    if let Some(e) = &*bulk_reapply_error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                </SpaceBetween>
            </Modal>
        }
    };

    // Bulk re-apply results modal
    let bulk_reapply_results_modal = {
        let results = (*bulk_reapply_results).clone();
        let n = results.as_ref().map_or(0, Vec::len);
        let on_dismiss = {
            let results = bulk_reapply_results.clone();
            Callback::from(move |_: ()| results.set(None))
        };
        let on_close = {
            let results = bulk_reapply_results.clone();
            Callback::from(move |_: MouseEvent| results.set(None))
        };
        let version_or_dash = |v: &str| if v.is_empty() { "—".to_string() } else { v.to_string() };
        let columns = vec![
            Column::new("asset", "System", |r: &BulkReapplyResult| html! { {r.asset_name.clone()} }),
            Column::new("stig", "STIG", |r: &BulkReapplyResult| html! { {r.stig_title.clone()} }),
            Column::new("version", "Version", move |r: &BulkReapplyResult| {
                if r.to_version.is_empty() {
                    html! { <UiBox color="text-status-inactive">{version_or_dash(&r.from_version)}</UiBox> }
                } else {
                    html! {
                        <span>
                            <span style="opacity:0.7">{version_or_dash(&r.from_version)}</span>
                            {" → "}
                            <strong>{r.to_version.clone()}</strong>
                        </span>
                    }
                }
            }),
            Column::new("pruned", "Pruned rules", |r: &BulkReapplyResult| html! {
                <Badge color={if r.pruned_rules > 0 { "blue" } else { "grey" }}>{r.pruned_rules}</Badge>
            }),
            Column::new("status", "Status", |r: &BulkReapplyResult| {
                let color = match r.status.as_str() {
                    "reapplied" => "green",
                    "skipped" => "grey",
                    _ => "red",
                };
                html! {
                    <SpaceBetween direction="horizontal" size="xs">
                        <Badge {color}>{r.status.clone()}</Badge>
                        if let Some(e) = r.error.as_ref().filter(|e| !e.is_empty()) {
                            <UiBox variant="small" color="text-status-inactive">{e.clone()}</UiBox>
                        }
                    </SpaceBetween>
                }
            }),
        ];
        html! {
            <Modal
                visible={results.is_some()}
                {on_dismiss}
                header={text(format!("Re-apply complete — {n} checklist{}", plural(n)))}
                size="large"
                footer={html! {
                    <UiBox float="right">
                        <Button variant="primary" onclick={on_close}>{"Close"}</Button>
                    </UiBox>
                }}
            >
                <Table<BulkReapplyResult>
                    variant="embedded"
                    items={results.unwrap_or_default()}
                    track_by={Callback::from(|r: BulkReapplyResult| r.checklist_id)}
                    {columns}
                    empty={html! {
                        <UiBox text_align="center" padding="l">
                            <UiBox variant="p" color="text-body-secondary">
                                {"No outdated checklists were found."}
                            </UiBox>
                        </UiBox>
                    }}
                />
            </Modal>
        }
    };

    let dismiss_flash = {
        let flash = reassign_flash.clone();
        Callback::from(move |_: ()| flash.set(None))
    };

    html! {
        <UiBox padding="m">
            <SpaceBetween direction="vertical" size="l">
                <Header variant="h1" actions={header_actions}>{"Compliance dashboard"}</Header>

                if let Some(flash) = &*reassign_flash {
                    <Alert kind="success" dismissible=true on_dismiss={dismiss_flash} testid="reassign-flash">
                        {flash.clone()}
                    </Alert>
                }

                {kpis}

                // Status breakdown chart
                if !pie_data.is_empty() {
                    <Container header={html! { <Header variant="h2">{"Overall status"}</Header> }}>
                        <PieChart
                            data={pie_data}
                            segment_description={Callback::from(|(datum, sum): (PieDatum, f64)| {
                                format!("{} ({}%)", datum.value, pct(datum.value, sum))
                            })}
                            aria_description="Pie chart showing overall rule status across all systems"
                            aria_label="Status breakdown"
                            size="medium"
                            empty={html! { <UiBox text_align="center" color="inherit">{"No data yet"}</UiBox> }}
                        />
                    </Container>
                }

                {trend_charts}

                // Compliance heatmap: asset × STIG matrix
                if !data.by_asset.is_empty() {
                    <HeatmapSection by_asset={data.by_asset.clone()} />
                }

                // Rule-level diff: "what changed on every system since <date>"
                <DiffSection />

                {by_system_table}
                {top_rules_table}
                {drilldown_table}
                if let Some(e) = &*findings_error {
                    <Alert kind="error">{e.clone()}</Alert>
                }
                {expanded_panel}
                {baseline_panel}
                {activity_panel}

                {bulk_modal}
                {reassign_modal}
                {save_baseline_modal}
                {bulk_reapply_modal}
                {bulk_reapply_results_modal}
            </SpaceBetween>
        </UiBox>
    }
}

// ── Small pieces ────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
struct DiffTableProps {
    title: AttrValue,
    tone: AttrValue,
    rows: Vec<BaselineDiffEntry>,
}

#[function_component]
fn DiffTable(p: &DiffTableProps) -> Html {
    html! {
        <div>
            <UiBox variant="awsui-key-label">
                <Badge color={p.tone.clone()}>{p.title.clone()}</Badge>{" "}
                <span style="margin-left:8px">{format!("({})", p.rows.len())}</span>
            </UiBox>
            if p.rows.is_empty() {
                <UiBox color="text-body-secondary" padding_top="xs">{"None."}</UiBox>
            } else {
                <UiBox padding_top="xs">
                    { for p.rows.iter().map(|r| html! {
                        <UiBox key={format!("{}:{}", r.checklist_id, r.rule_id)} padding_vertical="xxs">
                            <strong>{r.rule_id.clone()}</strong>{format!(" — {} · ", r.asset_name)}
                            <span style="opacity:0.7">{format!("{} → {}", r.from_status, r.to_status)}</span>
                        </UiBox>
                    }) }
                </UiBox>
            }
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct RuleSectionProps {
    title: AttrValue,
    body: AttrValue,
}

#[function_component]
fn RuleSection(p: &RuleSectionProps) -> Html {
    html! {
        <div>
            <UiBox variant="awsui-key-label">{p.title.clone()}</UiBox>
            <UiBox variant="p" color="text-body-secondary">
                <pre style="white-space:pre-wrap;margin:0;font-family:inherit;font-size:inherit">
                    {p.body.clone()}
                </pre>
            </UiBox>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct KpiCardProps {
    label: AttrValue,
    value: AttrValue,
    #[prop_or_default]
    sub: Option<AttrValue>,
    /// "ok" | "warning"
    #[prop_or_default]
    tone: Option<&'static str>,
    /// When set, the card shows a "View details" link.
    #[prop_or_default]
    onclick: Option<Callback<MouseEvent>>,
}

#[function_component]
fn KpiCard(p: &KpiCardProps) -> Html {
    let value = match p.tone {
        Some("ok") => html! { <StatusIndicator kind="success">{p.value.clone()}</StatusIndicator> },
        Some("warning") => html! { <StatusIndicator kind="warning">{p.value.clone()}</StatusIndicator> },
        _ => html! { <UiBox variant="h1">{p.value.clone()}</UiBox> },
    };
    html! {
        <Container>
            <UiBox variant="awsui-key-label">{p.label.clone()}</UiBox>
            {value}
            if let Some(sub) = p.sub.as_ref().filter(|s| !s.is_empty()) {
                <UiBox variant="small" color="text-body-secondary">{sub.clone()}</UiBox>
            }
            if let Some(onclick) = &p.onclick {
                <Button variant="inline-link" onclick={onclick.clone()}>{"View details"}</Button>
            }
        </Container>
    }
}

// ── Rule-level diff ─────────────────────────────────────────────────────────

/// The date picker works in YYYY-MM-DD strings; default to 7 days ago.
fn default_diff_since() -> String {
    let d = js_sys::Date::new(&JsValue::from_f64(now_ms() - 7.0 * 24.0 * 60.0 * 60.0 * 1000.0));
    String::from(d.to_iso_string()).chars().take(10).collect()
}

fn diff_field_label(field: &str) -> &str {
    match field {
        "status" => "Status",
        "finding_details" => "Finding details",
        "comments" => "Comments",
        "assignee_id" => "Assignee",
        "due_date" => "Due date",
        other => other,
    }
}

fn diff_value_display(field: &str, value: &Option<String>) -> String {
    match value.as_deref() {
        None | Some("") => "(unset)".to_string(),
        Some(v) if field == "status" => status_label(v).unwrap_or(v).to_string(),
        Some(v) => truncate(v, 80),
    }
}

/// From/To cell: statuses render as a coloured badge, everything else as text.
fn diff_value_cell(field: &str, value: &Option<String>) -> Html {
    let shown = diff_value_display(field, value);
    if field == "status" {
        let raw = value.as_deref().unwrap_or_default();
        let color = status_color(status_label(raw).unwrap_or(raw));
        html! { <Badge {color}>{shown}</Badge> }
    } else {
        html! { {shown} }
    }
}

/// One changed field of one rule.
#[derive(Clone, PartialEq)]
struct DiffRow {
    key: String,
    asset_name: String,
    stig_title: String,
    rule_id: String,
    change: FieldChange,
}

#[function_component]
fn DiffSection() -> Html {
    let (since, set_since) = use_url_state(vec![("diffSince", UrlVal::from(default_diff_since()))]);
    let since = since.str("diffSince");
    let rules = use_state(Vec::<RuleDiff>::new);
    let loading = use_state(|| false);
    let error = use_state(|| None::<String>);

    {
        let rules = rules.clone();
        let loading = loading.clone();
        let error = error.clone();
        use_effect_with(since.clone(), move |since| {
            let cancelled = Rc::new(Cell::new(false));
            if !since.is_empty() {
                loading.set(true);
                error.set(None);
                let path = format!("/api/diff?since={}", encode_uri_component(since));
                let cancelled = cancelled.clone();
                spawn_local(async move {
                    let res = api_get::<RuleDiffResponse>(&path).await;
                    if cancelled.get() {
                        return;
                    }
                    match res {
                        Ok(res) => rules.set(res.rules),
                        Err(e) => error.set(Some(e)),
                    }
                    loading.set(false);
                });
            }
            move || cancelled.set(true)
        });
    }

    // Flatten rules → per-field rows for the Table.
    let flat_rows: Vec<DiffRow> = rules
        .iter()
        .flat_map(|r| {
            r.changes.iter().map(move |c| DiffRow {
                key: format!("{}:{}:{}", r.checklist_id, r.rule_id, c.field),
                asset_name: r.asset_name.clone(),
                stig_title: r.stig_title.clone(),
                rule_id: r.rule_id.clone(),
                change: c.clone(),
            })
        })
        .collect();

    let on_change = Callback::from(move |value: String| {
        let value = if value.is_empty() { default_diff_since() } else { value };
        set_since.emit(vec![("diffSince", value.into())]);
    });

    let columns = vec![
        Column::new("asset", "System", |r: &DiffRow| html! { {r.asset_name.clone()} }),
        Column::new("stig", "STIG", |r: &DiffRow| html! { {r.stig_title.clone()} }),
        Column::new("rule", "Rule", |r: &DiffRow| html! { {r.rule_id.clone()} }),
        Column::new("field", "Field", |r: &DiffRow| html! { {diff_field_label(&r.change.field).to_string()} }),
        Column::new("from", "From", |r: &DiffRow| diff_value_cell(&r.change.field, &r.change.from)),
        Column::new("to", "To", |r: &DiffRow| diff_value_cell(&r.change.field, &r.change.to)),
        Column::new("by", "By", |r: &DiffRow| html! { {r.change.by.clone()} }),
        Column::new("at", "When", |r: &DiffRow| html! { {to_locale_string(&r.change.at)} }),
    ];

    html! {
        <Container header={html! {
            <Header
                variant="h2"
                description={text("Every rule whose status, assignee, due date, finding details, or comments changed inside the window. Repeated flips collapse to first → latest.")}
                actions={html! {
                    <UiBox float="right" padding_top="xxs">
                        <DatePicker
                            value={since.clone()}
                            {on_change}
                            placeholder="YYYY/MM/DD"
                            testid="diff-since-picker"
                        />
                    </UiBox>
                }}
            >
                {format!("Changes since {since}")}
            </Header>
        }}>
            if let Some(e) = &*error {
                <Alert kind="error">{e.clone()}</Alert>
            }
            <Table<DiffRow>
                variant="embedded"
                items={flat_rows}
                track_by={Callback::from(|r: DiffRow| r.key)}
                loading={*loading}
                loading_text="Loading diff…"
                empty={html! {
                    <UiBox text_align="center" padding="l" color="text-body-secondary">
                        {"No changes in the selected window."}
                    </UiBox>
                }}
                {columns}
            />
        </Container>
    }
}

// ── Compliance heatmap ──────────────────────────────────────────────────────

/// Aggregated counts for one heatmap cell (a row's assets × one STIG).
#[derive(Default)]
struct HeatCell {
    open_count: i64,
    naf_count: i64,
    na_count: i64,
    reviewed_count: i64,
    rule_count: i64,
}

/// (background, foreground, label) for a cell; `None` = STIG not applied.
fn cell_color(c: Option<&HeatCell>) -> (&'static str, &'static str, String) {
    match c {
        None => ("transparent", "var(--text-inactive)", "—".into()),
        Some(c) if c.open_count > 0 => ("#7a1c1c", "#fff", c.open_count.to_string()),
        Some(c) if c.reviewed_count == 0 => ("#444", "#ccc", "·".into()),
        Some(c) if c.reviewed_count < c.rule_count => ("#7a5e1c", "#fff", "↻".into()),
        Some(_) => ("#1c5e2d", "#fff", "✓".into()),
    }
}

/// Aggregate the cell metrics across all assets in the row for a given STIG.
fn aggregate_cell(assets: &[&AssetSummary], stig_id: &str) -> Option<HeatCell> {
    let mut cell = None::<HeatCell>;
    for a in assets {
        if let Some(c) = a.checklists.iter().find(|c| c.stig_id == stig_id) {
            let agg = cell.get_or_insert_with(HeatCell::default);
            agg.open_count += c.open_count;
            agg.naf_count += c.naf_count;
            agg.na_count += c.na_count;
            agg.reviewed_count += c.reviewed_count;
            agg.rule_count += c.rule_count;
        }
    }
    cell
}

#[derive(Properties, PartialEq)]
struct HeatmapSectionProps {
    by_asset: Vec<AssetSummary>,
}

#[function_component]
fn HeatmapSection(p: &HeatmapSectionProps) -> Html {
    let (hm_state, set_hm_state) = use_url_state(vec![("grpTag", UrlVal::from(false))]);
    let group_by_tag = hm_state.bool("grpTag");

    // Collect unique STIG titles across all assets, sorted alphabetically.
    let mut stigs: Vec<(&str, &str)> = Vec::new();
    for c in p.by_asset.iter().flat_map(|a| a.checklists.iter()) {
        if !stigs.iter().any(|(id, _)| *id == c.stig_id) {
            stigs.push((&c.stig_id, &c.stig_title));
        }
    }
    stigs.sort_by(|a, b| locale_compare(a.1, b.1));

    if stigs.is_empty() {
        return Html::default();
    }

    // Build display rows. In flat mode each row is one asset. In group-by-tag
    // mode each row is a tag bucket whose cell aggregates open/reviewed/rule
    // counts across all assets carrying that tag. Assets with no tags fall
    // into an "(untagged)" bucket. An asset with multiple tags shows up
    // under each.
    let rows: Vec<(String, Vec<&AssetSummary>)> = if group_by_tag {
        let mut buckets: Vec<(String, Vec<&AssetSummary>)> = Vec::new();
        for a in &p.by_asset {
            let untagged = ["(untagged)".to_string()];
            let tags: &[String] = if a.tags.is_empty() { &untagged } else { &a.tags };
            for t in tags {
                match buckets.iter_mut().find(|(name, _)| name == t) {
                    Some((_, assets)) => assets.push(a),
                    None => buckets.push((t.clone(), vec![a])),
                }
            }
        }
        buckets.sort_by(|a, b| locale_compare(&a.0, &b.0));
        buckets
    } else {
        p.by_asset.iter().map(|a| (a.name.clone(), vec![a])).collect()
    };

    let on_toggle = Callback::from(move |checked: bool| set_hm_state.emit(vec![("grpTag", checked.into())]));
    let sticky = "position:sticky;left:0;background:var(--bg-raised);";

    html! {
        <Container header={html! {
            <Header
                variant="h2"
                description={text("Open count per (system, STIG). Green = all reviewed and compliant, yellow = in progress, red = open findings, grey = not started.")}
                actions={html! {
                    <Toggle checked={group_by_tag} on_change={on_toggle}>{"Group by tag"}</Toggle>
                }}
            >
                {"Posture heatmap"}
            </Header>
        }}>
            <div style="overflow-x:auto">
                <table style="border-collapse:collapse;font-size:12px">
                    <thead>
                        <tr>
                            <th style={format!("text-align:left;padding:6px 10px;border-bottom:1px solid #444;{sticky}")}>
                                {"System"}
                            </th>
                            { for stigs.iter().map(|(id, title)| html! {
                                <th
                                    key={id.to_string()}
                                    style="padding:6px 10px;border-bottom:1px solid #444;font-weight:400;font-size:11px;writing-mode:vertical-rl;transform:rotate(180deg);white-space:nowrap;max-height:180px"
                                    title={title.to_string()}
                                >
                                    {truncate(title, 30)}
                                </th>
                            }) }
                        </tr>
                    </thead>
                    <tbody>
                        { for rows.iter().map(|(name, assets)| html! {
                            <tr key={name.clone()}>
                                <td style={format!("padding:6px 10px;border-bottom:1px solid #2b2b2b;{sticky}")}>
                                    if group_by_tag {
                                        <Badge color="grey">{name.clone()}</Badge>
                                        <span style="margin-left:6px;color:var(--text-inactive);font-size:11px">
                                            {assets.len()}
                                        </span>
                                    } else {
                                        {name.clone()}
                                    }
                                </td>
                                { for stigs.iter().map(|(id, title)| {
                                    let cell = aggregate_cell(assets, id);
                                    let (bg, fg, label) = cell_color(cell.as_ref());
                                    let tip = match &cell {
                                        Some(c) => format!(
                                            "{name} · {title}\n{} open / {} NaF / {} N/A / {} reviewed of {}",
                                            c.open_count, c.naf_count, c.na_count, c.reviewed_count, c.rule_count
                                        ),
                                        None => format!("{name} · {title} — not applied"),
                                    };
                                    html! {
                                        <td key={id.to_string()} title={tip} style="padding:0;border-bottom:1px solid #2b2b2b">
                                            <div style={format!(
                                                "width:32px;height:28px;margin:2px;background:{bg};color:{fg};display:flex;align-items:center;justify-content:center;font-weight:600;border-radius:3px"
                                            )}>
                                                {label}
                                            </div>
                                        </td>
                                    }
                                }) }
                            </tr>
                        }) }
                    </tbody>
                </table>
            </div>
        </Container>
    }
}
