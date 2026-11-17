//! STIG catalog library: browse / search / diff the server catalog, add STIGs
//! to it, or open a local file.

use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use gloo_net::http::Request;
use gloo_timers::callback::Timeout;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use yew::prelude::*;

use crate::api::{api_fetch, api_get, api_json, api_post_form, api_upload_raw, BACKEND};
use crate::hooks::{use_url_state, UrlVal};
use crate::model::Stig;
use crate::ui::*;
use crate::util::{encode_uri_component, spawn_local, to_locale_string};
use crate::utils::offline_cache::{cache_catalog, cache_stig, read_cached_catalog, read_cached_stig};

const CATEGORIES: [&str; 4] = ["Windows", "Linux", "Browser", "Network"];

/// Columns the user can show / hide from the preferences dialog.
const PREF_COLUMNS: [(&str, &str); 5] = [
    ("title", "Title"),
    ("version", "Version"),
    ("release", "Release"),
    ("category", "Category"),
    ("rules", "Rules"),
];

const PAGE_SIZES: [usize; 4] = [10, 25, 50, 100];
const DEFAULT_PAGE_SIZE: usize = 25;

// ── API payloads ─────────────────────────────────────────────────────────────

/// Row of `GET /api/catalog`. Also what the offline cache stores, so every
/// field round-trips.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct CatalogEntry {
    id: String,
    title: String,
    category: String,
    version: String,
    release_info: String,
    rule_count: i64,
    json_path: String,
    last_updated: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SearchResponse {
    results: Vec<SearchHit>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SearchHit {
    stig_id: String,
    stig_title: String,
    rule_id: Option<String>,
    /// One of: "stigTitle", "ruleId", "ruleTitle".
    field: String,
    /// Contains `<mark>…</mark>` around the match, no other tags.
    snippet: String,
    score: i64,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DiffResponse {
    from_version: String,
    from_release_info: String,
    to_version: String,
    to_release_info: String,
    added: Vec<AddedRule>,
    removed: Vec<RemovedRule>,
    changed: Vec<ChangedField>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(default)]
struct AddedRule {
    id: String,
    title: String,
    severity: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(default)]
struct RemovedRule {
    id: String,
    title: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(default)]
struct ChangedField {
    id: String,
    field: String,
    from: String,
    to: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct LintReport {
    rules_count: i64,
    errors: Vec<LintIssue>,
    warnings: Vec<LintIssue>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(default)]
struct LintIssue {
    path: String,
    message: String,
}

/// Response of `POST /api/upload`.
#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct UploadResult {
    title: String,
    version: String,
    rule_count: i64,
}

/// Response of `POST /api/upload/library`.
#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(default)]
struct LibraryImportResult {
    imported: i64,
    errors: i64,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(default)]
struct DraftCreated {
    id: String,
}

// ── Local state enums ────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum View {
    Library,
    Add,
    Upload,
}

/// Lifecycle of a request-backed bit of UI (uploads, lint, cross-search).
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Idle,
    Loading,
    Done,
    Error,
}

/// "Loading" while the GET is in flight, "Ready" once we have data, "Empty"
/// when the backend says there's no archived version yet, "Error" on
/// transport / 500 failures.
#[derive(Clone, Copy, PartialEq)]
enum DiffPhase {
    Idle,
    Loading,
    Ready,
    Empty,
    Error,
}

// ── Pure helpers ─────────────────────────────────────────────────────────────

/// Neutralise a server-generated snippet before it is handed to the DOM as
/// raw HTML. Only the exact `<mark>` and `</mark>` tags survive; every other
/// `<` or `>` (including a dangling `<`) is escaped. Existing entities from
/// the server's own escaping are left intact so they render as text.
fn sanitize_snippet(raw: &str) -> String {
    fn escape_angles(s: &str, out: &mut String) {
        for c in s.chars() {
            match c {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                _ => out.push(c),
            }
        }
    }
    let mut out = String::with_capacity(raw.len() + 16);
    let mut rest = raw;
    while let Some(i) = rest.find('<') {
        escape_angles(&rest[..i], &mut out);
        let tail = &rest[i..];
        if let Some(r) = tail.strip_prefix("<mark>") {
            out.push_str("<mark>");
            rest = r;
        } else if let Some(r) = tail.strip_prefix("</mark>") {
            out.push_str("</mark>");
            rest = r;
        } else {
            out.push_str("&lt;");
            rest = &tail[1..];
        }
    }
    escape_angles(rest, &mut out);
    out
}

/// Trim long body fields for the diff table cells so a 4 KB description
/// doesn't blow up the row height. The full text is still available in the
/// API response if a future "expand" UI wants it.
fn truncate(s: &str) -> String {
    const MAX: usize = 80;
    if s.is_empty() {
        "—".to_string()
    } else if s.chars().count() > MAX {
        format!("{}…", s.chars().take(MAX).collect::<String>())
    } else {
        s.to_string()
    }
}

/// Extract the numeric release from releaseInfo, e.g.
/// "Release: 4 Benchmark …" → 4. Zero when there is none.
fn parse_release(release_info: &str) -> f64 {
    const NEEDLE: &str = "release:";
    // ASCII lowercasing keeps byte offsets aligned with the original.
    let lower = release_info.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find(NEEDLE) {
        let after = from + pos + NEEDLE.len();
        let digits: String = lower[after..]
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if !digits.is_empty() {
            return digits.parse().unwrap_or(0.0);
        }
        from = after;
    }
    0.0
}

/// JavaScript `Number(version || 0)`: empty → 0, non-numeric → NaN.
fn version_number(version: &str) -> f64 {
    let v = version.trim();
    if v.is_empty() {
        0.0
    } else {
        v.parse().unwrap_or(f64::NAN)
    }
}

/// Ordering of `a - b` the way a JS sort comparator sees it (NaN → equal).
fn num_cmp(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).unwrap_or(Ordering::Equal)
}

fn release_cmp(a: &CatalogEntry, b: &CatalogEntry) -> Ordering {
    num_cmp(parse_release(&a.release_info), parse_release(&b.release_info))
}

/// Version, then release. A non-numeric version compares equal to everything
/// (the JS comparator returned NaN there), without falling back to release.
fn version_cmp(a: &CatalogEntry, b: &CatalogEntry) -> Ordering {
    let (av, bv) = (version_number(&a.version), version_number(&b.version));
    if av.is_nan() || bv.is_nan() {
        Ordering::Equal
    } else if av != bv {
        num_cmp(av, bv)
    } else {
        release_cmp(a, b)
    }
}

/// `a.localeCompare(b)`
fn locale_cmp(a: &str, b: &str) -> Ordering {
    js_sys::JsString::from(a)
        .locale_compare(b, &js_sys::Array::new(), &js_sys::Object::new())
        .cmp(&0)
}

/// Mark entries that are superseded by a newer version of the same STIG.
/// Two entries are "same STIG" when their titles match exactly. The entry
/// with the higher version (then higher release) wins. Returns the ids of
/// the superseded entries.
fn find_superseded(catalog: &[CatalogEntry]) -> HashSet<String> {
    let mut by_title: HashMap<&str, Vec<&CatalogEntry>> = HashMap::new();
    for entry in catalog {
        by_title.entry(entry.title.as_str()).or_default().push(entry);
    }
    let mut superseded = HashSet::new();
    for mut entries in by_title.into_values() {
        if entries.len() < 2 {
            continue;
        }
        entries.sort_by(|a, b| version_cmp(b, a));
        superseded.extend(entries.iter().skip(1).map(|e| e.id.clone()));
    }
    superseded
}

fn category_badge_color(category: &str) -> &'static str {
    match category {
        "Windows" => "blue",
        "Linux" => "green",
        "Network" => "red",
        _ => "grey",
    }
}

fn is_json_file(file: &web_sys::File) -> bool {
    file.name().to_lowercase().ends_with(".json") || file.type_() == "application/json"
}

// ── Network helpers ──────────────────────────────────────────────────────────

/// Unauthenticated GET + JSON parse, erroring as "Backend returned <status>".
/// The catalog endpoints are public, so no credentials are attached.
async fn public_get<T: DeserializeOwned>(path: &str) -> Result<T, String> {
    let res = Request::get(&format!("{BACKEND}{path}"))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.ok() {
        return Err(format!("Backend returned {}", res.status()));
    }
    res.json::<T>().await.map_err(|e| e.to_string())
}

/// Multipart POST to one of the upload endpoints, which require a signed-in
/// admin — so this goes through `api_post_form` to carry the session cookie
/// (and the X-User-Id test-bypass header in E2E). On a non-2xx answer the
/// error is the JSON body's `message`, else the plain-text body, falling back
/// to "Server returned <status>".
async fn post_form<T: DeserializeOwned>(path: &str, form: web_sys::FormData) -> Result<T, String> {
    let res = api_post_form(path, form).await?;
    let status = res.status();
    if res.ok() {
        return res.json::<T>().await.map_err(|e| e.to_string());
    }
    let text = res.text().await.unwrap_or_default();
    let message = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|json| json.get("message").and_then(|m| m.as_str()).map(str::to_string));
    Err(match (message, status) {
        (Some(m), _) => m,
        (None, 401) => "Sign in to upload STIGs.".to_string(),
        (None, 403) => "Uploading STIGs requires the admin role.".to_string(),
        (None, _) if !text.trim().is_empty() => text,
        (None, _) => format!("Server returned {status}"),
    })
}

fn form_with_file(file: &web_sys::File) -> Result<web_sys::FormData, String> {
    let form = web_sys::FormData::new().map_err(|e| format!("{e:?}"))?;
    form.append_with_blob_and_filename("file", file, &file.name())
        .map_err(|e| format!("{e:?}"))?;
    Ok(form)
}

async fn lint_file(file: &web_sys::File) -> Result<LintReport, String> {
    let res = api_upload_raw("/api/stigs/lint", file).await?;
    if !res.ok() {
        return Err(format!("Lint failed: {}", res.status()));
    }
    res.json::<LintReport>().await.map_err(|e| e.to_string())
}

// ── Diff modal pieces ────────────────────────────────────────────────────────

/// One section of the diff modal — Added / Removed / Changed each get a
/// labeled mini-table that renders an em-dash when empty.
fn diff_section<T: Clone + PartialEq + 'static>(
    title: String,
    testid: &'static str,
    items: &[T],
    columns: Vec<Column<T>>,
) -> Html {
    html! {
        <UiBox {testid}>
            <Header variant="h3">{title.clone()}</Header>
            if items.is_empty() {
                <UiBox padding_vertical="s">{"—"}</UiBox>
            } else {
                <Table<T> variant="embedded" items={items.to_vec()} {columns} aria_label={title} />
            }
        </UiBox>
    }
}

fn diff_body(diff: &DiffResponse) -> Html {
    html! {
        <SpaceBetween size="l">
            <UiBox>
                <strong>{"From:"}</strong>{" v"}{&diff.from_version}{" · "}{&diff.from_release_info}
                {" → "}<strong>{"To:"}</strong>{" v"}{&diff.to_version}{" · "}{&diff.to_release_info}
            </UiBox>
            { diff_section(
                format!("Added ({})", diff.added.len()),
                "catalog-diff-added",
                &diff.added,
                vec![
                    Column::new("id", "Rule", |r: &AddedRule| html! { {&r.id} }),
                    Column::new("title", "Title", |r: &AddedRule| html! { {&r.title} }),
                    Column::new("severity", "Severity", |r: &AddedRule| html! { {&r.severity} }),
                ],
            ) }
            { diff_section(
                format!("Removed ({})", diff.removed.len()),
                "catalog-diff-removed",
                &diff.removed,
                vec![
                    Column::new("id", "Rule", |r: &RemovedRule| html! { {&r.id} }),
                    Column::new("title", "Title", |r: &RemovedRule| html! { {&r.title} }),
                ],
            ) }
            { diff_section(
                format!("Changed ({})", diff.changed.len()),
                "catalog-diff-changed",
                &diff.changed,
                vec![
                    Column::new("id", "Rule", |r: &ChangedField| html! { {&r.id} }),
                    Column::new("field", "Field", |r: &ChangedField| html! { {&r.field} }),
                    Column::new("from", "From", |r: &ChangedField| html! { {truncate(&r.from)} }),
                    Column::new("to", "To", |r: &ChangedField| html! { {truncate(&r.to)} }),
                ],
            ) }
        </SpaceBetween>
    }
}

// ── Table preferences (Cloudscape CollectionPreferences) ─────────────────────

#[derive(Properties, PartialEq)]
struct TablePreferencesProps {
    page_size: usize,
    visible_content: Vec<String>,
    /// (page size, visible column ids) when the user confirms.
    on_confirm: Callback<(usize, Vec<String>)>,
}

/// Gear button that opens a dialog for page size and visible columns. The UI
/// kit has no CollectionPreferences, so this is a local stand-in.
#[function_component]
fn TablePreferences(p: &TablePreferencesProps) -> Html {
    let open = use_state(|| false);
    let page_size = use_state(|| p.page_size);
    let visible = use_state(|| p.visible_content.clone());
    // Striped rows are always on for this table; the checkbox mirrors the
    // original dialog, where the choice was likewise not persisted.
    let striped = use_state(|| true);

    let show = {
        let (open, page_size, visible, striped) = (open.clone(), page_size.clone(), visible.clone(), striped.clone());
        let (current_size, current_visible) = (p.page_size, p.visible_content.clone());
        Callback::from(move |_: MouseEvent| {
            // Start every session from the applied preferences.
            page_size.set(current_size);
            visible.set(current_visible.clone());
            striped.set(true);
            open.set(true);
        })
    };
    let dismiss = {
        let open = open.clone();
        Callback::from(move |_: ()| open.set(false))
    };
    let cancel = dismiss.reform(|_: MouseEvent| ());
    let confirm = {
        let (open, page_size, visible) = (open.clone(), page_size.clone(), visible.clone());
        let on_confirm = p.on_confirm.clone();
        Callback::from(move |_: MouseEvent| {
            on_confirm.emit((*page_size, (*visible).clone()));
            open.set(false);
        })
    };
    let on_page_size = {
        let page_size = page_size.clone();
        Callback::from(move |v: AttrValue| {
            if let Ok(n) = v.parse::<usize>() {
                page_size.set(n);
            }
        })
    };

    let footer = html! {
        <UiBox float="right">
            <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onclick={cancel}>{"Cancel"}</Button>
                <Button variant="primary" onclick={confirm}>{"Confirm"}</Button>
            </SpaceBetween>
        </UiBox>
    };
    html! {
        <>
            <button type="button" class="ui-btn ui-btn-icon" aria-label="Preferences" title="Preferences" onclick={show}>
                <svg class="ui-icon" viewBox="0 0 16 16" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round"
                     stroke-linejoin="round" aria-hidden="true" focusable="false">
                    <circle cx="8" cy="8" r="2.5" />
                    <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.05 3.05l1.4 1.4M11.55 11.55l1.4 1.4M3.05 12.95l1.4-1.4M11.55 4.45l1.4-1.4" />
                </svg>
            </button>
            <Modal visible={*open} on_dismiss={dismiss} header={html! { {"Preferences"} }} {footer}>
                <ColumnLayout columns={2}>
                    <SpaceBetween size="l">
                        <FormField label={html! { {"Page size"} }}>
                            <RadioGroup
                                value={AttrValue::from(page_size.to_string())}
                                on_change={on_page_size}
                                items={PAGE_SIZES.iter().map(|n| RadioItem::new(n.to_string(), format!("{n} items"))).collect::<Vec<_>>()} />
                        </FormField>
                        <div>
                            <Checkbox checked={*striped} on_change={{ let striped = striped.clone(); Callback::from(move |v: bool| striped.set(v)) }}>
                                {"Striped rows"}
                            </Checkbox>
                            <UiBox variant="small" color="text-body-secondary" display="block">
                                {"Select to add alternating shaded rows"}
                            </UiBox>
                        </div>
                    </SpaceBetween>
                    <SpaceBetween size="xs">
                        <UiBox variant="h3">{"Visible columns"}</UiBox>
                        <UiBox variant="awsui-key-label">{"STIG properties"}</UiBox>
                        { for PREF_COLUMNS.iter().map(|(id, label)| {
                            let checked = visible.iter().any(|v| v == id);
                            let on_change = {
                                let visible = visible.clone();
                                Callback::from(move |on: bool| {
                                    // Keep ids in column order so re-enabling everything
                                    // lands back on the default set.
                                    let next = PREF_COLUMNS
                                        .iter()
                                        .map(|(c, _)| *c)
                                        .filter(|c| if c == id { on } else { visible.iter().any(|v| v == c) })
                                        .map(str::to_string)
                                        .collect();
                                    visible.set(next);
                                })
                            };
                            html! { <Toggle key={*id} {checked} {on_change}>{*label}</Toggle> }
                        }) }
                    </SpaceBetween>
                </ColumnLayout>
            </Modal>
        </>
    }
}

// ── StigLibrary ──────────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
pub struct StigLibraryProps {
    /// A STIG fetched from the catalog, to open as a viewer tab.
    pub on_load: Callback<(String, Stig)>,
    /// Draft id to open in the writer.
    pub on_start_draft: Callback<String>,
    /// Content of the "Upload" tab (the DropZone).
    #[prop_or_default]
    pub upload_tab: Html,
}

#[function_component]
pub fn StigLibrary(props: &StigLibraryProps) -> Html {
    let view = use_state(|| View::Library);
    let catalog = use_state(|| Rc::new(Vec::<CatalogEntry>::new()));
    // Starts true: the catalog is always fetched on mount, and the first paint
    // must show the loading row rather than the "No STIGs cached yet" empty state.
    let catalog_loading = use_state(|| true);
    let catalog_error = use_state(|| None::<String>);
    let catalog_warning = use_state(|| None::<String>);
    let loading_id = use_state(|| None::<String>);
    let drafting_id = use_state(|| None::<String>);

    // Filter + sort + columns + pagination all live in the URL so a library
    // view is bookmarkable and shareable.
    let (url_state, set_url_state) = use_url_state(vec![
        ("cat", UrlVal::from("")),
        ("q", UrlVal::from("")),
        ("super", UrlVal::from(false)),
        ("sort", UrlVal::from("title")),
        ("dir", UrlVal::from("asc")),
        ("page", UrlVal::from(1.0)),
        ("size", UrlVal::from(DEFAULT_PAGE_SIZE as f64)),
        ("cols", UrlVal::from(PREF_COLUMNS.iter().map(|(id, _)| id.to_string()).collect::<Vec<_>>())),
    ]);
    let category_filter = url_state.str("cat");
    let search_text = url_state.str("q");
    let show_superseded = url_state.bool("super");
    let sort_col = url_state.str("sort");
    let sort_desc = url_state.str("dir") != "asc";
    let current_page = (url_state.num("page") as usize).max(1);
    let page_size = match url_state.num("size") as usize {
        0 => DEFAULT_PAGE_SIZE,
        n => n,
    };
    let visible_content = url_state.list("cols");

    // Add-to-library form state (single STIG)
    let add_files = use_state(Vec::<web_sys::File>::new);
    let add_id = use_state(String::new);
    let add_category = use_state(|| CATEGORIES[0].to_string());
    let add_status = use_state(|| Phase::Idle);
    let add_result = use_state(|| None::<Result<UploadResult, String>>);
    // Lint state for the staged JSON file. `lint_report` is None when nothing
    // has been linted yet (e.g. file is a .zip, or no file picked).
    let lint_report = use_state(|| None::<LintReport>);
    let lint_status = use_state(|| Phase::Idle);
    let lint_expanded = use_state(|| false);

    // Library bundle import state
    let lib_files = use_state(Vec::<web_sys::File>::new);
    let lib_status = use_state(|| Phase::Idle);
    let lib_result = use_state(|| None::<Result<LibraryImportResult, String>>);

    // Catalog version diff modal — opened from the per-row "Diff vs
    // previous" button. `diff_stig_id` is the STIG being diffed.
    let diff_stig_id = use_state(|| None::<String>);
    let diff_status = use_state(|| DiffPhase::Idle);
    let diff_data = use_state(|| None::<Rc<DiffResponse>>);
    let diff_error = use_state(|| None::<String>);

    // Cross-rule search — separate from the existing title-only `q` URL
    // filter. Hits a server endpoint that scans rule ids + titles across the
    // whole catalog. Debounced so each keystroke doesn't fire a request.
    let cross_search = use_state(String::new);
    let cross_results = use_state_eq(Vec::<SearchHit>::new);
    let cross_status = use_state_eq(|| Phase::Idle);
    let cross_error = use_state_eq(|| None::<String>);

    {
        let (results, status, error) = (cross_results.clone(), cross_status.clone(), cross_error.clone());
        use_effect_with((*cross_search).clone(), move |term| {
            let term = term.trim().to_string();
            let cancelled = Rc::new(Cell::new(false));
            let mut debounce = None;
            if term.encode_utf16().count() < 2 {
                results.set(Vec::new());
                status.set(Phase::Idle);
                error.set(None);
            } else {
                status.set(Phase::Loading);
                let cancelled = cancelled.clone();
                debounce = Some(Timeout::new(250, move || {
                    spawn_local(async move {
                        let path = format!("/api/catalog/search?q={}&limit=50", encode_uri_component(&term));
                        let response = api_get::<SearchResponse>(&path).await;
                        if cancelled.get() {
                            return;
                        }
                        match response {
                            Ok(data) => {
                                results.set(data.results);
                                status.set(Phase::Done);
                                error.set(None);
                            }
                            Err(err) => {
                                results.set(Vec::new());
                                status.set(Phase::Error);
                                error.set(Some(err));
                            }
                        }
                    });
                }));
            }
            move || {
                cancelled.set(true);
                drop(debounce);
            }
        });
    }

    let open_diff = {
        let (stig_id, status, data, error) =
            (diff_stig_id.clone(), diff_status.clone(), diff_data.clone(), diff_error.clone());
        Callback::from(move |id: String| {
            let (status, data, error) = (status.clone(), data.clone(), error.clone());
            stig_id.set(Some(id.clone()));
            status.set(DiffPhase::Loading);
            data.set(None);
            error.set(None);
            spawn_local(async move {
                // api_fetch so the X-User-Id test-bypass header is sent in E2E,
                // not just the session cookie that real OIDC sessions carry.
                let path = format!("/api/stigs/{}/diff", encode_uri_component(&id));
                let outcome = async {
                    let res = api_fetch("GET", &path).await?;
                    if res.status() == 404 {
                        return Ok(None);
                    }
                    if !res.ok() {
                        return Err(format!("Backend returned {}", res.status()));
                    }
                    res.json::<DiffResponse>().await.map(Some).map_err(|e| e.to_string())
                }
                .await;
                match outcome {
                    Ok(Some(diff)) => {
                        data.set(Some(Rc::new(diff)));
                        status.set(DiffPhase::Ready);
                    }
                    Ok(None) => status.set(DiffPhase::Empty),
                    Err(err) => {
                        error.set(Some(err));
                        status.set(DiffPhase::Error);
                    }
                }
            });
        })
    };

    let close_diff = {
        let (stig_id, status, data, error) =
            (diff_stig_id.clone(), diff_status.clone(), diff_data.clone(), diff_error.clone());
        Callback::from(move |_: ()| {
            stig_id.set(None);
            status.set(DiffPhase::Idle);
            data.set(None);
            error.set(None);
        })
    };

    // Cleared on unmount so a late catalog response doesn't touch state.
    let alive = use_memo((), |_| Cell::new(true));
    let fetch_catalog = {
        let (catalog, loading, error, warning) =
            (catalog.clone(), catalog_loading.clone(), catalog_error.clone(), catalog_warning.clone());
        let alive = alive.clone();
        Callback::from(move |_: ()| {
            let (catalog, loading, error, warning) = (catalog.clone(), loading.clone(), error.clone(), warning.clone());
            let alive = alive.clone();
            loading.set(true);
            error.set(None);
            warning.set(None);
            spawn_local(async move {
                let response = public_get::<Vec<CatalogEntry>>("/api/catalog").await;
                if !alive.get() {
                    return;
                }
                match response {
                    Ok(list) => {
                        let list = Rc::new(list);
                        catalog.set(list.clone());
                        loading.set(false);
                        cache_catalog(list.as_slice()).await;
                    }
                    Err(err) => {
                        let cached = read_cached_catalog::<Vec<CatalogEntry>>().await;
                        if !alive.get() {
                            return;
                        }
                        match cached {
                            Some(cached) => {
                                catalog.set(Rc::new(cached.list));
                                warning.set(Some(format!(
                                    "Backend unreachable — showing cached catalog from {}.",
                                    to_locale_string(&cached.cached_at)
                                )));
                            }
                            None => error.set(Some(err)),
                        }
                        loading.set(false);
                    }
                }
            });
        })
    };

    {
        let fetch_catalog = fetch_catalog.clone();
        use_effect_with((), move |_| {
            fetch_catalog.emit(());
            move || alive.set(false)
        });
    }

    let superseded_ids = use_memo(catalog.clone(), |catalog| find_superseded(catalog));

    let display_list = use_memo(
        (
            (*catalog).clone(),
            category_filter.clone(),
            search_text.clone(),
            show_superseded,
            sort_col.clone(),
            sort_desc,
        ),
        |(catalog, category, search, show_superseded, sort_col, sort_desc)| {
            let superseded = find_superseded(catalog);
            let term = search.to_lowercase();
            let mut list: Vec<CatalogEntry> = catalog
                .iter()
                .filter(|e| category.is_empty() || &e.category == category)
                .filter(|e| *show_superseded || !superseded.contains(&e.id))
                .filter(|e| term.is_empty() || e.title.to_lowercase().contains(&term))
                .cloned()
                .collect();
            list.sort_by(|a, b| {
                let ord = match sort_col.as_str() {
                    "category" => locale_cmp(&a.category, &b.category),
                    "title" => locale_cmp(&a.title, &b.title),
                    "version" => version_cmp(a, b),
                    "release" => release_cmp(a, b),
                    "rules" => a.rule_count.cmp(&b.rule_count),
                    _ => Ordering::Equal,
                };
                if *sort_desc {
                    ord.reverse()
                } else {
                    ord
                }
            });
            list
        },
    );

    let page_count = display_list.len().div_ceil(page_size).max(1);
    let paginated_items: Vec<CatalogEntry> = display_list
        .iter()
        .skip((current_page - 1) * page_size)
        .take(page_size)
        .cloned()
        .collect();

    let handle_load = {
        let on_load = props.on_load.clone();
        let (loading_id, error, warning) = (loading_id.clone(), catalog_error.clone(), catalog_warning.clone());
        Callback::from(move |id: String| {
            let on_load = on_load.clone();
            let (loading_id, error, warning) = (loading_id.clone(), error.clone(), warning.clone());
            loading_id.set(Some(id.clone()));
            spawn_local(async move {
                let path = format!("/api/stigs/{}", encode_uri_component(&id));
                match public_get::<Stig>(&path).await {
                    Ok(stig) => {
                        on_load.emit((id.clone(), stig.clone()));
                        loading_id.set(None);
                        cache_stig(&id, &stig).await;
                    }
                    Err(err) => {
                        match read_cached_stig::<Stig>(&id).await {
                            Some(cached) => {
                                let title = if cached.stig.title.is_empty() { id.clone() } else { cached.stig.title.clone() };
                                let when = to_locale_string(&cached.cached_at);
                                on_load.emit((id.clone(), cached.stig));
                                warning.set(Some(format!("Loaded \"{title}\" from cache ({when}).")));
                            }
                            None => error.set(Some(format!("Failed to load STIG: {err}"))),
                        }
                        loading_id.set(None);
                    }
                }
            });
        })
    };

    let handle_start_draft = {
        let on_start_draft = props.on_start_draft.clone();
        let (drafting_id, error) = (drafting_id.clone(), catalog_error.clone());
        Callback::from(move |id: String| {
            let on_start_draft = on_start_draft.clone();
            let (drafting_id, error) = (drafting_id.clone(), error.clone());
            drafting_id.set(Some(id.clone()));
            spawn_local(async move {
                let path = format!("/api/drafts/from-stig/{}", encode_uri_component(&id));
                match api_json::<DraftCreated, ()>(&path, "POST", None).await {
                    Ok(draft) => on_start_draft.emit(draft.id),
                    Err(err) => error.set(Some(format!("Failed to create draft: {err}"))),
                }
                drafting_id.set(None);
            });
        })
    };

    // Lint a staged JSON file via /api/stigs/lint. Only runs for *.json — ZIP
    // uploads still go through the XCCDF parser server-side. Sets
    // `lint_report` so the UI can render the issue list and decide whether to
    // disable the upload button.
    let run_lint = {
        let (report, status) = (lint_report.clone(), lint_status.clone());
        Callback::from(move |file: Option<web_sys::File>| {
            let (report, status) = (report.clone(), status.clone());
            report.set(None);
            let Some(file) = file.filter(is_json_file) else {
                status.set(Phase::Idle);
                return;
            };
            status.set(Phase::Loading);
            spawn_local(async move {
                let result = lint_file(&file).await.unwrap_or_else(|message| LintReport {
                    rules_count: 0,
                    errors: vec![LintIssue { path: String::new(), message }],
                    warnings: vec![],
                });
                report.set(Some(result));
                status.set(Phase::Done);
            });
        })
    };

    let handle_add_submit = {
        let (files, id, category) = (add_files.clone(), add_id.clone(), add_category.clone());
        let (status, result) = (add_status.clone(), add_result.clone());
        let (lint_report, lint_status, lint_expanded) =
            (lint_report.clone(), lint_status.clone(), lint_expanded.clone());
        let fetch_catalog = fetch_catalog.clone();
        Callback::from(move |_: ()| {
            let stig_id = id.trim().to_string();
            let Some(file) = files.first().cloned() else {
                return;
            };
            if stig_id.is_empty() {
                return;
            }
            let (files, id, category) = (files.clone(), id.clone(), (*category).clone());
            let (status, result) = (status.clone(), result.clone());
            let (lint_report, lint_status, lint_expanded) =
                (lint_report.clone(), lint_status.clone(), lint_expanded.clone());
            let fetch_catalog = fetch_catalog.clone();
            status.set(Phase::Loading);
            result.set(None);
            spawn_local(async move {
                let outcome = async {
                    let form = form_with_file(&file)?;
                    form.append_with_str("id", &stig_id).map_err(|e| format!("{e:?}"))?;
                    form.append_with_str("category", &category).map_err(|e| format!("{e:?}"))?;
                    post_form::<UploadResult>("/api/upload", form).await
                }
                .await;
                let ok = outcome.is_ok();
                result.set(Some(outcome));
                if ok {
                    status.set(Phase::Done);
                    files.set(Vec::new());
                    id.set(String::new());
                    lint_report.set(None);
                    lint_status.set(Phase::Idle);
                    lint_expanded.set(false);
                    fetch_catalog.emit(());
                } else {
                    status.set(Phase::Error);
                }
            });
        })
    };

    let handle_lib_submit = {
        let (files, status, result) = (lib_files.clone(), lib_status.clone(), lib_result.clone());
        let fetch_catalog = fetch_catalog.clone();
        Callback::from(move |_: ()| {
            let Some(file) = files.first().cloned() else {
                return;
            };
            let (files, status, result) = (files.clone(), status.clone(), result.clone());
            let fetch_catalog = fetch_catalog.clone();
            status.set(Phase::Loading);
            result.set(None);
            spawn_local(async move {
                let outcome = async {
                    let form = form_with_file(&file)?;
                    post_form::<LibraryImportResult>("/api/upload/library", form).await
                }
                .await;
                let ok = outcome.is_ok();
                result.set(Some(outcome));
                if ok {
                    status.set(Phase::Done);
                    files.set(Vec::new());
                    fetch_catalog.emit(());
                } else {
                    status.set(Phase::Error);
                }
            });
        })
    };

    let go_to = |target: View| {
        let view = view.clone();
        Callback::from(move |_: MouseEvent| view.set(target))
    };

    if *view == View::Library {
        // ── Column definitions ──────────────────────────────────────────────
        let mut columns: Vec<Column<CatalogEntry>> = vec![
            Column::new("title", "Title", {
                let superseded = superseded_ids.clone();
                let loading_id = (*loading_id).clone();
                let handle_load = handle_load.clone();
                move |item: &CatalogEntry| {
                    let dimmed = superseded.contains(&item.id);
                    let on_follow = {
                        let (handle_load, id) = (handle_load.clone(), item.id.clone());
                        Callback::from(move |e: MouseEvent| {
                            e.prevent_default();
                            handle_load.emit(id.clone());
                        })
                    };
                    html! {
                        <span style={dimmed.then_some("opacity:0.5;")}>
                            <Link {on_follow}>
                                { if loading_id.as_ref() == Some(&item.id) { "Loading…" } else { item.title.as_str() } }
                            </Link>
                            if dimmed {
                                {" "}
                                <StatusIndicator kind="warning">{"Superseded"}</StatusIndicator>
                            }
                        </span>
                    }
                }
            })
            .sortable(),
            Column::new("version", "Version", |item: &CatalogEntry| {
                html! { { if item.version.is_empty() { "—" } else { item.version.as_str() } } }
            })
            .sortable()
            .width("110px"),
            Column::new("release", "Release", |item: &CatalogEntry| {
                match parse_release(&item.release_info) {
                    0.0 => html! { {"—"} },
                    r => html! { {r} },
                }
            })
            .sortable()
            .width("110px"),
            Column::new("category", "Category", |item: &CatalogEntry| {
                html! { <Badge color={category_badge_color(&item.category)}>{&item.category}</Badge> }
            })
            .sortable()
            .width("130px"),
            Column::new("rules", "Rules", |item: &CatalogEntry| html! { {item.rule_count} })
                .sortable()
                .width("110px"),
        ];
        columns.retain(|c| visible_content.iter().any(|v| *v == *c.id));
        // The diff and actions columns are always shown.
        columns.push(
            Column::new("diff", "Diff", {
                let diffing = (*diff_status == DiffPhase::Loading).then(|| (*diff_stig_id).clone()).flatten();
                let open_diff = open_diff.clone();
                move |item: &CatalogEntry| {
                    let onclick = {
                        let (open_diff, id) = (open_diff.clone(), item.id.clone());
                        Callback::from(move |e: MouseEvent| {
                            e.stop_propagation();
                            open_diff.emit(id.clone());
                        })
                    };
                    html! {
                        <Button variant="inline-link" loading={diffing.as_ref() == Some(&item.id)} {onclick}
                                testid={format!("diff-button-{}", item.id)}>
                            {"Diff vs previous"}
                        </Button>
                    }
                }
            })
            .width("160px"),
        );
        columns.push(
            Column::new("actions", "Actions", {
                let drafting_id = (*drafting_id).clone();
                let handle_start_draft = handle_start_draft.clone();
                move |item: &CatalogEntry| {
                    let onclick = {
                        let (start, id) = (handle_start_draft.clone(), item.id.clone());
                        Callback::from(move |e: MouseEvent| {
                            e.stop_propagation();
                            start.emit(id.clone());
                        })
                    };
                    html! {
                        <Button variant="inline-link" loading={drafting_id.as_ref() == Some(&item.id)} {onclick}>
                            {"Start Draft"}
                        </Button>
                    }
                }
            })
            .width("130px"),
        );

        let on_sort = set_url_state.reform(|(column, descending): (AttrValue, bool)| {
            vec![
                ("sort", UrlVal::from(column.as_str())),
                ("dir", UrlVal::from(if descending { "desc" } else { "asc" })),
                ("page", UrlVal::from(1.0)),
            ]
        });
        let on_page = set_url_state.reform(|page: usize| vec![("page", UrlVal::from(page as f64))]);
        let on_preferences = set_url_state.reform(|(size, cols): (usize, Vec<String>)| {
            vec![
                ("size", UrlVal::from(size as f64)),
                ("cols", UrlVal::from(cols)),
                ("page", UrlVal::from(1.0)),
            ]
        });
        let on_show_superseded = set_url_state
            .reform(|checked: bool| vec![("super", UrlVal::from(checked)), ("page", UrlVal::from(1.0))]);
        let on_search =
            set_url_state.reform(|text: String| vec![("q", UrlVal::from(text)), ("page", UrlVal::from(1.0))]);
        let on_category = set_url_state.reform(|id: AttrValue| {
            let category = if id == "all" { "" } else { id.as_str() };
            vec![("cat", UrlVal::from(category)), ("page", UrlVal::from(1.0))]
        });
        let on_cross_search = {
            let cross_search = cross_search.clone();
            Callback::from(move |v: String| cross_search.set(v))
        };

        let pagination = html! {
            <SpaceBetween direction="horizontal" size="xs" align_items="center">
                <Pagination current_page_index={current_page} pages_count={page_count} on_change={on_page} />
                <TablePreferences {page_size} visible_content={visible_content.clone()} on_confirm={on_preferences} />
            </SpaceBetween>
        };

        let header = html! {
            <Header variant="awsui-h1-sticky" counter={format!("({})", display_list.len())}
                actions={html! {
                    <SpaceBetween direction="horizontal" size="xs" align_items="center">
                        if !superseded_ids.is_empty() {
                            <Toggle checked={show_superseded} on_change={on_show_superseded}>
                                {format!("Show superseded ({})", superseded_ids.len())}
                            </Toggle>
                        }
                        <Button onclick={go_to(View::Add)}>{"Add to Library"}</Button>
                        <Button onclick={go_to(View::Upload)}>{"Open Local File"}</Button>
                    </SpaceBetween>
                }}>
                {"STIG Library"}
            </Header>
        };

        let cross_columns: Vec<Column<SearchHit>> = vec![
            Column::new("stig", "STIG", {
                let handle_load = handle_load.clone();
                move |r: &SearchHit| {
                    let on_follow = {
                        let (handle_load, id) = (handle_load.clone(), r.stig_id.clone());
                        Callback::from(move |e: MouseEvent| {
                            e.prevent_default();
                            handle_load.emit(id.clone());
                        })
                    };
                    html! { <Link {on_follow}>{&r.stig_title}</Link> }
                }
            }),
            Column::new("ruleId", "Rule ID", |r: &SearchHit| {
                html! { { r.rule_id.as_deref().filter(|id| !id.is_empty()).unwrap_or("—") } }
            })
            .width("220px"),
            Column::new("field", "Field", |r: &SearchHit| html! { {&r.field} }).width("110px"),
            Column::new("snippet", "Snippet", |r: &SearchHit| {
                let testid = format!(
                    "catalog-cross-search-snippet-{}-{}-{}",
                    r.stig_id,
                    r.rule_id.as_deref().unwrap_or("stig"),
                    r.field
                );
                html! {
                    <span data-testid={testid}>
                        { Html::from_html_unchecked(AttrValue::from(sanitize_snippet(&r.snippet))) }
                    </span>
                }
            }),
            Column::new("score", "Score", |r: &SearchHit| html! { {r.score} }).width("80px"),
        ];

        let mut segments = vec![SegmentOption::new("all", "All")];
        segments.extend(CATEGORIES.iter().map(|c| SegmentOption::new(*c, *c)));
        let selected_segment = if category_filter.is_empty() { "all".to_string() } else { category_filter.clone() };

        let filter = html! {
            <SpaceBetween size="s">
                <SpaceBetween direction="horizontal" size="m" align_items="center">
                    <TextFilter filtering_text={search_text.clone()} on_change={on_search}
                        filtering_placeholder="Search by title"
                        count_text={format!("{} matches", display_list.len())} />
                    <SegmentedControl selected_id={AttrValue::from(selected_segment)} on_change={on_category}
                        options={segments} />
                    <FormField label={html! { {"Search across rules"} }}>
                        <Input kind="search" value={(*cross_search).clone()} on_change={on_cross_search}
                            placeholder="Search rule titles, ids…" testid="catalog-cross-search-input" />
                    </FormField>
                </SpaceBetween>
                if cross_search.trim().encode_utf16().count() >= 2 {
                    <ExpandableSection variant="container" default_expanded=true
                        header_text={html! {{
                            if *cross_status == Phase::Loading {
                                "Cross-rule matches (searching…)".to_string()
                            } else {
                                format!("Cross-rule matches ({})", cross_results.len())
                            }
                        }}}
                        testid="catalog-cross-search-panel">
                        if *cross_status == Phase::Error {
                            <Alert kind="error">{(*cross_error).clone().unwrap_or_default()}</Alert>
                        }
                        if *cross_status == Phase::Done && cross_results.is_empty() {
                            <UiBox testid="catalog-cross-search-empty">{"No matches."}</UiBox>
                        }
                        if !cross_results.is_empty() {
                            <Table<SearchHit> variant="embedded" items={(*cross_results).clone()}
                                columns={cross_columns} testid="catalog-cross-search-results"
                                aria_label="Cross-rule matches" />
                        }
                    </ExpandableSection>
                }
            </SpaceBetween>
        };

        let empty = html! {
            <UiBox text_align="center" padding_vertical="l">
                if catalog.is_empty() {
                    <SpaceBetween size="xs">
                        <b>{"No STIGs cached yet"}</b>
                        <UiBox>
                            {"Use the "}
                            <Link on_follow={go_to(View::Add)}>{"Add to Library"}</Link>
                            {" tab to upload a STIG ZIP."}
                        </UiBox>
                    </SpaceBetween>
                } else {
                    <b>{"No STIGs match the current filters."}</b>
                }
            </UiBox>
        };

        let diff_title = format!("Diff vs previous — {}", (*diff_stig_id).clone().unwrap_or_default());
        return html! {
            <>
                <Table<CatalogEntry>
                    variant="full-page"
                    sticky_header=true
                    striped_rows=true
                    loading={*catalog_loading}
                    loading_text="Connecting to backend"
                    items={paginated_items}
                    {columns}
                    track_by={Callback::from(|item: CatalogEntry| item.id)}
                    sorting_column={AttrValue::from(sort_col.clone())}
                    sorting_descending={sort_desc}
                    {on_sort}
                    {pagination}
                    {header}
                    {filter}
                    {empty} />
                <Modal visible={diff_stig_id.is_some()} on_dismiss={close_diff}
                       header={html! { {diff_title} }} size="large" testid="catalog-diff-modal">
                    { match *diff_status {
                        DiffPhase::Loading => html! { <UiBox>{"Loading diff…"}</UiBox> },
                        DiffPhase::Empty => html! {
                            <Alert kind="info" testid="catalog-diff-empty">
                                {"No previous version archived for this STIG yet."}
                            </Alert>
                        },
                        DiffPhase::Error => html! {
                            <Alert kind="error">
                                {"Failed to load diff: "}{(*diff_error).clone().unwrap_or_default()}
                            </Alert>
                        },
                        DiffPhase::Ready => diff_data.as_ref().map(|diff| diff_body(diff)).unwrap_or_default(),
                        DiffPhase::Idle => html! {},
                    } }
                </Modal>
            </>
        };
    }

    // ── Add to Library / Open Local File views ──────────────────────────────

    let dismiss_error = {
        let error = catalog_error.clone();
        Callback::from(move |_: ()| error.set(None))
    };
    let dismiss_warning = {
        let warning = catalog_warning.clone();
        Callback::from(move |_: ()| warning.set(None))
    };

    let add_view = if *view == View::Add {
        let dismiss_add = {
            let (status, result) = (add_status.clone(), add_result.clone());
            Callback::from(move |_: ()| {
                status.set(Phase::Idle);
                result.set(None);
            })
        };
        let dismiss_lib = {
            let (status, result) = (lib_status.clone(), lib_result.clone());
            Callback::from(move |_: ()| {
                status.set(Phase::Idle);
                result.set(None);
            })
        };
        let on_add_files = {
            let (files, run_lint) = (add_files.clone(), run_lint.clone());
            Callback::from(move |picked: Vec<web_sys::File>| {
                run_lint.emit(picked.first().cloned());
                files.set(picked);
            })
        };
        let on_add_id = {
            let id = add_id.clone();
            Callback::from(move |v: String| id.set(v))
        };
        // Enter in the ID field submits the form, as it did with a native submit button.
        let on_add_id_key = {
            let submit = handle_add_submit.clone();
            Callback::from(move |e: KeyboardEvent| {
                if e.key() == "Enter" {
                    e.prevent_default();
                    submit.emit(());
                }
            })
        };
        let on_add_category = {
            let category = add_category.clone();
            Callback::from(move |o: SelectOption| category.set(o.value.to_string()))
        };
        let on_lib_files = {
            let files = lib_files.clone();
            Callback::from(move |picked: Vec<web_sys::File>| files.set(picked))
        };
        let toggle_lint_details = {
            let expanded = lint_expanded.clone();
            Callback::from(move |_: MouseEvent| expanded.set(!*expanded))
        };
        let prevent_submit = Callback::from(|e: SubmitEvent| e.prevent_default());

        let lint_errors = lint_report.as_ref().map(|r| r.errors.len()).unwrap_or(0);
        let lint_warnings = lint_report.as_ref().map(|r| r.warnings.len()).unwrap_or(0);
        let lint_done = *lint_status == Phase::Done;
        let add_disabled = add_files.is_empty()
            || add_id.trim().is_empty()
            || lint_errors > 0
            || *lint_status == Phase::Loading;

        let downloads_link = html! {
            <Link href="https://public.cyber.mil/stigs/downloads/" external=true>{"public.cyber.mil"}</Link>
        };

        html! {
            <SpaceBetween size="l">
                if *add_status == Phase::Done {
                    if let Some(Ok(added)) = &*add_result {
                        <Alert kind="success" dismissible=true on_dismiss={dismiss_add.clone()}>
                            <strong>{&added.title}</strong>{" added — "}
                            {added.rule_count}{" rules ("}{&added.version}{"). "}
                            <Link on_follow={go_to(View::Library)}>{"View in Library"}</Link>
                        </Alert>
                    }
                }
                if *add_status == Phase::Error {
                    if let Some(Err(message)) = &*add_result {
                        <Alert kind="error" dismissible=true on_dismiss={dismiss_add.clone()}>{message}</Alert>
                    }
                }
                <Container header={html! {
                    <Header variant="h2" description={html! {
                        <>{"Download a STIG ZIP from "}{downloads_link.clone()}{", then upload it here."}</>
                    }}>
                        {"Add Single STIG"}
                    </Header>
                }}>
                    <form onsubmit={prevent_submit.clone()}>
                        <SpaceBetween size="l">
                            <FileUpload value={(*add_files).clone()} on_change={on_add_files}
                                accept=".zip,.json" show_file_size=true testid="add-stig-file-input" />
                            if *lint_status == Phase::Loading {
                                <Alert kind="info" testid="stig-lint-loading">{"Validating STIG JSON…"}</Alert>
                            }
                            if let Some(report) = (*lint_report).as_ref().filter(|_| lint_done) {
                                if lint_errors == 0 && lint_warnings == 0 {
                                    <Alert kind="success" testid="stig-lint-clean">
                                        {report.rules_count}{" rules · no issues"}
                                    </Alert>
                                } else {
                                    <Alert
                                        kind={if lint_errors > 0 { "error" } else { "warning" }}
                                        testid={if lint_errors > 0 { "stig-lint-errors" } else { "stig-lint-warnings" }}
                                        header={html! {
                                            <span>{lint_errors}{" errors, "}{lint_warnings}{" warnings"}</span>
                                        }}
                                        action={html! {
                                            <Button variant="inline-link" onclick={toggle_lint_details}>
                                                { if *lint_expanded { "Hide details" } else { "Show details" } }
                                            </Button>
                                        }}>
                                        if *lint_expanded {
                                            <UiBox testid="stig-lint-details">
                                                <ul style="margin:0;padding-left:20px;">
                                                    { for report.errors.iter().map(|i| ("error", i))
                                                        .chain(report.warnings.iter().map(|i| ("warning", i)))
                                                        .enumerate()
                                                        .map(|(idx, (kind, issue))| html! {
                                                            <li key={idx} data-testid={format!("stig-lint-issue-{idx}")}>
                                                                <strong>{kind}</strong>{" "}
                                                                <code>{ if issue.path.is_empty() { "/" } else { issue.path.as_str() } }</code>
                                                                {" · "}{&issue.message}
                                                            </li>
                                                        }) }
                                                </ul>
                                            </UiBox>
                                        }
                                    </Alert>
                                }
                            }
                            <ColumnLayout columns={2}>
                                <FormField label={html! { {"ID"} }} description={html! { {"Slug, e.g. windows-11"} }}>
                                    <Input value={(*add_id).clone()} on_change={on_add_id}
                                        on_key_down={on_add_id_key} placeholder="e.g. windows-11" />
                                </FormField>
                                <FormField label={html! { {"Category"} }} description={html! { {"Used for filtering"} }}>
                                    <Select selected={AttrValue::from((*add_category).clone())}
                                        on_change={on_add_category}
                                        options={CATEGORIES.iter().map(|c| SelectOption::new(*c, *c)).collect::<Vec<_>>()} />
                                </FormField>
                            </ColumnLayout>
                            <Button variant="primary" loading={*add_status == Phase::Loading}
                                disabled={add_disabled} testid="add-stig-upload-button"
                                onclick={handle_add_submit.reform(|_: MouseEvent| ())}>
                                {"Upload to Library"}
                            </Button>
                        </SpaceBetween>
                    </form>
                </Container>

                if *lib_status == Phase::Done {
                    if let Some(Ok(imported)) = &*lib_result {
                        <Alert kind="success" dismissible=true on_dismiss={dismiss_lib.clone()}>
                            {"Imported "}<strong>{imported.imported}</strong>{" STIGs"}
                            if imported.errors > 0 {
                                {format!(" ({} skipped)", imported.errors)}
                            }
                            {". "}
                            <Link on_follow={go_to(View::Library)}>{"View in Library"}</Link>
                        </Alert>
                    }
                }
                if *lib_status == Phase::Error {
                    if let Some(Err(message)) = &*lib_result {
                        <Alert kind="error" dismissible=true on_dismiss={dismiss_lib.clone()}>{message}</Alert>
                    }
                }
                <Container header={html! {
                    <Header variant="h2" description={html! {
                        <>
                            {"Download the all-in-one "}<strong>{"SRG-STIG Library"}</strong>
                            {" bundle (~350 MB) from "}{downloads_link.clone()}
                            {". IDs and categories are inferred automatically."}
                        </>
                    }}>
                        {"Import Library Bundle"}
                    </Header>
                }}>
                    <form onsubmit={prevent_submit}>
                        <SpaceBetween size="l">
                            <FileUpload value={(*lib_files).clone()} on_change={on_lib_files}
                                accept=".zip" show_file_size=true />
                            <Button variant="primary" loading={*lib_status == Phase::Loading}
                                disabled={lib_files.is_empty()}
                                onclick={handle_lib_submit.reform(|_: MouseEvent| ())}>
                                {"Import Bundle"}
                            </Button>
                        </SpaceBetween>
                    </form>
                </Container>
            </SpaceBetween>
        }
    } else {
        html! {}
    };

    html! {
        <div style="max-width:960px;margin:0 auto;padding-top:24px;">
            <SpaceBetween size="l">
                <Button variant="link" icon_name="arrow-left" onclick={go_to(View::Library)}>
                    {"Back to Library"}
                </Button>

                if let Some(message) = &*catalog_error {
                    <Alert kind="error" dismissible=true on_dismiss={dismiss_error}>{message}</Alert>
                }

                if let Some(message) = &*catalog_warning {
                    <Alert kind="warning" dismissible=true on_dismiss={dismiss_warning}>{message}</Alert>
                }

                {add_view}

                if *view == View::Upload {
                    <UiBox padding_vertical="l">{props.upload_tab.clone()}</UiBox>
                }
            </SpaceBetween>
        </div>
    }
}

#[cfg(test)]
mod snippet_tests {
    use super::sanitize_snippet;

    fn only_mark_tags(out: &str) -> bool {
        let rest = out.replace("<mark>", "").replace("</mark>", "");
        !rest.contains('<') && !rest.contains('>')
    }

    #[test]
    fn keeps_server_mark_tags() {
        assert_eq!(
            sanitize_snippet("a <mark>b</mark> c"),
            "a <mark>b</mark> c"
        );
    }

    #[test]
    fn escapes_markup_and_dangling_angle() {
        for input in [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "tail <",
            "<mark",
            "<<mark>x</mark>",
            "MARK_OPEN MARK_CLOSE",
            "a &amp; b &quot;q&quot;",
            "<MARK>x</MARK>",
        ] {
            assert!(only_mark_tags(&sanitize_snippet(input)), "input: {input}");
        }
    }

    #[test]
    fn sentinel_text_stays_literal() {
        assert_eq!(sanitize_snippet("MARK_CLOSE"), "MARK_CLOSE");
        assert_eq!(sanitize_snippet("x <"), "x &lt;");
    }
}
