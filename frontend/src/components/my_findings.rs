//! "My findings": open findings assigned to the current user, bucketed by
//! due date, with URL-synced filters and per-user saved searches.

use crate::api::{api_fetch, api_fetch_json, api_get};
use crate::hooks::{use_url_state, UrlVal};
use crate::ui::*;
use crate::util::{encode_uri_component, parse_date_ms, spawn_local, to_locale_string, window};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use yew::prelude::*;

const SAVED_PAGE: &str = "myfindings";

const DUE_SOON_DAYS: u32 = 7;

fn severity_badge(severity: &str) -> &'static str {
    match severity {
        "CAT I" => "severity-high",
        "CAT II" => "severity-medium",
        "CAT III" => "severity-low",
        _ => "grey",
    }
}

fn severity_options() -> Vec<SelectOption> {
    vec![
        SelectOption::new("", "All severities"),
        SelectOption::new("CAT I", "CAT I"),
        SelectOption::new("CAT II", "CAT II"),
        SelectOption::new("CAT III", "CAT III"),
    ]
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Finding {
    checklist_id: String,
    rule_id: String,
    severity: Option<String>,
    weighted_score: f64,
    asset_name: String,
    stig_title: String,
    due_date: Option<String>,
    updated_at: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SavedSearch {
    id: String,
    name: String,
    params: String,
}

impl SavedSearch {
    fn params_label(&self) -> String {
        if self.params.is_empty() {
            "(no filters)".to_string()
        } else {
            format!("?{}", self.params)
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Bucket {
    Overdue,
    DueSoon,
    Open,
}

/// `today` / `due_soon_cutoff` are epoch ms of local midnight today and
/// `DUE_SOON_DAYS` days later.
fn bucket_of(f: &Finding, today: f64, due_soon_cutoff: f64) -> Bucket {
    let Some(due) = f.due_date.as_deref().filter(|d| !d.is_empty()) else {
        return Bucket::Open;
    };
    let d = parse_date_ms(due);
    if d < today {
        Bucket::Overdue
    } else if d <= due_soon_cutoff {
        Bucket::DueSoon
    } else {
        Bucket::Open
    }
}

#[derive(Properties, PartialEq)]
struct FindingsTableProps {
    title: AttrValue,
    items: Vec<Finding>,
    /// Badge colour of the bucket: "red" | "blue" | "grey".
    tone: AttrValue,
    empty_text: AttrValue,
}

#[function_component]
fn FindingsTable(p: &FindingsTableProps) -> Html {
    let dash = || html! { <UiBox color="text-status-inactive">{"—"}</UiBox> };
    let tone = p.tone.clone();
    let columns = vec![
        Column::new("rule", "Rule", |f: &Finding| html! { {f.rule_id.clone()} }),
        Column::new("severity", "Severity", move |f: &Finding| {
            match &f.severity {
                Some(s) if !s.is_empty() => {
                    html! { <Badge color={severity_badge(s)}>{s.clone()}</Badge> }
                }
                _ => dash(),
            }
        }),
        Column::new("weight", "Weight", |f: &Finding| {
            let w = f.weighted_score;
            let color = if w > 20.0 {
                "red"
            } else if w > 5.0 {
                "blue"
            } else {
                "grey"
            };
            html! { <Badge {color}>{format!("{w:.1}")}</Badge> }
        }),
        Column::new(
            "system",
            "System",
            |f: &Finding| html! { {f.asset_name.clone()} },
        ),
        Column::new(
            "stig",
            "STIG",
            |f: &Finding| html! { {f.stig_title.clone()} },
        ),
        Column::new("due", "Due", move |f: &Finding| match &f.due_date {
            Some(d) if !d.is_empty() => html! {
                <UiBox color={if tone == "red" { "text-status-error" } else { "inherit" }}>
                    {d.clone()}
                </UiBox>
            },
            _ => dash(),
        }),
        Column::new(
            "updated",
            "Last update",
            |f: &Finding| html! { {to_locale_string(&f.updated_at)} },
        ),
    ];
    html! {
        <Table<Finding>
            variant="container"
            items={p.items.clone()}
            track_by={Callback::from(|f: Finding| format!("{}:{}", f.checklist_id, f.rule_id))}
            {columns}
            header={html! {
                <Header counter={format!("({})", p.items.len())} variant="h2">
                    <Badge color={p.tone.clone()}>{p.title.clone()}</Badge>
                </Header>
            }}
            empty={html! {
                <UiBox text_align="center" padding="l" color="text-body-secondary">
                    {p.empty_text.clone()}
                </UiBox>
            }}
        />
    }
}

/// Build the URL the user lands on after picking a saved search. We keep
/// `view=myfindings` (so the top-level page doesn't change) and overwrite
/// every other key with whatever the saved-params string carries.
fn build_applied_search(saved_param_string: &str) -> Option<String> {
    let next = web_sys::UrlSearchParams::new_with_str(saved_param_string).ok()?;
    // Drop any view= that snuck into the saved params; we set it ourselves.
    next.delete("view");
    next.set("view", SAVED_PAGE);
    Some(format!("?{}", String::from(next.to_string())))
}

fn apply_saved_search(s: &SavedSearch) {
    let Some(url) = build_applied_search(&s.params) else {
        return;
    };
    if let Ok(history) = window().history() {
        let _ = history.push_state_with_url(&JsValue::NULL, "", Some(&url));
    }
    if let Ok(ev) = web_sys::PopStateEvent::new("popstate") {
        let _ = window().dispatch_event(&ev);
    }
}

#[derive(Properties, PartialEq)]
pub struct MyFindingsProps {}

#[function_component]
pub fn MyFindings(_props: &MyFindingsProps) -> Html {
    let findings = use_state(Vec::<Finding>::new);
    let loading = use_state(|| true);
    let error = use_state(|| None::<String>);

    // Filter state synced to the URL so links are shareable + saved searches
    // can round-trip cleanly. `sev` mirrors the dashboard's encoding.
    let (filters, set_filters) = use_url_state(vec![("sev", UrlVal::from(""))]);
    let severity_value = filters.str("sev");

    // ── Saved searches state ───────────────────────────────────────────────
    let saved_searches = use_state(Vec::<SavedSearch>::new);
    let saved_error = use_state(|| None::<String>);
    let save_modal_open = use_state(|| false);
    let manage_open = use_state(|| false);
    let new_search_name = use_state(String::new);
    let saving_search = use_state(|| false);
    let save_search_error = use_state(|| None::<String>);

    let refresh = {
        let findings = findings.clone();
        let loading = loading.clone();
        let error = error.clone();
        let severity_value = severity_value.clone();
        Callback::from(move |_: ()| {
            let findings = findings.clone();
            let loading = loading.clone();
            let error = error.clone();
            let mut qs = "status=open&assignee=me".to_string();
            if !severity_value.is_empty() {
                // URLSearchParams encoding: spaces become `+`.
                qs.push_str("&severity=");
                qs.push_str(&encode_uri_component(&severity_value).replace("%20", "+"));
            }
            loading.set(true);
            error.set(None);
            spawn_local(async move {
                match api_get::<Vec<Finding>>(&format!("/api/findings?{qs}")).await {
                    Ok(rows) => findings.set(rows),
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            });
        })
    };

    {
        let refresh = refresh.clone();
        use_effect_with(severity_value.clone(), move |_| refresh.emit(()));
    }

    let refresh_saved_searches = {
        let saved_searches = saved_searches.clone();
        let saved_error = saved_error.clone();
        Callback::from(move |_: ()| {
            let saved_searches = saved_searches.clone();
            let saved_error = saved_error.clone();
            spawn_local(async move {
                let path = format!(
                    "/api/saved-searches?page={}",
                    encode_uri_component(SAVED_PAGE)
                );
                match api_get::<Vec<SavedSearch>>(&path).await {
                    Ok(rows) => {
                        saved_searches.set(rows);
                        saved_error.set(None);
                    }
                    // Non-fatal — leave the picker empty so the rest of the page still works.
                    Err(e) => saved_error.set(Some(e)),
                }
            });
        })
    };

    {
        let refresh_saved_searches = refresh_saved_searches.clone();
        use_effect_with((), move |_| refresh_saved_searches.emit(()));
    }

    let save_current_view = {
        let new_search_name = new_search_name.clone();
        let save_search_error = save_search_error.clone();
        let saving_search = saving_search.clone();
        let save_modal_open = save_modal_open.clone();
        let refresh_saved_searches = refresh_saved_searches.clone();
        Callback::from(move |_: MouseEvent| {
            let name = new_search_name.trim().to_string();
            if name.is_empty() {
                save_search_error.set(Some("Name is required.".to_string()));
                return;
            }
            // Drop the page-routing `view` key — that's implicit in the
            // saved-search row's `page` column.
            let search = window().location().search().unwrap_or_default();
            let params = match web_sys::UrlSearchParams::new_with_str(&search) {
                Ok(live) => {
                    live.delete("view");
                    String::from(live.to_string())
                }
                Err(_) => String::new(),
            };
            saving_search.set(true);
            save_search_error.set(None);
            let new_search_name = new_search_name.clone();
            let save_search_error = save_search_error.clone();
            let saving_search = saving_search.clone();
            let save_modal_open = save_modal_open.clone();
            let refresh_saved_searches = refresh_saved_searches.clone();
            spawn_local(async move {
                let body =
                    serde_json::json!({ "page": SAVED_PAGE, "name": name, "params": params });
                let result = match api_fetch_json("POST", "/api/saved-searches", &body).await {
                    Ok(res) if res.ok() => Ok(()),
                    Ok(res) => {
                        let status = res.status();
                        let text = res.text().await.unwrap_or_default();
                        if status == 409 || text.contains("409") {
                            Err("A saved search with that name already exists.".to_string())
                        } else if text.is_empty() {
                            Err(status.to_string())
                        } else {
                            Err(text)
                        }
                    }
                    Err(e) => Err(e),
                };
                match result {
                    Ok(()) => {
                        save_modal_open.set(false);
                        new_search_name.set(String::new());
                        refresh_saved_searches.emit(());
                    }
                    Err(msg) => save_search_error.set(Some(msg)),
                }
                saving_search.set(false);
            });
        })
    };

    let delete_saved_search = {
        let refresh_saved_searches = refresh_saved_searches.clone();
        Callback::from(move |id: String| {
            let refresh_saved_searches = refresh_saved_searches.clone();
            spawn_local(async move {
                match api_fetch("DELETE", &format!("/api/saved-searches/{id}")).await {
                    Ok(res) if res.ok() || res.status() == 204 => refresh_saved_searches.emit(()),
                    _ => {}
                }
            });
        })
    };

    if *loading {
        return html! {
            <UiBox padding="xxl" text_align="center">
                <StatusIndicator kind="loading">{"Loading my findings"}</StatusIndicator>
            </UiBox>
        };
    }

    let (mut overdue, mut due_soon, mut open) = (Vec::new(), Vec::new(), Vec::new());
    {
        let today = js_sys::Date::new_0();
        today.set_hours(0);
        today.set_minutes(0);
        today.set_seconds(0);
        today.set_milliseconds(0);
        let cutoff = js_sys::Date::new(&JsValue::from_f64(today.get_time()));
        cutoff.set_date(cutoff.get_date() + DUE_SOON_DAYS);
        let (today, cutoff) = (today.get_time(), cutoff.get_time());
        for f in findings.iter() {
            match bucket_of(f, today, cutoff) {
                Bucket::Overdue => overdue.push(f.clone()),
                Bucket::DueSoon => due_soon.push(f.clone()),
                Bucket::Open => open.push(f.clone()),
            }
        }
    }

    let saved_options: Vec<SelectOption> = saved_searches
        .iter()
        .map(|s| SelectOption::new(s.id.clone(), s.name.clone()).description(s.params_label()))
        .collect();
    let has_saved = !saved_searches.is_empty();
    let saved_placeholder = if has_saved {
        "Apply saved search"
    } else {
        "No saved searches yet"
    };

    let on_severity =
        set_filters.reform(|o: SelectOption| vec![("sev", UrlVal::from(o.value.to_string()))]);
    let on_apply_saved = {
        let saved_searches = saved_searches.clone();
        Callback::from(move |o: SelectOption| {
            if let Some(found) = saved_searches.iter().find(|s| s.id == o.value.as_str()) {
                apply_saved_search(found);
            }
        })
    };
    let open_save_modal = {
        let new_search_name = new_search_name.clone();
        let save_search_error = save_search_error.clone();
        let save_modal_open = save_modal_open.clone();
        Callback::from(move |_: MouseEvent| {
            new_search_name.set(String::new());
            save_search_error.set(None);
            save_modal_open.set(true);
        })
    };
    let close_save_modal = {
        let save_modal_open = save_modal_open.clone();
        Callback::from(move |_: ()| save_modal_open.set(false))
    };
    let close_manage = {
        let manage_open = manage_open.clone();
        Callback::from(move |_: ()| manage_open.set(false))
    };

    let count = findings.len();
    html! {
        <UiBox padding="m">
            <SpaceBetween direction="vertical" size="l">
                <Header
                    variant="h1"
                    description={html! { {format!("{count} open finding{} assigned to you", if count == 1 { "" } else { "s" })} }}
                    actions={html! {
                        <Button icon_name="refresh" onclick={refresh.reform(|_: MouseEvent| ())}>
                            {"Refresh"}
                        </Button>
                    }}
                >
                    {"My findings"}
                </Header>

                if let Some(e) = &*error {
                    <Alert kind="error">{e.clone()}</Alert>
                }
                if let Some(e) = &*saved_error {
                    <Alert kind="warning" header="Saved searches">{e.clone()}</Alert>
                }

                <SpaceBetween direction="horizontal" size="m">
                    <Select
                        selected={AttrValue::from(severity_value.clone())}
                        options={severity_options()}
                        on_change={on_severity}
                        aria_label="Filter by severity"
                    />
                    // Cloudscape names the trigger "<ariaLabel> <placeholder>";
                    // the kit only appends the selected label, so spell it out.
                    <Select
                        options={saved_options}
                        on_change={on_apply_saved}
                        placeholder={saved_placeholder}
                        disabled={!has_saved}
                        aria_label="Apply a saved search"
                    />
                    <Button onclick={open_save_modal}>{"Save current view"}</Button>
                    <Button
                        disabled={!has_saved}
                        onclick={{ let manage_open = manage_open.clone(); move |_| manage_open.set(true) }}
                    >
                        {"Manage…"}
                    </Button>
                </SpaceBetween>

                if count == 0 {
                    <UiBox padding="xxl" text_align="center">
                        <StatusIndicator kind="success">
                            {"Nothing assigned to you right now."}
                        </StatusIndicator>
                    </UiBox>
                } else {
                    <SpaceBetween direction="vertical" size="l">
                        if !overdue.is_empty() {
                            <FindingsTable title="Overdue" tone="red" items={overdue} empty_text="None overdue." />
                        }
                        if !due_soon.is_empty() {
                            <FindingsTable
                                title={format!("Due in the next {DUE_SOON_DAYS} days")}
                                tone="blue"
                                items={due_soon}
                                empty_text="None due soon."
                            />
                        }
                        if !open.is_empty() {
                            <FindingsTable title="Open (no urgent due)" tone="grey" items={open} empty_text="None." />
                        }
                    </SpaceBetween>
                }

                // Save current view modal
                <Modal
                    visible={*save_modal_open}
                    on_dismiss={close_save_modal.clone()}
                    header="Save current view"
                    footer={html! {
                        <UiBox float="right">
                            <SpaceBetween direction="horizontal" size="xs">
                                <Button variant="link" onclick={close_save_modal.reform(|_: MouseEvent| ())}>
                                    {"Cancel"}
                                </Button>
                                <Button variant="primary" loading={*saving_search} onclick={save_current_view}>
                                    {"Save"}
                                </Button>
                            </SpaceBetween>
                        </UiBox>
                    }}
                >
                    <SpaceBetween direction="vertical" size="m">
                        <UiBox variant="p" color="text-body-secondary">
                            {"Capture the current filter set as a named saved search. Picking it later restores the same URL parameters."}
                        </UiBox>
                        <FormField label="Name">
                            <Input
                                value={(*new_search_name).clone()}
                                on_change={{ let n = new_search_name.clone(); move |v: String| n.set(v) }}
                                placeholder="e.g. CAT I only"
                                auto_focus=true
                            />
                        </FormField>
                        if let Some(e) = &*save_search_error {
                            <Alert kind="error">{e.clone()}</Alert>
                        }
                    </SpaceBetween>
                </Modal>

                // Manage saved searches modal
                <Modal
                    visible={*manage_open}
                    on_dismiss={close_manage.clone()}
                    header="Manage saved searches"
                    footer={html! {
                        <UiBox float="right">
                            <Button onclick={close_manage.reform(|_: MouseEvent| ())}>{"Close"}</Button>
                        </UiBox>
                    }}
                >
                    if !has_saved {
                        <UiBox color="text-body-secondary">{"No saved searches yet."}</UiBox>
                    } else {
                        <SpaceBetween direction="vertical" size="xs">
                            { for saved_searches.iter().map(|s| {
                                let ondelete = {
                                    let id = s.id.clone();
                                    delete_saved_search.reform(move |_: MouseEvent| id.clone())
                                };
                                html! {
                                    <UiBox key={s.id.clone()} padding_vertical="xxs">
                                        <SpaceBetween direction="horizontal" size="m">
                                            <div style="flex:1;">
                                                <strong>{s.name.clone()}</strong>{" "}
                                                <UiBox variant="small" color="text-body-secondary" display="inline">
                                                    {s.params_label()}
                                                </UiBox>
                                            </div>
                                            <Button variant="normal" onclick={ondelete}>{"Delete"}</Button>
                                        </SpaceBetween>
                                    </UiBox>
                                }
                            }) }
                        </SpaceBetween>
                    }
                </Modal>
            </SpaceBetween>
        </UiBox>
    }
}

#[cfg(test)]
mod severity_badge_tests {
    use super::*;

    #[test]
    fn maps_cat_levels_to_severity_classes() {
        assert_eq!(severity_badge("CAT I"), "severity-high");
        assert_eq!(severity_badge("CAT II"), "severity-medium");
        assert_eq!(severity_badge("CAT III"), "severity-low");
        assert_eq!(severity_badge("bogus"), "grey");
    }
}
