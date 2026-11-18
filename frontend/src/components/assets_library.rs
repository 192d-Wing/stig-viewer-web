//! Systems (assets) list page: table with tag/group filters, create/edit/
//! delete modals and CSV import. Also hosts the asset-detail, checklist and
//! comparison sub-views.

use std::cell::Cell;
use std::collections::HashSet;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use yew::prelude::*;

use crate::api::{api_fetch, api_get, api_json, api_upload_raw};
use crate::auth::use_current_user;
use crate::components::asset_compare::AssetCompare;
use crate::components::asset_detail::AssetDetail;
use crate::components::checklist_view::ChecklistView;
use crate::hooks::{use_url_state, UrlVal};
use crate::ui::*;
use crate::util::{console_error, encode_uri_component, spawn_local, to_locale_string};

const CLASSIFICATIONS: [(&str, &str); 4] = [
    ("unclassified", "Unclassified"),
    ("cui", "CUI"),
    ("secret", "Secret"),
    ("top-secret", "Top Secret"),
];

fn classification_badge(value: &str) -> &'static str {
    match value {
        "unclassified" => "green",
        "cui" => "blue",
        "secret" | "top-secret" => "red",
        _ => "grey",
    }
}

fn classification_label(value: &str) -> String {
    CLASSIFICATIONS
        .iter()
        .find(|(v, _)| *v == value)
        .map(|(_, l)| l.to_string())
        .unwrap_or_else(|| value.to_string())
}

/// `—` when the string is empty.
fn or_dash(s: &str) -> String {
    if s.is_empty() {
        "—".to_string()
    } else {
        s.to_string()
    }
}

/// An asset as returned by GET /api/assets (summary: no `description`) or
/// GET /api/assets/:id (full row: no `ownerName`).
#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Asset {
    id: String,
    name: String,
    hostname: String,
    description: Option<String>,
    classification: String,
    owner_id: String,
    owner_name: String,
    updated_at: String,
    tags: Option<Vec<String>>,
    runbook: Option<String>,
}

impl Asset {
    fn tags(&self) -> &[String] {
        self.tags.as_deref().unwrap_or_default()
    }
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Group {
    id: String,
    name: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct GroupMember {
    asset_id: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ImportRow {
    row_number: usize,
    name: String,
    hostname: String,
    classification: String,
    tags: Vec<String>,
    status: String,
    error: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ImportResponse {
    rows: Vec<ImportRow>,
    created_count: usize,
}

/// Create/edit form; serialised as-is for POST /api/assets and
/// PUT /api/assets/:id.
#[derive(Clone, PartialEq, Serialize)]
struct AssetForm {
    name: String,
    hostname: String,
    description: String,
    classification: String,
    tags: Vec<String>,
    runbook: String,
}

impl Default for AssetForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            hostname: String::new(),
            description: String::new(),
            classification: "unclassified".into(),
            tags: vec![],
            runbook: String::new(),
        }
    }
}

enum FormAction {
    Reset(AssetForm),
    Name(String),
    Hostname(String),
    Description(String),
    Runbook(String),
    Classification(String),
    AddTag(String),
    RemoveTag(usize),
}

impl Reducible for AssetForm {
    type Action = FormAction;

    fn reduce(self: Rc<Self>, action: FormAction) -> Rc<Self> {
        let mut f = (*self).clone();
        match action {
            FormAction::Reset(next) => f = next,
            FormAction::Name(v) => f.name = v,
            FormAction::Hostname(v) => f.hostname = v,
            FormAction::Description(v) => f.description = v,
            FormAction::Runbook(v) => f.runbook = v,
            FormAction::Classification(v) => f.classification = v,
            FormAction::AddTag(t) => {
                if f.tags.contains(&t) {
                    return self;
                }
                f.tags.push(t);
            }
            FormAction::RemoveTag(idx) => {
                if idx < f.tags.len() {
                    f.tags.remove(idx);
                }
            }
        }
        Rc::new(f)
    }
}

#[derive(Clone, PartialEq)]
enum View {
    List,
    Asset { id: String },
    Checklist { id: String, asset_id: String },
    Compare,
}

/// Which flavour of the shared create/edit modal is open.
#[derive(Clone, PartialEq)]
enum ModalMode {
    Create,
    Edit { asset_id: String },
}

#[derive(Clone, Copy, PartialEq)]
enum ImportStep {
    /// Choose a file (which triggers the dry-run preview).
    Pick,
    /// Review parsed rows, click Import to commit.
    Preview,
}

/// POST the CSV to the import endpoint. Errors carry the response body text.
async fn import_request(file: &web_sys::File, dry_run: bool) -> Result<ImportResponse, String> {
    let res = api_upload_raw(&format!("/api/assets/import?dry_run={dry_run}"), file).await?;
    if !res.ok() {
        let status = res.status();
        let text = match res.text().await {
            Ok(t) => t,
            Err(_) => res.status_text(),
        };
        return Err(if text.is_empty() {
            status.to_string()
        } else {
            text
        });
    }
    res.json::<ImportResponse>()
        .await
        .map_err(|e| e.to_string())
}

fn locale_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let n =
        js_sys::JsString::from(a).locale_compare(b, &js_sys::Array::new(), &js_sys::Object::new());
    n.cmp(&0)
}

#[derive(Properties, PartialEq)]
pub struct AssetsLibraryProps {}

#[function_component]
pub fn AssetsLibrary(_props: &AssetsLibraryProps) -> Html {
    let current_user = use_current_user();

    let view = use_state(|| View::List);
    // Bumped after the edit modal saves successfully so a mounted
    // `AssetDetail` re-fetches the asset (and any new runbook content).
    // Used as the `key` on `AssetDetail` below.
    let detail_refresh_key = use_state(|| 0u32);

    let assets = use_state(Vec::<Asset>::new);
    let loading = use_state(|| true);
    let error = use_state(|| None::<String>);

    let modal = use_state(|| None::<ModalMode>);
    let form = use_reducer(AssetForm::default);
    let tag_draft = use_state(String::new);
    let submitting = use_state(|| false);
    let submit_error = use_state(|| None::<String>);

    let delete_target = use_state(|| None::<Asset>);

    // Active filters live in the URL. `tag` is CSV with AND semantics;
    // `group` is a single group id and narrows the list to that group's
    // membership. Both are independent and stack with each other.
    let (url_state, set_url_state) = use_url_state(vec![
        ("tag", UrlVal::List(vec![])),
        ("group", UrlVal::from("")),
    ]);
    let active_tags = url_state.list("tag");
    let active_group = url_state.str("group");

    // Available groups for the filter Select. Loaded once on mount —
    // changes from the Groups page are rare and a refresh button isn't
    // worth the toolbar real estate.
    let groups = use_state(Vec::<Group>::new);
    let group_member_ids = use_state(|| None::<HashSet<String>>);

    {
        let groups = groups.clone();
        use_effect_with((), move |_| {
            spawn_local(async move {
                // Non-fatal on error — groups filter just stays empty.
                groups.set(
                    api_get::<Vec<Group>>("/api/asset-groups")
                        .await
                        .unwrap_or_default(),
                );
            });
        });
    }

    // When a group is selected, fetch its membership and project down to a
    // set of asset ids for fast filtering. Falls back to "show nothing"
    // (rather than "show everything") if the fetch errors so the user
    // notices a stale selection rather than getting silently misled.
    {
        let group_member_ids = group_member_ids.clone();
        use_effect_with(active_group.clone(), move |group| {
            let cancelled = Rc::new(Cell::new(false));
            if group.is_empty() {
                group_member_ids.set(None);
            } else {
                let path = format!("/api/asset-groups/{group}/members");
                let cancelled = cancelled.clone();
                spawn_local(async move {
                    let rows = api_get::<Vec<GroupMember>>(&path).await.unwrap_or_default();
                    if !cancelled.get() {
                        group_member_ids.set(Some(rows.into_iter().map(|r| r.asset_id).collect()));
                    }
                });
            }
            move || cancelled.set(true)
        });
    }

    let all_tags: Vec<String> = {
        let mut set: Vec<String> = assets
            .iter()
            .flat_map(|a| a.tags().iter().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        set.sort_by(|a, b| locale_compare(a, b));
        set
    };
    let filtered_assets: Vec<Asset> = assets
        .iter()
        .filter(|a| active_tags.iter().all(|t| a.tags().contains(t)))
        .filter(|a| match (&*group_member_ids, active_group.is_empty()) {
            (Some(ids), false) => ids.contains(&a.id),
            _ => true,
        })
        .cloned()
        .collect();

    // Re-fetch the list. Returned as a future so callers can await it
    // before doing follow-up work.
    let refresh = {
        let assets = assets.clone();
        let loading = loading.clone();
        let error = error.clone();
        move || {
            let assets = assets.clone();
            let loading = loading.clone();
            let error = error.clone();
            async move {
                loading.set(true);
                error.set(None);
                match api_get::<Vec<Asset>>("/api/assets").await {
                    Ok(rows) => assets.set(rows),
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            }
        }
    };

    {
        let refresh = refresh.clone();
        use_effect_with((), move |_| spawn_local(refresh()));
    }

    // CSV import modal state.
    let import_open = use_state(|| false);
    let import_step = use_state(|| ImportStep::Pick);
    let import_file = use_state(|| None::<web_sys::File>);
    let import_preview = use_state(|| None::<ImportResponse>);
    let import_busy = use_state(|| false);
    let import_error = use_state(|| None::<String>);
    let import_success = use_state(|| None::<ImportResponse>);

    let reset_import = {
        let import_open = import_open.clone();
        let import_step = import_step.clone();
        let import_file = import_file.clone();
        let import_preview = import_preview.clone();
        let import_busy = import_busy.clone();
        let import_error = import_error.clone();
        let import_success = import_success.clone();
        move |open: bool| {
            import_open.set(open);
            import_step.set(ImportStep::Pick);
            import_file.set(None);
            import_preview.set(None);
            import_error.set(None);
            import_success.set(None);
            import_busy.set(false);
        }
    };
    let close_import = {
        let reset_import = reset_import.clone();
        Callback::from(move |_: ()| reset_import(false))
    };
    let open_import = Callback::from(move |_: MouseEvent| reset_import(true));

    let on_import_file_change = {
        let import_step = import_step.clone();
        let import_file = import_file.clone();
        let import_preview = import_preview.clone();
        let import_busy = import_busy.clone();
        let import_error = import_error.clone();
        let import_success = import_success.clone();
        Callback::from(move |e: Event| {
            let file = e
                .target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                .and_then(|i| i.files())
                .and_then(|l| l.get(0));
            let Some(file) = file else {
                return;
            };
            import_file.set(Some(file.clone()));
            import_preview.set(None);
            import_error.set(None);
            import_success.set(None);
            import_busy.set(true);
            let import_step = import_step.clone();
            let import_preview = import_preview.clone();
            let import_busy = import_busy.clone();
            let import_error = import_error.clone();
            spawn_local(async move {
                match import_request(&file, true).await {
                    Ok(data) => {
                        import_preview.set(Some(data));
                        import_step.set(ImportStep::Preview);
                    }
                    Err(e) => import_error.set(Some(e)),
                }
                import_busy.set(false);
            });
        })
    };

    let commit_import = {
        let import_file = import_file.clone();
        let import_busy = import_busy.clone();
        let import_error = import_error.clone();
        let import_success = import_success.clone();
        let close_import = close_import.clone();
        let refresh = refresh.clone();
        Callback::from(move |_: MouseEvent| {
            let Some(file) = (*import_file).clone() else {
                return;
            };
            import_busy.set(true);
            import_error.set(None);
            let import_busy = import_busy.clone();
            let import_error = import_error.clone();
            let import_success = import_success.clone();
            let close_import = close_import.clone();
            let refresh = refresh.clone();
            spawn_local(async move {
                match import_request(&file, false).await {
                    Ok(data) => {
                        import_success.set(Some(data));
                        refresh().await;
                        gloo_timers::callback::Timeout::new(800, move || close_import.emit(()))
                            .forget();
                    }
                    Err(e) => import_error.set(Some(e)),
                }
                import_busy.set(false);
            });
        })
    };

    // Data URL for the "Download template" link. Inline so we don't need a
    // backend route or static asset.
    let template_href = use_memo((), |_| {
        let csv = "name,hostname,description,classification,tags\n\
                   web-1,web-1.example.com,Sample web host,unclassified,production;public-facing\n";
        format!("data:text/csv;charset=utf-8,{}", encode_uri_component(csv))
    });

    let open_create = {
        let form = form.clone();
        let tag_draft = tag_draft.clone();
        let submit_error = submit_error.clone();
        let modal = modal.clone();
        Callback::from(move |_: MouseEvent| {
            form.dispatch(FormAction::Reset(AssetForm::default()));
            tag_draft.set(String::new());
            submit_error.set(None);
            modal.set(Some(ModalMode::Create));
        })
    };

    let open_edit = {
        let form = form.clone();
        let tag_draft = tag_draft.clone();
        let submit_error = submit_error.clone();
        let modal = modal.clone();
        Callback::from(move |asset: Asset| {
            form.dispatch(FormAction::Reset(AssetForm {
                name: asset.name.clone(),
                hostname: asset.hostname.clone(),
                description: asset.description.clone().unwrap_or_default(),
                classification: asset.classification.clone(),
                tags: asset.tags().to_vec(),
                runbook: asset.runbook.clone().unwrap_or_default(),
            }));
            tag_draft.set(String::new());
            submit_error.set(None);
            modal.set(Some(ModalMode::Edit { asset_id: asset.id }));
        })
    };

    let close_modal = {
        let modal = modal.clone();
        let tag_draft = tag_draft.clone();
        let submit_error = submit_error.clone();
        Callback::from(move |_: ()| {
            modal.set(None);
            tag_draft.set(String::new());
            submit_error.set(None);
        })
    };

    let on_tag_key_down = {
        let form = form.clone();
        let tag_draft = tag_draft.clone();
        Callback::from(move |e: KeyboardEvent| {
            if e.key() == "Enter" {
                e.prevent_default();
                let t = tag_draft.trim().to_string();
                if t.is_empty() {
                    return;
                }
                form.dispatch(FormAction::AddTag(t));
                tag_draft.set(String::new());
            }
        })
    };

    let submit = {
        let form = form.clone();
        let modal = modal.clone();
        let tag_draft = tag_draft.clone();
        let submitting = submitting.clone();
        let submit_error = submit_error.clone();
        let detail_refresh_key = detail_refresh_key.clone();
        let refresh = refresh.clone();
        Callback::from(move |_: MouseEvent| {
            let mut body = (*form).clone();
            if body.name.trim().is_empty() {
                submit_error.set(Some("Name is required.".into()));
                return;
            }
            let Some(mode) = (*modal).clone() else {
                return;
            };
            // Capture any tag the user typed but didn't press Enter on.
            let pending = tag_draft.trim().to_string();
            if !pending.is_empty() && !body.tags.contains(&pending) {
                body.tags.push(pending);
            }
            submitting.set(true);
            submit_error.set(None);
            let modal = modal.clone();
            let tag_draft = tag_draft.clone();
            let submitting = submitting.clone();
            let submit_error = submit_error.clone();
            let detail_refresh_key = detail_refresh_key.clone();
            let refresh = refresh.clone();
            spawn_local(async move {
                let res = match &mode {
                    ModalMode::Create => {
                        api_json::<serde_json::Value, _>("/api/assets", "POST", Some(&body)).await
                    }
                    ModalMode::Edit { asset_id } => {
                        api_json::<serde_json::Value, _>(
                            &format!("/api/assets/{asset_id}"),
                            "PUT",
                            Some(&body),
                        )
                        .await
                    }
                };
                match res {
                    Ok(_) => {
                        modal.set(None);
                        tag_draft.set(String::new());
                        refresh().await;
                        // If an AssetDetail page is open, force it to re-fetch so any
                        // edits made via this modal (runbook content, classification,
                        // tags, …) are immediately visible without bouncing back to
                        // the list.
                        detail_refresh_key.set(*detail_refresh_key + 1);
                    }
                    Err(e) => submit_error.set(Some(e)),
                }
                submitting.set(false);
            });
        })
    };

    let confirm_delete = {
        let delete_target = delete_target.clone();
        let submit_error = submit_error.clone();
        let refresh = refresh.clone();
        Callback::from(move |_: MouseEvent| {
            let Some(target) = (*delete_target).clone() else {
                return;
            };
            let delete_target = delete_target.clone();
            let submit_error = submit_error.clone();
            let refresh = refresh.clone();
            spawn_local(async move {
                match api_fetch("DELETE", &format!("/api/assets/{}", target.id)).await {
                    Ok(res) if res.ok() || res.status() == 204 => {
                        delete_target.set(None);
                        refresh().await;
                    }
                    Ok(res) => submit_error.set(Some(format!("Delete failed: {}", res.status()))),
                    Err(e) => submit_error.set(Some(e)),
                }
            });
        })
    };

    // The shared edit modal markup. Rendered both on the list view and
    // the asset-detail view (the Edit button on AssetDetail opens it
    // without bouncing the user back to the list).
    let is_edit = matches!(&*modal, Some(ModalMode::Edit { .. }));
    let selected_classification = if CLASSIFICATIONS
        .iter()
        .any(|(v, _)| *v == form.classification)
    {
        form.classification.clone()
    } else {
        CLASSIFICATIONS[0].0.to_string()
    };
    let field = |action: fn(String) -> FormAction| {
        let form = form.clone();
        Callback::from(move |v: String| form.dispatch(action(v)))
    };
    let close_modal_click = close_modal.reform(|_: MouseEvent| ());
    let edit_modal = html! {
        <Modal
            visible={modal.is_some()}
            on_dismiss={close_modal.clone()}
            header={html! { {if is_edit { "Edit system" } else { "Add system" }} }}
            footer={html! {
                <UiBox float="right">
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button variant="link" onclick={close_modal_click}>{"Cancel"}</Button>
                        <Button variant="primary" loading={*submitting} onclick={submit}>
                            {if is_edit { "Save" } else { "Create" }}
                        </Button>
                    </SpaceBetween>
                </UiBox>
            }}
        >
            <SpaceBetween direction="vertical" size="m">
                <FormField label={html! { {"Name"} }} description={html! { {"Friendly identifier, e.g. web-prod-01"} }}>
                    <Input value={form.name.clone()} on_change={field(FormAction::Name)} auto_focus=true />
                </FormField>
                <FormField label={html! { {"Hostname"} }} description={html! { {"DNS name or IP"} }}>
                    <Input value={form.hostname.clone()} on_change={field(FormAction::Hostname)} />
                </FormField>
                <FormField label={html! { {"Description"} }}>
                    <Textarea value={form.description.clone()} on_change={field(FormAction::Description)} rows={3} />
                </FormField>
                <FormField
                    label={html! { {"Runbook"} }}
                    description={html! { {"Free-form markdown — operational notes, escalation contacts, known issues."} }}
                >
                    <div data-testid="runbook-textarea">
                        <Textarea value={form.runbook.clone()} on_change={field(FormAction::Runbook)} rows={8} />
                    </div>
                </FormField>
                <FormField label={html! { {"Classification"} }}>
                    <Select
                        selected={AttrValue::from(selected_classification)}
                        on_change={{
                            let form = form.clone();
                            Callback::from(move |o: SelectOption| {
                                form.dispatch(FormAction::Classification(o.value.to_string()))
                            })
                        }}
                        options={CLASSIFICATIONS.iter().map(|(v, l)| SelectOption::new(*v, *l)).collect::<Vec<_>>()}
                    />
                </FormField>
                <FormField
                    label={html! { {"Tags"} }}
                    description={html! { {"Press Enter to add. Use tags to group systems (e.g. production, pii)."} }}
                >
                    <SpaceBetween direction="vertical" size="xs">
                        <Input
                            value={(*tag_draft).clone()}
                            on_change={{
                                let tag_draft = tag_draft.clone();
                                Callback::from(move |v: String| tag_draft.set(v))
                            }}
                            on_key_down={on_tag_key_down}
                            placeholder="Add tag…"
                        />
                        if !form.tags.is_empty() {
                            <TokenGroup
                                items={form.tags.iter().cloned().map(AttrValue::from).collect::<Vec<_>>()}
                                on_dismiss={{
                                    let form = form.clone();
                                    Callback::from(move |idx: usize| form.dispatch(FormAction::RemoveTag(idx)))
                                }}
                            />
                        }
                    </SpaceBetween>
                </FormField>
                if let Some(e) = &*submit_error {
                    <Alert kind="error">{e.clone()}</Alert>
                }
            </SpaceBetween>
        </Modal>
    };

    let back_to_list = {
        let view = view.clone();
        Callback::from(move |_: ()| view.set(View::List))
    };

    match &*view {
        View::Asset { id } => {
            let on_open_checklist = {
                let view = view.clone();
                let asset_id = id.clone();
                Callback::from(move |cid: String| {
                    view.set(View::Checklist {
                        id: cid,
                        asset_id: asset_id.clone(),
                    })
                })
            };
            // AssetDetail hands over the asset JSON it fetched; turn it into
            // the edit-modal form state.
            let on_edit = Callback::from(move |value: serde_json::Value| {
                match serde_json::from_value::<Asset>(value) {
                    Ok(asset) => open_edit.emit(asset),
                    Err(e) => console_error(&format!("cannot edit asset: {e}")),
                }
            });
            return html! {
                <>
                    <AssetDetail
                        key={format!("{id}-{}", *detail_refresh_key)}
                        asset_id={id.clone()}
                        on_back={back_to_list}
                        {on_open_checklist}
                        {on_edit}
                    />
                    {edit_modal}
                </>
            };
        }
        View::Checklist { id, asset_id } => {
            let on_back = {
                let view = view.clone();
                let asset_id = asset_id.clone();
                Callback::from(move |_: ()| {
                    view.set(View::Asset {
                        id: asset_id.clone(),
                    })
                })
            };
            return html! { <ChecklistView checklist_id={id.clone()} {on_back} /> };
        }
        View::Compare => {
            return html! { <AssetCompare on_back={back_to_list} /> };
        }
        View::List => {}
    }

    let columns: Vec<Column<Asset>> = vec![
        Column::new("name", "Name", {
            let view = view.clone();
            move |a: &Asset| {
                let view = view.clone();
                let id = a.id.clone();
                html! {
                    <Button variant="inline-link" onclick={move |_| view.set(View::Asset { id: id.clone() })}>
                        {a.name.clone()}
                    </Button>
                }
            }
        }),
        Column::new(
            "hostname",
            "Hostname",
            |a: &Asset| html! { {or_dash(&a.hostname)} },
        ),
        Column::new("classification", "Classification", |a: &Asset| {
            html! {
                <Badge color={classification_badge(&a.classification)}>
                    {classification_label(&a.classification)}
                </Badge>
            }
        }),
        Column::new("tags", "Tags", |a: &Asset| {
            if a.tags().is_empty() {
                html! { {"—"} }
            } else {
                html! {
                    <SpaceBetween direction="horizontal" size="xxs">
                        { for a.tags().iter().map(|t| html! {
                            <Badge key={t.clone()} color="grey">{t.clone()}</Badge>
                        }) }
                    </SpaceBetween>
                }
            }
        }),
        Column::new(
            "owner",
            "Owner",
            |a: &Asset| html! { {a.owner_name.clone()} },
        ),
        Column::new(
            "updated",
            "Updated",
            |a: &Asset| html! { {to_locale_string(&a.updated_at)} },
        ),
        Column::new("actions", "", {
            let current_user_id = current_user.map(|u| u.id);
            let open_edit = open_edit.clone();
            let delete_target = delete_target.clone();
            move |a: &Asset| {
                let is_owner = current_user_id.as_deref() == Some(a.owner_id.as_str());
                let on_edit = {
                    let open_edit = open_edit.clone();
                    let a = a.clone();
                    Callback::from(move |_: MouseEvent| open_edit.emit(a.clone()))
                };
                let on_delete = {
                    let delete_target = delete_target.clone();
                    let a = a.clone();
                    Callback::from(move |_: MouseEvent| delete_target.set(Some(a.clone())))
                };
                html! {
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button variant="inline-link" disabled={!is_owner} onclick={on_edit}>{"Edit"}</Button>
                        <Button variant="inline-link" disabled={!is_owner} onclick={on_delete}>{"Delete"}</Button>
                    </SpaceBetween>
                }
            }
        }),
    ];

    let set_tags = |tags: Vec<String>| {
        let set_url_state = set_url_state.clone();
        Callback::from(move |_: MouseEvent| {
            set_url_state.emit(vec![("tag", UrlVal::List(tags.clone()))])
        })
    };
    let set_group = {
        let set_url_state = set_url_state.clone();
        move |group: String| set_url_state.emit(vec![("group", UrlVal::Str(group))])
    };

    let filter = if all_tags.is_empty() && groups.is_empty() {
        Html::default()
    } else {
        // An unknown group id in the URL shows as "All groups".
        let selected_group = if groups.iter().any(|g| g.id == active_group) {
            active_group.clone()
        } else {
            String::new()
        };
        let group_options: Vec<SelectOption> = std::iter::once(SelectOption::new("", "All groups"))
            .chain(
                groups
                    .iter()
                    .map(|g| SelectOption::new(g.id.clone(), g.name.clone())),
            )
            .collect();
        html! {
            <SpaceBetween direction="vertical" size="xs">
                if !all_tags.is_empty() {
                    <SpaceBetween direction="horizontal" size="xs">
                        <UiBox variant="span" color="text-status-inactive">{"Filter by tag:"}</UiBox>
                        { for all_tags.iter().map(|t| {
                            let active = active_tags.contains(t);
                            let next: Vec<String> = if active {
                                active_tags.iter().filter(|x| *x != t).cloned().collect()
                            } else {
                                active_tags.iter().cloned().chain(std::iter::once(t.clone())).collect()
                            };
                            html! {
                                <Button key={t.clone()} variant={if active { "primary" } else { "normal" }}
                                        onclick={set_tags(next)}>
                                    {t.clone()}
                                </Button>
                            }
                        }) }
                        if !active_tags.is_empty() {
                            <Button variant="inline-link" onclick={set_tags(vec![])}>{"Clear"}</Button>
                        }
                    </SpaceBetween>
                }
                if !groups.is_empty() {
                    <SpaceBetween direction="horizontal" size="xs">
                        <UiBox variant="span" color="text-status-inactive">{"Filter by group:"}</UiBox>
                        <div style="min-width: 240px;" data-testid="asset-group-filter">
                            <Select
                                selected={AttrValue::from(selected_group)}
                                on_change={{
                                    let set_group = set_group.clone();
                                    Callback::from(move |o: SelectOption| set_group(o.value.to_string()))
                                }}
                                options={group_options}
                            />
                        </div>
                        if !active_group.is_empty() {
                            <Button variant="inline-link" onclick={{
                                let set_group = set_group.clone();
                                Callback::from(move |_: MouseEvent| set_group(String::new()))
                            }}>
                                {"Clear"}
                            </Button>
                        }
                    </SpaceBetween>
                }
            </SpaceBetween>
        }
    };

    let counter = if !active_tags.is_empty() || !active_group.is_empty() {
        format!("({}/{})", filtered_assets.len(), assets.len())
    } else {
        format!("({})", assets.len())
    };

    let preview_rows: &[ImportRow] = import_preview
        .as_ref()
        .map(|p| p.rows.as_slice())
        .unwrap_or_default();
    let ok_rows = preview_rows.iter().filter(|r| r.status == "ok").count();
    let error_rows = preview_rows.iter().filter(|r| r.status == "error").count();
    let import_columns: Vec<Column<ImportRow>> = vec![
        Column::new("row", "Row", |r: &ImportRow| html! { {r.row_number} }),
        Column::new("name", "Name", |r: &ImportRow| html! { {or_dash(&r.name)} }),
        Column::new(
            "hostname",
            "Hostname",
            |r: &ImportRow| html! { {or_dash(&r.hostname)} },
        ),
        Column::new("classification", "Classification", |r: &ImportRow| {
            html! { {or_dash(&r.classification)} }
        }),
        Column::new(
            "tags",
            "Tags",
            |r: &ImportRow| html! { {or_dash(&r.tags.join(", "))} },
        ),
        Column::new("status", "Status", |r: &ImportRow| {
            let color = match r.status.as_str() {
                "ok" => "green",
                "skipped" => "grey",
                _ => "red",
            };
            html! {
                <Badge {color} testid={format!("import-status-{}", r.row_number)}>{r.status.clone()}</Badge>
            }
        }),
        Column::new(
            "error",
            "Note",
            |r: &ImportRow| html! { {r.error.clone().unwrap_or_default()} },
        ),
    ];

    let close_import_click = close_import.reform(|_: MouseEvent| ());
    let close_delete = {
        let delete_target = delete_target.clone();
        Callback::from(move |_: ()| delete_target.set(None))
    };

    html! {
        <>
            <Table<Asset>
                variant="full-page"
                sticky_header=true
                items={filtered_assets}
                {columns}
                loading={*loading}
                loading_text="Loading systems"
                {filter}
                empty={html! {
                    <UiBox text_align="center" padding="l">
                        <SpaceBetween direction="vertical" size="m">
                            <StatusIndicator kind="info">{"No systems yet"}</StatusIndicator>
                            <Button variant="primary" onclick={open_create.clone()}>
                                {"Add your first system"}
                            </Button>
                        </SpaceBetween>
                    </UiBox>
                }}
                header={html! {
                    <Header
                        {counter}
                        actions={html! {
                            <SpaceBetween direction="horizontal" size="xs">
                                <Button
                                    onclick={{
                                        let view = view.clone();
                                        Callback::from(move |_: MouseEvent| view.set(View::Compare))
                                    }}
                                    disabled={assets.len() < 2}
                                >
                                    {"Compare"}
                                </Button>
                                <Button onclick={open_import} testid="import-csv-button">{"Import CSV"}</Button>
                                <Button variant="primary" onclick={open_create}>{"Add system"}</Button>
                            </SpaceBetween>
                        }}
                    >
                        {"Systems"}
                    </Header>
                }}
            />

            if let Some(e) = &*error {
                <UiBox padding="m">
                    <Alert kind="error">{e.clone()}</Alert>
                </UiBox>
            }

            {edit_modal}

            <Modal
                visible={*import_open}
                on_dismiss={close_import}
                header={html! { {"Import systems from CSV"} }}
                size="large"
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={close_import_click}>{"Cancel"}</Button>
                            if *import_step == ImportStep::Preview && import_preview.is_some() {
                                <Button
                                    variant="primary"
                                    loading={*import_busy}
                                    disabled={*import_busy || error_rows == preview_rows.len()}
                                    onclick={commit_import}
                                    testid="import-csv-commit"
                                >
                                    {format!("Import {ok_rows} rows")}
                                </Button>
                            }
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <SpaceBetween direction="vertical" size="m">
                    <UiBox>
                        {"CSV columns: "}<code>{"name, hostname, description, classification, tags"}</code>
                        {". Separate tags within a cell with semicolons. "}
                        <a href={(*template_href).clone()} download="assets-template.csv"
                           data-testid="import-csv-template">
                            {"Download template"}
                        </a>
                    </UiBox>
                    <FormField label={html! { {"CSV file"} }}>
                        <input
                            type="file"
                            accept=".csv,text/csv"
                            data-testid="import-csv-input"
                            onchange={on_import_file_change}
                        />
                    </FormField>
                    if *import_busy && *import_step == ImportStep::Pick {
                        <StatusIndicator kind="loading">{"Parsing…"}</StatusIndicator>
                    }
                    if let Some(e) = &*import_error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                    if let Some(s) = &*import_success {
                        <Alert kind="success" testid="import-csv-success">
                            {format!("Imported {} systems.", s.created_count)}
                        </Alert>
                    }
                    if import_preview.is_some() {
                        if error_rows > 0 {
                            <Alert kind="warning">
                                {format!("{error_rows} rows have errors and will be skipped.")}
                            </Alert>
                        }
                        <Table<ImportRow>
                            variant="embedded"
                            items={preview_rows.to_vec()}
                            track_by={Callback::from(|r: ImportRow| r.row_number.to_string())}
                            columns={import_columns}
                            empty={html! { <UiBox>{"No rows."}</UiBox> }}
                        />
                    }
                </SpaceBetween>
            </Modal>

            <Modal
                visible={delete_target.is_some()}
                on_dismiss={close_delete.clone()}
                header={html! { {"Delete system?"} }}
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={close_delete.reform(|_: MouseEvent| ())}>
                                {"Cancel"}
                            </Button>
                            <Button variant="primary" onclick={confirm_delete}>{"Delete"}</Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <Alert kind="warning">
                    {format!(
                        "Deleting \"{}\" cannot be undone.",
                        delete_target.as_ref().map(|a| a.name.as_str()).unwrap_or_default()
                    )}
                </Alert>
            </Modal>
        </>
    }
}
