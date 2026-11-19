//! "My checklists": the signed-in user's saved checklist sets. Open one to
//! resume it, rename or delete it, or start a new one from catalog STIGs.

use std::collections::HashSet;

use serde::Deserialize;
use yew::prelude::*;

use crate::api::{api_get, set_json, set_send, SET_REQUEST_TIMEOUT_MS};
use crate::autosave::{create_named_set, delete_set, fetch_set};
use crate::model::{ChecklistSet, Stig};
use crate::ui::{
    Alert, Button, Column, Container, FormField, Header, Input, Modal, Multiselect, SelectOption,
    SpaceBetween, Table, UiBox,
};
use crate::util::{confirm, encode_uri_component, new_request_id, spawn_local, to_locale_string};

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SetSummary {
    id: String,
    name: String,
    stig_count: u32,
    touched_count: u32,
    asset_id: Option<String>,
    asset_name: Option<String>,
    updated_at: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct CatalogItem {
    id: String,
    title: String,
    version: String,
    release_info: String,
}

/// What opening a set yields: the set, a tab's worth of STIG per catalog id
/// with the saved state applied, and how many saved rules no longer match.
pub type OpenedSet = (ChecklistSet, Vec<(String, Stig)>, usize);

/// Load a set and its STIGs and put the saved rule state on them.
pub async fn load_opened_set(set_id: &str) -> Result<OpenedSet, String> {
    let (set, rules_by_stig) = fetch_set(set_id).await?;
    let mut stigs = Vec::with_capacity(rules_by_stig.len());
    let mut unknown = 0;
    for (stig_id, rules) in rules_by_stig {
        let mut stig: Stig = api_get(&format!("/api/stigs/{}", encode_uri_component(&stig_id)))
            .await
            .map_err(|e| format!("Could not load STIG {stig_id}: {e}"))?;
        unknown += stig.overlay_server_state(&rules, &HashSet::new());
        stigs.push((stig_id, stig));
    }
    Ok((set, stigs, unknown))
}

/// Token of the last failed create, reusable only for the same name and STIGs.
type CreateAttempt = (String, String, Vec<String>);

fn reusable_key(last: Option<&CreateAttempt>, name: &str, ids: &[String]) -> Option<String> {
    match last {
        Some((key, n, i)) if n == name && i == ids => Some(key.clone()),
        _ => None,
    }
}

#[derive(Properties, PartialEq)]
pub struct MyChecklistsProps {
    pub show: bool,
    pub on_close: Callback<()>,
    pub on_open: Callback<OpenedSet>,
    pub on_renamed: Callback<(String, String)>,
    pub on_deleted: Callback<String>,
}

#[function_component]
pub fn MyChecklists(p: &MyChecklistsProps) -> Html {
    let sets = use_state(Vec::<SetSummary>::new);
    let catalog = use_state(Vec::<CatalogItem>::new);
    let loading = use_state(|| false);
    let busy = use_state(|| false);
    let error = use_state(|| None::<String>);
    let renaming = use_state(|| None::<(String, String)>);
    let new_name = use_state(String::new);
    let new_stigs = use_state(Vec::<AttrValue>::new);
    let reload = use_state(|| 0u32);
    // Token of the last create that failed, reused only for the same name and STIGs.
    let create_attempt = use_mut_ref(|| None::<CreateAttempt>);

    {
        let (sets, catalog, loading, error) = (
            sets.clone(),
            catalog.clone(),
            loading.clone(),
            error.clone(),
        );
        use_effect_with((p.show, *reload), move |(show, _)| {
            if *show {
                loading.set(true);
                error.set(None);
                spawn_local(async move {
                    match set_json::<Vec<SetSummary>, ()>(
                        "GET",
                        "/api/checklist-sets",
                        None,
                        SET_REQUEST_TIMEOUT_MS,
                    )
                    .await
                    {
                        Ok(list) => sets.set(list),
                        Err(e) => error.set(Some(format!("Could not load your checklists: {e}"))),
                    }
                    if catalog.is_empty() {
                        if let Ok(list) = api_get::<Vec<CatalogItem>>("/api/catalog").await {
                            catalog.set(list);
                        }
                    }
                    loading.set(false);
                });
            }
        });
    }

    let open_set = {
        let (busy, error, on_open) = (busy.clone(), error.clone(), p.on_open.clone());
        Callback::from(move |id: String| {
            let (busy, error, on_open) = (busy.clone(), error.clone(), on_open.clone());
            busy.set(true);
            error.set(None);
            spawn_local(async move {
                match load_opened_set(&id).await {
                    Ok(opened) => on_open.emit(opened),
                    Err(e) => error.set(Some(e)),
                }
                busy.set(false);
            });
        })
    };

    let create = {
        let (busy, error, new_name, new_stigs) = (
            busy.clone(),
            error.clone(),
            new_name.clone(),
            new_stigs.clone(),
        );
        let open_set = open_set.clone();
        let create_attempt = create_attempt.clone();
        Callback::from(move |_: MouseEvent| {
            let ids: Vec<String> = new_stigs.iter().map(|s| s.to_string()).collect();
            if ids.is_empty() {
                return;
            }
            let name = (*new_name).clone();
            let request_id = {
                let mut last = create_attempt.borrow_mut();
                match reusable_key(last.as_ref(), &name, &ids) {
                    Some(key) => Some(key),
                    None => {
                        let key = new_request_id();
                        *last = key.clone().map(|k| (k, name.clone(), ids.clone()));
                        key
                    }
                }
            };
            let create_attempt = create_attempt.clone();
            let (busy, error, new_name, new_stigs, open_set) = (
                busy.clone(),
                error.clone(),
                new_name.clone(),
                new_stigs.clone(),
                open_set.clone(),
            );
            busy.set(true);
            error.set(None);
            spawn_local(async move {
                match create_named_set(&name, &ids, request_id.as_deref()).await {
                    Ok(set) => {
                        *create_attempt.borrow_mut() = None;
                        new_name.set(String::new());
                        new_stigs.set(Vec::new());
                        busy.set(false);
                        open_set.emit(set.id);
                    }
                    Err(e) => {
                        error.set(Some(if e.contains("set_limit") {
                            "You have reached the limit of 50 checklists. Delete one first.".into()
                        } else {
                            format!("Could not create the checklist: {e}")
                        }));
                        busy.set(false);
                    }
                }
            });
        })
    };

    let columns = {
        let renaming_h = renaming.clone();
        let (error_c, reload_c, busy_c) = (error.clone(), reload.clone(), busy.clone());
        let (on_renamed, on_deleted) = (p.on_renamed.clone(), p.on_deleted.clone());
        let open_c = open_set.clone();
        vec![
            Column::new("name", "Name", {
                let renaming = renaming_h.clone();
                let (error, reload, on_renamed) =
                    (error_c.clone(), reload_c.clone(), on_renamed.clone());
                move |s: &SetSummary| match &*renaming {
                    Some((id, text)) if *id == s.id => {
                        let on_change = {
                            let (renaming, id) = (renaming.clone(), id.clone());
                            Callback::from(move |v: String| renaming.set(Some((id.clone(), v))))
                        };
                        let save = {
                            let (renaming, error, reload, on_renamed) = (
                                renaming.clone(),
                                error.clone(),
                                reload.clone(),
                                on_renamed.clone(),
                            );
                            let (id, text) = (id.clone(), text.clone());
                            Callback::from(move |_: MouseEvent| {
                                let (renaming, error, reload, on_renamed) = (
                                    renaming.clone(),
                                    error.clone(),
                                    reload.clone(),
                                    on_renamed.clone(),
                                );
                                let (id, text) = (id.clone(), text.clone());
                                spawn_local(async move {
                                    let body = serde_json::json!({ "name": text });
                                    match set_send(
                                        "PATCH",
                                        &format!(
                                            "/api/checklist-sets/{}",
                                            encode_uri_component(&id)
                                        ),
                                        Some(&body),
                                        SET_REQUEST_TIMEOUT_MS,
                                    )
                                    .await
                                    {
                                        Ok(()) => {
                                            on_renamed.emit((id, text.trim().to_string()));
                                            renaming.set(None);
                                            reload.set(*reload + 1);
                                        }
                                        Err(e) => error.set(Some(format!("Could not rename: {e}"))),
                                    }
                                });
                            })
                        };
                        let cancel = {
                            let renaming = renaming.clone();
                            Callback::from(move |_: MouseEvent| renaming.set(None))
                        };
                        html! {
                            <SpaceBetween direction="horizontal" size="xs">
                                <Input value={text.clone()} {on_change} aria_label="Checklist name" testid="set-rename-input" />
                                <Button onclick={save} testid="set-rename-save">{"Save"}</Button>
                                <Button variant="link" onclick={cancel}>{"Cancel"}</Button>
                            </SpaceBetween>
                        }
                    }
                    _ => html! { {s.name.clone()} },
                }
            }),
            Column::new("stigs", "STIGs", |s: &SetSummary| html! { {s.stig_count} }),
            Column::new(
                "touched",
                "Rules evaluated",
                |s: &SetSummary| html! { {s.touched_count} },
            ),
            Column::new("system", "System", |s: &SetSummary| {
                match (&s.asset_name, &s.asset_id) {
                    (Some(n), _) => html! { {n.clone()} },
                    (None, Some(_)) => html! { {"(no access)"} },
                    _ => html! { {"-"} },
                }
            }),
            Column::new(
                "updated",
                "Updated",
                |s: &SetSummary| html! { {to_locale_string(&s.updated_at)} },
            ),
            Column::new("actions", "Actions", move |s: &SetSummary| {
                let open = {
                    let (open_c, id) = (open_c.clone(), s.id.clone());
                    Callback::from(move |_: MouseEvent| open_c.emit(id.clone()))
                };
                let rename = {
                    let (renaming, id, name) = (renaming_h.clone(), s.id.clone(), s.name.clone());
                    Callback::from(move |_: MouseEvent| {
                        renaming.set(Some((id.clone(), name.clone())))
                    })
                };
                let delete = {
                    let (error, reload, on_deleted, busy) = (
                        error_c.clone(),
                        reload_c.clone(),
                        on_deleted.clone(),
                        busy_c.clone(),
                    );
                    let (id, name) = (s.id.clone(), s.name.clone());
                    Callback::from(move |_: MouseEvent| {
                        if !confirm(&format!(
                            "Delete checklist \"{name}\"? This cannot be undone."
                        )) {
                            return;
                        }
                        let (error, reload, on_deleted, busy, id) = (
                            error.clone(),
                            reload.clone(),
                            on_deleted.clone(),
                            busy.clone(),
                            id.clone(),
                        );
                        busy.set(true);
                        spawn_local(async move {
                            match delete_set(&id).await {
                                Ok(()) => {
                                    on_deleted.emit(id);
                                    reload.set(*reload + 1);
                                }
                                Err(e) => error.set(Some(e)),
                            }
                            busy.set(false);
                        });
                    })
                };
                html! {
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button onclick={open} testid="set-open">{"Open"}</Button>
                        <Button onclick={rename} testid="set-rename">{"Rename"}</Button>
                        <Button onclick={delete} testid="set-delete">{"Delete"}</Button>
                    </SpaceBetween>
                }
            }),
        ]
    };

    let options: Vec<SelectOption> = catalog
        .iter()
        .map(|c| {
            SelectOption::new(c.id.clone(), c.title.clone()).description(
                format!("{} {} {}", c.id, c.version, c.release_info)
                    .trim()
                    .to_string(),
            )
        })
        .collect();
    let on_pick = {
        let new_stigs = new_stigs.clone();
        Callback::from(move |picked: Vec<SelectOption>| {
            new_stigs.set(picked.into_iter().take(20).map(|o| o.value).collect());
        })
    };
    let on_name = {
        let new_name = new_name.clone();
        Callback::from(move |v: String| new_name.set(v))
    };
    let close = p.on_close.reform(|_: MouseEvent| ());

    let footer = html! {
        <SpaceBetween direction="horizontal" size="xs">
            <div style="flex:1;" />
            <Button variant="link" onclick={close} disabled={*busy}>{"Close"}</Button>
        </SpaceBetween>
    };
    let table = html! {
        <Table<SetSummary>
            items={(*sets).clone()}
            columns={columns}
            aria_label="My checklists"
            loading={*loading}
            empty={html! { <UiBox color="text-status-inactive">{"No saved checklists yet. Edit a STIG from the library and it is saved here automatically."}</UiBox> }}
            variant="embedded"
            track_by={Callback::from(|s: SetSummary| s.id)}
        />
    };

    html! {
        <Modal visible={p.show} on_dismiss={p.on_close.clone()} header="My checklists" {footer} size="large" testid="my-checklists">
            // Rendered only while open: the dialog is mounted at the app root, so
            // a hidden list would otherwise be the last table on every page.
            if p.show {
            <SpaceBetween size="m">
                if let Some(e) = &*error {
                    <Alert kind="error">{e.clone()}</Alert>
                }
                {table}
                <Container header={html! { <Header variant="h3">{"New checklist"}</Header> }}>
                    <SpaceBetween size="s">
                        <FormField label="Name" description="Optional. Defaults to the first STIG and today's date.">
                            <Input value={(*new_name).clone()} on_change={on_name} testid="new-set-name" />
                        </FormField>
                        <FormField label="STIGs" description="Up to 20.">
                            <Multiselect options={options} selected={(*new_stigs).clone()} on_change={on_pick}
                                         placeholder="Choose STIGs" filtering=true testid="new-set-stigs" />
                        </FormField>
                        <div>
                            <Button variant="primary" onclick={create} disabled={new_stigs.is_empty() || *busy}
                                    loading={*busy} testid="new-set-create">{"Create and open"}</Button>
                        </div>
                    </SpaceBetween>
                </Container>
            </SpaceBetween>
            }
        </Modal>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_create_key_is_reused_only_for_the_same_name_and_stigs() {
        let last = ("k".to_string(), "n".to_string(), vec!["a".to_string()]);
        let same = vec!["a".to_string()];
        assert_eq!(reusable_key(Some(&last), "n", &same), Some("k".into()));
        assert_eq!(reusable_key(Some(&last), "other", &same), None);
        assert_eq!(reusable_key(Some(&last), "n", &["b".to_string()]), None);
        assert_eq!(reusable_key(None, "n", &same), None);
    }
}
