//! "Save to system": push the tab's evaluated rules (status, finding details,
//! comments) into a system's server-side checklist for the catalog STIG.

use crate::api::{api_fetch_json, api_get};
use crate::model::Stig;
use crate::ui::*;
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AssetOption {
    id: String,
    name: String,
    hostname: String,
    owner_name: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ChecklistRef {
    stig_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveRule<'a> {
    rule_id: &'a str,
    status: &'a str,
    finding_details: &'a str,
    comments: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveRequest<'a> {
    stig_id: &'a str,
    rules: Vec<SaveRule<'a>>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SaveRow {
    rule_id: String,
    status: String,
    error: Option<String>,
    note: Option<String>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SaveResponse {
    results: Vec<SaveRow>,
    applied_count: u64,
    pending_count: u64,
    unchanged_count: u64,
    error_count: u64,
}

fn save_summary(system: &str, r: &SaveResponse) -> String {
    let plural = |n: u64| if n == 1 { "" } else { "s" };
    let mut parts = vec![format!("Saved {} rule{} to {system}.", r.applied_count, plural(r.applied_count))];
    if r.pending_count > 0 {
        parts.push(format!("{} submitted for review.", r.pending_count));
    }
    if r.unchanged_count > 0 {
        parts.push(format!("{} unchanged.", r.unchanged_count));
    }
    if r.error_count > 0 {
        parts.push(format!("{} not saved.", r.error_count));
    }
    parts.join(" ")
}

#[derive(Properties, PartialEq)]
pub struct SaveToSystemModalProps {
    pub show: bool,
    pub on_close: Callback<()>,
    pub stig: Rc<Stig>,
    pub catalog_id: String,
}

#[function_component]
pub fn SaveToSystemModal(p: &SaveToSystemModalProps) -> Html {
    let assets = use_state(Vec::<AssetOption>::new);
    let selected = use_state(|| None::<AssetOption>);
    let existing = use_state(|| None::<bool>);
    let busy = use_state(|| false);
    let error = use_state(|| None::<String>);
    let result = use_state(|| None::<(String, SaveResponse)>);
    // Bumped on every open/close, selection change and save, so a response
    // that arrives after the context moved on is dropped.
    let generation = use_mut_ref(|| 0u32);

    // Load the systems and reset state each time the dialog opens.
    {
        let (assets, selected, existing, error, result, busy, generation) = (
            assets.clone(),
            selected.clone(),
            existing.clone(),
            error.clone(),
            result.clone(),
            busy.clone(),
            generation.clone(),
        );
        use_effect_with(p.show, move |show| {
            *generation.borrow_mut() += 1;
            busy.set(false);
            if *show {
                error.set(None);
                result.set(None);
                selected.set(None);
                existing.set(None);
                let my_gen = *generation.borrow();
                spawn_local(async move {
                    let loaded = api_get::<Vec<AssetOption>>("/api/assets?writable=true").await;
                    if *generation.borrow() != my_gen {
                        return;
                    }
                    match loaded {
                        Ok(list) => assets.set(list),
                        Err(e) => {
                            assets.set(Vec::new());
                            error.set(Some(format!("Could not load systems: {e}")));
                        }
                    }
                });
            }
        });
    }

    let options: Vec<SelectOption> = assets
        .iter()
        .map(|a| {
            let label = if a.name.is_empty() { a.hostname.clone() } else { a.name.clone() };
            SelectOption::new(a.id.clone(), label).description(format!("{} · {}", a.hostname, a.owner_name))
        })
        .collect();

    let on_select = {
        let (assets, selected, existing) = (assets.clone(), selected.clone(), existing.clone());
        let (catalog_id, generation) = (p.catalog_id.clone(), generation.clone());
        Callback::from(move |o: SelectOption| {
            let id = o.value.to_string();
            *generation.borrow_mut() += 1;
            let my_gen = *generation.borrow();
            let generation = generation.clone();
            selected.set(assets.iter().find(|a| a.id == id).cloned());
            existing.set(None);
            let (existing, catalog_id) = (existing.clone(), catalog_id.clone());
            spawn_local(async move {
                let path = format!("/api/assets/{id}/checklists");
                if let Ok(list) = api_get::<Vec<ChecklistRef>>(&path).await {
                    if *generation.borrow() != my_gen {
                        return;
                    }
                    existing.set(Some(list.iter().any(|c| c.stig_id == catalog_id)));
                }
            });
        })
    };

    let save = {
        let (selected, busy, error, result) = (selected.clone(), busy.clone(), error.clone(), result.clone());
        let (stig, catalog_id, generation) = (p.stig.clone(), p.catalog_id.clone(), generation.clone());
        Callback::from(move |_: MouseEvent| {
            let Some(asset) = (*selected).clone() else { return };
            *generation.borrow_mut() += 1;
            let my_gen = *generation.borrow();
            let generation = generation.clone();
            let (busy, error, result) = (busy.clone(), error.clone(), result.clone());
            let (stig, catalog_id) = (stig.clone(), catalog_id.clone());
            busy.set(true);
            error.set(None);
            spawn_local(async move {
                let body = SaveRequest {
                    stig_id: &catalog_id,
                    rules: stig
                        .rules_to_save()
                        .into_iter()
                        .map(|r| SaveRule {
                            rule_id: &r.id,
                            status: &r.status,
                            finding_details: &r.finding_details,
                            comments: &r.comments,
                        })
                        .collect(),
                };
                let path = format!("/api/assets/{}/checklists/save", asset.id);
                let outcome = api_fetch_json("POST", &path, &body).await;
                let parsed: Result<SaveResponse, String> = match outcome {
                    Ok(res) if res.ok() => {
                        res.json::<SaveResponse>().await.map_err(|e| format!("Unexpected response: {e}"))
                    }
                    Ok(res) => Err(match res.status() {
                        403 => "You do not have write access to this system.".to_string(),
                        404 => "This STIG or system no longer exists on the server.".to_string(),
                        _ => res.text().await.unwrap_or_else(|_| "Save failed.".into()),
                    }),
                    Err(e) => Err(e),
                };
                if *generation.borrow() != my_gen {
                    return; // dialog was closed or reopened meanwhile
                }
                match parsed {
                    Ok(r) => {
                        let name = if asset.name.is_empty() { asset.hostname.clone() } else { asset.name.clone() };
                        result.set(Some((name, r)));
                    }
                    Err(e) => error.set(Some(e)),
                }
                if *generation.borrow() == my_gen {
                    busy.set(false);
                }
            });
        })
    };

    let total = p.stig.rules.len();
    let to_save = p.stig.rules_to_save().len();
    let cancel = p.on_close.reform(|_: MouseEvent| ());
    // The dialog cannot be dismissed while a save is in flight.
    let on_dismiss = {
        let (on_close, busy) = (p.on_close.clone(), *busy);
        Callback::from(move |_: ()| if !busy { on_close.emit(()) })
    };

    let body = match &*result {
        Some((system, r)) => {
            let failed: Vec<&SaveRow> = r.results.iter().filter(|x| x.status == "error").collect();
            let noted: Vec<&SaveRow> = r.results.iter().filter(|x| x.note.is_some()).collect();
            html! {
                <Alert kind={if r.error_count > 0 { "warning" } else { "success" }} testid="save-system-result">
                    {save_summary(system, r)}
                    if !noted.is_empty() {
                        <ul style="margin:6px 0 0;padding-left:18px;">
                            { for noted.iter().take(10).map(|x| html! {
                                <li key={x.rule_id.clone()}>
                                    <code>{x.rule_id.clone()}</code>{": "}{x.note.clone().unwrap_or_default()}
                                </li>
                            }) }
                            if noted.len() > 10 {
                                <li>{format!("…and {} more.", noted.len() - 10)}</li>
                            }
                        </ul>
                    }
                    if !failed.is_empty() {
                        <ul style="margin:6px 0 0;padding-left:18px;">
                            { for failed.iter().take(10).map(|x| html! {
                                <li key={x.rule_id.clone()}>
                                    <code>{x.rule_id.clone()}</code>{": "}{x.error.clone().unwrap_or_default()}
                                </li>
                            }) }
                            if failed.len() > 10 {
                                <li>{format!("…and {} more.", failed.len() - 10)}</li>
                            }
                        </ul>
                    }
                </Alert>
            }
        }
        None => html! {
            <SpaceBetween size="m">
                <FormField label="System">
                    <Select
                        options={options}
                        selected={(*selected).as_ref().map(|a| AttrValue::from(a.id.clone()))}
                        on_change={on_select}
                        disabled={*busy}
                        placeholder="Choose a system"
                        filtering=true
                        empty={if error.is_some() { "Systems could not be loaded." } else { "No systems you can write to." }}
                        testid="save-system-select"
                    />
                </FormField>
                <div>
                    {format!(
                        "{to_save} of {total} rules have a status or notes and will be saved. \
                         Rules you have not evaluated are left as they are on the system."
                    )}
                </div>
                if let Some(exists) = *existing {
                    <Alert kind="info">
                        { if exists {
                            "This system already has a checklist for this STIG. Saved rules will overwrite its status, finding details and comments; assignees and due dates are kept."
                        } else {
                            "A new checklist will be created."
                        } }
                    </Alert>
                }
                if let Some(e) = &*error {
                    <Alert kind="error">{e.clone()}</Alert>
                }
            </SpaceBetween>
        },
    };

    let footer = if result.is_some() {
        html! {
            <SpaceBetween direction="horizontal" size="xs">
                <div style="flex:1;" />
                <Button variant="primary" onclick={cancel}>{"Close"}</Button>
            </SpaceBetween>
        }
    } else {
        html! {
            <SpaceBetween direction="horizontal" size="xs">
                <div style="flex:1;" />
                <Button variant="link" onclick={cancel} disabled={*busy}>{"Cancel"}</Button>
                <Button variant="primary" onclick={save} loading={*busy}
                        disabled={selected.is_none()} testid="save-system-apply">
                    {"Save"}
                </Button>
            </SpaceBetween>
        }
    };

    html! {
        <Modal visible={p.show} on_dismiss={on_dismiss} header="Save to system" {footer}>
            {body}
        </Modal>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_summary_lists_each_outcome() {
        let r = SaveResponse { applied_count: 1, ..Default::default() };
        assert_eq!(save_summary("web-01", &r), "Saved 1 rule to web-01.");
        let r = SaveResponse { applied_count: 2, pending_count: 1, unchanged_count: 3, error_count: 4, ..Default::default() };
        assert_eq!(
            save_summary("web-01", &r),
            "Saved 2 rules to web-01. 1 submitted for review. 3 unchanged. 4 not saved."
        );
    }
}
