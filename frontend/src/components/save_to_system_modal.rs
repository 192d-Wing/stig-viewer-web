//! "Save to system": push the tab's evaluated rules (status, finding details,
//! comments) into a system's server-side checklist for the catalog STIG.

use crate::api::{
    api_fetch_json, api_get, api_request_timed, set_send, FetchFailure, SET_REQUEST_TIMEOUT_MS,
    SET_SAVE_TO_SYSTEM_TIMEOUT_MS,
};
use crate::autosave::Autosave;
use crate::model::{ChecklistSet, Stig, StigTab};
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

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SetStigResult {
    stig_id: String,
    ok: bool,
    status: Option<u16>,
    save: Option<SaveResponse>,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct SetSaveResponse {
    asset_id: String,
    asset_name: String,
    results: Vec<SetStigResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetSaveRequest<'a> {
    revision: i64,
    asset_id: &'a str,
}

fn set_failure_text(status: u16) -> &'static str {
    match status {
        404 => "STIG no longer available on the server",
        403 => "No write access to this system",
        _ => "Save failed",
    }
}

fn save_summary(system: &str, r: &SaveResponse) -> String {
    let plural = |n: u64| if n == 1 { "" } else { "s" };
    let mut parts = vec![format!(
        "Saved {} rule{} to {system}.",
        r.applied_count,
        plural(r.applied_count)
    )];
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
    /// The tab's checklist set. With a set, the whole set is saved, one STIG
    /// at a time; without one, just this tab's STIG.
    #[prop_or_default]
    pub set: Option<ChecklistSet>,
    #[prop_or_default]
    pub autosave: Option<Autosave>,
    /// Open tabs of the set, for the per-STIG counts.
    #[prop_or_default]
    pub set_tabs: Vec<StigTab>,
    /// Called with the system the set is now linked to, or `None` after an unlink.
    #[prop_or_default]
    pub on_linked: Callback<Option<(String, String)>>,
}

#[function_component]
pub fn SaveToSystemModal(p: &SaveToSystemModalProps) -> Html {
    let assets = use_state(Vec::<AssetOption>::new);
    let selected = use_state(|| None::<AssetOption>);
    let existing = use_state(|| None::<bool>);
    let busy = use_state(|| false);
    let error = use_state(|| None::<String>);
    let result = use_state(|| None::<(String, SaveResponse)>);
    let set_result = use_state(|| None::<SetSaveResponse>);
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
        let set_result = set_result.clone();
        let linked = p.set.as_ref().and_then(|s| s.asset.clone());
        use_effect_with(p.show, move |show| {
            *generation.borrow_mut() += 1;
            busy.set(false);
            if *show {
                error.set(None);
                result.set(None);
                set_result.set(None);
                // A linked set is saved back to its system.
                selected.set(linked.map(|(id, name)| AssetOption {
                    id,
                    name,
                    ..AssetOption::default()
                }));
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

    let linked = p.set.as_ref().and_then(|s| s.asset.clone());
    let mut shown: Vec<AssetOption> = (*assets).clone();
    if let Some((id, name)) = &linked {
        if !shown.iter().any(|a| &a.id == id) {
            shown.push(AssetOption {
                id: id.clone(),
                name: name.clone(),
                ..AssetOption::default()
            });
        }
    }
    let options: Vec<SelectOption> = shown
        .iter()
        .map(|a| {
            let label = if a.name.is_empty() {
                a.hostname.clone()
            } else {
                a.name.clone()
            };
            SelectOption::new(a.id.clone(), label)
                .description(format!("{} · {}", a.hostname, a.owner_name))
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
        let (selected, busy, error, result) = (
            selected.clone(),
            busy.clone(),
            error.clone(),
            result.clone(),
        );
        let (stig, catalog_id, generation) =
            (p.stig.clone(), p.catalog_id.clone(), generation.clone());
        let (set, autosave, on_linked, set_result) = (
            p.set.clone(),
            p.autosave.clone(),
            p.on_linked.clone(),
            set_result.clone(),
        );
        Callback::from(move |_: MouseEvent| {
            let Some(asset) = (*selected).clone() else {
                return;
            };
            if let (Some(set), Some(autosave)) = (set.clone(), autosave.clone()) {
                *generation.borrow_mut() += 1;
                let my_gen = *generation.borrow();
                let generation = generation.clone();
                let (busy, error, set_result, on_linked) = (
                    busy.clone(),
                    error.clone(),
                    set_result.clone(),
                    on_linked.clone(),
                );
                busy.set(true);
                error.set(None);
                spawn_local(async move {
                    // Push what was last saved: flush pending edits first.
                    let outcome: Result<SetSaveResponse, String> = match autosave.flush().await {
                        Err(e) => Err(format!("Your edits could not be saved yet: {e}")),
                        Ok(()) => {
                            let body = SetSaveRequest {
                                revision: autosave.revision(&set.id).unwrap_or(0),
                                asset_id: &asset.id,
                            };
                            let path = format!("/api/checklist-sets/{}/save-to-system", set.id);
                            let json = serde_json::to_string(&body).map_err(|e| e.to_string());
                            let sent = match &json {
                                Ok(j) => api_request_timed("POST", &path, Some(j), SET_SAVE_TO_SYSTEM_TIMEOUT_MS)
                                    .await
                                    .map_err(|f| match f {
                                        FetchFailure::Timeout => "The request timed out. The save may still have completed: close this dialog and check the checklist's system.".to_string(),
                                        other => other.message(),
                                    }),
                                Err(e) => Err(e.clone()),
                            };
                            match sent {
                                Ok(res) if res.ok() => {
                                    res.json::<SetSaveResponse>().map_err(|e| format!("Unexpected response: {e}"))
                                }
                                Ok(res) => Err(match res.status {
                                    409 => "This checklist changed in another tab or device. Close this dialog, then choose Reload latest or Keep my edits.".to_string(),
                                    403 => "You do not have write access to this system.".to_string(),
                                    404 => "This checklist or system no longer exists on the server.".to_string(),
                                    400 => "This checklist is linked to a different system. Unlink it first.".to_string(),
                                    _ if res.body.is_empty() => "Save failed.".to_string(),
                                    _ => res.body,
                                }),
                                Err(e) => Err(e),
                            }
                        }
                    };
                    if *generation.borrow() != my_gen {
                        return;
                    }
                    match outcome {
                        Ok(r) => {
                            if r.results.iter().any(|x| x.ok) {
                                on_linked.emit(Some((r.asset_id.clone(), r.asset_name.clone())));
                            }
                            set_result.set(Some(r));
                        }
                        Err(e) => error.set(Some(e)),
                    }
                    busy.set(false);
                });
                return;
            }
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
                    Ok(res) if res.ok() => res
                        .json::<SaveResponse>()
                        .await
                        .map_err(|e| format!("Unexpected response: {e}")),
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
                        let name = if asset.name.is_empty() {
                            asset.hostname.clone()
                        } else {
                            asset.name.clone()
                        };
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

    let unlink = {
        let (set, selected, error, on_linked) = (
            p.set.clone(),
            selected.clone(),
            error.clone(),
            p.on_linked.clone(),
        );
        Callback::from(move |_: MouseEvent| {
            let Some(set) = set.clone() else { return };
            let (selected, error, on_linked) = (selected.clone(), error.clone(), on_linked.clone());
            spawn_local(async move {
                let body = serde_json::json!({ "assetId": null });
                match set_send(
                    "PATCH",
                    &format!("/api/checklist-sets/{}", set.id),
                    Some(&body),
                    SET_REQUEST_TIMEOUT_MS,
                )
                .await
                {
                    Ok(()) => {
                        selected.set(None);
                        on_linked.emit(None);
                    }
                    Err(e) => error.set(Some(format!("Could not unlink: {e}"))),
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
        Callback::from(move |_: ()| {
            if !busy {
                on_close.emit(())
            }
        })
    };

    let in_set_mode = p.set.is_some() && p.autosave.is_some();
    let body = match &*result {
        _ if in_set_mode && set_result.is_some() => {
            let r = (*set_result).clone().unwrap_or_default();
            let any_issue = r
                .results
                .iter()
                .any(|x| !x.ok || x.save.as_ref().is_some_and(|s| s.error_count > 0));
            html! {
                <Alert kind={if any_issue { "warning" } else { "success" }} testid="save-system-result">
                    <SpaceBetween size="xs">
                        { for r.results.iter().map(|x| match (&x.save, x.ok) {
                            (Some(save), true) => html! {
                                <div>
                                    <strong>{x.stig_id.clone()}</strong>{": "}{save_summary(&r.asset_name, save)}
                                    {result_issue_lists(save.results.iter().map(|y| (y.rule_id.as_str(), y.status.as_str(), y.error.as_deref(), y.note.as_deref())), "")}
                                </div>
                            },
                            _ => html! {
                                <div><strong>{x.stig_id.clone()}</strong>{": not saved. "}{set_failure_text(x.status.unwrap_or(0))}{"."}</div>
                            },
                        }) }
                    </SpaceBetween>
                </Alert>
            }
        }
        _ if in_set_mode => {
            let rows: Vec<Html> = p
                .set_tabs
                .iter()
                .map(|t| html! { <li>{format!("{}: {} of {} rules to save", t.stig.title, t.stig.rules_to_save().len(), t.stig.rules.len())}</li> })
                .collect();
            html! {
                <SpaceBetween size="m">
                    <FormField label="System">
                        <Select
                            options={options}
                            selected={(*selected).as_ref().map(|a| AttrValue::from(a.id.clone()))}
                            on_change={on_select}
                            disabled={*busy || linked.is_some()}
                            placeholder="Choose a system"
                            filtering=true
                            empty={if error.is_some() { "Systems could not be loaded." } else { "No systems you can write to." }}
                            testid="save-system-select"
                        />
                    </FormField>
                    if linked.is_some() {
                        <div>
                            {"This checklist was saved to this system before. "}
                            <Button variant="link" onclick={unlink} disabled={*busy} testid="save-system-unlink">{"Unlink"}</Button>
                            {" to choose a different system."}
                        </div>
                    }
                    <div>
                        {"Every STIG in this checklist is saved, one at a time:"}
                        <ul>{ for rows }</ul>
                    </div>
                    <div>{"Saving never downgrades or erases what is already on the system: rules you have not evaluated and blank notes are left as they are."}</div>
                    if let Some(e) = &*error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                </SpaceBetween>
            }
        }
        Some((system, r)) => {
            html! {
                <Alert kind={if r.error_count > 0 { "warning" } else { "success" }} testid="save-system-result">
                    {save_summary(system, r)}
                    {result_issue_lists(r.results.iter().map(|x| (x.rule_id.as_str(), x.status.as_str(), x.error.as_deref(), x.note.as_deref())), "")}
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

    let footer = if result.is_some() || set_result.is_some() {
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
        let r = SaveResponse {
            applied_count: 1,
            ..Default::default()
        };
        assert_eq!(save_summary("web-01", &r), "Saved 1 rule to web-01.");
        let r = SaveResponse {
            applied_count: 2,
            pending_count: 1,
            unchanged_count: 3,
            error_count: 4,
            ..Default::default()
        };
        assert_eq!(
            save_summary("web-01", &r),
            "Saved 2 rules to web-01. 1 submitted for review. 3 unchanged. 4 not saved."
        );
    }
}
