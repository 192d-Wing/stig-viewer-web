//! Asset groups: list / create / edit / delete, plus a members sub-view.

use crate::api::{api_fetch, api_fetch_json, api_get, api_json};
use crate::auth::{use_current_user, User};
use crate::ui::*;
use crate::util::{spawn_local, to_locale_string};
use serde::Deserialize;
use yew::prelude::*;

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Group {
    id: String,
    name: String,
    description: String,
    owner_id: String,
    owner_name: String,
    member_count: i64,
    created_at: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Member {
    asset_id: String,
    name: String,
    hostname: String,
    added_at: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AssetLite {
    id: String,
    name: String,
    hostname: Option<String>,
}

/// Which form the create/edit modal is showing.
#[derive(Clone, PartialEq)]
enum GroupModal {
    Create,
    Edit(Group),
}

/// Only the owner or a global admin may mutate a group.
fn can_edit(user: &Option<User>, group: &Group) -> bool {
    user.as_ref().is_some_and(|u| u.id == group.owner_id || u.role == "admin")
}

#[derive(Properties, PartialEq)]
pub struct AssetGroupsPageProps {}

#[function_component]
pub fn AssetGroupsPage(_props: &AssetGroupsPageProps) -> Html {
    let current_user = use_current_user();

    // `None` is the list; `Some((id, name))` pivots to a dedicated members
    // sub-page, which keeps the membership editor focused (the list table is
    // full-page so an inline expander would fight the sticky header).
    let view = use_state(|| None::<(String, String)>);
    let groups = use_state(Vec::<Group>::new);
    let loading = use_state(|| true);
    let error = use_state(|| None::<String>);

    let modal = use_state(|| None::<GroupModal>);
    let form_name = use_state(String::new);
    let form_description = use_state(String::new);
    let submitting = use_state(|| false);
    let submit_error = use_state(|| None::<String>);

    let delete_target = use_state(|| None::<Group>);

    let refresh = {
        let groups = groups.clone();
        let loading = loading.clone();
        let error = error.clone();
        Callback::from(move |_: ()| {
            let groups = groups.clone();
            let loading = loading.clone();
            let error = error.clone();
            loading.set(true);
            error.set(None);
            spawn_local(async move {
                match api_get::<Vec<Group>>("/api/asset-groups").await {
                    Ok(rows) => groups.set(rows),
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            });
        })
    };

    {
        let refresh = refresh.clone();
        use_effect_with((), move |_| refresh.emit(()));
    }

    let open_create = {
        let form_name = form_name.clone();
        let form_description = form_description.clone();
        let submit_error = submit_error.clone();
        let modal = modal.clone();
        Callback::from(move |_: MouseEvent| {
            form_name.set(String::new());
            form_description.set(String::new());
            submit_error.set(None);
            modal.set(Some(GroupModal::Create));
        })
    };

    let open_edit = {
        let form_name = form_name.clone();
        let form_description = form_description.clone();
        let submit_error = submit_error.clone();
        let modal = modal.clone();
        Callback::from(move |group: Group| {
            form_name.set(group.name.clone());
            form_description.set(group.description.clone());
            submit_error.set(None);
            modal.set(Some(GroupModal::Edit(group)));
        })
    };

    let close_modal = {
        let modal = modal.clone();
        let submit_error = submit_error.clone();
        Callback::from(move |_: ()| {
            modal.set(None);
            submit_error.set(None);
        })
    };

    let submit = {
        let form_name = form_name.clone();
        let form_description = form_description.clone();
        let modal = modal.clone();
        let submitting = submitting.clone();
        let submit_error = submit_error.clone();
        let refresh = refresh.clone();
        Callback::from(move |_: MouseEvent| {
            if form_name.trim().is_empty() {
                submit_error.set(Some("Name is required.".to_string()));
                return;
            }
            let Some(mode) = (*modal).clone() else {
                return;
            };
            let body = serde_json::json!({
                "name": (*form_name).clone(),
                "description": (*form_description).clone(),
            });
            submitting.set(true);
            submit_error.set(None);
            let modal = modal.clone();
            let submitting = submitting.clone();
            let submit_error = submit_error.clone();
            let refresh = refresh.clone();
            spawn_local(async move {
                let result = match mode {
                    GroupModal::Create => {
                        api_json::<serde_json::Value, _>("/api/asset-groups", "POST", Some(&body)).await
                    }
                    GroupModal::Edit(group) => {
                        let path = format!("/api/asset-groups/{}", group.id);
                        api_json::<serde_json::Value, _>(&path, "PATCH", Some(&body)).await
                    }
                };
                match result {
                    Ok(_) => {
                        modal.set(None);
                        refresh.emit(());
                    }
                    Err(e) => submit_error.set(Some(e)),
                }
                submitting.set(false);
            });
        })
    };

    let close_delete = {
        let delete_target = delete_target.clone();
        Callback::from(move |_: ()| delete_target.set(None))
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
                match api_fetch("DELETE", &format!("/api/asset-groups/{}", target.id)).await {
                    Ok(res) if res.ok() || res.status() == 204 => {
                        delete_target.set(None);
                        refresh.emit(());
                    }
                    Ok(res) => submit_error.set(Some(format!("Delete failed: {}", res.status()))),
                    Err(e) => submit_error.set(Some(e)),
                }
            });
        })
    };

    if let Some((id, name)) = &*view {
        let editable = groups.iter().find(|g| &g.id == id).is_some_and(|g| can_edit(&current_user, g));
        let on_back = {
            let view = view.clone();
            let refresh = refresh.clone();
            Callback::from(move |_: ()| {
                view.set(None);
                refresh.emit(());
            })
        };
        return html! {
            <GroupMembersView group_id={id.clone()} group_name={name.clone()} can_edit={editable} {on_back} />
        };
    }

    let show_members = {
        let view = view.clone();
        Callback::from(move |g: Group| view.set(Some((g.id, g.name))))
    };

    let columns = {
        let name_click = show_members.clone();
        let view_click = show_members.clone();
        let open_edit = open_edit.clone();
        let delete_target = delete_target.clone();
        let current_user = current_user.clone();
        vec![
            Column::new("name", "Name", move |g: &Group| {
                let onclick = {
                    let g = g.clone();
                    name_click.reform(move |_: MouseEvent| g.clone())
                };
                html! {
                    <Button variant="inline-link" {onclick} testid={format!("group-name-{}", g.name)}>
                        {g.name.clone()}
                    </Button>
                }
            }),
            Column::new("description", "Description", |g: &Group| {
                html! { {if g.description.is_empty() { "—".to_string() } else { g.description.clone() }} }
            }),
            Column::new("owner", "Owner", |g: &Group| html! { {g.owner_name.clone()} }),
            Column::new("members", "Members", |g: &Group| html! { {g.member_count} }),
            Column::new("updated", "Created", |g: &Group| html! { {to_locale_string(&g.created_at)} }),
            Column::new("actions", "", move |g: &Group| {
                let editable = can_edit(&current_user, g);
                let on_view = {
                    let g = g.clone();
                    view_click.reform(move |_: MouseEvent| g.clone())
                };
                let on_edit = {
                    let g = g.clone();
                    open_edit.reform(move |_: MouseEvent| g.clone())
                };
                let on_delete = {
                    let g = g.clone();
                    let delete_target = delete_target.clone();
                    Callback::from(move |_: MouseEvent| delete_target.set(Some(g.clone())))
                };
                html! {
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button variant="inline-link" onclick={on_view}>{"View"}</Button>
                        <Button variant="inline-link" disabled={!editable} onclick={on_edit}>{"Edit"}</Button>
                        <Button variant="inline-link" disabled={!editable} onclick={on_delete}>{"Delete"}</Button>
                    </SpaceBetween>
                }
            }),
        ]
    };

    let is_edit = matches!(&*modal, Some(GroupModal::Edit(_)));
    let delete_name = delete_target.as_ref().map(|g| g.name.clone()).unwrap_or_default();

    html! {
        <>
            <Table<Group>
                variant="full-page"
                sticky_header=true
                items={(*groups).clone()}
                {columns}
                loading={*loading}
                loading_text="Loading groups"
                empty={html! {
                    <UiBox text_align="center" padding="l">
                        <SpaceBetween direction="vertical" size="m">
                            <StatusIndicator kind="info">{"No groups yet"}</StatusIndicator>
                            <Button variant="primary" onclick={open_create.clone()}>
                                {"Create your first group"}
                            </Button>
                        </SpaceBetween>
                    </UiBox>
                }}
                header={html! {
                    <Header
                        counter={format!("({})", groups.len())}
                        actions={html! {
                            <Button variant="primary" onclick={open_create.clone()} testid="create-group-button">
                                {"Create group"}
                            </Button>
                        }}
                    >
                        {"Asset groups"}
                    </Header>
                }}
            />

            if let Some(e) = &*error {
                <UiBox padding="m">
                    <Alert kind="error">{e.clone()}</Alert>
                </UiBox>
            }

            <Modal
                visible={modal.is_some()}
                on_dismiss={close_modal.clone()}
                header={if is_edit { "Edit group" } else { "Create group" }}
                footer={html! {
                    <UiBox float="right">
                        <SpaceBetween direction="horizontal" size="xs">
                            <Button variant="link" onclick={close_modal.reform(|_: MouseEvent| ())}>
                                {"Cancel"}
                            </Button>
                            <Button variant="primary" loading={*submitting} onclick={submit} testid="group-modal-submit">
                                {if is_edit { "Save" } else { "Create" }}
                            </Button>
                        </SpaceBetween>
                    </UiBox>
                }}
            >
                <SpaceBetween direction="vertical" size="m">
                    <FormField label="Name">
                        <Input
                            value={(*form_name).clone()}
                            testid="group-name-input"
                            on_change={{ let s = form_name.clone(); move |v: String| s.set(v) }}
                            auto_focus=true
                        />
                    </FormField>
                    <FormField label="Description">
                        <Textarea
                            value={(*form_description).clone()}
                            testid="group-description-input"
                            on_change={{ let s = form_description.clone(); move |v: String| s.set(v) }}
                            rows={3}
                        />
                    </FormField>
                    if let Some(e) = &*submit_error {
                        <Alert kind="error">{e.clone()}</Alert>
                    }
                </SpaceBetween>
            </Modal>

            <Modal
                visible={delete_target.is_some()}
                on_dismiss={close_delete.clone()}
                header="Delete group?"
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
                    {format!("Deleting \"{delete_name}\" removes the group and all of its memberships. Member assets themselves are not deleted.")}
                </Alert>
            </Modal>
        </>
    }
}

// ── Members sub-view ────────────────────────────────────────────────────────

#[derive(Properties, PartialEq)]
struct GroupMembersViewProps {
    group_id: AttrValue,
    group_name: AttrValue,
    can_edit: bool,
    on_back: Callback<()>,
}

#[function_component]
fn GroupMembersView(p: &GroupMembersViewProps) -> Html {
    let members = use_state(Vec::<Member>::new);
    let all_assets = use_state(Vec::<AssetLite>::new);
    let loading = use_state(|| true);
    let error = use_state(|| None::<String>);
    let selected = use_state(Vec::<AttrValue>::new);
    let adding = use_state(|| false);

    let refresh = {
        let members = members.clone();
        let all_assets = all_assets.clone();
        let loading = loading.clone();
        let error = error.clone();
        let group_id = p.group_id.clone();
        Callback::from(move |_: ()| {
            let members = members.clone();
            let all_assets = all_assets.clone();
            let loading = loading.clone();
            let error = error.clone();
            let group_id = group_id.clone();
            loading.set(true);
            error.set(None);
            spawn_local(async move {
                let m = api_get::<Vec<Member>>(&format!("/api/asset-groups/{group_id}/members")).await;
                let a = api_get::<Vec<AssetLite>>("/api/assets").await;
                match (m, a) {
                    (Ok(m), Ok(a)) => {
                        members.set(m);
                        all_assets.set(a);
                    }
                    (Err(e), _) | (_, Err(e)) => error.set(Some(e)),
                }
                loading.set(false);
            });
        })
    };

    {
        let refresh = refresh.clone();
        use_effect_with(p.group_id.clone(), move |_| refresh.emit(()));
    }

    // Candidate options = assets not already in the group.
    let options: Vec<SelectOption> = all_assets
        .iter()
        .filter(|a| !members.iter().any(|m| m.asset_id == a.id))
        .map(|a| {
            let opt = SelectOption::new(a.id.clone(), a.name.clone());
            match a.hostname.as_deref() {
                Some(h) if !h.is_empty() => opt.description(h.to_string()),
                _ => opt,
            }
        })
        .collect();

    let add_selected = {
        let selected = selected.clone();
        let adding = adding.clone();
        let error = error.clone();
        let refresh = refresh.clone();
        let group_id = p.group_id.clone();
        Callback::from(move |_: MouseEvent| {
            if selected.is_empty() {
                return;
            }
            let to_add = (*selected).clone();
            let selected = selected.clone();
            let adding = adding.clone();
            let error = error.clone();
            let refresh = refresh.clone();
            let group_id = group_id.clone();
            adding.set(true);
            error.set(None);
            spawn_local(async move {
                let path = format!("/api/asset-groups/{group_id}/members");
                let mut failure = None;
                for asset_id in &to_add {
                    // POST is idempotent server-side, so a retry on partial
                    // failure is safe — but stop on the first hard error to
                    // avoid spamming the user with one error per asset.
                    let body = serde_json::json!({ "assetId": asset_id.as_str() });
                    match api_fetch_json("POST", &path, &body).await {
                        Ok(res) if res.ok() || res.status() == 204 => {}
                        Ok(res) => {
                            let status = res.status();
                            let text = res.text().await.unwrap_or_else(|_| res.status_text());
                            failure = Some(if text.is_empty() { status.to_string() } else { text });
                            break;
                        }
                        Err(e) => {
                            failure = Some(e);
                            break;
                        }
                    }
                }
                match failure {
                    None => {
                        selected.set(vec![]);
                        refresh.emit(());
                    }
                    Some(e) => error.set(Some(e)),
                }
                adding.set(false);
            });
        })
    };

    let remove_member = {
        let error = error.clone();
        let refresh = refresh.clone();
        let group_id = p.group_id.clone();
        Callback::from(move |asset_id: String| {
            let error = error.clone();
            let refresh = refresh.clone();
            let path = format!("/api/asset-groups/{group_id}/members/{asset_id}");
            spawn_local(async move {
                match api_fetch("DELETE", &path).await {
                    Ok(res) if res.ok() || res.status() == 204 => refresh.emit(()),
                    Ok(res) => error.set(Some(format!("Remove failed: {}", res.status()))),
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    let can_edit = p.can_edit;
    let columns = vec![
        Column::new("name", "Name", |m: &Member| html! { {m.name.clone()} }),
        Column::new("hostname", "Hostname", |m: &Member| {
            html! { {if m.hostname.is_empty() { "—".to_string() } else { m.hostname.clone() }} }
        }),
        Column::new("added", "Added", |m: &Member| html! { {to_locale_string(&m.added_at)} }),
        Column::new("actions", "", move |m: &Member| {
            let onclick = {
                let id = m.asset_id.clone();
                remove_member.reform(move |_: MouseEvent| id.clone())
            };
            html! {
                <Button variant="inline-link" disabled={!can_edit} {onclick}
                        testid={format!("remove-member-{}", m.name)}>
                    {"Remove"}
                </Button>
            }
        }),
    ];

    let filter = if can_edit {
        let on_change = {
            let selected = selected.clone();
            Callback::from(move |opts: Vec<SelectOption>| {
                selected.set(opts.into_iter().map(|o| o.value).collect());
            })
        };
        html! {
            <SpaceBetween direction="horizontal" size="xs">
                <UiBox variant="span" color="text-status-inactive">{"Add assets:"}</UiBox>
                <div style="min-width:320px;" data-testid="add-member-multiselect">
                    <Multiselect
                        selected={(*selected).clone()}
                        {on_change}
                        {options}
                        placeholder="Select assets to add…"
                        empty="All assets already in this group"
                    />
                </div>
                <Button variant="primary" loading={*adding} disabled={selected.is_empty()}
                        onclick={add_selected} testid="add-member-button">
                    {"Add"}
                </Button>
            </SpaceBetween>
        }
    } else {
        Html::default()
    };

    let description = match &*error {
        Some(e) => html! { <UiBox color="text-status-error">{e.clone()}</UiBox> },
        None => Html::default(),
    };

    html! {
        <Table<Member>
            variant="full-page"
            sticky_header=true
            items={(*members).clone()}
            {columns}
            loading={*loading}
            loading_text="Loading members"
            empty={html! {
                <UiBox text_align="center" padding="l">
                    <StatusIndicator kind="info">{"No assets in this group yet."}</StatusIndicator>
                </UiBox>
            }}
            {filter}
            header={html! {
                <Header
                    counter={format!("({})", members.len())}
                    actions={html! { <Button onclick={p.on_back.reform(|_: MouseEvent| ())}>{"Back to groups"}</Button> }}
                    {description}
                >
                    {format!("Members of {}", p.group_name)}
                </Header>
            }}
        />
    }
}
