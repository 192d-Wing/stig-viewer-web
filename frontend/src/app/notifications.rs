//! The notification bell: state, polling, and the two modals.

use serde::{Deserialize, Serialize};
use yew::prelude::*;

use crate::api::{api_fetch, api_get, api_send};
use crate::hooks::use_interval;
use crate::ui::*;
use crate::util::{spawn_local, to_locale_string};

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NotifFinding {
    checklist_id: String,
    rule_id: String,
    asset_name: String,
    stig_title: String,
    occurred_at: String,
    due_date: Option<String>,
    unread: bool,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NotifMention {
    comment_id: String,
    rule_id: String,
    by_name: String,
    body: String,
    at: String,
    unread: bool,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NotifDraft {
    draft_id: String,
    title: String,
    by_name: String,
    at: String,
}

#[derive(Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NotifData {
    assigned: Vec<NotifFinding>,
    overdue: Vec<NotifFinding>,
    mentions: Vec<NotifMention>,
    assigned_drafts: Vec<NotifDraft>,
    unread_count: u32,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct NotifPrefs {
    assigned: bool,
    overdue: bool,
    mentions: bool,
    approvals: bool,
    decisions: bool,
    assigned_drafts: bool,
}

impl Default for NotifPrefs {
    /// The backend treats missing rows as enabled, so first-open shows
    /// every toggle on.
    fn default() -> Self {
        Self {
            assigned: true,
            overdue: true,
            mentions: true,
            approvals: true,
            decisions: true,
            assigned_drafts: true,
        }
    }
}

fn count_suffix(n: usize) -> String {
    if n > 0 {
        format!(" ({n})")
    } else {
        String::new()
    }
}

/// Bell button label: the unread count when there is one.
pub(super) fn bell_text(unread: u32) -> String {
    if unread > 0 {
        format!("Notifications ({unread})")
    } else {
        "Notifications".to_string()
    }
}

/// Bell and preferences state. Poll the bell endpoint every 30s so the badge
/// stays roughly fresh. Opening the panel calls /mark-read, which clears the
/// unread counter server-side and lets future events count as unread again.
#[derive(Clone)]
pub(super) struct Notifications {
    data: UseStateHandle<NotifData>,
    open: UseStateHandle<bool>,
    prefs_open: UseStateHandle<bool>,
    prefs: UseStateHandle<NotifPrefs>,
    prefs_saving: UseStateHandle<bool>,
    refresh: Callback<()>,
}

fn refresh_callback(data: UseStateHandle<NotifData>) -> Callback<()> {
    Callback::from(move |_: ()| {
        let data = data.clone();
        spawn_local(async move {
            // Non-fatal on failure; the bell stays as it was.
            if let Ok(d) = api_get::<NotifData>("/api/notifications").await {
                data.set(d);
            }
        });
    })
}

#[hook]
pub(super) fn use_notifications(user_id: Option<String>) -> Notifications {
    let data = use_state(NotifData::default);
    let open = use_state(|| false);
    let prefs_open = use_state(|| false);
    let prefs = use_state(NotifPrefs::default);
    let prefs_saving = use_state(|| false);

    let refresh = refresh_callback(data.clone());
    let signed_in = user_id.is_some();
    {
        let refresh = refresh.clone();
        use_effect_with(user_id, move |uid| {
            if uid.is_some() {
                refresh.emit(());
            }
        });
    }
    {
        let refresh = refresh.clone();
        let tick = Callback::from(move |_| {
            if signed_in {
                refresh.emit(());
            }
        });
        use_interval(signed_in, 30_000, tick);
    }
    Notifications {
        data,
        open,
        prefs_open,
        prefs,
        prefs_saving,
        refresh,
    }
}

impl Notifications {
    pub(super) fn unread_count(&self) -> u32 {
        self.data.unread_count
    }

    pub(super) fn on_open(&self) -> Callback<MouseEvent> {
        let open = self.open.clone();
        let data = self.data.clone();
        Callback::from(move |_: MouseEvent| {
            open.set(true);
            let data = data.clone();
            spawn_local(async move {
                // mark-read answers 204; failures are non-fatal and the
                // local clear below still runs.
                let _ = api_fetch("POST", "/api/notifications/mark-read").await;
                let mut d = (*data).clone();
                d.unread_count = 0;
                d.assigned.iter_mut().for_each(|a| a.unread = false);
                d.mentions.iter_mut().for_each(|m| m.unread = false);
                data.set(d);
            });
        })
    }

    fn on_open_prefs(&self) -> Callback<MouseEvent> {
        let prefs_open = self.prefs_open.clone();
        let prefs = self.prefs.clone();
        Callback::from(move |_: MouseEvent| {
            prefs_open.set(true);
            let prefs = prefs.clone();
            spawn_local(async move {
                // Non-fatal — leave defaults in place so the toggles still render.
                if let Ok(p) = api_get::<NotifPrefs>("/api/notifications/prefs").await {
                    prefs.set(p);
                }
            });
        })
    }

    fn on_save_prefs(&self) -> Callback<MouseEvent> {
        let prefs = self.prefs.clone();
        let saving = self.prefs_saving.clone();
        let prefs_open = self.prefs_open.clone();
        let refresh = self.refresh.clone();
        Callback::from(move |_: MouseEvent| {
            let prefs = (*prefs).clone();
            let saving = saving.clone();
            let prefs_open = prefs_open.clone();
            let refresh = refresh.clone();
            saving.set(true);
            spawn_local(async move {
                // On failure the toggles stay where the user left them and
                // the modal stays open so they can retry.
                if api_send("/api/notifications/prefs", "PUT", Some(&prefs))
                    .await
                    .is_ok()
                {
                    prefs_open.set(false);
                    // Refresh the bell so disabled buckets clear immediately.
                    refresh.emit(());
                }
                saving.set(false);
            });
        })
    }
}

fn inactive(text: &'static str) -> Html {
    html! {
        <UiBox color="text-status-inactive" padding_top="xs">{text}</UiBox>
    }
}

fn when(s: String) -> Html {
    html! { <UiBox variant="span" color="text-status-inactive">{s}</UiBox> }
}

fn pref_toggle(
    prefs: &UseStateHandle<NotifPrefs>,
    label: &'static str,
    testid: &'static str,
    checked: bool,
    set: fn(&mut NotifPrefs, bool),
) -> Html {
    let prefs = prefs.clone();
    let on_change = Callback::from(move |v: bool| {
        let mut p = (*prefs).clone();
        set(&mut p, v);
        prefs.set(p);
    });
    html! { <Toggle {checked} {testid} {on_change}>{label}</Toggle> }
}

fn assigned_section(data: &NotifData) -> Html {
    html! {
        <UiBox>
            <UiBox variant="h4">{"Newly assigned"}</UiBox>
            if data.assigned.is_empty() {
                {inactive("Nothing assigned to you recently.")}
            } else {
                <ul class="ui-notif-list">
                    { for data.assigned.iter().map(|a| html! {
                        <li key={format!("{}:{}:{}", a.checklist_id, a.rule_id, a.occurred_at)}>
                            <strong>{a.rule_id.clone()}</strong>{" on "}<em>{a.asset_name.clone()}</em>{" · "}{a.stig_title.clone()}
                            {when(format!(" — {}", to_locale_string(&a.occurred_at)))}
                        </li>
                    }) }
                </ul>
            }
        </UiBox>
    }
}

fn overdue_section(data: &NotifData) -> Html {
    html! {
        <UiBox>
            <UiBox variant="h4">{"Overdue"}{count_suffix(data.overdue.len())}</UiBox>
            if data.overdue.is_empty() {
                {inactive("Nothing assigned to you is past due.")}
            } else {
                <ul class="ui-notif-list">
                    { for data.overdue.iter().map(|o| html! {
                        <li key={format!("{}:{}", o.checklist_id, o.rule_id)}>
                            <strong>{o.rule_id.clone()}</strong>{" on "}<em>{o.asset_name.clone()}</em>{" · "}{o.stig_title.clone()}
                            {when(format!(" — due {}", o.due_date.clone().unwrap_or_default()))}
                        </li>
                    }) }
                </ul>
            }
        </UiBox>
    }
}

fn drafts_section(
    n: &Notifications,
    writer_draft_id: &UseStateHandle<Option<String>>,
    navigate_to: &Callback<&'static str>,
) -> Html {
    let (notif_open, data) = (&n.open, &n.data);
    html! {
        <UiBox>
            <UiBox variant="h4">{"Drafts waiting on you"}{count_suffix(data.assigned_drafts.len())}</UiBox>
            if data.assigned_drafts.is_empty() {
                {inactive("No drafts are awaiting your review.")}
            } else {
                <ul class="ui-notif-list" data-testid="assigned-drafts-list">
                    { for data.assigned_drafts.iter().map(|d| {
                        let onclick = {
                            let (notif_open, writer_draft_id, navigate_to, id) =
                                (notif_open.clone(), writer_draft_id.clone(), navigate_to.clone(), d.draft_id.clone());
                            Callback::from(move |_: MouseEvent| {
                                notif_open.set(false);
                                writer_draft_id.set(Some(id.clone()));
                                navigate_to.emit("writer");
                            })
                        };
                        html! {
                            <li key={d.draft_id.clone()} data-testid="assigned-draft-item" class="ui-clickable" {onclick}>
                                <strong>{if d.title.is_empty() { "(untitled draft)".to_string() } else { d.title.clone() }}</strong>
                                {" from "}<em>{d.by_name.clone()}</em>
                                {when(format!(" — {}", to_locale_string(&d.at)))}
                            </li>
                        }
                    }) }
                </ul>
            }
        </UiBox>
    }
}

fn mentions_section(n: &Notifications, navigate_to: &Callback<&'static str>) -> Html {
    let (notif_open, data) = (&n.open, &n.data);
    html! {
        <UiBox>
            <UiBox variant="h4">{"Mentions"}{count_suffix(data.mentions.len())}</UiBox>
            if data.mentions.is_empty() {
                {inactive("No one has @-mentioned you in a comment.")}
            } else {
                <ul class="ui-notif-list" data-testid="mentions-list">
                    { for data.mentions.iter().map(|m| {
                        let onclick = {
                            let (notif_open, navigate_to) = (notif_open.clone(), navigate_to.clone());
                            Callback::from(move |_: MouseEvent| {
                                notif_open.set(false);
                                navigate_to.emit("systems");
                            })
                        };
                        html! {
                            <li key={m.comment_id.clone()} data-testid="mention-item" class="ui-clickable" {onclick}>
                                <strong>{m.by_name.clone()}</strong>{" mentioned you on "}<em>{m.rule_id.clone()}</em>
                                {format!(": \"{}\"", m.body)}
                                {when(format!(" — {}", to_locale_string(&m.at)))}
                            </li>
                        }
                    }) }
                </ul>
            }
        </UiBox>
    }
}

pub(super) fn notifications_modal(
    n: &Notifications,
    writer_draft_id: &UseStateHandle<Option<String>>,
    navigate_to: &Callback<&'static str>,
) -> Html {
    let notif_open = n.open.clone();
    html! {
        <Modal visible={*n.open} size="medium"
            on_dismiss={Callback::from(move |_| notif_open.set(false))}
            header={html! {
                <SpaceBetween direction="horizontal" size="s">
                    <UiBox variant="h2" padding="n">{"Notifications"}</UiBox>
                    <Button variant="link" testid="notif-prefs-open" onclick={n.on_open_prefs()}>{"Preferences"}</Button>
                </SpaceBetween>
            }}>
            <SpaceBetween direction="vertical" size="l">
                {assigned_section(&n.data)}
                {overdue_section(&n.data)}
                {drafts_section(n, writer_draft_id, navigate_to)}
                {mentions_section(n, navigate_to)}
            </SpaceBetween>
        </Modal>
    }
}

pub(super) fn notif_prefs_modal(n: &Notifications) -> Html {
    let p = &n.prefs;
    let dismiss = n.prefs_open.clone();
    let cancel = n.prefs_open.clone();
    html! {
        <Modal visible={*n.prefs_open} size="small" header="Notification preferences" testid="notif-prefs-modal"
            on_dismiss={Callback::from(move |_| dismiss.set(false))}
            footer={html! {
                <UiBox float="right">
                    <SpaceBetween direction="horizontal" size="xs">
                        <Button variant="link" onclick={move |_| cancel.set(false)}>{"Cancel"}</Button>
                        <Button variant="primary" loading={*n.prefs_saving} testid="notif-prefs-save" onclick={n.on_save_prefs()}>{"Save"}</Button>
                    </SpaceBetween>
                </UiBox>
            }}>
            <SpaceBetween direction="vertical" size="s">
                <UiBox color="text-status-inactive">
                    {"Disable an event type to hide its bucket and exclude it from the bell badge."}
                </UiBox>
                {pref_toggle(p, "Newly assigned", "notif-pref-assigned", p.assigned, |p, v| p.assigned = v)}
                {pref_toggle(p, "Overdue", "notif-pref-overdue", p.overdue, |p, v| p.overdue = v)}
                {pref_toggle(p, "Mentions", "notif-pref-mentions", p.mentions, |p, v| p.mentions = v)}
                {pref_toggle(p, "Approvals (pending)", "notif-pref-approvals", p.approvals, |p, v| p.approvals = v)}
                {pref_toggle(p, "Decisions", "notif-pref-decisions", p.decisions, |p, v| p.decisions = v)}
                {pref_toggle(p, "Drafts waiting on you", "notif-pref-assigned_drafts", p.assigned_drafts, |p, v| p.assigned_drafts = v)}
            </SpaceBetween>
        </Modal>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bell_text_shows_count_only_when_unread() {
        assert_eq!(bell_text(0), "Notifications");
        assert_eq!(bell_text(3), "Notifications (3)");
    }

    #[test]
    fn count_suffix_hides_zero() {
        assert_eq!(count_suffix(0), "");
        assert_eq!(count_suffix(2), " (2)");
    }
}
