//! Autosave for checklist sets.
//!
//! Rule edits on a catalog tab are tracked as dirty (`DirtyTracker`) and
//! pushed to `PATCH /api/checklist-sets/:id/rules` with the last revision the
//! client saw. The first edit on a catalog tab creates its set. One request is
//! in flight at a time; edits made meanwhile coalesce into the next one.
//!
//! The push to a system is a separate, explicit action (Save to system).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use gloo_events::{EventListener, EventListenerOptions};
use gloo_timers::future::TimeoutFuture;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use yew::prelude::*;

use crate::api::{api_fetch, api_fetch_with_timeout, api_get, user_id, FetchFailure, BACKEND};
use crate::model::{
    split_batches, ChecklistSet, DirtyTracker, ServerRule, SetRuleChange, StigTab, BATCH_MAX_BYTES,
    BATCH_MAX_CHANGES,
};
use crate::util::{now_ms, spawn_local, window};

/// Longest an edit may wait before it is sent, however long typing continues.
const MAX_WAIT_MS: f64 = 15_000.0;
const DEBOUNCE_MS: u32 = 3_000;
const BACKOFF_START_MS: u32 = 1_000;
const BACKOFF_MAX_MS: u32 = 30_000;
/// Browsers cap `keepalive` request bodies near 64 KiB.
const KEEPALIVE_MAX_BYTES: usize = 60 * 1024;
/// A save request that has not answered by then is abandoned and retried, so
/// one hung connection cannot block sign-out, tab close or Save to system.
const REQUEST_TIMEOUT_MS: u32 = 15_000;
const LIMIT_MSG: &str = "You have reached the limit of 50 checklists. Delete one in My checklists.";
const TOO_LARGE_MSG: &str =
    "This checklist is too large to save. Remove some notes or start another checklist.";

#[derive(Clone, Debug, PartialEq)]
pub enum SaveStatus {
    Idle,
    Pending,
    Saving,
    /// Time of the last successful save, `HH:MM`.
    Saved(String),
    Error(String),
    Offline,
    Conflict,
}

impl SaveStatus {
    /// Indicator text and `StatusIndicator` kind; `None` when nothing is shown.
    pub fn indicator(&self) -> Option<(&'static str, String)> {
        match self {
            SaveStatus::Idle => None,
            SaveStatus::Pending => Some(("pending", "Unsaved changes".into())),
            SaveStatus::Saving => Some(("loading", "Saving...".into())),
            SaveStatus::Saved(t) => Some(("success", format!("Saved {t}"))),
            SaveStatus::Error(m) if m == "Signed out" => {
                Some(("error", "Signed out - sign in again".into()))
            }
            SaveStatus::Error(m) => Some(("error", format!("Save failed: {m}"))),
            SaveStatus::Offline => Some(("warning", "Offline - will retry".into())),
            SaveStatus::Conflict => Some(("warning", "Changed in another tab or device".into())),
        }
    }
}

/// What autosave tells the app shell to do to its tab state.
#[derive(Clone, Debug, PartialEq)]
pub enum SetEvent {
    /// A set was created for a tab by its first edit.
    Created { tab_id: String, set: ChecklistSet },
    /// A batch was saved; the set is now at `revision`.
    Saved { set_id: String, revision: i64 },
    /// Server state for a set's STIGs. Rules in `keep` (tab id, rule id) are
    /// left as the user has them.
    Replace {
        set_id: String,
        revision: i64,
        stigs: Vec<(String, Vec<ServerRule>)>,
        keep: HashSet<(String, String)>,
    },
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct SetDetailWire {
    id: String,
    name: String,
    revision: i64,
    asset_id: Option<String>,
    asset_name: Option<String>,
    stigs: Vec<StigWire>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct StigWire {
    stig_id: String,
    rules: Vec<ServerRule>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct AutosaveWire {
    revision: i64,
}

#[derive(Serialize)]
struct CreateBody<'a> {
    #[serde(rename = "stigIds")]
    stig_ids: Vec<&'a str>,
}

#[derive(Serialize)]
struct RulesBody<'a> {
    revision: i64,
    changes: &'a [SetRuleChange],
}

impl SetDetailWire {
    fn into_set(self) -> (ChecklistSet, Vec<(String, Vec<ServerRule>)>) {
        let asset = self.asset_id.map(|id| {
            let name = self.asset_name.unwrap_or_else(|| id.clone());
            (id, name)
        });
        let set = ChecklistSet {
            id: self.id,
            name: self.name,
            revision: self.revision,
            asset,
        };
        (
            set,
            self.stigs
                .into_iter()
                .map(|s| (s.stig_id, s.rules))
                .collect(),
        )
    }
}

/// Fetch one set with its sparse rule state.
pub async fn fetch_set(
    set_id: &str,
) -> Result<(ChecklistSet, Vec<(String, Vec<ServerRule>)>), String> {
    let wire: SetDetailWire = api_get(&format!(
        "/api/checklist-sets/{}",
        crate::util::encode_uri_component(set_id)
    ))
    .await?;
    Ok(wire.into_set())
}

#[derive(Default)]
struct Inner {
    enabled: bool,
    tracker: DirtyTracker,
    tabs: Vec<StigTab>,
    revisions: HashMap<String, i64>,
    /// Sets created for tabs whose `set_id` has not reached a render yet.
    created: HashMap<String, String>,
    paused: HashSet<String>,
    running: bool,
    stopped: bool,
    debounce_gen: u32,
    first_edit_at: Option<f64>,
    backoff_ms: u32,
    last_saved: Option<String>,
}

type Events = Callback<SetEvent>;

/// Handle to the autosaver; cheap to clone.
#[derive(Clone)]
pub struct Autosave {
    inner: Rc<RefCell<Inner>>,
    status: UseStateHandle<SaveStatus>,
    events: Rc<RefCell<Events>>,
}

impl PartialEq for Autosave {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner) && *self.status == *other.status
    }
}

fn clock_hhmm() -> String {
    let d = js_sys::Date::new_0();
    format!("{:02}:{:02}", d.get_hours(), d.get_minutes())
}

/// How a failed request is handled.
#[derive(Debug, PartialEq)]
enum Failure {
    Conflict,
    SignedOut,
    /// Worth retrying: network error, 429 or 5xx. Carries `Retry-After` secs.
    Transient {
        retry_after: Option<u32>,
        offline: bool,
        msg: String,
    },
    Fatal(String),
}

fn classify(status: u16, retry_after: Option<u32>, text: String) -> Failure {
    match status {
        409 => Failure::Conflict,
        401 => Failure::SignedOut,
        429 => Failure::Transient {
            retry_after,
            offline: false,
            msg: "Too many requests".into(),
        },
        413 => Failure::Fatal(TOO_LARGE_MSG.into()),
        s if s >= 500 => Failure::Transient {
            retry_after,
            offline: false,
            msg: format!("Server error ({s})"),
        },
        s => Failure::Fatal(if text.is_empty() {
            format!("Save failed ({s})")
        } else {
            text
        }),
    }
}

/// Like `classify`, for creating a set: its only 409 is the per-user set
/// limit, which no retry or reload can fix.
fn classify_create(status: u16, retry_after: Option<u32>, text: String) -> Failure {
    match status {
        409 => Failure::Fatal(LIMIT_MSG.into()),
        _ => classify(status, retry_after, text),
    }
}

/// What a failure does to the autosaver: the status to show, whether saving
/// stops for good, and the backoff (ms) before an automatic retry.
#[derive(Debug, PartialEq)]
struct Outcome {
    status: SaveStatus,
    stop: bool,
    retry_in: Option<u32>,
    msg: String,
}

fn outcome(f: Failure, backoff_ms: u32) -> Outcome {
    match f {
        Failure::Conflict => Outcome {
            status: SaveStatus::Conflict,
            stop: false,
            retry_in: None,
            msg: "Changed in another tab or device".into(),
        },
        // Keep the edits in memory; never retry across identities.
        Failure::SignedOut => Outcome {
            status: SaveStatus::Error("Signed out".into()),
            stop: true,
            retry_in: None,
            msg: "Signed out".into(),
        },
        Failure::Fatal(msg) => Outcome {
            status: SaveStatus::Error(msg.clone()),
            stop: false,
            retry_in: None,
            msg,
        },
        Failure::Transient {
            retry_after,
            offline,
            msg,
        } => Outcome {
            status: if offline {
                SaveStatus::Offline
            } else {
                SaveStatus::Error(msg.clone())
            },
            stop: false,
            retry_in: Some(next_backoff(backoff_ms, retry_after)),
            msg,
        },
    }
}

/// Next backoff delay: doubles from 1 s up to 30 s, never below `Retry-After`.
pub fn next_backoff(current_ms: u32, retry_after_secs: Option<u32>) -> u32 {
    let doubled = if current_ms == 0 {
        BACKOFF_START_MS
    } else {
        (current_ms.saturating_mul(2)).min(BACKOFF_MAX_MS)
    };
    match retry_after_secs {
        Some(s) => doubled
            .max(s.saturating_mul(1000))
            .min(BACKOFF_MAX_MS.max(s.saturating_mul(1000))),
        None => doubled,
    }
}

/// Whether edits to a tab are tracked for saving: autosave is on (never for
/// viewers), not stopped by a sign-out, and the tab came from the library.
fn can_track(enabled: bool, stopped: bool, catalog_id: Option<&str>) -> bool {
    enabled && !stopped && catalog_id.is_some()
}

impl Autosave {
    /// Tell the app shell. The callback is cloned out first: dispatching can
    /// re-render synchronously, and a render replaces the stored callback.
    fn emit(&self, e: SetEvent) {
        let cb = self.events.borrow().clone();
        cb.emit(e);
    }

    fn set_status(&self, s: SaveStatus) {
        if *self.status != s {
            self.status.set(s);
        }
    }

    pub fn status(&self) -> SaveStatus {
        (*self.status).clone()
    }

    /// Latest revision the client knows for a set.
    pub fn revision(&self, set_id: &str) -> Option<i64> {
        self.inner.borrow().revisions.get(set_id).copied()
    }

    pub fn has_unsaved(&self) -> bool {
        let i = self.inner.borrow();
        i.running || !i.tracker.is_empty()
    }

    /// True when the tab has edits that are not saved yet.
    pub fn tab_is_dirty(&self, tab_id: &str) -> bool {
        self.inner
            .borrow()
            .tracker
            .dirty_tabs()
            .iter()
            .any(|t| t == tab_id)
    }

    /// Called on every render with the current tabs.
    pub fn sync(&self, tabs: &[StigTab], sets: &[ChecklistSet], enabled: bool) {
        let mut i = self.inner.borrow_mut();
        i.enabled = enabled;
        i.tabs = tabs.to_vec();
        for s in sets {
            i.revisions.entry(s.id.clone()).or_insert(s.revision);
        }
        let live: HashSet<&str> = tabs.iter().map(|t| t.id.as_str()).collect();
        for gone in i
            .tracker
            .dirty_tabs()
            .into_iter()
            .filter(|t| !live.contains(t.as_str()))
        {
            i.tracker.forget_tab(&gone);
        }
        i.created.retain(|tab_id, _| live.contains(tab_id.as_str()));
    }

    /// Start tracking a set opened or created elsewhere.
    pub fn register_set(&self, set: &ChecklistSet) {
        self.inner
            .borrow_mut()
            .revisions
            .insert(set.id.clone(), set.revision);
    }

    /// Stop tracking a deleted set and drop its pending edits.
    pub fn forget_set(&self, set_id: &str) {
        let mut i = self.inner.borrow_mut();
        let tabs: Vec<String> = i
            .tabs
            .iter()
            .filter(|t| t.set_id.as_deref() == Some(set_id))
            .map(|t| t.id.clone())
            .collect();
        for t in tabs {
            i.tracker.forget_tab(&t);
        }
        i.revisions.remove(set_id);
        i.paused.remove(set_id);
    }

    /// Record edits to `rule_ids` of a tab and schedule a save. Only catalog
    /// tabs are saved; local files and the demo STIG are not.
    pub fn mark(&self, tab_id: &str, rule_ids: &[String]) {
        let delay = {
            let mut i = self.inner.borrow_mut();
            let catalog_id = i
                .tabs
                .iter()
                .find(|t| t.id == tab_id)
                .and_then(|t| t.catalog_id.as_deref());
            let eligible = can_track(i.enabled, i.stopped, catalog_id);
            if !eligible || rule_ids.is_empty() {
                return;
            }
            for r in rule_ids {
                i.tracker.mark(tab_id, r);
            }
            let now = now_ms();
            let first = *i.first_edit_at.get_or_insert(now);
            i.debounce_gen += 1;
            let waited = now - first;
            (f64::from(DEBOUNCE_MS)).min((MAX_WAIT_MS - waited).max(0.0)) as u32
        };
        if !matches!(*self.status, SaveStatus::Conflict | SaveStatus::Saving) {
            self.set_status(SaveStatus::Pending);
        }
        self.schedule(delay);
    }

    fn schedule(&self, delay_ms: u32) {
        let gen = {
            let mut i = self.inner.borrow_mut();
            i.debounce_gen += 1;
            i.debounce_gen
        };
        let this = self.clone();
        spawn_local(async move {
            TimeoutFuture::new(delay_ms).await;
            if this.inner.borrow().debounce_gen == gen {
                let _ = this.flush().await;
            }
        });
    }

    /// Fire-and-forget flush (focus loss, tab switch, hidden page).
    pub fn flush_soon(&self) {
        if !self.has_unsaved() {
            return;
        }
        let this = self.clone();
        spawn_local(async move {
            let _ = this.flush().await;
        });
    }

    /// Save everything dirty now. `Ok` when nothing remains unsaved; `Err`
    /// with a message when saving is blocked (conflict, signed out, failure).
    pub async fn flush(&self) -> Result<(), String> {
        // Let a render that follows the latest edit land, so the saved values
        // are the visible ones.
        TimeoutFuture::new(0).await;
        while self.inner.borrow().running {
            TimeoutFuture::new(40).await;
        }
        {
            let mut i = self.inner.borrow_mut();
            i.running = true;
            // A failed attempt must not leave the old edit time behind, or the
            // next debounce would collapse to zero.
            i.first_edit_at = None;
        }
        let result = self.run().await;
        {
            let mut i = self.inner.borrow_mut();
            i.running = false;
        }
        result
    }

    async fn run(&self) -> Result<(), String> {
        let mut sent = false;
        loop {
            // Tabs of a conflicted set wait for the user's choice; the rest go on.
            let (dirty_tabs, blocked) = self.ready_tabs()?;
            if dirty_tabs.is_empty() {
                if blocked {
                    self.set_status(SaveStatus::Conflict);
                    return Err("Changed in another tab or device".into());
                }
                if sent {
                    let t = clock_hhmm();
                    let mut i = self.inner.borrow_mut();
                    i.last_saved = Some(t.clone());
                    i.backoff_ms = 0;
                    drop(i);
                    self.set_status(SaveStatus::Saved(t));
                }
                return Ok(());
            }
            self.set_status(SaveStatus::Saving);

            let by_set = match self.group_by_set(dirty_tabs).await {
                Ok(g) => g,
                Err(f) => return self.fail(f),
            };
            for (set_id, tab_ids) in by_set {
                match self.send_set(&set_id, &tab_ids).await {
                    Ok(()) => sent = true,
                    // Paused by send_set; the next pass skips it.
                    Err(Failure::Conflict) => {}
                    Err(f) => return self.fail(f),
                }
            }
            // Go around: edits may have arrived while saving, and the top of
            // the loop reports a conflict or success.
        }
    }

    /// Dirty tabs that can be sent now, and whether any wait on a conflicted
    /// set. `Err` once autosave has stopped (signed out).
    fn ready_tabs(&self) -> Result<(Vec<String>, bool), String> {
        let i = self.inner.borrow();
        if i.stopped {
            return Err("Signed out".into());
        }
        let (mut ready, mut blocked) = (Vec::new(), false);
        for t in i.tracker.dirty_tabs() {
            let set = i
                .tabs
                .iter()
                .find(|x| x.id == t)
                .and_then(|x| x.set_id.clone())
                .or_else(|| i.created.get(&t).cloned());
            if set.is_some_and(|s| i.paused.contains(&s)) {
                blocked = true;
            } else {
                ready.push(t);
            }
        }
        Ok((ready, blocked))
    }

    /// Group dirty tabs by set, creating a set for tabs that have none.
    async fn group_by_set(
        &self,
        dirty_tabs: Vec<String>,
    ) -> Result<Vec<(String, Vec<String>)>, Failure> {
        let mut by_set: Vec<(String, Vec<String>)> = Vec::new();
        for tab_id in dirty_tabs {
            let (tab, known) = {
                let i = self.inner.borrow();
                let tab = i.tabs.iter().find(|t| t.id == tab_id).cloned();
                let known = tab
                    .as_ref()
                    .and_then(|t| t.set_id.clone())
                    .or_else(|| i.created.get(&tab_id).cloned());
                (tab, known)
            };
            let Some(tab) = tab else {
                self.inner.borrow_mut().tracker.forget_tab(&tab_id);
                continue;
            };
            let set_id = match known {
                Some(id) => id,
                None => self.create_set(&tab).await?,
            };
            match by_set.iter_mut().find(|(s, _)| *s == set_id) {
                Some((_, tabs)) => tabs.push(tab_id),
                None => by_set.push((set_id, vec![tab_id])),
            }
        }
        Ok(by_set)
    }

    fn fail(&self, f: Failure) -> Result<(), String> {
        let o = {
            let mut i = self.inner.borrow_mut();
            let o = outcome(f, i.backoff_ms);
            if o.stop {
                i.stopped = true;
            }
            if let Some(d) = o.retry_in {
                i.backoff_ms = d;
            }
            o
        };
        self.set_status(o.status);
        if let Some(d) = o.retry_in {
            self.schedule(d);
        }
        Err(o.msg)
    }

    /// One JSON request with a timeout. Serialization problems are fatal;
    /// network failures and timeouts are retried later.
    async fn request<B: Serialize + ?Sized>(
        method: &str,
        path: &str,
        body: &B,
    ) -> Result<gloo_net::http::Response, Failure> {
        let json = serde_json::to_string(body)
            .map_err(|e| Failure::Fatal(format!("Could not encode the save: {e}")))?;
        api_fetch_with_timeout(method, path, Some(&json), REQUEST_TIMEOUT_MS)
            .await
            .map_err(|e| match e {
                FetchFailure::Build(msg) => Failure::Fatal(msg),
                FetchFailure::Timeout => Failure::Transient {
                    retry_after: None,
                    offline: true,
                    msg: "Request timed out".into(),
                },
                FetchFailure::Network(msg) => Failure::Transient {
                    retry_after: None,
                    offline: true,
                    msg,
                },
            })
    }

    async fn create_set(&self, tab: &StigTab) -> Result<String, Failure> {
        let Some(catalog_id) = tab.catalog_id.as_deref() else {
            return Err(Failure::Fatal(
                "Only library STIGs are saved to your account".into(),
            ));
        };
        let res = Self::request(
            "POST",
            "/api/checklist-sets",
            &CreateBody {
                stig_ids: vec![catalog_id],
            },
        )
        .await?;
        if !res.ok() {
            let retry = res
                .headers()
                .get("retry-after")
                .and_then(|v| v.parse().ok());
            let text = res.text().await.unwrap_or_default();
            return Err(classify_create(res.status(), retry, text));
        }
        let wire = res
            .json::<SetDetailWire>()
            .await
            .map_err(|e| Failure::Fatal(format!("Unexpected response: {e}")))?;
        let (set, _) = wire.into_set();
        {
            let mut i = self.inner.borrow_mut();
            i.created.insert(tab.id.clone(), set.id.clone());
            i.revisions.insert(set.id.clone(), set.revision);
        }
        let id = set.id.clone();
        self.emit(SetEvent::Created {
            tab_id: tab.id.clone(),
            set,
        });
        Ok(id)
    }

    /// Changes for the given tabs' dirty rules, read from the current tabs.
    fn collect(&self, tab_ids: &[&str]) -> (Vec<SetRuleChange>, u64) {
        let i = self.inner.borrow();
        let (keys, hw) = i.tracker.take_batch(tab_ids);
        let mut changes = Vec::with_capacity(keys.len());
        for (tab_id, rule_id) in keys {
            let found = i.tabs.iter().find(|t| t.id == tab_id).and_then(|t| {
                let stig_id = t.catalog_id.clone()?;
                let r = t.stig.rules.iter().find(|r| r.id == rule_id)?;
                Some(SetRuleChange {
                    stig_id,
                    rule_id: r.id.clone(),
                    status: r.status.clone(),
                    finding_details: r.finding_details.clone(),
                    comments: r.comments.clone(),
                })
            });
            if let Some(c) = found {
                changes.push(c);
            }
        }
        (changes, hw)
    }

    async fn send_set(&self, set_id: &str, tab_ids: &[String]) -> Result<(), Failure> {
        let ids: Vec<&str> = tab_ids.iter().map(String::as_str).collect();
        let (changes, high_water) = self.collect(&ids);
        let path = format!(
            "/api/checklist-sets/{}/rules",
            crate::util::encode_uri_component(set_id)
        );
        let mut revision = self.revision(set_id).unwrap_or(0);
        for batch in split_batches(changes, BATCH_MAX_CHANGES, BATCH_MAX_BYTES) {
            let body = RulesBody {
                revision,
                changes: &batch,
            };
            let res = Self::request("PATCH", &path, &body).await?;
            if !res.ok() {
                let retry = res
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.parse().ok());
                let status = res.status();
                let text = res.text().await.unwrap_or_default();
                let f = classify(status, retry, text);
                if f == Failure::Conflict {
                    self.inner.borrow_mut().paused.insert(set_id.to_string());
                }
                return Err(f);
            }
            let ok = res
                .json::<AutosaveWire>()
                .await
                .map_err(|e| Failure::Fatal(format!("Unexpected response: {e}")))?;
            revision = ok.revision;
            self.inner
                .borrow_mut()
                .revisions
                .insert(set_id.to_string(), revision);
        }
        self.inner.borrow_mut().tracker.ack(&ids, high_water);
        self.emit(SetEvent::Saved {
            set_id: set_id.to_string(),
            revision,
        });
        Ok(())
    }

    /// Conflict: discard unsaved local edits and take the server's state.
    pub async fn reload_latest(&self, set_id: &str) -> Result<(), String> {
        self.take_server_state(set_id, false).await
    }

    /// Conflict: keep local edits, take the server's values for every other
    /// rule, and resend the local edits on the new revision.
    pub async fn keep_my_edits(&self, set_id: &str) -> Result<(), String> {
        self.take_server_state(set_id, true).await?;
        self.flush().await
    }

    async fn take_server_state(&self, set_id: &str, keep_dirty: bool) -> Result<(), String> {
        let (set, stigs) = fetch_set(set_id).await?;
        let keep: HashSet<(String, String)> = {
            let mut i = self.inner.borrow_mut();
            let tab_ids: Vec<String> = i
                .tabs
                .iter()
                .filter(|t| t.set_id.as_deref() == Some(set_id))
                .map(|t| t.id.clone())
                .collect();
            let mut keep = HashSet::new();
            for tab in &tab_ids {
                if keep_dirty {
                    let ids: Vec<&str> = vec![tab.as_str()];
                    let (dirty, _) = i.tracker.take_batch(&ids);
                    keep.extend(dirty);
                } else {
                    i.tracker.forget_tab(tab);
                }
            }
            i.revisions.insert(set_id.to_string(), set.revision);
            i.paused.remove(set_id);
            keep
        };
        self.emit(SetEvent::Replace {
            set_id: set_id.to_string(),
            revision: set.revision,
            stigs,
            keep,
        });
        let status = if keep_dirty && !self.inner.borrow().tracker.is_empty() {
            SaveStatus::Pending
        } else {
            SaveStatus::Idle
        };
        self.set_status(status);
        Ok(())
    }

    /// Bodies for a best-effort keepalive save of every set that already
    /// exists. Sets over the browser's keepalive cap are skipped.
    fn keepalive_requests(&self) -> Vec<(String, String)> {
        let tabs_by_set: HashMap<String, Vec<String>> = {
            let i = self.inner.borrow();
            let mut m: HashMap<String, Vec<String>> = HashMap::new();
            for tab_id in i.tracker.dirty_tabs() {
                let set = i
                    .tabs
                    .iter()
                    .find(|t| t.id == tab_id)
                    .and_then(|t| t.set_id.clone());
                if let Some(s) = set {
                    if !i.paused.contains(&s) {
                        m.entry(s).or_default().push(tab_id);
                    }
                }
            }
            m
        };
        let mut out = Vec::new();
        for (set_id, tabs) in tabs_by_set {
            let ids: Vec<&str> = tabs.iter().map(String::as_str).collect();
            let (changes, _) = self.collect(&ids);
            let revision = self.revision(&set_id).unwrap_or(0);
            if let Ok(body) = serde_json::to_string(&RulesBody {
                revision,
                changes: &changes,
            }) {
                if body.len() <= KEEPALIVE_MAX_BYTES && !changes.is_empty() {
                    out.push((
                        format!(
                            "{BACKEND}/api/checklist-sets/{}/rules",
                            crate::util::encode_uri_component(&set_id)
                        ),
                        body,
                    ));
                }
            }
        }
        out
    }

    /// `pagehide`: send what fits in a keepalive request. Results are not
    /// observed, so nothing is acknowledged locally.
    fn keepalive_flush(&self) {
        for (url, body) in self.keepalive_requests() {
            let init = web_sys::RequestInit::new();
            init.set_method("PATCH");
            init.set_body(&JsValue::from_str(&body));
            init.set_credentials(web_sys::RequestCredentials::Include);
            let headers = web_sys::Headers::new().ok();
            if let Some(h) = &headers {
                let _ = h.set("Content-Type", "application/json");
                let uid = user_id();
                if !uid.is_empty() {
                    let _ = h.set("X-User-Id", &uid);
                }
                init.set_headers(h);
            }
            // `keepalive` is not exposed by web-sys; set it on the init dict.
            let _ = js_sys::Reflect::set(&init, &JsValue::from_str("keepalive"), &JsValue::TRUE);
            let _ = window().fetch_with_str_and_init(&url, &init);
        }
    }
}

/// Create the autosaver and wire the page-level triggers: unload prompt,
/// hidden page, `pagehide`. `on_event` receives state changes for the tabs.
#[hook]
pub fn use_autosave(on_event: Callback<SetEvent>) -> Autosave {
    let status = use_state(|| SaveStatus::Idle);
    let inner = use_mut_ref(Inner::default);
    let events = use_mut_ref(|| on_event.clone());
    *events.borrow_mut() = on_event;
    let autosave = Autosave {
        inner,
        status,
        events,
    };

    {
        let a = autosave.clone();
        use_effect_with((), move |_| {
            let before = {
                let a = a.clone();
                EventListener::new_with_options(
                    &window(),
                    "beforeunload",
                    EventListenerOptions::enable_prevent_default(),
                    move |e| {
                        if a.has_unsaved() {
                            e.prevent_default();
                        }
                    },
                )
            };
            let hidden = {
                let a = a.clone();
                EventListener::new(&crate::util::document(), "visibilitychange", move |_| {
                    if crate::util::document().hidden() {
                        a.flush_soon();
                    }
                })
            };
            let pagehide = {
                let a = a.clone();
                EventListener::new(&window(), "pagehide", move |_| a.keepalive_flush())
            };
            move || {
                drop(before);
                drop(hidden);
                drop(pagehide);
            }
        });
    }
    autosave
}

/// Delete a set by id (used when it was deleted from My checklists).
pub async fn delete_set(set_id: &str) -> Result<(), String> {
    let res = api_fetch(
        "DELETE",
        &format!(
            "/api/checklist-sets/{}",
            crate::util::encode_uri_component(set_id)
        ),
    )
    .await?;
    if res.ok() {
        Ok(())
    } else {
        Err(format!("Delete failed ({})", res.status()))
    }
}

/// Create a set holding `stig_ids`; the server names it when `name` is blank.
pub async fn create_named_set(name: &str, stig_ids: &[String]) -> Result<ChecklistSet, String> {
    #[derive(Serialize)]
    struct Body<'a> {
        name: &'a str,
        #[serde(rename = "stigIds")]
        stig_ids: &'a [String],
    }
    let wire: SetDetailWire = crate::api::api_json(
        "/api/checklist-sets",
        "POST",
        Some(&Body { name, stig_ids }),
    )
    .await?;
    Ok(wire.into_set().0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_one_second_and_caps_at_thirty() {
        let mut d = 0;
        let mut seen = Vec::new();
        for _ in 0..7 {
            d = next_backoff(d, None);
            seen.push(d);
        }
        assert_eq!(seen, [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]);
    }

    #[test]
    fn backoff_honours_retry_after() {
        assert_eq!(next_backoff(0, Some(10)), 10_000);
        assert_eq!(next_backoff(8_000, Some(2)), 16_000);
    }

    #[test]
    fn failures_are_classified_by_status() {
        assert_eq!(classify(409, None, String::new()), Failure::Conflict);
        assert_eq!(classify(401, None, String::new()), Failure::SignedOut);
        assert!(matches!(
            classify(429, Some(3), String::new()),
            Failure::Transient {
                retry_after: Some(3),
                ..
            }
        ));
        assert!(matches!(
            classify(503, None, String::new()),
            Failure::Transient { .. }
        ));
        assert_eq!(
            classify(400, None, "bad".into()),
            Failure::Fatal("bad".into())
        );
        assert_eq!(
            classify(404, None, String::new()),
            Failure::Fatal("Save failed (404)".into())
        );
    }

    #[test]
    fn creating_a_set_treats_409_as_the_limit_not_a_conflict() {
        let f = classify_create(409, None, String::new());
        assert_eq!(f, Failure::Fatal(LIMIT_MSG.into()));
        let o = outcome(f, 0);
        assert_eq!(o.status, SaveStatus::Error(LIMIT_MSG.into()));
        assert_eq!(o.retry_in, None);
        assert!(!o.stop);
        // The same status while saving rules stays a conflict.
        assert_eq!(classify(409, None, String::new()), Failure::Conflict);
    }

    #[test]
    fn set_too_large_is_fatal_not_offline_or_retried() {
        let f = classify(413, None, "{\"error\":\"set_too_large\"}".into());
        assert_eq!(f, Failure::Fatal(TOO_LARGE_MSG.into()));
        let o = outcome(f, 4_000);
        assert_eq!((o.retry_in, o.stop), (None, false));
        assert_eq!(o.status.indicator().map(|i| i.0), Some("error"));
    }

    #[test]
    fn signed_out_stops_saving_and_says_so() {
        let o = outcome(classify(401, None, String::new()), 0);
        assert!(o.stop);
        assert_eq!(o.retry_in, None);
        assert_eq!(
            o.status.indicator(),
            Some(("error", "Signed out - sign in again".to_string()))
        );
    }

    #[test]
    fn transient_failures_retry_with_growing_backoff_and_conflict_waits() {
        let t = |s| outcome(classify(s, None, String::new()), 1_000);
        assert_eq!(t(503).retry_in, Some(2_000));
        assert_eq!(t(429).status, SaveStatus::Error("Too many requests".into()));
        let o = outcome(Failure::Conflict, 0);
        assert_eq!(
            (o.status, o.retry_in, o.stop),
            (SaveStatus::Conflict, None, false)
        );
        let net = outcome(
            Failure::Transient {
                retry_after: None,
                offline: true,
                msg: "x".into(),
            },
            0,
        );
        assert_eq!(
            (net.status, net.retry_in),
            (SaveStatus::Offline, Some(1_000))
        );
    }

    #[test]
    fn viewers_local_files_and_signed_out_sessions_track_nothing() {
        // enabled is false for the viewer role, so no set is created and no PATCH sent.
        assert!(!can_track(false, false, Some("edge")));
        assert!(!can_track(true, false, None));
        assert!(!can_track(true, true, Some("edge")));
        assert!(can_track(true, false, Some("edge")));
    }

    #[test]
    fn indicator_text_matches_the_status() {
        assert_eq!(SaveStatus::Idle.indicator(), None);
        assert_eq!(
            SaveStatus::Pending.indicator().map(|i| i.1),
            Some("Unsaved changes".into())
        );
        assert_eq!(
            SaveStatus::Saving.indicator().map(|i| i.1),
            Some("Saving...".into())
        );
        assert_eq!(
            SaveStatus::Saved("09:05".into()).indicator().map(|i| i.1),
            Some("Saved 09:05".into())
        );
        assert_eq!(
            SaveStatus::Error("x".into()).indicator().map(|i| i.1),
            Some("Save failed: x".into())
        );
        assert_eq!(
            SaveStatus::Offline.indicator().map(|i| i.1),
            Some("Offline - will retry".into())
        );
    }
}
