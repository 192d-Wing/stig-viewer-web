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

use crate::api::{
    api_request_timed, set_json, user_id, FetchFailure, TimedResponse, BACKEND,
    SET_REQUEST_TIMEOUT_MS,
};
use crate::model::{
    split_batches, ChecklistSet, DirtyTracker, ServerRule, SetRuleChange, StigTab, BATCH_MAX_BYTES,
    BATCH_MAX_CHANGES,
};
use crate::util::{new_request_id, now_ms, spawn_local, window};

/// Longest an edit may wait before it is sent, however long typing continues.
const MAX_WAIT_MS: f64 = 15_000.0;
const DEBOUNCE_MS: u32 = 3_000;
const BACKOFF_START_MS: u32 = 1_000;
const BACKOFF_MAX_MS: u32 = 30_000;
/// Browsers cap `keepalive` request bodies near 64 KiB.
const KEEPALIVE_MAX_BYTES: usize = 60 * 1024;
const LIMIT_MSG: &str = "You have reached the limit of 50 checklists. Delete one in My checklists.";
const TOO_LARGE_MSG: &str =
    "This checklist is over the 4 MB limit. Shorten or remove some notes, or start another checklist.";

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
    /// Reused when a create is retried, so the server makes one set.
    #[serde(rename = "clientRequestId", skip_serializing_if = "Option::is_none")]
    client_request_id: Option<&'a str>,
}

#[derive(Serialize)]
struct RulesBody<'a> {
    revision: i64,
    changes: &'a [SetRuleChange],
    /// Names this request so the server can recognise an exact retry.
    #[serde(rename = "saveId", skip_serializing_if = "Option::is_none")]
    save_id: Option<&'a str>,
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
    let wire: SetDetailWire = set_json(
        "GET",
        &format!(
            "/api/checklist-sets/{}",
            crate::util::encode_uri_component(set_id)
        ),
        None::<&()>,
        SET_REQUEST_TIMEOUT_MS,
    )
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
    /// Create token per tab, kept across retries of its set creation.
    create_keys: HashMap<String, String>,
    /// A save whose outcome is unknown (timeout, dropped connection, 5xx),
    /// per set. It is resent unchanged before anything newer, so the server
    /// can recognise it if it already applied.
    in_doubt: HashMap<String, InDoubt>,
    /// Bumped whenever in-doubt state is discarded on purpose (server state
    /// taken, set forgotten), so a save started earlier cannot re-stash.
    epoch: u32,
    paused: HashSet<String>,
    running: bool,
    stopped: bool,
    debounce_gen: u32,
    first_edit_at: Option<f64>,
    backoff_ms: u32,
    last_saved: Option<String>,
}

/// The exact JSON body (base revision and `saveId` included) of an
/// unconfirmed save.
#[derive(Clone, Debug, PartialEq)]
struct InDoubt {
    body: String,
    /// The tabs and dirty-tracker high-water mark the body covers, when it
    /// holds every dirty edit of those tabs (a single-batch save). Once the
    /// body is confirmed applied those edits are acknowledged, so they are
    /// not written a second time. `None` for one batch of several.
    settles: Option<(Vec<String>, u64)>,
}

/// What an answer to a resent in-doubt body means.
#[derive(Debug, PartialEq)]
enum Resend {
    /// Applied (now or earlier): take the revision and go on.
    Applied,
    /// A real conflict: another writer got in between.
    Conflict,
    /// Not retryable; forget the body and report the failure.
    Drop,
    /// Still unknown; keep the body for the next attempt.
    Keep,
}

fn after_resend(status: u16) -> Resend {
    match status {
        200..=299 => Resend::Applied,
        409 => Resend::Conflict,
        429 | 500..=599 => Resend::Keep,
        _ => Resend::Drop,
    }
}

/// Whether a failed save is remembered as in doubt: only a transient failure
/// of a request that carried a token, and only if nothing discarded in-doubt
/// state since the request started.
fn stash_allowed(transient: bool, has_token: bool, epoch_then: u32, epoch_now: u32) -> bool {
    transient && has_token && epoch_then == epoch_now
}

/// What the `pagehide` keepalive does for a set.
#[derive(Debug, PartialEq)]
enum Keepalive {
    /// A save is running or its answer is awaited; it settles the set.
    Skip,
    /// Resend the stashed body unchanged.
    Stashed,
    /// Build a new body from the dirty rules.
    Build,
}

fn keepalive_action(running: bool, stashed: bool) -> Keepalive {
    if running {
        Keepalive::Skip
    } else if stashed {
        Keepalive::Stashed
    } else {
        Keepalive::Build
    }
}

/// A batch was acknowledged: whatever was in doubt for the set is settled.
fn settle_success(in_doubt: &mut HashMap<String, InDoubt>, set_id: &str) {
    in_doubt.remove(set_id);
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
        i.create_keys
            .retain(|tab_id, _| live.contains(tab_id.as_str()));
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
        i.in_doubt.remove(set_id);
        i.epoch = i.epoch.wrapping_add(1);
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

    /// One JSON request under the set deadline, headers and body together.
    /// Network failures and timeouts are retried later.
    async fn send_json(method: &str, path: &str, json: &str) -> Result<TimedResponse, Failure> {
        api_request_timed(method, path, Some(json), SET_REQUEST_TIMEOUT_MS)
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

    fn encode<B: Serialize + ?Sized>(body: &B) -> Result<String, Failure> {
        serde_json::to_string(body)
            .map_err(|e| Failure::Fatal(format!("Could not encode the save: {e}")))
    }

    async fn create_set(&self, tab: &StigTab) -> Result<String, Failure> {
        let Some(catalog_id) = tab.catalog_id.as_deref() else {
            return Err(Failure::Fatal(
                "Only library STIGs are saved to your account".into(),
            ));
        };
        // One token per tab, reused by every retry of this create.
        let key = {
            let mut i = self.inner.borrow_mut();
            match i.create_keys.get(&tab.id) {
                Some(k) => Some(k.clone()),
                None => {
                    let k = new_request_id();
                    if let Some(k) = &k {
                        i.create_keys.insert(tab.id.clone(), k.clone());
                    }
                    k
                }
            }
        };
        let json = Self::encode(&CreateBody {
            stig_ids: vec![catalog_id],
            client_request_id: key.as_deref(),
        })?;
        let res = Self::send_json("POST", "/api/checklist-sets", &json).await?;
        if !res.ok() {
            return Err(classify_create(res.status, res.retry_after, res.body));
        }
        let wire = res
            .json::<SetDetailWire>()
            .map_err(|e| Failure::Fatal(format!("Unexpected response: {e}")))?;
        let (set, _) = wire.into_set();
        {
            let mut i = self.inner.borrow_mut();
            i.create_keys.remove(&tab.id);
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

    /// Resend the set's unconfirmed save, unchanged. `Ok` once it is settled
    /// (applied, or nothing was in doubt); the server then answers a copy of an
    /// applied save with the current revision instead of a conflict.
    async fn resolve_in_doubt(&self, set_id: &str, path: &str) -> Result<(), Failure> {
        let Some(d) = self.inner.borrow().in_doubt.get(set_id).cloned() else {
            return Ok(());
        };
        // A transient failure here returns early and leaves the body stashed.
        let res = Self::send_json("PATCH", path, &d.body).await?;
        match after_resend(res.status) {
            Resend::Applied => {
                let ok = res
                    .json::<AutosaveWire>()
                    .map_err(|e| Failure::Fatal(format!("Unexpected response: {e}")))?;
                {
                    let mut i = self.inner.borrow_mut();
                    i.in_doubt.remove(set_id);
                    i.revisions.insert(set_id.to_string(), ok.revision);
                    // The body's edits are now stored. Acknowledge them when
                    // the body covered them all; edits made since (or in
                    // other batches) stay dirty and go on this revision.
                    if let Some((tabs, high_water)) = &d.settles {
                        let ids: Vec<&str> = tabs.iter().map(String::as_str).collect();
                        i.tracker.ack(&ids, *high_water);
                    }
                }
                self.emit(SetEvent::Saved {
                    set_id: set_id.to_string(),
                    revision: ok.revision,
                });
                Ok(())
            }
            Resend::Conflict => {
                let mut i = self.inner.borrow_mut();
                i.in_doubt.remove(set_id);
                i.paused.insert(set_id.to_string());
                Err(Failure::Conflict)
            }
            Resend::Drop => {
                self.inner.borrow_mut().in_doubt.remove(set_id);
                Err(classify(res.status, res.retry_after, res.body))
            }
            Resend::Keep => Err(classify(res.status, res.retry_after, res.body)),
        }
    }

    async fn send_set(&self, set_id: &str, tab_ids: &[String]) -> Result<(), Failure> {
        let path = format!(
            "/api/checklist-sets/{}/rules",
            crate::util::encode_uri_component(set_id)
        );
        self.resolve_in_doubt(set_id, &path).await?;
        let ids: Vec<&str> = tab_ids.iter().map(String::as_str).collect();
        let epoch = self.inner.borrow().epoch;
        let (changes, high_water) = self.collect(&ids);
        let mut revision = self.revision(set_id).unwrap_or(0);
        let batches = split_batches(changes, BATCH_MAX_CHANGES, BATCH_MAX_BYTES);
        let settles = (batches.len() == 1).then(|| (tab_ids.to_vec(), high_water));
        for batch in batches {
            let save_id = new_request_id();
            let json = Self::encode(&RulesBody {
                revision,
                changes: &batch,
                save_id: save_id.as_deref(),
            })?;
            let failed = |this: &Self, f: Failure| {
                let mut i = this.inner.borrow_mut();
                let transient = matches!(f, Failure::Transient { .. });
                if stash_allowed(transient, save_id.is_some(), epoch, i.epoch) {
                    i.in_doubt.insert(
                        set_id.to_string(),
                        InDoubt {
                            body: json.clone(),
                            settles: settles.clone(),
                        },
                    );
                }
                f
            };
            let res = match Self::send_json("PATCH", &path, &json).await {
                Ok(r) => r,
                Err(f) => return Err(failed(self, f)),
            };
            if !res.ok() {
                let f = classify(res.status, res.retry_after, res.body);
                if f == Failure::Conflict {
                    self.inner.borrow_mut().paused.insert(set_id.to_string());
                }
                return Err(failed(self, f));
            }
            let ok = res
                .json::<AutosaveWire>()
                .map_err(|e| Failure::Fatal(format!("Unexpected response: {e}")))?;
            revision = ok.revision;
            let mut i = self.inner.borrow_mut();
            i.revisions.insert(set_id.to_string(), revision);
            settle_success(&mut i.in_doubt, set_id);
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
            i.in_doubt.remove(set_id);
            i.epoch = i.epoch.wrapping_add(1);
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
            let url = format!(
                "{BACKEND}/api/checklist-sets/{}/rules",
                crate::util::encode_uri_component(&set_id)
            );
            // An unconfirmed save goes first and unchanged: a page restored
            // from the back-forward cache resolves it before anything else.
            let (running, pending) = {
                let i = self.inner.borrow();
                (i.running, i.in_doubt.get(&set_id).cloned())
            };
            match keepalive_action(running, pending.is_some()) {
                // A save for this set is already in flight. Sending a second
                // body could double-apply or conflict; its edits stay dirty
                // and the `beforeunload` prompt covers a real close.
                Keepalive::Skip => continue,
                Keepalive::Stashed => {
                    if let Some(d) = pending.filter(|d| d.body.len() <= KEEPALIVE_MAX_BYTES) {
                        out.push((url, d.body));
                    }
                    continue;
                }
                Keepalive::Build => {}
            }
            let ids: Vec<&str> = tabs.iter().map(String::as_str).collect();
            let (changes, high_water) = self.collect(&ids);
            let revision = self.revision(&set_id).unwrap_or(0);
            let save_id = new_request_id();
            if let Ok(body) = serde_json::to_string(&RulesBody {
                revision,
                changes: &changes,
                save_id: save_id.as_deref(),
            }) {
                if body.len() <= KEEPALIVE_MAX_BYTES && !changes.is_empty() {
                    // The result is never seen, so treat it as in doubt.
                    if save_id.is_some() {
                        self.inner.borrow_mut().in_doubt.insert(
                            set_id.clone(),
                            InDoubt {
                                body: body.clone(),
                                settles: Some((tabs.clone(), high_water)),
                            },
                        );
                    }
                    out.push((url, body));
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

/// Delete a set by id (used when it was deleted from My checklists). A 404
/// counts as done, so retrying a delete that already applied is not an error.
pub async fn delete_set(set_id: &str) -> Result<(), String> {
    let path = format!(
        "/api/checklist-sets/{}",
        crate::util::encode_uri_component(set_id)
    );
    let res = api_request_timed("DELETE", &path, None, SET_REQUEST_TIMEOUT_MS)
        .await
        .map_err(|f| f.message())?;
    if res.ok() || res.status == 404 {
        Ok(())
    } else {
        Err(format!("Delete failed ({})", res.status))
    }
}

/// Create a set holding `stig_ids`; the server names it when `name` is blank.
/// `request_id` is reused when the same create is retried.
pub async fn create_named_set(
    name: &str,
    stig_ids: &[String],
    request_id: Option<&str>,
) -> Result<ChecklistSet, String> {
    #[derive(Serialize)]
    struct Body<'a> {
        name: &'a str,
        #[serde(rename = "stigIds")]
        stig_ids: &'a [String],
        #[serde(rename = "clientRequestId", skip_serializing_if = "Option::is_none")]
        client_request_id: Option<&'a str>,
    }
    let wire: SetDetailWire = set_json(
        "POST",
        "/api/checklist-sets",
        Some(&Body {
            name,
            stig_ids,
            client_request_id: request_id,
        }),
        SET_REQUEST_TIMEOUT_MS,
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

    #[test]
    fn a_resent_save_is_settled_by_its_status() {
        assert_eq!(after_resend(200), Resend::Applied);
        assert_eq!(after_resend(409), Resend::Conflict);
        assert_eq!(after_resend(503), Resend::Keep);
        assert_eq!(after_resend(429), Resend::Keep);
        for s in [400, 401, 404, 413] {
            assert_eq!(after_resend(s), Resend::Drop);
        }
    }

    #[test]
    fn request_tokens_serialize_in_camel_case_and_are_optional() {
        let create = serde_json::to_string(&CreateBody {
            stig_ids: vec!["a"],
            client_request_id: Some("k"),
        })
        .unwrap();
        assert_eq!(create, r#"{"stigIds":["a"],"clientRequestId":"k"}"#);
        let bare = serde_json::to_string(&CreateBody {
            stig_ids: vec!["a"],
            client_request_id: None,
        })
        .unwrap();
        assert_eq!(bare, r#"{"stigIds":["a"]}"#);
        let save = serde_json::to_string(&RulesBody {
            revision: 3,
            changes: &[],
            save_id: Some("s"),
        })
        .unwrap();
        assert_eq!(save, r#"{"revision":3,"changes":[],"saveId":"s"}"#);
    }

    #[test]
    fn only_a_transient_tokened_save_is_stashed_and_not_after_a_reset() {
        assert!(stash_allowed(true, true, 3, 3));
        assert!(!stash_allowed(false, true, 3, 3));
        assert!(!stash_allowed(true, false, 3, 3));
        // take_server_state / forget_set ran while the request was in flight.
        assert!(!stash_allowed(true, true, 3, 4));
    }

    #[test]
    fn keepalive_skips_a_running_save_and_resends_a_stash_unchanged() {
        assert_eq!(keepalive_action(true, false), Keepalive::Skip);
        assert_eq!(keepalive_action(true, true), Keepalive::Skip);
        assert_eq!(keepalive_action(false, true), Keepalive::Stashed);
        assert_eq!(keepalive_action(false, false), Keepalive::Build);
    }

    #[test]
    fn an_acknowledged_batch_clears_the_stash_for_that_set_only() {
        let mut m = HashMap::new();
        m.insert(
            "a".to_string(),
            InDoubt {
                body: "x".into(),
                settles: None,
            },
        );
        m.insert(
            "b".to_string(),
            InDoubt {
                body: "y".into(),
                settles: None,
            },
        );
        settle_success(&mut m, "a");
        assert!(!m.contains_key("a") && m.contains_key("b"));
    }
}
