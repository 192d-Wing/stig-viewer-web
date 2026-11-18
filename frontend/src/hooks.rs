//! Cross-cutting hooks: online status and URL-synced state.

use gloo_events::EventListener;
use std::collections::BTreeMap;
use std::rc::Rc;
use yew::prelude::*;

use crate::util::window;

/// `navigator.onLine`, kept fresh by the online/offline window events.
#[hook]
pub fn use_online() -> bool {
    let online = use_state(|| window().navigator().on_line());
    {
        let online = online.clone();
        use_effect_with((), move |_| {
            let o1 = online.clone();
            let on = EventListener::new(&window(), "online", move |_| o1.set(true));
            let o2 = online.clone();
            let off = EventListener::new(&window(), "offline", move |_| o2.set(false));
            move || {
                drop(on);
                drop(off);
            }
        });
    }
    *online
}

/// Run `f` every `ms` milliseconds while mounted (and whenever `deps` change,
/// restart the timer). Does not fire immediately.
#[hook]
pub fn use_interval<D: PartialEq + Clone + 'static>(deps: D, ms: u32, f: Callback<()>) {
    use_effect_with((deps, ms), move |_| {
        let handle = gloo_timers::callback::Interval::new(ms, move || f.emit(()));
        move || drop(handle)
    });
}

/// A typed value stored in the query string.
#[derive(Clone, Debug, PartialEq)]
pub enum UrlVal {
    Str(String),
    Bool(bool),
    Num(f64),
    List(Vec<String>),
}

impl From<&str> for UrlVal {
    fn from(s: &str) -> Self {
        UrlVal::Str(s.to_string())
    }
}
impl From<String> for UrlVal {
    fn from(s: String) -> Self {
        UrlVal::Str(s)
    }
}
impl From<bool> for UrlVal {
    fn from(b: bool) -> Self {
        UrlVal::Bool(b)
    }
}
impl From<f64> for UrlVal {
    fn from(n: f64) -> Self {
        UrlVal::Num(n)
    }
}
impl From<Vec<String>> for UrlVal {
    fn from(v: Vec<String>) -> Self {
        UrlVal::List(v)
    }
}

impl UrlVal {
    /// Coerce a raw query value into the same variant as `default`. Anything
    /// that doesn't parse falls back to the default so a hand-typed
    /// `?pastDue=garbage` can't break a component expecting a bool.
    fn decode(raw: Option<String>, default: &UrlVal) -> UrlVal {
        let Some(raw) = raw else {
            return default.clone();
        };
        match default {
            UrlVal::Bool(_) => match raw.as_str() {
                "true" => UrlVal::Bool(true),
                "false" => UrlVal::Bool(false),
                _ => default.clone(),
            },
            UrlVal::Num(_) => match raw.trim().parse::<f64>() {
                Ok(n) if n.is_finite() => UrlVal::Num(n),
                _ => default.clone(),
            },
            UrlVal::List(_) => {
                if raw.is_empty() {
                    UrlVal::List(vec![])
                } else {
                    UrlVal::List(raw.split(',').map(str::to_string).collect())
                }
            }
            UrlVal::Str(_) => UrlVal::Str(raw),
        }
    }

    fn encode(&self) -> String {
        match self {
            UrlVal::Str(s) => s.clone(),
            UrlVal::Bool(b) => b.to_string(),
            UrlVal::Num(n) => n.to_string(),
            UrlVal::List(v) => v.join(","),
        }
    }
}

/// Snapshot of the URL-synced keys a component owns.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct UrlState(Rc<BTreeMap<&'static str, UrlVal>>);

impl UrlState {
    pub fn get(&self, key: &str) -> Option<&UrlVal> {
        self.0.get(key)
    }
    pub fn str(&self, key: &str) -> String {
        match self.0.get(key) {
            Some(UrlVal::Str(s)) => s.clone(),
            _ => String::new(),
        }
    }
    pub fn bool(&self, key: &str) -> bool {
        matches!(self.0.get(key), Some(UrlVal::Bool(true)))
    }
    pub fn num(&self, key: &str) -> f64 {
        match self.0.get(key) {
            Some(UrlVal::Num(n)) => *n,
            _ => 0.0,
        }
    }
    pub fn list(&self, key: &str) -> Vec<String> {
        match self.0.get(key) {
            Some(UrlVal::List(v)) => v.clone(),
            _ => vec![],
        }
    }
}

fn read_from_url(defaults: &[(&'static str, UrlVal)]) -> UrlState {
    let search = window().location().search().unwrap_or_default();
    let params = web_sys::UrlSearchParams::new_with_str(&search).ok();
    let map = defaults
        .iter()
        .map(|(k, dv)| {
            (
                *k,
                UrlVal::decode(params.as_ref().and_then(|p| p.get(k)), dv),
            )
        })
        .collect();
    UrlState(Rc::new(map))
}

/// Sync a slice of state to `window.location.search`. The hook owns the keys
/// listed in `defaults` and ignores all others, so several pages can each
/// read/write their own slice without trampling each other.
///
/// - Reads initial values from the URL on mount (with type coercion).
/// - Writes back via `history.replaceState` (no history entry per keystroke).
/// - Listens for popstate so back/forward updates local state.
///
/// `defaults` is captured on first render; pass a stable list.
/// Returns the state and a `patch` callback taking the keys to change.
#[hook]
pub fn use_url_state(
    defaults: Vec<(&'static str, UrlVal)>,
) -> (UrlState, Callback<Vec<(&'static str, UrlVal)>>) {
    let defaults = use_memo((), |_| defaults);
    let state = {
        let defaults = defaults.clone();
        use_state(move || read_from_url(&defaults))
    };

    // Push state changes into the URL.
    {
        let defaults = defaults.clone();
        use_effect_with((*state).clone(), move |state| {
            let loc = window().location();
            let search = loc.search().unwrap_or_default();
            if let Ok(params) = web_sys::UrlSearchParams::new_with_str(&search) {
                for (k, dv) in defaults.iter() {
                    let v = state.get(k).unwrap_or(dv);
                    if v == dv {
                        params.delete(k);
                    } else {
                        params.set(k, &v.encode());
                    }
                }
                let qs: String = params.to_string().into();
                let path = loc.pathname().unwrap_or_default();
                let hash = loc.hash().unwrap_or_default();
                let next = if qs.is_empty() {
                    format!("{path}{hash}")
                } else {
                    format!("{path}?{qs}{hash}")
                };
                let current = format!("{path}{search}{hash}");
                if next != current {
                    if let Ok(h) = window().history() {
                        let _ =
                            h.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&next));
                    }
                }
            }
        });
    }

    // Pick up back/forward navigation.
    {
        let state = state.clone();
        let defaults = defaults.clone();
        use_effect_with((), move |_| {
            let l = EventListener::new(&window(), "popstate", move |_| {
                state.set(read_from_url(&defaults));
            });
            move || drop(l)
        });
    }

    // Mirror of the latest value so several patches fired from one event
    // handler compose instead of each starting from the render-time snapshot.
    let latest = use_mut_ref(|| (*state).clone());
    *latest.borrow_mut() = (*state).clone();

    let patch = {
        let state = state.clone();
        Callback::from(move |updates: Vec<(&'static str, UrlVal)>| {
            let mut map = (*latest.borrow().0).clone();
            for (k, v) in updates {
                map.insert(k, v);
            }
            let next = UrlState(Rc::new(map));
            *latest.borrow_mut() = next.clone();
            state.set(next);
        })
    };

    ((*state).clone(), patch)
}
