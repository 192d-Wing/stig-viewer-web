//! Test helper: capture `target: "audit"` tracing events as field maps.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing_subscriber::{layer::SubscriberExt, Layer};

pub(crate) type Line = BTreeMap<String, String>;

#[derive(Clone, Default)]
pub(crate) struct Captured(Arc<Mutex<Vec<Line>>>);

impl Captured {
    /// Forget everything captured so far.
    pub fn clear(&self) {
        if let Ok(mut l) = self.0.lock() {
            l.clear();
        }
    }

    /// Drain the buffer, asserting exactly one line arrived since the last
    /// `clear`/`take_one`. Loud on zero (thread-local sink) and on extras.
    pub fn take_one(&self) -> Line {
        let mut l = self
            .0
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default();
        assert_eq!(l.len(), 1, "expected exactly one new audit line, got {l:?}");
        l.remove(0)
    }

    /// Every captured line. Panics when nothing was captured: the sink is
    /// thread-local, so a multi-thread runtime would otherwise pass vacuously.
    pub fn lines(&self) -> Vec<Line> {
        let l = self.0.lock().map(|l| l.clone()).unwrap_or_default();
        assert!(
            !l.is_empty(),
            "no audit events captured (capture is thread-local; use a current-thread runtime)"
        );
        l
    }
    /// `(action, outcome, reason)` of every captured line; empty string when absent.
    pub fn summary(&self) -> Vec<(String, String, String)> {
        let get = |l: &Line, k: &str| l.get(k).cloned().unwrap_or_default();
        self.lines()
            .iter()
            .map(|l| (get(l, "action"), get(l, "outcome"), get(l, "reason")))
            .collect()
    }
}

struct Fields(Line);
impl Visit for Fields {
    fn record_debug(&mut self, f: &Field, v: &dyn Debug) {
        self.0.insert(
            f.name().to_string(),
            format!("{v:?}").trim_matches('"').to_string(),
        );
    }
    fn record_str(&mut self, f: &Field, v: &str) {
        self.0.insert(f.name().to_string(), v.to_string());
    }
}

thread_local! {
    static SINK: std::cell::RefCell<Option<Captured>> = const { std::cell::RefCell::new(None) };
}

/// Process-wide layer that forwards audit events to the current thread's sink.
/// Installed once as the global default so callsite interest never caches "off"
/// when tests run in parallel.
struct Cap;
impl<S: tracing::Subscriber> Layer<S> for Cap {
    fn on_event(&self, e: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if e.metadata().target() != "audit" {
            return;
        }
        SINK.with(|s| {
            if let Some(c) = s.borrow().as_ref() {
                let mut f = Fields(Line::new());
                e.record(&mut f);
                if let Ok(mut l) = c.0.lock() {
                    l.push(f.0);
                }
            }
        });
    }
}

pub(crate) struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        SINK.with(|s| *s.borrow_mut() = None);
    }
}

/// Capture audit events on this thread until the guard drops. Use with a
/// current-thread runtime (`#[tokio::test]` / `#[sqlx::test]` default).
pub(crate) fn capture() -> (Captured, Guard) {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry().with(Cap));
    });
    let c = Captured::default();
    SINK.with(|s| *s.borrow_mut() = Some(c.clone()));
    (c, Guard)
}
