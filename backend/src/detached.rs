//! Work the client cannot cancel.
//!
//! A handler whose change and audit event must both land runs them as one
//! spawned task via [`run`]: dropping the handler future (client abort, proxy
//! timeout) only stops waiting, the task still finishes. A [`Tracker`] counts
//! the tasks in flight so shutdown and tests can wait for them with
//! [`Tracker::idle`].
//!
//! Only tasks started through [`run`] are tracked.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::http::StatusCode;
use tokio::sync::Notify;

/// In-flight count of detached tasks, with a wakeup for [`Tracker::idle`].
#[derive(Debug, Default)]
pub struct Tracker {
    in_flight: AtomicUsize,
    idle: Notify,
}

/// Decrements the tracker's count when dropped (task finished or panicked).
#[derive(Debug)]
struct Guard {
    tracker: Arc<Tracker>,
}

impl Tracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Count one more task until the returned guard is dropped.
    fn enter(self: &Arc<Self>) -> Guard {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        Guard {
            tracker: Arc::clone(self),
        }
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Resolve once no tracked task is in flight.
    pub async fn idle(&self) {
        loop {
            // Register before checking so a wakeup between the two is kept.
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.in_flight() == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.tracker.in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.tracker.idle.notify_waiters();
        }
    }
}

/// Run `fut` as a spawned task and wait for it. If the caller is dropped the
/// task keeps running to completion. A panicked task is logged as
/// `"{what} task failed"` and answered with 500.
pub async fn run<T: Send + 'static>(
    tracker: &Arc<Tracker>,
    what: &'static str,
    fut: impl Future<Output = T> + Send + 'static,
) -> Result<T, StatusCode> {
    let guard = tracker.enter();
    let handle = tokio::spawn(async move {
        let _guard = guard;
        fut.await
    });
    handle.await.map_err(|e| {
        tracing::error!("{what} task failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use std::pin::pin;
    use std::task::Poll;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn a_dropped_caller_does_not_stop_the_task() {
        let tracker = Tracker::new();
        let (open, gate) = oneshot::channel::<()>();
        let (done_tx, done_rx) = oneshot::channel::<u8>();
        {
            let mut call = pin!(run(&tracker, "test", async move {
                let _ = gate.await;
                let _ = done_tx.send(7);
            }));
            // Submitted on first poll; still waiting on the gate.
            let pending = poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx).is_pending())).await;
            assert!(pending);
        } // caller dropped here
        assert_eq!(tracker.in_flight(), 1);
        let _ = open.send(());
        tracker.idle().await;
        assert_eq!(done_rx.await, Ok(7));
        assert_eq!(tracker.in_flight(), 0);
    }

    #[tokio::test]
    async fn idle_resolves_at_once_with_nothing_in_flight() {
        Tracker::new().idle().await;
    }

    #[tokio::test]
    async fn a_panic_returns_500_and_releases_the_guard() {
        let tracker = Tracker::new();
        let r = run(&tracker, "test", async { panic!("boom") }).await;
        let r: Result<(), StatusCode> = r;
        assert_eq!(r, Err(StatusCode::INTERNAL_SERVER_ERROR));
        tracker.idle().await;
        assert_eq!(tracker.in_flight(), 0);
    }

    #[tokio::test]
    async fn a_value_is_returned() {
        let tracker = Tracker::new();
        assert_eq!(run(&tracker, "test", async { 5 }).await, Ok(5));
    }
}
