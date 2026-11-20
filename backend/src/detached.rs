//! Work the client cannot cancel.
//!
//! A handler whose change and audit event must both land runs them as one
//! spawned task via [`run`] or [`run_bounded`]: dropping the handler future
//! (client abort, proxy timeout) only stops waiting, the task still finishes.
//! [`run_bounded`] adds a server deadline that cancels only work outside the
//! [`Shield`]; a shielded write gets a grace period and is abandoned only at
//! the hard cap. A [`Tracker`] counts the tasks in flight so shutdown and
//! tests can wait for them with [`Tracker::idle`].
//!
//! Only tasks started through [`run`] or [`run_bounded`] are tracked.
//!
//! The number of tasks is bounded by the admission permit (`api::admission`)
//! carried in the `RequestCtx` that each work function takes by value: at most
//! 32 in all and 4 per user, refused with 429/503 before the task is spawned.
//! Login tasks (pre-auth, no permit) are bounded per IP by the
//! `PreAuthLimiter`, which `claim_step` and `acs_core` check before the spawn;
//! there is no global ceiling.

use axum::http::StatusCode;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::{timeout_at, Instant};

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

/// Server-side time limits for one detached task.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Past this the work is dropped, unless it holds the [`Shield`].
    pub deadline: Duration,
    /// Extra time a shielded write gets past `deadline` before it is abandoned.
    pub write_grace: Duration,
}

/// Marks the stretch of work that must not be cut at the deadline: from just
/// before the first mutating call to after the last audit record.
#[derive(Debug, Clone, Default)]
pub struct Shield(Arc<AtomicUsize>);

/// Holds the [`Shield`] until dropped.
#[derive(Debug)]
pub struct ShieldGuard(Arc<AtomicUsize>);

impl Shield {
    pub fn hold(&self) -> ShieldGuard {
        self.0.fetch_add(1, Ordering::SeqCst);
        ShieldGuard(Arc::clone(&self.0))
    }

    fn held(&self) -> bool {
        self.0.load(Ordering::SeqCst) > 0
    }
}

impl Drop for ShieldGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Why [`run_bounded`] returned no value.
#[derive(Debug, PartialEq)]
pub enum Stopped {
    Panicked,
    Deadline,
}

/// Names a task in logs.
#[derive(Debug, Clone)]
pub struct Origin {
    pub what: &'static str,
    pub user_id: String,
    pub request_id: String,
}

/// Run `fut` as a spawned task and wait for it, with no server deadline. If
/// the caller is dropped the task keeps running. A panicked task is logged as
/// `"{what} task failed"` and answers 500.
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

/// Run the work as a spawned task and wait for it. If the caller is dropped
/// the task keeps running; the server deadline lives inside the task, so it
/// applies either way. A panicked task is logged as `"{what} task failed"`.
///
/// At `limits.deadline` the work is dropped unless it holds the [`Shield`]
/// (nothing is half-done outside it). A shielded write runs on until
/// `deadline + write_grace`; only then is it abandoned, which can leave a
/// committed change without its audit event. That is the one exception to
/// "the change and its event both land", and it is logged on target `audit`.
pub async fn run_bounded<T, Fut>(
    tracker: &Arc<Tracker>,
    origin: Origin,
    limits: Limits,
    work: impl FnOnce(Shield) -> Fut + Send + 'static,
) -> Result<T, Stopped>
where
    T: Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    // Bound first so it drops last: `idle()` resolves only once the work
    // future has been dropped.
    let guard = tracker.enter();
    let what = origin.what;
    let handle = tokio::spawn(async move {
        let _guard = guard;
        let shield = Shield::default();
        let fut = work(shield.clone());
        tokio::pin!(fut);
        let start = Instant::now();
        if let Ok(v) = timeout_at(start + limits.deadline, &mut fut).await {
            return Ok(v);
        }
        if !shield.held() {
            tracing::warn!(
                what = origin.what, user = %origin.user_id, request = %origin.request_id,
                "server deadline exceeded, work dropped"
            );
            return Err(Stopped::Deadline);
        }
        if let Ok(v) = timeout_at(start + limits.deadline + limits.write_grace, &mut fut).await {
            return Ok(v);
        }
        if shield.held() {
            tracing::error!(
                target: "audit",
                what = origin.what, user = %origin.user_id, request = %origin.request_id,
                "shielded write abandoned at the hard cap; the change may have committed without its audit event"
            );
        } else {
            tracing::warn!(
                what = origin.what, user = %origin.user_id, request = %origin.request_id,
                "server deadline exceeded, work dropped"
            );
        }
        Err(Stopped::Deadline)
    });
    match handle.await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{what} task failed: {e}");
            Err(Stopped::Panicked)
        }
    }
}

/// Test helper: poll `f` until a task has been spawned on `tracker`, then drop
/// `f` (the caller going away). Panics if `f` completes first.
#[cfg(test)]
pub(crate) async fn abort_once_spawned<F: Future>(tracker: &Tracker, f: F) {
    let mut f = std::pin::pin!(f);
    std::future::poll_fn(|cx| {
        if f.as_mut().poll(cx).is_ready() {
            panic!("future completed before a task was spawned");
        }
        if tracker.in_flight() >= 1 {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use std::pin::pin;
    use std::sync::atomic::AtomicBool;
    use std::task::Poll;
    use tokio::sync::oneshot;

    const LIMITS: Limits = Limits {
        deadline: Duration::from_secs(10),
        write_grace: Duration::from_secs(5),
    };

    fn origin() -> Origin {
        Origin {
            what: "test",
            user_id: "u".into(),
            request_id: "r".into(),
        }
    }

    /// Sets the flag when dropped.
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_dropped_caller_does_not_stop_the_task() {
        let tracker = Tracker::new();
        let (open, gate) = oneshot::channel::<()>();
        let (done_tx, done_rx) = oneshot::channel::<u8>();
        {
            let mut call = pin!(run_bounded(
                &tracker,
                origin(),
                LIMITS,
                move |_| async move {
                    let _ = gate.await;
                    let _ = done_tx.send(7);
                }
            ));
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
    async fn a_panic_is_reported_and_releases_the_guard() {
        let tracker = Tracker::new();
        let r: Result<(), Stopped> =
            run_bounded(&tracker, origin(), LIMITS, |_| async { panic!("boom") }).await;
        assert_eq!(r, Err(Stopped::Panicked));
        tracker.idle().await;
        assert_eq!(tracker.in_flight(), 0);
    }

    #[tokio::test]
    async fn a_value_is_returned() {
        let tracker = Tracker::new();
        assert_eq!(
            run_bounded(&tracker, origin(), LIMITS, |_| async { 5 }).await,
            Ok(5)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unshielded_work_is_dropped_at_the_deadline() {
        let tracker = Tracker::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = dropped.clone();
        let r: Result<(), Stopped> = run_bounded(&tracker, origin(), LIMITS, move |_| async move {
            let _flag = DropFlag(flag);
            std::future::pending::<()>().await;
        })
        .await;
        assert_eq!(r, Err(Stopped::Deadline));
        tracker.idle().await;
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn shielded_work_finishing_within_the_grace_is_kept() {
        let tracker = Tracker::new();
        let r = run_bounded(&tracker, origin(), LIMITS, |shield| async move {
            let _hold = shield.hold();
            tokio::time::sleep(Duration::from_secs(12)).await;
            9
        })
        .await;
        assert_eq!(r, Ok(9));
    }

    #[tokio::test(start_paused = true)]
    async fn shielded_work_is_abandoned_at_the_hard_cap() {
        let tracker = Tracker::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = dropped.clone();
        let started = Instant::now();
        let r: Result<(), Stopped> =
            run_bounded(&tracker, origin(), LIMITS, move |shield| async move {
                let _flag = DropFlag(flag);
                let _hold = shield.hold();
                std::future::pending::<()>().await;
            })
            .await;
        assert_eq!(r, Err(Stopped::Deadline));
        assert_eq!(started.elapsed(), Duration::from_secs(15));
        tracker.idle().await;
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_caller_is_still_cut_at_the_deadline() {
        let tracker = Tracker::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = dropped.clone();
        {
            let mut call = pin!(run_bounded(
                &tracker,
                origin(),
                LIMITS,
                move |_| async move {
                    let _flag = DropFlag(flag);
                    std::future::pending::<()>().await;
                }
            ));
            let pending = poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx).is_pending())).await;
            assert!(pending);
        } // caller dropped here
        assert_eq!(tracker.in_flight(), 1);
        tracker.idle().await;
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(tracker.in_flight(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn work_finishing_before_the_deadline_is_unaffected() {
        let tracker = Tracker::new();
        let r = run_bounded(&tracker, origin(), LIMITS, |_| async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            "done"
        })
        .await;
        assert_eq!(r, Ok("done"));
    }
}
