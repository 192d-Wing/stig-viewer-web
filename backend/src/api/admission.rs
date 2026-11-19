//! Admission cap for audited requests.
//!
//! One [`Permit`] is taken per audited request before anything runs and is
//! held until the request, every audit write it started and every detached
//! task it started have finished. Two caps are checked and taken atomically
//! under one lock: [`MAX_USER_IN_FLIGHT`] per user (admins included, so one
//! account cannot exhaust the pool) answers 429, and [`MAX_IN_FLIGHT`] in all
//! answers 503; non-admins may hold at most `MAX_IN_FLIGHT - ADMIN_RESERVE` of
//! the global cap, the rest is for admins. Both carry `Retry-After: 1` and are refused before the
//! handler mutates anything, so a flood is turned away instead of committing
//! changes whose audit events would then be shed.
//!
//! The permit travels in [`RequestCtx::permit`]. `OwnedEvent` clones the ctx
//! into the detached audit write and detached work functions take the ctx by
//! value, so the permit lives until the write or task ends, however late.
//!
//! The body of an admitted request must keep arriving. Timing starts at the
//! first read of the body (a handler that does other work first is not
//! charged for it) and is only consulted while the client is being waited
//! for: a frame the body can deliver at once is never charged. This depends
//! on the handler reading without long pauses mid-body: hyper's HTTP/1 body
//! channel is want-driven, so after a long gap in reading the next poll can
//! return Pending even though the client sent everything, and a handler that
//! pauses past the deadline then gets a spurious 400 and a penalty strike. The
//! first byte is due
//! within `ADMITTED_BODY_FIRST_BYTE` (5 s); after that the body is cut off
//! once `first_byte_at + ADMITTED_BODY_GRACE (10 s) + bytes_received /
//! ADMITTED_BODY_MIN_RATE (64 KiB/s)` has passed, so a 500 MiB upload is fine
//! while it averages 64 KiB/s. A cut-off makes the body extractor answer 400
//! and release the permit. Each cut-off is counted (`bodyDeadline`), logged
//! with the holder's user id (throttled per user), and after
//! `BODY_PENALTY_CUTS` (3) within 60 s the user is refused admission with 429
//! for 30 s. Streaming is kept: nothing is buffered here, and the routes'
//! `DefaultBodyLimit`s still apply.
//!
//! Admitted: every non-read method, and the GETs in [`AUDITED_READ_ROUTES`]
//! (the only GETs that record an event). Other GETs are not admitted:
//! dashboards fire many parallel reads. An `authz.denied` from a 403 on such
//! a GET holds no permit; it is bounded by the denied share and the per-user
//! denied sub-cap in `db_audit`.
//!
//! Sits after `rate_limit` and before `request_ctx` (see
//! `authz_audit::protected_stack`). A refusal is not written to
//! `audit_events` (that would feed the queue being protected); it is counted
//! (admin-only on `/api/admin/failure-counters`) and logged ids-only, at most
//! once per 60 s.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::{
    body::{Body, Bytes},
    extract::{MatchedPath, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use http_body::Body as _;
use serde_json::json;
use tokio::sync::Notify;

use crate::api::auth::AuthUser;
use crate::db_audit::{MAX_DENIED_PENDING, MAX_PENDING_WRITES};

/// Admitted requests in flight in all.
pub const MAX_IN_FLIGHT: u32 = 32;
/// Admitted requests in flight for one user.
pub const MAX_USER_IN_FLIGHT: u32 = 4;
/// Of [`MAX_IN_FLIGHT`], how many only admins can use, so incident response is
/// not locked out when ordinary accounts fill the rest.
pub const ADMIN_RESERVE: u32 = 4;
/// Time a body reader gets to receive its first byte, from the first time the
/// handler reads the body (a handler that does other work first is not
/// charged for it). Past it the body yields an error (the extractor answers
/// 400) and the handler returns, releasing the permit.
pub const ADMITTED_BODY_FIRST_BYTE: Duration = Duration::from_secs(5);
/// After the first byte: time allowed on top of the rate rule. The deadline
/// is `first_byte_at + ADMITTED_BODY_GRACE + bytes / ADMITTED_BODY_MIN_RATE`.
pub const ADMITTED_BODY_GRACE: Duration = Duration::from_secs(10);
/// Minimum average body rate in bytes per second; each byte received extends
/// the deadline by `1 / ADMITTED_BODY_MIN_RATE` seconds.
pub const ADMITTED_BODY_MIN_RATE: u64 = 64 * 1024;
/// Body cut-offs within [`BODY_PENALTY_WINDOW`] after which a user is refused
/// admission for [`BODY_PENALTY_BLOCK`].
pub const BODY_PENALTY_CUTS: u32 = 3;
pub const BODY_PENALTY_WINDOW: Duration = Duration::from_secs(60);
pub const BODY_PENALTY_BLOCK: Duration = Duration::from_secs(30);
/// Users tracked for body penalties and log throttling at once.
const MAX_TRACKED_USERS: usize = 1024;
/// Users listed in a global-refusal log line.
const MAX_LISTED_USERS: usize = 8;

/// Body-reading limits (injectable for tests).
#[derive(Debug, Clone, Copy)]
pub struct BodyLimits {
    pub first_byte: Duration,
    pub grace: Duration,
    pub min_rate: u64,
    pub penalty_cuts: u32,
    pub penalty_window: Duration,
    pub penalty_block: Duration,
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self {
            first_byte: ADMITTED_BODY_FIRST_BYTE,
            grace: ADMITTED_BODY_GRACE,
            min_rate: ADMITTED_BODY_MIN_RATE,
            penalty_cuts: BODY_PENALTY_CUTS,
            penalty_window: BODY_PENALTY_WINDOW,
            penalty_block: BODY_PENALTY_BLOCK,
        }
    }
}

/// Audit-queue slots kept free for events with no permit: `auth.notice_ack`
/// (no request ctx) and system events (scheduled sync).
pub const UNADMITTED_RESERVE: u32 = 16;

const _: () = assert!(ADMIN_RESERVE < MAX_IN_FLIGHT);

// Handlers await each audit write in turn, so an admitted request has at most
// one non-restricted write pending at a time on a healthy pool, and a late
// write keeps its permit. Non-restricted pending writes from admitted requests
// are therefore at most `MAX_IN_FLIGHT`, whatever the role or
// `RATE_LIMIT_BURST`, and the reserve covers the permit-less writers.
const _: () = assert!(
    MAX_IN_FLIGHT + UNADMITTED_RESERVE <= MAX_PENDING_WRITES - MAX_DENIED_PENDING,
    "admission caps must leave the audit queue's non-restricted share intact"
);

/// GET routes (as `MatchedPath` templates) that record an `audit.read` event.
pub const AUDITED_READ_ROUTES: [&str; 2] = ["/api/audit/search", "/api/audit/events"];

const WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Per-reason rate limit for the refusal log line, counting what it hid.
#[derive(Debug, Default)]
struct WarnThrottle {
    last: [Option<Instant>; 2],
    suppressed: [u64; 2],
}

impl WarnThrottle {
    /// `Some(suppressed since the last line)` when a line should be logged
    /// now for `reason`, else `None` (and the refusal is counted as hidden).
    fn decide(&mut self, reason: Refusal, now: Instant) -> Option<u64> {
        let i = reason as usize;
        let due = self.last[i].is_none_or(|t| now.saturating_duration_since(t) >= WARN_INTERVAL);
        if due {
            self.last[i] = Some(now);
            Some(std::mem::take(&mut self.suppressed[i]))
        } else {
            self.suppressed[i] += 1;
            None
        }
    }
}

/// Per-user rate limit for the body cut-off log line, bounded in size.
#[derive(Debug, Default)]
struct UserWarnThrottle {
    users: HashMap<String, (Instant, u64)>,
}

impl UserWarnThrottle {
    /// `Some(suppressed since the last line)` when a line for `user` is due.
    /// When the table is full of recent users, further users are not logged
    /// (they are still counted).
    fn decide(&mut self, user: &str, now: Instant) -> Option<u64> {
        if let Some((last, hidden)) = self.users.get_mut(user) {
            if now.saturating_duration_since(*last) >= WARN_INTERVAL {
                *last = now;
                return Some(std::mem::take(hidden));
            }
            *hidden += 1;
            return None;
        }
        if self.users.len() >= MAX_TRACKED_USERS {
            self.users
                .retain(|_, (t, _)| now.saturating_duration_since(*t) < WARN_INTERVAL);
            if self.users.len() >= MAX_TRACKED_USERS {
                return None;
            }
        }
        self.users.insert(user.to_owned(), (now, 0));
        Some(0)
    }
}

/// Recent body cut-offs of one user, and any admission block they earned.
#[derive(Debug, Default)]
struct Penalty {
    cuts: Vec<Instant>,
    blocked_until: Option<Instant>,
}

/// `"a(3), b(2) (+4 more)"`, or `"none"`, with each id made log-safe.
fn format_holders(top: &[(String, u32)], total: usize) -> String {
    if top.is_empty() {
        return "none".to_string();
    }
    let mut out = top
        .iter()
        .map(|(i, n)| format!("{}({n})", crate::db_audit::audit_safe_id(i)))
        .collect::<Vec<_>>()
        .join(", ");
    if total > top.len() {
        out.push_str(&format!(" (+{} more)", total - top.len()));
    }
    out
}

/// Which cap refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    User = 0,
    Global = 1,
}

#[derive(Debug, Default)]
struct Counts {
    total: u32,
    users: HashMap<String, u32>,
    penalties: HashMap<String, Penalty>,
}

#[derive(Debug)]
pub struct Admission {
    state: Mutex<Counts>,
    idle: Notify,
    refused_user: AtomicU64,
    refused_global: AtomicU64,
    warn: Mutex<WarnThrottle>,
    cut_warn: Mutex<UserWarnThrottle>,
    body_cut_offs: AtomicU64,
    cap: u32,
    user_cap: u32,
    admin_reserve: u32,
    body: BodyLimits,
}

/// One admitted request. Dropping it frees both counts.
#[derive(Debug)]
pub struct Permit {
    admission: Arc<Admission>,
    user_id: String,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Admission {
    pub fn new() -> Arc<Self> {
        Self::with_limits(MAX_IN_FLIGHT, MAX_USER_IN_FLIGHT, ADMIN_RESERVE)
    }

    /// Caps with no admin reserve (tests).
    pub fn with_caps(cap: u32, user_cap: u32) -> Arc<Self> {
        Self::with_limits(cap, user_cap, 0)
    }

    /// Default caps with other body limits (tests).
    pub fn with_body(body: BodyLimits) -> Arc<Self> {
        Self::build(MAX_IN_FLIGHT, MAX_USER_IN_FLIGHT, ADMIN_RESERVE, body)
    }

    pub fn with_limits(cap: u32, user_cap: u32, admin_reserve: u32) -> Arc<Self> {
        Self::build(cap, user_cap, admin_reserve, BodyLimits::default())
    }

    fn build(cap: u32, user_cap: u32, admin_reserve: u32, mut body: BodyLimits) -> Arc<Self> {
        body.min_rate = body.min_rate.max(1);
        Arc::new(Self {
            state: Mutex::new(Counts::default()),
            idle: Notify::new(),
            refused_user: AtomicU64::new(0),
            refused_global: AtomicU64::new(0),
            warn: Mutex::new(WarnThrottle::default()),
            cut_warn: Mutex::new(UserWarnThrottle::default()),
            body_cut_offs: AtomicU64::new(0),
            cap,
            user_cap,
            admin_reserve,
            body,
        })
    }

    /// [`Self::try_admit_as`] for a non-admin.
    pub fn try_admit(self: &Arc<Self>, user_id: &str) -> Result<Arc<Permit>, Refusal> {
        self.try_admit_as(user_id, false)
    }

    /// Take a permit for `user_id`, or say which cap is full. The per-user
    /// cap is checked first (admins included). Non-admins stop
    /// `admin_reserve` short of the global cap. All checked and taken under
    /// one lock. A user with too many recent body cut-offs is refused (as
    /// `User`) until their block ends.
    pub fn try_admit_as(
        self: &Arc<Self>,
        user_id: &str,
        admin: bool,
    ) -> Result<Arc<Permit>, Refusal> {
        self.try_admit_at(user_id, admin, Instant::now())
    }

    fn try_admit_at(
        self: &Arc<Self>,
        user_id: &str,
        admin: bool,
        now: Instant,
    ) -> Result<Arc<Permit>, Refusal> {
        let mut s = lock(&self.state);
        if let Some(p) = s.penalties.get_mut(user_id) {
            match p.blocked_until {
                Some(t) if now < t => return Err(Refusal::User),
                Some(_) => p.blocked_until = None,
                None => {}
            }
        }
        if s.users.get(user_id).copied().unwrap_or(0) >= self.user_cap {
            return Err(Refusal::User);
        }
        let limit = if admin {
            self.cap
        } else {
            self.cap.saturating_sub(self.admin_reserve)
        };
        if s.total >= limit {
            return Err(Refusal::Global);
        }
        s.total += 1;
        *s.users.entry(user_id.to_owned()).or_insert(0) += 1;
        Ok(Arc::new(Permit {
            admission: Arc::clone(self),
            user_id: user_id.to_owned(),
        }))
    }

    pub fn in_flight(&self) -> u32 {
        lock(&self.state).total
    }

    /// `(inFlight, refusedUser, refusedGlobal, bodyDeadline)`.
    pub fn stats(&self) -> (u32, u64, u64, u64) {
        (
            self.in_flight(),
            self.refused_user.load(Ordering::Relaxed),
            self.refused_global.load(Ordering::Relaxed),
            self.body_cut_offs.load(Ordering::Relaxed),
        )
    }

    /// Record that `user_id`'s body was cut off: count it, block the user after
    /// [`BodyLimits::penalty_cuts`] within the window, and log it (ids only,
    /// throttled per user).
    fn note_cut_off(&self, user_id: &str) {
        let now = Instant::now();
        self.note_cut_off_at(user_id, now);
        if let Some(hidden) = lock(&self.cut_warn).decide(user_id, now) {
            tracing::warn!(
                target: "audit",
                user_id = %crate::db_audit::audit_safe_id(user_id),
                suppressed = hidden,
                "request body cut off: too slow while holding an admission permit"
            );
        }
    }

    fn note_cut_off_at(&self, user_id: &str, now: Instant) {
        self.body_cut_offs.fetch_add(1, Ordering::Relaxed);
        let b = self.body;
        let mut s = lock(&self.state);
        if !s.penalties.contains_key(user_id) && s.penalties.len() >= MAX_TRACKED_USERS {
            s.penalties.retain(|_, p| {
                p.blocked_until.is_some_and(|t| now < t)
                    || p.cuts
                        .iter()
                        .any(|c| now.saturating_duration_since(*c) < b.penalty_window)
            });
            if s.penalties.len() >= MAX_TRACKED_USERS {
                return; // counted above; no per-user state when the table is full
            }
        }
        let p = s.penalties.entry(user_id.to_owned()).or_default();
        p.cuts
            .retain(|c| now.saturating_duration_since(*c) < b.penalty_window);
        p.cuts.push(now);
        if p.cuts.len() as u32 >= b.penalty_cuts {
            p.cuts.clear();
            p.blocked_until = Some(now + b.penalty_block);
        }
    }

    /// The users holding the most permits right now (count desc, then id),
    /// for the global-refusal log line.
    fn top_holders_summary(&self) -> String {
        let s = lock(&self.state);
        let mut held: Vec<(String, u32)> = s.users.iter().map(|(u, n)| (u.clone(), *n)).collect();
        held.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let total = held.len();
        held.truncate(MAX_LISTED_USERS);
        format_holders(&held, total)
    }

    /// Resolve once no permit is held.
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

    fn refuse(&self, user_id: &str, why: Refusal) {
        let counter = match why {
            Refusal::User => &self.refused_user,
            Refusal::Global => &self.refused_global,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let hidden = lock(&self.warn).decide(why, Instant::now());
        if let Some(hidden) = hidden {
            tracing::warn!(
                target: "audit",
                user_id = %crate::db_audit::audit_safe_id(user_id),
                reason = match why {
                    Refusal::User => "user_cap",
                    Refusal::Global => "global_cap",
                },
                suppressed = hidden,
                top_holders = %match why {
                    Refusal::Global => self.top_holders_summary(),
                    Refusal::User => String::new(),
                },
                "request refused: too many audited requests in flight"
            );
        }
    }
}

/// A request body that errors once it falls behind the minimum rate (see the
/// module docs). The clock starts at the first read, and is only consulted
/// when the inner body returns Pending (the client is being waited for), so a
/// frame the inner body can deliver at once is never charged. Handlers must
/// read without long pauses mid-body: after a long gap hyper's want-driven
/// HTTP/1 channel can answer Pending even though the client sent everything,
/// and the body is then cut off (400 and a penalty strike). Streams frames
/// from the inner body unchanged.
struct DeadlineBody {
    inner: Body,
    adm: Arc<Admission>,
    user_id: String,
    origin: Option<tokio::time::Instant>,
    first_byte_at: Option<tokio::time::Instant>,
    received: u64,
    ended: bool,
    failed: bool,
    timer: Pin<Box<tokio::time::Sleep>>,
}

impl DeadlineBody {
    fn new(inner: Body, adm: Arc<Admission>, user_id: String) -> Self {
        let ended = inner.is_end_stream();
        Self {
            inner,
            adm,
            user_id,
            origin: None,
            first_byte_at: None,
            received: 0,
            ended,
            failed: false,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
        }
    }

    fn deadline(&self, origin: tokio::time::Instant) -> tokio::time::Instant {
        let b = &self.adm.body;
        match self.first_byte_at {
            None => origin + b.first_byte,
            Some(t) => {
                t + b.grace + Duration::from_secs_f64(self.received as f64 / b.min_rate as f64)
            }
        }
    }
}

impl http_body::Body for DeadlineBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Some(Err(axum::Error::new("request body cut off"))));
        }
        if this.ended {
            return Pin::new(&mut this.inner).poll_frame(cx);
        }
        let now = tokio::time::Instant::now();
        let origin = *this.origin.get_or_insert(now);
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(None) => {
                this.ended = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref().filter(|d| !d.is_empty()) {
                    this.received += d.len() as u64;
                    this.first_byte_at.get_or_insert(now);
                }
                if this.inner.is_end_stream() {
                    this.ended = true;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(other) => Poll::Ready(other),
            Poll::Pending => {
                // Waiting on the client: keep a timer armed for the deadline.
                let deadline = this.deadline(origin);
                if this.timer.deadline() != deadline {
                    this.timer.as_mut().reset(deadline);
                }
                if this.timer.as_mut().poll(cx).is_ready() {
                    this.failed = true;
                    this.adm.note_cut_off(&this.user_id);
                    return Poll::Ready(Some(Err(axum::Error::new(
                        "request body fell behind the minimum rate",
                    ))));
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let a = &self.admission;
        let mut s = lock(&a.state);
        s.total = s.total.saturating_sub(1);
        if let Some(n) = s.users.get_mut(&self.user_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                s.users.remove(&self.user_id);
            }
        }
        if s.total == 0 {
            a.idle.notify_waiters();
        }
    }
}

/// Whether a request takes a permit: any non-read method, and the audited
/// GET routes.
pub fn needs_permit(method: &Method, matched_path: Option<&str>) -> bool {
    match *method {
        // axum serves HEAD through the GET handler, so it records too.
        Method::GET | Method::HEAD => {
            matched_path.is_some_and(|p| AUDITED_READ_ROUTES.contains(&p))
        }
        Method::OPTIONS => false,
        _ => true,
    }
}

pub async fn admission(
    State(adm): State<Arc<Admission>>,
    Extension(user): Extension<AuthUser>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.extensions().get::<MatchedPath>().map(|m| m.as_str());
    if !needs_permit(req.method(), path) {
        return next.run(req).await;
    }
    match adm.try_admit_as(&user.id, user.role == "admin") {
        Ok(permit) => {
            let (parts, body) = req.into_parts();
            let body = Body::new(DeadlineBody::new(body, Arc::clone(&adm), user.id.clone()));
            let mut req = Request::from_parts(parts, body);
            req.extensions_mut().insert(Arc::clone(&permit));
            // Held across the handler for routes that never extract the ctx.
            let resp = next.run(req).await;
            drop(permit);
            resp
        }
        Err(why) => {
            adm.refuse(&user.id, why);
            let (status, msg) = match why {
                Refusal::User => (
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many concurrent requests",
                ),
                Refusal::Global => (StatusCode::SERVICE_UNAVAILABLE, "server busy"),
            };
            (
                status,
                [("Retry-After", "1")],
                Json(json!({ "error": msg })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::authz_audit::protected_stack;
    use crate::api::request_ctx::RequestCtx;
    use crate::test_fixtures::{auth, lazy_state};
    use axum::{
        middleware,
        routing::{get, post},
        Router,
    };
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::{mpsc, Semaphore};

    #[test]
    fn the_per_user_cap_refuses_the_fifth_and_leaves_other_users_alone() {
        let a = Admission::new();
        let held: Vec<_> = (0..MAX_USER_IN_FLIGHT)
            .map(|_| a.try_admit("u1").unwrap())
            .collect();
        assert_eq!(a.try_admit("u1").unwrap_err(), Refusal::User);
        assert!(a.try_admit("u2").is_ok());
        assert_eq!(a.in_flight(), MAX_USER_IN_FLIGHT);
        drop(held);
        assert!(a.try_admit("u1").is_ok());
    }

    #[test]
    fn the_global_cap_refuses_with_global_and_the_user_cap_wins_when_both_apply() {
        let a = Admission::with_caps(3, 2);
        let _p: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|u| a.try_admit(u).unwrap())
            .collect();
        assert_eq!(a.try_admit("d").unwrap_err(), Refusal::Global);
        let _p2 = a.try_admit("a");
        // "a" holds 1 of 2 and the total is full: global.
        assert_eq!(a.try_admit("a").unwrap_err(), Refusal::Global);
        let b = Admission::with_caps(2, 1);
        let _q = b.try_admit("a").unwrap();
        let _r = b.try_admit("b").unwrap();
        // Both caps are full for "a": the per-user one is reported.
        assert_eq!(b.try_admit("a").unwrap_err(), Refusal::User);
    }

    enum Send {
        Nothing,
        /// One byte every 10 ms (100 B/s).
        Drip,
        /// 15 chunks of 5000 bytes, 40 ms apart (125 kB/s), 75000 in all.
        Steady,
    }

    /// Open a POST with a Content-Length of 75000, send the body as `how`,
    /// and read the response status line.
    async fn raw_status(base: &str, how: Send) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = base.trim_start_matches("http://");
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let head = "POST /api/body HTTP/1.1\r\nHost: x\r\nx-user: slow-body\r\n\
                    Content-Length: 75000\r\n\r\n";
        conn.write_all(head.as_bytes()).await.unwrap();
        let (mut rd, mut wr) = conn.into_split();
        // Kept alive until the response is read, so the connection stays open.
        let writer = tokio::spawn(async move {
            match how {
                Send::Nothing => std::future::pending::<()>().await,
                Send::Drip => {
                    for _ in 0..75_000 {
                        if wr.write_all(b"x").await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
                Send::Steady => {
                    for _ in 0..15 {
                        if wr.write_all(&[b'x'; 5000]).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(40)).await;
                    }
                    std::future::pending::<()>().await;
                }
            }
        });
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(10), rd.read(&mut buf))
            .await
            .expect("no response")
            .unwrap();
        writer.abort();
        String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or("")
            .to_string()
    }

    fn limits(first_byte_ms: u64, grace_ms: u64, min_rate: u64) -> BodyLimits {
        BodyLimits {
            first_byte: Duration::from_millis(first_byte_ms),
            grace: Duration::from_millis(grace_ms),
            min_rate,
            ..BodyLimits::default()
        }
    }

    async fn body_app(b: BodyLimits) -> (String, Arc<Admission>, Arc<Gate>) {
        let (mut state, _dir) = lazy_state();
        state.admission = Admission::with_body(b);
        let adm = state.admission.clone();
        let (gate, _entered) = Gate::new();
        (serve(app(state, gate.clone())).await, adm, gate)
    }

    #[tokio::test]
    async fn a_header_only_post_is_cut_off_at_the_first_byte_deadline_and_attributed() {
        // A huge grace shows it is the first-byte deadline that fires.
        let (base, adm, _gate) = body_app(limits(400, 600_000, 1000)).await;
        let started = std::time::Instant::now();
        assert!(raw_status(&base, Send::Nothing).await.contains(" 400"));
        assert!(started.elapsed() < Duration::from_secs(5));
        adm.idle().await;
        assert_eq!(adm.in_flight(), 0);
        // Counted, and recorded against the holder.
        assert_eq!(adm.stats().3, 1);
        assert_eq!(lock(&adm.state).penalties["slow-body"].cuts.len(), 1);
    }

    #[tokio::test]
    async fn a_drip_below_the_minimum_rate_is_cut_off() {
        // 100 B/s against a 1000 B/s minimum, so the deadline only creeps
        // ahead of the 10 ms pace once the 400 ms grace is used up.
        let (base, adm, _gate) = body_app(limits(400, 400, 1000)).await;
        assert!(raw_status(&base, Send::Drip).await.contains(" 400"));
        adm.idle().await;
        assert_eq!(adm.in_flight(), 0);
        assert_eq!(adm.stats().3, 1);
    }

    #[tokio::test]
    async fn a_body_above_the_minimum_rate_survives_past_the_grace() {
        // About 600 ms in all against a 400 ms grace, at 125 kB/s against a
        // 100 kB/s minimum.
        let (base, adm, _gate) = body_app(limits(400, 400, 100_000)).await;
        assert!(raw_status(&base, Send::Steady).await.contains(" 200"));
        adm.idle().await;
        assert_eq!(adm.stats().3, 0);
    }

    #[tokio::test]
    async fn the_deadline_does_not_cancel_a_handler_after_the_body_is_complete() {
        let (base, adm, _gate) = body_app(limits(500, 500, 1000)).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/api/slow"))
            .header("x-user", "slow-handler")
            .body("done")
            .send()
            .await
            .unwrap();
        // The handler ran for 1.5 s, well past the 500 ms limits.
        assert_eq!(r.status().as_u16(), 200);
        adm.idle().await;
        assert_eq!(adm.stats().3, 0);
    }

    #[tokio::test]
    async fn a_handler_that_reads_the_body_late_is_not_charged_for_its_delay() {
        let (base, adm, _gate) = body_app(limits(300, 300, 1000)).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/api/late"))
            .header("x-user", "late-reader")
            .body("complete body")
            .send()
            .await
            .unwrap();
        // The body was sent at once; the handler read it 900 ms later.
        assert_eq!(r.status().as_u16(), 200);
        adm.idle().await;
        assert_eq!(adm.stats().3, 0);
    }

    #[test]
    fn three_cut_offs_in_the_window_block_the_user_until_the_penalty_ends() {
        let b = BodyLimits {
            penalty_cuts: 3,
            penalty_window: Duration::from_secs(60),
            penalty_block: Duration::from_secs(30),
            ..BodyLimits::default()
        };
        let a = Admission::with_body(b);
        let t0 = Instant::now();
        a.note_cut_off_at("u1", t0);
        a.note_cut_off_at("u1", t0 + Duration::from_secs(10));
        assert!(a
            .try_admit_at("u1", false, t0 + Duration::from_secs(11))
            .is_ok());
        a.note_cut_off_at("u1", t0 + Duration::from_secs(12));
        let t = t0 + Duration::from_secs(13);
        assert_eq!(a.try_admit_at("u1", false, t).unwrap_err(), Refusal::User);
        assert_eq!(a.try_admit_at("u1", true, t).unwrap_err(), Refusal::User);
        // Others are unaffected, and the block ends.
        assert!(a.try_admit_at("u2", false, t).is_ok());
        assert!(a
            .try_admit_at("u1", false, t0 + Duration::from_secs(12 + 30))
            .is_ok());
        assert_eq!(a.stats().3, 3);
    }

    #[test]
    fn cut_offs_outside_the_window_do_not_add_up() {
        let a = Admission::with_body(BodyLimits::default());
        let t0 = Instant::now();
        for i in 0..5u64 {
            a.note_cut_off_at("u1", t0 + Duration::from_secs(i * 61));
        }
        let t = t0 + Duration::from_secs(5 * 61);
        assert!(a.try_admit_at("u1", false, t).is_ok());
    }

    #[test]
    fn the_cut_off_log_is_throttled_per_user_and_bounded() {
        let mut t = UserWarnThrottle::default();
        let t0 = Instant::now();
        assert_eq!(t.decide("a", t0), Some(0));
        assert_eq!(t.decide("a", t0), None);
        assert_eq!(t.decide("b", t0), Some(0));
        assert_eq!(t.decide("a", t0 + WARN_INTERVAL), Some(1));
        for i in 0..MAX_TRACKED_USERS * 2 {
            t.decide(&format!("x{i}"), t0 + WARN_INTERVAL * 2);
        }
        assert!(t.users.len() <= MAX_TRACKED_USERS);
    }

    #[test]
    fn a_global_refusal_names_the_top_holders_by_count() {
        let a = Admission::with_limits(32, 4, 0);
        let mut held = Vec::new();
        for (u, n) in [("bob", 3), ("alice", 3), ("carol", 2), ("dave", 1)] {
            for _ in 0..n {
                held.push(a.try_admit(u).unwrap());
            }
        }
        // Below the per-user cap, yet named: most permits first, then id.
        assert_eq!(
            a.top_holders_summary(),
            "alice(3), bob(3), carol(2), dave(1)"
        );
        assert_eq!(
            Admission::with_limits(6, 2, 0).top_holders_summary(),
            "none"
        );
        let many: Vec<(String, u32)> = (0..3).map(|i| (format!("u{i}"), 2)).collect();
        assert_eq!(format_holders(&many, 11), "u0(2), u1(2), u2(2) (+8 more)");
        assert!(!format_holders(&[("a b\nc".to_string(), 1)], 1).contains('\n'));
        let a = Admission::with_limits(100, 4, 0);
        let _h: Vec<_> = (0..12)
            .map(|i| a.try_admit(&format!("u{i:02}")).unwrap())
            .collect();
        assert!(a.top_holders_summary().ends_with("(+4 more)"));
    }

    #[tokio::test]
    async fn the_admin_reserve_holds_through_the_middleware() {
        let (state, _dir) = lazy_state();
        let adm = state.admission.clone();
        let (gate, mut entered) = Gate::new();
        let base = serve(app(state, gate.clone())).await;
        let mut held = Vec::new();
        for u in 0..(MAX_IN_FLIGHT - ADMIN_RESERVE) / MAX_USER_IN_FLIGHT {
            for _ in 0..MAX_USER_IN_FLIGHT {
                held.push(spawn_gated(&base, &format!("reserve-u{u}")));
            }
        }
        for _ in 0..MAX_IN_FLIGHT - ADMIN_RESERVE {
            entered.recv().await.unwrap();
        }
        expect_refused(
            call(&base, "POST", "/api/gate", "reserve-late").await,
            503,
            "server busy",
        )
        .await;
        assert_eq!(
            gate.entered.load(Ordering::SeqCst) as u32,
            MAX_IN_FLIGHT - ADMIN_RESERVE
        );
        // An admin still gets in.
        held.push(spawn_gated(&base, "admin-reserve"));
        entered.recv().await.unwrap();
        assert_eq!(adm.in_flight(), MAX_IN_FLIGHT - ADMIN_RESERVE + 1);
        gate.open();
        for h in held {
            assert_eq!(h.await.unwrap(), 200);
        }
        adm.idle().await;
    }

    #[tokio::test]
    async fn three_cut_offs_block_the_user_through_the_middleware() {
        let (base, adm, gate) = body_app(limits(150, 600_000, 1000)).await;
        for _ in 0..BODY_PENALTY_CUTS {
            assert!(raw_status(&base, Send::Nothing).await.contains(" 400"));
        }
        adm.idle().await;
        assert_eq!(adm.stats().3, u64::from(BODY_PENALTY_CUTS));
        // "slow-body" is now refused before the handler; others are not.
        expect_refused(
            call(&base, "POST", "/api/gate", "slow-body").await,
            429,
            "too many concurrent requests",
        )
        .await;
        assert_eq!(gate.entered.load(Ordering::SeqCst), 0);
        assert_eq!(
            call(&base, "POST", "/api/fast", "innocent").await.status(),
            200
        );
    }

    /// An inner body that yields `frames` at once, then ends or stays Pending.
    struct Script {
        frames: Vec<Bytes>,
        then_end: bool,
    }

    impl http_body::Body for Script {
        type Data = Bytes;
        type Error = axum::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
            if !self.frames.is_empty() {
                let b = self.frames.remove(0);
                return Poll::Ready(Some(Ok(http_body::Frame::data(b))));
            }
            if self.then_end {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }
    }

    async fn next_frame(
        b: &mut DeadlineBody,
    ) -> Option<Result<http_body::Frame<Bytes>, axum::Error>> {
        std::future::poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut *b), cx)).await
    }

    fn scripted(then_end: bool) -> (DeadlineBody, Arc<Admission>) {
        let adm = Admission::with_body(limits(1000, 1000, 1000));
        let inner = Body::new(Script {
            frames: vec![Bytes::from_static(b"0123456789"); 2],
            then_end,
        });
        (DeadlineBody::new(inner, adm.clone(), "u".into()), adm)
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_that_is_ready_is_delivered_even_past_the_deadline() {
        let (mut b, adm) = scripted(true);
        assert!(next_frame(&mut b).await.unwrap().is_ok());
        // Far past first byte + grace + the rate credit for 10 bytes.
        tokio::time::advance(Duration::from_secs(100)).await;
        assert!(next_frame(&mut b).await.unwrap().is_ok());
        assert!(next_frame(&mut b).await.is_none());
        assert_eq!(adm.stats().3, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_pending_body_past_the_deadline_is_cut_off() {
        let (mut b, adm) = scripted(false);
        assert!(next_frame(&mut b).await.unwrap().is_ok());
        assert!(next_frame(&mut b).await.unwrap().is_ok());
        // Nothing more is coming: the timer (paused clock auto-advances) fires.
        assert!(next_frame(&mut b).await.unwrap().is_err());
        assert_eq!(adm.stats().3, 1);
        // Once cut off, it stays an error without counting again.
        assert!(next_frame(&mut b).await.unwrap().is_err());
        assert_eq!(adm.stats().3, 1);
    }

    #[test]
    fn non_admins_stop_short_of_the_cap_by_the_admin_reserve() {
        let a = Admission::new();
        let per_user = MAX_USER_IN_FLIGHT;
        let mut held = Vec::new();
        let non_admin_cap = MAX_IN_FLIGHT - ADMIN_RESERVE;
        for i in 0..non_admin_cap / per_user {
            for _ in 0..per_user {
                held.push(a.try_admit(&format!("u{i}")).unwrap());
            }
        }
        assert_eq!(a.in_flight(), non_admin_cap);
        assert_eq!(a.try_admit("late").unwrap_err(), Refusal::Global);
        for _ in 0..per_user {
            held.push(a.try_admit_as("admin-x", true).unwrap());
        }
        assert_eq!(a.in_flight(), MAX_IN_FLIGHT);
        // The admin is still bound by the per-user cap and the global cap.
        assert_eq!(a.try_admit_as("admin-x", true).unwrap_err(), Refusal::User);
        assert_eq!(
            a.try_admit_as("admin-y", true).unwrap_err(),
            Refusal::Global
        );
    }

    #[test]
    fn the_refusal_log_is_throttled_per_reason_and_counts_what_it_hid() {
        let mut t = WarnThrottle::default();
        let t0 = Instant::now();
        assert_eq!(t.decide(Refusal::User, t0), Some(0));
        assert_eq!(t.decide(Refusal::User, t0), None);
        assert_eq!(t.decide(Refusal::User, t0), None);
        // A user-cap storm does not hide the first global-cap refusal.
        assert_eq!(t.decide(Refusal::Global, t0), Some(0));
        assert_eq!(t.decide(Refusal::Global, t0), None);
        let later = t0 + WARN_INTERVAL;
        assert_eq!(t.decide(Refusal::User, later), Some(2));
        assert_eq!(t.decide(Refusal::Global, later), Some(1));
        assert_eq!(t.decide(Refusal::User, later), None);
    }

    #[tokio::test]
    async fn dropping_a_permit_frees_both_counts_and_wakes_idle() {
        let a = Admission::new();
        let p = a.try_admit("u1").unwrap();
        let q = Arc::clone(&p);
        drop(p);
        assert_eq!(a.in_flight(), 1, "a clone still holds the permit");
        drop(q);
        a.idle().await;
        assert_eq!(a.in_flight(), 0);
        assert!(lock(&a.state).users.is_empty());
        Admission::new().idle().await;
    }

    #[test]
    fn which_requests_need_a_permit() {
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(needs_permit(&m, Some("/api/x")), "{m}");
            assert!(needs_permit(&m, None), "{m}");
        }
        let ext = Method::from_bytes(b"BREW").unwrap();
        assert!(needs_permit(&ext, Some("/api/x")));
        assert!(needs_permit(&Method::TRACE, None));
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!needs_permit(&m, Some("/api/stigs")), "{m}");
            assert!(!needs_permit(&m, None), "{m}");
        }
        assert!(needs_permit(&Method::GET, Some("/api/audit/search")));
        assert!(needs_permit(&Method::GET, Some("/api/audit/events")));
        assert!(needs_permit(&Method::HEAD, Some("/api/audit/events")));
        assert!(needs_permit(&Method::HEAD, Some("/api/audit/search")));
        assert!(!needs_permit(&Method::HEAD, Some("/api/stigs")));
        assert!(!needs_permit(&Method::OPTIONS, Some("/api/audit/events")));
    }

    /// A handler that reports it entered, then waits for the gate.
    struct Gate {
        entered: AtomicUsize,
        tx: mpsc::UnboundedSender<()>,
        open: Semaphore,
    }

    impl Gate {
        fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<()>) {
            let (tx, rx) = mpsc::unbounded_channel();
            let g = Arc::new(Self {
                entered: AtomicUsize::new(0),
                tx,
                open: Semaphore::new(0),
            });
            (g, rx)
        }
        fn open(&self) {
            self.open.add_permits(1000);
        }
    }

    /// The caller is whoever the `x-user` header names; `admin*` ids are admins.
    fn app(state: crate::AppState, gate: Arc<Gate>) -> Router {
        let gated = move || {
            let g = Arc::clone(&gate);
            async move {
                g.entered.fetch_add(1, Ordering::SeqCst);
                let _ = g.tx.send(());
                if let Ok(p) = g.open.acquire().await {
                    p.forget();
                }
                StatusCode::OK
            }
        };
        let probe = |Extension(ctx): Extension<RequestCtx>| async move {
            Json(json!({ "permit": ctx.permit.is_some() }))
        };
        protected_stack(
            Router::new()
                .route("/api/gate", post(gated))
                .route("/api/fast", post(|| async { StatusCode::OK }))
                .route("/api/probe", get(probe).post(probe))
                .route("/api/audit/events", get(probe))
                .route("/api/audit/search", get(probe))
                .route("/api/body", post(|_: Bytes| async { StatusCode::OK }))
                .route(
                    "/api/slow",
                    post(|_: Bytes| async {
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                        StatusCode::OK
                    }),
                )
                .route(
                    "/api/late",
                    // Does other work before it first reads the body.
                    post(|req: Request| async move {
                        tokio::time::sleep(Duration::from_millis(900)).await;
                        match axum::body::to_bytes(req.into_body(), 1 << 20).await {
                            Ok(_) => StatusCode::OK,
                            Err(_) => StatusCode::BAD_REQUEST,
                        }
                    }),
                ),
            &state,
        )
        .route_layer(middleware::from_fn(
            |mut req: Request, next: Next| async move {
                let id = req
                    .headers()
                    .get("x-user")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("anon")
                    .to_string();
                let role = if id.starts_with("admin") {
                    "admin"
                } else if id.starts_with("viewer") {
                    "viewer"
                } else {
                    "author"
                };
                req.extensions_mut().insert(auth(&id, role));
                next.run(req).await
            },
        ))
        .with_state(state)
    }

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        format!("http://{addr}")
    }

    async fn call(base: &str, method: &str, path: &str, user: &str) -> reqwest::Response {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        reqwest::Client::new()
            .request(m, format!("{base}{path}"))
            .header("x-user", user)
            .send()
            .await
            .unwrap()
    }

    async fn json_of(resp: reqwest::Response) -> serde_json::Value {
        serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap()
    }

    async fn expect_refused(resp: reqwest::Response, status: u16, msg: &str) {
        assert_eq!(resp.status().as_u16(), status);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "1");
        let body = json_of(resp).await;
        assert_eq!(body["error"], msg);
    }

    fn spawn_gated(base: &str, user: &str) -> tokio::task::JoinHandle<u16> {
        let (base, user) = (base.to_string(), user.to_string());
        tokio::spawn(async move {
            call(&base, "POST", "/api/gate", &user)
                .await
                .status()
                .as_u16()
        })
    }

    #[tokio::test]
    async fn a_per_user_flood_is_refused_before_the_handler_and_admins_are_not_exempt() {
        let (state, _dir) = lazy_state();
        let adm = state.admission.clone();
        let (gate, mut entered) = Gate::new();
        let base = serve(app(state, gate.clone())).await;
        let held: Vec<_> = (0..4).map(|_| spawn_gated(&base, "admin-flood")).collect();
        for _ in 0..4 {
            entered.recv().await.unwrap();
        }
        expect_refused(
            call(&base, "POST", "/api/gate", "admin-flood").await,
            429,
            "too many concurrent requests",
        )
        .await;
        assert_eq!(
            gate.entered.load(Ordering::SeqCst),
            4,
            "never reached the handler"
        );
        assert_eq!(adm.in_flight(), 4);
        assert_eq!(adm.stats(), (4, 1, 0, 0));
        // Another user is unaffected.
        assert_eq!(
            call(&base, "POST", "/api/fast", "other").await.status(),
            200
        );
        gate.open();
        for h in held {
            assert_eq!(h.await.unwrap(), 200);
        }
        adm.idle().await;
        assert_eq!(
            call(&base, "POST", "/api/gate", "admin-flood")
                .await
                .status(),
            200
        );
    }

    #[tokio::test]
    async fn a_global_flood_from_many_users_is_refused_with_503() {
        let (mut state, _dir) = lazy_state();
        state.admission = Admission::with_caps(3, 4);
        let adm = state.admission.clone();
        let (gate, mut entered) = Gate::new();
        let base = serve(app(state, gate.clone())).await;
        let held: Vec<_> = ["g1", "g2", "admin-g3"]
            .iter()
            .map(|u| spawn_gated(&base, u))
            .collect();
        for _ in 0..3 {
            entered.recv().await.unwrap();
        }
        expect_refused(
            call(&base, "POST", "/api/gate", "g4").await,
            503,
            "server busy",
        )
        .await;
        assert_eq!(gate.entered.load(Ordering::SeqCst), 3);
        assert_eq!(adm.stats(), (3, 0, 1, 0));
        gate.open();
        for h in held {
            assert_eq!(h.await.unwrap(), 200);
        }
        adm.idle().await;
        assert_eq!(call(&base, "POST", "/api/gate", "g4").await.status(), 200);
    }

    /// Verifies the effective layer order of `protected_stack`: `rate_limit`
    /// outside `admission` outside `request_ctx`.
    #[tokio::test]
    async fn the_layer_order_is_rate_limit_then_admission_then_request_ctx() {
        let (state, _dir) = lazy_state();
        let adm = state.admission.clone();
        let (gate, mut entered) = Gate::new();
        let base = serve(app(state, gate.clone())).await;

        // admission runs before request_ctx: the handler's ctx carries the
        // permit. Reads are not admitted; the audited GET route is.
        let post_probe = json_of(call(&base, "POST", "/api/probe", "order-u0").await).await;
        assert_eq!(post_probe["permit"], true);
        let get_probe = json_of(call(&base, "GET", "/api/probe", "admin-order").await).await;
        assert_eq!(get_probe["permit"], false);
        let audit_get = json_of(call(&base, "GET", "/api/audit/events", "admin-order").await).await;
        assert_eq!(audit_get["permit"], true);

        // rate_limit runs before admission: a user over both limits is told
        // about the rate limit and is not counted as an admission refusal.
        // Timing assumption: the default burst of 20 (no RATE_LIMIT_BURST in
        // the environment) and at most about a second between the first
        // request and the check, since the bucket refills 1 token per second.
        // The user id is unique to this test; the bucket map is process-wide.
        for _ in 0..16 {
            assert_eq!(
                call(&base, "POST", "/api/fast", "order-u1").await.status(),
                200
            );
        }
        let held: Vec<_> = (0..4).map(|_| spawn_gated(&base, "order-u1")).collect();
        for _ in 0..4 {
            entered.recv().await.unwrap();
        }
        expect_refused(
            call(&base, "POST", "/api/fast", "order-u1").await,
            429,
            "rate limit exceeded",
        )
        .await;
        assert_eq!(adm.stats(), (4, 0, 0, 0));
        gate.open();
        for h in held {
            assert_eq!(h.await.unwrap(), 200);
        }
        adm.idle().await;
    }

    #[tokio::test]
    async fn audited_reads_take_a_permit_including_head_and_search() {
        let (state, _dir) = lazy_state();
        let adm = state.admission.clone();
        let (gate, _entered) = Gate::new();
        let base = serve(app(state, gate)).await;
        let _held: Vec<_> = (0..4).map(|_| adm.try_admit("reader-u").unwrap()).collect();
        for (m, p) in [
            ("GET", "/api/audit/search"),
            ("GET", "/api/audit/events"),
            ("HEAD", "/api/audit/search"),
            ("HEAD", "/api/audit/events"),
        ] {
            let r = call(&base, m, p, "reader-u").await;
            assert_eq!(r.status().as_u16(), 429, "{m} {p}");
        }
        // Reads that record nothing are not admitted, so the cap ignores them.
        for m in ["GET", "HEAD"] {
            let r = call(&base, m, "/api/probe", "reader-u").await;
            assert_eq!(r.status().as_u16(), 200, "{m} /api/probe");
        }
    }

    #[tokio::test]
    async fn admission_runs_before_viewer_guard() {
        let (state, _dir) = lazy_state();
        let adm = state.admission.clone();
        let (gate, _entered) = Gate::new();
        let g = gate.clone();
        let base = serve(app(state, gate)).await;
        let _held: Vec<_> = (0..4).map(|_| adm.try_admit("viewer-v").unwrap()).collect();
        // A viewer over its cap gets 429, not the guard's 403, and the
        // handler is never entered.
        expect_refused(
            call(&base, "POST", "/api/gate", "viewer-v").await,
            429,
            "too many concurrent requests",
        )
        .await;
        assert_eq!(g.entered.load(Ordering::SeqCst), 0);
    }
}

/// #142: a flood beyond the cap is refused before mutating and no `ok` event
/// is shed.
#[cfg(test)]
mod flood_tests {
    use super::*;
    use crate::api::authz_audit::protected_stack;
    use crate::api::request_ctx::RequestCtx;
    use crate::db_audit::{record_or_log, NewAuditEvent};
    use crate::test_fixtures::{app_state, auth, seed_user};
    use crate::AppState;
    use axum::{middleware, routing::post, Router};
    use sqlx::PgPool;
    use tokio::sync::{mpsc, Semaphore};

    use std::time::Duration;

    async fn within<T>(what: &str, rx: &mut mpsc::UnboundedReceiver<T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .unwrap_or_else(|| panic!("channel closed waiting for {what}"))
    }

    /// The caller is whoever `x-user` names: `admin*` admins, `viewer*`
    /// viewers, anyone else an author.
    fn with_user(router: Router<AppState>) -> Router<AppState> {
        router.route_layer(middleware::from_fn(
            |mut req: Request, next: Next| async move {
                let id = req
                    .headers()
                    .get("x-user")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("anon")
                    .to_string();
                let role = if id.starts_with("admin") {
                    "admin"
                } else if id.starts_with("viewer") {
                    "viewer"
                } else {
                    "author"
                };
                req.extensions_mut().insert(auth(&id, role));
                next.run(req).await
            },
        ))
    }

    async fn serve_app(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.ok() });
        base
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_flood_beyond_the_cap_is_refused_and_every_committed_event_is_kept(pool: PgPool) {
        // Cap + 12 requests, four per user, one of the users an admin.
        let total = MAX_IN_FLIGHT + 12;
        let per_user = MAX_USER_IN_FLIGHT;
        let authors = (total - per_user) / per_user;
        let users: Vec<String> = (0..authors)
            .map(|i| format!("flood-author-{i}"))
            .chain(["admin-flood".to_string()])
            .collect();
        assert_eq!(users.len() as u32 * per_user, total);
        for u in &users {
            seed_user(&pool, u).await;
        }
        let (state, _dir) = app_state(pool.clone());
        let adm = state.admission.clone();
        let gate = Arc::new(Semaphore::new(0));
        let (tx, mut entered) = mpsc::unbounded_channel::<()>();
        let handler = {
            let gate = gate.clone();
            move |State(state): State<AppState>,
                  Extension(user): Extension<AuthUser>,
                  Extension(ctx): Extension<RequestCtx>| {
                let (gate, tx) = (gate.clone(), tx.clone());
                async move {
                    let _ = tx.send(());
                    if let Ok(p) = gate.acquire().await {
                        p.forget();
                    }
                    // The committed change's audit event.
                    record_or_log(
                        state.pool.as_ref(),
                        NewAuditEvent {
                            user_id: &user.id,
                            action: "checklist.save",
                            outcome: "ok",
                            asset_id: None,
                            checklist_id: None,
                            stig_id: None,
                            detail: json!({}),
                            ctx: Some(&ctx),
                        },
                    )
                    .await;
                    StatusCode::OK
                }
            }
        };
        let router = with_user(protected_stack(
            Router::new().route("/api/save", post(handler)),
            &state,
        ))
        .with_state(state);
        let base = serve_app(router).await;

        let (done_tx, mut done) = mpsc::unbounded_channel::<(String, u16)>();
        for u in &users {
            for _ in 0..per_user {
                let (base, u, done_tx) = (base.clone(), u.clone(), done_tx.clone());
                tokio::spawn(async move {
                    let s = reqwest::Client::new()
                        .post(format!("{base}/api/save"))
                        .header("x-user", &u)
                        .send()
                        .await
                        .map(|r| r.status().as_u16())
                        .unwrap_or(0);
                    let _ = done_tx.send((u, s));
                });
            }
        }
        drop(done_tx);
        for _ in 0..MAX_IN_FLIGHT {
            within("an admitted request to reach the handler", &mut entered).await;
        }
        // The 12 over the cap are refused while the admitted ones are held.
        for _ in 0..(total - MAX_IN_FLIGHT) {
            let (u, s) = within("a refusal", &mut done).await;
            assert!(s == 503 || s == 429, "unexpected status {s}");
            assert!(
                !u.starts_with("admin"),
                "the admin reserve must keep admins in"
            );
        }
        assert_eq!(adm.in_flight(), MAX_IN_FLIGHT);
        gate.add_permits(1000);
        let (mut ok, mut admin_ok) = (0, 0);
        while ok < MAX_IN_FLIGHT {
            let (u, s) = within("a response", &mut done).await;
            assert_eq!(s, 200);
            admin_ok += u32::from(u.starts_with("admin"));
            ok += 1;
        }
        // Non-admins stop at cap - reserve; the admin's requests all got in.
        assert_eq!(admin_ok, per_user);
        assert_eq!(ok - admin_ok, MAX_IN_FLIGHT - ADMIN_RESERVE);
        adm.idle().await;
        crate::db_audit::drain().await;
        let rows: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(repeat_count), 0)::bigint FROM audit_events \
             WHERE action = 'checklist.save' AND outcome = 'ok'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            i64::from(ok),
            "one ok row per 2xx response, none shed"
        );
        let all: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(all, i64::from(ok), "refusals write nothing");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn an_admitted_viewer_post_is_403_with_one_authz_denied_row(pool: PgPool) {
        seed_user(&pool, "viewer-d").await;
        let (state, _dir) = app_state(pool.clone());
        let adm = state.admission.clone();
        let router = with_user(protected_stack(
            Router::new().route("/api/save", post(|| async { StatusCode::OK })),
            &state,
        ))
        .with_state(state);
        let base = serve_app(router).await;
        let r = reqwest::Client::new()
            .post(format!("{base}/api/save"))
            .header("x-user", "viewer-d")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 403);
        adm.idle().await;
        crate::db_audit::drain().await;
        let got: Vec<(String, String)> = sqlx::query_as("SELECT action, outcome FROM audit_events")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(got, [("authz.denied".to_string(), "denied".to_string())]);
    }
}
